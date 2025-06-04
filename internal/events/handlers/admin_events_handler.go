package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	eventModels "github.com/your-org/auth-service/internal/events/models"
	kafkaPkg "github.com/your-org/auth-service/internal/events/kafka"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces"
	"go.uber.org/zap"
)

// AdminEventsHandler handles events originating from an Admin service or admin actions.
type AdminEventsHandler struct {
	logger        *zap.Logger
	cfg           *config.Config
	userRepo      repoInterfaces.UserRepository
	authService   domainService.AuthLogicService
	kafkaProducer *kafkaPkg.Producer
	// Added for audit logging in handlers, if they directly record
	auditLogRecorder domainService.AuditLogRecorder
}

// NewAdminEventsHandler creates a new AdminEventsHandler.
func NewAdminEventsHandler(
	logger *zap.Logger,
	cfg *config.Config,
	userRepo repoInterfaces.UserRepository,
	authService domainService.AuthLogicService,
	kafkaProducer *kafkaPkg.Producer,
	auditLogRecorder domainService.AuditLogRecorder, // Added
) *AdminEventsHandler {
	return &AdminEventsHandler{
		logger:        logger,
		cfg:           cfg,
		userRepo:      userRepo,
		authService:   authService,
		kafkaProducer: kafkaProducer,
		auditLogRecorder: auditLogRecorder, // Added
	}
}

// AdminUserForceLogoutPayload matches the expected structure from admin service.
type AdminUserForceLogoutPayload struct {
	UserID        string `json:"user_id"`
	AdminUserID   string `json:"admin_user_id"`
	Reason        string `json:"reason,omitempty"`
}

// HandleAdminUserForceLogout handles the admin.user.force_logout.v1 event.
func (h *AdminEventsHandler) HandleAdminUserForceLogout(ctx context.Context, event eventModels.CloudEvent) error {
	h.logger.Info("Handling admin.user.force_logout.v1 event", zap.String("eventID", event.ID), zap.String("subject", event.Subject))

	var payload AdminUserForceLogoutPayload
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AdminUserForceLogoutPayload", zap.Error(err), zap.String("eventID", event.ID))
		return fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	userIDToLogout, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Failed to parse UserID from AdminUserForceLogoutPayload", zap.Error(err), zap.String("rawUserID", payload.UserID))
		return fmt.Errorf("invalid UserID in payload: %w", err)
	}

	// The actor for the audit log is the admin user who initiated this.
	var actorAdminID *uuid.UUID
	if parsedUUID, parseErr := uuid.Parse(payload.AdminUserID); parseErr == nil {
		actorAdminID = &parsedUUID
	} else {
		h.logger.Warn("Could not parse AdminUserID as UUID for audit log", zap.String("rawAdminUserID", payload.AdminUserID))
		// Proceed with nil actorID if parsing fails, or handle as error if admin ID is strictly required.
	}

	auditDetails := map[string]interface{}{
		"reason":         payload.Reason,
		"admin_user_id":  payload.AdminUserID, // Log the raw string admin ID as well
		"source_event_id": event.ID,
	}

	// Use SystemLogoutAllUserSessions, passing the admin user ID as the actor and reason.
	err = h.authService.SystemLogoutAllUserSessions(ctx, userIDToLogout, payload.AdminUserID, payload.Reason)
	if err != nil {
		h.logger.Error("Failed to execute force logout for user", zap.Error(err), zap.String("userID", userIDToLogout.String()))
		h.auditLogRecorder.RecordEvent(ctx, actorAdminID, "admin_force_logout", models.AuditLogStatusFailure, &userIDToLogout, models.AuditTargetTypeUser, auditDetails, "internal_event", "internal_event")
		return fmt.Errorf("failed to force logout user %s: %w", userIDToLogout.String(), err)
	}

	h.auditLogRecorder.RecordEvent(ctx, actorAdminID, "admin_force_logout", models.AuditLogStatusSuccess, &userIDToLogout, models.AuditTargetTypeUser, auditDetails, "internal_event", "internal_event")
	h.logger.Info("admin.user.force_logout.v1 event processed successfully", zap.String("userID", userIDToLogout.String()))
	return nil
}

// AdminUserBlockPayload matches the expected structure from admin service.
type AdminUserBlockPayload struct {
	UserID      string `json:"user_id"`
	AdminUserID string `json:"admin_user_id"`
	Reason      string `json:"reason,omitempty"`
}

// HandleAdminUserBlock handles the admin.user.block.v1 event.
func (h *AdminEventsHandler) HandleAdminUserBlock(ctx context.Context, event eventModels.CloudEvent) error {
	h.logger.Info("Handling admin.user.block.v1 event", zap.String("eventID", event.ID), zap.String("subject", event.Subject))

	var payload AdminUserBlockPayload
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AdminUserBlockPayload", zap.Error(err), zap.String("eventID", event.ID))
		return fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	userIDToBlock, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Failed to parse UserID from AdminUserBlockPayload", zap.Error(err), zap.String("rawUserID", payload.UserID))
		return fmt.Errorf("invalid UserID in payload: %w", err)
	}

	var actorAdminID *uuid.UUID
	if parsedUUID, parseErr := uuid.Parse(payload.AdminUserID); parseErr == nil {
		actorAdminID = &parsedUUID
	}

	auditDetails := map[string]interface{}{
		"reason":         payload.Reason,
		"admin_user_id":  payload.AdminUserID,
		"source_event_id": event.ID,
	}

	// 1. Update user status to blocked
	// This might require fetching the user first if UpdateStatus is not a direct repo call for just status.
	// Or if other fields like StatusReason need to be set on the user model before an Update call.
	// Assuming UserRepository has a direct UpdateStatus method for simplicity.
	// If not, it would be: user, err := h.userRepo.FindByID...; user.Status=...; user.StatusReason=...; h.userRepo.Update(user)
	if err := h.userRepo.UpdateStatus(ctx, userIDToBlock, models.UserStatusBlocked); err != nil {
		h.logger.Error("Failed to update user status to blocked", zap.Error(err), zap.String("userID", userIDToBlock.String()))
		h.auditLogRecorder.RecordEvent(ctx, actorAdminID, "admin_user_block_received", models.AuditLogStatusFailure, &userIDToBlock, models.AuditTargetTypeUser, auditDetails, "internal_event", "internal_event")
		return fmt.Errorf("failed to block user %s: %w", userIDToBlock.String(), err)
	}
	// TODO: Update StatusReason if field exists and is populated from payload.Reason

	// 2. Call SystemLogoutAllUserSessions
	if err := h.authService.SystemLogoutAllUserSessions(ctx, userIDToBlock, payload.AdminUserID, payload.Reason); err != nil {
		h.logger.Error("Failed to logout all sessions for blocked user", zap.Error(err), zap.String("userID", userIDToBlock.String()))
		// Log and continue, as user is already marked as blocked.
		auditDetails["warning_logout_sessions_failed"] = err.Error()
	}

	// 3. Publish com.yourplatform.auth.user.account.blocked.v1 CloudEvent
	blockedEventPayload := eventModels.UserAccountBlockedPayload{
		UserID:    userIDToBlock.String(),
		BlockedAt: time.Now().UTC(),
		Reason:    &payload.Reason,
		ActorID:   &payload.AdminUserID,
	}
	if err := h.kafkaProducer.PublishCloudEvent(ctx, h.cfg.Kafka.Producer.Topic, eventModels.AuthUserAccountBlockedV1, userIDToBlock.String(), blockedEventPayload); err != nil {
		h.logger.Error("Failed to publish CloudEvent for user account blocked", zap.Error(err), zap.String("userID", userIDToBlock.String()))
		auditDetails["warning_cloudevent_publish_failed"] = err.Error()
	}

	h.auditLogRecorder.RecordEvent(ctx, actorAdminID, "admin_user_block_received", models.AuditLogStatusSuccess, &userIDToBlock, models.AuditTargetTypeUser, auditDetails, "internal_event", "internal_event")
	h.logger.Info("admin.user.block.v1 event processed successfully", zap.String("userID", userIDToBlock.String()))
	return nil
}

// AdminUserUnblockPayload matches the expected structure from admin service.
type AdminUserUnblockPayload struct {
	UserID      string `json:"user_id"`
	AdminUserID string `json:"admin_user_id"`
	Reason      string `json:"reason,omitempty"` // Reason for unblocking, if any
}

// HandleAdminUserUnblock handles the admin.user.unblock.v1 event.
func (h *AdminEventsHandler) HandleAdminUserUnblock(ctx context.Context, event eventModels.CloudEvent) error {
	h.logger.Info("Handling admin.user.unblock.v1 event", zap.String("eventID", event.ID), zap.String("subject", event.Subject))

	var payload AdminUserUnblockPayload
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AdminUserUnblockPayload", zap.Error(err), zap.String("eventID", event.ID))
		return fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	userIDToUnblock, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Failed to parse UserID from AdminUserUnblockPayload", zap.Error(err), zap.String("rawUserID", payload.UserID))
		return fmt.Errorf("invalid UserID in payload: %w", err)
	}

	var actorAdminID *uuid.UUID
	if parsedUUID, parseErr := uuid.Parse(payload.AdminUserID); parseErr == nil {
		actorAdminID = &parsedUUID
	}
	auditDetails := map[string]interface{}{
		"reason":         payload.Reason, // Reason for unblocking
		"admin_user_id":  payload.AdminUserID,
		"source_event_id": event.ID,
	}

	user, err := h.userRepo.FindByID(ctx, userIDToUnblock)
	if err != nil {
		h.logger.Error("User not found for unblocking", zap.Error(err), zap.String("userID", userIDToUnblock.String()))
		h.auditLogRecorder.RecordEvent(ctx, actorAdminID, "admin_user_unblock_received", models.AuditLogStatusFailure, &userIDToUnblock, models.AuditTargetTypeUser, auditDetails, "internal_event", "internal_event")
		return fmt.Errorf("user %s not found for unblocking: %w", userIDToUnblock.String(), err)
	}

	newStatus := models.UserStatusActive
	if user.EmailVerifiedAt == nil {
		newStatus = models.UserStatusPendingVerification
	}

	// Update status (and potentially clear StatusReason if that field exists on user model)
	// user.Status = newStatus
	// user.StatusReason = "" // Clear reason
	// if err := h.userRepo.Update(ctx, user); err != nil { ... }
	// For now, assuming direct UpdateStatus:
	if err := h.userRepo.UpdateStatus(ctx, userIDToUnblock, newStatus); err != nil {
		h.logger.Error("Failed to update user status to unblock", zap.Error(err), zap.String("userID", userIDToUnblock.String()))
		h.auditLogRecorder.RecordEvent(ctx, actorAdminID, "admin_user_unblock_received", models.AuditLogStatusFailure, &userIDToUnblock, models.AuditTargetTypeUser, auditDetails, "internal_event", "internal_event")
		return fmt.Errorf("failed to unblock user %s: %w", userIDToUnblock.String(), err)
	}

	// Publish com.yourplatform.auth.user.account.unlocked.v1 CloudEvent
	unlockedEventPayload := eventModels.UserAccountUnblockedPayload{
		UserID:      userIDToUnblock.String(),
		UnblockedAt: time.Now().UTC(),
		ActorID:     &payload.AdminUserID,
	}
	if err := h.kafkaProducer.PublishCloudEvent(ctx, h.cfg.Kafka.Producer.Topic, eventModels.AuthUserAccountUnblockedV1, userIDToUnblock.String(), unlockedEventPayload); err != nil {
		h.logger.Error("Failed to publish CloudEvent for user account unblocked", zap.Error(err), zap.String("userID", userIDToUnblock.String()))
		auditDetails["warning_cloudevent_publish_failed"] = err.Error()
	}

	h.auditLogRecorder.RecordEvent(ctx, actorAdminID, "admin_user_unblock_received", models.AuditLogStatusSuccess, &userIDToUnblock, models.AuditTargetTypeUser, auditDetails, "internal_event", "internal_event")
	h.logger.Info("admin.user.unblock.v1 event processed successfully", zap.String("userID", userIDToUnblock.String()))
	return nil
}
