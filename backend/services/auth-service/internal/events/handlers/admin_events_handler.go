// File: backend/services/auth-service/internal/events/handlers/admin_events_handler.go
package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka" // For kafka.CloudEvent
)

// AdminEventsHandler handles events originating from the Admin Service.
type AdminEventsHandler struct {
	logger        *zap.Logger
	cfg           *config.Config
	userRepo      domainService.UserRepository
	authService   domainService.AuthLogicService // For session revocation etc.
	auditRecorder domainService.AuditLogRecorder
}

// NewAdminEventsHandler creates a new AdminEventsHandler.
func NewAdminEventsHandler(
	logger *zap.Logger,
	cfg *config.Config,
	userRepo domainService.UserRepository,
	authService domainService.AuthLogicService,
	auditRecorder domainService.AuditLogRecorder,
) *AdminEventsHandler {
	return &AdminEventsHandler{
		logger:        logger.Named("admin_events_handler"),
		cfg:           cfg,
		userRepo:      userRepo,
		authService:   authService,
		auditRecorder: auditRecorder,
	}
}

// AdminUserForceLogoutPayload defines the structure for admin.user.force_logout.v1 event data.
type AdminUserForceLogoutPayload struct {
	UserID         string  `json:"user_id"`
	AdminUserID    string  `json:"admin_user_id"`
	Reason         *string `json:"reason,omitempty"`
	// ActionTimestamp string `json:"action_timestamp"` // Already in CloudEvent metadata
}

// HandleAdminUserForceLogout handles the admin.user.force_logout.v1 event.
func (h *AdminEventsHandler) HandleAdminUserForceLogout(ctx context.Context, event kafka.CloudEvent) error {
	h.logger.Info("Received admin.user.force_logout.v1 event",
		zap.String("eventType", event.Type),
		zap.String("eventID", event.ID),
		zap.Stringp("subject", event.Subject),
	)

	var payload AdminUserForceLogoutPayload
	if event.Data == nil {
		h.logger.Error("Received AdminUserForceLogout event with nil data", zap.String("eventID", event.ID))
		return fmt.Errorf("event data is nil for AdminUserForceLogout: eventID %s", event.ID)
	}
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AdminUserForceLogoutPayload from CloudEvent data",
			zap.Error(err),
			zap.String("eventID", event.ID),
			zap.ByteString("raw_event_data", event.Data),
		)
		return fmt.Errorf("failed to unmarshal event data for AdminUserForceLogout: %w", err)
	}

	targetUserID, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Invalid Target UserID in AdminUserForceLogoutPayload", zap.Error(err), zap.String("raw_userID", payload.UserID), zap.String("eventID", event.ID))
		return fmt.Errorf("invalid target user ID: %w", err)
	}

	var adminActorID *uuid.UUID
	if parsedUUID, errParse := uuid.Parse(payload.AdminUserID); errParse == nil {
		adminActorID = &parsedUUID
	}


	h.logger.Info("Processing user force logout from event", zap.String("targetUserID", targetUserID.String()), zap.Stringp("adminUserID", &payload.AdminUserID))

	// Call AuthService method to logout all sessions for the user.
	// The AuthService.LogoutAll method currently takes an access token.
	// We need a system-level equivalent that takes a userID.
	// Placeholder for: err = h.authService.SystemLogoutAllUserSessions(ctx, targetUserID, payload.AdminUserID, payload.Reason)
	// For now, directly call session and token service/repo methods as a placeholder.
	// This logic should be encapsulated in AuthService.
	if err := h.authService.SystemLogoutAllUserSessions(ctx, targetUserID, adminActorID, payload.Reason); err != nil {
		h.logger.Error("Failed to force logout user sessions based on event", zap.Error(err), zap.String("targetUserID", targetUserID.String()), zap.String("eventID", event.ID))
		// Depending on the error, may or may not NACK
	}

	auditDetails := map[string]interface{}{"event_payload": payload, "reason": "admin_force_logout_event", "cloud_event_id": event.ID}
	h.auditRecorder.RecordEvent(ctx, adminActorID, "admin_user_force_logout_event_consumed", models.AuditLogStatusSuccess, &targetUserID, models.AuditTargetTypeUser, auditDetails, "", "")
	return nil
}

// AdminUserBlockPayload defines the structure for admin.user.block.v1 event data.
type AdminUserBlockPayload struct {
	UserID        string  `json:"user_id"`
	AdminUserID   string  `json:"admin_user_id"`
	Reason        string  `json:"reason"`
	// ActionTimestamp string `json:"action_timestamp"`
}

// HandleAdminUserBlock handles the admin.user.block.v1 event.
func (h *AdminEventsHandler) HandleAdminUserBlock(ctx context.Context, event kafka.CloudEvent) error {
	h.logger.Info("Received admin.user.block.v1 event",
		zap.String("eventType", event.Type),
		zap.String("eventID", event.ID),
		zap.Stringp("subject", event.Subject),
	)

	var payload AdminUserBlockPayload
	if event.Data == nil {
		h.logger.Error("Received AdminUserBlock event with nil data", zap.String("eventID", event.ID))
		return fmt.Errorf("event data is nil for AdminUserBlock: eventID %s", event.ID)
	}
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AdminUserBlockPayload from CloudEvent data",
			zap.Error(err),
			zap.String("eventID", event.ID),
			zap.ByteString("raw_event_data", event.Data),
		)
		return fmt.Errorf("failed to unmarshal event data for AdminUserBlock: %w", err)
	}

	targetUserID, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Invalid Target UserID in AdminUserBlockPayload", zap.Error(err), zap.String("raw_userID", payload.UserID), zap.String("eventID", event.ID))
		return fmt.Errorf("invalid target user ID: %w", err)
	}

	var adminActorID *uuid.UUID
	if parsedUUID, errParse := uuid.Parse(payload.AdminUserID); errParse == nil {
		adminActorID = &parsedUUID
	}

	h.logger.Info("Processing user block from event", zap.String("targetUserID", targetUserID.String()), zap.Stringp("adminUserID", &payload.AdminUserID))

	if err := h.userRepo.UpdateStatus(ctx, targetUserID, models.UserStatusBlocked); err != nil {
		h.logger.Error("Failed to update user status to blocked from event", zap.Error(err), zap.String("targetUserID", targetUserID.String()), zap.String("eventID", event.ID))
	}
	// Also revoke sessions
	blockReason := "user_blocked_via_event"
	if err := h.authService.SystemLogoutAllUserSessions(ctx, targetUserID, adminActorID, &blockReason); err != nil {
		h.logger.Error("Failed to force logout user sessions during block event", zap.Error(err), zap.String("targetUserID", targetUserID.String()), zap.String("eventID", event.ID))
	}

	auditDetails := map[string]interface{}{"event_payload": payload, "reason": blockReason, "cloud_event_id": event.ID}
	h.auditRecorder.RecordEvent(ctx, adminActorID, "admin_user_block_event_consumed", models.AuditLogStatusSuccess, &targetUserID, models.AuditTargetTypeUser, auditDetails, "", "")
	return nil
}

// AdminUserUnblockPayload defines the structure for admin.user.unblock.v1 event data.
type AdminUserUnblockPayload struct {
	UserID        string  `json:"user_id"`
	AdminUserID   string  `json:"admin_user_id"`
	Reason        *string `json:"reason,omitempty"`
	// ActionTimestamp string `json:"action_timestamp"`
}

// HandleAdminUserUnblock handles the admin.user.unblock.v1 event.
func (h *AdminEventsHandler) HandleAdminUserUnblock(ctx context.Context, event kafka.CloudEvent) error {
	h.logger.Info("Received admin.user.unblock.v1 event",
		zap.String("eventType", event.Type),
		zap.String("eventID", event.ID),
		zap.Stringp("subject", event.Subject),
	)

	var payload AdminUserUnblockPayload
	if event.Data == nil {
		h.logger.Error("Received AdminUserUnblock event with nil data", zap.String("eventID", event.ID))
		return fmt.Errorf("event data is nil for AdminUserUnblock: eventID %s", event.ID)
	}
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AdminUserUnblockPayload from CloudEvent data",
			zap.Error(err),
			zap.String("eventID", event.ID),
			zap.ByteString("raw_event_data", event.Data),
		)
		return fmt.Errorf("failed to unmarshal event data for AdminUserUnblock: %w", err)
	}

	targetUserID, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Invalid Target UserID in AdminUserUnblockPayload", zap.Error(err), zap.String("raw_userID", payload.UserID), zap.String("eventID", event.ID))
		return fmt.Errorf("invalid target user ID: %w", err)
	}

	var adminActorID *uuid.UUID
	if parsedUUID, errParse := uuid.Parse(payload.AdminUserID); errParse == nil {
		adminActorID = &parsedUUID
	}

	h.logger.Info("Processing user unblock from event", zap.String("targetUserID", targetUserID.String()), zap.Stringp("adminUserID", &payload.AdminUserID))

	// User might have been pending verification before block, or just active.
	// Simplest is to set to active. If email verification is strict, check EmailVerifiedAt.
	user, err := h.userRepo.FindByID(ctx, targetUserID)
	if err != nil {
		h.logger.Error("User not found for unblock event", zap.Error(err), zap.String("targetUserID", targetUserID.String()), zap.String("eventID", event.ID))
		return domainErrors.ErrUserNotFound
	}

	newStatus := models.UserStatusActive
	if user.EmailVerifiedAt == nil {
		newStatus = models.UserStatusPendingVerification
	}

	if err := h.userRepo.UpdateStatus(ctx, targetUserID, newStatus); err != nil {
		h.logger.Error("Failed to update user status to active/pending from unblock event", zap.Error(err), zap.String("targetUserID", targetUserID.String()), zap.String("eventID", event.ID))
	}

	auditDetails := map[string]interface{}{"event_payload": payload, "reason": "admin_user_unblock_event", "new_status": newStatus, "cloud_event_id": event.ID}
	h.auditRecorder.RecordEvent(ctx, adminActorID, "admin_user_unblock_event_consumed", models.AuditLogStatusSuccess, &targetUserID, models.AuditTargetTypeUser, auditDetails, "", "")
	return nil
}
