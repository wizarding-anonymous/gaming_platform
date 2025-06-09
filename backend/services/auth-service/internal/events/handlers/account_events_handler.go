// File: backend/services/auth-service/internal/events/handlers/account_events_handler.go
package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	// Import for kafka.CloudEvent (Sarama consumer path)
	"github.com/your-org/auth-service/internal/events/kafka"
	// domainErrors "github.com/your-org/auth-service/internal/domain/errors" // Already imported
)

// AccountEventsHandler handles events originating from the Account Service.
type AccountEventsHandler struct {
	logger              *zap.Logger
	cfg                 *config.Config
	userRepo            domainService.UserRepository
	authService         domainService.AuthLogicService
	sessionRepo         domainService.SessionRepository
	refreshTokenRepo    domainService.RefreshTokenRepository
	mfaSecretRepo       domainService.MFASecretRepository
	mfaBackupCodeRepo   domainService.MFABackupCodeRepository
	apiKeyRepo          domainService.APIKeyRepository
	externalAccountRepo domainService.ExternalAccountRepository
	auditRecorder       domainService.AuditLogRecorder
	verificationCodeRepo domainService.VerificationCodeRepository
}

// NewAccountEventsHandler creates a new AccountEventsHandler.
func NewAccountEventsHandler(
	logger *zap.Logger,
	cfg *config.Config,
	userRepo domainService.UserRepository,
	verificationCodeRepo domainService.VerificationCodeRepository, // Added this based on main.go
	authService domainService.AuthLogicService,
	sessionRepo domainService.SessionRepository,
	refreshTokenRepo domainService.RefreshTokenRepository,
	mfaSecretRepo domainService.MFASecretRepository,
	mfaBackupCodeRepo domainService.MFABackupCodeRepository,
	apiKeyRepo domainService.APIKeyRepository,
	externalAccountRepo domainService.ExternalAccountRepository,
	auditRecorder domainService.AuditLogRecorder,
) *AccountEventsHandler {
	return &AccountEventsHandler{
		logger:              logger.Named("account_events_handler"),
		cfg:                 cfg,
		userRepo:            userRepo,
		verificationCodeRepo: verificationCodeRepo,
		authService:         authService,
		sessionRepo:         sessionRepo,
		refreshTokenRepo:    refreshTokenRepo,
		mfaSecretRepo:       mfaSecretRepo,
		mfaBackupCodeRepo:   mfaBackupCodeRepo,
		apiKeyRepo:          apiKeyRepo,
		externalAccountRepo: externalAccountRepo,
		auditRecorder:       auditRecorder,
	}
}

// AccountUserProfileUpdatedPayload defines the structure for account.user.profile_updated.v1 event data.
type AccountUserProfileUpdatedPayload struct {
	UserID        string                 `json:"user_id"`
	UpdatedFields []string               `json:"updated_fields"`
	NewValues     map[string]interface{} `json:"new_values"`
	// UpdateTimestamp string              `json:"update_timestamp"` // Already in CloudEvent metadata
}

// HandleAccountUserProfileUpdated handles the account.user.profile_updated.v1 event.
func (h *AccountEventsHandler) HandleAccountUserProfileUpdated(ctx context.Context, event kafka.CloudEvent) error {
	h.logger.Info("Received account.user.profile_updated.v1 event",
		zap.String("eventType", event.Type),
		zap.String("eventID", event.ID),
		zap.Stringp("subject", event.Subject),
	)

	var payload AccountUserProfileUpdatedPayload
	if event.Data == nil {
		h.logger.Error("Received CloudEvent with nil data for AccountUserProfileUpdated", zap.String("eventID", event.ID))
		return fmt.Errorf("event data is nil for AccountUserProfileUpdated: eventID %s", event.ID)
	}
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AccountUserProfileUpdatedPayload from CloudEvent data",
			zap.Error(err),
			zap.String("eventID", event.ID),
			zap.ByteString("raw_event_data", event.Data),
		)
		return fmt.Errorf("failed to unmarshal event data for AccountUserProfileUpdated: %w", err)
	}

	userID, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Invalid UserID in AccountUserProfileUpdatedPayload", zap.Error(err), zap.String("raw_userID", payload.UserID), zap.String("eventID", event.ID))
		return fmt.Errorf("invalid user ID: %w", err)
	}

	var emailChanged, statusChanged bool
	var newEmail, newStatus string

	for _, field := range payload.UpdatedFields {
		if field == "email" {
			if val, ok := payload.NewValues["email"].(string); ok {
				emailChanged = true
				newEmail = val
			}
		}
		if field == "status" {
			if val, ok := payload.NewValues["status"].(string); ok {
				statusChanged = true
				newStatus = val
			}
		}
	}

	if emailChanged {
		h.logger.Info("User email change detected from event", zap.String("userID", userID.String()), zap.String("newEmail", newEmail))
		// Placeholder: Logic to update email and require re-verification
		// user, _ := h.userRepo.FindByID(ctx, userID)
		// if user != nil { user.Email = newEmail; user.EmailVerifiedAt = nil; h.userRepo.Update(ctx, user) }
	}

	if statusChanged {
		h.logger.Info("User status change detected from event", zap.String("userID", userID.String()), zap.String("newStatus", newStatus))
		userStatus := models.UserStatus(newStatus)
		if userStatus == models.UserStatusBlocked || userStatus == models.UserStatusDeleted {
			h.logger.Info("User status changed to blocked/deleted, revoking sessions.", zap.String("userID", userID.String()))
			if _, err := h.sessionRepo.DeleteAllUserSessions(ctx, userID, nil); err != nil {
				h.logger.Error("Failed to delete user sessions after status change event", zap.Error(err), zap.String("userID", userID.String()))
			}
			// refreshTokenRepo.DeleteByUserID needs fix or alternative
			// if _, err := h.refreshTokenRepo.DeleteByUserID(ctx, userID); err != nil { ... }
		}
		if err := h.userRepo.UpdateStatus(ctx, userID, userStatus); err != nil {
			h.logger.Error("Failed to update user status after event", zap.Error(err), zap.String("userID", userID.String()))
		}
	}

	// Use event.Subject for actor if appropriate, or keep nil if system event.
	// For audit, userID is the target.
	h.auditRecorder.RecordEvent(ctx, nil, "profile_updated_event_consumed", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, map[string]interface{}{"event_payload": payload, "cloud_event_id": event.ID}, "", "")
	return nil
}

// AccountUserDeletedPayload defines the structure for account.user.deleted.v1 event data.
type AccountUserDeletedPayload struct {
	UserID string `json:"user_id"`
	// DeleteTimestamp string `json:"delete_timestamp"` // Already in CloudEvent metadata
	Reason *string `json:"reason,omitempty"`
}

// HandleAccountUserDeleted handles the account.user.deleted.v1 event.
func (h *AccountEventsHandler) HandleAccountUserDeleted(ctx context.Context, event kafka.CloudEvent) error {
	h.logger.Info("Received account.user.deleted.v1 event",
		zap.String("eventType", event.Type),
		zap.String("eventID", event.ID),
		zap.Stringp("subject", event.Subject),
	)

	var payload AccountUserDeletedPayload
	if event.Data == nil {
		h.logger.Error("Received CloudEvent with nil data for AccountUserDeleted", zap.String("eventID", event.ID))
		return fmt.Errorf("event data is nil for AccountUserDeleted: eventID %s", event.ID)
	}
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AccountUserDeletedPayload from CloudEvent data",
			zap.Error(err),
			zap.String("eventID", event.ID),
			zap.ByteString("raw_event_data", event.Data),
		)
		return fmt.Errorf("failed to unmarshal event data for AccountUserDeleted: %w", err)
	}

	userID, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Invalid UserID in AccountUserDeletedPayload", zap.Error(err), zap.String("raw_userID", payload.UserID), zap.String("eventID", event.ID))
		return fmt.Errorf("invalid user ID: %w", err)
	}

	h.logger.Info("Processing user deletion from event", zap.String("userID", userID.String()))

	// Cascade deletes are expected to handle most of this via DB foreign keys with ON DELETE CASCADE.
	// Explicit deletion here is for thoroughness or if CASCADE is not set on all relations.
	// The primary action is to delete/mark-as-deleted the user in this service's DB.
	if err := h.authService.SystemDeleteUser(ctx, userID); err != nil { // Assuming SystemDeleteUser exists on AuthLogicService
		 h.logger.Error("Failed to complete all system deletions for user", zap.Error(err), zap.String("userID", userID.String()), zap.String("eventID", event.ID))
		 // Decide if this is a critical error to NACK the message.
	}

	h.auditRecorder.RecordEvent(ctx, nil, "user_deleted_event_consumed", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, map[string]interface{}{"event_payload": payload, "cloud_event_id": event.ID}, "", "")
	return nil
}
