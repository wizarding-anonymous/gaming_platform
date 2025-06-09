// File: internal/events/handlers/account_events_handler.go
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
	appSecurity "github.com/your-org/auth-service/internal/infrastructure/security"
	"go.uber.org/zap"
)

// AccountEventsHandler handles events originating from the Account service.
type AccountEventsHandler struct {
	logger                 *zap.Logger
	cfg                    *config.Config
	userRepo               repoInterfaces.UserRepository
	verificationCodeRepo   repoInterfaces.VerificationCodeRepository
	authService            domainService.AuthLogicService
	kafkaProducer          *kafkaPkg.Producer
	// New dependencies for user deletion:
	sessionRepo            repoInterfaces.SessionRepository
	refreshTokenRepo       repoInterfaces.RefreshTokenRepository
	mfaSecretRepo          repoInterfaces.MFASecretRepository
	mfaBackupCodeRepo      repoInterfaces.MFABackupCodeRepository
	apiKeyRepo             repoInterfaces.APIKeyRepository
	externalAccountRepo    repoInterfaces.ExternalAccountRepository
	// VerificationCodeRepo is already present
	auditLogRecorder       domainService.AuditLogRecorder
}

// NewAccountEventsHandler creates a new AccountEventsHandler.
func NewAccountEventsHandler(
	logger *zap.Logger,
	cfg *config.Config,
	userRepo repoInterfaces.UserRepository,
	verificationCodeRepo repoInterfaces.VerificationCodeRepository,
	authService domainService.AuthLogicService,
	kafkaProducer *kafkaPkg.Producer,
	// New dependencies for user deletion:
	sessionRepo repoInterfaces.SessionRepository,
	refreshTokenRepo repoInterfaces.RefreshTokenRepository,
	mfaSecretRepo repoInterfaces.MFASecretRepository,
	mfaBackupCodeRepo repoInterfaces.MFABackupCodeRepository,
	apiKeyRepo repoInterfaces.APIKeyRepository,
	externalAccountRepo repoInterfaces.ExternalAccountRepository,
	auditLogRecorder domainService.AuditLogRecorder,
) *AccountEventsHandler {
	return &AccountEventsHandler{
		logger:                 logger,
		cfg:                    cfg,
		userRepo:               userRepo,
		verificationCodeRepo:   verificationCodeRepo,
		authService:            authService,
		kafkaProducer:          kafkaProducer,
		// New dependencies:
		sessionRepo:            sessionRepo,
		refreshTokenRepo:       refreshTokenRepo,
		mfaSecretRepo:          mfaSecretRepo,
		mfaBackupCodeRepo:      mfaBackupCodeRepo,
		apiKeyRepo:             apiKeyRepo,
		externalAccountRepo:    externalAccountRepo,
		auditLogRecorder:       auditLogRecorder,
	}
}

// AccountUserProfileUpdatedPayload matches the expected structure from account service.
type AccountUserProfileUpdatedPayload struct {
	UserID        string                 `json:"user_id"`
	UpdatedFields []string               `json:"updated_fields"`
	NewValues     map[string]interface{} `json:"new_values"`
}

// HandleAccountUserProfileUpdated handles the account.user.profile_updated.v1 event.
func (h *AccountEventsHandler) HandleAccountUserProfileUpdated(ctx context.Context, event eventModels.CloudEvent) error {
	h.logger.Info("Handling account.user.profile_updated.v1 event", zap.String("eventID", event.ID), zap.String("subject", event.Subject))

	var payload AccountUserProfileUpdatedPayload
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AccountUserProfileUpdatedPayload", zap.Error(err), zap.String("eventID", event.ID))
		return fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	userID, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Failed to parse UserID from payload", zap.Error(err), zap.String("rawUserID", payload.UserID))
		return fmt.Errorf("invalid UserID in payload: %w", err)
	}

	user, err := h.userRepo.FindByID(ctx, userID)
	if err != nil {
		h.logger.Warn("User not found in auth service DB for profile update, ignoring event.", zap.String("userID", userID.String()), zap.Error(err))
		return nil
	}

	needsStatusUpdate := false
	newStatus := user.Status

	for _, field := range payload.UpdatedFields {
		switch field {
		case "email":
			newEmailVal, ok := payload.NewValues["email"].(string)
			if !ok {
				h.logger.Warn("New email value is not a string or missing for profile update", zap.String("userID", userID.String()))
				continue
			}
			if newEmailVal != user.Email {
				h.logger.Info("User email change detected via event", zap.String("userID", userID.String()), zap.String("oldEmail", user.Email), zap.String("newEmail", newEmailVal))

				if err := h.userRepo.UpdateEmail(ctx, userID, newEmailVal); err != nil {
					h.logger.Error("Failed to update user email in DB", zap.Error(err), zap.String("userID", userID.String()))
					return fmt.Errorf("failed to update email: %w", err)
				}

				if err := h.userRepo.SetEmailVerifiedAt(ctx, userID, nil); err != nil {
					h.logger.Error("Failed to set email_verified_at to NULL", zap.Error(err), zap.String("userID", userID.String()))
				}

				if user.Status == models.UserStatusActive {
					newStatus = models.UserStatusPendingVerification
					needsStatusUpdate = true
				}

				plainToken, errTokenGen := appSecurity.GenerateSecureToken(32)
				if errTokenGen != nil {
					h.logger.Error("Failed to generate verification token for new email", zap.Error(errTokenGen), zap.String("userID", userID.String()))
					return fmt.Errorf("token generation failed: %w", errTokenGen)
				}
				hashedToken := appSecurity.HashToken(plainToken)
				verificationCode := &models.VerificationCode{
					ID:        uuid.New(),
					UserID:    userID,
					Type:      models.VerificationCodeTypeEmailVerification,
					CodeHash:  hashedToken,
					ExpiresAt: time.Now().Add(h.cfg.JWT.EmailVerificationToken.ExpiresIn),
				}
				if errCreateCode := h.verificationCodeRepo.Create(ctx, verificationCode); errCreateCode != nil {
					h.logger.Error("Failed to store new verification code for email change", zap.Error(errCreateCode), zap.String("userID", userID.String()))
					return fmt.Errorf("storing verification code failed: %w", errCreateCode)
				}

				verificationPayload := eventModels.UserEmailVerificationRequiredPayload{
					UserID:            userID.String(),
					Email:             newEmailVal,
					VerificationToken: plainToken,
					RequestTimestamp:  time.Now().UTC(),
				}

				if errPub := h.kafkaProducer.PublishCloudEvent(ctx, h.cfg.Kafka.Producer.Topic, eventModels.AuthUserEmailVerificationRequiredV1, userID.String(), verificationPayload); errPub != nil {
					h.logger.Error("Failed to publish CloudEvent for email verification required", zap.Error(errPub), zap.String("userID", userID.String()))
				}
				h.logger.Info("Published email verification required event for user", zap.String("userID", userID.String()), zap.String("newEmail", newEmailVal))
			}

		case "status": // Example: {"status": "blocked"} or {"status": "deleted"}
			newStatusValStr, ok := payload.NewValues["status"].(string)
			if !ok {
				h.logger.Warn("New status value is not a string or missing", zap.String("userID", userID.String()))
				continue
			}

			newStatusCandidate := models.UserStatus(newStatusValStr)
			// Define which statuses from account service trigger actions here
			isLockingStatus := newStatusCandidate == models.UserStatusBlocked ||
							   newStatusCandidate == models.UserStatusDeactivated || // Assuming "deleted" maps to "deactivated"
							   newStatusValStr == "deleted" // Catching "deleted" explicitly if it's not a UserStatus constant

			if isLockingStatus && newStatusCandidate != user.Status {
				h.logger.Info("User status change to blocked/deactivated detected from account service", zap.String("userID", userID.String()), zap.String("newStatus", newStatusValStr))
				newStatus = newStatusCandidate
				if newStatusValStr == "deleted" { newStatus = models.UserStatusDeactivated } // Normalize "deleted"
				needsStatusUpdate = true

				// Call SystemLogoutAllUserSessions from authService
				// Actor for this logout is the account service event, or the original actor if provided in event.
				var actorForLogout string
				if actorRaw, ok := payload.NewValues["actor_id"].(string); ok { // Check if actor_id provided with status change
					actorForLogout = actorRaw
				} else {
					actorForLogout = "system_account_profile_update"
				}

				if err := h.authService.SystemLogoutAllUserSessions(ctx, userID, actorForLogout, fmt.Sprintf("Account status changed to %s by external service", newStatusValStr)); err != nil {
					h.logger.Error("Failed to logout all user sessions for status change", zap.Error(err), zap.String("userID", userID.String()))
				}
			} else if newStatusCandidate != user.Status { // Handle other status changes if necessary
                 h.logger.Info("User status change detected (non-locking)", zap.String("userID", userID.String()), zap.String("newStatus", newStatusValStr))
                 newStatus = newStatusCandidate
                 needsStatusUpdate = true
            }
		}
	}

	if needsStatusUpdate {
		if err := h.userRepo.UpdateStatus(ctx, userID, newStatus); err != nil { // Ensure UpdateStatus is a valid method
			h.logger.Error("Failed to update user status in DB", zap.Error(err), zap.String("userID", userID.String()), zap.String("newStatus", string(newStatus)))
			return fmt.Errorf("failed to update status: %w", err)
		}
		h.logger.Info("User status updated successfully", zap.String("userID", userID.String()), zap.String("newStatus", string(newStatus)))
	}

	h.logger.Info("account.user.profile_updated.v1 event processed", zap.String("userID", userID.String()))
	return nil
}

// AccountUserDeletedPayload matches the expected structure from account service.
type AccountUserDeletedPayload struct {
	UserID            string    `json:"user_id"`
	DeletedBy         string    `json:"deleted_by"` // ID of the user/system that initiated the deletion
	DeletionTimestamp time.Time `json:"deletion_timestamp"`
}

// HandleAccountUserDeleted handles the account.user.deleted.v1 event.
func (h *AccountEventsHandler) HandleAccountUserDeleted(ctx context.Context, event eventModels.CloudEvent) error {
	h.logger.Info("Handling account.user.deleted.v1 event", zap.String("eventID", event.ID), zap.String("subject", event.Subject))

	var payload AccountUserDeletedPayload
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		h.logger.Error("Failed to unmarshal AccountUserDeletedPayload", zap.Error(err), zap.String("eventID", event.ID))
		return fmt.Errorf("failed to unmarshal event data: %w", err)
	}

	userID, err := uuid.Parse(payload.UserID)
	if err != nil {
		h.logger.Error("Failed to parse UserID from AccountUserDeletedPayload", zap.Error(err), zap.String("rawUserID", payload.UserID))
		return fmt.Errorf("invalid UserID in payload: %w", err)
	}

	// Log the deletion action in audit_logs
	actorIDForAudit, _ := uuid.Parse(payload.DeletedBy) // Try to parse, if fails, actor will be nil or just string
	var actorIDPtrForAudit *uuid.UUID
	if actorIDForAudit != uuid.Nil {
		actorIDPtrForAudit = &actorIDForAudit
	}
	auditDetails := map[string]interface{}{"deleted_by_actor_id": payload.DeletedBy, "deletion_timestamp_from_event": payload.DeletionTimestamp}

	// IP and UserAgent are not typically available in inter-service events unless explicitly passed.
	// Using "internal_event" or similar.
	ipAddress := "internal_event"
	userAgent := "internal_event"

	// Perform deletion of related data
	if _, err := h.sessionRepo.DeleteAllUserSessions(ctx, userID, nil); err != nil { // excludeCurrentSessionID is nil
		h.logger.Error("Failed to delete sessions for user", zap.Error(err), zap.String("userID", userID.String()))
		// Log and continue, try to delete as much as possible
	}
	if _, err := h.refreshTokenRepo.RevokeAllForUser(ctx, userID); err != nil {
		h.logger.Error("Failed to delete refresh tokens for user", zap.Error(err), zap.String("userID", userID.String()))
	}
	if _, err := h.mfaSecretRepo.DeleteAllForUser(ctx, userID); err != nil { // Assuming DeleteAllForUser exists
		h.logger.Error("Failed to delete MFA secrets for user", zap.Error(err), zap.String("userID", userID.String()))
	}
	if _, err := h.mfaBackupCodeRepo.DeleteByUserID(ctx, userID); err != nil {
		h.logger.Error("Failed to delete MFA backup codes for user", zap.Error(err), zap.String("userID", userID.String()))
	}
	if _, err := h.apiKeyRepo.RevokeAllForUser(ctx, userID); err != nil { // Assuming RevokeAllForUser exists
		h.logger.Error("Failed to delete API keys for user", zap.Error(err), zap.String("userID", userID.String()))
	}
	if _, err := h.externalAccountRepo.DeleteByUserID(ctx, userID); err != nil {
		h.logger.Error("Failed to delete external accounts for user", zap.Error(err), zap.String("userID", userID.String()))
	}
	if _, err := h.verificationCodeRepo.DeleteByUserID(ctx, userID); err != nil {
		h.logger.Error("Failed to delete verification codes for user", zap.Error(err), zap.String("userID", userID.String()))
	}

	// Soft delete the user record
	if err := h.userRepo.Delete(ctx, userID); err != nil { // Assuming Delete is soft delete
		h.logger.Error("Failed to soft delete user", zap.Error(err), zap.String("userID", userID.String()))
		h.auditLogRecorder.RecordEvent(ctx, actorIDPtrForAudit, "user_data_deleted_on_request", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return fmt.Errorf("failed to soft delete user %s: %w", userID.String(), err)
	}

	// TODO: Optionally, anonymize/nullify PII fields in the soft-deleted record if required.
	// This would involve fetching the user, clearing fields, and calling userRepo.Update.

	h.auditLogRecorder.RecordEvent(ctx, actorIDPtrForAudit, "user_data_deleted_on_request", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	h.logger.Info("User data deleted successfully based on account.user.deleted.v1 event", zap.String("userID", userID.String()))
	return nil
}
