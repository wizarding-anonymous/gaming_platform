// File: backend/services/auth-service/internal/service/auth_service_tokens.go
package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	kafkaEvents "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
)

// SystemDeleteUser handles the complete deletion of a user and all their associated data.
// This is intended for system-initiated events, like processing an account.user.deleted.v1 event.
func (s *AuthService) SystemDeleteUser(ctx context.Context, userID uuid.UUID, adminUserID *uuid.UUID, reason *string) error {
	s.logger.Info("SystemDeleteUser: Initiating deletion for user",
		zap.String("userID", userID.String()),
		zap.Stringp("reason", reason),
	)
	if adminUserID != nil {
		s.logger.Info("Deletion initiated by admin", zap.String("adminUserID", adminUserID.String()))
	}

	var errorsCollected []string

	// 1. Soft delete the user
	err := s.userRepo.UpdateStatus(ctx, userID, models.UserStatusDeleted)
	if err != nil {
		s.logger.Error("SystemDeleteUser: Failed to update user status to deleted", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("update user status: %v", err))
	}

	// 2. Delete all sessions for the user
	deletedSessionsCount, err := s.sessionService.DeleteAllUserSessions(ctx, userID, nil)
	if err != nil {
		s.logger.Error("SystemDeleteUser: Failed to delete user sessions", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("delete sessions: %v", err))
	}
	s.logger.Info("SystemDeleteUser: Deleted user sessions", zap.Int64("count", deletedSessionsCount), zap.String("userID", userID.String()))

	// 3. Revoke all refresh tokens
	revokedTokensCount, err := s.tokenService.RevokeAllRefreshTokensForUser(ctx, userID)
	if err != nil {
		s.logger.Error("SystemDeleteUser: Failed to revoke refresh tokens", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("revoke refresh tokens: %v", err))
	}
	s.logger.Info("SystemDeleteUser: Revoked refresh tokens", zap.Int64("count", revokedTokensCount), zap.String("userID", userID.String()))

	// 4. Delete MFA secrets
	deletedMFASecretsCount, err := s.mfaSecretRepo.DeleteAllForUser(ctx, userID)
	if err != nil {
		s.logger.Error("SystemDeleteUser: Failed to delete MFA secrets", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("delete mfa secrets: %v", err))
	}
	s.logger.Info("SystemDeleteUser: Deleted MFA secrets", zap.Int64("count", deletedMFASecretsCount), zap.String("userID", userID.String()))

	// 5. Delete MFA backup codes
	deletedBackupCodesCount, err := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("SystemDeleteUser: Failed to delete MFA backup codes", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("delete mfa backup codes: %v", err))
	}
	s.logger.Info("SystemDeleteUser: Deleted MFA backup codes", zap.Int64("count", deletedBackupCodesCount), zap.String("userID", userID.String()))

	// 6. Delete API keys
	deletedAPIKeysCount, err := s.apiKeyRepo.DeleteByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("SystemDeleteUser: Failed to delete API keys", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("delete api keys: %v", err))
	}
	s.logger.Info("SystemDeleteUser: Deleted API keys", zap.Int64("count", deletedAPIKeysCount), zap.String("userID", userID.String()))

	// 7. Delete external account links
	deletedExtAccountsCount, err := s.externalAccountRepo.DeleteByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("SystemDeleteUser: Failed to delete external account links", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("delete external accounts: %v", err))
	}
	s.logger.Info("SystemDeleteUser: Deleted external accounts", zap.Int64("count", deletedExtAccountsCount), zap.String("userID", userID.String()))

	// 8. Delete verification codes
	deletedVerCodesCount, err := s.verificationCodeRepo.DeleteAllByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("SystemDeleteUser: Failed to delete verification codes", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("delete verification codes: %v", err))
	}
	s.logger.Info("SystemDeleteUser: Deleted verification codes", zap.Int64("count", deletedVerCodesCount), zap.String("userID", userID.String()))

	var auditStatus models.AuditLogStatus
	if len(errorsCollected) > 0 {
		auditStatus = models.AuditLogStatusPartialSuccess
	} else {
		auditStatus = models.AuditLogStatusSuccess
	}

	var adminActorIDStr *uuid.UUID
	if adminUserID != nil {
		adminActorIDStr = adminUserID
	}

	currentReason := "User deleted by system."
	if reason != nil && *reason != "" {
		currentReason = *reason
	}

	auditDetails := map[string]interface{}{
		"reason": currentReason,
		"errors": strings.Join(errorsCollected, "; "),
	}

	ipAddress := "system"
	userAgent := "system"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists {
			ipAddress = val
		}
		if val, exists := md["user-agent"]; exists {
			userAgent = val
		}
	}

	s.auditLogRecorder.RecordEvent(ctx, adminActorIDStr, "system_user_delete", auditStatus, &userID, models.AuditTargetTypeUser, auditDetails, &ipAddress, &userAgent)

	if len(errorsCollected) > 0 {
		return fmt.Errorf("system delete user encountered errors for user %s: %s", userID.String(), strings.Join(errorsCollected, "; "))
	}

	s.logger.Info("SystemDeleteUser: Successfully processed deletion for user", zap.String("userID", userID.String()))
	return nil
}

// SystemLogoutAllUserSessions handles invalidating all active sessions and refresh tokens for a user.
// This is typically called by system events like admin-initiated force logout or user blocking.
func (s *AuthService) SystemLogoutAllUserSessions(ctx context.Context, userID uuid.UUID, adminUserID *uuid.UUID, reason *string) error {
	s.logger.Info("SystemLogoutAllUserSessions: Initiating for user",
		zap.String("userID", userID.String()),
		zap.Stringp("reason", reason),
	)
	if adminUserID != nil {
		s.logger.Info("SystemLogoutAllUserSessions: Initiated by admin", zap.String("adminUserID", adminUserID.String()))
	}

	var errorsCollected []string

	// 1. Delete all sessions for the user
	deletedSessionsCount, err := s.sessionService.DeleteAllUserSessions(ctx, userID, nil)
	if err != nil {
		s.logger.Error("SystemLogoutAllUserSessions: Failed to delete user sessions", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("delete sessions: %v", err))
	}
	s.logger.Info("SystemLogoutAllUserSessions: Deleted user sessions", zap.Int64("count", deletedSessionsCount), zap.String("userID", userID.String()))

	// 2. Revoke all refresh tokens
	revokedTokensCount, err := s.tokenService.RevokeAllRefreshTokensForUser(ctx, userID)
	if err != nil {
		s.logger.Error("SystemLogoutAllUserSessions: Failed to revoke refresh tokens", zap.Error(err), zap.String("userID", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("revoke refresh tokens: %v", err))
	}
	s.logger.Info("SystemLogoutAllUserSessions: Revoked refresh tokens", zap.Int64("count", revokedTokensCount), zap.String("userID", userID.String()))

	var adminActorIDStrKafka *string
	if adminUserID != nil {
		str := adminUserID.String()
		adminActorIDStrKafka = &str
	}
	allSessionsRevokedPayload := models.UserAllSessionsRevokedPayload{
		UserID:    userID.String(),
		RevokedAt: time.Now(),
		ActorID:   adminActorIDStrKafka,
	}
	subjectUserLogoutAll := userID.String()
	contentTypeJSONLogoutAll := "application/json"
	if err := s.kafkaClient.PublishCloudEvent(
		ctx,
		s.cfg.Kafka.Producer.Topic,
		kafkaEvents.EventType(models.AuthUserAllSessionsRevokedV1),
		&subjectUserLogoutAll,
		&contentTypeJSONLogoutAll,
		allSessionsRevokedPayload,
	); err != nil {
		s.logger.Error("SystemLogoutAllUserSessions: Failed to publish CloudEvent for all sessions revoked", zap.Error(err), zap.String("user_id", userID.String()))
		errorsCollected = append(errorsCollected, fmt.Sprintf("publish kafka event: %v", err))
	}

	auditStatus := models.AuditLogStatusSuccess
	if len(errorsCollected) > 0 {
		auditStatus = models.AuditLogStatusPartialSuccess
	}

	currentReason := "User sessions forcefully logged out by system."
	if reason != nil && *reason != "" {
		currentReason = *reason
	}
	auditDetails := map[string]interface{}{
		"reason":                 currentReason,
		"sessions_deleted":       deletedSessionsCount,
		"refresh_tokens_revoked": revokedTokensCount,
		"errors":                 strings.Join(errorsCollected, "; "),
	}

	ipAddress := "system"
	userAgent := "system"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists {
			ipAddress = val
		}
		if val, exists := md["user-agent"]; exists {
			userAgent = val
		}
	}

	s.auditLogRecorder.RecordEvent(ctx, adminActorIDStrKafka, "system_user_logout_all_sessions", auditStatus, &userID, models.AuditTargetTypeUser, auditDetails, &ipAddress, &userAgent)

	if len(errorsCollected) > 0 {
		return fmt.Errorf("system logout all user sessions encountered errors for user %s: %s", userID.String(), strings.Join(errorsCollected, "; "))
	}

	s.logger.Info("SystemLogoutAllUserSessions: Successfully processed for user", zap.String("userID", userID.String()))
	return nil
}
