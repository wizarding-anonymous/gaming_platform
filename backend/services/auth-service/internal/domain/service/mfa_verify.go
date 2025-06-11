// File: backend/services/auth-service/internal/domain/service/mfa_verify.go
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	kafkaPkg "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
)

// Verify2FACode implements MFALogicService.
func (s *mfaLogicService) Verify2FACode(ctx context.Context, userID uuid.UUID, code string, codeType models.MFAType) (bool, error) {
	actorAndTargetID := &userID
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists {
			ipAddress = val
		}
		if val, exists := md["user-agent"]; exists {
			userAgent = val
		}
	}
	var auditDetails = make(map[string]interface{})
	auditDetails["code_type"] = string(codeType)

	rateLimitRule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser
	if rateLimitRule.Enabled {
		rateKey := "2faverify_user:" + userID.String()
		allowed, rlErr := s.rateLimiter.Allow(ctx, rateKey, rateLimitRule)
		if rlErr != nil {
			auditDetails["warning_rate_limit_check_failed"] = rlErr.Error()
		}
		if !allowed {
			auditDetails["error"] = domainErrors.ErrRateLimitExceeded.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, domainErrors.ErrRateLimitExceeded
		}
	}

	if codeType == models.MFATypeTOTP {
		mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
		if err != nil {
			if errors.Is(err, domainErrors.ErrNotFound) {
				auditDetails["error"] = domainErrors.Err2FANotEnabled.Error()
				s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
				return false, domainErrors.Err2FANotEnabled
			}
			auditDetails["error"] = "error fetching TOTP secret"
			auditDetails["details"] = err.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, fmt.Errorf("error fetching TOTP secret: %w", err)
		}
		if !mfaSecret.Verified {
			auditDetails["error"] = domainErrors.ErrMFANotVerified.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, domainErrors.ErrMFANotVerified
		}
		decryptedSecret, err := s.encryptionService.Decrypt(mfaSecret.SecretKeyEncrypted, s.cfg.MFA.TOTPSecretEncryptionKey)
		if err != nil {
			auditDetails["error"] = "failed to decrypt TOTP secret"
			auditDetails["details"] = err.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
		}
		isValid, err := s.totpService.ValidateCode(decryptedSecret, code)
		if err != nil {
			auditDetails["error"] = "error validating TOTP code"
			auditDetails["details"] = err.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, fmt.Errorf("error validating TOTP code: %w", err)
		}
		if !isValid {
			auditDetails["error"] = domainErrors.ErrInvalid2FACode.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		} else {
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		}
		return isValid, nil
	} else if codeType == models.MFATypeBackup {
		allBackupCodes, err := s.mfaBackupCodeRepo.FindByUserID(ctx, userID)
		if err != nil {
			auditDetails["error"] = "failed to retrieve backup codes for verification"
			auditDetails["details"] = err.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, fmt.Errorf("failed to retrieve backup codes: %w", err)
		}

		var validBackupCode *models.MFABackupCode
		for _, bc := range allBackupCodes {
			match, checkErr := s.passwordService.CheckPasswordHash(code, bc.CodeHash)
			if checkErr != nil {
				continue
			}
			if match {
				validBackupCode = bc
				break
			}
		}

		if validBackupCode == nil {
			auditDetails["error"] = domainErrors.ErrInvalid2FACode.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, domainErrors.ErrInvalid2FACode
		}

		if err := s.mfaBackupCodeRepo.MarkAsUsed(ctx, validBackupCode.ID, time.Now()); err != nil {
			auditDetails["error"] = "failed to mark backup code as used"
			auditDetails["details"] = err.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, fmt.Errorf("failed to mark backup code as used: %w", err)
		}
		auditDetails["backup_code_id_used"] = validBackupCode.ID.String()
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return true, nil
	}
	auditDetails["error"] = "unsupported 2FA code type"
	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return false, fmt.Errorf("unsupported 2FA code type: %s", codeType)
}

// Disable2FA implements MFALogicService.
func (s *mfaLogicService) Disable2FA(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) error {
	actorAndTargetID := &userID
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists {
			ipAddress = val
		}
		if val, exists := md["user-agent"]; exists {
			userAgent = val
		}
	}
	var auditDetails map[string]interface{}

	authorized, err := s.isUserAuthorizedForSensitiveAction(ctx, userID, verificationToken, verificationMethod)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "authorization check failed", "details": err.Error(), "verification_method": verificationMethod}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable_authfail", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}
	if !authorized {
		auditDetails = map[string]interface{}{"error": domainErrors.ErrForbidden.Error(), "reason": "authorization failed", "verification_method": verificationMethod}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable_authfail", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrForbidden
	}

	deletedSecrets, err := s.mfaSecretRepo.DeleteAllForUser(ctx, userID)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "failed to delete MFA secrets", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return fmt.Errorf("failed to delete MFA secrets: %w", err)
	}
	deletedBackupCodes, err := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "failed to delete MFA backup codes", "details": err.Error(), "secrets_deleted_count": deletedSecrets}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return fmt.Errorf("failed to delete MFA backup codes: %w", err)
	}

	auditDetails = map[string]interface{}{"secrets_deleted_count": deletedSecrets, "backup_codes_deleted_count": deletedBackupCodes}
	if deletedSecrets > 0 || deletedBackupCodes > 0 {
		disabledAt := time.Now()
		mfaDisabledPayload := models.MFADisabledPayload{
			UserID:     userID.String(),
			MFAType:    string(models.MFATypeTOTP),
			DisabledAt: disabledAt,
		}
		subjectMFADisabled := userID.String()
		contentTypeJSON := "application/json"
		if err := s.kafkaProducer.PublishCloudEvent(
			ctx,
			"auth-events",
			kafkaPkg.EventType(models.AuthMFADisabledV1),
			&subjectMFADisabled,
			&contentTypeJSON,
			mfaDisabledPayload,
		); err != nil {
			auditDetails["warning_cloudevent_publish"] = err.Error()
		}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	} else {
		auditDetails["info"] = domainErrors.Err2FANotEnabled.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	}
	return nil
}

func (s *mfaLogicService) isUserAuthorizedForSensitiveAction(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) (bool, error) {
	switch verificationMethod {
	case "password":
		user, err := s.userRepo.FindByID(ctx, userID)
		if err != nil {
			return false, domainErrors.ErrUserNotFound
		}
		match, err := s.passwordService.CheckPasswordHash(verificationToken, user.PasswordHash)
		if err != nil {
			return false, fmt.Errorf("error checking password for sensitive action: %w", err)
		}
		return match, nil
	case "totp":
		valid, err := s.Verify2FACode(ctx, userID, verificationToken, models.MFATypeTOTP)
		if err != nil {
			if errors.Is(err, domainErrors.ErrInvalid2FACode) {
				return s.Verify2FACode(ctx, userID, verificationToken, models.MFATypeBackup)
			}
			return false, err
		}
		return valid, nil
	case "backup":
		return s.Verify2FACode(ctx, userID, verificationToken, models.MFATypeBackup)
	default:
		return false, fmt.Errorf("invalid verification method for sensitive action: %s", verificationMethod)
	}
}
