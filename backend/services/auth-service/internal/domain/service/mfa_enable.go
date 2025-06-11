// File: backend/services/auth-service/internal/domain/service/mfa_enable.go
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
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"
)

// Enable2FAInitiate implements MFALogicService.
func (s *mfaLogicService) Enable2FAInitiate(ctx context.Context, userID uuid.UUID, accountName string) (uuid.UUID, string, string, error) {
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

	// 1. Check if 2FA is already enabled and verified
	existingSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
	if err == nil && existingSecret != nil {
		if existingSecret.Verified {
			auditDetails = map[string]interface{}{"error": domainErrors.Err2FAAlreadyEnabled.Error()}
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_initiate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return uuid.Nil, "", "", domainErrors.Err2FAAlreadyEnabled
		}
		deleted, delErr := s.mfaSecretRepo.DeleteByUserIDAndTypeIfUnverified(ctx, userID, models.MFATypeTOTP)
		if delErr != nil {
			auditDetails = map[string]interface{}{"error": "failed to clear previous unverified MFA setup", "details": delErr.Error()}
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_initiate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return uuid.Nil, "", "", fmt.Errorf("failed to clear previous unverified MFA setup: %w", delErr)
		}
		if deleted {
			// s.logger.Info("Deleted previous unverified MFA secret for user", zap.String("userID", userID.String()))
		}
	} else if !errors.Is(err, domainErrors.ErrNotFound) {
		auditDetails = map[string]interface{}{"error": "error checking existing MFA secret", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_initiate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return uuid.Nil, "", "", fmt.Errorf("error checking existing MFA secret: %w", err)
	}

	secretBase32, otpAuthURL, err := s.totpService.GenerateSecret(accountName, s.cfg.MFA.TOTPIssuerName)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "failed to generate TOTP secret", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_initiate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return uuid.Nil, "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	encryptedSecret, err := s.encryptionService.Encrypt(secretBase32, s.cfg.MFA.TOTPSecretEncryptionKey)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "failed to encrypt TOTP secret", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_initiate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return uuid.Nil, "", "", fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	mfaSecretIDToStore := uuid.New()
	newSecret := &models.MFASecret{
		ID:                 mfaSecretIDToStore,
		UserID:             userID,
		Type:               models.MFATypeTOTP,
		SecretKeyEncrypted: encryptedSecret,
		Verified:           false,
	}
	if err = s.mfaSecretRepo.Create(ctx, newSecret); err != nil {
		auditDetails = map[string]interface{}{"error": "failed to store new MFA secret", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_initiate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return uuid.Nil, "", "", fmt.Errorf("failed to store new MFA secret: %w", err)
	}

	auditDetails = map[string]interface{}{"mfa_secret_id": mfaSecretIDToStore.String(), "mfa_type": models.MFATypeTOTP}
	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_initiate", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return mfaSecretIDToStore, secretBase32, otpAuthURL, nil
}

func (s *mfaLogicService) VerifyAndActivate2FA(ctx context.Context, userID uuid.UUID, plainTOTPCode string, mfaSecretID uuid.UUID) ([]string, error) {
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

	mfaSecret, err := s.mfaSecretRepo.FindByID(ctx, mfaSecretID)
	if err != nil {
		errReason := "failed to retrieve MFA secret"
		if errors.Is(err, domainErrors.ErrNotFound) {
			errReason = domainErrors.ErrNotFound.Error()
		}
		auditDetails = map[string]interface{}{"error": errReason, "mfa_secret_id": mfaSecretID.String(), "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_verify_code", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeMFASecret, auditDetails, ipAddress, userAgent)
		if errors.Is(err, domainErrors.ErrNotFound) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to retrieve MFA secret %s: %w", mfaSecretID, err)
	}

	if mfaSecret.Verified {
		auditDetails = map[string]interface{}{"error": domainErrors.Err2FAAlreadyEnabled.Error(), "mfa_secret_id": mfaSecretID.String()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_verify_code", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeMFASecret, auditDetails, ipAddress, userAgent)
		return nil, domainErrors.Err2FAAlreadyEnabled
	}
	if mfaSecret.UserID != userID {
		auditDetails = map[string]interface{}{"error": domainErrors.ErrForbidden.Error(), "reason": "MFA secret does not belong to user", "mfa_secret_id": mfaSecretID.String()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_verify_code", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeMFASecret, auditDetails, ipAddress, userAgent)
		return nil, domainErrors.ErrForbidden
	}
	if mfaSecret.Type != models.MFATypeTOTP {
		auditDetails = map[string]interface{}{"error": "invalid MFA secret type for TOTP verification", "mfa_secret_id": mfaSecretID.String(), "type_found": mfaSecret.Type}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_verify_code", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeMFASecret, auditDetails, ipAddress, userAgent)
		return nil, errors.New("invalid MFA secret type for TOTP verification")
	}

	decryptedSecret, err := s.encryptionService.Decrypt(mfaSecret.SecretKeyEncrypted, s.cfg.TOTPSecretEncryptionKey)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "failed to decrypt TOTP secret", "mfa_secret_id": mfaSecretID.String(), "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_verify_code", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeMFASecret, auditDetails, ipAddress, userAgent)
		return nil, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	isValid, err := s.totpService.ValidateCode(decryptedSecret, plainTOTPCode)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "error validating TOTP code", "mfa_secret_id": mfaSecretID.String(), "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_verify_code", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeMFASecret, auditDetails, ipAddress, userAgent)
		return nil, fmt.Errorf("error validating TOTP code: %w", err)
	}
	if !isValid {
		auditDetails = map[string]interface{}{"error": domainErrors.ErrInvalid2FACode.Error(), "mfa_secret_id": mfaSecretID.String()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_verify_code", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeMFASecret, auditDetails, ipAddress, userAgent)
		return nil, domainErrors.ErrInvalid2FACode
	}

	mfaSecret.Verified = true
	if err := s.mfaSecretRepo.Update(ctx, mfaSecret); err != nil {
		auditDetails = map[string]interface{}{"error": "failed to mark MFA secret as verified", "mfa_secret_id": mfaSecretID.String(), "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeMFASecret, auditDetails, ipAddress, userAgent)
		return nil, fmt.Errorf("failed to mark MFA secret as verified: %w", err)
	}

	if _, err := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID); err != nil {
		auditDetails = map[string]interface{}{"warning": "failed to delete old backup codes", "details": err.Error()}
	}

	plainBackupCodes := make([]string, s.cfg.MFA.TOTPBackupCodeCount)
	backupCodesToStore := make([]*models.MFABackupCode, s.cfg.MFA.TOTPBackupCodeCount)
	for i := 0; i < s.cfg.MFA.TOTPBackupCodeCount; i++ {
		codeStr, errGen := security.GenerateSecureToken(6)
		if errGen != nil {
			logDetails := map[string]interface{}{"error": "failed to generate backup code string", "details": errGen.Error()}
			if auditDetails != nil {
				for k, v := range auditDetails {
					logDetails[k] = v
				}
			}
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusPartialSuccess, actorAndTargetID, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
			return nil, fmt.Errorf("failed to generate backup code string: %w", errGen)
		}
		plainBackupCodes[i] = codeStr
		hashedCode, errHash := s.passwordService.HashPassword(codeStr)
		if errHash != nil {
			logDetails := map[string]interface{}{"error": "failed to hash backup code", "details": errHash.Error()}
			if auditDetails != nil {
				for k, v := range auditDetails {
					logDetails[k] = v
				}
			}
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusPartialSuccess, actorAndTargetID, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
			return nil, fmt.Errorf("failed to hash backup code %d: %w", i+1, errHash)
		}
		backupCodesToStore[i] = &models.MFABackupCode{ID: uuid.New(), UserID: userID, CodeHash: hashedCode}
	}

	if err := s.mfaBackupCodeRepo.CreateMultiple(ctx, backupCodesToStore); err != nil {
		logDetails := map[string]interface{}{"error": "2FA activated, but failed to store backup codes", "details": err.Error()}
		if auditDetails != nil {
			for k, v := range auditDetails {
				logDetails[k] = v
			}
		}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusPartialSuccess, actorAndTargetID, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
		return nil, fmt.Errorf("2FA activated, but failed to store backup codes: %w", err)
	}

	enabledAt := time.Now()
	mfaEnabledPayload := models.MFAEnabledPayload{
		UserID:    userID.String(),
		MFAType:   string(models.MFATypeTOTP),
		EnabledAt: enabledAt,
	}
	subjectMFAEnabled := userID.String()
	contentTypeJSON := "application/json"
	if err := s.kafkaProducer.PublishCloudEvent(
		ctx,
		"auth-events",
		kafkaPkg.EventType(models.AuthMFAEnabledV1),
		&subjectMFAEnabled,
		&contentTypeJSON,
		mfaEnabledPayload,
	); err != nil {
		if auditDetails == nil {
			auditDetails = make(map[string]interface{})
		}
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	if auditDetails == nil {
		auditDetails = make(map[string]interface{})
	}
	auditDetails["mfa_secret_id"] = mfaSecretID.String()
	auditDetails["mfa_type"] = string(models.MFATypeTOTP)
	auditDetails["backup_codes_generated"] = len(plainBackupCodes)
	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return plainBackupCodes, nil
}
