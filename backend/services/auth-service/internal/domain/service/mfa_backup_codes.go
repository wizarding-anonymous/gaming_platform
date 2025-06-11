// File: backend/services/auth-service/internal/domain/service/mfa_backup_codes.go
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"
)

// RegenerateBackupCodes implements MFALogicService.
func (s *mfaLogicService) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) ([]string, error) {
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
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, err
	}
	if !authorized {
		auditDetails = map[string]interface{}{"error": domainErrors.ErrForbidden.Error(), "reason": "authorization failed", "verification_method": verificationMethod}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, domainErrors.ErrForbidden
	}

	mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
	if err != nil {
		errReason := "error fetching mfa secret"
		if errors.Is(err, domainErrors.ErrNotFound) {
			errReason = domainErrors.Err2FANotEnabled.Error()
		}
		auditDetails = map[string]interface{}{"error": errReason, "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		if errors.Is(err, domainErrors.ErrNotFound) {
			return nil, domainErrors.Err2FANotEnabled
		}
		return nil, fmt.Errorf("error fetching mfa secret: %w", err)
	}
	if !mfaSecret.Verified {
		auditDetails = map[string]interface{}{"error": domainErrors.ErrMFANotVerified.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, domainErrors.ErrMFANotVerified
	}

	if _, errDel := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID); errDel != nil {
		auditDetails = map[string]interface{}{"error": "could not delete old backup codes", "details": errDel.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, fmt.Errorf("could not delete old backup codes: %w", errDel)
	}

	plainBackupCodes := make([]string, s.cfg.MFA.TOTPBackupCodeCount)
	backupCodesToStore := make([]*models.MFABackupCode, s.cfg.MFA.TOTPBackupCodeCount)
	for i := 0; i < s.cfg.MFA.TOTPBackupCodeCount; i++ {
		codeStr, errGen := security.GenerateSecureToken(6)
		if errGen != nil {
			auditDetails = map[string]interface{}{"error": "failed to generate backup code string", "details": errGen.Error()}
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return nil, fmt.Errorf("failed to generate backup code string: %w", errGen)
		}
		plainBackupCodes[i] = codeStr
		hashedCode, errHash := s.passwordService.HashPassword(codeStr)
		if errHash != nil {
			auditDetails = map[string]interface{}{"error": "failed to hash backup code", "details": errHash.Error()}
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return nil, fmt.Errorf("failed to hash backup code %d: %w", i+1, errHash)
		}
		backupCodesToStore[i] = &models.MFABackupCode{ID: uuid.New(), UserID: userID, CodeHash: hashedCode}
	}

	if errCreate := s.mfaBackupCodeRepo.CreateMultiple(ctx, backupCodesToStore); errCreate != nil {
		auditDetails = map[string]interface{}{"error": "failed to store regenerated backup codes", "details": errCreate.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return nil, fmt.Errorf("failed to store regenerated backup codes: %w", errCreate)
	}

	auditDetails = map[string]interface{}{"backup_codes_generated": len(plainBackupCodes)}
	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return plainBackupCodes, nil
}

func (s *mfaLogicService) GetActiveBackupCodeCount(ctx context.Context, userID uuid.UUID) (int, error) {
	actorAndTargetID := &userID
	ipAddress, userAgent := getIPAndUserAgentFromCtx(ctx)
	var auditDetails = make(map[string]interface{})

	mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			auditDetails["error"] = domainErrors.Err2FANotEnabled.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_get_backup_code_count", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return 0, domainErrors.Err2FANotEnabled
		}
		auditDetails["error"] = "failed to fetch mfa secret"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_get_backup_code_count", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return 0, fmt.Errorf("error fetching mfa secret: %w", err)
	}
	if !mfaSecret.Verified {
		auditDetails["error"] = domainErrors.ErrMFANotVerified.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_get_backup_code_count", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return 0, domainErrors.ErrMFANotVerified
	}

	count, err := s.mfaBackupCodeRepo.CountActiveByUserID(ctx, userID)
	if err != nil {
		auditDetails["error"] = "failed to count active backup codes"
		auditDetails["details"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_get_backup_code_count", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return 0, fmt.Errorf("failed to count active backup codes: %w", err)
	}

	auditDetails["active_backup_code_count"] = count
	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_get_backup_code_count", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return count, nil
}
