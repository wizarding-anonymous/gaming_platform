package service

import (
	"context"
	"crypto/rand"
	"errors" // Standard errors
	"fmt"
	// "math/big" // No longer needed for placeholder backup code generation
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/config" // For MFAConfig
	"github.com/your-org/auth-service/internal/domain/models"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces" // Corrected path
	"github.com/your-org/auth-service/internal/infrastructure/security"
	// Kafka client if events are published directly from here
)

// MFALogicService defines the interface for Multi-Factor Authentication business logic.
type MFALogicService interface {
	// Enable2FAInitiate starts the process of enabling 2FA for a user.
	// It generates a new TOTP secret and a URL for QR code generation.
	// The secret returned is the raw base32 secret.
	Enable2FAInitiate(ctx context.Context, userID uuid.UUID, accountName string) (mfaSecretID uuid.UUID, secretBase32 string, otpAuthURL string, err error)

	// VerifyAndActivate2FA verifies the initial TOTP code provided by the user and activates 2FA.
	// It also generates and returns plain text backup codes.
	// mfaSecretID is the ID of the mfa_secrets record from the initiate step.
	VerifyAndActivate2FA(ctx context.Context, userID uuid.UUID, plainTOTPCode string, mfaSecretID uuid.UUID) (backupCodes []string, err error)

	// Verify2FACode checks a TOTP code or a backup code during login or other sensitive operations.
	// userID is the ID of the user attempting to verify.
	// code is the plain code provided by the user.
	// codeType indicates if it's a "totp" or "backup" code.
	Verify2FACode(ctx context.Context, userID uuid.UUID, code string, codeType models.MFAType) (isValid bool, err error)

	// Disable2FA disables 2FA for a user after proper verification (e.g., password or current 2FA code).
	// verificationToken could be a password or a currently valid 2FA code.
	// verificationMethod indicates how the user is authorizing this disable action ("password", "totp", "backup").
	Disable2FA(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) error

	// RegenerateBackupCodes generates a new set of backup codes for the user after proper verification.
	RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) (backupCodes []string, err error)
}

// mfaLogicService implements MFALogicService.
type mfaLogicService struct {
	cfg                   *config.MFAConfig
	totpService           TOTPService
	encryptionService     security.EncryptionService
	mfaSecretRepo         repoInterfaces.MFASecretRepository
	mfaBackupCodeRepo     repoInterfaces.MFABackupCodeRepository
	userRepo              repoInterfaces.UserRepository
	passwordService       PasswordService
	auditLogRecorder      AuditLogRecorder // Added for audit logging
	// kafkaProducer      *kafka.Client
}


// NewMFALogicService creates a new instance of MFALogicService.
func NewMFALogicService(
	cfg *config.MFAConfig,
	totpService TOTPService,
	encryptionService security.EncryptionService,
	mfaSecretRepo repoInterfaces.MFASecretRepository,
	mfaBackupCodeRepo repoInterfaces.MFABackupCodeRepository,
	userRepo repoInterfaces.UserRepository,
	passwordService PasswordService,
	auditLogRecorder AuditLogRecorder, // Added
	// kafkaProducer *kafka.Client,
) MFALogicService {
	return &mfaLogicService{
		cfg:                   cfg,
		totpService:           totpService,
		encryptionService:     encryptionService,
		mfaSecretRepo:         mfaSecretRepo,
		mfaBackupCodeRepo:     mfaBackupCodeRepo,
		userRepo:              userRepo,
		passwordService:       passwordService,
		auditLogRecorder:      auditLogRecorder, // Added
		// kafkaProducer:      kafkaProducer,
	}
}

// TempEncryptionKey is a placeholder. In a real app, this comes from secure config.
// const TempEncryptionKey = "a-very-secure-32-byte-key-here" // MUST BE REPLACED // This will be removed

// Enable2FAInitiate implements MFALogicService.
func (s *mfaLogicService) Enable2FAInitiate(ctx context.Context, userID uuid.UUID, accountName string) (uuid.UUID, string, string, error) {
	actorAndTargetID := &userID
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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

	secretBase32, otpAuthURL, err := s.totpService.GenerateSecret(accountName, s.cfg.TOTPIssuerName)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "failed to generate TOTP secret", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_initiate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return uuid.Nil, "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	encryptedSecret, err := s.encryptionService.Encrypt(secretBase32, s.cfg.TOTPSecretEncryptionKey)
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
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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
		if errors.Is(err, domainErrors.ErrNotFound) { return nil, domainErrors.ErrNotFound }
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
		// This is a failure in completing the process, even if code was valid.
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeMFASecret, auditDetails, ipAddress, userAgent)
		return nil, fmt.Errorf("failed to mark MFA secret as verified: %w", err)
	}

	if _, err := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID); err != nil {
		// s.logger.Error("Failed to delete old backup codes during 2FA activation", zap.Error(err), zap.String("userID", userID.String()))
		// Non-critical for activation itself, can be logged as warning with success event.
		auditDetails = map[string]interface{}{"warning": "failed to delete old backup codes", "details": err.Error()}
	}

	plainBackupCodes := make([]string, s.cfg.TOTPBackupCodeCount)
	backupCodesToStore := make([]*models.MFABackupCode, s.cfg.TOTPBackupCodeCount)
	for i := 0; i < s.cfg.TOTPBackupCodeCount; i++ {
		codeStr, errGen := security.GenerateSecureToken(6)
		if errGen != nil {
			logDetails := map[string]interface{}{"error": "failed to generate backup code string", "details": errGen.Error()}
			if auditDetails != nil { for k,v := range auditDetails { logDetails[k] = v } } // merge
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusPartialSuccess, actorAndTargetID, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
			return nil, fmt.Errorf("failed to generate backup code string: %w", errGen)
		}
		plainBackupCodes[i] = codeStr
		hashedCode, errHash := s.passwordService.HashPassword(codeStr)
		if errHash != nil {
			logDetails := map[string]interface{}{"error": "failed to hash backup code", "details": errHash.Error()}
			if auditDetails != nil { for k,v := range auditDetails { logDetails[k] = v } }
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusPartialSuccess, actorAndTargetID, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
			return nil, fmt.Errorf("failed to hash backup code %d: %w", i+1, errHash)
		}
		backupCodesToStore[i] = &models.MFABackupCode{ID: uuid.New(), UserID: userID, CodeHash: hashedCode}
	}

	if err := s.mfaBackupCodeRepo.CreateMultiple(ctx, backupCodesToStore); err != nil {
		logDetails := map[string]interface{}{"error": "2FA activated, but failed to store backup codes", "details": err.Error()}
		if auditDetails != nil { for k,v := range auditDetails { logDetails[k] = v } } // merge
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusPartialSuccess, actorAndTargetID, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
		return nil, fmt.Errorf("2FA activated, but failed to store backup codes: %w", err)
	}

	// TODO: Publish auth.2fa.enabled Kafka event (UserID, Type: TOTP, ActivatedAt)
	if auditDetails == nil { auditDetails = make(map[string]interface{})} // Ensure not nil
	auditDetails["mfa_secret_id"] = mfaSecretID.String()
	auditDetails["mfa_type"] = models.MFATypeTOTP
	auditDetails["backup_codes_generated"] = len(plainBackupCodes)
	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return plainBackupCodes, nil
}


// Verify2FACode implements MFALogicService.
func (s *mfaLogicService) Verify2FACode(ctx context.Context, userID uuid.UUID, code string, codeType models.MFAType) (bool, error) {
	if codeType == models.MFATypeTOTP {
		mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
		if err != nil {
			if errors.Is(err, domainErrors.ErrNotFound) {
				return false, domainErrors.Err2FANotEnabled // No TOTP setup for user
			}
			return false, fmt.Errorf("error fetching TOTP secret: %w", err)
		}
		if !mfaSecret.Verified {
			return false, domainErrors.ErrMFANotVerified // TOTP setup not completed/verified
		}
		decryptedSecret, err := s.encryptionService.Decrypt(mfaSecret.SecretKeyEncrypted, s.cfg.TOTPSecretEncryptionKey)
		if err != nil {
			return false, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
		}
		isValid, err := s.totpService.ValidateCode(decryptedSecret, code)
		if err != nil {
			return false, fmt.Errorf("error validating TOTP code: %w", err)
		}
		return isValid, nil
	} else if codeType == "backup" {
		hashedCode, err := s.passwordService.HashPassword(code)
		if err != nil {
			return false, fmt.Errorf("failed to hash backup code for verification: %w", err)
		}
		backupCode, err := s.mfaBackupCodeRepo.FindByUserIDAndCodeHash(ctx, userID, hashedCode)
		if err != nil {
			if errors.Is(err, domainErrors.ErrNotFound) {
				return false, domainErrors.ErrInvalid2FACode // Backup code not found
			}
			return false, fmt.Errorf("error retrieving backup code: %w", err)
		}
		// FindByUserIDAndCodeHash in repo already checks if UsedAt IS NULL

		// Mark as used
		if err := s.mfaBackupCodeRepo.MarkAsUsed(ctx, backupCode.ID, time.Now()); err != nil {
			return false, fmt.Errorf("failed to mark backup code as used: %w", err)
		}
		// TODO: Publish event: auth.2fa.backup_code_used (UserID, BackupCodeID)
		return true, nil
	}
	return false, fmt.Errorf("unsupported 2FA code type: %s", codeType)
}

// Disable2FA implements MFALogicService.
func (s *mfaLogicService) Disable2FA(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) error {
	actorAndTargetID := &userID
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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
		// TODO: Publish auth.2fa.disabled Kafka event (UserID, DisabledAt)
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	} else {
		auditDetails["info"] = domainErrors.Err2FANotEnabled.Error() // Add info that nothing was enabled
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		// return domainErrors.Err2FANotEnabled // Returning success as the state is "disabled"
	}
	return nil
}

// RegenerateBackupCodes implements MFALogicService.
func (s *mfaLogicService) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) ([]string, error) {
	actorAndTargetID := &userID
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
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
		if errors.Is(err, domainErrors.ErrNotFound) { errReason = domainErrors.Err2FANotEnabled.Error() }
		auditDetails = map[string]interface{}{"error": errReason, "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		if errors.Is(err, domainErrors.ErrNotFound) { return nil, domainErrors.Err2FANotEnabled }
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

	plainBackupCodes := make([]string, s.cfg.TOTPBackupCodeCount)
	backupCodesToStore := make([]*models.MFABackupCode, s.cfg.TOTPBackupCodeCount)
	for i := 0; i < s.cfg.TOTPBackupCodeCount; i++ {
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

	// TODO: Publish event: auth.2fa.backup_codes_regenerated (UserID, Count)
	auditDetails = map[string]interface{}{"backup_codes_generated": len(plainBackupCodes)}
	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_backup_codes_regenerate", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return plainBackupCodes, nil
}

// isUserAuthorizedForSensitiveAction checks if the user is authorized via password or a current 2FA code.
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
		return s.Verify2FACode(ctx, userID, verificationToken, models.MFATypeTOTP)
	case "backup":
		// Note: Verify2FACode for backup codes marks them as used.
		// This means a backup code can only authorize one sensitive action.
		// If multiple actions are needed in a short timeframe, this could be an issue.
		// Consider if a "peek" validation is needed for authorization without consuming the code.
		return s.Verify2FACode(ctx, userID, verificationToken, models.MFATypeBackup) // Use models.MFATypeBackup
	default:
		return false, fmt.Errorf("invalid verification method for sensitive action: %s", verificationMethod)
	}
}


// Ensure mfaLogicService implements MFALogicService (compile-time check).
var _ MFALogicService = (*mfaLogicService)(nil)
