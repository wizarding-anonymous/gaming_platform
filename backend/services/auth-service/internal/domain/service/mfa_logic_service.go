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
		// kafkaProducer:      kafkaProducer,
	}
}

// TempEncryptionKey is a placeholder. In a real app, this comes from secure config.
// const TempEncryptionKey = "a-very-secure-32-byte-key-here" // MUST BE REPLACED // This will be removed

func (s *mfaLogicService) Enable2FAInitiate(ctx context.Context, userID uuid.UUID, accountName string) (uuid.UUID, string, string, error) {
	// 1. Check if 2FA is already enabled and verified
	existingSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
	if err == nil && existingSecret != nil {
		if existingSecret.Verified {
			// s.logger.Warn("Attempt to initiate 2FA for user with already verified secret", zap.String("userID", userID.String()))
			return uuid.Nil, "", "", domainErrors.Err2FAAlreadyEnabled // Use a domain error
		}
		// If an unverified secret exists, delete it before creating a new one.
		// This simplifies logic by not requiring an "upsert" or handling multiple unverified secrets.
		deleted, delErr := s.mfaSecretRepo.DeleteByUserIDAndTypeIfUnverified(ctx, userID, models.MFATypeTOTP)
		if delErr != nil {
			// s.logger.Error("Failed to delete existing unverified MFA secret", zap.Error(delErr), zap.String("userID", userID.String()))
			return uuid.Nil, "", "", fmt.Errorf("failed to clear previous unverified MFA setup: %w", delErr)
		}
		if deleted {
			// s.logger.Info("Deleted previous unverified MFA secret for user", zap.String("userID", userID.String()))
		}
	} else if !errors.Is(err, domainErrors.ErrNotFound) {
        // Handle other errors from FindByUserIDAndType, except NotFound which is fine
        // s.logger.Error("Failed to check for existing MFA secret", zap.Error(err), zap.String("userID", userID.String()))
        return uuid.Nil, "", "", fmt.Errorf("error checking existing MFA secret: %w", err)
    }


	// 2. Generate new TOTP secret and QR code
	// If issuerName is not provided, TOTPService might use a default from its own config
	secretBase32, otpAuthURL, err := s.totpService.GenerateSecret(accountName, s.cfg.TOTPIssuerName)
	if err != nil {
		return uuid.Nil, "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// 3. Encrypt the secret before storing
	encryptedSecret, err := s.encryptionService.Encrypt(secretBase32, s.cfg.TOTPSecretEncryptionKey)
	if err != nil {
		return uuid.Nil, "", "", fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	mfaSecretID := uuid.New()
	// 4. Create the new secret (previous unverified one, if any, is now deleted)
	mfaSecretIDToStore := uuid.New()
	newSecret := &models.MFASecret{
		ID:                 mfaSecretIDToStore,
		UserID:             userID,
		Type:               models.MFATypeTOTP,
		SecretKeyEncrypted: encryptedSecret,
		Verified:           false,
	}
	if err = s.mfaSecretRepo.Create(ctx, newSecret); err != nil {
		return uuid.Nil, "", "", fmt.Errorf("failed to store new MFA secret: %w", err)
	}

	return mfaSecretIDToStore, secretBase32, otpAuthURL, nil
}

func (s *mfaLogicService) VerifyAndActivate2FA(ctx context.Context, userID uuid.UUID, plainTOTPCode string, mfaSecretID uuid.UUID) ([]string, error) {
	// 1. Retrieve the pending MFA secret by its ID
	mfaSecret, err := s.mfaSecretRepo.FindByID(ctx, mfaSecretID)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			return nil, domainErrors.ErrNotFound // Or specific "MFA setup intent not found"
		}
		return nil, fmt.Errorf("failed to retrieve MFA secret %s: %w", mfaSecretID, err)
	}

	if mfaSecret.Verified {
		return nil, domainErrors.Err2FAAlreadyEnabled
	}
	if mfaSecret.UserID != userID {
		return nil, domainErrors.ErrForbidden // Secret does not belong to user
	}
	if mfaSecret.Type != models.MFATypeTOTP {
		return nil, errors.New("invalid MFA secret type for TOTP verification")
	}

	// 2. Decrypt the secret
	decryptedSecret, err := s.encryptionService.Decrypt(mfaSecret.SecretKeyEncrypted, s.cfg.TOTPSecretEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// 3. Validate the TOTP code
	isValid, err := s.totpService.ValidateCode(decryptedSecret, totpCode)
	if err != nil {
		return nil, fmt.Errorf("error validating TOTP code: %w", err)
	}
	if !isValid {
		return nil, domainErrors.ErrInvalid2FACode
	}

	// 4. Mark MFA as verified and active
	mfaSecret.Verified = true
	if err := s.mfaSecretRepo.Update(ctx, mfaSecret); err != nil {
		return nil, fmt.Errorf("failed to mark MFA secret as verified: %w", err)
	}

	// 5. Generate and store backup codes
	if _, err := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID); err != nil {
		// s.logger.Error("Failed to delete old backup codes during 2FA activation", zap.Error(err), zap.String("userID", userID.String()))
	}

	plainBackupCodes := make([]string, s.cfg.TOTPBackupCodeCount)
	backupCodesToStore := make([]*models.MFABackupCode, s.cfg.TOTPBackupCodeCount)

	for i := 0; i < s.cfg.TOTPBackupCodeCount; i++ {
		codeStr, errGen := security.GenerateSecureToken(6)
		if errGen != nil {
			return nil, fmt.Errorf("failed to generate backup code string: %w", errGen)
		}
		plainBackupCodes[i] = codeStr

		hashedCode, errHash := s.passwordService.HashPassword(codeStr)
		if errHash != nil {
			return nil, fmt.Errorf("failed to hash backup code %d: %w", i+1, errHash)
		}
		backupCodesToStore[i] = &models.MFABackupCode{
			ID:        uuid.New(),
			UserID:    userID,
			CodeHash:  hashedCode,
		}
	}

	if err := s.mfaBackupCodeRepo.CreateMultiple(ctx, backupCodesToStore); err != nil {
		return nil, fmt.Errorf("2FA activated, but failed to store backup codes: %w", err)
	}

	// TODO: Publish auth.2fa.enabled Kafka event (UserID, Type: TOTP, ActivatedAt)

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
	authorized, err := s.isUserAuthorizedForSensitiveAction(ctx, userID, verificationToken, verificationMethod)
	if err != nil { return err }
	if !authorized { return domainErrors.ErrForbidden }


	deletedSecrets, err := s.mfaSecretRepo.DeleteAllForUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to delete MFA secrets: %w", err)
	}
	deletedBackupCodes, err := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to delete MFA backup codes: %w", err)
	}

	if deletedSecrets > 0 || deletedBackupCodes > 0 {
		// TODO: Publish auth.2fa.disabled Kafka event (UserID, DisabledAt)
	} else {
		// No 2FA was active to disable
		return domainErrors.Err2FANotEnabled
	}
	return nil
}

// RegenerateBackupCodes implements MFALogicService.
func (s *mfaLogicService) RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) ([]string, error) {
	authorized, err := s.isUserAuthorizedForSensitiveAction(ctx, userID, verificationToken, verificationMethod)
	if err != nil { return nil, err }
	if !authorized { return nil, domainErrors.ErrForbidden }

	// Ensure 2FA (TOTP) is actually enabled and active for the user
	mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, models.MFATypeTOTP)
	if err != nil || !mfaSecret.Verified {
		return nil, errors.New("2FA not active or secret not found for user")
	}
	
	// Same logic as in VerifyAndActivate2FA for generating/storing backup codes
	if _, errDel := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID); errDel != nil {
		// s.logger.Error("Failed to delete old backup codes for regeneration", zap.Error(errDel), zap.String("userID", userID.String()))
		return nil, fmt.Errorf("could not delete old backup codes: %w", errDel)
	}

	plainBackupCodes := make([]string, s.cfg.TOTPBackupCodeCount)
	backupCodesToStore := make([]*models.MFABackupCode, s.cfg.TOTPBackupCodeCount)

	for i := 0; i < s.cfg.TOTPBackupCodeCount; i++ {
		codeStr, errGen := security.GenerateSecureToken(6)
		if errGen != nil {
			return nil, fmt.Errorf("failed to generate backup code string: %w", errGen)
		}
		plainBackupCodes[i] = codeStr

		hashedCode, errHash := s.passwordService.HashPassword(codeStr)
		if errHash != nil {
			return nil, fmt.Errorf("failed to hash backup code %d: %w", i+1, errHash)
		}
		backupCodesToStore[i] = &models.MFABackupCode{
			ID:       uuid.New(),
			UserID:   userID,
			CodeHash: hashedCode,
		}
	}

	if errCreate := s.mfaBackupCodeRepo.CreateMultiple(ctx, backupCodesToStore); errCreate != nil {
		return nil, fmt.Errorf("failed to store regenerated backup codes: %w", errCreate)
	}

	// TODO: Publish event: auth.2fa.backup_codes_regenerated (UserID, Count)

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
		return s.Verify2FACode(ctx, userID, verificationToken, "backup") // Assuming "backup" is handled as MFAType by Verify2FACode
	default:
		return false, fmt.Errorf("invalid verification method for sensitive action: %s", verificationMethod)
	}
}


// Ensure mfaLogicService implements MFALogicService (compile-time check).
var _ MFALogicService = (*mfaLogicService)(nil)
