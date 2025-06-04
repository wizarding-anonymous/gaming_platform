package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository"
	// Placeholder for where EncryptSecret/DecryptSecret would live if not in totp_mock.go
	// For now, assuming they are accessible, e.g. from a security utility package.
	// Or, they could be methods on a dedicated encryption service.
	// For this example, let's assume they are global funcs in security package for simplicity.
	"github.com/gameplatform/auth-service/internal/infrastructure/security" // For Encrypt/Decrypt/Password Hashing
)

// MFALogicService defines the interface for Multi-Factor Authentication operations.
type MFALogicService interface {
	// Enable2FAInitiate starts the process of enabling 2FA (TOTP) for a user.
	// Returns base32 secret, QR code data URL for authenticator app.
	Enable2FAInitiate(ctx context.Context, userID, accountName, issuerName string) (string, string, error)

	// VerifyAndActivate2FA finalizes 2FA setup by verifying a TOTP code and activating 2FA.
	// Generates and returns plaintext backup codes if successful.
	VerifyAndActivate2FA(ctx context.Context, userID, totpCode string) ([]string, error)

	// Verify2FACode validates a TOTP code or a backup code during login or other sensitive operations.
	// codeType can be "totp" or "backup".
	Verify2FACode(ctx context.Context, userID, code, codeType string) (bool, error)

	// Disable2FA disables 2FA for a user after proper verification (e.g., password or current 2FA code).
	// This example simplifies by not including the verification step for brevity.
	Disable2FA(ctx context.Context, userID string /*, verificationToken string or password string */) error

	// RegenerateBackupCodes generates new backup codes for a user, invalidating old ones.
	// Requires verification.
	RegenerateBackupCodes(ctx context.Context, userID string /*, verification */) ([]string, error)
}

// mfaLogicServiceImpl implements MFALogicService.
type mfaLogicServiceImpl struct {
	userRepo             repository.UserRepository
	mfaSecretRepo        repository.MFASecretRepository
	mfaBackupCodeRepo    repository.MFABackupCodeRepository
	totpService          TOTPService     // Defined in this package
	passwordService      PasswordService // For hashing backup codes
	// encryptionKey        string          // Key for encrypting/decrypting TOTP secrets, from config
}

// MFALogicServiceConfig holds dependencies for MFALogicService.
type MFALogicServiceConfig struct {
	UserRepo          repository.UserRepository
	MFASecretRepo     repository.MFASecretRepository
	MFABackupCodeRepo repository.MFABackupCodeRepository
	TOTPService       TOTPService
	PasswordService   PasswordService
	// EncryptionKey     string // Passed from main config
}

// NewMFALogicService creates a new mfaLogicServiceImpl.
func NewMFALogicService(cfg MFALogicServiceConfig) MFALogicService {
	return &mfaLogicServiceImpl{
		userRepo:             cfg.UserRepo,
		mfaSecretRepo:        cfg.MFASecretRepo,
		mfaBackupCodeRepo:    cfg.MFABackupCodeRepo,
		totpService:          cfg.TOTPService,
		passwordService:      cfg.PasswordService,
		// encryptionKey:        cfg.EncryptionKey,
	}
}

// TempEncryptionKey is a placeholder. In a real app, this comes from secure config.
const TempEncryptionKey = "a-very-secure-32-byte-key-here" // MUST BE REPLACED

func (s *mfaLogicServiceImpl) Enable2FAInitiate(ctx context.Context, userID, accountName, issuerName string) (string, string, error) {
	// 1. Check if 2FA is already enabled and verified
	existingSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, entity.MFATypeTOTP)
	if err == nil && existingSecret != nil && existingSecret.Verified {
		return "", "", errors.New("2FA is already verified and active for this user") // Placeholder: entity.ErrMFAAlreadyActive
	}

	// 2. Generate new TOTP secret and QR code
	// If issuerName is not provided, TOTPService might use a default from its own config
	secretB32, qrCodeDataURL, err := s.totpService.GenerateSecret(accountName, issuerName)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	// 3. Encrypt the secret before storing
	encryptedSecret, err := security.EncryptSecret(secretB32, TempEncryptionKey) // Using placeholder
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt TOTP secret: %w", err)
	}

	// 4. Store/update the pending (unverified) MFA secret
	now := time.Now()
	if existingSecret != nil { // Update existing pending secret
		existingSecret.SecretKeyEncrypted = encryptedSecret
		existingSecret.Verified = false // Reset verification status
		existingSecret.UpdatedAt = &now
		err = s.mfaSecretRepo.Update(ctx, existingSecret)
	} else { // Create new secret
		newSecret := &entity.MFASecret{
			ID:                 uuid.NewString(),
			UserID:             userID,
			Type:               entity.MFATypeTOTP,
			SecretKeyEncrypted: encryptedSecret,
			Verified:           false,
			CreatedAt:          now,
			UpdatedAt:          &now,
		}
		err = s.mfaSecretRepo.Create(ctx, newSecret)
	}

	if err != nil {
		return "", "", fmt.Errorf("failed to store MFA secret: %w", err)
	}

	// The plaintext secretB32 and qrCodeDataURL are returned to the user for setup.
	return secretB32, qrCodeDataURL, nil
}

func (s *mfaLogicServiceImpl) VerifyAndActivate2FA(ctx context.Context, userID, totpCode string) ([]string, error) {
	// 1. Retrieve the pending MFA secret
	mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, entity.MFATypeTOTP)
	if err != nil {
		if errors.Is(err, errors.New("MFA secret not found")) { // Placeholder for repo error
			return nil, errors.New("2FA setup not initiated or secret not found") // Placeholder entity.ErrMFASetupNotInitiated
		}
		return nil, fmt.Errorf("failed to retrieve MFA secret: %w", err)
	}

	if mfaSecret.Verified {
		return nil, errors.New("2FA is already verified for this user") // Placeholder entity.ErrMFAAlreadyVerified
	}

	// 2. Decrypt the secret
	decryptedSecret, err := security.DecryptSecret(mfaSecret.SecretKeyEncrypted, TempEncryptionKey) // Using placeholder
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}

	// 3. Validate the TOTP code
	isValid, err := s.totpService.ValidateCode(decryptedSecret, totpCode)
	if err != nil {
		return nil, fmt.Errorf("error validating TOTP code: %w", err)
	}
	if !isValid {
		return nil, errors.New("invalid TOTP code") // Placeholder entity.ErrInvalidTOTPCode
	}

	// 4. Mark MFA as verified and active
	now := time.Now()
	mfaSecret.Verified = true
	mfaSecret.UpdatedAt = &now
	if err := s.mfaSecretRepo.Update(ctx, mfaSecret); err != nil {
		return nil, fmt.Errorf("failed to mark MFA secret as verified: %w", err)
	}

	// (Optional: Update user entity if it has an mfa_enabled flag directly)
	// user, err := s.userRepo.FindByID(ctx, userID) ... user.MFAEnabled = true; s.userRepo.Update(ctx, user)

	// 5. Generate and store backup codes
	// Delete any old ones first
	if err := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID); err != nil {
		// Log error but proceed, as generating new codes is more critical
	}

	numBackupCodes := 10 // Should be configurable
	backupCodesPlain := make([]string, numBackupCodes)
	backupCodesHashed := make([]*entity.MFABackupCode, numBackupCodes)

	for i := 0; i < numBackupCodes; i++ {
		// Generate a simple random code (e.g., 8 digits) - placeholder
		// In a real app, use a crypto-secure random string/number generator
		n, _ := rand.Int(rand.Reader, big.NewInt(90000000)) 
		codeStr := fmt.Sprintf("%08d", n.Int64()+10000000) // Ensure 8 digits
		backupCodesPlain[i] = codeStr

		hashedCode, err := s.passwordService.HashPassword(codeStr) // Use PasswordService for hashing
		if err != nil {
			return nil, fmt.Errorf("failed to hash backup code %d: %w", i+1, err)
		}
		backupCodesHashed[i] = &entity.MFABackupCode{
			ID:        uuid.NewString(),
			UserID:    userID,
			CodeHash:  hashedCode,
			CreatedAt: now,
		}
	}

	if err := s.mfaBackupCodeRepo.CreateMultiple(ctx, backupCodesHashed); err != nil {
		// This is a problem: 2FA is active, but backup codes failed to save.
		// May need complex rollback or retry. For now, return error.
		return nil, fmt.Errorf("2FA activated, but failed to store backup codes: %w", err)
	}

	return backupCodesPlain, nil
}


// Verify2FACode: Implementation placeholder
func (s *mfaLogicServiceImpl) Verify2FACode(ctx context.Context, userID, code, codeType string) (bool, error) {
	mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, entity.MFATypeTOTP)
	if err != nil || !mfaSecret.Verified {
		return false, errors.New("2FA not active or secret not found for user") // Placeholder
	}

	if codeType == "totp" {
		decryptedSecret, err := security.DecryptSecret(mfaSecret.SecretKeyEncrypted, TempEncryptionKey)
		if err != nil {
			return false, fmt.Errorf("failed to decrypt TOTP secret: %w", err)
		}
		isValid, err := s.totpService.ValidateCode(decryptedSecret, code)
		if err != nil {
			return false, fmt.Errorf("error validating TOTP code: %w", err)
		}
		return isValid, nil
	} else if codeType == "backup" {
		// Need to iterate through stored hashed backup codes or find by hash directly
		// This is simplified. A real implementation would fetch the specific code if possible.
		hashedCodeToCheck, err := s.passwordService.HashPassword(code) // Hash the provided code
		if err != nil {
			return false, fmt.Errorf("failed to hash provided backup code: %w", err)
		}
		backupCodeEntity, err := s.mfaBackupCodeRepo.FindByUserIDAndCodeHash(ctx, userID, hashedCodeToCheck)
		if err != nil {
			// Could be ErrNotFound or other db error
			return false, errors.New("backup code not found or error retrieving") // Placeholder
		}
		if backupCodeEntity.UsedAt != nil {
			return false, errors.New("backup code already used") // Placeholder
		}
		// Mark as used
		err = s.mfaBackupCodeRepo.MarkAsUsed(ctx, backupCodeEntity.ID, time.Now())
		if err != nil {
			return false, fmt.Errorf("failed to mark backup code as used: %w", err)
		}
		return true, nil
	}
	return false, errors.New("invalid 2FA code type specified")
}

// Disable2FA: Implementation placeholder
func (s *mfaLogicServiceImpl) Disable2FA(ctx context.Context, userID string) error {
	// TODO: Add verification step (password or current 2FA code) before disabling

	if err := s.mfaSecretRepo.DeleteByUserIDAndType(ctx, userID, entity.MFATypeTOTP); err != nil {
		// Log error but proceed if it's "not found"
	}
	if err := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID); err != nil {
		// Log error
	}
	// TODO: Update user entity if it has an mfa_enabled flag
	return nil
}

// RegenerateBackupCodes: Implementation placeholder
func (s *mfaLogicServiceImpl) RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	// TODO: Add verification step

	// Ensure 2FA is actually enabled and active
	mfaSecret, err := s.mfaSecretRepo.FindByUserIDAndType(ctx, userID, entity.MFATypeTOTP)
	if err != nil || !mfaSecret.Verified {
		return nil, errors.New("2FA not active or secret not found for user")
	}
	
	// Same logic as in VerifyAndActivate2FA for generating/storing backup codes
	if err := s.mfaBackupCodeRepo.DeleteByUserID(ctx, userID); err != nil {
		// Log error but proceed
	}

	numBackupCodes := 10 // Should be configurable
	backupCodesPlain := make([]string, numBackupCodes)
	backupCodesHashed := make([]*entity.MFABackupCode, numBackupCodes)
	now := time.Now()

	for i := 0; i < numBackupCodes; i++ {
		n, _ := rand.Int(rand.Reader, big.NewInt(90000000))
		codeStr := fmt.Sprintf("%08d", n.Int64()+10000000)
		backupCodesPlain[i] = codeStr
		hashedCode, errHash := s.passwordService.HashPassword(codeStr)
		if errHash != nil {
			return nil, fmt.Errorf("failed to hash backup code %d: %w", i+1, errHash)
		}
		backupCodesHashed[i] = &entity.MFABackupCode{
			ID:        uuid.NewString(),
			UserID:    userID,
			CodeHash:  hashedCode,
			CreatedAt: now,
		}
	}
	if err := s.mfaBackupCodeRepo.CreateMultiple(ctx, backupCodesHashed); err != nil {
		return nil, fmt.Errorf("failed to store new backup codes: %w", err)
	}
	return backupCodesPlain, nil
}

var _ MFALogicService = (*mfaLogicServiceImpl)(nil)
