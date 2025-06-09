// File: backend/services/auth-service/internal/domain/service/mfa_logic_service.go
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
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"     // For domain errors like ErrNotFound
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces" // Corrected path
	"github.com/your-org/auth-service/internal/infrastructure/security"
	kafkaPkg "github.com/your-org/auth-service/internal/events/kafka" // Assuming this is the Sarama producer
)

// MFALogicService defines the interface for Multi-Factor Authentication (MFA) business logic.
// It handles operations such as initiating 2FA setup (e.g., TOTP), verifying codes,
// activating and disabling 2FA, and managing backup codes.
type MFALogicService interface {
	// Enable2FAInitiate starts the process of enabling 2FA (specifically TOTP) for a user.
	// It checks if 2FA is already enabled and verified. If not, or if a previous unverified setup exists,
	// it cleans up the old setup, generates a new TOTP secret (encrypted for storage) and an OTP Auth URL
	// (e.g., "otpauth://totp/...") suitable for QR code generation by the client.
	// The raw base32 encoded secret is returned for display to the user during setup.
	// Parameters:
	//  - ctx: The context for the request.
	//  - userID: The ID of the user for whom to initiate 2FA.
	//  - accountName: The account name to be displayed in the authenticator app (usually user's email or username).
	// Returns the ID of the newly created MFA secret record, the raw base32 secret string, the OTP Auth URL string,
	// and an error if any step fails (e.g., domainErrors.Err2FAAlreadyEnabled, errors during secret generation or storage).
	Enable2FAInitiate(ctx context.Context, userID uuid.UUID, accountName string) (mfaSecretID uuid.UUID, secretBase32 string, otpAuthURL string, err error)

	// VerifyAndActivate2FA verifies the initial TOTP code provided by the user against the generated secret
	// (identified by mfaSecretID from the Enable2FAInitiate step) and, if valid, marks the MFA setup as verified.
	// It then generates a new set of backup codes, stores their hashes, and returns the plain backup codes to the user.
	// Any old backup codes for the user are deleted. Publishes an AuthMFAEnabledV1 event on success.
	// Parameters:
	//  - ctx: The context for the request.
	//  - userID: The ID of the user activating 2FA.
	//  - plainTOTPCode: The TOTP code entered by the user from their authenticator app.
	//  - mfaSecretID: The ID of the MFA secret record created during the initiate step.
	// Returns a slice of plain text backup codes on success, or an error if verification fails
	// (e.g., domainErrors.ErrNotFound if mfaSecretID is invalid, domainErrors.ErrInvalid2FACode,
	// domainErrors.Err2FAAlreadyEnabled, or errors during backup code generation/storage).
	VerifyAndActivate2FA(ctx context.Context, userID uuid.UUID, plainTOTPCode string, mfaSecretID uuid.UUID) (backupCodes []string, err error)

	// Verify2FACode checks a TOTP code or a backup code during login or other sensitive operations.
	// It includes rate limiting for verification attempts.
	// For backup codes, it ensures the code is used only once by marking it as used.
	// Parameters:
	//  - ctx: The context for the request, used for rate limiting and metadata.
	//  - userID: The ID of the user attempting to verify the 2FA code.
	//  - code: The plain text code (TOTP or backup) provided by the user.
	//  - codeType: Indicates if it's a models.MFATypeTOTP or models.MFATypeBackup code.
	// Returns true if the code is valid, false otherwise, and an error if any issues occur
	// (e.g., domainErrors.ErrRateLimitExceeded, domainErrors.Err2FANotEnabled, domainErrors.ErrMFANotVerified,
	// domainErrors.ErrInvalid2FACode, or internal errors).
	Verify2FACode(ctx context.Context, userID uuid.UUID, code string, codeType models.MFAType) (isValid bool, err error)

	// Disable2FA disables 2FA for a user after proper authorization.
	// Authorization can be via current password, a valid TOTP code, or a valid backup code.
	// It deletes all MFA secrets and backup codes for the user. Publishes an AuthMFADisabledV1 event.
	// Parameters:
	//  - ctx: The context for the request.
	//  - userID: The ID of the user for whom to disable 2FA.
	//  - verificationToken: The token used for authorization (password, TOTP code, or backup code).
	//  - verificationMethod: A string indicating the type of token provided ("password", "totp", "backup").
	// Returns nil on success, or an error if authorization fails (e.g., domainErrors.ErrForbidden),
	// or if repository operations fail. If 2FA was not enabled, it returns nil but logs this information.
	Disable2FA(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) error

	// RegenerateBackupCodes generates a new set of MFA backup codes for a user after proper authorization.
	// Authorization can be via current password, a valid TOTP code, or a valid backup code.
	// It requires that 2FA (TOTP) is already active and verified for the user.
	// It deletes all existing backup codes and creates a new set.
	// Parameters:
	//  - ctx: The context for the request.
	//  - userID: The ID of the user for whom to regenerate backup codes.
	//  - verificationToken: The token used for authorization.
	//  - verificationMethod: The type of authorization token ("password", "totp", "backup").
	// Returns a slice of new plain text backup codes on success, or an error if authorization fails,
	// 2FA is not active (domainErrors.Err2FANotEnabled, domainErrors.ErrMFANotVerified),
	// or if repository operations fail.
	RegenerateBackupCodes(ctx context.Context, userID uuid.UUID, verificationToken string, verificationMethod string) (backupCodes []string, err error)
}

// mfaLogicService implements the MFALogicService interface, providing concrete business logic
// for multi-factor authentication operations. It coordinates interactions between repositories
// (for MFA secrets and backup codes, users), specialized services (TOTP generation/validation,
// password hashing, encryption), and event publishing.
type mfaLogicService struct {
	cfg                   *config.Config // Global application configuration.
	totpService           TOTPService         // Service for TOTP generation and validation.
	encryptionService     security.EncryptionService // Service for encrypting/decrypting sensitive data like TOTP secrets.
	mfaSecretRepo         repoInterfaces.MFASecretRepository // Repository for storing and managing MFA secrets (e.g., TOTP keys).
	mfaBackupCodeRepo     repoInterfaces.MFABackupCodeRepository // Repository for storing and managing MFA backup codes.
	userRepo              repoInterfaces.UserRepository // Repository for user data access, needed for password verification.
	passwordService       PasswordService // Service for hashing and checking passwords (used for backup code hashing and disabling 2FA via password).
	auditLogRecorder      AuditLogRecorder      // Service for recording audit log events.
	kafkaProducer         *kafkaPkg.Producer    // Kafka client for publishing events related to MFA status changes.
	rateLimiter           RateLimiter           // Service for rate limiting 2FA verification attempts.
}


// NewMFALogicService creates a new instance of mfaLogicService with all its dependencies.
// This constructor initializes the service with the necessary configuration, sub-services for
// TOTP, encryption, password management, rate limiting, and repositories for data access.
func NewMFALogicService(
	cfg *config.Config, // Global application configuration.
	totpService TOTPService,
	encryptionService security.EncryptionService,
	mfaSecretRepo repoInterfaces.MFASecretRepository,
	mfaBackupCodeRepo repoInterfaces.MFABackupCodeRepository,
	userRepo repoInterfaces.UserRepository,
	passwordService PasswordService,
	auditLogRecorder AuditLogRecorder,      // Added
	kafkaProducer *kafkaPkg.Producer,   // Added
	rateLimiter RateLimiter,          // Added
) MFALogicService {
	return &mfaLogicService{
		cfg:                   cfg, // Will now be global Config
		totpService:           totpService,
		encryptionService:     encryptionService,
		mfaSecretRepo:         mfaSecretRepo,
		mfaBackupCodeRepo:     mfaBackupCodeRepo,
		userRepo:              userRepo,
		passwordService:       passwordService,
		auditLogRecorder:      auditLogRecorder,      // Added
		kafkaProducer:         kafkaProducer,   // Added
		rateLimiter:           rateLimiter,           // Added
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

	secretBase32, otpAuthURL, err := s.totpService.GenerateSecret(accountName, s.cfg.MFA.TOTPIssuerName) // Adjusted: s.cfg.MFA
	if err != nil {
		auditDetails = map[string]interface{}{"error": "failed to generate TOTP secret", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_initiate", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return uuid.Nil, "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	encryptedSecret, err := s.encryptionService.Encrypt(secretBase32, s.cfg.MFA.TOTPSecretEncryptionKey) // Adjusted: s.cfg.MFA
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

	plainBackupCodes := make([]string, s.cfg.MFA.TOTPBackupCodeCount) // Adjusted: s.cfg.MFA
	backupCodesToStore := make([]*models.MFABackupCode, s.cfg.MFA.TOTPBackupCodeCount) // Adjusted: s.cfg.MFA
	for i := 0; i < s.cfg.MFA.TOTPBackupCodeCount; i++ { // Adjusted: s.cfg.MFA
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

	enabledAt := time.Now() // Capture consistent timestamp
	// Publish CloudEvent for MFA enabled
	// Assuming MFAEnabledPayload is in models package
	mfaEnabledPayload := models.MFAEnabledPayload{
		UserID:    userID.String(),
		MFAType:   string(models.MFATypeTOTP), // Assuming models.MFATypeTOTP is "totp"
		EnabledAt: enabledAt,
	}
	subjectMFAEnabled := userID.String()
	contentTypeJSON := "application/json"
	// TODO: Determine correct topic, using placeholder "auth-events" for now. Should be from cfg.
	// Assuming event type models.AuthMFAEnabledV1 is kafkaPkg.EventType (string alias)
	if err := s.kafkaProducer.PublishCloudEvent(
		ctx,
		"auth-events", // topic
		kafkaPkg.EventType(models.AuthMFAEnabledV1), // eventType
		&subjectMFAEnabled,    // subject
		&contentTypeJSON,      // dataContentType
		mfaEnabledPayload,     // dataPayload
	); err != nil {
		// s.logger.Error("Failed to publish CloudEvent for MFA enabled", zap.Error(err), zap.String("userID", userID.String()))
		// Add to audit details as a warning, as core MFA activation succeeded.
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	if auditDetails == nil { auditDetails = make(map[string]interface{})} // Ensure not nil
	auditDetails["mfa_secret_id"] = mfaSecretID.String()
	auditDetails["mfa_type"] = string(models.MFATypeTOTP)
	auditDetails["backup_codes_generated"] = len(plainBackupCodes)
	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_enable_complete", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return plainBackupCodes, nil
}


// Verify2FACode implements MFALogicService.
func (s *mfaLogicService) Verify2FACode(ctx context.Context, userID uuid.UUID, code string, codeType models.MFAType) (bool, error) {
	// Audit log context
	actorAndTargetID := &userID
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	var auditDetails = make(map[string]interface{}) // Initialize to avoid nil checks later
	auditDetails["code_type"] = string(codeType)

	// Rate Limiting
	rateLimitRule := s.cfg.Security.RateLimiting.TwoFAVerificationPerUser
	if rateLimitRule.Enabled {
		rateKey := "2faverify_user:" + userID.String()
		// Note: The RateLimiter interface might need to be adapted if it doesn't take RateLimitRule directly.
		// Assuming a simplified Allow(key, rule) or Allow(key, limit, window) exists.
		// For now, let's assume the existing interface can work or will be adapted.
		// The current redis_rate_limiter.Allow takes: ctx, key string, rule config.RateLimitRule
		allowed, rlErr := s.rateLimiter.Allow(ctx, rateKey, rateLimitRule)
		if rlErr != nil {
			// s.logger.Error("Rate limiter failed for 2FA verification", zap.Error(rlErr), zap.String("userID", userID.String()))
			// Decide policy: fail open or closed. For now, log and fail open (proceed with verification).
			// If critical, should return an error here.
			auditDetails["warning_rate_limit_check_failed"] = rlErr.Error()
		}
		if !allowed {
			// s.logger.Warn("Rate limit exceeded for 2FA verification", zap.String("userID", userID.String()))
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
				return false, domainErrors.Err2FANotEnabled // No TOTP setup for user
			}
			auditDetails["error"] = "error fetching TOTP secret"
			auditDetails["details"] = err.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, fmt.Errorf("error fetching TOTP secret: %w", err)
		}
		if !mfaSecret.Verified {
			auditDetails["error"] = domainErrors.ErrMFANotVerified.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, domainErrors.ErrMFANotVerified // TOTP setup not completed/verified
		}
		decryptedSecret, err := s.encryptionService.Decrypt(mfaSecret.SecretKeyEncrypted, s.cfg.MFA.TOTPSecretEncryptionKey) // Adjusted: s.cfg.MFA
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
	} else if codeType == models.MFATypeBackup { // Ensure using models.MFATypeBackup
		// For backup codes, we hash the provided plain code to compare with stored hashes
		// No, this is incorrect. The stored backup codes are already hashed.
		// We need to iterate through stored backup codes, hash the input, and compare.
		// OR, the repository FindByUserIDAndCodeHash should take the plain code, hash it, then search.
		// Re-checking `mfa_backup_code_repository_postgres.go`:
		// FindByUserIDAndCodeHash(ctx context.Context, userID uuid.UUID, plainCode string)
		// It hashes the plainCode inside. So, passing plain `code` is correct.

		// The original code was:
		// hashedCode, err := s.passwordService.HashPassword(code)
		// if err != nil { return false, fmt.Errorf("failed to hash backup code for verification: %w", err) }
		// backupCode, err := s.mfaBackupCodeRepo.FindByUserIDAndCodeHash(ctx, userID, hashedCode)
		// This implies the repo expects an already hashed code. This contradicts the idea of a generic PasswordService
		// being used to hash the *input* code to compare against *already hashed* stored codes.
		// Let's assume the repo's FindByUserIDAndCodeHash actually takes a *hashed* code.
		// The passwordService.HashPassword is for creating hashes, not for verifying them against existing ones.
		// For backup codes, we should iterate through the user's *hashed* backup codes and use passwordService.CheckPasswordHash for each.

		// Corrected logic for backup code verification:
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
				// Log individual check error but continue checking others
				// s.logger.Error("Error checking backup code hash", zap.Error(checkErr), zap.String("backupCodeID", bc.ID.String()))
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
			return false, domainErrors.ErrInvalid2FACode // No matching backup code found
		}

		// Mark as used
		if err := s.mfaBackupCodeRepo.MarkAsUsed(ctx, validBackupCode.ID, time.Now()); err != nil {
			auditDetails["error"] = "failed to mark backup code as used"
			auditDetails["details"] = err.Error()
			s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_code_verify", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return false, fmt.Errorf("failed to mark backup code as used: %w", err)
		}
		// TODO: Publish event: auth.2fa.backup_code_used (UserID, BackupCodeID)
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
		disabledAt := time.Now()
		// Assuming MFADisabledPayload is in models package
		mfaDisabledPayload := models.MFADisabledPayload{
			UserID:     userID.String(),
			MFAType:    string(models.MFATypeTOTP), // Assuming disable implies TOTP for now
			DisabledAt: disabledAt,
		}
		subjectMFADisabled := userID.String()
		contentTypeJSON := "application/json"
		// TODO: Determine correct topic
		// Assuming event type models.AuthMFADisabledV1 is kafkaPkg.EventType (string alias)
		if err := s.kafkaProducer.PublishCloudEvent(
			ctx,
			"auth-events", // topic
			kafkaPkg.EventType(models.AuthMFADisabledV1), // eventType
			&subjectMFADisabled,   // subject
			&contentTypeJSON,      // dataContentType
			mfaDisabledPayload,    // dataPayload
		); err != nil {
			// s.logger.Error("Failed to publish CloudEvent for MFA disabled", zap.Error(err), zap.String("userID", userID.String()))
			auditDetails["warning_cloudevent_publish"] = err.Error()
		}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	} else {
		auditDetails["info"] = domainErrors.Err2FANotEnabled.Error() // Ensure domainErrors is imported
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "mfa_disable", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
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

	plainBackupCodes := make([]string, s.cfg.MFA.TOTPBackupCodeCount) // Adjusted: s.cfg.MFA
	backupCodesToStore := make([]*models.MFABackupCode, s.cfg.MFA.TOTPBackupCodeCount) // Adjusted: s.cfg.MFA
	for i := 0; i < s.cfg.MFA.TOTPBackupCodeCount; i++ { // Adjusted: s.cfg.MFA
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
