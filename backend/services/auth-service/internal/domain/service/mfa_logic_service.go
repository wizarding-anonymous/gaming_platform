// File: backend/services/auth-service/internal/domain/service/mfa_logic_service.go
package service

import (
	"context"
	"errors" // Standard errors
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"                     // For MFAConfig
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors" // For domain errors like ErrNotFound
	domainInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/interfaces"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	kafkaPkg "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka" // Assuming this is the Sarama producer
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"
	repoInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/repository/interfaces" // Corrected path
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

	// GetActiveBackupCodeCount retrieves the number of active (unused) backup codes for a user.
	// Requires that 2FA (TOTP) is active and verified.
	// Returns the count of active backup codes, or an error if 2FA is not active/verified or on other failures.
	GetActiveBackupCodeCount(ctx context.Context, userID uuid.UUID) (count int, err error)
}

// mfaLogicService implements the MFALogicService interface, providing concrete business logic
// for multi-factor authentication operations. It coordinates interactions between repositories
// (for MFA secrets and backup codes, users), specialized services (TOTP generation/validation,
// password hashing, encryption), and event publishing.
type mfaLogicService struct {
	cfg               *config.Config                         // Global application configuration.
	totpService       domainInterfaces.TOTPService           // Service for TOTP generation and validation.
	encryptionService domainInterfaces.EncryptionService     // Service for encrypting/decrypting sensitive data like TOTP secrets.
	mfaSecretRepo     repoInterfaces.MFASecretRepository     // Repository for storing and managing MFA secrets (e.g., TOTP keys).
	mfaBackupCodeRepo repoInterfaces.MFABackupCodeRepository // Repository for storing and managing MFA backup codes.
	userRepo          repoInterfaces.UserRepository          // Repository for user data access, needed for password verification.
	passwordService   domainInterfaces.PasswordService       // Service for hashing and checking passwords (used for backup code hashing and disabling 2FA via password).
	auditLogRecorder  AuditLogRecorder                       // Service for recording audit log events.
	kafkaProducer     *kafkaPkg.Producer                     // Kafka client for publishing events related to MFA status changes.
	rateLimiter       RateLimiter                            // Service for rate limiting 2FA verification attempts.
}

// NewMFALogicService creates a new instance of mfaLogicService with all its dependencies.
// This constructor initializes the service with the necessary configuration, sub-services for
// TOTP, encryption, password management, rate limiting, and repositories for data access.
func NewMFALogicService(
	cfg *config.Config, // Global application configuration.
	totpService domainInterfaces.TOTPService,
	encryptionService domainInterfaces.EncryptionService,
	mfaSecretRepo repoInterfaces.MFASecretRepository,
	mfaBackupCodeRepo repoInterfaces.MFABackupCodeRepository,
	userRepo repoInterfaces.UserRepository,
	passwordService domainInterfaces.PasswordService,
	auditLogRecorder AuditLogRecorder, // Added
	kafkaProducer *kafkaPkg.Producer, // Added
	rateLimiter RateLimiter, // Added
) MFALogicService {
	return &mfaLogicService{
		cfg:               cfg, // Will now be global Config
		totpService:       totpService,
		encryptionService: encryptionService,
		mfaSecretRepo:     mfaSecretRepo,
		mfaBackupCodeRepo: mfaBackupCodeRepo,
		userRepo:          userRepo,
		passwordService:   passwordService,
		auditLogRecorder:  auditLogRecorder, // Added
		kafkaProducer:     kafkaProducer,    // Added
		rateLimiter:       rateLimiter,      // Added
	}
}

// TempEncryptionKey is a placeholder. In a real app, this comes from secure config.
// const TempEncryptionKey = "a-very-secure-32-byte-key-here" // MUST BE REPLACED // This will be removed

// Helper function to extract IP and UserAgent from context metadata
// This is a simplified example; actual implementation might vary based on how metadata is stored.
func getIPAndUserAgentFromCtx(ctx context.Context) (string, string) {
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
	return ipAddress, userAgent
}

// Ensure mfaLogicService implements MFALogicService (compile-time check).
var _ MFALogicService = (*mfaLogicService)(nil)
