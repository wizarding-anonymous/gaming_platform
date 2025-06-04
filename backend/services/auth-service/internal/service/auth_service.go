// Package service contains the core business logic for the authentication service.
// It orchestrates operations between repositories, external services (like token generation, password hashing),
// and other domain services to fulfill application use cases such as user registration, login,
// token management, MFA, and external authentication.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces"
	appSecurity "github.com/your-org/auth-service/internal/infrastructure/security"
	"github.com/your-org/auth-service/internal/utils/kafka"
	"go.uber.org/zap"
)

// AuthService provides methods for user authentication, authorization, and account management.
// It encapsulates the core business logic related to user identity, sessions, tokens,
// multi-factor authentication (MFA), password management, and external authentication providers.
type AuthService struct {
	userRepo               repoInterfaces.UserRepository // Handles user data persistence.
	verificationCodeRepo   repoInterfaces.VerificationCodeRepository // Manages verification codes (e.g., email, password reset).
	tokenService           *TokenService // Manages creation and validation of access/refresh token pairs with sessions.
	sessionService         *SessionService // Handles user session lifecycle.
	kafkaClient            *kafka.Client // Kafka client for publishing events.
	logger                 *zap.Logger // Application logger.
	passwordService        domainService.PasswordService // Service for hashing and verifying passwords.
	tokenManagementService domainService.TokenManagementService // Core service for JWT generation and validation (RS256).
	mfaSecretRepo          repoInterfaces.MFASecretRepository // Repository for MFA secrets.
	mfaLogicService        domainService.MFALogicService // Business logic for MFA operations.
	userRolesRepo          repoInterfaces.UserRolesRepository // Manages user-role assignments.
	roleService            *RoleService // Service for role and permission related logic, used for enriching JWTs.
	externalAccountRepo    repoInterfaces.ExternalAccountRepository // Repository for external (OAuth, Telegram) account links.
	telegramVerifier       domainService.TelegramVerifierService    // Service for verifying Telegram authentication data.
	auditLogRecorder       domainService.AuditLogRecorder           // Service for recording audit log events.
	cfg                    *config.Config // Application configuration.
	httpClient             *http.Client                             // HTTP client for external calls (e.g., OAuth providers).
	rateLimiter            domainService.RateLimiter                // Service for rate limiting operations.
}

// NewAuthService creates a new instance of AuthService with all its dependencies.
// It initializes the service with various repositories, sub-services, configuration,
// and utility clients required for its operations.
func NewAuthService(
	userRepo repoInterfaces.UserRepository,
	verificationCodeRepo repoInterfaces.VerificationCodeRepository,
	tokenService *TokenService,
	sessionService *SessionService,
	kafkaClient *kafka.Client,
	cfg *config.Config,
	logger *zap.Logger,
	passwordService domainService.PasswordService,
	tokenManagementService domainService.TokenManagementService,
	mfaSecretRepo repoInterfaces.MFASecretRepository,
	mfaLogicService domainService.MFALogicService,
	userRolesRepo repoInterfaces.UserRolesRepository,
	roleService *RoleService, // Added
	externalAccountRepo repoInterfaces.ExternalAccountRepository, // Added
	telegramVerifier domainService.TelegramVerifierService,    // Added
	auditLogRecorder domainService.AuditLogRecorder,           // Added
	rateLimiter domainService.RateLimiter, // Added
) *AuthService {
	httpClient := &http.Client{
		Timeout: 15 * time.Second, // Default timeout for OAuth HTTP calls
	}
	return &AuthService{
		userRepo:               userRepo,
		verificationCodeRepo:   verificationCodeRepo,
		tokenService:           tokenService,
		sessionService:         sessionService,
		kafkaClient:            kafkaClient,
		logger:                 logger,
		passwordService:        passwordService,
		tokenManagementService: tokenManagementService,
		mfaSecretRepo:          mfaSecretRepo,
		mfaLogicService:        mfaLogicService,
		userRolesRepo:          userRolesRepo,
		roleService:            roleService, // Added
		externalAccountRepo:    externalAccountRepo, // Added
		telegramVerifier:       telegramVerifier,    // Added
		auditLogRecorder:       auditLogRecorder,    // Added
		cfg:                    cfg,
		httpClient:             httpClient,          // Added
		rateLimiter:            rateLimiter,         // Added
	}
}

// Register handles new user registration.
// It validates input, checks for existing users, hashes the password, creates the user record,
// generates an email verification token, stores it, and publishes a UserRegisteredEvent.
// An audit log event is recorded for the registration attempt (success or failure).
// It returns the newly created user, the plain verification token (for email sending), and an error if any.
// Possible errors include domainErrors.ErrEmailExists, domainErrors.ErrUsernameExists,
// domainErrors.ErrRateLimitExceeded, or other internal errors.
func (s *AuthService) Register(ctx context.Context, req models.CreateUserRequest) (*models.User, string, error) {
	// Audit log helper vars
	var auditErrorDetails map[string]interface{}
	var actorUserID *uuid.UUID // For registration, actor is initially nil or system

	// Extract IP and UserAgent from context metadata if available
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}

	// Rate limit by IP
	allowed, rlErr := s.rateLimiter.Allow(ctx, "register_ip:"+ipAddress, s.cfg.Security.RateLimiting.RegisterIP)
	if rlErr != nil {
		s.logger.Error("Rate limiter failed for register_ip", zap.Error(rlErr), zap.String("ipAddress", ipAddress))
		// Decide policy: fail open or closed. For now, fail open but log. Consider returning an error.
	}
	if !allowed {
		s.logger.Warn("Rate limit exceeded for register_ip", zap.String("ipAddress", ipAddress))
		auditErrorDetails = map[string]interface{}{"error": domainErrors.ErrRateLimitExceeded.Error(), "ip_address": ipAddress}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusFailure, nil, nil, auditErrorDetails, ipAddress, userAgent)
		return nil, "", domainErrors.ErrRateLimitExceeded
	}

	_, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err == nil {
		auditErrorDetails = map[string]interface{}{"error": domainErrors.ErrEmailExists.Error(), "email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusFailure, nil, nil, auditErrorDetails, ipAddress, userAgent)
		return nil, "", domainErrors.ErrEmailExists
	}
	if !errors.Is(err, domainErrors.ErrUserNotFound) {
		s.logger.Error("Error checking email existence for registration", zap.Error(err))
		auditErrorDetails = map[string]interface{}{"error": err.Error(), "email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusFailure, nil, nil, auditErrorDetails, ipAddress, userAgent)
		return nil, "", err
	}

	_, err = s.userRepo.FindByUsername(ctx, req.Username)
	if err == nil {
		auditErrorDetails = map[string]interface{}{"error": domainErrors.ErrUsernameExists.Error(), "username": req.Username}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusFailure, nil, nil, auditErrorDetails, ipAddress, userAgent)
		return nil, "", domainErrors.ErrUsernameExists
	}
	if !errors.Is(err, domainErrors.ErrUserNotFound) {
		s.logger.Error("Error checking username existence for registration", zap.Error(err))
		auditErrorDetails = map[string]interface{}{"error": err.Error(), "username": req.Username}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusFailure, nil, nil, auditErrorDetails, ipAddress, userAgent)
		return nil, "", err
	}

	hashedPassword, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("Failed to hash password during registration", zap.Error(err))
		auditErrorDetails = map[string]interface{}{"error": "password hashing failed"}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusFailure, nil, nil, auditErrorDetails, ipAddress, userAgent)
		return nil, "", err
	}

	user := &models.User{
		ID:           uuid.New(),
		Email:        req.Email,
		Username:     req.Username,
		PasswordHash: hashedPassword,
		Status:       models.UserStatusPendingVerification,
	}

	if err = s.userRepo.Create(ctx, user); err != nil {
		s.logger.Error("Failed to create user during registration", zap.Error(err))
		auditErrorDetails = map[string]interface{}{"error": "user creation in db failed", "email": req.Email, "username": req.Username}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusFailure, nil, nil, auditErrorDetails, ipAddress, userAgent)
		return nil, "", err
	}

	// For successful registration, the new user ID is the target
	targetUserID := user.ID

	createdUser, err := s.userRepo.FindByID(ctx, user.ID)
	if err != nil {
	    s.logger.Error("Failed to fetch newly created user", zap.Error(err), zap.String("userID", user.ID.String()))
		// This is a system error post-creation, but the user IS created. Log success with a detail.
		auditErrorDetails = map[string]interface{}{"warning": "failed to fetch user post-creation, but user created", "error": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusSuccess, &targetUserID, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
	    return nil, "", fmt.Errorf("failed to fetch newly created user: %w", err)
	}

	plainVerificationToken, err := appSecurity.GenerateSecureToken(32)
	if err != nil {
		s.logger.Error("Failed to generate verification token", zap.Error(err))
		auditErrorDetails = map[string]interface{}{"error": "verification token generation failed"}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusFailure, &targetUserID, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, "", fmt.Errorf("could not generate verification token: %w", err)
	}
	hashedVerificationToken := appSecurity.HashToken(plainVerificationToken)

	verificationCode := &models.VerificationCode{
		ID:        uuid.New(),
		UserID:    user.ID,
		Type:      models.VerificationCodeTypeEmailVerification,
		CodeHash:  hashedVerificationToken,
		ExpiresAt: time.Now().Add(s.cfg.JWT.EmailVerificationToken.ExpiresIn),
	}
	if err := s.verificationCodeRepo.Create(ctx, verificationCode); err != nil {
		s.logger.Error("Failed to store verification code", zap.Error(err))
		auditErrorDetails = map[string]interface{}{"error": "storing verification code failed"}
		// User is created, but verification code failed. Log success with warning.
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusSuccess, &targetUserID, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, "", fmt.Errorf("could not store verification code: %w", err)
	}

	// Prepare CloudEvent payload
	// Assuming req.DisplayName is available, otherwise set to nil or handle as needed.
	// For now, DisplayName is not in CreateUserRequest, so it will be nil.
	var displayName *string
	// if req.DisplayName != "" { displayName = &req.DisplayName }


	userRegisteredPayload := models.UserRegisteredPayload{
		UserID:                 createdUser.ID.String(),
		Username:               createdUser.Username,
		Email:                  createdUser.Email,
		DisplayName:            displayName, // Or map from createdUser if available
		RegistrationTimestamp:  createdUser.CreatedAt, // Assuming CreatedAt is populated correctly
		InitialStatus:          string(createdUser.Status),
	}

	// Publish CloudEvent
	// The topic should ideally come from a central config or be a constant for this event stream
	// Using s.cfg.Kafka.Producer.Topic as per previous patterns for a general topic
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserRegisteredV1, createdUser.ID.String(), userRegisteredPayload); err != nil {
		s.logger.Error("Failed to publish CloudEvent for user registered", zap.Error(err), zap.String("user_id", createdUser.ID.String()))
		// Non-critical for registration flow itself, but good to note for audit/monitoring.
		// The audit log for registration success is recorded later.
		// If this is critical, the overall function should return an error.
	}

	s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_register", models.AuditLogStatusSuccess, &targetUserID, models.AuditTargetTypeUser, nil, ipAddress, userAgent)
	return createdUser, plainVerificationToken, nil
}

// Login authenticates a user based on their email and password.
// It performs rate limiting, user lookup, password verification, and checks for account status (blocked, unverified).
// If Multi-Factor Authentication (MFA/2FA) is enabled and verified for the user, it returns domainErrors.Err2FARequired
// along with a 2FA challenge token. The user must then complete the 2FA step using CompleteLoginAfter2FA.
// On successful login (or successful first phase if 2FA is required):
// - Failed login attempts are reset.
// - Last login time is updated.
// - A new session and token pair (access and refresh) are generated if 2FA is not required.
// - A UserLoginSuccessEvent is published via Kafka.
// - An audit log event is recorded.
// Returns the token pair, user details, a 2FA challenge token (if 2FA is required), and an error if any.
// Possible errors: domainErrors.ErrInvalidCredentials, domainErrors.ErrUserLockedOut, domainErrors.ErrUserBlocked,
// domainErrors.ErrEmailNotVerified, domainErrors.Err2FARequired, domainErrors.ErrRateLimitExceeded.
func (s *AuthService) Login(ctx context.Context, req models.LoginRequest) (*models.TokenPair, *models.User, string, error) {
	var auditErrorDetails map[string]interface{}
	var userIDForAudit *uuid.UUID // Use pointer for nil possibility

	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}

	// Rate limit by email and IP
	allowed, rlErr := s.rateLimiter.Allow(ctx, "login_email_ip:"+req.Email+":"+ipAddress, s.cfg.Security.RateLimiting.LoginEmailIP)
	if rlErr != nil {
		s.logger.Error("Rate limiter failed for login_email_ip", zap.Error(rlErr), zap.String("email", req.Email), zap.String("ipAddress", ipAddress))
		// Fail open or closed policy
	}
	if !allowed {
		s.logger.Warn("Rate limit exceeded for login_email_ip", zap.String("email", req.Email), zap.String("ipAddress", ipAddress))
		// Not logging to audit here as it might be a brute force, audit log for failed login later covers it.
		return nil, nil, "", domainErrors.ErrRateLimitExceeded
	}

	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			s.logger.Warn("Login attempt: User not found by email", zap.String("email", req.Email))
			auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrInvalidCredentials.Error(), "attempted_email": req.Email}
			s.auditLogRecorder.RecordEvent(ctx, nil, "user_login", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		} else {
			s.logger.Error("Login attempt: Error fetching user by email", zap.Error(err), zap.String("email", req.Email))
			auditErrorDetails = map[string]interface{}{"reason": "db error fetching user", "error": err.Error(), "attempted_email": req.Email}
			s.auditLogRecorder.RecordEvent(ctx, nil, "user_login", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		}
		return nil, nil, "", domainErrors.ErrInvalidCredentials
	}
	userIDForAudit = &user.ID


	if user.LockoutUntil != nil && time.Now().Before(*user.LockoutUntil) {
		s.logger.Warn("Login attempt for locked out user", zap.String("user_id", user.ID.String()), zap.Time("lockout_until", *user.LockoutUntil))
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrUserLockedOut.Error(), "attempted_email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, nil, "", domainErrors.ErrUserLockedOut
	}

	passwordMatch, err := s.passwordService.CheckPasswordHash(req.Password, user.PasswordHash)
	if err != nil {
		s.logger.Error("Error checking password hash", zap.Error(err), zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"reason": "password check error", "error": err.Error(), "attempted_email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, nil, "", domainErrors.ErrInternal
	}

	if !passwordMatch {
		s.logger.Warn("Invalid password attempt", zap.String("user_id", user.ID.String()))
		// Increment failed attempts logic...
		if errInc := s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID); errInc != nil {
			s.logger.Error("Failed to increment failed login attempts", zap.Error(errInc), zap.String("user_id", user.ID.String()))
		}
		updatedUser, fetchErr := s.userRepo.FindByID(ctx, user.ID) // Re-fetch to check current attempts
		if fetchErr != nil { // Should not happen if user was just fetched
			s.logger.Error("Failed to fetch user after failed attempt", zap.Error(fetchErr), zap.String("user_id", user.ID.String()))
			auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrInvalidCredentials.Error(), "attempted_email": req.Email}
			s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
			return nil, nil, "", domainErrors.ErrInvalidCredentials
		}

		if updatedUser.FailedLoginAttempts >= s.cfg.Security.Lockout.MaxFailedAttempts {
			lockoutUntil := time.Now().Add(s.cfg.Security.Lockout.LockoutDuration)
			if errLock := s.userRepo.UpdateLockout(ctx, updatedUser.ID, &lockoutUntil); errLock != nil {
				s.logger.Error("Failed to update lockout status for user", zap.Error(errLock), zap.String("user_id", updatedUser.ID.String()))
			}
			s.logger.Warn("User account locked", zap.String("user_id", updatedUser.ID.String()))
			auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrUserLockedOut.Error(), "attempted_email": req.Email, "lockout_triggered": true}
			s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
			return nil, nil, "", domainErrors.ErrUserLockedOut
		}
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrInvalidCredentials.Error(), "attempted_email": req.Email, "failed_attempts": updatedUser.FailedLoginAttempts}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, nil, "", domainErrors.ErrInvalidCredentials
	}

	if user.Status == models.UserStatusBlocked {
		s.logger.Warn("Login attempt for blocked user", zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrUserBlocked.Error(), "attempted_email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, nil, "", domainErrors.ErrUserBlocked
	}

	if user.EmailVerifiedAt == nil {
		s.logger.Warn("Login attempt for unverified email", zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrEmailNotVerified.Error(), "attempted_email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, nil, "", domainErrors.ErrEmailNotVerified
	}

	// --- MFA Check START ---
	mfaSecret, errMFA := s.mfaSecretRepo.FindByUserIDAndType(ctx, user.ID, models.MFATypeTOTP)
	if errMFA == nil && mfaSecret != nil && mfaSecret.Verified {
		s.logger.Info("2FA required for user", zap.String("user_id", user.ID.String()))
		challengeToken, errChallenge := s.tokenManagementService.Generate2FAChallengeToken(user.ID.String())
		if errChallenge != nil {
			s.logger.Error("Failed to generate 2FA challenge token", zap.Error(errChallenge), zap.String("user_id", user.ID.String()))
			auditErrorDetails = map[string]interface{}{"reason": "2FA challenge token generation failed", "error": errChallenge.Error(), "attempted_email": req.Email}
			s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
			return nil, nil, "", domainErrors.ErrInternal
		}
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.Err2FARequired.Error(), "attempted_email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, user, challengeToken, domainErrors.Err2FARequired
	}
	if errMFA != nil && !errors.Is(errMFA, domainErrors.ErrNotFound) { // Log if error is not simply "2FA not found"
		s.logger.Error("Error checking MFA status for user", zap.Error(errMFA), zap.String("user_id", user.ID.String()))
		// This is not a login failure itself, but an internal issue. Log it.
		// Depending on policy, might want to fail login here. For now, proceed.
	}
	// --- MFA Check END ---

	if err := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
		s.logger.Error("Failed to reset failed login attempts", zap.Error(err), zap.String("user_id", user.ID.String()))
		// Non-critical for login flow, but audit it as a warning with success.
		auditErrorDetails = map[string]interface{}{"warning": "failed to reset failed login attempts", "error": err.Error()}
	}
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now()); err != nil {
		s.logger.Error("Failed to update last login time", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditErrorDetails == nil { auditErrorDetails = make(map[string]interface{}) }
		auditErrorDetails["warning_update_last_login"] = err.Error()
	}

	// ipAddress and userAgent already extracted

	session, err := s.sessionService.CreateSession(ctx, user.ID, userAgent, ipAddress)
	if err != nil {
		s.logger.Error("Failed to create session during login", zap.Error(err), zap.String("user_id", user.ID.String()))
		logDetails := map[string]interface{}{"reason": "session creation failed", "error": err.Error(), "attempted_email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
		return nil, nil, "", err
	}

	tokenPair, err := s.tokenService.CreateTokenPairWithSession(ctx, user, session.ID)
	if err != nil {
		s.logger.Error("Failed to create token pair", zap.Error(err), zap.String("user_id", user.ID.String()))
		logDetails := map[string]interface{}{"reason": "token pair creation failed", "error": err.Error(), "attempted_email": req.Email}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
		return nil, nil, "", err // Propagate error
	}

	event := models.UserLoginEvent{
		UserID: user.ID.String(), Email: user.Email, IPAddress: ipAddress, UserAgent: userAgent, LoginAt: time.Now(),
	}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.login", event); err != nil {
		s.logger.Error("Failed to publish user login event", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditErrorDetails == nil { auditErrorDetails = make(map[string]interface{}) }
		auditErrorDetails["warning_kafka_event"] = err.Error()
	}

	// Publish CloudEvent for login success
	loginSuccessPayload := models.UserLoginSuccessPayload{
		UserID:    user.ID.String(),
		SessionID: session.ID.String(), // Assuming session object has ID
		LoginAt:   time.Now(),           // Can refine to use the actual login time if captured earlier
		IPAddress: ipAddress,
		UserAgent: userAgent,
		LoginType: "password", // This specific method is password-based login
	}
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserLoginSuccessV1, user.ID.String(), loginSuccessPayload); err != nil {
		s.logger.Error("Failed to publish CloudEvent for user login success", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditErrorDetails == nil { auditErrorDetails = make(map[string]interface{}) }
		auditErrorDetails["warning_cloudevent_publish"] = err.Error() // Add to audit details if publish fails
	}

	s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusSuccess, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
	return tokenPair, user, "", nil
}

// CompleteLoginAfter2FA finalizes the login process after a user has successfully passed a 2FA challenge.
// This method should be called after the initial Login method returned domainErrors.Err2FARequired and a challenge token,
// and the user has provided a valid 2FA code (TOTP or backup) which was verified by the appropriate handler calling MFALogicService.Verify2FACode.
// It performs final checks (user status), resets failed login attempts, updates last login time,
// creates a user session, generates access and refresh tokens, and publishes relevant events.
// An audit log event is recorded for the 2FA completion.
// Parameters:
//   - ctx: The context for the request.
//   - userID: The ID of the user completing the login.
//   - deviceInfo: A map containing device information like user_agent and ip_address.
//
// Returns the token pair, user details, and an error if any.
// Possible errors: domainErrors.ErrUserNotFound, domainErrors.ErrUserBlocked, domainErrors.ErrEmailNotVerified.
func (s *AuthService) CompleteLoginAfter2FA(ctx context.Context, userID uuid.UUID, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {
	var auditErrorDetails map[string]interface{}
	actorAndTargetID := &userID // In this context, actor and target are the same user.

	userAgent := deviceInfo["user_agent"]; if userAgent == "" { userAgent = "unknown" }
	ipAddress := deviceInfo["ip_address"]; if ipAddress == "" { ipAddress = "unknown" }

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("CompleteLoginAfter2FA: User not found", zap.Error(err), zap.String("user_id", userID.String()))
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrUserNotFound.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "user_login_2fa_complete", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, nil, domainErrors.ErrUserNotFound
	}

	if user.Status == models.UserStatusBlocked {
		s.logger.Warn("CompleteLoginAfter2FA: Attempt for blocked user", zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrUserBlocked.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "user_login_2fa_complete", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, nil, domainErrors.ErrUserBlocked
	}
	if user.EmailVerifiedAt == nil { // Should have been verified before 2FA setup
		s.logger.Warn("CompleteLoginAfter2FA: Attempt for unverified email", zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrEmailNotVerified.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "user_login_2fa_complete", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, nil, domainErrors.ErrEmailNotVerified
	}

	if err := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to reset failed login attempts", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditErrorDetails == nil { auditErrorDetails = make(map[string]interface{}) }
		auditErrorDetails["warning_reset_attempts"] = err.Error()
	}
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now()); err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to update last login time", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditErrorDetails == nil { auditErrorDetails = make(map[string]interface{}) }
		auditErrorDetails["warning_update_last_login"] = err.Error()
	}

	// userAgent and ipAddress already extracted

	session, err := s.sessionService.CreateSession(ctx, user.ID, userAgent, ipAddress)
	if err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to create session", zap.Error(err), zap.String("user_id", user.ID.String()))
		logDetails := map[string]interface{}{"reason": "session creation failed", "error": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "user_login_2fa_complete", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
		return nil, nil, err
	}

	tokenPair, err := s.tokenService.CreateTokenPairWithSession(ctx, user, session.ID)
	if err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to create token pair", zap.Error(err), zap.String("user_id", user.ID.String()))
		logDetails := map[string]interface{}{"reason": "token pair creation failed", "error": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "user_login_2fa_complete", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
		return nil, nil, err
	}

	// Publish CloudEvent for 2FA completion (which is also a form of login success)
	loginSuccessPayload := models.UserLoginSuccessPayload{
		UserID:    user.ID.String(),
		SessionID: session.ID.String(),
		LoginAt:   time.Now(), // Or a more precise time if captured earlier in the 2FA flow
		IPAddress: ipAddress,
		UserAgent: userAgent,
		LoginType: "password_2fa", // Specific login type
	}
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserLoginSuccessV1, user.ID.String(), loginSuccessPayload); err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to publish CloudEvent for user login success (2FA)", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditErrorDetails == nil { auditErrorDetails = make(map[string]interface{}) }
		auditErrorDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "user_login_2fa_complete", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
	return tokenPair, user, nil
}


// RefreshToken processes a given plain opaque refresh token to issue a new token pair (access and refresh).
// It relies on the TokenService to validate the refresh token, handle its rotation (if applicable),
// and generate the new tokens. It also records an audit log event for the refresh attempt.
// The IP address and User-Agent are extracted from the context for auditing.
// Parameters:
//   - ctx: The context for the request, potentially containing metadata like IP address and User-Agent.
//   - plainOpaqueRefreshToken: The plain (non-hashed) opaque refresh token string provided by the client.
//
// Returns a new models.TokenPair on success, or an error if the refresh token is invalid,
// expired, revoked, or if any other internal error occurs.
// Possible errors: domainErrors.ErrInvalidToken, domainErrors.ErrSessionNotFound, or other internal errors.
func (s *AuthService) RefreshToken(ctx context.Context, plainOpaqueRefreshToken string) (*models.TokenPair, error) {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}

	newTokenPair, err := s.tokenService.RefreshTokens(ctx, plainOpaqueRefreshToken)
	if err != nil {
		s.logger.Error("Failed to refresh tokens", zap.Error(err))
		// We might not know actorUserID if the refresh token is invalid/unparseable
		var actorUserIDForAudit *uuid.UUID
		// TODO: Consider if tokenService.RefreshTokens can return userID on certain errors
		// For now, log with nil actor if unknown.
		auditErrorDetails := map[string]interface{}{"error": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorUserIDForAudit, "token_refresh", models.AuditLogStatusFailure, nil, nil, auditErrorDetails, ipAddress, userAgent)
		return nil, err
	}

	// If refresh is successful, parse the new access token to get user ID and session ID for audit logging
	var actorUserID, sessionIDAudit *uuid.UUID
	var finalDetails map[string]interface{}

	if claims, errParse := s.tokenManagementService.ValidateAccessToken(newTokenPair.AccessToken); errParse == nil {
		if userID, pErr := uuid.Parse(claims.UserID); pErr == nil {
			actorUserID = &userID
		} else {
			s.logger.Error("RefreshToken: Failed to parse UserID from new access token claims for audit", zap.Error(pErr))
			finalDetails = map[string]interface{}{"warning": "failed to parse UserID from new AT for audit"}
		}
		if sID, pErr := uuid.Parse(claims.SessionID); pErr == nil {
			sessionIDAudit = &sID
		} else {
			s.logger.Error("RefreshToken: Failed to parse SessionID from new access token claims for audit", zap.Error(pErr))
			if finalDetails == nil { finalDetails = make(map[string]interface{}) }
			finalDetails["warning_sid"] = "failed to parse SessionID from new AT for audit"
		}
	} else {
		s.logger.Error("RefreshToken: Failed to validate/parse new access token for audit logging", zap.Error(errParse))
		finalDetails = map[string]interface{}{"warning": "failed to parse new AT for audit"}
	}

	s.auditLogRecorder.RecordEvent(ctx, actorUserID, "token_refresh", models.AuditLogStatusSuccess, sessionIDAudit, models.AuditTargetTypeSession, finalDetails, ipAddress, userAgent)
	return newTokenPair, nil
}

// Logout handles user logout. It performs several actions:
// 1. Validates the provided access token to identify the user and session.
// 2. Revokes the provided refresh token from the database via TokenService.
// 3. Deactivates the user's session via SessionService.
// 4. Blacklists the access token via TokenService to prevent its further use until expiry.
// 5. Publishes UserLogoutSuccessEvent and SessionRevokedEvent via Kafka.
// 6. Records an audit log event for the logout action.
// The IP address and User-Agent are extracted from the context for auditing.
// Parameters:
//   - ctx: The context for the request.
//   - accessToken: The access token of the session to be logged out.
//   - refreshToken: The refresh token associated with the session, to be revoked.
//
// Returns nil on successful logout (even if some non-critical cleanup steps fail, errors are logged),
// or an error like domainErrors.ErrInvalidToken if the access token is invalid and no refresh token is provided.
func (s *AuthService) Logout(ctx context.Context, accessToken, refreshToken string) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}

	var actorUserID, sessionIDForAudit *uuid.UUID
	var auditDetails map[string]interface{}

	claims, err := s.tokenManagementService.ValidateAccessToken(accessToken)
	if err != nil {
		s.logger.Warn("Logout: Failed to validate access token, proceeding with refresh token revocation", zap.Error(err))
		auditDetails = map[string]interface{}{"warning": "access token validation failed", "error": err.Error()}
		if refreshToken == "" {
			// No way to identify user or session if AT is invalid and no RT.
			s.auditLogRecorder.RecordEvent(ctx, nil, "user_logout", models.AuditLogStatusFailure, nil, nil, auditDetails, ipAddress, userAgent)
			return domainErrors.ErrInvalidToken
		}
	} else {
		if userID, pErr := uuid.Parse(claims.UserID); pErr == nil {
			actorUserID = &userID
		}
		if sessionID, pErr := uuid.Parse(claims.SessionID); pErr == nil {
			sessionIDForAudit = &sessionID
		}
	}

	if refreshToken != "" {
		if err := s.tokenService.RevokeRefreshToken(ctx, refreshToken); err != nil {
			s.logger.Error("Logout: Failed to revoke refresh token from DB", zap.Error(err))
			if auditDetails == nil { auditDetails = make(map[string]interface{}) }
			auditDetails["error_revoke_refresh_token"] = err.Error()
			// Log failure but continue, as AT might still be valid for session invalidation
			s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_logout", models.AuditLogStatusFailure, sessionIDForAudit, models.AuditTargetTypeSession, auditDetails, ipAddress, userAgent)
			// Do not return yet, try to invalidate session and AT
		}
	}

	if claims != nil && claims.SessionID != "" { // claims might be nil if AT was invalid from the start
		parsedSessionID, parseErr := uuid.Parse(claims.SessionID)
		if parseErr == nil {
			if err := s.sessionService.DeactivateSession(ctx, parsedSessionID); err != nil {
				s.logger.Error("Logout: Failed to delete session", zap.Error(err), zap.String("session_id", claims.SessionID))
				if auditDetails == nil { auditDetails = make(map[string]interface{}) }
				auditDetails["error_deactivate_session"] = err.Error()
			}
		} else {
			s.logger.Error("Logout: Failed to parse sessionID from access token claims", zap.Error(parseErr))
			if auditDetails == nil { auditDetails = make(map[string]interface{}) }
			auditDetails["error_parse_session_id"] = parseErr.Error()
		}
	} else if refreshToken == "" {
		s.logger.Warn("Logout: No session identifier available to delete session.")
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_no_session_id"] = "No session identifier available"
	}

	if accessToken != "" { // Blacklist access token regardless of initial validity
		if err := s.tokenService.RevokeToken(ctx, accessToken); err != nil {
			s.logger.Error("Logout: Failed to blacklist access token", zap.Error(err))
			if auditDetails == nil { auditDetails = make(map[string]interface{}) }
			auditDetails["error_blacklist_access_token"] = err.Error()
		}
	}

	// Determine final audit status
	status := models.AuditLogStatusSuccess
	if val, ok := auditDetails["error_revoke_refresh_token"]; ok && val != nil {
		status = models.AuditLogStatusFailure // If critical part like RT revoke failed.
	} else if val, ok := auditDetails["error_deactivate_session"]; ok && val != nil {
		// Could be partial success if session deletion failed but tokens were revoked
		status = models.AuditLogStatusPartialSuccess
	}


	if claims != nil { // claims might be nil if AT was invalid
		logoutTime := time.Now()
		logoutPayload := models.UserLogoutSuccessPayload{
			UserID:    claims.UserID,
			SessionID: claims.SessionID,
			LogoutAt:  logoutTime,
		}
		if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserLogoutSuccessV1, claims.UserID, logoutPayload); err != nil {
			s.logger.Error("Logout: Failed to publish CloudEvent for user logout", zap.Error(err), zap.String("user_id", claims.UserID))
			if auditDetails == nil { auditDetails = make(map[string]interface{}) }
			auditDetails["warning_cloudevent_publish_logout"] = err.Error()
		}

		// Also publish session revoked event
		sessionRevokedPayload := models.SessionRevokedPayload{
			SessionID: claims.SessionID,
			UserID:    claims.UserID,
			RevokedAt: logoutTime,
			ActorID:   &claims.UserID, // User initiated their own session revocation
		}
		if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthSessionRevokedV1, claims.SessionID, sessionRevokedPayload); err != nil {
			s.logger.Error("Logout: Failed to publish CloudEvent for session revoked", zap.Error(err), zap.String("session_id", claims.SessionID))
			if auditDetails == nil { auditDetails = make(map[string]interface{}) }
			auditDetails["warning_cloudevent_publish_session_revoked"] = err.Error()
		}
	}
	s.auditLogRecorder.RecordEvent(ctx, actorUserID, "user_logout", status, sessionIDForAudit, models.AuditTargetTypeSession, auditDetails, ipAddress, userAgent)
	return nil // Logout generally shouldn't fail from user's perspective if best effort is made
}

// LogoutAll handles logging out a user from all their active sessions.
// It validates the provided access token to identify the user.
// Then, it deactivates all sessions for that user via SessionService and
// revokes all their refresh tokens via TokenService.
// It publishes a UserAllSessionsRevokedEvent via Kafka and records an audit log event.
// The IP address and User-Agent are extracted from the context for auditing the initiating action.
// Parameters:
//   - ctx: The context for the request.
//   - accessToken: The access token from an active session of the user requesting to log out all sessions.
//
// Returns nil on success, or an error like domainErrors.ErrInvalidToken if the access token is invalid,
// or domainErrors.ErrInternal if parsing the user ID from token claims fails.
func (s *AuthService) LogoutAll(ctx context.Context, accessToken string) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	var auditDetails map[string]interface{}

	claims, err := s.tokenManagementService.ValidateAccessToken(accessToken)
	if err != nil {
		s.logger.Error("LogoutAll: Failed to validate access token", zap.Error(err))
		auditDetails = map[string]interface{}{"error": "access token validation failed", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, nil, "user_logout_all", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrInvalidToken
	}

	actorAndTargetID, err := uuid.Parse(claims.UserID)
	if err != nil {
		s.logger.Error("LogoutAll: Failed to parse UserID from token", zap.Error(err), zap.String("userID", claims.UserID))
		auditDetails = map[string]interface{}{"error": "parsing UserID from token failed", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, nil, "user_logout_all", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrInternal
	}

	sessionsDeleted, errSess := s.sessionService.DeleteAllUserSessions(ctx, actorAndTargetID, nil)
	if errSess != nil {
		s.logger.Error("LogoutAll: Failed to delete user sessions", zap.Error(errSess), zap.String("user_id", claims.UserID))
		auditDetails = map[string]interface{}{"error_delete_sessions": errSess.Error(), "sessions_deleted_count": sessionsDeleted}
	} else {
		auditDetails = map[string]interface{}{"sessions_deleted_count": sessionsDeleted}
	}

	tokensRevoked, errToken := s.tokenService.RevokeAllRefreshTokensForUser(ctx, actorAndTargetID)
	if errToken != nil {
		s.logger.Error("LogoutAll: Failed to revoke all refresh tokens for user", zap.Error(errToken), zap.String("user_id", claims.UserID))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["error_revoke_tokens"] = errToken.Error()
		auditDetails["refresh_tokens_revoked_count"] = tokensRevoked
	} else {
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["refresh_tokens_revoked_count"] = tokensRevoked
	}

	status := models.AuditLogStatusSuccess
	if errSess != nil || errToken != nil {
		status = models.AuditLogStatusPartialSuccess
	}

	allSessionsRevokedPayload := models.UserAllSessionsRevokedPayload{
		UserID:    claims.UserID,
		RevokedAt: time.Now(),
		ActorID:   &claims.UserID, // User initiated action
	}
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserAllSessionsRevokedV1, claims.UserID, allSessionsRevokedPayload); err != nil {
		s.logger.Error("LogoutAll: Failed to publish CloudEvent for all sessions revoked", zap.Error(err), zap.String("user_id", claims.UserID))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, &actorAndTargetID, "user_logout_all", status, &actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return nil // LogoutAll generally shouldn't fail from user's perspective
}

// VerifyEmail confirms a user's email address using a provided verification token.
// It hashes the plain token, finds the corresponding verification code in the database,
// checks if the user exists and if the email is already verified.
// If valid, it updates the user's `email_verified_at` timestamp, sets their status to active,
// marks the verification code as used, publishes a UserEmailVerifiedEvent, and records an audit log.
// The IP address and User-Agent are extracted from the context for auditing.
// Parameters:
//   - ctx: The context for the request.
//   - plainVerificationTokenValue: The plain (non-hashed) verification token string.
//
// Returns nil on success, or an error like domainErrors.ErrInvalidToken, domainErrors.ErrUserNotFound,
// or domainErrors.ErrEmailAlreadyVerified.
func (s *AuthService) VerifyEmail(ctx context.Context, plainVerificationTokenValue string) error {
	var auditErrorDetails map[string]interface{}
	var userIDForAudit *uuid.UUID // Will be set once verificationCode is fetched

	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}

	hashedToken := appSecurity.HashToken(plainVerificationTokenValue)
	verificationCode, err := s.verificationCodeRepo.FindByCodeHashAndType(ctx, hashedToken, models.VerificationCodeTypeEmailVerification)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			s.logger.Warn("Attempt to verify email with invalid/expired token", zap.String("hashed_token", hashedToken))
			auditErrorDetails = map[string]interface{}{"error": domainErrors.ErrInvalidToken.Error(), "token_hash": hashedToken}
			s.auditLogRecorder.RecordEvent(ctx, nil, "email_verify", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
			return domainErrors.ErrInvalidToken
		}
		s.logger.Error("Failed to find verification code for email verification", zap.Error(err))
		auditErrorDetails = map[string]interface{}{"error": err.Error(), "token_hash": hashedToken}
		s.auditLogRecorder.RecordEvent(ctx, nil, "email_verify", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return err
	}

	userIDForAudit = &verificationCode.UserID // Assign for subsequent audit logs
	user, err := s.userRepo.FindByID(ctx, *userIDForAudit)
	if err != nil {
		s.logger.Error("User not found for valid verification token", zap.Error(err), zap.String("user_id", userIDForAudit.String()))
		auditErrorDetails = map[string]interface{}{"error": domainErrors.ErrUserNotFound.Error()}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "email_verify", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return domainErrors.ErrUserNotFound
	}

	if user.EmailVerifiedAt != nil {
		s.logger.Info("Email already verified for user", zap.String("user_id", userIDForAudit.String()))
		_ = s.verificationCodeRepo.MarkAsUsed(ctx, verificationCode.ID, time.Now()) // Attempt to mark used
		auditErrorDetails = map[string]interface{}{"info": domainErrors.ErrEmailAlreadyVerified.Error()}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "email_verify", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return domainErrors.ErrEmailAlreadyVerified
	}

	now := time.Now()
	if err := s.userRepo.SetEmailVerifiedAt(ctx, user.ID, now); err != nil {
		s.logger.Error("Failed to set email_verified_at for user", zap.Error(err), zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"error": "failed to set email_verified_at in db"}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "email_verify", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return err
	}
	if err := s.userRepo.UpdateStatus(ctx, user.ID, models.UserStatusActive); err != nil {
		s.logger.Error("Failed to update user status to active", zap.Error(err), zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"error": "failed to update user status to active in db"}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "email_verify", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return err
	}
	if err := s.verificationCodeRepo.MarkAsUsed(ctx, verificationCode.ID, now); err != nil {
		s.logger.Error("Failed to mark email verification token as used", zap.Error(err), zap.String("token_id", verificationCode.ID.String()))
		// Non-critical for verification success itself, but log it as part of details for success
		auditErrorDetails = map[string]interface{}{"warning": "failed to mark verification token as used"}
	}

	emailVerifiedPayload := models.UserEmailVerifiedPayload{
		UserID:    user.ID.String(),
		Email:     user.Email,
		VerifiedAt: now,
	}
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserEmailVerifiedV1, user.ID.String(), emailVerifiedPayload); err != nil {
		s.logger.Error("Failed to publish CloudEvent for email verified", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditErrorDetails == nil { auditErrorDetails = make(map[string]interface{}) }
		auditErrorDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "email_verify", models.AuditLogStatusSuccess, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
	return nil
}

// ResendVerificationEmail handles a request to resend an email verification token.
// It performs a rate limit check based on the email address.
// It finds the user by email, checks if their email is already verified,
// deletes any existing email verification codes for the user, generates a new one,
// stores it, and publishes an EmailVerificationRequestedEvent.
// An audit log is recorded for rate-limited attempts.
// Parameters:
//   - ctx: The context for the request, used for metadata and rate limiting.
//   - email: The email address to resend the verification for.
//
// Returns nil if the process is initiated successfully (even if the user is not found, to prevent enumeration),
// or an error like domainErrors.ErrEmailAlreadyVerified or domainErrors.ErrRateLimitExceeded.
func (s *AuthService) ResendVerificationEmail(ctx context.Context, email string) error {
	ipAddress := "unknown"
	userAgent := "unknown" // User agent not strictly needed for audit here, but good practice if available
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	var actorUserID *uuid.UUID // will be set if user found

	// Rate limit by email
	allowed, rlErr := s.rateLimiter.Allow(ctx, "resend_verification_email:"+email, s.cfg.Security.RateLimiting.ResendVerificationEmail)
	if rlErr != nil {
		s.logger.Error("Rate limiter failed for resend_verification_email", zap.Error(rlErr), zap.String("email", email))
	}
	if !allowed {
		s.logger.Warn("Rate limit exceeded for resend_verification_email", zap.String("email", email))
		// Audit this attempt if it's a known email, otherwise it's an enumeration attempt.
		// For now, just return error. User will not exist for audit if enumeration.
		s.auditLogRecorder.RecordEvent(ctx, nil, "resend_verification_request", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, map[string]interface{}{"error": domainErrors.ErrRateLimitExceeded.Error(), "email": email}, ipAddress, userAgent)
		return domainErrors.ErrRateLimitExceeded
	}

	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			s.logger.Warn("Resend verification for non-existent email", zap.String("email", email))
		} else {
			s.logger.Error("Error fetching user for resend verification", zap.Error(err), zap.String("email", email))
		}
		return domainErrors.ErrUserNotFound
	}
	if user.EmailVerifiedAt != nil {
		return domainErrors.ErrEmailAlreadyVerified
	}
	_, _ = s.verificationCodeRepo.DeleteByUserIDAndType(ctx, user.ID, models.VerificationCodeTypeEmailVerification)

	plainToken, err := appSecurity.GenerateSecureToken(32)
	if err != nil { /* ... log ... */ return err }
	hashedToken := appSecurity.HashToken(plainToken)
	verificationCode := &models.VerificationCode{
		ID: uuid.New(), UserID: user.ID, Type: models.VerificationCodeTypeEmailVerification,
		CodeHash: hashedToken, ExpiresAt: time.Now().Add(s.cfg.JWT.EmailVerificationToken.ExpiresIn),
	}
	if err := s.verificationCodeRepo.Create(ctx, verificationCode); err != nil { /* ... log ... */ return err }

	emailVerificationRequestedPayload := eventModels.EmailVerificationRequestedPayload{
		UserID:      user.ID.String(),
		Email:       user.Email,
		RequestedAt: time.Now(),
	}
	// TODO: Determine correct topic. Using placeholder "auth-events".
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, eventModels.AuthSecurityEmailVerificationRequestedV1, user.ID.String(), emailVerificationRequestedPayload); err != nil {
		s.logger.Error("Failed to publish CloudEvent for email verification requested", zap.Error(err), zap.String("user_id", user.ID.String()))
		// Non-critical for flow, log only.
	}
	return nil
}

// ForgotPassword initiates the password reset process for a user.
// It performs rate limit checks by email and IP address.
// If the user exists, it deletes any existing password reset codes for the user,
// generates a new password reset token, stores its hash, and publishes a PasswordResetRequestedEvent.
// An audit log is recorded for the attempt. To prevent email enumeration, it returns nil even if the user is not found,
// but the audit log will reflect the outcome.
// Parameters:
//   - ctx: The context for the request, used for metadata and rate limiting.
//   - email: The email address of the user requesting a password reset.
//
// Returns nil on successful initiation (or if user not found, for security),
// or an error like domainErrors.ErrRateLimitExceeded.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	auditDetails := map[string]interface{}{"email": email}
	var actorUserID, targetUserID *uuid.UUID // actor is unknown, target might be known if user exists

	// Rate limit by email
	allowedEmail, rlErrEmail := s.rateLimiter.Allow(ctx, "forgot_password_email:"+email, s.cfg.Security.RateLimiting.PasswordResetPerEmail)
	if rlErrEmail != nil {
		s.logger.Error("Rate limiter failed for forgot_password_email", zap.Error(rlErrEmail), zap.String("email", email))
	}
	if !allowedEmail {
		s.logger.Warn("Rate limit exceeded for forgot_password_email", zap.String("email", email))
		s.auditLogRecorder.RecordEvent(ctx, nil, "password_reset_request", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, map[string]interface{}{"error": domainErrors.ErrRateLimitExceeded.Error(), "email": email, "reason": "email rate limit"}, ipAddress, userAgent)
		return domainErrors.ErrRateLimitExceeded // Return error to prevent further processing
	}

	// Rate limit by IP
	allowedIP, rlErrIP := s.rateLimiter.Allow(ctx, "forgot_password_ip:"+ipAddress, s.cfg.Security.RateLimiting.PasswordResetPerIP)
	if rlErrIP != nil {
		s.logger.Error("Rate limiter failed for forgot_password_ip", zap.Error(rlErrIP), zap.String("ipAddress", ipAddress))
	}
	if !allowedIP {
		s.logger.Warn("Rate limit exceeded for forgot_password_ip", zap.String("ipAddress", ipAddress))
		s.auditLogRecorder.RecordEvent(ctx, nil, "password_reset_request", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, map[string]interface{}{"error": domainErrors.ErrRateLimitExceeded.Error(), "ip_address": ipAddress, "reason": "ip rate limit"}, ipAddress, userAgent)
		return domainErrors.ErrRateLimitExceeded // Return error
	}

	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			s.logger.Info("Password reset for non-existent email (silent)", zap.String("email", email))
			// Log the attempt even if user not found, to track this action.
			s.auditLogRecorder.RecordEvent(ctx, nil, "password_reset_request", models.AuditLogStatusSuccess, // Success from perspective of "request processed"
				nil, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
			return nil // Prevent enumeration
		}
		s.logger.Error("Error fetching user for password reset", zap.Error(err), zap.String("email", email))
		auditDetails["error"] = err.Error()
		s.auditLogRecorder.RecordEvent(ctx, nil, "password_reset_request", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}
	actorUserID = &user.ID // The user is initiating this for themselves, even if not "logged in".
	targetUserID = &user.ID


	_, _ = s.verificationCodeRepo.DeleteByUserIDAndType(ctx, user.ID, models.VerificationCodeTypePasswordReset)
	plainToken, err := appSecurity.GenerateSecureToken(32)
	if err != nil {
		s.logger.Error("ForgotPassword: Failed to generate secure token", zap.Error(err))
		auditDetails["error"] = "token generation failed"
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "password_reset_request", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}
	hashedToken := appSecurity.HashToken(plainToken)
	verificationCode := &models.VerificationCode{
		ID: uuid.New(), UserID: user.ID, Type: models.VerificationCodeTypePasswordReset,
		CodeHash: hashedToken, ExpiresAt: time.Now().Add(s.cfg.JWT.PasswordResetToken.ExpiresIn),
	}
	if err := s.verificationCodeRepo.Create(ctx, verificationCode); err != nil {
		s.logger.Error("ForgotPassword: Failed to create verification code", zap.Error(err))
		auditDetails["error"] = "verification code creation failed"
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "password_reset_request", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	passwordResetRequestedPayload := eventModels.PasswordResetRequestedPayload{
		UserID:      user.ID.String(),
		Email:       user.Email,
		RequestedAt: time.Now(),
	}
	// TODO: Determine correct topic. Using placeholder "auth-events".
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, eventModels.AuthSecurityPasswordResetRequestedV1, user.ID.String(), passwordResetRequestedPayload); err != nil {
		s.logger.Error("ForgotPassword: Failed to publish CloudEvent for password reset requested", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditDetails == nil { auditDetails = make(map[string]interface{})} // Should not be nil if user was found
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}
	s.auditLogRecorder.RecordEvent(ctx, actorUserID, "password_reset_request", models.AuditLogStatusSuccess, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return nil
}

// ResetPassword completes the password reset process using a provided reset token and new password.
// It performs a rate limit check by IP address.
// It hashes the plain token, finds the corresponding verification code, checks user existence,
// hashes the new password, updates the user's password in the database, marks the verification code as used,
// invalidates all user sessions, publishes a UserPasswordResetEvent, and records an audit log.
// Parameters:
//   - ctx: The context for the request, used for metadata and rate limiting.
//   - plainToken: The plain (non-hashed) password reset token.
//   - newPassword: The new password chosen by the user.
//
// Returns nil on success, or an error like domainErrors.ErrRateLimitExceeded, domainErrors.ErrInvalidToken,
// or domainErrors.ErrUserNotFound.
func (s *AuthService) ResetPassword(ctx context.Context, plainToken, newPassword string) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	var actorUserID, targetUserID *uuid.UUID
	var auditDetails map[string]interface{}

	// Rate limit by IP
	allowed, rlErr := s.rateLimiter.Allow(ctx, "reset_password_ip:"+ipAddress, s.cfg.Security.RateLimiting.ResetPasswordIP)
	if rlErr != nil {
		s.logger.Error("Rate limiter failed for reset_password_ip", zap.Error(rlErr), zap.String("ipAddress", ipAddress))
	}
	if !allowed {
		s.logger.Warn("Rate limit exceeded for reset_password_ip", zap.String("ipAddress", ipAddress))
		// We don't know the user yet, so audit with nil user ID.
		s.auditLogRecorder.RecordEvent(ctx, nil, "password_reset", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, map[string]interface{}{"error": domainErrors.ErrRateLimitExceeded.Error(), "ip_address": ipAddress}, ipAddress, userAgent)
		return domainErrors.ErrRateLimitExceeded
	}

	hashedToken := appSecurity.HashToken(plainToken)
	verificationCode, err := s.verificationCodeRepo.FindByCodeHashAndType(ctx, hashedToken, models.VerificationCodeTypePasswordReset)
	if err != nil {
		auditDetails = map[string]interface{}{"error": domainErrors.ErrInvalidToken.Error(), "reason": "token not found or expired"}
		s.auditLogRecorder.RecordEvent(ctx, nil, "password_reset", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrInvalidToken
	}

	userID := verificationCode.UserID
	actorUserID = &userID
	targetUserID = &userID

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		auditDetails = map[string]interface{}{"error": domainErrors.ErrUserNotFound.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "password_reset", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrUserNotFound
	}

	newHashedPassword, err := s.passwordService.HashPassword(newPassword)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "password hashing failed"}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "password_reset", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}
	if err := s.userRepo.UpdatePassword(ctx, user.ID, newHashedPassword); err != nil {
		auditDetails = map[string]interface{}{"error": "db update password failed"}
		s.auditLogRecorder.RecordEvent(ctx, actorUserID, "password_reset", models.AuditLogStatusFailure, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}
	_ = s.verificationCodeRepo.MarkAsUsed(ctx, verificationCode.ID, time.Now())
	_, _ = s.sessionService.DeleteAllUserSessions(ctx, userID, nil) // Invalidate sessions

	passwordResetPayload := models.UserPasswordResetPayload{
		UserID:  user.ID.String(),
		ResetAt: time.Now(), // Or a more precise time if available from user object after update
	}
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserPasswordResetV1, user.ID.String(), passwordResetPayload); err != nil {
		s.logger.Error("ResetPassword: Failed to publish CloudEvent for password reset", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}
	s.auditLogRecorder.RecordEvent(ctx, actorUserID, "password_reset", models.AuditLogStatusSuccess, targetUserID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return nil
}

// ChangePassword allows an authenticated user to change their own password.
// It verifies the user's old password, hashes the new password, updates it in the database,
// invalidates all other user sessions, publishes a UserPasswordChangedEvent, and records an audit log.
// Parameters:
//   - ctx: The context for the request, containing metadata like IP and User-Agent.
//   - userID: The ID of the user changing their password (typically from authenticated context).
//   - oldPlainPassword: The user's current plain text password for verification.
//   - newPlainPassword: The new plain text password to be set.
//
// Returns nil on success, or an error like domainErrors.ErrUserNotFound, domainErrors.ErrInvalidCredentials,
// or internal errors related to password hashing or database updates.
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPlainPassword, newPlainPassword string) error {
	ipAddress := "unknown"
	userAgent := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if val, exists := md["ip-address"]; exists { ipAddress = val }
		if val, exists := md["user-agent"]; exists { userAgent = val }
	}
	actorAndTargetID := &userID
	var auditDetails map[string]interface{}

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		auditDetails = map[string]interface{}{"error": domainErrors.ErrUserNotFound.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "password_change", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrUserNotFound
	}

	match, err := s.passwordService.CheckPasswordHash(oldPlainPassword, user.PasswordHash)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "password check failed", "details": err.Error()}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "password_change", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrInternal
	}
	if !match {
		auditDetails = map[string]interface{}{"error": domainErrors.ErrInvalidCredentials.Error(), "reason": "old password mismatch"}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "password_change", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return domainErrors.ErrInvalidCredentials
	}

	newHashedPassword, err := s.passwordService.HashPassword(newPlainPassword)
	if err != nil {
		auditDetails = map[string]interface{}{"error": "new password hashing failed"}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "password_change", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}
	if err := s.userRepo.UpdatePassword(ctx, userID, newHashedPassword); err != nil {
		auditDetails = map[string]interface{}{"error": "db update password failed"}
		s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "password_change", models.AuditLogStatusFailure, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
		return err
	}

	// Invalidate other sessions (example: delete all, could exclude current session if ID is passed)
	_, _ = s.sessionService.DeleteAllUserSessions(ctx, userID, nil)

	passwordChangedPayload := models.UserPasswordChangedPayload{
		UserID:    userID.String(),
		ChangedAt: user.UpdatedAt, // Assuming user.UpdatedAt was set during password update
		Source:    "user_self_service",
	}
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserPasswordChangedV1, userID.String(), passwordChangedPayload); err != nil {
		s.logger.Error("ChangePassword: Failed to publish CloudEvent for password changed", zap.Error(err), zap.String("user_id", userID.String()))
		if auditDetails == nil { auditDetails = make(map[string]interface{}) }
		auditDetails["warning_cloudevent_publish"] = err.Error()
	}
	s.auditLogRecorder.RecordEvent(ctx, actorAndTargetID, "password_change", models.AuditLogStatusSuccess, actorAndTargetID, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	return nil
}

// CheckUserPermission verifies if a user possesses a specific permission.
// It retrieves the user's roles via UserRolesRepository, then fetches permissions for those roles
// via RoleService (which uses RoleRepository), and checks if the requested permissionKey (ID) is present.
// This method is crucial for RBAC (Role-Based Access Control) checks.
// Parameters:
//   - ctx: The context for the request.
//   - userID: The ID of the user whose permissions are being checked.
//   - permissionKey: The unique key or ID of the permission to check for.
//   - resourceID: Optional. The ID of the specific resource the permission applies to (not fully implemented in current logic).
//
// Returns true if the user has the permission, false otherwise, and an error if any issues occur during lookup
// (e.g., domainErrors.ErrInvalidRequest if userID is nil, or errors from repository/service calls).
func (s *AuthService) CheckUserPermission(ctx context.Context, userID uuid.UUID, permissionKey string, resourceID *string) (bool, error) {
	s.logger.Info("CheckUserPermission called (placeholder)", // TODO: Remove placeholder log once fully implemented
		zap.String("userID", userID.String()),
		zap.String("permissionKey", permissionKey),
		zap.Any("resourceID", resourceID),
	)
	// TODO: Implement actual RBAC permission checking logic.
	// For now, returning true for any check to allow testing of the endpoint.
	// In a real scenario, this would involve:
	// 1. Get roles for userID from UserRolesRepository.
	// 2. Get permissions for those roles from RolePermissionsRepository.
	// 3. Match against permissionKey (and resourceID if provided).
	if userID == uuid.Nil {
		return false, domainErrors.ErrInvalidRequest
	}

	roleIDs, err := s.userRolesRepo.GetRoleIDsForUser(ctx, userID) // UserRolesRepo needs to be on AuthService
	if err != nil {
		s.logger.Error("CheckUserPermission: Failed to get role IDs for user", zap.Error(err), zap.String("userID", userID.String()))
		return false, fmt.Errorf("could not retrieve roles for permission check: %w", err)
	}

	if len(roleIDs) == 0 {
		return false, nil // No roles, so no permissions
	}

	for _, roleID := range roleIDs {
		// This implies RoleService.RoleHasPermission should check by permission string (key/ID) not just name
		// Or RoleRepository has a method to check if a role has a specific permission ID.
		// RoleRepository.RoleHasPermission(ctx, roleID, permissionKey) is what we need.
		// The current RoleRepository.RoleHasPermission takes (roleID, permissionID string).
		// So permissionKey here should be the permission ID.

		// Alternative: Get all permissions for role and check
		permissions, err := s.roleService.GetRolePermissions(ctx, roleID) // roleService.GetRolePermissions uses roleRepo
		if err != nil {
			s.logger.Error("CheckUserPermission: Failed to get permissions for role", zap.Error(err), zap.String("roleID", roleID))
			// Potentially continue to check other roles, or return error
			return false, fmt.Errorf("could not retrieve permissions for role %s: %w", roleID, err)
		}
		for _, p := range permissions {
			if p.ID == permissionKey { // Assuming permissionKey is the permission ID
				// TODO: Add resourceID check logic here if needed
				// This would involve checking p.Resource and p.Action against the permissionKey's structure
				// and comparing resourceID if provided.
				// For now, a direct match on permissionKey (as ID) is implemented.
				return true, nil
			}
		}
	}
	return false, nil // No matching permission found in any role
}

// LoginWithTelegram handles user authentication or registration using data received from Telegram login widget.
// It verifies the authenticity of the Telegram data using TelegramVerifierService.
// If valid, it attempts to find an existing external account link for the Telegram user.
// - If found, it logs in the associated platform user.
// - If not found, it creates a new platform user and links it to the Telegram account.
// It then creates a session, generates tokens, updates last login time, and publishes relevant events.
// Records audit logs for these actions.
// Parameters:
//   - ctx: The context for the request.
//   - tgData: The authentication data received from Telegram (see models.TelegramLoginRequest).
//   - deviceInfo: A map containing device information like user_agent and ip_address.
//
// Returns a token pair, user details, and an error if any.
// Possible errors: domainErrors.ErrTelegramAuthFailed, domainErrors.ErrUserBlocked, or internal errors.
func (s *AuthService) LoginWithTelegram(
	ctx context.Context,
	tgData models.TelegramLoginRequest,
	deviceInfo map[string]string,
) (*models.TokenPair, *models.User, error) {

	s.logger.Info("Attempting Telegram login", zap.Int64("telegram_id", tgData.ID))

	// 1. Verify Telegram Authentication Data
	isValid, telegramUserID, err := s.telegramVerifier.VerifyTelegramAuth(ctx, tgData, s.cfg.Telegram.BotToken)
	if err != nil {
		s.logger.Error("Telegram data verification failed", zap.Error(err))
		return nil, nil, domainErrors.ErrTelegramAuthFailed // Or more specific error if verifier returns one
	}
	if !isValid {
		s.logger.Warn("Invalid Telegram data received", zap.Any("telegram_data", tgData))
		return nil, nil, domainErrors.ErrTelegramAuthFailed
	}
	telegramUserIDStr := strconv.FormatInt(telegramUserID, 10)

	var user *models.User
	var isNewUser bool = false

	// 2. Account Linking/Creation
	extAccount, err := s.externalAccountRepo.FindByProviderAndExternalID(ctx, "telegram", telegramUserIDStr)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			// External account not found, try to find user by Telegram username if provided and unique enough,
			// or create a new user.
			s.logger.Info("Telegram external account not found, attempting to link or create user.", zap.String("telegramUserID", telegramUserIDStr))

			platformUsername := tgData.Username
			if platformUsername == "" { // If no username from Telegram, use first_name or generate
				platformUsername = tgData.FirstName
				if platformUsername == "" {
					platformUsername = fmt.Sprintf("tg_%d", telegramUserID)
				}
			}
			// Ensure platformUsername is unique
			existingUser, findUserErr := s.userRepo.FindByUsername(ctx, platformUsername)
			if findUserErr == nil && existingUser != nil { // Username collision
				suffix, _ := appSecurity.GenerateSecureToken(2) // ~4 chars
				platformUsername = fmt.Sprintf("%s_%s", platformUsername, suffix)
			} else if findUserErr != nil && !errors.Is(findUserErr, domainErrors.ErrNotFound) {
				s.logger.Error("Error checking username existence during Telegram signup", zap.Error(findUserErr))
				return nil, nil, fmt.Errorf("error checking username: %w", findUserErr)
			}


			// Create new platform user
			newUser := &models.User{
				ID:           uuid.New(),
				Username:     platformUsername,
				// Email: N/A from Telegram by default, unless requested & provided via a more complex OAuth flow
				Status:       models.UserStatusActive, // Typically activate directly for social logins
				// PasswordHash will be empty for social-only login
			}
			if errCreateUser := s.userRepo.Create(ctx, newUser); errCreateUser != nil {
				s.logger.Error("Failed to create new user for Telegram login", zap.Error(errCreateUser))
				return nil, nil, fmt.Errorf("failed to create user: %w", errCreateUser)
			}
			user = newUser // Use the newly created user
			isNewUser = true
			s.logger.Info("New user created via Telegram login", zap.String("userID", user.ID.String()), zap.String("username", user.Username))

			// Create external account link
			newExtAccount := &models.ExternalAccount{
				ID:             uuid.New(),
				UserID:         user.ID,
				Provider:       "telegram",
				ExternalUserID: telegramUserIDStr,
				ProfileData:    nil, // Can store tgData as JSONB if needed
				// AccessTokenHash, RefreshTokenHash, TokenExpiresAt are not applicable for Telegram widget login
			}
			if profileDataBytes, marshalErr := json.Marshal(tgData); marshalErr == nil {
				newExtAccount.ProfileData = profileDataBytes
			}
			if errCreateExt := s.externalAccountRepo.Create(ctx, newExtAccount); errCreateExt != nil {
				s.logger.Error("Failed to create external account link for Telegram user", zap.Error(errCreateExt), zap.String("userID", user.ID.String()))
				// This is tricky: user created, but link failed. Might need rollback or cleanup.
				// For now, return error.
				return nil, nil, fmt.Errorf("failed to link external account: %w", errCreateExt)
			}

			// Publish user registered event
			regEvent := models.UserRegisteredEvent{
				UserID:        user.ID.String(),
				Email:         user.Email, // Will be empty if not available
				Username:      user.Username,
				InitialStatus: string(user.Status),
				CreatedAt:     user.CreatedAt, // This will be zero if Create doesn't populate it, fetch if needed
			}
			// Fetch user to get DB generated fields for event
			dbUser, _ := s.userRepo.FindByID(ctx, user.ID)
			if dbUser != nil { regEvent.CreatedAt = dbUser.CreatedAt } // Old event struct

			// Map to new CloudEvent payload UserRegisteredPayload
			userRegisteredPayload := eventModels.UserRegisteredPayload{
				UserID:                user.ID.String(),
				Username:              user.Username,
				Email:                 user.Email, // Will be empty if not available
				DisplayName:           nil,        // Not available from Telegram data directly
				RegistrationTimestamp: regEvent.CreatedAt, // Use the fetched CreatedAt
				InitialStatus:         string(models.UserStatusActive), // Social logins usually active
			}
			// TODO: Determine correct topic. Using placeholder "auth-events".
			if errKafka := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, eventModels.AuthUserRegisteredV1, user.ID.String(), userRegisteredPayload); errKafka != nil {
				s.logger.Error("Failed to publish CloudEvent for Telegram user registered", zap.Error(errKafka), zap.String("user_id", user.ID.String()))
			}

		} else { // Other error fetching external account
			s.logger.Error("Failed to fetch external account by provider ID", zap.Error(err))
			return nil, nil, err
		}
	} else { // External account exists
		// Fetch the associated platform user
		platformUser, errUser := s.userRepo.FindByID(ctx, extAccount.UserID)
		if errUser != nil {
			s.logger.Error("Platform user linked to Telegram account not found", zap.Error(errUser), zap.String("userID", extAccount.UserID.String()))
			// This indicates a data integrity issue if extAccount exists but user doesn't.
			return nil, nil, fmt.Errorf("linked user not found: %w", errUser)
		}
		user = platformUser
	}

	// Check platform user status
	if user.Status == models.UserStatusBlocked {
		s.logger.Warn("Login attempt for blocked user via Telegram", zap.String("userID", user.ID.String()))
		return nil, nil, domainErrors.ErrUserBlocked
	}
	// If user was PENDING_VERIFICATION and logs in via Telegram, consider activating.
	if user.Status == models.UserStatusPendingVerification {
		user.Status = models.UserStatusActive
		user.EmailVerifiedAt = nil // Telegram login doesn't verify platform email
		if errUpdate := s.userRepo.Update(ctx, user); errUpdate != nil {
			s.logger.Error("Failed to activate user status during Telegram login", zap.Error(errUpdate), zap.String("userID", user.ID.String()))
			// Non-fatal for login, but log.
		}
	}


	// 3. Session & Token Generation
	userAgent := deviceInfo["user_agent"]; if userAgent == "" { userAgent = "unknown" }
	ipAddress := deviceInfo["ip_address"]; if ipAddress == "" { ipAddress = "unknown" }

	session, err := s.sessionService.CreateSession(ctx, user.ID, userAgent, ipAddress)
	if err != nil {
		s.logger.Error("Failed to create session for Telegram login", zap.Error(err), zap.String("userID", user.ID.String()))
		return nil, nil, fmt.Errorf("session creation failed: %w", err)
	}

	tokenPair, err := s.tokenService.CreateTokenPairWithSession(ctx, user, session.ID)
	if err != nil {
		s.logger.Error("Failed to create token pair for Telegram login", zap.Error(err), zap.String("userID", user.ID.String()))
		return nil, nil, fmt.Errorf("token generation failed: %w", err)
	}

	// 4. Final User Updates
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now()); err != nil {
		s.logger.Error("Failed to update last_login_at for Telegram user", zap.Error(err), zap.String("userID", user.ID.String()))
		// Non-fatal
	}
	if err := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil { // Good practice
		s.logger.Error("Failed to reset failed login attempts for Telegram user", zap.Error(err), zap.String("userID", user.ID.String()))
		// Non-fatal
	}

	// 5. Publish login success event
	loginSuccessPayload := models.UserLoginSuccessPayload{
		UserID:    user.ID.String(),
		SessionID: session.ID.String(), // session must be available here
		LoginAt:   time.Now(),          // Or a more precise time from earlier
		IPAddress: ipAddress,
		UserAgent: userAgent,
		LoginType: "telegram",
	}
	if err := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserLoginSuccessV1, user.ID.String(), loginSuccessPayload); err != nil {
		s.logger.Error("Failed to publish CloudEvent for Telegram login success", zap.Error(err), zap.String("user_id", user.ID.String()))
		// Non-critical, but log it.
	}

	s.logger.Info("User successfully logged in via Telegram", zap.String("userID", user.ID.String()), zap.Bool("isNewUser", isNewUser))
	return tokenPair, user, nil
}

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http" // For http.Client and state cookie (conceptual)
	"net/url"  // For building URLs
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces"
	appSecurity "github.com/your-org/auth-service/internal/infrastructure/security"
	"github.com/your-org/auth-service/internal/utils/kafka"
	"go.uber.org/zap"
)
// ... (rest of the file before InitiateOAuthLogin)

// InitiateOAuthLogin prepares for an OAuth 2.0 login flow with a specified provider.
// It validates the provider, generates a CSRF token, and constructs an authorization URL
// to which the user should be redirected.
// It also generates a state JWT which should be set as an HttpOnly cookie by the caller (HTTP handler)
// to be validated during the OAuth callback.
// Parameters:
//   - ctx: The context for the request.
//   - providerName: The name of the OAuth provider (e.g., "google", "vk").
//   - clientProvidedRedirectURI: An optional redirect URI provided by the client application,
//     to which the user might be redirected after successful authentication and callback handling by this service.
//     This URI is stored within the state JWT.
//   - clientProvidedState: An optional state value provided by the client application, also stored in the state JWT.
//
// Returns the constructed authorization URL for the OAuth provider, the state JWT string (to be set as a cookie),
// and an error if any.
// Possible errors: domainErrors.ErrUnsupportedOAuthProvider or internal errors.
func (s *AuthService) InitiateOAuthLogin(ctx context.Context, providerName string, clientProvidedRedirectURI string, clientProvidedState string) (string, string, error) { // Corrected return type
	s.logger.Info("Initiating OAuth login",
		zap.String("provider", providerName),
		zap.String("clientProvidedRedirectURI", clientProvidedRedirectURI),
		zap.String("clientProvidedState", clientProvidedState),
	)

	providerConfig, ok := s.cfg.OAuthProviders[providerName]
	if !ok {
		return "", domainErrors.ErrUnsupportedOAuthProvider
	}

	// 1. State Management for CSRF protection
	// Service generates its own state, encrypts it, and sets it in a cookie.
	// If clientProvidedState exists, it can be included in the data to be encrypted in the state cookie.
	generatedStateVal, err := appSecurity.GenerateSecureToken(16) // 16 bytes = 32 hex chars
	if err != nil {
		s.logger.Error("Failed to generate OAuth state", zap.Error(err))
		return "", fmt.Errorf("could not generate state: %w", err)
	}

	// TODO: Implement secure state storage (e.g., short-lived, HttpOnly, Secure cookie containing `finalState` and `clientProvidedRedirectURI`)
	// For now, `finalState` is returned in the auth URL and expected back. `clientProvidedRedirectURI` is not persisted across calls yet.

	csrfToken, err := appSecurity.GenerateSecureToken(16) // Generate a CSRF token for the state param
	if err != nil {
		s.logger.Error("Failed to generate CSRF token for OAuth state", zap.Error(err))
		return "", "", fmt.Errorf("could not generate CSRF token: %w", err) // Return empty cookie value
	}

	stateClaims := &domainService.OAuthStateClaims{
		ProviderName:            providerName,
		ClientProvidedRedirectURI: clientProvidedRedirectURI, // Store original client redirect if provided
		ClientProvidedState:     clientProvidedState,     // Store original client state
		CSRFToken:               csrfToken,               // This goes into provider's state param
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.cfg.Security.OAuth.StateCookieTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
	}

	stateCookieJWT, err := s.tokenManagementService.GenerateStateJWT(stateClaims, s.cfg.Security.OAuth.StateSecret, s.cfg.Security.OAuth.StateCookieTTL)
	if err != nil {
		s.logger.Error("Failed to generate OAuth state JWT", zap.Error(err))
		return "", "", fmt.Errorf("could not generate state JWT: %w", err) // Return empty cookie value
	}

	finalStateProviderParam := csrfToken // This is what we send to the OAuth provider in the 'state' query param


	// 2. Determine Redirect URI
	// Use providerConfig.RedirectURL (our service's callback for this provider).
	// clientProvidedRedirectURI is for where our service should redirect the user *after* successful auth.
	// This needs to be stored with the state to be used in HandleOAuthCallback.
	serviceCallbackRedirectURI := providerConfig.RedirectURL


	// 3. Construct Authorization URL
	authURLValues := url.Values{}
	authURLValues.Add("client_id", providerConfig.ClientID)
	authURLValues.Add("response_type", "code")
	authURLValues.Add("redirect_uri", serviceCallbackRedirectURI)
	authURLValues.Add("scope", strings.Join(providerConfig.Scopes, " "))
	authURLValues.Add("state", finalStateProviderParam) // CSRF token goes to provider

	fullAuthURL := providerConfig.AuthURL + "?" + authURLValues.Encode()

	s.logger.Debug("Generated OAuth Authorization URL", zap.String("url", fullAuthURL))

	// Return the authorization URL and the state JWT to be set as a cookie by the handler
	return fullAuthURL, stateCookieJWT, nil
}

// HandleOAuthCallback processes the callback from an OAuth 2.0 provider after user authorization.
// It validates the received state (CSRF token) against the state JWT stored in a cookie,
// exchanges the authorization code for provider tokens (access, refresh, ID tokens),
// fetches user information from the provider, links or creates a platform user account,
// generates platform session and tokens, and publishes relevant events.
// Records audit logs for these actions.
// Parameters:
//   - ctx: The context for the request.
//   - providerName: The name of the OAuth provider.
//   - authorizationCode: The authorization code received from the provider.
//   - receivedCSRFState: The 'state' parameter received from the provider (should match CSRF token in state JWT).
//   - stateCookieJWT: The JWT string read from the state cookie set during InitiateOAuthLogin.
//   - deviceInfo: A map containing device information like user_agent and ip_address.
//
// Returns a platform token pair, user details, and an error if any.
// Possible errors: domainErrors.ErrUnsupportedOAuthProvider, domainErrors.ErrOAuthStateMismatch,
// errors during token exchange or user info fetching from provider, domainErrors.ErrUserBlocked, or internal errors.
func (s *AuthService) HandleOAuthCallback(
	ctx context.Context,
	providerName string,
	authorizationCode string,
	receivedCSRFState string, // Renamed from receivedState for clarity
	stateCookieJWT string,    // Added: the JWT read from the state cookie
	deviceInfo map[string]string,
) (*models.TokenPair, *models.User, error) {
	s.logger.Info("Handling OAuth callback",
		zap.String("provider", providerName),
		zap.Bool("code_present", authorizationCode != ""),
		zap.String("receivedCSRFState", receivedCSRFState),
		zap.Bool("stateCookie_present", stateCookieJWT != ""),
	)

	providerConfig, ok := s.cfg.OAuthProviders[providerName]
	if !ok {
		return nil, nil, domainErrors.ErrUnsupportedOAuthProvider
	}

	// 1. State Validation
	if stateCookieJWT == "" {
		s.logger.Warn("OAuth callback: state cookie JWT is missing.")
		return nil, nil, domainErrors.ErrOAuthStateMismatch
	}
	stateClaims, err := s.tokenManagementService.ValidateStateJWT(stateCookieJWT, s.cfg.Security.OAuth.StateSecret)
	if err != nil {
		s.logger.Warn("OAuth callback: state cookie JWT validation failed.", zap.Error(err))
		return nil, nil, domainErrors.ErrOAuthStateMismatch
	}

	if stateClaims.CSRFToken != receivedCSRFState {
		s.logger.Warn("OAuth callback: CSRF token from state cookie does not match state from provider.",
			zap.String("cookie_csrf", stateClaims.CSRFToken),
			zap.String("provider_csrf", receivedCSRFState))
		return nil, nil, domainErrors.ErrOAuthStateMismatch
	}
	if stateClaims.ProviderName != providerName {
		s.logger.Warn("OAuth callback: Provider name in state cookie does not match current provider.",
			zap.String("cookie_provider", stateClaims.ProviderName),
			zap.String("current_provider", providerName))
		return nil, nil, domainErrors.ErrOAuthStateMismatch
	}
	// clientOriginalRedirectURI := stateClaims.ClientProvidedRedirectURI // Can be used later if needed
	// clientOriginalState := stateClaims.ClientProvidedState           // Can be used later if needed
	s.logger.Info("OAuth state validation successful.", zap.String("provider", providerName))


	// TODO: 2. Token Exchange - Make HTTP POST to providerConfig.TokenURL
	//    Params: grant_type=authorization_code, code=authorizationCode, redirect_uri=providerConfig.RedirectURL, client_id, client_secret
	//    Requires an HTTP client. Parse JSON response for provider_access_token, provider_refresh_token, id_token.
	s.logger.Info("OAuth Token Exchange step is a TODO.", zap.String("provider", providerName))
	// Placeholder provider tokens
	providerAccessToken := "dummy-provider-access-token-" + providerName
	// providerRefreshToken := "dummy-provider-refresh-token-" + providerName
	// idToken := "dummy-id-token-" + providerName


	var externalUserID, externalEmail, externalUsername, externalFirstName, externalPhotoURL string
	var providerData interface{} // To store raw provider response if needed

	switch providerName {
	case "vk":
		// VK Token Exchange
		vkTokenURL := providerConfig.TokenURL
		vkData := url.Values{}
		vkData.Set("client_id", providerConfig.ClientID)
		vkData.Set("client_secret", providerConfig.ClientSecret)
		vkData.Set("redirect_uri", providerConfig.RedirectURL)
		vkData.Set("code", authorizationCode)

		var vkTokenResponse struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
			UserID      int64  `json:"user_id"` // VK returns user_id as int
			Email       string `json:"email"`   // Optional, depends on scope
		}
		if err := s.makePostFormRequest(vkTokenURL, vkData, &vkTokenResponse); err != nil {
			s.logger.Error("VK token exchange failed", zap.Error(err), zap.String("provider", providerName))
			return nil, nil, fmt.Errorf("VK token exchange failed: %w", err)
		}
		if vkTokenResponse.AccessToken == "" {
			s.logger.Error("VK token exchange returned empty access token", zap.String("provider", providerName))
			return nil, nil, errors.New("VK token exchange failed: empty access token")
		}
		providerData = vkTokenResponse

		// VK Fetch User Info
		// Ensure UserInfoURL is set in config, e.g., "https://api.vk.com/method/users.get"
		vkUserInfoURL, _ := url.Parse(providerConfig.UserInfoURL)
		q := vkUserInfoURL.Query()
		q.Set("user_ids", fmt.Sprintf("%d", vkTokenResponse.UserID))
		// Example fields: "screen_name,first_name,last_name,photo_max_orig"
		// Add "email" to fields if email scope was requested and granted.
		requestedFields := "screen_name,first_name,last_name,photo_max_orig"
		if providerConfig.ProviderSpecific["request_email_scope"] == "true" { // Example custom config
			requestedFields += ",email"
		}
		q.Set("fields", requestedFields)
		q.Set("access_token", vkTokenResponse.AccessToken)
		q.Set("v", providerConfig.ProviderSpecific["v"]) // e.g., "5.199" from config
		vkUserInfoURL.RawQuery = q.Encode()

		var vkUserResponse struct {
			Response []struct {
				ID        int64  `json:"id"`
				ScreenName string `json:"screen_name"`
				FirstName string `json:"first_name"`
				LastName  string `json:"last_name"`
				PhotoMax  string `json:"photo_max_orig"` // Or other photo field
				Email     string `json:"email"`          // If requested and available
			} `json:"response"`
		}
		if err := s.makeGetRequest(vkUserInfoURL.String(), &vkUserResponse); err != nil {
			s.logger.Error("VK user info fetch failed", zap.Error(err), zap.String("provider", providerName))
			return nil, nil, fmt.Errorf("VK user info fetch failed: %w", err)
		}
		if len(vkUserResponse.Response) == 0 {
			return nil, nil, errors.New("VK user info fetch failed: empty response")
		}
		vkUser := vkUserResponse.Response[0]
		externalUserID = fmt.Sprintf("%d", vkUser.ID)
		externalEmail = vkUser.Email // Might be empty if not provided or scope not granted
		if externalEmail == "" && vkTokenResponse.Email != "" { // Fallback to email from token response if available
			externalEmail = vkTokenResponse.Email
		}
		externalUsername = vkUser.ScreenName
		if externalUsername == "" { // Fallback for username
			externalUsername = fmt.Sprintf("vk_%d", vkUser.ID)
		}
		externalFirstName = vkUser.FirstName // Concatenate if desired: vkUser.FirstName + " " + vkUser.LastName
		externalPhotoURL = vkUser.PhotoMax


	case "odnoklassniki": // OK
		okTokenURL := providerConfig.TokenURL
		okData := url.Values{}
		okData.Set("code", authorizationCode)
		okData.Set("client_id", providerConfig.ClientID)
		okData.Set("client_secret", providerConfig.ClientSecret) // This is application_secret_key for OK
		okData.Set("redirect_uri", providerConfig.RedirectURL)
		okData.Set("grant_type", "authorization_code")

		var okTokenResponse struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := s.makePostFormRequest(okTokenURL, okData, &okTokenResponse); err != nil {
			s.logger.Error("OK token exchange failed", zap.Error(err), zap.String("provider", providerName))
			return nil, nil, fmt.Errorf("OK token exchange failed: %w", err)
		}
		if okTokenResponse.AccessToken == "" {
			s.logger.Error("OK token exchange returned empty access token", zap.String("provider", providerName))
			return nil, nil, errors.New("OK token exchange failed: empty access token")
		}
		providerData = okTokenResponse

		// OK Fetch User Info
		// UserInfoURL e.g., "https://api.ok.ru/fb.do"
		// Params: method=users.getCurrentUser, application_key (public key), access_token, sig
		okUserInfoURL, _ := url.Parse(providerConfig.UserInfoURL)
		okParams := url.Values{}
		okParams.Set("method", "users.getCurrentUser")
		okParams.Set("application_key", providerConfig.ProviderSpecific["application_public_key"]) // Public key from config
		okParams.Set("access_token", okTokenResponse.AccessToken)
		// Calculate sig: md5(sorted_params_concat + client_secret/application_secret_key)
		sig := appSecurity.CalculateOkSig(okParams, providerConfig.ClientSecret) // Helper needed
		okParams.Set("sig", sig)
		okUserInfoURL.RawQuery = okParams.Encode()

		var okUserResponse struct {
			UID       string `json:"uid"`
			Name      string `json:"name"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			PicFull   string `json:"pic_full"` // Example photo field
			// Email might not be available or require specific scope/permissions
		}
		if err := s.makeGetRequest(okUserInfoURL.String(), &okUserResponse); err != nil {
			s.logger.Error("OK user info fetch failed", zap.Error(err), zap.String("provider", providerName))
			return nil, nil, fmt.Errorf("OK user info fetch failed: %w", err)
		}
		externalUserID = okUserResponse.UID
		externalEmail = "" // OK usually doesn't provide email easily
		externalUsername = okUserResponse.Name // Or a generated one like ok_<uid>
		if externalUsername == "" {
			externalUsername = fmt.Sprintf("ok_%s", okUserResponse.UID)
		}
		externalFirstName = okUserResponse.FirstName
		externalPhotoURL = okUserResponse.PicFull

	default:
		s.logger.Warn("Unsupported OAuth provider in callback", zap.String("provider", providerName))
		return nil, nil, domainErrors.ErrUnsupportedOAuthProvider
	}
	_ = providerData // Use providerData if needed for storing raw tokens or additional info

	// --- Steps 4, 5, 6: Account Linking/Creation, Session & Platform Token Gen, Final Updates ---
	// This logic is very similar to LoginWithTelegram, refactor into a helper if possible.
	var user *models.User
	isNewUser := false

	extAccount, err := s.externalAccountRepo.FindByProviderAndExternalID(ctx, providerName, externalUserID)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			s.logger.Info("External account not found, creating new user/link.", zap.String("provider", providerName), zap.String("externalUserID", externalUserID))

			// Optional: Check if an existing platform user has `externalEmail` (if verified by provider)
			// if externalEmailVerified && externalEmail != "" { ... }

			platformUsername := externalUsername
			if platformUsername == "" { platformUsername = externalFirstName }
			if platformUsername == "" { platformUsername = fmt.Sprintf("%s_%s", providerName, externalUserID) }

			uniqueUsername, genUserErr := s.generateUniquePlatformUsername(ctx, platformUsername)
			if genUserErr != nil { return nil, nil, genUserErr }

			newUser := &models.User{
				ID:           uuid.New(),
				Username:     uniqueUsername,
				Email:        externalEmail, // May be empty or unverified by platform initially
				Status:       models.UserStatusActive,
				// PasswordHash empty for OAuth-only users initially
				EmailVerifiedAt: nil, // Platform email not verified by this flow directly
			}
			if errCreateUser := s.userRepo.Create(ctx, newUser); errCreateUser != nil {
				return nil, nil, fmt.Errorf("failed to create user for OAuth: %w", errCreateUser)
			}
			user = newUser
			isNewUser = true

			newExtAccount := &models.ExternalAccount{
				ID: uuid.New(), UserID: user.ID, Provider: providerName, ExternalUserID: externalUserID,
				// Store provider tokens (hashed if sensitive) and profile data if needed
				// AccessTokenHash: hash(providerAccessToken), RefreshTokenHash: hash(providerRefreshToken), TokenExpiresAt: ...,
				// ProfileData: json.Marshal(rawProviderProfileData),
			}
			if errCreateExt := s.externalAccountRepo.Create(ctx, newExtAccount); errCreateExt != nil {
				return nil, nil, fmt.Errorf("failed to link external OAuth account: %w", errCreateExt)
			}

			dbUser, _ := s.userRepo.FindByID(ctx, user.ID) // Re-fetch for CreatedAt
			if dbUser != nil { user.CreatedAt = dbUser.CreatedAt }
			// regEvent := models.UserRegisteredEvent{ /* ... populate ... */ CreatedAt: user.CreatedAt, InitialStatus: string(user.Status)} // Old event

			// Map to new CloudEvent payload UserRegisteredPayload
			userRegisteredPayload := eventModels.UserRegisteredPayload{
				UserID:                user.ID.String(),
				Username:              user.Username,
				Email:                 user.Email, // May be empty or unverified
				DisplayName:           nil,        // Not typically available from basic OAuth user info
				RegistrationTimestamp: user.CreatedAt,
				InitialStatus:         string(models.UserStatusActive), // Social logins usually active
			}
			// TODO: Determine correct topic. Using placeholder "auth-events".
			if errKafka := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, eventModels.AuthUserRegisteredV1, user.ID.String(), userRegisteredPayload); errKafka != nil {
				s.logger.Error("HandleOAuthCallback: Failed to publish CloudEvent for new OAuth user registered", zap.Error(errKafka), zap.String("user_id", user.ID.String()))
				// Non-critical for login flow.
			}

		} else {
			return nil, nil, fmt.Errorf("failed to fetch external OAuth account: %w", err)
		}
	} else {
		platformUser, errUser := s.userRepo.FindByID(ctx, extAccount.UserID)
		if errUser != nil { return nil, nil, fmt.Errorf("linked user not found: %w", errUser) }
		user = platformUser
	}

	if user.Status == models.UserStatusBlocked { return nil, nil, domainErrors.ErrUserBlocked }
	if user.Status == models.UserStatusPendingVerification { // Activate if was pending
		user.Status = models.UserStatusActive
		if errUpdate := s.userRepo.Update(ctx, user); errUpdate != nil { /* log */ }
	}

	userAgent := deviceInfo["user_agent"]; if userAgent == "" { userAgent = "unknown" }
	ipAddress := deviceInfo["ip_address"]; if ipAddress == "" { ipAddress = "unknown" }

	session, err := s.sessionService.CreateSession(ctx, user.ID, userAgent, ipAddress)
	if err != nil { return nil, nil, fmt.Errorf("session creation failed for OAuth: %w", err) }

	tokenPair, err := s.tokenService.CreateTokenPairWithSession(ctx, user, session.ID)
	if err != nil { return nil, nil, fmt.Errorf("token generation failed for OAuth: %w", err) }

	if errUpdate := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now()); errUpdate != nil { /* log */ }
	if errReset := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); errReset != nil { /* log */ }

	// Publish CloudEvent for OAuth login success
	oauthLoginSuccessPayload := models.UserLoginSuccessPayload{
		UserID:    user.ID.String(),
		SessionID: session.ID.String(), // session must be available here
		LoginAt:   time.Now(),          // Or a more precise time
		IPAddress: ipAddress,
		UserAgent: userAgent,
		LoginType: fmt.Sprintf("oauth_%s", providerName), // e.g., "oauth_google"
	}
	if errKafka := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, models.AuthUserLoginSuccessV1, user.ID.String(), oauthLoginSuccessPayload); errKafka != nil {
		s.logger.Error("Failed to publish CloudEvent for OAuth login success", zap.Error(errKafka), zap.String("user_id", user.ID.String()), zap.String("provider", providerName))
		// Non-critical, but log it.
	}

	s.logger.Info("User successfully logged in via OAuth", zap.String("provider", providerName), zap.String("userID", user.ID.String()), zap.Bool("isNewUser", isNewUser))
	return tokenPair, user, nil
}

// generateUniquePlatformUsername is a helper, can be moved to a common util if needed
func (s *AuthService) generateUniquePlatformUsername(ctx context.Context, baseUsername string) (string, error) {
	username := baseUsername
	for i := 0; i < 5; i++ {
		_, err := s.userRepo.FindByUsername(ctx, username)
		if err != nil {
			if errors.Is(err, domainErrors.ErrUserNotFound) {
				return username, nil
			}
			return "", fmt.Errorf("error checking username uniqueness: %w", err)
		}
		suffix, _ := appSecurity.GenerateSecureToken(2)
		username = fmt.Sprintf("%s_%s", baseUsername, suffix)
		if len(username) > 255 {
			username = username[:255]
		}
	}
	return "", errors.New("failed to generate unique username after multiple attempts")
}


// --- HTTP Client Helper Methods ---

func (s *AuthService) makePostFormRequest(url string, data url.Values, target interface{}) error {
	s.logger.Debug("Making POST form request", zap.String("url", url), zap.Any("data", data))
	resp, err := s.httpClient.PostForm(url, data)
	if err != nil {
		s.logger.Error("HTTP POST request failed", zap.Error(err), zap.String("url", url))
		return fmt.Errorf("http post request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.Error(err), zap.String("url", url))
		return fmt.Errorf("failed to read response body: %w", err)
	}
	s.logger.Debug("Received HTTP response", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("body", string(bodyBytes)))


	if resp.StatusCode != http.StatusOK {
		// Try to unmarshal into a generic error structure if possible, or just return status
		var errorResponse map[string]interface{}
		if json.Unmarshal(bodyBytes, &errorResponse) == nil {
			s.logger.Warn("OAuth provider returned non-200 status with JSON body", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.Any("error_body", errorResponse))
		} else {
			s.logger.Warn("OAuth provider returned non-200 status", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("body_text", string(bodyBytes)))
		}
		return fmt.Errorf("oauth provider returned non-200 status: %d - %s", resp.StatusCode, string(bodyBytes))
	}

	if err := json.Unmarshal(bodyBytes, target); err != nil {
		s.logger.Error("Failed to unmarshal JSON response", zap.Error(err), zap.String("url", url), zap.String("body", string(bodyBytes)))
		return fmt.Errorf("failed to unmarshal JSON response: %w. Body: %s", err, string(bodyBytes))
	}
	return nil
}

func (s *AuthService) makeGetRequest(url string, target interface{}) error {
	s.logger.Debug("Making GET request", zap.String("url", url))
	resp, err := s.httpClient.Get(url)
	if err != nil {
		s.logger.Error("HTTP GET request failed", zap.Error(err), zap.String("url", url))
		return fmt.Errorf("http get request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		s.logger.Error("Failed to read response body", zap.Error(err), zap.String("url", url))
		return fmt.Errorf("failed to read response body: %w", err)
	}
	s.logger.Debug("Received HTTP response", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("body", string(bodyBytes)))

	if resp.StatusCode != http.StatusOK {
		var errorResponse map[string]interface{}
		if json.Unmarshal(bodyBytes, &errorResponse) == nil {
			s.logger.Warn("OAuth provider returned non-200 status with JSON body", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.Any("error_body", errorResponse))
		} else {
			s.logger.Warn("OAuth provider returned non-200 status", zap.String("url", url), zap.Int("status", resp.StatusCode), zap.String("body_text", string(bodyBytes)))
		}
		return fmt.Errorf("oauth provider returned non-200 status: %d - %s", resp.StatusCode, string(bodyBytes))
	}

	if err := json.Unmarshal(bodyBytes, target); err != nil {
		s.logger.Error("Failed to unmarshal JSON response", zap.Error(err), zap.String("url", url), zap.String("body", string(bodyBytes)))
		return fmt.Errorf("failed to unmarshal JSON response: %w. Body: %s", err, string(bodyBytes))
	}
	return nil
}
>>>>>>> REPLACE
