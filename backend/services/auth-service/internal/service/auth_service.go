// File: internal/service/auth_service.go
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

// AuthService предоставляет методы для аутентификации и авторизации
type AuthService struct {
	userRepo               repoInterfaces.UserRepository
	verificationCodeRepo   repoInterfaces.VerificationCodeRepository
	tokenService           *TokenService // This is the refactored one
	sessionService         *SessionService
	kafkaClient            *kafka.Client
	logger                 *zap.Logger
	passwordService        domainService.PasswordService
	tokenManagementService domainService.TokenManagementService
	mfaSecretRepo          repoInterfaces.MFASecretRepository
	mfaLogicService        domainService.MFALogicService
	cfg                    *config.Config
}

// NewAuthService создает новый экземпляр AuthService
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
) *AuthService {
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
		cfg:                    cfg,
	}
}

// Register регистрирует нового пользователя
// Returns the created user, the plain verification token, and an error.
func (s *AuthService) Register(ctx context.Context, req models.CreateUserRequest) (*models.User, string, error) {
	_, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err == nil {
		return nil, "", domainErrors.ErrEmailExists
	}
	if !errors.Is(err, domainErrors.ErrUserNotFound) {
		s.logger.Error("Error checking email existence for registration", zap.Error(err))
		return nil, "", err
	}

	_, err = s.userRepo.FindByUsername(ctx, req.Username)
	if err == nil {
		return nil, "", domainErrors.ErrUsernameExists
	}
	if !errors.Is(err, domainErrors.ErrUserNotFound) {
		s.logger.Error("Error checking username existence for registration", zap.Error(err))
		return nil, "", err
	}

	hashedPassword, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("Failed to hash password during registration", zap.Error(err))
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
		return nil, "", err
	}

	createdUser, err := s.userRepo.FindByID(ctx, user.ID)
	if err != nil {
	    s.logger.Error("Failed to fetch newly created user", zap.Error(err), zap.String("userID", user.ID.String()))
	    return nil, "", fmt.Errorf("failed to fetch newly created user: %w", err)
	}

	plainVerificationToken, err := appSecurity.GenerateSecureToken(32)
	if err != nil {
		s.logger.Error("Failed to generate verification token", zap.Error(err))
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
		return nil, "", fmt.Errorf("could not store verification code: %w", err)
	}

	event := models.UserRegisteredEvent{
		UserID:        user.ID.String(),
		Email:         user.Email,
		Username:      user.Username,
		InitialStatus: string(user.Status),
		CreatedAt:     createdUser.CreatedAt,
	}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.registered", event); err != nil {
		s.logger.Error("Failed to publish user registered event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}
	return createdUser, plainVerificationToken, nil
}

// Login аутентифицирует пользователя
// Returns: access/refresh token pair, user details, 2FA challenge token (if required), error
func (s *AuthService) Login(ctx context.Context, req models.LoginRequest) (*models.TokenPair, *models.User, string, error) {
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			s.logger.Warn("Login attempt: User not found by email", zap.String("email", req.Email))
		} else {
			s.logger.Error("Login attempt: Error fetching user by email", zap.Error(err), zap.String("email", req.Email))
		}
		return nil, nil, "", domainErrors.ErrInvalidCredentials
	}

	if user.LockoutUntil != nil && time.Now().Before(*user.LockoutUntil) {
		s.logger.Warn("Login attempt for locked out user", zap.String("user_id", user.ID.String()), zap.Time("lockout_until", *user.LockoutUntil))
		return nil, nil, "", domainErrors.ErrUserLockedOut
	}

	passwordMatch, err := s.passwordService.CheckPasswordHash(req.Password, user.PasswordHash)
	if err != nil {
		s.logger.Error("Error checking password hash", zap.Error(err), zap.String("user_id", user.ID.String()))
		return nil, nil, "", domainErrors.ErrInternal
	}

	if !passwordMatch {
		s.logger.Warn("Invalid password attempt", zap.String("user_id", user.ID.String()))
		if errInc := s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID); errInc != nil {
			s.logger.Error("Failed to increment failed login attempts", zap.Error(errInc), zap.String("user_id", user.ID.String()))
		}
		updatedUser, fetchErr := s.userRepo.FindByID(ctx, user.ID)
		if fetchErr != nil {
			s.logger.Error("Failed to fetch user after failed attempt", zap.Error(fetchErr), zap.String("user_id", user.ID.String()))
			return nil, nil, "", domainErrors.ErrInvalidCredentials
		}
		if updatedUser.FailedLoginAttempts >= s.cfg.Security.Lockout.MaxFailedAttempts {
			lockoutUntil := time.Now().Add(s.cfg.Security.Lockout.LockoutDuration)
			if errLock := s.userRepo.UpdateLockout(ctx, updatedUser.ID, &lockoutUntil); errLock != nil {
				s.logger.Error("Failed to update lockout status for user", zap.Error(errLock), zap.String("user_id", updatedUser.ID.String()))
			}
			s.logger.Warn("User account locked", zap.String("user_id", updatedUser.ID.String()))
			return nil, nil, "", domainErrors.ErrUserLockedOut
		}
		return nil, nil, "", domainErrors.ErrInvalidCredentials
	}

	if user.Status == models.UserStatusBlocked {
		s.logger.Warn("Login attempt for blocked user", zap.String("user_id", user.ID.String()))
		return nil, nil, "", domainErrors.ErrUserBlocked
	}

	if user.EmailVerifiedAt == nil {
		s.logger.Warn("Login attempt for unverified email", zap.String("user_id", user.ID.String()))
		return nil, nil, "", domainErrors.ErrEmailNotVerified
	}

	// --- MFA Check START ---
	mfaSecret, errMFA := s.mfaSecretRepo.FindByUserIDAndType(ctx, user.ID, models.MFATypeTOTP)
	if errMFA == nil && mfaSecret != nil && mfaSecret.Verified {
		s.logger.Info("2FA required for user", zap.String("user_id", user.ID.String()))
		challengeToken, errChallenge := s.tokenManagementService.Generate2FAChallengeToken(user.ID.String())
		if errChallenge != nil {
			s.logger.Error("Failed to generate 2FA challenge token", zap.Error(errChallenge), zap.String("user_id", user.ID.String()))
			return nil, nil, "", domainErrors.ErrInternal
		}
		return nil, user, challengeToken, domainErrors.Err2FARequired
	}
	if errMFA != nil && !errors.Is(errMFA, domainErrors.ErrNotFound) {
		s.logger.Error("Error checking MFA status for user", zap.Error(errMFA), zap.String("user_id", user.ID.String()))
	}
	// --- MFA Check END ---

	if err := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
		s.logger.Error("Failed to reset failed login attempts", zap.Error(err), zap.String("user_id", user.ID.String()))
	}
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now()); err != nil {
		s.logger.Error("Failed to update last login time", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	userAgent := "unknown"
	ipAddress := "unknown"
	if md, ok := ctx.Value("metadata").(map[string]string); ok {
		if ua, exists := md["user-agent"]; exists { userAgent = ua }
		if ip, exists := md["ip-address"]; exists { ipAddress = ip }
	}

	session, err := s.sessionService.CreateSession(ctx, user.ID, userAgent, ipAddress)
	if err != nil {
		s.logger.Error("Failed to create session during login", zap.Error(err), zap.String("user_id", user.ID.String()))
		return nil, nil, "", err
	}

	tokenPair, err := s.tokenService.CreateTokenPairWithSession(ctx, user, session.ID)
	if err != nil {
		s.logger.Error("Failed to create token pair", zap.Error(err), zap.String("user_id", user.ID.String()))
		return nil, nil, "", err // Propagate error
	}

	event := models.UserLoginEvent{
		UserID: user.ID.String(), Email: user.Email, IPAddress: ipAddress, UserAgent: userAgent, LoginAt: time.Now(),
	}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.login", event); err != nil {
		s.logger.Error("Failed to publish user login event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}
	return tokenPair, user, "", nil
}

// CompleteLoginAfter2FA finalizes login after successful 2FA.
func (s *AuthService) CompleteLoginAfter2FA(ctx context.Context, userID uuid.UUID, deviceInfo map[string]string) (*models.TokenPair, *models.User, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("CompleteLoginAfter2FA: User not found", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, nil, domainErrors.ErrUserNotFound
	}

	if user.Status == models.UserStatusBlocked {
		s.logger.Warn("CompleteLoginAfter2FA: Attempt for blocked user", zap.String("user_id", user.ID.String()))
		return nil, nil, domainErrors.ErrUserBlocked
	}
	if user.EmailVerifiedAt == nil { // Should have been verified before 2FA setup
		s.logger.Warn("CompleteLoginAfter2FA: Attempt for unverified email", zap.String("user_id", user.ID.String()))
		return nil, nil, domainErrors.ErrEmailNotVerified
	}

	if err := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to reset failed login attempts", zap.Error(err), zap.String("user_id", user.ID.String()))
	}
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now()); err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to update last login time", zap.Error(err), zap.String("user_id", user.ID.String()))
	}

	userAgent := deviceInfo["user_agent"]; if userAgent == "" { userAgent = "unknown" }
	ipAddress := deviceInfo["ip_address"]; if ipAddress == "" { ipAddress = "unknown" }

	session, err := s.sessionService.CreateSession(ctx, user.ID, userAgent, ipAddress)
	if err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to create session", zap.Error(err), zap.String("user_id", user.ID.String()))
		return nil, nil, err
	}

	tokenPair, err := s.tokenService.CreateTokenPairWithSession(ctx, user, session.ID)
	if err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to create token pair", zap.Error(err), zap.String("user_id", user.ID.String()))
		return nil, nil, err
	}

	event := models.UserLoginEvent{
		UserID: user.ID.String(), Email: user.Email, IPAddress: ipAddress, UserAgent: userAgent, LoginAt: time.Now(),
	}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.login", event); err != nil {
		s.logger.Error("CompleteLoginAfter2FA: Failed to publish user login event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}
	return tokenPair, user, nil
}


// RefreshToken processes refresh token to issue new token pair.
func (s *AuthService) RefreshToken(ctx context.Context, plainOpaqueRefreshToken string) (*models.TokenPair, error) {
	newTokenPair, err := s.tokenService.RefreshTokens(ctx, plainOpaqueRefreshToken)
	if err != nil {
		s.logger.Error("Failed to refresh tokens", zap.Error(err))
		return nil, err
	}
	return newTokenPair, nil
}

// Logout performs user logout.
func (s *AuthService) Logout(ctx context.Context, accessToken, refreshToken string) error {
	claims, err := s.tokenManagementService.ValidateAccessToken(accessToken)
	if err != nil {
		s.logger.Warn("Logout: Failed to validate access token, proceeding with refresh token revocation", zap.Error(err))
		// If AT invalid, still try to revoke RT if provided
		if refreshToken == "" {
			return domainErrors.ErrInvalidToken // Cannot proceed if no RT
		}
	}

	// Revoke refresh token from DB
	if err := s.tokenService.RevokeRefreshToken(ctx, refreshToken); err != nil {
		s.logger.Error("Logout: Failed to revoke refresh token from DB", zap.Error(err))
		// Log and continue to attempt session deletion if possible from AT
	}

	// Delete session from DB
	if claims != nil && claims.SessionID != "" {
		sessionID, parseErr := uuid.Parse(claims.SessionID)
		if parseErr == nil {
			if err := s.sessionService.DeactivateSession(ctx, sessionID); err != nil { // DeactivateSession now deletes
				s.logger.Error("Logout: Failed to delete session", zap.Error(err), zap.String("session_id", claims.SessionID))
			}
		} else {
			s.logger.Error("Logout: Failed to parse sessionID from access token claims", zap.Error(parseErr))
		}
	} else if refreshToken == "" {
		// If no claims (AT invalid) and no RT, cannot identify session to delete.
		s.logger.Warn("Logout: No session identifier available to delete session.")
	}


	// Blacklist access token (even if it was initially invalid, to be safe)
	if accessToken != "" {
		if err := s.tokenService.RevokeToken(ctx, accessToken); err != nil {
			s.logger.Error("Logout: Failed to blacklist access token", zap.Error(err))
		}
	}

	if claims != nil {
		event := models.UserLogoutEvent{
			UserID:    claims.UserID,
			SessionID: claims.SessionID,
			LogoutAt:  time.Now(),
		}
		if err := s.kafkaClient.PublishUserEvent(ctx, "user.logout", event); err != nil {
			s.logger.Error("Logout: Failed to publish user logout event", zap.Error(err), zap.String("user_id", claims.UserID))
		}
	}
	return nil
}

// LogoutAll performs logout from all user sessions.
func (s *AuthService) LogoutAll(ctx context.Context, accessToken string) error {
	claims, err := s.tokenManagementService.ValidateAccessToken(accessToken)
	if err != nil {
		s.logger.Error("LogoutAll: Failed to validate access token", zap.Error(err))
		return domainErrors.ErrInvalidToken
	}
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		s.logger.Error("LogoutAll: Failed to parse UserID from token", zap.Error(err), zap.String("userID", claims.UserID))
		return domainErrors.ErrInternal
	}

	if _, err := s.sessionService.DeleteAllUserSessions(ctx, userID, nil); err != nil {
		s.logger.Error("LogoutAll: Failed to delete user sessions", zap.Error(err), zap.String("user_id", claims.UserID))
	}
	if _, err := s.tokenService.RevokeAllRefreshTokensForUser(ctx, userID); err != nil {
		s.logger.Error("LogoutAll: Failed to revoke all refresh tokens for user", zap.Error(err), zap.String("user_id", claims.UserID))
	}

	event := models.UserLogoutAllEvent{UserID: claims.UserID, LogoutAt: time.Now()}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.logout_all", event); err != nil {
		s.logger.Error("LogoutAll: Failed to publish event", zap.Error(err), zap.String("user_id", claims.UserID))
	}
	return nil
}

// VerifyEmail confirms user's email.
func (s *AuthService) VerifyEmail(ctx context.Context, plainVerificationTokenValue string) error {
	hashedToken := appSecurity.HashToken(plainVerificationTokenValue)
	verificationCode, err := s.verificationCodeRepo.FindByCodeHashAndType(ctx, hashedToken, models.VerificationCodeTypeEmailVerification)
	if err != nil {
		if errors.Is(err, domainErrors.ErrNotFound) {
			s.logger.Warn("Attempt to verify email with invalid/expired token", zap.String("hashed_token", hashedToken))
			return domainErrors.ErrInvalidToken
		}
		s.logger.Error("Failed to find verification code for email verification", zap.Error(err))
		return err
	}

	userID := verificationCode.UserID
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("User not found for valid verification token", zap.Error(err), zap.String("user_id", userID.String()))
		return domainErrors.ErrUserNotFound
	}

	if user.EmailVerifiedAt != nil {
		s.logger.Info("Email already verified for user", zap.String("user_id", userID.String()))
		_ = s.verificationCodeRepo.MarkAsUsed(ctx, verificationCode.ID, time.Now()) // Attempt to mark used
		return domainErrors.ErrEmailAlreadyVerified
	}

	now := time.Now()
	if err := s.userRepo.SetEmailVerifiedAt(ctx, user.ID, now); err != nil {
		s.logger.Error("Failed to set email_verified_at for user", zap.Error(err), zap.String("user_id", user.ID.String()))
		return err
	}
	if err := s.userRepo.UpdateStatus(ctx, user.ID, models.UserStatusActive); err != nil {
		s.logger.Error("Failed to update user status to active", zap.Error(err), zap.String("user_id", user.ID.String()))
		return err
	}
	if err := s.verificationCodeRepo.MarkAsUsed(ctx, verificationCode.ID, now); err != nil {
		s.logger.Error("Failed to mark email verification token as used", zap.Error(err), zap.String("token_id", verificationCode.ID.String()))
	}

	event := models.EmailVerifiedEvent{UserID: user.ID.String(), Email: user.Email, VerifiedAt: now}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.email_verified", event); err != nil {
		s.logger.Error("Failed to publish email_verified event", zap.Error(err), zap.String("user_id", user.ID.String()))
	}
	return nil
}

// ResendVerificationEmail resends email verification.
func (s *AuthService) ResendVerificationEmail(ctx context.Context, email string) error {
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

	event := models.VerificationEmailResentEvent{UserID: user.ID.String(), Email: user.Email, Token: plainToken, SentAt: time.Now()}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.verification_email_resent", event); err != nil { /* ... log ... */ }
	return nil
}

// ForgotPassword initiates password reset.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			s.logger.Info("Password reset for non-existent email (silent)", zap.String("email", email))
			return nil // Prevent enumeration
		}
		s.logger.Error("Error fetching user for password reset", zap.Error(err), zap.String("email", email))
		return err
	}
	_, _ = s.verificationCodeRepo.DeleteByUserIDAndType(ctx, user.ID, models.VerificationCodeTypePasswordReset)
	plainToken, err := appSecurity.GenerateSecureToken(32)
	if err != nil { /* ... log ... */ return err }
	hashedToken := appSecurity.HashToken(plainToken)
	verificationCode := &models.VerificationCode{
		ID: uuid.New(), UserID: user.ID, Type: models.VerificationCodeTypePasswordReset,
		CodeHash: hashedToken, ExpiresAt: time.Now().Add(s.cfg.JWT.PasswordResetToken.ExpiresIn),
	}
	if err := s.verificationCodeRepo.Create(ctx, verificationCode); err != nil { /* ... log ... */ return err }

	event := models.PasswordResetRequestedEvent{UserID: user.ID.String(), Email: user.Email, Token: plainToken, RequestedAt: time.Now()}
	if err := s.kafkaClient.PublishUserEvent(ctx, "user.password_reset_requested", event); err != nil { /* ... log ... */ }
	return nil
}

// ResetPassword completes password reset.
func (s *AuthService) ResetPassword(ctx context.Context, plainToken, newPassword string) error {
	hashedToken := appSecurity.HashToken(plainToken)
	verificationCode, err := s.verificationCodeRepo.FindByCodeHashAndType(ctx, hashedToken, models.VerificationCodeTypePasswordReset)
	if err != nil { return domainErrors.ErrInvalidToken }

	userID := verificationCode.UserID
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil { return domainErrors.ErrUserNotFound }

	newHashedPassword, err := s.passwordService.HashPassword(newPassword)
	if err != nil { return err }
	if err := s.userRepo.UpdatePassword(ctx, user.ID, newHashedPassword); err != nil { return err }
	_ = s.verificationCodeRepo.MarkAsUsed(ctx, verificationCode.ID, time.Now())
	_, _ = s.sessionService.DeleteAllUserSessions(ctx, userID, nil)

	event := models.PasswordResetEvent{UserID: user.ID.String(), Email: user.Email, ResetAt: time.Now()}
	_ = s.kafkaClient.PublishUserEvent(ctx, "user.password_reset", event)
	return nil
}

// ChangePassword allows authenticated user to change password.
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPlainPassword, newPlainPassword string) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil { return domainErrors.ErrUserNotFound }

	match, err := s.passwordService.CheckPasswordHash(oldPlainPassword, user.PasswordHash)
	if err != nil { return domainErrors.ErrInternal }
	if !match { return domainErrors.ErrInvalidCredentials }

	newHashedPassword, err := s.passwordService.HashPassword(newPlainPassword)
	if err != nil { return err }
	if err := s.userRepo.UpdatePassword(ctx, userID, newHashedPassword); err != nil { return err }

	// Invalidate other sessions (example: delete all, could exclude current session if ID is passed)
	_, _ = s.sessionService.DeleteAllUserSessions(ctx, userID, nil)

	event := models.PasswordChangedEvent{UserID: userID.String(), ChangedAt: time.Now()}
	_ = s.kafkaClient.PublishUserEvent(ctx, "user.password_changed", event)
	return nil
}

// CheckUserPermission checks if a user has a specific permission.
// This is a placeholder implementation. A real one would involve fetching user's roles,
// then permissions for those roles, and checking against the requested permission and resource.
func (s *AuthService) CheckUserPermission(ctx context.Context, userID uuid.UUID, permissionKey string, resourceID *string) (bool, error) {
	s.logger.Info("CheckUserPermission called (placeholder)",
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
	if userID == uuid.Nil { // Example: disallow if userID is nil
		return false, domainErrors.ErrInvalidRequest
	}
	return true, nil // Placeholder
}
>>>>>>> REPLACE
