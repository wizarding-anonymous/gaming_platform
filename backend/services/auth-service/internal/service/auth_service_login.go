// File: backend/services/auth-service/internal/service/auth_service_login.go
package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	kafkaEvents "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/metrics"
)

// Login method with new event publishing (ensure it's only present once)
func (s *AuthService) Login(ctx context.Context, req models.LoginRequest) (*models.TokenPair, *models.User, string, error) {
	var auditErrorDetails map[string]interface{}
	var userIDForAudit *uuid.UUID
	var user *models.User
	var err error

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

	// Determine if identifier is likely an email to prioritize search, or simply try both.
	// For simplicity here, try email first, then username.
	// A common approach is to check for "@" in the identifier.
	isLikelyEmail := strings.Contains(req.Identifier, "@")

	if isLikelyEmail {
		user, err = s.userRepo.FindByEmail(ctx, req.Identifier)
	} else {
		user, err = s.userRepo.FindByUsername(ctx, req.Identifier)
	}

	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			// If first attempt failed, try the other method
			if isLikelyEmail {
				user, err = s.userRepo.FindByUsername(ctx, req.Identifier)
			} else {
				user, err = s.userRepo.FindByEmail(ctx, req.Identifier)
			}
		}
		// If still not found or other error
		if err != nil {
			if errors.Is(err, domainErrors.ErrUserNotFound) {
				s.logger.Warn("Login attempt: User not found by identifier", zap.String("identifier", req.Identifier))
				loginFailedPayload := models.UserLoginFailedPayload{
					AttemptedLoginIdentifier: req.Identifier,
					FailureReason:            "user_not_found",
					FailureTimestamp:         time.Now().UTC(),
					IPAddress:                ipAddress,
					UserAgent:                userAgent,
				}
				subjectUserNotFound := "unknown_user_" + req.Identifier
				contentType := "application/json"
				if errPub := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, kafkaEvents.EventType(models.AuthUserLoginFailedV1), &subjectUserNotFound, &contentType, loginFailedPayload); errPub != nil {
					s.logger.Error("Failed to publish CloudEvent for user_not_found login failure", zap.Error(errPub))
				}
				auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrInvalidCredentials.Error(), "attempted_identifier": req.Identifier}
				s.auditLogRecorder.RecordEvent(ctx, nil, "user_login", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
			} else {
				s.logger.Error("Login attempt: Error fetching user by identifier", zap.Error(err), zap.String("identifier", req.Identifier))
				auditErrorDetails = map[string]interface{}{"reason": "db error fetching user", "error": err.Error(), "attempted_identifier": req.Identifier}
				s.auditLogRecorder.RecordEvent(ctx, nil, "user_login", models.AuditLogStatusFailure, nil, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
			}
			metrics.LoginAttemptsTotal.WithLabelValues("failure_user_not_found").Inc()
			return nil, nil, "", domainErrors.ErrInvalidCredentials
		}
	}

	// From here, 'user' object is available. The rest of the logic remains similar.
	userIDForAudit = &user.ID

	// Rate limit check (using identifier instead of email)
	rateLimitKey := "login_identifier_ip:" + req.Identifier + ":" + ipAddress
	allowed, rlErr := s.rateLimiter.Allow(ctx, rateLimitKey, s.cfg.Security.RateLimiting.LoginEmailIP) // Assuming LoginEmailIP config is general enough
	if rlErr != nil {
		s.logger.Error("Rate limiter failed for login_identifier_ip", zap.Error(rlErr), zap.String("identifier", req.Identifier), zap.String("ipAddress", ipAddress))
	}
	if !allowed {
		s.logger.Warn("Rate limit exceeded for login_identifier_ip", zap.String("identifier", req.Identifier), zap.String("ipAddress", ipAddress))
		// Consider if an event should be published here for rate limiting.
		// metrics.LoginAttemptsTotal.WithLabelValues("failure_rate_limit").Inc(); // Optional: if you want a specific metric for rate limit
		return nil, nil, "", domainErrors.ErrRateLimitExceeded
	}

	if user.LockoutUntil != nil && time.Now().Before(*user.LockoutUntil) {
		s.logger.Warn("Login attempt for locked out user", zap.String("user_id", user.ID.String()), zap.Time("lockout_until", *user.LockoutUntil))
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrUserLockedOut.Error(), "attempted_identifier": req.Identifier}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		metrics.LoginAttemptsTotal.WithLabelValues("failure_account_locked").Inc()
		return nil, nil, "", domainErrors.ErrUserLockedOut
	}

	passwordMatch, err := s.passwordService.CheckPasswordHash(req.Password, user.PasswordHash)
	if err != nil {
		s.logger.Error("Error checking password hash", zap.Error(err), zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"reason": "password check error", "error": err.Error(), "attempted_identifier": req.Identifier}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		return nil, nil, "", domainErrors.ErrInternal
	}

	if !passwordMatch {
		s.logger.Warn("Invalid password attempt", zap.String("user_id", user.ID.String()))
		if errInc := s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID); errInc != nil {
			s.logger.Error("Failed to increment failed login attempts", zap.Error(errInc), zap.String("user_id", user.ID.String()))
		}
		// Fetch user again to get updated FailedLoginAttempts
		updatedUser, fetchErr := s.userRepo.FindByID(ctx, user.ID)
		if fetchErr != nil {
			s.logger.Error("Failed to fetch user after failed attempt", zap.Error(fetchErr), zap.String("user_id", user.ID.String()))
			loginFailedPayload := models.UserLoginFailedPayload{
				AttemptedLoginIdentifier: req.Identifier,
				FailureReason:            "invalid_credentials",
				FailureTimestamp:         time.Now().UTC(),
				IPAddress:                ipAddress,
				UserAgent:                userAgent,
			}
			subjectInvalidCreds := user.ID.String()
			contentType := "application/json"
			if errPub := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, kafkaEvents.EventType(models.AuthUserLoginFailedV1), &subjectInvalidCreds, &contentType, loginFailedPayload); errPub != nil {
				s.logger.Error("Failed to publish CloudEvent for invalid_credentials (user fetch failed)", zap.Error(errPub))
			}
			auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrInvalidCredentials.Error(), "attempted_identifier": req.Identifier}
			s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
			return nil, nil, "", domainErrors.ErrInvalidCredentials
		}
		user = updatedUser // Use the updated user object

		loginFailedPayload := models.UserLoginFailedPayload{
			AttemptedLoginIdentifier: req.Identifier,
			FailureReason:            "invalid_credentials",
			FailureTimestamp:         time.Now().UTC(),
			IPAddress:                ipAddress,
			UserAgent:                userAgent,
		}
		subjectFailedLogin := user.ID.String()
		contentType := "application/json"
		if errPub := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, kafkaEvents.EventType(models.AuthUserLoginFailedV1), &subjectFailedLogin, &contentType, loginFailedPayload); errPub != nil {
			s.logger.Error("Failed to publish CloudEvent for invalid_credentials login failure", zap.Error(errPub))
		}

		if user.FailedLoginAttempts >= s.cfg.Security.Lockout.MaxFailedAttempts {
			lockoutUntil := time.Now().Add(s.cfg.Security.Lockout.LockoutDuration)
			if errLock := s.userRepo.UpdateLockout(ctx, user.ID, &lockoutUntil); errLock != nil {
				s.logger.Error("Failed to update lockout status for user", zap.Error(errLock), zap.String("user_id", user.ID.String()))
			} else {
				var durationSecs *int64
				dur := lockoutUntil.Sub(time.Now().UTC())
				if dur.Seconds() > 0 {
					val := int64(dur.Seconds())
					durationSecs = &val
				}
				accountLockedPayload := models.UserAccountLockedPayload{
					UserID:                 user.ID.String(),
					LockTimestamp:          time.Now().UTC(),
					Reason:                 "too_many_failed_login_attempts",
					LockoutDurationSeconds: durationSecs,
				}
				subjectAccountLocked := user.ID.String()
				if errPub := s.kafkaClient.PublishCloudEvent(ctx, s.cfg.Kafka.Producer.Topic, kafkaEvents.EventType(models.AuthUserAccountLockedV1), &subjectAccountLocked, &contentType, accountLockedPayload); errPub != nil {
					s.logger.Error("Failed to publish CloudEvent for account locked", zap.Error(errPub))
				}
			}
			s.logger.Warn("User account locked", zap.String("user_id", user.ID.String()))
			auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrUserLockedOut.Error(), "attempted_identifier": req.Identifier, "lockout_triggered": true, "failed_attempts": user.FailedLoginAttempts}
			s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
			metrics.LoginAttemptsTotal.WithLabelValues("failure_account_locked").Inc() // Duplicated for this path
			return nil, nil, "", domainErrors.ErrUserLockedOut
		}
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrInvalidCredentials.Error(), "attempted_identifier": req.Identifier, "failed_attempts": user.FailedLoginAttempts}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		metrics.LoginAttemptsTotal.WithLabelValues("failure_credentials").Inc()
		return nil, nil, "", domainErrors.ErrInvalidCredentials
	}

	if user.Status == models.UserStatusBlocked {
		s.logger.Warn("Login attempt for blocked user", zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.ErrUserBlocked.Error(), "attempted_identifier": req.Identifier}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		metrics.LoginAttemptsTotal.WithLabelValues("failure_account_blocked").Inc()
		return nil, nil, "", domainErrors.ErrUserBlocked
	}

	mfaSecret, errMFA := s.mfaSecretRepo.FindByUserIDAndType(ctx, user.ID, models.MFATypeTOTP)
	if errMFA == nil && mfaSecret != nil && mfaSecret.Verified {
		s.logger.Info("2FA required for user", zap.String("user_id", user.ID.String()))
		challengeToken, errChallenge := s.tokenManagementService.Generate2FAChallengeToken(user.ID.String())
		if errChallenge != nil {
			s.logger.Error("Failed to generate 2FA challenge token", zap.Error(errChallenge), zap.String("user_id", user.ID.String()))
			auditErrorDetails = map[string]interface{}{"reason": "2FA challenge token generation failed", "error": errChallenge.Error(), "attempted_identifier": req.Identifier}
			s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
			return nil, nil, "", domainErrors.ErrInternal
		}
		auditErrorDetails = map[string]interface{}{"reason": domainErrors.Err2FARequired.Error(), "attempted_identifier": req.Identifier}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
		metrics.LoginAttemptsTotal.WithLabelValues("success_2fa_required").Inc()
		return nil, user, challengeToken, domainErrors.Err2FARequired
	}
	if errMFA != nil && !errors.Is(errMFA, domainErrors.ErrNotFound) {
		s.logger.Error("Error checking MFA status for user", zap.Error(errMFA), zap.String("user_id", user.ID.String()))
	}

	if err := s.userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
		s.logger.Error("Failed to reset failed login attempts", zap.Error(err), zap.String("user_id", user.ID.String()))
		auditErrorDetails = map[string]interface{}{"warning": "failed to reset failed login attempts", "error": err.Error()}
	}
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now()); err != nil {
		s.logger.Error("Failed to update last login time", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditErrorDetails == nil {
			auditErrorDetails = make(map[string]interface{})
		}
		auditErrorDetails["warning_update_last_login"] = err.Error()
	}

	session, errSession := s.sessionService.CreateSession(ctx, user.ID, userAgent, ipAddress)
	if errSession != nil {
		s.logger.Error("Failed to create session during login", zap.Error(errSession), zap.String("user_id", user.ID.String()))
		logDetails := map[string]interface{}{"reason": "session creation failed", "error": errSession.Error(), "attempted_identifier": req.Identifier}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
		return nil, nil, "", errSession
	}

	tokenPair, errToken := s.tokenService.CreateTokenPairWithSession(ctx, user, session.ID)
	if errToken != nil {
		s.logger.Error("Failed to create token pair", zap.Error(errToken), zap.String("user_id", user.ID.String()))
		logDetails := map[string]interface{}{"reason": "token pair creation failed", "error": errToken.Error(), "attempted_identifier": req.Identifier}
		s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusFailure, userIDForAudit, models.AuditTargetTypeUser, logDetails, ipAddress, userAgent)
		return nil, nil, "", errToken
	}

	loginSuccessPayload := models.UserLoginSuccessPayload{
		UserID:         user.ID.String(),
		SessionID:      session.ID.String(),
		LoginTimestamp: time.Now().UTC(),
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
	}
	subjectUserIDLogin := user.ID.String()
	contentTypeJSONLogin := "application/json"
	if err := s.kafkaClient.PublishCloudEvent(
		ctx,
		s.cfg.Kafka.Producer.Topic,
		kafkaEvents.EventType(models.AuthUserLoginSuccessV1),
		&subjectUserIDLogin,
		&contentTypeJSONLogin,
		loginSuccessPayload,
	); err != nil {
		s.logger.Error("Failed to publish CloudEvent for user login success", zap.Error(err), zap.String("user_id", user.ID.String()))
		if auditErrorDetails == nil {
			auditErrorDetails = make(map[string]interface{})
		}
		auditErrorDetails["warning_cloudevent_publish"] = err.Error()
	}

	s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, "user_login", models.AuditLogStatusSuccess, userIDForAudit, models.AuditTargetTypeUser, auditErrorDetails, ipAddress, userAgent)
	metrics.LoginAttemptsTotal.WithLabelValues("success").Inc()
	return tokenPair, user, "", nil
}

// Register handles new user registration, including CAPTCHA and HIBP checks.
func (s *AuthService) Register(ctx context.Context, req models.RegisterRequest) (*models.User, *models.TokenPair, error) {
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

	// CAPTCHA Check
	if s.cfg.Captcha.Enabled {
		if req.CaptchaToken == "" {
			s.auditLogRecorder.RecordEvent(ctx, nil, "user_register_captcha_check", models.AuditLogStatusFailure, nil, models.AuditTargetTypeSystem, map[string]interface{}{"reason": "captcha_token_missing", "username": req.Username, "email": req.Email}, ipAddress, userAgent)
			return nil, nil, domainErrors.ErrInvalidCaptcha
		}
		isValid, err := s.captchaService.Verify(ctx, req.CaptchaToken, ipAddress)
		if err != nil {
			s.logger.Error("Captcha verification service failed", zap.Error(err), zap.String("username", req.Username), zap.String("email", req.Email))
			s.auditLogRecorder.RecordEvent(ctx, nil, "user_register_captcha_check", models.AuditLogStatusFailure, nil, models.AuditTargetTypeSystem, map[string]interface{}{"reason": "captcha_service_error", "error": err.Error(), "username": req.Username, "email": req.Email}, ipAddress, userAgent)
			return nil, nil, domainErrors.ErrInternal
		}
		if !isValid {
			s.auditLogRecorder.RecordEvent(ctx, nil, "user_register_captcha_check", models.AuditLogStatusFailure, nil, models.AuditTargetTypeSystem, map[string]interface{}{"reason": "captcha_invalid", "username": req.Username, "email": req.Email}, ipAddress, userAgent)
			return nil, nil, domainErrors.ErrInvalidCaptcha
		}
	}

	// HIBP Check (after other validations, before hashing password)
	if s.cfg.HIBP.Enabled {
		pwned, count, err := s.hibpService.CheckPasswordPwned(ctx, req.Password)
		if err != nil {
			s.logger.Error("HIBP check service failed", zap.Error(err), zap.String("username", req.Username), zap.String("email", req.Email))
			s.auditLogRecorder.RecordEvent(ctx, nil, "user_register_hibp_check", models.AuditLogStatusFailure, nil, models.AuditTargetTypeSystem, map[string]interface{}{"reason": "hibp_service_error", "error": err.Error(), "username": req.Username, "email": req.Email}, ipAddress, userAgent)
		} else if pwned {
			s.logger.Warn("Password pwned attempt during registration", zap.String("username", req.Username), zap.String("email", req.Email), zap.Int("count", count))
			s.auditLogRecorder.RecordEvent(ctx, nil, "user_register_hibp_check", models.AuditLogStatusFailure, nil, models.AuditTargetTypeSystem, map[string]interface{}{"reason": "password_pwned", "count": count, "username": req.Username, "email": req.Email}, ipAddress, userAgent)
			if count > s.cfg.HIBP.PwnedThreshold {
				return nil, nil, domainErrors.ErrPasswordPwned
			}
		}
	}

	// --- Placeholder for core registration logic ---
	s.logger.Info("Placeholder: Core registration logic (hashing password, creating user, session, tokens) needs to be implemented here.",
		zap.String("username", req.Username),
		zap.String("email", req.Email),
	)

	dummyUser := &models.User{ID: uuid.New(), Username: req.Username, Email: req.Email, Status: models.UserStatusPendingVerification}
	dummyTokenPair := &models.TokenPair{AccessToken: "dummy_access_token", RefreshToken: "dummy_refresh_token"}

	var userIDForAudit *uuid.UUID
	if dummyUser != nil {
		uid := dummyUser.ID
		userIDForAudit = &uid
	}
	s.auditLogRecorder.RecordEvent(ctx, userIDForAudit, models.AuthUserRegisteredV1, models.AuditLogStatusSuccess, userIDForAudit, models.AuditTargetTypeUser, map[string]interface{}{"email": req.Email, "username": req.Username, "method": "direct"}, ipAddress, userAgent)
	metrics.RegistrationAttemptsTotal.WithLabelValues("success").Inc()

	return dummyUser, dummyTokenPair, nil
}

// VerifyEmail verifies a user's email address using a verification token.
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	// Placeholder for actual logic
	s.logger.Info("VerifyEmail called", zap.String("token", token))
	metrics.EmailVerificationAttemptsTotal.WithLabelValues("success").Inc()
	return nil
}

// ForgotPassword initiates the password reset process for a user.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	// Placeholder for actual logic
	s.logger.Info("ForgotPassword called", zap.String("email", email))
	metrics.PasswordResetRequestsTotal.WithLabelValues("success_request_sent").Inc()
	return nil
}

// ResetPassword completes the password reset process.
func (s *AuthService) ResetPassword(ctx context.Context, token string, newPassword string) error {
	// Placeholder for actual logic
	s.logger.Info("ResetPassword called", zap.String("token", token))
	metrics.PasswordResetAttemptsTotal.WithLabelValues("success").Inc()
	return nil
}
