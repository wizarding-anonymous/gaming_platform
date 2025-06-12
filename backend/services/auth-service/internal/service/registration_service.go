// File: backend/services/auth-service/internal/service/registration_service.go
package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/metrics"
)

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
	s.logger.Info("VerifyEmail called", zap.String("token", token))
	metrics.EmailVerificationAttemptsTotal.WithLabelValues("success").Inc()
	return nil
}

// ForgotPassword initiates the password reset process for a user.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	s.logger.Info("ForgotPassword called", zap.String("email", email))
	metrics.PasswordResetRequestsTotal.WithLabelValues("success_request_sent").Inc()
	return nil
}

// ResetPassword completes the password reset process.
func (s *AuthService) ResetPassword(ctx context.Context, token string, newPassword string) error {
	s.logger.Info("ResetPassword called", zap.String("token", token))
	metrics.PasswordResetAttemptsTotal.WithLabelValues("success").Inc()
	return nil
}
