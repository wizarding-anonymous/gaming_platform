// File: backend/services/auth-service/internal/service/login_service.go
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

// Login handles user login and publishes audit events.
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

	isLikelyEmail := strings.Contains(req.Identifier, "@")

	if isLikelyEmail {
		user, err = s.userRepo.FindByEmail(ctx, req.Identifier)
	} else {
		user, err = s.userRepo.FindByUsername(ctx, req.Identifier)
	}

	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			if isLikelyEmail {
				user, err = s.userRepo.FindByUsername(ctx, req.Identifier)
			} else {
				user, err = s.userRepo.FindByEmail(ctx, req.Identifier)
			}
		}
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

	if err == nil && user != nil {
		userIDForAudit = &user.ID
	}

	rateLimitKey := req.Identifier + ":" + ipAddress
	allowed, rlErr := s.rateLimiter.Allow(ctx, rateLimitKey, s.cfg.Security.RateLimiting.LoginEmailIP)
	if rlErr != nil {
		s.logger.Error("Rate limiter error", zap.Error(rlErr))
	}
	if !allowed {
		metrics.LoginAttemptsTotal.WithLabelValues("failure_rate_limit").Inc()
		return nil, nil, "", domainErrors.ErrTooManyRequests
	}

	if user == nil {
		metrics.LoginAttemptsTotal.WithLabelValues("failure_user_not_found").Inc()
		return nil, nil, "", domainErrors.ErrInvalidCredentials
	}

	if err := s.passwordService.ComparePassword(user.PasswordHash, req.Password); err != nil {
		_ = s.userRepo.IncrementFailedLoginAttempts(ctx, user.ID)
		metrics.LoginAttemptsTotal.WithLabelValues("failure_invalid_password").Inc()
		return nil, nil, "", domainErrors.ErrInvalidCredentials
	}

	_ = s.userRepo.ResetFailedLoginAttempts(ctx, user.ID)
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID, time.Now()); err != nil {
		s.logger.Error("Failed to update last login", zap.Error(err))
	}

	session, err := s.sessionService.CreateSession(ctx, user.ID, userAgent, ipAddress)
	if err != nil {
		s.logger.Error("Failed to create session", zap.Error(err))
		return nil, nil, "", err
	}

	tokenPair, err := s.tokenService.CreateTokenPairWithSession(ctx, user, session.ID)
	if err != nil {
		s.logger.Error("Failed to generate tokens", zap.Error(err))
		return nil, nil, "", err
	}

	loginSuccessPayload := models.UserLoginSuccessPayload{
		UserID:         user.ID.String(),
		LoginTimestamp: time.Now().UTC(),
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		LoginMethod:    "password",
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
