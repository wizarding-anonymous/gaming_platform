// File: backend/services/auth-service/tests/internal/service/auth_service_login_test.go
package service

import (
	"context"
	"github.com/google/uuid"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	eventskafka "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
)

// --- Login Tests ---
func (s *AuthServiceTestSuite) TestLogin_Success() {
	ctx := context.Background()
	req := models.LoginRequest{Email: "test@example.com", Password: "password123"}
	ipAddress := "127.0.0.1"
	userAgent := "test-agent"

	user := &models.User{ID: uuid.New(), Email: req.Email, PasswordHash: "hashedpassword", Status: models.UserStatusActive, EmailVerifiedAt: &time.Time{}}
	session := &models.Session{ID: uuid.New(), UserID: user.ID}
	tokenPair := &models.TokenPair{AccessToken: "access", RefreshToken: "refresh"}

	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": ipAddress, "user-agent": userAgent})

	s.mockRateLimiter.On("Allow", metadataCtx, "login_email_ip:"+req.Email+":"+ipAddress, s.cfg.Security.RateLimiting.LoginEmailIP).Return(true, nil).Once()

	s.mockUserRepo.On("FindByEmail", metadataCtx, req.Email).Return(user, nil).Once()
	s.mockPasswordService.On("CheckPasswordHash", req.Password, user.PasswordHash).Return(true, nil).Once()
	s.mockMfaSecretRepo.On("FindByUserIDAndType", metadataCtx, user.ID, models.MFATypeTOTP).Return(nil, domainErrors.ErrNotFound).Once()
	s.mockUserRepo.On("ResetFailedLoginAttempts", metadataCtx, user.ID).Return(nil).Once()
	s.mockUserRepo.On("UpdateLastLogin", metadataCtx, user.ID, mock.AnythingOfType("time.Time")).Return(nil).Once()
	s.mockSessionService.On("CreateSession", metadataCtx, user.ID, userAgent, ipAddress).Return(session, nil).Once()
	s.mockTokenService.On("CreateTokenPairWithSession", metadataCtx, user, session.ID).Return(tokenPair, nil).Once()

	subjectUserIDStrLogin := user.ID.String()
	contentTypeJSONLogin := "application/json"
	s.mockKafkaProducer.On(
		"PublishCloudEvent",
		metadataCtx,
		s.cfg.Kafka.Producer.Topic,
		eventskafka.EventType(models.AuthUserLoginSuccessV1),
		&subjectUserIDStrLogin,
		&contentTypeJSONLogin,
		mock.AnythingOfType("models.UserLoginSuccessPayload"),
	).Return(nil).Once()
	s.mockAuditRecorder.On("RecordEvent", metadataCtx, &user.ID, "user_login", models.AuditLogStatusSuccess, &user.ID, models.AuditTargetTypeUser, mock.Anything, ipAddress, userAgent).Once()

	_, _, _, err := s.authService.Login(metadataCtx, req)

	assert.NoError(s.T(), err)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockUserRepo.AssertExpectations(s.T())
}

func (s *AuthServiceTestSuite) TestLogin_RateLimitExceeded() {
	ctx := context.Background()
	req := models.LoginRequest{Email: "test@example.com", Password: "password123"}
	ipAddress := "127.0.0.1"
	userAgent := "test-agent"

	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": ipAddress, "user-agent": userAgent})

	s.mockRateLimiter.On("Allow", metadataCtx, "login_email_ip:"+req.Email+":"+ipAddress, s.cfg.Security.RateLimiting.LoginEmailIP).Return(false, nil).Once()

	_, _, _, err := s.authService.Login(metadataCtx, req)

	assert.ErrorIs(s.T(), err, domainErrors.ErrRateLimitExceeded)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockUserRepo.AssertNotCalled(s.T(), "FindByEmail", mock.Anything, mock.Anything)
}
