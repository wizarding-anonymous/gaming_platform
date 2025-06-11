// File: backend/services/auth-service/tests/internal/service/auth_service_register_test.go
package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

func (s *AuthServiceTestSuite) TestRegister_RateLimitExceeded_IP() {
	ctx := context.Background()
	req := models.CreateUserRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "password123",
	}
	ipAddress := "192.168.1.100"
	userAgent := "test-agent-register"

	rateLimitRule := s.cfg.Security.RateLimiting.RegisterIP
	s.mockRateLimiter.On("Allow", ctx, "register_ip:"+ipAddress, rateLimitRule).Return(false, nil).Once()

	expectedDetails := map[string]interface{}{"error": domainErrors.ErrRateLimitExceeded.Error(), "ip_address": ipAddress}
	s.mockAuditRecorder.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusFailure, (*uuid.UUID)(nil), nil, expectedDetails, ipAddress, userAgent).Once()

	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": ipAddress, "user-agent": userAgent})
	_, _, err := s.authService.Register(metadataCtx, req)

	assert.ErrorIs(s.T(), err, domainErrors.ErrRateLimitExceeded)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
	s.mockUserRepo.AssertNotCalled(s.T(), "FindByEmail", mock.Anything, mock.Anything)
}

func (s *AuthServiceTestSuite) TestRegister_RateLimitExceeded_IP_Corrected() {
	ctx := context.Background()
	req := models.CreateUserRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "password123",
	}
	ipAddress := "192.168.1.100"
	userAgent := "test-agent-register"

	s.cfg.Security.RateLimiting.Rules = map[string]config.RateLimitRule{
		"register_ip": {Enabled: true, Limit: 5, Window: time.Minute * 10},
	}
	rateLimitRule := s.cfg.Security.RateLimiting.Rules["register_ip"]

	s.mockRateLimiter.On("Allow", ctx, "register_ip:"+ipAddress, rateLimitRule).Return(false, nil).Once()

	expectedDetails := map[string]interface{}{"error": domainErrors.ErrRateLimitExceeded.Error(), "ip_address": ipAddress}
	s.mockAuditRecorder.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusFailure, (*uuid.UUID)(nil), models.AuditTargetType(""), expectedDetails, ipAddress, userAgent).Once()

	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": ipAddress, "user-agent": userAgent})
	_, _, err := s.authService.Register(metadataCtx, req)

	assert.ErrorIs(s.T(), err, domainErrors.ErrRateLimitExceeded)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
	s.mockUserRepo.AssertNotCalled(s.T(), "FindByEmail", mock.Anything, mock.Anything)
}

func (s *AuthServiceTestSuite) TestRegister_RateLimitExceeded_IP_FinalCorrect() {
	ctx := context.Background()
	req := models.CreateUserRequest{
		Username: "newuser",
		Email:    "new@example.com",
		Password: "password123",
	}
	ipAddress := "192.168.1.100"
	userAgent := "test-agent-register"

	s.cfg.Security.RateLimiting.Rules = map[string]config.RateLimitRule{
		"register_ip": {Enabled: true, Limit: 5, Window: time.Minute * 10},
	}
	rateLimitRule := s.cfg.Security.RateLimiting.RegisterIP

	s.mockRateLimiter.On("Allow", ctx, "register_ip:"+ipAddress, rateLimitRule).Return(false, nil).Once()

	expectedDetails := map[string]interface{}{"error": domainErrors.ErrRateLimitExceeded.Error(), "ip_address": ipAddress}
	s.mockAuditRecorder.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusFailure, (*uuid.UUID)(nil), models.AuditTargetType(""), expectedDetails, ipAddress, userAgent).Once()

	metadataCtx := context.WithValue(ctx, "metadata", map[string]string{"ip-address": ipAddress, "user-agent": userAgent})
	_, _, err := s.authService.Register(metadataCtx, req)

	assert.ErrorIs(s.T(), err, domainErrors.ErrRateLimitExceeded)
	s.mockRateLimiter.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}
