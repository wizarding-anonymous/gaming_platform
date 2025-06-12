// File: backend/services/auth-service/tests/internal/service/token_service_validate_test.go
package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	domainInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/interfaces"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
)

type MockRedisClient struct{ mock.Mock }

func (m *MockRedisClient) IsBlacklisted(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockRedisClient) AddToBlacklist(ctx context.Context, token string, ttl time.Duration) error {
	return m.Called(ctx, token, ttl).Error(0)
}

type MockTokenMgmt struct{ mock.Mock }

func (m *MockTokenMgmt) GenerateAccessToken(userID string, username string, roles []string, permissions []string, sessionID string) (string, *domainInterfaces.Claims, error) {
	args := m.Called(userID, username, roles, permissions, sessionID)
	if args.Get(1) != nil {
		return args.String(0), args.Get(1).(*domainInterfaces.Claims), args.Error(2)
	}
	return args.String(0), nil, args.Error(2)
}

func (m *MockTokenMgmt) ValidateAccessToken(tokenString string) (*domainInterfaces.Claims, error) {
	args := m.Called(tokenString)
	if args.Get(0) != nil {
		return args.Get(0).(*domainInterfaces.Claims), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockTokenMgmt) GenerateRefreshTokenValue() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}
func (m *MockTokenMgmt) GetRefreshTokenExpiry() time.Duration {
	args := m.Called()
	return args.Get(0).(time.Duration)
}
func (m *MockTokenMgmt) GetJWKS() (map[string]interface{}, error) {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).(map[string]interface{}), args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockTokenMgmt) Generate2FAChallengeToken(userID string) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}
func (m *MockTokenMgmt) Validate2FAChallengeToken(tokenString string) (string, error) {
	args := m.Called(tokenString)
	return args.String(0), args.Error(1)
}
func (m *MockTokenMgmt) GenerateStateJWT(claims *domainInterfaces.OAuthStateClaims, secret string, ttl time.Duration) (string, error) {
	args := m.Called(claims, secret, ttl)
	return args.String(0), args.Error(1)
}
func (m *MockTokenMgmt) ValidateStateJWT(tokenString string, secret string) (*domainInterfaces.OAuthStateClaims, error) {
	args := m.Called(tokenString, secret)
	if args.Get(0) != nil {
		return args.Get(0).(*domainInterfaces.OAuthStateClaims), args.Error(1)
	}
	return nil, args.Error(1)
}

func TestValidateAccessToken_Blacklisted(t *testing.T) {
	ctx := context.Background()
	redisMock := new(MockRedisClient)
	redisMock.On("IsBlacklisted", ctx, "token").Return(true, nil)

	svc := &service.TokenService{redisClient: redisMock}
	_, err := svc.ValidateAccessToken(ctx, "token")
	assert.ErrorIs(t, err, domainErrors.ErrRevokedToken)
	redisMock.AssertExpectations(t)
}

func TestRevokeToken_AddsToBlacklist(t *testing.T) {
	ctx := context.Background()
	redisMock := new(MockRedisClient)
	tokenMgmt := new(MockTokenMgmt)
	claims := &domainInterfaces.Claims{RegisteredClaims: domainInterfaces.Claims{}.RegisteredClaims}
	claims.ExpiresAt = &domainInterfaces.Claims{}.RegisteredClaims.ExpiresAt
	claims.ExpiresAt.Time = time.Now().Add(time.Hour)
	tokenMgmt.On("ValidateAccessToken", "token").Return(claims, nil)
	redisMock.On("AddToBlacklist", ctx, "token", mock.AnythingOfType("time.Duration")).Return(nil)

	svc := &service.TokenService{redisClient: redisMock, tokenMgmtService: tokenMgmt}
	err := svc.RevokeToken(ctx, "token")
	assert.NoError(t, err)
	redisMock.AssertExpectations(t)
	tokenMgmt.AssertExpectations(t)
}
