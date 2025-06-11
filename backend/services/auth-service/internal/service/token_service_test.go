// File: backend/services/auth-service/internal/service/token_service_test.go
package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

type MockRefreshTokenRepository struct{ mock.Mock }

func (m *MockRefreshTokenRepository) Create(ctx context.Context, token *models.RefreshToken) error {
	return m.Called(ctx, token).Error(0)
}
func (m *MockRefreshTokenRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.RefreshToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RefreshToken), args.Error(1)
}
func (m *MockRefreshTokenRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RefreshToken), args.Error(1)
}
func (m *MockRefreshTokenRepository) FindBySessionID(ctx context.Context, id uuid.UUID) (*models.RefreshToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RefreshToken), args.Error(1)
}
func (m *MockRefreshTokenRepository) Revoke(ctx context.Context, id uuid.UUID, reason *string) error {
	return m.Called(ctx, id, reason).Error(0)
}
func (m *MockRefreshTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}
func (m *MockRefreshTokenRepository) DeleteBySessionID(ctx context.Context, id uuid.UUID) error {
	return m.Called(ctx, id).Error(0)
}
func (m *MockRefreshTokenRepository) DeleteByUserID(ctx context.Context, id uuid.UUID) (int64, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockRefreshTokenRepository) DeleteExpiredAndRevoked(ctx context.Context, d time.Duration) (int64, error) {
	args := m.Called(ctx, d)
	return args.Get(0).(int64), args.Error(1)
}

// User repo mock
type MockUserRepository struct{ mock.Mock }

func (m *MockUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

// Session repo mock
type MockSessionRepository struct{ mock.Mock }

func (m *MockSessionRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

func TestTokenService_RefreshTokens_InactiveSession(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	sessionID := uuid.New()
	hashed := "hash"

	rt := &models.RefreshToken{ID: uuid.New(), SessionID: sessionID, UserID: userID, TokenHash: hashed, ExpiresAt: time.Now().Add(time.Hour)}
	user := &models.User{ID: userID, Username: "u", Status: models.UserStatusActive}
	expiredSession := &models.Session{ID: sessionID, UserID: userID, ExpiresAt: time.Now().Add(-time.Hour)}

	refreshRepo := new(MockRefreshTokenRepository)
	refreshRepo.On("FindByTokenHash", ctx, hashed).Return(rt, nil)
	refreshRepo.On("Revoke", ctx, rt.ID, mock.AnythingOfType("*string")).Return(nil)
	userRepo := new(MockUserRepository)
	userRepo.On("FindByID", ctx, userID).Return(user, nil)
	sessionRepo := new(MockSessionRepository)
	sessionRepo.On("FindByID", ctx, sessionID).Return(expiredSession, nil)

	svc := &TokenService{refreshTokenRepo: refreshRepo, userRepo: userRepo, sessionRepo: sessionRepo, logger: zap.NewNop(), tokenMgmtService: nil, redisClient: nil}

	_, err := svc.RefreshTokens(ctx, "plain")
	assert.ErrorIs(t, err, domainErrors.ErrSessionNotFound)
	refreshRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	sessionRepo.AssertExpectations(t)
}
