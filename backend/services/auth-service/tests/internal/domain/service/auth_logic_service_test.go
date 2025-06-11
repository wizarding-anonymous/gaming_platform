// File: backend/services/auth-service/tests/internal/domain/service/auth_logic_service_test.go
package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	kafkaPkg "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka"
)

// --- Mocks ---

type MockUserRepository struct {
	mock.Mock
	repository.UserRepository
}

func (m *MockUserRepository) FindByUsername(ctx context.Context, username string) (*entity.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}
func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}
func (m *MockUserRepository) Create(ctx context.Context, user *entity.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID, t time.Time) error {
	args := m.Called(ctx, userID, t)
	return args.Error(0)
}
func (m *MockUserRepository) ResetFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}
func (m *MockUserRepository) UpdateFailedLoginAttempts(ctx context.Context, userID uuid.UUID, attempts int, lockoutUntil *time.Time) error {
	args := m.Called(ctx, userID, attempts, lockoutUntil)
	return args.Error(0)
}

// Other methods of UserRepository come from the embedded interface and are unused.

type MockSessionRepository struct {
	mock.Mock
	repository.SessionRepository
}

func (m *MockSessionRepository) Create(ctx context.Context, s *entity.Session) error {
	args := m.Called(ctx, s)
	return args.Error(0)
}

// RefreshToken repo

type MockRefreshTokenRepository struct {
	mock.Mock
	repository.RefreshTokenRepository
}

func (m *MockRefreshTokenRepository) Create(ctx context.Context, rt *entity.RefreshToken) error {
	args := m.Called(ctx, rt)
	return args.Error(0)
}

// VerificationCode repo

type MockVerificationCodeRepository struct {
	mock.Mock
	repository.VerificationCodeRepository
}

func (m *MockVerificationCodeRepository) Create(ctx context.Context, vc *entity.VerificationCode) error {
	args := m.Called(ctx, vc)
	return args.Error(0)
}

// MFA secret repo

type MockMFASecretRepository struct {
	mock.Mock
	repository.MFASecretRepository
}

func (m *MockMFASecretRepository) FindByUserIDAndType(ctx context.Context, userID uuid.UUID, t entity.MFAType) (*entity.MFASecret, error) {
	args := m.Called(ctx, userID, t)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.MFASecret), args.Error(1)
}

// Password service

type MockPasswordService struct{ mock.Mock }

func (m *MockPasswordService) HashPassword(p string) (string, error) {
	args := m.Called(p)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordService) CheckPasswordHash(p, h string) (bool, error) {
	args := m.Called(p, h)
	return args.Bool(0), args.Error(1)
}

// Token service

type MockTokenService struct{ mock.Mock }

func (m *MockTokenService) GenerateAccessToken(userID string, username string, roles []string, perms []string, sessionID string) (string, *service.Claims, error) {
	args := m.Called(userID, username, roles, perms, sessionID)
	if args.Get(1) == nil {
		return args.String(0), nil, args.Error(2)
	}
	return args.String(0), args.Get(1).(*service.Claims), args.Error(2)
}
func (m *MockTokenService) GenerateRefreshTokenValue() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}
func (m *MockTokenService) ValidateAccessToken(token string) (*service.Claims, error) {
	return nil, nil
}
func (m *MockTokenService) GetRefreshTokenExpiry() time.Duration     { return time.Hour }
func (m *MockTokenService) GetJWKS() (map[string]interface{}, error) { return nil, nil }

// Notification service

type MockNotificationService struct{ mock.Mock }

func (m *MockNotificationService) SendEmailVerificationNotification(ctx context.Context, userID uuid.UUID, code string) error {
	args := m.Called(ctx, userID, code)
	return args.Error(0)
}

// Kafka producer

type MockKafkaProducer struct{ mock.Mock }

func (m *MockKafkaProducer) PublishCloudEvent(ctx context.Context, topic string, eventType kafkaPkg.EventType, subject *string, dataContentType *string, payload interface{}) error {
	args := m.Called(ctx, topic, eventType, subject, dataContentType, payload)
	return args.Error(0)
}
func (m *MockKafkaProducer) Close() error { return nil }

// --- Test helpers ---

type authLogicTestDeps struct {
	userRepo             *MockUserRepository
	sessionRepo          *MockSessionRepository
	refreshTokenRepo     *MockRefreshTokenRepository
	verificationCodeRepo *MockVerificationCodeRepository
	mfaSecretRepo        *MockMFASecretRepository
	passwordService      *MockPasswordService
	tokenService         *MockTokenService
	notificationService  *MockNotificationService
	kafkaProducer        *MockKafkaProducer
}

func setupAuthLogicService(t *testing.T, lockout ...config.LockoutConfig) (service.AuthLogicService, *authLogicTestDeps) {
	deps := &authLogicTestDeps{
		userRepo:             new(MockUserRepository),
		sessionRepo:          new(MockSessionRepository),
		refreshTokenRepo:     new(MockRefreshTokenRepository),
		verificationCodeRepo: new(MockVerificationCodeRepository),
		mfaSecretRepo:        new(MockMFASecretRepository),
		passwordService:      new(MockPasswordService),
		tokenService:         new(MockTokenService),
		notificationService:  new(MockNotificationService),
		kafkaProducer:        new(MockKafkaProducer),
	}

	appCfg := &service.SimplifiedConfigForAuthLogic{}
	if len(lockout) > 0 {
		appCfg.Lockout = lockout[0]
	}

	cfg := service.AuthLogicServiceConfig{
		UserRepo:             deps.userRepo,
		SessionRepo:          deps.sessionRepo,
		RefreshTokenRepo:     deps.refreshTokenRepo,
		VerificationCodeRepo: deps.verificationCodeRepo,
		MFASecretRepo:        deps.mfaSecretRepo,
		ExternalAccountRepo:  nil,
		PasswordService:      deps.passwordService,
		TokenService:         deps.tokenService,
		NotificationService:  deps.notificationService,
		KafkaProducer:        deps.kafkaProducer,
		TelegramVerifier:     nil,
		RBACService:          nil,
		AppConfig:            appCfg,
	}

	return service.NewAuthLogicService(cfg), deps
}

// --- Tests ---

func TestRegisterUser_SendsVerificationEmail(t *testing.T) {
	svc, d := setupAuthLogicService(t)
	ctx := context.Background()

	d.userRepo.On("FindByUsername", ctx, "testuser").Return(nil, errors.New("user not found")).Once()
	d.userRepo.On("FindByEmail", ctx, "test@example.com").Return(nil, errors.New("user not found")).Once()
	d.passwordService.On("HashPassword", "password").Return("hashed", nil).Once()
	d.tokenService.On("GenerateRefreshTokenValue").Return("verifToken", nil).Once()
	d.passwordService.On("HashPassword", "verifToken").Return("hashedToken", nil).Once()
	d.userRepo.On("Create", ctx, mock.AnythingOfType("*entity.User")).Return(nil).Once()
	d.verificationCodeRepo.On("Create", ctx, mock.AnythingOfType("*entity.VerificationCode")).Return(nil).Once()
	d.notificationService.On("SendEmailVerificationNotification", ctx, mock.AnythingOfType("uuid.UUID"), "verifToken").Return(nil).Once()

	user, token, err := svc.RegisterUser(ctx, "testuser", "test@example.com", "password")
	require.NoError(t, err)
	assert.Equal(t, "verifToken", token)
	require.NotNil(t, user)

	d.userRepo.AssertExpectations(t)
	d.passwordService.AssertExpectations(t)
	d.tokenService.AssertExpectations(t)
	d.verificationCodeRepo.AssertExpectations(t)
	d.notificationService.AssertExpectations(t)
}

func TestLoginUser_PublishesLoginEvent(t *testing.T) {
	svc, d := setupAuthLogicService(t)
	ctx := context.Background()

	hashed := "hashedPW"
	user := &entity.User{ID: uuid.NewString(), Email: "test@example.com", Username: "user", PasswordHash: &hashed, Status: entity.UserStatusActive}

	d.userRepo.On("FindByEmail", ctx, "test@example.com").Return(user, nil).Once()
	d.passwordService.On("CheckPasswordHash", "password", hashed).Return(true, nil).Once()
	d.mfaSecretRepo.On("FindByUserIDAndType", ctx, user.ID, entity.MFATypeTOTP).Return(nil, errors.New("not found")).Once()
	d.sessionRepo.On("Create", ctx, mock.AnythingOfType("*entity.Session")).Return(nil).Once()
	d.tokenService.On("GenerateAccessToken", user.ID, user.Username, user.Roles, []string{}, mock.AnythingOfType("string")).Return("acc", nil, nil).Once()
	d.tokenService.On("GenerateRefreshTokenValue").Return("refToken", nil).Once()
	d.passwordService.On("HashPassword", "refToken").Return("refHash", nil).Once()
	d.refreshTokenRepo.On("Create", ctx, mock.AnythingOfType("*entity.RefreshToken")).Return(nil).Once()
	d.userRepo.On("UpdateLastLogin", ctx, mock.AnythingOfType("uuid.UUID"), mock.Anything).Return(nil).Once()
	d.userRepo.On("ResetFailedLoginAttempts", ctx, mock.AnythingOfType("uuid.UUID")).Return(nil).Once()
	d.kafkaProducer.On("PublishCloudEvent", ctx, "auth.events", kafkaPkg.EventType(models.AuthUserLoginSuccessV1), mock.AnythingOfType("*string"), mock.AnythingOfType("*string"), mock.Anything).Return(nil).Once()

	u, access, refresh, err := svc.LoginUser(ctx, "test@example.com", "password", nil)
	require.NoError(t, err)
	assert.Equal(t, user.ID, u.ID)
	assert.Equal(t, "acc", access)
	assert.Equal(t, "refToken", refresh)

	d.kafkaProducer.AssertExpectations(t)
}

func TestLoginUser_InvalidPassword_IncrementsAttempts(t *testing.T) {
	lockoutCfg := config.LockoutConfig{MaxFailedAttempts: 3, LockoutDuration: time.Minute}
	svc, d := setupAuthLogicService(t, lockoutCfg)
	ctx := context.Background()

	hashed := "hashedPW"
	user := &entity.User{ID: uuid.NewString(), Email: "test@example.com", Username: "user", PasswordHash: &hashed, Status: entity.UserStatusActive, FailedLoginAttempts: 1}

	d.userRepo.On("FindByEmail", ctx, "test@example.com").Return(user, nil).Once()
	d.passwordService.On("CheckPasswordHash", "wrong", hashed).Return(false, nil).Once()
	d.userRepo.On("UpdateFailedLoginAttempts", ctx, mock.AnythingOfType("uuid.UUID"), 2, (*time.Time)(nil)).Return(nil).Once()

	_, _, _, err := svc.LoginUser(ctx, "test@example.com", "wrong", nil)
	require.Error(t, err)

	d.userRepo.AssertExpectations(t)
}

func TestLoginUser_InvalidPassword_TriggersLockout(t *testing.T) {
	lockoutCfg := config.LockoutConfig{MaxFailedAttempts: 3, LockoutDuration: time.Minute}
	svc, d := setupAuthLogicService(t, lockoutCfg)
	ctx := context.Background()

	hashed := "hashedPW"
	user := &entity.User{ID: uuid.NewString(), Email: "test@example.com", Username: "user", PasswordHash: &hashed, Status: entity.UserStatusActive, FailedLoginAttempts: 2}

	d.userRepo.On("FindByEmail", ctx, "test@example.com").Return(user, nil).Once()
	d.passwordService.On("CheckPasswordHash", "wrong", hashed).Return(false, nil).Once()
	d.userRepo.On("UpdateFailedLoginAttempts", ctx, mock.AnythingOfType("uuid.UUID"), 3, mock.AnythingOfType("*time.Time")).Return(nil).Once()

	_, _, _, err := svc.LoginUser(ctx, "test@example.com", "wrong", nil)
	require.Error(t, err)

	call := d.userRepo.Calls[len(d.userRepo.Calls)-1]
	lockoutArg, ok := call.Arguments.Get(3).(*time.Time)
	require.True(t, ok)
	require.NotNil(t, lockoutArg)
	assert.WithinDuration(t, time.Now().Add(lockoutCfg.LockoutDuration), *lockoutArg, time.Second*2)

	d.userRepo.AssertExpectations(t)
}
