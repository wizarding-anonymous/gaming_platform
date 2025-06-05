// File: internal/service/auth_service_test.go
package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	eventModels "github.com/your-org/auth-service/internal/events/models"
	kafkaPkg "github.com/your-org/auth-service/internal/events/kafka"
	appSecurity "github.com/your-org/auth-service/internal/infrastructure/security"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces"
	"go.uber.org/zap"
)

// --- Mocks ---

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *MockUserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	args := m.Called(ctx, username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *MockUserRepository) IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockUserRepository) UpdateLockout(ctx context.Context, id uuid.UUID, lockoutUntil *time.Time) error {
	args := m.Called(ctx, id, lockoutUntil)
	return args.Error(0)
}
func (m *MockUserRepository) ResetFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error {
	args := m.Called(ctx, id, lastLoginAt)
	return args.Error(0)
}
func (m *MockUserRepository) SetEmailVerifiedAt(ctx context.Context, id uuid.UUID, verifiedAt *time.Time) error {
	args := m.Called(ctx, id, verifiedAt)
	return args.Error(0)
}
func (m *MockUserRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.UserStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}
func (m *MockUserRepository) UpdatePassword(ctx context.Context, id uuid.UUID, newPasswordHash string) error {
	args := m.Called(ctx, id, newPasswordHash)
	return args.Error(0)
}
func (m *MockUserRepository) UpdateEmail(ctx context.Context, id uuid.UUID, newEmail string) error {
    args := m.Called(ctx, id, newEmail)
    return args.Error(0)
}


type MockVerificationCodeRepository struct {
	mock.Mock
}

func (m *MockVerificationCodeRepository) Create(ctx context.Context, vc *models.VerificationCode) error {
	args := m.Called(ctx, vc)
	return args.Error(0)
}
func (m *MockVerificationCodeRepository) FindByCodeHashAndType(ctx context.Context, codeHash string, vcType models.VerificationCodeType) (*models.VerificationCode, error) {
	args := m.Called(ctx, codeHash, vcType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.VerificationCode), args.Error(1)
}
func (m *MockVerificationCodeRepository) MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error {
	args := m.Called(ctx, id, usedAt)
	return args.Error(0)
}
func (m *MockVerificationCodeRepository) DeleteByUserIDAndType(ctx context.Context, userID uuid.UUID, vcType models.VerificationCodeType) (int64, error) {
	args := m.Called(ctx, userID, vcType)
	return args.Get(0).(int64), args.Error(1)
}


type MockTokenService struct {
	mock.Mock
}
func (m *MockTokenService) CreateTokenPairWithSession(ctx context.Context, user *models.User, sessionID uuid.UUID) (*models.TokenPair, error) {
	args := m.Called(ctx, user, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenPair), args.Error(1)
}
func (m *MockTokenService) RefreshTokens(ctx context.Context, plainOpaqueRefreshToken string) (*models.TokenPair, error) {
    args := m.Called(ctx, plainOpaqueRefreshToken)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*models.TokenPair), args.Error(1)
}
func (m *MockTokenService) RevokeRefreshToken(ctx context.Context, plainOpaqueRefreshToken string) error {
    args := m.Called(ctx, plainOpaqueRefreshToken)
    return args.Error(0)
}
func (m *MockTokenService) RevokeToken(ctx context.Context, tokenStr string) error {
    args := m.Called(ctx, tokenStr)
    return args.Error(0)
}
func (m *MockTokenService) RevokeAllRefreshTokensForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return int64(args.Int(0)), args.Error(1)
}


type MockSessionService struct {
	mock.Mock
}
func (m *MockSessionService) CreateSession(ctx context.Context, userID uuid.UUID, userAgent string, ipAddress string) (*models.Session, error) {
	args := m.Called(ctx, userID, userAgent, ipAddress)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}
func (m *MockSessionService) DeactivateSession(ctx context.Context, sessionID uuid.UUID) error {
    args := m.Called(ctx, sessionID)
    return args.Error(0)
}
func (m *MockSessionService) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID, excludeSessionID *uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID, excludeSessionID)
    return int64(args.Int(0)), args.Error(1)
}


type MockKafkaProducer struct {
	mock.Mock
}
func (m *MockKafkaProducer) PublishCloudEvent(ctx context.Context, topic string, eventType eventModels.EventType, subject string, dataPayload interface{}) error {
	args := m.Called(ctx, topic, eventType, subject, dataPayload)
	return args.Error(0)
}
func (m *MockKafkaProducer) Close() error {
	args := m.Called()
	return args.Error(0)
}


type MockPasswordService struct {
	mock.Mock
}
func (m *MockPasswordService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordService) CheckPasswordHash(password, hash string) (bool, error) {
	args := m.Called(password, hash)
	return args.Bool(0), args.Error(1)
}

type MockTokenManagementService struct {
	mock.Mock
}
func (m *MockTokenManagementService) Generate2FAChallengeToken(userID string) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}
func (m *MockTokenManagementService) ValidateAccessToken(tokenString string) (*domainService.Claims, error) {
    args := m.Called(tokenString)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*domainService.Claims), args.Error(1)
}


type MockMFASecretRepository struct {
	mock.Mock
}
func (m *MockMFASecretRepository) FindByUserIDAndType(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) (*models.MFASecret, error) {
	args := m.Called(ctx, userID, mfaType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.MFASecret), args.Error(1)
}


type MockMFALogicService struct {
	mock.Mock
}


type MockAuditLogRecorder struct {
	mock.Mock
}
func (m *MockAuditLogRecorder) RecordEvent(ctx context.Context, actorID *uuid.UUID, action string, status models.AuditLogStatus, targetID interface{}, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	m.Called(ctx, actorID, action, status, targetID, targetType, details, ipAddress, userAgent)
}


type MockUserRolesRepository struct {mock.Mock}
func (m *MockUserRolesRepository) GetRoleIDsForUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
    args := m.Called(ctx, userID)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).([]string), args.Error(1)
}

type MockRoleService struct {mock.Mock}
func (m *MockRoleService) GetRolePermissions(ctx context.Context, roleID string) ([]*models.Permission, error) {
    args := m.Called(ctx, roleID)
     if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).([]*models.Permission), args.Error(1)
}


type MockExternalAccountRepository struct {mock.Mock}


type MockTelegramVerifierService struct {mock.Mock}


// --- Test Suite Setup ---

type AuthServiceTestSuite struct {
	service         domainService.AuthLogicService
	mockUserRepo    *MockUserRepository
	mockVcRepo      *MockVerificationCodeRepository
	mockTokenSvc    *MockTokenService
	mockSessionSvc  *MockSessionService
	mockKafka       *MockKafkaProducer
	mockPassSvc     *MockPasswordService
	mockTokenMgmtSvc *MockTokenManagementService
	mockMfaSecretRepo *MockMFASecretRepository
	mockMfaLogicSvc *MockMFALogicService
	mockAudit       *MockAuditLogRecorder
	mockUserRolesRepo *MockUserRolesRepository
	mockRoleService   *MockRoleService
	mockExtAcctRepo *MockExternalAccountRepository
	mockTelegramSvc *MockTelegramVerifierService
	testConfig      *config.Config
}

func setupAuthServiceTestSuite(t *testing.T) *AuthServiceTestSuite {
	ts := &AuthServiceTestSuite{}
	ts.mockUserRepo = new(MockUserRepository)
	ts.mockVcRepo = new(MockVerificationCodeRepository)
	ts.mockTokenSvc = new(MockTokenService)
	ts.mockSessionSvc = new(MockSessionService)
	ts.mockKafka = new(MockKafkaProducer)
	ts.mockPassSvc = new(MockPasswordService)
	ts.mockTokenMgmtSvc = new(MockTokenManagementService)
	ts.mockMfaSecretRepo = new(MockMFASecretRepository)
	ts.mockMfaLogicSvc = new(MockMFALogicService)
	ts.mockAudit = new(MockAuditLogRecorder)
	ts.mockUserRolesRepo = new(MockUserRolesRepository)
	ts.mockRoleService = new(MockRoleService)
	ts.mockExtAcctRepo = new(MockExternalAccountRepository)
	ts.mockTelegramSvc = new(MockTelegramVerifierService)

	ts.testConfig = &config.Config{
		JWT: config.JWTConfig{
			EmailVerificationToken: config.TokenConfig{ExpiresIn: time.Minute * 15},
			PasswordResetToken:    config.TokenConfig{ExpiresIn: time.Minute * 15},
			AccessTokenTTL:         time.Minute * 15,
		},
		Kafka: config.KafkaConfig{Producer: config.KafkaProducerConfig{Topic: "auth-events"}},
		Security: config.SecurityConfig{
			Lockout: config.LockoutConfig{
				MaxFailedAttempts: 5,
				LockoutDuration:   time.Minute * 15,
			},
		},
	}

	ts.service = NewAuthService(
		ts.mockUserRepo,
		ts.mockVcRepo,
		ts.mockTokenSvc,
		ts.mockSessionSvc,
		ts.mockKafka,
		ts.testConfig,
		zap.NewNop(),
		ts.mockPassSvc,
		ts.mockTokenMgmtSvc,
		ts.mockMfaSecretRepo,
		ts.mockMfaLogicSvc,
		ts.mockUserRolesRepo,
		ts.mockRoleService,
		ts.mockExtAcctRepo,
		ts.mockTelegramSvc,
		ts.mockAudit,
	)
	return ts
}

// --- AuthService.Register Tests ---
// ... (Register tests remain here) ...
func TestAuthService_Register_Success(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	req := models.CreateUserRequest{
		Email:    "test@example.com",
		Username: "testuser",
		Password: "password123",
	}
	hashedPassword := "hashed_password_mock"

	ts.mockUserRepo.On("FindByEmail", ctx, req.Email).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockUserRepo.On("FindByUsername", ctx, req.Username).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockPassSvc.On("HashPassword", req.Password).Return(hashedPassword, nil).Once()

	var capturedUser *models.User
	ts.mockUserRepo.On("Create", ctx, mock.MatchedBy(func(user *models.User) bool {
		capturedUser = user
		return user.Email == req.Email && user.Username == req.Username && user.PasswordHash == hashedPassword
	})).Return(nil).Once()

	ts.mockUserRepo.On("FindByID", ctx, mock.AnythingOfType("uuid.UUID")).Run(func(args mock.Arguments) {
		call := args.Get(0).(*mock.Call)
		if capturedUser == nil {
			call.ReturnArguments = mock.Arguments{nil, errors.New("FindByID called when capturedUser is nil in mock")}
			return
		}
		foundUser := *capturedUser
		foundUser.CreatedAt = time.Now()
		foundUser.Status = models.UserStatusPendingVerification
		call.ReturnArguments = mock.Arguments{&foundUser, nil}
	}).Once()


	ts.mockVcRepo.On("Create", ctx, mock.MatchedBy(func(vc *models.VerificationCode) bool {
		if capturedUser != nil {
			return vc.UserID == capturedUser.ID && vc.Type == models.VerificationCodeTypeEmailVerification
		}
		return vc.Type == models.VerificationCodeTypeEmailVerification
	})).Return(nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserRegisteredV1, mock.AnythingOfType("string"), mock.AnythingOfType("models.UserRegisteredPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusSuccess, mock.AnythingOfType("*uuid.UUID"), models.AuditTargetTypeUser, nil, "unknown", "unknown").Once()


	user, token, err := ts.service.Register(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.NotEmpty(t, token)
	assert.Equal(t, req.Email, user.Email)
	assert.Equal(t, req.Username, user.Username)
	assert.Equal(t, hashedPassword, user.PasswordHash)
	assert.Equal(t, models.UserStatusPendingVerification, user.Status)

	ts.mockUserRepo.AssertExpectations(t)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockVcRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_Register_Failure_EmailExists(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	req := models.CreateUserRequest{Email: "exists@example.com", Password: "password"}

	ts.mockUserRepo.On("FindByEmail", ctx, req.Email).Return(&models.User{}, nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusFailure, (*uuid.UUID)(nil), mock.Anything, mock.Anything, "unknown", "unknown").Once()


	user, token, err := ts.service.Register(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, user)
	assert.Empty(t, token)
	assert.Equal(t, domainErrors.ErrEmailExists, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_Register_Failure_UsernameExists(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	req := models.CreateUserRequest{Email: "new@example.com", Username: "existinguser", Password: "password"}

	ts.mockUserRepo.On("FindByEmail", ctx, req.Email).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockUserRepo.On("FindByUsername", ctx, req.Username).Return(&models.User{}, nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusFailure, (*uuid.UUID)(nil), mock.Anything, mock.Anything, "unknown", "unknown").Once()

	user, token, err := ts.service.Register(ctx, req)
	assert.ErrorIs(t, err, domainErrors.ErrUsernameExists)
	assert.Nil(t, user)
	assert.Empty(t, token)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_Register_Failure_PasswordHashingFails(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	req := models.CreateUserRequest{Email: "test@example.com", Username: "testuser", Password: "password123"}

	hashingError := errors.New("hashing failed")
	ts.mockUserRepo.On("FindByEmail", ctx, req.Email).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockUserRepo.On("FindByUsername", ctx, req.Username).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockPassSvc.On("HashPassword", req.Password).Return("", hashingError).Once()
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusFailure, (*uuid.UUID)(nil), mock.Anything, mock.Anything, "unknown", "unknown").Once()

	user, token, err := ts.service.Register(ctx, req)
	assert.ErrorIs(t, err, hashingError)
	assert.Nil(t, user)
	assert.Empty(t, token)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_Register_Failure_UserCreateFails(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	req := models.CreateUserRequest{Email: "test@example.com", Username: "testuser", Password: "password123"}
	hashedPassword := "hashed_password_mock"
	dbError := errors.New("db create error")

	ts.mockUserRepo.On("FindByEmail", ctx, req.Email).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockUserRepo.On("FindByUsername", ctx, req.Username).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockPassSvc.On("HashPassword", req.Password).Return(hashedPassword, nil).Once()
	ts.mockUserRepo.On("Create", ctx, mock.AnythingOfType("*models.User")).Return(dbError).Once()
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusFailure, (*uuid.UUID)(nil), mock.Anything, mock.Anything, "unknown", "unknown").Once()

	user, token, err := ts.service.Register(ctx, req)
	assert.ErrorIs(t, err, dbError)
	assert.Nil(t, user)
	assert.Empty(t, token)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_Register_Failure_VerificationCodeCreateFails(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	req := models.CreateUserRequest{Email: "test@example.com", Username: "testuser", Password: "password123"}
	hashedPassword := "hashed_password_mock"
	vcError := errors.New("vc create error")

	ts.mockUserRepo.On("FindByEmail", ctx, req.Email).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockUserRepo.On("FindByUsername", ctx, req.Username).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockPassSvc.On("HashPassword", req.Password).Return(hashedPassword, nil).Once()
	ts.mockUserRepo.On("Create", ctx, mock.AnythingOfType("*models.User")).Return(nil).Once()

	mockedCreatedUser := &models.User{ID: uuid.New(), Email: req.Email, Username: req.Username, PasswordHash: hashedPassword, CreatedAt: time.Now()}
	ts.mockUserRepo.On("FindByID", ctx, mock.AnythingOfType("uuid.UUID")).Return(mockedCreatedUser, nil).Once()

	ts.mockVcRepo.On("Create", ctx, mock.AnythingOfType("*models.VerificationCode")).Return(vcError).Once()
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusFailure, mock.AnythingOfType("*uuid.UUID"), models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()


	user, token, err := ts.service.Register(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "could not store verification code")
	assert.Nil(t, user)
	assert.Empty(t, token)

	ts.mockUserRepo.AssertExpectations(t)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockVcRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_Register_Success_KafkaPublishFails(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	req := models.CreateUserRequest{Email: "test@example.com", Username: "testuser", Password: "password123"}
	hashedPassword := "hashed_password_mock"
	kafkaError := errors.New("kafka publish error")

	ts.mockUserRepo.On("FindByEmail", ctx, req.Email).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockUserRepo.On("FindByUsername", ctx, req.Username).Return(nil, domainErrors.ErrUserNotFound).Once()
	ts.mockPassSvc.On("HashPassword", req.Password).Return(hashedPassword, nil).Once()
	var capturedUser *models.User
	ts.mockUserRepo.On("Create", ctx, mock.MatchedBy(func(user *models.User) bool {
		capturedUser = user
		return user.Email == req.Email
	})).Return(nil).Once()
	ts.mockUserRepo.On("FindByID", ctx, mock.AnythingOfType("uuid.UUID")).Run(func(args mock.Arguments) {
		call := args.Get(0).(*mock.Call)
		if capturedUser == nil { call.ReturnArguments = mock.Arguments{nil, errors.New("FindByID mock error")}; return }
		foundUser := *capturedUser; foundUser.CreatedAt = time.Now(); foundUser.Status = models.UserStatusPendingVerification
		call.ReturnArguments = mock.Arguments{&foundUser, nil}
	}).Once()
	ts.mockVcRepo.On("Create", ctx, mock.AnythingOfType("*models.VerificationCode")).Return(nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserRegisteredV1, mock.AnythingOfType("string"), mock.AnythingOfType("models.UserRegisteredPayload")).Return(kafkaError).Once()
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "user_register", models.AuditLogStatusSuccess, mock.AnythingOfType("*uuid.UUID"), models.AuditTargetTypeUser, nil, "unknown", "unknown").Once()


	user, token, err := ts.service.Register(ctx, req)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.NotEmpty(t, token)

	ts.mockUserRepo.AssertExpectations(t)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockVcRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

// --- AuthService.VerifyEmail Tests ---

func TestAuthService_VerifyEmail_Success(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	plainToken := "valid_plain_token"
	hashedToken := appSecurity.HashToken(plainToken)
	userID := uuid.New()
	verificationCode := &models.VerificationCode{ID: uuid.New(), UserID: userID, Type: models.VerificationCodeTypeEmailVerification, CodeHash: hashedToken, ExpiresAt: time.Now().Add(time.Hour)}
	user := &models.User{ID: userID, Email: "test@example.com", Status: models.UserStatusPendingVerification}

	ts.mockVcRepo.On("FindByCodeHashAndType", ctx, hashedToken, models.VerificationCodeTypeEmailVerification).Return(verificationCode, nil).Once()
	ts.mockUserRepo.On("FindByID", ctx, userID).Return(user, nil).Once()
	ts.mockUserRepo.On("SetEmailVerifiedAt", ctx, userID, mock.AnythingOfType("*time.Time")).Return(nil).Once()
	ts.mockUserRepo.On("UpdateStatus", ctx, userID, models.UserStatusActive).Return(nil).Once()
	ts.mockVcRepo.On("MarkAsUsed", ctx, verificationCode.ID, mock.AnythingOfType("time.Time")).Return(nil).Once()
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserEmailVerifiedV1, userID.String(), mock.AnythingOfType("models.UserEmailVerifiedPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "email_verify", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.VerifyEmail(ctx, plainToken)
	assert.NoError(t, err)
	ts.mockVcRepo.AssertExpectations(t)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_VerifyEmail_Failure_InvalidToken(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	plainToken := "invalid_token"
	hashedToken := appSecurity.HashToken(plainToken)

	ts.mockVcRepo.On("FindByCodeHashAndType", ctx, hashedToken, models.VerificationCodeTypeEmailVerification).Return(nil, domainErrors.ErrNotFound).Once()
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "email_verify", models.AuditLogStatusFailure, (*uuid.UUID)(nil), models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()


	err := ts.service.VerifyEmail(ctx, plainToken)
	assert.ErrorIs(t, err, domainErrors.ErrInvalidToken)
	ts.mockVcRepo.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

// TODO: Add more VerifyEmail failure cases

// --- AuthService.Login Tests ---

func TestAuthService_Login_Success_No2FA(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	loginReq := models.LoginRequest{Email: "test@example.com", Password: "password123"}
	userID := uuid.New()
	hashedPassword := "hashed_password"

	user := &models.User{
		ID: userID, Email: loginReq.Email, Username: "testuser", PasswordHash: hashedPassword,
		Status: models.UserStatusActive, EmailVerifiedAt: func() *time.Time { t := time.Now(); return &t }(),
	}
	session := &models.Session{ID: uuid.New(), UserID: userID}
	tokenPair := &models.TokenPair{AccessToken: "at", RefreshToken: "rt"}

	ts.mockUserRepo.On("FindByEmail", ctx, loginReq.Email).Return(user, nil).Once()
	ts.mockPassSvc.On("CheckPasswordHash", loginReq.Password, hashedPassword).Return(true, nil).Once()
	ts.mockMfaSecretRepo.On("FindByUserIDAndType", ctx, userID, models.MFATypeTOTP).Return(nil, domainErrors.ErrNotFound).Once()

	ts.mockUserRepo.On("ResetFailedLoginAttempts", ctx, userID).Return(nil).Once()
	ts.mockUserRepo.On("UpdateLastLogin", ctx, userID, mock.AnythingOfType("time.Time")).Return(nil).Once()
	ts.mockSessionSvc.On("CreateSession", ctx, userID, "unknown", "unknown").Return(session, nil).Once()
	ts.mockTokenSvc.On("CreateTokenPairWithSession", ctx, user, session.ID).Return(tokenPair, nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserLoginSuccessV1, userID.String(), mock.AnythingOfType("models.UserLoginSuccessPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "user_login", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	_, returnedUser, challengeToken, err := ts.service.Login(ctx, loginReq)

	assert.NoError(t, err)
	assert.NotNil(t, returnedUser)
	assert.Empty(t, challengeToken)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockMfaSecretRepo.AssertExpectations(t)
	ts.mockSessionSvc.AssertExpectations(t)
	ts.mockTokenSvc.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

// --- AuthService.RefreshToken Tests ---

func TestAuthService_RefreshToken_Success(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	plainRefreshToken := "valid-refresh-token"
	expectedTokenPair := &models.TokenPair{AccessToken: "new-access-token", RefreshToken: "new-refresh-token"}

	ts.mockTokenSvc.On("RefreshTokens", ctx, plainRefreshToken).Return(expectedTokenPair, nil).Once()

	userID := uuid.New()
	sessionID := uuid.New()
	claims := &domainService.Claims{UserID: userID.String(), SessionID: sessionID.String()}
	ts.mockTokenMgmtSvc.On("ValidateAccessToken", "new-access-token").Return(claims, nil).Once()

	ts.mockAudit.On("RecordEvent", ctx, &userID, "token_refresh", models.AuditLogStatusSuccess, &sessionID, models.AuditTargetTypeSession, mock.Anything, "unknown", "unknown").Once()

	tokenPair, err := ts.service.RefreshToken(ctx, plainRefreshToken)

	assert.NoError(t, err)
	assert.Equal(t, expectedTokenPair, tokenPair)
	ts.mockTokenSvc.AssertExpectations(t)
	ts.mockTokenMgmtSvc.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_RefreshToken_Failure(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	plainRefreshToken := "invalid-refresh-token"
	expectedError := domainErrors.ErrInvalidToken

	ts.mockTokenSvc.On("RefreshTokens", ctx, plainRefreshToken).Return(nil, expectedError).Once()
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "token_refresh", models.AuditLogStatusFailure, (*uuid.UUID)(nil), mock.Anything, mock.Anything, "unknown", "unknown").Once()


	tokenPair, err := ts.service.RefreshToken(ctx, plainRefreshToken)

	assert.ErrorIs(t, err, expectedError)
	assert.Nil(t, tokenPair)
	ts.mockTokenSvc.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

// --- AuthService.Logout and LogoutAll Tests ---

func TestAuthService_Logout_Success(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	accessToken := "valid-access-token"
	refreshToken := "valid-refresh-token"
	userID := uuid.New()
	sessionID := uuid.New()

	claims := &domainService.Claims{UserID: userID.String(), SessionID: sessionID.String()}
	ts.mockTokenMgmtSvc.On("ValidateAccessToken", accessToken).Return(claims, nil).Once()
	ts.mockTokenSvc.On("RevokeRefreshToken", ctx, refreshToken).Return(nil).Once()
	ts.mockSessionSvc.On("DeactivateSession", ctx, sessionID).Return(nil).Once()
	ts.mockTokenSvc.On("RevokeToken", ctx, accessToken).Return(nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserLogoutSuccessV1, userID.String(), mock.AnythingOfType("models.UserLogoutSuccessPayload")).Return(nil).Once()
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthSessionRevokedV1, sessionID.String(), mock.AnythingOfType("models.SessionRevokedPayload")).Return(nil).Once()

	ts.mockAudit.On("RecordEvent", ctx, &userID, "user_logout", models.AuditLogStatusSuccess, &sessionID, models.AuditTargetTypeSession, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.Logout(ctx, accessToken, refreshToken)
	assert.NoError(t, err)
	ts.mockTokenMgmtSvc.AssertExpectations(t)
	ts.mockTokenSvc.AssertExpectations(t)
	ts.mockSessionSvc.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}


func TestAuthService_LogoutAll_Success(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	accessToken := "valid-access-token"
	userID := uuid.New()

	claims := &domainService.Claims{UserID: userID.String(), SessionID: uuid.NewString()}
	ts.mockTokenMgmtSvc.On("ValidateAccessToken", accessToken).Return(claims, nil).Once()

	ts.mockSessionSvc.On("DeleteAllUserSessions", ctx, userID, (*uuid.UUID)(nil)).Return(int64(2), nil).Once()
	ts.mockTokenSvc.On("RevokeAllRefreshTokensForUser", ctx, userID).Return(int64(2), nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserAllSessionsRevokedV1, userID.String(), mock.AnythingOfType("models.UserAllSessionsRevokedPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "user_logout_all", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.LogoutAll(ctx, accessToken)
	assert.NoError(t, err)
	ts.mockTokenMgmtSvc.AssertExpectations(t)
	ts.mockSessionSvc.AssertExpectations(t)
	ts.mockTokenSvc.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

// --- AuthService Password Management Tests ---

func TestAuthService_ForgotPassword_Success_UserExists(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	email := "user@example.com"
	userID := uuid.New()
	user := &models.User{ID: userID, Email: email}

	ts.mockUserRepo.On("FindByEmail", ctx, email).Return(user, nil).Once()
	ts.mockVcRepo.On("DeleteByUserIDAndType", ctx, userID, models.VerificationCodeTypePasswordReset).Return(int64(1), nil).Once() // Assume one was deleted or 0 if none
	ts.mockVcRepo.On("Create", ctx, mock.MatchedBy(func(vc *models.VerificationCode) bool {
		return vc.UserID == userID && vc.Type == models.VerificationCodeTypePasswordReset
	})).Return(nil).Once()
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthSecurityPasswordResetRequestedV1, userID.String(), mock.AnythingOfType("models.PasswordResetRequestedPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "password_reset_request", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.ForgotPassword(ctx, email)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockVcRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_ForgotPassword_Success_UserDoesNotExist(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	email := "nonexistent@example.com"

	ts.mockUserRepo.On("FindByEmail", ctx, email).Return(nil, domainErrors.ErrUserNotFound).Once()
	// No VCrepo calls, no Kafka calls
	ts.mockAudit.On("RecordEvent", ctx, (*uuid.UUID)(nil), "password_reset_request", models.AuditLogStatusSuccess, (*uuid.UUID)(nil), models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()


	err := ts.service.ForgotPassword(ctx, email)
	assert.NoError(t, err) // Should be silent success
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockVcRepo.AssertNotCalled(t, "DeleteByUserIDAndType")
	ts.mockVcRepo.AssertNotCalled(t, "Create")
	ts.mockKafka.AssertNotCalled(t, "PublishCloudEvent")
	ts.mockAudit.AssertExpectations(t)
}


func TestAuthService_ResetPassword_Success(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	plainToken := "valid-reset-token"
	hashedToken := appSecurity.HashToken(plainToken)
	newPassword := "newSecurePassword123"
	hashedNewPassword := "hashedNewSecurePassword123"
	userID := uuid.New()

	verificationCode := &models.VerificationCode{ID: uuid.New(), UserID: userID, Type: models.VerificationCodeTypePasswordReset, CodeHash: hashedToken, ExpiresAt: time.Now().Add(time.Hour)}
	user := &models.User{ID: userID, Email: "user@example.com"}

	ts.mockVcRepo.On("FindByCodeHashAndType", ctx, hashedToken, models.VerificationCodeTypePasswordReset).Return(verificationCode, nil).Once()
	ts.mockUserRepo.On("FindByID", ctx, userID).Return(user, nil).Once()
	ts.mockPassSvc.On("HashPassword", newPassword).Return(hashedNewPassword, nil).Once()
	ts.mockUserRepo.On("UpdatePassword", ctx, userID, hashedNewPassword).Return(nil).Once()
	ts.mockVcRepo.On("MarkAsUsed", ctx, verificationCode.ID, mock.AnythingOfType("time.Time")).Return(nil).Once()
	ts.mockSessionSvc.On("DeleteAllUserSessions", ctx, userID, (*uuid.UUID)(nil)).Return(int64(1), nil).Once()
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserPasswordResetV1, userID.String(), mock.AnythingOfType("models.UserPasswordResetPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "password_reset", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.ResetPassword(ctx, plainToken, newPassword)
	assert.NoError(t, err)
	ts.mockVcRepo.AssertExpectations(t)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockSessionSvc.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAuthService_ChangePassword_Success(t *testing.T) {
	ts := setupAuthServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	oldPassword := "oldPassword123"
	newPassword := "newSecurePassword123"
	currentHashedPassword := "hashedOldPassword" // Mock current hash in DB
	newHashedPassword := "hashedNewSecurePassword123"

	user := &models.User{ID: userID, PasswordHash: currentHashedPassword, UpdatedAt: time.Now().Add(-time.Hour)} // ensure UpdatedAt changes

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(user, nil).Once()
	ts.mockPassSvc.On("CheckPasswordHash", oldPassword, currentHashedPassword).Return(true, nil).Once()
	ts.mockPassSvc.On("HashPassword", newPassword).Return(newHashedPassword, nil).Once()
	ts.mockUserRepo.On("UpdatePassword", ctx, userID, newHashedPassword).Return(nil).Once().Run(func(args mock.Arguments) {
		// Simulate DB updating UpdatedAt
		user.UpdatedAt = time.Now()
	})
	ts.mockSessionSvc.On("DeleteAllUserSessions", ctx, userID, (*uuid.UUID)(nil)).Return(int64(1), nil).Once()
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserPasswordChangedV1, userID.String(), mock.MatchedBy(func(payload models.UserPasswordChangedPayload) bool {
		return payload.UserID == userID.String() && payload.Source == "user_self_service"
	 })).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &userID, "password_change", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "unknown", "unknown").Once()

	err := ts.service.ChangePassword(ctx, userID, oldPassword, newPassword)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockPassSvc.AssertExpectations(t)
	ts.mockSessionSvc.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}


func init() {
	// Suppress token generation log messages if appSecurity uses a logger
}
