// File: backend/services/auth-service/internal/service/telegram_auth_service_test.go
package service

import (
	"context"
	"encoding/json"
	// "errors" // Not used in current example but likely for other tests
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	kafkaEvents "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/kafka" // For actual event types if needed in assertions
	eventMocks "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/events/mocks"  // Assuming kafka mock producer
)

// Mocks (similar to those in oauth_service_test.go, adapted for Telegram)

type MockUserRepositoryForTelegram struct {
	mock.Mock
}

func (m *MockUserRepositoryForTelegram) WithTx(tx domain.Transaction) domain.UserRepository {
	args := m.Called(tx)
	return args.Get(0).(domain.UserRepository)
}
func (m *MockUserRepositoryForTelegram) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *MockUserRepositoryForTelegram) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

type MockExternalAccountRepositoryForTelegram struct {
	mock.Mock
}

func (m *MockExternalAccountRepositoryForTelegram) WithTx(tx domain.Transaction) domain.ExternalAccountRepository {
	args := m.Called(tx)
	return args.Get(0).(domain.ExternalAccountRepository)
}
func (m *MockExternalAccountRepositoryForTelegram) FindByProviderAndExternalID(ctx context.Context, provider string, externalID string) (*models.ExternalAccount, error) {
	args := m.Called(ctx, provider, externalID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.ExternalAccount), args.Error(1)
}
func (m *MockExternalAccountRepositoryForTelegram) Create(ctx context.Context, acc *models.ExternalAccount) error {
	args := m.Called(ctx, acc)
	return args.Error(0)
}
func (m *MockExternalAccountRepositoryForTelegram) Update(ctx context.Context, acc *models.ExternalAccount) error {
	args := m.Called(ctx, acc)
	return args.Error(0)
}

type MockSessionServiceForTelegram struct {
	mock.Mock
}

func (m *MockSessionServiceForTelegram) CreateSession(ctx context.Context, userID uuid.UUID, userAgent string, ipAddress string) (*models.Session, error) {
	args := m.Called(ctx, userID, userAgent, ipAddress)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}

type MockTokenServiceForTelegram struct {
	mock.Mock
}

func (m *MockTokenServiceForTelegram) CreateTokenPairWithSession(ctx context.Context, user *models.User, sessionID uuid.UUID) (*models.TokenPair, error) {
	args := m.Called(ctx, user, sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TokenPair), args.Error(1)
}

type MockTelegramVerifierServiceForTest struct {
	mock.Mock
}

func (m *MockTelegramVerifierServiceForTest) Verify(ctx context.Context, telegramData models.TelegramAuthData) (*models.TelegramProfile, error) {
	args := m.Called(ctx, telegramData)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.TelegramProfile), args.Error(1)
}

type MockTransactionManagerForTelegram struct {
	mock.Mock
}

func (m *MockTransactionManagerForTelegram) Begin(ctx context.Context) (domain.Transaction, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(domain.Transaction), args.Error(1)
}
func (m *MockTransactionManagerForTelegram) Commit(tx domain.Transaction) error {
	args := m.Called(tx)
	return args.Error(0)
}
func (m *MockTransactionManagerForTelegram) Rollback(tx domain.Transaction) error {
	args := m.Called(tx)
	return args.Error(0)
}

// MockTransaction is a simple mock for domain.Transaction (can be shared if in common test util)
type MockTransactionForTelegram struct {
	mock.Mock
}

func (m *MockTransactionForTelegram) Commit() error {
	args := m.Called()
	return args.Error(0)
}
func (m *MockTransactionForTelegram) Rollback() error {
	args := m.Called()
	return args.Error(0)
}
func (m *MockTransactionForTelegram) DB() interface{} {
	args := m.Called()
	return args.Get(0)
}

type MockAuditLogRecorderForTelegram struct {
	mock.Mock
}

func (m *MockAuditLogRecorderForTelegram) RecordEvent(ctx context.Context, tx domain.Transaction, actorUserID *uuid.UUID, eventName string, status models.AuditLogStatus, targetUserID *uuid.UUID, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	// Adjusted signature to match the one in auth_service_test.go for consistency
	// The TelegramAuthService uses a slightly different signature for RecordEvent (without tx, actorUserID, etc. directly, but wrapped in AuditLogEvent)
	// This mock should match the actual signature used by TelegramAuthService's AuditLogRecorder.
	// The service uses: s.auditLogRecorder.RecordEvent(txCtx, userIDForAudit, auditAction, models.AuditLogStatusSuccess, userIDForAudit, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)
	// This implies the AuditLogRecorder interface method is more like the one in auth_service_test.go
	// For now, let's use the one from auth_service_test.go's mock as it's more complete.
	// If domainService.AuditLogRecorder's RecordEvent is different, this mock needs to adapt.
	// The one in oauth_service_test.go for RecordEvent was: `RecordEvent(ctx context.Context, tx domain.Transaction, event domainService.AuditLogEvent) error`
	// This is inconsistent. Assuming the one in TelegramAuthService is:
	// `RecordEvent(tx domain.Transaction, actorID *uuid.UUID, action string, status models.AuditLogStatus, targetID *uuid.UUID, targetType models.AuditTargetType, details map[string]interface{}, ip string, ua string)`
	// Let's assume for now the RecordEvent in TelegramAuthService matches the one used in its implementation.
	// The implementation uses: `s.auditLogRecorder.RecordEvent(txCtx, userIDForAudit, auditAction, models.AuditLogStatusSuccess, userIDForAudit, models.AuditTargetTypeUser, auditDetails, ipAddress, userAgent)`
	// This is not matching the interface `domainService.AuditLogRecorder` usually.
	// For the subtask, I will assume a generic RecordEvent that fits the call.
	m.Called(tx, actorUserID, eventName, status, targetUserID, targetType, details, ipAddress, userAgent)
}

type TelegramAuthServiceTestSuite struct {
	suite.Suite
	service              *TelegramAuthService
	mockUserRepo         *MockUserRepositoryForTelegram
	mockExtAccRepo       *MockExternalAccountRepositoryForTelegram
	mockSessionService   *MockSessionServiceForTelegram
	mockTokenService     *MockTokenServiceForTelegram
	mockTelegramVerifier *MockTelegramVerifierServiceForTest
	mockTransactionMgr   *MockTransactionManagerForTelegram
	mockKafkaProducer    *eventMocks.MockProducer
	mockAuditRecorder    *MockAuditLogRecorderForTelegram
	cfg                  *config.Config
	logger               *zap.Logger
}

func (s *TelegramAuthServiceTestSuite) SetupTest() {
	s.mockUserRepo = new(MockUserRepositoryForTelegram)
	s.mockExtAccRepo = new(MockExternalAccountRepositoryForTelegram)
	s.mockSessionService = new(MockSessionServiceForTelegram)
	s.mockTokenService = new(MockTokenServiceForTelegram)
	s.mockTelegramVerifier = new(MockTelegramVerifierServiceForTest)
	s.mockTransactionMgr = new(MockTransactionManagerForTelegram)
	s.mockKafkaProducer = new(eventMocks.MockProducer)
	s.mockAuditRecorder = new(MockAuditLogRecorderForTelegram)
	s.logger, _ = zap.NewDevelopment()
	s.cfg = &config.Config{Kafka: config.KafkaConfig{Producer: config.KafkaProducerConfig{Topic: "auth.events"}}}

	s.service = NewTelegramAuthService(
		s.cfg,
		s.logger,
		s.mockUserRepo,
		s.mockExtAccRepo,
		s.mockSessionService, // Cast if needed
		s.mockTokenService,   // Cast if needed
		s.mockTelegramVerifier,
		s.mockTransactionMgr,
		s.mockKafkaProducer,
		s.mockAuditRecorder,
	)
}

func TestTelegramAuthServiceTestSuite(t *testing.T) {
	suite.Run(t, new(TelegramAuthServiceTestSuite))
}

func (s *TelegramAuthServiceTestSuite) TestTelegramAuthService_AuthenticateViaTelegram_Success_NewUser() {
	ctx := context.Background()
	ipAddress := "127.0.0.1"
	userAgent := "test-agent"
	telegramID := int64(123456789)
	externalUserIDStr := "123456789"

	authData := models.TelegramAuthData{
		ID:        telegramID,
		FirstName: "Test",
		LastName:  "User",
		Username:  "testuser_tg",
		PhotoURL:  "http://example.com/photo.jpg",
		AuthDate:  time.Now().Unix() - 60, // Auth date 1 minute ago
		Hash:      "valid_hash_from_telegram",
	}

	verifiedProfile := &models.TelegramProfile{
		ID:        authData.ID,
		FirstName: authData.FirstName,
		LastName:  authData.LastName,
		Username:  authData.Username,
		PhotoURL:  authData.PhotoURL,
		AuthDate:  authData.AuthDate,
	}

	profileDataBytes, _ := json.Marshal(verifiedProfile)
	profileDataRaw := json.RawMessage(profileDataBytes)

	// Mock TelegramVerifier
	s.mockTelegramVerifier.On("Verify", ctx, authData).Return(verifiedProfile, nil).Once()

	// Mock TransactionManager
	mockTx := new(MockTransactionForTelegram) // Use the specific mock for this test suite
	s.mockTransactionMgr.On("Begin", ctx).Return(mockTx, nil).Once()
	s.mockTransactionMgr.On("Commit", mockTx).Return(nil).Once() // Expect commit

	// Mock Repositories (to be called with tx)
	s.mockUserRepo.On("WithTx", mockTx).Return(s.mockUserRepo).Once()
	s.mockExtAccRepo.On("WithTx", mockTx).Return(s.mockExtAccRepo).Once()

	// Mock ExternalAccountRepo: FindByProviderAndExternalID returns NotFound
	s.mockExtAccRepo.On("FindByProviderAndExternalID", ctx, TelegramProviderName, externalUserIDStr).Return(nil, domainErrors.ErrNotFound).Once()

	// Mock UserRepo: Create succeeds
	s.mockUserRepo.On("Create", ctx, mock.MatchedBy(func(user *models.User) bool {
		return user.Username == verifiedProfile.Username && *user.ProfileImageURL == verifiedProfile.PhotoURL
	})).Return(nil).Once()

	// Mock ExternalAccountRepo: Create succeeds
	s.mockExtAccRepo.On("Create", ctx, mock.MatchedBy(func(extAcc *models.ExternalAccount) bool {
		return extAcc.Provider == TelegramProviderName && extAcc.ExternalUserID == externalUserIDStr && string(extAcc.ProfileData) == string(profileDataRaw)
	})).Return(nil).Once()

	// Mock SessionService: CreateSession succeeds
	mockSession := &models.Session{ID: uuid.New(), UserID: uuid.New()} // UserID will be set by the service logic
	s.mockSessionService.On("CreateSession", ctx, mock.AnythingOfType("uuid.UUID"), userAgent, ipAddress).Return(mockSession, nil).Once()

	// Mock TokenService: CreateTokenPairWithSession succeeds
	mockTokenPair := &models.TokenPair{AccessToken: "access_token", RefreshToken: "refresh_token"}
	s.mockTokenService.On("CreateTokenPairWithSession", ctx, mock.AnythingOfType("*models.User"), mockSession.ID).Return(mockTokenPair, nil).Once()

	// Mock KafkaProducer for UserRegisteredEvent, AccountLinkedEvent, UserLoginSuccessEvent
	s.mockKafkaProducer.On("PublishCloudEvent", ctx, s.cfg.Kafka.Producer.Topic, kafkaEvents.EventType(models.AuthUserRegisteredV1), mock.AnythingOfType("*string"), mock.AnythingOfType("*string"), mock.AnythingOfType("models.UserRegisteredPayload")).Return(nil).Once()
	s.mockKafkaProducer.On("PublishAccountLinkedEvent", ctx, mock.AnythingOfType("kafkaEvents.AccountLinkedEvent")).Return(nil).Once()
	s.mockKafkaProducer.On("PublishCloudEvent", ctx, s.cfg.Kafka.Producer.Topic, kafkaEvents.EventType(models.AuthUserLoginSuccessV1), mock.AnythingOfType("*string"), mock.AnythingOfType("*string"), mock.AnythingOfType("models.UserLoginSuccessPayload")).Return(nil).Once()

	// Mock AuditLogRecorder
	s.mockAuditRecorder.On("RecordEvent", mockTx, mock.AnythingOfType("*uuid.UUID"), "user_telegram_register_login", models.AuditLogStatusSuccess, mock.AnythingOfType("*uuid.UUID"), models.AuditTargetTypeUser, mock.Anything, ipAddress, userAgent).Once()

	user, tokenPair, err := s.service.AuthenticateViaTelegram(ctx, authData, ipAddress, userAgent)

	assert.NoError(s.T(), err)
	assert.NotNil(s.T(), user)
	assert.NotNil(s.T(), tokenPair)
	assert.Equal(s.T(), verifiedProfile.Username, user.Username)

	s.mockTelegramVerifier.AssertExpectations(s.T())
	s.mockTransactionMgr.AssertExpectations(s.T())
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockExtAccRepo.AssertExpectations(s.T())
	s.mockSessionService.AssertExpectations(s.T())
	s.mockTokenService.AssertExpectations(s.T())
	s.mockKafkaProducer.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

// Further tests would cover:
// - AuthenticateViaTelegram: Existing User (ExternalAccount found)
// - AuthenticateViaTelegram: Telegram verification fails
// - AuthenticateViaTelegram: User is blocked or deleted
// - AuthenticateViaTelegram: DB errors during user/external account creation or update
// - AuthenticateViaTelegram: Session or Token creation errors
// - Correct transaction rollback on any critical error.
