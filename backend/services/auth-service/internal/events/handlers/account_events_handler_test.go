package handlers

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	eventModels "github.com/your-org/auth-service/internal/events/models" // For CloudEvent and payloads
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	kafkaMocks "github.com/your-org/auth-service/internal/events/mocks" // Using alias for clarity
	"go.uber.org/zap"
)

// --- Mocks for Dependencies ---

// MockUserRepository (subset for AccountEventsHandler)
type MockUserRepository struct {
	mock.Mock
	repoInterfaces.UserRepository
}
func (m *MockUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *MockUserRepository) UpdateEmail(ctx context.Context, userID uuid.UUID, newEmail string) error {
	args := m.Called(ctx, userID, newEmail)
	return args.Error(0)
}
func (m *MockUserRepository) SetEmailVerifiedAt(ctx context.Context, userID uuid.UUID, verifiedAt *time.Time) error {
	args := m.Called(ctx, userID, verifiedAt)
	return args.Error(0)
}
func (m *MockUserRepository) UpdateStatus(ctx context.Context, userID uuid.UUID, status models.UserStatus) error {
	args := m.Called(ctx, userID, status)
	return args.Error(0)
}
func (m *MockUserRepository) UpdateStatusReason(ctx context.Context, userID uuid.UUID, reason *string) error {
    args := m.Called(ctx, userID, reason)
    return args.Error(0)
}
func (m *MockUserRepository) Delete(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}
// Add other UserRepo methods if needed by handlers under test

// MockVerificationCodeRepository
type MockVerificationCodeRepository struct {
	mock.Mock
	repoInterfaces.VerificationCodeRepository
}
func (m *MockVerificationCodeRepository) Create(ctx context.Context, vc *models.VerificationCode) error {
	args := m.Called(ctx, vc)
	return args.Error(0)
}
func (m *MockVerificationCodeRepository) DeleteByUserIDAndType(ctx context.Context, userID uuid.UUID, codeType models.VerificationCodeType) (int64, error) {
	args := m.Called(ctx, userID, codeType)
	return args.Get(0).(int64), args.Error(1)
}
func (m *MockVerificationCodeRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}


// MockAuthLogicService (subset for AccountEventsHandler)
type MockAuthLogicService struct {
	mock.Mock
	domainService.AuthLogicService // Embed interface
}
func (m *MockAuthLogicService) SystemLogoutAllUserSessions(ctx context.Context, userID uuid.UUID, reason string) error {
	args := m.Called(ctx, userID, reason)
	return args.Error(0)
}
// Add other AuthLogicService methods if called by handlers

// MockSessionRepository
type MockSessionRepository struct {
    mock.Mock
    repoInterfaces.SessionRepository
}
func (m *MockSessionRepository) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

// MockRefreshTokenRepository
type MockRefreshTokenRepository struct {
    mock.Mock
    repoInterfaces.RefreshTokenRepository
}
func (m *MockRefreshTokenRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

// MockMFASecretRepository
type MockMFASecretRepository struct {
    mock.Mock
    repoInterfaces.MFASecretRepository
}
func (m *MockMFASecretRepository) DeleteAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

// MockMFABackupCodeRepository
type MockMFABackupCodeRepository struct {
    mock.Mock
    repoInterfaces.MFABackupCodeRepository
}
func (m *MockMFABackupCodeRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

// MockAPIKeyRepository
type MockAPIKeyRepository struct {
    mock.Mock
    repoInterfaces.APIKeyRepository
}
func (m *MockAPIKeyRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

// MockExternalAccountRepository
type MockExternalAccountRepository struct {
    mock.Mock
    repoInterfaces.ExternalAccountRepository
}
func (m *MockExternalAccountRepository) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

// MockAuditLogRecorder
type MockAuditLogRecorder struct {
	mock.Mock
	domainService.AuditLogRecorder
}
func (m *MockAuditLogRecorder) RecordEvent(ctx context.Context, actorUserID *uuid.UUID, eventName string, status models.AuditLogStatus, targetUserID *uuid.UUID, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	m.Called(ctx, actorUserID, eventName, status, targetUserID, targetType, details, ipAddress, userAgent)
}


// --- AccountEventsHandler Test Suite ---
type AccountEventsHandlerTestSuite struct {
	suite.Suite
	handler             *AccountEventsHandler
	mockUserRepo        *MockUserRepository
	mockVerificationRepo*MockVerificationCodeRepository
	mockAuthLogicSvc    *MockAuthLogicService
	mockKafkaProducer   *kafkaMocks.MockProducer
	mockSessionRepo     *MockSessionRepository
	mockRefreshRepo     *MockRefreshTokenRepository
	mockMfaSecretRepo   *MockMFASecretRepository
	mockMfaBackupRepo   *MockMFABackupCodeRepository
	mockApiKeyRepo      *MockAPIKeyRepository
	mockExtAccRepo      *MockExternalAccountRepository
	mockAuditRecorder   *MockAuditLogRecorder
	cfg                 *config.Config
	logger              *zap.Logger
}

func (s *AccountEventsHandlerTestSuite) SetupTest() {
	s.mockUserRepo = new(MockUserRepository)
	s.mockVerificationRepo = new(MockVerificationCodeRepository)
	s.mockAuthLogicSvc = new(MockAuthLogicService)
	s.mockKafkaProducer = new(kafkaMocks.MockProducer)
	s.mockSessionRepo = new(MockSessionRepository)
	s.mockRefreshRepo = new(MockRefreshTokenRepository)
	s.mockMfaSecretRepo = new(MockMFASecretRepository)
	s.mockMfaBackupRepo = new(MockMFABackupCodeRepository)
	s.mockApiKeyRepo = new(MockAPIKeyRepository)
	s.mockExtAccRepo = new(MockExternalAccountRepository)
	s.mockAuditRecorder = new(MockAuditLogRecorder)

	s.logger, _ = zap.NewDevelopment()
	s.cfg = &config.Config{ // Simplified config for tests
		JWT: config.JWTConfig{
			EmailVerificationToken: config.TokenConfig{ExpiresIn: 24 * time.Hour},
		},
		Kafka: config.KafkaConfig{
			Producer: config.KafkaProducerConfig{Topic: "auth-events-topic"},
		},
		// Add other necessary config fields if used by handlers
	}

	// Initialize AccountEventsHandler with mocks
	s.handler = NewAccountEventsHandler(
		s.logger,
		s.cfg,
		s.mockUserRepo,
		s.mockVerificationRepo,
		s.mockAuthLogicSvc,
		s.mockKafkaProducer,
		s.mockSessionRepo,
		s.mockRefreshRepo,
		s.mockMfaSecretRepo,
		s.mockMfaBackupRepo,
		s.mockApiKeyRepo,
		s.mockExtAccRepo,
		s.mockAuditRecorder,
	)
}

func TestAccountEventsHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(AccountEventsHandlerTestSuite))
}

// --- Test Cases ---

// TestHandleAccountUserProfileUpdated_EmailChange
func (s *AccountEventsHandlerTestSuite) TestHandleAccountUserProfileUpdated_EmailChange() {
	ctx := context.Background()
	userID := uuid.New()
	oldEmail := "old@example.com"
	newEmail := "new@example.com"

	payload := eventModels.AccountUserProfileUpdatedPayload{
		UserID:   userID.String(),
		OldEmail: &oldEmail,
		NewEmail: &newEmail,
		// Other fields can be nil or default if not relevant to this specific test
	}
	payloadBytes, _ := json.Marshal(payload)
	cloudEvent := models.CloudEvent{
		Type:   eventModels.AccountUserProfileUpdatedV1,
		Source: "account-service",
		Data:   payloadBytes,
	}

	user := &models.User{ID: userID, Email: oldEmail, Status: models.UserStatusActive}

	s.mockUserRepo.On("FindByID", ctx, userID).Return(user, nil).Once()
	s.mockUserRepo.On("UpdateEmail", ctx, userID, newEmail).Return(nil).Once()
	s.mockUserRepo.On("SetEmailVerifiedAt", ctx, userID, (*time.Time)(nil)).Return(nil).Once() // Expect nil time
	s.mockUserRepo.On("UpdateStatus", ctx, userID, models.UserStatusPendingVerification).Return(nil).Once()
	s.mockVerificationRepo.On("DeleteByUserIDAndType", ctx, userID, models.VerificationCodeTypeEmailVerification).Return(int64(1), nil).Once()
	s.mockVerificationRepo.On("Create", ctx, mock.AnythingOfType("*models.VerificationCode")).Run(func(args mock.Arguments) {
		vc := args.Get(1).(*models.VerificationCode)
		assert.Equal(s.T(), userID, vc.UserID)
		assert.Equal(s.T(), models.VerificationCodeTypeEmailVerification, vc.Type)
	}).Return(nil).Once()
	s.mockKafkaProducer.On("PublishCloudEvent", ctx, s.cfg.Kafka.Producer.Topic, eventModels.AuthUserEmailVerificationRequiredV1, userID.String(), mock.Anything).Return(nil).Once()
	s.mockAuditRecorder.On("RecordEvent", ctx, mock.Anything, "user_profile_updated_email_changed", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "", "").Once()


	err := s.handler.HandleAccountUserProfileUpdated(ctx, cloudEvent)
	assert.NoError(s.T(), err)
	s.mockUserRepo.AssertExpectations(s.T())
	s.mockVerificationRepo.AssertExpectations(s.T())
	s.mockKafkaProducer.AssertExpectations(s.T())
	s.mockAuditRecorder.AssertExpectations(s.T())
}

// TestHandleAccountUserProfileUpdated_StatusChangeToBlocked
func (s *AccountEventsHandlerTestSuite) TestHandleAccountUserProfileUpdated_StatusChangeToBlocked() {
	ctx := context.Background()
	userID := uuid.New()
	newStatus := string(models.UserStatusBlocked)
    statusReason := "policy_violation"

	payload := eventModels.AccountUserProfileUpdatedPayload{
		UserID:       userID.String(),
		NewStatus:    &newStatus,
        StatusReason: &statusReason,
	}
	payloadBytes, _ := json.Marshal(payload)
	cloudEvent := models.CloudEvent{
		Type:   eventModels.AccountUserProfileUpdatedV1,
		Source: "account-service",
		Data:   payloadBytes,
	}
    user := &models.User{ID: userID, Status: models.UserStatusActive}


	s.mockUserRepo.On("FindByID", ctx, userID).Return(user, nil).Once()
    s.mockUserRepo.On("UpdateStatus", ctx, userID, models.UserStatusBlocked).Return(nil).Once()
    s.mockUserRepo.On("UpdateStatusReason", ctx, userID, &statusReason).Return(nil).Once()
	s.mockAuthLogicSvc.On("SystemLogoutAllUserSessions", ctx, userID, "account_blocked_by_event").Return(nil).Once()
    s.mockAuditRecorder.On("RecordEvent", ctx, mock.Anything, "user_profile_updated_status_changed", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "", "").Once()


	err := s.handler.HandleAccountUserProfileUpdated(ctx, cloudEvent)
	assert.NoError(s.T(), err)
    s.mockUserRepo.AssertExpectations(s.T())
	s.mockAuthLogicSvc.AssertExpectations(s.T())
    s.mockAuditRecorder.AssertExpectations(s.T())
}


// TestHandleAccountUserDeleted
func (s *AccountEventsHandlerTestSuite) TestHandleAccountUserDeleted() {
	ctx := context.Background()
	userID := uuid.New()

	payload := eventModels.AccountUserDeletedPayload{UserID: userID.String()}
	payloadBytes, _ := json.Marshal(payload)
	cloudEvent := models.CloudEvent{
		Type:   eventModels.AccountUserDeletedV1,
		Source: "account-service",
		Data:   payloadBytes,
	}

	s.mockSessionRepo.On("DeleteAllByUserID", ctx, userID).Return(int64(1), nil).Once()
	s.mockRefreshRepo.On("RevokeAllByUserID", ctx, userID).Return(int64(1), nil).Once()
	s.mockMfaSecretRepo.On("DeleteAllForUser", ctx, userID).Return(int64(1), nil).Once()
	s.mockMfaBackupRepo.On("DeleteByUserID", ctx, userID).Return(int64(1), nil).Once()
	s.mockApiKeyRepo.On("RevokeAllByUserID", ctx, userID).Return(int64(1), nil).Once()
	s.mockExtAccRepo.On("DeleteAllByUserID", ctx, userID).Return(int64(1), nil).Once()
	s.mockVerificationRepo.On("DeleteByUserID", ctx, userID).Return(int64(1), nil).Once()
	s.mockUserRepo.On("Delete", ctx, userID).Return(nil).Once() // Soft delete
    s.mockAuditRecorder.On("RecordEvent", ctx, mock.Anything, "user_deleted_event_processed", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "", "").Once()


	err := s.handler.HandleAccountUserDeleted(ctx, cloudEvent)
	assert.NoError(s.T(), err)
    s.mockSessionRepo.AssertExpectations(s.T())
    s.mockRefreshRepo.AssertExpectations(s.T())
    // ... assert other delete calls
	s.mockUserRepo.AssertExpectations(s.T())
    s.mockAuditRecorder.AssertExpectations(s.T())
}
