package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	eventModels "github.com/your-org/auth-service/internal/events/models"
	kafkaPkg "github.com/your-org/auth-service/internal/events/kafka"
	repoInterfaces "github.com/your-org/auth-service/internal/repository/interfaces"
	appSecurity "github.com/your-org/auth-service/internal/infrastructure/security"
	"go.uber.org/zap"
)

// --- Mocks ---

type MockUserRepositoryForAccountHandler struct {
	mock.Mock
}
func (m *MockUserRepositoryForAccountHandler) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *MockUserRepositoryForAccountHandler) UpdateEmail(ctx context.Context, id uuid.UUID, newEmail string) error {
	args := m.Called(ctx, id, newEmail)
	return args.Error(0)
}
func (m *MockUserRepositoryForAccountHandler) SetEmailVerifiedAt(ctx context.Context, id uuid.UUID, verifiedAt *time.Time) error {
	args := m.Called(ctx, id, verifiedAt)
	return args.Error(0)
}
func (m *MockUserRepositoryForAccountHandler) UpdateStatus(ctx context.Context, id uuid.UUID, status models.UserStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}
func (m *MockUserRepositoryForAccountHandler) Update(ctx context.Context, user *models.User) error {
    args := m.Called(ctx, user)
    return args.Error(0)
}
func (m *MockUserRepositoryForAccountHandler) Delete(ctx context.Context, id uuid.UUID) error { // For soft delete
    args := m.Called(ctx, id)
    return args.Error(0)
}


type MockVerificationCodeRepositoryForAccountHandler struct {
	mock.Mock
}
func (m *MockVerificationCodeRepositoryForAccountHandler) Create(ctx context.Context, vc *models.VerificationCode) error {
	args := m.Called(ctx, vc)
	return args.Error(0)
}
func (m *MockVerificationCodeRepositoryForAccountHandler) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}


type MockAuthLogicServiceForAccountHandler struct {
	mock.Mock
}
func (m *MockAuthLogicServiceForAccountHandler) SystemLogoutAllUserSessions(ctx context.Context, userID uuid.UUID, actorID string, reason string) error {
	args := m.Called(ctx, userID, actorID, reason)
	return args.Error(0)
}


type MockKafkaProducerForAccountHandler struct {
	mock.Mock
}
func (m *MockKafkaProducerForAccountHandler) PublishCloudEvent(ctx context.Context, topic string, eventType eventModels.EventType, subject string, dataPayload interface{}) error {
	args := m.Called(ctx, topic, eventType, subject, dataPayload)
	return args.Error(0)
}

type MockSessionRepositoryForAccountHandler struct { // Added for user deletion
    mock.Mock
}
func (m *MockSessionRepositoryForAccountHandler) DeleteAllUserSessions(ctx context.Context, userID uuid.UUID, excludeSessionID *uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID, excludeSessionID)
    return args.Get(0).(int64), args.Error(1)
}

type MockRefreshTokenRepositoryForAccountHandler struct { // Added for user deletion
    mock.Mock
}
func (m *MockRefreshTokenRepositoryForAccountHandler) RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) { // Simplified signature for test
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

type MockMFASecretRepositoryForAccountHandler struct { // Added for user deletion
    mock.Mock
}
func (m *MockMFASecretRepositoryForAccountHandler) DeleteAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

type MockMFABackupCodeRepositoryForAccountHandler struct { // Added for user deletion
    mock.Mock
}
func (m *MockMFABackupCodeRepositoryForAccountHandler) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

type MockAPIKeyRepositoryForAccountHandler struct { // Added for user deletion
    mock.Mock
}
func (m *MockAPIKeyRepositoryForAccountHandler) RevokeAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) { // Assuming this method exists
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

type MockExternalAccountRepositoryForAccountHandler struct { // Added for user deletion
    mock.Mock
}
func (m *MockExternalAccountRepositoryForAccountHandler) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID)
    return args.Get(0).(int64), args.Error(1)
}

type MockAuditLogRecorderForAccountHandler struct { // Added for user deletion
	mock.Mock
}
func (m *MockAuditLogRecorderForAccountHandler) RecordEvent(ctx context.Context, actorID *uuid.UUID, action string, status models.AuditLogStatus, targetID interface{}, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	m.Called(ctx, actorID, action, status, targetID, targetType, details, ipAddress, userAgent)
}


// --- Test Suite Setup ---
type AccountEventsHandlerTestSuite struct {
	handler                *AccountEventsHandler
	mockUserRepo           *MockUserRepositoryForAccountHandler
	mockVcRepo             *MockVerificationCodeRepositoryForAccountHandler
	mockAuthService        *MockAuthLogicServiceForAccountHandler
	mockKafkaProducer      *MockKafkaProducerForAccountHandler
	mockSessionRepo        *MockSessionRepositoryForAccountHandler
	mockRefreshTokenRepo   *MockRefreshTokenRepositoryForAccountHandler
	mockMfaSecretRepo      *MockMFASecretRepositoryForAccountHandler
	mockMfaBackupCodeRepo  *MockMFABackupCodeRepositoryForAccountHandler
	mockApiKeyRepo         *MockAPIKeyRepositoryForAccountHandler
	mockExternalAccountRepo*MockExternalAccountRepositoryForAccountHandler
	mockAuditLogRecorder   *MockAuditLogRecorderForAccountHandler
	testConfig             *config.Config
	logger                 *zap.Logger
}

func setupAccountEventsHandlerTestSuite(t *testing.T) *AccountEventsHandlerTestSuite {
	ts := &AccountEventsHandlerTestSuite{}
	ts.logger = zap.NewNop()
	ts.mockUserRepo = new(MockUserRepositoryForAccountHandler)
	ts.mockVcRepo = new(MockVerificationCodeRepositoryForAccountHandler)
	ts.mockAuthService = new(MockAuthLogicServiceForAccountHandler)
	ts.mockKafkaProducer = new(MockKafkaProducerForAccountHandler)
	ts.mockSessionRepo = new(MockSessionRepositoryForAccountHandler)
	ts.mockRefreshTokenRepo = new(MockRefreshTokenRepositoryForAccountHandler)
	ts.mockMfaSecretRepo = new(MockMFASecretRepositoryForAccountHandler)
	ts.mockMfaBackupCodeRepo = new(MockMFABackupCodeRepositoryForAccountHandler)
	ts.mockApiKeyRepo = new(MockAPIKeyRepositoryForAccountHandler)
	ts.mockExternalAccountRepo = new(MockExternalAccountRepositoryForAccountHandler)
	ts.mockAuditLogRecorder = new(MockAuditLogRecorderForAccountHandler)


	ts.testConfig = &config.Config{
		JWT: config.JWTConfig{
			EmailVerificationToken: config.TokenConfig{ExpiresIn: time.Minute * 30},
		},
		Kafka: config.KafkaConfig{
			Producer: config.KafkaProducerConfig{Topic: "auth-events"},
		},
	}

	ts.handler = NewAccountEventsHandler(
		ts.logger,
		ts.testConfig,
		ts.mockUserRepo,
		ts.mockVcRepo,
		ts.mockAuthService,
		ts.mockKafkaProducer,
		ts.mockSessionRepo,
		ts.mockRefreshTokenRepo,
		ts.mockMfaSecretRepo,
		ts.mockMfaBackupCodeRepo,
		ts.mockApiKeyRepo,
		ts.mockExternalAccountRepo,
		ts.mockAuditLogRecorder,
	)
	require.NotNil(t, ts.handler)
	return ts
}

// --- Test HandleAccountUserProfileUpdated ---
// ... (HandleAccountUserProfileUpdated tests remain here) ...
func TestAccountEventsHandler_HandleAccountUserProfileUpdated_EmailChange(t *testing.T) {
	ts := setupAccountEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	oldEmail := "old@example.com"
	newEmail := "new@example.com"

	payload := AccountUserProfileUpdatedPayload{
		UserID:        userID.String(),
		UpdatedFields: []string{"email"},
		NewValues:     map[string]interface{}{"email": newEmail},
	}
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{
		ID:              uuid.NewString(),
		Source:          "/account-service",
		Type:            "com.yourplatform.account.user.profile_updated.v1",
		DataContentType: eventModels.CloudEventDataContentType,
		Time:            time.Now(),
		Data:            payloadBytes,
		Subject:         userID.String(),
	}

	mockUser := &models.User{ID: userID, Email: oldEmail, Status: models.UserStatusActive, EmailVerifiedAt: func() *time.Time { t := time.Now(); return &t }()}

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(mockUser, nil).Once()
	ts.mockUserRepo.On("UpdateEmail", ctx, userID, newEmail).Return(nil).Once()
	ts.mockUserRepo.On("SetEmailVerifiedAt", ctx, userID, (*time.Time)(nil)).Return(nil).Once()
	ts.mockUserRepo.On("UpdateStatus", ctx, userID, models.UserStatusPendingVerification).Return(nil).Once()
	ts.mockVcRepo.On("Create", ctx, mock.AnythingOfType("*models.VerificationCode")).Return(nil).Once()
	ts.mockKafkaProducer.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserEmailVerificationRequiredV1, userID.String(), mock.AnythingOfType("eventModels.UserEmailVerificationRequiredPayload")).Return(nil).Once()

	err := ts.handler.HandleAccountUserProfileUpdated(ctx, event)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockVcRepo.AssertExpectations(t)
	ts.mockKafkaProducer.AssertExpectations(t)
}

func TestAccountEventsHandler_HandleAccountUserProfileUpdated_StatusBlocked(t *testing.T) {
	ts := setupAccountEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()

	payload := AccountUserProfileUpdatedPayload{
		UserID:        userID.String(),
		UpdatedFields: []string{"status"},
		NewValues:     map[string]interface{}{"status": "blocked"},
	}
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{ Data: payloadBytes, Subject: userID.String()}

	mockUser := &models.User{ID: userID, Email: "user@example.com", Status: models.UserStatusActive}
	ts.mockUserRepo.On("FindByID", ctx, userID).Return(mockUser, nil).Once()
	ts.mockAuthService.On("SystemLogoutAllUserSessions", ctx, userID, "system_account_profile_update", "Account status changed to blocked by external service").Return(nil).Once()
	ts.mockUserRepo.On("UpdateStatus", ctx, userID, models.UserStatusBlocked).Return(nil).Once()

	err := ts.handler.HandleAccountUserProfileUpdated(ctx, event)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockAuthService.AssertExpectations(t)
}

func TestAccountEventsHandler_HandleAccountUserProfileUpdated_NoRelevantFields(t *testing.T) {
	ts := setupAccountEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()

	payload := AccountUserProfileUpdatedPayload{
		UserID:        userID.String(),
		UpdatedFields: []string{"display_name"},
		NewValues:     map[string]interface{}{"display_name": "New Name"},
	}
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{Data: payloadBytes, Subject: userID.String()}

	mockUser := &models.User{ID: userID, Email: "user@example.com", Status: models.UserStatusActive}
	ts.mockUserRepo.On("FindByID", ctx, userID).Return(mockUser, nil).Once()

	err := ts.handler.HandleAccountUserProfileUpdated(ctx, event)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockUserRepo.AssertNotCalled(t, "UpdateEmail")
	ts.mockUserRepo.AssertNotCalled(t, "SetEmailVerifiedAt")
	ts.mockUserRepo.AssertNotCalled(t, "UpdateStatus")
	ts.mockAuthService.AssertNotCalled(t, "SystemLogoutAllUserSessions")
	ts.mockKafkaProducer.AssertNotCalled(t, "PublishCloudEvent")
}

// --- Test HandleAccountUserDeleted ---
func TestAccountEventsHandler_HandleAccountUserDeleted_Success(t *testing.T) {
	ts := setupAccountEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	deleterActorID := uuid.New().String() // Actor who initiated deletion in account service

	payload := AccountUserDeletedPayload{
		UserID:            userID.String(),
		DeletedBy:         deleterActorID,
		DeletionTimestamp: time.Now(),
	}
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{
		ID: uuid.NewString(), Source: "/account-service", Type: "com.yourplatform.account.user.deleted.v1",
		DataContentType: eventModels.CloudEventDataContentType, Time: time.Now(),
		Data: payloadBytes, Subject: userID.String(),
	}

	ts.mockSessionRepo.On("DeleteAllUserSessions", ctx, userID, (*uuid.UUID)(nil)).Return(int64(2), nil).Once()
	ts.mockRefreshTokenRepo.On("RevokeAllForUser", ctx, userID).Return(int64(2), nil).Once()
	ts.mockMfaSecretRepo.On("DeleteAllForUser", ctx, userID).Return(int64(1), nil).Once()
	ts.mockMfaBackupCodeRepo.On("DeleteByUserID", ctx, userID).Return(int64(5), nil).Once()
	ts.mockApiKeyRepo.On("RevokeAllForUser", ctx, userID).Return(int64(1), nil).Once()
	ts.mockExternalAccountRepo.On("DeleteByUserID", ctx, userID).Return(int64(1), nil).Once()
	ts.mockVcRepo.On("DeleteByUserID", ctx, userID).Return(int64(1), nil).Once()
	ts.mockUserRepo.On("Delete", ctx, userID).Return(nil).Once() // Soft delete

	var expectedActorIDForAudit *uuid.UUID
	parsedDeleterID, errParse := uuid.Parse(deleterActorID)
	if errParse == nil {
		expectedActorIDForAudit = &parsedDeleterID
	}
	ts.mockAuditLogRecorder.On("RecordEvent", ctx, expectedActorIDForAudit, "user_data_deleted_on_request",
		models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser,
		mock.Anything, "internal_event", "internal_event").Once()

	err := ts.handler.HandleAccountUserDeleted(ctx, event)
	assert.NoError(t, err)
	ts.mockSessionRepo.AssertExpectations(t)
	ts.mockRefreshTokenRepo.AssertExpectations(t)
	ts.mockMfaSecretRepo.AssertExpectations(t)
	ts.mockMfaBackupCodeRepo.AssertExpectations(t)
	ts.mockApiKeyRepo.AssertExpectations(t)
	ts.mockExternalAccountRepo.AssertExpectations(t)
	ts.mockVcRepo.AssertExpectations(t)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockAuditLogRecorder.AssertExpectations(t)
}

func TestAccountEventsHandler_HandleAccountUserDeleted_UserRepoDeleteFails(t *testing.T) {
	ts := setupAccountEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	deleterActorID := "system"
	repoError := errors.New("user repo delete failed")

	payload := AccountUserDeletedPayload{UserID: userID.String(), DeletedBy: deleterActorID}
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{Data: payloadBytes, Subject: userID.String()}

	// Mock all preceding deletions to succeed
	ts.mockSessionRepo.On("DeleteAllUserSessions", ctx, userID, (*uuid.UUID)(nil)).Return(int64(0), nil)
	ts.mockRefreshTokenRepo.On("RevokeAllForUser", ctx, userID).Return(int64(0), nil)
	ts.mockMfaSecretRepo.On("DeleteAllForUser", ctx, userID).Return(int64(0), nil)
	ts.mockMfaBackupCodeRepo.On("DeleteByUserID", ctx, userID).Return(int64(0), nil)
	ts.mockApiKeyRepo.On("RevokeAllForUser", ctx, userID).Return(int64(0), nil)
	ts.mockExternalAccountRepo.On("DeleteByUserID", ctx, userID).Return(int64(0), nil)
	ts.mockVcRepo.On("DeleteByUserID", ctx, userID).Return(int64(0), nil)

	ts.mockUserRepo.On("Delete", ctx, userID).Return(repoError).Once() // User delete fails

	var expectedActorIDForAudit *uuid.UUID // deleterActorID "system" won't parse to UUID
	ts.mockAuditLogRecorder.On("RecordEvent", ctx, expectedActorIDForAudit, "user_data_deleted_on_request",
		models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser,
		mock.Anything, "internal_event", "internal_event").Once()

	err := ts.handler.HandleAccountUserDeleted(ctx, event)
	assert.ErrorIs(t, err, repoError)
	// Assert that all repo deletion methods were still called
	ts.mockSessionRepo.AssertExpectations(t)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockAuditLogRecorder.AssertExpectations(t)
}
