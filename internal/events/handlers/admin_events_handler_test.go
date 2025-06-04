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
	"go.uber.org/zap"
)

// --- Mocks ---
// Reusing mock definitions from account_events_handler_test.go by convention
// (e.g. MockUserRepositoryForAccountHandler -> MockUserRepositoryForAdminHandler if needed for clarity,
// but typically can reuse if method signatures are the same for the interfaces)

type MockUserRepositoryForAdminHandler struct {
	mock.Mock
}
func (m *MockUserRepositoryForAdminHandler) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil { return nil, args.Error(1) }
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *MockUserRepositoryForAdminHandler) UpdateStatus(ctx context.Context, id uuid.UUID, status models.UserStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}
func (m *MockUserRepositoryForAdminHandler) Update(ctx context.Context, user *models.User) error { // For clearing status reason
    args := m.Called(ctx, user)
    return args.Error(0)
}


type MockAuthLogicServiceForAdminHandler struct {
	mock.Mock
}
func (m *MockAuthLogicServiceForAdminHandler) SystemLogoutAllUserSessions(ctx context.Context, userID uuid.UUID, actorID string, reason string) error {
	args := m.Called(ctx, userID, actorID, reason)
	return args.Error(0)
}

type MockKafkaProducerForAdminHandler struct {
	mock.Mock
}
func (m *MockKafkaProducerForAdminHandler) PublishCloudEvent(ctx context.Context, topic string, eventType eventModels.EventType, subject string, dataPayload interface{}) error {
	args := m.Called(ctx, topic, eventType, subject, dataPayload)
	return args.Error(0)
}

type MockAuditLogRecorderForAdminHandler struct {
	mock.Mock
}
func (m *MockAuditLogRecorderForAdminHandler) RecordEvent(ctx context.Context, actorID *uuid.UUID, action string, status models.AuditLogStatus, targetID interface{}, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	m.Called(ctx, actorID, action, status, targetID, targetType, details, ipAddress, userAgent)
}


// --- Test Suite Setup ---
type AdminEventsHandlerTestSuite struct {
	handler          *AdminEventsHandler
	mockUserRepo     *MockUserRepositoryForAdminHandler
	mockAuthService  *MockAuthLogicServiceForAdminHandler
	mockKafka        *MockKafkaProducerForAdminHandler
	mockAudit        *MockAuditLogRecorderForAdminHandler
	testConfig       *config.Config
	logger           *zap.Logger
}

func setupAdminEventsHandlerTestSuite(t *testing.T) *AdminEventsHandlerTestSuite {
	ts := &AdminEventsHandlerTestSuite{}
	ts.logger = zap.NewNop()
	ts.mockUserRepo = new(MockUserRepositoryForAdminHandler)
	ts.mockAuthService = new(MockAuthLogicServiceForAdminHandler)
	ts.mockKafka = new(MockKafkaProducerForAdminHandler)
	ts.mockAudit = new(MockAuditLogRecorderForAdminHandler)

	ts.testConfig = &config.Config{
		Kafka: config.KafkaConfig{
			Producer: config.KafkaProducerConfig{Topic: "auth-events"}, // Default topic for outgoing auth events
		},
	}

	ts.handler = NewAdminEventsHandler(
		ts.logger,
		ts.testConfig,
		ts.mockUserRepo,
		ts.mockAuthService,
		ts.mockKafka,
		ts.mockAudit,
	)
	require.NotNil(t, ts.handler)
	return ts
}

// --- Test HandleAdminUserForceLogout ---
func TestAdminEventsHandler_HandleAdminUserForceLogout_Success(t *testing.T) {
	ts := setupAdminEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	adminID := uuid.New()

	payload := AdminUserForceLogoutPayload{
		UserID:      userID.String(),
		AdminUserID: adminID.String(),
		Reason:      "Test force logout",
	}
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{Data: payloadBytes, Subject: userID.String()}

	ts.mockAuthService.On("SystemLogoutAllUserSessions", ctx, userID, payload.AdminUserID, payload.Reason).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminID, "admin_force_logout", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "internal_event", "internal_event").Once()

	err := ts.handler.HandleAdminUserForceLogout(ctx, event)
	assert.NoError(t, err)
	ts.mockAuthService.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAdminEventsHandler_HandleAdminUserForceLogout_AuthServiceFails(t *testing.T) {
	ts := setupAdminEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	adminID := uuid.New()
	serviceErr := errors.New("auth service error")

	payload := AdminUserForceLogoutPayload{ UserID: userID.String(), AdminUserID: adminID.String() }
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{Data: payloadBytes, Subject: userID.String()}

	ts.mockAuthService.On("SystemLogoutAllUserSessions", ctx, userID, payload.AdminUserID, payload.Reason).Return(serviceErr).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminID, "admin_force_logout", models.AuditLogStatusFailure, &userID, models.AuditTargetTypeUser, mock.Anything, "internal_event", "internal_event").Once()

	err := ts.handler.HandleAdminUserForceLogout(ctx, event)
	assert.ErrorIs(t, err, serviceErr)
	ts.mockAuthService.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}


// --- Test HandleAdminUserBlock ---
func TestAdminEventsHandler_HandleAdminUserBlock_Success(t *testing.T) {
	ts := setupAdminEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	adminID := uuid.New()
	reason := "Violation of terms"

	payload := AdminUserBlockPayload{UserID: userID.String(), AdminUserID: adminID.String(), Reason: reason}
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{Data: payloadBytes, Subject: userID.String()}

	// Mock FindByID first for the update sequence
	mockUser := &models.User{ID: userID, Status: models.UserStatusActive}
	ts.mockUserRepo.On("FindByID", ctx, userID).Return(mockUser, nil).Once()
	// Then mock the Update call (which includes status and reason if applicable)
	ts.mockUserRepo.On("Update", ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == userID && u.Status == models.UserStatusBlocked
		// && u.StatusReason == reason // If StatusReason field is used
	})).Return(nil).Once()
	// ts.mockUserRepo.On("UpdateStatus", ctx, userID, models.UserStatusBlocked).Return(nil).Once() // If direct status update

	ts.mockAuthService.On("SystemLogoutAllUserSessions", ctx, userID, payload.AdminUserID, payload.Reason).Return(nil).Once()
	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserAccountBlockedV1, userID.String(), mock.AnythingOfType("eventModels.UserAccountBlockedPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminID, "admin_user_block_received", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "internal_event", "internal_event").Once()

	err := ts.handler.HandleAdminUserBlock(ctx, event)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockAuthService.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

// --- Test HandleAdminUserUnblock ---
func TestAdminEventsHandler_HandleAdminUserUnblock_Success_WasVerified(t *testing.T) {
	ts := setupAdminEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	adminID := uuid.New()

	payload := AdminUserUnblockPayload{UserID: userID.String(), AdminUserID: adminID.String()}
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{Data: payloadBytes, Subject: userID.String()}

	verifiedTime := time.Now().Add(-time.Hour)
	mockUser := &models.User{ID: userID, Status: models.UserStatusBlocked, EmailVerifiedAt: &verifiedTime}

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(mockUser, nil).Once()
	ts.mockUserRepo.On("Update", ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == userID && u.Status == models.UserStatusActive
	})).Return(nil).Once()
	// ts.mockUserRepo.On("UpdateStatus", ctx, userID, models.UserStatusActive).Return(nil).Once()


	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserAccountUnblockedV1, userID.String(), mock.AnythingOfType("eventModels.UserAccountUnblockedPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminID, "admin_user_unblock_received", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "internal_event", "internal_event").Once()

	err := ts.handler.HandleAdminUserUnblock(ctx, event)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}

func TestAdminEventsHandler_HandleAdminUserUnblock_Success_WasNeverVerified(t *testing.T) {
	ts := setupAdminEventsHandlerTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	adminID := uuid.New()

	payload := AdminUserUnblockPayload{UserID: userID.String(), AdminUserID: adminID.String()}
	payloadBytes, _ := json.Marshal(payload)
	event := eventModels.CloudEvent{Data: payloadBytes, Subject: userID.String()}

	mockUser := &models.User{ID: userID, Status: models.UserStatusBlocked, EmailVerifiedAt: nil} // Never verified

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(mockUser, nil).Once()
	ts.mockUserRepo.On("Update", ctx, mock.MatchedBy(func(u *models.User) bool {
		return u.ID == userID && u.Status == models.UserStatusPendingVerification
	})).Return(nil).Once()
	// ts.mockUserRepo.On("UpdateStatus", ctx, userID, models.UserStatusPendingVerification).Return(nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic, eventModels.AuthUserAccountUnblockedV1, userID.String(), mock.AnythingOfType("eventModels.UserAccountUnblockedPayload")).Return(nil).Once()
	ts.mockAudit.On("RecordEvent", ctx, &adminID, "admin_user_unblock_received", models.AuditLogStatusSuccess, &userID, models.AuditTargetTypeUser, mock.Anything, "internal_event", "internal_event").Once()

	err := ts.handler.HandleAdminUserUnblock(ctx, event)
	assert.NoError(t, err)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
	ts.mockAudit.AssertExpectations(t)
}
