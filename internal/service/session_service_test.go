package service

import (
	"context"
	"errors"
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

// --- Mocks (subset of AuthService mocks, plus RefreshTokenRepository) ---

type MockSessionRepository struct {
	mock.Mock
}

func (m *MockSessionRepository) Create(ctx context.Context, session *models.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}
func (m *MockSessionRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Session), args.Error(1)
}
func (m *MockSessionRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Session), args.Error(1)
}
func (m *MockSessionRepository) Update(ctx context.Context, session *models.Session) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}
func (m *MockSessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}
func (m *MockSessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID, excludeSessionID *uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID, excludeSessionID)
    return args.Get(0).(int64), args.Error(1)
}
func (m *MockSessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
    args := m.Called(ctx)
    return args.Get(0).(int64), args.Error(1) // Return type is int64 for count
}


type MockUserRepositoryForSessionTests struct {
	mock.Mock
}
func (m *MockUserRepositoryForSessionTests) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}


type MockRefreshTokenRepositoryForSessionTests struct {
	mock.Mock
}
func (m *MockRefreshTokenRepositoryForSessionTests) RevokeBySessionID(ctx context.Context, sessionID uuid.UUID) (int64, error) {
	args := m.Called(ctx, sessionID)
	return int64(args.Int(0)), args.Error(1)
}
func (m *MockRefreshTokenRepositoryForSessionTests) RevokeAllForUser(ctx context.Context, userID uuid.UUID, excludeSessionID *uuid.UUID) (int64, error) {
    args := m.Called(ctx, userID, excludeSessionID)
    return int64(args.Int(0)), args.Error(1)
}


type MockTokenManagementServiceForSessionTests struct {
	mock.Mock
}
func (m *MockTokenManagementServiceForSessionTests) GetRefreshTokenExpiry() time.Time {
	args := m.Called()
	return args.Get(0).(time.Time)
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

type MockAuditLogRecorder struct {
	mock.Mock
}
func (m *MockAuditLogRecorder) RecordEvent(ctx context.Context, actorID *uuid.UUID, action string, status models.AuditLogStatus, targetID interface{}, targetType models.AuditTargetType, details map[string]interface{}, ipAddress string, userAgent string) {
	m.Called(ctx, actorID, action, status, targetID, targetType, details, ipAddress, userAgent)
}


// --- Test Suite Setup ---

type SessionServiceTestSuite struct {
	service         domainService.SessionManager
	mockSessionRepo *MockSessionRepository
	mockUserRepo    *MockUserRepositoryForSessionTests
	mockRefreshRepo *MockRefreshTokenRepositoryForSessionTests
	mockTokenMgmtSvc *MockTokenManagementServiceForSessionTests
	mockKafka       *MockKafkaProducer
	testConfig      *config.Config
}

func setupSessionServiceTestSuite(t *testing.T) *SessionServiceTestSuite {
	ts := &SessionServiceTestSuite{}
	ts.mockSessionRepo = new(MockSessionRepository)
	ts.mockUserRepo = new(MockUserRepositoryForSessionTests)
	ts.mockRefreshRepo = new(MockRefreshTokenRepositoryForSessionTests)
	ts.mockTokenMgmtSvc = new(MockTokenManagementServiceForSessionTests)
	ts.mockKafka = new(MockKafkaProducer)

	ts.testConfig = &config.Config{
		RefreshToken: config.RefreshTokenRotationConfig{
			TTL: time.Hour * 24 * 7,
		},
		Kafka: config.KafkaConfig{Producer: config.KafkaProducerConfig{Topic: "auth-events"}},
	}

	ts.service = NewSessionService(
		ts.mockSessionRepo,
		ts.mockUserRepo,
		ts.mockKafka,
		zap.NewNop(),
		ts.mockTokenMgmtSvc,
	)
	return ts
}

// --- Test NewSessionService ---
func TestNewSessionService_Success(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	assert.NotNil(t, ts.service)
}


// --- Test SessionService.CreateSession ---
// ... (CreateSession tests remain here) ...
func TestSessionService_CreateSession_Success(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	userAgent := "test-agent"
	ipAddress := "127.0.0.1"

	refreshTokenExpiryTime := time.Now().Add(ts.testConfig.RefreshToken.TTL)
	ts.mockTokenMgmtSvc.On("GetRefreshTokenExpiry").Return(refreshTokenExpiryTime).Once()

	var capturedSession *models.Session
	ts.mockSessionRepo.On("Create", ctx, mock.MatchedBy(func(sess *models.Session) bool {
		capturedSession = sess
		return sess.UserID == userID && sess.UserAgent == userAgent && sess.IPAddress == ipAddress
	})).Return(nil).Once()

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic,
		eventModels.AuthSessionCreatedV1, userID.String(), mock.AnythingOfType("models.SessionCreatedPayload")).Return(nil).Once()

	session, err := ts.service.CreateSession(ctx, userID, userAgent, ipAddress)

	assert.NoError(t, err)
	assert.NotNil(t, session)
	require.NotNil(t, capturedSession, "Session should have been captured by mock")

	assert.Equal(t, userID, session.UserID)
	assert.Equal(t, userAgent, session.UserAgent)
	assert.Equal(t, ipAddress, session.IPAddress)
	assert.True(t, session.IsActive)
	assert.WithinDuration(t, refreshTokenExpiryTime, session.ExpiresAt, time.Second*5, "Session Expiry time mismatch")

	ts.mockTokenMgmtSvc.AssertExpectations(t)
	ts.mockSessionRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
}

func TestSessionService_CreateSession_Failure_RepoCreateFails(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	userAgent := "test-agent"
	ipAddress := "127.0.0.1"
	dbError := errors.New("database create error")

	refreshTokenExpiryTime := time.Now().Add(ts.testConfig.RefreshToken.TTL)
	ts.mockTokenMgmtSvc.On("GetRefreshTokenExpiry").Return(refreshTokenExpiryTime).Once()

	ts.mockSessionRepo.On("Create", ctx, mock.AnythingOfType("*models.Session")).Return(dbError).Once()

	session, err := ts.service.CreateSession(ctx, userID, userAgent, ipAddress)

	assert.ErrorIs(t, err, dbError)
	assert.Nil(t, session)

	ts.mockTokenMgmtSvc.AssertExpectations(t)
	ts.mockSessionRepo.AssertExpectations(t)
	ts.mockKafka.AssertNotCalled(t, "PublishCloudEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}


// --- Test SessionService.FindByID ---
func TestSessionService_FindByID_Success(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	sessionID := uuid.New()
	expectedSession := &models.Session{ID: sessionID, UserID: uuid.New(), IsActive: true}

	ts.mockSessionRepo.On("FindByID", ctx, sessionID).Return(expectedSession, nil).Once()

	session, err := ts.service.FindByID(ctx, sessionID)

	assert.NoError(t, err)
	assert.Equal(t, expectedSession, session)
	ts.mockSessionRepo.AssertExpectations(t)
}

func TestSessionService_FindByID_Failure_NotFound(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	sessionID := uuid.New()

	ts.mockSessionRepo.On("FindByID", ctx, sessionID).Return(nil, domainErrors.ErrNotFound).Once()

	session, err := ts.service.FindByID(ctx, sessionID)

	assert.ErrorIs(t, err, domainErrors.ErrNotFound)
	assert.Nil(t, session)
	ts.mockSessionRepo.AssertExpectations(t)
}

// --- Test SessionService.FindUserSessions ---
func TestSessionService_FindUserSessions_Success(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	expectedSessions := []*models.Session{
		{ID: uuid.New(), UserID: userID, IsActive: true},
		{ID: uuid.New(), UserID: userID, IsActive: false},
	}

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&models.User{ID: userID}, nil).Once()
	ts.mockSessionRepo.On("FindByUserID", ctx, userID).Return(expectedSessions, nil).Once()

	sessions, err := ts.service.FindUserSessions(ctx, userID)

	assert.NoError(t, err)
	assert.Equal(t, expectedSessions, sessions)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockSessionRepo.AssertExpectations(t)
}

func TestSessionService_FindUserSessions_Failure_UserNotFound(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(nil, domainErrors.ErrUserNotFound).Once()

	sessions, err := ts.service.FindUserSessions(ctx, userID)

	assert.ErrorIs(t, err, domainErrors.ErrUserNotFound)
	assert.Nil(t, sessions)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockSessionRepo.AssertNotCalled(t, "FindByUserID", mock.Anything, mock.Anything)
}

func TestSessionService_FindUserSessions_Failure_RepoError(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	repoError := errors.New("repo FindByUserID error")

	ts.mockUserRepo.On("FindByID", ctx, userID).Return(&models.User{ID: userID}, nil).Once()
	ts.mockSessionRepo.On("FindByUserID", ctx, userID).Return(nil, repoError).Once()

	sessions, err := ts.service.FindUserSessions(ctx, userID)

	assert.ErrorIs(t, err, repoError)
	assert.Nil(t, sessions)
	ts.mockUserRepo.AssertExpectations(t)
	ts.mockSessionRepo.AssertExpectations(t)
}

// --- Test SessionService.DeactivateSession ---
func TestSessionService_DeactivateSession_Success(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()

	activeSession := &models.Session{ID: sessionID, UserID: userID, IsActive: true, ExpiresAt: time.Now().Add(time.Hour)}
	ts.mockSessionRepo.On("FindByID", ctx, sessionID).Return(activeSession, nil).Once()
	ts.mockSessionRepo.On("Delete", ctx, sessionID).Return(nil).Once() // Delete should mark inactive

	ts.mockKafka.On("PublishCloudEvent", ctx, ts.testConfig.Kafka.Producer.Topic,
		eventModels.AuthSessionRevokedV1, sessionID.String(),
		mock.MatchedBy(func(payload models.SessionRevokedPayload) bool {
			return payload.SessionID == sessionID.String() &&
				   payload.UserID == userID.String() &&
				   payload.ActorID != nil && *payload.ActorID == userID.String()
		})).Return(nil).Once()

	err := ts.service.DeactivateSession(ctx, sessionID, &userID) // Assuming actorID is userID for self-deactivation

	assert.NoError(t, err)
	ts.mockSessionRepo.AssertExpectations(t)
	ts.mockKafka.AssertExpectations(t)
}

func TestSessionService_DeactivateSession_Failure_NotFound(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	sessionID := uuid.New()
	actorID := uuid.New()

	ts.mockSessionRepo.On("FindByID", ctx, sessionID).Return(nil, domainErrors.ErrNotFound).Once()

	err := ts.service.DeactivateSession(ctx, sessionID, &actorID)

	assert.ErrorIs(t, err, domainErrors.ErrNotFound)
	ts.mockSessionRepo.AssertExpectations(t)
	ts.mockKafka.AssertNotCalled(t, "PublishCloudEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestSessionService_DeactivateSession_Failure_RepoDeleteFails(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	sessionID := uuid.New()
	userID := uuid.New()
	actorID := userID
	dbError := errors.New("db delete error")

	activeSession := &models.Session{ID: sessionID, UserID: userID, IsActive: true, ExpiresAt: time.Now().Add(time.Hour)}
	ts.mockSessionRepo.On("FindByID", ctx, sessionID).Return(activeSession, nil).Once()
	ts.mockSessionRepo.On("Delete", ctx, sessionID).Return(dbError).Once()

	err := ts.service.DeactivateSession(ctx, sessionID, &actorID)

	assert.ErrorIs(t, err, dbError)
	ts.mockSessionRepo.AssertExpectations(t)
	ts.mockKafka.AssertNotCalled(t, "PublishCloudEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// --- Test SessionService.DeleteAllUserSessions ---
func TestSessionService_DeleteAllUserSessions_Success(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	excludeSessionID := uuid.New()

	deletedCount := int64(3)
	ts.mockSessionRepo.On("DeleteByUserID", ctx, userID, &excludeSessionID).Return(deletedCount, nil).Once()

	// Note: Kafka events for individual session revocations due to DeleteAllUserSessions
	// are typically handled by the orchestrating service (e.g., AuthService) after this call,
	// or SessionService would need to fetch all session IDs before deleting to publish events.
	// Current SessionService does not do this.

	count, err := ts.service.DeleteAllUserSessions(ctx, userID, &excludeSessionID)

	assert.NoError(t, err)
	assert.Equal(t, deletedCount, count)
	ts.mockSessionRepo.AssertExpectations(t)
	ts.mockKafka.AssertNotCalled(t, "PublishCloudEvent")
}

func TestSessionService_DeleteAllUserSessions_Failure_RepoError(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	userID := uuid.New()
	dbError := errors.New("repo DeleteByUserID error")

	ts.mockSessionRepo.On("DeleteByUserID", ctx, userID, (*uuid.UUID)(nil)).Return(int64(0), dbError).Once()

	count, err := ts.service.DeleteAllUserSessions(ctx, userID, nil)

	assert.ErrorIs(t, err, dbError)
	assert.Equal(t, int64(0), count)
	ts.mockSessionRepo.AssertExpectations(t)
}

// --- Test SessionService.CleanupExpiredSessions ---
func TestSessionService_CleanupExpiredSessions_Success(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	expectedDeletedCount := int64(5)

	ts.mockSessionRepo.On("DeleteExpired", ctx).Return(expectedDeletedCount, nil).Once()
	// TODO: Add mock for RefreshTokenRepository.DeleteForExpiredSessions if that logic is added to service.
	// For now, SessionService.CleanupExpiredSessions only calls sessionRepo.DeleteExpired.
	// Kafka events for these bulk revocations would also typically be handled by an orchestrator or not at all for cleanup.

	deletedCount, err := ts.service.CleanupExpiredSessions(ctx)
	assert.NoError(t, err)
	assert.Equal(t, expectedDeletedCount, deletedCount)
	ts.mockSessionRepo.AssertExpectations(t)
}

func TestSessionService_CleanupExpiredSessions_Failure_RepoError(t *testing.T) {
	ts := setupSessionServiceTestSuite(t)
	ctx := context.Background()
	repoError := errors.New("repo DeleteExpired error")

	ts.mockSessionRepo.On("DeleteExpired", ctx).Return(int64(0), repoError).Once()

	deletedCount, err := ts.service.CleanupExpiredSessions(ctx)
	assert.ErrorIs(t, err, repoError)
	assert.Equal(t, int64(0), deletedCount)
	ts.mockSessionRepo.AssertExpectations(t)
}


func init() {
	// Setup global test settings if needed
}
