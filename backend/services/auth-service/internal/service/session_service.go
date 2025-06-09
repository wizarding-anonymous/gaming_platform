// File: internal/service/session_service.go

package service

import (
	"context"
	"time"

	"errors" // Added for errors.Is
	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors" // For domainErrors.ErrSessionNotFound
	"github.com/your-org/auth-service/internal/repository/interfaces"
	// "github.com/your-org/auth-service/internal/utils/kafka" // To be replaced
	eventskafka "github.com/your-org/auth-service/internal/events/kafka" // Sarama-based producer
	domainService "github.com/your-org/auth-service/internal/domain/service" // Added for TokenManagementService
	"go.uber.org/zap"
)

// SessionService предоставляет методы для работы с сессиями пользователей
type SessionService struct {
	sessionRepo      interfaces.SessionRepository
	userRepo         interfaces.UserRepository // To verify user exists before creating session
	kafkaClient      *eventskafka.Producer     // Changed to Sarama-based producer
	logger           *zap.Logger
	tokenMgmtService domainService.TokenManagementService // Added
}

// NewSessionService создает новый экземпляр SessionService
func NewSessionService(
	sessionRepo interfaces.SessionRepository,
	userRepo interfaces.UserRepository,
	kafkaClient *eventskafka.Producer, // Changed to Sarama-based producer
	logger *zap.Logger,
	tokenMgmtService domainService.TokenManagementService, // Added
) *SessionService {
	return &SessionService{
		sessionRepo:      sessionRepo,
		userRepo:         userRepo,
		kafkaClient:      kafkaClient, // Assign Sarama-based producer
		logger:           logger,
		tokenMgmtService: tokenMgmtService, // Added
	}
}

// CreateSession создает новую сессию пользователя
// UserAgent and IPAddress are now pointers in models.Session, pass accordingly.
// DeviceInfo also needs to be handled if collected.
func (s *SessionService) CreateSession(ctx context.Context, userID uuid.UUID, userAgent string, ipAddress string /* deviceInfo json.RawMessage */) (*models.Session, error) {
	// Проверка существования пользователя (userRepo.FindByID now)
	_, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for session creation", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, models.ErrUserNotFound
	}

	now := time.Now()
	// Создание сессии
	session := &models.Session{
		ID:             uuid.New(),
		UserID:         userID,
		UserAgent:      &userAgent, // Assuming conversion to pointer
		IPAddress:      &ipAddress, // Assuming conversion to pointer
		// DeviceInfo:  deviceInfo, // Pass if available
		CreatedAt:      now, // Will be set by DB default if not provided by repo.Create
		LastActivityAt: now, // Initialize LastActivityAt
		ExpiresAt:      now.Add(s.tokenMgmtService.GetRefreshTokenExpiry()), // Use TokenManagementService for expiry
	}

	// Сохранение сессии (sessionRepo.Create now takes *models.Session and returns error)
	err = s.sessionRepo.Create(ctx, session)
	if err != nil {
		s.logger.Error("Failed to create session", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	// Отправка события о создании сессии
	event := models.SessionCreatedEvent{
		SessionID: session.ID.String(),
		UserID:    userID.String(),
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: session.CreatedAt, // This should be a time.Time type for CloudEvent payload
	}
	// Assuming SessionCreatedEvent is suitable as a CloudEvent data payload.
	// The actual CloudEvent payload for "auth.session.created.v1" might be models.SessionCreatedPayload.
	// For now, using the existing 'event' struct as dataPayload.
	// Topic needs to be from config or a central place. Using "auth-events" as placeholder.
	subjectSessionCreated := session.ID.String()
	contentTypeJSON := "application/json"
	if errPub := s.kafkaClient.PublishCloudEvent(
		ctx,
		"auth-events", // Replace with actual topic from cfg
		eventskafka.EventType(models.AuthSessionCreatedV1), // Use actual CloudEvent type constant
		&subjectSessionCreated,
		&contentTypeJSON,
		event, // This is models.SessionCreatedEvent
	); errPub != nil {
		s.logger.Error("Failed to publish session created CloudEvent", zap.Error(errPub), zap.String("session_id", session.ID.String()))
	}

	return session, nil
}

// GetSession получает сессию по ID
func (s *SessionService) GetSession(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) {
	// sessionRepo.GetByID now returns (*models.Session, error)
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		s.logger.Error("Failed to get session", zap.Error(err), zap.String("session_id", sessionID.String()))
		return nil, err
	}
	return session, nil
}

// GetUserSessions получает все сессии пользователя
func (s *SessionService) GetUserSessions(ctx context.Context, userID uuid.UUID, params models.ListSessionsParams) ([]*models.Session, int, error) {
	// Проверка существования пользователя (userRepo.FindByID now)
	_, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for sessions retrieval", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, 0, models.ErrUserNotFound
	}

	// Получение сессий (sessionRepo.GetUserSessions now)
	sessions, total, err := s.sessionRepo.GetUserSessions(ctx, userID, params)
	if err != nil {
		s.logger.Error("Failed to get user sessions", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}
	return sessions, nil
}

// GetActiveUserSessions получает активные сессии пользователя
func (s *SessionService) GetActiveUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	// Проверка существования пользователя
	_, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for active sessions retrieval", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, 0, models.ErrUserNotFound
	}

	// Получение активных сессий
	// sessionRepo.GetUserSessions handles filtering by activeOnly via ListSessionsParams
	params := models.ListSessionsParams{ActiveOnly: true, PageSize: 0} // PageSize 0 to get all matching
	sessions, _, err := s.sessionRepo.GetUserSessions(ctx, userID, params)
	if err != nil {
		s.logger.Error("Failed to get active user sessions", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}
	return sessions, nil
}

// DeactivateSession деактивирует сессию
func (s *SessionService) DeactivateSession(ctx context.Context, sessionID uuid.UUID) error {
	// Получение сессии
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		s.logger.Error("Failed to get session for deactivation", zap.Error(err), zap.String("session_id", sessionID.String()))
		return err
	}

	err = s.sessionRepo.Delete(ctx, sessionID)
	if err != nil {
		// If already not found by Delete, consider it success for deactivation.
		if errors.Is(err, domainErrors.ErrSessionNotFound) || errors.Is(err, domainErrors.ErrNotFound) {
			s.logger.Info("Session already deleted during deactivation attempt.", zap.String("session_id", sessionID.String()))
			return nil
		}
		s.logger.Error("Failed to delete session during deactivation", zap.Error(err), zap.String("session_id", sessionID.String()))
		return err
	}

	// Отправка события о деактивации/удалении сессии
	// Ensure models.SessionDeactivatedEvent is defined or use a generic SessionDeletedEvent
	event := models.SessionDeactivatedEvent{ // Or SessionDeletedEvent
		SessionID:    sessionID.String(), // Use sessionID from param as 'session' might be from before delete
		UserID:       session.UserID.String(), // UserID from fetched session
		DeactivatedAt: time.Now(), // This should be a time.Time type
	}
	// Assuming SessionDeactivatedEvent is suitable as a CloudEvent data payload.
	// The actual CloudEvent payload for "auth.session.revoked.v1" (as deactivation is a form of revocation)
	// might be models.SessionRevokedPayload.
	// For now, using the existing 'event' struct as dataPayload.
	subjectSessionDeactivated := sessionID.String()
	contentTypeJSON := "application/json"
	if errPub := s.kafkaClient.PublishCloudEvent(
		ctx,
		"auth-events", // Replace with actual topic from cfg
		eventskafka.EventType(models.AuthSessionRevokedV1), // Assuming deactivation maps to Revoked event
		&subjectSessionDeactivated,
		&contentTypeJSON,
		event, // This is models.SessionDeactivatedEvent
	); errPub != nil {
		s.logger.Error("Failed to publish session deactivated CloudEvent", zap.Error(errPub), zap.String("session_id", sessionID.String()))
	}

	return nil
}

// DeactivateAllUserSessions деактивирует все сессии пользователя
func (s *SessionService) DeactivateAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	// Проверка существования пользователя
	_, err := s.userRepo.FindByID(ctx, userID) // userRepo.FindByID now
	if err != nil {
		s.logger.Error("Failed to get user for sessions deactivation/deletion", zap.Error(err), zap.String("user_id", userID.String()))
		return models.ErrUserNotFound
	}

	// Деактивация (удаление) всех сессий
	// SessionRepository now has DeleteAllUserSessions(ctx, userID, exceptSessionID *uuid.UUID) (int64, error)
	deletedCount, err := s.sessionRepo.DeleteAllUserSessions(ctx, userID, nil) // No session to exclude
	if err != nil {
		s.logger.Error("Failed to delete all user sessions", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}
	s.logger.Info("Deleted all sessions for user", zap.String("user_id", userID.String()), zap.Int64("count", deletedCount))


	// Отправка события о деактивации (удалении) всех сессий
	// Ensure models.AllSessionsDeactivatedEvent is defined
	event := models.AllSessionsDeactivatedEvent{ // Or AllSessionsDeletedEvent
		UserID:       userID.String(),
		DeactivatedAt: time.Now(), // Or DeletedAt, should be time.Time
	}
	// Assuming AllSessionsDeactivatedEvent is suitable as a CloudEvent data payload.
	// The actual CloudEvent payload for "auth.user.all_sessions_revoked.v1"
	// might be models.UserAllSessionsRevokedPayload.
	// For now, using the existing 'event' struct as dataPayload.
	subjectAllSessionsDeactivated := userID.String()
	contentTypeJSON := "application/json"
	if errPub := s.kafkaClient.PublishCloudEvent(
		ctx,
		"auth-events", // Replace with actual topic from cfg
		eventskafka.EventType(models.AuthUserAllSessionsRevokedV1), // Assuming this event type
		&subjectAllSessionsDeactivated,
		&contentTypeJSON,
		event, // This is models.AllSessionsDeactivatedEvent
	); errPub != nil {
		s.logger.Error("Failed to publish all sessions deactivated CloudEvent", zap.Error(errPub), zap.String("user_id", userID.String()))
	}

	return nil
}

// CleanupExpiredSessions удаляет истекшие сессии
func (s *SessionService) CleanupExpiredSessions(ctx context.Context) error {
	// Удаление истекших сессий
	// sessionRepo.DeleteExpiredSessions now
	count, err := s.sessionRepo.DeleteExpiredSessions(ctx)
	if err != nil {
		s.logger.Error("Failed to delete expired sessions", zap.Error(err))
		return err
	}

	s.logger.Info("Expired sessions cleanup completed", zap.Int("deleted_count", count))
	return nil
}
