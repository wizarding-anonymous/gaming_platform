// File: internal/service/session_service.go

package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/repository/interfaces"
	"github.com/your-org/auth-service/internal/utils/kafka"
	"go.uber.org/zap"
)

// SessionService предоставляет методы для работы с сессиями пользователей
type SessionService struct {
	sessionRepo interfaces.SessionRepository
	userRepo    interfaces.UserRepository
	kafkaClient *kafka.Client
	logger      *zap.Logger
}

// NewSessionService создает новый экземпляр SessionService
func NewSessionService(
	sessionRepo interfaces.SessionRepository,
	userRepo interfaces.UserRepository,
	kafkaClient *kafka.Client,
	logger *zap.Logger,
) *SessionService {
	return &SessionService{
		sessionRepo: sessionRepo,
		userRepo:    userRepo,
		kafkaClient: kafkaClient,
		logger:      logger,
	}
}

// CreateSession создает новую сессию пользователя
func (s *SessionService) CreateSession(ctx context.Context, userID uuid.UUID, userAgent, ipAddress string) (*models.Session, error) {
	// Проверка существования пользователя
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for session creation", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, models.ErrUserNotFound
	}

	// Создание сессии
	session := &models.Session{
		ID:        uuid.New(),
		UserID:    userID,
		UserAgent: userAgent,
		IPAddress: ipAddress,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // 30 дней
		IsActive:  true,
	}

	// Сохранение сессии
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
		CreatedAt: session.CreatedAt,
	}
	err = s.kafkaClient.PublishSessionEvent(ctx, "session.created", event)
	if err != nil {
		s.logger.Error("Failed to publish session created event", zap.Error(err), zap.String("session_id", session.ID.String()))
	}

	return session, nil
}

// GetSession получает сессию по ID
func (s *SessionService) GetSession(ctx context.Context, sessionID uuid.UUID) (*models.Session, error) {
	session, err := s.sessionRepo.GetByID(ctx, sessionID)
	if err != nil {
		s.logger.Error("Failed to get session", zap.Error(err), zap.String("session_id", sessionID.String()))
		return nil, err
	}
	return session, nil
}

// GetUserSessions получает все сессии пользователя
func (s *SessionService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	// Проверка существования пользователя
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for sessions retrieval", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, models.ErrUserNotFound
	}

	// Получение сессий
	sessions, err := s.sessionRepo.GetByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user sessions", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}
	return sessions, nil
}

// GetActiveUserSessions получает активные сессии пользователя
func (s *SessionService) GetActiveUserSessions(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	// Проверка существования пользователя
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for active sessions retrieval", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, models.ErrUserNotFound
	}

	// Получение активных сессий
	sessions, err := s.sessionRepo.GetActiveByUserID(ctx, userID)
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

	// Деактивация сессии
	session.IsActive = false
	session.UpdatedAt = time.Now()

	// Сохранение сессии
	err = s.sessionRepo.Update(ctx, session)
	if err != nil {
		s.logger.Error("Failed to update session", zap.Error(err), zap.String("session_id", sessionID.String()))
		return err
	}

	// Отправка события о деактивации сессии
	event := models.SessionDeactivatedEvent{
		SessionID:    session.ID.String(),
		UserID:       session.UserID.String(),
		DeactivatedAt: session.UpdatedAt,
	}
	err = s.kafkaClient.PublishSessionEvent(ctx, "session.deactivated", event)
	if err != nil {
		s.logger.Error("Failed to publish session deactivated event", zap.Error(err), zap.String("session_id", session.ID.String()))
	}

	return nil
}

// DeactivateAllUserSessions деактивирует все сессии пользователя
func (s *SessionService) DeactivateAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	// Проверка существования пользователя
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get user for sessions deactivation", zap.Error(err), zap.String("user_id", userID.String()))
		return models.ErrUserNotFound
	}

	// Деактивация всех сессий
	err = s.sessionRepo.DeactivateAllByUserID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to deactivate all user sessions", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Отправка события о деактивации всех сессий
	event := models.AllSessionsDeactivatedEvent{
		UserID:       userID.String(),
		DeactivatedAt: time.Now(),
	}
	err = s.kafkaClient.PublishSessionEvent(ctx, "session.all_deactivated", event)
	if err != nil {
		s.logger.Error("Failed to publish all sessions deactivated event", zap.Error(err), zap.String("user_id", userID.String()))
	}

	return nil
}

// CleanupExpiredSessions удаляет истекшие сессии
func (s *SessionService) CleanupExpiredSessions(ctx context.Context) error {
	// Удаление истекших сессий
	count, err := s.sessionRepo.DeleteExpired(ctx)
	if err != nil {
		s.logger.Error("Failed to delete expired sessions", zap.Error(err))
		return err
	}

	s.logger.Info("Expired sessions cleanup completed", zap.Int("deleted_count", count))
	return nil
}
