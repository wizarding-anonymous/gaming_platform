package interfaces

import (
	"context"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
)

// SessionRepository определяет интерфейс для работы с сессиями в хранилище
type SessionRepository interface {
	// Create создает новую сессию
	Create(ctx context.Context, session models.Session) (models.Session, error)
	
	// GetByID получает сессию по ID
	GetByID(ctx context.Context, id uuid.UUID) (models.Session, error)
	
	// GetByRefreshToken получает сессию по refresh токену
	GetByRefreshToken(ctx context.Context, refreshToken string) (models.Session, error)
	
	// GetUserSessions получает все сессии пользователя
	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]models.Session, error)
	
	// Update обновляет информацию о сессии
	Update(ctx context.Context, session models.Session) error
	
	// UpdateLastActivity обновляет время последней активности сессии
	UpdateLastActivity(ctx context.Context, id uuid.UUID) error
	
	// Delete удаляет сессию
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Revoke отзывает сессию
	Revoke(ctx context.Context, id uuid.UUID) error
	
	// RevokeAllUserSessions отзывает все сессии пользователя
	RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, exceptSessionID *uuid.UUID) error
	
	// RevokeExpiredSessions отзывает все истекшие сессии
	RevokeExpiredSessions(ctx context.Context) error
	
	// StoreSessionInCache сохраняет сессию в кэше
	StoreSessionInCache(ctx context.Context, sessionID uuid.UUID, userID uuid.UUID) error
	
	// GetSessionFromCache получает информацию о сессии из кэша
	GetSessionFromCache(ctx context.Context, sessionID uuid.UUID) (uuid.UUID, error)
	
	// RemoveSessionFromCache удаляет сессию из кэша
	RemoveSessionFromCache(ctx context.Context, sessionID uuid.UUID) error
}
