package interfaces

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
)

// TokenRepository определяет интерфейс для работы с токенами в хранилище
type TokenRepository interface {
	// Create создает новый токен
	Create(ctx context.Context, token models.Token) (models.Token, error)
	
	// GetByID получает токен по ID
	GetByID(ctx context.Context, id uuid.UUID) (models.Token, error)
	
	// GetByValue получает токен по значению
	GetByValue(ctx context.Context, tokenValue string) (models.Token, error)
	
	// GetByUserAndType получает токены пользователя определенного типа
	GetByUserAndType(ctx context.Context, userID uuid.UUID, tokenType string) ([]models.Token, error)
	
	// Update обновляет информацию о токене
	Update(ctx context.Context, token models.Token) error
	
	// Delete удаляет токен
	Delete(ctx context.Context, id uuid.UUID) error
	
	// Revoke отзывает токен
	Revoke(ctx context.Context, id uuid.UUID) error
	
	// RevokeAllUserTokens отзывает все токены пользователя
	RevokeAllUserTokens(ctx context.Context, userID uuid.UUID, exceptTokenID *uuid.UUID) error
	
	// RevokeExpiredTokens отзывает все истекшие токены
	RevokeExpiredTokens(ctx context.Context) error
	
	// IsTokenRevoked проверяет, отозван ли токен
	IsTokenRevoked(ctx context.Context, tokenValue string) (bool, error)
	
	// StoreTokenInCache сохраняет токен в кэше
	StoreTokenInCache(ctx context.Context, tokenValue string, userID uuid.UUID, expiresIn time.Duration) error
	
	// GetTokenFromCache получает информацию о токене из кэша
	GetTokenFromCache(ctx context.Context, tokenValue string) (uuid.UUID, error)
	
	// RemoveTokenFromCache удаляет токен из кэша
	RemoveTokenFromCache(ctx context.Context, tokenValue string) error
}
