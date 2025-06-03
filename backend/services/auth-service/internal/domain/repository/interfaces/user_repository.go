package interfaces

import (
	"context"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
)

// UserRepository определяет интерфейс для работы с пользователями в хранилище
type UserRepository interface {
	// Create создает нового пользователя
	Create(ctx context.Context, user models.User) (models.User, error)
	
	// GetByID получает пользователя по ID
	GetByID(ctx context.Context, id uuid.UUID) (models.User, error)
	
	// GetByEmail получает пользователя по email
	GetByEmail(ctx context.Context, email string) (models.User, error)
	
	// GetByUsername получает пользователя по имени пользователя
	GetByUsername(ctx context.Context, username string) (models.User, error)
	
	// GetByTelegramID получает пользователя по Telegram ID
	GetByTelegramID(ctx context.Context, telegramID string) (models.User, error)
	
	// Update обновляет информацию о пользователе
	Update(ctx context.Context, user models.User) error
	
	// Delete удаляет пользователя
	Delete(ctx context.Context, id uuid.UUID) error
	
	// List получает список пользователей с пагинацией
	List(ctx context.Context, offset, limit int) ([]models.User, int64, error)
	
	// UpdatePassword обновляет пароль пользователя
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	
	// UpdateEmailVerificationStatus обновляет статус верификации email
	UpdateEmailVerificationStatus(ctx context.Context, id uuid.UUID, verified bool) error
	
	// UpdateTwoFactorStatus обновляет статус двухфакторной аутентификации
	UpdateTwoFactorStatus(ctx context.Context, id uuid.UUID, secret string, enabled bool) error
	
	// UpdateTelegramID обновляет Telegram ID пользователя
	UpdateTelegramID(ctx context.Context, id uuid.UUID, telegramID string) error
	
	// UpdateLastLogin обновляет время последнего входа
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	
	// GetUserRoles получает роли пользователя
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error)
	
	// AssignRole назначает роль пользователю
	AssignRole(ctx context.Context, userID, roleID uuid.UUID) error
	
	// RemoveRole удаляет роль у пользователя
	RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error
	
	// HasRole проверяет, имеет ли пользователь указанную роль
	HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error)
	
	// HasPermission проверяет, имеет ли пользователь указанное разрешение
	HasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error)
}
