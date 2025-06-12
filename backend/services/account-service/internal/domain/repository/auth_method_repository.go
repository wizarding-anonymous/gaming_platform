// File: backend/services/account-service/internal/domain/repository/auth_method_repository.go
// account-service/internal/domain/repository/auth_method_repository.go
package repository

import (
"context"

"github.com/google/uuid"
"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
)

// AuthMethodFilter представляет фильтр для поиска методов аутентификации
type AuthMethodFilter struct {
AccountID  uuid.UUID
Type       *entity.AuthMethodType
Provider   string
Identifier string
Verified   *bool
Limit      int
Offset     int
}

// AuthMethodRepository представляет интерфейс репозитория для работы с методами аутентификации
type AuthMethodRepository interface {
// Create создает новый метод аутентификации
Create(ctx context.Context, authMethod *entity.AuthMethod) error

// GetByID получает метод аутентификации по ID
GetByID(ctx context.Context, id uuid.UUID) (*entity.AuthMethod, error)

// GetByAccountID получает все методы аутентификации пользователя
GetByAccountID(ctx context.Context, accountID uuid.UUID) ([]*entity.AuthMethod, error)

// GetByTypeAndIdentifier получает метод аутентификации по типу и идентификатору
GetByTypeAndIdentifier(ctx context.Context, authType entity.AuthMethodType, identifier string) (*entity.AuthMethod, error)

// GetByProviderAndIdentifier получает метод аутентификации по провайдеру и идентификатору
GetByProviderAndIdentifier(ctx context.Context, provider, identifier string) (*entity.AuthMethod, error)

// Update обновляет метод аутентификации
Update(ctx context.Context, authMethod *entity.AuthMethod) error

// Delete удаляет метод аутентификации
Delete(ctx context.Context, id uuid.UUID) error

// DeleteByAccountID удаляет все методы аутентификации пользователя
DeleteByAccountID(ctx context.Context, accountID uuid.UUID) error

// List получает список методов аутентификации по фильтру
List(ctx context.Context, filter AuthMethodFilter) ([]*entity.AuthMethod, error)

// Exists проверяет существование метода аутентификации по ID
Exists(ctx context.Context, id uuid.UUID) (bool, error)

// ExistsByTypeAndIdentifier проверяет существование метода аутентификации по типу и идентификатору
ExistsByTypeAndIdentifier(ctx context.Context, authType entity.AuthMethodType, identifier string) (bool, error)

// UpdateSecret обновляет секрет метода аутентификации
UpdateSecret(ctx context.Context, id uuid.UUID, secret string) error

// Verify помечает метод аутентификации как верифицированный
Verify(ctx context.Context, id uuid.UUID) error
}
