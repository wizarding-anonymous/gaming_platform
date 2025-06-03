// account-service/internal/domain/repository/avatar_repository.go
package repository

import (
"context"

"github.com/google/uuid"
"github.com/steamru/account-service/internal/domain/entity"
)

// AvatarFilter представляет фильтр для поиска аватаров
type AvatarFilter struct {
AccountID uuid.UUID
Type      *entity.AvatarType
IsActive  *bool
Limit     int
Offset    int
}

// AvatarRepository представляет интерфейс репозитория для работы с аватарами
type AvatarRepository interface {
// Create создает новый аватар
Create(ctx context.Context, avatar *entity.Avatar) error

// GetByID получает аватар по ID
GetByID(ctx context.Context, id uuid.UUID) (*entity.Avatar, error)

// GetByAccountID получает все аватары пользователя
GetByAccountID(ctx context.Context, accountID uuid.UUID) ([]*entity.Avatar, error)

// GetActiveByAccountIDAndType получает активный аватар пользователя по типу
GetActiveByAccountIDAndType(ctx context.Context, accountID uuid.UUID, avatarType entity.AvatarType) (*entity.Avatar, error)

// Update обновляет аватар
Update(ctx context.Context, avatar *entity.Avatar) error

// Delete удаляет аватар
Delete(ctx context.Context, id uuid.UUID) error

// DeleteByAccountID удаляет все аватары пользователя
DeleteByAccountID(ctx context.Context, accountID uuid.UUID) error

// List получает список аватаров по фильтру
List(ctx context.Context, filter AvatarFilter) ([]*entity.Avatar, error)

// Exists проверяет существование аватара по ID
Exists(ctx context.Context, id uuid.UUID) (bool, error)

// Activate активирует аватар
Activate(ctx context.Context, id uuid.UUID) error

// Deactivate деактивирует аватар
Deactivate(ctx context.Context, id uuid.UUID) error

// DeactivateAllByAccountIDAndType деактивирует все аватары пользователя указанного типа
DeactivateAllByAccountIDAndType(ctx context.Context, accountID uuid.UUID, avatarType entity.AvatarType) error

// UpdateURL обновляет URL аватара
UpdateURL(ctx context.Context, id uuid.UUID, url string) error
}
