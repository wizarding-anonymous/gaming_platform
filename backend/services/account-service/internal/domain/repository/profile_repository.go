// File: backend/services/account-service/internal/domain/repository/profile_repository.go
// account-service/internal/domain/repository/profile_repository.go
package repository

import (
"context"

"github.com/google/uuid"
"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
)

// ProfileFilter представляет фильтр для поиска профилей
type ProfileFilter struct {
Nickname   string
Country    string
Language   string
Visibility *entity.ProfileVisibility
Limit      int
Offset     int
SortBy     string
SortOrder  string
}

// ProfileRepository представляет интерфейс репозитория для работы с профилями
type ProfileRepository interface {
// Create создает новый профиль
Create(ctx context.Context, profile *entity.Profile) error

// GetByID получает профиль по ID
GetByID(ctx context.Context, id uuid.UUID) (*entity.Profile, error)

// GetByAccountID получает профиль по ID аккаунта
GetByAccountID(ctx context.Context, accountID uuid.UUID) (*entity.Profile, error)

// GetByNickname получает профиль по никнейму
GetByNickname(ctx context.Context, nickname string) (*entity.Profile, error)

// Update обновляет профиль
Update(ctx context.Context, profile *entity.Profile) error

// Delete удаляет профиль
Delete(ctx context.Context, id uuid.UUID) error

// DeleteByAccountID удаляет профиль по ID аккаунта
DeleteByAccountID(ctx context.Context, accountID uuid.UUID) error

// List получает список профилей по фильтру
List(ctx context.Context, filter ProfileFilter) ([]*entity.Profile, int64, error)

// Exists проверяет существование профиля по ID
Exists(ctx context.Context, id uuid.UUID) (bool, error)

// ExistsByAccountID проверяет существование профиля по ID аккаунта
ExistsByAccountID(ctx context.Context, accountID uuid.UUID) (bool, error)

// ExistsByNickname проверяет существование профиля по никнейму
ExistsByNickname(ctx context.Context, nickname string) (bool, error)

// UpdateNickname обновляет никнейм профиля
UpdateNickname(ctx context.Context, id uuid.UUID, nickname string) error

// UpdateVisibility обновляет видимость профиля
UpdateVisibility(ctx context.Context, id uuid.UUID, visibility entity.ProfileVisibility) error

// UpdateAvatarURL обновляет URL аватара профиля
UpdateAvatarURL(ctx context.Context, id uuid.UUID, avatarURL string) error

// UpdateBannerURL обновляет URL баннера профиля
UpdateBannerURL(ctx context.Context, id uuid.UUID, bannerURL string) error

// Anonymize анонимизирует данные профиля
Anonymize(ctx context.Context, id uuid.UUID) error
}
