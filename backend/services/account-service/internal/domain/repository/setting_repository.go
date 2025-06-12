// File: backend/services/account-service/internal/domain/repository/setting_repository.go
// account-service/internal/domain/repository/setting_repository.go
package repository

import (
"context"

"github.com/google/uuid"
"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
)

// SettingFilter представляет фильтр для поиска настроек
type SettingFilter struct {
AccountID uuid.UUID
Category  *entity.SettingCategory
Limit     int
Offset    int
}

// SettingRepository представляет интерфейс репозитория для работы с настройками
type SettingRepository interface {
// Create создает новые настройки
Create(ctx context.Context, setting *entity.Setting) error

// GetByID получает настройки по ID
GetByID(ctx context.Context, id uuid.UUID) (*entity.Setting, error)

// GetByAccountID получает все настройки пользователя
GetByAccountID(ctx context.Context, accountID uuid.UUID) ([]*entity.Setting, error)

// GetByAccountIDAndCategory получает настройки пользователя по категории
GetByAccountIDAndCategory(ctx context.Context, accountID uuid.UUID, category entity.SettingCategory) (*entity.Setting, error)

// Update обновляет настройки
Update(ctx context.Context, setting *entity.Setting) error

// Delete удаляет настройки
Delete(ctx context.Context, id uuid.UUID) error

// DeleteByAccountID удаляет все настройки пользователя
DeleteByAccountID(ctx context.Context, accountID uuid.UUID) error

// List получает список настроек по фильтру
List(ctx context.Context, filter SettingFilter) ([]*entity.Setting, error)

// Exists проверяет существование настроек по ID
Exists(ctx context.Context, id uuid.UUID) (bool, error)

// ExistsByAccountIDAndCategory проверяет существование настроек по ID аккаунта и категории
ExistsByAccountIDAndCategory(ctx context.Context, accountID uuid.UUID, category entity.SettingCategory) (bool, error)

// SetSetting устанавливает значение настройки
SetSetting(ctx context.Context, id uuid.UUID, key string, value interface{}) error

// RemoveSetting удаляет настройку
RemoveSetting(ctx context.Context, id uuid.UUID, key string) error

// ResetToDefaults сбрасывает настройки на значения по умолчанию
ResetToDefaults(ctx context.Context, id uuid.UUID) error
}
