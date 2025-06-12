// File: backend/services/account-service/internal/infrastructure/repository/postgres/setting_repository.go
// account-service/internal/infrastructure/repository/postgres/setting_repository.go
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/repository"
)

// SettingModel представляет модель настроек в базе данных
type SettingModel struct {
	ID         uuid.UUID `gorm:"type:uuid;primary_key"`
	AccountID  uuid.UUID `gorm:"type:uuid;uniqueIndex"`
	Category   string    `gorm:"type:varchar(50);not null"`
	Settings   string    `gorm:"type:jsonb;not null"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// TableName возвращает имя таблицы
func (SettingModel) TableName() string {
	return "settings"
}

// ToEntity преобразует модель в сущность
func (m *SettingModel) ToEntity() (*entity.Setting, error) {
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(m.Settings), &settings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	return &entity.Setting{
		ID:        m.ID,
		AccountID: m.AccountID,
		Category:  entity.SettingCategory(m.Category),
		Settings:  settings,
		CreatedAt: m.CreatedAt,
		UpdatedAt: m.UpdatedAt,
	}, nil
}

// FromEntity преобразует сущность в модель
func (m *SettingModel) FromEntity(setting *entity.Setting) error {
	settingsJSON, err := json.Marshal(setting.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	m.ID = setting.ID
	m.AccountID = setting.AccountID
	m.Category = string(setting.Category)
	m.Settings = string(settingsJSON)
	m.CreatedAt = setting.CreatedAt
	m.UpdatedAt = setting.UpdatedAt

	return nil
}

// SettingRepositoryImpl реализация репозитория для работы с настройками
type SettingRepositoryImpl struct {
	db *gorm.DB
}

// NewSettingRepository создает новый экземпляр репозитория для работы с настройками
func NewSettingRepository(db *gorm.DB) repository.SettingRepository {
	return &SettingRepositoryImpl{
		db: db,
	}
}

// Create создает новые настройки
func (r *SettingRepositoryImpl) Create(ctx context.Context, setting *entity.Setting) error {
	model := &SettingModel{}
	if err := model.FromEntity(setting); err != nil {
		return err
	}

	result := r.db.WithContext(ctx).Create(model)
	if result.Error != nil {
		return fmt.Errorf("failed to create setting: %w", result.Error)
	}

	return nil
}

// GetByID получает настройки по ID
func (r *SettingRepositoryImpl) GetByID(ctx context.Context, id uuid.UUID) (*entity.Setting, error) {
	var model SettingModel
	result := r.db.WithContext(ctx).First(&model, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, repository.ErrSettingNotFound
		}
		return nil, fmt.Errorf("failed to get setting by ID: %w", result.Error)
	}

	return model.ToEntity()
}

// GetByAccountID получает все настройки пользователя
func (r *SettingRepositoryImpl) GetByAccountID(ctx context.Context, accountID uuid.UUID) ([]*entity.Setting, error) {
	var models []SettingModel
	result := r.db.WithContext(ctx).Where("account_id = ?", accountID).Find(&models)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get settings by account ID: %w", result.Error)
	}

	settings := make([]*entity.Setting, 0, len(models))
	for _, model := range models {
		setting, err := model.ToEntity()
		if err != nil {
			return nil, err
		}
		settings = append(settings, setting)
	}

	return settings, nil
}

// GetByAccountIDAndCategory получает настройки определенной категории
func (r *SettingRepositoryImpl) GetByAccountIDAndCategory(ctx context.Context, accountID uuid.UUID, category entity.SettingCategory) (*entity.Setting, error) {
	var model SettingModel
	result := r.db.WithContext(ctx).First(&model, "account_id = ? AND category = ?", accountID, string(category))
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, repository.ErrSettingNotFound
		}
		return nil, fmt.Errorf("failed to get setting by account ID and category: %w", result.Error)
	}

	return model.ToEntity()
}

// Update обновляет настройки
func (r *SettingRepositoryImpl) Update(ctx context.Context, setting *entity.Setting) error {
	model := &SettingModel{}
	if err := model.FromEntity(setting); err != nil {
		return err
	}

	result := r.db.WithContext(ctx).Save(model)
	if result.Error != nil {
		return fmt.Errorf("failed to update setting: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrSettingNotFound
	}

	return nil
}

// Delete удаляет настройки
func (r *SettingRepositoryImpl) Delete(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Delete(&SettingModel{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete setting: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return repository.ErrSettingNotFound
	}

	return nil
}

// List получает список настроек с фильтрацией
func (r *SettingRepositoryImpl) List(ctx context.Context, filter repository.SettingFilter) ([]*entity.Setting, error) {
	var models []SettingModel
	query := r.db.WithContext(ctx)

	// Применение фильтров
	if filter.AccountID != uuid.Nil {
		query = query.Where("account_id = ?", filter.AccountID)
	}
	if filter.Category != "" {
		query = query.Where("category = ?", filter.Category)
	}

	// Получение данных
	if err := query.Find(&models).Error; err != nil {
		return nil, fmt.Errorf("failed to list settings: %w", err)
	}

	// Преобразование моделей в сущности
	settings := make([]*entity.Setting, 0, len(models))
	for _, model := range models {
		setting, err := model.ToEntity()
		if err != nil {
			return nil, err
		}
		settings = append(settings, setting)
	}

	return settings, nil
}

// SetSetting устанавливает значение настройки
func (r *SettingRepositoryImpl) SetSetting(ctx context.Context, id uuid.UUID, key string, value interface{}) error {
	// Получаем текущие настройки
	setting, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Обновляем значение настройки
	setting.Settings[key] = value
	setting.UpdatedAt = time.Now()

	// Сохраняем обновленные настройки
	return r.Update(ctx, setting)
}

// RemoveSetting удаляет настройку
func (r *SettingRepositoryImpl) RemoveSetting(ctx context.Context, id uuid.UUID, key string) error {
	// Получаем текущие настройки
	setting, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Удаляем настройку
	delete(setting.Settings, key)
	setting.UpdatedAt = time.Now()

	// Сохраняем обновленные настройки
	return r.Update(ctx, setting)
}

// ResetToDefaults сбрасывает настройки на значения по умолчанию
func (r *SettingRepositoryImpl) ResetToDefaults(ctx context.Context, id uuid.UUID) error {
	// Получаем текущие настройки
	setting, err := r.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Сбрасываем настройки на значения по умолчанию в зависимости от категории
	switch setting.Category {
	case entity.SettingCategoryPrivacy:
		setting.Settings = entity.DefaultPrivacySettings()
	case entity.SettingCategoryNotification:
		setting.Settings = entity.DefaultNotificationSettings()
	case entity.SettingCategoryInterface:
		setting.Settings = entity.DefaultInterfaceSettings()
	case entity.SettingCategorySecurity:
		setting.Settings = entity.DefaultSecuritySettings()
	default:
		setting.Settings = make(map[string]interface{})
	}
	setting.UpdatedAt = time.Now()

	// Сохраняем обновленные настройки
	return r.Update(ctx, setting)
}
