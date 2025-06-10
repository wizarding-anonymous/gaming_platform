// File: backend/services/account-service/internal/app/usecase/setting_usecase.go
// account-service\internal\app\usecase\setting_usecase.go

package usecase

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/errors"
)

// SettingRepository интерфейс для работы с репозиторием настроек
type SettingRepository interface {
	Create(ctx context.Context, setting *entity.Setting) error
	GetByID(ctx context.Context, id string) (*entity.Setting, error)
	GetByAccountID(ctx context.Context, accountID string) ([]*entity.Setting, error)
	GetByAccountIDAndCategory(ctx context.Context, accountID, category string) (*entity.Setting, error)
	Update(ctx context.Context, setting *entity.Setting) error
	Delete(ctx context.Context, id string) error
}

// SettingCache интерфейс для работы с кэшем настроек
type SettingCache interface {
	Set(ctx context.Context, accountID, category string, settings map[string]interface{}, ttl time.Duration) error
	Get(ctx context.Context, accountID, category string) (map[string]interface{}, error)
	Delete(ctx context.Context, accountID, category string) error
	DeleteAll(ctx context.Context, accountID string) error
}

// SettingEventProducer интерфейс для отправки событий настроек
type SettingEventProducer interface {
	PublishSettingUpdated(ctx context.Context, accountID, category string, settings map[string]interface{}) error
}

// SettingUseCase реализует бизнес-логику для работы с настройками
type SettingUseCase struct {
	settingRepo   SettingRepository
	accountRepo   AccountRepository
	cache         SettingCache
	eventProducer SettingEventProducer
	logger        *zap.SugaredLogger
}

// NewSettingUseCase создает новый экземпляр SettingUseCase
func NewSettingUseCase(
	settingRepo SettingRepository,
	accountRepo AccountRepository,
	cache SettingCache,
	eventProducer SettingEventProducer,
	logger *zap.SugaredLogger,
) *SettingUseCase {
	return &SettingUseCase{
		settingRepo:   settingRepo,
		accountRepo:   accountRepo,
		cache:         cache,
		eventProducer: eventProducer,
		logger:        logger,
	}
}

// GetAllSettings получает все настройки пользователя
func (uc *SettingUseCase) GetAllSettings(ctx context.Context, accountID string) (map[string]map[string]interface{}, error) {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return nil, errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Получаем все настройки из БД
	settings, err := uc.settingRepo.GetByAccountID(ctx, accountID)
	if err != nil {
		uc.logger.Errorw("Failed to get settings by account ID", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Формируем результат
	result := make(map[string]map[string]interface{})
	for _, setting := range settings {
		var settingsMap map[string]interface{}
		if err := json.Unmarshal([]byte(setting.SettingsJSON), &settingsMap); err != nil {
			uc.logger.Errorw("Failed to unmarshal settings JSON", "error", err)
			continue
		}
		result[setting.Category] = settingsMap
	}

	return result, nil
}

// GetCategorySettings получает настройки определенной категории
func (uc *SettingUseCase) GetCategorySettings(ctx context.Context, accountID, category string) (map[string]interface{}, error) {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return nil, errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Пытаемся получить настройки из кэша
	settingsMap, err := uc.cache.Get(ctx, accountID, category)
	if err == nil {
		return settingsMap, nil
	}

	// Если настройки не найдены в кэше, получаем из БД
	setting, err := uc.settingRepo.GetByAccountIDAndCategory(ctx, accountID, category)
	if err != nil {
		if err == errors.ErrSettingNotFound {
			// Если настройки не найдены, возвращаем пустой объект
			return make(map[string]interface{}), nil
		}
		uc.logger.Errorw("Failed to get setting by account ID and category", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Преобразуем JSON в map
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(setting.SettingsJSON), &result); err != nil {
		uc.logger.Errorw("Failed to unmarshal settings JSON", "error", err)
		return nil, errors.ErrInvalidSettingData
	}

	// Сохраняем настройки в кэш
	if err := uc.cache.Set(ctx, accountID, category, result, 30*time.Minute); err != nil {
		uc.logger.Errorw("Failed to cache settings", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return result, nil
}

// UpdateCategorySettings обновляет настройки определенной категории
func (uc *SettingUseCase) UpdateCategorySettings(ctx context.Context, accountID, category, settingsJSON string) (map[string]interface{}, error) {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return nil, errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return nil, errors.ErrInternalServerError
	}

	// Проверяем валидность JSON
	var settingsMap map[string]interface{}
	if err := json.Unmarshal([]byte(settingsJSON), &settingsMap); err != nil {
		uc.logger.Errorw("Failed to unmarshal settings JSON", "error", err)
		return nil, errors.ErrInvalidSettingData
	}

	// Получаем текущие настройки
	setting, err := uc.settingRepo.GetByAccountIDAndCategory(ctx, accountID, category)
	if err != nil {
		if err == errors.ErrSettingNotFound {
			// Если настройки не найдены, создаем новые
			setting = entity.NewSetting(accountID, category, settingsJSON)
			setting.ID = uuid.New().String()
			if err := uc.settingRepo.Create(ctx, setting); err != nil {
				uc.logger.Errorw("Failed to create setting", "error", err)
				return nil, errors.ErrInternalServerError
			}
		} else {
			uc.logger.Errorw("Failed to get setting by account ID and category", "error", err)
			return nil, errors.ErrInternalServerError
		}
	} else {
		// Обновляем существующие настройки
		setting.UpdateSettings(settingsJSON)
		if err := uc.settingRepo.Update(ctx, setting); err != nil {
			uc.logger.Errorw("Failed to update setting", "error", err)
			return nil, errors.ErrInternalServerError
		}
	}

	// Обновляем кэш
	if err := uc.cache.Set(ctx, accountID, category, settingsMap, 30*time.Minute); err != nil {
		uc.logger.Errorw("Failed to update settings in cache", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	// Публикуем событие об обновлении настроек
	if err := uc.eventProducer.PublishSettingUpdated(ctx, accountID, category, settingsMap); err != nil {
		uc.logger.Errorw("Failed to publish setting updated event", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return settingsMap, nil
}

// DeleteCategorySettings удаляет настройки определенной категории
func (uc *SettingUseCase) DeleteCategorySettings(ctx context.Context, accountID, category string) error {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return errors.ErrInternalServerError
	}

	// Получаем настройки
	setting, err := uc.settingRepo.GetByAccountIDAndCategory(ctx, accountID, category)
	if err != nil {
		if err == errors.ErrSettingNotFound {
			// Если настройки не найдены, ничего не делаем
			return nil
		}
		uc.logger.Errorw("Failed to get setting by account ID and category", "error", err)
		return errors.ErrInternalServerError
	}

	// Удаляем настройки из БД
	if err := uc.settingRepo.Delete(ctx, setting.ID); err != nil {
		uc.logger.Errorw("Failed to delete setting", "error", err)
		return errors.ErrInternalServerError
	}

	// Удаляем настройки из кэша
	if err := uc.cache.Delete(ctx, accountID, category); err != nil {
		uc.logger.Errorw("Failed to delete settings from cache", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	// Публикуем событие об обновлении настроек (пустой объект)
	if err := uc.eventProducer.PublishSettingUpdated(ctx, accountID, category, make(map[string]interface{})); err != nil {
		uc.logger.Errorw("Failed to publish setting updated event", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return nil
}

// ResetAllSettings сбрасывает все настройки пользователя
func (uc *SettingUseCase) ResetAllSettings(ctx context.Context, accountID string) error {
	// Проверяем существование аккаунта
	_, err := uc.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		if err == errors.ErrAccountNotFound {
			return errors.ErrAccountNotFound
		}
		uc.logger.Errorw("Failed to get account", "error", err)
		return errors.ErrInternalServerError
	}

	// Получаем все настройки
	settings, err := uc.settingRepo.GetByAccountID(ctx, accountID)
	if err != nil {
		uc.logger.Errorw("Failed to get settings by account ID", "error", err)
		return errors.ErrInternalServerError
	}

	// Удаляем все настройки
	for _, setting := range settings {
		if err := uc.settingRepo.Delete(ctx, setting.ID); err != nil {
			uc.logger.Errorw("Failed to delete setting", "error", err)
			// Продолжаем удаление других настроек
		}
	}

	// Удаляем все настройки из кэша
	if err := uc.cache.DeleteAll(ctx, accountID); err != nil {
		uc.logger.Errorw("Failed to delete all settings from cache", "error", err)
		// Не возвращаем ошибку, так как это некритично
	}

	return nil
}
