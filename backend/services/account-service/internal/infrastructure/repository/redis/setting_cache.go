// File: backend/services/account-service/internal/infrastructure/repository/redis/setting_cache.go
// account-service\internal\infrastructure\repository\redis\setting_cache.go

package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"

	"github.com/gaiming/account-service/internal/domain/errors"
)

// SettingCache реализует кэш для настроек в Redis
type SettingCache struct {
	client *redis.Client
	logger *zap.SugaredLogger
}

// NewSettingCache создает новый экземпляр SettingCache
func NewSettingCache(client *redis.Client, logger *zap.SugaredLogger) *SettingCache {
	return &SettingCache{
		client: client,
		logger: logger,
	}
}

// Set сохраняет настройки в кэш
func (c *SettingCache) Set(ctx context.Context, accountID, category string, settings map[string]interface{}, ttl time.Duration) error {
	key := c.getSettingKey(accountID, category)

	// Сериализуем настройки в JSON
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		c.logger.Errorw("Failed to marshal settings to JSON", "error", err)
		return errors.ErrCacheError
	}

	// Сохраняем в Redis
	if err := c.client.Set(ctx, key, settingsJSON, ttl).Err(); err != nil {
		c.logger.Errorw("Failed to set settings in cache", "error", err)
		return errors.ErrCacheError
	}

	return nil
}

// Get получает настройки из кэша
func (c *SettingCache) Get(ctx context.Context, accountID, category string) (map[string]interface{}, error) {
	key := c.getSettingKey(accountID, category)

	// Получаем данные из Redis
	settingsJSON, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.ErrSettingNotFound
		}
		c.logger.Errorw("Failed to get settings from cache", "error", err)
		return nil, errors.ErrCacheError
	}

	// Десериализуем JSON в map
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(settingsJSON), &settings); err != nil {
		c.logger.Errorw("Failed to unmarshal settings from JSON", "error", err)
		return nil, errors.ErrCacheError
	}

	return settings, nil
}

// Delete удаляет настройки из кэша
func (c *SettingCache) Delete(ctx context.Context, accountID, category string) error {
	key := c.getSettingKey(accountID, category)

	// Удаляем из Redis
	if err := c.client.Del(ctx, key).Err(); err != nil {
		c.logger.Errorw("Failed to delete settings from cache", "error", err)
		return errors.ErrCacheError
	}

	return nil
}

// DeleteAll удаляет все настройки пользователя из кэша
func (c *SettingCache) DeleteAll(ctx context.Context, accountID string) error {
	pattern := c.getSettingKey(accountID, "*")

	// Находим все ключи по шаблону
	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		c.logger.Errorw("Failed to find setting keys", "error", err)
		return errors.ErrCacheError
	}

	// Если ключей нет, то ничего не делаем
	if len(keys) == 0 {
		return nil
	}

	// Удаляем все найденные ключи
	if err := c.client.Del(ctx, keys...).Err(); err != nil {
		c.logger.Errorw("Failed to delete all settings from cache", "error", err)
		return errors.ErrCacheError
	}

	return nil
}

// getSettingKey формирует ключ для настроек в Redis
func (c *SettingCache) getSettingKey(accountID, category string) string {
	return "setting:" + accountID + ":" + category
}
