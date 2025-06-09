// File: internal/utils/cache/cache.go

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/logger"
)

// Cache представляет интерфейс для работы с кешем
type Cache struct {
	client *redis.Client
	logger logger.Logger
	prefix string
}

// NewCache создает новый экземпляр кеша
func NewCache(client *redis.Client, logger logger.Logger, prefix string) *Cache {
	return &Cache{
		client: client,
		logger: logger,
		prefix: prefix,
	}
}

// formatKey форматирует ключ с префиксом
func (c *Cache) formatKey(key string) string {
	return fmt.Sprintf("%s:%s", c.prefix, key)
}

// Set устанавливает значение в кеш
func (c *Cache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	formattedKey := c.formatKey(key)

	// Если значение не является строкой, сериализуем его в JSON
	var dataToStore interface{}
	switch v := value.(type) {
	case string:
		dataToStore = v
	case []byte:
		dataToStore = string(v)
	default:
		jsonData, err := json.Marshal(value)
		if err != nil {
			c.logger.Error("Failed to marshal cache value", "error", err, "key", key)
			return fmt.Errorf("failed to marshal cache value: %w", err)
		}
		dataToStore = string(jsonData)
	}

	// Устанавливаем значение в Redis
	err := c.client.Set(ctx, formattedKey, dataToStore, expiration).Err()
	if err != nil {
		c.logger.Error("Failed to set cache value", "error", err, "key", key)
		return fmt.Errorf("failed to set cache value: %w", err)
	}

	return nil
}

// Get получает значение из кеша
func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	formattedKey := c.formatKey(key)

	// Получаем значение из Redis
	value, err := c.client.Get(ctx, formattedKey).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("key not found: %s", key)
		}
		c.logger.Error("Failed to get cache value", "error", err, "key", key)
		return "", fmt.Errorf("failed to get cache value: %w", err)
	}

	return value, nil
}

// GetObject получает объект из кеша и десериализует его
func (c *Cache) GetObject(ctx context.Context, key string, dest interface{}) error {
	// Получаем значение из кеша
	value, err := c.Get(ctx, key)
	if err != nil {
		return err
	}

	// Десериализуем JSON в объект
	err = json.Unmarshal([]byte(value), dest)
	if err != nil {
		c.logger.Error("Failed to unmarshal cache value", "error", err, "key", key)
		return fmt.Errorf("failed to unmarshal cache value: %w", err)
	}

	return nil
}

// Delete удаляет значение из кеша
func (c *Cache) Delete(ctx context.Context, key string) error {
	formattedKey := c.formatKey(key)

	// Удаляем значение из Redis
	err := c.client.Del(ctx, formattedKey).Err()
	if err != nil {
		c.logger.Error("Failed to delete cache value", "error", err, "key", key)
		return fmt.Errorf("failed to delete cache value: %w", err)
	}

	return nil
}

// DeleteByPattern удаляет значения из кеша по шаблону
func (c *Cache) DeleteByPattern(ctx context.Context, pattern string) error {
	formattedPattern := c.formatKey(pattern)

	// Получаем ключи по шаблону
	keys, err := c.client.Keys(ctx, formattedPattern).Result()
	if err != nil {
		c.logger.Error("Failed to get keys by pattern", "error", err, "pattern", pattern)
		return fmt.Errorf("failed to get keys by pattern: %w", err)
	}

	// Если ключей нет, возвращаем nil
	if len(keys) == 0 {
		return nil
	}

	// Удаляем ключи
	err = c.client.Del(ctx, keys...).Err()
	if err != nil {
		c.logger.Error("Failed to delete keys by pattern", "error", err, "pattern", pattern)
		return fmt.Errorf("failed to delete keys by pattern: %w", err)
	}

	return nil
}

// Exists проверяет существование ключа в кеше
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	formattedKey := c.formatKey(key)

	// Проверяем существование ключа
	exists, err := c.client.Exists(ctx, formattedKey).Result()
	if err != nil {
		c.logger.Error("Failed to check key existence", "error", err, "key", key)
		return false, fmt.Errorf("failed to check key existence: %w", err)
	}

	return exists > 0, nil
}

// SetNX устанавливает значение в кеш, только если ключ не существует
func (c *Cache) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	formattedKey := c.formatKey(key)

	// Если значение не является строкой, сериализуем его в JSON
	var dataToStore interface{}
	switch v := value.(type) {
	case string:
		dataToStore = v
	case []byte:
		dataToStore = string(v)
	default:
		jsonData, err := json.Marshal(value)
		if err != nil {
			c.logger.Error("Failed to marshal cache value", "error", err, "key", key)
			return false, fmt.Errorf("failed to marshal cache value: %w", err)
		}
		dataToStore = string(jsonData)
	}

	// Устанавливаем значение в Redis, только если ключ не существует
	result, err := c.client.SetNX(ctx, formattedKey, dataToStore, expiration).Result()
	if err != nil {
		c.logger.Error("Failed to set cache value with NX option", "error", err, "key", key)
		return false, fmt.Errorf("failed to set cache value with NX option: %w", err)
	}

	return result, nil
}

// Expire устанавливает время жизни ключа
func (c *Cache) Expire(ctx context.Context, key string, expiration time.Duration) error {
	formattedKey := c.formatKey(key)

	// Устанавливаем время жизни ключа
	err := c.client.Expire(ctx, formattedKey, expiration).Err()
	if err != nil {
		c.logger.Error("Failed to set key expiration", "error", err, "key", key)
		return fmt.Errorf("failed to set key expiration: %w", err)
	}

	return nil
}

// TTL возвращает оставшееся время жизни ключа
func (c *Cache) TTL(ctx context.Context, key string) (time.Duration, error) {
	formattedKey := c.formatKey(key)

	// Получаем оставшееся время жизни ключа
	ttl, err := c.client.TTL(ctx, formattedKey).Result()
	if err != nil {
		c.logger.Error("Failed to get key TTL", "error", err, "key", key)
		return 0, fmt.Errorf("failed to get key TTL: %w", err)
	}

	return ttl, nil
}

// Incr увеличивает значение ключа на 1
func (c *Cache) Incr(ctx context.Context, key string) (int64, error) {
	formattedKey := c.formatKey(key)

	// Увеличиваем значение ключа на 1
	result, err := c.client.Incr(ctx, formattedKey).Result()
	if err != nil {
		c.logger.Error("Failed to increment key value", "error", err, "key", key)
		return 0, fmt.Errorf("failed to increment key value: %w", err)
	}

	return result, nil
}

// IncrBy увеличивает значение ключа на указанное число
func (c *Cache) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	formattedKey := c.formatKey(key)

	// Увеличиваем значение ключа на указанное число
	result, err := c.client.IncrBy(ctx, formattedKey, value).Result()
	if err != nil {
		c.logger.Error("Failed to increment key value by specific amount", "error", err, "key", key, "value", value)
		return 0, fmt.Errorf("failed to increment key value by specific amount: %w", err)
	}

	return result, nil
}

// Decr уменьшает значение ключа на 1
func (c *Cache) Decr(ctx context.Context, key string) (int64, error) {
	formattedKey := c.formatKey(key)

	// Уменьшаем значение ключа на 1
	result, err := c.client.Decr(ctx, formattedKey).Result()
	if err != nil {
		c.logger.Error("Failed to decrement key value", "error", err, "key", key)
		return 0, fmt.Errorf("failed to decrement key value: %w", err)
	}

	return result, nil
}

// DecrBy уменьшает значение ключа на указанное число
func (c *Cache) DecrBy(ctx context.Context, key string, value int64) (int64, error) {
	formattedKey := c.formatKey(key)

	// Уменьшаем значение ключа на указанное число
	result, err := c.client.DecrBy(ctx, formattedKey, value).Result()
	if err != nil {
		c.logger.Error("Failed to decrement key value by specific amount", "error", err, "key", key, "value", value)
		return 0, fmt.Errorf("failed to decrement key value by specific amount: %w", err)
	}

	return result, nil
}
