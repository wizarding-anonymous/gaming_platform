// File: backend/services/account-service/internal/infrastructure/repository/redis/profile_cache.go
// account-service\internal\infrastructure\repository\redis\profile_cache.go

package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/domain/errors"
)

// ProfileCache реализует кэш для профилей в Redis
type ProfileCache struct {
	client *redis.Client
	logger *zap.SugaredLogger
}

// NewProfileCache создает новый экземпляр ProfileCache
func NewProfileCache(client *redis.Client, logger *zap.SugaredLogger) *ProfileCache {
	return &ProfileCache{
		client: client,
		logger: logger,
	}
}

// Set сохраняет профиль в кэш
func (c *ProfileCache) Set(ctx context.Context, profile *entity.Profile, ttl time.Duration) error {
	key := c.getProfileKey(profile.AccountID)

	// Сериализуем профиль в JSON
	profileJSON, err := json.Marshal(profile)
	if err != nil {
		c.logger.Errorw("Failed to marshal profile to JSON", "error", err)
		return errors.ErrCacheError
	}

	// Сохраняем в Redis
	if err := c.client.Set(ctx, key, profileJSON, ttl).Err(); err != nil {
		c.logger.Errorw("Failed to set profile in cache", "error", err)
		return errors.ErrCacheError
	}

	return nil
}

// Get получает профиль из кэша
func (c *ProfileCache) Get(ctx context.Context, accountID string) (*entity.Profile, error) {
	key := c.getProfileKey(accountID)

	// Получаем данные из Redis
	profileJSON, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.ErrProfileNotFound
		}
		c.logger.Errorw("Failed to get profile from cache", "error", err)
		return nil, errors.ErrCacheError
	}

	// Десериализуем JSON в профиль
	var profile entity.Profile
	if err := json.Unmarshal([]byte(profileJSON), &profile); err != nil {
		c.logger.Errorw("Failed to unmarshal profile from JSON", "error", err)
		return nil, errors.ErrCacheError
	}

	return &profile, nil
}

// Delete удаляет профиль из кэша
func (c *ProfileCache) Delete(ctx context.Context, accountID string) error {
	key := c.getProfileKey(accountID)

	// Удаляем из Redis
	if err := c.client.Del(ctx, key).Err(); err != nil {
		c.logger.Errorw("Failed to delete profile from cache", "error", err)
		return errors.ErrCacheError
	}

	return nil
}

// getProfileKey формирует ключ для профиля в Redis
func (c *ProfileCache) getProfileKey(accountID string) string {
	return "profile:" + accountID
}
