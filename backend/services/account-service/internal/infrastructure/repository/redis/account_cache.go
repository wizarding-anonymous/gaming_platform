// File: backend/services/account-service/internal/infrastructure/repository/redis/account_cache.go
// account-service\internal\infrastructure\repository\redis\account_cache.go

package redis

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"

	"github.com/gaiming/account-service/internal/domain/entity"
	"github.com/gaiming/account-service/pkg/metrics"
)

const (
	// AccountKeyPrefix префикс ключа для аккаунтов в Redis
	AccountKeyPrefix = "account:"
	// AccountTTL время жизни кэша аккаунта
	AccountTTL = 30 * time.Minute
)

// AccountCache реализует кэш для аккаунтов в Redis
type AccountCache struct {
	client  *redis.Client
	metrics *metrics.Registry
	logger  *zap.SugaredLogger
}

// NewAccountCache создает новый кэш аккаунтов
func NewAccountCache(client *redis.Client, metrics *metrics.Registry, logger *zap.SugaredLogger) *AccountCache {
	return &AccountCache{
		client:  client,
		metrics: metrics,
		logger:  logger,
	}
}

// Get получает аккаунт из кэша по ID
func (c *AccountCache) Get(ctx context.Context, id string) (*entity.Account, error) {
	key := AccountKeyPrefix + id
	
	// Получение данных из Redis
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			c.metrics.TrackCacheMiss("account", "by_id")
			return nil, err
		}
		c.logger.Errorw("Failed to get account from cache", "id", id, "error", err)
		c.metrics.TrackCacheMiss("account", "by_id")
		return nil, err
	}
	
	// Десериализация данных
	var account entity.Account
	if err := json.Unmarshal(data, &account); err != nil {
		c.logger.Errorw("Failed to unmarshal account from cache", "id", id, "error", err)
		c.metrics.TrackCacheMiss("account", "by_id")
		return nil, err
	}
	
	c.metrics.TrackCacheHit("account", "by_id")
	return &account, nil
}

// Set сохраняет аккаунт в кэш
func (c *AccountCache) Set(ctx context.Context, account *entity.Account) error {
	key := AccountKeyPrefix + account.ID
	
	// Сериализация данных
	data, err := json.Marshal(account)
	if err != nil {
		c.logger.Errorw("Failed to marshal account for cache", "account", account, "error", err)
		return err
	}
	
	// Сохранение в Redis с TTL
	if err := c.client.Set(ctx, key, data, AccountTTL).Err(); err != nil {
		c.logger.Errorw("Failed to set account in cache", "account", account, "error", err)
		return err
	}
	
	return nil
}

// Delete удаляет аккаунт из кэша
func (c *AccountCache) Delete(ctx context.Context, id string) error {
	key := AccountKeyPrefix + id
	
	// Удаление из Redis
	if err := c.client.Del(ctx, key).Err(); err != nil {
		c.logger.Errorw("Failed to delete account from cache", "id", id, "error", err)
		return err
	}
	
	return nil
}
