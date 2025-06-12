// File: backend/services/account-service/internal/infrastructure/database/redis/client.go
// account-service\internal\infrastructure\database\redis\client.go
package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/internal/config"
)

// NewRedisClient creates a Redis client using configuration.
func NewRedisClient(cfg config.RedisConfig) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	return client, client.Ping(context.Background()).Err()
}
