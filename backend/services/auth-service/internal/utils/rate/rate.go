// File: internal/utils/rate/rate.go

package rate

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/logger"
)

// Limiter представляет ограничитель скорости запросов
type Limiter struct {
	client *redis.Client
	logger logger.Logger
	config *config.RateLimitConfig
}

// NewLimiter создает новый ограничитель скорости запросов
func NewLimiter(client *redis.Client, logger logger.Logger, config *config.RateLimitConfig) *Limiter {
	return &Limiter{
		client: client,
		logger: logger,
		config: config,
	}
}

// Allow проверяет, разрешен ли запрос
func (l *Limiter) Allow(ctx context.Context, key string, limit int, period time.Duration) (bool, error) {
	// Если ограничение скорости отключено, всегда разрешаем запрос
	if !l.config.Enabled {
		return true, nil
	}

	// Формируем ключ для Redis
	redisKey := fmt.Sprintf("rate:%s", key)

	// Получаем текущее количество запросов
	count, err := l.client.Get(ctx, redisKey).Int()
	if err != nil && err != redis.Nil {
		l.logger.Error("Failed to get rate limit count", "error", err, "key", key)
		// В случае ошибки Redis разрешаем запрос, чтобы не блокировать пользователей
		return true, err
	}

	// Если ключ не существует или истек, создаем новый
	if err == redis.Nil {
		// Устанавливаем счетчик в 1 и задаем время жизни
		err = l.client.Set(ctx, redisKey, 1, period).Err()
		if err != nil {
			l.logger.Error("Failed to set rate limit count", "error", err, "key", key)
			// В случае ошибки Redis разрешаем запрос
			return true, err
		}
		return true, nil
	}

	// Если количество запросов превышает лимит, запрещаем запрос
	if count >= limit {
		l.logger.Warn("Rate limit exceeded", "key", key, "count", count, "limit", limit)
		return false, nil
	}

	// Увеличиваем счетчик
	_, err = l.client.Incr(ctx, redisKey).Result()
	if err != nil {
		l.logger.Error("Failed to increment rate limit count", "error", err, "key", key)
		// В случае ошибки Redis разрешаем запрос
		return true, err
	}

	// Получаем оставшееся время жизни ключа
	ttl, err := l.client.TTL(ctx, redisKey).Result()
	if err != nil {
		l.logger.Error("Failed to get TTL", "error", err, "key", key)
	}

	// Если TTL не установлен или отрицательный, устанавливаем его
	if ttl < 0 {
		err = l.client.Expire(ctx, redisKey, period).Err()
		if err != nil {
			l.logger.Error("Failed to set expiration", "error", err, "key", key)
		}
	}

	return true, nil
}

// AllowByIP проверяет, разрешен ли запрос для данного IP-адреса
func (l *Limiter) AllowByIP(ctx context.Context, ip string) (bool, error) {
	return l.Allow(ctx, fmt.Sprintf("ip:%s", ip), l.config.IPLimit, time.Duration(l.config.IPPeriod)*time.Second)
}

// AllowByUserID проверяет, разрешен ли запрос для данного пользователя
func (l *Limiter) AllowByUserID(ctx context.Context, userID string) (bool, error) {
	return l.Allow(ctx, fmt.Sprintf("user:%s", userID), l.config.UserLimit, time.Duration(l.config.UserPeriod)*time.Second)
}

// AllowByEndpoint проверяет, разрешен ли запрос для данного эндпоинта
func (l *Limiter) AllowByEndpoint(ctx context.Context, endpoint string) (bool, error) {
	return l.Allow(ctx, fmt.Sprintf("endpoint:%s", endpoint), l.config.EndpointLimit, time.Duration(l.config.EndpointPeriod)*time.Second)
}

// AllowLogin проверяет, разрешены ли попытки входа для данного IP-адреса
func (l *Limiter) AllowLogin(ctx context.Context, ip string) (bool, error) {
	return l.Allow(ctx, fmt.Sprintf("login:%s", ip), l.config.LoginLimit, time.Duration(l.config.LoginPeriod)*time.Second)
}

// AllowRegistration проверяет, разрешены ли попытки регистрации для данного IP-адреса
func (l *Limiter) AllowRegistration(ctx context.Context, ip string) (bool, error) {
	return l.Allow(ctx, fmt.Sprintf("registration:%s", ip), l.config.RegistrationLimit, time.Duration(l.config.RegistrationPeriod)*time.Second)
}

// Reset сбрасывает ограничение для данного ключа
func (l *Limiter) Reset(ctx context.Context, key string) error {
	redisKey := fmt.Sprintf("rate:%s", key)
	return l.client.Del(ctx, redisKey).Err()
}

// ResetByIP сбрасывает ограничение для данного IP-адреса
func (l *Limiter) ResetByIP(ctx context.Context, ip string) error {
	return l.Reset(ctx, fmt.Sprintf("ip:%s", ip))
}

// ResetByUserID сбрасывает ограничение для данного пользователя
func (l *Limiter) ResetByUserID(ctx context.Context, userID string) error {
	return l.Reset(ctx, fmt.Sprintf("user:%s", userID))
}

// GetRemainingAttempts возвращает оставшееся количество попыток для данного ключа
func (l *Limiter) GetRemainingAttempts(ctx context.Context, key string, limit int) (int, error) {
	redisKey := fmt.Sprintf("rate:%s", key)
	
	// Получаем текущее количество запросов
	count, err := l.client.Get(ctx, redisKey).Int()
	if err != nil && err != redis.Nil {
		return 0, err
	}
	
	// Если ключ не существует, возвращаем максимальное количество попыток
	if err == redis.Nil {
		return limit, nil
	}
	
	// Вычисляем оставшееся количество попыток
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	
	return remaining, nil
}

// GetRemainingTime возвращает оставшееся время до сброса ограничения для данного ключа
func (l *Limiter) GetRemainingTime(ctx context.Context, key string) (time.Duration, error) {
	redisKey := fmt.Sprintf("rate:%s", key)
	
	// Получаем оставшееся время жизни ключа
	ttl, err := l.client.TTL(ctx, redisKey).Result()
	if err != nil {
		return 0, err
	}
	
	// Если ключ не существует или TTL не установлен, возвращаем 0
	if ttl < 0 {
		return 0, nil
	}
	
	return ttl, nil
}
