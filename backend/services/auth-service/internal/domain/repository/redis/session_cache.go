// File: internal/repository/redis/session_cache.go

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	"go.uber.org/zap"
)

// SessionCache представляет кэш сессий в Redis
type SessionCache struct {
	client *redis.Client
	logger *zap.Logger
	ttl    time.Duration
}

// NewSessionCache создает новый экземпляр SessionCache
func NewSessionCache(client *redis.Client, logger *zap.Logger, ttl time.Duration) *SessionCache {
	return &SessionCache{
		client: client,
		logger: logger,
		ttl:    ttl,
	}
}

// GetByID получает сессию по ID из кэша
func (c *SessionCache) GetByID(ctx context.Context, id uuid.UUID) (*models.Session, error) {
	key := fmt.Sprintf("session:%s", id.String())
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, models.ErrSessionNotFound
		}
		c.logger.Error("Failed to get session from cache", zap.Error(err), zap.String("session_id", id.String()))
		return nil, err
	}

	var session models.Session
	err = json.Unmarshal(data, &session)
	if err != nil {
		c.logger.Error("Failed to unmarshal session data", zap.Error(err), zap.String("session_id", id.String()))
		return nil, err
	}

	return &session, nil
}

// Set сохраняет сессию в кэш
func (c *SessionCache) Set(ctx context.Context, session *models.Session) error {
	key := fmt.Sprintf("session:%s", session.ID.String())
	data, err := json.Marshal(session)
	if err != nil {
		c.logger.Error("Failed to marshal session data", zap.Error(err), zap.String("session_id", session.ID.String()))
		return err
	}

	// Вычисление TTL на основе времени истечения сессии
	ttl := c.ttl
	if !session.ExpiresAt.IsZero() {
		expiresIn := time.Until(session.ExpiresAt)
		if expiresIn > 0 {
			ttl = expiresIn
		}
	}

	err = c.client.Set(ctx, key, data, ttl).Err()
	if err != nil {
		c.logger.Error("Failed to set session in cache", zap.Error(err), zap.String("session_id", session.ID.String()))
		return err
	}

	// Добавление в индекс пользователя
	userKey := fmt.Sprintf("user:%s:sessions", session.UserID.String())
	err = c.client.SAdd(ctx, userKey, session.ID.String()).Err()
	if err != nil {
		c.logger.Error("Failed to add session to user index", 
			zap.Error(err), 
			zap.String("user_id", session.UserID.String()),
			zap.String("session_id", session.ID.String()),
		)
		return err
	}

	// Установка TTL для индекса пользователя
	err = c.client.Expire(ctx, userKey, ttl).Err()
	if err != nil {
		c.logger.Error("Failed to set TTL for user sessions index", 
			zap.Error(err), 
			zap.String("user_id", session.UserID.String()),
		)
	}

	return nil
}

// Delete удаляет сессию из кэша
func (c *SessionCache) Delete(ctx context.Context, id uuid.UUID) error {
	// Получение сессии для определения пользователя
	session, err := c.GetByID(ctx, id)
	if err != nil && err != models.ErrSessionNotFound {
		c.logger.Error("Failed to get session for deletion", zap.Error(err), zap.String("session_id", id.String()))
		return err
	}

	// Удаление сессии
	key := fmt.Sprintf("session:%s", id.String())
	err = c.client.Del(ctx, key).Err()
	if err != nil {
		c.logger.Error("Failed to delete session from cache", zap.Error(err), zap.String("session_id", id.String()))
		return err
	}

	// Удаление из индекса пользователя, если сессия была найдена
	if session != nil {
		userKey := fmt.Sprintf("user:%s:sessions", session.UserID.String())
		err = c.client.SRem(ctx, userKey, id.String()).Err()
		if err != nil {
			c.logger.Error("Failed to remove session from user index", 
				zap.Error(err), 
				zap.String("user_id", session.UserID.String()),
				zap.String("session_id", id.String()),
			)
			return err
		}
	}

	return nil
}

// DeleteAllByUserID удаляет все сессии пользователя из кэша
func (c *SessionCache) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) error {
	userKey := fmt.Sprintf("user:%s:sessions", userID.String())
	
	// Получение всех ID сессий пользователя
	sessionIDs, err := c.client.SMembers(ctx, userKey).Result()
	if err != nil {
		c.logger.Error("Failed to get user sessions from cache", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Удаление каждой сессии
	for _, sessionIDStr := range sessionIDs {
		key := fmt.Sprintf("session:%s", sessionIDStr)
		err = c.client.Del(ctx, key).Err()
		if err != nil {
			c.logger.Error("Failed to delete session from cache", zap.Error(err), zap.String("session_id", sessionIDStr))
		}
	}

	// Удаление индекса пользователя
	err = c.client.Del(ctx, userKey).Err()
	if err != nil {
		c.logger.Error("Failed to delete user sessions index", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	return nil
}

// DeactivateAllByUserID деактивирует все сессии пользователя в кэше
func (c *SessionCache) DeactivateAllByUserID(ctx context.Context, userID uuid.UUID) error {
	userKey := fmt.Sprintf("user:%s:sessions", userID.String())
	
	// Получение всех ID сессий пользователя
	sessionIDs, err := c.client.SMembers(ctx, userKey).Result()
	if err != nil {
		c.logger.Error("Failed to get user sessions from cache", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Деактивация каждой сессии
	for _, sessionIDStr := range sessionIDs {
		key := fmt.Sprintf("session:%s", sessionIDStr)
		data, err := c.client.Get(ctx, key).Bytes()
		if err != nil {
			if err != redis.Nil {
				c.logger.Error("Failed to get session from cache", zap.Error(err), zap.String("session_id", sessionIDStr))
			}
			continue
		}

		var session models.Session
		err = json.Unmarshal(data, &session)
		if err != nil {
			c.logger.Error("Failed to unmarshal session data", zap.Error(err), zap.String("session_id", sessionIDStr))
			continue
		}

		// Деактивация сессии
		session.IsActive = false
		session.UpdatedAt = time.Now()

		// Сохранение обновленной сессии
		updatedData, err := json.Marshal(session)
		if err != nil {
			c.logger.Error("Failed to marshal session data", zap.Error(err), zap.String("session_id", sessionIDStr))
			continue
		}

		// Вычисление TTL
		ttl := c.ttl
		if !session.ExpiresAt.IsZero() {
			expiresIn := time.Until(session.ExpiresAt)
			if expiresIn > 0 {
				ttl = expiresIn
			}
		}

		err = c.client.Set(ctx, key, updatedData, ttl).Err()
		if err != nil {
			c.logger.Error("Failed to update session in cache", zap.Error(err), zap.String("session_id", sessionIDStr))
		}
	}

	return nil
}
