// File: internal/repository/redis/token_cache.go

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"go.uber.org/zap"
)

// TokenCache представляет кэш токенов в Redis
type TokenCache struct {
	client *redis.Client
	logger *zap.Logger
	ttl    time.Duration
}

// NewTokenCache создает новый экземпляр TokenCache
func NewTokenCache(client *redis.Client, logger *zap.Logger, ttl time.Duration) *TokenCache {
	return &TokenCache{
		client: client,
		logger: logger,
		ttl:    ttl,
	}
}

// GetByValue получает токен по значению из кэша
func (c *TokenCache) GetByValue(ctx context.Context, value string) (*models.Token, error) {
	key := fmt.Sprintf("token:value:%s", value)
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, models.ErrTokenNotFound
		}
		c.logger.Error("Failed to get token from cache", zap.Error(err))
		return nil, err
	}

	var token models.Token
	err = json.Unmarshal(data, &token)
	if err != nil {
		c.logger.Error("Failed to unmarshal token data", zap.Error(err))
		return nil, err
	}

	return &token, nil
}

// GetByID получает токен по ID из кэша
func (c *TokenCache) GetByID(ctx context.Context, id uuid.UUID) (*models.Token, error) {
	key := fmt.Sprintf("token:id:%s", id.String())
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, models.ErrTokenNotFound
		}
		c.logger.Error("Failed to get token from cache", zap.Error(err), zap.String("token_id", id.String()))
		return nil, err
	}

	var token models.Token
	err = json.Unmarshal(data, &token)
	if err != nil {
		c.logger.Error("Failed to unmarshal token data", zap.Error(err), zap.String("token_id", id.String()))
		return nil, err
	}

	return &token, nil
}

// Set сохраняет токен в кэш
func (c *TokenCache) Set(ctx context.Context, token *models.Token) error {
	data, err := json.Marshal(token)
	if err != nil {
		c.logger.Error("Failed to marshal token data", zap.Error(err), zap.String("token_id", token.ID.String()))
		return err
	}

	// Вычисление TTL на основе времени истечения токена
	ttl := c.ttl
	if !token.ExpiresAt.IsZero() {
		expiresIn := time.Until(token.ExpiresAt)
		if expiresIn > 0 {
			ttl = expiresIn
		}
	}

	// Сохранение по ID
	idKey := fmt.Sprintf("token:id:%s", token.ID.String())
	err = c.client.Set(ctx, idKey, data, ttl).Err()
	if err != nil {
		c.logger.Error("Failed to set token in cache by ID", zap.Error(err), zap.String("token_id", token.ID.String()))
		return err
	}

	// Сохранение по значению
	valueKey := fmt.Sprintf("token:value:%s", token.TokenValue)
	err = c.client.Set(ctx, valueKey, data, ttl).Err()
	if err != nil {
		c.logger.Error("Failed to set token in cache by value", zap.Error(err), zap.String("token_id", token.ID.String()))
		return err
	}

	// Добавление в индекс пользователя
	userKey := fmt.Sprintf("user:%s:tokens", token.UserID.String())
	err = c.client.SAdd(ctx, userKey, token.ID.String()).Err()
	if err != nil {
		c.logger.Error("Failed to add token to user index", 
			zap.Error(err), 
			zap.String("user_id", token.UserID.String()),
			zap.String("token_id", token.ID.String()),
		)
		return err
	}

	// Установка TTL для индекса пользователя
	err = c.client.Expire(ctx, userKey, ttl).Err()
	if err != nil {
		c.logger.Error("Failed to set TTL for user tokens index", 
			zap.Error(err), 
			zap.String("user_id", token.UserID.String()),
		)
	}

	// Добавление в черный список, если токен отозван
	if token.Revoked {
		blacklistKey := fmt.Sprintf("blacklist:token:%s", token.TokenValue)
		err = c.client.Set(ctx, blacklistKey, "1", ttl).Err()
		if err != nil {
			c.logger.Error("Failed to add token to blacklist", zap.Error(err), zap.String("token_id", token.ID.String()))
			return err
		}
	}

	return nil
}

// Delete удаляет токен из кэша
func (c *TokenCache) Delete(ctx context.Context, token *models.Token) error {
	// Удаление по ID
	idKey := fmt.Sprintf("token:id:%s", token.ID.String())
	err := c.client.Del(ctx, idKey).Err()
	if err != nil {
		c.logger.Error("Failed to delete token from cache by ID", zap.Error(err), zap.String("token_id", token.ID.String()))
		return err
	}

	// Удаление по значению
	valueKey := fmt.Sprintf("token:value:%s", token.TokenValue)
	err = c.client.Del(ctx, valueKey).Err()
	if err != nil {
		c.logger.Error("Failed to delete token from cache by value", zap.Error(err), zap.String("token_id", token.ID.String()))
		return err
	}

	// Удаление из индекса пользователя
	userKey := fmt.Sprintf("user:%s:tokens", token.UserID.String())
	err = c.client.SRem(ctx, userKey, token.ID.String()).Err()
	if err != nil {
		c.logger.Error("Failed to remove token from user index", 
			zap.Error(err), 
			zap.String("user_id", token.UserID.String()),
			zap.String("token_id", token.ID.String()),
		)
		return err
	}

	return nil
}

// IsRevoked проверяет, отозван ли токен
func (c *TokenCache) IsRevoked(ctx context.Context, tokenValue string) (bool, error) {
	blacklistKey := fmt.Sprintf("blacklist:token:%s", tokenValue)
	exists, err := c.client.Exists(ctx, blacklistKey).Result()
	if err != nil {
		c.logger.Error("Failed to check if token is revoked", zap.Error(err))
		return false, err
	}

	return exists > 0, nil
}

// RevokeToken отзывает токен
func (c *TokenCache) RevokeToken(ctx context.Context, tokenValue string) error {
	// Получение токена по значению
	token, err := c.GetByValue(ctx, tokenValue)
	if err != nil && err != models.ErrTokenNotFound {
		c.logger.Error("Failed to get token for revocation", zap.Error(err))
		return err
	}

	// Если токен найден, обновляем его
	if token != nil {
		token.Revoked = true
		token.RevokedAt = time.Now()

		// Сохранение обновленного токена
		err = c.Set(ctx, token)
		if err != nil {
			c.logger.Error("Failed to update token in cache", zap.Error(err), zap.String("token_id", token.ID.String()))
			return err
		}
	}

	// В любом случае добавляем в черный список
	blacklistKey := fmt.Sprintf("blacklist:token:%s", tokenValue)
	
	// Определение TTL
	ttl := c.ttl
	if token != nil && !token.ExpiresAt.IsZero() {
		expiresIn := time.Until(token.ExpiresAt)
		if expiresIn > 0 {
			ttl = expiresIn
		}
	}

	err = c.client.Set(ctx, blacklistKey, "1", ttl).Err()
	if err != nil {
		c.logger.Error("Failed to add token to blacklist", zap.Error(err))
		return err
	}

	return nil
}

// RevokeAllUserTokens отзывает все токены пользователя
func (c *TokenCache) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	userKey := fmt.Sprintf("user:%s:tokens", userID.String())
	
	// Получение всех ID токенов пользователя
	tokenIDs, err := c.client.SMembers(ctx, userKey).Result()
	if err != nil {
		c.logger.Error("Failed to get user tokens from cache", zap.Error(err), zap.String("user_id", userID.String()))
		return err
	}

	// Отзыв каждого токена
	for _, tokenIDStr := range tokenIDs {
		tokenID, err := uuid.Parse(tokenIDStr)
		if err != nil {
			c.logger.Error("Failed to parse token ID", zap.Error(err), zap.String("token_id", tokenIDStr))
			continue
		}

		token, err := c.GetByID(ctx, tokenID)
		if err != nil {
			if err != models.ErrTokenNotFound {
				c.logger.Error("Failed to get token from cache", zap.Error(err), zap.String("token_id", tokenIDStr))
			}
			continue
		}

		// Отзыв токена
		token.Revoked = true
		token.RevokedAt = time.Now()

		// Сохранение обновленного токена
		err = c.Set(ctx, token)
		if err != nil {
			c.logger.Error("Failed to update token in cache", zap.Error(err), zap.String("token_id", tokenIDStr))
			continue
		}

		// Добавление в черный список
		blacklistKey := fmt.Sprintf("blacklist:token:%s", token.TokenValue)
		
		// Определение TTL
		ttl := c.ttl
		if !token.ExpiresAt.IsZero() {
			expiresIn := time.Until(token.ExpiresAt)
			if expiresIn > 0 {
				ttl = expiresIn
			}
		}

		err = c.client.Set(ctx, blacklistKey, "1", ttl).Err()
		if err != nil {
			c.logger.Error("Failed to add token to blacklist", zap.Error(err), zap.String("token_id", tokenIDStr))
		}
	}

	return nil
}
