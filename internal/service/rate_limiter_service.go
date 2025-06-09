// File: internal/service/rate_limiter_service.go
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8" // Assuming v8, adjust if different
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/utils/logger" // Assuming a logger interface here
)

// RateLimiter defines the interface for a rate limiting service.
type RateLimiter interface {
	// Allow checks if an action identified by key is allowed under the given limit and window.
	// It should also increment the counter for the key.
	// Returns true if allowed, false if denied. Error if Redis operation fails.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)

	// Check returns the current count for a key without incrementing.
	// Useful for checks before attempting an action that shouldn't always increment.
	Check(ctx context.Context, key string) (int, error)

	// Reset resets the counter for a key.
	Reset(ctx context.Context, key string) error
}

type redisRateLimiter struct {
	redisClient *redis.Client
	cfg         config.RateLimitConfig // General rate limiting config (enabled, defaults)
	logger      logger.Logger
}

// NewRedisRateLimiter creates a new Redis-backed RateLimiter.
func NewRedisRateLimiter(redisClient *redis.Client, cfg config.RateLimitConfig, logger logger.Logger) RateLimiter {
	return &redisRateLimiter{
		redisClient: redisClient,
		cfg:         cfg,
		logger:      logger,
	}
}

// Allow implements the RateLimiter interface using a sliding window log algorithm (simplified via INCR + EXPIRE).
// This is a common and relatively simple way to implement rate limiting with Redis.
// For very high precision, a sorted set based approach might be used for a true sliding window.
func (r *redisRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if !r.cfg.Enabled { // Global toggle for all rate limiting
		return true, nil
	}

	// Use a pipeline for atomic INCR and EXPIRE (if new key)
	pipe := r.redisClient.Pipeline()
	incr := pipe.Incr(ctx, key)
	// Set expiry only if it's a new key (count is 1 after INCR)
	// This needs to be conditional, or EXPIRE called every time.
	// Calling EXPIRE every time is simpler and generally fine for Redis.
	pipe.Expire(ctx, key, window)

	_, err := pipe.Exec(ctx)
	if err != nil {
		r.logger.Error("Redis pipeline for rate limiting failed", "key", key, "error", err)
		// Fail open or closed? For security, often fail closed (deny request).
		// However, if Redis is down, this makes the app unusable.
		// For now, let's fail open on Redis error but log it heavily.
		// A production system might have a circuit breaker or stricter fail-closed.
		return true, fmt.Errorf("redis operation failed during rate limit check: %w", err)
	}

	currentCount := incr.Val()

	if currentCount > int64(limit) {
		r.logger.Warn("Rate limit exceeded", "key", key, "count", currentCount, "limit", limit)
		return false, nil // Deny
	}

	return true, nil // Allow
}

// Check returns the current count for a key.
func (r *redisRateLimiter) Check(ctx context.Context, key string) (int, error) {
	if !r.cfg.Enabled {
		return 0, nil // No limit applied
	}
	count, err := r.redisClient.Get(ctx, key).Int()
	if err == redis.Nil {
		return 0, nil // Key doesn't exist, so count is 0
	}
	if err != nil {
		r.logger.Error("Redis GET for rate limit check failed", "key", key, "error", err)
		return 0, fmt.Errorf("redis GET failed: %w", err)
	}
	return count, nil
}

// Reset explicitly deletes a rate limiting key.
func (r *redisRateLimiter) Reset(ctx context.Context, key string) error {
	if !r.cfg.Enabled {
		return nil
	}
	if err := r.redisClient.Del(ctx, key).Err(); err != nil {
		r.logger.Error("Redis DEL for rate limit reset failed", "key", key, "error", err)
		return fmt.Errorf("redis DEL failed: %w", err)
	}
	r.logger.Info("Rate limit key reset", "key", key)
	return nil
}

// Ensure redisRateLimiter implements RateLimiter
var _ RateLimiter = (*redisRateLimiter)(nil)
