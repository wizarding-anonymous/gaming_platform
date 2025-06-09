// File: internal/infrastructure/ratelimit/redis_rate_limiter.go
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/service" // For the RateLimiter interface
	"github.com/your-org/auth-service/internal/utils/logger"   // Assuming a logger interface
)

type redisRateLimiter struct {
	redisClient *redis.Client
	cfg         config.RateLimitConfig // General rate limiting config (enabled, defaults)
	logger      logger.Logger
}

// NewRedisRateLimiter creates a new Redis-backed RateLimiter.
// The main cfg.RateLimiting is passed, specific rules are used by callers.
func NewRedisRateLimiter(redisClient *redis.Client, cfg config.RateLimitConfig, logger logger.Logger) service.RateLimiter {
	return &redisRateLimiter{
		redisClient: redisClient,
		cfg:         cfg, // Store the specific RateLimiting part of the config
		logger:      logger,
	}
}

// Allow implements the RateLimiter interface using Redis INCR and EXPIRE.
func (r *redisRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if !r.cfg.Enabled { // Global toggle for all rate limiting from config
		return true, nil
	}
	if limit <= 0 { // If a specific rule has limit 0 or less, effectively disabled for that rule
		return true, nil
	}

	// Use a pipeline for atomic INCR and EXPIRE on first increment
	var currentCount int64
	var err error

	_, err = r.redisClient.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		// Increment the counter for the key
		incrResult := pipe.Incr(ctx, key)
		// Set expiry only if it's a new key (count is 1 after INCR)
		// This happens atomically within the transaction.
		// If the key exists, INCR updates it. If not, INCR sets it to 1.
		// Then, if current value is 1, set the expiry.
		// This is slightly complex with INCR result being available only after Exec.
		// A common approach is to always set EXPIRE. Redis handles it efficiently.
		pipe.Expire(ctx, key, window)

		// CurrentCount will be set after Exec
		currentCount = incrResult.Val() // This will be 0 before Exec, need to get it after
		return nil // No error from pipeline func itself unless a command is wrongly formatted
	})

	// After pipe.Exec(), INCR command's result is available.
	// To get the actual count returned by INCR, we'd need to re-fetch or use Lua script for atomicity.
	// Simpler: Get the count after INCR. If INCR itself fails, err will be non-nil.
	// If pipe.Exec() fails, it's a Redis communication issue.
	if err != nil {
		r.logger.Error("Redis pipeline for rate limiting failed", "key", key, "error", err)
		// Fail open on Redis error to avoid blocking all actions if Redis is temporarily down.
		// Log an error and allow the action. A circuit breaker could be used here.
		return true, fmt.Errorf("redis operation failed during rate limit check: %w", err)
	}

	// Re-fetch the count after INCR and EXPIRE have been pipelined.
	// This is not ideal as it's another round trip, but simpler than Lua for now.
	// For high-performance, a Lua script is recommended for atomic INCR, EXPIRE (if new), and GET.
	currentVal, getErr := r.redisClient.Get(ctx, key).Int64()
	if getErr != nil && getErr != redis.Nil {
		r.logger.Error("Redis GET after INCR for rate limiting failed", "key", key, "error", getErr)
		return true, fmt.Errorf("redis GET operation failed: %w", getErr)
	}
	if getErr == redis.Nil { // Should not happen if INCR succeeded
		currentVal = 1 // Assume it was set to 1 by INCR
	}


	if currentVal > int64(limit) {
		r.logger.Warn("Rate limit exceeded", "key", key, "count", currentVal, "limit", limit)
		return false, nil // Deny
	}

	return true, nil // Allow
}

// Check returns the current count for a key.
func (r *redisRateLimiter) Check(ctx context.Context, key string) (int, error) {
	if !r.cfg.Enabled {
		return 0, nil
	}
	count, err := r.redisClient.Get(ctx, key).Int()
	if err == redis.Nil {
		return 0, nil
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
var _ service.RateLimiter = (*redisRateLimiter)(nil)
