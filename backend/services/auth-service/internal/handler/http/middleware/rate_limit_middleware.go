// File: backend/services/auth-service/internal/handler/http/middleware/rate_limit_middleware.go
package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service" // For RateLimiter interface
	"go.uber.org/zap"
)

// RateLimiterInterface defines the contract for a rate limiter.
// This should be compatible with the one provided by redis.NewRedisRateLimiter.
// Based on main.go, the redis.RedisRateLimiter has a method:
// Allow(ctx context.Context, key string, rule config.RateLimitRule) (bool, error)
// So, the middleware will need the context, key, and the specific rule.
type RateLimiterInterface interface {
	Allow(ctx *gin.Context, key string, rule config.RateLimitRule) (bool, error)
}

// RateLimitMiddleware creates a Gin middleware for rate limiting.
// It uses a specific RateLimitRule from the configuration.
func RateLimitMiddleware(limiter RateLimiterInterface, rule config.RateLimitRule, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rule.Enabled {
			c.Next()
			return
		}

		// Use ClientIP as the primary key for rate limiting.
		// For authenticated routes, this could be enhanced to use UserID if available.
		key := c.ClientIP()

		allowed, err := limiter.Allow(c, key, rule)
		if err != nil {
			logger.Error("Rate limiter failed", zap.Error(err), zap.String("key", key))
			// Depending on policy, might allow request or deny on limiter error.
			// For now, denying to be safe.
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "rate limiter error"})
			return
		}

		if !allowed {
			logger.Warn("Rate limit exceeded",
				zap.String("key", key),
				zap.Int("limit", rule.Limit),
				zap.Duration("window", rule.Window),
			)
			// Optionally, set "Retry-After" header.
			// c.Header("Retry-After", fmt.Sprintf("%.0f", rule.Window.Seconds()))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
			return
		}

		c.Next()
	}
}
