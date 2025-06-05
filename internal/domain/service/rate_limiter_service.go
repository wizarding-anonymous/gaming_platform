// File: internal/domain/service/rate_limiter_service.go
package service // Or potentially domain_service, matching other interfaces

import (
	"context"
	"time"
)

// RateLimiter defines the interface for a rate limiting service.
type RateLimiter interface {
	// Allow checks if an action identified by key is allowed under the given limit and window.
	// It should also increment the counter for the key.
	// Returns true if allowed, false if denied (rate limit exceeded).
	// Returns an error if the underlying operation (e.g., Redis communication) fails.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)

	// Check returns the current count for a key without incrementing.
	// Useful for checks before attempting an action that shouldn't always increment the counter.
	// Returns error if the underlying operation fails.
	Check(ctx context.Context, key string) (int, error)

	// Reset resets the counter for a key.
	// Useful for scenarios like successful 2FA verification.
	// Returns error if the underlying operation fails.
	Reset(ctx context.Context, key string) error
}
