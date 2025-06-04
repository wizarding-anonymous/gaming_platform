package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors" // Ensure this import is present
)

// RefreshTokenRepository defines the interface for interacting with refresh token data.
type RefreshTokenRepository interface {
	// Create persists a new refresh token to the database.
	Create(ctx context.Context, token *models.RefreshToken) error

	// FindByID retrieves a refresh token by its unique ID.
	// Returns domainErrors.ErrNotFound (or a specific ErrRefreshTokenNotFound) if not found.
	FindByID(ctx context.Context, id uuid.UUID) (*models.RefreshToken, error)

	// FindByTokenHash retrieves an active refresh token by its hashed value.
	// Returns domainErrors.ErrNotFound (or a specific ErrRefreshTokenNotFound) if not found or not active.
	FindByTokenHash(ctx context.Context, tokenHash string) (*models.RefreshToken, error)

	// FindBySessionID retrieves the active refresh token associated with a session ID.
	// Returns domainErrors.ErrNotFound if not found or not active.
	FindBySessionID(ctx context.Context, sessionID uuid.UUID) (*models.RefreshToken, error)

	// Revoke marks a refresh token as revoked by setting revoked_at and revoked_reason.
	Revoke(ctx context.Context, id uuid.UUID, reason *string) error
	
	// Delete removes a refresh token by its ID.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteBySessionID removes all refresh tokens associated with a given session ID.
	DeleteBySessionID(ctx context.Context, sessionID uuid.UUID) error

	// DeleteByUserID removes all refresh tokens for a specific user.
	// Returns the number of tokens deleted.
	DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error)

	// DeleteExpiredAndRevoked removes refresh tokens that are past their expires_at
	// or have been revoked for a certain period.
	// Returns the number of tokens deleted.
	// olderThanRevokedPeriod defines the minimum duration a token must have been revoked for to be deleted.
	// e.g., if a token was revoked 1 day ago and olderThanRevokedPeriod is 7 days, it won't be deleted.
	// Pass a zero duration for olderThanRevokedPeriod to delete all revoked tokens irrespective of when they were revoked.
	DeleteExpiredAndRevoked(ctx context.Context, olderThanRevokedPeriod time.Duration) (int64, error)
}
// Note: Using "github.com/your-org/auth-service/internal/domain/models" for models.
// Ensure domainErrors.ErrNotFound or a specific ErrRefreshTokenNotFound is available.