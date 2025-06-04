package repository

import (
	"context"
	"time"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// RefreshTokenRepository defines the interface for interacting with refresh token data.
type RefreshTokenRepository interface {
	// Create persists a new refresh token to the database.
	Create(ctx context.Context, token *entity.RefreshToken) error

	// FindByID retrieves a refresh token by its unique ID.
	// Returns entity.ErrRefreshTokenNotFound if not found.
	FindByID(ctx context.Context, id string) (*entity.RefreshToken, error)

	// FindByTokenHash retrieves a refresh token by its hashed value.
	// This is crucial for validating incoming refresh tokens.
	// Returns entity.ErrRefreshTokenNotFound if not found.
	FindByTokenHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error)

	// FindBySessionID retrieves refresh tokens associated with a session ID.
	// Typically, there should be one active refresh token per session.
	FindBySessionID(ctx context.Context, sessionID string) (*entity.RefreshToken, error) // Or []*entity.RefreshToken if multiple allowed by logic

	// Revoke marks a refresh token as revoked by setting revoked_at and revoked_reason.
	Revoke(ctx context.Context, id string, revokedAt time.Time, reason string) error
	
	// Delete removes a refresh token by its ID.
	// Generally, revoking is preferred over hard deleting for auditability,
	// but a delete might be used for cleanup of very old, revoked tokens.
	Delete(ctx context.Context, id string) error

	// DeleteBySessionID removes all refresh tokens associated with a given session ID.
	// Useful when a session is explicitly terminated.
	DeleteBySessionID(ctx context.Context, sessionID string) error

	// DeleteExpiredAndRevoked removes refresh tokens that are past their expires_at
	// or have been revoked for a certain period.
	// Returns the number of tokens deleted.
	DeleteExpiredAndRevoked(ctx context.Context, olderThanRevoked time.Duration) (int64, error)
}

// Note: entity.ErrRefreshTokenNotFound would be a custom error.
// Define in an appropriate error definitions file.
// Example:
// package entity
// import "errors"
// var ErrRefreshTokenNotFound = errors.New("refresh token not found")