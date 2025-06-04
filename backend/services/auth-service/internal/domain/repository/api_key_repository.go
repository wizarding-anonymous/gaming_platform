package repository

import (
	"context"
	"time"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// APIKeyRepository defines the interface for interacting with API key data.
type APIKeyRepository interface {
	// Create persists a new API key to the database.
	Create(ctx context.Context, apiKey *entity.APIKey) error

	// FindByID retrieves an API key by its unique ID, ensuring it belongs to the specified userID.
	// Returns entity.ErrAPIKeyNotFound if not found or if userID does not match.
	FindByID(ctx context.Context, id string, userID string) (*entity.APIKey, error)

	// FindByKeyPrefix retrieves an API key by its unique key prefix.
	// This can be used for quick lookups if the prefix is indexed.
	// Note: This method alone is not sufficient for authentication as it doesn't verify the secret.
	// Returns entity.ErrAPIKeyNotFound if not found.
	FindByKeyPrefix(ctx context.Context, prefix string) (*entity.APIKey, error)
	
	// FindByPrefixAndHash retrieves an API key by its prefix and the hash of its secret part.
	// This is the primary method for authenticating an API key.
	// Returns entity.ErrAPIKeyNotFound if not found or if hash doesn't match.
	FindByPrefixAndHash(ctx context.Context, prefix string, hash string) (*entity.APIKey, error)

	// ListByUserID retrieves all API key metadata (excluding key_hash) associated with a specific user ID.
	// Should allow for pagination in a real application.
	ListByUserID(ctx context.Context, userID string) ([]*entity.APIKey, error)

	// UpdateLastUsedAt updates the last_used_at timestamp for an API key by its ID.
	UpdateLastUsedAt(ctx context.Context, id string) error // Will use time.Now() internally
	
	// UpdateNameAndPermissions updates the name and permissions of an API key.
	// Ensures key belongs to userID.
	UpdateNameAndPermissions(ctx context.Context, id string, userID string, name string, permissions []byte) error // permissions as json.RawMessage

	// Revoke marks an API key as revoked by setting revoked_at.
	// Ensures the key belongs to the specified userID before revoking.
	Revoke(ctx context.Context, id string, userID string) error // Will use time.Now() internally for revoked_at

	// Delete removes an API key from the database.
	// This should typically be used for keys that are already revoked and/or expired.
	// Ensures key belongs to userID or is globally admin-deleted.
	Delete(ctx context.Context, id string) error
	
	// DeleteExpiredAndRevoked removes API keys that are past their expires_at
	// or have been revoked for a certain period.
	DeleteExpiredAndRevoked(ctx context.Context, olderThanRevoked time.Duration) (int64, error)
}

// Note: entity.ErrAPIKeyNotFound would be a custom error.
// Define in an appropriate error definitions file.
// Example:
// package entity
// import "errors"
// var ErrAPIKeyNotFound = errors.New("api key not found")