// File: backend/services/auth-service/internal/domain/repository/api_key_repository.go
package repository

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors" // Ensure this import
)

// APIKeyRepository defines the interface for interacting with API key data.
type APIKeyRepository interface {
	// Create persists a new API key to the database.
	Create(ctx context.Context, apiKey *models.APIKey) error

	// FindByID retrieves an API key by its unique ID.
	// For security, it might be better to always require userID if the key is user-specific.
	// However, a global admin might need to fetch by ID directly.
	// Consider if userID should be optional or if there should be two methods.
	FindByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error)

	// FindByUserIDAndID retrieves an API key by its ID, ensuring it belongs to the specified userID.
	// Returns domainErrors.ErrNotFound if not found or if userID does not match.
	FindByUserIDAndID(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*models.APIKey, error)

	// FindByKeyPrefix retrieves an API key by its unique key prefix.
	// This is used for initial lookup before hash comparison.
	// Returns domainErrors.ErrNotFound if not found.
	FindByKeyPrefix(ctx context.Context, prefix string) (*models.APIKey, error)
	
	// FindByPrefixAndHash retrieves an active API key by its prefix and the hash of its secret part.
	// This is the primary method for authenticating an API key.
	// Returns domainErrors.ErrNotFound if not found, hash doesn't match, or key is revoked/expired.
	// Note: This method implies the repository has access to the raw key for hashing,
	// or more likely, the hash is passed in. The latter is correct.
	FindByPrefixAndHash(ctx context.Context, prefix string, keyHash string) (*models.APIKey, error)

	// ListByUserID retrieves all API key metadata (excluding key_hash) for a specific user ID.
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error)

	// UpdateLastUsedAt updates the last_used_at timestamp for an API key by its ID.
	UpdateLastUsedAt(ctx context.Context, id uuid.UUID, lastUsedAt time.Time) error
	
	// UpdateNameAndPermissions updates the name and permissions of an API key.
	// Ensures key belongs to userID.
	UpdateNameAndPermissions(ctx context.Context, id uuid.UUID, userID uuid.UUID, name string, permissions json.RawMessage) error

	// Revoke marks an API key as revoked by setting revoked_at.
	// Ensures the key belongs to the specified userID before revoking.
	Revoke(ctx context.Context, id uuid.UUID, userID uuid.UUID, revokedAt time.Time) error

	// Delete removes an API key from the database by its ID.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteByUserID removes all API keys for a specific user ID.
	// Returns the number of keys deleted and an error if any.
	DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error)
	
	// DeleteExpiredAndRevoked removes API keys that are past their expires_at
	// or have been revoked for a certain period.
	DeleteExpiredAndRevoked(ctx context.Context, olderThanRevokedPeriod time.Duration) (int64, error)
}

// Note: domainErrors.ErrNotFound or a specific ErrAPIKeyNotFound should be used.