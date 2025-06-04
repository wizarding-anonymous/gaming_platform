package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors" // Ensure this import
)

// ExternalAccountRepository defines the interface for interacting with external account data
// (e.g., accounts linked via OAuth providers like Google, Telegram).
type ExternalAccountRepository interface {
	// Create persists a new external account link to the database.
	Create(ctx context.Context, acc *models.ExternalAccount) error

	// FindByID retrieves an external account link by its unique ID.
	// Returns domainErrors.ErrNotFound (or specific error) if not found.
	FindByID(ctx context.Context, id uuid.UUID) (*models.ExternalAccount, error)

	// FindByProviderAndExternalID retrieves an external account link by the provider name
	// and the user's ID on that external provider.
	// Returns domainErrors.ErrNotFound (or specific error) if not found.
	FindByProviderAndExternalID(ctx context.Context, provider string, externalUserID string) (*models.ExternalAccount, error)

	// FindByUserID retrieves all external accounts linked to a specific user ID.
	FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.ExternalAccount, error)

	// FindByUserIDAndProvider retrieves a specific external account link for a user by provider.
	// Returns domainErrors.ErrNotFound (or specific error) if not found.
	FindByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) (*models.ExternalAccount, error)

	// Update modifies details of an existing external account link (e.g., tokens, profile_data).
	Update(ctx context.Context, acc *models.ExternalAccount) error

	// Delete removes an external account link by its ID.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteByUserIDAndProvider removes a specific external account link for a user and provider.
	DeleteByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) error
}

// Note: domainErrors.ErrNotFound or a specific ErrExternalAccountNotFound should be used.
