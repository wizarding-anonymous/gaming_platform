package repository

import (
	"context"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// ExternalAccountRepository defines the interface for interacting with external account data
// (e.g., accounts linked via OAuth providers like Google, Telegram).
type ExternalAccountRepository interface {
	// Create persists a new external account link to the database.
	Create(ctx context.Context, acc *entity.ExternalAccount) error

	// FindByID retrieves an external account link by its unique ID.
	// Returns entity.ErrExternalAccountNotFound if not found.
	FindByID(ctx context.Context, id string) (*entity.ExternalAccount, error)

	// FindByProviderAndExternalID retrieves an external account link by the provider name
	// and the user's ID on that external provider.
	// Returns entity.ErrExternalAccountNotFound if not found.
	FindByProviderAndExternalID(ctx context.Context, provider string, externalUserID string) (*entity.ExternalAccount, error)

	// FindByUserID retrieves all external accounts linked to a specific user ID.
	FindByUserID(ctx context.Context, userID string) ([]*entity.ExternalAccount, error)

	// FindByUserIDAndProvider retrieves a specific external account link for a user by provider.
	// Returns entity.ErrExternalAccountNotFound if not found.
	FindByUserIDAndProvider(ctx context.Context, userID string, provider string) (*entity.ExternalAccount, error)

	// Update modifies details of an existing external account link (e.g., tokens, profile_data).
	Update(ctx context.Context, acc *entity.ExternalAccount) error

	// Delete removes an external account link by its ID.
	Delete(ctx context.Context, id string) error

	// DeleteByUserIDAndProvider removes a specific external account link for a user.
	DeleteByUserIDAndProvider(ctx context.Context, userID string, provider string) error
}

// Note: entity.ErrExternalAccountNotFound would be a custom error.
// Define in an appropriate error definitions file.
// Example:
// package entity
// import "errors"
// var ErrExternalAccountNotFound = errors.New("external account not found")
