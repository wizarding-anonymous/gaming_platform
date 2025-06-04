package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models" // Updated import path
)

// MFASecretRepository defines the interface for interacting with MFA secret data (e.g., TOTP secrets).
type MFASecretRepository interface {
	// Create persists a new MFA secret to the database.
	Create(ctx context.Context, secret *models.MFASecret) error

	// FindByID retrieves an MFA secret by its primary ID.
	// Returns domainErrors.ErrNotFound if not found.
	FindByID(ctx context.Context, id uuid.UUID) (*models.MFASecret, error)

	// FindByUserIDAndType retrieves an MFA secret for a specific user and MFA type.
	// Returns domainErrors.ErrNotFound (or specific error) if not found.
	FindByUserIDAndType(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) (*models.MFASecret, error)

	// Update modifies an existing MFA secret (e.g., to mark it as verified or update the secret key).
	// The ID of the secret must be set in the models.MFASecret object.
	Update(ctx context.Context, secret *models.MFASecret) error

	// DeleteByUserIDAndType removes a specific type of MFA secret for a user.
	DeleteByUserIDAndType(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) error

	// DeleteAllForUser removes all MFA secrets for a given user ID.
	// This might be used when a user wants to reset all their MFA configurations.
	DeleteAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) // Returns number of secrets deleted

	// DeleteByUserIDAndTypeIfUnverified removes a specific type of MFA secret for a user ONLY if it's not verified.
	// Returns true if a record was deleted, false otherwise.
	DeleteByUserIDAndTypeIfUnverified(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) (bool, error)
}

// Note: domainErrors.ErrNotFound or a specific ErrMFASecretNotFound should be used.
// The original FindByUserID(userID string) was potentially ambiguous if multiple types were allowed.
// FindByUserIDAndType is more explicit.
