package repository

import (
	"context"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// MFASecretRepository defines the interface for interacting with MFA secret data (e.g., TOTP secrets).
type MFASecretRepository interface {
	// Create persists a new MFA secret to the database.
	Create(ctx context.Context, secret *entity.MFASecret) error

	// FindByUserID retrieves the active MFA secret for a given user ID.
	// It's common to assume only one active MFA secret of a particular type (e.g., TOTP) per user.
	// Returns entity.ErrMFASecretNotFound if no secret is found.
	FindByUserID(ctx context.Context, userID string) (*entity.MFASecret, error)

	// FindByUserIDAndType retrieves an MFA secret for a specific user and MFA type.
	// Returns entity.ErrMFASecretNotFound if not found.
	FindByUserIDAndType(ctx context.Context, userID string, mfaType entity.MFAType) (*entity.MFASecret, error)

	// Update modifies an existing MFA secret (e.g., to mark it as verified or update the secret key).
	Update(ctx context.Context, secret *entity.MFASecret) error

	// DeleteByUserID removes all MFA secrets for a given user ID.
	DeleteByUserID(ctx context.Context, userID string) error
	
	// DeleteByUserIDAndType removes a specific type of MFA secret for a user.
	DeleteByUserIDAndType(ctx context.Context, userID string, mfaType entity.MFAType) error
}

// Note: entity.ErrMFASecretNotFound would be a custom error.
// Define in an appropriate error definitions file.
// Example:
// package entity
// import "errors"
// var ErrMFASecretNotFound = errors.New("mfa secret not found")
