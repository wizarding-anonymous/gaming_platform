package repository

import (
	"context"
	"time"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// MFABackupCodeRepository defines the interface for interacting with MFA backup code data.
type MFABackupCodeRepository interface {
	// Create persists a new MFA backup code to the database.
	Create(ctx context.Context, code *entity.MFABackupCode) error

	// CreateMultiple persists a batch of new MFA backup codes to the database,
	// typically within a transaction.
	CreateMultiple(ctx context.Context, codes []*entity.MFABackupCode) error

	// FindByUserIDAndCodeHash retrieves an MFA backup code by the user's ID and the hashed code.
	// This is used to validate a backup code provided by a user.
	// Returns entity.ErrMFABackupCodeNotFound if not found.
	FindByUserIDAndCodeHash(ctx context.Context, userID string, codeHash string) (*entity.MFABackupCode, error)

	// MarkAsUsed marks a specific backup code (by its ID or by UserID and CodeHash) as used.
	MarkAsUsed(ctx context.Context, id string, usedAt time.Time) error
	// Alternatively, or additionally:
	// MarkAsUsedByCodeHash(ctx context.Context, userID string, codeHash string, usedAt time.Time) error


	// DeleteByUserID removes all backup codes for a given user ID.
	// This is typically done when MFA is disabled or when new codes are generated.
	DeleteByUserID(ctx context.Context, userID string) error

	// CountActiveByUserID counts the number of unused backup codes for a user.
	CountActiveByUserID(ctx context.Context, userID string) (int, error)
}

// Note: entity.ErrMFABackupCodeNotFound would be a custom error.
// Define in an appropriate error definitions file.
// Example:
// package entity
// import "errors"
// var ErrMFABackupCodeNotFound = errors.New("mfa backup code not found")
