// File: backend/services/auth-service/internal/domain/repository/mfa_backup_code_repository.go
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors" // Ensure this import
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

// MFABackupCodeRepository defines the interface for interacting with MFA backup code data.
type MFABackupCodeRepository interface {
	// Create persists a new MFA backup code to the database.
	Create(ctx context.Context, code *models.MFABackupCode) error

	// CreateMultiple persists a batch of new MFA backup codes to the database,
	// typically within a transaction.
	CreateMultiple(ctx context.Context, codes []*models.MFABackupCode) error

	// FindByUserIDAndCodeHash retrieves an unused MFA backup code by the user's ID and the hashed code.
	// Returns domainErrors.ErrNotFound if not found or already used.
	FindByUserIDAndCodeHash(ctx context.Context, userID uuid.UUID, codeHash string) (*models.MFABackupCode, error)

	// FindByUserID retrieves all MFA backup codes for a user that have not been used yet.
	// Returns an empty slice if none exist.
	FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.MFABackupCode, error)

	// MarkAsUsed marks a specific backup code (by its primary ID) as used.
	MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error

	// MarkAsUsedByCodeHash marks a specific backup code (by UserID and CodeHash) as used.
	// This might be more convenient if the ID is not readily available post-lookup.
	MarkAsUsedByCodeHash(ctx context.Context, userID uuid.UUID, codeHash string, usedAt time.Time) error

	// DeleteByUserID removes all backup codes for a given user ID.
	// Returns the number of codes deleted.
	DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error)

	// CountActiveByUserID counts the number of unused backup codes for a user.
	CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error)
}

// Note: domainErrors.ErrNotFound or a specific ErrMFABackupCodeNotFound should be used.
