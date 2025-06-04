package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models" // Updated import path
)

// VerificationCodeRepository defines the interface for interacting with verification code data.
// These codes are used for operations like email verification, password reset, etc.
type VerificationCodeRepository interface {
	// Create persists a new verification code to the database.
	Create(ctx context.Context, vc *models.VerificationCode) error

	// FindByUserIDAndType retrieves an active (not used, not expired) verification code
	// for a specific user and type.
	// Returns domainErrors.ErrNotFound if not found or not active.
	FindByUserIDAndType(ctx context.Context, userID uuid.UUID, codeType models.VerificationCodeType) (*models.VerificationCode, error)

	// FindByCodeHashAndType retrieves an active (not used, not expired) verification code
	// by its hashed value and type. This is more secure than just hash if hashes could collide for different types.
	// Returns domainErrors.ErrNotFound if not found or not active.
	FindByCodeHashAndType(ctx context.Context, codeHash string, codeType models.VerificationCodeType) (*models.VerificationCode, error)
	
	// FindByID retrieves a verification code by its ID.
	// Returns domainErrors.ErrNotFound if not found.
	FindByID(ctx context.Context, id uuid.UUID) (*models.VerificationCode, error)

	// MarkAsUsed marks a verification code as used by setting the used_at timestamp.
	// Takes the ID of the code to mark as used.
	MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error

	// Delete removes a verification code by its ID.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteByUserIDAndType removes all verification codes for a specific user and type.
	// Returns the number of codes deleted.
	DeleteByUserIDAndType(ctx context.Context, userID uuid.UUID, codeType models.VerificationCodeType) (int64, error)

	// DeleteExpired removes all verification codes that have passed their expires_at time.
	// Returns the number of codes deleted.
	DeleteExpired(ctx context.Context) (int64, error)
}

// Note: domainErrors.ErrNotFound or a specific ErrVerificationCodeNotFound should be used.