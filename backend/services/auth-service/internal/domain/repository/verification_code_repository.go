// File: backend/services/auth-service/internal/domain/repository/verification_code_repository.go
// Package repository defines the interfaces for data persistence operations
// within the domain layer. These interfaces abstract the underlying data storage
// mechanisms (e.g., PostgreSQL, Redis) and allow for a decoupled architecture
// by defining contracts for data access.
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors" // Ensure this import is present
)

// VerificationCodeRepository defines the interface for interacting with verification code data.
// These codes are used for operations like email verification, password reset, etc.
type VerificationCodeRepository interface {
	// Create persists a new verification code to the database.
	Create(ctx context.Context, vc *models.VerificationCode) error

	// FindByUserIDAndType retrieves an active (not used, not expired) verification code
	// for a specific user and type (e.g., "email_verification", "password_reset").
	// Returns `domainErrors.ErrNotFound` if no active code is found for the given criteria.
	FindByUserIDAndType(ctx context.Context, userID uuid.UUID, codeType models.VerificationCodeType) (*models.VerificationCode, error)

	// FindByCodeHashAndType retrieves an active (not used, not expired) verification code
	// by its hashed value and type. This is the primary method for validating a token provided by a user.
	// It ensures that a hash collision for different types of codes does not lead to incorrect validation.
	// Returns `domainErrors.ErrNotFound` if no active code matches the hash and type.
	FindByCodeHashAndType(ctx context.Context, codeHash string, codeType models.VerificationCodeType) (*models.VerificationCode, error)
	
	// FindByID retrieves a verification code by its unique ID.
	// This method might be used for administrative purposes or internal lookups.
	// Returns `domainErrors.ErrNotFound` if no code is found with the given ID.
	FindByID(ctx context.Context, id uuid.UUID) (*models.VerificationCode, error)

	// MarkAsUsed marks a verification code as used by setting the `UsedAt` timestamp.
	// This prevents the code from being used again.
	// Takes the ID of the code to mark as used and the timestamp of when it was used.
	// Returns `domainErrors.ErrNotFound` if the code with the given ID does not exist.
	MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error

	// Delete removes a verification code by its ID. This is a hard delete.
	// Returns `domainErrors.ErrNotFound` if the code with the given ID does not exist.
	Delete(ctx context.Context, id uuid.UUID) error

	// DeleteByUserIDAndType removes all verification codes for a specific user and type.
	// This can be used, for example, to invalidate all existing password reset codes for a user
	// when a new one is requested.
	// Returns the number of codes deleted and an error if any.
	DeleteByUserIDAndType(ctx context.Context, userID uuid.UUID, codeType models.VerificationCodeType) (int64, error)

	// DeleteExpired removes all verification codes from the database that have passed their `ExpiresAt` time.
	// This is a cleanup task that should be run periodically to prevent accumulation of stale data.
	// Returns the number of codes deleted and an error if any.
	DeleteExpired(ctx context.Context) (int64, error)
}

// Note: Implementations should use domainErrors.ErrNotFound or a specific ErrVerificationCodeNotFound where appropriate.