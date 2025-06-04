package repository

import (
	"context"
	"time"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// VerificationCodeRepository defines the interface for interacting with verification code data.
// These codes are used for operations like email verification, password reset, etc.
type VerificationCodeRepository interface {
	// Create persists a new verification code to the database.
	Create(ctx context.Context, vc *entity.VerificationCode) error

	// FindByUserIDAndType retrieves an active (not used, not expired) verification code
	// for a specific user and type. There should ideally be only one active code per user/type.
	// Returns entity.ErrVerificationCodeNotFound if not found or not active.
	FindByUserIDAndType(ctx context.Context, userID string, codeType entity.VerificationCodeType) (*entity.VerificationCode, error)

	// FindByCodeHash retrieves a verification code by its hashed value.
	// This is used when a user provides a code to be verified.
	// Returns entity.ErrVerificationCodeNotFound if not found.
	FindByCodeHash(ctx context.Context, codeHash string) (*entity.VerificationCode, error)
	
	// FindByID retrieves a verification code by its ID.
	// Returns entity.ErrVerificationCodeNotFound if not found.
	FindByID(ctx context.Context, id string) (*entity.VerificationCode, error)

	// MarkAsUsed marks a verification code as used by setting the used_at timestamp.
	MarkAsUsed(ctx context.Context, id string, usedAt time.Time) error

	// Delete removes a verification code by its ID.
	// Usually done after it's successfully used or if it's explicitly invalidated.
	Delete(ctx context.Context, id string) error

	// DeleteByUserIDAndType removes all verification codes for a specific user and type.
	// Useful when a new code is issued, invalidating old ones.
	DeleteByUserIDAndType(ctx context.Context, userID string, codeType entity.VerificationCodeType) error

	// DeleteExpired removes all verification codes that have passed their expires_at time.
	// Returns the number of codes deleted.
	DeleteExpired(ctx context.Context) (int64, error)
}

// Note: entity.ErrVerificationCodeNotFound would be a custom error.
// Define in an appropriate error definitions file.
// Example:
// package entity
// import "errors"
// var ErrVerificationCodeNotFound = errors.New("verification code not found")