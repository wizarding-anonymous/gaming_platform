package repository

import (
	"context"
	"time"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// UserRepository defines the interface for interacting with user data.
// Implementations will handle the actual database operations.
type UserRepository interface {
	// Create persists a new user to the database.
	Create(ctx context.Context, user *entity.User) error

	// FindByID retrieves a user by their unique ID.
	// Returns entity.ErrUserNotFound if no user is found.
	FindByID(ctx context.Context, id string) (*entity.User, error)

	// FindByEmail retrieves a user by their email address.
	// Returns entity.ErrUserNotFound if no user is found.
	FindByEmail(ctx context.Context, email string) (*entity.User, error)

	// FindByUsername retrieves a user by their username.
	// Returns entity.ErrUserNotFound if no user is found.
	FindByUsername(ctx context.Context, username string) (*entity.User, error)

	// Update modifies an existing user's details in the database.
	Update(ctx context.Context, user *entity.User) error

	// Delete marks a user as deleted (soft delete by setting DeletedAt).
	// A hard delete method might also be considered if needed.
	Delete(ctx context.Context, id string, deletedAt time.Time) error

	// UpdateStatus changes the status of a user (e.g., active, blocked).
	UpdateStatus(ctx context.Context, id string, status entity.UserStatus) error

	// UpdateEmailVerification sets the email_verified_at timestamp.
	UpdateEmailVerification(ctx context.Context, id string, verifiedAt time.Time) error
	
	// UpdatePasswordHash updates the user's password hash.
	UpdatePasswordHash(ctx context.Context, id string, passwordHash string) error

	// UpdateFailedLoginAttempts increments the failed login counter and optionally updates lockout_until.
	UpdateFailedLoginAttempts(ctx context.Context, id string, attempts int, lockoutUntil *time.Time) error

	// ResetFailedLoginAttempts resets the failed login counter for a user.
	ResetFailedLoginAttempts(ctx context.Context, id string) error
	
	// UpdateLastLogin updates the last_login_at timestamp for a user.
	UpdateLastLogin(ctx context.Context, id string, lastLoginAt time.Time) error

	// List retrieves a paginated list of users, potentially with filters.
	// ListUsersParams would be a struct containing pagination and filter options.
	// For now, keeping it simple, but a real service would need this.
	// List(ctx context.Context, params ListUsersParams) ([]*entity.User, int, error) // Returns users, total count, error

	// UpdateUserStatusFields updates specific fields related to a user's status.
	// Nil values for pointer arguments mean those fields should not be updated.
	UpdateUserStatusFields(ctx context.Context, userID string, status entity.UserStatus, statusReason *string, lockoutUntil *time.Time, updatedBy *string) error
}

// Note: entity.ErrUserNotFound would be a custom error defined in the entity or a common errors package.
// For example:
// package entity // or package errors
// import "errors"
// var ErrUserNotFound = errors.New("user not found")
// This should be defined elsewhere, possibly in a new errors.go file within entity or a common pkg.
// For now, the interface definition assumes such an error exists.
// Need to import time for *time.Time
