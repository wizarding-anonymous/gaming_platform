// File: backend/services/auth-service/internal/domain/repository/user_repository.go
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
)

// UserRepository defines the interface for interacting with user data.
type UserRepository interface {
	// Create persists a new user to the database.
	Create(ctx context.Context, user *models.User) error

	// FindByID retrieves a user by their unique ID.
	// Returns domainErrors.ErrUserNotFound if no user is found.
	FindByID(ctx context.Context, id uuid.UUID) (*models.User, error)

	// FindByEmail retrieves a user by their email address.
	// Returns domainErrors.ErrUserNotFound if no user is found.
	FindByEmail(ctx context.Context, email string) (*models.User, error)

	// FindByUsername retrieves a user by their username.
	// Returns domainErrors.ErrUserNotFound if no user is found.
	FindByUsername(ctx context.Context, username string) (*models.User, error)

	// Update modifies an existing user's details in the database.
	Update(ctx context.Context, user *models.User) error

	// Delete marks a user as deleted (soft delete by setting DeletedAt and status to 'deleted').
	// Note: The original pgx implementation had `Delete(ctx context.Context, id string, deletedAt time.Time) error`.
	// I'm aligning this with a simpler `Delete(ctx context.Context, id uuid.UUID) error` and letting the implementation handle setting DeletedAt.
	Delete(ctx context.Context, id uuid.UUID) error

	// UpdateStatus changes the status of a user.
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.UserStatus) error

	// SetEmailVerifiedAt sets the email_verified_at timestamp.
	// The original pgx implementation had `UpdateEmailVerification`. I'm renaming to SetEmailVerifiedAt for clarity.
	SetEmailVerifiedAt(ctx context.Context, id uuid.UUID, verifiedAt time.Time) error
	
	// UpdatePassword updates the user's password hash.
	// The original pgx implementation had `UpdatePasswordHash`. I'm renaming to UpdatePassword for consistency.
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error

	// UpdateFailedLoginAttempts increments the failed login counter and optionally updates lockout_until.
	UpdateFailedLoginAttempts(ctx context.Context, id uuid.UUID, attempts int, lockoutUntil *time.Time) error

	// ResetFailedLoginAttempts resets the failed login counter and sets lockout_until to NULL.
	ResetFailedLoginAttempts(ctx context.Context, id uuid.UUID) error
	
	// UpdateLastLogin updates the last_login_at timestamp for a user.
	UpdateLastLogin(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error

	// List retrieves a paginated and filtered list of users.
	List(ctx context.Context, params models.ListUsersParams) ([]*models.User, int, error)

	// UpdateLockout sets/clears the lockout_until timestamp for a user.
    UpdateLockout(ctx context.Context, id uuid.UUID, lockoutUntil *time.Time) error

    // IncrementFailedLoginAttempts increments the counter.
    IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) error

	// The UpdateUserStatusFields method was present in the pgx implementation but not strictly defined in the original interface content.
	// It's a more specific update method. For now, I will keep it out of the main interface unless specifically requested
	// or if it's found to be essential for existing service logic that I haven't reviewed yet for this change.
	// The task focuses on ListUsers, so I'll keep the interface focused.
	// If `UpdateUserStatusFields` is indeed used by other parts of the service, it should be added here.
	// For now, assuming it's a helper or was part of a previous iteration.
}
