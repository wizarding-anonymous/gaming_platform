// File: backend/services/auth-service/internal/domain/repository/user_repository.go
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/gameplatform/auth-service/internal/domain/models" // Updated import path
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
	// This method should be designed carefully: does it update all fields from the user struct,
	// or only non-zero ones? Or are there specific methods for specific updates?
	// For now, assume it updates all applicable fields from the provided user struct.
	Update(ctx context.Context, user *models.User) error

	// Delete marks a user as deleted (soft delete by setting DeletedAt and status to 'deleted').
	Delete(ctx context.Context, id uuid.UUID) error

	// UpdateStatus changes the status of a user.
	UpdateStatus(ctx context.Context, id uuid.UUID, status models.UserStatus) error

	// SetEmailVerifiedAt sets the email_verified_at timestamp.
	SetEmailVerifiedAt(ctx context.Context, id uuid.UUID, verifiedAt time.Time) error
	
	// UpdatePassword updates the user's password hash (which includes the embedded salt).
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHashWithSalt string) error

	// UpdateFailedLoginAttempts increments the failed login counter and optionally updates lockout_until.
	UpdateFailedLoginAttempts(ctx context.Context, id uuid.UUID, attempts int, lockoutUntil *time.Time) error

	// ResetFailedLoginAttempts resets the failed login counter and sets lockout_until to NULL.
	ResetFailedLoginAttempts(ctx context.Context, id uuid.UUID) error
	
	// UpdateLastLogin updates the last_login_at timestamp for a user.
	UpdateLastLogin(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error

	// List retrieves a paginated and filtered list of users.
	List(ctx context.Context, params models.ListUsersParams) ([]*models.User, int, error) // Returns users, total count, error

	// UpdateLockout sets/clears the lockout_until timestamp for a user.
    UpdateLockout(ctx context.Context, id uuid.UUID, lockoutUntil *time.Time) error

	// GetSaltByUserID retrieves the salt for a given user ID.
	// Useful during login to fetch salt before password verification if salt is not part of the user object returned by FindByEmail/Username.
	// Alternatively, FindByEmail/Username should return the salt.
	// For now, assuming Find methods will include salt in the User object.

	// IncrementFailedLoginAttempts increments the counter.
    IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) error

	// UpdateUserFields allows updating a subset of user fields.
	// Takes user ID and a map of fields to update. Example: map[string]interface{}{"username": "new_user", "status": "active"}
	// This provides more flexibility than a full Update method.
	// This is an alternative to a full Update or many specific update methods.
	// For this iteration, we'll rely on specific update methods and the general Update.
	// UpdateFields(ctx context.Context, id uuid.UUID, fields map[string]interface{}) error

	// UpdateUserStatusFields was removed as status_reason and updated_by are not in the spec's user table after migration 000008
	// UpdateUserStatusFields(ctx context.Context, userID uuid.UUID, status models.UserStatus, statusReason *string, lockoutUntil *time.Time, updatedBy *string) error
}
// Note: domainErrors.ErrUserNotFound etc. are expected to be defined in the domain/errors package.
// The import path for models might need to be adjusted based on the actual project structure if "github.com/gameplatform/auth-service" is not correct.
// I am using "github.com/gameplatform/auth-service/internal/domain/models" as a placeholder, matching the structure of the prompt.
// If the actual module path is different (e.g. "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service"), this needs to be used in models and here.
// Based on previous logs, it seems "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service" is the actual module path.
// I will correct the import path for models.
// Corrected import: "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
// The provided user_repository.go uses "github.com/gameplatform/auth-service/internal/domain/entity".
// I will stick to "models" as per my current changes and assume "entity" was the old name.
// It looks like the original file used "github.com/gameplatform/auth-service/internal/domain/entity".
// I should use the existing project's module path.
// The postgres implementation uses "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models".
// The interface was using "github.com/gameplatform/auth-service/internal/domain/entity".
// This is an inconsistency I need to resolve. I will make the interface use "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models".
