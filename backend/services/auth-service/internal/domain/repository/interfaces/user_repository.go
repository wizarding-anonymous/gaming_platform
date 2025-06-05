// File: backend/services/auth-service/internal/domain/repository/interfaces/user_repository.go
// Package interfaces defines the interfaces for repository implementations.
// These interfaces provide an abstraction layer between the domain logic and data storage,
// allowing for different storage backends to be used and facilitating testing.
package interfaces

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
)

// UserRepository defines the interface for interacting with user data persistence.
// It outlines methods for creating, retrieving, updating, and deleting user records,
// as well as managing user-specific attributes like passwords, roles, and statuses.
type UserRepository interface {
	// Create persists a new user to the data store.
	// It returns the created user entity, potentially with database-generated fields like CreatedAt/UpdatedAt.
	// May return domainErrors.ErrDuplicateValue if a user with the same email or username already exists.
	Create(ctx context.Context, user *models.User) error // Changed from returning models.User to error based on typical Create patterns

	// FindByID retrieves a user by their unique ID.
	// Returns domainErrors.ErrUserNotFound if no user is found.
	FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) // Changed to pointer return

	// FindByEmail retrieves a user by their email address.
	// Returns domainErrors.ErrUserNotFound if no user is found.
	FindByEmail(ctx context.Context, email string) (*models.User, error) // Changed to pointer return

	// FindByUsername retrieves a user by their username.
	// Returns domainErrors.ErrUserNotFound if no user is found.
	FindByUsername(ctx context.Context, username string) (*models.User, error) // Changed to pointer return

	// GetByTelegramID retrieves a user by their Telegram ID.
	// This method might be specific and could be part of ExternalAccountRepository or similar.
	// Returns domainErrors.ErrUserNotFound if no user is found.
	GetByTelegramID(ctx context.Context, telegramID string) (*models.User, error) // Assuming this is still needed; Changed to pointer

	// Update modifies an existing user's details in the data store.
	// It typically updates fields like DisplayName, ProfileImageURL, etc.
	// Specific update methods (e.g., UpdatePassword, UpdateStatus) are preferred for atomic operations.
	Update(ctx context.Context, user *models.User) error

	// Delete marks a user as deleted (soft delete) or permanently removes them,
	// depending on the implementation. The current implementation is soft delete.
	// It expects the user ID and the time of deletion.
	Delete(ctx context.Context, id uuid.UUID) error // Removed deletedAt, repo should set it

	// List retrieves a paginated list of users based on the provided parameters.
	// It returns the list of users, the total count of users matching the criteria, and an error if any.
	List(ctx context.Context, params models.ListUsersParams) ([]*models.User, int, error) // Changed params
	
	// UpdatePassword changes a user's password hash in the data store.
	UpdatePassword(ctx context.Context, userID uuid.UUID, newPasswordHashWithSalt string) error // Clarified param name
	
	// SetEmailVerifiedAt updates the timestamp when a user's email was verified.
	// It also typically updates the user's status to active if it was pending verification.
	SetEmailVerifiedAt(ctx context.Context, userID uuid.UUID, verifiedAt time.Time) error
	
	// UpdateStatus updates a user's status (e.g., active, blocked, pending_verification).
	UpdateStatus(ctx context.Context, userID uuid.UUID, status models.UserStatus) error

	// UpdateTelegramID sets or updates the Telegram ID for a user.
	UpdateTelegramID(ctx context.Context, userID uuid.UUID, telegramID string) error
	
	// UpdateLastLogin sets the timestamp of the user's last successful login.
	UpdateLastLogin(ctx context.Context, userID uuid.UUID, lastLoginAt time.Time) error

	// IncrementFailedLoginAttempts increases the count of failed login attempts for a user.
	IncrementFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error

	// ResetFailedLoginAttempts resets the failed login attempt counter and clears any lockout.
	ResetFailedLoginAttempts(ctx context.Context, userID uuid.UUID) error
	
	// UpdateLockout sets or clears the lockout status for a user.
	// lockoutUntil being nil means the lockout is cleared.
	UpdateLockout(ctx context.Context, userID uuid.UUID, lockoutUntil *time.Time) error

	// UpdateUserStatusFields allows updating status, status_reason, and lockout_until.
	// updatedBy should be the ID of the admin or system performing the update.
	// This method consolidates several status-related updates.
	UpdateUserStatusFields(ctx context.Context, userID uuid.UUID, status models.UserStatus, statusReason *string, lockoutUntil *time.Time) error
	
	// --- User-Role specific methods might be better in UserRolesRepository ---
	// GetUserRoles retrieves all roles assigned to a specific user.
	// GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) // Changed to pointer
	
	// AssignRole assigns a role to a user. This is typically managed by UserRolesRepository.
	// AssignRole(ctx context.Context, userID uuid.UUID, roleID string) error // RoleID likely string
	
	// RemoveRole removes a role from a user. This is typically managed by UserRolesRepository.
	// RemoveRole(ctx context.Context, userID uuid.UUID, roleID string) error // RoleID likely string
	
	// HasRole checks if a user has a specific role by role name.
	// This might involve multiple queries or joins and could be a service-layer concern or a specific query in UserRolesRepository.
	// HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error)
	
	// HasPermission checks if a user has a specific permission by permission name.
	// This is a more complex query usually handled by the service layer or RBAC specific repository functions.
	// HasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error)
}
