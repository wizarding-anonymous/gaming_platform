package repository

import (
	"context"

	"github.com/google/uuid"
	// "github.com/your-org/auth-service/internal/domain/models" // Not directly needed for junction table ops
)

// UserRolesRepository defines the interface for managing the user-role assignments.
type UserRolesRepository interface {
	// AssignRoleToUser assigns a role to a user.
	// assignedByUserID is optional and can be nil.
	AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID string, assignedByUserID *uuid.UUID) error

	// RemoveRoleFromUser removes a role assignment from a user.
	RemoveRoleFromUser(ctx context.Context, userID uuid.UUID, roleID string) error

	// GetRoleIDsForUser retrieves all role IDs associated with a specific user ID.
	GetRoleIDsForUser(ctx context.Context, userID uuid.UUID) ([]string, error)

	// GetUserIDsForRole retrieves all user IDs associated with a specific role ID.
	// Useful for admin purposes, e.g., finding all users with an "admin" role.
	// Consider pagination if the number of users per role can be very large.
	GetUserIDsForRole(ctx context.Context, roleID string /*, params ListParams */) ([]uuid.UUID, error)

	// IsUserInRole checks if a user is assigned a specific role.
	IsUserInRole(ctx context.Context, userID uuid.UUID, roleID string) (bool, error)
}
