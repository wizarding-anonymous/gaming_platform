package repository

import (
	"context"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// RoleRepository defines the interface for interacting with role data
// and their relationships with permissions and users.
type RoleRepository interface {
	// Create persists a new role to the database.
	Create(ctx context.Context, role *entity.Role) error

	// FindByID retrieves a role by its unique ID (VARCHAR(50)).
	// Returns entity.ErrRoleNotFound if no role is found.
	FindByID(ctx context.Context, id string) (*entity.Role, error)

	// FindByName retrieves a role by its unique name.
	// Returns entity.ErrRoleNotFound if no role is found.
	FindByName(ctx context.Context, name string) (*entity.Role, error)

	// Update modifies an existing role's details in the database.
	Update(ctx context.Context, role *entity.Role) error

	// Delete removes a role from the database.
	Delete(ctx context.Context, id string) error

	// List retrieves all roles from the database.
	// Consider adding pagination parameters for production use.
	List(ctx context.Context) ([]*entity.Role, error)

	// --- Role-Permission Management ---

	// AddPermissionToRole links a permission to a role via the role_permissions table.
	AddPermissionToRole(ctx context.Context, roleID string, permissionID string) error

	// RemovePermissionFromRole unlinks a permission from a role.
	RemovePermissionFromRole(ctx context.Context, roleID string, permissionID string) error

	// GetPermissionsForRole retrieves all permissions associated with a specific role ID.
	GetPermissionsForRole(ctx context.Context, roleID string) ([]*entity.Permission, error)

	// RoleHasPermission checks if a role has a specific permission.
	RoleHasPermission(ctx context.Context, roleID string, permissionID string) (bool, error)

	// --- User-Role Management ---

	// AssignToUser links a role to a user via the user_roles table.
	// assignedByUserID is optional and can be nil if not applicable or system-assigned.
	AssignToUser(ctx context.Context, userID string, roleID string, assignedByUserID *string) error

	// RemoveFromUser unlinks a role from a user.
	RemoveFromUser(ctx context.Context, userID string, roleID string) error

	// GetRolesForUser retrieves all roles associated with a specific user ID.
	GetRolesForUser(ctx context.Context, userID string) ([]*entity.Role, error)

	// UserHasRole checks if a user has a specific role.
	UserHasRole(ctx context.Context, userID string, roleID string) (bool, error)
}

// Note: entity.ErrRoleNotFound, entity.ErrPermissionNotFound would be custom errors.
// Define these in an appropriate error definitions file (e.g., internal/domain/entity/errors.go or internal/domain/errors.go)
// Example:
// package entity
// import "errors"
// var ErrRoleNotFound = errors.New("role not found")
// var ErrPermissionNotFound = errors.New("permission not found")
// var ErrUserNotFound = errors.New("user not found") // (already mentioned for UserRepository)
