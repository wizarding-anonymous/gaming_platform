// File: backend/services/auth-service/internal/domain/repository/interfaces/role_repository.go
package interfaces

import (
	"context"

	// "github.com/google/uuid" // IDs are now string for Role and Permission
	"github.com/your-org/auth-service/internal/domain/models"
)

// RoleRepository defines the interface for interacting with role data
// and their relationships with permissions.
type RoleRepository interface {
	// Create persists a new role to the database.
	// The ID for the role (string) should be set on the models.Role object before calling.
	Create(ctx context.Context, role *models.Role) error
	
	// GetByID retrieves a role by its unique ID (string).
	// Returns domainErrors.ErrRoleNotFound if no role is found.
	GetByID(ctx context.Context, id string) (*models.Role, error)
	
	// GetByName retrieves a role by its unique name.
	// Returns domainErrors.ErrRoleNotFound if no role is found.
	GetByName(ctx context.Context, name string) (*models.Role, error)
	
	// Update modifies an existing role's details in the database.
	Update(ctx context.Context, role *models.Role) error
	
	// Delete removes a role from the database.
	// This should be a hard delete as roles table does not have soft-delete columns per spec.
	Delete(ctx context.Context, id string) error
	
	// List retrieves all roles from the database.
	// Consider adding pagination/filtering parameters if the number of roles can be large.
	List(ctx context.Context) ([]*models.Role, error)
	
	// --- Role-Permission Management ---

	// GetPermissionsForRole retrieves all permissions associated with a specific role ID.
	GetPermissionsForRole(ctx context.Context, roleID string) ([]*models.Permission, error)
	
	// AssignPermissionToRole links a permission to a role via the role_permissions table.
	AssignPermissionToRole(ctx context.Context, roleID string, permissionID string) error
	
	// RemovePermissionFromRole unlinks a permission from a role.
	RemovePermissionFromRole(ctx context.Context, roleID string, permissionID string) error
	
	// RoleHasPermission checks if a role has a specific permission by permission ID.
	RoleHasPermission(ctx context.Context, roleID string, permissionID string) (bool, error)

	// RoleHasPermissionByName checks if a role has a specific permission by permission name.
	// This might be more convenient in some service layer checks.
	// Implementation would involve joining with permissions table and checking name.
	// RoleHasPermissionByName(ctx context.Context, roleID string, permissionName string) (bool, error)
}
