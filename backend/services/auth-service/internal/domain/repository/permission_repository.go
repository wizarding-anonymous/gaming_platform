// File: backend/services/auth-service/internal/domain/repository/permission_repository.go
package repository

import (
	"context"

	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors" // Ensure this import
)

// PermissionRepository defines the interface for interacting with permission data.
type PermissionRepository interface {
	// Create persists a new permission to the database.
	// The ID for the permission (string) should be set on the models.Permission object.
	Create(ctx context.Context, permission *models.Permission) error

	// FindByID retrieves a permission by its unique ID (string).
	// Returns domainErrors.ErrPermissionNotFound if no permission is found.
	FindByID(ctx context.Context, id string) (*models.Permission, error)

	// FindByName retrieves a permission by its unique name.
	// Returns domainErrors.ErrPermissionNotFound if no permission is found.
	FindByName(ctx context.Context, name string) (*models.Permission, error)

	// Update modifies an existing permission's details in the database.
	Update(ctx context.Context, permission *models.Permission) error

	// Delete removes a permission from the database.
	// This is a hard delete as the permissions table does not have soft-delete columns per spec.
	Delete(ctx context.Context, id string) error

	// List retrieves all permissions from the database.
	// Consider adding pagination/filtering parameters if the number of permissions can be large.
	List(ctx context.Context /* params ListPermissionsParams */) ([]*models.Permission, error)
}

// Note: domainErrors.ErrPermissionNotFound should be used from the errors package.
// type ListPermissionsParams struct { ... } // Can be added if filtering/pagination is needed.