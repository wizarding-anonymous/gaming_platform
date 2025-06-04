package repository

import (
	"context"

	"github.com/gameplatform/auth-service/internal/domain/entity"
)

// PermissionRepository defines the interface for interacting with permission data.
type PermissionRepository interface {
	// Create persists a new permission to the database.
	Create(ctx context.Context, permission *entity.Permission) error

	// FindByID retrieves a permission by its unique ID (VARCHAR(100)).
	// Returns entity.ErrPermissionNotFound if no permission is found.
	FindByID(ctx context.Context, id string) (*entity.Permission, error)

	// FindByName retrieves a permission by its unique name.
	// Returns entity.ErrPermissionNotFound if no permission is found.
	FindByName(ctx context.Context, name string) (*entity.Permission, error)

	// Update modifies an existing permission's details in the database.
	Update(ctx context.Context, permission *entity.Permission) error

	// Delete removes a permission from the database.
	Delete(ctx context.Context, id string) error

	// List retrieves all permissions from the database.
	// Consider adding pagination parameters for production use.
	List(ctx context.Context) ([]*entity.Permission, error)
}

// Note: entity.ErrPermissionNotFound would be a custom error.
// (Already mentioned for RoleRepository)