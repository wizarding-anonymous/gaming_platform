// File: backend/services/auth-service/internal/domain/repository/postgres/role_repository.go
package postgres

import (
	"context"
	"database/sql" // Keep for sql.ErrNoRows if not using pgx specific error
	"errors"
	"fmt"
	// "time" // Not strictly needed if relying on DB for timestamps and not using soft delete here

	// "github.com/google/uuid" // IDs are now string for Role and Permission
	"github.com/jackc/pgx/v5" // For pgx.ErrNoRows
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/repository/interfaces"
	// "go.uber.org/zap" // Logger can be added if necessary
)

// RoleRepositoryPostgres implements interfaces.RoleRepository for PostgreSQL.
type RoleRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger
}

// NewRoleRepositoryPostgres creates a new instance of RoleRepositoryPostgres.
func NewRoleRepositoryPostgres(pool *pgxpool.Pool /*, logger *zap.Logger*/) *RoleRepositoryPostgres {
	return &RoleRepositoryPostgres{
		pool: pool,
		// logger: logger,
	}
}

// Create persists a new role. Role ID must be set on the input role object.
func (r *RoleRepositoryPostgres) Create(ctx context.Context, role *models.Role) error {
	query := `
		INSERT INTO roles (id, name, description)
		VALUES ($1, $2, $3)
	`
	// created_at and updated_at are handled by DB defaults/triggers.
	_, err := r.pool.Exec(ctx, query, role.ID, role.Name, role.Description)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			if strings.Contains(pgErr.ConstraintName, "roles_name_key") || strings.Contains(pgErr.ConstraintName, "roles_name_idx"){
				return fmt.Errorf("role with name '%s' already exists: %w", role.Name, domainErrors.ErrDuplicateValue)
			}
			if strings.Contains(pgErr.ConstraintName, "roles_pkey") {
				return fmt.Errorf("role with ID '%s' already exists: %w", role.ID, domainErrors.ErrDuplicateValue)
			}
			return fmt.Errorf("failed to create role due to unique constraint %s: %w", pgErr.ConstraintName, domainErrors.ErrDuplicateValue)
		}
		// r.logger.Error("Failed to create role", zap.Error(err), zap.String("role_name", role.Name))
		return fmt.Errorf("failed to create role: %w", err)
	}
	return nil
}

// GetByID retrieves a role by its ID.
func (r *RoleRepositoryPostgres) GetByID(ctx context.Context, id string) (*models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE id = $1
	`
	role := &models.Role{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrRoleNotFound
		}
		// r.logger.Error("Failed to get role by ID", zap.Error(err), zap.String("role_id", id))
		return nil, fmt.Errorf("failed to get role by ID: %w", err)
	}
	return role, nil
}

// GetByName retrieves a role by its name.
func (r *RoleRepositoryPostgres) GetByName(ctx context.Context, name string) (*models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE name = $1
	`
	role := &models.Role{}
	err := r.pool.QueryRow(ctx, query, name).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrRoleNotFound
		}
		// r.logger.Error("Failed to get role by name", zap.Error(err), zap.String("role_name", name))
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}
	return role, nil
}

// Update modifies an existing role.
func (r *RoleRepositoryPostgres) Update(ctx context.Context, role *models.Role) error {
	query := `
		UPDATE roles
		SET name = $1, description = $2
		WHERE id = $3
	`
	// updated_at is handled by trigger.
	result, err := r.pool.Exec(ctx, query, role.Name, role.Description, role.ID)
	if err != nil {
		var pgErr *pgconn.PgError
        if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation for name
            return fmt.Errorf("role name '%s' already exists: %w", role.Name, domainErrors.ErrDuplicateValue)
        }
		// r.logger.Error("Failed to update role", zap.Error(err), zap.String("role_id", role.ID))
		return fmt.Errorf("failed to update role: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrRoleNotFound
	}
	return nil
}

// Delete removes a role (hard delete).
func (r *RoleRepositoryPostgres) Delete(ctx context.Context, id string) error {
	// Roles table does not have deleted_at. This is a hard delete.
	// Associated user_roles and role_permissions should be handled by ON DELETE CASCADE or manually.
	// The spec for role_permissions and user_roles tables has ON DELETE CASCADE for role_id.
	query := `DELETE FROM roles WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		// r.logger.Error("Failed to delete role", zap.Error(err), zap.String("role_id", id))
		return fmt.Errorf("failed to delete role: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrRoleNotFound
	}
	return nil
}

// List retrieves all roles.
func (r *RoleRepositoryPostgres) List(ctx context.Context) ([]*models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		ORDER BY name
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		// r.logger.Error("Failed to list roles", zap.Error(err))
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer rows.Close()

	var roles []*models.Role
	for rows.Next() {
		role := &models.Role{}
		errScan := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt)
		if errScan != nil {
			// r.logger.Error("Failed to scan role row", zap.Error(errScan))
			return nil, fmt.Errorf("failed to scan role row: %w", errScan)
		}
		roles = append(roles, role)
	}
	if err = rows.Err(); err != nil {
        // r.logger.Error("Error iterating role rows", zap.Error(err))
        return nil, fmt.Errorf("error iterating role rows: %w", err)
    }
	return roles, nil
}

// --- Role-Permission Management ---

// GetPermissionsForRole retrieves all permissions for a role.
func (r *RoleRepositoryPostgres) GetPermissionsForRole(ctx context.Context, roleID string) ([]*models.Permission, error) {
	query := `
		SELECT p.id, p.name, p.description, p.resource, p.action, p.created_at, p.updated_at
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.name
	`
	rows, err := r.pool.Query(ctx, query, roleID)
	if err != nil {
		// r.logger.Error("Failed to get permissions for role", zap.Error(err), zap.String("role_id", roleID))
		return nil, fmt.Errorf("failed to get permissions for role %s: %w", roleID, err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		p := &models.Permission{}
		errScan := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt, &p.UpdatedAt)
		if errScan != nil {
			// r.logger.Error("Failed to scan permission row for role", zap.Error(errScan))
			return nil, fmt.Errorf("failed to scan permission row for role: %w", errScan)
		}
		permissions = append(permissions, p)
	}
	if err = rows.Err(); err != nil {
        // r.logger.Error("Error iterating role permissions rows", zap.Error(err))
        return nil, fmt.Errorf("error iterating role permissions rows: %w", err)
    }
	return permissions, nil
}

// AssignPermissionToRole links a permission to a role.
func (r *RoleRepositoryPostgres) AssignPermissionToRole(ctx context.Context, roleID string, permissionID string) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id)
		VALUES ($1, $2)
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`
	// created_at has a DB default.
	_, err := r.pool.Exec(ctx, query, roleID, permissionID)
	if err != nil {
		// r.logger.Error("Failed to assign permission to role", zap.Error(err), zap.String("role_id", roleID), zap.String("permission_id", permissionID))
		// Check for foreign key violations, e.g., if role or permission doesn't exist
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign_key_violation
			return fmt.Errorf("role or permission does not exist: %w", domainErrors.ErrNotFound)
		}
		return fmt.Errorf("failed to assign permission %s to role %s: %w", permissionID, roleID, err)
	}
	return nil
}

// RemovePermissionFromRole unlinks a permission from a role.
func (r *RoleRepositoryPostgres) RemovePermissionFromRole(ctx context.Context, roleID string, permissionID string) error {
	query := `
		DELETE FROM role_permissions
		WHERE role_id = $1 AND permission_id = $2
	`
	result, err := r.pool.Exec(ctx, query, roleID, permissionID)
	if err != nil {
		// r.logger.Error("Failed to remove permission from role", zap.Error(err), zap.String("role_id", roleID), zap.String("permission_id", permissionID))
		return fmt.Errorf("failed to remove permission %s from role %s: %w", permissionID, roleID, err)
	}
	if result.RowsAffected() == 0 {
		// This could mean the permission was not assigned, or role/permission ID was wrong.
		// Returning ErrNotFound might be misleading if the role/permission exist but weren't linked.
		// Consider a more specific error or just success if the link is gone.
		// For now, if no rows affected, we assume the link wasn't there, which is not an error state.
		return nil
	}
	return nil
}

// RoleHasPermission checks if a role has a specific permission.
func (r *RoleRepositoryPostgres) RoleHasPermission(ctx context.Context, roleID string, permissionID string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM role_permissions
			WHERE role_id = $1 AND permission_id = $2
		)
	`
	var exists bool
	err := r.pool.QueryRow(ctx, query, roleID, permissionID).Scan(&exists)
	if err != nil {
		// r.logger.Error("Failed to check role permission", zap.Error(err), zap.String("role_id", roleID), zap.String("permission_id", permissionID))
		return false, fmt.Errorf("failed to check if role %s has permission %s: %w", roleID, permissionID, err)
	}
	return exists, nil
}

// Ensure RoleRepositoryPostgres implements interfaces.RoleRepository
var _ interfaces.RoleRepository = (*RoleRepositoryPostgres)(nil)

// The old postgres/role_repository.go also contained methods for user-role assignments.
// These (GetUserRoles, AssignRoleToUser, RemoveRoleFromUser, UserHasRole)
// will be moved to a dedicated UserRolesRepository.
// Methods like GetAll, and specific GetUserRoles, AssignRoleToUser etc. from the old file
// are either adapted here or will be moved.
// The original file used sqlx.DB, this uses pgxpool.Pool.
// Soft delete logic for roles (using deleted_at) was removed as it's not in the schema spec for roles.
// Logger usage has been commented out but can be re-added if a logger instance is passed to the repo.
// Error checking for unique constraints in Create/Update is added.
// ON CONFLICT DO NOTHING is used for AssignPermissionToRole to make it idempotent.
// RemovePermissionFromRole now returns nil if the link wasn't there (idempotency).The `RoleRepositoryPostgres` implementation in `backend/services/auth-service/internal/domain/repository/postgres/role_repository.go` has been updated.

**Summary of `RolesRepository` changes:**
1.  **Models (`models/role.go`, `models/permission.go`):** Updated `ID` fields to `string`. Added `Resource` and `Action` to `Permission` model.
2.  **Interface (`interfaces/role_repository.go`):**
    *   Updated to use `string` for `roleID` and `permissionID`.
    *   `Create` method now returns `error` only.
    *   Focused on role-specific and role-permission linkage methods. User-role methods are to be handled by `UserRolesRepository`.
3.  **Implementation (`postgres/role_repository.go`):**
    *   Renamed struct to `RoleRepositoryPostgres` and updated constructor to use `*pgxpool.Pool`.
    *   Changed `roleID` and `permissionID` parameters and internal handling to `string`.
    *   SQL queries updated for `string` IDs.
    *   Removed `deleted_at` handling for the `roles` table (hard deletes).
    *   Ensured `created_at` and `updated_at` are handled by DB defaults/triggers by not setting them explicitly in `Create` and `Update` (except where the model itself carries this data from a previous read, which is fine for `Update`).
    *   Methods related to user-role linkage were conceptually separated (to be implemented in `UserRolesRepository`).
    *   Implemented role-permission linkage methods (`GetPermissionsForRole`, `AssignPermissionToRole`, `RemovePermissionFromRole`, `RoleHasPermission`).
    *   Improved error handling for unique constraints.

This largely completes the `RolesRepository` part of Task 4.

Next, I'll address **`PermissionsRepository`**.
*   Interface: `backend/services/auth-service/internal/domain/repository/permission_repository.go` (exists, based on `ls` output).
*   Implementation: No dedicated `postgres/permission_repository.go` was seen. Methods might be in the old `postgres/user_repository.go` or `postgres/role_repository.go`, or it needs to be created. The task implies creating it in `internal/infrastructure/database/` or `internal/domain/repository/postgres/`. I'll use the latter for consistency.
*   Model: `backend/services/auth-service/internal/domain/models/permission.go` (already updated).

I'll start by reading the existing `permission_repository.go` interface file.
