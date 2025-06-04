package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository"
)

type pgxRoleRepository struct {
	db *pgxpool.Pool
}

// NewPgxRoleRepository creates a new instance of pgxRoleRepository.
func NewPgxRoleRepository(db *pgxpool.Pool) repository.RoleRepository {
	return &pgxRoleRepository{db: db}
}

func (r *pgxRoleRepository) Create(ctx context.Context, role *entity.Role) error {
	query := `
		INSERT INTO roles (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := r.db.Exec(ctx, query,
		role.ID, role.Name, role.Description, role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Unique violation for id or name
			return errors.New("role with given id or name already exists: " + pgErr.Detail) // Placeholder for entity.ErrRoleAlreadyExists
		}
		return fmt.Errorf("failed to create role: %w", err)
	}
	return nil
}

func (r *pgxRoleRepository) FindByID(ctx context.Context, id string) (*entity.Role, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM roles WHERE id = $1`
	role := &entity.Role{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("role not found") // Placeholder for entity.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to find role by ID: %w", err)
	}
	return role, nil
}

func (r *pgxRoleRepository) FindByName(ctx context.Context, name string) (*entity.Role, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM roles WHERE name = $1`
	role := &entity.Role{}
	err := r.db.QueryRow(ctx, query, name).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("role not found") // Placeholder for entity.ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to find role by name: %w", err)
	}
	return role, nil
}

func (r *pgxRoleRepository) Update(ctx context.Context, role *entity.Role) error {
	// Assumes trigger handles updated_at
	query := `UPDATE roles SET name = $2, description = $3, updated_at = $4 WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, role.ID, role.Name, role.Description, time.Now())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Unique violation for name
			return errors.New("role name conflict: " + pgErr.Detail)
		}
		return fmt.Errorf("failed to update role: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("role not found or no changes made") // Placeholder for entity.ErrRoleNotFound
	}
	return nil
}

func (r *pgxRoleRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM roles WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("role not found") // Placeholder for entity.ErrRoleNotFound
	}
	return nil
}

func (r *pgxRoleRepository) List(ctx context.Context) ([]*entity.Role, error) {
	query := `SELECT id, name, description, created_at, updated_at FROM roles ORDER BY name`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer rows.Close()

	var roles []*entity.Role
	for rows.Next() {
		role := &entity.Role{}
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role during list: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after iterating roles list: %w", err)
	}
	return roles, nil
}

// --- Role-Permission Management ---
func (r *pgxRoleRepository) AddPermissionToRole(ctx context.Context, roleID string, permissionID string) error {
	query := `INSERT INTO role_permissions (role_id, permission_id, created_at) VALUES ($1, $2, $3)`
	_, err := r.db.Exec(ctx, query, roleID, permissionID, time.Now())
	if err != nil {
		// Handle potential FK violations or duplicate entries
		return fmt.Errorf("failed to add permission to role: %w", err)
	}
	return nil
}

func (r *pgxRoleRepository) RemovePermissionFromRole(ctx context.Context, roleID string, permissionID string) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`
	_, err := r.db.Exec(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to remove permission from role: %w", err)
	}
	// Consider checking commandTag.RowsAffected() if you need to know if a row was actually deleted.
	return nil
}

func (r *pgxRoleRepository) GetPermissionsForRole(ctx context.Context, roleID string) ([]*entity.Permission, error) {
	query := `
		SELECT p.id, p.name, p.description, p.resource, p.action, p.created_at, p.updated_at
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1`
	rows, err := r.db.Query(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions for role: %w", err)
	}
	defer rows.Close()

	var permissions []*entity.Permission
	for rows.Next() {
		p := &entity.Permission{}
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan permission for role: %w", err)
		}
		permissions = append(permissions, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after iterating permissions for role: %w", err)
	}
	return permissions, nil
}

func (r *pgxRoleRepository) RoleHasPermission(ctx context.Context, roleID string, permissionID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM role_permissions WHERE role_id = $1 AND permission_id = $2)`
	var exists bool
	err := r.db.QueryRow(ctx, query, roleID, permissionID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check role permission: %w", err)
	}
	return exists, nil
}


// --- User-Role Management ---
func (r *pgxRoleRepository) AssignToUser(ctx context.Context, userID string, roleID string, assignedByUserID *string) error {
	query := `INSERT INTO user_roles (user_id, role_id, assigned_by, created_at) VALUES ($1, $2, $3, $4)`
	_, err := r.db.Exec(ctx, query, userID, roleID, assignedByUserID, time.Now())
	if err != nil {
		// Handle potential FK violations or duplicate entries
		return fmt.Errorf("failed to assign role to user: %w", err)
	}
	return nil
}

func (r *pgxRoleRepository) RemoveFromUser(ctx context.Context, userID string, roleID string) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`
	_, err := r.db.Exec(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role from user: %w", err)
	}
	return nil
}

func (r *pgxRoleRepository) GetRolesForUser(ctx context.Context, userID string) ([]*entity.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles for user: %w", err)
	}
	defer rows.Close()

	var roles []*entity.Role
	for rows.Next() {
		role := &entity.Role{}
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan role for user: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after iterating roles for user: %w", err)
	}
	return roles, nil
}

func (r *pgxRoleRepository) UserHasRole(ctx context.Context, userID string, roleID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2)`
	var exists bool
	err := r.db.QueryRow(ctx, query, userID, roleID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check user role: %w", err)
	}
	return exists, nil
}

var _ repository.RoleRepository = (*pgxRoleRepository)(nil)