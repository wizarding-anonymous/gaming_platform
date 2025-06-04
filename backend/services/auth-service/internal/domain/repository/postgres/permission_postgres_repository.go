package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/repository" // For the interface
)

// PermissionRepositoryPostgres implements repository.PermissionRepository for PostgreSQL.
type PermissionRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger // Optional: if logging is needed
}

// NewPermissionRepositoryPostgres creates a new instance of PermissionRepositoryPostgres.
func NewPermissionRepositoryPostgres(pool *pgxpool.Pool /*, logger *zap.Logger*/) *PermissionRepositoryPostgres {
	return &PermissionRepositoryPostgres{
		pool: pool,
		// logger: logger,
	}
}

// Create persists a new permission. Permission ID must be set on the input object.
func (r *PermissionRepositoryPostgres) Create(ctx context.Context, permission *models.Permission) error {
	query := `
		INSERT INTO permissions (id, name, description, resource, action)
		VALUES ($1, $2, $3, $4, $5)
	`
	// created_at and updated_at are handled by DB defaults/triggers.
	_, err := r.pool.Exec(ctx, query,
		permission.ID,
		permission.Name,
		permission.Description,
		permission.Resource,
		permission.Action,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			if strings.Contains(pgErr.ConstraintName, "permissions_name_key") || strings.Contains(pgErr.ConstraintName, "permissions_name_idx"){
				return fmt.Errorf("permission with name '%s' already exists: %w", permission.Name, domainErrors.ErrDuplicateValue)
			}
			if strings.Contains(pgErr.ConstraintName, "permissions_pkey") {
				return fmt.Errorf("permission with ID '%s' already exists: %w", permission.ID, domainErrors.ErrDuplicateValue)
			}
			return fmt.Errorf("failed to create permission due to unique constraint %s: %w", pgErr.ConstraintName, domainErrors.ErrDuplicateValue)
		}
		// r.logger.Error("Failed to create permission", zap.Error(err), zap.String("permission_name", permission.Name))
		return fmt.Errorf("failed to create permission: %w", err)
	}
	return nil
}

// FindByID retrieves a permission by its ID.
func (r *PermissionRepositoryPostgres) FindByID(ctx context.Context, id string) (*models.Permission, error) {
	query := `
		SELECT id, name, description, resource, action, created_at, updated_at
		FROM permissions
		WHERE id = $1
	`
	p := &models.Permission{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrPermissionNotFound
		}
		// r.logger.Error("Failed to get permission by ID", zap.Error(err), zap.String("permission_id", id))
		return nil, fmt.Errorf("failed to get permission by ID: %w", err)
	}
	return p, nil
}

// FindByName retrieves a permission by its name.
func (r *PermissionRepositoryPostgres) FindByName(ctx context.Context, name string) (*models.Permission, error) {
	query := `
		SELECT id, name, description, resource, action, created_at, updated_at
		FROM permissions
		WHERE name = $1
	`
	p := &models.Permission{}
	err := r.pool.QueryRow(ctx, query, name).Scan(
		&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrPermissionNotFound
		}
		// r.logger.Error("Failed to get permission by name", zap.Error(err), zap.String("permission_name", name))
		return nil, fmt.Errorf("failed to get permission by name: %w", err)
	}
	return p, nil
}

// Update modifies an existing permission.
func (r *PermissionRepositoryPostgres) Update(ctx context.Context, permission *models.Permission) error {
	query := `
		UPDATE permissions
		SET name = $1, description = $2, resource = $3, action = $4
		WHERE id = $5
	`
	// updated_at is handled by trigger.
	result, err := r.pool.Exec(ctx, query,
		permission.Name,
		permission.Description,
		permission.Resource,
		permission.Action,
		permission.ID,
	)
	if err != nil {
		var pgErr *pgconn.PgError
        if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation for name
             return fmt.Errorf("permission name '%s' already exists: %w", permission.Name, domainErrors.ErrDuplicateValue)
        }
		// r.logger.Error("Failed to update permission", zap.Error(err), zap.String("permission_id", permission.ID))
		return fmt.Errorf("failed to update permission: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrPermissionNotFound
	}
	return nil
}

// Delete removes a permission (hard delete).
func (r *PermissionRepositoryPostgres) Delete(ctx context.Context, id string) error {
	// Associated role_permissions should be handled by ON DELETE CASCADE.
	query := `DELETE FROM permissions WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		// r.logger.Error("Failed to delete permission", zap.Error(err), zap.String("permission_id", id))
		return fmt.Errorf("failed to delete permission: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrPermissionNotFound
	}
	return nil
}

// List retrieves all permissions.
func (r *PermissionRepositoryPostgres) List(ctx context.Context) ([]*models.Permission, error) {
	query := `
		SELECT id, name, description, resource, action, created_at, updated_at
		FROM permissions
		ORDER BY name
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		// r.logger.Error("Failed to list permissions", zap.Error(err))
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}
	defer rows.Close()

	var permissions []*models.Permission
	for rows.Next() {
		p := &models.Permission{}
		errScan := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Resource, &p.Action, &p.CreatedAt, &p.UpdatedAt,
		)
		if errScan != nil {
			// r.logger.Error("Failed to scan permission row", zap.Error(errScan))
			return nil, fmt.Errorf("failed to scan permission row: %w", errScan)
		}
		permissions = append(permissions, p)
	}
	if err = rows.Err(); err != nil {
        // r.logger.Error("Error iterating permission rows", zap.Error(err))
        return nil, fmt.Errorf("error iterating permission rows: %w", err)
    }
	return permissions, nil
}

// Ensure PermissionRepositoryPostgres implements repository.PermissionRepository.
var _ repository.PermissionRepository = (*PermissionRepositoryPostgres)(nil)
