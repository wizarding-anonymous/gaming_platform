// File: internal/repository/postgres/role_repository.go

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/your-org/auth-service/internal/domain/models"
	"go.uber.org/zap"
)

// RoleRepository реализует интерфейс для работы с ролями в PostgreSQL
type RoleRepository struct {
	db     *sqlx.DB
	logger *zap.Logger
}

// NewRoleRepository создает новый экземпляр RoleRepository
func NewRoleRepository(db *sqlx.DB, logger *zap.Logger) *RoleRepository {
	return &RoleRepository{
		db:     db,
		logger: logger,
	}
}

// GetByID получает роль по ID
func (r *RoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE id = $1 AND deleted_at IS NULL
	`

	var role models.Role
	err := r.db.GetContext(ctx, &role, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrRoleNotFound
		}
		r.logger.Error("Failed to get role by ID", zap.Error(err), zap.String("role_id", id.String()))
		return nil, err
	}

	return &role, nil
}

// GetByName получает роль по имени
func (r *RoleRepository) GetByName(ctx context.Context, name string) (*models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE name = $1 AND deleted_at IS NULL
	`

	var role models.Role
	err := r.db.GetContext(ctx, &role, query, name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, models.ErrRoleNotFound
		}
		r.logger.Error("Failed to get role by name", zap.Error(err), zap.String("role_name", name))
		return nil, err
	}

	return &role, nil
}

// GetAll получает все роли
func (r *RoleRepository) GetAll(ctx context.Context) ([]*models.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE deleted_at IS NULL
		ORDER BY name
	`

	var roles []*models.Role
	err := r.db.SelectContext(ctx, &roles, query)
	if err != nil {
		r.logger.Error("Failed to get all roles", zap.Error(err))
		return nil, err
	}

	return roles, nil
}

// Create создает новую роль
func (r *RoleRepository) Create(ctx context.Context, role *models.Role) error {
	query := `
		INSERT INTO roles (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.db.ExecContext(
		ctx,
		query,
		role.ID,
		role.Name,
		role.Description,
		role.CreatedAt,
		role.UpdatedAt,
	)
	if err != nil {
		r.logger.Error("Failed to create role", zap.Error(err), zap.String("role_name", role.Name))
		return err
	}

	return nil
}

// Update обновляет роль
func (r *RoleRepository) Update(ctx context.Context, role *models.Role) error {
	query := `
		UPDATE roles
		SET name = $1, description = $2, updated_at = $3
		WHERE id = $4 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(
		ctx,
		query,
		role.Name,
		role.Description,
		role.UpdatedAt,
		role.ID,
	)
	if err != nil {
		r.logger.Error("Failed to update role", zap.Error(err), zap.String("role_id", role.ID.String()))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return err
	}

	if rowsAffected == 0 {
		return models.ErrRoleNotFound
	}

	return nil
}

// Delete удаляет роль (мягкое удаление)
func (r *RoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE roles
		SET deleted_at = $1
		WHERE id = $2 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		r.logger.Error("Failed to delete role", zap.Error(err), zap.String("role_id", id.String()))
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return err
	}

	if rowsAffected == 0 {
		return models.ErrRoleNotFound
	}

	// Удаление связей роли с пользователями
	_, err = r.db.ExecContext(ctx, "DELETE FROM user_roles WHERE role_id = $1", id)
	if err != nil {
		r.logger.Error("Failed to delete user-role associations", zap.Error(err), zap.String("role_id", id.String()))
		return err
	}

	return nil
}

// GetUserRoles получает роли пользователя
func (r *RoleRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]*models.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.deleted_at IS NULL
		ORDER BY r.name
	`

	var roles []*models.Role
	err := r.db.SelectContext(ctx, &roles, query, userID)
	if err != nil {
		r.logger.Error("Failed to get user roles", zap.Error(err), zap.String("user_id", userID.String()))
		return nil, err
	}

	return roles, nil
}

// AssignRoleToUser назначает роль пользователю
func (r *RoleRepository) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, created_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`

	_, err := r.db.ExecContext(ctx, query, userID, roleID, time.Now())
	if err != nil {
		r.logger.Error("Failed to assign role to user", 
			zap.Error(err), 
			zap.String("user_id", userID.String()),
			zap.String("role_id", roleID.String()),
		)
		return err
	}

	return nil
}

// RemoveRoleFromUser удаляет роль у пользователя
func (r *RoleRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `
		DELETE FROM user_roles
		WHERE user_id = $1 AND role_id = $2
	`

	result, err := r.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		r.logger.Error("Failed to remove role from user", 
			zap.Error(err), 
			zap.String("user_id", userID.String()),
			zap.String("role_id", roleID.String()),
		)
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return err
	}

	if rowsAffected == 0 {
		return models.ErrRoleNotAssigned
	}

	return nil
}

// UserHasRole проверяет, имеет ли пользователь указанную роль
func (r *RoleRepository) UserHasRole(ctx context.Context, userID, roleID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM user_roles
			WHERE user_id = $1 AND role_id = $2
		)
	`

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, userID, roleID)
	if err != nil {
		r.logger.Error("Failed to check if user has role", 
			zap.Error(err), 
			zap.String("user_id", userID.String()),
			zap.String("role_id", roleID.String()),
		)
		return false, err
	}

	return exists, nil
}

// GetRolePermissions получает разрешения роли
func (r *RoleRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*models.Permission, error) {
	query := `
		SELECT p.id, p.name, p.description, p.created_at, p.updated_at
		FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1 AND p.deleted_at IS NULL
		ORDER BY p.name
	`

	var permissions []*models.Permission
	err := r.db.SelectContext(ctx, &permissions, query, roleID)
	if err != nil {
		r.logger.Error("Failed to get role permissions", zap.Error(err), zap.String("role_id", roleID.String()))
		return nil, err
	}

	return permissions, nil
}

// AssignPermissionToRole назначает разрешение роли
func (r *RoleRepository) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id, created_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`

	_, err := r.db.ExecContext(ctx, query, roleID, permissionID, time.Now())
	if err != nil {
		r.logger.Error("Failed to assign permission to role", 
			zap.Error(err), 
			zap.String("role_id", roleID.String()),
			zap.String("permission_id", permissionID.String()),
		)
		return err
	}

	return nil
}

// RemovePermissionFromRole удаляет разрешение у роли
func (r *RoleRepository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `
		DELETE FROM role_permissions
		WHERE role_id = $1 AND permission_id = $2
	`

	result, err := r.db.ExecContext(ctx, query, roleID, permissionID)
	if err != nil {
		r.logger.Error("Failed to remove permission from role", 
			zap.Error(err), 
			zap.String("role_id", roleID.String()),
			zap.String("permission_id", permissionID.String()),
		)
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		r.logger.Error("Failed to get rows affected", zap.Error(err))
		return err
	}

	if rowsAffected == 0 {
		return fmt.Errorf("permission not assigned to role")
	}

	return nil
}

// RoleHasPermission проверяет, имеет ли роль указанное разрешение
func (r *RoleRepository) RoleHasPermission(ctx context.Context, roleID, permissionID uuid.UUID) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1 FROM role_permissions
			WHERE role_id = $1 AND permission_id = $2
		)
	`

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, roleID, permissionID)
	if err != nil {
		r.logger.Error("Failed to check if role has permission", 
			zap.Error(err), 
			zap.String("role_id", roleID.String()),
			zap.String("permission_id", permissionID.String()),
		)
		return false, err
	}

	return exists, nil
}
