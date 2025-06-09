// File: backend/services/auth-service/internal/domain/repository/postgres/user_roles_postgres_repository.go
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	// "github.com/your-org/auth-service/internal/domain/models" // Not directly needed for junction table
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/repository"
)

// UserRolesRepositoryPostgres implements repository.UserRolesRepository for PostgreSQL.
type UserRolesRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger // Optional
}

// NewUserRolesRepositoryPostgres creates a new instance of UserRolesRepositoryPostgres.
func NewUserRolesRepositoryPostgres(pool *pgxpool.Pool /*, logger *zap.Logger*/) *UserRolesRepositoryPostgres {
	return &UserRolesRepositoryPostgres{
		pool: pool,
		// logger: logger,
	}
}

// AssignRoleToUser assigns a role to a user.
func (r *UserRolesRepositoryPostgres) AssignRoleToUser(ctx context.Context, userID uuid.UUID, roleID string, assignedByUserID *uuid.UUID) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, assigned_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_id) DO NOTHING
	`
	// created_at has a DB default.
	_, err := r.pool.Exec(ctx, query, userID, roleID, assignedByUserID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign_key_violation
			// This error means either the user_id or role_id does not exist in their respective tables.
			// r.logger.Error("Foreign key violation assigning role to user", zap.Error(err), zap.String("userID", userID.String()), zap.String("roleID", roleID))
			return fmt.Errorf("user or role not found: %w", domainErrors.ErrNotFound)
		}
		// r.logger.Error("Failed to assign role to user", zap.Error(err), zap.String("userID", userID.String()), zap.String("roleID", roleID))
		return fmt.Errorf("failed to assign role %s to user %s: %w", roleID, userID, err)
	}
	return nil // ON CONFLICT DO NOTHING means no error if already assigned.
}

// RemoveRoleFromUser removes a role assignment from a user.
func (r *UserRolesRepositoryPostgres) RemoveRoleFromUser(ctx context.Context, userID uuid.UUID, roleID string) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`
	result, err := r.pool.Exec(ctx, query, userID, roleID)
	if err != nil {
		// r.logger.Error("Failed to remove role from user", zap.Error(err), zap.String("userID", userID.String()), zap.String("roleID", roleID))
		return fmt.Errorf("failed to remove role %s from user %s: %w", roleID, userID, err)
	}
	if result.RowsAffected() == 0 {
		// This could mean the user or role doesn't exist, or the assignment wasn't there.
		// Returning an error might not be necessary if the desired state (assignment gone) is achieved.
		// However, to be precise, if the intent was to remove an existing assignment, this indicates it wasn't there.
		// For now, treat as non-error to make it idempotent.
		return nil
	}
	return nil
}

// GetRoleIDsForUser retrieves all role IDs for a specific user.
func (r *UserRolesRepositoryPostgres) GetRoleIDsForUser(ctx context.Context, userID uuid.UUID) ([]string, error) {
	query := `SELECT role_id FROM user_roles WHERE user_id = $1`
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		// r.logger.Error("Failed to get role IDs for user", zap.Error(err), zap.String("userID", userID.String()))
		return nil, fmt.Errorf("failed to get role IDs for user %s: %w", userID, err)
	}
	defer rows.Close()

	var roleIDs []string
	for rows.Next() {
		var roleID string
		if errScan := rows.Scan(&roleID); errScan != nil {
			// r.logger.Error("Failed to scan role ID", zap.Error(errScan))
			return nil, fmt.Errorf("failed to scan role ID: %w", errScan)
		}
		roleIDs = append(roleIDs, roleID)
	}
	if err = rows.Err(); err != nil {
        // r.logger.Error("Error iterating user role IDs rows", zap.Error(err))
        return nil, fmt.Errorf("error iterating user role IDs rows: %w", err)
    }
	return roleIDs, nil
}

// GetUserIDsForRole retrieves all user IDs for a specific role.
func (r *UserRolesRepositoryPostgres) GetUserIDsForRole(ctx context.Context, roleID string) ([]uuid.UUID, error) {
	query := `SELECT user_id FROM user_roles WHERE role_id = $1`
	rows, err := r.pool.Query(ctx, query, roleID)
	if err != nil {
		// r.logger.Error("Failed to get user IDs for role", zap.Error(err), zap.String("roleID", roleID))
		return nil, fmt.Errorf("failed to get user IDs for role %s: %w", roleID, err)
	}
	defer rows.Close()

	var userIDs []uuid.UUID
	for rows.Next() {
		var userID uuid.UUID
		if errScan := rows.Scan(&userID); errScan != nil {
			// r.logger.Error("Failed to scan user ID for role", zap.Error(errScan))
			return nil, fmt.Errorf("failed to scan user ID for role: %w", errScan)
		}
		userIDs = append(userIDs, userID)
	}
	if err = rows.Err(); err != nil {
        // r.logger.Error("Error iterating role user IDs rows", zap.Error(err))
        return nil, fmt.Errorf("error iterating role user IDs rows: %w", err)
    }
	return userIDs, nil
}

// IsUserInRole checks if a user is assigned a specific role.
func (r *UserRolesRepositoryPostgres) IsUserInRole(ctx context.Context, userID uuid.UUID, roleID string) (bool, error) {
	query := `SELECT EXISTS (SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2)`
	var exists bool
	err := r.pool.QueryRow(ctx, query, userID, roleID).Scan(&exists)
	if err != nil {
		// r.logger.Error("Failed to check if user is in role", zap.Error(err), zap.String("userID", userID.String()), zap.String("roleID", roleID))
		return false, fmt.Errorf("failed to check if user %s is in role %s: %w", userID, roleID, err)
	}
	return exists, nil
}

// Ensure UserRolesRepositoryPostgres implements repository.UserRolesRepository.
var _ repository.UserRolesRepository = (*UserRolesRepositoryPostgres)(nil)
