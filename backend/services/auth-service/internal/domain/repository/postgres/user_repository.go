// File: backend/services/auth-service/internal/domain/repository/postgres/user_repository.go
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config" // Assuming this is the correct config path
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository" // For ListUsersParams if it's there, or use models.
)

// UserRepositoryPostgres implements the repository.UserRepository interface using PostgreSQL.
type UserRepositoryPostgres struct {
	pool *pgxpool.Pool
}

// NewUserRepositoryPostgres creates a new instance of UserRepositoryPostgres.
// Note: The original NewPostgresRepository was a generic constructor.
// It's better practice to have specific constructors for each repository type or a shared DB manager.
// For this refactoring, I'm creating a specific constructor for UserRepository.
// The main NewPostgresRepository can be refactored later or used to initialize this.
func NewUserRepositoryPostgres(pool *pgxpool.Pool) *UserRepositoryPostgres {
	return &UserRepositoryPostgres{pool: pool}
}

// Create persists a new user to the database.
func (r *UserRepositoryPostgres) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, username, email, password_hash, salt, status,
		                   email_verified_at, last_login_at, failed_login_attempts, lockout_until,
						   created_at, deleted_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	// created_at has a DB default, updated_at is by trigger.
	// Let's use the user.CreatedAt if provided, otherwise DB default will apply if column is omitted.
	// For explicit control and consistency with the model, we specify it.
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}

	_, err := r.pool.Exec(ctx, query,
		user.ID, user.Username, user.Email, user.PasswordHash, user.Salt, user.Status,
		user.EmailVerifiedAt, user.LastLoginAt, user.FailedLoginAttempts, user.LockoutUntil,
		user.CreatedAt, user.DeletedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505": // unique_violation
				if strings.Contains(pgErr.ConstraintName, "users_email_key") || strings.Contains(pgErr.ConstraintName, "users_email_idx") { // Adjusted for common index names
					return domainErrors.ErrEmailExists
				}
				if strings.Contains(pgErr.ConstraintName, "users_username_key") || strings.Contains(pgErr.ConstraintName, "users_username_idx") {
					return domainErrors.ErrUsernameExists
				}
				return fmt.Errorf("failed to create user due to unique constraint %s: %w", pgErr.ConstraintName, domainErrors.ErrDuplicateValue)
			}
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// FindByID retrieves a user by their unique ID.
func (r *UserRepositoryPostgres) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, salt, status,
		       email_verified_at, last_login_at, failed_login_attempts, lockout_until,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE id = $1 AND deleted_at IS NULL
	`
	user := &models.User{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Salt, &user.Status,
		&user.EmailVerifiedAt, &user.LastLoginAt, &user.FailedLoginAttempts, &user.LockoutUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user by ID: %w", err)
	}
	return user, nil
}

// FindByEmail retrieves a user by their email address.
func (r *UserRepositoryPostgres) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, salt, status,
		       email_verified_at, last_login_at, failed_login_attempts, lockout_until,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL
	`
	user := &models.User{}
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Salt, &user.Status,
		&user.EmailVerifiedAt, &user.LastLoginAt, &user.FailedLoginAttempts, &user.LockoutUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user by email: %w", err)
	}
	return user, nil
}

// FindByUsername retrieves a user by their username.
func (r *UserRepositoryPostgres) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT id, username, email, password_hash, salt, status,
		       email_verified_at, last_login_at, failed_login_attempts, lockout_until,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE username = $1 AND deleted_at IS NULL
	`
	user := &models.User{}
	err := r.pool.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Salt, &user.Status,
		&user.EmailVerifiedAt, &user.LastLoginAt, &user.FailedLoginAttempts, &user.LockoutUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user by username: %w", err)
	}
	return user, nil
}

// Update modifies an existing user's details.
// This implementation updates all fields provided in the user model.
// Consider using map[string]interface{} or specific update methods for more granular control.
func (r *UserRepositoryPostgres) Update(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users
		SET username = $1, email = $2, password_hash = $3, salt = $4, status = $5,
		    email_verified_at = $6, last_login_at = $7, failed_login_attempts = $8, lockout_until = $9
		    -- updated_at is handled by trigger
		WHERE id = $10 AND deleted_at IS NULL
	`
	result, err := r.pool.Exec(ctx, query,
		user.Username, user.Email, user.PasswordHash, user.Salt, user.Status,
		user.EmailVerifiedAt, user.LastLoginAt, user.FailedLoginAttempts, user.LockoutUntil,
		user.ID,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				// More specific error checking for email/username can be done here
				return domainErrors.ErrDuplicateValue
			}
		}
		return fmt.Errorf("failed to update user: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound // Or ErrUpdateFailed if that's more appropriate
	}
	return nil
}

// Delete marks a user as deleted (soft delete).
func (r *UserRepositoryPostgres) Delete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET deleted_at = CURRENT_TIMESTAMP, status = $1
		    -- updated_at is handled by trigger
		WHERE id = $2 AND deleted_at IS NULL
	`
	result, err := r.pool.Exec(ctx, query, models.UserStatusDeleted, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdateStatus changes the status of a user.
func (r *UserRepositoryPostgres) UpdateStatus(ctx context.Context, id uuid.UUID, status models.UserStatus) error {
	query := `
		UPDATE users SET status = $1
		WHERE id = $2 AND deleted_at IS NULL
	`
	// updated_at is handled by trigger
	result, err := r.pool.Exec(ctx, query, status, id)
	if err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// SetEmailVerifiedAt sets the email_verified_at timestamp.
func (r *UserRepositoryPostgres) SetEmailVerifiedAt(ctx context.Context, id uuid.UUID, verifiedAt time.Time) error {
	query := `
		UPDATE users SET email_verified_at = $1
		WHERE id = $2 AND deleted_at IS NULL
	`
	// updated_at is handled by trigger
	result, err := r.pool.Exec(ctx, query, verifiedAt, id)
	if err != nil {
		return fmt.Errorf("failed to set email verified_at: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdatePassword updates the user's password hash (which includes the embedded salt).
func (r *UserRepositoryPostgres) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHashWithSalt string) error {
	query := `
		UPDATE users SET password_hash = $1
		WHERE id = $2 AND deleted_at IS NULL
	`
	// updated_at is handled by trigger. The 'salt' column is considered redundant if salt is embedded in passwordHashWithSalt.
	result, err := r.pool.Exec(ctx, query, passwordHashWithSalt, id)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdateFailedLoginAttempts increments failed login attempts and optionally sets lockout_until.
func (r *UserRepositoryPostgres) UpdateFailedLoginAttempts(ctx context.Context, id uuid.UUID, attempts int, lockoutUntil *time.Time) error {
	query := `
		UPDATE users
		SET failed_login_attempts = $1, lockout_until = $2
		WHERE id = $3 AND deleted_at IS NULL
	`
	// updated_at is handled by trigger
	result, err := r.pool.Exec(ctx, query, attempts, lockoutUntil, id)
	if err != nil {
		return fmt.Errorf("failed to update failed login attempts: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// IncrementFailedLoginAttempts increments the failed_login_attempts counter for a user.
func (r *UserRepositoryPostgres) IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	query := `
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1
        WHERE id = $1 AND deleted_at IS NULL
    `
	// updated_at is handled by trigger
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment failed login attempts: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// ResetFailedLoginAttempts resets the failed login counter and lockout_until for a user.
func (r *UserRepositoryPostgres) ResetFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET failed_login_attempts = 0, lockout_until = NULL
		WHERE id = $1 AND deleted_at IS NULL
	`
	// updated_at is handled by trigger
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to reset failed login attempts: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdateLastLogin updates the last_login_at timestamp for a user.
func (r *UserRepositoryPostgres) UpdateLastLogin(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error {
	query := `
		UPDATE users SET last_login_at = $1
		WHERE id = $2 AND deleted_at IS NULL
	`
	// updated_at is handled by trigger (or could be set to lastLoginAt if desired)
	result, err := r.pool.Exec(ctx, query, lastLoginAt, id)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdateLockout sets/clears the lockout_until timestamp for a user.
func (r *UserRepositoryPostgres) UpdateLockout(ctx context.Context, id uuid.UUID, lockoutUntil *time.Time) error {
	query := `
        UPDATE users
        SET lockout_until = $1
        WHERE id = $2 AND deleted_at IS NULL
    `
	// updated_at will be set by the trigger
	result, err := r.pool.Exec(ctx, query, lockoutUntil, id)
	if err != nil {
		return fmt.Errorf("failed to update lockout status: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// List retrieves a paginated and filtered list of users.
func (r *UserRepositoryPostgres) List(ctx context.Context, params models.ListUsersParams) ([]*models.User, int, error) {
	var users []*models.User
	var totalCount int

	baseQuery := `
		SELECT id, username, email, password_hash, salt, status,
		       email_verified_at, last_login_at, failed_login_attempts, lockout_until,
		       created_at, updated_at, deleted_at
		FROM users
	`
	countQueryBase := `SELECT COUNT(*) FROM users`

	conditions := []string{"deleted_at IS NULL"}
	args := []interface{}{}
	argCount := 1

	if params.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argCount))
		args = append(args, params.Status)
		argCount++
	}
	if params.UsernameContains != "" {
		conditions = append(conditions, fmt.Sprintf("username ILIKE $%d", argCount))
		args = append(args, "%"+params.UsernameContains+"%")
		argCount++
	}
	if params.EmailContains != "" {
		conditions = append(conditions, fmt.Sprintf("email ILIKE $%d", argCount))
		args = append(args, "%"+params.EmailContains+"%")
		argCount++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count with filters
	countQuery := countQueryBase + whereClause
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	if totalCount == 0 {
		return users, 0, nil // No users found, return empty slice
	}

	// Prepare query for fetching users
	query := baseQuery + whereClause + " ORDER BY created_at DESC"
	if params.PageSize > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, params.PageSize)
		argCount++
		if params.Page > 0 {
			offset := (params.Page - 1) * params.PageSize
			query += fmt.Sprintf(" OFFSET $%d", argCount)
			args = append(args, offset)
			argCount++
		}
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		user := &models.User{}
		err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Salt, &user.Status,
			&user.EmailVerifiedAt, &user.LastLoginAt, &user.FailedLoginAttempts, &user.LockoutUntil,
			&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user row: %w", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating user rows: %w", err)
	}

	return users, totalCount, nil
}

// --- Methods from the old PostgresRepository that are not part of UserRepository or RoleRepository ---
// These methods (GetUserRoles, AssignRole, RemoveRole, HasRole, HasPermission, GetRoleByID, GetByName, etc.)
// belong to RoleRepository, UserRolesRepository, or PermissionRepository.
// They should be moved to their respective repository implementations.
// For now, I am commenting them out from this file to focus on UserRepository.
// The original file had a mix, this refactoring aims to separate them.

/*
The following methods were part of the original user_postgres_repository.go but are related to Roles or Permissions.
They will be handled when addressing RoleRepository, PermissionRepository, UserRolesRepository.

func (r *PostgresRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) { ... }
func (r *PostgresRepository) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error { ... }
func (r *PostgresRepository) RemoveRole(ctx context.Context, userID, roleID uuid.UUID) error { ... }
func (r *PostgresRepository) HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) { ... }
func (r *PostgresRepository) HasPermission(ctx context.Context, userID uuid.UUID, permissionName string) (bool, error) { ... }
func (r *PostgresRepository) GetRoleByID(ctx context.Context, id uuid.UUID) (models.Role, error) { ... } // This is RoleRepository specific
func (r *PostgresRepository) GetByName(ctx context.Context, name string) (models.Role, error) { ... } // This is RoleRepository specific
func (r *PostgresRepository) CreateRole(ctx context.Context, role models.Role) (models.Role, error) { ... } // This is RoleRepository specific
func (r *PostgresRepository) UpdateRole(ctx context.Context, role models.Role) error { ... } // This is RoleRepository specific
func (r *PostgresRepository) DeleteRole(ctx context.Context, id uuid.UUID) error { ... } // This is RoleRepository specific
func (r *PostgresRepository) ListRoles(ctx context.Context) ([]models.Role, error) { ... } // This is RoleRepository specific
func (r *PostgresRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]models.Permission, error) { ... }
func (r *PostgresRepository) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error { ... }
func (r *PostgresRepository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error { ... }
func (r *PostgresRepository) RoleHasPermission(ctx context.Context, roleID uuid.UUID, permissionName string) (bool, error) { ... }
func (r *PostgresRepository) GetPermissionByID(ctx context.Context, id uuid.UUID) (models.Permission, error) { ... } // This is PermissionRepository specific
*/

// Ensure UserRepositoryPostgres implements repository.UserRepository.
// The original file had a generic PostgresRepository implementing multiple interfaces.
// This structure is being refactored to have specific repository implementations.
var _ repository.UserRepository = (*UserRepositoryPostgres)(nil)

// The following methods were part of the original user_postgres_repository.go but are not part of the
// current UserRepository interface or are significantly different due to schema changes.
// They are commented out or removed.

// GetByTelegramID: This functionality should move to ExternalAccountRepository.
/*
func (r *PostgresRepository) GetByTelegramID(ctx context.Context, telegramID string) (models.User, error) { ... }
*/

// UpdateEmailVerificationStatus: Replaced by SetEmailVerifiedAt, schema changed from boolean to timestamp.
/*
func (r *PostgresRepository) UpdateEmailVerificationStatus(ctx context.Context, id uuid.UUID, verified bool) error { ... }
*/

// UpdateTwoFactorStatus: This functionality should move to MFASecretRepository.
/*
func (r *PostgresRepository) UpdateTwoFactorStatus(ctx context.Context, id uuid.UUID, secret string, enabled bool) error { ... }
*/

// UpdateTelegramID: This functionality should move to ExternalAccountRepository.
/*
func (r *PostgresRepository) UpdateTelegramID(ctx context.Context, id uuid.UUID, telegramID string) error { ... }
*/

// The old Create method returned (models.User, error), the interface is error. Adjusted.
// The old GetByID, GetByEmail, GetByUsername also fetched roles. This should be optional or a separate call.
// For now, Find methods return the User object without roles pre-filled to keep it focused.
// Roles can be fetched via UserRolesRepository or a service layer concern.
// The original `PostgresRepository` struct and `NewPostgresRepository` constructor were generic.
// I've added `UserRepositoryPostgres` and `NewUserRepositoryPostgres` for clarity.
// The original file also had `Close()`, `GetPool()`, `BeginTx()` methods on `PostgresRepository`.
// These are general DB management methods and should ideally be part of a shared DB manager/handler
// that's passed to specific repositories, rather than each repository implementing them.
// For now, they are removed from this specific user repository file to keep it focused.
// A central `db.Manager` or similar could provide the `*pgxpool.Pool` and transaction capabilities.

// The main NewPostgresRepository from the original file:
/*
func NewPostgresRepository(cfg config.DatabaseConfig) (*PostgresRepository, error) {
	connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName, cfg.SSLMode)

	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connection string: %w", err)
	}

	poolConfig.MaxConns = int32(cfg.MaxOpenConns)
	poolConfig.MinConns = int32(cfg.MaxIdleConns)
	poolConfig.MaxConnLifetime = cfg.ConnMaxLife
	poolConfig.MaxConnIdleTime = cfg.ConnMaxLife / 2

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return &PostgresRepository{ // This was the generic one
		pool: pool,
	}, nil
}
*/

// Methods for Role management are also in the original file.
