// File: backend/services/auth-service/internal/infrastructure/database/user_postgres_repository.go
package database

import (
	"context"
	"errors" // For custom errors or wrapping standard errors
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/google/uuid" // Added for uuid.UUID type
	"fmt" // Added for fmt.Sprintf
	"strings" // Added for strings.Builder and strings.Join

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository" // To refer to the interface
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors" // For domain errors
)

// pgxUserRepository implements the repository.UserRepository interface using pgx.
type pgxUserRepository struct {
	db *pgxpool.Pool
}

// NewPgxUserRepository creates a new instance of pgxUserRepository.
func NewPgxUserRepository(db *pgxpool.Pool) repository.UserRepository {
	return &pgxUserRepository{db: db}
}

// Create persists a new user to the database.
func (r *pgxUserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (
			id, username, email, password_hash, status, 
			email_verified_at, last_login_at, failed_login_attempts, lockout_until, 
			created_at, updated_at, deleted_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)`
	_, err := r.db.Exec(ctx, query,
		user.ID, user.Username, user.Email, user.PasswordHash, user.Status,
		user.EmailVerifiedAt, user.LastLoginAt, user.FailedLoginAttempts, user.LockoutUntil,
		user.CreatedAt, user.UpdatedAt, user.DeletedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" {
				// Check constraint name to distinguish between username and email
				if strings.Contains(pgErr.ConstraintName, "users_username_key") {
					return domainErrors.ErrUsernameExists
				} else if strings.Contains(pgErr.ConstraintName, "users_email_key") {
					return domainErrors.ErrEmailExists
				}
				return fmt.Errorf("user with given username or email already exists: %s: %w", pgErr.Detail, domainErrors.ErrConflict)
			}
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// FindByID retrieves a user by their unique ID.
func (r *pgxUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `
		SELECT 
			id, username, email, password_hash, status, 
			email_verified_at, last_login_at, failed_login_attempts, lockout_until, 
			created_at, updated_at, deleted_at
		FROM users 
		WHERE id = $1 AND deleted_at IS NULL`

	user := &models.User{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Status,
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
func (r *pgxUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT 
			id, username, email, password_hash, status, 
			email_verified_at, last_login_at, failed_login_attempts, lockout_until, 
			created_at, updated_at, deleted_at
		FROM users 
		WHERE email = $1 AND deleted_at IS NULL`

	user := &models.User{}
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Status,
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
func (r *pgxUserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `
		SELECT 
			id, username, email, password_hash, status, 
			email_verified_at, last_login_at, failed_login_attempts, lockout_until, 
			created_at, updated_at, deleted_at
		FROM users 
		WHERE username = $1 AND deleted_at IS NULL`

	user := &models.User{}
	err := r.db.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Status,
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

// Update modifies an existing user's details in the database.
func (r *pgxUserRepository) Update(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users SET
			username = $2, email = $3, password_hash = $4, status = $5,
			email_verified_at = $6, last_login_at = $7, failed_login_attempts = $8, lockout_until = $9,
			updated_at = $10
		WHERE id = $1 AND deleted_at IS NULL`
	
	commandTag, err := r.db.Exec(ctx, query,
		user.ID, user.Username, user.Email, user.PasswordHash, user.Status,
		user.EmailVerifiedAt, user.LastLoginAt, user.FailedLoginAttempts, user.LockoutUntil,
		time.Now(), // Explicitly set updated_at, trigger also handles this
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if strings.Contains(pgErr.ConstraintName, "users_username_key") {
				return domainErrors.ErrUsernameExists
			} else if strings.Contains(pgErr.ConstraintName, "users_email_key") {
				return domainErrors.ErrEmailExists
			}
			return fmt.Errorf("username or email conflict: %s: %w", pgErr.Detail, domainErrors.ErrConflict)
		}
		return fmt.Errorf("failed to update user: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// Delete marks a user as deleted (soft delete).
func (r *pgxUserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET deleted_at = $2, status = $3, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, time.Now(), models.UserStatusDeleted)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdateStatus changes the status of a user.
func (r *pgxUserRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status models.UserStatus) error {
	query := `UPDATE users SET status = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, status, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// SetEmailVerifiedAt sets the email_verified_at timestamp.
func (r *pgxUserRepository) SetEmailVerifiedAt(ctx context.Context, id uuid.UUID, verifiedAt time.Time) error {
	query := `UPDATE users SET email_verified_at = $2, status = CASE WHEN status = $3 THEN $4 ELSE status END, updated_at = $5 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, verifiedAt, models.UserStatusPendingVerification, models.UserStatusActive, time.Now())
	if err != nil {
		return fmt.Errorf("failed to set email verified_at: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdatePassword updates the user's password hash.
func (r *pgxUserRepository) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	query := `UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, passwordHash, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update password hash: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdateFailedLoginAttempts increments failed attempts and sets lockout if applicable.
func (r *pgxUserRepository) UpdateFailedLoginAttempts(ctx context.Context, id uuid.UUID, attempts int, lockoutUntil *time.Time) error {
	query := `UPDATE users SET failed_login_attempts = $2, lockout_until = $3, updated_at = $4 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, attempts, lockoutUntil, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update failed login attempts: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// ResetFailedLoginAttempts resets failed_login_attempts to 0 and clears lockout_until.
func (r *pgxUserRepository) ResetFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET failed_login_attempts = 0, lockout_until = NULL, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, time.Now())
	if err != nil {
		return fmt.Errorf("failed to reset failed login attempts: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdateLastLogin updates the last_login_at timestamp.
func (r *pgxUserRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID, lastLoginAt time.Time) error {
	query := `UPDATE users SET last_login_at = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, lastLoginAt, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update last login time: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// IncrementFailedLoginAttempts increments the counter.
func (r *pgxUserRepository) IncrementFailedLoginAttempts(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET failed_login_attempts = failed_login_attempts + 1, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, time.Now())
	if err != nil {
		return fmt.Errorf("failed to increment failed login attempts: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrUserNotFound
	}
	return nil
}

// UpdateLockout sets/clears the lockout_until timestamp for a user.
func (r *pgxUserRepository) UpdateLockout(ctx context.Context, id uuid.UUID, lockoutUntil *time.Time) error {
    query := `UPDATE users SET lockout_until = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
    commandTag, err := r.db.Exec(ctx, query, id, lockoutUntil, time.Now())
    if err != nil {
        return fmt.Errorf("failed to update lockout: %w", err)
    }
    if commandTag.RowsAffected() == 0 {
        return domainErrors.ErrUserNotFound
    }
    return nil
}

// List retrieves a paginated and filtered list of users.
func (r *pgxUserRepository) List(ctx context.Context, params models.ListUsersParams) ([]*models.User, int, error) {
	var baseQuery strings.Builder
	baseQuery.WriteString(`SELECT id, username, email, password_hash, status, email_verified_at, last_login_at, failed_login_attempts, lockout_until, created_at, updated_at, deleted_at FROM users`)

	var countQuery strings.Builder
	countQuery.WriteString(`SELECT COUNT(*) FROM users`)

	var conditions strings.Builder
	args := []interface{}{}
	argID := 1

	// Always filter out soft-deleted users unless explicitly asked (not part of current params)
	conditions.WriteString(" WHERE deleted_at IS NULL")

	if params.Status != "" {
		if conditions.Len() > 6 { // " WHERE " is 6 chars
			conditions.WriteString(" AND")
		} else if conditions.Len() == 0 { // Should not happen due to deleted_at IS NULL
			conditions.WriteString(" WHERE")
		}
		conditions.WriteString(fmt.Sprintf(" status = $%d", argID))
		args = append(args, params.Status)
		argID++
	}

	if params.UsernameContains != "" {
		if conditions.Len() > 6 {
			conditions.WriteString(" AND")
		} else if conditions.Len() == 0 {
			conditions.WriteString(" WHERE")
		}
		conditions.WriteString(fmt.Sprintf(" username ILIKE $%d", argID))
		args = append(args, "%"+params.UsernameContains+"%")
		argID++
	}

	if params.EmailContains != "" {
		if conditions.Len() > 6 {
			conditions.WriteString(" AND")
		} else if conditions.Len() == 0 {
			conditions.WriteString(" WHERE")
		}
		conditions.WriteString(fmt.Sprintf(" email ILIKE $%d", argID))
		args = append(args, "%"+params.EmailContains+"%")
		argID++
	}

	// Apply conditions to both queries
	baseQuery.WriteString(conditions.String())
	countQuery.WriteString(conditions.String())

	// Get total count
	var total int
	err := r.db.QueryRow(ctx, countQuery.String(), args...).Scan(&total)
	if err != nil {
		// It's possible pgx.ErrNoRows occurs if filters are too restrictive. Treat as 0 results.
		if errors.Is(err, pgx.ErrNoRows) {
			total = 0
		} else {
			return nil, 0, fmt.Errorf("failed to count users: %w", err)
		}
	}

	if total == 0 {
		return []*models.User{}, 0, nil
	}

	// Add pagination to the base query
	baseQuery.WriteString(fmt.Sprintf(" ORDER BY created_at DESC")) // Default sort order
	if params.PageSize > 0 {
		baseQuery.WriteString(fmt.Sprintf(" LIMIT $%d", argID))
		args = append(args, params.PageSize)
		argID++
		if params.Page > 0 {
			offset := (params.Page - 1) * params.PageSize
			baseQuery.WriteString(fmt.Sprintf(" OFFSET $%d", argID))
			args = append(args, offset)
			argID++
		}
	}

	rows, err := r.db.Query(ctx, baseQuery.String(), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	users := []*models.User{}
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Status,
			&user.EmailVerifiedAt, &user.LastLoginAt, &user.FailedLoginAttempts, &user.LockoutUntil,
			&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan user row: %w", err)
		}
		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating user rows: %w", err)
	}

	return users, total, nil
}

// Ensure pgxUserRepository implements UserRepository interface (compile-time check)
var _ repository.UserRepository = (*pgxUserRepository)(nil)

// Helper to import fmt if not already (it's used for error wrapping)
// import "fmt" // Already imported by previous change
// Need to import strings for strings.Join
// import "strings" // Already imported by previous change
