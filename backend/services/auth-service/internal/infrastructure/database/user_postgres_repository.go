package database

import (
	"context"
	"errors" // For custom errors or wrapping standard errors
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository" // To refer to the interface
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
func (r *pgxUserRepository) Create(ctx context.Context, user *entity.User) error {
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
			// Handle specific PostgreSQL errors, e.g., unique constraint violation
			if pgErr.Code == "23505" { // Unique violation
				// Consider wrapping this in a custom error, e.g., entity.ErrUserAlreadyExists
				return errors.New("user with given username or email already exists: " + pgErr.Detail)
			}
		}
		// Consider wrapping generic errors too for better context
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// FindByID retrieves a user by their unique ID.
func (r *pgxUserRepository) FindByID(ctx context.Context, id string) (*entity.User, error) {
	query := `
		SELECT 
			id, username, email, password_hash, status, 
			email_verified_at, last_login_at, failed_login_attempts, lockout_until, 
			created_at, updated_at, deleted_at
		FROM users 
		WHERE id = $1 AND deleted_at IS NULL` // Assuming soft delete check

	user := &entity.User{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Status,
		&user.EmailVerifiedAt, &user.LastLoginAt, &user.FailedLoginAttempts, &user.LockoutUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Use a custom error defined in entity or errors package
			// return nil, entity.ErrUserNotFound 
			return nil, errors.New("user not found") // Placeholder for custom error
		}
		return nil, fmt.Errorf("failed to find user by ID: %w", err)
	}
	return user, nil
}

// FindByEmail retrieves a user by their email address.
func (r *pgxUserRepository) FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	query := `
		SELECT 
			id, username, email, password_hash, status, 
			email_verified_at, last_login_at, failed_login_attempts, lockout_until, 
			created_at, updated_at, deleted_at
		FROM users 
		WHERE email = $1 AND deleted_at IS NULL`

	user := &entity.User{}
	err := r.db.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Status,
		&user.EmailVerifiedAt, &user.LastLoginAt, &user.FailedLoginAttempts, &user.LockoutUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// return nil, entity.ErrUserNotFound
			return nil, errors.New("user not found") // Placeholder
		}
		return nil, fmt.Errorf("failed to find user by email: %w", err)
	}
	return user, nil
}

// FindByUsername retrieves a user by their username.
func (r *pgxUserRepository) FindByUsername(ctx context.Context, username string) (*entity.User, error) {
	query := `
		SELECT 
			id, username, email, password_hash, status, 
			email_verified_at, last_login_at, failed_login_attempts, lockout_until, 
			created_at, updated_at, deleted_at
		FROM users 
		WHERE username = $1 AND deleted_at IS NULL`

	user := &entity.User{}
	err := r.db.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Status,
		&user.EmailVerifiedAt, &user.LastLoginAt, &user.FailedLoginAttempts, &user.LockoutUntil,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// return nil, entity.ErrUserNotFound
			return nil, errors.New("user not found") // Placeholder
		}
		return nil, fmt.Errorf("failed to find user by username: %w", err)
	}
	return user, nil
}

// Update modifies an existing user's details in the database.
// This implementation assumes all updatable fields are set in the user struct.
// A more granular approach might involve specific update methods for different fields.
func (r *pgxUserRepository) Update(ctx context.Context, user *entity.User) error {
	// Ensure updated_at is set before updating
	// user.UpdatedAt = time.Now() // This should ideally be handled by the database trigger or service layer

	query := `
		UPDATE users SET
			username = $2, email = $3, password_hash = $4, status = $5,
			email_verified_at = $6, last_login_at = $7, failed_login_attempts = $8, lockout_until = $9,
			updated_at = $10 -- Trigger should handle this, but explicit set is also possible
			-- created_at is generally not updated. deleted_at is handled by Delete method.
		WHERE id = $1 AND deleted_at IS NULL`
	
	// If your trigger handles updated_at, you might not need to pass it here, or pass time.Now()
	// For safety, ensure the entity's UpdatedAt is correctly set if not using a DB trigger for it.
	// The migration 000006 sets up a trigger for updated_at.
	
	commandTag, err := r.db.Exec(ctx, query,
		user.ID, user.Username, user.Email, user.PasswordHash, user.Status,
		user.EmailVerifiedAt, user.LastLoginAt, user.FailedLoginAttempts, user.LockoutUntil,
		time.Now(), // Explicitly setting updated_at for the query, trigger will also fire.
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// return entity.ErrUserAlreadyExists (or a more specific conflict error)
			return errors.New("username or email conflict: " + pgErr.Detail) // Placeholder
		}
		return fmt.Errorf("failed to update user: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		// return entity.ErrUserNotFound // Or some other error indicating no rows updated
		return errors.New("user not found or no changes made") // Placeholder
	}
	return nil
}

// Delete marks a user as deleted (soft delete).
func (r *pgxUserRepository) Delete(ctx context.Context, id string, deletedAt time.Time) error {
	query := `UPDATE users SET deleted_at = $2, status = $3 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, deletedAt, entity.UserStatusDeleted)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		// return entity.ErrUserNotFound
		return errors.New("user not found or already deleted") // Placeholder
	}
	return nil
}

// UpdateStatus changes the status of a user.
func (r *pgxUserRepository) UpdateStatus(ctx context.Context, id string, status entity.UserStatus) error {
	query := `UPDATE users SET status = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, status, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		// return entity.ErrUserNotFound
		return errors.New("user not found") // Placeholder
	}
	return nil
}

// UpdateEmailVerification sets the email_verified_at timestamp.
func (r *pgxUserRepository) UpdateEmailVerification(ctx context.Context, id string, verifiedAt time.Time) error {
	query := `UPDATE users SET email_verified_at = $2, status = $3, updated_at = $4 WHERE id = $1 AND deleted_at IS NULL`
	// Typically, status also changes to 'active' if it was 'pending_verification'
	commandTag, err := r.db.Exec(ctx, query, id, verifiedAt, entity.UserStatusActive, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update email verification status: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		// return entity.ErrUserNotFound
		return errors.New("user not found") // Placeholder
	}
	return nil
}

// UpdatePasswordHash updates the user's password hash.
func (r *pgxUserRepository) UpdatePasswordHash(ctx context.Context, id string, passwordHash string) error {
	query := `UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, passwordHash, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update password hash: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		// return entity.ErrUserNotFound
		return errors.New("user not found") // Placeholder
	}
	return nil
}

// UpdateFailedLoginAttempts increments failed attempts and sets lockout if applicable.
func (r *pgxUserRepository) UpdateFailedLoginAttempts(ctx context.Context, id string, attempts int, lockoutUntil *time.Time) error {
	query := `UPDATE users SET failed_login_attempts = $2, lockout_until = $3, updated_at = $4 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, attempts, lockoutUntil, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update failed login attempts: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		// return entity.ErrUserNotFound
		return errors.New("user not found") // Placeholder
	}
	return nil
}

// ResetFailedLoginAttempts resets failed_login_attempts to 0 and clears lockout_until.
func (r *pgxUserRepository) ResetFailedLoginAttempts(ctx context.Context, id string) error {
	query := `UPDATE users SET failed_login_attempts = 0, lockout_until = NULL, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, time.Now())
	if err != nil {
		return fmt.Errorf("failed to reset failed login attempts: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		// return entity.ErrUserNotFound
		return errors.New("user not found") // Placeholder
	}
	return nil
}

// UpdateLastLogin updates the last_login_at timestamp.
func (r *pgxUserRepository) UpdateLastLogin(ctx context.Context, id string, lastLoginAt time.Time) error {
	query := `UPDATE users SET last_login_at = $2, updated_at = $3 WHERE id = $1 AND deleted_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, lastLoginAt, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update last login time: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		// return entity.ErrUserNotFound
		return errors.New("user not found") // Placeholder
	}
	return nil
}

// UpdateUserStatusFields updates specific fields related to a user's status.
func (r *pgxUserRepository) UpdateUserStatusFields(ctx context.Context, userID string, status entity.UserStatus, statusReason *string, lockoutUntil *time.Time, updatedBy *string) error {
	var setClauses []string
	args := []interface{}{}
	argCount := 1

	// Always update status and updated_at
	setClauses = append(setClauses, fmt.Sprintf("status = $%d", argCount))
	args = append(args, status)
	argCount++

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argCount))
	args = append(args, time.Now().UTC()) // Ensure UTC for consistency
	argCount++

	if statusReason != nil {
		setClauses = append(setClauses, fmt.Sprintf("status_reason = $%d", argCount))
		args = append(args, *statusReason)
		argCount++
	}
	if lockoutUntil != nil {
		setClauses = append(setClauses, fmt.Sprintf("lockout_until = $%d", argCount))
		args = append(args, *lockoutUntil)
		argCount++
	} else { // Explicitly set to NULL if nil is passed and it's meant to clear it
		// Check if the current status implies clearing lockout (e.g., unblocking)
		if status == entity.UserStatusActive { // Example condition
			setClauses = append(setClauses, "lockout_until = NULL")
		}
	}

	if updatedBy != nil {
		setClauses = append(setClauses, fmt.Sprintf("updated_by = $%d", argCount))
		args = append(args, *updatedBy)
		argCount++
	}

	if len(setClauses) == 0 {
		// Nothing to update other than potentially updated_at if it were standalone
		// but status is always updated here.
		return errors.New("no fields to update for user status")
	}

	args = append(args, userID) // For WHERE clause
	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d AND deleted_at IS NULL",
		strings.Join(setClauses, ", "), argCount)

	commandTag, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update user status fields: %w", err)
	}

	if commandTag.RowsAffected() == 0 {
		// return entity.ErrUserNotFound // Or a more specific "update failed" error
		return errors.New("user not found or no update executed") // Placeholder
	}

	return nil
}


// Ensure pgxUserRepository implements UserRepository interface (compile-time check)
var _ repository.UserRepository = (*pgxUserRepository)(nil)

// Helper to import fmt if not already (it's used for error wrapping)
import "fmt"
// Need to import strings for strings.Join
import "strings"
