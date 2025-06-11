// File: backend/services/auth-service/internal/domain/repository/postgres/mfa_backup_code_postgres_repository.go
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
)

// MFABackupCodeRepositoryPostgres implements repository.MFABackupCodeRepository for PostgreSQL.
type MFABackupCodeRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger // Optional
}

// NewMFABackupCodeRepositoryPostgres creates a new instance.
func NewMFABackupCodeRepositoryPostgres(pool *pgxpool.Pool) *MFABackupCodeRepositoryPostgres {
	return &MFABackupCodeRepositoryPostgres{pool: pool}
}

// Create persists a new MFA backup code.
func (r *MFABackupCodeRepositoryPostgres) Create(ctx context.Context, code *models.MFABackupCode) error {
	query := `
		INSERT INTO mfa_backup_codes (id, user_id, code_hash, used_at)
		VALUES ($1, $2, $3, $4)
	`
	// created_at has DB default.
	_, err := r.pool.Exec(ctx, query,
		code.ID, code.UserID, code.CodeHash, code.UsedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation (user_id, code_hash)
				if strings.Contains(pgErr.ConstraintName, "mfa_backup_codes_user_id_code_hash_key") || strings.Contains(pgErr.ConstraintName, "idx_mfa_backup_codes_user_id_code_hash") {
					return fmt.Errorf("backup code hash already exists for this user: %w", domainErrors.ErrDuplicateValue)
				}
				return fmt.Errorf("failed to create MFA backup code due to unique constraint %s: %w", pgErr.ConstraintName, domainErrors.ErrDuplicateValue)
			}
			if pgErr.Code == "23503" { // foreign_key_violation (user_id)
				return fmt.Errorf("user ID '%s' not found for MFA backup code: %w", code.UserID, domainErrors.ErrUserNotFound)
			}
		}
		return fmt.Errorf("failed to create MFA backup code: %w", err)
	}
	return nil
}

// CreateMultiple persists a batch of new MFA backup codes.
func (r *MFABackupCodeRepositoryPostgres) CreateMultiple(ctx context.Context, codes []*models.MFABackupCode) error {
	if len(codes) == 0 {
		return nil
	}

	// Use pgx.CopyFrom for efficient bulk inserts.
	// Column order: id, user_id, code_hash, used_at
	rows := make([][]interface{}, len(codes))
	for i, code := range codes {
		rows[i] = []interface{}{code.ID, code.UserID, code.CodeHash, code.UsedAt}
	}

	copyCount, err := r.pool.CopyFrom(
		ctx,
		pgx.Identifier{"mfa_backup_codes"},
		[]string{"id", "user_id", "code_hash", "used_at"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		// Error handling for bulk insert can be complex.
		// Check for unique constraint violations if necessary, though CopyFrom might not return specific constraint names easily.
		return fmt.Errorf("failed to create multiple MFA backup codes: %w", err)
	}
	if copyCount != int64(len(codes)) {
		return fmt.Errorf("expected to create %d MFA backup codes, but created %d", len(codes), copyCount)
	}
	return nil
}

// FindByUserIDAndCodeHash retrieves an unused MFA backup code.
func (r *MFABackupCodeRepositoryPostgres) FindByUserIDAndCodeHash(ctx context.Context, userID uuid.UUID, codeHash string) (*models.MFABackupCode, error) {
	query := `
		SELECT id, user_id, code_hash, used_at, created_at
		FROM mfa_backup_codes
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
	`
	code := &models.MFABackupCode{}
	err := r.pool.QueryRow(ctx, query, userID, codeHash).Scan(
		&code.ID, &code.UserID, &code.CodeHash, &code.UsedAt, &code.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Or specific ErrMFABackupCodeNotFound / Invalid
		}
		return nil, fmt.Errorf("failed to find MFA backup code by user ID and hash: %w", err)
	}
	return code, nil
}

// FindByUserID retrieves all unused MFA backup codes for a user.
func (r *MFABackupCodeRepositoryPostgres) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.MFABackupCode, error) {
	query := `
               SELECT id, user_id, code_hash, used_at, created_at
               FROM mfa_backup_codes
               WHERE user_id = $1 AND used_at IS NULL
       `
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query MFA backup codes by user ID: %w", err)
	}
	defer rows.Close()

	var codes []*models.MFABackupCode
	for rows.Next() {
		c := &models.MFABackupCode{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.CodeHash, &c.UsedAt, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan MFA backup code: %w", err)
		}
		codes = append(codes, c)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("error iterating MFA backup code rows: %w", rows.Err())
	}
	return codes, nil
}

// MarkAsUsed marks a specific backup code (by ID) as used.
func (r *MFABackupCodeRepositoryPostgres) MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error {
	query := `
		UPDATE mfa_backup_codes
		SET used_at = $1
		WHERE id = $2 AND used_at IS NULL
	`
	result, err := r.pool.Exec(ctx, query, usedAt, id)
	if err != nil {
		return fmt.Errorf("failed to mark MFA backup code as used: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound // Or already used
	}
	return nil
}

// MarkAsUsedByCodeHash marks a specific backup code (by UserID and CodeHash) as used.
func (r *MFABackupCodeRepositoryPostgres) MarkAsUsedByCodeHash(ctx context.Context, userID uuid.UUID, codeHash string, usedAt time.Time) error {
	query := `
		UPDATE mfa_backup_codes
		SET used_at = $1
		WHERE user_id = $2 AND code_hash = $3 AND used_at IS NULL
	`
	result, err := r.pool.Exec(ctx, query, usedAt, userID, codeHash)
	if err != nil {
		return fmt.Errorf("failed to mark MFA backup code as used by code hash: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound // Or already used, or code doesn't match user
	}
	return nil
}

// DeleteByUserID removes all backup codes for a given user ID.
func (r *MFABackupCodeRepositoryPostgres) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `DELETE FROM mfa_backup_codes WHERE user_id = $1`
	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to delete MFA backup codes by user ID: %w", err)
	}
	return result.RowsAffected(), nil
}

// CountActiveByUserID counts unused backup codes for a user.
func (r *MFABackupCodeRepositoryPostgres) CountActiveByUserID(ctx context.Context, userID uuid.UUID) (int, error) {
	query := `SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL`
	var count int
	err := r.pool.QueryRow(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active MFA backup codes: %w", err)
	}
	return count, nil
}

var _ repository.MFABackupCodeRepository = (*MFABackupCodeRepositoryPostgres)(nil)
