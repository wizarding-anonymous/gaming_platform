// File: backend/services/auth-service/internal/domain/repository/postgres/verification_code_postgres_repository.go
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
	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/domain/repository"
)

// VerificationCodeRepositoryPostgres implements repository.VerificationCodeRepository.
type VerificationCodeRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger // Optional
}

// NewVerificationCodeRepositoryPostgres creates a new instance.
func NewVerificationCodeRepositoryPostgres(pool *pgxpool.Pool) *VerificationCodeRepositoryPostgres {
	return &VerificationCodeRepositoryPostgres{pool: pool}
}

// Create persists a new verification code.
func (r *VerificationCodeRepositoryPostgres) Create(ctx context.Context, vc *models.VerificationCode) error {
	query := `
		INSERT INTO verification_codes (id, user_id, type, code_hash, expires_at, used_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	// created_at has DB default.
	_, err := r.pool.Exec(ctx, query,
		vc.ID, vc.UserID, vc.Type, vc.CodeHash, vc.ExpiresAt, vc.UsedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" { // foreign_key_violation (user_id)
			return fmt.Errorf("user ID '%s' not found for verification code: %w", vc.UserID, domainErrors.ErrUserNotFound)
		}
		// Note: The schema has an index on (user_id, type), not a unique constraint by default from 000006.
		// If it were unique, code 23505 should be checked.
		return fmt.Errorf("failed to create verification code: %w", err)
	}
	return nil
}

// FindByUserIDAndType retrieves an active verification code for a user and type.
func (r *VerificationCodeRepositoryPostgres) FindByUserIDAndType(ctx context.Context, userID uuid.UUID, codeType models.VerificationCodeType) (*models.VerificationCode, error) {
	query := `
		SELECT id, user_id, type, code_hash, expires_at, created_at, used_at
		FROM verification_codes
		WHERE user_id = $1 AND type = $2 AND used_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1
		// Ensure we get the latest valid one if multiple somehow exist (should be rare)
	`
	vc := &models.VerificationCode{}
	err := r.pool.QueryRow(ctx, query, userID, codeType).Scan(
		&vc.ID, &vc.UserID, &vc.Type, &vc.CodeHash, &vc.ExpiresAt, &vc.CreatedAt, &vc.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Or specific ErrVerificationCodeNotFound
		}
		return nil, fmt.Errorf("failed to find verification code by user ID and type: %w", err)
	}
	return vc, nil
}

// FindByCodeHashAndType retrieves an active verification code by its hash and type.
func (r *VerificationCodeRepositoryPostgres) FindByCodeHashAndType(ctx context.Context, codeHash string, codeType models.VerificationCodeType) (*models.VerificationCode, error) {
	query := `
		SELECT id, user_id, type, code_hash, expires_at, created_at, used_at
		FROM verification_codes
		WHERE code_hash = $1 AND type = $2 AND used_at IS NULL AND expires_at > NOW()
	`
	vc := &models.VerificationCode{}
	// This might return multiple if code_hash is not globally unique across users for a type.
	// The spec index idx_verification_codes_code_hash_type implies it could be.
	// If a code should be unique, a unique constraint on (code_hash, type) would be better.
	err := r.pool.QueryRow(ctx, query, codeHash, codeType).Scan(
		&vc.ID, &vc.UserID, &vc.Type, &vc.CodeHash, &vc.ExpiresAt, &vc.CreatedAt, &vc.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Or specific ErrVerificationCodeInvalid
		}
		return nil, fmt.Errorf("failed to find verification code by hash and type: %w", err)
	}
	return vc, nil
}

// FindByID retrieves a verification code by its ID.
func (r *VerificationCodeRepositoryPostgres) FindByID(ctx context.Context, id uuid.UUID) (*models.VerificationCode, error) {
	query := `
		SELECT id, user_id, type, code_hash, expires_at, created_at, used_at
		FROM verification_codes
		WHERE id = $1
	`
	vc := &models.VerificationCode{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&vc.ID, &vc.UserID, &vc.Type, &vc.CodeHash, &vc.ExpiresAt, &vc.CreatedAt, &vc.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find verification code by ID: %w", err)
	}
	return vc, nil
}

// MarkAsUsed marks a verification code as used.
func (r *VerificationCodeRepositoryPostgres) MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error {
	query := `
		UPDATE verification_codes
		SET used_at = $1
		WHERE id = $2 AND used_at IS NULL AND expires_at > NOW()
		// Only mark as used if it's not already used and not expired
	`
	result, err := r.pool.Exec(ctx, query, usedAt, id)
	if err != nil {
		return fmt.Errorf("failed to mark verification code as used: %w", err)
	}
	if result.RowsAffected() == 0 {
		// Could be not found, already used, or expired
		return domainErrors.ErrNotFound // Or a more specific error like ErrVerificationCodeInvalidOrUsed
	}
	return nil
}

// Delete removes a verification code by its ID.
func (r *VerificationCodeRepositoryPostgres) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM verification_codes WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete verification code: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound
	}
	return nil
}

// DeleteByUserIDAndType removes all verification codes for a user and type.
func (r *VerificationCodeRepositoryPostgres) DeleteByUserIDAndType(ctx context.Context, userID uuid.UUID, codeType models.VerificationCodeType) (int64, error) {
	query := `DELETE FROM verification_codes WHERE user_id = $1 AND type = $2`
	result, err := r.pool.Exec(ctx, query, userID, codeType)
	if err != nil {
		return 0, fmt.Errorf("failed to delete verification codes by user ID and type: %w", err)
	}
	return result.RowsAffected(), nil
}

// DeleteExpired removes all expired verification codes.
func (r *VerificationCodeRepositoryPostgres) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM verification_codes WHERE expires_at < NOW()`
	result, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired verification codes: %w", err)
	}
	return result.RowsAffected(), nil
}

var _ repository.VerificationCodeRepository = (*VerificationCodeRepositoryPostgres)(nil)
