// File: backend/services/auth-service/internal/infrastructure/database/verification_code_postgres_repository.go
package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/google/uuid" // Added

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models" // Changed
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors" // Added
)

type pgxVerificationCodeRepository struct {
	db *pgxpool.Pool
}

// NewPgxVerificationCodeRepository creates a new instance of pgxVerificationCodeRepository.
func NewPgxVerificationCodeRepository(db *pgxpool.Pool) repository.VerificationCodeRepository {
	return &pgxVerificationCodeRepository{db: db}
}

func (r *pgxVerificationCodeRepository) Create(ctx context.Context, vc *models.VerificationCode) error { // Changed
	// created_at has default
	query := `
		INSERT INTO verification_codes (id, user_id, type, code_hash, expires_at, created_at, used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.Exec(ctx, query,
		vc.ID, vc.UserID, vc.Type, vc.CodeHash, vc.ExpiresAt, vc.CreatedAt, vc.UsedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: verification code with given ID already exists: %s", domainErrors.ErrConflict, pgErr.Detail)
		}
		return fmt.Errorf("failed to create verification code: %w", err)
	}
	return nil
}

func (r *pgxVerificationCodeRepository) FindByUserIDAndType(
	ctx context.Context, userID uuid.UUID, codeType models.VerificationCodeType) (*models.VerificationCode, error) { // Changed
	query := `
		SELECT id, user_id, type, code_hash, expires_at, created_at, used_at
		FROM verification_codes
		WHERE user_id = $1 AND type = $2 AND used_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC LIMIT 1`
	vc := &models.VerificationCode{} // Changed
	err := r.db.QueryRow(ctx, query, userID, codeType).Scan(
		&vc.ID, &vc.UserID, &vc.Type, &vc.CodeHash, &vc.ExpiresAt, &vc.CreatedAt, &vc.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Changed
		}
		return nil, fmt.Errorf("failed to find verification code by user ID and type: %w", err)
	}
	return vc, nil
}

// FindByCodeHashAndType retrieves an active (not used, not expired) verification code
// by its hashed value and type.
func (r *pgxVerificationCodeRepository) FindByCodeHashAndType(
	ctx context.Context, codeHash string, codeType models.VerificationCodeType) (*models.VerificationCode, error) { // Added method
	query := `
		SELECT id, user_id, type, code_hash, expires_at, created_at, used_at
		FROM verification_codes
		WHERE code_hash = $1 AND type = $2 AND used_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC LIMIT 1`
	vc := &models.VerificationCode{}
	err := r.db.QueryRow(ctx, query, codeHash, codeType).Scan(
		&vc.ID, &vc.UserID, &vc.Type, &vc.CodeHash, &vc.ExpiresAt, &vc.CreatedAt, &vc.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find verification code by hash and type: %w", err)
	}
	return vc, nil
}


func (r *pgxVerificationCodeRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.VerificationCode, error) { // Changed
	query := `
		SELECT id, user_id, type, code_hash, expires_at, created_at, used_at
		FROM verification_codes
		WHERE id = $1`
	vc := &models.VerificationCode{} // Changed
	err := r.db.QueryRow(ctx, query, id).Scan(
		&vc.ID, &vc.UserID, &vc.Type, &vc.CodeHash, &vc.ExpiresAt, &vc.CreatedAt, &vc.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Changed
		}
		return nil, fmt.Errorf("failed to find verification code by ID: %w", err)
	}
	return vc, nil
}


func (r *pgxVerificationCodeRepository) MarkAsUsed(ctx context.Context, id uuid.UUID, usedAt time.Time) error { // Changed
	query := `UPDATE verification_codes SET used_at = $2 WHERE id = $1 AND used_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, usedAt)
	if err != nil {
		return fmt.Errorf("failed to mark verification code as used: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrNotFound // Changed (or specific error like "already used or not found")
	}
	return nil
}

func (r *pgxVerificationCodeRepository) Delete(ctx context.Context, id uuid.UUID) error { // Changed
	query := `DELETE FROM verification_codes WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, id) // Added commandTag
	if err != nil {
		return fmt.Errorf("failed to delete verification code by ID: %w", err)
	}
	if commandTag.RowsAffected() == 0 { // Added check
		return domainErrors.ErrNotFound
	}
	return nil
}

func (r *pgxVerificationCodeRepository) DeleteByUserIDAndType(
	ctx context.Context, userID uuid.UUID, codeType models.VerificationCodeType) (int64, error) { // Changed signature
	query := `DELETE FROM verification_codes WHERE user_id = $1 AND type = $2`
	commandTag, err := r.db.Exec(ctx, query, userID, codeType)
	if err != nil {
		return 0, fmt.Errorf("failed to delete verification codes by user ID and type: %w", err)
	}
	return commandTag.RowsAffected(), nil
}

func (r *pgxVerificationCodeRepository) DeleteAllByUserID(ctx context.Context, userID uuid.UUID) (int64, error) { // Added method
	query := `DELETE FROM verification_codes WHERE user_id = $1`
	commandTag, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to delete all verification codes by user ID: %w", err)
	}
	return commandTag.RowsAffected(), nil
}

func (r *pgxVerificationCodeRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM verification_codes WHERE expires_at < $1`
	commandTag, err := r.db.Exec(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired verification codes: %w", err)
	}
	return commandTag.RowsAffected(), nil
}

var _ repository.VerificationCodeRepository = (*pgxVerificationCodeRepository)(nil)
