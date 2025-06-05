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

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository"
)

type pgxVerificationCodeRepository struct {
	db *pgxpool.Pool
}

// NewPgxVerificationCodeRepository creates a new instance of pgxVerificationCodeRepository.
func NewPgxVerificationCodeRepository(db *pgxpool.Pool) repository.VerificationCodeRepository {
	return &pgxVerificationCodeRepository{db: db}
}

func (r *pgxVerificationCodeRepository) Create(ctx context.Context, vc *entity.VerificationCode) error {
	// created_at has default
	query := `
		INSERT INTO verification_codes (id, user_id, type, code_hash, expires_at, created_at, used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.Exec(ctx, query,
		vc.ID, vc.UserID, vc.Type, vc.CodeHash, vc.ExpiresAt, vc.CreatedAt, vc.UsedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Unique violation on id
			return errors.New("verification code with given ID already exists: " + pgErr.Detail) // Placeholder
		}
		return fmt.Errorf("failed to create verification code: %w", err)
	}
	return nil
}

func (r *pgxVerificationCodeRepository) FindByUserIDAndType(
	ctx context.Context, userID string, codeType entity.VerificationCodeType) (*entity.VerificationCode, error) {
	query := `
		SELECT id, user_id, type, code_hash, expires_at, created_at, used_at
		FROM verification_codes
		WHERE user_id = $1 AND type = $2 AND used_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC LIMIT 1` // Get the latest active one
	vc := &entity.VerificationCode{}
	err := r.db.QueryRow(ctx, query, userID, codeType).Scan(
		&vc.ID, &vc.UserID, &vc.Type, &vc.CodeHash, &vc.ExpiresAt, &vc.CreatedAt, &vc.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("active verification code not found for user and type") // Placeholder for entity.ErrVerificationCodeNotFound
		}
		return nil, fmt.Errorf("failed to find verification code by user ID and type: %w", err)
	}
	return vc, nil
}

func (r *pgxVerificationCodeRepository) FindByCodeHash(ctx context.Context, codeHash string) (*entity.VerificationCode, error) {
	query := `
		SELECT id, user_id, type, code_hash, expires_at, created_at, used_at
		FROM verification_codes
		WHERE code_hash = $1`
	vc := &entity.VerificationCode{}
	err := r.db.QueryRow(ctx, query, codeHash).Scan(
		&vc.ID, &vc.UserID, &vc.Type, &vc.CodeHash, &vc.ExpiresAt, &vc.CreatedAt, &vc.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("verification code not found by hash") // Placeholder
		}
		return nil, fmt.Errorf("failed to find verification code by hash: %w", err)
	}
	return vc, nil
}

func (r *pgxVerificationCodeRepository) FindByID(ctx context.Context, id string) (*entity.VerificationCode, error) {
	query := `
		SELECT id, user_id, type, code_hash, expires_at, created_at, used_at
		FROM verification_codes
		WHERE id = $1`
	vc := &entity.VerificationCode{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&vc.ID, &vc.UserID, &vc.Type, &vc.CodeHash, &vc.ExpiresAt, &vc.CreatedAt, &vc.UsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("verification code not found by ID") // Placeholder
		}
		return nil, fmt.Errorf("failed to find verification code by ID: %w", err)
	}
	return vc, nil
}


func (r *pgxVerificationCodeRepository) MarkAsUsed(ctx context.Context, id string, usedAt time.Time) error {
	query := `UPDATE verification_codes SET used_at = $2 WHERE id = $1 AND used_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, usedAt)
	if err != nil {
		return fmt.Errorf("failed to mark verification code as used: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("verification code not found or already used") // Placeholder
	}
	return nil
}

func (r *pgxVerificationCodeRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM verification_codes WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete verification code by ID: %w", err)
	}
	return nil
}

func (r *pgxVerificationCodeRepository) DeleteByUserIDAndType(
	ctx context.Context, userID string, codeType entity.VerificationCodeType) error {
	query := `DELETE FROM verification_codes WHERE user_id = $1 AND type = $2`
	_, err := r.db.Exec(ctx, query, userID, codeType)
	if err != nil {
		return fmt.Errorf("failed to delete verification codes by user ID and type: %w", err)
	}
	return nil
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
