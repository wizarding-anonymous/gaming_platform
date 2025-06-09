// File: backend/services/auth-service/internal/infrastructure/database/mfa_backup_code_postgres_repository.go
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

type pgxMFABackupCodeRepository struct {
	db *pgxpool.Pool
}

// NewPgxMFABackupCodeRepository creates a new instance of pgxMFABackupCodeRepository.
func NewPgxMFABackupCodeRepository(db *pgxpool.Pool) repository.MFABackupCodeRepository {
	return &pgxMFABackupCodeRepository{db: db}
}

func (r *pgxMFABackupCodeRepository) Create(ctx context.Context, code *entity.MFABackupCode) error {
	query := `
		INSERT INTO mfa_backup_codes (id, user_id, code_hash, used_at, created_at)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := r.db.Exec(ctx, query,
		code.ID, code.UserID, code.CodeHash, code.UsedAt, code.CreatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		// Check for unique constraint on (user_id, code_hash) or id
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { 
			return errors.New("MFA backup code already exists or ID conflict: " + pgErr.Detail) // Placeholder
		}
		return fmt.Errorf("failed to create MFA backup code: %w", err)
	}
	return nil
}

func (r *pgxMFABackupCodeRepository) CreateMultiple(ctx context.Context, codes []*entity.MFABackupCode) error {
	// Use a transaction for batch insert
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for creating multiple MFA backup codes: %w", err)
	}
	defer tx.Rollback(ctx) // Rollback if not committed

	// Using pgx.CopyFrom for efficient batch insert
	columnNames := []string{"id", "user_id", "code_hash", "used_at", "created_at"}
	rows := make([][]interface{}, len(codes))
	for i, code := range codes {
		rows[i] = []interface{}{code.ID, code.UserID, code.CodeHash, code.UsedAt, code.CreatedAt}
	}

	_, err = tx.CopyFrom(ctx, pgx.Identifier{"mfa_backup_codes"}, columnNames, pgx.CopyFromRows(rows))
	if err != nil {
		return fmt.Errorf("failed to copy multiple MFA backup codes: %w", err)
	}

	return tx.Commit(ctx)
}


func (r *pgxMFABackupCodeRepository) FindByUserIDAndCodeHash(
	ctx context.Context, userID string, codeHash string) (*entity.MFABackupCode, error) {
	query := `
		SELECT id, user_id, code_hash, used_at, created_at
		FROM mfa_backup_codes
		WHERE user_id = $1 AND code_hash = $2`
	code := &entity.MFABackupCode{}
	err := r.db.QueryRow(ctx, query, userID, codeHash).Scan(
		&code.ID, &code.UserID, &code.CodeHash, &code.UsedAt, &code.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("MFA backup code not found") // Placeholder for entity.ErrMFABackupCodeNotFound
		}
		return nil, fmt.Errorf("failed to find MFA backup code by user ID and hash: %w", err)
	}
	return code, nil
}

func (r *pgxMFABackupCodeRepository) MarkAsUsed(ctx context.Context, id string, usedAt time.Time) error {
	query := `UPDATE mfa_backup_codes SET used_at = $2 WHERE id = $1 AND used_at IS NULL`
	commandTag, err := r.db.Exec(ctx, query, id, usedAt)
	if err != nil {
		return fmt.Errorf("failed to mark MFA backup code as used: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("MFA backup code not found or already used") // Placeholder
	}
	return nil
}

func (r *pgxMFABackupCodeRepository) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE FROM mfa_backup_codes WHERE user_id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete MFA backup codes by user ID: %w", err)
	}
	return nil
}

func (r *pgxMFABackupCodeRepository) CountActiveByUserID(ctx context.Context, userID string) (int, error) {
	query := `SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL`
	var count int
	err := r.db.QueryRow(ctx, query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active MFA backup codes: %w", err)
	}
	return count, nil
}

var _ repository.MFABackupCodeRepository = (*pgxMFABackupCodeRepository)(nil)
