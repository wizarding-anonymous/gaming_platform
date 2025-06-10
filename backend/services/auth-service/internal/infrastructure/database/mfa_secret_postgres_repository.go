// File: backend/services/auth-service/internal/infrastructure/database/mfa_secret_postgres_repository.go
package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/entity"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
)

type pgxMFASecretRepository struct {
	db *pgxpool.Pool
}

// NewPgxMFASecretRepository creates a new instance of pgxMFASecretRepository.
func NewPgxMFASecretRepository(db *pgxpool.Pool) repository.MFASecretRepository {
	return &pgxMFASecretRepository{db: db}
}

func (r *pgxMFASecretRepository) Create(ctx context.Context, secret *entity.MFASecret) error {
	// Trigger handles updated_at, created_at has default
	query := `
		INSERT INTO mfa_secrets (id, user_id, type, secret_key_encrypted, verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.Exec(ctx, query,
		secret.ID, secret.UserID, secret.Type, secret.SecretKeyEncrypted,
		secret.Verified, secret.CreatedAt, secret.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Unique violation on (user_id, type) or id
			return errors.New("MFA secret for this user and type already exists or ID conflict: " + pgErr.Detail) // Placeholder
		}
		return fmt.Errorf("failed to create MFA secret: %w", err)
	}
	return nil
}

func (r *pgxMFASecretRepository) FindByUserID(ctx context.Context, userID string) (*entity.MFASecret, error) {
	// Assuming TOTP is the primary/only type for this simplified FindByUserID
	return r.FindByUserIDAndType(ctx, userID, entity.MFATypeTOTP)
}

func (r *pgxMFASecretRepository) FindByUserIDAndType(
	ctx context.Context, userID string, mfaType entity.MFAType) (*entity.MFASecret, error) {
	query := `
		SELECT id, user_id, type, secret_key_encrypted, verified, created_at, updated_at
		FROM mfa_secrets
		WHERE user_id = $1 AND type = $2`
	secret := &entity.MFASecret{}
	err := r.db.QueryRow(ctx, query, userID, mfaType).Scan(
		&secret.ID, &secret.UserID, &secret.Type, &secret.SecretKeyEncrypted,
		&secret.Verified, &secret.CreatedAt, &secret.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("MFA secret not found") // Placeholder for entity.ErrMFASecretNotFound
		}
		return nil, fmt.Errorf("failed to find MFA secret by user ID and type: %w", err)
	}
	return secret, nil
}

func (r *pgxMFASecretRepository) Update(ctx context.Context, secret *entity.MFASecret) error {
	// Trigger handles updated_at
	query := `
		UPDATE mfa_secrets SET
			secret_key_encrypted = $2, verified = $3, updated_at = $4
		WHERE id = $1 AND user_id = $5 AND type = $6` // Ensure type is not changed, and user_id matches
	commandTag, err := r.db.Exec(ctx, query,
		secret.ID, secret.SecretKeyEncrypted, secret.Verified, time.Now(), secret.UserID, secret.Type,
	)
	if err != nil {
		return fmt.Errorf("failed to update MFA secret: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("MFA secret not found or no changes made") // Placeholder
	}
	return nil
}

func (r *pgxMFASecretRepository) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE FROM mfa_secrets WHERE user_id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete MFA secrets by user ID: %w", err)
	}
	return nil
}

func (r *pgxMFASecretRepository) DeleteByUserIDAndType(ctx context.Context, userID string, mfaType entity.MFAType) error {
	query := `DELETE FROM mfa_secrets WHERE user_id = $1 AND type = $2`
	_, err := r.db.Exec(ctx, query, userID, mfaType)
	if err != nil {
		return fmt.Errorf("failed to delete MFA secret by user ID and type: %w", err)
	}
	return nil
}

var _ repository.MFASecretRepository = (*pgxMFASecretRepository)(nil)