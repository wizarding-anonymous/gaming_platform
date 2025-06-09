// File: backend/services/auth-service/internal/domain/repository/postgres/mfa_secret_postgres_repository.go
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
)

// MFASecretRepositoryPostgres implements repository.MFASecretRepository for PostgreSQL.
type MFASecretRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger // Optional
}

// NewMFASecretRepositoryPostgres creates a new instance.
func NewMFASecretRepositoryPostgres(pool *pgxpool.Pool) *MFASecretRepositoryPostgres {
	return &MFASecretRepositoryPostgres{pool: pool}
}

// FindByID retrieves an MFA secret by its primary ID.
func (r *MFASecretRepositoryPostgres) FindByID(ctx context.Context, id uuid.UUID) (*models.MFASecret, error) {
	query := `
		SELECT id, user_id, type, secret_key_encrypted, verified, created_at, updated_at
		FROM mfa_secrets
		WHERE id = $1
	`
	s := &models.MFASecret{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&s.ID, &s.UserID, &s.Type, &s.SecretKeyEncrypted, &s.Verified, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find MFA secret by ID: %w", err)
	}
	return s, nil
}

// Create persists a new MFA secret.
func (r *MFASecretRepositoryPostgres) Create(ctx context.Context, secret *models.MFASecret) error {
	query := `
		INSERT INTO mfa_secrets (id, user_id, type, secret_key_encrypted, verified)
		VALUES ($1, $2, $3, $4, $5)
	`
	// created_at and updated_at are handled by DB defaults/triggers.
	_, err := r.pool.Exec(ctx, query,
		secret.ID, secret.UserID, secret.Type, secret.SecretKeyEncrypted, secret.Verified,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				// Schema has UNIQUE (user_id, type)
				if strings.Contains(pgErr.ConstraintName, "mfa_secrets_user_id_type_key") || strings.Contains(pgErr.ConstraintName, "idx_mfa_secrets_user_id_type") {
					return fmt.Errorf("MFA secret for user ID '%s' and type '%s' already exists: %w",
						secret.UserID, secret.Type, domainErrors.ErrDuplicateValue)
				}
				return fmt.Errorf("failed to create MFA secret due to unique constraint %s: %w", pgErr.ConstraintName, domainErrors.ErrDuplicateValue)
			}
			if pgErr.Code == "23503" { // foreign_key_violation (user_id)
				return fmt.Errorf("user ID '%s' not found for MFA secret: %w", secret.UserID, domainErrors.ErrUserNotFound)
			}
		}
		return fmt.Errorf("failed to create MFA secret: %w", err)
	}
	return nil
}

// FindByUserIDAndType retrieves an MFA secret for a specific user and type.
func (r *MFASecretRepositoryPostgres) FindByUserIDAndType(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) (*models.MFASecret, error) {
	query := `
		SELECT id, user_id, type, secret_key_encrypted, verified, created_at, updated_at
		FROM mfa_secrets
		WHERE user_id = $1 AND type = $2
	`
	s := &models.MFASecret{}
	err := r.pool.QueryRow(ctx, query, userID, mfaType).Scan(
		&s.ID, &s.UserID, &s.Type, &s.SecretKeyEncrypted, &s.Verified, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Or specific ErrMFASecretNotFound
		}
		return nil, fmt.Errorf("failed to find MFA secret by user ID and type: %w", err)
	}
	return s, nil
}

// Update modifies an existing MFA secret (e.g., to mark as verified or change the key).
func (r *MFASecretRepositoryPostgres) Update(ctx context.Context, secret *models.MFASecret) error {
	query := `
		UPDATE mfa_secrets
		SET secret_key_encrypted = $1, verified = $2
		WHERE id = $3 AND user_id = $4 AND type = $5
		// Ensures that we are updating the specific secret for the user and type.
		// ID alone should be sufficient if it's the primary key being used to identify the record.
	`
	// For more precise update, an ID is better:
	queryPrecise := `UPDATE mfa_secrets SET secret_key_encrypted = $1, verified = $2 WHERE id = $3`

	// updated_at is handled by trigger.
	result, err := r.pool.Exec(ctx, queryPrecise,
		secret.SecretKeyEncrypted, secret.Verified, secret.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update MFA secret: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound // Or specific ErrMFASecretNotFound
	}
	return nil
}

// DeleteByUserIDAndType removes a specific type of MFA secret for a user.
func (r *MFASecretRepositoryPostgres) DeleteByUserIDAndType(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) error {
	query := `DELETE FROM mfa_secrets WHERE user_id = $1 AND type = $2`
	result, err := r.pool.Exec(ctx, query, userID, mfaType)
	if err != nil {
		return fmt.Errorf("failed to delete MFA secret by user ID and type: %w", err)
	}
	if result.RowsAffected() == 0 {
		// Not finding one might not be an error if the goal is to ensure it's gone.
		return domainErrors.ErrNotFound // Or return nil if idempotency is preferred.
	}
	return nil
}

// DeleteAllForUser removes all MFA secrets for a given user ID.
func (r *MFASecretRepositoryPostgres) DeleteAllForUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `DELETE FROM mfa_secrets WHERE user_id = $1`
	result, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to delete all MFA secrets for user: %w", err)
	}
	return result.RowsAffected(), nil
}

// DeleteByUserIDAndTypeIfUnverified removes an unverified MFA secret for a user and type.
func (r *MFASecretRepositoryPostgres) DeleteByUserIDAndTypeIfUnverified(ctx context.Context, userID uuid.UUID, mfaType models.MFAType) (bool, error) {
	query := `
		DELETE FROM mfa_secrets
		WHERE user_id = $1 AND type = $2 AND verified = false
	`
	result, err := r.pool.Exec(ctx, query, userID, mfaType)
	if err != nil {
		return false, fmt.Errorf("failed to delete unverified MFA secret by user ID and type: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

var _ repository.MFASecretRepository = (*MFASecretRepositoryPostgres)(nil)
