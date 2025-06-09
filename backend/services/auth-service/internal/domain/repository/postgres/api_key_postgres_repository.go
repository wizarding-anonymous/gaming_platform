// File: backend/services/auth-service/internal/domain/repository/postgres/api_key_postgres_repository.go
package postgres

import (
	"context"
	"encoding/json"
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

// APIKeyRepositoryPostgres implements repository.APIKeyRepository for PostgreSQL.
type APIKeyRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger // Optional
}

// NewAPIKeyRepositoryPostgres creates a new instance.
func NewAPIKeyRepositoryPostgres(pool *pgxpool.Pool) *APIKeyRepositoryPostgres {
	return &APIKeyRepositoryPostgres{pool: pool}
}

// Create persists a new API key.
func (r *APIKeyRepositoryPostgres) Create(ctx context.Context, apiKey *models.APIKey) error {
	query := `
		INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, permissions, expires_at, last_used_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	// created_at and updated_at are handled by DB defaults/triggers.
	_, err := r.pool.Exec(ctx, query,
		apiKey.ID, apiKey.UserID, apiKey.Name, apiKey.KeyPrefix, apiKey.KeyHash,
		apiKey.Permissions, apiKey.ExpiresAt, apiKey.LastUsedAt, apiKey.RevokedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				if strings.Contains(pgErr.ConstraintName, "api_keys_key_prefix_key") {
					return fmt.Errorf("API key prefix '%s' already exists: %w", apiKey.KeyPrefix, domainErrors.ErrDuplicateValue)
				}
				// Add check for primary key if needed, though UUIDs are unlikely to collide.
				return fmt.Errorf("failed to create API key due to unique constraint %s: %w", pgErr.ConstraintName, domainErrors.ErrDuplicateValue)
			}
			if pgErr.Code == "23503" { // foreign_key_violation (user_id)
				return fmt.Errorf("user ID '%s' not found for API key: %w", apiKey.UserID, domainErrors.ErrUserNotFound)
			}
		}
		return fmt.Errorf("failed to create API key: %w", err)
	}
	return nil
}

// FindByID retrieves an API key by its ID.
func (r *APIKeyRepositoryPostgres) FindByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, expires_at,
		       created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE id = $1
	`
	key := &models.APIKey{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&key.ID, &key.UserID, &key.Name, &key.KeyPrefix, &key.KeyHash, &key.Permissions, &key.ExpiresAt,
		&key.CreatedAt, &key.LastUsedAt, &key.RevokedAt, &key.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Or specific ErrAPIKeyNotFound
		}
		return nil, fmt.Errorf("failed to find API key by ID: %w", err)
	}
	return key, nil
}

// FindByUserIDAndID retrieves an API key by ID, ensuring it belongs to the user.
func (r *APIKeyRepositoryPostgres) FindByUserIDAndID(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, expires_at,
		       created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE id = $1 AND user_id = $2
	`
	key := &models.APIKey{}
	err := r.pool.QueryRow(ctx, query, id, userID).Scan(
		&key.ID, &key.UserID, &key.Name, &key.KeyPrefix, &key.KeyHash, &key.Permissions, &key.ExpiresAt,
		&key.CreatedAt, &key.LastUsedAt, &key.RevokedAt, &key.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find API key by ID and UserID: %w", err)
	}
	return key, nil
}

// FindByKeyPrefix retrieves an API key by its prefix.
func (r *APIKeyRepositoryPostgres) FindByKeyPrefix(ctx context.Context, prefix string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, expires_at,
		       created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE key_prefix = $1
	`
	key := &models.APIKey{}
	err := r.pool.QueryRow(ctx, query, prefix).Scan(
		&key.ID, &key.UserID, &key.Name, &key.KeyPrefix, &key.KeyHash, &key.Permissions, &key.ExpiresAt,
		&key.CreatedAt, &key.LastUsedAt, &key.RevokedAt, &key.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find API key by prefix: %w", err)
	}
	return key, nil
}

// FindByPrefixAndHash retrieves an active API key by prefix and key hash.
func (r *APIKeyRepositoryPostgres) FindByPrefixAndHash(ctx context.Context, prefix string, keyHash string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, expires_at,
		       created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE key_prefix = $1 AND key_hash = $2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW())
	`
	key := &models.APIKey{}
	err := r.pool.QueryRow(ctx, query, prefix, keyHash).Scan(
		&key.ID, &key.UserID, &key.Name, &key.KeyPrefix, &key.KeyHash, &key.Permissions, &key.ExpiresAt,
		&key.CreatedAt, &key.LastUsedAt, &key.RevokedAt, &key.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrInvalidToken // Or ErrNotFound / ErrAPIKeyInvalid
		}
		return nil, fmt.Errorf("failed to find API key by prefix and hash: %w", err)
	}
	return key, nil
}

// ListByUserID retrieves all API keys for a specific user.
func (r *APIKeyRepositoryPostgres) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, permissions, expires_at,
		       created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC
	`
	// key_hash is excluded for listing
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys by user ID: %w", err)
	}
	defer rows.Close()

	var keys []*models.APIKey
	for rows.Next() {
		key := &models.APIKey{}
		errScan := rows.Scan(
			&key.ID, &key.UserID, &key.Name, &key.KeyPrefix, &key.Permissions, &key.ExpiresAt,
			&key.CreatedAt, &key.LastUsedAt, &key.RevokedAt, &key.UpdatedAt,
		)
		if errScan != nil {
			return nil, fmt.Errorf("failed to scan API key row: %w", errScan)
		}
		keys = append(keys, key)
	}
	if err = rows.Err(); err != nil {
        return nil, fmt.Errorf("error iterating API key rows: %w", err)
    }
	return keys, nil
}

// UpdateLastUsedAt updates the last_used_at timestamp for an API key.
func (r *APIKeyRepositoryPostgres) UpdateLastUsedAt(ctx context.Context, id uuid.UUID, lastUsedAt time.Time) error {
	query := `UPDATE api_keys SET last_used_at = $1 WHERE id = $2`
	// updated_at is handled by trigger.
	result, err := r.pool.Exec(ctx, query, lastUsedAt, id)
	if err != nil {
		return fmt.Errorf("failed to update API key last_used_at: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound
	}
	return nil
}

// UpdateNameAndPermissions updates the name and permissions of an API key.
func (r *APIKeyRepositoryPostgres) UpdateNameAndPermissions(ctx context.Context, id uuid.UUID, userID uuid.UUID, name string, permissions json.RawMessage) error {
	query := `
		UPDATE api_keys SET name = $1, permissions = $2
		WHERE id = $3 AND user_id = $4
	`
	// updated_at is handled by trigger.
	result, err := r.pool.Exec(ctx, query, name, permissions, id, userID)
	if err != nil {
		return fmt.Errorf("failed to update API key name/permissions: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound // Or ErrForbidden if user_id mismatch
	}
	return nil
}

// Revoke marks an API key as revoked.
func (r *APIKeyRepositoryPostgres) Revoke(ctx context.Context, id uuid.UUID, userID uuid.UUID, revokedAt time.Time) error {
	query := `
		UPDATE api_keys SET revoked_at = $1
		WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL
	`
	// updated_at is handled by trigger.
	result, err := r.pool.Exec(ctx, query, revokedAt, id, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound // Or already revoked / wrong user
	}
	return nil
}

// Delete removes an API key by its ID.
func (r *APIKeyRepositoryPostgres) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM api_keys WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound
	}
	return nil
}

// DeleteExpiredAndRevoked removes expired or long-revoked API keys.
func (r *APIKeyRepositoryPostgres) DeleteExpiredAndRevoked(ctx context.Context, olderThanRevokedPeriod time.Duration) (int64, error) {
	var totalDeleted int64

	queryExpired := `DELETE FROM api_keys WHERE expires_at IS NOT NULL AND expires_at < NOW()`
	expiredResult, err := r.pool.Exec(ctx, queryExpired)
	if err != nil {
		return totalDeleted, fmt.Errorf("failed to delete expired API keys: %w", err)
	}
	totalDeleted += expiredResult.RowsAffected()

	if olderThanRevokedPeriod > 0 {
		intervalStr := fmt.Sprintf("%f seconds", olderThanRevokedPeriod.Seconds())
		queryRevoked := `
			DELETE FROM api_keys
			WHERE revoked_at IS NOT NULL AND revoked_at < (CURRENT_TIMESTAMP - $1::interval)
		`
		revokedResult, err := r.pool.Exec(ctx, queryRevoked, intervalStr)
		if err != nil {
			return totalDeleted, fmt.Errorf("failed to delete old revoked API keys: %w", err)
		}
		totalDeleted += revokedResult.RowsAffected()
	}
	// If olderThanRevokedPeriod is zero, only explicitly expired ones are deleted by the first query.
	// Add a case for deleting all revoked if olderThanRevokedPeriod is zero, if desired.
	// For now, a zero duration means only expired ones are deleted by the first query.

	return totalDeleted, nil
}

var _ repository.APIKeyRepository = (*APIKeyRepositoryPostgres)(nil)
