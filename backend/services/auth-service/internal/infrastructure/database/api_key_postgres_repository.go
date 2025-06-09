// File: backend/services/auth-service/internal/infrastructure/database/api_key_postgres_repository.go
package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/google/uuid" // Added for uuid.UUID

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
)

type pgxAPIKeyRepository struct {
	db *pgxpool.Pool
}

// NewPgxAPIKeyRepository creates a new instance of pgxAPIKeyRepository.
func NewPgxAPIKeyRepository(db *pgxpool.Pool) repository.APIKeyRepository {
	return &pgxAPIKeyRepository{db: db}
}

func (r *pgxAPIKeyRepository) Create(ctx context.Context, apiKey *models.APIKey) error {
	// Trigger handles updated_at, created_at has default
	query := `
		INSERT INTO api_keys (
			id, user_id, name, key_prefix, key_hash, permissions, 
			expires_at, created_at, last_used_at, revoked_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	_, err := r.db.Exec(ctx, query,
		apiKey.ID, apiKey.UserID, apiKey.Name, apiKey.KeyPrefix, apiKey.KeyHash, apiKey.Permissions,
		apiKey.ExpiresAt, apiKey.CreatedAt, apiKey.LastUsedAt, apiKey.RevokedAt, apiKey.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: API key with given ID or prefix already exists: %s", domainErrors.ErrConflict, pgErr.Detail)
		}
		return fmt.Errorf("failed to create API key: %w", err)
	}
	return nil
}

// FindByID retrieves an API key by its unique ID.
// Note: The interface APIKeyRepository has FindByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error)
// The implementation here was FindByID(ctx context.Context, id string, userID string) (*entity.APIKey, error)
// I will align it with the interface: FindByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error)
// The FindByUserIDAndID method in the interface is for ownership-checked retrieval.
func (r *pgxAPIKeyRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, 
		       expires_at, created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE id = $1`
	apiKey := &models.APIKey{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyPrefix, &apiKey.KeyHash, &apiKey.Permissions,
		&apiKey.ExpiresAt, &apiKey.CreatedAt, &apiKey.LastUsedAt, &apiKey.RevokedAt, &apiKey.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Use domainErrors
		}
		return nil, fmt.Errorf("failed to find API key by ID: %w", err)
	}
	return apiKey, nil
}

func (r *pgxAPIKeyRepository) FindByUserIDAndID(ctx context.Context, id uuid.UUID, userID uuid.UUID) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions,
		       expires_at, created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE id = $1 AND user_id = $2`
	apiKey := &models.APIKey{}
	err := r.db.QueryRow(ctx, query, id, userID).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyPrefix, &apiKey.KeyHash, &apiKey.Permissions,
		&apiKey.ExpiresAt, &apiKey.CreatedAt, &apiKey.LastUsedAt, &apiKey.RevokedAt, &apiKey.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find API key by ID and userID: %w", err)
	}
	return apiKey, nil
}


func (r *pgxAPIKeyRepository) FindByKeyPrefix(ctx context.Context, prefix string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, 
		       expires_at, created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE key_prefix = $1`
	apiKey := &models.APIKey{}
	err := r.db.QueryRow(ctx, query, prefix).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyPrefix, &apiKey.KeyHash, &apiKey.Permissions,
		&apiKey.ExpiresAt, &apiKey.CreatedAt, &apiKey.LastUsedAt, &apiKey.RevokedAt, &apiKey.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find API key by prefix: %w", err)
	}
	return apiKey, nil
}

func (r *pgxAPIKeyRepository) FindByPrefixAndHash(ctx context.Context, prefix string, hash string) (*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, 
		       expires_at, created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE key_prefix = $1 AND key_hash = $2`
	apiKey := &models.APIKey{}
	err := r.db.QueryRow(ctx, query, prefix, hash).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyPrefix, &apiKey.KeyHash, &apiKey.Permissions,
		&apiKey.ExpiresAt, &apiKey.CreatedAt, &apiKey.LastUsedAt, &apiKey.RevokedAt, &apiKey.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find API key by prefix and hash: %w", err)
	}
	return apiKey, nil
}


func (r *pgxAPIKeyRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*models.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, permissions, 
		       expires_at, created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys by user ID: %w", err)
	}
	defer rows.Close()

	var keys []*models.APIKey
	for rows.Next() {
		key := &models.APIKey{}
		if err := rows.Scan(
			&key.ID, &key.UserID, &key.Name, &key.KeyPrefix, &key.Permissions,
			&key.ExpiresAt, &key.CreatedAt, &key.LastUsedAt, &key.RevokedAt, &key.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan API key during find by user ID: %w", err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after iterating API keys for user: %w", err)
	}
	return keys, nil
}

func (r *pgxAPIKeyRepository) UpdateLastUsedAt(ctx context.Context, id uuid.UUID, lastUsedAt time.Time) error {
	query := `UPDATE api_keys SET last_used_at = $2, updated_at = $3 WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, id, lastUsedAt, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update API key last_used_at: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrNotFound
	}
	return nil
}

func (r *pgxAPIKeyRepository) UpdateNameAndPermissions(ctx context.Context, id uuid.UUID, userID uuid.UUID, name string, permissions []byte) error {
    query := `UPDATE api_keys SET name = $3, permissions = $4, updated_at = $5 WHERE id = $1 AND user_id = $2`
    commandTag, err := r.db.Exec(ctx, query, id, userID, name, permissions, time.Now())
    if err != nil {
        return fmt.Errorf("failed to update API key name and permissions: %w", err)
    }
    if commandTag.RowsAffected() == 0 {
        return domainErrors.ErrNotFound // Or a more specific "not found or not owned"
    }
    return nil
}

func (r *pgxAPIKeyRepository) Revoke(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	query := `UPDATE api_keys SET revoked_at = $3, updated_at = $4 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`
	revokedAt := time.Now()
	commandTag, err := r.db.Exec(ctx, query, id, userID, revokedAt, revokedAt)
	if err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrNotFound // Or specific "not found, not owned, or already revoked"
	}
	return nil
}

func (r *pgxAPIKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM api_keys WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, id) // Store commandTag to check RowsAffected
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return domainErrors.ErrNotFound // API key with given ID not found
	}
	return nil
}

func (r *pgxAPIKeyRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	query := `DELETE FROM api_keys WHERE user_id = $1`
	commandTag, err := r.db.Exec(ctx, query, userID)
	if err != nil {
		return 0, fmt.Errorf("failed to delete API keys by user ID: %w", err)
	}
	return commandTag.RowsAffected(), nil
}

func (r *pgxAPIKeyRepository) DeleteExpiredAndRevoked(ctx context.Context, olderThanRevoked time.Duration) (int64, error) {
	cutoffRevokedTime := time.Now().Add(-olderThanRevoked)
	query := `
		DELETE FROM api_keys 
		WHERE (expires_at IS NOT NULL AND expires_at < $1) 
		   OR (revoked_at IS NOT NULL AND revoked_at < $2)`
	
	commandTag, err := r.db.Exec(ctx, query, time.Now(), cutoffRevokedTime)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired and revoked API keys: %w", err)
	}
	return commandTag.RowsAffected(), nil
}

var _ repository.APIKeyRepository = (*pgxAPIKeyRepository)(nil)
