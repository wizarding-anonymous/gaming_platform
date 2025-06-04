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

type pgxAPIKeyRepository struct {
	db *pgxpool.Pool
}

// NewPgxAPIKeyRepository creates a new instance of pgxAPIKeyRepository.
func NewPgxAPIKeyRepository(db *pgxpool.Pool) repository.APIKeyRepository {
	return &pgxAPIKeyRepository{db: db}
}

func (r *pgxAPIKeyRepository) Create(ctx context.Context, apiKey *entity.APIKey) error {
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
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Unique violation on id or key_prefix
			return errors.New("API key with given ID or prefix already exists: " + pgErr.Detail) // Placeholder
		}
		return fmt.Errorf("failed to create API key: %w", err)
	}
	return nil
}

func (r *pgxAPIKeyRepository) FindByID(ctx context.Context, id string, userID string) (*entity.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, 
		       expires_at, created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE id = $1 AND user_id = $2` // Added userID check for ownership
	apiKey := &entity.APIKey{}
	err := r.db.QueryRow(ctx, query, id, userID).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyPrefix, &apiKey.KeyHash, &apiKey.Permissions,
		&apiKey.ExpiresAt, &apiKey.CreatedAt, &apiKey.LastUsedAt, &apiKey.RevokedAt, &apiKey.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("API key not found or not owned by user") // Placeholder for entity.ErrAPIKeyNotFound
		}
		return nil, fmt.Errorf("failed to find API key by ID and userID: %w", err)
	}
	return apiKey, nil
}

func (r *pgxAPIKeyRepository) FindByKeyPrefix(ctx context.Context, prefix string) (*entity.APIKey, error) {
	// This method might be used internally or for admin purposes, not typically for auth.
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, 
		       expires_at, created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE key_prefix = $1`
	apiKey := &entity.APIKey{}
	err := r.db.QueryRow(ctx, query, prefix).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyPrefix, &apiKey.KeyHash, &apiKey.Permissions,
		&apiKey.ExpiresAt, &apiKey.CreatedAt, &apiKey.LastUsedAt, &apiKey.RevokedAt, &apiKey.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("API key not found by prefix") // Placeholder
		}
		return nil, fmt.Errorf("failed to find API key by prefix: %w", err)
	}
	return apiKey, nil
}

func (r *pgxAPIKeyRepository) FindByPrefixAndHash(ctx context.Context, prefix string, hash string) (*entity.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, key_hash, permissions, 
		       expires_at, created_at, last_used_at, revoked_at, updated_at
		FROM api_keys
		WHERE key_prefix = $1 AND key_hash = $2`
	apiKey := &entity.APIKey{}
	err := r.db.QueryRow(ctx, query, prefix, hash).Scan(
		&apiKey.ID, &apiKey.UserID, &apiKey.Name, &apiKey.KeyPrefix, &apiKey.KeyHash, &apiKey.Permissions,
		&apiKey.ExpiresAt, &apiKey.CreatedAt, &apiKey.LastUsedAt, &apiKey.RevokedAt, &apiKey.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("API key not found for prefix and hash") // Placeholder
		}
		return nil, fmt.Errorf("failed to find API key by prefix and hash: %w", err)
	}
	return apiKey, nil
}


func (r *pgxAPIKeyRepository) ListByUserID(ctx context.Context, userID string) ([]*entity.APIKey, error) {
	query := `
		SELECT id, user_id, name, key_prefix, permissions, 
		       expires_at, created_at, last_used_at, revoked_at, updated_at
		       -- key_hash is intentionally omitted for listing to user
		FROM api_keys
		WHERE user_id = $1
		ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys by user ID: %w", err)
	}
	defer rows.Close()

	var keys []*entity.APIKey
	for rows.Next() {
		key := &entity.APIKey{}
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

func (r *pgxAPIKeyRepository) UpdateLastUsedAt(ctx context.Context, id string, lastUsedAt time.Time) error {
	// Trigger handles updated_at
	query := `UPDATE api_keys SET last_used_at = $2, updated_at = $3 WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query, id, lastUsedAt, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update API key last_used_at: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("API key not found") // Placeholder for entity.ErrAPIKeyNotFound
	}
	return nil
}

func (r *pgxAPIKeyRepository) UpdateNameAndPermissions(ctx context.Context, id string, userID string, name string, permissions []byte) error {
    query := `UPDATE api_keys SET name = $3, permissions = $4, updated_at = $5 WHERE id = $1 AND user_id = $2`
    commandTag, err := r.db.Exec(ctx, query, id, userID, name, permissions, time.Now())
    if err != nil {
        return fmt.Errorf("failed to update API key name and permissions: %w", err)
    }
    if commandTag.RowsAffected() == 0 {
        return errors.New("API key not found, not owned by user, or no changes made") // Placeholder
    }
    return nil
}

func (r *pgxAPIKeyRepository) Revoke(ctx context.Context, id string, userID string) error {
	// Trigger handles updated_at
	query := `UPDATE api_keys SET revoked_at = $3, updated_at = $4 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`
	revokedAt := time.Now()
	commandTag, err := r.db.Exec(ctx, query, id, userID, revokedAt, revokedAt) // Pass time.Now() for updated_at as well
	if err != nil {
		return fmt.Errorf("failed to revoke API key: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("API key not found, not owned by user, or already revoked") // Placeholder
	}
	return nil
}

func (r *pgxAPIKeyRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM api_keys WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}
	return nil
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
