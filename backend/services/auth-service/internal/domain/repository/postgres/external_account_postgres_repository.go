// File: backend/services/auth-service/internal/domain/repository/postgres/external_account_postgres_repository.go
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

// ExternalAccountRepositoryPostgres implements repository.ExternalAccountRepository for PostgreSQL.
type ExternalAccountRepositoryPostgres struct {
	pool *pgxpool.Pool
	// logger *zap.Logger // Optional
}

// NewExternalAccountRepositoryPostgres creates a new instance.
func NewExternalAccountRepositoryPostgres(pool *pgxpool.Pool) *ExternalAccountRepositoryPostgres {
	return &ExternalAccountRepositoryPostgres{pool: pool}
}

// Create persists a new external account link.
func (r *ExternalAccountRepositoryPostgres) Create(ctx context.Context, acc *models.ExternalAccount) error {
	query := `
		INSERT INTO external_accounts (id, user_id, provider, external_user_id,
		                               access_token_hash, refresh_token_hash, token_expires_at, profile_data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	// created_at and updated_at are handled by DB defaults/triggers.
	_, err := r.pool.Exec(ctx, query,
		acc.ID, acc.UserID, acc.Provider, acc.ExternalUserID,
		acc.AccessTokenHash, acc.RefreshTokenHash, acc.TokenExpiresAt, acc.ProfileData,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			if pgErr.Code == "23505" { // unique_violation
				if strings.Contains(pgErr.ConstraintName, "external_accounts_provider_external_user_id_key") {
					return fmt.Errorf("external account for provider '%s' and external user ID '%s' already exists: %w",
						acc.Provider, acc.ExternalUserID, domainErrors.ErrDuplicateValue)
				}
				return fmt.Errorf("failed to create external account due to unique constraint %s: %w", pgErr.ConstraintName, domainErrors.ErrDuplicateValue)
			}
			if pgErr.Code == "23503" { // foreign_key_violation (e.g. user_id doesn't exist)
				return fmt.Errorf("user ID '%s' not found for external account: %w", acc.UserID, domainErrors.ErrUserNotFound)
			}
		}
		return fmt.Errorf("failed to create external account: %w", err)
	}
	return nil
}

// FindByID retrieves an external account link by its unique ID.
func (r *ExternalAccountRepositoryPostgres) FindByID(ctx context.Context, id uuid.UUID) (*models.ExternalAccount, error) {
	query := `
		SELECT id, user_id, provider, external_user_id, access_token_hash, refresh_token_hash,
		       token_expires_at, profile_data, created_at, updated_at
		FROM external_accounts
		WHERE id = $1
	`
	acc := &models.ExternalAccount{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&acc.ID, &acc.UserID, &acc.Provider, &acc.ExternalUserID, &acc.AccessTokenHash, &acc.RefreshTokenHash,
		&acc.TokenExpiresAt, &acc.ProfileData, &acc.CreatedAt, &acc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound // Or a specific ErrExternalAccountNotFound
		}
		return nil, fmt.Errorf("failed to find external account by ID: %w", err)
	}
	return acc, nil
}

// FindByProviderAndExternalID retrieves an external account by provider and external user ID.
func (r *ExternalAccountRepositoryPostgres) FindByProviderAndExternalID(ctx context.Context, provider string, externalUserID string) (*models.ExternalAccount, error) {
	query := `
		SELECT id, user_id, provider, external_user_id, access_token_hash, refresh_token_hash,
		       token_expires_at, profile_data, created_at, updated_at
		FROM external_accounts
		WHERE provider = $1 AND external_user_id = $2
	`
	acc := &models.ExternalAccount{}
	err := r.pool.QueryRow(ctx, query, provider, externalUserID).Scan(
		&acc.ID, &acc.UserID, &acc.Provider, &acc.ExternalUserID, &acc.AccessTokenHash, &acc.RefreshTokenHash,
		&acc.TokenExpiresAt, &acc.ProfileData, &acc.CreatedAt, &acc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find external account by provider and external ID: %w", err)
	}
	return acc, nil
}

// FindByUserID retrieves all external accounts for a specific user ID.
func (r *ExternalAccountRepositoryPostgres) FindByUserID(ctx context.Context, userID uuid.UUID) ([]*models.ExternalAccount, error) {
	query := `
		SELECT id, user_id, provider, external_user_id, access_token_hash, refresh_token_hash,
		       token_expires_at, profile_data, created_at, updated_at
		FROM external_accounts
		WHERE user_id = $1
		ORDER BY provider
	`
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find external accounts by user ID: %w", err)
	}
	defer rows.Close()

	var accounts []*models.ExternalAccount
	for rows.Next() {
		acc := &models.ExternalAccount{}
		errScan := rows.Scan(
			&acc.ID, &acc.UserID, &acc.Provider, &acc.ExternalUserID, &acc.AccessTokenHash, &acc.RefreshTokenHash,
			&acc.TokenExpiresAt, &acc.ProfileData, &acc.CreatedAt, &acc.UpdatedAt,
		)
		if errScan != nil {
			return nil, fmt.Errorf("failed to scan external account row: %w", errScan)
		}
		accounts = append(accounts, acc)
	}
	if err = rows.Err(); err != nil {
        return nil, fmt.Errorf("error iterating external account rows: %w", err)
    }
	return accounts, nil
}

// FindByUserIDAndProvider retrieves a specific external account for a user by provider.
func (r *ExternalAccountRepositoryPostgres) FindByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) (*models.ExternalAccount, error) {
	query := `
		SELECT id, user_id, provider, external_user_id, access_token_hash, refresh_token_hash,
		       token_expires_at, profile_data, created_at, updated_at
		FROM external_accounts
		WHERE user_id = $1 AND provider = $2
	`
	acc := &models.ExternalAccount{}
	err := r.pool.QueryRow(ctx, query, userID, provider).Scan(
		&acc.ID, &acc.UserID, &acc.Provider, &acc.ExternalUserID, &acc.AccessTokenHash, &acc.RefreshTokenHash,
		&acc.TokenExpiresAt, &acc.ProfileData, &acc.CreatedAt, &acc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domainErrors.ErrNotFound
		}
		return nil, fmt.Errorf("failed to find external account by user ID and provider: %w", err)
	}
	return acc, nil
}

// Update modifies details of an existing external account link.
func (r *ExternalAccountRepositoryPostgres) Update(ctx context.Context, acc *models.ExternalAccount) error {
	query := `
		UPDATE external_accounts
		SET access_token_hash = $1, refresh_token_hash = $2, token_expires_at = $3, profile_data = $4
		WHERE id = $5
	`
	// updated_at is handled by trigger.
	// provider, external_user_id, user_id are generally not updatable.
	result, err := r.pool.Exec(ctx, query,
		acc.AccessTokenHash, acc.RefreshTokenHash, acc.TokenExpiresAt, acc.ProfileData,
		acc.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update external account: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound
	}
	return nil
}

// Delete removes an external account link by its ID.
func (r *ExternalAccountRepositoryPostgres) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM external_accounts WHERE id = $1`
	result, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete external account by ID: %w", err)
	}
	if result.RowsAffected() == 0 {
		return domainErrors.ErrNotFound
	}
	return nil
}

// DeleteByUserIDAndProvider removes a specific external account link for a user and provider.
func (r *ExternalAccountRepositoryPostgres) DeleteByUserIDAndProvider(ctx context.Context, userID uuid.UUID, provider string) error {
	query := `DELETE FROM external_accounts WHERE user_id = $1 AND provider = $2`
	result, err := r.pool.Exec(ctx, query, userID, provider)
	if err != nil {
		return fmt.Errorf("failed to delete external account by user ID and provider: %w", err)
	}
	if result.RowsAffected() == 0 {
		// Not finding one to delete might not be an error in some contexts.
		// For now, treat as ErrNotFound if the specific link was expected to exist.
		return domainErrors.ErrNotFound
	}
	return nil
}

var _ repository.ExternalAccountRepository = (*ExternalAccountRepositoryPostgres)(nil)
