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

type pgxExternalAccountRepository struct {
	db *pgxpool.Pool
}

// NewPgxExternalAccountRepository creates a new instance of pgxExternalAccountRepository.
func NewPgxExternalAccountRepository(db *pgxpool.Pool) repository.ExternalAccountRepository {
	return &pgxExternalAccountRepository{db: db}
}

func (r *pgxExternalAccountRepository) Create(ctx context.Context, acc *entity.ExternalAccount) error {
	// Trigger handles updated_at, created_at has default
	query := `
		INSERT INTO external_accounts (
			id, user_id, provider, external_user_id, 
			access_token_hash, refresh_token_hash, token_expires_at, profile_data,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := r.db.Exec(ctx, query,
		acc.ID, acc.UserID, acc.Provider, acc.ExternalUserID,
		acc.AccessTokenHash, acc.RefreshTokenHash, acc.TokenExpiresAt, acc.ProfileData,
		acc.CreatedAt, acc.UpdatedAt, // Let trigger handle UpdatedAt if it's for initial creation
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // Unique violation on (provider, external_user_id) or id
			return errors.New("external account already exists or ID conflict: " + pgErr.Detail) // Placeholder
		}
		return fmt.Errorf("failed to create external account: %w", err)
	}
	return nil
}

func (r *pgxExternalAccountRepository) FindByProviderAndExternalID(
	ctx context.Context, provider string, externalUserID string) (*entity.ExternalAccount, error) {
	query := `
		SELECT id, user_id, provider, external_user_id, 
		       access_token_hash, refresh_token_hash, token_expires_at, profile_data,
		       created_at, updated_at
		FROM external_accounts
		WHERE provider = $1 AND external_user_id = $2`
	acc := &entity.ExternalAccount{}
	err := r.db.QueryRow(ctx, query, provider, externalUserID).Scan(
		&acc.ID, &acc.UserID, &acc.Provider, &acc.ExternalUserID,
		&acc.AccessTokenHash, &acc.RefreshTokenHash, &acc.TokenExpiresAt, &acc.ProfileData,
		&acc.CreatedAt, &acc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("external account not found") // Placeholder for entity.ErrExternalAccountNotFound
		}
		return nil, fmt.Errorf("failed to find external account by provider and external ID: %w", err)
	}
	return acc, nil
}

func (r *pgxExternalAccountRepository) FindByID(ctx context.Context, id string) (*entity.ExternalAccount, error) {
	query := `
		SELECT id, user_id, provider, external_user_id, 
		       access_token_hash, refresh_token_hash, token_expires_at, profile_data,
		       created_at, updated_at
		FROM external_accounts
		WHERE id = $1`
	acc := &entity.ExternalAccount{}
	err := r.db.QueryRow(ctx, query, id).Scan(
		&acc.ID, &acc.UserID, &acc.Provider, &acc.ExternalUserID,
		&acc.AccessTokenHash, &acc.RefreshTokenHash, &acc.TokenExpiresAt, &acc.ProfileData,
		&acc.CreatedAt, &acc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("external account not found") // Placeholder
		}
		return nil, fmt.Errorf("failed to find external account by ID: %w", err)
	}
	return acc, nil
}

func (r *pgxExternalAccountRepository) FindByUserID(ctx context.Context, userID string) ([]*entity.ExternalAccount, error) {
	query := `
		SELECT id, user_id, provider, external_user_id, 
		       access_token_hash, refresh_token_hash, token_expires_at, profile_data,
		       created_at, updated_at
		FROM external_accounts
		WHERE user_id = $1 ORDER BY provider`
	rows, err := r.db.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find external accounts by user ID: %w", err)
	}
	defer rows.Close()

	var accounts []*entity.ExternalAccount
	for rows.Next() {
		acc := &entity.ExternalAccount{}
		if err := rows.Scan(
			&acc.ID, &acc.UserID, &acc.Provider, &acc.ExternalUserID,
			&acc.AccessTokenHash, &acc.RefreshTokenHash, &acc.TokenExpiresAt, &acc.ProfileData,
			&acc.CreatedAt, &acc.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan external account during find by user ID: %w", err)
		}
		accounts = append(accounts, acc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error after iterating external accounts for user: %w", err)
	}
	return accounts, nil
}


func (r *pgxExternalAccountRepository) FindByUserIDAndProvider(ctx context.Context, userID string, provider string) (*entity.ExternalAccount, error) {
	query := `
		SELECT id, user_id, provider, external_user_id, 
		       access_token_hash, refresh_token_hash, token_expires_at, profile_data,
		       created_at, updated_at
		FROM external_accounts
		WHERE user_id = $1 AND provider = $2`
	acc := &entity.ExternalAccount{}
	err := r.db.QueryRow(ctx, query, userID, provider).Scan(
		&acc.ID, &acc.UserID, &acc.Provider, &acc.ExternalUserID,
		&acc.AccessTokenHash, &acc.RefreshTokenHash, &acc.TokenExpiresAt, &acc.ProfileData,
		&acc.CreatedAt, &acc.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("external account not found for user and provider") // Placeholder
		}
		return nil, fmt.Errorf("failed to find external account by user ID and provider: %w", err)
	}
	return acc, nil
}


func (r *pgxExternalAccountRepository) Update(ctx context.Context, acc *entity.ExternalAccount) error {
	// Trigger handles updated_at
	query := `
		UPDATE external_accounts SET
			access_token_hash = $2, refresh_token_hash = $3, token_expires_at = $4, profile_data = $5, updated_at = $6
		WHERE id = $1`
	commandTag, err := r.db.Exec(ctx, query,
		acc.ID, acc.AccessTokenHash, acc.RefreshTokenHash, acc.TokenExpiresAt, acc.ProfileData, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to update external account: %w", err)
	}
	if commandTag.RowsAffected() == 0 {
		return errors.New("external account not found or no changes made") // Placeholder
	}
	return nil
}

func (r *pgxExternalAccountRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM external_accounts WHERE id = $1`
	_, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete external account by ID: %w", err)
	}
	return nil
}

func (r *pgxExternalAccountRepository) DeleteByUserIDAndProvider(ctx context.Context, userID string, provider string) error {
	query := `DELETE FROM external_accounts WHERE user_id = $1 AND provider = $2`
	_, err := r.db.Exec(ctx, query, userID, provider)
	if err != nil {
		return fmt.Errorf("failed to delete external account by user ID and provider: %w", err)
	}
	return nil
}


var _ repository.ExternalAccountRepository = (*pgxExternalAccountRepository)(nil)
