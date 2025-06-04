package entity

import (
	"encoding/json"
	"time"
)

// ExternalAccount represents a user's linked external account (e.g., OAuth provider),
// mapping to the "external_accounts" table.
type ExternalAccount struct {
	ID               string          `db:"id"`
	UserID           string          `db:"user_id"`
	Provider         string          `db:"provider"`
	ExternalUserID   string          `db:"external_user_id"`
	AccessTokenHash  *string         `db:"access_token_hash"`  // Nullable
	RefreshTokenHash *string         `db:"refresh_token_hash"` // Nullable
	TokenExpiresAt   *time.Time      `db:"token_expires_at"`   // Nullable
	ProfileData      json.RawMessage `db:"profile_data"`       // Nullable JSONB
	CreatedAt        time.Time       `db:"created_at"`
	UpdatedAt        *time.Time      `db:"updated_at"`         // Nullable
}
