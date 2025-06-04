package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ExternalAccount represents an external account linked to a user (e.g., OAuth).
// Aligned with the 'external_accounts' table in auth_data_model.md.
type ExternalAccount struct {
	ID               uuid.UUID       `json:"id" db:"id"`
	UserID           uuid.UUID       `json:"user_id" db:"user_id"`
	Provider         string          `json:"provider" db:"provider"`                   // e.g., "telegram", "google"
	ExternalUserID   string          `json:"external_user_id" db:"external_user_id"` // User's ID from the external provider
	AccessTokenHash  *string         `json:"-" db:"access_token_hash"`               // Optional: Hash of the provider's access token
	RefreshTokenHash *string         `json:"-" db:"refresh_token_hash"`              // Optional: Hash of the provider's refresh token
	TokenExpiresAt   *time.Time      `json:"token_expires_at,omitempty" db:"token_expires_at"` // Expiry of the provider's token
	ProfileData      json.RawMessage `json:"profile_data,omitempty" db:"profile_data"`         // Raw profile data from the provider (JSONB)
	CreatedAt        time.Time       `json:"created_at" db:"created_at"`                         // Handled by DB default
	UpdatedAt        time.Time       `json:"updated_at" db:"updated_at"`                         // Handled by DB trigger
}

// CreateExternalAccountRequest contains data for linking a new external account.
type CreateExternalAccountRequest struct {
	UserID           uuid.UUID
	Provider         string
	ExternalUserID   string
	AccessTokenHash  *string
	RefreshTokenHash *string
	TokenExpiresAt   *time.Time
	ProfileData      json.RawMessage
}

// UpdateExternalAccountRequest contains data for updating an existing external account link
// (e.g. when tokens are refreshed).
type UpdateExternalAccountRequest struct {
	AccessTokenHash  *string
	RefreshTokenHash *string
	TokenExpiresAt   *time.Time
	ProfileData      json.RawMessage
}
