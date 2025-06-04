package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// APIKey represents an API key for programmatic access.
// Aligned with the 'api_keys' table in auth_data_model.md.
type APIKey struct {
	ID          uuid.UUID       `json:"id" db:"id"`
	UserID      uuid.UUID       `json:"user_id" db:"user_id"`
	Name        string          `json:"name" db:"name"`
	KeyPrefix   string          `json:"key_prefix" db:"key_prefix"`     // A short, unique, non-secret prefix
	KeyHash     string          `json:"-" db:"key_hash"`                // SHA256 hash of the API key's secret part
	Permissions json.RawMessage `json:"permissions,omitempty" db:"permissions"` // JSONB array of permission strings
	ExpiresAt   *time.Time      `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt   time.Time       `json:"created_at" db:"created_at"`
	LastUsedAt  *time.Time      `json:"last_used_at,omitempty" db:"last_used_at"`
	RevokedAt   *time.Time      `json:"revoked_at,omitempty" db:"revoked_at"`
	UpdatedAt   time.Time       `json:"updated_at" db:"updated_at"`
}

// CreateAPIKeyRequest contains data for creating a new API key by the user.
type CreateAPIKeyRequest struct {
	Name        string          `json:"name" binding:"required,min=3,max=100"`
	Permissions json.RawMessage `json:"permissions" binding:"required"` // e.g., json.Marshal([]string{"read:data", "write:config"})
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`         // Optional
}

// APIKeyResponse is the DTO for listing API keys (omits sensitive parts).
type APIKeyResponse struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	KeyPrefix   string          `json:"key_prefix"`
	Permissions json.RawMessage `json:"permissions,omitempty"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	LastUsedAt  *time.Time      `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time      `json:"revoked_at,omitempty"`
}

// APIKeyCreateResponse is the DTO returned when an API key is first created.
// It includes the plain API key value which is shown only once.
type APIKeyCreateResponse struct {
	APIKey      APIKeyResponse `json:"api_key_metadata"` // The metadata of the created key
	PlainAPIKey string         `json:"plain_api_key"`    // The full API key string (prefix + secret)
}

// ToResponse converts an APIKey model to an APIKeyResponse DTO.
func (ak *APIKey) ToResponse() APIKeyResponse {
	return APIKeyResponse{
		ID:          ak.ID,
		Name:        ak.Name,
		KeyPrefix:   ak.KeyPrefix,
		Permissions: ak.Permissions,
		ExpiresAt:   ak.ExpiresAt,
		CreatedAt:   ak.CreatedAt,
		LastUsedAt:  ak.LastUsedAt,
		RevokedAt:   ak.RevokedAt,
	}
}
