// File: backend/services/auth-service/internal/domain/models/mfa_secret.go
package models

import (
	"time"

	"github.com/google/uuid"
)

// MFAType represents the type of Multi-Factor Authentication.
type MFAType string

const (
	MFATypeTOTP MFAType = "totp" // Time-based One-Time Password
	// Potentially other types in the future e.g., MFATypeSMS, MFATypeEmail
)

// MFASecret stores the secrets for Multi-Factor Authentication methods like TOTP.
// Aligned with the 'mfa_secrets' table in auth_data_model.md.
type MFASecret struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	UserID             uuid.UUID `json:"user_id" db:"user_id"`
	Type               MFAType   `json:"type" db:"type"` // Currently only 'totp'
	SecretKeyEncrypted string    `json:"-" db:"secret_key_encrypted"` // Encrypted at application level
	Verified           bool      `json:"verified" db:"verified"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"` // Handled by DB default
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"` // Handled by DB trigger
}

// CreateMFASecretRequest contains data for creating a new MFA secret.
type CreateMFASecretRequest struct {
	UserID             uuid.UUID
	Type               MFAType
	SecretKeyEncrypted string // Already encrypted
}

// UpdateMFASecretRequest contains data for updating an MFA secret (e.g., verifying it).
type UpdateMFASecretRequest struct {
	Verified           *bool   // Pointer to distinguish between false and not provided
	SecretKeyEncrypted *string // If re-keying is allowed
}
