// File: backend/services/auth-service/internal/domain/entity/mfa_secret_entity.go
package entity

import (
	"time"
)

// MFAType defines the type of MFA secret.
type MFAType string

const (
	// MFATypeTOTP represents Time-based One-Time Password.
	MFATypeTOTP MFAType = "totp"
)

// MFASecret represents a secret for Multi-Factor Authentication (e.g., TOTP),
// mapping to the "mfa_secrets" table.
type MFASecret struct {
	ID                 string     `db:"id"`
	UserID             string     `db:"user_id"`
	Type               MFAType    `db:"type"` // e.g., "totp"
	SecretKeyEncrypted string     `db:"secret_key_encrypted"`
	Verified           bool       `db:"verified"`
	CreatedAt          time.Time  `db:"created_at"`
	UpdatedAt          *time.Time `db:"updated_at"` // Nullable
}
