// File: backend/services/auth-service/internal/domain/models/mfa_backup_code.go
package models

import (
	"time"

	"github.com/google/uuid"
)

// MFABackupCode stores a single backup code for Multi-Factor Authentication recovery.
// Aligned with the 'mfa_backup_codes' table in auth_data_model.md.
type MFABackupCode struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	CodeHash  string     `json:"-" db:"code_hash"` // SHA256 hash of the backup code
	UsedAt    *time.Time `json:"used_at,omitempty" db:"used_at"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"` // Handled by DB default
}

// CreateMFABackupCodeRequest contains data for creating new backup codes.
// This is more of a service-level DTO if codes are generated and hashed there.
type CreateMFABackupCodeRequest struct {
	UserID    uuid.UUID
	CodeHashes []string // Hashes of the generated backup codes
}
