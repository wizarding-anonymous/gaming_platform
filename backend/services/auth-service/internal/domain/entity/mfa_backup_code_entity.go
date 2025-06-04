package entity

import (
	"time"
)

// MFABackupCode represents a single backup code for Multi-Factor Authentication,
// mapping to the "mfa_backup_codes" table.
type MFABackupCode struct {
	ID        string     `db:"id"`
	UserID    string     `db:"user_id"`
	CodeHash  string     `db:"code_hash"`
	UsedAt    *time.Time `db:"used_at"` // Nullable, indicates if and when the code was used
	CreatedAt time.Time  `db:"created_at"`
}
