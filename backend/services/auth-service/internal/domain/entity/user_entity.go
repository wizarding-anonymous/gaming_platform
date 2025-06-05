// File: backend/services/auth-service/internal/domain/entity/user_entity.go
package entity

import (
	"time"
)

// User represents the structure of a user in the system,
// mapping to the "users" table in the database.
type User struct {
	ID                  string     `db:"id"`
	Username            string     `db:"username"`
	Email               string     `db:"email"`
	PasswordHash        *string    `db:"password_hash"` // Nullable
	Status              string     `db:"status"`
	EmailVerifiedAt     *time.Time `db:"email_verified_at"`     // Nullable
	LastLoginAt         *time.Time `db:"last_login_at"`         // Nullable
	FailedLoginAttempts int        `db:"failed_login_attempts"`
	LockoutUntil        *time.Time `db:"lockout_until"`         // Nullable
	CreatedAt           time.Time  `db:"created_at"`
	UpdatedAt           *time.Time `db:"updated_at,omitempty"`            // Nullable
	DeletedAt           *time.Time `db:"deleted_at,omitempty"`            // Nullable
	StatusReason        *string    `db:"status_reason,omitempty"`         // Nullable, for block reason etc.
	UpdatedBy           *string    `db:"updated_by,omitempty"`            // Nullable, actor who updated
}

// UserStatus defines possible statuses for a user.
type UserStatus string

const (
	UserStatusActive              UserStatus = "active"
	UserStatusInactive            UserStatus = "inactive" // Not in CHECK constraint from spec, but a common status
	UserStatusBlocked             UserStatus = "blocked"
	UserStatusPendingVerification UserStatus = "pending_verification"
	UserStatusDeleted             UserStatus = "deleted"
)
