// File: backend/services/auth-service/internal/domain/entity/verification_code_entity.go
package entity

import (
	"time"
)

// VerificationCodeType defines the purpose of a verification code.
type VerificationCodeType string

const (
	VerificationCodeTypeEmailVerification     VerificationCodeType = "email_verification"
	VerificationCodeTypePasswordReset       VerificationCodeType = "password_reset"
	VerificationCodeTypeMFADeviceVerification VerificationCodeType = "mfa_device_verification"
)

// VerificationCode represents a temporary code for operations like email verification or password reset,
// mapping to the "verification_codes" table.
type VerificationCode struct {
	ID        string               `db:"id"`
	UserID    string               `db:"user_id"`
	Type      VerificationCodeType `db:"type"`
	CodeHash  string               `db:"code_hash"`
	ExpiresAt time.Time            `db:"expires_at"`
	CreatedAt time.Time            `db:"created_at"`
	UsedAt    *time.Time           `db:"used_at"` // Nullable, indicates if and when the code was used
}
