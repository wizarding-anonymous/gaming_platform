package models

import (
	"time"
	"github.com/google/uuid"
)

type MFAType string

const (
	MFATypeTOTP MFAType = "totp"
	// Potentially other types like MFATypeSMS if supported later
)

// MFASecret maps to the 'mfa_secrets' table.
type MFASecret struct {
	ID                 uuid.UUID `json:"id" db:"id"`
	UserID             uuid.UUID `json:"user_id" db:"user_id"`
	Type               MFAType   `json:"type" db:"type"`
	SecretKeyEncrypted string    `json:"-" db:"secret_key_encrypted"` // Stored as TEXT, base64 of nonce+ciphertext
	Verified           bool      `json:"verified" db:"verified"`
	CreatedAt          time.Time `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time `json:"updated_at" db:"updated_at"`
}

// Enable2FAInitiateResponse DTO for returning data after initiating 2FA setup.
type Enable2FAInitiateResponse struct {
	MFASecretID   uuid.UUID `json:"mfa_secret_id"`
	SecretKey     string    `json:"secret_key"` // Raw base32 secret for manual input
	QRCodeImageURL string    `json:"qr_code_image_url"`
	RecoveryCodes []string  `json:"recovery_codes"` // Generated once at the end of successful verification
}

// Verify2FARequest DTO for verifying and activating 2FA.
type Verify2FARequest struct {
	MFASecretID uuid.UUID `json:"mfa_secret_id" binding:"required"`
	TOTPCode    string    `json:"totp_code" binding:"required"`
}

// Disable2FARequest DTO for disabling 2FA.
type Disable2FARequest struct {
	Code string `json:"code" binding:"required"` // Can be TOTP code or backup code
}

// VerifyTOTPRequest DTO for verifying TOTP code during login.
type VerifyTOTPRequest struct {
	UserID uuid.UUID `json:"user_id" binding:"required"` // Usually from a temporary token after password auth
	Code   string    `json:"code" binding:"required"`
}
