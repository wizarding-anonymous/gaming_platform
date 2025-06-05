// File: backend/services/auth-service/internal/domain/models/mfa.go
package models

import (
	// "github.com/google/uuid"
	// "time"
)

// Login2FARequest is the DTO for verifying a 2FA code after primary login.
type Login2FARequest struct {
	ChallengeToken string `json:"challenge_token" binding:"required"`
	Method         string `json:"method" binding:"required,oneof=totp backup"` // "totp" or "backup"
	Code           string `json:"code" binding:"required"`
}

// Login2FAResponse is the DTO for a successful 2FA verification, same as normal login response.
type Login2FAResponse struct {
	User      UserResponse `json:"user"`
	TokenPair TokenPair    `json:"tokens"`
}

// Enable2FARequest DTO for initiating 2FA setup.
// UserID comes from authenticated context. AccountName can be derived from user info.
type Enable2FAInitiateRequest struct {
	// No fields needed from client for initiation if accountName is derived server-side
}

// Enable2FAInitiateResponse DTO for returning TOTP secret and QR code URL.
type Enable2FAInitiateResponse struct {
	MFASecretID  string `json:"mfa_secret_id"` // ID of the mfa_secrets record created
	SecretKey    string `json:"secret_key"`    // Plain base32 secret for manual entry (maps to SecretBase32)
	QRCodeImage  string `json:"qr_code_image"` // otpauth:// URL for QR code generation (maps to OTPAuthURL)
}

// Verify2FARequest DTO for verifying the TOTP code during 2FA setup.
// This can also be used for verifying TOTP during login if challenge token is handled separately.
type Verify2FARequest struct {
	MFASecretID string `json:"mfa_secret_id,omitempty" binding:"omitempty,uuid"` // Needed for activation, optional for login verify step
	TOTPCode    string `json:"totp_code" binding:"required,len=6,numeric"`
}

// VerifyAndActivate2FAResponse DTO for returning backup codes after successful 2FA activation.
type VerifyAndActivate2FAResponse struct {
	Message     string   `json:"message"`
	Message     string   `json:"message"`
	BackupCodes []string `json:"backup_codes"`
}

// Disable2FARequest DTO for disabling 2FA.
type Disable2FARequest struct {
	VerificationToken string `json:"verification_token" binding:"required"` // Password or a current 2FA code
	VerificationMethod string `json:"verification_method" binding:"required,oneof=password totp backup"`
}

// RegenerateBackupCodesRequest DTO for regenerating backup codes.
type RegenerateBackupCodesRequest struct {
	VerificationToken string `json:"verification_token" binding:"required"`
	VerificationMethod string `json:"verification_method" binding:"required,oneof=password totp backup"`
}

// RegenerateBackupCodesResponse DTO for returning new backup codes.
type RegenerateBackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}
