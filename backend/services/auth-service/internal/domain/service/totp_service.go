// File: backend/services/auth-service/internal/domain/service/totp_service.go
package service

// TOTPService defines the interface for Time-based One-Time Password generation and validation.
type TOTPService interface {
	// GenerateSecret creates a new TOTP secret for a user account.
	// accountName is typically the user's email or username.
	// issuerNameOverride can be used if a specific issuer is needed for this key,
	// otherwise the service's default issuer name is used.
	// Returns:
	// - secretBase32: The new secret key, base32 encoded (this is what should be stored, encrypted).
	// - otpAuthURL: The otpauth:// URL for QR code generation (includes issuer, accountName, secret).
	// - error: Any error encountered.
	GenerateSecret(accountName string, issuerNameOverride string) (secretBase32 string, otpAuthURL string, err error)

	// ValidateCode checks if the provided TOTP code is valid for the given secret.
	// secretBase32 is the base32 encoded secret stored for the user.
	// code is the TOTP code entered by the user.
	// Returns true if valid, false otherwise, and any error.
	ValidateCode(secretBase32 string, code string) (bool, error)
}
