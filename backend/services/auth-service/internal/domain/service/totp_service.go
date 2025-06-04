package service

// TOTPService defines the interface for Time-based One-Time Password operations.
type TOTPService interface {
	// GenerateSecret creates a new TOTP secret for a user.
	// accountName is typically the user's email or username.
	// issuerName is the name of the application or service.
	// Returns the base32 encoded secret, a QR code data URL for authenticator apps, and an error.
	GenerateSecret(accountName, issuerName string) (secretB32 string, qrCodeDataURL string, err error)

	// ValidateCode checks if the provided TOTP code is valid for the given secret.
	// It should account for potential clock drift by checking codes for a small window
	// around the current time.
	ValidateCode(secretB32, code string) (isValid bool, err error)
}
