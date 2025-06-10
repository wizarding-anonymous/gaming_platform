// File: backend/services/auth-service/internal/infrastructure/security/pquerna_totp_service.go
package security

import (
	"fmt"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	domainInterfaces "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/interfaces" // Path to the TOTPService interface
)

// pquernaTOTPService implements the domainInterfaces.TOTPService using the pquerna/otp library.
type pquernaTOTPService struct {
	defaultIssuerName string
}

// NewPquernaTOTPService creates a new pquernaTOTPService.
// defaultIssuerName is the global issuer name for OTPs (e.g., your application's name).
func NewPquernaTOTPService(defaultIssuerName string) domainInterfaces.TOTPService {
	if strings.TrimSpace(defaultIssuerName) == "" {
		defaultIssuerName = "MyApp" // A fallback default if not configured
	}
	return &pquernaTOTPService{
		defaultIssuerName: defaultIssuerName,
	}
}

// GenerateSecret creates a new TOTP secret.
func (s *pquernaTOTPService) GenerateSecret(accountName string, issuerNameOverride string) (string, string, error) {
	issuer := s.defaultIssuerName
	if strings.TrimSpace(issuerNameOverride) != "" {
		issuer = issuerNameOverride
	}

	if strings.TrimSpace(accountName) == "" {
		return "", "", fmt.Errorf("accountName cannot be empty for TOTP secret generation")
	}
	if strings.Contains(accountName, ":") {
		return "", "", fmt.Errorf("accountName cannot contain a colon character")
	}
	if strings.Contains(issuer, ":") {
		return "", "", fmt.Errorf("issuer name cannot contain a colon character")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
		Period:      30,                // Standard TOTP period
		Digits:      otp.DigitsSix,     // Standard 6 digits
		Algorithm:   otp.AlgorithmSHA1, // Standard algorithm
		SecretSize:  20,                // Standard secret size (160 bits for SHA1)
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	secretBase32 := key.Secret()
	otpAuthURL := key.URL()

	return secretBase32, otpAuthURL, nil
}

// ValidateCode checks if the provided TOTP code is valid for the given secret.
func (s *pquernaTOTPService) ValidateCode(secretBase32 string, code string) (bool, error) {
	if strings.TrimSpace(secretBase32) == "" {
		return false, fmt.Errorf("secret cannot be empty")
	}
	if strings.TrimSpace(code) == "" {
		return false, fmt.Errorf("code cannot be empty")
	}

	valid, err := totp.ValidateCustom(code, secretBase32, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // Allow for 1 period (30 seconds) clock drift on either side
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})

	if err != nil {
		// Distinguish between "code is simply wrong" and other errors.
		// pquerna/otp might return specific errors for invalid formats, etc.
		// For now, any error from ValidateCustom is treated as a validation failure.
		return false, fmt.Errorf("error during TOTP code validation: %w", err)
	}

	return valid, nil
}

// Ensure pquernaTOTPService implements domainInterfaces.TOTPService (compile-time check).
var _ domainInterfaces.TOTPService = (*pquernaTOTPService)(nil)
