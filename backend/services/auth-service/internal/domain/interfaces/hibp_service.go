// File: backend/services/auth-service/internal/domain/interfaces/hibp_service.go
package interfaces

import (
	"context"
)

// HIBPService defines the interface for checking passwords against the "Have I Been Pwned?" database.
type HIBPService interface {
	// CheckPasswordPwned checks if a password has been exposed in known data breaches.
	// It calculates the SHA-1 hash of the password, sends the first 5 characters of the hash
	// to the HIBP API, and compares the remaining hash suffix against the API's response.
	// Returns true if the password hash suffix is found in the HIBP database, indicating it's pwned.
	// Returns false if the password is not found or if the check cannot be completed due to an error.
	// An error is returned for network issues or unexpected API responses.
	CheckPasswordPwned(ctx context.Context, password string) (bool, error)
}
