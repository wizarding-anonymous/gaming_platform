// File: backend/services/auth-service/internal/infrastructure/security/verification_utils.go
package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// GenerateSecureToken generates a URL-safe, random string of specified byte length.
// The resulting string will be hex encoded, so its length will be 2*byteLength.
func GenerateSecureToken(byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = 32 // Default to 32 bytes -> 64 char hex string
	}
	b := make([]byte, byteLength)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to read random bytes for token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashToken hashes a plain token string using SHA256 and returns the hex-encoded hash.
func HashToken(plainToken string) string {
	hasher := sha256.New()
	hasher.Write([]byte(plainToken)) // SHA256 operates on bytes
	return hex.EncodeToString(hasher.Sum(nil))
}
