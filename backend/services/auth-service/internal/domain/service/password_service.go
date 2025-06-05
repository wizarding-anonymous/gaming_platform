// File: backend/services/auth-service/internal/domain/service/password_service.go
package service

// PasswordService defines the interface for password hashing and verification.
type PasswordService interface {
	// HashPassword creates a hash (e.g., Argon2id) of the given password.
	HashPassword(password string) (string, error)

	// CheckPasswordHash compares a plain password against a stored hash.
	// Returns true if they match, false otherwise.
	CheckPasswordHash(password, hash string) (bool, error)
}
