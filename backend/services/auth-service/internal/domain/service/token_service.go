// File: backend/services/auth-service/internal/domain/service/token_service.go
package service

import (
	"time"

	"github.com/golang-jwt/jwt/v5" // Using v5 as it's current
)

// Claims represents the JWT claims for an access token.
type Claims struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions,omitempty"` // Optional
	SessionID   string   `json:"session_id"`
	jwt.RegisteredClaims
}

// TokenService defines the interface for generating and validating tokens.
type TokenService interface {
	// GenerateAccessToken creates a new JWT access token for a user.
	GenerateAccessToken(userID string, username string, roles []string, permissions []string, sessionID string) (string, *Claims, error)

	// GenerateRefreshToken creates a new opaque refresh token string.
	// The actual refresh token (e.g., long random string) is stored/managed separately.
	// This method might just generate the string, or could also handle its storage if tightly coupled.
	// For now, let's assume it generates an opaque string.
	// The spec mentions "Refresh token rotation: The implementation should support the idea that a new refresh token is issued when an old one is used."
	// This implies the refresh token itself is a value that can be stored and rotated.
	GenerateRefreshTokenValue() (string, error) // Generates an opaque secure random string

	// ValidateAccessToken parses and validates a JWT access token string.
	// Returns the claims if valid, or an error otherwise.
	ValidateAccessToken(tokenString string) (*Claims, error)

	// GetRefreshTokenExpiry returns the expiry duration for refresh tokens.
	GetRefreshTokenExpiry() time.Duration

	// GetJWKS returns the JSON Web Key Set containing the public keys used for signing tokens.
	GetJWKS() (map[string]interface{}, error) // JWKS typically represented as map[string]interface{} or a dedicated struct
}
