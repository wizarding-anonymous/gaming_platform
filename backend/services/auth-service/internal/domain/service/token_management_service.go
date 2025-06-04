package service // Or domain_service, sticking to service as per existing PasswordService

import (
	"time"
	// It's good practice to ensure the module path is correct for your project.
	// Assuming "github.com/your-org/auth-service" is the module path.
	// If Claims struct is used by other packages frequently, consider moving to models.
	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims for access tokens.
type Claims struct {
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"` // Optional: can be fetched by services using UserID
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions,omitempty"` // Optional, can be large
	SessionID   string   `json:"session_id"`            // Link back to the session
	jwt.RegisteredClaims
}

// TokenManagementService defines the interface for generating and validating tokens,
// specifically focusing on RS256 signed JWT access tokens and providing JWKS.
type TokenManagementService interface {
	// GenerateAccessToken creates a new JWT access token with the given user and session details.
	// It returns the signed token string and the claims used.
	GenerateAccessToken(userID string, username string, roles []string, permissions []string, sessionID string) (string, *Claims, error)

	// ValidateAccessToken validates the given JWT access token string.
	// It returns the parsed claims if the token is valid.
	ValidateAccessToken(tokenString string) (*Claims, error)

	// GenerateRefreshTokenValue creates a new opaque refresh token value.
	// This value will be stored (hashed) in the database.
	GenerateRefreshTokenValue() (string, error)

	// GetRefreshTokenExpiry returns the configured duration for refresh token validity.
	GetRefreshTokenExpiry() time.Duration

	// GetJWKS returns the JSON Web Key Set (JWKS) for exposing public keys.
	// This typically includes the public key(s) used to sign the access tokens.
	GetJWKS() (map[string]interface{}, error) // JWKS is a JSON object, map[string]interface{} is a common representation
}
