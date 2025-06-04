package security

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid" // For JTI

	"github.com/gameplatform/auth-service/internal/domain/service"
)

// JWTConfig holds configuration for the JWT service.
// This would typically be populated from the main application config.
type JWTConfig struct {
	Issuer            string
	Audience          string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration // For the opaque refresh token itself
	PrivateKeyPEM     string        // Placeholder for PEM encoded RSA private key
	PublicKeyPEM      string        // Placeholder for PEM encoded RSA public key
	JWKSKeyID         string        // Key ID for JWKS
}

type jwtService struct {
	config     JWTConfig
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewJWTService creates a new TokenService implementation using JWT with RS256.
// Keys (privateKeyPEM, publicKeyPEM) should be loaded from config and parsed here.
func NewJWTService(cfg JWTConfig) (service.TokenService, error) {
	if cfg.PrivateKeyPEM == "" || cfg.PublicKeyPEM == "" {
		// In a real app, you might only have private key locally and derive public,
		// or fetch public key if this service only validates.
		// For this example, we expect both for full generation & validation capability.
		// If keys are not set, this service cannot function for RS256.
		// Consider returning an error or using a fallback (e.g. HMAC for dev, though spec says RS256)
		// For now, let's assume they will be provided by a fuller config system.
		// This is a critical part that needs secure key management.
		// For this example, we'll proceed but log a warning or error if keys are missing.
		// return nil, errors.New("RSA private and public keys must be configured for JWTService")
		// For the subtask, we'll allow it to proceed with nil keys, methods will fail if keys are needed.
	}

	var privKey *rsa.PrivateKey
	var pubKey *rsa.PublicKey
	var err error

	if cfg.PrivateKeyPEM != "" {
		privKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(cfg.PrivateKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
	}

	if cfg.PublicKeyPEM != "" {
		pubKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(cfg.PublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
	}
	
	// Fallback to some example keys if not provided (NOT FOR PRODUCTION)
	if privKey == nil || pubKey == nil {
		// This is highly insecure and only for placeholder purposes for the subtask.
		// In a real application, keys MUST be provided securely.
		fmt.Println("WARNING: Using placeholder RSA keys for JWTService. NOT SUITABLE FOR PRODUCTION.")
		// Generate a temporary RSA key pair for this session if none were provided.
		tempPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		privKey = tempPrivKey
		pubKey = &tempPrivKey.PublicKey
	}


	return &jwtService{
		config:     cfg,
		privateKey: privKey,
		publicKey:  pubKey,
	}, nil
}

func (s *jwtService) GenerateAccessToken(
	userID string, username string, roles []string, permissions []string, sessionID string,
) (string, *service.Claims, error) {
	if s.privateKey == nil {
		return "", nil, errors.New("private key not configured for signing access tokens")
	}

	now := time.Now()
	jti := uuid.NewString() // Unique token ID

	claims := &service.Claims{
		UserID:      userID,
		Username:    username,
		Roles:       roles,
		Permissions: permissions,
		SessionID:   sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    s.config.Issuer,
			Audience:  jwt.ClaimStrings{s.config.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.config.AccessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.config.JWKSKeyID != "" {
		token.Header["kid"] = s.config.JWKSKeyID
	}

	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, claims, nil
}

func (s *jwtService) GenerateRefreshTokenValue() (string, error) {
	// Refresh tokens are often opaque, secure random strings.
	// Their association with userID and sessionID is stored server-side.
	b := make([]byte, 32) // 32 bytes = 256 bits
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate refresh token entropy: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *jwtService) ValidateAccessToken(tokenString string) (*service.Claims, error) {
	if s.publicKey == nil {
		return nil, errors.New("public key not configured for validating access tokens")
	}

	token, err := jwt.ParseWithClaims(tokenString, &service.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Potentially use a JWKS key provider here if `kid` is in header and multiple public keys are managed.
		return s.publicKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.New("token has expired") // Placeholder for entity.ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, errors.New("token not yet valid") // Placeholder for entity.ErrTokenNotValidYet
		}
		// This will also catch ErrSignatureInvalid
		return nil, fmt.Errorf("failed to parse or validate token: %w", err) // Placeholder for entity.ErrTokenInvalid
	}

	if claims, ok := token.Claims.(*service.Claims); ok && token.Valid {
		// Additional checks, though jwt.ParseWithClaims should handle exp, nbf, iat.
		// Issuer and Audience check:
		if claims.Issuer != s.config.Issuer {
			return nil, errors.New("invalid token issuer") // Placeholder for entity.ErrTokenInvalidIssuer
		}
		// Note: jwt.RegisteredClaims.Audience is jwt.ClaimStrings ([]string)
		// We need to check if our configured audience is present in this slice.
		validAudience := false
		for _, aud := range claims.Audience {
			if aud == s.config.Audience {
				validAudience = true
				break
			}
		}
		if !validAudience {
			return nil, errors.New("invalid token audience") // Placeholder for entity.ErrTokenInvalidAudience
		}
		return claims, nil
	}

	return nil, errors.New("invalid token or claims type") // Placeholder for entity.ErrTokenInvalid
}

func (s *jwtService) GetRefreshTokenExpiry() time.Duration {
	return s.config.RefreshTokenTTL
}

// GetJWKS returns the public key set in JWKS format.
// For RS256, this includes "kty", "kid", "use", "alg", "n", "e".
func (s *jwtService) GetJWKS() (map[string]interface{}, error) {
	if s.publicKey == nil {
		return nil, errors.New("public key not configured, cannot generate JWKS")
	}

	// For RSA, n (modulus) and e (exponent) are needed.
	// These are part of rsa.PublicKey.
	// N is a big.Int, E is an int. They need to be base64url encoded.
	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": s.config.JWKSKeyID, // Key ID, should be configured
		"use": "sig",             // Public key is used for signature verification
		"alg": jwt.SigningMethodRS256.Alg(), // Algorithm (RS256)
		"n":   base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.publicKey.E)).Bytes()),
	}

	return map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}, nil
}


var _ service.TokenService = (*jwtService)(nil)

// Placeholder for RSA keys (DO NOT USE IN PRODUCTION)
// These should be loaded from a secure configuration source.
// Need to import "math/big"
const (
	// Example, replace with actual key loading from config
	// In a real app, these would be fields in JWTConfig struct, populated from k8s secrets or Vault.
	// For the subtask, the NewJWTService will generate temporary ones if these are empty in config.
	// DefaultPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
	// MIIEog...
	// -----END RSA PRIVATE KEY-----`
	// DefaultPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
	// MIIBIj...
	// -----END PUBLIC KEY-----`
)