package security

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big" // Needed for JWKS
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid" // For JTI

	appConfig "github.com/your-org/auth-service/internal/config" // Alias for clarity
	"github.com/your-org/auth-service/internal/domain/service"
)

// rsaTokenManagementService implements the service.TokenManagementService using RS256.
type rsaTokenManagementService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	cfg        appConfig.JWTConfig // Store relevant parts of JWT config
}

// NewRSATokenManagementService creates a new rsaTokenManagementService.
// It requires RSA keys to be properly configured and loaded from file paths.
func NewRSATokenManagementService(cfg appConfig.JWTConfig) (service.TokenManagementService, error) {
	if cfg.RSAPrivateKeyPEMFile == "" || cfg.RSAPublicKeyPEMFile == "" || cfg.JWKSKeyID == "" {
		return nil, errors.New("RSA private key, public key file, and JWKS Key ID must be configured")
	}
	if cfg.AccessTokenTTL == 0 || cfg.RefreshTokenTTL == 0 {
		return nil, errors.New("access and refresh token TTLs must be configured")
	}
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("JWT issuer and audience must be configured")
	}

	privateKeyBytes, err := os.ReadFile(cfg.RSAPrivateKeyPEMFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA private key PEM file '%s': %w", cfg.RSAPrivateKeyPEMFile, err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key from PEM: %w", err)
	}

	publicKeyBytes, err := os.ReadFile(cfg.RSAPublicKeyPEMFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA public key PEM file '%s': %w", cfg.RSAPublicKeyPEMFile, err)
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key from PEM: %w", err)
	}

	return &rsaTokenManagementService{
		privateKey: privateKey,
		publicKey:  publicKey,
		cfg:        cfg,
	}, nil
}

// GenerateAccessToken creates a new JWT access token.
func (s *rsaTokenManagementService) GenerateAccessToken(
	userID string, username string, roles []string, permissions []string, sessionID string,
) (string, *service.Claims, error) {
	if s.privateKey == nil {
		return "", nil, errors.New("private key not configured for signing access tokens")
	}

	now := time.Now()
	jti := uuid.NewString()

	claims := &service.Claims{
		UserID:      userID,
		Username:    username,
		Roles:       roles,
		Permissions: permissions,
		SessionID:   sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    s.cfg.Issuer,
			Audience:  jwt.ClaimStrings{s.cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.cfg.JWKSKeyID

	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, claims, nil
}

// ValidateAccessToken validates the JWT access token.
func (s *rsaTokenManagementService) ValidateAccessToken(tokenString string) (*service.Claims, error) {
	if s.publicKey == nil {
		return nil, errors.New("public key not configured for validating access tokens")
	}

	token, err := jwt.ParseWithClaims(tokenString, &service.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Here, we could implement a more sophisticated key lookup if multiple keys/kids are used,
		// potentially fetching from a JWKS endpoint or cache.
		// For now, directly use the configured public key, assuming kid matches.
		if kid, ok := token.Header["kid"].(string); ok {
			if kid != s.cfg.JWKSKeyID {
				return nil, fmt.Errorf("token 'kid' %s does not match expected %s", kid, s.cfg.JWKSKeyID)
			}
		} else {
			// If kid is not present in token, and we only have one key, we can proceed.
			// Or, enforce 'kid' presence. For now, if no kid, assume it's for our key.
		}
		return s.publicKey, nil
	}, jwt.WithAudience(s.cfg.Audience), jwt.WithIssuer(s.cfg.Issuer))


	if err != nil {
		// err already contains detailed error like "token is expired" or "signature is invalid"
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if claims, ok := token.Claims.(*service.Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token or claims type")
}

// GenerateRefreshTokenValue creates an opaque refresh token value.
func (s *rsaTokenManagementService) GenerateRefreshTokenValue() (string, error) {
	b := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate refresh token entropy: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetRefreshTokenExpiry returns the configured duration for refresh token validity.
func (s *rsaTokenManagementService) GetRefreshTokenExpiry() time.Duration {
	return s.cfg.RefreshTokenTTL
}

// GetJWKS returns the public key set in JWKS format.
func (s *rsaTokenManagementService) GetJWKS() (map[string]interface{}, error) {
	if s.publicKey == nil {
		return nil, errors.New("public key not configured, cannot generate JWKS")
	}

	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": s.cfg.JWKSKeyID,
		"use": "sig",
		"alg": jwt.SigningMethodRS256.Alg(),
		"n":   base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.publicKey.E)).Bytes()),
	}

	return map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}, nil
}

// Ensure rsaTokenManagementService implements service.TokenManagementService.
var _ service.TokenManagementService = (*rsaTokenManagementService)(nil)