// File: internal/infrastructure/security/rsa_jwt_service_test.go
package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json" // For JWKS test
	"encoding/pem"
	"math/big" // For JWKS test
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/your-org/auth-service/internal/config"
	"github.com/your-org/auth-service/internal/domain/service"
	jose "gopkg.in/square/go-jose.v2" // For JWKS verification
)

const (
	testRSABits      = 2048
	testJWKSKeyID    = "test-kid"
	testIssuer       = "test-issuer"
	testAudience     = "test-audience"
	testHmacSecret   = "test-hmac-secret-for-state-and-challenge-tokens"
	testOAuthStateSecret = "another-hmac-secret-for-oauth-state"
)

// Helper to generate RSA keys for testing and save them to temp files
// Returns paths to private and public key files, and a cleanup function
func generateTestRSAKeys(t *testing.T) (privKeyPath string, pubKeyPath string, rsaPrivKey *rsa.PrivateKey, rsaPubKey *rsa.PublicKey, cleanupFunc func()) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, testRSABits)
	require.NoError(t, err, "Failed to generate RSA private key")
	rsaPrivKey = privateKey
	rsaPubKey = &privateKey.PublicKey

	privBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})

	pubASN1Bytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubASN1Bytes})

	tempDir, err := os.MkdirTemp("", "testkeys-")
	require.NoError(t, err, "Failed to create temp dir for keys")

	privKeyPath = filepath.Join(tempDir, "test_priv.pem")
	pubKeyPath = filepath.Join(tempDir, "test_pub.pem")

	err = os.WriteFile(privKeyPath, privPEM, 0600)
	require.NoError(t, err, "Failed to write private key to temp file")

	err = os.WriteFile(pubKeyPath, pubPEM, 0644)
	require.NoError(t, err, "Failed to write public key to temp file")

	cleanupFunc = func() {
		os.RemoveAll(tempDir)
	}
	return privKeyPath, pubKeyPath, rsaPrivKey, rsaPubKey, cleanupFunc
}

// --- Test NewRSAJWTService ---

func TestNewRSAJWTService_Success(t *testing.T) {
	privPath, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	cfg := config.JWTConfig{
		PrivateKeyPath:   privPath,
		PublicKeyPath:    pubPath,
		AccessTokenTTL:   time.Minute * 15,
		RefreshTokenTTL:  time.Hour * 24 * 7,
		JWKSKeyID:        testJWKSKeyID,
		Issuer:           testIssuer,
		Audience:         testAudience,
		HMACSecretKey:    testHmacSecret,
		OAuthStateSecret: testOAuthStateSecret,
	}

	svc, err := NewRSATokenManagementService(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, svc)
}

func TestNewRSAJWTService_Failure_MissingPrivateKey(t *testing.T) {
	_, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	cfg := config.JWTConfig{
		PrivateKeyPath:   "nonexistent_priv.pem",
		PublicKeyPath:    pubPath,
		AccessTokenTTL:   time.Minute * 15,
		RefreshTokenTTL:  time.Hour * 24 * 7,
		JWKSKeyID:        testJWKSKeyID,
		Issuer:           testIssuer,
		Audience:         testAudience,
		HMACSecretKey:    testHmacSecret,
		OAuthStateSecret: testOAuthStateSecret,
	}

	svc, err := NewRSATokenManagementService(cfg)
	assert.Error(t, err)
	assert.Nil(t, svc)
	assert.Contains(t, err.Error(), "failed to read private key")
}

func TestNewRSAJWTService_Failure_MissingPublicKey(t *testing.T) {
	privPath, _, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	cfg := config.JWTConfig{
		PrivateKeyPath:   privPath,
		PublicKeyPath:    "nonexistent_pub.pem",
		AccessTokenTTL:   time.Minute * 15,
		RefreshTokenTTL:  time.Hour * 24 * 7,
		JWKSKeyID:        testJWKSKeyID,
		Issuer:           testIssuer,
		Audience:         testAudience,
		HMACSecretKey:    testHmacSecret,
		OAuthStateSecret: testOAuthStateSecret,
	}

	svc, err := NewRSATokenManagementService(cfg)
	assert.Error(t, err)
	assert.Nil(t, svc)
	assert.Contains(t, err.Error(), "failed to read public key")
}

func TestNewRSAJWTService_Failure_InvalidPrivateKey(t *testing.T) {
	_, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	tempDir, err := os.MkdirTemp("", "testkeys-invalid-")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	invalidPrivPath := filepath.Join(tempDir, "invalid_priv.pem")
	err = os.WriteFile(invalidPrivPath, []byte("this is not a valid PEM key"), 0600)
	require.NoError(t, err)


	cfg := config.JWTConfig{
		PrivateKeyPath:   invalidPrivPath,
		PublicKeyPath:    pubPath,
		AccessTokenTTL:   time.Minute * 15,
		RefreshTokenTTL:  time.Hour * 24 * 7,
		JWKSKeyID:        testJWKSKeyID,
		Issuer:           testIssuer,
		Audience:         testAudience,
		HMACSecretKey:    testHmacSecret,
		OAuthStateSecret: testOAuthStateSecret,
	}

	svc, err := NewRSATokenManagementService(cfg)
	assert.Error(t, err)
	assert.Nil(t, svc)
	assert.Contains(t, err.Error(), "failed to parse private key PEM")
}

// --- Test GenerateAccessToken ---
func TestRSAJWTService_GenerateAccessToken_Success(t *testing.T) {
	privPath, pubPath, _, rsaPubKey, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	cfg := config.JWTConfig{
		PrivateKeyPath:   privPath,
		PublicKeyPath:    pubPath,
		AccessTokenTTL:   time.Minute * 15,
		RefreshTokenTTL:  time.Hour * 24 * 7,
		JWKSKeyID:        testJWKSKeyID,
		Issuer:           testIssuer,
		Audience:         testAudience,
		HMACSecretKey:    testHmacSecret,
		OAuthStateSecret: testOAuthStateSecret,
	}
	svc, err := NewRSATokenManagementService(cfg)
	require.NoError(t, err)

	userID := uuid.New().String()
	username := "testuser"
	roles := []string{"user", "editor"}
	permissions := []string{"read:article", "write:article"}
	sessionID := uuid.New().String()

	now := time.Now()
	tokenString, err := svc.GenerateAccessToken(userID, username, roles, permissions, sessionID)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	token, err := jwt.ParseWithClaims(tokenString, &service.Claims{}, func(token *jwt.Token) (interface{}, error) {
		assert.Equal(t, "RS256", token.Method.(*jwt.SigningMethodRSA).Name)
		if cfg.JWKSKeyID != "" {
			assert.Equal(t, cfg.JWKSKeyID, token.Header["kid"])
		}
		return rsaPubKey, nil
	})
	require.NoError(t, err, "Failed to parse generated token")
	assert.True(t, token.Valid, "Token should be valid")

	claims, ok := token.Claims.(*service.Claims)
	require.True(t, ok, "Failed to cast claims to service.Claims")

	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, username, claims.Username)
	assert.ElementsMatch(t, roles, claims.Roles)
	assert.ElementsMatch(t, permissions, claims.Permissions)
	assert.Equal(t, sessionID, claims.SessionID)

	assert.Equal(t, cfg.Issuer, claims.Issuer)
	assert.Equal(t, cfg.Audience, claims.Audience[0])

	expectedExpiry := now.Add(cfg.AccessTokenTTL)
	assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, time.Second*5, "Expiry time mismatch")
	assert.WithinDuration(t, now, claims.IssuedAt.Time, time.Second*5, "IssuedAt time mismatch")
	assert.WithinDuration(t, now, claims.NotBefore.Time, time.Second*5, "NotBefore time mismatch")
	assert.NotEmpty(t, claims.ID, "JTI should not be empty")
}

// --- Test ValidateAccessToken ---
func TestRSAJWTService_ValidateAccessToken_Success(t *testing.T) {
	privPath, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()
	cfg := config.JWTConfig{PrivateKeyPath: privPath, PublicKeyPath: pubPath, AccessTokenTTL: time.Minute, Issuer: testIssuer, Audience: testAudience, HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	svc, _ := NewRSATokenManagementService(cfg)

	userID := uuid.New().String()
	tokenString, _ := svc.GenerateAccessToken(userID, "user", nil, nil, "sid")

	claims, err := svc.ValidateAccessToken(tokenString)
	assert.NoError(t, err)
	assert.NotNil(t, claims)
	assert.Equal(t, userID, claims.UserID)
}

func TestRSAJWTService_ValidateAccessToken_Failure_InvalidSignature(t *testing.T) {
	privPath, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()
	cfg := config.JWTConfig{PrivateKeyPath: privPath, PublicKeyPath: pubPath, AccessTokenTTL: time.Minute, Issuer: testIssuer, Audience: testAudience, HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	svc, _ := NewRSATokenManagementService(cfg)

	tokenString, _ := svc.GenerateAccessToken(uuid.New().String(), "user", nil, nil, "sid")

	otherPrivPath, otherPubPath, _, _, otherCleanup := generateTestRSAKeys(t)
	defer otherCleanup()
	otherCfg := config.JWTConfig{PrivateKeyPath: otherPrivPath, PublicKeyPath: otherPubPath, AccessTokenTTL: time.Minute, Issuer: testIssuer, Audience: testAudience, HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	otherSvc, _ := NewRSATokenManagementService(otherCfg)

	claims, err := otherSvc.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "crypto/rsa: verification error", "Error should be signature validation error")
}

func TestRSAJWTService_ValidateAccessToken_Failure_Expired(t *testing.T) {
	privPath, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	expiredTTL := -time.Second * 1
	cfg := config.JWTConfig{PrivateKeyPath: privPath, PublicKeyPath: pubPath, AccessTokenTTL: expiredTTL, Issuer: testIssuer, Audience: testAudience, HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	svc, _ := NewRSATokenManagementService(cfg)

	tokenString, _ := svc.GenerateAccessToken(uuid.New().String(), "user", nil, nil, "sid")

	claims, err := svc.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
	var jwtErr *jwt.ValidationError
	require.ErrorAs(t, err, &jwtErr, "Error should be a JWT validation error")
	assert.True(t, jwtErr.Is(jwt.ErrTokenExpired), "Error should be due to token expiry")
}


func TestRSAJWTService_ValidateAccessToken_Failure_NotYetValid(t *testing.T) {
	privPath, pubPath, rsaPrivKey, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()
	cfg := config.JWTConfig{PrivateKeyPath: privPath, PublicKeyPath: pubPath, AccessTokenTTL: time.Minute, Issuer: testIssuer, Audience: testAudience, JWKSKeyID: testJWKSKeyID, HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	svc, _ := NewRSATokenManagementService(cfg)

	userID := uuid.New().String()
	now := time.Now()
	nbf := now.Add(time.Hour)
	exp := nbf.Add(cfg.AccessTokenTTL)

	customClaims := &service.Claims{
		UserID:    userID,
		Username:  "test",
		SessionID: "sid",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    cfg.Issuer,
			Audience:  jwt.ClaimStrings{cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(exp),
			NotBefore: jwt.NewNumericDate(nbf),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, customClaims)
	if cfg.JWKSKeyID != "" {
		token.Header["kid"] = cfg.JWKSKeyID
	}
	tokenString, errSign := token.SignedString(rsaPrivKey)
	require.NoError(t, errSign)

	claims, err := svc.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
	var jwtErr *jwt.ValidationError
	require.ErrorAs(t, err, &jwtErr, "Error should be a JWT validation error")
	assert.True(t, jwtErr.Is(jwt.ErrTokenNotValidYet), "Error should be due to NBF")
}

func TestRSAJWTService_ValidateAccessToken_Failure_IncorrectIssuer(t *testing.T) {
	privPath, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	cfgCorrectIssuer := config.JWTConfig{PrivateKeyPath: privPath, PublicKeyPath: pubPath, AccessTokenTTL: time.Minute, Issuer: "correct-issuer", Audience: testAudience, HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	svcCorrect, _ := NewRSATokenManagementService(cfgCorrectIssuer)

	cfgWrongIssuerService := config.JWTConfig{PrivateKeyPath: privPath, PublicKeyPath: pubPath, AccessTokenTTL: time.Minute, Issuer: "wrong-issuer", Audience: testAudience, HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	svcWrongIssuer, _ := NewRSATokenManagementService(cfgWrongIssuerService)

	tokenString, _ := svcCorrect.GenerateAccessToken(uuid.New().String(), "user", nil, nil, "sid")

	claims, err := svcWrongIssuer.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
	var jwtErr *jwt.ValidationError
	require.ErrorAs(t, err, &jwtErr, "Error should be a JWT validation error")
	assert.True(t, jwtErr.Is(jwt.ErrTokenInvalidIssuer), "Error should be due to incorrect issuer")
}

func TestRSAJWTService_ValidateAccessToken_Failure_IncorrectAudience(t *testing.T) {
	privPath, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	cfgCorrectAudience := config.JWTConfig{PrivateKeyPath: privPath, PublicKeyPath: pubPath, AccessTokenTTL: time.Minute, Issuer: testIssuer, Audience: "correct-audience", HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	svcCorrect, _ := NewRSATokenManagementService(cfgCorrectAudience)

	cfgWrongAudienceService := config.JWTConfig{PrivateKeyPath: privPath, PublicKeyPath: pubPath, AccessTokenTTL: time.Minute, Issuer: testIssuer, Audience: "wrong-audience", HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	svcWrongAudience, _ := NewRSATokenManagementService(cfgWrongAudienceService)

	tokenString, _ := svcCorrect.GenerateAccessToken(uuid.New().String(), "user", nil, nil, "sid")

	claims, err := svcWrongAudience.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
	var jwtErr *jwt.ValidationError
	require.ErrorAs(t, err, &jwtErr, "Error should be a JWT validation error")
	assert.Contains(t, err.Error(), "token has invalid claims: aud_claim_is_required_or_invalid", "Error should be due to incorrect audience")
}

func TestRSAJWTService_ValidateAccessToken_MalformedToken(t *testing.T) {
	privPath, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()
	cfg := config.JWTConfig{PrivateKeyPath: privPath, PublicKeyPath: pubPath, AccessTokenTTL: time.Minute, Issuer: testIssuer, Audience: testAudience, HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret}
	svc, _ := NewRSATokenManagementService(cfg)

	malformedToken := "this.is.not.a.jwt"
	claims, err := svc.ValidateAccessToken(malformedToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
	assert.Contains(t, err.Error(), "token contains an invalid number of segments")
}

// --- Test GenerateRefreshTokenValue ---
func TestRSAJWTService_GenerateRefreshTokenValue(t *testing.T) {
	privPath, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()
	cfg := config.JWTConfig{
		PrivateKeyPath: privPath, PublicKeyPath: pubPath,
		RefreshTokenByteLength: 32,
		HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret,
	}
	svc, _ := NewRSATokenManagementService(cfg)

	tokenVal1, err1 := svc.GenerateRefreshTokenValue()
	assert.NoError(t, err1)
	assert.NotEmpty(t, tokenVal1)

	_, errDecode1 := base64.RawURLEncoding.DecodeString(tokenVal1)
	assert.NoError(t, errDecode1, "Refresh token should be URL-safe base64")

	decodedBytes1, _ := base64.RawURLEncoding.DecodeString(tokenVal1)
	assert.Equal(t, int(cfg.RefreshTokenByteLength), len(decodedBytes1), "Decoded refresh token length mismatch")


	tokenVal2, err2 := svc.GenerateRefreshTokenValue()
	assert.NoError(t, err2)
	assert.NotEmpty(t, tokenVal2)
	assert.NotEqual(t, tokenVal1, tokenVal2, "Subsequent refresh tokens should be different")
}

// --- Test GetRefreshTokenExpiry ---
func TestRSAJWTService_GetRefreshTokenExpiry(t *testing.T) {
	privPath, pubPath, _, _, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	expectedTTL := time.Hour * 24 * 30
	cfg := config.JWTConfig{
		PrivateKeyPath: privPath, PublicKeyPath: pubPath,
		RefreshTokenTTL: expectedTTL,
		HMACSecretKey: testHmacSecret, OAuthStateSecret: testOAuthStateSecret,
	}
	svc, _ := NewRSATokenManagementService(cfg)

	actualExpiryTime := svc.GetRefreshTokenExpiry()

	expectedTime := time.Now().Add(expectedTTL)
	assert.WithinDuration(t, expectedTime, actualExpiryTime, time.Second*5, "Refresh token expiry time mismatch")
}

// --- Test GetJWKS ---
func TestRSAJWTService_GetJWKS_Success(t *testing.T) {
	privPath, pubPath, _, rsaPubKey, cleanup := generateTestRSAKeys(t)
	defer cleanup()

	cfg := config.JWTConfig{
		PrivateKeyPath:   privPath,
		PublicKeyPath:    pubPath,
		JWKSKeyID:        testJWKSKeyID, // Ensure KID is set
		HMACSecretKey:    testHmacSecret,
		OAuthStateSecret: testOAuthStateSecret,
	}
	svc, err := NewRSATokenManagementService(cfg)
	require.NoError(t, err)

	jwksJSON, err := svc.GetJWKS()
	assert.NoError(t, err)
	assert.NotEmpty(t, jwksJSON)

	// Unmarshal to verify structure
	var jwks jose.JSONWebKeySet
	err = json.Unmarshal(jwksJSON, &jwks)
	require.NoError(t, err, "Failed to unmarshal JWKS JSON")
	require.Len(t, jwks.Keys, 1, "JWKS should contain one key")

	jwk := jwks.Keys[0]
	assert.Equal(t, testJWKSKeyID, jwk.KeyID, "JWK KeyID mismatch")
	assert.Equal(t, "RS256", jwk.Algorithm, "JWK Algorithm mismatch")
	assert.Equal(t, "sig", jwk.Use, "JWK Use mismatch")

	// Verify RSA specific fields (n, e)
	rsaPublicKey, ok := jwk.Key.(*rsa.PublicKey)
	require.True(t, ok, "JWK key is not an RSA public key")
	assert.Equal(t, rsaPubKey.N, rsaPublicKey.N, "JWK modulus mismatch")
	assert.Equal(t, rsaPubKey.E, rsaPublicKey.E, "JWK exponent mismatch")

	// Check base64url encoding of N and E (optional, but good for spec compliance)
	// This requires parsing the raw JSON for the 'n' and 'e' fields
	var rawJWKS map[string][]map[string]string
	err = json.Unmarshal(jwksJSON, &rawJWKS)
	require.NoError(t, err)
	rawKeyFields := rawJWKS["keys"][0]

	expectedN := base64.RawURLEncoding.EncodeToString(rsaPubKey.N.Bytes())
	expectedE := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPubKey.E)).Bytes())
	assert.Equal(t, expectedN, rawKeyFields["n"])
	assert.Equal(t, expectedE, rawKeyFields["e"])
}


func TestRSAJWTService_GetJWKS_Failure_NoPublicKey(t *testing.T) {
	privPath, _, _, _, cleanup := generateTestRSAKeys(t) // Generate keys, but don't provide public key path to service
	defer cleanup()

	cfg := config.JWTConfig{
		PrivateKeyPath:   privPath,
		PublicKeyPath:    "", // Empty public key path
		JWKSKeyID:        testJWKSKeyID,
		HMACSecretKey:    testHmacSecret,
		OAuthStateSecret: testOAuthStateSecret,
	}
	// NewRSATokenManagementService might not error here if public key is optional for some ops,
	// but GetJWKS should fail.
	svc, err := NewRSATokenManagementService(cfg)
	if err != nil && strings.Contains(err.Error(), "public key path is empty") {
		// If constructor fails due to empty public key path, this test is valid.
		assert.Error(t, err)
		assert.Nil(t, svc)
		return
	}
	// If constructor allows empty public key path (e.g., if only signing is needed by an instance)
	// then GetJWKS should error.
	require.NotNil(t, svc, "Service should be instantiated if public key is optional for constructor")

	jwksJSON, err := svc.GetJWKS()
	assert.Error(t, err, "GetJWKS should error if public key is not available")
	assert.Nil(t, jwksJSON)
	assert.Contains(t, err.Error(), "public key not available for JWKS")
}
