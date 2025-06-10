// File: internal/infrastructure/security/rsa_jwt_service_test.go
package security_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appConfig "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service" // Alias for domain service
	appSecurity "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"
)

const (
	testRSAKeyBits      = 2048 // Use 2048 for tests; 512 is too small for some JWT libs or policies
	testJWKSKeyID       = "test-kid-rsa"
	testIssuerRSA       = "test-issuer-rsa"
	testAudienceRSA     = "test-audience-rsa"
	testHMACSecretRSA   = "test-hmac-secret-for-state-jwt-rsa"
	testPermissionsData = "read:data,write:data"
)

// createTestRSAFiles generates temporary PEM files for RSA private and public keys.
func createTestRSAFiles(t *testing.T, bits int) (privateKeyPath string, publicKeyPath string) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	pubKeyASN1, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyASN1,
	})

	privFile, err := os.CreateTemp(t.TempDir(), "test_private_*.pem")
	require.NoError(t, err)
	_, err = privFile.Write(privKeyPEM)
	require.NoError(t, err)
	require.NoError(t, privFile.Close())

	pubFile, err := os.CreateTemp(t.TempDir(), "test_public_*.pem")
	require.NoError(t, err)
	_, err = pubFile.Write(pubKeyPEM)
	require.NoError(t, err)
	require.NoError(t, pubFile.Close())

	return privFile.Name(), pubFile.Name()
}

func newTestJWTConfigRSA(t *testing.T, privateKeyPath, publicKeyPath string) appConfig.JWTConfig {
	return appConfig.JWTConfig{
		RSAPrivateKeyPEMFile: privateKeyPath,
		RSAPublicKeyPEMFile:  publicKeyPath,
		JWKSKeyID:            testJWKSKeyID,
		AccessTokenTTL:       15 * time.Minute,
		RefreshTokenTTL:      24 * 7 * time.Hour,
		MFAChallengeTokenTTL: 5 * time.Minute, // Though rsa_jwt_service uses a const for this
		OAuthStateCookieTTL:  10 * time.Minute,
		OAuthStateSecret:     testHMACSecretRSA, // Used for HS256 state tokens
		Issuer:               testIssuerRSA,
		Audience:             testAudienceRSA,
	}
}

func sampleRSADomainClaims() (userID, username string, roles, permissions []string, sessionID string) {
	return "user-rsa-123", "rsa_user", []string{"player", "subscriber"}, strings.Split(testPermissionsData, ","), "session-rsa-abc"
}

func TestNewRSATokenManagementService_ValidConfig(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)

	tm, err := appSecurity.NewRSATokenManagementService(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, tm)
}

func TestNewRSATokenManagementService_MissingConfig(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	baseCfg := newTestJWTConfigRSA(t, privPath, pubPath)

	testCases := []struct {
		name    string
		mutator func(c *appConfig.JWTConfig)
		errMsg  string
	}{
		{"MissingPrivateKeyPath", func(c *appConfig.JWTConfig) { c.RSAPrivateKeyPEMFile = "" }, "RSA private key, public key file, and JWKS Key ID must be configured"},
		{"MissingPublicKeyPath", func(c *appConfig.JWTConfig) { c.RSAPublicKeyPEMFile = "" }, "RSA private key, public key file, and JWKS Key ID must be configured"},
		{"MissingJWKSKeyID", func(c *appConfig.JWTConfig) { c.JWKSKeyID = "" }, "RSA private key, public key file, and JWKS Key ID must be configured"},
		{"MissingAccessTokenTTL", func(c *appConfig.JWTConfig) { c.AccessTokenTTL = 0 }, "access and refresh token TTLs must be configured"},
		{"MissingRefreshTokenTTL", func(c *appConfig.JWTConfig) { c.RefreshTokenTTL = 0 }, "access and refresh token TTLs must be configured"},
		{"MissingIssuer", func(c *appConfig.JWTConfig) { c.Issuer = "" }, "JWT issuer and audience must be configured"},
		{"MissingAudience", func(c *appConfig.JWTConfig) { c.Audience = "" }, "JWT issuer and audience must be configured"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfgCopy := baseCfg
			tc.mutator(&cfgCopy)
			_, err := appSecurity.NewRSATokenManagementService(cfgCopy)
			assert.Error(t, err)
			assert.EqualError(t, err, tc.errMsg)
		})
	}
}

func TestNewRSATokenManagementService_InvalidKeyFiles(t *testing.T) {
	_, pubPathValid := createTestRSAFiles(t, testRSAKeyBits)
	privPathValid, _ := createTestRSAFiles(t, testRSAKeyBits)

	t.Run("NonExistentPrivateKey", func(t *testing.T) {
		cfg := newTestJWTConfigRSA(t, "non_existent_private.pem", pubPathValid)
		_, err := appSecurity.NewRSATokenManagementService(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read RSA private key PEM file")
	})

	t.Run("NonExistentPublicKey", func(t *testing.T) {
		cfg := newTestJWTConfigRSA(t, privPathValid, "non_existent_public.pem")
		_, err := appSecurity.NewRSATokenManagementService(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read RSA public key PEM file")
	})

	t.Run("InvalidPrivateKeyPEM", func(t *testing.T) {
		invalidPEMFile, _ := os.CreateTemp(t.TempDir(), "invalid_private_*.pem")
		invalidPEMFile.WriteString("this is not a valid pem")
		invalidPEMFile.Close()
		cfg := newTestJWTConfigRSA(t, invalidPEMFile.Name(), pubPathValid)
		_, err := appSecurity.NewRSATokenManagementService(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse RSA private key from PEM")
	})
}

func TestGenerateAndValidateAccessToken_RS256_Valid(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, err := appSecurity.NewRSATokenManagementService(cfg)
	require.NoError(t, err)

	userID, username, roles, permissions, sessionID := sampleRSADomainClaims()
	tokenString, generatedClaims, err := tm.GenerateAccessToken(userID, username, roles, permissions, sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)
	require.NotNil(t, generatedClaims)

	// Check kid in header by parsing unverified first
	unverifiedToken, _, errUnverified := new(jwt.Parser).ParseUnverified(tokenString, &service.Claims{})
	require.NoError(t, errUnverified)
	assert.Equal(t, cfg.JWKSKeyID, unverifiedToken.Header["kid"])

	validatedClaims, err := tm.ValidateAccessToken(tokenString)
	require.NoError(t, err)
	require.NotNil(t, validatedClaims)

	assert.Equal(t, userID, validatedClaims.UserID)
	assert.Equal(t, username, validatedClaims.Username)
	assert.ElementsMatch(t, roles, validatedClaims.Roles)
	assert.ElementsMatch(t, permissions, validatedClaims.Permissions)
	assert.Equal(t, sessionID, validatedClaims.SessionID)
	assert.Equal(t, cfg.Issuer, validatedClaims.Issuer)
	assert.Contains(t, validatedClaims.Audience, cfg.Audience)
	assert.WithinDuration(t, time.Now().Add(cfg.AccessTokenTTL), validatedClaims.ExpiresAt.Time, 5*time.Second)
}

func TestValidateAccessToken_RS256_Expired(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	cfg.AccessTokenTTL = 1 * time.Millisecond // Very short TTL
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	userID, username, roles, permissions, sessionID := sampleRSADomainClaims()
	tokenString, _, _ := tm.GenerateAccessToken(userID, username, roles, permissions, sessionID)

	time.Sleep(5 * time.Millisecond) // Ensure token is expired

	_, err := tm.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), jwt.ErrTokenExpired.Error())
}

func TestValidateAccessToken_RS256_NotYetValid(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)
	userID, username, roles, permissions, sessionID := sampleRSADomainClaims()

	// Set time to the future for NBF generation
	futureTime := time.Now().Add(10 * time.Minute)
	jwt.TimeFunc = func() time.Time { return futureTime }

	tokenString, _, _ := tm.GenerateAccessToken(userID, username, roles, permissions, sessionID)

	jwt.TimeFunc = time.Now // Reset time for parsing

	_, err := tm.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), jwt.ErrTokenNotValidYet.Error())
	jwt.TimeFunc = time.Now // Ensure it's reset for other tests
}


func TestValidateAccessToken_RS256_WrongAudience(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	userID, username, roles, permissions, sessionID := sampleRSADomainClaims()
	tokenString, _, _ := tm.GenerateAccessToken(userID, username, roles, permissions, sessionID)

	// Create a new service/config with different audience for validation
	cfgWrongAud := cfg
	cfgWrongAud.Audience = "completely-different-audience"
	tmWrongAud, _ := appSecurity.NewRSATokenManagementService(cfgWrongAud)

	_, err := tmWrongAud.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token has invalid audience")
}

func TestValidateAccessToken_RS256_WrongIssuer(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	userID, username, roles, permissions, sessionID := sampleRSADomainClaims()
	tokenString, _, _ := tm.GenerateAccessToken(userID, username, roles, permissions, sessionID)

	cfgWrongIss := cfg
	cfgWrongIss.Issuer = "completely-different-issuer"
	tmWrongIss, _ := appSecurity.NewRSATokenManagementService(cfgWrongIss)

	_, err := tmWrongIss.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token has invalid issuer")
}

func TestValidateAccessToken_RS256_WrongKID(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	userID, username, roles, permissions, sessionID := sampleRSADomainClaims()
	tokenString, _, _ := tm.GenerateAccessToken(userID, username, roles, permissions, sessionID)

	cfgWrongKID := cfg
	cfgWrongKID.JWKSKeyID = "wrong-kid-for-validation"
	tmWrongKID, _ := appSecurity.NewRSATokenManagementService(cfgWrongKID)

	_, err := tmWrongKID.ValidateAccessToken(tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token 'kid' test-kid-rsa does not match expected wrong-kid-for-validation")
}

func TestValidateAccessToken_RS256_NoKIDInToken(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	userID, username, roles, permissions, sessionID := sampleRSADomainClaims()

	// Manually generate a token without KID
	claims := &service.Claims{
		UserID: userID, Username: username, Roles: roles, Permissions: permissions, SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: cfg.Issuer, Audience: jwt.ClaimStrings{cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.AccessTokenTTL)),
			NotBefore: jwt.NewNumericDate(time.Now()), IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}
	rawToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims) // No KID in header by default here

	// Load private key directly for signing
	privKeyBytes, _ := os.ReadFile(privPath)
	privateKey, _ := jwt.ParseRSAPrivateKeyFromPEM(privKeyBytes)
	tokenStringNoKID, _ := rawToken.SignedString(privateKey)

	// The current ValidateAccessToken implementation allows tokens with no KID if only one key is configured.
	// It might be desirable to make KID mandatory. This test checks current lenient behavior.
	validatedClaims, err := tm.ValidateAccessToken(tokenStringNoKID)
	assert.NoError(t, err, "Validation should pass if KID is absent but signature is valid with the service's key")
	assert.NotNil(t, validatedClaims)
}


func TestValidateAccessToken_RS256_Tampered(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	userID, username, roles, permissions, sessionID := sampleRSADomainClaims()
	tokenString, _, _ := tm.GenerateAccessToken(userID, username, roles, permissions, sessionID)

	parts := strings.Split(tokenString, ".")
	require.Len(t, parts, 3)
	// Tamper the signature part
	tamperedSignature := "tampered" + parts[2]
	tamperedTokenString := fmt.Sprintf("%s.%s.%s", parts[0], parts[1], tamperedSignature)

	_, err := tm.ValidateAccessToken(tamperedTokenString)
	assert.Error(t, err)
	// Error from crypto/rsa verification or jwt library for signature
	assert.Contains(t, err.Error(), "signature is invalid", "Expected signature validation error")
}

func TestGenerateAndValidate2FAChallengeToken_RS256_Valid(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	userID := "user-2fa-challenge"
	tokenString, err := tm.Generate2FAChallengeToken(userID)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	validatedUserID, err := tm.Validate2FAChallengeToken(tokenString)
	require.NoError(t, err)
	assert.Equal(t, userID, validatedUserID)
}

func TestGenerateAndValidateStateJWT_HS256_Valid(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits) // RSA keys not used for state JWTs directly but setup tm
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	stateClaims := &service.OAuthStateClaims{
		ProviderName: "google", CSRFToken: "csrf123",
		RegisteredClaims: jwt.RegisteredClaims{ID: "state-jti"},
	}
	tokenString, err := tm.GenerateStateJWT(stateClaims, cfg.OAuthStateSecret, cfg.OAuthStateCookieTTL)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	validatedClaims, err := tm.ValidateStateJWT(tokenString, cfg.OAuthStateSecret)
	require.NoError(t, err)
	assert.Equal(t, stateClaims.ProviderName, validatedClaims.ProviderName)
	assert.Equal(t, stateClaims.CSRFToken, validatedClaims.CSRFToken)
	assert.Equal(t, stateClaims.ID, validatedClaims.ID)
	assert.WithinDuration(t, time.Now().Add(cfg.OAuthStateCookieTTL), validatedClaims.ExpiresAt.Time, 5*time.Second)
}

func TestValidateStateJWT_HS256_WrongSecret(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	stateClaims := &service.OAuthStateClaims{ProviderName: "google", CSRFToken: "csrf123"}
	tokenString, _ := tm.GenerateStateJWT(stateClaims, cfg.OAuthStateSecret, cfg.OAuthStateCookieTTL)

	_, err := tm.ValidateStateJWT(tokenString, "completely-wrong-hmac-secret")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature is invalid")
}

func TestValidateStateJWT_HS256_Expired(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	stateClaims := &service.OAuthStateClaims{ProviderName: "google", CSRFToken: "csrf123"}
	// Generate with very short TTL
	tokenString, _ := tm.GenerateStateJWT(stateClaims, cfg.OAuthStateSecret, 1*time.Millisecond)

	time.Sleep(5 * time.Millisecond)

	_, err := tm.ValidateStateJWT(tokenString, cfg.OAuthStateSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), jwt.ErrTokenExpired.Error())
}


func TestGetJWKS(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	jwks, err := tm.GetJWKS()
	require.NoError(t, err)
	require.NotNil(t, jwks)
	require.Contains(t, jwks, "keys")

	keysList, ok := jwks["keys"].([]map[string]interface{})
	require.True(t, ok)
	require.Len(t, keysList, 1)

	jwk := keysList[0]
	assert.Equal(t, "RSA", jwk["kty"])
	assert.Equal(t, cfg.JWKSKeyID, jwk["kid"])
	assert.Equal(t, "sig", jwk["use"])
	assert.Equal(t, jwt.SigningMethodRS256.Alg(), jwk["alg"])
	assert.NotEmpty(t, jwk["n"], "Modulus should be present")
	assert.NotEmpty(t, jwk["e"], "Exponent should be present")

	// Verify N and E are correct for the public key
	pubKeyBytes, _ := os.ReadFile(pubPath)
	publicKey, _ := jwt.ParseRSAPublicKeyFromPEM(pubKeyBytes)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()), jwk["n"])
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(rsa.E.Bytes()), jwk["e"]) // Assuming E is standard 65537
}

func TestGenerateRefreshTokenValue(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	val1, err1 := tm.GenerateRefreshTokenValue()
	require.NoError(t, err1)
	assert.NotEmpty(t, val1)
	// Default 32 bytes of entropy -> base64 URL encoded -> 44 chars
	assert.Len(t, val1, 43, "Expected length 43 for 32 byte base64url encoded token (no padding)")


	val2, err2 := tm.GenerateRefreshTokenValue()
	require.NoError(t, err2)
	assert.NotEmpty(t, val2)
	assert.NotEqual(t, val1, val2)
}

func TestGetRefreshTokenExpiry(t *testing.T) {
	privPath, pubPath := createTestRSAFiles(t, testRSAKeyBits)
	cfg := newTestJWTConfigRSA(t, privPath, pubPath)
	tm, _ := appSecurity.NewRSATokenManagementService(cfg)

	assert.Equal(t, cfg.RefreshTokenTTL, tm.GetRefreshTokenExpiry())
}

[end of backend/services/auth-service/internal/infrastructure/security/rsa_jwt_service_test.go]
