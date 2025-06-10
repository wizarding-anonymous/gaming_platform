// File: backend/services/auth-service/internal/utils/jwt/jwt_test.go
package jwt_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	jwtUtil "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/jwt"
)

const (
	testSecret = "test-jwt-secret-key-for-unit-tests"
	testIssuer = "test-auth-service"
)

func newTestJWTConfig() *config.JWTConfig {
	return &config.JWTConfig{
		SecretKey:       testSecret,
		AccessTokenTTL:  15,     // minutes
		RefreshTokenTTL: 24 * 7, // hours
		EmailVerificationToken: config.TokenConfig{
			ExpiresIn: 24, // hours
		},
		PasswordResetToken: config.TokenConfig{
			ExpiresIn: 1, // hour
		},
		Issuer: testIssuer,
	}
}

func sampleUser() *models.User {
	return &models.User{
		ID:       "user-id-123",
		Username: "testuser",
		Email:    "test@example.com",
		Roles: []models.Role{
			{Name: "player"},
			{Name: "tester"},
		},
	}
}

func TestNewTokenManager(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)
	assert.NotNil(t, tm)
}

func TestGenerateAndParseAccessToken_Valid(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)
	user := sampleUser()
	sessionID := "session-id-abc"

	tokenString, err := tm.GenerateAccessToken(user, sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	claims, err := tm.ParseAccessToken(tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.Username, claims.Username)
	assert.Equal(t, user.Email, claims.Email)
	assert.ElementsMatch(t, []string{"player", "tester"}, claims.Roles)
	assert.Equal(t, string(jwtUtil.AccessToken), claims.TokenType)
	assert.Equal(t, user.ID, claims.Subject)
	assert.Equal(t, sessionID, claims.ID)
	assert.Equal(t, testIssuer, claims.Issuer)
	assert.WithinDuration(t, time.Now().Add(cfg.AccessTokenTTL*time.Minute), claims.ExpiresAt.Time, 5*time.Second)
	assert.WithinDuration(t, time.Now(), claims.IssuedAt.Time, 5*time.Second)
	assert.WithinDuration(t, time.Now(), claims.NotBefore.Time, 5*time.Second)
}

func TestGenerateAndParseRefreshToken_Valid(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)
	userID := "user-id-456"
	sessionID := "session-id-xyz"

	tokenString, err := tm.GenerateRefreshToken(userID, sessionID)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	claims, err := tm.ParseRefreshToken(tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, string(jwtUtil.RefreshToken), claims.TokenType)
	assert.Equal(t, userID, claims.Subject)
	assert.Equal(t, sessionID, claims.ID)
	assert.Equal(t, testIssuer, claims.Issuer)
	assert.WithinDuration(t, time.Now().Add(cfg.RefreshTokenTTL*time.Hour), claims.ExpiresAt.Time, 5*time.Second)
}

func TestGenerateAndParseEmailVerificationToken_Valid(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)
	userID := "user-id-ev"
	email := "verify@example.com"

	tokenString, err := tm.GenerateEmailVerificationToken(userID, email)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	claims, err := tm.ParseEmailVerificationToken(tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, string(jwtUtil.EmailVerificationToken), claims.TokenType)
	assert.Equal(t, userID, claims.Subject)
	assert.Equal(t, testIssuer, claims.Issuer)
	assert.WithinDuration(t, time.Now().Add(cfg.EmailVerificationToken.ExpiresIn*time.Hour), claims.ExpiresAt.Time, 5*time.Second)
}

func TestGenerateAndParsePasswordResetToken_Valid(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)
	userID := "user-id-pr"
	email := "reset@example.com"

	tokenString, err := tm.GeneratePasswordResetToken(userID, email)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	claims, err := tm.ParsePasswordResetToken(tokenString)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, string(jwtUtil.PasswordResetToken), claims.TokenType)
	assert.Equal(t, userID, claims.Subject)
	assert.Equal(t, testIssuer, claims.Issuer)
	assert.WithinDuration(t, time.Now().Add(cfg.PasswordResetToken.ExpiresIn*time.Hour), claims.ExpiresAt.Time, 5*time.Second)
}

func TestParseAccessToken_Expired(t *testing.T) {
	cfg := newTestJWTConfig()
	cfg.AccessTokenTTL = -1 // Expires 1 minute ago
	tm := jwtUtil.NewTokenManager(cfg)
	user := sampleUser()

	tokenString, err := tm.GenerateAccessToken(user, "session-exp")
	require.NoError(t, err)

	// Need to ensure that "now" for parsing is actually after the original "exp"
	// Even with TTL -1, if parsing happens immediately, clock skew or precision might matter.
	// A small sleep can help, but better to use jwt.TimeFunc if it were a problem.
	// For negative TTL, it's already expired relative to its own IAT.

	_, err = tm.ParseAccessToken(tokenString)
	assert.ErrorIs(t, err, jwtUtil.ErrExpiredToken)
}

func TestParseAccessToken_NotYetValid(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)
	user := sampleUser()

	// Freeze time for token generation to a point in the past
	pastTime := time.Now().Add(-10 * time.Minute)
	jwt.TimeFunc = func() time.Time {
		return pastTime
	}
	// Generate token - its 'nbf' and 'iat' will be `pastTime`
	// Its 'exp' will be `pastTime + AccessTokenTTL`
	tokenString, err := tm.GenerateAccessToken(user, "session-nbf")
	require.NoError(t, err)

	// Reset time to normal for parsing
	jwt.TimeFunc = time.Now

	// Now, modify the NBF claim in the generated token to be in the future for parsing.
	// This is complex as it requires decoding, modifying, and re-signing, or finding a way
	// to make GenerateAccessToken use a future NBF.
	// The current GenerateAccessToken sets NBF to time.Now() (which was `pastTime`).
	// So, if we parse it now (current real time), it *should* be valid past its NBF.

	// To properly test NBF, we need to make NBF be in the future relative to current parsing time.
	// Let's try to make the token's NBF be current time + 5 minutes when it's generated.
	// This means when we parse it *immediately*, it's not yet valid.

	futureNBFTime := time.Now().Add(5 * time.Minute)
	jwt.TimeFunc = func() time.Time {
		// For generation, "now" is such that NBF will be set to this futureNBFTime.
		// This is a bit of a hack, as NBF is set to "now" by the generation func.
		// So, we set "now" to be the future NBF time.
		return futureNBFTime
	}

	// Generate token. Its 'nbf' and 'iat' will be `futureNBFTime`.
	// 'exp' will be `futureNBFTime + AccessTokenTTL`.
	tokenWithFutureNBF, errGenerate := tm.GenerateAccessToken(user, "session-nbf-future")
	require.NoError(t, errGenerate)

	// Reset time to normal for parsing. Now, the token's NBF is in the future.
	jwt.TimeFunc = time.Now

	_, errParse := tm.ParseAccessToken(tokenWithFutureNBF)
	assert.ErrorIs(t, errParse, jwtUtil.ErrTokenNotYetValid)

	// Cleanup global time function
	jwt.TimeFunc = time.Now
}

func TestParseAccessToken_WrongSecret(t *testing.T) {
	cfg1 := newTestJWTConfig()
	tm1 := jwtUtil.NewTokenManager(cfg1)
	user := sampleUser()

	tokenString, err := tm1.GenerateAccessToken(user, "session-wrongsec")
	require.NoError(t, err)

	cfg2 := newTestJWTConfig()
	cfg2.SecretKey = "a-completely-different-secret-key-shhh"
	tm2 := jwtUtil.NewTokenManager(cfg2)

	_, err = tm2.ParseAccessToken(tokenString)
	assert.Error(t, err)
	assert.ErrorIs(t, err, jwtUtil.ErrInvalidToken) // Underlying error is likely signature invalid
	assert.Contains(t, err.Error(), "signature is invalid", "Error message should mention signature issue")
}

func TestParseAccessToken_InvalidSigningMethod(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)

	// Craft a token with a non-HS256 signing method in its header.
	// Example: Use SigningMethodNone for simplicity, though not recommended.
	// This only tests if the parsing function's keyFunc rejects based on method,
	// not a full non-HMAC signature validation.
	claims := &jwtUtil.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "test"},
		TokenType:        string(jwtUtil.AccessToken),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType) // Sign with "none"
	require.NoError(t, err)

	// Modify header to claim a different alg if necessary, though SigningMethodNone often sets "alg":"none"
	parts := strings.Split(tokenString, ".")
	require.Len(t, parts, 3, "JWT should have 3 parts")

	// Create a header claiming RS256 but body/sig is HS256 or None
	header := `{"alg":"RS256","typ":"JWT"}`
	badTokenString := fmt.Sprintf("%s.%s.%s", base64.RawURLEncoding.EncodeToString([]byte(header)), parts[1], parts[2])

	_, err = tm.ParseAccessToken(badTokenString)
	assert.ErrorIs(t, err, jwtUtil.ErrInvalidSigningMethod)
}

func TestParseAccessToken_WrongTokenTypeInClaim(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)

	// Generate a refresh token
	refreshTokenString, err := tm.GenerateRefreshToken("user-id-wrongtype", "session-wrongtype")
	require.NoError(t, err)

	// Attempt to parse it as an access token
	_, err = tm.ParseAccessToken(refreshTokenString)
	assert.Error(t, err)
	assert.ErrorIs(t, err, jwtUtil.ErrInvalidToken)
	assert.Contains(t, err.Error(), "invalid token type")
}

func TestParseToken_Generic_SuccessfulForAllTypes(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)
	user := sampleUser()

	// Access Token
	accessTokenStr, _ := tm.GenerateAccessToken(user, "s1")
	claims, err := tm.ParseToken(accessTokenStr)
	require.NoError(t, err)
	ac, ok := claims.(*jwtUtil.AccessTokenClaims)
	require.True(t, ok)
	assert.Equal(t, string(jwtUtil.AccessToken), ac.TokenType)
	assert.Equal(t, user.ID, ac.UserID)

	// Refresh Token
	refreshTokenStr, _ := tm.GenerateRefreshToken(user.ID, "s2")
	claims, err = tm.ParseToken(refreshTokenStr)
	require.NoError(t, err)
	rc, ok := claims.(*jwtUtil.RefreshTokenClaims)
	require.True(t, ok)
	assert.Equal(t, string(jwtUtil.RefreshToken), rc.TokenType)
	assert.Equal(t, user.ID, rc.UserID)

	// Email Verification Token
	emailTokenStr, _ := tm.GenerateEmailVerificationToken(user.ID, user.Email)
	claims, err = tm.ParseToken(emailTokenStr)
	require.NoError(t, err)
	ec, ok := claims.(*jwtUtil.EmailVerificationClaims)
	require.True(t, ok)
	assert.Equal(t, string(jwtUtil.EmailVerificationToken), ec.TokenType)
	assert.Equal(t, user.ID, ec.UserID)

	// Password Reset Token
	passwordTokenStr, _ := tm.GeneratePasswordResetToken(user.ID, user.Email)
	claims, err = tm.ParseToken(passwordTokenStr)
	require.NoError(t, err)
	pc, ok := claims.(*jwtUtil.PasswordResetClaims)
	require.True(t, ok)
	assert.Equal(t, string(jwtUtil.PasswordResetToken), pc.TokenType)
	assert.Equal(t, user.ID, pc.UserID)
}

func TestParseToken_Generic_InvalidToken(t *testing.T) {
	cfg := newTestJWTConfig()
	tm := jwtUtil.NewTokenManager(cfg)
	malformedToken := "this.is.not.a.jwt"

	_, err := tm.ParseToken(malformedToken)
	assert.Error(t, err)
	assert.ErrorIs(t, err, jwtUtil.ErrInvalidToken)
}

func TestParseToken_Generic_Expired(t *testing.T) {
	cfg := newTestJWTConfig()
	cfg.AccessTokenTTL = -1 // Expired
	tm := jwtUtil.NewTokenManager(cfg)
	user := sampleUser()

	expiredTokenStr, _ := tm.GenerateAccessToken(user, "s-exp")
	_, err := tm.ParseToken(expiredTokenStr)
	assert.ErrorIs(t, err, jwtUtil.ErrExpiredToken)
}

func TestGetRoleNames(t *testing.T) {
	// Test with a slice of models.Role
	roles := []models.Role{
		{Name: "admin"},
		{Name: "user"},
		{Name: "editor"},
	}
	// This function is unexported. To test it, we'd typically call it via an exported function
	// that uses it, or make it part of a testable struct.
	// For this exercise, assuming we can call it (e.g. by moving it to this test file or making it public).
	// If getRoleNames is truly private and only used by GenerateAccessToken, its effect is tested
	// in TestGenerateAndParseAccessToken_Valid via checking claims.Roles.

	// Let's simulate its usage as seen in GenerateAccessToken
	tm := jwtUtil.NewTokenManager(newTestJWTConfig())
	userWithRoles := &models.User{Roles: roles}
	tokenString, err := tm.GenerateAccessToken(userWithRoles, "s-roles")
	require.NoError(t, err)
	parsedClaims, err := tm.ParseAccessToken(tokenString)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "user", "editor"}, parsedClaims.Roles)

	// Test with empty slice
	userWithEmptyRoles := &models.User{Roles: []models.Role{}}
	tokenStringEmpty, errEmpty := tm.GenerateAccessToken(userWithEmptyRoles, "s-empty-roles")
	require.NoError(t, errEmpty)
	parsedClaimsEmpty, errEmptyParse := tm.ParseAccessToken(tokenStringEmpty)
	require.NoError(t, errEmptyParse)
	assert.Empty(t, parsedClaimsEmpty.Roles)

	// Test with nil slice
	userWithNilRoles := &models.User{Roles: nil}
	tokenStringNil, errNil := tm.GenerateAccessToken(userWithNilRoles, "s-nil-roles")
	require.NoError(t, errNil)
	parsedClaimsNil, errNilParse := tm.ParseAccessToken(tokenStringNil)
	require.NoError(t, errNilParse)
	// Depending on implementation of getRoleNames, nil might result in nil or empty slice.
	// The current getRoleNames will produce an empty slice for nil input.
	assert.Empty(t, parsedClaimsNil.Roles)
}
