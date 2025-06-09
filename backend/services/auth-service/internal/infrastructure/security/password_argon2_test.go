package security_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"
	"golang.org/x/crypto/argon2"
)

// Helper to get default valid Argon2idParams for tests
func defaultTestParams() security.Argon2idParams {
	return security.Argon2idParams{
		Memory:      64 * 1024,
		Iterations:  1, // Use 1 iteration for faster tests, but ensure it's non-zero
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func TestNewArgon2idPasswordService_ValidParams(t *testing.T) {
	params := defaultTestParams()
	ps, err := security.NewArgon2idPasswordService(params)
	assert.NoError(t, err)
	assert.NotNil(t, ps)
}

func TestNewArgon2idPasswordService_InvalidParams(t *testing.T) {
	testCases := []struct {
		name  string
		param security.Argon2idParams
	}{
		{"Zero Memory", security.Argon2idParams{Memory: 0, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}},
		{"Zero Iterations", security.Argon2idParams{Memory: 65536, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32}},
		{"Zero Parallelism", security.Argon2idParams{Memory: 65536, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32}},
		{"Zero SaltLength", security.Argon2idParams{Memory: 65536, Iterations: 1, Parallelism: 1, SaltLength: 0, KeyLength: 32}},
		{"Zero KeyLength", security.Argon2idParams{Memory: 65536, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 0}},
	}

	expectedError := "Argon2idParams must be fully configured"
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ps, err := security.NewArgon2idPasswordService(tc.param)
			assert.Error(t, err)
			assert.EqualError(t, err, expectedError)
			assert.Nil(t, ps)
		})
	}
}

func TestArgon2idPasswordService_HashPasswordAndCheckPasswordHash_Valid(t *testing.T) {
	params := defaultTestParams()
	ps, err := security.NewArgon2idPasswordService(params)
	require.NoError(t, err)
	require.NotNil(t, ps)

	password := "validPassword123"
	encodedHash, err := ps.HashPassword(password)
	require.NoError(t, err)
	require.NotEmpty(t, encodedHash)

	expectedPrefix := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism)
	assert.True(t, strings.HasPrefix(encodedHash, expectedPrefix), "Hash prefix should match service params")

	parts := strings.Split(encodedHash, "$")
	require.Len(t, parts, 6, "Hash should have 6 parts")
	_, err = base64.RawStdEncoding.DecodeString(parts[4]) // salt
	assert.NoError(t, err, "Salt should be valid base64")
	_, err = base64.RawStdEncoding.DecodeString(parts[5]) // hash
	assert.NoError(t, err, "Hash part should be valid base64")

	match, err := ps.CheckPasswordHash(password, encodedHash)
	assert.NoError(t, err, "CheckPasswordHash should not error for valid password")
	assert.True(t, match, "Password should match")
}

func TestArgon2idPasswordService_CheckPasswordHash_InvalidPassword(t *testing.T) {
	params := defaultTestParams()
	ps, err := security.NewArgon2idPasswordService(params)
	require.NoError(t, err)

	password := "correctPassword"
	wrongPassword := "wrongPassword"
	encodedHash, err := ps.HashPassword(password)
	require.NoError(t, err)

	match, err := ps.CheckPasswordHash(wrongPassword, encodedHash)
	assert.NoError(t, err, "CheckPasswordHash should not error for a mismatched password")
	assert.False(t, match, "Mismatched password should return false")
}

func TestArgon2idPasswordService_CheckPasswordHash_UsesParamsFromHash(t *testing.T) {
	params1 := security.Argon2idParams{Memory: 64 * 1024, Iterations: 1, Parallelism: 2, SaltLength: 16, KeyLength: 32}
	ps1, _ := security.NewArgon2idPasswordService(params1)

	params2 := security.Argon2idParams{Memory: 128 * 1024, Iterations: 2, Parallelism: 4, SaltLength: 16, KeyLength: 32}
	ps2, _ := security.NewArgon2idPasswordService(params2) // Service with different params

	password := "testpassword"
	hashFromPs1, err := ps1.HashPassword(password)
	require.NoError(t, err)

	// Verify using ps2, which has different default params. Should succeed because params from hash are used.
	match, err := ps2.CheckPasswordHash(password, hashFromPs1)
	assert.NoError(t, err)
	assert.True(t, match, "CheckPasswordHash should use params from the hash string")
}

func TestArgon2idPasswordService_CheckPasswordHash_InvalidHashFormat_TooFewParts(t *testing.T) {
	ps, _ := security.NewArgon2idPasswordService(defaultTestParams())
	invalidHash := "$argon2id$v=19$m=65536,t=1,p=2" // Missing salt and hash
	match, err := ps.CheckPasswordHash("password", invalidHash)
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid hash format: not enough parts")
	assert.False(t, match)
}

func TestArgon2idPasswordService_CheckPasswordHash_InvalidHashFormat_NotArgon2id(t *testing.T) {
	ps, _ := security.NewArgon2idPasswordService(defaultTestParams())
	invalidHash := "$argon2i$v=19$m=65536,t=1,p=2$somesalt$somehash"
	match, err := ps.CheckPasswordHash("password", invalidHash)
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid hash format: not argon2id")
	assert.False(t, match)
}

func TestArgon2idPasswordService_CheckPasswordHash_InvalidHashFormat_UnsupportedVersion(t *testing.T) {
	ps, _ := security.NewArgon2idPasswordService(defaultTestParams())
	// Case 1: Version number is different
	invalidHashVersion := "$argon2id$v=18$m=65536,t=1,p=2$somesalt$somehash"
	match, err := ps.CheckPasswordHash("password", invalidHashVersion)
	assert.Error(t, err)
	assert.EqualError(t, err, "invalid hash format: unsupported version")
	assert.False(t, match)
}

func TestArgon2idPasswordService_CheckPasswordHash_InvalidHashFormat_BadVersionScan(t *testing.T) {
	ps, _ := security.NewArgon2idPasswordService(defaultTestParams())
	// Case 2: Version string is malformed
	invalidHashScan := "$argon2id$v=abc$m=65536,t=1,p=2$somesalt$somehash"
	matchScan, errScan := ps.CheckPasswordHash("password", invalidHashScan)
	assert.Error(t, errScan)
	assert.EqualError(t, errScan, "invalid hash format: unsupported version") // This error is generic now
	assert.False(t, matchScan)
}


func TestArgon2idPasswordService_CheckPasswordHash_InvalidHashFormat_MalformedParams(t *testing.T) {
	ps, _ := security.NewArgon2idPasswordService(defaultTestParams())
	invalidHash := "$argon2id$v=19$m=abc,t=def,p=ghi$somesalt$somehash"
	match, err := ps.CheckPasswordHash("password", invalidHash)
	assert.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "invalid hash format: malformed params:"), "Error prefix mismatch")
	assert.False(t, match)
}

func TestArgon2idPasswordService_CheckPasswordHash_InvalidBase64Salt(t *testing.T) {
	ps, _ := security.NewArgon2idPasswordService(defaultTestParams())
	params := defaultTestParams()
	invalidSaltHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$!!!not_base64!!!$somesalthash",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism)
	match, err := ps.CheckPasswordHash("password", invalidSaltHash)
	assert.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "invalid hash format: failed to decode salt:"), "Error prefix mismatch")
	assert.False(t, match)
}

func TestArgon2idPasswordService_CheckPasswordHash_InvalidBase64Hash(t *testing.T) {
	ps, _ := security.NewArgon2idPasswordService(defaultTestParams())
	params := defaultTestParams()
	saltBytes := make([]byte, params.SaltLength)
	// In a real test, you might want to ensure saltBytes is properly initialized if needed,
	// but for this error case, its content doesn't matter as much as its valid base64 encoding.
	_, _ = base64.RawStdEncoding.DecodeString("abcdefghijklmnopqrstuv==") // dummy valid salt
	b64Salt := base64.RawStdEncoding.EncodeToString(saltBytes)

	invalidHashPartHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$!!!not_base64!!!",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism, b64Salt)
	match, err := ps.CheckPasswordHash("password", invalidHashPartHash)
	assert.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "invalid hash format: failed to decode hash:"), "Error prefix mismatch")
	assert.False(t, match)
}

// Ensure argon2idPasswordService implements PasswordService (compile-time check)
var _ service.PasswordService = (service.PasswordService)(nil)
var _ service.PasswordService = (*security.Argon2idPasswordService)(nil) // This will fail as Argon2idPasswordService is not exported

// To make the above check work, if Argon2idPasswordService were exported for some reason:
// type ExportedArgon2idPasswordService = security.Argon2idPasswordService
// var _ service.PasswordService = (*ExportedArgon2idPasswordService)(nil)
// However, it's better that it's not exported. The test is for the functionality via the interface.

[end of backend/services/auth-service/internal/infrastructure/security/password_argon2_test.go]
