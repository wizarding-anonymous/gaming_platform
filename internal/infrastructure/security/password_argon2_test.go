// File: internal/infrastructure/security/password_argon2_test.go
package security

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Default test parameters for Argon2id, can be overridden in specific tests if needed.
var defaultTestParams = Argon2idParams{
	Memory:      64 * 1024, // 64MB
	Iterations:  1,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

func TestArgon2idPasswordService_HashPassword(t *testing.T) {
	service, err := NewArgon2idPasswordService(defaultTestParams)
	require.NoError(t, err, "NewArgon2idPasswordService should not error with default params")

	password := "testpassword123"
	hashedPassword, err := service.HashPassword(password)
	require.NoError(t, err, "HashPassword should not return an error")

	t.Logf("Generated hash: %s", hashedPassword)

	// Verify hash format: $argon2id$v=19$m=...,t=...,p=...$salt$key
	assert.True(t, strings.HasPrefix(hashedPassword, "$argon2id$"), "Hash should start with $argon2id$ prefix")
	parts := strings.Split(hashedPassword, "$")
	require.Len(t, parts, 6, "Hash should have 6 parts separated by $")

	assert.Equal(t, "v=19", parts[2], "Argon2 version should be 19")

	// Check for m, t, p parameters (existence and basic format)
	paramPart := parts[3]
	assert.True(t, strings.HasPrefix(paramPart, "m="), "Params should contain memory (m)")
	assert.True(t, strings.Contains(paramPart, ",t="), "Params should contain iterations (t)")
	assert.True(t, strings.Contains(paramPart, ",p="), "Params should contain parallelism (p)")

	// Check if salt and key parts are present and not empty
	assert.NotEmpty(t, parts[4], "Salt part should not be empty")
	assert.NotEmpty(t, parts[5], "Key part should not be empty")

	// Further check: try to hash the same password again, should produce a different hash due to different salt
	hashedPassword2, err2 := service.HashPassword(password)
	require.NoError(t, err2)
	assert.NotEqual(t, hashedPassword, hashedPassword2, "Hashing the same password twice should produce different hashes (due to salt)")
}

func TestArgon2idPasswordService_CheckPasswordHash_Success(t *testing.T) {
	service, _ := NewArgon2idPasswordService(defaultTestParams)
	password := "correcthorsebatterystaple"

	hashedPassword, err := service.HashPassword(password)
	require.NoError(t, err)

	match, err := service.CheckPasswordHash(password, hashedPassword)
	assert.NoError(t, err, "CheckPasswordHash should not error on success")
	assert.True(t, match, "Password should match the hash")
}

func TestArgon2idPasswordService_CheckPasswordHash_Failure_WrongPassword(t *testing.T) {
	service, _ := NewArgon2idPasswordService(defaultTestParams)
	password := "correcthorsebatterystaple"
	wrongPassword := "incorrecthorsebatterystaple"

	hashedPassword, err := service.HashPassword(password)
	require.NoError(t, err)

	match, err := service.CheckPasswordHash(wrongPassword, hashedPassword)
	assert.NoError(t, err, "CheckPasswordHash should not error on wrong password, only return false")
	assert.False(t, match, "Wrong password should not match the hash")
}

func TestArgon2idPasswordService_CheckPasswordHash_Failure_InvalidHashFormat(t *testing.T) {
	service, _ := NewArgon2idPasswordService(defaultTestParams)
	password := "testpassword"

	invalidHashes := []struct {
		name string
		hash string
		errContains string // Substring of expected error message
	}{
		{"empty hash", "", "invalid hash format"},
		{"too few parts", "$argon2id$v=19$m=65536,t=1,p=2$salt", "invalid hash format"},
		{"no version", "$argon2id$m=65536,t=1,p=2$salt$key", "invalid hash format"},
		{"invalid version", "$argon2id$v=18$m=65536,t=1,p=2$salt$key", "incompatible version"},
		{"missing params", "$argon2id$v=19$salt$key", "invalid hash format"},
		{"malformed params m", "$argon2id$v=19$mx=65536,t=1,p=2$salt$key", "failed to parse parameters"},
		{"malformed params t", "$argon2id$v=19$m=65536,tx=1,p=2$salt$key", "failed to parse parameters"},
		{"malformed params p", "$argon2id$v=19$m=65536,t=1,px=2$salt$key", "failed to parse parameters"},
		{"non-base64 salt", "$argon2id$v=19$m=65536,t=1,p=2$!!!$key", "failed to decode salt"},
		{"non-base64 key", "$argon2id$v=19$m=65536,t=1,p=2$c2FsdA==$!!!", "failed to decode key"},
		{"short salt (if validation exists)", "$argon2id$v=19$m=65536,t=1,p=2$c2E=$key", "failed to decode salt"}, // "sa" -> c2E=
	}

	for _, tc := range invalidHashes {
		t.Run(tc.name, func(t *testing.T) {
			match, err := service.CheckPasswordHash(password, tc.hash)
			assert.Error(t, err, "CheckPasswordHash should error with invalid hash '%s'", tc.hash)
			if tc.errContains != "" {
				assert.Contains(t, err.Error(), tc.errContains, "Error message mismatch for hash '%s'", tc.hash)
			}
			assert.False(t, match, "Match should be false on error for hash '%s'", tc.hash)
		})
	}
}

func TestArgon2idPasswordService_WithDifferentValidParams(t *testing.T) {
	params := []Argon2idParams{
		{Memory: 32 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32},
		{Memory: 128 * 1024, Iterations: 1, Parallelism: 4, SaltLength: 32, KeyLength: 64},
	}
	password := "supersecurepassword"

	for i, p := range params {
		t.Run(fmt.Sprintf("ParamsSet%d", i+1), func(t *testing.T) {
			service, err := NewArgon2idPasswordService(p)
			require.NoError(t, err, "NewArgon2idPasswordService should not error")

			hashedPassword, err := service.HashPassword(password)
			require.NoError(t, err, "HashPassword should not error")

			// Verify format again, focusing on parameter reflection if possible (though format string doesn't show actual values easily)
			assert.True(t, strings.HasPrefix(hashedPassword, "$argon2id$"), "Hash should start with $argon2id$ prefix")
			parts := strings.Split(hashedPassword, "$")
			require.Len(t, parts, 6)
			assert.Equal(t, "v=19", parts[2])

			// Check that the parameters m, t, p are present in the hash string
			// Example: $argon2id$v=19$m=32768,t=2,p=1$salt_base64$key_base64
			// We can check if the m, t, p values from the hash string match the input params
			var m, iter uint32
			var para uint8
			// Note: The standard library's argon2.IDKey doesn't directly expose a way to parse these back from the string easily.
			// We are checking that CheckPasswordHash works with these parameters.
			// A more direct check of params in hash string would require manual parsing of parts[3].
			// For now, we assume the hash embeds them correctly if CheckPasswordHash works.

			// Check successful verification
			match, err := service.CheckPasswordHash(password, hashedPassword)
			assert.NoError(t, err, "CheckPasswordHash should not error on success")
			assert.True(t, match, "Password should match the hash with current params")

			// Check failure with wrong password
			match, err = service.CheckPasswordHash("wrong"+password, hashedPassword)
			assert.NoError(t, err, "CheckPasswordHash should not error on wrong password")
			assert.False(t, match, "Wrong password should not match the hash with current params")
		})
	}
}

func TestNewArgon2idPasswordService_InvalidParams(t *testing.T) {
	invalidParams := []struct {
		name   string
		params Argon2idParams
		errContains string
	}{
		{"zero memory", Argon2idParams{Memory: 0, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}, "memory parameter must be greater than 0"},
		{"zero iterations", Argon2idParams{Memory: 64*1024, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32}, "iterations parameter must be greater than 0"},
		{"zero parallelism", Argon2idParams{Memory: 64*1024, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32}, "parallelism parameter must be greater than 0"},
		{"short salt", Argon2idParams{Memory: 64*1024, Iterations: 1, Parallelism: 1, SaltLength: 7, KeyLength: 32}, "salt length parameter must be at least 8"},
		{"short key", Argon2idParams{Memory: 64*1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 7}, "key length parameter must be at least 8"},
	}

	for _, tc := range invalidParams {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewArgon2idPasswordService(tc.params)
			assert.Error(t, err)
			if tc.errContains != "" {
				assert.Contains(t, err.Error(), tc.errContains)
			}
		})
	}
}
