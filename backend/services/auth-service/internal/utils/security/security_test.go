package security_test

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/security"
	"golang.org/x/crypto/argon2"
)

func TestDefaultArgon2Params(t *testing.T) {
	params := security.DefaultArgon2Params()
	assert.Equal(t, uint32(64*1024), params.Memory, "Default memory should be 64KB")
	assert.Equal(t, uint32(3), params.Iterations, "Default iterations should be 3")
	assert.Equal(t, uint8(4), params.Parallelism, "Default parallelism should be 4")
	assert.Equal(t, uint32(16), params.SaltLength, "Default salt length should be 16")
	assert.Equal(t, uint32(32), params.KeyLength, "Default key length should be 32")
}

func TestGeneratePasswordAndVerifyPassword_Valid(t *testing.T) {
	password := "validpassword123"
	params := security.DefaultArgon2Params()

	encodedHash, err := security.GeneratePassword(password, params)
	require.NoError(t, err, "GeneratePassword should not return an error")
	require.NotEmpty(t, encodedHash, "Encoded hash should not be empty")

	// Expected format: $argon2id$v=19$m=65536,t=3,p=4$[salt]$[hash]
	expectedPrefix := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism)
	assert.True(t, strings.HasPrefix(encodedHash, expectedPrefix), "Hash should have the correct prefix and parameters")

	parts := strings.Split(encodedHash, "$")
	require.Len(t, parts, 6, "Hash should have 6 parts separated by $")
	_, err = base64.RawStdEncoding.DecodeString(parts[4])
	assert.NoError(t, err, "Salt part should be valid base64")
	_, err = base64.RawStdEncoding.DecodeString(parts[5])
	assert.NoError(t, err, "Hash part should be valid base64")

	match, err := security.VerifyPassword(password, encodedHash)
	assert.NoError(t, err, "VerifyPassword should not return an error for a valid password and hash")
	assert.True(t, match, "Password should match the hash")
}

func TestVerifyPassword_InvalidPassword(t *testing.T) {
	password := "validpassword123"
	wrongPassword := "invalidpasswordXYZ"
	params := security.DefaultArgon2Params()

	encodedHash, err := security.GeneratePassword(password, params)
	require.NoError(t, err)

	match, err := security.VerifyPassword(wrongPassword, encodedHash)
	assert.NoError(t, err, "VerifyPassword should not return an error for an invalid password")
	assert.False(t, match, "Incorrect password should not match the hash")
}

func TestVerifyPassword_InvalidHashFormat_TooFewParts(t *testing.T) {
	invalidHash := "$argon2id$v=19$m=65536,t=3,p=4$somesalt" // Missing hash part
	match, err := security.VerifyPassword("password", invalidHash)
	assert.Error(t, err, "VerifyPassword should return an error for too few parts")
	assert.EqualError(t, err, "invalid hash format")
	assert.False(t, match)
}

func TestVerifyPassword_InvalidHashFormat_UnsupportedAlgorithm(t *testing.T) {
	invalidHash := "$argon2i$v=19$m=65536,t=3,p=4$somesalt$somehash"
	match, err := security.VerifyPassword("password", invalidHash)
	assert.Error(t, err, "VerifyPassword should return an error for unsupported algorithm")
	assert.EqualError(t, err, "unsupported algorithm: argon2i")
	assert.False(t, match)
}

func TestVerifyPassword_InvalidHashFormat_VersionMismatch(t *testing.T) {
	invalidHash := "$argon2id$v=18$m=65536,t=3,p=4$somesalt$somehash" // argon2.Version is 19
	match, err := security.VerifyPassword("password", invalidHash)
	assert.Error(t, err, "VerifyPassword should return an error for version mismatch")
	assert.EqualError(t, err, "incompatible version: 18")
	assert.False(t, match)
}

func TestVerifyPassword_InvalidHashFormat_BadVersionString(t *testing.T) {
	invalidHash := "$argon2id$v=abc$m=65536,t=3,p=4$somesalt$somehash"
	match, err := security.VerifyPassword("password", invalidHash)
	assert.Error(t, err, "VerifyPassword should return an error for bad version string")
	// The error comes from fmt.Sscanf
	assert.Contains(t, err.Error(), "input error for specifier", "Error message should indicate sscanf failure")
	assert.False(t, match)
}


func TestVerifyPassword_InvalidHashFormat_BadParamsString(t *testing.T) {
	invalidHash := "$argon2id$v=19$m=abc,t=def,p=ghi$somesalt$somehash"
	match, err := security.VerifyPassword("password", invalidHash)
	assert.Error(t, err, "VerifyPassword should return an error for bad params string")
	// The error comes from fmt.Sscanf
	assert.Contains(t, err.Error(), "input error for specifier", "Error message should indicate sscanf failure")
	assert.False(t, match)
}

func TestVerifyPassword_InvalidHashFormat_MissingParams(t *testing.T) {
    // Example: missing 't' parameter
    invalidHash := "$argon2id$v=19$m=65536,p=4$somesalt$somehash"
    match, err := security.VerifyPassword("password", invalidHash)
    assert.Error(t, err, "VerifyPassword should return an error for missing params")
    assert.Contains(t, err.Error(), "input error for specifier", "Error message should indicate sscanf failure for params")
    assert.False(t, match)
}


func TestVerifyPassword_InvalidBase64Salt(t *testing.T) {
	params := security.DefaultArgon2Params()
	invalidSaltHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$!!!not_base64!!!$somesalthash",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism)
	match, err := security.VerifyPassword("password", invalidSaltHash)
	assert.Error(t, err, "VerifyPassword should return an error for invalid base64 salt")
	assert.IsType(t, base64.CorruptInputError(0), err.(base64.CorruptInputError), "Error should be a base64.CorruptInputError")
	assert.False(t, match)
}

func TestVerifyPassword_InvalidBase64Hash(t *testing.T) {
	params := security.DefaultArgon2Params()
	// Generate a valid salt to use
	saltBytes := make([]byte, params.SaltLength)
	_, _ = base64.RawStdEncoding.DecodeString("abcdefghijklmnopqrstuv==") // dummy valid salt
	rand.Read(saltBytes)
	b64Salt := base64.RawStdEncoding.EncodeToString(saltBytes)

	invalidHashPartHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$!!!not_base64!!!",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism, b64Salt)
	match, err := security.VerifyPassword("password", invalidHashPartHash)
	assert.Error(t, err, "VerifyPassword should return an error for invalid base64 hash")
	assert.IsType(t, base64.CorruptInputError(0), err.(base64.CorruptInputError), "Error should be a base64.CorruptInputError")
	assert.False(t, match)
}

func TestGeneratePassword_CustomParams(t *testing.T) {
	password := "customparamspass"
	customParams := &security.Argon2Params{
		Memory:      128 * 1024, // 128MB
		Iterations:  4,
		Parallelism: 2,
		SaltLength:  20,
		KeyLength:   40,
	}

	encodedHash, err := security.GeneratePassword(password, customParams)
	require.NoError(t, err)
	require.NotEmpty(t, encodedHash)

	expectedFormat := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$",
		argon2.Version, customParams.Memory, customParams.Iterations, customParams.Parallelism)
	assert.True(t, strings.HasPrefix(encodedHash, expectedFormat), "Hash should reflect custom parameters in its prefix")

	parts := strings.Split(encodedHash, "$")
	require.Len(t, parts, 6)
	salt, errSalt := base64.RawStdEncoding.DecodeString(parts[4])
	require.NoError(t, errSalt)
	assert.Len(t, salt, int(customParams.SaltLength), "Salt length should match custom parameter")

	key, errKey := base64.RawStdEncoding.DecodeString(parts[5])
	require.NoError(t, errKey)
	assert.Len(t, key, int(customParams.KeyLength), "Key length should match custom parameter")


	match, err := security.VerifyPassword(password, encodedHash)
	assert.NoError(t, err)
	assert.True(t, match, "Password should verify correctly with custom parameters hash")
}

func TestGenerateRandomToken_CorrectLengthAndFormat(t *testing.T) {
	lengthsToTest := []int{16, 32, 64, 5, 10} // Test various lengths, including non-multiples of 3/4

	for _, length := range lengthsToTest {
		t.Run(fmt.Sprintf("Length%d", length), func(t *testing.T) {
			token, err := security.GenerateRandomToken(length)
			require.NoError(t, err, "GenerateRandomToken should not return an error")
			require.NotEmpty(t, token, "Token should not be empty for length > 0 (unless length is very small and base64 encoding results in empty after truncation, which is not the case here for length > 0)")

			assert.Len(t, token, length, "Token length should be exactly as requested due to truncation")

			// Check if the token is valid base64 URL encoding *for its current (potentially truncated) length*.
			// A truncated base64 string might not be decodable if cut at a wrong spot.
			// The current implementation truncates, so we can only check if the characters are valid base64 URL chars.
			// A more robust test for "valid base64" would require the original length before truncation
			// to be a multiple that results in no padding, or handle padding.
			// Given the truncation, we'll check character set.
			isBase64URL := regexp.MustCompile(`^[A-Za-z0-9_-]*$`).MatchString
			assert.True(t, isBase64URL(token), "Token should contain only base64 URL characters")

			// Attempt to decode the (potentially truncated) token. This might fail if truncated.
			// This is more a test of the implication of truncation.
			_, errDecode := base64.URLEncoding.DecodeString(tokenPaddedForDecoding(token))
			if errDecode != nil {
				// This is expected if length is not a multiple of 4 for base64.
				// E.g. if token is "abc", DecodeString needs "abc=" or "ab=="
				t.Logf("Note: Decoding of truncated token of length %d failed as expected for some lengths: %v", length, errDecode)
			}
		})
	}
}

// Helper to add padding for base64 decoding, as truncated strings might lack it.
func tokenPaddedForDecoding(token string) string {
	if m := len(token) % 4; m != 0 {
		token += strings.Repeat("=", 4-m)
	}
	return token
}


func TestGenerateRandomToken_ZeroLength(t *testing.T) {
	token, err := security.GenerateRandomToken(0)
	require.NoError(t, err)
	assert.Empty(t, token, "Token should be empty for length 0")
}

func TestGenerateRandomToken_DifferentTokens(t *testing.T) {
	token1, err1 := security.GenerateRandomToken(32)
	require.NoError(t, err1)
	token2, err2 := security.GenerateRandomToken(32)
	require.NoError(t, err2)

	assert.NotEmpty(t, token1)
	assert.NotEmpty(t, token2)
	assert.NotEqual(t, token1, token2, "Multiple calls to GenerateRandomToken should produce different tokens")
}

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"No special chars", "hello world", "hello world"},
		{"Angle brackets", "<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{"Quotes", "He said \"hello\" and 'bye'", "He said &quot;hello&quot; and &#39;bye&#39;"},
		{"Semicolon", "test; value", "test&#59; value"},
		{"Parentheses", "func(arg)", "func&#40;arg&#41;"},
		{"Mixed", "<hello value=\"test\"> (do this;)", "&lt;hello value=&quot;test&quot;&gt; &#40;do this&#59;&#41;"},
		{"Empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized := security.SanitizeInput(tt.input)
			assert.Equal(t, tt.expected, sanitized)
		})
	}
}

[end of backend/services/auth-service/internal/utils/security/security_test.go]
