package totp_test

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/totp"
)

func TestDefaultConfig(t *testing.T) {
	config := totp.DefaultConfig()
	assert.Equal(t, "RussianSteam", config.Issuer)
	assert.Equal(t, uint(30), config.Period)
	assert.Equal(t, otp.DigitsSix, config.Digits)
	assert.Equal(t, uint(1), config.Skew)
}

func TestGenerateSecret(t *testing.T) {
	secret1, err1 := totp.GenerateSecret()
	require.NoError(t, err1)
	assert.NotEmpty(t, secret1, "Generated secret should not be empty")

	// Assert valid base32 (unpadded)
	// Try decoding. StdEncoding.WithPadding(NoPadding) should handle it.
	decodedSecret1, errDecode1 := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret1)
	require.NoError(t, errDecode1, "Generated secret should be valid base32")
	assert.Len(t, decodedSecret1, 20, "Decoded secret should be 20 bytes long")

	// Check for base32 character set (A-Z, 2-7) and no padding
	assert.NotContains(t, secret1, "=", "Generated secret should not contain padding characters")
	for _, r := range secret1 {
		isUpperAlpha := r >= 'A' && r <= 'Z'
		isDigit27 := r >= '2' && r <= '7'
		assert.True(t, isUpperAlpha || isDigit27, "Character '%c' not in base32 set", r)
	}


	secret2, err2 := totp.GenerateSecret()
	require.NoError(t, err2)
	assert.NotEmpty(t, secret2)
	assert.NotEqual(t, secret1, secret2, "Subsequent calls should generate different secrets")
}

func TestGenerateQRCodeURL(t *testing.T) {
	username := "testuser@example.com"
	secret, _ := totp.GenerateSecret() // This is unpadded
	config := totp.DefaultConfig()

	qrURLString := totp.GenerateQRCodeURL(username, secret, config)
	require.NotEmpty(t, qrURLString)

	parsedURL, err := url.Parse(qrURLString)
	require.NoError(t, err, "Generated QR code URL should be valid")

	assert.Equal(t, "otpauth", parsedURL.Scheme)
	assert.Equal(t, "totp", parsedURL.Host)

	expectedPath := fmt.Sprintf("/%s:%s", url.PathEscape(config.Issuer), url.PathEscape(username))
	assert.Equal(t, expectedPath, parsedURL.Path)

	queryParams := parsedURL.Query()
	assert.Equal(t, config.Issuer, queryParams.Get("issuer"))
	assert.Equal(t, fmt.Sprintf("%d", config.Period), queryParams.Get("period"))
	assert.Equal(t, "SHA1", queryParams.Get("algorithm")) // Hardcoded in implementation
	assert.Equal(t, fmt.Sprintf("%d", config.Digits), queryParams.Get("digits"))

	// Check secret in URL is padded if it was unpadded
	urlSecret := queryParams.Get("secret")
	require.NotEmpty(t, urlSecret)
	if len(urlSecret)%8 != 0 { // If not multiple of 8, must end with padding
		assert.True(t, strings.HasSuffix(urlSecret, "="), "Secret in URL should be padded if needed")
	}
	// And it should decode to the same as the original unpadded secret (after original is also padded for comparison)
	originalPaddedSecret := secret
	if !strings.HasSuffix(originalPaddedSecret, "=") {
		padding := 8 - (len(originalPaddedSecret) % 8)
		if padding < 8 {
			originalPaddedSecret = originalPaddedSecret + strings.Repeat("=", padding)
		}
	}
	assert.Equal(t, originalPaddedSecret, urlSecret)


	// Test with custom config
	customConfig := &totp.Config{
		Issuer: "MyCustomApp",
		Period: 60,
		Digits: otp.DigitsEight,
	}
	usernameCustom := "custom_user"
	secretCustom, _ := totp.GenerateSecret()
	qrURLStringCustom := totp.GenerateQRCodeURL(usernameCustom, secretCustom, customConfig)
	parsedURLCustom, _ := url.Parse(qrURLStringCustom)
	assert.Equal(t, customConfig.Issuer, parsedURLCustom.Query().Get("issuer"))
	assert.Equal(t, fmt.Sprintf("%d", customConfig.Period), parsedURLCustom.Query().Get("period"))
	assert.Equal(t, fmt.Sprintf("%d", customConfig.Digits), parsedURLCustom.Query().Get("digits"))
	assert.Contains(t, parsedURLCustom.Path, url.PathEscape(customConfig.Issuer))
	assert.Contains(t, parsedURLCustom.Path, url.PathEscape(usernameCustom))
}

func TestGenerateAndValidateCode_Valid(t *testing.T) {
	config := totp.DefaultConfig()
	secret, _ := totp.GenerateSecret() // Unpadded

	code, err := totp.GenerateCode(secret, config)
	require.NoError(t, err)
	assert.NotEmpty(t, code)
	assert.Len(t, code, int(config.Digits))

	valid, err := totp.ValidateCode(code, secret, config)
	require.NoError(t, err)
	assert.True(t, valid, "Generated code should be valid immediately")
}

func TestValidateCode_InvalidCode(t *testing.T) {
	config := totp.DefaultConfig()
	secret, _ := totp.GenerateSecret()

	invalidCode := "000000"
	if int(config.Digits) == 8 {
		invalidCode = "00000000"
	}

	valid, err := totp.ValidateCode(invalidCode, secret, config)
	require.NoError(t, err) // Validate itself shouldn't error for a wrong code, just return false
	assert.False(t, valid, "An incorrect code should not validate")
}

func TestValidateCode_ExpiredCode_And_Skew(t *testing.T) {
	config := totp.DefaultConfig() // Period 30s, Skew 1
	secret, _ := totp.GenerateSecret()

	now := time.Now()

	// Helper to generate code for a specific time
	generateCodeAtTime := func(secOffset int) string {
		code, err := totp.GenerateCodeCustom(
			secret,
			now.Add(time.Duration(secOffset)*time.Second),
			totp.ValidateOpts{
				Period:    config.Period,
				Digits:    config.Digits,
				Algorithm: otp.AlgorithmSHA1, // Match default
			},
		)
		require.NoError(t, err)
		return code
	}

	// Validate with current time `now`
	validate := func(code string, expected bool, msg string) {
		valid, err := totp.ValidateCustom(
			code,
			secret, // ValidateCode will pad this internally
			now,
			totp.ValidateOpts{
				Period:    config.Period,
				Skew:      config.Skew,
				Digits:    config.Digits,
				Algorithm: otp.AlgorithmSHA1,
			},
		)
		require.NoError(t, err)
		assert.Equal(t, expected, valid, msg)
	}

	// Current window
	codeNow := generateCodeAtTime(0)
	validate(codeNow, true, "Code from current window should be valid")

	// Previous window (within skew)
	codePrev := generateCodeAtTime(int(-config.Period))
	validate(codePrev, true, "Code from previous window (within skew) should be valid")

	// Next window (within skew)
	codeNext := generateCodeAtTime(int(config.Period))
	validate(codeNext, true, "Code from next window (within skew) should be valid")

	// Too old (outside skew: current - period * (skew+1) )
	// Example: Period 30, Skew 1. Too old is current - 30 * 2 = current - 60s.
	// Code generated at -60s from now.
	codeTooOld := generateCodeAtTime(int(-config.Period * (config.Skew + 1)))
	validate(codeTooOld, false, "Code from window too old (outside skew) should be invalid")

	// Also test just beyond the edge
	codeJustTooOld := generateCodeAtTime(int(-config.Period*(config.Skew+1) - 1))
	validate(codeJustTooOld, false, "Code from window just too old (outside skew) should be invalid")


	// Too new (outside skew: current + period * (skew+1) )
	// Code generated at +60s from now.
	codeTooNew := generateCodeAtTime(int(config.Period * (config.Skew + 1)))
	// When validating "too new" codes, the `pquerna/otp` library's `ValidateCustom`
	// considers future codes within the skew window from the *validation time*.
	// A code generated for T+60, when validated at T, is 2 periods away.
	// If skew is 1, it allows T-30, T, T+30. So T+60 is outside this.
	validate(codeTooNew, false, "Code from window too new (outside skew) should be invalid")

	codeJustTooNew := generateCodeAtTime(int(config.Period*(config.Skew+1) + 1))
	validate(codeJustTooNew, false, "Code from window just too new (outside skew) should be invalid")
}


func TestValidateCode_SecretPadding(t *testing.T) {
	config := totp.DefaultConfig()

	// 1. Test with a secret generated by our GenerateSecret (which is unpadded)
	unpaddedSecret1, _ := totp.GenerateSecret()
	code1, _ := totp.GenerateCode(unpaddedSecret1, config)
	valid1, err1 := totp.ValidateCode(code1, unpaddedSecret1, config)
	require.NoError(t, err1)
	assert.True(t, valid1, "Should validate with unpadded secret from GenerateSecret")

	// 2. Test with a manually created unpadded secret string that would require padding
	// A 16-char base32 string (decodes to 10 bytes) would need 4 padding chars.
	// Example: "JBSWY3DPEHPK3PXP" (unpadded) -> "JBSWY3DPEHPK3PXP====" (padded)
	// Let's use a string that's not a multiple of 8.
	// The `GenerateSecret` already produces unpadded strings. We need to ensure the functions
	// that *use* the secret (GenerateCode, ValidateCode, GenerateQRCodeURL) correctly pad it.
	// The functions in totp.go *do* have padding logic. This test confirms it.

	// Example raw bytes that will result in an unpadded base32 string not multiple of 8
	rawSecretBytes := []byte("123456789012345") // 15 bytes
	unpaddedSecret2 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawSecretBytes)
	assert.False(t, strings.HasSuffix(unpaddedSecret2, "="), "Manual unpadded secret should not have padding")

	code2, errGen2 := totp.GenerateCode(unpaddedSecret2, config)
	require.NoError(t, errGen2, "GenerateCode should work with manually unpadded secret due to internal padding")

	valid2, errVal2 := totp.ValidateCode(code2, unpaddedSecret2, config)
	require.NoError(t, errVal2, "ValidateCode should work with manually unpadded secret due to internal padding")
	assert.True(t, valid2, "Should validate with manually created unpadded secret")
}


func TestGenerateCode_CustomConfig(t *testing.T) {
	secret, _ := totp.GenerateSecret()

	customConfig := &totp.Config{
		Issuer:  "MyTestApp",
		Period:  60,
		Digits:  otp.DigitsEight,
		Skew:    0, // No skew for this test
	}

	// Generate code with custom config
	codeCustom, errCustom := totp.GenerateCode(secret, customConfig)
	require.NoError(t, errCustom)
	assert.Len(t, codeCustom, 8, "Code should have 8 digits as per custom config")

	// Validate with the same custom config - should be true
	validCustom, errValCustom := totp.ValidateCode(codeCustom, secret, customConfig)
	require.NoError(t, errValCustom)
	assert.True(t, validCustom, "Code should be valid with the same custom config")

	// Validate with default config - should be false (different period/digits)
	validDefault, errValDefault := totp.ValidateCode(codeCustom, secret, totp.DefaultConfig())
	// It might error if digits don't match expectation of validation func, or just return false.
	// pquerna/otp ValidateCustom will likely just return false if the code doesn't match any window.
	if errValDefault != nil {
		// This would be unusual, as Validate typically returns true/false based on match.
		t.Logf("Validation with default config returned error: %v (this might be ok if digits mismatch causes parse error)", errValDefault)
		assert.False(t, validDefault) // Ensure it's false anyway
	} else {
		assert.False(t, validDefault, "Code generated with custom config should not be valid with default config")
	}
}
[end of backend/services/auth-service/internal/utils/totp/totp_test.go]
