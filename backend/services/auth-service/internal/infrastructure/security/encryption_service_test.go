// File: internal/infrastructure/security/encryption_service_test.go
package security_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security"
)

// generateTestHexKey creates a 32-byte AES key and returns its hex encoding.
func generateTestHexKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32) // AES-256 requires 32-byte key
	_, err := rand.Read(key)
	require.NoError(t, err)
	return hex.EncodeToString(key)
}

func TestNewAESGCMEncryptionService(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	assert.NotNil(t, service, "NewAESGCMEncryptionService should return a non-nil service instance")
}

func TestEncryptDecrypt_Valid(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	keyHex := generateTestHexKey(t)
	plaintext := "This is a top secret message!"

	ciphertextBase64, err := service.Encrypt(plaintext, keyHex)
	require.NoError(t, err, "Encryption should not fail with a valid key and plaintext")
	require.NotEmpty(t, ciphertextBase64, "Ciphertext should not be empty")

	// Verify it's valid base64
	_, err = base64.StdEncoding.DecodeString(ciphertextBase64)
	require.NoError(t, err, "Ciphertext should be a valid base64 string")

	decryptedText, err := service.Decrypt(ciphertextBase64, keyHex)
	require.NoError(t, err, "Decryption should not fail with the correct key and valid ciphertext")
	assert.Equal(t, plaintext, decryptedText, "Decrypted text should match the original plaintext")
}

func TestEncrypt_DifferentCiphertextsForSamePlaintext(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	keyHex := generateTestHexKey(t)
	plaintext := "Encrypt this multiple times"

	ciphertext1, err1 := service.Encrypt(plaintext, keyHex)
	require.NoError(t, err1)
	ciphertext2, err2 := service.Encrypt(plaintext, keyHex)
	require.NoError(t, err2)

	assert.NotEmpty(t, ciphertext1)
	assert.NotEmpty(t, ciphertext2)
	assert.NotEqual(t, ciphertext1, ciphertext2, "Two ciphertexts for the same plaintext should be different due to random nonce")
}

func TestEncrypt_InvalidKey_NotHex(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	invalidKeyHex := "this-is-not-hex"
	plaintext := "test"

	_, err := service.Encrypt(plaintext, invalidKeyHex)
	assert.Error(t, err, "Encrypt should fail if key is not valid hex")
	assert.Contains(t, err.Error(), "failed to decode hex key", "Error message should indicate hex decoding failure")
}

func TestEncrypt_InvalidKey_WrongLength(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	// 16-byte key (32 hex chars), but service expects 32-byte key (64 hex chars)
	shortKeyHex := hex.EncodeToString(make([]byte, 16))
	plaintext := "test"

	_, err := service.Encrypt(plaintext, shortKeyHex)
	assert.Error(t, err, "Encrypt should fail if key length is not 32 bytes")
	assert.EqualError(t, err, "invalid key length: must be 32 bytes for AES-256")

	// 33-byte key (66 hex chars)
	longKeyHex := hex.EncodeToString(make([]byte, 33))
	_, err = service.Encrypt(plaintext, longKeyHex)
	assert.Error(t, err, "Encrypt should fail if key length is not 32 bytes")
	assert.EqualError(t, err, "invalid key length: must be 32 bytes for AES-256")
}

func TestDecrypt_InvalidKey_NotHex(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	invalidKeyHex := "this-is-not-hex"
	ciphertext := "dummyCiphertext" // Content doesn't matter as key parsing fails first

	_, err := service.Decrypt(ciphertext, invalidKeyHex)
	assert.Error(t, err, "Decrypt should fail if key is not valid hex")
	assert.Contains(t, err.Error(), "failed to decode hex key")
}

func TestDecrypt_InvalidKey_WrongLength(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	shortKeyHex := hex.EncodeToString(make([]byte, 16)) // 16-byte key
	ciphertext := "dummyCiphertext"

	_, err := service.Decrypt(ciphertext, shortKeyHex)
	assert.Error(t, err, "Decrypt should fail if key length is not 32 bytes")
	assert.EqualError(t, err, "invalid key length: must be 32 bytes for AES-256")
}

func TestDecrypt_InvalidCiphertext_NotBase64(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	keyHex := generateTestHexKey(t)
	invalidCiphertext := "!!! This is not base64 !!!"

	_, err := service.Decrypt(invalidCiphertext, keyHex)
	assert.Error(t, err, "Decrypt should fail if ciphertext is not valid base64")
	assert.Contains(t, err.Error(), "failed to decode base64 ciphertext")
}

func TestDecrypt_InvalidCiphertext_TooShort(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	keyHex := generateTestHexKey(t)

	// GCM standard nonce size is 12 bytes. A ciphertext shorter than this is invalid.
	// Create a byte slice shorter than 12 (e.g., 8 bytes) and base64 encode it.
	shortData := make([]byte, 8)
	_, _ = rand.Read(shortData)
	shortCiphertextBase64 := base64.StdEncoding.EncodeToString(shortData)

	_, err := service.Decrypt(shortCiphertextBase64, keyHex)
	assert.Error(t, err, "Decrypt should fail if decoded ciphertext is shorter than nonce size")
	assert.EqualError(t, err, "ciphertext too short to contain nonce")
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	keyHex := generateTestHexKey(t)
	plaintext := "A message to be tampered with."

	ciphertextBase64, err := service.Encrypt(plaintext, keyHex)
	require.NoError(t, err)

	decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	require.NoError(t, err)

	// Tamper a byte (e.g., the last byte, likely part of the GCM tag or actual ciphertext)
	require.True(t, len(decodedCiphertext) > 0, "Decoded ciphertext should not be empty")
	originalByte := decodedCiphertext[len(decodedCiphertext)-1]
	decodedCiphertext[len(decodedCiphertext)-1] = originalByte ^ 0xAA // Flip some bits

	tamperedCiphertextBase64 := base64.StdEncoding.EncodeToString(decodedCiphertext)

	_, err = service.Decrypt(tamperedCiphertextBase64, keyHex)
	assert.Error(t, err, "Decrypt should fail for tampered ciphertext")
	// Error from gcm.Open is typically "cipher: message authentication failed"
	assert.Contains(t, err.Error(), "failed to decrypt", "Error message should indicate decryption/authentication failure")
	assert.Contains(t, err.Error(), "message authentication failed", "Underlying error should be authentication failure")
}

func TestDecrypt_WrongKey(t *testing.T) {
	service := security.NewAESGCMEncryptionService()
	keyHex1 := generateTestHexKey(t)
	keyHex2 := generateTestHexKey(t) // Generate a different key
	require.NotEqual(t, keyHex1, keyHex2)

	plaintext := "Encrypt with key1, decrypt with key2"
	ciphertextBase64, err := service.Encrypt(plaintext, keyHex1)
	require.NoError(t, err)

	_, err = service.Decrypt(ciphertextBase64, keyHex2)
	assert.Error(t, err, "Decrypt should fail when using the wrong key")
	assert.Contains(t, err.Error(), "failed to decrypt", "Error message should indicate decryption/authentication failure")
	assert.Contains(t, err.Error(), "message authentication failed", "Underlying error should be authentication failure")
}

[end of backend/services/auth-service/internal/infrastructure/security/encryption_service_test.go]
