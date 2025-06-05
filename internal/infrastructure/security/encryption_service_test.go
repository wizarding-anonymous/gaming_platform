// File: internal/infrastructure/security/encryption_service_test.go
package security

import (
	"crypto/aes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAESGCMEncryptionService_EncryptDecrypt_RoundTrip tests successful encryption and decryption.
func TestAESGCMEncryptionService_EncryptDecrypt_RoundTrip(t *testing.T) {
	service := NewAESGCMEncryptionService() // Assuming a constructor if it exists, or direct use.
	// If aesGCMEncryptionService is a struct with methods, instantiate it:
	// service := aesGCMEncryptionService{}

	plaintext := "This is a super secret message!"
	// Must be a 32-byte key for AES-256, hex encoded (64 hex characters)
	keyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // Example 32-byte key

	ciphertext, err := service.Encrypt(plaintext, keyHex)
	require.NoError(t, err, "Encryption should not fail with valid key and plaintext")
	assert.NotEmpty(t, ciphertext, "Ciphertext should not be empty")
	assert.NotEqual(t, plaintext, ciphertext, "Ciphertext should be different from plaintext")

	decryptedText, err := service.Decrypt(ciphertext, keyHex)
	require.NoError(t, err, "Decryption should not fail with correct key and ciphertext")
	assert.Equal(t, plaintext, decryptedText, "Decrypted text should match original plaintext")
}

// TestAESGCMEncryptionService_Decrypt_WrongKey tests decryption failure with an incorrect key.
func TestAESGCMEncryptionService_Decrypt_WrongKey(t *testing.T) {
	service := NewAESGCMEncryptionService()
	plaintext := "Another secret message."
	keyHex1 := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	keyHex2 := "101112131415161718191a1b1c1d1e0f000102030405060708090a0b0c0d0e0f" // Different key

	ciphertext, err := service.Encrypt(plaintext, keyHex1)
	require.NoError(t, err)

	_, err = service.Decrypt(ciphertext, keyHex2)
	assert.Error(t, err, "Decryption should fail with the wrong key")
	// Specific error for GCM auth failure is "cipher: message authentication failed"
	assert.Contains(t, err.Error(), "message authentication failed", "Error should indicate authentication failure")
}

// TestAESGCMEncryptionService_Decrypt_CorruptedCiphertext tests decryption failure with tampered ciphertext.
func TestAESGCMEncryptionService_Decrypt_CorruptedCiphertext(t *testing.T) {
	service := NewAESGCMEncryptionService()
	plaintext := "Sensitive data."
	keyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

	ciphertext, err := service.Encrypt(plaintext, keyHex)
	require.NoError(t, err)

	// Corrupt the ciphertext (e.g., flip a bit or change a character)
	// Ciphertext is base64 encoded, so decode, corrupt, re-encode, or just change a char in base64.
	// Changing a char in base64 is simpler for test.
	corruptedCiphertext := ""
	if len(ciphertext) > 1 {
		// Change last character
		if ciphertext[len(ciphertext)-1] == 'A' {
			corruptedCiphertext = ciphertext[:len(ciphertext)-1] + "B"
		} else {
			corruptedCiphertext = ciphertext[:len(ciphertext)-1] + "A"
		}
	} else {
		corruptedCiphertext = ciphertext + "corruption" // If too short, just append
	}

	if ciphertext == corruptedCiphertext && len(ciphertext) > 1 {
		// This can happen if the last char was 'A' and became 'B', or vice-versa, and original was short.
		// Try a different corruption.
		corruptedCiphertext = "corrupted" + ciphertext
	}
	require.NotEqual(t, ciphertext, corruptedCiphertext, "Ciphertext should be corrupted for this test")


	_, err = service.Decrypt(corruptedCiphertext, keyHex)
	assert.Error(t, err, "Decryption should fail with corrupted ciphertext")
	// Error could be "cipher: message authentication failed" or "illegal base64 data" depending on corruption
	// For simple char change in base64, it might be auth failed.
	// If corruption makes it invalid base64, then it's a decode error before GCM.
}

// TestAESGCMEncryptionService_InvalidKey tests behavior with invalid keys.
func TestAESGCMEncryptionService_InvalidKey(t *testing.T) {
	service := NewAESGCMEncryptionService()
	plaintext := "Test data"

	invalidKeys := []struct {
		name   string
		keyHex string
		errContains string
	}{
		{"empty key", "", "failed to decode hex key"},
		{"short key hex", "00010203", "failed to decode hex key: encoding/hex: odd length hex string"}, // or specific length error from AES
		{"short key bytes", hex.EncodeToString([]byte("shortkey")), "crypto/aes: invalid key size 8"}, // AES needs 16, 24, or 32 bytes
		{"long key bytes", hex.EncodeToString([]byte("averylongkeythatisnot32bytesexactly")), "crypto/aes: invalid key size 36"},
		{"not hex", "not-a-hex-string", "failed to decode hex key: encoding/hex: invalid byte"},
	}

	for _, tc := range invalidKeys {
		t.Run(tc.name+"_Encrypt", func(t *testing.T) {
			_, err := service.Encrypt(plaintext, tc.keyHex)
			assert.Error(t, err)
			if tc.errContains != "" {
				assert.Contains(t, err.Error(), tc.errContains)
			}
		})
		t.Run(tc.name+"_Decrypt", func(t *testing.T) {
			// Decrypt needs some ciphertext; encrypt with a valid key first
			validKeyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
			validCiphertext, _ := service.Encrypt(plaintext, validKeyHex)

			_, err := service.Decrypt(validCiphertext, tc.keyHex)
			assert.Error(t, err)
			if tc.errContains != "" {
				assert.Contains(t, err.Error(), tc.errContains)
			}
		})
	}
}

// TestAESGCMEncryptionService_EmptyPlaintext tests encryption/decryption of empty string.
func TestAESGCMEncryptionService_EmptyPlaintext(t *testing.T) {
	service := NewAESGCMEncryptionService()
	keyHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	plaintext := ""

	ciphertext, err := service.Encrypt(plaintext, keyHex)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext, "Ciphertext for empty string should not be empty (due to nonce, auth tag)")

	decryptedText, err := service.Decrypt(ciphertext, keyHex)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decryptedText, "Decrypted empty string should match original")
}
