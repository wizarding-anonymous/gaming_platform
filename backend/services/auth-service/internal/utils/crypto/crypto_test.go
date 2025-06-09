package crypto_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/crypto"
)

func TestNewEncrypter_ValidKeySizes(t *testing.T) {
	validSizes := []int{16, 24, 32}
	for _, size := range validSizes {
		key := make([]byte, size)
		enc, err := crypto.NewEncrypter(key)
		assert.NoError(t, err, "NewEncrypter should not error for key size %d", size)
		assert.NotNil(t, enc, "Encrypter should not be nil for key size %d", size)
	}
}

func TestNewEncrypter_InvalidKeySizes(t *testing.T) {
	invalidSizes := []int{0, 1, 15, 20, 31, 33, 64}
	expectedError := "ключ шифрования должен быть длиной 16, 24 или 32 байта"
	for _, size := range invalidSizes {
		key := make([]byte, size)
		enc, err := crypto.NewEncrypter(key)
		assert.Error(t, err, "NewEncrypter should error for key size %d", size)
		assert.EqualError(t, err, expectedError, "Error message mismatch for key size %d", size)
		assert.Nil(t, enc, "Encrypter should be nil for invalid key size %d", size)
	}
}

func TestEncryptDecrypt_Bytes(t *testing.T) {
	key, _ := crypto.GenerateKey(32)
	enc, _ := crypto.NewEncrypter(key)
	require.NotNil(t, enc)

	plaintext := []byte("test message for bytes encryption")

	ciphertextBase64, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertextBase64)

	// Check if it's valid base64
	_, err = base64.StdEncoding.DecodeString(ciphertextBase64)
	require.NoError(t, err, "Ciphertext should be valid base64")

	decrypted, err := enc.Decrypt(ciphertextBase64)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "Decrypted plaintext should match original")
}

func TestEncryptDecrypt_String(t *testing.T) {
	key, _ := crypto.GenerateKey(32)
	enc, _ := crypto.NewEncrypter(key)
	require.NotNil(t, enc)

	plaintext := "test message for string encryption"

	ciphertextBase64, err := enc.EncryptString(plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertextBase64)

	_, err = base64.StdEncoding.DecodeString(ciphertextBase64)
	require.NoError(t, err, "Ciphertext should be valid base64")

	decrypted, err := enc.DecryptString(ciphertextBase64)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "Decrypted plaintext should match original")
}

func TestEncrypt_DifferentCiphertextsForSamePlaintext(t *testing.T) {
	key, _ := crypto.GenerateKey(32)
	enc, _ := crypto.NewEncrypter(key)
	require.NotNil(t, enc)

	plaintext := "same message"
	ciphertext1, err1 := enc.EncryptString(plaintext)
	require.NoError(t, err1)
	ciphertext2, err2 := enc.EncryptString(plaintext)
	require.NoError(t, err2)

	assert.NotEmpty(t, ciphertext1)
	assert.NotEmpty(t, ciphertext2)
	assert.NotEqual(t, ciphertext1, ciphertext2, "Ciphertexts for the same plaintext should be different due to random nonce")
}

func TestDecrypt_ErrorOnTamperedCiphertext(t *testing.T) {
	key, _ := crypto.GenerateKey(32)
	enc, _ := crypto.NewEncrypter(key)
	require.NotNil(t, enc)

	plaintext := "message to be tampered"
	ciphertextBase64, err := enc.EncryptString(plaintext)
	require.NoError(t, err)

	// Tamper the base64 ciphertext
	tamperedCiphertextBase64 := ""
	if len(ciphertextBase64) > 1 {
		// Change a character in the middle
		idx := len(ciphertextBase64) / 2
		originalChar := ciphertextBase64[idx]
		tamperedChar := originalChar + 1
		if tamperedChar > 'z' && tamperedChar < 'A' { // simple wrap around, might not always produce valid base64 char
			tamperedChar = 'A'
		} else if tamperedChar > 'Z' && tamperedChar < 'a' {
			tamperedChar = 'a'
		} else if tamperedChar > '9' && tamperedChar < '+' {
			tamperedChar = '+'
		}


		tamperedCiphertextBase64 = ciphertextBase64[:idx] + string(tamperedChar) + ciphertextBase64[idx+1:]
	} else {
		// If too short, make it invalid some other way
		tamperedCiphertextBase64 = ciphertextBase64 + "==" // This might make it invalid if already padded
	}

	// Try to make the tampered version valid base64, but with different content
	decodedTampered, errDecode := base64.StdEncoding.DecodeString(tamperedCiphertextBase64)
	if errDecode != nil { // If tampering made it invalid base64, just use a slightly modified byte slice from original
		decodedOriginal, _ := base64.StdEncoding.DecodeString(ciphertextBase64)
		if len(decodedOriginal) > 0 {
			decodedOriginal[len(decodedOriginal)-1] ^= 0x01 // Flip a bit in the last byte
			tamperedCiphertextBase64 = base64.StdEncoding.EncodeToString(decodedOriginal)
		} else {
			t.Skip("Ciphertext too short to tamper effectively for this test case")
		}
	}


	_, err = enc.DecryptString(tamperedCiphertextBase64)
	assert.Error(t, err, "Decrypt should return an error for tampered ciphertext")
	// AES-GCM typically returns "cipher: message authentication failed"
	assert.Contains(t, err.Error(), "ошибка дешифрования", "Error message should indicate decryption failure")
}

func TestDecrypt_ErrorOnWrongKey(t *testing.T) {
	key1, _ := crypto.GenerateKey(32)
	enc1, _ := crypto.NewEncrypter(key1)
	require.NotNil(t, enc1)

	key2, _ := crypto.GenerateKey(32) // Different key
	enc2, _ := crypto.NewEncrypter(key2)
	require.NotNil(t, enc2)

	plaintext := "message for wrong key test"
	ciphertext, err := enc1.EncryptString(plaintext)
	require.NoError(t, err)

	_, err = enc2.DecryptString(ciphertext)
	assert.Error(t, err, "Decrypt should return an error when using the wrong key")
	assert.Contains(t, err.Error(), "ошибка дешифрования", "Error message should indicate decryption failure")
}

func TestDecrypt_InvalidBase64Ciphertext(t *testing.T) {
	key, _ := crypto.GenerateKey(32)
	enc, _ := crypto.NewEncrypter(key)
	require.NotNil(t, enc)

	invalidBase64 := "!!!not base64!!!"
	_, err := enc.DecryptString(invalidBase64)
	assert.Error(t, err, "Decrypt should return an error for invalid base64 ciphertext")
	assert.Contains(t, err.Error(), "ошибка декодирования base64", "Error message should indicate base64 decoding error")
}

func TestDecrypt_CiphertextTooShort(t *testing.T) {
	key, _ := crypto.GenerateKey(32)
	enc, _ := crypto.NewEncrypter(key)
	require.NotNil(t, enc)

	// GCM nonce is typically 12 bytes. A base64 string that decodes to less than that.
	// "short" decodes to 4 bytes. "shorttext" decodes to 8 bytes.
	shortCiphertextBase64 := base64.StdEncoding.EncodeToString([]byte("short"))

	_, err := enc.DecryptString(shortCiphertextBase64)
	assert.Error(t, err, "Decrypt should return an error for ciphertext shorter than nonce size")
	assert.EqualError(t, err, "шифротекст слишком короткий")
}

func TestGenerateKey_ValidSizes(t *testing.T) {
	validSizes := []int{16, 24, 32}
	for _, size := range validSizes {
		key, err := crypto.GenerateKey(size)
		assert.NoError(t, err, "GenerateKey should not error for size %d", size)
		assert.Len(t, key, size, "Generated key should have length %d", size)

		key2, err2 := crypto.GenerateKey(size)
		assert.NoError(t, err2)
		assert.NotEqual(t, key, key2, "Subsequent calls to GenerateKey should produce different keys for size %d", size)
	}
}

func TestGenerateKey_InvalidSize(t *testing.T) {
	invalidSizes := []int{0, 1, 15, 33}
	expectedError := "размер ключа должен быть 16, 24 или 32 байта"
	for _, size := range invalidSizes {
		key, err := crypto.GenerateKey(size)
		assert.Error(t, err, "GenerateKey should error for size %d", size)
		assert.EqualError(t, err, expectedError)
		assert.Nil(t, key)
	}
}

func TestGenerateKeyString_ValidSizes(t *testing.T) {
	validSizes := []int{16, 24, 32}
	for _, size := range validSizes {
		keyStr, err := crypto.GenerateKeyString(size)
		assert.NoError(t, err, "GenerateKeyString should not error for size %d", size)
		assert.NotEmpty(t, keyStr)

		decodedKey, errDecode := base64.StdEncoding.DecodeString(keyStr)
		assert.NoError(t, errDecode, "Generated key string should be valid base64")
		assert.Len(t, decodedKey, size, "Decoded key string should have length %d", size)
	}
}

func TestParseKeyString_Valid(t *testing.T) {
	originalKey, _ := crypto.GenerateKey(32)
	keyStr := base64.StdEncoding.EncodeToString(originalKey)

	parsedKey, err := crypto.ParseKeyString(keyStr)
	assert.NoError(t, err)
	assert.True(t, bytes.Equal(originalKey, parsedKey), "Parsed key should match original key")
}

func TestParseKeyString_InvalidBase64(t *testing.T) {
	invalidBase64Str := "!!!not base64!!!"
	key, err := crypto.ParseKeyString(invalidBase64Str)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ошибка декодирования ключа", "Error message should indicate base64 decoding error for key")
	assert.Nil(t, key)
}

func TestParseKeyString_InvalidKeyLengthAfterDecode(t *testing.T) {
	// Valid base64, but decodes to an invalid key length (e.g., 10 bytes)
	invalidLengthKeyStr := base64.StdEncoding.EncodeToString([]byte("0123456789")) // 10 bytes
	expectedError := "размер ключа должен быть 16, 24 или 32 байта"

	key, err := crypto.ParseKeyString(invalidLengthKeyStr)
	assert.Error(t, err)
	assert.EqualError(t, err, expectedError)
	assert.Nil(t, key)
}

// Helper to get GCM nonce size for more precise short ciphertext test
func getGCMNonceSize(t *testing.T) int {
	dummyKey := make([]byte, 16)
	block, err := aes.NewCipher(dummyKey)
	require.NoError(t, err)
	aesGCM, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return aesGCM.NonceSize()
}

func TestDecrypt_CiphertextExactlyNonceSize(t *testing.T) {
    key, _ := crypto.GenerateKey(32)
    enc, _ := crypto.NewEncrypter(key)
    require.NotNil(t, enc)

    nonceSize := getGCMNonceSize(t)
    shortCiphertextBytes := make([]byte, nonceSize)
    // Fill with some data, doesn't matter what for this length check
    for i := 0; i < nonceSize; i++ { shortCiphertextBytes[i] = byte(i) }

    shortCiphertextBase64 := base64.StdEncoding.EncodeToString(shortCiphertextBytes)

    // Decrypting a message that is only a nonce (no actual ciphertext part) should fail.
    // The aesGCM.Open call will fail.
    _, err := enc.DecryptString(shortCiphertextBase64)
    assert.Error(t, err, "Decrypt should error if ciphertext is only nonce and no actual data")
    assert.Contains(t, err.Error(), "ошибка дешифрования", "Error message should indicate decryption failure")
}
