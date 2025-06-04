package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// EncryptionService defines methods for encrypting and decrypting data.
type EncryptionService interface {
	// Encrypt takes plaintext and a hex-encoded key, returns base64-encoded ciphertext.
	Encrypt(plainText string, keyHex string) (string, error)
	// Decrypt takes base64-encoded ciphertext and a hex-encoded key, returns plaintext.
	Decrypt(cipherTextBase64 string, keyHex string) (string, error)
}

// aesGCMEncryptionService implements EncryptionService using AES-GCM.
type aesGCMEncryptionService struct{}

// NewAESGCMEncryptionService creates a new instance of aesGCMEncryptionService.
func NewAESGCMEncryptionService() EncryptionService {
	return &aesGCMEncryptionService{}
}

// Encrypt encrypts plaintext using AES-256-GCM.
// keyHex is the 32-byte key, hex-encoded (64 characters).
// Output is base64 encoded: nonce + ciphertext + tag.
func (s *aesGCMEncryptionService) Encrypt(plainText string, keyHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex key: %w", err)
	}
	if len(key) != 32 { // AES-256 requires a 32-byte key
		return "", errors.New("invalid key length: must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Generate a random nonce. GCM standard nonce size is 12 bytes.
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data. The GCM Seal method prepends the nonce to the ciphertext if nonce is first arg.
	// However, it's common practice to manage nonce separately or prepend it explicitly for clarity.
	// We will prepend nonce: nonce + ciphertext + tag
	cipherText := gcm.Seal(nil, nonce, []byte(plainText), nil)

	// Prepend nonce to the ciphertext
	nonceAndCiphertext := append(nonce, cipherText...)

	return base64.StdEncoding.EncodeToString(nonceAndCiphertext), nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
// cipherTextBase64 is the base64 encoded (nonce + ciphertext + tag).
// keyHex is the 32-byte key, hex-encoded.
func (s *aesGCMEncryptionService) Decrypt(cipherTextBase64 string, keyHex string) (string, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex key: %w", err)
	}
	if len(key) != 32 {
		return "", errors.New("invalid key length: must be 32 bytes for AES-256")
	}

	nonceAndCiphertext, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(nonceAndCiphertext) < nonceSize {
		return "", errors.New("ciphertext too short to contain nonce")
	}

	nonce, actualCiphertext := nonceAndCiphertext[:nonceSize], nonceAndCiphertext[nonceSize:]

	plainTextBytes, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		// Common error is "cipher: message authentication failed" for wrong key or tampered data
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plainTextBytes), nil
}

// Ensure implementation satisfies the interface
var _ EncryptionService = (*aesGCMEncryptionService)(nil)
