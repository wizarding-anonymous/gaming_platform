// Package security provides implementations for security-related functionalities
// such as password hashing, token generation and validation, data encryption,
// and TOTP management. These services are typically used by higher-level
// application or domain services.
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

// EncryptionService defines methods for symmetric encryption and decryption of data.
// It is used to protect sensitive information, such as TOTP secrets, at rest.
type EncryptionService interface {
	// Encrypt encrypts the given plaintext string using a provided hex-encoded encryption key.
	// The key is expected to be a 64-character hex string (representing 32 bytes for AES-256).
	// The method uses AES-GCM and prepends a random nonce to the ciphertext.
	// The returned string is a base64-encoded representation of (nonce + ciphertext + GCM tag).
	// Returns the base64 encoded ciphertext string or an error if encryption fails
	// (e.g., due to invalid key length or issues with cryptographic operations).
	Encrypt(plainText string, keyHex string) (string, error)

	// Decrypt decrypts the given base64-encoded ciphertext string using a provided hex-encoded encryption key.
	// The key is expected to be a 64-character hex string (representing 32 bytes for AES-256).
	// The input ciphertextBase64 must be a base64 string that, when decoded, contains the nonce prepended
	// to the actual ciphertext and GCM tag.
	// Returns the original plaintext string or an error if decryption fails
	// (e.g., due to invalid key, malformed ciphertext, or message authentication failure).
	Decrypt(cipherTextBase64 string, keyHex string) (string, error)
}

// aesGCMEncryptionService implements the EncryptionService interface using AES in GCM mode.
// GCM (Galois/Counter Mode) is an authenticated encryption mode, providing both confidentiality and integrity.
type aesGCMEncryptionService struct{}

// NewAESGCMEncryptionService creates a new instance of aesGCMEncryptionService.
// This service provides AES-GCM encryption and decryption capabilities.
func NewAESGCMEncryptionService() EncryptionService {
	return &aesGCMEncryptionService{}
}

// Encrypt encrypts plaintext using AES-256-GCM.
// The keyHex parameter must be a 64-character hex-encoded string representing a 32-byte key for AES-256.
// The method generates a random 12-byte nonce, performs encryption, and prepends the nonce to the ciphertext.
// The final output (nonce + ciphertext + GCM tag) is then base64-encoded.
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

// Decrypt decrypts ciphertext that was previously encrypted using AES-256-GCM by the Encrypt method.
// The cipherTextBase64 parameter is expected to be a base64-encoded string containing the nonce prepended
// to the actual ciphertext and GCM tag.
// The keyHex parameter must be the same 64-character hex-encoded 32-byte key used for encryption.
// Returns the original plaintext if decryption is successful.
// Returns an error if the key is invalid, ciphertext is malformed, or if message authentication fails
// (indicating tampering or use of an incorrect key).
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
