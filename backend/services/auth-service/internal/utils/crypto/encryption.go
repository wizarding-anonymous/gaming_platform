// File: backend/services/auth-service/internal/utils/crypto/encryption.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext using AES-GCM with a 32-byte key.
// The nonce is prepended to the ciphertext.
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key length must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce.
	// GCM standard nonce size is 12 bytes.
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext. The GCM Seal function appends the ciphertext to the nonce.
	// We pass nil as the first argument to Seal because we are generating the nonce ourselves.
	// The result is nonce || ciphertext.
	ciphertextWithNonce := gcm.Seal(nonce, nonce, plaintext, nil)

	return ciphertextWithNonce, nil
}

// Decrypt decrypts ciphertextWithNonce using AES-GCM with a 32-byte key.
// It assumes the nonce is prepended to the ciphertext.
func Decrypt(ciphertextWithNonce []byte, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key length must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextWithNonce) < nonceSize {
		return nil, fmt.Errorf("ciphertext is too short to contain a nonce")
	}

	// Extract the nonce from the beginning of the ciphertext.
	nonce, ciphertext := ciphertextWithNonce[:nonceSize], ciphertextWithNonce[nonceSize:]

	// Decrypt the ciphertext.
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
