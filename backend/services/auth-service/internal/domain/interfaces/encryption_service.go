// File: backend/services/auth-service/internal/domain/interfaces/encryption_service.go
package interfaces

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
