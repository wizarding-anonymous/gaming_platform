package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/gameplatform/auth-service/internal/domain/service"
)

// Argon2idParams holds the parameters for Argon2id hashing.
// These should ideally be configurable via `internal/config`.
type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// argon2idPasswordService implements the PasswordService using Argon2id.
type argon2idPasswordService struct {
	params Argon2idParams
}

// NewArgon2idPasswordService creates a new argon2idPasswordService.
// Parameters would typically come from application configuration.
func NewArgon2idPasswordService(params Argon2idParams) (service.PasswordService, error) {
	if params.Memory == 0 || params.Iterations == 0 || params.Parallelism == 0 || params.SaltLength == 0 || params.KeyLength == 0 {
		// Provide sensible defaults if not configured or fall back to error
		// For this example, we use common defaults. The spec suggests:
		// memory=64MB (65536 KiB), time (iterations)=1-3, parallelism=2-4, saltLength=16, keyLength=32
		// We'll use moderate defaults here.
		return nil, errors.New("Argon2idParams must be fully configured")
	}
	return &argon2idPasswordService{params: params}, nil
}

// HashPassword creates an Argon2id hash of the password.
// The format of the output string is:
// $argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt_base64>$<hash_base64>
func (s *argon2idPasswordService) HashPassword(password string) (string, error) {
	salt := make([]byte, s.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, s.params.Iterations, s.params.Memory, s.params.Parallelism, s.params.KeyLength)

	// Encode salt and hash to Base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format into standard string
	// Example: $argon2id$v=19$m=65536,t=3,p=2$c2FsdFNhbHQ$aGFzaGVkSGFzaA
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, s.params.Memory, s.params.Iterations, s.params.Parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

// CheckPasswordHash verifies a password against an Argon2id hash string.
func (s *argon2idPasswordService) CheckPasswordHash(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format: not enough parts")
	}

	if parts[1] != "argon2id" {
		return false, errors.New("invalid hash format: not argon2id")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return false, errors.New("invalid hash format: unsupported version")
	}

	var memory, iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, fmt.Errorf("invalid hash format: malformed params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("invalid hash format: failed to decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("invalid hash format: failed to decode hash: %w", err)
	}

	// Use the parameters from the hash string, not from s.params,
	// to ensure compatibility with hashes created with different parameters.
	comparisonHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(hash)))

	if subtle.ConstantTimeCompare(hash, comparisonHash) == 1 {
		// Optional: Check if parameters need upgrading (if current s.params are stronger)
		// This would involve rehashing and updating the stored hash.
		// For this function, just returning match is sufficient.
		return true, nil
	}

	return false, nil
}

// Ensure argon2idPasswordService implements PasswordService (compile-time check)
var _ service.PasswordService = (*argon2idPasswordService)(nil)
