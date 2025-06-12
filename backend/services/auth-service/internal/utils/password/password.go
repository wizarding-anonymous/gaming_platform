// File: backend/services/auth-service/internal/utils/password/password.go

package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Errors
var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
	ErrMismatchedPassword  = errors.New("passwords do not match")
)

// Params определяет параметры для Argon2id
type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams возвращает параметры по умолчанию для Argon2id
func DefaultParams() *Params {
	return &Params{
		Memory:      64 * 1024, // 64MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Hash хеширует пароль с использованием Argon2id
func Hash(password string, params *Params) (string, error) {
	if params == nil {
		params = DefaultParams()
	}

	// Генерируем случайную соль
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Хешируем пароль
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Кодируем хеш и параметры в формате:
	// $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.Memory,
		params.Iterations,
		params.Parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// Verify проверяет пароль с использованием хеша Argon2id
func Verify(password, encodedHash string) (bool, error) {
	// Извлекаем параметры, соль и хеш из закодированного хеша
	params, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Хешируем входной пароль с теми же параметрами и солью
	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Сравниваем хеши
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}

	return false, ErrMismatchedPassword
}

// decodeHash декодирует хеш Argon2id и извлекает параметры, соль и хеш
func decodeHash(encodedHash string) (*Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	params := &Params{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return nil, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}
	params.SaltLength = uint32(len(salt))

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}
	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}

// GenerateRandomPassword генерирует случайный пароль заданной длины
func GenerateRandomPassword(length int) (string, error) {
	if length < 8 {
		length = 8 // Минимальная длина пароля
	}

	// Символы для пароля: буквы, цифры и специальные символы
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	charsetLength := len(charset)

	// Генерируем случайные байты
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	// Преобразуем случайные байты в символы из charset
	password := make([]byte, length)
	for i, b := range randomBytes {
		password[i] = charset[int(b)%charsetLength]
	}

	return string(password), nil
}

// IsStrongPassword проверяет, является ли пароль достаточно сильным
func IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	// Пароль должен содержать как минимум 3 из 4 типов символов
	count := 0
	if hasUpper {
		count++
	}
	if hasLower {
		count++
	}
	if hasDigit {
		count++
	}
	if hasSpecial {
		count++
	}

	return count >= 3
}
