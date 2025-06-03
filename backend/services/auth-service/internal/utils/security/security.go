package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params содержит параметры для алгоритма Argon2
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params возвращает параметры Argon2 по умолчанию
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Memory:      64 * 1024, // 64MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// GeneratePassword хеширует пароль с использованием Argon2id
func GeneratePassword(password string, params *Argon2Params) (string, error) {
	// Генерация случайной соли
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	// Хеширование пароля
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	// Кодирование соли и хеша в base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Формирование строки с параметрами и хешем
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

// VerifyPassword проверяет пароль с использованием Argon2id
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Разбор строки с хешем
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid hash format")
	}

	// Проверка алгоритма
	if parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	// Разбор версии
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, fmt.Errorf("incompatible version: %d", version)
	}

	// Разбор параметров
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, err
	}

	// Декодирование соли
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	// Декодирование хеша
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	// Вычисление хеша для проверки
	keyLength := uint32(len(hash))
	checkHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)

	// Сравнение хешей
	return subtle.ConstantTimeCompare(hash, checkHash) == 1, nil
}

// GenerateRandomToken генерирует случайный токен заданной длины
func GenerateRandomToken(length int) (string, error) {
	// Генерация случайных байтов
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Кодирование в base64
	token := base64.URLEncoding.EncodeToString(bytes)

	// Обрезка до нужной длины
	if len(token) > length {
		token = token[:length]
	}

	return token, nil
}

// SanitizeInput очищает входные данные от потенциально опасных символов
func SanitizeInput(input string) string {
	// Удаление HTML-тегов и специальных символов
	// В реальном сценарии здесь бы использовалась библиотека для санитизации
	// Но для простоты примера мы просто удаляем некоторые символы
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#39;")
	input = strings.ReplaceAll(input, ";", "&#59;")
	input = strings.ReplaceAll(input, "(", "&#40;")
	input = strings.ReplaceAll(input, ")", "&#41;")

	return input
}
