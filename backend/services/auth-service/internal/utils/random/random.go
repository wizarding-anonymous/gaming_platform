// File: backend/services/auth-service/internal/utils/random/random.go

package random

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// GenerateRandomBytes генерирует случайные байты указанной длины
func GenerateRandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// GenerateRandomString генерирует случайную строку указанной длины
func GenerateRandomString(length int) (string, error) {
	b, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

// GenerateRandomHex генерирует случайную шестнадцатеричную строку указанной длины
func GenerateRandomHex(length int) (string, error) {
	b, err := GenerateRandomBytes(length / 2)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateRandomInt генерирует случайное целое число в диапазоне [min, max]
func GenerateRandomInt(min, max int64) (int64, error) {
	if min > max {
		return 0, fmt.Errorf("min cannot be greater than max")
	}
	if min == max {
		return min, nil
	}

	// Вычисляем диапазон
	diff := big.NewInt(max - min + 1)

	// Генерируем случайное число в диапазоне [0, diff-1]
	n, err := rand.Int(rand.Reader, diff)
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int: %w", err)
	}

	// Добавляем min, чтобы получить число в диапазоне [min, max]
	return n.Int64() + min, nil
}

// GenerateRandomDigits генерирует случайную строку из цифр указанной длины
func GenerateRandomDigits(length int) (string, error) {
	digits := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate random digit: %w", err)
		}
		digits[i] = byte(n.Int64() + '0')
	}
	return string(digits), nil
}

// GenerateRandomAlphanumeric генерирует случайную буквенно-цифровую строку указанной длины
func GenerateRandomAlphanumeric(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	return GenerateRandomStringFromCharset(length, charset)
}

// GenerateRandomStringFromCharset генерирует случайную строку из указанного набора символов
func GenerateRandomStringFromCharset(length int, charset string) (string, error) {
	charsetLength := big.NewInt(int64(len(charset)))
	result := strings.Builder{}
	result.Grow(length)

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", fmt.Errorf("failed to generate random index: %w", err)
		}
		result.WriteByte(charset[n.Int64()])
	}

	return result.String(), nil
}

// GenerateSecureToken генерирует безопасный токен указанной длины
func GenerateSecureToken(length int) (string, error) {
	b, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)[:length], nil
}

// GenerateUUID генерирует UUID v4
func GenerateUUID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %w", err)
	}

	// Устанавливаем версию (4) и вариант (2)
	b[6] = (b[6] & 0x0F) | 0x40 // версия 4
	b[8] = (b[8] & 0x3F) | 0x80 // вариант 2

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// GeneratePassword генерирует случайный пароль указанной длины
func GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("password length must be at least 8 characters")
	}

	// Определяем наборы символов
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	special := "!@#$%^&*()-_=+[]{}|;:,.<>?"

	// Генерируем по одному символу из каждого набора
	lowercaseChar, err := GenerateRandomStringFromCharset(1, lowercase)
	if err != nil {
		return "", err
	}

	uppercaseChar, err := GenerateRandomStringFromCharset(1, uppercase)
	if err != nil {
		return "", err
	}

	digitChar, err := GenerateRandomStringFromCharset(1, digits)
	if err != nil {
		return "", err
	}

	specialChar, err := GenerateRandomStringFromCharset(1, special)
	if err != nil {
		return "", err
	}

	// Генерируем оставшиеся символы из всех наборов
	allChars := lowercase + uppercase + digits + special
	remainingLength := length - 4
	remainingChars, err := GenerateRandomStringFromCharset(remainingLength, allChars)
	if err != nil {
		return "", err
	}

	// Объединяем все символы
	password := lowercaseChar + uppercaseChar + digitChar + specialChar + remainingChars

	// Перемешиваем символы
	passwordRunes := []rune(password)
	for i := len(passwordRunes) - 1; i > 0; i-- {
		j, err := GenerateRandomInt(0, int64(i))
		if err != nil {
			return "", err
		}
		passwordRunes[i], passwordRunes[j] = passwordRunes[j], passwordRunes[i]
	}

	return string(passwordRunes), nil
}
