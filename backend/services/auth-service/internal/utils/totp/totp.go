// File: internal/utils/totp/totp.go

package totp

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Config содержит конфигурацию для TOTP
type Config struct {
	Issuer  string
	Period  uint
	Digits  otp.Digits
	Skew    uint
	Secret  string
}

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() *Config {
	return &Config{
		Issuer:  "RussianSteam",
		Period:  30,
		Digits:  otp.DigitsSix,
		Skew:    1,
	}
}

// GenerateSecret генерирует новый секретный ключ для TOTP
func GenerateSecret() (string, error) {
	// Генерируем 20 случайных байт
	secret := make([]byte, 20)
	_, err := rand.Read(secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Кодируем в base32
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

// GenerateQRCodeURL генерирует URL для QR-кода
func GenerateQRCodeURL(username, secret string, config *Config) string {
	if config == nil {
		config = DefaultConfig()
	}

	// Если секрет не содержит padding, добавляем его
	if !strings.HasSuffix(secret, "=") {
		padding := 8 - (len(secret) % 8)
		if padding < 8 {
			secret = secret + strings.Repeat("=", padding)
		}
	}

	// Создаем URL для QR-кода
	params := url.Values{}
	params.Add("secret", secret)
	params.Add("issuer", config.Issuer)
	params.Add("period", fmt.Sprintf("%d", config.Period))
	params.Add("algorithm", "SHA1")
	params.Add("digits", fmt.Sprintf("%d", config.Digits))

	return fmt.Sprintf("otpauth://totp/%s:%s?%s",
		url.PathEscape(config.Issuer),
		url.PathEscape(username),
		params.Encode(),
	)
}

// ValidateCode проверяет TOTP код
func ValidateCode(code, secret string, config *Config) (bool, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Если секрет не содержит padding, добавляем его
	if !strings.HasSuffix(secret, "=") {
		padding := 8 - (len(secret) % 8)
		if padding < 8 {
			secret = secret + strings.Repeat("=", padding)
		}
	}

	// Проверяем код
	return totp.ValidateCustom(
		code,
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    config.Period,
			Skew:      config.Skew,
			Digits:    config.Digits,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
}

// GenerateCode генерирует TOTP код
func GenerateCode(secret string, config *Config) (string, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Если секрет не содержит padding, добавляем его
	if !strings.HasSuffix(secret, "=") {
		padding := 8 - (len(secret) % 8)
		if padding < 8 {
			secret = secret + strings.Repeat("=", padding)
		}
	}

	// Генерируем код
	return totp.GenerateCodeCustom(
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    config.Period,
			Skew:      config.Skew,
			Digits:    config.Digits,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
}
