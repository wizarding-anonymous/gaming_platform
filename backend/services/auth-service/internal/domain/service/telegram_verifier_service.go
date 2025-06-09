// File: backend/services/auth-service/internal/domain/service/telegram_verifier_service.go
package service

import (
	"context"
	"time" // Keep for TelegramAuthMaxAge
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models" // For TelegramLoginRequest DTO
)

// TelegramVerifierService defines the interface for verifying Telegram authentication data.
type TelegramVerifierService interface {
	// VerifyTelegramAuth checks the authenticity of the data received from the Telegram login widget.
	// It uses the botToken to validate the hash.
	// Returns true if valid, the Telegram UserID, and an error if any occurs during validation.
	// The telegramData comes directly from the models.TelegramLoginRequest.
	VerifyTelegramAuth(ctx context.Context, telegramData models.TelegramLoginRequest, botToken string) (isValid bool, telegramUserID int64, err error)
}

// TelegramAuthMaxAge is the maximum acceptable age for the auth_date from Telegram.
// Consider making this configurable.
const TelegramAuthMaxAge = 24 * time.Hour
