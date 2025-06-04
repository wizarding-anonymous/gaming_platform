package service

import (
	"time"
)

// TelegramAuthData represents the data received from Telegram Login Widget.
// Using map[string]interface{} for flexibility as field presence can vary.
// A struct could also be used if fields are fixed.
type TelegramAuthData map[string]interface{}

// TelegramVerifierService defines the interface for verifying authentication data
// received from the Telegram Login Widget.
type TelegramVerifierService interface {
	// VerifyTelegramAuth validates the data received from Telegram.
	// data: a map of fields received from Telegram.
	// botToken: the Telegram Bot Token.
	// Returns:
	//   - isValid: true if the data is valid and recent.
	//   - telegramUserID: the Telegram user ID if validation is successful.
	//   - err: an error if validation fails or an issue occurs.
	VerifyTelegramAuth(data TelegramAuthData, botToken string) (isValid bool, telegramUserID int64, err error)
}

// TelegramAuthMaxAge is the maximum acceptable age for the auth_date from Telegram.
const TelegramAuthMaxAge = 24 * time.Hour
