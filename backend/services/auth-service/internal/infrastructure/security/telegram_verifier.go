// File: backend/services/auth-service/internal/infrastructure/security/telegram_verifier.go
package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gameplatform/auth-service/internal/domain/service"
)

type telegramVerifier struct{}

// NewTelegramVerifier creates a new TelegramVerifierService implementation.
func NewTelegramVerifier() service.TelegramVerifierService {
	return &telegramVerifier{}
}

// VerifyTelegramAuth validates the data received from Telegram.
func (v *telegramVerifier) VerifyTelegramAuth(data service.TelegramAuthData, botToken string) (bool, int64, error) {
	if data == nil {
		return false, 0, errors.New("telegram data cannot be nil")
	}
	if botToken == "" {
		return false, 0, errors.New("telegram bot token is required")
	}

	receivedHash, ok := data["hash"].(string)
	if !ok || receivedHash == "" {
		return false, 0, errors.New("hash field is missing or not a string in telegram data")
	}

	// Check auth_date
	authDateUnix, ok := data["auth_date"].(float64) // Telegram sends it as a number
	if !ok {
		// Try parsing as string if float64 fails (less common for direct widget data)
		authDateStr, okStr := data["auth_date"].(string)
		if !okStr {
			return false, 0, errors.New("auth_date field is missing or not a number/string in telegram data")
		}
		parsedUnix, err := strconv.ParseInt(authDateStr, 10, 64)
		if err != nil {
			return false, 0, fmt.Errorf("failed to parse auth_date string: %w", err)
		}
		authDateUnix = float64(parsedUnix)
	}

	authTimestamp := time.Unix(int64(authDateUnix), 0)
	if time.Since(authTimestamp) > service.TelegramAuthMaxAge {
		return false, 0, errors.New("telegram auth_date is too old")
	}

	// Prepare data-check-string
	var checkPairs []string
	for key, value := range data {
		if key == "hash" {
			continue
		}
		// Convert value to string. Telegram usually sends simple types.
		// For JSON objects/arrays, this might need more sophisticated stringification.
		// However, standard Telegram Login widget fields are simple.
		checkPairs = append(checkPairs, fmt.Sprintf("%s=%v", key, value))
	}
	sort.Strings(checkPairs)
	dataCheckString := strings.Join(checkPairs, "\n")

	// Calculate HMAC-SHA256
	secretKey := sha256.Sum256([]byte(botToken))
	mac := hmac.New(sha256.New, secretKey[:])
	mac.Write([]byte(dataCheckString))
	calculatedHash := hex.EncodeToString(mac.Sum(nil))

	if calculatedHash != receivedHash {
		return false, 0, errors.New("telegram hash verification failed")
	}

	// Extract Telegram User ID
	telegramUserIDFloat, ok := data["id"].(float64) // Telegram sends ID as number
	if !ok {
		idStr, okStr := data["id"].(string)
		if !okStr {
			return false, 0, errors.New("telegram user id (id) field is missing or not a number/string")
		}
		parsedID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return false, 0, fmt.Errorf("failed to parse telegram user id string: %w", err)
		}
		telegramUserIDFloat = float64(parsedID)
	}
	telegramUserID := int64(telegramUserIDFloat)
	if telegramUserID <= 0 {
		return false, 0, errors.New("invalid telegram user id")
	}

	return true, telegramUserID, nil
}

var _ service.TelegramVerifierService = (*telegramVerifier)(nil)