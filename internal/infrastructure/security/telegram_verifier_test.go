// File: internal/infrastructure/security/telegram_verifier_test.go
package security

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/your-org/auth-service/internal/config" // For config.TelegramConfig if needed
	"github.com/your-org/auth-service/internal/domain/models"
)

const (
	testTelegramBotToken = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
	// Default auth_date freshness, e.g., 24 hours.
	// This should ideally come from config if the service uses it.
	defaultAuthDateFreshness = 24 * time.Hour
)

// Helper function to generate a valid Telegram hash for testing
func generateTestTelegramHash(data map[string]string, botToken string) string {
	var checkStrings []string
	for k, v := range data {
		if k != "hash" {
			checkStrings = append(checkStrings, fmt.Sprintf("%s=%s", k, v))
		}
	}
	sort.Strings(checkStrings)
	checkString := strings.Join(checkStrings, "\n")

	secretKey := sha256.Sum256([]byte(botToken))
	mac := hmac.New(sha256.New, secretKey[:])
	mac.Write([]byte(checkString))
	expectedHash := hex.EncodeToString(mac.Sum(nil))
	return expectedHash
}

func TestNewTelegramVerifierService(t *testing.T) {
	// Assuming NewTelegramVerifierService might take config in the future,
	// but current implementation from rbac_service.go was NewTelegramService(cfg.Telegram, logger)
	// and telegram_verifier.go did not have a constructor.
	// If it's just a collection of functions, this test might not be needed.
	// For now, assuming a simple struct instantiation if it were a struct.
	// If TelegramVerifierService is an interface and telegramVerifierImpl is the concrete type:
	// var _ TelegramVerifierService = (*telegramVerifierImpl)(nil) // This would be in the main code

	// If NewTelegramVerifierService() exists and returns the service:
	// service := NewTelegramVerifierService()
	// assert.NotNil(t, service)
	t.Skip("Skipping NewTelegramVerifierService test as current implementation is likely function-based or part of TelegramService.")
}


func TestTelegramVerifier_VerifyTelegramAuth_Success(t *testing.T) {
	verifier := telegramVerifierImpl{} // Assuming concrete type if no constructor
	// If there's a constructor: verifier := NewTelegramVerifierService()

	authDate := time.Now().Unix() - 10 // 10 seconds ago, well within freshness
	data := models.TelegramLoginRequest{
		ID:        123456789,
		FirstName: "Test",
		Username:  "testuser",
		PhotoURL:  "http://example.com/photo.jpg",
		AuthDate:  authDate,
		// Hash will be set by helper
	}

	dataMap := map[string]string{
		"id":         fmt.Sprintf("%d", data.ID),
		"first_name": data.FirstName,
		"username":   data.Username,
		"photo_url":  data.PhotoURL,
		"auth_date":  fmt.Sprintf("%d", data.AuthDate),
	}
	data.Hash = generateTestTelegramHash(dataMap, testTelegramBotToken)

	// Pass a dummy TelegramConfig if the method needs it, or nil if it only uses botToken
	// The method signature is VerifyTelegramAuth(ctx context.Context, user models.TelegramLoginRequest, botToken string)
	isValid, userID, err := verifier.VerifyTelegramAuth(context.Background(), data, testTelegramBotToken)

	assert.NoError(t, err)
	assert.True(t, isValid)
	assert.Equal(t, data.ID, userID)
}

func TestTelegramVerifier_VerifyTelegramAuth_Failure_InvalidHash(t *testing.T) {
	verifier := telegramVerifierImpl{}
	authDate := time.Now().Unix() - 10
	data := models.TelegramLoginRequest{
		ID:        123456789,
		FirstName: "Test",
		AuthDate:  authDate,
		Hash:      "clearlyinvalidhash123", // Invalid hash
	}

	isValid, userID, err := verifier.VerifyTelegramAuth(context.Background(), data, testTelegramBotToken)

	assert.NoError(t, err) // VerifyTelegramAuth might not error, just return false
	assert.False(t, isValid)
	assert.Equal(t, int64(0), userID) // Expect zero userID on failure
}

func TestTelegramVerifier_VerifyTelegramAuth_Failure_OutdatedAuthDate(t *testing.T) {
	verifier := telegramVerifierImpl{}
	// AuthDate is 2 days ago, assuming defaultAuthDateFreshness is 24 hours
	authDate := time.Now().Add(-(defaultAuthDateFreshness + time.Hour)).Unix()

	data := models.TelegramLoginRequest{
		ID:        123456789,
		FirstName: "Test",
		AuthDate:  authDate,
	}
	dataMap := map[string]string{
		"id":         fmt.Sprintf("%d", data.ID),
		"first_name": data.FirstName,
		"auth_date":  fmt.Sprintf("%d", data.AuthDate),
	}
	data.Hash = generateTestTelegramHash(dataMap, testTelegramBotToken)


	// The VerifyTelegramAuth function needs to be aware of defaultAuthDateFreshness.
	// If it's hardcoded there, this test works. If it's configurable via TelegramConfig
	// passed to a constructor, then the test setup needs to use that config.
	// For now, assuming the check is internal to VerifyTelegramAuth with a known window.
	// The current telegram_verifier.go does not have a configurable freshness, it's hardcoded to 24h.

	isValid, userID, err := verifier.VerifyTelegramAuth(context.Background(), data, testTelegramBotToken)

	// The current implementation of VerifyTelegramAuth returns (false, 0, nil) for outdated timestamp
	// without a specific domainError.ErrTelegramAuthExpired error.
	assert.NoError(t, err, "Expected no error for outdated timestamp, just isValid=false")
	assert.False(t, isValid, "isValid should be false for outdated timestamp")
	assert.Equal(t, int64(0), userID)
}

func TestTelegramVerifier_VerifyTelegramAuth_Failure_MissingFieldsInCheckString(t *testing.T) {
	verifier := telegramVerifierImpl{}
	authDate := time.Now().Unix() - 10

	// Create data map with a field missing that would be in TelegramLoginRequest DTO
	// e.g. if FirstName was optional and not provided, but hash was calculated with it.
	// However, TelegramLoginRequest DTO makes fields non-optional if they are part of hash.
	// This test is more about the hash calculation robustness if fields could be omitted.
	// The current generateTestTelegramHash includes all non-hash fields.
	// If a field like 'username' was optional and NOT sent by Telegram, but our hash calculation expected it empty.

	dataMapCorrect := map[string]string{
		"id":         "98765",
		"first_name": "FName",
		"auth_date":  fmt.Sprintf("%d", authDate),
		// "username": "uname", // Username is omitted
	}
	correctHash := generateTestTelegramHash(dataMapCorrect, testTelegramBotToken)

	// Now, the actual data passed to VerifyTelegramAuth *includes* Username, making the hash mismatch
	dataWithUsername := models.TelegramLoginRequest{
		ID:        98765,
		FirstName: "FName",
		Username:  "uname", // This field makes the client-side calculated checkString different
		AuthDate:  authDate,
		Hash:      correctHash, // This hash was calculated WITHOUT username
	}

	isValid, _, _ := verifier.VerifyTelegramAuth(context.Background(), dataWithUsername, testTelegramBotToken)
	assert.False(t, isValid, "Hash should mismatch if check string differs due to more fields in DTO than in hash calculation map")


	// Scenario 2: DTO has fewer fields than what hash was calculated with (e.g. photo_url missing in DTO)
	dataMapWithPhoto := map[string]string{
		"id":         "98765",
		"first_name": "FName",
		"auth_date":  fmt.Sprintf("%d", authDate),
		"username":   "uname",
		"photo_url":  "http://example.com/pic.jpg",
	}
	hashWithPhoto := generateTestTelegramHash(dataMapWithPhoto, testTelegramBotToken)

	dataWithoutPhoto := models.TelegramLoginRequest{
		ID:        98765,
		FirstName: "FName",
		Username:  "uname",
		AuthDate:  authDate,
		Hash:      hashWithPhoto, // Hash calculated WITH photo_url
		// PhotoURL is omitted here
	}
	isValid2, _, _ := verifier.VerifyTelegramAuth(context.Background(), dataWithoutPhoto, testTelegramBotToken)
	assert.False(t, isValid2, "Hash should mismatch if check string differs due to fewer fields in DTO than in hash calculation map")
}


func TestTelegramVerifier_VerifyTelegramAuth_EmptyBotToken(t *testing.T) {
	verifier := telegramVerifierImpl{}
	data := models.TelegramLoginRequest{
		ID: 1, FirstName: "Test", AuthDate: time.Now().Unix() - 10, Hash: "somehash",
	}
	// Expecting VerifyTelegramAuth to handle this gracefully, likely returning false.
	// The current implementation would use an empty key for HMAC, which is not ideal but won't panic.
	// A production system should ideally error or log a warning if bot token is empty.
	isValid, _, err := verifier.VerifyTelegramAuth(context.Background(), data, "")
	assert.NoError(t, err) // Or specific error if service validates token presence
	assert.False(t, isValid) // Hash check will fail with wrong/empty token
}
