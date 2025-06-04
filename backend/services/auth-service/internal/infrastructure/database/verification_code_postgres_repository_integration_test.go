package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	repoPostgres "github.com/your-org/auth-service/internal/domain/repository/postgres"
	// argon2Service and testDB are global from user_postgres_repository_integration_test.go's TestMain
)

// Helper to clear verification_code and related tables
func clearVerificationCodeTestTables(t *testing.T) {
	t.Helper()
	tables := []string{"verification_codes", "users"} // Order for FKs
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

// Helper to create a user for verification code tests
func createTestUserForVerificationCodeTests(ctx context.Context, t *testing.T) *models.User {
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	hashedPassword, _ := argon2Service.HashPassword("password123")
	user := &models.User{
		ID:           uuid.New(),
		Username:     fmt.Sprintf("user_vc_%s", uuid.NewString()[:8]),
		Email:        fmt.Sprintf("user_vc_%s@example.com", uuid.NewString()[:8]),
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	return user
}

// Helper to hash a plain token for testing FindByCodeHashAndType
func hashPlainTokenForTest(plainToken string) string {
	hasher := sha256.New()
	hasher.Write([]byte(plainToken))
	return hex.EncodeToString(hasher.Sum(nil))
}

func TestVerificationCodeRepository_CreateAndFindByHash(t *testing.T) {
	ctx := context.Background()
	vcRepo := repoPostgres.NewVerificationCodeRepositoryPostgres(testDB)
	clearVerificationCodeTestTables(t)

	user := createTestUserForVerificationCodeTests(ctx, t)

	plainToken := "my_plain_verification_token_CreateAndFindByHash"
	tokenHash := hashPlainTokenForTest(plainToken)

	newVC := &models.VerificationCode{
		ID:        uuid.New(),
		UserID:    user.ID,
		Type:      models.VerificationCodeTypeEmailVerification,
		CodeHash:  tokenHash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	err := vcRepo.Create(ctx, newVC)
	require.NoError(t, err)

	// Find by Hash and Type
	foundVC, err := vcRepo.FindByCodeHashAndType(ctx, tokenHash, models.VerificationCodeTypeEmailVerification)
	require.NoError(t, err)
	require.NotNil(t, foundVC)
	assert.Equal(t, newVC.ID, foundVC.ID)
	assert.Equal(t, newVC.UserID, foundVC.UserID)
	assert.Nil(t, foundVC.UsedAt, "UsedAt should be nil initially")
	assert.WithinDuration(t, newVC.ExpiresAt, foundVC.ExpiresAt, time.Second)

	// Try to find with wrong type
	_, err = vcRepo.FindByCodeHashAndType(ctx, tokenHash, models.VerificationCodeTypePasswordReset)
	require.Error(t, err)
	assert.True(t, errors.Is(err, domainErrors.ErrNotFound), "Expected ErrNotFound for wrong type")
}

func TestVerificationCodeRepository_MarkAsUsed(t *testing.T) {
	ctx := context.Background()
	vcRepo := repoPostgres.NewVerificationCodeRepositoryPostgres(testDB)
	clearVerificationCodeTestTables(t)
	user := createTestUserForVerificationCodeTests(ctx, t)

	plainToken := "my_plain_token_MarkAsUsed"
	tokenHash := hashPlainTokenForTest(plainToken)
	vc := &models.VerificationCode{
		ID: uuid.New(), UserID: user.ID, Type: models.VerificationCodeTypeEmailVerification,
		CodeHash: tokenHash, ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	err := vcRepo.Create(ctx, vc)
	require.NoError(t, err)

	// Mark as used
	usedAtTime := time.Now()
	err = vcRepo.MarkAsUsed(ctx, vc.ID, usedAtTime)
	require.NoError(t, err)

	// Try to find it again using FindByCodeHashAndType (which should filter used codes)
	foundVC, err := vcRepo.FindByCodeHashAndType(ctx, tokenHash, models.VerificationCodeTypeEmailVerification)
	require.Error(t, err, "Finding a used token by hash and type should fail or return ErrNotFound")
	assert.True(t, errors.Is(err, domainErrors.ErrNotFound), "Expected ErrNotFound for used token")
	assert.Nil(t, foundVC)

	// Optionally, fetch directly by ID to check UsedAt (if a FindByID method existed, or query directly)
    // For now, the above check is sufficient to infer it was marked used.
    // var dbUsedAt pq.NullTime
    // query := "SELECT used_at FROM verification_codes WHERE id = $1"
    // err = testDB.QueryRow(ctx, query, vc.ID).Scan(&dbUsedAt)
    // require.NoError(t, err)
    // require.True(t, dbUsedAt.Valid, "UsedAt should be set in DB")
    // assert.WithinDuration(t, usedAtTime, dbUsedAt.Time, time.Second)
}


func TestVerificationCodeRepository_DeleteByUserIDAndType(t *testing.T) {
	ctx := context.Background()
	vcRepo := repoPostgres.NewVerificationCodeRepositoryPostgres(testDB)
	clearVerificationCodeTestTables(t)
	user1 := createTestUserForVerificationCodeTests(ctx, t)
	user2 := createTestUserForVerificationCodeTests(ctx, t)

	vc1User1Email := &models.VerificationCode{ID: uuid.New(), UserID: user1.ID, Type: models.VerificationCodeTypeEmailVerification, CodeHash: "hash1u1e", ExpiresAt: time.Now().Add(time.Hour)}
	err := vcRepo.Create(ctx, vc1User1Email); require.NoError(t, err)
	vc2User1PassReset := &models.VerificationCode{ID: uuid.New(), UserID: user1.ID, Type: models.VerificationCodeTypePasswordReset, CodeHash: "hash1u1p", ExpiresAt: time.Now().Add(time.Hour)}
	err = vcRepo.Create(ctx, vc2User1PassReset); require.NoError(t, err)
	vc1User2Email := &models.VerificationCode{ID: uuid.New(), UserID: user2.ID, Type: models.VerificationCodeTypeEmailVerification, CodeHash: "hash1u2e", ExpiresAt: time.Now().Add(time.Hour)}
	err = vcRepo.Create(ctx, vc1User2Email); require.NoError(t, err)

	// Delete email verification codes for user1
	deletedCount, err := vcRepo.DeleteByUserIDAndType(ctx, user1.ID, models.VerificationCodeTypeEmailVerification)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deletedCount)

	_, err = vcRepo.FindByCodeHashAndType(ctx, vc1User1Email.CodeHash, models.VerificationCodeTypeEmailVerification)
	assert.ErrorIs(t, err, domainErrors.ErrNotFound, "User1's email code should be deleted")

	foundPassReset, err := vcRepo.FindByCodeHashAndType(ctx, vc2User1PassReset.CodeHash, models.VerificationCodeTypePasswordReset)
	assert.NoError(t, err, "User1's password reset code should still exist")
	assert.NotNil(t, foundPassReset)

	foundUser2Email, err := vcRepo.FindByCodeHashAndType(ctx, vc1User2Email.CodeHash, models.VerificationCodeTypeEmailVerification)
	assert.NoError(t, err, "User2's email code should still exist")
	assert.NotNil(t, foundUser2Email)
}

func TestVerificationCodeRepository_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	vcRepo := repoPostgres.NewVerificationCodeRepositoryPostgres(testDB)
	clearVerificationCodeTestTables(t)
	user := createTestUserForVerificationCodeTests(ctx, t)

	// Expired code
	vcExpired := &models.VerificationCode{
		ID: uuid.New(), UserID: user.ID, Type: models.VerificationCodeTypeEmailVerification,
		CodeHash: "hash_expired_vc", ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	err := vcRepo.Create(ctx, vcExpired); require.NoError(t, err)

	// Active code
	vcActive := &models.VerificationCode{
		ID: uuid.New(), UserID: user.ID, Type: models.VerificationCodeTypePasswordReset,
		CodeHash: "hash_active_vc", ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	err = vcRepo.Create(ctx, vcActive); require.NoError(t, err)

	deletedCount, err := vcRepo.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.True(t, deletedCount >= 1, "Expected at least one expired code to be deleted")

	_, err = vcRepo.FindByCodeHashAndType(ctx, vcExpired.CodeHash, models.VerificationCodeTypeEmailVerification)
	assert.ErrorIs(t, err, domainErrors.ErrNotFound, "Expired code should be deleted")

	foundActive, err := vcRepo.FindByCodeHashAndType(ctx, vcActive.CodeHash, models.VerificationCodeTypePasswordReset)
	assert.NoError(t, err, "Active code should not be deleted")
	assert.NotNil(t, foundActive)
}
