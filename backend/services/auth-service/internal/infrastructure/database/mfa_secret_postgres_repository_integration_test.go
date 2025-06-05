// File: backend/services/auth-service/internal/infrastructure/database/mfa_secret_postgres_repository_integration_test.go
package database

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	repoPostgres "github.com/your-org/auth-service/internal/domain/repository/postgres"
	// argon2Service and testDB are assumed to be global and initialized in another _test.go file's TestMain
)

// Helper to clear mfa_secret and related tables
func clearMFASecretTestTables(t *testing.T) {
	t.Helper()
	tables := []string{"mfa_secrets", "users"} // Order for FKs
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

// Helper to create a user for MFA secret tests
func createTestUserForMFASecretTests(ctx context.Context, t *testing.T, suffix string) *models.User {
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	hashedPassword, _ := argon2Service.HashPassword("password123") // argon2Service from user_test
	user := &models.User{
		ID:           uuid.New(),
		Username:     fmt.Sprintf("user_mfas_%s", suffix),
		Email:        fmt.Sprintf("user_mfas_%s@example.com", suffix),
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	return user
}

func TestMFASecretRepository_CreateAndFind(t *testing.T) {
	ctx := context.Background()
	mfaSecretRepo := repoPostgres.NewMFASecretRepositoryPostgres(testDB)
	clearMFASecretTestTables(t)

	user := createTestUserForMFASecretTests(ctx, t, "cf")

	newSecret := &models.MFASecret{
		ID:                 uuid.New(),
		UserID:             user.ID,
		Type:               models.MFATypeTOTP,
		SecretKeyEncrypted: "encrypted_totp_secret_key_cf",
		Verified:           false,
	}

	err := mfaSecretRepo.Create(ctx, newSecret)
	require.NoError(t, err)

	// Find by UserID and Type
	foundSecret, err := mfaSecretRepo.FindByUserIDAndType(ctx, user.ID, models.MFATypeTOTP)
	require.NoError(t, err)
	require.NotNil(t, foundSecret)
	assert.Equal(t, newSecret.ID, foundSecret.ID)
	assert.Equal(t, newSecret.SecretKeyEncrypted, foundSecret.SecretKeyEncrypted)
	assert.False(t, foundSecret.Verified)

	// Find by ID (if method exists - it does on current interface)
	foundByID, err := mfaSecretRepo.FindByID(ctx, newSecret.ID)
	require.NoError(t, err)
	require.NotNil(t, foundByID)
	assert.Equal(t, newSecret.UserID, foundByID.UserID)
}

func TestMFASecretRepository_Create_DuplicateUserIDAndType(t *testing.T) {
	ctx := context.Background()
	mfaSecretRepo := repoPostgres.NewMFASecretRepositoryPostgres(testDB)
	clearMFASecretTestTables(t)

	user := createTestUserForMFASecretTests(ctx, t, "dup")

	secret1 := &models.MFASecret{
		ID: uuid.New(), UserID: user.ID, Type: models.MFATypeTOTP,
		SecretKeyEncrypted: "secret1", Verified: false,
	}
	err := mfaSecretRepo.Create(ctx, secret1)
	require.NoError(t, err)

	secret2 := &models.MFASecret{ // Same UserID and Type
		ID: uuid.New(), UserID: user.ID, Type: models.MFATypeTOTP,
		SecretKeyEncrypted: "secret2", Verified: false,
	}
	err = mfaSecretRepo.Create(ctx, secret2)
	require.Error(t, err, "Should have failed due to duplicate UserID and Type")

	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "Error should be a PgError")
	assert.Equal(t, "23505", pgErr.Code, "PostgreSQL error code for unique_violation should be 23505")
}

func TestMFASecretRepository_Update(t *testing.T) {
	ctx := context.Background()
	mfaSecretRepo := repoPostgres.NewMFASecretRepositoryPostgres(testDB)
	clearMFASecretTestTables(t)
	user := createTestUserForMFASecretTests(ctx, t, "upd")

	secret := &models.MFASecret{
		ID: uuid.New(), UserID: user.ID, Type: models.MFATypeTOTP,
		SecretKeyEncrypted: "initial_secret_upd", Verified: false,
	}
	err := mfaSecretRepo.Create(ctx, secret)
	require.NoError(t, err)

	// Update fields
	secret.Verified = true
	secret.SecretKeyEncrypted = "updated_secret_key_upd" // Assuming secret can be re-keyed/updated

	err = mfaSecretRepo.Update(ctx, secret)
	require.NoError(t, err)

	updatedSecret, err := mfaSecretRepo.FindByID(ctx, secret.ID)
	require.NoError(t, err)
	require.NotNil(t, updatedSecret)
	assert.True(t, updatedSecret.Verified)
	assert.Equal(t, "updated_secret_key_upd", updatedSecret.SecretKeyEncrypted)
	assert.True(t, updatedSecret.UpdatedAt.After(secret.CreatedAt))
}

func TestMFASecretRepository_DeleteByUserIDAndTypeIfUnverified(t *testing.T) {
	ctx := context.Background()
	mfaSecretRepo := repoPostgres.NewMFASecretRepositoryPostgres(testDB)
	clearMFASecretTestTables(t)
	user := createTestUserForMFASecretTests(ctx, t, "delunv")

	// Unverified secret
	unverifiedSecret := &models.MFASecret{
		ID: uuid.New(), UserID: user.ID, Type: models.MFATypeTOTP,
		SecretKeyEncrypted: "unverified_secret_del", Verified: false,
	}
	err := mfaSecretRepo.Create(ctx, unverifiedSecret)
	require.NoError(t, err)

	// Verified secret (should not be deleted by this method)
	verifiedSecret := &models.MFASecret{
		ID: uuid.New(), UserID: user.ID, Type: models.MFATypeU2F, // Different type for same user
		SecretKeyEncrypted: "verified_secret_del", Verified: true,
	}
	err = mfaSecretRepo.Create(ctx, verifiedSecret)
	require.NoError(t, err)

	// Attempt to delete unverified TOTP secret
	deleted, err := mfaSecretRepo.DeleteByUserIDAndTypeIfUnverified(ctx, user.ID, models.MFATypeTOTP)
	require.NoError(t, err)
	assert.True(t, deleted, "Should have deleted the unverified TOTP secret")

	_, err = mfaSecretRepo.FindByID(ctx, unverifiedSecret.ID)
	assert.ErrorIs(t, err, domainErrors.ErrNotFound, "Unverified secret should be deleted")

	// Attempt to delete again (should return false, no error)
	deletedAgain, err := mfaSecretRepo.DeleteByUserIDAndTypeIfUnverified(ctx, user.ID, models.MFATypeTOTP)
	require.NoError(t, err)
	assert.False(t, deletedAgain, "Should return false as no unverified TOTP secret exists now")

	// Verified U2F secret should still exist
	foundVerified, err := mfaSecretRepo.FindByID(ctx, verifiedSecret.ID)
	require.NoError(t, err)
	require.NotNil(t, foundVerified)
}


func TestMFASecretRepository_DeleteAllForUser(t *testing.T) {
	ctx := context.Background()
	mfaSecretRepo := repoPostgres.NewMFASecretRepositoryPostgres(testDB)
	clearMFASecretTestTables(t)
	user1 := createTestUserForMFASecretTests(ctx, t, "dall1")
	user2 := createTestUserForMFASecretTests(ctx, t, "dall2")

	// Secrets for user1
	secret1User1 := &models.MFASecret{ID: uuid.New(), UserID: user1.ID, Type: models.MFATypeTOTP, SecretKeyEncrypted: "s1u1"}
	err := mfaSecretRepo.Create(ctx, secret1User1); require.NoError(t, err)
	secret2User1 := &models.MFASecret{ID: uuid.New(), UserID: user1.ID, Type: models.MFATypeU2F, SecretKeyEncrypted: "s2u1"} // Example if schema allows multiple types
	err = mfaSecretRepo.Create(ctx, secret2User1); require.NoError(t, err)

	// Secret for user2
	secret1User2 := &models.MFASecret{ID: uuid.New(), UserID: user2.ID, Type: models.MFATypeTOTP, SecretKeyEncrypted: "s1u2"}
	err = mfaSecretRepo.Create(ctx, secret1User2); require.NoError(t, err)

	// Delete all for user1
	deletedCount, err := mfaSecretRepo.DeleteAllForUser(ctx, user1.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), deletedCount)

	_, err = mfaSecretRepo.FindByID(ctx, secret1User1.ID)
	assert.ErrorIs(t, err, domainErrors.ErrNotFound)
	_, err = mfaSecretRepo.FindByID(ctx, secret2User1.ID)
	assert.ErrorIs(t, err, domainErrors.ErrNotFound)

	// User2's secret should remain
	foundUser2Secret, err := mfaSecretRepo.FindByID(ctx, secret1User2.ID)
	require.NoError(t, err)
	assert.NotNil(t, foundUser2Secret)
}
