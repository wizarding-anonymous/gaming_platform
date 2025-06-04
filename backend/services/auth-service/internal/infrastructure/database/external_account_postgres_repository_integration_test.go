package database

import (
	"context"
	"encoding/json"
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
	// argon2Service and testDB are assumed global
)

// Helper to clear external_account and related tables
func clearExternalAccountTestTables(t *testing.T) {
	t.Helper()
	tables := []string{"external_accounts", "users"} // Order for FKs
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

// Helper to create a user for external account tests
func createTestUserForExternalAccountTests(ctx context.Context, t *testing.T, suffix string) *models.User {
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	hashedPassword, _ := argon2Service.HashPassword("password123")
	user := &models.User{
		ID:           uuid.New(),
		Username:     fmt.Sprintf("user_extacc_%s", suffix),
		Email:        fmt.Sprintf("user_extacc_%s@example.com", suffix),
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	return user
}

func TestExternalAccountRepository_CreateAndFind(t *testing.T) {
	ctx := context.Background()
	extAccRepo := repoPostgres.NewExternalAccountRepositoryPostgres(testDB)
	clearExternalAccountTestTables(t)

	user := createTestUserForExternalAccountTests(ctx, t, "cf")
	profileData := json.RawMessage(`{"provider_user_id":"12345","name":"Test Provider User"}`)

	newExtAcc := &models.ExternalAccount{
		ID:             uuid.New(),
		UserID:         user.ID,
		Provider:       "telegram",
		ExternalUserID: "tg_user_ext_id_cf",
		DisplayName:    "Telegram User CF",
		ProfileData:    profileData,
		AccessTokenHash: "hashed_at_cf",
		RefreshTokenHash:"hashed_rt_cf",
		TokenExpiresAt: time.Now().Add(time.Hour),
	}

	err := extAccRepo.Create(ctx, newExtAcc)
	require.NoError(t, err)

	// Find by Provider and ExternalID
	foundByProvider, err := extAccRepo.FindByProviderAndExternalID(ctx, "telegram", "tg_user_ext_id_cf")
	require.NoError(t, err)
	require.NotNil(t, foundByProvider)
	assert.Equal(t, newExtAcc.ID, foundByProvider.ID)
	assert.Equal(t, newExtAcc.UserID, foundByProvider.UserID)
	assert.Equal(t, newExtAcc.DisplayName, foundByProvider.DisplayName)
	assert.JSONEq(t, string(profileData), string(foundByProvider.ProfileData))
	assert.Equal(t, newExtAcc.AccessTokenHash, foundByProvider.AccessTokenHash)
	assert.Equal(t, newExtAcc.RefreshTokenHash, foundByProvider.RefreshTokenHash)
	assert.WithinDuration(t, newExtAcc.TokenExpiresAt, foundByProvider.TokenExpiresAt, time.Second)


	// Find by UserID
	accountsForUser, err := extAccRepo.FindByUserID(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, accountsForUser, 1)
	assert.Equal(t, newExtAcc.ID, accountsForUser[0].ID)

	// Find by ID
	foundByID, err := extAccRepo.FindByID(ctx, newExtAcc.ID)
	require.NoError(t, err)
	require.NotNil(t, foundByID)
	assert.Equal(t, newExtAcc.Provider, foundByID.Provider)
}

func TestExternalAccountRepository_Create_DuplicateProviderAndExternalID(t *testing.T) {
	ctx := context.Background()
	extAccRepo := repoPostgres.NewExternalAccountRepositoryPostgres(testDB)
	clearExternalAccountTestTables(t)
	user1 := createTestUserForExternalAccountTests(ctx, t, "dup1")
	user2 := createTestUserForExternalAccountTests(ctx, t, "dup2") // Different user

	extAcc1 := &models.ExternalAccount{
		ID: uuid.New(), UserID: user1.ID, Provider: "common_provider", ExternalUserID: "common_ext_id",
	}
	err := extAccRepo.Create(ctx, extAcc1)
	require.NoError(t, err)

	// Attempt to create another with the same provider and external_user_id (even for a different user, should fail)
	extAcc2 := &models.ExternalAccount{
		ID: uuid.New(), UserID: user2.ID, Provider: "common_provider", ExternalUserID: "common_ext_id",
	}
	err = extAccRepo.Create(ctx, extAcc2)
	require.Error(t, err, "Should have failed due to duplicate (provider, external_user_id)")

	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "Error should be a PgError")
	assert.Equal(t, "23505", pgErr.Code, "PostgreSQL error code for unique_violation should be 23505")
}

func TestExternalAccountRepository_Update(t *testing.T) {
	ctx := context.Background()
	extAccRepo := repoPostgres.NewExternalAccountRepositoryPostgres(testDB)
	clearExternalAccountTestTables(t)
	user := createTestUserForExternalAccountTests(ctx, t, "upd")

	initialProfileData := json.RawMessage(`{"key":"initial"}`)
	extAcc := &models.ExternalAccount{
		ID: uuid.New(), UserID: user.ID, Provider: "test_prov_upd", ExternalUserID: "ext_id_upd",
		ProfileData: initialProfileData, AccessTokenHash: "old_at",
	}
	err := extAccRepo.Create(ctx, extAcc)
	require.NoError(t, err)

	// Update fields
	updatedProfileData := json.RawMessage(`{"key":"updated","new_field":true}`)
	extAcc.ProfileData = updatedProfileData
	extAcc.AccessTokenHash = "new_at"
	extAcc.RefreshTokenHash = "new_rt"
	newExpiry := time.Now().Add(2 * time.Hour)
	extAcc.TokenExpiresAt = newExpiry
	extAcc.DisplayName = "Updated Display Name"

	err = extAccRepo.Update(ctx, extAcc)
	require.NoError(t, err)

	updatedExtAcc, err := extAccRepo.FindByID(ctx, extAcc.ID)
	require.NoError(t, err)
	require.NotNil(t, updatedExtAcc)
	assert.JSONEq(t, string(updatedProfileData), string(updatedExtAcc.ProfileData))
	assert.Equal(t, "new_at", updatedExtAcc.AccessTokenHash)
	assert.Equal(t, "new_rt", updatedExtAcc.RefreshTokenHash)
	assert.WithinDuration(t, newExpiry, updatedExtAcc.TokenExpiresAt, time.Second)
	assert.Equal(t, "Updated Display Name", updatedExtAcc.DisplayName)
	assert.True(t, updatedExtAcc.UpdatedAt.After(extAcc.CreatedAt))
}

func TestExternalAccountRepository_DeleteByUserID(t *testing.T) {
	ctx := context.Background()
	extAccRepo := repoPostgres.NewExternalAccountRepositoryPostgres(testDB)
	clearExternalAccountTestTables(t)
	user1 := createTestUserForExternalAccountTests(ctx, t, "delusr1")
	user2 := createTestUserForExternalAccountTests(ctx, t, "delusr2")

	// Accounts for user1
	extAcc1U1 := &models.ExternalAccount{ID: uuid.New(), UserID: user1.ID, Provider: "provA", ExternalUserID: "ext1u1"}
	err := extAccRepo.Create(ctx, extAcc1U1); require.NoError(t, err)
	extAcc2U1 := &models.ExternalAccount{ID: uuid.New(), UserID: user1.ID, Provider: "provB", ExternalUserID: "ext2u1"}
	err = extAccRepo.Create(ctx, extAcc2U1); require.NoError(t, err)

	// Account for user2
	extAcc1U2 := &models.ExternalAccount{ID: uuid.New(), UserID: user2.ID, Provider: "provA", ExternalUserID: "ext1u2"}
	err = extAccRepo.Create(ctx, extAcc1U2); require.NoError(t, err)

	// Delete all for user1
	deletedCount, err := extAccRepo.DeleteAllByUserID(ctx, user1.ID) // Changed method name to match interface
	require.NoError(t, err)
	assert.Equal(t, int64(2), deletedCount)

	user1Accounts, err := extAccRepo.FindByUserID(ctx, user1.ID)
	require.NoError(t, err)
	assert.Len(t, user1Accounts, 0)

	// User2's account should remain
	user2Accounts, err := extAccRepo.FindByUserID(ctx, user2.ID)
	require.NoError(t, err)
	assert.Len(t, user2Accounts, 1)
	assert.Equal(t, extAcc1U2.ID, user2Accounts[0].ID)
}

func TestExternalAccountRepository_DeleteByProviderAndExternalID(t *testing.T) {
	ctx := context.Background()
	extAccRepo := repoPostgres.NewExternalAccountRepositoryPostgres(testDB)
	clearExternalAccountTestTables(t)
	user := createTestUserForExternalAccountTests(ctx, t, "delprovid")

	provider := "myprovider"
	externalID := "myexternalid123"
	extAcc := &models.ExternalAccount{
		ID: uuid.New(), UserID: user.ID, Provider: provider, ExternalUserID: externalID,
	}
	err := extAccRepo.Create(ctx, extAcc)
	require.NoError(t, err)

	// Ensure it exists first
	_, err = extAccRepo.FindByProviderAndExternalID(ctx, provider, externalID)
	require.NoError(t, err)

	// Delete it
	err = extAccRepo.DeleteByProviderAndExternalID(ctx, provider, externalID)
	require.NoError(t, err)

	// Verify it's gone
	_, err = extAccRepo.FindByProviderAndExternalID(ctx, provider, externalID)
	require.Error(t, err)
	assert.True(t, errors.Is(err, domainErrors.ErrNotFound), "Expected ErrNotFound after deletion")
}
