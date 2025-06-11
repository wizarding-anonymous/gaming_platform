// File: backend/services/auth-service/tests/internal/infrastructure/database/refresh_token_postgres_repository_integration_test.go
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

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	repoPostgres "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres"
	// argon2Service and testDB are global from user_postgres_repository_integration_test.go's TestMain
	// createTestUserForSessionTests is defined in session_postgres_repository_integration_test.go
	// For this file, we might need to redefine or make it accessible if tests are run per-file.
	// For now, assuming it can be called or we'll create users directly.
)

// Helper to clear refresh_token and related tables
func clearRefreshTokenTestTables(t *testing.T) {
	t.Helper()
	tables := []string{"refresh_tokens", "sessions", "users"} // Order for FKs
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

// Helper to create a user and a session for refresh token tests
func createPrerequisitesForRefreshTokenTests(ctx context.Context, t *testing.T) (*models.User, *models.Session) {
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	sessionRepo := repoPostgres.NewSessionRepositoryPostgres(testDB)

	hashedPassword, _ := argon2Service.HashPassword("password123")
	user := &models.User{
		ID:           uuid.New(),
		Username:     fmt.Sprintf("user_rt_%s", uuid.NewString()[:8]),
		Email:        fmt.Sprintf("user_rt_%s@example.com", uuid.NewString()[:8]),
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	session := &models.Session{
		ID:             uuid.New(),
		UserID:         user.ID,
		UserAgent:      "TestAgentRT/1.0",
		IPAddress:      "127.0.0.1",
		ExpiresAt:      time.Now().Add(48 * time.Hour), // Longer expiry for session than RT
		LastActivityAt: time.Now(),
	}
	err = sessionRepo.Create(ctx, session)
	require.NoError(t, err)

	return user, session
}

func TestRefreshTokenRepository_CreateAndFind(t *testing.T) {
	ctx := context.Background()
	rtRepo := repoPostgres.NewRefreshTokenRepositoryPostgres(testDB)
	clearRefreshTokenTestTables(t)

	_, session := createPrerequisitesForRefreshTokenTests(ctx, t)

	opaqueToken := "test_opaque_refresh_token_value_CreateAndFind"
	hasher := sha256.New()
	hasher.Write([]byte(opaqueToken))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))

	newRT := &models.RefreshToken{
		ID:        uuid.New(),
		SessionID: session.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := rtRepo.Create(ctx, newRT)
	require.NoError(t, err)

	// Find by ID
	foundByID, err := rtRepo.FindByID(ctx, newRT.ID)
	require.NoError(t, err)
	require.NotNil(t, foundByID)
	assert.Equal(t, newRT.SessionID, foundByID.SessionID)
	assert.Equal(t, newRT.TokenHash, foundByID.TokenHash)
	assert.WithinDuration(t, newRT.ExpiresAt, foundByID.ExpiresAt, time.Second)

	// Find by Token Hash
	foundByHash, err := rtRepo.FindByTokenHash(ctx, tokenHash)
	require.NoError(t, err)
	require.NotNil(t, foundByHash)
	assert.Equal(t, newRT.ID, foundByHash.ID)
}

func TestRefreshTokenRepository_Revoke(t *testing.T) {
	ctx := context.Background()
	rtRepo := repoPostgres.NewRefreshTokenRepositoryPostgres(testDB)
	clearRefreshTokenTestTables(t)
	_, session := createPrerequisitesForRefreshTokenTests(ctx, t)

	opaqueToken := "test_opaque_refresh_token_value_Revoke"
	hasher := sha256.New()
	hasher.Write([]byte(opaqueToken))
	tokenHash := hex.EncodeToString(hasher.Sum(nil))

	rt := &models.RefreshToken{
		ID: uuid.New(), SessionID: session.ID, TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := rtRepo.Create(ctx, rt)
	require.NoError(t, err)

	// Revoke the token
	err = rtRepo.Revoke(ctx, rt.ID)
	require.NoError(t, err)

	revokedRT, err := rtRepo.FindByID(ctx, rt.ID)
	require.NoError(t, err) // FindByID should still find it
	require.NotNil(t, revokedRT)
	require.NotNil(t, revokedRT.RevokedAt, "RevokedAt should be set")
	assert.WithinDuration(t, time.Now(), *revokedRT.RevokedAt, time.Second)

	// Attempting to find by hash should now fail if FindByTokenHash filters revoked tokens
	// (Assuming FindByTokenHash filters out revoked tokens)
	foundByHashAfterRevoke, err := rtRepo.FindByTokenHash(ctx, tokenHash)
	require.Error(t, err)
	assert.True(t, errors.Is(err, domainErrors.ErrNotFound), "Expected ErrNotFound for revoked token by hash")
	assert.Nil(t, foundByHashAfterRevoke)
}

func TestRefreshTokenRepository_RevokeAllByUserID(t *testing.T) {
	ctx := context.Background()
	rtRepo := repoPostgres.NewRefreshTokenRepositoryPostgres(testDB)
	clearRefreshTokenTestTables(t)

	user1, session1User1 := createPrerequisitesForRefreshTokenTests(ctx, t)
	_, session2User1 := createPrerequisitesForRefreshTokenTests(ctx, t) // User1, Session2
	user2, session1User2 := createPrerequisitesForRefreshTokenTests(ctx, t)

	rt1User1 := &models.RefreshToken{ID: uuid.New(), SessionID: session1User1.ID, TokenHash: "hash1u1", ExpiresAt: time.Now().Add(time.Hour)}
	err := rtRepo.Create(ctx, rt1User1)
	require.NoError(t, err)
	rt2User1 := &models.RefreshToken{ID: uuid.New(), SessionID: session2User1.ID, TokenHash: "hash2u1", ExpiresAt: time.Now().Add(time.Hour)}
	err = rtRepo.Create(ctx, rt2User1)
	require.NoError(t, err)
	rt1User2 := &models.RefreshToken{ID: uuid.New(), SessionID: session1User2.ID, TokenHash: "hash1u2", ExpiresAt: time.Now().Add(time.Hour)}
	err = rtRepo.Create(ctx, rt1User2)
	require.NoError(t, err)

	// Revoke all for user1
	revokedCount, err := rtRepo.RevokeAllByUserID(ctx, user1.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), revokedCount)

	// Check user1's tokens are revoked
	rt1u1Db, err := rtRepo.FindByID(ctx, rt1User1.ID)
	require.NoError(t, err)
	assert.NotNil(t, rt1u1Db.RevokedAt)
	rt2u1Db, err := rtRepo.FindByID(ctx, rt2User1.ID)
	require.NoError(t, err)
	assert.NotNil(t, rt2u1Db.RevokedAt)

	// Check user2's token is not revoked
	rt1u2Db, err := rtRepo.FindByID(ctx, rt1User2.ID)
	require.NoError(t, err)
	assert.Nil(t, rt1u2Db.RevokedAt)
}

func TestRefreshTokenRepository_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	rtRepo := repoPostgres.NewRefreshTokenRepositoryPostgres(testDB)
	clearRefreshTokenTestTables(t)
	_, session1 := createPrerequisitesForRefreshTokenTests(ctx, t)
	_, session2 := createPrerequisitesForRefreshTokenTests(ctx, t)

	// Expired token
	rtExpired := &models.RefreshToken{
		ID: uuid.New(), SessionID: session1.ID, TokenHash: "hash_expired_rt",
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired yesterday
	}
	err := rtRepo.Create(ctx, rtExpired)
	require.NoError(t, err)

	// Active token
	rtActive := &models.RefreshToken{
		ID: uuid.New(), SessionID: session2.ID, TokenHash: "hash_active_rt",
		ExpiresAt: time.Now().Add(24 * time.Hour), // Expires tomorrow
	}
	err = rtRepo.Create(ctx, rtActive)
	require.NoError(t, err)

	deletedCount, err := rtRepo.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.True(t, deletedCount >= 1, "At least one expired refresh token should be deleted")

	foundExpired, err := rtRepo.FindByID(ctx, rtExpired.ID)
	assert.Error(t, err) // Should be an error if it's deleted
	assert.True(t, errors.Is(err, domainErrors.ErrNotFound), "Expected ErrNotFound for deleted expired token")
	assert.Nil(t, foundExpired)

	foundActive, err := rtRepo.FindByID(ctx, rtActive.ID)
	assert.NoError(t, err)
	assert.NotNil(t, foundActive)
}
