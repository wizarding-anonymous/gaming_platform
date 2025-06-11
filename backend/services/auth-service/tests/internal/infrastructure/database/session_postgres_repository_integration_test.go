// File: backend/services/auth-service/tests/internal/infrastructure/database/session_postgres_repository_integration_test.go
package database

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	repoPostgres "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres"
	// argon2Service and testDB are global from user_postgres_repository_integration_test.go's TestMain
)

// Helper to clear session-related tables (and users for FKs)
func clearSessionTestTables(t *testing.T) {
	t.Helper()
	// Order matters for FKs: refresh_tokens references sessions, sessions references users
	tables := []string{"refresh_tokens", "sessions", "users"}
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

func createTestUserForSessionTests(ctx context.Context, t *testing.T) *models.User {
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	hashedPassword, _ := argon2Service.HashPassword("password123")
	user := &models.User{
		ID:           uuid.New(),
		Username:     fmt.Sprintf("user_sess_%s", uuid.NewString()[:8]),             // Unique username
		Email:        fmt.Sprintf("user_sess_%s@example.com", uuid.NewString()[:8]), // Unique email
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	return user
}

func TestSessionRepository_CreateAndFind(t *testing.T) {
	ctx := context.Background()
	sessionRepo := repoPostgres.NewSessionRepositoryPostgres(testDB)
	clearSessionTestTables(t)

	user := createTestUserForSessionTests(ctx, t)

	newSession := &models.Session{
		ID:             uuid.New(),
		UserID:         user.ID,
		UserAgent:      "TestAgent/1.0",
		IPAddress:      "127.0.0.1",
		ExpiresAt:      time.Now().Add(24 * time.Hour),
		LastActivityAt: time.Now(),
	}

	err := sessionRepo.Create(ctx, newSession)
	require.NoError(t, err)

	// Find by ID
	foundByID, err := sessionRepo.FindByID(ctx, newSession.ID)
	require.NoError(t, err)
	require.NotNil(t, foundByID)
	assert.Equal(t, newSession.UserID, foundByID.UserID)
	assert.Equal(t, newSession.UserAgent, foundByID.UserAgent)
	assert.WithinDuration(t, newSession.ExpiresAt, foundByID.ExpiresAt, time.Second)
	assert.WithinDuration(t, newSession.LastActivityAt, foundByID.LastActivityAt, time.Second)

	// Find by UserID
	sessionsForUser, err := sessionRepo.FindByUserID(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, sessionsForUser, 1)
	assert.Equal(t, newSession.ID, sessionsForUser[0].ID)
}

func TestSessionRepository_UpdateLastActivity(t *testing.T) {
	ctx := context.Background()
	sessionRepo := repoPostgres.NewSessionRepositoryPostgres(testDB)
	clearSessionTestTables(t)
	user := createTestUserForSessionTests(ctx, t)

	initialLastActivity := time.Now().Add(-1 * time.Hour)
	session := &models.Session{
		ID: uuid.New(), UserID: user.ID, UserAgent: "TestAgent", IPAddress: "127.0.0.1",
		ExpiresAt: time.Now().Add(24 * time.Hour), LastActivityAt: initialLastActivity,
	}
	err := sessionRepo.Create(ctx, session)
	require.NoError(t, err)

	newLastActivity := time.Now().Add(10 * time.Minute) // Ensure it's different
	err = sessionRepo.UpdateLastActivityAt(ctx, session.ID, newLastActivity)
	require.NoError(t, err)

	updatedSession, err := sessionRepo.FindByID(ctx, session.ID)
	require.NoError(t, err)
	require.NotNil(t, updatedSession)
	// Compare seconds because of potential microsecond differences in DB
	assert.Equal(t, newLastActivity.Unix(), updatedSession.LastActivityAt.Unix())
}

func TestSessionRepository_Delete(t *testing.T) {
	ctx := context.Background()
	sessionRepo := repoPostgres.NewSessionRepositoryPostgres(testDB)
	clearSessionTestTables(t)
	user := createTestUserForSessionTests(ctx, t)

	session := &models.Session{
		ID: uuid.New(), UserID: user.ID, UserAgent: "TestAgent", IPAddress: "127.0.0.1",
		ExpiresAt: time.Now().Add(24 * time.Hour), LastActivityAt: time.Now(),
	}
	err := sessionRepo.Create(ctx, session)
	require.NoError(t, err)

	err = sessionRepo.Delete(ctx, session.ID)
	require.NoError(t, err)

	foundSession, err := sessionRepo.FindByID(ctx, session.ID)
	assert.Error(t, err) // Should be an error indicating not found
	assert.True(t, errors.Is(err, domainErrors.ErrNotFound), "Expected ErrNotFound")
	assert.Nil(t, foundSession)
}

func TestSessionRepository_DeleteAllByUserID(t *testing.T) {
	ctx := context.Background()
	sessionRepo := repoPostgres.NewSessionRepositoryPostgres(testDB)
	clearSessionTestTables(t)
	user1 := createTestUserForSessionTests(ctx, t)
	user2 := createTestUserForSessionTests(ctx, t) // Another user

	// Create sessions for user1
	session1User1 := &models.Session{ID: uuid.New(), UserID: user1.ID, LastActivityAt: time.Now()}
	err := sessionRepo.Create(ctx, session1User1)
	require.NoError(t, err)
	session2User1 := &models.Session{ID: uuid.New(), UserID: user1.ID, LastActivityAt: time.Now()}
	err = sessionRepo.Create(ctx, session2User1)
	require.NoError(t, err)

	// Create session for user2
	session1User2 := &models.Session{ID: uuid.New(), UserID: user2.ID, LastActivityAt: time.Now()}
	err = sessionRepo.Create(ctx, session1User2)
	require.NoError(t, err)

	// Delete all sessions for user1
	deletedCount, err := sessionRepo.DeleteAllByUserID(ctx, user1.ID, nil) // No session to exclude
	require.NoError(t, err)
	assert.Equal(t, int64(2), deletedCount)

	user1Sessions, err := sessionRepo.FindByUserID(ctx, user1.ID)
	require.NoError(t, err)
	assert.Len(t, user1Sessions, 0)

	user2Sessions, err := sessionRepo.FindByUserID(ctx, user2.ID)
	require.NoError(t, err)
	assert.Len(t, user2Sessions, 1, "User2's session should remain")
	assert.Equal(t, session1User2.ID, user2Sessions[0].ID)
}

func TestSessionRepository_DeleteAllByUserID_ExcludeOne(t *testing.T) {
	ctx := context.Background()
	sessionRepo := repoPostgres.NewSessionRepositoryPostgres(testDB)
	clearSessionTestTables(t)
	user1 := createTestUserForSessionTests(ctx, t)

	sessionToKeep := &models.Session{ID: uuid.New(), UserID: user1.ID, LastActivityAt: time.Now()}
	err := sessionRepo.Create(ctx, sessionToKeep)
	require.NoError(t, err)
	sessionToDelete := &models.Session{ID: uuid.New(), UserID: user1.ID, LastActivityAt: time.Now()}
	err = sessionRepo.Create(ctx, sessionToDelete)
	require.NoError(t, err)

	// Delete all sessions for user1, excluding sessionToKeep
	deletedCount, err := sessionRepo.DeleteAllByUserID(ctx, user1.ID, &sessionToKeep.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deletedCount)

	user1Sessions, err := sessionRepo.FindByUserID(ctx, user1.ID)
	require.NoError(t, err)
	assert.Len(t, user1Sessions, 1)
	assert.Equal(t, sessionToKeep.ID, user1Sessions[0].ID)
}

func TestSessionRepository_DeleteExpired(t *testing.T) {
	ctx := context.Background()
	sessionRepo := repoPostgres.NewSessionRepositoryPostgres(testDB)
	clearSessionTestTables(t)
	user1 := createTestUserForSessionTests(ctx, t)

	// Expired session
	sessionExpired := &models.Session{
		ID: uuid.New(), UserID: user1.ID, LastActivityAt: time.Now().Add(-48 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired yesterday
	}
	err := sessionRepo.Create(ctx, sessionExpired)
	require.NoError(t, err)

	// Active session
	sessionActive := &models.Session{
		ID: uuid.New(), UserID: user1.ID, LastActivityAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // Expires tomorrow
	}
	err = sessionRepo.Create(ctx, sessionActive)
	require.NoError(t, err)

	deletedCount, err := sessionRepo.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.True(t, deletedCount >= 1, "At least one expired session should be deleted")

	foundExpired, err := sessionRepo.FindByID(ctx, sessionExpired.ID)
	assert.Error(t, err)
	assert.Nil(t, foundExpired)

	foundActive, err := sessionRepo.FindByID(ctx, sessionActive.ID)
	assert.NoError(t, err)
	assert.NotNil(t, foundActive)
}
