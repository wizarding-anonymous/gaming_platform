// File: backend/services/auth-service/internal/domain/repository/postgres/session_repository_test.go
package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres"
	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// DSN and migrations path constants (ensure these are consistent with other tests or centralized)
// const (
// 	testPostgresDSNEnv = "TEST_AUTH_POSTGRES_DSN" // Defined in user_repository_test.go
// 	defaultTestDSN     = "postgres://testuser:testpassword@localhost:5433/auth_test_db?sslmode=disable" // Defined in user_repository_test.go
// 	defaultMigrationsPath = "file://../../../../migrations" // Defined in user_repository_test.go
// )

type SessionRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	userRepo   *postgres.UserRepositoryPostgres // For creating prerequisite users
	repo       *postgres.SessionRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
}

func TestSessionRepositoryTestSuite(t *testing.T) {
	dsn := os.Getenv(testPostgresDSNEnv)
	if dsn == "" {
		dsn = defaultTestDSN
	}

	migrationsPath := os.Getenv("MIGRATIONS_PATH")
	if migrationsPath == "" {
		migrationsPath = defaultMigrationsPath
	}
	if !strings.HasPrefix(migrationsPath, "file://") {
		migrationsPath = "file://" + migrationsPath
	}

	if os.Getenv(testPostgresDSNEnv) == "" && dsn == defaultTestDSN {
		_, errCfg := pgxpool.ParseConfig(dsn)
		if errCfg != nil {
			t.Logf("Default test DSN is invalid, skipping repo tests: %v", errCfg)
			t.Skip("Skipping repository tests: TEST_AUTH_POSTGRES_DSN not set and default DSN is invalid.")
			return
		}
		tempPool, errConn := pgxpool.New(context.Background(), dsn)
		if errConn != nil {
			t.Logf("Default test DSN not connectable, skipping repo tests: %v", errConn)
			t.Skip("Skipping repository tests: TEST_AUTH_POSTGRES_DSN not set and default DSN not connectable.")
			return
		}
		tempPool.Close()
	}

	m, err := migrate.New(migrationsPath, dsn)
	if err != nil {
		t.Fatalf("Failed to create migration instance (path: %s, dsn: %s): %v", migrationsPath, dsn, err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("Failed to apply migrations: %v", err)
	}
	t.Log("Migrations applied successfully for session tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &SessionRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *SessionRepositoryTestSuite) SetupSuite() {}

func (s *SessionRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for session tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for session tests rolled back successfully.")
		}
	}
}

func (s *SessionRepositoryTestSuite) SetupTest() {
	s.userRepo = postgres.NewUserRepositoryPostgres(s.pool)
	s.repo = postgres.NewSessionRepositoryPostgres(s.pool)

	_, err := s.pool.Exec(context.Background(), `
		TRUNCATE TABLE sessions CASCADE;
		TRUNCATE TABLE users CASCADE;
	`) // user_roles, verification_codes etc. also truncated due to CASCADE from users
	require.NoError(s.T(), err, "Failed to clean tables before test")
}

// Helper to create a user for tests
func (s *SessionRepositoryTestSuite) helperCreateUser(usernameSuffix string) *models.User {
	ctx := context.Background()
	user := &models.User{
		ID:           uuid.New(),
		Username:     fmt.Sprintf("user_%s", usernameSuffix),
		Email:        fmt.Sprintf("user_%s@example.com", usernameSuffix),
		PasswordHash: "hash",
		Status:       models.UserStatusActive,
		CreatedAt:    time.Now().UTC().Truncate(time.Millisecond),
	}
	err := s.userRepo.Create(ctx, user)
	require.NoError(s.T(), err)
	return user
}

func (s *SessionRepositoryTestSuite) TestCreateSession_Success() {
	ctx := context.Background()
	user := s.helperCreateUser("create_session")

	sessionID := uuid.New()
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Millisecond)
	lastActivityAt := time.Now().UTC().Truncate(time.Millisecond)
	userAgent := "test-agent"
	ipAddress := "127.0.0.1"

	session := &models.Session{
		ID:             sessionID,
		UserID:         user.ID,
		UserAgent:      &userAgent,
		IPAddress:      &ipAddress,
		ExpiresAt:      expiresAt,
		LastActivityAt: lastActivityAt,
		// CreatedAt handled by DB default
	}

	err := s.repo.Create(ctx, session)
	require.NoError(s.T(), err)

	fetchedSession, errFetch := s.repo.GetByID(ctx, sessionID)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetchedSession)
	assert.Equal(s.T(), user.ID, fetchedSession.UserID)
	assert.Equal(s.T(), userAgent, *fetchedSession.UserAgent)
	assert.Equal(s.T(), ipAddress, *fetchedSession.IPAddress)
	assert.WithinDuration(s.T(), expiresAt, fetchedSession.ExpiresAt, time.Second)
	assert.WithinDuration(s.T(), lastActivityAt, fetchedSession.LastActivityAt, time.Second)
	assert.NotZero(s.T(), fetchedSession.CreatedAt)
}

func (s *SessionRepositoryTestSuite) TestCreateSession_NonExistentUser() {
	ctx := context.Background()
	nonExistentUserID := uuid.New()
	session := &models.Session{
		ID:        uuid.New(),
		UserID:    nonExistentUserID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := s.repo.Create(ctx, session)
	require.Error(s.T(), err) // Expect foreign key violation
}

func (s *SessionRepositoryTestSuite) TestGetByID_SuccessAndNotFound() {
	ctx := context.Background()
	user := s.helperCreateUser("getbyid_session")
	session := &models.Session{ID: uuid.New(), UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, session)

	// Success
	fetched, err := s.repo.GetByID(ctx, session.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), session.UserID, fetched.UserID)

	// Not Found
	_, err = s.repo.GetByID(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrSessionNotFound)
}

func (s *SessionRepositoryTestSuite) TestGetUserSessions_VariousScenarios() {
	ctx := context.Background()
	user1 := s.helperCreateUser("user1_sessions")
	user2 := s.helperCreateUser("user2_sessions") // To ensure we only get user1's sessions

	now := time.Now().UTC()
	s1 := &models.Session{ID: uuid.New(), UserID: user1.ID, ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-3 * time.Minute), LastActivityAt: now.Add(-3 * time.Minute)}
	s2 := &models.Session{ID: uuid.New(), UserID: user1.ID, ExpiresAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Minute), LastActivityAt: now.Add(-2 * time.Minute)} // Expired
	s3 := &models.Session{ID: uuid.New(), UserID: user1.ID, ExpiresAt: now.Add(2 * time.Hour), CreatedAt: now.Add(-1 * time.Minute), LastActivityAt: now.Add(-1 * time.Minute)}
	s.repo.Create(ctx, s1)
	s.repo.Create(ctx, s2)
	s.repo.Create(ctx, s3)
	s.repo.Create(ctx, &models.Session{ID: uuid.New(), UserID: user2.ID, ExpiresAt: now.Add(time.Hour)}) // User2's session

	// User with no sessions
	userNoSessions := s.helperCreateUser("no_sessions")
	sessionsNone, totalNone, errNone := s.repo.GetUserSessions(ctx, userNoSessions.ID, models.ListSessionsParams{})
	require.NoError(s.T(), errNone)
	assert.Equal(s.T(), 0, totalNone)
	assert.Empty(s.T(), sessionsNone)

	// User1 all sessions (active and expired)
	sessionsAll, totalAll, errAll := s.repo.GetUserSessions(ctx, user1.ID, models.ListSessionsParams{})
	require.NoError(s.T(), errAll)
	assert.Equal(s.T(), 3, totalAll)
	assert.Len(s.T(), sessionsAll, 3)

	// User1 active only
	sessionsActive, totalActive, errActive := s.repo.GetUserSessions(ctx, user1.ID, models.ListSessionsParams{ActiveOnly: true})
	require.NoError(s.T(), errActive)
	assert.Equal(s.T(), 2, totalActive) // s1 and s3
	assert.Len(s.T(), sessionsActive, 2)

	// User1 pagination (expect 2 per page, get page 1)
	sessionsPage1, totalPage1, errPage1 := s.repo.GetUserSessions(ctx, user1.ID, models.ListSessionsParams{Page: 1, PageSize: 2, OrderBy: "created_at", SortOrder: "ASC"})
	require.NoError(s.T(), errPage1)
	assert.Equal(s.T(), 3, totalPage1)
	assert.Len(s.T(), sessionsPage1, 2)
	assert.Equal(s.T(), s1.ID, sessionsPage1[0].ID) // s1 was created first
	assert.Equal(s.T(), s2.ID, sessionsPage1[1].ID)

	// User1 pagination (expect 2 per page, get page 2)
	sessionsPage2, totalPage2, errPage2 := s.repo.GetUserSessions(ctx, user1.ID, models.ListSessionsParams{Page: 2, PageSize: 2, OrderBy: "created_at", SortOrder: "ASC"})
	require.NoError(s.T(), errPage2)
	assert.Equal(s.T(), 3, totalPage2)
	assert.Len(s.T(), sessionsPage2, 1)
	assert.Equal(s.T(), s3.ID, sessionsPage2[0].ID)
}

func (s *SessionRepositoryTestSuite) TestUpdateSession_Success() {
	ctx := context.Background()
	user := s.helperCreateUser("update_session")
	session := &models.Session{ID: uuid.New(), UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, session)

	newIP := "192.168.0.1"
	newAgent := "updated-agent"
	newLastActivity := time.Now().Add(time.Minute).UTC().Truncate(time.Millisecond)
	newExpiresAt := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Millisecond)

	session.IPAddress = &newIP
	session.UserAgent = &newAgent
	session.LastActivityAt = newLastActivity
	session.ExpiresAt = newExpiresAt

	err := s.repo.Update(ctx, session)
	require.NoError(s.T(), err)

	fetched, _ := s.repo.GetByID(ctx, session.ID)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), newIP, *fetched.IPAddress)
	assert.Equal(s.T(), newAgent, *fetched.UserAgent)
	assert.WithinDuration(s.T(), newLastActivity, fetched.LastActivityAt, time.Second)
	assert.WithinDuration(s.T(), newExpiresAt, fetched.ExpiresAt, time.Second)
}

func (s *SessionRepositoryTestSuite) TestDeleteSession_SuccessAndNotFound() {
	ctx := context.Background()
	user := s.helperCreateUser("delete_session")
	session := &models.Session{ID: uuid.New(), UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, session)

	// Success
	err := s.repo.Delete(ctx, session.ID)
	require.NoError(s.T(), err)
	_, errFind := s.repo.GetByID(ctx, session.ID)
	assert.ErrorIs(s.T(), errFind, domainErrors.ErrSessionNotFound)

	// Not Found
	err = s.repo.Delete(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrSessionNotFound)
}

func (s *SessionRepositoryTestSuite) TestDeleteAllUserSessions_Scenarios() {
	ctx := context.Background()
	user1 := s.helperCreateUser("user1_del_all")
	user2 := s.helperCreateUser("user2_keep_sess")

	s1_u1 := &models.Session{ID: uuid.New(), UserID: user1.ID, ExpiresAt: time.Now().Add(time.Hour)}
	s2_u1 := &models.Session{ID: uuid.New(), UserID: user1.ID, ExpiresAt: time.Now().Add(time.Hour)}
	s1_u2 := &models.Session{ID: uuid.New(), UserID: user2.ID, ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, s1_u1)
	s.repo.Create(ctx, s2_u1)
	s.repo.Create(ctx, s1_u2)

	// Delete all for user1 except s1_u1
	deletedCount, err := s.repo.DeleteAllUserSessions(ctx, user1.ID, &s1_u1.ID)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 1, deletedCount) // s2_u1 should be deleted
	_, err = s.repo.GetByID(ctx, s2_u1.ID)
	assert.ErrorIs(s.T(), err, domainErrors.ErrSessionNotFound)
	_, err = s.repo.GetByID(ctx, s1_u1.ID) // s1_u1 should still exist
	assert.NoError(s.T(), err)

	// Delete all remaining for user1 (which is just s1_u1)
	deletedCount, err = s.repo.DeleteAllUserSessions(ctx, user1.ID, nil)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 1, deletedCount)
	_, err = s.repo.GetByID(ctx, s1_u1.ID)
	assert.ErrorIs(s.T(), err, domainErrors.ErrSessionNotFound)

	// User2 session should still exist
	_, err = s.repo.GetByID(ctx, s1_u2.ID)
	assert.NoError(s.T(), err)

	// User with no sessions
	userNoSessions := s.helperCreateUser("user_no_sess_del")
	deletedCount, err = s.repo.DeleteAllUserSessions(ctx, userNoSessions.ID, nil)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 0, deletedCount)
}

func (s *SessionRepositoryTestSuite) TestDeleteExpiredSessions() {
	ctx := context.Background()
	user := s.helperCreateUser("user_exp_sess")

	s.repo.Create(ctx, &models.Session{ID: uuid.New(), UserID: user.ID, ExpiresAt: time.Now().Add(-time.Hour)})  // Expired
	s.repo.Create(ctx, &models.Session{ID: uuid.New(), UserID: user.ID, ExpiresAt: time.Now().Add(-time.Minute)}) // Expired
	activeSession := &models.Session{ID: uuid.New(), UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}      // Active
	s.repo.Create(ctx, activeSession)

	deletedCount, err := s.repo.DeleteExpiredSessions(ctx)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 2, deletedCount)

	_, err = s.repo.GetByID(ctx, activeSession.ID)
	assert.NoError(s.T(), err, "Active session should not be deleted")

	// Call again, no expired sessions left
	deletedCount, err = s.repo.DeleteExpiredSessions(ctx)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 0, deletedCount)
}

func (s *SessionRepositoryTestSuite) TestCacheMethods_ReturnNotImplemented() {
	ctx := context.Background()
	err := s.repo.StoreSessionInCache(ctx, &models.Session{})
	require.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "not implemented")

	_, err = s.repo.GetUserIDFromCache(ctx, "somekey")
	require.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "not implemented")

	err = s.repo.RemoveSessionFromCache(ctx, "somekey")
	require.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "not implemented")
}
