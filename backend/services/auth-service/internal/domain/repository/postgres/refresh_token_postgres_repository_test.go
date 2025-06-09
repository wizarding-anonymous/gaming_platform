// File: backend/services/auth-service/internal/domain/repository/postgres/refresh_token_repository_test.go
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

	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/domain/repository/postgres"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/infrastructure/security" // For hashing tokens

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// DSN and migrations path constants (same as user_repository_test.go)
// const (
// 	testPostgresDSNEnv = "TEST_AUTH_POSTGRES_DSN"
// 	defaultTestDSN     = "postgres://testuser:testpassword@localhost:5433/auth_test_db?sslmode=disable"
// 	defaultMigrationsPath = "file://../../../../migrations" // Adjust this path!
// )

type RefreshTokenRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	userRepo   *postgres.UserRepositoryPostgres
	sessionRepo *postgres.SessionRepositoryPostgres
	repo       *postgres.RefreshTokenRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
}

func TestRefreshTokenRepositoryTestSuite(t *testing.T) {
	dsn := os.Getenv(testPostgresDSNEnv)
	if dsn == "" {
		dsn = defaultTestDSN
	}

	migrationsPath := os.Getenv("MIGRATIONS_PATH")
	if migrationsPath == "" {
		migrationsPath = defaultMigrationsPath // Defined in user_repository_test.go, ensure it's accessible or redefine
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
	t.Log("Migrations applied successfully for refresh token tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &RefreshTokenRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *RefreshTokenRepositoryTestSuite) SetupSuite() {}

func (s *RefreshTokenRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for refresh token tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for refresh token tests rolled back successfully.")
		}
	}
}

func (s *RefreshTokenRepositoryTestSuite) SetupTest() {
	s.userRepo = postgres.NewUserRepositoryPostgres(s.pool)
	s.sessionRepo = postgres.NewSessionRepositoryPostgres(s.pool)
	s.repo = postgres.NewRefreshTokenRepositoryPostgres(s.pool)

	// Clean data from tables before each test
	_, err := s.pool.Exec(context.Background(), `
		TRUNCATE TABLE refresh_tokens CASCADE;
		TRUNCATE TABLE sessions CASCADE;
		TRUNCATE TABLE users CASCADE;
	`)
	require.NoError(s.T(), err, "Failed to clean tables before test")
}

// Helper to create a user and a session for tests
func (s *RefreshTokenRepositoryTestSuite) helperCreateUserAndSession(ctx context.Context, username, email string) (*models.User, *models.Session) {
	user := &models.User{
		ID: uuid.New(), Username: username, Email: email, PasswordHash: "hash", Status: models.UserStatusActive,
	}
	err := s.userRepo.Create(ctx, user)
	require.NoError(s.T(), err)

	session := &models.Session{
		ID: uuid.New(), UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour), LastActivityAt: time.Now(),
	}
	err = s.sessionRepo.Create(ctx, session)
	require.NoError(s.T(), err)
	return user, session
}

func (s *RefreshTokenRepositoryTestSuite) TestCreateRefreshToken_Success() {
	ctx := context.Background()
	_, session := s.helperCreateUserAndSession(ctx, "user_rt_create", "rt_create@example.com")

	tokenID := uuid.New()
	tokenHash := security.HashToken("test_token_value") // Assuming a simple hash for testing
	refreshToken := &models.RefreshToken{
		ID:        tokenID,
		SessionID: session.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := s.repo.Create(ctx, refreshToken)
	require.NoError(s.T(), err)

	fetchedToken, errFetch := s.repo.FindByID(ctx, tokenID)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetchedToken)
	assert.Equal(s.T(), tokenHash, fetchedToken.TokenHash)
	assert.Equal(s.T(), session.ID, fetchedToken.SessionID)
}

func (s *RefreshTokenRepositoryTestSuite) TestCreateRefreshToken_NonExistentSession() {
	ctx := context.Background()
	refreshToken := &models.RefreshToken{
		ID:        uuid.New(),
		SessionID: uuid.New(), // Non-existent session
		TokenHash: security.HashToken("test_token_fk_error"),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := s.repo.Create(ctx, refreshToken)
	require.Error(s.T(), err) // Expect foreign key violation
	// Note: Specific error type for FK violation depends on pgx driver and DB error code.
	// For now, just checking for a generic error.
}

func (s *RefreshTokenRepositoryTestSuite) TestCreateRefreshToken_DuplicateTokenHash() {
	ctx := context.Background()
	_, session := s.helperCreateUserAndSession(ctx, "user_rt_dup", "rt_dup@example.com")
	tokenHash := security.HashToken("duplicate_token_hash_value")

	rt1 := &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: tokenHash, ExpiresAt: time.Now().Add(time.Hour)}
	err := s.repo.Create(ctx, rt1)
	require.NoError(s.T(), err)

	rt2 := &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: tokenHash, ExpiresAt: time.Now().Add(time.Hour)}
	errCreate := s.repo.Create(ctx, rt2)
	require.Error(s.T(), errCreate)
	assert.ErrorIs(s.T(), errCreate, domainErrors.ErrDuplicateValue)
}


func (s *RefreshTokenRepositoryTestSuite) TestFindByID_SuccessAndNotFound() {
	ctx := context.Background()
	_, session := s.helperCreateUserAndSession(ctx, "user_rt_find", "rt_find@example.com")
	refreshToken := &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: "h1", ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, refreshToken)

	// Success
	fetched, err := s.repo.FindByID(ctx, refreshToken.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), refreshToken.TokenHash, fetched.TokenHash)

	// Not Found
	_, err = s.repo.FindByID(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *RefreshTokenRepositoryTestSuite) TestFindByTokenHash_Scenarios() {
	ctx := context.Background()
	_, session := s.helperCreateUserAndSession(ctx, "user_rt_findhash", "rt_findhash@example.com")

	activeTokenValue := "active_token"
	activeTokenHash := security.HashToken(activeTokenValue)
	activeRT := &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: activeTokenHash, ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, activeRT)

	expiredTokenValue := "expired_token"
	expiredTokenHash := security.HashToken(expiredTokenValue)
	expiredRT := &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: expiredTokenHash, ExpiresAt: time.Now().Add(-time.Hour)}
	s.repo.Create(ctx, expiredRT)

	revokedTokenValue := "revoked_token"
	revokedTokenHash := security.HashToken(revokedTokenValue)
	revokedTime := time.Now().Add(-time.Minute)
	revokedRT := &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: revokedTokenHash, ExpiresAt: time.Now().Add(time.Hour), RevokedAt: &revokedTime}
	s.repo.Create(ctx, revokedRT)

	// Success (active)
	fetched, err := s.repo.FindByTokenHash(ctx, activeTokenHash)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), activeRT.ID, fetched.ID)

	// Not Found (wrong hash)
	_, err = s.repo.FindByTokenHash(ctx, security.HashToken("wrong_token"))
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Expired token
	_, err = s.repo.FindByTokenHash(ctx, expiredTokenHash)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound) // FindByTokenHash only finds active

	// Revoked token
	_, err = s.repo.FindByTokenHash(ctx, revokedTokenHash)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound) // FindByTokenHash only finds active
}

func (s *RefreshTokenRepositoryTestSuite) TestFindBySessionID_SuccessAndNotFound() {
	ctx := context.Background()
	_, session1 := s.helperCreateUserAndSession(ctx, "user_rt_sfind1", "rt_sfind1@example.com")
	_, session2 := s.helperCreateUserAndSession(ctx, "user_rt_sfind2", "rt_sfind2@example.com") // For not found case

	rt1 := &models.RefreshToken{ID: uuid.New(), SessionID: session1.ID, TokenHash: "h_s1_1", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now().Add(-time.Minute)}
	s.repo.Create(ctx, rt1)
	// Newer token for same session, should be preferred
	rt2 := &models.RefreshToken{ID: uuid.New(), SessionID: session1.ID, TokenHash: "h_s1_2", ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	s.repo.Create(ctx, rt2)

	// Success (finds latest active for session1)
	fetched, err := s.repo.FindBySessionID(ctx, session1.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), rt2.ID, fetched.ID)

	// Not Found (for session2 which has no tokens)
	_, err = s.repo.FindBySessionID(ctx, session2.ID)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *RefreshTokenRepositoryTestSuite) TestRevokeToken_SuccessAndFailures() {
	ctx := context.Background()
	_, session := s.helperCreateUserAndSession(ctx, "user_rt_revoke", "rt_revoke@example.com")
	rt := &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: "h_revoke", ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, rt)

	reason := "user_logout"
	// Success
	err := s.repo.Revoke(ctx, rt.ID, &reason)
	require.NoError(s.T(), err)
	fetched, _ := s.repo.FindByID(ctx, rt.ID)
	require.NotNil(s.T(), fetched.RevokedAt)
	require.NotNil(s.T(), fetched.RevokedReason)
	assert.Equal(s.T(), reason, *fetched.RevokedReason)

	// Already revoked
	err = s.repo.Revoke(ctx, rt.ID, &reason)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound) // Or a specific "already revoked" error

	// Non-existent token
	err = s.repo.Revoke(ctx, uuid.New(), &reason)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *RefreshTokenRepositoryTestSuite) TestDeleteToken_SuccessAndNotFound() {
	ctx := context.Background()
	_, session := s.helperCreateUserAndSession(ctx, "user_rt_delete", "rt_delete@example.com")
	rt := &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: "h_delete", ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, rt)

	// Success
	err := s.repo.Delete(ctx, rt.ID)
	require.NoError(s.T(), err)
	_, errFind := s.repo.FindByID(ctx, rt.ID)
	assert.ErrorIs(s.T(), errFind, domainErrors.ErrNotFound)

	// Not Found
	err = s.repo.Delete(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *RefreshTokenRepositoryTestSuite) TestDeleteBySessionID_Success() {
	ctx := context.Background()
	_, session1 := s.helperCreateUserAndSession(ctx, "user_sdel1", "sdel1@example.com")
	_, session2 := s.helperCreateUserAndSession(ctx, "user_sdel2", "sdel2@example.com")

	s.repo.Create(ctx, &models.RefreshToken{ID: uuid.New(), SessionID: session1.ID, TokenHash: "s1t1", ExpiresAt: time.Now().Add(time.Hour)})
	s.repo.Create(ctx, &models.RefreshToken{ID: uuid.New(), SessionID: session1.ID, TokenHash: "s1t2", ExpiresAt: time.Now().Add(time.Hour)})
	s.repo.Create(ctx, &models.RefreshToken{ID: uuid.New(), SessionID: session2.ID, TokenHash: "s2t1", ExpiresAt: time.Now().Add(time.Hour)})

	err := s.repo.DeleteBySessionID(ctx, session1.ID)
	require.NoError(s.T(), err)

	_, errFetchS1 := s.repo.FindBySessionID(ctx, session1.ID)
	assert.ErrorIs(s.T(), errFetchS1, domainErrors.ErrNotFound)

	fetchedS2, errFetchS2 := s.repo.FindBySessionID(ctx, session2.ID)
	require.NoError(s.T(), errFetchS2)
	assert.NotNil(s.T(), fetchedS2) // Token for session2 should still exist
}

func (s *RefreshTokenRepositoryTestSuite) TestDeleteExpiredAndRevoked() {
	ctx := context.Background()
	_, session := s.helperCreateUserAndSession(ctx, "user_rt_exp_rev", "rt_exprv@example.com")

	// Expired
	s.repo.Create(ctx, &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: "exp1", ExpiresAt: time.Now().Add(-time.Hour)})
	// Revoked recently
	revokedTimeRecent := time.Now().Add(-time.Minute)
	s.repo.Create(ctx, &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: "rev1_recent", ExpiresAt: time.Now().Add(time.Hour), RevokedAt: &revokedTimeRecent})
	// Revoked long ago
	revokedTimeOld := time.Now().Add(-48 * time.Hour)
	s.repo.Create(ctx, &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: "rev2_old", ExpiresAt: time.Now().Add(time.Hour), RevokedAt: &revokedTimeOld})
	// Active
	activeToken := &models.RefreshToken{ID: uuid.New(), SessionID: session.ID, TokenHash: "active1", ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, activeToken)

	// Delete expired, and revoked tokens older than 1 day (24 hours)
	deletedCount, err := s.repo.DeleteExpiredAndRevoked(ctx, 24*time.Hour)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 2, deletedCount) // exp1 and rev2_old

	// Verify activeToken and rev1_recent still exist
	_, err = s.repo.FindByID(ctx, activeToken.ID)
	assert.NoError(s.T(), err, "Active token should still exist")

	_, err = s.repo.FindByTokenHash(ctx, security.HashToken("revoked_token_recent")) // This would fail if token is revoked
	// A better check is to FindByID and check RevokedAt
	fetchedRevokedRecent, err := s.repo.FindByID(ctx, revokedRT.ID) // Assuming revokedRT is the one with rev1_recent
	require.NoError(s.T(), err, "Recently revoked token should still exist if not older than period")
	assert.NotNil(s.T(), fetchedRevokedRecent.RevokedAt)


	// Test with zero duration (delete all revoked)
	deletedCount, err = s.repo.DeleteExpiredAndRevoked(ctx, 0)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 1, deletedCount) // rev1_recent should be deleted now

	_, err = s.repo.FindByID(ctx, activeToken.ID) // Active token should still be there
	assert.NoError(s.T(), err)
}


func (s *RefreshTokenRepositoryTestSuite) TestDeleteByUserID() {
	ctx := context.Background()
	user1, session1_1 := s.helperCreateUserAndSession(ctx, "user1_del_uid", "u1_del@example.com")
	_, session1_2 := s.helperCreateUserAndSession(ctx, user1.Username+"_s2", user1.Email+"_s2") // Same user, different session
	user2, session2_1 := s.helperCreateUserAndSession(ctx, "user2_keep", "u2_keep@example.com")

	// User1 tokens
	s.repo.Create(ctx, &models.RefreshToken{ID: uuid.New(), SessionID: session1_1.ID, TokenHash: "u1s1t1", ExpiresAt: time.Now().Add(time.Hour)})
	s.repo.Create(ctx, &models.RefreshToken{ID: uuid.New(), SessionID: session1_2.ID, TokenHash: "u1s2t1", ExpiresAt: time.Now().Add(time.Hour)})

	// User2 token
	rtUser2 := &models.RefreshToken{ID: uuid.New(), SessionID: session2_1.ID, TokenHash: "u2s1t1", ExpiresAt: time.Now().Add(time.Hour)}
	s.repo.Create(ctx, rtUser2)

	// Delete tokens for user1
	deletedCount, err := s.repo.DeleteByUserID(ctx, user1.ID)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 2, deletedCount)

	// Verify user1 tokens are gone
	_, err = s.repo.FindBySessionID(ctx, session1_1.ID)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
	_, err = s.repo.FindBySessionID(ctx, session1_2.ID)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Verify user2 token still exists
	fetchedUser2Token, err := s.repo.FindByTokenHash(ctx, rtUser2.TokenHash)
	require.NoError(s.T(), err)
	assert.NotNil(s.T(), fetchedUser2Token)
	assert.Equal(s.T(), rtUser2.ID, fetchedUser2Token.ID)
}
