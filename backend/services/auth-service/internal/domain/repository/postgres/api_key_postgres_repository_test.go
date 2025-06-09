// File: backend/services/auth-service/internal/domain/repository/postgres/api_key_repository_test.go
package postgres_test

import (
	"context"
	"encoding/json"
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
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/infrastructure/security" // For hashing

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// DSN and migrations path constants (ensure these are consistent)
// const (
// 	testPostgresDSNEnv = "TEST_AUTH_POSTGRES_DSN"
// 	defaultTestDSN     = "postgres://testuser:testpassword@localhost:5433/auth_test_db?sslmode=disable"
// 	defaultMigrationsPath = "file://../../../../migrations"
// )

type APIKeyRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	userRepo   *postgres.UserRepositoryPostgres // For creating prerequisite users
	repo       *postgres.APIKeyRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
	testUser   *models.User // A common user for most tests
}

func TestAPIKeyRepositoryTestSuite(t *testing.T) {
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
	t.Log("Migrations applied successfully for API key tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &APIKeyRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *APIKeyRepositoryTestSuite) SetupSuite() {
	s.userRepo = postgres.NewUserRepositoryPostgres(s.pool) // Initialize once for the suite
}

func (s *APIKeyRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for API key tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for API key tests rolled back successfully.")
		}
	}
}

func (s *APIKeyRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewAPIKeyRepositoryPostgres(s.pool)
	// UserRepo is already initialized in SetupSuite

	ctx := context.Background()
	_, err := s.pool.Exec(ctx, `TRUNCATE TABLE api_keys CASCADE; TRUNCATE TABLE users CASCADE;`)
	require.NoError(s.T(), err, "Failed to clean tables before test")

	// Create a common user for tests
	s.testUser = &models.User{
		ID: uuid.New(), Username: "apikey_test_user", Email: "apikey@example.com", PasswordHash: "hash", Status: models.UserStatusActive,
	}
	err = s.userRepo.Create(ctx, s.testUser)
	require.NoError(s.T(), err)
}

// Helper to create an API key
func (s *APIKeyRepositoryTestSuite) helperCreateAPIKey(userID uuid.UUID, name, prefix, hash string, permissions []string, expiresAt *time.Time) *models.APIKey {
	ctx := context.Background()
	permsJSON, err := json.Marshal(permissions)
	require.NoError(s.T(), err)

	apiKey := &models.APIKey{
		ID:          uuid.New(),
		UserID:      userID,
		Name:        name,
		KeyPrefix:   prefix,
		KeyHash:     hash,
		Permissions: permsJSON,
		ExpiresAt:   expiresAt,
	}
	err = s.repo.Create(ctx, apiKey)
	require.NoError(s.T(), err)
	return apiKey
}

func (s *APIKeyRepositoryTestSuite) TestCreateAPIKey_Success() {
	ctx := context.Background()
	keyName := "TestKey_CreateSuccess"
	keyPrefix := "test_pref_create_"
	keyHash := security.HashToken("secretpart_createsuccess")
	permissions := []string{"read:data", "write:data"}
	expiresAt := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Millisecond)

	apiKey := &models.APIKey{
		ID:          uuid.New(),
		UserID:      s.testUser.ID,
		Name:        keyName,
		KeyPrefix:   keyPrefix,
		KeyHash:     keyHash,
		Permissions: json.RawMessage(fmt.Sprintf(`["%s", "%s"]`, permissions[0], permissions[1])),
		ExpiresAt:   &expiresAt,
	}

	err := s.repo.Create(ctx, apiKey)
	require.NoError(s.T(), err)

	fetched, errFetch := s.repo.FindByID(ctx, apiKey.ID)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), keyName, fetched.Name)
	assert.Equal(s.T(), keyPrefix, fetched.KeyPrefix)
	assert.Equal(s.T(), keyHash, fetched.KeyHash)
	var fetchedPerms []string
	json.Unmarshal(fetched.Permissions, &fetchedPerms)
	assert.ElementsMatch(s.T(), permissions, fetchedPerms)
	require.NotNil(s.T(), fetched.ExpiresAt)
	assert.WithinDuration(s.T(), expiresAt, *fetched.ExpiresAt, time.Second)
}

func (s *APIKeyRepositoryTestSuite) TestCreateAPIKey_DuplicatePrefix() {
	ctx := context.Background()
	prefix := "unique_prefix_test"
	s.helperCreateAPIKey(s.testUser.ID, "Key1", prefix, "hash1", nil, nil)

	apiKey2 := &models.APIKey{
		ID: uuid.New(), UserID: s.testUser.ID, Name: "Key2", KeyPrefix: prefix, KeyHash: "hash2",
	}
	err := s.repo.Create(ctx, apiKey2)
	require.Error(s.T(), err) // Schema has UNIQUE constraint on key_prefix
	assert.ErrorIs(s.T(), err, domainErrors.ErrDuplicateValue)
}

func (s *APIKeyRepositoryTestSuite) TestFindByID_SuccessAndNotFound() {
	ctx := context.Background()
	apiKey := s.helperCreateAPIKey(s.testUser.ID, "FindByIDKey", "fbid_", "h1", nil, nil)

	fetched, err := s.repo.FindByID(ctx, apiKey.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), apiKey.Name, fetched.Name)

	_, err = s.repo.FindByID(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *APIKeyRepositoryTestSuite) TestFindByUserIDAndID_SuccessAndFailures() {
	ctx := context.Background()
	otherUser := s.helperCreateUser("other_for_apikey")
	apiKey := s.helperCreateAPIKey(s.testUser.ID, "FindByUIDKey", "fbuid_", "h1", nil, nil)

	// Success
	fetched, err := s.repo.FindByUserIDAndID(ctx, s.testUser.ID, apiKey.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), apiKey.Name, fetched.Name)

	// Key belongs to another user
	_, err = s.repo.FindByUserIDAndID(ctx, otherUser.ID, apiKey.ID)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)

	// Key not found
	_, err = s.repo.FindByUserIDAndID(ctx, s.testUser.ID, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *APIKeyRepositoryTestSuite) TestFindByKeyPrefix_SuccessAndNotFound() {
	ctx := context.Background()
	prefix := "find_by_prefix_"
	apiKey := s.helperCreateAPIKey(s.testUser.ID, "FindByPrefixKey", prefix, "h_fbp", nil, nil)

	fetched, err := s.repo.FindByKeyPrefix(ctx, prefix)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), apiKey.ID, fetched.ID)

	_, err = s.repo.FindByKeyPrefix(ctx, "non_existent_prefix_")
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *APIKeyRepositoryTestSuite) TestListByUserID_Success() {
	ctx := context.Background()
	s.helperCreateAPIKey(s.testUser.ID, "Key1List", "pref1_", "h1", nil, nil)
	s.helperCreateAPIKey(s.testUser.ID, "Key2List", "pref2_", "h2", nil, nil)
	otherUser := s.helperCreateUser("other_list")
	s.helperCreateAPIKey(otherUser.ID, "KeyOtherUser", "pref_other_", "h_other", nil, nil)


	keys, err := s.repo.ListByUserID(ctx, s.testUser.ID)
	require.NoError(s.T(), err)
	assert.Len(s.T(), keys, 2)
	for _, key := range keys {
		assert.Equal(s.T(), "", key.KeyHash, "KeyHash should not be returned in list")
	}

	keysEmpty, err := s.repo.ListByUserID(ctx, uuid.New()) // Non-existent user
	require.NoError(s.T(), err)
	assert.Empty(s.T(), keysEmpty)
}

func (s *APIKeyRepositoryTestSuite) TestUpdateLastUsedAt_Success() {
	ctx := context.Background()
	apiKey := s.helperCreateAPIKey(s.testUser.ID, "LastUsedKey", "lu_", "h_lu", nil, nil)
	require.Nil(s.T(), apiKey.LastUsedAt)

	err := s.repo.UpdateLastUsedAt(ctx, apiKey.ID)
	require.NoError(s.T(), err)

	fetched, _ := s.repo.FindByID(ctx, apiKey.ID)
	require.NotNil(s.T(), fetched.LastUsedAt)
	assert.WithinDuration(s.T(), time.Now(), *fetched.LastUsedAt, 5*time.Second)
}

func (s *APIKeyRepositoryTestSuite) TestUpdateNameAndPermissions_Success() {
	ctx := context.Background()
	apiKey := s.helperCreateAPIKey(s.testUser.ID, "UpdateNamePerms", "unp_", "h_unp", []string{"read"}, nil)

	newName := "Updated Name"
	newPermissions := []string{"read", "write"}
	newPermsJSON, _ := json.Marshal(newPermissions)

	err := s.repo.UpdateNameAndPermissions(ctx, s.testUser.ID, apiKey.ID, newName, newPermsJSON)
	require.NoError(s.T(), err)

	fetched, _ := s.repo.FindByID(ctx, apiKey.ID)
	assert.Equal(s.T(), newName, fetched.Name)
	var fetchedPerms []string
	json.Unmarshal(fetched.Permissions, &fetchedPerms)
	assert.ElementsMatch(s.T(), newPermissions, fetchedPerms)
}

func (s *APIKeyRepositoryTestSuite) TestRevoke_SuccessAndFailures() {
	ctx := context.Background()
	apiKey := s.helperCreateAPIKey(s.testUser.ID, "RevokeKey", "rev_", "h_rev", nil, nil)
	otherUser := s.helperCreateUser("other_for_revoke")

	reason := "compromised"
	// Success
	err := s.repo.Revoke(ctx, s.testUser.ID, apiKey.ID, &reason)
	require.NoError(s.T(), err)
	fetched, _ := s.repo.FindByID(ctx, apiKey.ID)
	require.NotNil(s.T(), fetched.RevokedAt)
	require.NotNil(s.T(), fetched.RevokedReason)
	assert.Equal(s.T(), reason, *fetched.RevokedReason)

	// Already revoked
	err = s.repo.Revoke(ctx, s.testUser.ID, apiKey.ID, &reason)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound) // Or specific "already revoked"

	// Key belongs to another user
	err = s.repo.Revoke(ctx, otherUser.ID, apiKey.ID, &reason)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound) // Or Forbidden
}

func (s *APIKeyRepositoryTestSuite) TestDeleteAPIKey_SuccessAndNotFound() {
	ctx := context.Background()
	apiKey := s.helperCreateAPIKey(s.testUser.ID, "DeleteKey", "del_", "h_del", nil, nil)

	// Success
	err := s.repo.Delete(ctx, apiKey.ID)
	require.NoError(s.T(), err)
	_, errFind := s.repo.FindByID(ctx, apiKey.ID)
	assert.ErrorIs(s.T(), errFind, domainErrors.ErrNotFound)

	// Not Found
	err = s.repo.Delete(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrNotFound)
}

func (s *APIKeyRepositoryTestSuite) TestDeleteExpiredAndRevokedAPIKeys() {
	ctx := context.Background()
	now := time.Now().UTC()

	// Expired
	s.helperCreateAPIKey(s.testUser.ID, "ExpiredKey", "expk_", "hexp", nil, PtrToTime(now.Add(-2*time.Hour)))
	// Revoked recently
	revokedRecentTime := now.Add(-10 * time.Minute)
	apiKeyRevokedRecent := s.helperCreateAPIKey(s.testUser.ID, "RevokedRecentKey", "revr_", "hrev_r", nil, PtrToTime(now.Add(time.Hour)))
	s.repo.Revoke(ctx, s.testUser.ID, apiKeyRevokedRecent.ID, PtrToString("test"))
	// Manually update revoked_at for more precise timing if needed, or rely on Revoke's CURRENT_TIMESTAMP
	// For this test, we'll assume Revoke sets a time close enough for the period check.
	// To be precise for testing olderThanRevokedPeriod:
	updateQuery := "UPDATE api_keys SET revoked_at = $1 WHERE id = $2"
	_, err := s.pool.Exec(ctx, updateQuery, revokedRecentTime, apiKeyRevokedRecent.ID)
	require.NoError(s.T(), err)


	// Revoked long ago
	revokedOldTime := now.Add(-30 * 24 * time.Hour) // 30 days ago
	apiKeyRevokedOld := s.helperCreateAPIKey(s.testUser.ID, "RevokedOldKey", "revo_", "hrev_o", nil, PtrToTime(now.Add(time.Hour)))
	s.repo.Revoke(ctx, s.testUser.ID, apiKeyRevokedOld.ID, PtrToString("old"))
	_, err = s.pool.Exec(ctx, updateQuery, revokedOldTime, apiKeyRevokedOld.ID)
	require.NoError(s.T(), err)


	// Active
	activeKey := s.helperCreateAPIKey(s.testUser.ID, "ActiveKey", "actk_", "hact", nil, PtrToTime(now.Add(24*time.Hour)))

	// Delete expired, and revoked tokens older than 7 days
	deletedCount, err := s.repo.DeleteExpiredAndRevoked(ctx, 7*24*time.Hour)
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 2, deletedCount) // ExpiredKey and RevokedOldKey

	_, err = s.repo.FindByID(ctx, activeKey.ID)
	assert.NoError(s.T(), err, "Active key should still exist")
	_, err = s.repo.FindByID(ctx, apiKeyRevokedRecent.ID)
	assert.NoError(s.T(), err, "Recently revoked key should still exist")

	// Delete all revoked (period = 0)
	deletedCount, err = s.repo.DeleteExpiredAndRevoked(ctx, 0) // No expired left, only recently revoked
	require.NoError(s.T(), err)
	assert.EqualValues(s.T(), 1, deletedCount) // apiKeyRevokedRecent
}

// Helper function to get a pointer to time.Time
func PtrToTime(t time.Time) *time.Time {
	return &t
}
// Helper function to get a pointer to string
func PtrToString(s string) *string {
	return &s
}
