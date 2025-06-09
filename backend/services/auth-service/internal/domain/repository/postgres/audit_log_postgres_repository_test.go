// File: backend/services/auth-service/internal/domain/repository/postgres/audit_log_repository_test.go
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

type AuditLogRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	userRepo   *postgres.UserRepositoryPostgres // For creating prerequisite users
	repo       *postgres.AuditLogRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
}

func TestAuditLogRepositoryTestSuite(t *testing.T) {
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
	t.Log("Migrations applied successfully for audit log tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &AuditLogRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *AuditLogRepositoryTestSuite) SetupSuite() {
	s.userRepo = postgres.NewUserRepositoryPostgres(s.pool)
}

func (s *AuditLogRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for audit log tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for audit log tests rolled back successfully.")
		}
	}
}

func (s *AuditLogRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewAuditLogRepositoryPostgres(s.pool)
	_, err := s.pool.Exec(context.Background(), `TRUNCATE TABLE audit_logs CASCADE; TRUNCATE TABLE users CASCADE;`)
	require.NoError(s.T(), err, "Failed to clean tables before test")
}

// Helper to create a user for tests
func (s *AuditLogRepositoryTestSuite) helperCreateUserForAuditTest(usernameSuffix string) *models.User {
	ctx := context.Background()
	user := &models.User{
		ID:           uuid.New(),
		Username:     fmt.Sprintf("audit_user_%s", usernameSuffix),
		Email:        fmt.Sprintf("audit_user_%s@example.com", usernameSuffix),
		PasswordHash: "hash",
		Status:       models.UserStatusActive,
	}
	// Using userRepo from suite to create user
	err := s.userRepo.Create(ctx, user)
	require.NoError(s.T(), err)
	return user
}

// Helper to create an audit log entry
func (s *AuditLogRepositoryTestSuite) helperCreateAuditLogEntry(action string, actorID, targetID *uuid.UUID, targetType models.AuditTargetType, status models.AuditLogStatus, details map[string]interface{}) *models.AuditLog {
	ctx := context.Background()
	detailsJSON, _ := json.Marshal(details)
	entry := &models.AuditLog{
		ID:             uuid.New(),
		ActorUserID:    actorID,
		Action:         action,
		TargetType:     targetType,
		TargetID:       targetID,
		Status:         status,
		Details:        detailsJSON,
		IPAddress:      "127.0.0.1",
		UserAgent:      "test-agent",
		Timestamp:      time.Now().UTC().Truncate(time.Millisecond),
	}
	err := s.repo.Create(ctx, entry)
	require.NoError(s.T(), err)
	return entry
}


func (s *AuditLogRepositoryTestSuite) TestCreateAuditLog_Success() {
	ctx := context.Background()
	actor := s.helperCreateUserForAuditTest("actor")
	target := s.helperCreateUserForAuditTest("target")

	detailsMap := map[string]interface{}{"reason": "test_creation"}
	detailsJSON, _ := json.Marshal(detailsMap)

	entry := &models.AuditLog{
		ID:          uuid.New(),
		ActorUserID: &actor.ID,
		Action:      "user_login",
		TargetType:  models.AuditTargetTypeUser,
		TargetID:    &target.ID,
		Status:      models.AuditLogStatusSuccess,
		Details:     detailsJSON,
		IPAddress:   "192.168.1.1",
		UserAgent:   "Go-Test-Agent",
		Timestamp:   time.Now().UTC().Truncate(time.Millisecond),
	}

	err := s.repo.Create(ctx, entry)
	require.NoError(s.T(), err)

	fetched, errFetch := s.repo.FindByID(ctx, entry.ID)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), entry.Action, fetched.Action)
	require.NotNil(s.T(), fetched.ActorUserID)
	assert.Equal(s.T(), actor.ID, *fetched.ActorUserID)
	require.NotNil(s.T(), fetched.TargetID)
	assert.Equal(s.T(), target.ID, *fetched.TargetID)
	assert.Equal(s.T(), entry.Status, fetched.Status)
	assert.JSONEq(s.T(), string(detailsJSON), string(fetched.Details))
}

func (s *AuditLogRepositoryTestSuite) TestCreateAuditLog_NilActorAndTarget() {
	ctx := context.Background()
	detailsMap := map[string]interface{}{"info": "system_event"}
	detailsJSON, _ := json.Marshal(detailsMap)

	entry := &models.AuditLog{
		ID:          uuid.New(),
		ActorUserID: nil,
		Action:      "system_cleanup",
		TargetType:  models.AuditTargetTypeSystem,
		TargetID:    nil,
		Status:      models.AuditLogStatusSuccess,
		Details:     detailsJSON,
		Timestamp:   time.Now().UTC().Truncate(time.Millisecond),
	}
	err := s.repo.Create(ctx, entry)
	require.NoError(s.T(), err)

	fetched, _ := s.repo.FindByID(ctx, entry.ID)
	require.NotNil(s.T(), fetched)
	assert.Nil(s.T(), fetched.ActorUserID)
	assert.Nil(s.T(), fetched.TargetID)
	assert.Equal(s.T(), models.AuditTargetTypeSystem, fetched.TargetType)
}


func (s *AuditLogRepositoryTestSuite) TestFindAuditLogByID_SuccessAndNotFound() {
	ctx := context.Background()
	entry := s.helperCreateAuditLogEntry("test_find", nil, nil, models.AuditTargetTypeSystem, models.AuditLogStatusSuccess, nil)

	// Success
	fetched, err := s.repo.FindByID(ctx, entry.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), entry.Action, fetched.Action)

	// Not Found
	_, err = s.repo.FindByID(ctx, uuid.New())
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrAuditLogNotFound)
}

func (s *AuditLogRepositoryTestSuite) TestListAuditLogs_VariousFiltersAndPagination() {
	ctx := context.Background()
	user1 := s.helperCreateUserForAuditTest("list_user1")
	user2 := s.helperCreateUserForAuditTest("list_user2")

	now := time.Now().UTC()
	s.helperCreateAuditLogEntry("login_success", &user1.ID, &user1.ID, models.AuditTargetTypeUser, models.AuditLogStatusSuccess, map[string]interface{}{"ip": "1.1.1.1"})
	time.Sleep(10 * time.Millisecond) // Ensure distinct timestamps for ordering
	s.helperCreateAuditLogEntry("login_failure", &user1.ID, &user1.ID, models.AuditTargetTypeUser, models.AuditLogStatusFailure, map[string]interface{}{"ip": "1.1.1.1"})
	time.Sleep(10 * time.Millisecond)
	s.helperCreateAuditLogEntry("item_create", &user2.ID, nil, models.AuditTargetTypeSystem, models.AuditLogStatusSuccess, map[string]interface{}{"ip": "2.2.2.2"})
	time.Sleep(10 * time.Millisecond)
	entry4Time := time.Now().UTC()
	s.helperCreateAuditLogEntry("item_delete", &user1.ID, nil, models.AuditTargetTypeSystem, models.AuditLogStatusSuccess, map[string]interface{}{"ip": "3.3.3.3", "ts_override": entry4Time.Format(time.RFC3339)})


	// No filters
	logs, total, err := s.repo.List(ctx, models.ListAuditLogsParams{})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 4, total)
	assert.Len(s.T(), logs, 4)

	// Filter by UserID (ActorUserID)
	logs, total, err = s.repo.List(ctx, models.ListAuditLogsParams{UserID: &user1.ID})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 3, total)
	assert.Len(s.T(), logs, 3)

	// Filter by Action
	logs, total, err = s.repo.List(ctx, models.ListAuditLogsParams{Action: "login_success"})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 1, total)
	assert.Len(s.T(), logs, 1)

	// Filter by TargetType and TargetID
	targetID := user1.ID
	logs, total, err = s.repo.List(ctx, models.ListAuditLogsParams{TargetType: models.AuditTargetTypeUser, TargetID: &targetID})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 2, total) // login_success and login_failure for user1 as target
	assert.Len(s.T(), logs, 2)

	// Filter by Status
	logs, total, err = s.repo.List(ctx, models.ListAuditLogsParams{Status: models.AuditLogStatusFailure})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 1, total)
	assert.Len(s.T(), logs, 1)
	assert.Equal(s.T(), "login_failure", logs[0].Action)

	// Filter by IPAddress
	logs, total, err = s.repo.List(ctx, models.ListAuditLogsParams{IPAddress: "2.2.2.2"})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 1, total)
	assert.Len(s.T(), logs, 1)
	assert.Equal(s.T(), "item_create", logs[0].Action)

	// Filter by DateFrom and DateTo
	dateFrom := now.Add(5 * time.Millisecond)    // After first event
	dateTo := entry4Time.Add(-5 * time.Millisecond) // Before last event (using its actual creation time)

	logs, total, err = s.repo.List(ctx, models.ListAuditLogsParams{DateFrom: &dateFrom, DateTo: &dateTo})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 2, total) // login_failure and item_create
	assert.Len(s.T(), logs, 2)


	// Pagination
	logs, total, err = s.repo.List(ctx, models.ListAuditLogsParams{PageSize: 2, Page: 1, SortBy: "timestamp", SortOrder: "DESC"})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 4, total)
	assert.Len(s.T(), logs, 2)
	assert.Equal(s.T(), "item_delete", logs[0].Action) // Most recent first

	logs, total, err = s.repo.List(ctx, models.ListAuditLogsParams{PageSize: 2, Page: 2, SortBy: "timestamp", SortOrder: "DESC"})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 4, total)
	assert.Len(s.T(), logs, 2)
	assert.Equal(s.T(), "login_success", logs[1].Action)


	// Test empty result set
	logs, total, err = s.repo.List(ctx, models.ListAuditLogsParams{Action: "non_existent_action"})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 0, total)
	assert.Empty(s.T(), logs)
}
