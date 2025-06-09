// File: backend/services/auth-service/internal/domain/repository/postgres/permission_repository_test.go
package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

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

type PermissionRepositoryTestSuite struct {
	suite.Suite
	pool       *pgxpool.Pool
	repo       *postgres.PermissionRepositoryPostgres
	migrations *migrate.Migrate
	dsn        string
}

func TestPermissionRepositoryTestSuite(t *testing.T) {
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
	t.Log("Migrations applied successfully for permission tests")

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database using DSN '%s': %v", dsn, err)
	}

	testSuite := &PermissionRepositoryTestSuite{
		Suite:      suite.Suite{},
		pool:       pool,
		migrations: m,
		dsn:        dsn,
	}
	suite.Run(t, testSuite)
}

func (s *PermissionRepositoryTestSuite) SetupSuite() {}

func (s *PermissionRepositoryTestSuite) TearDownSuite() {
	if s.pool != nil {
		s.pool.Close()
	}
	if s.migrations != nil {
		s.T().Log("Rolling back migrations for permission tests...")
		if err := s.migrations.Down(); err != nil && err != migrate.ErrNoChange {
			s.T().Logf("Warning: failed to rollback migrations in TearDownSuite: %v", err)
		} else {
			s.T().Log("Migrations for permission tests rolled back successfully.")
		}
	}
}

func (s *PermissionRepositoryTestSuite) SetupTest() {
	s.repo = postgres.NewPermissionRepositoryPostgres(s.pool)
	_, err := s.pool.Exec(context.Background(), `
		TRUNCATE TABLE permissions CASCADE;
		TRUNCATE TABLE role_permissions CASCADE;
	`)
	require.NoError(s.T(), err, "Failed to clean tables before test")
}

// Helper to create a permission
func (s *PermissionRepositoryTestSuite) helperCreatePermission(id, name, desc, resource, action string) *models.Permission {
	ctx := context.Background()
	permission := &models.Permission{
		ID:          id,
		Name:        name,
		Description: desc,
		Resource:    resource,
		Action:      action,
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	err := s.repo.Create(ctx, permission)
	require.NoError(s.T(), err)
	return permission
}

// --- Permission CRUD Tests ---
func (s *PermissionRepositoryTestSuite) TestCreatePermission_Success() {
	ctx := context.Background()
	permission := &models.Permission{
		ID:          "perm_create_success",
		Name:        "Test Permission Success",
		Description: "A permission for successful creation test",
		Resource:    "article",
		Action:      "create",
	}
	err := s.repo.Create(ctx, permission)
	require.NoError(s.T(), err)

	fetched, errFetch := s.repo.FindByID(ctx, permission.ID)
	require.NoError(s.T(), errFetch)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), permission.Name, fetched.Name)
	assert.Equal(s.T(), permission.Description, fetched.Description)
	assert.Equal(s.T(), permission.Resource, fetched.Resource)
	assert.Equal(s.T(), permission.Action, fetched.Action)
}

func (s *PermissionRepositoryTestSuite) TestCreatePermission_DuplicateID() {
	ctx := context.Background()
	s.helperCreatePermission("dup_id_perm", "Perm Dup ID 1", "D1", "r1", "a1")

	perm2 := &models.Permission{ID: "dup_id_perm", Name: "Another Perm", Description: "D2", Resource: "r2", Action: "a2"}
	err := s.repo.Create(ctx, perm2)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrDuplicateValue)
}

func (s *PermissionRepositoryTestSuite) TestCreatePermission_DuplicateName() {
	ctx := context.Background()
	s.helperCreatePermission("perm_dup_name1", "Duplicate Permission Name", "D1", "r1", "a1")

	perm2 := &models.Permission{ID: "perm_dup_name2", Name: "Duplicate Permission Name", Description: "D2", Resource: "r2", Action: "a2"}
	err := s.repo.Create(ctx, perm2)
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrDuplicateValue)
}


func (s *PermissionRepositoryTestSuite) TestFindByID_SuccessAndNotFound() {
	ctx := context.Background()
	perm := s.helperCreatePermission("find_by_id_perm", "Find By ID Perm", "D", "r", "a")

	// Success
	fetched, err := s.repo.FindByID(ctx, perm.ID)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), perm.Name, fetched.Name)

	// Not Found
	_, err = s.repo.FindByID(ctx, "non_existent_perm_id")
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrPermissionNotFound)
}

func (s *PermissionRepositoryTestSuite) TestFindByName_SuccessAndNotFound() {
	ctx := context.Background()
	permName := "Find By Name Permission"
	perm := s.helperCreatePermission("find_by_name_perm_id", permName, "D", "r", "a")

	// Success
	fetched, err := s.repo.FindByName(ctx, permName)
	require.NoError(s.T(), err)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), perm.ID, fetched.ID)

	// Not Found
	_, err = s.repo.FindByName(ctx, "Non Existent Permission Name")
	require.Error(s.T(), err)
	assert.ErrorIs(s.T(), err, domainErrors.ErrPermissionNotFound)
}

func (s *PermissionRepositoryTestSuite) TestUpdatePermission_Success() {
	ctx := context.Background()
	perm := s.helperCreatePermission("update_me_perm", "Original Perm Name", "Orig Desc", "orig_res", "orig_act")

	newName := "Updated Permission Name"
	newDesc := "Updated Perm Description"
	newResource := "updated_resource"
	newAction := "updated_action"
	now := time.Now().UTC().Truncate(time.Millisecond)

	perm.Name = newName
	perm.Description = newDesc
	perm.Resource = newResource
	perm.Action = newAction
	perm.UpdatedAt = &now

	err := s.repo.Update(ctx, perm)
	require.NoError(s.T(), err)

	fetched, _ := s.repo.FindByID(ctx, perm.ID)
	require.NotNil(s.T(), fetched)
	assert.Equal(s.T(), newName, fetched.Name)
	assert.Equal(s.T(), newDesc, fetched.Description)
	assert.Equal(s.T(), newResource, fetched.Resource)
	assert.Equal(s.T(), newAction, fetched.Action)
	require.NotNil(s.T(), fetched.UpdatedAt)
	assert.WithinDuration(s.T(), now, *fetched.UpdatedAt, time.Second)
}

func (s *PermissionRepositoryTestSuite) TestDeletePermission_Success() {
	ctx := context.Background()
	perm := s.helperCreatePermission("delete_me_perm", "To Be Deleted Perm", "Desc", "res", "act")

	// To test cascade, we'd need a role and role_permission entry.
	// For simplicity, we'll just test the permission deletion itself.
	// A more thorough test would involve creating a role, assigning this perm,
	// then deleting the perm and checking if the role_permissions entry is gone.

	err := s.repo.Delete(ctx, perm.ID)
	require.NoError(s.T(), err)

	_, errFind := s.repo.FindByID(ctx, perm.ID)
	assert.ErrorIs(s.T(), errFind, domainErrors.ErrPermissionNotFound)
}

func (s *PermissionRepositoryTestSuite) TestListPermissions() {
	ctx := context.Background()
	s.helperCreatePermission("perm_list1", "Perm List 1", "D A", "r A", "a A")
	s.helperCreatePermission("perm_list2", "Perm List 2", "D B", "r B", "a B")

	perms, total, err := s.repo.List(ctx, models.ListPermissionsParams{})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 2, total)
	assert.Len(s.T(), perms, 2)

	// Empty
	s.SetupTest() // Clean tables
	perms, total, err = s.repo.List(ctx, models.ListPermissionsParams{})
	require.NoError(s.T(), err)
	assert.Equal(s.T(), 0, total)
	assert.Empty(s.T(), perms)

	// Pagination
	s.helperCreatePermission("p1", "P1", "d", "r", "a")
	s.helperCreatePermission("p2", "P2", "d", "r", "a")
	s.helperCreatePermission("p3", "P3", "d", "r", "a")

	permsPage, totalPage, errPage := s.repo.List(ctx, models.ListPermissionsParams{PageSize: 2, Page: 1, OrderBy: "name", SortOrder: "ASC"})
	require.NoError(s.T(), errPage)
	assert.Equal(s.T(), 3, totalPage)
	assert.Len(s.T(), permsPage, 2)
	assert.Equal(s.T(), "P1", permsPage[0].Name)
	assert.Equal(s.T(), "P2", permsPage[1].Name)
}
