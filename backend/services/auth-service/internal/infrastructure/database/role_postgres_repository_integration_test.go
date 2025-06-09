// File: backend/services/auth-service/internal/infrastructure/database/role_postgres_repository_integration_test.go
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

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	repoPostgres "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres"
	// argon2Service is global from user_postgres_repository_integration_test.go's TestMain
	// testDB is global from user_postgres_repository_integration_test.go's TestMain
)

// Helper to clear role-related tables (and users for FKs)
func clearRoleTestTables(t *testing.T) {
	t.Helper()
	// Order matters due to foreign key constraints
	tables := []string{"role_permissions", "user_roles", "permissions", "roles", "users"}
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

func TestRoleRepository_CreateAndFind(t *testing.T) {
	ctx := context.Background()
	roleRepo := repoPostgres.NewRoleRepositoryPostgres(testDB)
	clearRoleTestTables(t)

	newRole := &models.Role{
		ID:          "test_role_cf",
		Name:        "Test Role CF",
		Description: "A role for testing CreateAndFind",
		IsSystem:    false,
	}

	err := roleRepo.Create(ctx, newRole)
	require.NoError(t, err)

	// Find by ID
	foundByID, err := roleRepo.FindByID(ctx, newRole.ID)
	require.NoError(t, err)
	require.NotNil(t, foundByID)
	assert.Equal(t, newRole.Name, foundByID.Name)
	assert.Equal(t, newRole.Description, foundByID.Description)

	// Find by Name
	foundByName, err := roleRepo.FindByName(ctx, newRole.Name)
	require.NoError(t, err)
	require.NotNil(t, foundByName)
	assert.Equal(t, newRole.ID, foundByName.ID)
}

func TestRoleRepository_Create_DuplicateNameOrID(t *testing.T) {
	ctx := context.Background()
	roleRepo := repoPostgres.NewRoleRepositoryPostgres(testDB)
	clearRoleTestTables(t)

	role1 := &models.Role{ID: "role_dup_1", Name: "Role Duplicate 1", IsSystem: false}
	err := roleRepo.Create(ctx, role1)
	require.NoError(t, err)

	// Duplicate ID
	roleDupID := &models.Role{ID: role1.ID, Name: "Another Name For Dup ID", IsSystem: false}
	err = roleRepo.Create(ctx, roleDupID)
	require.Error(t, err)
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr) && pgErr.Code == "23505", "Expected unique_violation (23505) for ID")

	// Duplicate Name
	roleDupName := &models.Role{ID: "role_dup_2", Name: role1.Name, IsSystem: false}
	err = roleRepo.Create(ctx, roleDupName)
	require.Error(t, err)
	require.True(t, errors.As(err, &pgErr) && pgErr.Code == "23505", "Expected unique_violation (23505) for Name")
}

func TestRoleRepository_Update(t *testing.T) {
	ctx := context.Background()
	roleRepo := repoPostgres.NewRoleRepositoryPostgres(testDB)
	clearRoleTestTables(t)

	role := &models.Role{ID: "role_update", Name: "Role to Update", Description: "Initial desc"}
	err := roleRepo.Create(ctx, role)
	require.NoError(t, err)

	role.Name = "Updated Role Name"
	role.Description = "Updated role description"
	updatedRole, err := roleRepo.Update(ctx, role)
	require.NoError(t, err)
	require.NotNil(t, updatedRole)
	assert.Equal(t, "Updated Role Name", updatedRole.Name)
	assert.Equal(t, "Updated role description", updatedRole.Description)
	assert.True(t, updatedRole.UpdatedAt.After(role.CreatedAt))
}

func TestRoleRepository_Delete(t *testing.T) {
	ctx := context.Background()
	roleRepo := repoPostgres.NewRoleRepositoryPostgres(testDB)
	clearRoleTestTables(t)

	role := &models.Role{ID: "role_delete", Name: "Role to Delete"}
	err := roleRepo.Create(ctx, role)
	require.NoError(t, err)

	err = roleRepo.Delete(ctx, role.ID)
	require.NoError(t, err)

	found, err := roleRepo.FindByID(ctx, role.ID)
	assert.Error(t, err) // Should be an error indicating not found
	assert.Nil(t, found)
}


// --- UserRolesRepository Tests (via RoleRepository or dedicated UserRolesRepository) ---
// Assuming UserRolesRepository is separate as per recent file structure.
// These tests would go into user_roles_postgres_repository_integration_test.go

// --- RolePermissionRepository Tests (via RoleRepository or dedicated RolePermissionRepository) ---
// These tests would go into role_permission_postgres_repository_integration_test.go
// For now, adding a basic LinkPermissionToRole and GetRolePermissions test here, assuming RoleRepository handles it.

func TestRoleRepository_PermissionLinks(t *testing.T) {
	ctx := context.Background()
	roleRepo := repoPostgres.NewRoleRepositoryPostgres(testDB)
	permRepo := repoPostgres.NewPermissionRepositoryPostgres(testDB) // Need permission repo too
	clearRoleTestTables(t)


	// 1. Create Role and Permission
	role := &models.Role{ID: "role_for_perms", Name: "Role For Permissions"}
	err := roleRepo.Create(ctx, role)
	require.NoError(t, err)

	perm := &models.Permission{ID: "perm_link_test", Name: "Test Link Permission", Description: "Permission for linking test"}
	err = permRepo.Create(ctx, perm)
	require.NoError(t, err)

	// 2. Link Permission to Role
	// Assuming RoleRepository has a method like LinkPermissionToRole
	// If not, this test needs to use a dedicated RolePermissionRepository
	// For now, let's assume RoleRepository has such a method (it doesn't based on current interface, so this will need adjustment)
	// err = roleRepo.LinkPermissionToRole(ctx, role.ID, perm.ID)
	// require.NoError(t, err)

	// Simulating direct insert into role_permissions for now if RoleRepository doesn't have the method
	// This highlights that a RolePermissionsRepository or methods on Role/Permission repo are needed.
	_, err = testDB.Exec(ctx, "INSERT INTO role_permissions (role_id, permission_id, created_at, updated_at) VALUES ($1, $2, $3, $3)", role.ID, perm.ID, time.Now())
	require.NoError(t, err, "Failed to manually link role to permission for test")


	// 3. Get Permissions for Role
	perms, err := roleRepo.GetRolePermissions(ctx, role.ID)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	assert.Equal(t, perm.ID, perms[0].ID)
	assert.Equal(t, perm.Name, perms[0].Name)

	// 4. Unlink Permission from Role (assuming a method exists)
	// err = roleRepo.UnlinkPermissionFromRole(ctx, role.ID, perm.ID)
	// require.NoError(t, err)
	// Simulating direct delete
	_, err = testDB.Exec(ctx, "DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2", role.ID, perm.ID)
	require.NoError(t, err)

	permsAfterDelete, err := roleRepo.GetRolePermissions(ctx, role.ID)
	require.NoError(t, err)
	assert.Len(t, permsAfterDelete, 0)
}
