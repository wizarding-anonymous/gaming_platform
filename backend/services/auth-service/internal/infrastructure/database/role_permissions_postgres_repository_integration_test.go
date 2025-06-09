// File: backend/services/auth-service/internal/infrastructure/database/role_permissions_postgres_repository_integration_test.go
package database

import (
	"context"
	"fmt"
	"testing"
	// "time"

	// "github.com/google/uuid"
	// "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	repoPostgres "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository/postgres"
	// argon2Service is global from user_postgres_repository_integration_test.go's TestMain
	// testDB is global from user_postgres_repository_integration_test.go's TestMain
)

// Helper to clear role_permissions and related tables for these tests
func clearRolePermissionsTestTables(t *testing.T) {
	t.Helper()
	tables := []string{"role_permissions", "permissions", "roles"} // Order for FKs
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

func TestRolePermissionsRepository_Integration(t *testing.T) {
	ctx := context.Background()
	roleRepo := repoPostgres.NewRoleRepositoryPostgres(testDB)
	permRepo := repoPostgres.NewPermissionRepositoryPostgres(testDB)
	rolePermsRepo := repoPostgres.NewRolePermissionRepositoryPostgres(testDB)

	clearRolePermissionsTestTables(t)

	// 1. Create Roles and Permissions
	roleManager := &models.Role{ID: "manager_rp", Name: "Manager RP"}
	err := roleRepo.Create(ctx, roleManager)
	require.NoError(t, err)

	roleViewer := &models.Role{ID: "viewer_rp", Name: "Viewer RP"}
	err = roleRepo.Create(ctx, roleViewer)
	require.NoError(t, err)

	permRead := &models.Permission{ID: "read_rp", Name: "Read RP", Description: "Read permission for RP test"}
	err = permRepo.Create(ctx, permRead)
	require.NoError(t, err)

	permWrite := &models.Permission{ID: "write_rp", Name: "Write RP", Description: "Write permission for RP test"}
	err = permRepo.Create(ctx, permWrite)
	require.NoError(t, err)

	permDelete := &models.Permission{ID: "delete_rp", Name: "Delete RP", Description: "Delete permission for RP test"}
	err = permRepo.Create(ctx, permDelete)
	require.NoError(t, err)

	// 2. Assign Permissions to Roles
	err = rolePermsRepo.AssignPermissionToRole(ctx, roleManager.ID, permRead.ID)
	require.NoError(t, err)
	err = rolePermsRepo.AssignPermissionToRole(ctx, roleManager.ID, permWrite.ID)
	require.NoError(t, err)
	err = rolePermsRepo.AssignPermissionToRole(ctx, roleManager.ID, permDelete.ID)
	require.NoError(t, err)

	err = rolePermsRepo.AssignPermissionToRole(ctx, roleViewer.ID, permRead.ID)
	require.NoError(t, err)

	// Assign duplicate - should be handled gracefully (no error) by "ON CONFLICT DO NOTHING"
	err = rolePermsRepo.AssignPermissionToRole(ctx, roleViewer.ID, permRead.ID)
	require.NoError(t, err)


	// 3. Get Permissions for Roles (using RoleRepository's method for this part as it's a common query)
	managerPermissions, err := roleRepo.GetRolePermissions(ctx, roleManager.ID)
	require.NoError(t, err)
	assert.Len(t, managerPermissions, 3)
	permIDsForManager := make([]string, len(managerPermissions))
	for i, p := range managerPermissions { permIDsForManager[i] = p.ID }
	assert.Contains(t, permIDsForManager, permRead.ID)
	assert.Contains(t, permIDsForManager, permWrite.ID)
	assert.Contains(t, permIDsForManager, permDelete.ID)

	viewerPermissions, err := roleRepo.GetRolePermissions(ctx, roleViewer.ID)
	require.NoError(t, err)
	assert.Len(t, viewerPermissions, 1)
	assert.Equal(t, permRead.ID, viewerPermissions[0].ID)


	// 4. Get Roles for Permission (if such a method exists on RolePermissionRepository - it does not yet)
	// rolesForReadPerm, err := rolePermsRepo.GetRolesForPermission(ctx, permRead.ID)
	// require.NoError(t, err)
	// assert.Len(t, rolesForReadPerm, 2)
	// roleIDsForReadPerm := make([]string, len(rolesForReadPerm))
	// for i, r := range rolesForReadPerm { roleIDsForReadPerm[i] = r.ID }
	// assert.Contains(t, roleIDsForReadPerm, roleManager.ID)
	// assert.Contains(t, roleIDsForReadPerm, roleViewer.ID)
	// This part is commented out as GetRolesForPermission is not in the current interface.

	// 5. Remove Permission from Role
	err = rolePermsRepo.RemovePermissionFromRole(ctx, roleManager.ID, permWrite.ID)
	require.NoError(t, err)

	managerPermissionsAfterRemove, err := roleRepo.GetRolePermissions(ctx, roleManager.ID)
	require.NoError(t, err)
	assert.Len(t, managerPermissionsAfterRemove, 2)
	permIDsForManagerAfterRemove := make([]string, len(managerPermissionsAfterRemove))
	for i, p := range managerPermissionsAfterRemove { permIDsForManagerAfterRemove[i] = p.ID }
	assert.NotContains(t, permIDsForManagerAfterRemove, permWrite.ID)
	assert.Contains(t, permIDsForManagerAfterRemove, permRead.ID)

	// 6. Remove non-existent permission assignment - should not error
	err = rolePermsRepo.RemovePermissionFromRole(ctx, roleManager.ID, "non_existent_perm_id")
	assert.NoError(t, err)
}
