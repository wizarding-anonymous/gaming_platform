package database

import (
	"context"
	"fmt"
	"testing"
	// "time"

	"github.com/google/uuid"
	// "github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/auth-service/internal/domain/models"
	repoPostgres "github.com/your-org/auth-service/internal/domain/repository/postgres"
	// argon2Service is global from user_postgres_repository_integration_test.go's TestMain
	// testDB is global from user_postgres_repository_integration_test.go's TestMain
)

// Helper to clear user_roles and related tables for these tests
func clearUserRolesTestTables(t *testing.T) {
	t.Helper()
	tables := []string{"user_roles", "roles", "users"} // Order for FKs
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

func TestUserRolesRepository_Integration(t *testing.T) {
	ctx := context.Background()
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	roleRepo := repoPostgres.NewRoleRepositoryPostgres(testDB)
	userRolesRepo := repoPostgres.NewUserRolesRepositoryPostgres(testDB)

	clearUserRolesTestTables(t)

	// 1. Create User and Roles
	hashedPassword, _ := argon2Service.HashPassword("password123")
	user1 := &models.User{ID: uuid.New(), Username: "user_for_roles1", Email: "ur1@example.com", PasswordHash: hashedPassword, Status: models.UserStatusActive}
	err := userRepo.Create(ctx, user1)
	require.NoError(t, err)

	roleAdmin := &models.Role{ID: "admin_ur", Name: "Admin UR"}
	err = roleRepo.Create(ctx, roleAdmin)
	require.NoError(t, err)

	roleEditor := &models.Role{ID: "editor_ur", Name: "Editor UR"}
	err = roleRepo.Create(ctx, roleEditor)
	require.NoError(t, err)

	// 2. Add Roles to User
	err = userRolesRepo.AddRoleToUser(ctx, user1.ID, roleAdmin.ID)
	require.NoError(t, err, "Failed to add admin role to user1")
	err = userRolesRepo.AddRoleToUser(ctx, user1.ID, roleEditor.ID)
	require.NoError(t, err, "Failed to add editor role to user1")

	// 3. Get Roles for User
	user1Roles, err := userRolesRepo.GetRoleIDsForUser(ctx, user1.ID)
	require.NoError(t, err, "Failed to get roles for user1")
	require.Len(t, user1Roles, 2, "User1 should have 2 roles")
	assert.Contains(t, user1Roles, roleAdmin.ID)
	assert.Contains(t, user1Roles, roleEditor.ID)

	// Try to add a duplicate role - should ideally be handled by DB constraint or repo logic
	// The current AddRoleToUser doesn't return an error for duplicates if ON CONFLICT DO NOTHING is used.
	// If it's a direct INSERT, it would error. Let's assume it handles duplicates gracefully (no error).
	err = userRolesRepo.AddRoleToUser(ctx, user1.ID, roleAdmin.ID)
	require.NoError(t, err, "Adding a duplicate role should not error if handled gracefully")
	user1RolesAfterDup, err := userRolesRepo.GetRoleIDsForUser(ctx, user1.ID)
	require.NoError(t, err)
	require.Len(t, user1RolesAfterDup, 2, "User1 should still have 2 roles after duplicate add attempt")


	// 4. Get Users for Role
	adminUsers, err := userRolesRepo.GetUserIDsForRole(ctx, roleAdmin.ID)
	require.NoError(t, err, "Failed to get users for admin role")
	require.Len(t, adminUsers, 1, "Admin role should have 1 user")
	assert.Equal(t, user1.ID, adminUsers[0])

	// 5. Remove Role from User
	err = userRolesRepo.RemoveRoleFromUser(ctx, user1.ID, roleEditor.ID)
	require.NoError(t, err, "Failed to remove editor role from user1")

	user1RolesAfterRemove, err := userRolesRepo.GetRoleIDsForUser(ctx, user1.ID)
	require.NoError(t, err)
	require.Len(t, user1RolesAfterRemove, 1, "User1 should have 1 role after removal")
	assert.Equal(t, roleAdmin.ID, user1RolesAfterRemove[0])

	// 6. Remove non-existent role assignment - should not error
	err = userRolesRepo.RemoveRoleFromUser(ctx, user1.ID, "non_existent_role_id")
	assert.NoError(t, err, "Removing a non-assigned role should not error")

	// 7. Remove All Roles From User (if such a method exists, or test by removing remaining)
	// For now, remove the last one
	err = userRolesRepo.RemoveRoleFromUser(ctx, user1.ID, roleAdmin.ID)
	require.NoError(t, err)
	user1RolesFinal, err := userRolesRepo.GetRoleIDsForUser(ctx, user1.ID)
	require.NoError(t, err)
	assert.Len(t, user1RolesFinal, 0, "User1 should have no roles")

	// 8. Get Users for Role (should be empty now for admin role regarding user1)
	adminUsersAfterRemove, err := userRolesRepo.GetUserIDsForRole(ctx, roleAdmin.ID)
	require.NoError(t, err)
	assert.Len(t, adminUsersAfterRemove, 0, "Admin role should have 0 users after user1's roles removed")
}
