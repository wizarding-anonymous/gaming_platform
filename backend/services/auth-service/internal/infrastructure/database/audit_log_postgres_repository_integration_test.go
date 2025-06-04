package database

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/your-org/auth-service/internal/domain/models"
	repoPostgres "github.com/your-org/auth-service/internal/domain/repository/postgres"
	// testDB and argon2Service are global
)

// Helper to clear audit_logs and related tables if any FKs were added (users for UserID)
func clearAuditLogTestTables(t *testing.T) {
	t.Helper()
	// If audit_logs.user_id or actor_id has FK to users table:
	tables := []string{"audit_logs", "users"}
	// If not, just "audit_logs"
	// tables := []string{"audit_logs"}
	for _, table := range tables {
		_, err := testDB.Exec(context.Background(), fmt.Sprintf("DELETE FROM %s", table))
		require.NoError(t, err, "Failed to clear table %s", table)
	}
}

// Helper to create a user for audit log tests (for UserID/ActorID fields)
func createTestUserForAuditLogTests(ctx context.Context, t *testing.T, suffix string) uuid.UUID {
	userRepo := repoPostgres.NewUserRepositoryPostgres(testDB)
	hashedPassword, _ := argon2Service.HashPassword("password123")
	userID := uuid.New()
	user := &models.User{
		ID:           userID,
		Username:     fmt.Sprintf("user_audit_%s", suffix),
		Email:        fmt.Sprintf("user_audit_%s@example.com", suffix),
		PasswordHash: hashedPassword,
		Status:       models.UserStatusActive,
	}
	err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	return userID
}


func TestAuditLogRepository_CreateAndFind(t *testing.T) {
	ctx := context.Background()
	auditRepo := repoPostgres.NewAuditLogRepositoryPostgres(testDB)
	clearAuditLogTestTables(t)

	actorID := createTestUserForAuditLogTests(ctx, t, "actor_cf")
	targetUserID := createTestUserForAuditLogTests(ctx, t, "target_cf")

	detailsMap := map[string]interface{}{"key1": "value1", "count": 42}
	detailsJSON, _ := json.Marshal(detailsMap)

	newLog := &models.AuditLog{
		// ID is bigserial, will be populated by DB
		ActorID:    &actorID,
		Action:     "test_action_create_find",
		TargetType: models.AuditTargetTypeUser,
		TargetID:   targetUserID.String(),
		Status:     models.AuditLogStatusSuccess,
		IPAddress:  "192.168.1.10",
		UserAgent:  "GoTest/1.0",
		Details:    detailsJSON,
		CreatedAt:  time.Now(), // DB will set this, but useful for WithinDuration checks
	}

	err := auditRepo.Create(ctx, newLog)
	require.NoError(t, err)
	require.NotZero(t, newLog.ID, "ID should be populated by the database")

	foundLog, err := auditRepo.FindByID(ctx, newLog.ID)
	require.NoError(t, err)
	require.NotNil(t, foundLog)

	assert.Equal(t, newLog.ID, foundLog.ID)
	require.NotNil(t, foundLog.ActorID)
	assert.Equal(t, actorID, *foundLog.ActorID)
	assert.Equal(t, newLog.Action, foundLog.Action)
	assert.Equal(t, newLog.TargetType, foundLog.TargetType)
	assert.Equal(t, newLog.TargetID, foundLog.TargetID)
	assert.Equal(t, newLog.Status, foundLog.Status)
	assert.Equal(t, newLog.IPAddress, foundLog.IPAddress)
	assert.Equal(t, newLog.UserAgent, foundLog.UserAgent)
	assert.JSONEq(t, string(newLog.Details), string(foundLog.Details))
	assert.WithinDuration(t, newLog.CreatedAt, foundLog.CreatedAt, time.Second)
}

func TestAuditLogRepository_List(t *testing.T) {
	ctx := context.Background()
	auditRepo := repoPostgres.NewAuditLogRepositoryPostgres(testDB)
	clearAuditLogTestTables(t)

	user1 := createTestUserForAuditLogTests(ctx, t, "u1_list")
	user2 := createTestUserForAuditLogTests(ctx, t, "u2_list")
	nilActorID := (*uuid.UUID)(nil) // For system actions

	logsToSeed := []*models.AuditLog{
		{ActorID: &user1, Action: "login_success", TargetType: models.AuditTargetTypeUser, TargetID: user1.String(), Status: models.AuditLogStatusSuccess, IPAddress: "10.0.0.1", CreatedAt: time.Now().Add(-5 * time.Hour)},
		{ActorID: &user1, Action: "item_update", TargetType: "item", TargetID: "item_123", Status: models.AuditLogStatusSuccess, IPAddress: "10.0.0.1", CreatedAt: time.Now().Add(-4 * time.Hour)},
		{ActorID: &user2, Action: "login_success", TargetType: models.AuditTargetTypeUser, TargetID: user2.String(), Status: models.AuditLogStatusSuccess, IPAddress: "10.0.0.2", CreatedAt: time.Now().Add(-3 * time.Hour)},
		{ActorID: &user2, Action: "item_update", TargetType: "item", TargetID: "item_456", Status: models.AuditLogStatusFailure, IPAddress: "10.0.0.2", CreatedAt: time.Now().Add(-2 * time.Hour)},
		{ActorID: nilActorID, Action: "system_cleanup", TargetType: "system", TargetID: "global", Status: models.AuditLogStatusSuccess, IPAddress: "127.0.0.1", CreatedAt: time.Now().Add(-1 * time.Hour)},
	}
	for _, logEntry := range logsToSeed {
		err := auditRepo.Create(ctx, logEntry)
		require.NoError(t, err)
	}

	// Test Case 1: No filters (list all)
	paramsAll := models.ListAuditLogParams{Page: 1, PageSize: 10, SortBy: "created_at", SortOrder: "ASC"}
	listedAll, totalAll, errAll := auditRepo.List(ctx, paramsAll)
	require.NoError(t, errAll)
	assert.Equal(t, int64(len(logsToSeed)), totalAll)
	assert.Len(t, listedAll, len(logsToSeed))

	// Test Case 2: Filter by UserID (ActorID)
	paramsUser1 := models.ListAuditLogParams{Page: 1, PageSize: 10, UserID: &user1, SortBy: "created_at", SortOrder: "ASC"}
	listedUser1, totalUser1, errUser1 := auditRepo.List(ctx, paramsUser1)
	require.NoError(t, errUser1)
	assert.Equal(t, int64(2), totalUser1)
	assert.Len(t, listedUser1, 2)
	assert.Equal(t, logsToSeed[0].Action, listedUser1[0].Action) // login_success
	assert.Equal(t, logsToSeed[1].Action, listedUser1[1].Action) // item_update for user1

	// Test Case 3: Filter by Action (partial match if supported, exact for now)
	actionFilter := "login_success"
	paramsAction := models.ListAuditLogParams{Page: 1, PageSize: 10, Action: &actionFilter, SortBy: "created_at", SortOrder: "ASC"}
	listedAction, totalAction, errAction := auditRepo.List(ctx, paramsAction)
	require.NoError(t, errAction)
	assert.Equal(t, int64(2), totalAction)
	assert.Len(t, listedAction, 2)

	// Test Case 4: Filter by TargetType and TargetID
	targetTypeFilter := "item"
	targetIDFilter := "item_123"
	paramsTarget := models.ListAuditLogParams{Page: 1, PageSize: 10, TargetType: &targetTypeFilter, TargetID: &targetIDFilter}
	listedTarget, totalTarget, errTarget := auditRepo.List(ctx, paramsTarget)
	require.NoError(t, errTarget)
	assert.Equal(t, int64(1), totalTarget)
	assert.Len(t, listedTarget, 1)
	assert.Equal(t, logsToSeed[1].ID, listedTarget[0].ID)

	// Test Case 5: Filter by Status
	statusFilter := models.AuditLogStatusFailure
	paramsStatus := models.ListAuditLogParams{Page: 1, PageSize: 10, Status: &statusFilter}
	listedStatus, totalStatus, errStatus := auditRepo.List(ctx, paramsStatus)
	require.NoError(t, errStatus)
	assert.Equal(t, int64(1), totalStatus)
	assert.Len(t, listedStatus, 1)
	assert.Equal(t, logsToSeed[3].ID, listedStatus[0].ID)

	// Test Case 6: Filter by Date Range
	dateFrom := time.Now().Add(-3 * time.Hour).Add(-30 * time.Minute) // Around user2's login_success
	dateTo := time.Now().Add(-2 * time.Hour).Add(30 * time.Minute)   // Around user2's item_update
	paramsDate := models.ListAuditLogParams{Page: 1, PageSize: 10, DateFrom: &dateFrom, DateTo: &dateTo, SortBy: "created_at", SortOrder: "ASC"}
	listedDate, totalDate, errDate := auditRepo.List(ctx, paramsDate)
	require.NoError(t, errDate)
	assert.Equal(t, int64(2), totalDate) // user2's login_success and item_update
	assert.Len(t, listedDate, 2)
	assert.Equal(t, logsToSeed[2].ID, listedDate[0].ID)
	assert.Equal(t, logsToSeed[3].ID, listedDate[1].ID)

	// Test Case 7: Pagination
	paramsPage1 := models.ListAuditLogParams{Page: 1, PageSize: 2, SortBy: "created_at", SortOrder: "ASC"}
	listedPage1, totalPage1, errPage1 := auditRepo.List(ctx, paramsPage1)
	require.NoError(t, errPage1)
	assert.Equal(t, int64(5), totalPage1)
	assert.Len(t, listedPage1, 2)
	assert.Equal(t, logsToSeed[0].ID, listedPage1[0].ID)
	assert.Equal(t, logsToSeed[1].ID, listedPage1[1].ID)

	paramsPage2 := models.ListAuditLogParams{Page: 2, PageSize: 2, SortBy: "created_at", SortOrder: "ASC"}
	listedPage2, totalPage2, errPage2 := auditRepo.List(ctx, paramsPage2)
	require.NoError(t, errPage2)
	assert.Equal(t, int64(5), totalPage2)
	assert.Len(t, listedPage2, 2)
	assert.Equal(t, logsToSeed[2].ID, listedPage2[0].ID)
	assert.Equal(t, logsToSeed[3].ID, listedPage2[1].ID)

	paramsPage3 := models.ListAuditLogParams{Page: 3, PageSize: 2, SortBy: "created_at", SortOrder: "ASC"}
	listedPage3, totalPage3, errPage3 := auditRepo.List(ctx, paramsPage3)
	require.NoError(t, errPage3)
	assert.Equal(t, int64(5), totalPage3)
	assert.Len(t, listedPage3, 1) // Last page
	assert.Equal(t, logsToSeed[4].ID, listedPage3[0].ID)


	// Test Case 8: Sorting (DESC)
	paramsSortDesc := models.ListAuditLogParams{Page: 1, PageSize: 5, SortBy: "created_at", SortOrder: "DESC"}
	listedSortDesc, _, errSortDesc := auditRepo.List(ctx, paramsSortDesc)
	require.NoError(t, errSortDesc)
	require.Len(t, listedSortDesc, 5)
	// Create a sorted list of original timestamps for comparison
	originalTimestamps := make([]time.Time, len(logsToSeed))
	for i, log := range logsToSeed {
		originalTimestamps[i] = log.CreatedAt
	}
	sort.Slice(originalTimestamps, func(i, j int) bool {
		return originalTimestamps[i].After(originalTimestamps[j]) // DESC
	})
	for i, log := range listedSortDesc {
		assert.WithinDuration(t, originalTimestamps[i], log.CreatedAt, time.Millisecond, "Order mismatch in DESC sort")
	}

	// Test Case 9: No results
	nonExistentAction := "non_existent_action_filter"
	paramsNoResults := models.ListAuditLogParams{Page: 1, PageSize: 10, Action: &nonExistentAction}
	listedNoResults, totalNoResults, errNoResults := auditRepo.List(ctx, paramsNoResults)
	require.NoError(t, errNoResults)
	assert.Equal(t, int64(0), totalNoResults)
	assert.Len(t, listedNoResults, 0)
}
