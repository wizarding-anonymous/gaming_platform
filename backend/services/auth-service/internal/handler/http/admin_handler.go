// File: backend/services/auth-service/internal/handler/http/admin_handler.go
package http

import (
	"net/http"
	"strconv"
	// "time"

	"github.com/gin-gonic/gin"
	"strconv"
	// "time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	domainErrors "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/repository" // For ListAuditLogParams
	domainService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/service"
	appService "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service" // For concrete services
)

// AdminHandler handles HTTP requests for administrative actions.
type AdminHandler struct {
	logger          *zap.Logger
	userService     *appService.UserService // Using concrete service
	roleService     *appService.RoleService // Using concrete service
	auditLogService domainService.AuditLogService
	auditLogRepo    repository.AuditLogRepository
	// authService     *appService.AuthService
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(
	logger *zap.Logger,
	userService *appService.UserService,
	roleService *appService.RoleService,
	auditLogService domainService.AuditLogService,
	auditLogRepo repository.AuditLogRepository,
	// authService *appService.AuthService,
) *AdminHandler {
	return &AdminHandler{
		logger:          logger.Named("admin_handler"),
		userService:     userService,
		roleService:     roleService,
		auditLogService: auditLogService,
		auditLogRepo:    auditLogRepo,
		// authService:     authService,
	}
}

// ListUsersResponse DTO for admin user listing
// Using models.UserResponse which is already defined.
// type AdminUserResponse models.UserResponse

type AdminListUsersResponse struct {
	Data []models.UserResponse `json:"data"`
	Meta models.PaginationMeta `json:"meta"` // Assuming a generic PaginationMeta model
}

// ListUsers handles fetching a paginated list of users.
// GET /admin/users
func (h *AdminHandler) ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	} // Max page size

	// Extract filters from query parameters
	// This should map to ListUsersParams in the UserRepository/UserService
	// For now, assuming UserService.ListUsers takes these directly or a similar struct.
	// The ListUsersParams in UserRepository is models.ListUsersParams
	// which has: Page, PageSize, Status, UsernameContains, EmailContains

	statusFilter := c.Query("status")
	usernameFilter := c.Query("username_contains") // Changed from "username" to "username_contains"
	emailFilter := c.Query("email_contains")       // Changed from "email" to "email_contains"

	listParams := models.ListUsersParams{
		Page:             page,
		PageSize:         pageSize,
		UsernameContains: usernameFilter,
		EmailContains:    emailFilter,
	}

	if statusFilter != "" {
		validStatus := models.UserStatus(statusFilter)
		// Basic validation for UserStatus. More robust validation could check against a list of valid statuses.
		switch validStatus {
		case models.UserStatusActive, models.UserStatusInactive, models.UserStatusBlocked, models.UserStatusPendingVerification, models.UserStatusDeleted:
			listParams.Status = validStatus
		default:
			h.logger.Warn("Invalid status filter provided", zap.String("status", statusFilter))
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid status filter value", nil)
			return
		}
	}

	logFields := []zap.Field{
		zap.Int("page", page),
		zap.Int("pageSize", pageSize),
	}
	if listParams.Status != "" {
		logFields = append(logFields, zap.String("status", string(listParams.Status)))
	}
	if listParams.UsernameContains != "" {
		logFields = append(logFields, zap.String("username_contains", listParams.UsernameContains))
	}
	if listParams.EmailContains != "" {
		logFields = append(logFields, zap.String("email_contains", listParams.EmailContains))
	}
	h.logger.Info("Admin ListUsers called", logFields...)

	users, total, err := h.userService.ListUsers(c.Request.Context(), listParams)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to list users", err)
		return
	}

	userResponses := make([]models.UserResponse, len(users))
	for i, u := range users {
		userResponses[i] = u.ToResponse()
	}

	c.JSON(http.StatusOK, AdminListUsersResponse{
		Data: userResponses,
		Meta: models.PaginationMeta{
			CurrentPage: page,
			PageSize:    pageSize,
			TotalItems:  total,
			TotalPages:  (total + pageSize - 1) / pageSize,
		},
	})
}

// GetUserByID handles fetching a specific user by ID for admin.
// GET /admin/users/:user_id
func (h *AdminHandler) GetUserByID(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid user ID format", err)
		return
	}

	// Assuming userService.GetUserDetailsForAdmin or similar that returns a comprehensive user model
	user, err := h.userService.GetUserByID(c.Request.Context(), userID) // Existing method
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusNotFound, "User not found", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to retrieve user", err)
		}
		return
	}
	// Use User.ToResponse() or a specific AdminUserResponse if created
	SuccessResponse(c.Writer, h.logger, http.StatusOK, user.ToResponse())
}

// BlockUser handles blocking a user.
// POST /admin/users/:user_id/block
func (h *AdminHandler) BlockUser(c *gin.Context) {
	adminUserIDStr, _ := c.Get(middleware.GinContextUserIDKey) // Admin performing the action
	adminUserID, _ := uuid.Parse(adminUserIDStr.(string))

	targetUserIDStr := c.Param("user_id")
	targetUserID, err := uuid.Parse(targetUserIDStr)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid target user ID format", err)
		return
	}

	var req models.BlockUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	// Assuming UserService has: BlockUser(ctx, targetUserID, reason, adminUserID) error
	err = h.userService.BlockUser(c.Request.Context(), targetUserID, req.Reason, adminUserID)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusNotFound, "Target user not found", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to block user", err)
		}
		return
	}

	adminUserIDRaw, _ := c.Get(middleware.GinContextUserIDKey)
	var adminIDPtr *uuid.UUID
	if adminUUID, ok := adminUserIDRaw.(uuid.UUID); ok {
		adminIDPtr = &adminUUID
	} else if adminIDStr, ok := adminUserIDRaw.(string); ok {
		if parsedID, pErr := uuid.Parse(adminIDStr); pErr == nil {
			adminIDPtr = &parsedID
		} else {
			h.logger.Error("Failed to parse adminUserID from context for audit log", zap.Any("adminUserIDRaw", adminUserIDRaw), zap.Error(pErr))
		}
	} else if adminUserIDRaw != nil {
		h.logger.Error("AdminUserID from context is of unexpected type for audit log", zap.Any("adminUserIDRaw", adminUserIDRaw))
	}

	auditDetails := map[string]interface{}{"reason": req.Reason, "target_user_id": targetUserID.String()}

	if errAudit := h.auditLogService.RecordEvent(
		c.Request.Context(),
		adminIDPtr,
		"admin_user_block",
		models.AuditLogStatusSuccess,
		targetUserID.String(),
		models.AuditTargetTypeUser,
		auditDetails,
		c.ClientIP(),
		c.Request.UserAgent(),
	); errAudit != nil {
		h.logger.Error("Failed to record audit event for admin_user_block", zap.Error(errAudit), zap.String("target_user_id", targetUserID.String()))
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "User blocked successfully"})
}

// UnblockUser handles unblocking a user.
// POST /admin/users/:user_id/unblock
func (h *AdminHandler) UnblockUser(c *gin.Context) {
	adminUserIDStr, _ := c.Get(middleware.GinContextUserIDKey)
	adminUserID, _ := uuid.Parse(adminUserIDStr.(string))

	targetUserIDStr := c.Param("user_id")
	targetUserID, err := uuid.Parse(targetUserIDStr)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid target user ID format", err)
		return
	}

	// Assuming UserService has: UnblockUser(ctx, targetUserID, adminUserID) error
	err = h.userService.UnblockUser(c.Request.Context(), targetUserID, adminUserID)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusNotFound, "Target user not found", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to unblock user", err)
		}
		return
	}

	adminUserIDRaw, _ := c.Get(middleware.GinContextUserIDKey)
	var adminIDPtr *uuid.UUID
	if adminUUID, ok := adminUserIDRaw.(uuid.UUID); ok {
		adminIDPtr = &adminUUID
	} else if adminIDStr, ok := adminUserIDRaw.(string); ok {
		if parsedID, pErr := uuid.Parse(adminIDStr); pErr == nil {
			adminIDPtr = &parsedID
		} else {
			h.logger.Error("Failed to parse adminUserID from context for audit log", zap.Any("adminUserIDRaw", adminUserIDRaw), zap.Error(pErr))
		}
	} else if adminUserIDRaw != nil {
		h.logger.Error("AdminUserID from context is of unexpected type for audit log", zap.Any("adminUserIDRaw", adminUserIDRaw))
	}

	auditDetails := map[string]interface{}{"target_user_id": targetUserID.String()}

	if errAudit := h.auditLogService.RecordEvent(
		c.Request.Context(),
		adminIDPtr,
		"admin_user_unblock",
		models.AuditLogStatusSuccess,
		targetUserID.String(),
		models.AuditTargetTypeUser,
		auditDetails,
		c.ClientIP(),
		c.Request.UserAgent(),
	); errAudit != nil {
		h.logger.Error("Failed to record audit event for admin_user_unblock", zap.Error(errAudit), zap.String("target_user_id", targetUserID.String()))
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "User unblocked successfully"})
}

// UpdateUserRoles handles updating roles for a specific user.
// PUT /admin/users/:user_id/roles
func (h *AdminHandler) UpdateUserRoles(c *gin.Context) {
	adminUserIDStr, _ := c.Get(middleware.GinContextUserIDKey)
	adminUserID, _ := uuid.Parse(adminUserIDStr.(string))

	targetUserIDStr := c.Param("user_id")
	targetUserID, err := uuid.Parse(targetUserIDStr)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid target user ID format", err)
		return
	}

	var req models.UpdateUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	// Assuming RoleService has: UpdateUserRoles(ctx, targetUserID, roleIDs []string, adminUserID uuid.UUID) error
	err = h.roleService.UpdateUserRoles(c.Request.Context(), targetUserID, req.RoleIDs, adminUserID)
	if err != nil {
		if errors.Is(err, domainErrors.ErrUserNotFound) {
			ErrorResponse(c.Writer, h.logger, http.StatusNotFound, "Target user not found", err)
		} else if errors.Is(err, domainErrors.ErrRoleNotFound) { // If a role ID is invalid
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "One or more role IDs are invalid", err)
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to update user roles", err)
		}
		return
	}

	adminUserIDRaw, _ := c.Get(middleware.GinContextUserIDKey)
	var adminIDPtr *uuid.UUID
	if adminUUID, ok := adminUserIDRaw.(uuid.UUID); ok {
		adminIDPtr = &adminUUID
	} else if adminIDStr, ok := adminUserIDRaw.(string); ok {
		if parsedID, pErr := uuid.Parse(adminIDStr); pErr == nil {
			adminIDPtr = &parsedID
		} else {
			h.logger.Error("Failed to parse adminUserID from context for audit log", zap.Any("adminUserIDRaw", adminUserIDRaw), zap.Error(pErr))
		}
	} else if adminUserIDRaw != nil {
		h.logger.Error("AdminUserID from context is of unexpected type for audit log", zap.Any("adminUserIDRaw", adminUserIDRaw))
	}

	auditDetails := map[string]interface{}{
		"target_user_id":   targetUserID.String(),
		"updated_role_ids": req.RoleIDs,
	}

	if errAudit := h.auditLogService.RecordEvent(
		c.Request.Context(),
		adminIDPtr,
		"admin_user_roles_update",
		models.AuditLogStatusSuccess,
		targetUserID.String(),
		models.AuditTargetTypeUser,
		auditDetails,
		c.ClientIP(),
		c.Request.UserAgent(),
	); errAudit != nil {
		h.logger.Error("Failed to record audit event for admin_user_roles_update", zap.Error(errAudit), zap.String("target_user_id", targetUserID.String()))
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "User roles updated successfully"})
}

// ListAuditLogs handles fetching audit log entries.
// GET /admin/audit-logs
func (h *AdminHandler) ListAuditLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var userIDFilter *uuid.UUID
	if userIDStr := c.Query("user_id"); userIDStr != "" {
		if parsedUUID, err := uuid.Parse(userIDStr); err == nil {
			userIDFilter = &parsedUUID
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid user_id filter format", err)
			return
		}
	}
	actionFilter := c.Query("action")          // Optional string filter
	targetTypeFilter := c.Query("target_type") // Optional string filter
	targetIDFilter := c.Query("target_id")     // Optional string filter

	dateFromStr := c.Query("date_from")
	dateToStr := c.Query("date_to")
	statusFilterStr := c.Query("status")
	ipAddressFilter := c.Query("ip_address")

	params := repository.ListAuditLogParams{
		Page:      page,
		PageSize:  pageSize,
		UserID:    userIDFilter,
		SortBy:    c.DefaultQuery("sort_by", "created_at"),
		SortOrder: c.DefaultQuery("sort_order", "DESC"),
	}

	if actionFilter != "" {
		params.Action = &actionFilter
	}
	if targetTypeFilter != "" {
		params.TargetType = &targetTypeFilter
	}
	if targetIDFilter != "" {
		params.TargetID = &targetIDFilter
	}
	if ipAddressFilter != "" {
		params.IPAddress = &ipAddressFilter
	}

	if dateFromStr != "" {
		t, err := time.Parse(time.RFC3339, dateFromStr)
		if err != nil {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid date_from format, use RFC3339 (YYYY-MM-DDTHH:MM:SSZ)", err)
			return
		}
		params.DateFrom = &t
	}
	if dateToStr != "" {
		t, err := time.Parse(time.RFC3339, dateToStr)
		if err != nil {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid date_to format, use RFC3339 (YYYY-MM-DDTHH:MM:SSZ)", err)
			return
		}
		params.DateTo = &t
	}

	if statusFilterStr != "" {
		validStatus := models.AuditLogStatus(statusFilterStr)
		switch validStatus {
		case models.AuditLogStatusSuccess, models.AuditLogStatusFailure:
			params.Status = &validStatus
		default:
			h.logger.Warn("Invalid status filter for audit logs", zap.String("status", statusFilterStr))
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid status filter value for audit logs", nil)
			return
		}
	}

	logFields := []zap.Field{
		zap.Int("page", params.Page),
		zap.Int("pageSize", params.PageSize),
		zap.String("sort_by", params.SortBy),
		zap.String("sort_order", params.SortOrder),
	}
	if params.UserID != nil {
		logFields = append(logFields, zap.String("user_id", params.UserID.String()))
	}
	if params.Action != nil {
		logFields = append(logFields, zap.String("action", *params.Action))
	}
	if params.TargetType != nil {
		logFields = append(logFields, zap.String("target_type", *params.TargetType))
	}
	if params.TargetID != nil {
		logFields = append(logFields, zap.String("target_id", *params.TargetID))
	}
	if params.DateFrom != nil {
		logFields = append(logFields, zap.Time("date_from", *params.DateFrom))
	}
	if params.DateTo != nil {
		logFields = append(logFields, zap.Time("date_to", *params.DateTo))
	}
	if params.Status != nil {
		logFields = append(logFields, zap.String("status", string(*params.Status)))
	}
	if params.IPAddress != nil {
		logFields = append(logFields, zap.String("ip_address", *params.IPAddress))
	}
	h.logger.Info("Admin ListAuditLogs called", logFields...)

	logs, total, err := h.auditLogRepo.List(c.Request.Context(), params)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to retrieve audit logs", err)
		return
	}

	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{
		"data": logs,
		"meta": models.PaginationMeta{
			CurrentPage: params.Page,     // Use params.Page for consistency
			PageSize:    params.PageSize, // Use params.PageSize
			TotalItems:  total,
			TotalPages:  (total + params.PageSize - 1) / params.PageSize,
		},
	})
}

// RegisterAdminRoutes registers /admin related HTTP routes.
// All routes in this group should be protected by authentication and authorization middleware.
func RegisterAdminRoutes(
	router *gin.RouterGroup,
	adminHandler *AdminHandler,
	/* authMiddleware gin.HandlerFunc, rbacMiddleware func(requiredPermission string) gin.HandlerFunc */
) {
	admin := router.Group("/admin")
	// admin.Use(authMiddleware) // Apply general auth middleware
	{
		// Example of applying RBAC middleware for a specific permission
		// admin.GET("/users", rbacMiddleware("admin.users.read"), adminHandler.ListUsers)
		admin.GET("/users", adminHandler.ListUsers) // Placeholder without RBAC middleware for now
		// Add other admin routes here
		// admin.GET("/users/:user_id", rbacMiddleware("admin.users.read"), adminHandler.GetUserDetail)
		// ...
	}
}
