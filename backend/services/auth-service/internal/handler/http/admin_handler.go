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

	"github.com/your-org/auth-service/internal/domain/models"
	domainErrors "github.com/your-org/auth-service/internal/domain/errors"
	domainService "github.com/your-org/auth-service/internal/domain/service"
	appService "github.com/your-org/auth-service/internal/service" // For concrete services
	"github.com/your-org/auth-service/internal/domain/repository" // For ListAuditLogParams
)

// AdminHandler handles HTTP requests for administrative actions.
type AdminHandler struct {
	logger          *zap.Logger
	userService     *appService.UserService     // Using concrete service
	roleService     *appService.RoleService     // Using concrete service
	auditLogService domainService.AuditLogService
	// authService     *appService.AuthService
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(
	logger *zap.Logger,
	userService *appService.UserService,
	roleService *appService.RoleService,
	auditLogService domainService.AuditLogService,
	// authService *appService.AuthService,
) *AdminHandler {
	return &AdminHandler{
		logger:          logger.Named("admin_handler"),
		userService:     userService,
		roleService:     roleService,
		auditLogService: auditLogService,
		// authService:     authService,
	}
}

// ListUsersResponse DTO for admin user listing
// Using models.UserResponse which is already defined.
// type AdminUserResponse models.UserResponse

type AdminListUsersResponse struct {
	Data  []models.UserResponse `json:"data"`
	Meta  models.PaginationMeta `json:"meta"` // Assuming a generic PaginationMeta model
}


// ListUsers handles fetching a paginated list of users.
// GET /admin/users
func (h *AdminHandler) ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	if page <= 0 { page = 1 }
	if pageSize <= 0 { pageSize = 20 }
	if pageSize > 100 { pageSize = 100 } // Max page size

	// Extract filters from query parameters
	// This should map to ListUsersParams in the UserRepository/UserService
	// For now, assuming UserService.ListUsers takes these directly or a similar struct.
	// The ListUsersParams in UserRepository is models.ListUsersParams
	// which has: Page, PageSize, Status, UsernameContains, EmailContains
	
	// This requires UserService to have a ListUsers method that accepts these filters.
	// This method does not exist on the current UserService stub.
	// For now, this handler will be a placeholder for the call.
	
	// Placeholder call:
	// listParams := models.ListUsersParams{
	// 	Page: page,
	// 	PageSize: pageSize,
	// 	Status: models.UserStatus(c.Query("status")), // Needs validation
	// 	UsernameContains: c.Query("username"),
	// 	EmailContains: c.Query("email"),
	// 	// Role: c.Query("role"), // Filtering by role needs more complex logic
	// }
	// users, total, err := h.userService.ListUsers(c.Request.Context(), listParams)
	// if err != nil {
	// 	ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to list users", err)
	// 	return
	// }
	
	// Mocked response for now as UserService.ListUsers is not fully implemented for these params
	h.logger.Info("Admin ListUsers called (mocked response)", zap.Int("page", page), zap.Int("pageSize", pageSize))
	users := []*models.User{} // Empty list
	total := 0

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

// TODO: Implement other /admin handlers:
// - GET /admin/audit-logs (using AuditLogRepository.List)

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
	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{"message": "User roles updated successfully"})
}

// ListAuditLogs handles fetching audit log entries.
// GET /admin/audit-logs
func (h *AdminHandler) ListAuditLogs(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	if page <= 0 { page = 1 }
	if pageSize <= 0 { pageSize = 20 }
	if pageSize > 100 { pageSize = 100 }

	var userIDFilter *uuid.UUID
	if userIDStr := c.Query("user_id"); userIDStr != "" {
		if parsedUUID, err := uuid.Parse(userIDStr); err == nil {
			userIDFilter = &parsedUUID
		} else {
			ErrorResponse(c.Writer, h.logger, http.StatusBadRequest, "Invalid user_id filter format", err)
			return
		}
	}
	actionFilter := c.Query("action")      // Optional string filter
	targetTypeFilter := c.Query("target_type") // Optional string filter
	targetIDFilter := c.Query("target_id")   // Optional string filter

	// TODO: Add date_from, date_to, status, ip_address filters

	params := repository.ListAuditLogParams{
		Page:       page,
		PageSize:   pageSize,
		UserID:     userIDFilter,
		Action:     &actionFilter,      // Pass as pointer if field is *string
		TargetType: &targetTypeFilter, // Pass as pointer
		TargetID:   &targetIDFilter,   // Pass as pointer
		SortBy:     c.DefaultQuery("sort_by", "created_at"),
		SortOrder:  c.DefaultQuery("sort_order", "DESC"),
	}
	// Adjust if Action, TargetType, TargetID in ListAuditLogParams are not pointers
	if actionFilter == "" { params.Action = nil }
	if targetTypeFilter == "" { params.TargetType = nil }
	if targetIDFilter == "" { params.TargetID = nil }


	logs, total, err := h.auditLogService.ListAuditLogs(c.Request.Context(), params)
	if err != nil {
		ErrorResponse(c.Writer, h.logger, http.StatusInternalServerError, "Failed to retrieve audit logs", err)
		return
	}

	// AuditLog model can be directly used if its JSON tags are appropriate for response
	SuccessResponse(c.Writer, h.logger, http.StatusOK, gin.H{
		"data": logs,
		"meta": models.PaginationMeta{
			CurrentPage: page,
			PageSize:    pageSize,
			TotalItems:  total,
			TotalPages:  (total + pageSize - 1) / pageSize,
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
