package http

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/gameplatform/auth-service/internal/domain/entity"
	"github.com/gameplatform/auth-service/internal/domain/repository" // For ListAuditLogParams if used directly by service
	"github.com/gameplatform/auth-service/internal/domain/service"
	// "github.com/gameplatform/auth-service/internal/middleware" 
)

// AdminHandler handles HTTP requests for administrative actions (`/admin/...`).
type AdminHandler struct {
	logger         *zap.Logger
	userService    service.UserService    
	authLogicSvc   service.AuthLogicService 
	rbacService    service.RBACService    
	auditLogSvc    service.AuditLogService  
}

// NewAdminHandler creates a new AdminHandler.
func NewAdminHandler(
	logger *zap.Logger,
	userService service.UserService,
	authLogicSvc service.AuthLogicService,
	rbacService service.RBACService,
	auditLogSvc service.AuditLogService,
) *AdminHandler {
	return &AdminHandler{
		logger:       logger.Named("admin_handler"),
		userService:  userService,
		authLogicSvc: authLogicSvc,
		rbacService:  rbacService,
		auditLogSvc:  auditLogSvc,
	}
}

// --- DTOs ---
// Re-using UserResponse and Meta from other handler files or shared DTO package.

// AdminListUsersRequestParams DTO for query binding
type AdminListUsersRequestParams struct {
	Page     int    `form:"page,default=1"`
	PerPage  int    `form:"per_page,default=20"`
	Email    string `form:"email"`
	Username string `form:"username"`
	Status   string `form:"status"`
	RoleID   string `form:"role_id"` 
	SortBy   string `form:"sort_by,default=created_at"` // Valid columns: username, email, created_at, last_login_at, status
	SortOrder string `form:"sort_order,default=desc"`  // asc, desc
}

// AdminUserInfoResponse DTO
type AdminUserInfoResponse struct {
	ID                  string     `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	Status              string     `json:"status"`
	Roles               []string   `json:"roles"` 
	Permissions         []string   `json:"permissions,omitempty"` 
	MFAEnabled          bool       `json:"mfa_enabled"`
	EmailVerifiedAt     *time.Time `json:"email_verified_at,omitempty"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           *time.Time `json:"updated_at,omitempty"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LockoutUntil        *time.Time `json:"lockout_until,omitempty"`
	StatusReason        *string    `json:"status_reason,omitempty"`
	UpdatedBy           *string    `json:"updated_by,omitempty"`
}


type BlockUserRequest struct {
	Reason string `json:"reason" binding:"omitempty,max=255"`
}

type UpdateUserRolesRequest struct {
	RoleIDs []string `json:"role_ids" binding:"required,dive,min=0"` // Allow empty list to remove all roles
}

// AdminListAuditLogsRequestParams DTO for query binding
type AdminListAuditLogsRequestParams struct {
	Page        int        `form:"page,default=1"`
	PerPage     int        `form:"per_page,default=50"`
	UserID      *string    `form:"user_id"`
	Action      *string    `form:"action"`
	TargetType  *string    `form:"target_type"`
	TargetID    *string    `form:"target_id"`
	Status      *string    `form:"status"` // Should be entity.AuditLogStatus
	IPAddress   *string    `form:"ip_address"`
	DateFrom    *time.Time `form:"date_from" time_format:"2006-01-02T15:04:05Z07:00"`
	DateTo      *time.Time `form:"date_to" time_format:"2006-01-02T15:04:05Z07:00"`
	SortBy      string     `form:"sort_by,default=created_at"`
	SortOrder   string     `form:"sort_order,default=desc"`
}


type AuditLogEntryDTO struct {
	ID          int64           `json:"id"`
	UserID      *string         `json:"user_id,omitempty"`
	Action      string          `json:"action"`
	TargetType  *string         `json:"target_type,omitempty"`
	TargetID    *string         `json:"target_id,omitempty"`
	IPAddress   *string         `json:"ip_address,omitempty"`
	UserAgent   *string         `json:"user_agent,omitempty"`
	Status      string          `json:"status"`
	Details     json.RawMessage `json:"details,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

type ListAuditLogsResponse struct {
	Data []AuditLogEntryDTO `json:"data"`
	Meta Meta               `json:"meta"` 
}


// --- Helper --- 
func (h *AdminHandler) respondWithError(c *gin.Context, code int, message string) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}
func (h *AdminHandler) getAdminUserIDFromContext(c *gin.Context) (string, bool) {
	adminIDVal, exists := c.Get("userID") 
	if !exists {
		adminIDStr := c.GetString("userID")
		if adminIDStr == "" {
			h.respondWithError(c, http.StatusUnauthorized, "Unauthorized admin: User ID not in context")
			return "", false
		}
		// Further check if this userID has admin privileges
		// For now, just returning the ID. RBAC middleware should handle permission checks.
		return adminIDStr, true
	}
	adminIDStr, ok := adminIDVal.(string)
	if !ok || adminIDStr == "" {
		h.respondWithError(c, http.StatusUnauthorized, "Invalid admin user identification in context")
		return "", false
	}
	return adminIDStr, true
}


// --- Handlers ---

func (h *AdminHandler) ListUsersHandler(c *gin.Context) {
	if _, ok := h.getAdminUserIDFromContext(c); !ok { return } 

	var params service.ListUsersAdminParams // Assuming service layer defines this DTO
	if err := c.ShouldBindQuery(&params); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid query parameters: "+err.Error())
		return
	}
	if params.Page == 0 { params.Page = 1 }
	if params.PerPage == 0 { params.PerPage = 20 }
	if params.SortBy == "" { params.SortBy = "created_at"}
	if params.SortOrder == "" { params.SortOrder = "desc"}


	users, total, err := h.userService.ListUsersAdmin(c.Request.Context(), params) 
	if err != nil {
		h.logger.Error("ListUsersHandler: service error", zap.Error(err))
		h.respondWithError(c, http.StatusInternalServerError, "Failed to list users.")
		return
	}

	userDTOs := make([]UserResponse, len(users)) 
	for i, u := range users {
		userDTOs[i] = UserResponse{
			ID: u.ID, Username: u.Username, Email: u.Email, 
			Status: string(u.Status), CreatedAt: u.CreatedAt,
			EmailVerifiedAt: u.EmailVerifiedAt, LastLoginAt: u.LastLoginAt,
			// MFAEnabled would need to be fetched or included in a specific AdminUserDTO
		}
	}
	
	totalPages := 0
	if params.PerPage > 0 && total > 0 { totalPages = (total + params.PerPage -1) / params.PerPage }

	c.JSON(http.StatusOK, ListUsersResponse{ 
		Data: userDTOs,
		Meta: Meta{CurrentPage: params.Page, PerPage: params.PerPage, TotalItems: total, TotalPages: totalPages},
	})
}

func (h *AdminHandler) GetUserDetailHandler(c *gin.Context) {
	if _, ok := h.getAdminUserIDFromContext(c); !ok { return }
	
	targetUserID := c.Param("user_id")

	user, mfaEnabled, err := h.userService.GetUserFullInfo(c.Request.Context(), targetUserID) 
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.respondWithError(c, http.StatusNotFound, "User not found.")
		} else {
			h.logger.Error("GetUserDetailHandler: service error", zap.Error(err), zap.String("targetUserID", targetUserID))
			h.respondWithError(c, http.StatusInternalServerError, "Failed to get user details.")
		}
		return
	}

	roles, _ := h.rbacService.GetUserRoles(c.Request.Context(), targetUserID) 
	roleIDs := make([]string, len(roles))
	for i, r := range roles { roleIDs[i] = r.ID } 
	
	permissions, _ := h.rbacService.GetAllUserPermissions(c.Request.Context(), targetUserID)
	permissionIDs := make([]string, len(permissions))
	for i, p := range permissions { permissionIDs[i] = p.ID }


	c.JSON(http.StatusOK, AdminUserInfoResponse{
		ID: user.ID, Username: user.Username, Email: user.Email, Status: string(user.Status),
		Roles: roleIDs, Permissions: permissionIDs, MFAEnabled: mfaEnabled, EmailVerifiedAt: user.EmailVerifiedAt,
		LastLoginAt: user.LastLoginAt, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
		FailedLoginAttempts: user.FailedLoginAttempts, LockoutUntil: user.LockoutUntil,
		StatusReason: user.StatusReason, UpdatedBy: user.UpdatedBy,
	})
}

func (h *AdminHandler) BlockUserHandler(c *gin.Context) {
	adminUserID, ok := h.getAdminUserIDFromContext(c); if !ok { return }
	targetUserID := c.Param("user_id")

	var req BlockUserRequest
	if err := c.ShouldBindJSON(&req); err != nil && err.Error() != "EOF" && !strings.Contains(err.Error(), "body is empty") {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}
	
	err := h.authLogicSvc.BlockUserByAdmin(c.Request.Context(), targetUserID, adminUserID, req.Reason)
	if err != nil {
		h.logger.Error("BlockUserHandler: service error", zap.Error(err), zap.String("targetUserID", targetUserID))
		if strings.Contains(err.Error(), "not found") { h.respondWithError(c, http.StatusNotFound, err.Error()) } else 
		if strings.Contains(err.Error(), "cannot block") { h.respondWithError(c, http.StatusForbidden, err.Error()) } else
		{ h.respondWithError(c, http.StatusInternalServerError, "Failed to block user.") }
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User blocked successfully."})
}

func (h *AdminHandler) UnblockUserHandler(c *gin.Context) {
	adminUserID, ok := h.getAdminUserIDFromContext(c); if !ok { return }
	targetUserID := c.Param("user_id")

	err := h.authLogicSvc.UnblockUserByAdmin(c.Request.Context(), targetUserID, adminUserID)
	if err != nil {
		h.logger.Error("UnblockUserHandler: service error", zap.Error(err), zap.String("targetUserID", targetUserID))
		if strings.Contains(err.Error(), "not found") { h.respondWithError(c, http.StatusNotFound, err.Error()) } else
		{ h.respondWithError(c, http.StatusInternalServerError, "Failed to unblock user.") }
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User unblocked successfully."})
}

func (h *AdminHandler) UpdateUserRolesHandler(c *gin.Context) {
	adminUserID, ok := h.getAdminUserIDFromContext(c); if !ok { return }
	targetUserID := c.Param("user_id")

	var req UpdateUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.respondWithError(c, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}
	
	err := h.rbacService.SetUserRoles(c.Request.Context(), targetUserID, req.RoleIDs, adminUserID)
	if err != nil {
		h.logger.Error("UpdateUserRolesHandler: service error", zap.Error(err), zap.String("targetUserID", targetUserID))
		if strings.Contains(err.Error(), "not found") { h.respondWithError(c, http.StatusNotFound, err.Error()) } else // User or Role not found
		if strings.Contains(err.Error(), "permission denied") { h.respondWithError(c, http.StatusForbidden, err.Error()) } else
		{ h.respondWithError(c, http.StatusInternalServerError, "Failed to update user roles.") }
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User roles updated successfully."})
}

func (h *AdminHandler) ListAuditLogsHandler(c *gin.Context) {
	if _, ok := h.getAdminUserIDFromContext(c); !ok { return }

	var params service.ListAuditLogParamsAdmin // Assuming service layer defines this DTO matching query params
	if err := c.ShouldBindQuery(&params); err != nil { 
		h.respondWithError(c, http.StatusBadRequest, "Invalid query parameters: "+err.Error())
		return
	}
	if params.Page == 0 { params.Page = 1 }
	if params.PerPage == 0 { params.PerPage = 50 }
	if params.SortBy == "" { params.SortBy = "created_at" }
	if params.SortOrder == "" { params.SortOrder = "desc" }


	logs, total, err := h.auditLogSvc.ListAuditLogs(c.Request.Context(), params)
	if err != nil {
		h.logger.Error("ListAuditLogsHandler: service error", zap.Error(err))
		h.respondWithError(c, http.StatusInternalServerError, "Failed to retrieve audit logs.")
		return
	}

	logDTOs := make([]AuditLogEntryDTO, len(logs))
	for i, l := range logs {
		logDTOs[i] = AuditLogEntryDTO{
			ID: l.ID, UserID: l.UserID, Action: l.Action, TargetType: l.TargetType, TargetID: l.TargetID,
			IPAddress: l.IPAddress, UserAgent: l.UserAgent, Status: string(l.Status), Details: l.Details, CreatedAt: l.CreatedAt,
		}
	}
	
	totalPages := 0
	if params.PerPage > 0 && total > 0 { totalPages = (total + params.PerPage -1) / params.PerPage }

	c.JSON(http.StatusOK, ListAuditLogsResponse{
		Data: logDTOs,
		Meta: Meta{CurrentPage: params.Page, PerPage: params.PerPage, TotalItems: total, TotalPages: totalPages},
	})
}


// RegisterAdminRoutes registers /admin related HTTP routes.
func RegisterAdminRoutes(
	routerGroup *gin.RouterGroup, 
	adminHandler *AdminHandler, 
	authMiddleware gin.HandlerFunc,
	rbacMiddleware func(requiredPermission string) gin.HandlerFunc, // More granular RBAC
) {
	admin := routerGroup.Group("/admin")
	admin.Use(authMiddleware) 
	{
		admin.GET("/users", rbacMiddleware("admin.users.list"), adminHandler.ListUsersHandler) 
		admin.GET("/users/:user_id", rbacMiddleware("admin.users.read"), adminHandler.GetUserDetailHandler) 
		admin.POST("/users/:user_id/block", rbacMiddleware("admin.users.block"), adminHandler.BlockUserHandler) 
		admin.POST("/users/:user_id/unblock", rbacMiddleware("admin.users.unblock"), adminHandler.UnblockUserHandler) 
		admin.PUT("/users/:user_id/roles", rbacMiddleware("admin.users.manage_roles"), adminHandler.UpdateUserRolesHandler) 
		admin.GET("/audit-logs", rbacMiddleware("admin.auditlogs.read"), adminHandler.ListAuditLogsHandler) 
	}
}

// Assuming Meta and UserResponse DTOs are accessible (e.g., defined in auth_handler.go or a shared DTO package)
// type Meta struct { ... }
// type UserResponse struct { ... }
