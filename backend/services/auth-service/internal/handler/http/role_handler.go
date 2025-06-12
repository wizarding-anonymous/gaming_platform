// File: backend/services/auth-service/internal/handler/http/role_handler.go

package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/models"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/handler/http/middleware" // Added for GinContextUserIDKey
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/validator"
	"go.uber.org/zap"
)

// RoleHandler обрабатывает HTTP-запросы, связанные с ролями
type RoleHandler struct {
	roleService *service.RoleService
	logger      *zap.Logger
}

// NewRoleHandler создает новый экземпляр RoleHandler
func NewRoleHandler(roleService *service.RoleService, logger *zap.Logger) *RoleHandler {
	return &RoleHandler{
		roleService: roleService,
		logger:      logger,
	}
}

// GetRoles обрабатывает запрос на получение списка ролей
func (h *RoleHandler) GetRoles(c *gin.Context) {
	// Получение списка ролей
	roles, err := h.roleService.GetRoles(c.Request.Context())
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	response := make([]models.RoleResponse, 0, len(roles))
	for _, role := range roles {
		response = append(response, models.RoleResponse{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
			CreatedAt:   role.CreatedAt,
			UpdatedAt:   role.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, response)
}

// GetRole обрабатывает запрос на получение информации о роли
func (h *RoleHandler) GetRole(c *gin.Context) {
	// Получение ID роли из URL
	roleIDStr := c.Param("id")
	// roleID, err := uuid.Parse(roleIDStr) // Changed: roleID is now string
	// if err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{
	// 		"error": "Invalid role ID",
	// 		"code":  "invalid_request",
	// 	})
	// 	return
	// }
	roleID := roleIDStr // Changed: roleID is now string

	// Получение роли
	role, err := h.roleService.GetRoleByID(c.Request.Context(), roleID) // roleID is now string
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, models.RoleResponse{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	})
}

// CreateRole обрабатывает запрос на создание новой роли
func (h *RoleHandler) CreateRole(c *gin.Context) {
	// Получение данных из запроса
	var req models.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "invalid_request",
		})
		return
	}

	// Валидация запроса
	if err := validator.Validate(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  "validation_error",
		})
		return
	}

	// Создание роли
	adminUserIDRaw, exists := c.Get(middleware.GinContextUserIDKey)
	var adminIDPtr *uuid.UUID
	if exists {
		if adminUUID, ok := adminUserIDRaw.(uuid.UUID); ok {
			adminIDPtr = &adminUUID
		} else if adminIDStr, ok := adminUserIDRaw.(string); ok {
			if parsedID, pErr := uuid.Parse(adminIDStr); pErr == nil {
				adminIDPtr = &parsedID
			} else {
				h.logger.Warn("Failed to parse admin user ID from context for CreateRole", zap.String("raw_admin_id", adminIDStr), zap.Error(pErr))
			}
		} else if adminUserIDRaw != nil { // only log if it exists but is of a wrong type
			h.logger.Warn("Admin user ID in context has unexpected type for CreateRole", zap.Any("raw_admin_id", adminUserIDRaw))
		}
	} else {
		h.logger.Warn("Admin user ID not found in context for CreateRole")
	}

	role, err := h.roleService.CreateRole(c.Request.Context(), req, adminIDPtr)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusCreated, models.RoleResponse{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	})
}

// UpdateRole обрабатывает запрос на обновление роли
func (h *RoleHandler) UpdateRole(c *gin.Context) {
	// Получение ID роли из URL
	roleIDStr := c.Param("id")
	// roleID, err := uuid.Parse(roleIDStr) // Changed: roleID is now string
	// if err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{
	// 		"error": "Invalid role ID",
	// 		"code":  "invalid_request",
	// 	})
	// 	return
	// }
	roleID := roleIDStr // Changed: roleID is now string

	// Получение данных из запроса
	var req models.UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "invalid_request",
		})
		return
	}

	// Валидация запроса
	if err := validator.Validate(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  "validation_error",
		})
		return
	}

	// Обновление роли
	adminUserIDRaw, exists := c.Get(middleware.GinContextUserIDKey)
	var adminIDPtr *uuid.UUID
	if exists {
		if adminUUID, ok := adminUserIDRaw.(uuid.UUID); ok {
			adminIDPtr = &adminUUID
		} else if adminIDStr, ok := adminUserIDRaw.(string); ok {
			if parsedID, pErr := uuid.Parse(adminIDStr); pErr == nil {
				adminIDPtr = &parsedID
			} else {
				h.logger.Warn("Failed to parse admin user ID from context for UpdateRole", zap.String("raw_admin_id", adminIDStr), zap.Error(pErr))
			}
		} else if adminUserIDRaw != nil {
			h.logger.Warn("Admin user ID in context has unexpected type for UpdateRole", zap.Any("raw_admin_id", adminUserIDRaw))
		}
	} else {
		h.logger.Warn("Admin user ID not found in context for UpdateRole")
	}

	role, err := h.roleService.UpdateRole(c.Request.Context(), roleID, req, adminIDPtr) // roleID is now string
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, models.RoleResponse{
		ID:          role.ID,
		Name:        role.Name,
		Description: role.Description,
		CreatedAt:   role.CreatedAt,
		UpdatedAt:   role.UpdatedAt,
	})
}

// DeleteRole обрабатывает запрос на удаление роли
func (h *RoleHandler) DeleteRole(c *gin.Context) {
	// Получение ID роли из URL
	roleIDStr := c.Param("id")
	// roleID, err := uuid.Parse(roleIDStr) // Changed: roleID is now string
	// if err != nil {
	// 	c.JSON(http.StatusBadRequest, gin.H{
	// 		"error": "Invalid role ID",
	// 		"code":  "invalid_request",
	// 	})
	// 	return
	// }
	roleID := roleIDStr // Changed: roleID is now string

	// Удаление роли
	adminUserIDRaw, exists := c.Get(middleware.GinContextUserIDKey)
	var adminIDPtr *uuid.UUID
	if exists {
		if adminUUID, ok := adminUserIDRaw.(uuid.UUID); ok {
			adminIDPtr = &adminUUID
		} else if adminIDStr, ok := adminUserIDRaw.(string); ok {
			if parsedID, pErr := uuid.Parse(adminIDStr); pErr == nil {
				adminIDPtr = &parsedID
			} else {
				h.logger.Warn("Failed to parse admin user ID from context for DeleteRole", zap.String("raw_admin_id", adminIDStr), zap.Error(pErr))
			}
		} else if adminUserIDRaw != nil {
			h.logger.Warn("Admin user ID in context has unexpected type for DeleteRole", zap.Any("raw_admin_id", adminUserIDRaw))
		}
	} else {
		h.logger.Warn("Admin user ID not found in context for DeleteRole")
	}

	err = h.roleService.DeleteRole(c.Request.Context(), roleID, adminIDPtr) // roleID is now string
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Role successfully deleted",
	})
}

// AssignRoleToUser обрабатывает запрос на назначение роли пользователю
func (h *RoleHandler) AssignRoleToUser(c *gin.Context) {
	// Получение данных из запроса
	var req models.AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "invalid_request",
		})
		return
	}

	// Валидация запроса
	if err := validator.Validate(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  "validation_error",
		})
		return
	}

	// Назначение роли пользователю
	adminUserIDRaw, exists := c.Get(middleware.GinContextUserIDKey)
	var adminIDPtr *uuid.UUID
	if exists {
		if adminUUID, ok := adminUserIDRaw.(uuid.UUID); ok {
			adminIDPtr = &adminUUID
		} else if adminIDStr, ok := adminUserIDRaw.(string); ok {
			if parsedID, pErr := uuid.Parse(adminIDStr); pErr == nil {
				adminIDPtr = &parsedID
			} else {
				h.logger.Warn("Failed to parse admin user ID from context for AssignRoleToUser", zap.String("raw_admin_id", adminIDStr), zap.Error(pErr))
			}
		} else if adminUserIDRaw != nil {
			h.logger.Warn("Admin user ID in context has unexpected type for AssignRoleToUser", zap.Any("raw_admin_id", adminUserIDRaw))
		}
	} else {
		h.logger.Warn("Admin user ID not found in context for AssignRoleToUser")
	}

	err := h.roleService.AssignRoleToUser(c.Request.Context(), req.UserID, req.RoleID, adminIDPtr)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Role successfully assigned to user",
	})
}

// RemoveRoleFromUser обрабатывает запрос на удаление роли у пользователя
func (h *RoleHandler) RemoveRoleFromUser(c *gin.Context) {
	// Получение данных из запроса
	var req models.RemoveRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "invalid_request",
		})
		return
	}

	// Валидация запроса
	if err := validator.Validate(req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
			"code":  "validation_error",
		})
		return
	}

	// Удаление роли у пользователя
	adminUserIDRaw, exists := c.Get(middleware.GinContextUserIDKey)
	var adminIDPtr *uuid.UUID
	if exists {
		if adminUUID, ok := adminUserIDRaw.(uuid.UUID); ok {
			adminIDPtr = &adminUUID
		} else if adminIDStr, ok := adminUserIDRaw.(string); ok {
			if parsedID, pErr := uuid.Parse(adminIDStr); pErr == nil {
				adminIDPtr = &parsedID
			} else {
				h.logger.Warn("Failed to parse admin user ID from context for RemoveRoleFromUser", zap.String("raw_admin_id", adminIDStr), zap.Error(pErr))
			}
		} else if adminUserIDRaw != nil {
			h.logger.Warn("Admin user ID in context has unexpected type for RemoveRoleFromUser", zap.Any("raw_admin_id", adminUserIDRaw))
		}
	} else {
		h.logger.Warn("Admin user ID not found in context for RemoveRoleFromUser")
	}

	err := h.roleService.RemoveRoleFromUser(c.Request.Context(), req.UserID, req.RoleID, adminIDPtr)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Role successfully removed from user",
	})
}

// GetUserRoles обрабатывает запрос на получение ролей пользователя
func (h *RoleHandler) GetUserRoles(c *gin.Context) {
	// Получение ID пользователя из URL
	userIDStr := c.Param("id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "invalid_request",
		})
		return
	}

	// Получение ролей пользователя
	roles, err := h.roleService.GetUserRoles(c.Request.Context(), userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	response := make([]models.RoleResponse, 0, len(roles))
	for _, role := range roles {
		response = append(response, models.RoleResponse{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
			CreatedAt:   role.CreatedAt,
			UpdatedAt:   role.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, response)
}

// handleError обрабатывает ошибки и возвращает соответствующий HTTP-ответ
func (h *RoleHandler) handleError(c *gin.Context, err error) {
	h.logger.Error("Error in role handler", zap.Error(err))

	status := http.StatusInternalServerError
	errMsg := "Internal server error"
	errCode := "internal_error"

	switch {
	case err == nil:
		return
	case err == models.ErrRoleNotFound:
		status = http.StatusNotFound
		errMsg = "Role not found"
		errCode = "role_not_found"
	case err == models.ErrRoleNameExists:
		status = http.StatusConflict
		errMsg = "Role name already exists"
		errCode = "role_name_exists"
	case err == models.ErrUserNotFound:
		status = http.StatusNotFound
		errMsg = "User not found"
		errCode = "user_not_found"
	case err == models.ErrRoleAlreadyAssigned:
		status = http.StatusConflict
		errMsg = "Role already assigned to user"
		errCode = "role_already_assigned"
	case err == models.ErrRoleNotAssigned:
		status = http.StatusBadRequest
		errMsg = "Role not assigned to user"
		errCode = "role_not_assigned"
	}

	c.JSON(status, gin.H{
		"error": errMsg,
		"code":  errCode,
	})
}
