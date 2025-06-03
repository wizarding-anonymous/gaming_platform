// File: internal/handler/http/validation_handler.go

package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/your-org/auth-service/internal/service"
	"github.com/your-org/auth-service/internal/utils/validator"
	"go.uber.org/zap"
)

// ValidationHandler обрабатывает HTTP-запросы, связанные с валидацией токенов
type ValidationHandler struct {
	tokenService *service.TokenService
	logger       *zap.Logger
}

// NewValidationHandler создает новый экземпляр ValidationHandler
func NewValidationHandler(tokenService *service.TokenService, logger *zap.Logger) *ValidationHandler {
	return &ValidationHandler{
		tokenService: tokenService,
		logger:       logger,
	}
}

// ValidateToken обрабатывает запрос на валидацию токена
func (h *ValidationHandler) ValidateToken(c *gin.Context) {
	// Получение данных из запроса
	var req struct {
		Token string `json:"token" validate:"required"`
	}
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

	// Валидация токена
	result, err := h.tokenService.ValidateToken(c.Request.Context(), req.Token)
	if err != nil {
		h.logger.Error("Token validation failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{
			"valid":  false,
			"error":  "Invalid token",
			"code":   "invalid_token",
			"reason": err.Error(),
		})
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"valid":   result.Valid,
		"user_id": result.UserID,
		"roles":   result.Roles,
	})
}

// CheckPermission обрабатывает запрос на проверку разрешения
func (h *ValidationHandler) CheckPermission(c *gin.Context) {
	// Получение данных из запроса
	var req struct {
		UserID     string `json:"user_id" validate:"required,uuid"`
		Permission string `json:"permission" validate:"required"`
	}
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

	// Проверка разрешения
	hasPermission, err := h.tokenService.CheckPermission(c.Request.Context(), req.UserID, req.Permission)
	if err != nil {
		h.logger.Error("Permission check failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to check permission",
			"code":  "internal_error",
		})
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"has_permission": hasPermission,
	})
}

// IntrospectToken обрабатывает запрос на интроспекцию токена
func (h *ValidationHandler) IntrospectToken(c *gin.Context) {
	// Получение данных из запроса
	var req struct {
		Token string `json:"token" validate:"required"`
	}
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

	// Интроспекция токена
	tokenInfo, err := h.tokenService.IntrospectToken(c.Request.Context(), req.Token)
	if err != nil {
		h.logger.Error("Token introspection failed", zap.Error(err))
		c.JSON(http.StatusUnauthorized, gin.H{
			"active": false,
			"error":  "Invalid token",
			"code":   "invalid_token",
		})
		return
	}

	// Если токен недействителен
	if !tokenInfo.Active {
		c.JSON(http.StatusOK, gin.H{
			"active": false,
		})
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"active":    true,
		"user_id":   tokenInfo.UserID,
		"username":  tokenInfo.Username,
		"roles":     tokenInfo.Roles,
		"issued_at": tokenInfo.IssuedAt,
		"expires":   tokenInfo.ExpiresAt,
		"scope":     tokenInfo.Scope,
	})
}
