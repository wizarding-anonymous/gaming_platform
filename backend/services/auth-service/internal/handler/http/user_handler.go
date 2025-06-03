// File: internal/handler/http/user_handler.go

package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/domain/models"
	"github.com/your-org/auth-service/internal/service"
	"github.com/your-org/auth-service/internal/utils/validator"
	"go.uber.org/zap"
)

// UserHandler обрабатывает HTTP-запросы, связанные с пользователями
type UserHandler struct {
	userService *service.UserService
	logger      *zap.Logger
}

// NewUserHandler создает новый экземпляр UserHandler
func NewUserHandler(userService *service.UserService, logger *zap.Logger) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
	}
}

// GetUser обрабатывает запрос на получение информации о пользователе
func (h *UserHandler) GetUser(c *gin.Context) {
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

	// Получение пользователя
	user, err := h.userService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})
}

// GetCurrentUser обрабатывает запрос на получение информации о текущем пользователе
func (h *UserHandler) GetCurrentUser(c *gin.Context) {
	// Получение ID пользователя из контекста
	userIDStr, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
			"code":  "unauthorized",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "invalid_request",
		})
		return
	}

	// Получение пользователя
	user, err := h.userService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})
}

// UpdateUser обрабатывает запрос на обновление информации о пользователе
func (h *UserHandler) UpdateUser(c *gin.Context) {
	// Получение ID пользователя из контекста
	userIDStr, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
			"code":  "unauthorized",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "invalid_request",
		})
		return
	}

	// Получение данных из запроса
	var req models.UpdateUserRequest
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

	// Обновление пользователя
	user, err := h.userService.UpdateUser(c.Request.Context(), userID, req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	})
}

// ChangePassword обрабатывает запрос на изменение пароля
func (h *UserHandler) ChangePassword(c *gin.Context) {
	// Получение ID пользователя из контекста
	userIDStr, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
			"code":  "unauthorized",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "invalid_request",
		})
		return
	}

	// Получение данных из запроса
	var req models.ChangePasswordRequest
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

	// Изменение пароля
	err = h.userService.ChangePassword(c.Request.Context(), userID, req.OldPassword, req.NewPassword)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Password successfully changed",
	})
}

// DeleteUser обрабатывает запрос на удаление пользователя
func (h *UserHandler) DeleteUser(c *gin.Context) {
	// Получение ID пользователя из контекста
	userIDStr, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
			"code":  "unauthorized",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "invalid_request",
		})
		return
	}

	// Удаление пользователя
	err = h.userService.DeleteUser(c.Request.Context(), userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "User successfully deleted",
	})
}

// handleError обрабатывает ошибки и возвращает соответствующий HTTP-ответ
func (h *UserHandler) handleError(c *gin.Context, err error) {
	h.logger.Error("Error in user handler", zap.Error(err))

	status := http.StatusInternalServerError
	errMsg := "Internal server error"
	errCode := "internal_error"

	switch {
	case err == nil:
		return
	case err == models.ErrUserNotFound:
		status = http.StatusNotFound
		errMsg = "User not found"
		errCode = "user_not_found"
	case err == models.ErrInvalidCredentials:
		status = http.StatusUnauthorized
		errMsg = "Invalid credentials"
		errCode = "invalid_credentials"
	case err == models.ErrEmailExists:
		status = http.StatusConflict
		errMsg = "Email already exists"
		errCode = "email_exists"
	case err == models.ErrUsernameExists:
		status = http.StatusConflict
		errMsg = "Username already exists"
		errCode = "username_exists"
	case err == models.ErrUserBlocked:
		status = http.StatusForbidden
		errMsg = "User is blocked"
		errCode = "user_blocked"
	}

	c.JSON(status, gin.H{
		"error": errMsg,
		"code":  errCode,
	})
}
