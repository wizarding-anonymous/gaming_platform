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

// AuthHandler обрабатывает HTTP-запросы, связанные с аутентификацией
type AuthHandler struct {
	authService      *service.AuthService
	tokenService     *service.TokenService
	twoFactorService *service.TwoFactorService
	telegramService  *service.TelegramService
	logger           *zap.Logger
}

// NewAuthHandler создает новый экземпляр AuthHandler
func NewAuthHandler(
	authService *service.AuthService,
	tokenService *service.TokenService,
	twoFactorService *service.TwoFactorService,
	telegramService *service.TelegramService,
	logger *zap.Logger,
) *AuthHandler {
	return &AuthHandler{
		authService:      authService,
		tokenService:     tokenService,
		twoFactorService: twoFactorService,
		telegramService:  telegramService,
		logger:           logger,
	}
}

// Register обрабатывает запрос на регистрацию нового пользователя
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.CreateUserRequest
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

	// Регистрация пользователя
	user, err := h.authService.Register(c.Request.Context(), req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusCreated, models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
	})
}

// Login обрабатывает запрос на вход в систему
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
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

	// Аутентификация пользователя
	tokenPair, user, err := h.authService.Login(c.Request.Context(), req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Проверка, требуется ли двухфакторная аутентификация
	if user.TwoFactorEnabled {
		c.JSON(http.StatusOK, gin.H{
			"requires_2fa": true,
			"user_id":      user.ID,
		})
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, tokenPair)
}

// TelegramLogin обрабатывает запрос на вход через Telegram
func (h *AuthHandler) TelegramLogin(c *gin.Context) {
	var req models.TelegramLoginRequest
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

	// Аутентификация через Telegram
	tokenPair, _, err := h.authService.TelegramLogin(c.Request.Context(), req)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, tokenPair)
}

// RefreshToken обрабатывает запрос на обновление токенов
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest
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

	// Обновление токенов
	tokenPair, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, tokenPair)
}

// Logout обрабатывает запрос на выход из системы
func (h *AuthHandler) Logout(c *gin.Context) {
	var req models.LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
			"code":  "invalid_request",
		})
		return
	}

	// Получение токена из заголовка
	authHeader := c.GetHeader("Authorization")
	tokenParts := authHeader[7:] // Убираем "Bearer "

	// Выход из системы
	err := h.authService.Logout(c.Request.Context(), tokenParts, req.RefreshToken)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully logged out",
	})
}

// LogoutAll обрабатывает запрос на выход из всех устройств
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	// Получение ID пользователя из контекста
	userIDStr, _ := c.Get("user_id")
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "invalid_request",
		})
		return
	}

	// Выход из всех устройств
	err = h.authService.LogoutAll(c.Request.Context(), userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully logged out from all devices",
	})
}

// VerifyEmail обрабатывает запрос на подтверждение email
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var req models.VerifyEmailRequest
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

	// Подтверждение email
	err := h.authService.VerifyEmail(c.Request.Context(), req.Token)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Email successfully verified",
	})
}

// ResendVerification обрабатывает запрос на повторную отправку письма для подтверждения email
func (h *AuthHandler) ResendVerification(c *gin.Context) {
	var req models.ResendVerificationRequest
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

	// Повторная отправка письма
	err := h.authService.ResendVerification(c.Request.Context(), req.Email)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Verification email sent",
	})
}

// ForgotPassword обрабатывает запрос на восстановление пароля
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest
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

	// Инициирование процесса восстановления пароля
	err := h.authService.ForgotPassword(c.Request.Context(), req.Email)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Password reset email sent",
	})
}

// ResetPassword обрабатывает запрос на сброс пароля
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
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

	// Сброс пароля
	err := h.authService.ResetPassword(c.Request.Context(), req.Token, req.Password)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "Password successfully reset",
	})
}

// Enable2FA обрабатывает запрос на включение двухфакторной аутентификации
func (h *AuthHandler) Enable2FA(c *gin.Context) {
	// Получение ID пользователя из контекста
	userIDStr, _ := c.Get("user_id")
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "invalid_request",
		})
		return
	}

	// Включение 2FA
	secret, qrCodeURL, err := h.authService.Enable2FA(c.Request.Context(), userID)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"secret":      secret,
		"qr_code_url": qrCodeURL,
	})
}

// Verify2FA обрабатывает запрос на проверку кода двухфакторной аутентификации
func (h *AuthHandler) Verify2FA(c *gin.Context) {
	var req models.Verify2FARequest
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

	// Получение ID пользователя из контекста
	userIDStr, _ := c.Get("user_id")
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "invalid_request",
		})
		return
	}

	// Проверка кода 2FA
	err = h.authService.Verify2FA(c.Request.Context(), userID, req.Code)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "2FA code verified",
	})
}

// Disable2FA обрабатывает запрос на отключение двухфакторной аутентификации
func (h *AuthHandler) Disable2FA(c *gin.Context) {
	var req models.Disable2FARequest
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

	// Получение ID пользователя из контекста
	userIDStr, _ := c.Get("user_id")
	userID, err := uuid.Parse(userIDStr.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
			"code":  "invalid_request",
		})
		return
	}

	// Отключение 2FA
	err = h.authService.Disable2FA(c.Request.Context(), userID, req.Code)
	if err != nil {
		h.handleError(c, err)
		return
	}

	// Формирование ответа
	c.JSON(http.StatusOK, gin.H{
		"message": "2FA disabled",
	})
}

// handleError обрабатывает ошибки и возвращает соответствующий HTTP-ответ
func (h *AuthHandler) handleError(c *gin.Context, err error) {
	h.logger.Error("Error in auth handler", zap.Error(err))

	status := http.StatusInternalServerError
	errMsg := "Internal server error"
	errCode := "internal_error"

	switch {
	case err == nil:
		return
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
	case err == models.ErrUserNotFound:
		status = http.StatusNotFound
		errMsg = "User not found"
		errCode = "user_not_found"
	case err == models.ErrInvalidToken:
		status = http.StatusUnauthorized
		errMsg = "Invalid token"
		errCode = "invalid_token"
	case err == models.ErrExpiredToken:
		status = http.StatusUnauthorized
		errMsg = "Token expired"
		errCode = "token_expired"
	case err == models.ErrRevokedToken:
		status = http.StatusUnauthorized
		errMsg = "Token revoked"
		errCode = "token_revoked"
	case err == models.ErrInvalidRefreshToken:
		status = http.StatusUnauthorized
		errMsg = "Invalid refresh token"
		errCode = "invalid_refresh_token"
	case err == models.ErrEmailNotVerified:
		status = http.StatusForbidden
		errMsg = "Email not verified"
		errCode = "email_not_verified"
	case err == models.ErrUserBlocked:
		status = http.StatusForbidden
		errMsg = "User is blocked"
		errCode = "user_blocked"
	case err == models.ErrInvalid2FACode:
		status = http.StatusBadRequest
		errMsg = "Invalid 2FA code"
		errCode = "invalid_2fa_code"
	case err == models.Err2FARequired:
		status = http.StatusForbidden
		errMsg = "2FA required"
		errCode = "2fa_required"
	case err == models.Err2FAAlreadyEnabled:
		status = http.StatusConflict
		errMsg = "2FA already enabled"
		errCode = "2fa_already_enabled"
	case err == models.Err2FANotEnabled:
		status = http.StatusBadRequest
		errMsg = "2FA not enabled"
		errCode = "2fa_not_enabled"
	case err == models.ErrTelegramAuth:
		status = http.StatusUnauthorized
		errMsg = "Telegram authentication failed"
		errCode = "telegram_auth_failed"
	case err == models.ErrTelegramIDExists:
		status = http.StatusConflict
		errMsg = "Telegram ID already linked to another account"
		errCode = "telegram_id_exists"
	}

	c.JSON(status, gin.H{
		"error": errMsg,
		"code":  errCode,
	})
}
