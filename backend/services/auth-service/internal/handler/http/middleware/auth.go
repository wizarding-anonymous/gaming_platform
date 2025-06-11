// File: backend/services/auth-service/internal/handler/http/middleware/auth.go

package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/domain/errors"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/service"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/metrics"
	"go.uber.org/zap"
)

// AuthMiddleware проверяет аутентификацию пользователя
func AuthMiddleware(tokenService *service.TokenService, logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Получение токена из заголовка Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header is required",
				"code":  "unauthorized",
			})
			return
		}

		// Проверка формата токена
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization format, expected 'Bearer {token}'",
				"code":  "unauthorized",
			})
			return
		}

		tokenString := parts[1]

		// Валидация токена
		token, claims, err := tokenService.ValidateAccessToken(c.Request.Context(), tokenString)
		if err != nil {
			status := http.StatusUnauthorized
			errMsg := "Invalid token"
			errCode := "unauthorized"

			if err == errors.ErrExpiredToken {
				errMsg = "Token expired"
				errCode = "token_expired"
			} else if err == errors.ErrRevokedToken {
				errMsg = "Token revoked"
				errCode = "token_revoked"
			}

			logger.Warn("Token validation failed",
				zap.String("error", errMsg),
				zap.Error(err),
				zap.String("client_ip", c.ClientIP()),
			)

			c.AbortWithStatusJSON(status, gin.H{
				"error": errMsg,
				"code":  errCode,
			})
			return
		}

		// Сохранение информации о пользователе в контексте
		c.Set("token", token)
		c.Set("claims", claims)
		c.Set("user_id", claims["sub"])

		// Увеличение метрики аутентифицированных запросов
		metrics.AuthenticatedRequestsTotal.Inc()

		c.Next()
	}
}
