// File: backend/services/auth-service/internal/handler/http/middleware/middleware.go
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/your-org/auth-service/internal/domain/errors"
	"github.com/your-org/auth-service/internal/service"
	"github.com/your-org/auth-service/internal/utils/metrics"
	"go.uber.org/zap"
)

// AuthMiddleware проверяет аутентификацию пользователя
func AuthMiddleware(tokenService *service.TokenService) gin.HandlerFunc {
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

// RoleMiddleware проверяет наличие у пользователя требуемых ролей
func RoleMiddleware(requiredRoles []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Получение claims из контекста
		claims, exists := c.Get("claims")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "User not authenticated",
				"code":  "unauthorized",
			})
			return
		}

		// Получение ролей пользователя
		userRolesInterface, ok := claims.(map[string]interface{})["roles"].([]interface{})
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "User has no roles",
				"code":  "forbidden",
			})
			return
		}

		// Преобразование ролей в строки
		userRoles := make([]string, 0, len(userRolesInterface))
		for _, roleInterface := range userRolesInterface {
			role, ok := roleInterface.(string)
			if !ok {
				continue
			}
			userRoles = append(userRoles, role)
		}

		// Проверка наличия требуемых ролей
		hasRequiredRole := false
		for _, requiredRole := range requiredRoles {
			for _, userRole := range userRoles {
				if userRole == requiredRole {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}

		if !hasRequiredRole {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"code":  "forbidden",
			})
			return
		}

		c.Next()
	}
}

// RecoveryMiddleware обрабатывает панику в обработчиках
func RecoveryMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("Panic recovered", zap.Any("error", err))
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Internal server error",
					"code":  "internal_error",
				})
			}
		}()
		c.Next()
	}
}

// MetricsMiddleware собирает метрики запросов
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Увеличение счетчика запросов
		metrics.RequestsTotal.Inc()

		// Запуск таймера для измерения времени обработки запроса
		timer := metrics.RequestDuration.Start()

		c.Next()

		// Остановка таймера и запись метрики
		timer.ObserveDuration()

		// Увеличение счетчика ответов по статусу
		metrics.ResponsesTotal.WithLabelValues(c.Writer.Status()).Inc()
	}
}

// RateLimitMiddleware ограничивает частоту запросов
func RateLimitMiddleware(redisClient interface{}, limit int, period int) gin.HandlerFunc {
	return func(c *gin.Context) {
		// В реальном сценарии здесь бы использовался Redis для ограничения частоты запросов
		// Но для простоты примера мы просто пропускаем все запросы
		c.Next()
	}
}
