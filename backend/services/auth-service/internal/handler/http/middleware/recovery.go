// File: internal/handler/http/middleware/recovery.go

package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// RecoveryMiddleware восстанавливает работу после паники в обработчиках
func RecoveryMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				// Получение стека вызовов
				stack := debug.Stack()
				
				// Логирование ошибки
				logger.Error("Panic recovered",
					zap.Any("error", err),
					zap.ByteString("stack", stack),
					zap.String("method", c.Request.Method),
					zap.String("path", c.Request.URL.Path),
					zap.String("client_ip", c.ClientIP()),
				)

				// Отправка ответа клиенту
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "Internal server error",
					"code":  "internal_error",
				})
			}
		}()
		
		c.Next()
	}
}
