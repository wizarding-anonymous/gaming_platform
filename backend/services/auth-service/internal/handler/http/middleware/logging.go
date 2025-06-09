// File: backend/services/auth-service/internal/handler/http/middleware/logging.go
package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/utils/logger"
	"go.uber.org/zap"
)

// LoggingMiddleware логирует информацию о запросах
func LoggingMiddleware(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Генерация уникального ID запроса
		requestID := uuid.New().String()
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		// Создание логгера с контекстом запроса
		requestLogger := logger.WithRequestID(log, requestID)

		// Запись времени начала обработки запроса
		startTime := time.Now()

		// Логирование начала запроса
		requestLogger.Info("Request started",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
		)

		// Добавление логгера в контекст
		c.Set("logger", requestLogger)

		// Обработка запроса
		c.Next()

		// Логирование завершения запроса
		duration := time.Since(startTime)
		requestLogger.Info("Request completed",
			zap.Int("status", c.Writer.Status()),
			zap.Duration("duration", duration),
			zap.Int("size", c.Writer.Size()),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
		)
	}
}
