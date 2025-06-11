// File: backend/services/auth-service/internal/handler/http/middleware/metrics.go

package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/metrics"
)

// MetricsMiddleware собирает метрики запросов
func MetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Увеличение счетчика запросов
		metrics.RequestsTotal.Inc()

		// Запуск таймера для измерения времени обработки запроса
		start := time.Now()

		// Обработка запроса
		c.Next()

		// Расчет времени обработки
		duration := time.Since(start).Seconds()

		// Запись метрик по статусу ответа
		statusCode := strconv.Itoa(c.Writer.Status())
		metrics.ResponsesTotal.WithLabelValues(statusCode).Inc()
		
		// Запись метрик по времени обработки
		metrics.RequestDuration.Observe(duration)
		
		// Запись метрик по методу и пути
		metrics.RequestDurationByPath.WithLabelValues(c.Request.Method, c.FullPath()).Observe(duration)
	}
}
