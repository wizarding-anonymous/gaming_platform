// File: internal/handler/http/middleware/tracing.go

package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// TracingMiddleware добавляет трассировку запросов с использованием OpenTelemetry
func TracingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Получение пропагатора контекста
		propagator := otel.GetTextMapPropagator()
		
		// Извлечение контекста трассировки из заголовков запроса
		ctx := propagator.Extract(c.Request.Context(), propagation.HeaderCarrier(c.Request.Header))
		
		// Получение трассировщика
		tracer := otel.Tracer("auth-service")
		
		// Получение или генерация ID запроса
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
			c.Header("X-Request-ID", requestID)
		}
		
		// Создание нового спана
		ctx, span := tracer.Start(
			ctx,
			c.FullPath(),
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.url", c.Request.URL.String()),
				attribute.String("http.client_ip", c.ClientIP()),
				attribute.String("http.user_agent", c.Request.UserAgent()),
				attribute.String("request.id", requestID),
			),
		)
		defer span.End()
		
		// Установка контекста трассировки в Gin
		c.Request = c.Request.WithContext(ctx)
		
		// Обработка запроса
		c.Next()
		
		// Добавление информации о результате запроса в спан
		span.SetAttributes(
			attribute.Int("http.status_code", c.Writer.Status()),
			attribute.Int("http.response_size", c.Writer.Size()),
		)
		
		// Если произошла ошибка, отметить спан как ошибочный
		if c.Writer.Status() >= 400 {
			span.SetAttributes(attribute.Bool("error", true))
		}
	}
}
