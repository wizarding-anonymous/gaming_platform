// File: backend/services/account-service/internal/utils/logger/logger.go

package logger

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// NewLogger создает новый экземпляр логгера
func NewLogger(level string, environment string) (*zap.Logger, error) {
	var config zap.Config

	if environment == "production" {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// Установка уровня логирования
	switch level {
	case "debug":
		config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
	case "info":
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	case "warn":
		config.Level = zap.NewAtomicLevelAt(zapcore.WarnLevel)
	case "error":
		config.Level = zap.NewAtomicLevelAt(zapcore.ErrorLevel)
	default:
		config.Level = zap.NewAtomicLevelAt(zapcore.InfoLevel)
	}

	return config.Build()
}

// GinMiddleware создает middleware для логирования HTTP-запросов
func GinMiddleware(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		// Обработка запроса
		c.Next()

		end := time.Now()
		latency := end.Sub(start)

		// Получение информации о пользователе
		userId := c.GetString("user_id")
		userRoles := c.GetStringSlice("user_roles")

		// Логирование запроса
		if len(c.Errors) > 0 {
			// Ошибки
			for _, e := range c.Errors.Errors() {
				logger.Error("HTTP Request Error",
					zap.String("path", path),
					zap.String("query", query),
					zap.String("method", c.Request.Method),
					zap.Int("status", c.Writer.Status()),
					zap.String("ip", c.ClientIP()),
					zap.String("user-agent", c.Request.UserAgent()),
					zap.Duration("latency", latency),
					zap.String("user_id", userId),
					zap.Strings("user_roles", userRoles),
					zap.String("error", e),
					zap.String("trace_id", c.GetString("trace_id")),
					zap.String("span_id", c.GetString("span_id")),
				)
			}
		} else {
			// Успешные запросы
			logger.Info("HTTP Request",
				zap.String("path", path),
				zap.String("query", query),
				zap.String("method", c.Request.Method),
				zap.Int("status", c.Writer.Status()),
				zap.String("ip", c.ClientIP()),
				zap.String("user-agent", c.Request.UserAgent()),
				zap.Duration("latency", latency),
				zap.String("user_id", userId),
				zap.Strings("user_roles", userRoles),
				zap.String("trace_id", c.GetString("trace_id")),
				zap.String("span_id", c.GetString("span_id")),
			)
		}
	}
}

// GrpcUnaryServerInterceptor создает перехватчик для логирования gRPC-запросов
func GrpcUnaryServerInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		// Получение метаданных запроса
		md, _ := metadata.FromIncomingContext(ctx)

		// Получение IP-адреса клиента
		var clientIP string
		if p, ok := peer.FromContext(ctx); ok {
			clientIP = p.Addr.String()
		}

		// Получение информации о пользователе
		var userId string
		var userRoles []string
		if ids, ok := md["user-id"]; ok && len(ids) > 0 {
			userId = ids[0]
		}
		if roles, ok := md["user-roles"]; ok {
			userRoles = roles
		}

		// Получение идентификаторов трассировки
		var traceId, spanId string
		if traces, ok := md["trace-id"]; ok && len(traces) > 0 {
			traceId = traces[0]
		}
		if spans, ok := md["span-id"]; ok && len(spans) > 0 {
			spanId = spans[0]
		}

		// Обработка запроса
		resp, err := handler(ctx, req)

		// Расчет времени выполнения
		duration := time.Since(start)

		// Логирование запроса
		if err != nil {
			logger.Error("gRPC Request Error",
				zap.String("method", info.FullMethod),
				zap.String("ip", clientIP),
				zap.Duration("duration", duration),
				zap.String("user_id", userId),
				zap.Strings("user_roles", userRoles),
				zap.Error(err),
				zap.String("trace_id", traceId),
				zap.String("span_id", spanId),
			)
		} else {
			logger.Info("gRPC Request",
				zap.String("method", info.FullMethod),
				zap.String("ip", clientIP),
				zap.Duration("duration", duration),
				zap.String("user_id", userId),
				zap.Strings("user_roles", userRoles),
				zap.String("trace_id", traceId),
				zap.String("span_id", spanId),
			)
		}

		return resp, err
	}
}
