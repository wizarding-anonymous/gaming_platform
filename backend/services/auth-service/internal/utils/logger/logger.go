// File: backend/services/auth-service/internal/utils/logger/logger.go
package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger создает новый экземпляр логгера
func NewLogger(level string, environment string) (*zap.Logger, error) {
	// Определение уровня логирования
	var logLevel zapcore.Level
	switch level {
	case "debug":
		logLevel = zapcore.DebugLevel
	case "info":
		logLevel = zapcore.InfoLevel
	case "warn":
		logLevel = zapcore.WarnLevel
	case "error":
		logLevel = zapcore.ErrorLevel
	default:
		logLevel = zapcore.InfoLevel
	}

	// Настройка кодировщика
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	// Создание ядра логгера
	var encoder zapcore.Encoder
	var output zapcore.WriteSyncer

	if environment == "production" {
		// В продакшене используем JSON-формат
		encoder = zapcore.NewJSONEncoder(encoderConfig)
		output = zapcore.AddSync(os.Stdout)
	} else {
		// В разработке используем консольный формат
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
		output = zapcore.AddSync(os.Stdout)
	}

	core := zapcore.NewCore(encoder, output, logLevel)

	// Создание логгера
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	return logger, nil
}

// WithContext добавляет контекстную информацию к логгеру
func WithContext(logger *zap.Logger, fields ...zapcore.Field) *zap.Logger {
	return logger.With(fields...)
}

// WithRequestID добавляет ID запроса к логгеру
func WithRequestID(logger *zap.Logger, requestID string) *zap.Logger {
	return logger.With(zap.String("request_id", requestID))
}

// WithUserID добавляет ID пользователя к логгеру
func WithUserID(logger *zap.Logger, userID string) *zap.Logger {
	return logger.With(zap.String("user_id", userID))
}

// WithService добавляет имя сервиса к логгеру
func WithService(logger *zap.Logger, service string) *zap.Logger {
	return logger.With(zap.String("service", service))
}

// WithComponent добавляет имя компонента к логгеру
func WithComponent(logger *zap.Logger, component string) *zap.Logger {
	return logger.With(zap.String("component", component))
}
