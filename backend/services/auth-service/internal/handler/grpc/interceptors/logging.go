// File: internal/handler/grpc/interceptors/logging.go

package interceptors

import (
	"context"
	"path"
	"time"

	"github.com/google/uuid"
	"github.com/your-org/auth-service/internal/utils/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// LoggingInterceptor представляет перехватчик для логирования gRPC-запросов
type LoggingInterceptor struct {
	logger *zap.Logger
}

// NewLoggingInterceptor создает новый экземпляр LoggingInterceptor
func NewLoggingInterceptor(logger *zap.Logger) *LoggingInterceptor {
	return &LoggingInterceptor{
		logger: logger,
	}
}

// Unary возвращает унарный перехватчик для логирования
func (i *LoggingInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Получение или генерация ID запроса
		requestID := getRequestIDFromContext(ctx)
		if requestID == "" {
			requestID = uuid.New().String()
			ctx = addRequestIDToContext(ctx, requestID)
		}

		// Создание логгера с контекстом запроса
		requestLogger := logger.WithRequestID(i.logger, requestID)

		// Получение информации о клиенте
		peerInfo, _ := peer.FromContext(ctx)
		clientIP := "unknown"
		if peerInfo != nil {
			clientIP = peerInfo.Addr.String()
		}

		// Запись времени начала обработки запроса
		startTime := time.Now()

		// Логирование начала запроса
		requestLogger.Info("gRPC request started",
			zap.String("method", info.FullMethod),
			zap.String("client_ip", clientIP),
		)

		// Добавление логгера в контекст
		ctx = context.WithValue(ctx, "logger", requestLogger)

		// Обработка запроса
		resp, err := handler(ctx, req)

		// Расчет времени обработки
		duration := time.Since(startTime)

		// Определение статуса ответа
		statusCode := codes.OK
		if err != nil {
			statusCode = status.Code(err)
		}

		// Логирование завершения запроса
		requestLogger.Info("gRPC request completed",
			zap.String("method", info.FullMethod),
			zap.String("status", statusCode.String()),
			zap.Duration("duration", duration),
			zap.Error(err),
		)

		return resp, err
	}
}

// Stream возвращает потоковый перехватчик для логирования
func (i *LoggingInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Получение или генерация ID запроса
		ctx := ss.Context()
		requestID := getRequestIDFromContext(ctx)
		if requestID == "" {
			requestID = uuid.New().String()
			ctx = addRequestIDToContext(ctx, requestID)
		}

		// Создание логгера с контекстом запроса
		requestLogger := logger.WithRequestID(i.logger, requestID)

		// Получение информации о клиенте
		peerInfo, _ := peer.FromContext(ctx)
		clientIP := "unknown"
		if peerInfo != nil {
			clientIP = peerInfo.Addr.String()
		}

		// Запись времени начала обработки запроса
		startTime := time.Now()

		// Логирование начала запроса
		requestLogger.Info("gRPC stream started",
			zap.String("method", info.FullMethod),
			zap.String("client_ip", clientIP),
		)

		// Создание обертки для потока с контекстом, содержащим логгер
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          context.WithValue(ctx, "logger", requestLogger),
		}

		// Обработка потока
		err := handler(srv, wrappedStream)

		// Расчет времени обработки
		duration := time.Since(startTime)

		// Определение статуса ответа
		statusCode := codes.OK
		if err != nil {
			statusCode = status.Code(err)
		}

		// Логирование завершения потока
		requestLogger.Info("gRPC stream completed",
			zap.String("method", info.FullMethod),
			zap.String("status", statusCode.String()),
			zap.Duration("duration", duration),
			zap.Error(err),
		)

		return err
	}
}

// getRequestIDFromContext извлекает ID запроса из контекста
func getRequestIDFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	values := md.Get("x-request-id")
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

// addRequestIDToContext добавляет ID запроса в контекст
func addRequestIDToContext(ctx context.Context, requestID string) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.New(map[string]string{})
	}

	md.Set("x-request-id", requestID)
	return metadata.NewIncomingContext(ctx, md)
}

// getMethodName извлекает имя метода из полного пути
func getMethodName(fullMethodName string) string {
	return path.Base(fullMethodName)
}
