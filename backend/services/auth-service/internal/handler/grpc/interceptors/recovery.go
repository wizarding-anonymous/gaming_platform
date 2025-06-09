// File: internal/handler/grpc/interceptors/recovery.go

package interceptors

import (
	"context"
	"runtime/debug"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryInterceptor представляет перехватчик для восстановления после паники в gRPC-обработчиках
type RecoveryInterceptor struct {
	logger *zap.Logger
}

// NewRecoveryInterceptor создает новый экземпляр RecoveryInterceptor
func NewRecoveryInterceptor(logger *zap.Logger) *RecoveryInterceptor {
	return &RecoveryInterceptor{
		logger: logger,
	}
}

// Unary возвращает унарный перехватчик для восстановления после паники
func (i *RecoveryInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				// Получение стека вызовов
				stack := debug.Stack()
				
				// Логирование ошибки
				i.logger.Error("Panic recovered in gRPC handler",
					zap.Any("panic", r),
					zap.ByteString("stack", stack),
					zap.String("method", info.FullMethod),
				)

				// Увеличение счетчика паник
				metrics.GrpcPanicsTotal.Inc()

				// Возврат ошибки клиенту
				err = status.Errorf(codes.Internal, "Internal server error")
			}
		}()

		// Вызов обработчика
		return handler(ctx, req)
	}
}

// Stream возвращает потоковый перехватчик для восстановления после паники
func (i *RecoveryInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				// Получение стека вызовов
				stack := debug.Stack()
				
				// Логирование ошибки
				i.logger.Error("Panic recovered in gRPC stream handler",
					zap.Any("panic", r),
					zap.ByteString("stack", stack),
					zap.String("method", info.FullMethod),
				)

				// Увеличение счетчика паник
				metrics.GrpcPanicsTotal.Inc()

				// Возврат ошибки клиенту
				err = status.Errorf(codes.Internal, "Internal server error")
			}
		}()

		// Вызов обработчика
		return handler(srv, ss)
	}
}
