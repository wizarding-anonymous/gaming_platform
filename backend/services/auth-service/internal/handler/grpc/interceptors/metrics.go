// File: backend/services/auth-service/internal/handler/grpc/interceptors/metrics.go

package interceptors

import (
	"context"
	"time"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MetricsInterceptor представляет перехватчик для сбора метрик gRPC-запросов
type MetricsInterceptor struct {
	logger *zap.Logger
}

// NewMetricsInterceptor создает новый экземпляр MetricsInterceptor
func NewMetricsInterceptor(logger *zap.Logger) *MetricsInterceptor {
	return &MetricsInterceptor{
		logger: logger,
	}
}

// Unary возвращает унарный перехватчик для сбора метрик
func (i *MetricsInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Увеличение счетчика запросов
		metrics.GrpcRequestsTotal.Inc()

		// Запуск таймера для измерения времени обработки запроса
		start := time.Now()

		// Обработка запроса
		resp, err := handler(ctx, req)

		// Расчет времени обработки
		duration := time.Since(start).Seconds()

		// Определение статуса ответа
		statusCode := codes.OK
		if err != nil {
			statusCode = status.Code(err)
		}

		// Запись метрик по статусу ответа
		metrics.GrpcResponsesTotal.WithLabelValues(statusCode.String()).Inc()
		
		// Запись метрик по времени обработки
		metrics.GrpcRequestDuration.Observe(duration)
		
		// Запись метрик по методу
		metrics.GrpcRequestDurationByMethod.WithLabelValues(getMethodName(info.FullMethod)).Observe(duration)

		return resp, err
	}
}

// Stream возвращает потоковый перехватчик для сбора метрик
func (i *MetricsInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Увеличение счетчика потоковых запросов
		metrics.GrpcStreamRequestsTotal.Inc()

		// Запуск таймера для измерения времени обработки потока
		start := time.Now()

		// Обработка потока
		err := handler(srv, ss)

		// Расчет времени обработки
		duration := time.Since(start).Seconds()

		// Определение статуса ответа
		statusCode := codes.OK
		if err != nil {
			statusCode = status.Code(err)
		}

		// Запись метрик по статусу ответа
		metrics.GrpcStreamResponsesTotal.WithLabelValues(statusCode.String()).Inc()
		
		// Запись метрик по времени обработки
		metrics.GrpcStreamDuration.Observe(duration)
		
		// Запись метрик по методу
		metrics.GrpcStreamDurationByMethod.WithLabelValues(getMethodName(info.FullMethod)).Observe(duration)

		return err
	}
}
