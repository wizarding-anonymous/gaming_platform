// File: internal/handler/grpc/interceptors/tracing.go

package interceptors

import (
	"context"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// TracingInterceptor представляет перехватчик для трассировки gRPC-запросов
type TracingInterceptor struct {
	logger *zap.Logger
}

// NewTracingInterceptor создает новый экземпляр TracingInterceptor
func NewTracingInterceptor(logger *zap.Logger) *TracingInterceptor {
	return &TracingInterceptor{
		logger: logger,
	}
}

// Unary возвращает унарный перехватчик для трассировки
func (i *TracingInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Получение пропагатора контекста
		propagator := otel.GetTextMapPropagator()
		
		// Извлечение контекста трассировки из метаданных запроса
		ctx = propagator.Extract(ctx, metadataCarrier(ctx))
		
		// Получение трассировщика
		tracer := otel.Tracer("auth-service")
		
		// Получение или генерация ID запроса
		requestID := getRequestIDFromContext(ctx)
		if requestID == "" {
			requestID = uuid.New().String()
			ctx = addRequestIDToContext(ctx, requestID)
		}
		
		// Получение информации о клиенте
		peerInfo, _ := peer.FromContext(ctx)
		clientIP := "unknown"
		if peerInfo != nil {
			clientIP = peerInfo.Addr.String()
		}
		
		// Создание нового спана
		ctx, span := tracer.Start(
			ctx,
			info.FullMethod,
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.method", getMethodName(info.FullMethod)),
				attribute.String("rpc.service", info.FullMethod),
				attribute.String("client.ip", clientIP),
				attribute.String("request.id", requestID),
			),
		)
		defer span.End()
		
		// Вызов обработчика
		resp, err := handler(ctx, req)
		
		// Добавление информации о результате запроса в спан
		if err != nil {
			statusCode := status.Code(err)
			span.SetAttributes(attribute.String("rpc.status_code", statusCode.String()))
			
			// Если произошла ошибка, отметить спан как ошибочный
			if statusCode != codes.OK {
				span.SetAttributes(attribute.Bool("error", true))
			}
		} else {
			span.SetAttributes(attribute.String("rpc.status_code", codes.OK.String()))
		}
		
		return resp, err
	}
}

// Stream возвращает потоковый перехватчик для трассировки
func (i *TracingInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Получение контекста
		ctx := ss.Context()
		
		// Получение пропагатора контекста
		propagator := otel.GetTextMapPropagator()
		
		// Извлечение контекста трассировки из метаданных запроса
		ctx = propagator.Extract(ctx, metadataCarrier(ctx))
		
		// Получение трассировщика
		tracer := otel.Tracer("auth-service")
		
		// Получение или генерация ID запроса
		requestID := getRequestIDFromContext(ctx)
		if requestID == "" {
			requestID = uuid.New().String()
			ctx = addRequestIDToContext(ctx, requestID)
		}
		
		// Получение информации о клиенте
		peerInfo, _ := peer.FromContext(ctx)
		clientIP := "unknown"
		if peerInfo != nil {
			clientIP = peerInfo.Addr.String()
		}
		
		// Создание нового спана
		ctx, span := tracer.Start(
			ctx,
			info.FullMethod,
			trace.WithAttributes(
				attribute.String("rpc.system", "grpc"),
				attribute.String("rpc.method", getMethodName(info.FullMethod)),
				attribute.String("rpc.service", info.FullMethod),
				attribute.String("client.ip", clientIP),
				attribute.String("request.id", requestID),
				attribute.Bool("rpc.stream", true),
			),
		)
		defer span.End()
		
		// Создание обертки для потока с контекстом трассировки
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}
		
		// Вызов обработчика
		err := handler(srv, wrappedStream)
		
		// Добавление информации о результате запроса в спан
		if err != nil {
			statusCode := status.Code(err)
			span.SetAttributes(attribute.String("rpc.status_code", statusCode.String()))
			
			// Если произошла ошибка, отметить спан как ошибочный
			if statusCode != codes.OK {
				span.SetAttributes(attribute.Bool("error", true))
			}
		} else {
			span.SetAttributes(attribute.String("rpc.status_code", codes.OK.String()))
		}
		
		return err
	}
}

// metadataCarrier представляет адаптер для извлечения контекста трассировки из метаданных gRPC
type metadataCarrier metadata.MD

// Get возвращает значение заголовка по ключу
func (mc metadataCarrier) Get(key string) string {
	values := metadata.MD(mc).Get(key)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// Set устанавливает значение заголовка
func (mc metadataCarrier) Set(key string, value string) {
	metadata.MD(mc).Set(key, value)
}

// Keys возвращает все ключи
func (mc metadataCarrier) Keys() []string {
	keys := make([]string, 0, len(metadata.MD(mc)))
	for k := range metadata.MD(mc) {
		keys = append(keys, k)
	}
	return keys
}

// metadataCarrier преобразует контекст в носитель метаданных
func metadataCarrier(ctx context.Context) propagation.TextMapCarrier {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		md = metadata.New(map[string]string{})
	}
	return metadataCarrier(md)
}
