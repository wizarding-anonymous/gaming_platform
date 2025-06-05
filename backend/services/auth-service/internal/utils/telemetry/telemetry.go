// File: backend/services/auth-service/internal/utils/telemetry/telemetry.go
package telemetry

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// InitTracer инициализирует трассировщик OpenTelemetry
func InitTracer(serviceName, jaegerEndpoint string, logger *zap.Logger) (func(), error) {
	// Создание ресурса с информацией о сервисе
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, err
	}

	// Создание экспортера Jaeger
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(jaegerEndpoint)))
	if err != nil {
		return nil, err
	}

	// Создание провайдера трассировки
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)

	// Установка глобального провайдера трассировки
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Возвращаем функцию для закрытия трассировщика
	return func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			logger.Error("Error shutting down tracer provider", zap.Error(err))
		}
	}, nil
}

// InitOTLPTracer инициализирует трассировщик OpenTelemetry с использованием OTLP
func InitOTLPTracer(serviceName, otlpEndpoint string, logger *zap.Logger) (func(), error) {
	// Создание ресурса с информацией о сервисе
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, err
	}

	// Создание клиента OTLP
	client := otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(otlpEndpoint),
		otlptracegrpc.WithInsecure(),
	)

	// Создание экспортера OTLP
	exp, err := otlptrace.New(context.Background(), client)
	if err != nil {
		return nil, err
	}

	// Создание провайдера трассировки
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)

	// Установка глобального провайдера трассировки
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Возвращаем функцию для закрытия трассировщика
	return func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			logger.Error("Error shutting down tracer provider", zap.Error(err))
		}
	}, nil
}

// StartSpan начинает новый спан трассировки
func StartSpan(ctx context.Context, name string) (context.Context, trace.Span) {
	tracer := otel.Tracer("auth-service")
	return tracer.Start(ctx, name)
}

// PrometheusHandler возвращает обработчик HTTP для метрик Prometheus
func PrometheusHandler() http.HandlerFunc {
	return promhttp.Handler().ServeHTTP
}
