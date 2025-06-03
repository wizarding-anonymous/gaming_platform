// account-service\pkg\metrics\metrics.go

package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// Registry содержит все метрики приложения
type Registry struct {
	HttpRequestsTotal   *prometheus.CounterVec
	HttpRequestDuration *prometheus.HistogramVec
	GrpcRequestsTotal   *prometheus.CounterVec
	GrpcRequestDuration *prometheus.HistogramVec
	DatabaseQueryTotal  *prometheus.CounterVec
	DatabaseQueryDuration *prometheus.HistogramVec
	CacheHitsTotal      *prometheus.CounterVec
	CacheMissesTotal    *prometheus.CounterVec
	BusinessOperationsTotal *prometheus.CounterVec
	BusinessOperationsDuration *prometheus.HistogramVec
}

// NewRegistry создает новый реестр метрик
func NewRegistry() *Registry {
	registry := &Registry{
		HttpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		HttpRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "http_request_duration_seconds",
				Help: "HTTP request duration in seconds",
				Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1, 2, 5, 10},
			},
			[]string{"method", "path", "status"},
		),
		GrpcRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "grpc_requests_total",
				Help: "Total number of gRPC requests",
			},
			[]string{"method", "status"},
		),
		GrpcRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "grpc_request_duration_seconds",
				Help: "gRPC request duration in seconds",
				Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1, 2, 5, 10},
			},
			[]string{"method", "status"},
		),
		DatabaseQueryTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "database_query_total",
				Help: "Total number of database queries",
			},
			[]string{"operation", "table", "status"},
		),
		DatabaseQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "database_query_duration_seconds",
				Help: "Database query duration in seconds",
				Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1, 2, 5},
			},
			[]string{"operation", "table"},
		),
		CacheHitsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_hits_total",
				Help: "Total number of cache hits",
			},
			[]string{"cache", "key_pattern"},
		),
		CacheMissesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_misses_total",
				Help: "Total number of cache misses",
			},
			[]string{"cache", "key_pattern"},
		),
		BusinessOperationsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "business_operations_total",
				Help: "Total number of business operations",
			},
			[]string{"operation", "status"},
		),
		BusinessOperationsDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "business_operations_duration_seconds",
				Help: "Business operation duration in seconds",
				Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1, 2, 5, 10},
			},
			[]string{"operation"},
		),
	}

	// Регистрация всех метрик в глобальном реестре Prometheus
	prometheus.MustRegister(
		registry.HttpRequestsTotal,
		registry.HttpRequestDuration,
		registry.GrpcRequestsTotal,
		registry.GrpcRequestDuration,
		registry.DatabaseQueryTotal,
		registry.DatabaseQueryDuration,
		registry.CacheHitsTotal,
		registry.CacheMissesTotal,
		registry.BusinessOperationsTotal,
		registry.BusinessOperationsDuration,
	)

	return registry
}

// GinMiddleware создает middleware для сбора метрик HTTP-запросов
func GinMiddleware(registry *Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		
		// Обработка запроса
		c.Next()
		
		// Расчет времени выполнения
		duration := time.Since(start).Seconds()
		
		// Получение пути запроса
		path := c.FullPath()
		if path == "" {
			path = "unknown"
		}
		
		// Получение статуса ответа
		status := strconv.Itoa(c.Writer.Status())
		
		// Обновление метрик
		registry.HttpRequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
		registry.HttpRequestDuration.WithLabelValues(c.Request.Method, path, status).Observe(duration)
	}
}

// GrpcUnaryServerInterceptor создает перехватчик для сбора метрик gRPC-запросов
func GrpcUnaryServerInterceptor(registry *Registry) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		
		// Обработка запроса
		resp, err := handler(ctx, req)
		
		// Расчет времени выполнения
		duration := time.Since(start).Seconds()
		
		// Получение статуса ответа
		statusCode := "OK"
		if err != nil {
			statusCode = status.Code(err).String()
		}
		
		// Обновление метрик
		registry.GrpcRequestsTotal.WithLabelValues(info.FullMethod, statusCode).Inc()
		registry.GrpcRequestDuration.WithLabelValues(info.FullMethod, statusCode).Observe(duration)
		
		return resp, err
	}
}

// TrackDatabaseQuery отслеживает выполнение запроса к базе данных
func (r *Registry) TrackDatabaseQuery(operation, table string, status string, duration float64) {
	r.DatabaseQueryTotal.WithLabelValues(operation, table, status).Inc()
	r.DatabaseQueryDuration.WithLabelValues(operation, table).Observe(duration)
}

// TrackCacheHit отслеживает попадание в кэш
func (r *Registry) TrackCacheHit(cache, keyPattern string) {
	r.CacheHitsTotal.WithLabelValues(cache, keyPattern).Inc()
}

// TrackCacheMiss отслеживает промах в кэше
func (r *Registry) TrackCacheMiss(cache, keyPattern string) {
	r.CacheMissesTotal.WithLabelValues(cache, keyPattern).Inc()
}

// TrackBusinessOperation отслеживает выполнение бизнес-операции
func (r *Registry) TrackBusinessOperation(operation, status string, duration float64) {
	r.BusinessOperationsTotal.WithLabelValues(operation, status).Inc()
	r.BusinessOperationsDuration.WithLabelValues(operation).Observe(duration)
}
