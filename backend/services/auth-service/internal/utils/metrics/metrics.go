package utils

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics содержит метрики для мониторинга сервиса
var (
	// RequestsTotal счетчик общего количества запросов
	RequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_service_requests_total",
		Help: "The total number of requests",
	})

	// ResponsesTotal счетчик ответов по статусам
	ResponsesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_responses_total",
		Help: "The total number of responses by status code",
	}, []string{"status"})

	// RequestDuration гистограмма времени обработки запросов
	RequestDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "auth_service_request_duration_seconds",
		Help:    "The request duration in seconds",
		Buckets: prometheus.DefBuckets,
	})

	// AuthenticatedRequestsTotal счетчик аутентифицированных запросов
	AuthenticatedRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_service_authenticated_requests_total",
		Help: "The total number of authenticated requests",
	})

	// LoginAttemptsTotal счетчик попыток входа
	LoginAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_login_attempts_total",
		Help: "The total number of login attempts",
	}, []string{"status"})

	// RegistrationAttemptsTotal счетчик попыток регистрации
	RegistrationAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_registration_attempts_total",
		Help: "The total number of registration attempts",
	}, []string{"status"})

	// TokenRefreshTotal счетчик обновлений токенов
	TokenRefreshTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_token_refresh_total",
		Help: "The total number of token refreshes",
	}, []string{"status"})

	// DatabaseOperationsTotal счетчик операций с базой данных
	DatabaseOperationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_database_operations_total",
		Help: "The total number of database operations",
	}, []string{"operation", "status"})

	// DatabaseOperationDuration гистограмма времени выполнения операций с базой данных
	DatabaseOperationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "auth_service_database_operation_duration_seconds",
		Help:    "The database operation duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"operation"})

	// CacheOperationsTotal счетчик операций с кэшем
	CacheOperationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_cache_operations_total",
		Help: "The total number of cache operations",
	}, []string{"operation", "status"})

	// CacheOperationDuration гистограмма времени выполнения операций с кэшем
	CacheOperationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "auth_service_cache_operation_duration_seconds",
		Help:    "The cache operation duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"operation"})

	// ActiveSessions счетчик активных сессий
	ActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "auth_service_active_sessions",
		Help: "The number of active sessions",
	})

	// RateLimitExceededTotal счетчик превышений ограничения частоты запросов
	RateLimitExceededTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_service_rate_limit_exceeded_total",
		Help: "The total number of rate limit exceeded events",
	})
)
