// File: backend/services/auth-service/internal/utils/metrics/metrics.go
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

	// TwoFactorVerificationAttemptsTotal счетчик попыток верификации 2FA
	TwoFactorVerificationAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_2fa_verification_attempts_total",
		Help: "The total number of 2FA verification attempts",
	}, []string{"status"}) // e.g., "success_activation", "failure_activation_invalid_code", "success_login", "failure_login_invalid_code", "failure_not_enabled", "success_disable", "failure_disable_invalid_code"

	// EmailVerificationAttemptsTotal счетчик попыток верификации email
	EmailVerificationAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_email_verification_attempts_total",
		Help: "The total number of email verification attempts",
	}, []string{"status"}) // e.g., "success", "failure_invalid_or_expired_token"

	// APIKeyValidationAttemptsTotal счетчик попыток валидации API ключей
	APIKeyValidationAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_api_key_validation_attempts_total",
		Help: "The total number of API key validation attempts",
	}, []string{"status"}) // e.g., "success", "failure_invalid_key", "failure_revoked", "failure_expired", "failure_no_permission"

	// PasswordResetRequestsTotal счетчик запросов на сброс пароля
	PasswordResetRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_password_reset_requests_total",
		Help: "The total number of password reset requests (forgot password step)",
	}, []string{"status"}) // e.g., "success_request_sent", "failure_user_not_found"

	// PasswordResetAttemptsTotal счетчик попыток установки нового пароля после сброса
	PasswordResetAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "auth_service_password_reset_attempts_total",
		Help: "The total number of password reset attempts (set new password step)",
	}, []string{"status"}) // e.g., "success", "failure_invalid_or_expired_token"
)
