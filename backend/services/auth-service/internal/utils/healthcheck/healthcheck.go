// File: backend/services/auth-service/internal/utils/healthcheck/healthcheck.go

package healthcheck

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

// Status представляет статус компонента
type Status string

const (
	// StatusUp означает, что компонент работает нормально
	StatusUp Status = "UP"
	// StatusDown означает, что компонент не работает
	StatusDown Status = "DOWN"
)

// Component представляет компонент системы для проверки здоровья
type Component struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Error  string `json:"error,omitempty"`
}

// HealthCheck представляет результат проверки здоровья системы
type HealthCheck struct {
	Status     Status      `json:"status"`
	Components []Component `json:"components"`
	Timestamp  time.Time   `json:"timestamp"`
}

// Service представляет сервис проверки здоровья
type Service struct {
	db     *sql.DB
	redis  *redis.Client
	logger *zap.Logger
}

// NewService создает новый сервис проверки здоровья
func NewService(db *sql.DB, redis *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		redis:  redis,
		logger: logger,
	}
}

// CheckHealth проверяет здоровье всех компонентов системы
func (s *Service) CheckHealth(ctx context.Context) HealthCheck {
	components := []Component{}
	overallStatus := StatusUp

	// Проверка базы данных
	dbComponent := s.checkDatabase(ctx)
	components = append(components, dbComponent)
	if dbComponent.Status == StatusDown {
		overallStatus = StatusDown
	}

	// Проверка Redis
	redisComponent := s.checkRedis(ctx)
	components = append(components, redisComponent)
	if redisComponent.Status == StatusDown {
		overallStatus = StatusDown
	}

	return HealthCheck{
		Status:     overallStatus,
		Components: components,
		Timestamp:  time.Now(),
	}
}

// checkDatabase проверяет соединение с базой данных
func (s *Service) checkDatabase(ctx context.Context) Component {
	component := Component{
		Name:   "database",
		Status: StatusUp,
	}

	if s.db == nil {
		component.Status = StatusDown
		component.Error = "database connection is not initialized"
		return component
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := s.db.PingContext(ctx)
	if err != nil {
		component.Status = StatusDown
		component.Error = err.Error()
		s.logger.Error("Database health check failed", zap.Error(err))
	}

	return component
}

// checkRedis проверяет соединение с Redis
func (s *Service) checkRedis(ctx context.Context) Component {
	component := Component{
		Name:   "redis",
		Status: StatusUp,
	}

	if s.redis == nil {
		component.Status = StatusDown
		component.Error = "redis connection is not initialized"
		return component
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.redis.Ping(ctx).Result()
	if err != nil {
		component.Status = StatusDown
		component.Error = err.Error()
		s.logger.Error("Redis health check failed", zap.Error(err))
	}

	return component
}

// Handler возвращает HTTP обработчик для проверки здоровья
func (s *Service) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		healthCheck := s.CheckHealth(r.Context())

		w.Header().Set("Content-Type", "application/json")
		if healthCheck.Status == StatusDown {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		encoder := json.NewEncoder(w)
		if err := encoder.Encode(healthCheck); err != nil {
			s.logger.Error("Failed to encode health check response", zap.Error(err))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}
