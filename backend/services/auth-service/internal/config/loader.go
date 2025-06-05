// File: backend/services/auth-service/internal/config/loader.go
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// LoadConfig загружает конфигурацию из файла и переменных окружения
func LoadConfig() (*Config, error) {
	// Установка значений по умолчанию
	setDefaults()

	// Настройка Viper для чтения конфигурации
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/auth-service")

	// Чтение переменных окружения
	viper.SetEnvPrefix("AUTH")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Чтение конфигурационного файла
	if err := viper.ReadInConfig(); err != nil {
		// Если файл не найден, используем только переменные окружения
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Загрузка конфигурации в структуру
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// setDefaults устанавливает значения по умолчанию для конфигурации
func setDefaults() {
	// Настройки сервера
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", 10*time.Second)
	viper.SetDefault("server.write_timeout", 10*time.Second)
	viper.SetDefault("server.idle_timeout", 120*time.Second)
	viper.SetDefault("server.shutdown_timeout", 5*time.Second)

	// Настройки базы данных
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "postgres")
	viper.SetDefault("database.password", "postgres")
	viper.SetDefault("database.dbname", "auth_service")
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.max_open_conns", 20)
	viper.SetDefault("database.max_idle_conns", 5)
	viper.SetDefault("database.conn_max_lifetime", 1*time.Hour)
	viper.SetDefault("database.auto_migrate", true)
	viper.SetDefault("database.migrations_dir", "migrations")

	// Настройки Redis
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)

	// Настройки Kafka
	viper.SetDefault("kafka.brokers", []string{"localhost:9092"})
	viper.SetDefault("kafka.producer.topic", "auth.events")
	viper.SetDefault("kafka.consumer.topics", []string{"account.events"})
	viper.SetDefault("kafka.consumer.group_id", "auth-service")

	// Настройки JWT
	viper.SetDefault("jwt.access_token.expires_in", 15*time.Minute)
	viper.SetDefault("jwt.refresh_token.expires_in", 7*24*time.Hour)

	// Настройки логирования
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")

	// Настройки телеметрии
	viper.SetDefault("telemetry.metrics.enabled", true)
	viper.SetDefault("telemetry.metrics.port", 9090)
	viper.SetDefault("telemetry.tracing.enabled", true)
	viper.SetDefault("telemetry.tracing.jaeger.agent_host", "localhost")
	viper.SetDefault("telemetry.tracing.jaeger.agent_port", 6831)

	// Настройки gRPC
	viper.SetDefault("grpc.port", 9000)
	viper.SetDefault("grpc.enable_reflection", true)

	// Настройки CORS
	viper.SetDefault("cors.allow_origins", []string{"*"})
	viper.SetDefault("cors.allow_methods", []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
	viper.SetDefault("cors.allow_headers", []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"})
	viper.SetDefault("cors.expose_headers", []string{"Content-Length", "Content-Type"})
	viper.SetDefault("cors.allow_credentials", true)
	viper.SetDefault("cors.max_age", 86400)
}
