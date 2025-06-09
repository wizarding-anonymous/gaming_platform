// File: backend/services/account-service/internal/config/config.go
// account-service/internal/config/config.go
package config

import (
"fmt"
"time"

"github.com/spf13/viper"
)

// Config содержит все настройки приложения
type Config struct {
App        AppConfig
HTTP       HTTPConfig
GRPC       GRPCConfig
Database   DatabaseConfig
Redis      RedisConfig
Kafka      KafkaConfig
Auth       AuthConfig
S3         S3Config
SMS        SMSConfig
Telemetry  TelemetryConfig
Monitoring MonitoringConfig
}

// AppConfig содержит общие настройки приложения
type AppConfig struct {
Name        string
Environment string
LogLevel    string
Debug       bool
}

// HTTPConfig содержит настройки HTTP сервера
type HTTPConfig struct {
Host           string
Port           int
ReadTimeout    time.Duration
WriteTimeout   time.Duration
MaxHeaderBytes int
CORS           CORSConfig
}

// CORSConfig содержит настройки CORS
type CORSConfig struct {
AllowOrigins     []string
AllowMethods     []string
AllowHeaders     []string
ExposeHeaders    []string
AllowCredentials bool
MaxAge           time.Duration
}

// GRPCConfig содержит настройки gRPC сервера
type GRPCConfig struct {
Host string
Port int
}

// DatabaseConfig содержит настройки базы данных
type DatabaseConfig struct {
Host            string
Port            int
Username        string
Password        string
Database        string
SSLMode         string
MaxOpenConns    int
MaxIdleConns    int
ConnMaxLifetime time.Duration
MigrationsPath  string
}

// RedisConfig содержит настройки Redis
type RedisConfig struct {
Host     string
Port     int
Password string
DB       int
}

// KafkaConfig содержит настройки Kafka
type KafkaConfig struct {
Brokers         []string
ConsumerGroupID string
Topics          KafkaTopics
}

// KafkaTopics содержит названия топиков Kafka
type KafkaTopics struct {
AccountCreated    string
AccountUpdated    string
AccountDeleted    string
ProfileUpdated    string
ContactInfoAdded  string
ContactInfoVerified string
}

// AuthConfig содержит настройки аутентификации
type AuthConfig struct {
JWTSecret        string
AccessTokenTTL   time.Duration
RefreshTokenTTL  time.Duration
AuthServiceURL   string
AuthServiceGRPC  string
}

// S3Config содержит настройки S3-совместимого хранилища
type S3Config struct {
Endpoint        string
Region          string
AccessKeyID     string
SecretAccessKey string
Bucket          string
UseSSL          bool
}

// SMSConfig содержит настройки SMS-провайдера
type SMSConfig struct {
Provider  string
APIKey    string
APISecret string
Sender    string
}

// TelemetryConfig содержит настройки телеметрии
type TelemetryConfig struct {
Enabled      bool
JaegerURL    string
ServiceName  string
SamplingRate float64
}

// MonitoringConfig содержит настройки мониторинга
type MonitoringConfig struct {
Enabled     bool
MetricsPort int
}

// LoadConfig загружает конфигурацию из файла и переменных окружения
func LoadConfig(path string) (*Config, error) {
v := viper.New()

// Настройки по умолчанию
setDefaults(v)

// Чтение из файла конфигурации
if path != "" {
v.SetConfigFile(path)
if err := v.ReadInConfig(); err != nil {
return nil, fmt.Errorf("error reading config file: %w", err)
}
}

// Чтение из переменных окружения
v.AutomaticEnv()
v.SetEnvPrefix("APP")

// Преобразование в структуру
var config Config
if err := v.Unmarshal(&config); err != nil {
return nil, fmt.Errorf("error unmarshaling config: %w", err)
}

return &config, nil
}

// setDefaults устанавливает значения по умолчанию
func setDefaults(v *viper.Viper) {
// App
v.SetDefault("App.Name", "account-service")
v.SetDefault("App.Environment", "development")
v.SetDefault("App.LogLevel", "info")
v.SetDefault("App.Debug", false)

// HTTP
v.SetDefault("HTTP.Host", "0.0.0.0")
v.SetDefault("HTTP.Port", 8080)
v.SetDefault("HTTP.ReadTimeout", 10*time.Second)
v.SetDefault("HTTP.WriteTimeout", 10*time.Second)
v.SetDefault("HTTP.MaxHeaderBytes", 1<<20) // 1 MB

// CORS
v.SetDefault("HTTP.CORS.AllowOrigins", []string{"*"})
v.SetDefault("HTTP.CORS.AllowMethods", []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
v.SetDefault("HTTP.CORS.AllowHeaders", []string{"Origin", "Content-Type", "Accept", "Authorization"})
v.SetDefault("HTTP.CORS.ExposeHeaders", []string{"Content-Length"})
v.SetDefault("HTTP.CORS.AllowCredentials", true)
v.SetDefault("HTTP.CORS.MaxAge", 12*time.Hour)

// gRPC
v.SetDefault("GRPC.Host", "0.0.0.0")
v.SetDefault("GRPC.Port", 9090)

// Database
v.SetDefault("Database.Host", "localhost")
v.SetDefault("Database.Port", 5432)
v.SetDefault("Database.Username", "postgres")
v.SetDefault("Database.Password", "postgres")
v.SetDefault("Database.Database", "account_service")
v.SetDefault("Database.SSLMode", "disable")
v.SetDefault("Database.MaxOpenConns", 25)
v.SetDefault("Database.MaxIdleConns", 5)
v.SetDefault("Database.ConnMaxLifetime", 5*time.Minute)
v.SetDefault("Database.MigrationsPath", "migrations")

// Redis
v.SetDefault("Redis.Host", "localhost")
v.SetDefault("Redis.Port", 6379)
v.SetDefault("Redis.Password", "")
v.SetDefault("Redis.DB", 0)

// Kafka
v.SetDefault("Kafka.Brokers", []string{"localhost:9092"})
v.SetDefault("Kafka.ConsumerGroupID", "account-service")
v.SetDefault("Kafka.Topics.AccountCreated", "account.created")
v.SetDefault("Kafka.Topics.AccountUpdated", "account.updated")
v.SetDefault("Kafka.Topics.AccountDeleted", "account.deleted")
v.SetDefault("Kafka.Topics.ProfileUpdated", "profile.updated")
v.SetDefault("Kafka.Topics.ContactInfoAdded", "contact.added")
v.SetDefault("Kafka.Topics.ContactInfoVerified", "contact.verified")

// Auth
v.SetDefault("Auth.JWTSecret", "supersecret")
v.SetDefault("Auth.AccessTokenTTL", 15*time.Minute)
v.SetDefault("Auth.RefreshTokenTTL", 7*24*time.Hour)
v.SetDefault("Auth.AuthServiceURL", "http://auth-service:8080")
v.SetDefault("Auth.AuthServiceGRPC", "auth-service:9090")

// S3
v.SetDefault("S3.Endpoint", "localhost:9000")
v.SetDefault("S3.Region", "us-east-1")
v.SetDefault("S3.AccessKeyID", "minioadmin")
v.SetDefault("S3.SecretAccessKey", "minioadmin")
v.SetDefault("S3.Bucket", "accounts")
v.SetDefault("S3.UseSSL", false)

// SMS
v.SetDefault("SMS.Provider", "mock")
v.SetDefault("SMS.APIKey", "")
v.SetDefault("SMS.APISecret", "")
v.SetDefault("SMS.Sender", "SteamClone")

// Telemetry
v.SetDefault("Telemetry.Enabled", false)
v.SetDefault("Telemetry.JaegerURL", "http://jaeger:14268/api/traces")
v.SetDefault("Telemetry.ServiceName", "account-service")
v.SetDefault("Telemetry.SamplingRate", 0.1)

// Monitoring
v.SetDefault("Monitoring.Enabled", true)
v.SetDefault("Monitoring.MetricsPort", 9100)
}
