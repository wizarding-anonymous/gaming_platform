package config

import (
	"time"
)

// Config представляет собой структуру конфигурации приложения
type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Kafka     KafkaConfig     `mapstructure:"kafka"`
	JWT       JWTConfig       `mapstructure:"jwt"`
	Telegram  TelegramConfig  `mapstructure:"telegram"`
	Logging   LoggingConfig   `mapstructure:"logging"`
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
	GRPC      GRPCConfig      `mapstructure:"grpc"`
	CORS      CORSConfig      `mapstructure:"cors"`
	Security  SecurityConfig  `mapstructure:"security"`
	MFA       MFAConfig       `mapstructure:"mfa"`
}

// MFAConfig holds configuration for Multi-Factor Authentication.
type MFAConfig struct {
	TOTPIssuerName          string `mapstructure:"totp_issuer_name"`
	TOTPSecretEncryptionKey string `mapstructure:"totp_secret_encryption_key"` // Hex or Base64 encoded 32-byte key for AES-256
	TOTPBackupCodeCount     int    `mapstructure:"totp_backup_code_count"`
}

// Argon2idConfig holds parameters for Argon2id password hashing.
type Argon2idConfig struct {
	Memory      uint32 `mapstructure:"memory"`
	Iterations  uint32 `mapstructure:"iterations"`
	Parallelism uint8  `mapstructure:"parallelism"`
	SaltLength  uint32 `mapstructure:"salt_length"`
	KeyLength   uint32 `mapstructure:"key_length"`
	// Algorithm string `mapstructure:"algorithm"` // Already specified as Argon2id
}

// SecurityConfig holds security-related configurations.
type SecurityConfig struct {
	PasswordHash Argon2idConfig `mapstructure:"password_hash"`
	Lockout      LockoutConfig  `mapstructure:"lockout"`
	// Add other security settings here, e.g., rate_limit, ip_whitelist from YAML
}

// LockoutConfig holds parameters for account lockout policy.
type LockoutConfig struct {
	MaxFailedAttempts int           `mapstructure:"max_failed_attempts"`
	LockoutDuration   time.Duration `mapstructure:"lockout_duration"`
}

// ServerConfig содержит настройки HTTP сервера
type ServerConfig struct {
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

// DatabaseConfig содержит настройки подключения к базе данных PostgreSQL
type DatabaseConfig struct {
	Host          string        `mapstructure:"host"`
	Port          int           `mapstructure:"port"`
	User          string        `mapstructure:"user"`
	Password      string        `mapstructure:"password"`
	DBName        string        `mapstructure:"dbname"`
	SSLMode       string        `mapstructure:"sslmode"`
	MaxOpenConns  int           `mapstructure:"max_open_conns"`
	MaxIdleConns  int           `mapstructure:"max_idle_conns"`
	ConnMaxLife   time.Duration `mapstructure:"conn_max_lifetime"`
	AutoMigrate   bool          `mapstructure:"auto_migrate"`
	MigrationsDir string        `mapstructure:"migrations_dir"`
}

// RedisConfig содержит настройки подключения к Redis
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// KafkaConfig содержит настройки для работы с Kafka
type KafkaConfig struct {
	Brokers  []string       `mapstructure:"brokers"`
	Producer ProducerConfig `mapstructure:"producer"`
	Consumer ConsumerConfig `mapstructure:"consumer"`
}

// ProducerConfig содержит настройки для Kafka Producer
type ProducerConfig struct {
	Topic string `mapstructure:"topic"`
}

// ConsumerConfig содержит настройки для Kafka Consumer
type ConsumerConfig struct {
	Topics  []string `mapstructure:"topics"`
	GroupID string   `mapstructure:"group_id"`
}

// JWTConfig содержит настройки для работы с JWT токенами
type JWTConfig struct {
	// For HMAC (existing, might be phased out or used for specific internal tokens)
	AccessToken            TokenConfig `mapstructure:"access_token"`            // Keep for now
	RefreshToken           TokenConfig `mapstructure:"refresh_token"`           // Keep for now
	EmailVerificationToken TokenConfig `mapstructure:"email_verification_token"` // Keep for now
	PasswordResetToken     TokenConfig `mapstructure:"password_reset_token"`     // Keep for now

	// For RS256 (new)
	RSAPrivateKeyPEMFile string        `mapstructure:"rsa_private_key_pem_file"`
	RSAPublicKeyPEMFile  string        `mapstructure:"rsa_public_key_pem_file"`
	JWKSKeyID            string        `mapstructure:"jwks_key_id"`
	AccessTokenTTL       time.Duration `mapstructure:"access_token_ttl"`  // e.g., "15m"
	RefreshTokenTTL      time.Duration `mapstructure:"refresh_token_ttl"` // e.g., "720h"
	Issuer               string        `mapstructure:"issuer"`
	Audience             string        `mapstructure:"audience"`
}

// TokenConfig содержит настройки для конкретного типа токена (primarily for HMAC secrets)
type TokenConfig struct {
	Secret    string        `mapstructure:"secret"`
	ExpiresIn time.Duration `mapstructure:"expires_in"`
}

// TelegramConfig содержит настройки для интеграции с Telegram
type TelegramConfig struct {
	BotToken string `mapstructure:"bot_token"`
}

// LoggingConfig содержит настройки логирования
type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// TelemetryConfig содержит настройки телеметрии (метрики, трассировка)
type TelemetryConfig struct {
	Metrics MetricsConfig `mapstructure:"metrics"`
	Tracing TracingConfig `mapstructure:"tracing"`
}

// MetricsConfig содержит настройки для метрик Prometheus
type MetricsConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Port    int  `mapstructure:"port"`
}

// TracingConfig содержит настройки для трассировки
type TracingConfig struct {
	Enabled bool         `mapstructure:"enabled"`
	Jaeger  JaegerConfig `mapstructure:"jaeger"`
}

// JaegerConfig содержит настройки для Jaeger
type JaegerConfig struct {
	AgentHost string `mapstructure:"agent_host"`
	AgentPort int    `mapstructure:"agent_port"`
}

// GRPCConfig содержит настройки для gRPC сервера
type GRPCConfig struct {
	Port             int  `mapstructure:"port"`
	EnableReflection bool `mapstructure:"enable_reflection"`
}

// CORSConfig содержит настройки для CORS
type CORSConfig struct {
	AllowOrigins     []string `mapstructure:"allow_origins"`
	AllowMethods     []string `mapstructure:"allow_methods"`
	AllowHeaders     []string `mapstructure:"allow_headers"`
	ExposeHeaders    []string `mapstructure:"expose_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
	MaxAge           int      `mapstructure:"max_age"`
}
