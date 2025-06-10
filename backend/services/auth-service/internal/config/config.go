// File: backend/services/auth-service/internal/config/config.go
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	Server         ServerConfig                   `mapstructure:"server"`
	Database       DatabaseConfig                 `mapstructure:"database"`
	Redis          RedisConfig                    `mapstructure:"redis"`
	Kafka          KafkaConfig                    `mapstructure:"kafka"`
	JWT            JWTConfig                      `mapstructure:"jwt"`
	Security       SecurityConfig                 `mapstructure:"security"`
	MFA            MFAConfig                      `mapstructure:"mfa"`
	Logging        LoggingConfig                  `mapstructure:"logging"`
	Telemetry      TelemetryConfig                `mapstructure:"telemetry"`
	OAuthProviders map[string]OAuthProviderConfig `mapstructure:"oauth_providers"`
	Telegram       TelegramConfig                 `mapstructure:"telegram"`
	HIBP           HIBPConfig                     `mapstructure:"hibp"`
	Captcha        CaptchaConfig                  `mapstructure:"captcha"`
}

type HIBPConfig struct {
	Enabled   bool   `mapstructure:"enabled" env-default:"false"`
	UserAgent string `mapstructure:"user_agent" env-default:"AuthServiceHIBPChecker/1.0"`
}

type CaptchaConfig struct {
	Enabled   bool   `mapstructure:"enabled" env-default:"false"`
	Provider  string `mapstructure:"provider" env-default:""` // e.g., "recaptcha_v2", "hcaptcha", "yandex_smartcaptcha"
	SecretKey string `mapstructure:"secret_key" env-default:""`
	// SiteKey string `mapstructure:"site_key"` // SiteKey is usually for client-side, might not be needed in backend config
	// VerifyURL string `mapstructure:"verify_url"` // Could be part of provider-specific logic
}

type ServerConfig struct {
	Port            int           `mapstructure:"port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
}

type DatabaseConfig struct {
	Host        string `mapstructure:"host"`
	Port        int    `mapstructure:"port"`
	User        string `mapstructure:"user"`
	Password    string `mapstructure:"password"`
	DBName      string `mapstructure:"dbname"`
	SSLMode     string `mapstructure:"sslmode"`
	AutoMigrate bool   `mapstructure:"auto_migrate"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

type KafkaProducerConfig struct {
	Topic         string `mapstructure:"topic"`
	RoleTopic     string `mapstructure:"role_topic"`
	UserRoleTopic string `mapstructure:"user_role_topic"`
}

type KafkaConsumerConfig struct {
	Topics  []string `mapstructure:"topics"`
	GroupID string   `mapstructure:"group_id"`
}

type KafkaConfig struct {
	Brokers  []string            `mapstructure:"brokers"`
	Producer KafkaProducerConfig `mapstructure:"producer"`
	Consumer KafkaConsumerConfig `mapstructure:"consumer"`
}

type TokenConfig struct {
	ExpiresIn time.Duration `mapstructure:"expires_in"`
}

type JWTConfig struct {
	AccessTokenTTL         time.Duration `mapstructure:"access_token_ttl"`
	RefreshTokenTTL        time.Duration `mapstructure:"refresh_token_ttl"`
	EmailVerificationToken TokenConfig   `mapstructure:"email_verification_token"`
	PasswordResetToken     TokenConfig   `mapstructure:"password_reset_token"`
	RSAPrivateKeyPEM       string        `mapstructure:"rsa_private_key_pem"`
	RSAPublicKeyPEM        string        `mapstructure:"rsa_public_key_pem"`
	JWKSKeyID              string        `mapstructure:"jwks_key_id"`
	Issuer                 string        `mapstructure:"issuer"`
	Audience               string        `mapstructure:"audience"`
	RefreshTokenByteLength uint32        `mapstructure:"refresh_token_byte_length"`
	OAuthStateCookieTTL    time.Duration `mapstructure:"oauth_state_cookie_ttl"`
	OAuthStateSecret       string        `mapstructure:"oauth_state_secret"`
	MFAChallengeTokenTTL   time.Duration `mapstructure:"mfa_challenge_token_ttl"`
}

type LockoutConfig struct {
	MaxFailedAttempts int           `mapstructure:"max_failed_attempts"`
	LockoutDuration   time.Duration `mapstructure:"lockout_duration"`
}

type PasswordHashConfig struct {
	Memory      uint32 `mapstructure:"memory"`
	Iterations  uint32 `mapstructure:"iterations"`
	Parallelism uint8  `mapstructure:"parallelism"`
	SaltLength  uint32 `mapstructure:"salt_length"`
	KeyLength   uint32 `mapstructure:"key_length"`
}

// RateLimitRule defines the configuration for a specific rate limit.
type RateLimitRule struct {
	Enabled bool          `mapstructure:"enabled"`
	Limit   int           `mapstructure:"limit"`
	Window  time.Duration `mapstructure:"window"`
}

// RateLimitConfig holds all rate limiting configurations.
type RateLimitConfig struct {
	Enabled                  bool          `mapstructure:"enabled"`
	PasswordResetPerEmail    RateLimitRule `mapstructure:"password_reset_per_email"`
	PasswordResetPerIP       RateLimitRule `mapstructure:"password_reset_per_ip"`
	TwoFAVerificationPerUser RateLimitRule `mapstructure:"two_fa_verification_per_user"`
	RegisterIP               RateLimitRule `mapstructure:"register_ip"`               // Added for registration by IP
	LoginEmailIP             RateLimitRule `mapstructure:"login_email_ip"`            // Added for login by email and IP
	ResendVerificationEmail  RateLimitRule `mapstructure:"resend_verification_email"` // Added for resend verification email
	ResetPasswordIP          RateLimitRule `mapstructure:"reset_password_ip"`         // Added for reset password by IP
	GeneralAuth              RateLimitRule `mapstructure:"general_auth"`              // For general public auth endpoints
}

type SecurityConfig struct {
	Lockout      LockoutConfig      `mapstructure:"lockout"`
	PasswordHash PasswordHashConfig `mapstructure:"password_hash"`
	RateLimiting RateLimitConfig    `mapstructure:"rate_limiting"` // Added
}

type MFAConfig struct {
	Enabled             bool   `mapstructure:"enabled"`
	TOTPIssuerName      string `mapstructure:"totp_issuer_name"`
	TOTPEncryptionKey   string `mapstructure:"totp_encryption_key"` // Hex-encoded 32-byte key
	TOTPBackupCodeCount int    `mapstructure:"totp_backup_code_count"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type JaegerConfig struct {
	AgentHost string `mapstructure:"agent_host"`
	AgentPort string `mapstructure:"agent_port"`
}
type TracingConfig struct {
	Enabled bool         `mapstructure:"enabled"`
	Jaeger  JaegerConfig `mapstructure:"jaeger"`
}
type MetricsConfig struct {
	Enabled bool `mapstructure:"enabled"`
	Port    int  `mapstructure:"port"`
}
type TelemetryConfig struct {
	ServiceName string        `mapstructure:"service_name"`
	Tracing     TracingConfig `mapstructure:"tracing"`
	Metrics     MetricsConfig `mapstructure:"metrics"`
}

type OAuthProviderConfig struct {
	ClientID         string            `mapstructure:"client_id"`
	ClientSecret     string            `mapstructure:"client_secret"`
	RedirectURL      string            `mapstructure:"redirect_url"`
	AuthURL          string            `mapstructure:"auth_url"`
	TokenURL         string            `mapstructure:"token_url"`
	UserInfoURL      string            `mapstructure:"user_info_url"`
	Scopes           []string          `mapstructure:"scopes"`
	ProviderSpecific map[string]string `mapstructure:"provider_specific"`
}

type TelegramConfig struct {
	BotToken string `mapstructure:"bot_token"`
}
