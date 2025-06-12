// File: backend/services/auth-service/internal/config/loader.go
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// LoadConfig загружает конфигурацию из файла и переменных окружения
func LoadConfig() (*Config, error) {
	// Установка значений по умолчанию
	setDefaults()

	env := strings.ToLower(os.Getenv("APP_ENV"))
	if env == "" {
		env = "development"
	}

	if path := os.Getenv("CONFIG_PATH"); path != "" {
		viper.SetConfigFile(path)
	} else {
		viper.SetConfigName(fmt.Sprintf("config.%s", env))
		viper.SetConfigType("yaml")
		viper.AddConfigPath("./configs")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/auth-service")
	}

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
	// Только базовые значения по умолчанию
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "json")
}
