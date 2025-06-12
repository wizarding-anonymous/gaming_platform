// File: backend/services/auth-service/cmd/auth-service/config.go
package main

import "github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"

func loadConfig() (*config.Config, error) {
	return config.LoadConfig()
}
