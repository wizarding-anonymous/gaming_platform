// File: backend/services/account-service/cmd/account-service/main_test.go
package main

import (
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/account-service/config"
	"testing"
)

func TestStartHTTPServer(t *testing.T) {
	router := gin.New()
	cfg := &config.Config{}
	cfg.HTTPPort = 8080

	srv := startHTTPServer(cfg, router)
	assert.Equal(t, ":8080", srv.Addr)
	assert.Equal(t, router, srv.Handler)
}
