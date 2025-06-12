// File: backend/services/auth-service/cmd/auth-service/servers.go
package main

import (
	"fmt"
	"net"
	"net/http"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func startHTTPServer(cfg *config.Config, handler http.Handler, logger *zap.Logger) *http.Server {
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	go func() {
		logger.Info("Starting HTTP server", zap.Int("port", cfg.Server.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start HTTP server", zap.Error(err))
		}
	}()

	return srv
}

func startGRPCServer(cfg *config.Config, grpcServer *grpc.Server, logger *zap.Logger) {
	go func() {
		lis, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPC.Port))
		if err != nil {
			logger.Fatal("Failed to listen for gRPC", zap.Error(err))
		}
		logger.Info("Starting gRPC server", zap.Int("port", cfg.GRPC.Port))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatal("Failed to start gRPC server", zap.Error(err))
		}
	}()
}
