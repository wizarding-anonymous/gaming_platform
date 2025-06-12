// File: backend/services/auth-service/internal/utils/shutdown/shutdown.go
package shutdown

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// Wait блокирует выполнение до получения сигнала завершения
// и выполняет graceful shutdown HTTP и gRPC серверов.
func Wait(httpSrv *http.Server, grpcSrv *grpc.Server, timeout time.Duration, logger *zap.Logger) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down servers...")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("HTTP server forced to shutdown", zap.Error(err))
	}

	grpcSrv.GracefulStop()
	logger.Info("Servers exited properly")
}
