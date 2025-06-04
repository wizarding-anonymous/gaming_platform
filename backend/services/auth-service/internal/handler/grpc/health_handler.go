package grpc

import (
	"context"

	"google.golang.org/grpc/health/grpc_health_v1"
	"go.uber.org/zap"
)

// HealthServer implements the gRPC health checking protocol.
type HealthServer struct {
	logger *zap.Logger
	grpc_health_v1.UnimplementedHealthServer
}

// NewHealthServer returns a new HealthServer.
func NewHealthServer(logger *zap.Logger) *HealthServer {
	return &HealthServer{
		logger: logger.Named("grpc_health_handler"),
	}
}

// Check implements the Check method of the Health service.
// It currently returns a SERVING status for all services.
// For more advanced health checking, this method can be customized
// to check the status of various dependencies (e.g., database, cache).
func (s *HealthServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	s.logger.Debug("gRPC Health Check requested", zap.String("service", req.GetService()))
	// For now, we always return SERVING. In a real-world scenario,
	// you might want to check the status of dependencies.
	// If req.Service is empty, it's a server-wide health check.
	// Otherwise, it's for a specific service.
	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}

// Watch implements the Watch method of the Health service.
// This example implementation does not support streaming health updates.
// It can be extended to send updates whenever the serving status changes.
func (s *HealthServer) Watch(req *grpc_health_v1.HealthCheckRequest, stream grpc_health_v1.Health_WatchServer) error {
	s.logger.Debug("gRPC Health Watch requested", zap.String("service", req.GetService()))
	// Send an initial SERVING status.
	err := stream.Send(&grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	})
	if err != nil {
		s.logger.Error("Failed to send initial health status on Watch", zap.Error(err))
		return err
	}
	// This simple implementation doesn't send further updates.
	// A more sophisticated version would monitor health and send updates.
	// For now, we just keep the stream open until the client cancels.
	<-stream.Context().Done()
	s.logger.Info("gRPC Health Watch stream ended", zap.String("service", req.GetService()))
	return stream.Context().Err()
}

// RegisterHealthServer registers the health server with the given gRPC server.
func (s *HealthServer) RegisterHealthServer(grpcServer *grpc.Server) {
	grpc_health_v1.RegisterHealthServer(grpcServer, s)
	s.logger.Info("gRPC Health Check service registered")
}
