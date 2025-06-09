// File: internal/handler/grpc/auth_v1_server_interface_workaround.go
package grpc // Assuming this file is in the same package as your gRPC service implementation.

import (
	"context"

	// Adjust the import path to where your generated `authv1` package is.
	// This should match the go_package option used in your .proto file.
	// Example: "github.com/your-org/your-project/gen/go/auth/v1"
	authv1 "github.com/your-org/auth-service/gen/go/auth/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// AuthServiceServer_Workaround is the server API for AuthService service.
// All implementations must embed UnimplementedAuthServiceServer_Workaround
// for forward compatibility (simulating protoc generation).
// THIS IS A WORKAROUND due to protoc generation issues.
type AuthServiceServer_Workaround interface {
	ValidateToken(context.Context, *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error)
	CheckPermission(context.Context, *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error)
	GetUserInfo(context.Context, *authv1.GetUserInfoRequest) (*authv1.UserInfoResponse, error)
	GetJWKS(context.Context, *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error)
	HealthCheck(context.Context, *emptypb.Empty) (*authv1.HealthCheckResponse, error)
	mustEmbedUnimplementedAuthServiceServer_Workaround() // To mimic protoc behavior
}

// UnimplementedAuthServiceServer_Workaround must be embedded to have forward compatible implementations.
type UnimplementedAuthServiceServer_Workaround struct {}

func (UnimplementedAuthServiceServer_Workaround) ValidateToken(context.Context, *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateToken not implemented")
}
func (UnimplementedAuthServiceServer_Workaround) CheckPermission(context.Context, *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckPermission not implemented")
}
func (UnimplementedAuthServiceServer_Workaround) GetUserInfo(context.Context, *authv1.GetUserInfoRequest) (*authv1.UserInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetUserInfo not implemented")
}
func (UnimplementedAuthServiceServer_Workaround) GetJWKS(context.Context, *authv1.GetJWKSRequest) (*authv1.GetJWKSResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetJWKS not implemented")
}
func (UnimplementedAuthServiceServer_Workaround) HealthCheck(context.Context, *emptypb.Empty) (*authv1.HealthCheckResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HealthCheck not implemented")
}
func (UnimplementedAuthServiceServer_Workaround) mustEmbedUnimplementedAuthServiceServer_Workaround() {}
