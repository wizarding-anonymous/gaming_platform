<!-- File: backend/services/auth-service/specification_final/auth_api_grpc.md -->
# Auth Service: gRPC API Specification

**Version:** 1.0
**Date:** 2023-10-27

## 1. Introduction

This document provides the detailed specification for the gRPC API exposed by the Auth Service. This API is primarily intended for internal, high-performance, server-to-server communication between other microservices on the platform and the Auth Service.

## 2. General Principles

*   **Protocol**: gRPC over HTTP/2.
*   **Serialization**: Protocol Buffers (proto3 syntax).
*   **Authentication & Authorization**:
    *   Inter-service calls should be secured using mTLS (mutual TLS) where the Auth Service verifies the client certificate of the calling service.
    *   Additionally, the calling service can pass metadata (e.g., a service account token or the original user's JWT if acting on behalf of a user) which the Auth Service can use for fine-grained authorization.
*   **Error Handling**: Standard gRPC status codes are used. More specific error details can be conveyed via `google.rpc.Status` and `google.rpc.ErrorInfo` in the response metadata or as part of the response message if appropriate.
*   **API Definition File**: `auth.v1.proto` (defined below).

## 3. Protobuf Definition (`auth.v1.proto`)

```protobuf
syntax = "proto3";

package auth.v1;

import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";

option go_package = "github.com/gameplatform/protos/gen/go/auth/v1;authv1"; // Example Go package path

// AuthService defines the gRPC interface for authentication and authorization.
service AuthService {
  // ValidateToken checks the validity of a JWT access token and returns its claims.
  // Used by API Gateway and other services to authorize user requests.
  rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse);

  // CheckPermission verifies if a user (identified by user_id or by token)
  // has a specific permission, optionally for a given resource.
  rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse);

  // GetUserInfo retrieves basic user information for an authenticated entity (user or service).
  // This is typically used by other services needing user details after token validation.
  rpc GetUserInfo(GetUserInfoRequest) returns (UserInfoResponse);

  // GetJWKS returns the JSON Web Key Set (JWKS) containing public keys
  // used to verify JWTs issued by this Auth Service.
  // This allows other services to validate tokens locally if needed.
  rpc GetJWKS(GetJWKSRequest) returns (GetJWKSResponse);

  // HealthCheck provides a standard gRPC health check.
  rpc HealthCheck(google.protobuf.Empty) returns (HealthCheckResponse);
}

// --- Message Definitions ---

message ValidateTokenRequest {
  string token = 1; // The JWT access token string.
}

message ValidateTokenResponse {
  bool valid = 1;                      // True if the token is valid, false otherwise.
  string user_id = 2;                  // User ID from the token claims.
  string username = 3;                 // Username from the token claims.
  repeated string roles = 4;           // List of roles associated with the user.
  repeated string permissions = 5;     // List of permissions associated with the user/roles.
  google.protobuf.Timestamp expires_at = 6; // Token expiration timestamp.
  string session_id = 7;               // Session ID associated with the token.
  string error_code = 8;               // Specific error code if token is invalid (e.g., "token_expired", "token_invalid_signature").
  string error_message = 9;            // Human-readable error message if token is invalid.
}

message CheckPermissionRequest {
  // Option 1: Provide user_id directly if known (e.g., for service-to-service checks on behalf of a user)
  string user_id = 1;

  // Option 2: Provide token, from which user_id and roles/permissions will be extracted.
  // If token is provided, user_id might be ignored or used as a cross-check.
  // string token = 2; // This was considered, but user_id is generally preferred for internal checks after initial validation.
  // The calling service is expected to have validated the token and extracted user_id first.

  string permission = 3;        // The permission string to check (e.g., "games.publish", "users.edit").
  string resource_id = 4;       // Optional: The ID of the resource being accessed (e.g., game_id, user_id).
                                // Used for fine-grained, resource-specific permission checks.
}

message CheckPermissionResponse {
  bool has_permission = 1;     // True if the user has the permission, false otherwise.
}

message GetUserInfoRequest {
  // User ID for whom information is requested.
  string user_id = 1;
  // Alternatively, a token could be passed, but similar to CheckPermission,
  // it's often better for the calling service to validate the token first.
}

message UserInfo {
  string id = 1;
  string username = 2;
  string email = 3;                 // Email address (may be empty depending on privacy/permissions).
  string status = 4;                // User account status (e.g., "active", "blocked", "pending_verification").
  google.protobuf.Timestamp created_at = 5;
  google.protobuf.Timestamp email_verified_at = 6; // Null if email is not verified.
  google.protobuf.Timestamp last_login_at = 7;     // Null if never logged in.
  repeated string roles = 8;           // List of roles.
  bool mfa_enabled = 9;             // True if Multi-Factor Authentication is enabled.
}

message UserInfoResponse {
  UserInfo user = 1;
}

message GetJWKSRequest {
  // No parameters needed for JWKS request.
}

message GetJWKSResponse {
  message JSONWebKey {
    string kty = 1; // Key Type (e.g., "RSA")
    string kid = 2; // Key ID
    string use = 3; // Public Key Use (e.g., "sig" for signature)
    string alg = 4; // Algorithm (e.g., "RS256")
    string n = 5;   // Modulus (for RSA keys, Base64URL encoded)
    string e = 6;   // Exponent (for RSA keys, Base64URL encoded)
    // Fields for EC keys (crv, x, y) can be added if other algorithms are supported.
  }
  repeated JSONWebKey keys = 1; // List of public keys.
}

message HealthCheckResponse {
  enum ServingStatus {
    UNKNOWN = 0;
    SERVING = 1;
    NOT_SERVING = 2;
    // SERVICE_UNKNOWN = 3; // If checking specific sub-services within Auth.
  }
  ServingStatus status = 1;
}

```

## 4. RPC Method Details

#### 4.1 `rpc ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse)`
*   **Description**: Validates a provided JWT access token. It checks the signature, expiration, issuer, audience, and any other relevant claims. If the token is valid, it returns key information extracted from the token. This is the primary method used by the API Gateway and other microservices to verify user authentication for incoming requests.
*   **Request (`ValidateTokenRequest`)**:
    *   `token` (string): The JWT access token to be validated.
*   **Response (`ValidateTokenResponse`)**:
    *   `valid` (bool): `true` if the token is valid and not expired, `false` otherwise.
    *   `user_id` (string): The unique identifier of the user if the token is valid.
    *   `username` (string): The username of the user.
    *   `roles` (repeated string): A list of roles assigned to the user.
    *   `permissions` (repeated string): A list of permissions derived from the user's roles (or directly assigned if applicable).
    *   `expires_at` (google.protobuf.Timestamp): The expiration timestamp of the token.
    *   `session_id` (string): The session identifier associated with this token.
    *   `error_code` (string): If `valid` is `false`, this field contains a machine-readable error code (e.g., `TOKEN_EXPIRED`, `TOKEN_INVALID_SIGNATURE`, `TOKEN_MALFORMED`, `TOKEN_REVOKED`).
    *   `error_message` (string): A human-readable message explaining why the token is not valid.
*   **gRPC Status Codes**:
    *   `OK` (0): Request processed. Check the `valid` field and `error_code`/`error_message` in the response for the outcome.
    *   `INVALID_ARGUMENT` (3): If the `token` field in the request is empty or malformed in a way that prevents parsing.
    *   `INTERNAL` (13): If an unexpected internal error occurs during validation (e.g., error accessing key storage, database issue when checking for revocation).
    *   `UNAUTHENTICATED` (16): Can be used if the service configuration for token validation is missing or invalid (e.g., JWKS keys not loaded). Typically, `OK` with `valid: false` is preferred for token-specific issues.

#### 4.2 `rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse)`
*   **Description**: Verifies if a specific user (identified by `user_id`) possesses a given permission, optionally in the context of a specific resource. This method is used by other services to perform fine-grained authorization checks.
*   **Request (`CheckPermissionRequest`)**:
    *   `user_id` (string): The ID of the user whose permissions are being checked. This user ID is typically obtained from a previously validated access token.
    *   `permission` (string): The permission string to check (e.g., "catalog.games.edit", "admin.users.list"). The format should follow a "resource.action" or "resource.subresource.action" pattern.
    *   `resource_id` (string, optional): The unique identifier of the resource to which the permission check applies (e.g., a specific game ID if checking "catalog.games.edit"). If the permission is global (not tied to a specific resource), this can be empty.
*   **Response (`CheckPermissionResponse`)**:
    *   `has_permission` (bool): `true` if the user has the specified permission (and for the given resource, if applicable), `false` otherwise.
*   **gRPC Status Codes**:
    *   `OK` (0): Request processed. The `has_permission` field indicates the result.
    *   `INVALID_ARGUMENT` (3): If `user_id` or `permission` is missing or in an invalid format.
    *   `NOT_FOUND` (5): If the specified `user_id` does not exist, or if the `permission` string itself is not a recognized permission in the system.
    *   `INTERNAL` (13): If an internal error occurs (e.g., database error while fetching user roles or permission definitions).

#### 4.3 `rpc GetUserInfo(GetUserInfoRequest) returns (UserInfoResponse)`
*   **Description**: Retrieves detailed information about a user by their ID. This is intended for use by other trusted microservices that need user details beyond what's in the JWT claims.
*   **Request (`GetUserInfoRequest`)**:
    *   `user_id` (string): The unique ID of the user.
*   **Response (`UserInfoResponse`)**:
    *   `user` (UserInfo): A `UserInfo` message containing details about the user.
        *   `id` (string): User's unique ID.
        *   `username` (string): User's username.
        *   `email` (string): User's email address.
        *   `status` (string): Account status (e.g., "active", "blocked").
        *   `created_at` (google.protobuf.Timestamp): Timestamp of account creation.
        *   `email_verified_at` (google.protobuf.Timestamp): Timestamp of email verification (null if not verified).
        *   `last_login_at` (google.protobuf.Timestamp): Timestamp of last login (null if never logged in).
        *   `roles` (repeated string): List of assigned roles.
        *   `mfa_enabled` (bool): Indicates if MFA is enabled for the user.
*   **gRPC Status Codes**:
    *   `OK` (0): User information successfully retrieved.
    *   `INVALID_ARGUMENT` (3): If `user_id` is missing or invalid.
    *   `NOT_FOUND` (5): If no user exists with the given `user_id`.
    *   `INTERNAL` (13): If an internal error occurs (e.g., database error).

#### 4.4 `rpc GetJWKS(GetJWKSRequest) returns (GetJWKSResponse)`
*   **Description**: Returns the JSON Web Key Set (JWKS) containing the public keys used by the Auth Service to sign JWTs. This allows other services or external parties to fetch these keys and validate JWT signatures locally, reducing the load on `ValidateToken` endpoint for every request.
*   **Request (`GetJWKSRequest`)**: Empty.
*   **Response (`GetJWKSResponse`)**:
    *   `keys` (repeated JSONWebKey): A list of public keys in JWK format.
        *   `kty` (string): Key Type (e.g., "RSA").
        *   `kid` (string): Key ID. This ID should be present in the JWT header (`kid` claim) to identify which key was used for signing.
        *   `use` (string): Public Key Use (e.g., "sig" for signature).
        *   `alg` (string): Algorithm (e.g., "RS256").
        *   `n` (string): Modulus for RSA key (Base64URL encoded).
        *   `e` (string): Exponent for RSA key (Base64URL encoded).
*   **gRPC Status Codes**:
    *   `OK` (0): JWKS successfully returned.
    *   `INTERNAL` (13): If an error occurs while fetching or formatting the keys (e.g., error reading key files, configuration issue).
    *   `UNAVAILABLE` (14): If the key store is temporarily unavailable.

#### 4.5 `rpc HealthCheck(google.protobuf.Empty) returns (HealthCheckResponse)`
*   **Description**: Implements the standard gRPC health checking protocol. Allows external systems (like Kubernetes liveness/readiness probes or load balancers) to check the health status of the Auth Service instance.
*   **Request (`google.protobuf.Empty`)**: Empty.
*   **Response (`HealthCheckResponse`)**:
    *   `status` (ServingStatus enum):
        *   `SERVING`: The service is healthy and ready to accept requests.
        *   `NOT_SERVING`: The service is not healthy and cannot accept requests (e.g., lost database connection, critical error).
        *   `UNKNOWN`: The health status is unknown.
*   **gRPC Status Codes**:
    *   `OK` (0): Health status successfully returned in the response.
    *   `UNIMPLEMENTED` (12): If the health check is requested for a sub-service name that is not supported (though typically an empty service name is used for overall health).

---
*This gRPC API specification provides a foundation for inter-service communication. Specific error details for each RPC can be further refined using `google.rpc.Status` and `trailers` for richer error information if needed.*
