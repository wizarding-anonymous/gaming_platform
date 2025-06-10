<!-- File: backend/services/auth-service/docs/integration_points.md -->
# Auth Microservice Integration Points

Date: (Current Date)
Version: Based on current implemented state and conceptual plans.

This document outlines the key integration points for the Auth microservice, including its provided APIs (gRPC and REST), published events, consumed events, and any direct dependencies on other services.

## 1. Provided Interfaces

These are the interfaces that the Auth microservice exposes to other components in the platform.

### 1.1. gRPC API (`api/proto/v1/auth.proto`)

The gRPC API is primarily intended for inter-service communication and for use by the API Gateway.

*   **Service**: `auth.v1.AuthService`
*   **Primary Consumers**: API Gateway, Other Microservices.

*   **RPC Methods**:
    *   **`HealthCheck(google.protobuf.Empty) returns (HealthCheckResponse)`**:
        *   Purpose: Allows monitoring systems and other services to check the health of the Auth service.
        *   Consumers: Kubernetes, monitoring tools, other services.
    *   **`ValidateToken(ValidateTokenRequest) returns (ValidateTokenResponse)`**:
        *   Purpose: Validates a JWT access token and returns its claims if valid.
        *   Primary Consumer: API Gateway (for authenticating incoming requests).
        *   Secondary Consumers: Other microservices that receive tokens directly and need to validate them without relying solely on API Gateway.
        *   Payload: `ValidateTokenRequest { token: string }`, `ValidateTokenResponse { valid: bool, user_id, username, roles, permissions, session_id, expires_at, error_code, error_message }`.
    *   **`CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse)`**:
        *   Purpose: Verifies if a user has a specific permission.
        *   Primary Consumers: API Gateway (for fine-grained route protection), other microservices (for business logic authorization).
        *   Payload: `CheckPermissionRequest { user_id, permission_id }`, `CheckPermissionResponse { has_permission: bool }`.
    *   **`GetUserInfo(GetUserInfoRequest) returns (UserInfoResponse)`**:
        *   Purpose: Retrieves detailed information about a user.
        *   Primary Consumers: Other microservices that need user details not present in the JWT (e.g., user status, email for notifications if not in token).
        *   Payload: `GetUserInfoRequest { user_id }`, `UserInfoResponse { user: UserInfo { id, username, email, status, created_at, email_verified_at, last_login_at, roles, mfa_enabled } }`.
    *   **`GetJWKS(GetJWKSRequest) returns (GetJWKSResponse)`**:
        *   Purpose: Provides the JSON Web Key Set (JWKS) containing the public keys used to sign JWTs. Allows external consumers (like API Gateway or other services) to validate JWT signatures offline/locally.
        *   Primary Consumers: API Gateway, other microservices.
        *   Payload: `GetJWKSRequest {}` (empty), `GetJWKSResponse { keys: [JSONWebKey { kty, kid, use, alg, n, e }] }`.

*   **Assumptions**:
    *   Consumed via standard gRPC mechanisms.
    *   Tracing headers (e.g., Jaeger, OpenTelemetry) are propagated via gRPC metadata, handled by common interceptors.

### 1.2. REST API (via API Gateway)

The REST API is primarily for end-user clients (via frontend applications) and administrative tools, proxied through an API Gateway.

*   **Endpoint Groups**:
    *   **`/api/v1/auth/...` (Core Authentication)**:
        *   Consumers: Client applications (web, mobile), third-party OAuth clients.
        *   Key Endpoints: `POST /register`, `POST /login`, `POST /refresh-token`, `POST /logout`, `POST /verify-email`, `POST /forgot-password`, `POST /reset-password`, `POST /login/2fa/verify`, `POST /telegram-login`.
        *   Purpose: User registration, login, token management, password lifecycle, 2FA during login.
    *   **`/api/v1/me/...` (User Self-Service)**:
        *   Consumers: Authenticated client applications.
        *   Authentication: Protected by JWT authentication middleware.
        *   Key Endpoints: `GET /me`, `PUT /me/password`, `GET /me/sessions`, `DELETE /me/sessions/{session_id}`, 2FA management (`/me/2fa/...`), API key management (`/me/api-keys/...`).
        *   Purpose: User profile management, password changes, session viewing/revocation, 2FA setup, API key management.
    *   **`/api/v1/admin/...` (Administrative)**:
        *   Consumers: Administrative frontends/tools.
        *   Authentication & Authorization: Protected by JWT authentication and RBAC middleware (requiring specific admin permissions).
        *   Key Endpoints: User management (`/admin/users/...`), audit log viewing (`/admin/audit-logs`).
        *   Purpose: Platform administration of users, roles, and system activity.

*   **DTOs and Error Responses**:
    *   Request and Response DTOs are defined per endpoint.
    *   Error responses are conceptualized as JSON objects (e.g., `{"error": "message", "details": "..."}`). Consistent platform-wide error DTOs are recommended.

## 2. Published Events (Kafka CloudEvents)

Auth Service publishes these events to inform other parts of the system.
**Default Source**: `auth-service`
**Default Topic**: `auth-events` (or specific topics per event group if needed)
**Format**: JSON CloudEvents 1.0

*   **`auth.user.registered`**:
    *   Purpose: User successfully created.
    *   Payload: `{ "user_id", "username", "email", "registered_at" }`
    *   Subject: `user_id`
*   **`auth.user.email_verified`**:
    *   Purpose: User's email successfully verified.
    *   Payload: `{ "user_id", "email", "verified_at" }`
    *   Subject: `user_id`
*   **`auth.user.password_reset_requested`**:
    *   Purpose: User initiated a password reset.
    *   Payload: `{ "user_id", "email", "requested_at", "reset_token_value_for_notification_service_if_not_handled_by_it" }` (Token value for notification if applicable)
    *   Subject: `user_id`
*   **`auth.user.password_changed`**:
    *   Purpose: User's password successfully changed.
    *   Payload: `{ "user_id", "changed_at" }`
    *   Subject: `user_id`
*   **`auth.user.login_success`**:
    *   Purpose: User successfully logged in (past all factors).
    *   Payload: `{ "user_id", "session_id", "ip_address", "user_agent", "login_at" }`
    *   Subject: `user_id`
*   **`auth.user.login_failed`**:
    *   Purpose: A login attempt failed.
    *   Payload: `{ "login_identifier", "ip_address", "user_agent", "reason", "failed_at" }`
    *   Subject: `login_identifier` (or `user_id` if user was identified)
*   **`auth.user.account_locked`**:
    *   Purpose: User account locked due to excessive failed attempts.
    *   Payload: `{ "user_id", "reason", "locked_at", "lockout_until" }`
    *   Subject: `user_id`
*   **`auth.user.account_unblocked`** (Published by UserService after admin action via event or direct call):
    *   Purpose: User account unblocked by an admin.
    *   Payload: `{ "user_id", "unblocked_by_admin_id", "unblocked_at" }`
    *   Subject: `user_id`
*   **`auth.user.roles_changed`**:
    *   Purpose: User's roles have been modified by an admin.
    *   Payload: `{ "user_id", "old_roles": [], "new_roles": [], "changed_by_admin_id", "changed_at" }`
    *   Subject: `user_id`
*   **`auth.session.created`**:
    *   Purpose: A new user session was created (often part of login).
    *   Payload: `{ "session_id", "user_id", "ip_address", "user_agent", "created_at", "expires_at" }`
    *   Subject: `session_id` (or `user_id`)
*   **`auth.session.revoked`**:
    *   Purpose: A user session was revoked (logout, admin action).
    *   Payload: `{ "session_id", "user_id", "revoked_at", "reason" }`
    *   Subject: `session_id` (or `user_id`)
*   **`auth.api_key.created`**:
    *   Purpose: A new API key was generated for a user.
    *   Payload: `{ "user_id", "api_key_id", "key_prefix", "name", "created_at" }`
    *   Subject: `api_key_id` (or `user_id`)
*   **`auth.api_key.revoked`**:
    *   Purpose: An API key was revoked.
    *   Payload: `{ "user_id", "api_key_id", "revoked_at" }`
    *   Subject: `api_key_id` (or `user_id`)
*   **(Conceptual) `auth.user.status_changed`**:
    *   Purpose: Generic event if user status changes not covered by block/unblock.
    *   Payload: `{ "user_id", "old_status", "new_status", "reason", "actor_id", "changed_at" }`
    *   Subject: `user_id`

## 3. Consumed Events (Kafka CloudEvents)

Auth Service consumes these events to react to changes in other parts of the platform.

*   **`account.user.profile_updated`**:
    *   Source: Account Service (Conceptual)
    *   Purpose: To inform Auth Service of user profile changes (e.g., email change, username change) that might be relevant for its local cache or JWT contents if it denormalizes such data.
    *   Handling: Currently logged. Could trigger updates to a local user projection if Auth Service maintains one beyond essential auth fields.
    *   Assumed Payload: `{ "user_id", "new_email", "new_username", "updated_fields": [] }`
*   **`admin.user.force_logout`**:
    *   Source: Admin Service (Conceptual)
    *   Purpose: To instruct Auth Service to terminate all sessions for a specific user.
    *   Handling: Calls `AuthLogicService.LogoutAllUserSessions(ctx, userID)`.
    *   Assumed Payload: `{ "user_id", "reason", "admin_actor_id" }`
*   **`admin.user.block`**:
    *   Source: Admin Service (Conceptual)
    *   Purpose: To instruct Auth Service to block a user account.
    *   Handling: Calls `UserService.UpdateUserStatus(ctx, userID, entity.UserStatusBlocked, reason, lockoutUntil, adminActorID)`.
    *   Assumed Payload: `{ "user_id", "reason", "lockout_until_optional", "admin_actor_id" }`
*   **`admin.user.unblock`**:
    *   Source: Admin Service (Conceptual)
    *   Purpose: To instruct Auth Service to unblock a user account.
    *   Handling: Calls `UserService.UpdateUserStatus(ctx, userID, entity.UserStatusActive, "", adminActorID)`.
    *   Assumed Payload: `{ "user_id", "admin_actor_id" }`

## 4. Direct Outgoing Dependencies

*   **Notification Service (Conceptual / Event-Driven Preferred)**:
    *   Purpose: Sending emails for account verification, password reset instructions, critical security alerts.
    *   Integration: Preferably via Kafka events published by Auth Service (e.g., `auth.user.registered` containing a verification token hint, `auth.user.password_reset_requested` containing reset token hint) which Notification Service consumes.
    *   Synchronous Fallback (Less Ideal): If immediate confirmation of email dispatch is required within an Auth Service flow (and cannot be handled by frontend polling or user re-request), a direct gRPC call to a Notification Service might be considered. This was not explicitly designed in the current service logic.

This document provides a summary of how the Auth microservice interacts with other components of the platform.
