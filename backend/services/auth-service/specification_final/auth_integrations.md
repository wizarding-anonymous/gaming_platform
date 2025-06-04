# Auth Service: Integrations Specification

**Version:** 1.0
**Date:** 2023-10-27

## 1. Introduction

This document details the integration points and interaction patterns between the Auth Service and other microservices within the [Platform Name] ecosystem, as well as with essential external systems like the API Gateway. Effective integration is crucial for ensuring consistent security policy enforcement and a seamless user experience.

## 2. General Integration Principles

*   **Communication Protocols**:
    *   **gRPC**: Preferred for synchronous, internal server-to-server communication due to its performance and strong typing.
    *   **REST (HTTP/JSON)**: Used for APIs exposed to clients (via API Gateway) and potentially for some internal communications where gRPC is not suitable.
    *   **Asynchronous (Kafka)**: Used for event-driven communication, decoupling services and handling non-blocking operations.
*   **Authentication**:
    *   Inter-service gRPC calls are secured with mTLS.
    *   Services may also present a service account JWT for Auth Service to authorize system-level actions.
*   **Error Handling**: Services should handle potential errors from Auth Service gracefully (e.g., network issues, specific gRPC error codes, HTTP error statuses) and implement appropriate retry or fallback mechanisms.
*   **Data Consistency**: For data owned by Auth Service (e.g., user roles), other services should treat Auth Service as the source of truth. For data owned by other services (e.g., user profile details from Account Service), Auth Service will either query it synchronously or consume events for eventual consistency if near real-time data is not strictly required for an auth decision.

## 3. Integration with API Gateway

*   **Direction**: API Gateway -> Auth Service
*   **Purpose**: The API Gateway is the primary consumer of Auth Service's token validation capabilities to secure platform APIs.
*   **Interface Type**: Primarily gRPC (`ValidateToken` RPC), can also use a REST endpoint for token introspection if needed by certain gateway implementations.
*   **Key Interactions**:
    1.  **Token Validation**:
        *   **Flow**: Client sends a request with JWT Access Token in `Authorization` header to API Gateway.
        *   API Gateway extracts the token and calls Auth Service's `ValidateToken` RPC.
        *   Auth Service validates the token's signature (using its public key), expiry, issuer, audience, and checks for revocation (if applicable).
        *   Auth Service returns the validation status and token claims (user_id, username, roles, permissions, session_id) to API Gateway.
        *   **Data Exchanged**: Access Token (string), ValidationResponse (bool valid, user_id, roles, permissions, etc.).
    2.  **Passing User Context**:
        *   **Flow**: If `ValidateToken` is successful, API Gateway extracts `user_id`, `roles`, and `permissions` from the response.
        *   API Gateway injects these into downstream request headers (e.g., `X-User-ID`, `X-User-Roles`, `X-User-Permissions`) for internal services to consume.
    3.  **JWKS Endpoint Access**:
        *   **Flow**: API Gateway (or other services needing to validate JWTs locally) periodically fetches public keys from Auth Service's JWKS endpoint (`GET /api/v1/auth/.well-known/jwks.json` or gRPC `GetJWKS`).
        *   This allows the API Gateway to validate token signatures without calling Auth Service for every request, improving performance. Auth Service must manage key rotation and ensure the JWKS endpoint is always up-to-date.
        *   **Data Exchanged**: JWKS payload (JSON).
    4.  **Public Endpoint Proxying**:
        *   **Flow**: API Gateway routes requests for Auth Service's public REST endpoints (e.g., `/register`, `/login`, `/refresh-token`, `/oauth/*`) directly to the Auth Service's HTTP interface.
*   **Security**: Communication between API Gateway and Auth Service should be over a secure internal network, ideally using mTLS if the gateway supports it for upstream connections.

## 4. Integration with Account Service

*   **Direction**: Auth Service <-> Account Service
*   **Purpose**: Coordination for user registration, profile information relevant to authentication, and account status updates.
*   **Interface Type**: Kafka Events, gRPC.
*   **Key Interactions**:
    1.  **User Registration**:
        *   **Flow**:
            1.  Auth Service receives a registration request (username, email, password).
            2.  Auth Service creates the core user credential record (hashed password, salt, status `pending_verification`).
            3.  Auth Service publishes `auth.user.registered.v1` event to Kafka.
            4.  Account Service consumes this event and creates the corresponding user profile record (display name, etc.).
        *   **Data Exchanged (Event)**: `user_id`, `username`, `email`, `display_name` (if provided to Auth).
    2.  **User Status Check (During Login)**:
        *   **Flow**: Before issuing tokens upon login, Auth Service may need to check the user's current status (e.g., if they are globally blocked or deleted by an admin action primarily managed in Account Service).
        *   Auth Service calls Account Service's gRPC endpoint (e.g., `AccountService.GetUserStatus(GetAccountStatusRequest {user_id})`) to get the current authoritative status.
        *   **Data Exchanged (gRPC)**: `user_id`, `status_response` (e.g., "active", "blocked").
    3.  **Profile Updates Affecting Auth**:
        *   **Flow**: If Account Service updates information that might affect authentication (e.g., user's primary email used for login changes, or account status changes to 'blocked' or 'deleted'), it publishes an event (e.g., `account.user.email_changed.v1`, `account.user.status_changed.v1`).
        *   Auth Service consumes these events.
        *   If status is 'blocked' or 'deleted', Auth Service revokes active sessions/refresh tokens for the user.
        *   If primary email changes, Auth Service updates its local copy (if it maintains one for login) or relies on Account Service for email lookups.
        *   **Data Exchanged (Event)**: `user_id`, changed fields, new values.

## 5. Integration with Notification Service

*   **Direction**: Auth Service -> Notification Service
*   **Purpose**: Auth Service triggers notifications for various events like email verification, password reset, 2FA code delivery, and security alerts.
*   **Interface Type**: Kafka Events (preferred for decoupling) or direct gRPC calls.
*   **Key Interactions**:
    1.  **Email Verification Request**:
        *   **Flow**: After user registration or manual request, Auth Service generates a verification token.
        *   Auth Service publishes an `auth.user.verification_required.v1` event (or similar, could be part of `auth.user.registered.v1`) containing `user_id`, `email`, and `verification_token_or_link`.
        *   Notification Service consumes this event and sends the verification email.
        *   **Data Exchanged (Event)**: `user_id`, `email`, `verification_token`/`link`.
    2.  **Password Reset Request**:
        *   **Flow**: User requests password reset. Auth Service generates a reset token.
        *   Auth Service publishes `auth.user.password_reset_requested.v1` event.
        *   Notification Service consumes and sends the password reset email.
        *   **Data Exchanged (Event)**: `user_id`, `email`, `reset_token`/`link`.
    3.  **2FA Code Delivery (SMS/Email)**:
        *   **Flow**: User attempts login, chooses SMS/Email 2FA. Auth Service generates OTP.
        *   Auth Service publishes an `auth.user.2fa_code_generated.v1` event (or calls gRPC) with `user_id`, `method` ("sms" or "email"), `otp_code`, and `recipient_contact_info` (phone/email from Account Service or Auth cache).
        *   Notification Service consumes/receives and sends the OTP.
        *   **Data Exchanged (Event/gRPC)**: `user_id`, `method`, `otp_code`, `recipient_contact_info`.
    4.  **Security Alerts**:
        *   **Flow**: Auth Service detects suspicious activity (e.g., login from new device/location, multiple failed attempts).
        *   Auth Service publishes an `auth.user.suspicious_activity_alert.v1` event.
        *   Notification Service consumes and alerts the user.
        *   **Data Exchanged (Event)**: `user_id`, `alert_type`, `details` (IP, timestamp, etc.).

## 6. Integration with Admin Service

*   **Direction**: Admin Service -> Auth Service
*   **Purpose**: Allows administrators to manage users, roles, sessions, and view audit logs related to authentication.
*   **Interface Type**: REST API (Auth Service's `/admin/*` endpoints, proxied by API Gateway) or direct gRPC calls if Admin Service backend calls Auth Service backend.
*   **Key Interactions**:
    1.  **User Management**:
        *   **Flow**: Admin performs actions like listing users, viewing user details, blocking/unblocking users, changing user roles via Admin Service UI.
        *   Admin Service calls corresponding Auth Service REST/gRPC endpoints (e.g., `GET /admin/users`, `POST /admin/users/{user_id}/block`, `PUT /admin/users/{user_id}/roles`).
        *   **Data Exchanged**: User IDs, status, roles, admin commands.
    2.  **Audit Log Viewing**:
        *   **Flow**: Admin views audit logs via Admin Service UI.
        *   Admin Service calls Auth Service `GET /admin/audit-logs` endpoint with appropriate filters.
        *   **Data Exchanged**: Audit log entries.
    3.  **Forced Logout/Session Revocation**:
        *   **Flow**: Admin forces a user logout or revokes a specific session.
        *   Admin Service can publish an `admin.user.force_logout.v1` event consumed by Auth Service, or call a specific gRPC/REST endpoint on Auth Service.
        *   **Data Exchanged**: `user_id`, `session_id` (optional).

## 7. Integration with Other Microservices (General Pattern)

*   **Direction**: Other Microservice -> Auth Service
*   **Purpose**: To validate access tokens and check permissions for requests they receive.
*   **Interface Type**: gRPC (`ValidateToken`, `CheckPermission`).
*   **Key Interactions**:
    1.  **Token Validation & Permission Check**:
        *   **Flow**: A microservice (e.g., Catalog Service) receives a request from a client (via API Gateway) containing a JWT in the `Authorization` header.
        *   The service *could* rely on user context (`X-User-ID`, `X-User-Roles`) injected by API Gateway if the gateway already validated the token with Auth Service.
        *   For critical operations or if direct token validation is preferred, the service calls Auth Service's `ValidateToken` RPC.
        *   If token is valid, the service then calls `CheckPermission` RPC with the `user_id` (from token claims), the required `permission`, and optional `resource_id`.
        *   Based on the `CheckPermissionResponse`, the service either proceeds or denies the request.
        *   **Data Exchanged**: Access Token, `user_id`, `permission_string`, `resource_id`, validation/permission results.

---
*This document outlines the primary integration points. Each interaction should have clearly defined contracts (API schemas, event payloads), error handling procedures, and security considerations (like mTLS for gRPC).*
