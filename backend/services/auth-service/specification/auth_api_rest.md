<!-- File: backend/services/auth-service/specification/auth_api_rest.md -->
# Auth Service: REST API Specification

**Version:** 1.0
**Date:** 2023-10-27

## 1. Introduction

This document provides the detailed specification for the RESTful API exposed by the Auth Service. This API is the primary interface for client applications (Web, Desktop, Mobile via API Gateway) to interact with authentication, authorization, and user session management functionalities.

## 2. General Principles

*   **Base URL**: All REST API endpoints for the Auth Service are prefixed with `/api/v1/auth`. The API Gateway is responsible for routing requests matching this prefix to the Auth Service.
*   **Data Format**: All request and response bodies are in JSON (application/json) format.
*   **Authentication**:
    *   Endpoints related to login, registration, token refresh, password reset, and email verification are generally public (do not require prior authentication).
    *   Authenticated endpoints require a valid JWT Access Token to be passed in the `Authorization` header as a Bearer token (e.g., `Authorization: Bearer <your_access_token>`).
*   **Error Handling**: Errors are returned using standard HTTP status codes. The response body for errors follows a common JSON structure:
    ```json
    {
      "errors": [
        {
          "code": "ERROR_CODE_STRING", // e.g., "invalid_credentials", "validation_error"
          "title": "Human-readable error title",
          "detail": "Detailed error message providing context or specific field issues.",
          "source": { // Optional: points to the part of the request that caused the error
            "pointer": "/data/attributes/email" // JSON Pointer
          },
          "meta": { // Optional: additional metadata
            "request_id": "trace-id-for-logging"
          }
        }
      ]
    }
    ```
    Refer to the "Стандарты API, форматов данных, событий и конфигурационных файлов.txt" for general error code guidelines. Specific error codes for Auth Service are detailed under each endpoint.
*   **Rate Limiting**: Applied by the API Gateway and potentially at the service level for sensitive endpoints to prevent abuse. Clients should expect `429 Too Many Requests` responses if limits are exceeded.
*   **Idempotency**: For critical mutating operations (e.g., creating API keys, initiating password reset), clients can provide an `Idempotency-Key` header (UUID format). The server should attempt to process the request idempotently if this key has been seen recently.
*   **CORS**: Handled by the API Gateway.

## 3. API Endpoints

### 3.1 User Registration and Login

#### 3.1.1 `POST /register`
*   **Description**: Registers a new user.
*   **Authentication**: Not required.
*   **Request Body**:
    ```json
    {
      "username": "newuser123", // Required, unique, constraints: 3-30 chars, alphanumeric, '-', '_'
      "email": "newuser@example.com", // Required, unique, valid email format
      "password": "Password123!", // Required, constraints: min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char
      "display_name": "Новый Пользователь" // Optional, public display name
    }
    ```
*   **Success Response (201 Created)**:
    ```json
    {
      "data": {
        "user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", // UUID
        "username": "newuser123",
        "email": "newuser@example.com",
        "display_name": "Новый Пользователь",
        "status": "pending_verification", // Initial status
        "message": "Для завершения регистрации проверьте ваш email и перейдите по ссылке для подтверждения."
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): Invalid input format (e.g., email format, password complexity). `details` will contain specific field errors.
    *   `409 Conflict` (Code: `username_already_exists`): Username is already taken.
    *   `409 Conflict` (Code: `email_already_exists`): Email is already registered.
    *   `500 Internal Server Error` (Code: `internal_error`): Server-side error.

#### 3.1.2 `POST /login`
*   **Description**: Authenticates a user and returns JWTs.
*   **Authentication**: Not required.
*   **Request Body**:
    ```json
    {
      "login": "newuser@example.com", // Can be username or email
      "password": "Password123!",
      "device_info": { // Optional: Information about the client device for session tracking
        "type": "desktop", // e.g., "desktop", "mobile_android", "mobile_ios", "web_browser"
        "os": "Windows 10",
        "app_version": "1.0.1",
        "device_name": "Основной ПК" // User-friendly name for the device/session
      }
    }
    ```
*   **Success Response (200 OK) (No 2FA)**:
    ```json
    {
      "data": {
        "access_token": "eyJhbGciOiJSUzI1NiIsI...", // RS256 JWT
        "refresh_token": "def50200abc...", // Opaque refresh token
        "token_type": "Bearer",
        "expires_in": 900, // Access token TTL in seconds (15 minutes)
        "user": {
          "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
          "username": "newuser123",
          "email": "newuser@example.com",
          "display_name": "Новый Пользователь",
          "roles": ["user"] // Array of roles
        }
      }
    }
    ```
*   **Success Response (200 OK) (2FA Required)**:
    ```json
    {
      "data": {
        "status": "2fa_required",
        "temp_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...", // Short-lived temporary token for 2FA verification step
        "available_methods": ["totp", "sms"], // List of 2FA methods enabled by the user
        "expires_in": 300 // TTL for temp_token (5 minutes)
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): Missing `login` or `password`.
    *   `401 Unauthorized` (Code: `invalid_credentials`): Incorrect login or password.
    *   `403 Forbidden` (Code: `user_blocked`): User account is blocked.
    *   `403 Forbidden` (Code: `email_not_verified`): User email is not verified (if required for login).
    *   `429 Too Many Requests` (Code: `too_many_login_attempts`): Login attempts exceeded.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.1.3 `POST /refresh-token`
*   **Description**: Issues a new pair of access and refresh tokens using a valid refresh token.
*   **Authentication**: Not required.
*   **Request Body**:
    ```json
    {
      "refresh_token": "def50200abc..."
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "access_token": "new_eyJhbGciOiJSUzI1NiIs...",
        "refresh_token": "new_def50200xyz...", // A new refresh token is issued (rotation)
        "token_type": "Bearer",
        "expires_in": 900 // New access token TTL
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): `refresh_token` is missing.
    *   `401 Unauthorized` (Code: `invalid_refresh_token`): Refresh token is invalid, expired, or revoked.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.1.4 `POST /logout`
*   **Description**: Invalidates the current user's session (associated refresh token). The client is responsible for discarding the access token.
*   **Authentication**: `Bearer <access_token>` required.
*   **Request Body**:
    ```json
    {
      // Refresh token is typically read from an HttpOnly cookie by the Auth service itself,
      // or if managed by client (e.g. mobile), it can be sent in the body.
      // V2 spec indicates it can be empty if cookie-based, or required if client-managed.
      // For robustness, let's assume client *can* send it.
      "refresh_token": "def50200abc..." // Optional: if client manages refresh tokens
    }
    ```
*   **Success Response (204 No Content)**.
*   **Error Responses**:
    *   `400 Bad Request` (Code: `missing_refresh_token`): If refresh token is expected in body but not provided.
    *   `401 Unauthorized` (Code: `invalid_token`): Access token is invalid or expired.
    *   `401 Unauthorized` (Code: `invalid_refresh_token`): If provided refresh_token is invalid or doesn't match the session.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.1.5 `POST /logout-all`
*   **Description**: Invalidates all active sessions (all refresh tokens) for the currently authenticated user, except potentially the current one if a mechanism to identify it exists.
*   **Authentication**: `Bearer <access_token>` required.
*   **Request Body**: Empty.
*   **Success Response (204 No Content)**.
*   **Error Responses**:
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `500 Internal Server Error` (Code: `internal_error`).

### 3.2 Email Verification

#### 3.2.1 `POST /verify-email`
*   **Description**: Verifies a user's email address using a token sent to their email.
*   **Authentication**: Not required.
*   **Request Body**:
    ```json
    {
      "token": "verification_code_from_email_12345"
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "message": "Email успешно подтвержден."
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): `token` is missing or invalid format.
    *   `400 Bad Request` (Code: `invalid_verification_code`): Token is incorrect.
    *   `400 Bad Request` (Code: `expired_verification_code`): Token has expired.
    *   `400 Bad Request` (Code: `already_used_verification_code`): Token has already been used.
    *   `404 Not Found` (Code: `user_not_found`): User associated with token not found.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.2.2 `POST /resend-verification`
*   **Description**: Resends the email verification link/code.
*   **Authentication**: Not required.
*   **Request Body**:
    ```json
    {
      "email": "user_awaiting_verification@example.com"
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "message": "Новый код подтверждения отправлен на ваш email."
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): Invalid email format.
    *   `404 Not Found` (Code: `user_not_found`): User with this email not found or already verified.
    *   `429 Too Many Requests` (Code: `too_many_resend_attempts`): Limit for resending verification exceeded.
    *   `500 Internal Server Error` (Code: `internal_error`).

### 3.3 Password Management

#### 3.3.1 `POST /forgot-password`
*   **Description**: Initiates the password reset process.
*   **Authentication**: Not required.
*   **Request Body**:
    ```json
    {
      "email": "user_to_reset@example.com"
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        // Generic message to prevent user enumeration
        "message": "Если пользователь с таким email существует, на него будет отправлена инструкция по сбросу пароля."
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): Invalid email format.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.3.2 `POST /reset-password`
*   **Description**: Sets a new password using a password reset token.
*   **Authentication**: Not required.
*   **Request Body**:
    ```json
    {
      "token": "reset_token_from_email_link_abc123",
      "new_password": "NewSecurePassword456!" // Must meet complexity requirements
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "message": "Пароль успешно изменен."
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): `token` or `new_password` missing, or password complexity not met.
    *   `400 Bad Request` (Code: `invalid_reset_token`): Token is incorrect.
    *   `400 Bad Request` (Code: `expired_reset_token`): Token has expired.
    *   `404 Not Found` (Code: `user_not_found`): User associated with token not found.
    *   `500 Internal Server Error` (Code: `internal_error`).

### 3.4 Two-Factor Authentication (2FA) Management (Current User)
*All endpoints in this section require `Bearer <access_token>` authentication.*

#### 3.4.1 `POST /me/2fa/totp/enable`
*   **Description**: Initiates enabling TOTP-based 2FA. Returns a secret key and a QR code.
*   **Request Body**: Empty.
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "secret_key": "JBSWY3DPEHPK3PXP", // Base32 encoded secret for manual entry
        "qr_code_image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAPoAAAD6CAYAAACI7Fo9AAAAAklEQVR4AewaftIAAA..." // Data URL of QR code image
      }
    }
    ```
*   **Error Responses**:
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `409 Conflict` (Code: `2fa_already_enabled`): 2FA is already active for this user.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.4.2 `POST /me/2fa/totp/verify`
*   **Description**: Verifies the TOTP code provided by the user and activates 2FA. Returns backup codes.
*   **Request Body**:
    ```json
    {
      "totp_code": "123456" // 6-digit code from authenticator app
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "message": "Двухфакторная аутентификация (TOTP) успешно включена.",
        "backup_codes": [ // One-time backup codes, user must save these
          "ABCDE-FGHIJ",
          "KLMNO-PQRST",
          // ... 3 more codes
        ]
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): Invalid `totp_code` format.
    *   `400 Bad Request` (Code: `invalid_2fa_code`): Incorrect TOTP code.
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `404 Not Found` (Code: `totp_setup_not_initiated`): `/me/2fa/totp/enable` was not called first.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.4.3 `POST /login/2fa/verify`
*   **Description**: Verifies a 2FA code during the login process. Used after successful password authentication when 2FA is required.
*   **Authentication**: Requires a `Bearer <temp_token>` (temporary token obtained from the `/login` endpoint).
*   **Request Body**:
    ```json
    {
      "method": "totp", // or "sms", "backup_code" depending on user's setup and choice
      "code": "123456"   // The 2FA code
    }
    ```
*   **Success Response (200 OK)**: Same as successful `/login` response (Access/Refresh tokens, user info).
    ```json
    {
      "data": {
        "access_token": "eyJhbGciOiJSUzI1NiIsI...",
        "refresh_token": "def50200abc...",
        "token_type": "Bearer",
        "expires_in": 900,
        "user": { /* ... user info ... */ }
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): Missing `method` or `code`.
    *   `401 Unauthorized` (Code: `invalid_temp_token`): Temporary token is invalid or expired.
    *   `401 Unauthorized` (Code: `invalid_2fa_code`): Incorrect 2FA code.
    *   `429 Too Many Requests` (Code: `too_many_2fa_attempts`): 2FA code entry attempts exceeded.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.4.4 `POST /me/2fa/disable`
*   **Description**: Disables 2FA for the current user. Requires password or current 2FA code for confirmation.
*   **Request Body**:
    ```json
    {
      // Provide one of the following for confirmation
      "password": "CurrentUserPassword",
      // OR
      // "totp_code": "123456"
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "message": "Двухфакторная аутентификация успешно отключена."
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): Missing confirmation field.
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `401 Unauthorized` (Code: `invalid_password_or_2fa_code`): Provided password or 2FA code is incorrect.
    *   `404 Not Found` (Code: `2fa_not_enabled`): 2FA is not currently active for this user.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.4.5 `POST /me/2fa/backup-codes/regenerate`
*   **Description**: Generates a new set of backup codes, invalidating any previous ones. Requires password or current 2FA code for confirmation.
*   **Request Body**:
    ```json
    {
      // Provide one of the following for confirmation
      "password": "CurrentUserPassword",
      // OR
      // "totp_code": "123456"
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "message": "Резервные коды успешно перегенерированы.",
        "backup_codes": [ // New set of one-time backup codes
          "VWXYZ-ABCDE",
          "FGHIJ-KLMNO",
          // ... 3 more codes
        ]
      }
    }
    ```
*   **Error Responses**:
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `401 Unauthorized` (Code: `invalid_password_or_2fa_code`): Provided password or 2FA code is incorrect.
    *   `404 Not Found` (Code: `2fa_not_enabled`): TOTP-based 2FA (which uses backup codes) is not active.
    *   `500 Internal Server Error` (Code: `internal_error`).

### 3.5 Current User Management (`/me`)
*All endpoints in this section require `Bearer <access_token>` authentication.*

#### 3.5.1 `GET /me`
*   **Description**: Retrieves detailed information about the currently authenticated user.
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "username": "newuser123",
        "email": "newuser@example.com",
        "display_name": "Новый Пользователь",
        "status": "active", // e.g., "active", "pending_verification"
        "email_verified_at": "2025-05-24T12:40:00Z", // Null if not verified
        "last_login_at": "2025-05-25T10:00:00Z",
        "created_at": "2025-05-24T12:34:56Z",
        "roles": ["user", "developer"],
        "mfa_enabled": true, // boolean indicating if any 2FA method is active
        "active_sessions_count": 2 // Number of currently active sessions
      }
    }
    ```
*   **Error Responses**:
    *   `401 Unauthorized` (Code: `invalid_token`).

#### 3.5.2 `PUT /me/password`
*   **Description**: Changes the password for the currently authenticated user.
*   **Request Body**:
    ```json
    {
      "current_password": "OldPassword123!",
      "new_password": "NewStrongerPassword456!" // Must meet complexity requirements
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "message": "Пароль успешно изменен. Все другие сессии были завершены."
      }
    }
    ```
    *(Note: Changing password should invalidate other active sessions/refresh tokens for security).*
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): New password does not meet complexity or fields missing.
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `401 Unauthorized` (Code: `invalid_current_password`): `current_password` is incorrect.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.5.3 `GET /me/sessions`
*   **Description**: Retrieves a list of active sessions for the current user.
*   **Success Response (200 OK)**:
    ```json
    {
      "data": [
        {
          "session_id": "b2c3d4e5-f6a7-8b9c-0d1e-2f3a4b5c6d7e",
          "ip_address": "192.168.1.10",
          "user_agent": "Chrome/100.0.4896.127 Windows NT 10.0",
          "device_info": {"type": "desktop", "os": "Windows 10", "device_name": "Основной ПК"},
          "last_activity_at": "2025-05-25T10:00:00Z",
          "created_at": "2025-05-25T09:00:00Z",
          "is_current": true // Indicates if this is the session making the request
        },
        {
          "session_id": "c3d4e5f6-a7b8-9c0d-1e2f-3a4b5c6d7e8f",
          "ip_address": "10.0.0.5",
          // ... other session details ...
          "is_current": false
        }
      ]
      // "meta": { "page": 1, "per_page": 20, "total_items": 2, "total_pages": 1 } // Optional pagination
    }
    ```
*   **Error Responses**:
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.5.4 `DELETE /me/sessions/{session_id}`
*   **Description**: Revokes a specific active session (identified by `session_id`) for the current user.
*   **Path Parameters**:
    *   `session_id` (string, UUID): The ID of the session to revoke.
*   **Success Response (204 No Content)**.
*   **Error Responses**:
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `403 Forbidden` (Code: `cannot_revoke_current_session`): If user attempts to revoke the session used for this request (use `/logout` instead).
    *   `404 Not Found` (Code: `session_not_found`): Session ID does not exist or does not belong to the user.
    *   `500 Internal Server Error` (Code: `internal_error`).

### 3.6 External Authentication (OAuth & Telegram)

#### 3.6.1 `GET /oauth/{provider}`
*   **Description**: Initiates OAuth 2.0 Authorization Code flow with the specified provider. Redirects the user to the provider's authentication page.
*   **Path Parameters**:
    *   `provider` (string): e.g., `vk`, `odnoklassniki`. (List of supported providers configured server-side).
*   **Query Parameters (Optional)**:
    *   `redirect_uri` (string): Overrides default redirect URI (must be whitelisted).
    *   `state` (string): For CSRF protection, will be returned in callback.
*   **Success Response (302 Found)**: Redirect to provider's auth URL.
*   **Error Responses**:
    *   `400 Bad Request` (Code: `invalid_provider`): Provider not supported.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.6.2 `GET /oauth/{provider}/callback`
*   **Description**: Handles the callback from the OAuth provider after user authentication. Exchanges authorization code for tokens, fetches user info, and logs in or registers the user on the platform.
*   **Path Parameters**:
    *   `provider` (string): e.g., `vk`, `odnoklassniki`.
*   **Query Parameters (from provider)**:
    *   `code` (string): Authorization code.
    *   `state` (string): State parameter (must match if sent in initiate step).
    *   `error` (string): Error code from provider (if any).
*   **Success Response**: Typically a redirect to a frontend URL with platform tokens (access & refresh) in URL fragment or query parameters, or sets HttpOnly cookies. Alternatively, can directly return tokens similar to `/login`.
    ```json
    // Example direct response
    {
      "data": {
        "access_token": "platform_eyJhbGciOiJSUzI1NiIsI...",
        "refresh_token": "platform_def50200abc...",
        "token_type": "Bearer",
        "expires_in": 900,
        "user": { /* ... user info ... */ },
        "is_new_user": false // boolean
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `invalid_oauth_callback`): Missing `code` or `state` mismatch.
    *   `401 Unauthorized` (Code: `oauth_provider_error`): Error from provider (e.g., `access_denied`).
    *   `500 Internal Server Error` (Code: `oauth_exchange_failed`, `internal_error`).

#### 3.6.3 `POST /telegram-login`
*   **Description**: Authenticates a user based on data from the Telegram Login Widget.
*   **Authentication**: Not required.
*   **Request Body** (Data from Telegram Widget):
    ```json
    {
      "id": 123456789,
      "first_name": "Иван",
      "last_name": "Петров", // optional
      "username": "ivan_petrov_tg", // optional
      "photo_url": "https://t.me/i/userpic/320/ivan_petrov_tg.jpg", // optional
      "auth_date": 1672531200, // Unix timestamp
      "hash": "abcdef1234567890..." // Hash to verify data integrity
    }
    ```
*   **Success Response (200 OK)**: Same as successful `/login` response.
*   **Error Responses**:
    *   `400 Bad Request` (Code: `invalid_telegram_data`): Missing or invalid fields.
    *   `401 Unauthorized` (Code: `telegram_hash_verification_failed`): Data integrity check failed.
    *   `401 Unauthorized` (Code: `telegram_auth_data_outdated`): `auth_date` is too old.
    *   `500 Internal Server Error` (Code: `internal_error`).

### 3.7 API Key Management (Current User)
*All endpoints in this section require `Bearer <access_token>` authentication.*

#### 3.7.1 `GET /me/api-keys`
*   **Description**: Retrieves a list of API keys for the current user. Secrets are not returned.
*   **Success Response (200 OK)**:
    ```json
    {
      "data": [
        {
          "id": "key_uuid_1",
          "name": "Мой тестовый ключ",
          "key_prefix": "pltfrm_pk_", // Prefix of the key for identification
          "permissions": ["statistics.read"], // Scopes/permissions associated
          "created_at": "2025-01-10T10:00:00Z",
          "last_used_at": "2025-05-20T15:30:00Z", // Null if never used
          "expires_at": null // Null if non-expiring
        }
      ]
      // "meta": { ... pagination ... } // Optional pagination
    }
    ```
*   **Error Responses**:
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.7.2 `POST /me/api-keys`
*   **Description**: Creates a new API key for the current user. The full API key is returned **only once**.
*   **Request Body**:
    ```json
    {
      "name": "Ключ для моего приложения", // User-defined name for the key
      "permissions": ["library.read", "catalog.search"], // Requested scopes
      "expires_at": "2026-01-01T00:00:00Z" // Optional: ISO 8601, null for non-expiring
    }
    ```
*   **Success Response (201 Created)**:
    ```json
    {
      "data": {
        "id": "new_key_uuid_3",
        "name": "Ключ для моего приложения",
        "api_key": "pltfrm_sk_THIS_IS_THE_SECRET_PART_SAVE_IT_NOW_jXnZvLqPbRoW", // Full API key - display once!
        "key_prefix": "pltfrm_sk_",
        "permissions": ["library.read", "catalog.search"],
        "created_at": "2025-05-26T10:00:00Z",
        "expires_at": "2026-01-01T00:00:00Z"
      }
    }
    ```
*   **Error Responses**:
    *   `400 Bad Request` (Code: `validation_error`): Invalid input (name, permissions, expires_at).
    *   `400 Bad Request` (Code: `invalid_permissions`): Requested permissions are not valid.
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `422 Unprocessable Entity` (Code: `max_api_keys_reached`): User has reached their API key limit.
    *   `500 Internal Server Error` (Code: `internal_error`).

#### 3.7.3 `DELETE /me/api-keys/{key_id}`
*   **Description**: Revokes/deletes an API key.
*   **Path Parameters**:
    *   `key_id` (string, UUID): ID of the API key to delete.
*   **Success Response (204 No Content)**.
*   **Error Responses**:
    *   `401 Unauthorized` (Code: `invalid_token`).
    *   `403 Forbidden` (Code: `permission_denied_key_foreign`): Key does not belong to user.
    *   `404 Not Found` (Code: `api_key_not_found`).
    *   `500 Internal Server Error` (Code: `internal_error`).

### 3.8 Administrative Endpoints (`/admin`)
*All endpoints in this section require `Bearer <access_token>` authentication and appropriate admin roles/permissions.*

#### 3.8.1 `GET /admin/users`
*   **Description**: Retrieves a list of platform users with filtering and pagination.
*   **Query Parameters**: `page`, `per_page`, `email`, `username`, `status`, `role`.
*   **Success Response (200 OK)**:
    ```json
    {
      "data": [ /* Array of user objects, similar to /me but with more admin-visible fields */ ],
      "meta": { /* Pagination info */ }
    }
    ```
*   **Error Responses**: `401 Unauthorized`, `403 Forbidden`, `400 Bad Request`, `500 Internal Server Error`.

#### 3.8.2 `GET /admin/users/{user_id}`
*   **Description**: Retrieves detailed information about a specific user.
*   **Path Parameters**: `user_id` (string, UUID).
*   **Success Response (200 OK)**:
    ```json
    {
      "data": { /* Detailed user object, including potentially sensitive info for admins */ }
    }
    ```
*   **Error Responses**: `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `500 Internal Server Error`.

#### 3.8.3 `POST /admin/users/{user_id}/block`
*   **Description**: Blocks a user account.
*   **Path Parameters**: `user_id` (string, UUID).
*   **Request Body**:
    ```json
    {
      "reason": "Нарушение правил платформы, пункт 5.3." // Optional reason for blocking
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "message": "Пользователь успешно заблокирован.",
        "user_id": "user_uuid_1",
        "new_status": "blocked"
      }
    }
    ```
*   **Error Responses**: `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `409 Conflict` (user already blocked), `422 Unprocessable Entity` (cannot block self), `500 Internal Server Error`.

#### 3.8.4 `POST /admin/users/{user_id}/unblock`
*   **Description**: Unblocks a user account.
*   **Path Parameters**: `user_id` (string, UUID).
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "message": "Пользователь успешно разблокирован.",
        "user_id": "user_uuid_1",
        "new_status": "active"
      }
    }
    ```
*   **Error Responses**: `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `409 Conflict` (user not blocked), `500 Internal Server Error`.

#### 3.8.5 `PUT /admin/users/{user_id}/roles`
*   **Description**: Updates the roles for a specific user.
*   **Path Parameters**: `user_id` (string, UUID).
*   **Request Body**:
    ```json
    {
      "roles": ["user", "editor"] // Complete list of roles to assign
    }
    ```
*   **Success Response (200 OK)**:
    ```json
    {
      "data": {
        "user_id": "user_uuid_1",
        "updated_roles": ["user", "editor"]
      }
    }
    ```
*   **Error Responses**: `400 Bad Request` (invalid roles), `401 Unauthorized`, `403 Forbidden`, `404 Not Found`, `422 Unprocessable Entity` (cannot change own admin role), `500 Internal Server Error`.

#### 3.8.6 `GET /admin/audit-logs`
*   **Description**: Retrieves audit log entries with filtering and pagination.
*   **Query Parameters**: `page`, `per_page`, `user_id` (actor), `action`, `target_type`, `target_id`, `status`, `ip_address`, `date_from`, `date_to`.
*   **Success Response (200 OK)**:
    ```json
    {
      "data": [ /* Array of audit log entry objects */ ],
      "meta": { /* Pagination info */ }
    }
    ```
    *Audit Log Entry Object Example:*
    ```json
    {
      "id": "log_entry_uuid_1",
      "user_id": "admin_user_uuid", // Actor
      "action": "user_blocked",
      "target_type": "user",
      "target_id": "blocked_user_uuid",
      "ip_address": "198.51.100.10",
      "user_agent": "AdminPanel/1.0",
      "status": "success",
      "details": {"reason": "Нарушение правил."}, // Action-specific details
      "created_at": "2023-10-01T15:00:00Z"
    }
    ```
*   **Error Responses**: `401 Unauthorized`, `403 Forbidden`, `400 Bad Request` (invalid filter params), `500 Internal Server Error`.

---
*This REST API specification covers the primary endpoints based on the V2 document. Further details like specific validation rules for each field, more granular error codes, and request/response examples for every endpoint would be fleshed out in a live document.*
