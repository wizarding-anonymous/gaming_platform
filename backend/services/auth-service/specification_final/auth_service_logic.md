<!-- File: backend/services/auth-service/specification_final/auth_service_logic.md -->
# Auth Service: Service Logic and Workflows

**Version:** 1.0
**Date:** 2023-10-27

## 1. Introduction

This document details the core business logic, workflows, and operational processes of the Auth Service. It describes how different functionalities like user registration, login, token management, two-factor authentication (2FA), external provider authentication, password management, API key handling, session management, and Role-Based Access Control (RBAC) are implemented.

## 2. Core User Authentication Workflows

### 2.1 User Registration (FR-AUTH-001)

**Goal**: Create a new user account, hash the password, and initiate email verification.

**Actors**: Unauthenticated User, Auth Service, Account Service, Notification Service, Database (PostgreSQL), Kafka.

**Workflow**:
1.  **Client Request**: User submits registration data (username, email, password, display_name) via REST API `POST /register`.
2.  **Input Validation (Auth Service)**:
    *   Validate format of email and username.
    *   Validate password complexity (min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char).
    *   Check for uniqueness of username and email by querying its own user table (or potentially a direct check/eventual consistency with Account Service, though V2 implies Auth Service's DB holds this for auth purposes).
3.  **Password Hashing (Auth Service)**:
    *   Generate a unique salt.
    *   Hash the provided password using **Argon2id** (time=1, memory=64MB, threads=4, keyLength=32, saltLength=16) with the generated salt.
4.  **User Record Creation (Auth Service)**:
    *   Create a new user record in the `users` table (PostgreSQL) with:
        *   `id` (UUID).
        *   `username`, `email`, `password_hash`, `salt`.
        *   `status` set to `pending_verification`.
        *   `display_name`.
        *   Timestamps (`created_at`, `updated_at`).
    *   Assign default role (e.g., "user") in `user_roles` table.
5.  **Email Verification Token (Auth Service)**:
    *   Generate a unique, time-limited verification token.
    *   Store the token hash and its expiry in the `verification_codes` table, associated with the user ID and type `email_verification`.
6.  **Event Publishing (Auth Service)**:
    *   Publish an `auth.user.registered` event to Kafka. This event includes `user_id`, `email`, `username`, `display_name`.
        *   **Account Service** consumes this event to create the user's profile.
        *   **Notification Service** consumes this event (or a dedicated `auth.user.verification_required` event if preferred) to send a verification email.
7.  **Response to Client**:
    *   Return a success response (e.g., 201 Created) with basic user information and a message indicating that an email verification is required.

**Security Considerations**:
*   Rate limit registration attempts per IP to prevent abuse.
*   Use CAPTCHA if bot registrations become an issue.

### 2.2 Email Confirmation (FR-AUTH-009)

**Goal**: Verify a user's email address using a token.

**Actors**: User, Auth Service, Database (PostgreSQL), Kafka.

**Workflow**:
1.  **User Action**: User clicks the verification link in the email or submits the verification token via REST API `POST /verify-email`.
2.  **Token Validation (Auth Service)**:
    *   Retrieve the verification token from the request.
    *   Find the corresponding record in the `verification_codes` table by token hash.
    *   Check if the token exists, is not expired, and has not been used.
3.  **User Status Update (Auth Service)**:
    *   If the token is valid:
        *   Update the user's status in the `users` table to `active`.
        *   Set `email_verified_at` timestamp.
        *   Mark the verification token as used or delete it from `verification_codes`.
4.  **Event Publishing (Auth Service)**:
    *   Publish an `auth.user.email_verified` event to Kafka, including `user_id` and `email`.
5.  **Response to Client**:
    *   Return a success message.
    *   If login is pending verification, the user might be automatically logged in or redirected to login.

### 2.3 User Login (Email/Username and Password) (FR-AUTH-002)

**Goal**: Authenticate a user with their credentials and issue JWTs.

**Actors**: User, Auth Service, Database (PostgreSQL), Redis (for session/rate limiting), Kafka.

**Workflow**:
1.  **Client Request**: User submits login credentials (login (username or email), password, device_info) via REST API `POST /login`.
2.  **Brute-Force Check (Auth Service)**:
    *   Check login attempt rates for the user account and IP address (using Redis or an in-memory store with distributed counters).
    *   If limits are exceeded, return `429 Too Many Requests`.
3.  **User Retrieval (Auth Service)**:
    *   Query the `users` table by username or email.
    *   If user not found, increment failure count for the login identifier/IP, return `401 Unauthorized`.
4.  **Status Check (Auth Service)**:
    *   Verify user `status` (must be `active`).
    *   If status is `pending_verification`, return `403 Forbidden` (email_not_verified).
    *   If status is `blocked`, return `403 Forbidden` (user_blocked).
5.  **Password Verification (Auth Service)**:
    *   Compare the provided password with the stored `password_hash` and `salt` using Argon2id.
    *   If password does not match, increment failure count for user account and IP, return `401 Unauthorized`.
6.  **Successful Password Verification**:
    *   Reset failed login attempt counters for the user account and IP.
    *   Update `last_login_at` timestamp for the user.
7.  **2FA Check (Auth Service)** (FR-AUTH-006):
    *   Check if 2FA is enabled for the user (from `mfa_secrets` table or a flag in `users` table).
    *   If 2FA is enabled:
        *   Generate a short-lived temporary token (JWT or opaque) containing `user_id` and an indicator that password auth was successful.
        *   Return a response indicating `2fa_required`, the `temp_token`, and available 2FA methods (e.g., `["totp", "sms"]`).
        *   **Proceed to 2FA Verification Workflow (2.4.2).**
8.  **Session and Token Generation (Auth Service)** (If 2FA is not enabled or already passed):
    *   Create a new session record in the `sessions` table (PostgreSQL), storing `user_id`, `ip_address`, `user_agent`, `device_info`, and an expiry time for the session (linked to refresh token expiry).
    *   Generate a new JWT Access Token (RS256, ~15 minutes TTL) containing `user_id`, `username`, `roles`, `permissions`, `session_id`.
    *   Generate a new opaque Refresh Token (long-lived, e.g., 30 days).
    *   Store a hash of the Refresh Token in the `refresh_tokens` table, linked to the session and user, with its own expiry.
9.  **Event Publishing (Auth Service)**:
    *   Publish `auth.user.login_success` event to Kafka with `user_id`, `ip_address`, `timestamp`.
    *   Publish `auth.session.created` event to Kafka with `session_id`, `user_id`, `ip_address`.
10. **Response to Client**:
    *   Return `200 OK` with Access Token, Refresh Token, token type ("Bearer"), access token `expires_in`, and basic user information.

### 2.4 Two-Factor Authentication (2FA) Workflows

#### 2.4.1 Enabling 2FA (TOTP Example) (FR-AUTH-006)

**Goal**: Allow a user to set up TOTP-based 2FA.

**Actors**: Authenticated User, Auth Service, Database (PostgreSQL).

**Workflow**:
1.  **Client Request**: User initiates 2FA setup via REST API `POST /me/2fa/totp/enable`.
2.  **Secret Generation (Auth Service)**:
    *   Generate a new TOTP secret key (e.g., 160-bit random string, base32 encoded).
    *   Temporarily store this secret (e.g., in Redis or a short-lived table) associated with the `user_id` and an "unverified" status, awaiting user confirmation.
3.  **QR Code Generation (Auth Service)**:
    *   Generate a provisioning URI (e.g., `otpauth://totp/PlatformName:username?secret=BASE32_SECRET&issuer=PlatformName`).
    *   Generate a QR code image from this URI.
4.  **Response to Client**:
    *   Return the base32 secret key (for manual entry) and the QR code image (as a data URL).

#### 2.4.2 Verifying and Activating 2FA (TOTP Example) (FR-AUTH-006)

**Goal**: User confirms TOTP setup by providing a valid code.

**Actors**: Authenticated User, Auth Service, Database (PostgreSQL).

**Workflow**:
1.  **Client Request**: User submits a TOTP code (e.g., 6 digits) obtained from their authenticator app via REST API `POST /me/2fa/totp/verify`, along with their current session's access token.
2.  **Code Verification (Auth Service)**:
    *   Retrieve the temporary TOTP secret for the `user_id` (from Redis/temporary store).
    *   Validate the submitted TOTP code against the secret, considering the current time window and potentially adjacent windows.
3.  **Activation (Auth Service)**:
    *   If the code is valid:
        *   Permanently and securely store the encrypted TOTP secret in the `mfa_secrets` table for the user, marking it as `verified`.
        *   Generate a set of one-time backup codes. Securely store hashes of these backup codes in the `mfa_backup_codes` table.
        *   Update user's record or flag to indicate 2FA is enabled.
        *   Remove the temporary unverified secret.
4.  **Response to Client**:
    *   Return a success message and the generated backup codes (displayed only once).

#### 2.4.3 Login with 2FA (FR-AUTH-006)

**Goal**: Complete login for a user with 2FA enabled.

**Actors**: User, Auth Service, Database (PostgreSQL), Redis.

**Workflow**:
1.  **Initial Login**: User completes password authentication successfully (Workflow 2.3, steps 1-7). Auth Service returns `2fa_required` status and a `temp_token`.
2.  **Client Request**: User submits their 2FA code (e.g., TOTP from app, code from SMS) along with the `temp_token` via REST API `POST /login/2fa/verify`. Request includes `method` (e.g., "totp", "sms", "backup_code") and `code`.
3.  **Temp Token Validation (Auth Service)**:
    *   Validate the `temp_token` (check signature, expiry, purpose). Extract `user_id`.
4.  **2FA Code Verification (Auth Service)**:
    *   Based on the `method`:
        *   **TOTP**: Retrieve user's `mfa_secret` (encrypted) from `mfa_secrets`, decrypt it, and validate the submitted TOTP code.
        *   **SMS/Email**: Retrieve expected code from temporary storage (e.g., Redis, associated with `temp_token` or `user_id`), compare with submitted code.
        *   **Backup Code**: Check submitted code against stored hashes in `mfa_backup_codes`. If valid, mark the backup code as used.
    *   If code is invalid, increment 2FA failure counter, return `401 Unauthorized`.
5.  **Session and Token Generation (Auth Service)**:
    *   If 2FA code is valid, proceed same as step 8 in Workflow 2.3 (create session, generate Access/Refresh JWTs).
6.  **Event Publishing & Response**: Proceed same as steps 9-10 in Workflow 2.3.

#### 2.4.4 Disabling 2FA (FR-AUTH-006)

**Goal**: User disables an active 2FA method.

**Actors**: Authenticated User, Auth Service, Database (PostgreSQL).

**Workflow**:
1.  **Client Request**: User initiates 2FA disable via REST API `POST /me/2fa/disable`. Request must include current password or a valid 2FA code for confirmation.
2.  **Confirmation (Auth Service)**:
    *   Verify the provided password or 2FA code.
3.  **Deactivation (Auth Service)**:
    *   If confirmation is successful:
        *   Remove/deactivate the relevant records from `mfa_secrets`.
        *   Delete any active `mfa_backup_codes`.
        *   Update user's record/flag to indicate 2FA is disabled.
4.  **Response to Client**: Return success message.

## 3. Token Management (FR-AUTH-003, FR-AUTH-005)

### 3.1 JWT Access Token Generation

*   **Algorithm**: RS256 (RSA Signature with SHA-256).
*   **Keys**: Auth Service uses a private key for signing. The corresponding public key is made available via a JWKS endpoint (`GET /api/v1/auth/.well-known/jwks.json` or gRPC `GetJWKS`).
*   **Payload (Claims)**:
    *   `iss` (Issuer): Auth Service identifier (e.g., "auth.yourplatform.ru").
    *   `sub` (Subject): User ID (UUID).
    *   `aud` (Audience): Intended audience (e.g., "api.yourplatform.ru", or specific service identifiers).
    *   `exp` (Expiration Time): Timestamp (e.g., 15 minutes from issuance).
    *   `nbf` (Not Before): Timestamp (usually same as `iat`).
    *   `iat` (Issued At): Timestamp.
    *   `jti` (JWT ID): Unique token identifier.
    *   `username` (string): User's username.
    *   `roles` (array of strings): User's assigned roles.
    *   `permissions` (array of strings): Effective permissions of the user.
    *   `session_id` (UUID): Identifier of the user's current session.
*   **TTL**: 15 minutes (configurable).

### 3.2 Refresh Token Generation and Management

*   **Format**: Cryptographically strong random opaque string.
*   **Storage**:
    *   A hash (e.g., SHA256) of the refresh token is stored in the `refresh_tokens` table in PostgreSQL.
    *   Associated with `user_id`, `session_id`, `expires_at`, `revoked_at`, `ip_address`, `user_agent`.
*   **TTL**: 30 days (configurable).
*   **Rotation**: When a refresh token is used to obtain a new access token, the used refresh token is invalidated/revoked, and a new refresh token is issued alongside the new access token. This helps mitigate the risk of leaked refresh tokens.
*   **Revocation**:
    *   Individual refresh tokens can be revoked (e.g., user logs out a specific session).
    *   All refresh tokens for a user can be revoked (e.g., "logout from all devices", password change).
    *   Revoked token hashes are marked in the `refresh_tokens` table or moved to a separate blacklist.

### 3.3 Access Token Refresh Workflow

1.  **Client Request**: Client sends `POST /refresh-token` with the current `refresh_token`.
2.  **Validation (Auth Service)**:
    *   Hash the received refresh token.
    *   Look up the hash in the `refresh_tokens` table.
    *   Check if found, not expired, and not revoked.
3.  **Token Generation (Auth Service)**:
    *   If valid, retrieve associated `user_id` and `session_id`.
    *   Fetch user roles and permissions.
    *   Generate a new JWT Access Token.
    *   Generate a new Refresh Token.
    *   Update the `refresh_tokens` table: mark the old token hash as used/revoked and store the hash of the new refresh token with a new expiry.
4.  **Response to Client**: Return the new Access Token and new Refresh Token.

### 3.4 Token Validation (by API Gateway or other services)

1.  **Request**: Service calls gRPC `ValidateToken` with the Access Token.
2.  **Signature Verification (Auth Service)**: Verify JWT signature using the public key.
3.  **Claims Validation (Auth Service)**: Check `exp`, `nbf`, `iss`, `aud`.
4.  **Revocation Check (Auth Service)**: Optionally, check if the token `jti` or associated `session_id` is in a revocation list (e.g., in Redis, if a user has logged out or changed password recently).
5.  **Response**: Return validation result and claims.

## 4. External Authentication (OAuth 2.0 / OIDC) (FR-AUTH-007)

**Providers**: Telegram, ВКонтакте (VK), Одноклассники.

**General OAuth 2.0 Authorization Code Flow**:
1.  **Client Request**: User clicks "Login with [Provider]" button. Frontend calls `GET /oauth/{provider}`.
2.  **Redirect to Provider (Auth Service)**: Auth Service constructs the provider's authorization URL (with `client_id`, `redirect_uri`, `scope`, `state`) and redirects the user's browser to it.
3.  **User Authentication at Provider**: User authenticates with the provider and grants permission.
4.  **Provider Callback**: Provider redirects user back to Auth Service's `redirect_uri` (`GET /oauth/{provider}/callback`) with an `authorization_code` and the `state`.
5.  **Code Exchange (Auth Service)**:
    *   Verify `state` parameter to prevent CSRF.
    *   Exchange `authorization_code` for provider's access token and ID token (if OIDC) by calling the provider's token endpoint.
6.  **Fetch User Info (Auth Service)**: Use provider's access token to fetch user profile information from the provider's user info endpoint.
7.  **Account Linking/Creation (Auth Service)**:
    *   Check if a user with this external provider ID already exists in `external_accounts`.
    *   If yes, log in that user.
    *   If no, check if the email from provider matches an existing local account. If yes, offer to link.
    *   If no existing account, create a new user in `users` table (status `active`, email may or may not be verified depending on provider data) and a new record in `external_accounts`. Publish `auth.user.registered`.
8.  **Session and Token Generation (Auth Service)**: Generate platform's Access and Refresh tokens for the user (as in Workflow 2.3).
9.  **Response/Redirect to Client**: Return tokens to client or redirect to frontend with tokens.

**Telegram Login Specifics**:
*   Uses data received directly from Telegram Login Widget (`POST /telegram-login`).
*   Auth Service verifies the `hash` parameter against the Telegram Bot Token.
*   Checks `auth_date` to prevent replay attacks.
*   Proceeds with account linking/creation based on Telegram User ID.

## 5. API Key Management (FR-AUTH-013)

**Goal**: Allow users (typically developers) or services to generate and manage API keys for programmatic access.

**Workflow**:
1.  **Client Request (User)**: User requests to create an API key via `POST /me/api-keys`, providing a name and desired permissions/scopes.
2.  **Generation (Auth Service)**:
    *   Generate a cryptographically strong API key string (e.g., prefix + random part).
    *   Store a hash (e.g., SHA256) of the API key in the `api_keys` table, along with `user_id`, `name`, `key_prefix`, `permissions`, `expires_at`.
3.  **Response to Client**: Return the full API key string **once**. The user must copy and store it securely. Also return key ID, prefix, name, permissions.
4.  **Authentication with API Key**:
    *   Client includes API key in a request header (e.g., `X-API-Key: <api_key_string>`).
    *   API Gateway (or service) extracts the key.
    *   The prefix is used to quickly identify the key type.
    *   Auth Service (or a local cache in API Gateway) looks up the key hash. If found, not expired, and not revoked, authentication is successful. Permissions associated with the key are then used for authorization.
5.  **Listing/Revocation**:
    *   `GET /me/api-keys`: Lists metadata of keys (ID, name, prefix, permissions, expiry), not the secret key itself.
    *   `DELETE /me/api-keys/{key_id}`: Marks the API key as revoked in the database.

## 6. Role-Based Access Control (RBAC) (FR-AUTH-010)

*   **Definitions**:
    *   `roles` table: Defines roles (e.g., "user", "admin", "developer").
    *   `permissions` table: Defines granular permissions (e.g., "game:create", "user:list").
    *   `role_permissions` table: Maps permissions to roles.
    *   `user_roles` table: Assigns roles to users.
*   **Token Enrichment**: When generating an Access Token, Auth Service fetches the user's roles from `user_roles` and then resolves all associated permissions from `role_permissions` and `permissions`. These roles and permissions are included in the JWT claims.
*   **Permission Checking**:
    *   **API Gateway**: Can perform coarse-grained checks based on roles present in the token for specific routes.
    *   **Microservices**: Can call Auth Service's `CheckPermission` gRPC endpoint or validate permissions locally if they have the JWT and the public key. The `CheckPermission` endpoint in Auth Service would look up the user's effective permissions.
*   **Management**: Admin users can manage roles, permissions, and user role assignments via admin endpoints (e.g., `PUT /admin/users/{user_id}/roles`).

## 7. Audit Logging (FR-AUTH-012)

*   **Events Logged**: All critical security events are logged into the `audit_logs` table.
    *   Successful and failed login attempts (including source IP, user agent).
    *   Logout events.
    *   Password change, password reset requests, successful password resets.
    *   2FA enablement, verification, disablement.
    *   Session creation, revocation.
    *   API key creation, revocation.
    *   Role/permission changes for users (by admins).
    *   Administrative actions (user blocking/unblocking).
*   **Log Content**: Timestamp, actor user ID (or system if automated), action type, target user ID/resource ID, source IP, user agent, status (success/failure), relevant details (JSONB).
*   **Access**: Admin users can view audit logs via `GET /admin/audit-logs`.

## 8. Suspicious Activity Detection & Blocking (FR-AUTH-014)

*   **Failed Login Attempts**:
    *   Track failed login attempts per account and per IP address (e.g., in Redis with TTL).
    *   After N failed attempts (e.g., 5) from an IP or for an account within a short time window (e.g., 15 minutes), temporarily block further login attempts from that IP/for that account. Block duration can increase exponentially.
    *   Publish `auth.user.account_locked` event.
*   **Unusual Login Location/Device (Future Enhancement)**:
    *   Maintain a history of typical login IPs/device fingerprints for users.
    *   If a login occurs from a significantly different location or new device, flag it.
    *   May trigger a notification to the user (via Notification Service) or require additional verification (e.g., email code, 2FA re-challenge).

---
*This service logic document outlines the primary workflows. Each workflow would be further expanded with more detailed sequence diagrams, error handling specifics, and edge cases in a fully fleshed-out specification.*
