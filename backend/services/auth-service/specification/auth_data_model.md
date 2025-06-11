<!-- File: backend/services/auth-service/specification_final/auth_data_model.md -->
# Auth Service: Data Model and Database Schema

**Version:** 1.0
**Date:** 2023-10-27

## 1. Introduction

This document specifies the data models and database schema for the Auth Service. The primary database is PostgreSQL, used for persistent storage of user credentials, roles, sessions, and other authentication-related data. Redis is used for caching and storing temporary data like OTPs or rate-limiting counters.

## 2. PostgreSQL Schema

The following SQL DDL defines the tables, columns, relationships, and constraints for the Auth Service in PostgreSQL. UUIDs are used as primary keys for most entities. Timestamps are stored with time zones.

```sql
-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users Table: Core user authentication information
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) NOT NULL UNIQUE, -- Login username
    email VARCHAR(255) NOT NULL UNIQUE,    -- Primary email for login and communication
    password_hash VARCHAR(255) NOT NULL,   -- Hashed password (Argon2id)
    salt VARCHAR(128) NOT NULL,            -- Salt used for password hashing
    status VARCHAR(50) NOT NULL DEFAULT 'pending_verification' CHECK (status IN ('active', 'inactive', 'blocked', 'pending_verification', 'deleted')), -- User account status
    email_verified_at TIMESTAMPTZ,         -- Timestamp of email verification
    last_login_at TIMESTAMPTZ,             -- Timestamp of the last successful login
    failed_login_attempts INT NOT NULL DEFAULT 0, -- Counter for failed login attempts
    lockout_until TIMESTAMPTZ,             -- Timestamp until which the account is locked out
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ                  -- For soft deletes
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);

-- Roles Table: Defines available roles in the system
CREATE TABLE roles (
    id VARCHAR(50) PRIMARY KEY, -- e.g., "user", "admin", "developer". Using VARCHAR for predefined, code-referenced roles.
    name VARCHAR(255) NOT NULL UNIQUE,             -- Human-readable name (e.g., "Пользователь", "Администратор")
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Permissions Table: Defines granular permissions
CREATE TABLE permissions (
    id VARCHAR(100) PRIMARY KEY, -- e.g., "users.read", "games.publish". Using VARCHAR for predefined permissions.
    name VARCHAR(255) NOT NULL UNIQUE,               -- Human-readable name (e.g., "Просмотр пользователей")
    description TEXT,
    resource VARCHAR(100),                          -- Optional: resource type this permission applies to (e.g., "user", "game")
    action VARCHAR(50),                             -- Optional: action this permission allows (e.g., "read", "create", "edit")
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Role_Permissions Table: Maps permissions to roles (Many-to-Many)
CREATE TABLE role_permissions (
    role_id VARCHAR(50) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- User_Roles Table: Assigns roles to users (Many-to-Many)
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id VARCHAR(50) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id), -- Optional: ID of the admin/system who assigned the role
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- Sessions Table: Tracks active user sessions
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- Session ID
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_info JSONB,                             -- Store structured device info (type, os, app_version, device_name)
    expires_at TIMESTAMPTZ NOT NULL,               -- Session expiry, usually aligned with refresh token expiry
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP -- Updated on token refresh or significant activity
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Refresh_Tokens Table: Stores refresh tokens associated with sessions
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,       -- SHA256 hash of the refresh token
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,                        -- Timestamp when token was revoked
    revoked_reason VARCHAR(100)                    -- Reason for revocation (e.g., "logout", "password_change", "stolen")
);

CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens(session_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- External_Accounts Table: Links platform accounts to external OAuth/OIDC providers
CREATE TABLE external_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,                 -- e.g., "telegram", "vk", "odnoklassniki"
    external_user_id VARCHAR(255) NOT NULL,        -- User ID from the external provider
    access_token_hash TEXT,                        -- Optional: Hash of the provider's access token (if needed for API calls)
    refresh_token_hash TEXT,                       -- Optional: Hash of the provider's refresh token
    token_expires_at TIMESTAMPTZ,                  -- Expiry of the provider's token
    profile_data JSONB,                            -- Raw profile data from the provider
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, external_user_id)
);

CREATE INDEX idx_external_accounts_user_id ON external_accounts(user_id);

-- MFA_Secrets Table: Stores secrets for Multi-Factor Authentication methods like TOTP
CREATE TABLE mfa_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('totp')), -- Currently only TOTP
    secret_key_encrypted TEXT NOT NULL,              -- TOTP secret, encrypted at application level
    verified BOOLEAN NOT NULL DEFAULT false,         -- True if this MFA method has been verified by the user
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_mfa_secrets_user_id_type ON mfa_secrets(user_id, type);

-- MFA_Backup_Codes Table: Stores backup codes for 2FA recovery
CREATE TABLE mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,                 -- SHA256 hash of the backup code
    used_at TIMESTAMPTZ,                           -- Timestamp when the code was used
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_mfa_backup_codes_user_id ON mfa_backup_codes(user_id);
CREATE UNIQUE INDEX idx_mfa_backup_codes_user_id_code_hash ON mfa_backup_codes(user_id, code_hash);


-- API_Keys Table: Stores API keys for developers or services
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- User who owns this API key
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL UNIQUE,        -- A short, unique, non-secret prefix to help identify the key (e.g., "pltfrm_pk_")
    key_hash VARCHAR(255) NOT NULL,                -- SHA256 hash of the API key's secret part
    permissions JSONB,                             -- Array of permission strings associated with this key
    expires_at TIMESTAMPTZ,                        -- Optional expiry for the key
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);

-- Audit_Logs Table: Records security-sensitive actions
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,                        -- Using BIGSERIAL for high-frequency writes
    user_id UUID REFERENCES users(id) ON DELETE SET NULL, -- Actor performing the action (null if system action)
    action VARCHAR(100) NOT NULL,                  -- e.g., "login_success", "password_change", "role_assigned"
    target_type VARCHAR(100),                      -- Optional: type of the entity being acted upon (e.g., "user", "session")
    target_id VARCHAR(255),                        -- Optional: ID of the entity being acted upon
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'success' CHECK (status IN ('success', 'failure')),
    details JSONB,                                 -- Additional context-specific details of the event
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_target_type_target_id ON audit_logs(target_type, target_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);

-- Verification_Codes Table: Stores temporary codes (email verification, password reset)
CREATE TABLE verification_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('email_verification', 'password_reset', 'mfa_device_verification')),
    code_hash VARCHAR(255) NOT NULL,                 -- SHA256 hash of the verification code
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMPTZ                            -- Timestamp when the code was used
);

CREATE INDEX idx_verification_codes_user_id_type ON verification_codes(user_id, type);
CREATE INDEX idx_verification_codes_expires_at ON verification_codes(expires_at);
CREATE INDEX idx_verification_codes_code_hash_type ON verification_codes(code_hash, type); -- For quick lookup

-- Function to update 'updated_at' timestamp
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply the trigger to relevant tables
CREATE TRIGGER set_timestamp_users
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TRIGGER set_timestamp_roles
BEFORE UPDATE ON roles
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TRIGGER set_timestamp_permissions
BEFORE UPDATE ON permissions
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TRIGGER set_timestamp_sessions
BEFORE UPDATE ON sessions
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TRIGGER set_timestamp_external_accounts
BEFORE UPDATE ON external_accounts
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TRIGGER set_timestamp_mfa_secrets
BEFORE UPDATE ON mfa_secrets
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TRIGGER set_timestamp_api_keys
BEFORE UPDATE ON api_keys
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

```

**Initial Data for Roles and Permissions (Examples):**
```sql
-- Basic Roles
INSERT INTO roles (id, name, description) VALUES
('user', 'Пользователь', 'Стандартный пользователь платформы'),
('admin', 'Администратор', 'Администратор платформы с полными правами'),
('developer', 'Разработчик', 'Разработчик игр'),
('service', 'Сервис', 'Внутренний системный сервис');

-- Basic Permissions
INSERT INTO permissions (id, name, description, resource, action) VALUES
('auth.users.read.self', 'Просмотр своего профиля', 'auth_user', 'read_self'),
('auth.users.edit.self', 'Редактирование своего профиля', 'auth_user', 'edit_self'),
('auth.admin.users.list', 'Просмотр списка всех пользователей', 'auth_user', 'list_all'),
('auth.admin.users.edit', 'Редактирование любого пользователя', 'auth_user', 'edit_any'),
('auth.admin.roles.manage', 'Управление ролями и разрешениями', 'auth_role', 'manage');

-- Assign permissions to roles
INSERT INTO role_permissions (role_id, permission_id) VALUES
-- User permissions
('user', 'auth.users.read.self'),
('user', 'auth.users.edit.self'),
('user', 'auth.2fa.manage'),        -- Manage their own 2FA settings
('user', 'auth.sessions.view'),     -- View their own active sessions
('user', 'auth.sessions.manage'),   -- Manage their own sessions (e.g., logout)
('user', 'auth.api_keys.view'),     -- View their own API keys
('user', 'auth.api_keys.manage'),   -- Manage their own API keys (create, delete)

-- Developer permissions (inherits user)
('developer', 'auth.api_keys.manage'), -- Developers specifically need to manage API keys for their tools/games

-- Moderator permissions (inherits user, specific moderation permissions would be in other services)
('moderator', 'auth.admin.users.view'), -- Moderators might need to view user details for context

-- Support permissions (inherits user)
('support', 'auth.admin.users.view'),          -- View user details
('support', 'auth.admin.users.edit_status'), -- Potentially change user status (e.g. unlock account after verification)
('support', 'auth.admin.sessions.manage'),   -- Manage user sessions for support reasons

-- Admin permissions
('admin', 'auth.admin.users.list'),
('admin', 'auth.admin.users.edit'),
('admin', 'auth.admin.users.block'),
('admin', 'auth.admin.roles.manage'),
('admin', 'auth.admin.permissions.manage'),
('admin', 'auth.audit.view'),
('admin', 'auth.admin.sessions.manage_all'), -- Manage any user's sessions

-- Service permissions (for inter-service communication, if a service needs to act on auth data)
('service', 'auth.users.read.self'); -- Example: A service might need to read its own service account's limited info.
-- Note: This is a representative list. A full matrix would be derived from "Единый реестр ролей пользователей и матрица доступа.txt"
-- and specific operational needs of each role concerning authentication data.
-- The permissions like 'catalog.games.create' are defined and managed by their respective services (e.g., Catalog Service),
-- Auth Service primarily stores the roles and the general permissions structure.
-- The JWT token will carry the roles, and resource servers will typically validate permissions based on these roles against their own policies.
```

## 3. Redis Data Structures

Redis is used for:

1.  **Session Caching (Optional)**:
    *   **Key**: `session:<session_id>`
    *   **Value**: JSON string or Hash containing session details (user_id, roles, expiry).
    *   **TTL**: Matches session expiry.
    *   *Note: Primary session state is in PostgreSQL (`sessions` table); Redis is for fast lookups.*

2.  **Rate Limiting Counters**:
    *   **Key**: `ratelimit:<action>:<identifier>` (e.g., `ratelimit:login_attempt:user_id:123`, `ratelimit:login_attempt:ip:1.2.3.4`).
    *   **Value**: Integer counter.
    *   **Type**: String (used with INCR).
    *   **TTL**: Sliding window (e.g., 1 minute, 15 minutes).

3.  **Temporary Tokens/Codes**:
    *   **Email Verification Codes**:
        *   **Key**: `verify_email_token:<token_hash>`
        *   **Value**: `user_id`
        *   **TTL**: Configurable (e.g., 24 hours).
    *   **Password Reset Tokens**:
        *   **Key**: `reset_password_token:<token_hash>`
        *   **Value**: `user_id`
        *   **TTL**: Configurable (e.g., 1 hour).
    *   **2FA Temporary Tokens (for login sequence)**:
        *   **Key**: `2fa_temp_token:<token_value>`
        *   **Value**: `user_id` and indication of first factor success.
        *   **TTL**: Configurable (e.g., 5 minutes).

4.  **Token Revocation List (Blacklist - if used for Access Tokens)**:
    *   **Key**: `token_blacklist_jti:<jti>` (JWT ID)
    *   **Value**: `1` or expiry timestamp of original token.
    *   **Type**: String.
    *   **TTL**: Should be set to the remaining validity of the token to auto-clean.
    *   *Note: More commonly, refresh token revocation is handled in PostgreSQL. Access token revocation is complex with JWTs; short expiry is the primary mitigation.*

## 4. Data Flow Diagrams (Conceptual)

*(These would typically be visual diagrams. Here's a textual description.)*

### 4.1 User Registration Data Flow:
1.  Client -> API (username, email, password)
2.  Auth Service:
    *   Validates input.
    *   Hashes password (Argon2id) -> `password_hash`, `salt`.
    *   Stores in `users` table (status `pending_verification`).
    *   Assigns default role in `user_roles`.
    *   Generates email verification code -> stores hash in `verification_codes`.
    *   Publishes `auth.user.registered` event (Kafka).
3.  Account Service (consumes event) -> Creates user profile.
4.  Notification Service (consumes event) -> Sends verification email.

### 4.2 User Login Data Flow:
1.  Client -> API (login_identifier, password, device_info)
2.  Auth Service:
    *   Checks rate limits (Redis).
    *   Retrieves user from `users` table.
    *   Verifies password against `password_hash` and `salt`.
    *   If 2FA enabled:
        *   Generates temp 2FA token.
        *   Returns 2FA required status.
        *   (Separate flow for 2FA code verification)
    *   If 2FA not enabled / passed:
        *   Creates session in `sessions` table.
        *   Generates Access & Refresh JWTs.
        *   Stores Refresh Token hash in `refresh_tokens` table.
        *   Updates `last_login_at` in `users`.
        *   Logs to `audit_logs`.
        *   Publishes `auth.user.login_success`, `auth.session.created` (Kafka).
        *   Returns tokens to client.

---
*This data model specification outlines the persistent and transient data structures. The SQL DDL provides the source of truth for the relational database, while Redis structures are described conceptually.*
