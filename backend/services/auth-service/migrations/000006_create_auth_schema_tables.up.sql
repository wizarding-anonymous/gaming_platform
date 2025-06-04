-- Migration to create tables based on the schema in auth_microservice_specification_final.md
-- This assumes a clean state for these specific tables or that prior conflicting migrations for these tables are handled.

-- Required extension for UUID generation if not already enabled
CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- Provides gen_random_uuid()

-- Trigger function for updated_at columns
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Пользователи (users)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255), -- Хеш пароля (Argon2id)
    status VARCHAR(50) NOT NULL DEFAULT 'pending_verification' CHECK (status IN ('active', 'inactive', 'blocked', 'pending_verification', 'deleted')),
    email_verified_at TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    lockout_until TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE -- Для мягкого удаления
);
CREATE INDEX idx_users_email_key ON users(email); -- Renamed from idx_users_email to avoid conflict if old table is altered not dropped
CREATE INDEX idx_users_status_key ON users(status); -- Renamed from idx_users_status
CREATE TRIGGER set_timestamp_users
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

-- Роли (roles)
CREATE TABLE roles (
    id VARCHAR(50) PRIMARY KEY, -- e.g., "user", "admin", "developer"
    name VARCHAR(255) NOT NULL UNIQUE, -- Локализованное имя роли
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);
CREATE TRIGGER set_timestamp_roles
BEFORE UPDATE ON roles
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

-- Разрешения (permissions)
CREATE TABLE permissions (
    id VARCHAR(100) PRIMARY KEY, -- e.g., "users.read", "games.publish"
    name VARCHAR(255) NOT NULL UNIQUE, -- Локализованное имя разрешения
    description TEXT,
    resource VARCHAR(100),
    action VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);
CREATE TRIGGER set_timestamp_permissions
BEFORE UPDATE ON permissions
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

-- Связь ролей и разрешений (role_permissions)
CREATE TABLE role_permissions (
    role_id VARCHAR(50) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- Связь пользователей и ролей (user_roles)
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id VARCHAR(50) NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id), -- Кто назначил роль
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

-- Сессии (sessions)
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_info JSONB, -- Информация об устройстве (ОС, браузер и т.д.)
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL, -- Время истечения сессии (соответствует Refresh Token)
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMP WITH TIME ZONE -- updated by application logic
);
CREATE INDEX idx_sessions_user_id_key ON sessions(user_id); -- Renamed
CREATE INDEX idx_sessions_expires_at_key ON sessions(expires_at); -- Renamed

-- Токены обновления (refresh_tokens)
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE, -- Хеш токена
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(100)
);
CREATE INDEX idx_refresh_tokens_session_id_key ON refresh_tokens(session_id); -- Renamed
CREATE INDEX idx_refresh_tokens_expires_at_key ON refresh_tokens(expires_at); -- Renamed

-- Внешние аккаунты (external_accounts)
CREATE TABLE external_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- Например, 'telegram', 'vk', 'google'
    external_user_id VARCHAR(255) NOT NULL, -- ID пользователя у провайдера
    access_token_hash TEXT, -- Хеш токена доступа провайдера (если нужно хранить)
    refresh_token_hash TEXT, -- Хеш токена обновления провайдера (если нужно хранить)
    token_expires_at TIMESTAMP WITH TIME ZONE,
    profile_data JSONB, -- Данные профиля от провайдера
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (provider, external_user_id)
);
CREATE INDEX idx_external_accounts_user_id_key ON external_accounts(user_id); -- Renamed
CREATE TRIGGER set_timestamp_external_accounts
BEFORE UPDATE ON external_accounts
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

-- MFA устройства/секреты (mfa_secrets)
CREATE TABLE mfa_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('totp')), -- Пока только TOTP
    secret_key_encrypted TEXT NOT NULL, -- Зашифрованный секретный ключ TOTP
    verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE
);
CREATE UNIQUE INDEX idx_mfa_secrets_user_id_type_key ON mfa_secrets(user_id, type); -- Renamed
CREATE TRIGGER set_timestamp_mfa_secrets
BEFORE UPDATE ON mfa_secrets
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

-- Резервные коды 2FA (mfa_backup_codes)
CREATE TABLE mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL, -- Хеш кода
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (user_id, code_hash)
);

-- API ключи (api_keys)
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(8) NOT NULL UNIQUE, -- Префикс для идентификации ключа
    key_hash VARCHAR(255) NOT NULL, -- Хеш самого ключа
    permissions JSONB, -- Разрешения, связанные с ключом (массив строк)
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX idx_api_keys_user_id_key ON api_keys(user_id); -- Renamed
CREATE TRIGGER set_timestamp_api_keys
BEFORE UPDATE ON api_keys
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

-- Журнал аудита (audit_logs)
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL, -- e.g., 'login', 'register', 'password_reset'
    target_type VARCHAR(100), -- e.g., 'user', 'session', 'role'
    target_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'success' CHECK (status IN ('success', 'failure')),
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_logs_user_id_key ON audit_logs(user_id); -- Renamed
CREATE INDEX idx_audit_logs_action_key ON audit_logs(action); -- Renamed
CREATE INDEX idx_audit_logs_created_at_key ON audit_logs(created_at); -- Renamed

-- Временные коды (verification_codes)
CREATE TABLE verification_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL CHECK (type IN ('email_verification', 'password_reset', 'mfa_device_verification')),
    code_hash VARCHAR(255) NOT NULL, -- Хеш кода
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX idx_verification_codes_user_id_type_key ON verification_codes(user_id, type); -- Renamed
CREATE INDEX idx_verification_codes_expires_at_key ON verification_codes(expires_at); -- Renamed

-- Note: Indexes from the specification are:
-- CREATE INDEX idx_users_email ON users(email); -> Renamed to idx_users_email_key
-- CREATE INDEX idx_users_status ON users(status); -> Renamed to idx_users_status_key
-- (No specific indexes listed for role_permissions, user_roles in spec, but they are good practice so kept from existing logic if applicable)
-- CREATE INDEX idx_sessions_user_id ON sessions(user_id); -> Renamed
-- CREATE INDEX idx_sessions_expires_at ON sessions(expires_at); -> Renamed
-- CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens(session_id); -> Renamed
-- CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at); -> Renamed
-- CREATE INDEX idx_external_accounts_user_id ON external_accounts(user_id); -> Renamed
-- CREATE UNIQUE INDEX idx_mfa_secrets_user_id_type ON mfa_secrets(user_id, type); -> Renamed
-- CREATE INDEX idx_api_keys_user_id ON api_keys(user_id); -> Renamed
-- CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id); -> Renamed
-- CREATE INDEX idx_audit_logs_action ON audit_logs(action); -> Renamed
-- CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at); -> Renamed
-- CREATE INDEX idx_verification_codes_user_id_type ON verification_codes(user_id, type); -> Renamed
-- CREATE INDEX idx_verification_codes_expires_at ON verification_codes(expires_at); -> Renamed
-- Renaming is to avoid collision if an alter-based strategy was chosen instead of drop/create for existing tables.
-- For a clean setup as per this migration, the original names from the spec would be fine.
-- I've used "_key" suffix for new indexes to distinguish them if this migration is applied to a DB
-- that might have remnants of the old schema's indexes. If it's a truly clean DB, this suffix isn't strictly needed.
-- The spec uses `gen_random_uuid()` which comes from `pgcrypto` extension.
-- The spec uses `CURRENT_TIMESTAMP` for `created_at` which is good.
-- The spec mentions `updated_at` for `roles`, `permissions`, `external_accounts`, `mfa_secrets`, `api_keys` and `users`.
-- Triggers are added for these. `sessions` table in spec has no `updated_at`.
-- `audit_logs` has no `updated_at`. `refresh_tokens` has no `updated_at`. `mfa_backup_codes` has no `updated_at`.
-- `verification_codes` has no `updated_at`. `user_roles` and `role_permissions` also do not have `updated_at`.
