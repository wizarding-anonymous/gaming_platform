-- File: backend/services/auth-service/migrations/000005_add_sessions.up.sql

-- Создание таблицы сессий
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_id UUID,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT NOT NULL,
    device_info JSONB,
    location_info JSONB,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_activity_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID,
    revocation_reason TEXT
);

-- Индексы для быстрого поиска
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_id ON sessions(refresh_token_id);
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity_at ON sessions(last_activity_at);

-- Триггер для автоматического обновления last_activity_at
CREATE OR REPLACE FUNCTION update_sessions_last_activity_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_activity_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_sessions_last_activity_at
BEFORE UPDATE ON sessions
FOR EACH ROW
EXECUTE FUNCTION update_sessions_last_activity_at();

-- Добавление аудита для sessions
CREATE TABLE IF NOT EXISTS sessions_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL,
    user_id UUID NOT NULL,
    action VARCHAR(10) NOT NULL,
    action_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    action_by UUID,
    old_data JSONB,
    new_data JSONB
);

CREATE INDEX IF NOT EXISTS idx_sessions_audit_session_id ON sessions_audit(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_audit_user_id ON sessions_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_audit_action_timestamp ON sessions_audit(action_timestamp);

-- Триггер для аудита sessions
CREATE OR REPLACE FUNCTION audit_sessions()
RETURNS TRIGGER AS $$
DECLARE
    action_type VARCHAR(10);
    old_data_json JSONB := NULL;
    new_data_json JSONB := NULL;
BEGIN
    IF TG_OP = 'INSERT' THEN
        action_type := 'INSERT';
        new_data_json := row_to_json(NEW)::JSONB;
    ELSIF TG_OP = 'UPDATE' THEN
        action_type := 'UPDATE';
        old_data_json := row_to_json(OLD)::JSONB;
        new_data_json := row_to_json(NEW)::JSONB;
    ELSIF TG_OP = 'DELETE' THEN
        action_type := 'DELETE';
        old_data_json := row_to_json(OLD)::JSONB;
    END IF;

    INSERT INTO sessions_audit (
        session_id,
        user_id,
        action,
        action_timestamp,
        old_data,
        new_data
    ) VALUES (
        CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END,
        action_type,
        NOW(),
        old_data_json,
        new_data_json
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_audit_sessions
AFTER INSERT OR UPDATE OR DELETE ON sessions
FOR EACH ROW
EXECUTE FUNCTION audit_sessions();

-- Комментарии к таблицам и столбцам
COMMENT ON TABLE sessions IS 'Сессии пользователей';
COMMENT ON COLUMN sessions.id IS 'Уникальный идентификатор сессии';
COMMENT ON COLUMN sessions.user_id IS 'Идентификатор пользователя';
COMMENT ON COLUMN sessions.refresh_token_id IS 'Идентификатор токена обновления';
COMMENT ON COLUMN sessions.ip_address IS 'IP-адрес пользователя';
COMMENT ON COLUMN sessions.user_agent IS 'User-Agent пользователя';
COMMENT ON COLUMN sessions.device_info IS 'Информация об устройстве пользователя';
COMMENT ON COLUMN sessions.location_info IS 'Информация о местоположении пользователя';
COMMENT ON COLUMN sessions.is_active IS 'Флаг активности сессии';
COMMENT ON COLUMN sessions.last_activity_at IS 'Дата и время последней активности';
COMMENT ON COLUMN sessions.created_at IS 'Дата и время создания сессии';
COMMENT ON COLUMN sessions.expires_at IS 'Дата и время истечения сессии';
COMMENT ON COLUMN sessions.revoked_at IS 'Дата и время отзыва сессии';
COMMENT ON COLUMN sessions.revoked_by IS 'Идентификатор пользователя, отозвавшего сессию';
COMMENT ON COLUMN sessions.revocation_reason IS 'Причина отзыва сессии';

COMMENT ON TABLE sessions_audit IS 'Аудит изменений сессий';
COMMENT ON COLUMN sessions_audit.id IS 'Уникальный идентификатор записи аудита';
COMMENT ON COLUMN sessions_audit.session_id IS 'Идентификатор сессии';
COMMENT ON COLUMN sessions_audit.user_id IS 'Идентификатор пользователя';
COMMENT ON COLUMN sessions_audit.action IS 'Тип действия (INSERT, UPDATE, DELETE)';
COMMENT ON COLUMN sessions_audit.action_timestamp IS 'Дата и время действия';
COMMENT ON COLUMN sessions_audit.action_by IS 'Идентификатор пользователя, выполнившего действие';
COMMENT ON COLUMN sessions_audit.old_data IS 'Старые данные (до изменения)';
COMMENT ON COLUMN sessions_audit.new_data IS 'Новые данные (после изменения)';
