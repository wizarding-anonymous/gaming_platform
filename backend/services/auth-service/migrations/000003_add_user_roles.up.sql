// File: backend/services/auth-service/migrations/000003_add_user_roles.up.sql

-- Добавление ролей пользователей
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, role_id)
);

-- Индексы для быстрого поиска
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);

-- Триггер для автоматического обновления updated_at
CREATE OR REPLACE FUNCTION update_user_roles_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_user_roles_updated_at
BEFORE UPDATE ON user_roles
FOR EACH ROW
EXECUTE FUNCTION update_user_roles_updated_at();

-- Добавление аудита для user_roles
CREATE TABLE IF NOT EXISTS user_roles_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_role_id UUID NOT NULL,
    user_id UUID NOT NULL,
    role_id UUID NOT NULL,
    action VARCHAR(10) NOT NULL,
    action_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    action_by UUID,
    old_data JSONB,
    new_data JSONB
);

CREATE INDEX IF NOT EXISTS idx_user_roles_audit_user_role_id ON user_roles_audit(user_role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_audit_user_id ON user_roles_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_audit_action_timestamp ON user_roles_audit(action_timestamp);

-- Триггер для аудита user_roles
CREATE OR REPLACE FUNCTION audit_user_roles()
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

    INSERT INTO user_roles_audit (
        user_role_id,
        user_id,
        role_id,
        action,
        action_timestamp,
        old_data,
        new_data
    ) VALUES (
        CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.role_id ELSE NEW.role_id END,
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

CREATE TRIGGER trigger_audit_user_roles
AFTER INSERT OR UPDATE OR DELETE ON user_roles
FOR EACH ROW
EXECUTE FUNCTION audit_user_roles();

-- Комментарии к таблицам и столбцам
COMMENT ON TABLE user_roles IS 'Связь между пользователями и ролями';
COMMENT ON COLUMN user_roles.id IS 'Уникальный идентификатор связи пользователя и роли';
COMMENT ON COLUMN user_roles.user_id IS 'Идентификатор пользователя';
COMMENT ON COLUMN user_roles.role_id IS 'Идентификатор роли';
COMMENT ON COLUMN user_roles.created_at IS 'Дата и время создания связи';
COMMENT ON COLUMN user_roles.updated_at IS 'Дата и время последнего обновления связи';

COMMENT ON TABLE user_roles_audit IS 'Аудит изменений связей пользователей и ролей';
COMMENT ON COLUMN user_roles_audit.id IS 'Уникальный идентификатор записи аудита';
COMMENT ON COLUMN user_roles_audit.user_role_id IS 'Идентификатор связи пользователя и роли';
COMMENT ON COLUMN user_roles_audit.user_id IS 'Идентификатор пользователя';
COMMENT ON COLUMN user_roles_audit.role_id IS 'Идентификатор роли';
COMMENT ON COLUMN user_roles_audit.action IS 'Тип действия (INSERT, UPDATE, DELETE)';
COMMENT ON COLUMN user_roles_audit.action_timestamp IS 'Дата и время действия';
COMMENT ON COLUMN user_roles_audit.action_by IS 'Идентификатор пользователя, выполнившего действие';
COMMENT ON COLUMN user_roles_audit.old_data IS 'Старые данные (до изменения)';
COMMENT ON COLUMN user_roles_audit.new_data IS 'Новые данные (после изменения)';
