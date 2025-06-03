// File: migrations/000004_add_role_permissions.up.sql

-- Добавление разрешений для ролей
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(role_id, permission_id)
);

-- Индексы для быстрого поиска
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission_id ON role_permissions(permission_id);

-- Триггер для автоматического обновления updated_at
CREATE OR REPLACE FUNCTION update_role_permissions_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_role_permissions_updated_at
BEFORE UPDATE ON role_permissions
FOR EACH ROW
EXECUTE FUNCTION update_role_permissions_updated_at();

-- Добавление аудита для role_permissions
CREATE TABLE IF NOT EXISTS role_permissions_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_permission_id UUID NOT NULL,
    role_id UUID NOT NULL,
    permission_id UUID NOT NULL,
    action VARCHAR(10) NOT NULL,
    action_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    action_by UUID,
    old_data JSONB,
    new_data JSONB
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_audit_role_permission_id ON role_permissions_audit(role_permission_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_audit_role_id ON role_permissions_audit(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_audit_action_timestamp ON role_permissions_audit(action_timestamp);

-- Триггер для аудита role_permissions
CREATE OR REPLACE FUNCTION audit_role_permissions()
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

    INSERT INTO role_permissions_audit (
        role_permission_id,
        role_id,
        permission_id,
        action,
        action_timestamp,
        old_data,
        new_data
    ) VALUES (
        CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.role_id ELSE NEW.role_id END,
        CASE WHEN TG_OP = 'DELETE' THEN OLD.permission_id ELSE NEW.permission_id END,
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

CREATE TRIGGER trigger_audit_role_permissions
AFTER INSERT OR UPDATE OR DELETE ON role_permissions
FOR EACH ROW
EXECUTE FUNCTION audit_role_permissions();

-- Комментарии к таблицам и столбцам
COMMENT ON TABLE role_permissions IS 'Связь между ролями и разрешениями';
COMMENT ON COLUMN role_permissions.id IS 'Уникальный идентификатор связи роли и разрешения';
COMMENT ON COLUMN role_permissions.role_id IS 'Идентификатор роли';
COMMENT ON COLUMN role_permissions.permission_id IS 'Идентификатор разрешения';
COMMENT ON COLUMN role_permissions.created_at IS 'Дата и время создания связи';
COMMENT ON COLUMN role_permissions.updated_at IS 'Дата и время последнего обновления связи';

COMMENT ON TABLE role_permissions_audit IS 'Аудит изменений связей ролей и разрешений';
COMMENT ON COLUMN role_permissions_audit.id IS 'Уникальный идентификатор записи аудита';
COMMENT ON COLUMN role_permissions_audit.role_permission_id IS 'Идентификатор связи роли и разрешения';
COMMENT ON COLUMN role_permissions_audit.role_id IS 'Идентификатор роли';
COMMENT ON COLUMN role_permissions_audit.permission_id IS 'Идентификатор разрешения';
COMMENT ON COLUMN role_permissions_audit.action IS 'Тип действия (INSERT, UPDATE, DELETE)';
COMMENT ON COLUMN role_permissions_audit.action_timestamp IS 'Дата и время действия';
COMMENT ON COLUMN role_permissions_audit.action_by IS 'Идентификатор пользователя, выполнившего действие';
COMMENT ON COLUMN role_permissions_audit.old_data IS 'Старые данные (до изменения)';
COMMENT ON COLUMN role_permissions_audit.new_data IS 'Новые данные (после изменения)';
