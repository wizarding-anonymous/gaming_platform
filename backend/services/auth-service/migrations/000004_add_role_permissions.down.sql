// File: backend/services/auth-service/migrations/000004_add_role_permissions.down.sql

-- Удаление триггеров
DROP TRIGGER IF EXISTS trigger_audit_role_permissions ON role_permissions;
DROP TRIGGER IF EXISTS trigger_update_role_permissions_updated_at ON role_permissions;

-- Удаление функций
DROP FUNCTION IF EXISTS audit_role_permissions();
DROP FUNCTION IF EXISTS update_role_permissions_updated_at();

-- Удаление таблиц
DROP TABLE IF EXISTS role_permissions_audit;
DROP TABLE IF EXISTS role_permissions;
