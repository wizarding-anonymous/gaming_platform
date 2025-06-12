// File: backend/services/auth-service/migrations/000003_add_user_roles.down.sql

-- Удаление триггеров
DROP TRIGGER IF EXISTS trigger_audit_user_roles ON user_roles;
DROP TRIGGER IF EXISTS trigger_update_user_roles_updated_at ON user_roles;

-- Удаление функций
DROP FUNCTION IF EXISTS audit_user_roles();
DROP FUNCTION IF EXISTS update_user_roles_updated_at();

-- Удаление таблиц
DROP TABLE IF EXISTS user_roles_audit;
DROP TABLE IF EXISTS user_roles;
