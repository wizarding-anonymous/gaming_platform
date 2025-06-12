-- File: backend/services/auth-service/migrations/000002_seed_initial_data.down.sql

-- Удаление всех связей ролей и разрешений
DELETE FROM role_permissions;

-- Удаление всех разрешений
DELETE FROM permissions;

-- Удаление всех ролей
DELETE FROM roles;
