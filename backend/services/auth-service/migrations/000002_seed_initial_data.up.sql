// File: backend/services/auth-service/migrations/000002_seed_initial_data.up.sql

-- Создание базовых ролей
INSERT INTO roles (id, name, description, created_at, updated_at)
VALUES 
    (uuid_generate_v4(), 'admin', 'Администратор системы с полным доступом', NOW(), NOW()),
    (uuid_generate_v4(), 'user', 'Обычный пользователь с базовыми правами', NOW(), NOW()),
    (uuid_generate_v4(), 'moderator', 'Модератор с расширенными правами', NOW(), NOW()),
    (uuid_generate_v4(), 'developer', 'Разработчик игр с доступом к инструментам разработки', NOW(), NOW());

-- Создание базовых разрешений
INSERT INTO permissions (id, name, description, created_at, updated_at)
VALUES 
    (uuid_generate_v4(), 'user:read', 'Просмотр информации о пользователях', NOW(), NOW()),
    (uuid_generate_v4(), 'user:write', 'Изменение информации о пользователях', NOW(), NOW()),
    (uuid_generate_v4(), 'user:delete', 'Удаление пользователей', NOW(), NOW()),
    (uuid_generate_v4(), 'role:read', 'Просмотр ролей', NOW(), NOW()),
    (uuid_generate_v4(), 'role:write', 'Изменение ролей', NOW(), NOW()),
    (uuid_generate_v4(), 'role:delete', 'Удаление ролей', NOW(), NOW()),
    (uuid_generate_v4(), 'permission:read', 'Просмотр разрешений', NOW(), NOW()),
    (uuid_generate_v4(), 'permission:write', 'Изменение разрешений', NOW(), NOW()),
    (uuid_generate_v4(), 'permission:delete', 'Удаление разрешений', NOW(), NOW()),
    (uuid_generate_v4(), 'session:read', 'Просмотр сессий', NOW(), NOW()),
    (uuid_generate_v4(), 'session:write', 'Изменение сессий', NOW(), NOW()),
    (uuid_generate_v4(), 'session:delete', 'Удаление сессий', NOW(), NOW());

-- Назначение разрешений роли администратора
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT 
    r.id, 
    p.id, 
    NOW()
FROM 
    roles r, 
    permissions p
WHERE 
    r.name = 'admin';

-- Назначение базовых разрешений роли пользователя
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT 
    r.id, 
    p.id, 
    NOW()
FROM 
    roles r, 
    permissions p
WHERE 
    r.name = 'user' AND 
    p.name IN ('user:read', 'session:read');

-- Назначение разрешений роли модератора
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT 
    r.id, 
    p.id, 
    NOW()
FROM 
    roles r, 
    permissions p
WHERE 
    r.name = 'moderator' AND 
    p.name IN ('user:read', 'user:write', 'role:read', 'session:read', 'session:write');

-- Назначение разрешений роли разработчика
INSERT INTO role_permissions (role_id, permission_id, created_at)
SELECT 
    r.id, 
    p.id, 
    NOW()
FROM 
    roles r, 
    permissions p
WHERE 
    r.name = 'developer' AND 
    p.name IN ('user:read', 'session:read');
