-- File: backend/services/auth-service/migrations/000001_create_initial_tables.down.sql

-- Удаление таблицы кодов восстановления
DROP TABLE IF EXISTS recovery_codes;

-- Удаление таблицы сессий
DROP TABLE IF EXISTS sessions;

-- Удаление таблицы токенов
DROP TABLE IF EXISTS tokens;

-- Удаление таблицы связи ролей и разрешений
DROP TABLE IF EXISTS role_permissions;

-- Удаление таблицы связи пользователей и ролей
DROP TABLE IF EXISTS user_roles;

-- Удаление таблицы разрешений
DROP TABLE IF EXISTS permissions;

-- Удаление таблицы ролей
DROP TABLE IF EXISTS roles;

-- Удаление таблицы пользователей
DROP TABLE IF EXISTS users;

-- Удаление расширения uuid-ossp
DROP EXTENSION IF EXISTS "uuid-ossp";
