-- File: backend/services/auth-service/migrations/000006_create_auth_schema_tables.down.sql
-- Migration to drop tables created in 000006_create_auth_schema_tables.up.sql

-- Drop tables in reverse order of creation to respect foreign key constraints

DROP TABLE IF EXISTS verification_codes;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS mfa_backup_codes;
DROP TABLE IF EXISTS mfa_secrets;
DROP TABLE IF EXISTS external_accounts;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;

-- Drop the trigger function
DROP FUNCTION IF EXISTS trigger_set_timestamp();

-- Note: Dropping extensions like "pgcrypto" is usually not done in individual down migrations
-- as other parts of the system or other migrations might still need them.
-- It's typically handled separately if the entire database is being decommissioned.
-- CREATE EXTENSION IF NOT EXISTS "pgcrypto"; was in the up script.
