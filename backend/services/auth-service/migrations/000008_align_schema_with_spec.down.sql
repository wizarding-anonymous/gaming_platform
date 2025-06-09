-- Migration to revert schema changes made by 000008_align_schema_with_spec.up.sql
-- This attempts to restore the schema to a state similar to after 000007 was applied.

BEGIN;

-- Revert 'users' table changes
-- Remove 'salt' column
ALTER TABLE users DROP COLUMN salt;

-- Make 'password_hash' nullable again (original state in 000006)
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Revert 'updated_at' to nullable and remove DEFAULT
ALTER TABLE users ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE users ALTER COLUMN updated_at DROP DEFAULT;

-- Drop added indexes from 'users' table
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_deleted_at;
-- If original indexes were dropped and renamed in UP, recreate them (example)
-- DROP INDEX IF EXISTS idx_users_email;
-- CREATE INDEX IF NOT EXISTS idx_users_email_key ON users(email); -- Assuming this was the name in 000006
-- DROP INDEX IF EXISTS idx_users_status;
-- CREATE INDEX IF NOT EXISTS idx_users_status_key ON users(status); -- Assuming this was the name in 000006

-- Add back columns removed from migration 000007
ALTER TABLE users ADD COLUMN IF NOT EXISTS status_reason TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_by TEXT;
COMMENT ON COLUMN users.status_reason IS 'Reason for the current status, e.g., reason for blocking.';
COMMENT ON COLUMN users.updated_by IS 'Identifier of the user or system that performed the last update on this record.';


-- Revert 'api_keys' table changes
-- Alter 'key_prefix' back to VARCHAR(8)
ALTER TABLE api_keys ALTER COLUMN key_prefix TYPE VARCHAR(8);

-- Revert 'updated_at' to nullable and remove DEFAULT
ALTER TABLE api_keys ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE api_keys ALTER COLUMN updated_at DROP DEFAULT;


-- Revert 'roles' table changes
-- Revert 'updated_at' to nullable and remove DEFAULT
ALTER TABLE roles ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE roles ALTER COLUMN updated_at DROP DEFAULT;


-- Revert 'permissions' table changes
-- Revert 'updated_at' to nullable and remove DEFAULT
ALTER TABLE permissions ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE permissions ALTER COLUMN updated_at DROP DEFAULT;


-- Revert 'external_accounts' table changes
-- Revert 'updated_at' to nullable and remove DEFAULT
ALTER TABLE external_accounts ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE external_accounts ALTER COLUMN updated_at DROP DEFAULT;


-- Revert 'mfa_secrets' table changes
-- Revert 'updated_at' to nullable and remove DEFAULT
ALTER TABLE mfa_secrets ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE mfa_secrets ALTER COLUMN updated_at DROP DEFAULT;


-- Revert 'sessions' table changes
-- Revert 'last_activity_at' to nullable and remove DEFAULT
ALTER TABLE sessions ALTER COLUMN last_activity_at DROP NOT NULL;
ALTER TABLE sessions ALTER COLUMN last_activity_at DROP DEFAULT;

-- Drop trigger from 'sessions'
DROP TRIGGER IF EXISTS set_timestamp_sessions ON sessions;

-- Drop 'updated_at' column from 'sessions' if it was added by the UP migration
ALTER TABLE sessions DROP COLUMN IF EXISTS updated_at;


-- Drop added indexes from 'user_roles' table
DROP INDEX IF EXISTS idx_user_roles_user_id;
DROP INDEX IF EXISTS idx_user_roles_role_id;


-- Drop added index from 'mfa_backup_codes' table
DROP INDEX IF EXISTS idx_mfa_backup_codes_user_id;


-- Revert 'audit_logs' table changes
-- Drop added index
DROP INDEX IF EXISTS idx_audit_logs_target_type_target_id;
-- Revert 'created_at' index to original from 000006 (if changed)
DROP INDEX IF EXISTS idx_audit_logs_created_at;
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at_key ON audit_logs(created_at); -- As defined in 000006


-- Revert 'verification_codes' table changes
-- Drop added index
DROP INDEX IF EXISTS idx_verification_codes_code_hash_type;

COMMIT;
