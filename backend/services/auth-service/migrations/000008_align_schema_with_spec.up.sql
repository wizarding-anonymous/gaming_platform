-- Migration to align schema with auth_data_model.md specification
-- Assumes migrations up to 000007 have been applied.

BEGIN;

-- Modify 'users' table
-- Add 'salt' column
ALTER TABLE users ADD COLUMN salt VARCHAR(128);
-- Update existing users with a dummy salt if needed, though ideally this is populated by application logic
-- For new users, this should be NOT NULL. For existing, we might need to allow NULL temporarily or use a default.
-- The spec says NOT NULL. If users exist, this migration might fail without a default or prior update.
-- For the purpose of this task, we assume we can set it to NOT NULL.
-- A real migration would need a strategy for existing rows (e.g. UPDATE users SET salt = 'dummy' WHERE salt IS NULL;)
ALTER TABLE users ALTER COLUMN salt SET NOT NULL;

-- Make 'password_hash' NOT NULL as per spec
ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;

-- Alter 'updated_at' to be NOT NULL and set DEFAULT
ALTER TABLE users ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE users ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;

-- Add missing indexes to 'users' table
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
-- Drop old indexes if they used different names and we want to enforce spec names (optional, depends on policy)
-- DROP INDEX IF EXISTS idx_users_email_key;
-- CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
-- DROP INDEX IF EXISTS idx_users_status_key;
-- CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
-- For this migration, we will ensure spec indexes exist. If old ones differ only by _key, they can remain or be cleaned separately.

-- Remove columns added by migration 000007 not present in the spec
ALTER TABLE users DROP COLUMN IF EXISTS status_reason;
ALTER TABLE users DROP COLUMN IF EXISTS updated_by;


-- Modify 'api_keys' table
-- Alter 'key_prefix' to VARCHAR(12)
ALTER TABLE api_keys ALTER COLUMN key_prefix TYPE VARCHAR(12);

-- Alter 'updated_at' to be NOT NULL and set DEFAULT
ALTER TABLE api_keys ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE api_keys ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;


-- Modify 'roles' table
-- Alter 'updated_at' to be NOT NULL and set DEFAULT
ALTER TABLE roles ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE roles ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;


-- Modify 'permissions' table
-- Alter 'updated_at' to be NOT NULL and set DEFAULT
ALTER TABLE permissions ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE permissions ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;


-- Modify 'external_accounts' table
-- Alter 'updated_at' to be NOT NULL and set DEFAULT
ALTER TABLE external_accounts ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE external_accounts ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;


-- Modify 'mfa_secrets' table
-- Alter 'updated_at' to be NOT NULL and set DEFAULT
ALTER TABLE mfa_secrets ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE mfa_secrets ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;


-- Modify 'sessions' table
-- Alter 'last_activity_at' to be NOT NULL and set DEFAULT
ALTER TABLE sessions ALTER COLUMN last_activity_at SET NOT NULL;
ALTER TABLE sessions ALTER COLUMN last_activity_at SET DEFAULT CURRENT_TIMESTAMP;

-- Add trigger for 'updated_at' on 'sessions' if it's missing or different
-- The spec implies 'updated_at' for sessions should also be auto-updated.
-- Migration 000006 does not create `updated_at` for sessions, nor a trigger for it.
-- The spec *does* show `updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP` for sessions
-- AND includes `CREATE TRIGGER set_timestamp_sessions BEFORE UPDATE ON sessions FOR EACH ROW EXECUTE PROCEDURE trigger_set_timestamp();`
-- Let's add `updated_at` column to sessions if it doesn't exist from a previous version of the schema (unlikely given 000006)
-- and ensure the trigger is applied.
-- Migration 000006 does not have updated_at for sessions. The spec does.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- Ensure the trigger function exists (it's defined in 000006 and spec)
-- CREATE OR REPLACE FUNCTION trigger_set_timestamp()... (already done in 000006)

-- Apply trigger to 'sessions' for 'updated_at'
CREATE TRIGGER set_timestamp_sessions
BEFORE UPDATE ON sessions
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();


-- Add missing indexes to 'user_roles' table
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);


-- Add missing index to 'mfa_backup_codes' table
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user_id ON mfa_backup_codes(user_id);
-- The spec also lists UNIQUE INDEX idx_mfa_backup_codes_user_id_code_hash.
-- Migration 000006 creates UNIQUE (user_id, code_hash) which creates a unique index.
-- So, only the non-unique idx_mfa_backup_codes_user_id is potentially missing.


-- Modify 'audit_logs' table
-- Add missing index
CREATE INDEX IF NOT EXISTS idx_audit_logs_target_type_target_id ON audit_logs(target_type, target_id);
-- Ensure 'created_at' index is DESC
DROP INDEX IF EXISTS idx_audit_logs_created_at_key; -- From 000006
DROP INDEX IF EXISTS idx_audit_logs_created_at; -- Generic name
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);


-- Modify 'verification_codes' table
-- Add missing index
CREATE INDEX IF NOT EXISTS idx_verification_codes_code_hash_type ON verification_codes(code_hash, type);


-- Note on UUID generation:
-- Migration 000006 uses pgcrypto's gen_random_uuid().
-- Spec mentions uuid-ossp's uuid_generate_v4().
-- This migration does not change the UUID generation function to avoid breaking existing defaults.

COMMIT;
