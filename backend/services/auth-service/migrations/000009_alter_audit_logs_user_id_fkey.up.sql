-- Start a transaction
BEGIN;

-- Step 1: Identify the existing foreign key constraint name.
-- This name can vary depending on how it was initially created (auto-named or explicitly named).
-- Common auto-generated names are like "audit_logs_user_id_fkey".
-- We need to find the actual name. For the purpose of this subtask, we will assume
-- we can find it or use a common pattern. If the `audit_logs` table was created in migration
-- `000006_create_auth_schema_tables.up.sql` without an explicit FK name, PostgreSQL
-- would generate one.

-- To make this migration robust, it would ideally look up the constraint name from information_schema.
-- However, for this subtask, we'll try a common pattern.
-- If migration 000006 named it, e.g. `fk_audit_logs_user_id`, use that.
-- If not named, it might be `audit_logs_user_id_fkey`.

-- Let's assume the constraint is named `audit_logs_user_id_fkey`.
-- If this fails, a manual lookup of the constraint name in the DB would be needed.
-- The table `audit_logs` is created in 000006. Let's check that file for an explicit name.
-- In 000006, it's: `user_id UUID REFERENCES users(id)` - no explicit FK name.

-- Attempt to drop the constraint if it exists with a common naming pattern.
-- PostgreSQL default naming for FK: <tablename>_<columnname>_fkey
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey;

-- Step 2: Add the new foreign key constraint with ON DELETE SET NULL.
-- We'll explicitly name this new constraint for easier management.
ALTER TABLE audit_logs
ADD CONSTRAINT fk_audit_logs_user_id_users_id FOREIGN KEY (user_id)
REFERENCES users(id) ON DELETE SET NULL;

COMMIT;
