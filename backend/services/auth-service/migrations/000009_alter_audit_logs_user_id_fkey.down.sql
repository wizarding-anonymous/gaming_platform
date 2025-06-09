-- Start a transaction
BEGIN;

-- Step 1: Drop the foreign key constraint added in the .up.sql migration.
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS fk_audit_logs_user_id_users_id;

-- Step 2: Re-add the original foreign key constraint (defaulting to ON DELETE NO ACTION).
-- Again, we'll explicitly name it for consistency, or use the default naming convention if preferred.
-- Let's use the default naming convention for the rollback to match what was likely there.
ALTER TABLE audit_logs
ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id)
REFERENCES users(id); -- Defaults to ON DELETE NO ACTION

COMMIT;
