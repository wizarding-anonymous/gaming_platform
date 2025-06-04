-- Revert adding status_reason and updated_by columns from the users table

ALTER TABLE users
DROP COLUMN IF EXISTS updated_by,
DROP COLUMN IF EXISTS status_reason;
