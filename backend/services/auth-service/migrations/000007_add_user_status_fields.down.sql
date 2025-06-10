-- File: backend/services/auth-service/migrations/000007_add_user_status_fields.down.sql
-- Revert adding status_reason and updated_by columns from the users table

ALTER TABLE users
DROP COLUMN IF EXISTS updated_by,
DROP COLUMN IF EXISTS status_reason;
