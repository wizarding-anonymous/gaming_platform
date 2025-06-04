-- Add status_reason and updated_by columns to the users table

ALTER TABLE users
ADD COLUMN IF NOT EXISTS status_reason TEXT,
ADD COLUMN IF NOT EXISTS updated_by TEXT;

-- It's also a good practice to add comments to these columns in the database
COMMENT ON COLUMN users.status_reason IS 'Reason for the current status, e.g., reason for blocking.';
COMMENT ON COLUMN users.updated_by IS 'Identifier of the user or system that performed the last update on this record.';
