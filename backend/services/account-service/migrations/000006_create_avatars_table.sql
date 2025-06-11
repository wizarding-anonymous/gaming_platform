# File: backend/services/account-service/migrations/000006_create_avatars_table.sql
-- account-service\migrations\000006_create_avatars_table.sql
-- migrations/000006_create_avatars_table.sql

-- Create avatars table
CREATE TABLE IF NOT EXISTS avatars (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    file_name VARCHAR(255) NOT NULL,
    file_size INT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    width INT NOT NULL,
    height INT NOT NULL,
    is_current BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_avatars_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Create index on account_id for faster lookups and joins
CREATE INDEX IF NOT EXISTS idx_avatars_account_id ON avatars(account_id);

-- Create index on is_current for filtering
CREATE INDEX IF NOT EXISTS idx_avatars_is_current ON avatars(is_current);

-- Add comments for documentation
COMMENT ON TABLE avatars IS 'Stores user avatar images';
COMMENT ON COLUMN avatars.id IS 'Unique identifier for the avatar';
COMMENT ON COLUMN avatars.account_id IS 'Foreign key to the accounts table';
COMMENT ON COLUMN avatars.file_path IS 'Path to the avatar file in storage';
COMMENT ON COLUMN avatars.file_name IS 'Original file name of the avatar';
COMMENT ON COLUMN avatars.file_size IS 'Size of the avatar file in bytes';
COMMENT ON COLUMN avatars.mime_type IS 'MIME type of the avatar file';
COMMENT ON COLUMN avatars.width IS 'Width of the avatar image in pixels';
COMMENT ON COLUMN avatars.height IS 'Height of the avatar image in pixels';
COMMENT ON COLUMN avatars.is_current IS 'Whether this is the current avatar for the account';
COMMENT ON COLUMN avatars.created_at IS 'Timestamp when the avatar was uploaded';
