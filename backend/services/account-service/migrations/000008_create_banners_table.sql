-- File: backend/services/account-service/migrations/000008_create_banners_table.sql

-- Create banners table
CREATE TABLE IF NOT EXISTS banners (
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
    CONSTRAINT fk_banners_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Create index on account_id for faster lookups and joins
CREATE INDEX IF NOT EXISTS idx_banners_account_id ON banners(account_id);

-- Create index on is_current for filtering
CREATE INDEX IF NOT EXISTS idx_banners_is_current ON banners(is_current);

-- Add comments for documentation
COMMENT ON TABLE banners IS 'Stores user profile banner images';
COMMENT ON COLUMN banners.id IS 'Unique identifier for the banner';
COMMENT ON COLUMN banners.account_id IS 'Foreign key to the accounts table';
COMMENT ON COLUMN banners.file_path IS 'Path to the banner file in storage';
COMMENT ON COLUMN banners.file_name IS 'Original file name of the banner';
COMMENT ON COLUMN banners.file_size IS 'Size of the banner file in bytes';
COMMENT ON COLUMN banners.mime_type IS 'MIME type of the banner file';
COMMENT ON COLUMN banners.width IS 'Width of the banner image in pixels';
COMMENT ON COLUMN banners.height IS 'Height of the banner image in pixels';
COMMENT ON COLUMN banners.is_current IS 'Whether this is the current banner for the account';
COMMENT ON COLUMN banners.created_at IS 'Timestamp when the banner was uploaded';
