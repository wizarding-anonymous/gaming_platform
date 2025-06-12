-- File: backend/services/account-service/migrations/000005_create_settings_table.sql

-- Create settings table
CREATE TABLE IF NOT EXISTS settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    category VARCHAR(50) NOT NULL,
    key VARCHAR(100) NOT NULL,
    value JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_settings_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT uq_settings_account_category_key UNIQUE (account_id, category, key)
);

-- Create index on account_id for faster lookups and joins
CREATE INDEX IF NOT EXISTS idx_settings_account_id ON settings(account_id);

-- Create index on category for filtering
CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category);

-- Create composite index on account_id and category for common queries
CREATE INDEX IF NOT EXISTS idx_settings_account_category ON settings(account_id, category);

-- Add comments for documentation
COMMENT ON TABLE settings IS 'Stores user settings by category and key';
COMMENT ON COLUMN settings.id IS 'Unique identifier for the setting';
COMMENT ON COLUMN settings.account_id IS 'Foreign key to the accounts table';
COMMENT ON COLUMN settings.category IS 'Category of the setting (privacy, notifications, interface, security, etc.)';
COMMENT ON COLUMN settings.key IS 'Key name of the setting within the category';
COMMENT ON COLUMN settings.value IS 'JSON value of the setting';
COMMENT ON COLUMN settings.created_at IS 'Timestamp when the setting was created';
COMMENT ON COLUMN settings.updated_at IS 'Timestamp when the setting was last updated';
