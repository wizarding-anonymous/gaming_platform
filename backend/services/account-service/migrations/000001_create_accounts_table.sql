-- File: backend/services/account-service/migrations/000001_create_accounts_table.sql

-- Create accounts table
CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Create index on username for faster lookups
CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username);

-- Create index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);

-- Create index on status for filtering
CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);

-- Create index on deleted_at for soft delete queries
CREATE INDEX IF NOT EXISTS idx_accounts_deleted_at ON accounts(deleted_at);

-- Add comments for documentation
COMMENT ON TABLE accounts IS 'Stores basic account information for users';
COMMENT ON COLUMN accounts.id IS 'Unique identifier for the account';
COMMENT ON COLUMN accounts.username IS 'Unique username for the account';
COMMENT ON COLUMN accounts.email IS 'Email address associated with the account';
COMMENT ON COLUMN accounts.status IS 'Current status of the account (pending, active, inactive, blocked, deleted)';
COMMENT ON COLUMN accounts.created_at IS 'Timestamp when the account was created';
COMMENT ON COLUMN accounts.updated_at IS 'Timestamp when the account was last updated';
COMMENT ON COLUMN accounts.deleted_at IS 'Timestamp when the account was soft deleted, NULL if not deleted';
