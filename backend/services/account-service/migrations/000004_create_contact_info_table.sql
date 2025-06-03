-- account-service\migrations\000004_create_contact_info_table.sql
-- migrations/000004_create_contact_info_table.sql

-- Create contact_info table
CREATE TABLE IF NOT EXISTS contact_info (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL,
    type VARCHAR(20) NOT NULL, -- 'email', 'phone', etc.
    value VARCHAR(255) NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT false,
    is_primary BOOLEAN NOT NULL DEFAULT false,
    verification_code VARCHAR(64),
    verification_expires_at TIMESTAMP WITH TIME ZONE,
    verification_attempts INT NOT NULL DEFAULT 0,
    last_verification_attempt_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_contact_info_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT uq_contact_info_type_value UNIQUE (type, value)
);

-- Create index on account_id for faster lookups and joins
CREATE INDEX IF NOT EXISTS idx_contact_info_account_id ON contact_info(account_id);

-- Create index on type for filtering
CREATE INDEX IF NOT EXISTS idx_contact_info_type ON contact_info(type);

-- Create index on is_verified for filtering
CREATE INDEX IF NOT EXISTS idx_contact_info_is_verified ON contact_info(is_verified);

-- Create index on is_primary for filtering
CREATE INDEX IF NOT EXISTS idx_contact_info_is_primary ON contact_info(is_primary);

-- Add comments for documentation
COMMENT ON TABLE contact_info IS 'Stores contact information for user accounts';
COMMENT ON COLUMN contact_info.id IS 'Unique identifier for the contact information';
COMMENT ON COLUMN contact_info.account_id IS 'Foreign key to the accounts table';
COMMENT ON COLUMN contact_info.type IS 'Type of contact information (email, phone, etc.)';
COMMENT ON COLUMN contact_info.value IS 'Value of the contact information';
COMMENT ON COLUMN contact_info.is_verified IS 'Whether this contact information has been verified';
COMMENT ON COLUMN contact_info.is_primary IS 'Whether this is the primary contact of its type for the account';
COMMENT ON COLUMN contact_info.verification_code IS 'Code sent for verification purposes';
COMMENT ON COLUMN contact_info.verification_expires_at IS 'Expiration timestamp for the verification code';
COMMENT ON COLUMN contact_info.verification_attempts IS 'Number of verification attempts made';
COMMENT ON COLUMN contact_info.last_verification_attempt_at IS 'Timestamp of the last verification attempt';
COMMENT ON COLUMN contact_info.created_at IS 'Timestamp when the contact information was created';
COMMENT ON COLUMN contact_info.updated_at IS 'Timestamp when the contact information was last updated';
