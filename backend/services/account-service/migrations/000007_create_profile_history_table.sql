-- File: backend/services/account-service/migrations/000007_create_profile_history_table.sql

-- Create profile_history table
CREATE TABLE IF NOT EXISTS profile_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL,
    account_id UUID NOT NULL,
    change_type VARCHAR(20) NOT NULL, -- 'create', 'update', 'delete'
    field_name VARCHAR(50) NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by UUID NOT NULL, -- account_id of the user who made the change
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_profile_history_profile FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
    CONSTRAINT fk_profile_history_account FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    CONSTRAINT fk_profile_history_changed_by FOREIGN KEY (changed_by) REFERENCES accounts(id) ON DELETE SET NULL
);

-- Create index on profile_id for faster lookups and joins
CREATE INDEX IF NOT EXISTS idx_profile_history_profile_id ON profile_history(profile_id);

-- Create index on account_id for faster lookups and joins
CREATE INDEX IF NOT EXISTS idx_profile_history_account_id ON profile_history(account_id);

-- Create index on changed_at for time-based queries
CREATE INDEX IF NOT EXISTS idx_profile_history_changed_at ON profile_history(changed_at);

-- Create index on field_name for filtering
CREATE INDEX IF NOT EXISTS idx_profile_history_field_name ON profile_history(field_name);

-- Add comments for documentation
COMMENT ON TABLE profile_history IS 'Stores history of changes to user profiles';
COMMENT ON COLUMN profile_history.id IS 'Unique identifier for the history record';
COMMENT ON COLUMN profile_history.profile_id IS 'Foreign key to the profiles table';
COMMENT ON COLUMN profile_history.account_id IS 'Foreign key to the accounts table';
COMMENT ON COLUMN profile_history.change_type IS 'Type of change (create, update, delete)';
COMMENT ON COLUMN profile_history.field_name IS 'Name of the field that was changed';
COMMENT ON COLUMN profile_history.old_value IS 'Previous value of the field';
COMMENT ON COLUMN profile_history.new_value IS 'New value of the field';
COMMENT ON COLUMN profile_history.changed_by IS 'Account ID of the user who made the change';
COMMENT ON COLUMN profile_history.changed_at IS 'Timestamp when the change was made';
