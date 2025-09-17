-- Add role column to users table
ALTER TABLE secureaccess.users
ADD COLUMN role VARCHAR(50) DEFAULT 'user' NOT NULL;

-- Update existing users to have a default role
UPDATE secureaccess.users SET role = 'user' WHERE role IS NULL;
