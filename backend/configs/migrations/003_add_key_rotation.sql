-- Add key rotation support

CREATE TABLE IF NOT EXISTS key_rotations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    old_key_id TEXT,
    new_key_id TEXT NOT NULL,
    rotation_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    cleanup_date DATETIME,
    public_key TEXT,
    private_key TEXT,
    encapsulated_secret TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_key_rotations_user_id ON key_rotations(user_id);
CREATE INDEX IF NOT EXISTS idx_key_rotations_cleanup_date ON key_rotations(cleanup_date);