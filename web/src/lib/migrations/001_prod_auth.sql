-- Migration for DBs created before production auth existed.
-- Run once; if a statement errors because it already ran, you can ignore it.

-- Add production auth fields to users (legacy columns may already exist).
ALTER TABLE users ADD COLUMN email TEXT;

-- Ensure legacy columns exist (older schema had these NOT NULL; if you already have them, these may fail).
ALTER TABLE users ADD COLUMN auth_salt_b64 TEXT;
ALTER TABLE users ADD COLUMN auth_iterations INTEGER;
ALTER TABLE users ADD COLUMN auth_verifier_b64 TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS otp_codes (
  email TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempt_count INTEGER NOT NULL,
  last_sent_at INTEGER
);

CREATE TABLE IF NOT EXISTS vault_item_metadata (
  vault_item_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  title TEXT,
  url_host TEXT,
  tags TEXT,
  FOREIGN KEY (vault_item_id) REFERENCES vault_items(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_vault_item_metadata_user_id ON vault_item_metadata(user_id);
CREATE INDEX IF NOT EXISTS idx_vault_item_metadata_title ON vault_item_metadata(user_id, title);
CREATE INDEX IF NOT EXISTS idx_vault_item_metadata_url_host ON vault_item_metadata(user_id, url_host);

