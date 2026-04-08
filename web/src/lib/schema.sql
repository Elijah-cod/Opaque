-- Zero-knowledge password manager schema.
-- Server stores only ciphertext and key-derivation parameters, never plaintext.

-- Fresh/prod schema. For existing DBs created before production auth,
-- apply `src/lib/migrations/001_prod_auth.sql` instead.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,

  -- Production auth
  email TEXT,

  -- Vault KDF params (salt is not secret)
  vault_version INTEGER NOT NULL DEFAULT 1,
  vault_salt_b64 TEXT,
  vault_iterations INTEGER,

  -- Legacy auth (temporary migration support)
  auth_salt_b64 TEXT,
  auth_iterations INTEGER,
  auth_verifier_b64 TEXT
);

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

CREATE TABLE IF NOT EXISTS vault_items (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,

  -- Client-side encryption parameters.
  enc_salt_b64 TEXT NOT NULL,
  enc_iterations INTEGER NOT NULL,
  iv_b64 TEXT NOT NULL,
  ciphertext_b64 TEXT NOT NULL,

  -- Optional server-visible metadata (trade-off: enables search).
  metadata TEXT,

  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vault_items_user_id ON vault_items(user_id);

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

