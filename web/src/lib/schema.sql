-- Zero-knowledge password manager schema.
-- Server stores only ciphertext and key-derivation parameters, never plaintext.

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,

  -- For client-side PBKDF2 auth verifier derivation.
  auth_salt_b64 TEXT NOT NULL,
  auth_iterations INTEGER NOT NULL,
  auth_verifier_b64 TEXT NOT NULL
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

  -- Optional server-visible metadata (keep empty for true zero-knowledge).
  metadata TEXT,

  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vault_items_user_id ON vault_items(user_id);

