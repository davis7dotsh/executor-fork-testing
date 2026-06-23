PRAGMA foreign_keys = ON;

CREATE TABLE instance_metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value BLOB NOT NULL
);

CREATE TABLE setup_state (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    token_digest BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    used_at INTEGER
);

CREATE TABLE admins (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE admin_sessions (
    session_digest BLOB PRIMARY KEY NOT NULL,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_digest BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX admin_sessions_expiry_idx ON admin_sessions(expires_at);

CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    token_digest BLOB NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    token_suffix TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER
);

CREATE INDEX api_tokens_active_digest_idx
    ON api_tokens(token_digest)
    WHERE revoked_at IS NULL;
