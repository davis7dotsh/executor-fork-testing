PRAGMA foreign_keys = ON;

CREATE TABLE api_token_creation_idempotency (
    record_id TEXT PRIMARY KEY NOT NULL CHECK (length(record_id) BETWEEN 1 AND 128),
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    key_digest BLOB NOT NULL CHECK (length(key_digest) = 32),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    token_id TEXT NOT NULL UNIQUE REFERENCES api_tokens(id) ON DELETE RESTRICT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    UNIQUE (admin_id, key_digest)
) STRICT;

CREATE INDEX api_token_creation_idempotency_admin_idx
    ON api_token_creation_idempotency(admin_id, created_at DESC);

CREATE TRIGGER api_token_creation_idempotency_immutable
BEFORE UPDATE ON api_token_creation_idempotency
BEGIN
    SELECT RAISE(ABORT, 'API token creation idempotency records are immutable');
END;
