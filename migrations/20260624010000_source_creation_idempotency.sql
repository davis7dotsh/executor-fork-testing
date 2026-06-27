PRAGMA foreign_keys = ON;

CREATE TABLE source_creation_idempotency_clock (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    effective_now INTEGER NOT NULL CHECK (effective_now >= 0)
) STRICT;

INSERT INTO source_creation_idempotency_clock (id, effective_now) VALUES (1, 0);

CREATE TABLE source_creation_idempotency (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 128),
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    route TEXT NOT NULL CHECK (length(route) BETWEEN 1 AND 200),
    key_digest BLOB NOT NULL CHECK (length(key_digest) = 32),
    request_digest BLOB CHECK (
        request_digest IS NULL OR length(request_digest) = 32
    ),
    state TEXT NOT NULL CHECK (
        state IN ('reserved', 'completed', 'failed', 'abandoned', 'interrupted')
    ),
    response_ciphertext BLOB CHECK (
        response_ciphertext IS NULL
        OR length(response_ciphertext) BETWEEN 42 AND 25165824
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    completed_at INTEGER,
    expires_at INTEGER,
    purge_at INTEGER,
    UNIQUE (admin_id, route, key_digest),
    CHECK (
        (state = 'reserved'
            AND request_digest IS NOT NULL
            AND response_ciphertext IS NULL
            AND completed_at IS NULL
            AND expires_at IS NULL
            AND purge_at IS NULL)
        OR (state IN ('completed', 'failed')
            AND request_digest IS NOT NULL
            AND response_ciphertext IS NOT NULL
            AND completed_at IS NOT NULL
            AND expires_at > completed_at
            AND purge_at > expires_at)
        OR (state IN ('abandoned', 'interrupted')
            AND response_ciphertext IS NULL
            AND completed_at IS NOT NULL
            AND expires_at > completed_at
            AND purge_at > expires_at)
    )
) STRICT;

CREATE INDEX source_creation_idempotency_expiry_idx
    ON source_creation_idempotency(purge_at)
    WHERE purge_at IS NOT NULL;

CREATE INDEX source_creation_idempotency_admin_route_idx
    ON source_creation_idempotency(admin_id, route, sequence DESC);

CREATE TRIGGER source_creation_idempotency_immutable_binding
BEFORE UPDATE OF id, admin_id, route, key_digest, request_digest, created_at
ON source_creation_idempotency
BEGIN
    SELECT RAISE(ABORT, 'source creation idempotency binding is immutable');
END;

CREATE TRIGGER source_creation_idempotency_legal_transition
BEFORE UPDATE OF state ON source_creation_idempotency
WHEN NEW.state <> OLD.state AND NOT (
    OLD.state = 'reserved'
    AND NEW.state IN ('completed', 'failed', 'abandoned', 'interrupted')
)
BEGIN
    SELECT RAISE(ABORT, 'illegal source creation idempotency state transition');
END;

CREATE TRIGGER source_creation_idempotency_immutable_terminal
BEFORE UPDATE OF response_ciphertext, completed_at, expires_at, purge_at, updated_at
ON source_creation_idempotency
WHEN OLD.state IN ('completed', 'failed', 'abandoned', 'interrupted')
BEGIN
    SELECT RAISE(ABORT, 'terminal source creation idempotency response is immutable');
END;
