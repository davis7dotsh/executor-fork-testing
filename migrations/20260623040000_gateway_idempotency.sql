PRAGMA foreign_keys = ON;

CREATE TABLE gateway_idempotency_clock (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    effective_now INTEGER NOT NULL CHECK (effective_now >= 0)
) STRICT;

INSERT INTO gateway_idempotency_clock (id, effective_now) VALUES (1, 0);

CREATE TABLE gateway_invocation_idempotency (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 128),
    owner_api_token_id TEXT NOT NULL
        REFERENCES api_tokens(id) ON DELETE CASCADE,
    key_digest BLOB NOT NULL CHECK (length(key_digest) = 32),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    state TEXT NOT NULL CHECK (
        state IN ('reserved', 'executing', 'completed', 'indeterminate')
    ),
    approval_id TEXT REFERENCES approvals(id) ON DELETE SET NULL,
    approval_correlation_id TEXT CHECK (
        approval_correlation_id IS NULL OR length(approval_correlation_id) BETWEEN 1 AND 128
    ),
    response_kind TEXT CHECK (
        response_kind IS NULL OR response_kind IN ('tool', 'approval')
    ),
    response_ciphertext BLOB CHECK (
        response_ciphertext IS NULL
        OR length(response_ciphertext) BETWEEN 42 AND 12582954
    ),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    completed_at INTEGER,
    expires_at INTEGER,
    UNIQUE (owner_api_token_id, key_digest),
    CHECK (
        (state IN ('reserved', 'executing')
            AND response_kind IS NULL
            AND response_ciphertext IS NULL
            AND completed_at IS NULL
            AND expires_at IS NULL)
        OR (state = 'completed'
            AND response_kind IS NOT NULL
            AND response_ciphertext IS NOT NULL
            AND completed_at IS NOT NULL
            AND expires_at > completed_at)
        OR (state = 'indeterminate'
            AND response_kind IS NULL
            AND response_ciphertext IS NULL
            AND completed_at IS NOT NULL
            AND expires_at > completed_at)
    )
) STRICT;

CREATE INDEX gateway_invocation_idempotency_expiry_idx
    ON gateway_invocation_idempotency(expires_at)
    WHERE expires_at IS NOT NULL;

CREATE INDEX gateway_invocation_idempotency_owner_idx
    ON gateway_invocation_idempotency(owner_api_token_id, sequence DESC);

CREATE INDEX gateway_invocation_idempotency_approval_correlation_idx
    ON gateway_invocation_idempotency(approval_correlation_id)
    WHERE approval_correlation_id IS NOT NULL;

CREATE TRIGGER gateway_idempotency_immutable_binding
BEFORE UPDATE OF id, owner_api_token_id, key_digest, request_digest, created_at
ON gateway_invocation_idempotency
BEGIN
    SELECT RAISE(ABORT, 'gateway idempotency binding is immutable');
END;

CREATE TRIGGER gateway_idempotency_legal_transition
BEFORE UPDATE OF state ON gateway_invocation_idempotency
WHEN NEW.state <> OLD.state AND NOT (
    (OLD.state = 'reserved' AND NEW.state IN ('executing', 'completed', 'indeterminate'))
    OR (OLD.state = 'executing' AND NEW.state IN ('completed', 'indeterminate'))
)
BEGIN
    SELECT RAISE(ABORT, 'illegal gateway idempotency state transition');
END;

CREATE TRIGGER gateway_idempotency_immutable_terminal
BEFORE UPDATE OF response_kind, response_ciphertext, completed_at, expires_at
ON gateway_invocation_idempotency
WHEN OLD.state IN ('completed', 'indeterminate')
BEGIN
    SELECT RAISE(ABORT, 'terminal gateway idempotency response is immutable');
END;

CREATE TRIGGER gateway_idempotency_capture_approval_correlation_insert
AFTER INSERT ON gateway_invocation_idempotency
WHEN NEW.approval_id IS NOT NULL AND NEW.approval_correlation_id IS NULL
BEGIN
    UPDATE gateway_invocation_idempotency
    SET approval_correlation_id = NEW.approval_id
    WHERE id = NEW.id;
END;

CREATE TRIGGER gateway_idempotency_capture_approval_correlation_update
AFTER UPDATE OF approval_id ON gateway_invocation_idempotency
WHEN OLD.approval_id IS NULL AND NEW.approval_id IS NOT NULL
BEGIN
    UPDATE gateway_invocation_idempotency
    SET approval_correlation_id = NEW.approval_id
    WHERE id = NEW.id;
END;

CREATE TRIGGER gateway_idempotency_approval_correlation_transition
BEFORE UPDATE OF approval_correlation_id ON gateway_invocation_idempotency
WHEN NOT (
    OLD.approval_correlation_id IS NULL
    AND NEW.approval_correlation_id = NEW.approval_id
    AND NEW.approval_correlation_id IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'gateway approval correlation transition is invalid');
END;

CREATE TRIGGER gateway_idempotency_approval_reference_transition
BEFORE UPDATE OF approval_id ON gateway_invocation_idempotency
WHEN OLD.approval_id IS NOT NULL
 AND NEW.approval_id IS NOT NULL
 AND NEW.approval_id <> OLD.approval_id
BEGIN
    SELECT RAISE(ABORT, 'gateway approval reference is immutable');
END;
