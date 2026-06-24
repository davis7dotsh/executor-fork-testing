PRAGMA foreign_keys = ON;

CREATE TABLE approval_clock (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    effective_now INTEGER NOT NULL CHECK (effective_now >= 0)
) STRICT;

INSERT INTO approval_clock (id, effective_now) VALUES (1, 0);

CREATE TABLE approvals (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE CHECK (length(id) BETWEEN 1 AND 128),
    execution_id TEXT NOT NULL CHECK (length(execution_id) BETWEEN 1 AND 128),
    call_id TEXT NOT NULL CHECK (length(call_id) BETWEEN 1 AND 128),
    worker_generation INTEGER NOT NULL CHECK (worker_generation >= 0),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('api_token', 'admin', 'system')),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
    actor_api_token_id TEXT REFERENCES api_tokens(id) ON DELETE RESTRICT,
    actor_name_snapshot TEXT
        CHECK (actor_name_snapshot IS NULL OR length(actor_name_snapshot) BETWEEN 1 AND 200),
    surface TEXT NOT NULL CHECK (surface IN ('gateway', 'cli', 'mcp')),
    source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 128),
    tool_id TEXT NOT NULL CHECK (length(tool_id) BETWEEN 1 AND 128),
    callable_path_snapshot TEXT NOT NULL
        CHECK (length(callable_path_snapshot) BETWEEN 1 AND 512),
    source_display_name_snapshot TEXT
        CHECK (source_display_name_snapshot IS NULL OR length(source_display_name_snapshot) BETWEEN 1 AND 300),
    tool_display_name_snapshot TEXT
        CHECK (tool_display_name_snapshot IS NULL OR length(tool_display_name_snapshot) BETWEEN 1 AND 300),
    mode_provenance TEXT NOT NULL
        CHECK (mode_provenance IN ('tool_override', 'source_override', 'intrinsic')),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    catalog_revision INTEGER NOT NULL CHECK (catalog_revision >= 0),
    tool_revision INTEGER NOT NULL CHECK (tool_revision >= 0),
    binding_revision INTEGER NOT NULL CHECK (binding_revision >= 0),
    credential_revision INTEGER CHECK (credential_revision IS NULL OR credential_revision >= 0),
    arguments_digest BLOB NOT NULL CHECK (length(arguments_digest) = 32),
    arguments_ciphertext BLOB NOT NULL CHECK (length(arguments_ciphertext) BETWEEN 42 AND 8388650),
    redacted_arguments_ciphertext BLOB NOT NULL
        CHECK (length(redacted_arguments_ciphertext) BETWEEN 42 AND 8388650),
    input_schema_ciphertext BLOB NOT NULL CHECK (length(input_schema_ciphertext) BETWEEN 42 AND 2097194),
    output_schema_ciphertext BLOB CHECK (
        output_schema_ciphertext IS NULL
        OR length(output_schema_ciphertext) BETWEEN 42 AND 2097194
    ),
    invocation_snapshot_ciphertext BLOB NOT NULL
        CHECK (length(invocation_snapshot_ciphertext) BETWEEN 42 AND 8388650),
    result_ciphertext BLOB CHECK (
        result_ciphertext IS NULL
        OR length(result_ciphertext) BETWEEN 42 AND 8388650
    ),
    status TEXT NOT NULL CHECK (
        status IN (
            'pending', 'approved', 'denied', 'expired', 'canceled',
            'executing', 'succeeded', 'failed', 'stale', 'interrupted'
        )
    ),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    decision_id TEXT CHECK (decision_id IS NULL OR length(decision_id) BETWEEN 1 AND 128),
    decision TEXT CHECK (decision IS NULL OR decision IN ('approve', 'deny')),
    decided_by_admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    failure_code TEXT CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    decided_at INTEGER,
    execution_started_at INTEGER,
    completed_at INTEGER,
    CHECK (
        (actor_kind = 'api_token' AND actor_api_token_id IS NOT NULL AND actor_id = actor_api_token_id)
        OR (actor_kind IN ('admin', 'system') AND actor_api_token_id IS NULL)
    ),
    CHECK (
        (decision_id IS NULL AND decision IS NULL AND decided_at IS NULL AND decided_by_admin_id IS NULL)
        OR (decision_id IS NOT NULL AND decision IS NOT NULL AND decided_at IS NOT NULL)
    ),
    CHECK (
        status NOT IN ('approved', 'denied')
        OR decision IS NOT NULL
    ),
    CHECK (
        (status = 'executing' AND execution_started_at IS NOT NULL)
        OR status <> 'executing'
    ),
    CHECK (
        (status IN ('succeeded', 'failed', 'stale', 'interrupted', 'denied', 'expired', 'canceled')
            AND completed_at IS NOT NULL)
        OR status IN ('pending', 'approved', 'executing')
    ),
    UNIQUE (actor_kind, actor_id, execution_id, call_id)
) STRICT;

CREATE INDEX approvals_admin_cursor_idx
    ON approvals(sequence DESC);
CREATE INDEX approvals_status_cursor_idx
    ON approvals(status, sequence DESC);
CREATE INDEX approvals_actor_cursor_idx
    ON approvals(actor_kind, actor_id, sequence DESC);
CREATE INDEX approvals_execution_idx
    ON approvals(execution_id, status);

CREATE TABLE approval_terminal_order (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    approval_id TEXT NOT NULL UNIQUE
        REFERENCES approvals(id) ON DELETE CASCADE
) STRICT;

CREATE TABLE approval_log_outbox (
    request_id TEXT PRIMARY KEY NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
    approval_id TEXT NOT NULL CHECK (length(approval_id) BETWEEN 1 AND 128),
    actor_api_token_id TEXT CHECK (
        actor_api_token_id IS NULL OR length(actor_api_token_id) BETWEEN 1 AND 128
    ),
    surface TEXT NOT NULL CHECK (surface IN ('gateway', 'cli', 'mcp')),
    source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 128),
    tool_id TEXT NOT NULL CHECK (length(tool_id) BETWEEN 1 AND 128),
    path_snapshot TEXT NOT NULL CHECK (length(path_snapshot) BETWEEN 1 AND 512),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed', 'denied')),
    error_code TEXT CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE approval_log_outbox_state (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    dropped_count INTEGER NOT NULL DEFAULT 0 CHECK (dropped_count >= 0)
) STRICT;

INSERT INTO approval_log_outbox_state (id, dropped_count) VALUES (1, 0);

CREATE TRIGGER approvals_fixed_expiry
BEFORE UPDATE OF created_at, expires_at ON approvals
WHEN NEW.created_at <> OLD.created_at OR NEW.expires_at <> OLD.expires_at
BEGIN
    SELECT RAISE(ABORT, 'approval expiry is immutable');
END;

CREATE TRIGGER approvals_immutable_snapshot
BEFORE UPDATE OF
    id, execution_id, call_id, worker_generation, actor_kind, actor_id, actor_api_token_id,
    surface,
    actor_name_snapshot, source_id, tool_id, callable_path_snapshot,
    source_display_name_snapshot, tool_display_name_snapshot, mode_provenance,
    source_revision, catalog_revision, tool_revision, binding_revision,
    credential_revision, arguments_digest, arguments_ciphertext,
    redacted_arguments_ciphertext,
    input_schema_ciphertext, output_schema_ciphertext,
    invocation_snapshot_ciphertext
ON approvals
BEGIN
    SELECT RAISE(ABORT, 'approval snapshot is immutable');
END;

CREATE TRIGGER approvals_legal_status_transition
BEFORE UPDATE OF status ON approvals
WHEN NEW.status <> OLD.status AND NOT (
    (OLD.status = 'pending' AND NEW.status IN ('approved', 'denied', 'expired', 'canceled'))
    OR (OLD.status = 'approved' AND NEW.status IN ('executing', 'stale', 'canceled'))
    OR (OLD.status = 'executing' AND NEW.status IN ('succeeded', 'failed', 'interrupted'))
)
BEGIN
    SELECT RAISE(ABORT, 'illegal approval status transition');
END;

CREATE TRIGGER approvals_terminal_log_outbox
AFTER UPDATE OF status ON approvals
WHEN NEW.status <> OLD.status
 AND NEW.status IN ('denied', 'expired', 'canceled', 'succeeded', 'failed', 'stale', 'interrupted')
BEGIN
    INSERT OR IGNORE INTO approval_log_outbox (
        request_id, approval_id, actor_api_token_id, surface, source_id, tool_id,
        path_snapshot, outcome, error_code, created_at
    ) VALUES (
        substr(NEW.execution_id, 1, 48) || ':approval:' || NEW.id || ':' || NEW.status,
        NEW.id,
        NEW.actor_api_token_id,
        NEW.surface,
        NEW.source_id,
        NEW.tool_id,
        NEW.callable_path_snapshot,
        CASE
            WHEN NEW.status = 'succeeded' THEN 'succeeded'
            WHEN NEW.status IN ('denied', 'expired', 'canceled') THEN 'denied'
            ELSE 'failed'
        END,
        CASE NEW.status
            WHEN 'denied' THEN 'approval_denied'
            WHEN 'expired' THEN 'approval_expired'
            WHEN 'canceled' THEN 'approval_canceled'
            WHEN 'failed' THEN coalesce(NEW.failure_code, 'approval_execution_failed')
            WHEN 'stale' THEN coalesce(NEW.failure_code, 'approval_stale')
            WHEN 'interrupted' THEN coalesce(NEW.failure_code, 'approval_interrupted')
            ELSE NULL
        END,
        NEW.updated_at
    );
END;

CREATE TRIGGER approval_log_outbox_retention
AFTER INSERT ON approval_log_outbox
WHEN (SELECT count(*) FROM approval_log_outbox) > 10000
BEGIN
    UPDATE approval_log_outbox_state
    SET dropped_count = dropped_count + (
        (SELECT count(*) FROM approval_log_outbox) - 10000
    )
    WHERE id = 1;
    DELETE FROM approval_log_outbox
    WHERE rowid IN (
        SELECT rowid FROM approval_log_outbox
        ORDER BY rowid DESC LIMIT -1 OFFSET 10000
    );
END;
