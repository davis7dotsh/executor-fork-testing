PRAGMA foreign_keys = ON;

CREATE TABLE approval_correlations (
    execution_id TEXT NOT NULL CHECK (length(execution_id) BETWEEN 1 AND 128),
    call_id TEXT NOT NULL CHECK (length(call_id) BETWEEN 1 AND 128),
    approval_id TEXT NOT NULL UNIQUE CHECK (length(approval_id) BETWEEN 1 AND 128),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('api_token', 'admin', 'system')),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
    surface TEXT NOT NULL CHECK (surface IN ('gateway', 'cli', 'mcp')),
    worker_generation INTEGER NOT NULL CHECK (worker_generation >= 0),
    callable_path TEXT NOT NULL CHECK (length(callable_path) BETWEEN 1 AND 512),
    arguments_digest BLOB NOT NULL CHECK (length(arguments_digest) = 32),
    expires_at INTEGER CHECK (expires_at IS NULL OR expires_at >= 0),
    PRIMARY KEY (actor_kind, actor_id, execution_id, call_id)
) STRICT;

CREATE INDEX approval_correlations_expiry_idx
    ON approval_correlations(expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE approval_correlation_state (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    correlation_count INTEGER NOT NULL CHECK (correlation_count BETWEEN 0 AND 100000)
) STRICT;

INSERT INTO approval_correlation_state (id, correlation_count) VALUES (1, 0);

INSERT INTO approval_correlations (
    execution_id, call_id, approval_id, actor_kind, actor_id, surface,
    worker_generation, callable_path, arguments_digest, expires_at
)
SELECT
    execution_id, call_id, id, actor_kind, actor_id, surface,
    worker_generation, callable_path_snapshot, arguments_digest,
    CASE
        WHEN status IN ('denied', 'expired', 'canceled', 'succeeded', 'failed', 'stale', 'interrupted')
        THEN completed_at + 86400
        ELSE NULL
    END
FROM approvals;

UPDATE approval_correlation_state
SET correlation_count = (SELECT count(*) FROM approval_correlations)
WHERE id = 1;

CREATE TRIGGER approval_correlations_capacity
BEFORE INSERT ON approval_correlations
WHEN (SELECT correlation_count FROM approval_correlation_state WHERE id = 1) >= 100000
BEGIN
    SELECT RAISE(ABORT, 'approval correlation capacity reached');
END;

CREATE TRIGGER approval_correlations_count_insert
AFTER INSERT ON approval_correlations
BEGIN
    UPDATE approval_correlation_state
    SET correlation_count = correlation_count + 1
    WHERE id = 1;
END;

CREATE TRIGGER approval_correlations_initial_expiry
BEFORE INSERT ON approval_correlations
WHEN NEW.expires_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'new approval correlation expiry must be null');
END;

CREATE TRIGGER approvals_insert_correlation
AFTER INSERT ON approvals
BEGIN
    INSERT INTO approval_correlations (
        execution_id, call_id, approval_id, actor_kind, actor_id, surface,
        worker_generation, callable_path, arguments_digest, expires_at
    ) VALUES (
        NEW.execution_id, NEW.call_id, NEW.id, NEW.actor_kind, NEW.actor_id, NEW.surface,
        NEW.worker_generation, NEW.callable_path_snapshot, NEW.arguments_digest, NULL
    );
END;

CREATE TRIGGER approval_correlations_immutable
BEFORE UPDATE OF
    execution_id, call_id, approval_id, actor_kind, actor_id, surface,
    worker_generation, callable_path, arguments_digest
ON approval_correlations
BEGIN
    SELECT RAISE(ABORT, 'approval correlation is immutable');
END;

CREATE TRIGGER approval_correlations_expiry_transition
BEFORE UPDATE OF expires_at ON approval_correlations
WHEN NOT (
    OLD.expires_at IS NULL
    AND NEW.expires_at = (
        SELECT completed_at + 86400
        FROM approvals
        WHERE id = OLD.approval_id
          AND status IN ('denied', 'expired', 'canceled', 'succeeded', 'failed', 'stale', 'interrupted')
    )
)
BEGIN
    SELECT RAISE(ABORT, 'approval correlation expiry transition is invalid');
END;

CREATE TRIGGER approvals_terminalize_correlation
AFTER UPDATE OF status ON approvals
WHEN NEW.status <> OLD.status
 AND NEW.status IN ('denied', 'expired', 'canceled', 'succeeded', 'failed', 'stale', 'interrupted')
BEGIN
    UPDATE approval_correlations
    SET expires_at = NEW.completed_at + 86400
    WHERE approval_id = NEW.id AND expires_at IS NULL;
END;

CREATE TRIGGER approval_correlations_delete_guard
BEFORE DELETE ON approval_correlations
WHEN OLD.expires_at IS NULL
  OR OLD.expires_at > (SELECT effective_now FROM approval_clock WHERE id = 1)
BEGIN
    SELECT RAISE(ABORT, 'unexpired approval correlation cannot be deleted');
END;

CREATE TRIGGER approval_correlations_count_delete
AFTER DELETE ON approval_correlations
BEGIN
    UPDATE approval_correlation_state
    SET correlation_count = correlation_count - 1
    WHERE id = 1;
    DELETE FROM approvals
    WHERE id = OLD.approval_id
      AND status IN ('denied', 'expired', 'canceled', 'succeeded', 'failed', 'stale', 'interrupted');
END;
