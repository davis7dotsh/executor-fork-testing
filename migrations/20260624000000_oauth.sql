PRAGMA foreign_keys = ON;

CREATE TABLE oauth_connections (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    credential_key TEXT NOT NULL CHECK (length(credential_key) BETWEEN 1 AND 128),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    current_config_revision INTEGER NOT NULL
        CHECK (current_config_revision > 0),
    current_secret_revision INTEGER
        CHECK (current_secret_revision IS NULL OR current_secret_revision > 0),
    status TEXT NOT NULL
        CHECK (status IN ('pending_authorization', 'connecting', 'active', 'reauth_required')),
    granted_scopes_json TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(granted_scopes_json))
        CHECK (json_type(granted_scopes_json) = 'array'),
    has_client_secret INTEGER NOT NULL DEFAULT 0 CHECK (has_client_secret IN (0, 1)),
    has_refresh_token INTEGER NOT NULL DEFAULT 0 CHECK (has_refresh_token IN (0, 1)),
    access_expires_at INTEGER,
    authorized_at INTEGER,
    last_refreshed_at INTEGER,
    error_code TEXT
        CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (source_id, credential_key),
    FOREIGN KEY (id, current_config_revision)
        REFERENCES oauth_connection_config_revisions(connection_id, revision)
        DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (id, current_secret_revision)
        REFERENCES oauth_connection_secret_revisions(connection_id, revision)
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (
        status <> 'reauth_required' OR error_code IS NOT NULL
    )
) STRICT;

CREATE TABLE oauth_connection_config_revisions (
    connection_id TEXT NOT NULL
        REFERENCES oauth_connections(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    config_json TEXT NOT NULL
        CHECK (length(config_json) BETWEEN 2 AND 65536)
        CHECK (json_valid(config_json))
        CHECK (json_type(config_json) = 'object'),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (connection_id, revision)
) STRICT;

CREATE TABLE oauth_connection_secret_revisions (
    connection_id TEXT NOT NULL
        REFERENCES oauth_connections(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    payload_ciphertext BLOB NOT NULL
        CHECK (length(payload_ciphertext) BETWEEN 42 AND 262186),
    access_token_expires_at INTEGER,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (connection_id, revision)
) STRICT;

CREATE TABLE oauth_authorization_transactions (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    connection_id TEXT NOT NULL
        REFERENCES oauth_connections(id) ON DELETE CASCADE,
    connection_revision INTEGER NOT NULL CHECK (connection_revision >= 0),
    config_revision INTEGER NOT NULL CHECK (config_revision > 0),
    base_secret_revision INTEGER
        CHECK (base_secret_revision IS NULL OR base_secret_revision > 0),
    state_digest BLOB NOT NULL UNIQUE CHECK (length(state_digest) = 32),
    admin_session_digest BLOB NOT NULL CHECK (length(admin_session_digest) = 32),
    pkce_verifier_ciphertext BLOB NOT NULL
        CHECK (length(pkce_verifier_ciphertext) BETWEEN 42 AND 8192),
    exchange_claim_digest BLOB CHECK (
        exchange_claim_digest IS NULL OR length(exchange_claim_digest) = 32
    ),
    status TEXT NOT NULL
        CHECK (status IN ('pending', 'exchanging', 'succeeded', 'failed', 'expired')),
    result_secret_revision INTEGER
        CHECK (result_secret_revision IS NULL OR result_secret_revision > 0),
    error_code TEXT CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    claimed_at INTEGER,
    exchange_expires_at INTEGER CHECK (
        exchange_expires_at IS NULL OR exchange_expires_at > claimed_at
    ),
    completed_at INTEGER,
    CHECK (
        (status = 'pending'
            AND exchange_claim_digest IS NULL
            AND claimed_at IS NULL
            AND exchange_expires_at IS NULL
            AND completed_at IS NULL
            AND result_secret_revision IS NULL
            AND error_code IS NULL)
        OR (status = 'exchanging'
            AND exchange_claim_digest IS NOT NULL
            AND claimed_at IS NOT NULL
            AND exchange_expires_at IS NOT NULL
            AND completed_at IS NULL
            AND result_secret_revision IS NULL
            AND error_code IS NULL)
        OR (status = 'succeeded'
            AND exchange_claim_digest IS NOT NULL
            AND claimed_at IS NOT NULL
            AND completed_at IS NOT NULL
            AND result_secret_revision IS NOT NULL
            AND error_code IS NULL)
        OR (status IN ('failed', 'expired')
            AND completed_at IS NOT NULL
            AND result_secret_revision IS NULL
            AND error_code IS NOT NULL)
    )
) STRICT;

CREATE INDEX oauth_authorization_transactions_connection_idx
    ON oauth_authorization_transactions(connection_id, created_at DESC);
CREATE INDEX oauth_authorization_transactions_status_expiry_idx
    ON oauth_authorization_transactions(status, expires_at);

CREATE TABLE oauth_refresh_leases (
    connection_id TEXT PRIMARY KEY NOT NULL
        REFERENCES oauth_connections(id) ON DELETE CASCADE,
    lease_digest BLOB NOT NULL UNIQUE CHECK (length(lease_digest) = 32),
    base_secret_revision INTEGER NOT NULL CHECK (base_secret_revision > 0),
    claimed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > claimed_at)
) STRICT;

CREATE INDEX oauth_refresh_leases_expiry_idx
    ON oauth_refresh_leases(expires_at);

CREATE TRIGGER oauth_config_revisions_immutable
BEFORE UPDATE ON oauth_connection_config_revisions
BEGIN
    SELECT RAISE(ABORT, 'OAuth config revisions are immutable');
END;

CREATE TRIGGER oauth_secret_revisions_immutable
BEFORE UPDATE ON oauth_connection_secret_revisions
BEGIN
    SELECT RAISE(ABORT, 'OAuth secret revisions are immutable');
END;

CREATE TRIGGER oauth_current_config_revision_delete_guard
BEFORE DELETE ON oauth_connection_config_revisions
WHEN EXISTS (
    SELECT 1 FROM oauth_connections
    WHERE id = OLD.connection_id AND current_config_revision = OLD.revision
)
BEGIN
    SELECT RAISE(ABORT, 'current OAuth config revision cannot be deleted');
END;

CREATE TRIGGER oauth_current_secret_revision_delete_guard
BEFORE DELETE ON oauth_connection_secret_revisions
WHEN EXISTS (
    SELECT 1 FROM oauth_connections
    WHERE id = OLD.connection_id AND current_secret_revision = OLD.revision
)
BEGIN
    SELECT RAISE(ABORT, 'current OAuth secret revision cannot be deleted');
END;

CREATE TRIGGER oauth_connections_config_pointer_valid
BEFORE UPDATE OF current_config_revision ON oauth_connections
WHEN NOT EXISTS (
    SELECT 1 FROM oauth_connection_config_revisions
    WHERE connection_id = OLD.id AND revision = NEW.current_config_revision
)
BEGIN
    SELECT RAISE(ABORT, 'OAuth config revision does not exist');
END;

CREATE TRIGGER oauth_connections_secret_pointer_valid
BEFORE UPDATE OF current_secret_revision ON oauth_connections
WHEN NEW.current_secret_revision IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM oauth_connection_secret_revisions
    WHERE connection_id = OLD.id AND revision = NEW.current_secret_revision
)
BEGIN
    SELECT RAISE(ABORT, 'OAuth secret revision does not exist');
END;

CREATE TRIGGER oauth_authorization_transactions_immutable_binding
BEFORE UPDATE OF
    id, connection_id, connection_revision, config_revision, base_secret_revision, state_digest,
    admin_session_digest, pkce_verifier_ciphertext, created_at, expires_at
ON oauth_authorization_transactions
BEGIN
    SELECT RAISE(ABORT, 'OAuth authorization transaction binding is immutable');
END;

CREATE TRIGGER oauth_authorization_transactions_legal_transition
BEFORE UPDATE OF status ON oauth_authorization_transactions
WHEN NEW.status <> OLD.status AND NOT (
    (OLD.status = 'pending' AND NEW.status IN ('exchanging', 'failed', 'expired'))
    OR (OLD.status = 'exchanging' AND NEW.status IN ('succeeded', 'failed'))
)
BEGIN
    SELECT RAISE(ABORT, 'illegal OAuth authorization transaction transition');
END;

CREATE TRIGGER oauth_authorization_transactions_claim_transition
BEFORE UPDATE OF exchange_claim_digest, claimed_at, exchange_expires_at
ON oauth_authorization_transactions
WHEN NOT (
    OLD.status = 'pending'
    AND NEW.status = 'exchanging'
    AND OLD.exchange_claim_digest IS NULL
    AND NEW.exchange_claim_digest IS NOT NULL
    AND OLD.claimed_at IS NULL
    AND NEW.claimed_at IS NOT NULL
    AND OLD.exchange_expires_at IS NULL
    AND NEW.exchange_expires_at > NEW.claimed_at
)
BEGIN
    SELECT RAISE(ABORT, 'invalid OAuth authorization exchange claim');
END;

CREATE TRIGGER oauth_authorization_transactions_capacity
BEFORE INSERT ON oauth_authorization_transactions
WHEN (
    SELECT count(*) FROM oauth_authorization_transactions
    WHERE connection_id = NEW.connection_id AND status IN ('pending', 'exchanging')
) >= 128
BEGIN
    SELECT RAISE(ABORT, 'OAuth authorization transaction capacity reached');
END;

CREATE TRIGGER oauth_authorization_transactions_terminal_retention
AFTER UPDATE OF status ON oauth_authorization_transactions
WHEN NEW.status <> OLD.status
 AND NEW.status IN ('succeeded', 'failed', 'expired')
 AND (
    SELECT count(*) FROM oauth_authorization_transactions
    WHERE status IN ('succeeded', 'failed', 'expired')
 ) > 10000
BEGIN
    DELETE FROM oauth_authorization_transactions
    WHERE rowid IN (
        SELECT rowid FROM oauth_authorization_transactions
        WHERE status IN ('succeeded', 'failed', 'expired')
        ORDER BY rowid DESC LIMIT -1 OFFSET 10000
    );
END;
