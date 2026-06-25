ALTER TABLE oauth_refresh_leases RENAME TO oauth_refresh_leases_unfenced;

CREATE TABLE oauth_refresh_leases (
    connection_id TEXT PRIMARY KEY NOT NULL
        REFERENCES oauth_connections(id) ON DELETE CASCADE,
    lease_digest BLOB NOT NULL UNIQUE CHECK (length(lease_digest) = 32),
    base_secret_revision INTEGER NOT NULL CHECK (base_secret_revision > 0),
    connection_revision INTEGER NOT NULL CHECK (connection_revision >= 0),
    config_revision INTEGER NOT NULL CHECK (config_revision > 0),
    claimed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > claimed_at)
) STRICT;

INSERT INTO oauth_refresh_leases (
    connection_id, lease_digest, base_secret_revision,
    connection_revision, config_revision, claimed_at, expires_at
)
SELECT
    lease.connection_id, lease.lease_digest, lease.base_secret_revision,
    connection.revision, connection.current_config_revision,
    lease.claimed_at, lease.expires_at
FROM oauth_refresh_leases_unfenced lease
JOIN oauth_connections connection ON connection.id = lease.connection_id;

DROP TABLE oauth_refresh_leases_unfenced;

CREATE INDEX oauth_refresh_leases_expiry_idx
    ON oauth_refresh_leases(expires_at);
