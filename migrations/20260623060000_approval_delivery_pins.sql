PRAGMA foreign_keys = ON;

CREATE TABLE approval_delivery_pins (
    approval_id TEXT PRIMARY KEY NOT NULL
        REFERENCES approvals(id) ON DELETE RESTRICT,
    ref_count INTEGER NOT NULL CHECK (ref_count BETWEEN 1 AND 128),
    snapshot_ciphertext_bytes INTEGER NOT NULL
        CHECK (snapshot_ciphertext_bytes BETWEEN 1 AND 67108864),
    created_at INTEGER NOT NULL
) STRICT;
