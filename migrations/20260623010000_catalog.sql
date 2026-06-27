PRAGMA foreign_keys = ON;

CREATE TABLE catalog_state (
    id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

INSERT INTO catalog_state (id, revision, created_at, updated_at)
VALUES (1, 0, unixepoch(), unixepoch());

CREATE TABLE sources (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK (kind IN ('openapi', 'graphql', 'mcp_http', 'mcp_stdio')),
    slug TEXT NOT NULL UNIQUE
        CHECK (length(slug) BETWEEN 1 AND 63)
        CHECK (substr(slug, 1, 1) BETWEEN 'a' AND 'z')
        CHECK (slug NOT GLOB '*[^a-z0-9_]*')
        CHECK (slug NOT IN ('tools', 'search', 'describe', 'executor')),
    search_short_grams TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    description TEXT CHECK (description IS NULL OR length(description) <= 2000),
    configuration_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(configuration_json))
        CHECK (json_type(configuration_json) = 'object'),
    mode_override TEXT CHECK (mode_override IS NULL OR mode_override IN ('enabled', 'ask', 'disabled')),
    health_status TEXT NOT NULL DEFAULT 'unknown'
        CHECK (health_status IN ('unknown', 'healthy', 'error')),
    health_error_code TEXT
        CHECK (health_error_code IS NULL OR length(health_error_code) BETWEEN 1 AND 128),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    catalog_revision INTEGER NOT NULL DEFAULT 0 CHECK (catalog_revision >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_refreshed_at INTEGER,
    CHECK (
        (health_status = 'error' AND health_error_code IS NOT NULL)
        OR (health_status <> 'error' AND health_error_code IS NULL)
    )
) STRICT;

CREATE INDEX sources_kind_slug_idx ON sources(kind, slug);

CREATE TABLE source_credentials (
    source_id TEXT PRIMARY KEY NOT NULL
        REFERENCES sources(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    payload_ciphertext BLOB NOT NULL CHECK (length(payload_ciphertext) > 0),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE source_artifacts (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    artifact_kind TEXT NOT NULL
        CHECK (artifact_kind IN ('openapi_document', 'graphql_schema', 'mcp_capabilities', 'metadata')),
    stable_key TEXT NOT NULL CHECK (length(stable_key) BETWEEN 1 AND 512),
    content_json TEXT NOT NULL CHECK (json_valid(content_json)),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (source_id, artifact_kind, stable_key)
) STRICT;

CREATE TABLE tools (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    source_id TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    stable_key TEXT NOT NULL CHECK (length(stable_key) BETWEEN 1 AND 1024),
    local_name TEXT NOT NULL
        CHECK (length(local_name) BETWEEN 1 AND 128)
        CHECK (substr(local_name, 1, 1) BETWEEN 'a' AND 'z')
        CHECK (local_name NOT GLOB '*[^a-z0-9_]*'),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 300),
    description TEXT CHECK (description IS NULL OR length(description) <= 4000),
    search_description TEXT NOT NULL DEFAULT '',
    search_short_grams TEXT NOT NULL DEFAULT '',
    input_schema_json TEXT NOT NULL CHECK (json_valid(input_schema_json)),
    output_schema_json TEXT CHECK (output_schema_json IS NULL OR json_valid(output_schema_json)),
    input_typescript TEXT CHECK (input_typescript IS NULL OR length(input_typescript) <= 100000),
    output_typescript TEXT CHECK (output_typescript IS NULL OR length(output_typescript) <= 100000),
    typescript_definitions_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(typescript_definitions_json))
        CHECK (json_type(typescript_definitions_json) = 'object'),
    intrinsic_mode TEXT NOT NULL CHECK (intrinsic_mode IN ('enabled', 'ask', 'disabled')),
    mode_override TEXT CHECK (mode_override IS NULL OR mode_override IN ('enabled', 'ask', 'disabled')),
    present INTEGER NOT NULL DEFAULT 1 CHECK (present IN (0, 1)),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    tombstoned_at INTEGER,
    UNIQUE (source_id, stable_key),
    UNIQUE (source_id, local_name),
    CHECK (
        (present = 1 AND tombstoned_at IS NULL)
        OR (present = 0 AND tombstoned_at IS NOT NULL)
    )
) STRICT;

CREATE INDEX tools_source_presence_name_idx
    ON tools(source_id, present, local_name);
CREATE INDEX tools_presence_mode_idx
    ON tools(present, intrinsic_mode, mode_override);

CREATE VIRTUAL TABLE tool_search USING fts5(
    source_id UNINDEXED,
    tool_id UNINDEXED,
    source_slug,
    local_name,
    description,
    sandbox_path,
    tokenize = 'unicode61'
);

CREATE VIRTUAL TABLE tool_search_trigram USING fts5(
    source_id UNINDEXED,
    tool_id UNINDEXED,
    source_slug,
    local_name,
    description,
    sandbox_path,
    tokenize = 'trigram'
);

CREATE VIRTUAL TABLE tool_search_short USING fts5(
    source_id UNINDEXED,
    tool_id UNINDEXED,
    grams,
    tokenize = 'unicode61'
);

CREATE TABLE request_logs (
    request_id TEXT PRIMARY KEY NOT NULL CHECK (length(request_id) BETWEEN 1 AND 128),
    actor_api_token_id TEXT REFERENCES api_tokens(id) ON DELETE SET NULL,
    surface TEXT NOT NULL CHECK (surface IN ('admin', 'gateway', 'cli', 'mcp')),
    source_id TEXT REFERENCES sources(id) ON DELETE SET NULL,
    tool_id TEXT REFERENCES tools(id) ON DELETE SET NULL,
    path_snapshot TEXT CHECK (path_snapshot IS NULL OR length(path_snapshot) BETWEEN 1 AND 512),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed', 'pending_approval', 'denied')),
    error_code TEXT CHECK (error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
    duration_ms INTEGER NOT NULL CHECK (duration_ms >= 0),
    approval_id TEXT CHECK (approval_id IS NULL OR length(approval_id) BETWEEN 1 AND 128),
    created_at INTEGER NOT NULL,
    CHECK ((source_id IS NULL AND tool_id IS NULL) OR path_snapshot IS NOT NULL)
) STRICT;

CREATE INDEX request_logs_created_cursor_idx
    ON request_logs(created_at DESC, request_id DESC);
CREATE INDEX request_logs_actor_created_idx
    ON request_logs(actor_api_token_id, created_at DESC);
CREATE INDEX request_logs_tool_created_idx
    ON request_logs(tool_id, created_at DESC);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
    request_id TEXT CHECK (request_id IS NULL OR length(request_id) BETWEEN 1 AND 128),
    actor_admin_id INTEGER REFERENCES admins(id) ON DELETE SET NULL,
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
    source_id TEXT REFERENCES sources(id) ON DELETE SET NULL,
    tool_id TEXT REFERENCES tools(id) ON DELETE SET NULL,
    target_path_snapshot TEXT
        CHECK (target_path_snapshot IS NULL OR length(target_path_snapshot) BETWEEN 1 AND 512),
    metadata_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(metadata_json))
        CHECK (json_type(metadata_json) = 'object'),
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX audit_events_created_idx
    ON audit_events(created_at DESC, id DESC);
CREATE INDEX audit_events_source_created_idx
    ON audit_events(source_id, created_at DESC);
