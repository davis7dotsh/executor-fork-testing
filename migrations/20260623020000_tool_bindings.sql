PRAGMA foreign_keys = ON;

CREATE TABLE tool_bindings (
    tool_id TEXT PRIMARY KEY NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL
        CHECK (protocol IN ('openapi', 'graphql', 'mcp_http', 'mcp_stdio')),
    binding_version INTEGER NOT NULL CHECK (binding_version > 0),
    definition_json TEXT NOT NULL
        CHECK (json_valid(definition_json))
        CHECK (json_type(definition_json) = 'object'),
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE INDEX tool_bindings_protocol_idx
    ON tool_bindings(protocol, binding_version, tool_id);
