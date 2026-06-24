# Executor rewrite architecture

## Product boundary

The rewrite targets a single-user, local and self-hosted Executor. Linux and
macOS native binaries plus Docker are first-class release targets. The current
cloud and desktop products remain legacy surfaces and do not constrain the new
architecture.

The production artifact is one Rust binary. It owns the control API, gateway
API, embedded SQLite state, upstream connections, sandboxed TypeScript runtime,
approval coordination, and static Svelte application. The production runtime
does not require Node.js. Packaging builds the `web/` application first and
embeds its static output at the `src/web_assets.rs` boundary. Cargo checks and
tests do not depend on generated web assets.

Version one supports these upstream source types:

- MCP servers over local stdio and remote Streamable HTTP
- OpenAPI-described HTTP APIs
- GraphQL endpoints

It supports API key, bearer token, basic authentication, and OAuth credential
flows. Each source has one active credential profile. Integrations and existing
data migration are intentionally out of scope.

## Control and gateway planes

The two authentication planes are deliberately disjoint:

- Control APIs accept only an administrator session cookie. Unsafe requests
  also require an origin match and CSRF token.
- Gateway APIs accept only dashboard-generated API tokens.

API tokens initially share one global enabled-tool set. Interactive approval
rules are evaluated separately and remain available for sensitive calls. An API
token can never authorize an administrator route.

First boot prints a one-time, high-entropy setup token in a fragment URL. Only a
keyed digest is stored. The atomic setup claim creates exactly one administrator
whose password is hashed with Argon2id. Administrator sessions and API tokens
are opaque, high-entropy values stored only as keyed digests. API token secrets
are shown once.

Reverse-proxy client addresses are disabled by default. `--trusted-proxy <CIDR>`
may be repeated, or `EXECUTOR_TRUSTED_PROXIES` may contain a comma-separated
list. Executor honors `X-Forwarded-For` only when the direct peer is trusted,
then walks the chain from right to left through configured trusted proxies.
Malformed, missing, or all-trusted chains are rejected before password work so
they cannot create a proxy-wide login-rate-limit bucket. Every intermediary
proxy must be listed and must append or replace `X-Forwarded-For` correctly.

## Storage and key management

SQLite is opened with foreign keys, WAL mode, a five-second busy timeout, and
`synchronous=FULL`. FULL is the initial durability choice because this local
control plane stores credential and approval state, while the expected write
volume is modest. This can be revisited with benchmarks. Network work must
never occur inside a database transaction.

Migrations are append-only SQL files embedded into the binary. The instance
master key comes from `EXECUTOR_MASTER_KEY_FILE`, or is atomically created as a
0600 file inside a 0700 data directory. An initialized database without its key
fails closed. A boot sentinel detects a wrong key or modified ciphertext.
Protected values use XChaCha20-Poly1305. HKDF derives purpose-specific subkeys,
and associated data binds ciphertext to its purpose and record identity.

## Delivery slices

1. Foundation: one Cargo package and binary, SQLite migrations, master-key
   lifecycle, setup, administrator sessions, CSRF and origin checks, API token
   management, a gateway authentication proof, and the Svelte SPA shell.
2. Sources: MCP stdio and Streamable HTTP, OpenAPI, GraphQL, credential profiles,
   OAuth callbacks, connectivity testing, and source lifecycle UI.
3. Tool catalog: normalized discovery, search and describe, global enable state,
   bulk and filtered enable workflows, and request-aware tool testing.
4. Runtime and approvals: sandboxed TypeScript execution, concurrent tool calls,
   interactive approvals, resume semantics, and CLI parity.
5. Operations: request logs, redaction, retention, embedded web assets, Docker,
   Linux and macOS packaging, upgrade safety, e2e recordings, and migration of
   the old TypeScript products into `legacy/` after parity is proven.

The current TypeScript implementation stays in place until the replacement has
parity. Moving it early would obscure behavior that still serves as the
reference contract.

## Source and tool catalog contract

The catalog is global to the single-user instance. Every API token sees the
same source and tool set. A source has one immutable ID, one collision-safe
slug, one non-secret configuration object, and at most one encrypted credential
payload. Source kinds are limited to `openapi`, `graphql`, `mcp_http`, and
`mcp_stdio`. Credential payloads carry a schema version and are encrypted with
record-bound associated data, so ciphertext copied between sources cannot be
decrypted.

Tools retain an immutable ID and upstream stable key separately from their
display name and callable name. The full callable path is
`tools.<source_slug>.<local_tool_name>`. Sandboxed TypeScript omits the leading
`tools.` because that is the proxy root. Local names are normalized and
collision suffixes are allocated in stable-key order. Existing and tombstoned
names stay reserved, which keeps paths stable when upstream discovery reorders,
removes, or restores a tool. The source roots `tools`, `search`, `describe`, and
`executor` are reserved for the sandbox and built-in catalog helpers.

A source may expose at most 100,000 active tools and retain at most 25,000
tombstoned tool identities, for a hard 125,000-row history ceiling. Refreshes
that would exceed either ceiling fail atomically with `catalog_too_large`.
Executor never silently deletes tombstones because they carry stable IDs,
callable names, and administrator overrides. Intentionally discarding that
history requires deleting and recreating the source. Administrator tool lists
apply filters, counts, ordering, and pagination in SQLite so reads remain
memory-bounded at the history ceiling.

Gateway search uses bounded word, trigram, and encoded short-gram indexes. SQL
first excludes tombstones and effectively disabled tools, then caps the
deduplicated candidate set at 4,096 before the reference lexical scorer runs.
This preserves token-prefix, substring, and reverse-prefix recall without
hydrating the complete historical table.

Each tool has an intrinsic mode. A source and a tool may each add an override.
The effective mode is always derived in this order:

1. Tool override
2. Source override
3. Tool intrinsic mode

The visible modes are `enabled`, `ask`, and `disabled`. Disabled tools remain
visible in the administrator catalog, but gateway search and describe omit
them. A direct invocation lookup returns `tool_disabled`, which prevents a
caller with an old path from bypassing the catalog. Ask tools remain
discoverable and carry approval-required metadata.

Protocol discovery and schema normalization happen before a catalog write.
Initial creation uses a create-only staged snapshot with no meaningless CAS
fields. Refresh snapshots record the source and credential revisions they used.
The commit rechecks both revisions, serializes catalog writers, replaces source
artifacts, upserts tools by `(source_id, stable_key)`, tombstones missing tools,
and advances the source and global catalog revisions in one transaction. Create
and refresh share the same transaction-scoped artifact, tool, binding, and
search-index application helpers. A failed stage or stale revision leaves the
last known good catalog untouched. Network work never occurs inside this
transaction.

Tool bindings use a closed Rust enum and a generic persisted wire vocabulary:
protocol, positive binding version, and private JSON definition. SQLite reserves
the supported source protocol names, while Rust rejects protocol/version pairs
that have no implemented typed variant. Generic source creation and gateway
invocation routes own authentication, limits, logging, and typed dispatch;
OpenAPI owns only its preview, compiler, credential adapter, and invocation
adapter.

Invocation admission acquires a catalog read lease and reads tool presence,
effective mode, source configuration, credential revision, and typed binding in
one coherent SQLite snapshot. Policy-affecting writers take the matching write
gate, so the admitted policy cannot change before or during outbound execution.
Ask releases the lease without network work and retains a revision token. A
future approval continuation must reacquire a fresh lease and revalidate every
source, tool, binding, catalog, and credential revision before execution.

Administrator catalog reads require a session cookie. Catalog mutations also
require the matching Origin, CSRF cookie, and CSRF header. Gateway discovery,
description, and invocation lookup accept API tokens only. The initial routes
are:

- `GET /api/v1/sources` and `GET /api/v1/sources/{id}`
- `DELETE /api/v1/sources/{id}`
- `PATCH /api/v1/sources/{id}/mode`
- `GET /api/v1/tools` and `GET /api/v1/tools/{id}`
- `PATCH /api/v1/tools/{id}/mode` and `PATCH /api/v1/tools/modes`
- `GET /api/v1/request-logs` and `GET /api/v1/request-logs/{id}`
- `POST /api/v1/gateway/tools/search`
- `POST /api/v1/gateway/tools/describe`
- `POST /api/v1/gateway/tools/lookup`
- `POST /api/v1/sources/openapi/preview`
- `POST /api/v1/sources` and `POST /api/v1/sources/{id}/refresh`
- `GET`, `PUT`, and `DELETE /api/v1/sources/{id}/credentials`
- `POST /api/v1/gateway/tools/invoke`

Request logs store metadata only: request ID, nullable actor token ID, surface,
nullable source and tool IDs, an immutable callable-path snapshot, outcome,
stable error code, duration, nullable approval ID, and timestamp. They never
store request headers, credentials, arguments, or results. Source and tool
deletion clears their foreign keys while retaining the history and path
snapshot.

## OpenAPI import and invocation

OpenAPI 3.0 and 3.1 documents can be previewed from pasted JSON or YAML and
from an HTTP URL. Swagger 2 documents and external references fail closed.
Local references have cycle and depth limits. Tool identities are derived from
the HTTP method and exact path, so operation ID and display-name changes do not
change tool IDs, callable names, or administrator mode overrides on refresh.

The persisted tool binding contains only typed protocol metadata. Static API keys,
bearer tokens, basic credentials, manually supplied OAuth access tokens, and
query-bearing source URLs live only in the source-bound encrypted credential
envelope. The source configuration and admin response expose a query-stripped
display URL. Refresh
performs network and compilation work before the catalog transaction, then
commits artifacts, tools, tombstones, bindings, and health together under
source and credential revision checks. A failed refresh leaves the last good
callable catalog in place.

Outbound requests resolve and validate every DNS answer, pin the validated
addresses into a proxy-free client, and reject mixed safe and unsafe answers.
Private and loopback targets require a per-source administrator opt-in.
Link-local, metadata, reserved, documentation, and multicast targets remain
blocked even with that opt-in. Spec redirects are manual, bounded, revalidated
at every hop, and cannot downgrade HTTPS. Tool invocation never follows
redirects. Request and response headers, bodies, time, DNS answers, redirects,
and document sizes have hard limits.

The first invocation surface deliberately supports this exact serialization
subset:

- Path and header parameters use `simple` style.
- Query parameters use `form`, `spaceDelimited`, `pipeDelimited`, or
  `deepObject`; `allowReserved` is not accepted.
- Cookie parameters use `form`, including scalar, array, and object explode
  behavior.
- Request bodies support JSON and `+json`, string-valued `text/plain`, and
  closed scalar-object `application/x-www-form-urlencoded` schemas.
- Parameter `content`, multipart bodies, arbitrary media types, and other
  styles fail during import instead of producing tools that cannot execute.

Enabled tools execute immediately, disabled or removed tools cannot reach the
transport, and Ask tools return the stable `approval_required` seam without
executing. Request logs remain metadata-only and never contain arguments,
credentials, upstream bodies, or results.

OAuth2 and OpenID Connect operations expose their declared flow metadata for a
later OAuth setup UI. This slice accepts a manually supplied access token in
the encrypted credential envelope, labeled `manual_oauth_access_token` in
metadata. It does not yet claim a managed OAuth flow. State and PKCE handling,
browser callbacks, authorization-code exchange, refresh-token rotation, and
provider error recovery remain part of the dedicated OAuth slice.

Audit history is bounded to the most recently inserted 10,000 events for a
single-user instance. Each event's serialized metadata is capped at 64 KiB.
Insertion and oldest-insertion compaction happen in the same catalog
transaction, so a committed mutation retains its actor, correlation ID, target
snapshots, and metadata while never leaving an over-cap audit table. Retention
uses SQLite insertion order rather than wall-clock timestamps, so clock
corrections cannot discard the audit for a newly committed mutation.
