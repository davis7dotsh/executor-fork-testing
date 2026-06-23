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
