# MCP support

Executor can sit on both sides of MCP:

- MCP clients connect to Executor's stateful Streamable HTTP endpoint at
  `/mcp`.
- Executor imports tools from upstream MCP servers over Streamable HTTP or
  local stdio.
- `executor mcp` adapts a local stdio-only MCP client to Executor's `/mcp`
  endpoint.

All three surfaces currently require MCP protocol version `2025-11-25`.
Executor does not negotiate an older protocol version.

The Rust package pins `rmcp` exactly at `1.8.0` for MCP model types. Executor
implements its HTTP and stdio transport boundaries locally so the gateway can
apply its own authentication, SSRF controls, process isolation, limits, and
lifecycle rules.

This slice supports MCP tools only. The downstream endpoint does not advertise
resources, prompts, completions, tasks, sampling, or elicitation. Upstream
discovery imports `tools/list`; other upstream capabilities are retained as
metadata but are not bridged into Executor surfaces.

## Connect an MCP client to Executor

The downstream endpoint is the instance public origin plus `/mcp`, for example
`http://127.0.0.1:4788/mcp`. Authenticate every non-preflight request with a
dashboard-generated API token:

```text
Authorization: Bearer <executor-api-token>
```

The endpoint uses the stateful Streamable HTTP lifecycle:

1. Send `initialize` without `MCP-Session-Id`.
2. Read the new `MCP-Session-Id` response header.
3. Send `notifications/initialized` with that session ID and
   `MCP-Protocol-Version: 2025-11-25`.
4. Include both headers on subsequent requests.
5. Send `DELETE /mcp` with both headers to close the session.

`POST /mcp` requires `Content-Type: application/json` and an `Accept` value
that permits both `application/json` and `text/event-stream`. Responses are
currently JSON request-response messages. `GET /mcp` does not open a server
event stream. After validating an initialized session it returns HTTP 405 with
`Allow: POST, DELETE, OPTIONS`.

Sessions belong to the API token that initialized them. A different token sees
the session as missing. Sending `DELETE /mcp`, revoking the owning API token,
or lazily pruning an idle-expired session terminates that session and cancels
its active waits. A pending Ask released by session termination cannot execute
later. Initialized sessions expire after eight idle hours; incomplete
handshakes expire after five idle minutes. The server allows 32 sessions per
API token and 4,096 sessions for the instance, returning service unavailable
when either capacity is full. Downstream session IDs are at most 128 printable
ASCII bytes.

Browser-origin requests must use the configured public origin. Executor checks
both `Host` and `Origin` before authentication and emits narrowly scoped CORS
headers for that origin. Repeated security-sensitive headers are rejected.

### Virtual tools

`tools/list` always returns five Executor-owned tools. It does not return every
upstream tool as a separate MCP tool.

| Tool       | Purpose                                                                                                                                                                  |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `execute`  | Run up to 1 MiB of sandboxed TypeScript that can discover and call multiple Executor tools concurrently. Accepts `code` and optional `timeoutMs` from 1 through 300,000. |
| `call`     | Call one catalog tool by a 1 through 512 byte `path`, with an optional `arguments` object. Ask-mode tools wait for administrator approval.                               |
| `search`   | Search the enabled global catalog by `query`, optional `namespace`, `limit`, and `offset`. The limit is 1 through 100 and defaults to 20.                                |
| `describe` | Return schemas and metadata for one enabled catalog tool by a 1 through 512 byte `path`.                                                                                 |
| `sources`  | List sources that currently expose tools through the global catalog.                                                                                                     |

Tool paths use `tools.<source_slug>.<tool_name>`. Disabled tools remain
unavailable. Imported tools are intrinsically `enabled` only when the upstream
explicitly marks them read-only without also marking them destructive. All
other imported MCP tools default to `ask` mode.

For `tools/call`, the MCP JSON-RPC request ID is part of the idempotency identity
and cancellation correlation. Numeric and string IDs are distinct; string IDs
are at most 256 bytes and cannot contain a NUL character. Reusing an ID for a
different virtual-tool invocation is rejected. `notifications/cancelled` is
scoped to an in-flight `tools/call` in the same session. A call that may already
have reached an upstream MCP server is never silently replayed.

### Local stdio bridge

For clients that can launch only a stdio MCP server, configure them to run:

```sh
EXECUTOR_API_TOKEN='<dashboard-token>' \
  executor --base-url http://127.0.0.1:4788 mcp
```

The bridge keeps stdout protocol-only, forwards requests concurrently, reserves
capacity for cancellation notifications, and closes the HTTP session on exit.
It allows eight ordinary requests in flight, with a separate ceiling of 16
while admitting cancellations. Non-loopback plaintext HTTP is rejected unless
the client command also receives `--allow-insecure-http`.

## Add upstream MCP sources

MCP source management uses the same administrator routes as other protocols:

- `POST /api/v1/sources`
- `POST /api/v1/sources/{id}/refresh`
- `GET`, `PUT`, and `DELETE /api/v1/sources/{id}/credentials`
- `GET /api/v1/mcp/stdio/templates`

Reads require the administrator session cookie. Mutations additionally require
the matching Origin and CSRF cookie/header pair. The dashboard is the normal
way to satisfy these controls. The JSON below documents the protocol payloads
for API clients that already implement administrator authentication.

### Streamable HTTP source

Create a remote HTTP source with `kind: "mcp_http"`:

```json
{
  "kind": "mcp_http",
  "displayName": "Issue tracker",
  "preferredSlug": "issues",
  "description": "Internal issue tools",
  "endpoint": "https://mcp.example.com/mcp",
  "allowPrivateNetwork": false,
  "credential": {
    "type": "bearer",
    "token": "secret"
  }
}
```

`preferredSlug`, `description`, and `credential` are optional.
`allowPrivateNetwork` defaults to `false`. The endpoint must be an absolute
HTTP or HTTPS URL without user information or a fragment. A query string is
allowed, but it is encrypted with the credential state and removed from the
public source configuration.

The HTTP credential is one of:

```json
{ "type": "bearer", "token": "secret" }
```

```json
{ "type": "basic", "username": "user", "password": "secret" }
```

```json
{ "type": "api_key_header", "name": "X-Api-Key", "value": "secret" }
```

```json
{ "type": "oauth_access_token", "accessToken": "secret" }
```

The OAuth form above is a manually supplied access token. For managed OAuth,
leave the static credential empty and configure the source's `default`
credential in the dashboard's Managed OAuth panel. HTTP MCP sources use
protected-resource and authorization-server discovery, PKCE authorization-code
callbacks, encrypted refresh-token storage, and just-in-time access tokens.
Static credentials take precedence when one is configured. Stdio MCP sources
do not expose managed OAuth.

Transport-owned headers cannot be used for `api_key_header`. This includes
`Authorization`, `Host`, `Content-Type`, `Accept`, length and connection
headers, `MCP-Session-Id`, `MCP-Protocol-Version`, `Origin`, `Referer`, and
proxy headers.

Replace the HTTP credential with optimistic concurrency:

```json
{
  "expectedRevision": 3,
  "credential": {
    "credential": {
      "type": "bearer",
      "token": "replacement"
    }
  }
}
```

For a non-null replacement, Executor discovers with the candidate credential
first. One SQLite transaction then replaces the encrypted credential and
refreshes artifacts, bindings, tools, health, and revisions. Discovery or
commit failure leaves the prior credential, catalog, and watcher unchanged.

Use `"credential": null` inside the protocol credential object to remove HTTP
authentication without changing the endpoint. Executor first attempts
anonymous discovery. On success, one SQLite transaction clears the credential
and refreshes the catalog. After commit, Executor installs a replacement
watcher only when the refreshed capabilities advertise `tools.listChanged`. If
anonymous discovery fails, Executor still commits the credential clear together
with unknown source health, preserves the last known catalog, and leaves its
watcher stopped. A failed clear commit preserves the old database state and
reinstalls its prior watcher. `GET` returns only the revision and configured
credential type, never secret values.

### Stdio source templates

Arbitrary commands are never accepted through the source API. The machine
administrator must first approve every executable, argument, working directory,
and non-secret environment value in a strict JSON template file. Start the
server with either form:

```sh
executor server --mcp-stdio-templates /absolute/path/to/mcp-stdio.json
```

```sh
EXECUTOR_MCP_STDIO_TEMPLATES_FILE=/absolute/path/to/mcp-stdio.json executor server
```

If neither is set, the registry is empty and HTTP MCP sources remain
available. If a path is set, an unreadable or invalid file fails server
startup.

The file has exactly this top-level shape:

```json
{
  "templates": [
    {
      "name": "filesystem",
      "executable": "/absolute/path/to/mcp-server",
      "cwd": "/absolute/path/to/approved-directory",
      "arguments": ["--stdio"],
      "environment": {
        "LOG_LEVEL": "warn"
      },
      "secretEnvironment": ["API_TOKEN"]
    }
  ]
}
```

`cwd`, `arguments`, `environment`, and `secretEnvironment` are optional. Unknown
fields fail startup. Template names contain only ASCII letters, digits, `_`, or
`-` and are at most 64 bytes. Template names must be unique. Executables and
working directories must be absolute and are canonicalized when the registry
loads. The executable must be a regular executable file, and `cwd` must be a
directory.

The configuration file is limited to 1 MiB and 256 templates. Each template
allows at most 128 arguments. The final static-plus-secret environment allows
at most 128 entries. An argument is at most 8 KiB, an environment value is at
most 16 KiB, and the combined argument or environment data for a template is
at most 128 KiB. Environment names use shell-style identifiers. A secret field
cannot duplicate a static environment entry.

Child processes receive a clean environment containing only the approved
static entries plus the exact secret overlay. On Unix, each child receives its
own process group. Graceful shutdown escalates to killing that process group,
including descendants that remain alive.

Executor does not enforce ownership or write permissions for the template
file, executable, or their ancestor directories. The machine administrator is
responsible for protecting those paths from untrusted modification.

After server startup, discover the non-secret template descriptors at
`GET /api/v1/mcp/stdio/templates`:

```json
{
  "templates": [
    {
      "name": "filesystem",
      "secretFields": ["API_TOKEN"]
    }
  ]
}
```

Create a source with a template name, never an executable path:

```json
{
  "kind": "mcp_stdio",
  "displayName": "Local filesystem",
  "preferredSlug": "files",
  "description": "Approved local file tools",
  "templateName": "filesystem",
  "secretValues": {
    "API_TOKEN": "secret"
  }
}
```

`preferredSlug`, `description`, and `secretValues` are optional. If a template
declares secrets and `secretValues` is omitted or empty, Executor creates an
empty source without starting the process. A later credential update must
supply every declared secret and no others, then discovery runs. Credential
replacement uses:

```json
{
  "expectedRevision": 0,
  "credential": {
    "secretValues": {
      "API_TOKEN": "replacement"
    }
  }
}
```

Credential replacement discovers first, then commits the encrypted credential
and refreshed catalog atomically. A discovery failure leaves both unchanged.
Clear credentials with
`DELETE /api/v1/sources/{id}/credentials?expectedRevision=<revision>`. For HTTP
sources, the nested `"credential": null` PUT form described above has the same
clear semantics.

Clearing credentials for a template that declares secrets stops its catalog
watcher and leaves both the approved template selection and existing catalog
entries in place. The empty encrypted overlay and unknown source health commit
together; calls cannot start until complete credentials are restored.
Templates without secret fields treat the empty overlay as complete, discover
first, and atomically commit the empty credential plus refreshed catalog so the
source remains healthy.

## Discovery, refresh, and invocation lifecycle

When credentials are complete, source creation initializes the upstream, walks
every `tools/list` page, validates and normalizes the complete result, then
commits the source, encrypted credential envelope, capabilities artifact,
bindings, and tools atomically. A stdio source created without its required
secrets follows the deferred empty-source behavior described above. Discovery
permits at most 1,000 pages, 100,000 tools, 32 MiB of aggregate tool metadata,
5 MiB for one tool, 2 MiB for one schema, and 8 MiB of capability metadata.
Cursor cycles, duplicate tool names, malformed schemas, and unstable catalogs
fail the operation.

Refresh performs all upstream work before opening the catalog transaction. It
commits only if the source and credential revisions still match. A failed or
stale refresh leaves the existing catalog untouched. When the retained
credential state remains complete, that catalog remains callable. Upstream tool
names are stable keys, so refresh preserves Executor tool IDs, callable paths,
and administrator mode overrides.

If an upstream advertises `tools.listChanged`, Executor maintains a watcher and
coalesces notifications into bounded refreshes. Watchers are restored at
startup and run a full revision-fenced catalog reconciliation on every
successful initial or reconnect handshake before entering steady notification
handling. They are replaced after relevant credential changes, stopped before
source deletion, and drained during shutdown. Stdio watchers also heartbeat the
transport lifecycle so an idle child exit reconnects even without a
notification. If an HTTP upstream returns 405 to the notification-stream GET,
Executor lets the current revision-fenced reconciliation commit, then treats
live notifications as unsupported and exits that watcher without reconnecting.
Use manual refresh for later catalog changes from that upstream.

An invocation uses a fresh upstream connection and MCP session. Executor
initializes it, calls the named tool, then terminates or shuts down the session.
An upstream `isError: true` result becomes a failed Executor tool result with
code `upstream_tool_error`. Disconnects after a stdio tool call or transport
failures during an HTTP tool call are treated as outcome-unknown and are not
replayed.

## Transport safety and limits

Remote HTTP MCP uses the shared hardened outbound client. It allows only HTTP
and HTTPS, disables environment proxies and redirects, validates and pins DNS
answers, and blocks private targets unless the source explicitly opts in.
Link-local, cloud metadata, multicast, documentation, and reserved addresses
remain blocked even with private-network access enabled.

An MCP endpoint is capped at 8 KiB. The shared client limits a resolved host to
32 addresses, request bodies to 8 MiB, collected request-response bodies to 16
MiB, and request or response headers to 64 KiB. Connection setup has a
five-second timeout. The HTTP MCP transport adds a 30-second deadline to
request-response exchanges, a 16 MiB aggregate ceiling across request-response
SSE resumptions, at most 1,024 SSE events per exchange, at most three
resumptions, and session IDs capped at 1,024 visible ASCII bytes.

Long-lived notification streams have no cumulative byte or lifetime limit.
They use a five-minute per-read idle timeout; declared `Content-Length`, each
delivered body chunk, each undelimited parser line, and each accumulated SSE
event are independently capped at 16 MiB. A connection accepts at most 1,024
completed SSE events. Event 1,025 fails the listener, after which the source
watcher reconnects with backoff and a fresh MCP initialization. The transport
accepts only JSON or SSE response media types. Session changes, malformed
JSON-RPC, unsupported server requests, and invalid content types fail closed.
Server `ping` requests are answered; other server-initiated requests receive
method not found.

The stdio transport defaults to a 16 MiB message limit, 64 KiB stderr
accounting ceiling, 60-second request timeout, two-second shutdown grace, and a
256-command queue. Stderr is continuously drained and is not exposed or stored;
only the exit code and whether the accounting ceiling was exceeded survive
internally. The transport restarts a failed process with bounded exponential
backoff, but a restart requires a new MCP initialization. It does not retry a
tool call after bytes may have reached the child.

The downstream `/mcp` body limit is the 8 MiB tool-argument ceiling plus a
64 KiB protocol envelope. Bearer tokens are capped at 512 bytes. Body admission
is limited to 16 requests for the instance and four per token. Detached
execution is independently limited to 16 for the instance and four per token,
leaving a control lane available for cancellation notifications. Body
saturation returns HTTP 429 with `mcp_busy`; execution saturation returns a
JSON-RPC `-32603` error. The cancellation registry is capped at 4,096 active
requests, with at most 128 short-lived pre-cancellation records per session.
Pre-cancellation records expire after 60 seconds. Pending Ask calls use the
durable ten-minute approval TTL, and expiry settlement is checked at intervals
of at most 30 seconds. There is no separate MCP transport wait timeout.
`notifications/cancelled` explicitly cancels the matching request wait;
`DELETE /mcp`, API-token revocation, and lazy idle-session expiry cancel all
session-scoped waits.
