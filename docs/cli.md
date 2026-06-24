# Rust CLI

The `executor` binary is both the self-hosted server and its local client. Client
commands connect to a running server. They do not open the SQLite database or
start another server. The server never auto-starts for a client command.

## Connection

The default server is `http://127.0.0.1:4788`. Override it with
`--base-url` or `EXECUTOR_BASE_URL`. Sign in as the administrator, create an
API token under **API tokens**, and provide it through `EXECUTOR_API_TOKEN`:

```sh
export EXECUTOR_API_TOKEN='copy-the-token-from-the-dashboard'
executor tools search calendar
```

You can also use `--api-token`, but the environment variable avoids placing a
secret in shell history or process arguments. Tokens are sent only in the
Authorization header. Executor never puts them in URLs.

Plain HTTP is accepted only for localhost and literal loopback addresses. Use
HTTPS for another host. `--allow-insecure-http` is an explicit escape hatch for
an authenticated and encrypted tunnel or equivalent transport that protects
the complete path. It sends the reusable bearer token over clear HTTP, so a
private LAN by itself is not sufficient protection.

Use `--json` for machine-readable output. Errors and approval instructions go
to stderr, leaving stdout available for JSON and MCP protocol messages.

Connection, authentication, validation, and protocol failures exit nonzero. An
upstream tool failure is a completed call: `--json` prints its result envelope
and the process exits successfully. Automation must inspect the envelope's
`ok` and `error` fields instead of treating exit status alone as tool success.

## Tools

Search the non-disabled global catalog. Enabled and Ask tools are discoverable;
Disabled tools are omitted:

```sh
executor tools search issue
executor tools search issue --namespace github --limit 25
executor tools describe github.issues_create
executor tools sources
```

Call a tool with a dotted path or two path segments. Arguments must be one JSON
object. Prefix a filename with `@` to read the object from disk.

```sh
executor call github.issues_create '{"owner":"acme","repo":"app","title":"Bug"}'
executor call github issues_create @arguments.json
```

Paths contain exactly the source slug and local tool name. A leading `tools.`
is accepted for a dotted path, but deeper legacy resource or method segments
are not.

Each call gets one idempotency key that remains stable across safe HTTP retries. An
Ask-mode tool prints and opens the clean dashboard approval URL, then polls as
the owning API token until the approval completes. Press Ctrl-C to request
cancellation.

## MCP stdio bridge

Configure a local MCP client to launch:

```sh
executor mcp
```

The bridge forwards newline-delimited MCP JSON-RPC over stdio to the running
authenticated `/mcp` endpoint. It preserves the server session, writes only MCP
messages to stdout, and closes the session on EOF or Ctrl-C. The server must
already be running.

## Dashboard

Open the dashboard without putting credentials in the URL. This command does
not require an API token. The browser still requires the administrator login
cookie:

```sh
executor open
```

This uses `open` on macOS and `xdg-open` on Linux. If no graphical opener is
available, the CLI prints the clean URL so it can be copied manually.
