# Executor

Executor is a single-user, self-hosted tool gateway for AI agents. One Rust
binary serves the Svelte dashboard, stores state in SQLite, exposes an MCP
endpoint, and runs concurrent TypeScript tool workflows in isolated QuickJS
workers.

The active product supports:

- OpenAPI, GraphQL, and MCP sources
- API key, bearer, basic, manual OAuth token, and managed OAuth credentials
- one global tool catalog with Enabled, Ask, and Disabled modes
- interactive approval for sensitive calls
- a stateful Streamable HTTP MCP endpoint and a local stdio bridge
- native Linux and macOS binaries, plus Docker

Windows is not a release target. The previous TypeScript CLI, local app,
hosted deployments, managed cloud, and Electron products are archived in
[`legacy/`](legacy/README.md).

`Cargo.toml` is the native product version source. Published releases provide
four checksum-verified Linux and macOS archives plus the multi-platform
`ghcr.io/<repository-owner>/executor` image. See [installation](docs/install.md)
and [release operations](RELEASING.md).

## Try it from this checkout

The production binary embeds the dashboard, so the web build must run before
the release Cargo build. From the repository root:

```sh
bun run bootstrap
bun run --cwd web build
cargo build --locked --release

mkdir -p .executor-local/data
chmod 0700 .executor-local/data
./target/release/executor server --data-dir "$PWD/.executor-local/data"
```

This checkout expects Bun 1.3.x and Rust 1.96 or newer. The release workflow
currently pins Bun 1.3.11 and Rust 1.96.0.

Executor listens at `http://127.0.0.1:4788` by default. Open the one-time
`/setup#token=...` URL printed by the server and create the only administrator
account with a password of at least 12 characters. The dashboard then signs in
with those credentials. Open **API tokens** and create a token for your client.
The token secret is shown once.

On WSL2, paste the setup URL into the Windows browser. You can also open the
dashboard from the WSL shell after setup:

```sh
/mnt/c/windows/explorer.exe http://127.0.0.1:4788
```

State is under `.executor-local/data` in this example. Stop the server before
copying that directory for backup, and keep `executor.db`, its WAL files, and
`master.key` together.

## Connect sources

Open **Sources**, choose a connector, and follow the preview or connection
flow:

- OpenAPI accepts a URL or pasted OpenAPI 3.0/3.1 JSON or YAML.
- GraphQL connects to an introspection-enabled endpoint.
- MCP Streamable HTTP connects to a remote or local HTTP MCP endpoint.
- MCP stdio selects only a machine-admin-approved command template.

After import, review each source under **Tools**. GraphQL queries start Enabled,
mutations start Ask, and deprecated operations start Disabled. MCP tools are
Enabled only when the upstream explicitly marks them read-only and not
destructive. Other MCP tools start Ask.

See [source and OAuth setup](docs/sources.md) and the detailed
[MCP contract](docs/mcp.md).

## Use the CLI

Client commands talk to an already-running Executor server. They never open a
second copy of the database.

```sh
./target/release/executor --version
export EXECUTOR_API_TOKEN='token-shown-by-the-dashboard'

./target/release/executor tools sources
./target/release/executor tools search 'create issue'
./target/release/executor tools describe source_slug.tool_name
./target/release/executor call source_slug.tool_name '{"input":"value"}'
```

Use `--base-url` or `EXECUTOR_BASE_URL` for another instance. Remote instances
must use HTTPS unless you deliberately pass `--allow-insecure-http` on a
separately authenticated and encrypted tunnel. A private LAN alone does not
protect the bearer token. See the [CLI guide](docs/cli.md).

## Use Executor as an MCP server

For clients that support Streamable HTTP, use the instance origin plus `/mcp`
and send the dashboard API token as a bearer token. Client configuration
schemas differ, so treat this as a schematic shape and adapt it to the selected
client's MCP documentation:

```json
{
  "mcpServers": {
    "executor": {
      "type": "http",
      "url": "http://127.0.0.1:4788/mcp",
      "headers": {
        "Authorization": "Bearer <EXECUTOR_API_TOKEN>"
      }
    }
  }
}
```

For a client that launches only stdio MCP servers, the common shape is:

```json
{
  "mcpServers": {
    "executor": {
      "command": "/absolute/path/to/executor",
      "args": ["mcp"],
      "env": {
        "EXECUTOR_API_TOKEN": "<EXECUTOR_API_TOKEN>"
      }
    }
  }
}
```

The bridge connects to `http://127.0.0.1:4788` by default. Set
`EXECUTOR_BASE_URL` when the server uses another origin.

## Install and operate

- [Native install and first boot](docs/install.md)
- [Docker Compose](docs/docker.md)
- [Linux systemd](docs/systemd.md)
- [macOS launchd](docs/launchd.md)
- [Runtime and sandbox boundary](docs/runtime.md)
- [Architecture and security contracts](docs/architecture.md)

For a reverse proxy or managed OAuth, set `EXECUTOR_PUBLIC_ORIGIN` to the exact
HTTPS origin used in the browser before starting Executor. Callback URLs are
connection-specific and are displayed in the source's Managed OAuth panel.

## Develop and verify

`bun run bootstrap` installs workspace dependencies, prepares the retained
TypeScript packages, and installs Playwright Chromium.

A debug Rust server does not require production web assets:

```sh
mkdir -p .executor-debug
chmod 0700 .executor-debug
cargo run -- server --data-dir "$PWD/.executor-debug"
```

Debug builds intentionally embed a small fixture page. That path is suitable
for API, CLI, and MCP work, not dashboard acceptance. Use the release build
sequence above when you need the real embedded Svelte application.

The broad merge gates are:

```sh
bun run format:check
bun run lint
bun run typecheck
bun run test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
bun run test:e2e
```

The e2e command builds the Svelte assets and a local debug Rust binary before
driving the real first-boot, source, tool-mode, approval, log, token, and OAuth
journeys in Chromium.

See [`RUNNING.md`](RUNNING.md) for the current repository workflow and e2e
status. Default commands exclude all archived application packages.

## License

MIT
