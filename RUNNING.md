# Running the Rust and Svelte rewrite

This file describes the active local and self-hosted product. The archived
cloud and Electron entry points are under `legacy/` and are not part of the
default workflow.

## Fresh checkout

From the repository root:

```sh
bun run bootstrap
```

Bootstrap runs the workspace install and prepare hooks, then installs
Playwright Chromium. It is safe to rerun. The workspace currently declares Bun
1.3.11 and the native release workflow uses Rust 1.96.0.

## Production-like local run

The real Svelte dashboard is compiled first and embedded in the Rust release
binary:

```sh
bun run --cwd web build
cargo build --locked --release

mkdir -p .executor-local/data
chmod 0700 .executor-local/data
./target/release/executor server --data-dir "$PWD/.executor-local/data"
```

Open the setup URL printed by the process. The dashboard creates the
administrator and immediately signs in with those credentials. Add a source,
review its tool modes, and create an API token under `/tokens`.

The server binds to `127.0.0.1:4788` unless `--bind` changes it. Keep plaintext
HTTP on loopback. For another browser-facing hostname, terminate TLS at a
reverse proxy and set the exact external origin with `--public-origin` or
`EXECUTOR_PUBLIC_ORIGIN`.

On this WSL2 machine, the Windows browser can reach the loopback server. Open
it with:

```sh
/mnt/c/windows/explorer.exe http://127.0.0.1:4788
```

Use a worktree-specific data directory, as shown above, so concurrent checkouts
never share SQLite or the instance master key. One process lock protects each
data directory.

## Debug server without a web build

Normal debug compilation does not require `web/build`:

```sh
mkdir -p .executor-debug
chmod 0700 .executor-debug
cargo run -- server --data-dir "$PWD/.executor-debug"
```

Debug builds embed the deterministic fixture under `tests/fixtures/web-assets`.
This is useful for Rust API, CLI, MCP, and lifecycle work. It is not a visual
dashboard development server. Use the production-like sequence when the real
Svelte application must be present.

`EXECUTOR_WEB_ASSETS_DIR` is a compile-time packaging override for focused
asset tests. It is not a runtime static-directory setting.

## Client smoke test

Create a dashboard API token, then use the same binary as a client:

```sh
export EXECUTOR_API_TOKEN='token-shown-once-by-the-dashboard'

./target/release/executor tools sources
./target/release/executor tools search 'health check'
./target/release/executor tools describe source_slug.tool_name
./target/release/executor call source_slug.tool_name '{}'
```

The server never auto-starts for client commands. `call`, `tools`, and `mcp`
require a running server and an API token. `open` only opens the clean dashboard
URL and uses the administrator login cookie in the browser.

## Managed OAuth callbacks

Set the final browser-facing origin before creating an OAuth connection:

```sh
./target/release/executor server \
  --data-dir "$PWD/.executor-local/data" \
  --public-origin https://executor.example.com
```

After importing an eligible OpenAPI, GraphQL, or HTTP MCP source, open its
**Managed OAuth** panel. Save the provider discovery and client configuration,
copy the exact displayed callback URL into the provider, then select **Connect
OAuth**. Every connection has its own callback path:

```text
/api/v1/oauth/callback/<connection-id>
```

The supported managed flow is OAuth 2 authorization code with PKCE. OpenID
Connect and the `openid` scope are not supported. See
[`docs/sources.md`](docs/sources.md).

## Verification

Use the narrowest relevant command while iterating. For a merge-ready change,
run the complete active-product gates:

```sh
bun run format:check
bun run lint
bun run typecheck
bun run test

bun run --cwd web format:check
bun run --cwd web lint
bun run --cwd web check
bun run --cwd web test

cargo fmt --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Use `vitest run ...` or a package script that delegates to Vitest for focused
TypeScript tests. Never use `bun test`.

## Browser e2e

`bun run test:e2e` builds the Svelte distribution, embeds it in the debug Rust
binary, and runs only the active `local-selfhost` browser project. The harness
boots two fresh loopback instances: one prepared single-admin instance for the
main journeys and one untouched instance for the first-boot setup journey.
Both use temporary private data directories that are removed during teardown.

The throwaway main-instance credentials are:

```text
username: admin
password: executor-e2e-admin-password
```

The archived cloud browser suite remains an explicit opt-in:

```sh
bun run legacy:test:e2e:cloud
```

Runs land under `e2e/runs/local-selfhost/<scenario>/`. View them with
`cd e2e && bun run serve`, then open the exact URL and port printed by the
viewer. Credential-entry journeys deliberately omit traces and video so setup
secrets, passwords, and one-time API tokens never become artifacts.

## Service and container runs

Do not invent service paths or flags from this file. Use the maintained
operator guides:

- [`docs/docker.md`](docs/docker.md)
- [`docs/systemd.md`](docs/systemd.md)
- [`docs/launchd.md`](docs/launchd.md)
- [`docs/install.md`](docs/install.md)

## Legacy opt-ins

Default dev, test, lint, typecheck, and format paths exclude the archived cloud
and desktop products. Work on them only through the explicit scripts:

```sh
bun run legacy:dev
bun run legacy:test
bun run legacy:typecheck
bun run legacy:typecheck:slow
bun run legacy:test:e2e:cloud
bun run legacy:test:e2e:desktop
```

See [`legacy/README.md`](legacy/README.md) for the boundary.
