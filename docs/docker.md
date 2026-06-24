# Run Executor with Docker

The root `Dockerfile` builds the Svelte application and embeds it into the Rust
binary. Its runtime image contains that one binary plus CA certificates and the
healthcheck client. Project and dependency license notices are installed under
`/usr/share/licenses/executor`. It supports Linux `amd64` and `arm64` images.

## Start the local instance

```sh
docker compose up --detach --build
docker compose logs executor
```

Open `http://127.0.0.1:4788`. On first boot, the logs contain the one-time setup
URL. The compose configuration publishes the port only on host loopback. Keep
that binding when using plain HTTP.

The named `executor-data` volume contains SQLite state, its WAL files, and the
generated `master.key`. Back up the whole volume while the service is stopped.
The database and key are one recovery unit. Losing the key makes encrypted
credentials and protected state unrecoverable, and inventing a new key beside
an existing database is intentionally rejected.

```sh
docker compose stop executor
# Snapshot the complete executor-data volume with your normal volume backup tool.
docker compose start executor
```

If you configure `EXECUTOR_MASTER_KEY_FILE`, the mounted key must contain
exactly 32 cryptographically random raw bytes from a secure random source or
secret manager and be readable by UID `10001`. Do not use a password, repeated
bytes, hand-authored content, hex text, or base64 text. Include that external
file in the same stopped recovery snapshot as the volume. Executor does not
create, chmod, rotate, or recover an external key.

The shipped Compose file does not pass this optional variable by default. Add
an override such as:

```yaml
services:
  executor:
    environment:
      EXECUTOR_MASTER_KEY_FILE: /run/secrets/executor-master.key
    volumes:
      - ./secrets/executor-master.key:/run/secrets/executor-master.key:ro
```

The container runs as UID and GID `10001`, uses a read-only root filesystem,
drops Linux capabilities, and receives a private temporary filesystem. If an
external backup or secret manager creates mounted files, make them readable by
UID `10001` without making them writable by other users.

## HTTPS reverse proxy

Leave the compose port bound to host loopback and set the exact browser-facing
origin before starting the service:

```sh
EXECUTOR_PUBLIC_ORIGIN=https://executor.example.com docker compose up --detach
```

Terminate TLS in a reverse proxy on the same host and forward to
`127.0.0.1:4788`. The compose file passes through
`EXECUTOR_TRUSTED_PROXIES` only when that host variable is set. Configure it
only when Executor must use forwarded client addresses, and include only the
proxy CIDRs that directly append or replace `X-Forwarded-For`.

## MCP stdio templates

The default mounted registry is empty and boot-safe. Start a private registry
from the full example:

```sh
mkdir -p .executor-local
cp docker/mcp-stdio-templates.full.example.json \
  .executor-local/mcp-stdio-templates.json
```

Edit the `compose.yaml` bind mount so its host side is
`./.executor-local/mcp-stdio-templates.json`, then mount each referenced Linux
executable and working directory at its exact absolute container path.

The runtime image does not include Node.js or Bun. Mounted stdio servers must be
self-contained Linux executables for the image architecture, or you must derive
a runtime image containing their dependencies. Treat every configured stdio
executable as fully trusted: it runs as Executor's UID and can read the data
volume and master key.

## Multi-platform image check

Release automation can build both supported architectures from the same file:

```sh
docker buildx build --platform linux/amd64,linux/arm64 --file Dockerfile .
```

The native artifact workflow currently builds release archives without
publishing this root Rust image. A separate older workflow still publishes the
previous TypeScript self-host image, so do not treat that tag as this rewrite
until the release wiring is updated.
