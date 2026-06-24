# Install and run Executor

Executor ships as one native binary with its Svelte dashboard embedded. The
supported native targets are Linux and macOS on x86-64 and ARM64. Windows is not
supported. Docker images support Linux `amd64` and `arm64`.

## Prerequisites

Building from a checkout requires Bun 1.3.x, Rust 1.96 or newer, a C toolchain,
and the normal SQLite build prerequisites for the platform. The workspace
declares Bun 1.3.11 and the release workflow currently uses Rust 1.96.0.

Run `bun run bootstrap` once in a fresh checkout. It installs workspace
dependencies, prepares retained TypeScript packages, and installs Playwright
Chromium for browser scenarios.

## Release archive

The native artifact workflow currently uploads archives to GitHub Actions but
does not publish them to a GitHub Release. Until a release owner publishes
those files, use the source-build or Docker path below. After a release is
published, install its checksum-verified archive with:

```sh
curl -fsSL https://raw.githubusercontent.com/RhysSullivan/executor/main/scripts/install.sh | bash
```

Export the repository before running the script when using a fork:

```sh
export EXECUTOR_REPOSITORY=owner/repository
curl -fsSL "https://raw.githubusercontent.com/$EXECUTOR_REPOSITORY/main/scripts/install.sh" | bash
```

Forward installer options after `bash -s --`, for example:

```sh
curl -fsSL "https://raw.githubusercontent.com/$EXECUTOR_REPOSITORY/main/scripts/install.sh" \
  | bash -s -- --version 2.0.0 --no-modify-path
```

The installer defaults to
`$HOME/.executor/bin`. Start a new shell, source its configuration file, or use
`$HOME/.executor/bin/executor` until the updated PATH is active.

The release artifact workflow creates these archives and matching `.sha256`
sidecars:

- `executor-x86_64-unknown-linux-gnu.tar.gz`
- `executor-aarch64-unknown-linux-gnu.tar.gz`
- `executor-x86_64-apple-darwin.tar.gz`
- `executor-aarch64-apple-darwin.tar.gz`

Each archive also contains the project `LICENSE`, the generated Rust
`THIRD_PARTY_LICENSES.html` inventory, and Vite's bundle-derived embedded-web
`THIRD_PARTY_JAVASCRIPT_LICENSES.json` inventory. The Linux binaries require
glibc 2.35 or newer, matching the Ubuntu 22.04 release baseline. Use Docker on
older Linux distributions.

The workflow creates `SHA256SUMS`, runs every target natively, smoke-tests each
binary, and records GitHub build-provenance attestations for the archives. The
current workflow uploads Actions artifacts only. Publishing remains an
explicit, human-approved release action:

```sh
tag=v2.0.0
run_id=RUN_ID
git fetch origin "refs/tags/$tag:refs/tags/$tag"
test "$(gh run view "$run_id" --json workflowName --jq .workflowName)" = \
  "Build release artifacts"
test "$(gh run view "$run_id" --json event --jq .event)" = push
test "$(gh run view "$run_id" --json conclusion --jq .conclusion)" = success
test "$(gh run view "$run_id" --json headBranch --jq .headBranch)" = "$tag"
test "$(gh run view "$run_id" --json headSha --jq .headSha)" = \
  "$(git rev-parse "$tag^{commit}")"
gh run download "$run_id" --name executor-release-artifacts --dir release-assets
(cd release-assets && sha256sum --check SHA256SUMS)
gh attestation verify release-assets/executor-x86_64-unknown-linux-gnu.tar.gz \
  --repo OWNER/REPOSITORY
gh release create "$tag" --draft --verify-tag
gh release upload "$tag" release-assets/*
```

Verify all four archive attestations before uploading. The run checks bind the
downloaded artifacts to the exact tag commit, rather than an arbitrary manual
workflow run. Publishing the draft is a separate deliberate action. The
installer becomes operational only after the archives and checksum sidecars
are attached to that GitHub Release.

## Build a local release binary

Install the prerequisites above, then run from the repository root:

```sh
bun run bootstrap
bun run --cwd web build
cargo build --locked --release
./scripts/install.sh --binary ./target/release/executor
```

The web build must happen before the release Cargo build so `build.rs` can
embed the static application. Node.js or Bun is not required after compilation.

## First boot

For an easy-to-inspect local instance, choose an explicit private data
directory:

```sh
mkdir -p "$HOME/.executor-data"
chmod 0700 "$HOME/.executor-data"
"$HOME/.executor/bin/executor" server --data-dir "$HOME/.executor-data"
```

Executor binds to `127.0.0.1:4788` by default. Open the one-time setup URL
printed at startup and create the administrator login. The dashboard immediately
signs in with those credentials. If that follow-up login fails, sign in manually,
then generate API tokens under **API tokens**. Token secrets are shown once.
The setup token expires after 15 minutes and is replaced on a later boot until
an administrator is created.

The data directory contains the SQLite database, WAL and SHM files when
present, process lock, and generated `master.key`. Back up the complete
directory only while Executor is stopped. Keep the database and key together
and private.

To use an externally managed key, supply an exact 32-byte cryptographically
random raw file from a secure random source or secret manager, restrict it to
the Executor service identity, and pass `--master-key-file` or
`EXECUTOR_MASTER_KEY_FILE`. This setting is a file path, never key material.
Do not use a password, repeated bytes, hand-authored content, hex text, or
base64 text as the key. Executor does not create, chmod, rotate, or recover an
external key. Include
that file in the same stopped recovery snapshot as the data directory. Losing
the key makes protected credentials, OAuth tokens, approvals, and results
unrecoverable.

Use `--public-origin https://executor.example.com` when a local HTTPS reverse
proxy exposes the dashboard at another origin. An HTTPS public origin does not
encrypt or firewall Executor's own listener. Keep the listener on loopback, or
enforce network isolation so clients can reach it only through the TLS proxy.
Do not expose the raw plaintext port.

The one-time setup URL is a secret until setup completes. It may appear in the
terminal, journal, or private service log, so protect those logs accordingly.

## Server configuration

| Environment variable                | Server flag             | Purpose                                        |
| ----------------------------------- | ----------------------- | ---------------------------------------------- |
| `EXECUTOR_DATA_DIR`                 | `--data-dir`            | SQLite, lock, and default master-key directory |
| `EXECUTOR_MASTER_KEY_FILE`          | `--master-key-file`     | Existing raw 32-byte master-key file           |
| `EXECUTOR_MCP_STDIO_TEMPLATES_FILE` | `--mcp-stdio-templates` | Trusted local MCP template registry            |
| `EXECUTOR_PUBLIC_ORIGIN`            | `--public-origin`       | Exact browser-facing HTTP or HTTPS origin      |
| `EXECUTOR_TRUSTED_PROXIES`          | `--trusted-proxy`       | Comma-separated trusted reverse-proxy CIDRs    |
| `RUST_LOG`                          | none                    | Rust tracing filter, default `executor=info`   |

`--bind` and `--allow-unsafe-http-non-loopback` intentionally have no
environment equivalents. Do not put credentials, API tokens, or raw key
material in service environment files.

Configure trusted proxies only when Executor must derive client addresses from
`X-Forwarded-For`. List only the actual proxy CIDRs, include every hop in the
chain, and configure each proxy to append or replace the header correctly. A
broad trust range can permit spoofed login identities, while an incomplete
chain causes forwarded logins to be rejected.

## Managed services and containers

- [Linux systemd service](systemd.md)
- [macOS LaunchAgent](launchd.md)
- [Docker Compose](docker.md)

MCP stdio templates are machine-admin allowlists. Every approved executable is
fully trusted because it runs with Executor's operating-system identity and can
access its data and master key. See [MCP support](mcp.md) for the exact template
schema and transport limits.
