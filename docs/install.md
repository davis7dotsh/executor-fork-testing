# Install and run Executor

Executor ships as one native binary with its Svelte dashboard embedded. The
supported native targets are Linux and macOS on x86-64 and ARM64. Windows is not
supported. The macOS archives require macOS 14 Sonoma or newer. Docker images
support Linux `amd64` and `arm64`.

## Prerequisites

Building from a checkout requires Bun 1.3.x, Rust 1.96 or newer, a C toolchain,
and the normal SQLite build prerequisites for the platform. The workspace
declares Bun 1.3.11 and the release workflow currently uses Rust 1.96.0.

Run `bun run bootstrap` once in a fresh checkout. It installs workspace
dependencies, prepares retained TypeScript packages, and installs Playwright
Chromium for browser scenarios.

## Release archive

The manual native release workflow publishes checksum-verified archives to the
matching GitHub release. Install the latest supported archive with:

```sh
curl -fsSL https://raw.githubusercontent.com/davis7dotsh/executor-fork-testing/main/scripts/install.sh | bash
```

The installer and native release workflow use
`davis7dotsh/executor-fork-testing` as the current publishing origin. Export
`EXECUTOR_REPOSITORY` before running the script to install from another fork:

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

On macOS, `executor service install` creates a separate managed copy at
`$HOME/.executor/service/bin/executor`. Archive install, upgrade, and uninstall
preserve the complete `$HOME/.executor/service` subtree. Service lifecycle
commands likewise leave the archive-owned `$HOME/.executor/bin` subtree alone.

The macOS command-line archive is not Developer ID signed or notarized. Use the
curl installer above, which verifies the release checksum before installation,
or download with `gh` and perform the checksum and immutable GitHub Release
verification checks below.
Browser-downloaded quarantined binaries are not a supported Gatekeeper
distribution path. The workflow sets `MACOSX_DEPLOYMENT_TARGET=14.0` and rejects
an archive whose Mach-O minimum does not match that support floor.

### Uninstall a user-level archive installation

If a managed service was installed, remove it while the binary is still
available. Skip the matching command when no service was installed:

```sh
# Linux system service
sudo "$(command -v executor)" service remove

# macOS per-user LaunchAgent, never use sudo
executor service remove
```

Then run the same installer in uninstall mode:

```sh
curl -fsSL https://raw.githubusercontent.com/davis7dotsh/executor-fork-testing/main/scripts/install.sh \
  | bash -s -- --uninstall
```

For a custom location, export the same absolute `EXECUTOR_INSTALL_DIR` used at
install time before running that command. Uninstall removes only `executor`,
the three installed notice files, and the exact `# Executor` PATH block added
by the installer. It preserves all databases, master keys, service definitions,
other files in the install directory, and every other shell configuration line.
Use `--no-modify-path` with `--uninstall` to leave shell configuration untouched.
The operation is safe to repeat. Each successful install records the exact
owned filenames and SHA-256 hashes in a private manifest. Installation refuses
to overwrite an unowned file, and uninstall fails closed if an owned file or the
manifest was replaced. Review and resolve such a replacement manually instead
of deleting it as though the installer still owned it. Before changing owned
files, installation publishes private rollback state. A later install or
uninstall automatically restores that state after an interrupted mutation,
while a partially completed uninstall resumes around already-removed owned
files. The ownership state also records every exact shell-config path and PATH
command the installer added, so uninstall cleans the original block even when
the current shell or `ZDOTDIR` has changed.

Install, recovery, PATH updates, and uninstall hold one private lock under the
validated install directory. A custom install path must be normalized, contain
no symbolic-link components, and have only root- or current-user-owned
ancestors with no group or world write permission. The installer pins the
parent and leaf directory identities before any owned-file mutation. A
concurrent invocation exits with the live owner PID. A lock left by a crashed
process is reclaimed only after its recorded process-birth identity no longer
matches, which also protects against PID reuse. Managed file renames, rollback
restoration, manifest publication, recovery retirement, and uninstall deletion
are separated by stock `sync` durability barriers. Shell-configuration edits
use a portable adjacent ownership lock, atomic replacement, and content checks
so different install roots cannot lose one another's PATH updates. The release
installer has no Python runtime dependency.

The release artifact workflow creates these archives and matching `.sha256`
sidecars:

- `executor-x86_64-unknown-linux-gnu.tar.gz`
- `executor-aarch64-unknown-linux-gnu.tar.gz`
- `executor-x86_64-apple-darwin.tar.gz`
- `executor-aarch64-apple-darwin.tar.gz`

Each archive also contains the project `LICENSE`, the generated Rust
`THIRD_PARTY_LICENSES.html` inventory, and Vite's bundle-derived embedded-web
`THIRD_PARTY_JAVASCRIPT_LICENSES.json` inventory. The Linux binaries require
glibc 2.35 or newer, matching the Ubuntu 22.04 release baseline. The release
workflow inspects symbol versions and rejects a binary above that ceiling. Use
Docker on older Linux distributions.

The `executor` binary embeds the maintained systemd unit, LaunchAgent template,
bounded log helper, and hardened installer logic. A downloaded release binary
can therefore install its service without a source checkout.

The workflow creates `SHA256SUMS`, runs every target natively, smoke-tests each
binary, and publishes the GitHub release as immutable. Verify both the checksum
manifest and GitHub's immutable release records before installing a downloaded
archive:

```sh
tag=v2.0.0
repository=OWNER/REPOSITORY
mkdir release-assets
gh release download "$tag" --repo "$repository" --dir release-assets
if command -v sha256sum >/dev/null 2>&1; then
  (cd release-assets && sha256sum --check SHA256SUMS)
else
  (cd release-assets && shasum -a 256 --check SHA256SUMS)
fi
gh release verify "$tag" --repo "$repository"
for archive in release-assets/executor-*.tar.gz; do
  gh release verify-asset "$tag" "$archive" --repo "$repository"
done
```

The release workflow accepts an exact full commit SHA and tag, checks that the
tag is `v<Cargo.toml version>`, and verifies that the remote tag resolves to the
same commit before publishing. The GitHub release remains a draft until the
archives, checksums, and root Docker image have all succeeded. Publishing the
draft creates the immutable release record checked by the commands above.

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
random raw regular file from a secure random source or secret manager, give it
exactly one hard link, and pass `--master-key-file` or
`EXECUTOR_MASTER_KEY_FILE`. A key owned by Executor's effective user must use
mode `0400` or `0600`. A root-owned secret-manager file may use `0400`, `0440`,
`0600`, or `0640`; group-readable modes work only when Executor belongs to that
group. This setting is a file path, never key material.
Do not use a password, repeated bytes, hand-authored content, hex text, or
base64 text as the key. Executor does not create, chmod, rotate, or recover an
external key. Files owned by another user, symbolic links, non-regular files,
additional hard links, and broader permissions fail closed. Include that file
in the same stopped recovery snapshot as the data directory. Losing the key
makes protected credentials, OAuth tokens, approvals, and results
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

After installing the release binary, install the native service directly:

```sh
# Linux system service
sudo "$(command -v executor)" service install

# macOS per-user LaunchAgent, never use sudo
executor service install
```

Use `--no-start` to install while leaving the service stopped. The same binary
provides `service status`, `start`, `stop`, `restart`, and `remove`. Removal
preserves persistent data and configuration. A private ownership manifest
binds later lifecycle mutations to the exact service files installed by this
workflow, so replacing a managed file outside `service install` fails closed.
On macOS, reinstall preserves the stored data directory, template file, public
origin, and trusted proxy list unless the corresponding environment variable
is explicitly supplied.

- [Linux systemd service](systemd.md)
- [macOS LaunchAgent](launchd.md)
- [Docker Compose](docker.md)

MCP stdio templates are machine-admin allowlists. Every approved executable is
fully trusted because it runs with Executor's operating-system identity and can
access its data and master key. See [MCP support](mcp.md) for the exact template
schema and transport limits.
