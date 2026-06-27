# Linux systemd service

Executor ships a hardened system service for Linux distributions that use
systemd. It runs as a dedicated unprivileged `executor` account and listens on
`127.0.0.1:4788` by default.

## Install

Install or download the Executor release binary, then run its embedded service
installer:

```sh
sudo "$(command -v executor)" service install
```

Using the resolved path matters on first install because `sudo` commonly omits
the user's `$HOME/.executor/bin` directory from its secure PATH. After the
managed copy exists at `/usr/local/bin/executor`, ordinary `sudo executor ...`
commands work.

The release binary contains the hardened installer, unit, environment template,
and master-key helper. A source checkout is not required.

Use `--no-start` to inspect or customize the installed files before the first
boot. If Executor is already running, the installer stops it before inspecting
managed directories or files. `--no-start` deliberately leaves that service
stopped.

The installer is safe to run again during an upgrade. It replaces the binary
and unit but never replaces the master key, environment file, or MCP stdio
template registry. An existing master key must already be a non-symlinked,
32-byte regular file owned by `executor:executor` with mode `0600` and exactly
one hard link. A valid key is preserved byte-for-byte. A new key is generated
inside a private root-only staging directory on the same filesystem. It gets
its final ownership and mode there before an exact-destination hard link
atomically publishes it at `master.key`.

If installation or the readiness check fails after the service lifecycle is
under its control, the installer leaves the service stopped. If systemd cannot
stop it, the installer reports that explicitly instead of claiming a safe
state. A private recovery marker distinguishes an interrupted managed-file
replacement from unrelated files, so a manifest-publication failure can be
fixed and safely retried. Rerun the installer after correcting the reported
problem; do not start a partially installed service manually.

The installed paths are:

| Path                                     | Purpose                          | Ownership and mode          |
| ---------------------------------------- | -------------------------------- | --------------------------- |
| `/usr/local/bin/executor`                | Rust server and CLI binary       | `root:root`, `0755`         |
| `/etc/systemd/system/executor.service`   | systemd unit                     | `root:root`, `0644`         |
| `/etc/executor/executor.env`             | Non-secret service configuration | `root:executor`, `0640`     |
| `/etc/executor/mcp-stdio-templates.json` | Approved local MCP commands      | `root:executor`, `0640`     |
| `/etc/executor/service-install.manifest` | Managed-file ownership hashes    | `root:root`, `0600`         |
| `/var/lib/executor`                      | SQLite state and protected data  | `executor:executor`, `0700` |
| `/var/lib/executor/master.key`           | Raw 32-byte instance master key  | `executor:executor`, `0600` |

For an external secret-manager key configured with
`EXECUTOR_MASTER_KEY_FILE`, a root-owned `root:executor` file with mode `0440`
or `0640` is also supported. Executor opens the file before accepting that
shape, so the service account must actually have access through its groups.
Symbolic links, non-regular files, extra hard links, other owners, and broader
permissions are rejected.

For the first boot with an external key, install without starting, place the
key, configure its path, then start Executor:

```sh
sudo "$(command -v executor)" service install --no-start
sudo install --owner root --group executor --mode 0640 \
  /secure/source/executor-master.key /etc/executor/external-master.key
sudoedit /etc/executor/executor.env
# Set EXECUTOR_MASTER_KEY_FILE=/etc/executor/external-master.key
sudo executor service start
```

The unit leaves `--master-key-file` unset, so this environment setting selects
the external file. Without it, Executor uses `/var/lib/executor/master.key`.
The example uses persistent protected configuration storage, so the key remains
available after reboot. A secret manager may use an ephemeral runtime path only
when its boot-time provisioning unit is ordered before `executor.service`.

Back up the SQLite database and its selected key together. For the default key,
stop the service and copy the complete `/var/lib/executor` directory, then start
it again. Include an external key in that same stopped recovery snapshot when
configured. Losing the selected key makes encrypted credentials and initialized
instance state unrecoverable. Replacing the key while keeping the database
makes startup fail closed. The installer refuses to invent a default key for an
existing database.

## First boot and operation

The one-time setup URL is written to the journal on first boot:

```sh
sudo journalctl -u executor.service -b
```

Complete setup in a browser, then create API tokens in the dashboard. Routine
service commands are:

```sh
executor service status
sudo executor service restart
sudo executor service stop
sudo executor service start
sudo journalctl -u executor.service -f
```

`service status` does not require root. It prints exactly `active` or
`inactive`, exits 0 for active, and exits 3 for inactive. Operational failures
exit 1. All mutating Linux service commands require `sudo` and fail before
running systemctl when invoked without it.

`systemctl stop` sends `SIGTERM`. Executor stops accepting work, cancels owned
waits, drains upstream MCP processes and background tasks, closes SQLite, and
then exits. systemd allows 90 seconds for this graceful path before forcing
termination.

## Public origin and reverse proxies

The default unit is intentionally loopback-only. For a browser-facing reverse
proxy, keep the bind address on loopback and set the exact external HTTPS
origin in `/etc/executor/executor.env`:

```sh
EXECUTOR_PUBLIC_ORIGIN=https://executor.example.com
```

This origin controls browser origin checks, setup links, and managed OAuth
callback URLs. It must contain only a scheme, host, and optional port.

Only configure `EXECUTOR_TRUSTED_PROXIES` when Executor must use forwarded
client addresses. List every proxy CIDR in the chain:

```sh
EXECUTOR_TRUSTED_PROXIES=127.0.0.1/32,::1/128
```

Restart the service after changing the environment file. Do not bind plaintext
HTTP to a non-loopback address. Terminate HTTPS at the local reverse proxy or
another explicitly trusted transport boundary.

## Local MCP stdio templates

Treat every approved MCP stdio executable as fully trusted with the complete
Executor instance. It runs under the same operating-system account as Executor
and can read the master key and database. The service-level sandbox limits what
the combined service can reach, but it is not a security boundary between the
Rust server and its stdio children. Do not approve untrusted executables.

The installer creates an empty template registry at
`/etc/executor/mcp-stdio-templates.json`. Start from
`packaging/systemd/mcp-stdio-templates.example.json` when approving a local MCP
server. Executables and working directories must use absolute paths and must be
readable or executable by the `executor` account. Put secret values in the
dashboard, not in the template or environment file.

The unit applies `ProtectSystem=strict`, `ProtectHome=yes`, and `PrivateTmp=yes`
to Executor and its MCP children. A child can read system paths, has private
temporary directories, and can persist writes only within `/var/lib/executor`
by default. Home directories are hidden. Grant only the paths a reviewed
template needs with a systemd drop-in:

```sh
sudo systemctl edit executor.service
```

For example:

```ini
[Service]
ReadOnlyPaths=/srv/reference-data
ReadWritePaths=/srv/executor-workspace
```

Create those paths with ownership and modes appropriate for the `executor`
account, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl restart executor.service
```

The service-level sandbox is inherited by every MCP stdio child. Do not weaken
the whole unit when one child needs a narrow filesystem exception. Any
supplemental groups assigned to the `executor` account are inherited too, so
review those memberships as part of every template approval.

## Upgrade or remove

To upgrade, run `sudo "$(command -v executor)" service install` from the
replacement binary. The service is stopped before managed state is inspected
and started only after the new binary and unit are installed and the master key
passes validation.

To remove the unit and managed binary while preserving `/etc/executor`,
`/var/lib/executor`, and the service account:

```sh
sudo executor service remove
```

The ownership manifest records hashes for the installed binary and unit.
Lifecycle mutations fail before touching systemd if either file was replaced
outside `service install`. Removal deletes the manifest but preserves all other
configuration and state.

Remove `/etc/executor`, `/var/lib/executor`, and the `executor` account only
after making and verifying any required backup.
