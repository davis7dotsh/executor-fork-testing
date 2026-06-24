# Linux systemd service

Executor ships a hardened system service for Linux distributions that use
systemd. It runs as a dedicated unprivileged `executor` account and listens on
`127.0.0.1:4788` by default.

## Install

Build or download the Executor binary, then run the installer from a source
checkout:

```sh
sudo scripts/install-systemd.sh --binary /path/to/executor
```

Use `--no-start` to inspect or customize the installed files before the first
boot. The installer is safe to run again during an upgrade. It replaces the
binary and unit but never replaces the master key, environment file, or MCP
stdio template registry.

The installed paths are:

| Path                                     | Purpose                          | Ownership and mode          |
| ---------------------------------------- | -------------------------------- | --------------------------- |
| `/usr/local/bin/executor`                | Rust server and CLI binary       | `root:root`, `0755`         |
| `/etc/systemd/system/executor.service`   | systemd unit                     | `root:root`, `0644`         |
| `/etc/executor/executor.env`             | Non-secret service configuration | `root:executor`, `0640`     |
| `/etc/executor/mcp-stdio-templates.json` | Approved local MCP commands      | `root:executor`, `0640`     |
| `/var/lib/executor`                      | SQLite state and protected data  | `executor:executor`, `0700` |
| `/var/lib/executor/master.key`           | Raw 32-byte instance master key  | `executor:executor`, `0600` |

Back up the SQLite database and `master.key` together. For a simple filesystem
backup, stop the service and copy the complete `/var/lib/executor` directory,
then start it again. Losing the key makes encrypted credentials and initialized
instance state unrecoverable. Replacing the key while keeping the database
makes startup fail closed. The installer refuses to invent a key for an
existing database.

## First boot and operation

The one-time setup URL is written to the journal on first boot:

```sh
sudo journalctl -u executor.service -b
```

Complete setup in a browser, then create API tokens in the dashboard. Routine
service commands are:

```sh
sudo systemctl status executor.service
sudo systemctl restart executor.service
sudo systemctl stop executor.service
sudo journalctl -u executor.service -f
```

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

To upgrade, rerun the installer with the replacement binary. The service is
restarted only after the new binary and unit are installed.

To remove the service while preserving data:

```sh
sudo systemctl disable --now executor.service
sudo rm /etc/systemd/system/executor.service
sudo systemctl daemon-reload
```

Remove `/etc/executor`, `/var/lib/executor`, and the `executor` account only
after making and verifying any required backup.
