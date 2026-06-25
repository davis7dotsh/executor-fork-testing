# Run Executor with launchd

The native macOS release supports both Apple Silicon and Intel Macs. Install the
release binary, then install its per-user LaunchAgent:

```sh
executor service install
```

Do not use `sudo`. The binary embeds the LaunchAgent template, bounded log
helper, and installer, copies itself to
`$HOME/.executor/service/bin/executor`, and uses private temporary files. A
source checkout is not required. The archive-installed command remains at
`$HOME/.executor/bin/executor`, with independent ownership and upgrade state.
Pass `--no-start` to install the files while leaving the agent unloaded.

The CLI records hashes for the installed binary, plist, wrapper, log helper,
and persisted service configuration in
`$HOME/.executor/service/service-install.manifest`, owned by the user with mode
`0600`. Lifecycle mutations fail closed if a managed file is replaced outside
`service install`. A private recovery marker makes an interrupted manifest
publication safely rerunnable while keeping the LaunchAgent unloaded.

LaunchAgent settings are stored in the private, non-executable control file
`$HOME/.executor/service/service-config`. Reinstalling with no related
environment variables preserves the exact existing data directory, template
file, public origin, and trusted proxy list. Setting one variable changes only
that field. An explicitly empty `EXECUTOR_PUBLIC_ORIGIN` or
`EXECUTOR_TRUSTED_PROXIES` clears that setting.

Custom data and template paths must be absolute. Every existing directory from
the user's home boundary, or from the filesystem root for paths outside the
home directory, must be owned by root or the current user and must not be
group-writable or world-writable. Symbolic-link ancestors are rejected. The
managed wrapper and bounded logger stay under `$HOME/.executor/service`, while
the database, key, templates, and log remain under their configured paths.
The template file also cannot equal, contain, or be nested beneath a managed
service path or a reserved database, key, lock, or log path. These checks are
case-insensitive so they remain safe on the default macOS filesystem.

The LaunchAgent runs only while that user is logged in. It binds Executor to
`127.0.0.1:4788`, keeps persistent state under
`~/Library/Application Support/Executor`, and stops it with `SIGTERM` so the
server can drain active work before launchd's 30-second exit deadline.

Executor creates `master.key` inside the data directory on first boot. Back up
the data directory and master key together. Losing the key makes encrypted
credentials and protected state unrecoverable. Keep the directory private and
never copy the key into a shell command, plist, log, or source-control file.

The installer creates an empty, mode `0600` MCP stdio template registry at
`~/Library/Application Support/Executor/mcp-stdio-templates.json`. Edit that
file to add trusted local executables, then restart Executor. Do not make the
template file, referenced executable, working directory, or any ancestor path
writable by untrusted users.

Treat every configured stdio executable as fully trusted. launchd runs it as
the same user as Executor, so it can read that user's Executor data directory
and master key. The template allowlist prevents dashboard users from selecting
arbitrary commands, but it is not a privilege boundary between Executor and an
approved executable.

## Operate the service

```sh
executor service status
executor service start
executor service stop
executor service restart
```

`service status` prints exactly `active` or `inactive`, exits 0 for active, and
exits 3 for inactive. Operational failures exit 1. Restart uses a graceful
`bootout` followed by `bootstrap`. The CLI never uses force-killing
`kickstart -k`.

Executor output is written to `executor.log` inside its mode `0700` data
directory. The generated LaunchAgent helper keeps the current log and three
rotated generations, each capped at 1 MiB and mode `0600`. It copies input in
fixed-size chunks, so a large stream with no newline cannot make the helper's
memory grow with the stream. This keeps the first-boot setup token in the
user's private data directory without allowing normal tracing output to grow
without a bound.

```sh
tail -f "$HOME/Library/Application Support/Executor/executor.log"
```

The one-time setup URL appears in that output on first boot.

To serve the dashboard through an HTTPS reverse proxy, reinstall the agent with
the exact browser-facing origin:

```sh
EXECUTOR_PUBLIC_ORIGIN=https://executor.example.com executor service install
```

Leave Executor on its default loopback bind. The local reverse proxy should be
the only process that exposes it to other machines. Configure trusted proxy
CIDRs only when forwarded client addresses are required:

```sh
EXECUTOR_PUBLIC_ORIGIN=https://executor.example.com \
EXECUTOR_TRUSTED_PROXIES=127.0.0.1/32,::1/128 \
executor service install
```

`EXECUTOR_TRUSTED_PROXIES` accepts the same CIDRs as a comma-separated list.

To remove the service without deleting data:

```sh
executor service remove
```

Removal checks `launchctl bootout` errors, then removes the managed plist,
wrapper, log helper, service-private binary, and ownership manifest. It
preserves the persisted service configuration, the archive installation under
`$HOME/.executor/bin`, and the database, master key, template registry, and
logs under Application Support. A later service install reuses the preserved
settings unless explicit environment overrides are supplied.

## Back up and restore

Stop Executor before copying its SQLite database, WAL files, and master key.
Back up the whole data directory as one unit:

```sh
executor service stop
cp -pR "$HOME/Library/Application Support/Executor" "$HOME/Executor-backup"
executor service start
```

To restore, stop the service, replace the complete data directory from one
backup, preserve its private permissions, then start the service. Never create
a replacement key beside an existing `executor.db`; Executor intentionally
fails closed when the initialized database and its original key are separated.
