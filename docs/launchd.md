# Run Executor with launchd

The native macOS release supports both Apple Silicon and Intel Macs. The
LaunchAgent installer uses templates from a source checkout. Install the single
binary first, then run the service installer from that checkout:

```sh
./scripts/install.sh --binary ./target/release/executor
./scripts/install-launchd.sh --binary "$HOME/.executor/bin/executor"
```

When published release archives are available, the first command can omit
`--binary`. Pass the absolute binary path explicitly because a PATH edit from
the binary installer is not active in the current shell.

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
launchctl print "gui/$(id -u)/dev.executor.gateway"
launchctl bootout "gui/$(id -u)/dev.executor.gateway"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.executor.gateway.plist"
```

A graceful restart uses `bootout` followed by `bootstrap`, as shown above.
`kickstart -k` force-kills the process and should be reserved for a stuck
service that cannot exit normally.

Executor output is written to `executor.log` inside its mode `0700` data
directory. The generated LaunchAgent helper keeps the current log and three
rotated generations, each capped at 1 MiB and mode `0600`. This keeps the
first-boot setup token in the user's private data directory without allowing
normal tracing output to grow without a bound.

```sh
tail -f "$HOME/Library/Application Support/Executor/executor.log"
```

The one-time setup URL appears in that output on first boot.

To serve the dashboard through an HTTPS reverse proxy, reinstall the agent with
the exact browser-facing origin:

```sh
./scripts/install-launchd.sh \
  --binary "$HOME/.executor/bin/executor" \
  --public-origin https://executor.example.com
```

Leave Executor on its default loopback bind. The local reverse proxy should be
the only process that exposes it to other machines. Configure trusted proxy
CIDRs only when forwarded client addresses are required:

```sh
./scripts/install-launchd.sh \
  --binary "$HOME/.executor/bin/executor" \
  --public-origin https://executor.example.com \
  --trusted-proxy 127.0.0.1/32 \
  --trusted-proxy ::1/128
```

`EXECUTOR_TRUSTED_PROXIES` accepts the same CIDRs as a comma-separated list.

To remove the service without deleting data:

```sh
launchctl bootout "gui/$(id -u)/dev.executor.gateway" || true
rm "$HOME/Library/LaunchAgents/dev.executor.gateway.plist"
```

## Back up and restore

Stop Executor before copying its SQLite database, WAL files, and master key.
Back up the whole data directory as one unit:

```sh
launchctl bootout "gui/$(id -u)/dev.executor.gateway"
cp -pR "$HOME/Library/Application Support/Executor" "$HOME/Executor-backup"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.executor.gateway.plist"
```

To restore, stop the service, replace the complete data directory from one
backup, preserve its private permissions, then start the service. Never create
a replacement key beside an existing `executor.db`; Executor intentionally
fails closed when the initialized database and its original key are separated.
