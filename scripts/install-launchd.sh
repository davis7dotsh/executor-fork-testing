#!/usr/bin/env bash
set -eo pipefail

LABEL="dev.executor.gateway"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
TEMPLATE="${REPOSITORY_ROOT}/packaging/launchd/${LABEL}.plist"
LOG_WRITER_SOURCE="${REPOSITORY_ROOT}/packaging/launchd/bounded-log.sh"
PLIST="${HOME}/Library/LaunchAgents/${LABEL}.plist"
DATA_DIR="${EXECUTOR_DATA_DIR:-$HOME/Library/Application Support/Executor}"
TEMPLATES_FILE="${EXECUTOR_MCP_STDIO_TEMPLATES_FILE:-${DATA_DIR}/mcp-stdio-templates.json}"
PUBLIC_ORIGIN="${EXECUTOR_PUBLIC_ORIGIN:-}"
EXECUTOR_BINARY="${EXECUTOR_BINARY:-}"
TRUSTED_PROXIES="${EXECUTOR_TRUSTED_PROXIES:-}"
trusted_proxies=()
start_service=true

usage() {
    cat <<EOF
Install Executor as a per-user macOS LaunchAgent.

Usage: install-launchd.sh [options]

Options:
    --binary <path>          Executor binary (default: executor from PATH)
    --data-dir <path>        Persistent data directory
    --templates <path>       MCP stdio template file
    --public-origin <origin> Browser-facing origin when using an HTTPS proxy
    --trusted-proxy <CIDR>   Trust one proxy network (repeatable)
    --no-start               Install without loading the service
    -h, --help               Display this help message
EOF
}

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            [[ -n "${2:-}" ]] || fail "--binary requires a path"
            EXECUTOR_BINARY="$2"
            shift 2
            ;;
        --data-dir)
            [[ -n "${2:-}" ]] || fail "--data-dir requires a path"
            DATA_DIR="$2"
            shift 2
            ;;
        --templates)
            [[ -n "${2:-}" ]] || fail "--templates requires a path"
            TEMPLATES_FILE="$2"
            shift 2
            ;;
        --public-origin)
            [[ -n "${2:-}" ]] || fail "--public-origin requires an origin"
            PUBLIC_ORIGIN="$2"
            shift 2
            ;;
        --trusted-proxy)
            [[ -n "${2:-}" ]] || fail "--trusted-proxy requires a CIDR"
            trusted_proxies+=("$2")
            shift 2
            ;;
        --no-start)
            start_service=false
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) fail "unknown option: $1" ;;
    esac
done

[[ "$(uname -s)" == "Darwin" ]] || fail "launchd installation is supported only on macOS"
[[ -f "$TEMPLATE" ]] || fail "launchd template not found at $TEMPLATE"
[[ -f "$LOG_WRITER_SOURCE" ]] || fail "bounded log writer not found at $LOG_WRITER_SOURCE"

if [[ -z "$EXECUTOR_BINARY" ]]; then
    EXECUTOR_BINARY="$(command -v executor || true)"
fi
[[ -n "$EXECUTOR_BINARY" && -x "$EXECUTOR_BINARY" ]] \
    || fail "an executable Executor binary is required"

absolute_path() {
    local path=$1 directory base
    directory="$(dirname "$path")"
    base="$(basename "$path")"
    [[ -d "$directory" ]] || fail "directory does not exist: $directory"
    printf '%s/%s\n' "$(cd "$directory" && pwd -P)" "$base"
}

EXECUTOR_BINARY="$(absolute_path "$EXECUTOR_BINARY")"
mkdir -p "$DATA_DIR" "$(dirname "$TEMPLATES_FILE")" "$(dirname "$PLIST")"
chmod 0700 "$DATA_DIR"
DATA_DIR="$(cd "$DATA_DIR" && pwd -P)"

if [[ ! -e "$TEMPLATES_FILE" ]]; then
    printf '{\n  "templates": []\n}\n' > "$TEMPLATES_FILE"
fi
[[ -f "$TEMPLATES_FILE" && ! -L "$TEMPLATES_FILE" ]] \
    || fail "the MCP stdio template path must be a regular file"
chmod 0600 "$TEMPLATES_FILE"
TEMPLATES_FILE="$(absolute_path "$TEMPLATES_FILE")"

if [[ -n "$TRUSTED_PROXIES" ]]; then
    IFS=',' read -r -a environment_proxies <<< "$TRUSTED_PROXIES"
    trusted_proxies+=("${environment_proxies[@]}")
fi

for value in "$EXECUTOR_BINARY" "$DATA_DIR" "$TEMPLATES_FILE" "$PUBLIC_ORIGIN"; do
    case "$value" in
        *'&'*|*'<'*|*'>'*|*'|'*|*'\'*)
            fail "service paths and origins cannot contain XML or template metacharacters"
            ;;
    esac
done

wrapper="${DATA_DIR}/run-launchd.sh"
log_writer="${DATA_DIR}/bounded-log.sh"
private_log="${DATA_DIR}/executor.log"
temporary_log_writer="$(mktemp "${log_writer}.XXXXXXXX")"
trap 'rm -f "$temporary_log_writer"' EXIT
cp "$LOG_WRITER_SOURCE" "$temporary_log_writer"
chmod 0700 "$temporary_log_writer"
mv -f "$temporary_log_writer" "$log_writer"
trap - EXIT

temporary_wrapper="$(mktemp "${wrapper}.XXXXXXXX")"
trap 'rm -f "$temporary_wrapper"' EXIT
{
    printf '#!/bin/bash\nset -euo pipefail\nexec '
    printf '%q ' "$EXECUTOR_BINARY" server --data-dir "$DATA_DIR" \
        --mcp-stdio-templates "$TEMPLATES_FILE"
    if [[ -n "$PUBLIC_ORIGIN" ]]; then
        printf '%q ' --public-origin "$PUBLIC_ORIGIN"
    fi
    if [[ ${#trusted_proxies[@]} -gt 0 ]]; then
        for trusted_proxy in "${trusted_proxies[@]}"; do
            [[ -n "$trusted_proxy" ]] || fail "trusted proxy entries cannot be empty"
            printf '%q ' --trusted-proxy "$trusted_proxy"
        done
    fi
    printf '> >(%q %q) 2>&1\n' "$log_writer" "$private_log"
} > "$temporary_wrapper"
chmod 0700 "$temporary_wrapper"
mv -f "$temporary_wrapper" "$wrapper"
trap - EXIT

temporary_plist="$(mktemp "${PLIST}.XXXXXXXX")"
trap 'rm -f "$temporary_plist"' EXIT
sed -e "s|@EXECUTOR_WRAPPER@|${wrapper}|g" "$TEMPLATE" > "$temporary_plist"

plutil -lint "$temporary_plist" >/dev/null
chmod 0600 "$temporary_plist"
mv -f "$temporary_plist" "$PLIST"
trap - EXIT

domain="gui/$(id -u)"
launchctl bootout "$domain/$LABEL" >/dev/null 2>&1 || true
if [[ "$start_service" == "true" ]]; then
    launchctl enable "$domain/$LABEL"
    launchctl bootstrap "$domain" "$PLIST"
    ready=false
    previous_pid=""
    consecutive_checks=0
    for _ in {1..30}; do
        current_pid="$(launchctl print "$domain/$LABEL" 2>/dev/null \
            | awk '/^[[:space:]]*pid = [0-9]+$/ { print $3; exit }')"
        if [[ -n "$current_pid" ]] \
            && curl --fail --silent --show-error --noproxy '*' \
                --connect-timeout 1 --max-time 1 \
                http://127.0.0.1:4788/healthz >/dev/null 2>&1; then
            if [[ "$current_pid" == "$previous_pid" ]]; then
                consecutive_checks=$((consecutive_checks + 1))
            else
                consecutive_checks=1
                previous_pid="$current_pid"
            fi
            if [[ "$consecutive_checks" -ge 2 ]]; then
                ready=true
                break
            fi
        else
            consecutive_checks=0
            previous_pid=""
        fi
        sleep 1
    done
    if [[ "$ready" != "true" ]]; then
        launchctl print "$domain/$LABEL" >&2 || true
        launchctl bootout "$domain/$LABEL" >/dev/null 2>&1 || true
        fail "Executor did not become healthy within 30 seconds"
    fi
    printf 'Executor is running at http://127.0.0.1:4788\n'
    printf 'Read first-boot setup and logs at %s\n' "$private_log"
else
    printf 'Installed %s\n' "$PLIST"
    printf 'Load it with: launchctl bootstrap %s %q\n' "$domain" "$PLIST"
fi
