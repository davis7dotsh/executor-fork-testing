#!/usr/bin/env bash
set -euo pipefail

readonly APP_USER="executor"
readonly APP_GROUP="executor"
readonly BINARY_TARGET="/usr/local/bin/executor"
readonly CONFIG_DIR="/etc/executor"
readonly DATA_DIR="/var/lib/executor"
readonly UNIT_TARGET="/etc/systemd/system/executor.service"

usage() {
    cat <<'EOF'
Install Executor as a hardened systemd service.

Usage: sudo scripts/install-systemd.sh [--binary /path/to/executor] [--no-start]

Options:
    --binary PATH  Install this binary. Defaults to executor from PATH.
    --no-start     Install and enable the unit without starting it.
    -h, --help     Show this help.

The installer never replaces an existing master key, environment file, or MCP
stdio template registry.
EOF
}

binary_source=""
start_service=true
while (($# > 0)); do
    case "$1" in
        --binary)
            if (($# < 2)); then
                echo "--binary requires a path" >&2
                exit 2
            fi
            binary_source=$2
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
        *)
            echo "unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ${EUID} -ne 0 ]]; then
    echo "run this installer as root, for example with sudo" >&2
    exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl is required" >&2
    exit 1
fi
if [[ ${start_service} == true ]] && ! command -v curl >/dev/null 2>&1; then
    echo "curl is required for the startup readiness check" >&2
    exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_dir=$(cd -- "${script_dir}/.." && pwd -P)
unit_source="${repo_dir}/packaging/systemd/executor.service"
env_source="${repo_dir}/packaging/systemd/executor.env.example"

if [[ -z ${binary_source} ]]; then
    binary_source=$(command -v executor || true)
fi
if [[ -z ${binary_source} || ! -f ${binary_source} || ! -x ${binary_source} ]]; then
    echo "an executable Executor binary is required; pass --binary PATH" >&2
    exit 1
fi
binary_source=$(cd -- "$(dirname -- "${binary_source}")" && pwd -P)/$(basename -- "${binary_source}")

if ! getent group "${APP_GROUP}" >/dev/null; then
    groupadd --system "${APP_GROUP}"
fi
if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    useradd \
        --system \
        --gid "${APP_GROUP}" \
        --home-dir "${DATA_DIR}" \
        --shell "$(command -v nologin || echo /usr/sbin/nologin)" \
        "${APP_USER}"
fi
IFS=: read -r _ _ app_uid _ _ app_home app_shell \
    <<< "$(getent passwd "${APP_USER}")"
app_primary_group=$(id -gn "${APP_USER}")
password_status=$(passwd -S "${APP_USER}" 2>/dev/null | awk '{print $2}')
if [[ ${app_uid} -eq 0 \
    || ${app_home} != "${DATA_DIR}" \
    || ! ${app_shell} =~ /(nologin|false)$ \
    || ${app_primary_group} != "${APP_GROUP}" \
    || ! ${password_status} =~ ^(L|LK)$ ]]; then
    echo "the executor account exists but is not the expected locked system account" >&2
    echo "refusing to grant it access to Executor state" >&2
    exit 1
fi

install -d -o root -g "${APP_GROUP}" -m 0750 "${CONFIG_DIR}"
install -d -o "${APP_USER}" -g "${APP_GROUP}" -m 0700 "${DATA_DIR}"

if [[ ${binary_source} != "${BINARY_TARGET}" ]]; then
    install -o root -g root -m 0755 "${binary_source}" "${BINARY_TARGET}"
else
    chown root:root "${BINARY_TARGET}"
    chmod 0755 "${BINARY_TARGET}"
fi
install -o root -g root -m 0644 "${unit_source}" "${UNIT_TARGET}"

for managed_file in \
    "${CONFIG_DIR}/executor.env" \
    "${CONFIG_DIR}/mcp-stdio-templates.json" \
    "${DATA_DIR}/master.key"; do
    if [[ -L ${managed_file} ]]; then
        echo "refusing symbolic link at managed path: ${managed_file}" >&2
        exit 1
    fi
    if [[ -e ${managed_file} && ! -f ${managed_file} ]]; then
        echo "managed path is not a regular file: ${managed_file}" >&2
        exit 1
    fi
done

if [[ ! -e ${CONFIG_DIR}/executor.env ]]; then
    install -o root -g "${APP_GROUP}" -m 0640 \
        "${env_source}" "${CONFIG_DIR}/executor.env"
fi
if [[ ! -e ${CONFIG_DIR}/mcp-stdio-templates.json ]]; then
    umask 0027
    printf '{\n  "templates": []\n}\n' > "${CONFIG_DIR}/mcp-stdio-templates.json"
    chown root:"${APP_GROUP}" "${CONFIG_DIR}/mcp-stdio-templates.json"
    chmod 0640 "${CONFIG_DIR}/mcp-stdio-templates.json"
fi
if [[ -e ${DATA_DIR}/executor.db && ! -e ${DATA_DIR}/master.key ]]; then
    echo "an existing Executor database has no master key; restore the original key" >&2
    exit 1
fi
if [[ ! -e ${DATA_DIR}/master.key ]]; then
    key_tmp=$(mktemp "${DATA_DIR}/.master.key.XXXXXXXX")
    trap 'rm -f -- "${key_tmp:-}"' EXIT
    chmod 0600 "${key_tmp}"
    head -c 32 /dev/urandom > "${key_tmp}"
    chown "${APP_USER}:${APP_GROUP}" "${key_tmp}"
    if ! ln -- "${key_tmp}" "${DATA_DIR}/master.key"; then
        echo "master key path appeared during installation; refusing to replace it" >&2
        exit 1
    fi
    rm -f -- "${key_tmp}"
    trap - EXIT
fi

if [[ $(wc -c < "${DATA_DIR}/master.key") -ne 32 ]]; then
    echo "${DATA_DIR}/master.key must contain exactly 32 bytes" >&2
    exit 1
fi
if [[ $(stat -c %h "${DATA_DIR}/master.key") -ne 1 ]]; then
    echo "${DATA_DIR}/master.key must not have additional hard links" >&2
    exit 1
fi
chown root:"${APP_GROUP}" \
    "${CONFIG_DIR}/executor.env" \
    "${CONFIG_DIR}/mcp-stdio-templates.json"
chmod 0640 \
    "${CONFIG_DIR}/executor.env" \
    "${CONFIG_DIR}/mcp-stdio-templates.json"
chown "${APP_USER}:${APP_GROUP}" "${DATA_DIR}/master.key"
chmod 0600 "${DATA_DIR}/master.key"

systemctl daemon-reload
systemctl enable executor.service
if [[ ${start_service} == true ]]; then
    if ! systemctl restart executor.service; then
        systemctl status --no-pager executor.service || true
        exit 1
    fi
    ready=false
    healthy_checks=0
    last_main_pid=0
    for _ in {1..30}; do
        main_pid=$(systemctl show --property MainPID --value executor.service)
        if systemctl is-active --quiet executor.service \
            && [[ ${main_pid} =~ ^[1-9][0-9]*$ ]] \
            && curl --noproxy '*' --fail --silent --max-time 1 \
                http://127.0.0.1:4788/healthz >/dev/null; then
            if [[ ${main_pid} == "${last_main_pid}" ]]; then
                ((healthy_checks += 1))
            else
                healthy_checks=1
                last_main_pid=${main_pid}
            fi
            if ((healthy_checks >= 2)); then
                ready=true
                break
            fi
        else
            healthy_checks=0
            last_main_pid=0
        fi
        if systemctl is-failed --quiet executor.service; then
            break
        fi
        sleep 1
    done
    if [[ ${ready} != true ]]; then
        echo "Executor did not become ready" >&2
        systemctl status --no-pager executor.service || true
        journalctl --unit executor.service --lines 30 --no-pager || true
        exit 1
    fi
    echo "Executor is ready at http://127.0.0.1:4788"
else
    echo "Executor is installed. Start it with: systemctl start executor.service"
fi
echo "Follow logs with: journalctl -u executor.service -f"
