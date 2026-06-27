#!/usr/bin/env bash
set -euo pipefail

readonly APP_USER="executor"
readonly APP_GROUP="executor"
readonly BINARY_TARGET="/usr/local/bin/executor"
readonly CONFIG_DIR="/etc/executor"
readonly DATA_DIR="/var/lib/executor"
readonly MASTER_KEY_STAGING_PARENT="${DATA_DIR%/*}"
readonly UNIT_TARGET="/etc/systemd/system/executor.service"
readonly MANIFEST_TARGET="${CONFIG_DIR}/service-install.manifest"
readonly RECOVERY_TARGET="${CONFIG_DIR}/service-install.recovery"
readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly REPO_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd -P)
readonly UNIT_SOURCE="${REPO_DIR}/packaging/systemd/executor.service"
readonly ENV_SOURCE="${REPO_DIR}/packaging/systemd/executor.env.example"
source "${SCRIPT_DIR}/lib/install-systemd-master-key.sh"

validate_systemd_path_layout() {
    local persistent_path persistent_root managed_path

    for persistent_path in \
        "${DATA_DIR}/master.key" \
        "${CONFIG_DIR}/executor.env" \
        "${CONFIG_DIR}/mcp-stdio-templates.json"; do
        for managed_path in \
            "${BINARY_TARGET}" \
            "${UNIT_TARGET}" \
            "${MANIFEST_TARGET}" \
            "${RECOVERY_TARGET}"; do
            executor_require_disjoint_paths \
                "${persistent_path}" "persistent Executor state" \
                "${managed_path}" "a managed service path"
        done
    done
    for persistent_root in "${DATA_DIR}" "${CONFIG_DIR}"; do
        executor_require_disjoint_paths \
            "${persistent_root}" "an Executor state directory" \
            "${BINARY_TARGET}" "the managed service binary"
        executor_require_disjoint_paths \
            "${persistent_root}" "an Executor state directory" \
            "${UNIT_TARGET}" "the managed systemd unit"
    done
}

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

validate_systemd_path_layout

if [[ ${EUID} -ne 0 ]]; then
    echo "run this installer as root, for example with sudo" >&2
    exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl is required" >&2
    exit 1
fi
if ! command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum is required" >&2
    exit 1
fi
if [[ ${start_service} == true ]] && ! command -v curl >/dev/null 2>&1; then
    echo "curl is required for the startup readiness check" >&2
    exit 1
fi

service_was_active=false
service_is_quiescent=false
service_lifecycle_managed=false
installation_finished=false
manifest_temporary=""
recovery_temporary=""

on_installer_exit() {
    local status=$?
    trap - EXIT
    if [[ -n ${manifest_temporary} ]]; then
        rm -f -- "${manifest_temporary}"
    fi
    if [[ -n ${recovery_temporary} ]]; then
        rm -f -- "${recovery_temporary}"
    fi
    if ((status != 0)) && [[ ${service_lifecycle_managed} == true \
        && ${installation_finished} != true ]]; then
        if [[ ${service_is_quiescent} != true ]]; then
            if systemctl stop executor.service >/dev/null 2>&1; then
                service_is_quiescent=true
            else
                echo "installation failed and executor.service could not be stopped" >&2
                echo "inspect its status before retrying the installation" >&2
            fi
        fi
        if [[ ${service_is_quiescent} == true ]]; then
            echo "installation failed; executor.service was left stopped" >&2
            echo "fix the reported problem, then rerun the installer or start the service manually" >&2
        fi
    fi
    exit "${status}"
}
trap on_installer_exit EXIT

service_state=$(systemctl is-active executor.service 2>/dev/null || true)
case "${service_state}" in
    active|activating|reloading|deactivating)
        service_was_active=true
        if ! systemctl stop executor.service; then
            echo "could not stop executor.service before inspecting its state" >&2
            exit 1
        fi
        service_is_quiescent=true
        ;;
    inactive|failed|unknown)
        service_is_quiescent=true
        ;;
    *)
        echo "could not determine whether executor.service is active" >&2
        exit 1
        ;;
esac
service_lifecycle_managed=true

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

for managed_dir in "${CONFIG_DIR}" "${DATA_DIR}"; do
    executor_require_safe_directory "${managed_dir}"
done
for managed_file in \
    "${BINARY_TARGET}" \
    "${UNIT_TARGET}" \
    "${CONFIG_DIR}/executor.env" \
    "${CONFIG_DIR}/mcp-stdio-templates.json" \
    "${MANIFEST_TARGET}" \
    "${RECOVERY_TARGET}" \
    "${DATA_DIR}/master.key"; do
    executor_require_regular_file_or_absent "${managed_file}"
done
if [[ -e ${MANIFEST_TARGET} ]]; then
    manifest_uid=$(stat -c '%u' -- "${MANIFEST_TARGET}")
    manifest_gid=$(stat -c '%g' -- "${MANIFEST_TARGET}")
    manifest_mode=$(stat -c '%a' -- "${MANIFEST_TARGET}")
    manifest_links=$(stat -c '%h' -- "${MANIFEST_TARGET}")
    if [[ ${manifest_uid} -ne 0 || ${manifest_gid} -ne 0 \
        || ${manifest_mode} != 600 || ${manifest_links} -ne 1 ]]; then
        echo "the service ownership manifest has unsafe metadata" >&2
        exit 1
    fi
fi
if [[ -e ${RECOVERY_TARGET} ]]; then
    recovery_uid=$(stat -c '%u' -- "${RECOVERY_TARGET}")
    recovery_gid=$(stat -c '%g' -- "${RECOVERY_TARGET}")
    recovery_mode=$(stat -c '%a' -- "${RECOVERY_TARGET}")
    recovery_links=$(stat -c '%h' -- "${RECOVERY_TARGET}")
    recovery_contents=$(cat -- "${RECOVERY_TARGET}")
    if [[ ${recovery_uid} -ne 0 || ${recovery_gid} -ne 0 \
        || ${recovery_mode} != 600 || ${recovery_links} -ne 1 \
        || ${recovery_contents} != executor-service-install-recovery-v1 ]]; then
        echo "the service installation recovery marker is unsafe or malformed" >&2
        exit 1
    fi
fi

install -d -o root -g "${APP_GROUP}" -m 0750 "${CONFIG_DIR}"
install -d -o "${APP_USER}" -g "${APP_GROUP}" -m 0700 "${DATA_DIR}"

if [[ ! -e ${CONFIG_DIR}/executor.env ]]; then
    install -o root -g "${APP_GROUP}" -m 0640 \
        "${ENV_SOURCE}" "${CONFIG_DIR}/executor.env"
fi
if [[ ! -e ${CONFIG_DIR}/mcp-stdio-templates.json ]]; then
    umask 0027
    printf '{\n  "templates": []\n}\n' > "${CONFIG_DIR}/mcp-stdio-templates.json"
    chown root:"${APP_GROUP}" "${CONFIG_DIR}/mcp-stdio-templates.json"
    chmod 0640 "${CONFIG_DIR}/mcp-stdio-templates.json"
fi
if [[ ( -e ${DATA_DIR}/executor.db || -L ${DATA_DIR}/executor.db ) \
    && ! -e ${DATA_DIR}/master.key \
    && ! -L ${DATA_DIR}/master.key ]]; then
    echo "an existing Executor database has no master key; restore the original key" >&2
    exit 1
fi
app_gid=$(id -g "${APP_USER}")
executor_ensure_master_key \
    "${MASTER_KEY_STAGING_PARENT}" "${DATA_DIR}" \
    "${DATA_DIR}/master.key" "${app_uid}" "${app_gid}"

chown root:"${APP_GROUP}" \
    "${CONFIG_DIR}/executor.env" \
    "${CONFIG_DIR}/mcp-stdio-templates.json"
chmod 0640 \
    "${CONFIG_DIR}/executor.env" \
    "${CONFIG_DIR}/mcp-stdio-templates.json"

if [[ ! -e ${RECOVERY_TARGET} ]]; then
    recovery_temporary=$(mktemp "${CONFIG_DIR}/.service-recovery.XXXXXXXX")
    printf 'executor-service-install-recovery-v1\n' > "${recovery_temporary}"
    chown root:root "${recovery_temporary}"
    chmod 0600 "${recovery_temporary}"
    sync -f "${recovery_temporary}"
    mv -- "${recovery_temporary}" "${RECOVERY_TARGET}"
    recovery_temporary=""
    sync -f "${RECOVERY_TARGET}"
fi

if [[ ${binary_source} != "${BINARY_TARGET}" ]]; then
    install -o root -g root -m 0755 "${binary_source}" "${BINARY_TARGET}"
else
    chown root:root "${BINARY_TARGET}"
    chmod 0755 "${BINARY_TARGET}"
fi
install -o root -g root -m 0644 "${UNIT_SOURCE}" "${UNIT_TARGET}"
executor_require_filesystem_sync \
    "${BINARY_TARGET}" "the installed Executor binary"
executor_require_filesystem_sync \
    "${BINARY_TARGET%/*}" "the Executor binary directory"
executor_require_filesystem_sync \
    "${UNIT_TARGET}" "the installed systemd unit"
executor_require_filesystem_sync \
    "${UNIT_TARGET%/*}" "the systemd unit directory"

binary_hash=$(sha256sum -- "${BINARY_TARGET}" | awk '{print $1}')
unit_hash=$(sha256sum -- "${UNIT_TARGET}" | awk '{print $1}')
manifest_temporary=$(mktemp "${CONFIG_DIR}/.service-install.XXXXXXXX")
{
    printf 'executor-service-install-v1\n'
    printf 'binary %s\n' "${binary_hash}"
    printf 'unit %s\n' "${unit_hash}"
} > "${manifest_temporary}"
chown root:root "${manifest_temporary}"
chmod 0600 "${manifest_temporary}"
sync -f "${manifest_temporary}"
mv -f -- "${manifest_temporary}" "${MANIFEST_TARGET}"
manifest_temporary=""
sync -f "${MANIFEST_TARGET}"
rm -f -- "${RECOVERY_TARGET}"
sync -f "${CONFIG_DIR}"

systemctl daemon-reload
systemctl enable executor.service
if [[ ${start_service} == true ]]; then
    service_is_quiescent=false
    if ! systemctl start executor.service; then
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
    installation_finished=true
    echo "Executor is ready at http://127.0.0.1:4788"
else
    installation_finished=true
    if [[ ${service_was_active} == true ]]; then
        echo "Executor was stopped and remains stopped because --no-start was supplied."
    fi
    echo "Executor is installed. Start it with: systemctl start executor.service"
fi
echo "Follow logs with: journalctl -u executor.service -f"
