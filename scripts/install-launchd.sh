#!/usr/bin/env bash
set -eo pipefail
export LC_ALL=C

LABEL="dev.executor.gateway"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
TEMPLATE="${REPOSITORY_ROOT}/packaging/launchd/${LABEL}.plist"
LOG_WRITER_SOURCE="${REPOSITORY_ROOT}/packaging/launchd/bounded-log.sh"
PLIST="${HOME}/Library/LaunchAgents/${LABEL}.plist"
EXECUTOR_BINARY="${EXECUTOR_BINARY:-}"
DEFAULT_DATA_DIR="${HOME}/Library/Application Support/Executor"
EXECUTOR_ROOT="${HOME}/.executor"
INSTALL_ROOT="${EXECUTOR_ROOT}/service"
MANIFEST="${INSTALL_ROOT}/service-install.manifest"
RECOVERY_MARKER="${INSTALL_ROOT}/service-install.recovery"
CONFIG_FILE="${INSTALL_ROOT}/service-config"
CURRENT_UID="$(id -u)"
data_dir_explicit=false
templates_explicit=false
public_origin_explicit=false
trusted_proxies_explicit=false
data_dir_override=""
templates_override=""
public_origin_override=""
trusted_proxies_override=""
if [[ ${EXECUTOR_DATA_DIR+x} == x ]]; then
    data_dir_explicit=true
    data_dir_override=$EXECUTOR_DATA_DIR
fi
if [[ ${EXECUTOR_MCP_STDIO_TEMPLATES_FILE+x} == x ]]; then
    templates_explicit=true
    templates_override=$EXECUTOR_MCP_STDIO_TEMPLATES_FILE
fi
if [[ ${EXECUTOR_PUBLIC_ORIGIN+x} == x ]]; then
    public_origin_explicit=true
    public_origin_override=$EXECUTOR_PUBLIC_ORIGIN
fi
if [[ ${EXECUTOR_TRUSTED_PROXIES+x} == x ]]; then
    trusted_proxies_explicit=true
    trusted_proxies_override=$EXECUTOR_TRUSTED_PROXIES
fi
trusted_proxy_options=()
start_service=true
validate_only=false

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
    --validate-only          Validate paths and configuration without changes
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
            data_dir_explicit=true
            data_dir_override="$2"
            shift 2
            ;;
        --templates)
            [[ -n "${2:-}" ]] || fail "--templates requires a path"
            templates_explicit=true
            templates_override="$2"
            shift 2
            ;;
        --public-origin)
            [[ -n "${2:-}" ]] || fail "--public-origin requires an origin"
            public_origin_explicit=true
            public_origin_override="$2"
            shift 2
            ;;
        --trusted-proxy)
            [[ -n "${2:-}" ]] || fail "--trusted-proxy requires a CIDR"
            trusted_proxies_explicit=true
            trusted_proxy_options+=("$2")
            shift 2
            ;;
        --no-start)
            start_service=false
            shift
            ;;
        --validate-only)
            validate_only=true
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
command -v shasum >/dev/null 2>&1 || fail "shasum is required"
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

require_directory_or_absent() {
    local path=$1 description=$2

    [[ ! -L "$path" ]] || fail "$description must not be a symbolic link: $path"
    if [[ -e "$path" && ! -d "$path" ]]; then
        fail "$description must be a directory: $path"
    fi
}

require_regular_file_or_absent() {
    local path=$1 description=$2

    [[ ! -L "$path" ]] || fail "$description must not be a symbolic link: $path"
    if [[ -e "$path" && ! -f "$path" ]]; then
        fail "$description must be a regular file: $path"
    fi
}

private_file_metadata() {
    local path=$1
    if stat --version >/dev/null 2>&1; then
        stat -c '%u|%a|%h' "$path"
    else
        stat -f '%u|%Lp|%l' "$path"
    fi
}

private_file_identity() {
    local path=$1
    if stat --version >/dev/null 2>&1; then
        stat -c '%u|%a|%h|%d|%i|%s' "$path"
    else
        stat -f '%u|%Lp|%l|%d|%i|%z' "$path"
    fi
}

require_private_control_file() {
    local path=$1 description=$2 metadata owner mode links

    require_regular_file_or_absent "$path" "$description"
    [[ -e "$path" ]] || return 0
    metadata="$(private_file_metadata "$path")" \
        || fail "could not inspect $description: $path"
    IFS='|' read -r owner mode links <<< "$metadata"
    if [[ "$owner" != "$CURRENT_UID" || "$mode" != 600 || "$links" != 1 ]]; then
        fail "$description must be owned by the current user with mode 0600 and one hard link"
    fi
}

require_recoverable_template_file() {
    local recover=$1 path=$TEMPLATES_FILE parent candidate candidate_name
    local metadata owner mode links destination_identity expected_digest actual_digest
    local matching_alias=""
    local -a candidates=()

    require_regular_file_or_absent "$path" "the MCP stdio template path"
    [[ -e "$path" ]] || return 0
    metadata="$(private_file_metadata "$path")" \
        || fail "could not inspect the MCP stdio template path: $path"
    IFS='|' read -r owner mode links <<< "$metadata"
    if [[ "$owner" == "$CURRENT_UID" && "$mode" == 600 && "$links" == 1 ]]; then
        return 0
    fi
    if [[ "$owner" != "$CURRENT_UID" || "$mode" != 600 || "$links" != 2 ]]; then
        fail "the MCP stdio template path has unsafe metadata"
    fi

    parent="$(dirname "$path")"
    destination_identity="$(private_file_identity "$path")" \
        || fail "could not inspect the MCP stdio template path"
    shopt -s nullglob
    candidates=("${parent}"/.executor-templates.????????)
    shopt -u nullglob
    for candidate in "${candidates[@]}"; do
        [[ "$candidate" != "$path" ]] || continue
        candidate_name="$(basename "$candidate")"
        [[ "$candidate_name" =~ ^\.executor-templates\.[A-Za-z0-9]{8}$ ]] \
            || continue
        [[ -f "$candidate" && ! -L "$candidate" ]] || continue
        if [[ "$(private_file_identity "$candidate")" == "$destination_identity" ]]; then
            [[ -z "$matching_alias" ]] \
                || fail "multiple MCP template recovery aliases were found"
            matching_alias=$candidate
        fi
    done
    [[ -n "$matching_alias" ]] \
        || fail "the MCP stdio template path has an unknown hard link"
    expected_digest="$(printf '{\n  "templates": []\n}\n' | shasum -a 256 | awk '{print $1}')"
    actual_digest="$(shasum -a 256 "$path" | awk '{print $1}')"
    [[ "$actual_digest" == "$expected_digest" ]] \
        || fail "the MCP template recovery alias has unexpected contents"

    if [[ "$recover" == true ]]; then
        require_private_control_file "$RECOVERY_MARKER" \
            "the service installation recovery marker"
        [[ "$(cat "$RECOVERY_MARKER")" == executor-service-install-recovery-v1 ]] \
            || fail "the service installation recovery marker is malformed"
        rm -f "$matching_alias"
        sync
        require_private_control_file "$path" "the MCP stdio template path"
    fi
}

require_safe_directory_metadata() {
    local path=$1 description=$2 owner_requirement=${3:-trusted}
    local metadata owner mode links permissions

    require_directory_or_absent "$path" "$description"
    [[ -d "$path" ]] || fail "$description does not exist: $path"
    metadata="$(private_file_metadata "$path")" \
        || fail "could not inspect $description: $path"
    IFS='|' read -r owner mode links <<< "$metadata"
    if [[ "$owner" != 0 && "$owner" != "$CURRENT_UID" ]]; then
        fail "$description must be owned by root or the current user: $path"
    fi
    if [[ "$owner_requirement" == current && "$owner" != "$CURRENT_UID" ]]; then
        fail "$description must be owned by the current user: $path"
    fi
    permissions=$((8#$mode))
    if (( permissions & 0022 )); then
        fail "$description must not be group-writable or world-writable: $path"
    fi
}

check_safe_directory_path() {
    local path=$1 description=$2 create_missing=$3 current relative component
    local -a components

    [[ "$path" == /* ]] || fail "$description must be an absolute path: $path"
    if [[ "$path" == "$HOME" ]]; then
        require_safe_directory_metadata "$HOME" "the home directory" current
        return
    fi
    if [[ "$path" == "$HOME/"* ]]; then
        current=$HOME
        relative=${path#"$HOME"/}
        require_safe_directory_metadata "$current" "the home directory" current
    else
        current=/
        relative=${path#/}
        require_safe_directory_metadata "$current" "the filesystem root"
    fi
    IFS='/' read -r -a components <<< "$relative"
    for component in "${components[@]}"; do
        [[ -n "$component" && "$component" != . && "$component" != .. ]] \
            || fail "$description contains an unsafe path component: $path"
        current="${current%/}/${component}"
        [[ ! -L "$current" ]] || fail "$description has a symbolic-link ancestor: $current"
        if [[ ! -e "$current" ]]; then
            if [[ "$create_missing" != true ]]; then
                return
            fi
            if ! mkdir -m 0700 "$current"; then
                fail "could not create $description: $current"
            fi
        fi
        require_safe_directory_metadata "$current" "$description"
    done
}

validate_safe_directory_path() {
    check_safe_directory_path "$1" "$2" false
}

ensure_safe_directory_path() {
    check_safe_directory_path "$1" "$2" true
}

normalize_absolute_path() {
    local path=$1 description=$2 relative component result=""
    local -a components

    [[ "$path" == /* ]] || fail "$description must be an absolute path: $path"
    [[ "$path" != *//* ]] \
        || fail "$description must not contain empty path components: $path"
    if [[ "$path" != / && "$path" == */ ]]; then
        fail "$description must not end with an empty path component: $path"
    fi
    relative=${path#/}
    if [[ -z "$relative" ]]; then
        normalized_path=/
        return
    fi
    IFS='/' read -r -a components <<< "$relative"
    for component in "${components[@]}"; do
        [[ -n "$component" && "$component" != . && "$component" != .. ]] \
            || fail "$description contains an unsafe path component: $path"
        result="${result}/${component}"
    done
    normalized_path=$result
}

canonicalize_path_without_creation() {
    local path=$1 description=$2 ancestor suffix="" component physical

    normalize_absolute_path "$path" "$description"
    ancestor=$normalized_path
    while [[ ! -d "$ancestor" ]]; do
        component=${ancestor##*/}
        suffix="/${component}${suffix}"
        ancestor=${ancestor%/*}
        [[ -n "$ancestor" ]] || ancestor=/
    done
    physical="$(cd "$ancestor" && pwd -P)" \
        || fail "could not resolve $description: $path"
    if [[ "$physical" == / ]]; then
        canonical_path="${physical}${suffix#/}"
    else
        canonical_path="${physical}${suffix}"
    fi
}

casefold_path() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

paths_overlap() {
    local left=$1 right=$2 left_fold right_fold

    canonicalize_path_without_creation "$left" "a configured path"
    left_fold="$(casefold_path "$canonical_path")"
    canonicalize_path_without_creation "$right" "a reserved path"
    right_fold="$(casefold_path "$canonical_path")"
    if [[ "$left_fold" == / || "$right_fold" == / \
        || "$left_fold" == "$right_fold" \
        || "$left_fold" == "$right_fold/"* \
        || "$right_fold" == "$left_fold/"* ]]; then
        return 0
    fi
    return 1
}

path_is_same_or_ancestor() {
    local possible_ancestor=$1 path=$2 ancestor_fold path_fold

    canonicalize_path_without_creation "$possible_ancestor" "a configured path"
    ancestor_fold="$(casefold_path "$canonical_path")"
    canonicalize_path_without_creation "$path" "a configured path"
    path_fold="$(casefold_path "$canonical_path")"
    [[ "$ancestor_fold" == / || "$ancestor_fold" == "$path_fold" \
        || "$path_fold" == "$ancestor_fold/"* ]]
}

reject_path_overlap() {
    local configured_path=$1 configured_description=$2 reserved_path=$3 reserved_description=$4

    if paths_overlap "$configured_path" "$reserved_path"; then
        fail "$configured_description must not overlap $reserved_description: $reserved_path"
    fi
}

validate_configured_path_collisions() {
    local service_binary="${INSTALL_ROOT}/bin/executor" reserved_path

    reject_path_overlap "$DATA_DIR" "the Executor data directory" \
        "$INSTALL_ROOT" "the managed service directory"
    reject_path_overlap "$DATA_DIR" "the Executor data directory" \
        "$PLIST" "the managed LaunchAgent plist"

    for reserved_path in \
        "$INSTALL_ROOT" \
        "$service_binary" \
        "$CONFIG_FILE" \
        "$MANIFEST" \
        "$RECOVERY_MARKER" \
        "$wrapper" \
        "$log_writer" \
        "$PLIST"; do
        reject_path_overlap "$TEMPLATES_FILE" "the MCP stdio template file" \
            "$reserved_path" "a managed service path"
    done

    if path_is_same_or_ancestor "$TEMPLATES_FILE" "$DATA_DIR"; then
        fail "the MCP stdio template file must not equal or contain the Executor data directory"
    fi
    for reserved_path in \
        "${DATA_DIR}/master.key" \
        "${DATA_DIR}/executor.db" \
        "${DATA_DIR}/executor.db-journal" \
        "${DATA_DIR}/executor.db-wal" \
        "${DATA_DIR}/executor.db-shm" \
        "${DATA_DIR}/executor.lock" \
        "$private_log" \
        "${private_log}.1" \
        "${private_log}.2" \
        "${private_log}.3"; do
        reject_path_overlap "$TEMPLATES_FILE" "the MCP stdio template file" \
            "$reserved_path" "a reserved Executor state path"
    done
}

validate_encoded_config_value() {
    local encoded=$1 description=$2 byte remainder

    if (( ${#encoded} % 2 != 0 )); then
        fail "$description has an invalid encoded length"
    fi
    case "$encoded" in
        *[!0-9a-f]*) fail "$description contains invalid encoded bytes" ;;
    esac
    remainder=$encoded
    while [[ -n "$remainder" ]]; do
        byte=${remainder:0:2}
        case "$byte" in
            0[0-9a-f]|1[0-9a-f]|7f)
                fail "$description contains unsupported control bytes"
                ;;
        esac
        remainder=${remainder:2}
    done
}

decode_config_value() {
    local encoded=$1 description=$2 byte decoded_byte

    validate_encoded_config_value "$encoded" "$description"
    decoded_config_value=""
    while [[ -n "$encoded" ]]; do
        byte=${encoded:0:2}
        printf -v decoded_byte '%b' "\\x${byte}"
        decoded_config_value="${decoded_config_value}${decoded_byte}"
        encoded=${encoded:2}
    done
}

encode_config_value() {
    printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

validate_safe_directory_path "$EXECUTOR_ROOT" "the Executor root directory"
if [[ -d "$EXECUTOR_ROOT" ]]; then
    require_safe_directory_metadata "$EXECUTOR_ROOT" "the Executor root directory" current
fi
validate_safe_directory_path "$INSTALL_ROOT" "the Executor service directory"
if [[ -d "$INSTALL_ROOT" ]]; then
    require_safe_directory_metadata "$INSTALL_ROOT" "the Executor service directory" current
fi
require_private_control_file "$CONFIG_FILE" "the persisted service configuration"
require_private_control_file "$MANIFEST" "the service ownership manifest"
require_private_control_file "$RECOVERY_MARKER" "the service installation recovery marker"

config_existed=false
DATA_DIR=$DEFAULT_DATA_DIR
TEMPLATES_FILE="${DATA_DIR}/mcp-stdio-templates.json"
PUBLIC_ORIGIN=""
trusted_proxies=()
if [[ -e "$CONFIG_FILE" ]]; then
    config_existed=true
    config_size="$(wc -c < "$CONFIG_FILE" | tr -d '[:space:]')"
    case "$config_size" in
        ''|*[!0-9]*) fail "the persisted service configuration size is invalid" ;;
    esac
    if (( config_size > 65536 )); then
        fail "the persisted service configuration is too large"
    fi

    config_line_number=0
    saw_data_dir=false
    saw_templates_file=false
    saw_public_origin=false
    while IFS= read -r config_line || [[ -n "$config_line" ]]; do
        config_line_number=$((config_line_number + 1))
        if [[ "$config_line_number" -eq 1 ]]; then
            [[ "$config_line" == executor-launchd-config-v1 ]] \
                || fail "the persisted service configuration has an unsupported format"
            continue
        fi
        case "$config_line" in
            data_dir_hex=*)
                [[ "$saw_data_dir" == false ]] \
                    || fail "the persisted service configuration repeats data_dir_hex"
                decode_config_value "${config_line#data_dir_hex=}" "the persisted data directory"
                DATA_DIR=$decoded_config_value
                saw_data_dir=true
                ;;
            templates_file_hex=*)
                [[ "$saw_templates_file" == false ]] \
                    || fail "the persisted service configuration repeats templates_file_hex"
                decode_config_value "${config_line#templates_file_hex=}" \
                    "the persisted template file"
                TEMPLATES_FILE=$decoded_config_value
                saw_templates_file=true
                ;;
            public_origin_hex=*)
                [[ "$saw_public_origin" == false ]] \
                    || fail "the persisted service configuration repeats public_origin_hex"
                decode_config_value "${config_line#public_origin_hex=}" \
                    "the persisted public origin"
                PUBLIC_ORIGIN=$decoded_config_value
                saw_public_origin=true
                ;;
            trusted_proxy_hex=*)
                decode_config_value "${config_line#trusted_proxy_hex=}" \
                    "a persisted trusted proxy"
                [[ -n "$decoded_config_value" ]] \
                    || fail "persisted trusted proxy entries cannot be empty"
                trusted_proxies+=("$decoded_config_value")
                ;;
            *) fail "the persisted service configuration contains an unknown field" ;;
        esac
    done < "$CONFIG_FILE"
    [[ "$config_line_number" -gt 0 && "$saw_data_dir" == true \
        && "$saw_templates_file" == true && "$saw_public_origin" == true ]] \
        || fail "the persisted service configuration is incomplete"
fi

if [[ "$data_dir_explicit" == true ]]; then
    DATA_DIR=$data_dir_override
fi
if [[ "$templates_explicit" == true ]]; then
    TEMPLATES_FILE=$templates_override
elif [[ "$config_existed" == false && "$data_dir_explicit" == true ]]; then
    TEMPLATES_FILE="${DATA_DIR}/mcp-stdio-templates.json"
fi
if [[ "$public_origin_explicit" == true ]]; then
    PUBLIC_ORIGIN=$public_origin_override
fi
if [[ "$trusted_proxies_explicit" == true ]]; then
    trusted_proxies=()
    if [[ -n "$trusted_proxies_override" ]]; then
        case "$trusted_proxies_override" in
            ,*|*,|*,,*) fail "trusted proxy entries cannot be empty" ;;
        esac
        IFS=',' read -r -a environment_proxies <<< "$trusted_proxies_override"
        trusted_proxies+=("${environment_proxies[@]}")
    fi
    trusted_proxies+=("${trusted_proxy_options[@]}")
fi

[[ -n "$DATA_DIR" ]] || fail "the Executor data directory cannot be empty"
[[ -n "$TEMPLATES_FILE" ]] || fail "the MCP stdio template file cannot be empty"
wrapper="${INSTALL_ROOT}/run-launchd.sh"
log_writer="${INSTALL_ROOT}/bounded-log.sh"
for value in \
    "$EXECUTOR_BINARY" \
    "$DATA_DIR" \
    "$TEMPLATES_FILE" \
    "$PUBLIC_ORIGIN" \
    "$wrapper"; do
    encoded_value="$(encode_config_value "$value")"
    validate_encoded_config_value "$encoded_value" "a service path or origin"
    case "$value" in
        *'&'*|*'<'*|*'>'*|*'|'*|*'\'*)
            fail "service paths and origins cannot contain XML or template metacharacters"
            ;;
    esac
done
for trusted_proxy in "${trusted_proxies[@]}"; do
    [[ -n "$trusted_proxy" ]] || fail "trusted proxy entries cannot be empty"
    encoded_value="$(encode_config_value "$trusted_proxy")"
    validate_encoded_config_value "$encoded_value" "a trusted proxy"
done

normalize_absolute_path "$DATA_DIR" "the Executor data directory"
DATA_DIR=$normalized_path
normalize_absolute_path "$TEMPLATES_FILE" "the MCP stdio template file"
TEMPLATES_FILE=$normalized_path
templates_directory="$(dirname "$TEMPLATES_FILE")"
plist_directory="$(dirname "$PLIST")"
validate_safe_directory_path "$DATA_DIR" "the Executor data directory"
validate_safe_directory_path "$templates_directory" "the MCP template directory"
validate_safe_directory_path "$plist_directory" "the LaunchAgents directory"
canonicalize_path_without_creation "$DATA_DIR" "the Executor data directory"
DATA_DIR=$canonical_path
canonicalize_path_without_creation "$TEMPLATES_FILE" "the MCP stdio template file"
TEMPLATES_FILE=$canonical_path
templates_directory="$(dirname "$TEMPLATES_FILE")"
private_log="${DATA_DIR}/executor.log"
validate_configured_path_collisions
require_recoverable_template_file false
require_regular_file_or_absent "$wrapper" "the LaunchAgent wrapper path"
require_regular_file_or_absent "$log_writer" "the bounded log helper path"
require_regular_file_or_absent "$private_log" "the private log path"
for generation in {1..3}; do
    require_regular_file_or_absent "${private_log}.${generation}" \
        "the rotated private log path"
done
require_regular_file_or_absent "$PLIST" "the LaunchAgent plist path"

if [[ "$validate_only" == true ]]; then
    printf 'LaunchAgent paths and configuration are valid.\n'
    exit 0
fi

ensure_safe_directory_path "$EXECUTOR_ROOT" "the Executor root directory"
require_safe_directory_metadata "$EXECUTOR_ROOT" "the Executor root directory" current
chmod 0700 "$EXECUTOR_ROOT"
ensure_safe_directory_path "$INSTALL_ROOT" "the Executor service directory"
require_safe_directory_metadata "$INSTALL_ROOT" "the Executor service directory" current
chmod 0700 "$INSTALL_ROOT"
require_private_control_file "$CONFIG_FILE" "the persisted service configuration"
require_private_control_file "$MANIFEST" "the service ownership manifest"
require_private_control_file "$RECOVERY_MARKER" "the service installation recovery marker"

ensure_safe_directory_path "$DATA_DIR" "the Executor data directory"
require_safe_directory_metadata "$DATA_DIR" "the Executor data directory" current
ensure_safe_directory_path "$templates_directory" "the MCP template directory"
ensure_safe_directory_path "$plist_directory" "the LaunchAgents directory"
chmod 0700 "$DATA_DIR"
DATA_DIR="$(cd "$DATA_DIR" && pwd -P)"
TEMPLATES_FILE="$(absolute_path "$TEMPLATES_FILE")"

private_log="${DATA_DIR}/executor.log"
validate_configured_path_collisions
require_recoverable_template_file false
require_regular_file_or_absent "$wrapper" "the LaunchAgent wrapper path"
require_regular_file_or_absent "$log_writer" "the bounded log helper path"
require_regular_file_or_absent "$private_log" "the private log path"
for generation in {1..3}; do
    require_regular_file_or_absent "${private_log}.${generation}" \
        "the rotated private log path"
done
require_regular_file_or_absent "$PLIST" "the LaunchAgent plist path"

if [[ -e "$RECOVERY_MARKER" ]]; then
    recovery_contents="$(cat "$RECOVERY_MARKER")"
    [[ "$recovery_contents" == executor-service-install-recovery-v1 ]] \
        || fail "the service installation recovery marker is malformed"
else
    temporary_recovery="$(mktemp "${INSTALL_ROOT}/.service-recovery.XXXXXXXX")"
    trap 'rm -f "$temporary_recovery"' EXIT
    printf 'executor-service-install-recovery-v1\n' > "$temporary_recovery"
    chmod 0600 "$temporary_recovery"
    sync
    mv "$temporary_recovery" "$RECOVERY_MARKER"
    trap - EXIT
    sync
fi

require_recoverable_template_file true

temporary_config="$(mktemp "${INSTALL_ROOT}/.service-config.XXXXXXXX")"
trap 'rm -f "$temporary_config"' EXIT
{
    printf 'executor-launchd-config-v1\n'
    printf 'data_dir_hex=%s\n' "$(encode_config_value "$DATA_DIR")"
    printf 'templates_file_hex=%s\n' "$(encode_config_value "$TEMPLATES_FILE")"
    printf 'public_origin_hex=%s\n' "$(encode_config_value "$PUBLIC_ORIGIN")"
    for trusted_proxy in "${trusted_proxies[@]}"; do
        printf 'trusted_proxy_hex=%s\n' "$(encode_config_value "$trusted_proxy")"
    done
} > "$temporary_config"
chmod 0600 "$temporary_config"
sync
mv -f "$temporary_config" "$CONFIG_FILE"
trap - EXIT
sync

if [[ ! -e "$TEMPLATES_FILE" && ! -L "$TEMPLATES_FILE" ]]; then
    temporary_templates="$(mktemp "${templates_directory}/.executor-templates.XXXXXXXX")"
    trap 'rm -f "$temporary_templates"' EXIT
    printf '{\n  "templates": []\n}\n' > "$temporary_templates"
    chmod 0600 "$temporary_templates"
    sync
    if ! ln "$temporary_templates" "$TEMPLATES_FILE"; then
        fail "the MCP stdio template path appeared during installation"
    fi
    sync
    if [[ ${EXECUTOR_INSTALL_TEST_CRASH_AFTER_TEMPLATE_LINK:-} == 1 ]]; then
        kill -KILL "${BASHPID}"
    fi
    rm -f "$temporary_templates"
    if [[ ${EXECUTOR_INSTALL_TEST_CRASH_AFTER_TEMPLATE_UNLINK:-} == 1 ]]; then
        kill -KILL "${BASHPID}"
    fi
    sync
    trap - EXIT
fi
[[ -f "$TEMPLATES_FILE" && ! -L "$TEMPLATES_FILE" ]] \
    || fail "the MCP stdio template path must be a regular file"
chmod 0600 "$TEMPLATES_FILE"
require_private_control_file "$TEMPLATES_FILE" "the MCP stdio template path"

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

binary_hash="$(shasum -a 256 "$EXECUTOR_BINARY" | awk '{print $1}')"
plist_hash="$(shasum -a 256 "$PLIST" | awk '{print $1}')"
wrapper_hash="$(shasum -a 256 "$wrapper" | awk '{print $1}')"
logger_hash="$(shasum -a 256 "$log_writer" | awk '{print $1}')"
config_hash="$(shasum -a 256 "$CONFIG_FILE" | awk '{print $1}')"
temporary_manifest="$(mktemp "${INSTALL_ROOT}/.service-install.XXXXXXXX")"
trap 'rm -f "$temporary_manifest"' EXIT
{
    printf 'executor-service-install-v1\n'
    printf 'binary %s\n' "$binary_hash"
    printf 'plist %s\n' "$plist_hash"
    printf 'wrapper %s\n' "$wrapper_hash"
    printf 'logger %s\n' "$logger_hash"
    printf 'config %s\n' "$config_hash"
} > "$temporary_manifest"
chmod 0600 "$temporary_manifest"
sync
mv -f "$temporary_manifest" "$MANIFEST"
trap - EXIT
sync
rm -f "$RECOVERY_MARKER"
sync

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
