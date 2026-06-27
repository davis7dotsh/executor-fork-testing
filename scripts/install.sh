#!/usr/bin/env bash
set -euo pipefail

APP="executor"
REPOSITORY="${EXECUTOR_REPOSITORY:-davis7dotsh/executor-fork-testing}"
INSTALL_DIR="${EXECUTOR_INSTALL_DIR:-$HOME/.executor/bin}"
MANIFEST_NAME=".executor-install-manifest"
PATH_OWNERSHIP_NAME=".executor-path-ownership"
RECOVERY_NAME=".executor-install-recovery"
LOCK_NAME=".executor-install-lock"
requested_version="${VERSION:-}"
binary_path=""
local_archive_path=""
local_checksum_path=""
no_modify_path=false
uninstall=false
version_option=false
manifest_present=false
manifest_digest=""
manifest_executor_hash=""
manifest_license_hash=""
manifest_rust_notices_hash=""
manifest_javascript_notices_hash=""
manifest_path_ownership_hash=""
install_source_executor=""
install_source_license=""
install_source_rust_notices=""
install_source_javascript_notices=""
record_path_config=false
path_update_requested=false
path_already_present=false
recorded_config_file=""
recorded_path_command=""
path_edit_changed=false
path_edit_error=""
path_edit_lock_acquired=false
path_edit_lock_digest=""
path_edit_lock_identity=""
path_edit_lock_path=""
path_edit_parent=""
path_edit_parent_identity=""
path_edit_result=""
trusted_temp_root=""
trusted_temp_root_identity=""
temporary_directory=""
temporary_directory_identity=""
test_swapped_temp_directory=""
install_lock_acquired=false
install_lock_digest=""
install_lock_identity=""
install_root_identity=""
install_root_parent=""
install_root_parent_identity=""
recovery_executor_old=""
recovery_executor_new=""
recovery_license_old=""
recovery_license_new=""
recovery_rust_notices_old=""
recovery_rust_notices_new=""
recovery_javascript_notices_old=""
recovery_javascript_notices_new=""
recovery_path_ownership_old=""
recovery_path_ownership_new=""

usage() {
    cat <<EOF
Executor installer

Usage: install.sh [options]

Options:
    -h, --help              Display this help message
    -v, --version <version> Install a specific version, such as 2.0.0
    -b, --binary <path>     Install from a local binary instead of downloading
    -a, --archive <path>    Install a release archive from disk
        --checksum <path>   Checksum sidecar for --archive (default: <path>.sha256)
        --no-modify-path    Do not modify shell configuration files
        --uninstall         Remove installer-owned files and PATH entry

Environment:
    EXECUTOR_INSTALL_DIR    Binary directory (default: \$HOME/.executor/bin)
    EXECUTOR_REPOSITORY     GitHub owner/repository for downloads
                            (default: davis7dotsh/executor-fork-testing)
    VERSION                 Version to install when --version is omitted

Examples:
    curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/main/scripts/install.sh | bash
    curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/main/scripts/install.sh | bash -s -- --version 2.0.0
    curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/main/scripts/install.sh | bash -s -- --uninstall
    ./scripts/install.sh --binary ./target/release/executor
EOF
}

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--version)
            [[ -n "${2:-}" ]] || fail "--version requires a version"
            requested_version="$2"
            version_option=true
            shift 2
            ;;
        -b|--binary)
            [[ -n "${2:-}" ]] || fail "--binary requires a path"
            binary_path="$2"
            shift 2
            ;;
        -a|--archive)
            [[ -n "${2:-}" ]] || fail "--archive requires a path"
            local_archive_path="$2"
            shift 2
            ;;
        --checksum)
            [[ -n "${2:-}" ]] || fail "--checksum requires a path"
            local_checksum_path="$2"
            shift 2
            ;;
        --no-modify-path)
            no_modify_path=true
            shift
            ;;
        --uninstall)
            uninstall=true
            shift
            ;;
        *)
            fail "unknown option: $1"
            ;;
    esac
done

if [[ -n "$binary_path" && -n "$local_archive_path" ]]; then
    fail "--binary and --archive cannot be used together"
fi
if [[ -n "$local_checksum_path" && -z "$local_archive_path" ]]; then
    fail "--checksum requires --archive"
fi
if [[ "$uninstall" == "true" ]] \
    && [[ "$version_option" == "true" \
        || -n "$binary_path" \
        || -n "$local_archive_path" \
        || -n "$local_checksum_path" ]]; then
    fail "--uninstall cannot be combined with install source options"
fi

[[ "$INSTALL_DIR" == /* ]] || fail "EXECUTOR_INSTALL_DIR must be an absolute path"
[[ "$INSTALL_DIR" != "/" ]] || fail "EXECUTOR_INSTALL_DIR cannot be the filesystem root"
case "$INSTALL_DIR" in
    *:*|*$'\n'*|*$'\r'*) fail "EXECUTOR_INSTALL_DIR cannot contain colons or line breaks" ;;
esac

resolve_path_config() {
    local current_shell quoted_install_dir
    current_shell="$(basename "${SHELL:-bash}")"
    case "$current_shell" in
        fish)
            config_file="$HOME/.config/fish/config.fish"
            quoted_install_dir=${INSTALL_DIR//\\/\\\\}
            quoted_install_dir=${quoted_install_dir//\'/\\\'}
            path_command="fish_add_path -- '$quoted_install_dir'"
            ;;
        zsh)
            config_file="${ZDOTDIR:-$HOME}/.zshrc"
            printf -v quoted_install_dir '%q' "$INSTALL_DIR"
            path_command="export PATH=$quoted_install_dir:\$PATH"
            ;;
        *)
            config_file="$HOME/.bashrc"
            printf -v quoted_install_dir '%q' "$INSTALL_DIR"
            path_command="export PATH=$quoted_install_dir:\$PATH"
            ;;
    esac
}

file_has_exact_line() {
    local file=$1 expected=$2 line normalized
    while IFS= read -r line || [[ -n "$line" ]]; do
        normalized="${line%$'\r'}"
        if [[ "$normalized" == "$expected" ]]; then
            return 0
        fi
    done < "$file"
    return 1
}

prepare_path_config_tracking() {
    if [[ "$no_modify_path" == "true" || ":${PATH}:" == *":${INSTALL_DIR}:"* ]]; then
        return 0
    fi
    path_update_requested=true
    resolve_path_config
    recorded_config_file="$config_file"
    recorded_path_command="$path_command"
    case "$recorded_config_file$recorded_path_command" in
        *$'\t'*|*$'\n'*|*$'\r'*) return 0 ;;
    esac
    [[ "$recorded_config_file" == /* ]] || return 0
    if [[ -f "$recorded_config_file" \
        && ! -L "$recorded_config_file" \
        && -O "$recorded_config_file" \
        && -w "$recorded_config_file" ]]; then
        if file_has_exact_line "$recorded_config_file" "$recorded_path_command"; then
            path_already_present=true
            return 0
        fi
        record_path_config=true
    fi
}

print_manual_path_change() {
    local operation=$1 config=$2 command=$3
    if [[ "$operation" == "add" ]]; then
        printf 'Add this to %s:\n  %s\n' "$config" "$command"
    else
        printf 'Could not update %s. Remove these exact lines manually:\n' "$config"
        printf '  # Executor\n  %s\n' "$command"
    fi
}

remove_path_entry() {
    edit_path_config_portable remove "$1" "$2"
}

sha256_file() {
    local path=$1
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$path" | awk '{ print $1 }'
    else
        fail "sha256sum or shasum is required"
    fi
}

durability_checkpoint() {
    local label=$1
    if [[ -n "${EXECUTOR_INSTALL_TEST_DURABILITY_LOG:-}" ]]; then
        printf '%s\n' "$label" >> "$EXECUTOR_INSTALL_TEST_DURABILITY_LOG" \
            || fail "could not record durability checkpoint: $label"
    fi
    if [[ "${EXECUTOR_INSTALL_TEST_FAIL_DURABILITY_POINT:-}" == "$label" ]]; then
        fail "injected durability failure at $label"
    fi
}

sync_with_label() {
    local label=$1
    command -v sync >/dev/null 2>&1 || return 1
    EXECUTOR_INSTALL_SYNC_LABEL="$label" sync
}

durability_barrier() {
    local label=$1
    if [[ -n "$install_root_identity" ]]; then
        assert_install_root
    fi
    sync_with_label "$label" || fail "could not complete durability barrier: $label"
    durability_checkpoint "$label"
}

portable_file_identity() {
    if stat -c '%d:%i:%u:%g:%f' -- "$1" >/dev/null 2>&1; then
        stat -c '%d:%i:%u:%g:%f' -- "$1"
    else
        stat -f '%d:%i:%u:%g:%p' "$1"
    fi
}

portable_link_count() {
    if stat -c '%h' -- "$1" >/dev/null 2>&1; then
        stat -c '%h' -- "$1"
    else
        stat -f '%l' "$1"
    fi
}

process_identity() {
    local pid=$1 stat_line remainder start_time boot_id snapshot
    if [[ "${EXECUTOR_INSTALL_TEST_FAIL_PROCESS_IDENTITY_PID:-}" == "$pid" ]]; then
        return 1
    fi
    if [[ -r "/proc/${pid}/stat" && -r /proc/sys/kernel/random/boot_id ]]; then
        stat_line="$(< "/proc/${pid}/stat")" || return 1
        [[ "$stat_line" == *') '* ]] || return 1
        remainder="${stat_line##*) }"
        start_time="$(awk '{ print $20 }' <<< "$remainder")"
        [[ "$start_time" =~ ^[0-9]+$ ]] || return 1
        boot_id="$(< /proc/sys/kernel/random/boot_id)" || return 1
        printf 'linux:%s:%s\n' "$boot_id" "$start_time"
        return 0
    fi
    snapshot="$(LC_ALL=C ps -p "$pid" -o lstart= -o command= 2>/dev/null)" \
        || return 1
    [[ -n "$snapshot" ]] || return 1
    printf '%s' "$snapshot" | cksum | awk '{ printf "ps:%s:%s\n", $1, $2 }'
}

validate_existing_secure_directory_chain() {
    local path=$1 remainder component current
    [[ "$path" == /* ]] || return 1
    case "$path" in
        */|*//*|*/./*|*/../*|*/.|*/..) return 1 ;;
    esac
    validate_install_path_component /
    remainder="${path#/}"
    current=""
    while [[ -n "$remainder" ]]; do
        component="${remainder%%/*}"
        [[ -n "$component" && "$component" != "." && "$component" != ".." ]] \
            || return 1
        current="${current}/${component}"
        validate_install_path_component "$current"
        if [[ "$remainder" == "$component" ]]; then
            remainder=""
        else
            remainder="${remainder#*/}"
        fi
    done
}

assert_path_edit_parent() {
    [[ -d "$path_edit_parent" && ! -L "$path_edit_parent" ]] \
        || return 1
    [[ "$(portable_file_identity "$path_edit_parent")" == "$path_edit_parent_identity" ]]
}

read_path_edit_lock() {
    local lock=$1 before after line key value extra line_number=0
    observed_lock_pid=""
    observed_lock_process_identity=""
    [[ -f "$lock" && ! -L "$lock" && -O "$lock" ]] || return 1
    before="$(sha256_file "$lock")" || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        if [[ "$line_number" -eq 1 ]]; then
            [[ "$line" == "executor-path-edit-lock-v1" ]] || return 1
            continue
        fi
        IFS=' ' read -r key value extra <<< "$line"
        [[ -n "$key" && -n "$value" && -z "${extra:-}" ]] || return 1
        case "$key" in
            pid)
                [[ -z "$observed_lock_pid" && "$value" =~ ^[1-9][0-9]*$ ]] \
                    || return 1
                observed_lock_pid="$value"
                ;;
            identity)
                [[ -z "$observed_lock_process_identity" \
                    && "$value" =~ ^[A-Za-z0-9:._-]+$ ]] \
                    || return 1
                observed_lock_process_identity="$value"
                ;;
            *) return 1 ;;
        esac
    done < "$lock"
    [[ "$line_number" -eq 3 \
        && -n "$observed_lock_pid" \
        && -n "$observed_lock_process_identity" ]] \
        || return 1
    after="$(sha256_file "$lock")" || return 1
    [[ "$after" == "$before" ]] || return 1
    observed_lock_digest="$after"
    observed_lock_identity="$(portable_file_identity "$lock")" || return 1
}

reclaim_stale_path_edit_lock() {
    local lock=$1 expected_identity=$2 expected_digest=$3 candidate snapshot
    assert_install_root
    assert_path_edit_parent || return 1
    for candidate in "${lock}.owner."*; do
        [[ -e "$candidate" || -L "$candidate" ]] || continue
        if [[ -f "$candidate" && ! -L "$candidate" && -O "$candidate" ]] \
            && [[ "$(portable_file_identity "$candidate")" == "$expected_identity" ]] \
            && [[ "$(sha256_file "$candidate")" == "$expected_digest" ]]; then
            rm -f -- "$candidate" || return 1
        fi
    done
    sync_with_label path-edit-stale-owner-cleanup || return 1
    snapshot="$(mktemp "${lock}.stale.XXXXXXXX")" || return 1
    rm -f -- "$snapshot" || return 1
    if ! ln "$lock" "$snapshot" 2>/dev/null; then
        return 1
    fi
    if [[ ! -f "$lock" \
        || -L "$lock" \
        || "$(portable_file_identity "$lock")" != "$expected_identity" \
        || "$(sha256_file "$lock")" != "$expected_digest" \
        || "$(portable_file_identity "$snapshot")" != "$expected_identity" \
        || "$(portable_link_count "$snapshot")" -ne 2 ]]; then
        rm -f -- "$snapshot" || return 1
        sync_with_label path-edit-stale-snapshot-cleanup || return 1
        return 1
    fi
    if ! assert_path_edit_parent; then
        rm -f -- "$snapshot" || return 1
        return 1
    fi
    if ! rm -f -- "$lock"; then
        if ! rm -f -- "$snapshot"; then
            :
        fi
        return 1
    fi
    sync_with_label path-edit-stale-lock-reclaimed || return 1
    rm -f -- "$snapshot" || return 1
    sync_with_label path-edit-stale-lock-cleanup || return 1
}

cleanup_unacquired_path_edit_lock() {
    local lock=$1 temporary=$2 status=0
    rm -f -- "$lock" || status=1
    rm -f -- "$temporary" || status=1
    return "$status"
}

acquire_path_edit_lock() {
    local config=$1 temporary owner_identity current_identity attempt
    path_edit_parent="$(dirname "$config")"
    validate_existing_secure_directory_chain "$path_edit_parent" || return 1
    path_edit_parent_identity="$(portable_file_identity "$path_edit_parent")" || return 1
    path_edit_lock_path="${config}.executor-edit-lock"
    owner_identity="$(process_identity "$$")" || return 1

    for attempt in {1..200}; do
        assert_install_root
        assert_path_edit_parent || return 1
        if [[ -e "$path_edit_lock_path" || -L "$path_edit_lock_path" ]]; then
            read_path_edit_lock "$path_edit_lock_path" || return 1
            if kill -0 "$observed_lock_pid" 2>/dev/null; then
                current_identity="$(process_identity "$observed_lock_pid" 2>/dev/null)" \
                    || return 1
                if [[ "$current_identity" == "$observed_lock_process_identity" ]]; then
                    sleep 0.05 || return 1
                    continue
                fi
            elif current_identity="$(process_identity "$observed_lock_pid" 2>/dev/null)"; then
                return 1
            fi
            if reclaim_stale_path_edit_lock \
                "$path_edit_lock_path" \
                "$observed_lock_identity" \
                "$observed_lock_digest"; then
                continue
            fi
            sleep 0.05 || return 1
            continue
        fi

        temporary="$(mktemp "${path_edit_lock_path}.owner.XXXXXXXX")" || return 1
        if ! {
            printf 'executor-path-edit-lock-v1\n'
            printf 'pid %s\n' "$$"
            printf 'identity %s\n' "$owner_identity"
        } > "$temporary"; then
            rm -f -- "$temporary" || return 1
            return 1
        fi
        if ! chmod 0600 "$temporary"; then
            rm -f -- "$temporary" || return 1
            return 1
        fi
        if ! sync_with_label path-edit-owner-record-durable; then
            rm -f -- "$temporary" || return 1
            return 1
        fi
        if ln "$temporary" "$path_edit_lock_path" 2>/dev/null; then
            if ! sync_with_label path-edit-lock-acquired; then
                rm -f -- "$path_edit_lock_path" || return 1
                rm -f -- "$temporary" || return 1
                sync_with_label path-edit-lock-acquire-rollback || return 1
                return 1
            fi
            path_edit_lock_identity="$(portable_file_identity "$path_edit_lock_path")" \
                || { cleanup_unacquired_path_edit_lock "$path_edit_lock_path" "$temporary"; return 1; }
            path_edit_lock_digest="$(sha256_file "$path_edit_lock_path")" \
                || { cleanup_unacquired_path_edit_lock "$path_edit_lock_path" "$temporary"; return 1; }
            path_edit_lock_acquired=true
            if ! rm -f -- "$temporary"; then
                release_path_edit_lock || return 1
                return 1
            fi
            sync_with_label path-edit-owner-temp-cleanup || return 1
            return 0
        fi
        rm -f -- "$temporary" || return 1
        sync_with_label path-edit-owner-temp-cleanup || return 1
    done
    return 1
}

release_path_edit_lock() {
    if [[ "$path_edit_lock_acquired" != "true" ]]; then
        return 0
    fi
    assert_path_edit_parent || return 1
    [[ -f "$path_edit_lock_path" \
        && ! -L "$path_edit_lock_path" \
        && "$(portable_file_identity "$path_edit_lock_path")" == "$path_edit_lock_identity" \
        && "$(sha256_file "$path_edit_lock_path")" == "$path_edit_lock_digest" ]] \
        || return 1
    rm -f -- "$path_edit_lock_path" || return 1
    sync_with_label path-edit-lock-release || return 1
    path_edit_lock_acquired=false
}

file_has_owned_path_block() {
    local file=$1 expected=$2 previous="" line normalized
    while IFS= read -r line || [[ -n "$line" ]]; do
        normalized="${line%$'\r'}"
        if [[ "$previous" == "# Executor" && "$normalized" == "$expected" ]]; then
            return 0
        fi
        previous="$normalized"
    done < "$file"
    return 1
}

perform_path_config_edit() {
    local operation=$1 config=$2 command=$3 attempt temporary
    local initial_identity initial_digest current_identity current_digest final_newline
    path_edit_error=""
    path_edit_result=""
    for attempt in {1..4}; do
        assert_install_root
        assert_path_edit_parent \
            || { path_edit_error="shell-config parent changed during update"; return 1; }
        initial_identity="$(portable_file_identity "$config")" \
            || { path_edit_error="could not inspect shell config"; return 1; }
        initial_digest="$(sha256_file "$config")" \
            || { path_edit_error="could not hash shell config"; return 1; }

        if [[ "$operation" == "add" ]] && file_has_exact_line "$config" "$command"; then
            path_edit_result=unchanged
            return 0
        fi
        if [[ "$operation" == "remove" ]] \
            && ! file_has_owned_path_block "$config" "$command"; then
            path_edit_result=unchanged
            return 0
        fi

        temporary="$(mktemp "${path_edit_parent}/.$(basename "$config").executor-XXXXXXXX")" \
            || { path_edit_error="could not create shell-config staging file"; return 1; }
        if ! cp -p "$config" "$temporary"; then
            rm -f -- "$temporary" \
                || path_edit_error="could not remove failed shell-config staging file"
            path_edit_error="could not stage shell config"
            return 1
        fi
        if [[ "${EXECUTOR_INSTALL_TEST_FAIL_CONFIG_WRITE:-}" == "1" ]]; then
            rm -f -- "$temporary" \
                || path_edit_error="could not remove injected shell-config staging file"
            path_edit_error="injected shell-config write failure"
            return 1
        fi
        if [[ "${EXECUTOR_INSTALL_TEST_FAIL_REAL_CONFIG_WRITE:-}" == "1" ]]; then
            if ! chmod 0400 "$temporary"; then
                rm -f -- "$temporary" \
                    || path_edit_error="could not remove failed shell-config staging file"
                path_edit_error="could not make the shell-config staging file read-only"
                return 1
            fi
        fi

        if [[ "$operation" == "add" ]]; then
            if [[ -s "$config" && "$(tail -c 1 "$config" | wc -l)" -eq 0 ]]; then
                if ! printf '\n' >> "$temporary"; then
                    rm -f -- "$temporary" \
                        || path_edit_error="could not remove failed shell-config staging file"
                    path_edit_error="could not append a shell-config separator"
                    return 1
                fi
            fi
            if ! printf '# Executor\n%s\n' "$command" >> "$temporary"; then
                rm -f -- "$temporary" \
                    || path_edit_error="could not remove failed shell-config staging file"
                path_edit_error="could not append the shell-config PATH block"
                return 1
            fi
        elif [[ "$operation" == "remove" ]]; then
            if [[ ! -s "$config" || "$(tail -c 1 "$config" | wc -l)" -eq 1 ]]; then
                final_newline=true
            else
                final_newline=false
            fi
            if ! EXECUTOR_PATH_EDIT_COMMAND="$command" \
                EXECUTOR_PATH_EDIT_FINAL_NEWLINE="$final_newline" \
                awk '
                    function body(value, normalized) {
                        normalized = value
                        sub(/\r$/, "", normalized)
                        return normalized
                    }
                    { lines[++count] = $0 }
                    END {
                        for (cursor = 1; cursor <= count; cursor++) {
                            if (body(lines[cursor]) == "# Executor" \
                                && cursor < count \
                                && body(lines[cursor + 1]) == ENVIRON["EXECUTOR_PATH_EDIT_COMMAND"]) {
                                cursor++
                                continue
                            }
                            printf "%s", lines[cursor]
                            if (cursor < count \
                                || ENVIRON["EXECUTOR_PATH_EDIT_FINAL_NEWLINE"] == "true") {
                                printf "\n"
                            }
                        }
                    }
                ' "$config" > "$temporary"; then
                rm -f -- "$temporary" \
                    || path_edit_error="could not remove failed shell-config staging file"
                path_edit_error="could not rewrite shell config"
                return 1
            fi
        else
            rm -f -- "$temporary" \
                || path_edit_error="could not remove invalid shell-config staging file"
            path_edit_error="invalid shell-config operation"
            return 1
        fi

        durability_barrier "staged-path-config-durable:$operation" sync "$temporary"
        if ! assert_path_edit_parent; then
            if ! rm -f -- "$temporary"; then
                path_edit_error="shell-config parent changed and staging cleanup failed"
            else
                path_edit_error="shell-config parent changed during update"
            fi
            return 1
        fi
        current_identity="$(portable_file_identity "$config")" || current_identity=""
        current_digest="$(sha256_file "$config")" || current_digest=""
        if [[ "$current_identity" != "$initial_identity" \
            || "$current_digest" != "$initial_digest" ]]; then
            rm -f -- "$temporary" \
                || { path_edit_error="could not remove stale shell-config staging file"; return 1; }
            continue
        fi
        if [[ "${EXECUTOR_INSTALL_TEST_FAIL_CONFIG_RENAME:-}" == "1" ]]; then
            rm -f -- "$temporary" \
                || path_edit_error="could not remove injected shell-config staging file"
            path_edit_error="injected shell-config rename failure"
            return 1
        fi
        if ! mv -f "$temporary" "$config"; then
            rm -f -- "$temporary" \
                || path_edit_error="could not remove failed shell-config staging file"
            path_edit_error="could not publish shell-config update"
            return 1
        fi
        durability_barrier "path-config-durable:$operation" sync "$config" "$path_edit_parent"
        path_edit_result=changed
        return 0
    done
    path_edit_error="shell config changed during every update attempt"
    return 1
}

edit_path_config_portable() {
    local operation=$1 config=$2 command=$3
    path_edit_changed=false
    if [[ ! -e "$config" ]]; then
        if [[ "$operation" == "add" ]]; then
            print_manual_path_change "$operation" "$config" "$command"
        fi
        return 0
    fi
    if [[ ! -f "$config" || -L "$config" || ! -O "$config" || ! -w "$config" ]]; then
        print_manual_path_change "$operation" "$config" "$command"
        return 0
    fi
    if ! acquire_path_edit_lock "$config"; then
        print_manual_path_change "$operation" "$config" "$command"
        return 0
    fi
    if [[ -n "${EXECUTOR_INSTALL_TEST_CONFIG_PAUSE_READY:-}" \
        || -n "${EXECUTOR_INSTALL_TEST_CONFIG_PAUSE_RELEASE:-}" ]]; then
        if [[ -z "${EXECUTOR_INSTALL_TEST_CONFIG_PAUSE_READY:-}" \
            || -z "${EXECUTOR_INSTALL_TEST_CONFIG_PAUSE_RELEASE:-}" ]]; then
            release_path_edit_lock
            fail "config pause injection is incomplete"
        fi
        : > "$EXECUTOR_INSTALL_TEST_CONFIG_PAUSE_READY"
        sync_with_label path-edit-test-pause \
            || fail "could not publish config pause checkpoint"
        while [[ ! -e "$EXECUTOR_INSTALL_TEST_CONFIG_PAUSE_RELEASE" ]]; do
            sleep 0.01
        done
    fi
    if ! perform_path_config_edit "$operation" "$config" "$command"; then
        if ! release_path_edit_lock; then
            path_edit_error="$path_edit_error; could not release shell-config edit lock"
        fi
        fail "$path_edit_error"
    fi
    release_path_edit_lock || fail "could not release shell-config edit lock"
    if [[ "$path_edit_result" == "changed" ]]; then
        path_edit_changed=true
        if [[ "$operation" == "add" ]]; then
            printf 'Added Executor to PATH in %s\n' "$config"
        else
            printf 'Removed Executor PATH entry from %s\n' "$config"
        fi
    fi
}

install_path_owner_mode() {
    if stat -c '%u:%a' -- "$1" >/dev/null 2>&1; then
        stat -c '%u:%a' -- "$1"
    else
        stat -f '%u:%Lp' "$1"
    fi
}

validate_install_path_component() {
    local path=$1 metadata uid mode numeric_mode
    [[ -d "$path" && ! -L "$path" ]] \
        || fail "install path component is not a real directory: $path"
    metadata="$(install_path_owner_mode "$path")" \
        || fail "could not inspect install path component: $path"
    IFS=: read -r uid mode <<< "$metadata"
    [[ "$uid" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]+$ ]] \
        || fail "install path component metadata is malformed: $path"
    [[ "$uid" -eq 0 || "$uid" -eq "$EUID" ]] \
        || fail "install path components must be owned by root or the current user: $path"
    numeric_mode=$((8#$mode))
    (( (numeric_mode & 0022) == 0 )) \
        || fail "install path components cannot be group or world writable: $path"
}

assert_install_root() {
    [[ -d "$install_root_parent" && ! -L "$install_root_parent" ]] \
        || fail "install root parent changed after validation: $install_root_parent"
    [[ "$(portable_file_identity "$install_root_parent")" \
        == "$install_root_parent_identity" ]] \
        || fail "install root parent changed after validation: $install_root_parent"
    [[ -d "$INSTALL_DIR" && ! -L "$INSTALL_DIR" && -O "$INSTALL_DIR" ]] \
        || fail "install root changed after validation: $INSTALL_DIR"
    [[ "$(portable_file_identity "$INSTALL_DIR")" == "$install_root_identity" ]] \
        || fail "install root changed after validation: $INSTALL_DIR"
}

prepare_install_root() {
    local remainder component current
    case "$INSTALL_DIR" in
        */|*//*|*/./*|*/../*|*/.|*/..)
            fail "EXECUTOR_INSTALL_DIR must be a normalized absolute path"
            ;;
    esac

    validate_install_path_component /
    remainder="${INSTALL_DIR#/}"
    current=""
    while [[ -n "$remainder" ]]; do
        component="${remainder%%/*}"
        [[ -n "$component" && "$component" != "." && "$component" != ".." ]] \
            || fail "EXECUTOR_INSTALL_DIR must be a normalized absolute path"
        current="${current}/${component}"
        if [[ ! -e "$current" && ! -L "$current" ]]; then
            if ! mkdir -m 0700 -- "$current" 2>/dev/null; then
                [[ -e "$current" || -L "$current" ]] \
                    || fail "could not create install path component: $current"
            fi
        fi
        validate_install_path_component "$current"
        if [[ "$remainder" == "$component" ]]; then
            remainder=""
        else
            remainder="${remainder#*/}"
        fi
    done

    [[ -O "$INSTALL_DIR" ]] \
        || fail "install root must be owned by the current user: $INSTALL_DIR"
    install_root_parent="$(dirname "$INSTALL_DIR")"
    install_root_parent_identity="$(portable_file_identity "$install_root_parent")"
    install_root_identity="$(portable_file_identity "$INSTALL_DIR")"
    durability_barrier install-root-durable sync "$INSTALL_DIR"
}

read_install_lock() {
    local lock=$1 before after line key value extra line_number=0
    observed_lock_pid=""
    observed_lock_process_identity=""
    [[ -f "$lock" && ! -L "$lock" && -O "$lock" ]] \
        || fail "install lock is not a regular current-user-owned file: $lock"
    before="$(sha256_file "$lock")"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        if [[ "$line_number" -eq 1 ]]; then
            [[ "$line" == "executor-install-lock-v1" ]] \
                || fail "install lock has an unsupported format"
            continue
        fi
        IFS=' ' read -r key value extra <<< "$line"
        [[ -n "$key" && -n "$value" && -z "${extra:-}" ]] \
            || fail "install lock contains a malformed entry"
        case "$key" in
            pid)
                [[ -z "$observed_lock_pid" && "$value" =~ ^[1-9][0-9]*$ ]] \
                    || fail "install lock contains an invalid pid"
                observed_lock_pid="$value"
                ;;
            identity)
                [[ -z "$observed_lock_process_identity" \
                    && "$value" =~ ^[A-Za-z0-9:._-]+$ ]] \
                    || fail "install lock contains an invalid process identity"
                observed_lock_process_identity="$value"
                ;;
            *) fail "install lock contains an unsupported entry: $key" ;;
        esac
    done < "$lock"
    [[ "$line_number" -eq 3 \
        && -n "$observed_lock_pid" \
        && -n "$observed_lock_process_identity" ]] \
        || fail "install lock is incomplete"
    after="$(sha256_file "$lock")"
    [[ "$after" == "$before" ]] || fail "install lock changed while it was read"
    observed_lock_digest="$after"
    observed_lock_identity="$(portable_file_identity "$lock")"
}

reclaim_stale_install_lock() {
    local lock=$1 expected_identity=$2 expected_digest=$3 candidate snapshot
    assert_install_root
    for candidate in "${lock}.owner."*; do
        [[ -e "$candidate" || -L "$candidate" ]] || continue
        if [[ -f "$candidate" && ! -L "$candidate" && -O "$candidate" ]] \
            && [[ "$(portable_file_identity "$candidate")" == "$expected_identity" ]] \
            && [[ "$(sha256_file "$candidate")" == "$expected_digest" ]]; then
            rm -f -- "$candidate" || return 1
        fi
    done
    durability_barrier stale-lock-owner-cleanup-durable sync "$INSTALL_DIR"
    snapshot="$(mktemp "${INSTALL_DIR}/.${LOCK_NAME}.stale.XXXXXXXX")" || return 1
    rm -f -- "$snapshot" || return 1
    if ! ln "$lock" "$snapshot" 2>/dev/null; then
        return 1
    fi
    if [[ ! -f "$lock" \
        || -L "$lock" \
        || "$(portable_file_identity "$lock")" != "$expected_identity" \
        || "$(sha256_file "$lock")" != "$expected_digest" \
        || "$(portable_file_identity "$snapshot")" != "$expected_identity" \
        || "$(portable_link_count "$snapshot")" -ne 2 ]]; then
        rm -f -- "$snapshot" || return 1
        durability_barrier stale-lock-snapshot-cleanup sync "$INSTALL_DIR"
        return 1
    fi
    assert_install_root
    if ! rm -f -- "$lock"; then
        rm -f -- "$snapshot" || return 1
        return 1
    fi
    durability_barrier stale-lock-reclaimed sync "$INSTALL_DIR"
    rm -f -- "$snapshot" || return 1
    durability_barrier stale-lock-cleanup-durable sync "$INSTALL_DIR"
}

test_pause_if_requested() {
    local point=$1
    if [[ "${EXECUTOR_INSTALL_TEST_PAUSE_POINT:-}" != "$point" ]]; then
        return 0
    fi
    [[ -n "${EXECUTOR_INSTALL_TEST_PAUSE_READY:-}" \
        && -n "${EXECUTOR_INSTALL_TEST_PAUSE_RELEASE:-}" ]] \
        || fail "pause injection requires ready and release paths"
    : > "$EXECUTOR_INSTALL_TEST_PAUSE_READY"
    durability_barrier "test-pause-ready:$point" sync "$EXECUTOR_INSTALL_TEST_PAUSE_READY"
    while [[ ! -e "$EXECUTOR_INSTALL_TEST_PAUSE_RELEASE" ]]; do
        sleep 0.1
    done
}

acquire_install_lock() {
    local lock="${INSTALL_DIR}/${LOCK_NAME}" temporary owner_identity
    local current_identity attempt
    assert_install_root
    owner_identity="$(process_identity "$$")" \
        || fail "could not determine installer process identity"
    for attempt in {1..8}; do
        temporary="$(mktemp "${INSTALL_DIR}/.${LOCK_NAME}.owner.XXXXXXXX")" \
            || fail "could not create install-lock owner record"
        if ! {
            printf 'executor-install-lock-v1\n'
            printf 'pid %s\n' "$$"
            printf 'identity %s\n' "$owner_identity"
        } > "$temporary"; then
            fail "could not write install-lock owner record"
        fi
        chmod 0600 "$temporary" || fail "could not protect install-lock owner record"
        durability_barrier lock-owner-record-durable sync "$temporary"
        assert_install_root
        if ln "$temporary" "$lock" 2>/dev/null; then
            durability_barrier lock-acquired sync "$INSTALL_DIR"
            install_lock_identity="$(portable_file_identity "$lock")"
            install_lock_digest="$(sha256_file "$lock")"
            install_lock_acquired=true
            rm -f -- "$temporary" || fail "could not remove install-lock owner staging file"
            durability_barrier lock-owner-temp-cleanup sync "$INSTALL_DIR"
            test_pause_if_requested after-lock
            return 0
        fi
        rm -f -- "$temporary" || fail "could not remove install-lock owner staging file"
        durability_barrier lock-owner-temp-cleanup sync "$INSTALL_DIR"
        if [[ ! -e "$lock" && ! -L "$lock" ]]; then
            continue
        fi
        read_install_lock "$lock"
        if kill -0 "$observed_lock_pid" 2>/dev/null; then
            current_identity="$(process_identity "$observed_lock_pid" 2>/dev/null)" \
                || fail "could not verify live install-lock owner pid $observed_lock_pid"
            if [[ "$current_identity" == "$observed_lock_process_identity" ]]; then
                fail "another Executor installer is active with pid $observed_lock_pid"
            fi
        elif current_identity="$(process_identity "$observed_lock_pid" 2>/dev/null)"; then
            fail "install-lock owner pid $observed_lock_pid exists but cannot be signaled"
        fi
        if reclaim_stale_install_lock \
            "$lock" \
            "$observed_lock_identity" \
            "$observed_lock_digest"; then
            continue
        fi
    done
    fail "could not acquire the Executor install lock after concurrent changes"
}

release_install_lock() {
    local lock="${INSTALL_DIR}/${LOCK_NAME}"
    if [[ "$install_lock_acquired" != "true" ]]; then
        return 0
    fi
    if [[ ! -f "$lock" \
        || -L "$lock" \
        || "$(portable_file_identity "$lock")" != "$install_lock_identity" \
        || "$(sha256_file "$lock")" != "$install_lock_digest" ]]; then
        printf 'Error: install lock changed while held\n' >&2
        return 1
    fi
    assert_install_root
    if ! rm -f -- "$lock"; then
        printf 'Error: could not release install lock\n' >&2
        return 1
    fi
    if ! sync_with_label install-lock-release; then
        printf 'Error: could not durably release install lock\n' >&2
        return 1
    fi
    if [[ -n "${EXECUTOR_INSTALL_TEST_DURABILITY_LOG:-}" ]]; then
        printf 'lock-released\n' >> "$EXECUTOR_INSTALL_TEST_DURABILITY_LOG" || return 1
    fi
    install_lock_acquired=false
}

installer_exit_cleanup() {
    local status=$?
    trap - EXIT
    if declare -F cleanup_private_temp_directory >/dev/null 2>&1; then
        cleanup_private_temp_directory || status=1
    fi
    if declare -F release_path_edit_lock >/dev/null 2>&1; then
        release_path_edit_lock || status=1
    fi
    release_install_lock || status=1
    exit "$status"
}

manifest_hash_for() {
    case "$1" in
        executor) printf '%s\n' "$manifest_executor_hash" ;;
        LICENSE) printf '%s\n' "$manifest_license_hash" ;;
        THIRD_PARTY_LICENSES.html) printf '%s\n' "$manifest_rust_notices_hash" ;;
        THIRD_PARTY_JAVASCRIPT_LICENSES.json)
            printf '%s\n' "$manifest_javascript_notices_hash"
            ;;
        .executor-path-ownership) printf '%s\n' "$manifest_path_ownership_hash" ;;
        *) fail "install manifest contains an unsupported file name: $1" ;;
    esac
}

set_manifest_hash() {
    local name=$1 hash=$2
    case "$name" in
        executor) manifest_executor_hash="$hash" ;;
        LICENSE) manifest_license_hash="$hash" ;;
        THIRD_PARTY_LICENSES.html) manifest_rust_notices_hash="$hash" ;;
        THIRD_PARTY_JAVASCRIPT_LICENSES.json)
            manifest_javascript_notices_hash="$hash"
            ;;
        .executor-path-ownership) manifest_path_ownership_hash="$hash" ;;
        *) fail "install manifest contains an unsupported file name: $name" ;;
    esac
}

verify_owned_file() {
    local name=$1 expected=$2 path actual
    path="${INSTALL_DIR}/${name}"
    [[ -f "$path" && ! -L "$path" ]] \
        || fail "installer-owned file is missing or not regular: $path"
    actual="$(sha256_file "$path")"
    [[ "$actual" == "$expected" ]] \
        || fail "installer-owned file was replaced after installation: $path"
}

load_install_manifest() {
    local manifest="${INSTALL_DIR}/${MANIFEST_NAME}"
    local allow_missing=${1:-false}
    local line hash name extra existing before_digest after_digest
    local line_number=0 entry_count=0
    manifest_present=false
    manifest_digest=""
    manifest_executor_hash=""
    manifest_license_hash=""
    manifest_rust_notices_hash=""
    manifest_javascript_notices_hash=""
    manifest_path_ownership_hash=""

    if [[ ! -e "$manifest" && ! -L "$manifest" ]]; then
        return 0
    fi
    [[ -f "$manifest" && ! -L "$manifest" && -O "$manifest" ]] \
        || fail "install manifest is not a regular owned file: $manifest"
    before_digest="$(sha256_file "$manifest")"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        if [[ "$line_number" -eq 1 ]]; then
            [[ "$line" == "executor-install-manifest-v1" ]] \
                || fail "install manifest has an unsupported format"
            continue
        fi
        IFS=' ' read -r hash name extra <<< "$line"
        [[ -n "$hash" && -n "$name" && -z "${extra:-}" && "$line" == "$hash $name" ]] \
            || fail "install manifest contains a malformed entry"
        [[ "$hash" =~ ^[0-9a-f]{64}$ ]] \
            || fail "install manifest contains a malformed SHA-256"
        existing="$(manifest_hash_for "$name")"
        [[ -z "$existing" ]] || fail "install manifest contains a duplicate entry: $name"
        set_manifest_hash "$name" "$hash"
        entry_count=$((entry_count + 1))
    done < "$manifest"
    [[ "$line_number" -gt 1 && "$entry_count" -gt 0 ]] \
        || fail "install manifest contains no owned files"
    after_digest="$(sha256_file "$manifest")"
    [[ "$after_digest" == "$before_digest" ]] \
        || fail "install manifest changed while it was being read"
    manifest_present=true
    manifest_digest="$after_digest"

    for name in \
        executor \
        LICENSE \
        THIRD_PARTY_LICENSES.html \
        THIRD_PARTY_JAVASCRIPT_LICENSES.json \
        .executor-path-ownership; do
        hash="$(manifest_hash_for "$name")"
        if [[ -n "$hash" ]]; then
            if [[ -e "${INSTALL_DIR}/${name}" || -L "${INSTALL_DIR}/${name}" ]]; then
                verify_owned_file "$name" "$hash"
            elif [[ "$allow_missing" != "true" ]]; then
                fail "installer-owned file is missing: ${INSTALL_DIR}/${name}"
            fi
        fi
    done
}

prepare_install_ownership() {
    local name expected path
    load_install_manifest
    for name in "$@"; do
        path="${INSTALL_DIR}/${name}"
        expected="$(manifest_hash_for "$name")"
        if [[ -e "$path" || -L "$path" ]]; then
            [[ -n "$expected" ]] \
                || fail "refusing to overwrite a file not owned by this installer: $path"
        fi
    done
}

install_source_for() {
    case "$1" in
        executor) printf '%s\n' "$install_source_executor" ;;
        LICENSE) printf '%s\n' "$install_source_license" ;;
        THIRD_PARTY_LICENSES.html) printf '%s\n' "$install_source_rust_notices" ;;
        THIRD_PARTY_JAVASCRIPT_LICENSES.json)
            printf '%s\n' "$install_source_javascript_notices"
            ;;
        *) fail "unsupported install transaction file: $1" ;;
    esac
}

install_mode_for() {
    if [[ "$1" == "executor" ]]; then
        printf '0755\n'
    elif [[ "$1" == ".executor-path-ownership" ]]; then
        printf '0600\n'
    else
        printf '0644\n'
    fi
}

set_recovery_hashes() {
    local name=$1 old=$2 new=$3
    case "$name" in
        executor)
            recovery_executor_old="$old"
            recovery_executor_new="$new"
            ;;
        LICENSE)
            recovery_license_old="$old"
            recovery_license_new="$new"
            ;;
        THIRD_PARTY_LICENSES.html)
            recovery_rust_notices_old="$old"
            recovery_rust_notices_new="$new"
            ;;
        THIRD_PARTY_JAVASCRIPT_LICENSES.json)
            recovery_javascript_notices_old="$old"
            recovery_javascript_notices_new="$new"
            ;;
        .executor-path-ownership)
            recovery_path_ownership_old="$old"
            recovery_path_ownership_new="$new"
            ;;
        *) fail "install recovery contains an unsupported file name: $name" ;;
    esac
}

recovery_old_for() {
    case "$1" in
        executor) printf '%s\n' "$recovery_executor_old" ;;
        LICENSE) printf '%s\n' "$recovery_license_old" ;;
        THIRD_PARTY_LICENSES.html) printf '%s\n' "$recovery_rust_notices_old" ;;
        THIRD_PARTY_JAVASCRIPT_LICENSES.json)
            printf '%s\n' "$recovery_javascript_notices_old"
            ;;
        .executor-path-ownership) printf '%s\n' "$recovery_path_ownership_old" ;;
        *) fail "install recovery contains an unsupported file name: $1" ;;
    esac
}

recovery_new_for() {
    case "$1" in
        executor) printf '%s\n' "$recovery_executor_new" ;;
        LICENSE) printf '%s\n' "$recovery_license_new" ;;
        THIRD_PARTY_LICENSES.html) printf '%s\n' "$recovery_rust_notices_new" ;;
        THIRD_PARTY_JAVASCRIPT_LICENSES.json)
            printf '%s\n' "$recovery_javascript_notices_new"
            ;;
        .executor-path-ownership) printf '%s\n' "$recovery_path_ownership_new" ;;
        *) fail "install recovery contains an unsupported file name: $1" ;;
    esac
}

copy_file_atomically() {
    local source=$1 destination=$2 label=$3 temporary parent
    assert_install_root
    parent="$(dirname "$destination")"
    temporary="$(mktemp "${destination}.recovery.XXXXXXXX")" \
        || fail "could not create rollback staging file"
    trap 'rm -f "$temporary"' RETURN
    cp -p "$source" "$temporary" || fail "could not stage rollback file"
    durability_barrier "staged-restore-durable:$label" sync "$temporary"
    assert_install_root
    mv -f "$temporary" "$destination" || fail "could not publish rollback file"
    durability_barrier "$label" sync "$destination" "$parent"
    trap - RETURN
}

retire_install_recovery() {
    local label=$1 recovery="${INSTALL_DIR}/${RECOVERY_NAME}" retired
    assert_install_root
    [[ -d "$recovery" && ! -L "$recovery" ]] \
        || fail "install recovery directory disappeared"
    retired="$(mktemp -d "${INSTALL_DIR}/.${RECOVERY_NAME}.retired.XXXXXXXX")" \
        || fail "could not create recovery retirement directory"
    assert_install_root
    mv "$recovery" "${retired}/state" || fail "could not retire install recovery"
    durability_barrier "recovery-retired:$label" sync "$retired" "$INSTALL_DIR"
    rm -rf "$retired" || fail "could not remove retired install recovery"
    durability_barrier "recovery-cleanup-durable:$label" sync "$INSTALL_DIR"
}

create_path_ownership_state() {
    local output=$1 existing="${INSTALL_DIR}/${PATH_OWNERSHIP_NAME}"
    local line tracked_config tracked_command extra line_number=0 entry_count=0
    local already_recorded=false
    printf 'executor-path-ownership-v1\n' > "$output"
    if [[ -n "$manifest_path_ownership_hash" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line_number=$((line_number + 1))
            if [[ "$line_number" -eq 1 ]]; then
                [[ "$line" == "executor-path-ownership-v1" ]] \
                    || fail "PATH ownership state has an unsupported format"
                continue
            fi
            IFS=$'\t' read -r tracked_config tracked_command extra <<< "$line"
            [[ -n "$tracked_config" \
                && -n "$tracked_command" \
                && -z "${extra:-}" \
                && "$tracked_config" == /* \
                && "$line" == "$tracked_config"$'\t'"$tracked_command" ]] \
                || fail "PATH ownership state has a malformed entry"
            printf '%s\t%s\n' "$tracked_config" "$tracked_command" >> "$output"
            if [[ "$tracked_config" == "$recorded_config_file" \
                && "$tracked_command" == "$recorded_path_command" ]]; then
                already_recorded=true
            fi
            entry_count=$((entry_count + 1))
        done < "$existing"
        [[ "$line_number" -gt 1 && "$entry_count" -gt 0 ]] \
            || fail "PATH ownership state contains no entries"
    fi
    if [[ "$already_recorded" != "true" ]]; then
        printf '%s\t%s\n' \
            "$recorded_config_file" \
            "$recorded_path_command" \
            >> "$output"
    fi
    chmod 0600 "$output"
}

remove_recorded_path_entries() {
    local state="${INSTALL_DIR}/${PATH_OWNERSHIP_NAME}"
    local line tracked_config tracked_command extra line_number=0 entry_count=0
    [[ -e "$state" || -L "$state" ]] || return 0
    [[ -f "$state" && ! -L "$state" && -O "$state" ]] \
        || fail "PATH ownership state is not a regular owned file"

    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        if [[ "$line_number" -eq 1 ]]; then
            [[ "$line" == "executor-path-ownership-v1" ]] \
                || fail "PATH ownership state has an unsupported format"
            continue
        fi
        IFS=$'\t' read -r tracked_config tracked_command extra <<< "$line"
        [[ -n "$tracked_config" \
            && -n "$tracked_command" \
            && -z "${extra:-}" \
            && "$tracked_config" == /* \
            && "$line" == "$tracked_config"$'\t'"$tracked_command" ]] \
            || fail "PATH ownership state has a malformed entry"
        entry_count=$((entry_count + 1))
    done < "$state"
    [[ "$line_number" -gt 1 && "$entry_count" -gt 0 ]] \
        || fail "PATH ownership state contains no entries"

    line_number=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        if [[ "$line_number" -eq 1 ]]; then
            continue
        fi
        IFS=$'\t' read -r tracked_config tracked_command extra <<< "$line"
        remove_path_entry "$tracked_config" "$tracked_command"
    done < "$state"
}

begin_install_transaction() {
    local recovery="${INSTALL_DIR}/${RECOVERY_NAME}" temporary plan_entries
    local manifest="${INSTALL_DIR}/${MANIFEST_NAME}"
    local transaction_label=$1
    local old_manifest new_manifest name source mode old_hash new_hash hash
    assert_install_root
    prepare_install_ownership "$@"
    mkdir -p "$INSTALL_DIR"
    durability_barrier "install-directory-durable:$transaction_label" chain "$INSTALL_DIR"
    [[ ! -e "$recovery" && ! -L "$recovery" ]] \
        || fail "an install recovery transaction is already present"

    temporary="$(mktemp -d "${INSTALL_DIR}/.${RECOVERY_NAME}.XXXXXXXX")" \
        || fail "could not create install recovery staging directory"
    trap 'rm -rf "$temporary"' RETURN
    chmod 0700 "$temporary"
    mkdir "${temporary}/backup" "${temporary}/new"
    plan_entries="${temporary}/plan.entries"
    : > "$plan_entries"
    chmod 0600 "$plan_entries"

    if [[ "$manifest_present" == "true" ]]; then
        cp -p "$manifest" "${temporary}/backup/${MANIFEST_NAME}"
        old_manifest="$manifest_digest"
    else
        old_manifest=absent
    fi

    for name in "$@"; do
        mode="$(install_mode_for "$name")"
        old_hash="$(manifest_hash_for "$name")"
        if [[ -n "$old_hash" ]]; then
            cp -p "${INSTALL_DIR}/${name}" "${temporary}/backup/${name}"
        else
            old_hash=absent
        fi
        if [[ "$name" == "$PATH_OWNERSHIP_NAME" ]]; then
            create_path_ownership_state "${temporary}/new/${name}"
        else
            source="$(install_source_for "$name")"
            [[ -f "$source" && ! -L "$source" ]] \
                || fail "install source is missing or not regular: $source"
            cp "$source" "${temporary}/new/${name}"
            chmod "$mode" "${temporary}/new/${name}"
        fi
        new_hash="$(sha256_file "${temporary}/new/${name}")"
        set_manifest_hash "$name" "$new_hash"
        printf 'file %s %s %s\n' "$old_hash" "$new_hash" "$name" >> "$plan_entries"
    done

    new_manifest="${temporary}/new/${MANIFEST_NAME}"
    printf 'executor-install-manifest-v1\n' > "$new_manifest"
    for name in \
        executor \
        LICENSE \
        THIRD_PARTY_LICENSES.html \
        THIRD_PARTY_JAVASCRIPT_LICENSES.json \
        .executor-path-ownership; do
        hash="$(manifest_hash_for "$name")"
        if [[ -n "$hash" ]]; then
            printf '%s %s\n' "$hash" "$name" >> "$new_manifest"
        fi
    done
    chmod 0600 "$new_manifest"
    new_manifest="$(sha256_file "$new_manifest")"

    {
        printf 'executor-install-recovery-v1\n'
        printf 'manifest %s %s\n' "$old_manifest" "$new_manifest"
        cat "$plan_entries"
    } > "${temporary}/plan"
    chmod 0600 "${temporary}/plan"
    rm -f "$plan_entries" || fail "could not finalize install recovery plan"
    durability_barrier "recovery-tree-durable:$transaction_label" tree "$temporary"
    assert_install_root
    mv "$temporary" "$recovery" || fail "could not publish install recovery"
    durability_barrier "recovery-durable:$transaction_label" sync "$recovery" "$INSTALL_DIR"
    trap - RETURN
}

recover_install_transaction() {
    local recovery="${INSTALL_DIR}/${RECOVERY_NAME}" plan manifest
    local line kind old_hash new_hash name extra current_hash
    local old_manifest="" new_manifest="" line_number=0 entry_count=0
    assert_install_root
    recovery_executor_old=""
    recovery_executor_new=""
    recovery_license_old=""
    recovery_license_new=""
    recovery_rust_notices_old=""
    recovery_rust_notices_new=""
    recovery_javascript_notices_old=""
    recovery_javascript_notices_new=""
    recovery_path_ownership_old=""
    recovery_path_ownership_new=""

    if [[ ! -e "$recovery" && ! -L "$recovery" ]]; then
        return 0
    fi
    [[ -d "$recovery" && ! -L "$recovery" && -O "$recovery" ]] \
        || fail "install recovery is not a private owned directory"
    plan="${recovery}/plan"
    [[ -f "$plan" && ! -L "$plan" && -O "$plan" ]] \
        || fail "install recovery plan is not a regular owned file"

    while IFS= read -r line || [[ -n "$line" ]]; do
        line_number=$((line_number + 1))
        if [[ "$line_number" -eq 1 ]]; then
            [[ "$line" == "executor-install-recovery-v1" ]] \
                || fail "install recovery has an unsupported format"
            continue
        fi
        if [[ "$line_number" -eq 2 ]]; then
            IFS=' ' read -r kind old_manifest new_manifest extra <<< "$line"
            [[ "$kind" == "manifest" && -z "${extra:-}" ]] \
                || fail "install recovery has a malformed manifest entry"
            [[ "$old_manifest" == "absent" || "$old_manifest" =~ ^[0-9a-f]{64}$ ]] \
                || fail "install recovery has a malformed old manifest hash"
            [[ "$new_manifest" =~ ^[0-9a-f]{64}$ ]] \
                || fail "install recovery has a malformed new manifest hash"
            continue
        fi
        IFS=' ' read -r kind old_hash new_hash name extra <<< "$line"
        [[ "$kind" == "file" && -n "$name" && -z "${extra:-}" ]] \
            || fail "install recovery has a malformed file entry"
        [[ "$old_hash" == "absent" || "$old_hash" =~ ^[0-9a-f]{64}$ ]] \
            || fail "install recovery has a malformed old file hash"
        [[ "$new_hash" =~ ^[0-9a-f]{64}$ ]] \
            || fail "install recovery has a malformed new file hash"
        [[ -z "$(recovery_new_for "$name")" ]] \
            || fail "install recovery has a duplicate file entry: $name"
        set_recovery_hashes "$name" "$old_hash" "$new_hash"
        entry_count=$((entry_count + 1))
    done < "$plan"
    [[ "$line_number" -gt 2 && "$entry_count" -gt 0 ]] \
        || fail "install recovery contains no files"

    manifest="${recovery}/new/${MANIFEST_NAME}"
    [[ -f "$manifest" && ! -L "$manifest" ]] \
        || fail "install recovery is missing the new manifest"
    [[ "$(sha256_file "$manifest")" == "$new_manifest" ]] \
        || fail "install recovery new manifest hash does not match"
    if [[ "$old_manifest" != "absent" ]]; then
        manifest="${recovery}/backup/${MANIFEST_NAME}"
        [[ -f "$manifest" && ! -L "$manifest" ]] \
            || fail "install recovery is missing the old manifest"
        [[ "$(sha256_file "$manifest")" == "$old_manifest" ]] \
            || fail "install recovery old manifest hash does not match"
    fi

    for name in \
        executor \
        LICENSE \
        THIRD_PARTY_LICENSES.html \
        THIRD_PARTY_JAVASCRIPT_LICENSES.json \
        .executor-path-ownership; do
        new_hash="$(recovery_new_for "$name")"
        if [[ -z "$new_hash" ]]; then
            continue
        fi
        old_hash="$(recovery_old_for "$name")"
        [[ -f "${recovery}/new/${name}" && ! -L "${recovery}/new/${name}" ]] \
            || fail "install recovery is missing a staged file: $name"
        [[ "$(sha256_file "${recovery}/new/${name}")" == "$new_hash" ]] \
            || fail "install recovery staged file hash does not match: $name"
        if [[ "$old_hash" != "absent" ]]; then
            [[ -f "${recovery}/backup/${name}" && ! -L "${recovery}/backup/${name}" ]] \
                || fail "install recovery is missing a backup file: $name"
            [[ "$(sha256_file "${recovery}/backup/${name}")" == "$old_hash" ]] \
                || fail "install recovery backup hash does not match: $name"
        elif [[ -e "${recovery}/backup/${name}" || -L "${recovery}/backup/${name}" ]]; then
            fail "install recovery has an unexpected backup file: $name"
        fi

        if [[ -e "${INSTALL_DIR}/${name}" || -L "${INSTALL_DIR}/${name}" ]]; then
            [[ -f "${INSTALL_DIR}/${name}" && ! -L "${INSTALL_DIR}/${name}" ]] \
                || fail "install destination was replaced during recovery: $name"
            current_hash="$(sha256_file "${INSTALL_DIR}/${name}")"
            [[ "$current_hash" == "$new_hash" \
                || "$old_hash" != "absent" && "$current_hash" == "$old_hash" ]] \
                || fail "install destination changed outside the recovery transaction: $name"
        fi
    done

    manifest="${INSTALL_DIR}/${MANIFEST_NAME}"
    if [[ -e "$manifest" || -L "$manifest" ]]; then
        [[ -f "$manifest" && ! -L "$manifest" && -O "$manifest" ]] \
            || fail "install manifest was replaced during recovery"
        current_hash="$(sha256_file "$manifest")"
        [[ "$current_hash" == "$new_manifest" \
            || "$old_manifest" != "absent" && "$current_hash" == "$old_manifest" ]] \
            || fail "install manifest changed outside the recovery transaction"
    fi

    assert_install_root
    for name in \
        executor \
        LICENSE \
        THIRD_PARTY_LICENSES.html \
        THIRD_PARTY_JAVASCRIPT_LICENSES.json \
        .executor-path-ownership; do
        new_hash="$(recovery_new_for "$name")"
        if [[ -z "$new_hash" ]]; then
            continue
        fi
        old_hash="$(recovery_old_for "$name")"
        if [[ "$old_hash" == "absent" ]]; then
            assert_install_root
            rm -f -- "${INSTALL_DIR}/${name}" \
                || fail "could not remove interrupted install file: $name"
            durability_barrier "rollback-managed-durable:$name" sync "$INSTALL_DIR"
        else
            copy_file_atomically \
                "${recovery}/backup/${name}" \
                "${INSTALL_DIR}/${name}" \
                "rollback-managed-durable:$name"
        fi
    done
    if [[ "$old_manifest" == "absent" ]]; then
        assert_install_root
        rm -f -- "${INSTALL_DIR}/${MANIFEST_NAME}" \
            || fail "could not remove interrupted install manifest"
        durability_barrier "rollback-manifest-durable" sync "$INSTALL_DIR"
    else
        copy_file_atomically \
            "${recovery}/backup/${MANIFEST_NAME}" \
            "${INSTALL_DIR}/${MANIFEST_NAME}" \
            "rollback-manifest-durable"
    fi
    retire_install_recovery rollback
    printf 'Recovered an interrupted Executor installation\n'
}

commit_install_transaction() {
    local recovery="${INSTALL_DIR}/${RECOVERY_NAME}" transaction_label=$1
    local name mode count=0
    assert_install_root
    for name in "$@"; do
        mode="$(install_mode_for "$name")"
        install_file \
            "${recovery}/new/${name}" \
            "$name" \
            "$mode" \
            "managed-file-durable:$name"
        count=$((count + 1))
        test_pause_if_requested "after-install-file-$count"
        if [[ "${EXECUTOR_INSTALL_TEST_FAIL_AFTER_INSTALL_FILE:-}" == "$count" ]]; then
            fail "injected failure after publishing install file $count"
        fi
    done
    if [[ "${EXECUTOR_INSTALL_TEST_FAIL_MANIFEST:-}" == "1" ]]; then
        fail "injected install manifest publication failure"
    fi
    install_file \
        "${recovery}/new/${MANIFEST_NAME}" \
        "$MANIFEST_NAME" \
        0600 \
        "manifest-durable:$transaction_label"
    retire_install_recovery "$transaction_label"
}

remove_owned_file() {
    local name=$1 expected=$2
    assert_install_root
    if [[ -e "${INSTALL_DIR}/${name}" || -L "${INSTALL_DIR}/${name}" ]]; then
        verify_owned_file "$name" "$expected"
        assert_install_root
        rm -f -- "${INSTALL_DIR}/${name}" \
            || fail "could not remove installer-owned file: $name"
    fi
    durability_barrier "uninstall-file-durable:$name" sync "$INSTALL_DIR"
}

uninstall_executor() {
    local name hash manifest="${INSTALL_DIR}/${MANIFEST_NAME}"
    local removed_count=0 seen_existing_owned_file=false
    load_install_manifest true
    if [[ "$manifest_present" != "true" ]]; then
        for name in \
            executor \
            LICENSE \
            THIRD_PARTY_LICENSES.html \
            THIRD_PARTY_JAVASCRIPT_LICENSES.json \
            .executor-path-ownership; do
            if [[ -e "${INSTALL_DIR}/${name}" || -L "${INSTALL_DIR}/${name}" ]]; then
                fail "refusing to remove files without an installer ownership manifest"
            fi
        done
    fi

    for name in \
        executor \
        LICENSE \
        THIRD_PARTY_LICENSES.html \
        THIRD_PARTY_JAVASCRIPT_LICENSES.json \
        .executor-path-ownership; do
        hash="$(manifest_hash_for "$name")"
        if [[ -z "$hash" ]]; then
            continue
        fi
        if [[ -e "${INSTALL_DIR}/${name}" || -L "${INSTALL_DIR}/${name}" ]]; then
            seen_existing_owned_file=true
        elif [[ "$seen_existing_owned_file" == "true" ]]; then
            fail "installer-owned files are missing outside resumable uninstall order"
        fi
    done

    if [[ "$no_modify_path" != "true" && -n "$manifest_path_ownership_hash" ]]; then
        remove_recorded_path_entries
    fi

    if [[ "$manifest_present" == "true" ]]; then
        for name in \
            executor \
            LICENSE \
            THIRD_PARTY_LICENSES.html \
            THIRD_PARTY_JAVASCRIPT_LICENSES.json \
            .executor-path-ownership; do
            hash="$(manifest_hash_for "$name")"
            if [[ -n "$hash" ]]; then
                remove_owned_file "$name" "$hash"
                removed_count=$((removed_count + 1))
                if [[ "${EXECUTOR_INSTALL_TEST_FAIL_AFTER_UNINSTALL_DELETE:-}" \
                    == "$removed_count" ]]; then
                    fail "injected failure after uninstall file $removed_count"
                fi
            fi
        done
        [[ "$(sha256_file "$manifest")" == "$manifest_digest" ]] \
            || fail "install manifest changed during uninstall"
        assert_install_root
        rm -f -- "$manifest" || fail "could not remove install manifest"
        durability_barrier "uninstall-manifest-durable" sync "$INSTALL_DIR"
    fi
    printf 'Removed Executor program files from %s\n' "$INSTALL_DIR"
    printf 'Executor data, service definitions, and unrelated files were preserved.\n'
}

prepare_install_root
trap installer_exit_cleanup EXIT
test_pause_if_requested after-install-root
acquire_install_lock
recover_install_transaction

if [[ "$uninstall" == "true" ]]; then
    uninstall_executor
    exit 0
fi

case "$REPOSITORY" in
    ''|/*|*/|*/*/*|*[!A-Za-z0-9._/-]*)
        fail "EXECUTOR_REPOSITORY must be an owner/repository name"
        ;;
esac

case "${OSTYPE:-}" in
    darwin*) platform="apple-darwin" ;;
    linux*) platform="unknown-linux-gnu" ;;
    *) fail "Executor release binaries support only Linux and macOS" ;;
esac

machine="$(uname -m)"
case "$machine" in
    x86_64|amd64) architecture="x86_64" ;;
    arm64|aarch64) architecture="aarch64" ;;
    *) fail "unsupported architecture: $machine" ;;
esac

if [[ "$platform" == "apple-darwin" && "$architecture" == "x86_64" ]]; then
    if [[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf '0')" == "1" ]]; then
        architecture="aarch64"
    fi
fi

target="${architecture}-${platform}"
archive="${APP}-${target}.tar.gz"
if [[ -n "$binary_path" ]]; then
    planned_install_files=(executor)
else
    planned_install_files=(
        executor
        LICENSE
        THIRD_PARTY_LICENSES.html
        THIRD_PARTY_JAVASCRIPT_LICENSES.json
    )
fi
prepare_path_config_tracking

path_identity() {
    if [[ "$platform" == "apple-darwin" ]]; then
        stat -f '%u:%Lp:%d:%i' "$1"
    else
        stat -c '%u:%a:%d:%i' -- "$1"
    fi
}

validate_trusted_temp_component() {
    local path=$1 identity uid mode device inode numeric_mode
    [[ -d "$path" && ! -L "$path" ]] \
        || fail "temporary-directory ancestor is not a real directory: $path"
    identity="$(path_identity "$path")" \
        || fail "could not inspect temporary-directory ancestor: $path"
    IFS=: read -r uid mode device inode <<< "$identity"
    [[ "$uid" =~ ^[0-9]+$ \
        && "$mode" =~ ^[0-7]+$ \
        && "$device" =~ ^[0-9]+$ \
        && "$inode" =~ ^[0-9]+$ ]] \
        || fail "temporary-directory ancestor metadata is malformed: $path"
    numeric_mode=$((8#$mode))
    if [[ "$uid" -eq 0 ]]; then
        if (( (numeric_mode & 0022) != 0 && (numeric_mode & 01000) == 0 )); then
            fail "writable root-owned temporary-directory ancestors must have the sticky bit: $path"
        fi
    elif [[ "$uid" -eq "$EUID" ]]; then
        (( (numeric_mode & 0022) == 0 )) \
            || fail "current-user temporary-directory ancestors cannot be group or world writable: $path"
    else
        fail "temporary-directory ancestors must be owned by root or the current user: $path"
    fi
}

prepare_trusted_temp_root() {
    local raw_temp_root remainder component current
    raw_temp_root="${TMPDIR:-/tmp}"
    case "$raw_temp_root" in
        ''|*$'\t'*|*$'\n'*|*$'\r'*) fail "TMPDIR must be a nonempty absolute path without control characters" ;;
    esac
    [[ "$raw_temp_root" == /* ]] || fail "TMPDIR must be an absolute path"
    trusted_temp_root="$(cd -P -- "$raw_temp_root" 2>/dev/null && pwd -P)" \
        || fail "TMPDIR does not resolve to an accessible directory"
    [[ "$trusted_temp_root" != "/" ]] || fail "TMPDIR cannot be the filesystem root"

    validate_trusted_temp_component /
    remainder="${trusted_temp_root#/}"
    current=""
    while [[ -n "$remainder" ]]; do
        component="${remainder%%/*}"
        [[ -n "$component" && "$component" != "." && "$component" != ".." ]] \
            || fail "TMPDIR must be a normalized path without empty, dot, or dot-dot components"
        current="${current}/${component}"
        validate_trusted_temp_component "$current"
        if [[ "$remainder" == "$component" ]]; then
            remainder=""
        else
            remainder="${remainder#*/}"
        fi
    done
    trusted_temp_root_identity="$(path_identity "$trusted_temp_root")"
}

verify_private_temp_directory() {
    local root_identity directory_identity uid mode device inode
    [[ -n "$temporary_directory" ]] || fail "private temporary directory is not initialized"
    [[ -d "$trusted_temp_root" && ! -L "$trusted_temp_root" ]] \
        || fail "trusted temporary root was replaced"
    root_identity="$(path_identity "$trusted_temp_root")" \
        || fail "could not recheck trusted temporary root"
    [[ "$root_identity" == "$trusted_temp_root_identity" ]] \
        || fail "trusted temporary root changed during installation"
    [[ -d "$temporary_directory" && ! -L "$temporary_directory" ]] \
        || fail "private temporary directory was replaced"
    directory_identity="$(path_identity "$temporary_directory")" \
        || fail "could not inspect private temporary directory"
    [[ "$directory_identity" == "$temporary_directory_identity" ]] \
        || fail "private temporary directory changed during installation"
    IFS=: read -r uid mode device inode <<< "$directory_identity"
    [[ "$uid" -eq "$EUID" && "$mode" == "700" ]] \
        || fail "private temporary directory must remain current-user owned with mode 0700"
}

cleanup_private_temp_directory() {
    local current_identity
    if [[ -n "$temporary_directory" \
        && -d "$temporary_directory" \
        && ! -L "$temporary_directory" ]] \
        && current_identity="$(path_identity "$temporary_directory" 2>/dev/null)" \
        && [[ "$current_identity" == "$temporary_directory_identity" ]]; then
        rm -rf -- "$temporary_directory" || return 1
    fi
    if [[ -n "$test_swapped_temp_directory" \
        && -d "$test_swapped_temp_directory" \
        && ! -L "$test_swapped_temp_directory" ]] \
        && current_identity="$(path_identity "$test_swapped_temp_directory" 2>/dev/null)" \
        && [[ "$current_identity" == "$temporary_directory_identity" ]]; then
        rm -rf -- "$test_swapped_temp_directory" || return 1
    fi
}

make_temp_dir() {
    local identity uid mode device inode
    prepare_trusted_temp_root
    temporary_directory="$(mktemp -d "${trusted_temp_root}/${APP}-install.XXXXXXXX")"
    chmod 0700 "$temporary_directory"
    [[ -d "$temporary_directory" && ! -L "$temporary_directory" ]] \
        || fail "mktemp did not create a private directory"
    identity="$(path_identity "$temporary_directory")" \
        || fail "could not inspect the private temporary directory"
    IFS=: read -r uid mode device inode <<< "$identity"
    [[ "$uid" -eq "$EUID" && "$mode" == "700" ]] \
        || fail "mktemp directory is not current-user owned with mode 0700"
    temporary_directory_identity="$identity"
    verify_private_temp_directory
}

inject_temp_directory_swap_for_test() {
    if [[ "${EXECUTOR_INSTALL_TEST_SWAP_TEMP_DIRECTORY:-}" != "1" ]]; then
        return 0
    fi
    test_swapped_temp_directory="${temporary_directory}.original"
    mv "$temporary_directory" "$test_swapped_temp_directory"
    mkdir -m 0700 "$temporary_directory"
}

verify_checksum() {
    local checksum_file=$1 archive_path=$2 expected actual
    expected="$(awk 'NF { print $1; exit }' "$checksum_file")"
    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || fail "release checksum is malformed"
    actual="$(sha256_file "$archive_path")"
    [[ "$actual" == "$expected" ]] || fail "release checksum verification failed"
}

install_file() {
    local source=$1 destination=$2 mode=$3 label=$4 temporary
    assert_install_root
    mkdir -p "$INSTALL_DIR"
    temporary="$(mktemp "${INSTALL_DIR}/.${destination}.XXXXXXXX")" \
        || fail "could not create install staging file: $destination"
    trap 'rm -f "$temporary"' RETURN
    cp "$source" "$temporary" || fail "could not stage install file: $destination"
    chmod "$mode" "$temporary" || fail "could not set install file mode: $destination"
    durability_barrier "staged-file-durable:$destination" sync "$temporary"
    assert_install_root
    mv -f "$temporary" "${INSTALL_DIR}/${destination}" \
        || fail "could not publish install file: $destination"
    durability_barrier "$label" sync "${INSTALL_DIR}/${destination}" "$INSTALL_DIR"
    trap - RETURN
}

if [[ -n "$binary_path" ]]; then
    [[ -f "$binary_path" ]] || fail "binary not found at $binary_path"
    install_source_executor="$binary_path"
else
    command -v tar >/dev/null 2>&1 || fail "tar is required"

    make_temp_dir
    trap installer_exit_cleanup EXIT
    if [[ -n "$local_archive_path" ]]; then
        local_archive_source="$local_archive_path"
        local_checksum_source="${local_checksum_path:-${local_archive_path}.sha256}"
        [[ -f "$local_archive_source" && ! -L "$local_archive_source" ]] \
            || fail "archive is not a regular non-symlink file: $local_archive_source"
        [[ -f "$local_checksum_source" && ! -L "$local_checksum_source" ]] \
            || fail "checksum is not a regular non-symlink file: $local_checksum_source"
        archive_path="${temporary_directory}/${archive}"
        checksum_path="${archive_path}.sha256"
        verify_private_temp_directory
        (
            ulimit -f 524288
            cp "$local_archive_source" "$archive_path"
        )
        (
            ulimit -f 2048
            cp "$local_checksum_source" "$checksum_path"
        )
        chmod 0600 "$archive_path" "$checksum_path"
        verify_private_temp_directory
        if [[ "${EXECUTOR_INSTALL_TEST_REMOVE_SOURCE_AFTER_STAGE:-}" == "1" ]]; then
            rm -f -- "$local_archive_source" "$local_checksum_source"
        fi
    else
        command -v curl >/dev/null 2>&1 || fail "curl is required"
        requested_version="${requested_version#v}"
        if [[ -n "$requested_version" ]]; then
            case "$requested_version" in
                *[!A-Za-z0-9._-]*) fail "the requested version contains unsafe characters" ;;
            esac
            release_base="https://github.com/${REPOSITORY}/releases/download/v${requested_version}"
            version_label="v${requested_version}"
        else
            release_base="https://github.com/${REPOSITORY}/releases/latest/download"
            version_label="latest"
        fi
        archive_path="${temporary_directory}/${archive}"
        checksum_path="${archive_path}.sha256"

        printf 'Downloading Executor %s for %s\n' "$version_label" "$target"
        curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --max-filesize 268435456 \
            --output "$archive_path" "${release_base}/${archive}"
        curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --max-filesize 1048576 \
            --output "$checksum_path" "${release_base}/${archive}.sha256"
    fi
    inject_temp_directory_swap_for_test
    verify_private_temp_directory
    [[ "$(wc -c < "$archive_path")" -le 268435456 ]] \
        || fail "release archive exceeds 256 MiB"
    [[ "$(wc -c < "$checksum_path")" -le 1048576 ]] \
        || fail "release checksum exceeds 1 MiB"
    verify_checksum "$checksum_path" "$archive_path"

    members_path="${temporary_directory}/archive-members.txt"
    verify_private_temp_directory
    (
        ulimit -f 2048
        ulimit -t 30
        tar -tzf "$archive_path" > "$members_path"
    )
    archive_members="$(< "$members_path")"
    expected_members=$'executor\nLICENSE\nTHIRD_PARTY_LICENSES.html\nTHIRD_PARTY_JAVASCRIPT_LICENSES.json'
    [[ "$archive_members" == "$expected_members" ]] \
        || fail "release archive has unexpected members"
    verbose_members_path="${temporary_directory}/archive-members-verbose.txt"
    verify_private_temp_directory
    (
        ulimit -f 2048
        ulimit -t 30
        tar -tvzf "$archive_path" > "$verbose_members_path"
    )
    while IFS= read -r member; do
        [[ "${member:0:1}" == "-" ]] \
            || fail "release archive members must be regular files"
    done < "$verbose_members_path"

    extracted_directory="${temporary_directory}/extracted"
    mkdir "$extracted_directory"
    extract_member() {
        local member=$1 file_blocks=$2
        verify_private_temp_directory
        (
            ulimit -f "$file_blocks"
            ulimit -t 60
            tar -xOzf "$archive_path" "$member" \
                > "${extracted_directory}/${member}"
        )
    }
    extract_member executor 524288
    extract_member LICENSE 4096
    extract_member THIRD_PARTY_LICENSES.html 131072
    extract_member THIRD_PARTY_JAVASCRIPT_LICENSES.json 131072
    verify_private_temp_directory

    extracted_binary="${extracted_directory}/${APP}"
    [[ -f "$extracted_binary" && -s "$extracted_binary" && ! -L "$extracted_binary" ]] \
        || fail "release archive does not contain a regular executor binary"
    for support_file in \
        LICENSE \
        THIRD_PARTY_LICENSES.html \
        THIRD_PARTY_JAVASCRIPT_LICENSES.json; do
        [[ -s "${extracted_directory}/${support_file}" ]] \
            || fail "release archive contains an empty support file"
    done
    install_source_executor="$extracted_binary"
    install_source_license="${extracted_directory}/LICENSE"
    install_source_rust_notices="${extracted_directory}/THIRD_PARTY_LICENSES.html"
    install_source_javascript_notices="${extracted_directory}/THIRD_PARTY_JAVASCRIPT_LICENSES.json"
fi

if [[ -n "$temporary_directory" ]]; then
    verify_private_temp_directory
fi
begin_install_transaction "${planned_install_files[@]}"
commit_install_transaction "${planned_install_files[@]}"

add_to_path() {
    edit_path_config_portable add "$1" "$2"
}

if [[ "$path_update_requested" == "true" ]]; then
    if [[ "$path_already_present" == "true" ]]; then
        :
    elif [[ "$record_path_config" == "true" ]]; then
        begin_install_transaction "$PATH_OWNERSHIP_NAME"
        commit_install_transaction "$PATH_OWNERSHIP_NAME"
        add_to_path "$recorded_config_file" "$recorded_path_command"
        if [[ "${EXECUTOR_INSTALL_TEST_FAIL_AFTER_PATH_CONFIG:-}" == "1" ]]; then
            fail "injected failure after PATH configuration update"
        fi
    else
        print_manual_path_change add "$recorded_config_file" "$recorded_path_command"
    fi
fi

if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    printf '%s\n' "$INSTALL_DIR" >> "$GITHUB_PATH"
fi

printf '\nInstalled Executor at %s\n' "${INSTALL_DIR}/${APP}"
printf 'Start it with: executor server\n'
