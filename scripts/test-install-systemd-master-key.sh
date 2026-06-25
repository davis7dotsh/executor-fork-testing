#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "${SCRIPT_DIR}/lib/install-systemd-master-key.sh"

readonly CURRENT_UID=$(id -u)
readonly CURRENT_GID=$(id -g)
TEST_NUMBER=0
test_root=$(mktemp -d)
trap 'rm -rf -- "${test_root}"' EXIT
staging_parent="${test_root}/staging-parent"
mkdir "${staging_parent}"
chmod 0700 "${staging_parent}"

pass() {
    TEST_NUMBER=$((TEST_NUMBER + 1))
    printf 'ok %s - %s\n' "${TEST_NUMBER}" "$1"
}

fail() {
    printf 'not ok %s - %s\n' "$((TEST_NUMBER + 1))" "$1" >&2
    exit 1
}

assert() {
    local description=$1
    shift
    if ! "$@"; then
        fail "${description}"
    fi
}

layout_dir="${test_root}/layout"
mkdir "${layout_dir}"
layout_sentinel="${layout_dir}/managed-unit"
printf 'managed unit sentinel\n' > "${layout_sentinel}"
if executor_require_disjoint_paths \
    "${layout_sentinel}" "persistent state" \
    "${layout_sentinel}" "managed unit" 2>/dev/null; then
    fail "equal persistent and managed paths were accepted"
fi
if executor_require_disjoint_paths \
    "${layout_dir}" "persistent state" \
    "${layout_sentinel}" "managed unit" 2>/dev/null; then
    fail "nested persistent and managed paths were accepted"
fi
executor_require_disjoint_paths \
    "${layout_dir}/master.key" "persistent state" \
    "${test_root}/systemd/executor.service" "managed unit"
assert "path-layout rejection changed the managed sentinel" test \
    "$(cat "${layout_sentinel}")" = "managed unit sentinel"
pass "systemd persistent and managed paths stay disjoint without mutation"

valid_dir="${test_root}/valid"
mkdir "${valid_dir}"
valid_key="${valid_dir}/master.key"
printf '0123456789abcdef0123456789abcdef' > "${valid_key}"
chmod 0600 "${valid_key}"
valid_copy="${test_root}/valid-key.copy"
cp "${valid_key}" "${valid_copy}"
valid_inode=$(stat --format='%i' -- "${valid_key}")
executor_ensure_master_key \
    "${staging_parent}" "${valid_dir}" "${valid_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
assert "valid key bytes changed" cmp -s "${valid_copy}" "${valid_key}"
assert "valid key inode changed" test \
    "$(stat --format='%i' -- "${valid_key}")" = "${valid_inode}"
pass "valid existing key is preserved byte-for-byte"

mode_dir="${test_root}/wrong-mode"
mkdir "${mode_dir}"
mode_key="${mode_dir}/master.key"
printf '89abcdef0123456789abcdef01234567' > "${mode_key}"
chmod 0640 "${mode_key}"
if executor_ensure_master_key \
    "${staging_parent}" "${mode_dir}" "${mode_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "wrong-mode key was accepted"
fi
assert "wrong-mode key permissions were changed" test \
    "$(stat --format='%a' -- "${mode_key}")" = 640
assert "wrong-mode key bytes were changed" test \
    "$(cat "${mode_key}")" = '89abcdef0123456789abcdef01234567'
pass "existing key with unsafe mode is rejected without repair"

symlink_dir="${test_root}/symlink"
mkdir "${symlink_dir}"
symlink_target="${symlink_dir}/target"
printf 'fedcba9876543210fedcba9876543210' > "${symlink_target}"
chmod 0600 "${symlink_target}"
ln -s "${symlink_target}" "${symlink_dir}/master.key"
if executor_ensure_master_key \
    "${staging_parent}" "${symlink_dir}" "${symlink_dir}/master.key" \
    "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "symbolic-link key was accepted"
fi
assert "symbolic-link target changed" test \
    "$(cat "${symlink_target}")" = 'fedcba9876543210fedcba9876543210'
pass "symbolic-link key is rejected without touching its target"

hardlink_dir="${test_root}/hardlink"
mkdir "${hardlink_dir}"
hardlink_key="${hardlink_dir}/master.key"
printf '00112233445566778899aabbccddeeff' > "${hardlink_key}"
chmod 0600 "${hardlink_key}"
ln "${hardlink_key}" "${hardlink_dir}/alias"
if executor_ensure_master_key \
    "${staging_parent}" "${hardlink_dir}" "${hardlink_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "hard-linked key was accepted"
fi
assert "hard-linked key was mutated" test \
    "$(cat "${hardlink_dir}/alias")" = '00112233445566778899aabbccddeeff'
pass "hard-linked key is rejected without mutation"

directory_target="${test_root}/directory-target"
mkdir "${directory_target}"
ln -s "${directory_target}" "${test_root}/directory-link"
if executor_require_safe_directory "${test_root}/directory-link" 2>/dev/null; then
    fail "symbolic-link managed directory was accepted"
fi
pass "symbolic-link managed directory is rejected"

new_dir="${test_root}/new"
mkdir "${new_dir}"
new_key="${new_dir}/master.key"
executor_ensure_master_key \
    "${staging_parent}" "${new_dir}" "${new_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
assert "new key has the wrong size" test \
    "$(stat --format='%s' -- "${new_key}")" = 32
assert "new key has the wrong link count" test \
    "$(stat --format='%h' -- "${new_key}")" = 1
assert "new key has the wrong mode" test \
    "$(stat --format='%a' -- "${new_key}")" = 600
pass "new key is safely published with validated metadata"

unsafe_staging_parent="${test_root}/unsafe-staging-parent"
unsafe_staging_data="${test_root}/unsafe-staging-data"
mkdir "${unsafe_staging_parent}" "${unsafe_staging_data}"
chmod 0770 "${unsafe_staging_parent}"
if executor_ensure_master_key \
    "${unsafe_staging_parent}" "${unsafe_staging_data}" \
    "${unsafe_staging_data}/master.key" \
    "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "group-writable staging parent was accepted"
fi
pass "staging parent must exclude unprivileged writers"

contention_dir="${test_root}/lock-contention"
mkdir "${contention_dir}"
contention_key="${contention_dir}/master.key"
printf 'contention-key-must-stay-intact!' > "${contention_key}"
chmod 0600 "${contention_key}"
contention_copy="${test_root}/contention-key.copy"
cp "${contention_key}" "${contention_copy}"
lock_path="${staging_parent}/.executor-master-key.lock"
exec {held_lock_fd}<>"${lock_path}"
flock -n -x "${held_lock_fd}"
if executor_ensure_master_key \
    "${staging_parent}" "${contention_dir}" "${contention_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "a live master key installation lock was ignored"
fi
assert "lock contention changed the existing master key" cmp -s \
    "${contention_copy}" "${contention_key}"
flock -u "${held_lock_fd}"
exec {held_lock_fd}>&-
executor_ensure_master_key \
    "${staging_parent}" "${contention_dir}" "${contention_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
pass "master key installation lock rejects contention without blocking"

spoof_staging_parent="${test_root}/spoof-staging-parent"
spoof_data_dir="${test_root}/spoof-data"
mkdir "${spoof_staging_parent}" "${spoof_data_dir}"
chmod 0700 "${spoof_staging_parent}"
spoof_lock="${spoof_staging_parent}/.executor-master-key.lock"
spoof_victim="${test_root}/spoof-lock-victim"
printf 'victim must remain unchanged\n' > "${spoof_victim}"
ln -s "${spoof_victim}" "${spoof_lock}"
if executor_ensure_master_key \
    "${spoof_staging_parent}" "${spoof_data_dir}" \
    "${spoof_data_dir}/master.key" "${CURRENT_UID}" "${CURRENT_GID}" \
    2>/dev/null; then
    fail "symbolic-link master key lock was accepted"
fi
assert "symbolic-link lock changed its victim" test \
    "$(cat "${spoof_victim}")" = "victim must remain unchanged"
rm -f -- "${spoof_lock}"
: > "${spoof_lock}"
chmod 0644 "${spoof_lock}"
if executor_ensure_master_key \
    "${spoof_staging_parent}" "${spoof_data_dir}" \
    "${spoof_data_dir}/master.key" "${CURRENT_UID}" "${CURRENT_GID}" \
    2>/dev/null; then
    fail "broad-mode master key lock was accepted"
fi
chmod 0600 "${spoof_lock}"
spoof_lock_alias="${test_root}/spoof-lock-alias"
ln "${spoof_lock}" "${spoof_lock_alias}"
if executor_ensure_master_key \
    "${spoof_staging_parent}" "${spoof_data_dir}" \
    "${spoof_data_dir}/master.key" "${CURRENT_UID}" "${CURRENT_GID}" \
    2>/dev/null; then
    fail "hard-linked master key lock was accepted"
fi
assert "hard-linked lock was mutated" test \
    "$(stat --format='%a:%h:%s' -- "${spoof_lock}")" = 600:2:0
pass "master key installation lock rejects spoofed inodes"

recovery_publish_dir="${test_root}/recovery-publish-failure"
recovery_publish_shim="${test_root}/recovery-publish-shim"
mkdir "${recovery_publish_dir}" "${recovery_publish_shim}"
recovery_publish_key="${recovery_publish_dir}/master.key"
real_mv=$(command -v mv)
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'destination=${!#}' \
    'case "${destination}" in' \
    '    */.executor-master-key.recovery) exit 76 ;;' \
    'esac' \
    'exec "${REAL_MV}" "$@"' > "${recovery_publish_shim}/mv"
chmod 0700 "${recovery_publish_shim}/mv"
if PATH="${recovery_publish_shim}:${PATH}" REAL_MV="${real_mv}" \
    executor_ensure_master_key \
        "${staging_parent}" "${recovery_publish_dir}" \
        "${recovery_publish_key}" "${CURRENT_UID}" "${CURRENT_GID}" \
        2>/dev/null; then
    fail "recovery record publication failure was ignored"
fi
assert "key was published without a durable recovery record" test \
    ! -e "${recovery_publish_key}"
if compgen -G "${staging_parent}/.executor-master-key.recovery*" >/dev/null; then
    fail "failed recovery publication left temporary control state"
fi
executor_ensure_master_key \
    "${staging_parent}" "${recovery_publish_dir}" "${recovery_publish_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
pass "recovery record publication failure stops key mutation"

recovery_retire_dir="${test_root}/recovery-retire-failure"
recovery_retire_shim="${test_root}/recovery-retire-shim"
mkdir "${recovery_retire_dir}" "${recovery_retire_shim}"
recovery_retire_key="${recovery_retire_dir}/master.key"
real_rm=$(command -v rm)
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'target=${!#}' \
    'case "${target}" in' \
    '    */.executor-master-key.recovery) exit 77 ;;' \
    'esac' \
    'exec "${REAL_RM}" "$@"' > "${recovery_retire_shim}/rm"
chmod 0700 "${recovery_retire_shim}/rm"
if PATH="${recovery_retire_shim}:${PATH}" REAL_RM="${real_rm}" \
    executor_ensure_master_key \
        "${staging_parent}" "${recovery_retire_dir}" \
        "${recovery_retire_key}" "${CURRENT_UID}" "${CURRENT_GID}" \
        2>/dev/null; then
    fail "recovery record retirement failure was ignored"
fi
assert "retirement failure removed the recovery record" test \
    -e "${staging_parent}/.executor-master-key.recovery"
assert "retirement failure lost the published key" test -e "${recovery_retire_key}"
recovery_retire_copy="${test_root}/recovery-retire-key.copy"
cp "${recovery_retire_key}" "${recovery_retire_copy}"
executor_ensure_master_key \
    "${staging_parent}" "${recovery_retire_dir}" "${recovery_retire_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
assert "retirement retry changed the published key" cmp -s \
    "${recovery_retire_copy}" "${recovery_retire_key}"
pass "recovery retirement failure remains safely retryable"

status_dir="${test_root}/validation-status"
mkdir "${status_dir}"
status_key="${status_dir}/master.key"
validator_definition=$(declare -f executor_validate_master_key)
executor_validate_master_key() {
    return 73
}
create_succeeded=false
validation_status=0
if executor_create_master_key \
    "${staging_parent}" "${status_dir}" "${status_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"; then
    create_succeeded=true
else
    validation_status=$?
fi
eval "${validator_definition}"
if [[ ${create_succeeded} == true ]]; then
    fail "temporary key validation failure was reported as success"
fi
assert "temporary key validation status was not propagated" test \
    "${validation_status}" = 73
assert "failed temporary key was published" test ! -e "${status_key}"
executor_ensure_master_key \
    "${staging_parent}" "${status_dir}" "${status_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
pass "temporary key validation status is propagated"

file_sync_dir="${test_root}/file-sync-failure"
mkdir "${file_sync_dir}"
file_sync_key="${file_sync_dir}/master.key"
writer_definition=$(declare -f executor_write_and_sync_master_key)
executor_write_and_sync_master_key() {
    printf '0123456789abcdef0123456789abcdef' > "$1"
    return 73
}
file_sync_succeeded=false
file_sync_status=0
if executor_ensure_master_key \
    "${staging_parent}" "${file_sync_dir}" "${file_sync_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    file_sync_succeeded=true
else
    file_sync_status=$?
fi
eval "${writer_definition}"
if [[ ${file_sync_succeeded} == true ]]; then
    fail "staged key fsync failure was reported as success"
fi
assert "staged key fsync status was not propagated" test \
    "${file_sync_status}" = 73
assert "key was published after staged file fsync failure" test ! -e "${file_sync_key}"
executor_ensure_master_key \
    "${staging_parent}" "${file_sync_dir}" "${file_sync_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
pass "staged master key fsync failure prevents publication"

directory_sync_dir="${test_root}/directory-sync-failure"
mkdir "${directory_sync_dir}"
directory_sync_key="${directory_sync_dir}/master.key"
directory_sync_ledger="${test_root}/directory-sync-ledger"
sync_definition=$(declare -f executor_sync_filesystem_path)
executor_sync_filesystem_path() {
    if [[ $1 == "${directory_sync_dir}" ]]; then
        printf '%s\n' "$1" >> "${directory_sync_ledger}"
        return 74
    fi
    command sync -f -- "$1"
}
directory_sync_succeeded=false
directory_sync_status=0
if executor_ensure_master_key \
    "${staging_parent}" "${directory_sync_dir}" "${directory_sync_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    directory_sync_succeeded=true
else
    directory_sync_status=$?
fi
eval "${sync_definition}"
if [[ ${directory_sync_succeeded} == true ]]; then
    fail "published key directory sync failure was reported as success"
fi
assert "published key directory sync status was not propagated" test \
    "${directory_sync_status}" = 74
assert "directory sync did not run on the destination data directory" test \
    "$(cat "${directory_sync_ledger}")" = "${directory_sync_dir}"
assert "atomically published key disappeared after sync failure" test \
    -e "${directory_sync_key}"
directory_sync_copy="${test_root}/directory-sync-key.copy"
cp "${directory_sync_key}" "${directory_sync_copy}"
executor_ensure_master_key \
    "${staging_parent}" "${directory_sync_dir}" "${directory_sync_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
assert "retry changed the published key after sync failure" cmp -s \
    "${directory_sync_copy}" "${directory_sync_key}"
pass "directory sync failures stop installation and recover on retry"

sync_order_dir="${test_root}/sync-order"
mkdir "${sync_order_dir}"
sync_order_key="${sync_order_dir}/master.key"
sync_order_ledger="${test_root}/sync-order-ledger"
writer_definition=$(declare -f executor_write_and_sync_master_key)
sync_definition=$(declare -f executor_sync_filesystem_path)
executor_write_and_sync_master_key() {
    printf 'file-sync|destination=%s\n' "$(test -e "${sync_order_key}" && printf present || printf absent)" \
        >> "${sync_order_ledger}"
    dd if=/dev/urandom of="$1" bs=32 count=1 \
        iflag=fullblock oflag=nofollow conv=fsync status=none
}
executor_sync_filesystem_path() {
    if [[ $1 == "${staging_parent}"/.executor-master-key.*/master.key ]]; then
        printf 'metadata-sync|destination=%s\n' \
            "$(test -e "${sync_order_key}" && printf present || printf absent)" \
            >> "${sync_order_ledger}"
    elif [[ $1 == "${sync_order_dir}" \
        || $1 == "${staging_parent}" \
            && -e ${sync_order_key} \
            && -e ${staging_parent}/.executor-master-key.recovery ]]; then
        printf 'directory-sync|%s|destination=%s\n' "$1" \
            "$(test -e "${sync_order_key}" && printf present || printf absent)" \
            >> "${sync_order_ledger}"
    fi
    command sync -f -- "$1"
}
executor_ensure_master_key \
    "${staging_parent}" "${sync_order_dir}" "${sync_order_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
eval "${writer_definition}"
eval "${sync_definition}"
first_sync_event=$(sed -n '1p' "${sync_order_ledger}")
metadata_sync_event=$(sed -n '2p' "${sync_order_ledger}")
first_directory_event=$(sed -n '3p' "${sync_order_ledger}")
assert "file fsync did not happen before publication" test \
    "${first_sync_event}" = "file-sync|destination=absent"
assert "final key metadata was not synced before publication" test \
    "${metadata_sync_event}" = "metadata-sync|destination=absent"
assert "destination directory sync did not happen after publication" test \
    "${first_directory_event}" = \
    "directory-sync|${sync_order_dir}|destination=present"
assert "publication cleanup did not receive all required directory syncs" test \
    "$(wc -l < "${sync_order_ledger}" | tr -d ' ')" = 5
pass "master key file and directory sync ordering is explicit"

metadata_crash_dir="${test_root}/metadata-sync-crash"
mkdir "${metadata_crash_dir}"
metadata_crash_key="${metadata_crash_dir}/master.key"
if EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_METADATA_SYNC=1 \
    executor_ensure_master_key \
        "${staging_parent}" "${metadata_crash_dir}" "${metadata_crash_key}" \
        "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "metadata-sync crash injection reported success"
fi
recovery_path="${staging_parent}/.executor-master-key.recovery"
metadata_staging_name=$(awk '$1 == "staging" { print $2 }' "${recovery_path}")
metadata_recorded_alias="${staging_parent}/${metadata_staging_name}/master.key"
metadata_recorded_copy="${test_root}/metadata-recorded-key.copy"
cp "${metadata_recorded_alias}" "${metadata_recorded_copy}"
assert "metadata-sync crash exposed the destination before publication" test \
    ! -e "${metadata_crash_key}"
assert "metadata-sync crash did not preserve final staged metadata" test \
    "$(stat --format='%u:%g:%a:%s:%h' -- "${metadata_recorded_alias}")" = \
    "${CURRENT_UID}:${CURRENT_GID}:600:32:1"
chmod 0640 "${metadata_recorded_alias}"
if executor_ensure_master_key \
    "${staging_parent}" "${metadata_crash_dir}" "${metadata_crash_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "recovery accepted staged metadata that differed from its record"
fi
assert "metadata mismatch retired the recovery record" test -e "${recovery_path}"
chmod 0600 "${metadata_recorded_alias}"
executor_ensure_master_key \
    "${staging_parent}" "${metadata_crash_dir}" "${metadata_crash_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
assert "metadata-sync recovery did not publish the exact staged key" cmp -s \
    "${metadata_recorded_copy}" "${metadata_crash_key}"
pass "metadata-sync crash recovers only the exact final key metadata"

destination_crash_dir="${test_root}/destination-sync-crash"
mkdir "${destination_crash_dir}"
destination_crash_key="${destination_crash_dir}/master.key"
if EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_DESTINATION_SYNC=1 \
    executor_ensure_master_key \
        "${staging_parent}" "${destination_crash_dir}" \
        "${destination_crash_key}" "${CURRENT_UID}" "${CURRENT_GID}" \
        2>/dev/null; then
    fail "destination-sync crash injection reported success"
fi
assert "destination-sync crash did not publish the key" test \
    -e "${destination_crash_key}"
assert "destination-sync crash did not leave the recorded two-link state" test \
    "$(stat --format='%h' -- "${destination_crash_key}")" = 2
destination_crash_copy="${test_root}/destination-sync-crash.copy"
cp "${destination_crash_key}" "${destination_crash_copy}"
executor_ensure_master_key \
    "${staging_parent}" "${destination_crash_dir}" \
    "${destination_crash_key}" "${CURRENT_UID}" "${CURRENT_GID}"
assert "destination-sync recovery changed the key" cmp -s \
    "${destination_crash_copy}" "${destination_crash_key}"
assert "destination-sync recovery did not retire the staging alias" test \
    "$(stat --format='%h' -- "${destination_crash_key}")" = 1
pass "destination-sync crash recovers the exact staged key"

alias_cleanup_dir="${test_root}/alias-cleanup-failure"
alias_cleanup_shim="${test_root}/alias-cleanup-shim"
mkdir "${alias_cleanup_dir}" "${alias_cleanup_shim}"
alias_cleanup_key="${alias_cleanup_dir}/master.key"
if EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_DESTINATION_SYNC=1 \
    executor_ensure_master_key \
        "${staging_parent}" "${alias_cleanup_dir}" "${alias_cleanup_key}" \
        "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "alias cleanup crash injection reported success"
fi
alias_cleanup_copy="${test_root}/alias-cleanup-key.copy"
cp "${alias_cleanup_key}" "${alias_cleanup_copy}"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'target=${!#}' \
    'case "${target}" in' \
    '    */.executor-master-key.????????/master.key) exit 78 ;;' \
    'esac' \
    'exec "${REAL_RM}" "$@"' > "${alias_cleanup_shim}/rm"
chmod 0700 "${alias_cleanup_shim}/rm"
if PATH="${alias_cleanup_shim}:${PATH}" REAL_RM="${real_rm}" \
    executor_ensure_master_key \
        "${staging_parent}" "${alias_cleanup_dir}" "${alias_cleanup_key}" \
        "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "recorded alias cleanup failure was ignored"
fi
assert "alias cleanup failure removed the recovery record" test \
    -e "${staging_parent}/.executor-master-key.recovery"
assert "alias cleanup failure changed the two-link key" test \
    "$(stat --format='%h' -- "${alias_cleanup_key}")" = 2
executor_ensure_master_key \
    "${staging_parent}" "${alias_cleanup_dir}" "${alias_cleanup_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
assert "alias cleanup retry changed the published key" cmp -s \
    "${alias_cleanup_copy}" "${alias_cleanup_key}"
pass "recorded alias cleanup failure remains safely retryable"

alias_unlink_crash_dir="${test_root}/alias-unlink-crash"
mkdir "${alias_unlink_crash_dir}"
alias_unlink_crash_key="${alias_unlink_crash_dir}/master.key"
if EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_ALIAS_UNLINK=1 \
    executor_ensure_master_key \
        "${staging_parent}" "${alias_unlink_crash_dir}" \
        "${alias_unlink_crash_key}" "${CURRENT_UID}" "${CURRENT_GID}" \
        2>/dev/null; then
    fail "alias-unlink crash injection reported success"
fi
assert "alias-unlink crash did not leave the published key" test \
    -e "${alias_unlink_crash_key}"
assert "alias-unlink crash left an additional key link" test \
    "$(stat --format='%h' -- "${alias_unlink_crash_key}")" = 1
alias_unlink_crash_copy="${test_root}/alias-unlink-crash.copy"
cp "${alias_unlink_crash_key}" "${alias_unlink_crash_copy}"
executor_ensure_master_key \
    "${staging_parent}" "${alias_unlink_crash_dir}" \
    "${alias_unlink_crash_key}" "${CURRENT_UID}" "${CURRENT_GID}"
assert "alias-unlink recovery changed the key" cmp -s \
    "${alias_unlink_crash_copy}" "${alias_unlink_crash_key}"
pass "alias-unlink crash retires the durable recovery record"

substitution_dir="${test_root}/recovery-substitution"
mkdir "${substitution_dir}"
substitution_key="${substitution_dir}/master.key"
if EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_DESTINATION_SYNC=1 \
    executor_ensure_master_key \
        "${staging_parent}" "${substitution_dir}" "${substitution_key}" \
        "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "substitution crash injection reported success"
fi
recovery_path="${staging_parent}/.executor-master-key.recovery"
substitution_staging_name=$(awk '$1 == "staging" { print $2 }' "${recovery_path}")
substitution_alias="${staging_parent}/${substitution_staging_name}/master.key"
substitution_unknown_alias="${test_root}/unknown-master-key-alias"
substitution_copy="${test_root}/recovery-substitution.copy"
cp "${substitution_key}" "${substitution_copy}"
rm -f -- "${substitution_alias}"
ln "${substitution_key}" "${substitution_unknown_alias}"
printf 'attacker-substitution-must-stay!' > "${substitution_alias}"
chmod 0600 "${substitution_alias}"
substitution_alias_copy="${test_root}/recovery-substitution-alias.copy"
cp "${substitution_alias}" "${substitution_alias_copy}"
if executor_ensure_master_key \
    "${staging_parent}" "${substitution_dir}" "${substitution_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "mismatched recorded staging alias was accepted"
fi
assert "failed substitution recovery changed the destination key" cmp -s \
    "${substitution_copy}" "${substitution_key}"
assert "failed substitution recovery changed the attacker file" cmp -s \
    "${substitution_alias_copy}" "${substitution_alias}"
assert "failed substitution recovery removed an unknown hard link" test \
    -e "${substitution_unknown_alias}"
rm -f -- "${substitution_alias}" "${substitution_unknown_alias}"
executor_ensure_master_key \
    "${staging_parent}" "${substitution_dir}" "${substitution_key}" \
    "${CURRENT_UID}" "${CURRENT_GID}"
assert "cleanup retry changed the destination key" cmp -s \
    "${substitution_copy}" "${substitution_key}"
pass "recovery rejects substituted and unknown master key aliases"

foreign_with_alias_dir="${test_root}/foreign-destination-with-alias"
mkdir "${foreign_with_alias_dir}"
foreign_with_alias_key="${foreign_with_alias_dir}/master.key"
if EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_DESTINATION_SYNC=1 \
    executor_ensure_master_key \
        "${staging_parent}" "${foreign_with_alias_dir}" \
        "${foreign_with_alias_key}" "${CURRENT_UID}" "${CURRENT_GID}" \
        2>/dev/null; then
    fail "foreign-destination alias crash injection reported success"
fi
recovery_path="${staging_parent}/.executor-master-key.recovery"
foreign_staging_name=$(awk '$1 == "staging" { print $2 }' "${recovery_path}")
foreign_recorded_alias="${staging_parent}/${foreign_staging_name}/master.key"
foreign_recorded_copy="${test_root}/foreign-recorded-key.copy"
cp "${foreign_recorded_alias}" "${foreign_recorded_copy}"
rm -f -- "${foreign_with_alias_key}"
printf 'foreign-destination-must-stay!!!' > "${foreign_with_alias_key}"
chmod 0600 "${foreign_with_alias_key}"
foreign_destination_copy="${test_root}/foreign-destination.copy"
cp "${foreign_with_alias_key}" "${foreign_destination_copy}"
if executor_ensure_master_key \
    "${staging_parent}" "${foreign_with_alias_dir}" \
    "${foreign_with_alias_key}" "${CURRENT_UID}" "${CURRENT_GID}" \
    2>/dev/null; then
    fail "foreign destination was accepted while the recorded alias existed"
fi
assert "foreign destination changed after failed recovery" cmp -s \
    "${foreign_destination_copy}" "${foreign_with_alias_key}"
assert "recorded alias changed after failed recovery" cmp -s \
    "${foreign_recorded_copy}" "${foreign_recorded_alias}"
assert "recovery record was retired after destination substitution" test \
    -e "${recovery_path}"
rm -f -- "${foreign_with_alias_key}"
ln "${foreign_recorded_alias}" "${foreign_with_alias_key}"
executor_ensure_master_key \
    "${staging_parent}" "${foreign_with_alias_dir}" \
    "${foreign_with_alias_key}" "${CURRENT_UID}" "${CURRENT_GID}"
assert "restored recorded key changed during recovery" cmp -s \
    "${foreign_recorded_copy}" "${foreign_with_alias_key}"
pass "recovery preserves a recorded alias when the destination is foreign"

foreign_without_alias_dir="${test_root}/foreign-destination-without-alias"
mkdir "${foreign_without_alias_dir}"
foreign_without_alias_key="${foreign_without_alias_dir}/master.key"
if EXECUTOR_INSTALL_TEST_CRASH_AFTER_KEY_DESTINATION_SYNC=1 \
    executor_ensure_master_key \
        "${staging_parent}" "${foreign_without_alias_dir}" \
        "${foreign_without_alias_key}" "${CURRENT_UID}" "${CURRENT_GID}" \
        2>/dev/null; then
    fail "foreign-destination no-alias crash injection reported success"
fi
recovery_path="${staging_parent}/.executor-master-key.recovery"
foreign_staging_name=$(awk '$1 == "staging" { print $2 }' "${recovery_path}")
foreign_recorded_alias="${staging_parent}/${foreign_staging_name}/master.key"
rm -f -- "${foreign_without_alias_key}" "${foreign_recorded_alias}"
printf 'foreign-destination-must-stay!!!' > "${foreign_without_alias_key}"
chmod 0600 "${foreign_without_alias_key}"
foreign_destination_copy="${test_root}/foreign-no-alias-destination.copy"
cp "${foreign_without_alias_key}" "${foreign_destination_copy}"
if executor_ensure_master_key \
    "${staging_parent}" "${foreign_without_alias_dir}" \
    "${foreign_without_alias_key}" "${CURRENT_UID}" "${CURRENT_GID}" \
    2>/dev/null; then
    fail "foreign destination was accepted after the recorded alias disappeared"
fi
assert "foreign no-alias destination changed after failed recovery" cmp -s \
    "${foreign_destination_copy}" "${foreign_without_alias_key}"
assert "no-alias recovery record was retired after substitution" test \
    -e "${recovery_path}"
rm -f -- "${foreign_without_alias_key}"
executor_ensure_master_key \
    "${staging_parent}" "${foreign_without_alias_dir}" \
    "${foreign_without_alias_key}" "${CURRENT_UID}" "${CURRENT_GID}"
assert "cleanup retry did not create a valid key" test \
    "$(stat --format='%s:%h:%a' -- "${foreign_without_alias_key}")" = 32:1:600
pass "recovery preserves state when a foreign destination has no recorded alias"

attack_dir="${test_root}/temp-swap"
attack_shim_dir="${test_root}/temp-swap-shim"
mkdir "${attack_dir}" "${attack_shim_dir}"
attack_key="${attack_dir}/master.key"
attack_victim="${test_root}/temp-swap-victim"
attack_victim_copy="${test_root}/temp-swap-victim.copy"
printf 'victim-must-remain-byte-for-byte!' > "${attack_victim}"
cp "${attack_victim}" "${attack_victim_copy}"
real_dd=$(command -v dd)
real_ln=$(command -v ln)
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'output_path=""' \
    'for argument in "$@"; do' \
    '    case "${argument}" in' \
    '        of=*) output_path=${argument#of=} ;;' \
    '    esac' \
    'done' \
    'printf seen > "${DD_SEEN}"' \
    'case "${output_path}" in' \
    '    "${ATTACKER_DATA_DIR}"/.master.key.*)' \
    '        printf attacked > "${ATTACK_TRIGGER}"' \
    '        rm -f -- "${output_path}"' \
    '        "${REAL_LN}" -s -- "${ATTACKER_VICTIM}" "${output_path}"' \
    '        ;;' \
    'esac' \
    'exec "${REAL_DD}" "$@"' > "${attack_shim_dir}/dd"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'source_path=""' \
    'destination=""' \
    'for argument in "$@"; do' \
    '    source_path=${destination}' \
    '    destination=${argument}' \
    'done' \
    'printf seen > "${LN_SEEN}"' \
    'case "${source_path}" in' \
    '    "${ATTACKER_DATA_DIR}"/.master.key.*)' \
    '        printf attacked > "${ATTACK_TRIGGER}"' \
    '        rm -f -- "${source_path}"' \
    '        "${REAL_LN}" -s -- "${ATTACKER_VICTIM}" "${source_path}"' \
    '        ;;' \
    'esac' \
    'exec "${REAL_LN}" "$@"' > "${attack_shim_dir}/ln"
chmod 0700 "${attack_shim_dir}/dd" "${attack_shim_dir}/ln"
attack_trigger="${test_root}/temp-swap-trigger"
dd_seen="${test_root}/temp-swap-dd-seen"
ln_seen="${test_root}/temp-swap-ln-seen"
PATH="${attack_shim_dir}:${PATH}" \
    ATTACKER_DATA_DIR="${attack_dir}" \
    ATTACKER_VICTIM="${attack_victim}" \
    ATTACK_TRIGGER="${attack_trigger}" \
    DD_SEEN="${dd_seen}" \
    LN_SEEN="${ln_seen}" \
    REAL_DD="${real_dd}" \
    REAL_LN="${real_ln}" \
    executor_ensure_master_key \
        "${staging_parent}" "${attack_dir}" "${attack_key}" \
        "${CURRENT_UID}" "${CURRENT_GID}"
assert "adversarial dd shim did not run" test -e "${dd_seen}"
assert "adversarial ln shim did not run" test -e "${ln_seen}"
assert "attacker reached a temporary key in the data directory" test \
    ! -e "${attack_trigger}"
assert "temporary key swap changed the victim" cmp -s \
    "${attack_victim_copy}" "${attack_victim}"
assert "staged key was not published" test -e "${attack_key}"
pass "temporary key stays outside the executor-owned data directory"

directory_race_dir="${test_root}/directory-race"
directory_race_target="${test_root}/directory-race-target"
directory_race_shim="${test_root}/directory-race-shim"
mkdir "${directory_race_dir}" "${directory_race_target}" \
    "${directory_race_shim}"
directory_race_key="${directory_race_dir}/master.key"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'destination=${!#}' \
    '"${REAL_LN}" -s -- "${RACE_DIRECTORY}" "${destination}"' \
    'exec "${REAL_LN}" "$@"' > "${directory_race_shim}/ln"
chmod 0700 "${directory_race_shim}/ln"
if PATH="${directory_race_shim}:${PATH}" \
    REAL_LN="${real_ln}" \
    RACE_DIRECTORY="${directory_race_target}" \
    executor_ensure_master_key \
        "${staging_parent}" "${directory_race_dir}" \
        "${directory_race_key}" "${CURRENT_UID}" "${CURRENT_GID}" \
        2>/dev/null; then
    fail "destination symlink to a directory was accepted"
fi
assert "directory-race destination is not a symlink" test \
    -L "${directory_race_key}"
if find "${directory_race_target}" -mindepth 1 -print -quit | read -r _; then
    fail "key was linked inside a racing destination directory"
fi
pass "destination symlink to a directory cannot redirect publication"

sentinel_dir="${test_root}/sentinel"
shim_dir="${test_root}/shim"
mkdir "${sentinel_dir}" "${shim_dir}"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'destination=${!#}' \
    'printf sentinel > "${destination}"' \
    'exec "${REAL_LN}" "$@"' > "${shim_dir}/ln"
chmod 0700 "${shim_dir}/ln"
sentinel_key="${sentinel_dir}/master.key"
if PATH="${shim_dir}:${PATH}" REAL_LN="${real_ln}" \
    executor_ensure_master_key \
        "${staging_parent}" "${sentinel_dir}" "${sentinel_key}" \
        "${CURRENT_UID}" "${CURRENT_GID}" 2>/dev/null; then
    fail "racing sentinel was overwritten"
fi
assert "racing sentinel content changed" test \
    "$(cat "${sentinel_key}")" = sentinel
if compgen -G "${sentinel_dir}/.master.key.*" >/dev/null; then
    fail "temporary key remained after publication race"
fi
pass "racing sentinel is preserved and temporary key is removed"

if [[ ${EUID} -eq 0 ]]; then
    wrong_owner_dir="${test_root}/wrong-owner"
    mkdir "${wrong_owner_dir}"
    wrong_owner_key="${wrong_owner_dir}/master.key"
    printf '76543210fedcba9876543210fedcba98' > "${wrong_owner_key}"
    chmod 0600 "${wrong_owner_key}"
    if executor_ensure_master_key \
        "${staging_parent}" "${wrong_owner_dir}" \
        "${wrong_owner_key}" 65534 65534 \
        2>/dev/null; then
        fail "wrong-owner key was accepted"
    fi
    assert "wrong-owner key ownership was changed" test \
        "$(stat --format='%u:%g' -- "${wrong_owner_key}")" = 0:0
    pass "root does not repair an existing key's ownership"

    alternate_dir="${test_root}/alternate-owner"
    mkdir "${alternate_dir}"
    alternate_key="${alternate_dir}/master.key"
    executor_ensure_master_key \
        "${staging_parent}" "${alternate_dir}" \
        "${alternate_key}" 65534 65534
    assert "root-created key has the wrong owner" test \
        "$(stat --format='%u:%g' -- "${alternate_key}")" = 65534:65534
    pass "root publishes ownership before exposing the key"
else
    TEST_NUMBER=$((TEST_NUMBER + 1))
    printf 'ok %s - root leaves wrong ownership unchanged # SKIP requires root\n' \
        "${TEST_NUMBER}"
    TEST_NUMBER=$((TEST_NUMBER + 1))
    printf 'ok %s - root publishes alternate ownership # SKIP requires root\n' \
        "${TEST_NUMBER}"
fi

if find "${staging_parent}" -mindepth 1 \
    ! -name '.executor-master-key.lock' -print -quit | read -r _; then
    fail "private master key staging directory was not cleaned up"
fi
assert "persistent master key lock has unsafe metadata" test \
    "$(stat --format='%F:%u:%a:%h:%s' -- \
        "${staging_parent}/.executor-master-key.lock")" = \
    "regular empty file:${CURRENT_UID}:600:1:0"

printf '1..%s\n' "${TEST_NUMBER}"
