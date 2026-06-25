#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
fixture="$(mktemp -d "${HOME}/.executor-release-fixture.XXXXXXXX")"
trap 'rm -rf "$fixture"' EXIT

event_line() {
    local log=$1 event=$2
    awk -v expected="$event" '
        $0 == expected { line = NR }
        END { if (line == 0) exit 1; print line }
    ' "$log"
}

assert_event_before() {
    local log=$1 first=$2 second=$3 first_line second_line
    first_line="$(event_line "$log" "$first")" \
        || { printf 'missing durability event: %s\n' "$first" >&2; exit 1; }
    second_line="$(event_line "$log" "$second")" \
        || { printf 'missing durability event: %s\n' "$second" >&2; exit 1; }
    if [[ "$first_line" -ge "$second_line" ]]; then
        printf 'durability event %s did not precede %s\n' "$first" "$second" >&2
        exit 1
    fi
}

wait_for_file() {
    local path=$1 process=$2 attempt
    for attempt in {1..100}; do
        [[ -e "$path" ]] && return 0
        if ! kill -0 "$process" 2>/dev/null; then
            printf 'process %s exited before creating %s\n' "$process" "$path" >&2
            return 1
        fi
        sleep 0.1
    done
    printf 'timed out waiting for %s\n' "$path" >&2
    return 1
}

default_help="$(env -u EXECUTOR_REPOSITORY "${repo_root}/scripts/install.sh" --help)"
[[ "$default_help" == *"raw.githubusercontent.com/davis7dotsh/executor-fork-testing/"* ]]
override_help="$(EXECUTOR_REPOSITORY=owner/repository "${repo_root}/scripts/install.sh" --help)"
[[ "$override_help" == *"raw.githubusercontent.com/owner/repository/"* ]]

stage="${fixture}/stage"
mkdir "$stage"
printf '#!/bin/sh\nexit 0\n' > "${stage}/executor"
chmod 0755 "${stage}/executor"
printf 'MIT fixture\n' > "${stage}/LICENSE"
printf '<html>Rust license fixture</html>\n' > "${stage}/THIRD_PARTY_LICENSES.html"
printf '[{"name":"Svelte","identifier":"MIT","text":"fixture"}]\n' \
    > "${stage}/THIRD_PARTY_JAVASCRIPT_LICENSES.json"

archive="${fixture}/executor-fixture.tar.gz"
archive_retry="${fixture}/executor-fixture-retry.tar.gz"
"${repo_root}/scripts/package-release-archive.py" \
    --source "$stage" \
    --output "$archive" \
    --epoch 1700000000
touch "${stage}"/*
"${repo_root}/scripts/package-release-archive.py" \
    --source "$stage" \
    --output "$archive_retry" \
    --epoch 1700000000
cmp "$archive" "$archive_retry"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$archive" > "${archive}.sha256"
else
    shasum -a 256 "$archive" > "${archive}.sha256"
fi
if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 --check "${archive}.sha256" >/dev/null
fi

failure_tools="${fixture}/failure-tools"
mkdir "$failure_tools"
printf '%s\n' \
    '#!/bin/sh' \
    'last_argument=' \
    'for argument in "$@"; do last_argument=$argument; done' \
    'if [ -n "${EXECUTOR_INSTALL_TEST_FAIL_REAL_MV_PATH:-}" ] && [ "$last_argument" = "$EXECUTOR_INSTALL_TEST_FAIL_REAL_MV_PATH" ]; then exit 73; fi' \
    'exec "$EXECUTOR_INSTALL_TEST_REAL_MV" "$@"' \
    > "${failure_tools}/mv"
printf '%s\n' \
    '#!/bin/sh' \
    'last_argument=' \
    'for argument in "$@"; do last_argument=$argument; done' \
    'if [ -n "${EXECUTOR_INSTALL_TEST_FAIL_REAL_RM_PATH:-}" ] && [ "$last_argument" = "$EXECUTOR_INSTALL_TEST_FAIL_REAL_RM_PATH" ]; then exit 74; fi' \
    'exec "$EXECUTOR_INSTALL_TEST_REAL_RM" "$@"' \
    > "${failure_tools}/rm"
printf '%s\n' \
    '#!/bin/sh' \
    'if [ "${EXECUTOR_INSTALL_SYNC_LABEL:-}" = "${EXECUTOR_INSTALL_TEST_FAIL_REAL_SYNC_LABEL:-}" ]; then exit 75; fi' \
    'exec "$EXECUTOR_INSTALL_TEST_REAL_SYNC" "$@"' \
    > "${failure_tools}/sync"
chmod 0755 "${failure_tools}/mv" "${failure_tools}/rm" "${failure_tools}/sync"
real_mv="$(type -P mv)"
real_rm="$(type -P rm)"
real_sync="$(type -P sync)"

install_dir="${fixture}/installed"
install_durability_log="${fixture}/install-durability.log"
EXECUTOR_INSTALL_DIR="$install_dir" \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$install_durability_log" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null

for installed in \
    executor \
    LICENSE \
    THIRD_PARTY_LICENSES.html \
    THIRD_PARTY_JAVASCRIPT_LICENSES.json; do
    [[ -s "${install_dir}/${installed}" ]]
done
[[ -x "${install_dir}/executor" ]]
assert_event_before \
    "$install_durability_log" \
    'recovery-durable:executor' \
    'managed-file-durable:executor'
assert_event_before \
    "$install_durability_log" \
    'managed-file-durable:executor' \
    'manifest-durable:executor'
assert_event_before \
    "$install_durability_log" \
    'manifest-durable:executor' \
    'recovery-retired:executor'
EXECUTOR_INSTALL_DIR="$install_dir" \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$install_durability_log" \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null
assert_event_before \
    "$install_durability_log" \
    'uninstall-file-durable:executor' \
    'uninstall-manifest-durable'

no_python_tools="${fixture}/no-python-tools"
no_python_home="${fixture}/no-python-home"
mkdir "$no_python_tools" "$no_python_home"
no_python_commands=(
    awk
    bash
    basename
    cat
    chmod
    cksum
    cp
    dirname
    gzip
    ln
    mkdir
    mktemp
    mv
    ps
    rm
    sleep
    stat
    sync
    sysctl
    tail
    tar
    uname
    wc
)
if command -v sha256sum >/dev/null 2>&1; then
    no_python_commands+=(sha256sum)
else
    no_python_commands+=(shasum)
fi
for command_name in "${no_python_commands[@]}"; do
    command_path="$(command -v "$command_name")"
    ln -s "$command_path" "${no_python_tools}/${command_name}"
done
printf '# no Python fixture\n' > "${no_python_home}/.bashrc"
PATH="$no_python_tools" \
    HOME="$no_python_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" > "${fixture}/no-python-install.log"
[[ -x "${no_python_home}/.executor/bin/executor" ]]
[[ -s "${no_python_home}/.executor/bin/.executor-path-ownership" ]]
no_python_path_command="export PATH=${no_python_home}/.executor/bin:\$PATH"
grep -Fqx '# Executor' "${no_python_home}/.bashrc"
grep -Fqx "$no_python_path_command" "${no_python_home}/.bashrc"
if grep -F 'Add this to' "${fixture}/no-python-install.log" >/dev/null; then
    printf 'Python-free installer fell back to a manual PATH edit\n' >&2
    exit 1
fi
PATH="$no_python_tools" \
    HOME="$no_python_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
if grep -Fqx '# Executor' "${no_python_home}/.bashrc"; then
    printf 'Python-free uninstall left its PATH marker behind\n' >&2
    exit 1
fi

real_failure_home="${fixture}/real-failure-home"
real_failure_config="${real_failure_home}/.bashrc"
mkdir "$real_failure_home"
printf '# real failure fixture\n' > "$real_failure_config"
cp "$real_failure_config" "${fixture}/real-failure-config-before"
if HOME="$real_failure_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_REAL_CONFIG_WRITE=1 \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" > "${fixture}/real-write-failure.log" 2>&1; then
    printf 'installer ignored a real shell-config write failure\n' >&2
    exit 1
fi
cmp "$real_failure_config" "${fixture}/real-failure-config-before"
[[ -x "${real_failure_home}/.executor/bin/executor" ]]
[[ -s "${real_failure_home}/.executor/bin/.executor-install-manifest" ]]
[[ -s "${real_failure_home}/.executor/bin/.executor-path-ownership" ]]
[[ ! -e "${real_failure_config}.executor-edit-lock" ]]
HOME="$real_failure_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null
cp "$real_failure_config" "${fixture}/real-failure-config-with-path"
if PATH="${failure_tools}:$PATH" \
    HOME="$real_failure_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_REAL_MV_PATH="$real_failure_config" \
    EXECUTOR_INSTALL_TEST_REAL_MV="$real_mv" \
    EXECUTOR_INSTALL_TEST_REAL_RM="$real_rm" \
    EXECUTOR_INSTALL_TEST_REAL_SYNC="$real_sync" \
    "${repo_root}/scripts/install.sh" \
    --uninstall > "${fixture}/real-move-failure.log" 2>&1; then
    printf 'uninstaller ignored a real shell-config move failure\n' >&2
    exit 1
fi
cmp "$real_failure_config" "${fixture}/real-failure-config-with-path"
[[ -x "${real_failure_home}/.executor/bin/executor" ]]
[[ -s "${real_failure_home}/.executor/bin/.executor-install-manifest" ]]
[[ ! -e "${real_failure_config}.executor-edit-lock" ]]
if PATH="${failure_tools}:$PATH" \
    HOME="$real_failure_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_REAL_RM_PATH="${real_failure_config}.executor-edit-lock" \
    EXECUTOR_INSTALL_TEST_REAL_MV="$real_mv" \
    EXECUTOR_INSTALL_TEST_REAL_RM="$real_rm" \
    EXECUTOR_INSTALL_TEST_REAL_SYNC="$real_sync" \
    "${repo_root}/scripts/install.sh" \
    --uninstall > "${fixture}/real-unlink-failure.log" 2>&1; then
    printf 'uninstaller ignored a real shell-config lock unlink failure\n' >&2
    exit 1
fi
[[ -x "${real_failure_home}/.executor/bin/executor" ]]
[[ -s "${real_failure_home}/.executor/bin/.executor-install-manifest" ]]
[[ -s "${real_failure_config}.executor-edit-lock" ]]
if grep -Fqx '# Executor' "$real_failure_config"; then
    printf 'real unlink failure did not reach the config-lock release boundary\n' >&2
    exit 1
fi
HOME="$real_failure_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
[[ ! -e "${real_failure_config}.executor-edit-lock" ]]

real_sync_home="${fixture}/real-sync-home"
mkdir "$real_sync_home"
if PATH="${failure_tools}:$PATH" \
    HOME="$real_sync_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_REAL_SYNC_LABEL='manifest-durable:executor' \
    EXECUTOR_INSTALL_TEST_REAL_MV="$real_mv" \
    EXECUTOR_INSTALL_TEST_REAL_RM="$real_rm" \
    EXECUTOR_INSTALL_TEST_REAL_SYNC="$real_sync" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path > "${fixture}/real-sync-failure.log" 2>&1; then
    printf 'installer ignored a real durability sync failure\n' >&2
    exit 1
fi
[[ -d "${real_sync_home}/.executor/bin/.executor-install-recovery" ]]
[[ -s "${real_sync_home}/.executor/bin/.executor-install-manifest" ]]
HOME="$real_sync_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null
[[ ! -e "${real_sync_home}/.executor/bin/.executor-install-recovery" ]]
HOME="$real_sync_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null

printf 'unexpected\n' > "${stage}/extra"
invalid_archive="${fixture}/invalid.tar.gz"
tar -C "$stage" -czf "$invalid_archive" \
    executor LICENSE THIRD_PARTY_LICENSES.html \
    THIRD_PARTY_JAVASCRIPT_LICENSES.json extra
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$invalid_archive" > "${invalid_archive}.sha256"
else
    shasum -a 256 "$invalid_archive" > "${invalid_archive}.sha256"
fi

if EXECUTOR_INSTALL_DIR="${fixture}/rejected" \
    "${repo_root}/scripts/install.sh" \
    --archive "$invalid_archive" \
    --no-modify-path >/dev/null 2>&1; then
    printf 'installer accepted an archive with an unexpected member\n' >&2
    exit 1
fi

unsafe_tmp="${fixture}/unsafe-tmp"
mkdir "$unsafe_tmp"
chmod 1777 "$unsafe_tmp"
if TMPDIR="$unsafe_tmp" \
    EXECUTOR_INSTALL_DIR="${fixture}/unsafe-tmp-install" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null 2>&1; then
    printf 'installer accepted a current-user-owned world-writable TMPDIR\n' >&2
    exit 1
fi
[[ ! -e "${fixture}/unsafe-tmp-install/executor" ]]

canonical_tmp="${fixture}/canonical-tmp"
canonical_tmp_alias="${fixture}/canonical-tmp-alias"
canonical_tmp_install="${fixture}/canonical-tmp-install"
mkdir "$canonical_tmp"
chmod 0700 "$canonical_tmp"
ln -s "$canonical_tmp" "$canonical_tmp_alias"
TMPDIR="$canonical_tmp_alias" \
    EXECUTOR_INSTALL_DIR="$canonical_tmp_install" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null
[[ -x "${canonical_tmp_install}/executor" ]]
EXECUTOR_INSTALL_DIR="$canonical_tmp_install" \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null

swap_tmp="${fixture}/swap-tmp"
mkdir "$swap_tmp"
chmod 0700 "$swap_tmp"
if TMPDIR="$swap_tmp" \
    EXECUTOR_INSTALL_DIR="${fixture}/swapped-tmp-install" \
    EXECUTOR_INSTALL_TEST_SWAP_TEMP_DIRECTORY=1 \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null 2>&1; then
    printf 'installer accepted a replaced private temporary directory\n' >&2
    exit 1
fi
[[ ! -e "${fixture}/swapped-tmp-install/executor" ]]

staged_source_tmp="${fixture}/staged-source-tmp"
staged_source_install="${fixture}/staged-source-install"
staged_source_archive="${fixture}/staged-source.tar.gz"
mkdir "$staged_source_tmp"
chmod 0700 "$staged_source_tmp"
cp "$archive" "$staged_source_archive"
cp "${archive}.sha256" "${staged_source_archive}.sha256"
TMPDIR="$staged_source_tmp" \
    EXECUTOR_INSTALL_DIR="$staged_source_install" \
    EXECUTOR_INSTALL_TEST_REMOVE_SOURCE_AFTER_STAGE=1 \
    "${repo_root}/scripts/install.sh" \
    --archive "$staged_source_archive" \
    --no-modify-path >/dev/null
[[ ! -e "$staged_source_archive" ]]
[[ ! -e "${staged_source_archive}.sha256" ]]
[[ -x "${staged_source_install}/executor" ]]
EXECUTOR_INSTALL_DIR="$staged_source_install" \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null

shared_install_dir="${fixture}/shared-bin"
mkdir -p "$shared_install_dir"
printf 'unrelated license sentinel\n' > "${shared_install_dir}/LICENSE"
if EXECUTOR_INSTALL_DIR="$shared_install_dir" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null 2>&1; then
    printf 'installer overwrote an unowned shared-directory file\n' >&2
    exit 1
fi
grep -Fqx 'unrelated license sentinel' "${shared_install_dir}/LICENSE"
[[ ! -e "${shared_install_dir}/executor" ]]
[[ ! -e "${shared_install_dir}/.executor-install-manifest" ]]

umask_install_dir="${fixture}/umask-install-parent/bin"
(
    umask 0002
    EXECUTOR_INSTALL_DIR="$umask_install_dir" \
        "${repo_root}/scripts/install.sh" \
        --archive "$archive" \
        --no-modify-path >/dev/null
)
[[ -x "${umask_install_dir}/executor" ]]
EXECUTOR_INSTALL_DIR="$umask_install_dir" \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null

unsafe_install_parent="${fixture}/unsafe-install-parent"
mkdir "$unsafe_install_parent"
chmod 0777 "$unsafe_install_parent"
if EXECUTOR_INSTALL_DIR="${unsafe_install_parent}/bin" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path > "${fixture}/unsafe-install-parent.log" 2>&1; then
    printf 'installer accepted a writable install-path ancestor\n' >&2
    exit 1
fi
grep -F 'install path components cannot be group or world writable' \
    "${fixture}/unsafe-install-parent.log" >/dev/null
[[ ! -e "${unsafe_install_parent}/bin" ]]
chmod 0700 "$unsafe_install_parent"

symlink_install_target="${fixture}/symlink-install-target"
symlink_install_component="${fixture}/symlink-install-component"
mkdir "$symlink_install_target"
ln -s "$symlink_install_target" "$symlink_install_component"
if EXECUTOR_INSTALL_DIR="${symlink_install_component}/bin" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path > "${fixture}/symlink-install-component.log" 2>&1; then
    printf 'installer accepted a symlinked install-path component\n' >&2
    exit 1
fi
grep -F 'install path component is not a real directory' \
    "${fixture}/symlink-install-component.log" >/dev/null
[[ ! -e "${symlink_install_target}/bin" ]]

ancestor_swap_parent="${fixture}/ancestor-swap-parent"
ancestor_swap_original="${fixture}/ancestor-swap-original"
ancestor_swap_ready="${fixture}/ancestor-swap-ready"
ancestor_swap_release="${fixture}/ancestor-swap-release"
mkdir "$ancestor_swap_parent"
EXECUTOR_INSTALL_DIR="${ancestor_swap_parent}/bin" \
    EXECUTOR_INSTALL_TEST_PAUSE_POINT=after-install-root \
    EXECUTOR_INSTALL_TEST_PAUSE_READY="$ancestor_swap_ready" \
    EXECUTOR_INSTALL_TEST_PAUSE_RELEASE="$ancestor_swap_release" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path > "${fixture}/ancestor-swap.log" 2>&1 &
ancestor_swap_pid=$!
wait_for_file "$ancestor_swap_ready" "$ancestor_swap_pid"
mv "$ancestor_swap_parent" "$ancestor_swap_original"
mkdir -p "${ancestor_swap_parent}/bin"
touch "$ancestor_swap_release"
if wait "$ancestor_swap_pid"; then
    printf 'installer accepted a swapped install-path ancestor\n' >&2
    exit 1
fi
grep -F 'install root parent changed after validation' \
    "${fixture}/ancestor-swap.log" >/dev/null
[[ ! -e "${ancestor_swap_parent}/bin/executor" ]]

service_home="${fixture}/service-preservation-home"
service_root="${service_home}/.executor/service"
mkdir -p "${service_root}/bin"
printf '#!/bin/sh\nprintf "service copy\\n"\n' > "${service_root}/bin/executor"
chmod 0755 "${service_root}/bin/executor"
printf 'service-install-manifest-v1\nfixture\n' > "${service_root}/service-install.manifest"
printf 'service configuration fixture\n' > "${service_root}/service-config"
cp -R "$service_root" "${fixture}/expected-service-root"
HOME="$service_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null
HOME="$service_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null
HOME="$service_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null
diff -r "${fixture}/expected-service-root" "$service_root"

concurrent_home="${fixture}/concurrent-home"
concurrent_ready="${fixture}/concurrent-ready"
concurrent_release="${fixture}/concurrent-release"
mkdir -p "$concurrent_home"
HOME="$concurrent_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_PAUSE_POINT=after-lock \
    EXECUTOR_INSTALL_TEST_PAUSE_READY="$concurrent_ready" \
    EXECUTOR_INSTALL_TEST_PAUSE_RELEASE="$concurrent_release" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path > "${fixture}/concurrent-first.log" 2>&1 &
concurrent_pid=$!
wait_for_file "$concurrent_ready" "$concurrent_pid"
if HOME="$concurrent_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path > "${fixture}/concurrent-second.log" 2>&1; then
    printf 'a concurrent installer acquired a live install lock\n' >&2
    exit 1
fi
grep -F 'another Executor installer is active' "${fixture}/concurrent-second.log" >/dev/null
if HOME="$concurrent_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_PROCESS_IDENTITY_PID="$concurrent_pid" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path > "${fixture}/concurrent-identity-failure.log" 2>&1; then
    printf 'installer reclaimed a live lock after an identity lookup failure\n' >&2
    exit 1
fi
grep -F 'could not verify live install-lock owner pid' \
    "${fixture}/concurrent-identity-failure.log" >/dev/null
if HOME="$concurrent_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path > "${fixture}/concurrent-uninstall.log" 2>&1; then
    printf 'a concurrent uninstall acquired a live install lock\n' >&2
    exit 1
fi
grep -F 'another Executor installer is active' "${fixture}/concurrent-uninstall.log" >/dev/null
touch "$concurrent_release"
wait "$concurrent_pid"
[[ -x "${concurrent_home}/.executor/bin/executor" ]]
[[ ! -e "${concurrent_home}/.executor/bin/.executor-install-lock" ]]
HOME="$concurrent_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null

crashed_home="${fixture}/crashed-home"
crashed_ready="${fixture}/crashed-ready"
crashed_release="${fixture}/crashed-release"
mkdir -p "$crashed_home"
HOME="$crashed_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_PAUSE_POINT=after-install-file-1 \
    EXECUTOR_INSTALL_TEST_PAUSE_READY="$crashed_ready" \
    EXECUTOR_INSTALL_TEST_PAUSE_RELEASE="$crashed_release" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path > "${fixture}/crashed-first.log" 2>&1 &
crashed_pid=$!
wait_for_file "$crashed_ready" "$crashed_pid"
[[ -x "${crashed_home}/.executor/bin/executor" ]]
[[ -d "${crashed_home}/.executor/bin/.executor-install-recovery" ]]
if HOME="$crashed_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path > "${fixture}/crashed-second.log" 2>&1; then
    printf 'a concurrent installer rolled back a live mid-commit transaction\n' >&2
    exit 1
fi
grep -F 'another Executor installer is active' "${fixture}/crashed-second.log" >/dev/null
[[ -x "${crashed_home}/.executor/bin/executor" ]]
[[ -d "${crashed_home}/.executor/bin/.executor-install-recovery" ]]
kill -KILL "$crashed_pid"
if wait "$crashed_pid" 2>/dev/null; then
    printf 'killed installer exited successfully\n' >&2
    exit 1
fi
[[ -s "${crashed_home}/.executor/bin/.executor-install-lock" ]]
HOME="$crashed_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null
[[ -x "${crashed_home}/.executor/bin/executor" ]]
[[ -s "${crashed_home}/.executor/bin/.executor-install-manifest" ]]
[[ ! -e "${crashed_home}/.executor/bin/.executor-install-recovery" ]]
[[ ! -e "${crashed_home}/.executor/bin/.executor-install-lock" ]]
HOME="$crashed_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null

reused_pid_install="${fixture}/reused-pid-install"
mkdir -p "$reused_pid_install"
chmod 0700 "$reused_pid_install"
printf 'executor-install-lock-v1\npid %s\nidentity ps:0:0\n' "$$" \
    > "${reused_pid_install}/.executor-install-lock"
chmod 0600 "${reused_pid_install}/.executor-install-lock"
EXECUTOR_INSTALL_DIR="$reused_pid_install" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null
[[ -x "${reused_pid_install}/executor" ]]
[[ ! -e "${reused_pid_install}/.executor-install-lock" ]]
EXECUTOR_INSTALL_DIR="$reused_pid_install" \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null

recovery_home="${fixture}/recovery-home"
recovery_durability_log="${fixture}/recovery-durability.log"
mkdir -p "$recovery_home"
if HOME="$recovery_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_AFTER_INSTALL_FILE=1 \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$recovery_durability_log" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null 2>&1; then
    printf 'installer ignored an injected mid-install failure\n' >&2
    exit 1
fi
[[ -d "${recovery_home}/.executor/bin/.executor-install-recovery" ]]
[[ -x "${recovery_home}/.executor/bin/executor" ]]
[[ ! -e "${recovery_home}/.executor/bin/.executor-install-manifest" ]]
assert_event_before \
    "$recovery_durability_log" \
    'recovery-durable:executor' \
    'managed-file-durable:executor'
if HOME="$recovery_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$recovery_durability_log" \
    EXECUTOR_INSTALL_TEST_FAIL_DURABILITY_POINT='rollback-managed-durable:executor' \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null 2>&1; then
    printf 'installer ignored an injected rollback durability failure\n' >&2
    exit 1
fi
[[ -d "${recovery_home}/.executor/bin/.executor-install-recovery" ]]
HOME="$recovery_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$recovery_durability_log" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null
[[ -s "${recovery_home}/.executor/bin/.executor-install-manifest" ]]
[[ ! -e "${recovery_home}/.executor/bin/.executor-install-recovery" ]]
assert_event_before \
    "$recovery_durability_log" \
    'rollback-managed-durable:executor' \
    'rollback-manifest-durable'
assert_event_before \
    "$recovery_durability_log" \
    'rollback-manifest-durable' \
    'recovery-retired:rollback'
HOME="$recovery_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --no-modify-path >/dev/null

unowned_path_home="${fixture}/unowned-path-home"
mkdir -p "$unowned_path_home"
unowned_path_command="export PATH=${unowned_path_home}/.executor/bin:\$PATH"
printf '# Executor\n%s\n' "$unowned_path_command" > "${unowned_path_home}/.bashrc"
HOME="$unowned_path_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
grep -Fqx '# Executor' "${unowned_path_home}/.bashrc"
grep -Fqx "$unowned_path_command" "${unowned_path_home}/.bashrc"

preexisting_path_home="${fixture}/preexisting-path-home"
mkdir -p "$preexisting_path_home"
preexisting_path_command="export PATH=${preexisting_path_home}/.executor/bin:\$PATH"
printf '# preexisting fixture\n# Executor\n%s\n' \
    "$preexisting_path_command" \
    > "${preexisting_path_home}/.bashrc"
HOME="$preexisting_path_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null
[[ ! -e "${preexisting_path_home}/.executor/bin/.executor-path-ownership" ]]
HOME="$preexisting_path_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
grep -Fqx '# Executor' "${preexisting_path_home}/.bashrc"
grep -Fqx "$preexisting_path_command" "${preexisting_path_home}/.bashrc"

path_failure_home="${fixture}/path-failure-home"
path_durability_log="${fixture}/path-durability.log"
mkdir -p "$path_failure_home"
printf '# path failure fixture\n' > "${path_failure_home}/.bashrc"
if HOME="$path_failure_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_AFTER_PATH_CONFIG=1 \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$path_durability_log" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null 2>&1; then
    printf 'installer ignored an injected post-PATH-update failure\n' >&2
    exit 1
fi
[[ -x "${path_failure_home}/.executor/bin/executor" ]]
[[ -s "${path_failure_home}/.executor/bin/.executor-path-ownership" ]]
[[ -s "${path_failure_home}/.executor/bin/.executor-install-manifest" ]]
grep -Fqx '# Executor' "${path_failure_home}/.bashrc"
assert_event_before \
    "$path_durability_log" \
    'managed-file-durable:.executor-path-ownership' \
    'manifest-durable:.executor-path-ownership'
assert_event_before \
    "$path_durability_log" \
    'manifest-durable:.executor-path-ownership' \
    'recovery-retired:.executor-path-ownership'
assert_event_before \
    "$path_durability_log" \
    'recovery-retired:.executor-path-ownership' \
    'path-config-durable:add'
HOME="$path_failure_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$path_durability_log" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null
HOME="$path_failure_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$path_durability_log" \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
assert_event_before \
    "$path_durability_log" \
    'path-config-durable:remove' \
    'uninstall-file-durable:.executor-path-ownership'
assert_event_before \
    "$path_durability_log" \
    'uninstall-file-durable:.executor-path-ownership' \
    'uninstall-manifest-durable'
if grep -Fqx '# Executor' "${path_failure_home}/.bashrc"; then
    printf 'uninstaller left a PATH block after a recovered PATH update failure\n' >&2
    exit 1
fi

cross_root_home="${fixture}/cross-root-home"
cross_root_a="${fixture}/cross-root-a"
cross_root_b="${fixture}/cross-root-b"
cross_root_ready="${fixture}/cross-root-ready"
cross_root_release="${fixture}/cross-root-release"
mkdir "$cross_root_home"
printf '# cross-root fixture\n' > "${cross_root_home}/.bashrc"
HOME="$cross_root_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_DIR="$cross_root_a" \
    EXECUTOR_INSTALL_TEST_CONFIG_PAUSE_READY="$cross_root_ready" \
    EXECUTOR_INSTALL_TEST_CONFIG_PAUSE_RELEASE="$cross_root_release" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" > "${fixture}/cross-root-a.log" 2>&1 &
cross_root_a_pid=$!
wait_for_file "$cross_root_ready" "$cross_root_a_pid"
HOME="$cross_root_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_DIR="$cross_root_b" \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" > "${fixture}/cross-root-b.log" 2>&1 &
cross_root_b_pid=$!
wait_for_file "${cross_root_b}/.executor-path-ownership" "$cross_root_b_pid"
touch "$cross_root_release"
wait "$cross_root_a_pid"
wait "$cross_root_b_pid"
cross_root_a_command="export PATH=${cross_root_a}:\$PATH"
cross_root_b_command="export PATH=${cross_root_b}:\$PATH"
[[ "$(grep -Fxc '# Executor' "${cross_root_home}/.bashrc")" -eq 2 ]]
[[ "$(grep -Fxc "$cross_root_a_command" "${cross_root_home}/.bashrc")" -eq 1 ]]
[[ "$(grep -Fxc "$cross_root_b_command" "${cross_root_home}/.bashrc")" -eq 1 ]]
HOME="$cross_root_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_DIR="$cross_root_a" \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
HOME="$cross_root_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_DIR="$cross_root_b" \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
if grep -Fqx '# Executor' "${cross_root_home}/.bashrc"; then
    printf 'cross-root uninstall left an Executor PATH marker\n' >&2
    exit 1
fi

no_modify_home="${fixture}/no-modify-home"
mkdir -p "$no_modify_home"
no_modify_path_command="export PATH=${no_modify_home}/.executor/bin:\$PATH"
printf '# Executor\n%s\n' "$no_modify_path_command" > "${no_modify_home}/.bashrc"
HOME="$no_modify_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" \
    --no-modify-path >/dev/null
[[ ! -e "${no_modify_home}/.executor/bin/.executor-path-ownership" ]]
HOME="$no_modify_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
grep -Fqx '# Executor' "${no_modify_home}/.bashrc"
grep -Fqx "$no_modify_path_command" "${no_modify_home}/.bashrc"

lost_state_home="${fixture}/lost-state-home"
mkdir -p "$lost_state_home"
printf '# lost state fixture\n' > "${lost_state_home}/.bashrc"
HOME="$lost_state_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null
rm -f "${lost_state_home}/.executor/bin/.executor-path-ownership"
if HOME="$lost_state_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null 2>&1; then
    printf 'uninstaller accepted missing PATH ownership state out of delete order\n' >&2
    exit 1
fi
grep -Fqx '# Executor' "${lost_state_home}/.bashrc"
[[ -x "${lost_state_home}/.executor/bin/executor" ]]
[[ -s "${lost_state_home}/.executor/bin/.executor-install-manifest" ]]

corrupt_state_home="${fixture}/corrupt-state-home"
mkdir -p "$corrupt_state_home"
printf '# corrupt state fixture\n' > "${corrupt_state_home}/.bashrc"
HOME="$corrupt_state_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null
printf 'corrupt ownership state\n' \
    > "${corrupt_state_home}/.executor/bin/.executor-path-ownership"
if HOME="$corrupt_state_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null 2>&1; then
    printf 'uninstaller accepted corrupt PATH ownership state\n' >&2
    exit 1
fi
grep -Fqx '# Executor' "${corrupt_state_home}/.bashrc"
[[ -x "${corrupt_state_home}/.executor/bin/executor" ]]
[[ -s "${corrupt_state_home}/.executor/bin/.executor-install-manifest" ]]

shell_change_home="${fixture}/shell-change-home"
shell_change_zdot="${shell_change_home}/original-zdot"
mkdir -p "$shell_change_zdot"
printf '# original zsh config\n' > "${shell_change_zdot}/.zshrc"
printf '# untouched bash config\n' > "${shell_change_home}/.bashrc"
HOME="$shell_change_home" \
    SHELL=/bin/zsh \
    ZDOTDIR="$shell_change_zdot" \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null
grep -Fqx '# Executor' "${shell_change_zdot}/.zshrc"
[[ -s "${shell_change_home}/.executor/bin/.executor-path-ownership" ]]
HOME="$shell_change_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null
grep -Fqx '# Executor' "${shell_change_home}/.bashrc"
[[ "$(grep -c $'^/' "${shell_change_home}/.executor/bin/.executor-path-ownership")" -eq 2 ]]
HOME="$shell_change_home" \
    SHELL=/bin/fish \
    ZDOTDIR="${shell_change_home}/different-zdot" \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
if grep -Fqx '# Executor' "${shell_change_zdot}/.zshrc"; then
    printf 'uninstaller left a PATH block recorded under the original shell\n' >&2
    exit 1
fi
if grep -Fqx '# Executor' "${shell_change_home}/.bashrc"; then
    printf 'uninstaller left a second recorded shell PATH block\n' >&2
    exit 1
fi
grep -Fqx '# original zsh config' "${shell_change_zdot}/.zshrc"
grep -Fqx '# untouched bash config' "${shell_change_home}/.bashrc"

lifecycle_home="${fixture}/home"
lifecycle_install_dir="${lifecycle_home}/.executor/bin"
lifecycle_config="${lifecycle_home}/.bashrc"
mkdir -p "$lifecycle_home"
printf '# fixture shell config\n' > "$lifecycle_config"
chmod 0640 "$lifecycle_config"
config_metadata="$(
    python3 - "$lifecycle_config" <<'PY'
import os
import stat
import sys

metadata = os.stat(sys.argv[1], follow_symlinks=False)
print(f"{stat.S_IMODE(metadata.st_mode)}:{metadata.st_uid}:{metadata.st_gid}")
PY
)"
HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null
HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null

path_command="export PATH=${lifecycle_install_dir}:\$PATH"
[[ "$(grep -Fxc '# Executor' "$lifecycle_config")" -eq 1 ]]
[[ "$(grep -Fxc "$path_command" "$lifecycle_config")" -eq 1 ]]
[[ -s "${lifecycle_install_dir}/.executor-install-manifest" ]]
[[ "$(
    python3 - "${lifecycle_install_dir}/.executor-install-manifest" <<'PY'
import os
import stat
import sys

print(stat.S_IMODE(os.stat(sys.argv[1], follow_symlinks=False).st_mode))
PY
)" -eq 384 ]]
[[ "$(
    python3 - "$lifecycle_config" <<'PY'
import os
import stat
import sys

metadata = os.stat(sys.argv[1], follow_symlinks=False)
print(f"{stat.S_IMODE(metadata.st_mode)}:{metadata.st_uid}:{metadata.st_gid}")
PY
)" == "$config_metadata" ]]
mkdir -p "${lifecycle_home}/.executor/data"
printf 'preserve data\n' > "${lifecycle_home}/.executor/data/database.fixture"
printf 'preserve unrelated file\n' > "${lifecycle_install_dir}/user-owned.fixture"
cp "$lifecycle_config" "${fixture}/expected-shell-config"

if HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_CONFIG_WRITE=1 \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null 2>&1; then
    printf 'uninstaller ignored an injected shell-config write failure\n' >&2
    exit 1
fi
cmp "$lifecycle_config" "${fixture}/expected-shell-config"
[[ -x "${lifecycle_install_dir}/executor" ]]
[[ -s "${lifecycle_install_dir}/.executor-install-manifest" ]]

if HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_CONFIG_RENAME=1 \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null 2>&1; then
    printf 'uninstaller ignored an injected shell-config rename failure\n' >&2
    exit 1
fi
cmp "$lifecycle_config" "${fixture}/expected-shell-config"
[[ -x "${lifecycle_install_dir}/executor" ]]
[[ -s "${lifecycle_install_dir}/.executor-install-manifest" ]]
[[ -z "$(find "$lifecycle_home" -maxdepth 1 -name '.bashrc.executor-*' -print -quit)" ]]

upgrade_binary="${fixture}/executor-upgrade"
printf '#!/bin/sh\nprintf "upgraded\\n"\n' > "$upgrade_binary"
chmod 0755 "$upgrade_binary"
if HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_MANIFEST=1 \
    "${repo_root}/scripts/install.sh" \
    --binary "$upgrade_binary" >/dev/null 2>&1; then
    printf 'installer ignored an injected manifest publication failure\n' >&2
    exit 1
fi
cmp "$upgrade_binary" "${lifecycle_install_dir}/executor"
[[ -d "${lifecycle_install_dir}/.executor-install-recovery" ]]
HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --binary "$upgrade_binary" >/dev/null
cmp "$upgrade_binary" "${lifecycle_install_dir}/executor"
[[ -s "${lifecycle_install_dir}/THIRD_PARTY_LICENSES.html" ]]
[[ -s "${lifecycle_install_dir}/.executor-install-manifest" ]]
[[ ! -e "${lifecycle_install_dir}/.executor-install-recovery" ]]

printf 'replacement sentinel\n' > "${lifecycle_install_dir}/LICENSE"
if HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --archive "$archive" >/dev/null 2>&1; then
    printf 'installer overwrote a replaced installer-owned file\n' >&2
    exit 1
fi
grep -Fqx 'replacement sentinel' "${lifecycle_install_dir}/LICENSE"
if HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null 2>&1; then
    printf 'uninstaller removed a replaced installer-owned file\n' >&2
    exit 1
fi
grep -Fqx 'replacement sentinel' "${lifecycle_install_dir}/LICENSE"
cmp "$lifecycle_config" "${fixture}/expected-shell-config"
[[ -x "${lifecycle_install_dir}/executor" ]]
[[ -s "${lifecycle_install_dir}/.executor-install-manifest" ]]
cp "${stage}/LICENSE" "${lifecycle_install_dir}/LICENSE"

uninstall_durability_log="${fixture}/uninstall-durability.log"
if HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_FAIL_AFTER_UNINSTALL_DELETE=1 \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$uninstall_durability_log" \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null 2>&1; then
    printf 'uninstaller ignored an injected partial-delete failure\n' >&2
    exit 1
fi
[[ ! -e "${lifecycle_install_dir}/executor" ]]
[[ -s "${lifecycle_install_dir}/LICENSE" ]]
[[ -s "${lifecycle_install_dir}/.executor-install-manifest" ]]
[[ -s "${lifecycle_home}/.executor/data/database.fixture" ]]
[[ -s "${lifecycle_install_dir}/user-owned.fixture" ]]
event_line "$uninstall_durability_log" 'uninstall-file-durable:executor' >/dev/null
if event_line "$uninstall_durability_log" 'uninstall-manifest-durable' >/dev/null 2>&1; then
    printf 'partial uninstall published the manifest deletion too early\n' >&2
    exit 1
fi

HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    EXECUTOR_INSTALL_TEST_DURABILITY_LOG="$uninstall_durability_log" \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
assert_event_before \
    "$uninstall_durability_log" \
    'uninstall-file-durable:executor' \
    'uninstall-file-durable:LICENSE'
assert_event_before \
    "$uninstall_durability_log" \
    'uninstall-file-durable:.executor-path-ownership' \
    'uninstall-manifest-durable'

for removed in \
    executor \
    LICENSE \
    THIRD_PARTY_LICENSES.html \
    THIRD_PARTY_JAVASCRIPT_LICENSES.json \
    .executor-path-ownership \
    .executor-install-manifest; do
    [[ ! -e "${lifecycle_install_dir}/${removed}" ]]
done
[[ -s "${lifecycle_home}/.executor/data/database.fixture" ]]
[[ -s "${lifecycle_install_dir}/user-owned.fixture" ]]
grep -Fqx '# fixture shell config' "$lifecycle_config"
[[ "$(
    python3 - "$lifecycle_config" <<'PY'
import os
import stat
import sys

metadata = os.stat(sys.argv[1], follow_symlinks=False)
print(f"{stat.S_IMODE(metadata.st_mode)}:{metadata.st_uid}:{metadata.st_gid}")
PY
)" == "$config_metadata" ]]
if grep -Fqx '# Executor' "$lifecycle_config"; then
    printf 'uninstaller left its shell marker behind\n' >&2
    exit 1
fi
if grep -Fqx "$path_command" "$lifecycle_config"; then
    printf 'uninstaller left its PATH entry behind\n' >&2
    exit 1
fi

HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null

empty_home="${fixture}/empty-home"
mkdir -p "$empty_home"
HOME="$empty_home" \
    SHELL=/bin/zsh \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall >/dev/null
if HOME="$lifecycle_home" \
    SHELL=/bin/bash \
    GITHUB_ACTIONS=false \
    "${repo_root}/scripts/install.sh" \
    --uninstall \
    --archive "$archive" >/dev/null 2>&1; then
    printf 'uninstaller accepted an install source option\n' >&2
    exit 1
fi

printf 'release archive installer fixture passed\n'
