#!/usr/bin/env bash
set -euo pipefail

readonly REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly INSTALLER="${REPOSITORY_ROOT}/scripts/install-launchd.sh"
readonly TEST_ROOT="$(mktemp -d)"

cleanup() {
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

test_number=0
run_case() {
    local name=$1

    CASE_ROOT="${TEST_ROOT}/${name}"
    HOME_DIR="${CASE_ROOT}/home"
    DATA_DIR="${HOME_DIR}/Library/Application Support/Executor"
    PLIST_DIR="${HOME_DIR}/Library/LaunchAgents"
    SERVICE_DIR="${HOME_DIR}/.executor/service"
    STUB_DIR="${CASE_ROOT}/bin"
    EXECUTOR_BINARY="${CASE_ROOT}/executor"
    OUTPUT="${CASE_ROOT}/output"
    mkdir -p "$DATA_DIR" "$PLIST_DIR" "$STUB_DIR"
    printf '#!/bin/sh\nprintf "Darwin\\n"\n' > "${STUB_DIR}/uname"
    chmod 0700 "${STUB_DIR}/uname"
    printf '#!/bin/sh\nexit 0\n' > "$EXECUTOR_BINARY"
    chmod 0700 "$EXECUTOR_BINARY"
}

expect_rejected() {
    if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
        bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
        >"$OUTPUT" 2>&1; then
        printf 'not ok %s - unsafe launchd destination was accepted\n' "$test_number"
        cat "$OUTPUT"
        exit 1
    fi
}

private_file_metadata() {
    if stat --version >/dev/null 2>&1; then
        stat -c '%u|%a|%h' "$1"
    else
        stat -f '%u|%Lp|%l' "$1"
    fi
}

test_number=$((test_number + 1))
run_case dangling-template
victim="${CASE_ROOT}/victim"
ln -s "$victim" "${DATA_DIR}/mcp-stdio-templates.json"
expect_rejected
if [[ ! -e "$victim" && -L "${DATA_DIR}/mcp-stdio-templates.json" ]]; then
    printf 'ok %s - dangling template symlink is rejected without creating its target\n' \
        "$test_number"
else
    printf 'not ok %s - dangling template symlink changed its target\n' "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case wrapper-symlink
victim="${CASE_ROOT}/victim-directory"
mkdir "$victim"
mkdir -p "$SERVICE_DIR"
ln -s "$victim" "${SERVICE_DIR}/run-launchd.sh"
expect_rejected
if [[ -L "${SERVICE_DIR}/run-launchd.sh" \
    && ! -e "${DATA_DIR}/mcp-stdio-templates.json" \
    && -z "$(find "$victim" -mindepth 1 -print -quit)" ]]; then
    printf 'ok %s - wrapper symlink-to-directory fails before managed writes\n' "$test_number"
else
    printf 'not ok %s - wrapper symlink redirected or allowed managed writes\n' "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case logger-directory
mkdir -p "$SERVICE_DIR"
mkdir "${SERVICE_DIR}/bounded-log.sh"
expect_rejected
if [[ -d "${SERVICE_DIR}/bounded-log.sh" \
    && ! -e "${DATA_DIR}/mcp-stdio-templates.json" ]]; then
    printf 'ok %s - nonregular logger destination fails before managed writes\n' "$test_number"
else
    printf 'not ok %s - nonregular logger destination was modified\n' "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case plist-symlink
victim="${CASE_ROOT}/victim-directory"
mkdir "$victim"
ln -s "$victim" "${PLIST_DIR}/dev.executor.gateway.plist"
expect_rejected
if [[ -L "${PLIST_DIR}/dev.executor.gateway.plist" \
    && ! -e "${DATA_DIR}/mcp-stdio-templates.json" \
    && -z "$(find "$victim" -mindepth 1 -print -quit)" ]]; then
    printf 'ok %s - plist symlink-to-directory fails before managed writes\n' "$test_number"
else
    printf 'not ok %s - plist symlink redirected or allowed managed writes\n' "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case manifest-publication-failure
ledger="${CASE_ROOT}/launchctl-ledger"
real_mktemp="$(command -v mktemp)"
printf '#!/bin/sh\ncase "$1" in *\/.service-install.*) exit 1 ;; esac\nexec %s "$@"\n' \
    "$real_mktemp" > "${STUB_DIR}/mktemp"
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/plutil"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> %q\nexit 0\n' \
    "$ledger" > "${STUB_DIR}/launchctl"
chmod 0700 "${STUB_DIR}/mktemp" "${STUB_DIR}/plutil" "${STUB_DIR}/launchctl"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" >"$OUTPUT" 2>&1; then
    printf 'not ok %s - manifest publication failure was accepted\n' "$test_number"
    exit 1
fi
if [[ -f "${PLIST_DIR}/dev.executor.gateway.plist" \
    && ! -e "${HOME_DIR}/.executor/service/service-install.manifest" \
    && -f "${HOME_DIR}/.executor/service/service-install.recovery" \
    && ! -s "$ledger" ]]; then
    rm -f "${STUB_DIR}/mktemp"
    HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
        bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
        >>"$OUTPUT" 2>&1
    if [[ -f "${HOME_DIR}/.executor/service/service-install.manifest" \
        && ! -e "${HOME_DIR}/.executor/service/service-install.recovery" ]]; then
        printf 'ok %s - manifest failure stays stopped and a clean rerun recovers\n' \
            "$test_number"
    else
        printf 'not ok %s - rerun did not recover manifest publication\n' "$test_number"
        cat "$OUTPUT"
        exit 1
    fi
else
    printf 'not ok %s - launchctl ran before the ownership manifest committed\n' "$test_number"
    cat "$OUTPUT"
    exit 1
fi

test_number=$((test_number + 1))
run_case template-link-crash
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/plutil"
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/launchctl"
chmod 0700 "${STUB_DIR}/plutil" "${STUB_DIR}/launchctl"
template_path="${DATA_DIR}/.executor-templates.ABCDEFGH"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_INSTALL_TEST_CRASH_AFTER_TEMPLATE_LINK=1 \
    EXECUTOR_MCP_STDIO_TEMPLATES_FILE="$template_path" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1; then
    printf 'not ok %s - template link crash injection reported success\n' "$test_number"
    exit 1
fi
template_copy="${CASE_ROOT}/template.copy"
cp "$template_path" "$template_copy"
if [[ "$(private_file_metadata "$template_path")" != "$(id -u)|600|2" \
    || ! -f "${SERVICE_DIR}/service-install.recovery" ]]; then
    printf 'not ok %s - template link crash did not leave recoverable state\n' \
        "$test_number"
    exit 1
fi
HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_MCP_STDIO_TEMPLATES_FILE="$template_path" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >>"$OUTPUT" 2>&1
if cmp -s "$template_copy" "$template_path" \
    && [[ "$(private_file_metadata "$template_path")" == "$(id -u)|600|1" \
        && ! -e "${SERVICE_DIR}/service-install.recovery" ]] \
    && [[ "$(find "$DATA_DIR" -maxdepth 1 -type f \
        -name '.executor-templates.*' ! -path "$template_path" | wc -l)" -eq 0 ]]; then
    printf 'ok %s - template basename crash recovers only the same-inode alias\n' \
        "$test_number"
else
    printf 'not ok %s - template link crash recovery changed or stranded state\n' \
        "$test_number"
    cat "$OUTPUT"
    exit 1
fi

test_number=$((test_number + 1))
run_case template-unlink-crash
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/plutil"
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/launchctl"
chmod 0700 "${STUB_DIR}/plutil" "${STUB_DIR}/launchctl"
template_path="${DATA_DIR}/mcp-stdio-templates.json"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_INSTALL_TEST_CRASH_AFTER_TEMPLATE_UNLINK=1 \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1; then
    printf 'not ok %s - template unlink crash injection reported success\n' "$test_number"
    exit 1
fi
template_copy="${CASE_ROOT}/template.copy"
cp "$template_path" "$template_copy"
HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >>"$OUTPUT" 2>&1
if cmp -s "$template_copy" "$template_path" \
    && [[ "$(private_file_metadata "$template_path")" == "$(id -u)|600|1" \
        && ! -e "${SERVICE_DIR}/service-install.recovery" ]]; then
    printf 'ok %s - template unlink crash resumes with the original file\n' \
        "$test_number"
else
    printf 'not ok %s - template unlink crash did not resume safely\n' "$test_number"
    cat "$OUTPUT"
    exit 1
fi

test_number=$((test_number + 1))
run_case template-alias-substitution
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/plutil"
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/launchctl"
chmod 0700 "${STUB_DIR}/plutil" "${STUB_DIR}/launchctl"
template_path="${DATA_DIR}/mcp-stdio-templates.json"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_INSTALL_TEST_CRASH_AFTER_TEMPLATE_LINK=1 \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1; then
    printf 'not ok %s - template substitution crash injection reported success\n' \
        "$test_number"
    exit 1
fi
template_alias="$(compgen -G "${DATA_DIR}/.executor-templates.*")"
unknown_alias="${CASE_ROOT}/unknown-template-alias"
rm -f "$template_alias"
ln "$template_path" "$unknown_alias"
printf '{\n  "templates": []\n}\n' > "$template_alias"
chmod 0600 "$template_alias"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >>"$OUTPUT" 2>&1; then
    printf 'not ok %s - substituted template recovery alias was accepted\n' \
        "$test_number"
    exit 1
fi
if [[ -f "$template_alias" && -f "$unknown_alias" \
    && "$(private_file_metadata "$template_path")" == "$(id -u)|600|2" ]]; then
    rm -f "$template_alias" "$unknown_alias"
    HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
        bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
        >>"$OUTPUT" 2>&1
    printf 'ok %s - substituted and unknown template aliases remain rejected\n' \
        "$test_number"
else
    printf 'not ok %s - failed template recovery mutated attacker state\n' \
        "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case template-destination-basename
template_path="${DATA_DIR}/.executor-templates.ABCDEFGH"
unknown_alias="${CASE_ROOT}/unknown-template-alias"
printf '{\n  "templates": []\n}\n' > "$template_path"
chmod 0600 "$template_path"
ln "$template_path" "$unknown_alias"
template_copy="${CASE_ROOT}/template.copy"
cp "$template_path" "$template_copy"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_MCP_STDIO_TEMPLATES_FILE="$template_path" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1; then
    printf 'not ok %s - destination basename was mistaken for a recovery alias\n' \
        "$test_number"
    exit 1
fi
if cmp -s "$template_copy" "$template_path" \
    && [[ -f "$unknown_alias" \
        && "$(private_file_metadata "$template_path")" == "$(id -u)|600|2" \
        && ! -e "$SERVICE_DIR" ]]; then
    printf 'ok %s - template destination basename never identifies itself as an alias\n' \
        "$test_number"
else
    printf 'not ok %s - basename recovery changed the destination or unknown alias\n' \
        "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
for corruption in zero truncated; do
    run_case "template-${corruption}-crash"
    printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/plutil"
    printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/launchctl"
    chmod 0700 "${STUB_DIR}/plutil" "${STUB_DIR}/launchctl"
    template_path="${DATA_DIR}/mcp-stdio-templates.json"
    if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
        EXECUTOR_INSTALL_TEST_CRASH_AFTER_TEMPLATE_LINK=1 \
        bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
        >"$OUTPUT" 2>&1; then
        printf 'not ok %s - %s template crash injection reported success\n' \
            "$test_number" "$corruption"
        exit 1
    fi
    if [[ "$corruption" == zero ]]; then
        : > "$template_path"
    else
        printf '{}' > "$template_path"
    fi
    template_copy="${CASE_ROOT}/template.copy"
    cp "$template_path" "$template_copy"
    if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
        bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
        >>"$OUTPUT" 2>&1; then
        printf 'not ok %s - %s crash template was accepted during recovery\n' \
            "$test_number" "$corruption"
        exit 1
    fi
    if ! cmp -s "$template_copy" "$template_path" \
        || [[ "$(private_file_metadata "$template_path")" != "$(id -u)|600|2" \
            || ! -e "${SERVICE_DIR}/service-install.recovery" ]]; then
        printf 'not ok %s - %s crash recovery mutated invalid template state\n' \
            "$test_number" "$corruption"
        exit 1
    fi
done
printf 'ok %s - zero and truncated template crash states fail closed\n' "$test_number"

test_number=$((test_number + 1))
run_case persisted-configuration
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/plutil"
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/launchctl"
chmod 0700 "${STUB_DIR}/plutil" "${STUB_DIR}/launchctl"
custom_data="${HOME_DIR}/Custom Executor Data"
custom_templates="${HOME_DIR}/Custom Templates/stdio templates.json"
service_root="${HOME_DIR}/.executor/service"
config="${service_root}/service-config"
wrapper="${service_root}/run-launchd.sh"
HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_DATA_DIR="$custom_data" \
    EXECUTOR_MCP_STDIO_TEMPLATES_FILE="$custom_templates" \
    EXECUTOR_PUBLIC_ORIGIN="https://executor.example.test" \
    EXECUTOR_TRUSTED_PROXIES="127.0.0.1/32,::1/128" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1
config_metadata="$(private_file_metadata "$config")"
escaped_custom_data="$(printf '%q' "$custom_data")"
escaped_custom_templates="$(printf '%q' "$custom_templates")"
if [[ "$config_metadata" != "$(id -u)|600|1" \
    || ! -f "${service_root}/bounded-log.sh" \
    || -e "${custom_data}/bounded-log.sh" \
    || -e "${custom_data}/run-launchd.sh" ]] \
    || ! grep -F -- "--data-dir ${escaped_custom_data}" "$wrapper" >/dev/null \
    || ! grep -F -- "--mcp-stdio-templates ${escaped_custom_templates}" \
        "$wrapper" >/dev/null; then
    printf 'not ok %s - persisted configuration metadata is not private\n' \
        "$test_number"
    exit 1
fi
cp "$config" "${CASE_ROOT}/initial-config"
cp "$wrapper" "${CASE_ROOT}/initial-wrapper"
HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >>"$OUTPUT" 2>&1
if ! cmp -s "$config" "${CASE_ROOT}/initial-config" \
    || ! cmp -s "$wrapper" "${CASE_ROOT}/initial-wrapper"; then
    printf 'not ok %s - reinstall without overrides reset persisted settings\n' \
        "$test_number"
    cat "$OUTPUT"
    exit 1
fi
initial_data_line="$(grep '^data_dir_hex=' "$config")"
initial_templates_line="$(grep '^templates_file_hex=' "$config")"
initial_proxies="$(grep '^trusted_proxy_hex=' "$config")"
HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_PUBLIC_ORIGIN="https://new.example.test" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >>"$OUTPUT" 2>&1
if [[ "$(grep '^data_dir_hex=' "$config")" != "$initial_data_line" \
    || "$(grep '^templates_file_hex=' "$config")" != "$initial_templates_line" \
    || "$(grep '^trusted_proxy_hex=' "$config")" != "$initial_proxies" ]] \
    || ! grep -F -- '--public-origin https://new.example.test' "$wrapper" >/dev/null; then
    printf 'not ok %s - one-field override reset unrelated persisted settings\n' \
        "$test_number"
    cat "$OUTPUT"
    exit 1
fi
HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_PUBLIC_ORIGIN="" EXECUTOR_TRUSTED_PROXIES="" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >>"$OUTPUT" 2>&1
if [[ "$(grep '^data_dir_hex=' "$config")" == "$initial_data_line" \
    && "$(grep '^templates_file_hex=' "$config")" == "$initial_templates_line" \
    && -z "$(grep '^trusted_proxy_hex=' "$config" || true)" ]] \
    && ! grep -F -- '--public-origin' "$wrapper" >/dev/null \
    && ! grep -F -- '--trusted-proxy' "$wrapper" >/dev/null; then
    printf 'ok %s - reinstall preserves settings and explicit empty overrides clear them\n' \
        "$test_number"
else
    printf 'not ok %s - explicit empty overrides did not clear persisted settings\n' \
        "$test_number"
    cat "$OUTPUT"
    exit 1
fi

test_number=$((test_number + 1))
run_case unsafe-config-symlink
victim="${CASE_ROOT}/config-victim"
mkdir -p "${HOME_DIR}/.executor/service"
printf 'keep me\n' > "$victim"
ln -s "$victim" "${HOME_DIR}/.executor/service/service-config"
expect_rejected
if [[ "$(cat "$victim")" == "keep me" \
    && -L "${HOME_DIR}/.executor/service/service-config" \
    && ! -e "${DATA_DIR}/mcp-stdio-templates.json" ]]; then
    printf 'ok %s - persisted configuration symlinks are rejected before managed writes\n' \
        "$test_number"
else
    printf 'not ok %s - unsafe persisted configuration was modified\n' "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case unsafe-custom-ancestor
unsafe_parent="${HOME_DIR}/unsafe-parent"
mkdir "$unsafe_parent"
chmod 0777 "$unsafe_parent"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_DATA_DIR="${unsafe_parent}/data" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1; then
    printf 'not ok %s - world-writable custom data ancestry was accepted\n' \
        "$test_number"
    exit 1
fi
if [[ ! -e "${unsafe_parent}/data" \
    && ! -e "${HOME_DIR}/.executor/service/service-config" \
    && ! -e "${HOME_DIR}/.executor/service/service-install.recovery" ]]; then
    printf 'ok %s - unsafe custom data ancestry fails before managed writes\n' \
        "$test_number"
else
    printf 'not ok %s - unsafe custom data ancestry allowed managed writes\n' \
        "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case symlinked-custom-ancestor
victim="${CASE_ROOT}/custom-data-victim"
mkdir "$victim"
ln -s "$victim" "${HOME_DIR}/custom-data-link"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_DATA_DIR="${HOME_DIR}/custom-data-link/data" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1; then
    printf 'not ok %s - symlinked custom data ancestry was accepted\n' \
        "$test_number"
    exit 1
fi
if [[ -L "${HOME_DIR}/custom-data-link" \
    && -z "$(find "$victim" -mindepth 1 -print -quit)" \
    && ! -e "${HOME_DIR}/.executor/service/service-config" ]]; then
    printf 'ok %s - symlinked custom data ancestry cannot redirect writes\n' \
        "$test_number"
else
    printf 'not ok %s - symlinked custom data ancestry redirected writes\n' \
        "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case unsafe-template-ancestor
unsafe_parent="${HOME_DIR}/unsafe-templates"
mkdir "$unsafe_parent"
chmod 0777 "$unsafe_parent"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_MCP_STDIO_TEMPLATES_FILE="${unsafe_parent}/templates.json" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1; then
    printf 'not ok %s - world-writable template ancestry was accepted\n' \
        "$test_number"
    exit 1
fi
if [[ ! -e "${unsafe_parent}/templates.json" \
    && ! -e "${HOME_DIR}/.executor/service/service-config" \
    && ! -e "${HOME_DIR}/.executor/service/service-install.recovery" ]]; then
    printf 'ok %s - unsafe template ancestry fails before managed writes\n' \
        "$test_number"
else
    printf 'not ok %s - unsafe template ancestry allowed managed writes\n' \
        "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case relative-custom-path
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" EXECUTOR_DATA_DIR="relative-data" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1; then
    printf 'not ok %s - relative custom data path was accepted\n' "$test_number"
    exit 1
fi
if [[ ! -e "${HOME_DIR}/.executor/service/service-config" \
    && ! -e "${HOME_DIR}/.executor/service/service-install.recovery" ]]; then
    printf 'ok %s - relative custom paths fail before managed writes\n' "$test_number"
else
    printf 'not ok %s - relative custom path allowed managed writes\n' "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
collision_case_number=0
for collision_name in \
    service-binary \
    service-config \
    manifest \
    recovery \
    wrapper \
    logger \
    plist \
    data-directory \
    master-key \
    database \
    database-journal \
    private-log \
    rotated-log \
    case-folded-master-key \
    nested-service-path; do
    collision_case_number=$((collision_case_number + 1))
    run_case "reserved-collision-${collision_case_number}"
    case "$collision_name" in
        service-binary) collision_path="${SERVICE_DIR}/bin/executor" ;;
        service-config) collision_path="${SERVICE_DIR}/service-config" ;;
        manifest) collision_path="${SERVICE_DIR}/service-install.manifest" ;;
        recovery) collision_path="${SERVICE_DIR}/service-install.recovery" ;;
        wrapper) collision_path="${SERVICE_DIR}/run-launchd.sh" ;;
        logger) collision_path="${SERVICE_DIR}/bounded-log.sh" ;;
        plist) collision_path="${PLIST_DIR}/dev.executor.gateway.plist" ;;
        data-directory) collision_path="$DATA_DIR" ;;
        master-key)
            collision_path="${DATA_DIR}/master.key"
            printf 'existing master key sentinel\n' > "$collision_path"
            chmod 0600 "$collision_path"
            ;;
        database) collision_path="${DATA_DIR}/executor.db" ;;
        database-journal) collision_path="${DATA_DIR}/executor.db-journal" ;;
        private-log) collision_path="${DATA_DIR}/executor.log" ;;
        rotated-log) collision_path="${DATA_DIR}/executor.log.2" ;;
        case-folded-master-key) collision_path="${DATA_DIR}/MASTER.KEY" ;;
        nested-service-path) collision_path="${SERVICE_DIR}/custom/templates.json" ;;
        *) exit 1 ;;
    esac
    if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
        EXECUTOR_MCP_STDIO_TEMPLATES_FILE="$collision_path" \
        bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
        >"$OUTPUT" 2>&1; then
        printf 'not ok %s - reserved template collision %s was accepted\n' \
            "$test_number" "$collision_name"
        exit 1
    fi
    if [[ -e "$SERVICE_DIR" \
        || -e "${PLIST_DIR}/dev.executor.gateway.plist" \
        || -e "${DATA_DIR}/mcp-stdio-templates.json" ]]; then
        printf 'not ok %s - collision %s wrote managed files before rejection\n' \
            "$test_number" "$collision_name"
        cat "$OUTPUT"
        exit 1
    fi
    if [[ "$collision_name" == master-key \
        && "$(cat "$collision_path")" != "existing master key sentinel" ]]; then
        printf 'not ok %s - master key collision changed the existing sentinel\n' \
            "$test_number"
        exit 1
    fi
done
printf 'ok %s - template collisions with every reserved path fail before writes\n' \
    "$test_number"

test_number=$((test_number + 1))
for collision_name in case-folded-service-root plist-parent; do
    run_case "data-collision-${collision_name}"
    case "$collision_name" in
        case-folded-service-root) collision_path="${HOME_DIR}/.EXECUTOR" ;;
        plist-parent) collision_path="$PLIST_DIR" ;;
        *) exit 1 ;;
    esac
    if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
        EXECUTOR_DATA_DIR="$collision_path" \
        bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
        >"$OUTPUT" 2>&1; then
        printf 'not ok %s - data collision %s was accepted\n' \
            "$test_number" "$collision_name"
        exit 1
    fi
    if [[ -e "$SERVICE_DIR" \
        || -e "${PLIST_DIR}/dev.executor.gateway.plist" ]]; then
        printf 'not ok %s - data collision %s wrote managed files\n' \
            "$test_number" "$collision_name"
        exit 1
    fi
done
printf 'ok %s - data paths cannot contain service-owned paths\n' "$test_number"

test_number=$((test_number + 1))
run_case collision-reinstall-preservation
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/plutil"
printf '#!/bin/sh\nexit 0\n' > "${STUB_DIR}/launchctl"
chmod 0700 "${STUB_DIR}/plutil" "${STUB_DIR}/launchctl"
HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >"$OUTPUT" 2>&1
snapshot="${CASE_ROOT}/snapshot"
mkdir "$snapshot"
cp "${SERVICE_DIR}/service-config" "${snapshot}/service-config"
cp "${SERVICE_DIR}/service-install.manifest" "${snapshot}/service-install.manifest"
cp "${SERVICE_DIR}/run-launchd.sh" "${snapshot}/run-launchd.sh"
cp "${SERVICE_DIR}/bounded-log.sh" "${snapshot}/bounded-log.sh"
cp "${PLIST_DIR}/dev.executor.gateway.plist" "${snapshot}/launchd.plist"
cp "${DATA_DIR}/mcp-stdio-templates.json" "${snapshot}/templates.json"
if HOME="$HOME_DIR" PATH="${STUB_DIR}:$PATH" \
    EXECUTOR_MCP_STDIO_TEMPLATES_FILE="${SERVICE_DIR}/service-config" \
    bash "$INSTALLER" --binary "$EXECUTOR_BINARY" --no-start \
    >>"$OUTPUT" 2>&1; then
    printf 'not ok %s - colliding reinstall was accepted\n' "$test_number"
    exit 1
fi
if cmp -s "${SERVICE_DIR}/service-config" "${snapshot}/service-config" \
    && cmp -s "${SERVICE_DIR}/service-install.manifest" \
        "${snapshot}/service-install.manifest" \
    && cmp -s "${SERVICE_DIR}/run-launchd.sh" "${snapshot}/run-launchd.sh" \
    && cmp -s "${SERVICE_DIR}/bounded-log.sh" "${snapshot}/bounded-log.sh" \
    && cmp -s "${PLIST_DIR}/dev.executor.gateway.plist" "${snapshot}/launchd.plist" \
    && cmp -s "${DATA_DIR}/mcp-stdio-templates.json" "${snapshot}/templates.json" \
    && [[ ! -e "${SERVICE_DIR}/service-install.recovery" ]]; then
    printf 'ok %s - rejected collision preserves an existing installation byte-for-byte\n' \
        "$test_number"
else
    printf 'not ok %s - rejected collision changed an existing installation\n' \
        "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case unsafe-config-hardlink
victim="${CASE_ROOT}/config-victim"
mkdir -p "${HOME_DIR}/.executor/service"
printf 'keep me\n' > "$victim"
chmod 0600 "$victim"
ln "$victim" "${HOME_DIR}/.executor/service/service-config"
expect_rejected
if [[ "$(cat "$victim")" == "keep me" \
    && "$(private_file_metadata "$victim")" == "$(id -u)|600|2" \
    && ! -e "${DATA_DIR}/mcp-stdio-templates.json" ]]; then
    printf 'ok %s - hard-linked persisted configuration is rejected without mutation\n' \
        "$test_number"
else
    printf 'not ok %s - hard-linked persisted configuration was modified\n' \
        "$test_number"
    exit 1
fi

test_number=$((test_number + 1))
run_case malformed-config
mkdir -p "${HOME_DIR}/.executor/service"
printf 'executor-launchd-config-v1\nunknown_hex=00\n' \
    > "${HOME_DIR}/.executor/service/service-config"
chmod 0600 "${HOME_DIR}/.executor/service/service-config"
expect_rejected
if [[ ! -e "${DATA_DIR}/mcp-stdio-templates.json" \
    && ! -e "${HOME_DIR}/.executor/service/service-install.recovery" ]]; then
    printf 'ok %s - malformed persisted configuration fails before managed writes\n' \
        "$test_number"
else
    printf 'not ok %s - malformed persisted configuration allowed managed writes\n' \
        "$test_number"
    exit 1
fi

printf '1..%s\n' "$test_number"
