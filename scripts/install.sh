#!/usr/bin/env bash
set -euo pipefail

APP="executor"
REPOSITORY="${EXECUTOR_REPOSITORY:-RhysSullivan/executor}"
INSTALL_DIR="${EXECUTOR_INSTALL_DIR:-$HOME/.executor/bin}"
requested_version="${VERSION:-}"
binary_path=""
local_archive_path=""
local_checksum_path=""
no_modify_path=false

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

Environment:
    EXECUTOR_INSTALL_DIR    Binary directory (default: \$HOME/.executor/bin)
    EXECUTOR_REPOSITORY     GitHub owner/repository for downloads
    VERSION                 Version to install when --version is omitted

Examples:
    curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/main/scripts/install.sh | bash
    curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/main/scripts/install.sh | bash -s -- --version 2.0.0
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

case "$REPOSITORY" in
    ''|/*|*/|*/*/*|*[!A-Za-z0-9._/-]*)
        fail "EXECUTOR_REPOSITORY must be an owner/repository name"
        ;;
esac
[[ "$INSTALL_DIR" == /* ]] || fail "EXECUTOR_INSTALL_DIR must be an absolute path"
case "$INSTALL_DIR" in
    *:*|*$'\n'*|*$'\r'*) fail "EXECUTOR_INSTALL_DIR cannot contain colons or line breaks" ;;
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

make_temp_dir() {
    mktemp -d "${TMPDIR:-/tmp}/${APP}-install.XXXXXXXX"
}

verify_checksum() {
    local checksum_file=$1 archive_path=$2 expected actual
    expected="$(awk 'NF { print $1; exit }' "$checksum_file")"
    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || fail "release checksum is malformed"

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$archive_path" | awk '{ print $1 }')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$archive_path" | awk '{ print $1 }')"
    else
        fail "sha256sum or shasum is required to verify the release"
    fi

    [[ "$actual" == "$expected" ]] || fail "release checksum verification failed"
}

install_binary() {
    local source=$1 temporary
    mkdir -p "$INSTALL_DIR"
    temporary="$(mktemp "${INSTALL_DIR}/.${APP}.XXXXXXXX")"
    trap 'rm -f "$temporary"' RETURN
    cp "$source" "$temporary"
    chmod 0755 "$temporary"
    mv -f "$temporary" "${INSTALL_DIR}/${APP}"
    trap - RETURN
}

install_support_file() {
    local source=$1 destination=$2 temporary
    temporary="$(mktemp "${INSTALL_DIR}/.${destination}.XXXXXXXX")"
    trap 'rm -f "$temporary"' RETURN
    cp "$source" "$temporary"
    chmod 0644 "$temporary"
    mv -f "$temporary" "${INSTALL_DIR}/${destination}"
    trap - RETURN
}

if [[ -n "$binary_path" ]]; then
    [[ -f "$binary_path" ]] || fail "binary not found at $binary_path"
    install_binary "$binary_path"
else
    command -v tar >/dev/null 2>&1 || fail "tar is required"

    temporary_directory="$(make_temp_dir)"
    trap 'rm -rf "$temporary_directory"' EXIT
    if [[ -n "$local_archive_path" ]]; then
        [[ -f "$local_archive_path" ]] || fail "archive not found at $local_archive_path"
        archive_path="$local_archive_path"
        checksum_path="${local_checksum_path:-${local_archive_path}.sha256}"
        [[ -f "$checksum_path" ]] || fail "checksum not found at $checksum_path"
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
    [[ "$(wc -c < "$archive_path")" -le 268435456 ]] \
        || fail "release archive exceeds 256 MiB"
    [[ "$(wc -c < "$checksum_path")" -le 1048576 ]] \
        || fail "release checksum exceeds 1 MiB"
    verify_checksum "$checksum_path" "$archive_path"

    members_path="${temporary_directory}/archive-members.txt"
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
    install_binary "$extracted_binary"
    install_support_file "${extracted_directory}/LICENSE" LICENSE
    install_support_file \
        "${extracted_directory}/THIRD_PARTY_LICENSES.html" \
        THIRD_PARTY_LICENSES.html
    install_support_file \
        "${extracted_directory}/THIRD_PARTY_JAVASCRIPT_LICENSES.json" \
        THIRD_PARTY_JAVASCRIPT_LICENSES.json
fi

add_to_path() {
    local config_file=$1 command=$2
    if grep -Fqx "$command" "$config_file"; then
        return
    fi
    if [[ -w "$config_file" ]]; then
        printf '\n# Executor\n%s\n' "$command" >> "$config_file"
        printf 'Added Executor to PATH in %s\n' "$config_file"
    else
        printf 'Add this to %s:\n  %s\n' "$config_file" "$command"
    fi
}

if [[ "$no_modify_path" != "true" && ":${PATH}:" != *":${INSTALL_DIR}:"* ]]; then
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

    if [[ -f "$config_file" ]]; then
        add_to_path "$config_file" "$path_command"
    else
        printf 'Add Executor to PATH:\n  %s\n' "$path_command"
    fi
fi

if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
    printf '%s\n' "$INSTALL_DIR" >> "$GITHUB_PATH"
fi

printf '\nInstalled Executor at %s\n' "${INSTALL_DIR}/${APP}"
printf 'Start it with: executor server\n'
