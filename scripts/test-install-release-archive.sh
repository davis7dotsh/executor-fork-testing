#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/executor-release-fixture.XXXXXXXX")"
trap 'rm -rf "$fixture"' EXIT

stage="${fixture}/stage"
mkdir "$stage"
printf '#!/bin/sh\nexit 0\n' > "${stage}/executor"
chmod 0755 "${stage}/executor"
printf 'MIT fixture\n' > "${stage}/LICENSE"
printf '<html>Rust license fixture</html>\n' > "${stage}/THIRD_PARTY_LICENSES.html"
printf '[{"name":"Svelte","identifier":"MIT","text":"fixture"}]\n' \
    > "${stage}/THIRD_PARTY_JAVASCRIPT_LICENSES.json"

archive="${fixture}/executor-fixture.tar.gz"
tar -C "$stage" -czf "$archive" \
    executor LICENSE THIRD_PARTY_LICENSES.html \
    THIRD_PARTY_JAVASCRIPT_LICENSES.json
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$archive" > "${archive}.sha256"
else
    shasum -a 256 "$archive" > "${archive}.sha256"
fi

install_dir="${fixture}/installed"
EXECUTOR_INSTALL_DIR="$install_dir" \
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

printf 'release archive installer fixture passed\n'
