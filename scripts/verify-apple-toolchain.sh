#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 6 ]]; then
    printf 'Usage: %s <developer-dir> <xcode-version> <xcode-build> <sdk-version> <clang-version> <ld-version>\n' "$0" >&2
    exit 2
fi

developer_dir=$1
expected_xcode_version=$2
expected_xcode_build=$3
expected_sdk_version=$4
expected_clang_version=$5
expected_ld_version=$6

[[ -d "$developer_dir" && ! -L "$developer_dir" ]] \
    || { printf 'Pinned Xcode developer directory is unavailable: %s\n' "$developer_dir" >&2; exit 1; }

export DEVELOPER_DIR="$developer_dir"

xcode_info="$(xcodebuild -version)"
expected_xcode_info="$(printf 'Xcode %s\nBuild version %s' \
    "$expected_xcode_version" \
    "$expected_xcode_build")"
[[ "$xcode_info" == "$expected_xcode_info" ]] \
    || { printf 'Unexpected Xcode identity:\n%s\n' "$xcode_info" >&2; exit 1; }

sdk_version="$(xcrun --sdk macosx --show-sdk-version)"
[[ "$sdk_version" == "$expected_sdk_version" ]] \
    || { printf 'Unexpected macOS SDK version: %s\n' "$sdk_version" >&2; exit 1; }
sdk_path="$(xcrun --sdk macosx --show-sdk-path)"
[[ "$sdk_path" == */"MacOSX${expected_sdk_version}.sdk" ]] \
    || { printf 'Unexpected macOS SDK path: %s\n' "$sdk_path" >&2; exit 1; }

clang_info="$(xcrun clang --version)"
clang_banner="${clang_info%%$'\n'*}"
[[ "$clang_banner" == "$expected_clang_version" ]] \
    || { printf 'Unexpected Apple clang version: %s\n' "$clang_banner" >&2; exit 1; }

ld_info="$(xcrun ld -v 2>&1)"
ld_banner="${ld_info%%$'\n'*}"
[[ "$ld_banner" == "@(#)PROGRAM:ld PROJECT:ld-${expected_ld_version}" ]] \
    || { printf 'Unexpected Apple ld version: %s\n' "$ld_banner" >&2; exit 1; }

toolchain_bin="${developer_dir}/Toolchains/XcodeDefault.xctoolchain/usr/bin"
[[ "$(xcrun --find clang)" == "${toolchain_bin}/clang" ]] \
    || { printf 'xcrun resolved clang outside the pinned Xcode toolchain\n' >&2; exit 1; }
[[ "$(xcrun --find ld)" == "${toolchain_bin}/ld" ]] \
    || { printf 'xcrun resolved ld outside the pinned Xcode toolchain\n' >&2; exit 1; }

printf 'Verified Xcode %s (%s), macOS SDK %s, %s, and ld-%s\n' \
    "$expected_xcode_version" \
    "$expected_xcode_build" \
    "$expected_sdk_version" \
    "$expected_clang_version" \
    "$expected_ld_version"
