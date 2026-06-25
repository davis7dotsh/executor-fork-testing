#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
readonly REPOSITORY_ROOT=$(cd -- "${SCRIPT_DIR}/.." && pwd -P)
readonly LOGGER="${REPOSITORY_ROOT}/packaging/launchd/bounded-log.sh"
readonly MIB=$((1024 * 1024))

test_root=$(mktemp -d)
trap 'rm -rf -- "${test_root}"' EXIT
test_number=0

pass() {
    test_number=$((test_number + 1))
    printf 'ok %s - %s\n' "${test_number}" "$1"
}

fail() {
    printf 'not ok %s - %s\n' "$((test_number + 1))" "$1" >&2
    exit 1
}

file_mode() {
    if stat -f '%Lp' "$1" >/dev/null 2>&1; then
        stat -f '%Lp' "$1"
    else
        stat --format='%a' -- "$1"
    fi
}

normal_log="${test_root}/normal.log"
normal_expected="${test_root}/normal.expected"
printf 'first line\nsecond line\nthird line without newline' > "$normal_expected"
"$LOGGER" "$normal_log" < "$normal_expected"
if ! cmp -s "$normal_expected" "$normal_log"; then
    fail "normal line input was not preserved exactly"
fi
if [[ "$(file_mode "$normal_log")" != 600 ]]; then
    fail "normal log does not have mode 0600"
fi
pass "normal lines and a final partial line are preserved"

symlink_target="${test_root}/symlink-target"
printf 'do not touch' > "$symlink_target"
symlink_log="${test_root}/symlink.log"
ln -s "$symlink_target" "$symlink_log"
if "$LOGGER" "$symlink_log" < "$normal_expected" 2>/dev/null; then
    fail "symbolic-link log path was accepted"
fi
if [[ "$(cat "$symlink_target")" != 'do not touch' ]]; then
    fail "symbolic-link log target was changed"
fi
pass "symbolic-link log path is rejected without touching its target"

large_input="${test_root}/large.input"
segment_c="${test_root}/segment-C"
segment_d="${test_root}/segment-D"
segment_e="${test_root}/segment-E"
segment_f="${test_root}/segment-F"
: > "$large_input"
for letter in A B C D E; do
    segment="${test_root}/segment-${letter}"
    dd if=/dev/zero bs="$MIB" count=1 2>/dev/null \
        | tr '\000' "$letter" > "$segment"
    cat "$segment" >> "$large_input"
done
dd if=/dev/zero bs=123 count=1 2>/dev/null \
    | tr '\000' F > "$segment_f"
cat "$segment_f" >> "$large_input"

large_log="${test_root}/large.log"
"$LOGGER" "$large_log" < "$large_input"
if ! cmp -s "$segment_f" "$large_log"; then
    fail "current log does not contain the final partial generation"
fi
if ! cmp -s "$segment_e" "${large_log}.1"; then
    fail "first rotated generation is incorrect"
fi
if ! cmp -s "$segment_d" "${large_log}.2"; then
    fail "second rotated generation is incorrect"
fi
if ! cmp -s "$segment_c" "${large_log}.3"; then
    fail "third rotated generation is incorrect"
fi
if [[ -e "${large_log}.4" ]]; then
    fail "logger retained more than three rotated generations"
fi
for retained_log in \
    "$large_log" \
    "${large_log}.1" \
    "${large_log}.2" \
    "${large_log}.3"; do
    if [[ "$(wc -c < "$retained_log")" -gt "$MIB" ]]; then
        fail "retained log exceeds 1 MiB: ${retained_log}"
    fi
    if [[ "$(file_mode "$retained_log")" != 600 ]]; then
        fail "retained log does not have mode 0600: ${retained_log}"
    fi
done
pass "large newline-free input stays within four secure bounded files"

printf '1..%s\n' "$test_number"
