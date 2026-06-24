#!/bin/bash
set -euo pipefail

readonly MAX_BYTES=$((1024 * 1024))
readonly GENERATIONS=3
readonly LOG_PATH=${1:?a log path is required}

umask 0077
if [[ -L "$LOG_PATH" ]]; then
    printf 'refusing symbolic-link log path: %s\n' "$LOG_PATH" >&2
    exit 1
fi
touch "$LOG_PATH"
chmod 0600 "$LOG_PATH"
bytes=$(wc -c < "$LOG_PATH")
LC_ALL=C

if [[ "$bytes" -gt "$MAX_BYTES" ]]; then
    trimmed_log=$(mktemp "${LOG_PATH}.trim.XXXXXXXX")
    trap 'rm -f "$trimmed_log"' EXIT
    tail -c "$MAX_BYTES" "$LOG_PATH" > "$trimmed_log"
    chmod 0600 "$trimmed_log"
    mv -f "$trimmed_log" "$LOG_PATH"
    trap - EXIT
    bytes=$MAX_BYTES
fi

rotate() {
    local generation
    rm -f "${LOG_PATH}.${GENERATIONS}"
    generation=$((GENERATIONS - 1))
    while [[ "$generation" -ge 1 ]]; do
        if [[ -f "${LOG_PATH}.${generation}" ]]; then
            mv -f "${LOG_PATH}.${generation}" "${LOG_PATH}.$((generation + 1))"
        fi
        generation=$((generation - 1))
    done
    if [[ -f "$LOG_PATH" ]]; then
        mv -f "$LOG_PATH" "${LOG_PATH}.1"
    fi
    : > "$LOG_PATH"
    chmod 0600 "$LOG_PATH"
    bytes=0
}

line=""
while IFS= read -r line || [[ -n "$line" ]]; do
    line_bytes=${#line}
    if [[ "$line_bytes" -ge "$MAX_BYTES" ]]; then
        line=${line:0:$((MAX_BYTES - 2))}
        line_bytes=${#line}
    fi
    required=$((line_bytes + 1))
    if [[ $((bytes + required)) -gt "$MAX_BYTES" ]]; then
        rotate
    fi
    printf '%s\n' "$line" >> "$LOG_PATH"
    bytes=$((bytes + required))
    line=""
done
