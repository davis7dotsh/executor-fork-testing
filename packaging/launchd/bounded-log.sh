#!/bin/bash
set -euo pipefail

readonly MAX_BYTES=$((1024 * 1024))
readonly GENERATIONS=3
readonly CHUNK_BYTES=$((64 * 1024))
readonly LOG_PATH=${1:?a log path is required}

umask 0077
LC_ALL=C
export LC_ALL

temporary_file=""
cleanup() {
    if [[ -n "$temporary_file" ]]; then
        rm -f "$temporary_file"
    fi
}
trap cleanup EXIT

require_regular_file_or_absent() {
    local path=$1

    if [[ -L "$path" ]]; then
        printf 'refusing symbolic-link log path: %s\n' "$path" >&2
        exit 1
    fi
    if [[ -e "$path" && ! -f "$path" ]]; then
        printf 'log path is not a regular file: %s\n' "$path" >&2
        exit 1
    fi
}

require_regular_file_or_absent "$LOG_PATH"
generation=1
while [[ "$generation" -le "$GENERATIONS" ]]; do
    require_regular_file_or_absent "${LOG_PATH}.${generation}"
    generation=$((generation + 1))
done

touch "$LOG_PATH"
chmod 0600 "$LOG_PATH"
generation=1
while [[ "$generation" -le "$GENERATIONS" ]]; do
    if [[ -f "${LOG_PATH}.${generation}" ]]; then
        chmod 0600 "${LOG_PATH}.${generation}"
    fi
    generation=$((generation + 1))
done
bytes=$(wc -c < "$LOG_PATH")

if [[ "$bytes" -gt "$MAX_BYTES" ]]; then
    trimmed_log=$(mktemp "${LOG_PATH}.trim.XXXXXXXX")
    temporary_file=$trimmed_log
    tail -c "$MAX_BYTES" "$LOG_PATH" > "$trimmed_log"
    chmod 0600 "$trimmed_log"
    mv -f "$trimmed_log" "$LOG_PATH"
    temporary_file=""
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

chunk_file=$(mktemp "${LOG_PATH}.chunk.XXXXXXXX")
temporary_file=$chunk_file

while :; do
    if [[ "$bytes" -ge "$MAX_BYTES" ]]; then
        read_size=$CHUNK_BYTES
    else
        read_size=$((MAX_BYTES - bytes))
        if [[ "$read_size" -gt "$CHUNK_BYTES" ]]; then
            read_size=$CHUNK_BYTES
        fi
    fi

    : > "$chunk_file"
    if ! dd bs="$read_size" count=1 of="$chunk_file" 2>/dev/null; then
        printf 'failed to read launchd log input\n' >&2
        exit 1
    fi
    chunk_size=$(wc -c < "$chunk_file")
    if [[ "$chunk_size" -eq 0 ]]; then
        break
    fi
    if [[ "$bytes" -ge "$MAX_BYTES" ]]; then
        rotate
    fi
    cat "$chunk_file" >> "$LOG_PATH"
    bytes=$((bytes + chunk_size))
done
