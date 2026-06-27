#!/usr/bin/env bash
set -euo pipefail

image="${1:?container image is required}"
canonical_web_dir="${2:?canonical web directory is required}"
container_name="${3:?container name is required}"
volume_name="${4:?volume name is required}"
log_file=""

cleanup() {
    local status=$1
    trap - EXIT
    if docker inspect "$container_name" >/dev/null 2>&1; then
        if [[ "$status" -ne 0 ]]; then
            docker logs "$container_name" >&2 || true
        fi
        docker rm --force "$container_name" >/dev/null 2>&1 || true
    fi
    docker volume rm --force "$volume_name" >/dev/null 2>&1 || true
    if [[ -n "$log_file" ]]; then
        rm -f "$log_file"
    fi
    exit "$status"
}
trap 'cleanup "$?"' EXIT

docker volume create "$volume_name" >/dev/null
docker run --detach \
    --name "$container_name" \
    --pull=never \
    --init \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --memory 2g \
    --pids-limit 512 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
    --mount "source=${volume_name},target=/var/lib/executor" \
    --publish 127.0.0.1::4788 \
    "$image" >/dev/null

endpoint="$(docker port "$container_name" 4788/tcp)"
port="${endpoint##*:}"
[[ "$port" =~ ^[0-9]+$ ]] \
    || { printf 'could not resolve mapped container port from %s\n' "$endpoint" >&2; exit 1; }
base_url="http://127.0.0.1:${port}"

ready=false
for _ in {1..120}; do
    if curl --fail --silent --show-error "${base_url}/healthz" >/dev/null 2>&1; then
        ready=true
        break
    fi
    if [[ "$(docker inspect --format '{{.State.Status}}' "$container_name")" == "exited" ]]; then
        break
    fi
    sleep 1
done
[[ "$ready" == true ]] \
    || { printf 'release container did not become healthy\n' >&2; exit 1; }

log_file="$(mktemp "${TMPDIR:-/tmp}/executor-container-smoke.XXXXXXXX")"
docker logs "$container_name" > "$log_file" 2>&1
grep -F 'Complete first-boot setup at:' "$log_file" >/dev/null
grep -E 'http://127\.0\.0\.1:4788/setup#token=.+' "$log_file" >/dev/null
rm -f "$log_file"
log_file=""

"$(dirname "${BASH_SOURCE[0]}")/smoke-release-server.sh" \
    "$base_url" \
    "$canonical_web_dir"

docker stop --time 120 "$container_name" >/dev/null
[[ "$(docker inspect --format '{{.State.ExitCode}}' "$container_name")" == "0" ]]
