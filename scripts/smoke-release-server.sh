#!/usr/bin/env bash
set -euo pipefail

base_url="${1:?base URL is required}"
canonical_web_dir="${2:?canonical web directory is required}"

[[ -f "${canonical_web_dir}/index.html" ]] \
    || { printf 'missing canonical index.html in %s\n' "$canonical_web_dir" >&2; exit 1; }

response_dir="$(mktemp -d "${TMPDIR:-/tmp}/executor-web-smoke.XXXXXXXX")"
trap 'rm -rf "$response_dir"' EXIT

curl --fail --globoff --silent --show-error "${base_url}/healthz" >/dev/null
curl --fail --globoff --silent --show-error --output "${response_dir}/root" "${base_url}/"
cmp "${canonical_web_dir}/index.html" "${response_dir}/root"

asset_list="${response_dir}/assets"
find "$canonical_web_dir" -type f | LC_ALL=C sort > "$asset_list"
asset_index=0
while IFS= read -r asset; do
    relative="${asset#${canonical_web_dir}/}"
    case "$relative" in
        *$'\n'*|*$'\r'*|*' '*|*'?'*|*'#'*|*'%'*)
            printf 'canonical web asset has an unsafe URL path: %s\n' "$relative" >&2
            exit 1
            ;;
    esac
    asset_index=$((asset_index + 1))
    served="${response_dir}/served-${asset_index}"
    curl --fail --globoff --silent --show-error \
        --output "$served" \
        "${base_url}/${relative}"
    cmp "$asset" "$served"
done < "$asset_list"

[[ "$asset_index" -gt 1 ]] \
    || { printf 'canonical web payload must contain more than index.html\n' >&2; exit 1; }

printf 'verified %s canonical web assets from %s\n' "$asset_index" "$base_url"
