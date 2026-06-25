---
name: cli-release
description: Runbook for the supported native Executor release. Covers Cargo versioning, immutable release inputs, dry runs, protected authorization, and owner-gated publishing.
---

# Executor release runbook

## Authoritative document

`RELEASING.md` at the repository root is the source of truth. The supported
native Rust product, published by `.github/workflows/release.yml`, is the only
release surface.

Do not infer another release path from archived source or historical tags.

## Native product release

`Cargo.toml` is the only native product version source. The manual
`.github/workflows/release.yml` workflow is the only entrypoint allowed to
publish native archives, the root container image, or the primary GitHub
release.

The workflow requires:

- `mode`: `dry-run` or `publish`
- `tag`: exact `v<Cargo.toml version>`
- `commit_sha`: exact lowercase 40-character commit on `origin/main`

Always run dry-run mode first. Publish mode additionally requires the remote tag
to point at the exact supplied commit, the protected `native-release`
environment, and its scoped `NATIVE_RELEASE_TOKEN` secret.

```sh
git fetch origin main
sha="$(git rev-parse origin/main)"
version="$(git show "$sha:Cargo.toml" | python3 -c 'import sys,tomllib; print(tomllib.load(sys.stdin.buffer)["package"]["version"])')"
tag="v$version"

gh workflow run release.yml --ref main \
  -f mode=dry-run \
  -f tag="$tag" \
  -f commit_sha="$sha"
```

Create and push the tag only after the dry run succeeds, then dispatch the same
workflow with `mode=publish`. Follow the exact tag verification sequence in
`RELEASING.md`.

## Retired package release paths

The TypeScript workspaces are private implementation packages used by the
active product and its retained source. This fork does not publish them to npm.
The old npm workflows, publisher scripts, and Changesets release machinery are
retired. Do not recreate a package release path from archived source or
upstream package metadata.

## Owner rules

- Never commit, push, tag, dispatch publish mode, or publish without explicit
  owner approval.
- Never add AI assistant attribution or co-author trailers.
- Preserve unrelated dirty worktree changes.
- Verify version, tag, commit, workflow inputs, and remote state before
  describing a release as ready.
- Ask one question when release scope or publish authority is unclear.
