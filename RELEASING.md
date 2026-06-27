# Releasing

`Cargo.toml` is the only version source for the native Executor product. The
manual `Release native Executor` workflow is the only entrypoint that may
publish native archives, the root Docker image, or the primary GitHub release.
It derives `EXECUTOR_REPOSITORY` from the repository running the workflow. The
supported installer currently defaults to `davis7dotsh/executor-fork-testing`
and accepts the same variable as an explicit fork override.

## Prepare the release commit

1. Change `[package].version` in `Cargo.toml`.
2. Run `cargo check --locked`. If Cargo reports that the lockfile needs an
   update, run `cargo check` once, review the `Cargo.lock` change, then rerun
   `cargo check --locked`.
3. Verify `cargo run -- --version` prints `executor <version>`.
4. Merge the release commit to `main` and record its full SHA.

Release tags must be exactly `v<Cargo.toml version>`. The commit must be on
`origin/main`, and publish mode requires the existing remote tag to resolve to
the exact 40-character SHA supplied to the workflow. Release versions cannot
contain SemVer build metadata (`+...`) because OCI image tags do not support
that character.

The `ghcr.io/<repository-owner>/executor` container package must be public
before promotion. On the first publish attempt, GHCR may create it as private.
If the anonymous-pull gate fails, open the package settings, change visibility
to public, then rerun the workflow with the same tag and commit. The GitHub
release remains a draft until that gate passes.

Before publishing, configure these repository controls. The workflow reads
them through GitHub's REST API and fails closed if they drift:

- Create a `native-release` environment with only a required-reviewers rule
  and a branch-policy rule. Set `prevent_self_review=false`, make the sole
  reviewer the GitHub user `bmdavis419` (user ID `45952064`), and configure a
  custom deployment branch policy whose sole entry is the `main` branch.
  Disable administrator bypass so every publish requires approval.
- Create an active tag ruleset for exactly `refs/tags/v*`, with no exclusions
  or bypass actors. Enable both restrict updates and restrict deletions. Do not
  allow fetch-and-merge updates, and do not add any other rule. Do not restrict
  creations, because the release tag must be created before dispatch.
- Enable immutable releases in the repository release settings.
- Add a `NATIVE_RELEASE_TOKEN` secret only to the `native-release` environment.
  It must be a classic personal access token owned by `bmdavis419`, with the
  exact scopes `public_repo` and `write:packages`, and no others. The same
  account login is used as the GHCR username. Create it from the
  [prefilled exact-scope form](https://github.com/settings/tokens/new?scopes=public_repo,write:packages)
  because selecting `write:packages` manually can auto-select the broader
  `repo` scope. Before saving, verify that only `public_repo` and
  `write:packages` are selected. Do not add this token as a repository or
  organization secret.

Every native job that publishes or reads a protected release credential uses
the `native-release` environment. A dedicated preflight checks
that the secret is present, belongs to the expected account, has both classic
PAT scopes and no extras, can push to the repository, can authenticate to GHCR, and sees
immutable releases enabled. All GitHub release and GHCR writes use that token.
The exact no-bypass ruleset check runs only after protected-environment approval
because the public read token does not expose bypass actors. The job-scoped
`GITHUB_TOKEN` remains read-only. Require a fresh protected-environment approval
on reruns.

## Dry run

Use dry-run mode before creating the tag. It performs the four native builds,
archive packaging, checksum assembly, version smoke tests, and the root
multi-platform Docker build. It does not publish an image, create a GitHub
release, or move a release channel.

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

The workflow run revision and `commit_sha` must be identical. If `main` moves
between resolving `sha` and dispatching the workflow, the run fails closed.
Resolve the new `origin/main` SHA and dispatch again.

Inspect the run and download the `executor-release-artifacts` workflow artifact
if desired. Dry runs are safe for forks because all publishing steps are
skipped.

## Publish

After a successful dry run, create the tag at the same commit and push only
that tag:

```sh
git tag -a "$tag" "$sha" -m "Release $tag"
git push origin "refs/tags/$tag"

test "$(git rev-parse "$tag^{commit}")" = "$sha"
test "$(git ls-remote origin "refs/tags/$tag^{}" | cut -f1)" = "$sha" || \
  test "$(git ls-remote origin "refs/tags/$tag" | cut -f1)" = "$sha"

gh workflow run release.yml --ref main \
  -f mode=publish \
  -f tag="$tag" \
  -f commit_sha="$sha"
```

Publish mode must be dispatched from `main`. On the first attempt, `main`, the
workflow definition, workflow source revision, checked-out source, input
commit, and release tag must all resolve to the same commit. A later attempt of
that same run may continue after `main` advances, but the original commit must
remain an ancestor of `main` and the remote tag must still resolve to it. Do
not dispatch a new run with the older SHA. Rerun the complete original run so
GitHub preserves its workflow run ID, source SHA, protected authorization, and
every release check:

```sh
run_id=<failed-run-database-id>
gh run rerun "$run_id"
gh run watch "$run_id" --exit-status
```

Publish mode performs these gated stages:

1. Verify the exact protected-environment policy, immutable tag ruleset,
   workflow revision, Cargo version, full commit SHA, `main` ancestry, and
   remote tag are bound to one commit.
2. Build the Svelte payload once, then build and smoke-test four native
   archives against that identical payload with their preserved installer
   names. Linux binaries use a digest-pinned Ubuntu 22.04 build image and
   checksummed Rust 1.96 toolchain archives. Both macOS binaries declare a
   macOS 14.0 minimum, which the workflow verifies from their Mach-O metadata.
   Release compilation selects Xcode 16.4 build 16F6, macOS SDK 15.5, Apple
   clang 17.0.0 (clang-1700.0.13.5), and ld 1167.5 by exact path and version.
   The macOS 14 compatibility-floor service tests select Xcode 15.4 build
   15F31d, macOS SDK 14.5, Apple clang 15.0.0 (clang-1500.3.9.4), and ld
   1053.12. The ARM64 archive is booted on macOS 14, while the x86-64 archive
   is booted on the available standard Intel macOS 15 runner.
3. Package all four raw binaries in one digest-pinned Ubuntu snapshot with one
   fixed Python and zlib implementation. Build the archives twice and require
   byte-identical archives and sidecars before assembling `SHA256SUMS`.
4. Extract the two Linux release archives into the root `Dockerfile`'s
   `runtime-prebuilt` target, push each architecture by digest, and assemble a
   run-scoped multi-platform staging manifest. The runtime base and apt
   snapshot are pinned, and image timestamps use the release commit time so a
   retry produces the same digest. Build orchestration and manifest creation
   use the exact Buildx v0.34.1 client and digest-pinned BuildKit v0.30.0 daemon.
5. Create the draft with an atomic `[executor-run:<run_id>]` title marker, then
   upload the complete exact asset set. `RELEASE-RUN.json` binds the repository,
   tag, commit, and workflow run ID. `RELEASE-IMAGE.json` additionally binds the
   exact assembled OCI image name and digest.
6. Boot both published architectures by exact assembled digest, then verify
   first boot, health, every byte of the canonical embedded web payload, and
   anonymous pull access.
7. Re-fetch the remote release tag and assign the immutable release, version,
   and commit image tags.
8. Recompute and byte-compare the run binding, image binding, and every release
   asset, then publish the draft GitHub release. Publication creates GitHub's
   automatic immutable release attestation. Require the release API to report
   the exact release as immutable, and retry bounded attestation verification
   until it succeeds.
9. Only after the GitHub release is public, move the mutable `latest` or
   `beta` channel to the verified image digest.

Stable versions move the Docker `latest` channel. Prerelease versions move the
`beta` channel. The image is `ghcr.io/<repository-owner>/executor` and receives
immutable `vX.Y.Z`, `X.Y.Z`, and `sha-<commit>` tags plus the channel tag.

The workflow may reuse only a release whose title contains the exact current
workflow run ID. If release creation succeeded before its binding asset upload,
that atomic title marker lets the same run recover the partial draft. Every
same-run draft retry uploads the complete asset list with clobber semantics,
then downloads and byte-compares the final exact set. An already-published
immutable release is compare-only and must contain a byte-identical
`RELEASE-RUN.json`, `RELEASE-IMAGE.json`, and complete rebuilt bundle. A new run
refuses to reuse either release state. Before the workflow
assigns any immutable release, version, or commit image tag, it verifies that
an existing tag already has the expected digest or fails closed. Only `latest`
or `beta` may move to another digest, and neither moves until the GitHub release
is public. The remote `v*` tag is force-refetched and compared with the validated
commit immediately before draft-release mutation and again immediately before
promotion. All native release runs share one
serialized concurrency group. Promotion reads the current channel manifest's
version annotation and refuses to move a channel to an older SemVer. A retry at
the same version succeeds only when the channel already has the exact assembled
digest. Published GitHub release history is checked too, so removing a channel
tag cannot bypass the version floor. A channel without a valid version
annotation fails closed.

## Release archives

The primary GitHub release contains:

- `executor-x86_64-unknown-linux-gnu.tar.gz`
- `executor-aarch64-unknown-linux-gnu.tar.gz`
- `executor-x86_64-apple-darwin.tar.gz`
- `executor-aarch64-apple-darwin.tar.gz`
- one `.sha256` sidecar for each archive
- `RELEASE-RUN.json`, binding the release to its repository, tag, commit, and
  workflow run ID
- `RELEASE-IMAGE.json`, binding that same source to the exact OCI image and
  digest
- `BUILD-TOOLCHAINS.txt`, recording the asserted build and packaging toolchains
- `SHA256SUMS`

Each archive contains `executor`, `LICENSE`, `THIRD_PARTY_LICENSES.html`, and
`THIRD_PARTY_JAVASCRIPT_LICENSES.json`.

After downloading an archive, verify both GitHub's release attestation and the
specific local asset before checking the checksum manifest:

```sh
gh release verify "$tag" --repo davis7dotsh/executor-fork-testing
gh release verify-asset "$tag" "executor-${target}.tar.gz" \
  --repo davis7dotsh/executor-fork-testing
sha256sum --check "executor-${target}.tar.gz.sha256"
```

The release installer fixture exercises archive verification, serialized
concurrent install and uninstall, stale-lock recovery with PID-reuse defense,
live-owner identity lookup failure, hostile and swapped install-path ancestors,
durability ordering, interrupted rollback, resumable partial uninstall,
Python-free installation, and locked cross-root PATH updates. Its injected
durability log must show owned-file changes before manifest publication or
deletion, and manifest changes before recovery retirement.

The macOS command-line archives are not Developer ID signed or notarized. The
supported path is the checksum-verifying curl installer, or a `gh` download
followed by the attestation and checksum verification above. GitHub records the
attestation automatically when the immutable release is published.
Browser-downloaded
quarantined binaries and app-style Gatekeeper distribution are not release
claims until a signing identity and notarization workflow are configured. Both
macOS architectures require macOS 14 Sonoma or newer.

## Legacy desktop compatibility

The desktop publishing workflow is retired. Historical tags predate the
`legacy/desktop` move and cannot be built honestly with current-tree paths. The
archived source remains available for local archaeology, but no release
workflow claims to produce supported desktop artifacts.
