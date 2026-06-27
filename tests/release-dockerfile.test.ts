import { describe, expect, it } from "@effect/vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const dockerfile = readFileSync(resolve(repoRoot, "Dockerfile"), "utf8");
const nativeDockerfile = readFileSync(resolve(repoRoot, "Dockerfile.release-native"), "utf8");
const packageDockerfile = readFileSync(resolve(repoRoot, "Dockerfile.release-package"), "utf8");
const dockerignore = readFileSync(resolve(repoRoot, "Dockerfile.dockerignore"), "utf8");
const serviceSource = readFileSync(resolve(repoRoot, "src/service.rs"), "utf8");
const release = readFileSync(resolve(repoRoot, ".github/workflows/release.yml"), "utf8");
const compose = readFileSync(resolve(repoRoot, "compose.yaml"), "utf8");
const dockerDocs = readFileSync(resolve(repoRoot, "docs/docker.md"), "utf8");
const installDocs = readFileSync(resolve(repoRoot, "docs/install.md"), "utf8");

const workflowJob = (name: string, nextName: string) =>
  release.slice(release.indexOf(`  ${name}:`), release.indexOf(`  ${nextName}:`));

describe("native release artifact reuse", () => {
  it("builds the web payload once and downloads it into every native leg", () => {
    expect(release.match(/bun run --cwd web build/gu)).toHaveLength(1);

    const web = workflowJob("web", "notices");
    const native = workflowJob("build-native", "package-native");
    expect(web).toContain("name: executor-web-build");
    expect(web).toContain("path: web/build/");
    expect(native).toContain("name: executor-web-build");
    expect(native).toContain("path: web/build");
    expect(native).not.toContain("bun run --cwd web build");
    expect(native).not.toContain("oven-sh/setup-bun");
  });

  it("boots every packaged native archive against the canonical web payload", () => {
    const smoke = workflowJob("smoke-native", "checksums");

    for (const target of [
      "aarch64-apple-darwin",
      "aarch64-unknown-linux-gnu",
      "x86_64-apple-darwin",
      "x86_64-unknown-linux-gnu",
    ]) {
      expect(smoke).toContain(`target: ${target}`);
    }
    expect(smoke).toContain("name: executor-release-archives");
    expect(smoke).toContain("name: executor-web-build");
    expect(smoke).toContain("shasum -a 256 --check");
    expect(smoke).toContain("Complete first-boot setup at:");
    expect(smoke).toContain("scripts/smoke-release-server.sh");
    expect(release).toContain("checksums:\n    name: Assemble checksum manifest\n    needs:");
    expect(release).toContain("      - smoke-native");
  });

  it("keeps the default Docker target self-contained and adds a prebuilt release target", () => {
    const stageNames = [...dockerfile.matchAll(/^FROM .+ AS (\S+)$/gmu)].map((match) => match[1]);
    expect(stageNames).toEqual([
      "web-builder",
      "rust-builder",
      "runtime-base",
      "runtime-prebuilt",
      "runtime",
    ]);

    const prebuilt = dockerfile.slice(
      dockerfile.indexOf("FROM runtime-base AS runtime-prebuilt"),
      dockerfile.indexOf("FROM runtime-base AS runtime\n"),
    );
    const runtime = dockerfile.slice(dockerfile.indexOf("FROM runtime-base AS runtime\n"));
    expect(prebuilt).toContain("COPY --from=prebuilt-executor");
    expect(prebuilt).not.toContain("cargo build");
    expect(prebuilt).not.toContain("bun run");
    expect(runtime).toContain("COPY --from=rust-builder /usr/local/bin/executor");
    expect(dockerfile).toContain(
      "FROM oven/bun:1.3.11@sha256:0733e50325078969732ebe3b15ce4c4be5082f18c4ac1a0f0ca4839c2e4e42a7 AS web-builder",
    );
    expect(dockerfile).toContain(
      "FROM rust:1.96-bookworm@sha256:6d19f49541d185805745b8baa781b1fd482118c81a3154510ee18dcce985d005 AS rust-builder",
    );
  });

  it("enables cargo-about's CLI binary everywhere it is installed", () => {
    const installs = [dockerfile, release].flatMap(
      (source) => source.match(/cargo install cargo-about[^\n]*/gu) ?? [],
    );

    expect(installs.length).toBeGreaterThan(0);
    for (const install of installs) {
      expect(install).toContain("--features cli");
    }
  });

  it("builds each release image from its matching Linux archive and assembles a manifest", () => {
    const containers = release.slice(release.indexOf("  build-container-dry-run:"));
    expect(containers).toContain("name: executor-release-artifacts");
    expect(containers).toContain("target: runtime-prebuilt");
    expect(containers).toContain("prebuilt-executor=${{ runner.temp }}/prebuilt-executor");
    expect(containers).toContain("platform: linux/amd64");
    expect(containers).toContain("platform: linux/arm64");
    expect(containers).toContain("push-by-digest=true");
    expect(containers).toContain('--tag "$staging"');
    expect(containers).not.toContain("cargo build");
    expect(containers).not.toContain("bun run --cwd web build");
  });

  it("smokes the release-only image path before promotion", () => {
    const dryRun = workflowJob("build-container-dry-run", "publish-container-arch");
    const published = workflowJob("smoke-container", "promote");
    const promote = release.slice(release.indexOf("  promote:"));

    expect(dryRun).toContain("load: true");
    expect(dryRun).toContain("scripts/smoke-release-container.sh");
    expect(published).toContain('reference="$IMAGE@$IMAGE_DIGEST"');
    expect(published).toContain('docker pull "$reference"');
    expect(published).toContain("scripts/smoke-release-container.sh");
    expect(published).toContain("name: executor-web-build");
    expect(published).toContain("name: Verify exact digest is anonymously pullable");
    expect(published).toContain('DOCKER_CONFIG="$anonymous_config" docker pull');
    expect(promote).toContain("      - smoke-container");
  });

  it("documents and configures a published prebuilt Compose start flow", () => {
    expect(compose).toContain('image: "${EXECUTOR_IMAGE:-executor:local}"');
    expect(dockerDocs).toContain("export EXECUTOR_IMAGE=ghcr.io/davis7dotsh/executor:v0.1.0");
    expect(dockerDocs).toContain("docker compose up --detach --no-build executor");
    expect(dockerDocs).toContain("curl --fail --silent --show-error");
    expect(installDocs).toContain("shasum -a 256 --check SHA256SUMS");
  });

  it("pins runtime inputs and normalizes image timestamps for retry-safe digests", () => {
    const containers = release.slice(release.indexOf("  build-container-dry-run:"));
    const native = workflowJob("build-native", "smoke-native");
    const promote = release.slice(release.indexOf("  promote:"));

    expect(dockerfile).toContain(
      "FROM debian:bookworm-20260623-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime-base",
    );
    expect(dockerfile).toContain(
      "# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
    );
    expect(dockerfile).toContain("ARG DEBIAN_SNAPSHOT=20260623T000000Z");
    expect(dockerfile).toContain("snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}");
    expect(release).toContain('source_date_epoch="$(git show -s --format=%ct HEAD)"');
    expect(release).toContain(
      "BUILDKIT_IMAGE: moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f",
    );
    expect(release).toContain("BUILDX_VERSION: v0.34.1");
    expect(release.match(/uses: docker\/setup-buildx-action@/gu)).toHaveLength(
      release.match(/driver-opts: image=\$\{\{ env\.BUILDKIT_IMAGE \}\}/gu)?.length ?? 0,
    );
    expect(release.match(/uses: docker\/setup-buildx-action@/gu)).toHaveLength(
      release.match(/version: \$\{\{ env\.BUILDX_VERSION \}\}/gu)?.length ?? 0,
    );
    expect(nativeDockerfile).toContain(
      "FROM ubuntu:22.04@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d AS builder",
    );
    expect(nativeDockerfile).toContain("ARG UBUNTU_SNAPSHOT=20260623T000000Z");
    expect(nativeDockerfile).toContain(
      "checksum=c295047583a56238ea06b43f849f4b877fa12bfd4c7103f8d9a74c94c9c4e108",
    );
    expect(nativeDockerfile).toContain(
      "checksum=371eadcca97062219cbd8593628eb5d2802bc370515d085fedce1b56b2baed57",
    );
    expect(native).toContain("SOURCE_DATE_EPOCH: ${{ needs.validate.outputs.source_date_epoch }}");
    expect(native).toContain("file: Dockerfile.release-native");
    expect(native).toContain("driver-opts: image=${{ env.BUILDKIT_IMAGE }}");
    expect(native).toContain("Verify Linux glibc 2.35 compatibility ceiling");
    expect(native).not.toContain("python3 scripts/package-release-archive.py");
    expect(native).not.toContain('tar -C "$stage" -czf');
    expect(release).toContain("name: Package native archives in pinned compressor environment");
    expect(release).toContain("file: Dockerfile.release-package");
    expect(release).toContain("name: Repeat pinned archive build");
    expect(release).toContain("REPRODUCIBILITY_RUN=first");
    expect(release).toContain("REPRODUCIBILITY_RUN=second");
    expect(release).toContain('cmp "$first/$archive" "$second/$archive"');
    expect(packageDockerfile).toContain(
      "# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
    );
    expect(packageDockerfile).toContain(
      "FROM ubuntu:22.04@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d AS packager",
    );
    expect(packageDockerfile).toContain("ARG UBUNTU_SNAPSHOT=20260623T000000Z");
    expect(packageDockerfile).toContain("python3-minimal");
    expect(packageDockerfile).toContain("python3 /usr/local/bin/package-release-archive.py");
    expect(packageDockerfile).toContain("> /output/BUILD-TOOLCHAINS.txt");
    expect(release).toContain('cmp "$first/BUILD-TOOLCHAINS.txt"');
    expect(release).toContain("sha256sum BUILD-TOOLCHAINS.txt >> SHA256SUMS");
    expect(release).not.toContain("actions/attest-build-provenance@");
    expect(containers.match(/SOURCE_DATE_EPOCH:/gu)).toHaveLength(2);
    expect(containers.match(/provenance: false/gu)).toHaveLength(2);
    expect(containers.match(/sbom: false/gu)).toHaveLength(2);
    expect(containers).toContain("push=true,rewrite-timestamp=true");
    expect(dockerfile).toContain(
      "FROM debian:bookworm-20260623-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime-base\n\nARG SOURCE_DATE_EPOCH",
    );
    expect(dockerfile).toContain('date --utc --date="@${SOURCE_DATE_EPOCH:-0}"');
    expect(promote).toContain("name: Verify published GitHub release is immutable");
    expect(promote).toContain('gh release verify "$RELEASE_TAG"');
  });

  it("stages every embedded service asset in both Rust Docker build contexts", () => {
    const embeddedPaths = [...serviceSource.matchAll(/include_bytes!\("\.\.\/([^"\n]+)"\)/gu)].map(
      (match) => match[1],
    );

    expect(embeddedPaths.length).toBeGreaterThan(0);
    for (const path of embeddedPaths) {
      expect(dockerfile).toContain(`COPY ${path} ./${path}`);
      expect(nativeDockerfile).toContain(`COPY ${path} ./${path}`);
      expect(dockerignore).toContain(`!${path}`);
    }
  });

  it("preflights immutable version tags and allows only the channel tag to move", () => {
    const promote = release.slice(release.indexOf("  promote:"));
    const preflight = promote.indexOf(
      'immutable_tags=("$RELEASE_TAG" "$VERSION" "sha-$RELEASE_SHA")',
    );
    const assignment = promote.indexOf('for tag in "${missing_tags[@]}"');
    const publish = promote.indexOf("name: Publish GitHub release");
    const verifyImmutable = promote.indexOf("name: Verify published GitHub release is immutable");
    const verifyAttestation = promote.indexOf('gh release verify "$RELEASE_TAG"');
    const channelStep = promote.indexOf(
      "name: Move mutable channel after GitHub release publication",
    );
    const channelMove = promote.indexOf('--tag "$channel_reference"');

    expect(promote).toContain('existing="$(inspect_digest "$reference")"');
    expect(promote).toContain('if [ "$existing" != "$IMAGE_DIGEST" ]');
    expect(promote).toContain("already points to the expected digest");
    expect(release).toContain('staging="$IMAGE:staging-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"');
    expect(preflight).toBeGreaterThan(-1);
    expect(assignment).toBeGreaterThan(preflight);
    expect(publish).toBeGreaterThan(assignment);
    expect(verifyImmutable).toBeGreaterThan(publish);
    expect(verifyAttestation).toBeGreaterThan(verifyImmutable);
    expect(channelStep).toBeGreaterThan(verifyAttestation);
    expect(channelMove).toBeGreaterThan(channelStep);
  });
});
