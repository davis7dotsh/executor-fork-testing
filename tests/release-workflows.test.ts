import { describe, expect, it } from "@effect/vitest";
import { Schema } from "effect";
import { spawnSync } from "node:child_process";
import { existsSync, globSync, readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

import { validateReleaseTag, validateReleaseVersion } from "../scripts/validate-release-ref";

const repoRoot = resolve(import.meta.dirname, "..");
const workflowsRoot = resolve(repoRoot, ".github/workflows");
const workflow = (name: string) => readFileSync(resolve(workflowsRoot, name), "utf8");
const repositoryFile = (name: string) => readFileSync(resolve(repoRoot, name), "utf8");
const privatePackageManifest = Schema.fromJsonString(
  Schema.Struct({ private: Schema.Literal(true) }),
);
const decodePrivatePackageManifest = Schema.decodeUnknownSync(privatePackageManifest);
const workspaceRootManifest = Schema.fromJsonString(
  Schema.Struct({
    private: Schema.Literal(true),
    workspaces: Schema.Array(Schema.String),
  }),
);
const decodeWorkspaceRootManifest = Schema.decodeUnknownSync(workspaceRootManifest);

const ownedWorkflows = readdirSync(workflowsRoot)
  .filter((name) => /\.ya?ml$/u.test(name))
  .sort();

const workflowJob = (contents: string, name: string) => {
  const marker = `\n  ${name}:\n`;
  const start = contents.indexOf(marker);
  const bodyStart = start + marker.length;
  const remaining = contents.slice(bodyStart);
  const nextJob = remaining.search(/\n  [a-z][a-z0-9-]*:\n/u);
  return contents.slice(start, nextJob === -1 ? contents.length : bodyStart + nextJob);
};

describe("release workflow hardening", () => {
  it("accepts only semver release versions and v-prefixed semver tags", () => {
    expect(validateReleaseVersion("1.2.3")).toBe("1.2.3");
    expect(validateReleaseVersion("1.2.3-beta.4")).toBe("1.2.3-beta.4");
    expect(validateReleaseTag("v1.2.3")).toBe("v1.2.3");
    expect(validateReleaseTag("v1.2.3-beta.4+build.5")).toBe("v1.2.3-beta.4+build.5");

    expect(() => validateReleaseVersion("v1.2.3")).toThrow();
    expect(() => validateReleaseVersion("1.2")).toThrow();
    expect(() => validateReleaseTag("1.2.3")).toThrow();
    expect(() => validateReleaseTag("v1.2.3; echo unsafe")).toThrow();
    expect(() => validateReleaseTag("v01.2.3")).toThrow();
  });

  it("has one explicit native product release entrypoint", () => {
    const release = workflow("release.yml");
    const triggerBlock = release.slice(release.indexOf("on:"), release.indexOf("\npermissions:"));

    expect(triggerBlock).toContain("workflow_dispatch:");
    expect(triggerBlock).toContain("dry-run");
    expect(triggerBlock).toContain("publish");
    expect(triggerBlock).toContain("commit_sha:");
    expect(triggerBlock).toContain("tag:");
    expect(triggerBlock).not.toContain("push:");

    expect(existsSync(resolve(workflowsRoot, "build-release-artifacts.yml"))).toBe(false);
    expect(existsSync(resolve(workflowsRoot, "publish-selfhost-docker.yml"))).toBe(false);
    expect(existsSync(resolve(workflowsRoot, "publish-executor-package.yml"))).toBe(false);
    expect(existsSync(resolve(workflowsRoot, "pkg-pr-new.yml"))).toBe(false);
  });

  it("runs the static release and installer contracts in CI", () => {
    const ci = workflow("ci.yml");

    expect(ci).toContain("run: bun run test:release:static");
    expect(ci).toContain("run: bun run test:release:installer");
    expect(ci).toContain("run: bun run test:release:systemd");
    expect(ci).toContain("run: bun run test:release:shell");
  });

  it("serializes installer mutations and preserves crash-durability ordering", () => {
    const installer = repositoryFile("scripts/install.sh");
    const beginTransaction = installer.slice(
      installer.indexOf("begin_install_transaction()"),
      installer.indexOf("recover_install_transaction()"),
    );
    const rollback = installer.slice(
      installer.indexOf("recover_install_transaction()"),
      installer.indexOf("commit_install_transaction()"),
    );
    const commit = installer.slice(
      installer.indexOf("commit_install_transaction()"),
      installer.indexOf("remove_owned_file()"),
    );
    const uninstall = installer.slice(
      installer.indexOf("uninstall_executor()"),
      installer.indexOf("\nprepare_install_root\n"),
    );
    const entrypoint = installer.slice(
      installer.indexOf("\nprepare_install_root\n"),
      installer.indexOf('\ncase "$REPOSITORY" in'),
    );

    const beginOrder = [
      'durability_barrier "recovery-tree-durable:$transaction_label"',
      'mv "$temporary" "$recovery"',
      'durability_barrier "recovery-durable:$transaction_label"',
    ];
    const rollbackOrder = [
      'durability_barrier "rollback-managed-durable:$name"',
      'durability_barrier "rollback-manifest-durable"',
      "retire_install_recovery rollback",
    ];
    const commitOrder = [
      '"managed-file-durable:$name"',
      '"manifest-durable:$transaction_label"',
      'retire_install_recovery "$transaction_label"',
    ];
    const uninstallOrder = [
      'remove_owned_file "$name" "$hash"',
      'rm -f -- "$manifest"',
      'durability_barrier "uninstall-manifest-durable"',
    ];

    for (const [section, fragments] of [
      [beginTransaction, beginOrder],
      [rollback, rollbackOrder],
      [commit, commitOrder],
      [uninstall, uninstallOrder],
    ] as const) {
      for (let index = 1; index < fragments.length; index += 1) {
        expect(section.indexOf(fragments[index - 1])).toBeGreaterThanOrEqual(0);
        expect(section.indexOf(fragments[index])).toBeGreaterThan(
          section.indexOf(fragments[index - 1]),
        );
      }
    }

    expect(entrypoint).toContain(
      "prepare_install_root\ntrap installer_exit_cleanup EXIT\ntest_pause_if_requested after-install-root\nacquire_install_lock\nrecover_install_transaction",
    );
    expect(installer).toContain("validate_install_path_component /");
    expect(installer).toContain("install_root_parent_identity");
    expect(installer).toContain("could not verify live install-lock owner pid");
    expect(installer).toContain("executor-path-edit-lock-v1");
    expect(installer).toContain("acquire_path_edit_lock");
    expect(installer).toContain("command -v sync");
    expect(installer).not.toContain("python3");
  });

  it("binds the release tag to Cargo.toml and an exact commit", () => {
    const release = workflow("release.yml");
    const cargoManifest = repositoryFile("Cargo.toml");
    const releasing = repositoryFile("RELEASING.md");

    expect(release).toContain("version=\"$(python3 - <<'PY'");
    expect(release).toContain('if [ "$RELEASE_TAG" != "v$version" ]');
    expect(release).toContain('[[ ! "$INPUT_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]]');
    expect(release).toContain('if [ "$WORKFLOW_SHA" != "$INPUT_COMMIT_SHA" ]');
    expect(release).toContain("RUN_ATTEMPT: ${{ github.run_attempt }}");
    expect(release).toContain('if [ "$RUN_ATTEMPT" = 1 ] \\');
    expect(release).toContain("The first release attempt must use the current origin/main commit");
    expect(release).toContain('actual_sha="$(git rev-parse HEAD)"');
    expect(release).toContain('git rev-parse "$RELEASE_TAG^{commit}"');
    expect(release).toContain('if [ "$RELEASE_MODE" = "publish" ] \\');
    expect(release).toContain('[ "$WORKFLOW_REF" != refs/heads/main ]');
    expect(release).toContain('echo "commit_sha=$actual_sha"');
    expect(release).toContain("ref: ${{ needs.validate.outputs.commit_sha }}");
    expect(release.match(/inputs\.commit_sha/gu)).toHaveLength(2);
    expect(release).toContain("is not on origin/main");
    expect(release).toContain('[[ "$version" == *+* ]]');
    expect(release).not.toContain("legacy/cli/package.json");
    expect(cargoManifest).toContain('rust-version = "1.96"');
    expect(releasing).toContain("gh workflow run release.yml --ref main");
    expect(releasing).toContain('gh run rerun "$run_id"');
    expect(releasing).not.toContain('gh run rerun "$run_id" --failed');
    expect(releasing).toContain("workflow source revision");
  });

  it("gates every native publisher with the exact reviewed environment and token", () => {
    const release = workflow("release.yml");
    const validate = workflowJob(release, "validate");
    const releasing = repositoryFile("RELEASING.md");

    expect(validate).toContain("Verify exact native release environment policy");
    expect(validate).toContain('"repos/$EXECUTOR_REPOSITORY/environments/native-release"');
    expect(validate).toContain(
      '"repos/$EXECUTOR_REPOSITORY/environments/native-release/deployment-branch-policies?per_page=100"',
    );
    expect(validate).toContain('rule_types != ["branch_policy", "required_reviewers"]');
    expect(validate).toContain('environment.get("can_admins_bypass") is not False');
    expect(validate).toContain('identity.get("login") != "bmdavis419"');
    expect(validate).toContain('identity.get("id") != 45952064');
    expect(validate).toContain('branch_policies[0].get("name") != "main"');
    expect(validate).toContain('branch_policies[0].get("type") != "branch"');

    const protectedJobs = [
      "authorize-publish",
      "stage-release",
      "publish-container-arch",
      "assemble-container",
      "smoke-container",
      "promote",
    ];
    for (const name of protectedJobs) {
      const job = workflowJob(release, name);
      expect(job, name).toContain("if: inputs.mode == 'publish'");
      expect(job, name).toContain("environment: native-release");
      expect(job, name).not.toContain("contents: write");
      expect(job, name).not.toContain("packages: write");
      expect(job, name).not.toContain("attestations: write");
      expect(job, name).not.toContain("${{ github.token }}");
    }

    for (const name of [
      "stage-release",
      "publish-container-arch",
      "assemble-container",
      "smoke-container",
      "promote",
    ]) {
      expect(workflowJob(release, name), name).toContain("- authorize-publish");
    }

    const authorization = workflowJob(release, "authorize-publish");
    expect(authorization).toContain("GH_TOKEN: ${{ secrets.NATIVE_RELEASE_TOKEN }}");
    expect(authorization).toContain('expected_scopes = {"public_repo", "write:packages"}');
    expect(authorization).toContain("if actual_scopes != expected_scopes:");
    expect(authorization).toContain(
      "NATIVE_RELEASE_TOKEN must have exactly public_repo and write:packages scopes",
    );
    expect(authorization).not.toContain("for required_scope in");
    expect(authorization).toContain('"repos/$EXECUTOR_REPOSITORY/immutable-releases"');
    expect(authorization).toContain("docker login ghcr.io");
    expect(authorization.indexOf("Verify exact immutable release tag ruleset")).toBeGreaterThan(
      authorization.indexOf("Require the environment-scoped release token and capabilities"),
    );
    expect(release).not.toContain("actions/attest-build-provenance@");
    expect(release).not.toContain("id-token: write");
    expect(release).not.toContain("attestations: write");
    expect(releasing).toContain("reviewer the GitHub user `bmdavis419`");
    expect(releasing).toContain("classic personal access token owned by `bmdavis419`");
    expect(releasing).toContain("exact scopes `public_repo` and `write:packages`, and no others");
    expect(releasing).toContain(
      "https://github.com/settings/tokens/new?scopes=public_repo,write:packages",
    );
    expect(releasing).toContain("`GITHUB_TOKEN` remains read-only");
  });

  it("requires immutable v tags and rechecks the tag at both mutation boundaries", () => {
    const release = workflow("release.yml");
    const validate = workflowJob(release, "validate");
    const authorization = workflowJob(release, "authorize-publish");
    const stage = workflowJob(release, "stage-release");
    const promote = workflowJob(release, "promote");
    const releasing = repositoryFile("RELEASING.md");

    expect(validate).not.toContain("bypass_actors");
    expect(validate).not.toContain("release-tag-rulesets");
    expect(authorization).toContain("Verify exact immutable release tag ruleset");
    expect(authorization).toContain('ref_name.get("include") == ["refs/tags/v*"]');
    expect(authorization).toContain('ruleset.get("bypass_actors") == []');
    expect(authorization).toContain('rule_types == ["deletion", "update"]');
    expect(authorization).toContain('== {"update_allows_fetch_and_merge": False}');

    const stageFetch = stage.indexOf("git fetch --force --no-tags origin");
    const stageMutation = stage.indexOf('gh release view "$RELEASE_TAG"');
    expect(stageFetch).toBeGreaterThanOrEqual(0);
    expect(stageMutation).toBeGreaterThan(stageFetch);
    expect(stage).toContain('if [ "$tag_sha" != "$RELEASE_SHA" ]');

    const promotionCheck = promote.indexOf("Revalidate remote release tag before promotion");
    const firstPromotionMutation = promote.indexOf(
      "Assign immutable tags and verify channel eligibility",
    );
    expect(promotionCheck).toBeGreaterThanOrEqual(0);
    expect(firstPromotionMutation).toBeGreaterThan(promotionCheck);
    expect(promote).toContain('if [ "$tag_sha" != "$RELEASE_SHA" ]');
    expect(release.match(/git fetch --force --no-tags origin/gu)).toHaveLength(2);
    expect(releasing).toContain("active tag ruleset for exactly `refs/tags/v*`");
  });

  it("uses the validated source and checksums throughout the release graph", () => {
    const release = workflow("release.yml");
    const stage = workflowJob(release, "stage-release");
    const checkoutCount = release.match(/uses: actions\/checkout@/gu)?.length ?? 0;
    const workflowCheckoutCount = release.match(/ref: \$\{\{ github\.sha \}\}/gu)?.length ?? 0;
    const validatedCheckoutCount =
      release.match(/ref: \$\{\{ needs\.validate\.outputs\.commit_sha \}\}/gu)?.length ?? 0;

    expect(workflowCheckoutCount).toBe(1);
    expect(validatedCheckoutCount).toBe(checkoutCount - 1);
    expect(release).not.toContain("ref: ${{ inputs.commit_sha }}");
    expect(
      release.match(
        /org\.opencontainers\.image\.revision=\$\{\{ needs\.validate\.outputs\.commit_sha \}\}/gu,
      ),
    ).toHaveLength(2);
    expect(release).not.toContain("org.opencontainers.image.revision=${{ inputs.commit_sha }}");
    expect(stage).toContain("RELEASE_SHA: ${{ needs.validate.outputs.commit_sha }}");
    expect(stage).toContain('--target "$RELEASE_SHA"');
    expect(stage).toContain("release-artifacts/SHA256SUMS");
    expect(release).toContain("sha256sum --check SHA256SUMS");
    expect(release).not.toContain("subject-path:");
    expect(release).not.toContain("subject-digest:");
  });

  it("publishes GitHub before moving the mutable container channel", () => {
    const promote = workflowJob(workflow("release.yml"), "promote");
    const immutableStep = promote.slice(
      promote.indexOf("Assign immutable tags and verify channel eligibility"),
      promote.indexOf("Publish GitHub release"),
    );
    const verifyBindings = promote.indexOf(
      "Verify release ownership and image binding before publication",
    );
    const publish = promote.indexOf("Publish GitHub release");
    const verifyImmutable = promote.indexOf("Verify published GitHub release is immutable");
    const moveChannel = promote.indexOf("Move mutable channel after GitHub release publication");

    expect(verifyBindings).toBeGreaterThanOrEqual(0);
    expect(publish).toBeGreaterThan(verifyBindings);
    expect(publish).toBeGreaterThanOrEqual(0);
    expect(verifyImmutable).toBeGreaterThan(publish);
    expect(moveChannel).toBeGreaterThan(verifyImmutable);
    expect(immutableStep).not.toContain('--tag "$IMAGE:$CHANNEL"');
    expect(promote.slice(moveChannel)).toContain('--tag "$channel_reference"');
    expect(promote.slice(moveChannel)).toContain("--json isDraft");
    expect(promote.slice(verifyImmutable, moveChannel)).toContain(
      'release.get("immutable") is not True',
    );
    expect(promote.slice(verifyImmutable, moveChannel)).toContain(
      'gh release verify "$RELEASE_TAG"',
    );
    expect(promote.slice(verifyImmutable, moveChannel)).toContain("for attempt in {1..24}");
    expect(promote.slice(publish, verifyImmutable)).not.toContain('--tag "$channel_reference"');
    expect(promote.slice(verifyImmutable, moveChannel)).not.toContain('--tag "$channel_reference"');
  });

  it("binds retry convergence and release assets to the original workflow run", () => {
    const release = workflow("release.yml");
    const validate = workflowJob(release, "validate");
    const publishContainer = workflowJob(release, "publish-container-arch");
    const stage = workflowJob(release, "stage-release");
    const promote = workflowJob(release, "promote");
    const releasing = repositoryFile("RELEASING.md");

    expect(validate).toContain('if [ "$RUN_ATTEMPT" = 1 ]');
    expect(validate).toContain("RUN_ID: ${{ github.run_id }}");
    expect(validate).toContain('release_title="$RELEASE_TAG [executor-run:$RUN_ID]"');
    expect(validate).toContain('release.get("immutable") is not True');
    expect(validate).toContain('select(.name == "RELEASE-RUN.json")');
    expect(validate).toContain(
      "Same-run draft is missing RELEASE-RUN.json; staging will repair it",
    );
    expect(validate).toContain("Same-run retry will reuse immutable published release");

    expect(stage).toContain("- assemble-container");
    expect(stage).toContain("RELEASE-RUN.json");
    expect(stage).toContain("RELEASE-IMAGE.json");
    expect(stage).toContain('"run_id": sys.argv[6]');
    expect(stage).toContain('"digest": sys.argv[8]');
    expect(stage).toContain('"image": sys.argv[7]');
    expect(stage).toContain('--title "$release_title"');
    expect(stage).not.toContain('--title "$RELEASE_TAG"');
    expect(stage).toContain("Recovering same-run draft created before its binding asset uploaded");
    expect(stage).toContain('if [ "$published_release" = false ]; then');
    expect(stage).toContain('gh release upload "$RELEASE_TAG"');
    expect(stage).toContain("--clobber");
    expect(stage).toContain('cmp "$run_binding" "$ownership/RELEASE-RUN.json"');
    expect(stage).toContain('cmp "$asset" "$verified_assets/$(basename "$asset")"');
    expect(publishContainer).toContain("name: executor-container-digest-${{ matrix.artifact }}");
    expect(
      publishContainer.slice(publishContainer.indexOf("- name: Upload architecture digest")),
    ).toContain("overwrite: true");

    const validateTitle = validate.indexOf('actual_title="$(jq -r');
    const validateBinding = validate.indexOf("--pattern RELEASE-RUN.json");
    const stageTitle = stage.indexOf('actual_title="$(jq -r');
    const stageUpload = stage.indexOf('gh release upload "$RELEASE_TAG"');
    expect(validateBinding).toBeGreaterThan(validateTitle);
    expect(stageUpload).toBeGreaterThan(stageTitle);

    expect(promote).toContain('release.get("name") != sys.argv[4]');
    expect(promote).toContain('cmp "$asset" "$verified_assets/$(basename "$asset")"');
    expect(promote).toContain('release.get("name") != sys.argv[5]');
    expect(validate).toContain('release.get("immutable") is not True');
    expect(promote).toContain("GitHub release $RELEASE_TAG is already published");
    expect(releasing).toContain("exact current\nworkflow run ID");
    expect(releasing).toContain('gh run rerun "$run_id"');
    expect(releasing).not.toContain("--failed");
  });

  it("keeps the release and installer repository identity coherent", () => {
    const canonicalRepository = "davis7dotsh/executor-fork-testing";
    const installer = repositoryFile("scripts/install.sh");
    const installDocs = repositoryFile("docs/install.md");
    const hostedDocs = repositoryFile("apps/docs/self-hosting.mdx");
    const docsIndex = repositoryFile("apps/docs/index.mdx");
    const docsConfig = repositoryFile("apps/docs/docs.json");
    const legacyCloudflareDocs = repositoryFile("apps/docs/hosted/cloudflare.mdx");
    const marketingIndex = repositoryFile("apps/marketing/src/pages/index.astro");
    const marketingLegal = repositoryFile("apps/marketing/src/components/LegalLayout.astro");
    const marketingPrivacy = repositoryFile("apps/marketing/src/pages/privacy.astro");
    const marketingTerms = repositoryFile("apps/marketing/src/pages/terms.astro");
    const rootPackage = repositoryFile("package.json");
    const release = workflow("release.yml");

    expect(installer).toContain(`REPOSITORY="\${EXECUTOR_REPOSITORY:-${canonicalRepository}}"`);
    expect(installer).toContain("EXECUTOR_REPOSITORY     GitHub owner/repository");
    expect(installDocs).toContain(
      `raw.githubusercontent.com/${canonicalRepository}/main/scripts/install.sh`,
    );
    expect(hostedDocs).toContain(
      `raw.githubusercontent.com/${canonicalRepository}/main/scripts/install.sh`,
    );
    expect(installDocs).toContain("export EXECUTOR_REPOSITORY=owner/repository");
    expect(installDocs).toContain("bash -s -- --uninstall");
    expect(installDocs).toContain("It preserves all databases, master keys");
    expect(hostedDocs).toContain("export EXECUTOR_REPOSITORY=owner/repository");
    expect(docsIndex).toContain(`https://github.com/${canonicalRepository}`);
    expect(docsConfig).toContain(`https://github.com/${canonicalRepository}`);
    expect(legacyCloudflareDocs).toContain(`https://github.com/${canonicalRepository}`);
    for (const activeSurface of [
      docsIndex,
      docsConfig,
      legacyCloudflareDocs,
      marketingIndex,
      marketingLegal,
      marketingPrivacy,
      marketingTerms,
      rootPackage,
    ]) {
      expect(activeSurface).toContain(`github.com/${canonicalRepository}`);
      expect(activeSurface).not.toContain("github.com/RhysSullivan/executor");
    }
    expect(installDocs).toContain("not Developer ID signed or notarized");
    expect(release).toContain("EXECUTOR_REPOSITORY: ${{ github.repository }}");
    expect(release).toContain('--repo "$EXECUTOR_REPOSITORY"');
  });

  it("packages four native targets and promotes only after assets and Docker succeed", () => {
    const release = workflow("release.yml");

    for (const target of [
      "aarch64-apple-darwin",
      "aarch64-unknown-linux-gnu",
      "x86_64-apple-darwin",
      "x86_64-unknown-linux-gnu",
    ]) {
      expect(release).toContain(`executor-${target}.tar.gz`);
    }

    expect(release).toContain("SHA256SUMS");
    expect(release).not.toContain("actions/attest-build-provenance@");
    expect(release).toContain("file: Dockerfile");
    expect(release).toContain("platform: linux/amd64");
    expect(release).toContain("platform: linux/arm64");
    expect(release).toContain("target: runtime-prebuilt");
    const promote = workflowJob(release, "promote");
    expect(promote).toContain("- assemble-container");
    expect(promote).toContain("- authorize-publish");
    expect(promote).toContain("- smoke-container");
    expect(promote).toContain("- stage-release");
    expect(promote).toContain('args=(release edit "$RELEASE_TAG"');
  });

  it("serializes releases and rejects a v0.1 channel rollback after v0.2", () => {
    const release = workflow("release.yml");
    const rollback = spawnSync(
      "python3",
      [
        resolve(repoRoot, "scripts/check-release-channel-order.py"),
        "--channel",
        "latest",
        "--current",
        "0.2.0",
        "--candidate",
        "0.1.0",
      ],
      { encoding: "utf8" },
    );
    const historicalRollback = spawnSync(
      "python3",
      [
        resolve(repoRoot, "scripts/check-release-channel-order.py"),
        "--channel",
        "latest",
        "--history-file",
        "-",
        "--candidate",
        "0.1.0",
      ],
      {
        encoding: "utf8",
        input: JSON.stringify([[{ draft: false, tag_name: "v0.2.0" }]]),
      },
    );
    const betaUpgrade = spawnSync(
      "python3",
      [
        resolve(repoRoot, "scripts/check-release-channel-order.py"),
        "--channel",
        "beta",
        "--current",
        "1.0.0-beta.2",
        "--candidate",
        "1.0.0-beta.10",
      ],
      { encoding: "utf8" },
    );

    expect(release).toContain("group: native-release\n");
    expect(release).not.toContain("group: native-release-${{ inputs.tag }}");
    expect(release).toContain("index:org.opencontainers.image.version=$VERSION");
    expect(release).toContain("scripts/check-release-channel-order.py");
    expect(release).toContain('--history-file "$release_history"');
    expect(rollback.status).toBe(1);
    expect(rollback.stderr).toContain("would move latest backward from 0.2.0 to 0.1.0");
    expect(historicalRollback.status).toBe(1);
    expect(historicalRollback.stderr).toContain("would move latest backward from 0.2.0 to 0.1.0");
    expect(betaUpgrade.status).toBe(0);
    expect(betaUpgrade.stdout.trim()).toBe("newer");
  });

  it("verifies the version annotation on a synthetic raw release index", () => {
    const release = workflow("release.yml");
    const verifier = resolve(repoRoot, "scripts/verify-release-index.py");
    const index = {
      annotations: { "org.opencontainers.image.version": "0.2.0" },
      manifests: [
        { platform: { architecture: "amd64", os: "linux" } },
        { platform: { architecture: "arm64", os: "linux" } },
      ],
      schemaVersion: 2,
    };
    const valid = spawnSync("python3", [verifier, "--version", "0.2.0"], {
      encoding: "utf8",
      input: JSON.stringify(index),
    });
    const missingAnnotation = spawnSync("python3", [verifier, "--version", "0.2.0"], {
      encoding: "utf8",
      input: JSON.stringify({ ...index, annotations: {} }),
    });

    expect(release).toContain('--annotation "index:org.opencontainers.image.version=$VERSION"');
    expect(release).toContain("python3 scripts/verify-release-index.py");
    expect(valid.status).toBe(0);
    expect(valid.stdout.trim()).toBe("verified release index for 0.2.0");
    expect(missingAnnotation.status).toBe(1);
    expect(missingAnnotation.stderr).toContain("version annotation does not equal 0.2.0");
  });

  it("declares and enforces the macOS 14 compatibility floor", () => {
    const release = workflow("release.yml");
    const nativeSmoke = release.slice(
      release.indexOf("  smoke-native:"),
      release.indexOf("  checksums:"),
    );
    const installDocs = repositoryFile("docs/install.md");
    const appleVerifier = repositoryFile("scripts/verify-apple-toolchain.sh");

    expect(release).toContain('MACOSX_DEPLOYMENT_TARGET: "14.0"');
    expect(release).toContain(
      "MACOS_BUILD_DEVELOPER_DIR: /Applications/Xcode_16.4.app/Contents/Developer",
    );
    expect(release).toContain('MACOS_BUILD_XCODE_VERSION: "16.4"');
    expect(release).toContain("MACOS_BUILD_XCODE_BUILD: 16F6");
    expect(release).toContain('MACOS_BUILD_SDK_VERSION: "15.5"');
    expect(release).toContain(
      "MACOS_BUILD_CLANG_VERSION: Apple clang version 17.0.0 (clang-1700.0.13.5)",
    );
    expect(release).toContain('MACOS_BUILD_LD_VERSION: "1167.5"');
    expect(release).toContain(
      "MACOS_FLOOR_DEVELOPER_DIR: /Applications/Xcode_15.4.app/Contents/Developer",
    );
    expect(release).toContain('MACOS_FLOOR_XCODE_VERSION: "15.4"');
    expect(release).toContain("MACOS_FLOOR_XCODE_BUILD: 15F31d");
    expect(release).toContain('MACOS_FLOOR_SDK_VERSION: "14.5"');
    expect(release).toContain(
      "MACOS_FLOOR_CLANG_VERSION: Apple clang version 15.0.0 (clang-1500.3.9.4)",
    );
    expect(release).toContain('MACOS_FLOOR_LD_VERSION: "1053.12"');
    expect(release.match(/bash scripts\/verify-apple-toolchain\.sh/gu)).toHaveLength(2);
    expect(release).toContain("DEVELOPER_DIR: ${{ env.MACOS_BUILD_DEVELOPER_DIR }}");
    expect(release).toContain("DEVELOPER_DIR: ${{ env.MACOS_FLOOR_DEVELOPER_DIR }}");
    expect(appleVerifier).toContain('xcode_info="$(xcodebuild -version)"');
    expect(appleVerifier).toContain('sdk_version="$(xcrun --sdk macosx --show-sdk-version)"');
    expect(appleVerifier).toContain('clang_info="$(xcrun clang --version)"');
    expect(appleVerifier).toContain('ld_info="$(xcrun ld -v 2>&1)"');
    expect(appleVerifier).toContain('[[ "$(xcrun --find clang)" == "${toolchain_bin}/clang" ]]');
    expect(release).toContain('xcrun vtool -show-build "$binary"');
    expect(release).toContain('if [ "$minos" != "$MACOSX_DEPLOYMENT_TARGET" ]');
    expect(release).toContain("name: Test macOS service lifecycle on compatibility floor");
    expect(release).toContain("run: cargo test --locked --lib service::tests");
    expect(release).toContain("run: bash scripts/test-install-launchd-safety.sh");
    expect(release).toContain("run: bash scripts/test-bounded-log.sh");
    expect(release).toContain("run: bash scripts/test-install-release-archive.sh");
    expect(nativeSmoke).toContain("- runner: macos-14\n            target: aarch64-apple-darwin");
    expect(installDocs).toContain("macOS 14 Sonoma or newer");
  });

  it("retires npm and Changesets publication surfaces", () => {
    const rootPackage = repositoryFile("package.json");

    for (const path of [
      ".github/workflows/publish-typescript-packages.yml",
      ".changeset/config.json",
      "scripts/lib/npm-tarball-equivalence.ts",
      "scripts/publish-packages.ts",
      "scripts/smoke-docs-install.ts",
      "scripts/smoke-test-packed.ts",
    ]) {
      expect(existsSync(resolve(repoRoot, path)), path).toBe(false);
    }

    expect(rootPackage).not.toContain("@changesets/");
    expect(rootPackage).not.toContain("changeset");
    expect(rootPackage).not.toContain("release:publish");
    expect(rootPackage).not.toContain("release:smoke:packages");
    expect(rootPackage).not.toContain("compatibility");
    expect(repositoryFile("RELEASING.md")).not.toContain("TypeScript compatibility packages");
    expect(existsSync(resolve(workflowsRoot, "publish-desktop.yml"))).toBe(false);
    expect(existsSync(resolve(import.meta.dirname, "..", "legacy/cli/src/release.ts"))).toBe(false);
  });

  it("marks the root and every configured workspace package as private", () => {
    const rootManifest = decodeWorkspaceRootManifest(repositoryFile("package.json"));
    const manifests = new Set(["package.json"]);

    for (const workspace of rootManifest.workspaces) {
      const matches = globSync(`${workspace}/package.json`, { cwd: repoRoot });
      expect(matches.length, workspace).toBeGreaterThan(0);
      for (const manifest of matches) {
        manifests.add(manifest);
      }
    }

    expect(manifests.size).toBeGreaterThan(rootManifest.workspaces.length);
    for (const manifest of manifests) {
      expect(decodePrivatePackageManifest(repositoryFile(manifest)), manifest).toEqual({
        private: true,
      });
    }
  });

  it("requires explicit opt-in for Cloudflare previews and removes mutable package previews", () => {
    expect(workflow("preview.yml")).toContain("vars.ENABLE_CLOUDFLARE_PREVIEWS == 'true'");
    expect(workflow("preview-sweep.yml")).toContain("vars.ENABLE_CLOUDFLARE_PREVIEWS == 'true'");
    expect(existsSync(resolve(workflowsRoot, "pkg-pr-new.yml"))).toBe(false);
    expect(existsSync(resolve(workflowsRoot, "publish-typescript-packages.yml"))).toBe(false);
  });

  it("checks out and reports the exact pull request head commit for previews", () => {
    const preview = workflow("preview.yml");
    const checkoutCount = preview.match(/uses: actions\/checkout@/gu)?.length ?? 0;
    const headRefCount =
      preview.match(/ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/gu)?.length ?? 0;

    expect(headRefCount).toBe(checkoutCount);
    expect(preview).toContain("PREVIEW_SHA: ${{ steps.checkout.outputs.commit }}");
    expect(preview).toContain("${process.env.PREVIEW_SHA}");
    expect(preview).not.toContain("github.sha");
  });

  it("does not grant publishing permissions to dry-run jobs", () => {
    const release = workflow("release.yml");
    const nativeDryRun = release.slice(
      release.indexOf("  build-container-dry-run:"),
      release.indexOf("  publish-container-arch:"),
    );

    expect(nativeDryRun).not.toContain("packages: write");
    expect(nativeDryRun).not.toContain("id-token: write");
    expect(nativeDryRun).not.toContain("NATIVE_RELEASE_TOKEN");
  });

  it("pins every external action in owned workflows to an immutable SHA", () => {
    for (const name of ownedWorkflows) {
      const contents = workflow(name);
      const actionReferences = [...contents.matchAll(/^\s*-?\s*uses:\s+\S+@([^\s#]+)/gmu)];
      expect(actionReferences.length, name).toBeGreaterThan(0);
      for (const reference of actionReferences) {
        expect(reference[1], `${name}: ${reference[0]}`).toMatch(/^[0-9a-f]{40}$/u);
      }
    }
  });

  it("does not persist checkout credentials in owned workflows", () => {
    for (const name of ownedWorkflows) {
      const contents = workflow(name);
      const checkoutCount = contents.match(/uses: actions\/checkout@/gu)?.length ?? 0;
      const credentialCount = contents.match(/persist-credentials: false/gu)?.length ?? 0;
      expect(credentialCount, name).toBe(checkoutCount);
    }
  });
});
