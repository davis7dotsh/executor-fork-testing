import { describe, expect, it } from "@effect/vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const readRepoFile = (path: string) => readFileSync(resolve(repoRoot, path), "utf8");
const normalizeWhitespace = (contents: string) => contents.replace(/\s+/gu, " ").trim();

const rootPackage = readRepoFile("package.json");
const cloudflarePackage = readRepoFile("legacy/host-cloudflare/package.json");
const selfhostPackage = readRepoFile("legacy/host-selfhost/package.json");
const cloudTsconfig = readRepoFile("legacy/cloud/tsconfig.json");
const openCode = readRepoFile("opencode.json");
const releaseRunbook = readRepoFile(".skills/cli-release/SKILL.md");
const warden = readRepoFile("warden.toml");
const wardenRunbook = readRepoFile(".skills/warden-security-review/SKILL.md");
const docsReadme = readRepoFile("apps/docs/README.md");
const docsConfig = readRepoFile("apps/docs/docs.json");
const docsIndex = readRepoFile("apps/docs/index.mdx");
const dockerDocs = readRepoFile("apps/docs/hosted/docker.mdx");
const legacyCliDocs = readRepoFile("apps/docs/local/cli.mdx");
const normalizedLegacyCliDocs = normalizeWhitespace(legacyCliDocs);
const marketing = readRepoFile("apps/marketing/src/pages/index.astro");
const marketingLayout = readRepoFile("apps/marketing/src/layouts/Layout.astro");

const legacyDocs = [
  "apps/docs/local/desktop.mdx",
  "apps/docs/hosted/cloud.mdx",
  "apps/docs/hosted/cloudflare.mdx",
]
  .map(readRepoFile)
  .concat(legacyCliDocs);

describe("archived product boundaries", () => {
  it("keeps every runnable legacy entrypoint explicitly named", () => {
    expect(rootPackage).not.toMatch(/^\s+"dev:cli":/mu);
    expect(rootPackage).toContain('"legacy:dev:cli"');

    const aggregateDev = rootPackage.split("\n").find((line) => line.includes('"legacy:dev":'));
    expect(aggregateDev).not.toContain("--filter='executor'");

    expect(cloudflarePackage).toContain('"typecheck:slow": "tsc --noEmit"');
    expect(selfhostPackage).toContain('"typecheck:slow": "tsc --noEmit"');
    expect(rootPackage).toContain(
      '"legacy:typecheck:slow": "bun run --filter=\'./legacy/*\' typecheck:slow"',
    );
    expect(cloudTsconfig).not.toContain('"rootDir": "."');
  });

  it("does not launch the archived local MCP from the default OpenCode config", () => {
    expect(openCode).toContain('"mcp": {}');
    expect(openCode).not.toContain("legacy:dev:cli");
    expect(openCode).not.toContain("legacy/local");
  });

  it("documents only the supported native release path", () => {
    expect(releaseRunbook).toContain(".github/workflows/release.yml");
    expect(releaseRunbook).toContain("This fork does not publish them to npm");
    expect(releaseRunbook).toContain("old npm workflows, publisher scripts");
    expect(releaseRunbook).not.toContain("confirm_publish=true");
    expect(releaseRunbook).not.toContain("compat-<version>");
    expect(releaseRunbook).not.toContain("legacy/cli");
    expect(releaseRunbook).not.toContain("pkg.pr.new");
  });

  it("keeps the supported product in active docs navigation", () => {
    const legacyGroup = docsConfig.indexOf('"group": "Legacy archive"');
    expect(legacyGroup).toBeGreaterThan(0);

    const activeNavigation = docsConfig.slice(0, legacyGroup);
    expect(activeNavigation).toContain('"self-hosting"');
    expect(activeNavigation).toContain('"hosted/docker"');
    expect(activeNavigation).toContain('"cli"');
    expect(activeNavigation).not.toContain('"local/cli"');
    expect(activeNavigation).not.toContain('"local/desktop"');
    expect(activeNavigation).not.toContain('"hosted/cloud"');
    expect(activeNavigation).not.toContain('"hosted/cloudflare"');

    expect(legacyDocs.every((legacyDoc) => legacyDoc.includes('title: "Legacy:'))).toBe(true);
    expect(legacyDocs.every((legacyDoc) => legacyDoc.includes("<Warning>"))).toBe(true);
  });

  it("describes only the Rust, Svelte, native, and Docker product as supported", () => {
    expect(docsIndex).toContain("binary serves the Svelte dashboard");
    expect(docsIndex).toContain("Native Linux or macOS");
    expect(dockerDocs).toContain("supported Docker image");
    expect(dockerDocs).toContain("ghcr.io/davis7dotsh/executor:");
    expect(dockerDocs).not.toContain("legacy/host-selfhost");
    expect(dockerDocs).not.toContain("executor-selfhost");

    expect(marketing).toContain("single-user, self-hosted tool gateway");
    expect(marketing).toContain("Linux and macOS archives");
    expect(marketing).not.toContain("Executor Cloud");
    expect(marketing).not.toContain('href="/cloud"');
    expect(marketing).not.toContain("npm i -g executor");
    expect(marketing).not.toContain("executor-desktop-");
    expect(marketing).not.toContain('id="pricing"');
    expect(marketing).not.toContain("ContextBloatDemo");
    expect(marketing).not.toContain("single tool");
    expect(marketingLayout).toContain("self-hosted tool gateway");
    expect(docsReadme).toContain("independent of archived code");
    expect(docsReadme).not.toContain("legacy/cloud");
  });

  it("retires actionable npm CLI installation guidance", () => {
    expect(normalizedLegacyCliDocs).toContain("TypeScript npm CLI is retired and unsupported");
    expect(normalizedLegacyCliDocs).toContain("Historical registry artifacts may still resolve");
    expect(normalizedLegacyCliDocs).toContain("they are no longer updated");
    expect(normalizedLegacyCliDocs).toContain("Do not use them for a new installation");
    expect(normalizedLegacyCliDocs).not.toContain("installation channels are unavailable");
    expect(normalizedLegacyCliDocs).toContain("[native self-hosting](/self-hosting)");
    expect(normalizedLegacyCliDocs).toContain("[Rust CLI](/cli)");
    expect(legacyCliDocs).not.toMatch(
      /(?:npm install|npm i|pnpm add|bun add|yarn global add)\s+-g\s+executor/iu,
    );
    expect(legacyCliDocs).not.toContain("executor install");
    expect(legacyCliDocs).not.toContain("executor web");
    expect(legacyCliDocs).not.toContain("npx add-mcp");
  });

  it("scans active Rust and retained compatibility surfaces that exist", () => {
    expect(warden).toContain('"src/database.rs"');
    expect(warden).toContain('"src/outbound.rs"');
    expect(warden).toContain('"src/mcp/**/*.rs"');
    expect(warden).toContain('"legacy/local/src/**/*.ts"');
    expect(warden).not.toContain("packages/core/storage-");
    expect(warden).not.toContain('"legacy/local/src/**/*.tsx"');
    expect(warden).not.toContain("legacy/local/src/server");
    expect(wardenRunbook).toContain("src legacy/local/src legacy/cli/src");
    expect(wardenRunbook).toContain("legacy/cloud/src/routes legacy/local/src");
    expect(wardenRunbook).not.toContain("packages/core/storage-");
    expect(wardenRunbook).not.toContain("packages/plugins/google-discovery");
    expect(wardenRunbook).not.toContain("packages/plugins/oauth2");
    expect(wardenRunbook).not.toContain("legacy/local/src/server");
  });
});
