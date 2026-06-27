import { describe, expect, it } from "@effect/vitest";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const readRepoFile = (path: string) => readFileSync(resolve(repoRoot, path), "utf8");

const docsConfig = readRepoFile("apps/docs/docs.json");
const docsIndex = readRepoFile("apps/docs/index.mdx");
const installGuide = readRepoFile("docs/install.md");
const selfHosting = readRepoFile("apps/docs/self-hosting.mdx");
const docker = readRepoFile("apps/docs/hosted/docker.mdx");
const cli = readRepoFile("apps/docs/cli.mdx");
const mcpEndpoint = readRepoFile("apps/docs/mcp-proxy.mdx");
const sources = readRepoFile("apps/docs/concepts/sources.mdx");
const credentials = readRepoFile("apps/docs/concepts/credentials.mdx");
const toolModes = readRepoFile("apps/docs/concepts/tool-modes.mdx");
const marketing = readRepoFile("apps/marketing/src/pages/index.astro");
const activeProductSurfaces = [
  docsIndex,
  selfHosting,
  docker,
  cli,
  mcpEndpoint,
  sources,
  credentials,
  toolModes,
  marketing,
];
const legacyConcepts = [
  "apps/docs/concepts/integrations.mdx",
  "apps/docs/concepts/connections.mdx",
  "apps/docs/concepts/policies.mdx",
].map(readRepoFile);

const extract = (contents: string, pattern: RegExp, label: string) => {
  const match = contents.match(pattern);
  expect(match, label).not.toBeNull();
  return match?.[1] ?? "";
};
const normalizeWhitespace = (contents: string) => contents.replace(/\s+/gu, " ").trim();

describe("active product terminology", () => {
  it("navigates by sources, credentials, and tool modes", () => {
    expect(docsConfig).toContain('"concepts/sources"');
    expect(docsConfig).toContain('"concepts/credentials"');
    expect(docsConfig).toContain('"concepts/tool-modes"');
    expect(docsConfig).not.toContain('"concepts/integrations"');
    expect(docsConfig).not.toContain('"concepts/connections"');
    expect(docsConfig).not.toContain('"concepts/policies"');

    for (const page of [
      "apps/docs/concepts/sources.mdx",
      "apps/docs/concepts/credentials.mdx",
      "apps/docs/concepts/tool-modes.mdx",
    ]) {
      expect(existsSync(resolve(repoRoot, page)), page).toBe(true);
    }

    for (const legacyConcept of legacyConcepts) {
      expect(legacyConcept).toContain("Legacy concept:");
      expect(legacyConcept).toContain("<Warning>");
    }
  });

  it("teaches the supported source and credential model", () => {
    for (const surface of activeProductSurfaces) {
      expect(surface).not.toMatch(
        /\b(?:integration|integrations|connection|connections|policy|policies)\b/iu,
      );
      expect(surface).not.toMatch(/one integration can have many connections/iu);
      expect(surface).not.toMatch(/custom integration/iu);
      expect(surface).not.toMatch(/configured instance of an integration/iu);
      expect(surface).not.toMatch(/\bAllow\b.*\bBlock\b/isu);
    }

    expect(docsIndex).toContain("sources");
    expect(sources).toContain("MCP server over Streamable HTTP");
    expect(sources).toContain("MCP stdio template");
    expect(sources).toContain("OpenAPI");
    expect(sources).toContain("GraphQL");
    expect(credentials).toContain("at most one active static credential");
    expect(credentials).toContain("Managed OAuth");
    expect(marketing).toContain("at most one encrypted static credential profile");
    expect(marketing).not.toContain("from any protocol");
  });

  it("uses the current global tool-mode vocabulary", () => {
    for (const surface of [docsIndex, toolModes, marketing]) {
      expect(surface).toContain("Inherit");
      expect(surface).toContain("Enabled");
      expect(surface).toContain("Ask");
      expect(surface).toContain("Disabled");
      expect(surface).not.toMatch(/Require approval/iu);
      expect(surface).not.toMatch(/\bAllow\b.*\bBlock\b/isu);
    }

    expect(toolModes).toContain("same global tool set");
  });

  it("keeps the docs and marketing setup prompt synchronized", () => {
    const docsPrompt = extract(
      docsIndex,
      /```text Setup prompt\n([\s\S]*?)\n```/u,
      "docs setup prompt",
    );
    const marketingPrompt = extract(
      marketing,
      /const setupPrompt = `([\s\S]*?)`;/u,
      "marketing setup prompt",
    ).replaceAll("\\`", "`");

    expect(marketingPrompt).toBe(docsPrompt);
    expect(docsPrompt).toContain("one-time setup URL");
    expect(docsPrompt).toContain("create the administrator");
    expect(docsPrompt).toContain("create an API token in the dashboard");
  });

  it("keeps first boot and dashboard-issued API tokens on every setup surface", () => {
    for (const setupPage of [selfHosting, docker]) {
      expect(setupPage).toMatch(/one-time setup URL/iu);
      expect(setupPage).toMatch(/create the administrator/iu);
      expect(setupPage).toMatch(/create an API token/iu);
    }

    expect(normalizeWhitespace(mcpEndpoint)).toContain("Create an API token in the dashboard");
    expect(normalizeWhitespace(cli)).toContain("Create an API token in the dashboard");
    expect(marketing).toContain("dashboard-issued API token");
  });

  it("verifies native archives through checksums and immutable GitHub Releases", () => {
    expect(installGuide).toContain("sha256sum --check SHA256SUMS");
    expect(installGuide).toContain("shasum -a 256 --check SHA256SUMS");
    expect(installGuide).toContain('gh release verify "$tag" --repo "$repository"');
    expect(installGuide).toContain(
      'gh release verify-asset "$tag" "$archive" --repo "$repository"',
    );
    expect(installGuide).not.toContain("gh attestation verify");
    expect(installGuide).not.toMatch(/build[- ]provenance/iu);
    expect(installGuide).not.toContain("archives, attestations");
  });
});
