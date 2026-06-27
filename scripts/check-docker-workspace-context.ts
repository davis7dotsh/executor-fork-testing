#!/usr/bin/env bun
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { runBootstrap, type BootstrapExecutor } from "./bootstrap";

const repoRoot = resolve(import.meta.dir, "..");
const sourceWorkspaceRoots = new Set(["web"]);

const read = (path: string) => readFileSync(resolve(repoRoot, path), "utf8");
const normalizedLines = (contents: string) =>
  contents
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));

const rootPackage = JSON.parse(read("package.json")) as { readonly workspaces?: unknown };
if (
  !Array.isArray(rootPackage.workspaces) ||
  !rootPackage.workspaces.every((workspace): workspace is string => typeof workspace === "string")
) {
  throw new Error("package.json must declare a string array of workspaces");
}

const failures: string[] = [];
const embeddedServiceFiles = [
  ...read("src/service.rs").matchAll(/include_bytes!\("\.\.\/([^"\n]+)"\)/gu),
].map((match) => match[1]);
const rustDockerfiles = ["Dockerfile", "Dockerfile.release-native"] as const;
for (const dockerfileName of rustDockerfiles) {
  const contents = read(dockerfileName);
  for (const embeddedFile of embeddedServiceFiles) {
    const copy = `COPY ${embeddedFile} ./${embeddedFile}`;
    if (!contents.includes(copy)) {
      failures.push(`${dockerfileName} must stage embedded Rust input: ${copy}`);
    }
  }
}

const requiredChromiumInstall = "run: bun run --cwd e2e playwright install --with-deps chromium";
const ciWorkflow = read(".github/workflows/ci.yml");
const chromiumInstallCount = ciWorkflow.split(requiredChromiumInstall).length - 1;
if (chromiumInstallCount !== 1) {
  failures.push(
    `CI must install Chromium exactly once through the e2e workspace: ${requiredChromiumInstall}`,
  );
}
if (ciWorkflow.includes("bunx playwright install")) {
  failures.push("CI must not install Playwright through root bunx resolution");
}

const bootstrapCommands: Parameters<BootstrapExecutor>[] = [];
runBootstrap((label, command, args) => bootstrapCommands.push([label, command, args]));
const actualBootstrapCommands = bootstrapCommands.map(([, command, args]) => [command, ...args]);
const expectedBootstrapCommands = [
  ["bun", "install", "--frozen-lockfile"],
  ["bun", "run", "--cwd", "e2e", "playwright", "install", "--with-deps", "chromium"],
];
if (JSON.stringify(actualBootstrapCommands) !== JSON.stringify(expectedBootstrapCommands)) {
  failures.push(
    "Bootstrap command plan must run only the frozen dependency install followed by the locked e2e Chromium install",
  );
}

const workspacePatterns = rootPackage.workspaces.map((workspace) => workspace.replace(/\/+$/u, ""));
const workspaceManifests = new Set<string>();
const patternsByRoot = new Map<string, string[]>();

for (const pattern of workspacePatterns) {
  const root = pattern.split("/", 1)[0];
  if (!root || /[*?[\]{}]/u.test(root)) {
    failures.push(`workspace pattern needs a literal top-level directory: ${pattern}`);
    continue;
  }

  const patterns = patternsByRoot.get(root) ?? [];
  patterns.push(pattern);
  patternsByRoot.set(root, patterns);

  const matches = [
    ...new Bun.Glob(`${pattern}/package.json`).scanSync({ cwd: repoRoot, onlyFiles: true }),
  ].map((path) => path.replaceAll("\\", "/"));
  if (matches.length === 0) {
    failures.push(`workspace pattern matches no package manifests: ${pattern}`);
  }
  for (const manifest of matches) workspaceManifests.add(manifest);
}

const manifestOnlyRoots = [...patternsByRoot.keys()]
  .filter((root) => !sourceWorkspaceRoots.has(root))
  .sort();
const dockerignoreRules = normalizedLines(read("Dockerfile.dockerignore"));
const requiredDockerContextPaths = [...embeddedServiceFiles, "scripts/package-release-archive.py"];
const requiredDockerContextDirectories = new Set(
  requiredDockerContextPaths.flatMap((path) => {
    const segments = path.split("/");
    return segments.slice(0, -1).map((_, index) => segments.slice(0, index + 1).join("/"));
  }),
);
for (const path of [...requiredDockerContextDirectories, ...requiredDockerContextPaths]) {
  if (!dockerignoreRules.includes(`!${path}`)) {
    failures.push(`Dockerfile.dockerignore must include release build input: !${path}`);
  }
}

const packageDockerfile = read("Dockerfile.release-package");
if (!packageDockerfile.includes("COPY scripts/package-release-archive.py")) {
  failures.push("Dockerfile.release-package must copy the deterministic archive packager");
}
const actualManifestRules = dockerignoreRules.filter((rule) => {
  const path = rule.startsWith("!") ? rule.slice(1) : rule;
  return manifestOnlyRoots.some((root) => path === root || path.startsWith(`${root}/`));
});
const expectedManifestRules = manifestOnlyRoots.flatMap((root) => [
  `!${root}`,
  `${root}/**`,
  ...(patternsByRoot.get(root) ?? []).toSorted().map((pattern) => `!${pattern}/package.json`),
]);

if (actualManifestRules.join("\n") !== expectedManifestRules.join("\n")) {
  failures.push(
    [
      "Dockerfile.dockerignore workspace rules are out of sync.",
      "Expected this manifest-only rule sequence:",
      ...expectedManifestRules.map((rule) => `  ${rule}`),
    ].join("\n"),
  );
}

const dockerfileLines = normalizedLines(read("Dockerfile")).map((line) =>
  line.replace(/\s+/gu, " "),
);
const installIndex = dockerfileLines.findIndex((line) =>
  line.includes("bun install --frozen-lockfile"),
);
if (installIndex === -1) {
  failures.push("Dockerfile has no frozen Bun install to validate");
} else {
  const stagedBeforeInstall = new Set(dockerfileLines.slice(0, installIndex));
  for (const root of manifestOnlyRoots) {
    const instruction = `COPY ${root} ./${root}`;
    if (!stagedBeforeInstall.has(instruction)) {
      failures.push(
        `Dockerfile must stage ${root} manifests before the frozen install: ${instruction}`,
      );
    }
  }
  for (const root of sourceWorkspaceRoots) {
    for (const manifest of [...workspaceManifests].filter((path) => path.startsWith(`${root}/`))) {
      const instruction = `COPY ${manifest} ./${manifest}`;
      if (!stagedBeforeInstall.has(instruction)) {
        failures.push(
          `Dockerfile must stage ${manifest} before the frozen install: ${instruction}`,
        );
      }
    }
  }
}

for (const root of sourceWorkspaceRoots) {
  if (!patternsByRoot.has(root)) {
    failures.push(`source workspace root is no longer declared: ${root}`);
  }
}

if (failures.length > 0) {
  console.error(`Docker workspace context check failed:\n\n${failures.join("\n\n")}\n`);
  process.exit(1);
}

console.log(
  `Docker workspace context stages ${workspaceManifests.size} manifests across ${patternsByRoot.size} roots.`,
);
