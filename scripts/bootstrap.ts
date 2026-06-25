// One-command setup for a fresh checkout or agent worktree: dependencies
// (whose prepare hook builds the internal packages dev servers need) and the
// Playwright browser the e2e suite drives. Idempotent and safe to re-run;
// each step prints what it is doing.
//
// There are no fork submodules: our upstream forks (@executor-js/emulate,
// @executor-js/mcporter) are consumed purely as published npm packages and
// developed in their own standalone repos. Nothing to init here.
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export type BootstrapExecutor = (
  label: string,
  command: string,
  args: ReadonlyArray<string>,
) => void;

export const runBootstrap = (execute: BootstrapExecutor) => {
  execute("dependencies (+ prepare builds)", "bun", ["install", "--frozen-lockfile"]);
  execute("playwright chromium", "bun", [
    "run",
    "--cwd",
    "e2e",
    "playwright",
    "install",
    "--with-deps",
    "chromium",
  ]);
};

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

const main = () => {
  // `bun install --frozen-lockfile` runs the workspace prepare hook, which builds
  // @executor-js/vite-plugin and @executor-js/react, the two artifacts the
  // legacy apps' Vite dev servers fail without in a fresh worktree.
  // Resolve Playwright from e2e so the browser revision matches its locked
  // dependency. The cache is shared per-machine when Chromium is already present.
  runBootstrap((label, command, args) => {
    console.log(`\n[bootstrap] ${label}: ${command} ${args.join(" ")}`);
    execFileSync(command, [...args], { cwd: repoRoot, stdio: "inherit" });
  });

  if (!existsSync(resolve(repoRoot, "node_modules/.bin/vitest"))) {
    throw new Error("bootstrap: vitest missing after install, bun install likely failed");
  }

  console.log("\n[bootstrap] done. See RUNNING.md for current verification commands.");
};

if (import.meta.main) main();
