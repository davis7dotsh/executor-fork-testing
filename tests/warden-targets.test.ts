import { describe, expect, it } from "@effect/vitest";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const runGuard = (...args: ReadonlyArray<string>) =>
  spawnSync("bun", ["run", "scripts/check-warden-targets.ts", ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });

describe("Warden target guard", () => {
  it("accepts every configured repository target", () => {
    const result = runGuard();

    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Warden target guard checked");
  });

  it("rejects a target that resolves to zero non-ignored files", () => {
    const result = runGuard("tests/fixtures/warden-zero-match.toml");

    expect(result.status).toBe(1);
    expect(result.stderr).toContain("zero-match-fixture: tests/fixtures/does-not-exist/**/*.ts");
  });
});
