import { describe, expect, it } from "@effect/vitest";

import { runBootstrap, type BootstrapExecutor } from "../scripts/bootstrap";

describe("fresh checkout bootstrap", () => {
  it("executes only the locked dependency and browser installs, in order", () => {
    const commands: Parameters<BootstrapExecutor>[] = [];
    runBootstrap((label, command, args) => commands.push([label, command, args]));

    expect(commands.map(([, command, args]) => [command, ...args])).toEqual([
      ["bun", "install", "--frozen-lockfile"],
      ["bun", "run", "--cwd", "e2e", "playwright", "install", "--with-deps", "chromium"],
    ]);
  });
});
