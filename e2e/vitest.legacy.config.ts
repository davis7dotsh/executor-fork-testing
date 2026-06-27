import { defineConfig } from "vitest/config";

const project = (name: string, overrides: Record<string, unknown> = {}) => ({
  test: {
    name,
    include: ["scenarios/**/*.test.ts", `${name}/**/*.test.ts`],
    env: { E2E_TARGET: name },
    globalSetup: [`./setup/${name}.globalsetup.ts`],
    testTimeout: 180_000,
    hookTimeout: 120_000,
    ...overrides,
  },
});

export default defineConfig({
  test: {
    projects: [
      project("cloud", { fileParallelism: false }),
      project("selfhost", { fileParallelism: false }),
      project("selfhost-docker", {
        include: ["scenarios/**/*.test.ts", "selfhost/**/*.test.ts"],
        fileParallelism: false,
      }),
      project("cloudflare", {
        include: [
          "scenarios/browser-approval.test.ts",
          "scenarios/microsoft-graph-full.test.ts",
          "scenarios/toolkits-mcp.test.ts",
          "cloudflare/**/*.test.ts",
        ],
        fileParallelism: false,
      }),
      project("desktop", {
        include: ["desktop/**/*.test.ts"],
        fileParallelism: false,
        testTimeout: 300_000,
      }),
      project("desktop-packaged", {
        include: ["desktop-packaged/**/*.test.ts"],
        fileParallelism: false,
        testTimeout: 360_000,
        hookTimeout: 600_000,
      }),
      project("local", {
        include: ["local/**/*.test.ts"],
        globalSetup: [],
        fileParallelism: true,
      }),
      ...(["macos", "linux"] as const).map((os) =>
        project(`cli-${os}`, {
          include: ["scenarios/restart-persistence.test.ts", "cli/**/*.test.ts"],
          env: { E2E_TARGET: `cli-${os}`, E2E_VM_OS: os },
          fileParallelism: false,
          testTimeout: 300_000,
          hookTimeout: 900_000,
        }),
      ),
    ],
  },
});
