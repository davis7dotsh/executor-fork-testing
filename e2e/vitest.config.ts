import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "local-selfhost",
          include: ["local-selfhost/**/*.test.ts"],
          env: { E2E_TARGET: "local-selfhost" },
          globalSetup: ["./setup/local-selfhost.globalsetup.ts"],
          fileParallelism: false,
          testTimeout: 180_000,
          hookTimeout: 120_000,
        },
      },
    ],
  },
});
