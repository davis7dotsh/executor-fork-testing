import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

execFileSync("bun", ["run", "build"], {
  cwd: fileURLToPath(new URL("../web", import.meta.url)),
  stdio: "inherit",
});
execFileSync("cargo", ["build", "--bin", "executor"], {
  cwd: root,
  env: { ...process.env, EXECUTOR_WEB_ASSETS_DIR: "web/build" },
  stdio: "inherit",
});
execFileSync("bun", ["run", "test:unit"], {
  cwd: fileURLToPath(new URL("../e2e", import.meta.url)),
  stdio: "inherit",
});
execFileSync("bun", ["run", "test"], {
  cwd: fileURLToPath(new URL("../e2e", import.meta.url)),
  stdio: "inherit",
});
