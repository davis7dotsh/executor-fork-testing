import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { claimPorts, repoRoot } from "../src/ports";
import { LOCAL_ADMIN } from "../targets/local-selfhost";
import { waitForHttp } from "./boot";

interface BootedExecutor {
  readonly child: ChildProcess;
  readonly dataDir: string;
  readonly setupToken: string;
}

const stop = async (process: ChildProcess) => {
  if (process.pid === undefined || process.exitCode !== null) return;
  const exited = new Promise<void>((resolveExit) => process.once("exit", () => resolveExit()));
  try {
    globalThis.process.kill(-process.pid, "SIGTERM");
  } catch {
    process.kill("SIGTERM");
  }
  const graceful = await Promise.race([
    exited.then(() => true),
    new Promise<false>((resolveGrace) => setTimeout(() => resolveGrace(false), 5_000)),
  ]);
  if (!graceful) {
    try {
      globalThis.process.kill(-process.pid, "SIGKILL");
    } catch {
      process.kill("SIGKILL");
    }
    await Promise.race([exited, new Promise((resolveWait) => setTimeout(resolveWait, 2_000))]);
  }
};

const bootExecutor = async (
  binary: string,
  port: number,
  label: string,
): Promise<BootedExecutor> => {
  const dataDir = mkdtempSync(`${tmpdir()}/executor-e2e-${label}-`);
  const stdioTemplatesFile = resolve(dataDir, "mcp-stdio-templates.json");
  writeFileSync(
    stdioTemplatesFile,
    JSON.stringify({
      templates: [
        {
          name: "executor-e2e-stdio",
          executable: process.execPath,
          cwd: repoRoot,
          arguments: [resolve(repoRoot, "e2e/fixtures/stdio-mcp-server.mjs")],
          environment: {},
          secretEnvironment: ["EXECUTOR_E2E_STDIO_SECRET"],
        },
      ],
    }),
  );
  const child = spawn(
    binary,
    [
      "server",
      "--bind",
      `127.0.0.1:${port}`,
      "--data-dir",
      dataDir,
      "--public-origin",
      `http://127.0.0.1:${port}`,
      "--mcp-stdio-templates",
      stdioTemplatesFile,
    ],
    { cwd: repoRoot, detached: true, stdio: ["ignore", "pipe", "pipe"] },
  );
  let output = "";
  let collectingSetupLink = true;
  const capture = (chunk: Buffer) => {
    if (!collectingSetupLink) return;
    output = `${output}${chunk.toString("utf8")}`.slice(-64 * 1024);
  };
  child.stdout?.on("data", capture);
  child.stderr?.on("data", capture);

  try {
    await waitForHttp(`http://127.0.0.1:${port}/api/v1/bootstrap`, { timeoutMs: 30_000 });
    const deadline = Date.now() + 10_000;
    while (!output.match(/\/setup#token=([^\s]+)/) && Date.now() < deadline) {
      await new Promise((resolveWait) => setTimeout(resolveWait, 50));
    }
    const setupToken = output.match(/\/setup#token=([^\s]+)/)?.[1];
    if (!setupToken) throw new Error(`could not read setup token from ${label} server output`);
    collectingSetupLink = false;
    output = "";
    return { child, dataDir, setupToken };
  } catch (error) {
    await stop(child);
    rmSync(dataDir, { recursive: true, force: true });
    throw error;
  }
};

const completeSetup = async (baseUrl: string, setupToken: string) => {
  const response = await fetch(new URL("/api/v1/setup", baseUrl), {
    method: "POST",
    headers: { "content-type": "application/json", origin: new URL(baseUrl).origin },
    body: JSON.stringify({ setupToken, ...LOCAL_ADMIN }),
  });
  if (!response.ok) {
    throw new Error(`could not prepare local selfhost administrator (${response.status})`);
  }
};

export default async function setup(): Promise<() => Promise<void>> {
  if (process.env.E2E_LOCAL_SELFHOST_URL || process.env.E2E_LOCAL_SETUP_URL) {
    throw new Error(
      "The complete local e2e suite needs two fresh instances. Run without E2E_LOCAL_SELFHOST_URL and E2E_LOCAL_SETUP_URL.",
    );
  }
  const binary = resolve(
    process.env.E2E_EXECUTOR_BIN ?? resolve(repoRoot, "target/debug/executor"),
  );
  if (!existsSync(binary)) {
    throw new Error(
      `Executor binary not found at ${binary}. Run the root test:e2e command so the Svelte assets and Rust binary are prepared first.`,
    );
  }
  process.env.E2E_EXECUTOR_BIN = binary;

  const { ports, release } = await claimPorts([
    { envVar: "E2E_LOCAL_SELFHOST_PORT", offset: 4, label: "Rust local selfhost" },
    { envVar: "E2E_LOCAL_SETUP_PORT", offset: 5, label: "Rust first-boot setup" },
    { envVar: "E2E_LOCAL_EMULATOR_A_PORT", offset: 6, label: "local emulator A" },
    { envVar: "E2E_LOCAL_EMULATOR_B_PORT", offset: 7, label: "local emulator B" },
    { envVar: "E2E_LOCAL_EMULATOR_C_PORT", offset: 8, label: "local emulator C" },
  ]);
  const mainPort = ports.E2E_LOCAL_SELFHOST_PORT!;
  const setupPort = ports.E2E_LOCAL_SETUP_PORT!;
  const main = await bootExecutor(binary, mainPort, "main");
  let firstBoot: BootedExecutor | undefined;
  try {
    await completeSetup(`http://127.0.0.1:${mainPort}`, main.setupToken);
    firstBoot = await bootExecutor(binary, setupPort, "setup");
    process.env.E2E_LOCAL_SELFHOST_URL = `http://127.0.0.1:${mainPort}`;
    process.env.E2E_LOCAL_SETUP_URL = `http://127.0.0.1:${setupPort}`;
    process.env.E2E_LOCAL_SETUP_TOKEN = firstBoot.setupToken;
  } catch (error) {
    await stop(main.child);
    if (firstBoot) await stop(firstBoot.child);
    rmSync(main.dataDir, { recursive: true, force: true });
    if (firstBoot) rmSync(firstBoot.dataDir, { recursive: true, force: true });
    await release();
    throw error;
  }

  return async () => {
    await Promise.all([stop(main.child), stop(firstBoot.child)]);
    rmSync(main.dataDir, { recursive: true, force: true });
    rmSync(firstBoot.dataDir, { recursive: true, force: true });
    await release();
  };
}
