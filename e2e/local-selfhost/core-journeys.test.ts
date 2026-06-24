import { randomBytes, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { expect } from "@effect/vitest";
import { createEmulator, type Emulator } from "@executor-js/emulate";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  makeGreetingGraphqlSchema,
  serveGraphqlTestServer,
} from "@executor-js/plugin-graphql/testing";
import { makeGreetingMcpServer, serveMcpServer } from "@executor-js/plugin-mcp/testing";
import { serveOpenApiEchoTestServer } from "@executor-js/plugin-openapi/testing";
import { Effect } from "effect";

import { scenario } from "../src/scenario";
import { LocalAdminClient, type LocalSource } from "../src/local-admin";
import { serveOAuthTestProvider } from "../src/oauth-test-provider";
import { Browser, Target } from "../src/services";
import { LOCAL_ADMIN, LOCAL_SETUP_BASE_URL } from "../targets/local-selfhost";

const unique = (prefix: string) => `${prefix}-${randomBytes(4).toString("hex")}`;
const executeFile = promisify(execFile);

const adminClient = (baseUrl: string) =>
  Effect.promise(() =>
    LocalAdminClient.signIn(baseUrl, LOCAL_ADMIN.username, LOCAL_ADMIN.password),
  );

const resendEmulator = Effect.acquireRelease(
  Effect.promise(() => createEmulator({ service: "resend" })),
  (emulator: Emulator) => Effect.promise(() => emulator.close()).pipe(Effect.ignore),
);

const deleteSources = (client: LocalAdminClient, sources: readonly LocalSource[]) =>
  Effect.forEach(sources, (source) =>
    Effect.promise(() => client.deleteSource(source.id)).pipe(Effect.ignore),
  ).pipe(Effect.asVoid);

scenario(
  "First boot · the one-time setup link creates the only administrator",
  {},
  Effect.gen(function* () {
    const browser = yield* Browser;
    const setupToken = process.env.E2E_LOCAL_SETUP_TOKEN;
    if (!setupToken) return yield* Effect.die("the fresh setup instance did not publish a token");

    yield* browser.privateSession({ label: "first-boot administrator" }, async ({ page, step }) => {
      await step("Open the one-time setup link and create the administrator", async () => {
        await page.goto(`${LOCAL_SETUP_BASE_URL}/setup#token=${encodeURIComponent(setupToken)}`);
        await expect.poll(() => new URL(page.url()).hash).toBe("");
        await page.getByLabel("Administrator username").fill("first-boot-admin");
        await page.getByLabel("Password", { exact: true }).fill("first-boot-password-123");
        await page.getByLabel("Confirm password").fill("first-boot-password-123");
        await page.getByRole("button", { name: "Create administrator" }).click();
        await page.waitForURL((url) => url.pathname === "/sources");
        await expect(page.getByRole("heading", { name: "Sources" })).toBeVisible();
      });
    });
    const replay = yield* Effect.promise(() =>
      fetch(new URL("/api/v1/setup", LOCAL_SETUP_BASE_URL), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: new URL(LOCAL_SETUP_BASE_URL).origin,
        },
        body: JSON.stringify({
          setupToken,
          username: "second-admin",
          password: "second-admin-password-123",
        }),
      }),
    );
    expect(replay.status, "the consumed setup token cannot create another administrator").toBe(409);
  }),
);

scenario(
  "Administrator access · sign-in creates a gateway token without exposing it twice",
  {},
  Effect.gen(function* () {
    const target = yield* Target;
    const browser = yield* Browser;

    yield* browser.privateSession({ label: "signed-out administrator" }, async ({ page, step }) => {
      await step("Sign in and create a token, then dismiss the one-time secret", async () => {
        await page.goto("/login");
        await page.getByLabel("Username").fill(LOCAL_ADMIN.username);
        await page.getByLabel("Password").fill(LOCAL_ADMIN.password);
        await page.getByRole("button", { name: "Sign in" }).click();
        await page.waitForURL((url) => url.pathname === "/sources");
        await page.goto("/tokens");
        await page.getByLabel("Token name").fill("E2E local agent");
        await page.getByRole("button", { name: "Create token" }).click();
        const secret = await page.getByLabel("API token").inputValue();
        expect(secret, "the token is revealed exactly once").toMatch(/^exr_/);
        await page.getByRole("button", { name: "I saved it" }).click();
        await expect(page.getByLabel("API token")).toHaveCount(0);
      });
    });

    const identity = yield* target.newIdentity();
    yield* browser.session(identity, async ({ page, step }) => {
      await step("Return to the token list and see only masked metadata", async () => {
        await page.goto("/tokens");
        const row = page.getByRole("row").filter({ hasText: "E2E local agent" });
        await expect(row).toContainText("Active");
        await expect(row.locator('td[data-label="Token"] code')).toContainText("...");
      });
    });
  }),
);

scenario(
  "Sources · OpenAPI, GraphQL, and MCP join one local catalog",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const resend = yield* resendEmulator;
      const graphql = yield* serveGraphqlTestServer({
        schema: makeGreetingGraphqlSchema({ includeMutation: false }),
      });
      const mcp = yield* serveMcpServer(() =>
        makeGreetingMcpServer({ name: unique("mcp"), text: "hello from local MCP" }),
      );
      const suffix = randomBytes(3).toString("hex");
      const created: LocalSource[] = [];

      yield* Effect.ensuring(
        Effect.gen(function* () {
          created.push(
            yield* Effect.promise(() =>
              client.createSource({
                kind: "openapi",
                displayName: `Resend emulator ${suffix}`,
                spec: { type: "url", url: resend.openapiUrl },
                allowPrivateNetwork: true,
              }),
            ),
          );
          created.push(
            yield* Effect.promise(() =>
              client.createSource({
                kind: "graphql",
                displayName: `GraphQL greeting ${suffix}`,
                endpoint: graphql.endpoint,
                allowPrivateNetwork: true,
              }),
            ),
          );
          created.push(
            yield* Effect.promise(() =>
              client.createSource({
                kind: "mcp_http",
                displayName: `MCP greeting ${suffix}`,
                endpoint: mcp.endpoint,
                allowPrivateNetwork: true,
              }),
            ),
          );

          const token = yield* Effect.promise(() => client.createToken(unique("source-agent")));
          for (const source of created.slice(1)) {
            const catalog = yield* Effect.promise(() => client.listTools({ sourceId: source.id }));
            expect(
              catalog.items.length,
              `${source.displayName} discovers at least one tool`,
            ).toBeGreaterThan(0);
            const enabled = yield* Effect.promise(() =>
              client.setToolMode(catalog.items[0]!, "enabled"),
            );
            const argumentsForTool = source.id === created[1]?.id ? { name: "Ada" } : {};
            const invoked = yield* Effect.promise(() =>
              fetch(new URL("/api/v1/gateway/tools/invoke", target.baseUrl), {
                method: "POST",
                headers: {
                  authorization: `Bearer ${token.token}`,
                  "content-type": "application/json",
                },
                body: JSON.stringify({ path: enabled.callablePath, arguments: argumentsForTool }),
              }),
            );
            expect(invoked.status, `${source.displayName} executes through the gateway`).toBe(200);
          }
          const graphqlRequests = yield* graphql.requests;
          expect(
            graphqlRequests.filter((request) => !request.payload.query?.includes("__schema")),
            "the GraphQL resolver received a non-introspection call",
          ).not.toHaveLength(0);
          const mcpRequests = yield* mcp.requests;
          expect(
            mcpRequests.length,
            "the MCP server received discovery and invocation traffic",
          ).toBeGreaterThanOrEqual(2);

          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            await step("Open Sources and see every supported protocol", async () => {
              await page.goto("/sources");
              for (const source of created) {
                await expect(page.getByText(source.displayName, { exact: true })).toBeVisible();
              }
              await expect(page.getByText("OpenAPI", { exact: true }).last()).toBeVisible();
              await expect(page.getByText("GraphQL", { exact: true }).last()).toBeVisible();
              await expect(page.getByText("MCP HTTP", { exact: true }).last()).toBeVisible();
            });
          });
        }),
        deleteSources(client, created),
      );
    }),
  ),
);

scenario(
  "Tools · search, filters, and broad mode changes stay explicit",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const upstream = yield* serveOpenApiEchoTestServer();
      const name = unique("Mode controls");
      const source = yield* Effect.promise(() =>
        client.createSource({
          kind: "openapi",
          displayName: name,
          preferredSlug: unique("modes").replaceAll("-", "_"),
          spec: { type: "inline", content: upstream.specJson },
          allowPrivateNetwork: true,
        }),
      );
      const catalog = yield* Effect.promise(() => client.listTools({ sourceId: source.id }));
      const tool = catalog.items[0];
      if (!tool) return yield* Effect.die("the mode fixture produced no tool");
      const token = yield* Effect.promise(() => client.createToken(unique("mode-agent")));
      const invoke = () =>
        fetch(new URL("/api/v1/gateway/tools/invoke", target.baseUrl), {
          method: "POST",
          headers: {
            authorization: `Bearer ${token.token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({ path: tool.callablePath, arguments: { message: "Mode" } }),
        });

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            await step("Search the global catalog and filter to one source", async () => {
              await page.goto("/tools");
              await page.getByLabel("Search tools").fill("echo");
              await page.getByRole("button", { name: "Search" }).click();
              await page.getByLabel("Source").selectOption({ label: name });
              await expect(page.getByRole("table")).toContainText("echo");
            });

            await step("Ask applies immediately to the selected tools", async () => {
              await page.getByLabel("Select all active tools on this page").check();
              await page
                .getByRole("group", { name: "Set selected tools" })
                .getByLabel("Ask")
                .check();
              await page.getByRole("button", { name: /Set .* to Ask/ }).click();
              await expect(page.locator("#bulk-status")).toContainText("Ask applied");
            });

            await step("Disabling many tools requires a second confirmation", async () => {
              await page.getByLabel("Select all active tools on this page").check();
              await page
                .getByRole("group", { name: "Set selected tools" })
                .getByLabel("Disabled")
                .check();
              await page.getByRole("button", { name: /Set .* to Disabled/ }).click();
              await expect(
                page.getByRole("group", { name: "Confirm bulk tool behavior" }),
              ).toBeVisible();
              await page.getByRole("button", { name: "Confirm Disabled" }).click();
              await expect(page.locator("#bulk-status")).toContainText("Disabled applied");
              const denied = await invoke();
              expect(
                (await denied.json()) as unknown,
                "disabled tools are denied at the gateway",
              ).toMatchObject({
                error: { code: "tool_disabled" },
              });
            });

            await step("Re-enabling many tools also requires deliberate confirmation", async () => {
              await page.getByLabel("Effective mode").selectOption("disabled");
              await page.getByLabel("Select all active tools on this page").check();
              await page
                .getByRole("group", { name: "Set selected tools" })
                .getByLabel("Enabled")
                .check();
              await page.getByRole("button", { name: /Set .* to Enabled/ }).click();
              await page.getByRole("button", { name: "Confirm Enabled" }).click();
              await expect(page.locator("#bulk-status")).toContainText("Enabled applied");
              expect((await invoke()).status, "enabled tools are callable without approval").toBe(
                200,
              );
            });
          });
        }),
        Effect.promise(() => client.deleteSource(source.id)).pipe(Effect.ignore),
      );
    }),
  ),
);

scenario(
  "MCP and CLI · bearer clients share the global catalog and concurrent runtime",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const client = yield* adminClient(target.baseUrl);
      const upstream = yield* serveOpenApiEchoTestServer();
      const source = yield* Effect.promise(() =>
        client.createSource({
          kind: "openapi",
          displayName: unique("MCP CLI source"),
          spec: { type: "inline", content: upstream.specJson },
          allowPrivateNetwork: true,
        }),
      );
      const catalog = yield* Effect.promise(() => client.listTools({ sourceId: source.id }));
      const tool = catalog.items[0];
      if (!tool) return yield* Effect.die("the MCP and CLI fixture produced no tool");
      yield* Effect.promise(() => client.setToolMode(tool, "enabled"));
      const token = yield* Effect.promise(() => client.createToken(unique("mcp-cli-agent")));
      const binary = process.env.E2E_EXECUTOR_BIN;
      if (!binary) return yield* Effect.die("the e2e harness did not publish its Executor binary");
      const cliEnvironment = { ...process.env, EXECUTOR_API_TOKEN: token.token };
      const cli = (arguments_: readonly string[]) =>
        Effect.promise(() =>
          executeFile(binary, ["--base-url", target.baseUrl, "--json", ...arguments_], {
            env: cliEnvironment,
          }),
        );

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const sources = yield* cli(["tools", "sources"]);
          expect(sources.stdout, "the CLI lists the source catalog").toContain(source.slug);
          const search = yield* cli(["tools", "search", "echo"]);
          expect(search.stdout, "the CLI searches the same global tools").toContain(
            tool.callablePath,
          );
          const described = yield* cli(["tools", "describe", tool.callablePath]);
          expect(described.stdout, "the CLI describes the selected tool").toContain(
            tool.displayName,
          );
          const called = yield* cli(["call", tool.callablePath, '{"message":"CLI"}']);
          expect(called.stdout, "the CLI calls the enabled tool").toContain("CLI");

          const httpMcp = yield* Effect.acquireRelease(
            Effect.promise(async () => {
              const mcp = new Client({ name: "executor-e2e-http", version: "1.0.0" });
              const transport = new StreamableHTTPClientTransport(new URL(target.mcpUrl), {
                requestInit: { headers: { authorization: `Bearer ${token.token}` } },
              });
              await mcp.connect(transport);
              return mcp;
            }),
            (mcp) => Effect.promise(() => mcp.close()).pipe(Effect.ignore),
          );
          const advertised = yield* Effect.promise(() => httpMcp.listTools());
          expect(
            advertised.tools.map((candidate) => candidate.name),
            "HTTP MCP advertises the bounded gateway surface",
          ).toEqual(expect.arrayContaining(["execute", "call", "search", "describe", "sources"]));
          const executed = yield* Effect.promise(() =>
            httpMcp.callTool({
              name: "execute",
              arguments: {
                code: `const values = await Promise.all([${tool.callablePath}({ message: "one" }), ${tool.callablePath}({ message: "two" })]); return values;`,
              },
            }),
          );
          expect(
            JSON.stringify(executed),
            "the TS runtime completes two concurrent calls",
          ).toContain("one");
          expect(JSON.stringify(executed)).toContain("two");

          const stdioMcp = yield* Effect.acquireRelease(
            Effect.promise(async () => {
              const mcp = new Client({ name: "executor-e2e-stdio", version: "1.0.0" });
              const transport = new StdioClientTransport({
                command: binary,
                args: ["--base-url", target.baseUrl, "mcp"],
                env: {
                  PATH: process.env.PATH ?? "",
                  HOME: process.env.HOME ?? "",
                  EXECUTOR_API_TOKEN: token.token,
                },
                stderr: "pipe",
              });
              await mcp.connect(transport);
              return mcp;
            }),
            (mcp) => Effect.promise(() => mcp.close()).pipe(Effect.ignore),
          );
          const bridged = yield* Effect.promise(() => stdioMcp.listTools());
          expect(
            bridged.tools.map((candidate) => candidate.name),
            "the CLI stdio bridge exposes the same MCP tools",
          ).toEqual(advertised.tools.map((candidate) => candidate.name));

          yield* Effect.promise(() => client.revokeToken(token.id));
          const afterRevocation = yield* Effect.exit(Effect.tryPromise(() => httpMcp.listTools()));
          expect(afterRevocation._tag, "revocation invalidates an existing MCP session").toBe(
            "Failure",
          );
        }),
        Effect.promise(() => client.deleteSource(source.id)).pipe(Effect.ignore),
      );
    }),
  ),
);

scenario(
  "Approvals and logs · an Ask call waits for one administrator decision",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const upstream = yield* serveOpenApiEchoTestServer();
      const source = yield* Effect.promise(() =>
        client.createSource({
          kind: "openapi",
          displayName: unique("Approval source"),
          spec: { type: "inline", content: upstream.specJson },
          allowPrivateNetwork: true,
        }),
      );

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const page = yield* Effect.promise(() => client.listTools({ sourceId: source.id }));
          const tool = page.items[0];
          if (!tool) return yield* Effect.die("the approval fixture produced no tool");
          yield* Effect.promise(() => client.setToolMode(tool, "ask"));
          const token = yield* Effect.promise(() => client.createToken(unique("approval-agent")));
          const invoke = yield* Effect.promise(() =>
            fetch(new URL("/api/v1/gateway/tools/invoke", target.baseUrl), {
              method: "POST",
              headers: {
                authorization: `Bearer ${token.token}`,
                "content-type": "application/json",
                "idempotency-key": randomUUID(),
              },
              body: JSON.stringify({ path: tool.callablePath, arguments: { message: "Ada" } }),
            }),
          );
          expect(invoke.status, "Ask returns an accepted approval handle").toBe(202);
          const pending = (yield* Effect.promise(() => invoke.json())) as {
            readonly approval: { readonly id: string; readonly statusUrl: string };
          };
          const approvalStatusUrl = new URL(pending.approval.statusUrl, target.baseUrl);
          expect(approvalStatusUrl.origin, "the bearer stays on this Executor origin").toBe(
            new URL(target.baseUrl).origin,
          );
          expect(approvalStatusUrl.pathname, "the handle names this exact approval").toBe(
            `/api/v1/gateway/approvals/${pending.approval.id}`,
          );

          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            await step("Review the exact pending request", async () => {
              await page.goto(`/approvals?approval=${encodeURIComponent(pending.approval.id)}`);
              await expect(page.getByText(tool.callablePath, { exact: true }).last()).toBeVisible();
              await expect(page.getByText("Structural, redacted argument preview")).toBeVisible();
            });
            await step("Approve this invocation once", async () => {
              await page.getByRole("button", { name: "Approve once" }).click();
              await page.getByRole("button", { name: "Yes, approve once" }).click();
              await expect(page.getByText(/was approved/i)).toBeVisible();
            });
            await step("Open Logs and find the completed gateway request", async () => {
              await page.goto("/logs");
              await expect(
                page.getByText(tool.callablePath, { exact: true }).first(),
              ).toBeVisible();
            });
          });

          const completed = yield* Effect.promise(async () => {
            for (let attempt = 0; attempt < 80; attempt += 1) {
              const response = await fetch(approvalStatusUrl, {
                headers: { authorization: `Bearer ${token.token}` },
              });
              const body = (await response.json()) as { readonly status: string };
              if (!["pending", "approved", "executing"].includes(body.status)) return body;
              await new Promise((resolveWait) => setTimeout(resolveWait, 100));
            }
            throw new Error("approved call did not finish");
          });
          expect(completed.status, "the approved invocation runs exactly once").toBe("succeeded");
          const requests = yield* upstream.requests;
          expect(
            requests.filter((request) => request.path.startsWith("/echo/")).length,
            "one approval produces one upstream side effect",
          ).toBe(1);
        }),
        Effect.promise(() => client.deleteSource(source.id)).pipe(Effect.ignore),
      );
    }),
  ),
);

scenario(
  "Managed OAuth · the provider callback connects a source without exposing tokens",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const provider = yield* serveOAuthTestProvider();
      const source = yield* Effect.promise(() =>
        client.createSource({
          kind: "mcp_http",
          displayName: unique("Managed OAuth"),
          allowPrivateNetwork: true,
          endpoint: provider.endpoint,
        }),
      );

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const available = yield* Effect.promise(() => client.getOAuthConnections(source.id));
          const credentialKey = available.availableCredentials[0]?.credentialKey;
          if (!credentialKey) return yield* Effect.die("the OAuth source exposed no credential");
          const placeholder = yield* Effect.promise(() =>
            client.putOAuthConnection(source.id, credentialKey, {
              expectedRevision: 0,
              discovery: { type: "issuer", issuer: provider.issuer },
              client: { clientId: "pending-dynamic-registration", authentication: "none" },
              scopes: ["repo", "read:user"],
            }),
          );
          const clientId = yield* Effect.promise(() =>
            provider.registerClient(placeholder.callbackUrl),
          );
          const connection = yield* Effect.promise(() =>
            client.putOAuthConnection(source.id, credentialKey, {
              expectedRevision: placeholder.revision,
              discovery: { type: "issuer", issuer: provider.issuer },
              client: { clientId, authentication: "none" },
              scopes: ["repo", "read:user"],
            }),
          );
          expect(connection.callbackUrl, "the callback is connection-specific").toContain(
            "/api/v1/oauth/callback/",
          );
          const authorization = yield* Effect.promise(() =>
            client.authorizeOAuthConnection(source.id, credentialKey, connection.revision),
          );
          const identity = yield* target.newIdentity();
          yield* browser.privateSession(identity, async ({ page, step }) => {
            await step(
              "Follow the provider authorization back to this exact connection",
              async () => {
                await page.goto(authorization.authorizationUrl);
                await page.getByRole("button", { name: /admin/i }).click();
                await page.waitForURL(
                  (url) => url.pathname === "/sources" && url.searchParams.has("oauth"),
                );
                await expect(page.getByText("OAuth authorization completed")).toBeVisible();
                await expect(page.getByText("Connected", { exact: true }).last()).toBeVisible();
              },
            );
          });
          const after = yield* Effect.promise(() => client.getOAuthConnections(source.id));
          expect(after.connections[0]?.status, "the callback exchanged the code").toBe("connected");
          yield* Effect.promise(() => client.refreshSource(source.id));
          yield* browser.session(identity, async ({ page, step }) => {
            await step("Return to Sources and see the managed connection online", async () => {
              await page.goto("/sources");
              await expect(page.getByText(source.displayName, { exact: true })).toBeVisible();
              await expect(page.getByText("Connected", { exact: true }).last()).toBeVisible();
            });
          });
          const tools = yield* Effect.promise(() => client.listTools({ sourceId: source.id }));
          const tool = tools.items.find((candidate) => candidate.stableKey.endsWith("get_me"));
          if (!tool) return yield* Effect.die("the managed OAuth source produced no tool");
          const enabled = yield* Effect.promise(() => client.setToolMode(tool, "enabled"));
          const token = yield* Effect.promise(() => client.createToken(unique("oauth-agent")));
          const callsBefore = (yield* Effect.promise(() => provider.ledger())).filter(
            (entry) => entry.path === "/mcp",
          ).length;
          const invoked = yield* Effect.promise(() =>
            fetch(new URL("/api/v1/gateway/tools/invoke", target.baseUrl), {
              method: "POST",
              headers: {
                authorization: `Bearer ${token.token}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({ path: enabled.callablePath, arguments: {} }),
            }),
          );
          expect(invoked.status, "the connected OAuth tool is callable").toBe(200);
          expect(
            (yield* Effect.promise(() => provider.ledger())).filter(
              (entry) => entry.path === "/mcp" && entry.response.status === 200,
            ).length,
            "the emulator ledger records an authenticated MCP tool call",
          ).toBeGreaterThan(callsBefore);
        }),
        Effect.promise(() => client.deleteSource(source.id)).pipe(Effect.ignore),
      );
    }),
  ),
);
