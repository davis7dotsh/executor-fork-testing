import { createHash, randomBytes, randomUUID } from "node:crypto";
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
import { Effect, Predicate } from "effect";
import type { Page } from "playwright";

import { scenario } from "../src/scenario";
import { LocalAdminClient, type LocalSource, type LocalToken } from "../src/local-admin";
import { serveOAuthTestProvider } from "../src/oauth-test-provider";
import { e2ePort } from "../src/ports";
import { Browser, Target } from "../src/services";
import { LOCAL_ADMIN, LOCAL_SETUP_BASE_URL } from "../targets/local-selfhost";

const unique = (prefix: string) => `${prefix}-${randomBytes(4).toString("hex")}`;
const executeFile = promisify(execFile);
const emulatorPortA = e2ePort("E2E_LOCAL_EMULATOR_A_PORT", 6);
const emulatorPortB = e2ePort("E2E_LOCAL_EMULATOR_B_PORT", 7);
const emulatorPortC = e2ePort("E2E_LOCAL_EMULATOR_C_PORT", 8);

const adminClient = (baseUrl: string) =>
  Effect.promise(() =>
    LocalAdminClient.signIn(baseUrl, LOCAL_ADMIN.username, LOCAL_ADMIN.password),
  );

const isLocalToken = (value: unknown): value is LocalToken =>
  typeof value === "object" &&
  value !== null &&
  "id" in value &&
  typeof value.id === "string" &&
  "token" in value &&
  typeof value.token === "string";

const resendEmulator = Effect.acquireRelease(
  Effect.promise(() => createEmulator({ service: "resend", port: emulatorPortA })),
  (emulator: Emulator) => Effect.promise(() => emulator.close()).pipe(Effect.ignore),
);

const githubEmulator = Effect.acquireRelease(
  Effect.promise(() => createEmulator({ service: "github", port: emulatorPortA })),
  (emulator: Emulator) => Effect.promise(() => emulator.close()).pipe(Effect.ignore),
);

const deleteSources = (client: LocalAdminClient, sources: readonly LocalSource[]) =>
  Effect.forEach(sources, (source) =>
    Effect.promise(() => client.deleteSource(source.id)).pipe(Effect.ignore),
  ).pipe(Effect.asVoid);

const deleteSourcesNamed = (client: LocalAdminClient, names: readonly string[]) =>
  Effect.gen(function* () {
    const sources = yield* Effect.promise(() => client.listSources());
    yield* deleteSources(
      client,
      sources.sources.filter((source) => names.includes(source.displayName)),
    );
  });

const acquireToken = (client: LocalAdminClient, baseUrl: string, name: string) =>
  Effect.acquireRelease(
    Effect.promise(() => client.createToken(name)),
    (token) =>
      Effect.gen(function* () {
        yield* Effect.promise(() =>
          client.revokeToken(token.id).then(
            () => undefined,
            () => undefined,
          ),
        );
        const gatewayStatus = yield* Effect.promise(() =>
          fetch(new URL("/api/v1/gateway/tools/invoke", baseUrl), {
            method: "POST",
            headers: {
              authorization: `Bearer ${token.token}`,
              "content-type": "application/json",
            },
            body: JSON.stringify({ path: "tools.revoked.probe", arguments: {} }),
          }).then(
            (response) => response.status,
            () => 0,
          ),
        );
        if (gatewayStatus !== 401) {
          return yield* Effect.die(`token cleanup left ${token.id} authorized`);
        }
      }),
  );

const openConnectSourcePanel = async (page: Page) => {
  const panel = page.locator("details.import-panel");
  if ((await panel.getAttribute("open")) === null) {
    await panel.locator("summary").click();
  }
};

const prepareInlineOpenApiSource = async (page: Page, document: string, displayName: string) => {
  await page.goto("/sources");
  await openConnectSourcePanel(page);
  await page.getByRole("group", { name: "Source type" }).getByLabel("OpenAPI service").check();
  await page.getByLabel("Paste document").check();
  await page.getByLabel("OpenAPI JSON or YAML").fill(document);
  await page.getByLabel("Allow private network addresses for this source").check();
  await page.getByRole("button", { name: "Preview tools" }).click();
  await expect(page.getByLabel("Source name")).toBeVisible();
  await page.getByLabel("Source name").fill(displayName);
};

const minimalOpenApiDocument = (origin: string, title: string) =>
  JSON.stringify({
    openapi: "3.1.0",
    info: { title, version: "1.0.0" },
    servers: [{ url: origin }],
    paths: {
      "/zen": {
        get: {
          operationId: "readZen",
          summary: "Read Zen",
          responses: { "200": { description: "OK" } },
        },
      },
    },
  });

const staticAuthOpenApiDocument = (githubOrigin: string, spotifyOrigin: string) =>
  JSON.stringify({
    openapi: "3.1.0",
    info: { title: "Executor authentication evidence", version: "1.0.0" },
    servers: [{ url: githubOrigin }],
    components: {
      securitySchemes: {
        basicAuth: { type: "http", scheme: "basic" },
        apiKeyAuth: { type: "apiKey", in: "header", name: "X-Executor-E2E-Key" },
        manualOAuth: {
          type: "oauth2",
          flows: {
            authorizationCode: {
              authorizationUrl: `${githubOrigin}/login/oauth/authorize`,
              tokenUrl: `${githubOrigin}/login/oauth/access_token`,
              scopes: { repo: "Read repositories" },
            },
          },
        },
      },
    },
    paths: {
      "/api/token": {
        post: {
          operationId: "exchangeClientCredentialsWithBasic",
          summary: "Exchange client credentials with Basic",
          servers: [{ url: spotifyOrigin }],
          security: [{ basicAuth: [] }],
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    grant_type: { type: "string", enum: ["client_credentials"] },
                  },
                  required: ["grant_type"],
                  additionalProperties: false,
                },
              },
            },
          },
          responses: { "200": { description: "OK" } },
        },
      },
      "/meta": {
        get: {
          operationId: "readMetaWithApiKey",
          summary: "Read metadata with API key",
          security: [{ apiKeyAuth: [] }],
          responses: { "200": { description: "OK" } },
        },
      },
      "/user": {
        get: {
          operationId: "readCurrentUserWithManualToken",
          summary: "Read current user with manual token",
          security: [{ manualOAuth: ["repo"] }],
          responses: { "200": { description: "OK" } },
        },
      },
    },
  });

const registerMcpOAuthClient = async (issuer: string, redirectUri: string) => {
  const response = await fetch(`${issuer}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_name: "Executor browser e2e",
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  });
  if (!response.ok) throw new Error(`MCP emulator client registration failed (${response.status})`);
  const registration = (await response.json()) as { readonly client_id?: string };
  if (!registration.client_id) {
    throw new Error("MCP emulator client registration returned no client_id");
  }
  return registration.client_id;
};

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
    const client = yield* adminClient(target.baseUrl);
    const tokenNames = [unique("E2E local agent"), unique("E2E local agent")] as const;
    const createdTokens: Array<LocalToken | undefined> = [];
    const tokenCreationGates = tokenNames.map(() => {
      let release = () => {};
      const wait = new Promise<void>((resolve) => {
        release = resolve;
      });
      let requestStarted = false;
      let markStarted = () => {};
      const started = new Promise<void>((resolve) => {
        markStarted = resolve;
      });
      let markSettled = () => {};
      const settled = new Promise<void>((resolve) => {
        markSettled = resolve;
      });
      return {
        wait,
        started,
        settled,
        release: () => release(),
        markStarted: () => {
          requestStarted = true;
          markStarted();
        },
        markSettled: () => markSettled(),
        hasStarted: () => requestStarted,
      };
    });

    expect(tokenNames[0], "sequential runs use different exact names").not.toBe(tokenNames[1]);

    yield* Effect.ensuring(
      Effect.gen(function* () {
        yield* browser.privateSession(
          { label: "signed-out administrator" },
          async ({ page, step }) => {
            const sessionDeletes: string[] = [];
            let tokenCreationIndex = 0;
            let unexpectedTokenPosts = 0;

            page.on("request", (request) => {
              const url = new URL(request.url());
              if (request.method() === "DELETE" && url.pathname === "/api/v1/session") {
                sessionDeletes.push(request.url());
              }
            });
            await page.route("**/api/v1/tokens", async (route) => {
              if (route.request().method() !== "POST") {
                await route.continue();
                return;
              }
              const index = tokenCreationIndex++;
              const gate = tokenCreationGates[index];
              if (gate === undefined) {
                unexpectedTokenPosts += 1;
                await route.abort("failed");
                return;
              }
              gate.markStarted();
              try {
                await gate.wait;
                const response = await route.fetch();
                const body: unknown = await response.json();
                if (!isLocalToken(body)) {
                  throw new Error("token creation returned an invalid response");
                }
                createdTokens[index] = body;
                expect(response.status(), "the token API created one credential").toBe(201);
                await route.fulfill({ response });
              } finally {
                gate.markSettled();
              }
            });

            await step("Sign in and open gateway token management", async () => {
              await page.goto("/login");
              await page.getByLabel("Username").fill(LOCAL_ADMIN.username);
              await page.getByLabel("Password").fill(LOCAL_ADMIN.password);
              await page.getByRole("button", { name: "Sign in" }).click();
              await page.waitForURL((url) => url.pathname === "/sources");
              await page.goto("/tokens");
              await expect(page.getByRole("heading", { name: "API tokens" })).toBeVisible();
            });

            const createAndDismissToken = async (index: number) => {
              const tokenName = tokenNames[index];
              const gate = tokenCreationGates[index];
              if (tokenName === undefined || gate === undefined) {
                throw new Error("token creation run is missing its unique fixture");
              }
              await page.getByLabel("Token name").fill(tokenName);
              try {
                await page.getByRole("button", { name: "Create token" }).click();
                await gate.started;
                await expect(
                  page.getByRole("button", { name: "Creating token..." }),
                ).toBeDisabled();
                await page.getByRole("button", { name: "Sign out" }).click();
                await expect(
                  page.getByRole("status").filter({
                    hasText:
                      "Wait for token creation to finish before leaving this page or signing out.",
                  }),
                ).toBeVisible();
                expect(
                  sessionDeletes,
                  "blocked sign-out does not destroy the administrator session",
                ).toHaveLength(0);
                expect(
                  new URL(page.url()).pathname,
                  "the guarded page stays open during creation",
                ).toBe("/tokens");
              } finally {
                gate.release();
                if (gate.hasStarted()) await gate.settled;
              }

              await expect(page.getByLabel("API token")).toBeVisible();
              const secret = await page.getByLabel("API token").inputValue();
              const created = createdTokens[index];
              if (created === undefined) throw new Error("created token ID was not captured");
              expect(secret.slice(0, 4), "the revealed token has the gateway prefix").toBe("exr_");
              expect(
                createHash("sha256").update(secret).digest("hex"),
                "the one-time reveal matches the captured response without logging the secret",
              ).toBe(createHash("sha256").update(created.token).digest("hex"));
              expect(
                created.id.length,
                "the exact created token ID is retained for cleanup",
              ).toBeGreaterThan(0);

              await page.getByRole("button", { name: "Sign out" }).click();
              await expect(
                page.getByRole("status").filter({
                  hasText:
                    "Save the token and choose “I saved it” before leaving this page or signing out.",
                }),
              ).toBeVisible();
              expect(sessionDeletes, "the unsaved reveal blocks session deletion too").toHaveLength(
                0,
              );
              expect(
                new URL(page.url()).pathname,
                "the revealed secret remains on the guarded page",
              ).toBe("/tokens");
              await page.getByRole("button", { name: "I saved it" }).click();
              await expect(page.getByLabel("API token")).toHaveCount(0);
            };

            await step("Create and safely dismiss the first unique token", async () => {
              await createAndDismissToken(0);
            });
            await step("Create and safely dismiss the second unique token", async () => {
              await createAndDismissToken(1);
            });
            await step("Sign out only after both one-time reveals are gone", async () => {
              const sessionDelete = page.waitForRequest((request) => {
                const url = new URL(request.url());
                return request.method() === "DELETE" && url.pathname === "/api/v1/session";
              });
              await page.getByRole("button", { name: "Sign out" }).click();
              await sessionDelete;
              await page.waitForURL((url) => url.pathname === "/login");
              expect(
                sessionDeletes,
                "acknowledgement permits exactly one session deletion",
              ).toHaveLength(1);
              expect(unexpectedTokenPosts, "two runs issued exactly two token POSTs").toBe(0);
            });
          },
        );

        expect(
          createdTokens.filter(Predicate.isNotUndefined),
          "both sequential runs captured their exact token IDs",
        ).toHaveLength(2);
        const identity = yield* target.newIdentity();
        yield* browser.session(identity, async ({ page, step }) => {
          try {
            await step("See only masked metadata for both exact unique token rows", async () => {
              await page.goto("/tokens");
              for (const tokenName of tokenNames) {
                const exactName = page.getByText(tokenName, { exact: true });
                const row = page.locator("tbody tr").filter({ has: exactName });
                await expect(row, `${tokenName} selects one repeat-safe row`).toHaveCount(1);
                await expect(row.locator('td[data-label="Status"]')).toContainText("Active");
                await expect(row.locator('td[data-label="Token"] code')).toContainText("...");
              }
            });
            await step("Revoke one exact token from the dashboard", async () => {
              const tokenName = tokenNames[0];
              const token = createdTokens[0];
              if (token === undefined) throw new Error("the first created token was not captured");
              const row = page.locator("tbody tr").filter({
                has: page.getByText(tokenName, { exact: true }),
              });
              await row.getByRole("button", { name: `Revoke ${tokenName}` }).click();
              const confirmation = page.getByRole("dialog", {
                name: `Stop using ${tokenName}?`,
              });
              await expect(confirmation).toBeVisible();
              await confirmation.getByRole("button", { name: "Revoke token" }).click();
              await expect(row.locator('td[data-label="Status"]')).toContainText("Revoked");

              const rejected = await fetch(
                new URL("/api/v1/gateway/tools/invoke", target.baseUrl),
                {
                  method: "POST",
                  headers: {
                    authorization: `Bearer ${token.token}`,
                    "content-type": "application/json",
                  },
                  body: JSON.stringify({ path: "tools.revoked.probe", arguments: {} }),
                },
              );
              expect(rejected.status, "dashboard revocation immediately rejects the token").toBe(
                401,
              );
            });
          } finally {
            await step("End the recorded administrator session", async () => {
              const csrf = identity.cookies?.find(
                (cookie) => cookie.name === "executor_csrf",
              )?.value;
              if (csrf === undefined) {
                throw new Error("the recorded administrator identity has no CSRF cookie");
              }
              const response = await fetch(new URL("/api/v1/session", target.baseUrl), {
                method: "DELETE",
                headers: {
                  ...identity.headers,
                  origin: new URL(target.baseUrl).origin,
                  "x-executor-csrf": csrf,
                },
              });
              expect(
                response.status,
                "the traced administrator cookie is invalidated before artifacts close",
              ).toBe(204);
              await page.goto("/login");
              await expect(page.getByLabel("Username")).toBeVisible();
            });
          }
        });
      }),
      Effect.gen(function* () {
        for (const gate of tokenCreationGates) gate.release();
        yield* Effect.promise(() =>
          Promise.all(
            tokenCreationGates.filter((gate) => gate.hasStarted()).map((gate) => gate.settled),
          ),
        );
        const captured = createdTokens.filter(Predicate.isNotUndefined);
        const outcomes = yield* Effect.forEach(
          captured,
          (token) =>
            Effect.promise(async () => {
              await client.revokeToken(token.id).then(
                () => undefined,
                () => undefined,
              );
              const gatewayStatus = await fetch(
                new URL("/api/v1/gateway/tools/invoke", target.baseUrl),
                {
                  method: "POST",
                  headers: {
                    authorization: `Bearer ${token.token}`,
                    "content-type": "application/json",
                  },
                  body: JSON.stringify({ path: "tools.revoked.probe", arguments: {} }),
                },
              ).then(
                (response) => response.status,
                () => 0,
              );
              return { id: token.id, gatewayStatus };
            }),
          { concurrency: "unbounded" },
        );
        createdTokens.length = 0;
        for (const outcome of outcomes) {
          expect(
            outcome.gatewayStatus,
            `captured token ${outcome.id} is revoked and unauthorized`,
          ).toBe(401);
        }
      }),
    );
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

          const token = yield* acquireToken(client, target.baseUrl, unique("source-agent"));
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
  "Sources dashboard · every protocol, static auth family, and managed OAuth work end to end",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const githubToken = unique("github-token");
      const mcpToken = unique("mcp-token");
      const spotifyClientId = unique("spotify-client");
      const basicPassword = unique("basic-password");
      const apiKey = unique("api-key");
      const stdioSecret = unique("stdio-secret");
      const stdioSecretDigest = createHash("sha256").update(stdioSecret).digest("hex");
      const github = yield* Effect.acquireRelease(
        Effect.promise(() =>
          createEmulator({
            service: "github",
            port: emulatorPortA,
            seed: {
              tokens: { [githubToken]: { login: "octocat", scopes: ["repo"] } },
              github: {
                users: [{ login: "octocat", name: "The Octocat", email: "octocat@example.test" }],
              },
            },
          }),
        ),
        (emulator) => Effect.promise(() => emulator.close()).pipe(Effect.ignore),
      );
      const staticMcp = yield* Effect.acquireRelease(
        Effect.promise(() =>
          createEmulator({
            service: "mcp",
            port: emulatorPortB,
            seed: {
              tokens: { [mcpToken]: { login: "admin", scopes: ["repo", "read:user"] } },
            },
          }),
        ),
        (emulator) => Effect.promise(() => emulator.close()).pipe(Effect.ignore),
      );
      const spotify = yield* Effect.acquireRelease(
        Effect.promise(() =>
          createEmulator({
            service: "spotify",
            port: emulatorPortC,
            seed: {
              spotify: {
                clients: [
                  {
                    client_id: spotifyClientId,
                    client_secret: basicPassword,
                    name: "Executor browser e2e",
                  },
                ],
              },
            },
          }),
        ),
        (emulator) => Effect.promise(() => emulator.close()).pipe(Effect.ignore),
      );
      const provider = {
        issuer: staticMcp.url,
        endpoint: `${staticMcp.url}/mcp`,
        registerClient: (redirectUri: string) => registerMcpOAuthClient(staticMcp.url, redirectUri),
        ledger: () => staticMcp.ledger.list(),
      };
      const suffix = randomBytes(3).toString("hex");
      const names = {
        openapi: `Browser OpenAPI ${suffix}`,
        graphql: `Browser GraphQL ${suffix}`,
        mcpHttp: `Browser MCP HTTP ${suffix}`,
        mcpStdio: `Browser MCP stdio ${suffix}`,
        managedOAuth: `Browser managed OAuth ${suffix}`,
      } as const;
      const createdNames = Object.values(names);

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.privateSession(identity, async ({ page, step }) => {
            await step("Import OpenAPI with Basic, API key, and a manual OAuth token", async () => {
              await prepareInlineOpenApiSource(
                page,
                staticAuthOpenApiDocument(github.url, spotify.url),
                names.openapi,
              );
              await page.getByRole("checkbox", { name: /basicAuth/ }).check();
              await page.getByLabel("Username").fill(spotifyClientId);
              await page.getByLabel("Basic auth", { exact: true }).fill(basicPassword);
              await page.getByRole("checkbox", { name: /apiKeyAuth/ }).check();
              await page.getByLabel("API key", { exact: true }).fill(apiKey);
              await page.getByRole("checkbox", { name: /manualOAuth/ }).check();
              await page
                .getByLabel("OAuth access token (manual, advanced)", { exact: true })
                .fill(githubToken);
              await page.getByRole("button", { name: "Import source" }).click();
              await expect(page.getByRole("heading", { name: names.openapi })).toBeVisible();
            });

            await step("Connect GraphQL with a bearer token", async () => {
              await page.goto("/sources");
              await openConnectSourcePanel(page);
              await page
                .getByRole("group", { name: "Source type" })
                .getByLabel("GraphQL API")
                .check();
              await page.getByLabel("Endpoint").fill(`${github.url}/graphql`);
              await page.getByLabel("Source name").fill(names.graphql);
              await page.getByLabel("Allow private network addresses for this source").check();
              await page.getByLabel("Method").selectOption("bearer");
              await page.getByLabel("Bearer token").fill(githubToken);
              await page.getByRole("button", { name: "Connect source" }).click();
              await expect(page.getByRole("heading", { name: names.graphql })).toBeVisible();
            });

            await step("Connect MCP HTTP with a manually managed access token", async () => {
              await page.goto("/sources");
              await openConnectSourcePanel(page);
              await page
                .getByRole("group", { name: "Source type" })
                .getByLabel("MCP over HTTP")
                .check();
              await page.getByLabel("Endpoint").fill(`${staticMcp.url}/mcp`);
              await page.getByLabel("Source name").fill(names.mcpHttp);
              await page.getByLabel("Allow private network addresses for this source").check();
              await page.getByLabel("Method").selectOption("oauth_access_token");
              await page.getByLabel("OAuth access token").fill(mcpToken);
              await page.getByRole("button", { name: "Connect source" }).click();
              await expect(page.getByRole("heading", { name: names.mcpHttp })).toBeVisible();
            });

            await step("Connect the trusted local MCP stdio template", async () => {
              await page.goto("/sources");
              await openConnectSourcePanel(page);
              await page
                .getByRole("group", { name: "Source type" })
                .getByLabel("Trusted local MCP template")
                .check();
              await page
                .getByLabel("Trusted template")
                .selectOption({ label: "executor-e2e-stdio" });
              await page.getByLabel("Source name").fill(names.mcpStdio);
              await page.getByLabel("EXECUTOR_E2E_STDIO_SECRET").fill(stdioSecret);
              await page.getByRole("button", { name: "Connect source" }).click();
              await expect(page.getByRole("heading", { name: names.mcpStdio })).toBeVisible();
            });

            await step("Configure and connect managed OAuth from the dashboard", async () => {
              await page.goto("/sources");
              await openConnectSourcePanel(page);
              await page
                .getByRole("group", { name: "Source type" })
                .getByLabel("MCP over HTTP")
                .check();
              await page.getByLabel("Endpoint").fill(provider.endpoint);
              await page.getByLabel("Source name").fill(names.managedOAuth);
              await page.getByLabel("Allow private network addresses for this source").check();
              await page.getByRole("button", { name: "Connect source" }).click();
              await expect(page.getByRole("heading", { name: names.managedOAuth })).toBeVisible();

              const oauth = page.getByRole("region", {
                name: `Managed OAuth for ${names.managedOAuth}`,
              });
              await expect(oauth.getByLabel("Client ID")).toBeVisible();
              await oauth
                .getByLabel("Authorization server override (optional)")
                .fill(provider.issuer);
              await oauth.getByLabel("Client ID").fill("pending-browser-registration");
              await oauth.getByLabel("Requested scopes").fill("repo read:user");
              await oauth.getByRole("button", { name: "Save configuration" }).click();
              const callback = oauth.getByLabel("Exact callback URL");
              await expect(callback).toBeVisible();
              const clientId = await provider.registerClient(await callback.inputValue());
              await oauth.getByLabel("Client ID").fill(clientId);
              await oauth.getByRole("button", { name: "Save configuration" }).click();
              await expect(oauth.getByText("OAuth configuration saved")).toBeVisible();
              await oauth.getByRole("button", { name: "Connect OAuth" }).click();
              await page.getByRole("button", { name: /admin/i }).click();
              await page.waitForURL(
                (url) => url.pathname === "/sources" && url.searchParams.has("oauth"),
              );
              await expect(page.getByText("OAuth authorization completed")).toBeVisible();
              const connectedOauth = page.getByRole("region", {
                name: `Managed OAuth for ${names.managedOAuth}`,
              });
              await expect(connectedOauth.getByText("Connected", { exact: true })).toBeVisible();
              const card = page.getByRole("article").filter({
                has: page.getByRole("heading", { name: names.managedOAuth, exact: true }),
              });
              await card.getByRole("button", { name: "Reconnect and refresh tools" }).click();
              await expect(page.locator("#source-status")).toContainText("Source refreshed:");
            });
          });

          const stored = yield* Effect.promise(() => client.listSources());
          const byName = (name: string) => {
            const source = stored.sources.find((candidate) => candidate.displayName === name);
            if (!source) throw new Error(`browser source was not stored: ${name}`);
            return source;
          };
          const sources = {
            openapi: byName(names.openapi),
            graphql: byName(names.graphql),
            mcpHttp: byName(names.mcpHttp),
            mcpStdio: byName(names.mcpStdio),
            managedOAuth: byName(names.managedOAuth),
          };
          const gatewayToken = yield* acquireToken(
            client,
            target.baseUrl,
            unique("browser-source-agent"),
          );
          const invoke = async (
            source: LocalSource,
            label: RegExp,
            arguments_: Readonly<Record<string, unknown>> = {},
          ) => {
            const catalog = await client.listTools({ sourceId: source.id });
            const tool = catalog.items.find((candidate) =>
              label.test(`${candidate.stableKey} ${candidate.displayName}`),
            );
            if (!tool) throw new Error(`${source.displayName} did not expose ${label.source}`);
            const enabled = await client.setToolMode(tool, "enabled");
            const response = await fetch(new URL("/api/v1/gateway/tools/invoke", target.baseUrl), {
              method: "POST",
              headers: {
                authorization: `Bearer ${gatewayToken.token}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({ path: enabled.callablePath, arguments: arguments_ }),
            });
            const body = await response.text();
            expect(response.status, `${source.displayName} invokes through the gateway`).toBe(200);
            return body;
          };

          yield* Effect.promise(() =>
            invoke(sources.openapi, /client.*credentials.*basic/i, {
              body: { grant_type: "client_credentials" },
            }),
          );
          const spotifyLedger = yield* Effect.promise(() => spotify.ledger.list());
          const basicCall = spotifyLedger.find((entry) => entry.path === "/api/token");
          expect(
            basicCall?.request.headers.authorization,
            "Spotify observed the HTTP Basic header",
          ).toBe("[redacted]");
          expect(
            basicCall?.response.status,
            "Spotify accepted the exact seeded Basic username and password",
          ).toBe(200);
          yield* Effect.promise(() => invoke(sources.openapi, /meta.*api.*key/i));
          yield* Effect.promise(() => invoke(sources.openapi, /current.*user.*manual/i));
          yield* Effect.promise(() => invoke(sources.graphql, /viewer/i));
          yield* Effect.promise(() => invoke(sources.mcpHttp, /get_me/i));
          const staticMcpLedger = yield* Effect.promise(() => staticMcp.ledger.list());
          const staticMcpCall = staticMcpLedger.find(
            (entry) =>
              entry.path === "/mcp" && JSON.stringify(entry.request.body).includes("get_me"),
          );
          expect(
            staticMcpCall?.request.headers.authorization,
            "the MCP emulator observed its manual access token",
          ).toBe("[redacted]");
          expect(staticMcpCall?.identity.user?.login).toBe("admin");
          const mcpToolCallsBeforeOAuth = staticMcpLedger.filter(
            (entry) =>
              entry.path === "/mcp" && JSON.stringify(entry.request.body).includes("get_me"),
          ).length;
          const stdioResult = yield* Effect.promise(() =>
            invoke(sources.mcpStdio, /secret_status/i),
          );
          expect(
            stdioResult,
            "the stdio process receives the exact encrypted template secret",
          ).toContain(`secret-sha256:${stdioSecretDigest}`);
          yield* Effect.promise(() => invoke(sources.managedOAuth, /get_me/i));

          const githubLedger = yield* Effect.promise(() => github.ledger.list());
          const githubCall = (path: string) => {
            const entry = githubLedger.find((candidate) => candidate.path === path);
            if (!entry) throw new Error(`GitHub emulator did not observe ${path}`);
            return entry;
          };
          expect(
            githubCall("/meta").request.headers["x-executor-e2e-key"],
            "the emulator observed the configured API key header",
          ).toBe(apiKey);
          expect(
            githubCall("/user").identity.user?.login,
            "the manual OAuth token authenticated its upstream request",
          ).toBe("octocat");
          const graphqlCall = githubLedger.find(
            (candidate) =>
              candidate.path === "/graphql" &&
              !JSON.stringify(candidate.request.body).includes("__schema"),
          );
          expect(
            graphqlCall?.identity.user?.login,
            "the GraphQL bearer token authenticated a non-introspection query",
          ).toBe("octocat");

          const oauthLedger = yield* Effect.promise(() => provider.ledger());
          const oauthToolCall = oauthLedger.find(
            (entry) =>
              entry.path === "/mcp" && JSON.stringify(entry.request.body).includes("get_me"),
          );
          expect(
            oauthToolCall?.identity.user?.login,
            "the managed OAuth token authenticated the upstream MCP call",
          ).toBe("admin");
          expect(
            oauthLedger.filter(
              (entry) =>
                entry.path === "/mcp" && JSON.stringify(entry.request.body).includes("get_me"),
            ).length,
            "managed OAuth added one independently authenticated tool call",
          ).toBe(mcpToolCallsBeforeOAuth + 1);

          yield* browser.session(identity, async ({ page, step }) => {
            await step(
              "Review every browser-created source in the redesigned dashboard",
              async () => {
                await page.goto("/sources");
                for (const name of createdNames) {
                  await expect(page.getByRole("heading", { name, exact: true })).toBeVisible();
                }
                await expect(
                  page.getByRole("region", { name: `Managed OAuth for ${names.managedOAuth}` }),
                ).toContainText("Connected");
              },
            );
            await step(
              "Open the shared tool catalog from the browser-created OpenAPI source",
              async () => {
                const card = page.getByRole("article").filter({
                  has: page.getByRole("heading", { name: names.openapi, exact: true }),
                });
                await card.getByRole("link", { name: "View tools" }).click();
                await expect(page.getByRole("table")).toContainText(
                  "Exchange client credentials with Basic",
                );
              },
            );
          });
        }),
        Effect.gen(function* () {
          yield* deleteSourcesNamed(client, createdNames);
        }),
      );
    }),
  ),
);

scenario(
  "Source creation recovery · a committed plain-text 502 reloads as exactly one source",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const github = yield* githubEmulator;
      const sourceName = unique("Committed replay");

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            let postCount = 0;
            let releaseLookup = () => {};
            const lookupGate = new Promise<void>((resolve) => {
              releaseLookup = resolve;
            });
            let markLookupStarted = () => {};
            const lookupStarted = new Promise<void>((resolve) => {
              markLookupStarted = resolve;
            });
            let lookupCount = 0;
            let replayResponse:
              | { readonly status: number; readonly headers: Record<string, string> }
              | undefined;

            await page.route("**/api/v1/sources/idempotency", async (route) => {
              if (route.request().method() !== "GET") {
                await route.continue();
                return;
              }
              lookupCount += 1;
              if (lookupCount === 1) {
                markLookupStarted();
                await lookupGate;
                await route.abort("aborted").catch(() => {});
                return;
              }
              if (lookupCount === 2) {
                await route.fulfill({
                  status: 200,
                  headers: {
                    "cache-control": "no-store",
                    "content-type": "application/json",
                  },
                  body: JSON.stringify({ status: "in_progress" }),
                });
                return;
              }
              const replay = await route.fetch();
              replayResponse = { status: replay.status(), headers: replay.headers() };
              await route.fulfill({ response: replay });
            });
            await page.route("**/api/v1/sources", async (route) => {
              if (route.request().method() !== "POST") {
                await route.continue();
                return;
              }
              postCount += 1;
              const committed = await route.fetch();
              expect(committed.status(), "the real API committed before delivery failed").toBe(201);
              await route.fulfill({
                status: 502,
                headers: { "content-type": "text/plain; charset=utf-8" },
                body: "gateway lost the committed response",
              });
            });

            await step("Reload the ambiguous create and recover its committed result", async () => {
              await prepareInlineOpenApiSource(
                page,
                minimalOpenApiDocument(github.url, sourceName),
                sourceName,
              );
              await page.getByRole("button", { name: "Import source" }).click();
              try {
                await lookupStarted;
                const pendingKeys = await page.evaluate(() => Object.values(sessionStorage));
                expect(pendingKeys, "one opaque key survives the ambiguous response").toHaveLength(
                  1,
                );
                expect(pendingKeys[0]).toMatch(/^[0-9a-f]{32}$/);
                const reloaded = page.reload();
                releaseLookup();
                await reloaded;
                await expect(
                  page.getByRole("status").filter({
                    hasText: "Executor is still finishing this source connection.",
                  }),
                ).toBeVisible();
                await expect(page.getByRole("heading", { name: sourceName })).toBeVisible();
                await expect.poll(() => page.evaluate(() => sessionStorage.length)).toBe(0);
              } finally {
                releaseLookup();
              }
              expect(postCount, "reload recovery never issued a second create").toBe(1);
              expect(
                lookupCount,
                "recovery polled after an in-progress status",
              ).toBeGreaterThanOrEqual(3);
              expect(replayResponse?.status, "the completed lookup replays HTTP 201").toBe(201);
              expect(
                replayResponse?.headers["idempotency-replayed"],
                "the browser accepted the real replay marker",
              ).toBe("true");
              expect(
                replayResponse?.headers["cache-control"],
                "replay handling remains explicitly uncached",
              ).toBe("no-store");
            });
          });

          const stored = yield* Effect.promise(() => client.listSources());
          expect(
            stored.sources.filter((source) => source.displayName === sourceName),
            "the committed key resolves to exactly one durable source",
          ).toHaveLength(1);
        }),
        deleteSourcesNamed(client, [sourceName]),
      );
    }),
  ),
);

scenario(
  "Source creation recovery · a hard reload seals a missing request before unlocking",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const github = yield* githubEmulator;
      const sourceName = unique("Missing sealed");

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            let postCount = 0;
            let sealCount = 0;
            let releaseLookup = () => {};
            const lookupGate = new Promise<void>((resolve) => {
              releaseLookup = resolve;
            });
            let markLookupStarted = () => {};
            const lookupStarted = new Promise<void>((resolve) => {
              markLookupStarted = resolve;
            });
            let firstLookup = true;

            await page.route("**/api/v1/sources", async (route) => {
              if (route.request().method() !== "POST") {
                await route.continue();
                return;
              }
              postCount += 1;
              await route.abort("connectionreset");
            });
            await page.route("**/api/v1/sources/idempotency", async (route) => {
              if (route.request().method() === "GET" && firstLookup) {
                firstLookup = false;
                markLookupStarted();
                await lookupGate;
                await route.abort("aborted").catch(() => {});
                return;
              }
              await route.continue();
            });
            await page.route("**/api/v1/sources/idempotency/seal", async (route) => {
              if (route.request().method() === "POST") sealCount += 1;
              await route.continue();
            });

            await step("Reload after delivery loss and seal the server's missing key", async () => {
              await prepareInlineOpenApiSource(
                page,
                minimalOpenApiDocument(github.url, sourceName),
                sourceName,
              );
              await page.getByRole("button", { name: "Import source" }).click();
              try {
                await lookupStarted;
                const unload = await page.evaluate(() => {
                  const event = new Event("beforeunload", { cancelable: true });
                  return {
                    dispatched: window.dispatchEvent(event),
                    defaultPrevented: event.defaultPrevented,
                  };
                });
                expect(
                  unload,
                  "recovery allows a real reload because no request is being dispatched",
                ).toEqual({ dispatched: true, defaultPrevented: false });
                const reloaded = page.reload();
                releaseLookup();
                await reloaded;
                await expect(
                  page.getByText(
                    "The unused source connection key was sealed. You can start a new request.",
                  ),
                ).toBeVisible();
                await expect.poll(() => page.evaluate(() => sessionStorage.length)).toBe(0);
              } finally {
                releaseLookup();
              }
              expect(postCount, "reload recovery did not redispatch the lost payload").toBe(1);
              expect(sealCount, "one seal permanently fences the unused key").toBe(1);
            });
          });

          const stored = yield* Effect.promise(() => client.listSources());
          expect(stored.sources.filter((source) => source.displayName === sourceName)).toHaveLength(
            0,
          );
        }),
        deleteSourcesNamed(client, [sourceName]),
      );
    }),
  ),
);

scenario(
  "Source creation recovery · failed delivery retries the same key and exact payload",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const github = yield* githubEmulator;
      const sourceName = unique("Exact retry");

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            const attempts: Array<{ readonly key: string | undefined; readonly body: string }> = [];
            await page.route("**/api/v1/sources", async (route) => {
              if (route.request().method() !== "POST") {
                await route.continue();
                return;
              }
              attempts.push({
                key: route.request().headers()["idempotency-key"],
                body: route.request().postData() ?? "",
              });
              if (attempts.length <= 2) {
                await route.abort("connectionreset");
                return;
              }
              await route.continue();
            });

            await step("Retry one in-memory request until the real API receives it", async () => {
              await prepareInlineOpenApiSource(
                page,
                minimalOpenApiDocument(github.url, sourceName),
                sourceName,
              );
              await page.getByRole("button", { name: "Import source" }).click();
              const retry = page.getByRole("button", { name: "Retry exact request" });
              await expect(retry).toBeVisible();
              expect(attempts, "initial delivery and its automatic retry both failed").toHaveLength(
                2,
              );
              expect(
                attempts.map((attempt) => attempt.key),
                "the automatic retry retained one idempotency key",
              ).toEqual([attempts[0]?.key, attempts[0]?.key]);
              expect(
                attempts.map((attempt) => attempt.body),
                "the automatic retry retained byte-identical JSON",
              ).toEqual([attempts[0]?.body, attempts[0]?.body]);

              await retry.click();
              await expect(page.getByRole("heading", { name: sourceName })).toBeVisible();
              expect(attempts, "the deliberate retry reached the server").toHaveLength(3);
              expect(attempts[2]?.key).toBe(attempts[0]?.key);
              expect(attempts[2]?.body).toBe(attempts[0]?.body);
              expect(attempts[0]?.key).toMatch(/^[0-9a-f]{32}$/);
            });
          });

          const stored = yield* Effect.promise(() => client.listSources());
          expect(stored.sources.filter((source) => source.displayName === sourceName)).toHaveLength(
            1,
          );
        }),
        deleteSourcesNamed(client, [sourceName]),
      );
    }),
  ),
);

scenario(
  "Source creation recovery · a lost failed response replays its exact error and headers",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const github = yield* githubEmulator;
      const sourceName = unique("Failed replay");

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            let postCount = 0;
            let releaseFirstLookup = () => {};
            const firstLookupGate = new Promise<void>((resolve) => {
              releaseFirstLookup = resolve;
            });
            let markFirstLookupStarted = () => {};
            const firstLookupStarted = new Promise<void>((resolve) => {
              markFirstLookupStarted = resolve;
            });
            let firstLookup = true;
            let originalFailure:
              | {
                  readonly status: number;
                  readonly body: string;
                  readonly headers: Record<string, string>;
                }
              | undefined;
            let replayFailure:
              | {
                  readonly status: number;
                  readonly body: string;
                  readonly headers: Record<string, string>;
                }
              | undefined;

            await page.route("**/api/v1/sources", async (route) => {
              if (route.request().method() !== "POST") {
                await route.continue();
                return;
              }
              postCount += 1;
              const failed = await route.fetch({
                postData: JSON.stringify({
                  kind: "openapi",
                  displayName: sourceName,
                  preferredSlug: unique("invalid-replay"),
                  spec: { type: "inline", content: "not an OpenAPI document" },
                }),
              });
              originalFailure = {
                status: failed.status(),
                body: await failed.text(),
                headers: failed.headers(),
              };
              await route.fulfill({
                status: 502,
                headers: { "content-type": "text/plain; charset=utf-8" },
                body: "gateway lost the failed response",
              });
            });
            await page.route("**/api/v1/sources/idempotency", async (route) => {
              if (firstLookup) {
                firstLookup = false;
                markFirstLookupStarted();
                await firstLookupGate;
                await route.abort("aborted").catch(() => {});
                return;
              }
              const replay = await route.fetch();
              const body = await replay.text();
              replayFailure = {
                status: replay.status(),
                body,
                headers: replay.headers(),
              };
              await route.fulfill({
                status: replay.status(),
                headers: replay.headers(),
                body,
              });
            });

            await step(
              "Recover the server's exact failed result after its response is lost",
              async () => {
                await prepareInlineOpenApiSource(
                  page,
                  minimalOpenApiDocument(github.url, sourceName),
                  sourceName,
                );
                await page.getByRole("button", { name: "Import source" }).click();
                try {
                  await firstLookupStarted;
                  const reloaded = page.reload();
                  releaseFirstLookup();
                  await reloaded;
                } finally {
                  releaseFirstLookup();
                }
                await expect(page.locator("#source-create-status")).toBeVisible();
                await expect.poll(() => page.evaluate(() => sessionStorage.length)).toBe(0);
                expect(postCount, "failed replay recovery never resubmits the source").toBe(1);
                expect(replayFailure?.status).toBe(originalFailure?.status);
                expect(replayFailure?.body, "the replay body is byte-identical").toBe(
                  originalFailure?.body,
                );
                expect(replayFailure?.headers["content-type"]).toBe(
                  originalFailure?.headers["content-type"],
                );
                const originalRequestReference = JSON.parse(originalFailure?.body ?? "{}") as {
                  readonly error?: { readonly requestId?: string };
                };
                const replayRequestReference = JSON.parse(replayFailure?.body ?? "{}") as {
                  readonly error?: { readonly requestId?: string };
                };
                expect(originalRequestReference.error?.requestId).toMatch(/\S+/);
                expect(replayRequestReference.error?.requestId).toBe(
                  originalRequestReference.error?.requestId,
                );
                expect(replayFailure?.headers["idempotency-replayed"]).toBe("true");
                expect(replayFailure?.headers["cache-control"]).toBe(
                  originalFailure?.headers["cache-control"],
                );
              },
            );
          });

          const stored = yield* Effect.promise(() => client.listSources());
          expect(stored.sources.filter((source) => source.displayName === sourceName)).toHaveLength(
            0,
          );
        }),
        deleteSourcesNamed(client, [sourceName]),
      );
    }),
  ),
);

scenario(
  "Source creation recovery · a duplicated tab joins one pending attempt without another POST",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const github = yield* githubEmulator;
      const sourceName = unique("Duplicated tab");

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            let releaseOriginal = () => {};
            const originalGate = new Promise<void>((resolve) => {
              releaseOriginal = resolve;
            });
            let markCommitted = () => {};
            const committed = new Promise<void>((resolve) => {
              markCommitted = resolve;
            });
            let postCount = 0;
            page.context().on("request", (request) => {
              const url = new URL(request.url());
              if (request.method() === "POST" && url.pathname === "/api/v1/sources") {
                postCount += 1;
              }
            });
            await page.route("**/api/v1/sources", async (route) => {
              if (route.request().method() !== "POST") {
                await route.continue();
                return;
              }
              const response = await route.fetch();
              expect(response.status(), "the pending browser delivery committed once").toBe(201);
              markCommitted();
              await originalGate;
              await route.fulfill({ response });
            });

            await step("Duplicate the pending tab and recover from its copied key", async () => {
              await prepareInlineOpenApiSource(
                page,
                minimalOpenApiDocument(github.url, sourceName),
                sourceName,
              );
              await page.getByRole("button", { name: "Import source" }).click();
              let clone: Page | null = null;
              try {
                await committed;
                expect(await page.evaluate(() => sessionStorage.length)).toBe(1);
                const popup = page.waitForEvent("popup");
                await page.evaluate(() => {
                  window.open("/sources", "_blank");
                });
                clone = await popup;
                await expect(clone.getByRole("heading", { name: sourceName })).toBeVisible();
                await expect.poll(() => clone?.evaluate(() => sessionStorage.length)).toBe(0);
                expect(postCount, "the duplicated tab used lookup instead of POST").toBe(1);
              } finally {
                releaseOriginal();
              }
              await expect(page.getByRole("heading", { name: sourceName })).toBeVisible();
              expect(postCount, "both tabs converge on the original POST").toBe(1);
              await clone?.close();
            });
          });

          const stored = yield* Effect.promise(() => client.listSources());
          expect(stored.sources.filter((source) => source.displayName === sourceName)).toHaveLength(
            1,
          );
        }),
        deleteSourcesNamed(client, [sourceName]),
      );
    }),
  ),
);

scenario(
  "Source creation recovery · signing out during lookup never redispatches the request",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const github = yield* githubEmulator;
      const sourceName = unique("Signout recovery");

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.privateSession(identity, async ({ page, step }) => {
            let postCount = 0;
            let sealCount = 0;
            let sessionDeleteCount = 0;
            let releaseLookup = () => {};
            const lookupGate = new Promise<void>((resolve) => {
              releaseLookup = resolve;
            });
            let markLookupStarted = () => {};
            const lookupStarted = new Promise<void>((resolve) => {
              markLookupStarted = resolve;
            });
            let markLookupSettled = () => {};
            const lookupSettled = new Promise<void>((resolve) => {
              markLookupSettled = resolve;
            });
            let releaseSessionDelete = () => {};
            const sessionDeleteGate = new Promise<void>((resolve) => {
              releaseSessionDelete = resolve;
            });
            let markSessionDeleteStarted = () => {};
            const sessionDeleteStarted = new Promise<void>((resolve) => {
              markSessionDeleteStarted = resolve;
            });
            let holdFirstLookup = true;
            await page.route("**/api/v1/sources", async (route) => {
              if (route.request().method() !== "POST") {
                await route.continue();
                return;
              }
              postCount += 1;
              const committed = await route.fetch();
              await route.fulfill({
                status: 502,
                headers: { "content-type": "text/plain; charset=utf-8" },
                body: "gateway lost the committed response",
              });
              expect(committed.status()).toBe(201);
            });
            await page.route("**/api/v1/sources/idempotency", async (route) => {
              if (route.request().method() === "GET" && holdFirstLookup) {
                holdFirstLookup = false;
                markLookupStarted();
                await lookupGate;
                await route.abort("aborted").catch(() => {});
                markLookupSettled();
                return;
              }
              await route.continue();
            });
            await page.route("**/api/v1/sources/idempotency/seal", async (route) => {
              if (route.request().method() === "POST") sealCount += 1;
              await route.continue();
            });
            await page.route("**/api/v1/session", async (route) => {
              if (route.request().method() !== "DELETE") {
                await route.continue();
                return;
              }
              sessionDeleteCount += 1;
              markSessionDeleteStarted();
              await sessionDeleteGate;
              await route.continue();
            });

            await step(
              "Sign out during recovery, sign back in, and join the committed result",
              async () => {
                await prepareInlineOpenApiSource(
                  page,
                  minimalOpenApiDocument(github.url, sourceName),
                  sourceName,
                );
                await page.getByRole("button", { name: "Import source" }).click();
                try {
                  await lookupStarted;
                  const unload = await page.evaluate(() => {
                    const event = new Event("beforeunload", { cancelable: true });
                    return {
                      dispatched: window.dispatchEvent(event),
                      defaultPrevented: event.defaultPrevented,
                    };
                  });
                  expect(unload, "recovery permits session navigation").toEqual({
                    dispatched: true,
                    defaultPrevented: false,
                  });
                  const signOut = page.getByRole("button", { name: "Sign out" }).click();
                  await sessionDeleteStarted;
                  expect(
                    new URL(page.url()).pathname,
                    "the recovery page remains mounted while session deletion is in flight",
                  ).toBe("/sources");
                  expect(await page.evaluate(() => sessionStorage.length)).toBe(1);
                  releaseLookup();
                  await lookupSettled;
                  await page.evaluate(
                    () =>
                      new Promise<void>((resolve) => {
                        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
                      }),
                  );
                  expect(
                    postCount,
                    "settled lookup did not redispatch while DELETE was gated",
                  ).toBe(1);
                  expect(sealCount, "sign-out pause never seals the recoverable key").toBe(0);
                  expect(
                    await page.evaluate(() => sessionStorage.length),
                    "the pending key survives the lookup and session-delete race",
                  ).toBe(1);
                  releaseSessionDelete();
                  await signOut;
                  await page.waitForURL((url) => url.pathname === "/login");
                  expect(sessionDeleteCount, "recovery permits one deliberate sign-out").toBe(1);
                  expect(
                    await page.evaluate(() => sessionStorage.length),
                    "the key remains available to the next authenticated Sources page",
                  ).toBe(1);

                  await page.getByLabel("Username").fill(LOCAL_ADMIN.username);
                  await page.getByLabel("Password").fill(LOCAL_ADMIN.password);
                  await page.getByRole("button", { name: "Sign in" }).click();
                  await page.waitForURL((url) => url.pathname === "/sources");
                  await expect(page.getByRole("heading", { name: sourceName })).toBeVisible();
                  await expect.poll(() => page.evaluate(() => sessionStorage.length)).toBe(0);
                  expect(postCount, "authenticated recovery still uses the original POST").toBe(1);
                  expect(sealCount, "authenticated recovery never seals a committed key").toBe(0);
                } finally {
                  releaseLookup();
                  releaseSessionDelete();
                }
                expect(postCount, "session recovery joins by key instead of redispatching").toBe(1);
              },
            );
          });

          const stored = yield* Effect.promise(() => client.listSources());
          expect(stored.sources.filter((source) => source.displayName === sourceName)).toHaveLength(
            1,
          );
        }),
        deleteSourcesNamed(client, [sourceName]),
      );
    }),
  ),
);

scenario(
  "Source creation recovery · authoritative refresh B cannot be overwritten by stale list A",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const github = yield* githubEmulator;
      const sourceName = unique("Authoritative refresh");

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            let postCount = 0;
            let committedStatus: number | undefined;
            let listCount = 0;
            let releaseStaleList = () => {};
            const staleListGate = new Promise<void>((resolve) => {
              releaseStaleList = resolve;
            });
            let markStaleListCaptured = () => {};
            const staleListCaptured = new Promise<void>((resolve) => {
              markStaleListCaptured = resolve;
            });
            let markStaleListDelivered = () => {};
            const staleListDelivered = new Promise<void>((resolve) => {
              markStaleListDelivered = resolve;
            });
            let markAuthoritativeListDelivered = () => {};
            const authoritativeListDelivered = new Promise<void>((resolve) => {
              markAuthoritativeListDelivered = resolve;
            });

            await page.route("**/api/v1/sources", async (route) => {
              if (route.request().method() === "POST") {
                postCount += 1;
                const committed = await route.fetch();
                committedStatus = committed.status();
                await route.fulfill({
                  status: 502,
                  headers: { "content-type": "text/plain; charset=utf-8" },
                  body: "gateway lost the committed response",
                });
                return;
              }
              if (route.request().method() !== "GET") {
                await route.continue();
                return;
              }
              const currentList = ++listCount;
              const response = await route.fetch();
              if (currentList === 1) {
                markStaleListCaptured();
                await staleListGate;
              } else if (currentList === 2) {
                markAuthoritativeListDelivered();
              }
              if (currentList === 1) {
                await route.fulfill({ response }).catch(() => {});
                markStaleListDelivered();
                return;
              }
              await route.fulfill({ response });
            });

            await step(
              "Keep list A in flight until replay refresh B is authoritative",
              async () => {
                await prepareInlineOpenApiSource(
                  page,
                  minimalOpenApiDocument(github.url, sourceName),
                  sourceName,
                );
                await staleListCaptured;
                await page.getByRole("button", { name: "Import source" }).click();
                try {
                  await authoritativeListDelivered;
                  await expect(page.getByRole("heading", { name: sourceName })).toBeVisible();
                  releaseStaleList();
                  await staleListDelivered;
                  await page.evaluate(
                    () =>
                      new Promise<void>((resolve) => {
                        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
                      }),
                  );
                  await expect(page.getByRole("heading", { name: sourceName })).toBeVisible();
                } finally {
                  releaseStaleList();
                }
                expect(
                  committedStatus,
                  "the source committed before response delivery failed",
                ).toBe(201);
                expect(postCount, "replay recovery keeps one source create").toBe(1);
                expect(listCount, "refresh B follows the earlier list A").toBeGreaterThanOrEqual(2);
              },
            );
          });

          const stored = yield* Effect.promise(() => client.listSources());
          expect(stored.sources.filter((source) => source.displayName === sourceName)).toHaveLength(
            1,
          );
        }),
        deleteSourcesNamed(client, [sourceName]),
      );
    }),
  ),
);

scenario(
  "Source creation guard · navigation waits and session storage retains only an opaque key",
  { timeout: 180_000 },
  Effect.scoped(
    Effect.gen(function* () {
      const target = yield* Target;
      const browser = yield* Browser;
      const client = yield* adminClient(target.baseUrl);
      const github = yield* githubEmulator;
      const sourceName = unique("Guarded source");
      const credential = unique("guarded-credential");

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.privateSession(identity, async ({ page, step }) => {
            let releaseSubmission = () => {};
            const submissionGate = new Promise<void>((resolve) => {
              releaseSubmission = resolve;
            });
            let markSubmissionStarted = () => {};
            const submissionStarted = new Promise<void>((resolve) => {
              markSubmissionStarted = resolve;
            });
            let submittedPayload = "";
            const sessionDeletes: string[] = [];
            page.on("request", (request) => {
              const url = new URL(request.url());
              if (request.method() === "DELETE" && url.pathname === "/api/v1/session") {
                sessionDeletes.push(request.url());
              }
            });
            await page.route("**/api/v1/sources", async (route) => {
              if (route.request().method() !== "POST") {
                await route.continue();
                return;
              }
              submittedPayload = route.request().postData() ?? "";
              markSubmissionStarted();
              await submissionGate;
              await route.continue();
            });

            await step("Block every exit while the exact source request is gated", async () => {
              await page.goto("/tools");
              await prepareInlineOpenApiSource(
                page,
                staticAuthOpenApiDocument(github.url, github.url),
                sourceName,
              );
              await page.getByRole("checkbox", { name: /basicAuth/ }).check();
              await page.getByLabel("Username").fill("guarded-admin");
              await page.getByLabel("Basic auth", { exact: true }).fill(credential);
              await page.getByRole("button", { name: "Import source" }).click();
              try {
                await submissionStarted;
                await expect(page.getByLabel("Basic auth", { exact: true })).toHaveValue("");
                const sourceTypes = page.getByRole("group", { name: "Source type" });
                for (const connector of [
                  "OpenAPI service",
                  "GraphQL API",
                  "MCP over HTTP",
                  "Trusted local MCP template",
                ]) {
                  await expect(
                    sourceTypes.getByLabel(connector),
                    `${connector} stays locked during dispatch`,
                  ).toBeDisabled();
                }

                const unload = await page.evaluate(() => {
                  const event = new Event("beforeunload", { cancelable: true });
                  return {
                    dispatched: window.dispatchEvent(event),
                    defaultPrevented: event.defaultPrevented,
                  };
                });
                expect(
                  unload,
                  "dispatch blocks an unload that could lose the in-memory payload",
                ).toEqual({ dispatched: false, defaultPrevented: true });

                const storage = await page.evaluate(() =>
                  Object.fromEntries(
                    Array.from({ length: sessionStorage.length }, (_, index) => {
                      const key = sessionStorage.key(index) ?? "";
                      return [key, sessionStorage.getItem(key) ?? ""];
                    }),
                  ),
                );
                const entries = Object.entries(storage);
                expect(
                  entries,
                  "session storage has only the pending idempotency record",
                ).toHaveLength(1);
                expect(entries[0]?.[1]).toMatch(/^[0-9a-f]{32}$/);
                const persisted = JSON.stringify(storage);
                expect(persisted).not.toContain(github.url);
                expect(persisted).not.toContain(sourceName);
                expect(persisted).not.toContain(credential);
                expect(persisted).not.toContain(submittedPayload);

                await page.getByRole("link", { name: "Tools" }).click();
                expect(new URL(page.url()).pathname).toBe("/sources");
                const warning = page.locator("#source-navigation-status");
                await expect(warning).toContainText("still being submitted");
                await expect(warning).toBeFocused();

                await page
                  .goBack({ waitUntil: "domcontentloaded", timeout: 1_000 })
                  .catch(() => null);
                expect(new URL(page.url()).pathname).toBe("/sources");
                await expect(warning).toBeFocused();

                await page.getByRole("button", { name: "Sign out" }).click();
                expect(new URL(page.url()).pathname).toBe("/sources");
                await expect(warning).toBeFocused();
                expect(
                  sessionDeletes,
                  "blocked sign-out never destroys the administrator session",
                ).toHaveLength(0);
              } finally {
                releaseSubmission();
              }

              await expect(page.getByRole("heading", { name: sourceName })).toBeVisible();
              await expect.poll(() => page.evaluate(() => sessionStorage.length)).toBe(0);
              await page.getByRole("link", { name: "Tools" }).click();
              await page.waitForURL((url) => url.pathname === "/tools");
              expect(
                sessionDeletes,
                "successful release does not sign the administrator out",
              ).toHaveLength(0);
            });
          });

          const stored = yield* Effect.promise(() => client.listSources());
          expect(stored.sources.filter((source) => source.displayName === sourceName)).toHaveLength(
            1,
          );
        }),
        deleteSourcesNamed(client, [sourceName]),
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
      const token = yield* acquireToken(client, target.baseUrl, unique("mode-agent"));
      const invoke = (idempotencyKey?: string) => {
        const headers = new Headers({
          authorization: `Bearer ${token.token}`,
          "content-type": "application/json",
        });
        if (idempotencyKey !== undefined) headers.set("idempotency-key", idempotencyKey);
        return fetch(new URL("/api/v1/gateway/tools/invoke", target.baseUrl), {
          method: "POST",
          headers,
          body: JSON.stringify({ path: tool.callablePath, arguments: { message: "Mode" } }),
        });
      };

      yield* Effect.ensuring(
        Effect.gen(function* () {
          const identity = yield* target.newIdentity();
          yield* browser.session(identity, async ({ page, step }) => {
            await step(
              "Set the source default to Enabled with deliberate confirmation",
              async () => {
                await page.goto("/sources");
                const card = page.getByRole("article").filter({
                  has: page.getByRole("heading", { name, exact: true }),
                });
                const sourceModes = card.getByRole("group", { name: "Default tool behavior" });
                await sourceModes.getByLabel("Enabled", { exact: true }).check();
                await card.getByRole("button", { name: "Apply source default" }).click();
                const confirmation = card.getByRole("group", {
                  name: `Confirm default for ${name}`,
                });
                await expect(confirmation).toBeVisible();
                await confirmation.getByRole("button", { name: "Confirm broad change" }).click();
                await expect(page.locator("#source-status")).toContainText(
                  "Source default changed to Enabled",
                );
              },
            );

            await step("Search the global catalog and filter to one source", async () => {
              await page.goto("/tools");
              await page.getByLabel("Search tools").fill("echo");
              await page.getByRole("button", { name: "Search" }).click();
              await page.getByLabel("Source").selectOption({ label: name });
              await expect(page.getByRole("table")).toContainText("echo");
            });

            await step(
              "Disable one tool from its row and enforce the change at the gateway",
              async () => {
                const toolModes = page.getByRole("group", {
                  name: `Behavior for ${tool.displayName}`,
                });
                const changed = page.waitForResponse((response) => {
                  const url = new URL(response.url());
                  return (
                    response.request().method() === "PATCH" &&
                    url.pathname === `/api/v1/tools/${tool.id}/mode`
                  );
                });
                await toolModes.getByLabel("Disabled", { exact: true }).check();
                expect((await changed).status(), "the row mutation reached the real API").toBe(200);
                await expect(toolModes.getByLabel("Disabled", { exact: true })).toBeChecked();
                const denied = await invoke();
                expect(
                  (await denied.json()) as unknown,
                  "the row-level Disabled setting is enforced at the gateway",
                ).toMatchObject({ error: { code: "tool_disabled" } });
              },
            );

            await step(
              "Inherit warns before the Disabled tool becomes source Enabled",
              async () => {
                await page.getByLabel(`Select ${tool.displayName}`).check();
                await page.getByRole("button", { name: "Apply Inherit to 1 selected" }).click();
                const confirmation = page.getByRole("group", {
                  name: "Confirm bulk tool behavior",
                });
                await expect(confirmation).toContainText(
                  "1 tool will become Enabled under its source default",
                );
                await confirmation.getByRole("button", { name: "Confirm Inherit" }).click();
                await expect(page.locator("#bulk-status")).toContainText(
                  "Inherit applied to 1 selected tool",
                );
                expect(
                  (await invoke()).status,
                  "the confirmed inherited Enabled mode is callable",
                ).toBe(200);
              },
            );

            await step("Set Ask from the tool row and approve its real gateway call", async () => {
              const toolModes = page.getByRole("group", {
                name: `Behavior for ${tool.displayName}`,
              });
              const changed = page.waitForResponse((response) => {
                const url = new URL(response.url());
                return (
                  response.request().method() === "PATCH" &&
                  url.pathname === `/api/v1/tools/${tool.id}/mode`
                );
              });
              await toolModes.getByLabel("Ask", { exact: true }).check();
              expect((await changed).status(), "the Ask row mutation reached the real API").toBe(
                200,
              );
              await expect(toolModes.getByLabel("Ask", { exact: true })).toBeChecked();

              const asked = await invoke(randomUUID());
              expect(asked.status, "the row-level Ask setting pauses the gateway call").toBe(202);
              const pending = (await asked.json()) as {
                readonly approval: { readonly id: string; readonly statusUrl: string };
              };
              await page.goto(`/approvals?approval=${encodeURIComponent(pending.approval.id)}`);
              await expect(page.getByText(tool.callablePath, { exact: true }).last()).toBeVisible();
              await page.getByRole("button", { name: "Approve once" }).click();
              await page.getByRole("button", { name: "Yes, approve once" }).click();
              await expect(page.getByText(/was approved/i)).toBeVisible();
              await expect
                .poll(
                  async () => {
                    const response = await fetch(
                      new URL(pending.approval.statusUrl, target.baseUrl),
                      { headers: { authorization: `Bearer ${token.token}` } },
                    );
                    const body = (await response.json()) as { readonly status: string };
                    return body.status;
                  },
                  { timeout: 10_000 },
                )
                .toBe("succeeded");
              await page.goto(
                `/tools?source=${encodeURIComponent(source.id)}&q=${encodeURIComponent("echo")}`,
              );
              await expect(page.getByRole("table")).toContainText(tool.displayName);
            });

            await step("Ask applies immediately to the selected tools", async () => {
              await page.getByLabel("Select all active tools on this page").check();
              await page
                .getByRole("group", { name: "Set selected tools" })
                .getByLabel("Ask")
                .check();
              await page.getByRole("button", { name: /^Apply Ask to \d+ selected$/ }).click();
              await expect(page.locator("#bulk-status")).toContainText("Ask applied");
            });

            await step("Disabling many tools requires a second confirmation", async () => {
              const selectAll = page.getByLabel("Select all active tools on this page");
              const selection = page.getByLabel(`Select ${tool.displayName}`);
              const bulkModes = page.getByRole("group", { name: "Set selected tools" });
              const toolModes = page.getByRole("group", {
                name: `Behavior for ${tool.displayName}`,
              });
              const applyDisabled = page.getByRole("button", {
                name: /^Apply Disabled to \d+ selected$/,
              });
              const applyInherit = page.getByRole("button", {
                name: /^Apply Inherit to \d+ selected$/,
              });

              await selectAll.check();
              await bulkModes.getByLabel("Disabled").check();
              await applyDisabled.click();

              let confirmation = page.getByRole("group", {
                name: "Confirm bulk tool behavior",
              });
              let cancel = confirmation.getByRole("button", { name: "Cancel" });
              await expect(confirmation).toBeVisible();
              await expect(cancel).toBeFocused();
              await expect(selectAll).toBeDisabled();
              await expect(selection).toBeDisabled();
              await expect(bulkModes).toBeDisabled();
              await expect(toolModes).toBeDisabled();
              await expect(applyDisabled).toBeDisabled();
              await expect(applyInherit).toBeDisabled();

              await cancel.press("Escape");
              await expect(confirmation).toHaveCount(0);
              await expect(applyDisabled).toBeFocused();

              await applyDisabled.click();
              confirmation = page.getByRole("group", { name: "Confirm bulk tool behavior" });
              cancel = confirmation.getByRole("button", { name: "Cancel" });
              await expect(cancel).toBeFocused();
              await cancel.click();
              await expect(confirmation).toHaveCount(0);
              await expect(applyDisabled).toBeFocused();

              await applyDisabled.click();
              confirmation = page.getByRole("group", { name: "Confirm bulk tool behavior" });
              await confirmation.getByRole("button", { name: "Confirm Disabled" }).click();
              const status = page.locator("#bulk-status");
              await expect(status).toContainText("Disabled applied");
              await expect(status).toBeFocused();
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
              await page.getByRole("button", { name: /^Apply Enabled to \d+ selected$/ }).click();
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
      const token = yield* acquireToken(client, target.baseUrl, unique("mcp-cli-agent"));
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
          const token = yield* acquireToken(client, target.baseUrl, unique("approval-agent"));
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
      const provider = yield* serveOAuthTestProvider(emulatorPortC);
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
              const oauth = page.getByRole("region", {
                name: `Managed OAuth for ${source.displayName}`,
              });
              await expect(oauth.getByText("Connected", { exact: true })).toBeVisible();
            });
            await step(
              "Cancel OAuth deletion with the keyboard and return to its opener",
              async () => {
                const oauth = page.getByRole("region", {
                  name: `Managed OAuth for ${source.displayName}`,
                });
                const deleteOpener = oauth.getByRole("button", { name: "Delete configuration" });
                await deleteOpener.click();
                const confirmation = oauth.getByRole("dialog", {
                  name: "Delete this OAuth configuration?",
                });
                const cancel = confirmation.getByRole("button", { name: "Cancel" });
                await expect(confirmation).toBeVisible();
                await expect(cancel).toBeFocused();
                await cancel.press("Escape");
                await expect(confirmation).toHaveCount(0);
                await expect(deleteOpener).toBeFocused();
              },
            );
          });
          const tools = yield* Effect.promise(() => client.listTools({ sourceId: source.id }));
          const tool = tools.items.find((candidate) => candidate.stableKey.endsWith("get_me"));
          if (!tool) return yield* Effect.die("the managed OAuth source produced no tool");
          const enabled = yield* Effect.promise(() => client.setToolMode(tool, "enabled"));
          const token = yield* acquireToken(client, target.baseUrl, unique("oauth-agent"));
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
