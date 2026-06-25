import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/svelte";
import { Effect, Schema } from "effect";
import {
  SOURCE_CREATE_STORAGE_KEY,
  type SourceCreateEnvironment,
} from "$lib/source-create-lifecycle";
import SourcesPageHarness from "./sources-page.test-harness.svelte";

const decodeJson = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Unknown));

function sourceFixture(id = "graphql-source", displayName = "Product API") {
  return {
    id,
    kind: "graphql",
    slug: id,
    displayName,
    description: null,
    configuration: { endpoint: "https://api.example.test/", allowPrivateNetwork: false },
    modeOverride: null,
    healthStatus: "healthy",
    healthErrorCode: null,
    revision: 1,
    catalogRevision: 1,
    createdAt: 100,
    updatedAt: 100,
    lastRefreshedAt: 100,
    toolCount: 4,
    tombstonedToolCount: 0,
  };
}

function openApiSourceFixture(id = "openapi-source", displayName = "Weather API") {
  return {
    ...sourceFixture(id, displayName),
    kind: "openapi",
    configuration: {},
  };
}

function mcpHttpSourceFixture(id = "mcp-http-source", displayName = "Issue tracker") {
  return {
    ...sourceFixture(id, displayName),
    kind: "mcp_http",
    configuration: { endpoint: "https://mcp.example.test", allowPrivateNetwork: false },
  };
}

function mcpStdioSourceFixture(id = "mcp-stdio-source", displayName = "Local tools") {
  return {
    ...sourceFixture(id, displayName),
    kind: "mcp_stdio",
    configuration: { templateName: "local" },
  };
}

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

function emptyOAuthConnections() {
  return Response.json({ connections: [], availableCredentials: [] });
}

function noStoreJson(value: unknown, init: ResponseInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("cache-control", "no-store");
  return Response.json(value, { ...init, headers });
}

function requestIdempotencyKey(init: RequestInit | undefined) {
  return new Headers(init?.headers).get("idempotency-key");
}

function fixedSourceCreateEnvironment(
  options: { readonly wait?: SourceCreateEnvironment["wait"] } = {},
): SourceCreateEnvironment {
  return {
    getStorage: () => window.sessionStorage,
    fillRandom: (bytes) => bytes.fill(0x7c),
    wait: options.wait ?? (() => Promise.resolve(true)),
  };
}

function oauthConnectionFixture(id: string) {
  return {
    id,
    credentialKey: "default",
    revision: 1,
    status: "connected",
    issuer: "https://identity.example.test/",
    clientId: "executor-client",
    clientAuthMethod: "none",
    callbackUrl: `https://executor.example.test/api/v1/oauth/callback/${id}`,
    requestedScopes: [],
    grantedScopes: [],
    hasClientSecret: false,
    hasRefreshToken: true,
    accessExpiresAt: null,
    authorizedAt: 100,
    lastRefreshedAt: 100,
    errorCode: null,
    managedOAuthEligible: true,
  };
}

function expectPreservedOAuthCleanup(url: URL | null) {
  expect(url).not.toBeNull();
  expect(url?.pathname).toBe("/sources");
  expect(url?.searchParams.get("keep")).toBe("present");
  expect(url?.searchParams.has("oauth")).toBe(false);
  expect(url?.searchParams.has("result")).toBe(false);
  expect(url?.hash).toBe("#details");
}

async function expectPendingWriteFence(logoutCalls: () => number) {
  const unload = new Event("beforeunload", { cancelable: true });
  window.dispatchEvent(unload);
  expect(unload.defaultPrevented).toBe(true);

  await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
  expect(
    await screen.findByText(/source or credential change is still being saved/i),
  ).toBeDefined();
  await waitFor(() =>
    expect(document.activeElement).toBe(document.getElementById("source-navigation-status")),
  );
  expect(logoutCalls()).toBe(0);
}

afterEach(() => {
  cleanup();
  window.sessionStorage.clear();
  vi.unstubAllGlobals();
});

describe("Sources page coordination", () => {
  it("guards dispatch and retries the exact OpenAPI payload with one retained key", async () => {
    const firstCreation = deferred<Response>();
    let listCalls = 0;
    const creates: Array<{ key: string | null; body: string }> = [];
    const statusRequest = {
      value: null as null | {
        method: string | undefined;
        body: BodyInit | null | undefined;
        cache: RequestCache | undefined;
        key: string | null;
      },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources/openapi/preview" && init?.method === "POST") {
          return Promise.resolve(
            Response.json({
              title: "Weather API",
              description: null,
              toolCount: 1,
              tools: [
                {
                  preferredName: "forecast",
                  displayName: "Forecast",
                  description: null,
                  intrinsicMode: "enabled",
                  security: [["bearerAuth"]],
                },
              ],
              securitySchemes: [
                {
                  name: "bearerAuth",
                  credentialType: "bearer",
                  placement: "header",
                  supported: true,
                  oauthFlows: null,
                },
              ],
            }),
          );
        }
        if (path === "/api/v1/sources/idempotency") {
          statusRequest.value = {
            method: init?.method,
            body: init?.body,
            cache: init?.cache,
            key: requestIdempotencyKey(init),
          };
          return Promise.resolve(noStoreJson({ status: "missing" }));
        }
        if (path === "/api/v1/sources" && init?.method === "POST") {
          creates.push({
            key: requestIdempotencyKey(init),
            body: String(init?.body),
          });
          return creates.length === 1
            ? firstCreation.promise
            : creates.length === 2
              ? Promise.resolve(new Response("gateway timeout", { status: 504 }))
              : Promise.resolve(
                  noStoreJson(openApiSourceFixture(), {
                    status: 201,
                  }),
                );
        }
        if (path === "/api/v1/sources") {
          listCalls += 1;
          return Promise.resolve(
            Response.json({
              sources: listCalls === 1 ? [] : [openApiSourceFixture()],
              catalogRevision: listCalls,
            }),
          );
        }
        if (path === "/api/v1/sources/openapi-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        return Promise.resolve(
          Response.json(
            {
              error: {
                code: "unexpected_test_request",
                message: `Unexpected request: ${path}`,
                requestId: "test-request",
              },
            },
            { status: 500 },
          ),
        );
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    await screen.findByText("No sources connected");
    await fireEvent.input(screen.getByLabelText("OpenAPI URL"), {
      target: { value: "https://api.example.test/openapi.json" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Preview tools" }));
    await screen.findByRole("heading", { name: "Weather API" });
    await fireEvent.click(screen.getByRole("checkbox", { name: /bearerAuth/ }));
    await fireEvent.input(screen.getByLabelText("Bearer token"), {
      target: { value: "never-store-this-secret" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Import source" }));

    const sourceTypePicker = screen.getByRole<HTMLFieldSetElement>("group", {
      name: "Source type",
    });
    const resetImporter = screen.getByRole<HTMLButtonElement>("button", {
      name: "Reset importer",
    });
    await waitFor(() => expect(sourceTypePicker.disabled).toBe(true));
    expect(resetImporter.disabled).toBe(true);
    await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByText(/source connection is still being submitted/i)).toBeDefined();
    expect(document.activeElement).toBe(document.getElementById("source-navigation-status"));
    const unload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unload);
    expect(unload.defaultPrevented).toBe(true);
    const storedKey = window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY);
    expect(storedKey).toMatch(/^[0-9a-f]{32}$/);
    expect(storedKey).toBe(creates[0]?.key);
    expect(JSON.stringify([...Object.entries(window.sessionStorage)])).not.toContain(
      "never-store-this-secret",
    );
    await fireEvent.click(screen.getByLabelText("GraphQL API"));
    await fireEvent.click(resetImporter);
    expect(screen.queryByRole("group", { name: "GraphQL API" })).toBeNull();

    firstCreation.resolve(new Response("gateway timeout", { status: 504 }));
    await waitFor(() => expect(creates).toHaveLength(2));
    const retryExact = await screen.findByRole("button", { name: "Retry exact request" });
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(storedKey);
    await fireEvent.click(retryExact);
    await waitFor(() => expect(creates).toHaveLength(3));
    await waitFor(() => expect(listCalls).toBe(2));
    await waitFor(() =>
      expect(screen.getAllByRole("heading", { name: "Weather API" })).toHaveLength(1),
    );
    expect(creates[1]?.key).toBe(creates[0]?.key);
    expect(creates[1]?.body).toBe(creates[0]?.body);
    expect(creates[2]?.key).toBe(creates[0]?.key);
    expect(creates[2]?.body).toBe(creates[0]?.body);
    expect(creates[0]?.body).toContain("never-store-this-secret");
    expect(statusRequest.value).toEqual({
      method: "GET",
      body: undefined,
      cache: "no-store",
      key: creates[0]?.key,
    });
    await waitFor(() =>
      expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull(),
    );
    await waitFor(() => expect(sourceTypePicker.disabled).toBe(false));
  });

  it("allows sign-out and unload during recovery polling while retaining the key", async () => {
    const key = "1".repeat(32);
    window.sessionStorage.setItem(SOURCE_CREATE_STORAGE_KEY, key);
    const polling = deferred<boolean>();
    const enteredPolling = deferred<void>();
    const poll = { signal: null as AbortSignal | null };
    const statusKeys: Array<string | null> = [];
    let logoutCalls = 0;
    let sourceCreateCalls = 0;
    let sealCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources/idempotency") {
          statusKeys.push(requestIdempotencyKey(init));
          return Promise.resolve(noStoreJson({ status: "in_progress" }));
        }
        if (path === "/api/v1/sources/idempotency/seal") {
          sealCalls += 1;
          return Promise.resolve(noStoreJson({ status: "abandoned" }));
        }
        if (path === "/api/v1/sources" && init?.method === "POST") {
          sourceCreateCalls += 1;
          return Promise.resolve(noStoreJson(sourceFixture(), { status: 201 }));
        }
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [], catalogRevision: 1 }));
        }
        if (path === "/api/v1/session" && init?.method === "DELETE") {
          logoutCalls += 1;
          return Promise.resolve(
            Response.json(
              {
                error: {
                  code: "logout_unavailable",
                  message: "Logout is unavailable in this test.",
                  requestId: "logout-test",
                },
              },
              { status: 503 },
            ),
          );
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    const mounted = render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment({
        wait: (_milliseconds, signal) => {
          poll.signal = signal;
          enteredPolling.resolve();
          return polling.promise;
        },
      }),
    });

    await enteredPolling.promise;
    expect(statusKeys).toEqual([key]);
    expect(screen.getByText(/still finishing this source connection/i)).toBeDefined();
    expect(screen.getByRole<HTMLFieldSetElement>("group", { name: "Source type" }).disabled).toBe(
      true,
    );
    const unload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unload);
    expect(unload.defaultPrevented).toBe(false);
    await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(logoutCalls).toBe(1));
    expect(screen.queryByText(/source connection is still being submitted/i)).toBeNull();

    mounted.unmount();
    expect(poll.signal?.aborted).toBe(true);
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
    polling.resolve(false);
    await polling.promise;
    await Promise.resolve();
    await Promise.resolve();
    expect(statusKeys).toEqual([key]);
    expect(sourceCreateCalls).toBe(0);
    expect(sealCalls).toBe(0);
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
  });

  it("suspends a gated live recovery before sign-out starts session deletion", async () => {
    const lookupResponse = deferred<Response>();
    const lookupStarted = deferred<void>();
    const deleteResponse = deferred<Response>();
    const deleteStarted = deferred<void>();
    const lookupRequest = { signal: null as AbortSignal | null };
    let sourceCreateCalls = 0;
    let sealCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources/idempotency") {
          lookupRequest.signal = init?.signal ?? null;
          lookupStarted.resolve();
          return lookupResponse.promise;
        }
        if (path === "/api/v1/sources/idempotency/seal") {
          sealCalls += 1;
          return Promise.resolve(noStoreJson({ status: "abandoned" }));
        }
        if (path === "/api/v1/sources" && init?.method === "POST") {
          sourceCreateCalls += 1;
          return Promise.resolve(new Response("gateway timeout", { status: 504 }));
        }
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [], catalogRevision: 1 }));
        }
        if (path === "/api/v1/session" && init?.method === "DELETE") {
          deleteStarted.resolve();
          return deleteResponse.promise;
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    await screen.findByText("No sources connected");
    await fireEvent.click(screen.getByLabelText("GraphQL API"));
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://api.example.test/graphql" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Product API" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));
    await lookupStarted.promise;
    const key = window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY);
    expect(key).toMatch(/^[0-9a-f]{32}$/);

    await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await deleteStarted.promise;
    expect(lookupRequest.signal?.aborted).toBe(true);
    expect(screen.getByText("Source recovery paused for sign-out.")).toBeDefined();

    lookupResponse.resolve(noStoreJson({ status: "missing" }));
    await lookupResponse.promise;
    await Promise.resolve();
    await Promise.resolve();
    expect(sourceCreateCalls).toBe(1);
    expect(sealCalls).toBe(0);
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);

    deleteResponse.resolve(
      Response.json(
        {
          error: {
            code: "logout_unavailable",
            message: "Logout is unavailable in this test.",
            requestId: "logout-test",
          },
        },
        { status: 503 },
      ),
    );
    expect(
      await screen.findByText(
        "Source recovery is paused because sign-out failed. Resume source recovery or reload this page.",
      ),
    ).toBeDefined();
    expect(screen.getByRole("button", { name: "Resume source recovery" })).toBeDefined();
    expect(sourceCreateCalls).toBe(1);
    expect(sealCalls).toBe(0);
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
  });

  it("routes GraphQL creation through the page coordinator", async () => {
    let listCalls = 0;
    const creates: Array<{ key: string | null; body: string }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources" && init?.method === "POST") {
          creates.push({ key: requestIdempotencyKey(init), body: String(init.body) });
          return Promise.resolve(noStoreJson(sourceFixture(), { status: 201 }));
        }
        if (path === "/api/v1/sources") {
          listCalls += 1;
          return Promise.resolve(
            Response.json({
              sources: listCalls === 1 ? [] : [sourceFixture()],
              catalogRevision: listCalls,
            }),
          );
        }
        if (path === "/api/v1/sources/graphql-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    await screen.findByText("No sources connected");
    await fireEvent.click(screen.getByLabelText("GraphQL API"));
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://api.example.test/graphql" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Product API" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    expect(await screen.findByRole("heading", { name: "Product API" })).toBeDefined();
    expect(listCalls).toBe(2);
    expect(creates).toHaveLength(1);
    expect(creates[0]?.key).toMatch(/^[0-9a-f]{32}$/);
    expect(decodeJson(creates[0]?.body ?? "{}")).toMatchObject({ kind: "graphql" });
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
  });

  it("routes MCP HTTP creation through the page coordinator", async () => {
    let listCalls = 0;
    const keys: Array<string | null> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources" && init?.method === "POST") {
          keys.push(requestIdempotencyKey(init));
          return Promise.resolve(
            noStoreJson(mcpHttpSourceFixture(), {
              status: 201,
            }),
          );
        }
        if (path === "/api/v1/sources") {
          listCalls += 1;
          return Promise.resolve(
            Response.json({
              sources: listCalls === 1 ? [] : [mcpHttpSourceFixture()],
              catalogRevision: listCalls,
            }),
          );
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    await screen.findByText("No sources connected");
    await fireEvent.click(screen.getByLabelText("MCP over HTTP"));
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://mcp.example.test/mcp" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Issue tracker" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    expect(await screen.findByRole("heading", { name: "Issue tracker" })).toBeDefined();
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
  });

  it("routes MCP stdio creation through the page coordinator", async () => {
    let listCalls = 0;
    const keys: Array<string | null> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/mcp/stdio/templates") {
          return Promise.resolve(
            Response.json({ templates: [{ name: "local", secretFields: [] }] }),
          );
        }
        if (path === "/api/v1/sources" && init?.method === "POST") {
          keys.push(requestIdempotencyKey(init));
          return Promise.resolve(noStoreJson(mcpStdioSourceFixture(), { status: 201 }));
        }
        if (path === "/api/v1/sources") {
          listCalls += 1;
          return Promise.resolve(
            Response.json({
              sources: listCalls === 1 ? [] : [mcpStdioSourceFixture()],
              catalogRevision: listCalls,
            }),
          );
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    await screen.findByText("No sources connected");
    await fireEvent.click(screen.getByLabelText("Trusted local MCP template"));
    await screen.findByRole("option", { name: "local" });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Local tools" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    expect(await screen.findByRole("heading", { name: "Local tools" })).toBeDefined();
    expect(keys).toHaveLength(1);
    expect(keys[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
  });

  it("refreshes the authoritative list before clearing a completed reload key", async () => {
    const key = "2".repeat(32);
    window.sessionStorage.setItem(SOURCE_CREATE_STORAGE_KEY, key);
    const status = deferred<Response>();
    const refreshedList = deferred<Response>();
    let listCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path === "/api/v1/sources/idempotency") return status.promise;
        if (path === "/api/v1/sources") {
          listCalls += 1;
          return listCalls === 1
            ? Promise.resolve(Response.json({ sources: [], catalogRevision: 1 }))
            : refreshedList.promise;
        }
        if (path === "/api/v1/sources/graphql-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    await screen.findByText("No sources connected");
    status.resolve(
      Response.json(sourceFixture(), {
        status: 201,
        headers: {
          "cache-control": "no-store",
          "idempotency-replayed": "true",
        },
      }),
    );
    await waitFor(() => expect(listCalls).toBe(2));
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);

    refreshedList.resolve(Response.json({ sources: [sourceFixture()], catalogRevision: 2 }));
    expect(await screen.findByRole("heading", { name: "Product API" })).toBeDefined();
    await waitFor(() =>
      expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull(),
    );
  });

  it("reports a definitive failed replay and safely clears its key", async () => {
    const key = "3".repeat(32);
    window.sessionStorage.setItem(SOURCE_CREATE_STORAGE_KEY, key);
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path === "/api/v1/sources/idempotency") {
          return Promise.resolve(
            Response.json(
              {
                error: {
                  code: "invalid_source",
                  message: "The source document is invalid.",
                  requestId: "failed-source",
                },
              },
              {
                status: 422,
                headers: {
                  "cache-control": "no-store",
                  "idempotency-replayed": "true",
                },
              },
            ),
          );
        }
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [], catalogRevision: 1 }));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    expect(await screen.findByText("The source document is invalid.")).toBeDefined();
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
    expect(screen.getByRole<HTMLFieldSetElement>("group", { name: "Source type" }).disabled).toBe(
      false,
    );
    expect(document.activeElement).toBe(document.getElementById("source-create-status"));
  });

  it("seals a missing reload key before unlocking the source forms", async () => {
    const key = "4".repeat(32);
    window.sessionStorage.setItem(SOURCE_CREATE_STORAGE_KEY, key);
    let sealCalls = 0;
    const sealRequest = {
      value: null as null | {
        method: string | undefined;
        body: BodyInit | null | undefined;
        key: string | null;
      },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources/idempotency") {
          return Promise.resolve(noStoreJson({ status: "missing" }));
        }
        if (path === "/api/v1/sources/idempotency/seal") {
          sealCalls += 1;
          sealRequest.value = {
            method: init?.method,
            body: init?.body,
            key: requestIdempotencyKey(init),
          };
          return Promise.resolve(noStoreJson({ status: "abandoned" }));
        }
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [], catalogRevision: 1 }));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    expect(await screen.findByText(/unused source connection key was sealed/i)).toBeDefined();
    expect(sealCalls).toBe(1);
    expect(sealRequest.value).toEqual({ method: "POST", body: undefined, key });
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
    expect(screen.getByRole<HTMLFieldSetElement>("group", { name: "Source type" }).disabled).toBe(
      false,
    );
  });

  it("retains the key and lock when a recovery status is malformed", async () => {
    const key = "5".repeat(32);
    window.sessionStorage.setItem(SOURCE_CREATE_STORAGE_KEY, key);
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path === "/api/v1/sources/idempotency") {
          return Promise.resolve(Response.json({ status: "missing" }));
        }
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [], catalogRevision: 1 }));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    expect(
      await screen.findByText(/idempotency status the dashboard could not understand/i),
    ).toBeDefined();
    expect(screen.getByRole("button", { name: "Check again" })).toBeDefined();
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
    expect(screen.getByRole<HTMLFieldSetElement>("group", { name: "Source type" }).disabled).toBe(
      true,
    );
  });

  it("fails closed before dispatch when secure randomness is unavailable", async () => {
    let createCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        if (String(input) === "/api/v1/sources" && init?.method === "POST") createCalls += 1;
        return Promise.resolve(Response.json({ sources: [], catalogRevision: 1 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: {
        getStorage: () => window.sessionStorage,
        fillRandom: () => Effect.runSync(Effect.fail("randomness unavailable")),
        wait: () => Promise.resolve(true),
      },
    });

    await screen.findByText("No sources connected");
    await fireEvent.click(screen.getByLabelText("GraphQL API"));
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://api.example.test/graphql" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Product API" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() =>
      expect(screen.getAllByText(/secure browser randomness is unavailable/i)).toHaveLength(2),
    );
    expect(createCalls).toBe(0);
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
  });

  it("locks recovery when tab storage cannot be read safely", async () => {
    let createCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        if (String(input) === "/api/v1/sources" && init?.method === "POST") createCalls += 1;
        return Promise.resolve(Response.json({ sources: [], catalogRevision: 1 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: {
        getStorage: () => Effect.runSync(Effect.fail("storage unavailable")),
        fillRandom: (bytes) => bytes.fill(1),
        wait: () => Promise.resolve(true),
      },
    });

    expect(await screen.findByText(/secure tab storage is unavailable/i)).toBeDefined();
    expect(createCalls).toBe(0);
    expect(screen.getByRole<HTMLFieldSetElement>("group", { name: "Source type" }).disabled).toBe(
      true,
    );
    expect(screen.getByRole("button", { name: "Check again" })).toBeDefined();
  });

  it("keeps stored operation B when operation A completes late", async () => {
    const keyB = "b".repeat(32);
    const refreshedList = deferred<Response>();
    let listCalls = 0;
    const statusKeys: Array<string | null> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources/idempotency") {
          statusKeys.push(requestIdempotencyKey(init));
          return Effect.runPromise(Effect.fail("offline"));
        }
        if (path === "/api/v1/sources" && init?.method === "POST") {
          return Promise.resolve(noStoreJson(sourceFixture(), { status: 201 }));
        }
        if (path === "/api/v1/sources") {
          listCalls += 1;
          return listCalls === 1
            ? Promise.resolve(Response.json({ sources: [], catalogRevision: 1 }))
            : refreshedList.promise;
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      sourceCreateEnvironment: fixedSourceCreateEnvironment(),
    });

    await screen.findByText("No sources connected");
    await fireEvent.click(screen.getByLabelText("GraphQL API"));
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://api.example.test/graphql" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Product API" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));
    await waitFor(() => expect(listCalls).toBe(2));
    window.sessionStorage.setItem(SOURCE_CREATE_STORAGE_KEY, keyB);
    refreshedList.resolve(Response.json({ sources: [sourceFixture()], catalogRevision: 2 }));

    expect(await screen.findByText(/Executor could not be reached/i)).toBeDefined();
    expect(statusKeys).toEqual([keyB]);
    expect(window.sessionStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(keyB);
    expect(screen.queryByText(/connected with 4 tools/i)).toBeNull();
    expect(screen.getByRole<HTMLFieldSetElement>("group", { name: "Source type" }).disabled).toBe(
      true,
    );
  });

  it("cleans a matched OAuth callback while preserving unrelated URL and history state", async () => {
    const initialState = { preserved: "history-state" };
    const replacement = {
      url: null as URL | null,
      state: null as App.PageState | null,
    };
    const onOAuthReplace = vi.fn((url: URL, state: App.PageState) => {
      replacement.url = url;
      replacement.state = state;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [sourceFixture()], catalogRevision: 1 }));
        }
        if (path === "/api/v1/sources/graphql-source/oauth") {
          return Promise.resolve(
            Response.json({
              connections: [oauthConnectionFixture("matched-connection")],
              availableCredentials: [],
            }),
          );
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      initialOAuthUrl:
        "https://executor.example.test/sources?keep=present&oauth=matched-connection&result=success#details",
      initialOAuthState: initialState,
      onOAuthReplace,
    });

    expect(
      await screen.findByText(
        "OAuth authorization completed and the connection status was refreshed.",
      ),
    ).toBeDefined();
    await waitFor(() => expect(onOAuthReplace).toHaveBeenCalledOnce());
    expectPreservedOAuthCleanup(replacement.url);
    expect(replacement.state).toBe(initialState);
  });

  it("focuses an unmatched OAuth notice before cleaning callback state", async () => {
    const initialState = { preserved: "unmatched-state" };
    const replacement = {
      url: null as URL | null,
      state: null as App.PageState | null,
      focusedId: null as string | null,
    };
    const onOAuthReplace = vi.fn((url: URL, state: App.PageState) => {
      replacement.url = url;
      replacement.state = state;
      replacement.focusedId = document.activeElement?.id ?? null;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [sourceFixture()], catalogRevision: 2 }));
        }
        if (path === "/api/v1/sources/graphql-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      initialOAuthUrl:
        "https://executor.example.test/sources?keep=present&oauth=missing-connection&result=success#details",
      initialOAuthState: initialState,
      onOAuthReplace,
    });

    expect(
      await screen.findByText("OAuth returned, but no matching managed connection is available."),
    ).toBeDefined();
    await waitFor(() => expect(onOAuthReplace).toHaveBeenCalledOnce());
    expect(replacement.focusedId).toBe("source-status");
    expectPreservedOAuthCleanup(replacement.url);
    expect(replacement.state).toBe(initialState);
  });

  it("focuses a safe OAuth notice when the current source set has no eligible connection", async () => {
    const replacement = {
      url: null as URL | null,
      focusedId: null as string | null,
    };
    const onOAuthReplace = vi.fn((url: URL) => {
      replacement.url = url;
      replacement.focusedId = document.activeElement?.id ?? null;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        if (String(input) === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [], catalogRevision: 3 }));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      initialOAuthUrl:
        "https://executor.example.test/sources?keep=present&oauth=missing-connection&result=failed#details",
      onOAuthReplace,
    });

    expect(
      await screen.findByText(
        "OAuth authorization did not complete. Review the connection status and try again.",
      ),
    ).toBeDefined();
    await waitFor(() => expect(onOAuthReplace).toHaveBeenCalledOnce());
    expect(replacement.focusedId).toBe("source-status");
    expectPreservedOAuthCleanup(replacement.url);
  });

  it("ignores an out-of-order OAuth check from a replaced eligible source set", async () => {
    const staleOAuth = deferred<Response>();
    let listCalls = 0;
    const onOAuthReplace = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          if (init?.method === "POST") {
            return Promise.resolve(
              noStoreJson(openApiSourceFixture("replacement", "Replacement source"), {
                status: 201,
              }),
            );
          }
          listCalls += 1;
          return Promise.resolve(
            Response.json({
              sources:
                listCalls === 1
                  ? [sourceFixture("source-a", "Source A"), sourceFixture("source-b", "Source B")]
                  : [openApiSourceFixture("replacement", "Replacement source")],
              catalogRevision: listCalls,
            }),
          );
        }
        if (path === "/api/v1/sources/openapi/preview" && init?.method === "POST") {
          return Promise.resolve(
            Response.json({
              title: "Replacement source",
              description: null,
              toolCount: 1,
              tools: [],
              securitySchemes: [],
            }),
          );
        }
        if (path === "/api/v1/sources/source-a/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        if (path === "/api/v1/sources/source-b/oauth") return staleOAuth.promise;
        if (path === "/api/v1/sources/replacement/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness, {
      initialOAuthUrl:
        "https://executor.example.test/sources?keep=present&oauth=late-match&result=success#details",
      onOAuthReplace,
    });

    await screen.findByRole("heading", { name: "Source A" });
    await screen.findByRole("heading", { name: "Source B" });
    await fireEvent.click(screen.getByText("Connect a source"));
    await fireEvent.input(screen.getByLabelText("OpenAPI URL"), {
      target: { value: "https://api.example.test/openapi.json" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Preview tools" }));
    await screen.findByRole("heading", { name: "Replacement source" });
    await fireEvent.click(screen.getByRole("button", { name: "Import source" }));

    await waitFor(() =>
      expect(screen.getAllByRole("heading", { name: "Replacement source" })).toHaveLength(1),
    );
    await waitFor(() => expect(onOAuthReplace).toHaveBeenCalledOnce());
    staleOAuth.resolve(
      Response.json({
        connections: [oauthConnectionFixture("late-match")],
        availableCredentials: [],
      }),
    );
    await staleOAuth.promise;
    await Promise.resolve();
    await Promise.resolve();

    expect(onOAuthReplace).toHaveBeenCalledOnce();
    expect(
      screen.queryByText("OAuth authorization completed and the connection status was refreshed."),
    ).toBeNull();
  });

  it("includes OpenAPI credential loading in the shared source lock", async () => {
    const credentials = deferred<Response>();
    let logoutCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          return Promise.resolve(
            Response.json({ sources: [openApiSourceFixture()], catalogRevision: 1 }),
          );
        }
        if (path === "/api/v1/sources/openapi-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        if (path === "/api/v1/sources/openapi-source/credentials") {
          return credentials.promise;
        }
        if (path === "/api/v1/session" && init?.method === "DELETE") {
          logoutCalls += 1;
          return Promise.resolve(
            Response.json(
              {
                error: {
                  code: "logout_unavailable",
                  message: "Logout is unavailable in this test.",
                  requestId: "logout-test",
                },
              },
              { status: 503 },
            ),
          );
        }
        return Promise.resolve(
          Response.json(
            {
              error: {
                code: "unexpected_test_request",
                message: `Unexpected request: ${path}`,
                requestId: "test-request",
              },
            },
            { status: 500 },
          ),
        );
      }),
    );
    render(SourcesPageHarness);

    const manageCredentials = await screen.findByRole<HTMLButtonElement>("button", {
      name: "Manage credentials",
    });
    await waitFor(() => expect(manageCredentials.disabled).toBe(false));
    await fireEvent.click(manageCredentials);

    await waitFor(() =>
      expect(
        screen.getByRole<HTMLFieldSetElement>("group", { name: "Default tool behavior" }).disabled,
      ).toBe(true),
    );
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Refresh" }).disabled).toBe(true);
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Delete" }).disabled).toBe(true);
    const unload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unload);
    expect(unload.defaultPrevented).toBe(false);
    await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(logoutCalls).toBe(1));

    credentials.resolve(
      Response.json({
        revision: 1,
        configuredSchemes: [{ name: "default", credentialType: "bearer" }],
      }),
    );
    await credentials.promise;
    await screen.findByRole("form", { name: "Credentials for Weather API" });
  });

  it("releases the OpenAPI credential lock after a rejected metadata request", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          return Promise.resolve(
            Response.json({ sources: [openApiSourceFixture()], catalogRevision: 1 }),
          );
        }
        if (path === "/api/v1/sources/openapi-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        if (path === "/api/v1/sources/openapi-source/credentials") {
          return Effect.runPromise(Effect.fail("offline"));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness);

    const manageCredentials = await screen.findByRole<HTMLButtonElement>("button", {
      name: "Manage credentials",
    });
    await waitFor(() => expect(manageCredentials.disabled).toBe(false));
    await fireEvent.click(manageCredentials);

    expect(
      await screen.findByText(
        "Executor could not be reached. Check that the local server is running.",
      ),
    ).toBeDefined();
    await waitFor(() => expect(manageCredentials.disabled).toBe(false));
    expect(
      screen.getByRole<HTMLFieldSetElement>("group", { name: "Default tool behavior" }).disabled,
    ).toBe(false);
    expect(manageCredentials.getAttribute("aria-expanded")).toBe("false");
  });

  it("disables sibling source controls while managed OAuth saves", async () => {
    const replacement = deferred<Response>();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [sourceFixture()], catalogRevision: 1 }));
        }
        if (path === "/api/v1/sources/graphql-source/oauth/default" && init?.method === "PUT") {
          return replacement.promise;
        }
        if (path === "/api/v1/sources/graphql-source/oauth") {
          return Promise.resolve(
            Response.json({
              connections: [],
              availableCredentials: [
                {
                  credentialKey: "default",
                  protocol: "graphql",
                  requestedScopes: [],
                  managedOAuthEligible: true,
                },
              ],
            }),
          );
        }
        return Promise.resolve(
          Response.json(
            {
              error: {
                code: "unexpected_test_request",
                message: `Unexpected request: ${path}`,
                requestId: "test-request",
              },
            },
            { status: 500 },
          ),
        );
      }),
    );
    render(SourcesPageHarness);

    const manageCredentials = await screen.findByRole<HTMLButtonElement>("button", {
      name: "Manage credentials",
    });
    await waitFor(() => expect(manageCredentials.disabled).toBe(false));
    await fireEvent.input(screen.getByLabelText("Issuer URL"), {
      target: { value: "https://identity.example.test" },
    });
    await fireEvent.input(screen.getByLabelText("Client ID"), {
      target: { value: "executor-client" },
    });
    const saveConfiguration = screen.getByRole<HTMLButtonElement>("button", {
      name: "Save configuration",
    });
    await waitFor(() => expect(saveConfiguration.disabled).toBe(false));
    await fireEvent.click(saveConfiguration);

    await waitFor(() => expect(manageCredentials.disabled).toBe(true));
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Refresh schema and tools" }).disabled,
    ).toBe(true);
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Delete" }).disabled).toBe(true);

    replacement.resolve(
      Response.json({
        id: "connection-1",
        credentialKey: "default",
        revision: 1,
        status: "ready_to_connect",
        issuer: "https://identity.example.test/",
        clientId: "executor-client",
        clientAuthMethod: "none",
        callbackUrl: "https://executor.example.test/api/v1/oauth/callback/connection-1",
        requestedScopes: [],
        grantedScopes: [],
        hasClientSecret: false,
        hasRefreshToken: false,
        accessExpiresAt: null,
        authorizedAt: null,
        lastRefreshedAt: null,
        errorCode: null,
        managedOAuthEligible: true,
      }),
    );
    await replacement.promise;
  });

  it("disables an open mode confirmation and sibling actions while credentials save", async () => {
    const replacement = deferred<Response>();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [sourceFixture()], catalogRevision: 1 }));
        }
        if (path.endsWith("/credentials") && init?.method === "PUT") {
          return replacement.promise;
        }
        if (path.endsWith("/credentials")) {
          return Promise.resolve(
            Response.json({
              revision: 4,
              configuredSchemes: [{ name: "default", credentialType: "bearer" }],
            }),
          );
        }
        if (path.endsWith("/oauth") && init?.method === undefined) {
          return Promise.resolve(emptyOAuthConnections());
        }
        return Promise.resolve(
          Response.json(
            {
              error: {
                code: "unexpected_test_request",
                message: `Unexpected request: ${path}`,
                requestId: "test-request",
              },
            },
            { status: 500 },
          ),
        );
      }),
    );
    render(SourcesPageHarness);

    await screen.findByRole("heading", { name: "Product API" });
    const manageCredentials = screen.getByRole<HTMLButtonElement>("button", {
      name: "Manage credentials",
    });
    await waitFor(() => expect(manageCredentials.disabled).toBe(false));
    await fireEvent.click(screen.getByLabelText("Enabled"));
    await fireEvent.click(screen.getByRole("button", { name: "Apply source default" }));
    const confirmMode = screen.getByRole<HTMLButtonElement>("button", {
      name: "Confirm broad change",
    });
    expect(confirmMode.disabled).toBe(false);

    await fireEvent.click(manageCredentials);
    const token = await screen.findByLabelText("Bearer token");
    await fireEvent.input(token, { target: { value: "credential-secret" } });
    const saveReplacement = screen.getByRole<HTMLButtonElement>("button", {
      name: "Save replacement",
    });
    await waitFor(() => expect(saveReplacement.disabled).toBe(false));
    await fireEvent.click(saveReplacement);

    await waitFor(() => expect(confirmMode.disabled).toBe(true));
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Refresh schema and tools" }).disabled,
    ).toBe(true);
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Delete" }).disabled).toBe(true);

    replacement.resolve(
      Response.json({
        revision: 5,
        configuredSchemes: [{ name: "default", credentialType: "bearer" }],
      }),
    );
    await replacement.promise;
  });

  it("does not abort a source save while a different source refreshes the list", async () => {
    const replacement = deferred<Response>();
    const saveRequest = { signal: null as AbortSignal | null };
    let listCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          listCalls += 1;
          return Promise.resolve(
            Response.json({
              sources: [
                sourceFixture("source-a", "Source A"),
                sourceFixture("source-b", "Source B"),
              ],
              catalogRevision: listCalls,
            }),
          );
        }
        if (path === "/api/v1/sources/source-a/credentials" && init?.method === "PUT") {
          saveRequest.signal = init.signal ?? null;
          return replacement.promise;
        }
        if (path === "/api/v1/sources/source-a/credentials") {
          return Promise.resolve(
            Response.json({
              revision: 4,
              configuredSchemes: [{ name: "default", credentialType: "bearer" }],
            }),
          );
        }
        if (path === "/api/v1/sources/source-b/refresh" && init?.method === "POST") {
          return Promise.resolve(
            Response.json({
              sourceId: "source-b",
              sourceRevision: 2,
              catalogRevision: 2,
              globalRevision: 2,
              activeToolCount: 4,
              tombstonedToolCount: 0,
            }),
          );
        }
        if (path.endsWith("/oauth") && init?.method === undefined) {
          return Promise.resolve(emptyOAuthConnections());
        }
        return Promise.resolve(
          Response.json(
            {
              error: {
                code: "unexpected_test_request",
                message: `Unexpected request: ${path}`,
                requestId: "test-request",
              },
            },
            { status: 500 },
          ),
        );
      }),
    );
    render(SourcesPageHarness);

    const sourceAHeading = await screen.findByRole("heading", { name: "Source A" });
    const sourceBHeading = screen.getByRole("heading", { name: "Source B" });
    const sourceA = within(sourceAHeading.closest("article") ?? document.body);
    const sourceB = within(sourceBHeading.closest("article") ?? document.body);
    const manageCredentials = sourceA.getByRole<HTMLButtonElement>("button", {
      name: "Manage credentials",
    });
    await waitFor(() => expect(manageCredentials.disabled).toBe(false));
    await fireEvent.click(manageCredentials);
    const token = await sourceA.findByLabelText("Bearer token");
    await fireEvent.input(token, { target: { value: "source-a-secret" } });
    const saveReplacement = sourceA.getByRole<HTMLButtonElement>("button", {
      name: "Save replacement",
    });
    await waitFor(() => expect(saveReplacement.disabled).toBe(false));
    await fireEvent.click(saveReplacement);
    await waitFor(() => expect(saveRequest.signal).not.toBeNull());

    const refreshSourceB = sourceB.getByRole<HTMLButtonElement>("button", {
      name: "Refresh schema and tools",
    });
    await waitFor(() => expect(refreshSourceB.disabled).toBe(false));
    await fireEvent.click(refreshSourceB);
    await waitFor(() => expect(listCalls).toBe(2));
    expect(saveRequest.signal?.aborted).toBe(false);

    replacement.resolve(
      Response.json({
        revision: 5,
        configuredSchemes: [{ name: "default", credentialType: "bearer" }],
      }),
    );
    await replacement.promise;
    expect(await sourceA.findByText(/Credentials replaced/)).toBeDefined();
  });

  it("fences source writes through settlement and aborts a forced unmount", async () => {
    const firstRefresh = deferred<Response>();
    const secondRefresh = deferred<Response>();
    const refreshSignals: AbortSignal[] = [];
    let refreshCalls = 0;
    let listCalls = 0;
    let logoutCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          listCalls += 1;
          return Promise.resolve(
            Response.json({ sources: [openApiSourceFixture()], catalogRevision: listCalls }),
          );
        }
        if (path === "/api/v1/sources/openapi-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        if (path === "/api/v1/sources/openapi-source/refresh" && init?.method === "POST") {
          if (init.signal instanceof AbortSignal) refreshSignals.push(init.signal);
          refreshCalls += 1;
          return refreshCalls === 1 ? firstRefresh.promise : secondRefresh.promise;
        }
        if (path === "/api/v1/session" && init?.method === "DELETE") {
          logoutCalls += 1;
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    const mounted = render(SourcesPageHarness);

    const refresh = await screen.findByRole<HTMLButtonElement>("button", { name: "Refresh" });
    await waitFor(() => expect(refresh.disabled).toBe(false));
    await fireEvent.click(refresh);
    await waitFor(() => expect(refreshCalls).toBe(1));
    await expectPendingWriteFence(() => logoutCalls);
    expect(refreshSignals[0]?.aborted).toBe(false);

    firstRefresh.resolve(
      Response.json({
        sourceId: "openapi-source",
        sourceRevision: 2,
        catalogRevision: 2,
        globalRevision: 2,
        activeToolCount: 4,
        tombstonedToolCount: 0,
      }),
    );
    await waitFor(() => expect(listCalls).toBe(2));
    await waitFor(() => expect(refresh.disabled).toBe(false));
    const settledUnload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(settledUnload);
    expect(settledUnload.defaultPrevented).toBe(false);

    await fireEvent.click(refresh);
    await waitFor(() => expect(refreshCalls).toBe(2));
    mounted.unmount();
    expect(refreshSignals[1]?.aborted).toBe(true);
    secondRefresh.resolve(
      Response.json({
        sourceId: "openapi-source",
        sourceRevision: 3,
        catalogRevision: 3,
        globalRevision: 3,
        activeToolCount: 4,
        tombstonedToolCount: 0,
      }),
    );
    await secondRefresh.promise;
  });

  it("freezes the complete OpenAPI credential draft and fences each deferred save", async () => {
    const firstSave = deferred<Response>();
    const secondSave = deferred<Response>();
    const saveSignals: AbortSignal[] = [];
    let saveCalls = 0;
    let logoutCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          return Promise.resolve(
            Response.json({ sources: [openApiSourceFixture()], catalogRevision: 1 }),
          );
        }
        if (path === "/api/v1/sources/openapi-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        if (path === "/api/v1/sources/openapi-source/credentials" && init?.method === "PUT") {
          if (init.signal instanceof AbortSignal) saveSignals.push(init.signal);
          saveCalls += 1;
          return saveCalls === 1 ? firstSave.promise : secondSave.promise;
        }
        if (path === "/api/v1/sources/openapi-source/credentials") {
          return Promise.resolve(
            Response.json({
              revision: saveCalls + 4,
              configuredSchemes: [{ name: "default", credentialType: "bearer" }],
            }),
          );
        }
        if (path === "/api/v1/session" && init?.method === "DELETE") {
          logoutCalls += 1;
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    const mounted = render(SourcesPageHarness);

    const manage = await screen.findByRole<HTMLButtonElement>("button", {
      name: "Manage credentials",
    });
    await waitFor(() => expect(manage.disabled).toBe(false));
    await fireEvent.click(manage);
    const name = await screen.findByLabelText<HTMLInputElement>("Security scheme name");
    const type = screen.getByLabelText<HTMLSelectElement>("Type");
    const token = screen.getByLabelText<HTMLInputElement>("Bearer token");
    await fireEvent.input(token, { target: { value: "visible-only-in-disabled-input" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    const row = screen.getByRole<HTMLFieldSetElement>("group", { name: "Credential" });
    await waitFor(() => expect(row.disabled).toBe(true));
    expect(name.value).toBe("default");
    expect(type.value).toBe("bearer");
    expect(token.value).toBe("visible-only-in-disabled-input");
    expect(screen.getByRole("button", { name: "Saving..." })).toBeDefined();
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Add credential" }).disabled).toBe(
      true,
    );
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Clear all credentials" }).disabled,
    ).toBe(true);
    await expectPendingWriteFence(() => logoutCalls);
    expect(saveSignals[0]?.aborted).toBe(false);

    firstSave.resolve(
      Response.json({
        revision: 5,
        configuredSchemes: [{ name: "default", credentialType: "bearer" }],
      }),
    );
    expect(await screen.findByText(/Credentials were replaced/)).toBeDefined();
    await waitFor(() => expect(manage.disabled).toBe(false));

    await fireEvent.click(manage);
    const nextToken = await screen.findByLabelText<HTMLInputElement>("Bearer token");
    await fireEvent.input(nextToken, { target: { value: "second-save" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));
    await waitFor(() => expect(saveCalls).toBe(2));
    mounted.unmount();
    expect(saveSignals[1]?.aborted).toBe(true);
    secondSave.resolve(
      Response.json({
        revision: 6,
        configuredSchemes: [{ name: "default", credentialType: "bearer" }],
      }),
    );
    await secondSave.promise;
  });

  it("fences a deferred GraphQL credential write without trapping its metadata load", async () => {
    const replacement = deferred<Response>();
    const request = { signal: null as AbortSignal | null };
    let logoutCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [sourceFixture()], catalogRevision: 1 }));
        }
        if (path === "/api/v1/sources/graphql-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        if (path === "/api/v1/sources/graphql-source/credentials" && init?.method === "PUT") {
          request.signal = init.signal ?? null;
          return replacement.promise;
        }
        if (path === "/api/v1/sources/graphql-source/credentials") {
          return Promise.resolve(
            Response.json({
              revision: 4,
              configuredSchemes: [{ name: "default", credentialType: "bearer" }],
            }),
          );
        }
        if (path === "/api/v1/session" && init?.method === "DELETE") logoutCalls += 1;
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness);

    const manage = await screen.findByRole<HTMLButtonElement>("button", {
      name: "Manage credentials",
    });
    await waitFor(() => expect(manage.disabled).toBe(false));
    await fireEvent.click(manage);
    const token = await screen.findByLabelText("Bearer token");
    const loadUnload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(loadUnload);
    expect(loadUnload.defaultPrevented).toBe(false);
    await fireEvent.input(token, { target: { value: "graphql-secret" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));
    await waitFor(() => expect(request.signal).not.toBeNull());
    await expectPendingWriteFence(() => logoutCalls);
    expect(request.signal?.aborted).toBe(false);

    replacement.resolve(
      Response.json({
        revision: 5,
        configuredSchemes: [{ name: "default", credentialType: "bearer" }],
      }),
    );
    expect(await screen.findByText(/Credentials replaced/)).toBeDefined();
  });

  it("fences a deferred MCP credential write without trapping its metadata load", async () => {
    const replacement = deferred<Response>();
    const request = { signal: null as AbortSignal | null };
    let logoutCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          return Promise.resolve(
            Response.json({ sources: [mcpHttpSourceFixture()], catalogRevision: 1 }),
          );
        }
        if (path === "/api/v1/sources/mcp-http-source/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        if (path === "/api/v1/sources/mcp-http-source/credentials" && init?.method === "PUT") {
          request.signal = init.signal ?? null;
          return replacement.promise;
        }
        if (path === "/api/v1/sources/mcp-http-source/credentials") {
          return Promise.resolve(
            Response.json({
              revision: 4,
              configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
            }),
          );
        }
        if (path === "/api/v1/session" && init?.method === "DELETE") logoutCalls += 1;
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness);

    const manage = await screen.findByRole<HTMLButtonElement>("button", {
      name: "Manage credentials",
    });
    await waitFor(() => expect(manage.disabled).toBe(false));
    await fireEvent.click(manage);
    const token = await screen.findByLabelText("Bearer token");
    const loadUnload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(loadUnload);
    expect(loadUnload.defaultPrevented).toBe(false);
    await fireEvent.input(token, { target: { value: "mcp-secret" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));
    await waitFor(() => expect(request.signal).not.toBeNull());
    await expectPendingWriteFence(() => logoutCalls);
    expect(request.signal?.aborted).toBe(false);

    replacement.resolve(
      Response.json({
        revision: 5,
        configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
      }),
    );
    expect(await screen.findByText(/Credentials replaced/)).toBeDefined();
  });

  it("keeps source A OAuth drafts and writes stable while source B refreshes", async () => {
    const saveResponse = deferred<Response>();
    const deleteResponse = deferred<Response>();
    const saveRequest = { signal: null as AbortSignal | null };
    const deleteRequest = { signal: null as AbortSignal | null };
    let listCalls = 0;
    let sourceAOAuthLoads = 0;
    let sourceBRefreshes = 0;
    let logoutCalls = 0;
    const sourceAConnection = {
      ...oauthConnectionFixture("source-a-connection"),
      credentialKey: "default",
      requestedScopes: ["read"],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/sources") {
          listCalls += 1;
          return Promise.resolve(
            Response.json({
              sources: [
                sourceFixture("source-a", "Source A"),
                sourceFixture("source-b", "Source B"),
              ],
              catalogRevision: listCalls,
            }),
          );
        }
        if (path === "/api/v1/sources/source-a/oauth/default" && init?.method === "PUT") {
          saveRequest.signal = init.signal ?? null;
          return saveResponse.promise;
        }
        if (
          path.startsWith("/api/v1/sources/source-a/oauth/default") &&
          init?.method === "DELETE"
        ) {
          deleteRequest.signal = init.signal ?? null;
          return deleteResponse.promise;
        }
        if (path === "/api/v1/sources/source-a/oauth") {
          sourceAOAuthLoads += 1;
          return Promise.resolve(
            Response.json({
              connections: [sourceAConnection],
              availableCredentials: [],
            }),
          );
        }
        if (path === "/api/v1/sources/source-b/oauth") {
          return Promise.resolve(emptyOAuthConnections());
        }
        if (path === "/api/v1/sources/source-b/refresh" && init?.method === "POST") {
          sourceBRefreshes += 1;
          return Promise.resolve(
            Response.json({
              sourceId: "source-b",
              sourceRevision: sourceBRefreshes + 1,
              catalogRevision: sourceBRefreshes + 1,
              globalRevision: sourceBRefreshes + 1,
              activeToolCount: 4,
              tombstonedToolCount: 0,
            }),
          );
        }
        if (path === "/api/v1/session" && init?.method === "DELETE") logoutCalls += 1;
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(SourcesPageHarness);

    const sourceAHeading = await screen.findByRole("heading", { name: "Source A" });
    const sourceBHeading = screen.getByRole("heading", { name: "Source B" });
    const sourceA = within(sourceAHeading.closest("article") ?? document.body);
    const sourceB = within(sourceBHeading.closest("article") ?? document.body);
    const scopes = await sourceA.findByLabelText<HTMLInputElement>(/Requested scopes/);
    const initialOAuthLoads = sourceAOAuthLoads;
    await fireEvent.input(scopes, { target: { value: "read profile" } });
    await fireEvent.click(sourceA.getByRole("button", { name: "Save configuration" }));
    await waitFor(() => expect(saveRequest.signal).not.toBeNull());

    const refreshSourceB = sourceB.getByRole<HTMLButtonElement>("button", {
      name: "Refresh schema and tools",
    });
    await waitFor(() => expect(refreshSourceB.disabled).toBe(false));
    await fireEvent.click(refreshSourceB);
    await waitFor(() => expect(listCalls).toBe(2));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(saveRequest.signal?.aborted).toBe(false);
    expect(scopes.value).toBe("read profile");
    expect(sourceAOAuthLoads).toBe(initialOAuthLoads);
    expect(sourceA.getByRole("button", { name: "Saving..." })).toBeDefined();
    await expectPendingWriteFence(() => logoutCalls);

    saveResponse.resolve(
      Response.json({
        ...sourceAConnection,
        revision: 2,
        requestedScopes: ["read", "profile"],
      }),
    );
    expect(await sourceA.findByText(/OAuth configuration saved/)).toBeDefined();
    await waitFor(() =>
      expect(screen.queryByText(/source or credential change is still being saved/i)).toBeNull(),
    );

    await fireEvent.click(sourceA.getByRole("button", { name: "Delete configuration" }));
    const deleteDialog = sourceA.getByRole("dialog", {
      name: "Delete this OAuth configuration?",
    });
    await fireEvent.click(within(deleteDialog).getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(deleteRequest.signal).not.toBeNull());
    await fireEvent.click(refreshSourceB);
    await waitFor(() => expect(listCalls).toBe(3));
    expect(deleteRequest.signal?.aborted).toBe(false);
    expect(sourceAOAuthLoads).toBe(initialOAuthLoads);
    await expectPendingWriteFence(() => logoutCalls);

    deleteResponse.resolve(new Response(null, { status: 204 }));
    expect(await sourceA.findByText("OAuth configuration deleted.")).toBeDefined();
  });
});
