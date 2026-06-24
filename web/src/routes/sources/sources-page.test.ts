import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/svelte";
import SourcesPageHarness from "./sources-page.test-harness.svelte";

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

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Sources page GraphQL coordination", () => {
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
    await fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));

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
    await fireEvent.click(screen.getByLabelText("Enabled"));
    await fireEvent.click(screen.getByRole("button", { name: "Apply source default" }));
    const confirmMode = screen.getByRole<HTMLButtonElement>("button", {
      name: "Confirm broad change",
    });
    expect(confirmMode.disabled).toBe(false);

    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const token = await screen.findByLabelText("Bearer token");
    await fireEvent.input(token, { target: { value: "credential-secret" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

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
    await fireEvent.click(sourceA.getByRole("button", { name: "Manage credentials" }));
    const token = await sourceA.findByLabelText("Bearer token");
    await fireEvent.input(token, { target: { value: "source-a-secret" } });
    await fireEvent.click(sourceA.getByRole("button", { name: "Save replacement" }));
    await waitFor(() => expect(saveRequest.signal).not.toBeNull());

    await fireEvent.click(sourceB.getByRole("button", { name: "Refresh schema and tools" }));
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
});
