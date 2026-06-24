import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/svelte";
import OAuthSourceConnections from "./OAuthSourceConnections.svelte";
import type {
  OAuthConnectionOperations,
  OAuthConnectionSummary,
  OAuthOperationResult,
} from "./oauth-connection-state";
import type { Source } from "./api";

function source(): Source {
  return {
    id: "source-1",
    kind: "openapi",
    slug: "provider",
    displayName: "Provider API",
    description: null,
    configuration: {},
    modeOverride: null,
    healthStatus: "healthy",
    healthErrorCode: null,
    revision: 1,
    catalogRevision: 1,
    createdAt: 1,
    updatedAt: 1,
    lastRefreshedAt: 1,
    toolCount: 2,
    tombstonedToolCount: 0,
  };
}

function connection(overrides: Partial<OAuthConnectionSummary> = {}): OAuthConnectionSummary {
  return {
    id: "connection-1",
    credentialKey: "configured-oauth",
    revision: 3,
    status: "connected",
    issuer: "https://identity.example.test/",
    clientId: "executor",
    clientAuthMethod: "none",
    callbackUrl: "https://executor.example.test/api/v1/oauth/callback/connection-1",
    requestedScopes: ["read"],
    grantedScopes: ["read"],
    hasClientSecret: false,
    hasRefreshToken: true,
    accessExpiresAt: null,
    authorizedAt: 1,
    lastRefreshedAt: 1,
    errorCode: null,
    managedOAuthEligible: true,
    ...overrides,
  };
}

function success<Value>(value: Value): OAuthOperationResult<Value> {
  return { ok: true, value };
}

function operations() {
  const list = {
    connections: [connection()],
    availableCredentials: [
      {
        credentialKey: "new-oauth",
        protocol: "openapi" as const,
        requestedScopes: ["read", "write"],
        managedOAuthEligible: true as const,
      },
    ],
  };
  return {
    load: vi.fn(async () => success(list)),
    save: vi.fn(async () => success(connection())),
    authorize: vi.fn(async () =>
      success({ authorizationUrl: "https://identity.example.test/authorize?state=opaque" }),
    ),
    disconnect: vi.fn(async () =>
      success({ ...connection(), status: "ready_to_connect" as const }),
    ),
    remove: vi.fn(async () => success(undefined)),
  } satisfies OAuthConnectionOperations;
}

afterEach(cleanup);

describe("OAuth source connections", () => {
  it("renders only discovered and configured credential keys without a free-form key", async () => {
    const api = operations();
    render(OAuthSourceConnections, { source: source(), operations: api });

    expect(await screen.findByText("new-oauth")).toBeDefined();
    expect(screen.getByText("configured-oauth")).toBeDefined();
    expect(screen.queryByLabelText(/Credential key/i)).toBeNull();
    expect(screen.getByDisplayValue("read write")).toBeDefined();
  });

  it("announces and consumes a failed callback only after its connection source refetches", async () => {
    const api = operations();
    const checked = vi.fn();
    const busy = vi.fn();
    const mounted = render(OAuthSourceConnections, {
      source: source(),
      operations: api,
      callbackRefreshKey: "failed:connection-1",
      oncallbackchecked: checked,
      onbusychange: busy,
    });

    await waitFor(() => expect(checked).toHaveBeenCalledWith(true));
    expect(screen.getByRole("alert").textContent).toContain("OAuth authorization did not complete");
    expect(busy).toHaveBeenCalledWith(true);
    await waitFor(() => expect(busy).toHaveBeenLastCalledWith(false));

    await mounted.rerender({
      source: source(),
      operations: api,
      callbackRefreshKey: "success:connection-1",
      oncallbackchecked: checked,
      onbusychange: busy,
    });
    expect(await screen.findByText(/OAuth authorization completed/)).toBeDefined();
    expect(screen.queryByText(/OAuth authorization did not complete/)).toBeNull();
  });

  it("cleans a failed callback for a missing connection without claiming a connection result", async () => {
    const api = operations();
    api.load.mockResolvedValue(
      success({
        connections: [],
        availableCredentials: [
          {
            credentialKey: "new-oauth",
            protocol: "openapi",
            requestedScopes: [],
            managedOAuthEligible: true,
          },
        ],
      }),
    );
    const checked = vi.fn();
    render(OAuthSourceConnections, {
      source: source(),
      operations: api,
      callbackRefreshKey: "failed:deleted-connection",
      oncallbackchecked: checked,
    });

    await waitFor(() => expect(checked).toHaveBeenCalledWith(false));
    expect(screen.queryByText(/OAuth authorization did not complete/)).toBeNull();
  });

  it("keeps configured but ineligible connections removable while blocking save and connect", async () => {
    const api = operations();
    api.load.mockResolvedValue(
      success({
        connections: [connection({ managedOAuthEligible: false })],
        availableCredentials: [],
      }),
    );
    render(OAuthSourceConnections, { source: source(), operations: api });

    expect(await screen.findByText(/no longer offers this managed OAuth credential/)).toBeDefined();
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Save configuration" }).disabled,
    ).toBe(true);
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Connect OAuth" }).disabled).toBe(
      true,
    );
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Disconnect tokens" }).disabled,
    ).toBe(false);
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Delete configuration" }).disabled,
    ).toBe(false);
  });
});
