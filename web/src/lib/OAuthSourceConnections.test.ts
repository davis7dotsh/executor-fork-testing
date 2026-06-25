import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/svelte";
import OAuthSourceConnections from "./OAuthSourceConnections.svelte";
import type {
  OAuthConnectionList,
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

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

function operations() {
  const list: OAuthConnectionList = {
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

  it("keeps the prior list visible after a callback reload fails and consumes it after retry", async () => {
    const api = operations();
    const checked = vi.fn();
    api.load
      .mockResolvedValueOnce(
        success({
          connections: [],
          availableCredentials: [],
        }),
      )
      .mockResolvedValueOnce({
        ok: false,
        error: {
          code: "network_error",
          displayMessage: "Managed OAuth refresh failed.",
          requestId: "oauth-reload",
          status: 503,
        },
      })
      .mockResolvedValue(
        success({
          connections: [connection()],
          availableCredentials: [],
        }),
      );
    const mounted = render(OAuthSourceConnections, {
      source: source(),
      operations: api,
      oncallbackchecked: checked,
    });
    await waitFor(() => expect(api.load).toHaveBeenCalledOnce());

    await mounted.rerender({
      source: source(),
      operations: api,
      callbackRefreshKey: "success:connection-1",
      oncallbackchecked: checked,
    });

    const staleError = await screen.findByRole("alert");
    expect(staleError.textContent).toContain("Managed OAuth refresh failed.");
    expect(staleError.textContent).toContain("Showing the last loaded managed OAuth options.");
    expect(checked).not.toHaveBeenCalled();

    await fireEvent.click(screen.getByRole("button", { name: "Retry managed OAuth" }));
    await waitFor(() => expect(checked).toHaveBeenCalledOnce());
    expect(checked).toHaveBeenCalledWith(true);
    expect(screen.queryByText("Managed OAuth refresh failed.")).toBeNull();
    expect(screen.getByText(/OAuth authorization completed/)).toBeDefined();
  });

  it("ignores a late callback reload failure after a newer load succeeds", async () => {
    const api = operations();
    const oldLoad = deferred<OAuthOperationResult<OAuthConnectionList>>();
    const newLoad = deferred<OAuthOperationResult<OAuthConnectionList>>();
    api.load
      .mockResolvedValueOnce(
        success({
          connections: [],
          availableCredentials: [],
        }),
      )
      .mockImplementationOnce(() => oldLoad.promise)
      .mockImplementationOnce(() => newLoad.promise)
      .mockResolvedValue(
        success({
          connections: [connection()],
          availableCredentials: [],
        }),
      );
    const checked = vi.fn();
    const mounted = render(OAuthSourceConnections, {
      source: source(),
      operations: api,
      oncallbackchecked: checked,
    });
    await waitFor(() => expect(api.load).toHaveBeenCalledOnce());

    await mounted.rerender({
      source: source(),
      operations: api,
      callbackRefreshKey: "failed:connection-1",
      oncallbackchecked: checked,
    });
    await waitFor(() => expect(api.load).toHaveBeenCalledTimes(2));
    await mounted.rerender({
      source: source(),
      operations: api,
      callbackRefreshKey: "success:connection-1",
      oncallbackchecked: checked,
    });
    await waitFor(() => expect(api.load).toHaveBeenCalledTimes(3));
    newLoad.resolve(
      success({
        connections: [connection()],
        availableCredentials: [],
      }),
    );
    await waitFor(() => expect(checked).toHaveBeenCalledOnce());

    oldLoad.resolve({
      ok: false,
      error: {
        code: "network_error",
        displayMessage: "Late old failure.",
        requestId: null,
        status: 503,
      },
    });
    await oldLoad.promise;
    await Promise.resolve();
    expect(screen.queryByText("Late old failure.")).toBeNull();
    expect(screen.getByText(/OAuth authorization completed/)).toBeDefined();
  });

  it("uses collision-free panel IDs and keeps error focus inside the active credential panel", async () => {
    const api = operations();
    api.load.mockResolvedValue(
      success({
        connections: [
          connection({
            id: "dot-connection",
            credentialKey: "client.id",
            callbackUrl: "https://executor.example.test/callback/dot",
            clientAuthMethod: "client_secret_basic",
            hasClientSecret: true,
          }),
          connection({
            id: "dash-connection",
            credentialKey: "client-id",
            callbackUrl: "https://executor.example.test/callback/dash",
            clientAuthMethod: "client_secret_basic",
            hasClientSecret: true,
          }),
        ],
        availableCredentials: [],
      }),
    );
    api.save.mockResolvedValue({
      ok: false,
      error: {
        code: "invalid_oauth_configuration",
        displayMessage: "Review this OAuth configuration.",
        requestId: null,
        status: 400,
      },
    });
    render(OAuthSourceConnections, { source: source(), operations: api });

    const dotHeading = await screen.findByRole("heading", { name: "client.id" });
    const dashHeading = screen.getByRole("heading", { name: "client-id" });
    const dotPanel = dotHeading.closest("section");
    const dashPanel = dashHeading.closest("section");
    expect(dotPanel).not.toBeNull();
    expect(dashPanel).not.toBeNull();
    if (dotPanel === null || dashPanel === null) return;

    expect(dotHeading.id).not.toBe(dashHeading.id);
    expect(dotPanel.getAttribute("aria-labelledby")).toBe(dotHeading.id);
    expect(dashPanel.getAttribute("aria-labelledby")).toBe(dashHeading.id);
    const dotCallback = within(dotPanel).getByLabelText<HTMLInputElement>("Exact callback URL");
    const dashCallback = within(dashPanel).getByLabelText<HTMLInputElement>("Exact callback URL");
    expect(dotCallback.id).not.toBe(dashCallback.id);
    const dotRadio = dotPanel.querySelector<HTMLInputElement>('input[type="radio"]');
    const dashRadio = dashPanel.querySelector<HTMLInputElement>('input[type="radio"]');
    expect(dotRadio?.name).not.toBe(dashRadio?.name);

    await fireEvent.input(within(dotPanel).getByLabelText(/Requested scopes/), {
      target: { value: "dot-change" },
    });
    await fireEvent.click(within(dotPanel).getByRole("button", { name: "Save configuration" }));
    await waitFor(() => expect(dotPanel.contains(document.activeElement)).toBe(true));

    await fireEvent.input(within(dashPanel).getByLabelText(/Requested scopes/), {
      target: { value: "dash-change" },
    });
    await fireEvent.click(within(dashPanel).getByRole("button", { name: "Save configuration" }));
    await waitFor(() => expect(dashPanel.contains(document.activeElement)).toBe(true));
    expect(dotPanel.querySelector('[role="alert"]')?.id).not.toBe(
      dashPanel.querySelector('[role="alert"]')?.id,
    );
  });
});
