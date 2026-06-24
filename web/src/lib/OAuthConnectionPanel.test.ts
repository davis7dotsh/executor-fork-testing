import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import OAuthConnectionPanel from "./OAuthConnectionPanel.svelte";
import type {
  OAuthConnectionOperations,
  OAuthConnectionList,
  OAuthConnectionSummary,
  OAuthOperationResult,
} from "./oauth-connection-state";

function summary(overrides: Partial<OAuthConnectionSummary> = {}): OAuthConnectionSummary {
  return {
    id: "oauth-1",
    credentialKey: "provider-oauth",
    revision: 4,
    status: "connected",
    issuer: "https://identity.example.test/",
    clientId: "executor-client",
    clientAuthMethod: "client_secret_basic",
    callbackUrl: "https://executor.example.test/api/v1/oauth/callback/provider-oauth",
    requestedScopes: ["read", "write"],
    grantedScopes: ["read"],
    hasClientSecret: true,
    hasRefreshToken: true,
    accessExpiresAt: 100,
    authorizedAt: 90,
    lastRefreshedAt: 95,
    errorCode: null,
    managedOAuthEligible: true,
    ...overrides,
  };
}

function success<Value>(value: Value): OAuthOperationResult<Value> {
  return { ok: true, value };
}

function connectionList(connections: readonly OAuthConnectionSummary[]): OAuthConnectionList {
  return { connections, availableCredentials: [] };
}

function operations(connection: OAuthConnectionSummary | null = summary()) {
  return {
    load: vi.fn(async (_sourceId: string, _signal: AbortSignal) =>
      success(connectionList(connection === null ? [] : [connection])),
    ),
    save: vi.fn(async (_sourceId, _credentialKey, _input, _signal) =>
      success(summary({ revision: 5 })),
    ),
    authorize: vi.fn(async (_sourceId, _credentialKey, _input, _signal) =>
      success({ authorizationUrl: "https://identity.example.test/authorize" }),
    ),
    disconnect: vi.fn(async (_sourceId, _credentialKey, _input, _signal) =>
      success(summary({ revision: 5, status: "ready_to_connect", hasRefreshToken: false })),
    ),
    remove: vi.fn(async (_sourceId, _credentialKey, _input, _signal) => success(undefined)),
  } satisfies OAuthConnectionOperations;
}

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

afterEach(() => cleanup());

describe("managed OAuth connection panel", () => {
  it("shows redacted connection metadata and keeps authorization separate from saving", async () => {
    const api = operations();
    const navigate = vi.fn();
    render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      operations: api,
      navigate,
    });

    expect(await screen.findByText("Connected")).toBeDefined();
    expect(screen.getByDisplayValue(summary().callbackUrl)).toBeDefined();
    expect(screen.getByText("Stored securely")).toBeDefined();
    expect(document.body.textContent).not.toContain("refresh-token");
    expect(document.body.textContent).not.toContain("client-secret");

    await fireEvent.input(screen.getByLabelText(/Requested scopes/), {
      target: { value: "read write profile" },
    });
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Connect OAuth" }).disabled).toBe(
      true,
    );
    await fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));

    await waitFor(() => expect(api.save).toHaveBeenCalledOnce());
    expect(api.save.mock.calls[0]?.[2]).toEqual({
      expectedRevision: 4,
      discovery: { type: "issuer", issuer: "https://identity.example.test/" },
      client: {
        clientId: "executor-client",
        authentication: "client_secret_basic",
        clientSecret: { action: "preserve" },
      },
      scopes: ["read", "write", "profile"],
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect OAuth" }));
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith("https://identity.example.test/authorize"),
    );
    expect(api.authorize).toHaveBeenCalledWith(
      "source-1",
      "provider-oauth",
      { expectedRevision: 5 },
      expect.any(AbortSignal),
    );
  });

  it("clears a replacement secret after a failed save without echoing it", async () => {
    const api = operations();
    const response = deferred<OAuthOperationResult<OAuthConnectionSummary>>();
    api.save.mockImplementation(() => response.promise);
    const failure = {
      ok: false,
      error: {
        code: "upstream_rejected",
        displayMessage: "The OAuth configuration was rejected.",
        requestId: "request-safe",
        status: 400,
      },
    } as const;
    render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      operations: api,
    });

    await screen.findByText("Connected");
    await fireEvent.click(screen.getByLabelText("Replace the saved secret"));
    const secret = screen.getByLabelText<HTMLInputElement>("New client secret");
    await fireEvent.input(secret, { target: { value: " never-render-this " } });
    await fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));

    await waitFor(() => expect(api.save).toHaveBeenCalledOnce());
    expect(screen.getByLabelText<HTMLInputElement>("New client secret").value).toBe("");
    expect(document.body.textContent).not.toContain("never-render-this");
    response.resolve(failure);
    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    expect(api.save.mock.calls[0]?.[2].client).toEqual({
      clientId: "executor-client",
      authentication: "client_secret_basic",
      clientSecret: { action: "replace", value: " never-render-this " },
    });
  });

  it("makes the public-client transition explicitly clear the stored secret", async () => {
    const api = operations();
    render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      operations: api,
    });

    await screen.findByText("Connected");
    await fireEvent.change(screen.getByLabelText("Client type"), { target: { value: "public" } });
    expect(screen.getByText(/clears the stored client secret/)).toBeDefined();
    await fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));
    await waitFor(() => expect(api.save).toHaveBeenCalledOnce());
    expect(api.save.mock.calls[0]?.[2].client).toEqual({
      clientId: "executor-client",
      authentication: "none",
    });
  });

  it("saves MCP discovery with default scopes and no required issuer override", async () => {
    const api = operations(null);
    render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "default",
      defaultRequestedScopes: ["tools.read", "tools.call"],
      discoveryType: "mcp",
      operations: api,
    });

    expect(await screen.findByDisplayValue("tools.read tools.call")).toBeDefined();
    await fireEvent.input(screen.getByLabelText("Client ID"), {
      target: { value: "executor-client" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));

    await waitFor(() => expect(api.save).toHaveBeenCalledOnce());
    expect(api.save.mock.calls[0]?.[2]).toEqual({
      expectedRevision: 0,
      discovery: { type: "mcp" },
      client: { clientId: "executor-client", authentication: "none" },
      scopes: ["tools.read", "tools.call"],
    });
  });

  it("refetches on an opaque callback key and rejects an older completion", async () => {
    const first = deferred<OAuthOperationResult<OAuthConnectionList>>();
    const second = deferred<OAuthOperationResult<OAuthConnectionList>>();
    const api = operations();
    api.load
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const mounted = render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      callbackRefreshKey: null,
      operations: api,
    });

    await mounted.rerender({
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      callbackRefreshKey: "success:oauth-1:provider-secret-data",
      operations: api,
    });
    second.resolve(success(connectionList([summary({ status: "connected" })])));
    const status = await screen.findByText("Connected");
    expect(status.getAttribute("role")).toBe("status");
    expect(status.getAttribute("aria-live")).toBe("polite");
    first.resolve(success(connectionList([summary({ status: "error" })])));
    await first.promise;
    await Promise.resolve();
    expect(screen.queryByText("Connection error")).toBeNull();
    expect(document.body.textContent).not.toContain("provider-secret-data");
  });

  it("aborts an owned load when the panel unmounts", async () => {
    const request = { signal: null as AbortSignal | null };
    const pending = deferred<OAuthOperationResult<OAuthConnectionList>>();
    const api = operations();
    api.load.mockImplementation((_sourceId, currentSignal) => {
      request.signal = currentSignal;
      return pending.promise;
    });
    const mounted = render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      operations: api,
    });

    await waitFor(() => expect(request.signal).not.toBeNull());
    mounted.unmount();
    expect(request.signal?.aborted).toBe(true);
  });

  it("aborts and rejects an authorization completion after the panel identity changes", async () => {
    const authorization = deferred<OAuthOperationResult<{ authorizationUrl: string }>>();
    const request = { signal: null as AbortSignal | null };
    const api = operations();
    api.authorize.mockImplementation((_sourceId, _credentialKey, _input, signal) => {
      request.signal = signal;
      return authorization.promise;
    });
    const navigate = vi.fn();
    const mounted = render(OAuthConnectionPanel, {
      sourceId: "source-a",
      credentialKey: "provider-oauth",
      operations: api,
      navigate,
    });
    await screen.findByText("Connected");
    await fireEvent.click(screen.getByRole("button", { name: "Connect OAuth" }));
    await waitFor(() => expect(request.signal).not.toBeNull());

    await mounted.rerender({
      sourceId: "source-b",
      credentialKey: "provider-oauth",
      operations: api,
      navigate,
    });
    expect(request.signal?.aborted).toBe(true);
    authorization.resolve(success({ authorizationUrl: "https://old.example.test/authorize" }));
    await authorization.promise;
    await Promise.resolve();
    expect(navigate).not.toHaveBeenCalled();
  });

  it("aborts a save when an OAuth callback triggers a status refresh", async () => {
    const response = deferred<OAuthOperationResult<OAuthConnectionSummary>>();
    const request = { signal: null as AbortSignal | null };
    const api = operations();
    api.save.mockImplementation((_sourceId, _credentialKey, _input, signal) => {
      request.signal = signal;
      return response.promise;
    });
    const mounted = render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      callbackRefreshKey: null,
      operations: api,
    });
    await screen.findByText("Connected");
    await fireEvent.input(screen.getByLabelText(/Requested scopes/), {
      target: { value: "read profile" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));
    await waitFor(() => expect(request.signal).not.toBeNull());

    await mounted.rerender({
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      callbackRefreshKey: "success:oauth-1",
      operations: api,
    });
    expect(request.signal?.aborted).toBe(true);
    response.resolve(success(summary({ revision: 99 })));
    await response.promise;
    await Promise.resolve();
    expect(screen.queryByText(/OAuth configuration saved/)).toBeNull();
  });

  it("aborts authorization when the operations implementation changes", async () => {
    const authorization = deferred<OAuthOperationResult<{ authorizationUrl: string }>>();
    const request = { signal: null as AbortSignal | null };
    const firstOperations = operations();
    firstOperations.authorize.mockImplementation((_sourceId, _credentialKey, _input, signal) => {
      request.signal = signal;
      return authorization.promise;
    });
    const nextOperations = operations();
    const navigate = vi.fn();
    const mounted = render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      operations: firstOperations,
      navigate,
    });
    await screen.findByText("Connected");
    await fireEvent.click(screen.getByRole("button", { name: "Connect OAuth" }));
    await waitFor(() => expect(request.signal).not.toBeNull());

    await mounted.rerender({
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      operations: nextOperations,
      navigate,
    });
    expect(request.signal?.aborted).toBe(true);
    authorization.resolve(success({ authorizationUrl: "https://old.example.test/authorize" }));
    await authorization.promise;
    await Promise.resolve();
    expect(navigate).not.toHaveBeenCalled();
  });

  it("clears a completed mutation notice when the panel identity changes", async () => {
    const api = operations();
    const mounted = render(OAuthConnectionPanel, {
      sourceId: "source-a",
      credentialKey: "provider-oauth",
      operations: api,
    });
    await screen.findByText("Connected");
    await fireEvent.input(screen.getByLabelText(/Requested scopes/), {
      target: { value: "read profile" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));
    expect(await screen.findByText(/OAuth configuration saved/)).toBeDefined();

    await mounted.rerender({
      sourceId: "source-b",
      credentialKey: "provider-oauth",
      operations: api,
    });
    await waitFor(() => expect(screen.queryByText(/OAuth configuration saved/)).toBeNull());
  });

  it("blocks a conflicted draft until the operator loads the latest revision", async () => {
    const api = operations();
    api.load
      .mockResolvedValueOnce(success(connectionList([summary({ revision: 4 })])))
      .mockResolvedValueOnce({
        ok: false,
        error: {
          code: "network_error",
          displayMessage: "Executor could not load the latest configuration.",
          requestId: null,
          status: 503,
        },
      })
      .mockResolvedValueOnce(
        success(connectionList([summary({ revision: 5, requestedScopes: ["server-change"] })])),
      );
    api.save
      .mockResolvedValueOnce({
        ok: false,
        error: {
          code: "revision_conflict",
          displayMessage: "OAuth configuration changed elsewhere.",
          requestId: "request-conflict",
          status: 409,
        },
      })
      .mockResolvedValueOnce(success(summary({ revision: 6 })));
    render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      operations: api,
    });
    await screen.findByText("Connected");
    let scopes = screen.getByLabelText<HTMLInputElement>(/Requested scopes/);
    await fireEvent.input(scopes, { target: { value: "my-draft" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));

    const retry = await screen.findByRole("button", { name: "Retry loading latest" });
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Save configuration" }).disabled,
    ).toBe(true);
    expect(api.save.mock.calls[0]?.[2].expectedRevision).toBe(4);
    await fireEvent.click(retry);
    const discard = await screen.findByRole("button", { name: "Discard draft and load latest" });
    await fireEvent.click(discard);
    await waitFor(() =>
      expect(screen.getByLabelText<HTMLInputElement>(/Requested scopes/).value).toBe(
        "server-change",
      ),
    );

    scopes = screen.getByLabelText<HTMLInputElement>(/Requested scopes/);
    await fireEvent.input(scopes, { target: { value: "server-change mine" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save configuration" }));
    await waitFor(() => expect(api.save).toHaveBeenCalledTimes(2));
    expect(api.save.mock.calls[1]?.[2].expectedRevision).toBe(5);
  });

  it("allows access-token-only disconnects and closes confirmation when status clears", async () => {
    const api = operations();
    api.load
      .mockResolvedValueOnce(
        success(connectionList([summary({ status: "connected", hasRefreshToken: false })])),
      )
      .mockResolvedValueOnce(
        success(connectionList([summary({ status: "ready_to_connect", hasRefreshToken: false })])),
      );
    const mounted = render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      callbackRefreshKey: null,
      operations: api,
    });
    expect(await screen.findByText("Not stored")).toBeDefined();
    const disconnect = screen.getByRole<HTMLButtonElement>("button", {
      name: "Disconnect tokens",
    });
    expect(disconnect.disabled).toBe(false);
    await fireEvent.click(disconnect);
    expect(screen.getByRole("dialog", { name: "Disconnect OAuth tokens?" })).toBeDefined();

    await mounted.rerender({
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      callbackRefreshKey: "success:oauth-1",
      operations: api,
    });
    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: "Disconnect OAuth tokens?" })).toBeNull(),
    );
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Disconnect tokens" }).disabled,
    ).toBe(true);
  });

  it("confirms destructive actions and manages keyboard focus", async () => {
    const api = operations();
    render(OAuthConnectionPanel, {
      sourceId: "source-1",
      credentialKey: "provider-oauth",
      operations: api,
    });
    await screen.findByText("Connected");

    const disconnectOpener = screen.getByRole("button", { name: "Disconnect tokens" });
    await fireEvent.click(disconnectOpener);
    const disconnectDialog = screen.getByRole("dialog", { name: "Disconnect OAuth tokens?" });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Disconnect tokens" }));
    await fireEvent.keyDown(disconnectDialog, { key: "Escape" });
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole("button", { name: "Disconnect tokens" }),
      ),
    );

    await fireEvent.click(screen.getByRole("button", { name: "Disconnect tokens" }));
    await fireEvent.click(screen.getByRole("button", { name: "Disconnect tokens" }));
    await waitFor(() => expect(api.disconnect).toHaveBeenCalledOnce());
    expect(api.disconnect).toHaveBeenCalledWith(
      "source-1",
      "provider-oauth",
      { expectedRevision: 4 },
      expect.any(AbortSignal),
    );
    const disconnectedNotice = screen.getByText(/OAuth tokens disconnected/);
    await waitFor(() => expect(document.activeElement).toBe(disconnectedNotice));
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Disconnect tokens" }).disabled,
    ).toBe(true);

    const deleteOpener = screen.getByRole("button", { name: "Delete configuration" });
    await fireEvent.click(deleteOpener);
    expect(screen.getByText("Delete this OAuth configuration?")).toBeDefined();
    const deleteDialog = screen.getByRole("dialog", {
      name: "Delete this OAuth configuration?",
    });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "Delete" }));
    await fireEvent.keyDown(deleteDialog, { key: "Escape" });
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole("button", { name: "Delete configuration" }),
      ),
    );

    await fireEvent.click(screen.getByRole("button", { name: "Delete configuration" }));
    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(api.remove).toHaveBeenCalledOnce());
    expect(screen.queryByDisplayValue(summary().callbackUrl)).toBeNull();
    const deletedNotice = screen.getByText("OAuth configuration deleted.");
    await waitFor(() => expect(document.activeElement).toBe(deletedNotice));
  });
});
