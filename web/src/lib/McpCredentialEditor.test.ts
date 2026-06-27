import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { Schema } from "effect";
import McpCredentialEditor from "./McpCredentialEditor.svelte";
import type { Source } from "./api";

const decodeJson = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Unknown));

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

function deferredDecodedResponse() {
  const response = deferred<Response>();
  const settled = deferred<void>();
  return {
    promise: response.promise,
    settled: settled.promise,
    resolve(value: unknown) {
      const decodedResponse = Response.json(value);
      const read = decodedResponse.text.bind(decodedResponse);
      decodedResponse.text = async () => {
        const text = await read();
        // The next task starts after API decoding and component promise continuations settle.
        setTimeout(() => settled.resolve(undefined), 0);
        return text;
      };
      response.resolve(decodedResponse);
    },
  };
}

function source(kind: "mcp_http" | "mcp_stdio"): Source {
  return {
    id: `${kind}-source`,
    kind,
    slug: kind,
    displayName: kind === "mcp_http" ? "Remote MCP" : "Local MCP",
    description: null,
    configuration:
      kind === "mcp_http"
        ? { endpoint: "https://mcp.example.test/mcp", allowPrivateNetwork: false }
        : { templateName: "github" },
    modeOverride: null,
    healthStatus: "healthy",
    healthErrorCode: null,
    revision: 1,
    catalogRevision: 1,
    createdAt: 100,
    updatedAt: 100,
    lastRefreshedAt: 100,
    toolCount: 3,
    tombstonedToolCount: 0,
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("MCP credential editor", () => {
  it("preserves an unsaved HTTP secret across a temporary disabled state", async () => {
    const fetcher = vi.fn<typeof fetch>(async () =>
      Response.json({
        revision: 4,
        configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
      }),
    );
    vi.stubGlobal("fetch", fetcher);
    const mounted = render(McpCredentialEditor, { source: source("mcp_http") });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const token = await screen.findByLabelText<HTMLInputElement>("Bearer token");
    await fireEvent.input(token, { target: { value: "still-unsaved" } });

    await mounted.rerender({ source: source("mcp_http"), disabled: true });
    await waitFor(() => expect(token.closest("fieldset")?.hasAttribute("disabled")).toBe(true));
    expect(token.value).toBe("still-unsaved");

    await mounted.rerender({ source: source("mcp_http"), disabled: false });
    await waitFor(() => expect(token.closest("fieldset")?.hasAttribute("disabled")).toBe(false));
    expect(token.value).toBe("still-unsaved");
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("preserves an unsaved stdio secret across a temporary disabled state", async () => {
    const fetcher = vi.fn<typeof fetch>(async (input) => {
      if (String(input).endsWith("/credentials")) {
        return Response.json({
          revision: 9,
          configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
        });
      }
      return Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] });
    });
    vi.stubGlobal("fetch", fetcher);
    const mounted = render(McpCredentialEditor, { source: source("mcp_stdio") });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const secret = await screen.findByLabelText<HTMLInputElement>("TOKEN");
    await fireEvent.input(secret, { target: { value: "still-unsaved" } });

    await mounted.rerender({ source: source("mcp_stdio"), disabled: true });
    await waitFor(() => expect(secret.closest("fieldset")?.hasAttribute("disabled")).toBe(true));
    expect(secret.value).toBe("still-unsaved");

    await mounted.rerender({ source: source("mcp_stdio"), disabled: false });
    await waitFor(() => expect(secret.closest("fieldset")?.hasAttribute("disabled")).toBe(false));
    expect(secret.value).toBe("still-unsaved");
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("aborts a submitted secret, reloads metadata, and ignores the late save completion", async () => {
    const saveA = deferredDecodedResponse();
    const reloadB = deferredDecodedResponse();
    const request = { signal: null as AbortSignal | null };
    let metadataRequests = 0;
    const onbusychange = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((_input, init) => {
        if (init?.method !== "PUT") {
          metadataRequests += 1;
          if (metadataRequests === 2) return reloadB.promise;
          return Promise.resolve(
            Response.json({
              revision: 4,
              configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
            }),
          );
        }
        request.signal = init.signal ?? null;
        return saveA.promise;
      }),
    );
    const mounted = render(McpCredentialEditor, {
      source: source("mcp_http"),
      onbusychange,
    });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const token = await screen.findByLabelText<HTMLInputElement>("Bearer token");
    onbusychange.mockClear();
    await fireEvent.input(token, { target: { value: "must-be-cleared" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));
    await waitFor(() => expect(request.signal).not.toBeNull());
    await waitFor(() => expect(onbusychange.mock.calls).toEqual([[true]]));

    await mounted.rerender({
      source: source("mcp_http"),
      disabled: true,
      onbusychange,
    });
    await waitFor(() => expect(request.signal?.aborted).toBe(true));
    await waitFor(() => expect(screen.queryByLabelText("Bearer token")).toBeNull());
    await waitFor(() => expect(onbusychange.mock.calls).toEqual([[true], [false]]));
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Save replacement" }).disabled,
    ).toBe(true);

    await mounted.rerender({
      source: source("mcp_http"),
      disabled: false,
      onbusychange,
    });
    await waitFor(() => expect(metadataRequests).toBe(2));
    await waitFor(() => expect(onbusychange.mock.calls).toEqual([[true], [false], [true]]));
    reloadB.resolve({
      revision: 8,
      configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
    });
    await reloadB.settled;
    const reloadedToken = await screen.findByLabelText<HTMLInputElement>("Bearer token");
    expect(reloadedToken.value).toBe("");
    await waitFor(() =>
      expect(onbusychange.mock.calls).toEqual([[true], [false], [true], [false]]),
    );

    saveA.resolve({
      revision: 5,
      configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
    });
    await saveA.settled;
    expect(screen.getByRole("button", { name: "Close credentials" })).toBeDefined();
    expect(screen.queryByRole("status")).toBeNull();
    expect(onbusychange.mock.calls).toEqual([[true], [false], [true], [false]]);
  });

  it("reports only MCP credential writes as mutations and clears the fence on unmount", async () => {
    const saveResponse = deferredDecodedResponse();
    const request = { signal: null as AbortSignal | null };
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((_input, init) => {
        if (init?.method === "PUT") {
          request.signal = init.signal ?? null;
          return saveResponse.promise;
        }
        return Promise.resolve(
          Response.json({
            revision: 4,
            configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
          }),
        );
      }),
    );
    const onmutationchange = vi.fn();
    const mounted = render(McpCredentialEditor, {
      source: source("mcp_http"),
      onmutationchange,
    });

    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const token = await screen.findByLabelText<HTMLInputElement>("Bearer token");
    expect(onmutationchange).not.toHaveBeenCalled();
    await fireEvent.input(token, { target: { value: "pending-secret" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));
    await waitFor(() => expect(onmutationchange).toHaveBeenLastCalledWith(true));

    mounted.unmount();
    expect(request.signal?.aborted).toBe(true);
    expect(onmutationchange).toHaveBeenLastCalledWith(false);
    saveResponse.resolve({
      revision: 5,
      configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
    });
    await saveResponse.settled;
  });

  it("retries an aborted metadata load and ignores its late completion", async () => {
    const loadA = deferredDecodedResponse();
    const retryB = deferredDecodedResponse();
    const requests: AbortSignal[] = [];
    const onbusychange = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((_input, init) => {
        if (init?.signal instanceof AbortSignal) requests.push(init.signal);
        return requests.length === 1 ? loadA.promise : retryB.promise;
      }),
    );
    const mounted = render(McpCredentialEditor, {
      source: source("mcp_http"),
      onbusychange,
    });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    await waitFor(() => expect(requests).toHaveLength(1));
    await waitFor(() => expect(onbusychange.mock.calls).toEqual([[true]]));

    await mounted.rerender({
      source: source("mcp_http"),
      disabled: true,
      onbusychange,
    });
    await waitFor(() => expect(requests[0]?.aborted).toBe(true));
    await waitFor(() => expect(onbusychange.mock.calls).toEqual([[true], [false]]));

    await mounted.rerender({
      source: source("mcp_http"),
      disabled: false,
      onbusychange,
    });
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(screen.queryByLabelText("Username")).toBeNull();

    retryB.resolve({
      revision: 7,
      configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
    });
    await retryB.settled;
    await screen.findByLabelText("Bearer token");
    expect(onbusychange.mock.calls).toEqual([[true], [false], [true], [false]]);

    loadA.resolve({
      revision: 3,
      configuredSchemes: [{ name: "authorization", credentialType: "basic" }],
    });
    await loadA.settled;
    expect(screen.queryByLabelText("Username")).toBeNull();
    expect(screen.getByLabelText("Bearer token")).toBeDefined();
    expect(onbusychange.mock.calls).toEqual([[true], [false], [true], [false]]);
  });

  it("replaces HTTP API-key auth with the viewed CAS revision", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input, init) => {
        if (init?.method !== "PUT") {
          return Response.json({ revision: 4, configuredSchemes: [] });
        }
        bodies.push(decodeJson(String(init.body)));
        return Response.json({
          revision: 5,
          configuredSchemes: [{ name: "authorization", credentialType: "api_key_header" }],
        });
      }),
    );
    render(McpCredentialEditor, { source: source("mcp_http") });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const method = await screen.findByLabelText<HTMLSelectElement>("Method");
    await fireEvent.change(method, { target: { value: "api_key_header" } });
    await fireEvent.input(screen.getByLabelText("Header name"), {
      target: { value: "X-Service-Key" },
    });
    await fireEvent.input(screen.getByLabelText("Header value"), {
      target: { value: " exact key " },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    await waitFor(() => expect(screen.getByRole("status")).toBeDefined());
    expect(bodies).toEqual([
      {
        expectedRevision: 4,
        credential: {
          credential: {
            type: "api_key_header",
            name: "X-Service-Key",
            value: " exact key ",
          },
        },
      },
    ]);
    expect(document.body.textContent).not.toContain("exact key");
    expect(document.activeElement).toBe(
      document.getElementById("mcp-credential-status-mcp_http-source"),
    );
  });

  it("uses only template-approved stdio fields and preserves secret bytes", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input, init) => {
        if (String(input).endsWith("/credentials") && init?.method !== "PUT") {
          return Response.json({
            revision: 9,
            configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
          });
        }
        if (String(input) === "/api/v1/mcp/stdio/templates") {
          return Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] });
        }
        bodies.push(decodeJson(String(init?.body)));
        return Response.json({
          revision: 10,
          configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
        });
      }),
    );
    render(McpCredentialEditor, { source: source("mcp_stdio") });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const secret = await screen.findByLabelText<HTMLInputElement>("TOKEN");
    await fireEvent.input(secret, { target: { value: " exact token " } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    await waitFor(() => expect(screen.getByRole("status")).toBeDefined());
    expect(bodies).toEqual([
      {
        expectedRevision: 9,
        credential: { secretValues: { TOKEN: " exact token " } },
      },
    ]);
    expect(document.body.textContent).not.toContain("exact token");
  });

  it("clears secrets and focuses a CAS conflict for review", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({
          revision: 4,
          configuredSchemes: [{ name: "authorization", credentialType: "bearer" }],
        }),
      )
      .mockResolvedValueOnce(
        Response.json(
          {
            error: {
              code: "revision_conflict",
              message: "Credentials changed elsewhere.",
              requestId: "request-conflict",
            },
          },
          { status: 409 },
        ),
      );
    vi.stubGlobal("fetch", fetcher);
    render(McpCredentialEditor, { source: source("mcp_http") });
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    const token = await screen.findByLabelText<HTMLInputElement>("Bearer token");
    await fireEvent.input(token, { target: { value: "clear-after-conflict" } });
    await fireEvent.click(screen.getByRole("button", { name: "Save replacement" }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    expect(screen.queryByLabelText("Bearer token")).toBeNull();
    expect(document.body.textContent).not.toContain("clear-after-conflict");
    expect(document.activeElement).toBe(
      document.getElementById("mcp-credential-error-mcp_http-source"),
    );
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Save replacement" }).disabled,
    ).toBe(true);
  });

  it("does not reuse stdio fields when a later template lookup is invalid", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({
          revision: 2,
          configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
        }),
      )
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] }),
      )
      .mockResolvedValueOnce(
        Response.json({
          revision: 3,
          configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
        }),
      )
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "different", secretFields: ["OTHER"] }] }),
      );
    vi.stubGlobal("fetch", fetcher);
    render(McpCredentialEditor, { source: source("mcp_stdio") });

    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));
    await screen.findByLabelText("TOKEN");
    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await fireEvent.click(screen.getByRole("button", { name: "Manage credentials" }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    expect(screen.queryByLabelText("TOKEN")).toBeNull();
    expect(screen.queryByLabelText("OTHER")).toBeNull();
    expect(
      screen.getByRole<HTMLButtonElement>("button", { name: "Save replacement" }).disabled,
    ).toBe(true);
  });
});
