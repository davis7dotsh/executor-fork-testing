import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { ApiError, type ApiResult, type McpHttpSourceInput, type Source } from "./api";
import McpHttpSourceForm from "./McpHttpSourceForm.svelte";

function sourceFixture(): Source {
  return {
    id: "source-1",
    kind: "mcp_http",
    slug: "issues",
    displayName: "Issue tracker",
    description: null,
    configuration: { endpoint: "https://mcp.example.test/mcp", allowPrivateNetwork: false },
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

describe("MCP HTTP source form", () => {
  it("submits the stable source contract and clears the completed draft", async () => {
    const inputs: McpHttpSourceInput[] = [];
    const create = vi.fn(async (input: McpHttpSourceInput) => {
      inputs.push(input);
      return { ok: true, value: sourceFixture() } as const;
    });
    const created = vi.fn();
    render(McpHttpSourceForm, { create, oncreated: created });

    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://mcp.example.test/mcp" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Issue tracker" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() => expect(created).toHaveBeenCalledOnce());
    expect(inputs).toEqual([
      {
        kind: "mcp_http",
        displayName: "Issue tracker",
        endpoint: "https://mcp.example.test/mcp",
        allowPrivateNetwork: false,
      },
    ]);
    expect(screen.getByLabelText<HTMLInputElement>("Endpoint").value).toBe("");
    expect(screen.getByLabelText<HTMLInputElement>("Source name").value).toBe("");
  });

  it("blocks an obvious private endpoint until the operator opts in", async () => {
    const create = vi.fn();
    render(McpHttpSourceForm, { create, oncreated: vi.fn() });

    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "http://127.42.0.1:7331/mcp" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Local tools" },
    });

    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Connect source" }).disabled).toBe(
      true,
    );
    expect(screen.getByText(/Enable private network access/)).toBeDefined();
    expect(create).not.toHaveBeenCalled();
  });

  it("rejects a completion after unmount and aborts the request", async () => {
    const response = deferred<ApiResult<Source>>();
    const request = { signal: null as AbortSignal | null };
    const create = vi.fn((_input: McpHttpSourceInput, signal: AbortSignal) => {
      request.signal = signal;
      return response.promise;
    });
    const created = vi.fn();
    const mounted = render(McpHttpSourceForm, { create, oncreated: created });
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://mcp.example.test/mcp" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Issue tracker" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    mounted.unmount();
    expect(request.signal?.aborted).toBe(true);
    response.resolve({ ok: true, value: sourceFixture() });
    await response.promise;
    await Promise.resolve();
    expect(created).not.toHaveBeenCalled();
  });

  it("clears the submitted secret and focuses a coordinator failure", async () => {
    const busy = vi.fn();
    const create = vi.fn(
      async () =>
        ({
          ok: false,
          error: new ApiError({
            code: "source_create_recovery_pending",
            displayMessage: "Source recovery is pending.",
            requestId: null,
            status: 0,
          }),
        }) as const,
    );
    render(McpHttpSourceForm, { create, oncreated: vi.fn(), onbusychange: busy });
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://mcp.example.test/mcp" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Issue tracker" },
    });
    await fireEvent.change(screen.getByLabelText("Method"), {
      target: { value: "bearer" },
    });
    const bearer = screen.getByLabelText<HTMLInputElement>("Bearer token");
    await fireEvent.input(bearer, { target: { value: "clear-after-attempt" } });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    await waitFor(() => expect(bearer.value).toBe(""));
    expect(busy).toHaveBeenLastCalledWith(false);
    expect(screen.getByText("Source recovery is pending.")).toBeDefined();
    expect(document.activeElement).toBe(document.getElementById("mcp-http-error"));
  });
});
