import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { Effect, Schema } from "effect";
import McpHttpSourceForm from "./McpHttpSourceForm.svelte";

const decodeJson = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Unknown));

function sourceFixture() {
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
    let submittedBody = "";
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      submittedBody = String(init?.body);
      return Response.json(sourceFixture(), { status: 201 });
    });
    vi.stubGlobal("fetch", fetcher);
    const created = vi.fn();
    render(McpHttpSourceForm, { oncreated: created });

    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://mcp.example.test/mcp" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Issue tracker" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() => expect(created).toHaveBeenCalledOnce());
    expect(decodeJson(submittedBody)).toEqual({
      kind: "mcp_http",
      displayName: "Issue tracker",
      endpoint: "https://mcp.example.test/mcp",
      allowPrivateNetwork: false,
    });
    expect(screen.getByLabelText<HTMLInputElement>("Endpoint").value).toBe("");
    expect(screen.getByLabelText<HTMLInputElement>("Source name").value).toBe("");
  });

  it("blocks an obvious private endpoint until the operator opts in", async () => {
    const fetcher = vi.fn<typeof fetch>();
    vi.stubGlobal("fetch", fetcher);
    render(McpHttpSourceForm, { oncreated: vi.fn() });

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
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("rejects a completion after unmount and aborts the request", async () => {
    const response = deferred<Response>();
    const request = { signal: null as AbortSignal | null };
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((_input, init) => {
        request.signal = init?.signal ?? null;
        return response.promise;
      }),
    );
    const created = vi.fn();
    const mounted = render(McpHttpSourceForm, { oncreated: created });
    await fireEvent.input(screen.getByLabelText("Endpoint"), {
      target: { value: "https://mcp.example.test/mcp" },
    });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Issue tracker" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    mounted.unmount();
    expect(request.signal?.aborted).toBe(true);
    response.resolve(Response.json(sourceFixture(), { status: 201 }));
    await response.promise;
    await Promise.resolve();
    expect(created).not.toHaveBeenCalled();
  });

  it("settles busy state and focuses the error after a network rejection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() => Effect.runPromise(Effect.fail("offline"))),
    );
    render(McpHttpSourceForm, { oncreated: vi.fn() });
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
    expect(bearer.disabled).toBe(false);
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Connect source" }).disabled).toBe(
      true,
    );
    expect(document.activeElement).toBe(document.getElementById("mcp-http-error"));
  });
});
