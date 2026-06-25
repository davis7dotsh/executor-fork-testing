import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { Effect } from "effect";
import { ApiError, type ApiResult, type McpStdioSourceInput, type Source } from "./api";
import McpStdioSourceForm from "./McpStdioSourceForm.svelte";

function sourceFixture(): Source {
  return {
    id: "source-stdio",
    kind: "mcp_stdio",
    slug: "github-local",
    displayName: "Local GitHub",
    description: null,
    configuration: { templateName: "github" },
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

describe("MCP stdio source form", () => {
  it("shows only trusted templates and preserves secret bytes in create payloads", async () => {
    const inputs: McpStdioSourceInput[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] }),
      ),
    );
    const create = vi.fn(async (input: McpStdioSourceInput) => {
      inputs.push(input);
      return { ok: true, value: sourceFixture() } as const;
    });
    const created = vi.fn();
    render(McpStdioSourceForm, { create, oncreated: created });

    await screen.findByRole("option", { name: "github" });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Local GitHub" },
    });
    await fireEvent.input(screen.getByLabelText("TOKEN"), {
      target: { value: " whitespace-sensitive " },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() => expect(created).toHaveBeenCalledOnce());
    expect(fetch).toHaveBeenCalledOnce();
    expect(inputs).toEqual([
      {
        kind: "mcp_stdio",
        displayName: "Local GitHub",
        templateName: "github",
        secretValues: { TOKEN: " whitespace-sensitive " },
      },
    ]);
    expect(document.body.textContent).not.toContain("whitespace-sensitive");
  });

  it("clears secrets whenever the trusted template changes", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () =>
        Response.json({
          templates: [
            { name: "github", secretFields: ["TOKEN"] },
            { name: "linear", secretFields: ["TOKEN"] },
          ],
        }),
      ),
    );
    render(McpStdioSourceForm, { create: vi.fn(), oncreated: vi.fn() });

    const selector = await screen.findByLabelText<HTMLSelectElement>("Trusted template");
    const secret = screen.getByLabelText<HTMLInputElement>("TOKEN");
    await fireEvent.input(secret, { target: { value: "must-not-cross-templates" } });
    await fireEvent.change(selector, { target: { value: "linear" } });

    expect(screen.getByLabelText<HTMLInputElement>("TOKEN").value).toBe("");
    expect(document.body.textContent).not.toContain("must-not-cross-templates");
  });

  it("shows an honest empty state instead of a dead connect action", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async () => Response.json({ templates: [] })),
    );
    render(McpStdioSourceForm, { create: vi.fn(), oncreated: vi.fn() });

    expect(await screen.findByText("No trusted local templates are configured.")).toBeDefined();
    expect(screen.getByText(/machine-admin JSON registry selected by/)).toBeDefined();
    expect(screen.getByText("--mcp-stdio-templates")).toBeDefined();
    expect(screen.getByText("EXECUTOR_MCP_STDIO_TEMPLATES_FILE")).toBeDefined();
    expect(document.body.textContent).not.toContain("local CLI");
    expect(screen.queryByRole("button", { name: "Connect source" })).toBeNull();
    expect(screen.getByRole("button", { name: "Refresh templates" })).toBeDefined();
  });

  it("retries a failed template refresh before making stale fields writable", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] }),
      )
      .mockImplementationOnce(() => Effect.runPromise(Effect.fail("offline")))
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] }),
      );
    vi.stubGlobal("fetch", fetcher);
    render(McpStdioSourceForm, { create: vi.fn(), oncreated: vi.fn() });

    await screen.findByRole("option", { name: "github" });
    await fireEvent.click(screen.getByRole("button", { name: "Refresh templates" }));
    expect(await screen.findByText(/Showing the last loaded template list/)).toBeDefined();
    expect(
      screen.getByRole<HTMLFieldSetElement>("group", { name: "Local process source" }).disabled,
    ).toBe(true);

    await fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() =>
      expect(
        screen.getByRole<HTMLFieldSetElement>("group", { name: "Local process source" }).disabled,
      ).toBe(false),
    );
  });

  it("clears secrets when a same-name template changes its approved fields", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] }),
      )
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "github", secretFields: ["API_KEY"] }] }),
      );
    vi.stubGlobal("fetch", fetcher);
    render(McpStdioSourceForm, { create: vi.fn(), oncreated: vi.fn() });

    const oldSecret = await screen.findByLabelText<HTMLInputElement>("TOKEN");
    await fireEvent.input(oldSecret, { target: { value: "must-be-forgotten" } });
    await fireEvent.click(screen.getByRole("button", { name: "Refresh templates" }));

    const nextSecret = await screen.findByLabelText<HTMLInputElement>("API_KEY");
    expect(nextSecret.value).toBe("");
    expect(screen.queryByLabelText("TOKEN")).toBeNull();
    expect(document.body.textContent).not.toContain("must-be-forgotten");
  });

  it("reports not busy on unmount and ignores a late create completion", async () => {
    const creation = deferred<ApiResult<Source>>();
    const request = { signal: null as AbortSignal | null };
    const busy = vi.fn();
    const created = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(() =>
        Promise.resolve(
          Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] }),
        ),
      ),
    );
    const create = vi.fn((_input: McpStdioSourceInput, signal: AbortSignal) => {
      request.signal = signal;
      return creation.promise;
    });
    const mounted = render(McpStdioSourceForm, { create, oncreated: created, onbusychange: busy });

    await screen.findByRole("option", { name: "github" });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Local GitHub" },
    });
    await fireEvent.input(screen.getByLabelText("TOKEN"), {
      target: { value: "forget-on-unmount" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));
    await waitFor(() => expect(busy).toHaveBeenLastCalledWith(true));

    mounted.unmount();
    expect(request.signal?.aborted).toBe(true);
    expect(busy).toHaveBeenLastCalledWith(false);
    creation.resolve({ ok: true, value: sourceFixture() });
    await creation.promise;
    await Promise.resolve();
    expect(created).not.toHaveBeenCalled();
  });

  it("clears template secrets and focuses a coordinator failure", async () => {
    const busy = vi.fn();
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] }),
      );
    vi.stubGlobal("fetch", fetcher);
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
    render(McpStdioSourceForm, { create, oncreated: vi.fn(), onbusychange: busy });

    await screen.findByRole("option", { name: "github" });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Local GitHub" },
    });
    await fireEvent.input(screen.getByLabelText("TOKEN"), {
      target: { value: "clear-me" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() => expect(screen.getByRole("alert")).toBeDefined());
    expect(screen.getByLabelText<HTMLInputElement>("TOKEN").value).toBe("");
    expect(busy).toHaveBeenLastCalledWith(false);
    expect(screen.getByText("Source recovery is pending.")).toBeDefined();
    expect(document.activeElement).toBe(document.getElementById("mcp-stdio-error"));
  });
});
