import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/svelte";
import { Effect, Schema } from "effect";
import McpStdioSourceForm from "./McpStdioSourceForm.svelte";

const decodeJson = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Unknown));

function sourceFixture() {
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

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("MCP stdio source form", () => {
  it("shows only trusted templates and preserves secret bytes in create payloads", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (input, init) => {
        if (String(input) === "/api/v1/mcp/stdio/templates") {
          return Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] });
        }
        expect(String(input)).toBe("/api/v1/sources");
        expect(init?.method).toBe("POST");
        bodies.push(decodeJson(String(init?.body)));
        return Response.json(sourceFixture(), { status: 201 });
      }),
    );
    const created = vi.fn();
    render(McpStdioSourceForm, { oncreated: created });

    await screen.findByRole("option", { name: "github" });
    await fireEvent.input(screen.getByLabelText("Source name"), {
      target: { value: "Local GitHub" },
    });
    await fireEvent.input(screen.getByLabelText("TOKEN"), {
      target: { value: " whitespace-sensitive " },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Connect source" }));

    await waitFor(() => expect(created).toHaveBeenCalledOnce());
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(bodies).toEqual([
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
    render(McpStdioSourceForm, { oncreated: vi.fn() });

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
    render(McpStdioSourceForm, { oncreated: vi.fn() });

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
    render(McpStdioSourceForm, { oncreated: vi.fn() });

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
    render(McpStdioSourceForm, { oncreated: vi.fn() });

    const oldSecret = await screen.findByLabelText<HTMLInputElement>("TOKEN");
    await fireEvent.input(oldSecret, { target: { value: "must-be-forgotten" } });
    await fireEvent.click(screen.getByRole("button", { name: "Refresh templates" }));

    const nextSecret = await screen.findByLabelText<HTMLInputElement>("API_KEY");
    expect(nextSecret.value).toBe("");
    expect(screen.queryByLabelText("TOKEN")).toBeNull();
    expect(document.body.textContent).not.toContain("must-be-forgotten");
  });

  it("clears entered secrets and restores controls after a failed create", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({ templates: [{ name: "github", secretFields: ["TOKEN"] }] }),
      )
      .mockImplementationOnce(() => Effect.runPromise(Effect.fail("offline")));
    vi.stubGlobal("fetch", fetcher);
    render(McpStdioSourceForm, { oncreated: vi.fn() });

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
    expect(document.activeElement).toBe(document.getElementById("mcp-stdio-error"));
  });
});
