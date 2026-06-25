import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/svelte";
import type { SourceList, ToolPage, ToolRecord } from "$lib/api";
import ToolsPageHarness from "./tools-page.test-harness.svelte";

const catalogRevision = 37;

function toolFixture(id: string, displayName: string) {
  return {
    id,
    sourceId: "source-1",
    sourceSlug: "product-api",
    stableKey: id,
    localName: id,
    callablePath: `tools.product_api.${id}`,
    sandboxPath: `tools.product_api.${id}`,
    displayName,
    description: null,
    intrinsicMode: "ask",
    modeOverride: null,
    effectiveMode: { mode: "ask", provenance: "intrinsic" },
    present: true,
    revision: 3,
    createdAt: 100,
    updatedAt: 100,
    lastSeenAt: 100,
    tombstonedAt: null,
  } satisfies ToolPage["items"][number];
}

const alphaTool = toolFixture("tool-a", "Alpha tool");
const tools = [alphaTool, toolFixture("tool-b", "Beta tool"), toolFixture("tool-c", "Gamma tool")];

function toolRecordFixture(tool: ToolPage["items"][number], mode: ToolRecord["modeOverride"]) {
  return {
    ...tool,
    modeOverride: mode,
    effectiveMode: {
      mode: mode ?? tool.intrinsicMode,
      provenance: mode === null ? "intrinsic" : "tool_override",
    },
    inputSchema: { type: "object" },
    outputSchema: null,
    inputTypescript: null,
    outputTypescript: null,
    typescriptDefinitions: {},
  } satisfies ToolRecord;
}

function toolPageResponse(revision = catalogRevision, items: ToolPage["items"] = tools) {
  return Response.json({
    items,
    total: items.length,
    hasMore: false,
    nextOffset: null,
    catalogRevision: revision,
  });
}

function sourceFixture() {
  return {
    id: "source-1",
    kind: "graphql",
    slug: "product-api",
    displayName: "Product API",
    description: null,
    configuration: { endpoint: "https://api.example.test/", allowPrivateNetwork: false },
    modeOverride: "enabled",
    healthStatus: "healthy",
    healthErrorCode: null,
    revision: 4,
    catalogRevision,
    createdAt: 100,
    updatedAt: 100,
    lastRefreshedAt: 100,
    toolCount: 1,
    tombstonedToolCount: 0,
  } satisfies SourceList["sources"][number];
}

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

function stubToolsApi() {
  const bulkRequestBodies: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn<typeof fetch>((input, init) => {
      const path = String(input);
      if (path.startsWith("/api/v1/tools?")) {
        return Promise.resolve(toolPageResponse());
      }
      if (path === "/api/v1/sources") {
        return Promise.resolve(Response.json({ sources: [], catalogRevision }));
      }
      if (path === "/api/v1/tools/modes" && init?.method === "PATCH") {
        bulkRequestBodies.push(String(init.body));
        return Promise.resolve(
          Response.json({
            updatedCount: 2,
            catalogRevision: catalogRevision + 1,
            sourceRevisions: { "source-1": 4 },
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
  return bulkRequestBodies;
}

async function openDisabledConfirmation() {
  const alphaSelection = await screen.findByLabelText<HTMLInputElement>("Select Alpha tool");
  const betaSelection = screen.getByLabelText<HTMLInputElement>("Select Beta tool");
  const gammaSelection = screen.getByLabelText<HTMLInputElement>("Select Gamma tool");
  await fireEvent.click(alphaSelection);
  await fireEvent.click(betaSelection);

  const bulkModes = screen.getByRole<HTMLFieldSetElement>("group", {
    name: "Set selected tools",
  });
  await fireEvent.click(within(bulkModes).getByLabelText("Disabled"));
  const applyButton = screen.getByRole<HTMLButtonElement>("button", {
    name: "Apply Disabled to 2 selected",
  });
  applyButton.focus();
  await fireEvent.click(applyButton);

  const confirmation = await screen.findByRole("group", {
    name: "Confirm bulk tool behavior",
  });
  return {
    alphaSelection,
    betaSelection,
    gammaSelection,
    bulkModes,
    applyButton,
    confirmation,
  };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Tools page bulk confirmation", () => {
  it("freezes the visible target snapshot and restores controls and opener focus on cancel", async () => {
    stubToolsApi();
    render(ToolsPageHarness);

    const { alphaSelection, betaSelection, gammaSelection, bulkModes, applyButton, confirmation } =
      await openDisabledConfirmation();
    const selectAll = screen.getByLabelText<HTMLInputElement>(
      "Select all active tools on this page",
    );
    const inheritButton = screen.getByRole<HTMLButtonElement>("button", {
      name: "Apply Inherit to 2 selected",
    });
    const alphaModes = within(
      alphaSelection.closest("tr") ?? document.body,
    ).getByRole<HTMLFieldSetElement>("group", { name: "Behavior for Alpha tool" });
    const betaModes = within(
      betaSelection.closest("tr") ?? document.body,
    ).getByRole<HTMLFieldSetElement>("group", { name: "Behavior for Beta tool" });
    const gammaModes = within(
      gammaSelection.closest("tr") ?? document.body,
    ).getByRole<HTMLFieldSetElement>("group", { name: "Behavior for Gamma tool" });
    const cancelButton = within(confirmation).getByRole<HTMLButtonElement>("button", {
      name: "Cancel",
    });
    const confirmButton = within(confirmation).getByRole<HTMLButtonElement>("button", {
      name: "Confirm Disabled",
    });

    await waitFor(() => expect(document.activeElement).toBe(cancelButton));
    expect(screen.getByText("2 selected on this page")).toBeDefined();
    expect(screen.getByText(`Bulk changes use catalog revision ${catalogRevision}.`)).toBeDefined();
    expect(alphaSelection.checked).toBe(true);
    expect(betaSelection.checked).toBe(true);
    expect(gammaSelection.checked).toBe(false);
    expect(selectAll.disabled).toBe(true);
    expect(alphaSelection.disabled).toBe(true);
    expect(betaSelection.disabled).toBe(true);
    expect(gammaSelection.disabled).toBe(true);
    expect(bulkModes.disabled).toBe(true);
    expect(applyButton.disabled).toBe(true);
    expect(inheritButton.disabled).toBe(true);
    expect(alphaModes.disabled).toBe(true);
    expect(betaModes.disabled).toBe(true);
    expect(gammaModes.disabled).toBe(true);
    expect(cancelButton.disabled).toBe(false);
    expect(confirmButton.disabled).toBe(false);

    await fireEvent.click(cancelButton);

    await waitFor(() => expect(document.activeElement).toBe(applyButton));
    expect(screen.queryByRole("group", { name: "Confirm bulk tool behavior" })).toBeNull();
    expect(selectAll.disabled).toBe(false);
    expect(alphaSelection.disabled).toBe(false);
    expect(betaSelection.disabled).toBe(false);
    expect(gammaSelection.disabled).toBe(false);
    expect(bulkModes.disabled).toBe(false);
    expect(applyButton.disabled).toBe(false);
    expect(inheritButton.disabled).toBe(false);
    expect(alphaModes.disabled).toBe(false);
    expect(betaModes.disabled).toBe(false);
    expect(gammaModes.disabled).toBe(false);
  });

  it("blocks broad confirmation through a per-tool mutation and its list refresh", async () => {
    const modeMutation = deferred<Response>();
    const listRefresh = deferred<Response>();
    let listCalls = 0;
    let modeMutationCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path.startsWith("/api/v1/tools?")) {
          listCalls += 1;
          return listCalls === 1 ? Promise.resolve(toolPageResponse()) : listRefresh.promise;
        }
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [], catalogRevision }));
        }
        if (path === "/api/v1/tools/tool-a/mode" && init?.method === "PATCH") {
          modeMutationCalls += 1;
          return modeMutation.promise;
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
    render(ToolsPageHarness);

    const alphaSelection = await screen.findByLabelText<HTMLInputElement>("Select Alpha tool");
    const betaSelection = screen.getByLabelText<HTMLInputElement>("Select Beta tool");
    await fireEvent.click(alphaSelection);
    await fireEvent.click(betaSelection);
    const bulkModes = screen.getByRole<HTMLFieldSetElement>("group", {
      name: "Set selected tools",
    });
    await fireEvent.click(within(bulkModes).getByLabelText("Disabled"));
    const applyButton = screen.getByRole<HTMLButtonElement>("button", {
      name: "Apply Disabled to 2 selected",
    });
    const alphaModes = within(
      alphaSelection.closest("tr") ?? document.body,
    ).getByRole<HTMLFieldSetElement>("group", { name: "Behavior for Alpha tool" });

    await fireEvent.click(within(alphaModes).getByLabelText("Enabled"));

    await waitFor(() => expect(modeMutationCalls).toBe(1));
    expect(screen.queryByText("Refreshing...")).toBeNull();
    expect(bulkModes.disabled).toBe(true);
    expect(applyButton.disabled).toBe(true);
    await fireEvent.click(applyButton);
    expect(screen.queryByRole("group", { name: "Confirm bulk tool behavior" })).toBeNull();

    modeMutation.resolve(Response.json(toolRecordFixture(alphaTool, "enabled")));

    await waitFor(() => expect(listCalls).toBe(2));
    expect(await screen.findByText("Refreshing...")).toBeDefined();
    expect(bulkModes.disabled).toBe(true);
    expect(applyButton.disabled).toBe(true);
    await fireEvent.click(applyButton);
    expect(screen.queryByRole("group", { name: "Confirm bulk tool behavior" })).toBeNull();

    listRefresh.resolve(toolPageResponse(catalogRevision + 1));

    await waitFor(() => expect(applyButton.disabled).toBe(false));
    expect(screen.queryByText("Refreshing...")).toBeNull();
    await fireEvent.click(applyButton);
    expect(await screen.findByRole("group", { name: "Confirm bulk tool behavior" })).toBeDefined();
  });

  for (const scenario of [
    { label: "Ask", mode: "ask", buttonName: "Apply Ask to 2 selected" },
    { label: "Inherit", mode: null, buttonName: "Apply Inherit to 2 selected" },
  ] as const) {
    it(`locks every row through a deferred bulk ${scenario.label} mutation`, async () => {
      const bulkMutation = deferred<Response>();
      const patchRequests: Array<{ path: string; body: string }> = [];
      vi.stubGlobal(
        "fetch",
        vi.fn<typeof fetch>((input, init) => {
          const path = String(input);
          if (path.startsWith("/api/v1/tools?")) {
            return Promise.resolve(toolPageResponse());
          }
          if (path === "/api/v1/sources") {
            return Promise.resolve(Response.json({ sources: [], catalogRevision }));
          }
          if (init?.method === "PATCH") {
            patchRequests.push({ path, body: String(init.body) });
            if (path === "/api/v1/tools/modes") return bulkMutation.promise;
            return Promise.resolve(Response.json(toolRecordFixture(alphaTool, "enabled")));
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
      render(ToolsPageHarness);

      const alphaSelection = await screen.findByLabelText<HTMLInputElement>("Select Alpha tool");
      const betaSelection = screen.getByLabelText<HTMLInputElement>("Select Beta tool");
      const gammaSelection = screen.getByLabelText<HTMLInputElement>("Select Gamma tool");
      await fireEvent.click(alphaSelection);
      await fireEvent.click(betaSelection);
      const bulkModes = screen.getByRole<HTMLFieldSetElement>("group", {
        name: "Set selected tools",
      });
      const applyButton = screen.getByRole<HTMLButtonElement>("button", {
        name: scenario.buttonName,
      });
      const alphaModes = within(
        alphaSelection.closest("tr") ?? document.body,
      ).getByRole<HTMLFieldSetElement>("group", { name: "Behavior for Alpha tool" });
      const betaModes = within(
        betaSelection.closest("tr") ?? document.body,
      ).getByRole<HTMLFieldSetElement>("group", { name: "Behavior for Beta tool" });
      const gammaModes = within(
        gammaSelection.closest("tr") ?? document.body,
      ).getByRole<HTMLFieldSetElement>("group", { name: "Behavior for Gamma tool" });
      applyButton.focus();

      await fireEvent.click(applyButton);

      await waitFor(() => expect(patchRequests).toHaveLength(1));
      expect(screen.queryByRole("group", { name: "Confirm bulk tool behavior" })).toBeNull();
      expect(alphaSelection.disabled).toBe(true);
      expect(betaSelection.disabled).toBe(true);
      expect(gammaSelection.disabled).toBe(true);
      expect(bulkModes.disabled).toBe(true);
      expect(alphaModes.disabled).toBe(true);
      expect(betaModes.disabled).toBe(true);
      expect(gammaModes.disabled).toBe(true);

      await fireEvent.change(within(alphaModes).getByLabelText("Enabled"));

      expect(patchRequests).toEqual([
        {
          path: "/api/v1/tools/modes",
          body: JSON.stringify({
            selection: {
              type: "tool_ids",
              toolIds: ["tool-a", "tool-b"],
              expectedCatalogRevision: catalogRevision,
            },
            mode: scenario.mode,
          }),
        },
      ]);

      bulkMutation.resolve(
        Response.json({
          updatedCount: 2,
          catalogRevision: catalogRevision + 1,
          sourceRevisions: { "source-1": 4 },
        }),
      );

      const status = await screen.findByText(`${scenario.label} applied to 2 selected tools.`);
      await waitFor(() => expect(document.activeElement).toBe(status));
      await waitFor(() => expect(alphaModes.disabled).toBe(false));
      expect(patchRequests).toHaveLength(1);
    });
  }

  it("confirms a frozen Inherit transition from Disabled to source Enabled", async () => {
    const disabledTool = {
      ...alphaTool,
      modeOverride: "disabled",
      effectiveMode: { mode: "disabled", provenance: "tool_override" },
    } satisfies ToolPage["items"][number];
    const bulkMutation = deferred<Response>();
    const patchRequests: Array<{ path: string; body: string }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path.startsWith("/api/v1/tools?")) {
          return Promise.resolve(toolPageResponse(catalogRevision, [disabledTool]));
        }
        if (path === "/api/v1/sources") {
          return Promise.resolve(Response.json({ sources: [sourceFixture()], catalogRevision }));
        }
        if (init?.method === "PATCH") {
          patchRequests.push({ path, body: String(init.body) });
          if (path === "/api/v1/tools/modes") return bulkMutation.promise;
          return Promise.resolve(Response.json(toolRecordFixture(disabledTool, "ask")));
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
    render(ToolsPageHarness);

    const selection = await screen.findByLabelText<HTMLInputElement>("Select Alpha tool");
    const rowModes = within(
      selection.closest("tr") ?? document.body,
    ).getByRole<HTMLFieldSetElement>("group", { name: "Behavior for Alpha tool" });
    await within(rowModes).findByLabelText("Inherit (currently Enabled)");
    await fireEvent.click(selection);
    const bulkModes = screen.getByRole<HTMLFieldSetElement>("group", {
      name: "Set selected tools",
    });
    const inheritButton = screen.getByRole<HTMLButtonElement>("button", {
      name: "Apply Inherit to 1 selected",
    });

    await fireEvent.click(inheritButton);

    const confirmation = await screen.findByRole("group", {
      name: "Confirm bulk tool behavior",
    });
    expect(
      within(confirmation).getByText(
        "Inherit 1 selected tool? 1 tool will become Enabled under its source default.",
      ),
    ).toBeDefined();
    expect(patchRequests).toHaveLength(0);
    expect(selection.checked).toBe(true);
    expect(selection.disabled).toBe(true);
    expect(bulkModes.disabled).toBe(true);
    expect(rowModes.disabled).toBe(true);
    const cancelButton = within(confirmation).getByRole<HTMLButtonElement>("button", {
      name: "Cancel",
    });
    const confirmButton = within(confirmation).getByRole<HTMLButtonElement>("button", {
      name: "Confirm Inherit",
    });
    expect(cancelButton.disabled).toBe(false);
    expect(confirmButton.disabled).toBe(false);

    await fireEvent.click(cancelButton);

    await waitFor(() => expect(document.activeElement).toBe(inheritButton));
    expect(screen.queryByRole("group", { name: "Confirm bulk tool behavior" })).toBeNull();
    await fireEvent.click(inheritButton);
    const applyConfirmation = await screen.findByRole("group", {
      name: "Confirm bulk tool behavior",
    });
    const applyCancelButton = within(applyConfirmation).getByRole<HTMLButtonElement>("button", {
      name: "Cancel",
    });
    const applyConfirmButton = within(applyConfirmation).getByRole<HTMLButtonElement>("button", {
      name: "Confirm Inherit",
    });

    await fireEvent.click(applyConfirmButton);

    await waitFor(() => expect(patchRequests).toHaveLength(1));
    expect(patchRequests[0]).toEqual({
      path: "/api/v1/tools/modes",
      body: JSON.stringify({
        selection: {
          type: "tool_ids",
          toolIds: ["tool-a"],
          expectedCatalogRevision: catalogRevision,
        },
        mode: null,
      }),
    });
    expect(selection.disabled).toBe(true);
    expect(bulkModes.disabled).toBe(true);
    expect(rowModes.disabled).toBe(true);
    expect(applyCancelButton.disabled).toBe(true);
    expect(applyConfirmButton.disabled).toBe(true);

    await fireEvent.change(within(rowModes).getByLabelText("Ask"));
    expect(patchRequests).toHaveLength(1);

    bulkMutation.resolve(
      Response.json({
        updatedCount: 1,
        catalogRevision: catalogRevision + 1,
        sourceRevisions: { "source-1": 5 },
      }),
    );

    const status = await screen.findByText("Inherit applied to 1 selected tool.");
    await waitFor(() => expect(document.activeElement).toBe(status));
  });

  it("uses a visible accessible Select all control at 390px", async () => {
    vi.stubGlobal("innerWidth", 390);
    stubToolsApi();
    render(ToolsPageHarness);

    const alphaSelection = await screen.findByLabelText<HTMLInputElement>("Select Alpha tool");
    const selectAll = screen.getByLabelText<HTMLInputElement>(
      "Select all active tools on this page",
    );
    expect(selectAll.closest("thead")).toBeNull();
    expect(selectAll.closest(".mobile-select-all")).not.toBeNull();
    expect(
      document.querySelector('thead input[aria-label="Select all active tools on this page"]'),
    ).toBeNull();

    await fireEvent.click(alphaSelection);
    await waitFor(() => expect(selectAll.indeterminate).toBe(true));
    await fireEvent.click(selectAll);
    await waitFor(() => expect(selectAll.checked).toBe(true));
    expect(screen.getByText("3 selected on this page")).toBeDefined();

    const bulkModes = screen.getByRole<HTMLFieldSetElement>("group", {
      name: "Set selected tools",
    });
    await fireEvent.click(within(bulkModes).getByLabelText("Disabled"));
    await fireEvent.click(screen.getByRole("button", { name: "Apply Disabled to 3 selected" }));

    expect(await screen.findByRole("group", { name: "Confirm bulk tool behavior" })).toBeDefined();
    expect(selectAll.disabled).toBe(true);
    expect(selectAll.closest("thead")).toBeNull();
  });

  it("cancels with Escape and restores focus to the apply button", async () => {
    stubToolsApi();
    render(ToolsPageHarness);

    const { applyButton, confirmation } = await openDisabledConfirmation();
    const confirmButton = within(confirmation).getByRole<HTMLButtonElement>("button", {
      name: "Confirm Disabled",
    });
    confirmButton.focus();
    await fireEvent.keyDown(confirmButton, { key: "Escape" });

    await waitFor(() => expect(document.activeElement).toBe(applyButton));
    expect(screen.queryByRole("group", { name: "Confirm bulk tool behavior" })).toBeNull();
    expect(applyButton.disabled).toBe(false);
  });

  it("submits the displayed snapshot and focuses the success status", async () => {
    const bulkRequestBodies = stubToolsApi();
    render(ToolsPageHarness);

    const { alphaSelection, betaSelection, gammaSelection, confirmation } =
      await openDisabledConfirmation();
    expect(alphaSelection.checked).toBe(true);
    expect(betaSelection.checked).toBe(true);
    expect(gammaSelection.checked).toBe(false);
    expect(screen.getByText(`Bulk changes use catalog revision ${catalogRevision}.`)).toBeDefined();

    await fireEvent.click(within(confirmation).getByRole("button", { name: "Confirm Disabled" }));

    await waitFor(() => expect(bulkRequestBodies).toHaveLength(1));
    expect(bulkRequestBodies).toEqual([
      JSON.stringify({
        selection: {
          type: "tool_ids",
          toolIds: ["tool-a", "tool-b"],
          expectedCatalogRevision: catalogRevision,
        },
        mode: "disabled",
      }),
    ]);
    const status = await screen.findByText("Disabled applied to 2 selected tools.");
    await waitFor(() => expect(document.activeElement).toBe(status));
  });
});
