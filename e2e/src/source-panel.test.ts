import { expect, it } from "@effect/vitest";

import { openConnectSourcePanel, type SourcePanelPage } from "./source-panel";

const sourcePanelSelector = "details.import-panel";
const sourcePickerSelector = "fieldset.source-type-picker";
const settledSourceCatalogSelector = 'div.source-grid[aria-busy="false"], section.empty-state';

const fixture = (initiallyOpen: boolean, autoOpenBeforeFirstClick = false) => {
  const calls: string[] = [];
  let panelOpen = initiallyOpen;
  let pendingAutoOpen = autoOpenBeforeFirstClick;

  const makeLocator = (selector: string) => ({
    async waitFor(options: { readonly state: "attached" | "visible" }) {
      calls.push(`wait:${selector}:${options.state}`);
    },
    async getAttribute(name: string) {
      calls.push(`attribute:${selector}:${name}`);
      return selector === sourcePanelSelector && name === "open" && panelOpen ? "" : null;
    },
    locator(child: string) {
      calls.push(`locator:${selector}:${child}`);
      return makeLocator(`${selector} ${child}`);
    },
    async click() {
      calls.push(`click:${selector}`);
      if (pendingAutoOpen) {
        pendingAutoOpen = false;
        panelOpen = true;
      }
      panelOpen = !panelOpen;
    },
  });

  const page = {
    locator: (selector: string) => makeLocator(selector),
  } satisfies SourcePanelPage;

  return { calls, page };
};

it("does not click a source panel that is visible once its picker is attached", async () => {
  const { calls, page } = fixture(true);

  await openConnectSourcePanel(page);

  expect(calls).toEqual([
    `wait:${settledSourceCatalogSelector}:attached`,
    `wait:${sourcePickerSelector}:attached`,
    `locator:${sourcePanelSelector}:summary`,
    `attribute:${sourcePanelSelector}:open`,
    `wait:${sourcePickerSelector}:visible`,
  ]);
});

it("opens an attached source picker when its panel is closed", async () => {
  const { calls, page } = fixture(false);

  await openConnectSourcePanel(page);

  expect(calls).toEqual([
    `wait:${settledSourceCatalogSelector}:attached`,
    `wait:${sourcePickerSelector}:attached`,
    `locator:${sourcePanelSelector}:summary`,
    `attribute:${sourcePanelSelector}:open`,
    `click:${sourcePanelSelector} summary`,
    `attribute:${sourcePanelSelector}:open`,
    `wait:${sourcePickerSelector}:visible`,
  ]);
});

it("reopens a panel that auto-opens between the open-state check and click", async () => {
  const { calls, page } = fixture(false, true);

  await openConnectSourcePanel(page);

  expect(calls).toEqual([
    `wait:${settledSourceCatalogSelector}:attached`,
    `wait:${sourcePickerSelector}:attached`,
    `locator:${sourcePanelSelector}:summary`,
    `attribute:${sourcePanelSelector}:open`,
    `click:${sourcePanelSelector} summary`,
    `attribute:${sourcePanelSelector}:open`,
    `click:${sourcePanelSelector} summary`,
    `wait:${sourcePickerSelector}:visible`,
  ]);
});

it("opens the panel without waiting for an intentionally gated catalog request", async () => {
  const { calls, page } = fixture(false);

  await openConnectSourcePanel(page, { waitForCatalog: false });

  expect(calls).toEqual([
    `wait:${sourcePickerSelector}:attached`,
    `locator:${sourcePanelSelector}:summary`,
    `attribute:${sourcePanelSelector}:open`,
    `click:${sourcePanelSelector} summary`,
    `attribute:${sourcePanelSelector}:open`,
    `wait:${sourcePickerSelector}:visible`,
  ]);
});
