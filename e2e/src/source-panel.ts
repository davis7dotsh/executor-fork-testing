interface SourcePanelLocator {
  readonly waitFor: (options: { readonly state: "attached" | "visible" }) => Promise<void>;
  readonly getAttribute: (name: string) => Promise<string | null>;
  readonly locator: (selector: string) => SourcePanelLocator;
  readonly click: () => Promise<void>;
}

export interface SourcePanelPage {
  readonly locator: (selector: string) => SourcePanelLocator;
}

const sourcePanelSelector = "details.import-panel";
const sourcePickerSelector = "fieldset.source-type-picker";
const settledSourceCatalogSelector = 'div.source-grid[aria-busy="false"], section.empty-state';

export const openConnectSourcePanel = async (
  page: SourcePanelPage,
  options: { readonly waitForCatalog?: boolean } = {},
) => {
  if (options.waitForCatalog !== false) {
    await page.locator(settledSourceCatalogSelector).waitFor({ state: "attached" });
  }
  const picker = page.locator(sourcePickerSelector);
  await picker.waitFor({ state: "attached" });
  const panel = page.locator(sourcePanelSelector);
  const summary = panel.locator("summary");
  if ((await panel.getAttribute("open")) === null) {
    await summary.click();
    if ((await panel.getAttribute("open")) === null) await summary.click();
  }

  await picker.waitFor({ state: "visible" });
};
