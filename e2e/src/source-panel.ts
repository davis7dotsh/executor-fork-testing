interface SourcePanelLocator {
  readonly waitFor: (options: { readonly state: "attached" | "visible" }) => Promise<void>;
  readonly isVisible: () => Promise<boolean>;
  readonly locator: (selector: string) => SourcePanelLocator;
  readonly click: () => Promise<void>;
}

export interface SourcePanelPage {
  readonly locator: (selector: string) => SourcePanelLocator;
}

const sourcePanelSelector = "details.import-panel";
const sourcePickerSelector = "fieldset.source-type-picker";

export const openConnectSourcePanel = async (page: SourcePanelPage) => {
  const picker = page.locator(sourcePickerSelector);
  await picker.waitFor({ state: "attached" });
  const panel = page.locator(sourcePanelSelector);
  const summary = panel.locator("summary");
  if (!(await picker.isVisible())) {
    await summary.click();
    if (!(await picker.isVisible())) await summary.click();
  }

  await picker.waitFor({ state: "visible" });
};
