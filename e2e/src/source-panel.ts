interface SourcePanelLocator {
  readonly waitFor: (options: { readonly state: "visible" }) => Promise<void>;
  readonly getAttribute: (name: string) => Promise<string | null>;
  readonly click: () => Promise<void>;
}

export interface SourcePanelPage {
  readonly getByRole: (
    role: "group",
    options: { readonly name: "Source type" },
  ) => SourcePanelLocator;
  readonly getByText: (
    text: "Connect a source",
    options: { readonly exact: true },
  ) => SourcePanelLocator;
  readonly locator: (selector: string) => SourcePanelLocator;
}

const sourcePanelSelector = "details.import-panel";

export const openConnectSourcePanel = async (page: SourcePanelPage) => {
  const panel = page.locator(sourcePanelSelector);
  if ((await panel.getAttribute("open")) === null) {
    await page.getByText("Connect a source", { exact: true }).click();
    if ((await panel.getAttribute("open")) === null) {
      await page.getByText("Connect a source", { exact: true }).click();
    }
  }
  await page.getByRole("group", { name: "Source type" }).waitFor({ state: "visible" });
};
