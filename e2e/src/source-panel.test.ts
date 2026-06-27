import { expect, it } from "@effect/vitest";

import { openConnectSourcePanel, type SourcePanelPage } from "./source-panel";

const sourcePanelSelector = "details.import-panel";
const sourcePickerSelector = 'role:group[name="Source type"]';
const sourceSummarySelector = 'text:exact="Connect a source"';

const fixture = (initiallyOpen: boolean) => {
  const calls: string[] = [];
  let panelOpen = initiallyOpen;

  const makeLocator = (selector: string) => ({
    async waitFor(options: { readonly state: "visible" }) {
      calls.push(`wait:${selector}:${options.state}`);
    },
    async getAttribute(name: string) {
      calls.push(`attribute:${selector}:${name}`);
      return selector === sourcePanelSelector && name === "open" && panelOpen ? "" : null;
    },
    async click() {
      calls.push(`click:${selector}`);
      panelOpen = !panelOpen;
    },
  });

  const page = {
    getByRole: () => makeLocator(sourcePickerSelector),
    getByText: () => makeLocator(sourceSummarySelector),
    locator: (selector: string) => makeLocator(selector),
  } satisfies SourcePanelPage;

  return { calls, page };
};

it("does not click a source panel that is visible once its picker is attached", async () => {
  const { calls, page } = fixture(true);

  await openConnectSourcePanel(page);

  expect(calls).toEqual([
    `attribute:${sourcePanelSelector}:open`,
    `wait:${sourcePickerSelector}:visible`,
  ]);
});

it("opens an attached source picker when its panel is closed", async () => {
  const { calls, page } = fixture(false);

  await openConnectSourcePanel(page);

  expect(calls).toEqual([
    `attribute:${sourcePanelSelector}:open`,
    `click:${sourceSummarySelector}`,
    `wait:${sourcePickerSelector}:visible`,
  ]);
});
