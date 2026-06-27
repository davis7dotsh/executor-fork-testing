import { it } from "@effect/vitest";

import {
  expectLocatorChecked,
  expectLocatorCount,
  expectLocatorDisabled,
  expectLocatorFocused,
  expectLocatorText,
  expectLocatorValue,
  expectLocatorVisible,
} from "./locator-assertions";

const sequence = <Value>(first: Value, ...rest: readonly Value[]) => {
  const values = [first, ...rest];
  let index = 0;
  return async () => values[Math.min(index++, values.length - 1)]!;
};

it("polls locator state until the user-visible assertion succeeds", async () => {
  await expectLocatorVisible({ isVisible: sequence(false, true) });
  await expectLocatorDisabled({ isDisabled: sequence(false, true) });
  await expectLocatorChecked({ isChecked: sequence(false, true) });
  await expectLocatorFocused({ evaluate: sequence(false, true) });
  await expectLocatorValue({ inputValue: sequence("pending", "ready") }, "ready");
  await expectLocatorCount({ count: sequence(0, 2) }, 2);
  await expectLocatorText({ textContent: sequence("Pending", "Ready\n now") }, "Ready now");
});
