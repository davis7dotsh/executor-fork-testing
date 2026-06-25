import { expect } from "@effect/vitest";
import type { Locator } from "playwright";

const locatorAssertionTimeout = 30_000;

const pollOptions = (message: string | undefined, fallback: string) => ({
  timeout: locatorAssertionTimeout,
  message: message ?? fallback,
});

const normalizeText = (text: string) => text.replace(/\s+/gu, " ").trim();

interface FocusLocator {
  readonly evaluate: (
    pageFunction: (element: HTMLElement | SVGElement) => boolean,
  ) => Promise<boolean>;
}

export const expectLocatorVisible = (locator: Pick<Locator, "isVisible">, message?: string) =>
  expect
    .poll(() => locator.isVisible(), pollOptions(message, "expected locator to become visible"))
    .toBe(true);

export const expectLocatorDisabled = (locator: Pick<Locator, "isDisabled">, message?: string) =>
  expect
    .poll(() => locator.isDisabled(), pollOptions(message, "expected locator to become disabled"))
    .toBe(true);

export const expectLocatorChecked = (locator: Pick<Locator, "isChecked">, message?: string) =>
  expect
    .poll(() => locator.isChecked(), pollOptions(message, "expected locator to become checked"))
    .toBe(true);

export const expectLocatorFocused = (locator: FocusLocator, message?: string) =>
  expect
    .poll(
      () => locator.evaluate((element) => element === element.ownerDocument.activeElement),
      pollOptions(message, "expected locator to become focused"),
    )
    .toBe(true);

export const expectLocatorValue = (
  locator: Pick<Locator, "inputValue">,
  expected: string,
  message?: string,
) =>
  expect
    .poll(
      () => locator.inputValue(),
      pollOptions(message, `expected locator value to equal ${JSON.stringify(expected)}`),
    )
    .toBe(expected);

export const expectLocatorCount = (
  locator: Pick<Locator, "count">,
  expected: number,
  message?: string,
) =>
  expect
    .poll(
      () => locator.count(),
      pollOptions(message, `expected locator count to equal ${expected}`),
    )
    .toBe(expected);

export const expectLocatorText = (
  locator: Pick<Locator, "textContent">,
  expected: string,
  message?: string,
) =>
  expect
    .poll(
      () => locator.textContent().then((text) => normalizeText(text ?? "")),
      pollOptions(message, `expected locator text to contain ${JSON.stringify(expected)}`),
    )
    .toContain(normalizeText(expected));
