import { afterEach, beforeEach, expect, it, vi } from "@effect/vitest";
import { copyText } from "./clipboard";

let clipboardDescriptor: PropertyDescriptor | undefined;
let execCommandDescriptor: PropertyDescriptor | undefined;

beforeEach(() => {
  clipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");
  execCommandDescriptor = Object.getOwnPropertyDescriptor(document, "execCommand");
});

afterEach(() => {
  if (clipboardDescriptor === undefined) {
    Reflect.deleteProperty(navigator, "clipboard");
  } else {
    Object.defineProperty(navigator, "clipboard", clipboardDescriptor);
  }

  if (execCommandDescriptor === undefined) {
    Reflect.deleteProperty(document, "execCommand");
  } else {
    Object.defineProperty(document, "execCommand", execCommandDescriptor);
  }
  document.body.replaceChildren();
});

it("uses the visible readonly field as a fallback and restores focus", async () => {
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined });
  const execCommand = vi.fn(() => true);
  Object.defineProperty(document, "execCommand", { configurable: true, value: execCommand });

  const copyButton = document.createElement("button");
  const field = document.createElement("input");
  field.readOnly = true;
  document.body.append(copyButton, field);
  copyButton.focus();

  const copied = await copyText("exr_secret", field);

  expect(copied).toBe(true);
  expect(field.value).toBe("exr_secret");
  expect(execCommand).toHaveBeenCalledWith("copy");
  expect(document.activeElement).toBe(copyButton);
});
