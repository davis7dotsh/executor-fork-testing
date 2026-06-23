import { describe, expect, it } from "@effect/vitest";
import { canCreateToken, shouldBlockTokenExit, tokenListView } from "./token-page-state";

describe("API token page state", () => {
  it("distinguishes an unavailable initial load from an empty successful load", () => {
    expect(tokenListView({ loading: false, hasLoaded: false, hasError: true, tokenCount: 0 })).toBe(
      "unavailable",
    );
    expect(tokenListView({ loading: false, hasLoaded: true, hasError: false, tokenCount: 0 })).toBe(
      "empty",
    );
  });

  it("labels retained data as stale after a refresh failure", () => {
    expect(tokenListView({ loading: false, hasLoaded: true, hasError: true, tokenCount: 2 })).toBe(
      "stale",
    );
  });

  it("blocks another token creation until the revealed secret is explicitly saved", () => {
    expect(canCreateToken({ name: "Laptop", creating: false, hasUnsavedToken: true })).toBe(false);
    expect(canCreateToken({ name: "Laptop", creating: false, hasUnsavedToken: false })).toBe(true);
  });

  it("guards navigation throughout creation and one-time reveal", () => {
    expect(shouldBlockTokenExit({ creating: true, hasUnsavedToken: false })).toBe(true);
    expect(shouldBlockTokenExit({ creating: false, hasUnsavedToken: true })).toBe(true);
    expect(shouldBlockTokenExit({ creating: false, hasUnsavedToken: false })).toBe(false);
  });
});
