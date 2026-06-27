import { describe, expect, it } from "@effect/vitest";
import {
  canCreateToken,
  isTokenRecoveryAuthNavigation,
  shouldBlockTokenExit,
  tokenExitBlockReason,
  tokenListView,
} from "./token-page-state";

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
    expect(
      canCreateToken({
        name: "Laptop",
        creating: false,
        hasPendingCreate: true,
        hasUnsavedToken: false,
      }),
    ).toBe(false);
    expect(
      canCreateToken({
        name: "Laptop",
        creating: false,
        hasPendingCreate: false,
        hasUnsavedToken: true,
      }),
    ).toBe(false);
    expect(
      canCreateToken({
        name: "Laptop",
        creating: false,
        hasPendingCreate: false,
        hasUnsavedToken: false,
      }),
    ).toBe(true);
  });

  it("guards navigation throughout creation and one-time reveal", () => {
    expect(
      shouldBlockTokenExit({
        creating: true,
        hasPendingCreate: true,
        hasUnsavedToken: false,
      }),
    ).toBe(true);
    expect(
      shouldBlockTokenExit({
        creating: false,
        hasPendingCreate: true,
        hasUnsavedToken: true,
      }),
    ).toBe(true);
    expect(
      shouldBlockTokenExit({
        creating: false,
        hasPendingCreate: true,
        hasUnsavedToken: false,
      }),
    ).toBe(true);
    expect(
      shouldBlockTokenExit({
        creating: false,
        hasPendingCreate: false,
        hasUnsavedToken: false,
      }),
    ).toBe(false);
  });

  it("reports why an exit is blocked so creation can show page-level feedback", () => {
    expect(
      tokenExitBlockReason({
        creating: true,
        hasPendingCreate: true,
        hasUnsavedToken: false,
      }),
    ).toBe("creating");
    expect(
      tokenExitBlockReason({
        creating: false,
        hasPendingCreate: true,
        hasUnsavedToken: true,
      }),
    ).toBe("unsaved-token");
    expect(
      tokenExitBlockReason({
        creating: false,
        hasPendingCreate: true,
        hasUnsavedToken: false,
      }),
    ).toBe("pending-recovery");
    expect(
      tokenExitBlockReason({
        creating: false,
        hasPendingCreate: false,
        hasUnsavedToken: false,
      }),
    ).toBeNull();
  });

  it("allows only forced reauthentication to bypass a pending recovery guard", () => {
    expect(isTokenRecoveryAuthNavigation({ authenticated: false, destinationPath: "/login" })).toBe(
      true,
    );
    expect(isTokenRecoveryAuthNavigation({ authenticated: true, destinationPath: "/login" })).toBe(
      false,
    );
    expect(
      isTokenRecoveryAuthNavigation({ authenticated: false, destinationPath: "/sources" }),
    ).toBe(false);
    expect(isTokenRecoveryAuthNavigation({ authenticated: false, destinationPath: null })).toBe(
      false,
    );
  });
});
