import { describe, expect, it } from "@effect/vitest";
import { consumeSetupToken, routeDestination, safeReturnTo } from "./navigation";

describe("dashboard navigation helpers", () => {
  it("consumes a setup token without putting it in the replacement URL", () => {
    let replacement = "";
    const token = consumeSetupToken(
      new URL("http://executor.local/setup?from=terminal#token=set_secret"),
      (nextUrl) => {
        replacement = nextUrl;
      },
    );

    expect(token).toBe("set_secret");
    expect(replacement).toBe("/setup?from=terminal");
    expect(replacement).not.toContain("set_secret");
  });

  it("accepts only protected same-origin return paths", () => {
    expect(safeReturnTo("/tokens?created=true", "http://executor.local")).toBe(
      "/tokens?created=true",
    );
    expect(safeReturnTo("/tokens#active", "http://executor.local")).toBe("/tokens#active");
    expect(safeReturnTo("/tokens#token=set_secret", "http://executor.local")).toBe("/tokens");
    expect(safeReturnTo("//attacker.example/tokens", "http://executor.local")).toBeNull();
    expect(safeReturnTo("https://attacker.example/tokens", "http://executor.local")).toBeNull();
    expect(safeReturnTo("/login", "http://executor.local")).toBeNull();
  });

  it("retains an internal destination across login", () => {
    const destination = routeDestination({
      pathname: "/tokens",
      search: "?filter=active",
      hash: "#latest",
      origin: "http://executor.local",
      setupRequired: false,
      authenticated: false,
    });

    expect(destination).toBe("/login?returnTo=%2Ftokens%3Ffilter%3Dactive%23latest");
  });

  it("omits a setup token fragment from the login return path", () => {
    const destination = routeDestination({
      pathname: "/tokens",
      search: "",
      hash: "#token=set_secret",
      origin: "http://executor.local",
      setupRequired: false,
      authenticated: false,
    });

    expect(destination).toBe("/login?returnTo=%2Ftokens");
  });
});
