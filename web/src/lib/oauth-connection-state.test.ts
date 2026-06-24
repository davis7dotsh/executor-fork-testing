import { describe, expect, it } from "@effect/vitest";
import {
  buildOAuthConnectionInput,
  canDisconnectOAuth,
  draftFromOAuthSummary,
  normalizeOAuthScopes,
  oauthCallbackConnectionId,
  oauthCallbackOutcomeNotice,
  oauthCallbackNoticeWithoutEligibleSources,
  oauthCallbackRefreshKey,
  safeAuthorizationUrl,
  withoutOAuthCallbackParameters,
  type OAuthConnectionSummary,
} from "./oauth-connection-state";

const summary: OAuthConnectionSummary = {
  id: "oauth-1",
  credentialKey: "oauth",
  revision: 4,
  status: "connected",
  issuer: "https://identity.example.test",
  clientId: "executor",
  clientAuthMethod: "client_secret_basic",
  callbackUrl: "https://executor.example.test/api/v1/oauth/callback",
  requestedScopes: ["read", "write"],
  grantedScopes: ["read"],
  hasClientSecret: true,
  hasRefreshToken: true,
  accessExpiresAt: 100,
  authorizedAt: 90,
  lastRefreshedAt: 95,
  errorCode: null,
  managedOAuthEligible: true,
};

describe("OAuth connection state", () => {
  it("builds a confidential-client update with explicit secret preservation", () => {
    const draft = draftFromOAuthSummary(summary);
    expect(buildOAuthConnectionInput(draft, summary.revision)).toEqual({
      expectedRevision: 4,
      discovery: { type: "issuer", issuer: "https://identity.example.test/" },
      client: {
        clientId: "executor",
        authentication: "client_secret_basic",
        clientSecret: { action: "preserve" },
      },
      scopes: ["read", "write"],
    });
  });

  it("makes changing to a public client an explicit secret-clearing operation", () => {
    const draft = { ...draftFromOAuthSummary(summary), clientKind: "public" as const };
    expect(buildOAuthConnectionInput(draft, 4)).toEqual({
      expectedRevision: 4,
      discovery: { type: "issuer", issuer: "https://identity.example.test/" },
      client: { clientId: "executor", authentication: "none" },
      scopes: ["read", "write"],
    });
  });

  it("requires a replacement value and never trims secret bytes", () => {
    const draft = {
      ...draftFromOAuthSummary(summary),
      clientSecretAction: "replace" as const,
      clientSecret: " exact secret ",
    };
    expect(buildOAuthConnectionInput(draft, 4)?.client).toEqual({
      clientId: "executor",
      authentication: "client_secret_basic",
      clientSecret: { action: "replace", value: " exact secret " },
    });
    expect(buildOAuthConnectionInput({ ...draft, clientSecret: "" }, 4)).toBeNull();
  });

  it("builds MCP protected-resource discovery with an optional server override", () => {
    const draft = {
      ...draftFromOAuthSummary(summary),
      issuer: "",
      clientKind: "public" as const,
    };
    expect(buildOAuthConnectionInput(draft, 0, "mcp")?.discovery).toEqual({ type: "mcp" });
    expect(
      buildOAuthConnectionInput(
        { ...draft, issuer: "https://identity.example.test/issuer" },
        0,
        "mcp",
      )?.discovery,
    ).toEqual({
      type: "mcp",
      authorizationServer: "https://identity.example.test/issuer",
    });
  });

  it("normalizes and de-duplicates requested scopes", () => {
    expect(normalizeOAuthScopes("read, write\nread profile")).toEqual(["read", "write", "profile"]);
  });

  it("uses only allowlisted callback fields as an opaque refetch key", () => {
    const parameters = new URLSearchParams({
      result: "failed",
      oauth: "connection-1",
      error_description: "provider secret detail",
      code: "authorization-code",
    });
    expect(oauthCallbackRefreshKey(parameters)).toBe("failed:connection-1");
    expect(oauthCallbackConnectionId("failed:connection-1")).toBe("connection-1");
    parameters.set("result", "provider-specific-value");
    expect(oauthCallbackRefreshKey(parameters)).toBeNull();
  });

  it("cleans only the fixed callback fields after refetch", () => {
    const cleaned = withoutOAuthCallbackParameters(
      new URL("https://executor.test/sources?oauth=connection-1&result=success&filter=active#list"),
    );
    expect(cleaned.toString()).toBe("https://executor.test/sources?filter=active#list");
  });

  it("returns fixed callback notices without provider-controlled detail", () => {
    expect(oauthCallbackOutcomeNotice("failed:connection-1", true).message).toContain(
      "did not complete",
    );
    expect(oauthCallbackOutcomeNotice("success:connection-1", true).message).toContain("completed");
    expect(oauthCallbackOutcomeNotice("success:missing", false).message).toContain("no matching");
  });

  it("handles a callback after loading when no OAuth-capable source can report it", () => {
    expect(
      oauthCallbackNoticeWithoutEligibleSources("failed:missing", ["mcp_stdio"], false)?.message,
    ).toContain("did not complete");
    expect(
      oauthCallbackNoticeWithoutEligibleSources("failed:missing", ["openapi"], false),
    ).toBeNull();
    expect(oauthCallbackNoticeWithoutEligibleSources("failed:missing", [], true)).toBeNull();
  });

  it("allows secure authorization destinations and loopback HTTP only", () => {
    expect(safeAuthorizationUrl("https://identity.example.test/authorize?state=opaque")).toBe(
      "https://identity.example.test/authorize?state=opaque",
    );
    expect(safeAuthorizationUrl("http://127.0.0.42:9911/authorize?state=opaque")).toBe(
      "http://127.0.0.42:9911/authorize?state=opaque",
    );
    expect(safeAuthorizationUrl("http://identity.example.test/authorize")).toBeNull();
    expect(safeAuthorizationUrl("https://operator@identity.example.test/authorize")).toBeNull();
    expect(safeAuthorizationUrl("https://identity.example.test/authorize#token")).toBeNull();
    expect(safeAuthorizationUrl("javascript:alert(1)")).toBeNull();
  });

  it("rejects unsafe issuer URLs before building a save payload", () => {
    const draft = draftFromOAuthSummary(summary);
    expect(
      buildOAuthConnectionInput({ ...draft, issuer: "http://identity.example.test" }, 4),
    ).toBeNull();
    expect(
      buildOAuthConnectionInput({ ...draft, issuer: "https://user@identity.example.test" }, 4),
    ).toBeNull();
    expect(
      buildOAuthConnectionInput({ ...draft, issuer: "https://identity.example.test?tenant=a" }, 4),
    ).toBeNull();
    expect(
      buildOAuthConnectionInput({ ...draft, issuer: "https://identity.example.test#fragment" }, 4),
    ).toBeNull();
    expect(
      buildOAuthConnectionInput({ ...draft, issuer: "http://localhost:8443/issuer" }, 4),
    ).not.toBeNull();
  });

  it("disconnects token-bearing statuses without assuming a refresh token exists", () => {
    expect(canDisconnectOAuth("connected")).toBe(true);
    expect(canDisconnectOAuth("reauthorization_required")).toBe(true);
    expect(canDisconnectOAuth("ready_to_connect")).toBe(false);
    expect(canDisconnectOAuth("connecting")).toBe(false);
  });
});
