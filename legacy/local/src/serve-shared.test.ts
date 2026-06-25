import { describe, expect, it } from "@effect/vitest";

import {
  DEFAULT_ALLOWED_HOSTS,
  hasBearerToken,
  isAllowedOrigin,
  isUnauthenticatedOAuthCallbackPath,
  makeIsAuthorized,
} from "./serve-shared";

const allowed = new Set<string>(DEFAULT_ALLOWED_HOSTS);
const req = (headers: Record<string, string>): Request =>
  new Request("http://127.0.0.1/api/scope", { headers });

describe("isAllowedOrigin", () => {
  it("allows loopback origins on any port", () => {
    expect(isAllowedOrigin("http://127.0.0.1:4789", allowed)).toBe(true);
    expect(isAllowedOrigin("http://localhost:5173", allowed)).toBe(true);
  });

  it("rejects foreign and malformed origins", () => {
    expect(isAllowedOrigin("https://evil.example", allowed)).toBe(false);
    expect(isAllowedOrigin("not-a-url", allowed)).toBe(false);
  });
});

describe("makeIsAuthorized", () => {
  const isAuthorized = makeIsAuthorized("secret-token");

  it("accepts a matching bearer token", () => {
    expect(isAuthorized(req({ authorization: "Bearer secret-token" }))).toBe(true);
    expect(hasBearerToken(req({ authorization: "bearer secret-token" }), "secret-token")).toBe(
      true,
    );
  });

  it("rejects a missing or wrong token", () => {
    expect(isAuthorized(req({}))).toBe(false);
    expect(isAuthorized(req({ authorization: "Bearer wrong" }))).toBe(false);
    expect(isAuthorized(req({ authorization: "Basic secret-token" }))).toBe(false);
  });
});

describe("isUnauthenticatedOAuthCallbackPath", () => {
  it("exempts only the callback path, not the await poll", () => {
    expect(isUnauthenticatedOAuthCallbackPath("/api/oauth/callback")).toBe(true);
    expect(isUnauthenticatedOAuthCallbackPath("/api/oauth/callback/x")).toBe(true);
    expect(isUnauthenticatedOAuthCallbackPath("/api/oauth/await/session-1")).toBe(false);
    expect(isUnauthenticatedOAuthCallbackPath("/api/scope")).toBe(false);
  });
});
