import { Effect } from "effect";

import { e2ePort } from "../src/ports";
import type { Identity, Target } from "../src/target";

export const LOCAL_SELFHOST_PORT = e2ePort("E2E_LOCAL_SELFHOST_PORT", 4);
export const LOCAL_SETUP_PORT = e2ePort("E2E_LOCAL_SETUP_PORT", 5);
export const LOCAL_SELFHOST_BASE_URL =
  process.env.E2E_LOCAL_SELFHOST_URL ?? `http://127.0.0.1:${LOCAL_SELFHOST_PORT}`;
export const LOCAL_SETUP_BASE_URL =
  process.env.E2E_LOCAL_SETUP_URL ?? `http://127.0.0.1:${LOCAL_SETUP_PORT}`;

export const LOCAL_ADMIN = {
  username: process.env.E2E_LOCAL_ADMIN_USERNAME ?? "admin",
  password: process.env.E2E_LOCAL_ADMIN_PASSWORD ?? "executor-e2e-admin-password",
};

const cookiePairs = (headers: Headers) =>
  (headers.getSetCookie?.() ?? [])
    .map((cookie) => cookie.split(";", 1)[0]?.trim())
    .filter((cookie): cookie is string => Boolean(cookie));

export const signInLocalAdmin = async (
  baseUrl: string,
  credentials = LOCAL_ADMIN,
): Promise<Identity> => {
  const response = await fetch(new URL("/api/v1/session", baseUrl), {
    method: "POST",
    headers: { "content-type": "application/json", origin: new URL(baseUrl).origin },
    body: JSON.stringify(credentials),
    redirect: "manual",
  });
  if (!response.ok) throw new Error(`local selfhost sign-in failed (${response.status})`);
  const pairs = cookiePairs(response.headers);
  if (pairs.length === 0) throw new Error("local selfhost sign-in returned no cookies");
  return {
    label: credentials.username,
    credentials: { email: credentials.username, password: credentials.password },
    headers: { cookie: pairs.join("; ") },
    cookies: pairs.map((pair) => {
      const separator = pair.indexOf("=");
      return { name: pair.slice(0, separator), value: pair.slice(separator + 1) };
    }),
  };
};

export const localSelfhostTarget = (): Target => ({
  name: "local-selfhost",
  baseUrl: LOCAL_SELFHOST_BASE_URL,
  mcpUrl: `${LOCAL_SELFHOST_BASE_URL}/mcp`,
  capabilities: new Set(["browser"]),
  newIdentity: () => Effect.promise(() => signInLocalAdmin(LOCAL_SELFHOST_BASE_URL)),
});
