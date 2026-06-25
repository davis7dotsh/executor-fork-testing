import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { serveOAuthTestProvider } from "./oauth-test-provider";

it.effect("uses the MCP emulator's RFC 8414 and dynamic client surfaces", () =>
  Effect.scoped(
    Effect.gen(function* () {
      const provider = yield* serveOAuthTestProvider();
      expect(new URL(provider.issuer).hostname).toBe("127.0.0.1");
      expect(provider.endpoint).toBe(`${provider.issuer}/mcp`);
      const metadata = yield* Effect.promise(() =>
        fetch(`${provider.issuer}/.well-known/oauth-authorization-server`).then((response) =>
          response.json(),
        ),
      );
      expect(metadata).toMatchObject({
        issuer: provider.issuer,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
      });

      const clientId = yield* Effect.promise(() =>
        provider.registerClient("http://127.0.0.1/callback"),
      );
      expect(clientId).toMatch(/^mcp-client-/);
      const authorization = new URL(`${provider.issuer}/authorize`);
      authorization.searchParams.set("client_id", clientId);
      authorization.searchParams.set("redirect_uri", "http://127.0.0.1/callback");
      authorization.searchParams.set("state", "unit-state");
      authorization.searchParams.set("response_type", "code");
      const callbackUrl = yield* Effect.promise(() =>
        provider.approveAuthorization(authorization.toString(), "admin"),
      );
      const callback = new URL(callbackUrl);
      expect(`${callback.origin}${callback.pathname}`).toBe("http://127.0.0.1/callback");
      expect(callback.searchParams.get("state")).toBe("unit-state");
      expect(/^[0-9a-f]+$/.test(callback.searchParams.get("code") ?? "")).toBe(true);
      const ledger = yield* Effect.promise(() => provider.ledger());
      expect(ledger.map((entry) => entry.path)).toEqual(
        expect.arrayContaining(["/register", "/authorize", "/authorize/approve"]),
      );
      const approval = ledger.find((entry) => entry.path === "/authorize/approve");
      expect(approval?.method).toBe("POST");
      expect(approval?.request.body).toMatchObject({ login: "admin", state: "unit-state" });
      expect(approval?.response.status).toBe(302);
    }),
  ),
);
