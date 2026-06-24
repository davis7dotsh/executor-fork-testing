import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { serveOAuthTestProvider } from "./oauth-test-provider";

it.effect("uses the MCP emulator's RFC 8414 and dynamic client surfaces", () =>
  Effect.scoped(
    Effect.gen(function* () {
      const provider = yield* serveOAuthTestProvider();
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
      expect((yield* Effect.promise(() => provider.ledger())).map((entry) => entry.path)).toContain(
        "/register",
      );
    }),
  ),
);
