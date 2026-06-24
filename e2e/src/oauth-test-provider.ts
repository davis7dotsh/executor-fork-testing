import { createEmulator, type Emulator, type LedgerEntry } from "@executor-js/emulate";
import { Effect } from "effect";

export interface OAuthTestProvider {
  readonly issuer: string;
  readonly endpoint: string;
  readonly registerClient: (redirectUri: string) => Promise<string>;
  readonly ledger: () => Promise<ReadonlyArray<LedgerEntry>>;
}

export const serveOAuthTestProvider = () =>
  Effect.acquireRelease(
    Effect.promise(async (): Promise<{ provider: OAuthTestProvider; emulator: Emulator }> => {
      const emulator = await createEmulator({ service: "mcp" });
      return {
        emulator,
        provider: {
          issuer: emulator.url,
          endpoint: `${emulator.url}/mcp`,
          registerClient: async (redirectUri) => {
            const response = await fetch(`${emulator.url}/register`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                client_name: "Executor local e2e",
                redirect_uris: [redirectUri],
                grant_types: ["authorization_code"],
                response_types: ["code"],
                token_endpoint_auth_method: "none",
              }),
            });
            if (!response.ok) {
              throw new Error(`MCP emulator client registration failed (${response.status})`);
            }
            const registration = (await response.json()) as { readonly client_id?: string };
            if (!registration.client_id) {
              throw new Error("MCP emulator client registration returned no client_id");
            }
            return registration.client_id;
          },
          ledger: () => emulator.ledger.list(),
        },
      };
    }),
    ({ emulator }) => Effect.promise(() => emulator.close()).pipe(Effect.ignore),
  ).pipe(Effect.map(({ provider }) => provider));
