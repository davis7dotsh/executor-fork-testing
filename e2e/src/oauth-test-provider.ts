import { createEmulator, type Emulator, type LedgerEntry } from "@executor-js/emulate";
import { Effect } from "effect";

export interface OAuthTestProvider {
  readonly issuer: string;
  readonly endpoint: string;
  readonly registerClient: (redirectUri: string) => Promise<string>;
  readonly approveAuthorization: (authorizationUrl: string, login: string) => Promise<string>;
  readonly ledger: () => Promise<ReadonlyArray<LedgerEntry>>;
}

const DEFAULT_EMULATOR_PORT = 4000;

const decodeHtmlAttribute = (value: string) =>
  value
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");

const authorizationFormFields = (html: string) => {
  const fields = new URLSearchParams();
  for (const match of html.matchAll(
    /<input\s+type="hidden"\s+name="([^"]+)"\s+value="([^"]*)"\s*\/?>/giu,
  )) {
    const [, name, value] = match;
    if (name !== undefined && value !== undefined) {
      fields.append(decodeHtmlAttribute(name), decodeHtmlAttribute(value));
    }
  }
  if (!fields.has("client_id") || !fields.has("redirect_uri") || !fields.has("state")) {
    throw new Error("MCP emulator authorization page returned no usable consent form");
  }
  return fields;
};

export const approveOAuthTestAuthorization = async (
  issuer: string,
  authorizationUrl: string,
  login: string,
) => {
  const authorization = new URL(authorizationUrl);
  if (authorization.origin !== new URL(issuer).origin) {
    throw new Error("MCP emulator authorization URL uses an unexpected origin");
  }
  const consent = await fetch(authorization, {
    headers: { accept: "text/html" },
    redirect: "manual",
  });
  if (!consent.ok) {
    throw new Error(`MCP emulator authorization page failed (${consent.status})`);
  }
  const fields = authorizationFormFields(await consent.text());
  fields.set("login", login);
  const approval = await fetch(new URL("/authorize/approve", issuer), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: fields,
    redirect: "manual",
  });
  if (approval.status !== 302) {
    throw new Error(`MCP emulator authorization approval failed (${approval.status})`);
  }
  const location = approval.headers.get("location");
  if (!location) {
    throw new Error("MCP emulator authorization approval returned no callback URL");
  }
  return new URL(location, issuer).toString();
};

export const serveOAuthTestProvider = (port?: number) =>
  Effect.acquireRelease(
    Effect.promise(async (): Promise<{ provider: OAuthTestProvider; emulator: Emulator }> => {
      const resolvedPort = port ?? DEFAULT_EMULATOR_PORT;
      const baseUrl = `http://127.0.0.1:${resolvedPort}`;
      const emulator = await createEmulator({
        service: "mcp",
        port: resolvedPort,
        baseUrl,
      });
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
          approveAuthorization: (authorizationUrl, login) =>
            approveOAuthTestAuthorization(emulator.url, authorizationUrl, login),
          ledger: () => emulator.ledger.list(),
        },
      };
    }),
    ({ emulator }) => Effect.promise(() => emulator.close()).pipe(Effect.ignore),
  ).pipe(Effect.map(({ provider }) => provider));
