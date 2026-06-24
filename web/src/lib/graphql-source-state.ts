export type GraphqlAuthDraft = {
  readonly type: "none" | "bearer" | "basic" | "api_key_header" | "oauth_access_token";
  readonly headerName: string;
  readonly username: string;
  readonly secret: string;
};

export type GraphqlCredential =
  | null
  | { readonly type: "bearer"; readonly token: string }
  | { readonly type: "basic"; readonly username: string; readonly password: string }
  | { readonly type: "api_key_header"; readonly name: string; readonly value: string }
  | { readonly type: "oauth_access_token"; readonly accessToken: string };

export type GraphqlSourceInput = {
  readonly kind: "graphql";
  readonly displayName: string;
  readonly preferredSlug?: string;
  readonly description?: string;
  readonly endpoint: string;
  readonly allowPrivateNetwork?: boolean;
  readonly credential?: Exclude<GraphqlCredential, null>;
};

export function emptyGraphqlAuthDraft(): GraphqlAuthDraft {
  return { type: "none", headerName: "", username: "", secret: "" };
}

export function clearGraphqlSecret(draft: GraphqlAuthDraft): GraphqlAuthDraft {
  return { ...draft, headerName: "", username: "", secret: "" };
}

export function buildGraphqlCredential(draft: GraphqlAuthDraft): GraphqlCredential | undefined {
  if (draft.type === "none") return null;
  if (draft.secret.trim() === "") return undefined;
  if (draft.type === "bearer") return { type: "bearer", token: draft.secret };
  if (draft.type === "basic") {
    const username = draft.username.trim();
    return username === "" ? undefined : { type: "basic", username, password: draft.secret };
  }
  if (draft.type === "oauth_access_token") {
    return { type: "oauth_access_token", accessToken: draft.secret };
  }
  const name = draft.headerName.trim();
  return name === "" ? undefined : { type: "api_key_header", name, value: draft.secret };
}

export function graphqlDraftFromCredentialType(type: string | undefined): GraphqlAuthDraft {
  const normalized = type === "manual_oauth_access_token" ? "oauth_access_token" : type;
  if (
    normalized === "bearer" ||
    normalized === "basic" ||
    normalized === "api_key_header" ||
    normalized === "oauth_access_token"
  ) {
    return { type: normalized, headerName: "", username: "", secret: "" };
  }
  return emptyGraphqlAuthDraft();
}

export function requiresGraphqlPrivateNetworkOptIn(endpoint: string) {
  const url = parseHttpUrl(endpoint);
  if (url === null) return false;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (host === "::1" || host.startsWith("fc") || host.startsWith("fd")) return true;
  if (host.startsWith("::ffff:")) {
    const groups = host.split(":");
    const high = Number.parseInt(groups.at(-2) ?? "", 16);
    const low = Number.parseInt(groups.at(-1) ?? "", 16);
    if (Number.isInteger(high) && Number.isInteger(low)) {
      return isPrivateIpv4([high >> 8, high & 0xff, low >> 8, low & 0xff]);
    }
  }
  const firstIpv6Group = Number.parseInt(host.split(":", 1)[0] ?? "", 16);
  if (Number.isInteger(firstIpv6Group) && firstIpv6Group >= 0xfe80 && firstIpv6Group <= 0xfebf) {
    return true;
  }
  const octets = host.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet))) return false;
  return isPrivateIpv4(octets);
}

export function normalizeGraphqlEndpoint(endpoint: string) {
  const normalized = endpoint.trim();
  const url = parseHttpUrl(normalized);
  if (
    url === null ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.protocol === "http:" && !isLoopbackHost(url.hostname))
  ) {
    return null;
  }
  return normalized;
}

function isLoopbackHost(hostname: string) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1") return true;
  const octets = host.split(".").map(Number);
  return (
    octets.length === 4 &&
    octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255) &&
    octets[0] === 127
  );
}

function isPrivateIpv4(octets: readonly number[]) {
  if (octets[0] === 10 || octets[0] === 127) return true;
  if (octets[0] === 169 && octets[1] === 254) return true;
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  return octets[0] === 192 && octets[1] === 168;
}

export function safeGraphqlSourceDetails(configuration: Readonly<Record<string, unknown>>) {
  const endpoint =
    typeof configuration.endpoint === "string" ? redactedEndpoint(configuration.endpoint) : null;
  return {
    endpoint,
    allowPrivateNetwork: configuration.allowPrivateNetwork === true,
  };
}

function redactedEndpoint(endpoint: string) {
  const url = parseHttpUrl(endpoint);
  return url === null ? null : url.origin;
}

function parseHttpUrl(value: string) {
  const normalized = value.trim();
  if (!URL.canParse(normalized)) return null;
  const url = new URL(normalized);
  return url.protocol === "http:" || url.protocol === "https:" ? url : null;
}
