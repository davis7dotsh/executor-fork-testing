export type OAuthClientAuthentication = "none" | "client_secret_basic" | "client_secret_post";

export type OAuthConnectionStatus =
  | "not_configured"
  | "ready_to_connect"
  | "connecting"
  | "connected"
  | "reauthorization_required"
  | "error";

export type OAuthConnectionSummary = {
  readonly id: string;
  readonly credentialKey: string;
  readonly revision: number;
  readonly status: OAuthConnectionStatus;
  readonly issuer: string;
  readonly clientId: string;
  readonly clientAuthMethod: OAuthClientAuthentication;
  readonly callbackUrl: string;
  readonly requestedScopes: readonly string[];
  readonly grantedScopes: readonly string[];
  readonly hasClientSecret: boolean;
  readonly hasRefreshToken: boolean;
  readonly accessExpiresAt: number | null;
  readonly authorizedAt: number | null;
  readonly lastRefreshedAt: number | null;
  readonly errorCode: string | null;
  readonly managedOAuthEligible: boolean;
};

export type OAuthConnectionList = {
  readonly connections: readonly OAuthConnectionSummary[];
  readonly availableCredentials: readonly OAuthAvailableCredential[];
};

export type OAuthAvailableCredential = {
  readonly credentialKey: string;
  readonly protocol: "openapi" | "graphql" | "mcp_http";
  readonly requestedScopes: readonly string[];
  readonly managedOAuthEligible: true;
};

export type OAuthClientSecretMutation =
  | { readonly action: "preserve" }
  | { readonly action: "replace"; readonly value: string };

export type OAuthConnectionInput = {
  readonly expectedRevision: number;
  readonly discovery:
    | { readonly type: "issuer"; readonly issuer: string }
    | { readonly type: "mcp"; readonly authorizationServer?: string };
  readonly client:
    | { readonly clientId: string; readonly authentication: "none" }
    | {
        readonly clientId: string;
        readonly authentication: "client_secret_basic" | "client_secret_post";
        readonly clientSecret: OAuthClientSecretMutation;
      };
  readonly scopes: readonly string[];
};

export type OAuthAuthorization = {
  readonly authorizationUrl: string;
};

export type OAuthOperationError = {
  readonly code: string;
  readonly displayMessage: string;
  readonly requestId: string | null;
  readonly status: number;
};

export type OAuthOperationResult<Value> =
  | { readonly ok: true; readonly value: Value }
  | { readonly ok: false; readonly error: OAuthOperationError };

export type OAuthConnectionOperations = {
  readonly load: (
    sourceId: string,
    signal: AbortSignal,
  ) => Promise<OAuthOperationResult<OAuthConnectionList>>;
  readonly save: (
    sourceId: string,
    credentialKey: string,
    input: OAuthConnectionInput,
    signal: AbortSignal,
  ) => Promise<OAuthOperationResult<OAuthConnectionSummary>>;
  readonly authorize: (
    sourceId: string,
    credentialKey: string,
    input: { readonly expectedRevision: number },
    signal: AbortSignal,
  ) => Promise<OAuthOperationResult<OAuthAuthorization>>;
  readonly disconnect: (
    sourceId: string,
    credentialKey: string,
    input: { readonly expectedRevision: number },
    signal: AbortSignal,
  ) => Promise<OAuthOperationResult<OAuthConnectionSummary>>;
  readonly remove: (
    sourceId: string,
    credentialKey: string,
    input: { readonly expectedRevision: number },
    signal: AbortSignal,
  ) => Promise<OAuthOperationResult<void>>;
};

export type OAuthConnectionDraft = {
  readonly issuer: string;
  readonly clientKind: "public" | "confidential";
  readonly clientId: string;
  readonly clientAuthMethod: "client_secret_basic" | "client_secret_post";
  readonly clientSecretAction: "preserve" | "replace" | "clear";
  readonly clientSecret: string;
  readonly scopes: string;
};

export function draftFromOAuthSummary(summary: OAuthConnectionSummary): OAuthConnectionDraft {
  const confidential = summary.clientAuthMethod !== "none";
  return {
    issuer: summary.issuer,
    clientKind: confidential ? "confidential" : "public",
    clientId: summary.clientId,
    clientAuthMethod: confidential ? summary.clientAuthMethod : "client_secret_basic",
    clientSecretAction: confidential && summary.hasClientSecret ? "preserve" : "clear",
    clientSecret: "",
    scopes: summary.requestedScopes.join(" "),
  };
}

export function emptyOAuthDraft(): OAuthConnectionDraft {
  return {
    issuer: "",
    clientKind: "public",
    clientId: "",
    clientAuthMethod: "client_secret_basic",
    clientSecretAction: "clear",
    clientSecret: "",
    scopes: "",
  };
}

export function buildOAuthConnectionInput(
  draft: OAuthConnectionDraft,
  expectedRevision: number,
  discoveryType: "issuer" | "mcp" = "issuer",
): OAuthConnectionInput | null {
  const clientId = draft.clientId.trim();
  const issuer = draft.issuer.trim() === "" ? null : normalizedHttpUrl(draft.issuer);
  if (clientId === "" || (discoveryType === "issuer" && issuer === null)) return null;
  if (draft.issuer.trim() !== "" && issuer === null) return null;
  const discovery: OAuthConnectionInput["discovery"] =
    discoveryType === "mcp"
      ? {
          type: "mcp",
          ...(issuer === null ? {} : { authorizationServer: issuer }),
        }
      : { type: "issuer", issuer: issuer ?? "" };

  const scopes = normalizeOAuthScopes(draft.scopes);
  if (draft.clientKind === "public") {
    return {
      expectedRevision,
      discovery,
      client: { clientId, authentication: "none" },
      scopes,
    };
  }

  if (draft.clientSecretAction === "clear") return null;
  if (draft.clientSecretAction === "replace" && draft.clientSecret === "") return null;
  const clientSecret =
    draft.clientSecretAction === "replace"
      ? { action: "replace" as const, value: draft.clientSecret }
      : { action: "preserve" as const };
  return {
    expectedRevision,
    discovery,
    client: {
      clientId,
      authentication: draft.clientAuthMethod,
      clientSecret,
    },
    scopes,
  };
}

export function normalizeOAuthScopes(value: string) {
  return [...new Set(value.split(/[\s,]+/u).filter(Boolean))];
}

export function oauthCallbackRefreshKey(parameters: URLSearchParams) {
  const result = parameters.get("result");
  if (result !== "success" && result !== "success_refresh_failed" && result !== "failed") {
    return null;
  }
  const connectionId = parameters.get("oauth");
  if (connectionId === null || connectionId.trim() === "") return null;
  return `${result}:${connectionId}`;
}

export function oauthCallbackConnectionId(refreshKey: string | null) {
  if (refreshKey === null) return null;
  const separator = refreshKey.indexOf(":");
  return separator < 0 ? null : refreshKey.slice(separator + 1);
}

export function oauthCallbackOutcomeNotice(refreshKey: string, matched: boolean) {
  if (refreshKey.startsWith("failed:")) {
    return {
      tone: "error" as const,
      message: "OAuth authorization did not complete. Review the connection status and try again.",
    };
  }
  if (!matched) {
    return {
      tone: "error" as const,
      message: "OAuth returned, but no matching managed connection is available.",
    };
  }
  if (refreshKey.startsWith("success_refresh_failed:")) {
    return {
      tone: "error" as const,
      message:
        "OAuth authorization completed, but the source catalog could not be refreshed. The connection remains authorized; retry the source refresh.",
    };
  }
  return {
    tone: "success" as const,
    message: "OAuth authorization completed and the connection status was refreshed.",
  };
}

export function oauthCallbackNoticeWithoutEligibleSources(
  refreshKey: string | null,
  sourceKinds: readonly string[],
  loading: boolean,
) {
  if (
    refreshKey === null ||
    loading ||
    sourceKinds.some((kind) => kind === "openapi" || kind === "graphql" || kind === "mcp_http")
  ) {
    return null;
  }
  return oauthCallbackOutcomeNotice(refreshKey, false);
}

export function withoutOAuthCallbackParameters(value: URL) {
  const url = new URL(value);
  url.searchParams.delete("oauth");
  url.searchParams.delete("result");
  return url;
}

export function safeAuthorizationUrl(value: string) {
  if (!URL.canParse(value)) return null;
  const url = new URL(value);
  if (!isSecureOAuthUrl(url) || hasUserInfo(url) || url.hash !== "") return null;
  return url.toString();
}

export function oauthStatusTone(status: OAuthConnectionStatus) {
  if (status === "connected") return "connected";
  if (status === "error" || status === "reauthorization_required") return "error";
  if (status === "connecting") return "pending";
  return "neutral";
}

export function oauthStatusLabel(status: OAuthConnectionStatus) {
  if (status === "not_configured") return "Not configured";
  if (status === "ready_to_connect") return "Ready to connect";
  if (status === "connecting") return "Connecting";
  if (status === "connected") return "Connected";
  if (status === "reauthorization_required") return "Reconnect required";
  return "Connection error";
}

export function canDisconnectOAuth(status: OAuthConnectionStatus) {
  return status === "connected" || status === "reauthorization_required";
}

function normalizedHttpUrl(value: string) {
  const normalized = value.trim();
  if (!URL.canParse(normalized)) return null;
  const url = new URL(normalized);
  if (!isSecureOAuthUrl(url) || hasUserInfo(url) || url.search !== "" || url.hash !== "") {
    return null;
  }
  return normalized;
}

function isSecureOAuthUrl(url: URL) {
  if (url.protocol === "https:") return true;
  if (url.protocol !== "http:") return false;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/gu, "");
  if (host === "localhost" || host.endsWith(".localhost") || host === "::1") return true;
  const octets = host.split(".").map(Number);
  return (
    octets.length === 4 &&
    octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255) &&
    octets[0] === 127
  );
}

function hasUserInfo(url: URL) {
  return url.username !== "" || url.password !== "";
}
