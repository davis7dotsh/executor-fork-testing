import { Option, Schema } from "effect";
import type { GraphqlCredential, GraphqlSourceInput } from "$lib/graphql-source-state";
import type {
  OAuthAuthorization,
  OAuthConnectionInput,
  OAuthConnectionList,
  OAuthConnectionSummary,
} from "$lib/oauth-connection-state";

export type { GraphqlCredential, GraphqlSourceInput } from "$lib/graphql-source-state";
export type {
  OAuthAuthorization,
  OAuthAvailableCredential,
  OAuthConnectionInput,
  OAuthConnectionList,
  OAuthConnectionSummary,
} from "$lib/oauth-connection-state";

const BootstrapSchema = Schema.Struct({
  setupRequired: Schema.Boolean,
  authenticated: Schema.Boolean,
});

const SessionSchema = Schema.Struct({
  username: Schema.String,
  csrfToken: Schema.NullOr(Schema.String),
});

const TokenMetadataSchema = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  maskedToken: Schema.String,
  createdAt: Schema.Number,
  lastUsedAt: Schema.NullOr(Schema.Number),
  revokedAt: Schema.NullOr(Schema.Number),
});

const CreatedTokenSchema = Schema.Struct({
  id: Schema.String,
  name: Schema.String,
  token: Schema.String,
  createdAt: Schema.Number,
});

const TokenListSchema = Schema.Struct({
  tokens: Schema.Array(TokenMetadataSchema),
});

const ToolModeSchema = Schema.Literals(["enabled", "ask", "disabled"]);
const ModeProvenanceSchema = Schema.Literals(["tool_override", "source_override", "intrinsic"]);
const SourcePublicConfigurationSchema = Schema.Struct({
  endpoint: Schema.optional(Schema.String),
  allowPrivateNetwork: Schema.optional(Schema.Boolean),
  templateName: Schema.optional(Schema.String),
  negotiatedProtocolVersion: Schema.optional(Schema.String),
});

const SourceSchema = Schema.Struct({
  id: Schema.String,
  kind: Schema.Literals(["openapi", "graphql", "mcp_http", "mcp_stdio"]),
  slug: Schema.String,
  displayName: Schema.String,
  description: Schema.NullOr(Schema.String),
  configuration: SourcePublicConfigurationSchema,
  modeOverride: Schema.NullOr(ToolModeSchema),
  healthStatus: Schema.Literals(["unknown", "healthy", "error"]),
  healthErrorCode: Schema.NullOr(Schema.String),
  revision: Schema.Number,
  catalogRevision: Schema.Number,
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
  lastRefreshedAt: Schema.NullOr(Schema.Number),
  toolCount: Schema.Number,
  tombstonedToolCount: Schema.Number,
});

const SourceListSchema = Schema.Struct({
  sources: Schema.Array(SourceSchema),
  catalogRevision: Schema.Number,
});

const OAuthFlowSchema = Schema.Struct({
  authorizationUrl: Schema.NullOr(Schema.String),
  tokenUrl: Schema.NullOr(Schema.String),
  refreshUrl: Schema.NullOr(Schema.String),
  scopes: Schema.Record(Schema.String, Schema.String),
});

const OAuthFlowsSchema = Schema.Struct({
  implicit: Schema.NullOr(OAuthFlowSchema),
  password: Schema.NullOr(OAuthFlowSchema),
  clientCredentials: Schema.NullOr(OAuthFlowSchema),
  authorizationCode: Schema.NullOr(OAuthFlowSchema),
});

const OpenApiCredentialTypeSchema = Schema.Literals([
  "api_key",
  "bearer",
  "basic",
  "manual_oauth_access_token",
  "http",
  "mutual_tls",
]);

const OpenApiPreviewSchema = Schema.Struct({
  title: Schema.String,
  description: Schema.NullOr(Schema.String),
  toolCount: Schema.Number,
  tools: Schema.Array(
    Schema.Struct({
      preferredName: Schema.String,
      displayName: Schema.String,
      description: Schema.NullOr(Schema.String),
      intrinsicMode: ToolModeSchema,
      security: Schema.Array(Schema.Array(Schema.String)),
    }),
  ),
  securitySchemes: Schema.Array(
    Schema.Struct({
      name: Schema.String,
      credentialType: OpenApiCredentialTypeSchema,
      placement: Schema.NullOr(Schema.Literals(["header", "query", "cookie", "path"])),
      supported: Schema.Boolean,
      oauthFlows: Schema.NullOr(OAuthFlowsSchema),
    }),
  ),
});

const CredentialMetadataSchema = Schema.Struct({
  revision: Schema.Number,
  configuredSchemes: Schema.Array(
    Schema.Struct({
      name: Schema.String,
      credentialType: Schema.Literals([
        "api_key",
        "bearer",
        "basic",
        "manual_oauth_access_token",
        "secret_env",
        "header",
        "api_key_header",
        "oauth_access_token",
      ]),
    }),
  ),
});

const McpStdioTemplateListSchema = Schema.Struct({
  templates: Schema.Array(
    Schema.Struct({
      name: Schema.String,
      secretFields: Schema.Array(Schema.String),
    }),
  ),
});

const OAuthConnectionStatusSchema = Schema.Literals([
  "not_configured",
  "ready_to_connect",
  "connecting",
  "connected",
  "reauthorization_required",
  "error",
]);

const OAuthConnectionSummarySchema = Schema.Struct({
  id: Schema.String,
  credentialKey: Schema.String,
  revision: Schema.Number,
  status: OAuthConnectionStatusSchema,
  issuer: Schema.String,
  clientId: Schema.String,
  clientAuthMethod: Schema.Literals(["none", "client_secret_basic", "client_secret_post"]),
  callbackUrl: Schema.String,
  requestedScopes: Schema.Array(Schema.String),
  grantedScopes: Schema.Array(Schema.String),
  hasClientSecret: Schema.Boolean,
  hasRefreshToken: Schema.Boolean,
  accessExpiresAt: Schema.NullOr(Schema.Number),
  authorizedAt: Schema.NullOr(Schema.Number),
  lastRefreshedAt: Schema.NullOr(Schema.Number),
  errorCode: Schema.NullOr(Schema.String),
  managedOAuthEligible: Schema.Boolean,
});

const OAuthAvailableCredentialSchema = Schema.Struct({
  credentialKey: Schema.String,
  protocol: Schema.Literals(["openapi", "graphql", "mcp_http"]),
  requestedScopes: Schema.Array(Schema.String),
  managedOAuthEligible: Schema.Literal(true),
});

const OAuthConnectionListSchema = Schema.Struct({
  connections: Schema.Array(OAuthConnectionSummarySchema),
  availableCredentials: Schema.Array(OAuthAvailableCredentialSchema),
});

const OAuthAuthorizationSchema = Schema.Struct({ authorizationUrl: Schema.String });

const CatalogSyncResultSchema = Schema.Struct({
  sourceId: Schema.String,
  sourceRevision: Schema.Number,
  catalogRevision: Schema.Number,
  globalRevision: Schema.Number,
  activeToolCount: Schema.Number,
  tombstonedToolCount: Schema.Number,
});

const EffectiveModeSchema = Schema.Struct({
  mode: ToolModeSchema,
  provenance: ModeProvenanceSchema,
});

const ToolSummarySchema = Schema.Struct({
  id: Schema.String,
  sourceId: Schema.String,
  sourceSlug: Schema.String,
  stableKey: Schema.String,
  localName: Schema.String,
  callablePath: Schema.String,
  sandboxPath: Schema.String,
  displayName: Schema.String,
  description: Schema.NullOr(Schema.String),
  intrinsicMode: ToolModeSchema,
  modeOverride: Schema.NullOr(ToolModeSchema),
  effectiveMode: EffectiveModeSchema,
  present: Schema.Boolean,
  revision: Schema.Number,
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
  lastSeenAt: Schema.Number,
  tombstonedAt: Schema.NullOr(Schema.Number),
});

const ToolRecordSchema = Schema.Struct({
  ...ToolSummarySchema.fields,
  inputSchema: Schema.Unknown,
  outputSchema: Schema.NullOr(Schema.Unknown),
  inputTypescript: Schema.NullOr(Schema.String),
  outputTypescript: Schema.NullOr(Schema.String),
  typescriptDefinitions: Schema.Record(Schema.String, Schema.String),
});

const ToolPageSchema = Schema.Struct({
  items: Schema.Array(ToolSummarySchema),
  total: Schema.Number,
  hasMore: Schema.Boolean,
  nextOffset: Schema.NullOr(Schema.Number),
  catalogRevision: Schema.Number,
});

const BulkToolModeResultSchema = Schema.Struct({
  updatedCount: Schema.Number,
  catalogRevision: Schema.Number,
  sourceRevisions: Schema.Record(Schema.String, Schema.Number),
});

const RequestLogSchema = Schema.Struct({
  requestId: Schema.String,
  actorApiTokenId: Schema.NullOr(Schema.String),
  surface: Schema.Literals(["admin", "gateway", "cli", "mcp"]),
  sourceId: Schema.NullOr(Schema.String),
  toolId: Schema.NullOr(Schema.String),
  pathSnapshot: Schema.NullOr(Schema.String),
  outcome: Schema.Literals(["succeeded", "failed", "pending_approval", "denied"]),
  errorCode: Schema.NullOr(Schema.String),
  durationMs: Schema.Number,
  approvalId: Schema.NullOr(Schema.String),
  createdAt: Schema.Number,
});

const RequestLogPageSchema = Schema.Struct({
  items: Schema.Array(RequestLogSchema),
  nextCursor: Schema.NullOr(Schema.String),
});

const ApprovalStatusSchema = Schema.Literals([
  "pending",
  "approved",
  "executing",
  "succeeded",
  "failed",
  "denied",
  "canceled",
  "expired",
  "stale",
  "interrupted",
]);

const ApprovalSummarySchema = Schema.Struct({
  id: Schema.String,
  status: ApprovalStatusSchema,
  revision: Schema.Number,
  sourceId: Schema.String,
  toolId: Schema.String,
  path: Schema.String,
  sourceDisplayName: Schema.NullOr(Schema.String),
  toolDisplayName: Schema.NullOr(Schema.String),
  actorKind: Schema.Literals(["api_token", "admin", "system"]),
  actorId: Schema.String,
  actorName: Schema.NullOr(Schema.String),
  actorLabel: Schema.String,
  actorApiTokenId: Schema.NullOr(Schema.String),
  actorTokenName: Schema.NullOr(Schema.String),
  surface: Schema.Literals(["gateway", "cli", "mcp"]),
  mode: Schema.Literal("ask"),
  provenance: ModeProvenanceSchema,
  executionId: Schema.String,
  callId: Schema.String,
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
  expiresAt: Schema.Number,
  decidedAt: Schema.NullOr(Schema.Number),
  startedAt: Schema.NullOr(Schema.Number),
  completedAt: Schema.NullOr(Schema.Number),
  decision: Schema.NullOr(Schema.Literals(["approve", "deny"])),
  failureCode: Schema.NullOr(Schema.String),
});

const ApprovalDetailSchema = Schema.Struct({
  ...ApprovalSummarySchema.fields,
  redactedArguments: Schema.Unknown,
  inputSchema: Schema.Unknown,
});

const ApprovalPageSchema = Schema.Struct({
  items: Schema.Array(ApprovalSummarySchema),
  nextCursor: Schema.NullOr(Schema.String),
});

const ErrorEnvelopeSchema = Schema.Struct({
  error: Schema.Struct({
    code: Schema.String,
    message: Schema.String,
    requestId: Schema.String,
  }),
});

export type Bootstrap = typeof BootstrapSchema.Type;
export type Session = typeof SessionSchema.Type;
export type TokenMetadata = typeof TokenMetadataSchema.Type;
export type CreatedToken = typeof CreatedTokenSchema.Type;
export type ToolMode = typeof ToolModeSchema.Type;
export type Source = typeof SourceSchema.Type;
export type SourceList = typeof SourceListSchema.Type;
export type OpenApiPreview = typeof OpenApiPreviewSchema.Type;
export type CatalogSyncResult = typeof CatalogSyncResultSchema.Type;
export type OpenApiCredentialMetadata = typeof CredentialMetadataSchema.Type;
export type McpStdioTemplate = (typeof McpStdioTemplateListSchema.Type)["templates"][number];
export type ToolSummary = typeof ToolSummarySchema.Type;
export type ToolRecord = typeof ToolRecordSchema.Type;
export type ToolPage = typeof ToolPageSchema.Type;
export type BulkToolModeResult = typeof BulkToolModeResultSchema.Type;
export type RequestLog = typeof RequestLogSchema.Type;
export type RequestLogPage = typeof RequestLogPageSchema.Type;
export type ApprovalStatus = typeof ApprovalStatusSchema.Type;
export type ApprovalSummary = typeof ApprovalSummarySchema.Type;
export type ApprovalDetail = typeof ApprovalDetailSchema.Type;
export type ApprovalPage = typeof ApprovalPageSchema.Type;
export type ApprovalDecision = "approve" | "deny";

export class ApiError extends Schema.TaggedErrorClass<ApiError>()("ApiError", {
  code: Schema.String,
  displayMessage: Schema.String,
  requestId: Schema.NullOr(Schema.String),
  status: Schema.Number,
}) {}

export type ApiResult<Value> =
  | { readonly ok: true; readonly value: Value }
  | { readonly ok: false; readonly error: ApiError };

type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
type ResponsePayload = { text: string; requestId: string | null };

const decodeBootstrap = Schema.decodeUnknownOption(Schema.fromJsonString(BootstrapSchema));
const decodeSession = Schema.decodeUnknownOption(Schema.fromJsonString(SessionSchema));
const decodeCreatedToken = Schema.decodeUnknownOption(Schema.fromJsonString(CreatedTokenSchema));
const decodeTokenList = Schema.decodeUnknownOption(Schema.fromJsonString(TokenListSchema));
const decodeRawSource = Schema.decodeUnknownOption(Schema.fromJsonString(SourceSchema));
const decodeRawSourceList = Schema.decodeUnknownOption(Schema.fromJsonString(SourceListSchema));
const decodeSource = (text: string) => sanitizeDecodedSource(decodeRawSource(text));
const decodeSourceList = (text: string) => {
  const decoded = decodeRawSourceList(text);
  if (Option.isNone(decoded)) return decoded;
  return Option.some({
    ...decoded.value,
    sources: decoded.value.sources.map(sanitizeSource),
  });
};
const decodeOpenApiPreview = Schema.decodeUnknownOption(
  Schema.fromJsonString(OpenApiPreviewSchema),
);
const decodeCatalogSyncResult = Schema.decodeUnknownOption(
  Schema.fromJsonString(CatalogSyncResultSchema),
);
const decodeCredentialMetadata = Schema.decodeUnknownOption(
  Schema.fromJsonString(CredentialMetadataSchema),
);
const decodeMcpStdioTemplateList = Schema.decodeUnknownOption(
  Schema.fromJsonString(McpStdioTemplateListSchema),
);
const decodeOAuthConnection = Schema.decodeUnknownOption(
  Schema.fromJsonString(OAuthConnectionSummarySchema),
);
const decodeOAuthConnectionList = Schema.decodeUnknownOption(
  Schema.fromJsonString(OAuthConnectionListSchema),
);
const decodeOAuthAuthorization = Schema.decodeUnknownOption(
  Schema.fromJsonString(OAuthAuthorizationSchema),
);
const decodeToolRecord = Schema.decodeUnknownOption(Schema.fromJsonString(ToolRecordSchema));
const decodeToolPage = Schema.decodeUnknownOption(Schema.fromJsonString(ToolPageSchema));
const decodeBulkToolModeResult = Schema.decodeUnknownOption(
  Schema.fromJsonString(BulkToolModeResultSchema),
);
const decodeRequestLog = Schema.decodeUnknownOption(Schema.fromJsonString(RequestLogSchema));
const decodeRequestLogPage = Schema.decodeUnknownOption(
  Schema.fromJsonString(RequestLogPageSchema),
);
const decodeApprovalDetail = Schema.decodeUnknownOption(
  Schema.fromJsonString(ApprovalDetailSchema),
);
const decodeApprovalPage = Schema.decodeUnknownOption(Schema.fromJsonString(ApprovalPageSchema));
const decodeErrorEnvelope = Schema.decodeUnknownOption(Schema.fromJsonString(ErrorEnvelopeSchema));

export async function getBootstrap(fetcher: Fetcher = fetch, signal?: AbortSignal) {
  const response = await request("/api/v1/bootstrap", { signal }, fetcher);
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeBootstrap);
}

export async function setupAdmin(
  input: { setupToken: string; username: string; password: string },
  fetcher: Fetcher = fetch,
) {
  const response = await request(
    "/api/v1/setup",
    { method: "POST", body: JSON.stringify(input) },
    fetcher,
    false,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeSession);
}

export async function loginAdmin(
  input: { username: string; password: string },
  fetcher: Fetcher = fetch,
) {
  const response = await request(
    "/api/v1/session",
    { method: "POST", body: JSON.stringify(input) },
    fetcher,
    false,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeSession);
}

export async function getSession(fetcher: Fetcher = fetch, signal?: AbortSignal) {
  const response = await request("/api/v1/session", { signal }, fetcher);
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeSession);
}

export async function logoutAdmin(fetcher: Fetcher = fetch) {
  const response = await request("/api/v1/session", { method: "DELETE" }, fetcher);
  if (!response.ok) return response;
  return { ok: true, value: undefined } as const;
}

export async function listTokens(fetcher: Fetcher = fetch, signal?: AbortSignal) {
  const response = await request("/api/v1/tokens", { signal }, fetcher);
  if (!response.ok) return response;

  const decoded = decodeResponse(response.value, decodeTokenList);
  if (!decoded.ok) return decoded;
  return { ok: true, value: [...decoded.value.tokens] } as const;
}

export async function createToken(name: string, fetcher: Fetcher = fetch, signal?: AbortSignal) {
  const response = await request(
    "/api/v1/tokens",
    { method: "POST", body: JSON.stringify({ name }), signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeCreatedToken);
}

export async function revokeToken(tokenId: string, fetcher: Fetcher = fetch, signal?: AbortSignal) {
  const response = await request(
    `/api/v1/tokens/${encodeURIComponent(tokenId)}`,
    { method: "DELETE", signal },
    fetcher,
  );
  if (!response.ok) return response;
  return { ok: true, value: undefined } as const;
}

export async function listSources(fetcher: Fetcher = fetch, signal?: AbortSignal) {
  const response = await request("/api/v1/sources", { signal }, fetcher);
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeSourceList);
}

export async function setSourceMode(
  sourceId: string,
  mode: ToolMode | null,
  expectedRevision: number,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/mode`,
    {
      method: "PATCH",
      body: JSON.stringify({ mode, expectedRevision }),
      signal,
    },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeSource);
}

export async function deleteSource(
  sourceId: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}`,
    { method: "DELETE", signal },
    fetcher,
  );
  if (!response.ok) return response;
  return { ok: true, value: undefined } as const;
}

export type OpenApiSpecInput =
  | { readonly type: "inline"; readonly content: string }
  | { readonly type: "url"; readonly url: string };

export type OpenApiStaticCredential =
  | { readonly type: "api_key"; readonly value: string }
  | { readonly type: "bearer"; readonly token: string }
  | { readonly type: "basic"; readonly username: string; readonly password: string }
  | { readonly type: "oauth_access_token"; readonly access_token: string };

export type OpenApiSourceInput = {
  readonly kind: "openapi";
  readonly displayName: string;
  readonly preferredSlug?: string;
  readonly description?: string;
  readonly spec: OpenApiSpecInput;
  readonly allowPrivateNetwork?: boolean;
  readonly credential?: {
    readonly schemes: Readonly<Record<string, OpenApiStaticCredential>>;
  };
};

export type McpHttpSourceInput = {
  readonly kind: "mcp_http";
  readonly displayName: string;
  readonly description?: string;
  readonly endpoint: string;
  readonly allowPrivateNetwork?: boolean;
  readonly credential?: Exclude<McpHttpCredential["credential"], null>;
};

export type McpStdioSourceInput = {
  readonly kind: "mcp_stdio";
  readonly displayName: string;
  readonly description?: string;
  readonly templateName: string;
  readonly secretValues: Readonly<Record<string, string>>;
};

export type McpHttpCredential =
  | { readonly credential: null }
  | { readonly credential: { readonly type: "bearer"; readonly token: string } }
  | {
      readonly credential: {
        readonly type: "basic";
        readonly username: string;
        readonly password: string;
      };
    }
  | {
      readonly credential: {
        readonly type: "api_key_header";
        readonly name: string;
        readonly value: string;
      };
    }
  | {
      readonly credential: {
        readonly type: "oauth_access_token";
        readonly accessToken: string;
      };
    };

export type McpStdioCredential = {
  readonly secretValues: Readonly<Record<string, string>>;
};

export async function previewOpenApiSource(
  spec: OpenApiSpecInput,
  allowPrivateNetwork: boolean,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    "/api/v1/sources/openapi/preview",
    { method: "POST", body: JSON.stringify({ spec, allowPrivateNetwork }), signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeOpenApiPreview);
}

export async function createOpenApiSource(
  input: OpenApiSourceInput,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    "/api/v1/sources",
    { method: "POST", body: JSON.stringify(input), signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeSource);
}

export async function createMcpHttpSource(
  input: McpHttpSourceInput,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    "/api/v1/sources",
    { method: "POST", body: JSON.stringify(input), signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeSource);
}

export async function createGraphqlSource(
  input: GraphqlSourceInput,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    "/api/v1/sources",
    { method: "POST", body: JSON.stringify(input), signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeSource);
}

export async function listMcpStdioTemplates(fetcher: Fetcher = fetch, signal?: AbortSignal) {
  const response = await request("/api/v1/mcp/stdio/templates", { signal }, fetcher);
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeMcpStdioTemplateList);
}

export async function createMcpStdioSource(
  input: McpStdioSourceInput,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    "/api/v1/sources",
    { method: "POST", body: JSON.stringify(input), signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeSource);
}

export async function refreshOpenApiSource(
  sourceId: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/refresh`,
    { method: "POST", body: "{}", signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeCatalogSyncResult);
}

export async function refreshSourceCatalog(
  sourceId: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/refresh`,
    { method: "POST", body: "{}", signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeCatalogSyncResult);
}

export async function getOpenApiCredentials(
  sourceId: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/credentials`,
    { signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeCredentialMetadata);
}

export async function getSourceCredentials(
  sourceId: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/credentials`,
    { signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeCredentialMetadata);
}

export async function putMcpHttpCredentials(
  sourceId: string,
  expectedRevision: number,
  credential: McpHttpCredential,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  return putProtocolCredentials(sourceId, expectedRevision, credential, fetcher, signal);
}

export async function putMcpStdioCredentials(
  sourceId: string,
  expectedRevision: number,
  credential: McpStdioCredential,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  return putProtocolCredentials(sourceId, expectedRevision, credential, fetcher, signal);
}

export async function putGraphqlCredentials(
  sourceId: string,
  expectedRevision: number,
  credential: GraphqlCredential,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/credentials`,
    {
      method: "PUT",
      body: JSON.stringify({ expectedRevision, credential }),
      signal,
    },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeCredentialMetadata);
}

export async function listOAuthConnections(
  sourceId: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
): Promise<ApiResult<OAuthConnectionList>> {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/oauth`,
    { signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeOAuthConnectionList);
}

export async function putOAuthConnection(
  sourceId: string,
  credentialKey: string,
  input: OAuthConnectionInput,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
): Promise<ApiResult<OAuthConnectionSummary>> {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/oauth/${encodeURIComponent(credentialKey)}`,
    { method: "PUT", body: JSON.stringify(input), signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeOAuthConnection);
}

export async function authorizeOAuthConnection(
  sourceId: string,
  credentialKey: string,
  input: { readonly expectedRevision: number },
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
): Promise<ApiResult<OAuthAuthorization>> {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/oauth/${encodeURIComponent(credentialKey)}/authorize`,
    { method: "POST", body: JSON.stringify(input), signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeOAuthAuthorization);
}

export async function disconnectOAuthConnection(
  sourceId: string,
  credentialKey: string,
  input: { readonly expectedRevision: number },
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
): Promise<ApiResult<OAuthConnectionSummary>> {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/oauth/${encodeURIComponent(credentialKey)}/disconnect`,
    { method: "POST", body: JSON.stringify(input), signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeOAuthConnection);
}

export async function deleteOAuthConnection(
  sourceId: string,
  credentialKey: string,
  input: { readonly expectedRevision: number },
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
): Promise<ApiResult<void>> {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/oauth/${encodeURIComponent(credentialKey)}?expectedRevision=${encodeURIComponent(String(input.expectedRevision))}`,
    { method: "DELETE", signal },
    fetcher,
  );
  if (!response.ok) return response;
  return { ok: true, value: undefined };
}

export async function putOpenApiCredentials(
  sourceId: string,
  expectedRevision: number,
  schemes: Readonly<Record<string, OpenApiStaticCredential>>,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/credentials`,
    {
      method: "PUT",
      body: JSON.stringify({ expectedRevision, credential: { schemes } }),
      signal,
    },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeCredentialMetadata);
}

export async function deleteOpenApiCredentials(
  sourceId: string,
  expectedRevision: number,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/credentials?expectedRevision=${encodeURIComponent(String(expectedRevision))}`,
    { method: "DELETE", signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeCredentialMetadata);
}

async function putProtocolCredentials(
  sourceId: string,
  expectedRevision: number,
  credential: McpHttpCredential | McpStdioCredential,
  fetcher: Fetcher,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/sources/${encodeURIComponent(sourceId)}/credentials`,
    {
      method: "PUT",
      body: JSON.stringify({ expectedRevision, credential }),
      signal,
    },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeCredentialMetadata);
}

export type ToolListFilters = {
  query?: string;
  sourceId?: string;
  mode?: ToolMode;
  includeTombstoned?: boolean;
  limit?: number;
  offset?: number;
};

export async function listTools(
  filters: ToolListFilters,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const parameters = new URLSearchParams();
  if (filters.query) parameters.set("query", filters.query);
  if (filters.sourceId) parameters.set("sourceId", filters.sourceId);
  if (filters.mode) parameters.set("mode", filters.mode);
  if (filters.includeTombstoned) parameters.set("includeTombstoned", "true");
  if (filters.limit !== undefined) parameters.set("limit", String(filters.limit));
  if (filters.offset !== undefined) parameters.set("offset", String(filters.offset));
  const response = await request(`/api/v1/tools?${parameters}`, { signal }, fetcher);
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeToolPage);
}

export async function getTool(toolId: string, fetcher: Fetcher = fetch, signal?: AbortSignal) {
  const response = await request(
    `/api/v1/tools/${encodeURIComponent(toolId)}`,
    { signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeToolRecord);
}

export async function setToolMode(
  toolId: string,
  mode: ToolMode | null,
  expectedRevision: number,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/tools/${encodeURIComponent(toolId)}/mode`,
    {
      method: "PATCH",
      body: JSON.stringify({ mode, expectedRevision }),
      signal,
    },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeToolRecord);
}

export async function bulkSetToolModes(
  toolIds: readonly string[],
  mode: ToolMode | null,
  expectedCatalogRevision: number,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    "/api/v1/tools/modes",
    {
      method: "PATCH",
      body: JSON.stringify({
        selection: { type: "tool_ids", toolIds, expectedCatalogRevision },
        mode,
      }),
      signal,
    },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeBulkToolModeResult);
}

export async function listRequestLogs(
  cursor: string | null,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const parameters = new URLSearchParams({ limit: "50" });
  if (cursor) parameters.set("cursor", cursor);
  const response = await request(`/api/v1/request-logs?${parameters}`, { signal }, fetcher);
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeRequestLogPage);
}

export async function getRequestLog(
  requestId: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/request-logs/${encodeURIComponent(requestId)}`,
    { signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeRequestLog);
}

export async function listApprovals(
  filters: {
    readonly status: ApprovalStatus | null;
    readonly cursor: string | null;
    readonly limit: number;
  },
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const parameters = new URLSearchParams({ limit: String(filters.limit) });
  if (filters.status !== null) parameters.set("status", filters.status);
  if (filters.cursor !== null) parameters.set("cursor", filters.cursor);
  const response = await request(`/api/v1/approvals?${parameters}`, { signal }, fetcher);
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeApprovalPage);
}

export async function getApproval(
  approvalId: string,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/approvals/${encodeURIComponent(approvalId)}`,
    { signal },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeApprovalDetail);
}

export async function decideApproval(
  approvalId: string,
  decision: ApprovalDecision,
  expectedRevision: number,
  fetcher: Fetcher = fetch,
  signal?: AbortSignal,
) {
  const response = await request(
    `/api/v1/approvals/${encodeURIComponent(approvalId)}/decision`,
    {
      method: "POST",
      body: JSON.stringify({ decision, expectedRevision }),
      signal,
    },
    fetcher,
  );
  if (!response.ok) return response;
  return decodeResponse(response.value, decodeApprovalDetail);
}

async function request(path: string, init: RequestInit, fetcher: Fetcher, includeCsrf = true) {
  if (!path.startsWith("/api/")) {
    return failure(
      "invalid_request_path",
      "The dashboard only sends requests to this Executor instance.",
      null,
      0,
    );
  }

  const headers = new Headers(init.headers);
  headers.set("accept", "application/json");
  if (init.body !== undefined) headers.set("content-type", "application/json");
  if (includeCsrf && isUnsafeMethod(init.method)) {
    const csrfToken = readCookie("executor_csrf");
    if (csrfToken !== null) headers.set("x-executor-csrf", csrfToken);
  }

  const fetched = await fetcher(path, {
    ...init,
    headers,
    credentials: "same-origin",
  }).then(
    (response) => ({ ok: true, response }) as const,
    () => ({ ok: false }) as const,
  );

  if (!fetched.ok) {
    return failure(
      init.signal?.aborted ? "request_cancelled" : "network_error",
      init.signal?.aborted
        ? "The request was cancelled."
        : "Executor could not be reached. Check that the local server is running.",
      null,
      0,
    );
  }

  const { response } = fetched;
  const requestId = response.headers.get("x-request-id");
  const body = await response.text().then(
    (text) => ({ ok: true, text }) as const,
    () => ({ ok: false }) as const,
  );
  if (!body.ok) {
    return failure(
      "invalid_response",
      "Executor returned a response body the dashboard could not read.",
      requestId,
      502,
    );
  }

  if (!response.ok) return decodeError(body.text, requestId, response.status);
  return { ok: true, value: { text: body.text, requestId } } as const;
}

function decodeResponse<Value>(
  response: ResponsePayload,
  decoder: (text: string) => Option.Option<Value>,
): ApiResult<Value> {
  const decoded = decoder(response.text);
  if (Option.isNone(decoded)) {
    return failure(
      "invalid_response",
      "Executor returned a response the dashboard could not understand.",
      response.requestId,
      502,
    );
  }
  return { ok: true, value: decoded.value };
}

function decodeError(text: string, headerRequestId: string | null, status: number) {
  const decoded = decodeErrorEnvelope(text);
  if (Option.isNone(decoded)) {
    return failure(`http_${status}`, fallbackStatusMessage(status), headerRequestId, status);
  }

  return failure(
    decoded.value.error.code,
    decoded.value.error.message,
    decoded.value.error.requestId || headerRequestId,
    status,
  );
}

function failure(code: string, displayMessage: string, requestId: string | null, status: number) {
  return {
    ok: false,
    error: new ApiError({ code, displayMessage, requestId, status }),
  } as const;
}

function fallbackStatusMessage(status: number) {
  if (status === 401) return "Your administrator session is no longer valid.";
  if (status === 403) return "Executor rejected this request.";
  if (status === 404) return "The requested Executor resource does not exist.";
  if (status >= 500) return "Executor could not complete the request.";
  return `Executor rejected the request with status ${status}.`;
}

function isUnsafeMethod(method: string | undefined) {
  return method !== undefined && !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

function readCookie(name: string) {
  if (typeof document === "undefined") return null;
  for (const part of document.cookie.split(";")) {
    const [cookieName, ...valueParts] = part.trim().split("=");
    if (cookieName === name) return valueParts.join("=");
  }
  return null;
}

function sanitizeDecodedSource(decoded: Option.Option<Source>) {
  return Option.isNone(decoded) ? decoded : Option.some(sanitizeSource(decoded.value));
}

function sanitizeSource(source: Source): Source {
  const endpoint = source.configuration.endpoint;
  return {
    ...source,
    configuration: {
      ...(endpoint === undefined ? {} : publicEndpoint(endpoint)),
      ...(source.configuration.allowPrivateNetwork === undefined
        ? {}
        : { allowPrivateNetwork: source.configuration.allowPrivateNetwork }),
      ...(source.configuration.templateName === undefined
        ? {}
        : { templateName: source.configuration.templateName }),
      ...(source.configuration.negotiatedProtocolVersion === undefined
        ? {}
        : { negotiatedProtocolVersion: source.configuration.negotiatedProtocolVersion }),
    },
  };
}

function publicEndpoint(endpoint: string) {
  if (!URL.canParse(endpoint)) return {};
  const url = new URL(endpoint);
  if (url.protocol !== "http:" && url.protocol !== "https:") return {};
  return { endpoint: url.origin };
}
