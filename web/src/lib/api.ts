import { Option, Schema } from "effect";

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
