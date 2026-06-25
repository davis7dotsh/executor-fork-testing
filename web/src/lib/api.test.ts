import { describe, expect, it } from "@effect/vitest";
import { Effect, Schema } from "effect";
import {
  ApiError,
  authorizeOAuthConnection,
  bulkSetToolModes,
  createGraphqlSource,
  createMcpHttpSource,
  createMcpStdioSource,
  createOpenApiSource,
  createToken,
  decideApproval,
  deleteOAuthConnection,
  deleteOpenApiCredentials,
  getApproval,
  getOpenApiCredentials,
  getSourceCreationResolution,
  getSourceCredentials,
  getBootstrap,
  disconnectOAuthConnection,
  listApprovals,
  listOAuthConnections,
  listMcpStdioTemplates,
  listRequestLogs,
  listSources,
  listTokens,
  listTools,
  loginAdmin,
  previewOpenApiSource,
  putOpenApiCredentials,
  putMcpHttpCredentials,
  putMcpStdioCredentials,
  putOAuthConnection,
  putGraphqlCredentials,
  refreshOpenApiSource,
  revokeToken,
  sealMissingSourceCreation,
  setSourceMode,
} from "./api";

function sourceFixture() {
  return {
    id: "source-1",
    kind: "openapi",
    slug: "github",
    displayName: "GitHub",
    description: "Repository API",
    configuration: { publicBaseUrl: "https://api.example.test" },
    modeOverride: null,
    healthStatus: "healthy",
    healthErrorCode: null,
    revision: 3,
    catalogRevision: 8,
    createdAt: 100,
    updatedAt: 200,
    lastRefreshedAt: 190,
    toolCount: 2,
    tombstonedToolCount: 1,
  };
}

function toolFixture() {
  return {
    id: "tool-1",
    sourceId: "source-1",
    sourceSlug: "github",
    stableKey: "GET /repos",
    localName: "list_repos",
    callablePath: "tools.github.list_repos",
    sandboxPath: "github.list_repos",
    displayName: "List repositories",
    description: "Lists repositories",
    intrinsicMode: "enabled",
    modeOverride: null,
    effectiveMode: { mode: "enabled", provenance: "intrinsic" },
    present: true,
    revision: 4,
    createdAt: 100,
    updatedAt: 200,
    lastSeenAt: 190,
    tombstonedAt: null,
  };
}

function logFixture() {
  return {
    requestId: "request-1",
    actorApiTokenId: "token-id",
    surface: "gateway",
    sourceId: "source-1",
    toolId: "tool-1",
    pathSnapshot: "tools.github.list_repos",
    outcome: "succeeded",
    errorCode: null,
    durationMs: 27,
    approvalId: null,
    createdAt: 200,
  };
}

function approvalSummaryFixture() {
  return {
    id: "approval-1",
    status: "pending",
    revision: 4,
    sourceId: "source-1",
    toolId: "tool-1",
    path: "tools.github.create_issue",
    sourceDisplayName: "GitHub",
    toolDisplayName: "Create issue",
    actorKind: "api_token",
    actorId: "token-1",
    actorName: "Laptop",
    actorLabel: "Laptop",
    actorApiTokenId: "token-1",
    actorTokenName: "Laptop",
    surface: "gateway",
    mode: "ask",
    provenance: "tool_override",
    executionId: "execution-1",
    callId: "call-1",
    createdAt: 100,
    updatedAt: 101,
    expiresAt: 700,
    decidedAt: null,
    startedAt: null,
    completedAt: null,
    decision: null,
    failureCode: null,
  };
}

function approvalDetailFixture() {
  return {
    ...approvalSummaryFixture(),
    redactedArguments: { title: "Issue title", body: "[REDACTED]" },
    inputSchema: { type: "object" },
  };
}

const decodeJson = Schema.decodeUnknownSync(Schema.fromJsonString(Schema.Unknown));
const validTokenSecret = `exr_${"A".repeat(43)}`;

describe("dashboard API client", () => {
  it("normalizes bootstrap data from the control API", async () => {
    const result = await getBootstrap(async () =>
      Response.json({ setupRequired: true, authenticated: false }),
    );

    expect(result).toEqual({
      ok: true,
      value: { setupRequired: true, authenticated: false },
    });
  });

  it("sends cookies and the double-submit CSRF token for authenticated mutations", async () => {
    document.cookie = "executor_csrf=csrf_test_value; Path=/";
    let observedHeaders = new Headers();
    let observedCredentials: RequestCredentials | undefined;
    const created = await createToken("Laptop", "a".repeat(64), async (_input, init) => {
      observedHeaders = new Headers(init?.headers);
      observedCredentials = init?.credentials;
      return Response.json(
        {
          id: "token-id",
          name: "Laptop",
          token: validTokenSecret,
          createdAt: 123,
        },
        { status: 201, headers: { "cache-control": "no-store" } },
      );
    });

    expect(observedHeaders.get("x-executor-csrf")).toBe("csrf_test_value");
    expect(observedHeaders.get("content-type")).toBe("application/json");
    expect(observedHeaders.get("idempotency-key")).toBe("a".repeat(64));
    expect(
      [...observedHeaders.keys()].filter((header) => header === "idempotency-key"),
    ).toHaveLength(1);
    expect(observedCredentials).toBe("same-origin");
    expect(created).toEqual({
      ok: true,
      value: {
        id: "token-id",
        name: "Laptop",
        token: validTokenSecret,
        createdAt: 123,
      },
      replayProvenance: "none",
      responseDisposition: "authoritative",
    });
  });

  it("accepts only strict no-store token creation and replay responses", async () => {
    const createdToken = {
      id: "token-id",
      name: "Laptop",
      token: validTokenSecret,
      createdAt: 123,
    };
    const fresh = await createToken("Laptop", "1".repeat(64), async () =>
      Response.json(createdToken, {
        status: 201,
        headers: { "cache-control": "private, no-store" },
      }),
    );
    const replay = await createToken("Laptop", "1".repeat(64), async () =>
      Response.json(createdToken, {
        status: 201,
        headers: {
          "cache-control": "no-store",
          "idempotency-replayed": "true",
        },
      }),
    );
    const missingNoStore = await createToken("Laptop", "1".repeat(64), async () =>
      Response.json(createdToken, { status: 201 }),
    );
    const wrongStatus = await createToken("Laptop", "1".repeat(64), async () =>
      Response.json(createdToken, {
        status: 200,
        headers: { "cache-control": "no-store" },
      }),
    );
    const invalidReplay = await createToken("Laptop", "1".repeat(64), async () =>
      Response.json(createdToken, {
        status: 201,
        headers: {
          "cache-control": "no-store",
          "idempotency-replayed": "false",
        },
      }),
    );

    expect(fresh).toMatchObject({
      ok: true,
      replayProvenance: "none",
      responseDisposition: "authoritative",
    });
    expect(replay).toMatchObject({
      ok: true,
      replayProvenance: "authoritative",
      responseDisposition: "authoritative",
    });
    for (const result of [missingNoStore, wrongStatus, invalidReplay]) {
      expect(result).toMatchObject({
        ok: false,
        error: { code: "invalid_response" },
        responseDisposition: "ambiguous",
      });
    }
  });

  it("keeps semantically malformed token successes ambiguous", async () => {
    const valid = {
      id: "token-id",
      name: "Laptop",
      token: validTokenSecret,
      createdAt: 123,
    };
    const malformed = [
      { ...valid, id: "" },
      { ...valid, id: "x".repeat(129) },
      { ...valid, name: "Different agent" },
      { ...valid, token: "exr_not-a-32-byte-secret" },
      { ...valid, token: `exr_${"A".repeat(42)}_` },
      { ...valid, createdAt: -1 },
      { ...valid, createdAt: Number.MAX_SAFE_INTEGER + 1 },
    ];

    for (const body of malformed) {
      const result = await createToken("Laptop", "2".repeat(64), async () =>
        Response.json(body, {
          status: 201,
          headers: { "cache-control": "no-store" },
        }),
      );

      expect(result).toMatchObject({
        ok: false,
        error: { code: "invalid_response" },
        responseDisposition: "ambiguous",
      });
    }
  });

  it("automatically retries one ambiguous token revocation", async () => {
    const calls: Array<{ path: string; method: string | undefined }> = [];
    const result = await revokeToken("token/one", async (input, init) => {
      calls.push({ path: String(input), method: init?.method });
      if (calls.length === 1) return Effect.runPromise(Effect.fail("response lost"));
      return new Response(null, { status: 204 });
    });

    expect(result).toEqual({ ok: true, value: undefined });
    expect(calls).toEqual([
      { path: "/api/v1/tokens/token%2Fone", method: "DELETE" },
      { path: "/api/v1/tokens/token%2Fone", method: "DELETE" },
    ]);
  });

  it("does not attach a stale CSRF token to login", async () => {
    document.cookie = "executor_csrf=stale_value; Path=/";
    let observedHeaders = new Headers();
    await loginAdmin({ username: "admin", password: "password" }, async (_input, init) => {
      observedHeaders = new Headers(init?.headers);
      return Response.json({ username: "admin", csrfToken: "csrf_fresh" });
    });

    expect(observedHeaders.has("x-executor-csrf")).toBe(false);
  });

  it("sends exactly one opaque idempotency header for every source connector", async () => {
    const observations: Array<{
      headers: Headers;
      body: unknown;
      credentials: RequestCredentials | undefined;
    }> = [];
    const fetcher = async (_input: RequestInfo | URL, init?: RequestInit) => {
      observations.push({
        headers: new Headers(init?.headers),
        body: decodeJson(String(init?.body)),
        credentials: init?.credentials,
      });
      return Response.json(sourceFixture(), { status: 201 });
    };

    await createOpenApiSource(
      {
        kind: "openapi",
        displayName: "OpenAPI",
        spec: { type: "inline", content: "openapi: 3.1.0" },
      },
      "openapi-key",
      fetcher,
    );
    await createGraphqlSource(
      {
        kind: "graphql",
        displayName: "GraphQL",
        endpoint: "https://api.example.test/graphql",
      },
      "graphql-key",
      fetcher,
    );
    await createMcpHttpSource(
      {
        kind: "mcp_http",
        displayName: "MCP HTTP",
        endpoint: "https://mcp.example.test/mcp",
      },
      "mcp-http-key",
      fetcher,
    );
    await createMcpStdioSource(
      {
        kind: "mcp_stdio",
        displayName: "MCP stdio",
        templateName: "local",
        secretValues: {},
      },
      "mcp-stdio-key",
      fetcher,
    );

    expect(observations.map(({ headers }) => headers.get("idempotency-key"))).toEqual([
      "openapi-key",
      "graphql-key",
      "mcp-http-key",
      "mcp-stdio-key",
    ]);
    for (const observation of observations) {
      expect(
        [...observation.headers.keys()].filter((name) => name === "idempotency-key"),
      ).toHaveLength(1);
      expect(observation.credentials).toBe("same-origin");
      expect(JSON.stringify(observation.body)).not.toContain("-key");
    }
  });

  it("preserves failed source-create replay metadata and transport ambiguity", async () => {
    const input = {
      kind: "graphql" as const,
      displayName: "GraphQL",
      endpoint: "https://api.example.test/graphql",
    };
    const replayedFailure = await createGraphqlSource(input, "replayed-key", async () =>
      Response.json(
        {
          error: {
            code: "internal_error",
            message: "The stored source creation failed.",
            requestId: "stored-failure",
          },
        },
        {
          status: 500,
          headers: { "cache-control": "no-store", "idempotency-replayed": "true" },
        },
      ),
    );
    const firstFailure = await createGraphqlSource(input, "first-key", async () =>
      Response.json(
        {
          error: {
            code: "internal_error",
            message: "Source creation failed.",
            requestId: "first-failure",
          },
        },
        { status: 500 },
      ),
    );
    const duplicateReplayHeaders = new Headers();
    duplicateReplayHeaders.set("Cache-Control", "no-store");
    duplicateReplayHeaders.append("Idempotency-Replayed", "true");
    duplicateReplayHeaders.append("idempotency-replayed", "true");
    const invalidReplayFailure = await createGraphqlSource(input, "invalid-replay-key", async () =>
      Response.json(
        {
          error: {
            code: "internal_error",
            message: "Source creation failed.",
            requestId: "invalid-replay-failure",
          },
        },
        { status: 500, headers: duplicateReplayHeaders },
      ),
    );
    const transportFailure = await createGraphqlSource(input, "transport-key", async () =>
      Effect.runPromise(Effect.fail("connection lost")),
    );

    expect(replayedFailure).toEqual({
      ok: false,
      error: new ApiError({
        code: "internal_error",
        displayMessage: "The stored source creation failed.",
        requestId: "stored-failure",
        status: 500,
      }),
      replayProvenance: "authoritative",
      responseDisposition: "authoritative",
    });
    expect(firstFailure).toMatchObject({
      ok: false,
      error: { code: "internal_error", status: 500 },
      replayProvenance: "none",
    });
    expect(invalidReplayFailure).toMatchObject({
      ok: false,
      error: { code: "internal_error", status: 500 },
      replayProvenance: "invalid",
    });
    expect(transportFailure).toMatchObject({
      ok: false,
      error: { code: "network_error", status: 0 },
      replayProvenance: "none",
    });
  });

  it("keeps malformed replayed failure bodies ambiguous", async () => {
    const input = {
      kind: "graphql" as const,
      displayName: "GraphQL",
      endpoint: "https://api.example.test/graphql",
    };
    const headers = {
      "cache-control": "no-store",
      "idempotency-replayed": "true",
    };
    const malformedText = await createGraphqlSource(
      input,
      "text-key",
      async () => new Response("gateway failure", { status: 500, headers }),
    );
    const malformedJson = await createGraphqlSource(
      input,
      "json-key",
      async () => new Response('{"error":', { status: 500, headers }),
    );
    const incompleteError = await createGraphqlSource(input, "incomplete-key", async () =>
      Response.json(
        { error: { code: "internal_error", message: "Stored failure." } },
        { status: 500, headers },
      ),
    );
    const missingNoStore = await createGraphqlSource(input, "cache-key", async () =>
      Response.json(
        {
          error: {
            code: "internal_error",
            message: "Stored failure.",
            requestId: "stored-failure",
          },
        },
        { status: 500, headers: { "idempotency-replayed": "true" } },
      ),
    );

    for (const result of [malformedText, malformedJson, incompleteError, missingNoStore]) {
      expect(result.ok).toBe(false);
      expect(result.replayProvenance).toBe("invalid");
    }
  });

  it("requires a valid source body and replay contract for authoritative success", async () => {
    const input = {
      kind: "graphql" as const,
      displayName: "GraphQL",
      endpoint: "https://api.example.test/graphql",
    };
    const replayHeaders = {
      "cache-control": "private, No-Store",
      "idempotency-replayed": "true",
    };
    const authoritative = await createGraphqlSource(input, "success-key", async () =>
      Response.json(sourceFixture(), { status: 201, headers: replayHeaders }),
    );
    const incompleteBody = await createGraphqlSource(input, "incomplete-key", async () =>
      Response.json({ ...sourceFixture(), id: undefined }, { status: 201, headers: replayHeaders }),
    );
    const missingNoStore = await createGraphqlSource(input, "cache-key", async () =>
      Response.json(sourceFixture(), {
        status: 201,
        headers: { "idempotency-replayed": "true" },
      }),
    );

    expect(authoritative).toMatchObject({ ok: true, replayProvenance: "authoritative" });
    expect(incompleteBody).toMatchObject({
      ok: false,
      error: { code: "invalid_response" },
      replayProvenance: "invalid",
    });
    expect(missingNoStore).toMatchObject({ ok: true, replayProvenance: "invalid" });
  });

  it("looks up source creation using only a no-store authenticated header", async () => {
    const result = await getSourceCreationResolution("lookup-key", async (input, init) => {
      expect(String(input)).toBe("/api/v1/sources/idempotency");
      expect(init?.method).toBe("GET");
      expect(init?.body).toBeUndefined();
      expect(init?.credentials).toBe("same-origin");
      expect(init?.cache).toBe("no-store");
      const headers = new Headers(init?.headers);
      expect(headers.get("idempotency-key")).toBe("lookup-key");
      expect(headers.has("content-type")).toBe(false);
      return Response.json({ status: "missing" }, { headers: { "cache-control": "no-store" } });
    });

    expect(result).toEqual({ ok: true, value: { kind: "status", status: "missing" } });
  });

  it("accepts a case-insensitive no-store directive from combined Fetch headers", async () => {
    const headers = new Headers();
    headers.append("Cache-Control", "private");
    headers.append("cache-control", "No-Store");
    expect(headers.get("cache-control")).toBe("private, No-Store");

    const result = await getSourceCreationResolution("lookup-key", async () =>
      Response.json({ status: "missing" }, { headers }),
    );

    expect(result).toEqual({ ok: true, value: { kind: "status", status: "missing" } });
  });

  it("strictly distinguishes successful and failed stored replays", async () => {
    const completed = await getSourceCreationResolution("completed-key", async () =>
      Response.json(sourceFixture(), {
        status: 201,
        headers: {
          "cache-control": "no-store",
          "idempotency-replayed": "true",
        },
      }),
    );
    const failed = await getSourceCreationResolution("failed-key", async () =>
      Response.json(
        {
          error: {
            code: "invalid_source",
            message: "The source is invalid.",
            requestId: "failed-request",
          },
        },
        {
          status: 422,
          headers: {
            "cache-control": "no-store",
            "idempotency-replayed": "true",
          },
        },
      ),
    );

    expect(completed.ok && completed.value.kind).toBe("replay");
    expect(completed.ok && completed.value.kind === "replay" && completed.value.result.ok).toBe(
      true,
    );
    expect(failed).toEqual({
      ok: true,
      value: {
        kind: "replay",
        result: {
          ok: false,
          error: new ApiError({
            code: "invalid_source",
            displayMessage: "The source is invalid.",
            requestId: "failed-request",
            status: 422,
          }),
        },
      },
    });
  });

  it("accepts failed replays only for HTTP error statuses across every source path", async () => {
    const input = {
      kind: "graphql" as const,
      displayName: "GraphQL",
      endpoint: "https://api.example.test/graphql",
    };
    const invalidStatuses = [199, 200, 204, 302, 399, 600] as const;
    const authoritativeStatuses = [400, 599] as const;

    function failedReplayResponse(status: number) {
      const nativeStatus = status < 200 ? 200 : status > 599 ? 599 : status;
      const init = {
        status: nativeStatus,
        headers: {
          "cache-control": "no-store",
          "idempotency-replayed": "true",
        },
      };
      const response =
        nativeStatus === 204
          ? new Response(null, init)
          : Response.json(
              {
                error: {
                  code: "internal_error",
                  message: "The stored source creation failed.",
                  requestId: `failed-${status}`,
                },
              },
              init,
            );
      if (nativeStatus !== status) Object.defineProperty(response, "status", { value: status });
      return response;
    }

    for (const status of invalidStatuses) {
      const direct = await createGraphqlSource(input, `direct-${status}`, async () =>
        failedReplayResponse(status),
      );
      const lookup = await getSourceCreationResolution(`lookup-${status}`, async () =>
        failedReplayResponse(status),
      );
      const seal = await sealMissingSourceCreation(`seal-${status}`, async () =>
        failedReplayResponse(status),
      );

      expect(direct.ok).toBe(false);
      expect(direct.replayProvenance).toBe("invalid");
      for (const result of [lookup, seal]) {
        expect(result).toMatchObject({
          ok: false,
          error: { code: "invalid_response" },
        });
      }
    }

    for (const status of authoritativeStatuses) {
      const direct = await createGraphqlSource(input, `direct-${status}`, async () =>
        failedReplayResponse(status),
      );
      const lookup = await getSourceCreationResolution(`lookup-${status}`, async () =>
        failedReplayResponse(status),
      );
      const seal = await sealMissingSourceCreation(`seal-${status}`, async () =>
        failedReplayResponse(status),
      );

      expect(direct.ok).toBe(false);
      expect(direct.replayProvenance).toBe("authoritative");
      for (const result of [lookup, seal]) {
        expect(result).toMatchObject({
          ok: true,
          value: {
            kind: "replay",
            result: { ok: false, error: { code: "internal_error", status } },
          },
        });
      }
    }
  });

  it("seals with no body and validates the in-progress retry contract", async () => {
    document.cookie = "executor_csrf=seal_csrf; Path=/";
    const result = await sealMissingSourceCreation("seal-key", async (input, init) => {
      expect(String(input)).toBe("/api/v1/sources/idempotency/seal");
      expect(init?.method).toBe("POST");
      expect(init?.body).toBeUndefined();
      expect(init?.credentials).toBe("same-origin");
      expect(init?.cache).toBe("no-store");
      const headers = new Headers(init?.headers);
      expect(headers.get("idempotency-key")).toBe("seal-key");
      expect(headers.get("x-executor-csrf")).toBe("seal_csrf");
      expect(headers.has("content-type")).toBe(false);
      return Response.json(
        {
          error: {
            code: "idempotency_in_progress",
            message: "Source creation is still in progress.",
            requestId: "seal-request",
          },
        },
        {
          status: 409,
          headers: { "cache-control": "no-store", "retry-after": "1" },
        },
      );
    });

    expect(result).toEqual({ ok: true, value: { kind: "status", status: "in_progress" } });
  });

  it("normalizes terminal seal races without treating them as transport failures", async () => {
    const result = await sealMissingSourceCreation("expired-key", async () =>
      Response.json(
        {
          error: {
            code: "idempotency_expired_unknown",
            message: "The record expired.",
            requestId: "expired-request",
          },
        },
        { status: 410, headers: { "cache-control": "no-store" } },
      ),
    );

    expect(result).toEqual({
      ok: true,
      value: { kind: "status", status: "expired_unknown" },
    });
  });

  it("rejects malformed source creation status metadata", async () => {
    const missingNoStore = await getSourceCreationResolution("key", async () =>
      Response.json({ status: "missing" }),
    );
    const unknownStatus = await getSourceCreationResolution("key", async () =>
      Response.json({ status: "completed" }, { headers: { "cache-control": "no-store" } }),
    );
    const invalidReplayHeader = await getSourceCreationResolution("key", async () =>
      Response.json(sourceFixture(), {
        status: 201,
        headers: {
          "cache-control": "no-store",
          "idempotency-replayed": "false",
        },
      }),
    );
    const invalidReplayStatus = await getSourceCreationResolution("key", async () =>
      Response.json(sourceFixture(), {
        status: 200,
        headers: {
          "cache-control": "no-store",
          "idempotency-replayed": "true",
        },
      }),
    );
    const missingRetryAfter = await sealMissingSourceCreation("key", async () =>
      Response.json(
        {
          error: {
            code: "idempotency_in_progress",
            message: "Still running.",
            requestId: "request",
          },
        },
        { status: 409, headers: { "cache-control": "no-store" } },
      ),
    );

    for (const result of [
      missingNoStore,
      unknownStatus,
      invalidReplayHeader,
      invalidReplayStatus,
      missingRetryAfter,
    ]) {
      expect(result.ok).toBe(false);
      expect(!result.ok && result.error.code).toBe("invalid_response");
    }
  });

  it("rejects excess properties in lookup and seal status responses", async () => {
    const lookup = await getSourceCreationResolution("key", async () =>
      Response.json(
        { status: "missing", outcome: "completed" },
        { headers: { "cache-control": "no-store" } },
      ),
    );
    const seal = await sealMissingSourceCreation("key", async () =>
      Response.json(
        { status: "missing", outcome: "completed" },
        { headers: { "cache-control": "no-store" } },
      ),
    );

    for (const result of [lookup, seal]) {
      expect(result.ok).toBe(false);
      expect(!result.ok && result.error.code).toBe("invalid_response");
    }
  });

  it("keeps token list responses masked", async () => {
    const tokens = await listTokens(async () =>
      Response.json({
        tokens: [
          {
            id: "token-id",
            name: "Laptop",
            maskedToken: "exr_abcd...wxyz",
            createdAt: 123,
            lastUsedAt: null,
            revokedAt: null,
          },
        ],
      }),
    );

    expect(tokens).toEqual({
      ok: true,
      value: [
        {
          id: "token-id",
          name: "Laptop",
          maskedToken: "exr_abcd...wxyz",
          createdAt: 123,
          lastUsedAt: null,
          revokedAt: null,
        },
      ],
    });
  });

  it("preserves the stable server error envelope", async () => {
    const failure = await getBootstrap(async () =>
      Response.json(
        {
          error: {
            code: "unauthorized",
            message: "An administrator session is required.",
            requestId: "request-body",
          },
        },
        { status: 401, headers: { "x-request-id": "request-header" } },
      ),
    );

    expect(failure).toEqual({
      ok: false,
      error: new ApiError({
        code: "unauthorized",
        displayMessage: "An administrator session is required.",
        requestId: "request-body",
        status: 401,
      }),
    });
  });

  it("uses a response request ID when an error body is malformed", async () => {
    const failure = await getBootstrap(
      async () =>
        new Response("upstream exploded", {
          status: 502,
          headers: { "x-request-id": "request-header" },
        }),
    );

    expect(failure).toEqual({
      ok: false,
      error: new ApiError({
        code: "http_502",
        displayMessage: "Executor could not complete the request.",
        requestId: "request-header",
        status: 502,
      }),
    });
  });

  it("reports successful payloads that drift from the Rust DTO", async () => {
    const failure = await getBootstrap(async () =>
      Response.json(
        { setupRequired: "yes", authenticated: false },
        { headers: { "x-request-id": "request-invalid" } },
      ),
    );

    expect(failure).toEqual({
      ok: false,
      error: new ApiError({
        code: "invalid_response",
        displayMessage: "Executor returned a response the dashboard could not understand.",
        requestId: "request-invalid",
        status: 502,
      }),
    });
  });

  it("strictly decodes source and tool catalog snapshots", async () => {
    const sources = await listSources(async () =>
      Response.json({ sources: [sourceFixture()], catalogRevision: 12 }),
    );
    const tools = await listTools(
      {
        query: "repos & teams",
        sourceId: "source/one",
        mode: "ask",
        includeTombstoned: true,
        limit: 50,
        offset: 100,
      },
      async (input) => {
        expect(String(input)).toBe(
          "/api/v1/tools?query=repos+%26+teams&sourceId=source%2Fone&mode=ask&includeTombstoned=true&limit=50&offset=100",
        );
        return Response.json({
          items: [toolFixture()],
          total: 1,
          hasMore: false,
          nextOffset: null,
          catalogRevision: 12,
        });
      },
    );

    expect(sources.ok && sources.value.sources[0]?.kind).toBe("openapi");
    expect(tools.ok && tools.value.items[0]?.effectiveMode.provenance).toBe("intrinsic");
  });

  it("rejects catalog enum drift instead of trusting response JSON", async () => {
    const source = sourceFixture();
    const result = await listSources(async () =>
      Response.json(
        { sources: [{ ...source, healthStatus: "mostly_fine" }], catalogRevision: 12 },
        { headers: { "x-request-id": "request-invalid-catalog" } },
      ),
    );

    expect(result).toEqual({
      ok: false,
      error: new ApiError({
        code: "invalid_response",
        displayMessage: "Executor returned a response the dashboard could not understand.",
        requestId: "request-invalid-catalog",
        status: 502,
      }),
    });
  });

  it("strips nested private source configuration before it enters browser state", async () => {
    const secret = "nested-source-secret";
    const result = await listSources(async () =>
      Response.json({
        sources: [
          {
            ...sourceFixture(),
            kind: "mcp_http",
            configuration: {
              endpoint: "https://mcp.example.test/mcp",
              allowPrivateNetwork: false,
              sessionId: secret,
              query: `token=${secret}`,
              headers: { authorization: secret },
              env: { TOKEN: secret },
              stderr: secret,
              command: secret,
            },
          },
        ],
        catalogRevision: 12,
      }),
    );

    expect(result.ok && result.value.sources[0]?.configuration).toEqual({
      endpoint: "https://mcp.example.test",
      allowPrivateNetwork: false,
    });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("sends source and current-page bulk revisions exactly once", async () => {
    const bodies: unknown[] = [];
    await setSourceMode("source/1", "ask", 7, async (input, init) => {
      expect(String(input)).toBe("/api/v1/sources/source%2F1/mode");
      bodies.push(decodeJson(String(init?.body)));
      return Response.json({ ...sourceFixture(), modeOverride: "ask", revision: 8 });
    });
    await bulkSetToolModes(["tool-1", "tool-2"], "disabled", 19, async (_input, init) => {
      bodies.push(decodeJson(String(init?.body)));
      return Response.json({
        updatedCount: 2,
        catalogRevision: 20,
        sourceRevisions: { "source-1": 9 },
      });
    });

    expect(bodies).toEqual([
      { mode: "ask", expectedRevision: 7 },
      {
        selection: {
          type: "tool_ids",
          toolIds: ["tool-1", "tool-2"],
          expectedCatalogRevision: 19,
        },
        mode: "disabled",
      },
    ]);
  });

  it("preserves revision conflicts for review instead of retrying", async () => {
    const result = await setSourceMode("source-1", "enabled", 2, async () =>
      Response.json(
        {
          error: {
            code: "revision_conflict",
            message: "The source changed.",
            requestId: "request-conflict",
          },
        },
        { status: 409 },
      ),
    );

    expect(result).toEqual({
      ok: false,
      error: new ApiError({
        code: "revision_conflict",
        displayMessage: "The source changed.",
        requestId: "request-conflict",
        status: 409,
      }),
    });
  });

  it("keeps request-log state metadata-only even if a server adds secret fields", async () => {
    const secret = "secret-sentinel-never-render";
    const result = await listRequestLogs(null, async (input) => {
      expect(String(input)).toBe("/api/v1/request-logs?limit=50");
      return Response.json({
        items: [
          {
            ...logFixture(),
            requestBody: secret,
            responseBody: secret,
            headers: { authorization: secret },
            credential: secret,
            token: secret,
          },
        ],
        nextCursor: "older",
      });
    });

    expect(result.ok).toBe(true);
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(result.ok && Object.keys(result.value.items[0] ?? {})).toEqual([
      "requestId",
      "actorApiTokenId",
      "surface",
      "sourceId",
      "toolId",
      "pathSnapshot",
      "outcome",
      "errorCode",
      "durationMs",
      "approvalId",
      "createdAt",
    ]);
  });

  it("previews an OpenAPI URL with strict tool metadata", async () => {
    let body: unknown;
    const result = await previewOpenApiSource(
      { type: "url", url: "https://api.example.test/openapi.json" },
      false,
      async (input, init) => {
        expect(String(input)).toBe("/api/v1/sources/openapi/preview");
        body = decodeJson(String(init?.body));
        return Response.json({
          title: "Example API",
          description: null,
          toolCount: 1,
          tools: [
            {
              preferredName: "list_widgets",
              displayName: "List widgets",
              description: "Lists widgets",
              intrinsicMode: "enabled",
              security: [["bearerAuth"]],
            },
          ],
          securitySchemes: [
            {
              name: "bearerAuth",
              credentialType: "bearer",
              placement: "header",
              supported: true,
              oauthFlows: null,
            },
          ],
        });
      },
    );

    expect(body).toEqual({
      spec: { type: "url", url: "https://api.example.test/openapi.json" },
      allowPrivateNetwork: false,
    });
    expect(result.ok && result.value.tools[0]?.intrinsicMode).toBe("enabled");
    expect(result.ok && result.value.securitySchemes[0]?.name).toBe("bearerAuth");
  });

  it("imports credentials without accepting secret echoes in the source response", async () => {
    const secret = "source-secret-sentinel";
    let body: unknown;
    const result = await createOpenApiSource(
      {
        kind: "openapi",
        displayName: "Example API",
        spec: { type: "inline", content: "openapi: 3.1.0" },
        credential: {
          schemes: { bearerAuth: { type: "bearer", token: secret } },
        },
      },
      "openapi-import-key",
      async (input, init) => {
        expect(String(input)).toBe("/api/v1/sources");
        expect(init?.method).toBe("POST");
        body = decodeJson(String(init?.body));
        return Response.json({ ...sourceFixture(), credentials: secret }, { status: 201 });
      },
    );

    expect(JSON.stringify(body)).toContain(secret);
    expect(result.ok).toBe(true);
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("creates an MCP HTTP source and strips unrecognized connection secrets", async () => {
    let body: unknown;
    const result = await createMcpHttpSource(
      {
        kind: "mcp_http",
        displayName: "Issue tracker",
        description: "Local issue tools",
        endpoint: "https://mcp.example.test/rpc?tenant=private",
        allowPrivateNetwork: false,
      },
      "mcp-http-create-key",
      async (input, init) => {
        expect(String(input)).toBe("/api/v1/sources");
        body = decodeJson(String(init?.body));
        return Response.json(
          {
            ...sourceFixture(),
            kind: "mcp_http",
            displayName: "Issue tracker",
            configuration: {
              endpoint: "https://mcp.example.test/rpc",
              allowPrivateNetwork: false,
            },
            sessionId: "upstream-session-secret",
            authorization: "Bearer source-secret",
          },
          { status: 201 },
        );
      },
    );

    expect(body).toEqual({
      kind: "mcp_http",
      displayName: "Issue tracker",
      description: "Local issue tools",
      endpoint: "https://mcp.example.test/rpc?tenant=private",
      allowPrivateNetwork: false,
    });
    expect(result.ok && result.value.kind).toBe("mcp_http");
    expect(JSON.stringify(result)).not.toContain("upstream-session-secret");
    expect(JSON.stringify(result)).not.toContain("source-secret");
  });

  it("sends every supported initial MCP HTTP credential directly on source create", async () => {
    const credentials = [
      { type: "bearer", token: "bearer-secret" },
      { type: "basic", username: "admin", password: "password-secret" },
      { type: "api_key_header", name: "X-Service-Key", value: "header-secret" },
      { type: "oauth_access_token", accessToken: "oauth-secret" },
    ] as const;
    const bodies: unknown[] = [];

    for (const credential of credentials) {
      await createMcpHttpSource(
        {
          kind: "mcp_http",
          displayName: "Authenticated MCP",
          endpoint: "https://mcp.example.test/mcp",
          credential,
        },
        `mcp-http-credential-${credential.type}`,
        async (_input, init) => {
          bodies.push(decodeJson(String(init?.body)));
          return Response.json({
            ...sourceFixture(),
            kind: "mcp_http",
            configuration: {
              endpoint: "https://mcp.example.test/mcp",
              allowPrivateNetwork: false,
            },
          });
        },
      );
    }

    expect(bodies).toEqual(
      credentials.map((credential) => ({
        kind: "mcp_http",
        displayName: "Authenticated MCP",
        endpoint: "https://mcp.example.test/mcp",
        credential,
      })),
    );
  });

  it("creates GraphQL sources with the flattened credential contract and redacted public endpoint", async () => {
    const secret = "graphql-query-secret";
    let body: unknown;
    const result = await createGraphqlSource(
      {
        kind: "graphql",
        displayName: "Product API",
        preferredSlug: "product",
        endpoint: `https://api.example.test/graphql?token=${secret}`,
        allowPrivateNetwork: false,
        credential: { type: "bearer", token: "bearer-secret" },
      },
      "graphql-create-key",
      async (input, init) => {
        expect(String(input)).toBe("/api/v1/sources");
        body = decodeJson(String(init?.body));
        return Response.json(
          {
            ...sourceFixture(),
            kind: "graphql",
            slug: "product",
            displayName: "Product API",
            configuration: {
              endpoint: `https://api.example.test/graphql?token=${secret}`,
              allowPrivateNetwork: false,
              encryptedEndpoint: secret,
            },
          },
          { status: 201 },
        );
      },
    );

    expect(body).toEqual({
      kind: "graphql",
      displayName: "Product API",
      preferredSlug: "product",
      endpoint: `https://api.example.test/graphql?token=${secret}`,
      allowPrivateNetwork: false,
      credential: { type: "bearer", token: "bearer-secret" },
    });
    expect(result.ok && result.value.configuration).toEqual({
      endpoint: "https://api.example.test",
      allowPrivateNetwork: false,
    });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(JSON.stringify(result)).not.toContain("bearer-secret");
  });

  it("strips path credentials from source endpoints before browser state", async () => {
    const pathSecret = "path-secret-never-render";
    const result = await listSources(async () =>
      Response.json({
        sources: [
          {
            ...sourceFixture(),
            kind: "graphql",
            configuration: {
              endpoint: `https://api.example.test/graphql/${pathSecret}`,
              allowPrivateNetwork: false,
            },
          },
        ],
        catalogRevision: 12,
      }),
    );

    expect(result.ok && result.value.sources[0]?.configuration.endpoint).toBe(
      "https://api.example.test",
    );
    expect(JSON.stringify(result)).not.toContain(pathSecret);
  });

  it("lists trusted stdio templates without decoding raw process configuration", async () => {
    const secret = "raw-process-secret";
    const result = await listMcpStdioTemplates(async (input) => {
      expect(String(input)).toBe("/api/v1/mcp/stdio/templates");
      return Response.json({
        templates: [
          {
            name: "github-local",
            secretFields: ["GITHUB_TOKEN"],
            command: "/usr/local/bin/private-server",
            args: ["--token", secret],
            env: { TOKEN: secret },
          },
        ],
      });
    });

    expect(result).toEqual({
      ok: true,
      value: { templates: [{ name: "github-local", secretFields: ["GITHUB_TOKEN"] }] },
    });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(JSON.stringify(result)).not.toContain("private-server");
  });

  it("creates a trusted stdio source without accepting a secret echo", async () => {
    const secret = " whitespace-sensitive-secret ";
    let body: unknown;
    const result = await createMcpStdioSource(
      {
        kind: "mcp_stdio",
        displayName: "Local GitHub",
        templateName: "github-local",
        secretValues: { GITHUB_TOKEN: secret },
      },
      "mcp-stdio-create-key",
      async (input, init) => {
        expect(String(input)).toBe("/api/v1/sources");
        expect(init?.method).toBe("POST");
        body = decodeJson(String(init?.body));
        return Response.json({
          ...sourceFixture(),
          kind: "mcp_stdio",
          configuration: { templateName: "github-local" },
          secretValues: { GITHUB_TOKEN: secret },
        });
      },
    );

    expect(body).toEqual({
      kind: "mcp_stdio",
      displayName: "Local GitHub",
      templateName: "github-local",
      secretValues: { GITHUB_TOKEN: secret },
    });
    expect(result.ok && result.value.configuration).toEqual({ templateName: "github-local" });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("reads MCP credential metadata and sends protocol-specific CAS replacements", async () => {
    const reads = await getSourceCredentials("mcp/source", async (input) => {
      expect(String(input)).toBe("/api/v1/sources/mcp%2Fsource/credentials");
      return Response.json({
        revision: 7,
        configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
      });
    });
    const bodies: unknown[] = [];
    await putMcpHttpCredentials(
      "http-source",
      4,
      {
        credential: { type: "api_key_header", name: "X-Service-Key", value: "secret" },
      },
      async (_input, init) => {
        bodies.push(decodeJson(String(init?.body)));
        return Response.json({
          revision: 5,
          configuredSchemes: [{ name: "authorization", credentialType: "api_key_header" }],
        });
      },
    );
    await putMcpStdioCredentials(
      "stdio-source",
      7,
      { secretValues: { TOKEN: " exact secret " } },
      async (_input, init) => {
        bodies.push(decodeJson(String(init?.body)));
        return Response.json({
          revision: 8,
          configuredSchemes: [{ name: "TOKEN", credentialType: "secret_env" }],
        });
      },
    );

    expect(reads.ok && reads.value.revision).toBe(7);
    expect(bodies).toEqual([
      {
        expectedRevision: 4,
        credential: {
          credential: { type: "api_key_header", name: "X-Service-Key", value: "secret" },
        },
      },
      {
        expectedRevision: 7,
        credential: { secretValues: { TOKEN: " exact secret " } },
      },
    ]);
  });

  it("sends GraphQL replacement and clear credentials without an extra envelope", async () => {
    const bodies: unknown[] = [];
    await putGraphqlCredentials(
      "graphql/source",
      7,
      { type: "api_key_header", name: "X-Service-Key", value: " exact secret " },
      async (input, init) => {
        expect(String(input)).toBe("/api/v1/sources/graphql%2Fsource/credentials");
        bodies.push(decodeJson(String(init?.body)));
        return Response.json({
          revision: 8,
          configuredSchemes: [{ name: "default", credentialType: "api_key_header" }],
        });
      },
    );
    await putGraphqlCredentials("graphql/source", 8, null, async (_input, init) => {
      bodies.push(decodeJson(String(init?.body)));
      return Response.json({ revision: 9, configuredSchemes: [] });
    });

    expect(bodies).toEqual([
      {
        expectedRevision: 7,
        credential: {
          type: "api_key_header",
          name: "X-Service-Key",
          value: " exact secret ",
        },
      },
      { expectedRevision: 8, credential: null },
    ]);
  });

  it("strictly decodes managed OAuth metadata and sends credential-keyed CAS operations", async () => {
    const secret = "oauth-secret-never-decode";
    const connection = {
      id: "connection-1",
      credentialKey: "oauth/scheme",
      revision: 4,
      status: "connected",
      issuer: "https://identity.example.test/",
      clientId: "executor-client",
      clientAuthMethod: "client_secret_basic",
      callbackUrl: "https://executor.example.test/api/v1/oauth/callback/connection-1",
      requestedScopes: ["read"],
      grantedScopes: ["read"],
      hasClientSecret: true,
      hasRefreshToken: true,
      accessExpiresAt: 900,
      authorizedAt: 100,
      lastRefreshedAt: 200,
      errorCode: null,
      managedOAuthEligible: true,
    } as const;
    const listed = await listOAuthConnections("source/1", async (input) => {
      expect(String(input)).toBe("/api/v1/sources/source%2F1/oauth");
      return Response.json({
        connections: [
          {
            ...connection,
            managedOAuthEligible: false,
            accessToken: secret,
            clientSecret: secret,
          },
        ],
        availableCredentials: [
          {
            credentialKey: "oauth/scheme",
            protocol: "openapi",
            requestedScopes: ["read"],
            managedOAuthEligible: true,
            providerMetadata: secret,
          },
        ],
        tokenResponse: secret,
      });
    });
    expect(listed.ok).toBe(true);
    expect(listed.ok && listed.value.connections[0]?.managedOAuthEligible).toBe(false);
    expect(JSON.stringify(listed)).not.toContain(secret);

    const bodies: unknown[] = [];
    const saveInput = {
      expectedRevision: 4,
      discovery: { type: "issuer" as const, issuer: "https://identity.example.test/" },
      client: {
        clientId: "executor-client",
        authentication: "client_secret_basic" as const,
        clientSecret: { action: "preserve" as const },
      },
      scopes: ["read"],
    };
    await putOAuthConnection("source/1", "oauth/scheme", saveInput, async (input, init) => {
      expect(String(input)).toBe("/api/v1/sources/source%2F1/oauth/oauth%2Fscheme");
      bodies.push(decodeJson(String(init?.body)));
      return Response.json({ ...connection, revision: 5 });
    });
    await authorizeOAuthConnection(
      "source/1",
      "oauth/scheme",
      { expectedRevision: 5 },
      async (input, init) => {
        expect(String(input)).toBe("/api/v1/sources/source%2F1/oauth/oauth%2Fscheme/authorize");
        bodies.push(decodeJson(String(init?.body)));
        return Response.json({
          authorizationUrl: "https://identity.example.test/authorize?state=opaque",
          state: secret,
        });
      },
    );
    const disconnected = await disconnectOAuthConnection(
      "source/1",
      "oauth/scheme",
      { expectedRevision: 5 },
      async (input, init) => {
        expect(String(input)).toBe("/api/v1/sources/source%2F1/oauth/oauth%2Fscheme/disconnect");
        bodies.push(decodeJson(String(init?.body)));
        return Response.json({
          ...connection,
          revision: 6,
          status: "ready_to_connect",
          managedOAuthEligible: false,
        });
      },
    );
    expect(disconnected.ok && disconnected.value.managedOAuthEligible).toBe(false);
    await deleteOAuthConnection(
      "source/1",
      "oauth/scheme",
      { expectedRevision: 6 },
      async (input, init) => {
        expect(String(input)).toBe(
          "/api/v1/sources/source%2F1/oauth/oauth%2Fscheme?expectedRevision=6",
        );
        expect(init?.method).toBe("DELETE");
        return new Response(null, { status: 204 });
      },
    );
    expect(bodies).toEqual([saveInput, { expectedRevision: 5 }, { expectedRevision: 5 }]);
  });

  it("decodes OpenAPI refresh counts", async () => {
    const result = await refreshOpenApiSource("source/1", async (input, init) => {
      expect(String(input)).toBe("/api/v1/sources/source%2F1/refresh");
      expect(init?.body).toBe("{}");
      return Response.json({
        sourceId: "source/1",
        sourceRevision: 4,
        catalogRevision: 9,
        globalRevision: 13,
        activeToolCount: 6,
        tombstonedToolCount: 2,
      });
    });

    expect(result.ok && result.value.activeToolCount).toBe(6);
  });

  it("reads and replaces only credential metadata and sends CAS revisions", async () => {
    const metadata = {
      revision: 4,
      configuredSchemes: [{ name: "bearerAuth", credentialType: "bearer" }],
    };
    const read = await getOpenApiCredentials("source-1", async () => Response.json(metadata));
    let putBody: unknown;
    const replaced = await putOpenApiCredentials(
      "source-1",
      4,
      { oauth: { type: "oauth_access_token", access_token: "secret-token" } },
      async (_input, init) => {
        putBody = decodeJson(String(init?.body));
        return Response.json({
          revision: 5,
          configuredSchemes: [{ name: "oauth", credentialType: "manual_oauth_access_token" }],
        });
      },
    );

    expect(read).toEqual({ ok: true, value: metadata });
    expect(putBody).toEqual({
      expectedRevision: 4,
      credential: {
        schemes: { oauth: { type: "oauth_access_token", access_token: "secret-token" } },
      },
    });
    expect(replaced.ok && replaced.value.revision).toBe(5);
  });

  it("clears credentials with an encoded CAS query", async () => {
    const result = await deleteOpenApiCredentials("source/1", 5, async (input, init) => {
      expect(String(input)).toBe("/api/v1/sources/source%2F1/credentials?expectedRevision=5");
      expect(init?.method).toBe("DELETE");
      return Response.json({ revision: 6, configuredSchemes: [] });
    });

    expect(result.ok && result.value.configuredSchemes).toEqual([]);
  });

  it("lists and reads strict approval DTOs without retaining secret extras", async () => {
    const secret = "approval-secret-sentinel";
    const list = await listApprovals(
      { status: "pending", cursor: "older/page", limit: 50 },
      async (input) => {
        expect(String(input)).toBe("/api/v1/approvals?limit=50&status=pending&cursor=older%2Fpage");
        return Response.json({
          items: [
            {
              ...approvalSummaryFixture(),
              sourceDisplayName: null,
              toolDisplayName: null,
              actorKind: "system",
              actorId: "local_cli",
              actorName: null,
              actorLabel: "Local CLI",
              actorApiTokenId: null,
              actorTokenName: null,
              rawArguments: { password: secret },
              encryptedArguments: secret,
              credential: secret,
            },
          ],
          nextCursor: "next",
          internalKey: secret,
        });
      },
    );
    const detail = await getApproval("approval/1", async (input) => {
      expect(String(input)).toBe("/api/v1/approvals/approval%2F1");
      return Response.json({
        ...approvalDetailFixture(),
        rawArguments: { password: secret },
        encryptedArguments: secret,
        result: secret,
      });
    });

    expect(list.ok).toBe(true);
    expect(detail.ok).toBe(true);
    expect(JSON.stringify(list)).not.toContain(secret);
    expect(JSON.stringify(detail)).not.toContain(secret);
    expect(list.ok && list.value.items[0]?.sourceDisplayName).toBeNull();
    expect(list.ok && list.value.items[0]?.toolDisplayName).toBeNull();
    expect(list.ok && list.value.items[0]?.actorTokenName).toBeNull();
    expect(list.ok && list.value.items[0]?.actorKind).toBe("system");
    expect(list.ok && list.value.items[0]?.actorLabel).toBe("Local CLI");
    expect(list.ok && list.value.items[0]?.actorApiTokenId).toBeNull();
    expect(detail.ok && detail.value.redactedArguments).toEqual({
      title: "Issue title",
      body: "[REDACTED]",
    });
  });

  it("omits the approval status parameter for an all-status list", async () => {
    await listApprovals({ status: null, cursor: null, limit: 50 }, async (input) => {
      expect(String(input)).toBe("/api/v1/approvals?limit=50");
      return Response.json({ items: [], nextCursor: null });
    });
  });

  it("sends approval decisions once with the viewed CAS revision", async () => {
    document.cookie = "executor_csrf=approval_csrf; Path=/";
    let calls = 0;
    let body: unknown;
    let csrf: string | null = null;
    const result = await decideApproval("approval/1", "approve", 4, async (input, init) => {
      calls += 1;
      expect(String(input)).toBe("/api/v1/approvals/approval%2F1/decision");
      expect(init?.method).toBe("POST");
      body = decodeJson(String(init?.body));
      csrf = new Headers(init?.headers).get("x-executor-csrf");
      return Response.json({
        ...approvalDetailFixture(),
        status: "approved",
        revision: 5,
        decidedAt: 150,
      });
    });

    expect(calls).toBe(1);
    expect(body).toEqual({ decision: "approve", expectedRevision: 4 });
    expect(csrf).toBe("approval_csrf");
    expect(result.ok && result.value.status).toBe("approved");
  });

  it("preserves an approval conflict for refetch and review without retrying", async () => {
    let calls = 0;
    const result = await decideApproval("approval-1", "deny", 4, async () => {
      calls += 1;
      return Response.json(
        {
          error: {
            code: "revision_conflict",
            message: "The approval changed.",
            requestId: "request-conflict",
          },
        },
        { status: 409 },
      );
    });

    expect(calls).toBe(1);
    expect(result).toEqual({
      ok: false,
      error: new ApiError({
        code: "revision_conflict",
        displayMessage: "The approval changed.",
        requestId: "request-conflict",
        status: 409,
      }),
    });
  });
});
