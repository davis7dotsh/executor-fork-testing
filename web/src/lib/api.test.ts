import { describe, expect, it } from "@effect/vitest";
import { Schema } from "effect";
import {
  ApiError,
  bulkSetToolModes,
  createOpenApiSource,
  createToken,
  decideApproval,
  deleteOpenApiCredentials,
  getApproval,
  getOpenApiCredentials,
  getBootstrap,
  listApprovals,
  listRequestLogs,
  listSources,
  listTokens,
  listTools,
  loginAdmin,
  previewOpenApiSource,
  putOpenApiCredentials,
  refreshOpenApiSource,
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
    const created = await createToken("Laptop", async (_input, init) => {
      observedHeaders = new Headers(init?.headers);
      observedCredentials = init?.credentials;
      return Response.json(
        {
          id: "token-id",
          name: "Laptop",
          token: "exr_secret",
          createdAt: 123,
        },
        { status: 201 },
      );
    });

    expect(observedHeaders.get("x-executor-csrf")).toBe("csrf_test_value");
    expect(observedHeaders.get("content-type")).toBe("application/json");
    expect(observedCredentials).toBe("same-origin");
    expect(created).toEqual({
      ok: true,
      value: {
        id: "token-id",
        name: "Laptop",
        token: "exr_secret",
        createdAt: 123,
      },
    });
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
      async (_input, init) => {
        body = decodeJson(String(init?.body));
        return Response.json({ ...sourceFixture(), credentials: secret }, { status: 201 });
      },
    );

    expect(JSON.stringify(body)).toContain(secret);
    expect(result.ok).toBe(true);
    expect(JSON.stringify(result)).not.toContain(secret);
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
