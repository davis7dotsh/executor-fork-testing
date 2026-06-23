import { describe, expect, it } from "@effect/vitest";
import { ApiError, createToken, getBootstrap, listTokens, loginAdmin } from "./api";

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
});
