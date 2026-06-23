import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { ApiError } from "./api";
import { createAuthState } from "./auth.svelte";

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("dashboard auth state", () => {
  it("hydrates an authenticated administrator session", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ setupRequired: false, authenticated: true }))
      .mockResolvedValueOnce(Response.json({ username: "admin", csrfToken: null }));
    vi.stubGlobal("fetch", fetcher);

    const auth = createAuthState();
    await auth.refresh();

    expect(auth.phase).toBe("ready");
    expect(auth.setupRequired).toBe(false);
    expect(auth.authenticated).toBe(true);
    expect(auth.username).toBe("admin");
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("claims first boot and immediately establishes the session", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ username: "admin", csrfToken: null }, { status: 201 }))
      .mockResolvedValueOnce(Response.json({ username: "admin", csrfToken: "csrf_fresh" }));
    vi.stubGlobal("fetch", fetcher);

    const auth = createAuthState();
    const result = await auth.completeSetup({
      setupToken: "set_secret",
      username: "admin",
      password: "long-enough-password",
    });

    expect(result.ok).toBe(true);
    expect(auth.setupRequired).toBe(false);
    expect(auth.authenticated).toBe(true);
    expect(auth.username).toBe("admin");
    expect(auth.notice).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it("does not let an older refresh overwrite a successful sign-in", async () => {
    const bootstrap = deferred<Response>();
    const fetcher = vi.fn<typeof fetch>((input, init) => {
      if (String(input) === "/api/v1/session" && init?.method === "POST") {
        return Promise.resolve(Response.json({ username: "admin", csrfToken: "csrf_fresh" }));
      }
      return bootstrap.promise;
    });
    vi.stubGlobal("fetch", fetcher);

    const auth = createAuthState();
    const refreshing = auth.refresh();
    const signedIn = await auth.signIn({ username: "admin", password: "password" });
    bootstrap.resolve(Response.json({ setupRequired: false, authenticated: false }));
    await refreshing;

    expect(signedIn.ok).toBe(true);
    expect(auth.phase).toBe("ready");
    expect(auth.authenticated).toBe(true);
    expect(auth.username).toBe("admin");
  });

  it("does not let an older refresh overwrite a completed first boot", async () => {
    const bootstrap = deferred<Response>();
    const fetcher = vi.fn<typeof fetch>((input, init) => {
      if (String(input) === "/api/v1/setup") {
        return Promise.resolve(
          Response.json({ username: "admin", csrfToken: null }, { status: 201 }),
        );
      }
      if (String(input) === "/api/v1/session" && init?.method === "POST") {
        return Promise.resolve(Response.json({ username: "admin", csrfToken: "csrf_fresh" }));
      }
      return bootstrap.promise;
    });
    vi.stubGlobal("fetch", fetcher);

    const auth = createAuthState();
    const refreshing = auth.refresh();
    const setup = await auth.completeSetup({
      setupToken: "set_secret",
      username: "admin",
      password: "long-enough-password",
    });
    bootstrap.resolve(Response.json({ setupRequired: true, authenticated: false }));
    await refreshing;

    expect(setup.ok).toBe(true);
    expect(auth.setupRequired).toBe(false);
    expect(auth.authenticated).toBe(true);
  });

  it("does not let an older refresh restore a completed sign-out", async () => {
    const bootstrap = deferred<Response>();
    const fetcher = vi.fn<typeof fetch>((input, init) => {
      if (String(input) === "/api/v1/session" && init?.method === "POST") {
        return Promise.resolve(Response.json({ username: "admin", csrfToken: "csrf_fresh" }));
      }
      if (String(input) === "/api/v1/session" && init?.method === "DELETE") {
        return Promise.resolve(new Response(null, { status: 204 }));
      }
      return bootstrap.promise;
    });
    vi.stubGlobal("fetch", fetcher);

    const auth = createAuthState();
    await auth.signIn({ username: "admin", password: "password" });
    const refreshing = auth.refresh();
    const signedOut = await auth.signOut();
    bootstrap.resolve(Response.json({ setupRequired: false, authenticated: true }));
    await refreshing;

    expect(signedOut.ok).toBe(true);
    expect(auth.phase).toBe("ready");
    expect(auth.authenticated).toBe(false);
    expect(auth.username).toBeNull();
  });

  it("transitions to sign-in when an authenticated API reports an invalid CSRF token", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json({ username: "admin", csrfToken: "csrf_fresh" }));
    vi.stubGlobal("fetch", fetcher);

    const auth = createAuthState();
    await auth.signIn({ username: "admin", password: "password" });
    const recovered = auth.recoverFromApiError(
      new ApiError({
        code: "invalid_csrf",
        displayMessage: "A valid CSRF token is required.",
        requestId: "request-1",
        status: 403,
      }),
    );

    expect(recovered).toBe(true);
    expect(auth.authenticated).toBe(false);
    expect(auth.phase).toBe("ready");
    expect(auth.notice).toContain("Sign in again");
  });

  it("recovers from a session that expires between bootstrap and session lookup", async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ setupRequired: false, authenticated: true }))
      .mockResolvedValueOnce(
        Response.json(
          {
            error: {
              code: "unauthorized",
              message: "An administrator session is required.",
              requestId: "request-expired",
            },
          },
          { status: 401 },
        ),
      );
    vi.stubGlobal("fetch", fetcher);

    const auth = createAuthState();
    await auth.refresh();

    expect(auth.phase).toBe("ready");
    expect(auth.authenticated).toBe(false);
    expect(auth.notice).toContain("session expired");
  });
});
