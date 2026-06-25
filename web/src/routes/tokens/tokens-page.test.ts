import { afterEach, beforeEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/svelte";
import { Effect, Schema } from "effect";
import { TOKEN_CREATE_STORAGE_KEY, type TokenCreateEnvironment } from "$lib/token-create-lifecycle";
import TokensPageHarness from "./tokens-page.test-harness.svelte";

const PendingRecordSchema = Schema.Struct({
  version: Schema.Literal(1),
  key: Schema.String,
  name: Schema.String,
});
const decodePendingRecord = Schema.decodeUnknownSync(Schema.fromJsonString(PendingRecordSchema));
const oneTimeSecret = `exr_${"A".repeat(43)}`;

function tokenMetadata(revokedAt: number | null = null) {
  return {
    id: "token-1",
    name: "Laptop agent",
    maskedToken: "exr_••••••••1234",
    createdAt: 100,
    lastUsedAt: null,
    revokedAt,
  };
}

function createdToken(name = "Laptop agent") {
  return {
    id: "token-1",
    name,
    token: oneTimeSecret,
    createdAt: 100,
  };
}

function noStoreJson(value: unknown, init: ResponseInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("cache-control", "no-store");
  return Response.json(value, { ...init, headers });
}

function fixedEnvironment(): TokenCreateEnvironment {
  return {
    getStorage: () => window.sessionStorage,
    fillRandom: (bytes) => bytes.fill(0x5a),
  };
}

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

beforeEach(() => {
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = true;
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = false;
    },
  });
});

afterEach(() => {
  cleanup();
  window.sessionStorage.clear();
  vi.unstubAllGlobals();
});

describe("API token page delivery safety", () => {
  it("replays a lost first response with the exact persisted request and never stores the secret", async () => {
    let listCalls = 0;
    const creates: Array<{ key: string | null; body: string; keyHeaderCount: number }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/tokens" && init?.method === "POST") {
          const headers = new Headers(init.headers);
          creates.push({
            key: headers.get("idempotency-key"),
            body: String(init.body),
            keyHeaderCount: [...headers.keys()].filter((name) => name === "idempotency-key").length,
          });
          if (creates.length === 1) return Effect.runPromise(Effect.fail("response lost"));
          return Promise.resolve(
            noStoreJson(createdToken(), {
              status: 201,
              headers: { "idempotency-replayed": "true" },
            }),
          );
        }
        if (path === "/api/v1/tokens") {
          listCalls += 1;
          return Promise.resolve(
            Response.json({ tokens: listCalls === 1 ? [] : [tokenMetadata()] }),
          );
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(TokensPageHarness, { tokenCreateEnvironment: fixedEnvironment() });

    await screen.findByText("No API tokens have been issued.");
    await fireEvent.input(screen.getByLabelText("Token name"), {
      target: { value: "Laptop agent" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Create token" }));

    const secretField = await screen.findByDisplayValue(oneTimeSecret);
    const stored = window.sessionStorage.getItem(TOKEN_CREATE_STORAGE_KEY);
    expect(stored).not.toBeNull();
    expect(stored === null ? null : decodePendingRecord(stored)).toEqual({
      version: 1,
      key: "5a".repeat(32),
      name: "Laptop agent",
    });
    expect(stored).not.toContain(oneTimeSecret);
    expect(creates).toHaveLength(2);
    expect(creates[0]).toEqual(creates[1]);
    expect(creates[0]?.key).toMatch(/^[0-9a-f]{64}$/);
    expect(creates[0]?.keyHeaderCount).toBe(1);
    expect(screen.getByText(/this tab can recover the same secret/i)).toBeDefined();
    await waitFor(() => expect(secretField).toBe(document.activeElement));

    await fireEvent.click(screen.getByRole("button", { name: "I saved it" }));
    await waitFor(() => expect(window.sessionStorage.getItem(TOKEN_CREATE_STORAGE_KEY)).toBeNull());
    await waitFor(() => expect(listCalls).toBe(2));
    expect(screen.queryByDisplayValue(oneTimeSecret)).toBeNull();
  });

  it("automatically recovers a pending record after reload", async () => {
    const pending = {
      version: 1,
      key: "6".repeat(64),
      name: "Reloaded agent",
    } as const;
    window.sessionStorage.setItem(TOKEN_CREATE_STORAGE_KEY, JSON.stringify(pending));
    const creates: Array<{ key: string | null; body: string }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/tokens" && init?.method === "POST") {
          creates.push({
            key: new Headers(init.headers).get("idempotency-key"),
            body: String(init.body),
          });
          return Promise.resolve(
            noStoreJson(createdToken(pending.name), {
              status: 201,
              headers: { "idempotency-replayed": "true" },
            }),
          );
        }
        if (path === "/api/v1/tokens") {
          return Promise.resolve(Response.json({ tokens: [tokenMetadata()] }));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );

    render(TokensPageHarness, { tokenCreateEnvironment: fixedEnvironment() });

    expect(await screen.findByDisplayValue(oneTimeSecret)).toBeDefined();
    expect(creates).toEqual([
      {
        key: pending.key,
        body: JSON.stringify({ name: pending.name }),
      },
    ]);
    expect(window.sessionStorage.getItem(TOKEN_CREATE_STORAGE_KEY)).toBe(JSON.stringify(pending));
  });

  it("guards unload and sign-out while a pending request is blocked", async () => {
    let createCalls = 0;
    let logoutCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/tokens" && init?.method === "POST") {
          createCalls += 1;
          return Effect.runPromise(Effect.fail("response lost"));
        }
        if (path === "/api/v1/tokens") {
          return Promise.resolve(Response.json({ tokens: [] }));
        }
        if (path === "/api/v1/session" && init?.method === "DELETE") {
          logoutCalls += 1;
          return Promise.resolve(new Response(null, { status: 204 }));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(TokensPageHarness, { tokenCreateEnvironment: fixedEnvironment() });

    await screen.findByText("No API tokens have been issued.");
    await fireEvent.input(screen.getByLabelText("Token name"), {
      target: { value: "Blocked agent" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Create token" }));
    expect(
      await screen.findByRole("button", { name: "Retry pending token request" }),
    ).toBeDefined();
    expect(createCalls).toBe(2);
    expect(window.sessionStorage.getItem(TOKEN_CREATE_STORAGE_KEY)).not.toBeNull();

    const unload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unload);
    expect(unload.defaultPrevented).toBe(true);
    await fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(
      await screen.findByText(
        "Recover the pending token request before leaving this page or signing out.",
      ),
    ).toBeDefined();
    expect(logoutCalls).toBe(0);
    expect(window.sessionStorage.getItem(TOKEN_CREATE_STORAGE_KEY)).not.toBeNull();
  });

  it("fails closed around an unreadable retained record", async () => {
    window.sessionStorage.setItem(
      TOKEN_CREATE_STORAGE_KEY,
      JSON.stringify({ version: 1, key: "invalid", name: "Unknown agent" }),
    );
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        if (String(input) === "/api/v1/tokens") {
          return Promise.resolve(Response.json({ tokens: [] }));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(TokensPageHarness, { tokenCreateEnvironment: fixedEnvironment() });

    expect(await screen.findByText(/stored token request is invalid/i)).toBeDefined();
    expect(screen.getByLabelText<HTMLInputElement>("Token name").disabled).toBe(true);
    expect(screen.getByRole<HTMLButtonElement>("button", { name: "Create token" }).disabled).toBe(
      true,
    );
    const unload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unload);
    expect(unload.defaultPrevented).toBe(true);
    expect(window.sessionStorage.getItem(TOKEN_CREATE_STORAGE_KEY)).not.toBeNull();
  });

  it("aborts recovery on unmount, ignores the late secret, and retains the pending record", async () => {
    const pending = {
      version: 1,
      key: "8".repeat(64),
      name: "Unmounted agent",
    } as const;
    window.sessionStorage.setItem(TOKEN_CREATE_STORAGE_KEY, JSON.stringify(pending));
    const response = deferred<Response>();
    const request = { signal: null as AbortSignal | null };
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/tokens" && init?.method === "POST") {
          request.signal = init.signal ?? null;
          return response.promise;
        }
        if (path === "/api/v1/tokens") {
          return Promise.resolve(Response.json({ tokens: [] }));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    const mounted = render(TokensPageHarness, {
      tokenCreateEnvironment: fixedEnvironment(),
    });

    await waitFor(() => expect(request.signal).not.toBeNull());
    mounted.unmount();
    expect(request.signal?.aborted).toBe(true);
    response.resolve(
      noStoreJson(createdToken(pending.name), {
        status: 201,
        headers: { "idempotency-replayed": "true" },
      }),
    );
    await response.promise;
    await Promise.resolve();
    await Promise.resolve();

    expect(screen.queryByDisplayValue(oneTimeSecret)).toBeNull();
    expect(window.sessionStorage.getItem(TOKEN_CREATE_STORAGE_KEY)).toBe(JSON.stringify(pending));
  });

  it("retries one ambiguous revoke and refreshes the revoked row", async () => {
    let listCalls = 0;
    let revokeCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/tokens") {
          listCalls += 1;
          return Promise.resolve(
            Response.json({ tokens: [tokenMetadata(listCalls === 1 ? null : 200)] }),
          );
        }
        if (path === "/api/v1/tokens/token-1" && init?.method === "DELETE") {
          revokeCalls += 1;
          return revokeCalls === 1
            ? Effect.runPromise(Effect.fail("response lost"))
            : Promise.resolve(new Response(null, { status: 204 }));
        }
        return Promise.resolve(Response.json({}, { status: 500 }));
      }),
    );
    render(TokensPageHarness, { tokenCreateEnvironment: fixedEnvironment() });

    const revoke = await screen.findByRole("button", { name: "Revoke Laptop agent" });
    await fireEvent.click(revoke);
    const dialog = await screen.findByRole("dialog", { name: "Stop using Laptop agent?" });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Revoke token" }));

    await waitFor(() => expect(revokeCalls).toBe(2));
    await waitFor(() => expect(listCalls).toBe(2));
    expect(await screen.findByText("Revoked")).toBeDefined();
  });
});
