import { describe, expect, it, vi } from "@effect/vitest";
import { Effect } from "effect";
import {
  ApiError,
  createGraphqlSource,
  type ApiResult,
  type Source,
  type SourceCreateApiResult,
  type SourceCreationResolution,
} from "$lib/api";
import {
  SOURCE_CREATE_STORAGE_KEY,
  createSourceCreateCoordinator,
  isAmbiguousSourceCreateResult,
  type SourceCreateEnvironment,
  type SourceCreateInput,
  type SourceCreateState,
} from "$lib/source-create-lifecycle";

function sourceFixture(): Source {
  return {
    id: "source-1",
    kind: "graphql",
    slug: "product",
    displayName: "Product API",
    description: null,
    configuration: { endpoint: "https://api.example.test", allowPrivateNetwork: false },
    modeOverride: null,
    healthStatus: "healthy",
    healthErrorCode: null,
    revision: 1,
    catalogRevision: 1,
    createdAt: 100,
    updatedAt: 100,
    lastRefreshedAt: 100,
    toolCount: 4,
    tombstonedToolCount: 0,
  };
}

function payload(secret = "exact-secret") {
  return {
    kind: "graphql",
    displayName: "Product API",
    endpoint: "https://api.example.test/graphql",
    credential: { type: "bearer", token: secret },
  } satisfies SourceCreateInput;
}

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

class MemoryStorage {
  readonly values = new Map<string, string>();
  readonly writes: Array<{ key: string; value: string }> = [];

  getItem(key: string) {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string) {
    this.values.set(key, value);
    this.writes.push({ key, value });
  }

  removeItem(key: string) {
    this.values.delete(key);
  }

  clone() {
    const clone = new MemoryStorage();
    for (const [key, value] of this.values) clone.values.set(key, value);
    return clone;
  }
}

function environment(
  storage: MemoryStorage,
  options: {
    readonly fillRandom?: SourceCreateEnvironment["fillRandom"];
    readonly wait?: SourceCreateEnvironment["wait"];
  } = {},
): SourceCreateEnvironment {
  return {
    getStorage: () => storage,
    fillRandom:
      options.fillRandom ??
      ((bytes) => {
        bytes.fill(0xab);
      }),
    wait: options.wait ?? (() => Promise.resolve(true)),
  };
}

function apiError(code: string, status: number) {
  return new ApiError({ code, displayMessage: code, requestId: null, status });
}

function sourceCreateSuccess() {
  return {
    ok: true,
    value: sourceFixture(),
    replayProvenance: "none",
    responseDisposition: "authoritative",
  } as const satisfies SourceCreateApiResult;
}

function sourceCreateFailure(
  code: string,
  status: number,
  replayProvenance: SourceCreateApiResult["replayProvenance"] = "none",
  responseDisposition: SourceCreateApiResult["responseDisposition"] = status >= 400 && status <= 499
    ? "authoritative"
    : "ambiguous",
) {
  return {
    ok: false,
    error: apiError(code, status),
    replayProvenance,
    responseDisposition,
  } as const satisfies SourceCreateApiResult;
}

function freshSourceResponse(status: number, includeNoStore = true) {
  const nativeStatus = status < 200 ? 200 : status > 599 ? 599 : status;
  const headers = includeNoStore ? { "cache-control": "no-store" } : undefined;
  const response =
    nativeStatus === 204
      ? new Response(null, { status: nativeStatus, headers })
      : Response.json(sourceFixture(), { status: nativeStatus, headers });
  if (nativeStatus !== status) Object.defineProperty(response, "status", { value: status });
  return response;
}

function freshErrorResponse(status: number, code = "invalid_source", includeNoStore = true) {
  const nativeStatus = status < 200 ? 200 : status > 599 ? 599 : status;
  const response = Response.json(
    {
      error: {
        code,
        message: `Failure ${status}`,
        requestId: `failure-${status}`,
      },
    },
    {
      status: nativeStatus,
      headers: includeNoStore ? { "cache-control": "no-store" } : undefined,
    },
  );
  if (nativeStatus !== status) Object.defineProperty(response, "status", { value: status });
  return response;
}

function successfulList() {
  return {
    ok: true,
    value: { sources: [sourceFixture()], catalogRevision: 1 },
  } as const;
}

function coordinatorHarness(
  storage: MemoryStorage,
  overrides: Partial<{
    environment: SourceCreateEnvironment;
    create: (
      input: SourceCreateInput,
      key: string,
      signal: AbortSignal,
    ) => Promise<SourceCreateApiResult>;
    lookup: (key: string, signal: AbortSignal) => Promise<ApiResult<SourceCreationResolution>>;
    seal: (key: string, signal: AbortSignal) => Promise<ApiResult<SourceCreationResolution>>;
    refresh: (signal: AbortSignal) => Promise<ReturnType<typeof successfulList> | null>;
  }> = {},
) {
  const states: SourceCreateState[] = [];
  const completed: Source[] = [];
  const coordinator = createSourceCreateCoordinator({
    environment: overrides.environment ?? environment(storage),
    create: overrides.create ?? (() => Promise.resolve(sourceCreateSuccess())),
    lookup:
      overrides.lookup ??
      (() =>
        Promise.resolve({
          ok: true,
          value: { kind: "status", status: "missing" },
        } as const)),
    seal:
      overrides.seal ??
      (() =>
        Promise.resolve({
          ok: true,
          value: { kind: "status", status: "abandoned" },
        } as const)),
    refresh: overrides.refresh ?? (() => Promise.resolve(successfulList())),
    onstatechange: (state) => states.push(state),
    oncompleted: (source) => completed.push(source),
  });
  return { coordinator, states, completed };
}

describe("source create lifecycle", () => {
  it("classifies only outcomes that require key reconciliation as ambiguous", () => {
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("network_error", 0))).toBe(true);
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("request_cancelled", 0))).toBe(true);
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("invalid_response", 502))).toBe(true);
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("unexpected_client_error", 0))).toBe(
      true,
    );
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("http_502", 502))).toBe(true);
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("http_504", 504))).toBe(true);
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("idempotency_in_progress", 409))).toBe(
      true,
    );
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("unauthorized", 401))).toBe(true);
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("typed_gateway_error", 502))).toBe(
      true,
    );
    expect(
      isAmbiguousSourceCreateResult(
        sourceCreateFailure("internal_error", 500, "authoritative", "authoritative"),
      ),
    ).toBe(false);
    expect(
      isAmbiguousSourceCreateResult({
        ...sourceCreateSuccess(),
        replayProvenance: "invalid",
        responseDisposition: "ambiguous",
      }),
    ).toBe(true);
    expect(isAmbiguousSourceCreateResult(sourceCreateFailure("invalid_source", 400))).toBe(false);
  });

  it("persists only a 128-bit opaque key synchronously before dispatch", async () => {
    const storage = new MemoryStorage();
    const submitted: Array<{ input: SourceCreateInput; key: string; stored: string | null }> = [];
    const input = payload("never-persist-this-secret");
    const { coordinator } = coordinatorHarness(storage, {
      create: async (createdInput, key) => {
        submitted.push({
          input: createdInput,
          key,
          stored: storage.getItem(SOURCE_CREATE_STORAGE_KEY),
        });
        return sourceCreateSuccess();
      },
    });

    const result = await coordinator.start(input);

    expect(result.ok).toBe(true);
    expect(submitted).toHaveLength(1);
    expect(submitted[0]?.key).toMatch(/^[0-9a-f]{32}$/);
    expect(submitted[0]?.stored).toBe(submitted[0]?.key);
    expect(submitted[0]?.input).toBe(input);
    expect(storage.writes).toEqual([
      { key: SOURCE_CREATE_STORAGE_KEY, value: submitted[0]?.key ?? "" },
    ]);
    expect(JSON.stringify(storage.writes)).not.toContain("never-persist-this-secret");
    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
  });

  it("fails closed when secure randomness or tab storage is unavailable", async () => {
    const randomStorage = new MemoryStorage();
    const randomCreate = vi.fn();
    const randomHarness = coordinatorHarness(randomStorage, {
      environment: environment(randomStorage, {
        fillRandom: () => Effect.runSync(Effect.fail("randomness unavailable")),
      }),
      create: randomCreate,
    });
    const storageCreate = vi.fn();
    const storageHarness = coordinatorHarness(new MemoryStorage(), {
      environment: {
        getStorage: () => Effect.runSync(Effect.fail("storage unavailable")),
        fillRandom: (bytes) => bytes.fill(1),
        wait: () => Promise.resolve(true),
      },
      create: storageCreate,
    });

    const randomResult = await randomHarness.coordinator.start(payload());
    const storageResult = await storageHarness.coordinator.start(payload());

    expect(randomResult.ok).toBe(false);
    expect(!randomResult.ok && randomResult.error.code).toBe(
      "source_create_randomness_unavailable",
    );
    expect(storageResult.ok).toBe(false);
    expect(!storageResult.ok && storageResult.error.code).toBe("source_create_storage_unavailable");
    expect(randomCreate).not.toHaveBeenCalled();
    expect(storageCreate).not.toHaveBeenCalled();
  });

  it("retries an ambiguous live request with the exact key and in-memory payload", async () => {
    const storage = new MemoryStorage();
    const calls: Array<{ input: SourceCreateInput; key: string }> = [];
    let createCalls = 0;
    const { coordinator } = coordinatorHarness(storage, {
      create: async (input, key) => {
        calls.push({ input, key });
        createCalls += 1;
        return createCalls === 1 ? sourceCreateFailure("network_error", 0) : sourceCreateSuccess();
      },
    });
    const input = payload("same-secret-payload");

    const result = await coordinator.start(input);

    expect(result.ok).toBe(true);
    expect(calls).toHaveLength(2);
    expect(calls[0]?.key).toBe(calls[1]?.key);
    expect(calls[0]?.input).toBe(input);
    expect(calls[1]?.input).toBe(input);
    expect(JSON.stringify(storage.writes)).not.toContain("same-secret-payload");
  });

  it("retains a non-replayed structured 5xx while reconciling its key", async () => {
    const storage = new MemoryStorage();
    const lookup = vi.fn(() =>
      Promise.resolve({ ok: false, error: apiError("network_error", 0) } as const),
    );
    const { coordinator, states } = coordinatorHarness(storage, {
      create: () => Promise.resolve(sourceCreateFailure("internal_error", 500)),
      lookup,
    });

    const result = await coordinator.start(payload());
    const key = storage.writes[0]?.value ?? null;

    expect(result).toMatchObject({ ok: false, error: { code: "network_error" } });
    expect(lookup).toHaveBeenCalledOnce();
    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
    expect(states.at(-1)).toMatchObject({ phase: "blocked", key, retry: "lookup" });
  });

  it("reports and clears a structured 5xx only when it is a valid stored replay", async () => {
    const storage = new MemoryStorage();
    const lookup = vi.fn();
    const error = apiError("internal_error", 500);
    const { coordinator, states } = coordinatorHarness(storage, {
      create: () =>
        Promise.resolve({
          ok: false,
          error,
          replayProvenance: "authoritative",
          responseDisposition: "authoritative",
        } as const),
      lookup,
    });

    const result = await coordinator.start(payload());

    expect(result).toEqual({ ok: false, error });
    expect(lookup).not.toHaveBeenCalled();
    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
    expect(states.at(-1)).toMatchObject({ phase: "idle", key: null, error });
  });

  it("keeps the key when source-create transport rejects during recovery", async () => {
    const storage = new MemoryStorage();
    const lookup = vi.fn(() =>
      Promise.resolve({ ok: false, error: apiError("network_error", 0) } as const),
    );
    const { coordinator } = coordinatorHarness(storage, {
      create: () => Effect.runPromise(Effect.fail("transport disconnected")),
      lookup,
    });

    const result = await coordinator.start(payload());
    const key = storage.writes[0]?.value ?? null;

    expect(result).toMatchObject({ ok: false, error: { code: "network_error" } });
    expect(lookup).toHaveBeenCalledOnce();
    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
  });

  it("reconciles invalid fresh response contracts without clearing their keys", async () => {
    const responses = [
      () => freshSourceResponse(199),
      () => freshSourceResponse(200),
      () => freshSourceResponse(204),
      () => freshErrorResponse(302),
      () => freshErrorResponse(399),
      () => freshErrorResponse(500),
      () => freshErrorResponse(600),
      () => freshSourceResponse(201, false),
      () =>
        Response.json(
          { error: { code: "invalid_source", message: "Missing request ID." } },
          { status: 400, headers: { "cache-control": "no-store" } },
        ),
    ];

    for (const response of responses) {
      const storage = new MemoryStorage();
      const lookup = vi.fn(() =>
        Promise.resolve({ ok: false, error: apiError("network_error", 0) } as const),
      );
      const { coordinator, states } = coordinatorHarness(storage, {
        create: (_input, key, signal) =>
          createGraphqlSource(payload(), key, async () => response(), signal),
        lookup,
      });

      const result = await coordinator.start(payload());
      const key = storage.writes[0]?.value ?? null;

      expect(result).toMatchObject({ ok: false, error: { code: "network_error" } });
      expect(lookup).toHaveBeenCalledOnce();
      expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
      expect(states.at(-1)).toMatchObject({ phase: "blocked", key, retry: "lookup" });
    }
  });

  it("settles valid fresh 201 successes and 400 through 499 client failures", async () => {
    const successStorage = new MemoryStorage();
    const successLookup = vi.fn();
    const successHarness = coordinatorHarness(successStorage, {
      create: (_input, key, signal) =>
        createGraphqlSource(payload(), key, async () => freshSourceResponse(201), signal),
      lookup: successLookup,
    });

    const success = await successHarness.coordinator.start(payload());

    expect(success).toMatchObject({ ok: true, value: { id: "source-1" } });
    expect(successLookup).not.toHaveBeenCalled();
    expect(successStorage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();

    for (const status of [400, 499]) {
      const storage = new MemoryStorage();
      const lookup = vi.fn();
      const { coordinator, states } = coordinatorHarness(storage, {
        create: (_input, key, signal) =>
          createGraphqlSource(payload(), key, async () => freshErrorResponse(status), signal),
        lookup,
      });

      const result = await coordinator.start(payload());

      expect(result).toMatchObject({
        ok: false,
        error: { code: "invalid_source", status },
      });
      expect(lookup).not.toHaveBeenCalled();
      expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
      expect(states.at(-1)).toMatchObject({ phase: "idle", key: null });
    }
  });

  it("keeps typed auth and idempotency client failures in recovery", async () => {
    const failures = [
      { status: 401, code: "unauthorized" },
      { status: 403, code: "invalid_csrf" },
      { status: 409, code: "idempotency_in_progress" },
    ] as const;

    for (const { status, code } of failures) {
      const storage = new MemoryStorage();
      const lookup = vi.fn(() =>
        Promise.resolve({ ok: false, error: apiError("network_error", 0) } as const),
      );
      const { coordinator } = coordinatorHarness(storage, {
        create: (_input, key, signal) =>
          createGraphqlSource(payload(), key, async () => freshErrorResponse(status, code), signal),
        lookup,
      });

      await coordinator.start(payload());
      const key = storage.writes[0]?.value ?? null;

      expect(lookup).toHaveBeenCalledOnce();
      expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
    }
  });

  it("recovers a completed reload only after an authoritative refresh", async () => {
    const storage = new MemoryStorage();
    const key = "1".repeat(32);
    storage.setItem(SOURCE_CREATE_STORAGE_KEY, key);
    const refresh = deferred<ReturnType<typeof successfulList> | null>();
    const { coordinator, completed } = coordinatorHarness(storage, {
      lookup: async (observedKey) => {
        expect(observedKey).toBe(key);
        return {
          ok: true,
          value: { kind: "replay", result: { ok: true, value: sourceFixture() } },
        };
      },
      refresh: () => refresh.promise,
    });

    const recovery = coordinator.recoverStored();
    await Promise.resolve();
    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
    refresh.resolve(successfulList());
    const result = await recovery;

    expect(result?.ok).toBe(true);
    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
    expect(completed).toEqual([sourceFixture()]);
  });

  it("reports a stored definitive failure and compare-clears its key", async () => {
    const storage = new MemoryStorage();
    const key = "2".repeat(32);
    storage.setItem(SOURCE_CREATE_STORAGE_KEY, key);
    const failure = apiError("invalid_source", 422);
    const { coordinator, states } = coordinatorHarness(storage, {
      lookup: () =>
        Promise.resolve({
          ok: true,
          value: { kind: "replay", result: { ok: false, error: failure } },
        }),
    });

    const result = await coordinator.recoverStored();

    expect(result).toEqual({ ok: false, error: failure });
    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
    expect(states.at(-1)).toMatchObject({ phase: "idle", error: failure });
  });

  it("seals a missing reload key before clearing a cloned session store", async () => {
    const original = new MemoryStorage();
    const key = "3".repeat(32);
    original.setItem(SOURCE_CREATE_STORAGE_KEY, key);
    const clone = original.clone();
    const seal = vi.fn(async (observedKey: string) => {
      expect(clone.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
      expect(observedKey).toBe(key);
      return {
        ok: true,
        value: { kind: "status", status: "abandoned" },
      } as const;
    });
    const { coordinator } = coordinatorHarness(clone, { seal });

    await coordinator.recoverStored();

    expect(seal).toHaveBeenCalledOnce();
    expect(clone.getItem(SOURCE_CREATE_STORAGE_KEY)).toBeNull();
    expect(original.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
  });

  it("retains the key and lock for unauthorized, network, and malformed status failures", async () => {
    for (const error of [
      apiError("unauthorized", 401),
      apiError("network_error", 0),
      apiError("invalid_response", 502),
    ]) {
      const storage = new MemoryStorage();
      const key = "4".repeat(32);
      storage.setItem(SOURCE_CREATE_STORAGE_KEY, key);
      const { coordinator, states } = coordinatorHarness(storage, {
        lookup: () => Promise.resolve({ ok: false, error }),
      });

      const result = await coordinator.recoverStored();

      expect(result).toEqual({ ok: false, error });
      expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
      expect(states.at(-1)).toMatchObject({ phase: "blocked", key, retry: "lookup" });
    }
  });

  it("aborts local polling on dispose without deleting the pending key", async () => {
    const storage = new MemoryStorage();
    const key = "5".repeat(32);
    storage.setItem(SOURCE_CREATE_STORAGE_KEY, key);
    const polling = deferred<boolean>();
    const enteredPolling = deferred<void>();
    const poll = { signal: null as AbortSignal | null };
    const { coordinator } = coordinatorHarness(storage, {
      environment: environment(storage, {
        wait: (_milliseconds, signal) => {
          poll.signal = signal;
          enteredPolling.resolve();
          return polling.promise;
        },
      }),
      lookup: () =>
        Promise.resolve({
          ok: true,
          value: { kind: "status", status: "in_progress" },
        }),
    });

    const recovery = coordinator.recoverStored();
    await enteredPolling.promise;
    coordinator.dispose();

    expect(poll.signal?.aborted).toBe(true);
    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);
    polling.resolve(false);
    await recovery;
  });

  it("suspends recovery before sign-out and ignores a late missing lookup", async () => {
    const storage = new MemoryStorage();
    const lookupResponse = deferred<ApiResult<SourceCreationResolution>>();
    const lookupStarted = deferred<void>();
    const lookupRequest = { signal: null as AbortSignal | null };
    const create = vi.fn(() => Promise.resolve(sourceCreateFailure("network_error", 0)));
    const seal = vi.fn();
    const { coordinator, states } = coordinatorHarness(storage, {
      create,
      lookup: (_key, signal) => {
        lookupRequest.signal = signal;
        lookupStarted.resolve();
        return lookupResponse.promise;
      },
      seal,
    });

    const creation = coordinator.start(payload());
    await lookupStarted.promise;
    const key = storage.writes[0]?.value ?? null;

    expect(coordinator.suspendForSignOut()).toBe(true);
    expect(lookupRequest.signal?.aborted).toBe(true);
    expect(states.at(-1)).toMatchObject({
      phase: "paused",
      key,
      notice: "Source recovery paused for sign-out.",
      retry: null,
    });

    lookupResponse.resolve({
      ok: true,
      value: { kind: "status", status: "missing" },
    });
    await creation;

    expect(create).toHaveBeenCalledOnce();
    expect(seal).not.toHaveBeenCalled();
    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(key);

    coordinator.signOutFailed();
    expect(states.at(-1)).toMatchObject({
      phase: "paused",
      key,
      notice:
        "Source recovery is paused because sign-out failed. Resume source recovery or reload this page.",
      retry: "lookup",
    });
  });

  it("never lets stale operation A clear or overwrite stored operation B", async () => {
    const storage = new MemoryStorage();
    const refresh = deferred<ReturnType<typeof successfulList> | null>();
    const keyB = "b".repeat(32);
    const lookups: string[] = [];
    const { coordinator, completed, states } = coordinatorHarness(storage, {
      refresh: () => refresh.promise,
      lookup: async (key) => {
        lookups.push(key);
        return { ok: false, error: apiError("network_error", 0) };
      },
    });

    const operationA = coordinator.start(payload("operation-a-secret"));
    await Promise.resolve();
    storage.setItem(SOURCE_CREATE_STORAGE_KEY, keyB);
    refresh.resolve(successfulList());
    await operationA;

    expect(storage.getItem(SOURCE_CREATE_STORAGE_KEY)).toBe(keyB);
    expect(lookups).toEqual([keyB]);
    expect(completed).toEqual([]);
    expect(states.at(-1)).toMatchObject({ phase: "blocked", key: keyB });
  });
});
