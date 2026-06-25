import { describe, expect, it, vi } from "@effect/vitest";
import { Schema } from "effect";
import { ApiError, type CreatedToken, type TokenCreateApiResult } from "./api";
import {
  TOKEN_CREATE_STORAGE_KEY,
  createTokenCreateCoordinator,
  isAmbiguousTokenCreateResult,
  type TokenCreateEnvironment,
  type TokenCreateState,
} from "./token-create-lifecycle";

const PendingRecordSchema = Schema.Struct({
  version: Schema.Literal(1),
  key: Schema.String,
  name: Schema.String,
});
const decodePendingRecord = Schema.decodeUnknownSync(Schema.fromJsonString(PendingRecordSchema));

class MemoryStorage implements Pick<Storage, "getItem" | "setItem" | "removeItem"> {
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
}

function token(id = "token-1", name = "Laptop") {
  return {
    id,
    name,
    token: `exr_${"A".repeat(43)}`,
    createdAt: 1_750_000_000,
  } satisfies CreatedToken;
}

function success(value = token(), replayed = false): TokenCreateApiResult {
  return {
    ok: true,
    value,
    replayProvenance: replayed ? "authoritative" : "none",
    responseDisposition: "authoritative",
  };
}

function failure(
  code: string,
  status: number,
  responseDisposition: TokenCreateApiResult["responseDisposition"] = "authoritative",
  replayProvenance: TokenCreateApiResult["replayProvenance"] = "none",
): TokenCreateApiResult {
  return {
    ok: false,
    error: new ApiError({ code, displayMessage: code, requestId: null, status }),
    replayProvenance,
    responseDisposition,
  };
}

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  const promise = new Promise<Value>((complete) => {
    resolve = complete;
  });
  return { promise, resolve };
}

function environment(storage: MemoryStorage): TokenCreateEnvironment {
  return {
    getStorage: () => storage,
    fillRandom: (bytes) => bytes.fill(0xab),
  };
}

function harness(
  storage: MemoryStorage,
  create: (name: string, key: string, signal: AbortSignal) => Promise<TokenCreateApiResult>,
) {
  const states: TokenCreateState[] = [];
  const revealed: CreatedToken[] = [];
  const coordinator = createTokenCreateCoordinator({
    environment: environment(storage),
    create,
    onstatechange: (state) => states.push(state),
    onrevealed: (created) => revealed.push(created),
  });
  return { coordinator, states, revealed };
}

function readPending(storage: MemoryStorage) {
  const stored = storage.getItem(TOKEN_CREATE_STORAGE_KEY);
  return stored === null ? null : decodePendingRecord(stored);
}

describe("delivery-safe token creation", () => {
  it("persists a versioned 256-bit key and name before dispatch, then retries exactly once", async () => {
    const storage = new MemoryStorage();
    const calls: Array<{ name: string; key: string; stored: string | null }> = [];
    const { coordinator, revealed } = harness(storage, async (name, key) => {
      calls.push({ name, key, stored: storage.getItem(TOKEN_CREATE_STORAGE_KEY) });
      return calls.length === 1
        ? failure("network_error", 0, "ambiguous")
        : success(token("token-replayed", name), true);
    });

    const result = await coordinator.start("  Laptop agent  ");

    expect(result.ok).toBe(true);
    expect(calls).toHaveLength(2);
    expect(calls[0]?.key).toBe(calls[1]?.key);
    expect(calls[0]?.key).toMatch(/^[0-9a-f]{64}$/);
    expect(calls.map(({ name }) => name)).toEqual(["Laptop agent", "Laptop agent"]);
    expect(calls[0]?.stored).toBe(calls[1]?.stored);
    expect(readPending(storage)).toEqual({
      version: 1,
      key: calls[0]?.key,
      name: "Laptop agent",
    });
    expect(JSON.stringify(storage.writes)).not.toContain(`exr_${"A".repeat(43)}`);
    expect(revealed).toEqual([token("token-replayed", "Laptop agent")]);

    expect(coordinator.acknowledge()).toEqual({ ok: true, value: undefined });
    expect(storage.getItem(TOKEN_CREATE_STORAGE_KEY)).toBeNull();
  });

  it("recovers a reload by reposting the exact pending name and key", async () => {
    const storage = new MemoryStorage();
    const pending = {
      version: 1,
      key: "7".repeat(64),
      name: "Reloaded agent",
    } as const;
    storage.setItem(TOKEN_CREATE_STORAGE_KEY, JSON.stringify(pending));
    const create = vi.fn(async (name: string, key: string) => {
      expect({ name, key }).toEqual({ name: pending.name, key: pending.key });
      return success(token("token-recovered", name), true);
    });
    const { coordinator, revealed } = harness(storage, create);

    const result = await coordinator.recoverStored();

    expect(result?.ok).toBe(true);
    expect(create).toHaveBeenCalledOnce();
    expect(revealed).toEqual([token("token-recovered", pending.name)]);
    expect(storage.getItem(TOKEN_CREATE_STORAGE_KEY)).toBe(JSON.stringify(pending));
  });

  it("retries a success with the wrong name and reveals only the exact pending name", async () => {
    const storage = new MemoryStorage();
    let calls = 0;
    const { coordinator, revealed } = harness(storage, async () => {
      calls += 1;
      return calls === 1
        ? success(token("wrong-name", "Different agent"))
        : success(token("exact-name", "Laptop agent"), true);
    });

    const result = await coordinator.start("Laptop agent");

    expect(result.ok).toBe(true);
    expect(calls).toBe(2);
    expect(revealed).toEqual([token("exact-name", "Laptop agent")]);
    expect(readPending(storage)?.name).toBe("Laptop agent");
  });

  it("retains auth, mismatch, network, and invalid responses but clears replay-revoked", async () => {
    for (const ambiguous of [
      failure("unauthorized", 401),
      failure("idempotency_mismatch", 409),
      failure("network_error", 0, "ambiguous"),
      failure("invalid_response", 502, "ambiguous"),
      failure("internal_error", 500, "authoritative", "authoritative"),
      failure("idempotency_replay_revoked", 500, "authoritative", "authoritative"),
    ]) {
      const storage = new MemoryStorage();
      const { coordinator, states } = harness(storage, async () => ambiguous);

      const result = await coordinator.start("Retained agent");

      expect(result.ok).toBe(false);
      expect(storage.getItem(TOKEN_CREATE_STORAGE_KEY)).not.toBeNull();
      expect(states.at(-1)).toMatchObject({ phase: "blocked", canRetry: true });
    }

    const storage = new MemoryStorage();
    const revoked = failure("idempotency_replay_revoked", 409, "authoritative", "authoritative");
    const { coordinator, states } = harness(storage, async () => revoked);

    const result = await coordinator.start("Revoked agent");

    expect(result).toMatchObject({ ok: false, error: { code: "idempotency_replay_revoked" } });
    expect(storage.getItem(TOKEN_CREATE_STORAGE_KEY)).toBeNull();
    expect(states.at(-1)).toMatchObject({ phase: "idle", pending: null });
  });

  it("reuses the retained key after reauthentication", async () => {
    const storage = new MemoryStorage();
    let authenticated = false;
    const calls: Array<{ name: string; key: string }> = [];
    const { coordinator, revealed } = harness(storage, async (name, key) => {
      calls.push({ name, key });
      return authenticated
        ? success(token("recovered-after-login", name), true)
        : failure("unauthorized", 401);
    });

    const blocked = await coordinator.start("Reauthenticated agent");
    const retained = readPending(storage);
    authenticated = true;
    const recovered = await coordinator.retry();

    expect(blocked).toMatchObject({ ok: false, error: { code: "unauthorized" } });
    expect(recovered?.ok).toBe(true);
    expect(calls).toHaveLength(3);
    expect(calls.map(({ key }) => key)).toEqual([retained?.key, retained?.key, retained?.key]);
    expect(calls.map(({ name }) => name)).toEqual([
      "Reauthenticated agent",
      "Reauthenticated agent",
      "Reauthenticated agent",
    ]);
    expect(revealed).toEqual([token("recovered-after-login", "Reauthenticated agent")]);
    expect(readPending(storage)).toEqual(retained);
  });

  it("rejects stale completion A and recovers pending operation B", async () => {
    const storage = new MemoryStorage();
    const operationA = deferred<TokenCreateApiResult>();
    const calls: string[] = [];
    const { coordinator, revealed } = harness(storage, async (name) => {
      calls.push(name);
      return name === "Operation A"
        ? operationA.promise
        : success(token("token-b", "Operation B"), true);
    });

    const startedA = coordinator.start("Operation A");
    await Promise.resolve();
    const pendingB = {
      version: 1,
      key: "b".repeat(64),
      name: "Operation B",
    } as const;
    storage.setItem(TOKEN_CREATE_STORAGE_KEY, JSON.stringify(pendingB));
    operationA.resolve(success(token("token-a", "Operation A")));
    const result = await startedA;

    expect(result.ok).toBe(true);
    expect(calls).toEqual(["Operation A", "Operation B"]);
    expect(revealed).toEqual([token("token-b", "Operation B")]);
    expect(readPending(storage)).toEqual(pendingB);
  });

  it("aborts on dispose and ignores a late token secret", async () => {
    const storage = new MemoryStorage();
    const response = deferred<TokenCreateApiResult>();
    const started = deferred<void>();
    const request = { signal: null as AbortSignal | null };
    const { coordinator, revealed, states } = harness(storage, (_name, _key, signal) => {
      request.signal = signal;
      started.resolve();
      return response.promise;
    });

    const creation = coordinator.start("Unmounted agent");
    await started.promise;
    const stored = storage.getItem(TOKEN_CREATE_STORAGE_KEY);
    coordinator.dispose();

    expect(request.signal?.aborted).toBe(true);
    response.resolve(success(token("late-token")));
    await creation;
    expect(revealed).toEqual([]);
    expect(storage.getItem(TOKEN_CREATE_STORAGE_KEY)).toBe(stored);
    expect(states.some(({ phase }) => phase === "revealed")).toBe(false);
  });
});

describe("token create ambiguity", () => {
  it("keeps mismatch ambiguous while treating an authoritative revoked replay as final", () => {
    expect(isAmbiguousTokenCreateResult(failure("idempotency_mismatch", 409))).toBe(true);
    expect(
      isAmbiguousTokenCreateResult(
        failure("idempotency_replay_revoked", 409, "authoritative", "authoritative"),
      ),
    ).toBe(false);
    expect(
      isAmbiguousTokenCreateResult(
        failure("idempotency_replay_revoked", 409, "authoritative", "none"),
      ),
    ).toBe(true);
    expect(
      isAmbiguousTokenCreateResult(
        failure("internal_error", 500, "authoritative", "authoritative"),
      ),
    ).toBe(true);
    expect(
      isAmbiguousTokenCreateResult(
        failure("idempotency_replay_revoked", 500, "authoritative", "authoritative"),
      ),
    ).toBe(true);
  });
});
