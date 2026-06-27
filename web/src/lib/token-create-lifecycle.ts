import { Effect, Exit, Option, Schema } from "effect";
import { ApiError, type ApiResult, type CreatedToken, type TokenCreateApiResult } from "$lib/api";

export const TOKEN_CREATE_STORAGE_KEY = "executor.token-create.pending.v1";

const PendingTokenCreationSchema = Schema.Struct({
  version: Schema.Literal(1),
  key: Schema.String,
  name: Schema.String,
});

const decodePendingTokenCreationJson = Schema.decodeUnknownOption(
  Schema.fromJsonString(PendingTokenCreationSchema),
);
const decodePendingTokenCreation = (text: string) =>
  decodePendingTokenCreationJson(text, { onExcessProperty: "error" });

export type PendingTokenCreation = typeof PendingTokenCreationSchema.Type;
export type TokenCreatePhase = "idle" | "dispatching" | "blocked" | "revealed";

export type TokenCreateState = {
  readonly phase: TokenCreatePhase;
  readonly pending: PendingTokenCreation | null;
  readonly error: ApiError | null;
  readonly notice: string | null;
  readonly canRetry: boolean;
};

export type TokenCreateEnvironment = {
  readonly getStorage: () => Pick<Storage, "getItem" | "setItem" | "removeItem">;
  readonly fillRandom: (bytes: Uint8Array<ArrayBuffer>) => void;
};

type TokenCreateCoordinatorOptions = {
  readonly environment: TokenCreateEnvironment;
  readonly create: (
    name: string,
    idempotencyKey: string,
    signal: AbortSignal,
  ) => Promise<TokenCreateApiResult>;
  readonly onstatechange: (state: TokenCreateState) => void;
  readonly onrevealed: (token: CreatedToken) => void;
};

type ActiveTokenCreate = {
  readonly pending: PendingTokenCreation;
  readonly generation: number;
  readonly controller: AbortController;
  readonly automaticRetryUsed: boolean;
};

type PendingRead =
  | { readonly ok: true; readonly value: PendingTokenCreation | null }
  | { readonly ok: false; readonly reason: "invalid" | "storage" };

export function emptyTokenCreateState(): TokenCreateState {
  return { phase: "idle", pending: null, error: null, notice: null, canRetry: false };
}

export function browserTokenCreateEnvironment(): TokenCreateEnvironment {
  return {
    getStorage: () => window.sessionStorage,
    fillRandom: (bytes) => {
      globalThis.crypto.getRandomValues(bytes);
    },
  };
}

export function isAmbiguousTokenCreateResult(result: TokenCreateApiResult) {
  if (
    !result.ok &&
    result.error.code === "idempotency_replay_revoked" &&
    result.error.status === 409 &&
    result.replayProvenance === "authoritative" &&
    result.responseDisposition === "authoritative"
  ) {
    return false;
  }
  if (!result.ok && result.error.code === "idempotency_replay_revoked") return true;
  if (!result.ok && result.replayProvenance === "authoritative") return true;
  if (result.responseDisposition === "ambiguous" || result.replayProvenance === "invalid") {
    return true;
  }
  if (result.ok) return false;
  if (
    [
      "idempotency_mismatch",
      "invalid_csrf",
      "invalid_response",
      "network_error",
      "request_cancelled",
      "unexpected_client_error",
    ].includes(result.error.code)
  ) {
    return true;
  }
  if (result.error.status === 401) return true;
  return result.error.status >= 500 && result.replayProvenance !== "authoritative";
}

export function createTokenCreateCoordinator(options: TokenCreateCoordinatorOptions) {
  let state = emptyTokenCreateState();
  let active: ActiveTokenCreate | null = null;
  let revealedPending: PendingTokenCreation | null = null;
  let generation = 0;
  let disposed = false;

  function publish(next: TokenCreateState) {
    if (disposed) return;
    state = next;
    options.onstatechange(next);
  }

  function owns(operation: ActiveTokenCreate) {
    return (
      !disposed &&
      active === operation &&
      generation === operation.generation &&
      !operation.controller.signal.aborted
    );
  }

  function storage() {
    return syncResult(options.environment.getStorage);
  }

  function readStoredPending(): PendingRead {
    const available = storage();
    if (!available.ok) return { ok: false, reason: "storage" };
    const stored = syncResult(() => available.value.getItem(TOKEN_CREATE_STORAGE_KEY));
    if (!stored.ok) return { ok: false, reason: "storage" };
    if (stored.value === null) return { ok: true, value: null };
    const decoded = decodePendingTokenCreation(stored.value);
    if (Option.isNone(decoded) || !validPending(decoded.value)) {
      return { ok: false, reason: "invalid" };
    }
    return { ok: true, value: decoded.value };
  }

  function persistPending(pending: PendingTokenCreation): PendingRead {
    const current = readStoredPending();
    if (!current.ok || current.value !== null) return current;
    const available = storage();
    if (!available.ok) return { ok: false, reason: "storage" };
    const written = syncResult(() =>
      available.value.setItem(TOKEN_CREATE_STORAGE_KEY, JSON.stringify(pending)),
    );
    if (!written.ok) return { ok: false, reason: "storage" };
    const verified = readStoredPending();
    return verified.ok && samePending(verified.value, pending)
      ? ({ ok: true, value: pending } as const)
      : ({ ok: false, reason: "storage" } as const);
  }

  function compareAndClearPending(pending: PendingTokenCreation) {
    const current = readStoredPending();
    if (!current.ok) return { ok: false, mismatch: false, reason: current.reason } as const;
    if (!samePending(current.value, pending)) {
      return { ok: false, mismatch: true, reason: "invalid" } as const;
    }
    const available = storage();
    if (!available.ok) {
      return { ok: false, mismatch: false, reason: "storage" } as const;
    }
    const removed = syncResult(() => available.value.removeItem(TOKEN_CREATE_STORAGE_KEY));
    if (!removed.ok) return { ok: false, mismatch: false, reason: "storage" } as const;
    const verified = readStoredPending();
    return verified.ok && verified.value === null
      ? ({ ok: true, mismatch: false } as const)
      : ({ ok: false, mismatch: false, reason: "storage" } as const);
  }

  function generateKey() {
    const bytes = new Uint8Array(32);
    const filled = syncResult(() => options.environment.fillRandom(bytes));
    if (!filled.ok) return null;
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function newOperation(pending: PendingTokenCreation, automaticRetryUsed: boolean) {
    active?.controller.abort();
    const operation = {
      pending,
      generation: ++generation,
      controller: new AbortController(),
      automaticRetryUsed,
    } satisfies ActiveTokenCreate;
    active = operation;
    return operation;
  }

  function publishBlocked(
    pending: PendingTokenCreation | null,
    error: ApiError,
    canRetry: boolean,
  ) {
    active = null;
    publish({
      phase: "blocked",
      pending,
      error,
      notice: "Executor could not safely finish token creation. The pending request was retained.",
      canRetry,
    });
    return { ok: false, error } as const;
  }

  async function recoverDifferentPending(operation: ActiveTokenCreate) {
    if (!owns(operation)) return requestCancelled();
    operation.controller.abort();
    active = null;
    generation += 1;
    const recovered = await recoverStored();
    return recovered ?? requestCancelled();
  }

  async function fencePending(operation: ActiveTokenCreate) {
    if (!owns(operation)) return requestCancelled();
    const stored = readStoredPending();
    if (!stored.ok) {
      return publishBlocked(
        operation.pending,
        stored.reason === "invalid" ? invalidStoredPendingError() : storageUnavailableError(),
        stored.reason !== "invalid",
      );
    }
    if (!samePending(stored.value, operation.pending)) return recoverDifferentPending(operation);
    return null;
  }

  async function settleDefinitiveFailure(operation: ActiveTokenCreate, error: ApiError) {
    if (!owns(operation)) return requestCancelled();
    const cleared = compareAndClearPending(operation.pending);
    if (cleared.mismatch) return recoverDifferentPending(operation);
    if (!cleared.ok) {
      return publishBlocked(operation.pending, storageUnavailableError(), true);
    }
    if (!owns(operation)) return requestCancelled();
    active = null;
    publish({ phase: "idle", pending: null, error, notice: null, canRetry: false });
    return { ok: false, error } as const;
  }

  async function handleAmbiguous(
    operation: ActiveTokenCreate,
    result: TokenCreateApiResult | null,
  ): Promise<ApiResult<CreatedToken>> {
    if (!owns(operation)) return requestCancelled();
    if (!operation.automaticRetryUsed) {
      return dispatch(newOperation(operation.pending, true));
    }
    const error = result !== null && !result.ok ? result.error : invalidTokenCreateResponseError();
    return publishBlocked(operation.pending, error, true);
  }

  async function dispatch(operation: ActiveTokenCreate): Promise<ApiResult<CreatedToken>> {
    const before = await fencePending(operation);
    if (before !== null) return before;
    publish({
      phase: "dispatching",
      pending: operation.pending,
      error: null,
      notice: operation.automaticRetryUsed
        ? "Retrying the exact pending token request."
        : "Submitting the token request.",
      canRetry: false,
    });
    const settled = await settlePromise(() =>
      options.create(operation.pending.name, operation.pending.key, operation.controller.signal),
    );
    if (!owns(operation)) return requestCancelled();
    const after = await fencePending(operation);
    if (after !== null) return after;
    if (!settled.ok) return handleAmbiguous(operation, null);
    if (isAmbiguousTokenCreateResult(settled.value)) {
      return handleAmbiguous(operation, settled.value);
    }
    if (!settled.value.ok) {
      return settleDefinitiveFailure(operation, settled.value.error);
    }
    if (settled.value.value.name !== operation.pending.name) {
      return handleAmbiguous(operation, settled.value);
    }

    const token = settled.value.value;
    active = null;
    revealedPending = operation.pending;
    publish({
      phase: "revealed",
      pending: operation.pending,
      error: null,
      notice: "Token created. Save the secret before acknowledging it.",
      canRetry: false,
    });
    if (!disposed && revealedPending === operation.pending) options.onrevealed(token);
    return { ok: true, value: token };
  }

  async function start(name: string) {
    if (disposed) return requestCancelled();
    if (active !== null || state.phase !== "idle" || revealedPending !== null) {
      return {
        ok: false,
        error: operationError(
          "token_create_already_pending",
          "Finish the pending token request before creating another token.",
        ),
      } as const;
    }

    const normalizedName = name.trim();
    if (normalizedName === "" || normalizedName.length > 80) {
      const error = operationError(
        "invalid_token_name",
        "Token names must contain between 1 and 80 characters.",
        400,
      );
      publish({ phase: "idle", pending: null, error, notice: null, canRetry: false });
      return { ok: false, error } as const;
    }
    const key = generateKey();
    if (key === null) {
      const error = randomnessUnavailableError();
      publish({ phase: "idle", pending: null, error, notice: null, canRetry: false });
      return { ok: false, error } as const;
    }
    const pending = { version: 1, key, name: normalizedName } as const;
    const persisted = persistPending(pending);
    if (!persisted.ok) {
      const error =
        persisted.reason === "invalid" ? invalidStoredPendingError() : storageUnavailableError();
      publish({ phase: "blocked", pending: null, error, notice: null, canRetry: false });
      return { ok: false, error } as const;
    }
    if (!samePending(persisted.value, pending)) {
      const recovered = await recoverStored();
      return (
        recovered ?? {
          ok: false,
          error: operationError(
            "token_create_recovery_pending",
            "A token request from this browser tab must be recovered first.",
          ),
        }
      );
    }
    return dispatch(newOperation(pending, false));
  }

  async function recoverStored() {
    if (disposed || active !== null || state.phase === "revealed") return null;
    const stored = readStoredPending();
    if (!stored.ok) {
      const error =
        stored.reason === "invalid" ? invalidStoredPendingError() : storageUnavailableError();
      publish({
        phase: "blocked",
        pending: null,
        error,
        notice: "The pending token request could not be read safely.",
        canRetry: false,
      });
      return { ok: false, error } as const;
    }
    if (stored.value === null) {
      publish(emptyTokenCreateState());
      return null;
    }
    return dispatch(newOperation(stored.value, false));
  }

  async function retry() {
    if (disposed) return requestCancelled();
    if (state.phase !== "blocked" || !state.canRetry) return recoverStored();
    const stored = readStoredPending();
    if (!stored.ok || stored.value === null) {
      const error =
        !stored.ok && stored.reason === "storage"
          ? storageUnavailableError()
          : invalidStoredPendingError();
      return publishBlocked(null, error, false);
    }
    return dispatch(newOperation(stored.value, false));
  }

  function acknowledge() {
    if (disposed || revealedPending === null || state.phase !== "revealed") {
      return requestCancelled();
    }
    const pending = revealedPending;
    const cleared = compareAndClearPending(pending);
    if (!cleared.ok) {
      const error = cleared.mismatch ? pendingChangedError() : storageUnavailableError();
      publish({ ...state, error, notice: null });
      return { ok: false, error } as const;
    }
    revealedPending = null;
    publish(emptyTokenCreateState());
    return { ok: true, value: undefined } as const;
  }

  function dispose() {
    disposed = true;
    generation += 1;
    active?.controller.abort();
    active = null;
    revealedPending = null;
  }

  return {
    start,
    recoverStored,
    retry,
    acknowledge,
    dispose,
    get state() {
      return state;
    },
  };
}

function validPending(pending: PendingTokenCreation) {
  return (
    /^[0-9a-f]{64}$/.test(pending.key) &&
    pending.name === pending.name.trim() &&
    pending.name.length > 0 &&
    pending.name.length <= 80
  );
}

function samePending(left: PendingTokenCreation | null, right: PendingTokenCreation | null) {
  return (
    left === right ||
    (left !== null &&
      right !== null &&
      left.version === right.version &&
      left.key === right.key &&
      left.name === right.name)
  );
}

function syncResult<Value>(evaluate: () => Value) {
  const result = Effect.runSyncExit(Effect.try({ try: evaluate, catch: () => undefined }));
  return Exit.isSuccess(result)
    ? ({ ok: true, value: result.value } as const)
    : ({ ok: false } as const);
}

async function settlePromise<Value>(evaluate: () => Promise<Value>) {
  return Promise.resolve()
    .then(evaluate)
    .then(
      (value) => ({ ok: true, value }) as const,
      () => ({ ok: false }) as const,
    );
}

function operationError(
  code: string,
  displayMessage: string,
  status = 0,
  requestId: string | null = null,
) {
  return new ApiError({ code, displayMessage, requestId, status });
}

function requestCancelled() {
  return {
    ok: false,
    error: operationError("request_cancelled", "The request was cancelled."),
  } as const;
}

function storageUnavailableError() {
  return operationError(
    "token_create_storage_unavailable",
    "Secure tab storage is unavailable. Executor did not start a new token request.",
  );
}

function randomnessUnavailableError() {
  return operationError(
    "token_create_randomness_unavailable",
    "Secure browser randomness is unavailable. Executor did not start a new token request.",
  );
}

function invalidStoredPendingError() {
  return operationError(
    "token_create_pending_invalid",
    "The stored token request is invalid. It was retained for manual recovery.",
  );
}

function invalidTokenCreateResponseError() {
  return operationError(
    "invalid_response",
    "Executor returned a token creation response the dashboard could not safely use.",
    502,
  );
}

function pendingChangedError() {
  return operationError(
    "token_create_pending_changed",
    "A different token request is pending. Its recovery state was not cleared.",
  );
}
