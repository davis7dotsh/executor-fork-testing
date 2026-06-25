import { Effect, Exit } from "effect";
import {
  ApiError,
  type ApiResult,
  type GraphqlSourceInput,
  type McpHttpSourceInput,
  type McpStdioSourceInput,
  type OpenApiSourceInput,
  type Source,
  type SourceCreateApiResult,
  type SourceCreationResolution,
  type SourceCreationStatus,
  type SourceList,
} from "$lib/api";

export const SOURCE_CREATE_STORAGE_KEY = "executor.source-create.idempotency-key.v1";

export type SourceCreateInput =
  | OpenApiSourceInput
  | GraphqlSourceInput
  | McpHttpSourceInput
  | McpStdioSourceInput;

export type SourceCreatePhase = "idle" | "dispatching" | "recovering" | "blocked" | "paused";
export type SourceCreateRetry = "dispatch" | "lookup" | null;

export type SourceCreateState = {
  readonly phase: SourceCreatePhase;
  readonly key: string | null;
  readonly error: ApiError | null;
  readonly notice: string | null;
  readonly retry: SourceCreateRetry;
};

export type SourceCreateEnvironment = {
  readonly getStorage: () => Pick<Storage, "getItem" | "setItem" | "removeItem">;
  readonly fillRandom: (bytes: Uint8Array<ArrayBuffer>) => void;
  readonly wait: (milliseconds: number, signal: AbortSignal) => Promise<boolean>;
};

type SourceCreateCoordinatorOptions = {
  readonly environment: SourceCreateEnvironment;
  readonly create: (
    input: SourceCreateInput,
    idempotencyKey: string,
    signal: AbortSignal,
  ) => Promise<SourceCreateApiResult>;
  readonly lookup: (
    idempotencyKey: string,
    signal: AbortSignal,
  ) => Promise<ApiResult<SourceCreationResolution>>;
  readonly seal: (
    idempotencyKey: string,
    signal: AbortSignal,
  ) => Promise<ApiResult<SourceCreationResolution>>;
  readonly refresh: (signal: AbortSignal) => Promise<ApiResult<SourceList> | null>;
  readonly onstatechange: (state: SourceCreateState) => void;
  readonly oncompleted: (source: Source) => void;
};

type ActiveSourceCreate = {
  readonly key: string;
  readonly payload: SourceCreateInput | null;
  readonly generation: number;
  readonly controller: AbortController;
  readonly automaticRetryUsed: boolean;
};

type PausedSourceCreate = {
  readonly key: string;
  readonly payload: SourceCreateInput | null;
  readonly automaticRetryUsed: boolean;
  readonly retry: Exclude<SourceCreateRetry, null>;
};

export function emptySourceCreateState(): SourceCreateState {
  return { phase: "idle", key: null, error: null, notice: null, retry: null };
}

export function browserSourceCreateEnvironment(): SourceCreateEnvironment {
  return {
    getStorage: () => window.sessionStorage,
    fillRandom: (bytes) => {
      globalThis.crypto.getRandomValues(bytes);
    },
    wait: waitForSourceCreatePoll,
  };
}

export function isAmbiguousSourceCreateResult(result: SourceCreateApiResult) {
  if (result.responseDisposition === "ambiguous") return true;
  if (result.replayProvenance === "invalid") return true;
  if (result.ok) return false;
  const { error } = result;
  if (
    [
      "invalid_response",
      "network_error",
      "request_cancelled",
      "unexpected_client_error",
      "idempotency_in_progress",
      "invalid_csrf",
    ].includes(error.code)
  ) {
    return true;
  }
  if (error.status === 401) return true;
  return error.status >= 500 && result.replayProvenance !== "authoritative";
}

export function createSourceCreateCoordinator(options: SourceCreateCoordinatorOptions) {
  let state = emptySourceCreateState();
  let active: ActiveSourceCreate | null = null;
  let paused: PausedSourceCreate | null = null;
  let generation = 0;
  let disposed = false;

  function publish(next: SourceCreateState) {
    state = next;
    options.onstatechange(next);
  }

  function owns(operation: ActiveSourceCreate) {
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

  function readStoredKey() {
    const available = storage();
    if (!available.ok) return available;
    return syncResult(() => available.value.getItem(SOURCE_CREATE_STORAGE_KEY));
  }

  function persistNewKey(key: string) {
    const available = storage();
    if (!available.ok) return { ok: false } as const;
    const current = syncResult(() => available.value.getItem(SOURCE_CREATE_STORAGE_KEY));
    if (!current.ok) return current;
    if (current.value !== null) return { ok: true, value: current.value } as const;
    const stored = syncResult(() => available.value.setItem(SOURCE_CREATE_STORAGE_KEY, key));
    if (!stored.ok) return stored;
    const verified = syncResult(() => available.value.getItem(SOURCE_CREATE_STORAGE_KEY));
    if (!verified.ok || verified.value !== key) return { ok: false } as const;
    return { ok: true, value: key } as const;
  }

  function compareAndClearStoredKey(key: string) {
    const available = storage();
    if (!available.ok) return { ok: false, mismatch: false } as const;
    const current = syncResult(() => available.value.getItem(SOURCE_CREATE_STORAGE_KEY));
    if (!current.ok) return { ok: false, mismatch: false } as const;
    if (current.value !== key) return { ok: false, mismatch: true } as const;
    const removed = syncResult(() => available.value.removeItem(SOURCE_CREATE_STORAGE_KEY));
    if (!removed.ok) return { ok: false, mismatch: false } as const;
    const verified = syncResult(() => available.value.getItem(SOURCE_CREATE_STORAGE_KEY));
    return verified.ok && verified.value === null
      ? ({ ok: true, mismatch: false } as const)
      : ({ ok: false, mismatch: false } as const);
  }

  function generateKey() {
    const bytes = new Uint8Array(16);
    const filled = syncResult(() => options.environment.fillRandom(bytes));
    if (!filled.ok) return null;
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function newOperation(
    key: string,
    payload: SourceCreateInput | null,
    automaticRetryUsed: boolean,
  ) {
    active?.controller.abort();
    paused = null;
    const operation = {
      key,
      payload,
      generation: ++generation,
      controller: new AbortController(),
      automaticRetryUsed,
    } satisfies ActiveSourceCreate;
    active = operation;
    return operation;
  }

  function operationError(
    code: string,
    displayMessage: string,
    status = 0,
    requestId: string | null = null,
  ) {
    return new ApiError({ code, displayMessage, requestId, status });
  }

  function publishBlocked(
    operation: ActiveSourceCreate,
    error: ApiError,
    retry: Exclude<SourceCreateRetry, null>,
  ) {
    publish({
      phase: "blocked",
      key: operation.key,
      error,
      notice: "Executor could not safely finish source recovery. The pending key was retained.",
      retry,
    });
    return { ok: false, error } as const;
  }

  async function blocked(
    operation: ActiveSourceCreate,
    error: ApiError,
    retry: Exclude<SourceCreateRetry, null>,
  ) {
    if (!owns(operation)) return requestCancelled();
    const stored = readStoredKey();
    if (!stored.ok || stored.value === null) {
      return publishBlocked(operation, storageUnavailableError(), "lookup");
    }
    if (stored.value !== operation.key) return recoverDifferentStoredKey(operation);
    return publishBlocked(operation, error, retry);
  }

  async function fenceStoredKey(operation: ActiveSourceCreate) {
    if (!owns(operation)) return requestCancelled();
    const stored = readStoredKey();
    if (!stored.ok || stored.value === null) {
      return blocked(operation, storageUnavailableError(), "lookup");
    }
    if (stored.value !== operation.key) return recoverDifferentStoredKey(operation);
    return null;
  }

  async function recoverDifferentStoredKey(operation: ActiveSourceCreate) {
    if (!owns(operation)) return requestCancelled();
    operation.controller.abort();
    active = null;
    generation += 1;
    const recovered = await recoverStored();
    return (
      recovered ?? {
        ok: false,
        error: operationError(
          "source_create_recovery_pending",
          "Another source connection is pending in this browser tab.",
        ),
      }
    );
  }

  async function settleSuccess(operation: ActiveSourceCreate, source: Source) {
    if (!owns(operation)) return requestCancelled();
    const beforeRefresh = readStoredKey();
    if (!beforeRefresh.ok) {
      return blocked(operation, storageUnavailableError(), "lookup");
    }
    if (beforeRefresh.value !== operation.key) return recoverDifferentStoredKey(operation);

    const refreshed = await settlePromise(() => options.refresh(operation.controller.signal));
    if (!owns(operation)) return requestCancelled();
    if (!refreshed.ok || refreshed.value === null || !refreshed.value.ok) {
      const error =
        refreshed.ok && refreshed.value !== null && !refreshed.value.ok
          ? refreshed.value.error
          : operationError(
              "source_list_refresh_failed",
              "The source connection completed, but the authoritative source list could not be refreshed.",
            );
      return blocked(operation, error, "lookup");
    }

    const cleared = compareAndClearStoredKey(operation.key);
    if (cleared.mismatch) return recoverDifferentStoredKey(operation);
    if (!cleared.ok) return blocked(operation, storageUnavailableError(), "lookup");
    if (!owns(operation)) return requestCancelled();
    active = null;
    publish({
      phase: "idle",
      key: null,
      error: null,
      notice: "Source connection completed and the authoritative source list was refreshed.",
      retry: null,
    });
    options.oncompleted(source);
    return { ok: true, value: source } as const;
  }

  async function settleFailure(operation: ActiveSourceCreate, error: ApiError) {
    if (!owns(operation)) return requestCancelled();
    const cleared = compareAndClearStoredKey(operation.key);
    if (cleared.mismatch) return recoverDifferentStoredKey(operation);
    if (!cleared.ok) return blocked(operation, storageUnavailableError(), "lookup");
    if (!owns(operation)) return requestCancelled();
    active = null;
    publish({ phase: "idle", key: null, error, notice: null, retry: null });
    return { ok: false, error } as const;
  }

  async function settleTerminal(
    operation: ActiveSourceCreate,
    status: Exclude<SourceCreationStatus, "missing" | "in_progress">,
  ) {
    return settleFailure(operation, terminalStatusError(status));
  }

  async function handleResolution(
    operation: ActiveSourceCreate,
    resolution: ApiResult<SourceCreationResolution>,
    source: "lookup" | "seal",
  ): Promise<ApiResult<Source>> {
    if (!owns(operation)) return requestCancelled();
    const fenced = await fenceStoredKey(operation);
    if (fenced !== null) return fenced;
    if (!resolution.ok) return blocked(operation, resolution.error, "lookup");
    if (resolution.value.kind === "replay") {
      return resolution.value.result.ok
        ? settleSuccess(operation, resolution.value.result.value)
        : settleFailure(operation, resolution.value.result.error);
    }

    const { status } = resolution.value;
    if (status === "in_progress") {
      publish({
        phase: "recovering",
        key: operation.key,
        error: null,
        notice: "Executor is still finishing this source connection.",
        retry: null,
      });
      const elapsed = await options.environment.wait(1_000, operation.controller.signal);
      if (!elapsed || !owns(operation)) return requestCancelled();
      return lookup(operation);
    }
    if (status === "missing") {
      if (operation.payload !== null) {
        if (!operation.automaticRetryUsed) {
          const retry = newOperation(operation.key, operation.payload, true);
          return dispatch(retry);
        }
        return blocked(
          operation,
          operationError(
            "source_create_retry_required",
            "Executor has no record of this request. Retry the exact in-memory request with the retained key.",
          ),
          "dispatch",
        );
      }
      if (source === "seal") {
        return blocked(
          operation,
          operationError(
            "invalid_response",
            "Executor returned an invalid seal result. The pending key was retained.",
            502,
          ),
          "lookup",
        );
      }
      return seal(operation);
    }
    return settleTerminal(operation, status);
  }

  async function lookup(operation: ActiveSourceCreate): Promise<ApiResult<Source>> {
    const fenced = await fenceStoredKey(operation);
    if (fenced !== null) return fenced;
    publish({
      phase: "recovering",
      key: operation.key,
      error: null,
      notice: "Checking the pending source connection with Executor.",
      retry: null,
    });
    const resolution = await settlePromise(() =>
      options.lookup(operation.key, operation.controller.signal),
    );
    if (!owns(operation)) return requestCancelled();
    return handleResolution(
      operation,
      resolution.ok ? resolution.value : { ok: false, error: unexpectedRequestError() },
      "lookup",
    );
  }

  async function seal(operation: ActiveSourceCreate): Promise<ApiResult<Source>> {
    const fenced = await fenceStoredKey(operation);
    if (fenced !== null) return fenced;
    publish({
      phase: "recovering",
      key: operation.key,
      error: null,
      notice: "Securing the unused source connection key before unlocking this page.",
      retry: null,
    });
    const resolution = await settlePromise(() =>
      options.seal(operation.key, operation.controller.signal),
    );
    if (!owns(operation)) return requestCancelled();
    return handleResolution(
      operation,
      resolution.ok ? resolution.value : { ok: false, error: unexpectedRequestError() },
      "seal",
    );
  }

  async function dispatch(operation: ActiveSourceCreate): Promise<ApiResult<Source>> {
    const payload = operation.payload;
    if (!owns(operation) || payload === null) return requestCancelled();
    const fenced = await fenceStoredKey(operation);
    if (fenced !== null) return fenced;
    publish({
      phase: "dispatching",
      key: operation.key,
      error: null,
      notice: "Submitting the source connection.",
      retry: null,
    });
    const settled = await settlePromise(() =>
      options.create(payload, operation.key, operation.controller.signal),
    );
    if (!owns(operation)) return requestCancelled();
    if (!settled.ok) return lookup(operation);
    if (isAmbiguousSourceCreateResult(settled.value)) return lookup(operation);
    if (settled.value.ok) return settleSuccess(operation, settled.value.value);
    return settleFailure(operation, settled.value.error);
  }

  async function start(input: SourceCreateInput) {
    if (disposed) return requestCancelled();
    if (state.phase !== "idle" || active !== null) {
      return {
        ok: false,
        error: operationError(
          "source_create_already_pending",
          "Finish recovering the pending source connection before starting another.",
        ),
      } as const;
    }

    const key = generateKey();
    if (key === null) {
      const error = randomnessUnavailableError();
      publish({ phase: "idle", key: null, error, notice: null, retry: null });
      return { ok: false, error } as const;
    }
    const persisted = persistNewKey(key);
    if (!persisted.ok) {
      const error = storageUnavailableError();
      publish({ phase: "idle", key: null, error, notice: null, retry: null });
      return { ok: false, error } as const;
    }
    if (persisted.value !== key) {
      void recoverStored();
      return {
        ok: false,
        error: operationError(
          "source_create_recovery_pending",
          "A source connection from this browser tab must be recovered first.",
        ),
      } as const;
    }

    return dispatch(newOperation(key, input, false));
  }

  async function recoverStored() {
    if (disposed || active !== null || state.phase === "paused") return null;
    const stored = readStoredKey();
    if (!stored.ok) {
      const error = storageUnavailableError();
      publish({
        phase: "blocked",
        key: null,
        error,
        notice: "The pending source state could not be read safely.",
        retry: "lookup",
      });
      return { ok: false, error } as const;
    }
    if (stored.value === null) {
      publish(emptySourceCreateState());
      return null;
    }
    if (!/^[0-9a-f]{32}$/.test(stored.value)) {
      const error = operationError(
        "source_create_key_invalid",
        "The stored source connection key is invalid. It was retained for manual recovery.",
      );
      publish({ phase: "blocked", key: null, error, notice: null, retry: "lookup" });
      return { ok: false, error } as const;
    }
    return lookup(newOperation(stored.value, null, true));
  }

  async function resume() {
    if (disposed) return requestCancelled();
    if (state.phase === "paused") {
      if (state.retry === null) return requestCancelled();
      const suspended = paused;
      if (suspended === null) {
        publish({ ...state, phase: "blocked", retry: "lookup" });
        return recoverStored();
      }
      const retry = state.retry;
      const operation = newOperation(
        suspended.key,
        suspended.payload,
        suspended.automaticRetryUsed,
      );
      if (retry === "dispatch" && operation.payload !== null) return dispatch(operation);
      return lookup(operation);
    }
    if (active === null) return recoverStored();
    const operation = active;
    const stored = readStoredKey();
    if (!stored.ok) return blocked(operation, storageUnavailableError(), "lookup");
    if (stored.value !== operation.key) return recoverDifferentStoredKey(operation);
    const retry = state.retry;
    if (retry === "dispatch" && operation.payload !== null) {
      return dispatch(newOperation(operation.key, operation.payload, true));
    }
    return lookup(newOperation(operation.key, operation.payload, operation.automaticRetryUsed));
  }

  function suspendForSignOut() {
    if (disposed || state.phase === "dispatching") return false;
    if (state.phase === "idle") return true;
    if (active !== null) {
      paused = {
        key: active.key,
        payload: active.payload,
        automaticRetryUsed: active.automaticRetryUsed,
        retry: state.retry ?? "lookup",
      };
    }
    generation += 1;
    const controller = active?.controller;
    active = null;
    controller?.abort();
    publish({
      phase: "paused",
      key: state.key,
      error: state.error,
      notice: "Source recovery paused for sign-out.",
      retry: null,
    });
    return true;
  }

  function signOutFailed() {
    if (disposed || state.phase !== "paused") return;
    publish({
      ...state,
      notice:
        "Source recovery is paused because sign-out failed. Resume source recovery or reload this page.",
      retry: paused?.retry ?? "lookup",
    });
  }

  function dispose() {
    disposed = true;
    generation += 1;
    active?.controller.abort();
    active = null;
    paused = null;
  }

  return {
    start,
    recoverStored,
    resume,
    suspendForSignOut,
    signOutFailed,
    dispose,
    get state() {
      return state;
    },
  };
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

function waitForSourceCreatePoll(milliseconds: number, signal: AbortSignal) {
  if (signal.aborted) return Promise.resolve(false);
  return new Promise<boolean>((resolve) => {
    const timeout = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve(true);
    }, milliseconds);
    const abort = () => {
      clearTimeout(timeout);
      signal.removeEventListener("abort", abort);
      resolve(false);
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}

function requestCancelled() {
  return {
    ok: false,
    error: new ApiError({
      code: "request_cancelled",
      displayMessage: "The request was cancelled.",
      requestId: null,
      status: 0,
    }),
  } as const;
}

function unexpectedRequestError() {
  return new ApiError({
    code: "unexpected_client_error",
    displayMessage: "The request ended unexpectedly. Try again.",
    requestId: null,
    status: 0,
  });
}

function storageUnavailableError() {
  return new ApiError({
    code: "source_create_storage_unavailable",
    displayMessage:
      "Secure tab storage is unavailable. Executor did not start a new source connection.",
    requestId: null,
    status: 0,
  });
}

function randomnessUnavailableError() {
  return new ApiError({
    code: "source_create_randomness_unavailable",
    displayMessage:
      "Secure browser randomness is unavailable. Executor did not start a new source connection.",
    requestId: null,
    status: 0,
  });
}

function terminalStatusError(status: Exclude<SourceCreationStatus, "missing" | "in_progress">) {
  if (status === "abandoned") {
    return new ApiError({
      code: "idempotency_abandoned",
      displayMessage: "The unused source connection key was sealed. You can start a new request.",
      requestId: null,
      status: 409,
    });
  }
  if (status === "interrupted") {
    return new ApiError({
      code: "idempotency_interrupted",
      displayMessage: "The source connection was interrupted and cannot be retried.",
      requestId: null,
      status: 409,
    });
  }
  return new ApiError({
    code: "idempotency_expired_unknown",
    displayMessage: "The source connection record expired without a confirmable outcome.",
    requestId: null,
    status: 409,
  });
}
