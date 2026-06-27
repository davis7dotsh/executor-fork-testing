import { ApiError, type ApiResult, type ToolMode } from "$lib/api";

export type ResourceState<Value> = {
  readonly data: Value | null;
  readonly loading: boolean;
  readonly error: ApiError | null;
  readonly stale: boolean;
};

export function emptyResource<Value>(): ResourceState<Value> {
  return { data: null, loading: true, error: null, stale: false };
}

export function beginResourceLoad<Value>(state: ResourceState<Value>) {
  return { ...state, loading: true, error: null };
}

export function beginIdentityResourceLoad<Value>(
  state: ResourceState<Value>,
  currentIdentity: string | null,
  nextIdentity: string,
) {
  return {
    identity: nextIdentity,
    state: currentIdentity === nextIdentity ? beginResourceLoad(state) : emptyResource<Value>(),
  };
}

export function settleResourceLoad<Value>(
  state: ResourceState<Value>,
  result: ApiResult<Value>,
  options: { readonly retainDataOnError?: boolean } = {},
) {
  if (result.ok) {
    return { data: result.value, loading: false, error: null, stale: false };
  }
  const data = options.retainDataOnError === false ? null : state.data;
  return {
    data,
    loading: false,
    error: result.error,
    stale: data !== null,
  };
}

export function unexpectedRequestError() {
  return new ApiError({
    code: "unexpected_client_error",
    displayMessage: "The request ended unexpectedly. Try again.",
    requestId: null,
    status: 0,
  });
}

export function createLatestRequest() {
  let generation = 0;
  let activeController: AbortController | null = null;

  function start<Value>(
    task: (signal: AbortSignal) => Promise<Value>,
    commit: (value: Value) => void,
    reject: (error: unknown) => void,
  ) {
    activeController?.abort();
    const mine = ++generation;
    const controller = new AbortController();
    activeController = controller;
    void task(controller.signal).then(
      (value) => {
        if (!controller.signal.aborted && mine === generation) commit(value);
      },
      (error: unknown) => {
        if (!controller.signal.aborted && mine === generation) reject(error);
      },
    );

    return () => {
      controller.abort();
      if (mine === generation) {
        generation += 1;
        activeController = null;
      }
    };
  }

  return { start };
}

export const toolModes = ["enabled", "ask", "disabled"] as const satisfies readonly ToolMode[];

export function modeLabel(mode: ToolMode) {
  if (mode === "enabled") return "Enabled";
  if (mode === "ask") return "Ask";
  return "Disabled";
}

export function provenanceLabel(provenance: "tool_override" | "source_override" | "intrinsic") {
  if (provenance === "tool_override") return "Tool override";
  if (provenance === "source_override") return "Source default";
  return "Tool default";
}
