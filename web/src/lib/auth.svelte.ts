import { getContext, setContext } from "svelte";
import {
  getBootstrap,
  getSession,
  loginAdmin,
  logoutAdmin,
  setupAdmin,
  type ApiError,
} from "$lib/api";

const authContext = Symbol("executor-auth");

export function createAuthState() {
  let phase = $state<"loading" | "ready" | "error">("loading");
  let setupRequired = $state(false);
  let authenticated = $state(false);
  let username = $state<string | null>(null);
  let error = $state<ApiError | null>(null);
  let notice = $state<string | null>(null);
  let refreshGeneration = 0;
  let mutationGeneration = 0;

  async function refresh(signal?: AbortSignal) {
    const mine = ++refreshGeneration;
    phase = "loading";
    error = null;

    const bootstrap = await getBootstrap(undefined, signal);
    if (mine !== refreshGeneration || signal?.aborted) return;
    if (!bootstrap.ok) {
      if (recoverFromApiError(bootstrap.error)) return;
      error = bootstrap.error;
      phase = "error";
      return;
    }

    let nextUsername: string | null = null;

    if (bootstrap.value.authenticated) {
      const session = await getSession(undefined, signal);
      if (mine !== refreshGeneration || signal?.aborted) return;
      if (!session.ok) {
        if (recoverFromApiError(session.error)) return;
        error = session.error;
        phase = "error";
        return;
      }
      nextUsername = session.value.username;
    }

    if (mine !== refreshGeneration || signal?.aborted) return;
    setupRequired = bootstrap.value.setupRequired;
    authenticated = bootstrap.value.authenticated;
    username = nextUsername;
    phase = "ready";
  }

  async function signIn(input: { username: string; password: string }) {
    const mine = beginMutation();
    const session = await loginAdmin(input);
    settleMutation();
    if (mine !== mutationGeneration) return session;
    if (!session.ok) return session;
    setupRequired = false;
    authenticated = true;
    username = session.value.username;
    notice = null;
    error = null;
    phase = "ready";
    return session;
  }

  async function completeSetup(input: { setupToken: string; username: string; password: string }) {
    const mine = beginMutation();
    const setup = await setupAdmin(input);
    if (mine !== mutationGeneration) {
      settleMutation();
      return setup;
    }
    if (!setup.ok) {
      settleMutation();
      return setup;
    }

    const login = await loginAdmin({ username: input.username, password: input.password });
    settleMutation();
    if (mine !== mutationGeneration) return login;
    if (!login.ok) {
      setupRequired = false;
      authenticated = false;
      username = null;
      notice =
        "Your administrator was created, but automatic sign-in failed. Sign in with the credentials you just chose.";
      error = null;
      phase = "ready";
      return login;
    }

    setupRequired = false;
    authenticated = true;
    username = login.value.username;
    notice = null;
    error = null;
    phase = "ready";
    return login;
  }

  async function signOut() {
    const mine = beginMutation();
    const logout = await logoutAdmin();
    settleMutation();
    if (mine !== mutationGeneration) return logout;
    if (!logout.ok) {
      recoverFromApiError(logout.error);
      return logout;
    }
    authenticated = false;
    username = null;
    notice = null;
    return logout;
  }

  function recoverFromApiError(apiError: ApiError) {
    if (apiError.status !== 401 && apiError.code !== "invalid_csrf") return false;

    mutationGeneration += 1;
    refreshGeneration += 1;
    authenticated = false;
    username = null;
    error = null;
    notice =
      apiError.code === "invalid_csrf"
        ? "Your security token is no longer valid. Sign in again to continue."
        : "Your session expired. Sign in again to continue.";
    phase = "ready";
    return true;
  }

  function beginMutation() {
    refreshGeneration += 1;
    mutationGeneration += 1;
    return mutationGeneration;
  }

  function settleMutation() {
    refreshGeneration += 1;
    phase = "ready";
  }

  function clearNotice() {
    notice = null;
  }

  function dispose() {
    refreshGeneration += 1;
    mutationGeneration += 1;
  }

  return {
    get phase() {
      return phase;
    },
    get setupRequired() {
      return setupRequired;
    },
    get authenticated() {
      return authenticated;
    },
    get username() {
      return username;
    },
    get error() {
      return error;
    },
    get notice() {
      return notice;
    },
    refresh,
    signIn,
    completeSetup,
    signOut,
    recoverFromApiError,
    clearNotice,
    dispose,
  };
}

export type AuthState = ReturnType<typeof createAuthState>;

export function provideAuthState(auth: AuthState) {
  setContext(authContext, auth);
}

export function useAuthState() {
  return getContext<AuthState>(authContext);
}
