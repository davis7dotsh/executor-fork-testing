export type TokenListView = "loading" | "unavailable" | "empty" | "ready" | "stale";

export function tokenListView(input: {
  loading: boolean;
  hasLoaded: boolean;
  hasError: boolean;
  tokenCount: number;
}) {
  if (!input.hasLoaded && input.loading) return "loading";
  if (!input.hasLoaded) return input.hasError ? "unavailable" : "loading";
  if (input.hasError) return "stale";
  return input.tokenCount === 0 ? "empty" : "ready";
}

export function canCreateToken(input: {
  name: string;
  creating: boolean;
  hasPendingCreate: boolean;
  hasUnsavedToken: boolean;
}) {
  return (
    input.name.trim() !== "" && !input.creating && !input.hasPendingCreate && !input.hasUnsavedToken
  );
}

export function tokenExitBlockReason(input: {
  creating: boolean;
  hasPendingCreate: boolean;
  hasUnsavedToken: boolean;
}) {
  if (input.creating) return "creating";
  if (input.hasUnsavedToken) return "unsaved-token";
  if (input.hasPendingCreate) return "pending-recovery";
  return null;
}

export function shouldBlockTokenExit(input: {
  creating: boolean;
  hasPendingCreate: boolean;
  hasUnsavedToken: boolean;
}) {
  return tokenExitBlockReason(input) !== null;
}

export function isTokenRecoveryAuthNavigation(input: {
  authenticated: boolean;
  destinationPath: string | null;
}) {
  return !input.authenticated && input.destinationPath === "/login";
}
