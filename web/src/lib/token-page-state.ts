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
  hasUnsavedToken: boolean;
}) {
  return input.name.trim() !== "" && !input.creating && !input.hasUnsavedToken;
}

export function shouldBlockTokenExit(input: { creating: boolean; hasUnsavedToken: boolean }) {
  return input.creating || input.hasUnsavedToken;
}
