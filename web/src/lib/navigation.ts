const protectedRoutes = ["/sources", "/tools", "/approvals", "/logs", "/tokens"];

export function isProtectedPath(pathname: string) {
  return protectedRoutes.some((route) => pathname === route || pathname.startsWith(`${route}/`));
}

export function safeReturnTo(value: string | null, origin: string) {
  if (value === null || !value.startsWith("/") || value.startsWith("//")) return null;

  if (!URL.canParse(value, origin)) return null;
  const url = new URL(value, origin);

  if (url.origin !== origin || !isProtectedPath(url.pathname)) return null;
  return `${url.pathname}${url.search}${safeReturnHash(url.hash)}`;
}

export function safeReturnHash(hash: string) {
  if (hash === "") return "";
  return new URLSearchParams(hash.slice(1)).has("token") ? "" : hash;
}

export function consumeSetupToken(url: URL, replace: (nextUrl: string) => void) {
  if (url.hash === "") return null;

  const token = new URLSearchParams(url.hash.slice(1)).get("token");
  replace(`${url.pathname}${url.search}`);
  return token === null || token === "" ? null : token;
}

export function routeDestination(input: {
  pathname: string;
  search: string;
  hash: string;
  origin: string;
  setupRequired: boolean;
  authenticated: boolean;
}) {
  const { pathname, search, hash, origin, setupRequired, authenticated } = input;

  if (setupRequired) return pathname === "/setup" ? null : "/setup";

  if (authenticated) {
    if (pathname === "/login") {
      const returnTo = new URLSearchParams(search).get("returnTo");
      return safeReturnTo(returnTo, origin) ?? "/sources";
    }
    if (pathname === "/" || pathname === "/setup") return "/sources";
    if (!isProtectedPath(pathname)) return "/sources";
    return null;
  }

  if (pathname === "/login") return null;
  if (isProtectedPath(pathname)) {
    const returnTo = `${pathname}${search}${safeReturnHash(hash)}`;
    return `/login?returnTo=${encodeURIComponent(returnTo)}`;
  }
  return "/login";
}
