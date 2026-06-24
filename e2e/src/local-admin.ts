export interface LocalTool {
  readonly id: string;
  readonly sourceId: string;
  readonly stableKey: string;
  readonly displayName: string;
  readonly callablePath: string;
  readonly revision: number;
  readonly effectiveMode: { readonly mode: "enabled" | "ask" | "disabled" };
}

export interface LocalSource {
  readonly id: string;
  readonly slug: string;
  readonly displayName: string;
  readonly revision: number;
  readonly toolCount: number;
}

export interface LocalToken {
  readonly id: string;
  readonly token: string;
}

export class LocalAdminClient {
  readonly #origin: string;
  readonly #cookie: string;
  readonly #csrf: string;

  private constructor(origin: string, cookie: string, csrf: string) {
    this.#origin = origin;
    this.#cookie = cookie;
    this.#csrf = csrf;
  }

  static async signIn(origin: string, username: string, password: string) {
    const response = await fetch(new URL("/api/v1/session", origin), {
      method: "POST",
      headers: { "content-type": "application/json", origin: new URL(origin).origin },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) throw new Error(`administrator sign-in failed (${response.status})`);
    const pairs = response.headers
      .getSetCookie()
      .map((cookie) => cookie.split(";", 1)[0]?.trim())
      .filter((cookie): cookie is string => Boolean(cookie));
    const csrf = pairs
      .find((cookie) => cookie.startsWith("executor_csrf="))
      ?.slice("executor_csrf=".length);
    if (pairs.length === 0 || !csrf)
      throw new Error("administrator sign-in returned no CSRF cookie");
    return new LocalAdminClient(origin, pairs.join("; "), csrf);
  }

  async createToken(name: string) {
    return this.#json<LocalToken>("/api/v1/tokens", { method: "POST", body: { name } });
  }

  async revokeToken(tokenId: string) {
    await this.#request(`/api/v1/tokens/${encodeURIComponent(tokenId)}`, { method: "DELETE" });
  }

  async createSource(input: unknown) {
    return this.#json<LocalSource>("/api/v1/sources", { method: "POST", body: input });
  }

  async deleteSource(sourceId: string) {
    await this.#request(`/api/v1/sources/${encodeURIComponent(sourceId)}`, { method: "DELETE" });
  }

  async refreshSource(sourceId: string) {
    await this.#request(`/api/v1/sources/${encodeURIComponent(sourceId)}/refresh`, {
      method: "POST",
      body: {},
    });
  }

  async listTools(query: { readonly sourceId?: string; readonly q?: string } = {}) {
    const parameters = new URLSearchParams({ limit: "100" });
    if (query.sourceId) parameters.set("sourceId", query.sourceId);
    if (query.q) parameters.set("query", query.q);
    return this.#json<{ readonly items: readonly LocalTool[]; readonly catalogRevision: number }>(
      `/api/v1/tools?${parameters}`,
    );
  }

  async setToolMode(tool: LocalTool, mode: "enabled" | "ask" | "disabled" | null) {
    return this.#json<LocalTool>(`/api/v1/tools/${encodeURIComponent(tool.id)}/mode`, {
      method: "PATCH",
      body: { mode, expectedRevision: tool.revision },
    });
  }

  async putOAuthConnection(sourceId: string, credentialKey: string, input: unknown) {
    return this.#json<{ readonly revision: number; readonly callbackUrl: string }>(
      `/api/v1/sources/${encodeURIComponent(sourceId)}/oauth/${encodeURIComponent(credentialKey)}`,
      { method: "PUT", body: input },
    );
  }

  async authorizeOAuthConnection(
    sourceId: string,
    credentialKey: string,
    expectedRevision: number,
  ) {
    return this.#json<{ readonly authorizationUrl: string }>(
      `/api/v1/sources/${encodeURIComponent(sourceId)}/oauth/${encodeURIComponent(credentialKey)}/authorize`,
      { method: "POST", body: { expectedRevision } },
    );
  }

  async getOAuthConnections(sourceId: string) {
    return this.#json<{
      readonly connections: ReadonlyArray<{
        readonly credentialKey: string;
        readonly status: string;
        readonly callbackUrl: string;
      }>;
      readonly availableCredentials: ReadonlyArray<{ readonly credentialKey: string }>;
    }>(`/api/v1/sources/${encodeURIComponent(sourceId)}/oauth`);
  }

  async #json<Value>(
    path: string,
    options: { readonly method?: string; readonly body?: unknown } = {},
  ) {
    const response = await this.#request(path, options);
    return (await response.json()) as Value;
  }

  async #request(
    path: string,
    options: { readonly method?: string; readonly body?: unknown } = {},
  ) {
    const method = options.method ?? "GET";
    const headers = new Headers({ accept: "application/json", cookie: this.#cookie });
    if (options.body !== undefined) headers.set("content-type", "application/json");
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      headers.set("origin", new URL(this.#origin).origin);
      headers.set("x-executor-csrf", this.#csrf);
    }
    const response = await fetch(new URL(path, this.#origin), {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    if (!response.ok) {
      throw new Error(`${method} ${path} failed (${response.status}): ${await response.text()}`);
    }
    return response;
  }
}
