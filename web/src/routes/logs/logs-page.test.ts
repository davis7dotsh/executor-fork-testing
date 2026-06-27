import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/svelte";
import type { RequestLog, RequestLogPage } from "$lib/api";
import LogsPageHarness from "./logs-page.test-harness.svelte";

function requestLog(requestId: string) {
  return {
    requestId,
    actorApiTokenId: null,
    surface: "gateway",
    sourceId: "source-1",
    toolId: "tool-1",
    pathSnapshot: `tools.source_1.${requestId}`,
    outcome: "succeeded",
    errorCode: null,
    durationMs: 12,
    approvalId: null,
    createdAt: 100,
  } satisfies RequestLog;
}

function logPage(requestId: string, nextCursor: string | null = null) {
  return Response.json({ items: [requestLog(requestId)], nextCursor } satisfies RequestLogPage);
}

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  let reject = (_error: unknown) => {};
  const promise = new Promise<Value>((complete, fail) => {
    resolve = complete;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function errorResponse(code: string, message: string, status = 503) {
  return Response.json({ error: { code, message, requestId: `${code}-request` } }, { status });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("Request logs list identity", () => {
  it("does not present cursor A as cursor B while B is held or after B is rejected", async () => {
    const pageB = deferred<Response>();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path === "/api/v1/request-logs?limit=50&cursor=cursor-a") {
          return Promise.resolve(logPage("request-a"));
        }
        if (path === "/api/v1/request-logs?limit=50&cursor=cursor-b") return pageB.promise;
        return Promise.resolve(errorResponse("unexpected_test_request", path, 500));
      }),
    );
    const mounted = render(LogsPageHarness, { search: "?cursor=cursor-a" });

    expect(await screen.findByText("request-a")).toBeDefined();
    await mounted.rerender({ search: "?cursor=cursor-b" });

    expect(screen.queryByText("request-a")).toBeNull();
    expect(screen.getByText("Loading request logs...")).toBeDefined();

    pageB.reject({ _tag: "CursorBNetworkFailure" });

    expect(
      await screen.findByText(
        "Executor could not be reached. Check that the local server is running.",
      ),
    ).toBeDefined();
    expect(screen.queryByText("request-a")).toBeNull();
    expect(
      screen.queryByText("Showing the last loaded request page while Executor reconnects."),
    ).toBeNull();
  });

  it("keeps cursor B after an out-of-order cursor A completion", async () => {
    const pageA = deferred<Response>();
    const pageB = deferred<Response>();
    const signals = new Map<string, AbortSignal>();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        const signal = init?.signal;
        if (signal !== undefined && signal !== null) signals.set(path, signal);
        if (path === "/api/v1/request-logs?limit=50&cursor=cursor-a") return pageA.promise;
        if (path === "/api/v1/request-logs?limit=50&cursor=cursor-b") return pageB.promise;
        return Promise.resolve(errorResponse("unexpected_test_request", path, 500));
      }),
    );
    const mounted = render(LogsPageHarness, { search: "?cursor=cursor-a" });

    await waitFor(() => expect(signals.size).toBe(1));
    await mounted.rerender({ search: "?cursor=cursor-b" });
    await waitFor(() => expect(signals.size).toBe(2));
    expect(signals.get("/api/v1/request-logs?limit=50&cursor=cursor-a")?.aborted).toBe(true);

    pageB.resolve(logPage("request-b"));
    expect(await screen.findByText("request-b")).toBeDefined();
    pageA.resolve(logPage("request-a"));
    await pageA.promise;
    await Promise.resolve();
    await Promise.resolve();

    expect(screen.getByText("request-b")).toBeDefined();
    expect(screen.queryByText("request-a")).toBeNull();
  });

  it("preserves the honestly labeled list across detail-only query changes", async () => {
    let listCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path === "/api/v1/request-logs?limit=50&cursor=cursor-b") {
          listCalls += 1;
          return Promise.resolve(logPage("request-b"));
        }
        if (path === "/api/v1/request-logs/request-b") {
          return Promise.resolve(Response.json(requestLog("request-b")));
        }
        return Promise.resolve(errorResponse("unexpected_test_request", path, 500));
      }),
    );
    const mounted = render(LogsPageHarness, { search: "?cursor=cursor-b" });

    expect(await screen.findByText("request-b")).toBeDefined();
    await mounted.rerender({ search: "?cursor=cursor-b&request=request-b" });

    expect(await screen.findByRole("heading", { name: "request-b" })).toBeDefined();
    expect(screen.getAllByText("request-b").length).toBeGreaterThan(1);
    expect(listCalls).toBe(1);
  });

  it("aborts its active page request and ignores completion after unmount", async () => {
    const pending = deferred<Response>();
    const request = { signal: null as AbortSignal | null };
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path === "/api/v1/request-logs?limit=50&cursor=cursor-a") {
          request.signal = init?.signal ?? null;
          return pending.promise;
        }
        return Promise.resolve(errorResponse("unexpected_test_request", path, 500));
      }),
    );
    const mounted = render(LogsPageHarness, { search: "?cursor=cursor-a" });

    await waitFor(() => expect(request.signal).not.toBeNull());
    mounted.unmount();
    expect(request.signal?.aborted).toBe(true);

    pending.resolve(logPage("request-after-unmount"));
    await pending.promise;
    await Promise.resolve();
    await Promise.resolve();

    expect(screen.queryByText("request-after-unmount")).toBeNull();
  });
});
