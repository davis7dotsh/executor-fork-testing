import { afterEach, describe, expect, it, vi } from "@effect/vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/svelte";
import type { ApprovalDetail, ApprovalPage, ApprovalSummary } from "$lib/api";

const auth = {
  authenticated: true,
  username: "admin",
  recoverFromApiError: vi.fn(() => false),
  signOut: vi.fn(async () => ({ ok: true as const, value: undefined })),
};
const fallbackGoto = vi.fn(async () => {});

vi.doMock("$app/navigation", () => ({ goto: fallbackGoto }));
vi.doMock("$app/state", () => ({ page: { url: new URL("http://localhost/approvals") } }));
vi.doMock("$lib/auth.svelte", () => ({ useAuthState: () => auth }));

const { default: ApprovalsPageHarness } = await import("./approvals-page.test-harness.svelte");

function approvalSummary(overrides: Partial<ApprovalSummary> = {}) {
  const now = Math.floor(Date.now() / 1_000);
  return {
    id: "approval-1",
    status: "pending",
    revision: 7,
    sourceId: "source-1",
    toolId: "tool-1",
    path: "tools.product_api.create_issue",
    sourceDisplayName: "Product API",
    toolDisplayName: "Create issue",
    actorKind: "api_token",
    actorId: "actor-1",
    actorName: "Automation",
    actorLabel: "Automation token",
    actorApiTokenId: "token-1",
    actorTokenName: "Automation",
    surface: "gateway",
    mode: "ask",
    provenance: "intrinsic",
    executionId: "execution-1",
    callId: "call-1",
    createdAt: now - 10,
    updatedAt: now - 5,
    expiresAt: now + 3_600,
    decidedAt: null,
    startedAt: null,
    completedAt: null,
    decision: null,
    failureCode: null,
    ...overrides,
  } satisfies ApprovalSummary;
}

function approvalDetail(overrides: Partial<ApprovalDetail> = {}) {
  return {
    ...approvalSummary(overrides),
    redactedArguments: { title: "[redacted]" },
    inputSchema: { type: "object" },
    ...overrides,
  } satisfies ApprovalDetail;
}

function approvalPage(items: readonly ApprovalSummary[] = []) {
  return Response.json({ items, nextCursor: null } satisfies ApprovalPage);
}

function errorResponse(status: number, code: string, message: string, requestId = "test-request") {
  return Response.json({ error: { code, message, requestId } }, { status });
}

function deferred<Value>() {
  let resolve = (_value: Value) => {};
  let reject = (_reason?: unknown) => {};
  const promise = new Promise<Value>((complete, fail) => {
    resolve = complete;
    reject = fail;
  });
  return { promise, resolve, reject };
}

function manualPollEnvironment() {
  let callback: (() => void) | null = null;
  let activeHandle = 0;
  return {
    environment: {
      schedule(next: () => void) {
        callback = next;
        activeHandle += 1;
        return activeHandle;
      },
      cancel(handle: number) {
        if (handle === activeHandle) callback = null;
      },
      isVisible: () => true,
    },
    trigger() {
      const next = callback;
      callback = null;
      next?.();
    },
  };
}

async function approveOnce() {
  const start = await screen.findByRole<HTMLButtonElement>("button", { name: "Approve once" });
  await waitFor(() => expect(start.disabled).toBe(false));
  await fireEvent.click(start);
  const confirmation = await screen.findByRole("group", { name: "Confirm approval" });
  await fireEvent.click(within(confirmation).getByRole("button", { name: "Yes, approve once" }));
}

afterEach(() => {
  cleanup();
  auth.authenticated = true;
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("Approvals page request coordination", () => {
  it("allows a current pending detail decision while the list request never resolves", async () => {
    const heldList = deferred<Response>();
    const decisions: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path.startsWith("/api/v1/approvals?")) return heldList.promise;
        if (path === "/api/v1/approvals/approval-1/decision" && init?.method === "POST") {
          decisions.push(String(init.body));
          return Promise.resolve(
            Response.json(
              approvalDetail({
                status: "approved",
                revision: 8,
                decision: "approve",
                decidedAt: Math.floor(Date.now() / 1_000),
              }),
            ),
          );
        }
        if (path === "/api/v1/approvals/approval-1") {
          return Promise.resolve(Response.json(approvalDetail()));
        }
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    render(ApprovalsPageHarness, {
      initialUrl: "http://localhost/approvals?approval=approval-1",
    });

    await approveOnce();

    await waitFor(() => expect(decisions).toHaveLength(1));
    expect(decisions).toEqual([JSON.stringify({ decision: "approve", expectedRevision: 7 })]);
  });

  it("keeps decisions available when a silent background list refresh fails", async () => {
    const poll = manualPollEnvironment();
    const failedRefresh = deferred<Response>();
    const backgroundDetail = deferred<Response>();
    let listCalls = 0;
    let detailCalls = 0;
    let decisionCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path.startsWith("/api/v1/approvals?")) {
          listCalls += 1;
          return listCalls === 1
            ? Promise.resolve(approvalPage([approvalSummary()]))
            : failedRefresh.promise;
        }
        if (path === "/api/v1/approvals/approval-1/decision" && init?.method === "POST") {
          decisionCalls += 1;
          return Promise.resolve(
            Response.json(
              approvalDetail({
                status: "approved",
                revision: 8,
                decision: "approve",
                decidedAt: Math.floor(Date.now() / 1_000),
              }),
            ),
          );
        }
        if (path === "/api/v1/approvals/approval-1") {
          detailCalls += 1;
          if (detailCalls === 1) return Promise.resolve(Response.json(approvalDetail()));
          if (detailCalls === 2) return backgroundDetail.promise;
          return Promise.resolve(Response.json(approvalDetail()));
        }
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    render(ApprovalsPageHarness, {
      initialUrl: "http://localhost/approvals?approval=approval-1",
      pollEnvironment: poll.environment,
    });

    const approve = await screen.findByRole<HTMLButtonElement>("button", { name: "Approve once" });
    await waitFor(() => expect(approve.disabled).toBe(false));
    poll.trigger();
    await waitFor(() => {
      expect(listCalls).toBe(2);
      expect(detailCalls).toBe(2);
    });
    expect(screen.getByText("Refreshing...").getAttribute("role")).toBeNull();
    expect(screen.getByText("Refreshing approval detail...").getAttribute("role")).toBeNull();

    backgroundDetail.resolve(Response.json(approvalDetail()));
    await waitFor(() => expect(approve.disabled).toBe(false));
    failedRefresh.reject("offline");
    const refreshError = await screen.findByText(
      "Executor could not be reached. Check that the local server is running.",
    );
    expect(refreshError.closest(".notice")?.getAttribute("role") ?? null).toBeNull();
    const staleNotice = refreshError.closest(".stale-notice");
    expect(staleNotice?.getAttribute("role")).toBe("status");
    await waitFor(() => expect(approve.disabled).toBe(false));

    poll.trigger();
    await waitFor(() => {
      expect(listCalls).toBe(3);
      expect(detailCalls).toBe(3);
    });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByRole("status")).toBe(staleNotice);
    expect(
      screen
        .getByText("Executor could not be reached. Check that the local server is running.")
        .closest(".stale-notice"),
    ).toBe(staleNotice);

    await approveOnce();
    await waitFor(() => expect(decisionCalls).toBe(1));
  });

  it("keeps an initial list error mounted through passive retries", async () => {
    const poll = manualPollEnvironment();
    const initialLoad = deferred<Response>();
    const firstRetry = deferred<Response>();
    const secondRetry = deferred<Response>();
    let listCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path.startsWith("/api/v1/approvals?")) {
          listCalls += 1;
          if (listCalls === 1) return initialLoad.promise;
          if (listCalls === 2) return firstRetry.promise;
          return secondRetry.promise;
        }
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    render(ApprovalsPageHarness, {
      initialUrl: "http://localhost/approvals",
      pollEnvironment: poll.environment,
    });

    initialLoad.resolve(errorResponse(503, "initial_failure", "Initial list failure", "list-a"));
    const errorText = await screen.findByText("Initial list failure");
    const errorAlert = errorText.closest(".notice");
    expect(errorAlert?.getAttribute("role")).toBe("alert");
    expect(screen.getByText("list-a")).toBeDefined();

    poll.trigger();
    await waitFor(() => expect(listCalls).toBe(2));
    expect(screen.getByText("Loading approvals...").getAttribute("aria-live")).toBeNull();
    expect(screen.getByText("Initial list failure").closest(".notice")).toBe(errorAlert);
    firstRetry.resolve(errorResponse(502, "retry_failure", "Second list failure", "list-b"));
    await waitFor(() =>
      expect(screen.getByRole<HTMLButtonElement>("button", { name: "Refresh" }).disabled).toBe(
        false,
      ),
    );

    poll.trigger();
    await waitFor(() => expect(listCalls).toBe(3));
    expect(screen.getByText("Loading approvals...").getAttribute("aria-live")).toBeNull();
    expect(screen.getByRole("alert")).toBe(errorAlert);
    expect(screen.getByText("Initial list failure")).toBeDefined();
    expect(screen.getByText("list-a")).toBeDefined();
    expect(screen.queryByText("Second list failure")).toBeNull();
    expect(screen.queryByText("list-b")).toBeNull();
    secondRetry.resolve(errorResponse(500, "retry_failure", "Third list failure", "list-c"));
    await waitFor(() =>
      expect(screen.getByRole<HTMLButtonElement>("button", { name: "Refresh" }).disabled).toBe(
        false,
      ),
    );
    expect(screen.getByRole("alert")).toBe(errorAlert);
    expect(screen.getByText("Initial list failure")).toBeDefined();
    expect(screen.getByText("list-a")).toBeDefined();
    expect(screen.queryByText("Third list failure")).toBeNull();
    expect(screen.queryByText("list-c")).toBeNull();
  });

  it("keeps a passive detail error mounted through its next passive retry", async () => {
    const poll = manualPollEnvironment();
    const firstFailure = deferred<Response>();
    const secondFailure = deferred<Response>();
    let detailCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path.startsWith("/api/v1/approvals?")) {
          return Promise.resolve(approvalPage([approvalSummary()]));
        }
        if (path === "/api/v1/approvals/approval-1") {
          detailCalls += 1;
          if (detailCalls === 1) return Promise.resolve(Response.json(approvalDetail()));
          if (detailCalls === 2) return firstFailure.promise;
          return secondFailure.promise;
        }
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    render(ApprovalsPageHarness, {
      initialUrl: "http://localhost/approvals?approval=approval-1",
      pollEnvironment: poll.environment,
    });

    await screen.findByRole("button", { name: "Approve once" });
    poll.trigger();
    await waitFor(() => expect(detailCalls).toBe(2));
    firstFailure.resolve(
      errorResponse(503, "initial_failure", "Initial detail failure", "detail-a"),
    );
    const errorText = await screen.findByText("Initial detail failure");
    const errorAlert = errorText.closest(".notice");
    expect(errorAlert?.getAttribute("role")).toBe("alert");
    expect(screen.getByText("detail-a")).toBeDefined();

    poll.trigger();
    await waitFor(() => expect(detailCalls).toBe(3));
    expect(screen.queryByText("Loading approval detail...")).toBeNull();
    expect(screen.getByRole("alert")).toBe(errorAlert);
    expect(screen.getByText("Initial detail failure").closest(".notice")).toBe(errorAlert);
    secondFailure.resolve(errorResponse(502, "retry_failure", "Second detail failure", "detail-b"));
    await waitFor(() =>
      expect(document.getElementById("approval-detail-panel")?.getAttribute("aria-busy")).toBe(
        "false",
      ),
    );
    expect(screen.getByRole("alert")).toBe(errorAlert);
    expect(screen.getByText("Initial detail failure")).toBeDefined();
    expect(screen.getByText("detail-a")).toBeDefined();
    expect(screen.queryByText("Second detail failure")).toBeNull();
    expect(screen.queryByText("detail-b")).toBeNull();
  });

  it("keeps decision controls disabled without an authenticated admin", async () => {
    auth.authenticated = false;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path.startsWith("/api/v1/approvals?")) {
          return Promise.resolve(approvalPage([approvalSummary()]));
        }
        if (path === "/api/v1/approvals/approval-1") {
          return Promise.resolve(Response.json(approvalDetail()));
        }
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    render(ApprovalsPageHarness, {
      initialUrl: "http://localhost/approvals?approval=approval-1",
    });

    const approve = await screen.findByRole<HTMLButtonElement>("button", { name: "Approve once" });
    const deny = screen.getByRole<HTMLButtonElement>("button", { name: "Deny" });
    expect(approve.disabled).toBe(true);
    expect(deny.disabled).toBe(true);
  });

  it("resets list data when a new filter request is held and then rejected", async () => {
    const deniedPage = deferred<Response>();
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path.includes("status=pending")) {
          return Promise.resolve(
            approvalPage([approvalSummary({ id: "approval-a", toolDisplayName: "Alpha tool" })]),
          );
        }
        if (path.includes("status=denied")) return deniedPage.promise;
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    render(ApprovalsPageHarness, { initialUrl: "http://localhost/approvals" });

    expect(await screen.findByRole("heading", { name: "Alpha tool" })).toBeDefined();
    await fireEvent.change(screen.getByLabelText("Status"), { target: { value: "denied" } });

    expect(await screen.findByText("Loading approvals...")).toBeDefined();
    expect(screen.queryByRole("heading", { name: "Alpha tool" })).toBeNull();
    deniedPage.reject("offline");
    expect(
      await screen.findByText(
        "Executor could not be reached. Check that the local server is running.",
      ),
    ).toBeDefined();
    expect(screen.queryByRole("heading", { name: "Alpha tool" })).toBeNull();
  });

  it("ignores an out-of-order list response from the replaced filter identity", async () => {
    const pendingPage = deferred<Response>();
    const pendingRequest = { signal: null as AbortSignal | null };
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path.includes("status=pending")) {
          pendingRequest.signal = init?.signal ?? null;
          return pendingPage.promise;
        }
        if (path.includes("status=denied")) {
          return Promise.resolve(
            approvalPage([
              approvalSummary({
                id: "approval-b",
                status: "denied",
                toolDisplayName: "Beta tool",
              }),
            ]),
          );
        }
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    render(ApprovalsPageHarness, { initialUrl: "http://localhost/approvals" });
    await waitFor(() => expect(pendingRequest.signal).not.toBeNull());
    await fireEvent.change(screen.getByLabelText("Status"), { target: { value: "denied" } });

    expect(await screen.findByRole("heading", { name: "Beta tool" })).toBeDefined();
    expect(pendingRequest.signal?.aborted).toBe(true);
    pendingPage.resolve(
      approvalPage([approvalSummary({ id: "approval-a", toolDisplayName: "Alpha tool" })]),
    );
    await pendingPage.promise;
    await Promise.resolve();
    await Promise.resolve();

    expect(screen.getByRole("heading", { name: "Beta tool" })).toBeDefined();
    expect(screen.queryByRole("heading", { name: "Alpha tool" })).toBeNull();
  });

  it("closes an existing confirmation when a background detail refresh changes status", async () => {
    const poll = manualPollEnvironment();
    let detailCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input) => {
        const path = String(input);
        if (path.startsWith("/api/v1/approvals?")) {
          return Promise.resolve(approvalPage([approvalSummary()]));
        }
        if (path === "/api/v1/approvals/approval-1") {
          detailCalls += 1;
          return Promise.resolve(
            Response.json(
              detailCalls === 1
                ? approvalDetail()
                : approvalDetail({ status: "denied", revision: 8, decision: "deny" }),
            ),
          );
        }
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    render(ApprovalsPageHarness, {
      initialUrl: "http://localhost/approvals?approval=approval-1",
      pollEnvironment: poll.environment,
    });

    const approve = await screen.findByRole<HTMLButtonElement>("button", { name: "Approve once" });
    await waitFor(() => expect(approve.disabled).toBe(false));
    await fireEvent.click(approve);
    expect(await screen.findByRole("group", { name: "Confirm approval" })).toBeDefined();

    poll.trigger();

    expect(await screen.findByText("This request can no longer be decided.")).toBeDefined();
    expect(screen.queryByRole("group", { name: "Confirm approval" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve once" })).toBeNull();
  });

  it("fences a conflicting decision until a newer detail revision loads", async () => {
    const rollbackDetail = deferred<Response>();
    const newerDetail = deferred<Response>();
    let detailCalls = 0;
    const decisionBodies: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path.startsWith("/api/v1/approvals?")) {
          return Promise.resolve(approvalPage([approvalSummary()]));
        }
        if (path === "/api/v1/approvals/approval-1") {
          detailCalls += 1;
          if (detailCalls === 1) return Promise.resolve(Response.json(approvalDetail()));
          if (detailCalls === 2) return rollbackDetail.promise;
          return newerDetail.promise;
        }
        if (path === "/api/v1/approvals/approval-1/decision" && init?.method === "POST") {
          decisionBodies.push(String(init.body));
          return Promise.resolve(errorResponse(409, "approval_conflict", "The approval changed."));
        }
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    render(ApprovalsPageHarness, {
      initialUrl: "http://localhost/approvals?approval=approval-1",
    });

    await approveOnce();
    await waitFor(() => expect(detailCalls).toBe(2));
    const approve = await screen.findByRole<HTMLButtonElement>("button", { name: "Approve once" });
    expect(approve.disabled).toBe(true);
    await fireEvent.click(approve);
    expect(decisionBodies).toEqual([JSON.stringify({ decision: "approve", expectedRevision: 7 })]);

    rollbackDetail.resolve(Response.json(approvalDetail({ revision: 6 })));
    await waitFor(() =>
      expect(screen.getByRole<HTMLButtonElement>("button", { name: "Approve once" }).disabled).toBe(
        true,
      ),
    );
    await fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(detailCalls).toBe(3));
    newerDetail.resolve(Response.json(approvalDetail({ revision: 8 })));
    await waitFor(() =>
      expect(screen.getByRole<HTMLButtonElement>("button", { name: "Approve once" }).disabled).toBe(
        false,
      ),
    );
    expect(screen.queryByText("The approval changed.")).toBeNull();
  });

  it("aborts list and detail loads on unmount and ignores their late responses", async () => {
    const list = deferred<Response>();
    const detail = deferred<Response>();
    const requests = {
      listSignal: null as AbortSignal | null,
      detailSignal: null as AbortSignal | null,
    };
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>((input, init) => {
        const path = String(input);
        if (path.startsWith("/api/v1/approvals?")) {
          requests.listSignal = init?.signal ?? null;
          return list.promise;
        }
        if (path === "/api/v1/approvals/approval-1") {
          requests.detailSignal = init?.signal ?? null;
          return detail.promise;
        }
        return Promise.resolve(errorResponse(500, "unexpected_test_request", path));
      }),
    );

    const rendered = render(ApprovalsPageHarness, {
      initialUrl: "http://localhost/approvals?approval=approval-1",
    });
    await waitFor(() => {
      expect(requests.listSignal).not.toBeNull();
      expect(requests.detailSignal).not.toBeNull();
    });

    rendered.unmount();
    expect(requests.listSignal?.aborted).toBe(true);
    expect(requests.detailSignal?.aborted).toBe(true);
    list.resolve(approvalPage([approvalSummary()]));
    detail.resolve(Response.json(approvalDetail()));
    await Promise.all([list.promise, detail.promise]);
    await Promise.resolve();
    await Promise.resolve();

    expect(rendered.container.innerHTML).toBe("");
  });
});
