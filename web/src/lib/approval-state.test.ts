import { describe, expect, it } from "@effect/vitest";
import type { ApprovalDetail } from "$lib/api";
import {
  approvalCountdown,
  approvalDecisionCopy,
  approvalStatusLabel,
  canDecideApproval,
  createApprovalPoller,
  decisionResultScope,
  focusTargetAfterDecision,
} from "./approval-state";

function fixture(overrides: Partial<ApprovalDetail> = {}): ApprovalDetail {
  return {
    id: "approval-1",
    status: "pending",
    revision: 4,
    createdAt: 100,
    updatedAt: 101,
    expiresAt: 200,
    decidedAt: null,
    completedAt: null,
    sourceId: "source-1",
    toolId: "tool-1",
    path: "tools.github.create_issue",
    sourceDisplayName: "GitHub",
    toolDisplayName: "Create issue",
    actorKind: "api_token",
    actorId: "token-1",
    actorName: "Laptop",
    actorLabel: "Laptop",
    actorApiTokenId: "token-1",
    actorTokenName: "Laptop",
    surface: "gateway",
    mode: "ask",
    provenance: "tool_override",
    executionId: "execution-1",
    callId: "call-1",
    redactedArguments: { title: "Safe title", token: "[REDACTED]" },
    inputSchema: { type: "object" },
    failureCode: null,
    startedAt: null,
    decision: null,
    ...overrides,
  };
}

describe("approval UI state", () => {
  it("labels every terminal and uncertain state honestly", () => {
    expect(approvalStatusLabel("stale")).toBe("Stale");
    expect(approvalStatusLabel("interrupted")).toBe("Interrupted");
    expect(approvalStatusLabel("canceled")).toBe("Canceled");
  });

  it("only permits decisions while the approval is pending and unexpired", () => {
    expect(canDecideApproval(fixture(), 150_000)).toBe(true);
    expect(canDecideApproval(fixture({ status: "approved" }), 150_000)).toBe(false);
    expect(canDecideApproval(fixture({ status: "stale" }), 150_000)).toBe(false);
    expect(canDecideApproval(fixture(), 200_000)).toBe(false);
  });

  it("computes countdown text with an injected clock", () => {
    expect(approvalCountdown(200, 150_000)).toBe("50s remaining");
    expect(approvalCountdown(250, 150_000)).toBe("2m remaining");
    expect(approvalCountdown(150, 150_000)).toBe("Expired");
  });

  it("restates the tool and side-effect boundary in confirmations", () => {
    expect(approvalDecisionCopy(fixture(), "approve")).toContain(
      "stored original arguments, including values hidden from this structural preview",
    );
    expect(approvalDecisionCopy(fixture(), "approve")).toContain(
      "This may cause side effects in GitHub.",
    );
    expect(approvalDecisionCopy(fixture(), "deny")).toContain("waiting caller will not run");
  });

  it("uses safe confirmation fallbacks when snapshot names are unavailable", () => {
    const approval = fixture({
      sourceDisplayName: null,
      toolDisplayName: null,
    });
    expect(approvalDecisionCopy(approval, "approve")).toContain(
      "Approve one execution of tools.github.create_issue?",
    );
    expect(approvalDecisionCopy(approval, "approve")).toContain("the connected source");
  });

  it("chooses a stable focus target after a decision removes a pending row", () => {
    const first = fixture();
    const second = fixture({ id: "approval-2" });
    const third = fixture({ id: "approval-3" });
    expect(focusTargetAfterDecision([first, second, third], second.id)).toBe(
      "inspect-approval-approval-3",
    );
    expect(focusTargetAfterDecision([first], first.id)).toBe("approvals-heading");
  });

  it("rejects a late decision result for a newer detail or list identity", () => {
    expect(
      decisionResultScope({
        submittedApprovalId: "approval-a",
        submittedListKey: "pending:first",
        currentApprovalId: "approval-b",
        currentListKey: "pending:first",
      }),
    ).toEqual({ sameDetail: false, sameList: true });
    expect(
      decisionResultScope({
        submittedApprovalId: "approval-a",
        submittedListKey: "pending:first",
        currentApprovalId: "approval-a",
        currentListKey: "denied:first",
      }),
    ).toEqual({ sameDetail: true, sameList: false });
  });

  it("polls only completed resources and cancels the scheduled retry on disposal", () => {
    let listLoading = true;
    let detailLoading = true;
    let listRefreshes = 0;
    let detailRefreshes = 0;
    let nextHandle = 0;
    const scheduled = new Map<number, () => void>();
    const canceled: number[] = [];
    const dispose = createApprovalPoller({
      schedule: (callback) => {
        const handle = ++nextHandle;
        scheduled.set(handle, callback);
        return handle;
      },
      cancel: (handle) => canceled.push(handle),
      isVisible: () => true,
      isListLoading: () => listLoading,
      hasDetail: () => true,
      isDetailLoading: () => detailLoading,
      refreshList: () => (listRefreshes += 1),
      refreshDetail: () => (detailRefreshes += 1),
    });

    scheduled.get(1)?.();
    expect([listRefreshes, detailRefreshes]).toEqual([0, 0]);
    listLoading = false;
    detailLoading = false;
    scheduled.get(2)?.();
    expect([listRefreshes, detailRefreshes]).toEqual([1, 1]);
    dispose();
    expect(canceled).toEqual([3]);
    scheduled.get(3)?.();
    expect([listRefreshes, detailRefreshes]).toEqual([1, 1]);
  });
});
