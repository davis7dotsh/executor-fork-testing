import type { ApprovalDecision, ApprovalDetail, ApprovalStatus, ApprovalSummary } from "$lib/api";

export const approvalStatuses = [
  "pending",
  "approved",
  "executing",
  "succeeded",
  "failed",
  "denied",
  "expired",
  "canceled",
  "stale",
  "interrupted",
] as const satisfies readonly ApprovalStatus[];

export function approvalStatusLabel(status: ApprovalStatus) {
  return `${status[0].toUpperCase()}${status.slice(1)}`;
}

export function canDecideApproval(approval: ApprovalSummary, now: number) {
  return approval.status === "pending" && approval.expiresAt > Math.floor(now / 1000);
}

export function approvalCountdown(expiresAt: number, now: number) {
  const remaining = expiresAt - Math.floor(now / 1000);
  if (remaining <= 0) return "Expired";
  if (remaining < 60) return `${remaining}s remaining`;
  const minutes = Math.ceil(remaining / 60);
  return `${minutes}m remaining`;
}

export function approvalDecisionCopy(approval: ApprovalDetail, decision: ApprovalDecision) {
  const tool = approval.toolDisplayName ?? approval.path;
  const source = approval.sourceDisplayName ?? "the connected source";
  if (decision === "approve") {
    return `Approve one execution of ${tool}? Executor will use the stored original arguments, including values hidden from this structural preview. This may cause side effects in ${source}.`;
  }
  return `Deny this execution of ${tool}? The waiting caller will not run this request.`;
}

export function focusTargetAfterDecision(items: readonly ApprovalSummary[], approvalId: string) {
  const index = items.findIndex((approval) => approval.id === approvalId);
  const next = items[index + 1] ?? items[index - 1];
  return next === undefined ? "approvals-heading" : `inspect-approval-${next.id}`;
}

export function decisionResultScope(input: {
  readonly submittedApprovalId: string;
  readonly submittedListKey: string;
  readonly currentApprovalId: string | null;
  readonly currentListKey: string;
}) {
  return {
    sameDetail: input.currentApprovalId === input.submittedApprovalId,
    sameList: input.currentListKey === input.submittedListKey,
  };
}

export function createApprovalPoller(
  options: {
    readonly schedule: (callback: () => void, delay: number) => number;
    readonly cancel: (handle: number) => void;
    readonly isVisible: () => boolean;
    readonly isListLoading: () => boolean;
    readonly hasDetail: () => boolean;
    readonly isDetailLoading: () => boolean;
    readonly refreshList: () => void;
    readonly refreshDetail: () => void;
  },
  interval = 5_000,
) {
  let disposed = false;
  let handle = 0;

  function poll() {
    if (disposed) return;
    if (options.isVisible()) {
      if (!options.isListLoading()) options.refreshList();
      if (options.hasDetail() && !options.isDetailLoading()) options.refreshDetail();
    }
    handle = options.schedule(poll, interval);
  }

  handle = options.schedule(poll, interval);
  return () => {
    disposed = true;
    options.cancel(handle);
  };
}
