import type { ApprovalStatus } from "$lib/api";

const statuses = new Set<ApprovalStatus>([
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
]);

export type ApprovalStatusFilter = ApprovalStatus | "all";

export type ApprovalsUrlState = {
  readonly status: ApprovalStatusFilter;
  readonly cursor: string | null;
  readonly approval: string | null;
};

export function parseApprovalsUrl(parameters: URLSearchParams): ApprovalsUrlState {
  const rawStatus = parameters.get("status");
  return {
    status: rawStatus === "all" || isApprovalStatus(rawStatus) ? rawStatus : "pending",
    cursor: nonEmpty(parameters.get("cursor")),
    approval: nonEmpty(parameters.get("approval")),
  };
}

export function approvalsUrl(state: ApprovalsUrlState, updates: Partial<ApprovalsUrlState> = {}) {
  const next = { ...state, ...updates };
  const parameters = new URLSearchParams();
  if (next.status !== "pending") parameters.set("status", next.status);
  if (next.cursor) parameters.set("cursor", next.cursor);
  if (next.approval) parameters.set("approval", next.approval);
  const search = parameters.toString();
  return search ? `/approvals?${search}` : "/approvals";
}

export function approvalsListKey(state: ApprovalsUrlState) {
  return JSON.stringify([state.status, state.cursor]);
}

function isApprovalStatus(value: string | null): value is ApprovalStatus {
  return value !== null && statuses.has(value as ApprovalStatus);
}

function nonEmpty(value: string | null) {
  return value === null || value === "" ? null : value;
}
