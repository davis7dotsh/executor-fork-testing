import { describe, expect, it } from "@effect/vitest";
import { approvalsListKey, approvalsUrl, parseApprovalsUrl } from "./approval-url";

describe("approval URL state", () => {
  it("defaults invalid and missing status filters to pending", () => {
    expect(parseApprovalsUrl(new URLSearchParams())).toEqual({
      status: "pending",
      cursor: null,
      approval: null,
    });
    expect(parseApprovalsUrl(new URLSearchParams("status=surprise&cursor=&approval="))).toEqual({
      status: "pending",
      cursor: null,
      approval: null,
    });
    expect(parseApprovalsUrl(new URLSearchParams("status=active"))).toEqual({
      status: "pending",
      cursor: null,
      approval: null,
    });
  });

  it("keeps status, pagination, and detail selection bookmarkable", () => {
    const state = parseApprovalsUrl(
      new URLSearchParams("status=denied&cursor=older-page&approval=approval-1"),
    );

    expect(state).toEqual({
      status: "denied",
      cursor: "older-page",
      approval: "approval-1",
    });
    expect(approvalsUrl(state, { approval: null })).toBe(
      "/approvals?status=denied&cursor=older-page",
    );
    expect(approvalsUrl(state, { status: "pending", cursor: null })).toBe(
      "/approvals?approval=approval-1",
    );
  });

  it("excludes detail selection from the list request identity", () => {
    const first = parseApprovalsUrl(
      new URLSearchParams("status=failed&cursor=older&approval=approval-a"),
    );
    const second = parseApprovalsUrl(
      new URLSearchParams("status=failed&cursor=older&approval=approval-b"),
    );

    expect(approvalsListKey(first)).toBe(approvalsListKey(second));
    expect(approvalsListKey(first)).not.toBe(
      approvalsListKey({ status: "pending", cursor: "older", approval: "approval-a" }),
    );
  });
});
