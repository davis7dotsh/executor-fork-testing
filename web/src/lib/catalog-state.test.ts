import { describe, expect, it } from "@effect/vitest";
import { ApiError } from "$lib/api";
import {
  beginIdentityResourceLoad,
  beginResourceLoad,
  createLatestRequest,
  emptyResource,
  settleResourceLoad,
} from "./catalog-state";

describe("catalog resource state", () => {
  it("distinguishes loading, empty, error, and stale data", () => {
    const loading = emptyResource<readonly string[]>();
    const empty = settleResourceLoad(loading, { ok: true, value: [] });
    const refreshing = beginResourceLoad(empty);
    const error = new ApiError({
      code: "offline",
      displayMessage: "offline",
      requestId: null,
      status: 0,
    });
    const failedEmpty = settleResourceLoad(loading, { ok: false, error });
    const loaded = settleResourceLoad(loading, { ok: true, value: ["tool"] });
    const stale = settleResourceLoad(loaded, { ok: false, error });

    expect(loading).toMatchObject({ loading: true, data: null, stale: false });
    expect(empty).toMatchObject({ loading: false, data: [], stale: false });
    expect(refreshing).toMatchObject({ loading: true, data: [], stale: false });
    expect(failedEmpty).toMatchObject({ loading: false, data: null, stale: false });
    expect(stale).toMatchObject({ loading: false, data: ["tool"], stale: true, error });
  });

  it("can discard retained detail data when a same-identity reload fails", () => {
    const loaded = settleResourceLoad(emptyResource<string>(), { ok: true, value: "tool-a" });
    const refreshing = beginIdentityResourceLoad(loaded, "a", "a").state;
    const error = new ApiError({
      code: "network_error",
      displayMessage: "offline",
      requestId: null,
      status: 0,
    });
    const failed = settleResourceLoad(
      refreshing,
      { ok: false, error },
      {
        retainDataOnError: false,
      },
    );

    expect(failed).toEqual({ data: null, loading: false, stale: false, error });
  });

  it("rejects an older completion after a newer request wins", async () => {
    const latest = createLatestRequest();
    const commits: string[] = [];
    let resolveA = (_value: string) => {};
    let resolveB = (_value: string) => {};
    const a = new Promise<string>((resolve) => (resolveA = resolve));
    const b = new Promise<string>((resolve) => (resolveB = resolve));

    latest.start(
      () => a,
      (value) => commits.push(value),
      () => {},
    );
    latest.start(
      () => b,
      (value) => commits.push(value),
      () => {},
    );
    resolveB("b");
    await b;
    resolveA("a");
    await a;
    await Promise.resolve();

    expect(commits).toEqual(["b"]);
  });

  it("reports an unexpected rejection through the current request contract", async () => {
    const latest = createLatestRequest();
    const commits: string[] = [];
    const rejections: unknown[] = [];
    let reject = (_error: unknown) => {};
    const pending = new Promise<string>((_resolve, fail) => (reject = fail));
    const failure = { _tag: "UnexpectedTestRejection" } as const;

    latest.start(
      () => pending,
      (value) => commits.push(value),
      (error) => rejections.push(error),
    );
    await Promise.resolve();
    reject(failure);
    await Promise.resolve();
    await Promise.resolve();

    expect(commits).toEqual([]);
    expect(rejections).toEqual([failure]);
  });

  it("ignores an older rejection after a newer request wins", async () => {
    const latest = createLatestRequest();
    const commits: string[] = [];
    const rejections: unknown[] = [];
    let rejectA = (_error: unknown) => {};
    let resolveB = (_value: string) => {};
    const a = new Promise<string>((_resolve, reject) => (rejectA = reject));
    const b = new Promise<string>((resolve) => (resolveB = resolve));

    latest.start(
      () => a,
      (value) => commits.push(value),
      (error) => rejections.push(error),
    );
    latest.start(
      () => b,
      (value) => commits.push(value),
      (error) => rejections.push(error),
    );
    await Promise.resolve();
    resolveB("b");
    await b;
    rejectA({ _tag: "LateTestRejection" });
    await Promise.resolve();
    await Promise.resolve();

    expect(commits).toEqual(["b"]);
    expect(rejections).toEqual([]);
  });

  it("retains data for a refresh but clears it across detail identities", () => {
    const loaded = settleResourceLoad(emptyResource<string>(), { ok: true, value: "tool-a" });

    expect(beginIdentityResourceLoad(loaded, "a", "a")).toEqual({
      identity: "a",
      state: { data: "tool-a", loading: true, error: null, stale: false },
    });
    expect(beginIdentityResourceLoad(loaded, "a", "b")).toEqual({
      identity: "b",
      state: { data: null, loading: true, error: null, stale: false },
    });
  });

  it("never leaves a previous tool list writable after a new list identity fails", () => {
    const loaded = settleResourceLoad(emptyResource<readonly string[]>(), {
      ok: true,
      value: ["old-tool"],
    });
    const changed = beginIdentityResourceLoad(loaded, "source-a", "source-b").state;
    const error = new ApiError({
      code: "network_error",
      displayMessage: "offline",
      requestId: null,
      status: 0,
    });
    const failed = settleResourceLoad(changed, { ok: false, error });

    expect(changed.data).toBeNull();
    expect(failed).toMatchObject({ data: null, loading: false, stale: false, error });
  });

  it("rejects completion after the owner is disposed", async () => {
    const latest = createLatestRequest();
    const commits: string[] = [];
    let resolve = (_value: string) => {};
    const pending = new Promise<string>((done) => (resolve = done));
    const dispose = latest.start(
      () => pending,
      (value) => commits.push(value),
      () => {},
    );

    dispose();
    resolve("late");
    await pending;
    await Promise.resolve();

    expect(commits).toEqual([]);
  });

  it("ignores a rejected task after the owner is disposed", async () => {
    const latest = createLatestRequest();
    const rejections: unknown[] = [];
    let reject = (_error: unknown) => {};
    const pending = new Promise<string>((_resolve, fail) => (reject = fail));
    const dispose = latest.start(
      () => pending,
      () => {},
      (error) => rejections.push(error),
    );

    await Promise.resolve();
    dispose();
    reject({ _tag: "LateDisposedTestRejection" });
    await Promise.resolve();
    await Promise.resolve();

    expect(rejections).toEqual([]);
  });
});
