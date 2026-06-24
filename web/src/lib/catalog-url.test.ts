import { describe, expect, it } from "@effect/vitest";
import {
  logsListKey,
  logsUrl,
  parseLogsUrl,
  parseToolsUrl,
  toolsListKey,
  toolsUrl,
} from "./catalog-url";

describe("catalog URL state", () => {
  it("normalizes invalid tool filters without hiding valid choices", () => {
    const state = parseToolsUrl(
      new URLSearchParams(
        "q=deploy&source=github&mode=surprise&removed=true&offset=-4&tool=tool-1",
      ),
    );

    expect(state).toEqual({
      q: "deploy",
      source: "github",
      mode: null,
      removed: false,
      offset: 0,
      tool: "tool-1",
    });
  });

  it("creates bookmarkable tool URLs and resets offsets on filter changes", () => {
    const state = parseToolsUrl(new URLSearchParams("source=github&offset=100&removed=1"));
    expect(toolsUrl(state, { mode: "ask", offset: 0 })).toBe(
      "/tools?source=github&mode=ask&removed=1",
    );
  });

  it("keeps log cursors and inline request selection independently addressable", () => {
    const state = parseLogsUrl(new URLSearchParams("cursor=older-page&request=req-1"));
    expect(state).toEqual({ cursor: "older-page", request: "req-1" });
    expect(logsUrl(state, { request: null })).toBe("/logs?cursor=older-page");
    expect(logsUrl(state, { cursor: null })).toBe("/logs?request=req-1");
  });

  it("excludes detail-only selections from list request identities", () => {
    const toolA = parseToolsUrl(new URLSearchParams("source=github&tool=a"));
    const toolB = parseToolsUrl(new URLSearchParams("source=github&tool=b"));
    const logA = parseLogsUrl(new URLSearchParams("cursor=older&request=a"));
    const logB = parseLogsUrl(new URLSearchParams("cursor=older&request=b"));

    expect(toolsListKey(toolA)).toBe(toolsListKey(toolB));
    expect(logsListKey(logA)).toBe(logsListKey(logB));
  });

  it("changes list identity for filters, offsets, and cursors", () => {
    const first = parseToolsUrl(new URLSearchParams("source=github&offset=0"));
    const second = parseToolsUrl(new URLSearchParams("source=github&offset=50"));
    expect(toolsListKey(first)).not.toBe(toolsListKey(second));
    expect(logsListKey({ cursor: "a", request: null })).not.toBe(
      logsListKey({ cursor: "b", request: null }),
    );
  });
});
