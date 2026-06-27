import type { ToolMode } from "$lib/api";

const modes = new Set<ToolMode>(["enabled", "ask", "disabled"]);
const maxSearchLength = 256;
const maxOffset = 1_000_000_000;

export type ToolsUrlState = {
  q: string;
  source: string | null;
  mode: ToolMode | null;
  removed: boolean;
  offset: number;
  tool: string | null;
};

export function parseToolsUrl(parameters: URLSearchParams): ToolsUrlState {
  const rawMode = parameters.get("mode");
  return {
    q: (parameters.get("q") ?? "").slice(0, maxSearchLength),
    source: nonEmpty(parameters.get("source")),
    mode: isToolMode(rawMode) ? rawMode : null,
    removed: parameters.get("removed") === "1",
    offset: parseOffset(parameters.get("offset")),
    tool: nonEmpty(parameters.get("tool")),
  };
}

export function toolsUrl(state: ToolsUrlState, updates: Partial<ToolsUrlState> = {}) {
  const next = { ...state, ...updates };
  const parameters = new URLSearchParams();
  if (next.q) parameters.set("q", next.q);
  if (next.source) parameters.set("source", next.source);
  if (next.mode) parameters.set("mode", next.mode);
  if (next.removed) parameters.set("removed", "1");
  if (next.offset > 0) parameters.set("offset", String(next.offset));
  if (next.tool) parameters.set("tool", next.tool);
  const search = parameters.toString();
  return search ? `/tools?${search}` : "/tools";
}

export function toolsListKey(state: ToolsUrlState) {
  return JSON.stringify([state.q, state.source, state.mode, state.removed, state.offset]);
}

export type LogsUrlState = {
  cursor: string | null;
  request: string | null;
};

export function parseLogsUrl(parameters: URLSearchParams): LogsUrlState {
  return {
    cursor: nonEmpty(parameters.get("cursor")),
    request: nonEmpty(parameters.get("request")),
  };
}

export function logsUrl(state: LogsUrlState, updates: Partial<LogsUrlState> = {}) {
  const next = { ...state, ...updates };
  const parameters = new URLSearchParams();
  if (next.cursor) parameters.set("cursor", next.cursor);
  if (next.request) parameters.set("request", next.request);
  const search = parameters.toString();
  return search ? `/logs?${search}` : "/logs";
}

export function logsListKey(state: LogsUrlState) {
  return state.cursor ?? "";
}

function isToolMode(value: string | null): value is ToolMode {
  return value !== null && modes.has(value as ToolMode);
}

function nonEmpty(value: string | null) {
  return value === null || value === "" ? null : value;
}

function parseOffset(value: string | null) {
  if (value === null || !/^\d+$/.test(value)) return 0;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? Math.min(parsed, maxOffset) : 0;
}
