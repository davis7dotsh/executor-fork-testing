# Sandboxed TypeScript runtime

Executor runs each TypeScript execution in a fresh hidden worker process. The
server process owns authentication, policy, approvals, credentials, network
access, tool dispatch, cancellation, and request logging. The worker receives
only source code, public limits, and sanitized tool results.

## Integration contract

`RuntimeManager::execute` accepts an `ExecutionRequest`, a
`HostToolDispatcher`, and an `ExecutionCancellation`. The worker can request
only a tool path and one JSON argument. The parent adds the execution identity
before calling `HostToolDispatcher::dispatch`. Implementations must select on
the supplied cancellation handle while waiting for an interactive approval.
They must also treat a dropped dispatch future as cancellation and remove any
pending approval for that execution.

The application adapter captures the authenticated actor and surface outside
the worker, maps each runtime `ToolCall` into `invocation::ToolCallService`, and
waits for an Ask decision while selecting on cancellation. When an execution
ends, it calls `cancel_execution(execution_id)` so pending approval calls do not
outlive their QuickJS continuation.

The adapter assigns a distinct request-log ID to every tool call while keeping
the HTTP request ID and execution ID as parent-side correlation. Worker
generations are positive signed-range integers. They are included in approval
records but expose no authority. Approval decisions start at most one
server-owned background invocation. The worker waiter only observes the stored
terminal result and never dispatches the upstream call itself.

Expected upstream tool failures use `ToolResult::Failure`. They resolve in
TypeScript as `{ error: { code, message } }`, so a script can inspect and react
to them. IPC, worker, and internal bridge failures reject the tool promise or
fail the execution with a stable public code.

The result contract keeps the final JSON result, emitted JSON items, captured
console entries, and parent-side tool-call correlation separate. Neither IPC
nor runtime output contains credentials, request headers, source bindings, or
approval records.

## Source recovery and tool proxy

Executor uses the first fenced code block when one is present. It accepts an
async body with top-level `await` and `return`, a named function declaration, a
function or arrow expression, a callable variable declaration, or a default
exported callable. Oxc parses and removes TypeScript syntax inside the worker.
Imports, module loading, decorators, enums, namespaces, and JSX fail closed.

`tools` is a lazy recursive frozen proxy. Dotted and bracket access are
equivalent. `then` and symbol property reads return `undefined`, which prevents
accidental thenable behavior. A call forwards only its first argument and that
argument must be JSON serializable. `Promise.all` creates concurrent parent
dispatches, with at most 16 active calls and 128 total calls per execution.

Three protocol-neutral discovery calls are handled entirely by the parent:
`tools.search`, `tools.describe`, and `tools.sources`. They use the same catalog
visibility rules as gateway discovery. `tools.sources` returns only public
source metadata and never returns source configuration or credentials.

## Gateway execution API

`POST /api/v1/gateway/execute` is bearer-token only. Its JSON body is
`{ "code": string, "timeoutMs"?: number }`. Authentication runs before JSON
body parsing. Code is limited to 1 MiB, and the timeout defaults to 30 seconds
with a five-minute maximum.

The response contains `executionId`, `result`, `emits`, `console`, and `calls`.
The call records contain only worker call IDs, public paths, and sanitized
results. The endpoint holds the HTTP request open while Ask tools await an
administrator decision. It does not provide persistence or replay. A client
disconnect cancels the worker and all pending or approved calls that have not
started upstream execution. Already-executing approved work remains owned by
the server because an upstream side effect may already have occurred.

The application-level `ExecutionService` owns actor context, runtime admission,
disconnect cancellation, worker construction, and active execution tracking.
HTTP only authenticates, parses, and maps the protocol response. CLI and MCP
can reuse the same service without rebuilding lifecycle logic. Graceful
shutdown stops new runtime admission, cancels active workers, waits for their
parent-side cleanup, then stops approval and request-log tasks before closing
SQLite.

Before disconnect, revocation, shutdown, timeout, or worker-failure cancellation
reaches the runtime, execution records an in-memory lost-continuation barrier.
Approval decisions and approved-work claims share that gate, so cancellation
and the `approved -> executing` transition have one linearized winner. If
immediate SQLite cleanup repeatedly fails, a tracked retry task keeps the
barrier active. Shutdown aborts that retry deterministically, and startup
recovery terminalizes every pending or approved sandbox approval whose worker
generation was lost.

The worker has no module loader and exposes no filesystem, environment,
process, FFI, or network API. `fetch`, `XMLHttpRequest`, `WebSocket`, `process`,
`require`, `module`, `Deno`, and `Bun` are absent.

## Isolation and limits

IPC uses a private inherited Unix socket, never standard output. Every
length-prefixed JSON frame has a strict version, execution generation, tagged
schema, 18 MiB frame ceiling, and 32 MiB aggregate ceiling. Call IDs are
monotonic. Unknown fields, duplicate or unknown IDs, wrong generations,
partial frames, invalid lengths, and excessive JSON depth or node counts fail
closed before serde allocation.

QuickJS has a 64 MiB heap limit and 1 MiB engine stack limit. Source and
transformed code are each capped at 1 MiB. Arguments and final results are
capped at 8 MiB. Console capture is capped at 1,000 entries and 256 KiB. Emits
are capped at 100 items and 8 MiB. The server admits at most eight workers at
once. Additional executions fail immediately with `runtime_busy` rather than
forming an unbounded waiter queue.

The child starts with an empty environment, null standard streams, a private
empty working directory, umask `077`, a new process group, and resource limits
for CPU, address space, process stack, open files, output files, and core
dumps. Executor intentionally does not set `RLIMIT_NPROC`, which would affect
the shared user account rather than one worker. Cancellation and timeout kill
the worker process group and reap the child before releasing its worker slot.
Linux also sets `no_new_privs` and a parent-death kill signal before exec.

Linux applies the complete resource-limit contract. macOS uses the
same process, descriptor, environment, QuickJS, and IPC boundaries, but its
kernel may treat address-space and CPU limits less strictly. Executor does not
claim a macOS Seatbelt profile or container boundary.

This is a capability, crash, and resource boundary for JavaScript, not a
multi-tenant native-code sandbox. A QuickJS, Oxc, or Rust memory-safety escape
would still run as the service account on both Linux and macOS. Executor does
not currently install a Linux seccomp or Landlock policy.

The caller chooses a positive wall deadline of at most five minutes. The same
deadline drives parent timeout handling and the QuickJS interrupt handler. The
kernel CPU limit is the deadline rounded up to a whole second, with exact whole
seconds left unchanged and subsecond deadlines receiving a one-second minimum.
