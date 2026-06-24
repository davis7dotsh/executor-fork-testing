use std::{
    collections::HashMap,
    os::fd::OwnedFd,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use rquickjs::{
    AsyncContext, AsyncRuntime, CatchResultExt, Promise, Value,
    function::{Async, Func},
};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use tokio::{
    net::UnixStream,
    sync::{Mutex, mpsc, oneshot},
};

use super::{
    ConsoleEntry, RuntimeFailure, RuntimeLimits, ToolResult,
    protocol::{
        PROTOCOL_VERSION, ParentMessage, WorkerMessage, encode_frame, read_frame,
        write_encoded_frame,
    },
    transform::recover_and_transform,
};

type PendingCalls = Arc<Mutex<HashMap<u64, oneshot::Sender<ToolResult>>>>;

/// Runs the internal sandbox worker over an exclusively owned Unix stream.
#[doc(hidden)]
pub async fn worker_main(ipc_fd: OwnedFd, expected_generation: u64) -> Result<(), RuntimeFailure> {
    let std_stream = std::os::unix::net::UnixStream::from(ipc_fd);
    std_stream.set_nonblocking(true).map_err(|_| {
        RuntimeFailure::internal("worker_ipc_failed", "could not configure worker IPC")
    })?;
    let stream = UnixStream::from_std(std_stream)
        .map_err(|_| RuntimeFailure::internal("worker_ipc_failed", "could not open worker IPC"))?;
    let (mut reader, mut writer) = stream.into_split();
    let (start, initial_bytes) = read_frame::<_, ParentMessage>(&mut reader).await?;
    let (generation, code, limits) = match start {
        ParentMessage::Start {
            version,
            generation,
            code,
            limits,
        } if version == PROTOCOL_VERSION && generation == expected_generation => {
            (generation, code, limits)
        }
        _ => {
            return Err(RuntimeFailure::internal(
                "ipc_protocol_violation",
                "worker start frame was invalid",
            ));
        }
    };
    limits.validate()?;

    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<WorkerMessage>(32);
    let aggregate_bytes = Arc::new(AtomicUsize::new(initial_bytes));
    let writer_aggregate = aggregate_bytes.clone();
    let aggregate_limit = limits.aggregate_bytes;
    let writer_task = tokio::spawn(async move {
        while let Some(message) = outgoing_rx.recv().await {
            let payload = encode_frame(&message)?;
            let bytes = payload.len() + 4;
            if writer_aggregate
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(bytes)
                        .filter(|updated| *updated <= aggregate_limit)
                })
                .is_err()
            {
                return Err(RuntimeFailure::internal(
                    "ipc_limit_exceeded",
                    "IPC byte limit exceeded",
                ));
            }
            write_encoded_frame(&mut writer, &payload).await?;
        }
        Ok::<_, RuntimeFailure>(())
    });

    let pending: PendingCalls = Arc::new(Mutex::new(HashMap::new()));
    let pending_reader = pending.clone();
    let reader_aggregate = aggregate_bytes;
    let mut reader_task = tokio::spawn(async move {
        loop {
            let (message, bytes) = read_frame::<_, ParentMessage>(&mut reader).await?;
            if reader_aggregate
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current
                        .checked_add(bytes)
                        .filter(|updated| *updated <= aggregate_limit)
                })
                .is_err()
            {
                return Err(RuntimeFailure::internal(
                    "ipc_limit_exceeded",
                    "IPC byte limit exceeded",
                ));
            }
            match message {
                ParentMessage::ToolResult {
                    version,
                    generation: message_generation,
                    call_id,
                    result,
                } if version == PROTOCOL_VERSION && message_generation == generation => {
                    let sender = pending_reader
                        .lock()
                        .await
                        .remove(&call_id)
                        .ok_or_else(|| {
                            RuntimeFailure::internal(
                                "ipc_protocol_violation",
                                "tool result had an unknown or duplicate call ID",
                            )
                        })?;
                    let _ = sender.send(result);
                }
                _ => {
                    return Err(RuntimeFailure::internal(
                        "ipc_protocol_violation",
                        "parent IPC message was invalid",
                    ));
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), RuntimeFailure>(())
    });

    let execution = tokio::select! {
        execution = execute_javascript(
            code,
            limits.clone(),
            generation,
            outgoing_tx.clone(),
            pending,
        ) => execution,
        reader = &mut reader_task => {
            return Err(match reader {
                Ok(Err(failure)) => failure,
                Ok(Ok(())) => RuntimeFailure::internal("worker_disconnected", "sandbox parent disconnected"),
                Err(_) => RuntimeFailure::internal("worker_failed", "IPC reader failed"),
            });
        }
    };
    let final_message = match execution {
        Ok((result, emits, console)) => WorkerMessage::Complete {
            version: PROTOCOL_VERSION,
            generation,
            result,
            emits,
            console,
        },
        Err(failure) => WorkerMessage::Failed {
            version: PROTOCOL_VERSION,
            generation,
            failure,
        },
    };
    outgoing_tx.send(final_message).await.map_err(|_| {
        RuntimeFailure::internal("worker_disconnected", "sandbox parent disconnected")
    })?;
    drop(outgoing_tx);
    reader_task.abort();
    writer_task
        .await
        .map_err(|_| RuntimeFailure::internal("worker_failed", "IPC writer failed"))??;
    Ok(())
}

async fn execute_javascript(
    source: String,
    limits: RuntimeLimits,
    generation: u64,
    outgoing: mpsc::Sender<WorkerMessage>,
    pending: PendingCalls,
) -> Result<(JsonValue, Vec<JsonValue>, Vec<ConsoleEntry>), RuntimeFailure> {
    let transformed = recover_and_transform(&source)?;
    let runtime = AsyncRuntime::new().map_err(js_internal)?;
    runtime.set_memory_limit(limits.heap_bytes).await;
    runtime.set_max_stack_size(limits.stack_bytes).await;
    let deadline = Instant::now() + Duration::from_millis(limits.wall_time_millis);
    runtime
        .set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)))
        .await;
    let context = AsyncContext::full(&runtime).await.map_err(js_internal)?;
    let next_call_id = Arc::new(AtomicU64::new(1));
    let issue_lock = Arc::new(Mutex::new(()));

    let collected = context
        .async_with(async |ctx| {
            let sender = outgoing.clone();
            let pending_calls = pending.clone();
            let call_ids = next_call_id.clone();
            let issue_calls = issue_lock.clone();
            let argument_limit = limits.argument_bytes;
            ctx.globals()
                .set(
                    "__executor_host_call",
                    Func::from(Async(move |path: String, arguments: String| {
                        let sender = sender.clone();
                        let pending_calls = pending_calls.clone();
                        let call_ids = call_ids.clone();
                        let issue_calls = issue_calls.clone();
                        async move {
                            if arguments.len() > argument_limit {
                                return Ok::<_, rquickjs::Error>(internal_result_json(
                                    "argument_too_large",
                                ));
                            }
                            let parsed: JsonValue = match serde_json::from_str(&arguments) {
                                Ok(value) => value,
                                Err(_) => {
                                    return Ok(internal_result_json("argument_not_json"));
                                }
                            };
                            let response_rx = {
                                let _issue = issue_calls.lock().await;
                                let call_id = call_ids.fetch_add(1, Ordering::Relaxed);
                                let (response_tx, response_rx) = oneshot::channel();
                                pending_calls.lock().await.insert(call_id, response_tx);
                                if sender
                                    .send(WorkerMessage::ToolCall {
                                        version: PROTOCOL_VERSION,
                                        generation,
                                        call_id,
                                        path,
                                        arguments: parsed,
                                    })
                                    .await
                                    .is_err()
                                {
                                    pending_calls.lock().await.remove(&call_id);
                                    return Ok(internal_result_json("tool_bridge_failed"));
                                }
                                response_rx
                            };
                            match response_rx.await {
                                Ok(result) => serde_json::to_string(&result)
                                    .map_err(|_| rquickjs::Error::Unknown),
                                Err(_) => Ok(internal_result_json("tool_bridge_failed")),
                            }
                        }
                    })),
                )
                .map_err(js_public)?;

            let bootstrap = bootstrap_script(&limits);
            ctx.eval::<(), _>(bootstrap).map_err(|error| js_caught(&ctx, error))?;
            ctx.eval::<(), _>(transformed)
                .map_err(|error| js_caught(&ctx, error))?;
            let promise: Promise = ctx
                .globals()
                .get("__executor_entry")
                .map_err(|error| js_caught(&ctx, error))?;
            let value: Value = promise
                .into_future()
                .await
                .catch(&ctx)
                .map_err(|_| RuntimeFailure::public("execution_failed", "TypeScript execution failed"))?;
            ctx.globals()
                .set("__executor_result", value)
                .map_err(|error| js_caught(&ctx, error))?;
            let serialized: String = ctx
                .eval("JSON.stringify({result: __executor_result === undefined ? null : __executor_result, emits: __executor_emits, console: __executor_console})")
                .map_err(|error| js_caught(&ctx, error))?;
            if serialized.len() > limits.result_bytes + limits.max_emit_bytes + limits.max_console_bytes {
                return Err(RuntimeFailure::public(
                    "result_too_large",
                    "execution output exceeded its size limit",
                ));
            }
            let collected: CollectedOutput = serde_json::from_str(&serialized).map_err(|_| {
                RuntimeFailure::public("result_not_json", "execution result was not JSON serializable")
            })?;
            if serde_json::to_vec(&collected.result).map_or(true, |value| value.len() > limits.result_bytes) {
                return Err(RuntimeFailure::public(
                    "result_too_large",
                    "execution result exceeded 8 MiB",
                ));
            }
            Ok(collected)
        })
        .await?;
    runtime.idle().await;
    if !pending.lock().await.is_empty() {
        return Err(RuntimeFailure::internal(
            "tool_bridge_failed",
            "tool calls did not settle",
        ));
    }
    Ok((collected.result, collected.emits, collected.console))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CollectedOutput {
    result: JsonValue,
    emits: Vec<JsonValue>,
    console: Vec<ConsoleEntry>,
}

fn bootstrap_script(limits: &RuntimeLimits) -> String {
    format!(
        r#"
        (() => {{
          'use strict';
          const hostCall = globalThis.__executor_host_call;
          delete globalThis.__executor_host_call;
          const safeString = (value) => {{
            try {{
              if (typeof value === 'string') return value;
              const encoded = JSON.stringify(value);
              return encoded === undefined ? String(value) : encoded;
            }} catch (_) {{ return '[unserializable]'; }}
          }};
          const utf8Bytes = (value) => {{
            let bytes = 0;
            for (const character of value) {{
              const point = character.codePointAt(0);
              bytes += point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
            }}
            return bytes;
          }};
          globalThis.__executor_console = [];
          let consoleBytes = 0;
          const capture = (level, values) => {{
            if (__executor_console.length >= {console_count}) return;
            const message = values.map(safeString).join(' ');
            consoleBytes += utf8Bytes(message);
            if (consoleBytes <= {console_bytes}) __executor_console.push({{ level, message }});
          }};
          globalThis.console = Object.freeze({{
            debug: (...v) => capture('debug', v), info: (...v) => capture('info', v),
            log: (...v) => capture('log', v), warn: (...v) => capture('warn', v),
            error: (...v) => capture('error', v)
          }});
          globalThis.__executor_emits = [];
          let emitBytes = 0;
          globalThis.emit = (value) => {{
            if (__executor_emits.length >= {emit_count}) throw new Error('emit_limit_exceeded');
            const encoded = JSON.stringify(value);
            if (encoded === undefined) throw new Error('emit_not_json');
            emitBytes += utf8Bytes(encoded);
            if (emitBytes > {emit_bytes}) throw new Error('emit_limit_exceeded');
            __executor_emits.push(JSON.parse(encoded));
          }};
          const makeTools = (path = []) => {{
            const target = (..._args) => {{}};
            delete target.name;
            delete target.length;
            Object.freeze(target);
            return new Proxy(target, {{
              get(_target, key) {{
                if (key === 'then' || typeof key === 'symbol') return undefined;
                return makeTools(path.concat(String(key)));
              }},
              apply(_target, _this, args) {{
                const argument = args.length === 0 ? {{}} : args[0];
                let encoded;
                try {{ encoded = JSON.stringify(argument); }}
                catch (_) {{ return Promise.reject(new Error('tool_argument_not_json')); }}
                if (encoded === undefined) return Promise.reject(new Error('tool_argument_not_json'));
                return hostCall(path.join('.'), encoded).then((raw) => {{
                  const response = JSON.parse(raw);
                  if (response.kind === 'success') return response.value;
                  if (response.kind === 'failure') return {{ error: {{ code: response.code, message: response.message }} }};
                  throw new Error(response.code || 'tool_bridge_failed');
                }});
              }}
            }});
          }};
          globalThis.tools = makeTools();
          for (const name of ['fetch','XMLHttpRequest','WebSocket','process','require','module','Deno','Bun']) {{
            try {{ delete globalThis[name]; }} catch (_) {{ globalThis[name] = undefined; }}
          }}
        }})();
        "#,
        console_count = limits.max_console_entries,
        console_bytes = limits.max_console_bytes,
        emit_count = limits.max_emits,
        emit_bytes = limits.max_emit_bytes,
    )
}

fn internal_result_json(code: &str) -> String {
    format!(r#"{{"kind":"internal_error","code":"{code}"}}"#)
}

fn js_internal(_: rquickjs::Error) -> RuntimeFailure {
    RuntimeFailure::internal(
        "javascript_runtime_failed",
        "could not initialize JavaScript runtime",
    )
}

fn js_public(_: rquickjs::Error) -> RuntimeFailure {
    RuntimeFailure::public("execution_failed", "TypeScript execution failed")
}

fn js_caught<'js>(ctx: &rquickjs::Ctx<'js>, error: rquickjs::Error) -> RuntimeFailure {
    let _ = (ctx, error);
    RuntimeFailure::public("execution_failed", "TypeScript execution failed")
}

#[cfg(test)]
mod tests {
    use super::bootstrap_script;
    use crate::runtime::RuntimeLimits;

    #[test]
    fn bootstrap_does_not_embed_capabilities() {
        let script = bootstrap_script(&RuntimeLimits::default());
        assert!(script.contains("delete globalThis[name]"));
        assert!(!script.contains("actor"));
        assert!(!script.contains("credential"));
    }
}
