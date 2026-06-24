use std::{
    collections::HashMap,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use executor::runtime::{
    ExecutionCancellation, ExecutionRequest, HostToolDispatcher, RuntimeManager, ToolCall,
    ToolResult,
};
use serde_json::{Value, json};
use tokio::sync::{Barrier, Mutex};

fn manager() -> RuntimeManager {
    RuntimeManager::new(env!("CARGO_BIN_EXE_executor"))
}

fn request(code: &str) -> ExecutionRequest {
    ExecutionRequest {
        execution_id: uuid::Uuid::new_v4().to_string(),
        code: code.into(),
        timeout: Duration::from_secs(5),
    }
}

async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(())).lock().await
}

struct EchoDispatcher;

#[async_trait]
impl HostToolDispatcher for EchoDispatcher {
    async fn dispatch(&self, call: ToolCall, _: ExecutionCancellation) -> ToolResult {
        ToolResult::Success {
            value: json!({ "path": call.path, "arguments": call.arguments }),
        }
    }
}

#[tokio::test]
async fn executes_typescript_with_proxy_console_and_emit() {
    let _guard = test_guard().await;
    let output = manager()
        .execute(
            request(
                r#"
                const count: number = 2;
                console.info("calling", count);
                emit({ phase: "ready" });
                const response = await tools.weather["forecast"]({ city: "Paris", count });
                return { response, missingThen: tools.weather.then === undefined };
                "#,
            ),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("execution should succeed");
    assert_eq!(output.result["response"]["path"], "weather.forecast");
    assert_eq!(output.result["response"]["arguments"]["count"], 2);
    assert_eq!(output.result["missingThen"], true);
    assert_eq!(output.emits, vec![json!({ "phase": "ready" })]);
    assert_eq!(output.console[0].message, "calling 2");
    assert_eq!(output.tool_calls.len(), 1);
}

struct DependencyDispatcher;

#[async_trait]
impl HostToolDispatcher for DependencyDispatcher {
    async fn dispatch(&self, call: ToolCall, _: ExecutionCancellation) -> ToolResult {
        let value = match call.path.as_str() {
            "sequence.first" => json!(7),
            "sequence.second" => json!(call.arguments["value"].as_i64().unwrap_or_default() * 2),
            _ => Value::Null,
        };
        ToolResult::Success { value }
    }
}

#[tokio::test]
async fn sequential_calls_can_depend_on_prior_results() {
    let _guard = test_guard().await;
    let output = manager()
        .execute(
            request(
                "const first = await tools.sequence.first(); return await tools.sequence.second({ value: first });",
            ),
            Arc::new(DependencyDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("execution should succeed");
    assert_eq!(output.result, 14);
    assert_eq!(
        output
            .tool_calls
            .iter()
            .map(|call| call.call_id)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
}

struct ConcurrentDispatcher {
    barrier: Barrier,
    active: AtomicUsize,
    peak: AtomicUsize,
    releases: Mutex<HashMap<String, u64>>,
}

#[async_trait]
impl HostToolDispatcher for ConcurrentDispatcher {
    async fn dispatch(&self, call: ToolCall, _: ExecutionCancellation) -> ToolResult {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.barrier.wait().await;
        let delay = self.releases.lock().await[&call.path];
        tokio::time::sleep(Duration::from_millis(delay)).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        ToolResult::Success {
            value: json!(call.path),
        }
    }
}

#[tokio::test]
async fn promise_all_overlaps_and_preserves_input_order() {
    let _guard = test_guard().await;
    let dispatcher = Arc::new(ConcurrentDispatcher {
        barrier: Barrier::new(2),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        releases: Mutex::new(HashMap::from([
            ("parallel.slow".into(), 50),
            ("parallel.fast".into(), 0),
        ])),
    });
    let output = manager()
        .execute(
            request("return await Promise.all([tools.parallel.slow(), tools.parallel.fast()]);"),
            dispatcher.clone(),
            ExecutionCancellation::default(),
        )
        .await
        .expect("execution should succeed");
    assert_eq!(dispatcher.peak.load(Ordering::SeqCst), 2);
    assert_eq!(output.result, json!(["parallel.slow", "parallel.fast"]));
}

#[tokio::test]
async fn unawaited_started_calls_settle_before_completion() {
    let _guard = test_guard().await;
    let output = manager()
        .execute(
            request(
                "tools.background.started({ value: 1 }); await Promise.resolve(); return 'done';",
            ),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("started call should settle before completion");
    assert_eq!(output.result, "done");
    assert_eq!(output.tool_calls.len(), 1);
    assert_eq!(output.tool_calls[0].path, "background.started");
}

#[tokio::test]
async fn expected_tool_failures_are_values_not_rejections() {
    let _guard = test_guard().await;
    struct FailureDispatcher;
    #[async_trait]
    impl HostToolDispatcher for FailureDispatcher {
        async fn dispatch(&self, _: ToolCall, _: ExecutionCancellation) -> ToolResult {
            ToolResult::Failure {
                code: "upstream_denied".into(),
                message: "denied".into(),
            }
        }
    }
    let output = manager()
        .execute(
            request("return await tools.example.fail();"),
            Arc::new(FailureDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("expected failure should remain a value");
    assert_eq!(output.result["error"]["code"], "upstream_denied");
}

#[tokio::test]
async fn cpu_loops_and_unresolved_promises_time_out_without_poisoning_next_execution() {
    let _guard = test_guard().await;
    let mut timed = request("while (true) {};");
    timed.timeout = Duration::from_millis(150);
    assert_eq!(
        manager()
            .execute(
                timed,
                Arc::new(EchoDispatcher),
                ExecutionCancellation::default()
            )
            .await
            .expect_err("loop must time out")
            .code,
        "execution_timeout"
    );

    let output = manager()
        .execute(
            request("return 42;"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("next worker must be isolated");
    assert_eq!(output.result, 42);

    let mut unresolved = request("return await new Promise(() => {});");
    unresolved.timeout = Duration::from_millis(100);
    assert_eq!(
        manager()
            .execute(
                unresolved,
                Arc::new(EchoDispatcher),
                ExecutionCancellation::default()
            )
            .await
            .expect_err("unresolved promise must time out")
            .code,
        "execution_timeout"
    );
}

#[tokio::test]
async fn cancellation_terminates_pending_dispatch() {
    let _guard = test_guard().await;
    struct PendingDispatcher;
    #[async_trait]
    impl HostToolDispatcher for PendingDispatcher {
        async fn dispatch(&self, _: ToolCall, cancellation: ExecutionCancellation) -> ToolResult {
            cancellation.cancelled().await;
            ToolResult::Failure {
                code: "cancelled".into(),
                message: "cancelled".into(),
            }
        }
    }
    let cancellation = ExecutionCancellation::default();
    let cancel_from_task = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel_from_task.cancel();
    });
    let failure = manager()
        .execute(
            request("return await tools.wait.forever();"),
            Arc::new(PendingDispatcher),
            cancellation,
        )
        .await
        .expect_err("execution must cancel");
    assert_eq!(failure.code, "execution_cancelled");
}

#[tokio::test]
async fn dispatcher_failure_stops_execution_without_waiting_for_wall_timeout() {
    let _guard = test_guard().await;
    struct PanicDispatcher;
    #[async_trait]
    impl HostToolDispatcher for PanicDispatcher {
        async fn dispatch(&self, _: ToolCall, _: ExecutionCancellation) -> ToolResult {
            panic!("intentional dispatcher failure")
        }
    }
    let started = std::time::Instant::now();
    let failure = manager()
        .execute(
            request("return await tools.failure.panic();"),
            Arc::new(PanicDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect_err("dispatcher panic should fail the execution");
    assert_eq!(failure.code, "tool_bridge_failed");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn unavailable_host_globals_stay_unavailable() {
    let _guard = test_guard().await;
    let output = manager()
        .execute(
            request(
                "return [typeof fetch, typeof process, typeof require, typeof Deno, typeof Bun];",
            ),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("execution should succeed");
    assert_eq!(
        output.result,
        json!([
            "undefined",
            "undefined",
            "undefined",
            "undefined",
            "undefined"
        ])
    );
}

#[tokio::test]
async fn stack_memory_and_output_limits_fail_inside_one_worker() {
    let _guard = test_guard().await;
    for (code, forbidden_failure) in [
        (
            "function recurse() { return recurse(); }",
            "execution_timeout",
        ),
        (
            "const values = []; while (true) { values.push('x'.repeat(1024 * 1024)); }",
            "execution_timeout",
        ),
        ("return 'x'.repeat(9 * 1024 * 1024);", "execution_timeout"),
    ] {
        let mut bounded = request(code);
        bounded.timeout = Duration::from_secs(2);
        let failure = manager()
            .execute(
                bounded,
                Arc::new(EchoDispatcher),
                ExecutionCancellation::default(),
            )
            .await
            .expect_err("hostile execution must fail");
        assert_ne!(
            failure.code, forbidden_failure,
            "engine limit must fire: {code}"
        );
    }
}

#[tokio::test]
async fn console_emit_and_call_caps_are_enforced() {
    let _guard = test_guard().await;
    let output = manager()
        .execute(
            request("for (let i = 0; i < 1100; i++) console.log(i); return true;"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("console capture should truncate safely");
    assert_eq!(output.console.len(), 1000);

    let unicode = manager()
        .execute(
            request("console.log('😀'.repeat(70000)); return true;"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("oversized unicode console entry should truncate safely");
    assert!(unicode.console.is_empty());

    let emit_failure = manager()
        .execute(
            request("for (let i = 0; i < 101; i++) emit(i); return true;"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect_err("emit cap must fail");
    assert_eq!(emit_failure.code, "execution_failed");

    let unicode_emit_failure = manager()
        .execute(
            request("emit('😀'.repeat(2100000)); return true;"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect_err("UTF-8 emit cap must fail");
    assert_eq!(unicode_emit_failure.code, "execution_failed");

    let call_failure = manager()
        .execute(
            request("return await Promise.all(Array.from({length: 129}, (_, i) => tools.cap.call({i})));"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect_err("call cap must fail");
    assert_eq!(call_failure.code, "tool_call_limit_exceeded");
}

#[tokio::test]
async fn proxy_ignores_symbols_and_hostile_json_does_not_mutate_prototypes() {
    let _guard = test_guard().await;
    let output = manager()
        .execute(
            request(
                "const result = await tools.prototype.check(JSON.parse('{\"__proto__\":{\"polluted\":true}}')); return { symbol: tools[Symbol.iterator] === undefined, polluted: ({}).polluted ?? null, result };",
            ),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("hostile JSON should remain data");
    assert_eq!(output.result["symbol"], true);
    assert_eq!(output.result["polluted"], Value::Null);
    assert_eq!(
        output.result["result"]["arguments"]["__proto__"]["polluted"],
        true
    );
}

#[tokio::test]
async fn parallel_executions_have_fresh_globals() {
    let _guard = test_guard().await;
    let manager = manager();
    let first = manager.execute(
        request("globalThis.secret = 99; return secret;"),
        Arc::new(EchoDispatcher),
        ExecutionCancellation::default(),
    );
    let second = manager.execute(
        request("return typeof secret;"),
        Arc::new(EchoDispatcher),
        ExecutionCancellation::default(),
    );
    let (first, second) = tokio::join!(first, second);
    assert_eq!(first.expect("first execution should succeed").result, 99);
    assert_eq!(
        second.expect("second execution should succeed").result,
        "undefined"
    );
}

#[tokio::test]
async fn worker_crash_isolated_from_following_execution() {
    let _guard = test_guard().await;
    let failure = RuntimeManager::new("/bin/true")
        .execute(
            request("return 1;"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect_err("exited worker must fail");
    assert!(failure.internal);

    let output = manager()
        .execute(
            request("return 2;"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect("next worker must remain healthy");
    assert_eq!(output.result, 2);
}

#[tokio::test]
async fn dropping_waiters_cleans_workers_before_releasing_slots() {
    let _guard = test_guard().await;
    let mut waiters = Vec::new();
    for _ in 0..8 {
        waiters.push(tokio::spawn(async move {
            manager()
                .execute(
                    request("while (true) {}"),
                    Arc::new(EchoDispatcher),
                    ExecutionCancellation::default(),
                )
                .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let busy = manager()
        .execute(
            request("return 'no slot';"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        )
        .await
        .expect_err("ninth worker must fail without queueing");
    assert_eq!(busy.code, "runtime_busy");
    for waiter in waiters {
        waiter.abort();
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let output = tokio::time::timeout(
        Duration::from_secs(2),
        manager().execute(
            request("return 'reaped';"),
            Arc::new(EchoDispatcher),
            ExecutionCancellation::default(),
        ),
    )
    .await
    .expect("worker slot should be released")
    .expect("replacement execution should succeed");
    assert_eq!(output.result, "reaped");
}
