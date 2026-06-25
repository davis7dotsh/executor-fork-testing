use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    extract::{OriginalUri, State},
    http::{Method, Request, StatusCode, header},
};
use executor::{
    AppConfig, ExecutorApp,
    actor::ToolActor,
    approval::{ApprovalDecision, ApprovalListQuery, ApprovalStatus},
    catalog::{
        ArtifactKind, AuditContext, CreateSource, CredentialPayload, InitialCatalogSnapshot,
        RequestSurface, SourceKind, StagedArtifact, StagedTool, StagedToolBinding, ToolBinding,
        ToolMode,
    },
    invocation::{ToolCall, ToolCallSubmission},
    openapi::{OpenApiBinding, OpenApiSecurityAlternative},
    runtime::{
        ExecutionCancellation, ExecutionRequest, HostToolDispatcher, InvocationContext,
        InvocationToolDispatcher, RuntimeManager, ToolCall as RuntimeToolCall,
        ToolResult as RuntimeToolResult,
    },
};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use tokio::{net::TcpListener, sync::Notify};
use tower::ServiceExt;

#[derive(Clone, Default)]
struct UpstreamState {
    block_ask: Arc<AtomicBool>,
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

async fn upstream(
    State(state): State<UpstreamState>,
    OriginalUri(uri): OriginalUri,
) -> Json<Value> {
    if state.block_ask.load(Ordering::Acquire) {
        state.entered.notify_one();
        state.release.notified().await;
    }
    Json(json!({ "path": uri.path() }))
}

async fn api_request(
    router: Router,
    method: Method,
    uri: &str,
    body: String,
    headers: &[(&str, &str)],
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    router
        .oneshot(
            request
                .body(Body::from(body))
                .expect("request should build"),
        )
        .await
        .expect("router should answer")
}

async fn api_body(response: axum::response::Response) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response should collect")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("response should contain JSON")
}

fn response_cookies(response: &axum::response::Response) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie should be text")
                .split(';')
                .next()
                .expect("cookie should contain a value")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn fixture() -> (
    tempfile::TempDir,
    ExecutorApp,
    UpstreamState,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream should bind");
    let address = listener.local_addr().expect("upstream address should read");
    let upstream_state = UpstreamState::default();
    let server_state = upstream_state.clone();
    let upstream_task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(upstream).with_state(server_state),
        )
        .await
        .expect("upstream should serve");
    });
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    sqlx::query(
        "INSERT INTO api_tokens (id, name, token_digest, token_prefix, token_suffix, created_at) \
         VALUES ('runtime-owner', 'Runtime owner', x'010203', 'exr_test', 'test', 1)",
    )
    .execute(app.pool())
    .await
    .expect("owner token should insert");
    sqlx::query(
        "INSERT INTO admins (id, username, password_hash, created_at) \
         VALUES (1, 'admin', 'unused', 1)",
    )
    .execute(app.pool())
    .await
    .expect("admin should insert");

    let definitions = [
        ("enabled", ToolMode::Enabled),
        ("first", ToolMode::Ask),
        ("second", ToolMode::Ask),
        ("third", ToolMode::Ask),
        ("deny", ToolMode::Ask),
        ("cancel", ToolMode::Ask),
        ("revoke", ToolMode::Ask),
    ];
    let tools = definitions
        .iter()
        .map(|(name, mode)| StagedTool {
            stable_key: (*name).to_owned(),
            preferred_name: (*name).to_owned(),
            display_name: (*name).to_owned(),
            description: None,
            input_schema: json!({
                "type": "object",
                "additionalProperties": false
            }),
            output_schema: None,
            input_typescript: None,
            output_typescript: None,
            typescript_definitions: BTreeMap::new(),
            intrinsic_mode: *mode,
        })
        .collect();
    let bindings = definitions
        .iter()
        .map(|(name, _)| StagedToolBinding {
            stable_key: (*name).to_owned(),
            binding: ToolBinding::OpenapiV1(OpenApiBinding {
                version: 1,
                method: "GET".to_owned(),
                path_template: format!("/{name}"),
                server_url: format!("http://{address}"),
                parameters: Vec::new(),
                request_body: None,
                security: vec![OpenApiSecurityAlternative {
                    requirements: Vec::new(),
                }],
            }),
        })
        .collect();
    app.catalog()
        .create_source_with_catalog(
            CreateSource {
                kind: SourceKind::Openapi,
                preferred_slug: "runtime".to_owned(),
                display_name: "Runtime".to_owned(),
                description: None,
                configuration: Map::from_iter([
                    ("spec".to_owned(), json!({ "type": "inline" })),
                    ("allowPrivateNetwork".to_owned(), Value::Bool(true)),
                ]),
            },
            &CredentialPayload {
                schema_version: 1,
                payload: json!({
                    "locator": { "type": "inline" },
                    "credentials": { "schemes": {} }
                }),
            },
            InitialCatalogSnapshot {
                artifacts: vec![StagedArtifact {
                    kind: ArtifactKind::OpenapiDocument,
                    stable_key: "document".to_owned(),
                    content: json!({ "openapi": "3.1.0" }),
                }],
                tools,
            },
            bindings,
            AuditContext::system(Some("runtime-invocation-test")),
        )
        .await
        .expect("runtime fixture should import");
    (directory, app, upstream_state, upstream_task)
}

fn execution(
    app: &ExecutorApp,
    execution_id: &str,
) -> (RuntimeManager, Arc<InvocationToolDispatcher>) {
    let dispatcher = Arc::new(InvocationToolDispatcher::new(
        app.tool_calls().clone(),
        InvocationContext {
            request_id: uuid::Uuid::new_v4().to_string(),
            actor: ToolActor::api_token("runtime-owner", Some("Runtime owner".to_owned())),
            surface: RequestSurface::Gateway,
            execution_id: execution_id.to_owned(),
        },
    ));
    (
        RuntimeManager::new(env!("CARGO_BIN_EXE_executor")),
        dispatcher,
    )
}

async fn pending(
    app: &ExecutorApp,
    execution_id: &str,
    count: usize,
) -> Vec<executor::approval::ApprovalRecord> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let approvals = app
                .tool_calls()
                .approvals()
                .list_admin(ApprovalListQuery {
                    limit: 100,
                    status: Some(ApprovalStatus::Pending),
                    ..Default::default()
                })
                .await
                .expect("approvals should list")
                .items
                .into_iter()
                .filter(|approval| approval.execution_id == execution_id)
                .collect::<Vec<_>>();
            if approvals.len() == count {
                break approvals;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pending approvals should appear")
}

#[tokio::test]
async fn real_worker_dispatches_enabled_openapi_and_builtin_discovery() {
    let (_directory, app, _upstream_state, upstream_task) = fixture().await;
    let execution_id = "runtime-enabled";
    let (manager, dispatcher) = execution(&app, execution_id);
    let output = manager
        .execute(
            ExecutionRequest {
                execution_id: execution_id.to_owned(),
                code: "const found = await tools.search({query: 'enabled'}); const described = await tools.describe({path: 'runtime.enabled'}); const sources = await tools.sources(); const result = await tools.runtime.enabled(); return {found: found.total, described: described.path, sources: sources.length, result};".to_owned(),
                timeout: Duration::from_secs(5),
            },
            dispatcher.clone(),
            ExecutionCancellation::default(),
        )
        .await
        .expect("enabled execution should succeed");
    dispatcher.finish().await;
    assert_eq!(output.result["described"], "runtime.enabled");
    assert_eq!(output.result["sources"], 1);
    assert_eq!(output.result["result"]["path"], "/enabled");
    assert!(
        output.result["found"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );
    upstream_task.abort();
}

#[tokio::test]
async fn concurrent_ask_calls_settle_independently_in_javascript_order() {
    let (_directory, app, _upstream_state, upstream_task) = fixture().await;
    let execution_id = "runtime-concurrent-ask";
    let (manager, dispatcher) = execution(&app, execution_id);
    let runtime_dispatcher = dispatcher.clone();
    let execution = tokio::spawn(async move {
        manager
            .execute(
                ExecutionRequest {
                    execution_id: execution_id.to_owned(),
                    code: "return await Promise.all([tools.runtime.first(), tools.runtime.second(), tools.runtime.third()]);"
                        .to_owned(),
                    timeout: Duration::from_secs(5),
                },
                runtime_dispatcher,
                ExecutionCancellation::default(),
            )
            .await
    });
    let approvals = pending(&app, execution_id, 3).await;
    let first = approvals
        .iter()
        .find(|approval| approval.callable_path_snapshot.ends_with(".first"))
        .expect("first approval should exist");
    let second = approvals
        .iter()
        .find(|approval| approval.callable_path_snapshot.ends_with(".second"))
        .expect("second approval should exist");
    let third = approvals
        .iter()
        .find(|approval| approval.callable_path_snapshot.ends_with(".third"))
        .expect("third approval should exist");
    assert!(first.worker_generation > 0 && first.worker_generation <= i64::MAX as u64);
    assert_eq!(first.worker_generation, second.worker_generation);
    app.tool_calls()
        .decide(
            &second.id,
            "approve-second",
            second.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("second approval should succeed");
    app.tool_calls()
        .decide(
            &third.id,
            "deny-third",
            third.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("third denial should succeed");
    app.tool_calls()
        .decide(
            &first.id,
            "approve-first",
            first.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("first approval should succeed");
    let output = execution
        .await
        .expect("execution task should not panic")
        .expect("approved execution should succeed");
    dispatcher.finish().await;
    assert_eq!(output.result[0]["path"], "/first", "{}", output.result);
    assert_eq!(output.result[1]["path"], "/second");
    assert_eq!(output.result[2]["error"]["code"], "approval_denied");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let distinct = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(DISTINCT request_id) FROM request_logs \
                 WHERE approval_id IN (?, ?, ?)",
            )
            .bind(&first.id)
            .bind(&second.id)
            .bind(&third.id)
            .fetch_one(app.pool())
            .await
            .expect("request logs should read");
            if distinct >= 3 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("concurrent calls should have distinct request IDs");
    upstream_task.abort();
}

#[tokio::test]
async fn catalog_revision_change_marks_waiting_approval_stale() {
    let (_directory, app, _upstream_state, upstream_task) = fixture().await;
    let execution_id = "runtime-stale";
    let (manager, dispatcher) = execution(&app, execution_id);
    let runtime_dispatcher = dispatcher.clone();
    let execution = tokio::spawn(async move {
        manager
            .execute(
                ExecutionRequest {
                    execution_id: execution_id.to_owned(),
                    code: "return await tools.runtime.first();".to_owned(),
                    timeout: Duration::from_secs(5),
                },
                runtime_dispatcher,
                ExecutionCancellation::default(),
            )
            .await
    });
    let approval = pending(&app, execution_id, 1).await.remove(0);
    let tool = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("tools should list")
        .items
        .into_iter()
        .find(|tool| tool.local_name == "first")
        .expect("Ask tool should exist");
    app.catalog()
        .set_tool_mode(
            &tool.id,
            Some(ToolMode::Enabled),
            tool.revision,
            AuditContext::system(Some("runtime-stale-test")),
        )
        .await
        .expect("tool revision should change");
    app.tool_calls()
        .decide(
            &approval.id,
            "approve-stale",
            approval.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("approval decision should persist");
    let output = execution
        .await
        .expect("execution task should not panic")
        .expect("stale approval should settle as a value");
    assert_eq!(output.result["error"]["code"], "approval_stale");
    dispatcher.finish().await;
    upstream_task.abort();
}

#[tokio::test]
async fn dropped_runtime_waiter_still_cancels_pending_approval() {
    let (_directory, app, _upstream_state, upstream_task) = fixture().await;
    let execution_id = "runtime-dropped-waiter";
    let (manager, dispatcher) = execution(&app, execution_id);
    let execution = tokio::spawn(async move {
        manager
            .execute(
                ExecutionRequest {
                    execution_id: execution_id.to_owned(),
                    code: "return await tools.runtime.cancel();".to_owned(),
                    timeout: Duration::from_secs(5),
                },
                dispatcher,
                ExecutionCancellation::default(),
            )
            .await
    });
    let approval = pending(&app, execution_id, 1).await.remove(0);
    let held_delivery = app
        .tool_calls()
        .submit(ToolCall {
            request_id: "held-dropped-waiter-delivery".to_owned(),
            actor: ToolActor::api_token("runtime-owner", Some("Runtime owner".to_owned())),
            surface: RequestSurface::Gateway,
            execution_id: execution_id.to_owned(),
            call_id: "1".to_owned(),
            worker_generation: approval.worker_generation,
            path: "runtime.cancel".to_owned(),
            arguments: json!({}),
        })
        .await
        .expect("the correlated delivery should be reusable");
    let ToolCallSubmission::ApprovalRequired(held_delivery) = held_delivery else {
        panic!("the correlated delivery should remain pending");
    };
    assert_eq!(held_delivery.id, approval.id);
    let pin_refs = sqlx::query_scalar::<_, i64>(
        "SELECT ref_count FROM approval_delivery_pins WHERE approval_id = ?",
    )
    .bind(&approval.id)
    .fetch_one(app.pool())
    .await
    .expect("both pending deliveries should be pinned");
    assert_eq!(pin_refs, 2);
    execution.abort();
    assert!(
        execution
            .await
            .expect_err("request waiter should be aborted")
            .is_cancelled()
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let detail = app
                .tool_calls()
                .approvals()
                .get_admin(&approval.id)
                .await
                .expect("approval should read")
                .expect("approval should remain stored");
            if detail.record.status == ApprovalStatus::Canceled {
                assert_eq!(detail.record.revision, 1);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached actor should complete approval cleanup");
    let pins = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM approval_delivery_pins WHERE approval_id = ?",
    )
    .bind(&approval.id)
    .fetch_one(app.pool())
    .await
    .expect("dropped waiter delivery pin should read");
    assert_eq!(
        pins, 0,
        "lost-execution cancellation must release pins atomically while another ticket is alive"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let logged = sqlx::query_scalar::<_, i64>(
                "SELECT EXISTS(SELECT 1 FROM request_logs \
                 WHERE approval_id = ? AND error_code = 'approval_canceled')",
            )
            .bind(&approval.id)
            .fetch_one(app.pool())
            .await
            .expect("canceled approval log should read");
            if logged != 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropped waiter cancellation should remain durably logged");
    drop(held_delivery);
    upstream_task.abort();
    let _ = upstream_task.await;
    app.begin_shutdown();
    drop(app);
}

#[tokio::test]
async fn cancellation_during_blocked_submission_leaves_no_delivery_pin() {
    let (_directory, app, _upstream_state, upstream_task) = fixture().await;
    let execution_id = "runtime-cancel-during-submit";
    let (_manager, dispatcher) = execution(&app, execution_id);
    let writer = app
        .pool()
        .begin_with("BEGIN IMMEDIATE")
        .await
        .expect("submission blocker should acquire the SQLite writer");
    let cancellation = ExecutionCancellation::default();
    let dispatch_cancellation = cancellation.clone();
    let dispatch = tokio::spawn({
        let dispatcher = dispatcher.clone();
        async move {
            dispatcher
                .dispatch(
                    RuntimeToolCall {
                        execution_id: execution_id.to_owned(),
                        worker_generation: 11,
                        call_id: 1,
                        path: "runtime.cancel".to_owned(),
                        arguments: json!({}),
                    },
                    dispatch_cancellation,
                )
                .await
        }
    });
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancellation.cancel();
    writer
        .commit()
        .await
        .expect("submission blocker should release the SQLite writer");

    let result = tokio::time::timeout(Duration::from_secs(2), dispatch)
        .await
        .expect("canceled submission should finish")
        .expect("dispatch task should join");
    assert!(matches!(
        result,
        RuntimeToolResult::InternalFailure { ref code } if code == "execution_cancelled"
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let (approvals, pins) = sqlx::query_as::<_, (i64, i64)>(
                "SELECT \
                 (SELECT COUNT(*) FROM approvals WHERE execution_id = ?), \
                 (SELECT COUNT(*) FROM approval_delivery_pins)",
            )
            .bind(execution_id)
            .fetch_one(app.pool())
            .await
            .expect("canceled submission state should read");
            if approvals == 1 && pins == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("canceled submission ticket should release its delivery pin");
    dispatcher.finish().await;
    upstream_task.abort();
}

#[tokio::test]
async fn cancellation_and_approval_claim_have_one_linearized_winner() {
    let (_directory, app, upstream_state, upstream_task) = fixture().await;

    let canceled_execution_id = "runtime-cancel-wins";
    let (manager, dispatcher) = execution(&app, canceled_execution_id);
    let cancellation = ExecutionCancellation::default();
    let runtime_cancellation = cancellation.clone();
    let runtime_dispatcher = dispatcher.clone();
    let canceled_execution = tokio::spawn(async move {
        manager
            .execute(
                ExecutionRequest {
                    execution_id: canceled_execution_id.to_owned(),
                    code: "return await tools.runtime.first();".to_owned(),
                    timeout: Duration::from_secs(5),
                },
                runtime_dispatcher,
                runtime_cancellation,
            )
            .await
    });
    let canceled_approval = pending(&app, canceled_execution_id, 1).await.remove(0);
    sqlx::query(
        "CREATE TRIGGER reject_cancel_winner_cleanup BEFORE UPDATE OF status ON approvals \
         WHEN OLD.execution_id = 'runtime-cancel-wins' AND NEW.status = 'canceled' BEGIN \
         SELECT RAISE(FAIL, 'hold cancellation cleanup'); END",
    )
    .execute(app.pool())
    .await
    .expect("cancellation cleanup blocker should install");
    cancellation.cancel();
    let canceled_decision = app
        .tool_calls()
        .decide(
            &canceled_approval.id,
            "approval-must-lose",
            canceled_approval.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await;
    assert!(canceled_decision.is_err());
    sqlx::query("DROP TRIGGER reject_cancel_winner_cleanup")
        .execute(app.pool())
        .await
        .expect("cancellation cleanup blocker should be removed");
    let canceled = canceled_execution
        .await
        .expect("canceled execution task should not panic")
        .expect_err("cancellation winner should stop the runtime");
    assert_eq!(canceled.code, "execution_cancelled");
    dispatcher.finish().await;

    upstream_state.block_ask.store(true, Ordering::Release);
    let claimed_execution_id = "runtime-claim-wins";
    let (manager, dispatcher) = execution(&app, claimed_execution_id);
    let cancellation = ExecutionCancellation::default();
    let runtime_cancellation = cancellation.clone();
    let runtime_dispatcher = dispatcher.clone();
    let claimed_execution = tokio::spawn(async move {
        manager
            .execute(
                ExecutionRequest {
                    execution_id: claimed_execution_id.to_owned(),
                    code: "return await tools.runtime.second();".to_owned(),
                    timeout: Duration::from_secs(5),
                },
                runtime_dispatcher,
                runtime_cancellation,
            )
            .await
    });
    let claimed_approval = pending(&app, claimed_execution_id, 1).await.remove(0);
    app.tool_calls()
        .decide(
            &claimed_approval.id,
            "approval-must-win",
            claimed_approval.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("approval should claim execution");
    tokio::time::timeout(Duration::from_secs(2), upstream_state.entered.notified())
        .await
        .expect("approved request should reach upstream after claim");
    cancellation.cancel();
    upstream_state.release.notify_one();
    let stopped = claimed_execution
        .await
        .expect("claimed execution task should not panic")
        .expect_err("lost continuation should stop waiting for claimed work");
    assert_eq!(stopped.code, "execution_cancelled");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let detail = app
                .tool_calls()
                .approvals()
                .get_admin(&claimed_approval.id)
                .await
                .expect("claimed approval should read")
                .expect("claimed approval should remain stored");
            if detail.record.status == ApprovalStatus::Succeeded {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("already executing approved work should finish truthfully");
    dispatcher.finish().await;
    upstream_task.abort();
}

#[tokio::test]
async fn persistent_cleanup_failure_defers_safely_without_hanging_shutdown() {
    let (_directory, app, _upstream_state, upstream_task) = fixture().await;
    let execution_id = "runtime-persistent-cleanup-failure";
    let (manager, dispatcher) = execution(&app, execution_id);
    let cancellation = ExecutionCancellation::default();
    let runtime_cancellation = cancellation.clone();
    let execution = tokio::spawn(async move {
        manager
            .execute(
                ExecutionRequest {
                    execution_id: execution_id.to_owned(),
                    code: "return await tools.runtime.cancel();".to_owned(),
                    timeout: Duration::from_secs(5),
                },
                dispatcher,
                runtime_cancellation,
            )
            .await
    });
    let approval = pending(&app, execution_id, 1).await.remove(0);
    sqlx::query(
        "CREATE TRIGGER reject_runtime_cleanup BEFORE UPDATE OF status ON approvals \
         WHEN NEW.status = 'canceled' BEGIN \
         SELECT RAISE(FAIL, 'forced persistent cleanup failure'); END",
    )
    .execute(app.pool())
    .await
    .expect("persistent cleanup failure trigger should install");
    cancellation.cancel();
    let failure = tokio::time::timeout(Duration::from_secs(2), execution)
        .await
        .expect("bounded cleanup should let the execution finish")
        .expect("execution task should not panic")
        .expect_err("canceled execution should fail");
    assert_eq!(failure.code, "execution_cancelled");

    let decision = app
        .tool_calls()
        .decide(
            &approval.id,
            "must-not-approve-lost-continuation",
            approval.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await;
    assert!(
        decision.is_err(),
        "lost continuation must not become executable"
    );
    let stored = app
        .tool_calls()
        .approvals()
        .get_admin(&approval.id)
        .await
        .expect("approval should remain readable")
        .expect("approval should remain stored");
    assert_eq!(stored.record.status, ApprovalStatus::Pending);

    upstream_task.abort();
    tokio::time::timeout(Duration::from_secs(2), app.shutdown())
        .await
        .expect("persistent cleanup failure must not hang shutdown");
}

#[tokio::test]
async fn denial_revocation_cancellation_and_correlation_fail_closed() {
    let (_directory, app, _upstream_state, upstream_task) = fixture().await;

    let execution_id = "runtime-denied";
    let (manager, dispatcher) = execution(&app, execution_id);
    let runtime_dispatcher = dispatcher.clone();
    let denied = tokio::spawn(async move {
        manager
            .execute(
                ExecutionRequest {
                    execution_id: execution_id.to_owned(),
                    code: "return await tools.runtime.deny();".to_owned(),
                    timeout: Duration::from_secs(5),
                },
                runtime_dispatcher,
                ExecutionCancellation::default(),
            )
            .await
    });
    let approval = pending(&app, execution_id, 1).await.remove(0);
    app.tool_calls()
        .decide(
            &approval.id,
            "deny-runtime",
            approval.revision,
            ApprovalDecision::Deny,
            1,
        )
        .await
        .expect("denial should succeed");
    let output = denied
        .await
        .expect("denied task should not panic")
        .expect("denial should remain a tool value");
    assert_eq!(output.result["error"]["code"], "approval_denied");
    dispatcher.finish().await;

    let correlation = Arc::new(InvocationToolDispatcher::new(
        app.tool_calls().clone(),
        InvocationContext {
            request_id: "correlation-request".to_owned(),
            actor: ToolActor::api_token("runtime-owner", None),
            surface: RequestSurface::Gateway,
            execution_id: "expected-execution".to_owned(),
        },
    ));
    let result = correlation
        .dispatch(
            RuntimeToolCall {
                execution_id: "wrong-execution".to_owned(),
                worker_generation: 1,
                call_id: 1,
                path: "runtime.enabled".to_owned(),
                arguments: json!({}),
            },
            ExecutionCancellation::default(),
        )
        .await;
    assert!(matches!(
        result,
        RuntimeToolResult::InternalFailure { ref code } if code == "tool_correlation_failed"
    ));
    correlation.finish().await;

    let execution_id = "runtime-canceled";
    let (manager, dispatcher) = execution(&app, execution_id);
    let cancellation = ExecutionCancellation::default();
    let runtime_cancellation = cancellation.clone();
    let runtime_dispatcher = dispatcher.clone();
    let canceled = tokio::spawn(async move {
        manager
            .execute(
                ExecutionRequest {
                    execution_id: execution_id.to_owned(),
                    code: "return await tools.runtime.cancel();".to_owned(),
                    timeout: Duration::from_secs(5),
                },
                runtime_dispatcher,
                runtime_cancellation,
            )
            .await
    });
    let approval = pending(&app, execution_id, 1).await.remove(0);
    cancellation.cancel();
    let failure = canceled
        .await
        .expect("canceled task should not panic")
        .expect_err("canceled execution should fail");
    assert_eq!(failure.code, "execution_cancelled");
    dispatcher.finish().await;
    let approval = app
        .tool_calls()
        .approvals()
        .get_admin(&approval.id)
        .await
        .expect("approval should read")
        .expect("approval should remain stored");
    assert_eq!(approval.record.status, ApprovalStatus::Canceled);
    assert_eq!(approval.record.revision, 1);

    let execution_id = "runtime-revoked";
    let (manager, dispatcher) = execution(&app, execution_id);
    let runtime_dispatcher = dispatcher.clone();
    let revoked = tokio::spawn(async move {
        manager
            .execute(
                ExecutionRequest {
                    execution_id: execution_id.to_owned(),
                    code: "return await tools.runtime.revoke();".to_owned(),
                    timeout: Duration::from_secs(5),
                },
                runtime_dispatcher,
                ExecutionCancellation::default(),
            )
            .await
    });
    pending(&app, execution_id, 1).await;
    assert!(
        app.tool_calls()
            .revoke_owner_token("runtime-owner")
            .await
            .expect("token revocation should succeed")
    );
    let output = revoked
        .await
        .expect("revoked task should not panic")
        .expect("revocation should settle the tool promise");
    assert_eq!(output.result["error"]["code"], "approval_canceled");
    dispatcher.finish().await;
    upstream_task.abort();
}

#[tokio::test]
async fn execute_api_authenticates_before_body_and_enforces_source_and_time_limits() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("API upstream should bind");
    let upstream_address = listener.local_addr().expect("upstream address should read");
    let upstream_task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .fallback(upstream)
                .with_state(UpstreamState::default()),
        )
        .await
        .expect("API upstream should serve");
    });
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(
        AppConfig::new(directory.path().to_path_buf())
            .with_runtime_executable(env!("CARGO_BIN_EXE_executor").into()),
    )
    .await
    .expect("Executor should open");

    let oversized = json!({ "code": "x".repeat(2 * 1024 * 1024) }).to_string();
    let unauthenticated = api_request(
        app.router(),
        Method::POST,
        "/api/v1/gateway/execute",
        oversized,
        &[],
    )
    .await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let setup = api_request(
        app.router(),
        Method::POST,
        "/api/v1/setup",
        json!({
            "setupToken": app.setup_token().expect("setup token should exist"),
            "username": "admin",
            "password": "correct horse battery staple"
        })
        .to_string(),
        &[(header::ORIGIN.as_str(), "http://127.0.0.1:4788")],
    )
    .await;
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = api_request(
        app.router(),
        Method::POST,
        "/api/v1/session",
        json!({
            "username": "admin",
            "password": "correct horse battery staple"
        })
        .to_string(),
        &[(header::ORIGIN.as_str(), "http://127.0.0.1:4788")],
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
    let cookies = response_cookies(&login);
    let login_body = api_body(login).await;
    let csrf = login_body["csrfToken"]
        .as_str()
        .expect("setup should return CSRF");
    let token_response = api_request(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "Runtime API" }).to_string(),
        &[
            (header::COOKIE.as_str(), &cookies),
            (header::ORIGIN.as_str(), "http://127.0.0.1:4788"),
            ("x-executor-csrf", csrf),
            ("idempotency-key", "runtime-api-token"),
        ],
    )
    .await;
    assert_eq!(token_response.status(), StatusCode::CREATED);
    let token_body = api_body(token_response).await;
    let token = token_body["token"]
        .as_str()
        .expect("token should be returned")
        .to_owned();
    let token_id = token_body["id"]
        .as_str()
        .expect("token ID should be returned")
        .to_owned();
    let authorization = format!("Bearer {token}");

    let cookie_only = api_request(
        app.router(),
        Method::POST,
        "/api/v1/gateway/execute",
        json!({ "code": "return 1" }).to_string(),
        &[(header::COOKIE.as_str(), &cookies)],
    )
    .await;
    assert_eq!(cookie_only.status(), StatusCode::UNAUTHORIZED);

    let invalid_timeout = api_request(
        app.router(),
        Method::POST,
        "/api/v1/gateway/execute",
        json!({ "code": "return 1", "timeoutMs": 300_001 }).to_string(),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(invalid_timeout.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        api_body(invalid_timeout).await["error"]["code"],
        "invalid_timeout"
    );

    let invalid_json = api_request(
        app.router(),
        Method::POST,
        "/api/v1/gateway/execute",
        "{".to_owned(),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(invalid_json.status(), StatusCode::BAD_REQUEST);
    let invalid_request_id = invalid_json
        .headers()
        .get("x-request-id")
        .expect("invalid response should have a request ID")
        .to_str()
        .expect("request ID should be text")
        .to_owned();
    assert_eq!(
        api_body(invalid_json).await["error"]["code"],
        "invalid_json"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let recorded = sqlx::query_scalar::<_, i64>(
                "SELECT EXISTS(SELECT 1 FROM request_logs WHERE request_id = ? \
                 AND path_snapshot = 'executor.execute' AND error_code = 'invalid_json')",
            )
            .bind(&invalid_request_id)
            .fetch_one(app.pool())
            .await
            .expect("invalid execution log should read");
            if recorded != 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("authenticated invalid JSON should be logged");

    let source_too_large = api_request(
        app.router(),
        Method::POST,
        "/api/v1/gateway/execute",
        json!({ "code": "x".repeat(1024 * 1024 + 1) }).to_string(),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(source_too_large.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        api_body(source_too_large).await["error"]["code"],
        "source_too_large"
    );

    let valid = api_request(
        app.router(),
        Method::POST,
        "/api/v1/gateway/execute",
        json!({ "code": "emit({phase: 'ready'}); console.log('ok'); return 42" }).to_string(),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(valid.status(), StatusCode::OK);
    let valid = api_body(valid).await;
    assert_eq!(valid["result"], 42);
    assert_eq!(valid["emits"][0]["phase"], "ready");
    assert_eq!(valid["console"][0]["message"], "ok");
    assert!(valid["executionId"].as_str().is_some());
    assert_eq!(valid["calls"], json!([]));

    let source = api_request(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Runtime API source",
            "preferredSlug": "api",
            "spec": {
                "type": "inline",
                "content": json!({
                    "openapi": "3.1.0",
                    "info": { "title": "Runtime API" },
                    "servers": [{ "url": format!("http://{upstream_address}") }],
                    "paths": {
                        "/enabled": {
                            "get": {
                                "operationId": "enabled",
                                "security": [{}],
                                "responses": { "200": { "description": "ok" } }
                            }
                        },
                        "/ask": {
                            "post": {
                                "operationId": "ask",
                                "security": [{}],
                                "responses": { "200": { "description": "ok" } }
                            }
                        }
                    }
                }).to_string()
            },
            "allowPrivateNetwork": true
        })
        .to_string(),
        &[
            (header::COOKIE.as_str(), &cookies),
            (header::ORIGIN.as_str(), "http://127.0.0.1:4788"),
            ("x-executor-csrf", csrf),
        ],
    )
    .await;
    assert_eq!(
        source.status(),
        StatusCode::CREATED,
        "{}",
        api_body(source).await
    );

    let enabled = api_request(
        app.router(),
        Method::POST,
        "/api/v1/gateway/execute",
        json!({ "code": "return await tools.api.enabled()" }).to_string(),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(enabled.status(), StatusCode::OK);
    let enabled = api_body(enabled).await;
    assert_eq!(enabled["result"]["path"], "/enabled");
    assert_eq!(enabled["calls"].as_array().map(Vec::len), Some(1));

    let ask_router = app.router();
    let ask_authorization = authorization.clone();
    let ask = tokio::spawn(async move {
        api_request(
            ask_router,
            Method::POST,
            "/api/v1/gateway/execute",
            json!({ "code": "return await tools.api.ask()" }).to_string(),
            &[(header::AUTHORIZATION.as_str(), &ask_authorization)],
        )
        .await
    });
    let approval = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut pending = app
                .tool_calls()
                .approvals()
                .list_admin(ApprovalListQuery {
                    status: Some(ApprovalStatus::Pending),
                    limit: 100,
                    ..Default::default()
                })
                .await
                .expect("API approvals should list")
                .items;
            if let Some(approval) = pending
                .drain(..)
                .find(|approval| approval.callable_path_snapshot.ends_with(".ask"))
            {
                break approval;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("API approval should appear");
    let approved_id = approval.id.clone();
    app.tool_calls()
        .decide(
            &approval.id,
            "approve-api-runtime",
            approval.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await
        .expect("API approval should succeed");
    let ask = ask.await.expect("Ask HTTP task should not panic");
    assert_eq!(ask.status(), StatusCode::OK);
    assert_eq!(api_body(ask).await["result"]["path"], "/ask");

    let dropped_router = app.router();
    let dropped_authorization = authorization.clone();
    let dropped = tokio::spawn(async move {
        api_request(
            dropped_router,
            Method::POST,
            "/api/v1/gateway/execute",
            json!({ "code": "return await tools.api.ask()" }).to_string(),
            &[(header::AUTHORIZATION.as_str(), &dropped_authorization)],
        )
        .await
    });
    let dropped_approval = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pending = app
                .tool_calls()
                .approvals()
                .list_admin(ApprovalListQuery {
                    status: Some(ApprovalStatus::Pending),
                    limit: 100,
                    ..Default::default()
                })
                .await
                .expect("API approvals should list")
                .items;
            if let Some(approval) = pending
                .into_iter()
                .find(|approval| approval.id != approved_id)
            {
                break approval;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropped request approval should appear");
    sqlx::query(&format!(
        "CREATE TRIGGER reject_dropped_http_cleanup BEFORE UPDATE OF status ON approvals \
         WHEN OLD.execution_id = '{}' AND NEW.status = 'canceled' BEGIN \
         SELECT RAISE(FAIL, 'hold HTTP cancellation cleanup'); END",
        dropped_approval.execution_id
    ))
    .execute(app.pool())
    .await
    .expect("HTTP cancellation cleanup blocker should install");
    dropped.abort();
    assert!(
        dropped
            .await
            .expect_err("HTTP execution waiter should be aborted")
            .is_cancelled()
    );
    let dropped_decision = app
        .tool_calls()
        .decide(
            &dropped_approval.id,
            "dropped-request-must-not-execute",
            dropped_approval.revision,
            ApprovalDecision::Approve,
            1,
        )
        .await;
    assert!(
        dropped_decision.is_err(),
        "a disconnected HTTP execution must close its approval gate synchronously"
    );
    sqlx::query("DROP TRIGGER reject_dropped_http_cleanup")
        .execute(app.pool())
        .await
        .expect("HTTP cancellation cleanup blocker should be removed");

    let revoke_router = app.router();
    let revoke_authorization = authorization.clone();
    let waiting = tokio::spawn(async move {
        api_request(
            revoke_router,
            Method::POST,
            "/api/v1/gateway/execute",
            json!({ "code": "return await tools.api.ask()" }).to_string(),
            &[(header::AUTHORIZATION.as_str(), &revoke_authorization)],
        )
        .await
    });
    let pending_revoke = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pending = app
                .tool_calls()
                .approvals()
                .list_admin(ApprovalListQuery {
                    status: Some(ApprovalStatus::Pending),
                    limit: 100,
                    ..Default::default()
                })
                .await
                .expect("API approvals should list")
                .items;
            if let Some(approval) = pending
                .into_iter()
                .find(|approval| approval.id != approved_id && approval.id != dropped_approval.id)
            {
                break approval;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("revoked approval should appear");
    let revoked = api_request(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/tokens/{token_id}"),
        String::new(),
        &[
            (header::COOKIE.as_str(), &cookies),
            (header::ORIGIN.as_str(), "http://127.0.0.1:4788"),
            ("x-executor-csrf", csrf),
        ],
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    let waiting = waiting
        .await
        .expect("revoked execution task should not panic");
    assert_eq!(waiting.status(), StatusCode::CONFLICT);
    assert_eq!(
        api_body(waiting).await["error"]["code"],
        "execution_cancelled"
    );
    let pending_revoke = app
        .tool_calls()
        .approvals()
        .get_admin(&pending_revoke.id)
        .await
        .expect("revoked approval should read")
        .expect("revoked approval should remain stored");
    assert_eq!(pending_revoke.record.status, ApprovalStatus::Canceled);
    upstream_task.abort();
    app.shutdown().await;
}
