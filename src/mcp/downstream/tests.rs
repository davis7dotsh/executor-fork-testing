use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, header},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{
    CancellationRegistry, McpRequestLimiter, PROTOCOL_HEADER, PROTOCOL_VERSION, SESSION_HEADER,
    SessionRegistrationRaceHook, accepts, cancellation_signal, mcp_execution_request_id,
    mcp_idempotency_key, rpc_id_string, valid_request_id, virtual_tools,
};
use crate::{
    AppConfig, ExecutorApp,
    catalog::{
        ArtifactKind, AuditContext, CreateSource, CredentialPayload, InitialCatalogSnapshot,
        SourceKind, StagedArtifact, StagedTool, StagedToolBinding, ToolBinding, ToolMode,
    },
    invocation::{McpIdempotencyClaim, McpIdempotencyRequest},
    openapi::{OpenApiBinding, OpenApiSecurityAlternative},
};

const ORIGIN: &str = "http://127.0.0.1:4788";
const PASSWORD: &str = "correct-horse-battery-staple";

#[test]
fn accept_parsing_requires_each_supported_transport_type() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/json, text/event-stream"),
    );
    assert!(accepts(&headers, "application/json"));
    assert!(accepts(&headers, "text/event-stream"));
    assert!(!accepts(&headers, "image/png"));

    headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/json;q=0, text/event-stream"),
    );
    assert!(!accepts(&headers, "application/json"));
}

#[test]
fn advertised_protocol_is_the_stable_revision() {
    assert_eq!(PROTOCOL_VERSION, "2025-11-25");
}

#[test]
fn only_five_stable_virtual_tools_are_advertised() {
    let tools = virtual_tools();
    assert_eq!(
        tools
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>(),
        ["execute", "call", "search", "describe", "sources"]
    );
    let sources = tools
        .iter()
        .find(|tool| tool.name == "sources")
        .expect("sources tool");
    assert_eq!(
        sources.output_schema.as_ref().expect("output schema"),
        &json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["sources"],
            "properties": {
                "sources": { "type": "array", "items": { "type": "object" } }
            }
        })
    );
}

#[test]
fn request_ids_are_bounded_strings_or_numbers() {
    assert!(valid_request_id(&serde_json::json!(42)));
    assert!(valid_request_id(&serde_json::json!("request")));
    assert!(!valid_request_id(&serde_json::Value::Null));
    assert!(!valid_request_id(&serde_json::json!(true)));
    assert!(!valid_request_id(&serde_json::json!("x".repeat(257))));
    assert_ne!(
        mcp_idempotency_key("session", &rpc_id_string(&json!(1))),
        mcp_idempotency_key("session", &rpc_id_string(&json!("1")))
    );
}

#[test]
fn execute_request_log_ids_are_safe_deterministic_and_bounded() {
    let token_id = "token-private-identity";
    let session_id = "session-private-identity";
    let raw_request_id = "request-private-identity".repeat(8);
    let rpc_request_id = json!(raw_request_id.clone());
    assert!(valid_request_id(&rpc_request_id));
    let correlation = rpc_id_string(&rpc_request_id);

    let request_log_id = mcp_execution_request_id(token_id, session_id, &correlation);
    assert_eq!(
        request_log_id,
        mcp_execution_request_id(token_id, session_id, &correlation)
    );
    assert_eq!(request_log_id.len(), 102);
    assert!(!request_log_id.contains(token_id));
    assert!(!request_log_id.contains(session_id));
    assert!(!request_log_id.contains(raw_request_id.as_str()));
    assert_ne!(
        request_log_id,
        mcp_execution_request_id("another-token", session_id, &correlation)
    );
    assert_ne!(
        request_log_id,
        mcp_execution_request_id(token_id, "another-session", &correlation)
    );

    let longest_request_id = json!("x".repeat(256));
    assert!(valid_request_id(&longest_request_id));
    let longest_request_log_id =
        mcp_execution_request_id(token_id, session_id, &rpc_id_string(&longest_request_id));
    assert_eq!(longest_request_log_id.len(), 102);
    assert_eq!(
        format!("{longest_request_log_id}:call:{}", u64::MAX).len(),
        128
    );
}

#[tokio::test]
async fn cancellation_arriving_before_call_registration_is_consumed() {
    let registry = CancellationRegistry::default();
    registry.cancel("session\0s:request");
    let registration = registry
        .register("session\0s:request".to_owned())
        .expect("pre-canceled request can register");
    tokio::time::timeout(
        std::time::Duration::from_millis(50),
        cancellation_signal(&registration).wait(),
    )
    .await
    .expect("pre-cancel signal resolves before side effects");
}

#[test]
fn request_limiter_is_per_token_and_releases_with_detached_work() {
    let limiter = McpRequestLimiter::new(16, 4);
    let permits = (0..4)
        .map(|_| limiter.try_acquire("token-a").expect("token slot"))
        .collect::<Vec<_>>();
    assert!(limiter.try_acquire("token-a").is_none());
    let other = limiter
        .try_acquire("token-b")
        .expect("another token keeps an independent allowance");
    drop(permits);
    assert!(limiter.try_acquire("token-a").is_some());
    drop(other);
}

#[tokio::test]
async fn saturated_execution_slots_do_not_block_cancellation_control() {
    let execution_limiter = McpRequestLimiter::new(16, 4);
    let _executions = (0..4)
        .map(|_| {
            execution_limiter
                .try_acquire("token-a")
                .expect("execution permit")
        })
        .collect::<Vec<_>>();
    assert!(execution_limiter.try_acquire("token-a").is_none());

    let registry = CancellationRegistry::default();
    let registration = registry
        .register("session\0s:request".to_owned())
        .expect("control registration");
    registry.cancel("session\0s:request");
    tokio::time::timeout(
        std::time::Duration::from_millis(50),
        cancellation_signal(&registration).wait(),
    )
    .await
    .expect("cancellation remains available under execution saturation");
}

#[tokio::test]
async fn expired_session_cancels_pending_ask_before_it_can_execute() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    configure_ask_tool(&app).await;
    let router = app.router();
    let setup = send_json(
        router.clone(),
        Method::POST,
        "/api/v1/setup",
        json!({
            "setupToken": app.setup_token().expect("setup token"),
            "username": "admin",
            "password": PASSWORD
        }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = send_json(
        router.clone(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": "admin", "password": PASSWORD }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    let cookie = response_cookies(&login);
    let login_body = response_json(login).await;
    let csrf = login_body["csrfToken"].as_str().expect("CSRF token");
    let token = response_json(
        send_json(
            router.clone(),
            Method::POST,
            "/api/v1/tokens",
            json!({ "name": "Expiring MCP" }),
            &[
                (header::COOKIE.as_str(), &cookie),
                (header::ORIGIN.as_str(), ORIGIN),
                ("x-executor-csrf", csrf),
                ("idempotency-key", "mcp-expiring-token"),
            ],
        )
        .await,
    )
    .await["token"]
        .as_str()
        .expect("API token")
        .to_owned();
    let authorization = format!("Bearer {token}");
    let transport_headers = [
        (header::HOST.as_str(), "127.0.0.1:4788"),
        (header::ORIGIN.as_str(), ORIGIN),
        (header::AUTHORIZATION.as_str(), authorization.as_str()),
        (
            header::ACCEPT.as_str(),
            "application/json, text/event-stream",
        ),
    ];
    let initialized = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": "expiry-initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "expiry-test", "version": "1" }
            }
        }),
        &transport_headers,
    )
    .await;
    let session = initialized
        .headers()
        .get(SESSION_HEADER)
        .expect("session header")
        .to_str()
        .expect("session text")
        .to_owned();
    let session_headers = [
        (header::HOST.as_str(), "127.0.0.1:4788"),
        (header::ORIGIN.as_str(), ORIGIN),
        (header::AUTHORIZATION.as_str(), authorization.as_str()),
        (
            header::ACCEPT.as_str(),
            "application/json, text/event-stream",
        ),
        (SESSION_HEADER, session.as_str()),
        (PROTOCOL_HEADER, PROTOCOL_VERSION),
    ];
    assert_eq!(
        send_json(
            router.clone(),
            Method::POST,
            "/mcp",
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            &session_headers,
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    let pending_ask = spawn_mcp_call(
        router.clone(),
        authorization.clone(),
        session.clone(),
        "expiry-ask",
        "call",
        json!({
            "path": "expiry_approval.write",
            "arguments": { "value": "must not execute" }
        }),
    );
    let approval_id = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Some(approval_id) = sqlx::query_scalar::<_, String>(
                "SELECT id FROM approvals WHERE status = 'pending' ORDER BY sequence DESC LIMIT 1",
            )
            .fetch_optional(app.pool())
            .await
            .expect("approval query")
            {
                break approval_id;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Ask approval should become pending");
    {
        let mut sessions = app
            .mcp_state()
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sessions
            .get_mut(&session)
            .expect("active session")
            .last_seen =
            std::time::Instant::now() - super::SESSION_TTL - std::time::Duration::from_secs(1);
    }
    let expired = send_json(
        router,
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": "expiry-trigger", "method": "ping" }),
        &session_headers,
    )
    .await;
    assert_eq!(expired.status(), StatusCode::NOT_FOUND);
    let canceled = tokio::time::timeout(std::time::Duration::from_secs(2), pending_ask)
        .await
        .expect("expiry should release the pending Ask")
        .expect("request task");
    assert_eq!(response_json(canceled).await["error"]["code"], -32603);
    let approval_status =
        sqlx::query_scalar::<_, String>("SELECT status FROM approvals WHERE id = ?")
            .bind(approval_id)
            .fetch_one(app.pool())
            .await
            .expect("approval status");
    assert_eq!(approval_status, "canceled");
    app.shutdown().await;
}

#[tokio::test]
async fn streamable_http_lifecycle_is_authenticated_session_bound_and_finite() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let router = app.router();
    let unauthenticated_oversized = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "padding": "x".repeat(9 * 1024 * 1024) }),
        &[
            (header::HOST.as_str(), "127.0.0.1:4788"),
            (header::ORIGIN.as_str(), ORIGIN),
        ],
    )
    .await;
    assert_eq!(unauthenticated_oversized.status(), StatusCode::UNAUTHORIZED);
    let invalid_origin_before_auth = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({}),
        &[
            (header::HOST.as_str(), "127.0.0.1:4788"),
            (header::ORIGIN.as_str(), "https://attacker.invalid"),
        ],
    )
    .await;
    assert_eq!(invalid_origin_before_auth.status(), StatusCode::FORBIDDEN);
    let setup = send_json(
        router.clone(),
        Method::POST,
        "/api/v1/setup",
        json!({
            "setupToken": app.setup_token().expect("setup token"),
            "username": "admin",
            "password": PASSWORD
        }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = send_json(
        router.clone(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": "admin", "password": PASSWORD }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    let cookie = response_cookies(&login);
    let login_body = response_json(login).await;
    let csrf = login_body["csrfToken"].as_str().expect("CSRF token");
    let token_response = send_json(
        router.clone(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "MCP" }),
        &[
            (header::COOKIE.as_str(), &cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", csrf),
            ("idempotency-key", "mcp-stream-primary-token"),
        ],
    )
    .await;
    let token_body = response_json(token_response).await;
    let token_id = token_body["id"].as_str().expect("token ID").to_owned();
    let token = token_body["token"].as_str().expect("API token").to_owned();
    let authorization = format!("Bearer {token}");
    let transport_headers = [
        (header::HOST.as_str(), "127.0.0.1:4788"),
        (header::ORIGIN.as_str(), ORIGIN),
        (header::AUTHORIZATION.as_str(), authorization.as_str()),
        (
            header::ACCEPT.as_str(),
            "application/json, text/event-stream",
        ),
    ];

    let wrong_host = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        &[(header::HOST.as_str(), "attacker.invalid")],
    )
    .await;
    assert_eq!(wrong_host.status(), StatusCode::FORBIDDEN);

    let initialized = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1" }
            }
        }),
        &transport_headers,
    )
    .await;
    assert_eq!(initialized.status(), StatusCode::OK);
    let session = initialized
        .headers()
        .get(SESSION_HEADER)
        .expect("session header")
        .to_str()
        .expect("session text")
        .to_owned();
    let body = response_json(initialized).await;
    assert_eq!(body["result"]["protocolVersion"], PROTOCOL_VERSION);

    let session_headers = [
        (header::HOST.as_str(), "127.0.0.1:4788"),
        (header::ORIGIN.as_str(), ORIGIN),
        (header::AUTHORIZATION.as_str(), authorization.as_str()),
        (
            header::ACCEPT.as_str(),
            "application/json, text/event-stream",
        ),
        (SESSION_HEADER, session.as_str()),
        (PROTOCOL_HEADER, PROTOCOL_VERSION),
    ];
    let notification = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        &session_headers,
    )
    .await;
    assert_eq!(notification.status(), StatusCode::ACCEPTED);
    let client_response = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": "server-request", "result": {} }),
        &session_headers,
    )
    .await;
    assert_eq!(client_response.status(), StatusCode::ACCEPTED);
    let null_response = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": "server-null", "result": null }),
        &session_headers,
    )
    .await;
    assert_eq!(null_response.status(), StatusCode::ACCEPTED);
    for invalid_envelope in [
        json!({ "jsonrpc": "2.0", "id": 20, "method": "ping", "result": {} }),
        json!({ "jsonrpc": "2.0", "id": 21, "result": {}, "error": { "code": -1, "message": "bad" } }),
        json!({ "jsonrpc": "2.0", "id": 22, "error": { "message": "missing code" } }),
        json!({ "jsonrpc": "2.0", "id": 23, "result": {}, "params": {} }),
    ] {
        let invalid = send_json(
            router.clone(),
            Method::POST,
            "/mcp",
            invalid_envelope,
            &session_headers,
        )
        .await;
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    }
    let missing_protocol = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": "missing-version", "method": "ping" }),
        &session_headers[..5],
    )
    .await;
    assert_eq!(missing_protocol.status(), StatusCode::BAD_REQUEST);
    let tools = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": "tools", "method": "tools/list" }),
        &session_headers,
    )
    .await;
    let body = response_json(tools).await;
    assert_eq!(body["result"]["tools"].as_array().map(Vec::len), Some(5));

    for (request_id, name, invalid_arguments, corrected_arguments) in [
        (
            "invalid-search",
            "search",
            json!({ "query": "tool", "limit": 0 }),
            json!({ "query": "tool" }),
        ),
        (
            "invalid-describe",
            "describe",
            json!({ "path": "" }),
            json!({ "path": "missing.tool" }),
        ),
        (
            "invalid-sources",
            "sources",
            json!({ "unexpected": true }),
            json!({}),
        ),
    ] {
        let invalid_call = json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": { "name": name, "arguments": invalid_arguments }
        });
        for _ in 0..2 {
            let invalid = response_json(
                send_json(
                    router.clone(),
                    Method::POST,
                    "/mcp",
                    invalid_call.clone(),
                    &session_headers,
                )
                .await,
            )
            .await;
            assert_eq!(invalid["error"]["code"], -32602);
        }
        let corrected = response_json(
            send_json(
                router.clone(),
                Method::POST,
                "/mcp",
                json!({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "tools/call",
                    "params": { "name": name, "arguments": corrected_arguments }
                }),
                &session_headers,
            )
            .await,
        )
        .await;
        assert!(corrected.get("result").is_some());
    }

    let sources_call = json!({
        "jsonrpc": "2.0",
        "id": "stable-call",
        "method": "tools/call",
        "params": { "name": "sources", "arguments": {} }
    });
    let first_sources = response_json(
        send_json(
            router.clone(),
            Method::POST,
            "/mcp",
            sources_call.clone(),
            &session_headers,
        )
        .await,
    )
    .await;
    assert!(first_sources["result"]["structuredContent"]["sources"].is_array());
    let replayed_sources = response_json(
        send_json(
            router.clone(),
            Method::POST,
            "/mcp",
            sources_call,
            &session_headers,
        )
        .await,
    )
    .await;
    assert_eq!(replayed_sources, first_sources);
    let mismatched = response_json(
        send_json(
            router.clone(),
            Method::POST,
            "/mcp",
            json!({
                "jsonrpc": "2.0",
                "id": "stable-call",
                "method": "tools/call",
                "params": { "name": "search", "arguments": { "query": "tool" } }
            }),
            &session_headers,
        )
        .await,
    )
    .await;
    assert_eq!(mismatched["error"]["code"], -32600);

    let get = send_empty(
        router.clone(),
        Method::GET,
        "/mcp",
        &[
            (header::HOST.as_str(), "127.0.0.1:4788"),
            (header::ORIGIN.as_str(), ORIGIN),
            (header::AUTHORIZATION.as_str(), authorization.as_str()),
            (header::ACCEPT.as_str(), "text/event-stream"),
            (SESSION_HEADER, session.as_str()),
            (PROTOCOL_HEADER, PROTOCOL_VERSION),
        ],
    )
    .await;
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        get.headers().get(header::ALLOW),
        Some(&HeaderValue::from_static("POST, DELETE, OPTIONS"))
    );

    let idempotency_rows_before_delete_race =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM gateway_invocation_idempotency")
            .fetch_one(app.pool())
            .await
            .expect("idempotency count");
    let delete_hook = Arc::new(SessionRegistrationRaceHook::default());
    *app.mcp_state()
        .session_registration_race_hook
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(delete_hook.clone());
    let pending_delete_race = spawn_mcp_call(
        router.clone(),
        authorization.clone(),
        session.clone(),
        "delete-race",
        "sources",
        json!({}),
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        delete_hook.validation_complete.notified(),
    )
    .await
    .expect("tools/call should pause after session validation");
    let deleted = send_empty(router.clone(), Method::DELETE, "/mcp", &session_headers).await;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    delete_hook.continue_registration.notify_one();
    let delete_race_response =
        tokio::time::timeout(std::time::Duration::from_secs(1), pending_delete_race)
            .await
            .expect("deleted session request should stop")
            .expect("request task");
    assert_eq!(
        response_json(delete_race_response).await["error"]["code"],
        -32603
    );
    *app.mcp_state()
        .session_registration_race_hook
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let idempotency_rows_after_delete_race =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM gateway_invocation_idempotency")
            .fetch_one(app.pool())
            .await
            .expect("idempotency count");
    assert_eq!(
        idempotency_rows_after_delete_race,
        idempotency_rows_before_delete_race
    );
    let after_delete = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }),
        &session_headers,
    )
    .await;
    assert_eq!(after_delete.status(), StatusCode::NOT_FOUND);

    let second_token = response_json(
        send_json(
            router.clone(),
            Method::POST,
            "/api/v1/tokens",
            json!({ "name": "Other MCP" }),
            &[
                (header::COOKIE.as_str(), &cookie),
                (header::ORIGIN.as_str(), ORIGIN),
                ("x-executor-csrf", csrf),
                ("idempotency-key", "mcp-stream-secondary-token"),
            ],
        )
        .await,
    )
    .await["token"]
        .as_str()
        .expect("second token")
        .to_owned();
    let new_session_response = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "test", "version": "1" }
            }
        }),
        &transport_headers,
    )
    .await;
    let new_session = new_session_response
        .headers()
        .get(SESSION_HEADER)
        .expect("new session")
        .to_str()
        .expect("session text")
        .to_owned();
    let new_session_headers = [
        (header::HOST.as_str(), "127.0.0.1:4788"),
        (header::ORIGIN.as_str(), ORIGIN),
        (header::AUTHORIZATION.as_str(), authorization.as_str()),
        (
            header::ACCEPT.as_str(),
            "application/json, text/event-stream",
        ),
        (SESSION_HEADER, new_session.as_str()),
        (PROTOCOL_HEADER, PROTOCOL_VERSION),
    ];
    assert_eq!(
        send_json(
            router.clone(),
            Method::POST,
            "/mcp",
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            &new_session_headers,
        )
        .await
        .status(),
        StatusCode::ACCEPTED
    );
    let other_authorization = format!("Bearer {second_token}");
    let cross_token = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": 10, "method": "ping" }),
        &[
            (header::HOST.as_str(), "127.0.0.1:4788"),
            (header::ORIGIN.as_str(), ORIGIN),
            (header::AUTHORIZATION.as_str(), &other_authorization),
            (
                header::ACCEPT.as_str(),
                "application/json, text/event-stream",
            ),
            (SESSION_HEADER, &new_session),
            (PROTOCOL_HEADER, PROTOCOL_VERSION),
        ],
    )
    .await;
    assert_eq!(cross_token.status(), StatusCode::NOT_FOUND);
    for request_id in 100..131 {
        let extra_session = send_json(
            router.clone(),
            Method::POST,
            "/mcp",
            json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "capacity-test", "version": "1" }
                }
            }),
            &transport_headers,
        )
        .await;
        assert_eq!(extra_session.status(), StatusCode::OK);
    }
    let token_capacity = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": 131,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "capacity-test", "version": "1" }
            }
        }),
        &transport_headers,
    )
    .await;
    assert_eq!(token_capacity.status(), StatusCode::SERVICE_UNAVAILABLE);
    let idempotency_rows_before_revoke_race =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM gateway_invocation_idempotency")
            .fetch_one(app.pool())
            .await
            .expect("idempotency count");
    let revoke_hook = Arc::new(SessionRegistrationRaceHook::default());
    *app.mcp_state()
        .session_registration_race_hook
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(revoke_hook.clone());
    let pending_revoke_race = spawn_mcp_call(
        router.clone(),
        authorization.clone(),
        new_session.clone(),
        "revoke-race",
        "sources",
        json!({}),
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        revoke_hook.validation_complete.notified(),
    )
    .await
    .expect("tools/call should pause after session validation");
    let revoked = send_empty(
        router.clone(),
        Method::DELETE,
        &format!("/api/v1/tokens/{token_id}"),
        &[
            (header::COOKIE.as_str(), &cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", csrf),
        ],
    )
    .await;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    revoke_hook.continue_registration.notify_one();
    let revoke_race_response =
        tokio::time::timeout(std::time::Duration::from_secs(1), pending_revoke_race)
            .await
            .expect("revoked token request should stop")
            .expect("request task");
    assert_eq!(
        response_json(revoke_race_response).await["error"]["code"],
        -32603
    );
    *app.mcp_state()
        .session_registration_race_hook
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let idempotency_rows_after_revoke_race =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM gateway_invocation_idempotency")
            .fetch_one(app.pool())
            .await
            .expect("idempotency count");
    assert_eq!(
        idempotency_rows_after_revoke_race,
        idempotency_rows_before_revoke_race
    );
    let revoked_session = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "id": 11, "method": "ping" }),
        &[
            (header::HOST.as_str(), "127.0.0.1:4788"),
            (header::ORIGIN.as_str(), ORIGIN),
            (header::AUTHORIZATION.as_str(), &authorization),
            (
                header::ACCEPT.as_str(),
                "application/json, text/event-stream",
            ),
            (SESSION_HEADER, &new_session),
            (PROTOCOL_HEADER, PROTOCOL_VERSION),
        ],
    )
    .await;
    assert_eq!(revoked_session.status(), StatusCode::UNAUTHORIZED);

    let preflight = send_empty(
        router.clone(),
        Method::OPTIONS,
        "/mcp",
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(preflight.status(), StatusCode::NO_CONTENT);

    let shutdown_authorization = format!("Bearer {second_token}");
    let shutdown_transport_headers = [
        (header::HOST.as_str(), "127.0.0.1:4788"),
        (header::ORIGIN.as_str(), ORIGIN),
        (
            header::AUTHORIZATION.as_str(),
            shutdown_authorization.as_str(),
        ),
        (
            header::ACCEPT.as_str(),
            "application/json, text/event-stream",
        ),
    ];
    let shutdown_initialized = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({
            "jsonrpc": "2.0",
            "id": "shutdown-initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "shutdown-test", "version": "1" }
            }
        }),
        &shutdown_transport_headers,
    )
    .await;
    let shutdown_session = shutdown_initialized
        .headers()
        .get(SESSION_HEADER)
        .expect("shutdown session")
        .to_str()
        .expect("session text")
        .to_owned();
    let shutdown_session_headers = [
        (header::HOST.as_str(), "127.0.0.1:4788"),
        (header::ORIGIN.as_str(), ORIGIN),
        (
            header::AUTHORIZATION.as_str(),
            shutdown_authorization.as_str(),
        ),
        (
            header::ACCEPT.as_str(),
            "application/json, text/event-stream",
        ),
        (SESSION_HEADER, shutdown_session.as_str()),
        (PROTOCOL_HEADER, PROTOCOL_VERSION),
    ];
    let shutdown_notification = send_json(
        router.clone(),
        Method::POST,
        "/mcp",
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        &shutdown_session_headers,
    )
    .await;
    assert_eq!(shutdown_notification.status(), StatusCode::ACCEPTED);

    let (second_token_id,): (String,) =
        sqlx::query_as("SELECT id FROM api_tokens WHERE name = 'Other MCP'")
            .fetch_one(app.pool())
            .await
            .expect("second token ID");
    let shutdown_request_id = json!("shutdown-pending");
    let shutdown_correlation = rpc_id_string(&shutdown_request_id);
    let shutdown_idempotency = McpIdempotencyRequest {
        owner_api_token_id: second_token_id,
        key: mcp_idempotency_key(&shutdown_session, &shutdown_correlation),
        route: "POST /mcp tools/call".to_owned(),
        callable_path: "executor.sources".to_owned(),
        arguments: json!({}),
    };
    let reservation = match app
        .tool_calls()
        .claim_mcp_idempotency(&shutdown_idempotency)
        .await
        .expect("idempotency claim")
    {
        McpIdempotencyClaim::Fresh(reservation) => *reservation,
        _ => panic!("new shutdown request should own a fresh reservation"),
    };
    let execution = reservation
        .mark_executing()
        .await
        .expect("pending idempotency execution");
    let pending_authorization = shutdown_authorization.clone();
    let pending_session = shutdown_session.clone();
    let pending_request = tokio::spawn(async move {
        let headers = [
            (header::HOST.as_str(), "127.0.0.1:4788"),
            (header::ORIGIN.as_str(), ORIGIN),
            (
                header::AUTHORIZATION.as_str(),
                pending_authorization.as_str(),
            ),
            (
                header::ACCEPT.as_str(),
                "application/json, text/event-stream",
            ),
            (SESSION_HEADER, pending_session.as_str()),
            (PROTOCOL_HEADER, PROTOCOL_VERSION),
        ];
        send_json(
            router,
            Method::POST,
            "/mcp",
            json!({
                "jsonrpc": "2.0",
                "id": shutdown_request_id,
                "method": "tools/call",
                "params": { "name": "sources", "arguments": {} }
            }),
            &headers,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!pending_request.is_finished());
    app.begin_shutdown();
    let shutdown_response =
        tokio::time::timeout(std::time::Duration::from_secs(1), pending_request)
            .await
            .expect("pre-drain shutdown should release the pending handler")
            .expect("request task");
    assert_eq!(
        response_json(shutdown_response).await["error"]["code"],
        -32603
    );
    execution
        .mark_indeterminate()
        .await
        .expect("clean up synthetic execution");
    app.shutdown().await;
}

fn spawn_mcp_call(
    router: Router,
    authorization: String,
    session: String,
    request_id: &'static str,
    name: &'static str,
    arguments: Value,
) -> tokio::task::JoinHandle<Response<Body>> {
    tokio::spawn(async move {
        let headers = [
            (header::HOST.as_str(), "127.0.0.1:4788"),
            (header::ORIGIN.as_str(), ORIGIN),
            (header::AUTHORIZATION.as_str(), authorization.as_str()),
            (
                header::ACCEPT.as_str(),
                "application/json, text/event-stream",
            ),
            (SESSION_HEADER, session.as_str()),
            (PROTOCOL_HEADER, PROTOCOL_VERSION),
        ];
        send_json(
            router,
            Method::POST,
            "/mcp",
            json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": { "name": name, "arguments": arguments }
            }),
            &headers,
        )
        .await
    })
}

async fn configure_ask_tool(app: &ExecutorApp) {
    app.catalog()
        .create_source_with_catalog(
            CreateSource {
                kind: SourceKind::Openapi,
                preferred_slug: "expiry-approval".to_owned(),
                display_name: "Expiry approval source".to_owned(),
                description: None,
                configuration: json!({
                    "spec": { "type": "inline" },
                    "allowPrivateNetwork": true
                })
                .as_object()
                .expect("source configuration object")
                .clone(),
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
                tools: vec![StagedTool {
                    stable_key: "write".to_owned(),
                    preferred_name: "write".to_owned(),
                    display_name: "Write".to_owned(),
                    description: None,
                    input_schema: json!({
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["value"],
                        "properties": { "value": { "type": "string" } }
                    }),
                    output_schema: None,
                    input_typescript: None,
                    output_typescript: None,
                    typescript_definitions: BTreeMap::new(),
                    intrinsic_mode: ToolMode::Ask,
                }],
            },
            vec![StagedToolBinding {
                stable_key: "write".to_owned(),
                binding: ToolBinding::OpenapiV1(OpenApiBinding {
                    version: 1,
                    method: "POST".to_owned(),
                    path_template: "/write".to_owned(),
                    server_url: "http://127.0.0.1:9".to_owned(),
                    parameters: Vec::new(),
                    request_body: None,
                    security: vec![OpenApiSecurityAlternative {
                        requirements: Vec::new(),
                    }],
                }),
            }],
            AuditContext::system(Some("mcp-expiry-test")),
        )
        .await
        .expect("Ask tool should import");
}

async fn send_json(
    router: Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    router
        .oneshot(request.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("router response")
}

async fn send_empty(
    router: Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    router
        .oneshot(request.body(Body::empty()).expect("request"))
        .await
        .expect("router response")
}

async fn response_json(response: Response<Body>) -> Value {
    let body = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    serde_json::from_slice(&body).expect("JSON response")
}

fn response_cookies(response: &Response<Body>) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie text")
                .split(';')
                .next()
                .expect("cookie pair")
        })
        .collect::<Vec<_>>()
        .join("; ")
}
