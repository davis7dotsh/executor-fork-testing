use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    routing::post,
};
use executor::{AppConfig, ExecutorApp};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::Semaphore};
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:4788";
const IDEMPOTENCY_KEY: &str = "idempotency-key";
const IDEMPOTENCY_REPLAYED: &str = "idempotency-replayed";

struct Admin {
    cookie: String,
    csrf: String,
}

#[derive(Debug)]
struct ResponseSnapshot {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl ResponseSnapshot {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response contains JSON")
    }
}

#[derive(Clone)]
struct DiscoveryGate {
    calls: Arc<AtomicUsize>,
    reached: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

impl DiscoveryGate {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            reached: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }

    async fn wait_until_reached(&self) {
        self.reached
            .acquire()
            .await
            .expect("discovery gate remains open")
            .forget();
    }

    fn release(&self) {
        self.release.add_permits(1);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn keyed_source_creation_replays_exact_bytes_without_repeating_side_effects() {
    let mcp_calls = Arc::new(AtomicUsize::new(0));
    let mcp_server_calls = mcp_calls.clone();
    let mcp_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("MCP listener binds");
    let mcp_address = mcp_listener.local_addr().expect("MCP address reads");
    let mcp_task = tokio::spawn(async move {
        axum::serve(
            mcp_listener,
            Router::new().route(
                "/mcp",
                post(move || {
                    let calls = mcp_server_calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::UNAUTHORIZED
                    }
                }),
            ),
        )
        .await
        .expect("MCP server runs");
    });

    let directory = tempfile::tempdir().expect("temporary directory is created");
    let templates_path = directory.path().join("mcp-templates.json");
    std::fs::write(
        &templates_path,
        json!({
            "templates": [{
                "name": "deferred",
                "executable": "/bin/sh",
                "arguments": ["-c", "exit 1"],
                "secretEnvironment": ["API_TOKEN"]
            }]
        })
        .to_string(),
    )
    .expect("MCP templates write");
    let app = ExecutorApp::open(
        AppConfig::new(directory.path().to_path_buf())
            .with_mcp_stdio_templates_file(Some(templates_path)),
    )
    .await
    .expect("Executor opens");
    let admin = setup(&app).await;

    let openapi_spec = json!({
        "openapi": "3.1.0",
        "info": { "title": "Idempotent API", "version": "1" },
        "servers": [{ "url": "https://example.com" }],
        "paths": {}
    });
    let requests = [
        (
            "openapi-exact-replay",
            json!({
                "kind": "openapi",
                "displayName": "Idempotent API",
                "preferredSlug": "idempotent-api",
                "spec": { "type": "inline", "content": openapi_spec.to_string() }
            }),
        ),
        (
            "mcp-http-exact-replay",
            json!({
                "kind": "mcp_http",
                "displayName": "Deferred MCP HTTP",
                "preferredSlug": "deferred-mcp-http",
                "endpoint": format!("http://{mcp_address}/mcp"),
                "allowPrivateNetwork": true
            }),
        ),
        (
            "mcp-stdio-exact-replay",
            json!({
                "kind": "mcp_stdio",
                "displayName": "Deferred MCP stdio",
                "preferredSlug": "deferred-mcp-stdio",
                "templateName": "deferred",
                "secretValues": {}
            }),
        ),
    ];

    for (key, request) in requests {
        let first = send_snapshot(
            app.router(),
            Method::POST,
            "/api/v1/sources",
            request.clone(),
            mutation_headers(&admin, Some(key)),
        )
        .await;
        assert_eq!(
            first.status,
            StatusCode::CREATED,
            "first response for {key}"
        );
        assert!(
            !first.headers.contains_key(IDEMPOTENCY_REPLAYED),
            "fresh response must not be marked replayed"
        );
        assert_single_no_store(&first);
        let revision_after_first = app
            .catalog()
            .global_revision()
            .await
            .expect("catalog revision reads");
        let audits_after_first = audit_count(&app).await;

        let replay = send_snapshot(
            app.router(),
            Method::POST,
            "/api/v1/sources",
            request,
            mutation_headers(&admin, Some(key)),
        )
        .await;
        assert_eq!(replay.status, first.status, "replay status for {key}");
        assert_eq!(replay.body, first.body, "replay body for {key}");
        assert_single_no_store(&replay);
        assert_eq!(
            replay
                .headers
                .get(IDEMPOTENCY_REPLAYED)
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            app.catalog()
                .global_revision()
                .await
                .expect("catalog revision reads after replay"),
            revision_after_first,
            "replay must not bump the catalog revision"
        );
        assert_eq!(
            audit_count(&app).await,
            audits_after_first,
            "replay must not append an audit event"
        );

        let completed_status = send_snapshot(
            app.router(),
            Method::GET,
            "/api/v1/sources/idempotency",
            Value::Null,
            authentication_headers(&admin, Some(key)),
        )
        .await;
        assert_eq!(completed_status.status, first.status);
        assert_eq!(completed_status.body, first.body);
        assert_single_no_store(&completed_status);
        assert_eq!(
            completed_status
                .headers
                .get(IDEMPOTENCY_REPLAYED)
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );

        let sealed_completion = send_snapshot(
            app.router(),
            Method::POST,
            "/api/v1/sources/idempotency/seal",
            Value::Null,
            mutation_headers(&admin, Some(key)),
        )
        .await;
        assert_eq!(
            sealed_completion.status, first.status,
            "seal must return the completed response for {key}"
        );
        assert_eq!(sealed_completion.body, first.body);
        assert_single_no_store(&sealed_completion);
        assert_eq!(
            sealed_completion
                .headers
                .get(IDEMPOTENCY_REPLAYED)
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            app.catalog()
                .global_revision()
                .await
                .expect("catalog revision reads after completed seal"),
            revision_after_first
        );
        assert_eq!(audit_count(&app).await, audits_after_first);
    }

    assert_eq!(
        app.catalog()
            .list_sources()
            .await
            .expect("sources list")
            .len(),
        3
    );
    assert_eq!(mcp_calls.load(Ordering::SeqCst), 1);
    app.shutdown().await;
    mcp_task.abort();
}

#[tokio::test]
async fn concurrent_requests_detect_in_progress_and_mismatch_before_discovery() {
    let gate = DiscoveryGate::new();
    let (address, upstream_task) = start_gated_graphql(gate.clone()).await;
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    let key = "graphql-race";
    let request = graphql_request(address, "secret-one");

    let first_router = app.router();
    let first_headers = mutation_headers(&admin, Some(key));
    let first_request = request.clone();
    let first = tokio::spawn(async move {
        send_snapshot(
            first_router,
            Method::POST,
            "/api/v1/sources",
            first_request,
            first_headers,
        )
        .await
    });
    gate.wait_until_reached().await;
    assert_eq!(gate.calls(), 1);

    let duplicate = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        request.clone(),
        mutation_headers(&admin, Some(key)),
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    assert_eq!(duplicate.json()["error"]["code"], "idempotency_in_progress");
    assert_eq!(
        duplicate
            .headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );

    let seal_in_progress = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources/idempotency/seal",
        Value::Null,
        mutation_headers(&admin, Some(key)),
    )
    .await;
    assert_eq!(seal_in_progress.status, StatusCode::CONFLICT);
    assert_eq!(
        seal_in_progress.json()["error"]["code"],
        "idempotency_in_progress"
    );
    let in_progress_status = send_snapshot(
        app.router(),
        Method::GET,
        "/api/v1/sources/idempotency",
        Value::Null,
        authentication_headers(&admin, Some(key)),
    )
    .await;
    assert_eq!(in_progress_status.status, StatusCode::OK);
    assert_eq!(
        in_progress_status.json(),
        json!({ "status": "in_progress" })
    );
    assert_single_no_store(&in_progress_status);

    let mut changed_secret = request.clone();
    changed_secret["credential"]["token"] = json!("secret-two");
    assert_mismatch(&app, &admin, key, changed_secret).await;

    let mut changed_unknown_field = request.clone();
    changed_unknown_field["futureField"] = json!({ "nested": true });
    assert_mismatch(&app, &admin, key, changed_unknown_field).await;

    let mut changed_kind = request.clone();
    changed_kind["kind"] = json!("openapi");
    assert_mismatch(&app, &admin, key, changed_kind).await;
    assert_eq!(gate.calls(), 1, "mismatches must not repeat discovery");

    gate.release();
    let first = first.await.expect("first request task joins");
    assert_eq!(first.status, StatusCode::CREATED);
    let replay = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        request,
        mutation_headers(&admin, Some(key)),
    )
    .await;
    assert_eq!(replay.status, first.status);
    assert_eq!(replay.body, first.body);
    assert_eq!(gate.calls(), 1);
    app.shutdown().await;
    upstream_task.abort();
}

#[tokio::test]
async fn status_seal_and_key_validation_are_fail_closed() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;

    let unauthenticated = send_snapshot(
        app.router(),
        Method::GET,
        "/api/v1/sources/idempotency",
        Value::Null,
        idempotency_headers("status-key"),
    )
    .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    assert_single_no_store(&unauthenticated);

    let missing = send_snapshot(
        app.router(),
        Method::GET,
        "/api/v1/sources/idempotency",
        Value::Null,
        authentication_headers(&admin, Some("missing-key")),
    )
    .await;
    assert_eq!(missing.status, StatusCode::OK);
    assert_eq!(missing.json(), json!({ "status": "missing" }));
    assert_single_no_store(&missing);

    let missing_header = send_snapshot(
        app.router(),
        Method::GET,
        "/api/v1/sources/idempotency?key=query-values-are-ignored",
        Value::Null,
        authentication_headers(&admin, None),
    )
    .await;
    assert_eq!(missing_header.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        missing_header.json()["error"]["code"],
        "idempotency_key_required"
    );

    let request = openapi_request("Key validation", "key-validation");
    let mut invalid_headers = Vec::new();
    invalid_headers.push(mutation_headers(&admin, Some("")));
    invalid_headers.push(mutation_headers(&admin, Some("contains space")));
    invalid_headers.push(mutation_headers(&admin, Some(&"x".repeat(256))));
    let mut non_ascii = mutation_headers(&admin, None);
    non_ascii.insert(
        IDEMPOTENCY_KEY,
        HeaderValue::from_bytes(&[0x80]).expect("opaque header value builds"),
    );
    invalid_headers.push(non_ascii);
    let mut duplicate = mutation_headers(&admin, None);
    duplicate.append(IDEMPOTENCY_KEY, HeaderValue::from_static("first"));
    duplicate.append(IDEMPOTENCY_KEY, HeaderValue::from_static("second"));
    invalid_headers.push(duplicate);

    for headers in invalid_headers {
        let response = send_snapshot(
            app.router(),
            Method::POST,
            "/api/v1/sources",
            request.clone(),
            headers,
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(response.json()["error"]["code"], "invalid_idempotency_key");
    }

    let seal_without_csrf = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources/idempotency/seal",
        Value::Null,
        authentication_headers(&admin, Some("sealed-before-create")),
    )
    .await;
    assert_eq!(seal_without_csrf.status, StatusCode::FORBIDDEN);

    let sealed = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources/idempotency/seal",
        Value::Null,
        mutation_headers(&admin, Some("sealed-before-create")),
    )
    .await;
    assert_eq!(sealed.status, StatusCode::OK);
    assert_eq!(sealed.json(), json!({ "status": "abandoned" }));
    assert_single_no_store(&sealed);

    let delayed_create = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        request,
        mutation_headers(&admin, Some("sealed-before-create")),
    )
    .await;
    assert_eq!(delayed_create.status, StatusCode::CONFLICT);
    assert_eq!(
        delayed_create.json()["error"]["code"],
        "idempotency_abandoned"
    );

    let status = send_snapshot(
        app.router(),
        Method::GET,
        "/api/v1/sources/idempotency",
        Value::Null,
        authentication_headers(&admin, Some("sealed-before-create")),
    )
    .await;
    assert_eq!(status.json(), json!({ "status": "abandoned" }));
    assert!(
        app.catalog()
            .list_sources()
            .await
            .expect("sources list")
            .is_empty()
    );
    app.shutdown().await;
}

#[tokio::test]
async fn failed_and_successful_replays_remain_exact_and_private_after_source_deletion() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    let failed_key = "failed-key-must-not-be-stored";
    let secret_marker = "request-secret-must-not-be-stored";
    let failed_request = json!({
        "kind": "openapi",
        "displayName": "Invalid document",
        "preferredSlug": "invalid-document",
        "spec": { "type": "inline", "content": secret_marker }
    });

    let failed = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        failed_request.clone(),
        mutation_headers(&admin, Some(failed_key)),
    )
    .await;
    assert_eq!(failed.status, StatusCode::BAD_REQUEST);
    assert_single_no_store(&failed);
    let failed_replay = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        failed_request,
        mutation_headers(&admin, Some(failed_key)),
    )
    .await;
    assert_eq!(failed_replay.status, failed.status);
    assert_eq!(failed_replay.body, failed.body);
    assert_single_no_store(&failed_replay);
    assert_eq!(
        failed_replay
            .headers
            .get(IDEMPOTENCY_REPLAYED)
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let failed_status = send_snapshot(
        app.router(),
        Method::GET,
        "/api/v1/sources/idempotency",
        Value::Null,
        authentication_headers(&admin, Some(failed_key)),
    )
    .await;
    assert_eq!(failed_status.status, failed.status);
    assert_eq!(failed_status.body, failed.body);
    assert_single_no_store(&failed_status);
    assert_eq!(
        failed_status
            .headers
            .get(IDEMPOTENCY_REPLAYED)
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let failed_seal = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources/idempotency/seal",
        Value::Null,
        mutation_headers(&admin, Some(failed_key)),
    )
    .await;
    assert_eq!(failed_seal.status, failed.status);
    assert_eq!(failed_seal.body, failed.body);
    assert_single_no_store(&failed_seal);
    assert_eq!(
        failed_seal
            .headers
            .get(IDEMPOTENCY_REPLAYED)
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );

    let persisted = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT key_digest, request_digest, response_ciphertext \
         FROM source_creation_idempotency WHERE state = 'failed'",
    )
    .fetch_one(app.pool())
    .await
    .expect("failed idempotency row reads");
    for value in [&persisted.0, &persisted.1, &persisted.2] {
        let text = String::from_utf8_lossy(value);
        assert!(!text.contains(failed_key));
        assert!(!text.contains(secret_marker));
    }

    let success_key = "successful-replay-after-delete";
    let successful = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        openapi_request("Delete after create", "delete-after-create"),
        mutation_headers(&admin, Some(success_key)),
    )
    .await;
    assert_eq!(successful.status, StatusCode::CREATED);
    let source_id = successful.json()["id"]
        .as_str()
        .expect("created source has an ID")
        .to_owned();
    sqlx::query("DELETE FROM sources WHERE id = ?")
        .bind(&source_id)
        .execute(app.pool())
        .await
        .expect("source deletes directly for retention test");

    let replay_after_delete = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        openapi_request("Delete after create", "delete-after-create"),
        mutation_headers(&admin, Some(success_key)),
    )
    .await;
    assert_eq!(replay_after_delete.status, successful.status);
    assert_eq!(replay_after_delete.body, successful.body);
    assert_single_no_store(&replay_after_delete);
    assert!(
        app.catalog()
            .list_sources()
            .await
            .expect("sources list after replay")
            .is_empty(),
        "replay must not recreate a deleted source"
    );
    app.shutdown().await;
}

#[tokio::test]
async fn disconnecting_the_http_handler_does_not_cancel_source_creation() {
    let gate = DiscoveryGate::new();
    let (address, upstream_task) = start_gated_graphql(gate.clone()).await;
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    let key = "disconnected-handler";
    let request = graphql_request(address, "disconnect-secret");
    let request_for_task = request.clone();
    let router = app.router();
    let headers = mutation_headers(&admin, Some(key));
    let handler = tokio::spawn(async move {
        send_snapshot(
            router,
            Method::POST,
            "/api/v1/sources",
            request_for_task,
            headers,
        )
        .await
    });
    gate.wait_until_reached().await;
    handler.abort();
    gate.release();

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if app
                .catalog()
                .list_sources()
                .await
                .expect("sources list while waiting")
                .len()
                == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("detached source creation completes");

    let replay = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        request,
        mutation_headers(&admin, Some(key)),
    )
    .await;
    assert_eq!(replay.status, StatusCode::CREATED);
    assert_eq!(
        replay
            .headers
            .get(IDEMPOTENCY_REPLAYED)
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    assert_eq!(gate.calls(), 1);
    app.shutdown().await;
    upstream_task.abort();
}

#[tokio::test]
async fn settlement_storage_failure_is_recovered_to_an_interrupted_tombstone() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    sqlx::query(
        "CREATE TRIGGER reject_source_creation_failed_response \
         BEFORE UPDATE OF state ON source_creation_idempotency \
         WHEN NEW.state = 'failed' \
         BEGIN SELECT RAISE(FAIL, 'injected failed-response write error'); END",
    )
    .execute(app.pool())
    .await
    .expect("failure trigger installs");
    let key = "failed-response-storage-error";
    let response = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Invalid document",
            "preferredSlug": "invalid-storage-failure",
            "spec": { "type": "inline", "content": "not an OpenAPI document" }
        }),
        mutation_headers(&admin, Some(key)),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "idempotency_interrupted");

    let status = send_snapshot(
        app.router(),
        Method::GET,
        "/api/v1/sources/idempotency",
        Value::Null,
        authentication_headers(&admin, Some(key)),
    )
    .await;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.json(), json!({ "status": "interrupted" }));
    assert!(
        app.catalog()
            .list_sources()
            .await
            .expect("sources list")
            .is_empty()
    );
    app.shutdown().await;
}

#[tokio::test]
async fn app_shutdown_cancels_discovery_and_spawn_rejection_terminalizes_reservations() {
    let gate = DiscoveryGate::new();
    let (address, upstream_task) = start_gated_graphql(gate.clone()).await;
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    let key = "shutdown-during-discovery";
    let request = graphql_request(address, "shutdown-secret");
    let router = app.router();
    let headers = mutation_headers(&admin, Some(key));
    let in_flight = tokio::spawn(async move {
        send_snapshot(router, Method::POST, "/api/v1/sources", request, headers).await
    });
    gate.wait_until_reached().await;
    app.begin_shutdown();
    let interrupted = tokio::time::timeout(Duration::from_secs(5), in_flight)
        .await
        .expect("shutdown joins the supervised source creation")
        .expect("request task joins");
    assert_eq!(interrupted.status, StatusCode::CONFLICT);
    assert_eq!(
        interrupted.json()["error"]["code"],
        "idempotency_interrupted"
    );
    assert!(
        app.catalog()
            .list_sources()
            .await
            .expect("sources list after cancellation")
            .is_empty()
    );

    let rejected_key = "spawn-rejected-during-shutdown";
    let rejected = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        openapi_request("Rejected during shutdown", "rejected-during-shutdown"),
        mutation_headers(&admin, Some(rejected_key)),
    )
    .await;
    assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        rejected.json()["error"]["code"],
        "source_creation_unavailable"
    );
    let rejected_status = send_snapshot(
        app.router(),
        Method::GET,
        "/api/v1/sources/idempotency",
        Value::Null,
        authentication_headers(&admin, Some(rejected_key)),
    )
    .await;
    assert_eq!(rejected_status.json(), json!({ "status": "interrupted" }));

    gate.release();
    app.shutdown().await;
    upstream_task.abort();
}

async fn assert_mismatch(app: &ExecutorApp, admin: &Admin, key: &str, request: Value) {
    let response = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        request,
        mutation_headers(admin, Some(key)),
    )
    .await;
    assert_eq!(response.status, StatusCode::CONFLICT);
    assert_eq!(response.json()["error"]["code"], "idempotency_key_mismatch");
}

async fn start_gated_graphql(
    gate: DiscoveryGate,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("GraphQL listener binds");
    let address = listener.local_addr().expect("GraphQL address reads");
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/graphql",
                post(move |Json(_request): Json<Value>| {
                    let gate = gate.clone();
                    async move {
                        gate.calls.fetch_add(1, Ordering::SeqCst);
                        gate.reached.add_permits(1);
                        gate.release
                            .acquire()
                            .await
                            .expect("discovery gate remains open")
                            .forget();
                        Json(graphql_introspection())
                    }
                }),
            ),
        )
        .await
        .expect("GraphQL server runs");
    });
    (address, task)
}

fn graphql_request(address: std::net::SocketAddr, token: &str) -> Value {
    json!({
        "kind": "graphql",
        "displayName": "Idempotent GraphQL",
        "preferredSlug": "idempotent-graphql",
        "endpoint": format!("http://{address}/graphql"),
        "allowPrivateNetwork": true,
        "credential": { "type": "bearer", "token": token }
    })
}

fn graphql_introspection() -> Value {
    json!({
        "data": {
            "__schema": {
                "queryType": { "name": "Query" },
                "mutationType": null,
                "subscriptionType": null,
                "types": [
                    {
                        "kind": "SCALAR",
                        "name": "String",
                        "description": null,
                        "fields": null,
                        "inputFields": null,
                        "enumValues": null
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "description": null,
                        "inputFields": null,
                        "enumValues": null,
                        "fields": [{
                            "name": "hello",
                            "description": "Say hello",
                            "isDeprecated": false,
                            "args": [],
                            "type": { "kind": "SCALAR", "name": "String", "ofType": null }
                        }]
                    }
                ]
            }
        }
    })
}

fn openapi_request(display_name: &str, slug: &str) -> Value {
    let specification = json!({
        "openapi": "3.1.0",
        "info": { "title": display_name, "version": "1" },
        "servers": [{ "url": "https://example.com" }],
        "paths": {}
    });
    json!({
        "kind": "openapi",
        "displayName": display_name,
        "preferredSlug": slug,
        "spec": { "type": "inline", "content": specification.to_string() }
    })
}

async fn setup(app: &ExecutorApp) -> Admin {
    let setup_token = app.setup_token().expect("fresh instance has setup token");
    let setup = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/setup",
        json!({
            "setupToken": setup_token,
            "username": "admin",
            "password": "correct horse battery staple"
        }),
        origin_headers(),
    )
    .await;
    assert_eq!(setup.status, StatusCode::CREATED);

    let login = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/session",
        json!({
            "username": "admin",
            "password": "correct horse battery staple"
        }),
        origin_headers(),
    )
    .await;
    assert_eq!(login.status, StatusCode::OK);
    let cookie = login
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie is text")
                .split(';')
                .next()
                .expect("cookie has a value")
        })
        .collect::<Vec<_>>()
        .join("; ");
    let csrf = login.json()["csrfToken"]
        .as_str()
        .expect("login returns CSRF")
        .to_owned();
    Admin { cookie, csrf }
}

fn origin_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    headers
}

fn authentication_headers(admin: &Admin, key: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&admin.cookie).expect("cookie header is valid"),
    );
    if let Some(key) = key {
        headers.insert(
            IDEMPOTENCY_KEY,
            HeaderValue::from_str(key).expect("idempotency header builds"),
        );
    }
    headers
}

fn mutation_headers(admin: &Admin, key: Option<&str>) -> HeaderMap {
    let mut headers = authentication_headers(admin, key);
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    headers.insert(
        "x-executor-csrf",
        HeaderValue::from_str(&admin.csrf).expect("CSRF header is valid"),
    );
    headers
}

fn idempotency_headers(key: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        IDEMPOTENCY_KEY,
        HeaderValue::from_str(key).expect("idempotency header is valid"),
    );
    headers
}

fn assert_single_no_store(response: &ResponseSnapshot) {
    assert_eq!(
        response
            .headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .count(),
        1,
        "Cache-Control must be represented by exactly one header value"
    );
    assert_eq!(
        response
            .headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

async fn audit_count(app: &ExecutorApp) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(app.pool())
        .await
        .expect("audit count reads")
}

async fn send_snapshot(
    router: Router,
    method: Method,
    uri: &str,
    body: Value,
    mut headers: HeaderMap,
) -> ResponseSnapshot {
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body.to_string()))
        .expect("request builds");
    *request.headers_mut() = headers;
    let response = router.oneshot(request).await.expect("router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("response collects")
        .to_bytes()
        .to_vec();
    ResponseSnapshot {
        status,
        headers,
        body,
    }
}
