use std::{
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
};
use executor::{AppConfig, ExecutorApp};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::time::timeout;
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:4788";
const IDEMPOTENCY_KEY: &str = "idempotency-key";
const IDEMPOTENCY_REPLAYED: &str = "idempotency-replayed";
const REVOKE_RECONCILED: &str = "revoke-reconciled";

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

#[tokio::test]
async fn token_creation_requires_one_valid_idempotency_key_without_echoing_it() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    let name = "validation-name-must-not-be-echoed";

    let missing = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": name }),
        mutation_headers(&admin, None),
    )
    .await;
    assert_error(
        &missing,
        StatusCode::BAD_REQUEST,
        "idempotency_key_required",
        &[name],
    );

    let oversized = "x".repeat(256);
    let invalid_cases = ["", "contains space", oversized.as_str()];
    for invalid_key in invalid_cases {
        let response = send_snapshot(
            app.router(),
            Method::POST,
            "/api/v1/tokens",
            json!({ "name": name }),
            mutation_headers(&admin, Some(invalid_key)),
        )
        .await;
        assert_error(
            &response,
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            &[invalid_key, name],
        );
    }

    let mut non_ascii = mutation_headers(&admin, None);
    non_ascii.insert(
        IDEMPOTENCY_KEY,
        HeaderValue::from_bytes(&[0x80]).expect("opaque header value builds"),
    );
    let response = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": name }),
        non_ascii,
    )
    .await;
    assert_error(
        &response,
        StatusCode::BAD_REQUEST,
        "invalid_idempotency_key",
        &[name],
    );

    let first_duplicate = "duplicate-first-must-not-be-echoed";
    let second_duplicate = "duplicate-second-must-not-be-echoed";
    let mut duplicate = mutation_headers(&admin, None);
    duplicate.append(IDEMPOTENCY_KEY, HeaderValue::from_static(first_duplicate));
    duplicate.append(IDEMPOTENCY_KEY, HeaderValue::from_static(second_duplicate));
    let response = send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": name }),
        duplicate,
    )
    .await;
    assert_error(
        &response,
        StatusCode::BAD_REQUEST,
        "invalid_idempotency_key",
        &[first_duplicate, second_duplicate, name],
    );

    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM api_tokens")
        .fetch_one(app.pool())
        .await
        .expect("API token count reads");
    assert_eq!(count, 0, "invalid requests must not create API tokens");
    app.shutdown().await;
}

#[tokio::test]
async fn token_creation_replays_exactly_rejects_mismatches_and_converges_concurrently() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    let replay_key = unique_key("exact-replay");
    let name = "Exact replay";

    let first = create_token(&app, &admin, name, &replay_key).await;
    assert_eq!(first.status, StatusCode::CREATED);
    assert_json_content_type(&first);
    assert_single_no_store(&first);
    assert!(!first.headers.contains_key(IDEMPOTENCY_REPLAYED));
    let first_json = first.json();
    assert_eq!(
        first_json
            .as_object()
            .expect("created token response is an object")
            .len(),
        4,
        "idempotency must not change the successful response shape"
    );
    assert_eq!(first_json["name"], name);
    assert!(
        first_json["id"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "created token has an ID"
    );
    let plaintext_token = first_json["token"]
        .as_str()
        .expect("created token is revealed")
        .to_owned();
    assert!(plaintext_token.starts_with("exr_"));
    assert!(first_json["createdAt"].is_i64());

    let replay = create_token(&app, &admin, name, &replay_key).await;
    assert_eq!(replay.status, first.status);
    assert_eq!(
        replay.body, first.body,
        "replay must return exact token bytes"
    );
    assert_json_content_type(&replay);
    assert_single_no_store(&replay);
    assert_eq!(
        replay
            .headers
            .get(IDEMPOTENCY_REPLAYED)
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );

    let mismatched_name = "different-name-must-not-be-echoed";
    let mismatch = create_token(&app, &admin, mismatched_name, &replay_key).await;
    assert_error(
        &mismatch,
        StatusCode::CONFLICT,
        "idempotency_mismatch",
        &[mismatched_name, &replay_key, &plaintext_token],
    );

    let concurrent_key = unique_key("concurrent");
    let concurrent_name = "Concurrent token";
    let first_request = create_token(&app, &admin, concurrent_name, &concurrent_key);
    let second_request = create_token(&app, &admin, concurrent_name, &concurrent_key);
    let (first_concurrent, second_concurrent) = tokio::join!(first_request, second_request);
    assert_eq!(first_concurrent.status, StatusCode::CREATED);
    assert_eq!(second_concurrent.status, StatusCode::CREATED);
    assert_eq!(
        first_concurrent.body, second_concurrent.body,
        "concurrent callers must converge on one token"
    );
    let replay_markers = [&first_concurrent, &second_concurrent]
        .into_iter()
        .filter(|response| {
            response
                .headers
                .get(IDEMPOTENCY_REPLAYED)
                .is_some_and(|value| value == "true")
        })
        .count();
    assert_eq!(
        replay_markers, 1,
        "exactly one concurrent response is replayed"
    );
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM api_tokens WHERE name = ? AND revoked_at IS NULL",
    )
    .bind(concurrent_name)
    .fetch_one(app.pool())
    .await
    .expect("concurrent API token count reads");
    assert_eq!(count, 1);

    app.shutdown().await;
}

#[tokio::test]
async fn token_replay_survives_restart_without_plaintext_and_revocation_is_reconciled() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let config = AppConfig::new(directory.path().to_path_buf());
    let app = ExecutorApp::open(config.clone())
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    let replay_key = unique_key("restart-private");
    let created = create_token(&app, &admin, "Restart replay", &replay_key).await;
    assert_eq!(created.status, StatusCode::CREATED);
    let created_json = created.json();
    let token_id = created_json["id"]
        .as_str()
        .expect("created token has an ID")
        .to_owned();
    let plaintext_token = created_json["token"]
        .as_str()
        .expect("created token is revealed")
        .to_owned();
    assert_storage_omits(directory.path(), &[&replay_key, &plaintext_token]);

    app.shutdown().await;
    let app = ExecutorApp::open(config).await.expect("Executor reopens");
    let replay = create_token(&app, &admin, "Restart replay", &replay_key).await;
    assert_eq!(replay.status, created.status);
    assert_eq!(
        replay.body, created.body,
        "restart replay returns exact bytes"
    );
    assert_eq!(
        replay
            .headers
            .get(IDEMPOTENCY_REPLAYED)
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    assert_json_content_type(&replay);
    assert_single_no_store(&replay);
    assert_storage_omits(directory.path(), &[&replay_key, &plaintext_token]);

    let first_revoke = send_snapshot(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/tokens/{token_id}"),
        Value::Null,
        mutation_headers(&admin, None),
    )
    .await;
    assert_eq!(first_revoke.status, StatusCode::NO_CONTENT);
    assert!(first_revoke.body.is_empty());
    assert!(!first_revoke.headers.contains_key(REVOKE_RECONCILED));

    let repeated_revoke = send_snapshot(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/tokens/{token_id}"),
        Value::Null,
        mutation_headers(&admin, None),
    )
    .await;
    assert_eq!(repeated_revoke.status, StatusCode::NO_CONTENT);
    assert!(repeated_revoke.body.is_empty());
    assert_eq!(
        repeated_revoke
            .headers
            .get(REVOKE_RECONCILED)
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );

    let revoked_replay = create_token(&app, &admin, "Restart replay", &replay_key).await;
    assert_error(
        &revoked_replay,
        StatusCode::CONFLICT,
        "idempotency_replay_revoked",
        &[&replay_key, &plaintext_token],
    );
    assert_eq!(
        revoked_replay
            .headers
            .get(IDEMPOTENCY_REPLAYED)
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );

    let unknown_id = "unknown-token-id-secret-marker";
    let unknown = send_snapshot(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/tokens/{unknown_id}"),
        Value::Null,
        mutation_headers(&admin, None),
    )
    .await;
    assert_error(
        &unknown,
        StatusCode::NOT_FOUND,
        "token_not_found",
        &[unknown_id, &plaintext_token],
    );
    assert_storage_omits(directory.path(), &[&replay_key, &plaintext_token]);

    app.shutdown().await;
}

#[tokio::test]
async fn dropped_revoke_request_finishes_durably_and_reconciles() {
    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    let created = create_token(
        &app,
        &admin,
        "Dropped revoke request",
        &unique_key("dropped-revoke"),
    )
    .await;
    let token_id = created.json()["id"]
        .as_str()
        .expect("created token has an ID")
        .to_owned();

    let mut writer = app
        .pool()
        .acquire()
        .await
        .expect("test writer connection is acquired");
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *writer)
        .await
        .expect("test writer holds the SQLite write lock");

    let mut request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/v1/tokens/{token_id}"))
        .body(Body::from(Value::Null.to_string()))
        .expect("revoke request builds");
    *request.headers_mut() = mutation_headers(&admin, None);
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let router = app.router();
    let revoke_request = tokio::spawn(async move { router.oneshot(request).await });

    timeout(Duration::from_secs(2), async {
        loop {
            let in_use = app.pool().size() as usize - app.pool().num_idle();
            if in_use >= 2 && !revoke_request.is_finished() {
                tokio::time::sleep(Duration::from_millis(50)).await;
                if !revoke_request.is_finished() {
                    return;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("revoke reaches the blocked durable operation");
    revoke_request.abort();
    assert!(
        revoke_request
            .await
            .expect_err("dropped request task is canceled")
            .is_cancelled()
    );

    sqlx::query("COMMIT")
        .execute(&mut *writer)
        .await
        .expect("test writer releases the SQLite write lock");
    drop(writer);

    timeout(Duration::from_secs(2), async {
        loop {
            let revoked_at = sqlx::query_scalar::<_, Option<i64>>(
                "SELECT revoked_at FROM api_tokens WHERE id = ?",
            )
            .bind(&token_id)
            .fetch_one(app.pool())
            .await
            .expect("token revocation state reads");
            if revoked_at.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("supervised revoke completes after its request is dropped");

    let reconciled = send_snapshot(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/tokens/{token_id}"),
        Value::Null,
        mutation_headers(&admin, None),
    )
    .await;
    assert_eq!(reconciled.status, StatusCode::NO_CONTENT);
    assert_eq!(
        reconciled
            .headers
            .get(REVOKE_RECONCILED)
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );

    app.shutdown().await;
}

async fn create_token(
    app: &ExecutorApp,
    admin: &Admin,
    name: &str,
    idempotency_key: &str,
) -> ResponseSnapshot {
    send_snapshot(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": name }),
        mutation_headers(admin, Some(idempotency_key)),
    )
    .await
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

fn unique_key(scope: &str) -> String {
    format!(
        "token-delivery-{scope}-{}",
        TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn origin_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    headers
}

fn mutation_headers(admin: &Admin, idempotency_key: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&admin.cookie).expect("cookie header is valid"),
    );
    headers.insert(header::ORIGIN, HeaderValue::from_static(ORIGIN));
    headers.insert(
        "x-executor-csrf",
        HeaderValue::from_str(&admin.csrf).expect("CSRF header is valid"),
    );
    if let Some(idempotency_key) = idempotency_key {
        headers.insert(
            IDEMPOTENCY_KEY,
            HeaderValue::from_str(idempotency_key).expect("idempotency header is valid"),
        );
    }
    headers
}

fn assert_error(
    response: &ResponseSnapshot,
    expected_status: StatusCode,
    expected_code: &str,
    forbidden_values: &[&str],
) {
    assert_eq!(response.status, expected_status, "{}", response.text());
    assert_json_content_type(response);
    assert_single_no_store(response);
    let body = response.json();
    let envelope = body.as_object().expect("error response is an object");
    assert_eq!(envelope.len(), 1);
    let error = envelope["error"]
        .as_object()
        .expect("error envelope has an error object");
    assert_eq!(error.len(), 3);
    assert_eq!(error["code"], expected_code);
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty()),
        "error has a stable public message"
    );
    assert!(
        error["requestId"]
            .as_str()
            .is_some_and(|request_id| !request_id.is_empty()),
        "error has a request ID"
    );
    let encoded = response.text();
    for forbidden in forbidden_values {
        assert!(
            forbidden.is_empty() || !encoded.contains(forbidden),
            "error response must not echo sensitive input {forbidden:?}: {encoded}"
        );
    }
}

fn assert_json_content_type(response: &ResponseSnapshot) {
    assert_eq!(
        response
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
}

fn assert_single_no_store(response: &ResponseSnapshot) {
    assert_eq!(
        response
            .headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .count(),
        1
    );
    assert_eq!(
        response
            .headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

fn assert_storage_omits(data_dir: &Path, forbidden_values: &[&str]) {
    let mut inspected = 0;
    for entry in std::fs::read_dir(data_dir).expect("data directory reads") {
        let entry = entry.expect("data directory entry reads");
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with("executor.db") || !entry.path().is_file() {
            continue;
        }
        inspected += 1;
        let bytes = std::fs::read(entry.path()).expect("SQLite storage file reads");
        for forbidden in forbidden_values {
            assert!(
                !contains_bytes(&bytes, forbidden.as_bytes()),
                "SQLite storage {file_name} must not contain plaintext {forbidden:?}"
            );
        }
    }
    assert!(inspected > 0, "at least the SQLite database is inspected");
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
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
