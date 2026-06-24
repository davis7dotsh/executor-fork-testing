use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode, header},
};
use executor::{
    AppConfig, ExecutorApp,
    catalog::{AuditContext, ToolMode},
};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Notify},
};
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:4788";

struct Admin {
    cookie: String,
    csrf: String,
}

#[derive(Clone, Default)]
struct Recorder {
    count: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Recorder {
    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    async fn take_last(&self) -> Value {
        self.requests
            .lock()
            .await
            .last()
            .cloned()
            .expect("the upstream should have recorded a request")
    }
}

async fn record_upstream(State(recorder): State<Recorder>, request: Request<Body>) -> Json<Value> {
    recorder.count.fetch_add(1, Ordering::SeqCst);
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let headers = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), Value::String(value.to_owned())))
        })
        .collect::<Map<_, _>>();
    let body = request
        .into_body()
        .collect()
        .await
        .expect("upstream request body should collect")
        .to_bytes();
    let observed = json!({
        "method": method,
        "path": path,
        "query": query,
        "headers": headers,
        "body": String::from_utf8_lossy(&body),
    });
    recorder.requests.lock().await.push(observed.clone());
    Json(observed)
}

#[derive(Clone, Default)]
struct BlockingUpstream {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

async fn block_upstream(State(state): State<BlockingUpstream>) -> Json<Value> {
    state.entered.notify_one();
    state.release.notified().await;
    Json(json!({ "completed": true }))
}

async fn send(
    router: Router,
    method: Method,
    uri: &str,
    body: Value,
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
                .body(Body::from(body.to_string()))
                .expect("request should build"),
        )
        .await
        .expect("router should answer")
}

async fn response_body(response: axum::response::Response) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response should collect")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("response should contain JSON")
}

fn cookies(response: &axum::response::Response) -> String {
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
                .expect("cookie should have a value")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn setup(app: &ExecutorApp) -> Admin {
    let setup_token = app
        .setup_token()
        .expect("fresh instance should have a setup token");
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/setup",
        json!({
            "setupToken": setup_token,
            "username": "admin",
            "password": "correct horse battery staple"
        }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": "admin", "password": "correct horse battery staple" }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = cookies(&response);
    let csrf = response_body(response).await["csrfToken"]
        .as_str()
        .expect("login should return a CSRF token")
        .to_owned();
    Admin { cookie, csrf }
}

fn admin_headers(admin: &Admin) -> [(&str, &str); 3] {
    [
        (header::COOKIE.as_str(), admin.cookie.as_str()),
        (header::ORIGIN.as_str(), ORIGIN),
        ("x-executor-csrf", admin.csrf.as_str()),
    ]
}

async fn create_gateway_token(app: &ExecutorApp, admin: &Admin) -> String {
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "OpenAPI contract" }),
        &admin_headers(admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    response_body(response).await["token"]
        .as_str()
        .expect("token should be returned")
        .to_owned()
}

async fn invoke(
    app: &ExecutorApp,
    token: &str,
    path: &str,
    arguments: Value,
) -> (StatusCode, Value) {
    let authorization = format!("Bearer {token}");
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": path, "arguments": arguments }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    let status = response.status();
    (status, response_body(response).await)
}

async fn invoke_idempotent(
    app: &ExecutorApp,
    token: &str,
    key: &str,
    path: &str,
    arguments: Value,
) -> (StatusCode, Value, bool) {
    let authorization = format!("Bearer {token}");
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": path, "arguments": arguments }),
        &[
            (header::AUTHORIZATION.as_str(), &authorization),
            ("idempotency-key", key),
        ],
    )
    .await;
    let status = response.status();
    let replayed = response
        .headers()
        .get("idempotency-replayed")
        .is_some_and(|value| value == "true");
    (status, response_body(response).await, replayed)
}

fn operation(method: &str, operation_id: &str, security: Value) -> Value {
    json!({
        method: {
            "operationId": operation_id,
            "security": security,
            "responses": {
                "200": {
                    "description": "recorded",
                    "content": {
                        "application/json": { "schema": { "type": "object" } }
                    }
                }
            }
        }
    })
}

async fn set_mode(app: &ExecutorApp, local_name: &str, mode: ToolMode) {
    let tool = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("tools should list")
        .items
        .into_iter()
        .find(|tool| tool.local_name == local_name)
        .unwrap_or_else(|| panic!("tool {local_name} should exist"));
    app.catalog()
        .set_tool_mode(
            &tool.id,
            Some(mode),
            tool.revision,
            AuditContext::system(Some("openapi-gateway-contract")),
        )
        .await
        .expect("tool mode should update");
}

async fn wait_for_log(app: &ExecutorApp, path: &str, outcome: &str, error_code: &str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM request_logs \
                 WHERE path_snapshot = ? AND outcome = ? AND error_code = ?",
            )
            .bind(path)
            .bind(outcome)
            .bind(error_code)
            .fetch_one(app.pool())
            .await
            .expect("request logs should read");
            if count > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("request log {path} {outcome} {error_code} should be written"));
}

#[tokio::test]
async fn production_gateway_honors_openapi_security_arguments_bodies_and_modes() {
    let recorder = Recorder::default();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream listener should bind");
    let address = listener.local_addr().expect("upstream address should read");
    let upstream = Router::new()
        .fallback(record_upstream)
        .with_state(recorder.clone());
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("upstream should serve");
    });

    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;

    let mut paths = Map::new();
    for (path, operation_id, security) in [
        ("/anonymous", "anonymous", json!([{}])),
        (
            "/or-fallback",
            "or_fallback",
            json!([{ "MissingKey": [] }, {}]),
        ),
        ("/header", "header_key", json!([{ "HeaderKey": [] }])),
        ("/query", "query_key", json!([{ "QueryKey": [] }])),
        ("/cookie", "cookie_key", json!([{ "CookieKey": [] }])),
        ("/bearer", "bearer", json!([{ "BearerAuth": [] }])),
        ("/basic", "basic", json!([{ "BasicAuth": [] }])),
        ("/oauth", "oauth", json!([{ "OAuth": ["read"] }])),
        ("/no-body", "no_body", json!([{}])),
        ("/disabled", "disabled", json!([{}])),
    ] {
        paths.insert(path.to_owned(), operation("get", operation_id, security));
    }
    paths.insert(
        "/combined/{id}".to_owned(),
        json!({
            "get": {
                "operationId": "combined",
                "security": [{ "HeaderKey": [], "QueryKey": [] }],
                "parameters": [
                    { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } },
                    { "name": "q", "in": "query", "schema": { "type": "string" } },
                    { "name": "X-Input", "in": "header", "schema": { "type": "string" } },
                    { "name": "flavor", "in": "cookie", "schema": { "type": "string" } }
                ],
                "responses": { "200": { "description": "recorded" } }
            }
        }),
    );
    for (path, operation_id, content) in [
        ("/json", "json_body", "application/json"),
        ("/text", "text_body", "text/plain"),
        ("/form", "form_body", "application/x-www-form-urlencoded"),
        ("/ask", "ask", "application/json"),
    ] {
        let schema = match content {
            "application/x-www-form-urlencoded" => json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "a": { "type": "string" },
                    "b": { "type": "integer" }
                }
            }),
            "text/plain" => json!({ "type": "string" }),
            _ => json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["hello", "mode", "nested"],
                "properties": {
                    "hello": { "type": "string", "pattern": "^[a-z]+$" },
                    "count": { "type": "integer", "minimum": 1 },
                    "mode": { "enum": ["safe", "fast"] },
                    "tags": { "type": "array", "items": { "type": "string" }, "uniqueItems": true },
                    "nested": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["id"],
                        "properties": { "id": { "type": "integer" } }
                    },
                    "choice": {
                        "oneOf": [
                            { "type": "string", "pattern": "^choice-" },
                            { "type": "integer", "minimum": 1 }
                        ]
                    },
                    "maybe": { "type": ["string", "null"] }
                }
            }),
        };
        paths.insert(
            path.to_owned(),
            json!({
                "post": {
                    "operationId": operation_id,
                    "security": [{}],
                    "requestBody": {
                        "required": true,
                        "content": { content: { "schema": schema } }
                    },
                    "responses": { "200": { "description": "recorded" } }
                }
            }),
        );
    }
    paths.insert(
        "/multi".to_owned(),
        json!({
            "post": {
                "operationId": "multi_body",
                "security": [{}],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["json"],
                                "properties": { "json": { "type": "boolean" } }
                            }
                        },
                        "text/plain": { "schema": { "type": "string" } }
                    }
                },
                "responses": { "200": { "description": "recorded" } }
            }
        }),
    );
    for (path, operation_id, header_name) in [
        (
            "/method-override",
            "method_override",
            "X-HTTP-Method-Override",
        ),
        ("/http-method", "http_method", "X-HTTP-Method"),
        ("/original-method", "original_method", "X-Original-Method"),
        ("/forwarded", "forwarded", "X-Forwarded-For"),
    ] {
        paths.insert(
            path.to_owned(),
            json!({
                "get": {
                    "operationId": operation_id,
                    "security": [{}],
                    "parameters": [{
                        "name": header_name,
                        "in": "header",
                        "schema": { "type": "string" }
                    }],
                    "responses": { "200": { "description": "recorded" } }
                }
            }),
        );
    }

    let specification = json!({
        "openapi": "3.1.0",
        "info": { "title": "Gateway Contract" },
        "servers": [{ "url": format!("http://{address}") }],
        "components": {
            "securitySchemes": {
                "MissingKey": { "type": "apiKey", "in": "header", "name": "X-Missing" },
                "HeaderKey": { "type": "apiKey", "in": "header", "name": "X-Header-Key" },
                "QueryKey": { "type": "apiKey", "in": "query", "name": "query_key" },
                "CookieKey": { "type": "apiKey", "in": "cookie", "name": "cookie_key" },
                "BearerAuth": { "type": "http", "scheme": "bearer" },
                "BasicAuth": { "type": "http", "scheme": "basic" },
                "OAuth": {
                    "type": "oauth2",
                    "flows": {
                        "clientCredentials": {
                            "tokenUrl": "https://identity.example.test/token",
                            "scopes": { "read": "Read access" }
                        }
                    }
                }
            }
        },
        "paths": paths
    });
    let created = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Gateway Contract",
            "preferredSlug": "contract",
            "spec": { "type": "inline", "content": specification.to_string() },
            "allowPrivateNetwork": true,
            "credential": {
                "schemes": {
                    "HeaderKey": { "type": "api_key", "value": "header-secret" },
                    "QueryKey": { "type": "api_key", "value": "query-secret" },
                    "CookieKey": { "type": "api_key", "value": "cookie-secret" },
                    "BearerAuth": { "type": "bearer", "token": "bearer-secret" },
                    "BasicAuth": { "type": "basic", "username": "aladdin", "password": "open-sesame" },
                    "OAuth": { "type": "oauth_access_token", "access_token": "oauth-secret" }
                }
            }
        }),
        &admin_headers(&admin),
    )
    .await;
    let created_status = created.status();
    let created_body = response_body(created).await;
    assert_eq!(created_status, StatusCode::CREATED, "{created_body}");
    let token = create_gateway_token(&app, &admin).await;
    for tool in ["json_body", "text_body", "form_body", "multi_body"] {
        set_mode(&app, tool, ToolMode::Enabled).await;
    }
    set_mode(&app, "disabled", ToolMode::Disabled).await;

    for path in ["anonymous", "or_fallback"] {
        let (status, response) = invoke(&app, &token, &format!("contract.{path}"), json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["ok"], true);
    }

    let (status, response) = invoke(
        &app,
        &token,
        "contract.combined",
        json!({
            "path": { "id": "a/b" },
            "query": { "q": "hello world" },
            "headers": { "X-Input": "header input" },
            "cookies": { "flavor": "mint chip" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let observed = &response["data"];
    assert_eq!(observed["path"], "/combined/a%2Fb");
    let query = observed["query"].as_str().expect("query should be text");
    assert!(query.contains("q=hello+world"));
    assert!(query.contains("query_key=query-secret"));
    assert_eq!(observed["headers"]["x-header-key"], "header-secret");
    assert_eq!(observed["headers"]["x-input"], "header input");
    let cookie = observed["headers"]["cookie"]
        .as_str()
        .expect("cookie should be text");
    assert!(cookie.contains("flavor=mint%20chip"));

    let expected_auth = BTreeMap::from([
        ("header_key", ("x-header-key", "header-secret")),
        ("bearer", ("authorization", "Bearer bearer-secret")),
        (
            "basic",
            ("authorization", "Basic YWxhZGRpbjpvcGVuLXNlc2FtZQ=="),
        ),
        ("oauth", ("authorization", "Bearer oauth-secret")),
    ]);
    for (tool, (name, value)) in expected_auth {
        let (status, response) = invoke(&app, &token, &format!("contract.{tool}"), json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["data"]["headers"][name], value);
    }
    let (status, response) = invoke(&app, &token, "contract.query_key", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["query"], "query_key=query-secret");
    let (status, response) = invoke(&app, &token, "contract.cookie_key", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        response["data"]["headers"]["cookie"],
        "cookie_key=cookie-secret"
    );

    for (tool, content_type, body, expected_body) in [
        (
            "json_body",
            "application/json",
            json!({ "hello": "world", "mode": "safe", "nested": { "id": 1 } }),
            r#"{"hello":"world","mode":"safe","nested":{"id":1}}"#,
        ),
        (
            "text_body",
            "text/plain",
            json!("plain words"),
            "plain words",
        ),
        (
            "form_body",
            "application/x-www-form-urlencoded",
            json!({ "a": "one two", "b": 2 }),
            "a=one+two&b=2",
        ),
    ] {
        let (status, response) = invoke(
            &app,
            &token,
            &format!("contract.{tool}"),
            json!({ "contentType": content_type, "body": body }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["data"]["method"], "POST");
        assert_eq!(response["data"]["headers"]["content-type"], content_type);
        assert_eq!(response["data"]["body"], expected_body);
    }
    let (status, response) = invoke(
        &app,
        &token,
        "contract.multi_body",
        json!({ "contentType": "text/plain", "body": "plain multi" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["body"], "plain multi");

    for (tool, arguments) in [
        ("anonymous", json!({ "surprise": true })),
        ("no_body", json!({ "body": { "no": "body" } })),
        ("no_body", json!({ "contentType": "application/json" })),
        (
            "combined",
            json!({ "path": { "id": "ok" }, "query": { "q": 42 } }),
        ),
        (
            "combined",
            json!({ "path": { "id": "ok" }, "query": { "unknown": "value" } }),
        ),
        (
            "json_body",
            json!({
                "contentType": "application/json",
                "body": {
                    "hello": "world", "mode": "safe", "nested": { "id": 1 }, "unknown": true
                }
            }),
        ),
        (
            "json_body",
            json!({ "body": { "hello": "WORLD", "mode": "safe", "nested": { "id": 1 } } }),
        ),
        (
            "json_body",
            json!({ "body": { "hello": "world", "count": 1.5, "mode": "safe", "nested": { "id": 1 } } }),
        ),
        (
            "json_body",
            json!({ "body": { "hello": "world", "mode": "other", "nested": { "id": 1 } } }),
        ),
        (
            "json_body",
            json!({ "body": { "mode": "safe", "nested": { "id": 1 } } }),
        ),
        (
            "json_body",
            json!({ "body": { "hello": "world", "mode": "safe", "nested": {} } }),
        ),
        (
            "json_body",
            json!({ "body": { "hello": "world", "mode": "safe", "nested": { "id": 1 }, "choice": true } }),
        ),
        (
            "json_body",
            json!({ "body": { "hello": "world", "mode": "safe", "nested": { "id": 1 }, "tags": ["same", "same"] } }),
        ),
        (
            "multi_body",
            json!({ "contentType": "application/json", "body": "valid text, invalid JSON body" }),
        ),
    ] {
        let before = recorder.count();
        let (status, response) = invoke(&app, &token, &format!("contract.{tool}"), arguments).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"]["code"], "invalid_tool_arguments");
        assert_eq!(recorder.count(), before);
    }
    wait_for_log(
        &app,
        "tools.contract.json_body",
        "failed",
        "invalid_tool_arguments",
    )
    .await;
    for (tool, header_name) in [
        ("method_override", "X-HTTP-Method-Override"),
        ("http_method", "X-HTTP-Method"),
        ("original_method", "X-Original-Method"),
        ("forwarded", "X-Forwarded-For"),
    ] {
        let before = recorder.count();
        let (status, response) = invoke(
            &app,
            &token,
            &format!("contract.{tool}"),
            json!({ "headers": { header_name: "DELETE" } }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["error"]["code"], "forbidden_tool_header");
        assert_eq!(recorder.count(), before);
    }

    let before = recorder.count();
    let (status, response) = invoke(
        &app,
        &token,
        "contract.ask",
        json!({ "body": { "hello": "write", "mode": "safe", "nested": { "id": 1 } } }),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(response["status"], "approval_required");
    assert_eq!(response["approval"]["status"], "pending");
    assert_eq!(response["approval"]["path"], "tools.contract.ask");
    assert!(response["approval"]["id"].as_str().is_some());
    assert!(response["approval"]["statusUrl"].as_str().is_some());
    let approval_id = response["approval"]["id"]
        .as_str()
        .expect("approval ID should be text")
        .to_owned();
    assert_eq!(recorder.count(), before);
    wait_for_log(
        &app,
        "tools.contract.ask",
        "pending_approval",
        "approval_required",
    )
    .await;

    let detail_uri = format!("/api/v1/approvals/{approval_id}");
    let response = send(
        app.router(),
        Method::GET,
        &detail_uri,
        json!({}),
        &[(header::COOKIE.as_str(), admin.cookie.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let detail = response_body(response).await;
    assert_eq!(detail["status"], "pending");
    assert_eq!(detail["redactedArguments"]["body"]["hello"], "[redacted]");
    assert!(detail.get("result").is_none());

    let second_token = create_gateway_token(&app, &admin).await;
    let second_authorization = format!("Bearer {second_token}");
    let gateway_uri = format!("/api/v1/gateway/approvals/{approval_id}");
    let response = send(
        app.router(),
        Method::GET,
        &gateway_uri,
        json!({}),
        &[(header::AUTHORIZATION.as_str(), &second_authorization)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/approvals/{approval_id}/decision"),
        json!({ "decision": "approve", "expectedRevision": 0 }),
        &[(header::COOKIE.as_str(), admin.cookie.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/approvals/{approval_id}/decision"),
        json!({ "decision": "approve", "expectedRevision": 0 }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let replay = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/approvals/{approval_id}/decision"),
        json!({ "decision": "approve", "expectedRevision": 0 }),
        &admin_headers(&admin),
    )
    .await;
    assert!(matches!(
        replay.status(),
        StatusCode::OK | StatusCode::ACCEPTED
    ));

    let authorization = format!("Bearer {token}");
    let mut terminal = None;
    for _ in 0..100 {
        let response = send(
            app.router(),
            Method::GET,
            &gateway_uri,
            json!({}),
            &[(header::AUTHORIZATION.as_str(), &authorization)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_body(response).await;
        if body["status"] == "succeeded" {
            terminal = Some(body);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let terminal = terminal.expect("approved call should complete in the background");
    assert_eq!(terminal["result"]["ok"], true);
    assert_eq!(recorder.count(), before + 1);

    let (status, response) = invoke(&app, &token, "contract.disabled", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(response["error"]["code"], "tool_disabled");
    assert_eq!(recorder.count(), before + 1);
    wait_for_log(&app, "tools.contract.disabled", "denied", "tool_disabled").await;

    let last = recorder.take_last().await;
    assert_eq!(last["path"], "/ask");
    upstream_task.abort();
}

#[tokio::test]
async fn invocation_holds_its_catalog_lease_until_the_upstream_request_finishes() {
    let blocker = BlockingUpstream::default();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream listener should bind");
    let address = listener.local_addr().expect("upstream address should read");
    let upstream = Router::new()
        .fallback(block_upstream)
        .with_state(blocker.clone());
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("upstream should serve");
    });

    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let specification = json!({
        "openapi": "3.1.0",
        "info": { "title": "Lease Contract" },
        "servers": [{ "url": format!("http://{address}") }],
        "paths": {
            "/wait": {
                "get": {
                    "operationId": "wait",
                    "security": [{}],
                    "responses": { "200": { "description": "completed" } }
                }
            }
        }
    });
    let created = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Lease Contract",
            "preferredSlug": "lease",
            "spec": { "type": "inline", "content": specification.to_string() },
            "allowPrivateNetwork": true
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let token = create_gateway_token(&app, &admin).await;
    let tool = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("tools should list")
        .items
        .into_iter()
        .find(|tool| tool.local_name == "wait")
        .expect("wait tool should exist");

    let invoke_router = app.router();
    let invoke_token = token.clone();
    let invocation = tokio::spawn(async move {
        let authorization = format!("Bearer {invoke_token}");
        let response = send(
            invoke_router,
            Method::POST,
            "/api/v1/gateway/tools/invoke",
            json!({ "path": "lease.wait", "arguments": {} }),
            &[(header::AUTHORIZATION.as_str(), &authorization)],
        )
        .await;
        let status = response.status();
        (status, response_body(response).await)
    });
    blocker.entered.notified().await;

    let catalog = app.catalog().clone();
    let tool_id = tool.id.clone();
    let mut mutation = tokio::spawn(async move {
        catalog
            .set_tool_mode(
                &tool_id,
                Some(ToolMode::Disabled),
                tool.revision,
                AuditContext::system(Some("lease-concurrency-regression")),
            )
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut mutation)
            .await
            .is_err(),
        "catalog mutation must wait while outbound invocation owns its lease"
    );

    blocker.release.notify_one();
    let (status, response) = invocation.await.expect("invocation task should complete");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["data"]["completed"], true);
    tokio::time::timeout(Duration::from_secs(2), mutation)
        .await
        .expect("catalog mutation should resume after invocation")
        .expect("catalog mutation task should complete")
        .expect("catalog mutation should succeed");
    upstream_task.abort();
}

#[tokio::test]
async fn gateway_idempotency_validates_scopes_and_replays_exact_responses() {
    let recorder = Recorder::default();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream listener should bind");
    let address = listener.local_addr().expect("upstream address should read");
    let upstream = Router::new()
        .fallback(record_upstream)
        .with_state(recorder.clone());
    let upstream_task = tokio::spawn(async move {
        axum::serve(listener, upstream)
            .await
            .expect("upstream should serve");
    });

    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let token = create_gateway_token(&app, &admin).await;
    let authorization = format!("Bearer {token}");

    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": "missing.tool", "arguments": {}, "unexpected": true }),
        &[
            (header::AUTHORIZATION.as_str(), &authorization),
            ("idempotency-key", "unknown-field"),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(recorder.count(), 0);
    let reserved =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM gateway_invocation_idempotency")
            .fetch_one(app.pool())
            .await
            .expect("idempotency records should count");
    assert_eq!(
        reserved, 0,
        "invalid JSON must not reserve an idempotency key"
    );

    for key in ["", "contains space"] {
        let response = send(
            app.router(),
            Method::POST,
            "/api/v1/gateway/tools/invoke",
            json!({ "path": "missing.tool", "arguments": {} }),
            &[
                (header::AUTHORIZATION.as_str(), &authorization),
                ("idempotency-key", key),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_body(response).await["error"]["code"],
            "invalid_idempotency_key"
        );
    }
    let oversized_key = "a".repeat(256);
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": "missing.tool", "arguments": {} }),
        &[
            (header::AUTHORIZATION.as_str(), &authorization),
            ("idempotency-key", oversized_key.as_str()),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_body(response).await["error"]["code"],
        "invalid_idempotency_key"
    );
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": "missing.tool", "arguments": {} }),
        &[
            (header::AUTHORIZATION.as_str(), &authorization),
            ("idempotency-key", "duplicate-one"),
            ("idempotency-key", "duplicate-two"),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_body(response).await["error"]["code"],
        "invalid_idempotency_key"
    );
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/execute",
        json!({ "code": "export default 1" }),
        &[
            (header::AUTHORIZATION.as_str(), &authorization),
            ("idempotency-key", "execute-key"),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_body(response).await["error"]["code"],
        "idempotency_not_supported"
    );
    assert_eq!(recorder.count(), 0);

    let body_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["value"],
        "properties": { "value": { "type": "string" } }
    });
    let specification = json!({
        "openapi": "3.1.0",
        "info": { "title": "Idempotency Contract" },
        "servers": [{ "url": format!("http://{address}") }],
        "paths": {
            "/enabled": {
                "post": {
                    "operationId": "enabled",
                    "security": [{}],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": body_schema.clone() } }
                    },
                    "responses": { "200": { "description": "recorded" } }
                }
            },
            "/ask": {
                "post": {
                    "operationId": "ask",
                    "security": [{}],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": body_schema.clone() } }
                    },
                    "responses": { "200": { "description": "recorded" } }
                }
            },
            "/other": {
                "post": {
                    "operationId": "other",
                    "security": [{}],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": body_schema } }
                    },
                    "responses": { "200": { "description": "recorded" } }
                }
            },
            "/forbidden-prepare": {
                "get": {
                    "operationId": "forbidden_prepare",
                    "security": [{}],
                    "parameters": [{
                        "name": "X-HTTP-Method-Override",
                        "in": "header",
                        "schema": { "type": "string" }
                    }],
                    "responses": { "200": { "description": "recorded" } }
                }
            }
        }
    });
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Idempotency Contract",
            "preferredSlug": "idempotency",
            "spec": { "type": "inline", "content": specification.to_string() },
            "allowPrivateNetwork": true
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    set_mode(&app, "enabled", ToolMode::Enabled).await;
    set_mode(&app, "forbidden_prepare", ToolMode::Enabled).await;

    let ask_arguments = json!({
        "contentType": "application/json",
        "body": { "value": "same" }
    });
    let (first_status, first_body, first_replayed) = invoke_idempotent(
        &app,
        &token,
        "ask-replay",
        "idempotency.ask",
        ask_arguments.clone(),
    )
    .await;
    assert_eq!(first_status, StatusCode::ACCEPTED);
    assert!(!first_replayed);
    let (second_status, second_body, second_replayed) = invoke_idempotent(
        &app,
        &token,
        "ask-replay",
        "idempotency.ask",
        ask_arguments.clone(),
    )
    .await;
    assert_eq!(second_status, StatusCode::ACCEPTED);
    assert!(second_replayed);
    assert_eq!(
        second_body, first_body,
        "Ask replay must be byte-equivalent JSON"
    );
    let approval_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM approvals WHERE callable_path_snapshot = 'tools.idempotency.ask'",
    )
    .fetch_one(app.pool())
    .await
    .expect("approvals should count");
    assert_eq!(approval_count, 1);
    assert_eq!(recorder.count(), 0);

    let pruned_approval_id = first_body["approval"]["id"]
        .as_str()
        .expect("Ask response should include an approval ID");
    let pruned_idempotency_id = sqlx::query_scalar::<_, String>(
        "SELECT id FROM gateway_invocation_idempotency WHERE approval_id = ?",
    )
    .bind(pruned_approval_id)
    .fetch_one(app.pool())
    .await
    .expect("Ask approval should be linked to its idempotency result");
    let mut prune_connection = app
        .pool()
        .acquire()
        .await
        .expect("approval retention connection should open");
    sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut *prune_connection)
        .await
        .expect("approval retention should enforce foreign keys");
    let deleted = sqlx::query("DELETE FROM approvals WHERE id = ?")
        .bind(pruned_approval_id)
        .execute(&mut *prune_connection)
        .await
        .expect("approval retention should be reproducible")
        .rows_affected();
    drop(prune_connection);
    assert_eq!(deleted, 1);
    let retained_idempotency = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT state, approval_id FROM gateway_invocation_idempotency WHERE id = ?",
    )
    .bind(pruned_idempotency_id)
    .fetch_one(app.pool())
    .await
    .expect("completed idempotency result should outlive its pruned approval");
    assert_eq!(retained_idempotency.0, "completed");
    assert_eq!(retained_idempotency.1, None);

    let (pruned_status, pruned_body, pruned_replayed) = invoke_idempotent(
        &app,
        &token,
        "ask-replay",
        "idempotency.ask",
        ask_arguments.clone(),
    )
    .await;
    assert_eq!(pruned_status, StatusCode::CONFLICT);
    assert_eq!(pruned_body["error"]["code"], "idempotency_outcome_unknown");
    assert!(!pruned_replayed, "a dead Ask response must not be replayed");
    let approval_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM approvals WHERE callable_path_snapshot = 'tools.idempotency.ask'",
    )
    .fetch_one(app.pool())
    .await
    .expect("approvals should count after the retry");
    assert_eq!(approval_count, 0, "the retry must not create an approval");
    assert_eq!(recorder.count(), 0, "the retry must not call upstream");

    sqlx::query(
        "CREATE TRIGGER reject_ask_idempotency_completion \
         BEFORE UPDATE OF state ON gateway_invocation_idempotency \
         WHEN OLD.state = 'reserved' AND NEW.state = 'completed' AND NEW.approval_id IS NOT NULL \
         BEGIN SELECT RAISE(ABORT, 'forced Ask completion failure'); END",
    )
    .execute(app.pool())
    .await
    .expect("completion failure trigger should install");
    let (failed_status, _, failed_replayed) = invoke_idempotent(
        &app,
        &token,
        "ask-completion-failure",
        "idempotency.ask",
        ask_arguments.clone(),
    )
    .await;
    assert_eq!(failed_status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!failed_replayed);
    sqlx::query("DROP TRIGGER reject_ask_idempotency_completion")
        .execute(app.pool())
        .await
        .expect("completion failure trigger should be removed");
    let stranded = sqlx::query_as::<_, (String, i64)>(
        "SELECT state, (SELECT COUNT(*) FROM approvals \
         WHERE execution_id = 'gateway-idempotency:' || gateway_invocation_idempotency.id) \
         FROM gateway_invocation_idempotency WHERE state = 'indeterminate' \
         ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_one(app.pool())
    .await
    .expect("failed completion should fail closed with its correlated approval");
    assert_eq!(stranded, ("indeterminate".to_owned(), 1));

    let (failed_retry_status, failed_retry_body, failed_retry_replayed) = invoke_idempotent(
        &app,
        &token,
        "ask-completion-failure",
        "idempotency.ask",
        ask_arguments.clone(),
    )
    .await;
    assert_eq!(failed_retry_status, StatusCode::CONFLICT);
    assert_eq!(
        failed_retry_body["error"]["code"],
        "idempotency_outcome_unknown"
    );
    assert!(!failed_retry_replayed);
    let matching_approvals = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM approvals WHERE callable_path_snapshot = 'tools.idempotency.ask'",
    )
    .fetch_one(app.pool())
    .await
    .expect("failed completion approval should count");
    assert_eq!(
        matching_approvals, 1,
        "failed-closed retry must not duplicate the approval"
    );
    assert_eq!(
        recorder.count(),
        0,
        "failed-closed retry must not call upstream"
    );

    let (status, body, _) = invoke_idempotent(
        &app,
        &token,
        "ask-replay",
        "idempotency.other",
        ask_arguments.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "idempotency_key_mismatch");
    let (status, body, _) = invoke_idempotent(
        &app,
        &token,
        "ask-replay",
        "idempotency.ask",
        json!({
            "contentType": "application/json",
            "body": { "value": "different" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "idempotency_key_mismatch");

    let second_token = create_gateway_token(&app, &admin).await;
    let (first_owner_status, first_owner, first_owner_replayed) = invoke_idempotent(
        &app,
        &token,
        "shared-across-tokens",
        "idempotency.ask",
        ask_arguments.clone(),
    )
    .await;
    assert_eq!(first_owner_status, StatusCode::ACCEPTED);
    assert!(!first_owner_replayed);
    let (second_owner_status, second_owner, second_owner_replayed) = invoke_idempotent(
        &app,
        &second_token,
        "shared-across-tokens",
        "idempotency.ask",
        ask_arguments.clone(),
    )
    .await;
    assert_eq!(second_owner_status, StatusCode::ACCEPTED);
    assert!(!second_owner_replayed);
    assert_ne!(
        first_owner["approval"]["id"],
        second_owner["approval"]["id"]
    );

    let enabled_arguments = json!({
        "contentType": "application/json",
        "body": { "value": "enabled" }
    });
    let before_prepare_failure = recorder.count();
    let reserved_before_failure = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM gateway_invocation_idempotency WHERE state = 'reserved'",
    )
    .fetch_one(app.pool())
    .await
    .expect("reserved idempotency records should count");
    let (status, body, replayed) = invoke_idempotent(
        &app,
        &token,
        "released-prepare-failure",
        "idempotency.forbidden_prepare",
        json!({ "headers": { "X-HTTP-Method-Override": "DELETE" } }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "forbidden_tool_header");
    assert!(!replayed);
    assert_eq!(recorder.count(), before_prepare_failure);
    let reserved_after_failure = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM gateway_invocation_idempotency WHERE state = 'reserved'",
    )
    .fetch_one(app.pool())
    .await
    .expect("reserved idempotency records should count");
    assert_eq!(reserved_after_failure, reserved_before_failure);
    let (status, _, replayed) = invoke_idempotent(
        &app,
        &token,
        "released-prepare-failure",
        "idempotency.enabled",
        enabled_arguments.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!replayed);
    assert_eq!(recorder.count(), before_prepare_failure + 1);

    let before_enabled = recorder.count();
    let (status, first_enabled, replayed) = invoke_idempotent(
        &app,
        &token,
        "enabled-replay",
        "idempotency.enabled",
        enabled_arguments.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!replayed);
    let (status, second_enabled, replayed) = invoke_idempotent(
        &app,
        &token,
        "enabled-replay",
        "idempotency.enabled",
        enabled_arguments.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(replayed);
    assert_eq!(second_enabled, first_enabled);
    assert_eq!(recorder.count(), before_enabled + 1);

    let concurrent_before = recorder.count();
    let mut invocations = Vec::new();
    for _ in 0..12 {
        let router = app.router();
        let token = token.clone();
        let arguments = enabled_arguments.clone();
        invocations.push(tokio::spawn(async move {
            let authorization = format!("Bearer {token}");
            let response = send(
                router,
                Method::POST,
                "/api/v1/gateway/tools/invoke",
                json!({ "path": "idempotency.enabled", "arguments": arguments }),
                &[
                    (header::AUTHORIZATION.as_str(), &authorization),
                    ("idempotency-key", "enabled-concurrent"),
                ],
            )
            .await;
            (response.status(), response_body(response).await)
        }));
    }
    for invocation in invocations {
        let (status, body) = invocation.await.expect("invocation task should join");
        assert!(
            matches!(status, StatusCode::OK | StatusCode::CONFLICT),
            "unexpected concurrent response {status}: {body}"
        );
        if status == StatusCode::CONFLICT {
            assert_eq!(body["error"]["code"], "idempotency_in_progress");
        }
    }
    assert_eq!(recorder.count(), concurrent_before + 1);
    let (status, _, replayed) = invoke_idempotent(
        &app,
        &token,
        "enabled-concurrent",
        "idempotency.enabled",
        enabled_arguments,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(replayed);
    assert_eq!(recorder.count(), concurrent_before + 1);

    upstream_task.abort();
}
