use std::net::SocketAddr;

use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    routing::get,
};
use executor::catalog::{AuditContext, ToolMode};
use executor::{AppConfig, ExecutorApp};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:4788";

struct Admin {
    cookie: String,
    csrf: String,
}

#[tokio::test]
async fn source_import_rejects_an_unsupported_openapi_31_schema_dialect_without_writes() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let specification = json!({
        "openapi": "3.1.0",
        "jsonSchemaDialect": "https://example.test/custom-dialect",
        "info": { "title": "Unsupported dialect", "version": "1" },
        "paths": {
            "/items": {
                "get": {
                    "operationId": "listItems",
                    "responses": { "200": { "description": "ok" } }
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
            "displayName": "Unsupported dialect",
            "preferredSlug": "unsupported-dialect",
            "spec": { "type": "inline", "content": specification.to_string() }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body(response).await["error"]["code"],
        "invalid_openapi_document"
    );
    assert!(
        app.catalog()
            .list_sources()
            .await
            .expect("sources should list")
            .is_empty()
    );
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

async fn send_raw(
    router: Router,
    method: Method,
    uri: &str,
    raw_body: String,
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
                .body(Body::from(raw_body))
                .expect("request should build"),
        )
        .await
        .expect("router should answer")
}

async fn body(response: axum::response::Response) -> Value {
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

fn assert_json_content_type(response: &axum::response::Response) {
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
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
    let csrf = body(response).await["csrfToken"]
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

#[tokio::test]
async fn preview_import_and_invoke_enforce_planes_modes_and_body_limits() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream listener should bind");
    let address = upstream.local_addr().expect("upstream address should read");
    let upstream_router = Router::new().route(
        "/api/hello",
        get(|| async { Json(json!({ "message": "hello" })) }),
    );
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream, upstream_router)
            .await
            .expect("upstream should serve");
    });

    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let padding = "x".repeat(20_000);
    let specification = json!({
        "openapi": "3.1.0",
        "info": { "title": "Local API", "description": padding },
        "servers": [{ "url": format!("http://{address}/api") }],
        "security": [{ "ApiKey": [] }, {}],
        "components": {
            "securitySchemes": {
                "ApiKey": { "type": "apiKey", "in": "header", "name": "X-API-Key" }
            }
        },
        "paths": {
            "/hello": {
                "get": {
                    "operationId": "hello",
                    "parameters": [{
                        "name": "X-Padding",
                        "in": "header",
                        "schema": { "type": "string" }
                    }],
                    "responses": { "200": { "description": "ok", "content": { "application/json": { "schema": { "type": "object" } } } } }
                }
            },
            "/write": {
                "post": {
                    "operationId": "write",
                    "responses": { "204": { "description": "ok" } }
                }
            }
        }
    })
    .to_string();

    let unauthenticated = send(
        app.router(),
        Method::POST,
        "/api/v1/sources/openapi/preview",
        json!({ "spec": { "type": "inline", "content": specification } }),
        &[],
    )
    .await;
    assert_eq!(unauthenticated.status(), StatusCode::FORBIDDEN);

    let preview = send(
        app.router(),
        Method::POST,
        "/api/v1/sources/openapi/preview",
        json!({
            "spec": { "type": "inline", "content": specification },
            "allowPrivateNetwork": true
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = body(preview).await;
    assert_eq!(preview["toolCount"], 2);
    assert_eq!(preview["securitySchemes"][0]["name"], "ApiKey");
    assert_eq!(preview["securitySchemes"][0]["credentialType"], "api_key");
    assert_eq!(preview["tools"][0]["security"][0], json!(["ApiKey"]));

    let missing_inline_server = send(
        app.router(),
        Method::POST,
        "/api/v1/sources/openapi/preview",
        json!({
            "spec": {
                "type": "inline",
                "content": json!({
                    "openapi": "3.1.0",
                    "info": { "title": "No server" },
                    "paths": { "/x": { "get": { "responses": {} } } }
                }).to_string()
            }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(missing_inline_server.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body(missing_inline_server).await["error"]["code"],
        "inline_openapi_server_required"
    );
    let missing_server_create = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "No server",
            "spec": {
                "type": "inline",
                "content": json!({
                    "openapi": "3.1.0",
                    "info": { "title": "No server" },
                    "paths": { "/x": { "get": { "responses": {} } } }
                }).to_string()
            }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(missing_server_create.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sources")
            .fetch_one(app.pool())
            .await
            .expect("source count should read"),
        0
    );

    let created = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Local API",
            "preferredSlug": "local",
            "spec": { "type": "inline", "content": specification },
            "allowPrivateNetwork": true
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let before_refresh = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("tools should list");
    let write_tool = before_refresh
        .items
        .iter()
        .find(|tool| tool.local_name == "write")
        .expect("write tool should exist");
    let stable_write_id = write_tool.id.clone();
    app.catalog()
        .set_tool_mode(
            &stable_write_id,
            Some(ToolMode::Ask),
            write_tool.revision,
            AuditContext::system(Some("test-mode-override")),
        )
        .await
        .expect("tool override should store");
    let source_id = app
        .catalog()
        .list_sources()
        .await
        .expect("sources should list")[0]
        .id
        .clone();
    let refreshed = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/sources/{source_id}/refresh"),
        json!({}),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(refreshed.status(), StatusCode::OK);
    let after_refresh = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("refreshed tools should list");
    let write_tool = after_refresh
        .items
        .iter()
        .find(|tool| tool.local_name == "write")
        .expect("write tool should survive refresh");
    assert_eq!(write_tool.id, stable_write_id);
    assert_eq!(write_tool.mode_override, Some(ToolMode::Ask));

    let token_response = send(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "test" }),
        &[
            (header::COOKIE.as_str(), admin.cookie.as_str()),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", admin.csrf.as_str()),
            ("idempotency-key", "openapi-preview-token"),
        ],
    )
    .await;
    assert_eq!(token_response.status(), StatusCode::CREATED);
    let token = body(token_response).await["token"]
        .as_str()
        .expect("token should be returned")
        .to_owned();
    let authorization = format!("Bearer {token}");

    let invoked = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": "local.hello", "arguments": {} }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(invoked.status(), StatusCode::OK);
    let invoked = body(invoked).await;
    assert_eq!(invoked["ok"], true);
    assert_eq!(invoked["data"]["message"], "hello");

    let large_but_allowed = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({
            "path": "local.hello",
            "arguments": { "headers": { "X-Padding": "x".repeat(20_000) } }
        }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(large_but_allowed.status(), StatusCode::OK);

    let over_invoke_cap = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({
            "path": "local.hello",
            "arguments": { "padding": "x".repeat(8 * 1024 * 1024 + 128 * 1024) }
        }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(over_invoke_cap.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let over_import_cap = send(
        app.router(),
        Method::POST,
        "/api/v1/sources/openapi/preview",
        json!({
            "spec": { "type": "inline", "content": "x".repeat(16 * 1024 * 1024 + 128 * 1024) }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(over_import_cap.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let over_create_cap = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Too large",
            "spec": { "type": "inline", "content": "x".repeat(16 * 1024 * 1024 + 128 * 1024) }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(over_create_cap.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let invalid = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": "local.hello", "arguments": [] }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body(invalid).await["error"]["code"],
        "invalid_tool_arguments"
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let logged = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM request_logs WHERE error_code = 'invalid_tool_arguments'",
            )
            .fetch_one(app.pool())
            .await
            .expect("request logs should read");
            if logged == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("failed invocation should be logged");

    let ask = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": "local.write", "arguments": {} }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(ask.status(), StatusCode::ACCEPTED);
    let ask = body(ask).await;
    assert_eq!(ask["status"], "approval_required");
    assert_eq!(ask["approval"]["status"], "pending");

    upstream_task.abort();
}

#[tokio::test]
async fn source_configuration_never_exposes_a_query_bearing_spec_url() {
    let spec_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("spec listener should bind");
    let address: SocketAddr = spec_listener
        .local_addr()
        .expect("spec address should read");
    let server_url = format!("http://{address}");
    let spec = json!({
        "openapi": "3.0.3",
        "info": { "title": "URL API" },
        "servers": [{ "url": server_url }],
        "paths": {}
    });
    let spec_router = Router::new().route(
        "/openapi.json",
        get(move || {
            let spec = spec.clone();
            async move { Json(spec) }
        }),
    );
    let spec_task = tokio::spawn(async move {
        axum::serve(spec_listener, spec_router)
            .await
            .expect("spec server should serve");
    });

    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let secret_url = format!("http://{address}/openapi.json?api_key=plaintext-secret");
    let created = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "URL API",
            "spec": { "type": "url", "url": secret_url },
            "allowPrivateNetwork": true
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = body(created).await;
    assert!(!created.to_string().contains("plaintext-secret"));
    let source_id = created["id"]
        .as_str()
        .expect("created source should have an ID");
    let metadata = send(
        app.router(),
        Method::GET,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!(null),
        &[(header::COOKIE.as_str(), admin.cookie.as_str())],
    )
    .await;
    assert_eq!(metadata.status(), StatusCode::OK);
    let metadata = body(metadata).await;
    assert_eq!(metadata["revision"], 0);
    assert_eq!(metadata["configuredSchemes"], json!([]));

    let static_secret = "static-secret-never-returned";
    let updated = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "expectedRevision": 0,
            "credential": {
                "schemes": {
                    "ApiKey": { "type": "api_key", "value": static_secret }
                }
            }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(updated.status(), StatusCode::OK);
    let updated = body(updated).await;
    assert_eq!(updated["revision"], 1);
    assert_eq!(
        updated["configuredSchemes"],
        json!([{ "name": "ApiKey", "credentialType": "api_key" }])
    );
    assert!(!updated.to_string().contains(static_secret));

    let configuration = sqlx::query_scalar::<_, String>("SELECT configuration_json FROM sources")
        .fetch_one(app.pool())
        .await
        .expect("source config should read");
    assert!(!configuration.contains("plaintext-secret"));
    let ciphertext =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT payload_ciphertext FROM source_credentials")
            .fetch_one(app.pool())
            .await
            .expect("credential ciphertext should read");
    assert!(!String::from_utf8_lossy(&ciphertext).contains("plaintext-secret"));
    assert!(!String::from_utf8_lossy(&ciphertext).contains(static_secret));

    spec_task.abort();
}

#[tokio::test]
async fn large_body_routes_authenticate_before_parsing_json() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let malformed = format!("{{{}", "x".repeat(64 * 1024));

    for uri in ["/api/v1/sources", "/api/v1/sources/openapi/preview"] {
        let response = send_raw(app.router(), Method::POST, uri, malformed.clone(), &[]).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body(response).await["error"]["code"], "invalid_origin");
    }
    let response = send_raw(
        app.router(),
        Method::PUT,
        "/api/v1/sources/not-a-source/credentials",
        malformed.clone(),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(response).await["error"]["code"], "invalid_origin");

    let response = send_raw(
        app.router(),
        Method::POST,
        "/api/v1/sources/not-a-source/refresh",
        malformed.clone(),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body(response).await["error"]["code"], "invalid_origin");

    let response = send_raw(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        malformed,
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body(response).await["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn openapi_credentials_reject_unknown_schema_versions() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let specification = json!({
        "openapi": "3.1.0",
        "info": { "title": "Credential schema" },
        "servers": [{ "url": "https://example.com" }],
        "paths": {
            "/hello": {
                "get": {
                    "operationId": "hello",
                    "responses": { "200": { "description": "ok" } }
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
            "displayName": "Credential schema",
            "preferredSlug": "schema",
            "spec": { "type": "inline", "content": specification.to_string() }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let source_id = body(response).await["id"]
        .as_str()
        .expect("source should have an ID")
        .to_owned();
    let mut credential = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should read")
        .expect("credential should exist");
    credential.credential.schema_version = 2;
    app.catalog()
        .put_credential(
            &source_id,
            &credential.credential,
            Some(credential.revision),
            AuditContext::system(Some("unsupported-credential-schema")),
        )
        .await
        .expect("future credential schema should store opaquely");

    let response = send(
        app.router(),
        Method::GET,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!(null),
        &[(header::COOKIE.as_str(), admin.cookie.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        body(response).await["error"]["code"],
        "unsupported_credential_schema"
    );

    let replace = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "expectedRevision": 1,
            "credential": { "schemes": {
                "ApiKey": { "type": "api_key", "value": "must-not-store" }
            }}
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(replace.status(), StatusCode::CONFLICT);
    assert_eq!(
        body(replace).await["error"]["code"],
        "unsupported_credential_schema"
    );

    let clear = send(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/sources/{source_id}/credentials?expectedRevision=1"),
        json!(null),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(clear.status(), StatusCode::CONFLICT);
    assert_eq!(
        body(clear).await["error"]["code"],
        "unsupported_credential_schema"
    );
    let unchanged = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should remain readable")
        .expect("credential should remain stored");
    assert_eq!(unchanged.revision, 1);
    assert_eq!(unchanged.credential.schema_version, 2);

    let token_response = send(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "credential-schema" }),
        &[
            (header::COOKIE.as_str(), admin.cookie.as_str()),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", admin.csrf.as_str()),
            ("idempotency-key", "openapi-credential-schema-token"),
        ],
    )
    .await;
    let token = body(token_response).await["token"]
        .as_str()
        .expect("token should be returned")
        .to_owned();
    let authorization = format!("Bearer {token}");
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": "schema.hello", "arguments": {} }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body(response).await["error"]["code"],
        "unsupported_credential_schema"
    );
}

#[tokio::test]
async fn source_requests_reject_typos_before_mutating_catalog_or_credentials() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let specification = json!({
        "openapi": "3.1.0",
        "info": { "title": "Strict requests" },
        "servers": [{ "url": "https://example.com" }],
        "paths": {}
    })
    .to_string();

    let preview_typo = send(
        app.router(),
        Method::POST,
        "/api/v1/sources/openapi/preview",
        json!({
            "spec": { "type": "inline", "content": specification },
            "allowPrivateNetwrok": false
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(preview_typo.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body(preview_typo).await["error"]["code"], "invalid_json");

    let spec_typo = send(
        app.router(),
        Method::POST,
        "/api/v1/sources/openapi/preview",
        json!({
            "spec": {
                "type": "inline",
                "content": specification,
                "contnet": specification
            }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(spec_typo.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body(spec_typo).await["error"]["code"], "invalid_json");

    let create_typo = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayNmae": "Strict requests",
            "spec": { "type": "inline", "content": specification }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(create_typo.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body(create_typo).await["error"]["code"], "invalid_json");
    assert!(
        app.catalog()
            .list_sources()
            .await
            .expect("sources should list")
            .is_empty()
    );

    let malformed_credential = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Strict requests",
            "spec": { "type": "inline", "content": specification },
            "credential": {}
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(malformed_credential.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body(malformed_credential).await["error"]["code"],
        "invalid_json"
    );
    assert!(
        app.catalog()
            .list_sources()
            .await
            .expect("sources should list")
            .is_empty()
    );

    let created = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Strict requests",
            "preferredSlug": "strict",
            "spec": { "type": "inline", "content": specification }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let source_id = body(created).await["id"]
        .as_str()
        .expect("created source should have an ID")
        .to_owned();

    let put_typo = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "expectedRevison": 0,
            "credential": {
                "schemes": {
                    "ApiKey": { "type": "api_key", "value": "must-not-store" }
                }
            }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(put_typo.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body(put_typo).await["error"]["code"], "invalid_json");

    let put_missing_revision = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "credential": {
                "schemes": {
                    "ApiKey": { "type": "api_key", "value": "must-not-store" }
                }
            }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(put_missing_revision.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body(put_missing_revision).await["error"]["code"],
        "invalid_json"
    );

    let delete_typo = send(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/sources/{source_id}/credentials?expectedRevison=0"),
        json!(null),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(delete_typo.status(), StatusCode::BAD_REQUEST);
    assert_json_content_type(&delete_typo);
    assert_eq!(body(delete_typo).await["error"]["code"], "invalid_query");

    let metadata = send(
        app.router(),
        Method::GET,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!(null),
        &[(header::COOKIE.as_str(), admin.cookie.as_str())],
    )
    .await;
    assert_eq!(metadata.status(), StatusCode::OK);
    let metadata = body(metadata).await;
    assert_eq!(metadata["revision"], 0);
    assert_eq!(metadata["configuredSchemes"], json!([]));
}

#[tokio::test]
async fn credential_delete_queries_use_sanitized_json_errors_and_strict_revisions() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let specification = json!({
        "openapi": "3.1.0",
        "info": { "title": "Credential delete", "version": "1" },
        "servers": [{ "url": "https://example.com" }],
        "components": {
            "securitySchemes": {
                "ApiKey": { "type": "apiKey", "in": "header", "name": "X-API-Key" }
            }
        },
        "paths": {}
    });
    let created = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Credential delete",
            "preferredSlug": "credential-delete",
            "spec": { "type": "inline", "content": specification.to_string() }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let source_id = body(created).await["id"]
        .as_str()
        .expect("created source should have an ID")
        .to_owned();

    let configured = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "expectedRevision": 0,
            "credential": {
                "schemes": {
                    "ApiKey": { "type": "api_key", "value": "delete-query-secret" }
                }
            }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(configured.status(), StatusCode::OK);
    assert_eq!(body(configured).await["revision"], 1);

    let invalid_queries = [
        (
            "malformed percent encoding",
            "expectedRevision=%E0%A4%A",
            "%E0%A4%A",
        ),
        (
            "duplicate source parameter",
            "sourceId=duplicate-source-secret&sourceId=other&expectedRevision=1",
            "duplicate-source-secret",
        ),
        (
            "duplicate revision parameter",
            "expectedRevision=1&expectedRevision=1",
            "expectedRevision",
        ),
        (
            "unknown parameter",
            "expectedRevision=1&unexpected=unknown-query-secret",
            "unknown-query-secret",
        ),
        (
            "missing revision value",
            "expectedRevision=",
            "expectedRevision",
        ),
        ("missing revision parameter", "", "expectedRevision"),
    ];
    for (case, query, forbidden_fragment) in invalid_queries {
        let separator = if query.is_empty() { "" } else { "?" };
        let response = send(
            app.router(),
            Method::DELETE,
            &format!("/api/v1/sources/{source_id}/credentials{separator}{query}"),
            json!(null),
            &admin_headers(&admin),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}");
        assert_json_content_type(&response);
        let response = body(response).await;
        assert_eq!(response["error"]["code"], "invalid_query", "{case}");
        assert_eq!(
            response["error"]["message"], "The query parameters are invalid.",
            "{case}"
        );
        assert!(
            response["error"]["requestId"]
                .as_str()
                .is_some_and(|request_id| !request_id.is_empty()),
            "{case}"
        );
        assert!(
            !response.to_string().contains(forbidden_fragment),
            "{case} must not echo query input"
        );
    }

    let unchanged = send(
        app.router(),
        Method::GET,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!(null),
        &[(header::COOKIE.as_str(), admin.cookie.as_str())],
    )
    .await;
    assert_eq!(unchanged.status(), StatusCode::OK);
    let unchanged = body(unchanged).await;
    assert_eq!(unchanged["revision"], 1);
    assert_eq!(
        unchanged["configuredSchemes"],
        json!([{ "name": "ApiKey", "credentialType": "api_key" }])
    );

    let conflict = send(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/sources/{source_id}/credentials?expectedRevision=0"),
        json!(null),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_json_content_type(&conflict);
    assert_eq!(body(conflict).await["error"]["code"], "revision_conflict");

    let cleared = send(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/sources/{source_id}/credentials?expectedRevision=1"),
        json!(null),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(cleared.status(), StatusCode::OK);
    assert_json_content_type(&cleared);
    let cleared = body(cleared).await;
    assert_eq!(cleared["revision"], 2);
    assert_eq!(cleared["configuredSchemes"], json!([]));
    assert!(!cleared.to_string().contains("delete-query-secret"));
    app.shutdown().await;
}
