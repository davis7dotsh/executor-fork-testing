use std::{path::Path, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode, header},
    routing::get,
};
use executor::{
    AppConfig, ExecutorApp,
    catalog::{AuditContext, ListToolsFilter, ToolMode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::{net::TcpListener, sync::RwLock};
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:4788";

struct Admin {
    cookie: String,
    csrf: String,
}

struct Upstream {
    address: std::net::SocketAddr,
    specification: Arc<RwLock<Value>>,
    task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    async fn start() -> Self {
        async fn serve_specification(
            State(specification): State<Arc<RwLock<Value>>>,
        ) -> Json<Value> {
            Json(specification.read().await.clone())
        }

        let specification = Arc::new(RwLock::new(json!({})));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener should bind");
        let address = listener.local_addr().expect("upstream address should read");
        let router = Router::new()
            .route("/openapi.json", get(serve_specification))
            .route(
                "/api/hello",
                get(|| async { Json(json!({ "message": "still callable" })) }),
            )
            .with_state(Arc::clone(&specification));
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("upstream should serve");
        });
        Self {
            address,
            specification,
            task,
        }
    }

    async fn set_paths(&self, paths: Value, description: &str) {
        *self.specification.write().await = json!({
            "openapi": "3.1.0",
            "info": { "title": "Lifecycle API", "description": description },
            "servers": [{ "url": format!("http://{}/api", self.address) }],
            "paths": paths
        });
    }

    fn spec_url(&self, query: Option<&str>) -> String {
        match query {
            Some(query) => format!("http://{}/openapi.json?{query}", self.address),
            None => format!("http://{}/openapi.json", self.address),
        }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
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

async fn json_body(response: axum::response::Response) -> Value {
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
                .expect("cookie should contain a value")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn setup(app: &ExecutorApp) -> Admin {
    let setup_token = app
        .setup_token()
        .expect("fresh app should expose a setup token");
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
        json!({
            "username": "admin",
            "password": "correct horse battery staple"
        }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = cookies(&response);
    let csrf = json_body(response).await["csrfToken"]
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

async fn import_source(
    app: &ExecutorApp,
    admin: &Admin,
    spec_url: &str,
    preferred_slug: &str,
    credential: Value,
) -> Value {
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Lifecycle API",
            "preferredSlug": preferred_slug,
            "spec": { "type": "url", "url": spec_url },
            "allowPrivateNetwork": true,
            "credential": credential
        }),
        &admin_headers(admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await
}

async fn gateway_token(app: &ExecutorApp, admin: &Admin) -> String {
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "lifecycle-test" }),
        &admin_headers(admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await["token"]
        .as_str()
        .expect("token should be returned once")
        .to_owned()
}

async fn refresh(app: &ExecutorApp, admin: &Admin, source_id: &str) -> StatusCode {
    send(
        app.router(),
        Method::POST,
        &format!("/api/v1/sources/{source_id}/refresh"),
        json!({}),
        &admin_headers(admin),
    )
    .await
    .status()
}

fn hello_paths() -> Value {
    json!({
        "/hello": {
            "get": {
                "operationId": "sayHello",
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {
                            "application/json": { "schema": { "type": "object" } }
                        }
                    }
                }
            }
        }
    })
}

#[tokio::test]
async fn removed_then_restored_openapi_tool_keeps_identity_override_and_callable_binding() {
    let upstream = Upstream::start().await;
    upstream.set_paths(hello_paths(), "initial").await;
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let created = import_source(
        &app,
        &admin,
        &upstream.spec_url(None),
        "lifecycle",
        json!({}),
    )
    .await;
    let source_id = created["id"]
        .as_str()
        .expect("source should have an ID")
        .to_owned();
    let original = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("tools should list")
        .items
        .pop()
        .expect("imported tool should exist");
    let original_binding = app
        .catalog()
        .tool_binding(&original.id)
        .await
        .expect("imported tool should have a binding");
    app.catalog()
        .set_tool_mode(
            &original.id,
            Some(ToolMode::Enabled),
            original.revision,
            AuditContext::system(Some("lifecycle-mode")),
        )
        .await
        .expect("explicit tool mode should store");

    upstream.set_paths(json!({}), "temporarily removed").await;
    assert_eq!(refresh(&app, &admin, &source_id).await, StatusCode::OK);
    let tombstone = app
        .catalog()
        .list_tools(ListToolsFilter {
            include_tombstoned: true,
            ..Default::default()
        })
        .await
        .expect("tool history should list")
        .items
        .pop()
        .expect("removed tool should remain in history");
    assert_eq!(tombstone.id, original.id);
    assert_eq!(tombstone.local_name, original.local_name);
    assert_eq!(tombstone.mode_override, Some(ToolMode::Enabled));
    assert!(!tombstone.present);
    assert!(app.catalog().tool_binding(&original.id).await.is_err());

    upstream.set_paths(hello_paths(), "restored").await;
    assert_eq!(refresh(&app, &admin, &source_id).await, StatusCode::OK);
    let restored = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("restored tools should list")
        .items
        .pop()
        .expect("tool should be restored");
    assert_eq!(restored.id, original.id);
    assert_eq!(restored.local_name, original.local_name);
    assert_eq!(restored.callable_path, original.callable_path);
    assert_eq!(restored.mode_override, Some(ToolMode::Enabled));
    assert!(restored.present);
    let restored_binding = app
        .catalog()
        .tool_binding(&restored.id)
        .await
        .expect("restored tool should regain a binding");
    assert_eq!(restored_binding.binding, original_binding.binding);

    let token = gateway_token(&app, &admin).await;
    let authorization = format!("Bearer {token}");
    let invoked = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": restored.sandbox_path, "arguments": {} }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(invoked.status(), StatusCode::OK);
    assert_eq!(
        json_body(invoked).await["data"]["message"],
        "still callable"
    );
}

#[tokio::test]
async fn refresh_binding_failure_rolls_back_artifact_tools_bindings_and_revisions() {
    let upstream = Upstream::start().await;
    upstream
        .set_paths(hello_paths(), "before failed refresh")
        .await;
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let created = import_source(
        &app,
        &admin,
        &upstream.spec_url(None),
        "rollback",
        json!({}),
    )
    .await;
    let source_id = created["id"]
        .as_str()
        .expect("source should have an ID")
        .to_owned();
    let before_source = app
        .catalog()
        .source(&source_id)
        .await
        .expect("source should read");
    let before_global_revision = app
        .catalog()
        .global_revision()
        .await
        .expect("global revision should read");
    let before_tool = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("tools should list")
        .items
        .pop()
        .expect("tool should exist");
    let before_binding = app
        .catalog()
        .tool_binding(&before_tool.id)
        .await
        .expect("binding should exist");
    let before_artifact = sqlx::query_scalar::<_, String>(
        "SELECT content_json FROM source_artifacts WHERE source_id = ?",
    )
    .bind(&source_id)
    .fetch_one(app.pool())
    .await
    .expect("artifact should read");
    let before_audits = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
        .fetch_one(app.pool())
        .await
        .expect("audit count should read");

    upstream
        .set_paths(
            json!({
                "/hello": hello_paths()["/hello"].clone(),
                "/new": {
                    "get": {
                        "operationId": "newOperation",
                        "responses": { "204": { "description": "ok" } }
                    }
                }
            }),
            "must roll back",
        )
        .await;
    sqlx::query(
        "CREATE TRIGGER reject_refresh_binding BEFORE INSERT ON tool_bindings \
         BEGIN SELECT RAISE(ABORT, 'reject refresh binding'); END",
    )
    .execute(app.pool())
    .await
    .expect("binding failure trigger should install");
    assert_eq!(
        refresh(&app, &admin, &source_id).await,
        StatusCode::INTERNAL_SERVER_ERROR
    );

    let after_source = app
        .catalog()
        .source(&source_id)
        .await
        .expect("source should still read");
    assert_eq!(after_source.revision, before_source.revision);
    assert_eq!(
        after_source.catalog_revision,
        before_source.catalog_revision
    );
    assert_eq!(after_source.tool_count, before_source.tool_count);
    assert_eq!(
        app.catalog()
            .global_revision()
            .await
            .expect("global revision should still read"),
        before_global_revision
    );
    let after_tools = app
        .catalog()
        .list_tools(ListToolsFilter {
            include_tombstoned: true,
            ..Default::default()
        })
        .await
        .expect("tool history should still list");
    assert_eq!(after_tools.items.len(), 1);
    assert_eq!(after_tools.items[0].id, before_tool.id);
    assert_eq!(after_tools.items[0].revision, before_tool.revision);
    assert_eq!(
        app.catalog()
            .tool_binding(&before_tool.id)
            .await
            .expect("old binding should survive")
            .binding,
        before_binding.binding
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT content_json FROM source_artifacts WHERE source_id = ?",
        )
        .bind(&source_id)
        .fetch_one(app.pool())
        .await
        .expect("artifact should survive"),
        before_artifact
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
            .fetch_one(app.pool())
            .await
            .expect("audit count should still read"),
        before_audits
    );

    let token = gateway_token(&app, &admin).await;
    let authorization = format!("Bearer {token}");
    let invoked = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": before_tool.sandbox_path, "arguments": {} }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await;
    assert_eq!(invoked.status(), StatusCode::OK);
    assert_eq!(
        json_body(invoked).await["data"]["message"],
        "still callable"
    );
}

#[tokio::test]
async fn credentials_delete_uses_cas_preserves_locator_and_leaves_no_plaintext_on_disk() {
    let upstream = Upstream::start().await;
    upstream
        .set_paths(
            json!({
                "/hello": {
                    "get": {
                        "operationId": "sayHello",
                        "security": [{ "ApiKey": [] }],
                        "responses": { "200": { "description": "ok" } }
                    }
                }
            }),
            "secret persistence test",
        )
        .await;
    {
        let mut specification = upstream.specification.write().await;
        specification["components"] = json!({
            "securitySchemes": {
                "ApiKey": { "type": "apiKey", "in": "header", "name": "X-API-Key" }
            }
        });
    }
    let locator_secret = "locator-secret-4f08dd75512a47a6";
    let auth_secret = "auth-secret-a5477b04afe2405d";
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let data_dir = directory.path().to_path_buf();
    let app = ExecutorApp::open(AppConfig::new(data_dir.clone()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let secret_spec_url = upstream.spec_url(Some(&format!("api_key={locator_secret}")));
    let created = import_source(
        &app,
        &admin,
        &secret_spec_url,
        "secrets",
        json!({
            "schemes": {
                "ApiKey": { "type": "api_key", "value": auth_secret }
            }
        }),
    )
    .await;
    assert!(!created.to_string().contains(locator_secret));
    assert!(!created.to_string().contains(auth_secret));
    let source_id = created["id"]
        .as_str()
        .expect("source should have an ID")
        .to_owned();

    let stale = send(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/sources/{source_id}/credentials?expectedRevision=7"),
        json!(null),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::CONFLICT);
    let stale_body = json_body(stale).await;
    assert_eq!(stale_body["error"]["code"], "revision_conflict");
    assert!(!stale_body.to_string().contains(locator_secret));
    assert!(!stale_body.to_string().contains(auth_secret));

    let deleted = send(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/sources/{source_id}/credentials?expectedRevision=0"),
        json!(null),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::OK);
    let deleted_body = json_body(deleted).await;
    assert_eq!(deleted_body["revision"], 1);
    assert_eq!(deleted_body["configuredSchemes"], json!([]));
    assert!(!deleted_body.to_string().contains(locator_secret));
    assert!(!deleted_body.to_string().contains(auth_secret));

    let stored = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("locator envelope should remain");
    assert_eq!(stored.revision, 1);
    assert_eq!(stored.credential.payload["locator"]["url"], secret_spec_url);
    assert_eq!(
        stored.credential.payload["credentials"]["schemes"],
        json!({})
    );
    assert!(!stored.credential.payload.to_string().contains(auth_secret));
    assert_eq!(refresh(&app, &admin, &source_id).await, StatusCode::OK);

    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_all(app.pool())
        .await
        .expect("WAL should checkpoint");
    app.pool().close().await;
    drop(app);

    for file_name in ["executor.db", "executor.db-wal", "executor.db-shm"] {
        let path = data_dir.join(file_name);
        if path.exists() {
            assert_file_excludes(&path, locator_secret);
            assert_file_excludes(&path, auth_secret);
        }
    }
}

fn assert_file_excludes(path: &Path, secret: &str) {
    let bytes = std::fs::read(path).expect("database sidecar should read");
    assert!(
        !bytes
            .windows(secret.len())
            .any(|window| window == secret.as_bytes()),
        "{} contains plaintext secret",
        path.display()
    );
}
