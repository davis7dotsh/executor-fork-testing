use std::{
    collections::BTreeMap,
    path::Path,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode, header},
    response::Redirect,
    routing::{any, get},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use executor::{
    AppConfig, ExecutorApp,
    catalog::{AuditContext, ListToolsFilter, SourceHealth, ToolMode},
};
use http_body_util::BodyExt;
use reqwest::{Client, redirect::Policy};
use serde_json::{Value, json};
use tokio::{net::TcpListener, process::Command, sync::RwLock, time::sleep};
use tower::ServiceExt;
use url::Url;

const ORIGIN: &str = "http://127.0.0.1:4788";
static TOKEN_IDEMPOTENCY_SEQUENCE: AtomicUsize = AtomicUsize::new(1);

struct Admin {
    cookie: String,
    csrf: String,
}

struct Upstream {
    address: std::net::SocketAddr,
    specification: Arc<RwLock<Value>>,
    spec_requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

struct CredentialTarget {
    address: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    task: tokio::task::JoinHandle<()>,
}

struct OAuthTestProvider {
    issuer: String,
    client: Client,
    child: tokio::process::Child,
}

struct SpecRedirect {
    address: std::net::SocketAddr,
    target: Arc<RwLock<String>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    path_and_query: String,
    headers: BTreeMap<String, String>,
}

#[derive(Clone)]
struct CredentialTargetState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

#[derive(Clone)]
struct UpstreamState {
    specification: Arc<RwLock<Value>>,
    spec_requests: Arc<AtomicUsize>,
}

impl Upstream {
    async fn start() -> Self {
        Self::start_bound("127.0.0.1:0").await
    }

    async fn start_non_loopback() -> Self {
        Self::start_bound("0.0.0.0:0").await
    }

    async fn start_bound(bind_address: &str) -> Self {
        async fn serve_specification(State(state): State<UpstreamState>) -> Json<Value> {
            state.spec_requests.fetch_add(1, Ordering::SeqCst);
            Json(state.specification.read().await.clone())
        }

        let specification = Arc::new(RwLock::new(json!({})));
        let spec_requests = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind(bind_address)
            .await
            .expect("upstream listener should bind");
        let address = listener.local_addr().expect("upstream address should read");
        let router = Router::new()
            .route("/openapi.json", get(serve_specification))
            .route(
                "/api/hello",
                get(|| async { Json(json!({ "message": "still callable" })) }),
            )
            .with_state(UpstreamState {
                specification: Arc::clone(&specification),
                spec_requests: Arc::clone(&spec_requests),
            });
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("upstream should serve");
        });
        Self {
            address,
            specification,
            spec_requests,
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

    fn spec_request_count(&self) -> usize {
        self.spec_requests.load(Ordering::SeqCst)
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CredentialTarget {
    async fn start() -> Self {
        Self::start_bound("127.0.0.1:0").await
    }

    async fn start_non_loopback() -> Self {
        Self::start_bound("0.0.0.0:0").await
    }

    async fn start_bound(bind_address: &str) -> Self {
        async fn capture(
            State(state): State<CredentialTargetState>,
            request: Request<Body>,
        ) -> Json<Value> {
            let captured = CapturedRequest {
                path_and_query: request
                    .uri()
                    .path_and_query()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| request.uri().path().to_owned()),
                headers: request
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.as_str().to_owned(), value.to_owned()))
                    })
                    .collect(),
            };
            state
                .requests
                .lock()
                .expect("credential target ledger locks")
                .push(captured);
            Json(json!({ "ok": true }))
        }

        let requests = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind(bind_address)
            .await
            .expect("credential target listener should bind");
        let address = listener
            .local_addr()
            .expect("credential target address should read");
        let router = Router::new()
            .route("/api/credential", any(capture))
            .with_state(CredentialTargetState {
                requests: Arc::clone(&requests),
            });
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("credential target should serve");
        });
        Self {
            address,
            requests,
            task,
        }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> Vec<CapturedRequest> {
        self.requests
            .lock()
            .expect("credential target ledger locks")
            .clone()
    }
}

impl Drop for CredentialTarget {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl OAuthTestProvider {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test port reserves");
        let port = listener.local_addr().expect("test port resolves").port();
        drop(listener);
        let executable = format!(
            "{}/e2e/node_modules/.bin/emulate",
            env!("CARGO_MANIFEST_DIR")
        );
        let mut child = Command::new(executable)
            .args(["start", "--service", "mcp", "--port", &port.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("OAuth emulator starts");
        let client = Client::builder()
            .redirect(Policy::none())
            .build()
            .expect("test HTTP client builds");
        let metadata_url =
            format!("http://127.0.0.1:{port}/.well-known/oauth-authorization-server");
        for _ in 0..200 {
            if let Some(status) = child.try_wait().expect("OAuth emulator status reads") {
                panic!("OAuth emulator exited before readiness with {status}");
            }
            if let Ok(response) = client.get(&metadata_url).send().await
                && response.status().is_success()
                && let Ok(metadata) = response.json::<Value>().await
                && let Some(issuer) = metadata["issuer"].as_str()
            {
                return Self {
                    issuer: issuer.to_owned(),
                    client,
                    child,
                };
            }
            sleep(Duration::from_millis(25)).await;
        }
        let _ = child.start_kill();
        panic!("OAuth emulator did not become ready");
    }

    async fn register_client(&self, callback_url: &str) -> String {
        let response = self
            .client
            .post(format!("{}/register", self.issuer))
            .json(&json!({
                "client_name": "Executor OpenAPI origin test",
                "redirect_uris": [callback_url],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none"
            }))
            .send()
            .await
            .expect("OAuth client registration responds");
        assert_eq!(response.status(), reqwest::StatusCode::CREATED);
        response
            .json::<Value>()
            .await
            .expect("OAuth registration is JSON")["client_id"]
            .as_str()
            .expect("OAuth registration returns client ID")
            .to_owned()
    }

    async fn approve(&self, authorization_url: &str) -> Url {
        let authorization_url = Url::parse(authorization_url).expect("authorization URL parses");
        let mut form = authorization_url
            .query_pairs()
            .into_owned()
            .collect::<Vec<_>>();
        form.push(("login".to_owned(), "admin".to_owned()));
        let response = self
            .client
            .post(format!("{}/authorize/approve", self.issuer))
            .form(&form)
            .send()
            .await
            .expect("OAuth approval responds");
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        Url::parse(
            response
                .headers()
                .get(reqwest::header::LOCATION)
                .expect("OAuth approval redirects")
                .to_str()
                .expect("OAuth redirect is text"),
        )
        .expect("OAuth callback URL parses")
    }
}

impl Drop for OAuthTestProvider {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl SpecRedirect {
    async fn start(target_url: String) -> Self {
        async fn redirect(State(target): State<Arc<RwLock<String>>>) -> Redirect {
            let target = target.read().await.clone();
            Redirect::temporary(&target)
        }

        let target = Arc::new(RwLock::new(target_url));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("redirect listener should bind");
        let address = listener.local_addr().expect("redirect address should read");
        let router = Router::new()
            .route("/openapi.json", get(redirect))
            .with_state(Arc::clone(&target));
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("redirect source should serve");
        });
        Self {
            address,
            target,
            task,
        }
    }

    fn url(&self) -> String {
        format!("http://{}/openapi.json", self.address)
    }

    async fn set_target(&self, target_url: String) {
        *self.target.write().await = target_url;
    }
}

impl Drop for SpecRedirect {
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
    let idempotency_key = format!(
        "openapi-lifecycle-token-{}",
        TOKEN_IDEMPOTENCY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let mut headers = admin_headers(admin).to_vec();
    headers.push(("idempotency-key", idempotency_key.as_str()));
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "lifecycle-test" }),
        &headers,
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

async fn set_secured_specification(
    upstream: &Upstream,
    server_origin: &str,
    scheme_name: &str,
    scheme: Value,
    operation_id: &str,
) {
    *upstream.specification.write().await = json!({
        "openapi": "3.1.0",
        "info": { "title": "Credential origin API" },
        "servers": [{ "url": format!("{server_origin}/api") }],
        "components": { "securitySchemes": { (scheme_name): scheme } },
        "paths": { "/credential": { "get": {
            "operationId": operation_id,
            "security": [{ (scheme_name): [] }],
            "responses": {
                "200": {
                    "description": "ok",
                    "content": {
                        "application/json": { "schema": { "type": "object" } }
                    }
                }
            }
        }}}
    });
}

async fn source_tool_path(app: &ExecutorApp, source_id: &str) -> String {
    app.catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(source_id.to_owned()),
            limit: 10,
            ..Default::default()
        })
        .await
        .expect("source tools should list")
        .items
        .into_iter()
        .next()
        .expect("source should expose a tool")
        .sandbox_path
}

async fn invoke_path(app: &ExecutorApp, token: &str, path: &str) -> axum::response::Response {
    let authorization = format!("Bearer {token}");
    send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": path, "arguments": {} }),
        &[(header::AUTHORIZATION.as_str(), &authorization)],
    )
    .await
}

#[tokio::test]
async fn non_loopback_http_rejects_every_static_credential_before_catalog_or_dispatch() {
    let upstream = Upstream::start().await;
    let insecure_target = CredentialTarget::start_non_loopback().await;
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let cases = [
        (
            "insecure-header",
            json!({ "type": "apiKey", "in": "header", "name": "X-API-Key" }),
            json!({ "type": "api_key", "value": "header-secret" }),
        ),
        (
            "insecure-query",
            json!({ "type": "apiKey", "in": "query", "name": "api_key" }),
            json!({ "type": "api_key", "value": "query-secret" }),
        ),
        (
            "insecure-cookie",
            json!({ "type": "apiKey", "in": "cookie", "name": "session" }),
            json!({ "type": "api_key", "value": "cookie-secret" }),
        ),
        (
            "insecure-basic",
            json!({ "type": "http", "scheme": "basic" }),
            json!({ "type": "basic", "username": "user", "password": "pass" }),
        ),
        (
            "insecure-bearer",
            json!({ "type": "http", "scheme": "bearer" }),
            json!({ "type": "bearer", "token": "bearer-secret" }),
        ),
        (
            "insecure-manual-oauth",
            json!({ "type": "oauth2", "flows": {} }),
            json!({ "type": "oauth_access_token", "access_token": "oauth-secret" }),
        ),
    ];

    for (slug, scheme, credential) in cases {
        set_secured_specification(&upstream, &insecure_target.origin(), "Auth", scheme, slug).await;
        let rejected = send(
            app.router(),
            Method::POST,
            "/api/v1/sources",
            json!({
                "kind": "openapi",
                "displayName": "Insecure transport",
                "preferredSlug": slug,
                "spec": { "type": "url", "url": upstream.spec_url(None) },
                "allowPrivateNetwork": true,
                "credential": { "schemes": { "Auth": credential } }
            }),
            &admin_headers(&admin),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST, "{slug}");
        assert_eq!(
            json_body(rejected).await["error"]["code"],
            "insecure_openapi_transport",
            "{slug}"
        );
        assert!(insecure_target.requests().is_empty(), "{slug}");
    }

    set_secured_specification(
        &upstream,
        "http://198.51.100.10",
        "Auth",
        json!({ "type": "http", "scheme": "bearer" }),
        "insecurePublicAnonymous",
    )
    .await;
    let anonymous = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Public plaintext transport",
            "preferredSlug": "insecure-public-anonymous",
            "spec": { "type": "url", "url": upstream.spec_url(None) },
            "allowPrivateNetwork": true,
            "credential": { "schemes": {} }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(anonymous.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(anonymous).await["error"]["code"],
        "insecure_openapi_transport"
    );
    let preview = send(
        app.router(),
        Method::POST,
        "/api/v1/sources/openapi/preview",
        json!({
            "spec": {
                "type": "inline",
                "content": upstream.specification.read().await.to_string()
            },
            "allowPrivateNetwork": true
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(preview.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(preview).await["error"]["code"],
        "insecure_openapi_transport"
    );
    set_secured_specification(
        &upstream,
        "https://api.example.test",
        "Auth",
        json!({ "type": "http", "scheme": "bearer" }),
        "secureHttpsPreview",
    )
    .await;
    let https_preview = send(
        app.router(),
        Method::POST,
        "/api/v1/sources/openapi/preview",
        json!({
            "spec": {
                "type": "inline",
                "content": upstream.specification.read().await.to_string()
            },
            "allowPrivateNetwork": false
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(https_preview.status(), StatusCode::OK);
    assert!(
        app.catalog()
            .list_tools(ListToolsFilter {
                include_tombstoned: true,
                ..Default::default()
            })
            .await
            .expect("catalog should remain readable")
            .items
            .is_empty()
    );
    assert!(insecure_target.requests().is_empty());
}

#[tokio::test]
async fn spec_locators_and_redirect_hops_enforce_confidential_transport_before_request() {
    let insecure_spec = Upstream::start_non_loopback().await;
    insecure_spec
        .set_paths(hello_paths(), "must not fetch")
        .await;
    let safe_spec = Upstream::start().await;
    safe_spec.set_paths(hello_paths(), "safe loopback").await;
    let second_redirect = SpecRedirect::start(insecure_spec.spec_url(None)).await;
    let first_redirect = SpecRedirect::start(second_redirect.url()).await;
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;

    for (slug, spec_url) in [
        ("private-plaintext-spec", insecure_spec.spec_url(None)),
        (
            "public-plaintext-spec",
            "http://198.51.100.10/openapi.json".to_owned(),
        ),
        ("redirect-downgrade-spec", first_redirect.url()),
    ] {
        let rejected = send(
            app.router(),
            Method::POST,
            "/api/v1/sources",
            json!({
                "kind": "openapi",
                "displayName": "Insecure specification",
                "preferredSlug": slug,
                "spec": { "type": "url", "url": spec_url },
                "allowPrivateNetwork": true,
                "credential": { "schemes": {} }
            }),
            &admin_headers(&admin),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST, "{slug}");
        assert_eq!(
            json_body(rejected).await["error"]["code"],
            "insecure_openapi_transport",
            "{slug}"
        );
    }
    assert_eq!(
        insecure_spec.spec_request_count(),
        0,
        "the private HTTP locator and redirect target must receive no request"
    );

    first_redirect.set_target(safe_spec.spec_url(None)).await;
    let created = import_source(
        &app,
        &admin,
        &first_redirect.url(),
        "loopback-redirect-spec",
        json!({ "schemes": {} }),
    )
    .await;
    assert!(created["id"].is_string());
    assert_eq!(safe_spec.spec_request_count(), 1);
}

#[tokio::test]
async fn refresh_rejects_per_scheme_origin_changes_for_every_static_credential_carrier() {
    let upstream = Upstream::start().await;
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let token = gateway_token(&app, &admin).await;
    let insecure_target = CredentialTarget::start_non_loopback().await;
    let cases = [
        (
            "origin-header",
            json!({ "type": "apiKey", "in": "header", "name": "X-API-Key" }),
            json!({ "type": "api_key", "value": "header-secret" }),
            "header-secret",
        ),
        (
            "origin-query",
            json!({ "type": "apiKey", "in": "query", "name": "api_key" }),
            json!({ "type": "api_key", "value": "query-secret" }),
            "api_key=query-secret",
        ),
        (
            "origin-cookie",
            json!({ "type": "apiKey", "in": "cookie", "name": "session" }),
            json!({ "type": "api_key", "value": "cookie-secret" }),
            "session=cookie-secret",
        ),
        (
            "origin-basic",
            json!({ "type": "http", "scheme": "basic" }),
            json!({ "type": "basic", "username": "user", "password": "pass" }),
            "Basic dXNlcjpwYXNz",
        ),
        (
            "origin-bearer",
            json!({ "type": "http", "scheme": "bearer" }),
            json!({ "type": "bearer", "token": "bearer-secret" }),
            "Bearer bearer-secret",
        ),
        (
            "origin-manual-oauth",
            json!({ "type": "oauth2", "flows": {} }),
            json!({ "type": "oauth_access_token", "access_token": "oauth-secret" }),
            "Bearer oauth-secret",
        ),
    ];

    for (slug, scheme, credential, expected_carrier) in cases {
        let origin_a = CredentialTarget::start().await;
        let origin_b = CredentialTarget::start().await;
        set_secured_specification(&upstream, &origin_a.origin(), "Auth", scheme.clone(), slug)
            .await;
        let created = import_source(
            &app,
            &admin,
            &upstream.spec_url(None),
            slug,
            json!({ "schemes": { "Auth": credential } }),
        )
        .await;
        let source_id = created["id"]
            .as_str()
            .expect("source should have an ID")
            .to_owned();
        let path = source_tool_path(&app, &source_id).await;
        let invoked = invoke_path(&app, &token, &path).await;
        assert_eq!(invoked.status(), StatusCode::OK, "{slug} should invoke");
        let first = origin_a.requests();
        assert_eq!(first.len(), 1, "{slug} should reach origin A once");
        let captured = format!("{} {:?}", first[0].path_and_query, first[0].headers);
        assert!(
            captured.contains(expected_carrier),
            "{slug} should send its expected credential carrier"
        );

        let before_source = app
            .catalog()
            .source(&source_id)
            .await
            .expect("source should read");
        let before_binding = app
            .catalog()
            .tool_binding(
                &app.catalog()
                    .list_tools(ListToolsFilter {
                        source_id: Some(source_id.clone()),
                        limit: 10,
                        ..Default::default()
                    })
                    .await
                    .expect("source tools should list")
                    .items[0]
                    .id,
            )
            .await
            .expect("binding should read");
        let before_global_revision = app
            .catalog()
            .global_revision()
            .await
            .expect("global revision should read");

        set_secured_specification(&upstream, &origin_b.origin(), "Auth", scheme, slug).await;
        let rejected = send(
            app.router(),
            Method::POST,
            &format!("/api/v1/sources/{source_id}/refresh"),
            json!({}),
            &admin_headers(&admin),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::CONFLICT, "{slug}");
        assert_eq!(
            json_body(rejected).await["error"]["code"],
            "openapi_credential_origin_changed"
        );

        let after_source = app
            .catalog()
            .source(&source_id)
            .await
            .expect("source should remain readable");
        assert_eq!(after_source.revision, before_source.revision, "{slug}");
        assert_eq!(
            after_source.catalog_revision, before_source.catalog_revision,
            "{slug}"
        );
        assert_eq!(
            app.catalog()
                .global_revision()
                .await
                .expect("global revision should remain readable"),
            before_global_revision,
            "{slug}"
        );
        assert_eq!(
            app.catalog()
                .tool_binding(&before_binding.tool_id)
                .await
                .expect("last-good binding should remain")
                .binding,
            before_binding.binding,
            "{slug}"
        );

        let invoked = invoke_path(&app, &token, &path).await;
        assert_eq!(
            invoked.status(),
            StatusCode::OK,
            "{slug} last-good binding should remain callable"
        );
        assert_eq!(origin_a.requests().len(), 2, "{slug}");
        assert!(
            origin_b.requests().is_empty(),
            "{slug} must not reach origin B"
        );

        sqlx::query(
            "UPDATE tool_bindings SET definition_json = json_set(definition_json, '$.serverUrl', ?) \
             WHERE tool_id = ?",
        )
        .bind(format!("{}/api", insecure_target.origin()))
        .bind(&before_binding.tool_id)
        .execute(app.pool())
        .await
        .expect("stored binding should tamper");
        let blocked = invoke_path(&app, &token, &path).await;
        assert_eq!(blocked.status(), StatusCode::CONFLICT, "{slug}");
        assert_eq!(
            json_body(blocked).await["error"]["code"],
            "insecure_openapi_transport",
            "{slug}"
        );
        assert!(insecure_target.requests().is_empty(), "{slug}");
        assert_eq!(origin_a.requests().len(), 2, "{slug}");
    }
}

#[tokio::test]
async fn oauth_callback_refresh_cannot_move_managed_bearer_to_a_new_origin() {
    let provider = OAuthTestProvider::start().await;
    let upstream = Upstream::start().await;
    let origin_a = CredentialTarget::start().await;
    let origin_b = CredentialTarget::start().await;
    let oauth_scheme = json!({
        "type": "oauth2",
        "flows": { "authorizationCode": {
            "authorizationUrl": format!("{}/authorize", provider.issuer),
            "tokenUrl": format!("{}/token", provider.issuer),
            "scopes": { "repo": "Read repositories" }
        }}
    });
    set_secured_specification(
        &upstream,
        &origin_a.origin(),
        "oauth",
        oauth_scheme.clone(),
        "managedOAuthCall",
    )
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
        "managed_oauth_origin",
        json!({ "schemes": {} }),
    )
    .await;
    let source_id = created["id"]
        .as_str()
        .expect("source should have an ID")
        .to_owned();
    let mutation_headers = admin_headers(&admin);
    let connection_input = |expected_revision, client_id: &str| {
        json!({
            "expectedRevision": expected_revision,
            "discovery": { "type": "issuer", "issuer": provider.issuer },
            "client": { "clientId": client_id, "authentication": "none" },
            "scopes": ["repo"]
        })
    };
    let placeholder = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/oauth/oauth"),
        connection_input(0, "pending-dynamic-registration"),
        &mutation_headers,
    )
    .await;
    assert_eq!(placeholder.status(), StatusCode::OK);
    let placeholder = json_body(placeholder).await;
    let connection_id = placeholder["id"]
        .as_str()
        .expect("placeholder connection has an ID")
        .to_owned();
    let client_id = provider
        .register_client(
            placeholder["callbackUrl"]
                .as_str()
                .expect("placeholder has a callback URL"),
        )
        .await;
    let configured = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/oauth/oauth"),
        connection_input(
            placeholder["revision"]
                .as_i64()
                .expect("placeholder has a revision"),
            &client_id,
        ),
        &mutation_headers,
    )
    .await;
    assert_eq!(configured.status(), StatusCode::OK);
    let configured = json_body(configured).await;
    let authorization = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/sources/{source_id}/oauth/oauth/authorize"),
        json!({
            "expectedRevision": configured["revision"]
                .as_i64()
                .expect("configured connection has a revision")
        }),
        &mutation_headers,
    )
    .await;
    assert_eq!(authorization.status(), StatusCode::OK);
    let authorization = json_body(authorization).await;
    let provider_callback = provider
        .approve(
            authorization["authorizationUrl"]
                .as_str()
                .expect("authorization URL returns"),
        )
        .await;
    let before_callback_source = app
        .catalog()
        .source(&source_id)
        .await
        .expect("source should read");
    let before_callback_binding = app
        .catalog()
        .tool_binding(
            &app.catalog()
                .list_tools(ListToolsFilter {
                    source_id: Some(source_id.clone()),
                    limit: 10,
                    ..Default::default()
                })
                .await
                .expect("source tools should list")
                .items[0]
                .id,
        )
        .await
        .expect("binding should read");

    set_secured_specification(
        &upstream,
        &origin_b.origin(),
        "oauth",
        oauth_scheme,
        "managedOAuthCall",
    )
    .await;
    let callback_uri = provider_callback.query().map_or_else(
        || provider_callback.path().to_owned(),
        |query| format!("{}?{query}", provider_callback.path()),
    );
    let callback = send(
        app.router(),
        Method::GET,
        &callback_uri,
        json!(null),
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    let redirect = Url::parse(
        callback
            .headers()
            .get(header::LOCATION)
            .expect("callback redirects")
            .to_str()
            .expect("callback redirect is text"),
    )
    .expect("callback redirect parses");
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "result")
            .expect("callback includes a result")
            .1,
        "success_refresh_failed"
    );
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "oauth")
            .expect("callback includes a connection")
            .1,
        connection_id
    );

    let after_callback_source = app
        .catalog()
        .source(&source_id)
        .await
        .expect("source should remain readable");
    assert_eq!(
        after_callback_source.revision,
        before_callback_source.revision
    );
    assert_eq!(
        after_callback_source.catalog_revision,
        before_callback_source.catalog_revision
    );
    assert_eq!(
        app.catalog()
            .tool_binding(&before_callback_binding.tool_id)
            .await
            .expect("last-good binding should remain")
            .binding,
        before_callback_binding.binding
    );
    let stored = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("credential envelope should exist");
    assert_eq!(
        stored.credential.payload["credentialOrigins"]["oauth"],
        json!([origin_a.origin()])
    );

    let manual_refresh = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/sources/{source_id}/refresh"),
        json!({}),
        &mutation_headers,
    )
    .await;
    assert_eq!(manual_refresh.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(manual_refresh).await["error"]["code"],
        "openapi_credential_origin_changed"
    );

    let token = gateway_token(&app, &admin).await;
    let path = source_tool_path(&app, &source_id).await;
    let invoked = invoke_path(&app, &token, &path).await;
    assert_eq!(invoked.status(), StatusCode::OK);
    let requests = origin_a.requests();
    assert_eq!(requests.len(), 1);
    assert!(
        requests[0]
            .headers
            .get("authorization")
            .is_some_and(|value| value.starts_with("Bearer "))
    );
    assert!(origin_b.requests().is_empty());

    let listed = send(
        app.router(),
        Method::GET,
        &format!("/api/v1/sources/{source_id}/oauth"),
        json!(null),
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = json_body(listed).await;
    let connection_revision = listed["connections"][0]["revision"]
        .as_i64()
        .expect("managed OAuth connection has a revision");
    sqlx::query(
        "CREATE TRIGGER reject_oauth_origin_retire BEFORE UPDATE ON source_credentials \
         BEGIN SELECT RAISE(ABORT, 'reject OAuth origin retirement'); END",
    )
    .execute(app.pool())
    .await
    .expect("origin retirement failure trigger should install");
    let delete_uri =
        format!("/api/v1/sources/{source_id}/oauth/oauth?expectedRevision={connection_revision}");
    let failed_delete = send(
        app.router(),
        Method::DELETE,
        &delete_uri,
        json!(null),
        &mutation_headers,
    )
    .await;
    assert_eq!(failed_delete.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        json_body(failed_delete).await["error"]["code"],
        "internal_error"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM oauth_connections WHERE source_id = ? AND credential_key = ?",
        )
        .bind(&source_id)
        .bind("oauth")
        .fetch_one(app.pool())
        .await
        .expect("OAuth connection count should read"),
        0
    );
    let stranded = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("credential envelope should remain");
    assert_eq!(
        stranded.credential.payload["credentialOrigins"]["oauth"],
        json!([origin_a.origin()])
    );
    sqlx::query("DROP TRIGGER reject_oauth_origin_retire")
        .execute(app.pool())
        .await
        .expect("origin retirement failure trigger should drop");
    let retried_delete = send(
        app.router(),
        Method::DELETE,
        &delete_uri,
        json!(null),
        &mutation_headers,
    )
    .await;
    assert_eq!(retried_delete.status(), StatusCode::NO_CONTENT);
    let retired = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("credential envelope should remain");
    assert!(
        retired
            .credential
            .payload
            .get("credentialOrigins")
            .is_none(),
        "deleting the last owner must retire its origin pin"
    );
    assert_eq!(refresh(&app, &admin, &source_id).await, StatusCode::OK);
    assert_eq!(
        app.catalog()
            .tool_binding(&before_callback_binding.tool_id)
            .await
            .expect("refreshed binding should read")
            .binding
            .openapi()
            .expect("binding should remain OpenAPI")
            .server_url,
        format!("{}/api", origin_b.origin())
    );
}

#[tokio::test]
async fn redirected_spec_final_origin_fences_relative_credential_destinations() {
    let spec_a = Upstream::start().await;
    let spec_b = Upstream::start().await;
    let relative_document = json!({
        "openapi": "3.1.0",
        "info": { "title": "Redirected relative API" },
        "servers": [{ "url": "./api" }],
        "components": { "securitySchemes": {
            "ApiKey": { "type": "apiKey", "in": "header", "name": "X-API-Key" }
        }},
        "paths": { "/credential": { "get": {
            "operationId": "redirectedCredential",
            "security": [{ "ApiKey": [] }],
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    *spec_a.specification.write().await = relative_document.clone();
    *spec_b.specification.write().await = relative_document;
    let redirect = SpecRedirect::start(spec_a.spec_url(None)).await;
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let created = import_source(
        &app,
        &admin,
        &redirect.url(),
        "redirected_origin",
        json!({ "schemes": {
            "ApiKey": { "type": "api_key", "value": "secret" }
        }}),
    )
    .await;
    let source_id = created["id"]
        .as_str()
        .expect("source should have an ID")
        .to_owned();
    let before = app
        .catalog()
        .source(&source_id)
        .await
        .expect("source should read");
    let stored = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("credential should exist");
    assert_eq!(
        stored.credential.payload["credentialOrigins"]["ApiKey"],
        json!([format!("http://{}", spec_a.address)])
    );

    redirect.set_target(spec_b.spec_url(None)).await;
    let rejected = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/sources/{source_id}/refresh"),
        json!({}),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(rejected).await["error"]["code"],
        "openapi_credential_origin_changed"
    );
    let after = app
        .catalog()
        .source(&source_id)
        .await
        .expect("source should remain readable");
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.catalog_revision, before.catalog_revision);
}

#[tokio::test]
async fn query_bearing_document_urls_never_reach_persisted_tool_bindings() {
    let upstream = Upstream::start().await;
    *upstream.specification.write().await = json!({
        "openapi": "3.1.0",
        "info": { "title": "Query-safe document base" },
        "servers": [{ "url": "" }],
        "paths": { "/api/hello": { "get": {
            "operationId": "querySafeHello",
            "responses": {
                "200": {
                    "description": "ok",
                    "content": {
                        "application/json": { "schema": { "type": "object" } }
                    }
                }
            }
        }}}
    });
    let direct_secret = "direct-document-secret-4a2dc144";
    let redirect_secret = "redirect-document-secret-a576c879";
    let redirect =
        SpecRedirect::start(upstream.spec_url(Some(&format!("token={redirect_secret}")))).await;
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let data_dir = directory.path().to_path_buf();
    let app = ExecutorApp::open(AppConfig::new(data_dir.clone()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let token = gateway_token(&app, &admin).await;

    let direct = import_source(
        &app,
        &admin,
        &upstream.spec_url(Some(&format!("token={direct_secret}"))),
        "direct-query-base",
        json!({ "schemes": {} }),
    )
    .await;
    let redirected = import_source(
        &app,
        &admin,
        &redirect.url(),
        "redirect-query-base",
        json!({ "schemes": {} }),
    )
    .await;

    for created in [&direct, &redirected] {
        let source_id = created["id"].as_str().expect("source should have an ID");
        let path = source_tool_path(&app, source_id).await;
        assert_eq!(
            invoke_path(&app, &token, &path).await.status(),
            StatusCode::OK
        );
    }
    let definitions = sqlx::query_scalar::<_, String>(
        "SELECT definition_json FROM tool_bindings ORDER BY tool_id",
    )
    .fetch_all(app.pool())
    .await
    .expect("tool bindings should read");
    assert_eq!(definitions.len(), 2);
    for definition in definitions {
        assert!(!definition.contains(direct_secret));
        assert!(!definition.contains(redirect_secret));
        let binding: Value = serde_json::from_str(&definition).expect("binding should be JSON");
        assert!(
            Url::parse(
                binding["serverUrl"]
                    .as_str()
                    .expect("binding should contain a server URL")
            )
            .expect("server URL should parse")
            .query()
            .is_none()
        );
    }

    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_all(app.pool())
        .await
        .expect("WAL should checkpoint");
    app.pool().close().await;
    drop(app);
    for file_name in ["executor.db", "executor.db-wal", "executor.db-shm"] {
        let path = data_dir.join(file_name);
        if path.exists() {
            assert_file_excludes(&path, direct_secret);
            assert_file_excludes(&path, redirect_secret);
        }
    }
}

#[tokio::test]
async fn credentialless_refresh_can_move_then_later_credential_binding_pins_current_origin() {
    let upstream = Upstream::start().await;
    let origin_a = CredentialTarget::start().await;
    let origin_b = CredentialTarget::start().await;
    let insecure_origin = CredentialTarget::start_non_loopback().await;
    let scheme = json!({ "type": "http", "scheme": "bearer" });
    set_secured_specification(
        &upstream,
        &origin_a.origin(),
        "BearerAuth",
        scheme.clone(),
        "anonymousMove",
    )
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
        "credentialless_move",
        json!({ "schemes": {} }),
    )
    .await;
    let source_id = created["id"]
        .as_str()
        .expect("source should have an ID")
        .to_owned();

    let tool_id = app
        .catalog()
        .list_tools(ListToolsFilter {
            source_id: Some(source_id.clone()),
            limit: 10,
            ..Default::default()
        })
        .await
        .expect("source tools should list")
        .items[0]
        .id
        .clone();
    let original_binding = sqlx::query_scalar::<_, String>(
        "SELECT definition_json FROM tool_bindings WHERE tool_id = ?",
    )
    .bind(&tool_id)
    .fetch_one(app.pool())
    .await
    .expect("tool binding should read");
    sqlx::query(
        "UPDATE tool_bindings SET definition_json = json_set(definition_json, '$.serverUrl', ?) \
         WHERE tool_id = ?",
    )
    .bind(format!("{}/api", insecure_origin.origin()))
    .bind(&tool_id)
    .execute(app.pool())
    .await
    .expect("tool binding should tamper");
    let insecure_rebind = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "expectedRevision": 0,
            "credential": { "schemes": {
                "BearerAuth": { "type": "bearer", "token": "must-not-bind" }
            }}
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(insecure_rebind.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(insecure_rebind).await["error"]["code"],
        "insecure_openapi_transport"
    );
    assert_eq!(
        app.catalog()
            .credential(&source_id)
            .await
            .expect("credential should decrypt")
            .expect("credential envelope should exist")
            .revision,
        0
    );
    assert!(insecure_origin.requests().is_empty());
    sqlx::query("UPDATE tool_bindings SET definition_json = ? WHERE tool_id = ?")
        .bind(original_binding)
        .bind(&tool_id)
        .execute(app.pool())
        .await
        .expect("tool binding should restore");

    set_secured_specification(
        &upstream,
        &origin_b.origin(),
        "BearerAuth",
        scheme.clone(),
        "anonymousMove",
    )
    .await;
    assert_eq!(refresh(&app, &admin, &source_id).await, StatusCode::OK);
    let saved = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "expectedRevision": 0,
            "credential": { "schemes": {
                "BearerAuth": { "type": "bearer", "token": "later-secret" }
            }}
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(saved.status(), StatusCode::OK);
    let stored = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("credential should exist");
    assert_eq!(
        stored.credential.payload["credentialOrigins"]["BearerAuth"],
        json!([origin_b.origin()])
    );

    set_secured_specification(
        &upstream,
        &origin_a.origin(),
        "BearerAuth",
        scheme.clone(),
        "anonymousMove",
    )
    .await;
    let rejected = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/sources/{source_id}/refresh"),
        json!({}),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(rejected).await["error"]["code"],
        "openapi_credential_origin_changed"
    );
    assert!(origin_a.requests().is_empty());
    assert!(origin_b.requests().is_empty());

    let cleared = send(
        app.router(),
        Method::DELETE,
        &format!("/api/v1/sources/{source_id}/credentials?expectedRevision=1"),
        json!(null),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(cleared.status(), StatusCode::OK);
    assert_eq!(json_body(cleared).await["revision"], 2);
    let unbound = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("credential locator should remain");
    assert!(
        unbound
            .credential
            .payload
            .get("credentialOrigins")
            .is_none(),
        "clearing the final credential must explicitly release its origin pin"
    );
    set_secured_specification(
        &upstream,
        &insecure_origin.origin(),
        "BearerAuth",
        scheme.clone(),
        "anonymousMove",
    )
    .await;
    let before_insecure_refresh = app
        .catalog()
        .source(&source_id)
        .await
        .expect("source should read");
    let insecure_refresh = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/sources/{source_id}/refresh"),
        json!({}),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(insecure_refresh.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(insecure_refresh).await["error"]["code"],
        "insecure_openapi_transport"
    );
    assert_eq!(
        app.catalog()
            .source(&source_id)
            .await
            .expect("source should remain readable")
            .revision,
        before_insecure_refresh.revision
    );
    assert!(insecure_origin.requests().is_empty());

    set_secured_specification(
        &upstream,
        &origin_a.origin(),
        "BearerAuth",
        scheme,
        "anonymousMove",
    )
    .await;
    assert_eq!(refresh(&app, &admin, &source_id).await, StatusCode::OK);
    let rebound = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "expectedRevision": 2,
            "credential": { "schemes": {
                "BearerAuth": { "type": "bearer", "token": "rebound-secret" }
            }}
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(rebound.status(), StatusCode::OK);
    let rebound_stored = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("credential should exist");
    assert_eq!(
        rebound_stored.credential.payload["credentialOrigins"]["BearerAuth"],
        json!([origin_a.origin()])
    );
    let token = gateway_token(&app, &admin).await;
    let path = source_tool_path(&app, &source_id).await;
    assert_eq!(
        invoke_path(&app, &token, &path).await.status(),
        StatusCode::OK
    );
    let captured = origin_a.requests();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].headers.get("authorization").map(String::as_str),
        Some("Bearer rebound-secret")
    );
}

#[tokio::test]
async fn basic_credentials_reject_ambiguous_identity_before_persistence_or_dispatch() {
    let upstream = Upstream::start().await;
    let target = CredentialTarget::start().await;
    set_secured_specification(
        &upstream,
        &target.origin(),
        "BasicAuth",
        json!({ "type": "http", "scheme": "basic" }),
        "basicIdentity",
    )
    .await;
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;

    let spec_requests = upstream.spec_request_count();
    let invalid_scheme_create = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Invalid scheme name",
            "preferredSlug": "invalid-scheme-name",
            "spec": { "type": "url", "url": upstream.spec_url(None) },
            "allowPrivateNetwork": true,
            "credential": { "schemes": {
                "Basic\nAuth": { "type": "basic", "username": "user", "password": "secret" }
            }}
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(invalid_scheme_create.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(invalid_scheme_create).await["error"]["code"],
        "invalid_credentials"
    );
    assert_eq!(upstream.spec_request_count(), spec_requests);
    let spec_requests = upstream.spec_request_count();

    for (slug, username, password, code) in [
        (
            "invalid-basic-colon",
            "admin:other",
            "secret",
            "invalid_basic_username",
        ),
        (
            "invalid-basic-user-control",
            "admin\nother",
            "secret",
            "invalid_basic_credentials",
        ),
        (
            "invalid-basic-password-control",
            "admin",
            "secret\u{7f}",
            "invalid_basic_credentials",
        ),
    ] {
        let rejected = send(
            app.router(),
            Method::POST,
            "/api/v1/sources",
            json!({
                "kind": "openapi",
                "displayName": "Invalid Basic",
                "preferredSlug": slug,
                "spec": { "type": "url", "url": upstream.spec_url(None) },
                "allowPrivateNetwork": true,
                "credential": { "schemes": {
                    "BasicAuth": { "type": "basic", "username": username, "password": password }
                }}
            }),
            &admin_headers(&admin),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(rejected).await["error"]["code"], code);
    }
    assert_eq!(upstream.spec_request_count(), spec_requests);
    assert!(target.requests().is_empty());

    let unicode_username = "δοκιμή";
    let unicode_password = "päss:word";
    let created = import_source(
        &app,
        &admin,
        &upstream.spec_url(None),
        "valid-basic-identity",
        json!({ "schemes": {
            "BasicAuth": {
                "type": "basic",
                "username": unicode_username,
                "password": unicode_password
            }
        }}),
    )
    .await;
    let source_id = created["id"]
        .as_str()
        .expect("source should have an ID")
        .to_owned();
    let path = source_tool_path(&app, &source_id).await;
    let token = gateway_token(&app, &admin).await;
    assert_eq!(
        invoke_path(&app, &token, &path).await.status(),
        StatusCode::OK
    );
    let expected_unicode = format!(
        "Basic {}",
        STANDARD.encode(format!("{unicode_username}:{unicode_password}"))
    );
    assert_eq!(
        target.requests()[0].headers.get("authorization"),
        Some(&expected_unicode)
    );

    for (username, password, code) in [
        ("admin:other", "secret", "invalid_basic_username"),
        ("admin\nother", "secret", "invalid_basic_credentials"),
        ("admin", "secret\u{7f}", "invalid_basic_credentials"),
    ] {
        let rejected = send(
            app.router(),
            Method::PUT,
            &format!("/api/v1/sources/{source_id}/credentials"),
            json!({
                "expectedRevision": 0,
                "credential": { "schemes": {
                    "BasicAuth": { "type": "basic", "username": username, "password": password }
                }}
            }),
            &admin_headers(&admin),
        )
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(rejected).await["error"]["code"], code);
    }
    let preserved = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("credential should exist");
    assert_eq!(preserved.revision, 0);
    assert_eq!(
        preserved.credential.payload["credentials"]["schemes"]["BasicAuth"]["username"],
        unicode_username
    );
    assert_eq!(
        preserved.credential.payload["credentials"]["schemes"]["BasicAuth"]["password"],
        unicode_password
    );
    assert_eq!(target.requests().len(), 1);

    let invalid_scheme_replace = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "expectedRevision": 0,
            "credential": { "schemes": {
                "Basic\nAuth": { "type": "basic", "username": "user", "password": "secret" }
            }}
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(invalid_scheme_replace.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(invalid_scheme_replace).await["error"]["code"],
        "invalid_credentials"
    );
    let preserved = app
        .catalog()
        .credential(&source_id)
        .await
        .expect("credential should decrypt")
        .expect("credential should exist");
    assert_eq!(preserved.revision, 0);
    assert_eq!(
        preserved.credential.payload["credentials"]["schemes"]["BasicAuth"]["username"],
        unicode_username
    );

    let empty_username = send(
        app.router(),
        Method::PUT,
        &format!("/api/v1/sources/{source_id}/credentials"),
        json!({
            "expectedRevision": 0,
            "credential": { "schemes": {
                "BasicAuth": {
                    "type": "basic",
                    "username": "",
                    "password": "password:with:colons"
                }
            }}
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(empty_username.status(), StatusCode::OK);
    assert_eq!(json_body(empty_username).await["revision"], 1);
    assert_eq!(
        invoke_path(&app, &token, &path).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        target.requests()[1].headers.get("authorization"),
        Some(&format!(
            "Basic {}",
            STANDARD.encode(":password:with:colons")
        ))
    );
}

#[tokio::test]
async fn trace_operations_never_enter_the_catalog_or_become_mode_overridable() {
    let upstream = Upstream::start().await;
    *upstream.specification.write().await = json!({
        "openapi": "3.1.0",
        "info": { "title": "Unsupported TRACE" },
        "servers": [{ "url": format!("http://{}/api", upstream.address) }],
        "paths": { "/trace": { "trace": {
            "operationId": "traceRequest",
            "responses": { "200": { "description": "ok" } }
        }}}
    });
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;
    let before_global_revision = app
        .catalog()
        .global_revision()
        .await
        .expect("global revision should read");
    let rejected = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "openapi",
            "displayName": "Unsupported TRACE",
            "preferredSlug": "unsupported_trace",
            "spec": { "type": "url", "url": upstream.spec_url(None) },
            "allowPrivateNetwork": true,
            "credential": { "schemes": {} }
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(rejected).await["error"]["code"],
        "invalid_openapi_document"
    );
    assert!(
        app.catalog()
            .list_tools(ListToolsFilter {
                include_tombstoned: true,
                ..Default::default()
            })
            .await
            .expect("catalog should remain readable")
            .items
            .is_empty(),
        "there must be no TRACE tool whose mode can be overridden"
    );
    assert_eq!(
        app.catalog()
            .global_revision()
            .await
            .expect("global revision should remain readable"),
        before_global_revision
    );
}

#[tokio::test]
async fn refresh_rejects_unknown_fields_before_fetching_or_mutating() {
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
        "strict-refresh",
        json!({ "schemes": {} }),
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
    let before_spec_requests = upstream.spec_request_count();

    let response = send(
        app.router(),
        Method::POST,
        &format!("/api/v1/sources/{source_id}/refresh"),
        json!({ "expectedRevison": before_source.revision }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"]["code"], "invalid_json");
    assert_eq!(upstream.spec_request_count(), before_spec_requests);

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
        json!({ "schemes": {} }),
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
async fn refresh_binding_failure_rolls_back_catalog_data_while_recording_health() {
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
        json!({ "schemes": {} }),
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
    assert_eq!(after_source.revision, before_source.revision + 1);
    assert_eq!(after_source.health_status, SourceHealth::Error);
    assert_eq!(
        after_source.health_error_code.as_deref(),
        Some("openapi_refresh_failed")
    );
    assert_eq!(
        after_source.last_refreshed_at,
        before_source.last_refreshed_at
    );
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
        before_global_revision + 1
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
        before_audits + 1
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
