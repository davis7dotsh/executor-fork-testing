use std::{
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, Response, StatusCode, header},
    routing::{get, post},
};
use executor::{AppConfig, ExecutorApp};
use http_body_util::BodyExt as _;
use reqwest::{Client, redirect::Policy};
use serde_json::{Value, json};
use tokio::{net::TcpListener, process::Command, time::sleep};
use tower::ServiceExt as _;
use url::Url;

const ORIGIN: &str = "http://127.0.0.1:4788";

struct TestExecutor {
    app: ExecutorApp,
    setup_token: String,
}

struct AdminSession {
    cookie: String,
    csrf: String,
}

struct OAuthTestProvider {
    issuer: String,
    client: Client,
    child: tokio::process::Child,
}

struct MalformedTokenProvider {
    issuer: String,
    token_requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
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
                "client_name": "Executor OAuth API test",
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
        assert_eq!(authorization_url.path(), "/authorize");
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

impl MalformedTokenProvider {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test OAuth provider binds");
        let issuer = format!(
            "http://{}",
            listener.local_addr().expect("test provider address reads")
        );
        let metadata_issuer = issuer.clone();
        let token_requests = Arc::new(AtomicUsize::new(0));
        let token_request_counter = token_requests.clone();
        let app = Router::new()
            .route(
                "/.well-known/oauth-authorization-server",
                get(move || {
                    let issuer = metadata_issuer.clone();
                    async move {
                        Json(json!({
                            "issuer": issuer.clone(),
                            "authorization_endpoint": format!("{issuer}/authorize"),
                            "token_endpoint": format!("{issuer}/token"),
                            "scopes_supported": ["read"],
                            "response_types_supported": ["code"],
                            "grant_types_supported": ["authorization_code"],
                            "code_challenge_methods_supported": ["S256"],
                            "token_endpoint_auth_methods_supported": ["none"]
                        }))
                    }
                }),
            )
            .route(
                "/token",
                post(move || {
                    let attempt = token_request_counter.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if attempt == 0 {
                            Json(json!({
                                "access_token": "malformed-access-token-marker",
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "scope": "read unrequested"
                            }))
                        } else {
                            Json(json!({
                                "access_token": "valid-access-token-marker",
                                "refresh_token": "valid-refresh-token-marker",
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "scope": "read"
                            }))
                        }
                    }
                }),
            );
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test OAuth provider serves");
        });
        Self {
            issuer,
            token_requests,
            task,
        }
    }
}

impl Drop for MalformedTokenProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestExecutor {
    async fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary data directory");
        let path = directory.keep();
        let app = ExecutorApp::open(AppConfig::new(path))
            .await
            .expect("Executor opens");
        let setup_token = app
            .setup_token()
            .expect("fresh Executor has a setup token")
            .to_owned();
        Self { app, setup_token }
    }

    async fn setup_and_login(&self) -> AdminSession {
        let setup = send_json(
            self.app.router(),
            Method::POST,
            "/api/v1/setup",
            json!({
                "setupToken": self.setup_token,
                "username": "admin",
                "password": "correct horse battery staple"
            }),
            &[(header::ORIGIN.as_str(), ORIGIN)],
        )
        .await;
        assert_eq!(setup.status(), StatusCode::CREATED);

        let login = send_json(
            self.app.router(),
            Method::POST,
            "/api/v1/session",
            json!({
                "username": "admin",
                "password": "correct horse battery staple"
            }),
            &[(header::ORIGIN.as_str(), ORIGIN)],
        )
        .await;
        assert_eq!(login.status(), StatusCode::OK);
        let cookie = response_cookie_header(&login);
        let body = response_json(login).await;
        let csrf = body["csrfToken"]
            .as_str()
            .expect("login returns CSRF token")
            .to_owned();
        AdminSession { cookie, csrf }
    }

    async fn insert_source(&self) {
        self.insert_source_at("https://api.example.test/mcp", false)
            .await;
    }

    async fn insert_source_at(&self, endpoint: &str, allow_private_network: bool) {
        sqlx::query(
            "INSERT INTO sources (
                id, kind, slug, display_name, configuration_json,
                revision, catalog_revision, created_at, updated_at
             ) VALUES (?, 'mcp_http', 'oauth_test', 'OAuth test', ?, 0, 0, 1, 1)",
        )
        .bind("source-oauth-test")
        .bind(
            json!({
                "endpoint": endpoint,
                "allowPrivateNetwork": allow_private_network,
                "negotiatedProtocolVersion": "2025-11-25"
            })
            .to_string(),
        )
        .execute(self.app.pool())
        .await
        .expect("test source inserts");
    }

    async fn insert_oauth_connection(&self) {
        let mut transaction = self.app.pool().begin().await.expect("transaction begins");
        sqlx::query(
            "INSERT INTO oauth_connections (
                id, source_id, credential_key, revision, current_config_revision,
                current_secret_revision, status, granted_scopes_json,
                has_client_secret, has_refresh_token, created_at, updated_at
             ) VALUES (?, ?, 'default', 1, 1, NULL, 'pending_authorization',
                       '[]', 0, 0, 1, 1)",
        )
        .bind("oauth-connection-test")
        .bind("source-oauth-test")
        .execute(&mut *transaction)
        .await
        .expect("OAuth connection inserts");
        sqlx::query(
            "INSERT INTO oauth_connection_config_revisions (
                connection_id, revision, config_json, created_at
             ) VALUES (?, 1, ?, 1)",
        )
        .bind("oauth-connection-test")
        .bind(
            json!({
                "issuer": "https://issuer.example.test",
                "authorization_endpoint": "https://issuer.example.test/authorize",
                "token_endpoint": "https://issuer.example.test/token",
                "client_id": "public-client",
                "client_authentication": "none",
                "token_endpoint_auth_methods_supported": ["none"],
                "scopes": ["read"],
                "allow_private_network": false
            })
            .to_string(),
        )
        .execute(&mut *transaction)
        .await
        .expect("OAuth config inserts");
        transaction.commit().await.expect("transaction commits");
    }
}

#[tokio::test]
async fn oauth_routes_use_admin_and_csrf_boundaries() {
    let executor = TestExecutor::new().await;
    let admin = executor.setup_and_login().await;
    executor.insert_source().await;

    let unauthorized = send_empty(
        executor.app.router(),
        Method::GET,
        "/api/v1/sources/source-oauth-test/oauth",
        &[],
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let listed = send_empty(
        executor.app.router(),
        Method::GET,
        "/api/v1/sources/source-oauth-test/oauth",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(
        response_json(listed).await,
        json!({
            "connections": [],
            "availableCredentials": [{
                "credentialKey": "default",
                "protocol": "mcp_http",
                "requestedScopes": [],
                "managedOAuthEligible": true
            }]
        })
    );

    let input = json!({
        "expectedRevision": 0,
        "discovery": { "type": "issuer", "issuer": "https://issuer.example.test" },
        "client": { "clientId": "public-client", "authentication": "none" },
        "scopes": ["openid"]
    });
    let missing_csrf = send_json(
        executor.app.router(),
        Method::PUT,
        "/api/v1/sources/source-oauth-test/oauth/default",
        input.clone(),
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);

    let malformed_issuer = send_json(
        executor.app.router(),
        Method::PUT,
        "/api/v1/sources/source-oauth-test/oauth/default",
        json!({
            "expectedRevision": 0,
            "discovery": { "type": "issuer", "issuer": "not a valid issuer" },
            "client": { "clientId": "public-client", "authentication": "none" },
            "scopes": []
        }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(malformed_issuer.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(malformed_issuer).await["error"]["code"],
        "invalid_oauth_url"
    );

    let ineligible = send_json(
        executor.app.router(),
        Method::PUT,
        "/api/v1/sources/source-oauth-test/oauth/not-a-protocol-credential",
        input.clone(),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(ineligible.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(ineligible).await["error"]["code"],
        "oauth_credential_ineligible"
    );

    let ineligible_authorization = send_json(
        executor.app.router(),
        Method::POST,
        "/api/v1/sources/source-oauth-test/oauth/not-a-protocol-credential/authorize",
        json!({ "expectedRevision": 0 }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(ineligible_authorization.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(ineligible_authorization).await["error"]["code"],
        "oauth_credential_ineligible"
    );

    let rejected_scope = send_json(
        executor.app.router(),
        Method::PUT,
        "/api/v1/sources/source-oauth-test/oauth/default",
        input,
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(rejected_scope.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(rejected_scope).await["error"]["code"],
        "oauth_openid_unsupported"
    );

    executor.insert_oauth_connection().await;
    let disconnected = send_json(
        executor.app.router(),
        Method::POST,
        "/api/v1/sources/source-oauth-test/oauth/default/disconnect",
        json!({ "expectedRevision": 1 }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(disconnected.status(), StatusCode::OK);
    let disconnected = response_json(disconnected).await;
    assert_eq!(disconnected["credentialKey"], "default");
    assert_eq!(disconnected["managedOAuthEligible"], true);
}

#[tokio::test]
async fn callback_failures_redirect_without_reflecting_callback_secrets() {
    let executor = TestExecutor::new().await;
    let response = send_empty(
        executor.app.router(),
        Method::GET,
        "/api/v1/oauth/callback/opaque-connection?state=state-secret&code=code-secret",
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("callback redirects")
        .to_str()
        .expect("redirect is text");
    assert_eq!(
        location,
        "http://127.0.0.1:4788/sources?oauth=opaque%2Dconnection&result=failed"
    );
    assert!(!location.contains("state-secret"));
    assert!(!location.contains("code-secret"));
    assert_eq!(
        response.headers().get(header::REFERRER_POLICY),
        Some(&header::HeaderValue::from_static("no-referrer"))
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
}

#[tokio::test]
async fn malformed_successful_token_response_terminalizes_the_claim_and_allows_retry() {
    let provider = MalformedTokenProvider::start().await;
    let executor = TestExecutor::new().await;
    let admin = executor.setup_and_login().await;
    executor
        .insert_source_at(&format!("{}/mcp", provider.issuer), true)
        .await;
    let mutation_headers = [
        (header::COOKIE.as_str(), admin.cookie.as_str()),
        (header::ORIGIN.as_str(), ORIGIN),
        ("x-executor-csrf", admin.csrf.as_str()),
    ];
    let configured = send_json(
        executor.app.router(),
        Method::PUT,
        "/api/v1/sources/source-oauth-test/oauth/default",
        json!({
            "expectedRevision": 0,
            "discovery": { "type": "issuer", "issuer": provider.issuer.clone() },
            "client": { "clientId": "public-client", "authentication": "none" },
            "scopes": ["read"]
        }),
        &mutation_headers,
    )
    .await;
    assert_eq!(configured.status(), StatusCode::OK);
    let configured = response_json(configured).await;
    let connection_id = configured["id"]
        .as_str()
        .expect("configured connection has ID")
        .to_owned();

    let malformed = begin_and_complete_authorization(
        &executor,
        &admin,
        &connection_id,
        configured["revision"]
            .as_i64()
            .expect("configured connection has revision"),
        "first-code",
    )
    .await;
    assert_eq!(malformed.status(), StatusCode::SEE_OTHER);
    let malformed_location = malformed
        .headers()
        .get(header::LOCATION)
        .expect("failed callback redirects")
        .to_str()
        .expect("failed callback location is text");
    assert!(malformed_location.ends_with("&result=failed"));
    assert!(!malformed_location.contains("malformed-access-token-marker"));

    let failed = sqlx::query_as::<_, (i64, String, Option<i64>, Option<String>)>(
        "SELECT revision, status, current_secret_revision, error_code
         FROM oauth_connections WHERE id = ?",
    )
    .bind(&connection_id)
    .fetch_one(executor.app.pool())
    .await
    .expect("failed connection state reads");
    assert_eq!(failed.1, "pending_authorization");
    assert_eq!(failed.2, None);
    assert_eq!(failed.3.as_deref(), Some("oauth_scope_escalation"));
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT status FROM oauth_authorization_transactions
             WHERE connection_id = ? ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&connection_id)
        .fetch_one(executor.app.pool())
        .await
        .expect("failed authorization transaction reads"),
        "failed"
    );

    let retried = begin_and_complete_authorization(
        &executor,
        &admin,
        &connection_id,
        failed.0,
        "second-code",
    )
    .await;
    assert_eq!(retried.status(), StatusCode::SEE_OTHER);
    let retry_location = retried
        .headers()
        .get(header::LOCATION)
        .expect("successful callback redirects")
        .to_str()
        .expect("successful callback location is text");
    assert!(retry_location.ends_with("&result=success_refresh_failed"));

    let active = sqlx::query_as::<_, (String, Option<i64>, Option<String>)>(
        "SELECT status, current_secret_revision, error_code
         FROM oauth_connections WHERE id = ?",
    )
    .bind(&connection_id)
    .fetch_one(executor.app.pool())
    .await
    .expect("retried connection state reads");
    assert_eq!(active.0, "active");
    assert!(active.1.is_some());
    assert_eq!(active.2, None);
    assert_eq!(provider.token_requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn callback_catalog_refresh_failure_preserves_the_authorized_connection() {
    let provider = OAuthTestProvider::start().await;
    let executor = TestExecutor::new().await;
    let admin = executor.setup_and_login().await;
    executor
        .insert_source_at(&format!("{}/missing", provider.issuer), true)
        .await;
    let mutation_headers = [
        (header::COOKIE.as_str(), admin.cookie.as_str()),
        (header::ORIGIN.as_str(), ORIGIN),
        ("x-executor-csrf", admin.csrf.as_str()),
    ];
    let connection_input = |expected_revision, client_id: &str| {
        json!({
            "expectedRevision": expected_revision,
            "discovery": { "type": "issuer", "issuer": provider.issuer },
            "client": { "clientId": client_id, "authentication": "none" },
            "scopes": ["repo", "read:user"]
        })
    };

    let placeholder = send_json(
        executor.app.router(),
        Method::PUT,
        "/api/v1/sources/source-oauth-test/oauth/default",
        connection_input(0, "pending-dynamic-registration"),
        &mutation_headers,
    )
    .await;
    assert_eq!(placeholder.status(), StatusCode::OK);
    let placeholder = response_json(placeholder).await;
    let connection_id = placeholder["id"]
        .as_str()
        .expect("placeholder connection has ID")
        .to_owned();
    let callback_url = placeholder["callbackUrl"]
        .as_str()
        .expect("placeholder connection has callback URL");
    let client_id = provider.register_client(callback_url).await;

    let configured = send_json(
        executor.app.router(),
        Method::PUT,
        "/api/v1/sources/source-oauth-test/oauth/default",
        connection_input(
            placeholder["revision"]
                .as_i64()
                .expect("placeholder has revision"),
            &client_id,
        ),
        &mutation_headers,
    )
    .await;
    assert_eq!(configured.status(), StatusCode::OK);
    let configured = response_json(configured).await;
    let authorization = send_json(
        executor.app.router(),
        Method::POST,
        "/api/v1/sources/source-oauth-test/oauth/default/authorize",
        json!({
            "expectedRevision": configured["revision"]
                .as_i64()
                .expect("configured connection has revision")
        }),
        &mutation_headers,
    )
    .await;
    assert_eq!(authorization.status(), StatusCode::OK);
    let authorization = response_json(authorization).await;
    let provider_callback = provider
        .approve(
            authorization["authorizationUrl"]
                .as_str()
                .expect("authorization URL returns"),
        )
        .await;
    assert_eq!(provider_callback.origin().ascii_serialization(), ORIGIN);
    let callback_uri = provider_callback.query().map_or_else(
        || provider_callback.path().to_owned(),
        |query| format!("{}?{query}", provider_callback.path()),
    );

    let callback = send_empty(
        executor.app.router(),
        Method::GET,
        &callback_uri,
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        callback.headers().get(header::REFERRER_POLICY),
        Some(&header::HeaderValue::from_static("no-referrer"))
    );
    assert_eq!(
        callback.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    let redirect = Url::parse(
        callback
            .headers()
            .get(header::LOCATION)
            .expect("callback redirects")
            .to_str()
            .expect("callback redirect is text"),
    )
    .expect("callback redirect parses");
    assert_eq!(redirect.query_pairs().count(), 2);
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "oauth")
            .unwrap()
            .1,
        connection_id
    );
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "result")
            .unwrap()
            .1,
        "success_refresh_failed"
    );
    assert!(!redirect.as_str().contains("code="));
    assert!(!redirect.as_str().contains("state="));

    let listed = send_empty(
        executor.app.router(),
        Method::GET,
        "/api/v1/sources/source-oauth-test/oauth",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = response_json(listed).await;
    assert_eq!(listed["connections"][0]["id"], connection_id);
    assert_eq!(listed["connections"][0]["status"], "connected");
    assert!(listed["connections"][0]["authorizedAt"].is_i64());
    assert_eq!(listed["connections"][0]["errorCode"], Value::Null);

    let persisted = sqlx::query_as::<_, (String, Option<i64>, Option<String>)>(
        "SELECT status, authorized_at, error_code FROM oauth_connections WHERE id = ?",
    )
    .bind(&connection_id)
    .fetch_one(executor.app.pool())
    .await
    .expect("authorized connection persists");
    assert_eq!(persisted.0, "active");
    assert!(persisted.1.is_some());
    assert_eq!(persisted.2, None);
}

async fn begin_and_complete_authorization(
    executor: &TestExecutor,
    admin: &AdminSession,
    connection_id: &str,
    expected_revision: i64,
    code: &str,
) -> Response<Body> {
    let authorization = send_json(
        executor.app.router(),
        Method::POST,
        "/api/v1/sources/source-oauth-test/oauth/default/authorize",
        json!({ "expectedRevision": expected_revision }),
        &[
            (header::COOKIE.as_str(), admin.cookie.as_str()),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", admin.csrf.as_str()),
        ],
    )
    .await;
    assert_eq!(authorization.status(), StatusCode::OK);
    let authorization = response_json(authorization).await;
    let authorization_url = Url::parse(
        authorization["authorizationUrl"]
            .as_str()
            .expect("authorization URL returns"),
    )
    .expect("authorization URL parses");
    let state = authorization_url
        .query_pairs()
        .find(|(key, _)| key == "state")
        .expect("authorization URL has state")
        .1
        .into_owned();
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("state", &state).append_pair("code", code);
    let query = query.finish();
    send_empty(
        executor.app.router(),
        Method::GET,
        &format!("/api/v1/oauth/callback/{connection_id}?{query}"),
        &[(header::COOKIE.as_str(), admin.cookie.as_str())],
    )
    .await
}

async fn send_json(
    router: axum::Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> Response<Body> {
    send_raw(router, method, uri, Body::from(body.to_string()), headers).await
}

async fn send_empty(
    router: axum::Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
) -> Response<Body> {
    send_raw(router, method, uri, Body::empty(), headers).await
}

async fn send_raw(
    router: axum::Router,
    method: Method,
    uri: &str,
    body: Body,
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
        .oneshot(request.body(body).expect("request is valid"))
        .await
        .expect("router responds")
}

fn response_cookie_header(response: &Response<Body>) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie is text")
                .split(';')
                .next()
                .expect("cookie has value")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn response_json(response: Response<Body>) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collects")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("response is JSON")
}
