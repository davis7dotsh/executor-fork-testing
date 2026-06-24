use axum::{
    body::Body,
    http::{Method, Request, Response, StatusCode, header},
};
use executor::{AppConfig, ExecutorApp};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ORIGIN: &str = "http://127.0.0.1:4788";

struct TestExecutor {
    app: ExecutorApp,
    setup_token: String,
}

struct AdminSession {
    cookie: String,
    csrf: String,
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
        sqlx::query(
            "INSERT INTO sources (
                id, kind, slug, display_name, configuration_json,
                revision, catalog_revision, created_at, updated_at
             ) VALUES (?, 'mcp_http', 'oauth_test', 'OAuth test', ?, 0, 0, 1, 1)",
        )
        .bind("source-oauth-test")
        .bind(
            json!({
                "endpoint": "https://api.example.test/mcp",
                "allowPrivateNetwork": false,
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
