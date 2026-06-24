use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use executor::{AppConfig, ExecutorApp};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:4788";

struct Admin {
    cookie: String,
    csrf: String,
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

async fn create_gateway_token(app: &ExecutorApp, admin: &Admin) -> String {
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "approval strictness" }),
        &admin_headers(admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    json_body(response).await["token"]
        .as_str()
        .expect("token should be returned")
        .to_owned()
}

#[tokio::test]
async fn approval_endpoints_reject_unknown_body_fields_and_query_parameters() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup(&app).await;

    let response = send(
        app.router(),
        Method::GET,
        "/api/v1/approvals?limit=10&unexpected=true",
        json!(null),
        &[(header::COOKIE.as_str(), admin.cookie.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"]["code"], "invalid_query");

    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/approvals/missing/decision",
        json!({
            "decision": "approve",
            "expectedRevision": 0,
            "unexpected": true
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"]["code"], "invalid_json");

    let token = create_gateway_token(&app, &admin).await;
    let authorization = format!("Bearer {token}");
    let response = send(
        app.router(),
        Method::DELETE,
        "/api/v1/gateway/approvals/missing?expectedRevision=0&unexpected=true",
        json!(null),
        &[(header::AUTHORIZATION.as_str(), authorization.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(json_body(response).await["error"]["code"], "invalid_query");

    app.shutdown().await;
}
