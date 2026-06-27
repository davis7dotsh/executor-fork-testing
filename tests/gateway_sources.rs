use std::collections::BTreeMap;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use executor::{
    AppConfig, ExecutorApp,
    catalog::{
        AuditContext, CatalogSnapshot, CreateSource, SourceKind, StagedTool, StagedToolBinding,
        ToolBinding, ToolMode,
    },
    graphql::{GraphqlBindingV1, GraphqlOperation},
};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:4788";
const PASSWORD: &str = "correct horse battery staple";

struct AdminSession {
    cookie: String,
    csrf: String,
}

async fn send(
    router: Router,
    method: Method,
    uri: &str,
    body: Body,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    router
        .oneshot(request.body(body).expect("request should build"))
        .await
        .expect("router should answer")
}

async fn send_json(
    router: Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut headers = headers.to_vec();
    headers.push((header::CONTENT_TYPE.as_str(), "application/json"));
    send(router, method, uri, Body::from(body.to_string()), &headers).await
}

async fn response_json(response: Response<Body>) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response should collect")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("response should contain JSON")
}

fn response_cookies(response: &Response<Body>) -> String {
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

async fn setup_admin(app: &ExecutorApp) -> AdminSession {
    let response = send_json(
        app.router(),
        Method::POST,
        "/api/v1/setup",
        json!({
            "setupToken": app.setup_token().expect("fresh app should expose a setup token"),
            "username": "admin",
            "password": PASSWORD,
        }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = send_json(
        app.router(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": "admin", "password": PASSWORD }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response_cookies(&response);
    let csrf = response_json(response).await["csrfToken"]
        .as_str()
        .expect("login should return a CSRF token")
        .to_owned();
    AdminSession { cookie, csrf }
}

async fn create_gateway_token(app: &ExecutorApp, admin: &AdminSession) -> String {
    let response = send_json(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "Gateway source discovery" }),
        &[
            (header::COOKIE.as_str(), admin.cookie.as_str()),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", admin.csrf.as_str()),
            ("idempotency-key", "gateway-sources-token"),
        ],
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    response_json(response).await["token"]
        .as_str()
        .expect("token should be revealed once")
        .to_owned()
}

fn staged_tool(stable_key: &str, mode: ToolMode) -> StagedTool {
    StagedTool {
        stable_key: format!("graphql:v1:query:{stable_key}"),
        preferred_name: stable_key.to_owned(),
        display_name: stable_key.to_owned(),
        description: None,
        input_schema: json!({ "type": "object" }),
        output_schema: None,
        input_typescript: None,
        output_typescript: None,
        typescript_definitions: BTreeMap::new(),
        intrinsic_mode: mode,
    }
}

async fn create_source(
    app: &ExecutorApp,
    slug: &str,
    display_name: &str,
    description: Option<&str>,
    modes: &[ToolMode],
) {
    let source = app
        .catalog()
        .create_source(
            CreateSource {
                kind: SourceKind::Graphql,
                preferred_slug: slug.to_owned(),
                display_name: display_name.to_owned(),
                description: description.map(str::to_owned),
                configuration: Map::new(),
            },
            AuditContext::system(None),
        )
        .await
        .expect("source should be created");
    let tools = modes
        .iter()
        .enumerate()
        .map(|(index, mode)| staged_tool(&format!("tool_{index}"), *mode))
        .collect::<Vec<_>>();
    let bindings = tools
        .iter()
        .map(|tool| StagedToolBinding {
            stable_key: tool.stable_key.clone(),
            binding: ToolBinding::GraphqlV1(GraphqlBindingV1 {
                version: 1,
                operation: GraphqlOperation::Query,
                field_name: tool.preferred_name.clone(),
                operation_name: "ExecutorOperation".to_owned(),
                variables: Vec::new(),
                selection: Vec::new(),
                document: format!(
                    "query ExecutorOperation {{ result: {} }}",
                    tool.preferred_name
                ),
            }),
        })
        .collect();
    app.catalog()
        .sync_catalog_with_bindings(
            &source.id,
            CatalogSnapshot {
                expected_source_revision: source.revision,
                expected_credential_revision: None,
                artifacts: Vec::new(),
                tools,
            },
            bindings,
            AuditContext::system(None),
        )
        .await
        .expect("catalog should be synchronized");
}

#[tokio::test]
async fn gateway_sources_returns_only_the_exact_public_dto_for_callable_sources() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    let admin = setup_admin(&app).await;
    let token = create_gateway_token(&app, &admin).await;

    create_source(
        &app,
        "alpha",
        "Alpha API",
        Some("Enabled and approval-gated operations"),
        &[ToolMode::Enabled, ToolMode::Ask, ToolMode::Disabled],
    )
    .await;
    create_source(
        &app,
        "disabled_only",
        "Disabled API",
        Some("Must not be discoverable"),
        &[ToolMode::Disabled, ToolMode::Disabled],
    )
    .await;
    create_source(&app, "zulu", "Zulu API", None, &[ToolMode::Ask]).await;

    let authorization = format!("Bearer {token}");
    let response = send(
        app.router(),
        Method::GET,
        "/api/v1/gateway/sources",
        Body::empty(),
        &[(header::AUTHORIZATION.as_str(), authorization.as_str())],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await,
        json!({
            "sources": [
                {
                    "slug": "alpha",
                    "displayName": "Alpha API",
                    "description": "Enabled and approval-gated operations",
                    "kind": "graphql",
                    "toolCount": 2,
                },
                {
                    "slug": "zulu",
                    "displayName": "Zulu API",
                    "description": null,
                    "kind": "graphql",
                    "toolCount": 1,
                },
            ],
        })
    );

    app.shutdown().await;
}

#[tokio::test]
async fn gateway_sources_rejects_missing_authentication_before_catalog_work() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor should open");
    app.pool().close().await;

    let response = send(
        app.router(),
        Method::GET,
        "/api/v1/gateway/sources",
        Body::empty(),
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let request_id = response
        .headers()
        .get("x-request-id")
        .expect("authentication error should have a request ID")
        .to_str()
        .expect("request ID should be text")
        .to_owned();
    assert_eq!(
        response_json(response).await,
        json!({
            "error": {
                "code": "unauthorized",
                "message": "A valid Executor API token is required.",
                "requestId": request_id,
            },
        })
    );
}
