use axum::{
    Json, Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
    routing::post,
};
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
async fn graphql_create_redacts_the_locator_and_query_tools_invoke() {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("GraphQL upstream binds");
    let address = upstream.local_addr().expect("upstream address reads");
    let upstream_router = Router::new().route(
        "/secret-path/graphql",
        post(|Json(request): Json<Value>| async move {
            if request["query"]
                .as_str()
                .is_some_and(|query| query.contains("__schema"))
            {
                Json(introspection())
            } else {
                Json(json!({ "data": { "result": "hello" } }))
            }
        }),
    );
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream, upstream_router)
            .await
            .expect("GraphQL upstream serves");
    });

    let directory = tempfile::tempdir().expect("temporary directory is created");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("Executor opens");
    let admin = setup(&app).await;
    let endpoint = format!("http://{address}/secret-path/graphql?token=query-secret");
    let response = send(
        app.router(),
        Method::POST,
        "/api/v1/sources",
        json!({
            "kind": "graphql",
            "displayName": "GraphQL test",
            "preferredSlug": "graphql-test",
            "endpoint": endpoint,
            "allowPrivateNetwork": true
        }),
        &admin_headers(&admin),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let source = body(response).await;
    assert_eq!(
        source["configuration"]["endpoint"],
        format!("http://{address}/")
    );
    let encoded_source = source.to_string();
    assert!(!encoded_source.contains("secret-path"));
    assert!(!encoded_source.contains("query-secret"));
    let source_slug = source["slug"]
        .as_str()
        .expect("created source has a slug")
        .to_owned();

    let tools = app
        .catalog()
        .list_tools(Default::default())
        .await
        .expect("GraphQL tools list");
    assert_eq!(tools.items.len(), 1);
    assert_eq!(tools.items[0].stable_key, "graphql:v1:query:hello");

    let token_response = send(
        app.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "GraphQL test" }),
        &[
            (header::COOKIE.as_str(), admin.cookie.as_str()),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", admin.csrf.as_str()),
            ("idempotency-key", "graphql-api-token"),
        ],
    )
    .await;
    let token = body(token_response).await["token"]
        .as_str()
        .expect("API token is returned")
        .to_owned();
    let authorization = format!("Bearer {token}");
    let invoked = send(
        app.router(),
        Method::POST,
        "/api/v1/gateway/tools/invoke",
        json!({ "path": format!("{source_slug}.hello"), "arguments": {} }),
        &[(header::AUTHORIZATION.as_str(), authorization.as_str())],
    )
    .await;
    assert_eq!(invoked.status(), StatusCode::OK);
    let invoked = body(invoked).await;
    assert_eq!(invoked["ok"], true);
    assert_eq!(invoked["data"], "hello");

    app.shutdown().await;
    upstream_task.abort();
}

fn introspection() -> Value {
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

async fn setup(app: &ExecutorApp) -> Admin {
    let setup_token = app.setup_token().expect("fresh instance has a setup token");
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
    let cookie = response
        .headers()
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
    let csrf = body(response).await["csrfToken"]
        .as_str()
        .expect("login returns CSRF")
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
                .expect("request builds"),
        )
        .await
        .expect("router answers")
}

async fn body(response: axum::response::Response) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response collects")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("response contains JSON")
}
