use std::fs;

use axum::{
    Router,
    body::{Body, Bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use executor::{AppConfig, ExecutorApp};
use http_body_util::BodyExt;
use tower::ServiceExt;

const PRIVATE_MARKER: &str = "executor-private-data-must-never-be-served-91d94a";

#[tokio::test]
async fn app_router_preserves_static_policy_and_keeps_protocol_paths_json() {
    let directory = tempfile::tempdir().expect("temporary data directory");
    let private_file = directory.path().join("private-marker");
    fs::write(&private_file, PRIVATE_MARKER).expect("private marker fixture is written");
    let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
        .await
        .expect("test Executor opens");
    let router = app.router();

    let asset = send(
        router.clone(),
        Method::GET,
        "/_app/immutable/entry/start.fixture.js?v=1",
    )
    .await;
    assert_eq!(asset.status(), StatusCode::OK);
    assert_eq!(
        asset.headers().get(header::CONTENT_TYPE),
        Some(&header::HeaderValue::from_static(
            "text/javascript; charset=utf-8"
        ))
    );
    assert_eq!(
        asset.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static(
            "public, max-age=31536000, immutable"
        ))
    );
    assert!(asset.headers().contains_key("x-request-id"));
    assert!(
        !body(asset)
            .await
            .windows(PRIVATE_MARKER.len())
            .any(|window| { window == PRIVATE_MARKER.as_bytes() })
    );

    let spa = send(router.clone(), Method::GET, "/tools/example?view=detail").await;
    assert_eq!(spa.status(), StatusCode::OK);
    assert_eq!(
        spa.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-cache"))
    );
    assert!(spa.headers().contains_key("x-request-id"));
    assert!(
        body(spa)
            .await
            .windows(16)
            .any(|window| window == b"Executor fixture")
    );

    for path in [
        "/api/v1/definitely-missing",
        "/mcp/definitely-missing",
        "/healthz/definitely-missing",
    ] {
        let response = send(router.clone(), Method::GET, path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&header::HeaderValue::from_static("no-store")),
            "{path}"
        );
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .is_some_and(|value| value.as_bytes().starts_with(b"application/json")),
            "{path}"
        );
        let bytes = body(response).await;
        assert!(
            !bytes
                .windows(16)
                .any(|window| window == b"Executor fixture"),
            "{path}"
        );
        assert!(
            !bytes
                .windows(PRIVATE_MARKER.len())
                .any(|window| window == PRIVATE_MARKER.as_bytes()),
            "{path}"
        );
    }

    for path in [
        "/.env",
        "/master.key",
        "/executor.db",
        "/%2e%2e/private-marker",
        "/%252e%252e%252fprivate-marker",
    ] {
        let response = send(router.clone(), Method::GET, path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        let bytes = body(response).await;
        assert!(
            !bytes
                .windows(PRIVATE_MARKER.len())
                .any(|window| window == PRIVATE_MARKER.as_bytes()),
            "{path} leaked a data-directory file"
        );
    }

    app.shutdown().await;
}

async fn send(router: Router, method: Method, uri: &str) -> Response<Body> {
    router
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .expect("test request is valid"),
        )
        .await
        .expect("router answers")
}

async fn body(response: Response<Body>) -> Bytes {
    response
        .into_body()
        .collect()
        .await
        .expect("response body collects")
        .to_bytes()
}
