use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::Response,
};
use percent_encoding::percent_decode_str;

struct EmbeddedAsset {
    path: &'static str,
    content: &'static [u8],
    etag: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/embedded_web_assets.rs"));

pub(crate) fn response(
    method: &Method,
    uri: &Uri,
    request_headers: &HeaderMap,
) -> Option<Response> {
    if !matches!(*method, Method::GET | Method::HEAD) {
        return None;
    }

    let path = normalized_path(uri.path())?;
    if is_reserved_path(&path) {
        return None;
    }

    let exact_asset = find_asset(&path);
    let (asset, spa_fallback) = match exact_asset {
        Some(asset) => (asset, false),
        None if can_use_spa_fallback(&path) => (find_asset("index.html")?, true),
        None => return None,
    };
    let etag = asset.etag;
    let not_modified = request_headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|values| {
            values
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == "*" || candidate == etag)
        });

    let mut response = if not_modified {
        Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .body(Body::empty())
            .expect("static response is valid")
    } else {
        let body = if *method == Method::HEAD {
            Body::empty()
        } else {
            Body::from(Bytes::from_static(asset.content))
        };
        let mut response = Response::new(body);
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&asset.content.len().to_string())
                .expect("asset lengths are valid headers"),
        );
        response
    };

    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type(asset.path)),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control(asset.path, spa_fallback)),
    );
    headers.insert(
        header::ETAG,
        HeaderValue::from_str(etag).expect("SHA-256 ETags are valid headers"),
    );
    add_security_headers(headers);
    Some(response)
}

fn normalized_path(path: &str) -> Option<String> {
    let raw_path = path.strip_prefix('/').unwrap_or(path);
    let lowercase = raw_path.to_ascii_lowercase();
    if lowercase.contains("%2f") || lowercase.contains("%5c") {
        return None;
    }
    let decoded = percent_decode_str(raw_path).decode_utf8().ok()?;
    if decoded.contains('\\') || decoded.contains('\0') || decoded.contains('%') {
        return None;
    }
    if decoded.is_empty() {
        return Some("index.html".to_owned());
    }

    let segments = decoded.split('/').collect::<Vec<_>>();
    if segments.iter().enumerate().any(|(index, segment)| {
        *segment == "." || *segment == ".." || (segment.is_empty() && index + 1 != segments.len())
    }) {
        return None;
    }
    Some(decoded.into_owned())
}

fn is_reserved_path(path: &str) -> bool {
    ["api", "mcp", "healthz"].iter().any(|prefix| {
        path == *prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn can_use_spa_fallback(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|segment| segment.is_empty() || !segment.contains('.'))
}

fn find_asset(path: &str) -> Option<&'static EmbeddedAsset> {
    EMBEDDED_WEB_ASSETS
        .binary_search_by_key(&path, |asset| asset.path)
        .ok()
        .map(|index| &EMBEDDED_WEB_ASSETS[index])
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("json" | "map") => "application/json; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("avif") => "image/avif",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml; charset=utf-8",
        Some("webmanifest") => "application/manifest+json; charset=utf-8",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn cache_control(path: &str, spa_fallback: bool) -> &'static str {
    if !spa_fallback && path.starts_with("_app/immutable/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

fn add_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(EMBEDDED_WEB_CSP),
    );
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), geolocation=(), microphone=()"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("same-origin"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use http_body_util::BodyExt;
    use sha2::{Digest, Sha256};

    use super::response;

    const FIXTURE_INDEX: &[u8] = include_bytes!("../tests/fixtures/web-assets/index.html");

    #[tokio::test]
    async fn serves_exact_assets_with_queries_and_immutable_cache_headers() {
        let response = response(
            &Method::GET,
            &"/_app/immutable/entry/start.fixture.js?v=1"
                .parse::<Uri>()
                .expect("valid URI"),
            &HeaderMap::new(),
        )
        .expect("fixture asset response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/javascript; charset=utf-8"))
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static(
                "public, max-age=31536000, immutable"
            ))
        );
        assert_eq!(
            response.headers().get("x-content-type-options"),
            Some(&HeaderValue::from_static("nosniff"))
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("asset body")
            .to_bytes();
        assert!(body.starts_with(b"document.documentElement"));
    }

    #[tokio::test]
    async fn head_reports_the_get_length_without_a_body() {
        let response = response(&Method::HEAD, &Uri::from_static("/"), &HeaderMap::new())
            .expect("fixture index response");
        let length = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .expect("content length")
            .clone();
        assert_ne!(length, HeaderValue::from_static("0"));
        assert!(
            response
                .into_body()
                .collect()
                .await
                .expect("HEAD body")
                .to_bytes()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn client_routes_use_the_index_fallback_and_ignore_queries() {
        let response = response(
            &Method::GET,
            &"/tools/example?view=detail"
                .parse::<Uri>()
                .expect("valid URI"),
            &HeaderMap::new(),
        )
        .expect("SPA response");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-cache"))
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("SPA body")
            .to_bytes();
        assert!(body.windows(16).any(|window| window == b"Executor fixture"));
    }

    #[test]
    fn leaves_reserved_paths_methods_missing_files_and_unsafe_paths_to_the_api_fallback() {
        for (method, path) in [
            (Method::GET, "/api/v1/missing"),
            (Method::GET, "/mcp/missing"),
            (Method::GET, "/healthz/missing"),
            (Method::POST, "/tools"),
            (Method::GET, "/missing.js"),
            (Method::GET, "/.env"),
            (Method::GET, "/_app/immutable/entry/start.fixture.js.map"),
            (Method::GET, "/%2e%2e/index.html"),
            (Method::GET, "/safe%2f..%2findex.html"),
            (Method::GET, "/%252e%252e/index.html"),
            (Method::GET, "/%252e%252e%252fsecret"),
        ] {
            assert!(
                response(
                    &method,
                    &path.parse::<Uri>().expect("valid test URI"),
                    &HeaderMap::new(),
                )
                .is_none(),
                "{method} {path} must not receive the SPA shell"
            );
        }
    }

    #[test]
    fn static_responses_include_browser_security_headers() {
        let response = response(&Method::GET, &Uri::from_static("/"), &HeaderMap::new())
            .expect("fixture index response");
        let headers = response.headers();

        assert_eq!(
            headers.get("x-content-type-options"),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            headers.get("x-frame-options"),
            Some(&HeaderValue::from_static("DENY"))
        );
        assert_eq!(
            headers.get("cross-origin-opener-policy"),
            Some(&HeaderValue::from_static("same-origin"))
        );
        assert_eq!(
            headers.get("cross-origin-resource-policy"),
            Some(&HeaderValue::from_static("same-origin"))
        );
        assert!(headers.contains_key("permissions-policy"));
        assert!(headers.contains_key("referrer-policy"));
        let csp = headers
            .get("content-security-policy")
            .expect("content security policy")
            .to_str()
            .expect("CSP is text");
        for directive in [
            "default-src 'none'",
            "base-uri 'none'",
            "connect-src 'self'",
            "font-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "img-src 'self' data:",
            "manifest-src 'self'",
            "object-src 'none'",
            "style-src 'self' 'unsafe-inline'",
            "worker-src 'self'",
        ] {
            assert!(
                csp.split("; ").any(|value| value == directive),
                "{directive}"
            );
        }
        let script_source = csp
            .split("; ")
            .find(|directive| directive.starts_with("script-src "))
            .expect("script source directive");
        let actual_hashes = script_source
            .split_ascii_whitespace()
            .skip(2)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_hashes, fixture_script_hashes());
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));
        assert!(!csp.contains("'unsafe-eval'"));
    }

    #[test]
    fn matching_etag_returns_not_modified() {
        let first = response(&Method::GET, &Uri::from_static("/"), &HeaderMap::new())
            .expect("initial response");
        let etag = first.headers().get(header::ETAG).expect("ETag").clone();
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_NONE_MATCH, etag);

        let response =
            response(&Method::GET, &Uri::from_static("/"), &headers).expect("conditional response");
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
    }

    #[test]
    fn etag_is_the_stable_build_time_digest_of_the_fixture() {
        let expected = HeaderValue::from_str(&format!("\"{:x}\"", Sha256::digest(FIXTURE_INDEX)))
            .expect("fixture digest is a valid ETag");
        for _ in 0..2 {
            let response = response(&Method::GET, &Uri::from_static("/"), &HeaderMap::new())
                .expect("fixture index response");
            assert_eq!(response.headers().get(header::ETAG), Some(&expected));
        }
    }

    fn fixture_script_hashes() -> BTreeSet<String> {
        let html = std::str::from_utf8(FIXTURE_INDEX).expect("fixture index is UTF-8");
        let mut remainder = html;
        let mut hashes = BTreeSet::new();
        while let Some(open) = remainder.find("<script") {
            let after_open = &remainder[open..];
            let body_start = after_open
                .find('>')
                .map(|position| position + 1)
                .expect("fixture script opener closes");
            let after_open = &after_open[body_start..];
            let body_end = after_open
                .find("</script>")
                .expect("fixture script body closes");
            let digest = STANDARD.encode(Sha256::digest(&after_open.as_bytes()[..body_end]));
            hashes.insert(format!("'sha256-{digest}'"));
            remainder = &after_open[body_end + "</script>".len()..];
        }
        assert!(
            !hashes.is_empty(),
            "fixture must exercise CSP script hashes"
        );
        hashes
    }
}
