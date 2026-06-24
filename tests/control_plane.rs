use std::{fs, net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, Response, StatusCode, header},
};
use executor::{
    AppConfig, DatabaseError, ExecutorApp,
    catalog::{RequestOutcome, RequestSurface},
};
use http_body_util::BodyExt;
use ipnet::IpNet;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const ORIGIN: &str = "http://127.0.0.1:4788";
const PASSWORD: &str = "correct-horse-battery-staple";

struct TestExecutor {
    _directory: TempDir,
    app: Arc<ExecutorApp>,
}

struct AdminSession {
    cookie: String,
    csrf: String,
}

impl TestExecutor {
    async fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test Executor should open");
        Self {
            _directory: directory,
            app: Arc::new(app),
        }
    }

    async fn with_trusted_proxies(networks: &[&str]) -> Self {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let trusted_proxies = networks
            .iter()
            .map(|network| {
                network
                    .parse::<IpNet>()
                    .expect("trusted proxy network should parse")
            })
            .collect();
        let app = ExecutorApp::open(
            AppConfig::new(directory.path().to_path_buf()).with_trusted_proxies(trusted_proxies),
        )
        .await
        .expect("test Executor should open");
        Self {
            _directory: directory,
            app: Arc::new(app),
        }
    }

    fn router(&self) -> Router {
        self.app.router()
    }

    fn setup_token(&self) -> String {
        self.app
            .setup_token()
            .expect("fresh test app should issue a setup token")
            .to_owned()
    }

    async fn setup_admin(&self) {
        let response = send_json(
            self.router(),
            Method::POST,
            "/api/v1/setup",
            json!({
                "setupToken": self.setup_token(),
                "username": "admin",
                "password": PASSWORD
            }),
            &[(header::ORIGIN.as_str(), ORIGIN)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    async fn login(&self) -> AdminSession {
        let response = send_json(
            self.router(),
            Method::POST,
            "/api/v1/session",
            json!({ "username": "admin", "password": PASSWORD }),
            &[(header::ORIGIN.as_str(), ORIGIN)],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response_cookie_header(&response);
        let body = response_json(response).await;
        let csrf = body["csrfToken"]
            .as_str()
            .expect("login should reveal a CSRF token")
            .to_owned();
        AdminSession { cookie, csrf }
    }
}

#[tokio::test]
async fn migrations_and_sqlite_safety_pragmas_are_active() {
    let executor = TestExecutor::new().await;
    let table_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN \
         ('instance_metadata', 'setup_state', 'admins', 'admin_sessions', 'api_tokens')",
    )
    .fetch_one(executor.app.pool())
    .await
    .expect("schema query should succeed");
    assert_eq!(table_count, 5);

    let foreign_keys = sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys")
        .fetch_one(executor.app.pool())
        .await
        .expect("foreign_keys pragma should be readable");
    let journal_mode = sqlx::query_scalar::<_, String>("PRAGMA journal_mode")
        .fetch_one(executor.app.pool())
        .await
        .expect("journal mode should be readable");
    let synchronous = sqlx::query_scalar::<_, i64>("PRAGMA synchronous")
        .fetch_one(executor.app.pool())
        .await
        .expect("synchronous pragma should be readable");
    assert_eq!(foreign_keys, 1);
    assert_eq!(journal_mode, "wal");
    assert_eq!(synchronous, 2);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let directory_mode = fs::metadata(executor._directory.path())
            .expect("data directory metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        let key_mode = fs::metadata(executor._directory.path().join("master.key"))
            .expect("master key metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        let database_mode = fs::metadata(executor._directory.path().join("executor.db"))
            .expect("database metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        let lock_mode = fs::metadata(executor._directory.path().join("executor.lock"))
            .expect("lock metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(key_mode, 0o600);
        assert_eq!(database_mode, 0o600);
        assert_eq!(lock_mode, 0o600);
    }
}

#[tokio::test]
async fn one_process_holds_the_data_directory_lock_for_its_lifetime() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let config = AppConfig::new(directory.path().to_path_buf());
    let first = ExecutorApp::open(config.clone())
        .await
        .expect("first process should acquire the lock");
    let Err(error) = ExecutorApp::open(config.clone()).await else {
        panic!("a second process must not acquire the same data directory");
    };
    assert!(matches!(error, DatabaseError::AlreadyRunning(_)));

    first.pool().close().await;
    drop(first);
    let reopened = ExecutorApp::open(config)
        .await
        .expect("dropping the app should release the lock");
    reopened.pool().close().await;
}

#[tokio::test]
async fn initialized_database_fails_closed_for_missing_or_wrong_keys() {
    let missing_key_directory = tempfile::tempdir().expect("temporary directory should be created");
    let missing_config = AppConfig::new(missing_key_directory.path().to_path_buf());
    let missing_app = ExecutorApp::open(missing_config.clone())
        .await
        .expect("initial open should succeed");
    missing_app.pool().close().await;
    drop(missing_app);
    fs::remove_file(missing_key_directory.path().join("master.key"))
        .expect("master key should be removable in the test");
    let Err(missing_error) = ExecutorApp::open(missing_config).await else {
        panic!("missing key must fail closed");
    };
    assert!(matches!(
        missing_error,
        DatabaseError::Crypto(executor::crypto::CryptoError::MissingMasterKey(_))
    ));

    let wrong_key_directory = tempfile::tempdir().expect("temporary directory should be created");
    let wrong_config = AppConfig::new(wrong_key_directory.path().to_path_buf());
    let wrong_app = ExecutorApp::open(wrong_config.clone())
        .await
        .expect("initial open should succeed");
    wrong_app.pool().close().await;
    drop(wrong_app);
    fs::write(wrong_key_directory.path().join("master.key"), [9_u8; 32])
        .expect("test should replace the key");
    let Err(wrong_error) = ExecutorApp::open(wrong_config).await else {
        panic!("wrong key must fail closed");
    };
    assert!(matches!(wrong_error, DatabaseError::InvalidBootSentinel));
}

#[tokio::test]
async fn tampered_boot_sentinel_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let config = AppConfig::new(directory.path().to_path_buf());
    let app = ExecutorApp::open(config.clone())
        .await
        .expect("initial open should succeed");
    let mut sentinel = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT value FROM instance_metadata WHERE key = 'boot_sentinel'",
    )
    .fetch_one(app.pool())
    .await
    .expect("sentinel should exist");
    let last = sentinel.len() - 1;
    sentinel[last] ^= 0x01;
    sqlx::query("UPDATE instance_metadata SET value = ? WHERE key = 'boot_sentinel'")
        .bind(sentinel)
        .execute(app.pool())
        .await
        .expect("sentinel should be updateable in the test");
    app.pool().close().await;
    drop(app);

    let Err(error) = ExecutorApp::open(config).await else {
        panic!("tampered sentinel must fail closed");
    };
    assert!(matches!(error, DatabaseError::InvalidBootSentinel));
}

#[tokio::test]
async fn interrupted_empty_initialization_recreates_the_boot_sentinel() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let config = AppConfig::new(directory.path().to_path_buf());
    let app = ExecutorApp::open(config.clone())
        .await
        .expect("initial open should succeed");
    sqlx::query("DELETE FROM setup_state")
        .execute(app.pool())
        .await
        .expect("test should remove setup state");
    sqlx::query("DELETE FROM instance_metadata WHERE key = 'boot_sentinel'")
        .execute(app.pool())
        .await
        .expect("test should remove the sentinel");
    app.pool().close().await;
    drop(app);

    let recovered = ExecutorApp::open(config)
        .await
        .expect("empty post-migration state should recover");
    assert!(recovered.setup_token().is_some());
    let sentinel_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM instance_metadata WHERE key = 'boot_sentinel'",
    )
    .fetch_one(recovered.pool())
    .await
    .expect("sentinel should be readable");
    assert_eq!(sentinel_count, 1);
}

#[tokio::test]
async fn missing_sentinel_with_application_state_still_fails_closed() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let config = AppConfig::new(directory.path().to_path_buf());
    let app = ExecutorApp::open(config.clone())
        .await
        .expect("initial open should succeed");
    sqlx::query("DELETE FROM instance_metadata WHERE key = 'boot_sentinel'")
        .execute(app.pool())
        .await
        .expect("test should remove the sentinel");
    app.pool().close().await;
    drop(app);

    let Err(error) = ExecutorApp::open(config).await else {
        panic!("setup state without a sentinel must fail closed");
    };
    assert!(matches!(error, DatabaseError::MissingBootSentinel));
}

#[tokio::test]
async fn expired_setup_tokens_are_rejected_before_password_work() {
    let executor = TestExecutor::new().await;
    sqlx::query("UPDATE setup_state SET created_at = 0 WHERE id = 1")
        .execute(executor.app.pool())
        .await
        .expect("test should expire the setup token");
    let response = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/setup",
        json!({
            "setupToken": executor.setup_token(),
            "username": "admin",
            "password": PASSWORD
        }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;

    assert_error(response, StatusCode::UNAUTHORIZED, "unauthorized").await;
}

#[tokio::test]
async fn concurrent_setup_claims_create_exactly_one_admin() {
    let executor = TestExecutor::new().await;
    let token = executor.setup_token();
    let first_headers = [(header::ORIGIN.as_str(), ORIGIN)];
    let second_headers = [(header::ORIGIN.as_str(), ORIGIN)];
    let first = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/setup",
        json!({ "setupToken": token, "username": "first", "password": PASSWORD }),
        &first_headers,
    );
    let second = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/setup",
        json!({ "setupToken": executor.setup_token(), "username": "second", "password": PASSWORD }),
        &second_headers,
    );
    let (first_response, second_response) = tokio::join!(first, second);
    let mut statuses = [first_response.status(), second_response.status()];
    statuses.sort_by_key(|status| status.as_u16());
    assert_eq!(statuses, [StatusCode::CREATED, StatusCode::CONFLICT]);

    let admin_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM admins")
        .fetch_one(executor.app.pool())
        .await
        .expect("admin count should be readable");
    assert_eq!(admin_count, 1);
}

#[tokio::test]
async fn sessions_enforce_cookie_csrf_origin_and_logout() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let admin = executor.login().await;

    let session_response = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/session",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(session_response.status(), StatusCode::OK);

    let missing_origin = create_token_request(&executor, &admin, None, Some(&admin.csrf)).await;
    assert_error(missing_origin, StatusCode::FORBIDDEN, "invalid_origin").await;

    let wrong_origin = create_token_request(
        &executor,
        &admin,
        Some("https://attacker.invalid"),
        Some(&admin.csrf),
    )
    .await;
    assert_error(wrong_origin, StatusCode::FORBIDDEN, "invalid_origin").await;

    let missing_csrf = create_token_request(&executor, &admin, Some(ORIGIN), None).await;
    assert_error(missing_csrf, StatusCode::FORBIDDEN, "invalid_csrf").await;

    let wrong_csrf =
        create_token_request(&executor, &admin, Some(ORIGIN), Some("csrf_wrong")).await;
    assert_error(wrong_csrf, StatusCode::FORBIDDEN, "invalid_csrf").await;

    let created = create_token_request(&executor, &admin, Some(ORIGIN), Some(&admin.csrf)).await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let logout = send_empty(
        executor.router(),
        Method::DELETE,
        "/api/v1/session",
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);

    let after_logout = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/session",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_error(after_logout, StatusCode::UNAUTHORIZED, "unauthorized").await;
}

#[tokio::test]
async fn usernames_are_trimmed_and_credential_fields_are_bounded() {
    let executor = TestExecutor::new().await;
    let setup = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/setup",
        json!({
            "setupToken": executor.setup_token(),
            "username": "  admin  ",
            "password": PASSWORD
        }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(setup.status(), StatusCode::CREATED);
    let stored_username =
        sqlx::query_scalar::<_, String>("SELECT username FROM admins WHERE id = 1")
            .fetch_one(executor.app.pool())
            .await
            .expect("admin should be stored");
    assert_eq!(stored_username, "admin");

    let login = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": " admin ", "password": PASSWORD }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);

    let oversized_password = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": "admin", "password": "x".repeat(1025) }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_error(
        oversized_password,
        StatusCode::BAD_REQUEST,
        "invalid_password",
    )
    .await;

    let oversized_username = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": "x".repeat(65), "password": PASSWORD }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_error(
        oversized_username,
        StatusCode::BAD_REQUEST,
        "invalid_username",
    )
    .await;
}

#[tokio::test]
async fn https_public_origins_produce_secure_session_cookies() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let app = ExecutorApp::open(
        AppConfig::new(directory.path().to_path_buf())
            .with_origin("https://executor.example.com")
            .expect("HTTPS origin should be valid"),
    )
    .await
    .expect("test Executor should open");
    let setup = send_json(
        app.router(),
        Method::POST,
        "/api/v1/setup",
        json!({
            "setupToken": app.setup_token().expect("setup token should exist"),
            "username": "admin",
            "password": PASSWORD
        }),
        &[(header::ORIGIN.as_str(), "https://executor.example.com")],
    )
    .await;
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = send_json(
        app.router(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": "admin", "password": PASSWORD }),
        &[(header::ORIGIN.as_str(), "https://executor.example.com")],
    )
    .await;
    assert_eq!(login.status(), StatusCode::OK);
    assert!(
        login
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|value| {
                value
                    .to_str()
                    .expect("set-cookie should be text")
                    .contains("Secure")
            })
    );
}

#[tokio::test]
async fn password_work_is_non_waiting_and_bounded() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let headers = [(header::ORIGIN.as_str(), ORIGIN)];
    let login_body = json!({ "username": "missing", "password": PASSWORD });
    let first = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/session",
        login_body.clone(),
        &headers,
    );
    let second = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/session",
        login_body.clone(),
        &headers,
    );
    let third = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/session",
        login_body.clone(),
        &headers,
    );
    let fourth = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/session",
        login_body,
        &headers,
    );
    let responses = tokio::join!(first, second, third, fourth);
    let statuses = [
        responses.0.status(),
        responses.1.status(),
        responses.2.status(),
        responses.3.status(),
    ];
    assert!(statuses.contains(&StatusCode::TOO_MANY_REQUESTS));
    assert!(statuses.iter().all(|status| {
        matches!(
            *status,
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
        )
    }));
}

#[tokio::test]
async fn login_rate_limit_uses_peer_ip_and_ignores_forwarded_headers() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let first_peer_ip = "192.0.2.10";

    for attempt in 0..5 {
        let peer: SocketAddr = format!("{first_peer_ip}:{}", 4100 + attempt)
            .parse()
            .expect("peer address should parse");
        let forwarded = format!("203.0.113.{}", attempt + 1);
        let response = send_json_from(
            executor.router(),
            peer,
            Method::POST,
            "/api/v1/session",
            json!({ "username": format!("missing-{attempt}"), "password": PASSWORD }),
            &[
                (header::ORIGIN.as_str(), ORIGIN),
                ("x-forwarded-for", &forwarded),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let limited_peer: SocketAddr = format!("{first_peer_ip}:4200")
        .parse()
        .expect("peer address should parse");
    let limited = send_json_from(
        executor.router(),
        limited_peer,
        Method::POST,
        "/api/v1/session",
        json!({ "username": "another-missing-user", "password": PASSWORD }),
        &[
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-forwarded-for", "198.51.100.200"),
        ],
    )
    .await;
    let retry_after = limited
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    assert!(retry_after.is_some_and(|seconds| seconds > 0));
    assert_error(limited, StatusCode::TOO_MANY_REQUESTS, "login_rate_limited").await;

    let second_peer: SocketAddr = "192.0.2.11:4100"
        .parse()
        .expect("peer address should parse");
    let independent = send_json_from(
        executor.router(),
        second_peer,
        Method::POST,
        "/api/v1/session",
        json!({ "username": "missing", "password": PASSWORD }),
        &[
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-forwarded-for", first_peer_ip),
        ],
    )
    .await;
    assert_eq!(independent.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn trusted_proxy_separates_clients_and_avoids_proxy_wide_lockout() {
    let executor = TestExecutor::with_trusted_proxies(&["10.0.0.0/8"]).await;
    executor.setup_admin().await;
    let proxy: SocketAddr = "10.20.30.40:443"
        .parse()
        .expect("proxy address should parse");

    for attempt in 0..5 {
        let response = send_json_from(
            executor.router(),
            proxy,
            Method::POST,
            "/api/v1/session",
            json!({ "username": format!("missing-{attempt}"), "password": PASSWORD }),
            &[
                (header::ORIGIN.as_str(), ORIGIN),
                ("x-forwarded-for", "203.0.113.10"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let limited = send_json_from(
        executor.router(),
        proxy,
        Method::POST,
        "/api/v1/session",
        json!({ "username": "still-missing", "password": PASSWORD }),
        &[
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-forwarded-for", "203.0.113.10"),
        ],
    )
    .await;
    assert_error(limited, StatusCode::TOO_MANY_REQUESTS, "login_rate_limited").await;

    let independent_client = send_json_from(
        executor.router(),
        proxy,
        Method::POST,
        "/api/v1/session",
        json!({ "username": "another-client", "password": PASSWORD }),
        &[
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-forwarded-for", "203.0.113.11"),
        ],
    )
    .await;
    assert_eq!(independent_client.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn trusted_proxy_chain_walks_right_to_left_and_stops_at_the_client() {
    let executor = TestExecutor::with_trusted_proxies(&["10.0.0.0/8", "192.168.0.0/16"]).await;
    executor.setup_admin().await;
    let edge_proxy: SocketAddr = "10.0.0.5:443".parse().expect("proxy address should parse");

    for attempt in 0..5 {
        let forwarded = format!("not-an-ip-{}, 203.0.113.20, 192.168.1.10", attempt + 1);
        let response = send_json_from(
            executor.router(),
            edge_proxy,
            Method::POST,
            "/api/v1/session",
            json!({ "username": format!("missing-{attempt}"), "password": PASSWORD }),
            &[
                (header::ORIGIN.as_str(), ORIGIN),
                ("x-forwarded-for", &forwarded),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let limited = send_json_from(
        executor.router(),
        edge_proxy,
        Method::POST,
        "/api/v1/session",
        json!({ "username": "still-missing", "password": PASSWORD }),
        &[
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-forwarded-for", "not-an-ip, 203.0.113.20, 192.168.1.10"),
        ],
    )
    .await;
    assert_error(limited, StatusCode::TOO_MANY_REQUESTS, "login_rate_limited").await;

    let independent_client = send_json_from(
        executor.router(),
        edge_proxy,
        Method::POST,
        "/api/v1/session",
        json!({ "username": "another-client", "password": PASSWORD }),
        &[
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-forwarded-for", "not-an-ip, 203.0.113.21, 192.168.1.10"),
        ],
    )
    .await;
    assert_eq!(independent_client.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_forwarded_chains_are_rejected_without_proxy_lockout() {
    let executor = TestExecutor::with_trusted_proxies(&["10.0.0.0/8"]).await;
    executor.setup_admin().await;
    let proxy: SocketAddr = "10.0.0.8:443".parse().expect("proxy address should parse");

    for attempt in 0..6 {
        let malformed = format!("203.0.113.{}, not-an-ip", attempt + 1);
        let response = send_json_from(
            executor.router(),
            proxy,
            Method::POST,
            "/api/v1/session",
            json!({ "username": format!("missing-{attempt}"), "password": PASSWORD }),
            &[
                (header::ORIGIN.as_str(), ORIGIN),
                ("x-forwarded-for", &malformed),
            ],
        )
        .await;
        assert_error(response, StatusCode::UNAUTHORIZED, "unauthorized").await;
    }

    let missing = send_json_from(
        executor.router(),
        proxy,
        Method::POST,
        "/api/v1/session",
        json!({ "username": "missing-header", "password": PASSWORD }),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;
    assert_error(missing, StatusCode::UNAUTHORIZED, "unauthorized").await;

    let all_trusted = send_json_from(
        executor.router(),
        proxy,
        Method::POST,
        "/api/v1/session",
        json!({ "username": "all-trusted", "password": PASSWORD }),
        &[
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-forwarded-for", "10.0.0.9"),
        ],
    )
    .await;
    assert_error(all_trusted, StatusCode::UNAUTHORIZED, "unauthorized").await;

    let valid_client = send_json_from(
        executor.router(),
        proxy,
        Method::POST,
        "/api/v1/session",
        json!({ "username": "valid-client", "password": PASSWORD }),
        &[
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-forwarded-for", "203.0.113.100"),
        ],
    )
    .await;
    assert_eq!(valid_client.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn successful_login_clears_the_in_process_rate_limit_window() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let headers = [(header::ORIGIN.as_str(), ORIGIN)];

    for attempt in 0..4 {
        let response = send_json(
            executor.router(),
            Method::POST,
            "/api/v1/session",
            json!({ "username": format!("missing-{attempt}"), "password": PASSWORD }),
            &headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let success = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": "admin", "password": PASSWORD }),
        &headers,
    )
    .await;
    assert_eq!(success.status(), StatusCode::OK);

    let after_success = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/session",
        json!({ "username": "missing-again", "password": PASSWORD }),
        &headers,
    )
    .await;
    assert_eq!(after_success.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oversized_api_bodies_are_rejected_with_the_stable_envelope() {
    let executor = TestExecutor::new().await;
    let response = send_raw(
        executor.router(),
        Method::POST,
        "/api/v1/setup",
        format!("{{\"padding\":\"{}\"}}", "x".repeat(17 * 1024)),
        &[(header::ORIGIN.as_str(), ORIGIN)],
    )
    .await;

    assert_error(response, StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large").await;
}

#[tokio::test]
async fn session_database_failures_are_internal_errors_not_logged_out_states() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let admin = executor.login().await;
    executor.app.pool().close().await;

    let response = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/session",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_error(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
    )
    .await;
}

#[tokio::test]
async fn api_tokens_are_revealed_once_revocable_and_gateway_only() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let admin = executor.login().await;
    let created = create_token_request(&executor, &admin, Some(ORIGIN), Some(&admin.csrf)).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body = response_json(created).await;
    let token = created_body["token"]
        .as_str()
        .expect("create should reveal the token")
        .to_owned();
    let token_id = created_body["id"]
        .as_str()
        .expect("create should return the ID")
        .to_owned();

    let listed = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/tokens",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed_body = response_json(listed).await;
    assert_eq!(listed_body["tokens"].as_array().map(Vec::len), Some(1));
    assert!(listed_body.to_string().contains("maskedToken"));
    assert!(!listed_body.to_string().contains(&token));

    let gateway = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/gateway/whoami",
        &[(header::AUTHORIZATION.as_str(), &format!("bEaReR {token}"))],
    )
    .await;
    assert_eq!(gateway.status(), StatusCode::OK);
    let gateway_body = response_json(gateway).await;
    assert_eq!(gateway_body["tokenId"], token_id);
    let mut last_used = None;
    for _ in 0..100 {
        last_used = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_used_at FROM api_tokens WHERE id = ?",
        )
        .bind(&token_id)
        .fetch_one(executor.app.pool())
        .await
        .expect("last-used timestamp should be readable");
        if last_used.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(last_used.is_some());

    let bearer_on_control_plane = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/tokens",
        &[(header::AUTHORIZATION.as_str(), &format!("Bearer {token}"))],
    )
    .await;
    assert_error(
        bearer_on_control_plane,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    )
    .await;

    let revoke = send_empty(
        executor.router(),
        Method::DELETE,
        &format!("/api/v1/tokens/{token_id}"),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(revoke.status(), StatusCode::NO_CONTENT);

    let revoked_gateway = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/gateway/whoami",
        &[(header::AUTHORIZATION.as_str(), &format!("Bearer {token}"))],
    )
    .await;
    assert_error(revoked_gateway, StatusCode::UNAUTHORIZED, "unauthorized").await;
}

#[tokio::test]
async fn gateway_request_logging_does_not_wait_for_the_sqlite_writer() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let admin = executor.login().await;
    let created = create_token_request(&executor, &admin, Some(ORIGIN), Some(&admin.csrf)).await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_body = response_json(created).await;
    let token = created_body["token"]
        .as_str()
        .expect("create should reveal the token")
        .to_owned();
    let token_id = created_body["id"]
        .as_str()
        .expect("create should return the token ID")
        .to_owned();

    let mut writer = executor
        .app
        .pool()
        .acquire()
        .await
        .expect("test writer connection should be acquired");
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *writer)
        .await
        .expect("test writer should hold the SQLite write lock");

    let authorization = format!("Bearer {token}");
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        send_json(
            executor.router(),
            Method::POST,
            "/api/v1/gateway/tools/search",
            json!({ "query": "nothing" }),
            &[(header::AUTHORIZATION.as_str(), &authorization)],
        ),
    )
    .await
    .expect("gateway reads must return without waiting for request-log persistence");
    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response
        .headers()
        .get("x-request-id")
        .expect("gateway response should have a request ID")
        .to_str()
        .expect("request ID should be text")
        .to_owned();

    sqlx::query("COMMIT")
        .execute(&mut *writer)
        .await
        .expect("test writer should release the SQLite write lock");
    drop(writer);

    let stored = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if let Ok(stored) = executor.app.catalog().request_log(&request_id).await {
                break stored;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("queued request log should persist after writer contention clears");
    assert_eq!(
        stored.actor_api_token_id.as_deref(),
        Some(token_id.as_str())
    );
    assert_eq!(stored.surface, RequestSurface::Gateway);
    assert_eq!(stored.path_snapshot.as_deref(), Some("tools.search"));
    assert_eq!(stored.outcome, RequestOutcome::Succeeded);
}

#[tokio::test]
async fn token_last_used_retries_after_write_slot_contention() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let admin = executor.login().await;

    let first_created =
        create_token_request(&executor, &admin, Some(ORIGIN), Some(&admin.csrf)).await;
    assert_eq!(first_created.status(), StatusCode::CREATED);
    let first_body = response_json(first_created).await;
    let first_token = first_body["token"]
        .as_str()
        .expect("first token should be revealed")
        .to_owned();
    let first_token_id = first_body["id"]
        .as_str()
        .expect("first token ID should be returned")
        .to_owned();

    let second_created =
        create_token_request(&executor, &admin, Some(ORIGIN), Some(&admin.csrf)).await;
    assert_eq!(second_created.status(), StatusCode::CREATED);
    let second_body = response_json(second_created).await;
    let second_token = second_body["token"]
        .as_str()
        .expect("second token should be revealed")
        .to_owned();
    let second_token_id = second_body["id"]
        .as_str()
        .expect("second token ID should be returned")
        .to_owned();

    let mut writer = executor
        .app
        .pool()
        .acquire()
        .await
        .expect("test writer connection should be acquired");
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *writer)
        .await
        .expect("test writer should hold the SQLite write lock");

    let first_gateway = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/gateway/whoami",
        &[(
            header::AUTHORIZATION.as_str(),
            &format!("Bearer {first_token}"),
        )],
    )
    .await;
    assert_eq!(first_gateway.status(), StatusCode::OK);

    let mut telemetry_writer_started = false;
    for _ in 0..100 {
        let checked_out_connections =
            executor.app.pool().size() as usize - executor.app.pool().num_idle();
        if checked_out_connections >= 2 {
            telemetry_writer_started = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(telemetry_writer_started);

    let contended_gateway = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/gateway/whoami",
        &[(
            header::AUTHORIZATION.as_str(),
            &format!("Bearer {second_token}"),
        )],
    )
    .await;
    assert_eq!(contended_gateway.status(), StatusCode::OK);

    sqlx::query("COMMIT")
        .execute(&mut *writer)
        .await
        .expect("test writer should release the SQLite write lock");
    drop(writer);

    let mut first_last_used = None;
    for _ in 0..100 {
        first_last_used = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_used_at FROM api_tokens WHERE id = ?",
        )
        .bind(&first_token_id)
        .fetch_one(executor.app.pool())
        .await
        .expect("first token last-used timestamp should be readable");
        if first_last_used.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(first_last_used.is_some());

    let retry_gateway = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/gateway/whoami",
        &[(
            header::AUTHORIZATION.as_str(),
            &format!("Bearer {second_token}"),
        )],
    )
    .await;
    assert_eq!(retry_gateway.status(), StatusCode::OK);

    let mut second_last_used = None;
    for _ in 0..100 {
        second_last_used = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_used_at FROM api_tokens WHERE id = ?",
        )
        .bind(&second_token_id)
        .fetch_one(executor.app.pool())
        .await
        .expect("second token last-used timestamp should be readable");
        if second_last_used.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(second_last_used.is_some());
}

#[tokio::test]
async fn token_names_are_counted_by_characters_and_stored_trimmed() {
    let executor = TestExecutor::new().await;
    executor.setup_admin().await;
    let admin = executor.login().await;
    let unicode_name = "é".repeat(80);
    let created = send_json(
        executor.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": format!("  {unicode_name}  ") }),
        &[
            (header::COOKIE.as_str(), &admin.cookie),
            (header::ORIGIN.as_str(), ORIGIN),
            ("x-executor-csrf", &admin.csrf),
        ],
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = response_json(created).await;
    assert_eq!(body["name"], unicode_name);
}

#[tokio::test]
async fn health_bootstrap_and_errors_have_stable_shapes() {
    let executor = TestExecutor::new().await;
    let health = send_empty(executor.router(), Method::GET, "/healthz", &[]).await;
    assert_eq!(health.status(), StatusCode::OK);
    assert!(health.headers().contains_key("x-request-id"));
    assert_eq!(response_json(health).await, json!({ "status": "ok" }));

    let health_method_mismatch = send_empty(executor.router(), Method::POST, "/healthz", &[]).await;
    assert_error(
        health_method_mismatch,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    )
    .await;

    let before = send_empty(executor.router(), Method::GET, "/api/v1/bootstrap", &[]).await;
    assert_eq!(
        response_json(before).await,
        json!({ "setupRequired": true, "authenticated": false })
    );

    executor.setup_admin().await;
    let admin = executor.login().await;
    let after = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/bootstrap",
        &[(header::COOKIE.as_str(), &admin.cookie)],
    )
    .await;
    assert_eq!(
        response_json(after).await,
        json!({ "setupRequired": false, "authenticated": true })
    );

    let missing = send_empty(executor.router(), Method::GET, "/missing", &[]).await;
    assert_error(missing, StatusCode::NOT_FOUND, "not_found").await;
}

#[tokio::test]
async fn catalog_route_rejections_have_stable_error_envelopes() {
    let executor = TestExecutor::new().await;

    let method_mismatch = send_empty(executor.router(), Method::POST, "/api/v1/tools", &[]).await;
    assert_error(
        method_mismatch,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    )
    .await;

    executor.setup_admin().await;
    let admin = executor.login().await;
    let headers = [(header::COOKIE.as_str(), admin.cookie.as_str())];

    let invalid_query = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/tools?limit=not-a-number",
        &headers,
    )
    .await;
    assert_error(invalid_query, StatusCode::BAD_REQUEST, "invalid_query").await;

    let invalid_path = send_empty(
        executor.router(),
        Method::GET,
        "/api/v1/tools/%FF",
        &headers,
    )
    .await;
    assert_error(invalid_path, StatusCode::BAD_REQUEST, "invalid_path").await;
}

async fn create_token_request(
    executor: &TestExecutor,
    admin: &AdminSession,
    origin: Option<&str>,
    csrf: Option<&str>,
) -> Response<Body> {
    let mut headers = vec![(header::COOKIE.as_str(), admin.cookie.as_str())];
    if let Some(origin) = origin {
        headers.push((header::ORIGIN.as_str(), origin));
    }
    if let Some(csrf) = csrf {
        headers.push(("x-executor-csrf", csrf));
    }
    send_json(
        executor.router(),
        Method::POST,
        "/api/v1/tokens",
        json!({ "name": "Automation" }),
        &headers,
    )
    .await
}

async fn send_json(
    router: Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> Response<Body> {
    send_raw(router, method, uri, body.to_string(), headers).await
}

async fn send_json_from(
    router: Router,
    peer: SocketAddr,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> Response<Body> {
    send_raw_with_peer(router, method, uri, body.to_string(), headers, Some(peer)).await
}

async fn send_raw(
    router: Router,
    method: Method,
    uri: &str,
    body: String,
    headers: &[(&str, &str)],
) -> Response<Body> {
    send_raw_with_peer(router, method, uri, body, headers, None).await
}

async fn send_raw_with_peer(
    router: Router,
    method: Method,
    uri: &str,
    body: String,
    headers: &[(&str, &str)],
    peer: Option<SocketAddr>,
) -> Response<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut request = request
        .body(Body::from(body))
        .expect("test request should be valid");
    if let Some(peer) = peer {
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    router.oneshot(request).await.expect("router should answer")
}

async fn send_empty(
    router: Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
) -> Response<Body> {
    let mut request = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    router
        .oneshot(
            request
                .body(Body::empty())
                .expect("test request should be valid"),
        )
        .await
        .expect("router should answer")
}

fn response_cookie_header(response: &Response<Body>) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("set-cookie should be text")
                .split(';')
                .next()
                .expect("set-cookie should contain a value")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn response_json(response: Response<Body>) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body should collect")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("response should contain JSON")
}

async fn assert_error(response: Response<Body>, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&header::HeaderValue::from_static("no-store"))
    );
    let header_request_id = response
        .headers()
        .get("x-request-id")
        .expect("error should have a request ID")
        .to_str()
        .expect("request ID should be text")
        .to_owned();
    let body = response_json(response).await;
    assert_eq!(body["error"]["code"], code);
    assert_eq!(body["error"]["requestId"], header_request_id);
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );
}
