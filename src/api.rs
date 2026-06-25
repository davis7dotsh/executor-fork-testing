use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{
        ConnectInfo, DefaultBodyLimit, Extension, FromRequestParts, Path, State,
        rejection::JsonRejection,
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use uuid::Uuid;

use crate::{
    AppConfig,
    catalog::CatalogStore,
    crypto::{generate_secret, hash_password, verify_password},
    database::{Database, SETUP_TOKEN_TTL_SECONDS},
    execution::ExecutionService,
    invocation::ToolCallService,
    mcp::downstream::McpState,
    oauth::OAuthService,
    protocols::SourceService,
    request_logs::RequestLogSink,
    tasks::TaskTracker,
    unix_timestamp,
};

mod approvals;
mod catalog;
mod oauth;
pub(crate) mod openapi;
mod protocols;
mod token_delivery;

const SESSION_COOKIE: &str = "executor_session";
const CSRF_COOKIE: &str = "executor_csrf";
const CSRF_HEADER: &str = "x-executor-csrf";
const MAX_API_BODY_BYTES: usize = 16 * 1024;
const PASSWORD_HASH_CONCURRENCY: usize = 2;
const MAX_USERNAME_CHARACTERS: usize = 64;
const MAX_USERNAME_BYTES: usize = 256;
const MIN_PASSWORD_CHARACTERS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;
const MAX_SETUP_TOKEN_BYTES: usize = 128;
const MAX_TOKEN_NAME_CHARACTERS: usize = 80;
const MAX_TOKEN_NAME_BYTES: usize = 320;
const LOGIN_ATTEMPT_LIMIT: usize = 5;
const LOGIN_ATTEMPT_WINDOW: Duration = Duration::from_secs(60);
const MAX_LOGIN_RATE_LIMIT_CLIENTS: usize = 4096;
const MAX_FORWARDED_FOR_HOPS: usize = 64;
const MAX_FORWARDED_FOR_BYTES: usize = 4 * 1024;
const X_FORWARDED_FOR: &str = "x-forwarded-for";
const IDEMPOTENCY_KEY: &str = "idempotency-key";
const IDEMPOTENCY_REPLAYED: &str = "idempotency-replayed";
const REVOKE_RECONCILED: &str = "revoke-reconciled";
const TOKEN_LAST_USED_WRITE_INTERVAL_SECONDS: i64 = 60;
const TOKEN_LAST_USED_WRITE_INTERVAL: Duration = Duration::from_secs(60);
const MAX_TOKEN_LAST_USED_ATTEMPTS: usize = 4096;

#[derive(Clone)]
struct AppState {
    database: Database,
    catalog: CatalogStore,
    sources: SourceService,
    tool_calls: ToolCallService,
    execution: ExecutionService,
    mcp: McpState,
    oauth: OAuthService,
    request_logs: RequestLogSink,
    origin: Arc<str>,
    session_ttl_seconds: i64,
    secure_cookies: bool,
    password_hash_slots: Arc<Semaphore>,
    gateway_search_slots: Arc<Semaphore>,
    dummy_password_hash: Arc<str>,
    login_rate_limiter: Arc<LoginRateLimiter>,
    token_last_used_tracker: Arc<TokenLastUsedTracker>,
    trusted_proxies: Arc<[IpNet]>,
    background_tasks: TaskTracker,
    source_creation_supervisors: protocols::SourceCreationSupervisorRegistry,
}

#[derive(Clone)]
struct RequestId(String);

#[derive(Clone, Hash, Eq, PartialEq)]
enum LoginClientKey {
    PeerIp(IpAddr),
    InProcess,
    InvalidForwardedChain(&'static str),
}

struct LoginRateLimiter {
    attempts: Mutex<HashMap<LoginClientKey, VecDeque<Instant>>>,
}

struct TokenLastUsedTracker {
    attempts: Mutex<HashMap<String, Instant>>,
    write_slot: Arc<Semaphore>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorDetail {
    code: &'static str,
    message: String,
    request_id: String,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    request_id: String,
    retry_after_seconds: Option<u64>,
}

impl ApiError {
    fn new(
        request_id: &RequestId,
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            request_id: request_id.0.clone(),
            retry_after_seconds: None,
        }
    }

    fn unauthorized(request_id: &RequestId, message: impl Into<String>) -> Self {
        Self::new(
            request_id,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            message,
        )
    }

    fn internal(request_id: &RequestId) -> Self {
        Self::new(
            request_id,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "The request could not be completed.",
        )
    }

    fn internal_logged(request_id: &RequestId, error: impl std::fmt::Display) -> Self {
        tracing::error!(request_id = %request_id.0, error = %error, "control API request failed");
        Self::internal(request_id)
    }

    fn password_work_saturated(request_id: &RequestId) -> Self {
        Self::new(
            request_id,
            StatusCode::TOO_MANY_REQUESTS,
            "password_work_saturated",
            "Password verification is busy. Try again shortly.",
        )
        .with_retry_after(1)
    }

    fn login_rate_limited(request_id: &RequestId, retry_after_seconds: u64) -> Self {
        Self::new(
            request_id,
            StatusCode::TOO_MANY_REQUESTS,
            "login_rate_limited",
            "Too many login attempts. Try again later.",
        )
        .with_retry_after(retry_after_seconds)
    }

    fn with_retry_after(mut self, retry_after_seconds: u64) -> Self {
        self.retry_after_seconds = Some(retry_after_seconds);
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let retry_after_seconds = self.retry_after_seconds;
        let mut response = (
            self.status,
            Json(ErrorEnvelope {
                error: ErrorDetail {
                    code: self.code,
                    message: self.message,
                    request_id: self.request_id,
                },
            }),
        )
            .into_response();
        if let Some(retry_after_seconds) = retry_after_seconds {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_str(&retry_after_seconds.to_string())
                    .expect("retry delays are valid header values"),
            );
        }
        response
    }
}

impl LoginRateLimiter {
    fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, client: &LoginClientKey) -> Result<(), u64> {
        let now = Instant::now();
        let cutoff = now.checked_sub(LOGIN_ATTEMPT_WINDOW).unwrap_or(now);
        let mut attempts_by_client = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        attempts_by_client.retain(|_, attempts| {
            while attempts.front().is_some_and(|attempt| *attempt <= cutoff) {
                attempts.pop_front();
            }
            !attempts.is_empty()
        });

        if !attempts_by_client.contains_key(client)
            && attempts_by_client.len() >= MAX_LOGIN_RATE_LIMIT_CLIENTS
        {
            let oldest_client = attempts_by_client
                .iter()
                .filter_map(|(client, attempts)| attempts.front().map(|attempt| (client, attempt)))
                .min_by_key(|(_, attempt)| *attempt)
                .map(|(client, _)| client.clone());
            if let Some(oldest_client) = oldest_client {
                attempts_by_client.remove(&oldest_client);
            }
        }

        let attempts = attempts_by_client.entry(client.clone()).or_default();
        if attempts.len() >= LOGIN_ATTEMPT_LIMIT {
            let oldest = attempts.front().copied().unwrap_or(now);
            let remaining = LOGIN_ATTEMPT_WINDOW.saturating_sub(now.duration_since(oldest));
            return Err(remaining.as_secs().max(1));
        }
        attempts.push_back(now);
        Ok(())
    }

    fn clear(&self, client: &LoginClientKey) {
        self.attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(client);
    }
}

impl TokenLastUsedTracker {
    fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            write_slot: Arc::new(Semaphore::new(1)),
        }
    }

    fn schedule(
        self: &Arc<Self>,
        database: Database,
        token_id: String,
        used_at: i64,
        request_id: String,
        background_tasks: &TaskTracker,
    ) {
        let attempted_at = Instant::now();
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        attempts.retain(|_, previous_attempt| {
            attempted_at.saturating_duration_since(*previous_attempt)
                < TOKEN_LAST_USED_WRITE_INTERVAL
        });
        if attempts.contains_key(&token_id) {
            return;
        }
        let Ok(permit) = self.write_slot.clone().try_acquire_owned() else {
            return;
        };
        if attempts.len() >= MAX_TOKEN_LAST_USED_ATTEMPTS
            && let Some(oldest) = attempts
                .iter()
                .min_by_key(|(_, attempted_at)| *attempted_at)
                .map(|(token_id, _)| token_id.clone())
        {
            attempts.remove(&oldest);
        }
        attempts.insert(token_id.clone(), attempted_at);
        drop(attempts);

        let tracker = Arc::clone(self);
        background_tasks.spawn(async move {
            let _permit = permit;
            let database_guard = database;
            let result = sqlx::query(
                "UPDATE api_tokens SET last_used_at = ? WHERE id = ? AND revoked_at IS NULL \
                 AND (last_used_at IS NULL OR last_used_at <= ?)",
            )
            .bind(used_at)
            .bind(&token_id)
            .bind(used_at - TOKEN_LAST_USED_WRITE_INTERVAL_SECONDS)
            .execute(&database_guard.pool)
            .await;
            if let Err(error) = result {
                tracker.clear_failed_attempt(&token_id, attempted_at);
                tracing::warn!(request_id, error = %error, "API token last-used update failed");
            }
            drop(database_guard);
        });
    }

    fn clear_failed_attempt(&self, token_id: &str, attempted_at: Instant) {
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if attempts.get(token_id) == Some(&attempted_at) {
            attempts.remove(token_id);
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapResponse {
    setup_required: bool,
    authenticated: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetupRequest {
    setup_token: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    username: String,
    csrf_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTokenRequest {
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedTokenResponse {
    id: String,
    name: String,
    token: String,
    created_at: i64,
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct TokenMetadata {
    id: String,
    name: String,
    masked_token: String,
    created_at: i64,
    last_used_at: Option<i64>,
    revoked_at: Option<i64>,
}

#[derive(Serialize)]
struct TokenListResponse {
    tokens: Vec<TokenMetadata>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayIdentityResponse {
    token_id: String,
    token_name: String,
}

struct GatewayIdentity {
    token_id: String,
    token_name: String,
}

struct AdminMutation(i64);

struct AdminAuthentication(i64);

struct GatewayAuthentication(GatewayIdentity);

pub(crate) struct ApiServices {
    sources: SourceService,
    tool_calls: ToolCallService,
    execution: ExecutionService,
    mcp: McpState,
    oauth: OAuthService,
}

impl ApiServices {
    pub(crate) fn new(
        sources: SourceService,
        tool_calls: ToolCallService,
        execution: ExecutionService,
        mcp: McpState,
        oauth: OAuthService,
    ) -> Self {
        Self {
            sources,
            tool_calls,
            execution,
            mcp,
            oauth,
        }
    }
}

struct AdminSession {
    id: i64,
    username: String,
    session_digest: Vec<u8>,
    csrf_digest: Vec<u8>,
}

impl FromRequestParts<AppState> for AdminMutation {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .expect("request ID middleware runs before authentication")
            .clone();
        let admin = require_admin_mutation(&request_id, state, &parts.headers).await?;
        Ok(Self(admin.id))
    }
}

impl FromRequestParts<AppState> for AdminAuthentication {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .expect("request ID middleware runs before authentication")
            .clone();
        let admin = require_admin(&request_id, state, &parts.headers).await?;
        Ok(Self(admin.id))
    }
}

impl FromRequestParts<AppState> for GatewayAuthentication {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .expect("request ID middleware runs before authentication")
            .clone();
        let identity = require_gateway_token(&request_id, state, &parts.headers).await?;
        Ok(Self(identity))
    }
}

pub(crate) fn router(
    database: Database,
    catalog: CatalogStore,
    services: ApiServices,
    request_logs: RequestLogSink,
    background_tasks: TaskTracker,
    config: &AppConfig,
    dummy_password_hash: String,
) -> Router {
    let gateway_search_slots = services.tool_calls.discovery_slots();
    let state = AppState {
        database,
        catalog,
        sources: services.sources,
        tool_calls: services.tool_calls,
        execution: services.execution,
        mcp: services.mcp,
        oauth: services.oauth,
        request_logs,
        origin: Arc::from(config.public_origin()),
        session_ttl_seconds: config.session_ttl_seconds,
        secure_cookies: config.origin.scheme() == "https",
        password_hash_slots: Arc::new(Semaphore::new(PASSWORD_HASH_CONCURRENCY)),
        gateway_search_slots,
        dummy_password_hash: Arc::from(dummy_password_hash),
        login_rate_limiter: Arc::new(LoginRateLimiter::new()),
        token_last_used_tracker: Arc::new(TokenLastUsedTracker::new()),
        trusted_proxies: config.trusted_proxies.clone(),
        background_tasks,
        source_creation_supervisors: protocols::SourceCreationSupervisorRegistry::default(),
    };
    let middleware_state = state.clone();

    Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/bootstrap", get(bootstrap))
        .route("/api/v1/setup", post(setup))
        .route("/api/v1/session", post(login).get(session).delete(logout))
        .route("/api/v1/tokens", get(list_tokens).post(create_token))
        .route("/api/v1/tokens/{id}", delete(revoke_token))
        .route("/api/v1/gateway/whoami", get(gateway_whoami))
        .merge(catalog::router())
        .merge(approvals::router())
        .merge(protocols::router())
        .merge(openapi::router())
        .merge(oauth::router())
        .merge(crate::mcp::downstream::router(state.mcp.clone()))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_API_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            middleware_state,
            request_id_middleware,
        ))
}

async fn request_id_middleware(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let request_id = RequestId(Uuid::new_v4().to_string());
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| canonical_ip(peer.ip()));
    let login_client = login_client_key(peer_ip, request.headers(), &state.trusted_proxies);
    request.extensions_mut().insert(request_id.clone());
    request.extensions_mut().insert(login_client);
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.0).expect("UUID request IDs are valid headers"),
    );
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

fn login_client_key(
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> LoginClientKey {
    let Some(peer_ip) = peer_ip else {
        return LoginClientKey::InProcess;
    };
    if !is_trusted_proxy(peer_ip, trusted_proxies) {
        return LoginClientKey::PeerIp(peer_ip);
    }

    let forwarded_for = match forwarded_for_chain(headers) {
        Ok(forwarded_for) => forwarded_for,
        Err(reason) => return LoginClientKey::InvalidForwardedChain(reason),
    };
    let mut client_ip = peer_ip;
    for forwarded_ip in forwarded_for.into_iter().rev() {
        if !is_trusted_proxy(client_ip, trusted_proxies) {
            return LoginClientKey::PeerIp(client_ip);
        }
        let Ok(forwarded_ip) = forwarded_ip.parse() else {
            return LoginClientKey::InvalidForwardedChain("malformed X-Forwarded-For address");
        };
        client_ip = canonical_ip(forwarded_ip);
    }
    if is_trusted_proxy(client_ip, trusted_proxies) {
        LoginClientKey::InvalidForwardedChain("no untrusted client address in X-Forwarded-For")
    } else {
        LoginClientKey::PeerIp(client_ip)
    }
}

fn forwarded_for_chain(headers: &HeaderMap) -> Result<Vec<&str>, &'static str> {
    let mut chain = Vec::new();
    let mut total_bytes = 0_usize;
    for value in headers.get_all(X_FORWARDED_FOR).iter() {
        let value = value
            .to_str()
            .map_err(|_| "X-Forwarded-For is not valid text")?;
        total_bytes = total_bytes
            .checked_add(value.len())
            .filter(|length| *length <= MAX_FORWARDED_FOR_BYTES)
            .ok_or("X-Forwarded-For is too large")?;
        for address in value.split(',') {
            if chain.len() >= MAX_FORWARDED_FOR_HOPS {
                return Err("X-Forwarded-For has too many hops");
            }
            chain.push(address.trim());
        }
    }
    if chain.is_empty() {
        Err("X-Forwarded-For is missing")
    } else {
        Ok(chain)
    }
}

fn is_trusted_proxy(address: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    trusted_proxies
        .iter()
        .any(|network| network.contains(&address))
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn bootstrap(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<BootstrapResponse>, ApiError> {
    let setup_required =
        sqlx::query_scalar::<_, i64>("SELECT NOT EXISTS(SELECT 1 FROM admins WHERE id = 1)")
            .fetch_one(&state.database.pool)
            .await
            .map_err(|error| ApiError::internal_logged(&request_id, error))?
            != 0;
    let authenticated = optional_admin_session(&state, &headers)
        .await
        .map_err(|error| ApiError::internal_logged(&request_id, error))?
        .is_some();
    Ok(Json(BootstrapResponse {
        setup_required,
        authenticated,
    }))
}

async fn setup(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<SetupRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    require_origin(&request_id, &state, &headers)?;
    let Json(payload) = parse_json(&request_id, payload)?;
    let username = validate_username(&request_id, &payload.username)?;
    validate_setup_password(&request_id, &payload.password)?;
    if payload.setup_token.is_empty() || payload.setup_token.len() > MAX_SETUP_TOKEN_BYTES {
        return Err(ApiError::unauthorized(
            &request_id,
            "The setup token is invalid or has expired.",
        ));
    }

    let digest = state
        .database
        .keyring
        .digest("setup-token", payload.setup_token.as_bytes());
    let now = unix_timestamp();
    let setup_status = sqlx::query_scalar::<_, i64>(
        "SELECT CASE \
         WHEN EXISTS(SELECT 1 FROM admins WHERE id = 1) THEN 2 \
         WHEN EXISTS(SELECT 1 FROM setup_state WHERE id = 1 AND used_at IS NULL \
         AND token_digest = ? AND created_at >= ?) THEN 1 \
         ELSE 0 END",
    )
    .bind(digest.to_vec())
    .bind(now - SETUP_TOKEN_TTL_SECONDS)
    .fetch_one(&state.database.pool)
    .await
    .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    match setup_status {
        2 => {
            return Err(ApiError::new(
                &request_id,
                StatusCode::CONFLICT,
                "setup_complete",
                "This Executor instance is already configured.",
            ));
        }
        1 => {}
        _ => {
            return Err(ApiError::unauthorized(
                &request_id,
                "The setup token is invalid or has expired.",
            ));
        }
    }

    let permit = acquire_password_slot(&request_id, &state)?;
    let password = payload.password;
    let password_hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&password)
    })
    .await
    .map_err(|error| ApiError::internal_logged(&request_id, error))?
    .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    let claim_time = unix_timestamp();
    let mut transaction = state
        .database
        .pool
        .begin()
        .await
        .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO admins (id, username, password_hash, created_at) \
         SELECT 1, ?, ?, ? FROM setup_state \
         WHERE id = 1 AND used_at IS NULL AND token_digest = ? AND created_at >= ?",
    )
    .bind(&username)
    .bind(password_hash)
    .bind(claim_time)
    .bind(digest.to_vec())
    .bind(claim_time - SETUP_TOKEN_TTL_SECONDS)
    .execute(&mut *transaction)
    .await
    .map_err(|error| ApiError::internal_logged(&request_id, error))?
    .rows_affected();

    if inserted == 0 {
        let setup_complete =
            sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM admins WHERE id = 1)")
                .fetch_one(&mut *transaction)
                .await
                .map_err(|error| ApiError::internal_logged(&request_id, error))?
                != 0;
        transaction
            .rollback()
            .await
            .map_err(|error| ApiError::internal_logged(&request_id, error))?;
        return if setup_complete {
            Err(ApiError::new(
                &request_id,
                StatusCode::CONFLICT,
                "setup_complete",
                "This Executor instance is already configured.",
            ))
        } else {
            Err(ApiError::unauthorized(
                &request_id,
                "The setup token is invalid or has expired.",
            ))
        };
    }

    sqlx::query("UPDATE setup_state SET used_at = ? WHERE id = 1")
        .bind(claim_time)
        .execute(&mut *transaction)
        .await
        .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    transaction
        .commit()
        .await
        .map_err(|error| ApiError::internal_logged(&request_id, error))?;

    Ok((
        StatusCode::CREATED,
        Json(SessionResponse {
            username,
            csrf_token: None,
        }),
    ))
}

async fn login(
    Extension(request_id): Extension<RequestId>,
    Extension(login_client): Extension<LoginClientKey>,
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    require_origin(&request_id, &state, &headers)?;
    let Json(payload) = parse_json(&request_id, payload)?;
    let requested_username = validate_username(&request_id, &payload.username)?;
    validate_login_password(&request_id, &payload.password)?;
    if let LoginClientKey::InvalidForwardedChain(reason) = &login_client {
        tracing::warn!(request_id = %request_id.0, reason, "trusted proxy chain rejected");
        return Err(ApiError::unauthorized(
            &request_id,
            "The request could not be authenticated.",
        ));
    }
    state
        .login_rate_limiter
        .check(&login_client)
        .map_err(|retry_after| ApiError::login_rate_limited(&request_id, retry_after))?;
    let admin = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT id, username, password_hash FROM admins WHERE username = ?",
    )
    .bind(&requested_username)
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    let (admin_id, username, password_hash, admin_exists) = match admin {
        Some((admin_id, username, password_hash)) => (admin_id, username, password_hash, true),
        None => (
            0,
            requested_username,
            state.dummy_password_hash.to_string(),
            false,
        ),
    };
    let permit = acquire_password_slot(&request_id, &state)?;
    let password = payload.password;
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_password(&password, &password_hash)
    })
    .await
    .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    if !admin_exists || !verified {
        return Err(ApiError::unauthorized(
            &request_id,
            "The username or password is incorrect.",
        ));
    }

    let session_token = generate_secret("ses_");
    let csrf_token = generate_secret("csrf_");
    let session_digest = state
        .database
        .keyring
        .digest("admin-session", session_token.as_bytes());
    let csrf_digest = state
        .database
        .keyring
        .digest("csrf-token", csrf_token.as_bytes());
    let now = unix_timestamp();
    let expires_at = now + state.session_ttl_seconds;
    sqlx::query("DELETE FROM admin_sessions WHERE expires_at <= ?")
        .bind(now)
        .execute(&state.database.pool)
        .await
        .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    sqlx::query(
        "INSERT INTO admin_sessions \
         (session_digest, admin_id, csrf_digest, created_at, expires_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(session_digest.to_vec())
    .bind(admin_id)
    .bind(csrf_digest.to_vec())
    .bind(now)
    .bind(expires_at)
    .execute(&state.database.pool)
    .await
    .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    state.login_rate_limiter.clear(&login_client);

    let mut response = Json(SessionResponse {
        username,
        csrf_token: Some(csrf_token.clone()),
    })
    .into_response();
    append_set_cookie(
        response.headers_mut(),
        session_cookie(&state, &session_token),
    );
    append_set_cookie(response.headers_mut(), csrf_cookie(&state, &csrf_token));
    Ok(response)
}

async fn session(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let admin = require_admin(&request_id, &state, &headers).await?;
    Ok(Json(SessionResponse {
        username: admin.username,
        csrf_token: None,
    }))
}

async fn logout(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let admin = require_admin_mutation(&request_id, &state, &headers).await?;
    sqlx::query("DELETE FROM admin_sessions WHERE session_digest = ?")
        .bind(admin.session_digest)
        .execute(&state.database.pool)
        .await
        .map_err(|error| ApiError::internal_logged(&request_id, error))?;

    let mut response = StatusCode::NO_CONTENT.into_response();
    append_set_cookie(response.headers_mut(), clear_cookie(SESSION_COOKIE));
    append_set_cookie(response.headers_mut(), clear_cookie(CSRF_COOKIE));
    Ok(response)
}

async fn create_token(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateTokenRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let admin = require_admin_mutation(&request_id, &state, &headers).await?;
    let idempotency_key = required_idempotency_key(&request_id, &headers)?;
    let Json(payload) = parse_json(&request_id, payload)?;
    let name = payload.name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_TOKEN_NAME_CHARACTERS
        || name.len() > MAX_TOKEN_NAME_BYTES
    {
        return Err(ApiError::new(
            &request_id,
            StatusCode::BAD_REQUEST,
            "invalid_token_name",
            "Token names must contain between 1 and 80 characters.",
        ));
    }

    let claim = token_delivery::claim_token_creation(
        &state.database.pool,
        &state.database.keyring,
        admin.id,
        name,
        idempotency_key,
        unix_timestamp(),
    )
    .await
    .map_err(|error| token_delivery_error(&request_id, error))?;

    match claim {
        token_delivery::TokenCreationClaim::Fresh(token) => {
            Ok(created_token_response(token, false))
        }
        token_delivery::TokenCreationClaim::Replay(token) => {
            Ok(created_token_response(token, true))
        }
        token_delivery::TokenCreationClaim::Mismatch => Err(ApiError::new(
            &request_id,
            StatusCode::CONFLICT,
            "idempotency_mismatch",
            "The Idempotency-Key is already bound to a different token creation request.",
        )),
        token_delivery::TokenCreationClaim::Revoked => {
            let mut response = ApiError::new(
                &request_id,
                StatusCode::CONFLICT,
                "idempotency_replay_revoked",
                "The token created by this Idempotency-Key has been revoked.",
            )
            .into_response();
            response
                .headers_mut()
                .insert(IDEMPOTENCY_REPLAYED, HeaderValue::from_static("true"));
            Ok(response)
        }
    }
}

fn required_idempotency_key<'a>(
    request_id: &RequestId,
    headers: &'a HeaderMap,
) -> Result<&'a str, ApiError> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY).iter();
    let Some(value) = values.next() else {
        return Err(ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "An Idempotency-Key header is required when creating an API token.",
        ));
    };
    if values.next().is_some() {
        return Err(ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "The Idempotency-Key header is invalid.",
        ));
    }
    let key = value.to_str().map_err(|_| {
        ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "The Idempotency-Key header is invalid.",
        )
    })?;
    token_delivery::validate_idempotency_key(key).map_err(|_| {
        ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "The Idempotency-Key header is invalid.",
        )
    })?;
    Ok(key)
}

fn token_delivery_error(
    request_id: &RequestId,
    error: token_delivery::TokenDeliveryError,
) -> ApiError {
    match error {
        token_delivery::TokenDeliveryError::InvalidKey => ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_idempotency_key",
            "The Idempotency-Key header is invalid.",
        ),
        error @ (token_delivery::TokenDeliveryError::Database(_)
        | token_delivery::TokenDeliveryError::CorruptData) => {
            ApiError::internal_logged(request_id, error)
        }
    }
}

fn created_token_response(token: token_delivery::DeliveredToken, replayed: bool) -> Response {
    let mut response = (
        StatusCode::CREATED,
        Json(CreatedTokenResponse {
            id: token.id,
            name: token.name,
            token: token.token,
            created_at: token.created_at,
        }),
    )
        .into_response();
    if replayed {
        response
            .headers_mut()
            .insert(IDEMPOTENCY_REPLAYED, HeaderValue::from_static("true"));
    }
    response
}

async fn list_tokens(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<TokenListResponse>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    let tokens = sqlx::query_as::<_, TokenMetadata>(
        "SELECT id, name, token_prefix || '...' || token_suffix AS masked_token, \
         created_at, last_used_at, revoked_at \
         FROM api_tokens ORDER BY created_at DESC, id DESC",
    )
    .fetch_all(&state.database.pool)
    .await
    .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    Ok(Json(TokenListResponse { tokens }))
}

async fn revoke_token(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> Result<Response, ApiError> {
    require_admin_mutation(&request_id, &state, &headers).await?;
    let cleanup_state = state.clone();
    let cleanup_request_id = request_id.clone();
    let cleanup = async move {
        revoke_token_and_cleanup(&cleanup_request_id, &cleanup_state, &token_id).await
    };
    let result = spawn_supervised_result(&state.background_tasks, cleanup).ok_or_else(|| {
        ApiError::new(
            &request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "shutting_down",
            "Executor is shutting down.",
        )
    })?;
    let reconciled = result
        .await
        .map_err(|error| ApiError::internal_logged(&request_id, error))??;
    let mut response = StatusCode::NO_CONTENT.into_response();
    if reconciled {
        response
            .headers_mut()
            .insert(REVOKE_RECONCILED, HeaderValue::from_static("true"));
    }
    Ok(response)
}

async fn revoke_token_and_cleanup(
    request_id: &RequestId,
    state: &AppState,
    token_id: &str,
) -> Result<bool, ApiError> {
    let changed = state
        .tool_calls
        .revoke_owner_token(token_id)
        .await
        .map_err(|error| ApiError::internal_logged(request_id, error))?;
    let reconciled = if changed {
        false
    } else {
        let state =
            sqlx::query_as::<_, (Option<i64>,)>("SELECT revoked_at FROM api_tokens WHERE id = ?")
                .bind(token_id)
                .fetch_optional(&state.database.pool)
                .await
                .map_err(|error| ApiError::internal_logged(request_id, error))?;
        match state {
            None => {
                return Err(ApiError::new(
                    request_id,
                    StatusCode::NOT_FOUND,
                    "token_not_found",
                    "The API token was not found.",
                ));
            }
            Some((Some(_),)) => true,
            Some((None,)) => {
                return Err(ApiError::internal_logged(
                    request_id,
                    "an active API token could not be revoked",
                ));
            }
        }
    };
    state.mcp.revoke_token(token_id);
    state.execution.revoke_owner(token_id).await;
    Ok(reconciled)
}

fn spawn_supervised_result<T, F>(
    background_tasks: &TaskTracker,
    future: F,
) -> Option<oneshot::Receiver<T>>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    background_tasks
        .spawn_supervised(move |shutdown| async move {
            let _shutdown = shutdown;
            let _ = sender.send(future.await);
        })
        .then_some(receiver)
}

async fn gateway_whoami(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<GatewayIdentityResponse>, ApiError> {
    let identity = require_gateway_token(&request_id, &state, &headers).await?;
    Ok(Json(GatewayIdentityResponse {
        token_id: identity.token_id,
        token_name: identity.token_name,
    }))
}

async fn require_gateway_token(
    request_id: &RequestId,
    state: &AppState,
    headers: &HeaderMap,
) -> Result<GatewayIdentity, ApiError> {
    let token = bearer_token(headers).ok_or_else(|| {
        ApiError::unauthorized(request_id, "A valid Executor API token is required.")
    })?;
    let digest = state.database.keyring.digest("api-token", token.as_bytes());
    let identity = sqlx::query_as::<_, (String, String, Option<i64>)>(
        "SELECT id, name, last_used_at FROM api_tokens \
         WHERE token_digest = ? AND revoked_at IS NULL",
    )
    .bind(digest.to_vec())
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|error| ApiError::internal_logged(request_id, error))?
    .ok_or_else(|| ApiError::unauthorized(request_id, "A valid Executor API token is required."))?;
    let now = unix_timestamp();
    if identity
        .2
        .is_none_or(|last_used_at| last_used_at <= now - TOKEN_LAST_USED_WRITE_INTERVAL_SECONDS)
    {
        state.token_last_used_tracker.schedule(
            state.database.clone(),
            identity.0.clone(),
            now,
            request_id.0.clone(),
            &state.background_tasks,
        );
    }
    Ok(GatewayIdentity {
        token_id: identity.0,
        token_name: identity.1,
    })
}

async fn not_found(
    Extension(request_id): Extension<RequestId>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Some(response) = crate::web_assets::response(&method, &uri, &headers) {
        return response;
    }
    ApiError::new(
        &request_id,
        StatusCode::NOT_FOUND,
        "not_found",
        "The requested resource does not exist.",
    )
    .into_response()
}

async fn method_not_allowed(Extension(request_id): Extension<RequestId>) -> ApiError {
    ApiError::new(
        &request_id,
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "The request method is not allowed for this resource.",
    )
}

fn parse_json<T>(
    request_id: &RequestId,
    payload: Result<Json<T>, JsonRejection>,
) -> Result<Json<T>, ApiError> {
    payload.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(
                request_id,
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                "The request body exceeds the allowed size.",
            )
        } else {
            ApiError::new(
                request_id,
                StatusCode::BAD_REQUEST,
                "invalid_json",
                "The request body must be valid JSON with the expected fields.",
            )
        }
    })
}

fn validate_username(request_id: &RequestId, username: &str) -> Result<String, ApiError> {
    let username = username.trim();
    let username_length = username.chars().count();
    if !(1..=MAX_USERNAME_CHARACTERS).contains(&username_length)
        || username.len() > MAX_USERNAME_BYTES
    {
        return Err(ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_username",
            "Usernames must contain between 1 and 64 characters.",
        ));
    }
    Ok(username.to_owned())
}

fn validate_setup_password(request_id: &RequestId, password: &str) -> Result<(), ApiError> {
    if password.chars().count() < MIN_PASSWORD_CHARACTERS || password.len() > MAX_PASSWORD_BYTES {
        return Err(ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_password",
            "Passwords must contain at least 12 characters.",
        ));
    }
    Ok(())
}

fn validate_login_password(request_id: &RequestId, password: &str) -> Result<(), ApiError> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_password",
            "The password exceeds the allowed size.",
        ));
    }
    Ok(())
}

fn acquire_password_slot(
    request_id: &RequestId,
    state: &AppState,
) -> Result<OwnedSemaphorePermit, ApiError> {
    state
        .password_hash_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::password_work_saturated(request_id))
}

fn require_origin(
    request_id: &RequestId,
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    let origin_matches = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|origin| origin == state.origin.as_ref());
    if origin_matches {
        Ok(())
    } else {
        Err(ApiError::new(
            request_id,
            StatusCode::FORBIDDEN,
            "invalid_origin",
            "The request Origin does not match this Executor instance.",
        ))
    }
}

async fn require_admin(
    request_id: &RequestId,
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AdminSession, ApiError> {
    optional_admin_session(state, headers)
        .await
        .map_err(|error| ApiError::internal_logged(request_id, error))?
        .ok_or_else(|| ApiError::unauthorized(request_id, "An administrator session is required."))
}

async fn optional_admin_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<AdminSession>, sqlx::Error> {
    let Some(token) = cookie_value(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let digest = state
        .database
        .keyring
        .digest("admin-session", token.as_bytes());
    sqlx::query_as::<_, (i64, String, Vec<u8>, Vec<u8>)>(
        "SELECT admins.id, admins.username, admin_sessions.session_digest, admin_sessions.csrf_digest \
         FROM admin_sessions JOIN admins ON admins.id = admin_sessions.admin_id \
         WHERE admin_sessions.session_digest = ? AND admin_sessions.expires_at > ?",
    )
    .bind(digest.to_vec())
    .bind(unix_timestamp())
    .fetch_optional(&state.database.pool)
    .await
    .map(|row| {
        row.map(|(id, username, session_digest, csrf_digest)| AdminSession {
            id,
            username,
            session_digest,
            csrf_digest,
        })
    })
}

async fn require_admin_mutation(
    request_id: &RequestId,
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AdminSession, ApiError> {
    require_origin(request_id, state, headers)?;
    let admin = require_admin(request_id, state, headers).await?;
    let csrf_header = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ApiError::new(
                request_id,
                StatusCode::FORBIDDEN,
                "invalid_csrf",
                "A valid CSRF token is required.",
            )
        })?;
    let csrf_cookie = cookie_value(headers, CSRF_COOKIE).ok_or_else(|| {
        ApiError::new(
            request_id,
            StatusCode::FORBIDDEN,
            "invalid_csrf",
            "A valid CSRF token is required.",
        )
    })?;
    let same_token: bool = csrf_header.as_bytes().ct_eq(csrf_cookie.as_bytes()).into();
    let valid_digest = state.database.keyring.digest_matches(
        "csrf-token",
        csrf_header.as_bytes(),
        &admin.csrf_digest,
    );
    if !same_token || !valid_digest {
        return Err(ApiError::new(
            request_id,
            StatusCode::FORBIDDEN,
            "invalid_csrf",
            "A valid CSRF token is required.",
        ));
    }
    Ok(admin)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(cookie_name, value)| (cookie_name == name).then(|| value.to_owned()))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let mut parts = value.split_ascii_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    (scheme.eq_ignore_ascii_case("bearer") && parts.next().is_none()).then_some(token)
}

fn append_set_cookie(headers: &mut HeaderMap, cookie: String) {
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).expect("generated cookies contain only safe characters"),
    );
}

fn session_cookie(state: &AppState, token: &str) -> String {
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{secure}",
        state.session_ttl_seconds
    )
}

fn csrf_cookie(state: &AppState, token: &str) -> String {
    let secure = if state.secure_cookies { "; Secure" } else { "" };
    format!(
        "{CSRF_COOKIE}={token}; Path=/; SameSite=Lax; Max-Age={}{secure}",
        state.session_ttl_seconds
    )
}

fn clear_cookie(name: &str) -> String {
    format!("{name}=; Path=/; SameSite=Lax; Max-Age=0")
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };

    use tempfile::TempDir;
    use tokio::{sync::oneshot, time::timeout};

    use super::{TokenLastUsedTracker, spawn_supervised_result};
    use crate::{
        AppConfig,
        database::{Database, DatabaseError, OpenedDatabase},
        tasks::TaskTracker,
    };

    async fn open_database() -> (TempDir, AppConfig, Database) {
        let directory = tempfile::tempdir().expect("temporary data directory");
        let config = AppConfig::new(directory.path().into());
        let OpenedDatabase { database, .. } =
            Database::open(&config).await.expect("test database opens");
        (directory, config, database)
    }

    async fn insert_token(database: &Database, token_id: &str) {
        sqlx::query(
            "INSERT INTO api_tokens \
             (id, name, token_digest, token_prefix, token_suffix, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(token_id)
        .bind(token_id)
        .bind(format!("digest-{token_id}").into_bytes())
        .bind("exr_test")
        .bind("test")
        .bind(1_i64)
        .execute(&database.pool)
        .await
        .expect("test API token is inserted");
    }

    async fn wait_for_token_write(tracker: &Arc<TokenLastUsedTracker>) {
        let permit = timeout(
            Duration::from_secs(2),
            tracker.write_slot.clone().acquire_owned(),
        )
        .await
        .expect("token last-used write completes")
        .expect("token last-used write semaphore remains open");
        drop(permit);
    }

    #[tokio::test]
    async fn dropping_token_revoke_waiter_does_not_cancel_supervised_cleanup() {
        let background_tasks = TaskTracker::default();
        let cleaned = Arc::new(AtomicBool::new(false));
        let task_cleaned = cleaned.clone();
        let (started_sender, started_receiver) = oneshot::channel();
        let (release_sender, release_receiver) = oneshot::channel();
        let waiter = spawn_supervised_result(&background_tasks, async move {
            let _ = started_sender.send(());
            let _ = release_receiver.await;
            task_cleaned.store(true, Ordering::Release);
        })
        .expect("token revoke cleanup is supervised");

        started_receiver.await.expect("cleanup task starts");
        drop(waiter);
        background_tasks.abort_all();
        release_sender.send(()).expect("cleanup task releases");
        background_tasks.shutdown().await;

        assert!(cleaned.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn failed_token_last_used_write_clears_only_its_matching_attempt_and_retries() {
        let (_directory, _config, database) = open_database().await;
        insert_token(&database, "retry-token").await;
        sqlx::query(
            "CREATE TRIGGER reject_token_last_used \
             BEFORE UPDATE OF last_used_at ON api_tokens \
             BEGIN SELECT RAISE(FAIL, 'forced token last-used failure'); END",
        )
        .execute(&database.pool)
        .await
        .expect("failure trigger is installed");

        let tracker = Arc::new(TokenLastUsedTracker::new());
        let background_tasks = TaskTracker::default();
        let unrelated_attempt = Instant::now();
        tracker
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert("unrelated-token".to_owned(), unrelated_attempt);

        let replaced_attempt = Instant::now();
        let replacement_attempt = replaced_attempt + Duration::from_secs(1);
        tracker
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert("replacement-token".to_owned(), replacement_attempt);
        tracker.clear_failed_attempt("replacement-token", replaced_attempt);

        tracker.schedule(
            database.clone(),
            "retry-token".to_owned(),
            1_750_000_000,
            "failed-request".to_owned(),
            &background_tasks,
        );
        wait_for_token_write(&tracker).await;

        {
            let attempts = tracker
                .attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(!attempts.contains_key("retry-token"));
            assert_eq!(attempts.get("unrelated-token"), Some(&unrelated_attempt));
            assert_eq!(
                attempts.get("replacement-token"),
                Some(&replacement_attempt)
            );
        }

        sqlx::query("DROP TRIGGER reject_token_last_used")
            .execute(&database.pool)
            .await
            .expect("failure trigger is removed");
        tracker.schedule(
            database.clone(),
            "retry-token".to_owned(),
            1_750_000_001,
            "retry-request".to_owned(),
            &background_tasks,
        );
        wait_for_token_write(&tracker).await;

        let last_used = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT last_used_at FROM api_tokens WHERE id = 'retry-token'",
        )
        .fetch_one(&database.pool)
        .await
        .expect("last-used timestamp is readable");
        assert_eq!(last_used, Some(1_750_000_001));
        background_tasks.shutdown().await;
    }

    #[tokio::test]
    async fn token_last_used_background_write_retains_the_instance_lock() {
        let (_directory, config, database) = open_database().await;
        insert_token(&database, "guarded-token").await;
        let mut writer = database
            .pool
            .acquire()
            .await
            .expect("test writer connection is acquired");
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *writer)
            .await
            .expect("test writer holds the SQLite write lock");

        let tracker = Arc::new(TokenLastUsedTracker::new());
        let background_tasks = TaskTracker::default();
        tracker.schedule(
            database.clone(),
            "guarded-token".to_owned(),
            1_750_000_000,
            "guarded-request".to_owned(),
            &background_tasks,
        );
        drop(database);

        let second_open = Database::open(&config).await;
        assert!(matches!(second_open, Err(DatabaseError::AlreadyRunning(_))));

        sqlx::query("COMMIT")
            .execute(&mut *writer)
            .await
            .expect("test writer releases the SQLite write lock");
        drop(writer);
        wait_for_token_write(&tracker).await;

        let reopened = timeout(Duration::from_secs(2), async {
            loop {
                match Database::open(&config).await {
                    Ok(opened) => break opened.database,
                    Err(DatabaseError::AlreadyRunning(_)) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(error) => panic!("database should reopen after the write: {error}"),
                }
            }
        })
        .await
        .expect("background write releases its instance-lock guard");
        reopened.pool.close().await;
        background_tasks.shutdown().await;
    }
}
