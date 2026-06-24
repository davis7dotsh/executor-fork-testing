use std::{
    collections::HashMap,
    future::Future,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{DefaultBodyLimit, Extension, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::post,
};
use rmcp::model::ProtocolVersion;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use url::Url;
use uuid::Uuid;

use crate::{
    actor::ToolActor,
    catalog::{CatalogError, CatalogStore, RequestSurface},
    database::Database,
    execution::{ExecuteCodeRequest, ExecutionService, ExecutionServiceError},
    invocation::{
        GatewayInvokeError, McpIdempotencyBlob, McpIdempotencyClaim, McpIdempotencyRequest,
        ToolCall, ToolCallError, ToolCallService, ToolResult,
    },
    tasks::TaskTracker,
    unix_timestamp,
};

const PROTOCOL_VERSION: &str = "2025-11-25";
const SESSION_HEADER: &str = "mcp-session-id";
const PROTOCOL_HEADER: &str = "mcp-protocol-version";
const MAX_MCP_BODY_BYTES: usize = crate::invocation::MAX_ARGUMENT_BYTES + 64 * 1024;
const MAX_BEARER_TOKEN_BYTES: usize = 512;
const MAX_SESSIONS: usize = 4_096;
const MAX_SESSIONS_PER_TOKEN: usize = 32;
const MAX_ACTIVE_REQUESTS: usize = 4_096;
const MAX_PRE_CANCELS_PER_SESSION: usize = 128;
const MAX_CONCURRENT_BODIES: usize = 16;
const MAX_CONCURRENT_BODIES_PER_TOKEN: usize = 4;
const MAX_CONCURRENT_EXECUTIONS: usize = 16;
const MAX_CONCURRENT_EXECUTIONS_PER_TOKEN: usize = 4;
const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
const UNINITIALIZED_SESSION_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_EXECUTION_TIMEOUT_MILLIS: u64 = 30_000;
const MAX_EXECUTION_TIMEOUT_MILLIS: u64 = 300_000;
const PRE_CANCEL_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub(crate) struct McpState {
    database: Database,
    _catalog: CatalogStore,
    tool_calls: ToolCallService,
    execution: ExecutionService,
    origin: Arc<str>,
    origin_url: Url,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    cancellations: CancellationRegistry,
    tasks: TaskTracker,
    body_limiter: McpRequestLimiter,
    execution_limiter: McpRequestLimiter,
    #[cfg(test)]
    session_registration_race_hook: Arc<Mutex<Option<Arc<SessionRegistrationRaceHook>>>>,
}

#[derive(Clone)]
struct McpRequestLimiter {
    global: Arc<Semaphore>,
    by_token: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    per_token: usize,
}

struct McpRequestPermits {
    _global: OwnedSemaphorePermit,
    _token: OwnedSemaphorePermit,
}

impl McpRequestLimiter {
    fn new(global: usize, per_token: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global)),
            by_token: Arc::new(Mutex::new(HashMap::new())),
            per_token,
        }
    }

    fn try_acquire(&self, token_id: &str) -> Option<Arc<McpRequestPermits>> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        let token_slots = {
            let mut slots = self
                .by_token
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slots
                .entry(token_id.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_token)))
                .clone()
        };
        let token = token_slots.try_acquire_owned().ok()?;
        Some(Arc::new(McpRequestPermits {
            _global: global,
            _token: token,
        }))
    }
}

#[derive(Clone, Default)]
struct CancellationRegistry {
    entries: Arc<Mutex<HashMap<String, CancellationEntry>>>,
}

struct CancellationEntry {
    notify: Arc<Notify>,
    canceled: Arc<AtomicBool>,
    waiters: usize,
    created_at: Instant,
}

struct CancellationRegistration {
    key: String,
    notify: Arc<Notify>,
    canceled: Arc<AtomicBool>,
    registry: CancellationRegistry,
}

#[derive(Clone)]
struct CancellationSignal {
    notify: Arc<Notify>,
    canceled: Arc<AtomicBool>,
}

enum SessionRequestRegistrationError {
    SessionEnded,
    Capacity,
}

#[cfg(test)]
#[derive(Default)]
struct SessionRegistrationRaceHook {
    validation_complete: Notify,
    continue_registration: Notify,
}

#[derive(Clone)]
struct Session {
    token_id: String,
    token_name: String,
    initialized: bool,
    last_seen: Instant,
}

#[derive(Clone)]
struct Identity {
    token_id: String,
    token_name: String,
}

#[derive(Debug, Deserialize)]
struct IncomingMessage {
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: Option<String>,
    #[serde(default)]
    params: Value,
}

struct EnvelopeShape {
    has_method: bool,
    has_params: bool,
    has_result: bool,
    has_error: bool,
    error_valid: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InitializeParams {
    protocol_version: ProtocolVersion,
    capabilities: Value,
    client_info: Value,
    #[serde(rename = "_meta")]
    meta: Option<Value>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ListToolsParams {
    cursor: Option<String>,
    #[serde(rename = "_meta")]
    meta: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallToolParams {
    name: String,
    #[serde(default = "empty_arguments")]
    arguments: Map<String, Value>,
    #[serde(rename = "_meta")]
    meta: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecuteArguments {
    code: String,
    timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectCallArguments {
    path: String,
    #[serde(default = "empty_arguments")]
    arguments: Map<String, Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SearchArguments {
    query: String,
    namespace: Option<String>,
    #[serde(default = "default_search_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescribeArguments {
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CancelledParams {
    request_id: Value,
}

#[derive(Serialize)]
struct McpTool {
    name: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    output_schema: Option<Value>,
}

impl McpState {
    pub(crate) fn new(
        database: Database,
        catalog: CatalogStore,
        tool_calls: ToolCallService,
        execution: ExecutionService,
        tasks: TaskTracker,
        origin: String,
    ) -> Self {
        let origin_url = Url::parse(&origin).expect("validated application origins are URLs");
        Self {
            database,
            _catalog: catalog,
            tool_calls,
            execution,
            origin: Arc::from(origin),
            origin_url,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            cancellations: CancellationRegistry::default(),
            tasks,
            body_limiter: McpRequestLimiter::new(
                MAX_CONCURRENT_BODIES,
                MAX_CONCURRENT_BODIES_PER_TOKEN,
            ),
            execution_limiter: McpRequestLimiter::new(
                MAX_CONCURRENT_EXECUTIONS,
                MAX_CONCURRENT_EXECUTIONS_PER_TOKEN,
            ),
            #[cfg(test)]
            session_registration_race_hook: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn revoke_token(&self, token_id: &str) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let revoked_sessions = sessions
            .iter()
            .filter(|(_, session)| session.token_id == token_id)
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();
        for session_id in revoked_sessions {
            sessions.remove(&session_id);
            self.cancellations.cancel_session(&session_id);
        }
    }

    fn create_session(&self, identity: &Identity) -> Result<String, TransportError> {
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.prune_expired_sessions(&mut sessions, now);
        if sessions
            .values()
            .filter(|session| session.token_id == identity.token_id)
            .count()
            >= MAX_SESSIONS_PER_TOKEN
        {
            return Err(TransportError::service_unavailable(
                "session_capacity",
                "The API token has reached its MCP session limit.",
            ));
        }
        if sessions.len() >= MAX_SESSIONS {
            return Err(TransportError::service_unavailable(
                "session_capacity",
                "The MCP session limit has been reached.",
            ));
        }
        let id = Uuid::new_v4().to_string();
        sessions.insert(
            id.clone(),
            Session {
                token_id: identity.token_id.clone(),
                token_name: identity.token_name.clone(),
                initialized: false,
                last_seen: now,
            },
        );
        Ok(id)
    }

    fn require_session(
        &self,
        headers: &HeaderMap,
        identity: &Identity,
        require_initialized: bool,
    ) -> Result<(String, Session), TransportError> {
        require_protocol_version(headers)?;
        let id = unique_text_header(headers, SESSION_HEADER)?.ok_or_else(|| {
            TransportError::bad_request(
                "missing_session",
                "Mcp-Session-Id is required after initialization.",
            )
        })?;
        if id.len() > 128 || !id.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(TransportError::bad_request(
                "invalid_session",
                "Mcp-Session-Id is invalid.",
            ));
        }
        let now = Instant::now();
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.prune_expired_sessions(&mut sessions, now);
        let session = sessions.get_mut(id).ok_or_else(|| {
            TransportError::not_found("session_not_found", "The MCP session does not exist.")
        })?;
        if session.token_id != identity.token_id {
            return Err(TransportError::not_found(
                "session_not_found",
                "The MCP session does not exist.",
            ));
        }
        if require_initialized && !session.initialized {
            return Err(TransportError::bad_request(
                "session_not_initialized",
                "The MCP initialization handshake is incomplete.",
            ));
        }
        session.last_seen = now;
        Ok((id.to_owned(), session.clone()))
    }

    fn register_session_request(
        &self,
        session_id: &str,
        token_id: &str,
        request_key: String,
    ) -> Result<CancellationRegistration, SessionRequestRegistrationError> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.prune_expired_sessions(&mut sessions, Instant::now());
        let active = sessions
            .get(session_id)
            .is_some_and(|session| session.initialized && session.token_id == token_id);
        if !active {
            return Err(SessionRequestRegistrationError::SessionEnded);
        }
        self.cancellations
            .register(request_key)
            .ok_or(SessionRequestRegistrationError::Capacity)
    }

    fn terminate_session(&self, session_id: &str, token_id: &str) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let owned = sessions
            .get(session_id)
            .is_some_and(|session| session.token_id == token_id);
        if owned {
            sessions.remove(session_id);
            self.cancellations.cancel_session(session_id);
        }
        owned
    }

    fn prune_expired_sessions(&self, sessions: &mut HashMap<String, Session>, now: Instant) {
        let expired = sessions
            .iter()
            .filter(|(_, session)| {
                let ttl = if session.initialized {
                    SESSION_TTL
                } else {
                    UNINITIALIZED_SESSION_TTL
                };
                now.saturating_duration_since(session.last_seen) >= ttl
            })
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();
        for session_id in expired {
            sessions.remove(&session_id);
            self.cancellations.cancel_session(&session_id);
        }
    }
}

impl CancellationRegistry {
    fn register(&self, key: String) -> Option<CancellationRegistration> {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        entries.retain(|_, entry| {
            entry.waiters > 0 || now.saturating_duration_since(entry.created_at) < PRE_CANCEL_TTL
        });
        if !entries.contains_key(&key) && entries.len() >= MAX_ACTIVE_REQUESTS {
            return None;
        }
        let entry = entries
            .entry(key.clone())
            .or_insert_with(|| CancellationEntry {
                notify: Arc::new(Notify::new()),
                canceled: Arc::new(AtomicBool::new(false)),
                waiters: 0,
                created_at: now,
            });
        entry.waiters = entry.waiters.saturating_add(1);
        Some(CancellationRegistration {
            key,
            notify: entry.notify.clone(),
            canceled: entry.canceled.clone(),
            registry: self.clone(),
        })
    }

    fn cancel(&self, key: &str) {
        let now = Instant::now();
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.retain(|_, entry| {
            entry.waiters > 0 || now.saturating_duration_since(entry.created_at) < PRE_CANCEL_TTL
        });
        let session_prefix = key
            .split_once('\0')
            .map(|(session, _)| format!("{session}\0"));
        let session_tombstones = session_prefix.as_deref().map_or(0, |prefix| {
            entries
                .iter()
                .filter(|(entry_key, entry)| entry.waiters == 0 && entry_key.starts_with(prefix))
                .count()
        });
        if !entries.contains_key(key)
            && entries.len() < MAX_ACTIVE_REQUESTS
            && session_tombstones < MAX_PRE_CANCELS_PER_SESSION
        {
            entries.insert(
                key.to_owned(),
                CancellationEntry {
                    notify: Arc::new(Notify::new()),
                    canceled: Arc::new(AtomicBool::new(true)),
                    waiters: 0,
                    created_at: now,
                },
            );
        }
        if let Some(entry) = entries.get(key) {
            entry.canceled.store(true, Ordering::Release);
            entry.notify.notify_waiters();
        }
    }

    fn cancel_session(&self, session_id: &str) {
        let prefix = format!("{session_id}\0");
        let signals = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .map(|(_, entry)| (entry.notify.clone(), entry.canceled.clone()))
            .collect::<Vec<_>>();
        for (notify, canceled) in signals {
            canceled.store(true, Ordering::Release);
            notify.notify_waiters();
        }
    }
}

impl Drop for CancellationRegistration {
    fn drop(&mut self) {
        let mut entries = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remove = entries.get_mut(&self.key).is_some_and(|entry| {
            if !Arc::ptr_eq(&entry.notify, &self.notify) {
                return false;
            }
            entry.waiters = entry.waiters.saturating_sub(1);
            entry.waiters == 0
        });
        if remove {
            entries.remove(&self.key);
        }
    }
}

pub(crate) fn router<S>(state: McpState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let guard_state = state.clone();
    Router::new()
        .route(
            "/mcp",
            post(handle_post)
                .get(handle_get)
                .delete(handle_delete)
                .options(handle_options),
        )
        .layer(DefaultBodyLimit::max(MAX_MCP_BODY_BYTES))
        .route_layer(middleware::from_fn_with_state(
            guard_state,
            connection_guard,
        ))
        .with_state(state)
}

async fn connection_guard(
    State(state): State<McpState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    if request.method() != axum::http::Method::OPTIONS {
        if let Err(error) = validate_connection(&state, request.headers()) {
            return error.into_response();
        }
        let identity = match authenticate(&state, request.headers()).await {
            Ok(identity) => identity,
            Err(error) => return error.into_response(),
        };
        if request.method() == axum::http::Method::POST {
            let Some(permits) = state.body_limiter.try_acquire(&identity.token_id) else {
                return TransportError::too_many_requests(
                    "mcp_busy",
                    "The MCP endpoint is busy. Try again shortly.",
                )
                .into_response();
            };
            request.extensions_mut().insert(permits);
        }
        request.extensions_mut().insert(identity);
    }
    next.run(request).await
}

async fn handle_options(State(state): State<McpState>, headers: HeaderMap) -> Response {
    if let Err(error) = validate_origin(&state, &headers) {
        return error.into_response();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors_headers(response.headers_mut(), &state);
    response.headers_mut().insert(
        header::ALLOW,
        HeaderValue::from_static("POST, GET, DELETE, OPTIONS"),
    );
    response
}

async fn handle_get(
    State(state): State<McpState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = validate_connection(&state, &headers) {
        return error.into_response();
    }
    if let Err(error) = state.require_session(&headers, &identity, true) {
        return error.into_response();
    }
    let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
    response.headers_mut().insert(
        header::ALLOW,
        HeaderValue::from_static("POST, DELETE, OPTIONS"),
    );
    add_cors_headers(response.headers_mut(), &state);
    response
}

async fn handle_delete(
    State(state): State<McpState>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = validate_connection(&state, &headers) {
        return error.into_response();
    }
    let (session_id, session) = match state.require_session(&headers, &identity, false) {
        Ok(session) => session,
        Err(error) => return error.into_response(),
    };
    if !state.terminate_session(&session_id, &session.token_id) {
        return TransportError::not_found("session_not_found", "The MCP session does not exist.")
            .into_response();
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    add_cors_headers(response.headers_mut(), &state);
    response
}

async fn handle_post(
    State(state): State<McpState>,
    Extension(identity): Extension<Identity>,
    Extension(request_permits): Extension<Arc<McpRequestPermits>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    drop(request_permits);
    if let Err(error) = validate_connection(&state, &headers) {
        return error.into_response();
    }
    if let Err(error) = validate_post_headers(&headers) {
        return error.into_response();
    }
    let raw_message = match serde_json::from_slice::<Value>(&body) {
        Ok(message) => message,
        Err(_) => return rpc_error_response(None, -32700, "Parse error", None, &state),
    };
    let Some(object) = raw_message.as_object() else {
        return rpc_error_response(None, -32600, "Invalid Request", None, &state);
    };
    let shape = EnvelopeShape {
        has_method: object.contains_key("method"),
        has_params: object.contains_key("params"),
        has_result: object.contains_key("result"),
        has_error: object.contains_key("error"),
        error_valid: object.get("error").is_none_or(valid_jsonrpc_error),
    };
    let message = match serde_json::from_value::<IncomingMessage>(raw_message) {
        Ok(message) => message,
        Err(_) => return rpc_error_response(None, -32600, "Invalid Request", None, &state),
    };
    if message.jsonrpc.as_deref() != Some("2.0")
        || message.id.as_ref().is_some_and(|id| !valid_request_id(id))
        || (shape.has_method && message.method.is_none())
    {
        return rpc_error_response(message.id, -32600, "Invalid Request", None, &state);
    }
    if !shape.has_method {
        let response_shape = message.id.is_some()
            && (shape.has_result ^ shape.has_error)
            && !shape.has_params
            && shape.error_valid;
        if !response_shape {
            return TransportError::bad_request(
                "invalid_jsonrpc_message",
                "The JSON-RPC response is invalid.",
            )
            .into_response();
        }
        if let Err(error) = state.require_session(&headers, &identity, true) {
            return error.into_response();
        }
        let mut response = StatusCode::ACCEPTED.into_response();
        add_cors_headers(response.headers_mut(), &state);
        return response;
    }
    if shape.has_result || shape.has_error {
        return TransportError::bad_request(
            "invalid_jsonrpc_message",
            "A JSON-RPC request cannot contain response fields.",
        )
        .into_response();
    }
    let method = message.method.as_deref().unwrap_or_default();
    if method == "initialize" {
        return initialize(state, headers, identity, message).await;
    }
    let (session_id, session) = match state.require_session(&headers, &identity, false) {
        Ok(session) => session,
        Err(error) => return error.into_response(),
    };
    if message.id.is_none() {
        return handle_notification(state, session_id, session, message).await;
    }
    if !session.initialized {
        return rpc_error_response(
            message.id,
            -32600,
            "Initialization handshake incomplete",
            None,
            &state,
        );
    }
    match method {
        "ping" => rpc_result_response(message.id, json!({}), None, &state),
        "tools/list" => list_tools(&state, message).await,
        "tools/call" => call_tool(&state, &session_id, session, message).await,
        _ => rpc_error_response(message.id, -32601, "Method not found", None, &state),
    }
}

async fn initialize(
    state: McpState,
    headers: HeaderMap,
    identity: Identity,
    message: IncomingMessage,
) -> Response {
    let Some(id) = message.id else {
        return rpc_error_response(None, -32600, "Invalid Request", None, &state);
    };
    match unique_text_header(&headers, SESSION_HEADER) {
        Ok(None) => {}
        Ok(Some(_)) => {
            return TransportError::bad_request(
                "unexpected_session",
                "Initialization must not include Mcp-Session-Id.",
            )
            .into_response();
        }
        Err(error) => return error.into_response(),
    }
    let params = match serde_json::from_value::<InitializeParams>(message.params) {
        Ok(params) => params,
        Err(_) => return rpc_error_response(Some(id), -32602, "Invalid params", None, &state),
    };
    if params.protocol_version != ProtocolVersion::V_2025_11_25 {
        return rpc_error_response(
            Some(id),
            -32602,
            "Unsupported protocol version",
            Some(json!({ "supported": [PROTOCOL_VERSION] })),
            &state,
        );
    }
    let client_info_valid = params.client_info.as_object().is_some_and(|client_info| {
        client_info
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty())
            && client_info
                .get("version")
                .and_then(Value::as_str)
                .is_some_and(|version| !version.is_empty())
    });
    if !params.capabilities.is_object() || !client_info_valid {
        return rpc_error_response(Some(id), -32602, "Invalid params", None, &state);
    }
    let _ = params.meta;
    let session_id = match state.create_session(&identity) {
        Ok(session_id) => session_id,
        Err(error) => return error.into_response(),
    };
    rpc_result_response(
        Some(id),
        json!({
            "protocolVersion": ProtocolVersion::V_2025_11_25,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": {
                "name": "executor",
                "title": "Executor",
                "version": env!("CARGO_PKG_VERSION")
            },
            "instructions": "Executor exposes the globally enabled tool catalog. Tools in Ask mode pause until approved by the administrator."
        }),
        Some(&session_id),
        &state,
    )
}

async fn handle_notification(
    state: McpState,
    session_id: String,
    _session: Session,
    message: IncomingMessage,
) -> Response {
    if message.method.as_deref() == Some("notifications/initialized") {
        let mut sessions = state
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(session) = sessions.get_mut(&session_id) {
            session.initialized = true;
            session.last_seen = Instant::now();
        }
    } else if message.method.as_deref() == Some("notifications/cancelled")
        && let Ok(params) = serde_json::from_value::<CancelledParams>(message.params)
        && valid_request_id(&params.request_id)
    {
        state.cancellations.cancel(&request_cancellation_key(
            &session_id,
            &rpc_id_string(&params.request_id),
        ));
    }
    let mut response = StatusCode::ACCEPTED.into_response();
    add_cors_headers(response.headers_mut(), &state);
    response
}

async fn list_tools(state: &McpState, message: IncomingMessage) -> Response {
    let id = message.id;
    let params = match decode_optional_params::<ListToolsParams>(message.params) {
        Ok(params) => params,
        Err(()) => return rpc_error_response(id, -32602, "Invalid params", None, state),
    };
    let _ = params.meta;
    if params.cursor.is_some() {
        return rpc_error_response(id, -32602, "Invalid cursor", None, state);
    }
    rpc_result_response(id, json!({ "tools": virtual_tools() }), None, state)
}

async fn call_tool(
    state: &McpState,
    session_id: &str,
    session: Session,
    message: IncomingMessage,
) -> Response {
    let id = message.id;
    let params = match serde_json::from_value::<CallToolParams>(message.params) {
        Ok(params) => params,
        Err(_) => return rpc_error_response(id, -32602, "Invalid params", None, state),
    };
    if params.name.is_empty() || params.name.len() > 512 {
        return rpc_error_response(id, -32602, "Invalid params", None, state);
    }
    if !matches!(
        params.name.as_str(),
        "execute" | "call" | "search" | "describe" | "sources"
    ) {
        return rpc_error_response(
            id,
            -32602,
            "The requested tool does not exist.",
            None,
            state,
        );
    }
    let _ = params.meta;
    let correlation = rpc_id_string(id.as_ref().expect("request IDs are present for calls"));
    #[cfg(test)]
    {
        let hook = state
            .session_registration_race_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook.validation_complete.notify_one();
            hook.continue_registration.notified().await;
        }
    }
    let Some(execution_permits) = state.execution_limiter.try_acquire(&session.token_id) else {
        return rpc_error_response(
            id,
            -32603,
            "The MCP execution limit was reached.",
            None,
            state,
        );
    };
    let cancellation = match state.register_session_request(
        session_id,
        &session.token_id,
        request_cancellation_key(session_id, &correlation),
    ) {
        Ok(cancellation) => cancellation,
        Err(SessionRequestRegistrationError::SessionEnded) => {
            return idempotency_error(id, GatewayInvokeError::Canceled, state);
        }
        Err(SessionRequestRegistrationError::Capacity) => {
            return rpc_error_response(
                id,
                -32603,
                "The MCP request limit was reached.",
                None,
                state,
            );
        }
    };
    if cancellation.canceled.load(Ordering::Acquire) {
        return idempotency_error(id, GatewayInvokeError::Canceled, state);
    }
    let session_id = session_id.to_owned();
    let task_state = state.clone();
    let detached = async move {
        let _execution_permits = execution_permits;
        let state = &task_state;
        let execution_id = format!("mcp:{session_id}:{correlation}");
        let token_id = session.token_id.clone();
        let actor = ToolActor::api_token(token_id.clone(), Some(session.token_name));
        let arguments = Value::Object(params.arguments);
        let idempotency_key = mcp_idempotency_key(&session_id, &correlation);
        match params.name.as_str() {
            "execute" => {
                let request = idempotency_request(
                    &token_id,
                    &idempotency_key,
                    "executor.execute",
                    &arguments,
                );
                match prepare_execute(arguments) {
                    Ok(arguments) => {
                        run_idempotent_virtual(
                            state,
                            &request,
                            execute_virtual(state, &actor, &correlation, arguments),
                            cancellation_signal(&cancellation),
                        )
                        .await
                    }
                    Err(error) => Err(error),
                }
            }
            "call" => {
                call_virtual(
                    state,
                    &actor,
                    &execution_id,
                    &correlation,
                    arguments,
                    &idempotency_key,
                    cancellation_signal(&cancellation),
                )
                .await
            }
            "search" => {
                let request =
                    idempotency_request(&token_id, &idempotency_key, "executor.search", &arguments);
                match prepare_search(arguments) {
                    Ok(arguments) => {
                        run_idempotent_virtual(
                            state,
                            &request,
                            search_virtual(state, &actor, &execution_id, &correlation, arguments),
                            cancellation_signal(&cancellation),
                        )
                        .await
                    }
                    Err(error) => Err(error),
                }
            }
            "describe" => {
                let request = idempotency_request(
                    &token_id,
                    &idempotency_key,
                    "executor.describe",
                    &arguments,
                );
                match prepare_describe(arguments) {
                    Ok(arguments) => {
                        run_idempotent_virtual(
                            state,
                            &request,
                            describe_virtual(state, &actor, &execution_id, &correlation, arguments),
                            cancellation_signal(&cancellation),
                        )
                        .await
                    }
                    Err(error) => Err(error),
                }
            }
            "sources" => {
                let request = idempotency_request(
                    &token_id,
                    &idempotency_key,
                    "executor.sources",
                    &arguments,
                );
                match prepare_sources(arguments) {
                    Ok(()) => {
                        run_idempotent_virtual(
                            state,
                            &request,
                            sources_virtual(state, &actor, &execution_id, &correlation),
                            cancellation_signal(&cancellation),
                        )
                        .await
                    }
                    Err(error) => Err(error),
                }
            }
            _ => unreachable!("virtual tool names were validated before dispatch"),
        }
    };
    let (completed, result) = tokio::sync::oneshot::channel();
    if !state.tasks.spawn(async move {
        let _ = completed.send(detached.await);
    }) {
        return rpc_error_response(id, -32603, "MCP service is shutting down", None, state);
    }
    let result = match result.await {
        Ok(result) => result,
        Err(_) => return rpc_error_response(id, -32603, "Internal error", None, state),
    };
    match result {
        Ok(result) => tool_result_response(id, result, state),
        Err(VirtualToolError::Execution(error)) => {
            tracing::warn!(error = %error, "MCP TypeScript execution failed");
            tool_result_response(
                id,
                failure_result("execution_failed", "TypeScript execution failed."),
                state,
            )
        }
        Err(VirtualToolError::InvalidArguments) => {
            rpc_error_response(id, -32602, "Invalid params", None, state)
        }
        Err(VirtualToolError::Idempotency(error)) => idempotency_error(id, error, state),
    }
}

fn idempotency_request(
    token_id: &str,
    key: &str,
    callable_path: &str,
    arguments: &Value,
) -> McpIdempotencyRequest {
    McpIdempotencyRequest {
        owner_api_token_id: token_id.to_owned(),
        key: key.to_owned(),
        route: "POST /mcp tools/call".to_owned(),
        callable_path: callable_path.to_owned(),
        arguments: arguments.clone(),
    }
}

#[derive(Debug)]
enum VirtualToolError {
    InvalidArguments,
    Execution(ExecutionServiceError),
    Idempotency(GatewayInvokeError),
}

async fn run_idempotent_virtual<F>(
    state: &McpState,
    request: &McpIdempotencyRequest,
    operation: F,
    cancellation: CancellationSignal,
) -> Result<ToolResult, VirtualToolError>
where
    F: Future<Output = Result<ToolResult, VirtualToolError>>,
{
    let claim = state
        .tool_calls
        .claim_mcp_idempotency(request)
        .await
        .map_err(VirtualToolError::Idempotency)?;
    let reservation = match claim {
        McpIdempotencyClaim::Fresh(reservation) => *reservation,
        McpIdempotencyClaim::Replay(response) => return decode_idempotent_result(response),
        McpIdempotencyClaim::InProgress => {
            match state
                .tool_calls
                .wait_mcp_idempotency(request, cancellation.wait())
                .await
                .map_err(VirtualToolError::Idempotency)?
            {
                McpIdempotencyClaim::Fresh(reservation) => *reservation,
                McpIdempotencyClaim::Replay(response) => {
                    return decode_idempotent_result(response);
                }
                McpIdempotencyClaim::Indeterminate => {
                    return Err(VirtualToolError::Idempotency(
                        GatewayInvokeError::OutcomeUnknown,
                    ));
                }
                McpIdempotencyClaim::Mismatch => {
                    return Err(VirtualToolError::Idempotency(
                        GatewayInvokeError::KeyMismatch,
                    ));
                }
                McpIdempotencyClaim::InProgress => {
                    return Err(VirtualToolError::Idempotency(
                        GatewayInvokeError::InProgress,
                    ));
                }
            }
        }
        McpIdempotencyClaim::Indeterminate => {
            return Err(VirtualToolError::Idempotency(
                GatewayInvokeError::OutcomeUnknown,
            ));
        }
        McpIdempotencyClaim::Mismatch => {
            return Err(VirtualToolError::Idempotency(
                GatewayInvokeError::KeyMismatch,
            ));
        }
    };
    let execution = reservation
        .mark_executing()
        .await
        .map_err(VirtualToolError::Idempotency)?;
    let result = tokio::select! {
        result = operation => match result {
            Ok(result) => result,
            Err(error) => {
                execution
                    .mark_indeterminate()
                    .await
                    .map_err(VirtualToolError::Idempotency)?;
                return Err(error);
            }
        },
        () = cancellation.wait() => {
            execution
                .mark_indeterminate()
                .await
                .map_err(VirtualToolError::Idempotency)?;
            return Err(VirtualToolError::Idempotency(GatewayInvokeError::Canceled));
        }
    };
    let body = serde_json::to_vec(&result).map_err(|_| {
        VirtualToolError::Idempotency(GatewayInvokeError::Idempotency(
            "MCP result serialization failed".to_owned(),
        ))
    })?;
    execution
        .complete(McpIdempotencyBlob { body })
        .await
        .map_err(VirtualToolError::Idempotency)?;
    Ok(result)
}

fn decode_idempotent_result(response: McpIdempotencyBlob) -> Result<ToolResult, VirtualToolError> {
    serde_json::from_slice(&response.body).map_err(|_| {
        VirtualToolError::Idempotency(GatewayInvokeError::Idempotency(
            "stored MCP response was invalid".to_owned(),
        ))
    })
}

async fn call_virtual(
    state: &McpState,
    actor: &ToolActor,
    execution_id: &str,
    call_id: &str,
    arguments: Value,
    idempotency_key: &str,
    cancellation: CancellationSignal,
) -> Result<ToolResult, VirtualToolError> {
    let arguments = serde_json::from_value::<DirectCallArguments>(arguments)
        .map_err(|_| VirtualToolError::InvalidArguments)?;
    if arguments.path.is_empty() || arguments.path.len() > 512 {
        return Err(VirtualToolError::InvalidArguments);
    }
    let response = state
        .tool_calls
        .submit_mcp_idempotent(
            ToolCall {
                request_id: Uuid::new_v4().to_string(),
                actor: actor.clone(),
                surface: RequestSurface::Mcp,
                execution_id: execution_id.to_owned(),
                call_id: call_id.to_owned(),
                worker_generation: 0,
                path: arguments.path,
                arguments: Value::Object(arguments.arguments),
            },
            "POST /mcp tools/call",
            idempotency_key,
            cancellation.wait(),
        )
        .await
        .map_err(VirtualToolError::Idempotency)?;
    if response.replayed {
        tracing::debug!("replayed durable MCP call result");
    }
    Ok(response.result)
}

async fn execute_virtual(
    state: &McpState,
    actor: &ToolActor,
    correlation: &str,
    arguments: ExecuteArguments,
) -> Result<ToolResult, VirtualToolError> {
    let timeout_ms = arguments
        .timeout_ms
        .unwrap_or(DEFAULT_EXECUTION_TIMEOUT_MILLIS);
    if !(1..=MAX_EXECUTION_TIMEOUT_MILLIS).contains(&timeout_ms) {
        return Err(VirtualToolError::InvalidArguments);
    }
    let output = state
        .execution
        .execute(ExecuteCodeRequest {
            request_id: format!("mcp-{correlation}"),
            actor: actor.clone(),
            surface: RequestSurface::Mcp,
            code: arguments.code,
            timeout: Duration::from_millis(timeout_ms),
        })
        .await
        .map_err(VirtualToolError::Execution)?;
    Ok(success_result(json!({
        "executionId": output.execution_id,
        "result": output.result,
        "emits": output.emits,
        "console": output.console,
        "calls": output.calls
    })))
}

fn prepare_execute(arguments: Value) -> Result<ExecuteArguments, VirtualToolError> {
    let arguments = serde_json::from_value::<ExecuteArguments>(arguments)
        .map_err(|_| VirtualToolError::InvalidArguments)?;
    let timeout_ms = arguments
        .timeout_ms
        .unwrap_or(DEFAULT_EXECUTION_TIMEOUT_MILLIS);
    if arguments.code.len() > crate::runtime::MAX_SOURCE_BYTES
        || !(1..=MAX_EXECUTION_TIMEOUT_MILLIS).contains(&timeout_ms)
    {
        return Err(VirtualToolError::InvalidArguments);
    }
    Ok(arguments)
}

async fn search_virtual(
    state: &McpState,
    actor: &ToolActor,
    execution_id: &str,
    call_id: &str,
    arguments: SearchArguments,
) -> Result<ToolResult, VirtualToolError> {
    let call = discovery_call(
        actor,
        execution_id,
        call_id,
        "executor.search",
        serde_json::to_value(&arguments).expect("search arguments serialize"),
    );
    let result = match state
        .tool_calls
        .discover_search(
            &call,
            arguments.query,
            arguments.namespace,
            arguments.limit,
            arguments.offset,
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(error = %error, "MCP tool search failed");
            return Ok(failure_result("discovery_failed", "Tool search failed."));
        }
    };
    Ok(success_result(
        serde_json::to_value(result).expect("discovery result serializes"),
    ))
}

fn prepare_search(arguments: Value) -> Result<SearchArguments, VirtualToolError> {
    let arguments = serde_json::from_value::<SearchArguments>(arguments)
        .map_err(|_| VirtualToolError::InvalidArguments)?;
    if !(1..=100).contains(&arguments.limit) {
        return Err(VirtualToolError::InvalidArguments);
    }
    Ok(arguments)
}

async fn describe_virtual(
    state: &McpState,
    actor: &ToolActor,
    execution_id: &str,
    call_id: &str,
    arguments: DescribeArguments,
) -> Result<ToolResult, VirtualToolError> {
    let call = discovery_call(
        actor,
        execution_id,
        call_id,
        "executor.describe",
        json!({ "path": arguments.path }),
    );
    let result = match state
        .tool_calls
        .discover_describe(&call, &arguments.path)
        .await
    {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(error = %error, "MCP tool description failed");
            return Ok(failure_result(
                "discovery_failed",
                "Tool description failed.",
            ));
        }
    };
    Ok(success_result(
        serde_json::to_value(result).expect("description serializes"),
    ))
}

fn prepare_describe(arguments: Value) -> Result<DescribeArguments, VirtualToolError> {
    let arguments = serde_json::from_value::<DescribeArguments>(arguments)
        .map_err(|_| VirtualToolError::InvalidArguments)?;
    if arguments.path.is_empty() || arguments.path.len() > 512 {
        return Err(VirtualToolError::InvalidArguments);
    }
    Ok(arguments)
}

async fn sources_virtual(
    state: &McpState,
    actor: &ToolActor,
    execution_id: &str,
    call_id: &str,
) -> Result<ToolResult, VirtualToolError> {
    let call = discovery_call(actor, execution_id, call_id, "executor.sources", json!({}));
    let result = match state.tool_calls.discover_sources(&call).await {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(error = %error, "MCP source discovery failed");
            return Ok(failure_result(
                "discovery_failed",
                "Source discovery failed.",
            ));
        }
    };
    Ok(success_result(json!({ "sources": result })))
}

fn prepare_sources(arguments: Value) -> Result<(), VirtualToolError> {
    if arguments
        .as_object()
        .is_none_or(|arguments| !arguments.is_empty())
    {
        return Err(VirtualToolError::InvalidArguments);
    }
    Ok(())
}

fn discovery_call(
    actor: &ToolActor,
    execution_id: &str,
    call_id: &str,
    path: &str,
    arguments: Value,
) -> ToolCall {
    ToolCall {
        request_id: Uuid::new_v4().to_string(),
        actor: actor.clone(),
        surface: RequestSurface::Mcp,
        execution_id: execution_id.to_owned(),
        call_id: call_id.to_owned(),
        worker_generation: 0,
        path: path.to_owned(),
        arguments,
    }
}

fn success_result(data: Value) -> ToolResult {
    ToolResult {
        ok: true,
        data: Some(data),
        error: None,
        http: None,
    }
}

fn failure_result(code: &str, message: &str) -> ToolResult {
    ToolResult {
        ok: false,
        data: None,
        error: Some(crate::invocation::PublicToolError {
            code: code.to_owned(),
            message: message.to_owned(),
        }),
        http: None,
    }
}

fn virtual_tools() -> Vec<McpTool> {
    vec![
        McpTool {
            name: "execute".to_owned(),
            title: "Execute TypeScript".to_owned(),
            description: Some(
                "Run sandboxed TypeScript that can discover and call multiple Executor tools concurrently."
                    .to_owned(),
            ),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["code"],
                "properties": {
                    "code": { "type": "string" },
                    "timeoutMs": { "type": "integer", "minimum": 1, "maximum": MAX_EXECUTION_TIMEOUT_MILLIS }
                }
            }),
            output_schema: Some(generic_output_schema()),
        },
        McpTool {
            name: "call".to_owned(),
            title: "Call Tool".to_owned(),
            description: Some(
                "Call one enabled Executor tool. Ask-mode tools wait for administrator approval."
                    .to_owned(),
            ),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" },
                    "arguments": { "type": "object", "additionalProperties": true }
                }
            }),
            output_schema: None,
        },
        McpTool {
            name: "search".to_owned(),
            title: "Search Tools".to_owned(),
            description: Some("Search the enabled global Executor tool catalog.".to_owned()),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["query"],
                "properties": {
                    "query": { "type": "string" },
                    "namespace": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                    "offset": { "type": "integer", "minimum": 0, "default": 0 }
                }
            }),
            output_schema: Some(generic_output_schema()),
        },
        McpTool {
            name: "describe".to_owned(),
            title: "Describe Tool".to_owned(),
            description: Some("Read the schemas and metadata for one enabled Executor tool.".to_owned()),
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["path"],
                "properties": { "path": { "type": "string" } }
            }),
            output_schema: Some(generic_output_schema()),
        },
        McpTool {
            name: "sources".to_owned(),
            title: "List Sources".to_owned(),
            description: Some("List sources with tools visible through the global catalog.".to_owned()),
            input_schema: json!({ "type": "object", "additionalProperties": false }),
            output_schema: Some(json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["sources"],
                "properties": {
                    "sources": { "type": "array", "items": { "type": "object" } }
                }
            })),
        },
    ]
}

fn generic_output_schema() -> Value {
    json!({ "type": "object", "additionalProperties": true })
}

fn tool_result_response(id: Option<Value>, result: ToolResult, state: &McpState) -> Response {
    let serialized = serde_json::to_string(&result).unwrap_or_else(|_| "null".to_owned());
    let structured = result
        .data
        .as_ref()
        .and_then(Value::as_object)
        .map(|object| Value::Object(object.clone()));
    let mut response = Map::from_iter([
        (
            "content".to_owned(),
            json!([{ "type": "text", "text": serialized }]),
        ),
        ("isError".to_owned(), Value::Bool(!result.ok)),
    ]);
    if let Some(structured) = structured {
        response.insert("structuredContent".to_owned(), structured);
    }
    rpc_result_response(id, Value::Object(response), None, state)
}

fn idempotency_error(id: Option<Value>, error: GatewayInvokeError, state: &McpState) -> Response {
    let (code, message) = match error {
        GatewayInvokeError::ToolCall(error) => return tool_call_failure(id, error, state),
        GatewayInvokeError::KeyMismatch => (-32600, "The JSON-RPC request ID was reused."),
        GatewayInvokeError::OutcomeUnknown => (-32603, "The prior invocation outcome is unknown."),
        GatewayInvokeError::InProgress => (-32603, "The invocation is still in progress."),
        GatewayInvokeError::Canceled => (-32603, "The invocation wait was canceled."),
        GatewayInvokeError::InvalidKey
        | GatewayInvokeError::Capacity
        | GatewayInvokeError::Idempotency(_) => {
            tracing::warn!(error = %error, "MCP idempotent invocation failed");
            (-32603, "The invocation could not be completed safely.")
        }
    };
    rpc_error_response(id, code, message, None, state)
}

fn tool_call_failure(id: Option<Value>, error: ToolCallError, state: &McpState) -> Response {
    match error {
        ToolCallError::Catalog(CatalogError::ToolNotFound { .. })
        | ToolCallError::Catalog(CatalogError::NotFound { .. })
        | ToolCallError::Catalog(CatalogError::ToolDisabled { .. })
        | ToolCallError::InvalidArguments
        | ToolCallError::ArgumentsTooLarge => rpc_error_response(
            id,
            -32602,
            "The tool or its arguments are invalid.",
            None,
            state,
        ),
        error => {
            tracing::warn!(error = %error, "MCP tool invocation failed");
            tool_result_response(
                id,
                failure_result(
                    "tool_call_failed",
                    "The tool call could not be completed safely.",
                ),
                state,
            )
        }
    }
}

fn rpc_result_response(
    id: Option<Value>,
    result: Value,
    session_id: Option<&str>,
    state: &McpState,
) -> Response {
    json_response(
        StatusCode::OK,
        json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result }),
        session_id,
        state,
    )
}

fn rpc_error_response(
    id: Option<Value>,
    code: i64,
    message: &'static str,
    data: Option<Value>,
    state: &McpState,
) -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "jsonrpc": "2.0",
            "id": id.unwrap_or(Value::Null),
            "error": { "code": code, "message": message, "data": data }
        }),
        None,
        state,
    )
}

fn json_response(
    status: StatusCode,
    body: Value,
    session_id: Option<&str>,
    state: &McpState,
) -> Response {
    let mut response = (status, axum::Json(body)).into_response();
    if let Some(session_id) = session_id {
        response.headers_mut().insert(
            SESSION_HEADER,
            HeaderValue::from_str(session_id).expect("UUID session IDs are valid headers"),
        );
    }
    add_cors_headers(response.headers_mut(), state);
    response
}

#[derive(Debug)]
struct TransportError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    authenticate: bool,
}

impl TransportError {
    fn bad_request(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    fn unauthorized(code: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
            message,
            authenticate: true,
        }
    }

    fn forbidden(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    fn not_found(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }

    fn not_acceptable(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::NOT_ACCEPTABLE, code, message)
    }

    fn service_unavailable(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, code, message)
    }

    fn too_many_requests(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, code, message)
    }

    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            authenticate: false,
        }
    }
}

impl IntoResponse for TransportError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            axum::Json(json!({ "error": { "code": self.code, "message": self.message } })),
        )
            .into_response();
        if self.authenticate {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"executor-mcp\""),
            );
        }
        response
    }
}

async fn authenticate(state: &McpState, headers: &HeaderMap) -> Result<Identity, TransportError> {
    let authorization =
        unique_text_header(headers, header::AUTHORIZATION.as_str())?.ok_or_else(|| {
            TransportError::unauthorized("unauthorized", "A valid Executor API token is required.")
        })?;
    let mut parts = authorization.split_ascii_whitespace();
    let scheme = parts.next();
    let token = parts.next();
    if !scheme.is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer"))
        || token.is_none()
        || parts.next().is_some()
    {
        return Err(TransportError::unauthorized(
            "unauthorized",
            "A valid Executor API token is required.",
        ));
    }
    let token = token.unwrap_or_default();
    if token.is_empty() || token.len() > MAX_BEARER_TOKEN_BYTES {
        return Err(TransportError::unauthorized(
            "unauthorized",
            "A valid Executor API token is required.",
        ));
    }
    let digest = state.database.keyring.digest("api-token", token.as_bytes());
    let identity = sqlx::query_as::<_, (String, String, Option<i64>)>(
        "SELECT id, name, last_used_at FROM api_tokens WHERE token_digest = ? AND revoked_at IS NULL",
    )
    .bind(digest.to_vec())
    .fetch_optional(&state.database.pool)
    .await
    .map_err(|error| {
        tracing::error!(error = %error, "MCP token authentication failed");
        TransportError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "The request could not be authenticated.",
        )
    })?
    .ok_or_else(|| {
        TransportError::unauthorized(
            "unauthorized",
            "A valid Executor API token is required.",
        )
    })?;
    let now = unix_timestamp();
    if identity
        .2
        .is_none_or(|last_used_at| last_used_at <= now - 60)
    {
        let _ = sqlx::query(
            "UPDATE api_tokens SET last_used_at = ? WHERE id = ? AND revoked_at IS NULL AND (last_used_at IS NULL OR last_used_at <= ?)",
        )
        .bind(now)
        .bind(&identity.0)
        .bind(now - 60)
        .execute(&state.database.pool)
        .await;
    }
    Ok(Identity {
        token_id: identity.0,
        token_name: identity.1,
    })
}

fn validate_origin(state: &McpState, headers: &HeaderMap) -> Result<(), TransportError> {
    let Some(origin) = unique_text_header(headers, header::ORIGIN.as_str())? else {
        return Ok(());
    };
    if origin == state.origin.as_ref() {
        Ok(())
    } else {
        Err(TransportError::forbidden(
            "invalid_origin",
            "The request Origin does not match this Executor instance.",
        ))
    }
}

fn validate_connection(state: &McpState, headers: &HeaderMap) -> Result<(), TransportError> {
    validate_host(state, headers)?;
    validate_origin(state, headers)
}

fn validate_host(state: &McpState, headers: &HeaderMap) -> Result<(), TransportError> {
    let host = unique_text_header(headers, header::HOST.as_str())?.ok_or_else(|| {
        TransportError::bad_request("missing_host", "Host is required for the MCP endpoint.")
    })?;
    if host.len() > 512 || host.contains(['/', '\\', '@', '#', '?']) {
        return Err(TransportError::forbidden(
            "invalid_host",
            "Host does not match this Executor instance.",
        ));
    }
    let candidate =
        Url::parse(&format!("{}://{host}", state.origin_url.scheme())).map_err(|_| {
            TransportError::forbidden(
                "invalid_host",
                "Host does not match this Executor instance.",
            )
        })?;
    let matches = candidate.host() == state.origin_url.host()
        && candidate.port_or_known_default() == state.origin_url.port_or_known_default();
    if matches {
        Ok(())
    } else {
        Err(TransportError::forbidden(
            "invalid_host",
            "Host does not match this Executor instance.",
        ))
    }
}

fn validate_post_headers(headers: &HeaderMap) -> Result<(), TransportError> {
    let content_type =
        unique_text_header(headers, header::CONTENT_TYPE.as_str())?.ok_or_else(|| {
            TransportError::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_content_type",
                "POST /mcp requires Content-Type: application/json.",
            )
        })?;
    let mut content_type_parts = content_type.split(';');
    let media_type_matches = content_type_parts
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    let parameters_valid = content_type_parts.all(|parameter| {
        parameter
            .trim()
            .split_once('=')
            .is_some_and(|(name, value)| {
                name.trim().eq_ignore_ascii_case("charset")
                    && value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
            })
    });
    if !media_type_matches || !parameters_valid {
        return Err(TransportError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_content_type",
            "POST /mcp requires Content-Type: application/json.",
        ));
    }
    if !accepts(headers, "application/json") || !accepts(headers, "text/event-stream") {
        return Err(TransportError::not_acceptable(
            "unsupported_accept",
            "POST /mcp requires Accept for application/json and text/event-stream.",
        ));
    }
    Ok(())
}

fn require_protocol_version(headers: &HeaderMap) -> Result<(), TransportError> {
    let version = unique_text_header(headers, PROTOCOL_HEADER)?.ok_or_else(|| {
        TransportError::bad_request(
            "missing_protocol_version",
            "MCP-Protocol-Version is required after initialization.",
        )
    })?;
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(TransportError::bad_request(
            "unsupported_protocol_version",
            "MCP-Protocol-Version is not supported.",
        ))
    }
}

fn unique_text_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, TransportError> {
    let values = headers.get_all(name);
    let mut values = values.iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(TransportError::bad_request(
            "duplicate_header",
            "A security-sensitive header was repeated.",
        ));
    }
    value.to_str().map(Some).map_err(|_| {
        TransportError::bad_request("invalid_header", "A request header is not valid text.")
    })
}

fn accepts(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|item| {
            let mut segments = item.split(';');
            let media_type = segments.next().unwrap_or_default().trim();
            let rejected = segments.any(|parameter| {
                parameter
                    .trim()
                    .split_once('=')
                    .is_some_and(|(name, value)| {
                        name.trim().eq_ignore_ascii_case("q")
                            && value
                                .trim()
                                .parse::<f32>()
                                .is_ok_and(|quality| quality <= 0.0)
                    })
            });
            !rejected && (media_type == "*/*" || media_type.eq_ignore_ascii_case(expected))
        })
}

fn add_cors_headers(headers: &mut HeaderMap, state: &McpState) {
    if let Ok(origin) = HeaderValue::from_str(&state.origin) {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, GET, DELETE, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(
            "Authorization, Content-Type, Accept, MCP-Session-Id, MCP-Protocol-Version",
        ),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("MCP-Session-Id"),
    );
}

fn decode_optional_params<T>(value: Value) -> Result<T, ()>
where
    T: for<'de> Deserialize<'de> + Default,
{
    if value.is_null() {
        Ok(T::default())
    } else {
        serde_json::from_value(value).map_err(|_| ())
    }
}

fn empty_arguments() -> Map<String, Value> {
    Map::new()
}

fn default_search_limit() -> u32 {
    20
}

fn rpc_id_string(id: &Value) -> String {
    match id {
        Value::String(value) => format!("s:{value}"),
        Value::Number(value) => format!("n:{value}"),
        _ => "invalid".to_owned(),
    }
}

fn mcp_idempotency_key(session_id: &str, request_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"executor-mcp-idempotency-v1");
    digest.update((session_id.len() as u64).to_be_bytes());
    digest.update(session_id.as_bytes());
    digest.update((request_id.len() as u64).to_be_bytes());
    digest.update(request_id.as_bytes());
    format!("mcp_{:x}", digest.finalize())
}

fn request_cancellation_key(session_id: &str, request_id: &str) -> String {
    format!("{session_id}\0{request_id}")
}

fn cancellation_signal(registration: &CancellationRegistration) -> CancellationSignal {
    CancellationSignal {
        notify: registration.notify.clone(),
        canceled: registration.canceled.clone(),
    }
}

impl CancellationSignal {
    async fn wait(&self) {
        if self.canceled.load(Ordering::Acquire) {
            return;
        }
        let notified = self.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.canceled.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

fn valid_request_id(id: &Value) -> bool {
    match id {
        Value::String(value) => value.len() <= 256 && !value.contains('\0'),
        Value::Number(_) => true,
        _ => false,
    }
}

fn valid_jsonrpc_error(error: &Value) -> bool {
    error.as_object().is_some_and(|error| {
        error.get("code").and_then(Value::as_i64).is_some()
            && error.get("message").and_then(Value::as_str).is_some()
    })
}

#[cfg(test)]
mod tests;
