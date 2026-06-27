use std::{
    sync::{
        Arc, Mutex as StateMutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use reqwest::{
    Method, StatusCode,
    header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue},
};
use rmcp::model::{CallToolResult, ProtocolVersion};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::sync::{Notify, RwLock as AsyncRwLock, broadcast, oneshot};
use url::{Host, Url};

#[cfg(test)]
use crate::outbound::OutboundResponse;
use crate::outbound::{
    HardenedHttpClient, OutboundError, OutboundPolicy, OutboundRequest, OutboundStreamResponse,
    parse_url,
};

pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-11-25";
const SUPPORTED_PROTOCOL_VERSIONS: [&str; 2] = [DEFAULT_PROTOCOL_VERSION, "2025-06-18"];

pub(crate) fn is_supported_protocol_version(version: &str) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

const MCP_SESSION_ID: HeaderName = HeaderName::from_static("mcp-session-id");
const MCP_PROTOCOL_VERSION: HeaderName = HeaderName::from_static("mcp-protocol-version");
const LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");
const MAX_SESSION_ID_BYTES: usize = 1024;
const MAX_SSE_EVENTS: usize = 1024;
const MAX_SSE_RECONNECTS: usize = 3;
const MAX_LOGICAL_STREAM_BYTES: usize = 16 * 1024 * 1024;
const MCP_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);
const NOTIFICATION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const SESSION_TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct StreamableHttpConfig {
    pub endpoint: String,
    pub headers: HeaderMap,
    pub allow_private_networks: bool,
    pub protocol_version: String,
    pub client_name: String,
    pub client_version: String,
}

impl StreamableHttpConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            headers: HeaderMap::new(),
            allow_private_networks: false,
            protocol_version: DEFAULT_PROTOCOL_VERSION.to_owned(),
            client_name: "executor".to_owned(),
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListToolsPage {
    pub tools: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Error)]
pub enum StreamableHttpError {
    #[error("the MCP HTTP configuration contains a reserved header")]
    ReservedHeader,
    #[error("the MCP protocol version is invalid")]
    InvalidProtocolVersion,
    #[error("the MCP client name or version is invalid")]
    InvalidClientInfo,
    #[error("the MCP request is not a valid JSON-RPC message")]
    InvalidRequest,
    #[error("the MCP response is not valid UTF-8")]
    InvalidUtf8,
    #[error("the MCP response has an unsupported content type")]
    UnsupportedContentType,
    #[error("the MCP response is malformed")]
    InvalidResponse,
    #[error("the MCP server returned HTTP {0}")]
    HttpStatus(StatusCode),
    #[error("the MCP session expired")]
    SessionExpired,
    #[error("the MCP session was invalidated while the request was in flight")]
    SessionInvalidated,
    #[error("the MCP server returned an invalid session identifier")]
    InvalidSessionId,
    #[error("the MCP server changed the active session identifier")]
    SessionChanged,
    #[error("the MCP server selected an unsupported protocol version")]
    ProtocolVersionMismatch,
    #[error("MCP HTTP endpoints must use HTTPS, except for loopback HTTP")]
    InsecureEndpoint,
    #[error("the MCP transport has not been initialized")]
    NotInitialized,
    #[error("the MCP transport is already initialized")]
    AlreadyInitialized,
    #[error("the MCP server returned a JSON-RPC error")]
    JsonRpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Outbound(#[from] OutboundError),
}

#[derive(Default)]
struct TransportState {
    session_id: Option<String>,
    negotiated_protocol_version: Option<ProtocolVersion>,
    initialized: bool,
    generation: u64,
}

#[derive(Default)]
struct SessionTerminationTracker {
    pending: AtomicUsize,
    drained: Notify,
}

impl SessionTerminationTracker {
    fn start(self: &Arc<Self>) -> SessionTerminationPermit {
        self.pending.fetch_add(1, Ordering::AcqRel);
        SessionTerminationPermit {
            tracker: self.clone(),
        }
    }

    async fn wait(&self) {
        while self.pending.load(Ordering::Acquire) != 0 {
            self.drained.notified().await;
        }
    }

    fn has_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire) != 0
    }
}

struct SessionTerminationPermit {
    tracker: Arc<SessionTerminationTracker>,
}

impl Drop for SessionTerminationPermit {
    fn drop(&mut self) {
        self.tracker.pending.fetch_sub(1, Ordering::AcqRel);
        self.tracker.drained.notify_one();
    }
}

#[cfg(test)]
#[derive(Default)]
struct InitializationCleanupInterleave {
    drained: Notify,
    resume: Notify,
}

struct InitializationGuard {
    state: Arc<StateMutex<TransportState>>,
    client: HardenedHttpClient,
    endpoint: Url,
    headers: HeaderMap,
    requested_protocol_version: ProtocolVersion,
    session_terminations: Arc<SessionTerminationTracker>,
    generation: u64,
    committed: bool,
}

impl InitializationGuard {
    fn new(transport: &StreamableHttpTransport, generation: u64) -> Self {
        Self {
            state: transport.state.clone(),
            client: transport.client.clone(),
            endpoint: transport.endpoint.clone(),
            headers: transport.headers.clone(),
            requested_protocol_version: transport.requested_protocol_version.clone(),
            session_terminations: transport.session_terminations.clone(),
            generation,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for InitializationGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let cleanup = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.generation != self.generation {
                return;
            }
            state.generation = state.generation.wrapping_add(1);
            let session_id = state.session_id.take();
            let protocol_version = state
                .negotiated_protocol_version
                .take()
                .unwrap_or_else(|| self.requested_protocol_version.clone());
            state.initialized = false;
            session_id.map(|session_id| {
                (
                    session_id,
                    protocol_version,
                    self.session_terminations.start(),
                )
            })
        };
        if let Some((session_id, protocol_version, permit)) = cleanup {
            let _ = spawn_session_termination(
                self.client.clone(),
                self.endpoint.clone(),
                self.headers.clone(),
                session_id,
                protocol_version,
                permit,
            );
        }
    }
}

#[derive(Clone)]
/// Hardened request-response Streamable HTTP transport.
///
/// SSE responses are processed incrementally with bounded events, bytes, and
/// deadlines. Interrupted streams resume through GET and `Last-Event-ID` when
/// the server supplied both a session and an event identifier.
pub struct StreamableHttpTransport {
    endpoint: Url,
    headers: HeaderMap,
    client: HardenedHttpClient,
    requested_protocol_version: ProtocolVersion,
    client_name: Arc<str>,
    client_version: Arc<str>,
    state: Arc<StateMutex<TransportState>>,
    lifecycle: Arc<AsyncRwLock<()>>,
    session_terminations: Arc<SessionTerminationTracker>,
    #[cfg(test)]
    initialization_cleanup_interleave:
        Arc<StateMutex<Option<Arc<InitializationCleanupInterleave>>>>,
    tool_list_changed: broadcast::Sender<()>,
}

impl StreamableHttpTransport {
    pub fn new(config: StreamableHttpConfig) -> Result<Self, StreamableHttpError> {
        validate_custom_headers(&config.headers)?;
        let requested_protocol_version =
            serde_json::from_value::<ProtocolVersion>(Value::String(config.protocol_version))
                .map_err(|_| StreamableHttpError::InvalidProtocolVersion)?;
        if requested_protocol_version != ProtocolVersion::V_2025_11_25 {
            return Err(StreamableHttpError::InvalidProtocolVersion);
        }
        if config.client_name.trim().is_empty()
            || config.client_version.trim().is_empty()
            || config.client_name.len() > 256
            || config.client_version.len() > 256
        {
            return Err(StreamableHttpError::InvalidClientInfo);
        }
        let policy = OutboundPolicy {
            allow_private_networks: config.allow_private_networks,
            require_https_or_loopback: true,
            max_redirects: 0,
            ..OutboundPolicy::default()
        };
        if let Ok(endpoint) = Url::parse(&config.endpoint)
            && endpoint.scheme() == "http"
        {
            validate_transport_endpoint(&endpoint)?;
        }
        let endpoint = parse_url(&config.endpoint, &policy)?;
        validate_transport_endpoint(&endpoint)?;
        let (tool_list_changed, _) = broadcast::channel(16);
        Ok(Self {
            endpoint,
            headers: config.headers,
            client: HardenedHttpClient::new(policy),
            requested_protocol_version,
            client_name: Arc::from(config.client_name),
            client_version: Arc::from(config.client_version),
            state: Arc::new(StateMutex::new(TransportState::default())),
            lifecycle: Arc::new(AsyncRwLock::new(())),
            session_terminations: Arc::new(SessionTerminationTracker::default()),
            #[cfg(test)]
            initialization_cleanup_interleave: Arc::new(StateMutex::new(None)),
            tool_list_changed,
        })
    }

    pub async fn initialize(&self) -> Result<Value, StreamableHttpError> {
        validate_transport_endpoint(&self.endpoint)?;
        let _lifecycle = self.lifecycle.write().await;
        let generation = loop {
            self.session_terminations.wait().await;
            #[cfg(test)]
            {
                let interleave = self
                    .initialization_cleanup_interleave
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                if let Some(interleave) = interleave {
                    interleave.drained.notify_one();
                    interleave.resume.notified().await;
                }
            }
            let state = self.lock_state();
            if self.session_terminations.has_pending() {
                continue;
            }
            if state.initialized {
                return Err(StreamableHttpError::AlreadyInitialized);
            }
            break state.generation;
        };
        let mut initialization = InitializationGuard::new(self, generation);

        let id = json!(0);
        let result = self
            .request_result(
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": self.requested_protocol_version,
                        "capabilities": {},
                        "clientInfo": {
                            "name": self.client_name.as_ref(),
                            "version": self.client_version.as_ref()
                        }
                    }
                }),
                &id,
                false,
                true,
            )
            .await?;
        let Some(selected_version_value) = result
            .as_object()
            .and_then(|result| result.get("protocolVersion"))
        else {
            return Err(StreamableHttpError::InvalidResponse);
        };
        let selected_version =
            serde_json::from_value::<ProtocolVersion>(selected_version_value.clone())
                .map_err(|_| StreamableHttpError::InvalidResponse)?;
        if !is_supported_protocol_version(selected_version.as_str()) {
            return Err(StreamableHttpError::ProtocolVersionMismatch);
        }
        self.lock_state().negotiated_protocol_version = Some(selected_version);

        let notification = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        self.send_internal(notification, false, false).await?;
        self.lock_state().initialized = true;
        initialization.commit();
        Ok(result)
    }

    pub async fn list_tools(
        &self,
        cursor: Option<&str>,
        id: Value,
    ) -> Result<ListToolsPage, StreamableHttpError> {
        validate_id(&id)?;
        let mut params = Map::new();
        if let Some(cursor) = cursor {
            params.insert("cursor".to_owned(), Value::String(cursor.to_owned()));
        }
        let result = self
            .request_result(
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/list",
                    "params": params
                }),
                &id,
                true,
                false,
            )
            .await?;
        let result = result
            .as_object()
            .ok_or(StreamableHttpError::InvalidResponse)?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .ok_or(StreamableHttpError::InvalidResponse)?;
        if tools.iter().any(|tool| !tool.is_object()) {
            return Err(StreamableHttpError::InvalidResponse);
        }
        let next_cursor = match result.get("nextCursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(cursor)) => Some(cursor.clone()),
            Some(_) => return Err(StreamableHttpError::InvalidResponse),
        };
        Ok(ListToolsPage { tools, next_cursor })
    }

    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
        id: Value,
    ) -> Result<Value, StreamableHttpError> {
        validate_id(&id)?;
        if name.is_empty() || name.len() > 1024 || !arguments.is_object() {
            return Err(StreamableHttpError::InvalidRequest);
        }
        let result = self
            .request_result(
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": name, "arguments": arguments }
                }),
                &id,
                true,
                false,
            )
            .await?;
        validate_call_tool_result(&result)?;
        Ok(result)
    }

    pub async fn terminate(&self) -> Result<(), StreamableHttpError> {
        validate_transport_endpoint(&self.endpoint)?;
        let _lifecycle = self.lifecycle.write().await;
        let cleanup = loop {
            self.session_terminations.wait().await;
            let mut state = self.lock_state();
            if self.session_terminations.has_pending() {
                continue;
            }
            state.generation = state.generation.wrapping_add(1);
            let session_id = state.session_id.take();
            let protocol_version = state.negotiated_protocol_version.take();
            state.initialized = false;
            break session_id.map(|session_id| {
                (
                    session_id,
                    protocol_version,
                    self.session_terminations.start(),
                )
            });
        };
        let Some((session_id, protocol_version, permit)) = cleanup else {
            return Ok(());
        };
        let protocol_version =
            protocol_version.unwrap_or_else(|| self.requested_protocol_version.clone());
        let result = spawn_session_termination(
            self.client.clone(),
            self.endpoint.clone(),
            self.headers.clone(),
            session_id,
            protocol_version,
            permit,
        )?;
        let status = result
            .await
            .map_err(|_| StreamableHttpError::InvalidResponse)??;
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(StreamableHttpError::HttpStatus(status))
        }
    }

    #[cfg(test)]
    async fn session_id(&self) -> Option<String> {
        self.lock_state().session_id.clone()
    }

    /// Signals are coalescible. A lagged receiver should perform one refresh
    /// and then continue receiving rather than attempting to count events.
    pub fn subscribe_tool_list_changed(&self) -> broadcast::Receiver<()> {
        self.tool_list_changed.subscribe()
    }

    /// Runs the optional standalone GET SSE stream until it closes or fails.
    /// The caller owns cancellation and may restart this future after errors.
    pub async fn listen_notifications(&self) -> Result<(), StreamableHttpError> {
        validate_transport_endpoint(&self.endpoint)?;
        let (session_id, protocol_version, generation) = {
            let state = self.lock_state();
            if !state.initialized {
                return Err(StreamableHttpError::NotInitialized);
            }
            (
                state.session_id.clone(),
                state.negotiated_protocol_version.clone(),
                state.generation,
            )
        };
        let protocol_version = protocol_version.ok_or(StreamableHttpError::NotInitialized)?;
        let mut response = self
            .open_notification_stream(session_id.as_deref(), &protocol_version, None, true)
            .await?;
        let mut decoder = SseDecoder::default();
        loop {
            if self.lock_state().generation != generation {
                return Err(StreamableHttpError::SessionInvalidated);
            }
            if response.status == StatusCode::NOT_FOUND {
                self.reset_state_if_generation(generation).await;
                return Err(StreamableHttpError::SessionExpired);
            }
            if response.status != StatusCode::OK {
                return Err(StreamableHttpError::HttpStatus(response.status));
            }
            self.accept_response_session_or_reset(&response.headers, generation, false)
                .await?;
            if response.declared_response_too_large() {
                return Err(OutboundError::ResponseBodyTooLarge.into());
            }
            if response_content_type(&response.headers)? != ResponseContentType::Sse {
                return Err(StreamableHttpError::UnsupportedContentType);
            }
            loop {
                match response.next_chunk().await {
                    Ok(Some(chunk)) => {
                        for event in decoder.push(&chunk)? {
                            if let Some(message) = event.message {
                                self.handle_server_message(&message, generation).await?;
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(error) if resumable_stream_error(&error) => {
                        decoder.reset_stream();
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            for event in decoder.finish()? {
                if let Some(message) = event.message {
                    self.handle_server_message(&message, generation).await?;
                }
            }
            let last_event_id = decoder.last_event_id().map(str::to_owned);
            let retry_delay = decoder.retry_delay();
            if !retry_delay.is_zero() {
                tokio::time::sleep(retry_delay).await;
            }
            self.ensure_generation(generation).await?;
            decoder.reset_connection_limits();
            response = self
                .open_notification_stream(
                    session_id.as_deref(),
                    &protocol_version,
                    last_event_id.as_deref(),
                    true,
                )
                .await?;
        }
    }

    async fn request_result(
        &self,
        request: Value,
        id: &Value,
        require_initialized: bool,
        accept_new_session: bool,
    ) -> Result<Value, StreamableHttpError> {
        let messages = self
            .send_internal(request, require_initialized, accept_new_session)
            .await?;
        response_result(messages, id)
    }

    async fn send_internal(
        &self,
        message: Value,
        require_initialized: bool,
        accept_new_session: bool,
    ) -> Result<Vec<Value>, StreamableHttpError> {
        let _lifecycle = if require_initialized {
            Some(self.lifecycle.read().await)
        } else {
            None
        };
        tokio::time::timeout(
            MCP_TOTAL_TIMEOUT,
            self.send_internal_with_deadline(message, require_initialized, accept_new_session),
        )
        .await
        .map_err(|_| StreamableHttpError::Outbound(OutboundError::Timeout))?
    }

    async fn send_internal_with_deadline(
        &self,
        message: Value,
        require_initialized: bool,
        accept_new_session: bool,
    ) -> Result<Vec<Value>, StreamableHttpError> {
        validate_transport_endpoint(&self.endpoint)?;
        validate_outgoing_message(&message)?;
        let (session_id, protocol_version, generation) = {
            let state = self.lock_state();
            if require_initialized && !state.initialized {
                return Err(StreamableHttpError::NotInitialized);
            }
            (
                state.session_id.clone(),
                state.negotiated_protocol_version.clone(),
                state.generation,
            )
        };
        let mut headers = self.headers.clone();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(session_id) = session_id.as_deref() {
            headers.insert(
                MCP_SESSION_ID,
                HeaderValue::from_str(session_id)
                    .map_err(|_| StreamableHttpError::InvalidSessionId)?,
            );
        }
        if let Some(protocol_version) = protocol_version.as_ref() {
            headers.insert(
                MCP_PROTOCOL_VERSION,
                HeaderValue::from_str(protocol_version.as_str())
                    .map_err(|_| StreamableHttpError::InvalidProtocolVersion)?,
            );
        }
        let awaited_id = message
            .as_object()
            .and_then(|message| message.get("method"))
            .and_then(|_| message.get("id"))
            .cloned();
        let response = self
            .client
            .execute_streaming_headers_first(OutboundRequest {
                method: Method::POST,
                url: self.endpoint.clone(),
                headers,
                body: serde_json::to_vec(&message)?,
            })
            .await?;
        self.accept_streaming_response(
            response,
            generation,
            accept_new_session,
            session_id.as_deref(),
            protocol_version.as_ref(),
            awaited_id.as_ref(),
        )
        .await
    }

    async fn accept_streaming_response(
        &self,
        mut response: OutboundStreamResponse,
        generation: u64,
        accept_new_session: bool,
        session_id: Option<&str>,
        protocol_version: Option<&ProtocolVersion>,
        awaited_id: Option<&Value>,
    ) -> Result<Vec<Value>, StreamableHttpError> {
        if self.lock_state().generation != generation {
            return Err(StreamableHttpError::SessionInvalidated);
        }
        if response.status == StatusCode::NOT_FOUND && session_id.is_some() {
            self.reset_state_if_generation(generation).await;
            return Err(StreamableHttpError::SessionExpired);
        }
        if !response.status.is_success() {
            return Err(StreamableHttpError::HttpStatus(response.status));
        }
        if let Err(error) = self
            .accept_response_session(&response.headers, generation, accept_new_session)
            .await
        {
            if matches!(
                error,
                StreamableHttpError::InvalidSessionId | StreamableHttpError::SessionChanged
            ) {
                self.terminate_state_session_if_generation(generation).await;
            }
            return Err(error);
        }
        if response.declared_response_too_large() {
            return Err(OutboundError::ResponseBodyTooLarge.into());
        }
        let active_session_id = {
            let state = self.lock_state();
            if state.generation != generation {
                return Err(StreamableHttpError::SessionInvalidated);
            }
            state.session_id.clone()
        };
        if awaited_id.is_none() {
            if response.status == StatusCode::ACCEPTED && response.next_chunk().await?.is_none() {
                self.ensure_generation(generation).await?;
                return Ok(Vec::new());
            }
            return Err(StreamableHttpError::InvalidResponse);
        }
        if response.status == StatusCode::ACCEPTED || response.status == StatusCode::NO_CONTENT {
            return Err(StreamableHttpError::InvalidResponse);
        }

        match response_content_type(&response.headers)? {
            ResponseContentType::Json => {
                let body = collect_stream_body(&mut response).await?;
                if body.is_empty() {
                    return Err(StreamableHttpError::InvalidResponse);
                }
                self.ensure_generation(generation).await?;
                let messages = flatten_json_messages(serde_json::from_slice(&body)?)?;
                self.handle_server_requests(&messages, generation).await?;
                Ok(messages)
            }
            ResponseContentType::Sse => {
                self.read_sse_with_resume(
                    response,
                    generation,
                    active_session_id.as_deref(),
                    protocol_version,
                    awaited_id,
                )
                .await
            }
        }
    }

    async fn read_sse_with_resume(
        &self,
        mut response: OutboundStreamResponse,
        generation: u64,
        session_id: Option<&str>,
        protocol_version: Option<&ProtocolVersion>,
        awaited_id: Option<&Value>,
    ) -> Result<Vec<Value>, StreamableHttpError> {
        let mut decoder = SseDecoder::default();
        let mut messages = Vec::new();
        let mut reconnects = 0_usize;
        let mut total_bytes = 0_usize;
        loop {
            self.ensure_generation(generation).await?;
            loop {
                match response.next_chunk().await {
                    Ok(Some(chunk)) => {
                        total_bytes = total_bytes.checked_add(chunk.len()).ok_or(
                            StreamableHttpError::Outbound(OutboundError::ResponseBodyTooLarge),
                        )?;
                        if total_bytes > MAX_LOGICAL_STREAM_BYTES {
                            return Err(OutboundError::ResponseBodyTooLarge.into());
                        }
                        for event in decoder.push(&chunk)? {
                            if let Some(message) = event.message {
                                let is_response =
                                    self.handle_server_message(&message, generation).await?;
                                let complete = is_response && message.get("id") == awaited_id;
                                if is_response {
                                    messages.push(message);
                                }
                                if complete {
                                    self.ensure_generation(generation).await?;
                                    return Ok(messages);
                                }
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(error)
                        if resumable_stream_error(&error) && decoder.last_event_id().is_some() =>
                    {
                        decoder.reset_stream();
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            for event in decoder.finish()? {
                if let Some(message) = event.message {
                    let is_response = self.handle_server_message(&message, generation).await?;
                    let complete = is_response && message.get("id") == awaited_id;
                    if is_response {
                        messages.push(message);
                    }
                    if complete {
                        self.ensure_generation(generation).await?;
                        return Ok(messages);
                    }
                }
            }
            if awaited_id.is_none() && !messages.is_empty() {
                return Ok(messages);
            }
            let last_event_id = decoder
                .last_event_id()
                .ok_or(StreamableHttpError::InvalidResponse)?
                .to_owned();
            let retry_delay = decoder.retry_delay();
            response = loop {
                if reconnects >= MAX_SSE_RECONNECTS {
                    return Err(StreamableHttpError::InvalidResponse);
                }
                reconnects += 1;
                if !retry_delay.is_zero() {
                    tokio::time::sleep(retry_delay).await;
                }
                self.ensure_generation(generation).await?;
                match self
                    .resume_stream(session_id, protocol_version, &last_event_id)
                    .await
                {
                    Ok(response) if response.status == StatusCode::NOT_FOUND => {
                        self.reset_state_if_generation(generation).await;
                        return Err(StreamableHttpError::SessionExpired);
                    }
                    Ok(response) if response.status.is_server_error() => continue,
                    Ok(response) if response.status != StatusCode::OK => {
                        return Err(StreamableHttpError::HttpStatus(response.status));
                    }
                    Ok(response) => break response,
                    Err(StreamableHttpError::Outbound(error)) if resumable_stream_error(&error) => {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            };
            self.ensure_generation(generation).await?;
            self.accept_response_session_or_reset(&response.headers, generation, false)
                .await?;
            if response.declared_response_too_large() {
                return Err(OutboundError::ResponseBodyTooLarge.into());
            }
            if response_content_type(&response.headers)? != ResponseContentType::Sse {
                return Err(StreamableHttpError::UnsupportedContentType);
            }
            decoder.reset_stream();
        }
    }

    async fn resume_stream(
        &self,
        session_id: Option<&str>,
        protocol_version: Option<&ProtocolVersion>,
        last_event_id: &str,
    ) -> Result<OutboundStreamResponse, StreamableHttpError> {
        self.open_notification_stream(
            session_id,
            protocol_version.unwrap_or(&self.requested_protocol_version),
            Some(last_event_id),
            false,
        )
        .await
    }

    async fn open_notification_stream(
        &self,
        session_id: Option<&str>,
        protocol_version: &ProtocolVersion,
        last_event_id: Option<&str>,
        long_lived: bool,
    ) -> Result<OutboundStreamResponse, StreamableHttpError> {
        validate_transport_endpoint(&self.endpoint)?;
        let mut headers = self.headers.clone();
        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        if let Some(session_id) = session_id {
            headers.insert(
                MCP_SESSION_ID,
                HeaderValue::from_str(session_id)
                    .map_err(|_| StreamableHttpError::InvalidSessionId)?,
            );
        }
        if let Some(last_event_id) = last_event_id {
            headers.insert(
                LAST_EVENT_ID,
                HeaderValue::from_str(last_event_id)
                    .map_err(|_| StreamableHttpError::InvalidResponse)?,
            );
        }
        headers.insert(
            MCP_PROTOCOL_VERSION,
            HeaderValue::from_str(protocol_version.as_str())
                .map_err(|_| StreamableHttpError::InvalidProtocolVersion)?,
        );
        let request = OutboundRequest {
            method: Method::GET,
            url: self.endpoint.clone(),
            headers,
            body: Vec::new(),
        };
        if long_lived {
            self.client
                .execute_long_lived_streaming(request, NOTIFICATION_IDLE_TIMEOUT)
                .await
                .map_err(Into::into)
        } else {
            self.client
                .execute_streaming_headers_first(request)
                .await
                .map_err(Into::into)
        }
    }

    async fn handle_server_requests(
        &self,
        messages: &[Value],
        generation: u64,
    ) -> Result<(), StreamableHttpError> {
        for message in messages {
            self.handle_server_message(message, generation).await?;
        }
        Ok(())
    }

    async fn handle_server_message(
        &self,
        message: &Value,
        generation: u64,
    ) -> Result<bool, StreamableHttpError> {
        let request = match classify_incoming_message(message)? {
            IncomingMessage::Response => return Ok(true),
            IncomingMessage::Notification { method } => {
                if method == "notifications/tools/list_changed" {
                    let _ = self.tool_list_changed.send(());
                }
                return Ok(false);
            }
            IncomingMessage::Request(request) => request,
        };
        let response = if request.method == "ping" {
            json!({ "jsonrpc": "2.0", "id": request.id, "result": {} })
        } else {
            json!({
                "jsonrpc": "2.0",
                "id": request.id,
                "error": { "code": -32601, "message": "Method not found" }
            })
        };
        self.post_auxiliary_response(response, generation).await?;
        Ok(false)
    }

    async fn post_auxiliary_response(
        &self,
        response: Value,
        generation: u64,
    ) -> Result<(), StreamableHttpError> {
        validate_transport_endpoint(&self.endpoint)?;
        validate_outgoing_message(&response)?;
        let (session_id, protocol_version) = {
            let state = self.lock_state();
            if state.generation != generation {
                return Err(StreamableHttpError::SessionInvalidated);
            }
            (
                state.session_id.clone(),
                state
                    .negotiated_protocol_version
                    .clone()
                    .unwrap_or_else(|| self.requested_protocol_version.clone()),
            )
        };
        let mut headers = self.headers.clone();
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(session_id) = session_id.as_deref() {
            headers.insert(
                MCP_SESSION_ID,
                HeaderValue::from_str(session_id)
                    .map_err(|_| StreamableHttpError::InvalidSessionId)?,
            );
        }
        headers.insert(
            MCP_PROTOCOL_VERSION,
            HeaderValue::from_str(protocol_version.as_str())
                .map_err(|_| StreamableHttpError::InvalidProtocolVersion)?,
        );
        let auxiliary = self
            .client
            .execute_streaming_headers_first(OutboundRequest {
                method: Method::POST,
                url: self.endpoint.clone(),
                headers,
                body: serde_json::to_vec(&response)?,
            })
            .await?;
        self.ensure_generation(generation).await?;
        if auxiliary.status == StatusCode::NOT_FOUND && session_id.is_some() {
            self.reset_state_if_generation(generation).await;
            return Err(StreamableHttpError::SessionExpired);
        }
        self.accept_response_session_or_reset(&auxiliary.headers, generation, false)
            .await?;
        if auxiliary.declared_response_too_large() {
            return Err(OutboundError::ResponseBodyTooLarge.into());
        }
        if auxiliary.status != StatusCode::ACCEPTED {
            return Err(StreamableHttpError::InvalidResponse);
        }
        let mut auxiliary = auxiliary;
        if auxiliary.next_chunk().await?.is_some() {
            return Err(StreamableHttpError::InvalidResponse);
        }
        Ok(())
    }

    async fn accept_response_session(
        &self,
        headers: &HeaderMap,
        generation: u64,
        accept_new_session: bool,
    ) -> Result<(), StreamableHttpError> {
        let mut session_values = headers.get_all(&MCP_SESSION_ID).iter();
        let Some(session_id) = session_values.next() else {
            return Ok(());
        };
        if session_values.next().is_some() {
            return Err(StreamableHttpError::InvalidSessionId);
        }
        let session_id = session_id
            .to_str()
            .map_err(|_| StreamableHttpError::InvalidSessionId)?;
        validate_session_id(session_id)?;
        let mut state = self.lock_state();
        if state.generation != generation {
            return Err(StreamableHttpError::SessionInvalidated);
        }
        match state.session_id.as_deref() {
            Some(current) if current != session_id => Err(StreamableHttpError::SessionChanged),
            Some(_) => Ok(()),
            None if accept_new_session => {
                state.session_id = Some(session_id.to_owned());
                Ok(())
            }
            None => Err(StreamableHttpError::InvalidSessionId),
        }
    }

    async fn accept_response_session_or_reset(
        &self,
        headers: &HeaderMap,
        generation: u64,
        accept_new_session: bool,
    ) -> Result<(), StreamableHttpError> {
        match self
            .accept_response_session(headers, generation, accept_new_session)
            .await
        {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error,
                    StreamableHttpError::InvalidSessionId | StreamableHttpError::SessionChanged
                ) =>
            {
                self.terminate_state_session_if_generation(generation).await;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, TransportState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    async fn ensure_generation(&self, generation: u64) -> Result<(), StreamableHttpError> {
        if self.lock_state().generation == generation {
            Ok(())
        } else {
            Err(StreamableHttpError::SessionInvalidated)
        }
    }

    #[cfg(test)]
    async fn reset_state(&self) {
        let mut state = self.lock_state();
        state.generation = state.generation.wrapping_add(1);
        state.session_id = None;
        state.negotiated_protocol_version = None;
        state.initialized = false;
    }

    async fn reset_state_if_generation(&self, generation: u64) {
        let mut state = self.lock_state();
        if state.generation == generation {
            state.generation = state.generation.wrapping_add(1);
            state.session_id = None;
            state.negotiated_protocol_version = None;
            state.initialized = false;
        }
    }

    async fn terminate_state_session_if_generation(&self, generation: u64) {
        let cleanup = {
            let mut state = self.lock_state();
            if state.generation != generation {
                return;
            }
            state.generation = state.generation.wrapping_add(1);
            let session_id = state.session_id.take();
            let protocol_version = state
                .negotiated_protocol_version
                .take()
                .unwrap_or_else(|| self.requested_protocol_version.clone());
            state.initialized = false;
            session_id.map(|session_id| {
                (
                    session_id,
                    protocol_version,
                    self.session_terminations.start(),
                )
            })
        };
        if let Some((session_id, protocol_version, permit)) = cleanup {
            let _ = spawn_session_termination(
                self.client.clone(),
                self.endpoint.clone(),
                self.headers.clone(),
                session_id,
                protocol_version,
                permit,
            );
        }
    }
}

fn spawn_session_termination(
    client: HardenedHttpClient,
    endpoint: Url,
    mut headers: HeaderMap,
    session_id: String,
    protocol_version: ProtocolVersion,
    permit: SessionTerminationPermit,
) -> Result<oneshot::Receiver<Result<StatusCode, StreamableHttpError>>, StreamableHttpError> {
    validate_transport_endpoint(&endpoint)?;
    let session_id =
        HeaderValue::from_str(&session_id).map_err(|_| StreamableHttpError::InvalidSessionId)?;
    let protocol_version = HeaderValue::from_str(protocol_version.as_str())
        .map_err(|_| StreamableHttpError::InvalidProtocolVersion)?;
    headers.insert(MCP_SESSION_ID, session_id);
    headers.insert(MCP_PROTOCOL_VERSION, protocol_version);
    let runtime =
        tokio::runtime::Handle::try_current().map_err(|_| StreamableHttpError::InvalidResponse)?;
    let (result_tx, result_rx) = oneshot::channel();
    let cleanup = async move {
        let _permit = permit;
        let result = tokio::time::timeout(
            SESSION_TERMINATION_TIMEOUT,
            client.execute(OutboundRequest {
                method: Method::DELETE,
                url: endpoint,
                headers,
                body: Vec::new(),
            }),
        )
        .await
        .map_err(|_| StreamableHttpError::Outbound(OutboundError::Timeout))
        .and_then(|response| response.map(|response| response.status).map_err(Into::into));
        let _ = result_tx.send(result);
    };
    drop(runtime.spawn(cleanup));
    Ok(result_rx)
}

fn validate_transport_endpoint(endpoint: &Url) -> Result<(), StreamableHttpError> {
    if endpoint.scheme() == "https"
        || (endpoint.scheme() == "http" && is_loopback_endpoint(endpoint))
    {
        Ok(())
    } else {
        Err(StreamableHttpError::InsecureEndpoint)
    }
}

fn is_loopback_endpoint(endpoint: &Url) -> bool {
    match endpoint.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => {
            let domain = domain.strip_suffix('.').unwrap_or(domain);
            domain.eq_ignore_ascii_case("localhost")
                || domain
                    .to_ascii_lowercase()
                    .strip_suffix(".localhost")
                    .is_some_and(|prefix| !prefix.is_empty())
        }
        None => false,
    }
}

fn validate_custom_headers(headers: &HeaderMap) -> Result<(), StreamableHttpError> {
    if headers.contains_key(ACCEPT)
        || headers.contains_key(CONTENT_TYPE)
        || headers.contains_key(&MCP_SESSION_ID)
        || headers.contains_key(&MCP_PROTOCOL_VERSION)
        || headers.contains_key(&LAST_EVENT_ID)
    {
        Err(StreamableHttpError::ReservedHeader)
    } else {
        Ok(())
    }
}

fn validate_session_id(value: &str) -> Result<(), StreamableHttpError> {
    if value.is_empty()
        || value.len() > MAX_SESSION_ID_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(StreamableHttpError::InvalidSessionId)
    } else {
        Ok(())
    }
}

fn resumable_stream_error(error: &OutboundError) -> bool {
    matches!(
        error,
        OutboundError::Timeout | OutboundError::Connection | OutboundError::Request
    )
}

fn validate_id(id: &Value) -> Result<(), StreamableHttpError> {
    if id.is_string()
        || id
            .as_number()
            .is_some_and(|number| number.as_i64().is_some() || number.as_u64().is_some())
    {
        Ok(())
    } else {
        Err(StreamableHttpError::InvalidRequest)
    }
}

fn validate_call_tool_result(result: &Value) -> Result<(), StreamableHttpError> {
    if result
        .get("structuredContent")
        .is_some_and(|structured_content| !structured_content.is_object())
    {
        return Err(StreamableHttpError::InvalidResponse);
    }
    serde_json::from_value::<CallToolResult>(result.clone())
        .map_err(|_| StreamableHttpError::InvalidResponse)?;
    Ok(())
}

fn validate_outgoing_message(message: &Value) -> Result<(), StreamableHttpError> {
    let messages = match message {
        Value::Object(_) => std::slice::from_ref(message),
        _ => return Err(StreamableHttpError::InvalidRequest),
    };
    for message in messages {
        let message = message
            .as_object()
            .ok_or(StreamableHttpError::InvalidRequest)?;
        if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(StreamableHttpError::InvalidRequest);
        }
        let has_method = message.get("method").and_then(Value::as_str).is_some();
        let has_result = message.contains_key("result");
        let has_error = message.contains_key("error");
        if has_method && (has_result || has_error) {
            return Err(StreamableHttpError::InvalidRequest);
        }
        if has_method {
            if let Some(id) = message.get("id") {
                validate_id(id)?;
            }
        } else {
            let id = message
                .get("id")
                .ok_or(StreamableHttpError::InvalidRequest)?;
            validate_id(id)?;
            if has_result == has_error {
                return Err(StreamableHttpError::InvalidRequest);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn parse_response_messages(response: &OutboundResponse) -> Result<Vec<Value>, StreamableHttpError> {
    match response_content_type(&response.headers)? {
        ResponseContentType::Json => flatten_json_messages(serde_json::from_slice(&response.body)?),
        ResponseContentType::Sse => parse_sse(&response.body),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseContentType {
    Json,
    Sse,
}

fn response_content_type(headers: &HeaderMap) -> Result<ResponseContentType, StreamableHttpError> {
    let mut content_types = headers.get_all(CONTENT_TYPE).iter();
    let content_type = content_types
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .ok_or(StreamableHttpError::UnsupportedContentType)?;
    if content_types.next().is_some() {
        return Err(StreamableHttpError::UnsupportedContentType);
    }
    if content_type.eq_ignore_ascii_case("application/json") {
        Ok(ResponseContentType::Json)
    } else if content_type.eq_ignore_ascii_case("text/event-stream") {
        Ok(ResponseContentType::Sse)
    } else {
        Err(StreamableHttpError::UnsupportedContentType)
    }
}

async fn collect_stream_body(
    response: &mut OutboundStreamResponse,
) -> Result<Vec<u8>, StreamableHttpError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.next_chunk().await? {
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn flatten_json_messages(value: Value) -> Result<Vec<Value>, StreamableHttpError> {
    match value {
        Value::Object(_) => Ok(vec![value]),
        _ => Err(StreamableHttpError::InvalidResponse),
    }
}

#[cfg(test)]
fn parse_sse(body: &[u8]) -> Result<Vec<Value>, StreamableHttpError> {
    let mut decoder = SseDecoder::default();
    let mut messages = Vec::new();
    for event in decoder.push(body)?.into_iter().chain(decoder.finish()?) {
        if let Some(message) = event.message {
            messages.push(message);
        }
    }
    if messages.is_empty() {
        Err(StreamableHttpError::InvalidResponse)
    } else {
        Ok(messages)
    }
}

struct SseEvent {
    message: Option<Value>,
}

struct SseDecoder {
    pending: Vec<u8>,
    scan_offset: usize,
    data: String,
    has_data: bool,
    event_id: Option<String>,
    last_event_id: Option<String>,
    event_count: usize,
    retry_delay: Duration,
    event_bytes: usize,
    stream_start: bool,
}

impl Default for SseDecoder {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            scan_offset: 0,
            data: String::new(),
            has_data: false,
            event_id: None,
            last_event_id: None,
            event_count: 0,
            retry_delay: Duration::from_millis(250),
            event_bytes: 0,
            stream_start: true,
        }
    }
}

impl SseDecoder {
    fn push(&mut self, chunk: &[u8]) -> Result<Vec<SseEvent>, StreamableHttpError> {
        self.pending.extend_from_slice(chunk);
        let mut consumed = 0_usize;
        let mut events = Vec::new();
        let mut cursor = self.scan_offset.min(self.pending.len());
        while cursor < self.pending.len() {
            let delimiter = match self.pending[cursor] {
                b'\n' => Some((cursor, 1)),
                b'\r' if cursor + 1 < self.pending.len() => Some((
                    cursor,
                    if self.pending[cursor + 1] == b'\n' {
                        2
                    } else {
                        1
                    },
                )),
                b'\r' => None,
                _ => {
                    cursor += 1;
                    continue;
                }
            };
            let Some((end, delimiter_bytes)) = delimiter else {
                break;
            };
            let line = self.pending[consumed..end].to_vec();
            consumed = end + delimiter_bytes;
            cursor = consumed;
            if let Some(event) = self.line(&line)? {
                events.push(event);
            }
        }
        self.pending.drain(..consumed);
        self.scan_offset = self.pending.len();
        if self.pending.last() == Some(&b'\r') {
            self.scan_offset = self.scan_offset.saturating_sub(1);
        }
        if self.pending.len() > MAX_LOGICAL_STREAM_BYTES {
            return Err(StreamableHttpError::InvalidResponse);
        }
        Ok(events)
    }

    fn finish(&mut self) -> Result<Vec<SseEvent>, StreamableHttpError> {
        let mut events = Vec::new();
        if self.pending.last() == Some(&b'\r') {
            let mut line = std::mem::take(&mut self.pending);
            line.pop();
            if let Some(event) = self.line(&line)? {
                events.push(event);
            }
        }
        self.pending.clear();
        self.scan_offset = 0;
        self.data.clear();
        self.has_data = false;
        self.event_id = None;
        self.event_bytes = 0;
        Ok(events)
    }

    fn line(&mut self, line: &[u8]) -> Result<Option<SseEvent>, StreamableHttpError> {
        let line = if self.stream_start {
            self.stream_start = false;
            line.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(line)
        } else {
            line
        };
        self.event_bytes = self
            .event_bytes
            .checked_add(line.len())
            .ok_or(StreamableHttpError::InvalidResponse)?;
        if self.event_bytes > MAX_LOGICAL_STREAM_BYTES {
            return Err(StreamableHttpError::InvalidResponse);
        }
        let line = std::str::from_utf8(line).map_err(|_| StreamableHttpError::InvalidUtf8)?;
        if line.is_empty() {
            return self.dispatch();
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "data" => {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
                if self.data.len() > MAX_LOGICAL_STREAM_BYTES {
                    return Err(StreamableHttpError::InvalidResponse);
                }
            }
            "id" if !value.contains('\0') => {
                if value.len() > MAX_SESSION_ID_BYTES {
                    return Err(StreamableHttpError::InvalidResponse);
                }
                self.event_id = Some(value.to_owned());
            }
            "retry" => {
                if let Ok(milliseconds) = value.parse::<u64>() {
                    self.retry_delay = Duration::from_millis(milliseconds.clamp(50, 10_000));
                }
            }
            _ => {}
        }
        Ok(None)
    }

    fn dispatch(&mut self) -> Result<Option<SseEvent>, StreamableHttpError> {
        self.event_bytes = 0;
        if !self.has_data && self.event_id.is_none() {
            return Ok(None);
        }
        self.event_count = self
            .event_count
            .checked_add(1)
            .ok_or(StreamableHttpError::InvalidResponse)?;
        if self.event_count > MAX_SSE_EVENTS {
            return Err(StreamableHttpError::InvalidResponse);
        }
        if let Some(event_id) = self.event_id.take() {
            if event_id.is_empty() {
                self.last_event_id = None;
            } else {
                self.last_event_id = Some(event_id);
            }
        }
        let data = std::mem::take(&mut self.data);
        self.has_data = false;
        let message: Option<Value> = if data.is_empty() {
            None
        } else {
            Some(serde_json::from_str(&data)?)
        };
        if message.as_ref().is_some_and(|message| !message.is_object()) {
            return Err(StreamableHttpError::InvalidResponse);
        }
        Ok(Some(SseEvent { message }))
    }

    fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }

    fn reset_stream(&mut self) {
        self.pending.clear();
        self.scan_offset = 0;
        self.data.clear();
        self.has_data = false;
        self.event_id = None;
        self.event_bytes = 0;
        self.stream_start = true;
    }

    fn retry_delay(&self) -> Duration {
        self.retry_delay
    }

    fn reset_connection_limits(&mut self) {
        self.reset_stream();
        self.event_count = 0;
    }
}

struct ServerRequest {
    id: Value,
    method: String,
}

enum IncomingMessage {
    Response,
    Request(ServerRequest),
    Notification { method: String },
}

fn classify_incoming_message(message: &Value) -> Result<IncomingMessage, StreamableHttpError> {
    let message = message
        .as_object()
        .ok_or(StreamableHttpError::InvalidResponse)?;
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(StreamableHttpError::InvalidResponse);
    }
    let method = message.get("method").and_then(Value::as_str);
    let has_result = message.contains_key("result");
    let has_error = message.contains_key("error");
    if let Some(method) = method {
        if has_result || has_error {
            return Err(StreamableHttpError::InvalidResponse);
        }
        return match message.get("id") {
            Some(id) => {
                validate_id(id).map_err(|_| StreamableHttpError::InvalidResponse)?;
                Ok(IncomingMessage::Request(ServerRequest {
                    id: id.clone(),
                    method: method.to_owned(),
                }))
            }
            None => Ok(IncomingMessage::Notification {
                method: method.to_owned(),
            }),
        };
    }
    let id = message
        .get("id")
        .ok_or(StreamableHttpError::InvalidResponse)?;
    validate_id(id).map_err(|_| StreamableHttpError::InvalidResponse)?;
    if has_result == has_error {
        return Err(StreamableHttpError::InvalidResponse);
    }
    Ok(IncomingMessage::Response)
}

fn response_result(messages: Vec<Value>, id: &Value) -> Result<Value, StreamableHttpError> {
    let response = messages
        .into_iter()
        .find(|message| message.get("id") == Some(id))
        .ok_or(StreamableHttpError::InvalidResponse)?;
    let response = response
        .as_object()
        .ok_or(StreamableHttpError::InvalidResponse)?;
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(StreamableHttpError::InvalidResponse);
    }
    if let Some(error) = response.get("error") {
        let error = error
            .as_object()
            .ok_or(StreamableHttpError::InvalidResponse)?;
        return Err(StreamableHttpError::JsonRpc {
            code: error
                .get("code")
                .and_then(Value::as_i64)
                .ok_or(StreamableHttpError::InvalidResponse)?,
            message: error
                .get("message")
                .and_then(Value::as_str)
                .ok_or(StreamableHttpError::InvalidResponse)?
                .to_owned(),
            data: error.get("data").cloned(),
        });
    }
    response
        .get("result")
        .cloned()
        .ok_or(StreamableHttpError::InvalidResponse)
}

#[cfg(test)]
mod tests;
