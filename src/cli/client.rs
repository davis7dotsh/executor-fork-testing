use std::{
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};

use reqwest::{Method, Response, StatusCode, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

use super::terminal::safe_field;

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_LOOPBACK_ADDRESSES: usize = 32;
const IDEMPOTENCY_WAIT_LIMIT: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct GatewayClient {
    http: reqwest::Client,
    base_url: Url,
    token: String,
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("the Executor base URL is invalid: {0}")]
    InvalidBaseUrl(String),
    #[error("EXECUTOR_API_TOKEN or --api-token is required")]
    MissingToken,
    #[error("Executor is not reachable at {base_url}: {source}")]
    Unreachable {
        base_url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("Executor returned an invalid response: {0}")]
    InvalidResponse(String),
    #[error("Executor returned too much data")]
    ResponseTooLarge,
    #[error(
        "plaintext HTTP is allowed only when the Executor host resolves exclusively to loopback addresses; use HTTPS or pass --allow-insecure-http"
    )]
    UnsafeHttpResolution,
    #[error(
        "Executor may have completed {operation}, but {reason}; the outcome is unknown. Do not repeat it with a new request identity.{recovery_suffix}"
    )]
    OutcomeUnknown {
        operation: &'static str,
        reason: &'static str,
        recovery_suffix: String,
    },
    #[error("Executor request failed ({status} {code}): {message}{request_suffix}")]
    Api {
        status: StatusCode,
        code: String,
        message: String,
        request_suffix: String,
    },
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: ApiErrorBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    code: String,
    message: String,
    request_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApprovalRequired {
    pub status: String,
    pub approval: PendingApproval,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingApproval {
    pub id: String,
    pub status: String,
    pub revision: i64,
    pub path: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub status_url: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalDetail {
    pub id: String,
    pub status: String,
    pub revision: i64,
    pub path: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
    pub failure_code: Option<String>,
    pub result: Option<Value>,
}

pub enum InvokeResponse {
    Complete(Value),
    ApprovalRequired(ApprovalRequired),
}

impl GatewayClient {
    #[cfg(test)]
    pub fn new(base_url: &str, token: Option<&str>) -> Result<Self, ClientError> {
        Self::new_with_policy(base_url, token, false)
    }

    pub fn new_with_policy(
        base_url: &str,
        token: Option<&str>,
        allow_insecure_http: bool,
    ) -> Result<Self, ClientError> {
        Self::new_with_policy_and_resolver(
            base_url,
            token,
            allow_insecure_http,
            resolve_system_addresses,
        )
    }

    fn new_with_policy_and_resolver<F>(
        base_url: &str,
        token: Option<&str>,
        allow_insecure_http: bool,
        resolver: F,
    ) -> Result<Self, ClientError>
    where
        F: FnOnce(&str, u16) -> io::Result<Vec<SocketAddr>>,
    {
        let token = token
            .filter(|token| !token.is_empty())
            .ok_or(ClientError::MissingToken)?;
        let base_url = normalized_base_url_with_policy(base_url, allow_insecure_http)?;
        let builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(35))
            .user_agent(concat!("executor-cli/", env!("CARGO_PKG_VERSION")));
        let http = pin_plaintext_loopback(builder, &base_url, allow_insecure_http, resolver)?
            .build()
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
        Ok(Self {
            http,
            base_url,
            token: token.to_owned(),
        })
    }

    pub fn dashboard_url(&self) -> Url {
        self.base_url.clone()
    }

    pub async fn invoke(
        &self,
        path: &str,
        arguments: Value,
        idempotency_key: &str,
    ) -> Result<InvokeResponse, ClientError> {
        self.invoke_with_wait_limit(path, arguments, idempotency_key, IDEMPOTENCY_WAIT_LIMIT)
            .await
    }

    async fn invoke_with_wait_limit(
        &self,
        path: &str,
        arguments: Value,
        idempotency_key: &str,
        wait_limit: Duration,
    ) -> Result<InvokeResponse, ClientError> {
        let payload = json!({"path": path, "arguments": arguments});
        let mut send_retry_used = false;
        let mut response_retry_used = false;
        let mut outcome_may_exist = false;
        let started = Instant::now();
        loop {
            let response = self
                .request(Method::POST, "api/v1/gateway/tools/invoke")?
                .header("idempotency-key", idempotency_key)
                .json(&payload)
                .send()
                .await;
            let response = match response {
                Ok(response) => response,
                Err(source) if !send_retry_used => {
                    outcome_may_exist |= !source.is_connect();
                    send_retry_used = true;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
                Err(source) if outcome_may_exist || !source.is_connect() => {
                    return Err(outcome_unknown(
                        "the tool call",
                        "its response could not be received",
                        Some(idempotency_key),
                    ));
                }
                Err(source) => return Err(self.unreachable(source)),
            };

            let status = response.status();
            let retry_after = response
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1)
                .min(2);
            let bytes = match read_bounded(response).await {
                Ok(bytes) => bytes,
                Err(ResponseReadError::Transport(_))
                    if status.is_success()
                        || status == StatusCode::CONFLICT
                        || status.is_server_error()
                        || outcome_may_exist =>
                {
                    outcome_may_exist = true;
                    if !response_retry_used {
                        response_retry_used = true;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                    return Err(outcome_unknown(
                        "the tool call",
                        "its response could not be read after a safe replay attempt",
                        Some(idempotency_key),
                    ));
                }
                Err(ResponseReadError::TooLarge)
                    if status.is_success()
                        || status == StatusCode::CONFLICT
                        || status.is_server_error()
                        || outcome_may_exist =>
                {
                    outcome_may_exist = true;
                    if !response_retry_used {
                        response_retry_used = true;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                    return Err(outcome_unknown(
                        "the tool call",
                        "its response was too large to verify after a safe replay attempt",
                        Some(idempotency_key),
                    ));
                }
                Err(error) if !status.is_success() => {
                    return match error {
                        ResponseReadError::Transport(_) => {
                            Err(api_error(status, None, &self.token))
                        }
                        ResponseReadError::TooLarge => Err(ClientError::ResponseTooLarge),
                    };
                }
                Err(error) => return Err(error.into_client_error()),
            };

            if !status.is_success() {
                let envelope = serde_json::from_slice::<ErrorEnvelope>(&bytes).ok();
                if status == StatusCode::CONFLICT {
                    if envelope
                        .as_ref()
                        .is_some_and(|envelope| envelope.error.code == "idempotency_in_progress")
                    {
                        outcome_may_exist = true;
                        if started.elapsed() < wait_limit {
                            tokio::time::sleep(Duration::from_secs(retry_after)).await;
                            continue;
                        }
                        return Err(outcome_unknown(
                            "the tool call",
                            "it remained in progress beyond the safe wait limit",
                            Some(idempotency_key),
                        ));
                    }
                    if envelope.is_none() {
                        outcome_may_exist = true;
                        if !response_retry_used {
                            response_retry_used = true;
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            continue;
                        }
                        return Err(outcome_unknown(
                            "the tool call",
                            "its conflict response could not be decoded after a safe replay attempt",
                            Some(idempotency_key),
                        ));
                    }
                }
                if envelope.is_none() && (status.is_server_error() || outcome_may_exist) {
                    outcome_may_exist = true;
                    if !response_retry_used {
                        response_retry_used = true;
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                    return Err(outcome_unknown(
                        "the tool call",
                        "the replay did not return a definitive typed response after a safe replay attempt",
                        Some(idempotency_key),
                    ));
                }
                return Err(api_error(status, envelope, &self.token));
            }

            let decoded = if status == StatusCode::ACCEPTED {
                decode_success::<ApprovalRequired>(status, &bytes, &self.token)
                    .map(InvokeResponse::ApprovalRequired)
            } else {
                decode_success(status, &bytes, &self.token).map(InvokeResponse::Complete)
            };
            match decoded {
                Ok(response) => return Ok(response),
                Err(ClientError::InvalidResponse(_)) if !response_retry_used => {
                    outcome_may_exist = true;
                    response_retry_used = true;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(ClientError::InvalidResponse(_)) => {
                    return Err(outcome_unknown(
                        "the tool call",
                        "its response could not be decoded after a safe replay attempt",
                        Some(idempotency_key),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn approval(&self, approval_id: &str) -> Result<ApprovalDetail, ClientError> {
        let path = approval_path(approval_id)?;
        let response = self
            .request(Method::GET, &path)?
            .send()
            .await
            .map_err(|source| self.unreachable(source))?;
        self.decode_success(response).await
    }

    pub async fn cancel_approval(
        &self,
        approval_id: &str,
        expected_revision: i64,
    ) -> Result<ApprovalDetail, ClientError> {
        let path = approval_path(approval_id)?;
        let response = self
            .request(Method::DELETE, &path)?
            .query(&[("expectedRevision", expected_revision)])
            .send()
            .await
            .map_err(|source| {
                if source.is_connect() {
                    self.unreachable(source)
                } else {
                    outcome_unknown(
                        "the approval cancellation",
                        "its response could not be received",
                        None,
                    )
                }
            })?;
        self.decode_non_idempotent_mutation(response, "the approval cancellation")
            .await
    }

    pub async fn search(
        &self,
        query: &str,
        namespace: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<Value, ClientError> {
        let response = self
            .request(Method::POST, "api/v1/gateway/tools/search")?
            .json(&json!({
                "query": query,
                "namespace": namespace,
                "limit": limit,
                "offset": offset,
            }))
            .send()
            .await
            .map_err(|source| self.unreachable(source))?;
        self.decode_success(response).await
    }

    pub async fn describe(&self, path: &str) -> Result<Value, ClientError> {
        let response = self
            .request(Method::POST, "api/v1/gateway/tools/describe")?
            .json(&json!({"path": path}))
            .send()
            .await
            .map_err(|source| self.unreachable(source))?;
        self.decode_success(response).await
    }

    pub async fn sources(&self) -> Result<Value, ClientError> {
        let response = self
            .request(Method::GET, "api/v1/gateway/sources")?
            .send()
            .await
            .map_err(|source| self.unreachable(source))?;
        self.decode_success(response).await
    }

    fn request(&self, method: Method, path: &str) -> Result<reqwest::RequestBuilder, ClientError> {
        let url = self.base_url.join(path).map_err(|_| {
            ClientError::InvalidResponse("could not construct the Executor API URL".to_owned())
        })?;
        Ok(self
            .http
            .request(method, url)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(header::ACCEPT, "application/json"))
    }

    async fn decode_success<T: DeserializeOwned>(
        &self,
        response: Response,
    ) -> Result<T, ClientError> {
        let status = response.status();
        let bytes = read_bounded(response)
            .await
            .map_err(ResponseReadError::into_client_error)?;
        decode_success(status, &bytes, &self.token)
    }

    async fn decode_non_idempotent_mutation<T: DeserializeOwned>(
        &self,
        response: Response,
        operation: &'static str,
    ) -> Result<T, ClientError> {
        let status = response.status();
        let bytes = match read_bounded(response).await {
            Ok(bytes) => bytes,
            Err(ResponseReadError::Transport(_))
                if status.is_success() || status.is_server_error() =>
            {
                return Err(outcome_unknown(
                    operation,
                    "its response could not be read and the request was not automatically retried",
                    None,
                ));
            }
            Err(ResponseReadError::TooLarge) if status.is_success() || status.is_server_error() => {
                return Err(outcome_unknown(
                    operation,
                    "its response was too large to verify and the request was not automatically retried",
                    None,
                ));
            }
            Err(error) if !status.is_success() => {
                return match error {
                    ResponseReadError::Transport(_) => Err(api_error(status, None, &self.token)),
                    ResponseReadError::TooLarge => Err(ClientError::ResponseTooLarge),
                };
            }
            Err(error) => return Err(error.into_client_error()),
        };
        if !status.is_success() {
            let envelope = serde_json::from_slice::<ErrorEnvelope>(&bytes).ok();
            if envelope.is_none() && status.is_server_error() {
                return Err(outcome_unknown(
                    operation,
                    "its server-error response could not be decoded and the request was not automatically retried",
                    None,
                ));
            }
            return Err(api_error(status, envelope, &self.token));
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            outcome_unknown(
                operation,
                "its response could not be decoded and the request was not automatically retried",
                None,
            )
        })
    }

    fn unreachable(&self, source: reqwest::Error) -> ClientError {
        ClientError::Unreachable {
            base_url: self.base_url.to_string(),
            source,
        }
    }
}

pub fn normalized_base_url(input: &str) -> Result<Url, ClientError> {
    normalized_base_url_with_policy(input, false)
}

pub(crate) fn normalized_base_url_with_policy(
    input: &str,
    allow_insecure_http: bool,
) -> Result<Url, ClientError> {
    let mut url =
        Url::parse(input).map_err(|error| ClientError::InvalidBaseUrl(error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ClientError::InvalidBaseUrl(
            "use an http(s) origin without credentials, query, or fragment".to_owned(),
        ));
    }
    if !matches!(url.path(), "" | "/") {
        return Err(ClientError::InvalidBaseUrl(
            "the base URL must not contain a path".to_owned(),
        ));
    }
    if url.scheme() == "http" && !is_loopback_host(&url) && !allow_insecure_http {
        return Err(ClientError::InvalidBaseUrl(
            "plaintext HTTP is allowed only for localhost or a loopback IP; use HTTPS".to_owned(),
        ));
    }
    url.set_path("/");
    Ok(url)
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => canonical_ip(IpAddr::V6(address)).is_loopback(),
        Some(url::Host::Domain(domain)) => is_localhost_domain(domain),
        None => false,
    }
}

fn is_localhost_domain(domain: &str) -> bool {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    domain.eq_ignore_ascii_case("localhost")
        || domain
            .to_ascii_lowercase()
            .strip_suffix(".localhost")
            .is_some_and(|prefix| !prefix.is_empty())
}

pub(crate) fn resolve_system_addresses(hostname: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    (hostname, port)
        .to_socket_addrs()
        .map(|addresses| addresses.take(MAX_LOOPBACK_ADDRESSES + 1).collect())
}

pub(crate) fn pin_plaintext_loopback<F>(
    builder: reqwest::ClientBuilder,
    origin: &Url,
    allow_insecure_http: bool,
    resolver: F,
) -> Result<reqwest::ClientBuilder, ClientError>
where
    F: FnOnce(&str, u16) -> io::Result<Vec<SocketAddr>>,
{
    if origin.scheme() != "http" || allow_insecure_http {
        return Ok(builder);
    }
    let port = origin
        .port_or_known_default()
        .ok_or(ClientError::UnsafeHttpResolution)?;
    let Some(host) = origin.host() else {
        return Err(ClientError::UnsafeHttpResolution);
    };
    let url::Host::Domain(hostname) = host else {
        let address = match host {
            url::Host::Ipv4(address) => IpAddr::V4(address),
            url::Host::Ipv6(address) => canonical_ip(IpAddr::V6(address)),
            url::Host::Domain(_) => unreachable!("domain handled above"),
        };
        return address
            .is_loopback()
            .then_some(builder)
            .ok_or(ClientError::UnsafeHttpResolution);
    };
    if !is_localhost_domain(hostname) {
        return Err(ClientError::UnsafeHttpResolution);
    }
    let addresses = resolver(hostname, port).map_err(|_| ClientError::UnsafeHttpResolution)?;
    if addresses.is_empty() || addresses.len() > MAX_LOOPBACK_ADDRESSES {
        return Err(ClientError::UnsafeHttpResolution);
    }
    let mut addresses = addresses
        .into_iter()
        .map(|address| SocketAddr::new(canonical_ip(address.ip()), port))
        .collect::<Vec<_>>();
    if addresses.iter().any(|address| !address.ip().is_loopback()) {
        return Err(ClientError::UnsafeHttpResolution);
    }
    addresses.sort_unstable();
    addresses.dedup();
    Ok(builder.resolve_to_addrs(hostname, &addresses))
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

fn approval_path(approval_id: &str) -> Result<String, ClientError> {
    if approval_id.is_empty()
        || approval_id.len() > 128
        || !approval_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(ClientError::InvalidResponse(
            "approval ID was invalid".to_owned(),
        ));
    }
    Ok(format!("api/v1/gateway/approvals/{approval_id}"))
}

fn api_error(status: StatusCode, envelope: Option<ErrorEnvelope>, token: &str) -> ClientError {
    let (code, message, request_suffix) = match envelope {
        Some(envelope) => (
            safe_field_redacting_secret(&envelope.error.code, token),
            safe_field_redacting_secret(&envelope.error.message, token),
            envelope
                .error
                .request_id
                .map(|id| format!(" (request {})", safe_field_redacting_secret(&id, token)))
                .unwrap_or_default(),
        ),
        None => (
            "http_error".to_owned(),
            status
                .canonical_reason()
                .unwrap_or("request failed")
                .to_owned(),
            String::new(),
        ),
    };
    ClientError::Api {
        status,
        code,
        message,
        request_suffix,
    }
}

fn decode_success<T: DeserializeOwned>(
    status: StatusCode,
    bytes: &[u8],
    token: &str,
) -> Result<T, ClientError> {
    if !status.is_success() {
        let envelope = serde_json::from_slice::<ErrorEnvelope>(bytes).ok();
        return Err(api_error(status, envelope, token));
    }
    serde_json::from_slice(bytes).map_err(|error| ClientError::InvalidResponse(error.to_string()))
}

pub(crate) fn safe_field_redacting_secret(value: &str, secret: &str) -> String {
    if secret.is_empty() {
        return safe_field(value);
    }
    safe_field(&value.replace(secret, "[redacted]"))
}

fn outcome_unknown(
    operation: &'static str,
    reason: &'static str,
    idempotency_key: Option<&str>,
) -> ClientError {
    let recovery_suffix = idempotency_key
        .map(|key| format!(" Recovery idempotency key: {}.", safe_field(key)))
        .unwrap_or_default();
    ClientError::OutcomeUnknown {
        operation,
        reason,
        recovery_suffix,
    }
}

enum ResponseReadError {
    Transport(reqwest::Error),
    TooLarge,
}

impl ResponseReadError {
    fn into_client_error(self) -> ClientError {
        match self {
            Self::Transport(error) => ClientError::InvalidResponse(error.to_string()),
            Self::TooLarge => ClientError::ResponseTooLarge,
        }
    }
}

async fn read_bounded(mut response: Response) -> Result<Vec<u8>, ResponseReadError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ResponseReadError::TooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(ResponseReadError::Transport)?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ResponseReadError::TooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, Uri},
        response::IntoResponse,
        routing::{get, post},
    };
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
    };

    use super::*;

    type CapturedRequestSender =
        std::sync::Arc<std::sync::Mutex<Option<oneshot::Sender<(Uri, HeaderMap)>>>>;

    enum RawReply {
        Complete {
            status: StatusCode,
            body: &'static str,
        },
        Truncated {
            status: StatusCode,
            body: &'static str,
        },
    }

    impl RawReply {
        fn status(&self) -> StatusCode {
            match self {
                Self::Complete { status, .. } | Self::Truncated { status, .. } => *status,
            }
        }

        fn body(&self) -> &'static str {
            match self {
                Self::Complete { body, .. } | Self::Truncated { body, .. } => body,
            }
        }
    }

    #[derive(Debug)]
    struct RawCall {
        method: String,
        target: String,
        idempotency_key: Option<String>,
    }

    #[derive(Default)]
    struct RawServerState {
        calls: Mutex<Vec<RawCall>>,
        committed_keys: Mutex<HashSet<String>>,
        dispatches: AtomicUsize,
    }

    async fn spawn_server(router: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("test server");
        });
        (format!("http://{address}"), task)
    }

    async fn spawn_raw_server(
        replies: Vec<RawReply>,
    ) -> (String, tokio::task::JoinHandle<()>, Arc<RawServerState>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let state = Arc::new(RawServerState::default());
        let server_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            for reply in replies {
                let (mut stream, _) = listener.accept().await.expect("connection");
                let call = read_raw_call(&mut stream).await;
                if reply.status().is_success() || reply.status().is_server_error() {
                    match &call.idempotency_key {
                        Some(key) => {
                            if server_state
                                .committed_keys
                                .lock()
                                .expect("committed keys")
                                .insert(key.clone())
                            {
                                server_state.dispatches.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        None => {
                            server_state.dispatches.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
                server_state.calls.lock().expect("calls").push(call);
                write_raw_reply(&mut stream, reply).await;
            }
        });
        (format!("http://{address}"), task, state)
    }

    async fn finish_raw_server(mut task: tokio::task::JoinHandle<()>) {
        match tokio::time::timeout(Duration::from_secs(2), &mut task).await {
            Ok(result) => result.expect("raw server"),
            Err(_) => {
                task.abort();
                let _ = task.await;
                panic!("raw server did not receive the expected requests");
            }
        }
    }

    async fn read_raw_call(stream: &mut tokio::net::TcpStream) -> RawCall {
        let mut request = Vec::new();
        let header_end = loop {
            if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).await.expect("read request");
            assert_ne!(read, 0, "request ended before headers");
            request.extend_from_slice(&buffer[..read]);
            assert!(request.len() <= 64 * 1024, "request headers were too large");
        };
        let headers = String::from_utf8(request[..header_end].to_vec()).expect("ASCII headers");
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
            .unwrap_or_default();
        while request.len() < header_end + content_length {
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).await.expect("read request body");
            assert_ne!(read, 0, "request ended before body");
            request.extend_from_slice(&buffer[..read]);
        }
        let request_line = headers.lines().next().expect("request line");
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts.next().expect("request method").to_owned();
        let target = request_parts.next().expect("request target").to_owned();
        let idempotency_key = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("idempotency-key")
                .then(|| value.trim().to_owned())
        });
        RawCall {
            method,
            target,
            idempotency_key,
        }
    }

    async fn write_raw_reply(stream: &mut tokio::net::TcpStream, reply: RawReply) {
        let status = reply.status();
        let body = reply.body().as_bytes();
        let headers = format!(
            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown"),
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .expect("write response headers");
        match reply {
            RawReply::Complete { .. } => stream.write_all(body).await.expect("write response body"),
            RawReply::Truncated { .. } => stream
                .write_all(&body[..body.len() / 2])
                .await
                .expect("write partial response body"),
        }
        stream.shutdown().await.expect("close response");
    }

    #[test]
    fn normalizes_clean_origins_and_rejects_secret_bearing_urls() {
        assert_eq!(
            normalized_base_url("http://localhost:4788")
                .expect("valid URL")
                .as_str(),
            "http://localhost:4788/"
        );
        for invalid in [
            "http://token@localhost:4788",
            "http://localhost:4788/?token=secret",
            "http://localhost:4788/#secret",
            "file:///tmp/executor",
            "http://localhost:4788/prefix",
            "http://example.com:4788",
        ] {
            assert!(normalized_base_url(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn requires_a_token_without_putting_it_in_the_dashboard_url() {
        assert!(matches!(
            GatewayClient::new("http://localhost:4788", None),
            Err(ClientError::MissingToken)
        ));
        let client = GatewayClient::new("http://localhost:4788", Some("secret")).expect("client");
        assert_eq!(client.dashboard_url().as_str(), "http://localhost:4788/");
        assert!(!client.dashboard_url().as_str().contains("secret"));
    }

    #[test]
    fn default_http_accepts_only_resolved_loopback_origins() {
        for origin in [
            "http://127.0.0.1:4788",
            "http://[::1]:4788",
            "http://localhost:4788",
        ] {
            GatewayClient::new(origin, Some("secret")).expect("loopback origin");
        }

        let subdomain = GatewayClient::new_with_policy_and_resolver(
            "http://api.localhost:4788",
            Some("secret"),
            false,
            |hostname, port| {
                assert_eq!(hostname, "api.localhost");
                Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
            },
        )
        .expect("resolved localhost subdomain");
        assert_eq!(subdomain.dashboard_url().host_str(), Some("api.localhost"));
    }

    #[test]
    fn poisoned_localhost_resolution_is_rejected_before_client_creation() {
        let resolutions = Arc::new(AtomicUsize::new(0));
        for resolved_ips in [
            vec![[203, 0, 113, 10]],
            vec![[127, 0, 0, 1], [203, 0, 113, 10]],
        ] {
            let resolver_calls = Arc::clone(&resolutions);
            let error = match GatewayClient::new_with_policy_and_resolver(
                "http://poison.localhost:4788",
                Some("top-secret-token"),
                false,
                move |hostname, port| {
                    resolver_calls.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(hostname, "poison.localhost");
                    Ok(resolved_ips
                        .into_iter()
                        .map(|address| SocketAddr::from((address, port)))
                        .collect())
                },
            ) {
                Ok(_) => panic!("poisoned resolution created an HTTP client"),
                Err(error) => error,
            };

            assert!(matches!(error, ClientError::UnsafeHttpResolution));
            assert!(!error.to_string().contains("top-secret-token"));
        }
        assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn resolved_localhost_is_pinned_for_bearer_requests() {
        async fn invoke(headers: HeaderMap) -> impl IntoResponse {
            assert_eq!(
                headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer secret-token")
            );
            Json(json!({"ok": true, "data": {"pinned": true}}))
        }

        let router = Router::new().route("/api/v1/gateway/tools/invoke", post(invoke));
        let (numeric_base_url, task) = spawn_server(router).await;
        let numeric = Url::parse(&numeric_base_url).expect("numeric test URL");
        let address = match numeric.host().expect("host") {
            url::Host::Ipv4(address) => {
                SocketAddr::new(IpAddr::V4(address), numeric.port().expect("port"))
            }
            host => panic!("expected IPv4 test server, got {host:?}"),
        };
        let client = GatewayClient::new_with_policy_and_resolver(
            &format!("http://gateway.localhost:{}/", address.port()),
            Some("secret-token"),
            false,
            move |hostname, port| {
                assert_eq!(hostname, "gateway.localhost");
                assert_eq!(port, address.port());
                Ok(vec![address])
            },
        )
        .expect("pinned client");

        let InvokeResponse::Complete(result) = client
            .invoke("tools.jobs.run", json!({}), "pinned-request")
            .await
            .expect("pinned request")
        else {
            panic!("expected completed invocation");
        };
        assert_eq!(result["data"]["pinned"], true);
        task.abort();
    }

    #[test]
    fn https_and_explicit_insecure_http_skip_loopback_resolution() {
        for (origin, allow_insecure_http) in [
            ("https://example.test:4788", false),
            ("http://example.test:4788", true),
        ] {
            let client = GatewayClient::new_with_policy_and_resolver(
                origin,
                Some("secret"),
                allow_insecure_http,
                |_, _| panic!("safe-mode loopback resolution was not required"),
            )
            .expect("origin without safe-mode plaintext resolution");
            assert_eq!(client.dashboard_url().host_str(), Some("example.test"));
        }
    }

    #[tokio::test]
    async fn invocation_uses_auth_header_and_never_a_url_secret() {
        async fn invoke(
            State(sender): State<CapturedRequestSender>,
            uri: Uri,
            headers: HeaderMap,
        ) -> impl IntoResponse {
            if let Some(sender) = sender.lock().expect("sender lock").take() {
                let _ = sender.send((uri, headers));
            }
            Json(json!({"ok": true, "data": {"value": 2}}))
        }

        let (sender, receiver) = oneshot::channel();
        let state = std::sync::Arc::new(std::sync::Mutex::new(Some(sender)));
        let router = Router::new()
            .route("/api/v1/gateway/tools/invoke", post(invoke))
            .with_state(state);
        let (base_url, task) = spawn_server(router).await;
        let client = GatewayClient::new(&base_url, Some("secret-token")).expect("client");
        let result = client
            .invoke("tools.math.add", json!({}), "one-command-key")
            .await
            .expect("invoke");
        assert!(matches!(result, InvokeResponse::Complete(_)));
        let (uri, headers) = receiver.await.expect("request capture");
        assert_eq!(uri.path(), "/api/v1/gateway/tools/invoke");
        assert_eq!(uri.query(), None);
        assert_eq!(
            headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer secret-token")
        );
        assert_eq!(
            headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok()),
            Some("one-command-key")
        );
        task.abort();
    }

    #[tokio::test]
    async fn bearer_requests_never_follow_redirects() {
        async fn redirect(State(location): State<String>, headers: HeaderMap) -> impl IntoResponse {
            assert_eq!(
                headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer redirect-secret")
            );
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, location)],
            )
        }

        let target = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("redirect target listener");
        let target_address = target.local_addr().expect("target address");
        let router = Router::new()
            .route("/api/v1/gateway/tools/invoke", post(redirect))
            .with_state(format!("http://{target_address}/steal"));
        let (base_url, task) = spawn_server(router).await;
        let client = GatewayClient::new(&base_url, Some("redirect-secret")).expect("client");

        let error = match client
            .invoke("tools.jobs.run", json!({}), "redirect-request")
            .await
        {
            Ok(_) => panic!("redirect unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ClientError::Api {
                status: StatusCode::TEMPORARY_REDIRECT,
                ..
            }
        ));
        assert!(!error.to_string().contains("redirect-secret"));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), target.accept())
                .await
                .is_err(),
            "redirect target received a bearer-bearing request"
        );
        task.abort();
    }

    #[tokio::test]
    async fn api_error_fields_cannot_reflect_the_bearer_token() {
        async fn reflected(headers: HeaderMap) -> impl IntoResponse {
            assert_eq!(
                headers
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok()),
                Some("Bearer secret-reflection-token")
            );
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": {
                        "code": "secret-reflection-token",
                        "message": "Bearer secret-reflection-token was rejected",
                        "requestId": "secret-reflection-token"
                    }
                })),
            )
        }

        let router = Router::new().route("/api/v1/gateway/sources", get(reflected));
        let (base_url, task) = spawn_server(router).await;
        let client = GatewayClient::new(&base_url, Some("secret-reflection-token"))
            .expect("loopback client");

        let error = client.sources().await.expect_err("reflected API error");
        let rendered = error.to_string();
        assert!(!rendered.contains("secret-reflection-token"));
        assert!(rendered.contains("[redacted]"));
        task.abort();
    }

    #[tokio::test]
    async fn decodes_approval_poll_cancel_and_revoked_token_errors() {
        async fn invoke() -> impl IntoResponse {
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "status": "approval_required",
                    "approval": {
                        "id": "approval-1",
                        "status": "pending",
                        "revision": 0,
                        "path": "tools.mail.send",
                        "createdAt": 1,
                        "expiresAt": 60,
                        "statusUrl": "/api/v1/gateway/approvals/approval-1"
                    }
                })),
            )
        }
        async fn approval() -> impl IntoResponse {
            Json(json!({
                "id": "approval-1",
                "status": "succeeded",
                "revision": 2,
                "path": "tools.mail.send",
                "createdAt": 1,
                "updatedAt": 2,
                "expiresAt": 60,
                "failureCode": null,
                "result": {"ok": true, "data": {"sent": true}}
            }))
        }
        async fn revoked() -> impl IntoResponse {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": {
                        "code": "unauthorized",
                        "message": "The API token is no longer active.",
                        "requestId": "request-1"
                    }
                })),
            )
        }
        let router = Router::new()
            .route("/api/v1/gateway/tools/invoke", post(invoke))
            .route(
                "/api/v1/gateway/approvals/approval-1",
                get(approval).delete(approval),
            )
            .route("/api/v1/gateway/sources", get(revoked));
        let (base_url, task) = spawn_server(router).await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");
        let InvokeResponse::ApprovalRequired(pending) = client
            .invoke("tools.mail.send", json!({}), "approval-key")
            .await
            .expect("approval")
        else {
            panic!("expected approval");
        };
        let detail = client
            .approval(&pending.approval.id)
            .await
            .expect("approval detail");
        assert_eq!(detail.status, "succeeded");
        let cancelled = client
            .cancel_approval(&pending.approval.id, detail.revision)
            .await
            .expect("cancel request");
        assert_eq!(cancelled.id, "approval-1");
        let error = client.sources().await.expect_err("revoked token");
        assert!(matches!(
            error,
            ClientError::Api {
                status: StatusCode::UNAUTHORIZED,
                ref code,
                ..
            } if code == "unauthorized"
        ));
        assert!(error.to_string().contains("request request-1"));
        task.abort();
    }

    #[tokio::test]
    async fn reports_when_the_server_is_not_running() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let client =
            GatewayClient::new(&format!("http://{address}"), Some("token")).expect("client");
        assert!(matches!(
            client.sources().await,
            Err(ClientError::Unreachable { .. })
        ));
    }

    #[test]
    fn approval_ids_cannot_redirect_bearer_requests() {
        for invalid in [
            "https://attacker.example/x",
            "/https://attacker.example/x",
            "../other",
            "approval?id=secret",
        ] {
            assert!(approval_path(invalid).is_err(), "accepted {invalid}");
        }
        assert_eq!(
            approval_path("9d6e9268-197d-4e60-b267-3f2bf85d368f").expect("UUID"),
            "api/v1/gateway/approvals/9d6e9268-197d-4e60-b267-3f2bf85d368f"
        );
    }

    #[tokio::test]
    async fn retries_in_progress_with_the_same_idempotency_key() {
        #[derive(Clone, Default)]
        struct StateValue {
            calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        }
        async fn invoke(State(state): State<StateValue>, headers: HeaderMap) -> impl IntoResponse {
            let key = headers
                .get("idempotency-key")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let count = {
                let mut calls = state.calls.lock().expect("calls");
                calls.push(key);
                calls.len()
            };
            if count < 3 {
                return (
                    StatusCode::CONFLICT,
                    [(header::RETRY_AFTER, "0")],
                    Json(json!({
                        "error": {
                            "code": "idempotency_in_progress",
                            "message": "Still running",
                            "requestId": "request-1"
                        }
                    })),
                )
                    .into_response();
            }
            Json(json!({"ok": true, "data": {"done": true}})).into_response()
        }
        let state = StateValue::default();
        let router = Router::new()
            .route("/api/v1/gateway/tools/invoke", post(invoke))
            .with_state(state.clone());
        let (base_url, task) = spawn_server(router).await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");
        let result = client
            .invoke("tools.jobs.run", json!({}), "stable-key")
            .await
            .expect("eventual replay");
        assert!(matches!(result, InvokeResponse::Complete(_)));
        assert_eq!(
            state.calls.lock().expect("calls").as_slice(),
            ["stable-key", "stable-key", "stable-key"]
        );
        task.abort();
    }

    #[tokio::test]
    async fn in_progress_wait_exhaustion_preserves_the_recovery_identity() {
        const BODY: &str = r#"{"error":{"code":"idempotency_in_progress","message":"Still running","requestId":"request-1"}}"#;
        let (base_url, task, state) = spawn_raw_server(vec![RawReply::Complete {
            status: StatusCode::CONFLICT,
            body: BODY,
        }])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let error = match client
            .invoke_with_wait_limit(
                "tools.jobs.run",
                json!({}),
                "in-progress-recovery-key",
                Duration::ZERO,
            )
            .await
        {
            Ok(_) => panic!("expected unresolved in-progress invocation"),
            Err(error) => error,
        };

        assert!(matches!(error, ClientError::OutcomeUnknown { .. }));
        assert!(error.to_string().contains("in-progress-recovery-key"));
        finish_raw_server(task).await;
        let calls = state.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].idempotency_key.as_deref(),
            Some("in-progress-recovery-key")
        );
    }

    #[tokio::test]
    async fn malformed_conflict_replays_then_exhausts_as_outcome_unknown() {
        let (base_url, task, state) = spawn_raw_server(vec![
            RawReply::Complete {
                status: StatusCode::CONFLICT,
                body: "not-json",
            },
            RawReply::Complete {
                status: StatusCode::CONFLICT,
                body: "still-not-json",
            },
        ])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let error = match client
            .invoke("tools.jobs.run", json!({}), "conflict-recovery-key")
            .await
        {
            Ok(_) => panic!("expected unresolved conflict response"),
            Err(error) => error,
        };

        assert!(matches!(error, ClientError::OutcomeUnknown { .. }));
        assert!(error.to_string().contains("conflict-recovery-key"));
        finish_raw_server(task).await;
        let calls = state.calls.lock().expect("calls");
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|call| call.idempotency_key.as_deref() == Some("conflict-recovery-key"))
        );
    }

    #[tokio::test]
    async fn truncated_server_error_replays_with_the_same_identity() {
        const ERROR_BODY: &str = r#"{"error":{"code":"internal_error","message":"Response unavailable","requestId":"request-1"}}"#;
        const SUCCESS_BODY: &str = r#"{"ok":true,"data":{"executions":1}}"#;
        let (base_url, task, state) = spawn_raw_server(vec![
            RawReply::Truncated {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                body: ERROR_BODY,
            },
            RawReply::Complete {
                status: StatusCode::OK,
                body: SUCCESS_BODY,
            },
        ])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let InvokeResponse::Complete(result) = client
            .invoke("tools.jobs.run", json!({}), "server-error-replay-key")
            .await
            .expect("safe replay")
        else {
            panic!("expected completed invocation");
        };

        assert_eq!(result["data"]["executions"], 1);
        finish_raw_server(task).await;
        let calls = state.calls.lock().expect("calls");
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|call| { call.idempotency_key.as_deref() == Some("server-error-replay-key") })
        );
        assert_eq!(state.dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn malformed_server_error_replays_then_exhausts_as_outcome_unknown() {
        let (base_url, task, state) = spawn_raw_server(vec![
            RawReply::Complete {
                status: StatusCode::BAD_GATEWAY,
                body: "not-json",
            },
            RawReply::Complete {
                status: StatusCode::BAD_GATEWAY,
                body: "still-not-json",
            },
        ])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let error = match client
            .invoke("tools.jobs.run", json!({}), "server-error-unknown-key")
            .await
        {
            Ok(_) => panic!("expected unresolved server error response"),
            Err(error) => error,
        };

        assert!(matches!(error, ClientError::OutcomeUnknown { .. }));
        assert!(error.to_string().contains("server-error-unknown-key"));
        finish_raw_server(task).await;
        let calls = state.calls.lock().expect("calls");
        assert_eq!(calls.len(), 2);
        assert!(
            calls.iter().all(|call| {
                call.idempotency_key.as_deref() == Some("server-error-unknown-key")
            })
        );
        assert_eq!(state.dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn replays_a_committed_mutation_after_the_first_response_is_truncated() {
        const BODY: &str = r#"{"ok":true,"data":{"executions":1}}"#;
        let (base_url, task, state) = spawn_raw_server(vec![
            RawReply::Truncated {
                status: StatusCode::OK,
                body: BODY,
            },
            RawReply::Complete {
                status: StatusCode::OK,
                body: BODY,
            },
        ])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let InvokeResponse::Complete(result) = client
            .invoke("tools.jobs.run", json!({}), "stable-replay-key")
            .await
            .expect("safe replay")
        else {
            panic!("expected completed invocation");
        };

        assert_eq!(result["data"]["executions"], 1);
        finish_raw_server(task).await;
        let calls = state.calls.lock().expect("calls");
        assert_eq!(calls.len(), 2);
        assert!(calls.iter().all(|call| {
            call.method == "POST"
                && call.target == "/api/v1/gateway/tools/invoke"
                && call.idempotency_key.as_deref() == Some("stable-replay-key")
        }));
        assert_eq!(state.dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn replays_with_the_same_identity_when_a_success_body_cannot_be_decoded() {
        const BODY: &str = r#"{"ok":true,"data":{"executions":1}}"#;
        let (base_url, task, state) = spawn_raw_server(vec![
            RawReply::Complete {
                status: StatusCode::OK,
                body: "not-json",
            },
            RawReply::Complete {
                status: StatusCode::OK,
                body: BODY,
            },
        ])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let InvokeResponse::Complete(result) = client
            .invoke("tools.jobs.run", json!({}), "decode-replay-key")
            .await
            .expect("safe replay")
        else {
            panic!("expected completed invocation");
        };

        assert_eq!(result["data"]["executions"], 1);
        finish_raw_server(task).await;
        let calls = state.calls.lock().expect("calls");
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|call| call.idempotency_key.as_deref() == Some("decode-replay-key"))
        );
        assert_eq!(state.dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn repeated_response_truncation_exhausts_as_outcome_unknown() {
        const BODY: &str = r#"{"ok":true,"data":{"executions":1}}"#;
        let (base_url, task, state) = spawn_raw_server(vec![
            RawReply::Truncated {
                status: StatusCode::OK,
                body: BODY,
            },
            RawReply::Truncated {
                status: StatusCode::OK,
                body: BODY,
            },
        ])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let error = match client
            .invoke("tools.jobs.run", json!({}), "exhausted-replay-key")
            .await
        {
            Ok(_) => panic!("expected unresolved response ambiguity"),
            Err(error) => error,
        };

        assert!(matches!(error, ClientError::OutcomeUnknown { .. }));
        assert!(error.to_string().contains("outcome is unknown"));
        assert!(error.to_string().contains("exhausted-replay-key"));
        finish_raw_server(task).await;
        let calls = state.calls.lock().expect("calls");
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|call| { call.idempotency_key.as_deref() == Some("exhausted-replay-key") })
        );
        assert_eq!(state.dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn definitive_client_errors_are_not_retried() {
        const BODY: &str = r#"{"error":{"code":"invalid_arguments","message":"Bad input","requestId":"request-1"}}"#;
        let (base_url, task, state) = spawn_raw_server(vec![RawReply::Complete {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            body: BODY,
        }])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let error = match client
            .invoke("tools.jobs.run", json!({}), "definitive-error-key")
            .await
        {
            Ok(_) => panic!("expected typed API error"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ClientError::Api {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                ref code,
                ..
            } if code == "invalid_arguments"
        ));
        finish_raw_server(task).await;
        assert_eq!(state.calls.lock().expect("calls").len(), 1);
        assert_eq!(state.dispatches.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn non_idempotent_mutations_are_not_retried_after_response_truncation() {
        const BODY: &str = r#"{"id":"approval-1","status":"canceled","revision":2,"path":"tools.mail.send","createdAt":1,"updatedAt":2,"expiresAt":60,"failureCode":"canceled","result":null}"#;
        let (base_url, task, state) = spawn_raw_server(vec![RawReply::Truncated {
            status: StatusCode::OK,
            body: BODY,
        }])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let error = client
            .cancel_approval("approval-1", 1)
            .await
            .expect_err("unknown cancellation outcome");

        assert!(matches!(error, ClientError::OutcomeUnknown { .. }));
        assert!(error.to_string().contains("not automatically retried"));
        finish_raw_server(task).await;
        let calls = state.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, "DELETE");
        assert_eq!(
            calls[0].target,
            "/api/v1/gateway/approvals/approval-1?expectedRevision=1"
        );
        assert_eq!(calls[0].idempotency_key, None);
        assert_eq!(state.dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn non_idempotent_mutations_preserve_unknown_outcomes_for_truncated_server_errors() {
        const BODY: &str = r#"{"error":{"code":"internal_error","message":"Response unavailable","requestId":"request-1"}}"#;
        let (base_url, task, state) = spawn_raw_server(vec![RawReply::Truncated {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: BODY,
        }])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let error = client
            .cancel_approval("approval-1", 1)
            .await
            .expect_err("unknown cancellation outcome");

        assert!(matches!(error, ClientError::OutcomeUnknown { .. }));
        assert!(error.to_string().contains("not automatically retried"));
        finish_raw_server(task).await;
        assert_eq!(state.calls.lock().expect("calls").len(), 1);
        assert_eq!(state.dispatches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn query_responses_still_decode_normally() {
        const BODY: &str = r#"{"ok":true,"data":{"sources":[{"id":"source-1"}]}}"#;
        let (base_url, task, state) = spawn_raw_server(vec![RawReply::Complete {
            status: StatusCode::OK,
            body: BODY,
        }])
        .await;
        let client = GatewayClient::new(&base_url, Some("token")).expect("client");

        let result = client.sources().await.expect("sources query");

        assert_eq!(result["data"]["sources"][0]["id"], "source-1");
        finish_raw_server(task).await;
        let calls = state.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].method, "GET");
        assert_eq!(calls[0].target, "/api/v1/gateway/sources");
        assert_eq!(calls[0].idempotency_key, None);
    }
}
