use std::time::{Duration, Instant};

use reqwest::{Method, Response, StatusCode, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use thiserror::Error;
use url::Url;

use super::terminal::safe_field;

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

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
        let token = token
            .filter(|token| !token.is_empty())
            .ok_or(ClientError::MissingToken)?;
        let base_url = normalized_base_url_with_policy(base_url, allow_insecure_http)?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(35))
            .user_agent(concat!("executor-cli/", env!("CARGO_PKG_VERSION")))
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
        let payload = json!({"path": path, "arguments": arguments});
        let mut retry = false;
        let started = Instant::now();
        let response = loop {
            let response = self
                .request(Method::POST, "api/v1/gateway/tools/invoke")?
                .header("idempotency-key", idempotency_key)
                .json(&payload)
                .send()
                .await;
            match response {
                Ok(response) if response.status() == StatusCode::CONFLICT => {
                    let retry_after = response
                        .headers()
                        .get(header::RETRY_AFTER)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(1)
                        .min(2);
                    let bytes = read_bounded(response).await?;
                    let envelope = serde_json::from_slice::<ErrorEnvelope>(&bytes).ok();
                    if envelope
                        .as_ref()
                        .is_some_and(|envelope| envelope.error.code == "idempotency_in_progress")
                        && started.elapsed() < Duration::from_secs(60)
                    {
                        tokio::time::sleep(Duration::from_secs(retry_after)).await;
                        continue;
                    }
                    return Err(api_error(StatusCode::CONFLICT, envelope));
                }
                Ok(response) => break response,
                Err(_) if !retry => {
                    retry = true;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(source) => return Err(self.unreachable(source)),
            }
        };
        if response.status() == StatusCode::ACCEPTED {
            return self
                .decode_success::<ApprovalRequired>(response)
                .await
                .map(InvokeResponse::ApprovalRequired);
        }
        self.decode_success(response)
            .await
            .map(InvokeResponse::Complete)
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
            .map_err(|source| self.unreachable(source))?;
        self.decode_success(response).await
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
        let bytes = read_bounded(response).await?;
        if !status.is_success() {
            let envelope = serde_json::from_slice::<ErrorEnvelope>(&bytes).ok();
            return Err(api_error(status, envelope));
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))
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
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
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

fn api_error(status: StatusCode, envelope: Option<ErrorEnvelope>) -> ClientError {
    let (code, message, request_suffix) = match envelope {
        Some(envelope) => (
            safe_field(&envelope.error.code),
            safe_field(&envelope.error.message),
            envelope
                .error
                .request_id
                .map(|id| format!(" (request {})", safe_field(&id)))
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

async fn read_bounded(mut response: Response) -> Result<Vec<u8>, ClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ClientError::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ClientError::InvalidResponse(error.to_string()))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ClientError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, Uri},
        response::IntoResponse,
        routing::{get, post},
    };
    use serde_json::json;
    use tokio::sync::oneshot;

    use super::*;

    type CapturedRequestSender =
        std::sync::Arc<std::sync::Mutex<Option<oneshot::Sender<(Uri, HeaderMap)>>>>;

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
}
