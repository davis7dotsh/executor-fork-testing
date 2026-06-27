use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    extract::{
        DefaultBodyLimit, Extension, Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{
    AdminAuthentication, AdminMutation, ApiError, AppState, ErrorDetail, ErrorEnvelope,
    GatewayAuthentication, RequestId, parse_json,
};
use crate::{
    actor::ToolActor,
    approval::ApprovalError,
    catalog::{
        AuditContext, CatalogError, RequestSurface, SourceKind,
        source_idempotency::{
            SOURCE_CREATION_ROUTE, SourceCreationIdempotencyClaim, SourceCreationIdempotencyError,
            SourceCreationIdempotencyStatus, SourceCreationIdempotencyStore, SourceCreationReplay,
            SourceCreationReservation, SourceCreationResponse, SourceCreationResponseKind,
            source_creation_idempotency_key_is_valid,
        },
    },
    execution::{ExecuteCodeRequest, ExecutionServiceError},
    invocation::{
        GatewayInvokeError, GatewayInvokeResponse, ToolCall, ToolCallAdapterErrorCode,
        ToolCallError, ToolCallOAuthError, ToolCallSubmission, ToolDiscoveryError,
        gateway_idempotency_key_is_valid,
    },
    outbound::OutboundError,
    protocols::{CredentialMetadata, ProtocolError, ProtocolErrorCategory},
    runtime::RuntimeFailure,
};

const MAX_SOURCE_BODY_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;
const MAX_INVOKE_BODY_BYTES: usize = crate::invocation::MAX_ARGUMENT_BYTES + 64 * 1024;
const MAX_EXECUTE_BODY_BYTES: usize = crate::runtime::MAX_SOURCE_BYTES + 64 * 1024;
const DEFAULT_EXECUTION_TIMEOUT_MILLIS: u64 = 30_000;
const MAX_EXECUTION_TIMEOUT_MILLIS: u64 = 300_000;
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
const SOURCE_CREATION_RECOVERY_ATTEMPTS: usize = 4;

#[derive(Clone, Default)]
pub(super) struct SourceCreationSupervisorRegistry {
    active: Arc<Mutex<HashMap<SourceCreationSupervisorKey, Arc<SourceCreationCompletion>>>>,
}

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
struct SourceCreationSupervisorKey {
    admin_id: i64,
    key_digest: [u8; 32],
}

struct SourceCreationCompletion {
    finished: AtomicBool,
    notify: tokio::sync::Notify,
}

struct SourceCreationSupervisorGuard {
    registry: SourceCreationSupervisorRegistry,
    key: SourceCreationSupervisorKey,
    completion: Arc<SourceCreationCompletion>,
}

impl SourceCreationSupervisorRegistry {
    fn register(&self, key: SourceCreationSupervisorKey) -> SourceCreationSupervisorGuard {
        let completion = Arc::new(SourceCreationCompletion {
            finished: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        });
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, completion.clone());
        SourceCreationSupervisorGuard {
            registry: self.clone(),
            key,
            completion,
        }
    }

    async fn wait_if_active(&self, key: SourceCreationSupervisorKey) {
        let completion = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .cloned();
        if let Some(completion) = completion {
            completion.wait().await;
        }
    }
}

impl SourceCreationCompletion {
    async fn wait(&self) {
        loop {
            let finished = self.notify.notified();
            if self.finished.load(Ordering::Acquire) {
                return;
            }
            finished.await;
        }
    }
}

impl Drop for SourceCreationSupervisorGuard {
    fn drop(&mut self) {
        self.completion.finished.store(true, Ordering::Release);
        self.completion.notify.notify_waiters();
        let mut active = self
            .registry
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active
            .get(&self.key)
            .is_some_and(|completion| Arc::ptr_eq(completion, &self.completion))
        {
            active.remove(&self.key);
        }
    }
}

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sources", post(create_source))
        .route("/api/v1/sources/idempotency", get(source_creation_status))
        .route(
            "/api/v1/sources/idempotency/seal",
            post(seal_missing_source_creation),
        )
        .layer(DefaultBodyLimit::max(MAX_SOURCE_BODY_BYTES))
        .merge(
            Router::new()
                .route("/api/v1/sources/{id}/refresh", post(refresh_source))
                .route("/api/v1/mcp/stdio/templates", get(stdio_templates))
                .route(
                    "/api/v1/sources/{id}/credentials",
                    get(get_credentials)
                        .put(put_credentials)
                        .delete(delete_credentials),
                ),
        )
        .merge(
            Router::new()
                .route("/api/v1/gateway/tools/invoke", post(invoke))
                .route("/api/v1/gateway/sources", get(gateway_sources))
                .layer(DefaultBodyLimit::max(MAX_INVOKE_BODY_BYTES)),
        )
        .merge(
            Router::new()
                .route("/api/v1/gateway/execute", post(execute))
                .layer(DefaultBodyLimit::max(MAX_EXECUTE_BODY_BYTES)),
        )
}

#[derive(Serialize)]
struct StdioTemplatesResponse {
    templates: Vec<crate::mcp::upstream::stdio::StdioTemplateDescriptor>,
}

async fn stdio_templates(
    _admin: AdminAuthentication,
    State(state): State<AppState>,
) -> Json<StdioTemplatesResponse> {
    Json(StdioTemplatesResponse {
        templates: state.sources.stdio_template_descriptors(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewaySourcesResponse {
    sources: Vec<GatewaySourceResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewaySourceResponse {
    slug: String,
    display_name: String,
    description: Option<String>,
    kind: SourceKind,
    tool_count: usize,
}

async fn gateway_sources(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    GatewayAuthentication(identity): GatewayAuthentication,
) -> Result<Json<GatewaySourcesResponse>, ApiError> {
    let call = ToolCall {
        request_id: request_id.0.clone(),
        actor: ToolActor::api_token(identity.token_id, Some(identity.token_name)),
        surface: RequestSurface::Gateway,
        execution_id: request_id.0.clone(),
        call_id: "gateway.sources".to_owned(),
        worker_generation: 0,
        path: "executor.sources".to_owned(),
        arguments: Value::Object(Map::new()),
    };
    let discovered = state
        .tool_calls
        .discover_sources(&call)
        .await
        .map_err(|error| discovery_error(&request_id, error))?;
    let Value::Array(items) = discovered else {
        return Err(ApiError::internal_logged(
            &request_id,
            "source discovery returned an invalid payload",
        ));
    };
    let mut sources = Vec::with_capacity(items.len());
    for item in items {
        let Some(item) = item.as_object() else {
            return Err(ApiError::internal(&request_id));
        };
        let source = GatewaySourceResponse {
            slug: required_string(item, "slug").ok_or_else(|| ApiError::internal(&request_id))?,
            display_name: required_string(item, "displayName")
                .ok_or_else(|| ApiError::internal(&request_id))?,
            description: item
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned),
            kind: serde_json::from_value(
                item.get("kind")
                    .cloned()
                    .ok_or_else(|| ApiError::internal(&request_id))?,
            )
            .map_err(|_| ApiError::internal(&request_id))?,
            tool_count: item
                .get("toolCount")
                .and_then(Value::as_u64)
                .and_then(|count| usize::try_from(count).ok())
                .ok_or_else(|| ApiError::internal(&request_id))?,
        };
        sources.push(source);
    }
    Ok(Json(GatewaySourcesResponse { sources }))
}

fn required_string(item: &Map<String, Value>, field: &str) -> Option<String> {
    item.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn discovery_error(request_id: &RequestId, error: ToolDiscoveryError) -> ApiError {
    match error {
        ToolDiscoveryError::Busy => ApiError::new(
            request_id,
            StatusCode::TOO_MANY_REQUESTS,
            "search_busy",
            "Tool discovery is busy. Try again shortly.",
        )
        .with_retry_after(1),
        ToolDiscoveryError::Catalog(error) => catalog_error(request_id, error),
        ToolDiscoveryError::Interrupted => ApiError::new(
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "discovery_interrupted",
            "Tool discovery was interrupted. Try again.",
        ),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecuteRequest {
    code: String,
    timeout_ms: Option<u64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecuteResponse {
    execution_id: String,
    result: Value,
    emits: Vec<Value>,
    console: Vec<crate::runtime::ConsoleEntry>,
    calls: Vec<crate::runtime::ToolCallRecord>,
}

async fn execute(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    GatewayAuthentication(identity): GatewayAuthentication,
    headers: HeaderMap,
    payload: Result<Json<ExecuteRequest>, JsonRejection>,
) -> Result<Json<ExecuteResponse>, ApiError> {
    if headers.contains_key(IDEMPOTENCY_KEY_HEADER) {
        return Err(ApiError::new(
            &request_id,
            StatusCode::BAD_REQUEST,
            "idempotency_not_supported",
            "Idempotency-Key is not supported for whole TypeScript executions yet.",
        ));
    }
    let Json(payload) = match parse_json(&request_id, payload) {
        Ok(payload) => payload,
        Err(error) => {
            state.tool_calls.record_rejected_request(
                &request_id.0,
                &identity.token_id,
                RequestSurface::Gateway,
                "executor.execute",
                error.code,
            );
            return Err(error);
        }
    };
    let timeout_ms = payload
        .timeout_ms
        .unwrap_or(DEFAULT_EXECUTION_TIMEOUT_MILLIS);
    let output = state
        .execution
        .execute(ExecuteCodeRequest {
            request_id: request_id.0.clone(),
            actor: ToolActor::api_token(identity.token_id, Some(identity.token_name)),
            surface: RequestSurface::Gateway,
            code: payload.code,
            timeout: std::time::Duration::from_millis(timeout_ms),
        })
        .await
        .map_err(|error| execution_error(&request_id, error))?;
    Ok(Json(ExecuteResponse {
        execution_id: output.execution_id,
        result: output.result,
        emits: output.emits,
        console: output.console,
        calls: output.calls,
    }))
}

fn execution_error(request_id: &RequestId, error: ExecutionServiceError) -> ApiError {
    match error {
        ExecutionServiceError::SourceTooLarge => ApiError::new(
            request_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "source_too_large",
            "TypeScript source exceeds 1 MiB.",
        ),
        ExecutionServiceError::InvalidTimeout => ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_timeout",
            format!(
                "Execution timeout must be between 1 and {MAX_EXECUTION_TIMEOUT_MILLIS} milliseconds."
            ),
        ),
        ExecutionServiceError::ShuttingDown => ApiError::new(
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_shutting_down",
            "The TypeScript runtime is shutting down.",
        ),
        ExecutionServiceError::OwnerRevoked => {
            ApiError::unauthorized(request_id, "The API token is no longer active.")
        }
        ExecutionServiceError::ActorFailed => {
            tracing::error!(request_id = request_id.0, "runtime execution task failed");
            ApiError::internal(request_id)
        }
        ExecutionServiceError::Runtime(failure) => runtime_error(request_id, failure),
    }
}

fn runtime_error(request_id: &RequestId, failure: RuntimeFailure) -> ApiError {
    let status = match failure.code.as_str() {
        "source_too_large" | "result_too_large" => StatusCode::PAYLOAD_TOO_LARGE,
        "runtime_busy" => StatusCode::TOO_MANY_REQUESTS,
        "execution_timeout" => StatusCode::REQUEST_TIMEOUT,
        "execution_cancelled" => StatusCode::CONFLICT,
        "invalid_timeout"
        | "typescript_invalid"
        | "typescript_unsupported"
        | "transformed_source_too_large"
        | "execution_failed"
        | "result_not_json"
        | "argument_too_large"
        | "tool_call_limit_exceeded"
        | "tool_path_invalid" => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let code: &'static str = match failure.code.as_str() {
        "source_too_large" => "source_too_large",
        "result_too_large" => "result_too_large",
        "runtime_busy" => "runtime_busy",
        "execution_timeout" => "execution_timeout",
        "execution_cancelled" => "execution_cancelled",
        "invalid_timeout" => "invalid_timeout",
        "typescript_invalid" => "typescript_invalid",
        "typescript_unsupported" => "typescript_unsupported",
        "transformed_source_too_large" => "transformed_source_too_large",
        "execution_failed" => "execution_failed",
        "result_not_json" => "result_not_json",
        "argument_too_large" => "argument_too_large",
        "tool_call_limit_exceeded" => "tool_call_limit_exceeded",
        "tool_path_invalid" => "tool_path_invalid",
        _ => "runtime_failed",
    };
    let message = if failure.internal {
        "The TypeScript execution could not be completed safely.".to_owned()
    } else {
        failure.message
    };
    let error = ApiError::new(request_id, status, code, message);
    if code == "runtime_busy" {
        error.with_retry_after(1)
    } else {
        error
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateSourceRequest {
    kind: SourceKind,
    #[serde(flatten)]
    protocol: Map<String, Value>,
}

async fn create_source(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    AdminMutation(admin_id): AdminMutation,
    headers: HeaderMap,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Response, ApiError> {
    let idempotency_key = parse_source_creation_idempotency_key(&request_id, &headers)?;
    let Json(payload) = parse_json(&request_id, payload)?;
    let payload: CreateSourceRequest = serde_json::from_value(payload).map_err(|_| {
        ApiError::new(
            &request_id,
            StatusCode::BAD_REQUEST,
            "invalid_json",
            "The request body must be valid JSON with the expected fields.",
        )
    })?;
    let canonical_request = serde_json::to_value(&payload)
        .map_err(|error| ApiError::internal_logged(&request_id, error))?;
    let Some(idempotency_key) = idempotency_key else {
        let source = state
            .sources
            .create(
                payload.kind,
                Value::Object(payload.protocol),
                AuditContext::admin(&request_id.0, admin_id),
            )
            .await
            .map_err(|error| protocol_error(&request_id, error))?;
        return Ok((StatusCode::CREATED, Json(source)).into_response());
    };

    let idempotency = state.sources.source_creation_idempotency();
    let active_key = source_creation_supervisor_key(&state, admin_id, &idempotency_key);
    let claim = idempotency
        .claim(
            admin_id,
            SOURCE_CREATION_ROUTE,
            &idempotency_key,
            &canonical_request,
        )
        .await
        .map_err(|error| source_creation_idempotency_error(&request_id, error))?;
    match claim {
        SourceCreationIdempotencyClaim::Fresh(reservation) => {
            start_source_creation(
                &request_id,
                &state,
                admin_id,
                idempotency_key,
                payload,
                idempotency,
                reservation,
                active_key,
            )
            .await
        }
        SourceCreationIdempotencyClaim::Replay(replay) => {
            state
                .source_creation_supervisors
                .wait_if_active(active_key)
                .await;
            exact_source_creation_response(&request_id, replay.response, true)
        }
        SourceCreationIdempotencyClaim::InProgress => Err(source_creation_in_progress(&request_id)),
        SourceCreationIdempotencyClaim::Mismatch => Err(ApiError::new(
            &request_id,
            StatusCode::CONFLICT,
            "idempotency_key_mismatch",
            "This Idempotency-Key was already used for a different source creation request.",
        )),
        SourceCreationIdempotencyClaim::Abandoned => {
            Err(source_creation_terminal_error(&request_id, "abandoned"))
        }
        SourceCreationIdempotencyClaim::Interrupted => {
            Err(source_creation_terminal_error(&request_id, "interrupted"))
        }
        SourceCreationIdempotencyClaim::Expired => Err(source_creation_terminal_error(
            &request_id,
            "expired_unknown",
        )),
    }
}

async fn source_creation_status(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    AdminAuthentication(admin_id): AdminAuthentication,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let key = require_source_creation_idempotency_key(&request_id, &headers)?;
    let active_key = source_creation_supervisor_key(&state, admin_id, &key);
    let status = state
        .sources
        .source_creation_idempotency()
        .lookup(admin_id, SOURCE_CREATION_ROUTE, &key)
        .await
        .map_err(|error| source_creation_idempotency_error(&request_id, error))?;
    match status {
        None => source_creation_status_response(&request_id, "missing"),
        Some(SourceCreationIdempotencyStatus::InProgress) => {
            source_creation_status_response(&request_id, "in_progress")
        }
        Some(SourceCreationIdempotencyStatus::Replay(replay)) => {
            state
                .source_creation_supervisors
                .wait_if_active(active_key)
                .await;
            exact_source_creation_response(&request_id, replay.response, true)
        }
        Some(SourceCreationIdempotencyStatus::Abandoned) => {
            source_creation_status_response(&request_id, "abandoned")
        }
        Some(SourceCreationIdempotencyStatus::Interrupted) => {
            source_creation_status_response(&request_id, "interrupted")
        }
        Some(SourceCreationIdempotencyStatus::Expired) => {
            source_creation_status_response(&request_id, "expired_unknown")
        }
    }
}

async fn seal_missing_source_creation(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    AdminMutation(admin_id): AdminMutation,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let key = require_source_creation_idempotency_key(&request_id, &headers)?;
    let active_key = source_creation_supervisor_key(&state, admin_id, &key);
    let status = state
        .sources
        .source_creation_idempotency()
        .seal_missing(admin_id, SOURCE_CREATION_ROUTE, &key)
        .await
        .map_err(|error| source_creation_idempotency_error(&request_id, error))?;
    match status {
        SourceCreationIdempotencyStatus::Abandoned => {
            source_creation_status_response(&request_id, "abandoned")
        }
        SourceCreationIdempotencyStatus::InProgress => {
            Err(source_creation_in_progress(&request_id))
        }
        SourceCreationIdempotencyStatus::Replay(replay) => {
            state
                .source_creation_supervisors
                .wait_if_active(active_key)
                .await;
            exact_source_creation_response(&request_id, replay.response, true)
        }
        SourceCreationIdempotencyStatus::Interrupted => {
            Err(source_creation_terminal_error(&request_id, "interrupted"))
        }
        SourceCreationIdempotencyStatus::Expired => Err(source_creation_terminal_error(
            &request_id,
            "expired_unknown",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_source_creation(
    request_id: &RequestId,
    state: &AppState,
    admin_id: i64,
    idempotency_key: String,
    payload: CreateSourceRequest,
    idempotency: SourceCreationIdempotencyStore,
    reservation: SourceCreationReservation,
    active_key: SourceCreationSupervisorKey,
) -> Result<Response, ApiError> {
    let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
    let supervisor_request_id = request_id.0.clone();
    let supervisor_sources = state.sources.clone();
    let supervisor_idempotency = idempotency.clone();
    let supervisor_key = idempotency_key.clone();
    let supervisor_reservation = reservation.clone();
    let supervisor_database = state.database.clone();
    let supervisor_kind = payload.kind;
    let supervisor_guard = state.source_creation_supervisors.register(active_key);
    let spawned = state
        .background_tasks
        .spawn_supervised(|shutdown| async move {
            let _database_guard = supervisor_database;
            let _supervisor_guard = supervisor_guard;
            let result = supervise_source_creation(
                supervisor_request_id,
                supervisor_sources,
                admin_id,
                supervisor_key,
                payload,
                supervisor_idempotency,
                supervisor_reservation,
                shutdown,
            )
            .await;
            let _ = result_sender.send(result);
        });
    if !spawned {
        let _ = recover_interrupted_source_creation(
            request_id,
            &state.sources,
            admin_id,
            &idempotency_key,
            &idempotency,
            &reservation,
            Some(supervisor_kind),
        )
        .await;
        return Err(ApiError::new(
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "source_creation_unavailable",
            "Source creation is unavailable while Executor is shutting down.",
        ));
    }

    match result_receiver.await {
        Ok(Ok(response)) => exact_source_creation_response(request_id, response, false),
        Ok(Err(error)) => Err(error),
        Err(_) => recover_interrupted_source_creation(
            request_id,
            &state.sources,
            admin_id,
            &idempotency_key,
            &idempotency,
            &reservation,
            None,
        )
        .await
        .and_then(|response| exact_source_creation_response(request_id, response, false)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn supervise_source_creation(
    request_id: String,
    sources: crate::protocols::SourceService,
    admin_id: i64,
    idempotency_key: String,
    payload: CreateSourceRequest,
    idempotency: SourceCreationIdempotencyStore,
    reservation: SourceCreationReservation,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<SourceCreationResponse, ApiError> {
    let kind = payload.kind;
    let mut job = tokio::spawn(source_creation_job(
        request_id.clone(),
        sources.clone(),
        admin_id,
        idempotency_key.clone(),
        payload,
        idempotency.clone(),
        reservation.clone(),
    ));
    tokio::select! {
        result = &mut job => match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => {
                tracing::error!(
                    request_id,
                    status = error.status.as_u16(),
                    code = error.code,
                    "source creation worker did not settle cleanly"
                );
                recover_interrupted_source_creation(
                    &RequestId(request_id),
                    &sources,
                    admin_id,
                    &idempotency_key,
                    &idempotency,
                    &reservation,
                    Some(kind),
                )
                .await
            }
            Err(_) => {
                tracing::error!(
                    request_id,
                    "source creation worker terminated unexpectedly"
                );
                recover_interrupted_source_creation(
                    &RequestId(request_id),
                    &sources,
                    admin_id,
                    &idempotency_key,
                    &idempotency,
                    &reservation,
                    Some(kind),
                )
                .await
            }
        },
        _ = &mut shutdown => {
            job.abort();
            let _ = job.await;
            recover_interrupted_source_creation(
                &RequestId(request_id),
                &sources,
                admin_id,
                &idempotency_key,
                &idempotency,
                &reservation,
                Some(kind),
            )
            .await
        }
    }
}

async fn source_creation_job(
    request_id: String,
    sources: crate::protocols::SourceService,
    admin_id: i64,
    idempotency_key: String,
    payload: CreateSourceRequest,
    idempotency: SourceCreationIdempotencyStore,
    reservation: SourceCreationReservation,
) -> Result<SourceCreationResponse, ApiError> {
    let operation_request_id = RequestId(request_id.clone());
    #[cfg(test)]
    if sources.source_creation_panics_at(crate::protocols::SourceCreationPanic::BeforeCreate) {
        panic!("injected source creation panic before commit");
    }
    let outcome = sources
        .create(
            payload.kind,
            Value::Object(payload.protocol),
            AuditContext::admin(&request_id, admin_id)
                .with_source_creation_idempotency(&reservation),
        )
        .await;
    #[cfg(test)]
    if outcome.is_ok()
        && sources.source_creation_panics_at(crate::protocols::SourceCreationPanic::AfterCreate)
    {
        panic!("injected source creation panic after commit");
    }
    settle_source_creation(
        &operation_request_id,
        &sources,
        admin_id,
        &idempotency_key,
        payload.kind,
        outcome,
        &idempotency,
        &reservation,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn settle_source_creation(
    request_id: &RequestId,
    sources: &crate::protocols::SourceService,
    admin_id: i64,
    idempotency_key: &str,
    kind: SourceKind,
    outcome: Result<crate::catalog::SourceRecord, ProtocolError>,
    idempotency: &SourceCreationIdempotencyStore,
    reservation: &SourceCreationReservation,
) -> Result<SourceCreationResponse, ApiError> {
    let source_id = outcome.as_ref().ok().map(|source| source.id.as_str());
    let status = idempotency
        .lookup(admin_id, SOURCE_CREATION_ROUTE, idempotency_key)
        .await
        .map_err(|error| source_creation_idempotency_error(request_id, error))?;
    match status {
        Some(SourceCreationIdempotencyStatus::Replay(replay)) => {
            finish_completed_source_creation(request_id, sources, kind, source_id, replay).await
        }
        Some(SourceCreationIdempotencyStatus::InProgress) => match outcome {
            Ok(_) => {
                let _ = idempotency.interrupt(reservation).await;
                Err(ApiError::internal_logged(
                    request_id,
                    "source creation committed without completing its reservation",
                ))
            }
            Err(error) => {
                let response = source_creation_api_error_response(
                    request_id,
                    protocol_error(request_id, error),
                )?;
                let status = idempotency
                    .fail(reservation, &response)
                    .await
                    .map_err(|error| source_creation_idempotency_error(request_id, error))?;
                source_creation_settlement_response(request_id, sources, kind, status).await
            }
        },
        Some(SourceCreationIdempotencyStatus::Abandoned) => {
            Err(source_creation_terminal_error(request_id, "abandoned"))
        }
        Some(SourceCreationIdempotencyStatus::Interrupted) => {
            Err(source_creation_terminal_error(request_id, "interrupted"))
        }
        Some(SourceCreationIdempotencyStatus::Expired) => Err(source_creation_terminal_error(
            request_id,
            "expired_unknown",
        )),
        None => Err(ApiError::internal_logged(
            request_id,
            "source creation reservation disappeared before settlement",
        )),
    }
}

async fn source_creation_settlement_response(
    request_id: &RequestId,
    sources: &crate::protocols::SourceService,
    kind: SourceKind,
    status: SourceCreationIdempotencyStatus,
) -> Result<SourceCreationResponse, ApiError> {
    match status {
        SourceCreationIdempotencyStatus::Replay(replay) => {
            finish_completed_source_creation(request_id, sources, kind, None, replay).await
        }
        SourceCreationIdempotencyStatus::InProgress => Err(source_creation_in_progress(request_id)),
        SourceCreationIdempotencyStatus::Abandoned => {
            Err(source_creation_terminal_error(request_id, "abandoned"))
        }
        SourceCreationIdempotencyStatus::Interrupted => {
            Err(source_creation_terminal_error(request_id, "interrupted"))
        }
        SourceCreationIdempotencyStatus::Expired => Err(source_creation_terminal_error(
            request_id,
            "expired_unknown",
        )),
    }
}

async fn finish_completed_source_creation(
    request_id: &RequestId,
    sources: &crate::protocols::SourceService,
    kind: SourceKind,
    source_id: Option<&str>,
    replay: SourceCreationReplay,
) -> Result<SourceCreationResponse, ApiError> {
    if replay.kind == SourceCreationResponseKind::Completed {
        let source_id = source_id
            .map(str::to_owned)
            .or_else(|| source_id_from_creation_response(&replay.response));
        let source_id = source_id.ok_or_else(|| {
            ApiError::internal_logged(request_id, "stored source creation response is invalid")
        })?;
        sources.finish_source_creation(kind, &source_id).await;
    }
    Ok(replay.response)
}

#[allow(clippy::too_many_arguments)]
async fn recover_interrupted_source_creation(
    request_id: &RequestId,
    sources: &crate::protocols::SourceService,
    admin_id: i64,
    idempotency_key: &str,
    idempotency: &SourceCreationIdempotencyStore,
    reservation: &SourceCreationReservation,
    kind: Option<SourceKind>,
) -> Result<SourceCreationResponse, ApiError> {
    let mut last_error = None;
    for attempt in 0..SOURCE_CREATION_RECOVERY_ATTEMPTS {
        match idempotency
            .lookup(admin_id, SOURCE_CREATION_ROUTE, idempotency_key)
            .await
        {
            Ok(Some(SourceCreationIdempotencyStatus::Replay(replay))) => {
                if replay.kind == SourceCreationResponseKind::Completed {
                    let Some(kind) =
                        kind.or_else(|| source_kind_from_creation_response(&replay.response))
                    else {
                        return Err(ApiError::internal_logged(
                            request_id,
                            "stored source creation response is invalid",
                        ));
                    };
                    return finish_completed_source_creation(
                        request_id, sources, kind, None, replay,
                    )
                    .await;
                }
                return Ok(replay.response);
            }
            Ok(Some(SourceCreationIdempotencyStatus::InProgress)) => {
                match idempotency.interrupt(reservation).await {
                    Ok(SourceCreationIdempotencyStatus::Replay(replay)) => {
                        if replay.kind == SourceCreationResponseKind::Completed {
                            let Some(kind) = kind
                                .or_else(|| source_kind_from_creation_response(&replay.response))
                            else {
                                return Err(ApiError::internal_logged(
                                    request_id,
                                    "stored source creation response is invalid",
                                ));
                            };
                            return finish_completed_source_creation(
                                request_id, sources, kind, None, replay,
                            )
                            .await;
                        }
                        return Ok(replay.response);
                    }
                    Ok(SourceCreationIdempotencyStatus::Abandoned) => {
                        return Err(source_creation_terminal_error(request_id, "abandoned"));
                    }
                    Ok(SourceCreationIdempotencyStatus::Interrupted) => {
                        return Err(source_creation_terminal_error(request_id, "interrupted"));
                    }
                    Ok(SourceCreationIdempotencyStatus::Expired) => {
                        return Err(source_creation_terminal_error(
                            request_id,
                            "expired_unknown",
                        ));
                    }
                    Ok(SourceCreationIdempotencyStatus::InProgress) => {}
                    Err(error) => last_error = Some(error),
                }
            }
            Ok(Some(SourceCreationIdempotencyStatus::Abandoned)) => {
                return Err(source_creation_terminal_error(request_id, "abandoned"));
            }
            Ok(Some(SourceCreationIdempotencyStatus::Interrupted)) => {
                return Err(source_creation_terminal_error(request_id, "interrupted"));
            }
            Ok(Some(SourceCreationIdempotencyStatus::Expired)) => {
                return Err(source_creation_terminal_error(
                    request_id,
                    "expired_unknown",
                ));
            }
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
        if attempt + 1 < SOURCE_CREATION_RECOVERY_ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(10 * (attempt as u64 + 1))).await;
        }
    }
    if let Some(error) = last_error {
        Err(source_creation_idempotency_error(request_id, error))
    } else {
        Err(ApiError::internal_logged(
            request_id,
            "source creation recovery could not locate or terminalize its reservation",
        ))
    }
}

fn source_id_from_creation_response(response: &SourceCreationResponse) -> Option<String> {
    serde_json::from_slice::<Value>(&response.body)
        .ok()?
        .as_object()?
        .get("id")?
        .as_str()
        .map(str::to_owned)
}

fn source_kind_from_creation_response(response: &SourceCreationResponse) -> Option<SourceKind> {
    serde_json::from_slice::<Value>(&response.body)
        .ok()?
        .as_object()?
        .get("kind")
        .cloned()
        .and_then(|kind| serde_json::from_value(kind).ok())
}

fn source_creation_supervisor_key(
    state: &AppState,
    admin_id: i64,
    key: &str,
) -> SourceCreationSupervisorKey {
    SourceCreationSupervisorKey {
        admin_id,
        key_digest: state
            .database
            .keyring
            .digest("source-creation-supervisor", key.as_bytes()),
    }
}

fn parse_source_creation_idempotency_key(
    request_id: &RequestId,
    headers: &HeaderMap,
) -> Result<Option<String>, ApiError> {
    parse_single_idempotency_key(
        request_id,
        headers,
        source_creation_idempotency_key_is_valid,
    )
}

fn require_source_creation_idempotency_key(
    request_id: &RequestId,
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    parse_source_creation_idempotency_key(request_id, headers)?.ok_or_else(|| {
        ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "Idempotency-Key is required for this endpoint.",
        )
    })
}

fn source_creation_api_error_response(
    request_id: &RequestId,
    error: ApiError,
) -> Result<SourceCreationResponse, ApiError> {
    let body = serde_json::to_vec(&ErrorEnvelope {
        error: ErrorDetail {
            code: error.code,
            message: error.message,
            request_id: error.request_id,
        },
    })
    .map_err(|encoding_error| ApiError::internal_logged(request_id, encoding_error))?;
    let mut headers = BTreeMap::from([
        ("cache-control".to_owned(), "no-store".to_owned()),
        ("content-type".to_owned(), "application/json".to_owned()),
    ]);
    if let Some(retry_after_seconds) = error.retry_after_seconds {
        headers.insert("retry-after".to_owned(), retry_after_seconds.to_string());
    }
    Ok(SourceCreationResponse {
        status: error.status.as_u16(),
        headers,
        body,
    })
}

fn exact_source_creation_response(
    request_id: &RequestId,
    output: SourceCreationResponse,
    replayed: bool,
) -> Result<Response, ApiError> {
    let mut response = Response::builder()
        .status(output.status)
        .body(Body::from(output.body))
        .map_err(|_| ApiError::internal(request_id))?;
    for (name, value) in output.headers {
        let name = HeaderName::try_from(name).map_err(|_| ApiError::internal(request_id))?;
        let value = HeaderValue::try_from(value).map_err(|_| ApiError::internal(request_id))?;
        response.headers_mut().insert(name, value);
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if replayed {
        response.headers_mut().insert(
            HeaderName::from_static("idempotency-replayed"),
            HeaderValue::from_static("true"),
        );
    }
    Ok(response)
}

#[derive(Serialize)]
struct SourceCreationStatusResponse {
    status: &'static str,
}

fn source_creation_status_response(
    request_id: &RequestId,
    status: &'static str,
) -> Result<Response, ApiError> {
    let body = serde_json::to_vec(&SourceCreationStatusResponse { status })
        .map_err(|error| ApiError::internal_logged(request_id, error))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .map_err(|_| ApiError::internal(request_id))
}

fn source_creation_in_progress(request_id: &RequestId) -> ApiError {
    ApiError::new(
        request_id,
        StatusCode::CONFLICT,
        "idempotency_in_progress",
        "The source creation for this Idempotency-Key is still in progress.",
    )
    .with_retry_after(1)
}

fn source_creation_terminal_error(request_id: &RequestId, status: &'static str) -> ApiError {
    match status {
        "abandoned" => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "idempotency_abandoned",
            "This Idempotency-Key was sealed before source creation began.",
        ),
        "interrupted" => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "idempotency_interrupted",
            "Source creation was interrupted and cannot be retried with this Idempotency-Key.",
        ),
        "expired_unknown" => ApiError::new(
            request_id,
            StatusCode::GONE,
            "idempotency_expired_unknown",
            "The retained source creation response expired and its outcome must be verified manually.",
        ),
        _ => ApiError::internal(request_id),
    }
}

fn source_creation_idempotency_error(
    request_id: &RequestId,
    error: SourceCreationIdempotencyError,
) -> ApiError {
    match error {
        SourceCreationIdempotencyError::InvalidKey => invalid_idempotency_key(request_id),
        SourceCreationIdempotencyError::PayloadTooLarge => ApiError::new(
            request_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "The request body exceeds the allowed size.",
        ),
        SourceCreationIdempotencyError::Capacity => ApiError::new(
            request_id,
            StatusCode::TOO_MANY_REQUESTS,
            "idempotency_capacity",
            "Source creation idempotency capacity has been reached. Retry later.",
        )
        .with_retry_after(1),
        error => ApiError::internal_logged(request_id, error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutCredentialsRequest {
    expected_revision: i64,
    credential: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeleteCredentialsQuery {
    expected_revision: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RefreshSourceRequest {}

async fn refresh_source(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    AdminMutation(admin_id): AdminMutation,
    Path(source_id): Path<String>,
    payload: Result<Json<RefreshSourceRequest>, JsonRejection>,
) -> Result<Json<crate::catalog::CatalogSyncResult>, ApiError> {
    let Json(_payload) = parse_json(&request_id, payload)?;
    let refreshed = state
        .sources
        .refresh(&source_id, AuditContext::admin(&request_id.0, admin_id))
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    Ok(Json(refreshed))
}

async fn get_credentials(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    _admin: AdminAuthentication,
    Path(source_id): Path<String>,
) -> Result<Json<CredentialMetadata>, ApiError> {
    let metadata = state
        .sources
        .credential_metadata(&source_id)
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    Ok(Json(metadata))
}

async fn put_credentials(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    AdminMutation(admin_id): AdminMutation,
    Path(source_id): Path<String>,
    payload: Result<Json<PutCredentialsRequest>, JsonRejection>,
) -> Result<Json<CredentialMetadata>, ApiError> {
    let Json(payload) = parse_json(&request_id, payload)?;
    let metadata = state
        .sources
        .replace_credentials(
            &source_id,
            payload.expected_revision,
            payload.credential,
            AuditContext::admin(&request_id.0, admin_id),
        )
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    Ok(Json(metadata))
}

async fn delete_credentials(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    AdminMutation(admin_id): AdminMutation,
    Path(source_id): Path<String>,
    query: Result<Query<DeleteCredentialsQuery>, QueryRejection>,
) -> Result<Json<CredentialMetadata>, ApiError> {
    let Query(query) = query.map_err(|_| invalid_query(&request_id))?;
    let metadata = state
        .sources
        .clear_credentials(
            &source_id,
            query.expected_revision,
            AuditContext::admin(&request_id.0, admin_id),
        )
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    Ok(Json(metadata))
}

fn invalid_query(request_id: &RequestId) -> ApiError {
    ApiError::new(
        request_id,
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "The query parameters are invalid.",
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvokeRequest {
    path: String,
    #[serde(default = "empty_object")]
    arguments: Value,
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

fn parse_idempotency_key(
    request_id: &RequestId,
    headers: &HeaderMap,
) -> Result<Option<String>, ApiError> {
    parse_single_idempotency_key(request_id, headers, gateway_idempotency_key_is_valid)
}

fn parse_single_idempotency_key(
    request_id: &RequestId,
    headers: &HeaderMap,
    is_valid: impl FnOnce(&str) -> bool,
) -> Result<Option<String>, ApiError> {
    let mut values = headers.get_all(IDEMPOTENCY_KEY_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(invalid_idempotency_key(request_id));
    }
    let value = value
        .to_str()
        .map_err(|_| invalid_idempotency_key(request_id))?;
    if !is_valid(value) {
        return Err(invalid_idempotency_key(request_id));
    }
    Ok(Some(value.to_owned()))
}

fn invalid_idempotency_key(request_id: &RequestId) -> ApiError {
    ApiError::new(
        request_id,
        StatusCode::BAD_REQUEST,
        "invalid_idempotency_key",
        "Idempotency-Key must contain between 1 and 255 visible ASCII bytes.",
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalRequiredResponse {
    status: &'static str,
    approval: PendingApprovalResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PendingApprovalResponse {
    id: String,
    status: crate::approval::ApprovalStatus,
    revision: i64,
    path: String,
    created_at: i64,
    expires_at: i64,
    status_url: String,
}

async fn invoke(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    GatewayAuthentication(identity): GatewayAuthentication,
    headers: HeaderMap,
    payload: Result<Json<InvokeRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let idempotency_key = parse_idempotency_key(&request_id, &headers)?;
    let Json(payload) = match parse_json(&request_id, payload) {
        Ok(payload) => payload,
        Err(error) => {
            state.tool_calls.record_rejected_request(
                &request_id.0,
                &identity.token_id,
                RequestSurface::Gateway,
                "tools.invoke",
                error.code,
            );
            return Err(error);
        }
    };
    let call = ToolCall {
        request_id: request_id.0.clone(),
        actor: ToolActor::api_token(identity.token_id, Some(identity.token_name)),
        surface: RequestSurface::Gateway,
        execution_id: request_id.0.clone(),
        call_id: "gateway".to_owned(),
        worker_generation: 0,
        path: payload.path,
        arguments: payload.arguments,
    };
    if let Some(idempotency_key) = idempotency_key {
        let response = state
            .tool_calls
            .submit_gateway_idempotent(call, &idempotency_key)
            .await
            .map_err(|error| gateway_invoke_error(&request_id, error))?;
        return exact_gateway_response(&request_id, response);
    }
    let submission = state
        .tool_calls
        .submit(call)
        .await
        .map_err(|error| tool_call_error(&request_id, error))?;
    match submission {
        ToolCallSubmission::Completed(result) => Ok(Json(result).into_response()),
        ToolCallSubmission::ApprovalRequired(approval) => Ok((
            StatusCode::ACCEPTED,
            Json(ApprovalRequiredResponse {
                status: "approval_required",
                approval: PendingApprovalResponse {
                    status_url: format!("/api/v1/gateway/approvals/{}", approval.id),
                    id: approval.id.clone(),
                    status: approval.status,
                    revision: approval.revision,
                    path: approval.callable_path_snapshot.clone(),
                    created_at: approval.created_at,
                    expires_at: approval.expires_at,
                },
            }),
        )
            .into_response()),
    }
}

fn exact_gateway_response(
    request_id: &RequestId,
    output: GatewayInvokeResponse,
) -> Result<Response, ApiError> {
    let mut response = Response::builder().status(output.response.status);
    for (name, value) in output.response.headers {
        let name = HeaderName::try_from(name).map_err(|_| ApiError::internal(request_id))?;
        let value = HeaderValue::try_from(value).map_err(|_| ApiError::internal(request_id))?;
        response = response.header(name, value);
    }
    if output.replayed {
        response = response.header("idempotency-replayed", "true");
    }
    response
        .body(Body::from(output.response.body))
        .map_err(|_| ApiError::internal(request_id))
}

fn gateway_invoke_error(request_id: &RequestId, error: GatewayInvokeError) -> ApiError {
    match error {
        GatewayInvokeError::ToolCall(error) => tool_call_error(request_id, error),
        GatewayInvokeError::InvalidKey => invalid_idempotency_key(request_id),
        GatewayInvokeError::Capacity => ApiError::new(
            request_id,
            StatusCode::TOO_MANY_REQUESTS,
            "idempotency_capacity",
            "Gateway idempotency capacity has been reached. Retry later.",
        )
        .with_retry_after(1),
        GatewayInvokeError::KeyMismatch => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "idempotency_key_mismatch",
            "This Idempotency-Key was already used for a different invocation.",
        ),
        GatewayInvokeError::InProgress => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "idempotency_in_progress",
            "The invocation for this Idempotency-Key is still in progress.",
        )
        .with_retry_after(1),
        GatewayInvokeError::OutcomeUnknown => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "idempotency_outcome_unknown",
            "The invocation may have reached the upstream service, so it will not be retried.",
        ),
        GatewayInvokeError::Canceled => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "idempotency_in_progress",
            "The invocation is still in progress.",
        )
        .with_retry_after(1),
        GatewayInvokeError::Idempotency(error) => ApiError::internal_logged(request_id, error),
    }
}

pub(super) fn tool_call_error(request_id: &RequestId, error: ToolCallError) -> ApiError {
    match error {
        ToolCallError::Approval(error) => approval_error(request_id, error),
        ToolCallError::Catalog(error) => catalog_error(request_id, error),
        ToolCallError::Adapter { code, message } => adapter_error(request_id, code, message),
        ToolCallError::OAuth(error) => tool_call_oauth_error(request_id, error),
        ToolCallError::ArgumentsTooLarge => ApiError::new(
            request_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "arguments_too_large",
            "Tool arguments exceed the allowed size.",
        ),
        ToolCallError::InvalidArguments => ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_tool_arguments",
            "The tool arguments do not match the imported input schema.",
        ),
        ToolCallError::Protocol(error) => protocol_error(request_id, error),
        ToolCallError::Stale => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "invocation_stale",
            "The tool changed before invocation. Retry with the current catalog.",
        ),
        ToolCallError::Outbound(error) => outbound_error(request_id, error),
        ToolCallError::ResultTooLarge => ApiError::new(
            request_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "result_too_large",
            "The upstream tool result exceeds the allowed size.",
        ),
    }
}

fn tool_call_oauth_error(request_id: &RequestId, error: ToolCallOAuthError) -> ApiError {
    let code = error.code();
    match error {
        ToolCallOAuthError::Validation { .. } => ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            code,
            "The managed OAuth configuration is invalid.",
        ),
        ToolCallOAuthError::ConnectionRequired => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            code,
            "A managed OAuth connection is required before this tool can run.",
        ),
        ToolCallOAuthError::Conflict { .. } => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            code,
            "The managed OAuth connection changed. Retry with its current configuration.",
        ),
        ToolCallOAuthError::UnauthorizedTransaction => ApiError::new(
            request_id,
            StatusCode::UNAUTHORIZED,
            code,
            "The managed OAuth transaction is not authorized for this session.",
        ),
        ToolCallOAuthError::AuthorizationDenied => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            code,
            "Managed OAuth authorization was denied.",
        ),
        ToolCallOAuthError::Upstream { .. } => ApiError::new(
            request_id,
            StatusCode::BAD_GATEWAY,
            code,
            "The OAuth provider request failed.",
        ),
        ToolCallOAuthError::Internal => {
            ApiError::internal_logged(request_id, "managed OAuth failed internally")
        }
    }
}

fn adapter_error(
    request_id: &RequestId,
    code: ToolCallAdapterErrorCode,
    message: String,
) -> ApiError {
    let status = match code {
        ToolCallAdapterErrorCode::ApprovalPersistenceUnavailable
        | ToolCallAdapterErrorCode::ApprovalPersistenceInterrupted
        | ToolCallAdapterErrorCode::McpShuttingDown
        | ToolCallAdapterErrorCode::McpCapacity => StatusCode::SERVICE_UNAVAILABLE,
        ToolCallAdapterErrorCode::OAuthConnectionFailed
        | ToolCallAdapterErrorCode::OAuthBindingChanged
        | ToolCallAdapterErrorCode::InvocationOutcomeUnknown
        | ToolCallAdapterErrorCode::OpenApiOutcomeUnknown
        | ToolCallAdapterErrorCode::GraphqlOutcomeUnknown
        | ToolCallAdapterErrorCode::McpOutcomeUnknown
        | ToolCallAdapterErrorCode::McpSessionConflict => StatusCode::CONFLICT,
        ToolCallAdapterErrorCode::McpProtocolUnavailable
        | ToolCallAdapterErrorCode::McpUpstreamUnauthorized
        | ToolCallAdapterErrorCode::McpUpstreamForbidden => StatusCode::BAD_GATEWAY,
        ToolCallAdapterErrorCode::McpMessageTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ToolCallAdapterErrorCode::IdempotencyMetadataInvalid
        | ToolCallAdapterErrorCode::IdempotencyFailed => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let error = ApiError::new(request_id, status, code.as_str(), message);
    if code == ToolCallAdapterErrorCode::McpCapacity {
        error.with_retry_after(1)
    } else {
        error
    }
}

pub(super) fn approval_error(request_id: &RequestId, error: ApprovalError) -> ApiError {
    match error {
        ApprovalError::NotFound => ApiError::new(
            request_id,
            StatusCode::NOT_FOUND,
            "approval_not_found",
            "The requested approval does not exist.",
        ),
        ApprovalError::Expired => ApiError::new(
            request_id,
            StatusCode::GONE,
            "approval_expired",
            "The approval has expired.",
        ),
        ApprovalError::RevisionConflict { .. } | ApprovalError::DecisionConflict => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "revision_conflict",
            "The approval changed. Refresh it and retry.",
        ),
        ApprovalError::InvalidTransition { .. } => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "approval_not_cancelable",
            "The approval can no longer be canceled or changed.",
        ),
        ApprovalError::OwnerTokenInactive => ApiError::unauthorized(
            request_id,
            "The API token that created this approval is no longer active.",
        ),
        ApprovalError::Capacity { .. } => ApiError::new(
            request_id,
            StatusCode::TOO_MANY_REQUESTS,
            "approval_capacity",
            "Too many approvals are active. Resolve an existing approval and retry.",
        )
        .with_retry_after(1),
        ApprovalError::CorrelationConflict => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "duplicate_tool_call",
            "The execution call conflicts with an existing approval.",
        ),
        ApprovalError::CorrelationRetired => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "approval_stale",
            "The correlated approval is no longer retained.",
        ),
        ApprovalError::WorkerGenerationConflict => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "approval_stale",
            "The approval belongs to an older execution generation.",
        ),
        ApprovalError::PayloadTooLarge { .. } => ApiError::new(
            request_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "approval_payload_too_large",
            "The approval payload exceeds the allowed size.",
        ),
        ApprovalError::Validation { code, message } => {
            ApiError::new(request_id, StatusCode::BAD_REQUEST, code, message)
        }
        error => ApiError::internal_logged(request_id, error),
    }
}

fn catalog_error(request_id: &RequestId, error: CatalogError) -> ApiError {
    match error {
        CatalogError::Validation {
            code: "oauth_binding_changed",
            message,
        } => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "oauth_binding_changed",
            message,
        ),
        CatalogError::Validation { code, message } => {
            ApiError::new(request_id, StatusCode::BAD_REQUEST, code, message)
        }
        CatalogError::NotFound { entity: "source" } => ApiError::new(
            request_id,
            StatusCode::NOT_FOUND,
            "source_not_found",
            "The requested source does not exist.",
        ),
        CatalogError::NotFound { .. } | CatalogError::ToolNotFound { .. } => ApiError::new(
            request_id,
            StatusCode::NOT_FOUND,
            "tool_not_found",
            "The requested tool does not exist.",
        ),
        CatalogError::ToolDisabled { .. } => ApiError::new(
            request_id,
            StatusCode::FORBIDDEN,
            "tool_disabled",
            "The requested tool is disabled.",
        ),
        CatalogError::RevisionConflict { .. } => ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "revision_conflict",
            "The source changed. Refresh and retry the update.",
        ),
        error => ApiError::internal_logged(request_id, error),
    }
}

pub(super) fn protocol_error(request_id: &RequestId, error: ProtocolError) -> ApiError {
    if matches!(
        error.category,
        ProtocolErrorCategory::CorruptData | ProtocolErrorCategory::Internal
    ) {
        return ApiError::internal_logged(request_id, error);
    }
    let status = match error.category {
        ProtocolErrorCategory::InvalidInput if error.code == "oauth_binding_changed" => {
            StatusCode::CONFLICT
        }
        ProtocolErrorCategory::InvalidInput => match error.code {
            "private_network_denied" | "forbidden_network_target" => StatusCode::FORBIDDEN,
            "outbound_headers_too_large"
            | "outbound_request_too_large"
            | "upstream_headers_too_large"
            | "upstream_response_too_large"
            | "openapi_document_too_large" => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::BAD_REQUEST,
        },
        ProtocolErrorCategory::NotFound => StatusCode::NOT_FOUND,
        ProtocolErrorCategory::Conflict => StatusCode::CONFLICT,
        ProtocolErrorCategory::Unsupported => StatusCode::BAD_REQUEST,
        ProtocolErrorCategory::Upstream if error.code == "upstream_timeout" => {
            StatusCode::GATEWAY_TIMEOUT
        }
        ProtocolErrorCategory::Upstream => StatusCode::BAD_GATEWAY,
        ProtocolErrorCategory::CorruptData | ProtocolErrorCategory::Internal => {
            unreachable!("non-public protocol errors return above")
        }
    };
    ApiError::new(request_id, status, error.code, error.message)
}

pub(super) fn outbound_error(request_id: &RequestId, error: OutboundError) -> ApiError {
    let status = match error {
        OutboundError::InvalidUrl
        | OutboundError::InsecureTransport
        | OutboundError::UnsupportedScheme
        | OutboundError::CredentialsNotAllowed
        | OutboundError::FragmentNotAllowed
        | OutboundError::MissingHost
        | OutboundError::MissingPort
        | OutboundError::ForbiddenHeader
        | OutboundError::ForbiddenMethod => StatusCode::BAD_REQUEST,
        OutboundError::PrivateAddress | OutboundError::ForbiddenAddress => StatusCode::FORBIDDEN,
        OutboundError::ResponseBodyTooLarge
        | OutboundError::ResponseHeadersTooLarge
        | OutboundError::RequestBodyTooLarge
        | OutboundError::RequestHeadersTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        OutboundError::ClientInitialization => StatusCode::SERVICE_UNAVAILABLE,
        OutboundError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        OutboundError::Connection
        | OutboundError::Request
        | OutboundError::DnsResolution
        | OutboundError::UnsupportedContentEncoding
        | OutboundError::InvalidRedirect
        | OutboundError::RedirectDowngrade
        | OutboundError::RedirectLoop
        | OutboundError::TooManyRedirects
        | OutboundError::UpstreamStatus { .. } => StatusCode::BAD_GATEWAY,
    };
    ApiError::new(
        request_id,
        status,
        error.code(),
        "The upstream request could not be completed safely.",
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;

    fn request_id() -> RequestId {
        RequestId("protocol-error-test".to_owned())
    }

    #[test]
    fn adapter_error_statuses_are_typed_and_exhaustive() {
        use ToolCallAdapterErrorCode as Code;

        let cases = [
            (
                Code::ApprovalPersistenceUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
                None,
            ),
            (
                Code::ApprovalPersistenceInterrupted,
                StatusCode::SERVICE_UNAVAILABLE,
                None,
            ),
            (
                Code::IdempotencyMetadataInvalid,
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
            ),
            (
                Code::IdempotencyFailed,
                StatusCode::INTERNAL_SERVER_ERROR,
                None,
            ),
            (Code::OAuthConnectionFailed, StatusCode::CONFLICT, None),
            (Code::OAuthBindingChanged, StatusCode::CONFLICT, None),
            (Code::InvocationOutcomeUnknown, StatusCode::CONFLICT, None),
            (Code::OpenApiOutcomeUnknown, StatusCode::CONFLICT, None),
            (Code::GraphqlOutcomeUnknown, StatusCode::CONFLICT, None),
            (Code::McpOutcomeUnknown, StatusCode::CONFLICT, None),
            (Code::McpProtocolUnavailable, StatusCode::BAD_GATEWAY, None),
            (Code::McpUpstreamUnauthorized, StatusCode::BAD_GATEWAY, None),
            (Code::McpUpstreamForbidden, StatusCode::BAD_GATEWAY, None),
            (Code::McpSessionConflict, StatusCode::CONFLICT, None),
            (Code::McpShuttingDown, StatusCode::SERVICE_UNAVAILABLE, None),
            (Code::McpCapacity, StatusCode::SERVICE_UNAVAILABLE, Some(1)),
            (
                Code::McpMessageTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                None,
            ),
        ];
        for (code, status, retry_after_seconds) in cases {
            let error = adapter_error(&request_id(), code, "A safe public message.".to_owned());
            assert_eq!(error.status, status, "wrong status for {}", code.as_str());
            assert_eq!(error.code, code.as_str());
            assert_eq!(error.retry_after_seconds, retry_after_seconds);
            assert_eq!(error.message, "A safe public message.");
        }
    }

    #[test]
    fn gateway_outcome_unknown_is_non_retryable() {
        let error = gateway_invoke_error(&request_id(), GatewayInvokeError::OutcomeUnknown);
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert_eq!(error.code, "idempotency_outcome_unknown");
        assert_eq!(error.retry_after_seconds, None);

        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(!response.headers().contains_key(header::RETRY_AFTER));
    }

    #[test]
    fn oauth_error_statuses_preserve_typed_failure_categories() {
        let cases = [
            (
                ToolCallOAuthError::Validation {
                    code: "oauth_scope_invalid",
                },
                StatusCode::BAD_REQUEST,
                "oauth_scope_invalid",
            ),
            (
                ToolCallOAuthError::ConnectionRequired,
                StatusCode::CONFLICT,
                "oauth_connection_required",
            ),
            (
                ToolCallOAuthError::Conflict {
                    code: "oauth_binding_changed",
                },
                StatusCode::CONFLICT,
                "oauth_binding_changed",
            ),
            (
                ToolCallOAuthError::UnauthorizedTransaction,
                StatusCode::UNAUTHORIZED,
                "oauth_transaction_unauthorized",
            ),
            (
                ToolCallOAuthError::AuthorizationDenied,
                StatusCode::CONFLICT,
                "oauth_authorization_denied",
            ),
            (
                ToolCallOAuthError::Upstream {
                    code: "oauth_provider_timeout",
                },
                StatusCode::BAD_GATEWAY,
                "oauth_provider_timeout",
            ),
            (
                ToolCallOAuthError::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
            ),
        ];
        for (source, expected_status, expected_code) in cases {
            let error = tool_call_oauth_error(&request_id(), source);
            assert_eq!(error.status, expected_status);
            assert_eq!(error.code, expected_code);
        }
    }

    #[test]
    fn outbound_error_statuses_are_typed_and_exhaustive() {
        let cases = vec![
            (OutboundError::InvalidUrl, StatusCode::BAD_REQUEST),
            (OutboundError::InsecureTransport, StatusCode::BAD_REQUEST),
            (OutboundError::UnsupportedScheme, StatusCode::BAD_REQUEST),
            (
                OutboundError::CredentialsNotAllowed,
                StatusCode::BAD_REQUEST,
            ),
            (OutboundError::FragmentNotAllowed, StatusCode::BAD_REQUEST),
            (OutboundError::MissingHost, StatusCode::BAD_REQUEST),
            (OutboundError::MissingPort, StatusCode::BAD_REQUEST),
            (OutboundError::PrivateAddress, StatusCode::FORBIDDEN),
            (OutboundError::ForbiddenAddress, StatusCode::FORBIDDEN),
            (OutboundError::DnsResolution, StatusCode::BAD_GATEWAY),
            (OutboundError::ForbiddenHeader, StatusCode::BAD_REQUEST),
            (OutboundError::ForbiddenMethod, StatusCode::BAD_REQUEST),
            (
                OutboundError::RequestHeadersTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                OutboundError::RequestBodyTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                OutboundError::ClientInitialization,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (OutboundError::Timeout, StatusCode::GATEWAY_TIMEOUT),
            (OutboundError::Connection, StatusCode::BAD_GATEWAY),
            (OutboundError::Request, StatusCode::BAD_GATEWAY),
            (
                OutboundError::ResponseHeadersTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                OutboundError::ResponseBodyTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
            (
                OutboundError::UnsupportedContentEncoding,
                StatusCode::BAD_GATEWAY,
            ),
            (OutboundError::InvalidRedirect, StatusCode::BAD_GATEWAY),
            (OutboundError::RedirectDowngrade, StatusCode::BAD_GATEWAY),
            (OutboundError::RedirectLoop, StatusCode::BAD_GATEWAY),
            (OutboundError::TooManyRedirects, StatusCode::BAD_GATEWAY),
            (
                OutboundError::UpstreamStatus {
                    status: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                },
                StatusCode::BAD_GATEWAY,
            ),
        ];
        for (source, expected_status) in cases {
            let expected_code = source.code();
            let error = outbound_error(&request_id(), source);
            assert_eq!(
                error.status, expected_status,
                "wrong status for {expected_code}"
            );
            assert_eq!(error.code, expected_code);
            assert_eq!(
                error.message,
                "The upstream request could not be completed safely."
            );
            assert_eq!(error.retry_after_seconds, None);
        }
    }

    #[test]
    fn protocol_error_categories_map_without_exposing_non_public_failures() {
        use ProtocolErrorCategory as Category;

        let public_cases = [
            (
                Category::InvalidInput,
                "invalid_tool_arguments",
                StatusCode::BAD_REQUEST,
            ),
            (
                Category::InvalidInput,
                "oauth_binding_changed",
                StatusCode::CONFLICT,
            ),
            (
                Category::NotFound,
                "source_not_found",
                StatusCode::NOT_FOUND,
            ),
            (
                Category::Conflict,
                "revision_conflict",
                StatusCode::CONFLICT,
            ),
            (
                Category::Conflict,
                "insecure_openapi_transport",
                StatusCode::CONFLICT,
            ),
            (
                Category::Unsupported,
                "unsupported_protocol",
                StatusCode::BAD_REQUEST,
            ),
            (
                Category::Upstream,
                "upstream_timeout",
                StatusCode::GATEWAY_TIMEOUT,
            ),
            (
                Category::Upstream,
                "upstream_connection_failed",
                StatusCode::BAD_GATEWAY,
            ),
            (
                Category::InvalidInput,
                "private_network_denied",
                StatusCode::FORBIDDEN,
            ),
            (
                Category::InvalidInput,
                "invalid_mcp_endpoint",
                StatusCode::BAD_REQUEST,
            ),
            (
                Category::InvalidInput,
                "upstream_response_too_large",
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ];
        for (category, code, status) in public_cases {
            let error = protocol_error(
                &request_id(),
                ProtocolError::new(category, code, "A safe public message."),
            );
            assert_eq!(error.status, status, "wrong status for {code}");
            assert_eq!(error.code, code);
            assert_eq!(error.message, "A safe public message.");
            assert_eq!(error.retry_after_seconds, None);
        }
        for category in [Category::CorruptData, Category::Internal] {
            let error = protocol_error(
                &request_id(),
                ProtocolError::new(category, "private_failure", "secret upstream detail"),
            );
            assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(error.code, "internal_error");
            assert!(!error.message.contains("secret upstream detail"));
        }
    }

    #[test]
    fn caller_and_catalog_failures_keep_their_http_contracts() {
        let missing = tool_call_error(
            &request_id(),
            ToolCallError::Catalog(CatalogError::ToolNotFound {
                path: "missing.tool".to_owned(),
            }),
        );
        assert_eq!(
            (missing.status, missing.code),
            (StatusCode::NOT_FOUND, "tool_not_found")
        );

        let disabled = tool_call_error(
            &request_id(),
            ToolCallError::Catalog(CatalogError::ToolDisabled {
                path: "disabled.tool".to_owned(),
            }),
        );
        assert_eq!(
            (disabled.status, disabled.code),
            (StatusCode::FORBIDDEN, "tool_disabled")
        );

        let oauth_binding_changed = catalog_error(
            &request_id(),
            CatalogError::Validation {
                code: "oauth_binding_changed",
                message: "The managed OAuth binding changed.".to_owned(),
            },
        );
        assert_eq!(
            (oauth_binding_changed.status, oauth_binding_changed.code),
            (StatusCode::CONFLICT, "oauth_binding_changed")
        );

        let invalid = tool_call_error(&request_id(), ToolCallError::InvalidArguments);
        assert_eq!(
            (invalid.status, invalid.code),
            (StatusCode::BAD_REQUEST, "invalid_tool_arguments")
        );

        let revoked = tool_call_error(
            &request_id(),
            ToolCallError::Approval(ApprovalError::OwnerTokenInactive),
        );
        assert_eq!(
            (revoked.status, revoked.code),
            (StatusCode::UNAUTHORIZED, "unauthorized")
        );
    }

    struct SourceCreationFixture {
        pool: sqlx::SqlitePool,
        connections: Arc<crate::mcp::manager::McpConnectionManager>,
        sources: crate::protocols::SourceService,
        idempotency: SourceCreationIdempotencyStore,
    }

    async fn source_creation_fixture() -> SourceCreationFixture {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("test database opens");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations apply");
        sqlx::query(
            "INSERT INTO admins (id, username, password_hash, created_at) \
             VALUES (1, 'admin', 'test-password-hash', 1)",
        )
        .execute(&pool)
        .await
        .expect("test administrator inserts");
        let keyring =
            crate::crypto::Keyring::from_master_key([87; 32]).expect("test keyring derives");
        let catalog = crate::catalog::CatalogStore::new(pool.clone(), keyring.clone());
        let templates = crate::mcp::upstream::stdio::StdioTemplateRegistry::new(vec![
            crate::mcp::upstream::stdio::StdioTemplate {
                name: "deferred".to_owned(),
                executable: PathBuf::from("/bin/sh"),
                cwd: None,
                arguments: vec!["-c".to_owned(), "exit 1".to_owned()],
                environment: BTreeMap::new(),
                secret_environment: vec!["API_TOKEN".to_owned()],
            },
        ])
        .expect("test stdio template validates");
        let connections = Arc::new(crate::mcp::manager::McpConnectionManager::new(templates));
        let oauth = crate::oauth::OAuthService::new(
            pool.clone(),
            keyring,
            "http://127.0.0.1:4788".to_owned(),
            crate::outbound::OutboundPolicy::default(),
        );
        SourceCreationFixture {
            pool,
            connections: connections.clone(),
            sources: crate::protocols::SourceService::new(catalog.clone(), connections, oauth),
            idempotency: catalog.source_creation_idempotency(),
        }
    }

    fn deferred_source_request() -> (Value, CreateSourceRequest) {
        let request = json!({
            "kind": "mcp_stdio",
            "displayName": "Deferred stdio",
            "templateName": "deferred",
            "secretValues": {}
        });
        let payload = CreateSourceRequest {
            kind: SourceKind::McpStdio,
            protocol: request
                .as_object()
                .expect("request is an object")
                .iter()
                .filter(|(name, _)| name.as_str() != "kind")
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        };
        (request, payload)
    }

    async fn reserve_source_creation(
        fixture: &SourceCreationFixture,
        key: &str,
        request: &Value,
    ) -> SourceCreationReservation {
        let SourceCreationIdempotencyClaim::Fresh(reservation) = fixture
            .idempotency
            .claim(1, SOURCE_CREATION_ROUTE, key, request)
            .await
            .expect("source creation reservation succeeds")
        else {
            panic!("source creation reservation must be fresh");
        };
        reservation
    }

    async fn close_source_creation_fixture(fixture: SourceCreationFixture) {
        fixture.connections.shutdown().await;
        fixture.pool.close().await;
    }

    #[tokio::test]
    async fn source_creation_job_waits_for_post_commit_mcp_reconciliation() {
        let mut fixture = source_creation_fixture().await;
        let pause = fixture.sources.pause_source_creation_finish();
        let key = "post-commit-reconciliation";
        let (request, payload) = deferred_source_request();
        let reservation = reserve_source_creation(&fixture, key, &request).await;
        let registry = SourceCreationSupervisorRegistry::default();
        let active_key = SourceCreationSupervisorKey {
            admin_id: 1,
            key_digest: [11; 32],
        };
        let supervisor_guard = registry.register(active_key);
        let replay_waiter = tokio::spawn({
            let registry = registry.clone();
            async move { registry.wait_if_active(active_key).await }
        });
        let job = tokio::spawn(source_creation_job(
            "source-create-test".to_owned(),
            fixture.sources.clone(),
            1,
            key.to_owned(),
            payload,
            fixture.idempotency.clone(),
            reservation,
        ));

        pause.reached().await;
        assert!(
            !job.is_finished(),
            "the HTTP result must wait for post-commit reconciliation"
        );
        assert!(
            !replay_waiter.is_finished(),
            "replay must wait for the active post-commit reconciliation"
        );
        assert!(matches!(
            fixture
                .idempotency
                .lookup(1, SOURCE_CREATION_ROUTE, key)
                .await
                .expect("completed reservation reads"),
            Some(SourceCreationIdempotencyStatus::Replay(
                SourceCreationReplay {
                    kind: SourceCreationResponseKind::Completed,
                    ..
                }
            ))
        ));
        pause.release();
        let response = match job.await.expect("source creation task joins") {
            Ok(response) => response,
            Err(error) => panic!(
                "source creation should succeed, got {} ({})",
                error.code, error.status
            ),
        };
        assert_eq!(response.status, StatusCode::CREATED.as_u16());
        drop(supervisor_guard);
        replay_waiter.await.expect("replay barrier waiter joins");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sources")
                .fetch_one(&fixture.pool)
                .await
                .expect("source count reads"),
            1
        );
        close_source_creation_fixture(fixture).await;
    }

    #[tokio::test]
    async fn supervised_shutdown_after_commit_recovers_reconciliation_and_stored_success() {
        let mut fixture = source_creation_fixture().await;
        let pause = fixture.sources.pause_source_creation_finish();
        let key = "shutdown-after-commit";
        let (request, payload) = deferred_source_request();
        let reservation = reserve_source_creation(&fixture, key, &request).await;
        let tracker = crate::tasks::TaskTracker::default();
        let (result_sender, result_receiver) = tokio::sync::oneshot::channel();
        let sources = fixture.sources.clone();
        let idempotency = fixture.idempotency.clone();
        assert!(tracker.spawn_supervised(|shutdown| async move {
            let result = supervise_source_creation(
                "shutdown-after-commit-request".to_owned(),
                sources,
                1,
                key.to_owned(),
                payload,
                idempotency,
                reservation,
                shutdown,
            )
            .await;
            let _ = result_sender.send(result);
        }));

        pause.reached().await;
        assert!(matches!(
            fixture
                .idempotency
                .lookup(1, SOURCE_CREATION_ROUTE, key)
                .await
                .expect("completed reservation reads"),
            Some(SourceCreationIdempotencyStatus::Replay(
                SourceCreationReplay {
                    kind: SourceCreationResponseKind::Completed,
                    ..
                }
            ))
        ));
        tracker.shutdown().await;
        let response = match result_receiver
            .await
            .expect("supervisor reports its shutdown result")
        {
            Ok(response) => response,
            Err(error) => panic!(
                "completed source creation should recover, got {} ({})",
                error.code, error.status
            ),
        };
        assert_eq!(response.status, StatusCode::CREATED.as_u16());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sources")
                .fetch_one(&fixture.pool)
                .await
                .expect("source count reads"),
            1
        );
        close_source_creation_fixture(fixture).await;
    }

    #[tokio::test]
    async fn worker_panic_before_commit_interrupts_the_reservation() {
        let mut fixture = source_creation_fixture().await;
        fixture
            .sources
            .panic_source_creation_at(crate::protocols::SourceCreationPanic::BeforeCreate);
        let key = "panic-before-commit";
        let (request, payload) = deferred_source_request();
        let reservation = reserve_source_creation(&fixture, key, &request).await;
        let (shutdown_sender, shutdown) = tokio::sync::oneshot::channel();
        let result = supervise_source_creation(
            "panic-before-commit-request".to_owned(),
            fixture.sources.clone(),
            1,
            key.to_owned(),
            payload,
            fixture.idempotency.clone(),
            reservation,
            shutdown,
        )
        .await;
        drop(shutdown_sender);
        let Err(error) = result else {
            panic!("a pre-commit panic must not produce a source response");
        };
        assert_eq!(error.code, "idempotency_interrupted");
        assert!(matches!(
            fixture
                .idempotency
                .lookup(1, SOURCE_CREATION_ROUTE, key)
                .await
                .expect("interrupted reservation reads"),
            Some(SourceCreationIdempotencyStatus::Interrupted)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sources")
                .fetch_one(&fixture.pool)
                .await
                .expect("source count reads"),
            0
        );
        close_source_creation_fixture(fixture).await;
    }

    #[tokio::test]
    async fn worker_panic_after_commit_recovers_the_exact_success() {
        let mut fixture = source_creation_fixture().await;
        fixture
            .sources
            .panic_source_creation_at(crate::protocols::SourceCreationPanic::AfterCreate);
        let key = "panic-after-commit";
        let (request, payload) = deferred_source_request();
        let reservation = reserve_source_creation(&fixture, key, &request).await;
        let (shutdown_sender, shutdown) = tokio::sync::oneshot::channel();
        let result = supervise_source_creation(
            "panic-after-commit-request".to_owned(),
            fixture.sources.clone(),
            1,
            key.to_owned(),
            payload,
            fixture.idempotency.clone(),
            reservation,
            shutdown,
        )
        .await;
        drop(shutdown_sender);
        let response = match result {
            Ok(response) => response,
            Err(error) => panic!(
                "a post-commit panic should recover, got {} ({})",
                error.code, error.status
            ),
        };
        assert_eq!(response.status, StatusCode::CREATED.as_u16());
        assert!(matches!(
            fixture
                .idempotency
                .lookup(1, SOURCE_CREATION_ROUTE, key)
                .await
                .expect("completed reservation reads"),
            Some(SourceCreationIdempotencyStatus::Replay(
                SourceCreationReplay {
                    kind: SourceCreationResponseKind::Completed,
                    ..
                }
            ))
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sources")
                .fetch_one(&fixture.pool)
                .await
                .expect("source count reads"),
            1
        );
        close_source_creation_fixture(fixture).await;
    }

    #[tokio::test]
    async fn transient_settlement_lookup_failure_retries_and_recovers_committed_success() {
        let fixture = source_creation_fixture().await;
        let key = "transient-settlement-lookup";
        let (request, payload) = deferred_source_request();
        let reservation = reserve_source_creation(&fixture, key, &request).await;
        fixture.idempotency.fail_next_lookup_for_test();
        let (shutdown_sender, shutdown) = tokio::sync::oneshot::channel();
        let result = supervise_source_creation(
            "transient-settlement-lookup-request".to_owned(),
            fixture.sources.clone(),
            1,
            key.to_owned(),
            payload,
            fixture.idempotency.clone(),
            reservation,
            shutdown,
        )
        .await;
        drop(shutdown_sender);
        let response = match result {
            Ok(response) => response,
            Err(error) => panic!(
                "a transient lookup failure should recover, got {} ({})",
                error.code, error.status
            ),
        };
        assert_eq!(response.status, StatusCode::CREATED.as_u16());
        assert!(matches!(
            fixture
                .idempotency
                .lookup(1, SOURCE_CREATION_ROUTE, key)
                .await
                .expect("completed reservation reads"),
            Some(SourceCreationIdempotencyStatus::Replay(
                SourceCreationReplay {
                    kind: SourceCreationResponseKind::Completed,
                    ..
                }
            ))
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sources")
                .fetch_one(&fixture.pool)
                .await
                .expect("source count reads"),
            1
        );
        close_source_creation_fixture(fixture).await;
    }
}
