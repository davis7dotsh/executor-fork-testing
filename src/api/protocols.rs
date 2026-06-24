use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Extension, Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{
    AdminAuthentication, AdminMutation, ApiError, AppState, GatewayAuthentication, RequestId,
    parse_json,
};
use crate::{
    actor::ToolActor,
    approval::ApprovalError,
    catalog::{AuditContext, CatalogError, RequestSurface, SourceKind},
    execution::{ExecuteCodeRequest, ExecutionServiceError},
    invocation::{
        GatewayInvokeError, GatewayInvokeResponse, ToolCall, ToolCallError, ToolCallSubmission,
        ToolDiscoveryError, gateway_idempotency_key_is_valid,
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

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sources", post(create_source))
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

#[derive(Deserialize)]
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
    payload: Result<Json<CreateSourceRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<crate::catalog::SourceRecord>), ApiError> {
    let Json(payload) = parse_json(&request_id, payload)?;
    let source = state
        .sources
        .create(
            payload.kind,
            Value::Object(payload.protocol),
            AuditContext::admin(&request_id.0, admin_id),
        )
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    Ok((StatusCode::CREATED, Json(source)))
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
    Query(query): Query<DeleteCredentialsQuery>,
) -> Result<Json<CredentialMetadata>, ApiError> {
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
    if !gateway_idempotency_key_is_valid(value) {
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
        ToolCallError::Adapter { code, message } => {
            ApiError::new(request_id, StatusCode::BAD_REQUEST, code, message)
        }
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
    if error.category == ProtocolErrorCategory::Internal {
        return ApiError::internal_logged(request_id, error);
    }
    let status = match error.category {
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
        ProtocolErrorCategory::Conflict | ProtocolErrorCategory::CorruptData => {
            StatusCode::CONFLICT
        }
        ProtocolErrorCategory::Unsupported => StatusCode::BAD_REQUEST,
        ProtocolErrorCategory::Upstream if error.code == "upstream_timeout" => {
            StatusCode::GATEWAY_TIMEOUT
        }
        ProtocolErrorCategory::Upstream => StatusCode::BAD_GATEWAY,
        ProtocolErrorCategory::Internal => unreachable!("internal protocol errors return above"),
    };
    ApiError::new(request_id, status, error.code, error.message)
}

pub(super) fn outbound_error(request_id: &RequestId, error: OutboundError) -> ApiError {
    let status = match error {
        OutboundError::PrivateAddress | OutboundError::ForbiddenAddress => StatusCode::FORBIDDEN,
        OutboundError::ResponseBodyTooLarge
        | OutboundError::ResponseHeadersTooLarge
        | OutboundError::RequestBodyTooLarge
        | OutboundError::RequestHeadersTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        OutboundError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        OutboundError::Connection
        | OutboundError::Request
        | OutboundError::DnsResolution
        | OutboundError::UpstreamStatus { .. } => StatusCode::BAD_GATEWAY,
        _ => StatusCode::BAD_REQUEST,
    };
    ApiError::new(
        request_id,
        status,
        error.code(),
        "The upstream request could not be completed safely.",
    )
}
