use std::{collections::BTreeMap, time::Instant};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{
    AdminMutation, ApiError, AppState, GatewayAuthentication, RequestId, openapi, parse_json,
};
use crate::{
    catalog::{
        CatalogError, InvocationLease, InvocationLookup, InvocationRevisionToken, NewRequestLog,
        RequestOutcome, RequestSurface, SourceKind, ToolBinding,
    },
    outbound::{HardenedHttpClient, OutboundError},
    unix_timestamp,
};

const MAX_SOURCE_BODY_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_INVOKE_BODY_BYTES: usize = MAX_ARGUMENT_BYTES + 64 * 1024;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sources", post(create_source))
        .layer(DefaultBodyLimit::max(MAX_SOURCE_BODY_BYTES))
        .merge(
            Router::new()
                .route("/api/v1/gateway/tools/invoke", post(invoke))
                .layer(DefaultBodyLimit::max(MAX_INVOKE_BODY_BYTES)),
        )
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
    match payload.kind {
        SourceKind::Openapi => {
            let request =
                serde_json::from_value(Value::Object(payload.protocol)).map_err(|_| {
                    ApiError::new(
                        &request_id,
                        StatusCode::BAD_REQUEST,
                        "invalid_json",
                        "The request body must be valid JSON with the expected fields.",
                    )
                })?;
            let source = openapi::create_source(&state, &request_id, admin_id, request).await?;
            Ok((StatusCode::CREATED, Json(source)))
        }
        SourceKind::Graphql | SourceKind::McpHttp | SourceKind::McpStdio => Err(ApiError::new(
            &request_id,
            StatusCode::BAD_REQUEST,
            "unsupported_source_kind",
            "This source protocol is not supported yet.",
        )),
    }
}

#[derive(Deserialize)]
struct InvokeRequest {
    path: String,
    #[serde(default = "empty_object")]
    arguments: Value,
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvokeResponse {
    ok: bool,
    data: Option<Value>,
    error: Option<InvokeError>,
    http: InvokeHttp,
}

#[derive(Serialize)]
struct InvokeError {
    code: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct InvokeHttp {
    status: u16,
    headers: BTreeMap<String, String>,
    truncated: bool,
}

pub(super) struct InvocationAdapterError {
    pub code: &'static str,
    pub message: &'static str,
}

async fn invoke(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    GatewayAuthentication(identity): GatewayAuthentication,
    payload: Result<Json<InvokeRequest>, JsonRejection>,
) -> Result<Json<InvokeResponse>, ApiError> {
    let started = Instant::now();
    let Json(payload) = match parse_json(&request_id, payload) {
        Ok(payload) => payload,
        Err(error) => {
            record_invocation_attempt(
                &state,
                &request_id,
                &identity.token_id,
                None,
                None,
                "tools.invoke",
                started,
                RequestOutcome::Failed,
                Some(error.code),
            );
            return Err(error);
        }
    };
    if serde_json::to_vec(&payload.arguments)
        .is_ok_and(|encoded| encoded.len() > MAX_ARGUMENT_BYTES)
    {
        record_invocation_attempt(
            &state,
            &request_id,
            &identity.token_id,
            None,
            None,
            &payload.path,
            started,
            RequestOutcome::Failed,
            Some("arguments_too_large"),
        );
        return Err(ApiError::new(
            &request_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "arguments_too_large",
            "Tool arguments exceed the allowed size.",
        ));
    }

    let lease = match state.catalog.prepare_invocation(&payload.path).await {
        Ok(lease) => lease,
        Err(error) => {
            record_invocation_attempt(
                &state,
                &request_id,
                &identity.token_id,
                None,
                None,
                &payload.path,
                started,
                if matches!(error, CatalogError::ToolDisabled { .. }) {
                    RequestOutcome::Denied
                } else {
                    RequestOutcome::Failed
                },
                Some(catalog_log_code(&error)),
            );
            return Err(catalog_error(&request_id, error));
        }
    };
    let plan = match dispatch(&lease, &payload.arguments) {
        Ok(plan) => plan,
        Err(error) => {
            record_invocation(
                &state,
                &request_id,
                &identity.token_id,
                &lease.lookup,
                started,
                RequestOutcome::Failed,
                Some(error.code),
            );
            return Err(ApiError::new(
                &request_id,
                StatusCode::BAD_REQUEST,
                error.code,
                error.message,
            ));
        }
    };
    if !lease.arguments_are_valid(&payload.arguments) {
        record_invocation(
            &state,
            &request_id,
            &identity.token_id,
            &lease.lookup,
            started,
            RequestOutcome::Failed,
            Some("invalid_tool_arguments"),
        );
        return Err(ApiError::new(
            &request_id,
            StatusCode::BAD_REQUEST,
            "invalid_tool_arguments",
            "The tool arguments do not match the imported input schema.",
        ));
    }
    if lease.lookup.requires_approval {
        let pending = PendingApproval {
            revisions: lease.revisions.clone(),
        };
        record_invocation(
            &state,
            &request_id,
            &identity.token_id,
            &lease.lookup,
            started,
            RequestOutcome::PendingApproval,
            Some("approval_required"),
        );
        return Err(pending.into_api_error(&request_id));
    }

    let response = match HardenedHttpClient::new(plan.policy)
        .execute(plan.request)
        .await
    {
        Ok(response) => {
            let succeeded = response.status.is_success();
            let data = response_data(&response.headers, &response.body);
            record_invocation(
                &state,
                &request_id,
                &identity.token_id,
                &lease.lookup,
                started,
                if succeeded {
                    RequestOutcome::Succeeded
                } else {
                    RequestOutcome::Failed
                },
                (!succeeded).then_some("upstream_http_error"),
            );
            InvokeResponse {
                ok: succeeded,
                data: succeeded.then_some(data),
                error: (!succeeded).then_some(InvokeError {
                    code: "upstream_http_error",
                    message: "The upstream API returned an error response.",
                }),
                http: InvokeHttp {
                    status: response.status.as_u16(),
                    headers: safe_response_headers(&response.headers),
                    truncated: false,
                },
            }
        }
        Err(error) => {
            record_invocation(
                &state,
                &request_id,
                &identity.token_id,
                &lease.lookup,
                started,
                RequestOutcome::Failed,
                Some(error.code()),
            );
            return Err(outbound_error(&request_id, error));
        }
    };
    drop(lease);
    Ok(Json(response))
}

fn dispatch(
    lease: &InvocationLease,
    arguments: &Value,
) -> Result<openapi::OpenApiInvocationPlan, InvocationAdapterError> {
    match &lease.binding {
        ToolBinding::OpenapiV1(binding) => openapi::invocation_plan(
            binding,
            &lease.source_configuration,
            lease.credential.as_ref(),
            arguments,
        ),
    }
}

struct PendingApproval {
    revisions: InvocationRevisionToken,
}

impl PendingApproval {
    fn into_api_error(self, request_id: &RequestId) -> ApiError {
        tracing::debug!(
            request_id = %request_id.0,
            source_id = %self.revisions.source_id,
            tool_id = %self.revisions.tool_id,
            source_revision = self.revisions.source_revision,
            catalog_revision = self.revisions.catalog_revision,
            tool_revision = self.revisions.tool_revision,
            binding_revision = self.revisions.binding_revision,
            credential_revision = self.revisions.credential_revision,
            "invocation requires approval against a catalog revision token"
        );
        ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "approval_required",
            "This tool requires interactive approval before it can run.",
        )
    }
}

fn response_data(headers: &HeaderMap, body: &[u8]) -> Value {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if (content_type.contains("/json") || content_type.contains("+json"))
        && let Ok(value) = serde_json::from_slice(body)
    {
        value
    } else if let Ok(value) = std::str::from_utf8(body) {
        Value::String(value.to_owned())
    } else {
        json!({ "encoding": "base64", "data": STANDARD.encode(body) })
    }
}

fn safe_response_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    [
        header::CONTENT_TYPE,
        header::CONTENT_LENGTH,
        header::RETRY_AFTER,
    ]
    .into_iter()
    .filter_map(|name| {
        headers
            .get(&name)
            .and_then(|value| value.to_str().ok())
            .map(|value| (name.as_str().to_owned(), value.to_owned()))
    })
    .collect()
}

fn record_invocation(
    state: &AppState,
    request_id: &RequestId,
    token_id: &str,
    lookup: &InvocationLookup,
    started: Instant,
    outcome: RequestOutcome,
    error_code: Option<&str>,
) {
    record_invocation_attempt(
        state,
        request_id,
        token_id,
        Some(lookup.source_id.clone()),
        Some(lookup.tool_id.clone()),
        &lookup.callable_path,
        started,
        outcome,
        error_code,
    );
}

#[allow(clippy::too_many_arguments)]
fn record_invocation_attempt(
    state: &AppState,
    request_id: &RequestId,
    token_id: &str,
    source_id: Option<String>,
    tool_id: Option<String>,
    path: &str,
    started: Instant,
    outcome: RequestOutcome,
    error_code: Option<&str>,
) {
    let mut path_snapshot = if path.starts_with("tools.") {
        path.to_owned()
    } else {
        format!("tools.{path}")
    };
    if path_snapshot.len() > 512 || path_snapshot.contains('\0') {
        path_snapshot = "tools.invoke".to_owned();
    }
    state.request_logs.try_record(NewRequestLog {
        request_id: request_id.0.clone(),
        actor_api_token_id: Some(token_id.to_owned()),
        surface: RequestSurface::Gateway,
        source_id,
        tool_id,
        path_snapshot: Some(path_snapshot),
        outcome,
        error_code: error_code.map(str::to_owned),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        approval_id: None,
        created_at: unix_timestamp(),
    });
}

fn catalog_log_code(error: &CatalogError) -> &'static str {
    match error {
        CatalogError::Validation { code, .. } => code,
        CatalogError::NotFound { entity: "source" } => "source_not_found",
        CatalogError::NotFound { .. } | CatalogError::ToolNotFound { .. } => "tool_not_found",
        CatalogError::ToolDisabled { .. } => "tool_disabled",
        CatalogError::RevisionConflict { .. } => "revision_conflict",
        CatalogError::Database(_)
        | CatalogError::Crypto(_)
        | CatalogError::Json(_)
        | CatalogError::CorruptData(_) => "internal_error",
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

fn outbound_error(request_id: &RequestId, error: OutboundError) -> ApiError {
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
