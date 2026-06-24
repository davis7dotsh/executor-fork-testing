use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State, rejection::JsonRejection, rejection::QueryRejection},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    AdminMutation, ApiError, AppState, GatewayAuthentication, RequestId, parse_json,
    protocols::approval_error, require_admin,
};
use crate::approval::{
    ApprovalAdminDetail, ApprovalDecision, ApprovalListQuery, ApprovalRecord, ApprovalStatus,
};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/approvals", get(list))
        .route("/api/v1/approvals/{id}", get(admin_detail))
        .route(
            "/api/v1/approvals/{id}/decision",
            axum::routing::post(decide),
        )
        .route(
            "/api/v1/gateway/approvals/{id}",
            get(owner_detail).delete(cancel),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ListQuery {
    status: Option<ApprovalStatus>,
    cursor: Option<String>,
    #[serde(default = "default_limit")]
    limit: u32,
}

const fn default_limit() -> u32 {
    50
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalListResponse {
    items: Vec<ApprovalSummary>,
    next_cursor: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalSummary {
    id: String,
    status: ApprovalStatus,
    revision: i64,
    source_id: String,
    tool_id: String,
    path: String,
    source_display_name: Option<String>,
    tool_display_name: Option<String>,
    actor_kind: crate::actor::ActorKind,
    actor_id: String,
    actor_name: Option<String>,
    actor_label: String,
    actor_api_token_id: Option<String>,
    actor_token_name: Option<String>,
    surface: crate::catalog::RequestSurface,
    mode: &'static str,
    provenance: crate::catalog::ModeProvenance,
    execution_id: String,
    call_id: String,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
    decided_at: Option<i64>,
    started_at: Option<i64>,
    completed_at: Option<i64>,
    decision: Option<ApprovalDecision>,
    failure_code: Option<String>,
}

impl From<ApprovalRecord> for ApprovalSummary {
    fn from(record: ApprovalRecord) -> Self {
        let actor_label = match record.actor_kind {
            crate::actor::ActorKind::ApiToken => record
                .actor_name_snapshot
                .clone()
                .unwrap_or_else(|| "API token".to_owned()),
            crate::actor::ActorKind::Admin => format!("Admin {}", record.actor_id),
            crate::actor::ActorKind::System => match record.actor_id.as_str() {
                "local_cli" => "Local CLI".to_owned(),
                _ => "System".to_owned(),
            },
        };
        Self {
            id: record.id,
            status: record.status,
            revision: record.revision,
            source_id: record.revisions.source_id,
            tool_id: record.revisions.tool_id,
            path: record.callable_path_snapshot,
            source_display_name: record.source_display_name,
            tool_display_name: record.tool_display_name,
            actor_kind: record.actor_kind,
            actor_id: record.actor_id,
            actor_name: record.actor_name_snapshot.clone(),
            actor_label,
            actor_api_token_id: record.actor_api_token_id,
            actor_token_name: record.actor_name_snapshot,
            surface: record.surface,
            mode: "ask",
            provenance: record.mode_provenance,
            execution_id: record.execution_id,
            call_id: record.call_id,
            created_at: record.created_at,
            updated_at: record.updated_at,
            expires_at: record.expires_at,
            decided_at: record.decided_at,
            started_at: record.execution_started_at,
            completed_at: record.completed_at,
            decision: record.decision,
            failure_code: record.failure_code,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminDetailResponse {
    #[serde(flatten)]
    summary: ApprovalSummary,
    redacted_arguments: Value,
    input_schema: Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerDetailResponse {
    id: String,
    status: ApprovalStatus,
    revision: i64,
    path: String,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
    failure_code: Option<String>,
    result: Option<Value>,
}

async fn list(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> Result<Json<ApprovalListResponse>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    let Query(query) = query.map_err(|_| invalid_query(&request_id))?;
    let before_sequence = query
        .cursor
        .as_deref()
        .map(|cursor| decode_cursor(&request_id, cursor))
        .transpose()?;
    state
        .tool_calls
        .expire_approvals()
        .await
        .map_err(|error| approval_error(&request_id, error))?;
    let page = state
        .tool_calls
        .approvals()
        .list_admin(ApprovalListQuery {
            before_sequence,
            limit: query.limit,
            status: query.status,
        })
        .await
        .map_err(|error| approval_error(&request_id, error))?;
    Ok(Json(ApprovalListResponse {
        items: page.items.into_iter().map(ApprovalSummary::from).collect(),
        next_cursor: page.next_cursor.map(encode_cursor),
    }))
}

async fn admin_detail(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(approval_id): Path<String>,
) -> Result<Json<AdminDetailResponse>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    state
        .tool_calls
        .expire_approvals()
        .await
        .map_err(|error| approval_error(&request_id, error))?;
    let detail = state
        .tool_calls
        .approvals()
        .get_admin(&approval_id)
        .await
        .map_err(|error| approval_error(&request_id, error))?
        .ok_or_else(|| approval_error(&request_id, crate::approval::ApprovalError::NotFound))?;
    Ok(Json(admin_response(detail)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DecisionRequest {
    decision: ApprovalDecision,
    expected_revision: i64,
}

async fn decide(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    AdminMutation(admin_id): AdminMutation,
    Path(approval_id): Path<String>,
    payload: Result<Json<DecisionRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<AdminDetailResponse>), ApiError> {
    let Json(payload) = parse_json(&request_id, payload)?;
    let detail = state
        .tool_calls
        .decide(
            &approval_id,
            &request_id.0,
            payload.expected_revision,
            payload.decision,
            admin_id,
        )
        .await
        .map_err(|error| approval_error(&request_id, error))?;
    let status = if detail.record.status.is_terminal() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((status, Json(admin_response(detail))))
}

async fn owner_detail(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    GatewayAuthentication(identity): GatewayAuthentication,
    Path(approval_id): Path<String>,
) -> Result<Json<OwnerDetailResponse>, ApiError> {
    state
        .tool_calls
        .expire_approvals()
        .await
        .map_err(|error| approval_error(&request_id, error))?;
    let detail = state
        .tool_calls
        .approvals()
        .get_for_token(&approval_id, &identity.token_id)
        .await
        .map_err(|error| approval_error(&request_id, error))?
        .ok_or_else(|| approval_error(&request_id, crate::approval::ApprovalError::NotFound))?;
    Ok(Json(OwnerDetailResponse {
        id: detail.record.id,
        status: detail.record.status,
        revision: detail.record.revision,
        path: detail.record.callable_path_snapshot,
        created_at: detail.record.created_at,
        updated_at: detail.record.updated_at,
        expires_at: detail.record.expires_at,
        failure_code: detail.record.failure_code,
        result: detail.result,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CancelQuery {
    expected_revision: i64,
}

async fn cancel(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    GatewayAuthentication(identity): GatewayAuthentication,
    Path(approval_id): Path<String>,
    query: Result<Query<CancelQuery>, QueryRejection>,
) -> Result<Json<OwnerDetailResponse>, ApiError> {
    let Query(query) = query.map_err(|_| invalid_query(&request_id))?;
    state
        .tool_calls
        .cancel_approval(&approval_id, &identity.token_id, query.expected_revision)
        .await
        .map_err(|error| approval_error(&request_id, error))?;
    owner_detail(
        Extension(request_id),
        State(state),
        GatewayAuthentication(identity),
        Path(approval_id),
    )
    .await
}

fn admin_response(detail: ApprovalAdminDetail) -> AdminDetailResponse {
    AdminDetailResponse {
        summary: ApprovalSummary::from(detail.record),
        redacted_arguments: detail.redacted_arguments,
        input_schema: detail.input_schema,
    }
}

fn encode_cursor(sequence: i64) -> String {
    URL_SAFE_NO_PAD.encode(sequence.to_be_bytes())
}

fn decode_cursor(request_id: &RequestId, cursor: &str) -> Result<i64, ApiError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| invalid_query(request_id))?;
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| invalid_query(request_id))?;
    let sequence = i64::from_be_bytes(bytes);
    if sequence <= 0 {
        return Err(invalid_query(request_id));
    }
    Ok(sequence)
}

fn invalid_query(request_id: &RequestId) -> ApiError {
    ApiError::new(
        request_id,
        StatusCode::BAD_REQUEST,
        "invalid_query",
        "The approval query is invalid.",
    )
}
