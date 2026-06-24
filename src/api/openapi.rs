use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, State, rejection::JsonRejection},
    routing::post,
};
use serde::Deserialize;

use super::{AdminMutation, ApiError, AppState, RequestId, parse_json, protocols::protocol_error};
use crate::protocols::{OpenApiPreview, OpenApiSpecInput};

const MAX_SPEC_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sources/openapi/preview", post(preview))
        .layer(DefaultBodyLimit::max(MAX_SPEC_BYTES + 64 * 1024))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreviewRequest {
    spec: OpenApiSpecInput,
    #[serde(default)]
    allow_private_network: bool,
}

async fn preview(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    AdminMutation(_admin_id): AdminMutation,
    payload: Result<Json<PreviewRequest>, JsonRejection>,
) -> Result<Json<OpenApiPreview>, ApiError> {
    let Json(payload) = parse_json(&request_id, payload)?;
    let preview = state
        .sources
        .preview_openapi(&payload.spec, payload.allow_private_network)
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    Ok(Json(preview))
}
