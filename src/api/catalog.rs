use axum::{
    Json, Router,
    extract::{
        Extension, Path, Query, State,
        rejection::{PathRejection, QueryRejection},
    },
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
};
use serde::{Deserialize, Serialize};
use std::{future::Future, sync::Arc, time::Instant};
use tokio::sync::Semaphore;

use super::{
    ApiError, AppState, RequestId, parse_json, require_admin, require_admin_mutation,
    require_gateway_token,
};
use crate::{
    catalog::{
        AuditContext, CatalogError, ListToolsFilter, NewRequestLog, RequestOutcome, RequestSurface,
        ToolMode,
    },
    unix_timestamp,
};

const MAX_QUERY_CHARACTERS: usize = 256;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sources", get(list_sources))
        .route(
            "/api/v1/sources/{id}",
            get(source_detail).delete(delete_source),
        )
        .route("/api/v1/sources/{id}/mode", patch(set_source_mode))
        .route("/api/v1/tools", get(list_tools))
        .route("/api/v1/tools/modes", patch(bulk_set_tool_modes))
        .route("/api/v1/tools/{id}", get(tool_detail))
        .route("/api/v1/tools/{id}/mode", patch(set_tool_mode))
        .route("/api/v1/request-logs", get(list_request_logs))
        .route("/api/v1/request-logs/{id}", get(request_log_detail))
        .route("/api/v1/gateway/tools/search", post(gateway_search))
        .route("/api/v1/gateway/tools/describe", post(gateway_describe))
        .route("/api/v1/gateway/tools/lookup", post(gateway_lookup))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceListResponse {
    sources: Vec<crate::catalog::SourceRecord>,
    catalog_revision: i64,
}

async fn list_sources(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SourceListResponse>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    let (sources, catalog_revision) = state
        .catalog
        .list_sources_snapshot()
        .await
        .map_err(|error| catalog_error(&request_id, error))?;
    Ok(Json(SourceListResponse {
        sources,
        catalog_revision,
    }))
}

async fn source_detail(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<crate::catalog::SourceRecord>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    let Path(source_id) = parse_path(&request_id, path)?;
    state
        .catalog
        .source(&source_id)
        .await
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

async fn delete_source(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
) -> Result<StatusCode, ApiError> {
    let admin = require_admin_mutation(&request_id, &state, &headers).await?;
    let Path(source_id) = parse_path(&request_id, path)?;
    state
        .catalog
        .delete_source(&source_id, AuditContext::admin(&request_id.0, admin.id))
        .await
        .map_err(|error| catalog_error(&request_id, error))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetModeRequest {
    mode: serde_json::Value,
    expected_revision: i64,
}

async fn set_source_mode(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
    payload: Result<Json<SetModeRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::catalog::SourceRecord>, ApiError> {
    let admin = require_admin_mutation(&request_id, &state, &headers).await?;
    let Path(source_id) = parse_path(&request_id, path)?;
    let Json(payload) = parse_json(&request_id, payload)?;
    let mode = parse_mode(&request_id, payload.mode)?;
    state
        .catalog
        .set_source_mode(
            &source_id,
            mode,
            payload.expected_revision,
            AuditContext::admin(&request_id.0, admin.id),
        )
        .await
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListToolsQuery {
    query: Option<String>,
    source_id: Option<String>,
    mode: Option<ToolMode>,
    include_tombstoned: Option<bool>,
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn list_tools(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<ListToolsQuery>, QueryRejection>,
) -> Result<Json<crate::catalog::ToolPage>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    let Query(query) = parse_query(&request_id, query)?;
    validate_query(&request_id, query.query.as_deref())?;
    state
        .catalog
        .list_tools(ListToolsFilter {
            query: query.query,
            source_id: query.source_id,
            effective_mode: query.mode,
            include_tombstoned: query.include_tombstoned.unwrap_or(false),
            limit: query.limit.unwrap_or(50),
            offset: query.offset.unwrap_or(0),
        })
        .await
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

async fn tool_detail(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<crate::catalog::ToolRecord>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    let Path(tool_id) = parse_path(&request_id, path)?;
    state
        .catalog
        .tool(&tool_id)
        .await
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

async fn set_tool_mode(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
    payload: Result<Json<SetModeRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::catalog::ToolRecord>, ApiError> {
    let admin = require_admin_mutation(&request_id, &state, &headers).await?;
    let Path(tool_id) = parse_path(&request_id, path)?;
    let Json(payload) = parse_json(&request_id, payload)?;
    let mode = parse_mode(&request_id, payload.mode)?;
    state
        .catalog
        .set_tool_mode(
            &tool_id,
            mode,
            payload.expected_revision,
            AuditContext::admin(&request_id.0, admin.id),
        )
        .await
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkModeRequest {
    selection: BulkModeSelection,
    mode: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum BulkModeSelection {
    Source {
        source_id: String,
        expected_source_revision: i64,
    },
    ToolIds {
        tool_ids: Vec<String>,
        expected_catalog_revision: i64,
    },
}

async fn bulk_set_tool_modes(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<BulkModeRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::catalog::BulkToolModeResult>, ApiError> {
    let admin = require_admin_mutation(&request_id, &state, &headers).await?;
    let Json(payload) = parse_json(&request_id, payload)?;
    let mode = parse_mode(&request_id, payload.mode)?;
    let result = match payload.selection {
        BulkModeSelection::Source {
            source_id,
            expected_source_revision,
        } => {
            state
                .catalog
                .bulk_set_source_tool_modes(
                    &source_id,
                    mode,
                    expected_source_revision,
                    AuditContext::admin(&request_id.0, admin.id),
                )
                .await
        }
        BulkModeSelection::ToolIds {
            tool_ids,
            expected_catalog_revision,
        } => {
            state
                .catalog
                .bulk_set_tool_modes(
                    &tool_ids,
                    mode,
                    expected_catalog_revision,
                    AuditContext::admin(&request_id.0, admin.id),
                )
                .await
        }
    }
    .map_err(|error| catalog_error(&request_id, error))?;
    Ok(Json(result))
}

#[derive(Default, Deserialize)]
struct RequestLogQuery {
    cursor: Option<String>,
    limit: Option<u32>,
}

async fn list_request_logs(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<RequestLogQuery>, QueryRejection>,
) -> Result<Json<crate::catalog::RequestLogPage>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    let Query(query) = parse_query(&request_id, query)?;
    state
        .catalog
        .list_request_logs(query.cursor.as_deref(), query.limit.unwrap_or(50))
        .await
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

async fn request_log_detail(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
) -> Result<Json<crate::catalog::RequestLogRecord>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    let Path(log_id) = parse_path(&request_id, path)?;
    state
        .catalog
        .request_log(&log_id)
        .await
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

#[derive(Deserialize)]
struct SearchRequest {
    query: String,
    namespace: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

async fn gateway_search(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<SearchRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::catalog::DiscoveryPage>, ApiError> {
    let identity = require_gateway_token(&request_id, &state, &headers).await?;
    let Json(payload) = parse_json(&request_id, payload)?;
    validate_query(&request_id, Some(&payload.query))?;
    let started = Instant::now();
    let catalog = state.catalog.clone();
    let query = payload.query;
    let namespace = payload.namespace;
    let limit = payload.limit.unwrap_or(12);
    let offset = payload.offset.unwrap_or(0);
    let result =
        match with_gateway_search_slot(&request_id, &state.gateway_search_slots, async move {
            catalog
                .search_tools(&query, namespace.as_deref(), limit, offset)
                .await
        })
        .await
        {
            Ok(result) => result,
            Err(error) => {
                record_gateway_busy(&state, &request_id, &identity.token_id, started);
                return Err(error);
            }
        };
    record_gateway_result(
        &state,
        &request_id,
        &identity.token_id,
        "tools.search",
        None,
        None,
        started,
        &result,
    );
    result
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

async fn with_gateway_search_slot<T>(
    request_id: &RequestId,
    slots: &Arc<Semaphore>,
    search: impl Future<Output = T> + Send + 'static,
) -> Result<T, ApiError>
where
    T: Send + 'static,
{
    let permit = slots.clone().try_acquire_owned().map_err(|_| {
        ApiError::new(
            request_id,
            StatusCode::TOO_MANY_REQUESTS,
            "search_busy",
            "Tool search is busy. Try again shortly.",
        )
        .with_retry_after(1)
    })?;
    let search = tokio::spawn(async move {
        let result = search.await;
        drop(permit);
        result
    });
    Ok(search
        .await
        .expect("the gateway search task must run to completion"))
}

fn record_gateway_busy(state: &AppState, request_id: &RequestId, token_id: &str, started: Instant) {
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    state.request_logs.try_record(NewRequestLog {
        request_id: request_id.0.clone(),
        actor_api_token_id: Some(token_id.to_owned()),
        surface: RequestSurface::Gateway,
        source_id: None,
        tool_id: None,
        path_snapshot: Some("tools.search".to_owned()),
        outcome: RequestOutcome::Failed,
        error_code: Some("search_busy".to_owned()),
        duration_ms,
        approval_id: None,
        created_at: unix_timestamp(),
    });
}

#[derive(Deserialize)]
struct PathRequest {
    path: String,
}

async fn gateway_describe(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PathRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::catalog::DescribedTool>, ApiError> {
    let identity = require_gateway_token(&request_id, &state, &headers).await?;
    let Json(payload) = parse_json(&request_id, payload)?;
    validate_path(&request_id, &payload.path)?;
    let started = Instant::now();
    let result = state.catalog.describe_tool(&payload.path).await;
    record_gateway_result(
        &state,
        &request_id,
        &identity.token_id,
        &callable_snapshot(&payload.path),
        None,
        None,
        started,
        &result,
    );
    result
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

async fn gateway_lookup(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<PathRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<crate::catalog::InvocationLookup>, ApiError> {
    let identity = require_gateway_token(&request_id, &state, &headers).await?;
    let Json(payload) = parse_json(&request_id, payload)?;
    validate_path(&request_id, &payload.path)?;
    let started = Instant::now();
    let result = state.catalog.guard_invocation(&payload.path).await;
    let source_id = result.as_ref().ok().map(|lookup| lookup.source_id.as_str());
    let tool_id = result.as_ref().ok().map(|lookup| lookup.tool_id.as_str());
    let path = result
        .as_ref()
        .ok()
        .map(|lookup| lookup.callable_path.clone())
        .unwrap_or_else(|| callable_snapshot(&payload.path));
    record_gateway_result(
        &state,
        &request_id,
        &identity.token_id,
        &path,
        source_id,
        tool_id,
        started,
        &result,
    );
    result
        .map(Json)
        .map_err(|error| catalog_error(&request_id, error))
}

#[allow(clippy::too_many_arguments)]
fn record_gateway_result<T>(
    state: &AppState,
    request_id: &RequestId,
    token_id: &str,
    path_snapshot: &str,
    source_id: Option<&str>,
    tool_id: Option<&str>,
    started: Instant,
    result: &Result<T, CatalogError>,
) {
    let (outcome, error_code) = match result {
        Ok(_) => (RequestOutcome::Succeeded, None),
        Err(CatalogError::ToolDisabled { .. }) => (RequestOutcome::Denied, Some("tool_disabled")),
        Err(error) => (RequestOutcome::Failed, Some(catalog_error_code(error))),
    };
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    state.request_logs.try_record(NewRequestLog {
        request_id: request_id.0.clone(),
        actor_api_token_id: Some(token_id.to_owned()),
        surface: RequestSurface::Gateway,
        source_id: source_id.map(str::to_owned),
        tool_id: tool_id.map(str::to_owned),
        path_snapshot: Some(path_snapshot.to_owned()),
        outcome,
        error_code: error_code.map(str::to_owned),
        duration_ms,
        approval_id: None,
        created_at: unix_timestamp(),
    });
}

fn catalog_error_code(error: &CatalogError) -> &'static str {
    match error {
        CatalogError::Validation { code, .. } => code,
        CatalogError::NotFound { entity: "source" } => "source_not_found",
        CatalogError::NotFound {
            entity: "request log",
        } => "request_log_not_found",
        CatalogError::NotFound { .. } | CatalogError::ToolNotFound { .. } => "tool_not_found",
        CatalogError::ToolDisabled { .. } => "tool_disabled",
        CatalogError::RevisionConflict { .. } => "revision_conflict",
        CatalogError::Database(_)
        | CatalogError::Crypto(_)
        | CatalogError::Json(_)
        | CatalogError::CorruptData(_) => "internal_error",
    }
}

fn callable_snapshot(path: &str) -> String {
    if path.starts_with("tools.") {
        path.to_owned()
    } else {
        format!("tools.{path}")
    }
}

fn parse_query<T>(
    request_id: &RequestId,
    query: Result<Query<T>, QueryRejection>,
) -> Result<Query<T>, ApiError> {
    query.map_err(|_| {
        ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "The query parameters are invalid.",
        )
    })
}

fn parse_path<T>(
    request_id: &RequestId,
    path: Result<Path<T>, PathRejection>,
) -> Result<Path<T>, ApiError> {
    path.map_err(|_| {
        ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_path",
            "The path parameters are invalid.",
        )
    })
}

fn parse_mode(
    request_id: &RequestId,
    value: serde_json::Value,
) -> Result<Option<ToolMode>, ApiError> {
    if value.is_null() {
        return Ok(None);
    }
    serde_json::from_value(value).map(Some).map_err(|_| {
        ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_tool_mode",
            "Tool mode must be enabled, ask, disabled, or null.",
        )
    })
}

fn validate_query(request_id: &RequestId, query: Option<&str>) -> Result<(), ApiError> {
    if query.is_some_and(|query| query.chars().count() > MAX_QUERY_CHARACTERS) {
        Err(ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_query",
            "Search queries may contain at most 256 characters.",
        ))
    } else {
        Ok(())
    }
}

fn validate_path(request_id: &RequestId, path: &str) -> Result<(), ApiError> {
    let sandbox_path = path.strip_prefix("tools.").unwrap_or(path);
    let mut segments = sandbox_path.split('.');
    let valid = segments.next().is_some_and(valid_path_segment)
        && segments.next().is_some_and(valid_path_segment)
        && segments.next().is_none()
        && callable_snapshot(path).len() <= 512;
    if !valid {
        Err(ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_tool_path",
            "A valid tool path is required.",
        ))
    } else {
        Ok(())
    }
}

fn valid_path_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    characters
        .next()
        .is_some_and(|character| character.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
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
        CatalogError::NotFound {
            entity: "request log",
        } => ApiError::new(
            request_id,
            StatusCode::NOT_FOUND,
            "request_log_not_found",
            "The requested request log does not exist.",
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
            "The catalog changed. Refresh and retry the update.",
        ),
        error => ApiError::internal_logged(request_id, error),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use axum::{http::header, response::IntoResponse};
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tokio::{
        sync::{Notify, Semaphore},
        time::timeout,
    };

    use super::{RequestId, with_gateway_search_slot};

    #[tokio::test]
    async fn broad_gateway_search_rejects_excess_without_waiting_and_then_recovers() {
        let slots = Arc::new(Semaphore::new(1));
        let broad_started = Arc::new(Notify::new());
        let release_broad = Arc::new(Notify::new());
        let broad_slots = Arc::clone(&slots);
        let broad_started_signal = Arc::clone(&broad_started);
        let broad_release_signal = Arc::clone(&release_broad);
        let broad_search = tokio::spawn(async move {
            with_gateway_search_slot(
                &RequestId("broad-search".to_owned()),
                &broad_slots,
                async move {
                    broad_started_signal.notify_one();
                    broad_release_signal.notified().await;
                    "broad-result"
                },
            )
            .await
        });
        broad_started.notified().await;

        let excess_polled = Arc::new(AtomicBool::new(false));
        let excess_polled_inside = Arc::clone(&excess_polled);
        let busy = timeout(
            Duration::from_millis(100),
            with_gateway_search_slot(&RequestId("excess-search".to_owned()), &slots, async move {
                excess_polled_inside.store(true, Ordering::SeqCst);
                "must-not-run"
            }),
        )
        .await
        .expect("an excess search must fail without waiting")
        .expect_err("the occupied global search slot must reject excess work");
        assert!(!excess_polled.load(Ordering::SeqCst));

        let response = busy.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER),
            Some(&axum::http::HeaderValue::from_static("1"))
        );
        let body = response
            .into_body()
            .collect()
            .await
            .expect("busy response body should collect")
            .to_bytes();
        let body: Value = serde_json::from_slice(&body).expect("busy response should contain JSON");
        assert_eq!(body["error"]["code"], "search_busy");
        assert_eq!(body["error"]["requestId"], "excess-search");

        release_broad.notify_one();
        let broad_result = broad_search
            .await
            .expect("broad search task should not panic");
        let Ok(broad_result) = broad_result else {
            panic!("broad search should own the slot");
        };
        assert_eq!(broad_result, "broad-result");
        let recovered =
            with_gateway_search_slot(&RequestId("recovered-search".to_owned()), &slots, async {
                "recovered-result"
            })
            .await;
        let Ok(recovered) = recovered else {
            panic!("the global search slot should recover after completion");
        };
        assert_eq!(recovered, "recovered-result");
    }

    #[tokio::test]
    async fn aborted_search_waiter_keeps_slot_until_underlying_search_completes() {
        let slots = Arc::new(Semaphore::new(1));
        let search_started = Arc::new(Notify::new());
        let release_search = Arc::new(Notify::new());
        let search_completed = Arc::new(Notify::new());
        let waiter_slots = Arc::clone(&slots);
        let started_signal = Arc::clone(&search_started);
        let release_signal = Arc::clone(&release_search);
        let completed_signal = Arc::clone(&search_completed);
        let waiter = tokio::spawn(async move {
            with_gateway_search_slot(
                &RequestId("cancelled-search".to_owned()),
                &waiter_slots,
                async move {
                    started_signal.notify_one();
                    release_signal.notified().await;
                    completed_signal.notify_one();
                    "cancelled-waiter-result"
                },
            )
            .await
        });
        search_started.notified().await;

        waiter.abort();
        let waiter_error = match waiter.await {
            Err(error) => error,
            Ok(_) => panic!("the request-side waiter should be cancelled"),
        };
        assert!(waiter_error.is_cancelled());

        let excess_polled = Arc::new(AtomicBool::new(false));
        let excess_polled_inside = Arc::clone(&excess_polled);
        let busy = with_gateway_search_slot(
            &RequestId("cancelled-search-excess".to_owned()),
            &slots,
            async move {
                excess_polled_inside.store(true, Ordering::SeqCst);
                "must-not-run"
            },
        )
        .await
        .expect_err("the detached underlying search must continue owning the slot");
        assert!(!excess_polled.load(Ordering::SeqCst));
        assert_eq!(
            busy.into_response().status(),
            axum::http::StatusCode::TOO_MANY_REQUESTS
        );

        release_search.notify_one();
        timeout(Duration::from_secs(1), search_completed.notified())
            .await
            .expect("the detached underlying search should finish");
        timeout(Duration::from_secs(1), async {
            while slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the slot should be released after underlying completion");

        let recovered = with_gateway_search_slot(
            &RequestId("cancelled-search-recovered".to_owned()),
            &slots,
            async { "recovered-result" },
        )
        .await;
        let Ok(recovered) = recovered else {
            panic!("search admission should recover after underlying completion");
        };
        assert_eq!(recovered, "recovered-result");
    }
}
