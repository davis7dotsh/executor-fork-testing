use std::collections::HashSet;

use axum::{
    Json, Router,
    extract::{
        Extension, FromRequestParts, Path, Query, State, rejection::JsonRejection,
        rejection::QueryRejection,
    },
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};

use super::protocols::protocol_error;
use super::{
    AdminAuthentication, AdminSession, ApiError, AppState, RequestId, parse_json, require_admin,
    require_admin_mutation,
};
use crate::catalog::AuditContext;
use crate::oauth::{
    CallbackRequest, ConnectionView, OAuthClientInput, OAuthDiscoveryInput, OAuthError,
    SaveConnectionRequest,
};
use crate::protocols::AvailableOAuthCredential;

const CALLBACK_UI_PATH: &str = "/sources";

#[derive(Clone, Copy)]
enum CallbackOutcome {
    Failed,
    Success,
    SuccessRefreshFailed,
}

impl CallbackOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Success => "success",
            Self::SuccessRefreshFailed => "success_refresh_failed",
        }
    }
}

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sources/{sourceId}/oauth", get(list_connections))
        .route(
            "/api/v1/sources/{sourceId}/oauth/{credentialKey}",
            axum::routing::put(save_connection).delete(delete_connection),
        )
        .route(
            "/api/v1/sources/{sourceId}/oauth/{credentialKey}/authorize",
            post(begin_authorization),
        )
        .route(
            "/api/v1/sources/{sourceId}/oauth/{credentialKey}/disconnect",
            post(disconnect),
        )
        .route(
            "/api/v1/oauth/callback/{connectionId}",
            get(complete_callback),
        )
}

struct OAuthAdminMutation(AdminSession);

impl FromRequestParts<AppState> for OAuthAdminMutation {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .expect("request ID middleware runs before authentication")
            .clone();
        let admin = require_admin_mutation(&request_id, state, &parts.headers).await?;
        Ok(Self(admin))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SaveConnectionBody {
    expected_revision: i64,
    discovery: OAuthDiscoveryInput,
    client: OAuthClientInput,
    scopes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevisionBody {
    expected_revision: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RevisionQuery {
    expected_revision: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionListResponse {
    connections: Vec<ConnectionListItem>,
    available_credentials: Vec<AvailableOAuthCredential>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionListItem {
    #[serde(flatten)]
    connection: ConnectionView,
    #[serde(rename = "managedOAuthEligible")]
    managed_oauth_eligible: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationStartResponse {
    authorization_url: String,
}

#[derive(Deserialize)]
struct CallbackQuery {
    state: String,
    code: Option<String>,
    error: Option<String>,
}

async fn list_connections(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    _admin: AdminAuthentication,
    Path(source_id): Path<String>,
) -> Result<Json<ConnectionListResponse>, ApiError> {
    let connections = state
        .oauth
        .list_connections(&source_id)
        .await
        .map_err(|error| oauth_error(&request_id, error))?;
    let configured_keys = connections
        .iter()
        .map(|connection| connection.credential_key.clone())
        .collect::<HashSet<_>>();
    let credential_options = state
        .sources
        .available_oauth_credentials(&source_id)
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    let eligible_keys = credential_options
        .iter()
        .filter(|credential| credential.managed_oauth_eligible)
        .map(|credential| credential.credential_key.as_str())
        .collect::<HashSet<_>>();
    let connections = connections
        .into_iter()
        .map(|connection| ConnectionListItem {
            managed_oauth_eligible: eligible_keys.contains(connection.credential_key.as_str()),
            connection,
        })
        .collect();
    let available_credentials = credential_options
        .into_iter()
        .filter(|credential| !configured_keys.contains(credential.credential_key.as_str()))
        .collect();
    Ok(Json(ConnectionListResponse {
        connections,
        available_credentials,
    }))
}

async fn save_connection(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    OAuthAdminMutation(admin): OAuthAdminMutation,
    Path((source_id, credential_key)): Path<(String, String)>,
    payload: Result<Json<SaveConnectionBody>, JsonRejection>,
) -> Result<Json<ConnectionListItem>, ApiError> {
    let Json(payload) = parse_json(&request_id, payload)?;
    require_eligible_credential(&request_id, &state, &source_id, &credential_key).await?;
    state
        .sources
        .ensure_managed_oauth_origin_bound(
            &source_id,
            &credential_key,
            AuditContext::admin(&request_id.0, admin.id),
        )
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    let connection = state
        .oauth
        .save_connection(
            &source_id,
            &credential_key,
            SaveConnectionRequest {
                expected_revision: payload.expected_revision,
                discovery: payload.discovery,
                client: payload.client,
                scopes: payload.scopes,
            },
        )
        .await
        .map_err(|error| oauth_error(&request_id, error))?;
    Ok(Json(ConnectionListItem {
        connection,
        managed_oauth_eligible: true,
    }))
}

async fn begin_authorization(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    OAuthAdminMutation(admin): OAuthAdminMutation,
    Path((source_id, credential_key)): Path<(String, String)>,
    payload: Result<Json<RevisionBody>, JsonRejection>,
) -> Result<Json<AuthorizationStartResponse>, ApiError> {
    let Json(payload) = parse_json(&request_id, payload)?;
    require_eligible_credential(&request_id, &state, &source_id, &credential_key).await?;
    state
        .sources
        .ensure_managed_oauth_origin_bound(
            &source_id,
            &credential_key,
            AuditContext::admin(&request_id.0, admin.id),
        )
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    let authorization = state
        .oauth
        .begin_authorization(
            &source_id,
            &credential_key,
            payload.expected_revision,
            admin.id,
            &admin.session_digest,
        )
        .await
        .map_err(|error| oauth_error(&request_id, error))?;
    Ok(Json(AuthorizationStartResponse {
        authorization_url: authorization.authorization_url,
    }))
}

async fn require_eligible_credential(
    request_id: &RequestId,
    state: &AppState,
    source_id: &str,
    credential_key: &str,
) -> Result<(), ApiError> {
    let eligible = credential_is_eligible(request_id, state, source_id, credential_key).await?;
    if eligible {
        Ok(())
    } else {
        Err(ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "oauth_credential_ineligible",
            "The selected source credential does not support managed OAuth.",
        ))
    }
}

async fn credential_is_eligible(
    request_id: &RequestId,
    state: &AppState,
    source_id: &str,
    credential_key: &str,
) -> Result<bool, ApiError> {
    Ok(state
        .sources
        .available_oauth_credentials(source_id)
        .await
        .map_err(|error| protocol_error(request_id, error))?
        .into_iter()
        .any(|credential| {
            credential.managed_oauth_eligible && credential.credential_key == credential_key
        }))
}

async fn disconnect(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    OAuthAdminMutation(_admin): OAuthAdminMutation,
    Path((source_id, credential_key)): Path<(String, String)>,
    payload: Result<Json<RevisionBody>, JsonRejection>,
) -> Result<Json<ConnectionListItem>, ApiError> {
    let Json(payload) = parse_json(&request_id, payload)?;
    let managed_oauth_eligible =
        credential_is_eligible(&request_id, &state, &source_id, &credential_key).await?;
    let connection = state
        .oauth
        .disconnect(&source_id, &credential_key, payload.expected_revision)
        .await
        .map_err(|error| oauth_error(&request_id, error))?;
    Ok(Json(ConnectionListItem {
        connection,
        managed_oauth_eligible,
    }))
}

async fn delete_connection(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    OAuthAdminMutation(admin): OAuthAdminMutation,
    Path((source_id, credential_key)): Path<(String, String)>,
    query: Result<Query<RevisionQuery>, QueryRejection>,
) -> Result<StatusCode, ApiError> {
    let Query(query) = query.map_err(|_| invalid_revision(&request_id))?;
    match state
        .oauth
        .delete_connection(&source_id, &credential_key, query.expected_revision)
        .await
    {
        Ok(()) | Err(OAuthError::NotFound) => {}
        Err(error) => return Err(oauth_error(&request_id, error)),
    }
    state
        .sources
        .retire_managed_oauth_origin(
            &source_id,
            &credential_key,
            AuditContext::admin(&request_id.0, admin.id),
        )
        .await
        .map_err(|error| protocol_error(&request_id, error))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn complete_callback(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(connection_id): Path<String>,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Response {
    let response =
        match complete_callback_result(&request_id, &state, &headers, connection_id.clone(), query)
            .await
        {
            Ok(redirect) => redirect.into_response(),
            Err(_) => {
                callback_redirect(&state, CallbackOutcome::Failed, &connection_id).into_response()
            }
        };
    with_callback_headers(response)
}

async fn complete_callback_result(
    request_id: &RequestId,
    state: &AppState,
    headers: &HeaderMap,
    connection_id: String,
    query: Result<Query<CallbackQuery>, QueryRejection>,
) -> Result<Redirect, ApiError> {
    let admin = require_admin(request_id, state, headers).await?;
    let Query(query) = query.map_err(|_| invalid_callback(request_id))?;
    let result = match state
        .oauth
        .complete_callback(
            CallbackRequest {
                connection_id,
                state: query.state,
                code: query.code,
                error: query.error,
            },
            admin.id,
            &admin.session_digest,
        )
        .await
    {
        Ok(result) => result,
        Err(OAuthError::AuthorizationDenied { connection_id }) => {
            return Ok(callback_redirect(
                state,
                CallbackOutcome::Failed,
                &connection_id,
            ));
        }
        Err(error) => return Err(oauth_error(request_id, error)),
    };
    let outcome = match state
        .sources
        .refresh(
            &result.source_id,
            AuditContext::admin(&request_id.0, admin.id),
        )
        .await
    {
        Ok(_) => CallbackOutcome::Success,
        Err(_) => CallbackOutcome::SuccessRefreshFailed,
    };
    Ok(callback_redirect(state, outcome, &result.connection_id))
}

fn callback_redirect(state: &AppState, outcome: CallbackOutcome, connection_id: &str) -> Redirect {
    Redirect::to(&callback_target(
        state.origin.as_ref(),
        outcome,
        connection_id,
    ))
}

fn callback_target(origin: &str, outcome: CallbackOutcome, connection_id: &str) -> String {
    let connection_id = utf8_percent_encode(connection_id, NON_ALPHANUMERIC);
    let result = outcome.as_str();
    format!("{origin}{CALLBACK_UI_PATH}?oauth={connection_id}&result={result}")
}

fn with_callback_headers(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn invalid_revision(request_id: &RequestId) -> ApiError {
    ApiError::new(
        request_id,
        StatusCode::BAD_REQUEST,
        "invalid_revision",
        "A valid expectedRevision query parameter is required.",
    )
}

fn invalid_callback(request_id: &RequestId) -> ApiError {
    ApiError::new(
        request_id,
        StatusCode::BAD_REQUEST,
        "invalid_oauth_callback",
        "The OAuth callback parameters are invalid.",
    )
}

fn oauth_error(request_id: &RequestId, error: OAuthError) -> ApiError {
    match error {
        OAuthError::Validation { code, message } => {
            ApiError::new(request_id, StatusCode::BAD_REQUEST, code, message)
        }
        OAuthError::NotFound => ApiError::new(
            request_id,
            StatusCode::NOT_FOUND,
            "oauth_connection_not_found",
            "The OAuth connection does not exist.",
        ),
        OAuthError::Conflict { code, message } => {
            ApiError::new(request_id, StatusCode::CONFLICT, code, message)
        }
        OAuthError::UnauthorizedTransaction => ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_oauth_transaction",
            "The OAuth transaction is invalid for this administrator session.",
        ),
        OAuthError::AuthorizationDenied { .. } => ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "oauth_authorization_denied",
            "OAuth authorization was denied.",
        ),
        OAuthError::Upstream { .. } => ApiError::new(
            request_id,
            StatusCode::BAD_GATEWAY,
            "oauth_upstream_failed",
            "The OAuth provider could not complete the request.",
        ),
        OAuthError::Internal => ApiError::internal(request_id),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        http::{HeaderValue, StatusCode, header},
        response::{IntoResponse, Redirect},
    };

    use super::{
        CallbackOutcome, ConnectionListItem, callback_target, oauth_error, with_callback_headers,
    };
    use crate::{
        api::RequestId,
        oauth::{ClientAuthentication, ConnectionStatus, ConnectionView, OAuthError},
    };

    #[test]
    fn callback_target_uses_only_the_configured_origin_and_fixed_ui_path() {
        assert_eq!(
            callback_target(
                "https://executor.example",
                CallbackOutcome::Failed,
                "connection&result=success#fragment",
            ),
            "https://executor.example/sources?oauth=connection%26result%3Dsuccess%23fragment&result=failed"
        );
    }

    #[test]
    fn callback_target_allows_the_partial_success_outcome() {
        assert_eq!(
            callback_target(
                "https://executor.example",
                CallbackOutcome::SuccessRefreshFailed,
                "connection",
            ),
            "https://executor.example/sources?oauth=connection&result=success_refresh_failed"
        );
    }

    #[test]
    fn callback_responses_never_forward_callback_secrets_as_referrers() {
        let response = with_callback_headers(
            Redirect::to("https://executor.example/sources?oauth=connection&result=success")
                .into_response(),
        );
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY),
            Some(&HeaderValue::from_static("no-referrer"))
        );
    }

    #[test]
    fn oauth_errors_have_exhaustive_status_and_redaction_contracts() {
        let cases = [
            (
                OAuthError::Validation {
                    code: "invalid_oauth_input",
                    message: "The OAuth input is invalid.",
                },
                StatusCode::BAD_REQUEST,
                "invalid_oauth_input",
                "The OAuth input is invalid.",
            ),
            (
                OAuthError::NotFound,
                StatusCode::NOT_FOUND,
                "oauth_connection_not_found",
                "The OAuth connection does not exist.",
            ),
            (
                OAuthError::Conflict {
                    code: "oauth_binding_changed",
                    message: "The OAuth binding changed.",
                },
                StatusCode::CONFLICT,
                "oauth_binding_changed",
                "The OAuth binding changed.",
            ),
            (
                OAuthError::UnauthorizedTransaction,
                StatusCode::BAD_REQUEST,
                "invalid_oauth_transaction",
                "The OAuth transaction is invalid for this administrator session.",
            ),
            (
                OAuthError::AuthorizationDenied {
                    connection_id: "secret-connection-id".to_owned(),
                },
                StatusCode::BAD_REQUEST,
                "oauth_authorization_denied",
                "OAuth authorization was denied.",
            ),
            (
                OAuthError::Upstream {
                    code: "provider_secret_marker",
                },
                StatusCode::BAD_GATEWAY,
                "oauth_upstream_failed",
                "The OAuth provider could not complete the request.",
            ),
            (
                OAuthError::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "The request could not be completed.",
            ),
        ];
        for (source, status, code, message) in cases {
            let error = oauth_error(&RequestId("request-id".to_owned()), source);
            assert_eq!(error.status, status);
            assert_eq!(error.code, code);
            assert_eq!(error.message, message);
            assert!(!error.message.contains("provider_secret_marker"));
            assert!(!error.message.contains("secret-connection-id"));
        }
    }

    #[test]
    fn configured_connections_expose_current_managed_oauth_eligibility() {
        let value = serde_json::to_value(ConnectionListItem {
            connection: ConnectionView {
                id: "connection".to_owned(),
                credential_key: "default".to_owned(),
                revision: 1,
                status: ConnectionStatus::Connected,
                issuer: "https://issuer.example".to_owned(),
                client_id: "client".to_owned(),
                client_auth_method: ClientAuthentication::None,
                callback_url: "https://executor.example/api/v1/oauth/callback/connection"
                    .to_owned(),
                requested_scopes: vec!["read".to_owned()],
                granted_scopes: vec!["read".to_owned()],
                has_client_secret: false,
                has_refresh_token: true,
                access_expires_at: None,
                authorized_at: Some(1),
                last_refreshed_at: None,
                error_code: None,
            },
            managed_oauth_eligible: false,
        })
        .expect("connection serializes");
        assert_eq!(value["managedOAuthEligible"], false);
        assert!(value.get("managedOauthEligible").is_none());
    }
}
