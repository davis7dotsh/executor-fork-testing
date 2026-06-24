use std::collections::BTreeMap;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, Query, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    routing::{get, post},
};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

use super::{
    AdminMutation, ApiError, AppState, RequestId, parse_json, protocols::InvocationAdapterError,
    require_admin, require_admin_mutation,
};
use crate::{
    catalog::{
        ArtifactKind, AuditContext, CatalogError, CatalogSnapshot, CreateSource, CredentialPayload,
        InitialCatalogSnapshot, SourceKind, StagedArtifact, StagedTool, StagedToolBinding,
        StoredCredential, ToolBinding,
    },
    openapi::{
        CompiledOpenApi, OpenApiBinding, OpenApiCredentialSet, OpenApiError,
        OpenApiInvocationError, OpenApiParameterLocation, OpenApiSecurityScheme,
        build_protocol_request_with_base, compile_document,
    },
    outbound::{HardenedHttpClient, OutboundError, OutboundPolicy, OutboundRequest, parse_url},
};

const MAX_SPEC_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/sources/openapi/preview", post(preview))
        .layer(DefaultBodyLimit::max(MAX_SPEC_BYTES + 64 * 1024))
        .merge(
            Router::new()
                .route("/api/v1/sources/{id}/refresh", post(refresh_source))
                .route(
                    "/api/v1/sources/{id}/credentials",
                    get(get_credentials)
                        .put(put_credentials)
                        .delete(delete_credentials),
                ),
        )
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OpenApiSpecInput {
    Inline { content: String },
    Url { url: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreviewRequest {
    spec: OpenApiSpecInput,
    #[serde(default)]
    allow_private_network: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewResponse {
    title: String,
    description: Option<String>,
    tool_count: usize,
    tools: Vec<PreviewTool>,
    security_schemes: Vec<PreviewSecurityScheme>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewTool {
    preferred_name: String,
    display_name: String,
    description: Option<String>,
    intrinsic_mode: crate::catalog::ToolMode,
    security: Vec<Vec<String>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreviewSecurityScheme {
    name: String,
    credential_type: &'static str,
    placement: Option<&'static str>,
    supported: bool,
    oauth_flows: Option<crate::openapi::OpenApiOAuthFlows>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateOpenApiSourceRequest {
    display_name: String,
    preferred_slug: Option<String>,
    description: Option<String>,
    spec: OpenApiSpecInput,
    #[serde(default)]
    allow_private_network: bool,
    #[serde(default)]
    credential: OpenApiCredentialSet,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
enum StoredLocator {
    Inline,
    Url {
        url: String,
        document_base_url: String,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StoredOpenApiCredential {
    locator: StoredLocator,
    credentials: OpenApiCredentialSet,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutCredentialsRequest {
    expected_revision: Option<i64>,
    credential: OpenApiCredentialSet,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteCredentialsQuery {
    expected_revision: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialMetadata {
    revision: i64,
    configured_schemes: Vec<ConfiguredCredential>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfiguredCredential {
    name: String,
    credential_type: &'static str,
}

async fn get_credentials(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(source_id): Path<String>,
) -> Result<Json<CredentialMetadata>, ApiError> {
    require_admin(&request_id, &state, &headers).await?;
    require_openapi_source(&state, &request_id, &source_id).await?;
    credential_metadata(&state, &request_id, &source_id).await
}

async fn preview(
    Extension(request_id): Extension<RequestId>,
    AdminMutation(_admin_id): AdminMutation,
    payload: Result<Json<PreviewRequest>, JsonRejection>,
) -> Result<Json<PreviewResponse>, ApiError> {
    let Json(payload) = parse_json(&request_id, payload)?;
    let fetched = fetch_and_compile(&payload.spec, payload.allow_private_network)
        .await
        .map_err(|error| import_error(&request_id, error))?;
    Ok(Json(preview_response(fetched.compiled)))
}

pub(super) async fn create_source(
    state: &AppState,
    request_id: &RequestId,
    admin_id: i64,
    payload: CreateOpenApiSourceRequest,
) -> Result<crate::catalog::SourceRecord, ApiError> {
    validate_credentials(request_id, &payload.credential)?;
    let fetched = fetch_and_compile(&payload.spec, payload.allow_private_network)
        .await
        .map_err(|error| import_error(request_id, error))?;
    let configuration = source_configuration(&payload.spec, payload.allow_private_network)
        .map_err(|error| import_error(request_id, error))?;
    let preferred_slug = payload
        .preferred_slug
        .unwrap_or_else(|| payload.display_name.clone());
    let audit = AuditContext::admin(&request_id.0, admin_id);
    let credential = StoredOpenApiCredential {
        locator: fetched.locator,
        credentials: payload.credential,
    };
    let snapshot = initial_catalog_snapshot(&fetched.compiled);
    let bindings = staged_bindings(&fetched.compiled);
    let (source, _) = state
        .catalog
        .create_source_with_catalog(
            CreateSource {
                kind: SourceKind::Openapi,
                preferred_slug,
                display_name: payload.display_name,
                description: payload.description,
                configuration,
            },
            &credential_payload(&credential)
                .map_err(|error| ApiError::internal_logged(request_id, error))?,
            snapshot,
            bindings,
            audit,
        )
        .await
        .map_err(|error| catalog_error(request_id, error))?;
    Ok(source)
}

async fn refresh_source(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(source_id): Path<String>,
) -> Result<Json<crate::catalog::CatalogSyncResult>, ApiError> {
    let admin = require_admin_mutation(&request_id, &state, &headers).await?;
    let source = require_openapi_source(&state, &request_id, &source_id).await?;
    let stored = stored_credential(&state, &request_id, &source_id).await?;
    let allow_private_network = source
        .configuration
        .get("allowPrivateNetwork")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let fetched = match &stored.1.locator {
        StoredLocator::Inline => {
            let document = sqlx::query_scalar::<_, String>(
                "SELECT content_json FROM source_artifacts WHERE source_id = ? \
                 AND artifact_kind = 'openapi_document' AND stable_key = 'document'",
            )
            .bind(&source_id)
            .fetch_optional(state.catalog.pool())
            .await
            .map_err(|error| ApiError::internal_logged(&request_id, error))?
            .ok_or_else(|| {
                ApiError::new(
                    &request_id,
                    StatusCode::CONFLICT,
                    "source_artifact_missing",
                    "The source has no OpenAPI document to refresh.",
                )
            })?;
            FetchedSpec {
                compiled: compile_bytes(document.into_bytes())
                    .await
                    .map_err(|error| import_error(&request_id, error))?,
                locator: StoredLocator::Inline,
            }
        }
        StoredLocator::Url { url, .. } => fetch_url(url, allow_private_network)
            .await
            .map_err(|error| import_error(&request_id, error))?,
    };
    let result = import_compiled(
        &state,
        &source_id,
        source.revision,
        stored.0,
        fetched.compiled,
        AuditContext::admin(&request_id.0, admin.id),
    )
    .await?;
    Ok(Json(result))
}

async fn put_credentials(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    Path(source_id): Path<String>,
    AdminMutation(admin_id): AdminMutation,
    payload: Result<Json<PutCredentialsRequest>, JsonRejection>,
) -> Result<Json<CredentialMetadata>, ApiError> {
    let Json(payload) = parse_json(&request_id, payload)?;
    require_openapi_source(&state, &request_id, &source_id).await?;
    validate_credentials(&request_id, &payload.credential)?;
    let (revision, mut stored) = stored_credential(&state, &request_id, &source_id).await?;
    if payload.expected_revision != Some(revision) {
        return Err(revision_conflict(&request_id));
    }
    stored.credentials = payload.credential;
    state
        .catalog
        .put_credential(
            &source_id,
            &credential_payload(&stored)
                .map_err(|error| ApiError::internal_logged(&request_id, error))?,
            Some(revision),
            AuditContext::admin(&request_id.0, admin_id),
        )
        .await
        .map_err(|error| catalog_error(&request_id, error))?;
    credential_metadata(&state, &request_id, &source_id).await
}

async fn delete_credentials(
    Extension(request_id): Extension<RequestId>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(source_id): Path<String>,
    Query(query): Query<DeleteCredentialsQuery>,
) -> Result<Json<CredentialMetadata>, ApiError> {
    let admin = require_admin_mutation(&request_id, &state, &headers).await?;
    require_openapi_source(&state, &request_id, &source_id).await?;
    let (revision, mut stored) = stored_credential(&state, &request_id, &source_id).await?;
    if query.expected_revision != revision {
        return Err(revision_conflict(&request_id));
    }
    stored.credentials = OpenApiCredentialSet::default();
    state
        .catalog
        .put_credential(
            &source_id,
            &credential_payload(&stored)
                .map_err(|error| ApiError::internal_logged(&request_id, error))?,
            Some(revision),
            AuditContext::admin(&request_id.0, admin.id),
        )
        .await
        .map_err(|error| catalog_error(&request_id, error))?;
    credential_metadata(&state, &request_id, &source_id).await
}

struct FetchedSpec {
    compiled: CompiledOpenApi,
    locator: StoredLocator,
}

#[derive(Debug)]
enum ImportError {
    OpenApi(OpenApiError),
    Outbound(OutboundError),
    TooLarge,
    InlineServerRequired,
}

async fn fetch_and_compile(
    spec: &OpenApiSpecInput,
    allow_private_network: bool,
) -> Result<FetchedSpec, ImportError> {
    match spec {
        OpenApiSpecInput::Inline { content } => {
            if content.len() > MAX_SPEC_BYTES {
                return Err(ImportError::TooLarge);
            }
            let compiled = compile_bytes(content.as_bytes().to_vec()).await?;
            if compiled
                .tools
                .iter()
                .any(|tool| Url::parse(&tool.binding.server_url).is_err())
            {
                return Err(ImportError::InlineServerRequired);
            }
            Ok(FetchedSpec {
                compiled,
                locator: StoredLocator::Inline,
            })
        }
        OpenApiSpecInput::Url { url } => fetch_url(url, allow_private_network).await,
    }
}

async fn fetch_url(url: &str, allow_private_network: bool) -> Result<FetchedSpec, ImportError> {
    let policy = OutboundPolicy {
        allow_private_networks: allow_private_network,
        max_response_bytes: MAX_SPEC_BYTES,
        ..OutboundPolicy::default()
    };
    let url = parse_url(url, &policy).map_err(ImportError::Outbound)?;
    let response = HardenedHttpClient::new(policy)
        .fetch_spec(url.clone(), HeaderMap::new())
        .await
        .map_err(ImportError::Outbound)?;
    let mut compiled = compile_bytes(response.body).await?;
    for tool in &mut compiled.tools {
        tool.binding.server_url = response
            .final_url
            .join(&tool.binding.server_url)
            .map_err(|_| {
                ImportError::OpenApi(OpenApiError::InvalidDocument("a server URL is invalid"))
            })?
            .to_string();
    }
    Ok(FetchedSpec {
        compiled,
        locator: StoredLocator::Url {
            url: url.to_string(),
            document_base_url: response.final_url.to_string(),
        },
    })
}

async fn compile_bytes(bytes: Vec<u8>) -> Result<CompiledOpenApi, ImportError> {
    tokio::task::spawn_blocking(move || compile_document(&bytes))
        .await
        .map_err(|_| {
            ImportError::OpenApi(OpenApiError::InvalidDocument("OpenAPI compilation failed"))
        })?
        .map_err(ImportError::OpenApi)
}

async fn import_compiled(
    state: &AppState,
    source_id: &str,
    source_revision: i64,
    credential_revision: i64,
    compiled: CompiledOpenApi,
    audit: AuditContext<'_>,
) -> Result<crate::catalog::CatalogSyncResult, ApiError> {
    let request_id = RequestId(audit.request_id().unwrap_or("openapi-import").to_owned());
    let snapshot = catalog_snapshot(&compiled, source_revision, credential_revision);
    let bindings = staged_bindings(&compiled);
    let result = state
        .catalog
        .sync_catalog_with_bindings(source_id, snapshot, bindings, audit)
        .await
        .map_err(|error| catalog_error(&request_id, error))?;
    Ok(result)
}

fn initial_catalog_snapshot(compiled: &CompiledOpenApi) -> InitialCatalogSnapshot {
    InitialCatalogSnapshot {
        artifacts: staged_artifacts(compiled),
        tools: staged_tools(compiled),
    }
}

fn catalog_snapshot(
    compiled: &CompiledOpenApi,
    source_revision: i64,
    credential_revision: i64,
) -> CatalogSnapshot {
    CatalogSnapshot {
        expected_source_revision: source_revision,
        expected_credential_revision: Some(credential_revision),
        artifacts: staged_artifacts(compiled),
        tools: staged_tools(compiled),
    }
}

fn staged_tools(compiled: &CompiledOpenApi) -> Vec<StagedTool> {
    compiled
        .tools
        .iter()
        .map(|tool| StagedTool {
            stable_key: tool.stable_key.clone(),
            preferred_name: tool.preferred_name.clone(),
            display_name: tool.display_name.clone(),
            description: tool.description.clone(),
            input_schema: tool.input_schema.clone(),
            output_schema: tool.output_schema.clone(),
            input_typescript: None,
            output_typescript: None,
            typescript_definitions: BTreeMap::new(),
            intrinsic_mode: tool.intrinsic_mode,
        })
        .collect()
}

fn staged_bindings(compiled: &CompiledOpenApi) -> Vec<StagedToolBinding> {
    compiled
        .tools
        .iter()
        .map(|tool| StagedToolBinding {
            stable_key: tool.stable_key.clone(),
            binding: ToolBinding::OpenapiV1(tool.binding.clone()),
        })
        .collect()
}

fn staged_artifacts(compiled: &CompiledOpenApi) -> Vec<StagedArtifact> {
    vec![StagedArtifact {
        kind: ArtifactKind::OpenapiDocument,
        stable_key: "document".to_owned(),
        content: compiled.document.clone(),
    }]
}

fn preview_response(compiled: CompiledOpenApi) -> PreviewResponse {
    let tool_count = compiled.tools.len();
    let mut security_schemes = BTreeMap::new();
    for tool in &compiled.tools {
        for alternative in &tool.binding.security {
            for requirement in &alternative.requirements {
                security_schemes
                    .entry(requirement.scheme_name.clone())
                    .or_insert_with(|| preview_security_scheme(requirement));
            }
        }
    }
    PreviewResponse {
        title: compiled.title,
        description: compiled.description,
        tool_count,
        tools: compiled
            .tools
            .into_iter()
            .map(|tool| PreviewTool {
                preferred_name: tool.preferred_name,
                display_name: tool.display_name,
                description: tool.description,
                intrinsic_mode: tool.intrinsic_mode,
                security: tool
                    .binding
                    .security
                    .into_iter()
                    .map(|alternative| {
                        alternative
                            .requirements
                            .into_iter()
                            .map(|requirement| requirement.scheme_name)
                            .collect()
                    })
                    .collect(),
            })
            .collect(),
        security_schemes: security_schemes.into_values().collect(),
    }
}

fn preview_security_scheme(
    requirement: &crate::openapi::OpenApiSecurityRequirement,
) -> PreviewSecurityScheme {
    let (credential_type, placement, supported) = match &requirement.scheme {
        OpenApiSecurityScheme::ApiKey { location, .. } => (
            "api_key",
            Some(match location {
                OpenApiParameterLocation::Header => "header",
                OpenApiParameterLocation::Query => "query",
                OpenApiParameterLocation::Cookie => "cookie",
                OpenApiParameterLocation::Path => "path",
            }),
            *location != OpenApiParameterLocation::Path,
        ),
        OpenApiSecurityScheme::Http { scheme, .. } if scheme == "bearer" => {
            ("bearer", Some("header"), true)
        }
        OpenApiSecurityScheme::Http { scheme, .. } if scheme == "basic" => {
            ("basic", Some("header"), true)
        }
        OpenApiSecurityScheme::Http { .. } => ("http", Some("header"), false),
        OpenApiSecurityScheme::OAuth2 => ("manual_oauth_access_token", Some("header"), true),
        OpenApiSecurityScheme::OpenIdConnect { .. } => {
            ("manual_oauth_access_token", Some("header"), true)
        }
        OpenApiSecurityScheme::MutualTls => ("mutual_tls", None, false),
    };
    PreviewSecurityScheme {
        name: requirement.scheme_name.clone(),
        credential_type,
        placement,
        supported,
        oauth_flows: requirement.oauth_flows.clone(),
    }
}

fn source_configuration(
    spec: &OpenApiSpecInput,
    allow_private_network: bool,
) -> Result<Map<String, Value>, ImportError> {
    let spec = match spec {
        OpenApiSpecInput::Inline { .. } => json!({ "type": "inline" }),
        OpenApiSpecInput::Url { url } => {
            let mut display =
                Url::parse(url).map_err(|_| ImportError::Outbound(OutboundError::InvalidUrl))?;
            display.set_query(None);
            json!({ "type": "url", "displayUrl": display.to_string() })
        }
    };
    Ok(Map::from_iter([
        ("spec".to_owned(), spec),
        (
            "allowPrivateNetwork".to_owned(),
            Value::Bool(allow_private_network),
        ),
    ]))
}

fn credential_payload(
    credential: &StoredOpenApiCredential,
) -> Result<CredentialPayload, serde_json::Error> {
    Ok(CredentialPayload {
        schema_version: 1,
        payload: serde_json::to_value(credential)?,
    })
}

async fn require_openapi_source(
    state: &AppState,
    request_id: &RequestId,
    source_id: &str,
) -> Result<crate::catalog::SourceRecord, ApiError> {
    let source = state
        .catalog
        .source(source_id)
        .await
        .map_err(|error| catalog_error(request_id, error))?;
    if source.kind != SourceKind::Openapi {
        return Err(ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "unsupported_source_kind",
            "Only OpenAPI sources can use this endpoint.",
        ));
    }
    Ok(source)
}

async fn stored_credential(
    state: &AppState,
    request_id: &RequestId,
    source_id: &str,
) -> Result<(i64, StoredOpenApiCredential), ApiError> {
    let stored = state
        .catalog
        .credential(source_id)
        .await
        .map_err(|error| catalog_error(request_id, error))?
        .ok_or_else(|| {
            ApiError::new(
                request_id,
                StatusCode::CONFLICT,
                "source_credentials_missing",
                "The source credential state is missing.",
            )
        })?;
    if stored.credential.schema_version != 1 {
        return Err(ApiError::new(
            request_id,
            StatusCode::CONFLICT,
            "unsupported_credential_schema",
            "The stored OpenAPI credential schema is not supported.",
        ));
    }
    let credential = serde_json::from_value(stored.credential.payload)
        .map_err(|error| ApiError::internal_logged(request_id, error))?;
    Ok((stored.revision, credential))
}

async fn credential_metadata(
    state: &AppState,
    request_id: &RequestId,
    source_id: &str,
) -> Result<Json<CredentialMetadata>, ApiError> {
    let (revision, stored) = stored_credential(state, request_id, source_id).await?;
    Ok(Json(CredentialMetadata {
        revision,
        configured_schemes: stored
            .credentials
            .schemes
            .into_iter()
            .map(|(name, credential)| ConfiguredCredential {
                name,
                credential_type: credential.credential_type(),
            })
            .collect(),
    }))
}

fn validate_credentials(
    request_id: &RequestId,
    credentials: &OpenApiCredentialSet,
) -> Result<(), ApiError> {
    credentials.validate().map_err(|_| {
        ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_credentials",
            "The static credential configuration is invalid.",
        )
    })
}

pub(super) struct OpenApiInvocationPlan {
    pub request: OutboundRequest,
    pub policy: OutboundPolicy,
}

pub(super) fn invocation_plan(
    binding: &OpenApiBinding,
    source_configuration: &Map<String, Value>,
    stored: Option<&StoredCredential>,
    arguments: &Value,
) -> Result<OpenApiInvocationPlan, InvocationAdapterError> {
    let stored = stored.ok_or(InvocationAdapterError {
        code: "source_credentials_missing",
        message: "The source credential state is missing.",
    })?;
    if stored.credential.schema_version != 1 {
        return Err(InvocationAdapterError {
            code: "unsupported_credential_schema",
            message: "The stored OpenAPI credential schema is not supported.",
        });
    }
    let credential: StoredOpenApiCredential =
        serde_json::from_value(stored.credential.payload.clone()).map_err(|_| {
            InvocationAdapterError {
                code: "invalid_source_credentials",
                message: "The source credential state is invalid.",
            }
        })?;
    let document_base_url = match &credential.locator {
        StoredLocator::Inline => None,
        StoredLocator::Url {
            document_base_url, ..
        } => Some(
            Url::parse(document_base_url).map_err(|_| InvocationAdapterError {
                code: "invalid_openapi_server",
                message: "The OpenAPI operation has no usable server URL.",
            })?,
        ),
    };
    let protocol_request = build_protocol_request_with_base(
        binding,
        arguments,
        &credential.credentials,
        document_base_url.as_ref(),
    )
    .map_err(invocation_adapter_error)?;
    let method = Method::from_bytes(protocol_request.method.as_bytes()).map_err(|_| {
        InvocationAdapterError {
            code: "invalid_tool_arguments",
            message: "The tool arguments are invalid.",
        }
    })?;
    let mut request = OutboundRequest::new(method, protocol_request.url);
    for (name, value) in protocol_request.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| InvocationAdapterError {
            code: "forbidden_tool_header",
            message: "Tool arguments cannot set a protected HTTP header.",
        })?;
        let value = HeaderValue::from_str(&value).map_err(|_| InvocationAdapterError {
            code: "invalid_tool_arguments",
            message: "The tool arguments are invalid.",
        })?;
        request.headers.insert(name, value);
    }
    request.body = protocol_request.body;
    Ok(OpenApiInvocationPlan {
        request,
        policy: OutboundPolicy {
            allow_private_networks: source_configuration
                .get("allowPrivateNetwork")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            ..OutboundPolicy::default()
        },
    })
}

fn invocation_adapter_error(error: OpenApiInvocationError) -> InvocationAdapterError {
    match error {
        OpenApiInvocationError::InvalidArguments | OpenApiInvocationError::InvalidArgument(_) => {
            InvocationAdapterError {
                code: "invalid_tool_arguments",
                message: "The tool arguments are invalid.",
            }
        }
        OpenApiInvocationError::MissingArgument(_) => InvocationAdapterError {
            code: "missing_tool_argument",
            message: "A required tool argument is missing.",
        },
        OpenApiInvocationError::UnsatisfiedSecurity => InvocationAdapterError {
            code: "missing_source_credentials",
            message: "No configured credential satisfies this operation.",
        },
        OpenApiInvocationError::InvalidCredential(_) => InvocationAdapterError {
            code: "unsupported_authentication",
            message: "This operation requires an authentication method that is not configured.",
        },
        OpenApiInvocationError::InvalidCredentialConfiguration => InvocationAdapterError {
            code: "invalid_source_credentials",
            message: "The source credential state is invalid.",
        },
        OpenApiInvocationError::InvalidHeader(_) => InvocationAdapterError {
            code: "forbidden_tool_header",
            message: "Tool arguments cannot set a protected HTTP header.",
        },
        OpenApiInvocationError::InvalidUrl => InvocationAdapterError {
            code: "invalid_openapi_server",
            message: "The OpenAPI operation has no usable server URL.",
        },
    }
}

fn import_error(request_id: &RequestId, error: ImportError) -> ApiError {
    match error {
        ImportError::OpenApi(error) => ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            openapi_error_code(&error),
            error.to_string(),
        ),
        ImportError::Outbound(error) => outbound_error(request_id, error),
        ImportError::TooLarge => ApiError::new(
            request_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "openapi_document_too_large",
            "The OpenAPI document exceeds the allowed size.",
        ),
        ImportError::InlineServerRequired => ApiError::new(
            request_id,
            StatusCode::BAD_REQUEST,
            "inline_openapi_server_required",
            "Inline OpenAPI documents must define an absolute HTTP or HTTPS server URL.",
        ),
    }
}

fn openapi_error_code(error: &OpenApiError) -> &'static str {
    match error {
        OpenApiError::Parse => "invalid_openapi_document",
        OpenApiError::UnsupportedVersion => "unsupported_openapi_version",
        OpenApiError::ExternalReference(_) => "external_reference_unsupported",
        OpenApiError::ReferenceNotFound(_) => "openapi_reference_not_found",
        OpenApiError::ReferenceCycle(_) => "openapi_reference_cycle",
        OpenApiError::ReferenceDepth => "openapi_reference_depth",
        OpenApiError::LimitExceeded { code } => code,
        OpenApiError::InvalidDocument(_) | OpenApiError::InvalidOperation { .. } => {
            "invalid_openapi_document"
        }
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
        CatalogError::RevisionConflict { .. } => revision_conflict(request_id),
        error => ApiError::internal_logged(request_id, error),
    }
}

fn revision_conflict(request_id: &RequestId) -> ApiError {
    ApiError::new(
        request_id,
        StatusCode::CONFLICT,
        "revision_conflict",
        "The source changed. Refresh and retry the update.",
    )
}
