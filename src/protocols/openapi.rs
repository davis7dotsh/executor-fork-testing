use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{
    Method,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

use super::{
    ConfiguredCredential, CredentialMetadata, ProtocolError, ProtocolErrorCategory,
    ProtocolExecutionResponse, ProtocolHttpMetadata, ProtocolInvocationError,
    ProtocolResponseError, protocol_catalog_error, protocol_outbound_error,
};
use crate::{
    catalog::{
        ArtifactKind, AuditContext, CatalogSnapshot, CatalogStore, CatalogSyncResult, CreateSource,
        CredentialPayload, InitialCatalogSnapshot, SourceKind, SourceRecord, StagedArtifact,
        StagedTool, StagedToolBinding, StoredCredential, ToolBinding,
    },
    openapi::{
        CompiledOpenApi, OpenApiBinding, OpenApiCredentialSet, OpenApiError,
        OpenApiInvocationError, OpenApiOAuthFlows, OpenApiParameterLocation,
        OpenApiSecurityRequirement, OpenApiSecurityScheme, build_protocol_request_with_base,
        compile_document,
    },
    outbound::{HardenedHttpClient, OutboundPolicy, OutboundRequest, parse_url},
};

const MAX_SPEC_BYTES: usize = 16 * 1024 * 1024;
const OPENAPI_CREDENTIAL_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OpenApiSpecInput {
    Inline { content: String },
    Url { url: String },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateOpenApiSource {
    pub display_name: String,
    pub preferred_slug: Option<String>,
    pub description: Option<String>,
    pub spec: OpenApiSpecInput,
    #[serde(default)]
    pub allow_private_network: bool,
    #[serde(default)]
    pub credential: OpenApiCredentialSet,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiPreview {
    pub title: String,
    pub description: Option<String>,
    pub tool_count: usize,
    pub tools: Vec<OpenApiPreviewTool>,
    pub security_schemes: Vec<OpenApiPreviewSecurityScheme>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiPreviewTool {
    pub preferred_name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub intrinsic_mode: crate::catalog::ToolMode,
    pub security: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiPreviewSecurityScheme {
    pub name: String,
    pub credential_type: &'static str,
    pub placement: Option<&'static str>,
    pub supported: bool,
    pub oauth_flows: Option<OpenApiOAuthFlows>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum StoredOpenApiSpecV1 {
    Inline,
    Url { display_url: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenApiSourceConfigurationV1 {
    spec: StoredOpenApiSpecV1,
    allow_private_network: bool,
}

impl OpenApiSourceConfigurationV1 {
    fn decode(configuration: &Map<String, Value>) -> Result<Self, ProtocolError> {
        let decoded: Self =
            serde_json::from_value(Value::Object(configuration.clone())).map_err(|_| {
                ProtocolError::corrupt(
                    "invalid_source_configuration",
                    "The stored OpenAPI source configuration is invalid.",
                )
            })?;
        if let StoredOpenApiSpecV1::Url { display_url } = &decoded.spec {
            require_http_url(display_url).map_err(|_| {
                ProtocolError::corrupt(
                    "invalid_source_configuration",
                    "The stored OpenAPI source configuration is invalid.",
                )
            })?;
        }
        Ok(decoded)
    }

    fn encode(&self) -> Result<Map<String, Value>, ProtocolError> {
        serde_json::to_value(self)
            .map_err(internal_encoding_error)?
            .as_object()
            .cloned()
            .ok_or_else(|| {
                internal_encoding_error(serde_json::Error::io(std::io::Error::other(
                    "OpenAPI source configuration did not encode as an object",
                )))
            })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum StoredOpenApiLocatorV1 {
    Inline,
    Url {
        url: String,
        document_base_url: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredOpenApiCredentialV1 {
    locator: StoredOpenApiLocatorV1,
    credentials: OpenApiCredentialSet,
}

impl StoredOpenApiCredentialV1 {
    fn decode(stored: &StoredCredential) -> Result<Self, ProtocolError> {
        if stored.credential.schema_version != OPENAPI_CREDENTIAL_SCHEMA_VERSION {
            return Err(ProtocolError::corrupt(
                "unsupported_credential_schema",
                "The stored OpenAPI credential schema is not supported.",
            ));
        }
        let decoded: Self =
            serde_json::from_value(stored.credential.payload.clone()).map_err(|_| {
                ProtocolError::corrupt(
                    "invalid_source_credentials",
                    "The stored OpenAPI credential state is invalid.",
                )
            })?;
        decoded.validate_stored()?;
        Ok(decoded)
    }

    fn validate_stored(&self) -> Result<(), ProtocolError> {
        self.credentials.validate().map_err(|_| {
            ProtocolError::corrupt(
                "invalid_source_credentials",
                "The stored OpenAPI credential state is invalid.",
            )
        })?;
        if let StoredOpenApiLocatorV1::Url {
            url,
            document_base_url,
        } = &self.locator
        {
            require_http_url(url).map_err(|_| {
                ProtocolError::corrupt(
                    "invalid_source_credentials",
                    "The stored OpenAPI credential state is invalid.",
                )
            })?;
            require_http_url(document_base_url).map_err(|_| {
                ProtocolError::corrupt(
                    "invalid_source_credentials",
                    "The stored OpenAPI credential state is invalid.",
                )
            })?;
        }
        Ok(())
    }

    fn decode_for_invocation(stored: &StoredCredential) -> Result<Self, ProtocolError> {
        if stored.credential.schema_version != OPENAPI_CREDENTIAL_SCHEMA_VERSION {
            return Err(ProtocolError::new(
                ProtocolErrorCategory::InvalidInput,
                "unsupported_credential_schema",
                "The stored OpenAPI credential schema is not supported.",
            ));
        }
        Self::decode(stored)
    }

    fn payload(&self) -> Result<CredentialPayload, ProtocolError> {
        Ok(CredentialPayload {
            schema_version: OPENAPI_CREDENTIAL_SCHEMA_VERSION,
            payload: serde_json::to_value(self).map_err(internal_encoding_error)?,
        })
    }
}

pub(super) struct PreparedOpenApiInvocation {
    request: OutboundRequest,
    policy: OutboundPolicy,
}

#[derive(Clone, Default)]
pub struct OpenApiAdapter;

impl OpenApiAdapter {
    pub(super) fn prepare_invocation(
        &self,
        binding: &OpenApiBinding,
        source_configuration: &Map<String, Value>,
        stored: Option<&StoredCredential>,
        arguments: &Value,
    ) -> Result<PreparedOpenApiInvocation, ProtocolError> {
        self.plan_invocation(binding, source_configuration, stored, arguments)
    }

    pub(super) async fn execute_invocation(
        &self,
        prepared: PreparedOpenApiInvocation,
    ) -> Result<ProtocolExecutionResponse, ProtocolInvocationError> {
        let response = HardenedHttpClient::new(prepared.policy)
            .execute(prepared.request)
            .await
            .map_err(ProtocolInvocationError::Outbound)?;
        let succeeded = response.status.is_success();
        let data = response_data(&response.headers, &response.body);
        Ok(ProtocolExecutionResponse {
            ok: succeeded,
            data: succeeded.then_some(data),
            error: (!succeeded).then_some(ProtocolResponseError {
                code: "upstream_http_error".to_owned(),
                message: "The upstream API returned an error response.".to_owned(),
            }),
            http: Some(ProtocolHttpMetadata {
                status: response.status.as_u16(),
                headers: safe_response_headers(&response.headers),
                truncated: false,
            }),
        })
    }

    pub async fn preview(
        &self,
        spec: &OpenApiSpecInput,
        allow_private_network: bool,
    ) -> Result<OpenApiPreview, ProtocolError> {
        let fetched = fetch_and_compile(spec, allow_private_network).await?;
        Ok(preview_response(fetched.compiled))
    }

    pub async fn create_source(
        &self,
        catalog: &CatalogStore,
        input: CreateOpenApiSource,
        audit: AuditContext<'_>,
    ) -> Result<SourceRecord, ProtocolError> {
        validate_input_credentials(&input.credential)?;
        let fetched = fetch_and_compile(&input.spec, input.allow_private_network).await?;
        let configuration = source_configuration(&input.spec, input.allow_private_network)?;
        let preferred_slug = input
            .preferred_slug
            .unwrap_or_else(|| input.display_name.clone());
        let credential = StoredOpenApiCredentialV1 {
            locator: fetched.locator,
            credentials: input.credential,
        };
        let snapshot = initial_catalog_snapshot(&fetched.compiled);
        let bindings = staged_bindings(&fetched.compiled);
        let (source, _) = catalog
            .create_source_with_catalog(
                CreateSource {
                    kind: SourceKind::Openapi,
                    preferred_slug,
                    display_name: input.display_name,
                    description: input.description,
                    configuration,
                },
                &credential.payload()?,
                snapshot,
                bindings,
                audit,
            )
            .await
            .map_err(protocol_catalog_error)?;
        Ok(source)
    }

    pub async fn refresh_source(
        &self,
        catalog: &CatalogStore,
        source: SourceRecord,
        audit: AuditContext<'_>,
    ) -> Result<CatalogSyncResult, ProtocolError> {
        if source.kind != SourceKind::Openapi {
            return Err(ProtocolError::corrupt(
                "source_protocol_mismatch",
                "The stored source does not match the OpenAPI protocol.",
            ));
        }
        let configuration = OpenApiSourceConfigurationV1::decode(&source.configuration)?;
        let stored = required_stored_credential(catalog, &source.id).await?;
        let credential = StoredOpenApiCredentialV1::decode(&stored)?;
        let fetched = match &credential.locator {
            StoredOpenApiLocatorV1::Inline => {
                let document = sqlx::query_scalar::<_, String>(
                    "SELECT content_json FROM source_artifacts WHERE source_id = ? \
                     AND artifact_kind = 'openapi_document' AND stable_key = 'document'",
                )
                .bind(&source.id)
                .fetch_optional(catalog.pool())
                .await
                .map_err(|_| internal_storage_error())?
                .ok_or_else(|| {
                    ProtocolError::new(
                        ProtocolErrorCategory::Conflict,
                        "source_artifact_missing",
                        "The source has no OpenAPI document to refresh.",
                    )
                })?;
                FetchedSpec {
                    compiled: compile_bytes(document.into_bytes()).await?,
                    locator: StoredOpenApiLocatorV1::Inline,
                }
            }
            StoredOpenApiLocatorV1::Url { url, .. } => {
                fetch_url(url, configuration.allow_private_network).await?
            }
        };
        let snapshot = catalog_snapshot(&fetched.compiled, source.revision, stored.revision);
        catalog
            .sync_catalog_with_bindings(
                &source.id,
                snapshot,
                staged_bindings(&fetched.compiled),
                audit,
            )
            .await
            .map_err(protocol_catalog_error)
    }

    pub async fn credential_metadata(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let stored = required_stored_credential(catalog, source_id).await?;
        let credential = StoredOpenApiCredentialV1::decode(&stored)?;
        Ok(credential_metadata(stored.revision, credential))
    }

    pub async fn replace_credentials(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        expected_revision: i64,
        credential_set: OpenApiCredentialSet,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        validate_input_credentials(&credential_set)?;
        let stored = required_stored_credential(catalog, source_id).await?;
        if expected_revision != stored.revision {
            return Err(revision_conflict());
        }
        let mut credential = StoredOpenApiCredentialV1::decode(&stored)?;
        credential.credentials = credential_set;
        catalog
            .put_credential(
                source_id,
                &credential.payload()?,
                Some(stored.revision),
                audit,
            )
            .await
            .map_err(protocol_catalog_error)?;
        self.credential_metadata(catalog, source_id).await
    }

    pub async fn clear_credentials(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        expected_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let stored = required_stored_credential(catalog, source_id).await?;
        if expected_revision != stored.revision {
            return Err(revision_conflict());
        }
        let mut credential = StoredOpenApiCredentialV1::decode(&stored)?;
        credential.credentials = OpenApiCredentialSet::default();
        catalog
            .put_credential(
                source_id,
                &credential.payload()?,
                Some(stored.revision),
                audit,
            )
            .await
            .map_err(protocol_catalog_error)?;
        self.credential_metadata(catalog, source_id).await
    }

    fn plan_invocation(
        &self,
        binding: &OpenApiBinding,
        source_configuration: &Map<String, Value>,
        stored: Option<&StoredCredential>,
        arguments: &Value,
    ) -> Result<PreparedOpenApiInvocation, ProtocolError> {
        if binding.version != 1 {
            return Err(ProtocolError::corrupt(
                "unsupported_binding_schema",
                "The stored OpenAPI tool binding schema is not supported.",
            ));
        }
        let configuration = OpenApiSourceConfigurationV1::decode(source_configuration)?;
        let stored = stored.ok_or_else(|| {
            ProtocolError::corrupt(
                "source_credentials_missing",
                "The source credential state is missing.",
            )
        })?;
        let credential = StoredOpenApiCredentialV1::decode_for_invocation(stored)?;
        let document_base_url = match &credential.locator {
            StoredOpenApiLocatorV1::Inline => None,
            StoredOpenApiLocatorV1::Url {
                document_base_url, ..
            } => Some(require_http_url(document_base_url).map_err(|_| {
                ProtocolError::corrupt(
                    "invalid_source_credentials",
                    "The stored OpenAPI credential state is invalid.",
                )
            })?),
        };
        let protocol_request = build_protocol_request_with_base(
            binding,
            arguments,
            &credential.credentials,
            document_base_url.as_ref(),
        )
        .map_err(invocation_error)?;
        let method = Method::from_bytes(protocol_request.method.as_bytes()).map_err(|_| {
            ProtocolError::corrupt(
                "invalid_tool_binding",
                "The stored OpenAPI tool binding is invalid.",
            )
        })?;
        let mut request = OutboundRequest::new(method, protocol_request.url);
        for (name, value) in protocol_request.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                ProtocolError::corrupt(
                    "invalid_tool_binding",
                    "The stored OpenAPI tool binding is invalid.",
                )
            })?;
            let value = HeaderValue::from_str(&value).map_err(|_| {
                ProtocolError::new(
                    ProtocolErrorCategory::InvalidInput,
                    "invalid_tool_arguments",
                    "The tool arguments are invalid.",
                )
            })?;
            request.headers.insert(name, value);
        }
        request.body = protocol_request.body;
        Ok(PreparedOpenApiInvocation {
            request,
            policy: OutboundPolicy {
                allow_private_networks: configuration.allow_private_network,
                ..OutboundPolicy::default()
            },
        })
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

struct FetchedSpec {
    compiled: CompiledOpenApi,
    locator: StoredOpenApiLocatorV1,
}

async fn fetch_and_compile(
    spec: &OpenApiSpecInput,
    allow_private_network: bool,
) -> Result<FetchedSpec, ProtocolError> {
    match spec {
        OpenApiSpecInput::Inline { content } => {
            if content.len() > MAX_SPEC_BYTES {
                return Err(ProtocolError::new(
                    ProtocolErrorCategory::InvalidInput,
                    "openapi_document_too_large",
                    "The OpenAPI document exceeds the allowed size.",
                ));
            }
            let compiled = compile_bytes(content.as_bytes().to_vec()).await?;
            if compiled
                .tools
                .iter()
                .any(|tool| require_http_url(&tool.binding.server_url).is_err())
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCategory::InvalidInput,
                    "inline_openapi_server_required",
                    "Inline OpenAPI documents must define an absolute HTTP or HTTPS server URL.",
                ));
            }
            Ok(FetchedSpec {
                compiled,
                locator: StoredOpenApiLocatorV1::Inline,
            })
        }
        OpenApiSpecInput::Url { url } => fetch_url(url, allow_private_network).await,
    }
}

async fn fetch_url(url: &str, allow_private_network: bool) -> Result<FetchedSpec, ProtocolError> {
    let policy = OutboundPolicy {
        allow_private_networks: allow_private_network,
        max_response_bytes: MAX_SPEC_BYTES,
        ..OutboundPolicy::default()
    };
    let url = parse_url(url, &policy).map_err(protocol_outbound_error)?;
    let response = HardenedHttpClient::new(policy)
        .fetch_spec(url.clone(), HeaderMap::new())
        .await
        .map_err(protocol_outbound_error)?;
    let mut compiled = compile_bytes(response.body).await?;
    for tool in &mut compiled.tools {
        tool.binding.server_url = response
            .final_url
            .join(&tool.binding.server_url)
            .map_err(|_| {
                ProtocolError::new(
                    ProtocolErrorCategory::InvalidInput,
                    "invalid_openapi_document",
                    "The OpenAPI document contains an invalid server URL.",
                )
            })?
            .to_string();
    }
    Ok(FetchedSpec {
        compiled,
        locator: StoredOpenApiLocatorV1::Url {
            url: url.to_string(),
            document_base_url: response.final_url.to_string(),
        },
    })
}

async fn compile_bytes(bytes: Vec<u8>) -> Result<CompiledOpenApi, ProtocolError> {
    tokio::task::spawn_blocking(move || compile_document(&bytes))
        .await
        .map_err(|_| internal_compile_error())?
        .map_err(openapi_error)
}

fn source_configuration(
    spec: &OpenApiSpecInput,
    allow_private_network: bool,
) -> Result<Map<String, Value>, ProtocolError> {
    let spec = match spec {
        OpenApiSpecInput::Inline { .. } => StoredOpenApiSpecV1::Inline,
        OpenApiSpecInput::Url { url } => {
            let mut display = require_http_url(url).map_err(protocol_outbound_error)?;
            display.set_query(None);
            StoredOpenApiSpecV1::Url {
                display_url: display.to_string(),
            }
        }
    };
    OpenApiSourceConfigurationV1 {
        spec,
        allow_private_network,
    }
    .encode()
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

fn preview_response(compiled: CompiledOpenApi) -> OpenApiPreview {
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
    OpenApiPreview {
        title: compiled.title,
        description: compiled.description,
        tool_count,
        tools: compiled
            .tools
            .into_iter()
            .map(|tool| OpenApiPreviewTool {
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
    requirement: &OpenApiSecurityRequirement,
) -> OpenApiPreviewSecurityScheme {
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
        OpenApiSecurityScheme::OAuth2 | OpenApiSecurityScheme::OpenIdConnect { .. } => {
            ("manual_oauth_access_token", Some("header"), true)
        }
        OpenApiSecurityScheme::MutualTls => ("mutual_tls", None, false),
    };
    OpenApiPreviewSecurityScheme {
        name: requirement.scheme_name.clone(),
        credential_type,
        placement,
        supported,
        oauth_flows: requirement.oauth_flows.clone(),
    }
}

async fn required_stored_credential(
    catalog: &CatalogStore,
    source_id: &str,
) -> Result<StoredCredential, ProtocolError> {
    catalog
        .credential(source_id)
        .await
        .map_err(protocol_catalog_error)?
        .ok_or_else(|| {
            ProtocolError::corrupt(
                "source_credentials_missing",
                "The source credential state is missing.",
            )
        })
}

fn credential_metadata(revision: i64, stored: StoredOpenApiCredentialV1) -> CredentialMetadata {
    CredentialMetadata {
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
    }
}

fn validate_input_credentials(credentials: &OpenApiCredentialSet) -> Result<(), ProtocolError> {
    credentials.validate().map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "invalid_credentials",
            "The static credential configuration is invalid.",
        )
    })
}

fn invocation_error(error: OpenApiInvocationError) -> ProtocolError {
    match error {
        OpenApiInvocationError::InvalidArguments | OpenApiInvocationError::InvalidArgument(_) => {
            ProtocolError::new(
                ProtocolErrorCategory::InvalidInput,
                "invalid_tool_arguments",
                "The tool arguments are invalid.",
            )
        }
        OpenApiInvocationError::MissingArgument(_) => ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "missing_tool_argument",
            "A required tool argument is missing.",
        ),
        OpenApiInvocationError::UnsatisfiedSecurity => ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "missing_source_credentials",
            "No configured credential satisfies this operation.",
        ),
        OpenApiInvocationError::InvalidCredential(_) => ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "unsupported_authentication",
            "This operation requires an authentication method that is not configured.",
        ),
        OpenApiInvocationError::InvalidCredentialConfiguration => ProtocolError::corrupt(
            "invalid_source_credentials",
            "The stored OpenAPI credential state is invalid.",
        ),
        OpenApiInvocationError::InvalidHeader(_) => ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "forbidden_tool_header",
            "Tool arguments cannot set a protected HTTP header.",
        ),
        OpenApiInvocationError::InvalidUrl => ProtocolError::corrupt(
            "invalid_openapi_server",
            "The OpenAPI operation has no usable server URL.",
        ),
    }
}

fn openapi_error(error: OpenApiError) -> ProtocolError {
    let code = match &error {
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
    };
    ProtocolError::new(ProtocolErrorCategory::InvalidInput, code, error.to_string())
}

fn require_http_url(value: &str) -> Result<Url, crate::outbound::OutboundError> {
    let url = Url::parse(value).map_err(|_| crate::outbound::OutboundError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(crate::outbound::OutboundError::UnsupportedScheme);
    }
    if url.host().is_none() {
        return Err(crate::outbound::OutboundError::MissingHost);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(crate::outbound::OutboundError::CredentialsNotAllowed);
    }
    if url.fragment().is_some() {
        return Err(crate::outbound::OutboundError::FragmentNotAllowed);
    }
    Ok(url)
}

fn revision_conflict() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        "revision_conflict",
        "The source changed. Refresh and retry the update.",
    )
}

fn internal_storage_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Internal,
        "internal_error",
        "The protocol operation could not be completed.",
    )
}

fn internal_compile_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Internal,
        "openapi_compiler_failed",
        "The OpenAPI document could not be compiled.",
    )
}

fn internal_encoding_error(_error: serde_json::Error) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Internal,
        "internal_error",
        "The protocol operation could not be completed.",
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use reqwest::header::{
        AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderMap, HeaderValue, RETRY_AFTER,
        SET_COOKIE,
    };
    use serde_json::json;

    use super::{
        OpenApiSourceConfigurationV1, StoredOpenApiCredentialV1, response_data,
        safe_response_headers,
    };
    use crate::{
        catalog::{CredentialPayload, StoredCredential},
        protocols::ProtocolErrorCategory,
    };

    #[test]
    fn malformed_source_configuration_is_corrupt_data() {
        let malformed = json!({
            "spec": { "type": "inline" },
            "allowPrivateNetwork": "yes"
        })
        .as_object()
        .expect("test configuration is an object")
        .clone();
        let error = OpenApiSourceConfigurationV1::decode(&malformed)
            .expect_err("malformed stored configuration fails closed");
        assert_eq!(error.code, "invalid_source_configuration");
        assert_eq!(error.category, ProtocolErrorCategory::CorruptData);
    }

    #[test]
    fn incomplete_source_configuration_is_corrupt_data() {
        let incomplete = json!({ "spec": { "type": "inline" } })
            .as_object()
            .expect("test configuration is an object")
            .clone();
        let error = OpenApiSourceConfigurationV1::decode(&incomplete)
            .expect_err("incomplete stored configuration fails closed");
        assert_eq!(error.code, "invalid_source_configuration");
        assert_eq!(error.category, ProtocolErrorCategory::CorruptData);
    }

    #[test]
    fn malformed_stored_credentials_are_corrupt_data() {
        let stored = StoredCredential {
            revision: 4,
            credential: CredentialPayload {
                schema_version: 1,
                payload: json!({
                    "locator": { "type": "inline" },
                    "credentials": {
                        "schemes": {
                            "oauth": { "type": "oauth_access_token", "access_token": "" }
                        }
                    }
                }),
            },
        };
        let error = StoredOpenApiCredentialV1::decode(&stored)
            .expect_err("invalid persisted credential values fail closed");
        assert_eq!(error.code, "invalid_source_credentials");
        assert_eq!(error.category, ProtocolErrorCategory::CorruptData);
    }

    #[test]
    fn protocol_response_data_preserves_json_text_and_binary_bodies() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert_eq!(
            response_data(&headers, br#"{"ok":true}"#),
            json!({ "ok": true })
        );

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        assert_eq!(
            response_data(&headers, br#"{"title":"problem"}"#),
            json!({ "title": "problem" })
        );

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(response_data(&headers, b"hello"), json!("hello"));
        assert_eq!(
            response_data(&headers, &[0xff, 0x00]),
            json!({ "encoding": "base64", "data": "/wA=" })
        );
    }

    #[test]
    fn protocol_response_headers_use_the_existing_safe_allowlist() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("12"));
        headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("session=secret"));
        headers.insert("x-upstream-secret", HeaderValue::from_static("secret"));

        assert_eq!(
            safe_response_headers(&headers),
            BTreeMap::from([
                ("content-length".to_owned(), "12".to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
                ("retry-after".to_owned(), "5".to_owned()),
            ])
        );
    }
}
