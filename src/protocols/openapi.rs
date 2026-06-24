use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{
    Method,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use url::Url;

use super::{
    ConfiguredCredential, CredentialMetadata, ProtocolError, ProtocolErrorCategory,
    ProtocolExecutionResponse, ProtocolHttpMetadata, ProtocolResponseError, protocol_catalog_error,
    protocol_outbound_error,
};
use crate::{
    catalog::{
        ArtifactKind, AuditContext, CatalogSnapshot, CatalogStore, CatalogSyncResult, CreateSource,
        CredentialPayload, InitialCatalogSnapshot, SourceKind, SourceRecord, StagedArtifact,
        StagedTool, StagedToolBinding, StoredCredential, ToolBinding,
    },
    oauth::{OAuthBinding, OAuthError, OAuthService},
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
const MANAGED_OAUTH_PLACEHOLDER: &str = "executor-managed-oauth-placeholder";
const MAX_MANAGED_OAUTH_OPTIONS: usize = 64;
const MAX_MANAGED_OAUTH_SCOPES: usize = 64;
const MAX_MANAGED_OAUTH_KEY_BYTES: usize = 128;
const MAX_MANAGED_OAUTH_SCOPE_BYTES: usize = 256;

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenApiManagedOAuthOption {
    pub(crate) credential_key: String,
    pub(crate) scopes: Vec<String>,
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
    oauth_authorization: Option<PreparedOAuthAuthorization>,
}

struct PreparedOAuthAuthorization {
    source_id: String,
    scheme_name: String,
    required_scopes: Vec<String>,
    expected_binding: OAuthBinding,
}

#[derive(Debug, Error)]
pub enum OpenApiExecutionError {
    #[error("OpenAPI transport failed")]
    Outbound {
        #[source]
        source: crate::outbound::OutboundError,
        outcome_unknown: bool,
    },
    #[error("the OpenAPI mutation outcome is unknown")]
    Indeterminate,
    #[error("managed OAuth authorization is unavailable")]
    OAuth { code: &'static str },
}

impl OpenApiExecutionError {
    pub const fn outcome_unknown(&self) -> bool {
        matches!(
            self,
            Self::Outbound {
                outcome_unknown: true,
                ..
            } | Self::Indeterminate
        )
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Outbound { source, .. } => source.code(),
            Self::Indeterminate => "openapi_outcome_unknown",
            Self::OAuth { code } => code,
        }
    }
}

#[derive(Clone, Default)]
pub struct OpenApiAdapter {
    oauth: Option<OAuthService>,
}

impl OpenApiAdapter {
    pub(crate) fn with_oauth(oauth: OAuthService) -> Self {
        Self { oauth: Some(oauth) }
    }

    pub(super) async fn prepare_invocation(
        &self,
        source_id: &str,
        binding: &OpenApiBinding,
        source_configuration: &Map<String, Value>,
        stored: Option<&StoredCredential>,
        arguments: &Value,
        expected_oauth_bindings: Option<&[OAuthBinding]>,
    ) -> Result<PreparedOpenApiInvocation, ProtocolError> {
        let static_plan = self.plan_invocation(
            source_id,
            binding,
            source_configuration,
            stored,
            arguments,
            &BTreeMap::new(),
        );
        match static_plan {
            Ok(prepared) => Ok(prepared),
            Err(error) if error.code == "missing_source_credentials" => {
                let (eligible_binding, resolved_oauth) = self
                    .resolve_managed_oauth(source_id, binding, stored, expected_oauth_bindings)
                    .await?;
                self.plan_invocation(
                    source_id,
                    &eligible_binding,
                    source_configuration,
                    stored,
                    arguments,
                    &resolved_oauth,
                )
            }
            Err(error) => Err(error),
        }
    }

    pub(super) async fn execute_invocation(
        &self,
        mut prepared: PreparedOpenApiInvocation,
    ) -> Result<ProtocolExecutionResponse, OpenApiExecutionError> {
        if let Some(authorization) = prepared.oauth_authorization {
            let oauth = self.oauth.as_ref().ok_or(OpenApiExecutionError::OAuth {
                code: "oauth_service_unavailable",
            })?;
            let current_binding = oauth
                .binding_for_scopes(
                    &authorization.source_id,
                    &authorization.scheme_name,
                    &authorization.required_scopes,
                )
                .await
                .map_err(openapi_oauth_error)?;
            let binding = match current_binding {
                Some(current) if authorization.expected_binding == current => {
                    authorization.expected_binding
                }
                _ => {
                    return Err(OpenApiExecutionError::OAuth {
                        code: "oauth_binding_changed",
                    });
                }
            };
            let token = oauth
                .access_token_for_binding(&binding)
                .await
                .map_err(openapi_oauth_error)?;
            let mut value =
                HeaderValue::from_str(&format!("Bearer {}", token.expose())).map_err(|_| {
                    OpenApiExecutionError::OAuth {
                        code: "oauth_access_token_invalid",
                    }
                })?;
            value.set_sensitive(true);
            prepared
                .request
                .headers
                .insert(header::AUTHORIZATION, value);
        }
        let mutating = prepared.request.method != Method::GET
            && prepared.request.method != Method::HEAD
            && prepared.request.method != Method::OPTIONS;
        let response = HardenedHttpClient::new(prepared.policy)
            .execute(prepared.request)
            .await
            .map_err(|source| OpenApiExecutionError::Outbound {
                outcome_unknown: mutating && may_have_dispatched(&source),
                source,
            })?;
        let succeeded = response.status.is_success();
        if mutating
            && (response.status.is_server_error()
                || response.status == reqwest::StatusCode::REQUEST_TIMEOUT)
        {
            return Err(OpenApiExecutionError::Indeterminate);
        }
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

    async fn resolve_managed_oauth(
        &self,
        source_id: &str,
        binding: &OpenApiBinding,
        stored: Option<&StoredCredential>,
        expected_oauth_bindings: Option<&[OAuthBinding]>,
    ) -> Result<(OpenApiBinding, BTreeMap<String, OAuthBinding>), ProtocolError> {
        let stored = stored.ok_or_else(|| {
            ProtocolError::corrupt(
                "source_credentials_missing",
                "The source credential state is missing.",
            )
        })?;
        let credential = StoredOpenApiCredentialV1::decode_for_invocation(stored)?;
        let oauth = self.oauth.as_ref().ok_or_else(|| {
            ProtocolError::new(
                ProtocolErrorCategory::Internal,
                "oauth_service_unavailable",
                "Managed OAuth is unavailable.",
            )
        })?;
        let mut eligible_binding = binding.clone();
        eligible_binding.security.clear();
        let mut resolved = BTreeMap::new();
        let mut candidates = std::collections::BTreeSet::new();
        for alternative in &binding.security {
            let mut eligible = true;
            for requirement in &alternative.requirements {
                if credential
                    .credentials
                    .schemes
                    .contains_key(&requirement.scheme_name)
                    || !managed_oauth_supported(requirement)
                {
                    continue;
                }
                let candidate = (requirement.scheme_name.clone(), requirement.scopes.clone());
                if candidates.insert(candidate) && candidates.len() > MAX_MANAGED_OAUTH_OPTIONS {
                    return Err(ProtocolError::new(
                        ProtocolErrorCategory::InvalidInput,
                        "openapi_oauth_scheme_limit_exceeded",
                        "The OpenAPI operation has too many managed OAuth alternatives.",
                    ));
                }
                let current = match oauth
                    .ready_binding_for_scopes(
                        source_id,
                        &requirement.scheme_name,
                        &requirement.scopes,
                    )
                    .await
                {
                    Ok(current) => current,
                    Err(
                        OAuthError::Validation {
                            code: "oauth_scope_not_requested",
                            ..
                        }
                        | OAuthError::Conflict {
                            code: "oauth_scope_not_granted",
                            ..
                        },
                    ) => {
                        eligible = false;
                        break;
                    }
                    Err(error) => return Err(openapi_oauth_prepare_error(error)),
                };
                let selected = match expected_oauth_bindings {
                    Some(expected) => {
                        let expected = expected
                            .iter()
                            .find(|binding| binding.credential_key == requirement.scheme_name);
                        match (expected, current) {
                            (Some(expected), Some(current)) if expected == &current => {
                                Some(expected.clone())
                            }
                            (_, None) => None,
                            _ => {
                                return Err(ProtocolError::new(
                                    ProtocolErrorCategory::Conflict,
                                    "oauth_binding_changed",
                                    "The OAuth connection changed before execution.",
                                ));
                            }
                        }
                    }
                    None => current,
                };
                let Some(selected) = selected else {
                    eligible = false;
                    break;
                };
                resolved.insert(requirement.scheme_name.clone(), selected);
            }
            if eligible {
                eligible_binding.security.push(alternative.clone());
            }
        }
        Ok((eligible_binding, resolved))
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

    pub(crate) async fn managed_oauth_options(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
    ) -> Result<Vec<OpenApiManagedOAuthOption>, ProtocolError> {
        let source = catalog
            .source(source_id)
            .await
            .map_err(protocol_catalog_error)?;
        if source.kind != SourceKind::Openapi {
            return Err(ProtocolError::new(
                ProtocolErrorCategory::InvalidInput,
                "oauth_source_protocol_mismatch",
                "Managed OpenAPI OAuth can only be configured for an OpenAPI source.",
            ));
        }
        let document = stored_openapi_document(catalog, source_id).await?;
        let compiled = compile_bytes(document.into_bytes()).await?;
        managed_oauth_options(&compiled)
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
        source_id: &str,
        binding: &OpenApiBinding,
        source_configuration: &Map<String, Value>,
        stored: Option<&StoredCredential>,
        arguments: &Value,
        resolved_oauth: &BTreeMap<String, OAuthBinding>,
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
        let mut invocation_credentials = credential.credentials.clone();
        for scheme_name in resolved_oauth.keys() {
            if !invocation_credentials.schemes.contains_key(scheme_name) {
                invocation_credentials.schemes.insert(
                    scheme_name.clone(),
                    crate::openapi::OpenApiCredential::OAuthAccessToken {
                        access_token: MANAGED_OAUTH_PLACEHOLDER.to_owned(),
                    },
                );
            }
        }
        let mut protocol_request = build_protocol_request_with_base(
            binding,
            arguments,
            &invocation_credentials,
            document_base_url.as_ref(),
        )
        .map_err(invocation_error)?;
        let managed = protocol_request
            .selected_security_schemes
            .iter()
            .filter(|scheme_name| {
                !credential.credentials.schemes.contains_key(*scheme_name)
                    && resolved_oauth.contains_key(*scheme_name)
            })
            .cloned()
            .collect::<Vec<_>>();
        if managed.len() > 1 {
            return Err(ProtocolError::corrupt(
                "oauth_carrier_conflict",
                "The OpenAPI operation requires conflicting managed OAuth credentials.",
            ));
        }
        let oauth_authorization = match managed.first() {
            Some(scheme_name) => {
                let requirement =
                    selected_security_requirement(binding, &protocol_request, scheme_name)
                        .ok_or_else(|| {
                            ProtocolError::corrupt(
                                "invalid_tool_binding",
                                "The stored OpenAPI tool binding is invalid.",
                            )
                        })?;
                Some(PreparedOAuthAuthorization {
                    source_id: source_id.to_owned(),
                    scheme_name: scheme_name.clone(),
                    required_scopes: requirement.scopes.clone(),
                    expected_binding: resolved_oauth.get(scheme_name).cloned().ok_or_else(
                        || {
                            ProtocolError::corrupt(
                                "invalid_oauth_binding",
                                "The resolved OpenAPI OAuth binding is invalid.",
                            )
                        },
                    )?,
                })
            }
            None => None,
        };
        if oauth_authorization.is_some() {
            protocol_request.headers.remove("authorization");
        }
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
            oauth_authorization,
        })
    }
}

fn openapi_oauth_error(error: OAuthError) -> OpenApiExecutionError {
    let code = match error {
        OAuthError::Validation { code, .. }
        | OAuthError::Conflict { code, .. }
        | OAuthError::Upstream { code } => code,
        OAuthError::NotFound => "oauth_connection_required",
        OAuthError::UnauthorizedTransaction => "oauth_transaction_unauthorized",
        OAuthError::AuthorizationDenied { .. } => "oauth_authorization_denied",
        OAuthError::Internal => "oauth_internal_error",
    };
    OpenApiExecutionError::OAuth { code }
}

fn openapi_oauth_prepare_error(error: OAuthError) -> ProtocolError {
    match error {
        OAuthError::Validation { code, message } => {
            ProtocolError::new(ProtocolErrorCategory::InvalidInput, code, message)
        }
        OAuthError::Conflict { code, message } => {
            ProtocolError::new(ProtocolErrorCategory::Conflict, code, message)
        }
        OAuthError::NotFound => ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "oauth_connection_required",
            "The OAuth connection must be configured before this operation can run.",
        ),
        OAuthError::Upstream { code } => ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            code,
            "The OAuth provider request failed.",
        ),
        OAuthError::UnauthorizedTransaction
        | OAuthError::AuthorizationDenied { .. }
        | OAuthError::Internal => ProtocolError::new(
            ProtocolErrorCategory::Internal,
            "oauth_internal_error",
            "Managed OAuth could not be resolved safely.",
        ),
    }
}

fn may_have_dispatched(error: &crate::outbound::OutboundError) -> bool {
    matches!(
        error,
        crate::outbound::OutboundError::Timeout
            | crate::outbound::OutboundError::Request
            | crate::outbound::OutboundError::ResponseHeadersTooLarge
            | crate::outbound::OutboundError::ResponseBodyTooLarge
            | crate::outbound::OutboundError::UnsupportedContentEncoding
    )
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

async fn stored_openapi_document(
    catalog: &CatalogStore,
    source_id: &str,
) -> Result<String, ProtocolError> {
    sqlx::query_scalar::<_, String>(
        "SELECT content_json FROM source_artifacts WHERE source_id = ? \
         AND artifact_kind = 'openapi_document' AND stable_key = 'document'",
    )
    .bind(source_id)
    .fetch_optional(catalog.pool())
    .await
    .map_err(|_| internal_storage_error())?
    .ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "source_artifact_missing",
            "The source has no OpenAPI document.",
        )
    })
}

fn managed_oauth_options(
    compiled: &CompiledOpenApi,
) -> Result<Vec<OpenApiManagedOAuthOption>, ProtocolError> {
    let mut options = BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    for requirement in compiled
        .tools
        .iter()
        .flat_map(|tool| &tool.binding.security)
        .flat_map(|alternative| &alternative.requirements)
    {
        if !matches!(requirement.scheme, OpenApiSecurityScheme::OAuth2) {
            continue;
        }
        let Some(flow) = requirement
            .oauth_flows
            .as_ref()
            .and_then(|flows| flows.authorization_code.as_ref())
        else {
            continue;
        };
        if requirement.scheme_name.is_empty()
            || requirement.scheme_name.len() > MAX_MANAGED_OAUTH_KEY_BYTES
            || requirement.scheme_name.chars().any(char::is_control)
        {
            return Err(ProtocolError::new(
                ProtocolErrorCategory::InvalidInput,
                "invalid_oauth_credential_key",
                "An OpenAPI managed OAuth credential key is invalid.",
            ));
        }
        if !options.contains_key(&requirement.scheme_name)
            && options.len() >= MAX_MANAGED_OAUTH_OPTIONS
        {
            return Err(ProtocolError::new(
                ProtocolErrorCategory::InvalidInput,
                "openapi_oauth_scheme_limit_exceeded",
                "The OpenAPI document declares too many managed OAuth schemes.",
            ));
        }
        let scopes = options.entry(requirement.scheme_name.clone()).or_default();
        for scope in &requirement.scopes {
            if !flow.scopes.contains_key(scope)
                || scope.is_empty()
                || scope.len() > MAX_MANAGED_OAUTH_SCOPE_BYTES
                || !scope
                    .bytes()
                    .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
            {
                return Err(ProtocolError::new(
                    ProtocolErrorCategory::InvalidInput,
                    "invalid_oauth_scopes",
                    "An OpenAPI managed OAuth scope is invalid.",
                ));
            }
            if !scopes.contains(scope) && scopes.len() >= MAX_MANAGED_OAUTH_SCOPES {
                return Err(ProtocolError::new(
                    ProtocolErrorCategory::InvalidInput,
                    "openapi_oauth_scope_limit_exceeded",
                    "An OpenAPI managed OAuth scheme declares too many scopes.",
                ));
            }
            scopes.insert(scope.clone());
        }
    }
    Ok(options
        .into_iter()
        .map(|(credential_key, scopes)| OpenApiManagedOAuthOption {
            credential_key,
            scopes: scopes.into_iter().collect(),
        })
        .collect())
}

fn managed_oauth_supported(requirement: &OpenApiSecurityRequirement) -> bool {
    matches!(requirement.scheme, OpenApiSecurityScheme::OAuth2)
        && requirement
            .oauth_flows
            .as_ref()
            .is_some_and(|flows| flows.authorization_code.is_some())
}

fn selected_security_requirement<'a>(
    binding: &'a OpenApiBinding,
    request: &crate::openapi::OpenApiProtocolRequest,
    scheme_name: &str,
) -> Option<&'a OpenApiSecurityRequirement> {
    binding
        .security
        .iter()
        .find(|alternative| {
            alternative.requirements.len() == request.selected_security_schemes.len()
                && alternative
                    .requirements
                    .iter()
                    .zip(&request.selected_security_schemes)
                    .all(|(requirement, selected)| requirement.scheme_name == *selected)
        })?
        .requirements
        .iter()
        .find(|requirement| requirement.scheme_name == scheme_name)
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
    use sqlx::sqlite::SqlitePoolOptions;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::{Duration, timeout},
    };

    use super::{
        OpenApiAdapter, OpenApiSourceConfigurationV1, StoredOpenApiCredentialV1, response_data,
        safe_response_headers,
    };
    use crate::{
        catalog::{CredentialPayload, StoredCredential},
        crypto::Keyring,
        oauth::{
            OAuthService,
            model::{OAuthClientAuthentication, OAuthConnectionConfig, OAuthSecretSet},
            store::OAuthStore,
        },
        openapi::{OpenApiCredential, OpenApiCredentialSet, compile_document},
        outbound::OutboundPolicy,
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

    #[test]
    fn managed_oauth_is_selected_only_when_the_scheme_has_no_static_credential() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "Managed OAuth" },
            "servers": [{ "url": "https://api.example.test" }],
            "components": { "securitySchemes": {
                "oauth": { "type": "oauth2", "flows": { "authorizationCode": {
                    "authorizationUrl": "https://auth.example.test/authorize",
                    "tokenUrl": "https://auth.example.test/token",
                    "scopes": {}
                }} }
            }},
            "paths": {
                "/items": { "get": {
                    "security": [{ "oauth": [] }],
                    "responses": { "200": { "description": "ok" } }
                }},
                "/public": { "get": {
                    "security": [{ "oauth": [] }, {}],
                    "responses": { "200": { "description": "ok" } }
                }}
            }
        });
        let compiled = compile_document(&serde_json::to_vec(&document).unwrap())
            .expect("OAuth document compiles");
        let binding = &compiled
            .tools
            .iter()
            .find(|tool| tool.binding.path_template == "/items")
            .expect("OAuth operation exists")
            .binding;
        let configuration = json!({
            "spec": { "type": "inline" },
            "allowPrivateNetwork": false
        })
        .as_object()
        .unwrap()
        .clone();
        let stored = |credentials: OpenApiCredentialSet| StoredCredential {
            revision: 1,
            credential: CredentialPayload {
                schema_version: 1,
                payload: json!({
                    "locator": { "type": "inline" },
                    "credentials": credentials
                }),
            },
        };
        let expected = crate::oauth::OAuthBinding {
            connection_id: "connection-id".to_owned(),
            credential_key: "oauth".to_owned(),
            config_revision: 3,
        };
        let resolved = BTreeMap::from([("oauth".to_owned(), expected.clone())]);

        let managed = OpenApiAdapter::default()
            .plan_invocation(
                "source-id",
                binding,
                &configuration,
                Some(&stored(OpenApiCredentialSet::default())),
                &json!({}),
                &resolved,
            )
            .expect("missing static OAuth selects managed OAuth");
        let authorization = managed
            .oauth_authorization
            .expect("managed OAuth is deferred until execution");
        assert_eq!(authorization.source_id, "source-id");
        assert_eq!(authorization.scheme_name, "oauth");
        assert!(!managed.request.headers.contains_key(AUTHORIZATION));

        let snapshotted = OpenApiAdapter::default()
            .plan_invocation(
                "source-id",
                binding,
                &configuration,
                Some(&stored(OpenApiCredentialSet::default())),
                &json!({}),
                &resolved,
            )
            .expect("the snapshotted OAuth binding is retained exactly");
        assert_eq!(
            snapshotted
                .oauth_authorization
                .map(|authorization| authorization.expected_binding),
            Some(expected)
        );

        let public_binding = &compiled
            .tools
            .iter()
            .find(|tool| tool.binding.path_template == "/public")
            .expect("public operation exists")
            .binding;
        let public = OpenApiAdapter::default()
            .plan_invocation(
                "source-id",
                public_binding,
                &configuration,
                Some(&stored(OpenApiCredentialSet::default())),
                &json!({}),
                &BTreeMap::new(),
            )
            .expect("an anonymous alternative remains anonymous");
        assert!(public.oauth_authorization.is_none());
        assert!(!public.request.headers.contains_key(AUTHORIZATION));

        let static_credentials = OpenApiCredentialSet {
            schemes: [(
                "oauth".to_owned(),
                OpenApiCredential::OAuthAccessToken {
                    access_token: "static-access".to_owned(),
                },
            )]
            .into_iter()
            .collect(),
        };
        let static_plan = OpenApiAdapter::default()
            .plan_invocation(
                "source-id",
                binding,
                &configuration,
                Some(&stored(static_credentials)),
                &json!({}),
                &BTreeMap::new(),
            )
            .expect("a configured static credential remains authoritative");
        assert!(static_plan.oauth_authorization.is_none());
        assert_eq!(
            static_plan
                .request
                .headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer static-access")
        );
    }

    #[test]
    fn managed_oauth_options_expose_only_authorization_code_keys_and_scopes() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "OAuth options" },
            "servers": [{ "url": "https://api.example.test" }],
            "components": { "securitySchemes": {
                "authorizationCode": {
                    "type": "oauth2",
                    "flows": { "authorizationCode": {
                        "authorizationUrl": "https://auth.example.test/authorize",
                        "tokenUrl": "https://auth.example.test/token",
                        "scopes": { "write:items": "Write", "read:items": "Read" }
                    }}
                },
                "clientCredentials": {
                    "type": "oauth2",
                    "flows": { "clientCredentials": {
                        "tokenUrl": "https://auth.example.test/token",
                        "scopes": { "service": "Service" }
                    }}
                },
                "bearer": { "type": "http", "scheme": "bearer" }
            }},
            "paths": {
                "/items": { "get": {
                    "security": [
                        { "authorizationCode": ["read:items"] },
                        { "clientCredentials": ["service"] },
                        { "bearer": [] }
                    ],
                    "responses": { "200": { "description": "ok" } }
                }}
            }
        });
        let compiled = compile_document(&serde_json::to_vec(&document).unwrap())
            .expect("OAuth document compiles");
        assert_eq!(
            super::managed_oauth_options(&compiled).expect("options are bounded"),
            vec![super::OpenApiManagedOAuthOption {
                credential_key: "authorizationCode".to_owned(),
                scopes: vec!["read:items".to_owned()],
            }]
        );
    }

    #[tokio::test]
    async fn non_idempotent_unauthorized_response_is_never_replayed() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let server_url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "No OAuth replay" },
            "servers": [{ "url": server_url }],
            "components": { "securitySchemes": {
                "oauth": { "type": "oauth2", "flows": {} }
            }},
            "paths": { "/write": { "post": {
                "security": [{ "oauth": [] }],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        let compiled = compile_document(&serde_json::to_vec(&document).unwrap())
            .expect("OAuth document compiles");
        let configuration = json!({
            "spec": { "type": "inline" },
            "allowPrivateNetwork": true
        })
        .as_object()
        .unwrap()
        .clone();
        let stored = StoredCredential {
            revision: 1,
            credential: CredentialPayload {
                schema_version: 1,
                payload: json!({
                    "locator": { "type": "inline" },
                    "credentials": { "schemes": {
                        "oauth": {
                            "type": "oauth_access_token",
                            "access_token": "static-access"
                        }
                    }}
                }),
            },
        };
        let adapter = OpenApiAdapter::default();
        let prepared = adapter
            .plan_invocation(
                "source-id",
                &compiled.tools[0].binding,
                &configuration,
                Some(&stored),
                &json!({}),
                &BTreeMap::new(),
            )
            .expect("invocation plans");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request accepted");
            let mut request = vec![0_u8; 4096];
            let read = stream.read(&mut request).await.expect("request reads");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.starts_with("POST /write HTTP/1.1"));
            assert!(request.contains("authorization: Bearer static-access"));
            stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("response writes");
            assert!(
                timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "a 401 response must not trigger a blind replay"
            );
        });
        let response = adapter
            .execute_invocation(prepared)
            .await
            .expect("a 401 is a completed upstream response");
        assert!(!response.ok);
        assert_eq!(response.http.expect("HTTP metadata").status, 401);
        server.await.expect("test server completes");
    }

    #[tokio::test]
    async fn mutating_server_errors_are_single_attempt_and_indeterminate() {
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "Indeterminate mutations" },
            "servers": [{ "url": "https://placeholder.example.test" }],
            "components": { "securitySchemes": {
                "oauth": { "type": "oauth2", "flows": {} }
            }},
            "paths": { "/write": { "post": {
                "security": [{ "oauth": [] }],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        let compiled = compile_document(&serde_json::to_vec(&document).unwrap())
            .expect("OpenAPI document compiles");
        let configuration = json!({
            "spec": { "type": "inline" },
            "allowPrivateNetwork": true
        })
        .as_object()
        .unwrap()
        .clone();
        let stored = StoredCredential {
            revision: 1,
            credential: CredentialPayload {
                schema_version: 1,
                payload: json!({
                    "locator": { "type": "inline" },
                    "credentials": { "schemes": {
                        "oauth": {
                            "type": "oauth_access_token",
                            "access_token": "static-access"
                        }
                    }}
                }),
            },
        };

        for method in ["POST", "PATCH", "DELETE"] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("test listener binds");
            let mut binding = compiled.tools[0].binding.clone();
            binding.method = method.to_owned();
            binding.server_url = format!(
                "http://{}",
                listener.local_addr().expect("listener address")
            );
            let adapter = OpenApiAdapter::default();
            let prepared = adapter
                .plan_invocation(
                    "source-id",
                    &binding,
                    &configuration,
                    Some(&stored),
                    &json!({}),
                    &BTreeMap::new(),
                )
                .expect("mutation plans");
            let expected_method = method.to_owned();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("request accepted");
                let mut request = vec![0_u8; 4096];
                let read = stream.read(&mut request).await.expect("request reads");
                let request = String::from_utf8_lossy(&request[..read]);
                assert!(request.starts_with(&format!("{expected_method} /write HTTP/1.1")));
                stream
                    .write_all(
                        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("response writes");
                assert!(
                    timeout(Duration::from_millis(100), listener.accept())
                        .await
                        .is_err(),
                    "an ambiguous mutation response must not trigger a replay"
                );
            });
            let error = adapter
                .execute_invocation(prepared)
                .await
                .expect_err("a mutation 5xx outcome is indeterminate");
            assert!(matches!(error, super::OpenApiExecutionError::Indeterminate));
            assert!(error.outcome_unknown());
            server.await.expect("test server completes");
        }
    }

    #[tokio::test]
    async fn managed_oauth_authorized_invocation_injects_bearer_only_at_execution() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let server_url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "Managed OAuth execution" },
            "servers": [{ "url": server_url }],
            "components": { "securitySchemes": {
                "oauthPending": { "type": "oauth2", "flows": { "authorizationCode": {
                    "authorizationUrl": "https://auth.example.test/authorize",
                    "tokenUrl": "https://auth.example.test/token",
                    "scopes": { "write:items": "Write items" }
                }} },
                "oauthActive": { "type": "oauth2", "flows": { "authorizationCode": {
                    "authorizationUrl": "https://auth.example.test/authorize",
                    "tokenUrl": "https://auth.example.test/token",
                    "scopes": { "write:items": "Write items" }
                }} }
            }},
            "paths": { "/write": { "post": {
                "security": [
                    { "oauthPending": ["write:items"] },
                    { "oauthActive": ["write:items"] }
                ],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        let compiled = compile_document(&serde_json::to_vec(&document).unwrap())
            .expect("OAuth document compiles");
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
            "INSERT INTO sources (
                id, kind, slug, display_name, configuration_json, health_status,
                revision, catalog_revision, created_at, updated_at
             ) VALUES (?, 'openapi', 'managed', 'Managed', ?, 'unknown', 0, 0, 1, 1)",
        )
        .bind("source-id")
        .bind(r#"{"spec":{"type":"inline"},"allowPrivateNetwork":true}"#)
        .execute(&pool)
        .await
        .expect("source inserts");
        let keyring = Keyring::from_master_key([41; 32]).expect("test keyring");
        let oauth_store = OAuthStore::new(pool.clone(), keyring.clone());
        let connection_config = OAuthConnectionConfig {
            issuer: "https://auth.example.test".to_owned(),
            authorization_endpoint: "https://auth.example.test/authorize".to_owned(),
            token_endpoint: "https://auth.example.test/token".to_owned(),
            client_id: "client".to_owned(),
            client_authentication: OAuthClientAuthentication::None,
            token_endpoint_auth_methods_supported: vec!["none".to_owned()],
            scopes: vec!["write:items".to_owned()],
            allow_private_network: true,
            resource: None,
        };
        oauth_store
            .create_connection("source-id", "oauthPending", &connection_config, None, 1)
            .await
            .expect("pending OAuth connection inserts");
        oauth_store
            .create_connection(
                "source-id",
                "oauthActive",
                &connection_config,
                Some(&OAuthSecretSet {
                    access_token: Some("managed-access-token".to_owned()),
                    token_type: Some("Bearer".to_owned()),
                    granted_scopes: vec!["write:items".to_owned()],
                    access_token_expires_at: Some(i64::MAX),
                    ..OAuthSecretSet::default()
                }),
                1,
            )
            .await
            .expect("managed OAuth connection inserts");
        let oauth = OAuthService::new(
            pool,
            keyring,
            "http://127.0.0.1:4788".to_owned(),
            OutboundPolicy::default(),
        );
        let expected_oauth_bindings = oauth
            .bindings_for_source("source-id")
            .await
            .expect("approval OAuth bindings snapshot");
        let adapter = OpenApiAdapter::with_oauth(oauth);
        let configuration = json!({
            "spec": { "type": "inline" },
            "allowPrivateNetwork": true
        })
        .as_object()
        .unwrap()
        .clone();
        let stored = StoredCredential {
            revision: 1,
            credential: CredentialPayload {
                schema_version: 1,
                payload: json!({
                    "locator": { "type": "inline" },
                    "credentials": { "schemes": {} }
                }),
            },
        };
        let prepared = adapter
            .prepare_invocation(
                "source-id",
                &compiled.tools[0].binding,
                &configuration,
                Some(&stored),
                &json!({}),
                Some(&expected_oauth_bindings),
            )
            .await
            .expect("managed OAuth invocation prepares");
        assert_eq!(
            prepared
                .oauth_authorization
                .as_ref()
                .map(|authorization| authorization.scheme_name.as_str()),
            Some("oauthActive")
        );
        assert!(!prepared.request.headers.contains_key(AUTHORIZATION));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request accepted");
            let mut request = vec![0_u8; 4096];
            let read = stream.read(&mut request).await.expect("request reads");
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains("authorization: Bearer managed-access-token"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
                )
                .await
                .expect("response writes");
        });
        let response = adapter
            .execute_invocation(prepared)
            .await
            .expect("managed OAuth invocation executes");
        assert!(response.ok);
        assert_eq!(response.data, Some(json!({ "ok": true })));
        server.await.expect("test server completes");
    }
}
