use std::collections::{BTreeMap, BTreeSet};

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
    outbound::{HardenedHttpClient, OutboundError, OutboundPolicy, OutboundRequest, parse_url},
};

const MAX_SPEC_BYTES: usize = 16 * 1024 * 1024;
const OPENAPI_CREDENTIAL_SCHEMA_VERSION: u32 = 1;
const MANAGED_OAUTH_PLACEHOLDER: &str = "executor-managed-oauth-placeholder";
const MAX_MANAGED_OAUTH_OPTIONS: usize = 64;
const MAX_MANAGED_OAUTH_SCOPES: usize = 64;
const MAX_MANAGED_OAUTH_KEY_BYTES: usize = 128;
const MAX_MANAGED_OAUTH_SCOPE_BYTES: usize = 256;
const MAX_BOUND_CREDENTIAL_SCHEMES: usize = 128;
const MAX_CREDENTIAL_ORIGINS_PER_SCHEME: usize = 1_024;
const MAX_ORIGIN_RETIRE_CAS_ATTEMPTS: usize = 4;

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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    credential_origins: BTreeMap<String, Vec<String>>,
}

impl StoredOpenApiCredentialV1 {
    fn decode(stored: &StoredCredential) -> Result<Self, ProtocolError> {
        if stored.credential.schema_version != OPENAPI_CREDENTIAL_SCHEMA_VERSION {
            return Err(ProtocolError::new(
                ProtocolErrorCategory::Conflict,
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
        if self.credential_origins.len() > MAX_BOUND_CREDENTIAL_SCHEMES {
            return Err(invalid_stored_credentials());
        }
        for (scheme_name, origins) in &self.credential_origins {
            if scheme_name.is_empty()
                || scheme_name.len() > 256
                || scheme_name.chars().any(char::is_control)
                || origins.len() > MAX_CREDENTIAL_ORIGINS_PER_SCHEME
                || origins.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(invalid_stored_credentials());
            }
            for origin in origins {
                let parsed = require_http_url(origin).map_err(|_| invalid_stored_credentials())?;
                if parsed.origin().ascii_serialization() != origin.as_str() {
                    return Err(invalid_stored_credentials());
                }
            }
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
    #[error("OpenAPI transport is not confidential")]
    InsecureTransport,
    #[error("OpenAPI transport failed")]
    Outbound {
        #[source]
        source: crate::outbound::OutboundError,
        outcome_unknown: bool,
    },
    #[error("the OpenAPI mutation outcome is unknown")]
    Indeterminate,
    #[error("managed OAuth authorization is unavailable")]
    OAuth(#[source] OAuthError),
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
            Self::InsecureTransport => "insecure_openapi_transport",
            Self::Outbound {
                source: OutboundError::InsecureTransport,
                ..
            } => "insecure_openapi_transport",
            Self::Outbound { source, .. } => source.code(),
            Self::Indeterminate => "openapi_outcome_unknown",
            Self::OAuth(error) => error.code(),
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
        prepared: PreparedOpenApiInvocation,
    ) -> Result<ProtocolExecutionResponse, OpenApiExecutionError> {
        let client = HardenedHttpClient::new(prepared.policy.clone());
        self.execute_invocation_with_client(prepared, client).await
    }

    async fn execute_invocation_with_client(
        &self,
        mut prepared: PreparedOpenApiInvocation,
        client: HardenedHttpClient,
    ) -> Result<ProtocolExecutionResponse, OpenApiExecutionError> {
        if !is_confidential_openapi_url(&prepared.request.url) {
            return Err(OpenApiExecutionError::InsecureTransport);
        }
        if let Some(authorization) = prepared.oauth_authorization {
            let oauth = self
                .oauth
                .as_ref()
                .ok_or(OpenApiExecutionError::OAuth(OAuthError::Internal))?;
            let current_binding = oauth
                .ready_binding_for_scopes(
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
                    return Err(OpenApiExecutionError::OAuth(OAuthError::Conflict {
                        code: "oauth_binding_changed",
                        message: "The managed OAuth binding changed before dispatch.",
                    }));
                }
            };
            let token = oauth
                .access_token_for_binding(&binding)
                .await
                .map_err(openapi_oauth_error)?;
            let mut value = HeaderValue::from_str(&format!("Bearer {}", token.expose()))
                .map_err(|_| OpenApiExecutionError::OAuth(OAuthError::Internal))?;
            value.set_sensitive(true);
            prepared
                .request
                .headers
                .insert(header::AUTHORIZATION, value);
        }
        let mutating = prepared.request.method != Method::GET
            && prepared.request.method != Method::HEAD
            && prepared.request.method != Method::OPTIONS;
        let response = client.execute(prepared.request).await.map_err(|source| {
            OpenApiExecutionError::Outbound {
                outcome_unknown: mutating && may_have_dispatched(&source),
                source,
            }
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
        if let Some(expected) = expected_oauth_bindings {
            return Self::resolve_snapshotted_managed_oauth(
                oauth,
                source_id,
                binding,
                &credential,
                expected,
            )
            .await;
        }
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
                let selected = current;
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

    async fn resolve_snapshotted_managed_oauth(
        oauth: &OAuthService,
        source_id: &str,
        binding: &OpenApiBinding,
        credential: &StoredOpenApiCredentialV1,
        expected: &[OAuthBinding],
    ) -> Result<(OpenApiBinding, BTreeMap<String, OAuthBinding>), ProtocolError> {
        let expected = expected
            .iter()
            .map(|binding| (binding.credential_key.as_str(), binding))
            .collect::<BTreeMap<_, _>>();
        let selected = binding.security.iter().find(|alternative| {
            alternative.requirements.iter().all(|requirement| {
                credential
                    .credentials
                    .schemes
                    .contains_key(&requirement.scheme_name)
                    || (managed_oauth_supported(requirement)
                        && expected
                            .get(requirement.scheme_name.as_str())
                            .is_some_and(|binding| {
                                requirement
                                    .scopes
                                    .iter()
                                    .all(|scope| binding.granted_scopes.contains(scope))
                            }))
            })
        });
        let Some(selected) = selected else {
            let mut eligible_binding = binding.clone();
            eligible_binding.security.clear();
            return Ok((eligible_binding, BTreeMap::new()));
        };
        let mut resolved = BTreeMap::new();
        for requirement in &selected.requirements {
            if credential
                .credentials
                .schemes
                .contains_key(&requirement.scheme_name)
            {
                continue;
            }
            let expected = expected
                .get(requirement.scheme_name.as_str())
                .expect("the snapshotted alternative was selected from this binding map");
            let current = oauth
                .binding(source_id, &requirement.scheme_name)
                .await
                .map_err(openapi_oauth_prepare_error)?;
            if current.as_ref() != Some(*expected) {
                return Err(oauth_binding_changed());
            }
            let ready = oauth
                .ready_binding_for_scopes(source_id, &requirement.scheme_name, &requirement.scopes)
                .await
                .map_err(openapi_oauth_prepare_error)?;
            if ready.as_ref() != Some(*expected) {
                return Err(oauth_binding_changed());
            }
            resolved.insert(requirement.scheme_name.clone(), (*expected).clone());
        }
        let mut eligible_binding = binding.clone();
        eligible_binding.security = vec![selected.clone()];
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
        let mut credential = StoredOpenApiCredentialV1 {
            locator: fetched.locator,
            credentials: input.credential,
            credential_origins: BTreeMap::new(),
        };
        let credential_keys = credential
            .credentials
            .schemes
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        bind_missing_credential_origins(
            &mut credential,
            fetched.compiled.tools.iter().map(|tool| &tool.binding),
            credential_keys,
            OriginInput::Untrusted,
        )?;
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
                let compiled = compile_bytes(document.into_bytes()).await?;
                validate_inline_operation_transports(&compiled)?;
                FetchedSpec {
                    compiled,
                    locator: StoredOpenApiLocatorV1::Inline,
                }
            }
            StoredOpenApiLocatorV1::Url { url, .. } => {
                fetch_url(url, configuration.allow_private_network).await?
            }
        };
        verify_refresh_credential_origins(&credential, &fetched.compiled)?;
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
        let bindings = stored_openapi_bindings(catalog, source_id).await?;
        credential.credentials = credential_set;
        self.retire_unused_credential_origins(source_id, &mut credential)
            .await?;
        let credential_keys = credential
            .credentials
            .schemes
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        bind_missing_credential_origins(
            &mut credential,
            bindings.iter(),
            credential_keys,
            OriginInput::Stored,
        )?;
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

    pub(crate) async fn ensure_managed_oauth_origin_bound(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        credential_key: &str,
        audit: AuditContext<'_>,
    ) -> Result<(), ProtocolError> {
        let stored = required_stored_credential(catalog, source_id).await?;
        let mut credential = StoredOpenApiCredentialV1::decode(&stored)?;
        let bindings = stored_openapi_bindings(catalog, source_id).await?;
        if !matches!(credential.locator, StoredOpenApiLocatorV1::Url { .. })
            || credential.credential_origins.contains_key(credential_key)
        {
            return Ok(());
        }
        bind_missing_credential_origins(
            &mut credential,
            bindings.iter(),
            [credential_key.to_owned()],
            OriginInput::Stored,
        )?;
        catalog
            .put_credential(
                source_id,
                &credential.payload()?,
                Some(stored.revision),
                audit,
            )
            .await
            .map_err(protocol_catalog_error)?;
        Ok(())
    }

    pub(crate) async fn retire_managed_oauth_origin(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        credential_key: &str,
        audit: AuditContext<'_>,
    ) -> Result<(), ProtocolError> {
        let Some(oauth) = self.oauth.as_ref() else {
            return Ok(());
        };
        for _ in 0..MAX_ORIGIN_RETIRE_CAS_ATTEMPTS {
            let stored = required_stored_credential(catalog, source_id).await?;
            let mut credential = StoredOpenApiCredentialV1::decode(&stored)?;
            if !credential.credential_origins.contains_key(credential_key)
                || credential.credentials.schemes.contains_key(credential_key)
                || oauth
                    .binding(source_id, credential_key)
                    .await
                    .map_err(openapi_oauth_prepare_error)?
                    .is_some()
            {
                return Ok(());
            }
            credential.credential_origins.remove(credential_key);
            match catalog
                .put_credential(
                    source_id,
                    &credential.payload()?,
                    Some(stored.revision),
                    audit,
                )
                .await
            {
                Ok(_) => return Ok(()),
                Err(error) => {
                    let error = protocol_catalog_error(error);
                    if error.code != "revision_conflict" {
                        return Err(error);
                    }
                }
            }
        }
        Err(revision_conflict())
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
        self.retire_unused_credential_origins(source_id, &mut credential)
            .await?;
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

    async fn retire_unused_credential_origins(
        &self,
        source_id: &str,
        credential: &mut StoredOpenApiCredentialV1,
    ) -> Result<(), ProtocolError> {
        let static_keys = credential
            .credentials
            .schemes
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let Some(oauth) = self.oauth.as_ref() else {
            return Ok(());
        };
        let mut retained = BTreeSet::new();
        for key in credential.credential_origins.keys() {
            if static_keys.contains(key) {
                continue;
            }
            if oauth
                .binding(source_id, key)
                .await
                .map_err(openapi_oauth_prepare_error)?
                .is_some()
            {
                retained.insert(key.clone());
            }
        }
        credential
            .credential_origins
            .retain(|key, _| static_keys.contains(key) || retained.contains(key));
        Ok(())
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
        let binding_url =
            require_http_url(&binding.server_url).map_err(|_| invalid_tool_binding())?;
        require_confidential_stored_url(&binding_url)?;
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
                url,
                document_base_url,
            } => {
                let locator_url = require_http_url(url).map_err(|_| {
                    ProtocolError::corrupt(
                        "invalid_source_credentials",
                        "The stored OpenAPI credential state is invalid.",
                    )
                })?;
                require_confidential_stored_url(&locator_url)?;
                let document_base_url = require_http_url(document_base_url).map_err(|_| {
                    ProtocolError::corrupt(
                        "invalid_source_credentials",
                        "The stored OpenAPI credential state is invalid.",
                    )
                })?;
                require_confidential_stored_url(&document_base_url)?;
                Some(document_base_url)
            }
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
        require_confidential_stored_url(&protocol_request.url)?;
        verify_invocation_credential_origins(&credential, &protocol_request)?;
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
                require_https_or_loopback: true,
                ..OutboundPolicy::default()
            },
            oauth_authorization,
        })
    }
}

fn openapi_oauth_error(error: OAuthError) -> OpenApiExecutionError {
    OpenApiExecutionError::OAuth(error)
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

fn oauth_binding_changed() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        "oauth_binding_changed",
        "The OAuth connection changed before execution.",
    )
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

#[derive(Clone, Copy)]
enum OriginInput {
    Stored,
    Untrusted,
}

fn bind_missing_credential_origins<'a>(
    credential: &mut StoredOpenApiCredentialV1,
    bindings: impl IntoIterator<Item = &'a OpenApiBinding>,
    credential_keys: impl IntoIterator<Item = String>,
    input: OriginInput,
) -> Result<(), ProtocolError> {
    if !matches!(&credential.locator, StoredOpenApiLocatorV1::Url { .. }) {
        return Ok(());
    }
    let missing = credential_keys
        .into_iter()
        .filter(|key| !credential.credential_origins.contains_key(key))
        .collect::<BTreeSet<_>>();
    if missing.is_empty() {
        return Ok(());
    }
    if credential
        .credential_origins
        .len()
        .checked_add(missing.len())
        .is_none_or(|count| count > MAX_BOUND_CREDENTIAL_SCHEMES)
    {
        return Err(origin_limit_error(input));
    }
    credential
        .credential_origins
        .extend(credential_origins_for_bindings(bindings, missing, input)?);
    Ok(())
}

fn credential_origins_for_bindings<'a>(
    bindings: impl IntoIterator<Item = &'a OpenApiBinding>,
    credential_keys: impl IntoIterator<Item = String>,
    input: OriginInput,
) -> Result<BTreeMap<String, Vec<String>>, ProtocolError> {
    let mut origins = credential_keys
        .into_iter()
        .map(|key| (key, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    if origins.len() > MAX_BOUND_CREDENTIAL_SCHEMES {
        return Err(origin_limit_error(input));
    }
    for binding in bindings {
        let matching = binding
            .security
            .iter()
            .flat_map(|alternative| &alternative.requirements)
            .map(|requirement| requirement.scheme_name.as_str())
            .filter(|scheme_name| origins.contains_key(*scheme_name))
            .collect::<BTreeSet<_>>();
        if matching.is_empty() {
            continue;
        }
        let server_url = require_http_url(&binding.server_url).map_err(|_| match input {
            OriginInput::Stored => invalid_tool_binding(),
            OriginInput::Untrusted => ProtocolError::new(
                ProtocolErrorCategory::InvalidInput,
                "invalid_openapi_document",
                "The OpenAPI document contains an invalid server URL.",
            ),
        })?;
        require_confidential_untrusted_url(&server_url)?;
        let origin = normalized_http_origin(&binding.server_url).map_err(|_| match input {
            OriginInput::Stored => ProtocolError::corrupt(
                "invalid_tool_binding",
                "The stored OpenAPI tool binding is invalid.",
            ),
            OriginInput::Untrusted => ProtocolError::new(
                ProtocolErrorCategory::InvalidInput,
                "invalid_openapi_document",
                "The OpenAPI document contains an invalid server URL.",
            ),
        })?;
        for scheme_name in matching {
            let destinations = origins
                .get_mut(scheme_name)
                .expect("the matching credential key came from the destination map");
            destinations.insert(origin.clone());
            if destinations.len() > MAX_CREDENTIAL_ORIGINS_PER_SCHEME {
                return Err(origin_limit_error(input));
            }
        }
    }
    Ok(origins
        .into_iter()
        .map(|(key, origins)| (key, origins.into_iter().collect()))
        .collect())
}

fn verify_refresh_credential_origins(
    credential: &StoredOpenApiCredentialV1,
    compiled: &CompiledOpenApi,
) -> Result<(), ProtocolError> {
    verify_candidate_credential_origins(credential, compiled.tools.iter().map(|tool| &tool.binding))
}

fn verify_candidate_credential_origins<'a>(
    credential: &StoredOpenApiCredentialV1,
    bindings: impl IntoIterator<Item = &'a OpenApiBinding>,
) -> Result<(), ProtocolError> {
    if !matches!(&credential.locator, StoredOpenApiLocatorV1::Url { .. }) {
        return Ok(());
    }
    for key in credential.credentials.schemes.keys() {
        if !credential.credential_origins.contains_key(key) {
            return Err(unbound_credential_origin());
        }
    }
    let candidates = credential_origins_for_bindings(
        bindings,
        credential.credential_origins.keys().cloned(),
        OriginInput::Untrusted,
    )?;
    for (scheme_name, destinations) in candidates {
        let allowed = credential
            .credential_origins
            .get(&scheme_name)
            .ok_or_else(unbound_credential_origin)?;
        if destinations
            .iter()
            .any(|destination| allowed.binary_search(destination).is_err())
        {
            return Err(changed_credential_origin());
        }
    }
    Ok(())
}

fn verify_invocation_credential_origins(
    credential: &StoredOpenApiCredentialV1,
    request: &crate::openapi::OpenApiProtocolRequest,
) -> Result<(), ProtocolError> {
    if !matches!(&credential.locator, StoredOpenApiLocatorV1::Url { .. })
        || request.selected_security_schemes.is_empty()
    {
        return Ok(());
    }
    let destination = request.url.origin().ascii_serialization();
    for scheme_name in &request.selected_security_schemes {
        let allowed = credential
            .credential_origins
            .get(scheme_name)
            .ok_or_else(unbound_credential_origin)?;
        if allowed.binary_search(&destination).is_err() {
            return Err(changed_credential_origin());
        }
    }
    Ok(())
}

fn normalized_http_origin(value: &str) -> Result<String, crate::outbound::OutboundError> {
    Ok(require_http_url(value)?.origin().ascii_serialization())
}

fn origin_limit_error(input: OriginInput) -> ProtocolError {
    match input {
        OriginInput::Stored => invalid_stored_credentials(),
        OriginInput::Untrusted => ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "openapi_credential_origin_limit_exceeded",
            "The OpenAPI document declares too many credential destinations.",
        ),
    }
}

fn unbound_credential_origin() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        "openapi_credential_origin_unbound",
        "The OpenAPI credential destination is not bound. Save the credential again before use.",
    )
}

fn changed_credential_origin() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        "openapi_credential_origin_changed",
        "The OpenAPI refresh changed a credential destination origin.",
    )
}

fn invalid_stored_credentials() -> ProtocolError {
    ProtocolError::corrupt(
        "invalid_source_credentials",
        "The stored OpenAPI credential state is invalid.",
    )
}

async fn stored_openapi_bindings(
    catalog: &CatalogStore,
    source_id: &str,
) -> Result<Vec<OpenApiBinding>, ProtocolError> {
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT tool_bindings.binding_version, tool_bindings.definition_json \
         FROM tool_bindings JOIN tools ON tools.id = tool_bindings.tool_id \
         WHERE tools.source_id = ? AND tools.present = 1 \
         AND tool_bindings.protocol = 'openapi' ORDER BY tools.stable_key",
    )
    .bind(source_id)
    .fetch_all(catalog.pool())
    .await
    .map_err(|_| internal_storage_error())?;
    rows.into_iter()
        .map(|(version, definition)| {
            let binding: OpenApiBinding =
                serde_json::from_str(&definition).map_err(|_| invalid_tool_binding())?;
            if version != 1 || binding.version != 1 {
                return Err(invalid_tool_binding());
            }
            let server_url =
                require_http_url(&binding.server_url).map_err(|_| invalid_tool_binding())?;
            require_confidential_untrusted_url(&server_url)?;
            Ok(binding)
        })
        .collect()
}

fn invalid_tool_binding() -> ProtocolError {
    ProtocolError::corrupt(
        "invalid_tool_binding",
        "The stored OpenAPI tool binding is invalid.",
    )
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
            validate_inline_operation_transports(&compiled)?;
            Ok(FetchedSpec {
                compiled,
                locator: StoredOpenApiLocatorV1::Inline,
            })
        }
        OpenApiSpecInput::Url { url } => fetch_url(url, allow_private_network).await,
    }
}

fn validate_inline_operation_transports(compiled: &CompiledOpenApi) -> Result<(), ProtocolError> {
    for tool in &compiled.tools {
        let url = require_http_url(&tool.binding.server_url).map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCategory::InvalidInput,
                "inline_openapi_server_required",
                "Inline OpenAPI documents must define an absolute HTTP or HTTPS server URL.",
            )
        })?;
        require_confidential_untrusted_url(&url)?;
    }
    Ok(())
}

async fn fetch_url(url: &str, allow_private_network: bool) -> Result<FetchedSpec, ProtocolError> {
    let policy = OutboundPolicy {
        allow_private_networks: allow_private_network,
        require_https_or_loopback: true,
        max_response_bytes: MAX_SPEC_BYTES,
        ..OutboundPolicy::default()
    };
    let transport_url =
        Url::parse(url).map_err(|_| protocol_outbound_error(OutboundError::InvalidUrl))?;
    require_confidential_untrusted_url(&transport_url)?;
    let url = parse_url(url, &policy).map_err(protocol_outbound_error)?;
    let response = HardenedHttpClient::new(policy)
        .fetch_spec_with_url_policy(url.clone(), HeaderMap::new(), |candidate| {
            if is_confidential_openapi_url(candidate) {
                Ok(())
            } else {
                Err(OutboundError::RedirectDowngrade)
            }
        })
        .await
        .map_err(|error| match error {
            OutboundError::RedirectDowngrade | OutboundError::InsecureTransport => {
                insecure_openapi_transport(ProtocolErrorCategory::InvalidInput)
            }
            error => protocol_outbound_error(error),
        })?;
    require_confidential_untrusted_url(&response.final_url)?;
    let mut compiled = compile_bytes(response.body).await?;
    let mut document_base_url = response.final_url.clone();
    document_base_url.set_query(None);
    document_base_url.set_fragment(None);
    for tool in &mut compiled.tools {
        tool.binding.server_url =
            resolved_document_server_url(&document_base_url, &tool.binding.server_url)?;
    }
    Ok(FetchedSpec {
        compiled,
        locator: StoredOpenApiLocatorV1::Url {
            url: url.to_string(),
            document_base_url: document_base_url.to_string(),
        },
    })
}

fn resolved_document_server_url(
    document_base_url: &Url,
    server_url: &str,
) -> Result<String, ProtocolError> {
    let resolved = document_base_url.join(server_url).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "invalid_openapi_document",
            "The OpenAPI document contains an invalid server URL.",
        )
    })?;
    if !matches!(resolved.scheme(), "http" | "https")
        || !resolved.username().is_empty()
        || resolved.password().is_some()
        || resolved.query().is_some()
        || resolved.fragment().is_some()
    {
        return Err(ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "invalid_openapi_document",
            "The OpenAPI document contains an invalid server URL.",
        ));
    }
    require_confidential_untrusted_url(&resolved)?;
    Ok(resolved.to_string())
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
    credentials.validate().map_err(|error| match error {
        crate::openapi::OpenApiCredentialError::InvalidBasicUsername => ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "invalid_basic_username",
            "An HTTP Basic username must not contain a colon.",
        ),
        crate::openapi::OpenApiCredentialError::InvalidBasicValue => ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "invalid_basic_credentials",
            "HTTP Basic credentials must not contain control characters.",
        ),
        _ => ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "invalid_credentials",
            "The static credential configuration is invalid.",
        ),
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

fn is_confidential_openapi_url(url: &Url) -> bool {
    match url.scheme() {
        "https" => url.host().is_some(),
        "http" => match url.host() {
            Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(address)) => address.is_loopback(),
            Some(url::Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        },
        _ => false,
    }
}

fn require_confidential_untrusted_url(url: &Url) -> Result<(), ProtocolError> {
    if is_confidential_openapi_url(url) {
        Ok(())
    } else {
        Err(insecure_openapi_transport(
            ProtocolErrorCategory::InvalidInput,
        ))
    }
}

fn require_confidential_stored_url(url: &Url) -> Result<(), ProtocolError> {
    if is_confidential_openapi_url(url) {
        Ok(())
    } else {
        Err(insecure_openapi_transport(ProtocolErrorCategory::Conflict))
    }
}

fn insecure_openapi_transport(category: ProtocolErrorCategory) -> ProtocolError {
    ProtocolError::new(
        category,
        "insecure_openapi_transport",
        "OpenAPI URLs must use HTTPS, except for loopback HTTP endpoints.",
    )
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
    use url::Url;

    use super::{
        OpenApiAdapter, OpenApiSourceConfigurationV1, StoredOpenApiCredentialV1,
        StoredOpenApiLocatorV1, is_confidential_openapi_url, normalized_http_origin, response_data,
        safe_response_headers, verify_candidate_credential_origins,
    };
    use crate::{
        catalog::{CredentialPayload, StoredCredential},
        crypto::Keyring,
        oauth::{
            OAuthBinding, OAuthService,
            model::{
                OAuthClientAuthentication, OAuthClientSecretUpdate, OAuthConnectionConfig,
                OAuthSecretSet,
            },
            store::OAuthStore,
        },
        openapi::{
            OpenApiBinding, OpenApiCredential, OpenApiCredentialSet, OpenApiSecurityAlternative,
            OpenApiSecurityRequirement, OpenApiSecurityScheme, compile_document,
        },
        outbound::{HardenedHttpClient, OutboundPolicy},
        protocols::ProtocolErrorCategory,
    };

    fn origin_binding(server_url: &str, scheme_name: &str) -> OpenApiBinding {
        OpenApiBinding {
            version: 1,
            method: "GET".to_owned(),
            path_template: "/credential".to_owned(),
            server_url: server_url.to_owned(),
            parameters: Vec::new(),
            request_body: None,
            security: vec![OpenApiSecurityAlternative {
                requirements: vec![OpenApiSecurityRequirement {
                    scheme_name: scheme_name.to_owned(),
                    scopes: Vec::new(),
                    scheme: OpenApiSecurityScheme::Http {
                        scheme: "bearer".to_owned(),
                        bearer_format: None,
                    },
                    oauth_flows: None,
                }],
            }],
        }
    }

    struct ManagedAlternativeFixture {
        adapter: OpenApiAdapter,
        oauth: OAuthService,
        store: OAuthStore,
        pool: sqlx::SqlitePool,
        binding: OpenApiBinding,
        configuration: serde_json::Map<String, serde_json::Value>,
        stored: StoredCredential,
        expected: Vec<OAuthBinding>,
        config: OAuthConnectionConfig,
        first_connection_revision: i64,
    }

    async fn managed_alternative_fixture() -> ManagedAlternativeFixture {
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
             ) VALUES (?, 'openapi', 'alternatives', 'Alternatives', ?, 'unknown', 0, 0, 1, 1)",
        )
        .bind("source-alternatives")
        .bind(r#"{"spec":{"type":"inline"},"allowPrivateNetwork":false}"#)
        .execute(&pool)
        .await
        .expect("source inserts");
        let keyring = Keyring::from_master_key([57; 32]).expect("test keyring");
        let store = OAuthStore::new(pool.clone(), keyring.clone());
        let config = OAuthConnectionConfig {
            issuer: "https://auth.example.test".to_owned(),
            authorization_endpoint: "https://auth.example.test/authorize".to_owned(),
            token_endpoint: "https://auth.example.test/token".to_owned(),
            client_id: "client".to_owned(),
            client_authentication: OAuthClientAuthentication::None,
            token_endpoint_auth_methods_supported: vec!["none".to_owned()],
            scopes: vec!["read".to_owned()],
            allow_private_network: false,
            resource: None,
        };
        let secrets = |token: &str| OAuthSecretSet {
            access_token: Some(token.to_owned()),
            token_type: Some("Bearer".to_owned()),
            granted_scopes: vec!["read".to_owned()],
            access_token_expires_at: Some(i64::MAX),
            ..OAuthSecretSet::default()
        };
        let first = store
            .create_connection(
                "source-alternatives",
                "oauthA",
                &config,
                Some(&secrets("token-a")),
                1,
            )
            .await
            .expect("first OAuth connection inserts");
        store
            .create_connection(
                "source-alternatives",
                "oauthB",
                &config,
                Some(&secrets("token-b")),
                1,
            )
            .await
            .expect("second OAuth connection inserts");
        let oauth = OAuthService::new(
            pool.clone(),
            keyring,
            "http://127.0.0.1:4788".to_owned(),
            OutboundPolicy::default(),
        );
        let expected = oauth
            .bindings_for_source("source-alternatives")
            .await
            .expect("approval OAuth snapshot reads");
        let document = json!({
            "openapi": "3.1.0",
            "info": { "title": "Managed alternatives" },
            "servers": [{ "url": "https://api.example.test" }],
            "components": { "securitySchemes": {
                "oauthA": { "type": "oauth2", "flows": { "authorizationCode": {
                    "authorizationUrl": "https://auth.example.test/authorize",
                    "tokenUrl": "https://auth.example.test/token",
                    "scopes": { "read": "Read" }
                }}},
                "oauthB": { "type": "oauth2", "flows": { "authorizationCode": {
                    "authorizationUrl": "https://auth.example.test/authorize",
                    "tokenUrl": "https://auth.example.test/token",
                    "scopes": { "read": "Read" }
                }}}
            }},
            "paths": { "/items": { "get": {
                "security": [{ "oauthA": ["read"] }, { "oauthB": ["read"] }],
                "responses": { "200": { "description": "ok" } }
            }}}
        });
        let binding = compile_document(&serde_json::to_vec(&document).unwrap())
            .expect("OAuth alternatives compile")
            .tools
            .remove(0)
            .binding;
        ManagedAlternativeFixture {
            adapter: OpenApiAdapter::with_oauth(oauth.clone()),
            oauth,
            store,
            pool,
            binding,
            configuration: json!({
                "spec": { "type": "inline" },
                "allowPrivateNetwork": false
            })
            .as_object()
            .unwrap()
            .clone(),
            stored: StoredCredential {
                revision: 1,
                credential: CredentialPayload {
                    schema_version: 1,
                    payload: json!({
                        "locator": { "type": "inline" },
                        "credentials": { "schemes": {} }
                    }),
                },
            },
            expected,
            config,
            first_connection_revision: first.connection.revision,
        }
    }

    #[test]
    fn credential_origin_normalization_covers_default_ports_idna_case_and_ipv6() {
        assert_eq!(
            normalized_http_origin("HTTPS://EXAMPLE.COM:443/v1").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            normalized_http_origin("https://bücher.example/v1").unwrap(),
            "https://xn--bcher-kva.example"
        );
        assert_eq!(
            normalized_http_origin("http://[2001:db8::1]:80/v1").unwrap(),
            "http://[2001:db8::1]"
        );
        assert_eq!(
            normalized_http_origin("https://example.com:8443/v1").unwrap(),
            "https://example.com:8443"
        );
    }

    #[test]
    fn confidential_transport_allows_https_and_only_loopback_http() {
        for allowed in [
            "https://api.example.test/v1",
            "http://localhost:8080/v1",
            "http://127.0.0.1/v1",
            "http://127.255.10.20/v1",
            "http://[::1]:8080/v1",
        ] {
            assert!(
                is_confidential_openapi_url(&Url::parse(allowed).expect("allowed URL parses")),
                "{allowed} should be confidential"
            );
        }
        for rejected in [
            "http://example.com/v1",
            "http://10.0.0.1/v1",
            "http://192.168.1.10/v1",
            "http://[fd00::1]/v1",
            "http://[::]/v1",
            "http://localhost.example/v1",
        ] {
            assert!(
                !is_confidential_openapi_url(&Url::parse(rejected).expect("rejected URL parses")),
                "{rejected} should be rejected"
            );
        }
    }

    #[test]
    fn credential_origins_are_compared_per_scheme_and_unused_keys_bind_empty() {
        let credential = StoredOpenApiCredentialV1 {
            locator: StoredOpenApiLocatorV1::Url {
                url: "https://spec.example/openapi.json".to_owned(),
                document_base_url: "https://spec.example/openapi.json".to_owned(),
            },
            credentials: OpenApiCredentialSet {
                schemes: [(
                    "unused".to_owned(),
                    OpenApiCredential::Bearer {
                        token: "secret".to_owned(),
                    },
                )]
                .into_iter()
                .collect(),
            },
            credential_origins: BTreeMap::from([
                ("first".to_owned(), vec!["https://one.example".to_owned()]),
                ("second".to_owned(), vec!["https://two.example".to_owned()]),
                ("unused".to_owned(), Vec::new()),
            ]),
        };
        let same_origins_new_paths = [
            origin_binding("https://one.example/new/path", "first"),
            origin_binding("https://two.example:443/other", "second"),
        ];
        verify_candidate_credential_origins(&credential, same_origins_new_paths.iter())
            .expect("same-origin path changes remain valid");

        let swapped = [
            origin_binding("https://two.example/path", "first"),
            origin_binding("https://one.example/path", "second"),
        ];
        assert_eq!(
            verify_candidate_credential_origins(&credential, swapped.iter())
                .expect_err("per-scheme destination swaps must fail")
                .code,
            "openapi_credential_origin_changed"
        );

        let newly_used = [origin_binding("https://one.example/path", "unused")];
        assert_eq!(
            verify_candidate_credential_origins(&credential, newly_used.iter())
                .expect_err("an unused configured credential has no approved destination")
                .code,
            "openapi_credential_origin_changed"
        );
    }

    #[tokio::test]
    async fn clearing_static_credentials_retires_only_unused_origin_pins() {
        let fixture = managed_alternative_fixture().await;
        let mut credential = StoredOpenApiCredentialV1 {
            locator: StoredOpenApiLocatorV1::Url {
                url: "https://spec.example/openapi.json".to_owned(),
                document_base_url: "https://spec.example/openapi.json".to_owned(),
            },
            credentials: OpenApiCredentialSet::default(),
            credential_origins: BTreeMap::from([
                ("oauthA".to_owned(), vec!["https://api.example".to_owned()]),
                (
                    "retiredStatic".to_owned(),
                    vec!["https://old.example".to_owned()],
                ),
            ]),
        };
        let mut unavailable = credential.clone();
        OpenApiAdapter::default()
            .retire_unused_credential_origins("source-alternatives", &mut unavailable)
            .await
            .expect("an unavailable OAuth registry fails closed");
        assert_eq!(
            unavailable.credential_origins,
            credential.credential_origins
        );
        fixture
            .adapter
            .retire_unused_credential_origins("source-alternatives", &mut credential)
            .await
            .expect("origin pins reconcile");
        assert!(credential.credential_origins.contains_key("oauthA"));
        assert!(!credential.credential_origins.contains_key("retiredStatic"));

        fixture
            .oauth
            .delete_connection(
                "source-alternatives",
                "oauthA",
                fixture.first_connection_revision,
            )
            .await
            .expect("managed OAuth connection deletes");
        fixture
            .adapter
            .retire_unused_credential_origins("source-alternatives", &mut credential)
            .await
            .expect("origin pins reconcile after OAuth deletion");
        assert!(credential.credential_origins.is_empty());
    }

    #[tokio::test]
    async fn approved_oauth_alternative_does_not_fall_through_when_preferred_disappears() {
        let fixture = managed_alternative_fixture().await;
        let prepared = fixture
            .adapter
            .prepare_invocation(
                "source-alternatives",
                &fixture.binding,
                &fixture.configuration,
                Some(&fixture.stored),
                &json!({}),
                Some(&fixture.expected),
            )
            .await
            .expect("the approval snapshot should select its first alternative");
        assert_eq!(
            prepared
                .oauth_authorization
                .as_ref()
                .map(|authorization| authorization.scheme_name.as_str()),
            Some("oauthA")
        );
        fixture
            .oauth
            .delete_connection(
                "source-alternatives",
                "oauthA",
                fixture.first_connection_revision,
            )
            .await
            .expect("the preferred connection deletes");
        assert!(
            fixture
                .oauth
                .ready_binding_for_scopes("source-alternatives", "oauthB", &["read".to_owned()])
                .await
                .expect("fallback binding reads")
                .is_some(),
            "the fallback remains eligible"
        );
        let error = match fixture
            .adapter
            .prepare_invocation(
                "source-alternatives",
                &fixture.binding,
                &fixture.configuration,
                Some(&fixture.stored),
                &json!({}),
                Some(&fixture.expected),
            )
            .await
        {
            Ok(_) => panic!("the approved connection may not fall through to another alternative"),
            Err(error) => error,
        };
        assert_eq!(error.code, "oauth_binding_changed");
        assert_eq!(error.category, ProtocolErrorCategory::Conflict);
    }

    #[tokio::test]
    async fn approved_oauth_alternative_does_not_fall_through_after_revision_change() {
        let fixture = managed_alternative_fixture().await;
        fixture
            .store
            .upsert_connection(
                "source-alternatives",
                "oauthA",
                fixture.first_connection_revision,
                &fixture.config,
                OAuthClientSecretUpdate::Preserve,
                2,
            )
            .await
            .expect("the preferred connection revision changes");
        assert!(
            fixture
                .oauth
                .ready_binding_for_scopes("source-alternatives", "oauthB", &["read".to_owned()])
                .await
                .expect("fallback binding reads")
                .is_some(),
            "the fallback remains eligible"
        );
        let error = match fixture
            .adapter
            .prepare_invocation(
                "source-alternatives",
                &fixture.binding,
                &fixture.configuration,
                Some(&fixture.stored),
                &json!({}),
                Some(&fixture.expected),
            )
            .await
        {
            Ok(_) => panic!("a changed approved connection may not fall through"),
            Err(error) => error,
        };
        assert_eq!(error.code, "oauth_binding_changed");
        assert_eq!(error.category, ProtocolErrorCategory::Conflict);
    }

    #[tokio::test]
    async fn approval_scope_snapshot_keeps_the_originally_eligible_alternative() {
        let mut fixture = managed_alternative_fixture().await;
        sqlx::query(
            "UPDATE oauth_connections SET granted_scopes_json = '[]' \
             WHERE source_id = ? AND credential_key = 'oauthA'",
        )
        .bind("source-alternatives")
        .execute(&fixture.pool)
        .await
        .expect("first alternative loses its grant before approval");
        fixture.expected = fixture
            .oauth
            .bindings_for_source("source-alternatives")
            .await
            .expect("approval OAuth snapshot reads");
        assert_eq!(fixture.expected.len(), 2);
        assert!(
            fixture
                .expected
                .iter()
                .find(|binding| binding.credential_key == "oauthA")
                .expect("first OAuth alternative is snapshotted")
                .granted_scopes
                .is_empty()
        );

        let selected = fixture
            .adapter
            .prepare_invocation(
                "source-alternatives",
                &fixture.binding,
                &fixture.configuration,
                Some(&fixture.stored),
                &json!({}),
                Some(&fixture.expected),
            )
            .await
            .expect("the scope-eligible second alternative prepares");
        assert_eq!(
            selected
                .oauth_authorization
                .as_ref()
                .map(|authorization| authorization.scheme_name.as_str()),
            Some("oauthB")
        );

        sqlx::query(
            "UPDATE oauth_connections SET granted_scopes_json = '[\"read\"]' \
             WHERE source_id = ? AND credential_key = 'oauthA'",
        )
        .bind("source-alternatives")
        .execute(&fixture.pool)
        .await
        .expect("first alternative gains scope while approval waits");
        assert!(
            !fixture
                .oauth
                .bindings_match("source-alternatives", &fixture.expected)
                .await
                .expect("approval OAuth snapshot compares"),
            "a changed approval-time scope snapshot must become stale"
        );
        let still_selected = fixture
            .adapter
            .prepare_invocation(
                "source-alternatives",
                &fixture.binding,
                &fixture.configuration,
                Some(&fixture.stored),
                &json!({}),
                Some(&fixture.expected),
            )
            .await
            .expect("selection is reconstructed from approval-time scopes");
        assert_eq!(
            still_selected
                .oauth_authorization
                .as_ref()
                .map(|authorization| authorization.scheme_name.as_str()),
            Some("oauthB")
        );
    }

    #[tokio::test]
    async fn prepared_oauth_invocation_rechecks_active_state_before_dispatch() {
        let mut fixture = managed_alternative_fixture().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        fixture.binding.server_url = format!(
            "http://{}",
            listener.local_addr().expect("listener address reads")
        );
        fixture.configuration.insert(
            "allowPrivateNetwork".to_owned(),
            serde_json::Value::Bool(true),
        );
        let prepared = fixture
            .adapter
            .prepare_invocation(
                "source-alternatives",
                &fixture.binding,
                &fixture.configuration,
                Some(&fixture.stored),
                &json!({}),
                Some(&fixture.expected),
            )
            .await
            .expect("active OAuth invocation prepares");
        fixture
            .store
            .begin_authorization(
                "source-alternatives",
                "oauthA",
                fixture.first_connection_revision,
                &[9_u8; 32],
                10,
                100,
            )
            .await
            .expect("reauthorization transitions the selected connection to connecting");

        let error = fixture
            .adapter
            .execute_invocation(prepared)
            .await
            .expect_err("a connecting OAuth binding cannot dispatch");
        assert_eq!(error.code(), "oauth_binding_changed");
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "the upstream must receive no request after the OAuth state transition"
        );
    }

    #[tokio::test]
    async fn prepared_oauth_invocation_rechecks_connection_existence_before_dispatch() {
        let mut fixture = managed_alternative_fixture().await;
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream listener binds");
        fixture.binding.server_url = format!(
            "http://{}",
            listener.local_addr().expect("listener address reads")
        );
        fixture.configuration.insert(
            "allowPrivateNetwork".to_owned(),
            serde_json::Value::Bool(true),
        );
        let prepared = fixture
            .adapter
            .prepare_invocation(
                "source-alternatives",
                &fixture.binding,
                &fixture.configuration,
                Some(&fixture.stored),
                &json!({}),
                Some(&fixture.expected),
            )
            .await
            .expect("active OAuth invocation prepares");
        fixture
            .oauth
            .delete_connection(
                "source-alternatives",
                "oauthA",
                fixture.first_connection_revision,
            )
            .await
            .expect("the selected OAuth connection deletes");

        let error = fixture
            .adapter
            .execute_invocation(prepared)
            .await
            .expect_err("a deleted OAuth binding cannot dispatch");
        assert_eq!(error.code(), "oauth_binding_changed");
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "the upstream must receive no request after OAuth revocation"
        );
    }

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
            granted_scopes: Vec::new(),
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
        let pending = oauth_store
            .create_connection(
                "source-id",
                "oauthPending",
                &connection_config,
                Some(&OAuthSecretSet {
                    access_token: Some("pending-access-token".to_owned()),
                    token_type: Some("Bearer".to_owned()),
                    granted_scopes: vec!["write:items".to_owned()],
                    access_token_expires_at: Some(i64::MAX),
                    ..OAuthSecretSet::default()
                }),
                1,
            )
            .await
            .expect("pending OAuth connection inserts");
        sqlx::query("UPDATE oauth_connections SET status = 'connecting' WHERE id = ?")
            .bind(&pending.connection.id)
            .execute(&pool)
            .await
            .expect("first OAuth alternative becomes pending");
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
            pool.clone(),
            keyring,
            "http://127.0.0.1:4788".to_owned(),
            OutboundPolicy::default(),
        );
        let expected_oauth_bindings = oauth
            .bindings_for_source("source-id")
            .await
            .expect("approval OAuth bindings snapshot");
        assert_eq!(expected_oauth_bindings.len(), 1);
        assert_eq!(expected_oauth_bindings[0].credential_key, "oauthActive");
        sqlx::query("UPDATE oauth_connections SET status = 'active' WHERE id = ?")
            .bind(&pending.connection.id)
            .execute(&pool)
            .await
            .expect("first OAuth alternative becomes ready while approval waits");
        assert!(
            oauth
                .bindings_match("source-id", &expected_oauth_bindings)
                .await
                .expect("selected approval binding remains valid"),
            "a newly ready unselected alternative must not invalidate the approved binding"
        );
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
        let mut insecure = adapter
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
        insecure.request.url = Url::parse(&format!(
            "http://0.0.0.0:{}/write",
            listener
                .local_addr()
                .expect("listener address reads")
                .port()
        ))
        .expect("insecure target URL parses");
        assert_eq!(
            insecure
                .oauth_authorization
                .as_ref()
                .map(|authorization| authorization.scheme_name.as_str()),
            Some("oauthActive")
        );
        assert!(!insecure.request.headers.contains_key(AUTHORIZATION));
        let error = adapter
            .execute_invocation(insecure)
            .await
            .expect_err("managed OAuth cannot dispatch over non-loopback HTTP");
        assert_eq!(error.code(), "insecure_openapi_transport");
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "the insecure target must receive no managed OAuth request"
        );
        let mut poisoned = adapter
            .prepare_invocation(
                "source-id",
                &compiled.tools[0].binding,
                &configuration,
                Some(&stored),
                &json!({}),
                Some(&expected_oauth_bindings),
            )
            .await
            .expect("managed OAuth invocation prepares for a poisoned localhost");
        poisoned.request.url = Url::parse(&format!(
            "http://localhost:{}/write",
            listener
                .local_addr()
                .expect("listener address reads")
                .port()
        ))
        .expect("poisoned localhost URL parses");
        let poisoned_client = HardenedHttpClient::new(poisoned.policy.clone())
            .with_test_dns_resolution(
                "localhost",
                vec!["8.8.8.8".parse().expect("test IP parses")],
            );
        let error = adapter
            .execute_invocation_with_client(poisoned, poisoned_client)
            .await
            .expect_err("managed OAuth cannot dispatch when localhost resolves off loopback");
        assert_eq!(error.code(), "insecure_openapi_transport");
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "a poisoned localhost must receive no managed OAuth request"
        );
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
            .expect("loopback managed OAuth invocation prepares");
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
