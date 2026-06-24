use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{
    Method,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::sync::Semaphore;
use url::{Host, Url};

use super::{
    ConfiguredCredential, CredentialMetadata, ProtocolError, ProtocolErrorCategory,
    ProtocolExecutionResponse, ProtocolHttpMetadata, ProtocolResponseError, protocol_catalog_error,
    protocol_outbound_error,
};
use crate::{
    catalog::{
        ArtifactKind, AuditContext, CatalogSnapshot, CatalogStore, CatalogSyncResult, CreateSource,
        CredentialPayload, InitialCatalogSnapshot, OAuthBindingExpectation, SourceKind,
        SourceRecord, StagedArtifact, StagedTool, StagedToolBinding, StoredCredential, ToolBinding,
    },
    graphql::{
        CompiledGraphql, GraphqlBindingV1, GraphqlError, GraphqlOperation, INTROSPECTION_QUERY,
        compile_introspection,
    },
    oauth::{OAuthBinding, OAuthError, OAuthService},
    outbound::{HardenedHttpClient, OutboundError, OutboundPolicy, OutboundRequest, parse_url},
};

const GRAPHQL_CREDENTIAL_SCHEMA_VERSION: u32 = 1;
const MAX_ENDPOINT_BYTES: usize = 16 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_HEADER_NAME_BYTES: usize = 256;
const MAX_INTROSPECTION_BYTES: usize = 16 * 1024 * 1024;
const GRAPHQL_COMPILE_CONCURRENCY: usize = 2;
static GRAPHQL_COMPILE_PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateGraphqlSource {
    pub display_name: String,
    pub preferred_slug: Option<String>,
    pub description: Option<String>,
    pub endpoint: String,
    #[serde(default)]
    pub allow_private_network: bool,
    pub credential: Option<GraphqlCredential>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GraphqlCredential {
    Bearer { token: String },
    Basic { username: String, password: String },
    ApiKeyHeader { name: String, value: String },
    OAuthAccessToken { access_token: String },
}

impl GraphqlCredential {
    fn credential_type(&self) -> &'static str {
        match self {
            Self::Bearer { .. } => "bearer",
            Self::Basic { .. } => "basic",
            Self::ApiKeyHeader { .. } => "api_key_header",
            Self::OAuthAccessToken { .. } => "oauth_access_token",
        }
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Bearer { token } => validate_secret(token),
            Self::Basic { username, password } => {
                validate_secret(username)?;
                if username.contains(':') {
                    return Err(invalid_credentials());
                }
                validate_secret(password)
            }
            Self::ApiKeyHeader { name, value } => {
                if name.is_empty() || name.len() > MAX_HEADER_NAME_BYTES {
                    return Err(invalid_credentials());
                }
                let name =
                    HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid_credentials())?;
                if protected_header(&name) {
                    return Err(invalid_credentials());
                }
                validate_secret(value)
            }
            Self::OAuthAccessToken { access_token } => validate_secret(access_token),
        }
    }

    fn apply(&self, headers: &mut HeaderMap) -> Result<(), ProtocolError> {
        self.validate()?;
        let (name, mut value) = match self {
            Self::Bearer { token }
            | Self::OAuthAccessToken {
                access_token: token,
            } => (
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| invalid_credentials())?,
            ),
            Self::Basic { username, password } => {
                let encoded = STANDARD.encode(format!("{username}:{password}"));
                (
                    header::AUTHORIZATION,
                    HeaderValue::from_str(&format!("Basic {encoded}"))
                        .map_err(|_| invalid_credentials())?,
                )
            }
            Self::ApiKeyHeader { name, value } => (
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid_credentials())?,
                HeaderValue::from_str(value).map_err(|_| invalid_credentials())?,
            ),
        };
        value.set_sensitive(true);
        headers.insert(name, value);
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GraphqlSourceConfigurationV1 {
    endpoint: String,
    allow_private_network: bool,
}

impl GraphqlSourceConfigurationV1 {
    fn decode(configuration: &Map<String, Value>) -> Result<Self, ProtocolError> {
        let decoded: Self =
            serde_json::from_value(Value::Object(configuration.clone())).map_err(|_| {
                ProtocolError::corrupt(
                    "invalid_source_configuration",
                    "The stored GraphQL source configuration is invalid.",
                )
            })?;
        validate_endpoint(&decoded.endpoint).map_err(|_| {
            ProtocolError::corrupt(
                "invalid_source_configuration",
                "The stored GraphQL source configuration is invalid.",
            )
        })?;
        if public_endpoint(&decoded.endpoint).ok().as_deref() != Some(decoded.endpoint.as_str()) {
            return Err(ProtocolError::corrupt(
                "invalid_source_configuration",
                "The stored GraphQL source configuration is invalid.",
            ));
        }
        Ok(decoded)
    }

    fn encode(&self) -> Result<Map<String, Value>, ProtocolError> {
        serde_json::to_value(self)
            .map_err(internal_encoding_error)?
            .as_object()
            .cloned()
            .ok_or_else(internal_error)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredGraphqlCredentialV1 {
    endpoint: String,
    credential: Option<GraphqlCredential>,
}

impl StoredGraphqlCredentialV1 {
    fn decode(stored: &StoredCredential) -> Result<Self, ProtocolError> {
        if stored.credential.schema_version != GRAPHQL_CREDENTIAL_SCHEMA_VERSION {
            return Err(ProtocolError::corrupt(
                "unsupported_credential_schema",
                "The stored GraphQL credential schema is not supported.",
            ));
        }
        let decoded: Self =
            serde_json::from_value(stored.credential.payload.clone()).map_err(|_| {
                ProtocolError::corrupt(
                    "invalid_source_credentials",
                    "The stored GraphQL credential state is invalid.",
                )
            })?;
        validate_endpoint(&decoded.endpoint).map_err(|_| {
            ProtocolError::corrupt(
                "invalid_source_credentials",
                "The stored GraphQL credential state is invalid.",
            )
        })?;
        if decoded
            .credential
            .as_ref()
            .is_some_and(|value| value.validate().is_err())
        {
            return Err(ProtocolError::corrupt(
                "invalid_source_credentials",
                "The stored GraphQL credential state is invalid.",
            ));
        }
        Ok(decoded)
    }

    fn payload(&self) -> Result<CredentialPayload, ProtocolError> {
        Ok(CredentialPayload {
            schema_version: GRAPHQL_CREDENTIAL_SCHEMA_VERSION,
            payload: serde_json::to_value(self).map_err(internal_encoding_error)?,
        })
    }
}

pub struct PreparedGraphqlInvocation {
    request: OutboundRequest,
    policy: OutboundPolicy,
    mutation: bool,
    oauth_binding: Option<OAuthBinding>,
}

#[derive(Debug, Error)]
pub enum GraphqlInvocationError {
    #[error("GraphQL transport failed")]
    Outbound {
        #[source]
        source: OutboundError,
        outcome_unknown: bool,
    },
    #[error("GraphQL mutation outcome is unknown")]
    Indeterminate,
    #[error("GraphQL OAuth authorization is unavailable")]
    OAuth,
}

impl GraphqlInvocationError {
    pub const fn outcome_unknown(&self) -> bool {
        match self {
            Self::Outbound {
                outcome_unknown, ..
            } => *outcome_unknown,
            Self::Indeterminate => true,
            Self::OAuth => false,
        }
    }
}

#[derive(Clone, Default)]
pub struct GraphqlAdapter {
    oauth: Option<OAuthService>,
}

impl GraphqlAdapter {
    pub(crate) fn with_oauth(oauth: OAuthService) -> Self {
        Self { oauth: Some(oauth) }
    }

    pub(crate) async fn oauth_binding_observation(
        &self,
        source_id: &str,
        stored: Option<&StoredCredential>,
        expected_bindings: Option<&[OAuthBinding]>,
    ) -> Result<Option<OAuthBinding>, ProtocolError> {
        let stored = stored.ok_or_else(|| {
            ProtocolError::corrupt(
                "source_credentials_missing",
                "The source credential state is missing.",
            )
        })?;
        if StoredGraphqlCredentialV1::decode(stored)?
            .credential
            .is_some()
        {
            return Ok(None);
        }
        if let Some(expected_bindings) = expected_bindings {
            return Ok(expected_bindings
                .iter()
                .find(|binding| binding.credential_key == "default")
                .cloned());
        }
        let Some(oauth) = &self.oauth else {
            return Ok(None);
        };
        oauth
            .binding(source_id, "default")
            .await
            .map_err(protocol_oauth_error)
    }

    pub fn prepare_invocation(
        &self,
        binding: &GraphqlBindingV1,
        source_configuration: &Map<String, Value>,
        stored: Option<&StoredCredential>,
        arguments: &Value,
        oauth_binding: Option<OAuthBinding>,
    ) -> Result<PreparedGraphqlInvocation, ProtocolError> {
        if oauth_binding
            .as_ref()
            .is_some_and(|binding| binding.credential_key != "default")
        {
            return Err(ProtocolError::corrupt(
                "invalid_oauth_binding",
                "The GraphQL source OAuth binding is invalid.",
            ));
        }
        binding.validate().map_err(|_| invalid_binding())?;
        let configuration = GraphqlSourceConfigurationV1::decode(source_configuration)?;
        let stored = stored.ok_or_else(|| {
            ProtocolError::corrupt(
                "source_credentials_missing",
                "The source credential state is missing.",
            )
        })?;
        let credential = StoredGraphqlCredentialV1::decode(stored)?;
        if public_endpoint(&credential.endpoint).map_err(|_| invalid_binding())?
            != configuration.endpoint
        {
            return Err(ProtocolError::corrupt(
                "source_endpoint_mismatch",
                "The stored GraphQL endpoint does not match its source configuration.",
            ));
        }
        let arguments = arguments.as_object().ok_or_else(invalid_arguments)?;
        let allowed = binding
            .variables
            .iter()
            .map(|variable| &variable.name)
            .collect::<BTreeSet<_>>();
        if arguments.keys().any(|key| !allowed.contains(key)) {
            return Err(invalid_arguments());
        }
        let body = serde_json::to_vec(&json!({
            "query": binding.document,
            "operationName": binding.operation_name,
            "variables": arguments,
        }))
        .map_err(internal_encoding_error)?;
        let policy = OutboundPolicy {
            allow_private_networks: configuration.allow_private_network,
            ..OutboundPolicy::default()
        };
        let url = parse_url(&credential.endpoint, &policy).map_err(protocol_outbound_error)?;
        let mut request = OutboundRequest::new(Method::POST, url);
        request.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        request.headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/graphql-response+json, application/json"),
        );
        if let Some(credential) = &credential.credential {
            if oauth_binding.is_some() {
                return Err(ProtocolError::corrupt(
                    "ambiguous_source_credentials",
                    "The GraphQL source has conflicting credential bindings.",
                ));
            }
            credential.apply(&mut request.headers)?;
        }
        request.body = body;
        Ok(PreparedGraphqlInvocation {
            request,
            policy,
            mutation: binding.operation == GraphqlOperation::Mutation,
            oauth_binding,
        })
    }

    pub async fn execute_invocation(
        &self,
        prepared: PreparedGraphqlInvocation,
    ) -> Result<ProtocolExecutionResponse, GraphqlInvocationError> {
        let PreparedGraphqlInvocation {
            mut request,
            policy,
            mutation,
            oauth_binding,
        } = prepared;
        if let Some(binding) = oauth_binding {
            let oauth = self.oauth.as_ref().ok_or(GraphqlInvocationError::OAuth)?;
            let access_token = oauth
                .access_token_for_binding(&binding)
                .await
                .map_err(|_| GraphqlInvocationError::OAuth)?;
            let mut authorization =
                HeaderValue::from_str(&format!("Bearer {}", access_token.expose()))
                    .map_err(|_| GraphqlInvocationError::OAuth)?;
            authorization.set_sensitive(true);
            request.headers.insert(header::AUTHORIZATION, authorization);
        }
        let response = HardenedHttpClient::new(policy)
            .execute(request)
            .await
            .map_err(|source| {
                let outcome_unknown = mutation && may_have_dispatched(&source);
                GraphqlInvocationError::Outbound {
                    source,
                    outcome_unknown,
                }
            })?;
        let http = Some(ProtocolHttpMetadata {
            status: response.status.as_u16(),
            headers: safe_response_headers(&response.headers),
            truncated: false,
        });
        if !response.status.is_success() {
            if mutation {
                return Err(GraphqlInvocationError::Indeterminate);
            }
            return Ok(protocol_failure(
                "upstream_http_error",
                "The upstream GraphQL API returned an HTTP error response.",
                http,
            ));
        }
        let value: Value = match serde_json::from_slice(&response.body) {
            Ok(value) => value,
            Err(_) => {
                return invalid_execution_response(mutation, http);
            }
        };
        let Some(object) = value.as_object() else {
            return invalid_execution_response(mutation, http);
        };
        if let Some(errors) = object.get("errors") {
            match errors {
                Value::Null => {}
                Value::Array(errors) if errors.is_empty() => {}
                Value::Array(errors) => {
                    if graphql_errors_are_well_formed(errors) {
                        if mutation {
                            return Err(GraphqlInvocationError::Indeterminate);
                        }
                        return Ok(protocol_failure(
                            "graphql_error",
                            "The upstream GraphQL operation returned an error.",
                            http,
                        ));
                    }
                    return invalid_execution_response(mutation, http);
                }
                _ => return invalid_execution_response(mutation, http),
            }
        }
        let Some(data) = object.get("data").and_then(Value::as_object) else {
            return invalid_execution_response(mutation, http);
        };
        let Some(result) = data.get("result") else {
            return invalid_execution_response(mutation, http);
        };
        Ok(ProtocolExecutionResponse {
            ok: true,
            data: Some(result.clone()),
            error: None,
            http,
        })
    }

    pub async fn create_source(
        &self,
        catalog: &CatalogStore,
        input: CreateGraphqlSource,
        audit: AuditContext<'_>,
    ) -> Result<SourceRecord, ProtocolError> {
        validate_endpoint(&input.endpoint).map_err(protocol_outbound_error)?;
        if let Some(credential) = &input.credential {
            credential.validate()?;
        }
        let configuration = GraphqlSourceConfigurationV1 {
            endpoint: public_endpoint(&input.endpoint).map_err(protocol_outbound_error)?,
            allow_private_network: input.allow_private_network,
        };
        let stored = StoredGraphqlCredentialV1 {
            endpoint: input.endpoint,
            credential: input.credential,
        };
        let discovery = fetch_and_compile(&configuration, &stored, None).await;
        let authorization_required = stored.credential.is_none()
            && discovery
                .as_ref()
                .is_err_and(|error| error.code == "authorization_required");
        let preferred_slug = input
            .preferred_slug
            .unwrap_or_else(|| input.display_name.clone());
        let create = CreateSource {
            kind: SourceKind::Graphql,
            preferred_slug,
            display_name: input.display_name,
            description: input.description,
            configuration: configuration.encode()?,
        };
        let payload = stored.payload()?;
        let (source, _) = match discovery {
            Ok(compiled) => catalog
                .create_source_with_catalog(
                    create,
                    &payload,
                    initial_catalog_snapshot(&compiled),
                    staged_bindings(&compiled),
                    audit,
                )
                .await
                .map_err(protocol_catalog_error)?,
            Err(_error) if authorization_required => catalog
                .create_authorization_required_source_with_catalog(
                    create,
                    &payload,
                    InitialCatalogSnapshot {
                        artifacts: Vec::new(),
                        tools: Vec::new(),
                    },
                    Vec::new(),
                    audit,
                )
                .await
                .map_err(protocol_catalog_error)?,
            Err(error) => return Err(error),
        };
        Ok(source)
    }

    pub async fn refresh_source(
        &self,
        catalog: &CatalogStore,
        source: SourceRecord,
        audit: AuditContext<'_>,
    ) -> Result<CatalogSyncResult, ProtocolError> {
        if source.kind != SourceKind::Graphql {
            return Err(ProtocolError::corrupt(
                "source_protocol_mismatch",
                "The stored source does not match the GraphQL protocol.",
            ));
        }
        let configuration = GraphqlSourceConfigurationV1::decode(&source.configuration)?;
        let stored_record = required_stored_credential(catalog, &source.id).await?;
        let stored = StoredGraphqlCredentialV1::decode(&stored_record)?;
        let oauth_binding = if stored.credential.is_none() {
            match &self.oauth {
                Some(oauth) => oauth
                    .binding(&source.id, "default")
                    .await
                    .map_err(protocol_oauth_error)?,
                None => None,
            }
        } else {
            None
        };
        let access_token = oauth_access(self, oauth_binding.clone()).await?;
        let oauth_expectation = if stored.credential.is_none() {
            Some(match (&oauth_binding, access_token.as_ref()) {
                (Some(binding), Some(_access_token)) => OAuthBindingExpectation::Exact {
                    credential_key: "default".to_owned(),
                    connection_id: binding.connection_id.clone(),
                    config_revision: binding.config_revision,
                },
                (None, None) => OAuthBindingExpectation::Absent {
                    credential_key: "default".to_owned(),
                },
                _ => {
                    return Err(ProtocolError::new(
                        ProtocolErrorCategory::Internal,
                        "oauth_binding_invalid",
                        "The managed OAuth connection could not be resolved safely.",
                    ));
                }
            })
        } else {
            None
        };
        let compiled = fetch_and_compile(&configuration, &stored, access_token).await?;
        let snapshot = CatalogSnapshot {
            expected_source_revision: source.revision,
            expected_credential_revision: Some(stored_record.revision),
            artifacts: staged_artifacts(&compiled),
            tools: staged_tools(&compiled),
        };
        let bindings = staged_bindings(&compiled);
        if let Some(expectation) = oauth_expectation {
            catalog
                .sync_catalog_with_bindings_and_oauth_binding(
                    &source.id,
                    snapshot,
                    bindings,
                    expectation,
                    audit,
                )
                .await
                .map_err(protocol_catalog_error)
        } else {
            catalog
                .sync_catalog_with_bindings(&source.id, snapshot, bindings, audit)
                .await
                .map_err(protocol_catalog_error)
        }
    }

    pub async fn credential_metadata(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let stored = required_stored_credential(catalog, source_id).await?;
        let credential = StoredGraphqlCredentialV1::decode(&stored)?;
        Ok(credential_metadata(stored.revision, credential))
    }

    pub async fn replace_credentials(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        expected_revision: i64,
        credential: Option<GraphqlCredential>,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        if let Some(credential) = &credential {
            credential.validate()?;
        }
        self.replace_optional_credentials(catalog, source_id, expected_revision, credential, audit)
            .await
    }

    pub async fn clear_credentials(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        expected_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        self.replace_optional_credentials(catalog, source_id, expected_revision, None, audit)
            .await
    }

    async fn replace_optional_credentials(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        expected_revision: i64,
        credential: Option<GraphqlCredential>,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let stored = required_stored_credential(catalog, source_id).await?;
        if stored.revision != expected_revision {
            return Err(revision_conflict());
        }
        let current = StoredGraphqlCredentialV1::decode(&stored)?;
        let replacement = StoredGraphqlCredentialV1 {
            endpoint: current.endpoint,
            credential,
        };
        let payload = replacement.payload()?;
        catalog
            .put_credential(source_id, &payload, Some(expected_revision), audit)
            .await
            .map_err(protocol_catalog_error)?;
        let revision = expected_revision
            .checked_add(1)
            .ok_or_else(internal_error)?;
        Ok(credential_metadata(revision, replacement))
    }
}

async fn oauth_access(
    adapter: &GraphqlAdapter,
    binding: Option<OAuthBinding>,
) -> Result<Option<crate::oauth::OAuthAccessToken>, ProtocolError> {
    let Some(binding) = binding else {
        return Ok(None);
    };
    let oauth = adapter.oauth.as_ref().ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorCategory::Internal,
            "oauth_service_unavailable",
            "Managed OAuth is unavailable for this source.",
        )
    })?;
    oauth
        .access_token_for_binding(&binding)
        .await
        .map(Some)
        .map_err(protocol_oauth_error)
}

async fn fetch_and_compile(
    configuration: &GraphqlSourceConfigurationV1,
    stored: &StoredGraphqlCredentialV1,
    oauth_access_token: Option<crate::oauth::OAuthAccessToken>,
) -> Result<CompiledGraphql, ProtocolError> {
    let permit = try_compile_permit(
        GRAPHQL_COMPILE_PERMITS
            .get_or_init(|| Arc::new(Semaphore::new(GRAPHQL_COMPILE_CONCURRENCY)))
            .clone(),
    )?;
    let policy = OutboundPolicy {
        allow_private_networks: configuration.allow_private_network,
        max_response_bytes: MAX_INTROSPECTION_BYTES,
        ..OutboundPolicy::default()
    };
    if public_endpoint(&stored.endpoint).map_err(protocol_outbound_error)?
        != configuration.endpoint.as_str()
    {
        return Err(ProtocolError::corrupt(
            "source_endpoint_mismatch",
            "The stored GraphQL endpoint does not match its source configuration.",
        ));
    }
    let url = parse_url(&stored.endpoint, &policy).map_err(protocol_outbound_error)?;
    let mut request = OutboundRequest::new(Method::POST, url);
    request.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    request.headers.insert(
        header::ACCEPT,
        HeaderValue::from_static("application/graphql-response+json, application/json"),
    );
    if let Some(credential) = &stored.credential {
        credential.apply(&mut request.headers)?;
    } else if let Some(access_token) = oauth_access_token {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", access_token.expose()))
            .map_err(|_| protocol_oauth_error(OAuthError::Internal))?;
        authorization.set_sensitive(true);
        request.headers.insert(header::AUTHORIZATION, authorization);
    }
    request.body = serde_json::to_vec(&json!({
        "query": INTROSPECTION_QUERY,
        "operationName": "ExecutorIntrospection",
        "variables": {},
    }))
    .map_err(internal_encoding_error)?;
    let response = HardenedHttpClient::new(policy)
        .execute(request)
        .await
        .map_err(protocol_outbound_error)?;
    if stored.credential.is_none()
        && matches!(
            response.status,
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        )
    {
        return Err(authorization_required_error());
    }
    if !response.status.is_success() {
        return Err(ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            "upstream_http_error",
            "The GraphQL introspection request failed.",
        ));
    }
    compile_introspection_bounded(response.body, permit).await
}

enum GraphqlCompileTaskError {
    InvalidJson,
    AuthorizationRequired,
    Rejected,
    Compile(GraphqlError),
}

fn try_compile_permit(
    permits: Arc<Semaphore>,
) -> Result<tokio::sync::OwnedSemaphorePermit, ProtocolError> {
    permits.try_acquire_owned().map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "graphql_compiler_busy",
            "GraphQL schema import is busy. Retry shortly.",
        )
    })
}

async fn compile_introspection_bounded(
    response: Vec<u8>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Result<CompiledGraphql, ProtocolError> {
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let response: Value =
            serde_json::from_slice(&response).map_err(|_| GraphqlCompileTaskError::InvalidJson)?;
        let errors = response.as_object().and_then(|object| object.get("errors"));
        if errors.is_some_and(graphql_errors_require_authorization) {
            return Err(GraphqlCompileTaskError::AuthorizationRequired);
        }
        if errors.is_some_and(non_empty_graphql_errors) {
            return Err(GraphqlCompileTaskError::Rejected);
        }
        compile_introspection(response).map_err(GraphqlCompileTaskError::Compile)
    })
    .await
    .map_err(|_| internal_error())?
    .map_err(|error| match error {
        GraphqlCompileTaskError::InvalidJson => ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            "invalid_graphql_response",
            "The GraphQL introspection response is invalid.",
        ),
        GraphqlCompileTaskError::AuthorizationRequired => authorization_required_error(),
        GraphqlCompileTaskError::Rejected => ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            "graphql_introspection_failed",
            "The GraphQL server rejected introspection.",
        ),
        GraphqlCompileTaskError::Compile(error) => graphql_error(error),
    })
}

fn initial_catalog_snapshot(compiled: &CompiledGraphql) -> InitialCatalogSnapshot {
    InitialCatalogSnapshot {
        artifacts: staged_artifacts(compiled),
        tools: staged_tools(compiled),
    }
}

fn staged_artifacts(compiled: &CompiledGraphql) -> Vec<StagedArtifact> {
    vec![StagedArtifact {
        kind: ArtifactKind::GraphqlSchema,
        stable_key: "schema".to_owned(),
        content: compiled.document.clone(),
    }]
}

fn staged_tools(compiled: &CompiledGraphql) -> Vec<StagedTool> {
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

fn staged_bindings(compiled: &CompiledGraphql) -> Vec<StagedToolBinding> {
    compiled
        .tools
        .iter()
        .map(|tool| StagedToolBinding {
            stable_key: tool.stable_key.clone(),
            binding: ToolBinding::GraphqlV1(tool.binding.clone()),
        })
        .collect()
}

fn validate_endpoint(value: &str) -> Result<(), OutboundError> {
    if value.len() > MAX_ENDPOINT_BYTES {
        return Err(OutboundError::InvalidUrl);
    }
    let url = Url::parse(value).map_err(|_| OutboundError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(OutboundError::UnsupportedScheme);
    }
    if url.scheme() == "http" && !loopback_endpoint(&url) {
        return Err(OutboundError::UnsupportedScheme);
    }
    if url.host().is_none() {
        return Err(OutboundError::MissingHost);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OutboundError::CredentialsNotAllowed);
    }
    if url.fragment().is_some() {
        return Err(OutboundError::FragmentNotAllowed);
    }
    Ok(())
}

fn loopback_endpoint(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(hostname)) => {
            hostname.eq_ignore_ascii_case("localhost")
                || hostname.to_ascii_lowercase().ends_with(".localhost")
        }
        None => false,
    }
}

fn public_endpoint(value: &str) -> Result<String, OutboundError> {
    validate_endpoint(value)?;
    let mut url = Url::parse(value).map_err(|_| OutboundError::InvalidUrl)?;
    url.set_path("/");
    url.set_query(None);
    Ok(url.to_string())
}

fn may_have_dispatched(error: &OutboundError) -> bool {
    matches!(
        error,
        OutboundError::Timeout
            | OutboundError::Request
            | OutboundError::ResponseHeadersTooLarge
            | OutboundError::ResponseBodyTooLarge
            | OutboundError::UnsupportedContentEncoding
    )
}

fn validate_secret(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES || value.chars().any(char::is_control)
    {
        Err(invalid_credentials())
    } else {
        Ok(())
    }
}

fn protected_header(name: &HeaderName) -> bool {
    name == header::AUTHORIZATION
        || name == header::ACCEPT
        || name == header::ACCEPT_ENCODING
        || name == header::CONTENT_TYPE
        || name == header::CONTENT_LENGTH
        || name == header::HOST
        || name == header::CONNECTION
        || name == header::TRANSFER_ENCODING
        || name == header::TE
        || name == header::TRAILER
        || name == header::UPGRADE
        || name == header::REFERER
        || name == header::COOKIE
        || name == header::ORIGIN
        || name == "keep-alive"
        || name == "forwarded"
        || name == "via"
        || name == "x-http-method-override"
        || name == "x-method-override"
        || name == "x-original-url"
        || name == "x-rewrite-url"
        || name == "x-real-ip"
        || name.as_str().starts_with("x-forwarded-")
        || name.as_str().starts_with("proxy-")
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

fn non_empty_graphql_errors(value: &Value) -> bool {
    !matches!(value, Value::Array(errors) if errors.is_empty()) && !value.is_null()
}

fn graphql_errors_require_authorization(value: &Value) -> bool {
    let Some(errors) = value.as_array().filter(|errors| !errors.is_empty()) else {
        return false;
    };
    errors.iter().any(|error| {
        let Some(error) = error.as_object() else {
            return false;
        };
        let extensions = error.get("extensions").and_then(Value::as_object);
        let code = extensions
            .and_then(|extensions| extensions.get("code"))
            .and_then(Value::as_str)
            .or_else(|| error.get("code").and_then(Value::as_str));
        if code.is_some_and(|code| {
            matches!(
                code.to_ascii_uppercase().as_str(),
                "UNAUTHENTICATED"
                    | "UNAUTHORIZED"
                    | "FORBIDDEN"
                    | "AUTHENTICATION_REQUIRED"
                    | "AUTHORIZATION_REQUIRED"
                    | "ACCESS_DENIED"
                    | "INVALID_TOKEN"
                    | "TOKEN_EXPIRED"
            )
        }) {
            return true;
        }
        let status = extensions
            .and_then(|extensions| extensions.get("http"))
            .and_then(Value::as_object)
            .and_then(|http| http.get("status"))
            .or_else(|| extensions.and_then(|extensions| extensions.get("status")));
        if status.is_some_and(|status| {
            status
                .as_u64()
                .is_some_and(|status| status == 401 || status == 403)
                || status
                    .as_str()
                    .is_some_and(|status| matches!(status, "401" | "403"))
        }) {
            return true;
        }
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .map(str::trim)
            .map(str::to_ascii_lowercase);
        message.is_some_and(|message| {
            [
                "authentication required",
                "authorization required",
                "not authenticated",
                "access denied",
                "invalid access token",
                "access token expired",
                "missing bearer token",
            ]
            .into_iter()
            .any(|prefix| {
                message == prefix
                    || message
                        .strip_prefix(prefix)
                        .and_then(|suffix| suffix.chars().next())
                        .is_some_and(|character| matches!(character, '.' | ':' | ';'))
            })
        })
    })
}

fn graphql_errors_are_well_formed(errors: &[Value]) -> bool {
    !errors.is_empty()
        && errors.iter().all(|error| {
            error
                .as_object()
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str)
                .is_some()
        })
}

fn protocol_failure(
    code: &str,
    message: &str,
    http: Option<ProtocolHttpMetadata>,
) -> ProtocolExecutionResponse {
    ProtocolExecutionResponse {
        ok: false,
        data: None,
        error: Some(ProtocolResponseError {
            code: code.to_owned(),
            message: message.to_owned(),
        }),
        http,
    }
}

fn invalid_execution_response(
    mutation: bool,
    http: Option<ProtocolHttpMetadata>,
) -> Result<ProtocolExecutionResponse, GraphqlInvocationError> {
    if mutation {
        Err(GraphqlInvocationError::Indeterminate)
    } else {
        Ok(protocol_failure(
            "invalid_graphql_response",
            "The upstream GraphQL API returned an invalid response.",
            http,
        ))
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

fn credential_metadata(revision: i64, stored: StoredGraphqlCredentialV1) -> CredentialMetadata {
    CredentialMetadata {
        revision,
        configured_schemes: stored
            .credential
            .into_iter()
            .map(|credential| ConfiguredCredential {
                name: "default".to_owned(),
                credential_type: credential.credential_type(),
            })
            .collect(),
    }
}

fn graphql_error(error: GraphqlError) -> ProtocolError {
    let code = match error {
        GraphqlError::InvalidDocument(_) => "invalid_graphql_schema",
        GraphqlError::UnsupportedType(_) => "unsupported_graphql_type",
        GraphqlError::LimitExceeded { .. } => "graphql_schema_limit_exceeded",
        GraphqlError::InvalidBinding => "invalid_graphql_schema",
    };
    ProtocolError::new(
        ProtocolErrorCategory::InvalidInput,
        code,
        "The GraphQL schema could not be imported safely.",
    )
}

fn protocol_oauth_error(error: OAuthError) -> ProtocolError {
    let code = match error {
        OAuthError::Conflict { code, .. } => code,
        OAuthError::NotFound => "oauth_connection_not_found",
        OAuthError::Validation { .. }
        | OAuthError::UnauthorizedTransaction
        | OAuthError::AuthorizationDenied { .. }
        | OAuthError::Upstream { .. }
        | OAuthError::Internal => "oauth_unavailable",
    };
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        code,
        "Managed OAuth is not ready for this GraphQL source.",
    )
}

fn authorization_required_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        "authorization_required",
        "Authorize this GraphQL source, then refresh it to import tools.",
    )
}

fn invalid_binding() -> ProtocolError {
    ProtocolError::corrupt(
        "invalid_tool_binding",
        "The stored GraphQL tool binding is invalid.",
    )
}

fn invalid_arguments() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::InvalidInput,
        "invalid_tool_arguments",
        "The tool arguments are invalid.",
    )
}

fn invalid_credentials() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::InvalidInput,
        "invalid_credentials",
        "The static credential configuration is invalid.",
    )
}

fn revision_conflict() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        "revision_conflict",
        "The source changed. Refresh and retry the update.",
    )
}

fn internal_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Internal,
        "internal_error",
        "The protocol operation could not be completed.",
    )
}

fn internal_encoding_error(_error: serde_json::Error) -> ProtocolError {
    internal_error()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use reqwest::header::HeaderName;
    use serde_json::{Map, Value, json};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::{
        CreateGraphqlSource, GraphqlAdapter, GraphqlCredential, GraphqlSourceConfigurationV1,
        StoredGraphqlCredentialV1, graphql_errors_require_authorization, may_have_dispatched,
        protected_header, public_endpoint, try_compile_permit,
    };
    use crate::{
        AppConfig, ExecutorApp,
        catalog::{
            AuditContext, CreateSource, CredentialPayload, InitialCatalogSnapshot, SourceHealth,
            SourceKind, StoredCredential,
        },
        crypto::Keyring,
        graphql::{GraphqlBindingV1, GraphqlOperation, GraphqlTypeRef, GraphqlVariableBinding},
        oauth::{
            OAuthBinding, OAuthService,
            model::{OAuthClientAuthentication, OAuthConnectionConfig, OAuthSecretSet},
            store::OAuthStore,
        },
        outbound::{OutboundError, OutboundPolicy},
        protocols::ProtocolErrorCategory,
    };

    fn query_binding() -> GraphqlBindingV1 {
        let mut binding = GraphqlBindingV1 {
            version: 1,
            operation: GraphqlOperation::Query,
            field_name: "hello".to_owned(),
            operation_name: "ExecutorQueryHello".to_owned(),
            variables: vec![GraphqlVariableBinding {
                name: "id".to_owned(),
                type_ref: GraphqlTypeRef::NonNull {
                    of_type: Box::new(GraphqlTypeRef::Named {
                        name: "ID".to_owned(),
                    }),
                },
            }],
            selection: Vec::new(),
            document: String::new(),
        };
        binding.document = binding.canonical_document().unwrap();
        binding
    }

    fn mutation_binding() -> GraphqlBindingV1 {
        let mut binding = GraphqlBindingV1 {
            operation: GraphqlOperation::Mutation,
            operation_name: "ExecutorMutationHello".to_owned(),
            ..query_binding()
        };
        binding.document = binding.canonical_document().unwrap();
        binding
    }

    fn source_configuration(endpoint: String, allow_private_network: bool) -> Map<String, Value> {
        GraphqlSourceConfigurationV1 {
            endpoint: public_endpoint(&endpoint).expect("test endpoint has a safe public origin"),
            allow_private_network,
        }
        .encode()
        .unwrap()
    }

    fn stored_credential(
        endpoint: impl Into<String>,
        credential: Option<GraphqlCredential>,
    ) -> StoredCredential {
        StoredCredential {
            revision: 0,
            credential: StoredGraphqlCredentialV1 {
                endpoint: endpoint.into(),
                credential,
            }
            .payload()
            .unwrap(),
        }
    }

    async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        loop {
            let mut buffer = [0_u8; 4096];
            let read = timeout(Duration::from_secs(2), stream.read(&mut buffer))
                .await
                .expect("request arrives before timeout")
                .expect("request is readable");
            assert_ne!(read, 0, "request does not end before its body");
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n")
            else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if request.len() >= header_end + content_length {
                return request;
            }
        }
    }

    fn response(status: &str, body: &str, extra_headers: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn minimal_introspection() -> Value {
        json!({
            "data": { "__schema": {
                "queryType": { "name": "Query" },
                "mutationType": null,
                "subscriptionType": null,
                "types": [
                    { "kind": "SCALAR", "name": "String", "description": null, "fields": null, "inputFields": null, "enumValues": null },
                    { "kind": "OBJECT", "name": "Query", "description": null, "inputFields": null, "enumValues": null, "fields": [
                        { "name": "hello", "description": null, "isDeprecated": false, "args": [], "type": { "kind": "SCALAR", "name": "String", "ofType": null } }
                    ] }
                ]
            } }
        })
    }

    async fn execute_with_response(
        binding: &GraphqlBindingV1,
        status: &str,
        body: &str,
    ) -> Result<super::ProtocolExecutionResponse, super::GraphqlInvocationError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let prepared = GraphqlAdapter::default()
            .prepare_invocation(
                binding,
                &source_configuration(endpoint.clone(), true),
                Some(&stored_credential(endpoint, None)),
                &json!({ "id": "user-1" }),
                None,
            )
            .unwrap();
        let execution =
            tokio::spawn(
                async move { GraphqlAdapter::default().execute_invocation(prepared).await },
            );
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream.write_all(&response(status, body, "")).await.unwrap();
        execution.await.unwrap()
    }

    #[test]
    fn mutation_outcome_is_unknown_only_for_errors_after_dispatch_may_have_started() {
        assert!(may_have_dispatched(&OutboundError::Timeout));
        assert!(may_have_dispatched(&OutboundError::Request));
        assert!(may_have_dispatched(&OutboundError::ResponseBodyTooLarge));
        assert!(!may_have_dispatched(&OutboundError::Connection));
        assert!(!may_have_dispatched(&OutboundError::DnsResolution));
        assert!(!may_have_dispatched(&OutboundError::PrivateAddress));
        assert!(!may_have_dispatched(&OutboundError::ForbiddenHeader));
    }

    #[test]
    fn api_key_headers_cannot_take_over_transport_or_forwarding_metadata() {
        for name in [
            "authorization",
            "accept",
            "accept-encoding",
            "content-type",
            "content-length",
            "host",
            "connection",
            "transfer-encoding",
            "te",
            "trailer",
            "upgrade",
            "keep-alive",
            "referer",
            "cookie",
            "origin",
            "forwarded",
            "via",
            "x-http-method-override",
            "x-method-override",
            "x-original-url",
            "x-rewrite-url",
            "x-real-ip",
            "x-forwarded-host",
            "proxy-authorization",
        ] {
            assert!(protected_header(
                &HeaderName::from_bytes(name.as_bytes()).unwrap()
            ));
        }
    }

    #[test]
    fn credentials_reject_empty_oversized_and_control_character_values() {
        for credential in [
            GraphqlCredential::Bearer {
                token: String::new(),
            },
            GraphqlCredential::Bearer {
                token: "token\r\nx-injected: value".to_owned(),
            },
            GraphqlCredential::ApiKeyHeader {
                name: "x-api-key".to_owned(),
                value: "value\nmore".to_owned(),
            },
            GraphqlCredential::Basic {
                username: "admin".to_owned(),
                password: "x".repeat(super::MAX_CREDENTIAL_BYTES + 1),
            },
            GraphqlCredential::Basic {
                username: "admin:injected".to_owned(),
                password: "password".to_owned(),
            },
        ] {
            assert!(credential.validate().is_err());
        }
    }

    #[test]
    fn only_narrow_graphql_auth_errors_defer_discovery() {
        for errors in [
            json!([{ "message": "authentication required" }]),
            json!([{ "message": "safe", "extensions": { "code": "UNAUTHENTICATED" } }]),
            json!([{ "message": "safe", "extensions": { "http": { "status": 403 } } }]),
        ] {
            assert!(graphql_errors_require_authorization(&errors));
        }
        for errors in [
            json!([{ "message": "GraphQL introspection is disabled" }]),
            json!([{ "message": "Cannot query field unauthorized" }]),
            json!([{ "message": "safe", "extensions": { "code": "GRAPHQL_VALIDATION_FAILED" } }]),
        ] {
            assert!(!graphql_errors_require_authorization(&errors));
        }
    }

    #[test]
    fn compiler_capacity_fails_fast_with_a_sanitized_retryable_error() {
        let error = try_compile_permit(std::sync::Arc::new(tokio::sync::Semaphore::new(0)))
            .expect_err("exhausted capacity is rejected before network or parsing");
        assert_eq!(error.code, "graphql_compiler_busy");
        assert_eq!(error.category, ProtocolErrorCategory::Conflict);
        assert!(!error.message.contains("hostile"));
    }

    #[test]
    fn stored_credentials_and_configuration_fail_closed() {
        let malformed_credential = StoredCredential {
            revision: 1,
            credential: CredentialPayload {
                schema_version: 1,
                payload: json!({
                    "endpoint": "https://example.test/graphql",
                    "credential": {
                        "type": "api_key_header",
                        "name": "x-forwarded-host",
                        "value": "internal.example"
                    }
                }),
            },
        };
        let error = match StoredGraphqlCredentialV1::decode(&malformed_credential) {
            Ok(_) => panic!("protected stored credential must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.code, "invalid_source_credentials");
        assert_eq!(error.category, ProtocolErrorCategory::CorruptData);

        let configuration = Map::from_iter([
            (
                "endpoint".to_owned(),
                json!("https://example.test/graphql?token=secret"),
            ),
            ("allowPrivateNetwork".to_owned(), json!(false)),
        ]);
        assert!(GraphqlSourceConfigurationV1::decode(&configuration).is_err());
    }

    #[tokio::test]
    async fn invocation_posts_fixed_document_exact_variables_and_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let prepared = GraphqlAdapter::default()
            .prepare_invocation(
                &query_binding(),
                &source_configuration(endpoint.clone(), true),
                Some(&stored_credential(
                    endpoint,
                    Some(GraphqlCredential::Bearer {
                        token: "secret-token".to_owned(),
                    }),
                )),
                &json!({ "id": "user-1" }),
                None,
            )
            .unwrap();
        let execution =
            tokio::spawn(
                async move { GraphqlAdapter::default().execute_invocation(prepared).await },
            );
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        let request_text = String::from_utf8_lossy(&request);
        assert!(request_text.starts_with("POST /graphql HTTP/1.1"));
        assert!(request_text.contains("authorization: Bearer secret-token\r\n"));
        let body = request_text.split("\r\n\r\n").nth(1).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            json!({
                "query": "query ExecutorQueryHello($id: ID!) { result: hello(id: $id) }",
                "operationName": "ExecutorQueryHello",
                "variables": { "id": "user-1" }
            })
        );
        stream
            .write_all(&response("200 OK", r#"{"data":{"result":"world"}}"#, ""))
            .await
            .unwrap();
        let result = execution.await.unwrap().unwrap();
        assert!(result.ok);
        assert_eq!(result.data, Some(json!("world")));
    }

    #[tokio::test]
    async fn import_and_credential_cas_return_the_exact_committed_revision() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let directory = tempfile::tempdir().unwrap();
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .unwrap();
        let catalog = app.catalog().clone();
        let create = tokio::spawn(async move {
            GraphqlAdapter::default()
                .create_source(
                    &catalog,
                    CreateGraphqlSource {
                        display_name: "GraphQL".to_owned(),
                        preferred_slug: None,
                        description: None,
                        endpoint,
                        allow_private_network: true,
                        credential: None,
                    },
                    AuditContext::system(Some("graphql-create")),
                )
                .await
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        let body = serde_json::to_string(&minimal_introspection()).unwrap();
        stream
            .write_all(&response("200 OK", &body, ""))
            .await
            .unwrap();
        let source = create.await.unwrap().unwrap();
        assert_eq!(source.tool_count, 1);

        let first_catalog = app.catalog().clone();
        let first_source = source.id.clone();
        let first = tokio::spawn(async move {
            GraphqlAdapter::default()
                .replace_credentials(
                    &first_catalog,
                    &first_source,
                    0,
                    Some(GraphqlCredential::Bearer {
                        token: "first-secret".to_owned(),
                    }),
                    AuditContext::system(Some("graphql-first-credential")),
                )
                .await
        });
        let second_catalog = app.catalog().clone();
        let second_source = source.id.clone();
        let second = tokio::spawn(async move {
            GraphqlAdapter::default()
                .replace_credentials(
                    &second_catalog,
                    &second_source,
                    0,
                    Some(GraphqlCredential::Basic {
                        username: "second".to_owned(),
                        password: "second-secret".to_owned(),
                    }),
                    AuditContext::system(Some("graphql-second-credential")),
                )
                .await
        });
        let outcomes = [first.await.unwrap(), second.await.unwrap()];
        let committed = outcomes
            .iter()
            .find_map(|outcome| outcome.as_ref().ok())
            .expect("one credential update commits");
        assert_eq!(committed.revision, 1);
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1
        );
        let current = GraphqlAdapter::default()
            .credential_metadata(app.catalog(), &source.id)
            .await
            .unwrap();
        assert_eq!(current.revision, committed.revision);
        assert_eq!(
            current.configured_schemes[0].credential_type,
            committed.configured_schemes[0].credential_type
        );
    }

    #[tokio::test]
    async fn unauthenticated_denials_can_stage_an_authorization_required_source() {
        for (status, body) in [
            ("401 Unauthorized", "{}"),
            (
                "200 OK",
                r#"{"errors":[{"message":"authentication required"}]}"#,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
            let directory = tempfile::tempdir().unwrap();
            let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
                .await
                .unwrap();
            let catalog = app.catalog().clone();
            let create = tokio::spawn(async move {
                GraphqlAdapter::default()
                    .create_source(
                        &catalog,
                        CreateGraphqlSource {
                            display_name: "GraphQL OAuth".to_owned(),
                            preferred_slug: None,
                            description: None,
                            endpoint,
                            allow_private_network: true,
                            credential: None,
                        },
                        AuditContext::system(Some("graphql-oauth-create")),
                    )
                    .await
            });
            let (mut stream, _) = listener.accept().await.unwrap();
            read_request(&mut stream).await;
            stream.write_all(&response(status, body, "")).await.unwrap();
            let source = create.await.unwrap().unwrap();
            assert_eq!(source.tool_count, 0);
            assert_eq!(source.health_status, SourceHealth::Error);
            assert_eq!(
                source.health_error_code.as_deref(),
                Some("authorization_required")
            );
            app.shutdown().await;
        }
    }

    #[tokio::test]
    async fn static_credentials_suppress_managed_oauth_and_conflicts_fail_closed() {
        let endpoint = "https://example.test/graphql".to_owned();
        let stored = stored_credential(
            endpoint.clone(),
            Some(GraphqlCredential::Bearer {
                token: "static-secret".to_owned(),
            }),
        );
        let adapter = GraphqlAdapter::default();
        assert!(
            adapter
                .oauth_binding_observation(
                    "source-id",
                    Some(&stored),
                    Some(&[OAuthBinding {
                        connection_id: "ignored-connection".to_owned(),
                        credential_key: "default".to_owned(),
                        config_revision: 1,
                    }]),
                )
                .await
                .unwrap()
                .is_none()
        );
        let error = match adapter.prepare_invocation(
            &query_binding(),
            &source_configuration(endpoint, false),
            Some(&stored),
            &json!({ "id": "user-1" }),
            Some(OAuthBinding {
                connection_id: "connection-id".to_owned(),
                credential_key: "default".to_owned(),
                config_revision: 1,
            }),
        ) {
            Ok(_) => panic!("static and managed credentials must not both apply"),
            Err(error) => error,
        };
        assert_eq!(error.code, "ambiguous_source_credentials");
        assert_eq!(error.category, ProtocolErrorCategory::CorruptData);
    }

    #[tokio::test]
    async fn managed_oauth_reaches_queries_and_mutations_static_wins_and_401_is_not_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let directory = tempfile::tempdir().unwrap();
        let master_key = [73_u8; 32];
        let master_key_file = directory.path().join("fixture-master.key");
        std::fs::write(&master_key_file, master_key).unwrap();
        let app = ExecutorApp::open(
            AppConfig::new(directory.path().join("data"))
                .with_master_key_file(Some(master_key_file)),
        )
        .await
        .unwrap();
        let stored = StoredGraphqlCredentialV1 {
            endpoint: endpoint.clone(),
            credential: None,
        };
        let (source, _) = app
            .catalog()
            .create_source_with_catalog_health(
                CreateSource {
                    kind: SourceKind::Graphql,
                    preferred_slug: "oauth_graphql".to_owned(),
                    display_name: "OAuth GraphQL".to_owned(),
                    description: None,
                    configuration: source_configuration(endpoint.clone(), true),
                },
                &stored.payload().unwrap(),
                InitialCatalogSnapshot {
                    artifacts: Vec::new(),
                    tools: Vec::new(),
                },
                Vec::new(),
                SourceHealth::Unknown,
                AuditContext::system(Some("graphql-oauth-fixture")),
            )
            .await
            .unwrap();
        let keyring = Keyring::from_master_key(master_key).unwrap();
        OAuthStore::new(app.pool().clone(), keyring.clone())
            .create_connection(
                &source.id,
                "default",
                &OAuthConnectionConfig {
                    issuer: "https://auth.example.test".to_owned(),
                    authorization_endpoint: "https://auth.example.test/authorize".to_owned(),
                    token_endpoint: "https://auth.example.test/token".to_owned(),
                    client_id: "fixture-client".to_owned(),
                    client_authentication: OAuthClientAuthentication::None,
                    token_endpoint_auth_methods_supported: vec!["none".to_owned()],
                    scopes: vec!["graphql".to_owned()],
                    allow_private_network: false,
                    resource: None,
                },
                Some(&OAuthSecretSet {
                    access_token: Some("managed-secret-token".to_owned()),
                    granted_scopes: vec!["graphql".to_owned()],
                    ..OAuthSecretSet::default()
                }),
                1,
            )
            .await
            .unwrap();
        let adapter = GraphqlAdapter::with_oauth(OAuthService::new(
            app.pool().clone(),
            keyring,
            "http://127.0.0.1:4788".to_owned(),
            OutboundPolicy::default(),
        ));
        let stored_record = app.catalog().credential(&source.id).await.unwrap().unwrap();
        let binding = adapter
            .oauth_binding_observation(&source.id, Some(&stored_record), None)
            .await
            .unwrap()
            .unwrap();

        let prepared = adapter
            .prepare_invocation(
                &query_binding(),
                &source.configuration,
                Some(&stored_record),
                &json!({ "id": "user-1" }),
                Some(binding.clone()),
            )
            .unwrap();
        let query_adapter = adapter.clone();
        let query = tokio::spawn(async move { query_adapter.execute_invocation(prepared).await });
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = String::from_utf8_lossy(&read_request(&mut stream).await).into_owned();
        assert!(request.contains("authorization: Bearer managed-secret-token\r\n"));
        stream
            .write_all(&response("200 OK", r#"{"data":{"result":"managed"}}"#, ""))
            .await
            .unwrap();
        assert_eq!(query.await.unwrap().unwrap().data, Some(json!("managed")));

        let prepared = adapter
            .prepare_invocation(
                &mutation_binding(),
                &source.configuration,
                Some(&stored_record),
                &json!({ "id": "user-1" }),
                Some(binding.clone()),
            )
            .unwrap();
        let mutation_adapter = adapter.clone();
        let mutation =
            tokio::spawn(async move { mutation_adapter.execute_invocation(prepared).await });
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = String::from_utf8_lossy(&read_request(&mut stream).await).into_owned();
        assert!(request.contains("authorization: Bearer managed-secret-token\r\n"));
        stream
            .write_all(&response("401 Unauthorized", "{}", ""))
            .await
            .unwrap();
        assert!(matches!(
            mutation.await.unwrap(),
            Err(super::GraphqlInvocationError::Indeterminate)
        ));
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "a dispatched mutation is never retried after an authentication response"
        );

        let static_stored = stored_credential(
            endpoint,
            Some(GraphqlCredential::Bearer {
                token: "static-secret-token".to_owned(),
            }),
        );
        let observed = adapter
            .oauth_binding_observation(&source.id, Some(&static_stored), Some(&[binding]))
            .await
            .unwrap();
        assert!(observed.is_none());
        let prepared = adapter
            .prepare_invocation(
                &query_binding(),
                &source.configuration,
                Some(&static_stored),
                &json!({ "id": "user-1" }),
                observed,
            )
            .unwrap();
        let static_adapter = adapter.clone();
        let static_query =
            tokio::spawn(async move { static_adapter.execute_invocation(prepared).await });
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = String::from_utf8_lossy(&read_request(&mut stream).await).into_owned();
        assert!(request.contains("authorization: Bearer static-secret-token\r\n"));
        assert!(!request.contains("managed-secret-token"));
        stream
            .write_all(&response("200 OK", r#"{"data":{"result":"static"}}"#, ""))
            .await
            .unwrap();
        assert_eq!(
            static_query.await.unwrap().unwrap().data,
            Some(json!("static"))
        );
        app.shutdown().await;
    }

    #[tokio::test]
    async fn upstream_errors_are_sanitized_and_redirects_are_not_followed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let prepared = GraphqlAdapter::default()
            .prepare_invocation(
                &query_binding(),
                &source_configuration(endpoint.clone(), true),
                Some(&stored_credential(endpoint, None)),
                &json!({ "id": "user-1" }),
                None,
            )
            .unwrap();
        let execution =
            tokio::spawn(
                async move { GraphqlAdapter::default().execute_invocation(prepared).await },
            );
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(&response(
                "200 OK",
                r#"{"errors":[{"message":"database password is hunter2"}],"data":{"result":null}}"#,
                "",
            ))
            .await
            .unwrap();
        let result = execution.await.unwrap().unwrap();
        let error = result.error.unwrap();
        assert_eq!(error.code, "graphql_error");
        assert!(!error.message.contains("hunter2"));

        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let prepared = GraphqlAdapter::default()
            .prepare_invocation(
                &query_binding(),
                &source_configuration(endpoint.clone(), true),
                Some(&stored_credential(endpoint, None)),
                &json!({ "id": "user-1" }),
                None,
            )
            .unwrap();
        let execution =
            tokio::spawn(
                async move { GraphqlAdapter::default().execute_invocation(prepared).await },
            );
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(&response("302 Found", "{}", "Location: /redirected\r\n"))
            .await
            .unwrap();
        let result = execution.await.unwrap().unwrap();
        assert!(!result.ok);
        assert_eq!(result.http.unwrap().status, 302);
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn mutation_ambiguous_responses_and_graphql_errors_are_indeterminate() {
        for (status, body) in [
            ("302 Found", "{}"),
            ("400 Bad Request", "{}"),
            ("409 Conflict", "{}"),
            ("429 Too Many Requests", "{}"),
            ("500 Internal Server Error", "{}"),
            ("408 Request Timeout", "{}"),
            ("200 OK", "not-json"),
            ("200 OK", r#"{"data":{}}"#),
            ("200 OK", r#"{"errors":{},"data":{"result":null}}"#),
            ("200 OK", r#"{"errors":[null],"data":{"result":null}}"#),
        ] {
            let error = execute_with_response(&mutation_binding(), status, body)
                .await
                .expect_err("ambiguous mutation response must be indeterminate");
            assert!(matches!(
                error,
                super::GraphqlInvocationError::Indeterminate
            ));
            assert!(error.outcome_unknown());
        }

        let error = execute_with_response(
            &mutation_binding(),
            "200 OK",
            r#"{"errors":[{"message":"secret upstream detail"}],"data":{"result":null}}"#,
        )
        .await
        .expect_err("mutation errors can follow committed side effects");
        assert!(error.outcome_unknown());

        let result = execute_with_response(&query_binding(), "200 OK", "not-json")
            .await
            .expect("malformed query responses are ordinary failures");
        assert!(!result.ok);
        assert_eq!(result.error.unwrap().code, "invalid_graphql_response");
    }

    #[tokio::test]
    async fn post_write_disconnect_is_unknown_but_private_policy_failure_is_pre_dispatch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/graphql", listener.local_addr().unwrap());
        let prepared = GraphqlAdapter::default()
            .prepare_invocation(
                &mutation_binding(),
                &source_configuration(endpoint.clone(), true),
                Some(&stored_credential(endpoint, None)),
                &json!({ "id": "user-1" }),
                None,
            )
            .unwrap();
        let execution =
            tokio::spawn(
                async move { GraphqlAdapter::default().execute_invocation(prepared).await },
            );
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        drop(stream);
        let error = execution.await.unwrap().unwrap_err();
        assert!(error.outcome_unknown());

        let endpoint = "http://127.0.0.1:1/graphql".to_owned();
        let error = match GraphqlAdapter::default().prepare_invocation(
            &mutation_binding(),
            &source_configuration(endpoint.clone(), false),
            Some(&stored_credential(endpoint, None)),
            &json!({ "id": "user-1" }),
            None,
        ) {
            Ok(_) => panic!("private policy failure must happen before dispatch"),
            Err(error) => error,
        };
        assert_eq!(error.code, "private_network_denied");
    }

    #[test]
    fn canonical_binding_tampering_and_extra_arguments_fail_before_network() {
        let mut binding = query_binding();
        binding.document = "query Evil { result: adminSecrets }".to_owned();
        let endpoint = "https://example.test/graphql".to_owned();
        let error = match GraphqlAdapter::default().prepare_invocation(
            &binding,
            &source_configuration(endpoint.clone(), false),
            Some(&stored_credential(endpoint.clone(), None)),
            &json!({ "id": "user-1" }),
            None,
        ) {
            Ok(_) => panic!("tampered binding must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error.code, "invalid_tool_binding");
        assert_eq!(error.category, ProtocolErrorCategory::CorruptData);

        let error = match GraphqlAdapter::default().prepare_invocation(
            &query_binding(),
            &source_configuration(endpoint.clone(), false),
            Some(&stored_credential(endpoint, None)),
            &json!({ "id": "user-1", "document": "mutation Evil" }),
            None,
        ) {
            Ok(_) => panic!("extra arguments must not alter the document"),
            Err(error) => error,
        };
        assert_eq!(error.code, "invalid_tool_arguments");
    }

    #[test]
    fn public_endpoint_strips_path_and_query_secrets_and_public_configuration_rejects_them() {
        let endpoint = public_endpoint(
            "https://graphql.example.test/secret-path/api?token=secret&tenant=customer",
        )
        .expect("query-bearing endpoints are valid in encrypted storage");
        assert_eq!(endpoint, "https://graphql.example.test/");
        assert!(!endpoint.contains("secret"));

        let exposed = Map::from_iter([
            (
                "endpoint".to_owned(),
                json!("https://graphql.example.test/api?token=secret"),
            ),
            ("allowPrivateNetwork".to_owned(), json!(false)),
        ]);
        assert!(GraphqlSourceConfigurationV1::decode(&exposed).is_err());
        assert!(public_endpoint("https://user:secret@example.test/graphql").is_err());
        assert!(public_endpoint("https://example.test/graphql#secret").is_err());
        assert!(public_endpoint("http://api.example.test/graphql").is_err());
        assert!(public_endpoint("http://localhost:8080/graphql").is_ok());
        assert!(public_endpoint("http://127.0.0.1:8080/graphql").is_ok());
    }
}
