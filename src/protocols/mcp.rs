use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use url::{Host, Url};

use super::{
    ConfiguredCredential, CredentialMetadata, ProtocolError, ProtocolErrorCategory,
    ProtocolExecutionResponse, ProtocolResponseError, protocol_catalog_error,
};
use crate::{
    catalog::{
        AuditContext, CatalogStore, CatalogSyncResult, CreateSource, CredentialPayload,
        InitialCatalogSnapshot, McpToolBindingV1, OAuthBindingExpectation, SourceHealth,
        SourceKind, SourceRecord, StoredCredential,
    },
    mcp::{
        discovery::{
            DiscoveredMcpTool, DiscoveryBasis, DiscoveryError, DiscoveryPlan, ListChangedCoalescer,
            ToolPage, ToolPageFetcher, bindings_for_source_kind, discover,
        },
        manager::{McpConnectionManager, SourceRevisionLease, WatcherRevisionLease},
        upstream::{
            http::{
                DEFAULT_PROTOCOL_VERSION as HTTP_PROTOCOL_VERSION, StreamableHttpConfig,
                StreamableHttpError, StreamableHttpTransport, is_supported_protocol_version,
            },
            stdio::{
                DEFAULT_PROTOCOL_VERSION as STDIO_PROTOCOL_VERSION, InitializeResult,
                StdioLifecycleMonitor, StdioTemplateError, StdioTemplateRegistry,
                StdioTransportError, StdioTransportLimits,
            },
        },
    },
    oauth::{OAuthBinding, OAuthError, OAuthService},
};

const MCP_CREDENTIAL_SCHEMA_VERSION: u32 = 1;
const MAX_ENDPOINT_BYTES: usize = 8 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_SECRET_VALUES: usize = 128;
const MAX_SECRET_NAME_BYTES: usize = 256;
const MAX_SECRET_VALUE_BYTES: usize = 16 * 1024;
const MAX_DISCOVERY_GENERATIONS: usize = 8;
const DISCOVERY_DEADLINE: Duration = Duration::from_secs(120);
const DISCOVERY_QUIET_PERIOD: Duration = Duration::from_millis(25);
const STDIO_WATCHER_HEARTBEAT: Duration = Duration::from_secs(1);
const WATCHER_RECONCILIATION_ATTEMPTS: usize = 3;
const WATCHER_RECONCILIATION_RETRY_DELAY: Duration = Duration::from_millis(25);

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum McpHttpCredential {
    Bearer {
        token: String,
    },
    Basic {
        username: String,
        password: String,
    },
    ApiKeyHeader {
        name: String,
        value: String,
    },
    #[serde(rename = "oauth_access_token")]
    OAuthAccessToken {
        access_token: String,
    },
}

impl McpHttpCredential {
    fn credential_type(&self) -> &'static str {
        match self {
            Self::Bearer { .. } => "bearer",
            Self::Basic { .. } => "basic",
            Self::ApiKeyHeader { .. } => "api_key_header",
            Self::OAuthAccessToken { .. } => "oauth_access_token",
        }
    }

    fn headers(&self) -> Result<HeaderMap, ProtocolError> {
        let mut headers = HeaderMap::new();
        match self {
            Self::Bearer { token }
            | Self::OAuthAccessToken {
                access_token: token,
            } => {
                let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| invalid_credentials("The MCP bearer credential is invalid."))?;
                value.set_sensitive(true);
                headers.insert(AUTHORIZATION, value);
            }
            Self::Basic { username, password } => {
                let encoded = STANDARD.encode(format!("{username}:{password}"));
                let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
                    .map_err(|_| invalid_credentials("The MCP basic credential is invalid."))?;
                value.set_sensitive(true);
                headers.insert(AUTHORIZATION, value);
            }
            Self::ApiKeyHeader { name, value } => {
                let name = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| invalid_credentials("The MCP API key header name is invalid."))?;
                if protected_mcp_header(&name) {
                    return Err(invalid_credentials(
                        "The MCP API key cannot use a protected HTTP header.",
                    ));
                }
                let mut value = HeaderValue::from_str(value)
                    .map_err(|_| invalid_credentials("The MCP API key header value is invalid."))?;
                value.set_sensitive(true);
                headers.insert(name, value);
            }
        }
        Ok(headers)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Bearer { token }
            | Self::OAuthAccessToken {
                access_token: token,
            } => {
                validate_secret(token)?;
            }
            Self::Basic { username, password } => {
                if username.is_empty() || username.contains(':') || username.len() > 4 * 1024 {
                    return Err(invalid_credentials(
                        "The MCP basic credential username is invalid.",
                    ));
                }
                validate_secret(password)?;
            }
            Self::ApiKeyHeader { name, value } => {
                if name.is_empty() || name.len() > 256 {
                    return Err(invalid_credentials(
                        "The MCP API key header name is invalid.",
                    ));
                }
                validate_secret(value)?;
            }
        }
        let headers = self.headers()?;
        let mut config = StreamableHttpConfig::new("https://example.invalid/mcp");
        config.headers = headers;
        StreamableHttpTransport::new(config).map_err(http_configuration_error)?;
        Ok(())
    }
}

fn protected_mcp_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "content-type"
            | "accept"
            | "content-length"
            | "connection"
            | "transfer-encoding"
            | "mcp-session-id"
            | "mcp-protocol-version"
            | "origin"
            | "referer"
            | "authorization"
            | "proxy-authorization"
            | "proxy-connection"
    ) || name.as_str().starts_with("proxy-")
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMcpHttpSource {
    pub display_name: String,
    pub preferred_slug: Option<String>,
    pub description: Option<String>,
    pub endpoint: String,
    #[serde(default)]
    pub allow_private_network: bool,
    pub credential: Option<McpHttpCredential>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMcpStdioSource {
    pub display_name: String,
    pub preferred_slug: Option<String>,
    pub description: Option<String>,
    pub template_name: String,
    #[serde(default)]
    pub secret_values: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplaceMcpHttpCredential {
    pub credential: Option<McpHttpCredential>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplaceMcpStdioCredential {
    #[serde(default)]
    pub secret_values: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpHttpSourceConfigurationV1 {
    endpoint: String,
    allow_private_network: bool,
    negotiated_protocol_version: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpStdioSourceConfigurationV1 {
    template_name: String,
    negotiated_protocol_version: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StoredMcpHttpCredentialV1 {
    endpoint: String,
    credential: Option<McpHttpCredential>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredMcpStdioCredentialV1 {
    template_name: String,
    secret_values: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct McpAdapter {
    connections: Arc<McpConnectionManager>,
    oauth: Option<OAuthService>,
    #[cfg(test)]
    post_commit_pause: Option<Arc<PostCommitPause>>,
    #[cfg(test)]
    watcher_unavailable_pause: Option<Arc<WatcherUnavailablePause>>,
    #[cfg(test)]
    watcher_install_attempts: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    watcher_capability_load_failures: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    watcher_credential_load_failures: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

#[cfg(test)]
#[derive(Default)]
struct PostCommitPause {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

struct WatcherReconciliationFailure {
    error: ProtocolError,
    failed_revision: Option<i64>,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct WatcherUnavailablePause {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
impl WatcherUnavailablePause {
    pub(super) async fn reached(&self) {
        self.reached.notified().await;
    }

    pub(super) fn release(&self) {
        self.release.notify_one();
    }
}

impl Default for McpAdapter {
    fn default() -> Self {
        Self::new(StdioTemplateRegistry::default())
    }
}

impl McpAdapter {
    pub fn new(stdio_templates: StdioTemplateRegistry) -> Self {
        Self {
            connections: Arc::new(McpConnectionManager::new(stdio_templates)),
            oauth: None,
            #[cfg(test)]
            post_commit_pause: None,
            #[cfg(test)]
            watcher_unavailable_pause: None,
            #[cfg(test)]
            watcher_install_attempts: None,
            #[cfg(test)]
            watcher_capability_load_failures: None,
            #[cfg(test)]
            watcher_credential_load_failures: None,
        }
    }

    pub fn stdio_templates(&self) -> &StdioTemplateRegistry {
        self.connections.stdio_templates()
    }

    pub(crate) fn with_connection_manager(connections: Arc<McpConnectionManager>) -> Self {
        Self {
            connections,
            oauth: None,
            #[cfg(test)]
            post_commit_pause: None,
            #[cfg(test)]
            watcher_unavailable_pause: None,
            #[cfg(test)]
            watcher_install_attempts: None,
            #[cfg(test)]
            watcher_capability_load_failures: None,
            #[cfg(test)]
            watcher_credential_load_failures: None,
        }
    }

    pub(crate) fn with_services(
        connections: Arc<McpConnectionManager>,
        oauth: OAuthService,
    ) -> Self {
        Self {
            connections,
            oauth: Some(oauth),
            #[cfg(test)]
            post_commit_pause: None,
            #[cfg(test)]
            watcher_unavailable_pause: None,
            #[cfg(test)]
            watcher_install_attempts: None,
            #[cfg(test)]
            watcher_capability_load_failures: None,
            #[cfg(test)]
            watcher_credential_load_failures: None,
        }
    }

    pub async fn create_http_source(
        &self,
        catalog: &CatalogStore,
        input: CreateMcpHttpSource,
        audit: AuditContext<'_>,
    ) -> Result<SourceRecord, ProtocolError> {
        validate_http_credential(input.credential.as_ref())?;
        let endpoint = validate_endpoint(&input.endpoint)?;
        let stored = StoredMcpHttpCredentialV1 {
            endpoint: endpoint.to_string(),
            credential: input.credential,
        };
        let _operation = self.connections.begin_operation().map_err(shutting_down)?;
        let discovery =
            discover_http_for_create(&stored, input.allow_private_network, 0, Some(0)).await?;
        let configuration = McpHttpSourceConfigurationV1 {
            endpoint: display_endpoint(&endpoint),
            allow_private_network: input.allow_private_network,
            negotiated_protocol_version: discovery.protocol_version().to_owned(),
        };
        let preferred_slug = input
            .preferred_slug
            .unwrap_or_else(|| input.display_name.clone());
        let create = CreateSource {
            kind: SourceKind::McpHttp,
            preferred_slug,
            display_name: input.display_name,
            description: input.description,
            configuration: encode_configuration(&configuration)?,
        };
        let credential = stored.payload()?;
        let (source, authorization_required) = match discovery {
            HttpCreateDiscovery::Ready(plan) => {
                let plan = *plan;
                (
                    catalog
                        .create_source_with_catalog(
                            create,
                            &credential,
                            plan.initial_catalog_snapshot(),
                            plan.bindings,
                            audit,
                        )
                        .await
                        .map_err(protocol_catalog_error)?
                        .0,
                    false,
                )
            }
            HttpCreateDiscovery::AuthorizationRequired => (
                catalog
                    .create_authorization_required_source_with_catalog(
                        create,
                        &credential,
                        InitialCatalogSnapshot {
                            artifacts: Vec::new(),
                            tools: Vec::new(),
                        },
                        Vec::new(),
                        audit,
                    )
                    .await
                    .map_err(protocol_catalog_error)?
                    .0,
                true,
            ),
        };
        if !authorization_required
            && let Err(error) = self.install_source_watcher(catalog, &source).await
        {
            tracing::warn!(
                source_id = source.id,
                code = error.code,
                "MCP HTTP source watcher installation failed"
            );
        }
        Ok(source)
    }

    pub async fn create_stdio_source(
        &self,
        catalog: &CatalogStore,
        input: CreateMcpStdioSource,
        audit: AuditContext<'_>,
    ) -> Result<SourceRecord, ProtocolError> {
        self.connections
            .stdio_templates()
            .template(&input.template_name)
            .map_err(input_template_error)?;
        validate_secret_values(&input.secret_values)?;
        let discover_now = stdio_secrets_complete(
            self.connections.stdio_templates(),
            &input.template_name,
            &input.secret_values,
        )?;
        let stored = StoredMcpStdioCredentialV1 {
            template_name: input.template_name.clone(),
            secret_values: input.secret_values,
        };
        let (snapshot, bindings, negotiated_protocol_version) = if discover_now {
            let _operation = self.connections.begin_operation().map_err(shutting_down)?;
            let plan =
                discover_stdio(self.connections.stdio_templates(), &stored, 0, Some(0)).await?;
            let negotiated_protocol_version = plan.basis.protocol_version.clone();
            (
                plan.initial_catalog_snapshot(),
                plan.bindings,
                negotiated_protocol_version,
            )
        } else {
            (
                InitialCatalogSnapshot {
                    artifacts: Vec::new(),
                    tools: Vec::new(),
                },
                Vec::new(),
                HTTP_PROTOCOL_VERSION.to_owned(),
            )
        };
        let configuration = McpStdioSourceConfigurationV1 {
            template_name: input.template_name,
            negotiated_protocol_version: discover_now.then_some(negotiated_protocol_version),
        };
        let preferred_slug = input
            .preferred_slug
            .unwrap_or_else(|| input.display_name.clone());
        let create = CreateSource {
            kind: SourceKind::McpStdio,
            preferred_slug,
            display_name: input.display_name,
            description: input.description,
            configuration: encode_configuration(&configuration)?,
        };
        let credential = stored.payload()?;
        let (source, _) = if discover_now {
            catalog
                .create_source_with_catalog(create, &credential, snapshot, bindings, audit)
                .await
        } else {
            catalog
                .create_source_with_catalog_health(
                    create,
                    &credential,
                    snapshot,
                    bindings,
                    SourceHealth::Unknown,
                    audit,
                )
                .await
        }
        .map_err(protocol_catalog_error)?;
        if discover_now && let Err(error) = self.install_source_watcher(catalog, &source).await {
            tracing::warn!(
                source_id = source.id,
                code = error.code,
                "MCP stdio source watcher installation failed"
            );
        }
        Ok(source)
    }

    pub async fn refresh_source(
        &self,
        catalog: &CatalogStore,
        source: SourceRecord,
        audit: AuditContext<'_>,
    ) -> Result<CatalogSyncResult, ProtocolError> {
        let _operation = self.connections.begin_operation().map_err(shutting_down)?;
        let source_id = source.id.clone();
        let result = self.refresh_source_core(catalog, source, audit).await?;
        self.finish_source_watcher_reconciliation(catalog, &source_id, result.source_revision)
            .await?;
        Ok(result)
    }

    async fn refresh_source_core(
        &self,
        catalog: &CatalogStore,
        source: SourceRecord,
        audit: AuditContext<'_>,
    ) -> Result<CatalogSyncResult, ProtocolError> {
        let stored = required_stored_credential(catalog, &source.id).await?;
        let _operation = self.connections.begin_operation().map_err(shutting_down)?;
        let (plan, oauth_expectation) = match source.kind {
            SourceKind::McpHttp => {
                let configuration = McpHttpSourceConfigurationV1::decode(&source.configuration)?;
                let credential = StoredMcpHttpCredentialV1::decode(&stored)?;
                self.discover_http_source(
                    &source.id,
                    &credential,
                    configuration.allow_private_network,
                    source.revision,
                    Some(stored.revision),
                )
                .await?
            }
            SourceKind::McpStdio => {
                let configuration = McpStdioSourceConfigurationV1::decode(&source.configuration)?;
                let credential = StoredMcpStdioCredentialV1::decode(&stored)?;
                if configuration.template_name != credential.template_name {
                    return Err(corrupt_configuration());
                }
                self.connections
                    .stdio_templates()
                    .template(&credential.template_name)
                    .map_err(stored_template_error)?;
                (
                    discover_stdio(
                        self.connections.stdio_templates(),
                        &credential,
                        source.revision,
                        Some(stored.revision),
                    )
                    .await?,
                    None,
                )
            }
            SourceKind::Openapi | SourceKind::Graphql => {
                return Err(ProtocolError::corrupt(
                    "source_protocol_mismatch",
                    "The stored source does not match the MCP protocol.",
                ));
            }
        };
        let result = match oauth_expectation {
            Some(expectation) => {
                catalog
                    .sync_catalog_with_bindings_and_oauth_binding(
                        &source.id,
                        plan.catalog_snapshot(),
                        plan.bindings,
                        expectation,
                        audit,
                    )
                    .await
            }
            None => {
                catalog
                    .sync_catalog_with_bindings(
                        &source.id,
                        plan.catalog_snapshot(),
                        plan.bindings,
                        audit,
                    )
                    .await
            }
        }
        .map_err(protocol_catalog_error)?;
        Ok(result)
    }

    pub async fn credential_metadata(
        &self,
        catalog: &CatalogStore,
        source: &SourceRecord,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let stored = required_stored_credential(catalog, &source.id).await?;
        match source.kind {
            SourceKind::McpHttp => {
                let credential = StoredMcpHttpCredentialV1::decode(&stored)?;
                Ok(http_credential_metadata(stored.revision, &credential))
            }
            SourceKind::McpStdio => {
                let credential = StoredMcpStdioCredentialV1::decode(&stored)?;
                Ok(stdio_credential_metadata(stored.revision, &credential))
            }
            SourceKind::Openapi | SourceKind::Graphql => Err(ProtocolError::corrupt(
                "source_protocol_mismatch",
                "The stored source does not match the MCP protocol.",
            )),
        }
    }

    pub async fn replace_http_credentials(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        expected_revision: i64,
        update: ReplaceMcpHttpCredential,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let _operation = self.connections.begin_operation().map_err(shutting_down)?;
        validate_http_credential(update.credential.as_ref())?;
        let stored = required_stored_credential(catalog, source_id).await?;
        require_revision(expected_revision, stored.revision)?;
        let mut credential = StoredMcpHttpCredentialV1::decode(&stored)?;
        let Some(candidate) = update.credential else {
            return self
                .clear_http_credentials(catalog, source_id, stored, credential, audit)
                .await;
        };
        credential.credential = Some(candidate);
        let source = catalog
            .source(source_id)
            .await
            .map_err(protocol_catalog_error)?;
        let configuration = McpHttpSourceConfigurationV1::decode(&source.configuration)?;
        let plan = discover_http(
            &credential,
            configuration.allow_private_network,
            source.revision,
            Some(stored.revision),
        )
        .await?;
        let (stored, _synced, committed_source) = catalog
            .replace_credential_and_sync_catalog(
                source_id,
                &credential.payload()?,
                plan.catalog_snapshot(),
                plan.bindings,
                audit,
            )
            .await
            .map_err(protocol_catalog_error)?;
        self.finish_source_watcher_reconciliation(catalog, source_id, committed_source.revision)
            .await?;
        let credential = StoredMcpHttpCredentialV1::decode(&stored)?;
        let metadata = http_credential_metadata(stored.revision, &credential);
        Ok(metadata)
    }

    async fn clear_http_credentials(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        stored: StoredCredential,
        mut credential: StoredMcpHttpCredentialV1,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let source = catalog
            .source(source_id)
            .await
            .map_err(protocol_catalog_error)?;
        let configuration = McpHttpSourceConfigurationV1::decode(&source.configuration)?;
        credential.credential = None;
        let anonymous_discovery = self
            .discover_http_source(
                source_id,
                &credential,
                configuration.allow_private_network,
                source.revision,
                Some(stored.revision),
            )
            .await
            .and_then(|(plan, expectation)| {
                expectation
                    .map(|expectation| (plan, expectation))
                    .ok_or_else(corrupt_configuration)
            });
        self.connections
            .stop_watcher_and_wait_at_revision(source_id, source.revision)
            .await;
        let committed = match anonymous_discovery {
            Ok((plan, expectation)) => catalog
                .replace_credential_and_sync_catalog_with_oauth_binding(
                    source_id,
                    &credential.payload()?,
                    plan.catalog_snapshot(),
                    plan.bindings,
                    expectation,
                    audit,
                )
                .await
                .map(|(stored, _, source)| (stored, source)),
            Err(error) => {
                tracing::info!(
                    source_id,
                    code = error.code,
                    "MCP HTTP source does not support anonymous discovery after credential clear"
                );
                catalog
                    .replace_credential_and_mark_unknown(
                        source_id,
                        &credential.payload()?,
                        source.revision,
                        stored.revision,
                        audit,
                    )
                    .await
            }
        };
        let (stored, committed_source) = match committed {
            Ok(committed) => committed,
            Err(error) => {
                if let Err(recovery_error) = self
                    .reconcile_source_watcher(catalog, source_id, source.revision)
                    .await
                {
                    tracing::warn!(
                        source_id,
                        code = recovery_error.code,
                        "MCP HTTP watcher rollback recovery failed"
                    );
                }
                return Err(protocol_catalog_error(error));
            }
        };
        self.finish_source_watcher_reconciliation(catalog, source_id, committed_source.revision)
            .await?;
        let credential = StoredMcpHttpCredentialV1::decode(&stored)?;
        let metadata = http_credential_metadata(stored.revision, &credential);
        Ok(metadata)
    }

    pub async fn replace_stdio_credentials(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        expected_revision: i64,
        update: ReplaceMcpStdioCredential,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let _operation = self.connections.begin_operation().map_err(shutting_down)?;
        validate_secret_values(&update.secret_values)?;
        let stored = required_stored_credential(catalog, source_id).await?;
        require_revision(expected_revision, stored.revision)?;
        let mut credential = StoredMcpStdioCredentialV1::decode(&stored)?;
        if !stdio_secrets_complete(
            self.connections.stdio_templates(),
            &credential.template_name,
            &update.secret_values,
        )? {
            return Err(invalid_credentials(
                "The MCP stdio source requires all template secret values.",
            ));
        }
        credential.secret_values = update.secret_values;
        let source = catalog
            .source(source_id)
            .await
            .map_err(protocol_catalog_error)?;
        let plan = discover_stdio(
            self.connections.stdio_templates(),
            &credential,
            source.revision,
            Some(stored.revision),
        )
        .await?;
        let (stored, _synced, committed_source) = catalog
            .replace_credential_and_sync_catalog(
                source_id,
                &credential.payload()?,
                plan.catalog_snapshot(),
                plan.bindings,
                audit,
            )
            .await
            .map_err(protocol_catalog_error)?;
        self.finish_source_watcher_reconciliation(catalog, source_id, committed_source.revision)
            .await?;
        let credential = StoredMcpStdioCredentialV1::decode(&stored)?;
        let metadata = stdio_credential_metadata(stored.revision, &credential);
        Ok(metadata)
    }

    pub async fn clear_credentials(
        &self,
        catalog: &CatalogStore,
        source: &SourceRecord,
        expected_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        match source.kind {
            SourceKind::McpHttp => {
                self.replace_http_credentials(
                    catalog,
                    &source.id,
                    expected_revision,
                    ReplaceMcpHttpCredential { credential: None },
                    audit,
                )
                .await
            }
            SourceKind::McpStdio => {
                let _operation = self.connections.begin_operation().map_err(shutting_down)?;
                let stored = required_stored_credential(catalog, &source.id).await?;
                require_revision(expected_revision, stored.revision)?;
                let mut credential = StoredMcpStdioCredentialV1::decode(&stored)?;
                credential.secret_values.clear();
                if stdio_secrets_complete(
                    self.connections.stdio_templates(),
                    &credential.template_name,
                    &credential.secret_values,
                )? {
                    return self
                        .replace_stdio_credentials(
                            catalog,
                            &source.id,
                            expected_revision,
                            ReplaceMcpStdioCredential {
                                secret_values: BTreeMap::new(),
                            },
                            audit,
                        )
                        .await;
                }
                self.connections
                    .stop_watcher_and_wait_at_revision(&source.id, source.revision)
                    .await;
                let cleared = catalog
                    .replace_credential_and_mark_unknown(
                        &source.id,
                        &credential.payload()?,
                        source.revision,
                        stored.revision,
                        audit,
                    )
                    .await;
                let (stored, committed_source) = match cleared {
                    Ok(cleared) => cleared,
                    Err(error) => {
                        if let Err(recovery_error) = self
                            .reconcile_source_watcher(catalog, &source.id, source.revision)
                            .await
                        {
                            tracing::warn!(
                                source_id = source.id,
                                code = recovery_error.code,
                                "MCP stdio watcher rollback recovery failed"
                            );
                        }
                        return Err(protocol_catalog_error(error));
                    }
                };
                self.finish_source_watcher_reconciliation(
                    catalog,
                    &committed_source.id,
                    committed_source.revision,
                )
                .await?;
                let credential = StoredMcpStdioCredentialV1::decode(&stored)?;
                Ok(stdio_credential_metadata(stored.revision, &credential))
            }
            SourceKind::Openapi | SourceKind::Graphql => Err(ProtocolError::corrupt(
                "source_protocol_mismatch",
                "The stored source does not match the MCP protocol.",
            )),
        }
    }

    async fn install_source_watcher(
        &self,
        catalog: &CatalogStore,
        source: &SourceRecord,
    ) -> Result<bool, ProtocolError> {
        #[cfg(test)]
        if let Some(attempts) = &self.watcher_install_attempts {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        if source.health_status == SourceHealth::Unknown {
            return Ok(self
                .connections
                .stop_watcher_and_wait_at_revision(&source.id, source.revision)
                .await);
        }
        #[cfg(test)]
        if consume_test_failure(&self.watcher_capability_load_failures) {
            return Err(internal_error());
        }
        match source_supports_list_changed(catalog, &source.id).await {
            Ok(true) => {}
            Ok(false) => {
                return Ok(self
                    .connections
                    .stop_watcher_and_wait_at_revision(&source.id, source.revision)
                    .await);
            }
            Err(error) => return Err(error),
        }
        #[cfg(test)]
        if consume_test_failure(&self.watcher_credential_load_failures) {
            return Err(internal_error());
        }
        let stored = required_stored_credential(catalog, &source.id).await?;
        let source_id = source.id.clone();
        let credential_revision = stored.revision;
        let connections = self.connections.clone();
        let oauth = self.oauth.clone();
        let catalog = catalog.clone();
        let installed = match source.kind {
            SourceKind::McpHttp => {
                let configuration = McpHttpSourceConfigurationV1::decode(&source.configuration)?;
                let credential = StoredMcpHttpCredentialV1::decode(&stored)?;
                self.connections
                    .replace_watcher(
                        source_id.clone(),
                        source.revision,
                        move |canceled, revision_lease| {
                            run_http_watcher(
                                HttpWatcherContext {
                                    connections,
                                    oauth,
                                    catalog,
                                    source_id,
                                    credential,
                                    allow_private_network: configuration.allow_private_network,
                                    credential_revision,
                                    revision_lease,
                                },
                                canceled,
                            )
                        },
                    )
                    .await
            }
            SourceKind::McpStdio => {
                let configuration = McpStdioSourceConfigurationV1::decode(&source.configuration)?;
                let credential = match StoredMcpStdioCredentialV1::decode(&stored) {
                    Ok(credential) if credential.template_name == configuration.template_name => {
                        credential
                    }
                    Ok(_) => return Err(corrupt_configuration()),
                    Err(error) => return Err(error),
                };
                self.connections
                    .replace_watcher(
                        source_id.clone(),
                        source.revision,
                        move |canceled, revision_lease| {
                            run_stdio_watcher(
                                StdioWatcherContext {
                                    connections,
                                    catalog,
                                    source_id,
                                    credential,
                                    credential_revision,
                                    revision_lease,
                                },
                                canceled,
                            )
                        },
                    )
                    .await
            }
            SourceKind::Openapi | SourceKind::Graphql => {
                return Err(ProtocolError::corrupt(
                    "source_protocol_mismatch",
                    "The stored source does not match the MCP protocol.",
                ));
            }
        };
        match installed {
            Ok(installed) => Ok(installed),
            Err(error) => Err(shutting_down(error)),
        }
    }

    async fn reconcile_source_watcher(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        minimum_revision: i64,
    ) -> Result<(), ProtocolError> {
        let _reconciliation = self.connections.lock_watcher_reconciliation().await;
        self.reconcile_source_watcher_locked(catalog, source_id, minimum_revision)
            .await
            .map_err(|failure| failure.error)
    }

    async fn reconcile_source_watcher_locked(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        minimum_revision: i64,
    ) -> Result<(), WatcherReconciliationFailure> {
        if self
            .connections
            .watcher_revision(source_id)
            .is_some_and(|revision| revision >= minimum_revision)
        {
            match catalog.source(source_id).await {
                Ok(source)
                    if self.connections.watcher_revision(source_id) == Some(source.revision) =>
                {
                    return Ok(());
                }
                Ok(_) => {}
                Err(crate::catalog::CatalogError::NotFound { .. }) => {
                    self.connections
                        .stop_watcher_and_wait_at_least_revision(source_id, minimum_revision)
                        .await;
                    return Ok(());
                }
                Err(error) => {
                    return Err(WatcherReconciliationFailure {
                        error: protocol_catalog_error(error),
                        failed_revision: None,
                    });
                }
            }
        }
        self.connections
            .stop_watcher_and_wait_at_least_revision(source_id, minimum_revision)
            .await;
        let mut last_failure = None;
        for attempt in 0..WATCHER_RECONCILIATION_ATTEMPTS {
            let source = match catalog.source(source_id).await {
                Ok(source) => source,
                Err(crate::catalog::CatalogError::NotFound { .. }) => return Ok(()),
                Err(error) => {
                    last_failure = Some(WatcherReconciliationFailure {
                        error: protocol_catalog_error(error),
                        failed_revision: None,
                    });
                    if attempt + 1 < WATCHER_RECONCILIATION_ATTEMPTS {
                        tokio::time::sleep(WATCHER_RECONCILIATION_RETRY_DELAY).await;
                    }
                    continue;
                }
            };
            if source.revision < minimum_revision {
                last_failure = Some(WatcherReconciliationFailure {
                    error: stale_watcher_reconciliation(),
                    failed_revision: None,
                });
                if attempt + 1 < WATCHER_RECONCILIATION_ATTEMPTS {
                    tokio::time::sleep(WATCHER_RECONCILIATION_RETRY_DELAY).await;
                }
                continue;
            }
            let observed_revision = source.revision;
            self.connections
                .stop_watcher_and_wait_at_least_revision(source_id, observed_revision)
                .await;
            match self.install_source_watcher(catalog, &source).await {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    last_failure = Some(WatcherReconciliationFailure {
                        error: stale_watcher_reconciliation(),
                        failed_revision: None,
                    });
                }
                Err(error) => {
                    last_failure = Some(WatcherReconciliationFailure {
                        error,
                        failed_revision: Some(observed_revision),
                    });
                }
            }
            if attempt + 1 < WATCHER_RECONCILIATION_ATTEMPTS {
                tokio::time::sleep(WATCHER_RECONCILIATION_RETRY_DELAY).await;
            }
        }
        Err(
            last_failure.unwrap_or_else(|| WatcherReconciliationFailure {
                error: stale_watcher_reconciliation(),
                failed_revision: None,
            }),
        )
    }

    pub(super) async fn finish_source_watcher_reconciliation(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        committed_revision: i64,
    ) -> Result<(), ProtocolError> {
        #[cfg(test)]
        if let Some(pause) = &self.post_commit_pause {
            pause.reached.notify_one();
            pause.release.notified().await;
        }
        self.reconcile_source_watcher(catalog, source_id, committed_revision)
            .await
    }

    pub(super) async fn ensure_source_creation_watcher(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
    ) {
        let source = match catalog.source(source_id).await {
            Ok(source) => source,
            Err(crate::catalog::CatalogError::NotFound { .. }) => return,
            Err(error) => {
                tracing::warn!(
                    source_id,
                    error = %error,
                    "MCP source-create watcher reload failed"
                );
                return;
            }
        };
        if let Err(error) = self.ensure_source_watcher(catalog, &source).await {
            tracing::warn!(
                source_id,
                code = error.code,
                "MCP source-create watcher recovery failed"
            );
        }
    }

    async fn ensure_source_watcher(
        &self,
        catalog: &CatalogStore,
        source: &SourceRecord,
    ) -> Result<(), ProtocolError> {
        if source.health_status == SourceHealth::Unknown {
            self.connections
                .stop_watcher_and_wait_at_least_revision(&source.id, source.revision)
                .await;
            return Ok(());
        }
        if self.connections.has_watcher(&source.id) {
            match source_supports_list_changed(catalog, &source.id).await {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    self.connections
                        .stop_watcher_and_wait_at_revision(&source.id, source.revision)
                        .await;
                    return Ok(());
                }
                Err(error) => {
                    self.connections
                        .stop_watcher_and_wait_at_least_revision(&source.id, source.revision)
                        .await;
                    return Err(error);
                }
            }
        }
        self.reconcile_source_watcher(catalog, &source.id, source.revision)
            .await
    }

    pub async fn restore_watchers(&self, catalog: &CatalogStore) -> Result<(), ProtocolError> {
        let sources = catalog
            .list_sources()
            .await
            .map_err(protocol_catalog_error)?;
        for source in sources {
            if matches!(source.kind, SourceKind::McpHttp | SourceKind::McpStdio) {
                self.ensure_source_watcher(catalog, &source).await?;
            }
        }
        Ok(())
    }

    pub async fn recover_source_watcher_after_failed_delete(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        minimum_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<(), ProtocolError> {
        let _reconciliation = self.connections.lock_watcher_reconciliation().await;
        match self
            .reconcile_source_watcher_locked(catalog, source_id, minimum_revision)
            .await
        {
            Ok(()) => Ok(()),
            Err(failure) => {
                if let Some(failed_revision) = failure.failed_revision {
                    self.persist_watcher_unavailable_at_revision(
                        catalog,
                        source_id,
                        failed_revision,
                        audit,
                    )
                    .await;
                }
                Err(failure.error)
            }
        }
    }

    async fn persist_watcher_unavailable_at_revision(
        &self,
        catalog: &CatalogStore,
        source_id: &str,
        failed_revision: i64,
        audit: AuditContext<'_>,
    ) {
        #[cfg(test)]
        if let Some(pause) = &self.watcher_unavailable_pause {
            pause.reached.notify_one();
            pause.release.notified().await;
        }
        let source = match catalog.source(source_id).await {
            Ok(source) if source.revision == failed_revision => source,
            Ok(_) | Err(crate::catalog::CatalogError::NotFound { .. }) => return,
            Err(error) => {
                tracing::warn!(
                    source_id,
                    error = %error,
                    "MCP watcher unavailability could not be revalidated"
                );
                return;
            }
        };
        if self.connections.has_watcher(source_id) {
            return;
        }
        let Some(revisions) = self
            .connections
            .lock_source_revisions([(source.id.clone(), failed_revision)])
            .await
        else {
            return;
        };
        match catalog
            .mark_source_error(source_id, "mcp_watcher_unavailable", failed_revision, audit)
            .await
        {
            Ok(updated) => {
                if !revisions.advance(&std::collections::HashMap::from([(
                    updated.id.clone(),
                    updated.revision,
                )])) {
                    tracing::error!(
                        source_id,
                        "MCP watcher revision did not match unavailable health persistence"
                    );
                }
                self.connections
                    .stop_watcher_and_wait_at_least_revision(&updated.id, updated.revision)
                    .await;
            }
            Err(
                crate::catalog::CatalogError::RevisionConflict { .. }
                | crate::catalog::CatalogError::NotFound { .. },
            ) => {}
            Err(error) => {
                tracing::warn!(
                    source_id,
                    error = %error,
                    "MCP watcher unavailability could not be persisted"
                );
            }
        }
    }

    #[cfg(test)]
    pub(super) fn fail_watcher_capability_loads(
        &mut self,
        failures: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        self.watcher_capability_load_failures = Some(failures);
    }

    #[cfg(test)]
    pub(super) fn pause_watcher_unavailable_persistence(&mut self) -> Arc<WatcherUnavailablePause> {
        let pause = Arc::new(WatcherUnavailablePause::default());
        self.watcher_unavailable_pause = Some(pause.clone());
        pause
    }

    pub(super) async fn lock_source_deletion(
        &self,
        source_id: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.connections.lock_source_deletion(source_id).await
    }

    pub async fn retire_source_watcher(&self, source_id: &str) {
        self.connections.retire_source(source_id).await;
    }

    pub async fn unretire_source_watcher(&self, source_id: &str) {
        self.connections.unretire_source(source_id).await;
    }

    pub(super) async fn lock_source_revisions(
        &self,
        observed_revisions: impl IntoIterator<Item = (String, i64)>,
    ) -> Option<SourceRevisionLease> {
        self.connections
            .lock_source_revisions(observed_revisions)
            .await
    }

    pub(super) async fn oauth_binding_observation(
        &self,
        source_id: &str,
        source_kind: SourceKind,
        stored: Option<&StoredCredential>,
        expected_bindings: Option<&[OAuthBinding]>,
    ) -> Result<McpOAuthBindingObservation, ProtocolError> {
        if source_kind == SourceKind::McpStdio {
            return Ok(McpOAuthBindingObservation::NotApplicable);
        }
        if source_kind != SourceKind::McpHttp {
            return Err(ProtocolError::corrupt(
                "source_protocol_mismatch",
                "The stored source does not match the MCP protocol.",
            ));
        }
        let stored = stored.ok_or_else(|| {
            ProtocolError::corrupt(
                "source_credentials_missing",
                "The source credential state is missing.",
            )
        })?;
        let credential = StoredMcpHttpCredentialV1::decode_for_invocation(stored)?;
        if credential.credential.is_some() {
            return Ok(McpOAuthBindingObservation::Static);
        }
        if let Some(expected_bindings) = expected_bindings {
            let mut defaults = expected_bindings
                .iter()
                .filter(|binding| binding.credential_key == "default");
            let binding = defaults.next().cloned();
            if defaults.next().is_some() {
                return Err(ProtocolError::corrupt(
                    "source_authorization_mismatch",
                    "The prepared MCP authorization state is inconsistent.",
                ));
            }
            return Ok(binding.map_or(
                McpOAuthBindingObservation::Anonymous,
                McpOAuthBindingObservation::Managed,
            ));
        }
        let Some(oauth) = &self.oauth else {
            return Ok(McpOAuthBindingObservation::Anonymous);
        };
        Ok(oauth
            .binding(source_id, "default")
            .await
            .map_err(mcp_oauth_error)?
            .map_or(
                McpOAuthBindingObservation::Anonymous,
                McpOAuthBindingObservation::Managed,
            ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn prepare_invocation(
        &self,
        source_id: &str,
        source_kind: SourceKind,
        binding: &McpToolBindingV1,
        source_configuration: &Map<String, Value>,
        stored: Option<&StoredCredential>,
        arguments: &Value,
        oauth_binding: McpOAuthBindingObservation,
    ) -> Result<PreparedMcpInvocation, ProtocolError> {
        if binding.version != 1 || binding.tool_name.is_empty() {
            return Err(ProtocolError::corrupt(
                "unsupported_binding_schema",
                "The stored MCP tool binding schema is not supported.",
            ));
        }
        if !arguments.is_object() {
            return Err(ProtocolError::new(
                ProtocolErrorCategory::InvalidInput,
                "invalid_tool_arguments",
                "The tool arguments are invalid.",
            ));
        }
        let stored = stored.ok_or_else(|| {
            ProtocolError::corrupt(
                "source_credentials_missing",
                "The source credential state is missing.",
            )
        })?;
        match source_kind {
            SourceKind::McpHttp => {
                let configuration = McpHttpSourceConfigurationV1::decode(source_configuration)?;
                let credential = StoredMcpHttpCredentialV1::decode_for_invocation(stored)?;
                let config =
                    http_transport_config(&credential, configuration.allow_private_network)?;
                StreamableHttpTransport::new(config).map_err(http_configuration_error)?;
                let authorization_matches = matches!(
                    (&credential.credential, &oauth_binding),
                    (Some(_), McpOAuthBindingObservation::Static)
                        | (None, McpOAuthBindingObservation::Anonymous)
                        | (None, McpOAuthBindingObservation::Managed(_))
                );
                if !authorization_matches {
                    return Err(ProtocolError::corrupt(
                        "source_authorization_mismatch",
                        "The prepared MCP authorization state is inconsistent.",
                    ));
                }
                Ok(PreparedMcpInvocation::Http {
                    source_id: source_id.to_owned(),
                    credential,
                    allow_private_network: configuration.allow_private_network,
                    oauth_binding,
                    tool_name: binding.tool_name.clone(),
                    arguments: arguments.clone(),
                })
            }
            SourceKind::McpStdio => {
                if !matches!(oauth_binding, McpOAuthBindingObservation::NotApplicable) {
                    return Err(ProtocolError::corrupt(
                        "source_authorization_mismatch",
                        "The prepared MCP authorization state is inconsistent.",
                    ));
                }
                let configuration = McpStdioSourceConfigurationV1::decode(source_configuration)?;
                let credential = StoredMcpStdioCredentialV1::decode_for_invocation(stored)?;
                if configuration.template_name != credential.template_name {
                    return Err(corrupt_configuration());
                }
                if !stdio_secrets_complete(
                    self.connections.stdio_templates(),
                    &credential.template_name,
                    &credential.secret_values,
                )? {
                    return Err(ProtocolError::new(
                        ProtocolErrorCategory::InvalidInput,
                        "missing_source_credentials",
                        "The MCP stdio source requires credentials before its tools can run.",
                    ));
                }
                self.connections
                    .stdio_templates()
                    .template(&credential.template_name)
                    .map_err(stored_template_error)?;
                Ok(PreparedMcpInvocation::Stdio {
                    template_name: credential.template_name,
                    secret_values: credential.secret_values,
                    tool_name: binding.tool_name.clone(),
                    arguments: arguments.clone(),
                })
            }
            SourceKind::Openapi | SourceKind::Graphql => Err(ProtocolError::corrupt(
                "source_binding_mismatch",
                "The stored tool binding does not match its source protocol.",
            )),
        }
    }

    async fn discover_http_source(
        &self,
        source_id: &str,
        stored: &StoredMcpHttpCredentialV1,
        allow_private_network: bool,
        source_revision: i64,
        credential_revision: Option<i64>,
    ) -> Result<(DiscoveryPlan, Option<OAuthBindingExpectation>), ProtocolError> {
        let (config, oauth_revision) = self
            .http_transport_config_for_source(source_id, stored, allow_private_network)
            .await?;
        let plan = discover_http_config(
            config,
            source_revision,
            credential_revision,
            stored.credential.is_none(),
        )
        .await?;
        Ok((
            plan,
            catalog_oauth_expectation(stored, oauth_revision.as_ref()),
        ))
    }

    pub(super) async fn execute_invocation(
        &self,
        prepared: PreparedMcpInvocation,
    ) -> Result<ProtocolExecutionResponse, McpInvocationError> {
        let _operation = self
            .connections
            .begin_operation()
            .map_err(|_| McpInvocationError::ShuttingDown)?;
        match prepared {
            PreparedMcpInvocation::Http {
                source_id,
                credential,
                allow_private_network,
                oauth_binding,
                tool_name,
                arguments,
            } => {
                let config = http_transport_config_for_observation(
                    self.oauth.as_ref(),
                    &source_id,
                    &credential,
                    allow_private_network,
                    &oauth_binding,
                )
                .await
                .map_err(McpInvocationError::AuthorizationSetup)?;
                execute_http(config, &tool_name, arguments).await
            }
            PreparedMcpInvocation::Stdio {
                template_name,
                secret_values,
                tool_name,
                arguments,
            } => {
                execute_stdio(
                    self.connections.stdio_templates(),
                    &template_name,
                    &secret_values,
                    &tool_name,
                    arguments,
                )
                .await
            }
        }
    }

    async fn http_transport_config_for_source(
        &self,
        source_id: &str,
        stored: &StoredMcpHttpCredentialV1,
        allow_private_network: bool,
    ) -> Result<(StreamableHttpConfig, Option<OAuthTransportRevision>), ProtocolError> {
        http_transport_config_for_source(
            self.oauth.as_ref(),
            source_id,
            stored,
            allow_private_network,
        )
        .await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OAuthTransportRevision {
    binding: OAuthBinding,
    secret_revision: i64,
}

fn catalog_oauth_expectation(
    stored: &StoredMcpHttpCredentialV1,
    revision: Option<&OAuthTransportRevision>,
) -> Option<OAuthBindingExpectation> {
    if stored.credential.is_some() {
        return None;
    }
    Some(match revision {
        Some(revision) => OAuthBindingExpectation::Exact {
            credential_key: "default".to_owned(),
            connection_id: revision.binding.connection_id.clone(),
            config_revision: revision.binding.config_revision,
        },
        None => OAuthBindingExpectation::Absent {
            credential_key: "default".to_owned(),
        },
    })
}

fn oauth_transport_changed(
    active: Option<&OAuthTransportRevision>,
    current: Option<&OAuthTransportRevision>,
) -> bool {
    active != current
}

struct HttpWatcherContext {
    connections: Arc<McpConnectionManager>,
    oauth: Option<OAuthService>,
    catalog: CatalogStore,
    source_id: String,
    credential: StoredMcpHttpCredentialV1,
    allow_private_network: bool,
    credential_revision: i64,
    revision_lease: WatcherRevisionLease,
}

async fn run_http_watcher(
    context: HttpWatcherContext,
    mut canceled: tokio::sync::oneshot::Receiver<()>,
) {
    let HttpWatcherContext {
        connections,
        oauth,
        catalog,
        source_id,
        credential,
        allow_private_network,
        credential_revision,
        revision_lease,
    } = context;
    let mut retry_delay = Duration::from_secs(1);
    loop {
        let Some(source_revision) = revision_lease.current_revision() else {
            return;
        };
        let operation = match connections.begin_operation() {
            Ok(operation) => operation,
            Err(_) => return,
        };
        let (config, oauth_revision) = match http_transport_config_for_source(
            oauth.as_ref(),
            &source_id,
            &credential,
            allow_private_network,
        )
        .await
        {
            Ok(config) => config,
            Err(error) => {
                tracing::warn!(
                    source_id,
                    code = error.code,
                    "MCP HTTP watcher configuration failed"
                );
                let authorization_required = error.code == "authorization_required";
                if authorization_required {
                    mark_watcher_authorization_required(&catalog, &source_id, &revision_lease)
                        .await;
                    drop(operation);
                    if wait_for_http_authorization_change(
                        oauth.as_ref(),
                        &source_id,
                        &credential,
                        allow_private_network,
                        None,
                        &mut canceled,
                    )
                    .await
                    {
                        return;
                    }
                    retry_delay = Duration::from_secs(1);
                    continue;
                }
                drop(operation);
                if watcher_retry_or_cancel(&mut canceled, retry_delay).await {
                    return;
                }
                retry_delay = next_watcher_backoff(retry_delay);
                continue;
            }
        };
        let oauth_expectation = catalog_oauth_expectation(&credential, oauth_revision.as_ref());
        let transport = match StreamableHttpTransport::new(config) {
            Ok(transport) => transport,
            Err(_) => {
                tracing::warn!(source_id, "MCP HTTP watcher transport failed");
                return;
            }
        };
        let mut changed = transport.subscribe_tool_list_changed();
        let initialized = match transport.initialize().await {
            Ok(initialized) => initialized,
            Err(error) => {
                tracing::warn!(source_id, "MCP HTTP watcher initialization failed");
                if credential.credential.is_none() && http_authorization_denied(&error) {
                    mark_watcher_authorization_required(&catalog, &source_id, &revision_lease)
                        .await;
                    drop(operation);
                    if wait_for_http_authorization_change(
                        oauth.as_ref(),
                        &source_id,
                        &credential,
                        allow_private_network,
                        oauth_revision.as_ref(),
                        &mut canceled,
                    )
                    .await
                    {
                        return;
                    }
                    retry_delay = Duration::from_secs(1);
                    continue;
                }
                drop(operation);
                if watcher_retry_or_cancel(&mut canceled, retry_delay).await {
                    return;
                }
                retry_delay = next_watcher_backoff(retry_delay);
                continue;
            }
        };
        let basis =
            match http_discovery_basis(initialized, source_revision, Some(credential_revision)) {
                Ok(basis) => basis,
                Err(error) => {
                    tracing::warn!(
                        source_id,
                        code = error.code,
                        "MCP HTTP watcher initialization metadata is invalid"
                    );
                    let _ = transport.terminate().await;
                    return;
                }
            };
        let listener_transport = transport.clone();
        let mut listener =
            tokio::spawn(async move { listener_transport.listen_notifications().await });
        let reconciled = {
            let reconciliation = reconcile_watcher_session(async {
                let plan = discover_http_session(
                    &transport,
                    &mut changed,
                    basis.clone(),
                    credential.credential.is_none(),
                )
                .await?;
                commit_watcher_discovery(
                    &catalog,
                    &source_id,
                    plan,
                    oauth_expectation.clone(),
                    &revision_lease,
                )
                .await
            });
            tokio::pin!(reconciliation);
            tokio::select! {
                _ = &mut canceled => {
                    abort_and_join(&mut listener).await;
                    let _ = transport.terminate().await;
                    return;
                }
                result = &mut reconciliation => result,
            }
        };
        let mut listener_finished = false;
        let mut reconnect = false;
        match reconciled {
            Ok(reconciled) => {
                if let Some(listener_result) =
                    finished_http_listener_after_reconciliation(&reconciled, &mut listener).await
                {
                    listener_finished = true;
                    if let Ok(Err(error)) = listener_result {
                        if permanent_http_notification_error(&error) {
                            let _ = transport.terminate().await;
                            return;
                        }
                        tracing::debug!(
                            source_id,
                            "MCP HTTP notification listener disconnected after reconciliation"
                        );
                    }
                    reconnect = true;
                }
                let (synced, supports_list_changed) = reconciled.into_inner();
                retry_delay = Duration::from_secs(1);
                if !supports_list_changed {
                    connections
                        .stop_watcher_at_revision(&source_id, synced.source_revision)
                        .await;
                    if !listener_finished {
                        abort_and_join(&mut listener).await;
                    }
                    let _ = transport.terminate().await;
                    return;
                }
            }
            Err(error) => {
                tracing::warn!(
                    source_id,
                    code = error.code,
                    "MCP HTTP watcher startup reconciliation failed"
                );
                let authorization_required = error.code == "authorization_required";
                if authorization_required {
                    mark_watcher_authorization_required(&catalog, &source_id, &revision_lease)
                        .await;
                }
                abort_and_join(&mut listener).await;
                let _ = transport.terminate().await;
                drop(operation);
                if authorization_required {
                    if wait_for_http_authorization_change(
                        oauth.as_ref(),
                        &source_id,
                        &credential,
                        allow_private_network,
                        oauth_revision.as_ref(),
                        &mut canceled,
                    )
                    .await
                    {
                        return;
                    }
                    retry_delay = Duration::from_secs(1);
                    continue;
                }
                if watcher_retry_or_cancel(&mut canceled, retry_delay).await {
                    return;
                }
                retry_delay = next_watcher_backoff(retry_delay);
                continue;
            }
        }
        let coalescer = ListChangedCoalescer::default();
        let mut oauth_revision_check = tokio::time::interval(Duration::from_secs(30));
        oauth_revision_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        oauth_revision_check.tick().await;
        let mut authorization_blocked = false;
        while !reconnect {
            tokio::select! {
                _ = &mut canceled => {
                    abort_and_join(&mut listener).await;
                    let _ = transport.terminate().await;
                    return;
                }
                result = &mut listener => {
                    listener_finished = true;
                    if let Ok(Err(error)) = result {
                        if permanent_http_notification_error(&error) {
                            let _ = transport.terminate().await;
                            return;
                        }
                        tracing::debug!(source_id, "MCP HTTP notification listener disconnected");
                    }
                    reconnect = true;
                }
                _ = oauth_revision_check.tick(), if credential.credential.is_none() && oauth.is_some() => {
                    match http_transport_config_for_source(
                        oauth.as_ref(),
                        &source_id,
                        &credential,
                        allow_private_network,
                    )
                    .await
                    {
                        Ok((_, current_revision))
                            if !oauth_transport_changed(
                                oauth_revision.as_ref(),
                                current_revision.as_ref(),
                            ) => {}
                        Ok(_) => {
                            tracing::debug!(source_id, "MCP HTTP OAuth token changed; reconnecting");
                            reconnect = true;
                        }
                        Err(error) => {
                            tracing::warn!(source_id, code = error.code, "MCP HTTP OAuth token check failed");
                            if error.code == "authorization_required" {
                                mark_watcher_authorization_required(
                                    &catalog,
                                    &source_id,
                                    &revision_lease,
                                )
                                .await;
                                authorization_blocked = true;
                            }
                            reconnect = true;
                        }
                    }
                }
                signal = changed.recv() => {
                    match signal {
                        Ok(()) | Err(RecvError::Lagged(_)) => {
                            retry_delay = Duration::from_secs(1);
                            coalescer.notify_changed();
                            drain_change_signals(&mut changed, &coalescer);
                            let refresh = coalescer.refresh_pending(|| {
                                refresh_http_watcher_session(
                                    catalog.clone(),
                                    source_id.clone(),
                                    transport.clone(),
                                    basis.clone(),
                                    oauth_expectation.clone(),
                                    connections.clone(),
                                    revision_lease.clone(),
                                )
                            });
                            tokio::pin!(refresh);
                            match wait_for_watcher_refresh(
                                &mut canceled,
                                &mut listener,
                                &mut refresh,
                            )
                            .await
                            {
                                WatcherRefreshWait::Canceled => {
                                    abort_and_join(&mut listener).await;
                                    let _ = transport.terminate().await;
                                    return;
                                }
                                WatcherRefreshWait::Disconnected(result) => {
                                    listener_finished = true;
                                    if let Ok(Err(error)) = result {
                                        if permanent_http_notification_error(&error) {
                                            let _ = transport.terminate().await;
                                            return;
                                        }
                                        tracing::debug!(source_id, "MCP HTTP notification listener disconnected");
                                    }
                                    reconnect = true;
                                }
                                WatcherRefreshWait::Completed(result) => {
                                    if let Err(error) = result {
                                        tracing::warn!(source_id, code = error.code, "MCP HTTP notification refresh failed");
                                        if error.code == "authorization_required" {
                                            mark_watcher_authorization_required(
                                                &catalog,
                                                &source_id,
                                                &revision_lease,
                                            )
                                            .await;
                                            authorization_blocked = true;
                                        }
                                        if matches!(
                                            error.code,
                                            "authorization_required" | "oauth_binding_changed"
                                        ) {
                                            reconnect = true;
                                            continue;
                                        }
                                        let mut refresh_delay = Duration::from_secs(1);
                                        'http_refresh_retries: while coalescer.has_pending() {
                                            match wait_for_watcher_refresh(
                                                &mut canceled,
                                                &mut listener,
                                                tokio::time::sleep(refresh_delay),
                                            )
                                            .await
                                            {
                                                WatcherRefreshWait::Canceled => {
                                                    abort_and_join(&mut listener).await;
                                                    let _ = transport.terminate().await;
                                                    return;
                                                }
                                                WatcherRefreshWait::Disconnected(result) => {
                                                    listener_finished = true;
                                                    if let Ok(Err(error)) = result
                                                        && permanent_http_notification_error(&error)
                                                    {
                                                        let _ = transport.terminate().await;
                                                        return;
                                                    }
                                                    tracing::debug!(source_id, "MCP HTTP notification listener disconnected during refresh retry");
                                                    reconnect = true;
                                                    break 'http_refresh_retries;
                                                }
                                                WatcherRefreshWait::Completed(()) => {}
                                            }
                                            if reconnect {
                                                break;
                                            }
                                            let retried = coalescer.refresh_pending(|| {
                                                refresh_http_watcher_session(
                                                    catalog.clone(),
                                                    source_id.clone(),
                                                    transport.clone(),
                                                    basis.clone(),
                                                    oauth_expectation.clone(),
                                                    connections.clone(),
                                                    revision_lease.clone(),
                                                )
                                            });
                                            tokio::pin!(retried);
                                            match wait_for_watcher_refresh(
                                                &mut canceled,
                                                &mut listener,
                                                &mut retried,
                                            )
                                            .await
                                            {
                                                WatcherRefreshWait::Canceled => {
                                                    abort_and_join(&mut listener).await;
                                                    let _ = transport.terminate().await;
                                                    return;
                                                }
                                                WatcherRefreshWait::Disconnected(result) => {
                                                    listener_finished = true;
                                                    if let Ok(Err(error)) = result
                                                        && permanent_http_notification_error(&error)
                                                    {
                                                        let _ = transport.terminate().await;
                                                        return;
                                                    }
                                                    tracing::debug!(source_id, "MCP HTTP notification listener disconnected during refresh retry");
                                                    reconnect = true;
                                                    break 'http_refresh_retries;
                                                }
                                                WatcherRefreshWait::Completed(result) => {
                                                    match result {
                                                        Ok(_) => break 'http_refresh_retries,
                                                        Err(error)
                                                            if matches!(
                                                                error.code,
                                                                "authorization_required"
                                                                    | "oauth_binding_changed"
                                                            ) =>
                                                        {
                                                            if error.code == "authorization_required" {
                                                                mark_watcher_authorization_required(
                                                                    &catalog,
                                                                    &source_id,
                                                                    &revision_lease,
                                                                )
                                                                .await;
                                                                authorization_blocked = true;
                                                            }
                                                            reconnect = true;
                                                            break 'http_refresh_retries;
                                                        }
                                                        Err(_) => {}
                                                    }
                                                }
                                            }
                                            refresh_delay = next_watcher_backoff(refresh_delay);
                                        }
                                    }
                                }
                            }
                        }
                        Err(RecvError::Closed) => reconnect = true,
                    }
                }
            }
        }
        if !listener_finished {
            abort_and_join(&mut listener).await;
        }
        let _ = transport.terminate().await;
        drop(operation);
        if authorization_blocked {
            if wait_for_http_authorization_change(
                oauth.as_ref(),
                &source_id,
                &credential,
                allow_private_network,
                oauth_revision.as_ref(),
                &mut canceled,
            )
            .await
            {
                return;
            }
            retry_delay = Duration::from_secs(1);
            continue;
        }
        if watcher_retry_or_cancel(&mut canceled, retry_delay).await {
            return;
        }
        retry_delay = next_watcher_backoff(retry_delay);
    }
}

async fn abort_and_join<T>(task: &mut tokio::task::JoinHandle<T>) {
    task.abort();
    let _ = task.await;
}

async fn mark_watcher_authorization_required(
    catalog: &CatalogStore,
    source_id: &str,
    revision_lease: &WatcherRevisionLease,
) {
    let Some(expected_revision) = revision_lease.current_revision() else {
        return;
    };
    let Some(revision_guard) = revision_lease.lock_revision(expected_revision).await else {
        return;
    };
    let source = match catalog
        .mark_source_error(
            source_id,
            "authorization_required",
            expected_revision,
            AuditContext::system(None),
        )
        .await
    {
        Ok(source) => source,
        Err(error) => {
            tracing::debug!(
                source_id,
                error = %error,
                "MCP authorization health transition was superseded"
            );
            return;
        }
    };
    let _ = revision_guard.advance(source.revision);
}

async fn wait_for_http_authorization_change(
    oauth: Option<&OAuthService>,
    source_id: &str,
    credential: &StoredMcpHttpCredentialV1,
    allow_private_network: bool,
    active_revision: Option<&OAuthTransportRevision>,
    canceled: &mut tokio::sync::oneshot::Receiver<()>,
) -> bool {
    if credential.credential.is_some() || oauth.is_none() {
        return true;
    }
    let mut poll = tokio::time::interval(Duration::from_secs(30));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    poll.tick().await;
    loop {
        tokio::select! {
            _ = &mut *canceled => return true,
            _ = poll.tick() => {
                if let Ok((_, current_revision)) = http_transport_config_for_source(
                    oauth,
                    source_id,
                    credential,
                    allow_private_network,
                )
                .await
                    && oauth_transport_changed(active_revision, current_revision.as_ref())
                {
                    return false;
                }
            }
        }
    }
}

struct StdioWatcherContext {
    connections: Arc<McpConnectionManager>,
    catalog: CatalogStore,
    source_id: String,
    credential: StoredMcpStdioCredentialV1,
    credential_revision: i64,
    revision_lease: WatcherRevisionLease,
}

async fn run_stdio_watcher(
    context: StdioWatcherContext,
    mut canceled: tokio::sync::oneshot::Receiver<()>,
) {
    let StdioWatcherContext {
        connections,
        catalog,
        source_id,
        credential,
        credential_revision,
        revision_lease,
    } = context;
    let mut retry_delay = Duration::from_secs(1);
    loop {
        let Some(source_revision) = revision_lease.current_revision() else {
            return;
        };
        let operation = match connections.begin_operation() {
            Ok(operation) => operation,
            Err(_) => return,
        };
        let client = match connections
            .stdio_templates()
            .connect_with_secrets(
                &credential.template_name,
                &credential.secret_values,
                StdioTransportLimits::default(),
            )
            .await
        {
            Ok(client) => client,
            Err(_) => {
                tracing::warn!(source_id, "MCP stdio watcher transport failed");
                drop(operation);
                if watcher_retry_or_cancel(&mut canceled, retry_delay).await {
                    return;
                }
                retry_delay = next_watcher_backoff(retry_delay);
                continue;
            }
        };
        let mut changed = client.subscribe_tool_list_changed();
        let initialized = match client
            .initialize(
                STDIO_PROTOCOL_VERSION,
                client_info(),
                Value::Object(Map::new()),
            )
            .await
        {
            Ok(initialized) => initialized,
            Err(_) => {
                tracing::warn!(source_id, "MCP stdio watcher initialization failed");
                client.shutdown().await;
                drop(operation);
                if watcher_retry_or_cancel(&mut canceled, retry_delay).await {
                    return;
                }
                retry_delay = next_watcher_backoff(retry_delay);
                continue;
            }
        };
        let basis =
            match stdio_discovery_basis(initialized, source_revision, Some(credential_revision)) {
                Ok(basis) => basis,
                Err(error) => {
                    tracing::warn!(
                        source_id,
                        code = error.code,
                        "MCP stdio watcher initialization metadata is invalid"
                    );
                    client.shutdown().await;
                    return;
                }
            };
        match watcher_reconcile_or_cancel(&mut canceled, || {
            reconcile_watcher_session(async {
                let plan = discover_stdio_session(&client, &mut changed, basis.clone()).await?;
                commit_watcher_discovery(&catalog, &source_id, plan, None, &revision_lease).await
            })
        })
        .await
        {
            None => {
                client.shutdown().await;
                return;
            }
            Some(Ok(reconciled)) => {
                let (synced, supports_list_changed) = reconciled.into_inner();
                retry_delay = Duration::from_secs(1);
                if !supports_list_changed {
                    connections
                        .stop_watcher_at_revision(&source_id, synced.source_revision)
                        .await;
                    client.shutdown().await;
                    return;
                }
            }
            Some(Err(error)) => {
                tracing::warn!(
                    source_id,
                    code = error.code,
                    "MCP stdio watcher startup reconciliation failed"
                );
                client.shutdown().await;
                drop(operation);
                if watcher_retry_or_cancel(&mut canceled, retry_delay).await {
                    return;
                }
                retry_delay = next_watcher_backoff(retry_delay);
                continue;
            }
        }
        let lifecycle = client.lifecycle_monitor();
        let client = Arc::new(tokio::sync::Mutex::new(Some(client)));
        let coalescer = ListChangedCoalescer::default();
        let mut heartbeat = tokio::time::interval(STDIO_WATCHER_HEARTBEAT);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat.tick().await;
        'stdio_notifications: loop {
            tokio::select! {
                _ = &mut canceled => {
                    shutdown_shared_stdio(client).await;
                    return;
                }
                _ = heartbeat.tick() => {
                    if !lifecycle.is_initialized() {
                        tracing::debug!(source_id, "MCP stdio watcher disconnected");
                        break;
                    }
                }
                signal = changed.recv() => {
                    match signal {
                        Ok(()) | Err(RecvError::Lagged(_)) => {
                            retry_delay = Duration::from_secs(1);
                            coalescer.notify_changed();
                            drain_change_signals(&mut changed, &coalescer);
                            let refresh_result = {
                                let refresh = coalescer.refresh_pending(|| {
                                    refresh_stdio_watcher_session(
                                        catalog.clone(),
                                        source_id.clone(),
                                        client.clone(),
                                        basis.clone(),
                                        connections.clone(),
                                        revision_lease.clone(),
                                    )
                                });
                                tokio::pin!(refresh);
                                wait_for_watcher_refresh(
                                    &mut canceled,
                                    wait_for_stdio_disconnect(&lifecycle),
                                    &mut refresh,
                                )
                                .await
                            };
                            let refresh_result = match refresh_result {
                                WatcherRefreshWait::Canceled => {
                                    shutdown_shared_stdio(client.clone()).await;
                                    return;
                                }
                                WatcherRefreshWait::Disconnected(()) => {
                                    tracing::debug!(source_id, "MCP stdio watcher disconnected during refresh");
                                    break 'stdio_notifications;
                                }
                                WatcherRefreshWait::Completed(result) => result,
                            };
                            if let Err(error) = refresh_result {
                                tracing::warn!(source_id, code = error.code, "MCP stdio notification refresh failed");
                                let mut refresh_delay = Duration::from_secs(1);
                                'stdio_refresh_retries: while coalescer.has_pending() {
                                    match wait_for_watcher_refresh(
                                        &mut canceled,
                                        wait_for_stdio_disconnect(&lifecycle),
                                        tokio::time::sleep(refresh_delay),
                                    )
                                    .await
                                    {
                                        WatcherRefreshWait::Canceled => {
                                            shutdown_shared_stdio(client.clone()).await;
                                            return;
                                        }
                                        WatcherRefreshWait::Disconnected(()) => {
                                            tracing::debug!(source_id, "MCP stdio watcher disconnected during refresh retry");
                                            break 'stdio_notifications;
                                        }
                                        WatcherRefreshWait::Completed(()) => {}
                                    }
                                    let retried = coalescer.refresh_pending(|| {
                                        refresh_stdio_watcher_session(
                                            catalog.clone(),
                                            source_id.clone(),
                                            client.clone(),
                                            basis.clone(),
                                            connections.clone(),
                                            revision_lease.clone(),
                                        )
                                    });
                                    tokio::pin!(retried);
                                    match wait_for_watcher_refresh(
                                        &mut canceled,
                                        wait_for_stdio_disconnect(&lifecycle),
                                        &mut retried,
                                    )
                                    .await
                                    {
                                        WatcherRefreshWait::Canceled => {
                                            shutdown_shared_stdio(client.clone()).await;
                                            return;
                                        }
                                        WatcherRefreshWait::Disconnected(()) => {
                                            tracing::debug!(source_id, "MCP stdio watcher disconnected during refresh retry");
                                            break 'stdio_notifications;
                                        }
                                        WatcherRefreshWait::Completed(Ok(_)) => {
                                            break 'stdio_refresh_retries;
                                        }
                                        WatcherRefreshWait::Completed(Err(_)) => {}
                                    }
                                    refresh_delay = next_watcher_backoff(refresh_delay);
                                }
                            }
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
            }
        }
        shutdown_shared_stdio(client).await;
        drop(operation);
        if watcher_retry_or_cancel(&mut canceled, retry_delay).await {
            return;
        }
        retry_delay = next_watcher_backoff(retry_delay);
    }
}

fn drain_change_signals(
    receiver: &mut tokio::sync::broadcast::Receiver<()>,
    coalescer: &ListChangedCoalescer,
) {
    loop {
        match receiver.try_recv() {
            Ok(()) | Err(TryRecvError::Lagged(_)) => {
                coalescer.notify_changed();
            }
            Err(TryRecvError::Empty | TryRecvError::Closed) => return,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn refresh_http_watcher_session(
    catalog: CatalogStore,
    source_id: String,
    transport: StreamableHttpTransport,
    mut basis: DiscoveryBasis,
    oauth_expectation: Option<OAuthBindingExpectation>,
    connections: Arc<McpConnectionManager>,
    revision_lease: WatcherRevisionLease,
) -> Result<(), ProtocolError> {
    basis.expected_source_revision = revision_lease
        .current_revision()
        .ok_or_else(stale_watcher_reconciliation)?;
    let mut changed = transport.subscribe_tool_list_changed();
    let authorization_required_on_denial = oauth_expectation.is_some();
    let plan = discover_http_session(
        &transport,
        &mut changed,
        basis,
        authorization_required_on_denial,
    )
    .await?;
    let (_, supports_list_changed) = commit_watcher_discovery(
        &catalog,
        &source_id,
        plan,
        oauth_expectation,
        &revision_lease,
    )
    .await?;
    if !supports_list_changed {
        let source_revision = revision_lease
            .current_revision()
            .ok_or_else(stale_watcher_reconciliation)?;
        connections
            .stop_watcher_at_revision(&source_id, source_revision)
            .await;
    }
    Ok(())
}

async fn refresh_stdio_watcher_session(
    catalog: CatalogStore,
    source_id: String,
    client: Arc<tokio::sync::Mutex<Option<crate::mcp::upstream::stdio::StdioClient>>>,
    mut basis: DiscoveryBasis,
    connections: Arc<McpConnectionManager>,
    revision_lease: WatcherRevisionLease,
) -> Result<(), ProtocolError> {
    basis.expected_source_revision = revision_lease
        .current_revision()
        .ok_or_else(stale_watcher_reconciliation)?;
    let client = client.lock().await;
    let client = client.as_ref().ok_or_else(stale_watcher_reconciliation)?;
    let mut changed = client.subscribe_tool_list_changed();
    let plan = discover_stdio_session(client, &mut changed, basis).await?;
    let (_, supports_list_changed) =
        commit_watcher_discovery(&catalog, &source_id, plan, None, &revision_lease).await?;
    if !supports_list_changed {
        let source_revision = revision_lease
            .current_revision()
            .ok_or_else(stale_watcher_reconciliation)?;
        connections
            .stop_watcher_at_revision(&source_id, source_revision)
            .await;
    }
    Ok(())
}

async fn shutdown_shared_stdio(
    client: Arc<tokio::sync::Mutex<Option<crate::mcp::upstream::stdio::StdioClient>>>,
) {
    if let Some(client) = client.lock().await.take() {
        client.shutdown().await;
    }
}

async fn wait_for_stdio_disconnect(lifecycle: &StdioLifecycleMonitor) {
    loop {
        if !lifecycle.is_initialized() {
            return;
        }
        tokio::time::sleep(STDIO_WATCHER_HEARTBEAT).await;
    }
}

enum WatcherRefreshWait<Output, Disconnect = ()> {
    Canceled,
    Disconnected(Disconnect),
    Completed(Output),
}

async fn wait_for_watcher_refresh<Disconnect, Refresh>(
    canceled: &mut tokio::sync::oneshot::Receiver<()>,
    disconnect: Disconnect,
    refresh: Refresh,
) -> WatcherRefreshWait<Refresh::Output, Disconnect::Output>
where
    Disconnect: Future,
    Refresh: Future,
{
    tokio::select! {
        _ = canceled => WatcherRefreshWait::Canceled,
        disconnected = disconnect => WatcherRefreshWait::Disconnected(disconnected),
        result = refresh => WatcherRefreshWait::Completed(result),
    }
}

async fn commit_watcher_discovery(
    catalog: &CatalogStore,
    source_id: &str,
    plan: DiscoveryPlan,
    oauth_expectation: Option<OAuthBindingExpectation>,
    revision_lease: &WatcherRevisionLease,
) -> Result<(CatalogSyncResult, bool), ProtocolError> {
    let expected_revision = plan.basis.expected_source_revision;
    let supports_list_changed = plan.basis.tools_list_changed;
    let revision_guard = revision_lease
        .lock_revision(expected_revision)
        .await
        .ok_or_else(stale_watcher_reconciliation)?;
    let result = match oauth_expectation {
        Some(expectation) => {
            catalog
                .sync_catalog_with_bindings_and_oauth_binding(
                    source_id,
                    plan.catalog_snapshot(),
                    plan.bindings,
                    expectation,
                    AuditContext::system(None),
                )
                .await
        }
        None => {
            catalog
                .sync_catalog_with_bindings(
                    source_id,
                    plan.catalog_snapshot(),
                    plan.bindings,
                    AuditContext::system(None),
                )
                .await
        }
    }
    .map_err(protocol_catalog_error)?;
    if !revision_guard.advance(result.source_revision) {
        return Err(stale_watcher_reconciliation());
    }
    Ok((result, supports_list_changed))
}

struct ReconciledWatcherSession<Output>(Output);

impl<Output> ReconciledWatcherSession<Output> {
    fn into_inner(self) -> Output {
        self.0
    }
}

async fn finished_http_listener_after_reconciliation<Output>(
    _reconciled: &ReconciledWatcherSession<Output>,
    listener: &mut tokio::task::JoinHandle<Result<(), StreamableHttpError>>,
) -> Option<Result<Result<(), StreamableHttpError>, tokio::task::JoinError>> {
    if listener.is_finished() {
        Some(listener.await)
    } else {
        None
    }
}

async fn reconcile_watcher_session<Reconciliation, Output, Error>(
    reconciliation: Reconciliation,
) -> Result<ReconciledWatcherSession<Output>, Error>
where
    Reconciliation: Future<Output = Result<Output, Error>>,
{
    reconciliation.await.map(ReconciledWatcherSession)
}

async fn watcher_reconcile_or_cancel<Refresh, RefreshFuture, Output>(
    canceled: &mut tokio::sync::oneshot::Receiver<()>,
    refresh: Refresh,
) -> Option<Output>
where
    Refresh: FnOnce() -> RefreshFuture,
    RefreshFuture: Future<Output = Output>,
{
    tokio::select! {
        _ = canceled => None,
        result = refresh() => Some(result),
    }
}

async fn watcher_retry_or_cancel(
    canceled: &mut tokio::sync::oneshot::Receiver<()>,
    delay: Duration,
) -> bool {
    tokio::select! {
        _ = canceled => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

fn next_watcher_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(Duration::from_secs(60))
}

fn permanent_http_notification_error(error: &StreamableHttpError) -> bool {
    matches!(
        error,
        StreamableHttpError::HttpStatus(reqwest::StatusCode::METHOD_NOT_ALLOWED)
            | StreamableHttpError::InvalidSessionId
            | StreamableHttpError::NotInitialized
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum McpOAuthBindingObservation {
    NotApplicable,
    Static,
    Anonymous,
    Managed(OAuthBinding),
}

#[must_use = "a prepared MCP invocation must be executed or explicitly discarded"]
pub(super) enum PreparedMcpInvocation {
    Http {
        source_id: String,
        credential: StoredMcpHttpCredentialV1,
        allow_private_network: bool,
        oauth_binding: McpOAuthBindingObservation,
        tool_name: String,
        arguments: Value,
    },
    Stdio {
        template_name: String,
        secret_values: BTreeMap<String, String>,
        tool_name: String,
        arguments: Value,
    },
}

#[derive(Debug, Error)]
pub enum McpInvocationError {
    #[error("MCP authorization setup failed")]
    AuthorizationSetup(#[source] ProtocolError),
    #[error("MCP Streamable HTTP session setup failed")]
    HttpSetup(#[source] StreamableHttpError),
    #[error("MCP Streamable HTTP tool call failed and its outcome is unknown")]
    HttpCall(#[source] StreamableHttpError),
    #[error("MCP stdio session setup failed")]
    StdioSetup(#[source] StdioTransportError),
    #[error("MCP stdio tool call failed and its outcome is unknown")]
    StdioCall(#[source] StdioTransportError),
    #[error("MCP connections are shutting down")]
    ShuttingDown,
}

impl McpInvocationError {
    pub fn outcome_unknown(&self) -> bool {
        matches!(self, Self::StdioCall(_) | Self::HttpCall(_))
    }
}

impl McpHttpSourceConfigurationV1 {
    fn decode(configuration: &Map<String, Value>) -> Result<Self, ProtocolError> {
        let decoded: Self = decode_configuration(configuration)?;
        if !is_supported_protocol_version(&decoded.negotiated_protocol_version) {
            return Err(corrupt_configuration());
        }
        validate_endpoint(&decoded.endpoint).map_err(|_| corrupt_configuration())?;
        Ok(decoded)
    }
}

impl McpStdioSourceConfigurationV1 {
    fn decode(configuration: &Map<String, Value>) -> Result<Self, ProtocolError> {
        let decoded: Self = decode_configuration(configuration)?;
        if decoded.template_name.is_empty()
            || decoded
                .negotiated_protocol_version
                .as_deref()
                .is_some_and(|version| version != HTTP_PROTOCOL_VERSION)
        {
            return Err(corrupt_configuration());
        }
        Ok(decoded)
    }
}

impl StoredMcpHttpCredentialV1 {
    fn decode(stored: &StoredCredential) -> Result<Self, ProtocolError> {
        require_schema(stored, false)?;
        let decoded: Self = serde_json::from_value(stored.credential.payload.clone())
            .map_err(|_| corrupt_credentials())?;
        validate_endpoint(&decoded.endpoint).map_err(|_| corrupt_credentials())?;
        validate_http_credential(decoded.credential.as_ref()).map_err(|_| corrupt_credentials())?;
        Ok(decoded)
    }

    fn decode_for_invocation(stored: &StoredCredential) -> Result<Self, ProtocolError> {
        require_schema(stored, true)?;
        Self::decode(stored)
    }

    fn payload(&self) -> Result<CredentialPayload, ProtocolError> {
        credential_payload(self)
    }
}

impl StoredMcpStdioCredentialV1 {
    fn decode(stored: &StoredCredential) -> Result<Self, ProtocolError> {
        require_schema(stored, false)?;
        let decoded: Self = serde_json::from_value(stored.credential.payload.clone())
            .map_err(|_| corrupt_credentials())?;
        if decoded.template_name.is_empty() {
            return Err(corrupt_credentials());
        }
        validate_secret_values(&decoded.secret_values).map_err(|_| corrupt_credentials())?;
        Ok(decoded)
    }

    fn decode_for_invocation(stored: &StoredCredential) -> Result<Self, ProtocolError> {
        require_schema(stored, true)?;
        Self::decode(stored)
    }

    fn payload(&self) -> Result<CredentialPayload, ProtocolError> {
        credential_payload(self)
    }
}

async fn execute_http(
    config: StreamableHttpConfig,
    tool_name: &str,
    arguments: Value,
) -> Result<ProtocolExecutionResponse, McpInvocationError> {
    let transport = StreamableHttpTransport::new(config).map_err(McpInvocationError::HttpSetup)?;
    transport
        .initialize()
        .await
        .map_err(McpInvocationError::HttpSetup)?;
    let called = transport
        .call_tool(tool_name, arguments, json!(1))
        .await
        .map_err(McpInvocationError::HttpCall);
    let _ = transport.terminate().await;
    called.map(mcp_response)
}

async fn execute_stdio(
    templates: &StdioTemplateRegistry,
    template_name: &str,
    secret_values: &BTreeMap<String, String>,
    tool_name: &str,
    arguments: Value,
) -> Result<ProtocolExecutionResponse, McpInvocationError> {
    let client = templates
        .connect_with_secrets(
            template_name,
            secret_values,
            StdioTransportLimits::default(),
        )
        .await
        .map_err(McpInvocationError::StdioSetup)?;
    if let Err(error) = client
        .initialize(
            STDIO_PROTOCOL_VERSION,
            client_info(),
            Value::Object(Map::new()),
        )
        .await
    {
        client.shutdown().await;
        return Err(McpInvocationError::StdioSetup(error));
    }
    let called = client
        .call_tool(tool_name, arguments, 2)
        .await
        .map_err(McpInvocationError::StdioCall);
    client.shutdown().await;
    called.map(|result| {
        mcp_response(json!({
            "content": result.content,
            "structuredContent": result.structured_content,
            "isError": result.is_error,
        }))
    })
}

fn mcp_response(result: Value) -> ProtocolExecutionResponse {
    let is_error = result
        .as_object()
        .and_then(|result| result.get("isError"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    ProtocolExecutionResponse {
        ok: !is_error,
        data: (!is_error).then_some(result),
        error: is_error.then_some(ProtocolResponseError {
            code: "upstream_tool_error".to_owned(),
            message: "The upstream MCP tool returned an error result.".to_owned(),
        }),
        http: None,
    }
}

async fn discover_http(
    stored: &StoredMcpHttpCredentialV1,
    allow_private_network: bool,
    source_revision: i64,
    credential_revision: Option<i64>,
) -> Result<DiscoveryPlan, ProtocolError> {
    let config = http_transport_config(stored, allow_private_network)?;
    discover_http_config(
        config,
        source_revision,
        credential_revision,
        stored.credential.is_none(),
    )
    .await
}

async fn discover_http_config(
    config: StreamableHttpConfig,
    source_revision: i64,
    credential_revision: Option<i64>,
    authorization_required_on_denial: bool,
) -> Result<DiscoveryPlan, ProtocolError> {
    let transport = StreamableHttpTransport::new(config).map_err(http_protocol_error)?;
    let mut changed = transport.subscribe_tool_list_changed();
    let initialized = transport.initialize().await.map_err(|error| {
        http_protocol_error_for_authorization(error, authorization_required_on_denial)
    })?;
    let plan = match http_discovery_basis(initialized, source_revision, credential_revision) {
        Ok(basis) => {
            discover_http_session(
                &transport,
                &mut changed,
                basis,
                authorization_required_on_denial,
            )
            .await
        }
        Err(error) => Err(error),
    };
    let _ = transport.terminate().await;
    plan
}

enum HttpCreateDiscovery {
    Ready(Box<DiscoveryPlan>),
    AuthorizationRequired,
}

impl HttpCreateDiscovery {
    fn protocol_version(&self) -> &str {
        match self {
            Self::Ready(plan) => &plan.basis.protocol_version,
            Self::AuthorizationRequired => HTTP_PROTOCOL_VERSION,
        }
    }
}

async fn discover_http_for_create(
    stored: &StoredMcpHttpCredentialV1,
    allow_private_network: bool,
    source_revision: i64,
    credential_revision: Option<i64>,
) -> Result<HttpCreateDiscovery, ProtocolError> {
    let config = http_transport_config(stored, allow_private_network)?;
    let transport = StreamableHttpTransport::new(config).map_err(http_protocol_error)?;
    let mut changed = transport.subscribe_tool_list_changed();
    let initialized = match transport.initialize().await {
        Ok(initialized) => initialized,
        Err(error) if stored.credential.is_none() && http_authorization_denied(&error) => {
            return Ok(HttpCreateDiscovery::AuthorizationRequired);
        }
        Err(error) => return Err(http_protocol_error(error)),
    };
    let plan = match http_discovery_basis(initialized, source_revision, credential_revision) {
        Ok(basis) => {
            discover_http_session(&transport, &mut changed, basis, stored.credential.is_none())
                .await
        }
        Err(error) => Err(error),
    };
    let _ = transport.terminate().await;
    match plan {
        Ok(plan) => Ok(HttpCreateDiscovery::Ready(Box::new(plan))),
        Err(error) if stored.credential.is_none() && error.code == "authorization_required" => {
            Ok(HttpCreateDiscovery::AuthorizationRequired)
        }
        Err(error) => Err(error),
    }
}

async fn discover_stdio(
    templates: &StdioTemplateRegistry,
    stored: &StoredMcpStdioCredentialV1,
    source_revision: i64,
    credential_revision: Option<i64>,
) -> Result<DiscoveryPlan, ProtocolError> {
    let client = templates
        .connect_with_secrets(
            &stored.template_name,
            &stored.secret_values,
            StdioTransportLimits::default(),
        )
        .await
        .map_err(stdio_protocol_error)?;
    let mut changed = client.subscribe_tool_list_changed();
    let initialized = match client
        .initialize(
            STDIO_PROTOCOL_VERSION,
            client_info(),
            Value::Object(Map::new()),
        )
        .await
    {
        Ok(initialized) => initialized,
        Err(error) => {
            client.shutdown().await;
            return Err(stdio_protocol_error(error));
        }
    };
    let plan = match stdio_discovery_basis(initialized, source_revision, credential_revision) {
        Ok(basis) => discover_stdio_session(&client, &mut changed, basis).await,
        Err(error) => Err(error),
    };
    client.shutdown().await;
    plan
}

async fn discover_http_session(
    transport: &StreamableHttpTransport,
    changed: &mut tokio::sync::broadcast::Receiver<()>,
    basis: DiscoveryBasis,
    authorization_required_on_denial: bool,
) -> Result<DiscoveryPlan, ProtocolError> {
    tokio::time::timeout(DISCOVERY_DEADLINE, async {
        let mut generation = 0_usize;
        let mut next_request_id = 1_u64;
        loop {
            generation += 1;
            if generation > MAX_DISCOVERY_GENERATIONS {
                return Err(unstable_catalog());
            }
            let starting_request_id = next_request_id;
            let mut fetcher = HttpPageFetcher {
                transport,
                next_request_id,
                authorization_required_on_denial,
            };
            let plan = discover(&mut fetcher, basis.clone())
                .await
                .map_err(discovery_protocol_error)?;
            next_request_id = fetcher.next_request_id;
            if next_request_id == starting_request_id {
                return Err(ProtocolError::new(
                    ProtocolErrorCategory::Internal,
                    "internal_error",
                    "MCP discovery did not issue a tools/list request.",
                ));
            }
            if !catalog_changed_before_quiet(changed).await {
                return Ok(plan);
            }
        }
    })
    .await
    .unwrap_or_else(|_| Err(discovery_timeout()))
}

async fn discover_stdio_session(
    client: &crate::mcp::upstream::stdio::StdioClient,
    changed: &mut tokio::sync::broadcast::Receiver<()>,
    basis: DiscoveryBasis,
) -> Result<DiscoveryPlan, ProtocolError> {
    tokio::time::timeout(DISCOVERY_DEADLINE, async {
        for _ in 0..MAX_DISCOVERY_GENERATIONS {
            let mut fetcher = StdioPageFetcher { client };
            let plan = discover(&mut fetcher, basis.clone())
                .await
                .map(bindings_for_stdio)
                .map_err(discovery_protocol_error)?;
            if !catalog_changed_before_quiet(changed).await {
                return Ok(plan);
            }
        }
        Err(unstable_catalog())
    })
    .await
    .unwrap_or_else(|_| Err(discovery_timeout()))
}

async fn catalog_changed_before_quiet(receiver: &mut tokio::sync::broadcast::Receiver<()>) -> bool {
    let mut changed = false;
    loop {
        match receiver.try_recv() {
            Ok(()) | Err(TryRecvError::Lagged(_)) => changed = true,
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Closed) => return changed,
        }
    }
    if changed {
        return true;
    }
    match tokio::time::timeout(DISCOVERY_QUIET_PERIOD, receiver.recv()).await {
        Ok(Ok(())) | Ok(Err(RecvError::Lagged(_))) => true,
        Ok(Err(RecvError::Closed)) | Err(_) => false,
    }
}

fn bindings_for_stdio(plan: DiscoveryPlan) -> DiscoveryPlan {
    bindings_for_source_kind(plan, true)
}

struct HttpPageFetcher<'a> {
    transport: &'a StreamableHttpTransport,
    next_request_id: u64,
    authorization_required_on_denial: bool,
}

#[async_trait]
impl ToolPageFetcher for HttpPageFetcher<'_> {
    type Error = McpPageFetchError;

    async fn fetch_tools_page(&mut self, cursor: Option<&str>) -> Result<ToolPage, Self::Error> {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        let page = self
            .transport
            .list_tools(cursor, json!(id))
            .await
            .map_err(|error| {
                if self.authorization_required_on_denial && http_authorization_denied(&error) {
                    McpPageFetchError::AuthorizationRequired
                } else {
                    McpPageFetchError::Http(error)
                }
            })?;
        let tools = page
            .tools
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<DiscoveredMcpTool>, _>>()
            .map_err(|_| McpPageFetchError::Decode)?;
        Ok(ToolPage {
            tools,
            next_cursor: page.next_cursor,
        })
    }
}

struct StdioPageFetcher<'a> {
    client: &'a crate::mcp::upstream::stdio::StdioClient,
}

#[async_trait]
impl ToolPageFetcher for StdioPageFetcher<'_> {
    type Error = McpPageFetchError;

    async fn fetch_tools_page(&mut self, cursor: Option<&str>) -> Result<ToolPage, Self::Error> {
        let page = self
            .client
            .list_tools(cursor)
            .await
            .map_err(McpPageFetchError::Stdio)?;
        let tools = page
            .tools
            .into_iter()
            .map(|tool| {
                let annotations = tool
                    .annotations
                    .map(serde_json::from_value)
                    .transpose()
                    .map_err(|_| McpPageFetchError::Decode)?;
                Ok(DiscoveredMcpTool {
                    name: tool.name,
                    title: tool.title,
                    description: tool.description,
                    input_schema: tool.input_schema,
                    output_schema: tool.output_schema,
                    annotations,
                    meta: Map::new(),
                })
            })
            .collect::<Result<Vec<_>, McpPageFetchError>>()?;
        Ok(ToolPage {
            tools,
            next_cursor: page.next_cursor,
        })
    }
}

#[derive(Debug, Error)]
enum McpPageFetchError {
    #[error("MCP authorization is required")]
    AuthorizationRequired,
    #[error("MCP HTTP tools/list failed")]
    Http(#[source] StreamableHttpError),
    #[error("MCP stdio tools/list failed")]
    Stdio(#[source] StdioTransportError),
    #[error("MCP tools/list response could not be decoded")]
    Decode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpInitializeResult {
    protocol_version: String,
    #[serde(default)]
    capabilities: Value,
    server_info: HttpServerInfo,
    #[serde(default)]
    instructions: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HttpServerInfo {
    name: String,
    version: String,
    #[serde(default)]
    title: Option<String>,
}

fn http_discovery_basis(
    initialized: Value,
    expected_source_revision: i64,
    expected_credential_revision: Option<i64>,
) -> Result<DiscoveryBasis, ProtocolError> {
    let initialized: HttpInitializeResult = serde_json::from_value(initialized).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            "invalid_mcp_initialize",
            "The MCP server returned invalid initialization metadata.",
        )
    })?;
    if !is_supported_protocol_version(&initialized.protocol_version) {
        return Err(ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            "mcp_protocol_version_mismatch",
            "The MCP server selected an unsupported protocol version.",
        ));
    }
    Ok(DiscoveryBasis {
        expected_source_revision,
        expected_credential_revision,
        protocol_version: initialized.protocol_version,
        server_name: initialized.server_info.name,
        server_version: initialized.server_info.version,
        server_title: initialized.server_info.title,
        instructions: initialized.instructions,
        capabilities: initialized.capabilities.clone(),
        tools_list_changed: tools_list_changed(&initialized.capabilities),
    })
}

fn stdio_discovery_basis(
    initialized: InitializeResult,
    expected_source_revision: i64,
    expected_credential_revision: Option<i64>,
) -> Result<DiscoveryBasis, ProtocolError> {
    let server_info = initialized.server_info.ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            "invalid_mcp_initialize",
            "The MCP server returned invalid initialization metadata.",
        )
    })?;
    Ok(DiscoveryBasis {
        expected_source_revision,
        expected_credential_revision,
        protocol_version: initialized.protocol_version.to_string(),
        server_name: server_info.name,
        server_version: server_info.version,
        server_title: server_info.title,
        instructions: initialized.instructions,
        capabilities: initialized.capabilities.clone(),
        tools_list_changed: tools_list_changed(&initialized.capabilities),
    })
}

fn tools_list_changed(capabilities: &Value) -> bool {
    capabilities
        .as_object()
        .and_then(|capabilities| capabilities.get("tools"))
        .and_then(Value::as_object)
        .and_then(|tools| tools.get("listChanged"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn client_info() -> Value {
    json!({ "name": "executor", "version": env!("CARGO_PKG_VERSION") })
}

fn http_transport_config(
    stored: &StoredMcpHttpCredentialV1,
    allow_private_network: bool,
) -> Result<StreamableHttpConfig, ProtocolError> {
    validate_http_credential(stored.credential.as_ref())?;
    let endpoint = validate_endpoint(&stored.endpoint)?;
    let mut config = StreamableHttpConfig::new(endpoint.to_string());
    config.allow_private_networks = allow_private_network;
    if let Some(credential) = &stored.credential {
        config.headers = credential.headers()?;
    }
    Ok(config)
}

async fn http_transport_config_for_source(
    oauth: Option<&OAuthService>,
    source_id: &str,
    stored: &StoredMcpHttpCredentialV1,
    allow_private_network: bool,
) -> Result<(StreamableHttpConfig, Option<OAuthTransportRevision>), ProtocolError> {
    let config = http_transport_config(stored, allow_private_network)?;
    if stored.credential.is_some() {
        return Ok((config, None));
    }
    let Some(oauth) = oauth else {
        return Ok((config, None));
    };
    let Some(binding) = oauth
        .binding(source_id, "default")
        .await
        .map_err(mcp_oauth_error)?
    else {
        return Ok((config, None));
    };
    http_transport_config_for_binding(
        Some(oauth),
        source_id,
        stored,
        allow_private_network,
        Some(&binding),
    )
    .await
}

async fn http_transport_config_for_binding(
    oauth: Option<&OAuthService>,
    source_id: &str,
    stored: &StoredMcpHttpCredentialV1,
    allow_private_network: bool,
    binding: Option<&OAuthBinding>,
) -> Result<(StreamableHttpConfig, Option<OAuthTransportRevision>), ProtocolError> {
    let mut config = http_transport_config(stored, allow_private_network)?;
    if stored.credential.is_some() || binding.is_none() {
        return Ok((config, None));
    }
    let oauth = oauth.ok_or_else(|| {
        ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "authorization_required",
            "The MCP source requires OAuth authorization.",
        )
    })?;
    let binding = binding.expect("binding presence checked");
    if binding.credential_key != "default" {
        return Err(ProtocolError::corrupt(
            "source_authorization_mismatch",
            "The prepared MCP authorization state is inconsistent.",
        ));
    }
    let current = oauth
        .binding(source_id, "default")
        .await
        .map_err(mcp_oauth_error)?;
    if current.as_ref() != Some(binding) {
        return Err(ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "oauth_binding_changed",
            "The managed OAuth connection changed. Retry the operation.",
        ));
    }
    let token = oauth
        .access_token_for_binding(binding)
        .await
        .map_err(mcp_oauth_error)?;
    if token.connection_id() != binding.connection_id
        || token.config_revision() != binding.config_revision
    {
        return Err(ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "oauth_binding_changed",
            "The managed OAuth connection changed. Retry the operation.",
        ));
    }
    let mut authorization =
        HeaderValue::from_str(&format!("Bearer {}", token.expose())).map_err(|_| {
            ProtocolError::new(
                ProtocolErrorCategory::Upstream,
                "invalid_oauth_access_token",
                "The OAuth provider returned an access token that cannot be used safely.",
            )
        })?;
    authorization.set_sensitive(true);
    config.headers.insert(AUTHORIZATION, authorization);
    Ok((
        config,
        Some(OAuthTransportRevision {
            binding: binding.clone(),
            secret_revision: token.secret_revision(),
        }),
    ))
}

async fn http_transport_config_for_observation(
    oauth: Option<&OAuthService>,
    source_id: &str,
    stored: &StoredMcpHttpCredentialV1,
    allow_private_network: bool,
    observation: &McpOAuthBindingObservation,
) -> Result<StreamableHttpConfig, ProtocolError> {
    match observation {
        McpOAuthBindingObservation::Static if stored.credential.is_some() => {
            http_transport_config(stored, allow_private_network)
        }
        McpOAuthBindingObservation::Anonymous if stored.credential.is_none() => {
            let current = match oauth {
                Some(oauth) => oauth
                    .binding(source_id, "default")
                    .await
                    .map_err(mcp_oauth_error)?,
                None => None,
            };
            if current.is_some() {
                return Err(ProtocolError::new(
                    ProtocolErrorCategory::Conflict,
                    "oauth_binding_changed",
                    "The managed OAuth connection changed. Retry the operation.",
                ));
            }
            http_transport_config(stored, allow_private_network)
        }
        McpOAuthBindingObservation::Managed(binding) if stored.credential.is_none() => {
            http_transport_config_for_binding(
                oauth,
                source_id,
                stored,
                allow_private_network,
                Some(binding),
            )
            .await
            .map(|(config, _)| config)
        }
        _ => Err(ProtocolError::corrupt(
            "source_authorization_mismatch",
            "The prepared MCP authorization state is inconsistent.",
        )),
    }
}

fn validate_endpoint(endpoint: &str) -> Result<Url, ProtocolError> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_BYTES {
        return Err(ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "invalid_mcp_endpoint",
            "The MCP endpoint is invalid.",
        ));
    }
    let url = Url::parse(endpoint).map_err(|_| invalid_endpoint())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid_endpoint());
    }
    if url.scheme() == "http" && !loopback_endpoint(&url) {
        return Err(invalid_endpoint());
    }
    Ok(url)
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

fn display_endpoint(endpoint: &Url) -> String {
    let mut display = endpoint.clone();
    display.set_query(None);
    display.to_string()
}

fn validate_http_credential(credential: Option<&McpHttpCredential>) -> Result<(), ProtocolError> {
    if let Some(credential) = credential {
        credential.validate()?;
        if serde_json::to_vec(credential)
            .map(|encoded| encoded.len() > MAX_CREDENTIAL_BYTES)
            .unwrap_or(true)
        {
            return Err(invalid_credentials(
                "The MCP credential exceeds the allowed size.",
            ));
        }
    }
    Ok(())
}

fn validate_secret(secret: &str) -> Result<(), ProtocolError> {
    if secret.is_empty() || secret.len() > MAX_SECRET_VALUE_BYTES || secret.as_bytes().contains(&0)
    {
        Err(invalid_credentials("The MCP credential value is invalid."))
    } else {
        Ok(())
    }
}

fn validate_secret_values(values: &BTreeMap<String, String>) -> Result<(), ProtocolError> {
    if values.len() > MAX_SECRET_VALUES {
        return Err(invalid_credentials(
            "The MCP stdio source has too many secret values.",
        ));
    }
    for (name, value) in values {
        if name.is_empty()
            || name.len() > MAX_SECRET_NAME_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(invalid_credentials("An MCP stdio secret name is invalid."));
        }
        validate_secret(value)?;
    }
    Ok(())
}

fn stdio_secrets_complete(
    templates: &StdioTemplateRegistry,
    template_name: &str,
    values: &BTreeMap<String, String>,
) -> Result<bool, ProtocolError> {
    let descriptor = templates
        .descriptors()
        .into_iter()
        .find(|descriptor| descriptor.name == template_name)
        .ok_or_else(|| input_template_error(StdioTemplateError::UnknownTemplate))?;
    if values.is_empty() && !descriptor.secret_fields.is_empty() {
        return Ok(false);
    }
    let exact = values.len() == descriptor.secret_fields.len()
        && descriptor
            .secret_fields
            .iter()
            .all(|field| values.contains_key(field));
    if exact {
        Ok(true)
    } else {
        Err(invalid_credentials(
            "The MCP stdio secret values must exactly match the selected template.",
        ))
    }
}

fn http_credential_metadata(
    revision: i64,
    credential: &StoredMcpHttpCredentialV1,
) -> CredentialMetadata {
    CredentialMetadata {
        revision,
        configured_schemes: credential
            .credential
            .as_ref()
            .map(|credential| {
                vec![ConfiguredCredential {
                    name: "connection".to_owned(),
                    credential_type: credential.credential_type(),
                }]
            })
            .unwrap_or_default(),
    }
}

fn stdio_credential_metadata(
    revision: i64,
    credential: &StoredMcpStdioCredentialV1,
) -> CredentialMetadata {
    CredentialMetadata {
        revision,
        configured_schemes: credential
            .secret_values
            .keys()
            .map(|name| ConfiguredCredential {
                name: name.clone(),
                credential_type: "secret_env",
            })
            .collect(),
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

async fn source_supports_list_changed(
    catalog: &CatalogStore,
    source_id: &str,
) -> Result<bool, ProtocolError> {
    let content = sqlx::query_scalar::<_, String>(
        "SELECT content_json FROM source_artifacts \
         WHERE source_id = ? AND artifact_kind = 'mcp_capabilities' AND stable_key = 'mcp-server'",
    )
    .bind(source_id)
    .fetch_optional(catalog.pool())
    .await
    .map_err(|_| internal_error())?
    .ok_or_else(|| {
        ProtocolError::corrupt(
            "source_artifact_missing",
            "The MCP source capability artifact is missing.",
        )
    })?;
    let content: Value = serde_json::from_str(&content).map_err(|_| corrupt_configuration())?;
    Ok(content
        .as_object()
        .and_then(|content| content.get("toolsListChanged"))
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

fn credential_payload<T: Serialize>(value: &T) -> Result<CredentialPayload, ProtocolError> {
    Ok(CredentialPayload {
        schema_version: MCP_CREDENTIAL_SCHEMA_VERSION,
        payload: serde_json::to_value(value).map_err(|_| internal_error())?,
    })
}

fn encode_configuration<T: Serialize>(value: &T) -> Result<Map<String, Value>, ProtocolError> {
    serde_json::to_value(value)
        .map_err(|_| internal_error())?
        .as_object()
        .cloned()
        .ok_or_else(internal_error)
}

fn decode_configuration<T: for<'de> Deserialize<'de>>(
    configuration: &Map<String, Value>,
) -> Result<T, ProtocolError> {
    serde_json::from_value(Value::Object(configuration.clone()))
        .map_err(|_| corrupt_configuration())
}

fn require_schema(stored: &StoredCredential, invocation: bool) -> Result<(), ProtocolError> {
    if stored.credential.schema_version == MCP_CREDENTIAL_SCHEMA_VERSION {
        Ok(())
    } else if invocation {
        Err(ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "unsupported_credential_schema",
            "The stored MCP credential schema is not supported.",
        ))
    } else {
        Err(ProtocolError::corrupt(
            "unsupported_credential_schema",
            "The stored MCP credential schema is not supported.",
        ))
    }
}

fn require_revision(expected: i64, actual: i64) -> Result<(), ProtocolError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "revision_conflict",
            "The source changed. Refresh and retry the update.",
        ))
    }
}

fn discovery_protocol_error(error: DiscoveryError) -> ProtocolError {
    if let DiscoveryError::Fetch(source) = &error
        && source
            .downcast_ref::<McpPageFetchError>()
            .is_some_and(|error| matches!(error, McpPageFetchError::AuthorizationRequired))
    {
        return ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "authorization_required",
            "The MCP source requires authorization.",
        );
    }
    let (code, message) = match error {
        DiscoveryError::Fetch(_) => (
            "mcp_discovery_failed",
            "The MCP server failed while listing tools.",
        ),
        DiscoveryError::TooManyPages { .. } => (
            "mcp_too_many_pages",
            "The MCP server returned too many tool pages.",
        ),
        DiscoveryError::TooManyTools { .. } => (
            "mcp_too_many_tools",
            "The MCP server returned too many tools.",
        ),
        DiscoveryError::InvalidCursor | DiscoveryError::CursorCycle => (
            "invalid_mcp_cursor",
            "The MCP server returned invalid tool pagination.",
        ),
        DiscoveryError::DuplicateTool { .. } => (
            "duplicate_mcp_tool",
            "The MCP server returned duplicate tool names.",
        ),
        DiscoveryError::InvalidTool { .. } => (
            "invalid_mcp_tool",
            "The MCP server returned an invalid tool definition.",
        ),
        DiscoveryError::CapabilitiesTooLarge => (
            "mcp_capabilities_too_large",
            "The MCP server returned too much capability metadata.",
        ),
        DiscoveryError::InvalidCapabilities => (
            "invalid_mcp_capabilities",
            "The MCP server returned invalid capabilities.",
        ),
        DiscoveryError::ToolMetadataTooLarge => (
            "mcp_tool_metadata_too_large",
            "The MCP server returned too much tool metadata.",
        ),
    };
    ProtocolError::new(ProtocolErrorCategory::Upstream, code, message)
}

fn http_configuration_error(error: StreamableHttpError) -> ProtocolError {
    match error {
        StreamableHttpError::InsecureEndpoint => invalid_endpoint(),
        StreamableHttpError::Outbound(error) => super::protocol_outbound_error(error),
        _ => invalid_credentials("The MCP HTTP credential configuration is invalid."),
    }
}

fn http_protocol_error(error: StreamableHttpError) -> ProtocolError {
    match error {
        StreamableHttpError::InsecureEndpoint => invalid_endpoint(),
        StreamableHttpError::Outbound(error) => super::protocol_outbound_error(error),
        StreamableHttpError::ProtocolVersionMismatch => ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            "mcp_protocol_version_mismatch",
            "The MCP server selected an unsupported protocol version.",
        ),
        _ => ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            "mcp_transport_error",
            "The MCP HTTP server could not be reached or returned an invalid response.",
        ),
    }
}

fn http_authorization_denied(error: &StreamableHttpError) -> bool {
    matches!(
        error,
        StreamableHttpError::HttpStatus(status)
            if matches!(
                *status,
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
            )
    )
}

fn http_protocol_error_for_authorization(
    error: StreamableHttpError,
    authorization_required_on_denial: bool,
) -> ProtocolError {
    if authorization_required_on_denial && http_authorization_denied(&error) {
        ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "authorization_required",
            "The MCP source requires authorization.",
        )
    } else {
        http_protocol_error(error)
    }
}

fn stdio_protocol_error(_error: StdioTransportError) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Upstream,
        "mcp_transport_error",
        "The MCP stdio server could not be started or returned an invalid response.",
    )
}

fn shutting_down(_error: crate::mcp::manager::McpShuttingDown) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        "mcp_shutting_down",
        "MCP connections are shutting down.",
    )
}

fn unstable_catalog() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Upstream,
        "mcp_catalog_unstable",
        "The MCP tool catalog kept changing during discovery.",
    )
}

fn discovery_timeout() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Upstream,
        "mcp_discovery_timeout",
        "MCP tool discovery exceeded its deadline.",
    )
}

fn stale_watcher_reconciliation() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        "stale_watcher_reconciliation",
        "The MCP source changed while its watcher was reconciling.",
    )
}

fn input_template_error(_error: StdioTemplateError) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::InvalidInput,
        "invalid_stdio_template",
        "The selected MCP stdio template is unavailable.",
    )
}

fn stored_template_error(_error: StdioTemplateError) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Conflict,
        "stdio_template_unavailable",
        "The configured MCP stdio template is unavailable.",
    )
}

fn invalid_endpoint() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::InvalidInput,
        "invalid_mcp_endpoint",
        "The MCP endpoint must use HTTPS, or loopback HTTP, without user info or a fragment.",
    )
}

fn invalid_credentials(message: &'static str) -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::InvalidInput,
        "invalid_credentials",
        message,
    )
}

fn mcp_oauth_error(error: OAuthError) -> ProtocolError {
    match error {
        OAuthError::Validation { code, message } => {
            ProtocolError::new(ProtocolErrorCategory::InvalidInput, code, message)
        }
        OAuthError::NotFound | OAuthError::AuthorizationDenied { .. } => ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "authorization_required",
            "The MCP source requires OAuth authorization.",
        ),
        OAuthError::Conflict {
            code: "oauth_reauthorization_required",
            ..
        } => ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "authorization_required",
            "The MCP source requires OAuth authorization.",
        ),
        OAuthError::Conflict { .. } => ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "oauth_binding_changed",
            "The managed OAuth connection changed. Retry the operation.",
        ),
        OAuthError::UnauthorizedTransaction => ProtocolError::new(
            ProtocolErrorCategory::Internal,
            "oauth_internal_error",
            "The managed OAuth credential could not be resolved.",
        ),
        OAuthError::Upstream { code } => ProtocolError::new(
            ProtocolErrorCategory::Upstream,
            code,
            "The OAuth provider request failed.",
        ),
        OAuthError::Internal => ProtocolError::new(
            ProtocolErrorCategory::Internal,
            "oauth_internal_error",
            "The managed OAuth credential could not be resolved.",
        ),
    }
}

fn corrupt_configuration() -> ProtocolError {
    ProtocolError::corrupt(
        "invalid_source_configuration",
        "The stored MCP source configuration is invalid.",
    )
}

fn corrupt_credentials() -> ProtocolError {
    ProtocolError::corrupt(
        "invalid_source_credentials",
        "The stored MCP credential state is invalid.",
    )
}

fn internal_error() -> ProtocolError {
    ProtocolError::new(
        ProtocolErrorCategory::Internal,
        "internal_error",
        "The MCP protocol operation could not be completed.",
    )
}

#[cfg(test)]
fn consume_test_failure(counter: &Option<Arc<std::sync::atomic::AtomicUsize>>) -> bool {
    counter.as_ref().is_some_and(|counter| {
        counter
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        convert::Infallible,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{
        AppConfig, ExecutorApp,
        catalog::{
            AuditContext, CreateSource, CredentialPayload, InitialCatalogSnapshot, ListToolsFilter,
            SourceRecord, StoredCredential, ToolMode,
        },
        crypto::Keyring,
        oauth::{
            model::{OAuthClientAuthentication, OAuthConnectionConfig, OAuthSecretSet},
            store::OAuthStore,
        },
        outbound::OutboundPolicy,
    };

    #[test]
    fn manual_oauth_credential_uses_the_public_wire_shape() {
        let credential: McpHttpCredential = serde_json::from_value(json!({
            "type": "oauth_access_token",
            "accessToken": "secret-token"
        }))
        .expect("public manual OAuth credential decodes");

        assert!(matches!(
            credential,
            McpHttpCredential::OAuthAccessToken { ref access_token }
                if access_token == "secret-token"
        ));
        assert_eq!(
            serde_json::to_value(credential).expect("manual OAuth credential encodes"),
            json!({ "type": "oauth_access_token", "accessToken": "secret-token" })
        );
        assert!(
            serde_json::from_value::<McpHttpCredential>(json!({
                "type": "o_auth_access_token",
                "accessToken": "secret-token"
            }))
            .is_err()
        );
    }

    struct ReconciliationFetcher {
        pages: VecDeque<ToolPage>,
        events: Arc<std::sync::Mutex<Vec<String>>>,
        session: &'static str,
        generation: usize,
    }

    #[async_trait]
    impl ToolPageFetcher for ReconciliationFetcher {
        type Error = Infallible;

        async fn fetch_tools_page(
            &mut self,
            cursor: Option<&str>,
        ) -> Result<ToolPage, Self::Error> {
            let page = if cursor.is_some() { 2 } else { 1 };
            self.events
                .lock()
                .expect("event mutex is available")
                .push(format!(
                    "{}:discover-{}-page-{page}",
                    self.session, self.generation
                ));
            Ok(self.pages.pop_front().expect("discovery page exists"))
        }
    }

    fn reconciliation_basis(expected_source_revision: i64) -> DiscoveryBasis {
        DiscoveryBasis {
            expected_source_revision,
            expected_credential_revision: Some(0),
            protocol_version: HTTP_PROTOCOL_VERSION.to_owned(),
            server_name: "fixture".to_owned(),
            server_version: "1".to_owned(),
            server_title: None,
            instructions: None,
            capabilities: json!({ "tools": { "listChanged": true } }),
            tools_list_changed: true,
        }
    }

    fn reconciliation_tool(name: &str) -> DiscoveredMcpTool {
        DiscoveredMcpTool {
            name: name.to_owned(),
            title: None,
            description: None,
            input_schema: json!({ "type": "object" }),
            output_schema: None,
            annotations: None,
            meta: Map::new(),
        }
    }

    async fn reconciliation_plan_with_list_changed(
        expected_source_revision: i64,
        name: &str,
        tools_list_changed: bool,
    ) -> DiscoveryPlan {
        let mut fetcher = ReconciliationFetcher {
            pages: VecDeque::from([ToolPage {
                tools: vec![reconciliation_tool(name)],
                next_cursor: None,
            }]),
            events: Arc::new(std::sync::Mutex::new(Vec::new())),
            session: "plan",
            generation: 1,
        };
        let mut basis = reconciliation_basis(expected_source_revision);
        basis.capabilities = json!({ "tools": { "listChanged": tools_list_changed } });
        basis.tools_list_changed = tools_list_changed;
        discover(&mut fetcher, basis)
            .await
            .expect("test discovery succeeds")
    }

    async fn reconciliation_plan(expected_source_revision: i64, name: &str) -> DiscoveryPlan {
        reconciliation_plan_with_list_changed(expected_source_revision, name, true).await
    }

    fn race_manager(kind: SourceKind) -> Arc<McpConnectionManager> {
        let templates = if kind == SourceKind::McpStdio {
            StdioTemplateRegistry::new(vec![crate::mcp::upstream::stdio::StdioTemplate {
                name: "race-fixture".to_owned(),
                executable: std::path::PathBuf::from("/bin/sh"),
                cwd: None,
                arguments: vec!["-c".to_owned(), "exit 1".to_owned()],
                environment: BTreeMap::new(),
                secret_environment: vec!["API_TOKEN".to_owned()],
            }])
            .expect("race stdio template validates")
        } else {
            StdioTemplateRegistry::default()
        };
        Arc::new(McpConnectionManager::new(templates))
    }

    async fn create_watcher_race_source(catalog: &CatalogStore, kind: SourceKind) -> SourceRecord {
        let mut plan = reconciliation_plan(0, "initial").await;
        let (configuration, credential) = match kind {
            SourceKind::McpHttp => (
                encode_configuration(&McpHttpSourceConfigurationV1 {
                    endpoint: "http://127.0.0.1:1/mcp".to_owned(),
                    allow_private_network: true,
                    negotiated_protocol_version: HTTP_PROTOCOL_VERSION.to_owned(),
                })
                .expect("HTTP configuration encodes"),
                StoredMcpHttpCredentialV1 {
                    endpoint: "http://127.0.0.1:1/mcp".to_owned(),
                    credential: Some(McpHttpCredential::Bearer {
                        token: "old-http-token".to_owned(),
                    }),
                }
                .payload()
                .expect("HTTP credential encodes"),
            ),
            SourceKind::McpStdio => {
                plan = bindings_for_stdio(plan);
                (
                    encode_configuration(&McpStdioSourceConfigurationV1 {
                        template_name: "race-fixture".to_owned(),
                        negotiated_protocol_version: Some(HTTP_PROTOCOL_VERSION.to_owned()),
                    })
                    .expect("stdio configuration encodes"),
                    StoredMcpStdioCredentialV1 {
                        template_name: "race-fixture".to_owned(),
                        secret_values: BTreeMap::from([(
                            "API_TOKEN".to_owned(),
                            "old-stdio-token".to_owned(),
                        )]),
                    }
                    .payload()
                    .expect("stdio credential encodes"),
                )
            }
            SourceKind::Openapi | SourceKind::Graphql => {
                unreachable!("watcher race fixtures require MCP")
            }
        };
        catalog
            .create_source_with_catalog(
                CreateSource {
                    kind,
                    preferred_slug: format!("{}-watcher-race", kind.as_str()),
                    display_name: "Watcher race".to_owned(),
                    description: None,
                    configuration,
                },
                &credential,
                plan.initial_catalog_snapshot(),
                plan.bindings,
                AuditContext::system(Some("watcher-race-create")),
            )
            .await
            .expect("watcher race source creates")
            .0
    }

    async fn install_old_race_watcher(
        manager: &McpConnectionManager,
        source: &SourceRecord,
    ) -> WatcherRevisionLease {
        let (lease_sender, lease_receiver) = tokio::sync::oneshot::channel();
        assert!(
            manager
                .replace_watcher(
                    source.id.clone(),
                    source.revision,
                    move |mut canceled, lease| async move {
                        lease_sender.send(lease).ok();
                        let _ = (&mut canceled).await;
                    },
                )
                .await
                .expect("old race watcher installs")
        );
        lease_receiver
            .await
            .expect("old race watcher exposes lease")
    }

    struct OldSecretWatcherSentinel {
        canceled: tokio::sync::Notify,
        release: tokio::sync::Notify,
        in_use: std::sync::atomic::AtomicBool,
    }

    async fn install_old_secret_watcher(
        manager: &McpConnectionManager,
        source: &SourceRecord,
    ) -> (WatcherRevisionLease, Arc<OldSecretWatcherSentinel>) {
        let sentinel = Arc::new(OldSecretWatcherSentinel {
            canceled: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            in_use: std::sync::atomic::AtomicBool::new(true),
        });
        let (lease_sender, lease_receiver) = tokio::sync::oneshot::channel();
        assert!(
            manager
                .replace_watcher(source.id.clone(), source.revision, {
                    let sentinel = sentinel.clone();
                    move |mut canceled, lease| async move {
                        lease_sender.send(lease).ok();
                        let _ = (&mut canceled).await;
                        sentinel.canceled.notify_one();
                        sentinel.release.notified().await;
                        sentinel
                            .in_use
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                    }
                })
                .await
                .expect("old-secret watcher installs")
        );
        let lease = lease_receiver
            .await
            .expect("old-secret watcher exposes lease");
        (lease, sentinel)
    }

    async fn commit_replacement_fixture(
        catalog: &CatalogStore,
        source: &SourceRecord,
    ) -> SourceRecord {
        let mut plan = reconciliation_plan(source.revision, "replacement").await;
        let credential = match source.kind {
            SourceKind::McpHttp => StoredMcpHttpCredentialV1 {
                endpoint: "http://127.0.0.1:1/mcp".to_owned(),
                credential: Some(McpHttpCredential::Bearer {
                    token: "new-http-token".to_owned(),
                }),
            }
            .payload()
            .expect("replacement HTTP credential encodes"),
            SourceKind::McpStdio => {
                plan = bindings_for_stdio(plan);
                StoredMcpStdioCredentialV1 {
                    template_name: "race-fixture".to_owned(),
                    secret_values: BTreeMap::from([(
                        "API_TOKEN".to_owned(),
                        "new-stdio-token".to_owned(),
                    )]),
                }
                .payload()
                .expect("replacement stdio credential encodes")
            }
            SourceKind::Openapi | SourceKind::Graphql => {
                unreachable!("watcher race fixtures require MCP")
            }
        };
        catalog
            .replace_credential_and_sync_catalog(
                &source.id,
                &credential,
                plan.catalog_snapshot(),
                plan.bindings,
                AuditContext::system(Some("watcher-race-replace")),
            )
            .await
            .expect("replacement commits")
            .2
    }

    async fn commit_mode_during_post_commit_pause(
        manager: &McpConnectionManager,
        catalog: &CatalogStore,
        source: &SourceRecord,
    ) -> SourceRecord {
        let lease = manager
            .lock_source_revisions([(source.id.clone(), source.revision)])
            .await
            .expect("post-commit catalog revision leases");
        let updated = catalog
            .set_source_mode(
                &source.id,
                Some(ToolMode::Ask),
                source.revision,
                AuditContext::system(Some("watcher-race-mode")),
            )
            .await
            .expect("post-commit mode mutation commits");
        assert!(lease.advance(&HashMap::from([(updated.id.clone(), updated.revision,)])));
        updated
    }

    #[test]
    fn strict_create_inputs_reject_unknown_fields_and_default_private_access_off() {
        let input: CreateMcpHttpSource = serde_json::from_value(json!({
            "displayName": "Example",
            "endpoint": "https://example.com/mcp"
        }))
        .expect("minimal HTTP input decodes");
        assert!(!input.allow_private_network);
        assert!(input.credential.is_none());

        assert!(
            serde_json::from_value::<CreateMcpHttpSource>(json!({
                "displayName": "Example",
                "endpoint": "https://example.com/mcp",
                "unexpected": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CreateMcpStdioSource>(json!({
                "displayName": "Example",
                "templateName": "fixture",
                "secretValues": {},
                "executable": "/bin/sh"
            }))
            .is_err()
        );
    }

    #[test]
    fn supported_http_protocol_versions_decode_for_discovery_and_persistence() {
        for protocol_version in [HTTP_PROTOCOL_VERSION, "2025-06-18"] {
            let basis = http_discovery_basis(
                json!({
                    "protocolVersion": protocol_version,
                    "capabilities": {},
                    "serverInfo": { "name": "fixture", "version": "1" }
                }),
                4,
                Some(7),
            )
            .expect("supported HTTP discovery metadata decodes");
            assert_eq!(basis.protocol_version, protocol_version);

            let configuration = json!({
                "endpoint": "https://example.com/mcp",
                "allowPrivateNetwork": false,
                "negotiatedProtocolVersion": protocol_version,
            })
            .as_object()
            .expect("configuration is an object")
            .clone();
            let decoded = McpHttpSourceConfigurationV1::decode(&configuration)
                .expect("supported persisted HTTP protocol version decodes");
            assert_eq!(decoded.negotiated_protocol_version, protocol_version);
        }
    }

    #[test]
    fn old_and_unknown_http_protocol_versions_fail_discovery_and_persistence() {
        for protocol_version in ["2025-03-26", "2099-01-01"] {
            let discovery_error = http_discovery_basis(
                json!({
                    "protocolVersion": protocol_version,
                    "capabilities": {},
                    "serverInfo": { "name": "fixture", "version": "1" }
                }),
                0,
                None,
            )
            .expect_err("unsupported HTTP discovery version is rejected");
            assert_eq!(discovery_error.code, "mcp_protocol_version_mismatch");
            assert_eq!(discovery_error.category, ProtocolErrorCategory::Upstream);

            let configuration = json!({
                "endpoint": "https://example.com/mcp",
                "allowPrivateNetwork": false,
                "negotiatedProtocolVersion": protocol_version,
            })
            .as_object()
            .expect("configuration is an object")
            .clone();
            let Err(configuration_error) = McpHttpSourceConfigurationV1::decode(&configuration)
            else {
                panic!("unsupported persisted HTTP protocol version is rejected");
            };
            assert_eq!(configuration_error.code, "invalid_source_configuration");
            assert_eq!(
                configuration_error.category,
                ProtocolErrorCategory::CorruptData
            );
        }
    }

    #[tokio::test]
    async fn plaintext_nonloopback_create_rejects_static_and_anonymous_without_a_request() {
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .expect("zero-request listener binds");
        let endpoint = format!(
            "http://0.0.0.0:{}/mcp",
            listener
                .local_addr()
                .expect("zero-request listener has an address")
                .port()
        );
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let adapter = McpAdapter::default();

        for allow_private_network in [false, true] {
            for credential in [
                None,
                Some(McpHttpCredential::Bearer {
                    token: "must-not-dispatch".to_owned(),
                }),
            ] {
                let error = adapter
                    .create_http_source(
                        app.catalog(),
                        CreateMcpHttpSource {
                            display_name: "Plaintext rejection".to_owned(),
                            preferred_slug: None,
                            description: None,
                            endpoint: endpoint.clone(),
                            allow_private_network,
                            credential,
                        },
                        AuditContext::system(Some("plaintext-create-rejection")),
                    )
                    .await
                    .expect_err("non-loopback plaintext create is rejected");
                assert_eq!(error.code, "invalid_mcp_endpoint");
            }
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(25), listener.accept())
                .await
                .is_err(),
            "rejected source creation must not reach the endpoint"
        );
        app.shutdown().await;
    }

    #[tokio::test]
    async fn plaintext_nonloopback_refresh_rejects_legacy_state_without_a_request() {
        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .expect("refresh zero-request listener binds");
        let endpoint = format!(
            "http://0.0.0.0:{}/mcp",
            listener
                .local_addr()
                .expect("refresh listener has an address")
                .port()
        );
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let (source, _) = app
            .catalog()
            .create_source_with_catalog(
                CreateSource {
                    kind: SourceKind::McpHttp,
                    preferred_slug: "legacy-plaintext-mcp".to_owned(),
                    display_name: "Legacy plaintext MCP".to_owned(),
                    description: None,
                    configuration: json!({
                        "endpoint": endpoint.clone(),
                        "allowPrivateNetwork": true,
                        "negotiatedProtocolVersion": HTTP_PROTOCOL_VERSION,
                    })
                    .as_object()
                    .expect("legacy configuration is an object")
                    .clone(),
                },
                &CredentialPayload {
                    schema_version: MCP_CREDENTIAL_SCHEMA_VERSION,
                    payload: json!({
                        "endpoint": endpoint,
                        "credential": {
                            "type": "bearer",
                            "token": "must-not-dispatch"
                        }
                    }),
                },
                InitialCatalogSnapshot {
                    artifacts: Vec::new(),
                    tools: Vec::new(),
                },
                Vec::new(),
                AuditContext::system(Some("legacy-plaintext-create")),
            )
            .await
            .expect("legacy source fixture is stored");
        let error = McpAdapter::default()
            .refresh_source(
                app.catalog(),
                source,
                AuditContext::system(Some("legacy-plaintext-refresh")),
            )
            .await
            .expect_err("legacy plaintext refresh is rejected");
        assert_eq!(error.code, "invalid_source_configuration");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), listener.accept())
                .await
                .is_err(),
            "rejected refresh must not reach the endpoint"
        );
        app.shutdown().await;
    }

    #[test]
    fn public_http_configuration_removes_query_secrets() {
        let endpoint = validate_endpoint("https://example.com/mcp?api_key=secret")
            .expect("endpoint validates");
        assert_eq!(display_endpoint(&endpoint), "https://example.com/mcp");
        let stored = StoredMcpHttpCredentialV1 {
            endpoint: endpoint.to_string(),
            credential: None,
        };
        assert!(stored.endpoint.contains("api_key=secret"));
    }

    #[test]
    fn plaintext_http_is_rejected_before_transport_except_for_loopback() {
        assert_eq!(
            http_configuration_error(StreamableHttpError::InsecureEndpoint).code,
            "invalid_mcp_endpoint"
        );
        assert_eq!(
            http_protocol_error(StreamableHttpError::InsecureEndpoint).code,
            "invalid_mcp_endpoint"
        );
        for endpoint in [
            "http://example.com/mcp",
            "http://10.0.0.5/mcp",
            "http://192.168.1.5/mcp",
            "http://169.254.1.2/mcp",
            "http://[fc00::1]/mcp",
        ] {
            assert_eq!(
                validate_endpoint(endpoint)
                    .expect_err("non-loopback plaintext endpoint is rejected")
                    .code,
                "invalid_mcp_endpoint"
            );
            for allow_private_network in [false, true] {
                for credential in [
                    None,
                    Some(McpHttpCredential::Bearer {
                        token: "must-not-dispatch".to_owned(),
                    }),
                ] {
                    let stored = StoredMcpHttpCredentialV1 {
                        endpoint: endpoint.to_owned(),
                        credential,
                    };
                    let error = match http_transport_config(&stored, allow_private_network) {
                        Ok(_) => panic!("plaintext transport must be rejected before construction"),
                        Err(error) => error,
                    };
                    assert_eq!(error.code, "invalid_mcp_endpoint");
                }
            }
        }

        for endpoint in [
            "http://localhost:3000/mcp",
            "http://worker.localhost:3000/mcp",
            "http://127.0.0.1:3000/mcp",
            "http://[::1]:3000/mcp",
            "https://example.com/mcp",
            "https://10.0.0.5/mcp",
        ] {
            let stored = StoredMcpHttpCredentialV1 {
                endpoint: endpoint.to_owned(),
                credential: Some(McpHttpCredential::Bearer {
                    token: "allowed-transport".to_owned(),
                }),
            };
            http_transport_config(&stored, true)
                .expect("HTTPS and loopback HTTP transport configurations remain valid");
        }
    }

    #[test]
    fn credentials_validate_and_metadata_never_contains_values() {
        let credential = McpHttpCredential::Bearer {
            token: "highly-secret".to_owned(),
        };
        credential.validate().expect("bearer validates");
        assert!(
            credential
                .headers()
                .expect("bearer headers encode")
                .get(AUTHORIZATION)
                .expect("authorization header exists")
                .is_sensitive()
        );
        let stored = StoredMcpHttpCredentialV1 {
            endpoint: "https://example.com/mcp".to_owned(),
            credential: Some(credential),
        };
        let metadata = http_credential_metadata(3, &stored);
        assert_eq!(metadata.revision, 3);
        assert_eq!(metadata.configured_schemes[0].credential_type, "bearer");
        assert!(!format!("{metadata:?}").contains("highly-secret"));

        let stdio = StoredMcpStdioCredentialV1 {
            template_name: "fixture".to_owned(),
            secret_values: BTreeMap::from([("API_TOKEN".to_owned(), "hidden".to_owned())]),
        };
        let metadata = stdio_credential_metadata(5, &stdio);
        assert_eq!(metadata.configured_schemes[0].name, "API_TOKEN");
        assert_eq!(metadata.configured_schemes[0].credential_type, "secret_env");
        assert!(!format!("{metadata:?}").contains("hidden"));
    }

    #[test]
    fn api_key_credentials_reject_protected_transport_headers() {
        for name in [
            "Authorization",
            "Host",
            "Content-Type",
            "Accept",
            "Content-Length",
            "Connection",
            "Transfer-Encoding",
            "Mcp-Session-Id",
            "Mcp-Protocol-Version",
            "Origin",
            "Referer",
            "Proxy-Authorization",
            "Proxy-Custom",
        ] {
            let credential = McpHttpCredential::ApiKeyHeader {
                name: name.to_owned(),
                value: "secret".to_owned(),
            };
            assert!(credential.validate().is_err(), "{name} must be protected");
        }
        McpHttpCredential::ApiKeyHeader {
            name: "X-Api-Key".to_owned(),
            value: "secret".to_owned(),
        }
        .validate()
        .expect("an ordinary API key header validates");
    }

    #[test]
    fn stdio_secret_completeness_allows_deferred_create_but_requires_exact_rotation() {
        let registry =
            StdioTemplateRegistry::new(vec![crate::mcp::upstream::stdio::StdioTemplate {
                name: "fixture".to_owned(),
                executable: std::path::PathBuf::from("/bin/sh"),
                cwd: None,
                arguments: Vec::new(),
                environment: BTreeMap::new(),
                secret_environment: vec!["API_TOKEN".to_owned()],
            }])
            .expect("fixture registry validates");
        assert!(
            !stdio_secrets_complete(&registry, "fixture", &BTreeMap::new())
                .expect("omitted secrets select deferred creation")
        );
        assert!(
            stdio_secrets_complete(
                &registry,
                "fixture",
                &BTreeMap::from([("API_TOKEN".to_owned(), " secret ".to_owned())]),
            )
            .expect("an exact secret overlay is complete")
        );
        assert!(
            stdio_secrets_complete(
                &registry,
                "fixture",
                &BTreeMap::from([("OTHER".to_owned(), "secret".to_owned())]),
            )
            .is_err()
        );

        let public_registry =
            StdioTemplateRegistry::new(vec![crate::mcp::upstream::stdio::StdioTemplate {
                name: "public-fixture".to_owned(),
                executable: std::path::PathBuf::from("/bin/sh"),
                cwd: None,
                arguments: Vec::new(),
                environment: BTreeMap::new(),
                secret_environment: Vec::new(),
            }])
            .expect("public fixture registry validates");
        assert!(
            stdio_secrets_complete(&public_registry, "public-fixture", &BTreeMap::new())
                .expect("an empty overlay is complete for a template without secrets")
        );
    }

    #[test]
    fn malformed_persisted_credentials_fail_closed() {
        let stored = StoredCredential {
            revision: 1,
            credential: CredentialPayload {
                schema_version: MCP_CREDENTIAL_SCHEMA_VERSION,
                payload: json!({
                    "endpoint": "file:///tmp/mcp",
                    "credential": null
                }),
            },
        };
        let Err(error) = StoredMcpHttpCredentialV1::decode(&stored) else {
            panic!("invalid stored endpoint must fail closed");
        };
        assert_eq!(error.code, "invalid_source_credentials");
        assert_eq!(error.category, ProtocolErrorCategory::CorruptData);
    }

    #[tokio::test]
    async fn anonymous_create_can_defer_discovery_for_an_oauth_protected_resource() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        for (status, reason) in [(401, "Unauthorized"), (403, "Forbidden")] {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("fixture listener binds");
            let address = listener.local_addr().expect("fixture address exists");
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("fixture accepts request");
                let mut request = vec![0_u8; 4096];
                let read = stream
                    .read(&mut request)
                    .await
                    .expect("fixture reads request");
                let request = String::from_utf8_lossy(&request[..read]);
                assert!(request.starts_with("POST /mcp HTTP/1.1"));
                assert!(!request.to_ascii_lowercase().contains("authorization:"));
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nWWW-Authenticate: Bearer resource_metadata=\"https://auth.example/.well-known/oauth-protected-resource\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("fixture writes response");
            });
            let source = McpAdapter::default()
                .create_http_source(
                    app.catalog(),
                    CreateMcpHttpSource {
                        display_name: format!("OAuth fixture {status}"),
                        preferred_slug: Some(format!("oauth_fixture_{status}")),
                        description: None,
                        endpoint: format!("http://{address}/mcp"),
                        allow_private_network: true,
                        credential: None,
                    },
                    AuditContext::system(Some("oauth-protected-create")),
                )
                .await
                .expect("OAuth-protected source creation is deferred");

            assert_eq!(source.health_status, SourceHealth::Error);
            assert_eq!(
                source.health_error_code.as_deref(),
                Some("authorization_required")
            );
            let tools = app
                .catalog()
                .list_tools(ListToolsFilter {
                    source_id: Some(source.id),
                    include_tombstoned: true,
                    limit: 100,
                    ..ListToolsFilter::default()
                })
                .await
                .expect("deferred source catalog remains readable");
            assert!(tools.items.is_empty());
            server.await.expect("fixture server joins");
        }
        app.shutdown().await;
    }

    #[tokio::test]
    async fn credentialless_create_defers_when_tools_list_is_forbidden() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture listener binds");
        let address = listener.local_addr().expect("fixture address exists");
        let server = tokio::spawn(async move {
            let initialize_body = json!({
                "jsonrpc": "2.0",
                "id": 0,
                "result": {
                    "protocolVersion": HTTP_PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "fixture", "version": "1" }
                }
            })
            .to_string();
            for step in 0..3 {
                let (mut stream, _) = listener.accept().await.expect("fixture accepts request");
                let mut request = vec![0_u8; 8192];
                let read = stream
                    .read(&mut request)
                    .await
                    .expect("fixture reads request");
                let request = String::from_utf8_lossy(&request[..read]);
                let response = match step {
                    0 => {
                        assert!(request.contains("\"method\":\"initialize\""));
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{initialize_body}",
                            initialize_body.len()
                        )
                    }
                    1 => {
                        assert!(request.contains("notifications/initialized"));
                        "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned()
                    }
                    _ => {
                        assert!(request.contains("\"method\":\"tools/list\""));
                        "HTTP/1.1 403 Forbidden\r\nWWW-Authenticate: Bearer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_owned()
                    }
                };
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("fixture writes response");
            }
        });

        let source = McpAdapter::default()
            .create_http_source(
                app.catalog(),
                CreateMcpHttpSource {
                    display_name: "Split auth fixture".to_owned(),
                    preferred_slug: Some("split_auth_fixture".to_owned()),
                    description: None,
                    endpoint: format!("http://{address}/mcp"),
                    allow_private_network: true,
                    credential: None,
                },
                AuditContext::system(Some("split-auth-create")),
            )
            .await
            .expect("tools/list denial defers source creation");

        assert_eq!(source.health_status, SourceHealth::Error);
        assert_eq!(
            source.health_error_code.as_deref(),
            Some("authorization_required")
        );
        server.await.expect("fixture server joins");
        app.shutdown().await;
    }

    #[tokio::test]
    async fn managed_oauth_is_resolved_just_in_time_and_static_credentials_take_precedence() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let master_key = [42_u8; 32];
        let master_key_file = directory.path().join("fixture-master.key");
        std::fs::write(&master_key_file, master_key).expect("fixture master key is written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(&master_key_file, std::fs::Permissions::from_mode(0o600))
                .expect("fixture master key permissions are restricted");
        }
        let app = ExecutorApp::open(
            AppConfig::new(directory.path().join("data"))
                .with_master_key_file(Some(master_key_file)),
        )
        .await
        .expect("test app opens");
        let stored = StoredMcpHttpCredentialV1 {
            endpoint: "https://mcp.example.test/rpc".to_owned(),
            credential: None,
        };
        let (source, _) = app
            .catalog()
            .create_source_with_catalog_health(
                CreateSource {
                    kind: SourceKind::McpHttp,
                    preferred_slug: "managed_oauth".to_owned(),
                    display_name: "Managed OAuth".to_owned(),
                    description: None,
                    configuration: json!({
                        "endpoint": "https://mcp.example.test/rpc",
                        "allowPrivateNetwork": false,
                        "negotiatedProtocolVersion": HTTP_PROTOCOL_VERSION,
                    })
                    .as_object()
                    .expect("configuration is an object")
                    .clone(),
                },
                &stored.payload().expect("credential encodes"),
                InitialCatalogSnapshot {
                    artifacts: Vec::new(),
                    tools: Vec::new(),
                },
                Vec::new(),
                SourceHealth::Unknown,
                AuditContext::system(Some("managed-oauth-source")),
            )
            .await
            .expect("fixture source is created");
        let keyring = Keyring::from_master_key(master_key).expect("fixture keyring derives");
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
                    scopes: vec!["tools:read".to_owned()],
                    allow_private_network: false,
                    resource: Some("https://mcp.example.test/rpc".to_owned()),
                },
                Some(&OAuthSecretSet {
                    access_token: Some("managed-secret-token".to_owned()),
                    granted_scopes: vec!["tools:read".to_owned()],
                    ..OAuthSecretSet::default()
                }),
                1,
            )
            .await
            .expect("managed OAuth connection is created");
        let oauth = OAuthService::new(
            app.pool().clone(),
            keyring,
            "http://127.0.0.1:4788".to_owned(),
            OutboundPolicy::default(),
        );

        let (managed, revision) =
            http_transport_config_for_source(Some(&oauth), &source.id, &stored, false)
                .await
                .expect("managed OAuth token resolves");
        assert_eq!(
            managed
                .headers
                .get(AUTHORIZATION)
                .expect("authorization header exists"),
            "Bearer managed-secret-token"
        );
        assert!(
            managed
                .headers
                .get(AUTHORIZATION)
                .expect("authorization header exists")
                .is_sensitive()
        );
        assert!(!format!("{:?}", managed.headers).contains("managed-secret-token"));
        assert_eq!(
            revision.expect("managed revision exists").secret_revision,
            1
        );
        let source_credential = app
            .catalog()
            .credential(&source.id)
            .await
            .expect("source credential remains readable")
            .expect("source credential exists");
        let source_payload = serde_json::to_string(&source_credential.credential.payload)
            .expect("source credential serializes");
        assert!(!source_payload.contains("managed-secret-token"));
        assert!(!source_payload.contains("access_token"));
        let mut stale_binding = oauth
            .binding(&source.id, "default")
            .await
            .expect("binding lookup succeeds")
            .expect("managed binding exists");
        stale_binding.config_revision += 1;
        let stale = match http_transport_config_for_binding(
            Some(&oauth),
            &source.id,
            &stored,
            false,
            Some(&stale_binding),
        )
        .await
        {
            Ok(_) => panic!("a stale approval binding must be rejected before transport setup"),
            Err(error) => error,
        };
        assert_eq!(stale.code, "oauth_binding_changed");
        let anonymous = match http_transport_config_for_observation(
            Some(&oauth),
            &source.id,
            &stored,
            false,
            &McpOAuthBindingObservation::Anonymous,
        )
        .await
        {
            Ok(_) => panic!("observed OAuth absence must be fenced at execution"),
            Err(error) => error,
        };
        assert_eq!(anonymous.code, "oauth_binding_changed");

        let zero_request_listener = TcpListener::bind("0.0.0.0:0")
            .await
            .expect("managed OAuth zero-request listener binds");
        let insecure_managed = StoredMcpHttpCredentialV1 {
            endpoint: format!(
                "http://0.0.0.0:{}/mcp",
                zero_request_listener
                    .local_addr()
                    .expect("managed OAuth listener has an address")
                    .port()
            ),
            credential: None,
        };
        for allow_private_network in [false, true] {
            let error = match http_transport_config_for_source(
                Some(&oauth),
                &source.id,
                &insecure_managed,
                allow_private_network,
            )
            .await
            {
                Ok(_) => panic!("managed OAuth must not configure plaintext public transport"),
                Err(error) => error,
            };
            assert_eq!(error.code, "invalid_mcp_endpoint");
        }
        let error = match http_transport_config_for_binding(
            Some(&oauth),
            &source.id,
            &insecure_managed,
            true,
            Some(&stale_binding),
        )
        .await
        {
            Ok(_) => panic!("plaintext rejection must precede managed OAuth resolution"),
            Err(error) => error,
        };
        assert_eq!(error.code, "invalid_mcp_endpoint");
        assert!(
            tokio::time::timeout(Duration::from_millis(25), zero_request_listener.accept())
                .await
                .is_err(),
            "managed OAuth rejection must not reach the plaintext endpoint"
        );

        let static_stored = StoredMcpHttpCredentialV1 {
            endpoint: stored.endpoint,
            credential: Some(McpHttpCredential::Bearer {
                token: "static-secret-token".to_owned(),
            }),
        };
        let (static_config, revision) =
            http_transport_config_for_source(Some(&oauth), &source.id, &static_stored, false)
                .await
                .expect("static credential resolves without managed OAuth");
        assert_eq!(
            static_config
                .headers
                .get(AUTHORIZATION)
                .expect("authorization header exists"),
            "Bearer static-secret-token"
        );
        assert!(revision.is_none());
        app.shutdown().await;
    }

    #[test]
    fn oauth_config_or_secret_rotation_requires_a_new_http_session() {
        let active = OAuthTransportRevision {
            binding: OAuthBinding {
                connection_id: "connection".to_owned(),
                credential_key: "default".to_owned(),
                config_revision: 4,
                granted_scopes: vec![],
            },
            secret_revision: 7,
        };
        let anonymous_stored = StoredMcpHttpCredentialV1 {
            endpoint: "https://mcp.example.test".to_owned(),
            credential: None,
        };
        assert!(matches!(
            catalog_oauth_expectation(&anonymous_stored, None),
            Some(OAuthBindingExpectation::Absent { credential_key })
                if credential_key == "default"
        ));
        assert!(matches!(
            catalog_oauth_expectation(&anonymous_stored, Some(&active)),
            Some(OAuthBindingExpectation::Exact {
                credential_key,
                connection_id,
                config_revision: 4,
            }) if credential_key == "default" && connection_id == "connection"
        ));
        assert!(
            catalog_oauth_expectation(
                &StoredMcpHttpCredentialV1 {
                    endpoint: anonymous_stored.endpoint.clone(),
                    credential: Some(McpHttpCredential::Bearer {
                        token: "static".to_owned(),
                    }),
                },
                Some(&active),
            )
            .is_none()
        );
        assert!(!oauth_transport_changed(Some(&active), Some(&active)));
        assert!(oauth_transport_changed(
            Some(&active),
            Some(&OAuthTransportRevision {
                binding: OAuthBinding {
                    config_revision: 5,
                    ..active.binding.clone()
                },
                secret_revision: active.secret_revision,
            })
        ));
        assert!(oauth_transport_changed(
            Some(&active),
            Some(&OAuthTransportRevision {
                binding: active.binding.clone(),
                secret_revision: 8,
            })
        ));
        assert!(oauth_transport_changed(None, Some(&active)));
    }

    #[test]
    fn preparation_is_network_free_and_preserves_secret_values() {
        let adapter = McpAdapter::default();
        let configuration = json!({
            "endpoint": "https://example.com/mcp",
            "allowPrivateNetwork": false,
            "negotiatedProtocolVersion": HTTP_PROTOCOL_VERSION
        })
        .as_object()
        .expect("configuration is an object")
        .clone();
        let stored = StoredCredential {
            revision: 1,
            credential: StoredMcpHttpCredentialV1 {
                endpoint: "https://example.com/mcp?secret=query".to_owned(),
                credential: Some(McpHttpCredential::Bearer {
                    token: "token".to_owned(),
                }),
            }
            .payload()
            .expect("credential encodes"),
        };
        let prepared = adapter
            .prepare_invocation(
                "source-id",
                SourceKind::McpHttp,
                &McpToolBindingV1 {
                    version: 1,
                    tool_name: "ping".to_owned(),
                },
                &configuration,
                Some(&stored),
                &json!({}),
                McpOAuthBindingObservation::Static,
            )
            .expect("preparation succeeds without transport I/O");
        let PreparedMcpInvocation::Http { credential, .. } = prepared else {
            panic!("HTTP invocation is prepared")
        };
        assert!(credential.endpoint.contains("secret=query"));
        assert!(credential.credential.is_some());

        let insecure_changed_endpoint = StoredCredential {
            revision: 2,
            credential: StoredMcpHttpCredentialV1 {
                endpoint: "http://example.com/mcp".to_owned(),
                credential: Some(McpHttpCredential::Bearer {
                    token: "must-not-dispatch".to_owned(),
                }),
            }
            .payload()
            .expect("changed credential encodes"),
        };
        let error = match adapter.prepare_invocation(
            "source-id",
            SourceKind::McpHttp,
            &McpToolBindingV1 {
                version: 1,
                tool_name: "ping".to_owned(),
            },
            &configuration,
            Some(&insecure_changed_endpoint),
            &json!({}),
            McpOAuthBindingObservation::Static,
        ) {
            Ok(_) => panic!("changed plaintext public endpoint must fail before invocation"),
            Err(error) => error,
        };
        assert_eq!(error.code, "invalid_source_credentials");
    }

    #[test]
    fn mcp_error_results_are_not_exposed_as_success_data() {
        let response = mcp_response(json!({
            "content": [{ "type": "text", "text": "failed" }],
            "isError": true
        }));
        assert!(!response.ok);
        assert!(response.data.is_none());
        assert_eq!(
            response.error.expect("error metadata exists").code,
            "upstream_tool_error"
        );
    }

    #[tokio::test]
    async fn discovery_change_signals_coalesce_and_require_a_quiet_period() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(2);
        sender.send(()).expect("first signal sends");
        sender.send(()).expect("second signal sends");
        sender.send(()).expect("lagging signal sends");
        assert!(catalog_changed_before_quiet(&mut receiver).await);
        assert!(!catalog_changed_before_quiet(&mut receiver).await);
    }

    #[tokio::test]
    async fn watcher_reconciliation_gate_finishes_full_discovery_before_steady_state() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));

        for session in ["startup", "reconnect"] {
            let reconcile_events = events.clone();
            let reconciled = reconcile_watcher_session(async move {
                for generation in 1..=2 {
                    let mut fetcher = ReconciliationFetcher {
                        pages: VecDeque::from([
                            ToolPage {
                                tools: vec![reconciliation_tool("one")],
                                next_cursor: Some("next".to_owned()),
                            },
                            ToolPage {
                                tools: vec![reconciliation_tool("two")],
                                next_cursor: None,
                            },
                        ]),
                        events: reconcile_events.clone(),
                        session,
                        generation,
                    };
                    discover(&mut fetcher, reconciliation_basis(1))
                        .await
                        .expect("full paginated discovery succeeds");
                }
                Ok::<(), Infallible>(())
            })
            .await
            .expect("reconciliation reaches the steady-state gate");
            let () = reconciled.into_inner();
            events
                .lock()
                .expect("event mutex is available")
                .push(format!("{session}:steady-state"));
        }

        assert_eq!(
            *events.lock().expect("event mutex is available"),
            [
                "startup:discover-1-page-1",
                "startup:discover-1-page-2",
                "startup:discover-2-page-1",
                "startup:discover-2-page-2",
                "startup:steady-state",
                "reconnect:discover-1-page-1",
                "reconnect:discover-1-page-2",
                "reconnect:discover-2-page-1",
                "reconnect:discover-2-page-2",
                "reconnect:steady-state",
            ]
        );
    }

    #[tokio::test]
    async fn immediate_http_405_is_observed_only_after_startup_reconciliation_commits() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener_events = events.clone();
        let mut listener = tokio::spawn(async move {
            listener_events
                .lock()
                .expect("event mutex is available")
                .push("listener-405".to_owned());
            Err(StreamableHttpError::HttpStatus(
                reqwest::StatusCode::METHOD_NOT_ALLOWED,
            ))
        });
        tokio::task::yield_now().await;
        assert!(listener.is_finished());

        let reconciliation_events = events.clone();
        let reconciled = reconcile_watcher_session(async move {
            let mut fetcher = ReconciliationFetcher {
                pages: VecDeque::from([ToolPage {
                    tools: vec![reconciliation_tool("startup")],
                    next_cursor: None,
                }]),
                events: reconciliation_events.clone(),
                session: "startup-405",
                generation: 1,
            };
            let plan = discover(&mut fetcher, reconciliation_basis(1))
                .await
                .expect("startup discovery succeeds");
            reconciliation_events
                .lock()
                .expect("event mutex is available")
                .push("catalog-commit".to_owned());
            Ok::<_, Infallible>(plan)
        })
        .await
        .expect("startup reconciliation completes");

        let listener_result =
            finished_http_listener_after_reconciliation(&reconciled, &mut listener)
                .await
                .expect("the completed listener is observed after reconciliation")
                .expect("listener task joins");
        assert!(matches!(
            listener_result,
            Err(StreamableHttpError::HttpStatus(status))
                if status == reqwest::StatusCode::METHOD_NOT_ALLOWED
        ));
        events
            .lock()
            .expect("event mutex is available")
            .push("405-honored".to_owned());

        assert_eq!(
            *events.lock().expect("event mutex is available"),
            [
                "listener-405",
                "startup-405:discover-1-page-1",
                "catalog-commit",
                "405-honored",
            ]
        );
    }

    #[tokio::test]
    async fn stale_catalog_cas_does_not_publish_a_watcher_plan() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let initial = reconciliation_plan(0, "initial").await;
        let (source, _) = app
            .catalog()
            .create_source_with_catalog(
                CreateSource {
                    kind: SourceKind::McpHttp,
                    preferred_slug: "watcher-cas".to_owned(),
                    display_name: "Watcher CAS".to_owned(),
                    description: None,
                    configuration: Map::new(),
                },
                &CredentialPayload {
                    schema_version: MCP_CREDENTIAL_SCHEMA_VERSION,
                    payload: json!({}),
                },
                initial.initial_catalog_snapshot(),
                initial.bindings,
                AuditContext::system(Some("watcher-cas-create")),
            )
            .await
            .expect("source is created");
        let manager = Arc::new(McpConnectionManager::new(StdioTemplateRegistry::default()));
        let (lease_sender, lease_receiver) = tokio::sync::oneshot::channel();
        assert!(
            manager
                .replace_watcher(
                    source.id.clone(),
                    source.revision,
                    move |mut canceled, lease| async move {
                        lease_sender.send(lease).ok();
                        let _ = (&mut canceled).await;
                    },
                )
                .await
                .expect("manager accepts watcher")
        );
        let lease = tokio::time::timeout(Duration::from_secs(2), lease_receiver)
            .await
            .expect("watcher delivers its lease promptly")
            .expect("watcher exposes its lease");
        let fresh = reconciliation_plan(source.revision, "fresh").await;
        let fresh_result = app
            .catalog()
            .sync_catalog_with_bindings(
                &source.id,
                fresh.catalog_snapshot(),
                fresh.bindings,
                AuditContext::system(Some("watcher-cas-fresh")),
            )
            .await
            .expect("concurrent catalog update commits");
        let stale = reconciliation_plan(source.revision, "stale").await;
        let error = commit_watcher_discovery(app.catalog(), &source.id, stale, None, &lease)
            .await
            .expect_err("stale watcher CAS is rejected");
        assert_eq!(error.code, "revision_conflict");
        assert_eq!(
            app.catalog()
                .source(&source.id)
                .await
                .expect("source remains readable")
                .revision,
            fresh_result.source_revision
        );
        let tools = app
            .catalog()
            .list_tools(ListToolsFilter {
                source_id: Some(source.id.clone()),
                include_tombstoned: true,
                limit: 100,
                ..ListToolsFilter::default()
            })
            .await
            .expect("catalog remains readable");
        assert!(tools.items.iter().any(|tool| tool.stable_key == "fresh"));
        assert!(!tools.items.iter().any(|tool| tool.stable_key == "stale"));

        manager.shutdown().await;
        app.shutdown().await;
    }

    #[tokio::test]
    async fn stale_watcher_generation_cannot_publish_at_the_current_catalog_revision() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let initial = reconciliation_plan(0, "initial").await;
        let (source, _) = app
            .catalog()
            .create_source_with_catalog(
                CreateSource {
                    kind: SourceKind::McpHttp,
                    preferred_slug: "watcher-generation".to_owned(),
                    display_name: "Watcher generation".to_owned(),
                    description: None,
                    configuration: Map::new(),
                },
                &CredentialPayload {
                    schema_version: MCP_CREDENTIAL_SCHEMA_VERSION,
                    payload: json!({}),
                },
                initial.initial_catalog_snapshot(),
                initial.bindings,
                AuditContext::system(Some("watcher-generation-create")),
            )
            .await
            .expect("source is created");
        let manager = Arc::new(McpConnectionManager::new(StdioTemplateRegistry::default()));
        let (stale_sender, stale_receiver) = tokio::sync::oneshot::channel();
        assert!(
            manager
                .replace_watcher(
                    source.id.clone(),
                    source.revision,
                    move |mut canceled, lease| async move {
                        stale_sender.send(lease).ok();
                        let _ = (&mut canceled).await;
                    },
                )
                .await
                .expect("first watcher installs")
        );
        let stale_lease = tokio::time::timeout(Duration::from_secs(2), stale_receiver)
            .await
            .expect("first watcher delivers its lease promptly")
            .expect("first watcher exposes its lease");
        assert!(
            manager
                .replace_watcher(
                    source.id.clone(),
                    source.revision,
                    move |mut canceled, _lease| async move {
                        let _ = (&mut canceled).await;
                    },
                )
                .await
                .expect("replacement watcher installs")
        );
        let stale_plan = reconciliation_plan(source.revision, "stale-generation").await;
        let error =
            commit_watcher_discovery(app.catalog(), &source.id, stale_plan, None, &stale_lease)
                .await
                .expect_err("replaced watcher cannot publish at the current revision");
        assert_eq!(error.code, "stale_watcher_reconciliation");
        assert_eq!(
            app.catalog()
                .source(&source.id)
                .await
                .expect("source remains readable")
                .revision,
            source.revision
        );
        let tools = app
            .catalog()
            .list_tools(ListToolsFilter {
                source_id: Some(source.id.clone()),
                include_tombstoned: true,
                limit: 100,
                ..ListToolsFilter::default()
            })
            .await
            .expect("catalog remains readable");
        assert!(tools.items.iter().any(|tool| tool.stable_key == "initial"));
        assert!(
            !tools
                .items
                .iter()
                .any(|tool| tool.stable_key == "stale-generation")
        );

        manager.shutdown().await;
        app.shutdown().await;
    }

    async fn credential_replacement_post_commit_race(kind: SourceKind) {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let manager = race_manager(kind);
        let source = create_watcher_race_source(app.catalog(), kind).await;
        let old_watcher = install_old_race_watcher(&manager, &source).await;
        let committed = commit_replacement_fixture(app.catalog(), &source).await;
        assert_eq!(committed.revision, source.revision + 1);

        let pause = Arc::new(PostCommitPause::default());
        let mut adapter = McpAdapter::with_connection_manager(manager.clone());
        adapter.post_commit_pause = Some(pause.clone());
        let committed_revision = committed.revision;
        let finishing = tokio::spawn({
            let adapter = adapter.clone();
            let catalog = app.catalog().clone();
            let source_id = source.id.clone();
            async move {
                adapter
                    .finish_source_watcher_reconciliation(&catalog, &source_id, committed_revision)
                    .await
                    .expect("replacement watcher reconciliation succeeds");
            }
        });
        pause.reached.notified().await;

        let current =
            commit_mode_during_post_commit_pause(&manager, app.catalog(), &committed).await;
        assert_eq!(current.revision, committed.revision + 1);
        assert_eq!(old_watcher.current_revision(), None);
        assert_eq!(manager.watcher_revision(&source.id), Some(source.revision));

        pause.release.notify_one();
        finishing.await.expect("post-commit reconciliation joins");
        assert_eq!(manager.watcher_revision(&source.id), Some(current.revision));
        assert_eq!(old_watcher.current_revision(), None);

        let stored = app
            .catalog()
            .credential(&source.id)
            .await
            .expect("replacement credential reads")
            .expect("replacement credential exists");
        match kind {
            SourceKind::McpHttp => {
                let stored = StoredMcpHttpCredentialV1::decode(&stored)
                    .expect("replacement HTTP credential decodes");
                assert!(matches!(
                    stored.credential,
                    Some(McpHttpCredential::Bearer { token }) if token == "new-http-token"
                ));
            }
            SourceKind::McpStdio => {
                let stored = StoredMcpStdioCredentialV1::decode(&stored)
                    .expect("replacement stdio credential decodes");
                assert_eq!(
                    stored.secret_values.get("API_TOKEN").map(String::as_str),
                    Some("new-stdio-token")
                );
            }
            SourceKind::Openapi | SourceKind::Graphql => unreachable!(),
        }
        manager.shutdown().await;
        app.shutdown().await;
    }

    async fn credential_reconciliation_load_failure_recovers_without_old_secret(
        kind: SourceKind,
        fail_capabilities: bool,
    ) {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let manager = race_manager(kind);
        let source = create_watcher_race_source(app.catalog(), kind).await;
        let (old_watcher, sentinel) = install_old_secret_watcher(&manager, &source).await;
        let committed = commit_replacement_fixture(app.catalog(), &source).await;
        let failures = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let install_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut adapter = McpAdapter::with_connection_manager(manager.clone());
        adapter.watcher_install_attempts = Some(install_attempts.clone());
        if fail_capabilities {
            adapter.watcher_capability_load_failures = Some(failures.clone());
        } else {
            adapter.watcher_credential_load_failures = Some(failures.clone());
        }
        let committed_revision = committed.revision;

        let finishing = tokio::spawn({
            let adapter = adapter.clone();
            let catalog = app.catalog().clone();
            let source_id = source.id.clone();
            async move {
                adapter
                    .finish_source_watcher_reconciliation(&catalog, &source_id, committed_revision)
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(2), sentinel.canceled.notified())
            .await
            .expect("old-secret watcher is canceled promptly");
        assert!(sentinel.in_use.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!finishing.is_finished());
        sentinel.release.notify_one();

        finishing
            .await
            .expect("credential reconciliation task joins")
            .expect("transient watcher load failure recovers");
        assert!(!sentinel.in_use.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(old_watcher.current_revision(), None);
        assert_eq!(failures.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            install_attempts.load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        assert_eq!(
            manager.watcher_revision(&source.id),
            Some(committed_revision)
        );

        manager.shutdown().await;
        app.shutdown().await;
    }

    #[tokio::test]
    async fn http_credential_reconciliation_fails_closed_then_recovers_capability_load() {
        credential_reconciliation_load_failure_recovers_without_old_secret(
            SourceKind::McpHttp,
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn stdio_credential_reconciliation_fails_closed_then_recovers_credential_load() {
        credential_reconciliation_load_failure_recovers_without_old_secret(
            SourceKind::McpStdio,
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn persistent_post_commit_load_failure_returns_error_without_old_secret_watcher() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let manager = race_manager(SourceKind::McpHttp);
        let source = create_watcher_race_source(app.catalog(), SourceKind::McpHttp).await;
        let (_old_watcher, sentinel) = install_old_secret_watcher(&manager, &source).await;
        let committed = commit_replacement_fixture(app.catalog(), &source).await;
        let mut adapter = McpAdapter::with_connection_manager(manager.clone());
        adapter.watcher_capability_load_failures = Some(Arc::new(
            std::sync::atomic::AtomicUsize::new(WATCHER_RECONCILIATION_ATTEMPTS),
        ));

        let finishing = tokio::spawn({
            let adapter = adapter.clone();
            let catalog = app.catalog().clone();
            let source_id = source.id.clone();
            async move {
                adapter
                    .finish_source_watcher_reconciliation(&catalog, &source_id, committed.revision)
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(2), sentinel.canceled.notified())
            .await
            .expect("old-secret watcher is canceled promptly");
        assert!(!finishing.is_finished());
        sentinel.release.notify_one();

        let error = finishing
            .await
            .expect("credential reconciliation task joins")
            .expect_err("persistent watcher load failure is reported");
        assert_eq!(error.code, "internal_error");
        assert!(!sentinel.in_use.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!manager.has_watcher(&source.id));

        manager.shutdown().await;
        app.shutdown().await;
    }

    async fn source_creation_finish_preserves_or_recovers_watcher(kind: SourceKind) {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let manager = race_manager(kind);
        let source = create_watcher_race_source(app.catalog(), kind).await;
        let watcher_canceled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let canceled_flag = watcher_canceled.clone();
        assert!(
            manager
                .replace_watcher(
                    source.id.clone(),
                    source.revision,
                    move |mut canceled, _lease| async move {
                        let _ = (&mut canceled).await;
                        canceled_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    },
                )
                .await
                .expect("ready source watcher installs")
        );

        let install_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut adapter = McpAdapter::with_connection_manager(manager.clone());
        adapter.watcher_install_attempts = Some(install_attempts.clone());
        adapter
            .ensure_source_creation_watcher(app.catalog(), &source.id)
            .await;
        assert_eq!(
            install_attempts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "finishing a ready create must preserve its current watcher"
        );
        assert!(!watcher_canceled.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(manager.watcher_revision(&source.id), Some(source.revision));

        assert!(
            manager
                .stop_watcher_and_wait_at_revision(&source.id, source.revision)
                .await
        );
        assert!(watcher_canceled.load(std::sync::atomic::Ordering::SeqCst));
        adapter
            .ensure_source_creation_watcher(app.catalog(), &source.id)
            .await;
        assert_eq!(
            install_attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "recovery must make exactly one watcher installation attempt"
        );

        manager.shutdown().await;
        app.shutdown().await;
    }

    #[tokio::test]
    async fn http_source_creation_finish_preserves_ready_watcher_and_recovers_missing() {
        source_creation_finish_preserves_or_recovers_watcher(SourceKind::McpHttp).await;
    }

    #[tokio::test]
    async fn stdio_source_creation_finish_preserves_ready_watcher_and_recovers_missing() {
        source_creation_finish_preserves_or_recovers_watcher(SourceKind::McpStdio).await;
    }

    #[tokio::test]
    async fn http_credential_replacement_reloads_after_a_paused_post_commit_mode_race() {
        credential_replacement_post_commit_race(SourceKind::McpHttp).await;
    }

    #[tokio::test]
    async fn stdio_credential_replacement_reloads_after_a_paused_post_commit_mode_race() {
        credential_replacement_post_commit_race(SourceKind::McpStdio).await;
    }

    #[tokio::test]
    async fn http_clear_fallback_stops_a_stale_old_credential_watcher_after_commit() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let manager = race_manager(SourceKind::McpHttp);
        let source = create_watcher_race_source(app.catalog(), SourceKind::McpHttp).await;
        let old_watcher = install_old_race_watcher(&manager, &source).await;
        let expected_credential_revision = app
            .catalog()
            .credential(&source.id)
            .await
            .expect("HTTP credential reads")
            .expect("HTTP credential exists")
            .revision;

        let pause = Arc::new(PostCommitPause::default());
        let mut adapter = McpAdapter::with_connection_manager(manager.clone());
        adapter.post_commit_pause = Some(pause.clone());
        let clearing = tokio::spawn({
            let adapter = adapter.clone();
            let catalog = app.catalog().clone();
            let source_id = source.id.clone();
            async move {
                adapter
                    .replace_http_credentials(
                        &catalog,
                        &source_id,
                        expected_credential_revision,
                        ReplaceMcpHttpCredential { credential: None },
                        AuditContext::system(Some("watcher-race-http-clear")),
                    )
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), pause.reached.notified())
            .await
            .expect("HTTP clear reaches its post-commit fence");

        assert_eq!(old_watcher.current_revision(), None);
        assert!(!manager.has_watcher(&source.id));
        let stale_watcher = install_old_race_watcher(&manager, &source).await;
        assert_eq!(stale_watcher.current_revision(), Some(source.revision));

        pause.release.notify_one();
        let metadata = tokio::time::timeout(Duration::from_secs(5), clearing)
            .await
            .expect("HTTP clear finishes promptly")
            .expect("HTTP clear task joins")
            .expect("HTTP clear commits");
        assert!(metadata.configured_schemes.is_empty());
        assert!(!manager.has_watcher(&source.id));
        assert_eq!(stale_watcher.current_revision(), None);
        let current = app
            .catalog()
            .source(&source.id)
            .await
            .expect("cleared HTTP source reads");
        assert_eq!(current.health_status, SourceHealth::Unknown);
        assert!(current.revision > source.revision);
        let stored = app
            .catalog()
            .credential(&source.id)
            .await
            .expect("cleared HTTP credential reads")
            .expect("cleared HTTP credential exists");
        assert!(
            StoredMcpHttpCredentialV1::decode(&stored)
                .expect("cleared HTTP credential decodes")
                .credential
                .is_none()
        );

        manager.shutdown().await;
        app.shutdown().await;
    }

    #[tokio::test]
    async fn clearing_required_stdio_secrets_keeps_the_committed_revision_without_a_watcher() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let manager = race_manager(SourceKind::McpStdio);
        let source = create_watcher_race_source(app.catalog(), SourceKind::McpStdio).await;
        let old_watcher = install_old_race_watcher(&manager, &source).await;
        let expected_credential_revision = app
            .catalog()
            .credential(&source.id)
            .await
            .expect("stdio credential reads")
            .expect("stdio credential exists")
            .revision;
        let adapter = McpAdapter::with_connection_manager(manager.clone());

        let metadata = adapter
            .clear_credentials(
                app.catalog(),
                &source,
                expected_credential_revision,
                AuditContext::system(Some("watcher-race-stdio-clear")),
            )
            .await
            .expect("stdio credential clear commits");
        assert!(metadata.configured_schemes.is_empty());
        assert!(!manager.has_watcher(&source.id));
        assert_eq!(old_watcher.current_revision(), None);

        let current = app
            .catalog()
            .source(&source.id)
            .await
            .expect("cleared stdio source reads");
        assert_eq!(current.health_status, SourceHealth::Unknown);
        assert!(current.revision > source.revision);
        let stored = app
            .catalog()
            .credential(&source.id)
            .await
            .expect("cleared stdio credential reads")
            .expect("cleared stdio credential exists");
        assert!(
            StoredMcpStdioCredentialV1::decode(&stored)
                .expect("cleared stdio credential decodes")
                .secret_values
                .is_empty()
        );

        adapter
            .reconcile_source_watcher(app.catalog(), &source.id, current.revision)
            .await
            .expect("cleared stdio watcher remains absent");
        assert!(!manager.has_watcher(&source.id));

        manager.shutdown().await;
        app.shutdown().await;
    }

    #[tokio::test]
    async fn manual_refresh_capability_removal_stops_stale_watcher_after_post_commit_mode_race() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let manager = race_manager(SourceKind::McpHttp);
        let source = create_watcher_race_source(app.catalog(), SourceKind::McpHttp).await;
        let (old_watcher, sentinel) = install_old_secret_watcher(&manager, &source).await;

        let removed =
            reconciliation_plan_with_list_changed(source.revision, "refreshed", false).await;
        let sync = app
            .catalog()
            .sync_catalog_with_bindings(
                &source.id,
                removed.catalog_snapshot(),
                removed.bindings,
                AuditContext::system(Some("watcher-race-refresh")),
            )
            .await
            .expect("capability removal refresh commits");
        let committed = app
            .catalog()
            .source(&source.id)
            .await
            .expect("refreshed source reads");
        assert_eq!(committed.revision, sync.source_revision);

        let pause = Arc::new(PostCommitPause::default());
        let mut adapter = McpAdapter::with_connection_manager(manager.clone());
        adapter.post_commit_pause = Some(pause.clone());
        let committed_revision = committed.revision;
        let finishing = tokio::spawn({
            let adapter = adapter.clone();
            let catalog = app.catalog().clone();
            let source_id = source.id.clone();
            async move {
                adapter
                    .finish_source_watcher_reconciliation(&catalog, &source_id, committed_revision)
                    .await
                    .expect("capability removal watcher reconciliation succeeds");
            }
        });
        pause.reached.notified().await;

        let current =
            commit_mode_during_post_commit_pause(&manager, app.catalog(), &committed).await;
        assert_eq!(old_watcher.current_revision(), None);
        assert_eq!(manager.watcher_revision(&source.id), Some(source.revision));

        pause.release.notify_one();
        tokio::time::timeout(Duration::from_secs(2), sentinel.canceled.notified())
            .await
            .expect("capability removal cancels the old-secret watcher promptly");
        assert!(sentinel.in_use.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!finishing.is_finished());
        sentinel.release.notify_one();
        finishing.await.expect("post-commit reconciliation joins");
        assert!(!sentinel.in_use.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!manager.has_watcher(&source.id));
        assert_eq!(old_watcher.current_revision(), None);
        assert_eq!(
            app.catalog()
                .source(&source.id)
                .await
                .expect("current source reads")
                .revision,
            current.revision
        );
        manager.shutdown().await;
        app.shutdown().await;
    }

    #[tokio::test]
    async fn watcher_lease_advancement_fences_a_stale_generation() {
        let manager = Arc::new(McpConnectionManager::new(StdioTemplateRegistry::default()));
        let (first_sender, first_receiver) = tokio::sync::oneshot::channel();
        assert!(
            manager
                .replace_watcher(
                    "source".to_owned(),
                    7,
                    move |mut canceled, lease| async move {
                        first_sender.send(lease).ok();
                        let _ = (&mut canceled).await;
                    }
                )
                .await
                .expect("first watcher installs")
        );
        let stale = tokio::time::timeout(Duration::from_secs(2), first_receiver)
            .await
            .expect("first watcher delivers its lease promptly")
            .expect("first lease is available");
        let (current_sender, current_receiver) = tokio::sync::oneshot::channel();
        assert!(
            manager
                .replace_watcher(
                    "source".to_owned(),
                    7,
                    move |mut canceled, lease| async move {
                        current_sender.send(lease).ok();
                        let _ = (&mut canceled).await;
                    }
                )
                .await
                .expect("replacement watcher installs")
        );
        let current = tokio::time::timeout(Duration::from_secs(2), current_receiver)
            .await
            .expect("replacement watcher delivers its lease promptly")
            .expect("replacement lease is available");

        assert!(stale.lock_revision(7).await.is_none());
        let current_guard = current
            .lock_revision(7)
            .await
            .expect("current watcher locks its revision");
        assert!(current_guard.advance(8));
        assert!(stale.lock_revision(8).await.is_none());
        assert!(manager.stop_watcher_and_wait_at_revision("source", 8).await);
        manager.shutdown().await;
    }

    #[tokio::test]
    async fn watcher_authorization_failure_updates_health_and_revision_fence() {
        let directory = tempfile::tempdir().expect("temporary data directory exists");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test app opens");
        let (source, _) = app
            .catalog()
            .create_source_with_catalog_health(
                CreateSource {
                    kind: SourceKind::McpHttp,
                    preferred_slug: "watcher_oauth_health".to_owned(),
                    display_name: "Watcher OAuth health".to_owned(),
                    description: None,
                    configuration: Map::new(),
                },
                &CredentialPayload {
                    schema_version: MCP_CREDENTIAL_SCHEMA_VERSION,
                    payload: json!({}),
                },
                InitialCatalogSnapshot {
                    artifacts: Vec::new(),
                    tools: Vec::new(),
                },
                Vec::new(),
                SourceHealth::Unknown,
                AuditContext::system(Some("watcher-oauth-health-create")),
            )
            .await
            .expect("fixture source is created");
        let manager = Arc::new(McpConnectionManager::new(StdioTemplateRegistry::default()));
        let (lease_sender, lease_receiver) = tokio::sync::oneshot::channel();
        manager
            .replace_watcher(
                source.id.clone(),
                source.revision,
                move |mut canceled, lease| async move {
                    lease_sender.send(lease).ok();
                    let _ = (&mut canceled).await;
                },
            )
            .await
            .expect("watcher installs");
        let lease = lease_receiver.await.expect("watcher lease is available");
        for status in [
            reqwest::StatusCode::UNAUTHORIZED,
            reqwest::StatusCode::FORBIDDEN,
        ] {
            assert_eq!(
                http_protocol_error_for_authorization(
                    StreamableHttpError::HttpStatus(status),
                    true,
                )
                .code,
                "authorization_required"
            );
            assert_eq!(
                http_protocol_error_for_authorization(
                    StreamableHttpError::HttpStatus(status),
                    false,
                )
                .code,
                "mcp_transport_error"
            );
        }
        assert_eq!(
            discovery_protocol_error(DiscoveryError::Fetch(Box::new(
                McpPageFetchError::AuthorizationRequired,
            )))
            .code,
            "authorization_required"
        );

        mark_watcher_authorization_required(app.catalog(), &source.id, &lease).await;

        let current = app
            .catalog()
            .source(&source.id)
            .await
            .expect("source remains readable");
        assert_eq!(current.health_status, SourceHealth::Error);
        assert_eq!(
            current.health_error_code.as_deref(),
            Some("authorization_required")
        );
        assert_eq!(lease.current_revision(), Some(current.revision));
        assert!(lease.lock_revision(current.revision).await.is_some());
        manager.shutdown().await;
        app.shutdown().await;
    }

    #[tokio::test]
    async fn buffered_list_changed_notifications_use_one_refresh_runner() {
        let (sender, mut receiver) = tokio::sync::broadcast::channel(4);
        let coalescer = ListChangedCoalescer::default();
        sender.send(()).expect("notification is buffered");
        drain_change_signals(&mut receiver, &coalescer);
        assert!(coalescer.has_pending());

        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let maximum_in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let runner = {
            let coalescer = coalescer.clone();
            let started = started.clone();
            let release = release.clone();
            let calls = calls.clone();
            let in_flight = in_flight.clone();
            let maximum_in_flight = maximum_in_flight.clone();
            tokio::spawn(async move {
                coalescer
                    .refresh_pending(|| {
                        let started = started.clone();
                        let release = release.clone();
                        let calls = calls.clone();
                        let in_flight = in_flight.clone();
                        let maximum_in_flight = maximum_in_flight.clone();
                        async move {
                            let active =
                                in_flight.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                            maximum_in_flight
                                .fetch_max(active, std::sync::atomic::Ordering::SeqCst);
                            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                            if call == 1 {
                                started.notify_one();
                                release.notified().await;
                            }
                            in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                            Ok::<(), Infallible>(())
                        }
                    })
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .expect("refresh runner starts promptly");
        sender.send(()).expect("second notification is buffered");
        drain_change_signals(&mut receiver, &coalescer);
        assert_eq!(
            coalescer
                .refresh_pending(|| async { Ok::<(), Infallible>(()) })
                .await
                .expect("competing runner exits cleanly"),
            0
        );
        release.notify_one();

        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), runner)
                .await
                .expect("refresh runner completes promptly")
                .expect("refresh task joins")
                .expect("refreshes succeed"),
            2
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            maximum_in_flight.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(!coalescer.has_pending());
    }

    #[tokio::test]
    async fn http_listener_disconnect_interrupts_refresh_discovery_and_retry_backoff() {
        let (_cancel, mut canceled) = tokio::sync::oneshot::channel();
        let refresh_started = Arc::new(tokio::sync::Notify::new());
        let mut listener = {
            let refresh_started = refresh_started.clone();
            tokio::spawn(async move {
                refresh_started.notified().await;
                Err::<(), _>(StreamableHttpError::InvalidResponse)
            })
        };
        let refresh = async {
            refresh_started.notify_one();
            std::future::pending::<Result<(), ProtocolError>>().await
        };
        tokio::pin!(refresh);

        match tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_watcher_refresh(&mut canceled, &mut listener, &mut refresh),
        )
        .await
        .expect("HTTP listener disconnect wins promptly")
        {
            WatcherRefreshWait::Disconnected(Ok(Err(StreamableHttpError::InvalidResponse))) => {}
            _ => panic!("HTTP refresh discovery must yield to listener disconnect"),
        }

        let mut listener =
            tokio::spawn(async { Err::<(), _>(StreamableHttpError::InvalidResponse) });
        match tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_watcher_refresh(
                &mut canceled,
                &mut listener,
                tokio::time::sleep(Duration::from_secs(60)),
            ),
        )
        .await
        .expect("HTTP listener disconnect interrupts backoff promptly")
        {
            WatcherRefreshWait::Disconnected(Ok(Err(StreamableHttpError::InvalidResponse))) => {}
            _ => panic!("HTTP retry backoff must yield to listener disconnect"),
        }
    }

    #[tokio::test]
    async fn stdio_lifecycle_disconnect_interrupts_refresh_discovery_and_retry_backoff() {
        let (_cancel, mut canceled) = tokio::sync::oneshot::channel();
        let lifecycle = StdioLifecycleMonitor::initialized_fixture();
        let client_lock = tokio::sync::Mutex::new(());
        let client_guard = client_lock.lock().await;
        let refresh_started = Arc::new(tokio::sync::Notify::new());
        let disconnect = tokio::spawn({
            let refresh_started = refresh_started.clone();
            let lifecycle = lifecycle.clone();
            async move {
                refresh_started.notified().await;
                lifecycle.disconnect_fixture();
            }
        });
        let refresh = async {
            refresh_started.notify_one();
            std::future::pending::<Result<(), ProtocolError>>().await
        };

        match tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_watcher_refresh(
                &mut canceled,
                wait_for_stdio_disconnect(&lifecycle),
                refresh,
            ),
        )
        .await
        .expect("stdio disconnect wins promptly")
        {
            WatcherRefreshWait::Disconnected(()) => {}
            _ => panic!("stdio refresh discovery must yield to lifecycle disconnect"),
        }
        disconnect.await.expect("disconnect fixture task joins");
        assert!(client_lock.try_lock().is_err());
        drop(client_guard);

        let lifecycle = StdioLifecycleMonitor::initialized_fixture();
        lifecycle.disconnect_fixture();
        match tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_watcher_refresh(
                &mut canceled,
                wait_for_stdio_disconnect(&lifecycle),
                tokio::time::sleep(Duration::from_secs(60)),
            ),
        )
        .await
        .expect("stdio disconnect interrupts backoff promptly")
        {
            WatcherRefreshWait::Disconnected(()) => {}
            _ => panic!("stdio retry backoff must yield to lifecycle disconnect"),
        }
    }

    #[test]
    fn every_http_call_transport_failure_is_outcome_unknown() {
        let error = McpInvocationError::HttpCall(StreamableHttpError::InvalidResponse);
        assert!(error.outcome_unknown());
        let setup = McpInvocationError::HttpSetup(StreamableHttpError::InvalidResponse);
        assert!(!setup.outcome_unknown());

        let stdio_call = McpInvocationError::StdioCall(StdioTransportError::Decode);
        assert!(stdio_call.outcome_unknown());
        let stdio_setup = McpInvocationError::StdioSetup(StdioTransportError::Decode);
        assert!(!stdio_setup.outcome_unknown());
    }
}
