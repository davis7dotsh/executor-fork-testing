pub mod graphql;
pub mod mcp;
pub mod openapi;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::Arc,
};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    catalog::{
        AuditContext, BulkToolModeResult, CatalogError, CatalogStore, CatalogSyncResult,
        InvocationLease, SourceKind, SourceRecord, ToolMode, ToolRecord,
    },
    mcp::manager::SourceRevisionLease,
    oauth::OAuthBinding,
    outbound::OutboundError,
};

pub use openapi::{OpenApiPreview, OpenApiSpecInput};

#[derive(Clone, Debug)]
pub struct ProtocolExecutionResponse {
    pub ok: bool,
    pub data: Option<Value>,
    pub error: Option<ProtocolResponseError>,
    pub http: Option<ProtocolHttpMetadata>,
}

#[derive(Clone, Debug)]
pub struct ProtocolResponseError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct ProtocolHttpMetadata {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub truncated: bool,
}

#[must_use = "a prepared protocol invocation must be executed or explicitly discarded"]
pub struct PreparedProtocolInvocation {
    lease: InvocationLease,
    execution: PreparedProtocolExecution,
}

enum PreparedProtocolExecution {
    OpenApi(openapi::PreparedOpenApiInvocation),
    Graphql(graphql::PreparedGraphqlInvocation),
    Mcp(mcp::PreparedMcpInvocation),
}

#[derive(Debug)]
pub enum ProtocolInvocationError {
    OpenApi(openapi::OpenApiExecutionError),
    Graphql(graphql::GraphqlInvocationError),
    Mcp(mcp::McpInvocationError),
}

impl fmt::Display for ProtocolInvocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenApi(error) => error.fmt(formatter),
            Self::Graphql(error) => error.fmt(formatter),
            Self::Mcp(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ProtocolInvocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenApi(error) => Some(error),
            Self::Graphql(error) => Some(error),
            Self::Mcp(error) => Some(error),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMetadata {
    pub revision: i64,
    pub configured_schemes: Vec<ConfiguredCredential>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfiguredCredential {
    pub name: String,
    pub credential_type: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AvailableOAuthCredential {
    pub credential_key: String,
    pub protocol: &'static str,
    pub requested_scopes: Vec<String>,
    #[serde(rename = "managedOAuthEligible")]
    pub managed_oauth_eligible: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolErrorCategory {
    InvalidInput,
    NotFound,
    Conflict,
    CorruptData,
    Unsupported,
    Upstream,
    Internal,
}

#[derive(Debug)]
pub struct ProtocolError {
    pub code: &'static str,
    pub message: String,
    pub category: ProtocolErrorCategory,
}

impl ProtocolError {
    pub(crate) fn new(
        category: ProtocolErrorCategory,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            category,
        }
    }

    pub(crate) fn corrupt(code: &'static str, message: &'static str) -> Self {
        Self::new(ProtocolErrorCategory::CorruptData, code, message)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolRegistration {
    OpenApi,
    Graphql,
    McpHttp,
    McpStdio,
}

#[derive(Clone)]
pub struct ProtocolRegistry {
    openapi: openapi::OpenApiAdapter,
    graphql: graphql::GraphqlAdapter,
    mcp: mcp::McpAdapter,
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self {
            openapi: openapi::OpenApiAdapter::default(),
            graphql: graphql::GraphqlAdapter::default(),
            mcp: mcp::McpAdapter::with_connection_manager(Arc::new(
                crate::mcp::manager::McpConnectionManager::new(
                    crate::mcp::upstream::stdio::StdioTemplateRegistry::default(),
                ),
            )),
        }
    }
}

impl ProtocolRegistry {
    pub(crate) fn new(
        connections: Arc<crate::mcp::manager::McpConnectionManager>,
        oauth: crate::oauth::OAuthService,
    ) -> Self {
        Self {
            openapi: openapi::OpenApiAdapter::with_oauth(oauth.clone()),
            graphql: graphql::GraphqlAdapter::with_oauth(oauth.clone()),
            mcp: mcp::McpAdapter::with_services(connections, oauth),
        }
    }

    pub fn registration(&self, kind: SourceKind) -> ProtocolRegistration {
        match kind {
            SourceKind::Openapi => ProtocolRegistration::OpenApi,
            SourceKind::Graphql => ProtocolRegistration::Graphql,
            SourceKind::McpHttp => ProtocolRegistration::McpHttp,
            SourceKind::McpStdio => ProtocolRegistration::McpStdio,
        }
    }

    fn require_supported(&self, kind: SourceKind) -> Result<(), ProtocolError> {
        match self.registration(kind) {
            ProtocolRegistration::OpenApi
            | ProtocolRegistration::Graphql
            | ProtocolRegistration::McpHttp
            | ProtocolRegistration::McpStdio => Ok(()),
        }
    }

    pub async fn prepare_invocation(
        &self,
        lease: InvocationLease,
        arguments: &Value,
        expected_oauth_bindings: Option<&[OAuthBinding]>,
    ) -> Result<PreparedProtocolInvocation, ProtocolError> {
        self.require_supported(lease.source_kind())?;
        let source_id = lease.lookup().source_id.clone();
        let execution = match lease.source_kind() {
            SourceKind::Openapi => {
                let binding = lease.binding().openapi().ok_or_else(|| {
                    ProtocolError::corrupt(
                        "source_binding_mismatch",
                        "The stored tool binding does not match its source protocol.",
                    )
                })?;
                PreparedProtocolExecution::OpenApi(
                    self.openapi
                        .prepare_invocation(
                            &source_id,
                            binding,
                            lease.source_configuration(),
                            lease.credential(),
                            arguments,
                            expected_oauth_bindings,
                        )
                        .await?,
                )
            }
            SourceKind::McpHttp | SourceKind::McpStdio => {
                let binding = match (lease.source_kind(), lease.binding()) {
                    (SourceKind::McpHttp, crate::catalog::ToolBinding::McpHttpV1(binding))
                    | (SourceKind::McpStdio, crate::catalog::ToolBinding::McpStdioV1(binding)) => {
                        binding
                    }
                    _ => {
                        return Err(ProtocolError::corrupt(
                            "source_binding_mismatch",
                            "The stored tool binding does not match its source protocol.",
                        ));
                    }
                };
                let oauth_binding = self
                    .mcp
                    .oauth_binding_observation(
                        &source_id,
                        lease.source_kind(),
                        lease.credential(),
                        expected_oauth_bindings,
                    )
                    .await?;
                PreparedProtocolExecution::Mcp(self.mcp.prepare_invocation(
                    &source_id,
                    lease.source_kind(),
                    binding,
                    lease.source_configuration(),
                    lease.credential(),
                    arguments,
                    oauth_binding,
                )?)
            }
            SourceKind::Graphql => {
                let binding = lease.binding().graphql().ok_or_else(|| {
                    ProtocolError::corrupt(
                        "source_binding_mismatch",
                        "The stored tool binding does not match its source protocol.",
                    )
                })?;
                let oauth_binding = self
                    .graphql
                    .oauth_binding_observation(
                        &source_id,
                        lease.credential(),
                        expected_oauth_bindings,
                    )
                    .await?;
                PreparedProtocolExecution::Graphql(self.graphql.prepare_invocation(
                    binding,
                    lease.source_configuration(),
                    lease.credential(),
                    arguments,
                    oauth_binding,
                )?)
            }
        };
        Ok(PreparedProtocolInvocation { lease, execution })
    }

    pub async fn execute_invocation(
        &self,
        prepared: PreparedProtocolInvocation,
    ) -> Result<ProtocolExecutionResponse, ProtocolInvocationError> {
        let PreparedProtocolInvocation { lease, execution } = prepared;
        let response = match execution {
            PreparedProtocolExecution::OpenApi(prepared) => self
                .openapi
                .execute_invocation(prepared)
                .await
                .map_err(ProtocolInvocationError::OpenApi),
            PreparedProtocolExecution::Graphql(prepared) => self
                .graphql
                .execute_invocation(prepared)
                .await
                .map_err(ProtocolInvocationError::Graphql),
            PreparedProtocolExecution::Mcp(prepared) => self
                .mcp
                .execute_invocation(prepared)
                .await
                .map_err(ProtocolInvocationError::Mcp),
        };
        drop(lease);
        response
    }
}

#[derive(Clone)]
pub struct SourceService {
    catalog: CatalogStore,
    registry: ProtocolRegistry,
    #[cfg(test)]
    source_creation_finish_pause: Option<Arc<SourceCreationFinishPause>>,
    #[cfg(test)]
    source_creation_panic: Option<SourceCreationPanic>,
    #[cfg(test)]
    source_delete_failure: Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    source_delete_pause: Option<Arc<SourceDeletePause>>,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum SourceCreationPanic {
    BeforeCreate,
    AfterCreate,
}

#[cfg(test)]
pub(crate) struct SourceCreationFinishPause {
    armed: std::sync::atomic::AtomicBool,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
impl Default for SourceCreationFinishPause {
    fn default() -> Self {
        Self {
            armed: std::sync::atomic::AtomicBool::new(true),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }
}

#[cfg(test)]
impl SourceCreationFinishPause {
    pub(crate) async fn reached(&self) {
        self.reached.notified().await;
    }

    pub(crate) fn release(&self) {
        self.release.notify_one();
    }
}

#[cfg(test)]
pub(crate) struct SourceDeletePause {
    armed: std::sync::atomic::AtomicBool,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
impl Default for SourceDeletePause {
    fn default() -> Self {
        Self {
            armed: std::sync::atomic::AtomicBool::new(true),
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }
}

#[cfg(test)]
impl SourceDeletePause {
    pub(crate) async fn reached(&self) {
        self.reached.notified().await;
    }

    pub(crate) fn release(&self) {
        self.release.notify_one();
    }
}

impl SourceService {
    pub(crate) fn new(
        catalog: CatalogStore,
        connections: Arc<crate::mcp::manager::McpConnectionManager>,
        oauth: crate::oauth::OAuthService,
    ) -> Self {
        Self {
            catalog,
            registry: ProtocolRegistry::new(connections, oauth),
            #[cfg(test)]
            source_creation_finish_pause: None,
            #[cfg(test)]
            source_creation_panic: None,
            #[cfg(test)]
            source_delete_failure: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            source_delete_pause: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn pause_source_creation_finish(&mut self) -> Arc<SourceCreationFinishPause> {
        let pause = Arc::new(SourceCreationFinishPause::default());
        self.source_creation_finish_pause = Some(pause.clone());
        pause
    }

    #[cfg(test)]
    pub(crate) fn panic_source_creation_at(&mut self, stage: SourceCreationPanic) {
        self.source_creation_panic = Some(stage);
    }

    #[cfg(test)]
    pub(crate) fn fail_next_source_delete(&self) {
        self.source_delete_failure
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn pause_source_delete_after_retire(&mut self) -> Arc<SourceDeletePause> {
        let pause = Arc::new(SourceDeletePause::default());
        self.source_delete_pause = Some(pause.clone());
        pause
    }

    #[cfg(test)]
    pub(crate) fn fail_mcp_watcher_capability_loads(
        &mut self,
        failures: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        self.registry.mcp.fail_watcher_capability_loads(failures);
    }

    #[cfg(test)]
    fn pause_mcp_watcher_unavailable_persistence(&mut self) -> Arc<mcp::WatcherUnavailablePause> {
        self.registry.mcp.pause_watcher_unavailable_persistence()
    }

    #[cfg(test)]
    pub(crate) fn source_creation_panics_at(&self, stage: SourceCreationPanic) -> bool {
        self.source_creation_panic == Some(stage)
    }

    pub fn registry(&self) -> &ProtocolRegistry {
        &self.registry
    }

    pub fn stdio_template_descriptors(
        &self,
    ) -> Vec<crate::mcp::upstream::stdio::StdioTemplateDescriptor> {
        self.registry.mcp.stdio_templates().descriptors()
    }

    pub(crate) fn source_creation_idempotency(
        &self,
    ) -> crate::catalog::source_idempotency::SourceCreationIdempotencyStore {
        self.catalog.source_creation_idempotency()
    }

    pub(crate) async fn finish_source_creation(&self, kind: SourceKind, source_id: &str) {
        if matches!(kind, SourceKind::McpHttp | SourceKind::McpStdio) {
            #[cfg(test)]
            if let Some(pause) = &self.source_creation_finish_pause
                && pause.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                pause.reached.notify_one();
                pause.release.notified().await;
            }
            self.registry
                .mcp
                .ensure_source_creation_watcher(&self.catalog, source_id)
                .await;
        }
    }

    pub async fn restore_mcp_watchers(&self) -> Result<(), ProtocolError> {
        self.registry.mcp.restore_watchers(&self.catalog).await
    }

    pub async fn delete(
        &self,
        source_id: &str,
        audit: AuditContext<'_>,
    ) -> Result<(), ProtocolError> {
        let _source_deletion = self.registry.mcp.lock_source_deletion(source_id).await;
        let source = self.source(source_id).await?;
        let is_mcp = matches!(source.kind, SourceKind::McpHttp | SourceKind::McpStdio);
        if is_mcp {
            self.registry.mcp.retire_source_watcher(source_id).await;
        }
        #[cfg(test)]
        if let Some(pause) = &self.source_delete_pause
            && pause.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            pause.reached.notify_one();
            pause.release.notified().await;
        }
        #[cfg(test)]
        let deleted = if self
            .source_delete_failure
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            Err(ProtocolError::new(
                ProtocolErrorCategory::Internal,
                "internal_error",
                "The source could not be deleted.",
            ))
        } else {
            self.catalog
                .delete_source(source_id, audit)
                .await
                .map_err(protocol_catalog_error)
        };
        #[cfg(not(test))]
        let deleted = self
            .catalog
            .delete_source(source_id, audit)
            .await
            .map_err(protocol_catalog_error);
        if deleted.is_err() && is_mcp {
            self.registry.mcp.unretire_source_watcher(source_id).await;
            if let Err(error) = self
                .registry
                .mcp
                .recover_source_watcher_after_failed_delete(
                    &self.catalog,
                    source_id,
                    source.revision,
                    audit,
                )
                .await
            {
                tracing::warn!(
                    source_id,
                    code = error.code,
                    "MCP watcher recovery after failed source delete failed"
                );
            }
        }
        deleted
    }

    pub async fn set_source_mode(
        &self,
        source_id: &str,
        mode: Option<ToolMode>,
        expected_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<SourceRecord, ProtocolError> {
        let revisions = self
            .lock_mcp_source_revisions([source_id.to_owned()])
            .await?;
        let source = self
            .catalog
            .set_source_mode(source_id, mode, expected_revision, audit)
            .await
            .map_err(protocol_catalog_error)?;
        self.advance_mcp_source_revisions(
            revisions,
            &[(source.id.clone(), source.revision)].into_iter().collect(),
        );
        Ok(source)
    }

    pub async fn set_tool_mode(
        &self,
        tool_id: &str,
        mode: Option<ToolMode>,
        expected_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<ToolRecord, ProtocolError> {
        let tool = self
            .catalog
            .tool(tool_id)
            .await
            .map_err(protocol_catalog_error)?;
        let revisions = self
            .lock_mcp_source_revisions([tool.source_id.clone()])
            .await?;
        let (tool, source_id, source_revision) = self
            .catalog
            .set_tool_mode_with_source_revision(tool_id, mode, expected_revision, audit)
            .await
            .map_err(protocol_catalog_error)?;
        self.advance_mcp_source_revisions(
            revisions,
            &[(source_id, source_revision)].into_iter().collect(),
        );
        Ok(tool)
    }

    pub async fn bulk_set_source_tool_modes(
        &self,
        source_id: &str,
        mode: Option<ToolMode>,
        expected_source_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<BulkToolModeResult, ProtocolError> {
        let revisions = self
            .lock_mcp_source_revisions([source_id.to_owned()])
            .await?;
        let result = self
            .catalog
            .bulk_set_source_tool_modes(source_id, mode, expected_source_revision, audit)
            .await
            .map_err(protocol_catalog_error)?;
        self.advance_mcp_source_revisions(revisions, &result.source_revisions);
        Ok(result)
    }

    pub async fn bulk_set_tool_modes(
        &self,
        tool_ids: &[String],
        mode: Option<ToolMode>,
        expected_catalog_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<BulkToolModeResult, ProtocolError> {
        let mut source_ids = HashSet::new();
        for tool_id in tool_ids {
            source_ids.insert(
                self.catalog
                    .tool(tool_id)
                    .await
                    .map_err(protocol_catalog_error)?
                    .source_id,
            );
        }
        let revisions = self.lock_mcp_source_revisions(source_ids).await?;
        let result = self
            .catalog
            .bulk_set_tool_modes(tool_ids, mode, expected_catalog_revision, audit)
            .await
            .map_err(protocol_catalog_error)?;
        self.advance_mcp_source_revisions(revisions, &result.source_revisions);
        Ok(result)
    }

    pub async fn preview_openapi(
        &self,
        spec: &OpenApiSpecInput,
        allow_private_network: bool,
    ) -> Result<OpenApiPreview, ProtocolError> {
        self.registry
            .openapi
            .preview(spec, allow_private_network)
            .await
    }

    pub async fn create(
        &self,
        kind: SourceKind,
        protocol: Value,
        audit: AuditContext<'_>,
    ) -> Result<SourceRecord, ProtocolError> {
        self.registry.require_supported(kind)?;
        match kind {
            SourceKind::Openapi => {
                let input = decode_protocol_input(protocol)?;
                self.registry
                    .openapi
                    .create_source(&self.catalog, input, audit)
                    .await
            }
            SourceKind::McpHttp => {
                let input = decode_protocol_input(protocol)?;
                self.registry
                    .mcp
                    .create_http_source(&self.catalog, input, audit)
                    .await
            }
            SourceKind::McpStdio => {
                let input = decode_protocol_input(protocol)?;
                self.registry
                    .mcp
                    .create_stdio_source(&self.catalog, input, audit)
                    .await
            }
            SourceKind::Graphql => {
                let input = decode_protocol_input(protocol)?;
                self.registry
                    .graphql
                    .create_source(&self.catalog, input, audit)
                    .await
            }
        }
    }

    pub async fn refresh(
        &self,
        source_id: &str,
        audit: AuditContext<'_>,
    ) -> Result<CatalogSyncResult, ProtocolError> {
        let source = self.source(source_id).await?;
        self.registry.require_supported(source.kind)?;
        let refreshed = match source.kind {
            SourceKind::Openapi => {
                self.registry
                    .openapi
                    .refresh_source(&self.catalog, source.clone(), audit)
                    .await
            }
            SourceKind::McpHttp | SourceKind::McpStdio => {
                self.registry
                    .mcp
                    .refresh_source(&self.catalog, source.clone(), audit)
                    .await
            }
            SourceKind::Graphql => {
                self.registry
                    .graphql
                    .refresh_source(&self.catalog, source.clone(), audit)
                    .await
            }
        };
        if let Err(error) = &refreshed {
            self.persist_refresh_failure(&source, error, audit).await;
        }
        refreshed
    }

    pub async fn credential_metadata(
        &self,
        source_id: &str,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let source = self.source(source_id).await?;
        self.registry.require_supported(source.kind)?;
        match source.kind {
            SourceKind::Openapi => {
                self.registry
                    .openapi
                    .credential_metadata(&self.catalog, &source.id)
                    .await
            }
            SourceKind::McpHttp | SourceKind::McpStdio => {
                self.registry
                    .mcp
                    .credential_metadata(&self.catalog, &source)
                    .await
            }
            SourceKind::Graphql => {
                self.registry
                    .graphql
                    .credential_metadata(&self.catalog, &source.id)
                    .await
            }
        }
    }

    pub async fn available_oauth_credentials(
        &self,
        source_id: &str,
    ) -> Result<Vec<AvailableOAuthCredential>, ProtocolError> {
        let source = self.source(source_id).await?;
        self.registry.require_supported(source.kind)?;
        let credentials = match source.kind {
            SourceKind::Openapi => self
                .registry
                .openapi
                .managed_oauth_options(&self.catalog, &source.id)
                .await?
                .into_iter()
                .map(|option| AvailableOAuthCredential {
                    credential_key: option.credential_key,
                    protocol: "openapi",
                    requested_scopes: option.scopes,
                    managed_oauth_eligible: true,
                })
                .collect(),
            SourceKind::Graphql => vec![AvailableOAuthCredential {
                credential_key: "default".to_owned(),
                protocol: "graphql",
                requested_scopes: Vec::new(),
                managed_oauth_eligible: true,
            }],
            SourceKind::McpHttp => vec![AvailableOAuthCredential {
                credential_key: "default".to_owned(),
                protocol: "mcp_http",
                requested_scopes: Vec::new(),
                managed_oauth_eligible: true,
            }],
            SourceKind::McpStdio => Vec::new(),
        };
        Ok(credentials)
    }

    pub async fn ensure_managed_oauth_origin_bound(
        &self,
        source_id: &str,
        credential_key: &str,
        audit: AuditContext<'_>,
    ) -> Result<(), ProtocolError> {
        let source = self.source(source_id).await?;
        if source.kind != SourceKind::Openapi {
            return Ok(());
        }
        self.registry
            .openapi
            .ensure_managed_oauth_origin_bound(&self.catalog, source_id, credential_key, audit)
            .await
    }

    pub async fn retire_managed_oauth_origin(
        &self,
        source_id: &str,
        credential_key: &str,
        audit: AuditContext<'_>,
    ) -> Result<(), ProtocolError> {
        let source = self.source(source_id).await?;
        if source.kind != SourceKind::Openapi {
            return Ok(());
        }
        self.registry
            .openapi
            .retire_managed_oauth_origin(&self.catalog, source_id, credential_key, audit)
            .await
    }

    pub async fn replace_credentials(
        &self,
        source_id: &str,
        expected_revision: i64,
        credential: Value,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let source = self.source(source_id).await?;
        self.registry.require_supported(source.kind)?;
        match source.kind {
            SourceKind::Openapi => {
                let credential = decode_protocol_input(credential)?;
                self.registry
                    .openapi
                    .replace_credentials(
                        &self.catalog,
                        &source.id,
                        expected_revision,
                        credential,
                        audit,
                    )
                    .await
            }
            SourceKind::McpHttp => {
                let credential = decode_protocol_input(credential)?;
                self.registry
                    .mcp
                    .replace_http_credentials(
                        &self.catalog,
                        &source.id,
                        expected_revision,
                        credential,
                        audit,
                    )
                    .await
            }
            SourceKind::McpStdio => {
                let credential = decode_protocol_input(credential)?;
                self.registry
                    .mcp
                    .replace_stdio_credentials(
                        &self.catalog,
                        &source.id,
                        expected_revision,
                        credential,
                        audit,
                    )
                    .await
            }
            SourceKind::Graphql => {
                let credential = decode_protocol_input(credential)?;
                self.registry
                    .graphql
                    .replace_credentials(
                        &self.catalog,
                        &source.id,
                        expected_revision,
                        credential,
                        audit,
                    )
                    .await
            }
        }
    }

    pub async fn clear_credentials(
        &self,
        source_id: &str,
        expected_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<CredentialMetadata, ProtocolError> {
        let source = self.source(source_id).await?;
        self.registry.require_supported(source.kind)?;
        match source.kind {
            SourceKind::Openapi => {
                self.registry
                    .openapi
                    .clear_credentials(&self.catalog, &source.id, expected_revision, audit)
                    .await
            }
            SourceKind::McpHttp | SourceKind::McpStdio => {
                self.registry
                    .mcp
                    .clear_credentials(&self.catalog, &source, expected_revision, audit)
                    .await
            }
            SourceKind::Graphql => {
                self.registry
                    .graphql
                    .clear_credentials(&self.catalog, &source.id, expected_revision, audit)
                    .await
            }
        }
    }

    async fn source(&self, source_id: &str) -> Result<SourceRecord, ProtocolError> {
        self.catalog
            .source(source_id)
            .await
            .map_err(protocol_catalog_error)
    }

    async fn lock_mcp_source_revisions(
        &self,
        source_ids: impl IntoIterator<Item = String>,
    ) -> Result<Option<SourceRevisionLease>, ProtocolError> {
        let source_ids = source_ids.into_iter().collect::<HashSet<_>>();
        loop {
            let mut observed = Vec::new();
            for source_id in &source_ids {
                let source = self.source(source_id).await?;
                if matches!(source.kind, SourceKind::McpHttp | SourceKind::McpStdio) {
                    observed.push((source.id, source.revision));
                }
            }
            if observed.is_empty() {
                return Ok(None);
            }
            if let Some(revisions) = self.registry.mcp.lock_source_revisions(observed).await {
                return Ok(Some(revisions));
            }
            tokio::task::yield_now().await;
        }
    }

    fn advance_mcp_source_revisions(
        &self,
        revisions: Option<SourceRevisionLease>,
        committed: &BTreeMap<String, i64>,
    ) {
        let Some(revisions) = revisions else {
            return;
        };
        let committed = revisions
            .source_ids()
            .filter_map(|source_id| {
                committed
                    .get(source_id)
                    .map(|revision| (source_id.to_owned(), *revision))
            })
            .collect::<HashMap<_, _>>();
        if !revisions.advance(&committed) {
            tracing::error!("MCP watcher revisions did not match a committed catalog mutation");
        }
    }

    async fn persist_refresh_failure(
        &self,
        source: &SourceRecord,
        error: &ProtocolError,
        audit: AuditContext<'_>,
    ) {
        if matches!(
            error.code,
            "revision_conflict"
                | "oauth_binding_changed"
                | "mcp_shutting_down"
                | "openapi_credential_origin_changed"
                | "openapi_credential_origin_unbound"
                | "insecure_openapi_transport"
        ) {
            return;
        }
        let health_code = if error.code == "authorization_required" {
            "authorization_required"
        } else {
            match source.kind {
                SourceKind::Openapi => "openapi_refresh_failed",
                SourceKind::Graphql => "graphql_refresh_failed",
                SourceKind::McpHttp | SourceKind::McpStdio => "mcp_refresh_failed",
            }
        };
        let revisions = if matches!(source.kind, SourceKind::McpHttp | SourceKind::McpStdio) {
            let Some(revisions) = self
                .registry
                .mcp
                .lock_source_revisions([(source.id.clone(), source.revision)])
                .await
            else {
                return;
            };
            Some(revisions)
        } else {
            None
        };
        match self
            .catalog
            .mark_source_error(&source.id, health_code, source.revision, audit)
            .await
        {
            Ok(updated) => self.advance_mcp_source_revisions(
                revisions,
                &[(updated.id, updated.revision)].into_iter().collect(),
            ),
            Err(CatalogError::RevisionConflict { .. } | CatalogError::NotFound { .. }) => {}
            Err(persistence_error) => {
                tracing::warn!(
                    source_id = source.id,
                    error = %persistence_error,
                    "source refresh failure health could not be persisted"
                );
            }
        }
    }
}

fn decode_protocol_input<T: DeserializeOwned>(value: Value) -> Result<T, ProtocolError> {
    serde_json::from_value(value).map_err(|_| {
        ProtocolError::new(
            ProtocolErrorCategory::InvalidInput,
            "invalid_json",
            "The request body must be valid JSON with the expected fields.",
        )
    })
}

pub(crate) fn protocol_catalog_error(error: CatalogError) -> ProtocolError {
    match error {
        CatalogError::Validation {
            code: "oauth_binding_changed",
            message,
        } => ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "oauth_binding_changed",
            message,
        ),
        CatalogError::Validation { code, message } => {
            ProtocolError::new(ProtocolErrorCategory::InvalidInput, code, message)
        }
        CatalogError::NotFound { entity: "source" } => ProtocolError::new(
            ProtocolErrorCategory::NotFound,
            "source_not_found",
            "The requested source does not exist.",
        ),
        CatalogError::NotFound { .. } | CatalogError::ToolNotFound { .. } => ProtocolError::new(
            ProtocolErrorCategory::NotFound,
            "tool_not_found",
            "The requested tool does not exist.",
        ),
        CatalogError::ToolDisabled { .. } => ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "tool_disabled",
            "The requested tool is disabled.",
        ),
        CatalogError::RevisionConflict { .. } => ProtocolError::new(
            ProtocolErrorCategory::Conflict,
            "revision_conflict",
            "The source changed. Refresh and retry the update.",
        ),
        CatalogError::CorruptData(_) => ProtocolError::corrupt(
            "corrupt_protocol_data",
            "The stored protocol data is invalid.",
        ),
        CatalogError::Database(_) | CatalogError::Crypto(_) | CatalogError::Json(_) => {
            ProtocolError::new(
                ProtocolErrorCategory::Internal,
                "internal_error",
                "The protocol operation could not be completed.",
            )
        }
    }
}

pub(crate) fn protocol_outbound_error(error: OutboundError) -> ProtocolError {
    let category = match error {
        OutboundError::InsecureTransport => ProtocolErrorCategory::InvalidInput,
        OutboundError::Connection
        | OutboundError::DnsResolution
        | OutboundError::Request
        | OutboundError::Timeout
        | OutboundError::UpstreamStatus { .. } => ProtocolErrorCategory::Upstream,
        _ => ProtocolErrorCategory::InvalidInput,
    };
    ProtocolError::new(
        category,
        error.code(),
        "The upstream request could not be completed safely.",
    )
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use serde_json::{Map, json};
    use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::RwLock,
        time::timeout,
    };

    use super::{
        ProtocolError, ProtocolErrorCategory, ProtocolRegistration, ProtocolRegistry,
        SourceService, decode_protocol_input, protocol_catalog_error, protocol_outbound_error,
    };
    use crate::catalog::{
        AuditContext, CatalogError, CatalogSnapshot, CredentialPayload, InitialCatalogSnapshot,
        InvocationLease, InvocationLookup, InvocationRevisionToken, ListToolsFilter,
        McpToolBindingV1, ModeProvenance, SourceHealth, SourceKind, StagedArtifact, StagedTool,
        StagedToolBinding, StoredCredential, ToolBinding, ToolMode,
    };
    use crate::crypto::Keyring;
    use crate::graphql::{GraphqlBindingV1, GraphqlOperation};
    use crate::mcp::{
        manager::{McpConnectionManager, WatcherRevisionLease},
        upstream::stdio::StdioTemplateRegistry,
    };
    use crate::oauth::OAuthService;
    use crate::openapi::{OpenApiBinding, OpenApiCredentialSet, OpenApiSecurityAlternative};
    use crate::outbound::{OutboundError, OutboundPolicy};
    use crate::protocols::openapi::CreateOpenApiSource;

    #[test]
    fn insecure_outbound_transport_is_sanitized_invalid_input() {
        let error = protocol_outbound_error(OutboundError::InsecureTransport);
        assert_eq!(error.category, ProtocolErrorCategory::InvalidInput);
        assert_eq!(error.code, "insecure_outbound_transport");
        assert_eq!(
            error.message,
            "The upstream request could not be completed safely."
        );
    }

    async fn source_service_fixture() -> (
        SourceService,
        crate::catalog::CatalogStore,
        Arc<McpConnectionManager>,
        SqlitePool,
    ) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("test database opens");
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("migrations apply");
        let keyring = Keyring::from_master_key([91; 32]).expect("test keyring derives");
        let catalog = crate::catalog::CatalogStore::new(pool.clone(), keyring.clone());
        let templates =
            StdioTemplateRegistry::new(vec![crate::mcp::upstream::stdio::StdioTemplate {
                name: "delete-fixture".to_owned(),
                executable: std::path::PathBuf::from("/bin/sh"),
                cwd: None,
                arguments: vec!["-c".to_owned(), "exit 1".to_owned()],
                environment: Default::default(),
                secret_environment: vec!["API_TOKEN".to_owned()],
            }])
            .expect("test stdio template validates");
        let connections = Arc::new(McpConnectionManager::new(templates));
        let oauth = OAuthService::new(
            pool.clone(),
            keyring,
            "http://127.0.0.1:4788".to_owned(),
            OutboundPolicy::default(),
        );
        let sources = SourceService::new(catalog.clone(), connections.clone(), oauth);
        (sources, catalog, connections, pool)
    }

    fn staged_tool(stable_key: &str, preferred_name: &str) -> StagedTool {
        StagedTool {
            stable_key: stable_key.to_owned(),
            preferred_name: preferred_name.to_owned(),
            display_name: preferred_name.to_owned(),
            description: None,
            input_schema: json!({ "type": "object" }),
            output_schema: None,
            input_typescript: None,
            output_typescript: None,
            typescript_definitions: Default::default(),
            intrinsic_mode: ToolMode::Enabled,
        }
    }

    fn openapi_binding(path: &str) -> ToolBinding {
        ToolBinding::OpenapiV1(OpenApiBinding {
            version: 1,
            method: "GET".to_owned(),
            path_template: path.to_owned(),
            server_url: "https://api.example.test".to_owned(),
            parameters: Vec::new(),
            request_body: None,
            security: Vec::new(),
        })
    }

    fn protocol_fixture(kind: SourceKind) -> (String, ToolBinding, CredentialPayload) {
        match kind {
            SourceKind::Openapi => (
                "fixture".to_owned(),
                openapi_binding("/fixture"),
                CredentialPayload {
                    schema_version: 1,
                    payload: json!({
                        "locator": { "type": "inline" },
                        "credentials": { "schemes": {} }
                    }),
                },
            ),
            SourceKind::Graphql => {
                let mut binding = GraphqlBindingV1 {
                    version: 1,
                    operation: GraphqlOperation::Query,
                    field_name: "fixture".to_owned(),
                    operation_name: "ExecutorFixture".to_owned(),
                    variables: Vec::new(),
                    selection: Vec::new(),
                    document: String::new(),
                };
                binding.document = binding
                    .canonical_document()
                    .expect("fixture binding is canonical");
                let stable_key = binding.stable_key().expect("fixture has a stable key");
                (
                    stable_key,
                    ToolBinding::GraphqlV1(binding),
                    CredentialPayload {
                        schema_version: 1,
                        payload: json!({
                            "endpoint": "https://graphql.example.test/query",
                            "credential": null
                        }),
                    },
                )
            }
            SourceKind::McpHttp => (
                "fixture".to_owned(),
                ToolBinding::McpHttpV1(McpToolBindingV1 {
                    version: 1,
                    tool_name: "fixture".to_owned(),
                }),
                CredentialPayload {
                    schema_version: 1,
                    payload: json!({
                        "endpoint": "https://mcp.example.test/rpc",
                        "credential": null
                    }),
                },
            ),
            SourceKind::McpStdio => unreachable!("lifecycle fixtures use MCP HTTP"),
        }
    }

    async fn create_invalid_refresh_fixture(
        catalog: &crate::catalog::CatalogStore,
        kind: SourceKind,
        slug: &str,
    ) -> (crate::catalog::SourceRecord, crate::catalog::ToolRecord) {
        let (stable_key, binding, credential) = protocol_fixture(kind);
        let (source, _) = catalog
            .create_source_with_catalog(
                crate::catalog::CreateSource {
                    kind,
                    preferred_slug: slug.to_owned(),
                    display_name: slug.to_owned(),
                    description: None,
                    configuration: Map::new(),
                },
                &credential,
                InitialCatalogSnapshot {
                    artifacts: vec![StagedArtifact {
                        kind: crate::catalog::ArtifactKind::Metadata,
                        stable_key: "last-good".to_owned(),
                        content: json!({ "lastGood": true }),
                    }],
                    tools: vec![staged_tool(&stable_key, "fixture")],
                },
                vec![StagedToolBinding {
                    stable_key,
                    binding,
                }],
                AuditContext::system(Some("invalid-refresh-fixture")),
            )
            .await
            .expect("fixture source is created");
        let tool_id = catalog
            .list_tools(ListToolsFilter {
                source_id: Some(source.id.clone()),
                include_tombstoned: true,
                limit: 10,
                ..ListToolsFilter::default()
            })
            .await
            .expect("fixture tools list")
            .items[0]
            .id
            .clone();
        let tool = catalog.tool(&tool_id).await.expect("fixture tool reads");
        (source, tool)
    }

    async fn create_mcp_watcher_fixture(
        catalog: &crate::catalog::CatalogStore,
        slug: &str,
        kind: SourceKind,
    ) -> crate::catalog::SourceRecord {
        let (configuration, credential, binding) = match kind {
            SourceKind::McpHttp => (
                json!({
                    "endpoint": "http://127.0.0.1:1/mcp",
                    "allowPrivateNetwork": true,
                    "negotiatedProtocolVersion": crate::mcp::upstream::http::DEFAULT_PROTOCOL_VERSION,
                }),
                json!({
                    "endpoint": "http://127.0.0.1:1/mcp",
                    "credential": {
                        "type": "bearer",
                        "token": "delete-rollback-secret"
                    }
                }),
                ToolBinding::McpHttpV1(McpToolBindingV1 {
                    version: 1,
                    tool_name: "fixture".to_owned(),
                }),
            ),
            SourceKind::McpStdio => (
                json!({
                    "templateName": "delete-fixture",
                    "negotiatedProtocolVersion": crate::mcp::upstream::stdio::DEFAULT_PROTOCOL_VERSION,
                }),
                json!({
                    "templateName": "delete-fixture",
                    "secretValues": {
                        "API_TOKEN": "delete-rollback-secret"
                    }
                }),
                ToolBinding::McpStdioV1(McpToolBindingV1 {
                    version: 1,
                    tool_name: "fixture".to_owned(),
                }),
            ),
            SourceKind::Openapi | SourceKind::Graphql => {
                unreachable!("MCP watcher fixtures require MCP source kinds")
            }
        };
        catalog
            .create_source_with_catalog(
                crate::catalog::CreateSource {
                    kind,
                    preferred_slug: slug.to_owned(),
                    display_name: slug.to_owned(),
                    description: None,
                    configuration: configuration
                        .as_object()
                        .expect("MCP configuration is an object")
                        .clone(),
                },
                &CredentialPayload {
                    schema_version: 1,
                    payload: credential,
                },
                InitialCatalogSnapshot {
                    artifacts: vec![StagedArtifact {
                        kind: crate::catalog::ArtifactKind::McpCapabilities,
                        stable_key: "mcp-server".to_owned(),
                        content: json!({
                            "protocolVersion": crate::mcp::upstream::http::DEFAULT_PROTOCOL_VERSION,
                            "serverInfo": { "name": "fixture", "version": "1" },
                            "instructions": null,
                            "capabilities": { "tools": { "listChanged": true } },
                            "toolsListChanged": true
                        }),
                    }],
                    tools: vec![staged_tool("fixture", "fixture")],
                },
                vec![StagedToolBinding {
                    stable_key: "fixture".to_owned(),
                    binding,
                }],
                AuditContext::system(Some("mcp-watcher-fixture")),
            )
            .await
            .expect("MCP watcher fixture creates")
            .0
    }

    async fn install_test_watcher(
        manager: &McpConnectionManager,
        source_id: &str,
        source_revision: i64,
    ) -> WatcherRevisionLease {
        let (lease_sender, lease_receiver) = tokio::sync::oneshot::channel();
        assert!(
            manager
                .replace_watcher(
                    source_id.to_owned(),
                    source_revision,
                    move |mut canceled, lease| async move {
                        lease_sender.send(lease).ok();
                        let _ = (&mut canceled).await;
                    },
                )
                .await
                .expect("test watcher installs")
        );
        lease_receiver.await.expect("test watcher exposes lease")
    }

    struct BlockingWatcherSentinel {
        canceled: tokio::sync::Notify,
        release: tokio::sync::Notify,
        in_use: std::sync::atomic::AtomicBool,
    }

    async fn install_blocking_test_watcher(
        manager: &McpConnectionManager,
        source_id: &str,
        source_revision: i64,
    ) -> (WatcherRevisionLease, Arc<BlockingWatcherSentinel>) {
        let sentinel = Arc::new(BlockingWatcherSentinel {
            canceled: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            in_use: std::sync::atomic::AtomicBool::new(false),
        });
        let (lease_sender, lease_receiver) = tokio::sync::oneshot::channel();
        assert!(
            manager
                .replace_watcher(source_id.to_owned(), source_revision, {
                    let sentinel = sentinel.clone();
                    move |mut canceled, lease| async move {
                        sentinel
                            .in_use
                            .store(true, std::sync::atomic::Ordering::SeqCst);
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
                .expect("blocking test watcher installs")
        );
        (
            lease_receiver
                .await
                .expect("blocking test watcher exposes lease"),
            sentinel,
        )
    }

    async fn commit_mcp_http_credential_replacement(
        catalog: &crate::catalog::CatalogStore,
        source: &crate::catalog::SourceRecord,
    ) -> crate::catalog::SourceRecord {
        let credential_revision = catalog
            .credential(&source.id)
            .await
            .expect("MCP credential reads")
            .expect("MCP credential exists")
            .revision;
        catalog
            .replace_credential_and_sync_catalog(
                &source.id,
                &CredentialPayload {
                    schema_version: 1,
                    payload: json!({
                        "endpoint": "http://127.0.0.1:1/mcp",
                        "credential": {
                            "type": "bearer",
                            "token": "replacement-secret"
                        }
                    }),
                },
                CatalogSnapshot {
                    expected_source_revision: source.revision,
                    expected_credential_revision: Some(credential_revision),
                    artifacts: vec![StagedArtifact {
                        kind: crate::catalog::ArtifactKind::McpCapabilities,
                        stable_key: "mcp-server".to_owned(),
                        content: json!({
                            "protocolVersion": crate::mcp::upstream::http::DEFAULT_PROTOCOL_VERSION,
                            "serverInfo": { "name": "fixture", "version": "1" },
                            "instructions": null,
                            "capabilities": { "tools": { "listChanged": true } },
                            "toolsListChanged": true
                        }),
                    }],
                    tools: vec![staged_tool("fixture", "fixture")],
                },
                vec![StagedToolBinding {
                    stable_key: "fixture".to_owned(),
                    binding: ToolBinding::McpHttpV1(McpToolBindingV1 {
                        version: 1,
                        tool_name: "fixture".to_owned(),
                    }),
                }],
                AuditContext::system(Some("replacement-during-unavailable-persist")),
            )
            .await
            .expect("MCP credential replacement commits")
            .2
    }

    #[test]
    fn registry_supports_all_imported_protocols() {
        let registry = ProtocolRegistry::default();
        assert_eq!(
            registry.registration(SourceKind::Openapi),
            ProtocolRegistration::OpenApi
        );
        assert_eq!(
            registry.registration(SourceKind::Graphql),
            ProtocolRegistration::Graphql
        );
        assert_eq!(
            registry.registration(SourceKind::McpHttp),
            ProtocolRegistration::McpHttp
        );
        assert_eq!(
            registry.registration(SourceKind::McpStdio),
            ProtocolRegistration::McpStdio
        );
    }

    #[test]
    fn malformed_create_and_credential_values_are_invalid_json() {
        let create_error = decode_protocol_input::<CreateOpenApiSource>(json!({
            "displayName": "Example",
            "spec": { "type": "inline", "content": 42 }
        }))
        .expect_err("malformed create input is rejected");
        assert_eq!(create_error.code, "invalid_json");
        assert_eq!(create_error.category, ProtocolErrorCategory::InvalidInput);

        let credential_error = decode_protocol_input::<OpenApiCredentialSet>(json!({
            "schemes": { "token": { "type": "bearer", "token": 42 } }
        }))
        .expect_err("malformed credential input is rejected");
        assert_eq!(credential_error.code, "invalid_json");
        assert_eq!(
            credential_error.category,
            ProtocolErrorCategory::InvalidInput
        );
    }

    #[test]
    fn oauth_binding_catalog_validation_is_a_protocol_conflict() {
        let error = protocol_catalog_error(CatalogError::Validation {
            code: "oauth_binding_changed",
            message: "The managed OAuth binding changed.".to_owned(),
        });
        assert_eq!(error.category, ProtocolErrorCategory::Conflict);
        assert_eq!(error.code, "oauth_binding_changed");
    }

    #[tokio::test]
    async fn mcp_watcher_revision_rebases_across_every_catalog_mode_mutation() {
        let (sources, catalog, connections, pool) = source_service_fixture().await;
        let (mut source, mut tool) =
            create_invalid_refresh_fixture(&catalog, SourceKind::McpHttp, "mode-revisions").await;
        let watcher = install_test_watcher(&connections, &source.id, source.revision).await;

        source = sources
            .set_source_mode(
                &source.id,
                Some(ToolMode::Ask),
                source.revision,
                AuditContext::system(Some("source-mode")),
            )
            .await
            .expect("source mode changes");
        assert_eq!(watcher.current_revision(), Some(source.revision));

        tool = sources
            .set_tool_mode(
                &tool.id,
                Some(ToolMode::Disabled),
                tool.revision,
                AuditContext::system(Some("tool-mode")),
            )
            .await
            .expect("tool mode changes");
        source = catalog.source(&source.id).await.expect("source reads");
        assert_eq!(watcher.current_revision(), Some(source.revision));

        let bulk_source = sources
            .bulk_set_source_tool_modes(
                &source.id,
                Some(ToolMode::Enabled),
                source.revision,
                AuditContext::system(Some("bulk-source-mode")),
            )
            .await
            .expect("source tool modes change");
        assert_eq!(
            watcher.current_revision(),
            bulk_source.source_revisions.get(&source.id).copied()
        );

        let bulk_tools = sources
            .bulk_set_tool_modes(
                &[tool.id.clone()],
                None,
                bulk_source.catalog_revision,
                AuditContext::system(Some("bulk-explicit-mode")),
            )
            .await
            .expect("explicit tool modes change");
        let final_revision = bulk_tools.source_revisions[&source.id];
        assert_eq!(watcher.current_revision(), Some(final_revision));
        assert!(
            connections
                .stop_watcher_and_wait_at_revision(&source.id, final_revision)
                .await
        );
        connections.shutdown().await;
        pool.close().await;
    }

    #[tokio::test]
    async fn failed_mcp_delete_reloads_authoritative_revision_before_restoring_watcher() {
        let (mut sources, catalog, connections, pool) = source_service_fixture().await;
        let source =
            create_mcp_watcher_fixture(&catalog, "delete-rollback-race", SourceKind::McpHttp).await;
        let old_watcher = install_test_watcher(&connections, &source.id, source.revision).await;
        sources.fail_next_source_delete();
        let pause = sources.pause_source_delete_after_retire();
        let deleting = tokio::spawn({
            let sources = sources.clone();
            let source_id = source.id.clone();
            async move {
                sources
                    .delete(&source_id, AuditContext::system(Some("failed-delete-race")))
                    .await
            }
        });
        timeout(Duration::from_secs(2), pause.reached())
            .await
            .expect("delete pauses after retiring its watcher");
        assert!(!connections.has_watcher(&source.id));

        let updated = sources
            .set_source_mode(
                &source.id,
                Some(ToolMode::Ask),
                source.revision,
                AuditContext::system(Some("delete-race-mode")),
            )
            .await
            .expect("concurrent source mutation commits");
        pause.release();
        let error = deleting
            .await
            .expect("failed delete task joins")
            .expect_err("fixture delete fails");
        assert_eq!(error.code, "internal_error");

        let current = catalog
            .source(&source.id)
            .await
            .expect("source remains after failed delete");
        assert_eq!(current.revision, updated.revision);
        assert_eq!(current.mode_override, Some(ToolMode::Ask));
        assert_eq!(current.health_status, SourceHealth::Healthy);
        assert_eq!(old_watcher.current_revision(), None);
        assert_eq!(
            connections.watcher_revision(&source.id),
            Some(current.revision)
        );

        connections.shutdown().await;
        pool.close().await;
    }

    #[tokio::test]
    async fn failed_mcp_delete_marks_unavailable_when_recovery_fails_then_restores_once() {
        let (mut sources, catalog, connections, pool) = source_service_fixture().await;
        let source =
            create_mcp_watcher_fixture(&catalog, "delete-recovery-failure", SourceKind::McpHttp)
                .await;
        let old_watcher = install_test_watcher(&connections, &source.id, source.revision).await;
        let failures = Arc::new(std::sync::atomic::AtomicUsize::new(3));
        sources.fail_mcp_watcher_capability_loads(failures.clone());
        sources.fail_next_source_delete();

        let error = sources
            .delete(
                &source.id,
                AuditContext::system(Some("failed-delete-recovery")),
            )
            .await
            .expect_err("fixture delete fails");
        assert_eq!(error.code, "internal_error");
        assert_eq!(failures.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(old_watcher.current_revision(), None);
        assert!(!connections.has_watcher(&source.id));

        let unavailable = catalog
            .source(&source.id)
            .await
            .expect("unavailable source remains readable");
        assert_eq!(unavailable.health_status, SourceHealth::Error);
        assert_eq!(
            unavailable.health_error_code.as_deref(),
            Some("mcp_watcher_unavailable")
        );

        sources
            .restore_mcp_watchers()
            .await
            .expect("watcher recovery succeeds after the load failure clears");
        assert_eq!(
            connections.watcher_revision(&source.id),
            Some(unavailable.revision)
        );
        let generation = connections
            .watcher_generation(&source.id)
            .expect("recovered watcher has a generation");
        sources
            .restore_mcp_watchers()
            .await
            .expect("repeated recovery preserves the current watcher");
        assert_eq!(connections.watcher_generation(&source.id), Some(generation));

        connections.shutdown().await;
        pool.close().await;
    }

    async fn concurrent_mcp_deletes_keep_successful_retirement(kind: SourceKind) {
        let (mut sources, catalog, connections, pool) = source_service_fixture().await;
        let source = create_mcp_watcher_fixture(
            &catalog,
            &format!("concurrent-delete-{}", kind.as_str()),
            kind,
        )
        .await;
        let (old_watcher, sentinel) =
            install_blocking_test_watcher(&connections, &source.id, source.revision).await;
        sources.fail_next_source_delete();
        let pause = sources.pause_source_delete_after_retire();

        let failing_delete = tokio::spawn({
            let sources = sources.clone();
            let source_id = source.id.clone();
            async move {
                sources
                    .delete(
                        &source_id,
                        AuditContext::system(Some("serialized-failed-delete")),
                    )
                    .await
            }
        });
        timeout(Duration::from_secs(2), sentinel.canceled.notified())
            .await
            .expect("first delete cancels the old-secret watcher");
        assert!(sentinel.in_use.load(std::sync::atomic::Ordering::SeqCst));

        let successful_delete = tokio::spawn({
            let sources = sources.clone();
            let source_id = source.id.clone();
            async move {
                sources
                    .delete(
                        &source_id,
                        AuditContext::system(Some("serialized-successful-delete")),
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!successful_delete.is_finished());

        sentinel.release.notify_one();
        timeout(Duration::from_secs(2), pause.reached())
            .await
            .expect("first delete pauses after joining the old-secret watcher");
        assert!(!successful_delete.is_finished());
        pause.release();

        let failure = failing_delete
            .await
            .expect("failed delete task joins")
            .expect_err("first delete receives the injected failure");
        assert_eq!(failure.code, "internal_error");
        successful_delete
            .await
            .expect("successful delete task joins")
            .expect("second delete commits");

        assert!(matches!(
            catalog.source(&source.id).await,
            Err(CatalogError::NotFound { .. })
        ));
        assert!(!connections.has_watcher(&source.id));
        assert_eq!(old_watcher.current_revision(), None);
        assert!(!sentinel.in_use.load(std::sync::atomic::Ordering::SeqCst));

        let stale_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let installed = connections
            .replace_watcher(source.id.clone(), source.revision, {
                let stale_started = stale_started.clone();
                move |_canceled, _lease| async move {
                    stale_started.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .await
            .expect("manager remains available");
        assert!(!installed);
        assert!(!stale_started.load(std::sync::atomic::Ordering::SeqCst));

        connections.shutdown().await;
        pool.close().await;
    }

    #[tokio::test]
    async fn concurrent_http_deletes_cannot_restore_after_successful_delete() {
        concurrent_mcp_deletes_keep_successful_retirement(SourceKind::McpHttp).await;
    }

    #[tokio::test]
    async fn concurrent_stdio_deletes_cannot_restore_after_successful_delete() {
        concurrent_mcp_deletes_keep_successful_retirement(SourceKind::McpStdio).await;
    }

    #[tokio::test]
    async fn stale_unavailable_persistence_cannot_overwrite_newer_credential_recovery() {
        let (mut sources, catalog, connections, pool) = source_service_fixture().await;
        let source = create_mcp_watcher_fixture(
            &catalog,
            "stale-unavailable-persistence",
            SourceKind::McpHttp,
        )
        .await;
        let old_watcher = install_test_watcher(&connections, &source.id, source.revision).await;
        sources.fail_mcp_watcher_capability_loads(Arc::new(std::sync::atomic::AtomicUsize::new(3)));
        sources.fail_next_source_delete();
        let pause = sources.pause_mcp_watcher_unavailable_persistence();

        let deleting = tokio::spawn({
            let sources = sources.clone();
            let source_id = source.id.clone();
            async move {
                sources
                    .delete(
                        &source_id,
                        AuditContext::system(Some("stale-unavailable-delete")),
                    )
                    .await
            }
        });
        timeout(Duration::from_secs(2), pause.reached())
            .await
            .expect("failed recovery pauses before unavailable persistence");
        assert!(!connections.has_watcher(&source.id));
        assert_eq!(old_watcher.current_revision(), None);

        let committed = commit_mcp_http_credential_replacement(&catalog, &source).await;
        let committed_revision = committed.revision;
        let finishing = tokio::spawn({
            let adapter = sources.registry.mcp.clone();
            let catalog = catalog.clone();
            let source_id = source.id.clone();
            async move {
                adapter
                    .finish_source_watcher_reconciliation(&catalog, &source_id, committed_revision)
                    .await
            }
        });
        tokio::task::yield_now().await;
        assert!(!finishing.is_finished());
        pause.release();

        let failure = deleting
            .await
            .expect("failed delete task joins")
            .expect_err("delete keeps its injected failure");
        assert_eq!(failure.code, "internal_error");
        finishing
            .await
            .expect("newer reconciliation task joins")
            .expect("newer credential watcher installs");

        let current = catalog
            .source(&source.id)
            .await
            .expect("newer source remains readable");
        assert_eq!(current.revision, committed_revision);
        assert_eq!(current.health_status, SourceHealth::Healthy);
        assert!(current.health_error_code.is_none());
        assert_eq!(
            connections.watcher_revision(&source.id),
            Some(committed_revision)
        );
        let credential = catalog
            .credential(&source.id)
            .await
            .expect("replacement credential reads")
            .expect("replacement credential exists");
        assert_eq!(
            credential.credential.payload["credential"]["token"],
            "replacement-secret"
        );

        assert!(
            connections
                .stop_watcher_and_wait_at_revision(&source.id, committed_revision)
                .await
        );
        connections.shutdown().await;
        pool.close().await;
    }

    #[tokio::test]
    async fn refresh_failures_persist_health_and_retain_last_good_catalogs() {
        let (sources, catalog, connections, pool) = source_service_fixture().await;
        for (kind, slug, health_code) in [
            (
                SourceKind::Openapi,
                "openapi-refresh-failure",
                "openapi_refresh_failed",
            ),
            (
                SourceKind::Graphql,
                "graphql-refresh-failure",
                "graphql_refresh_failed",
            ),
            (
                SourceKind::McpHttp,
                "mcp-refresh-failure",
                "mcp_refresh_failed",
            ),
        ] {
            let (source, last_good_tool) =
                create_invalid_refresh_fixture(&catalog, kind, slug).await;
            let watcher = if kind == SourceKind::McpHttp {
                Some(install_test_watcher(&connections, &source.id, source.revision).await)
            } else {
                None
            };

            let error = sources
                .refresh(&source.id, AuditContext::system(Some("failed-refresh")))
                .await
                .expect_err("invalid stored configuration fails refresh");
            assert_eq!(error.code, "invalid_source_configuration");
            let current = catalog
                .source(&source.id)
                .await
                .expect("source remains readable");
            assert_eq!(current.health_status, SourceHealth::Error);
            assert_eq!(current.health_error_code.as_deref(), Some(health_code));
            assert_eq!(current.catalog_revision, source.catalog_revision);

            let retained = catalog
                .tool(&last_good_tool.id)
                .await
                .expect("last-good tool remains readable");
            assert_eq!(retained.id, last_good_tool.id);
            assert_eq!(retained.local_name, last_good_tool.local_name);
            assert!(retained.present);
            if let Some(watcher) = watcher {
                assert_eq!(watcher.current_revision(), Some(current.revision));
                assert!(
                    connections
                        .stop_watcher_and_wait_at_revision(&source.id, current.revision)
                        .await
                );
            }
        }
        connections.shutdown().await;
        pool.close().await;
    }

    #[tokio::test]
    async fn stale_refresh_failure_cannot_overwrite_a_concurrent_source_revision() {
        let (sources, catalog, connections, pool) = source_service_fixture().await;
        let (source, _) =
            create_invalid_refresh_fixture(&catalog, SourceKind::Openapi, "stale-failure").await;
        let updated = sources
            .set_source_mode(
                &source.id,
                Some(ToolMode::Ask),
                source.revision,
                AuditContext::system(Some("concurrent-source-mode")),
            )
            .await
            .expect("concurrent source mutation commits");
        sources
            .persist_refresh_failure(
                &source,
                &ProtocolError::new(
                    ProtocolErrorCategory::Upstream,
                    "fixture_refresh_failed",
                    "fixture refresh failed",
                ),
                AuditContext::system(Some("stale-refresh-failure")),
            )
            .await;

        let current = catalog
            .source(&source.id)
            .await
            .expect("source remains readable");
        assert_eq!(current.revision, updated.revision);
        assert_eq!(current.mode_override, Some(ToolMode::Ask));
        assert_eq!(current.health_status, SourceHealth::Healthy);
        assert!(current.health_error_code.is_none());
        connections.shutdown().await;
        pool.close().await;
    }

    #[tokio::test]
    async fn then_aliases_are_reserved_without_changing_tool_identity_across_tombstones() {
        let (_sources, catalog, connections, pool) = source_service_fixture().await;
        let stable_key = "stable-then";
        let binding = StagedToolBinding {
            stable_key: stable_key.to_owned(),
            binding: openapi_binding("/then"),
        };
        let credential = CredentialPayload {
            schema_version: 1,
            payload: json!({}),
        };
        let (source, _) = catalog
            .create_source_with_catalog(
                crate::catalog::CreateSource {
                    kind: SourceKind::Openapi,
                    preferred_slug: "then".to_owned(),
                    display_name: "Then".to_owned(),
                    description: None,
                    configuration: Map::new(),
                },
                &credential,
                InitialCatalogSnapshot {
                    artifacts: Vec::new(),
                    tools: vec![staged_tool(stable_key, "then")],
                },
                vec![binding.clone()],
                AuditContext::system(Some("then-alias-create")),
            )
            .await
            .expect("source is created");
        assert_ne!(source.slug, "then");
        let original = catalog
            .list_tools(ListToolsFilter {
                source_id: Some(source.id.clone()),
                include_tombstoned: true,
                limit: 10,
                ..ListToolsFilter::default()
            })
            .await
            .expect("tools list")
            .items
            .into_iter()
            .next()
            .expect("tool exists");
        assert_ne!(original.local_name, "then");

        let removed = catalog
            .sync_catalog_with_bindings(
                &source.id,
                CatalogSnapshot {
                    expected_source_revision: source.revision,
                    expected_credential_revision: Some(0),
                    artifacts: Vec::new(),
                    tools: Vec::new(),
                },
                Vec::new(),
                AuditContext::system(Some("then-alias-remove")),
            )
            .await
            .expect("tool is tombstoned");
        let tombstone = catalog.tool(&original.id).await.expect("tombstone reads");
        assert!(!tombstone.present);

        catalog
            .sync_catalog_with_bindings(
                &source.id,
                CatalogSnapshot {
                    expected_source_revision: removed.source_revision,
                    expected_credential_revision: Some(0),
                    artifacts: Vec::new(),
                    tools: vec![staged_tool(stable_key, "then")],
                },
                vec![binding],
                AuditContext::system(Some("then-alias-restore")),
            )
            .await
            .expect("tool is restored");
        let restored = catalog
            .tool(&original.id)
            .await
            .expect("restored tool reads");
        assert!(restored.present);
        assert_eq!(restored.id, original.id);
        assert_eq!(restored.local_name, original.local_name);
        assert_eq!(restored.stable_key, original.stable_key);
        connections.shutdown().await;
        pool.close().await;
    }

    #[tokio::test]
    async fn preparation_has_no_network_and_the_lease_lives_through_execution() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let server_url = format!(
            "http://{}",
            listener.local_addr().expect("test listener has an address")
        );
        let mutation_gate = Arc::new(RwLock::new(()));
        let guard = mutation_gate.clone().read_owned().await;
        let input_schema = json!({ "type": "object" });
        let lease = InvocationLease {
            lookup: InvocationLookup {
                tool_id: "tool".to_owned(),
                source_id: "source".to_owned(),
                source_display_name: "Source".to_owned(),
                tool_display_name: "Tool".to_owned(),
                callable_path: "source.tool".to_owned(),
                sandbox_path: "tools.source.tool".to_owned(),
                effective_mode: ToolMode::Enabled,
                mode_provenance: ModeProvenance::Intrinsic,
                requires_approval: false,
            },
            revisions: InvocationRevisionToken {
                source_id: "source".to_owned(),
                tool_id: "tool".to_owned(),
                source_revision: 0,
                catalog_revision: 0,
                tool_revision: 0,
                binding_revision: 0,
                credential_revision: Some(0),
            },
            source_kind: SourceKind::Openapi,
            binding: ToolBinding::OpenapiV1(OpenApiBinding {
                version: 1,
                method: "GET".to_owned(),
                path_template: "/execute".to_owned(),
                server_url,
                parameters: Vec::new(),
                request_body: None,
                security: vec![OpenApiSecurityAlternative {
                    requirements: Vec::new(),
                }],
            }),
            input_schema: input_schema.clone(),
            input_validator: jsonschema::validator_for(&input_schema)
                .expect("test input schema compiles"),
            source_configuration: json!({
                "spec": { "type": "inline" },
                "allowPrivateNetwork": true
            })
            .as_object()
            .expect("test source configuration is an object")
            .clone(),
            credential: Some(StoredCredential {
                revision: 0,
                credential: CredentialPayload {
                    schema_version: 1,
                    payload: json!({
                        "locator": { "type": "inline" },
                        "credentials": { "schemes": {} }
                    }),
                },
            }),
            _guard: guard,
        };
        let registry = ProtocolRegistry::default();
        let prepared = registry
            .prepare_invocation(lease, &json!({}), None)
            .await
            .expect("invocation preparation succeeds");

        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "preparation must not connect to the upstream"
        );
        assert!(
            mutation_gate.try_write().is_err(),
            "the prepared invocation retains its lease"
        );

        let execution = tokio::spawn(async move { registry.execute_invocation(prepared).await });
        let (mut connection, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("execution connects to the upstream")
            .expect("test listener accepts the connection");
        assert!(
            mutation_gate.try_write().is_err(),
            "the lease remains held while transport is in flight"
        );
        let mut request = vec![0_u8; 4096];
        let read = timeout(Duration::from_secs(2), connection.read(&mut request))
            .await
            .expect("upstream request arrives")
            .expect("upstream request is readable");
        assert!(
            String::from_utf8_lossy(&request[..read]).starts_with("GET /execute HTTP/1.1"),
            "the prepared request is executed"
        );
        connection
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}",
            )
            .await
            .expect("test response writes");

        let response = execution
            .await
            .expect("protocol execution task completes")
            .expect("protocol execution succeeds");
        assert!(response.ok);
        assert_eq!(response.data, Some(json!({ "ok": true })));
        assert!(
            mutation_gate.try_write().is_ok(),
            "the lease is released after execution"
        );
    }
}
