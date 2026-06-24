mod schema;
mod search;
mod store;

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::crypto::CryptoError;
use crate::openapi::OpenApiBinding;

pub use store::CatalogStore;

pub const DEFAULT_PAGE_LIMIT: u32 = 50;
pub const MAX_PAGE_LIMIT: u32 = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditActor {
    System,
    Admin { id: i64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditContext<'a> {
    request_id: Option<&'a str>,
    actor: AuditActor,
}

impl<'a> AuditContext<'a> {
    pub const fn system(request_id: Option<&'a str>) -> Self {
        Self {
            request_id,
            actor: AuditActor::System,
        }
    }

    pub const fn admin(request_id: &'a str, id: i64) -> Self {
        Self {
            request_id: Some(request_id),
            actor: AuditActor::Admin { id },
        }
    }

    pub(crate) const fn request_id(self) -> Option<&'a str> {
        self.request_id
    }

    pub(crate) const fn actor_admin_id(self) -> Option<i64> {
        match self.actor {
            AuditActor::System => None,
            AuditActor::Admin { id } => Some(id),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Openapi,
    Graphql,
    McpHttp,
    McpStdio,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Openapi => "openapi",
            Self::Graphql => "graphql",
            Self::McpHttp => "mcp_http",
            Self::McpStdio => "mcp_stdio",
        }
    }
}

impl fmt::Display for SourceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SourceKind {
    type Err = CatalogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "openapi" => Ok(Self::Openapi),
            "graphql" => Ok(Self::Graphql),
            "mcp_http" => Ok(Self::McpHttp),
            "mcp_stdio" => Ok(Self::McpStdio),
            _ => Err(CatalogError::CorruptData("unknown source kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceHealth {
    Unknown,
    Healthy,
    Error,
}

impl FromStr for SourceHealth {
    type Err = CatalogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "healthy" => Ok(Self::Healthy),
            "error" => Ok(Self::Error),
            _ => Err(CatalogError::CorruptData("unknown source health")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    OpenapiDocument,
    GraphqlSchema,
    McpCapabilities,
    Metadata,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenapiDocument => "openapi_document",
            Self::GraphqlSchema => "graphql_schema",
            Self::McpCapabilities => "mcp_capabilities",
            Self::Metadata => "metadata",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolMode {
    Enabled,
    Ask,
    Disabled,
}

impl ToolMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Ask => "ask",
            Self::Disabled => "disabled",
        }
    }
}

impl fmt::Display for ToolMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ToolMode {
    type Err = CatalogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "ask" => Ok(Self::Ask),
            "disabled" => Ok(Self::Disabled),
            _ => Err(CatalogError::CorruptData("unknown tool mode")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModeProvenance {
    ToolOverride,
    SourceOverride,
    Intrinsic,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveMode {
    pub mode: ToolMode,
    pub provenance: ModeProvenance,
}

#[derive(Clone, Debug)]
pub struct CreateSource {
    pub kind: SourceKind,
    pub preferred_slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub configuration: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug)]
pub struct UpdateSource {
    pub display_name: String,
    pub description: Option<String>,
    pub configuration: serde_json::Map<String, Value>,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRecord {
    pub id: String,
    pub kind: SourceKind,
    pub slug: String,
    pub display_name: String,
    pub description: Option<String>,
    pub configuration: serde_json::Map<String, Value>,
    pub mode_override: Option<ToolMode>,
    pub health_status: SourceHealth,
    pub health_error_code: Option<String>,
    pub revision: i64,
    pub catalog_revision: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_refreshed_at: Option<i64>,
    pub tool_count: i64,
    pub tombstoned_tool_count: i64,
}

#[derive(Clone, Debug)]
pub struct StagedTool {
    pub stable_key: String,
    pub preferred_name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub input_typescript: Option<String>,
    pub output_typescript: Option<String>,
    pub typescript_definitions: BTreeMap<String, String>,
    pub intrinsic_mode: ToolMode,
}

#[derive(Clone, Debug)]
pub struct InitialCatalogSnapshot {
    pub artifacts: Vec<StagedArtifact>,
    pub tools: Vec<StagedTool>,
}

#[derive(Clone, Debug)]
pub struct CatalogSnapshot {
    pub expected_source_revision: i64,
    pub expected_credential_revision: Option<i64>,
    pub artifacts: Vec<StagedArtifact>,
    pub tools: Vec<StagedTool>,
}

#[derive(Clone, Debug)]
pub struct StagedArtifact {
    pub kind: ArtifactKind,
    pub stable_key: String,
    pub content: Value,
}

#[derive(Clone, Debug)]
pub struct StagedToolBinding {
    pub stable_key: String,
    pub binding: ToolBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "definition", rename_all = "snake_case")]
pub enum ToolBinding {
    OpenapiV1(OpenApiBinding),
}

impl ToolBinding {
    pub const fn protocol(&self) -> &'static str {
        match self {
            Self::OpenapiV1(_) => "openapi",
        }
    }

    pub const fn version(&self) -> i64 {
        match self {
            Self::OpenapiV1(_) => 1,
        }
    }

    pub fn openapi(&self) -> Option<&OpenApiBinding> {
        match self {
            Self::OpenapiV1(binding) => Some(binding),
        }
    }

    pub(crate) fn decode(
        protocol: &str,
        version: i64,
        definition_json: &str,
    ) -> Result<Self, CatalogError> {
        match (protocol, version) {
            ("openapi", 1) => {
                let binding: OpenApiBinding = serde_json::from_str(definition_json)?;
                if binding.version != 1 {
                    return Err(CatalogError::CorruptData(
                        "unsupported OpenAPI binding version",
                    ));
                }
                Ok(Self::OpenapiV1(binding))
            }
            _ => Err(CatalogError::CorruptData(
                "unknown tool binding protocol or version",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredToolBinding {
    pub tool_id: String,
    pub source_id: String,
    pub revision: i64,
    pub binding: ToolBinding,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogSyncResult {
    pub source_id: String,
    pub source_revision: i64,
    pub catalog_revision: i64,
    pub global_revision: i64,
    pub active_tool_count: usize,
    pub tombstoned_tool_count: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolSummary {
    pub id: String,
    pub source_id: String,
    pub source_slug: String,
    pub stable_key: String,
    pub local_name: String,
    pub callable_path: String,
    pub sandbox_path: String,
    pub display_name: String,
    pub description: Option<String>,
    pub intrinsic_mode: ToolMode,
    pub mode_override: Option<ToolMode>,
    pub effective_mode: EffectiveMode,
    pub present: bool,
    pub revision: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_seen_at: i64,
    pub tombstoned_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolRecord {
    pub id: String,
    pub source_id: String,
    pub source_slug: String,
    pub stable_key: String,
    pub local_name: String,
    pub callable_path: String,
    pub sandbox_path: String,
    pub display_name: String,
    pub description: Option<String>,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub input_typescript: Option<String>,
    pub output_typescript: Option<String>,
    pub typescript_definitions: BTreeMap<String, String>,
    pub intrinsic_mode: ToolMode,
    pub mode_override: Option<ToolMode>,
    pub effective_mode: EffectiveMode,
    pub present: bool,
    pub revision: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_seen_at: i64,
    pub tombstoned_at: Option<i64>,
}

#[derive(Clone, Debug, Default)]
pub struct ListToolsFilter {
    pub query: Option<String>,
    pub source_id: Option<String>,
    pub effective_mode: Option<ToolMode>,
    pub include_tombstoned: bool,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolPage {
    pub items: Vec<ToolSummary>,
    pub total: usize,
    pub has_more: bool,
    pub next_offset: Option<usize>,
    pub catalog_revision: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkToolModeResult {
    pub updated_count: usize,
    pub catalog_revision: i64,
    pub source_revisions: std::collections::BTreeMap<String, i64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDiscoveryResult {
    pub path: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub integration: String,
    pub score: i64,
    pub effective_mode: ToolMode,
    pub requires_approval: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryPage {
    pub items: Vec<ToolDiscoveryResult>,
    pub total: usize,
    pub has_more: bool,
    pub next_offset: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribedTool {
    pub path: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_typescript: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_typescript: Option<String>,
    pub type_script_definitions: BTreeMap<String, String>,
    pub input_schema: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    pub effective_mode: EffectiveMode,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationLookup {
    pub tool_id: String,
    pub source_id: String,
    pub callable_path: String,
    pub sandbox_path: String,
    pub effective_mode: ToolMode,
    pub requires_approval: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationRevisionToken {
    pub source_id: String,
    pub tool_id: String,
    pub source_revision: i64,
    pub catalog_revision: i64,
    pub tool_revision: i64,
    pub binding_revision: i64,
    pub credential_revision: Option<i64>,
}

pub struct InvocationLease {
    pub(crate) lookup: InvocationLookup,
    pub(crate) revisions: InvocationRevisionToken,
    pub(crate) binding: ToolBinding,
    pub(crate) input_schema: Value,
    pub(crate) input_validator: jsonschema::Validator,
    pub(crate) source_configuration: serde_json::Map<String, Value>,
    pub(crate) credential: Option<StoredCredential>,
    pub(crate) _guard: tokio::sync::OwnedRwLockReadGuard<()>,
}

impl InvocationLease {
    pub fn lookup(&self) -> &InvocationLookup {
        &self.lookup
    }

    pub fn revisions(&self) -> &InvocationRevisionToken {
        &self.revisions
    }

    pub fn binding(&self) -> &ToolBinding {
        &self.binding
    }

    pub fn input_schema(&self) -> &Value {
        &self.input_schema
    }

    pub fn arguments_are_valid(&self, arguments: &Value) -> bool {
        self.input_validator.is_valid(arguments)
    }

    pub fn source_configuration(&self) -> &serde_json::Map<String, Value> {
        &self.source_configuration
    }

    pub fn credential(&self) -> Option<&StoredCredential> {
        self.credential.as_ref()
    }
}

impl Drop for InvocationLease {
    fn drop(&mut self) {}
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPayload {
    pub schema_version: u32,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredCredential {
    pub revision: i64,
    pub credential: CredentialPayload,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestSurface {
    Admin,
    Gateway,
    Cli,
    Mcp,
}

impl RequestSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Gateway => "gateway",
            Self::Cli => "cli",
            Self::Mcp => "mcp",
        }
    }
}

impl FromStr for RequestSurface {
    type Err = CatalogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "admin" => Ok(Self::Admin),
            "gateway" => Ok(Self::Gateway),
            "cli" => Ok(Self::Cli),
            "mcp" => Ok(Self::Mcp),
            _ => Err(CatalogError::CorruptData("unknown request surface")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestOutcome {
    Succeeded,
    Failed,
    PendingApproval,
    Denied,
}

impl RequestOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::PendingApproval => "pending_approval",
            Self::Denied => "denied",
        }
    }
}

impl FromStr for RequestOutcome {
    type Err = CatalogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "pending_approval" => Ok(Self::PendingApproval),
            "denied" => Ok(Self::Denied),
            _ => Err(CatalogError::CorruptData("unknown request outcome")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct NewRequestLog {
    pub request_id: String,
    pub actor_api_token_id: Option<String>,
    pub surface: RequestSurface,
    pub source_id: Option<String>,
    pub tool_id: Option<String>,
    pub path_snapshot: Option<String>,
    pub outcome: RequestOutcome,
    pub error_code: Option<String>,
    pub duration_ms: u64,
    pub approval_id: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestLogRecord {
    pub request_id: String,
    pub actor_api_token_id: Option<String>,
    pub surface: RequestSurface,
    pub source_id: Option<String>,
    pub tool_id: Option<String>,
    pub path_snapshot: Option<String>,
    pub outcome: RequestOutcome,
    pub error_code: Option<String>,
    pub duration_ms: i64,
    pub approval_id: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestLogPage {
    pub items: Vec<RequestLogRecord>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("catalog storage failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("credential protection failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("catalog payload encoding failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{message}")]
    Validation { code: &'static str, message: String },
    #[error("{entity} was not found")]
    NotFound { entity: &'static str },
    #[error("{scope} revision conflict: expected {expected}, found {actual}")]
    RevisionConflict {
        scope: &'static str,
        expected: i64,
        actual: i64,
    },
    #[error("tool not found: {path}")]
    ToolNotFound { path: String },
    #[error("tool disabled: {path}")]
    ToolDisabled { path: String },
    #[error("stored catalog data is invalid: {0}")]
    CorruptData(&'static str),
}

pub(crate) fn effective_mode(
    intrinsic: ToolMode,
    source_override: Option<ToolMode>,
    tool_override: Option<ToolMode>,
) -> EffectiveMode {
    if let Some(mode) = tool_override {
        EffectiveMode {
            mode,
            provenance: ModeProvenance::ToolOverride,
        }
    } else if let Some(mode) = source_override {
        EffectiveMode {
            mode,
            provenance: ModeProvenance::SourceOverride,
        }
    } else {
        EffectiveMode {
            mode: intrinsic,
            provenance: ModeProvenance::Intrinsic,
        }
    }
}
