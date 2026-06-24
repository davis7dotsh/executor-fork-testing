pub mod openapi;

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    catalog::{
        AuditContext, CatalogError, CatalogStore, CatalogSyncResult, InvocationLease, SourceKind,
        SourceRecord,
    },
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
}

#[derive(Debug)]
pub enum ProtocolInvocationError {
    Outbound(OutboundError),
}

impl fmt::Display for ProtocolInvocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Outbound(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ProtocolInvocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Outbound(error) => Some(error),
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
    GraphqlUnsupported,
    McpHttpUnsupported,
    McpStdioUnsupported,
}

#[derive(Clone, Default)]
pub struct ProtocolRegistry {
    openapi: openapi::OpenApiAdapter,
}

impl ProtocolRegistry {
    pub fn registration(&self, kind: SourceKind) -> ProtocolRegistration {
        match kind {
            SourceKind::Openapi => ProtocolRegistration::OpenApi,
            SourceKind::Graphql => ProtocolRegistration::GraphqlUnsupported,
            SourceKind::McpHttp => ProtocolRegistration::McpHttpUnsupported,
            SourceKind::McpStdio => ProtocolRegistration::McpStdioUnsupported,
        }
    }

    fn require_supported(&self, kind: SourceKind) -> Result<(), ProtocolError> {
        match self.registration(kind) {
            ProtocolRegistration::OpenApi => Ok(()),
            ProtocolRegistration::GraphqlUnsupported
            | ProtocolRegistration::McpHttpUnsupported
            | ProtocolRegistration::McpStdioUnsupported => Err(ProtocolError::new(
                ProtocolErrorCategory::Unsupported,
                "unsupported_source_kind",
                "This source protocol is not supported yet.",
            )),
        }
    }

    pub fn prepare_invocation(
        &self,
        lease: InvocationLease,
        arguments: &Value,
    ) -> Result<PreparedProtocolInvocation, ProtocolError> {
        self.require_supported(lease.source_kind())?;
        let execution = match lease.source_kind() {
            SourceKind::Openapi => {
                let binding = lease.binding().openapi().ok_or_else(|| {
                    ProtocolError::corrupt(
                        "source_binding_mismatch",
                        "The stored tool binding does not match its source protocol.",
                    )
                })?;
                PreparedProtocolExecution::OpenApi(self.openapi.prepare_invocation(
                    binding,
                    lease.source_configuration(),
                    lease.credential(),
                    arguments,
                )?)
            }
            SourceKind::Graphql | SourceKind::McpHttp | SourceKind::McpStdio => {
                return Err(ProtocolError::corrupt(
                    "source_binding_mismatch",
                    "The stored tool binding does not match its source protocol.",
                ));
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
            PreparedProtocolExecution::OpenApi(prepared) => {
                self.openapi.execute_invocation(prepared).await
            }
        };
        drop(lease);
        response
    }
}

#[derive(Clone)]
pub struct SourceService {
    catalog: CatalogStore,
    registry: ProtocolRegistry,
}

impl SourceService {
    pub fn new(catalog: CatalogStore) -> Self {
        Self {
            catalog,
            registry: ProtocolRegistry::default(),
        }
    }

    pub fn registry(&self) -> &ProtocolRegistry {
        &self.registry
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
            SourceKind::Graphql | SourceKind::McpHttp | SourceKind::McpStdio => {
                unreachable!("unsupported protocols return before create dispatch")
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
        match source.kind {
            SourceKind::Openapi => {
                self.registry
                    .openapi
                    .refresh_source(&self.catalog, source, audit)
                    .await
            }
            SourceKind::Graphql | SourceKind::McpHttp | SourceKind::McpStdio => {
                unreachable!("unsupported protocols return before refresh dispatch")
            }
        }
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
            SourceKind::Graphql | SourceKind::McpHttp | SourceKind::McpStdio => {
                unreachable!("unsupported protocols return before credential dispatch")
            }
        }
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
            SourceKind::Graphql | SourceKind::McpHttp | SourceKind::McpStdio => {
                unreachable!("unsupported protocols return before credential dispatch")
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
            SourceKind::Graphql | SourceKind::McpHttp | SourceKind::McpStdio => {
                unreachable!("unsupported protocols return before credential dispatch")
            }
        }
    }

    async fn source(&self, source_id: &str) -> Result<SourceRecord, ProtocolError> {
        self.catalog
            .source(source_id)
            .await
            .map_err(protocol_catalog_error)
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

    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::RwLock,
        time::timeout,
    };

    use super::{
        ProtocolErrorCategory, ProtocolRegistration, ProtocolRegistry, decode_protocol_input,
    };
    use crate::catalog::{
        CredentialPayload, InvocationLease, InvocationLookup, InvocationRevisionToken,
        ModeProvenance, SourceKind, StoredCredential, ToolBinding, ToolMode,
    };
    use crate::openapi::{OpenApiBinding, OpenApiCredentialSet, OpenApiSecurityAlternative};
    use crate::protocols::openapi::CreateOpenApiSource;

    #[test]
    fn registry_has_one_supported_protocol_and_explicit_extension_slots() {
        let registry = ProtocolRegistry::default();
        assert_eq!(
            registry.registration(SourceKind::Openapi),
            ProtocolRegistration::OpenApi
        );
        assert_eq!(
            registry.registration(SourceKind::Graphql),
            ProtocolRegistration::GraphqlUnsupported
        );
        assert_eq!(
            registry.registration(SourceKind::McpHttp),
            ProtocolRegistration::McpHttpUnsupported
        );
        assert_eq!(
            registry.registration(SourceKind::McpStdio),
            ProtocolRegistration::McpStdioUnsupported
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
            .prepare_invocation(lease, &json!({}))
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
