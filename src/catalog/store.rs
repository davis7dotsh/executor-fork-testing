use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};
use sqlx::{FromRow, SqlitePool, Transaction};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

use super::{
    ArtifactKind, AuditContext, BulkToolModeResult, CatalogError, CatalogSnapshot,
    CatalogSyncResult, CreateSource, CredentialPayload, DEFAULT_PAGE_LIMIT, DescribedTool,
    DiscoveryPage, InitialCatalogSnapshot, InvocationLease, InvocationLookup, InvocationPreflight,
    InvocationRevisionToken, ListToolsFilter, MAX_PAGE_LIMIT, NewRequestLog, RequestLogPage,
    RequestLogRecord, RequestOutcome, RequestSurface, SourceHealth, SourceKind, SourceRecord,
    StagedToolBinding, StoredCredential, StoredToolBinding, ToolBinding, ToolMode, ToolPage,
    ToolRecord, ToolSummary, UpdateSource, effective_mode, search,
};
use crate::{crypto::Keyring, unix_timestamp};

const CREDENTIAL_PURPOSE: &str = "source-credential-v1";
const RESERVED_SOURCE_SLUGS: [&str; 5] = ["tools", "search", "describe", "sources", "executor"];
const TOOL_ERROR_TYPESCRIPT: &str =
    "{ code: string; message: string; status?: number; details?: unknown; retryable?: boolean }";
const TOOL_HTTP_META_TYPESCRIPT: &str = "{ status: number; headers: { [k: string]: string; } }";
const TOOL_FILE_TYPESCRIPT: &str = r#"{ _tag: "ToolFile"; name?: string; mimeType: string; encoding: "base64"; data: string; byteLength: number; }"#;
const MAX_SEARCH_CANDIDATES: i64 = 4_096;
const MAX_SEARCH_QUERY_CHARACTERS: usize = 256;
const MAX_SEARCH_QUERY_BYTES: usize = 1_024;
const MAX_SEARCH_QUERY_TOKENS: usize = 64;
const MAX_SEARCH_TOKEN_BYTES: usize = 256;
const MAX_ACTIVE_TOOLS_PER_SOURCE: usize = 100_000;
const MAX_TOMBSTONED_TOOLS_PER_SOURCE: usize = 25_000;
const MAX_TOOL_HISTORY_PER_SOURCE: usize =
    MAX_ACTIVE_TOOLS_PER_SOURCE + MAX_TOMBSTONED_TOOLS_PER_SOURCE;
const MAX_REQUEST_LOG_ROWS: i64 = 10_000;
const MAX_AUDIT_EVENT_ROWS: i64 = 10_000;
const MAX_AUDIT_METADATA_BYTES: usize = 64 * 1024;
const MAX_ARTIFACT_COUNT: usize = 4_096;
const MAX_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ARTIFACT_KEY_BYTES: usize = 1024;
const MAX_SCHEMA_BYTES: usize = 2 * 1024 * 1024;
const MAX_TYPESCRIPT_DEFINITIONS_BYTES: usize = 2 * 1024 * 1024;
const MAX_TYPESCRIPT_PREVIEW_BYTES: usize = 256 * 1024;
const MAX_TOOL_STABLE_KEY_BYTES: usize = 2 * 1024;
const MAX_TOOL_NAME_BYTES: usize = 1024;
const MAX_TOOL_DESCRIPTION_BYTES: usize = 16 * 1024;
const MAX_SEARCH_DESCRIPTION_BYTES: usize = 32 * 1024;
const MAX_SHORT_GRAM_DOCUMENT_BYTES: usize = 16 * 1024;
const MAX_LOCAL_NAME_BYTES: usize = 128;
const MAX_CATALOG_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
pub struct CatalogStore {
    pool: SqlitePool,
    keyring: Keyring,
    mutation_lock: Arc<RwLock<()>>,
    request_log_writes: Arc<Semaphore>,
}

#[derive(FromRow)]
struct SourceRow {
    id: String,
    kind: String,
    slug: String,
    display_name: String,
    description: Option<String>,
    configuration_json: String,
    mode_override: Option<String>,
    health_status: String,
    health_error_code: Option<String>,
    revision: i64,
    catalog_revision: i64,
    created_at: i64,
    updated_at: i64,
    last_refreshed_at: Option<i64>,
    tool_count: i64,
    tombstoned_tool_count: i64,
}

#[derive(FromRow)]
struct ToolRow {
    id: String,
    source_id: String,
    source_slug: String,
    source_mode_override: Option<String>,
    stable_key: String,
    local_name: String,
    display_name: String,
    description: Option<String>,
    input_schema_json: String,
    output_schema_json: Option<String>,
    input_typescript: Option<String>,
    output_typescript: Option<String>,
    typescript_definitions_json: String,
    intrinsic_mode: String,
    mode_override: Option<String>,
    present: i64,
    revision: i64,
    created_at: i64,
    updated_at: i64,
    last_seen_at: i64,
    tombstoned_at: Option<i64>,
}

#[derive(FromRow)]
struct ToolSummaryRow {
    id: String,
    source_id: String,
    source_slug: String,
    source_mode_override: Option<String>,
    stable_key: String,
    local_name: String,
    display_name: String,
    description: Option<String>,
    intrinsic_mode: String,
    mode_override: Option<String>,
    present: i64,
    revision: i64,
    created_at: i64,
    updated_at: i64,
    last_seen_at: i64,
    tombstoned_at: Option<i64>,
}

#[derive(FromRow)]
struct RequestLogRow {
    request_id: String,
    actor_api_token_id: Option<String>,
    surface: String,
    source_id: Option<String>,
    tool_id: Option<String>,
    path_snapshot: Option<String>,
    outcome: String,
    error_code: Option<String>,
    duration_ms: i64,
    approval_id: Option<String>,
    created_at: i64,
}

#[derive(FromRow)]
struct InvocationRow {
    tool_id: String,
    source_id: String,
    source_display_name: String,
    tool_display_name: String,
    source_kind: String,
    source_slug: String,
    local_name: String,
    present: i64,
    intrinsic_mode: String,
    tool_mode_override: Option<String>,
    source_mode_override: Option<String>,
    tool_revision: i64,
    source_revision: i64,
    catalog_revision: i64,
    configuration_json: String,
    input_schema_json: String,
    binding_protocol: Option<String>,
    binding_version: Option<i64>,
    definition_json: Option<String>,
    binding_revision: Option<i64>,
    credential_schema_version: Option<i64>,
    credential_ciphertext: Option<Vec<u8>>,
    credential_revision: Option<i64>,
}

struct PreparedTool {
    stable_key: String,
    preferred_name: String,
    display_name: String,
    description: Option<String>,
    search_description: String,
    search_short_grams: String,
    input_schema_json: String,
    output_schema_json: Option<String>,
    input_typescript: Option<String>,
    output_typescript: Option<String>,
    typescript_definitions_json: String,
    intrinsic_mode: ToolMode,
}

struct PreparedArtifact {
    kind: ArtifactKind,
    stable_key: String,
    content_json: String,
}

struct PreparedSnapshot {
    tools: Vec<PreparedTool>,
    artifacts: Vec<PreparedArtifact>,
    payload_bytes: usize,
}

enum CatalogApplyKind<'a> {
    Initial {
        source_kind: SourceKind,
        slug: &'a str,
        credential_schema_version: u32,
    },
    Refresh,
}

struct PreparedToolBinding {
    stable_key: String,
    protocol: &'static str,
    version: i64,
    definition_json: String,
}

type PreparedToolBindings = Vec<PreparedToolBinding>;

#[derive(Clone, Copy)]
struct PayloadLimits {
    artifact_count: usize,
    artifact: usize,
    artifact_key: usize,
    schema: usize,
    typescript_definitions: usize,
    typescript_preview: usize,
    tool_stable_key: usize,
    tool_name: usize,
    tool_description: usize,
    search_description: usize,
    short_gram_document: usize,
    local_name: usize,
    aggregate: usize,
}

impl Default for PayloadLimits {
    fn default() -> Self {
        Self {
            artifact_count: MAX_ARTIFACT_COUNT,
            artifact: MAX_ARTIFACT_BYTES,
            artifact_key: MAX_ARTIFACT_KEY_BYTES,
            schema: MAX_SCHEMA_BYTES,
            typescript_definitions: MAX_TYPESCRIPT_DEFINITIONS_BYTES,
            typescript_preview: MAX_TYPESCRIPT_PREVIEW_BYTES,
            tool_stable_key: MAX_TOOL_STABLE_KEY_BYTES,
            tool_name: MAX_TOOL_NAME_BYTES,
            tool_description: MAX_TOOL_DESCRIPTION_BYTES,
            search_description: MAX_SEARCH_DESCRIPTION_BYTES,
            short_gram_document: MAX_SHORT_GRAM_DOCUMENT_BYTES,
            local_name: MAX_LOCAL_NAME_BYTES,
            aggregate: MAX_CATALOG_PAYLOAD_BYTES,
        }
    }
}

struct PayloadBudget {
    limits: PayloadLimits,
    consumed: usize,
}

struct NameAllocator {
    used: HashSet<String>,
    next_suffix: HashMap<CollisionNamespace, u64>,
    candidate_probes: usize,
}

#[derive(Eq, Hash, PartialEq)]
struct CollisionNamespace {
    prefix: String,
    separator: char,
    suffix_digits: u32,
}

impl CatalogStore {
    pub(crate) fn new(pool: SqlitePool, keyring: Keyring) -> Self {
        Self {
            pool,
            keyring,
            mutation_lock: Arc::new(RwLock::new(())),
            request_log_writes: Arc::new(Semaphore::new(1)),
        }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn global_revision(&self) -> Result<i64, CatalogError> {
        Ok(
            sqlx::query_scalar("SELECT revision FROM catalog_state WHERE id = 1")
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn create_source_with_catalog(
        &self,
        input: CreateSource,
        credential: &CredentialPayload,
        snapshot: InitialCatalogSnapshot,
        bindings: Vec<StagedToolBinding>,
        audit: AuditContext<'_>,
    ) -> Result<(SourceRecord, CatalogSyncResult), CatalogError> {
        if input.kind != SourceKind::Openapi {
            return Err(validation(
                "invalid_source_kind",
                "Atomic imported-source creation currently supports OpenAPI sources only.",
            ));
        }
        let display_name = validate_text(
            "invalid_source_name",
            "Source names must contain between 1 and 200 characters.",
            &input.display_name,
            200,
        )?;
        let description = validate_optional_text(
            "invalid_source_description",
            "Source descriptions may contain at most 2000 characters.",
            input.description.as_deref(),
            2000,
        )?;
        if credential.schema_version == 0 {
            return Err(validation(
                "invalid_credential_schema",
                "Credential schema versions must be positive.",
            ));
        }
        let (prepared, prepared_bindings) =
            prepare_initial_snapshot_and_bindings(snapshot, bindings)?;
        if prepared_bindings
            .iter()
            .map(|binding| &binding.stable_key)
            .collect::<HashSet<_>>()
            != prepared
                .tools
                .iter()
                .map(|tool| &tool.stable_key)
                .collect::<HashSet<_>>()
        {
            return Err(validation(
                "incomplete_tool_bindings",
                "Every staged imported tool must have exactly one binding.",
            ));
        }

        let source_id = Uuid::new_v4().to_string();
        let configuration_json = serde_json::to_string(&input.configuration)?;
        let credential_plaintext = serde_json::to_vec(&credential.payload)?;
        let credential_ciphertext =
            self.keyring
                .encrypt(CREDENTIAL_PURPOSE, &source_id, &credential_plaintext)?;
        let base_slug = normalize_source_slug(&input.preferred_slug);
        let now = unix_timestamp();
        let _write = self.mutation_lock.write().await;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;

        let mut used_slugs = sqlx::query_scalar::<_, String>("SELECT slug FROM sources")
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .collect::<HashSet<_>>();
        used_slugs.extend(RESERVED_SOURCE_SLUGS.into_iter().map(str::to_owned));
        let slug = NameAllocator::new(used_slugs).allocate(&base_slug, 63, '_');
        let search_short_grams = search::short_gram_document(&[&slug]);
        sqlx::query(
            "INSERT INTO sources \
             (id, kind, slug, search_short_grams, display_name, description, configuration_json, \
              health_status, revision, catalog_revision, created_at, updated_at, last_refreshed_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 'healthy', 1, 1, ?, ?, ?)",
        )
        .bind(&source_id)
        .bind(input.kind.as_str())
        .bind(&slug)
        .bind(search_short_grams)
        .bind(display_name)
        .bind(description)
        .bind(configuration_json)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO source_credentials \
             (source_id, schema_version, payload_ciphertext, revision, created_at, updated_at) \
             VALUES (?, ?, ?, 0, ?, ?)",
        )
        .bind(&source_id)
        .bind(i64::from(credential.schema_version))
        .bind(credential_ciphertext)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;

        apply_artifacts(&mut transaction, &source_id, &prepared.artifacts, now).await?;
        let missing = apply_tools(&mut transaction, &source_id, &prepared.tools, now).await?;
        debug_assert!(missing.is_empty());
        apply_tool_bindings(&mut transaction, &source_id, &prepared_bindings, now).await?;
        rebuild_search_indexes(&mut transaction, &source_id).await?;

        let source_path = format!("tools.{slug}");
        let (source_revision, catalog_revision, global_revision) = finalize_catalog_apply(
            &mut transaction,
            audit,
            &source_id,
            &source_path,
            CatalogApplyKind::Initial {
                source_kind: input.kind,
                slug: &slug,
                credential_schema_version: credential.schema_version,
            },
            prepared.tools.len(),
            prepared.artifacts.len(),
            0,
            now,
        )
        .await?;

        let source = sqlx::query_as::<_, SourceRow>(SOURCE_SELECT_BY_ID)
            .bind(&source_id)
            .fetch_one(&mut *transaction)
            .await?
            .try_into()?;
        transaction.commit().await?;
        let sync = CatalogSyncResult {
            source_id,
            source_revision,
            catalog_revision,
            global_revision,
            active_tool_count: prepared.tools.len(),
            tombstoned_tool_count: 0,
        };
        Ok((source, sync))
    }

    pub async fn create_source(
        &self,
        input: CreateSource,
        audit: AuditContext<'_>,
    ) -> Result<SourceRecord, CatalogError> {
        let display_name = validate_text(
            "invalid_source_name",
            "Source names must contain between 1 and 200 characters.",
            &input.display_name,
            200,
        )?;
        let description = validate_optional_text(
            "invalid_source_description",
            "Source descriptions may contain at most 2000 characters.",
            input.description.as_deref(),
            2000,
        )?;
        let base_slug = normalize_source_slug(&input.preferred_slug);
        let source_id = Uuid::new_v4().to_string();
        let configuration_json = serde_json::to_string(&input.configuration)?;
        let now = unix_timestamp();
        let _write = self.mutation_lock.write().await;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let mut used_slugs = sqlx::query_scalar::<_, String>("SELECT slug FROM sources")
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .collect::<HashSet<_>>();
        used_slugs.extend(RESERVED_SOURCE_SLUGS.into_iter().map(str::to_owned));
        let slug = NameAllocator::new(used_slugs).allocate(&base_slug, 63, '_');
        let search_short_grams = search::short_gram_document(&[&slug]);
        sqlx::query(
            "INSERT INTO sources \
             (id, kind, slug, search_short_grams, display_name, description, configuration_json, \
              created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&source_id)
        .bind(input.kind.as_str())
        .bind(&slug)
        .bind(search_short_grams)
        .bind(display_name)
        .bind(description)
        .bind(configuration_json)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        bump_global_revision(&mut transaction, now).await?;
        insert_audit(
            &mut transaction,
            audit,
            "source.created",
            Some(&source_id),
            None,
            Some(&format!("tools.{slug}")),
            json!({ "kind": input.kind, "slug": slug }),
            now,
        )
        .await?;
        transaction.commit().await?;
        self.source(&source_id).await
    }

    pub async fn list_sources(&self) -> Result<Vec<SourceRecord>, CatalogError> {
        Ok(self.list_sources_snapshot().await?.0)
    }

    pub async fn list_sources_snapshot(&self) -> Result<(Vec<SourceRecord>, i64), CatalogError> {
        let mut transaction = self.pool.begin().await?;
        let sources = sqlx::query_as::<_, SourceRow>(SOURCE_SELECT_ALL)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(SourceRecord::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let revision = sqlx::query_scalar("SELECT revision FROM catalog_state WHERE id = 1")
            .fetch_one(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok((sources, revision))
    }

    pub async fn source(&self, source_id: &str) -> Result<SourceRecord, CatalogError> {
        sqlx::query_as::<_, SourceRow>(SOURCE_SELECT_BY_ID)
            .bind(source_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(CatalogError::NotFound { entity: "source" })?
            .try_into()
    }

    pub async fn update_source(
        &self,
        source_id: &str,
        input: UpdateSource,
        audit: AuditContext<'_>,
    ) -> Result<SourceRecord, CatalogError> {
        let display_name = validate_text(
            "invalid_source_name",
            "Source names must contain between 1 and 200 characters.",
            &input.display_name,
            200,
        )?;
        let description = validate_optional_text(
            "invalid_source_description",
            "Source descriptions may contain at most 2000 characters.",
            input.description.as_deref(),
            2000,
        )?;
        let configuration_json = serde_json::to_string(&input.configuration)?;
        let _write = self.mutation_lock.write().await;
        let now = unix_timestamp();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let changed = sqlx::query(
            "UPDATE sources SET display_name = ?, description = ?, configuration_json = ?, \
             revision = revision + 1, updated_at = ? WHERE id = ? AND revision = ?",
        )
        .bind(display_name)
        .bind(description)
        .bind(configuration_json)
        .bind(now)
        .bind(source_id)
        .bind(input.expected_revision)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 0 {
            return Err(revision_or_not_found(
                &mut transaction,
                "sources",
                source_id,
                "source",
                input.expected_revision,
            )
            .await?);
        }
        let global_revision = bump_global_revision(&mut transaction, now).await?;
        let source_path = source_path_snapshot(&mut transaction, source_id).await?;
        insert_audit(
            &mut transaction,
            audit,
            "source.updated",
            Some(source_id),
            None,
            Some(&source_path),
            json!({ "globalRevision": global_revision }),
            now,
        )
        .await?;
        transaction.commit().await?;
        self.source(source_id).await
    }

    pub async fn delete_source(
        &self,
        source_id: &str,
        audit: AuditContext<'_>,
    ) -> Result<(), CatalogError> {
        let _write = self.mutation_lock.write().await;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let source = sqlx::query_as::<_, SourceRow>(SOURCE_SELECT_BY_ID)
            .bind(source_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(CatalogError::NotFound { entity: "source" })?;
        let path = format!("tools.{}", source.slug);
        insert_audit(
            &mut transaction,
            audit,
            "source.deleted",
            Some(source_id),
            None,
            Some(&path),
            json!({ "slug": source.slug, "kind": source.kind }),
            unix_timestamp(),
        )
        .await?;
        sqlx::query("DELETE FROM tool_search WHERE source_id = ?")
            .bind(source_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM tool_search_trigram WHERE source_id = ?")
            .bind(source_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM tool_search_short WHERE source_id = ?")
            .bind(source_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("DELETE FROM sources WHERE id = ?")
            .bind(source_id)
            .execute(&mut *transaction)
            .await?;
        bump_global_revision(&mut transaction, unix_timestamp()).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn set_source_mode(
        &self,
        source_id: &str,
        mode: Option<ToolMode>,
        expected_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<SourceRecord, CatalogError> {
        let _write = self.mutation_lock.write().await;
        let now = unix_timestamp();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let changed = sqlx::query(
            "UPDATE sources SET mode_override = ?, revision = revision + 1, updated_at = ? \
             WHERE id = ? AND revision = ?",
        )
        .bind(mode.map(ToolMode::as_str))
        .bind(now)
        .bind(source_id)
        .bind(expected_revision)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 0 {
            return Err(revision_or_not_found(
                &mut transaction,
                "sources",
                source_id,
                "source",
                expected_revision,
            )
            .await?);
        }
        let global_revision = bump_global_revision(&mut transaction, now).await?;
        let source_path = source_path_snapshot(&mut transaction, source_id).await?;
        insert_audit(
            &mut transaction,
            audit,
            "source.mode_changed",
            Some(source_id),
            None,
            Some(&source_path),
            json!({ "modeOverride": mode, "globalRevision": global_revision }),
            now,
        )
        .await?;
        transaction.commit().await?;
        self.source(source_id).await
    }

    pub async fn put_credential(
        &self,
        source_id: &str,
        credential: &CredentialPayload,
        expected_revision: Option<i64>,
        audit: AuditContext<'_>,
    ) -> Result<(), CatalogError> {
        if credential.schema_version == 0 {
            return Err(validation(
                "invalid_credential_schema",
                "Credential schema versions must be positive.",
            ));
        }
        let plaintext = serde_json::to_vec(&credential.payload)?;
        let ciphertext = self
            .keyring
            .encrypt(CREDENTIAL_PURPOSE, source_id, &plaintext)?;
        let now = unix_timestamp();
        let _write = self.mutation_lock.write().await;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        ensure_source_exists(&mut transaction, source_id).await?;
        let actual_revision = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM source_credentials WHERE source_id = ?",
        )
        .bind(source_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if actual_revision != expected_revision {
            return Err(CatalogError::RevisionConflict {
                scope: "credential",
                expected: expected_revision.unwrap_or(-1),
                actual: actual_revision.unwrap_or(-1),
            });
        }
        if let Some(actual_revision) = actual_revision {
            let changed = sqlx::query(
                "UPDATE source_credentials SET schema_version = ?, payload_ciphertext = ?, \
                 revision = revision + 1, updated_at = ? WHERE source_id = ? AND revision = ?",
            )
            .bind(i64::from(credential.schema_version))
            .bind(ciphertext)
            .bind(now)
            .bind(source_id)
            .bind(actual_revision)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed == 0 {
                return Err(CatalogError::RevisionConflict {
                    scope: "credential",
                    expected: actual_revision,
                    actual: sqlx::query_scalar(
                        "SELECT revision FROM source_credentials WHERE source_id = ?",
                    )
                    .bind(source_id)
                    .fetch_optional(&mut *transaction)
                    .await?
                    .unwrap_or(-1),
                });
            }
        } else {
            sqlx::query(
                "INSERT INTO source_credentials \
                 (source_id, schema_version, payload_ciphertext, revision, created_at, updated_at) \
                 VALUES (?, ?, ?, 0, ?, ?)",
            )
            .bind(source_id)
            .bind(i64::from(credential.schema_version))
            .bind(ciphertext)
            .bind(now)
            .bind(now)
            .execute(&mut *transaction)
            .await?;
        }
        increment_source_and_global(&mut transaction, source_id, now).await?;
        let source_path = source_path_snapshot(&mut transaction, source_id).await?;
        insert_audit(
            &mut transaction,
            audit,
            "source.credential_changed",
            Some(source_id),
            None,
            Some(&source_path),
            json!({ "schemaVersion": credential.schema_version }),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn credential(
        &self,
        source_id: &str,
    ) -> Result<Option<StoredCredential>, CatalogError> {
        let credential = sqlx::query_as::<_, (i64, Vec<u8>, i64)>(
            "SELECT schema_version, payload_ciphertext, revision FROM source_credentials WHERE source_id = ?",
        )
        .bind(source_id)
        .fetch_optional(&self.pool)
        .await?;
        credential
            .map(|(schema_version, ciphertext, revision)| {
                let plaintext = self
                    .keyring
                    .decrypt(CREDENTIAL_PURPOSE, source_id, &ciphertext)?;
                Ok(StoredCredential {
                    revision,
                    credential: CredentialPayload {
                        schema_version: u32::try_from(schema_version)
                            .map_err(|_| CatalogError::CorruptData("credential schema version"))?,
                        payload: serde_json::from_slice(&plaintext)?,
                    },
                })
            })
            .transpose()
    }

    pub async fn delete_credential(
        &self,
        source_id: &str,
        expected_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<(), CatalogError> {
        let now = unix_timestamp();
        let _write = self.mutation_lock.write().await;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        ensure_source_exists(&mut transaction, source_id).await?;
        let changed =
            sqlx::query("DELETE FROM source_credentials WHERE source_id = ? AND revision = ?")
                .bind(source_id)
                .bind(expected_revision)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        if changed == 0 {
            let actual = sqlx::query_scalar::<_, i64>(
                "SELECT revision FROM source_credentials WHERE source_id = ?",
            )
            .bind(source_id)
            .fetch_optional(&mut *transaction)
            .await?
            .unwrap_or(-1);
            return Err(CatalogError::RevisionConflict {
                scope: "credential",
                expected: expected_revision,
                actual,
            });
        }
        increment_source_and_global(&mut transaction, source_id, now).await?;
        let source_path = source_path_snapshot(&mut transaction, source_id).await?;
        insert_audit(
            &mut transaction,
            audit,
            "source.credential_deleted",
            Some(source_id),
            None,
            Some(&source_path),
            json!({}),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn replace_tool_bindings(
        &self,
        source_id: &str,
        bindings: Vec<StagedToolBinding>,
    ) -> Result<(), CatalogError> {
        let prepared = prepare_tool_bindings(bindings)?;

        let _write = self.mutation_lock.write().await;
        let now = unix_timestamp();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let source_kind = source_kind(&mut transaction, source_id).await?;
        if source_kind != SourceKind::Openapi {
            return Err(validation(
                "invalid_source_kind",
                "OpenAPI tool bindings may only be stored for OpenAPI sources.",
            ));
        }
        let active_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM tools WHERE source_id = ? AND present = 1",
        )
        .bind(source_id)
        .fetch_one(&mut *transaction)
        .await?;
        if usize::try_from(active_count).ok() != Some(prepared.len()) {
            return Err(validation(
                "incomplete_tool_bindings",
                "Every active imported tool must have exactly one binding.",
            ));
        }
        for binding in prepared {
            let changed = sqlx::query(
                "INSERT INTO tool_bindings (tool_id, protocol, binding_version, definition_json, revision, created_at, updated_at) \
                 SELECT id, ?, ?, ?, 0, ?, ? FROM tools \
                 WHERE source_id = ? AND stable_key = ? AND present = 1 \
                 ON CONFLICT(tool_id) DO UPDATE SET protocol = excluded.protocol, \
                 binding_version = excluded.binding_version, \
                 definition_json = excluded.definition_json, revision = tool_bindings.revision + 1, \
                 updated_at = excluded.updated_at",
            )
            .bind(binding.protocol)
            .bind(binding.version)
            .bind(binding.definition_json)
            .bind(now)
            .bind(now)
            .bind(source_id)
            .bind(binding.stable_key)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(validation(
                    "invalid_tool_binding",
                    "A tool binding does not match an active imported tool.",
                ));
            }
        }
        sqlx::query(
            "DELETE FROM tool_bindings WHERE tool_id IN (\
             SELECT id FROM tools WHERE source_id = ? AND present = 0)",
        )
        .bind(source_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn tool_binding(&self, tool_id: &str) -> Result<StoredToolBinding, CatalogError> {
        let row = sqlx::query_as::<_, (String, String, String, String, i64, String, i64)>(
            "SELECT tool_bindings.tool_id, tools.source_id, sources.kind, \
             tool_bindings.protocol, tool_bindings.binding_version, tool_bindings.definition_json, \
             tool_bindings.revision FROM tool_bindings \
             JOIN tools ON tools.id = tool_bindings.tool_id \
             JOIN sources ON sources.id = tools.source_id \
             WHERE tool_bindings.tool_id = ? AND tools.present = 1",
        )
        .bind(tool_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CatalogError::NotFound {
            entity: "tool binding",
        })?;
        let binding = ToolBinding::decode(&row.3, row.4, &row.5)?;
        if !matches!(
            (&binding, SourceKind::from_str(&row.2)?),
            (ToolBinding::OpenapiV1(_), SourceKind::Openapi)
        ) {
            return Err(CatalogError::CorruptData(
                "tool binding does not match source kind",
            ));
        }
        Ok(StoredToolBinding {
            tool_id: row.0,
            source_id: row.1,
            revision: row.6,
            binding,
        })
    }

    pub async fn sync_catalog(
        &self,
        source_id: &str,
        snapshot: CatalogSnapshot,
        audit: AuditContext<'_>,
    ) -> Result<CatalogSyncResult, CatalogError> {
        self.sync_catalog_with_bindings(source_id, snapshot, Vec::new(), audit)
            .await
    }

    pub async fn sync_catalog_with_bindings(
        &self,
        source_id: &str,
        snapshot: CatalogSnapshot,
        bindings: Vec<StagedToolBinding>,
        audit: AuditContext<'_>,
    ) -> Result<CatalogSyncResult, CatalogError> {
        let expected_source_revision = snapshot.expected_source_revision;
        let expected_credential_revision = snapshot.expected_credential_revision;
        let (prepared, prepared_bindings) = prepare_snapshot_and_bindings(snapshot, bindings)?;
        let now = unix_timestamp();
        let _write = self.mutation_lock.write().await;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let (actual_source_revision, source_kind) =
            sqlx::query_as::<_, (i64, String)>("SELECT revision, kind FROM sources WHERE id = ?")
                .bind(source_id)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(CatalogError::NotFound { entity: "source" })?;
        if actual_source_revision != expected_source_revision {
            return Err(CatalogError::RevisionConflict {
                scope: "source",
                expected: expected_source_revision,
                actual: actual_source_revision,
            });
        }
        let source_kind = SourceKind::from_str(&source_kind)?;
        let binding_keys = prepared_bindings
            .iter()
            .map(|binding| &binding.stable_key)
            .collect::<HashSet<_>>();
        let staged_tool_keys = prepared
            .tools
            .iter()
            .map(|tool| &tool.stable_key)
            .collect::<HashSet<_>>();
        match source_kind {
            SourceKind::Openapi if binding_keys != staged_tool_keys => {
                return Err(validation(
                    "incomplete_tool_bindings",
                    "Every active OpenAPI tool must have exactly one binding.",
                ));
            }
            SourceKind::Openapi => {}
            _ if !prepared_bindings.is_empty() => {
                return Err(validation(
                    "invalid_source_kind",
                    "OpenAPI tool bindings may only be stored for OpenAPI sources.",
                ));
            }
            _ => {}
        }
        let actual_credential_revision = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM source_credentials WHERE source_id = ?",
        )
        .bind(source_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if actual_credential_revision != expected_credential_revision {
            return Err(CatalogError::RevisionConflict {
                scope: "credential",
                expected: expected_credential_revision.unwrap_or(-1),
                actual: actual_credential_revision.unwrap_or(-1),
            });
        }
        apply_artifacts(&mut transaction, source_id, &prepared.artifacts, now).await?;
        let missing = apply_tools(&mut transaction, source_id, &prepared.tools, now).await?;
        apply_tool_bindings(&mut transaction, source_id, &prepared_bindings, now).await?;
        rebuild_search_indexes(&mut transaction, source_id).await?;

        let source_path = source_path_snapshot(&mut transaction, source_id).await?;
        let (source_revision, catalog_revision, global_revision) = finalize_catalog_apply(
            &mut transaction,
            audit,
            source_id,
            &source_path,
            CatalogApplyKind::Refresh,
            prepared.tools.len(),
            prepared.artifacts.len(),
            missing.len(),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(CatalogSyncResult {
            source_id: source_id.to_owned(),
            source_revision,
            catalog_revision,
            global_revision,
            active_tool_count: prepared.tools.len(),
            tombstoned_tool_count: missing.len(),
        })
    }

    pub async fn list_tools(&self, filter: ListToolsFilter) -> Result<ToolPage, CatalogError> {
        let tokens_json = serde_json::to_string(
            &filter
                .query
                .as_deref()
                .map(normalize_filter_query)
                .unwrap_or_default(),
        )?;
        let source_id = filter.source_id.as_deref();
        let effective_mode = filter.effective_mode.map(ToolMode::as_str);
        let include_tombstoned = i64::from(filter.include_tombstoned);
        let limit = page_limit(filter.limit);
        let offset = i64::from(filter.offset);
        let mut transaction = self.pool.begin().await?;
        let total = sqlx::query_scalar::<_, i64>(TOOL_LIST_COUNT)
            .bind(include_tombstoned)
            .bind(source_id)
            .bind(source_id)
            .bind(effective_mode)
            .bind(effective_mode)
            .bind(&tokens_json)
            .fetch_one(&mut *transaction)
            .await?;
        let items = sqlx::query_as::<_, ToolSummaryRow>(TOOL_LIST_PAGE)
            .bind(include_tombstoned)
            .bind(source_id)
            .bind(source_id)
            .bind(effective_mode)
            .bind(effective_mode)
            .bind(tokens_json)
            .bind(i64::try_from(limit).unwrap_or(i64::MAX))
            .bind(offset)
            .fetch_all(&mut *transaction)
            .await?
            .into_iter()
            .map(ToolSummary::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let catalog_revision =
            sqlx::query_scalar("SELECT revision FROM catalog_state WHERE id = 1")
                .fetch_one(&mut *transaction)
                .await?;
        transaction.commit().await?;
        let total = usize::try_from(total).map_err(|_| CatalogError::CorruptData("tool count"))?;
        let start = usize::try_from(filter.offset)
            .unwrap_or(usize::MAX)
            .min(total);
        let consumed = start + items.len();
        let has_more = consumed < total;
        Ok(ToolPage {
            items,
            total,
            has_more,
            next_offset: has_more.then_some(consumed),
            catalog_revision,
        })
    }

    pub async fn tool(&self, tool_id: &str) -> Result<ToolRecord, CatalogError> {
        sqlx::query_as::<_, ToolRow>(TOOL_SELECT_BY_ID)
            .bind(tool_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(CatalogError::NotFound { entity: "tool" })?
            .try_into()
    }

    pub async fn set_tool_mode(
        &self,
        tool_id: &str,
        mode: Option<ToolMode>,
        expected_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<ToolRecord, CatalogError> {
        let _write = self.mutation_lock.write().await;
        let now = unix_timestamp();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query_as::<_, (String, String, String)>(
            "SELECT tools.source_id, sources.slug, tools.local_name \
             FROM tools JOIN sources ON sources.id = tools.source_id WHERE tools.id = ?",
        )
        .bind(tool_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(CatalogError::NotFound { entity: "tool" })?;
        let changed = sqlx::query(
            "UPDATE tools SET mode_override = ?, revision = revision + 1, updated_at = ? \
             WHERE id = ? AND revision = ?",
        )
        .bind(mode.map(ToolMode::as_str))
        .bind(now)
        .bind(tool_id)
        .bind(expected_revision)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 0 {
            let actual = sqlx::query_scalar::<_, i64>("SELECT revision FROM tools WHERE id = ?")
                .bind(tool_id)
                .fetch_one(&mut *transaction)
                .await?;
            return Err(CatalogError::RevisionConflict {
                scope: "tool",
                expected: expected_revision,
                actual,
            });
        }
        let source_revision = increment_source_revision(&mut transaction, &row.0, now).await?;
        let global_revision = bump_global_revision(&mut transaction, now).await?;
        let path = format!("tools.{}.{}", row.1, row.2);
        insert_audit(
            &mut transaction,
            audit,
            "tool.mode_changed",
            Some(&row.0),
            Some(tool_id),
            Some(&path),
            json!({
                "modeOverride": mode,
                "sourceRevision": source_revision,
                "globalRevision": global_revision
            }),
            now,
        )
        .await?;
        transaction.commit().await?;
        self.tool(tool_id).await
    }

    pub async fn bulk_set_source_tool_modes(
        &self,
        source_id: &str,
        mode: Option<ToolMode>,
        expected_source_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<BulkToolModeResult, CatalogError> {
        let _write = self.mutation_lock.write().await;
        let now = unix_timestamp();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let actual_revision =
            sqlx::query_scalar::<_, i64>("SELECT revision FROM sources WHERE id = ?")
                .bind(source_id)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(CatalogError::NotFound { entity: "source" })?;
        if actual_revision != expected_source_revision {
            return Err(CatalogError::RevisionConflict {
                scope: "source",
                expected: expected_source_revision,
                actual: actual_revision,
            });
        }
        let updated_count = sqlx::query(
            "UPDATE tools SET mode_override = ?, revision = revision + 1, updated_at = ? \
             WHERE source_id = ? AND present = 1",
        )
        .bind(mode.map(ToolMode::as_str))
        .bind(now)
        .bind(source_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected() as usize;
        let source_revision = increment_source_revision(&mut transaction, source_id, now).await?;
        let catalog_revision = bump_global_revision(&mut transaction, now).await?;
        let source_path = source_path_snapshot(&mut transaction, source_id).await?;
        insert_audit(
            &mut transaction,
            audit,
            "tool.mode_bulk_changed",
            Some(source_id),
            None,
            Some(&source_path),
            json!({
                "selection": "source",
                "modeOverride": mode,
                "updatedCount": updated_count,
                "sourceRevision": source_revision,
                "globalRevision": catalog_revision
            }),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(BulkToolModeResult {
            updated_count,
            catalog_revision,
            source_revisions: [(source_id.to_owned(), source_revision)]
                .into_iter()
                .collect(),
        })
    }

    pub async fn bulk_set_tool_modes(
        &self,
        tool_ids: &[String],
        mode: Option<ToolMode>,
        expected_catalog_revision: i64,
        audit: AuditContext<'_>,
    ) -> Result<BulkToolModeResult, CatalogError> {
        let mut unique_ids = tool_ids.to_vec();
        unique_ids.sort_unstable();
        unique_ids.dedup();
        if unique_ids.is_empty() || unique_ids.len() > 200 {
            return Err(validation(
                "invalid_tool_selection",
                "Select between 1 and 200 tools for a bulk mode change.",
            ));
        }
        let _write = self.mutation_lock.write().await;
        let now = unix_timestamp();
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let actual_catalog_revision =
            sqlx::query_scalar::<_, i64>("SELECT revision FROM catalog_state WHERE id = 1")
                .fetch_one(&mut *transaction)
                .await?;
        if actual_catalog_revision != expected_catalog_revision {
            return Err(CatalogError::RevisionConflict {
                scope: "catalog",
                expected: expected_catalog_revision,
                actual: actual_catalog_revision,
            });
        }
        let mut source_ids = HashSet::new();
        let mut selected_tools = Vec::with_capacity(unique_ids.len());
        for tool_id in &unique_ids {
            let (source_id, source_slug, local_name) =
                sqlx::query_as::<_, (String, String, String)>(
                    "SELECT tools.source_id, sources.slug, tools.local_name \
                 FROM tools JOIN sources ON sources.id = tools.source_id \
                 WHERE tools.id = ? AND tools.present = 1",
                )
                .bind(tool_id)
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(CatalogError::NotFound { entity: "tool" })?;
            source_ids.insert(source_id);
            selected_tools.push(json!({
                "toolId": tool_id,
                "path": format!("tools.{source_slug}.{local_name}")
            }));
        }
        for tool_id in &unique_ids {
            sqlx::query(
                "UPDATE tools SET mode_override = ?, revision = revision + 1, updated_at = ? \
                 WHERE id = ?",
            )
            .bind(mode.map(ToolMode::as_str))
            .bind(now)
            .bind(tool_id)
            .execute(&mut *transaction)
            .await?;
        }
        let mut source_revisions = std::collections::BTreeMap::new();
        for source_id in source_ids {
            let revision = increment_source_revision(&mut transaction, &source_id, now).await?;
            source_revisions.insert(source_id, revision);
        }
        let catalog_revision = bump_global_revision(&mut transaction, now).await?;
        insert_audit(
            &mut transaction,
            audit,
            "tool.mode_bulk_changed",
            None,
            None,
            None,
            json!({
                "selection": "explicit",
                "selectedTools": selected_tools,
                "modeOverride": mode,
                "updatedCount": unique_ids.len(),
                "globalRevision": catalog_revision
            }),
            now,
        )
        .await?;
        transaction.commit().await?;
        Ok(BulkToolModeResult {
            updated_count: unique_ids.len(),
            catalog_revision,
            source_revisions,
        })
    }

    pub async fn search_tools(
        &self,
        query: &str,
        namespace: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> Result<DiscoveryPage, CatalogError> {
        validate_search_input("query", query)?;
        if let Some(namespace) = namespace {
            validate_search_input("namespace", namespace)?;
        }
        let Some(expressions) = search::candidate_expressions(query) else {
            return Ok(search::search(
                &[],
                query,
                namespace,
                page_limit(limit),
                usize::try_from(offset).unwrap_or(usize::MAX),
            ));
        };
        let namespace_prefix = search::namespace_prefix(namespace);
        let namespace_like = namespace_prefix
            .as_ref()
            .map(|namespace| format!("{namespace} %"));
        let trigram_enabled = i64::from(expressions.trigram.is_some());
        let short_bigram_enabled = i64::from(expressions.short_bigram.is_some());
        let trigram = expressions
            .trigram
            .as_deref()
            .unwrap_or(r#""executorsearchnomatchsentinel""#);
        let short_bigram = expressions.short_bigram.as_deref().unwrap_or(r#""g2ffff""#);
        let tools = sqlx::query_as::<_, ToolSummaryRow>(TOOL_SEARCH_CANDIDATES)
            .bind(expressions.word)
            .bind(trigram)
            .bind(short_bigram)
            .bind(expressions.short_unigram)
            .bind(namespace_prefix.as_deref())
            .bind(namespace_prefix.as_deref())
            .bind(namespace_like.as_deref())
            .bind(MAX_SEARCH_CANDIDATES)
            .bind(trigram_enabled)
            .bind(short_bigram_enabled)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(ToolSummary::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(search::search(
            &tools,
            query,
            namespace,
            page_limit(limit),
            usize::try_from(offset).unwrap_or(usize::MAX),
        ))
    }

    pub async fn describe_tool(&self, path: &str) -> Result<DescribedTool, CatalogError> {
        let tool = self.gateway_tool_by_path(path).await?;
        let mut definitions = tool.typescript_definitions.clone();
        definitions.insert("ToolError".to_owned(), TOOL_ERROR_TYPESCRIPT.to_owned());
        definitions.insert(
            "ToolHttpMeta".to_owned(),
            TOOL_HTTP_META_TYPESCRIPT.to_owned(),
        );
        definitions.insert("ToolFile".to_owned(), TOOL_FILE_TYPESCRIPT.to_owned());
        let output = tool.output_typescript.as_deref().unwrap_or("unknown");
        Ok(DescribedTool {
            path: path.to_owned(),
            name: tool.local_name,
            description: tool.description,
            input_typescript: tool.input_typescript,
            output_typescript: Some(format!(
                "{{ ok: true; data: {output}; http?: ToolHttpMeta }} | {{ ok: false; error: ToolError }}"
            )),
            type_script_definitions: definitions,
            input_schema: tool.input_schema,
            output_schema: tool.output_schema,
            effective_mode: tool.effective_mode,
        })
    }

    pub async fn guard_invocation(&self, path: &str) -> Result<InvocationLookup, CatalogError> {
        let tool =
            self.tool_summary_by_path(path)
                .await?
                .ok_or_else(|| CatalogError::ToolNotFound {
                    path: normalize_sandbox_path(path),
                })?;
        if !tool.present {
            return Err(CatalogError::ToolNotFound {
                path: normalize_sandbox_path(path),
            });
        }
        if tool.effective_mode.mode == ToolMode::Disabled {
            return Err(CatalogError::ToolDisabled {
                path: tool.sandbox_path,
            });
        }
        let source_display_name = self.source(&tool.source_id).await?.display_name;
        Ok(InvocationLookup {
            tool_id: tool.id,
            source_id: tool.source_id,
            source_display_name,
            tool_display_name: tool.display_name,
            callable_path: tool.callable_path,
            sandbox_path: tool.sandbox_path,
            effective_mode: tool.effective_mode.mode,
            mode_provenance: tool.effective_mode.provenance,
            requires_approval: tool.effective_mode.mode == ToolMode::Ask,
        })
    }

    pub async fn prepare_invocation(&self, path: &str) -> Result<InvocationLease, CatalogError> {
        let Some((source_slug, local_name)) = parse_tool_path(path) else {
            return Err(CatalogError::ToolNotFound {
                path: normalize_sandbox_path(path),
            });
        };
        let guard = self.mutation_lock.clone().read_owned().await;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query_as::<_, InvocationRow>(INVOCATION_SELECT_BY_PATH)
            .bind(source_slug)
            .bind(local_name)
            .fetch_optional(&mut *transaction)
            .await?;
        transaction.commit().await?;
        let row = row.ok_or_else(|| CatalogError::ToolNotFound {
            path: normalize_sandbox_path(path),
        })?;
        self.invocation_lease(row, guard)
    }

    /// Resolves policy and validates the stored input schema without decrypting source credentials.
    ///
    /// Ask-mode callers must use this snapshot before creating an approval. The read guard keeps
    /// the revision token coherent only for the duration of preflight and must not be retained while
    /// an approval is pending.
    pub async fn preflight_invocation(
        &self,
        path: &str,
    ) -> Result<InvocationPreflight, CatalogError> {
        let Some((source_slug, local_name)) = parse_tool_path(path) else {
            return Err(CatalogError::ToolNotFound {
                path: normalize_sandbox_path(path),
            });
        };
        let guard = self.mutation_lock.clone().read_owned().await;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query_as::<_, InvocationRow>(INVOCATION_SELECT_BY_PATH)
            .bind(source_slug)
            .bind(local_name)
            .fetch_optional(&mut *transaction)
            .await?;
        transaction.commit().await?;
        let row = row.ok_or_else(|| CatalogError::ToolNotFound {
            path: normalize_sandbox_path(path),
        })?;
        Self::invocation_preflight(row, guard)
    }

    pub async fn revalidate_invocation(
        &self,
        token: &InvocationRevisionToken,
    ) -> Result<Option<InvocationLease>, CatalogError> {
        let guard = self.mutation_lock.clone().read_owned().await;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query_as::<_, InvocationRow>(INVOCATION_SELECT_BY_REVISION)
            .bind(&token.tool_id)
            .bind(&token.source_id)
            .bind(token.source_revision)
            .bind(token.catalog_revision)
            .bind(token.tool_revision)
            .bind(token.binding_revision)
            .bind(token.credential_revision)
            .fetch_optional(&mut *transaction)
            .await?;
        transaction.commit().await?;
        row.map(|row| self.invocation_lease(row, guard)).transpose()
    }

    fn invocation_lease(
        &self,
        row: InvocationRow,
        guard: tokio::sync::OwnedRwLockReadGuard<()>,
    ) -> Result<InvocationLease, CatalogError> {
        let sandbox_path = format!("{}.{}", row.source_slug, row.local_name);
        if row.present == 0 {
            return Err(CatalogError::ToolNotFound { path: sandbox_path });
        }
        let effective_mode = effective_mode(
            ToolMode::from_str(&row.intrinsic_mode)?,
            parse_optional_mode(row.source_mode_override)?,
            parse_optional_mode(row.tool_mode_override)?,
        );
        let mode = effective_mode.mode;
        if mode == ToolMode::Disabled {
            return Err(CatalogError::ToolDisabled { path: sandbox_path });
        }
        let binding_protocol = row
            .binding_protocol
            .as_deref()
            .ok_or(CatalogError::CorruptData("active tool binding missing"))?;
        let binding_version = row
            .binding_version
            .ok_or(CatalogError::CorruptData("active tool binding missing"))?;
        let definition_json = row
            .definition_json
            .as_deref()
            .ok_or(CatalogError::CorruptData("active tool binding missing"))?;
        let binding_revision = row
            .binding_revision
            .ok_or(CatalogError::CorruptData("active tool binding missing"))?;
        let binding = ToolBinding::decode(binding_protocol, binding_version, definition_json)?;
        let source_kind = SourceKind::from_str(&row.source_kind)?;
        if !matches!(
            (&binding, source_kind),
            (ToolBinding::OpenapiV1(_), SourceKind::Openapi)
        ) {
            return Err(CatalogError::CorruptData(
                "tool binding does not match source kind",
            ));
        }
        let credential = match (
            row.credential_schema_version,
            row.credential_ciphertext,
            row.credential_revision,
        ) {
            (Some(schema_version), Some(ciphertext), Some(revision)) => {
                let plaintext =
                    self.keyring
                        .decrypt(CREDENTIAL_PURPOSE, &row.source_id, &ciphertext)?;
                Some(StoredCredential {
                    revision,
                    credential: CredentialPayload {
                        schema_version: u32::try_from(schema_version)
                            .map_err(|_| CatalogError::CorruptData("credential schema version"))?,
                        payload: serde_json::from_slice(&plaintext)?,
                    },
                })
            }
            (None, None, None) => None,
            _ => return Err(CatalogError::CorruptData("incomplete source credential")),
        };
        let callable_path = format!("tools.{sandbox_path}");
        let lookup = InvocationLookup {
            tool_id: row.tool_id.clone(),
            source_id: row.source_id.clone(),
            source_display_name: row.source_display_name,
            tool_display_name: row.tool_display_name,
            callable_path,
            sandbox_path,
            effective_mode: mode,
            mode_provenance: effective_mode.provenance,
            requires_approval: mode == ToolMode::Ask,
        };
        if row.input_schema_json.len() > MAX_SCHEMA_BYTES {
            return Err(CatalogError::CorruptData("tool input schema is too large"));
        }
        let input_schema: Value = serde_json::from_str(&row.input_schema_json)?;
        let input_validator = super::schema::compile(&input_schema)
            .map_err(|()| CatalogError::CorruptData("tool input schema is invalid"))?;
        Ok(InvocationLease {
            revisions: InvocationRevisionToken {
                source_id: row.source_id,
                tool_id: row.tool_id,
                source_revision: row.source_revision,
                catalog_revision: row.catalog_revision,
                tool_revision: row.tool_revision,
                binding_revision,
                credential_revision: row.credential_revision,
            },
            lookup,
            source_kind,
            binding,
            input_schema,
            input_validator,
            source_configuration: serde_json::from_str(&row.configuration_json)?,
            credential,
            _guard: guard,
        })
    }

    fn invocation_preflight(
        row: InvocationRow,
        guard: tokio::sync::OwnedRwLockReadGuard<()>,
    ) -> Result<InvocationPreflight, CatalogError> {
        let sandbox_path = format!("{}.{}", row.source_slug, row.local_name);
        if row.present == 0 {
            return Err(CatalogError::ToolNotFound { path: sandbox_path });
        }
        let effective_mode = effective_mode(
            ToolMode::from_str(&row.intrinsic_mode)?,
            parse_optional_mode(row.source_mode_override)?,
            parse_optional_mode(row.tool_mode_override)?,
        );
        let mode = effective_mode.mode;
        if mode == ToolMode::Disabled {
            return Err(CatalogError::ToolDisabled { path: sandbox_path });
        }
        let binding_protocol = row
            .binding_protocol
            .as_deref()
            .ok_or(CatalogError::CorruptData("active tool binding missing"))?;
        let binding_version = row
            .binding_version
            .ok_or(CatalogError::CorruptData("active tool binding missing"))?;
        let definition_json = row
            .definition_json
            .as_deref()
            .ok_or(CatalogError::CorruptData("active tool binding missing"))?;
        let binding_revision = row
            .binding_revision
            .ok_or(CatalogError::CorruptData("active tool binding missing"))?;
        let binding = ToolBinding::decode(binding_protocol, binding_version, definition_json)?;
        if !matches!(
            (&binding, SourceKind::from_str(&row.source_kind)?),
            (ToolBinding::OpenapiV1(_), SourceKind::Openapi)
        ) {
            return Err(CatalogError::CorruptData(
                "tool binding does not match source kind",
            ));
        }
        if row.input_schema_json.len() > MAX_SCHEMA_BYTES {
            return Err(CatalogError::CorruptData("tool input schema is too large"));
        }
        let input_schema: Value = serde_json::from_str(&row.input_schema_json)?;
        let input_validator = super::schema::compile(&input_schema)
            .map_err(|()| CatalogError::CorruptData("tool input schema is invalid"))?;
        Ok(InvocationPreflight {
            revisions: InvocationRevisionToken {
                source_id: row.source_id.clone(),
                tool_id: row.tool_id.clone(),
                source_revision: row.source_revision,
                catalog_revision: row.catalog_revision,
                tool_revision: row.tool_revision,
                binding_revision,
                credential_revision: row.credential_revision,
            },
            lookup: InvocationLookup {
                tool_id: row.tool_id,
                source_id: row.source_id,
                source_display_name: row.source_display_name,
                tool_display_name: row.tool_display_name,
                callable_path: format!("tools.{sandbox_path}"),
                sandbox_path,
                effective_mode: mode,
                mode_provenance: effective_mode.provenance,
                requires_approval: mode == ToolMode::Ask,
            },
            input_schema,
            input_validator,
            _guard: guard,
        })
    }

    pub async fn record_request(&self, log: NewRequestLog) -> Result<(), CatalogError> {
        let duration_ms = i64::try_from(log.duration_ms).map_err(|_| {
            validation(
                "invalid_duration",
                "Request duration is too large to store.",
            )
        })?;
        validate_log_text("request ID", &log.request_id, 128)?;
        validate_optional_log_text("path snapshot", log.path_snapshot.as_deref(), 512)?;
        validate_optional_log_text("error code", log.error_code.as_deref(), 128)?;
        validate_optional_log_text("approval ID", log.approval_id.as_deref(), 128)?;
        if (log.source_id.is_some() || log.tool_id.is_some()) && log.path_snapshot.is_none() {
            return Err(validation(
                "invalid_log_path",
                "Catalog request logs with source or tool IDs require a path snapshot.",
            ));
        }
        let _permit = self
            .request_log_writes
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                validation(
                    "request_log_backpressure",
                    "Request logging is at capacity. The request log was not stored.",
                )
            })?;
        self.persist_request(log, duration_ms).await
    }

    async fn persist_request(
        &self,
        log: NewRequestLog,
        duration_ms: i64,
    ) -> Result<(), CatalogError> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO request_logs \
             (request_id, actor_api_token_id, surface, source_id, tool_id, path_snapshot, \
              outcome, error_code, duration_ms, approval_id, created_at) \
             VALUES (?, \
              (SELECT id FROM api_tokens WHERE id = ?), ?, \
              (SELECT id FROM sources WHERE id = ?), \
              (SELECT id FROM tools WHERE id = ?), ?, ?, ?, ?, ?, ?)",
        )
        .bind(log.request_id)
        .bind(log.actor_api_token_id)
        .bind(log.surface.as_str())
        .bind(log.source_id)
        .bind(log.tool_id)
        .bind(log.path_snapshot)
        .bind(log.outcome.as_str())
        .bind(log.error_code)
        .bind(duration_ms)
        .bind(log.approval_id)
        .bind(log.created_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM request_logs WHERE request_id IN ( \
             SELECT request_id FROM request_logs \
             ORDER BY created_at DESC, request_id DESC LIMIT -1 OFFSET ?)",
        )
        .bind(MAX_REQUEST_LOG_ROWS)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn request_log(&self, request_id: &str) -> Result<RequestLogRecord, CatalogError> {
        sqlx::query_as::<_, RequestLogRow>(REQUEST_LOG_SELECT_BY_ID)
            .bind(request_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(CatalogError::NotFound {
                entity: "request log",
            })?
            .try_into()
    }

    pub async fn list_request_logs(
        &self,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<RequestLogPage, CatalogError> {
        let limit = page_limit(limit);
        let cursor = cursor.map(decode_cursor).transpose()?;
        let mut rows = if let Some((created_at, request_id)) = cursor {
            sqlx::query_as::<_, RequestLogRow>(
                "SELECT request_id, actor_api_token_id, surface, source_id, tool_id, \
                 path_snapshot, outcome, error_code, duration_ms, approval_id, created_at \
                 FROM request_logs WHERE created_at < ? OR (created_at = ? AND request_id < ?) \
                 ORDER BY created_at DESC, request_id DESC LIMIT ?",
            )
            .bind(created_at)
            .bind(created_at)
            .bind(request_id)
            .bind(i64::try_from(limit + 1).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, RequestLogRow>(
                "SELECT request_id, actor_api_token_id, surface, source_id, tool_id, \
                 path_snapshot, outcome, error_code, duration_ms, approval_id, created_at \
                 FROM request_logs ORDER BY created_at DESC, request_id DESC LIMIT ?",
            )
            .bind(i64::try_from(limit + 1).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await?
        };
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = has_more.then(|| {
            let last = rows.last().expect("a page with more rows is not empty");
            encode_cursor(last.created_at, &last.request_id)
        });
        Ok(RequestLogPage {
            items: rows
                .into_iter()
                .map(RequestLogRecord::try_from)
                .collect::<Result<_, _>>()?,
            next_cursor,
        })
    }

    async fn tool_by_path(&self, path: &str) -> Result<Option<ToolRecord>, CatalogError> {
        let Some((source_slug, local_name)) = parse_tool_path(path) else {
            return Ok(None);
        };
        sqlx::query_as::<_, ToolRow>(TOOL_SELECT_BY_PATH)
            .bind(source_slug)
            .bind(local_name)
            .fetch_optional(&self.pool)
            .await?
            .map(ToolRecord::try_from)
            .transpose()
    }

    async fn tool_summary_by_path(&self, path: &str) -> Result<Option<ToolSummary>, CatalogError> {
        let Some((source_slug, local_name)) = parse_tool_path(path) else {
            return Ok(None);
        };
        sqlx::query_as::<_, ToolSummaryRow>(TOOL_SUMMARY_SELECT_BY_PATH)
            .bind(source_slug)
            .bind(local_name)
            .fetch_optional(&self.pool)
            .await?
            .map(ToolSummary::try_from)
            .transpose()
    }

    async fn gateway_tool_by_path(&self, path: &str) -> Result<ToolRecord, CatalogError> {
        let tool = self
            .tool_by_path(path)
            .await?
            .ok_or_else(|| CatalogError::ToolNotFound {
                path: normalize_sandbox_path(path),
            })?;
        if !tool.present || tool.effective_mode.mode == ToolMode::Disabled {
            return Err(CatalogError::ToolNotFound {
                path: normalize_sandbox_path(path),
            });
        }
        Ok(tool)
    }
}

impl TryFrom<SourceRow> for SourceRecord {
    type Error = CatalogError;

    fn try_from(row: SourceRow) -> Result<Self, Self::Error> {
        let configuration = serde_json::from_str::<Map<String, Value>>(&row.configuration_json)?;
        Ok(Self {
            id: row.id,
            kind: SourceKind::from_str(&row.kind)?,
            slug: row.slug,
            display_name: row.display_name,
            description: row.description,
            configuration,
            mode_override: parse_optional_mode(row.mode_override)?,
            health_status: SourceHealth::from_str(&row.health_status)?,
            health_error_code: row.health_error_code,
            revision: row.revision,
            catalog_revision: row.catalog_revision,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_refreshed_at: row.last_refreshed_at,
            tool_count: row.tool_count,
            tombstoned_tool_count: row.tombstoned_tool_count,
        })
    }
}

impl TryFrom<ToolRow> for ToolRecord {
    type Error = CatalogError;

    fn try_from(row: ToolRow) -> Result<Self, Self::Error> {
        let intrinsic_mode = ToolMode::from_str(&row.intrinsic_mode)?;
        let source_override = parse_optional_mode(row.source_mode_override)?;
        let mode_override = parse_optional_mode(row.mode_override)?;
        let effective_mode = effective_mode(intrinsic_mode, source_override, mode_override);
        let sandbox_path = format!("{}.{}", row.source_slug, row.local_name);
        let callable_path = format!("tools.{sandbox_path}");
        Ok(Self {
            id: row.id,
            source_id: row.source_id,
            source_slug: row.source_slug,
            stable_key: row.stable_key,
            local_name: row.local_name,
            callable_path,
            sandbox_path,
            display_name: row.display_name,
            description: row.description,
            input_schema: serde_json::from_str(&row.input_schema_json)?,
            output_schema: row
                .output_schema_json
                .map(|json| serde_json::from_str(&json))
                .transpose()?,
            input_typescript: row.input_typescript,
            output_typescript: row.output_typescript,
            typescript_definitions: serde_json::from_str(&row.typescript_definitions_json)?,
            intrinsic_mode,
            mode_override,
            effective_mode,
            present: row.present != 0,
            revision: row.revision,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_seen_at: row.last_seen_at,
            tombstoned_at: row.tombstoned_at,
        })
    }
}

impl TryFrom<ToolSummaryRow> for ToolSummary {
    type Error = CatalogError;

    fn try_from(row: ToolSummaryRow) -> Result<Self, Self::Error> {
        let intrinsic_mode = ToolMode::from_str(&row.intrinsic_mode)?;
        let source_override = parse_optional_mode(row.source_mode_override)?;
        let mode_override = parse_optional_mode(row.mode_override)?;
        let effective_mode = effective_mode(intrinsic_mode, source_override, mode_override);
        let sandbox_path = format!("{}.{}", row.source_slug, row.local_name);
        let callable_path = format!("tools.{sandbox_path}");
        Ok(Self {
            id: row.id,
            source_id: row.source_id,
            source_slug: row.source_slug,
            stable_key: row.stable_key,
            local_name: row.local_name,
            callable_path,
            sandbox_path,
            display_name: row.display_name,
            description: row.description,
            intrinsic_mode,
            mode_override,
            effective_mode,
            present: row.present != 0,
            revision: row.revision,
            created_at: row.created_at,
            updated_at: row.updated_at,
            last_seen_at: row.last_seen_at,
            tombstoned_at: row.tombstoned_at,
        })
    }
}

impl TryFrom<RequestLogRow> for RequestLogRecord {
    type Error = CatalogError;

    fn try_from(row: RequestLogRow) -> Result<Self, Self::Error> {
        Ok(Self {
            request_id: row.request_id,
            actor_api_token_id: row.actor_api_token_id,
            surface: RequestSurface::from_str(&row.surface)?,
            source_id: row.source_id,
            tool_id: row.tool_id,
            path_snapshot: row.path_snapshot,
            outcome: RequestOutcome::from_str(&row.outcome)?,
            error_code: row.error_code,
            duration_ms: row.duration_ms,
            approval_id: row.approval_id,
            created_at: row.created_at,
        })
    }
}

const SOURCE_SELECT_ALL: &str = "SELECT sources.id, sources.kind, sources.slug, sources.display_name, sources.description, \
     sources.configuration_json, sources.mode_override, sources.health_status, \
     sources.health_error_code, sources.revision, sources.catalog_revision, \
     sources.created_at, sources.updated_at, sources.last_refreshed_at, \
     (SELECT COUNT(*) FROM tools WHERE tools.source_id = sources.id AND tools.present = 1) AS tool_count, \
     (SELECT COUNT(*) FROM tools WHERE tools.source_id = sources.id AND tools.present = 0) AS tombstoned_tool_count \
     FROM sources ORDER BY sources.slug, sources.id";

const SOURCE_SELECT_BY_ID: &str = "SELECT sources.id, sources.kind, sources.slug, sources.display_name, sources.description, \
     sources.configuration_json, sources.mode_override, sources.health_status, \
     sources.health_error_code, sources.revision, sources.catalog_revision, \
     sources.created_at, sources.updated_at, sources.last_refreshed_at, \
     (SELECT COUNT(*) FROM tools WHERE tools.source_id = sources.id AND tools.present = 1) AS tool_count, \
     (SELECT COUNT(*) FROM tools WHERE tools.source_id = sources.id AND tools.present = 0) AS tombstoned_tool_count \
     FROM sources WHERE sources.id = ?";

const TOOL_SELECT_BY_ID: &str = "SELECT tools.id, tools.source_id, sources.slug AS source_slug, \
     sources.mode_override AS source_mode_override, tools.stable_key, tools.local_name, \
     tools.display_name, tools.description, tools.input_schema_json, tools.output_schema_json, \
     tools.input_typescript, tools.output_typescript, tools.typescript_definitions_json, \
     tools.intrinsic_mode, tools.mode_override, tools.present, tools.revision, \
     tools.created_at, tools.updated_at, tools.last_seen_at, tools.tombstoned_at \
     FROM tools JOIN sources ON sources.id = tools.source_id WHERE tools.id = ?";

const TOOL_SELECT_BY_PATH: &str = "SELECT tools.id, tools.source_id, sources.slug AS source_slug, \
     sources.mode_override AS source_mode_override, tools.stable_key, tools.local_name, \
     tools.display_name, tools.description, tools.input_schema_json, tools.output_schema_json, \
     tools.input_typescript, tools.output_typescript, tools.typescript_definitions_json, \
     tools.intrinsic_mode, tools.mode_override, tools.present, tools.revision, \
     tools.created_at, tools.updated_at, tools.last_seen_at, tools.tombstoned_at \
     FROM tools JOIN sources ON sources.id = tools.source_id \
     WHERE sources.slug = ? AND tools.local_name = ?";

const TOOL_LIST_COUNT: &str = "SELECT COUNT(*) FROM tools \
     JOIN sources ON sources.id = tools.source_id \
     WHERE (? = 1 OR tools.present = 1) \
       AND (? IS NULL OR tools.source_id = ?) \
       AND (? IS NULL OR coalesce(tools.mode_override, sources.mode_override, tools.intrinsic_mode) = ?) \
       AND NOT EXISTS ( \
         SELECT 1 FROM json_each(?) AS query_tokens \
         WHERE instr(lower( \
           'tools.' || sources.slug || '.' || tools.local_name || ' ' || tools.display_name || ' ' || \
           tools.stable_key || ' ' || coalesce(tools.description, '') || ' ' || sources.slug \
         ), CAST(query_tokens.value AS TEXT)) = 0)";

const TOOL_LIST_PAGE: &str = "SELECT tools.id, tools.source_id, sources.slug AS source_slug, \
     sources.mode_override AS source_mode_override, tools.stable_key, tools.local_name, \
     tools.display_name, tools.description, tools.intrinsic_mode, tools.mode_override, \
     tools.present, tools.revision, tools.created_at, tools.updated_at, \
     tools.last_seen_at, tools.tombstoned_at \
     FROM tools JOIN sources ON sources.id = tools.source_id \
     WHERE (? = 1 OR tools.present = 1) \
       AND (? IS NULL OR tools.source_id = ?) \
       AND (? IS NULL OR coalesce(tools.mode_override, sources.mode_override, tools.intrinsic_mode) = ?) \
       AND NOT EXISTS ( \
         SELECT 1 FROM json_each(?) AS query_tokens \
         WHERE instr(lower( \
           'tools.' || sources.slug || '.' || tools.local_name || ' ' || tools.display_name || ' ' || \
           tools.stable_key || ' ' || coalesce(tools.description, '') || ' ' || sources.slug \
         ), CAST(query_tokens.value AS TEXT)) = 0) \
     ORDER BY sources.slug, tools.local_name, tools.id LIMIT ? OFFSET ?";

const TOOL_SEARCH_CANDIDATES: &str = "WITH ranked_candidates AS ( \
       SELECT * FROM ( \
         SELECT tools.id AS tool_id, 0 AS priority, \
                bm25(tool_search, 0.0, 0.0, 8.0, 10.0, 5.0, 12.0) AS relevance \
         FROM tool_search JOIN tools ON tools.id = tool_search.tool_id \
         JOIN sources ON sources.id = tools.source_id \
         WHERE tool_search MATCH ?1 AND tools.present = 1 \
           AND coalesce(tools.mode_override, sources.mode_override, tools.intrinsic_mode) <> 'disabled' \
           AND (?5 IS NULL OR ( \
             replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') = ?6 \
             OR replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') LIKE ?7)) \
         ORDER BY relevance, tools.id LIMIT ?8) \
       UNION ALL \
       SELECT * FROM ( \
         SELECT tools.id AS tool_id, 1 AS priority, \
                bm25(tool_search_trigram, 0.0, 0.0, 8.0, 10.0, 5.0, 12.0) AS relevance \
         FROM tool_search_trigram JOIN tools ON tools.id = tool_search_trigram.tool_id \
         JOIN sources ON sources.id = tools.source_id \
         WHERE ?9 = 1 AND tool_search_trigram MATCH ?2 AND tools.present = 1 \
           AND coalesce(tools.mode_override, sources.mode_override, tools.intrinsic_mode) <> 'disabled' \
           AND (?5 IS NULL OR ( \
             replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') = ?6 \
             OR replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') LIKE ?7)) \
         ORDER BY relevance, tools.id LIMIT ?8) \
       UNION ALL \
       SELECT * FROM ( \
         SELECT tools.id AS tool_id, 2 AS priority, \
                bm25(tool_search_short, 0.0, 0.0, 1.0) AS relevance \
         FROM tool_search_short JOIN tools ON tools.id = tool_search_short.tool_id \
         JOIN sources ON sources.id = tools.source_id \
         WHERE ?10 = 1 AND tool_search_short MATCH ?3 AND tools.present = 1 \
           AND coalesce(tools.mode_override, sources.mode_override, tools.intrinsic_mode) <> 'disabled' \
           AND (?5 IS NULL OR ( \
             replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') = ?6 \
             OR replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') LIKE ?7)) \
         ORDER BY relevance, tools.id LIMIT ?8) \
       UNION ALL \
       SELECT * FROM ( \
         SELECT tools.id AS tool_id, 3 AS priority, \
                bm25(tool_search_short, 0.0, 0.0, 1.0) AS relevance \
         FROM tool_search_short JOIN tools ON tools.id = tool_search_short.tool_id \
         JOIN sources ON sources.id = tools.source_id \
         WHERE tool_search_short MATCH ?4 AND tools.present = 1 \
           AND coalesce(tools.mode_override, sources.mode_override, tools.intrinsic_mode) <> 'disabled' \
           AND (?5 IS NULL OR ( \
             replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') = ?6 \
             OR replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') LIKE ?7)) \
         ORDER BY relevance, tools.id LIMIT ?8) \
     ), best_priority AS ( \
       SELECT tool_id, min(priority) AS priority FROM ranked_candidates GROUP BY tool_id \
     ), deduped AS ( \
       SELECT ranked.tool_id, ranked.priority, min(ranked.relevance) AS relevance \
       FROM ranked_candidates AS ranked \
       JOIN best_priority AS best \
         ON best.tool_id = ranked.tool_id AND best.priority = ranked.priority \
       GROUP BY ranked.tool_id, ranked.priority \
     ), candidates AS ( \
       SELECT tool_id, priority, relevance FROM deduped \
       ORDER BY priority, relevance, tool_id LIMIT ?8 \
     ) \
     SELECT tools.id, tools.source_id, sources.slug AS source_slug, \
            sources.mode_override AS source_mode_override, tools.stable_key, tools.local_name, \
            tools.display_name, tools.description, tools.intrinsic_mode, tools.mode_override, \
            tools.present, tools.revision, tools.created_at, tools.updated_at, \
            tools.last_seen_at, tools.tombstoned_at \
     FROM candidates JOIN tools ON tools.id = candidates.tool_id \
     JOIN sources ON sources.id = tools.source_id \
     ORDER BY candidates.priority, candidates.relevance, sources.slug, tools.local_name, tools.id";

const TOOL_SUMMARY_SELECT_BY_PATH: &str = "SELECT tools.id, tools.source_id, sources.slug AS source_slug, \
     sources.mode_override AS source_mode_override, tools.stable_key, tools.local_name, \
     tools.display_name, tools.description, tools.intrinsic_mode, tools.mode_override, \
     tools.present, tools.revision, tools.created_at, tools.updated_at, \
     tools.last_seen_at, tools.tombstoned_at \
     FROM tools JOIN sources ON sources.id = tools.source_id \
     WHERE sources.slug = ? AND tools.local_name = ?";

const INVOCATION_SELECT_BY_PATH: &str = "SELECT tools.id AS tool_id, tools.source_id, \
     sources.display_name AS source_display_name, tools.display_name AS tool_display_name, \
     sources.kind AS source_kind, sources.slug AS source_slug, tools.local_name, \
     tools.present, tools.intrinsic_mode, \
     tools.mode_override AS tool_mode_override, sources.mode_override AS source_mode_override, \
     tools.revision AS tool_revision, sources.revision AS source_revision, \
     sources.catalog_revision, sources.configuration_json, tools.input_schema_json, \
     tool_bindings.protocol AS binding_protocol, tool_bindings.binding_version, \
     tool_bindings.definition_json, tool_bindings.revision AS binding_revision, \
     source_credentials.schema_version AS credential_schema_version, \
     source_credentials.payload_ciphertext AS credential_ciphertext, \
     source_credentials.revision AS credential_revision \
     FROM tools JOIN sources ON sources.id = tools.source_id \
     LEFT JOIN tool_bindings ON tool_bindings.tool_id = tools.id \
     LEFT JOIN source_credentials ON source_credentials.source_id = sources.id \
     WHERE sources.slug = ? AND tools.local_name = ?";

const INVOCATION_SELECT_BY_REVISION: &str = "SELECT tools.id AS tool_id, tools.source_id, \
     sources.display_name AS source_display_name, tools.display_name AS tool_display_name, \
     sources.kind AS source_kind, sources.slug AS source_slug, tools.local_name, \
     tools.present, tools.intrinsic_mode, \
     tools.mode_override AS tool_mode_override, sources.mode_override AS source_mode_override, \
     tools.revision AS tool_revision, sources.revision AS source_revision, \
     sources.catalog_revision, sources.configuration_json, tools.input_schema_json, \
     tool_bindings.protocol AS binding_protocol, tool_bindings.binding_version, \
     tool_bindings.definition_json, tool_bindings.revision AS binding_revision, \
     source_credentials.schema_version AS credential_schema_version, \
     source_credentials.payload_ciphertext AS credential_ciphertext, \
     source_credentials.revision AS credential_revision \
     FROM tools JOIN sources ON sources.id = tools.source_id \
     JOIN tool_bindings ON tool_bindings.tool_id = tools.id \
     LEFT JOIN source_credentials ON source_credentials.source_id = sources.id \
     WHERE tools.id = ? AND tools.source_id = ? AND tools.present = 1 \
       AND sources.revision = ? AND sources.catalog_revision = ? \
       AND tools.revision = ? AND tool_bindings.revision = ? \
       AND source_credentials.revision IS ?";

const REQUEST_LOG_SELECT_BY_ID: &str = "SELECT request_id, actor_api_token_id, surface, source_id, tool_id, path_snapshot, \
     outcome, error_code, duration_ms, approval_id, created_at \
     FROM request_logs WHERE request_id = ?";

fn prepare_snapshot_and_bindings(
    snapshot: CatalogSnapshot,
    bindings: Vec<StagedToolBinding>,
) -> Result<(PreparedSnapshot, PreparedToolBindings), CatalogError> {
    prepare_snapshot_and_bindings_with_limits(snapshot, bindings, PayloadLimits::default())
}

fn prepare_initial_snapshot_and_bindings(
    snapshot: InitialCatalogSnapshot,
    bindings: Vec<StagedToolBinding>,
) -> Result<(PreparedSnapshot, PreparedToolBindings), CatalogError> {
    let prepared = prepare_catalog_content_with_limits(
        snapshot.artifacts,
        snapshot.tools,
        PayloadLimits::default(),
    )?;
    let prepared_bindings = prepare_tool_bindings_with_limits(
        bindings,
        PayloadLimits::default(),
        prepared.payload_bytes,
    )?;
    Ok((prepared, prepared_bindings))
}

fn prepare_snapshot_and_bindings_with_limits(
    snapshot: CatalogSnapshot,
    bindings: Vec<StagedToolBinding>,
    limits: PayloadLimits,
) -> Result<(PreparedSnapshot, PreparedToolBindings), CatalogError> {
    let prepared = prepare_snapshot_with_limits(snapshot, limits)?;
    let prepared_bindings =
        prepare_tool_bindings_with_limits(bindings, limits, prepared.payload_bytes)?;
    Ok((prepared, prepared_bindings))
}

#[cfg(test)]
fn prepare_tool_bindings(
    bindings: Vec<StagedToolBinding>,
) -> Result<PreparedToolBindings, CatalogError> {
    prepare_tool_bindings_with_limits(bindings, PayloadLimits::default(), 0)
}

fn prepare_tool_bindings_with_limits(
    bindings: Vec<StagedToolBinding>,
    limits: PayloadLimits,
    initial_payload_bytes: usize,
) -> Result<PreparedToolBindings, CatalogError> {
    let mut prepared = Vec::with_capacity(bindings.len());
    let mut seen = HashSet::with_capacity(bindings.len());
    let mut total_bytes = initial_payload_bytes;
    for binding in bindings {
        let stable_key = validate_stable_text(
            "invalid_stable_key",
            "Tool stable keys must contain between 1 and 1024 characters.",
            &binding.stable_key,
            1024,
        )?;
        if !seen.insert(stable_key.clone()) {
            return Err(validation(
                "duplicate_tool_binding",
                "A staged catalog contains the same tool binding more than once.",
            ));
        }
        let definition_json = match &binding.binding {
            ToolBinding::OpenapiV1(binding) => {
                if binding.version != 1 {
                    return Err(validation(
                        "invalid_tool_binding",
                        "The OpenAPI tool binding version is not supported.",
                    ));
                }
                serde_json::to_string(binding)?
            }
        };
        if definition_json.len() > limits.schema {
            return Err(validation(
                "tool_binding_too_large",
                "A tool binding exceeds the serialized-size limit.",
            ));
        }
        total_bytes = total_bytes
            .checked_add(definition_json.len())
            .filter(|size| *size <= limits.aggregate)
            .ok_or_else(|| {
                validation(
                    "catalog_payload_too_large",
                    "The staged tool bindings exceed the aggregate size limit.",
                )
            })?;
        prepared.push(PreparedToolBinding {
            stable_key,
            protocol: binding.binding.protocol(),
            version: binding.binding.version(),
            definition_json,
        });
    }
    Ok(prepared)
}

fn prepare_snapshot_with_limits(
    snapshot: CatalogSnapshot,
    limits: PayloadLimits,
) -> Result<PreparedSnapshot, CatalogError> {
    prepare_catalog_content_with_limits(snapshot.artifacts, snapshot.tools, limits)
}

fn prepare_catalog_content_with_limits(
    staged_artifacts: Vec<super::StagedArtifact>,
    staged_tools: Vec<super::StagedTool>,
    limits: PayloadLimits,
) -> Result<PreparedSnapshot, CatalogError> {
    if staged_tools.len() > MAX_ACTIVE_TOOLS_PER_SOURCE {
        return Err(validation(
            "catalog_too_large",
            format!(
                "A catalog refresh may contain at most {MAX_ACTIVE_TOOLS_PER_SOURCE} active tools."
            ),
        ));
    }
    validate_artifact_count(staged_artifacts.len(), limits.artifact_count)?;
    let mut budget = PayloadBudget::new(limits);
    let mut artifact_keys = HashSet::with_capacity(staged_artifacts.len());
    let mut artifacts = Vec::with_capacity(staged_artifacts.len());
    for artifact in staged_artifacts {
        let stable_key = validate_stable_text(
            "invalid_artifact_key",
            "Artifact stable keys must contain between 1 and 512 characters.",
            &artifact.stable_key,
            512,
        )?;
        if !artifact_keys.insert((artifact.kind.as_str(), stable_key.clone())) {
            return Err(validation(
                "duplicate_artifact_key",
                "A staged catalog contains the same source artifact more than once.",
            ));
        }
        budget.charge(
            stable_key.len(),
            limits.artifact_key,
            "artifact_key_too_large",
            "A staged artifact key exceeds the byte-size limit.",
        )?;
        budget.charge_aggregate(artifact.kind.as_str().len())?;
        let content_json = serde_json::to_string(&artifact.content)?;
        budget.charge(
            content_json.len(),
            limits.artifact,
            "artifact_too_large",
            "A staged artifact exceeds the serialized-size limit.",
        )?;
        artifacts.push(PreparedArtifact {
            kind: artifact.kind,
            stable_key,
            content_json,
        });
    }
    artifacts.sort_by(|left, right| {
        left.kind
            .as_str()
            .cmp(right.kind.as_str())
            .then_with(|| left.stable_key.cmp(&right.stable_key))
    });

    let mut stable_keys = HashSet::with_capacity(staged_tools.len());
    let mut tools = Vec::with_capacity(staged_tools.len());
    for tool in staged_tools {
        let stable_key = validate_stable_text(
            "invalid_stable_key",
            "Tool stable keys must contain between 1 and 1024 characters.",
            &tool.stable_key,
            1024,
        )?;
        if !stable_keys.insert(stable_key.clone()) {
            return Err(validation(
                "duplicate_stable_key",
                "A staged catalog contains the same stable tool key more than once.",
            ));
        }
        budget.charge(
            stable_key.len(),
            limits.tool_stable_key,
            "tool_key_too_large",
            "A staged tool stable key exceeds the byte-size limit.",
        )?;
        let preferred_name = validate_text(
            "invalid_tool_name",
            "Tool names must contain between 1 and 300 characters.",
            &tool.preferred_name,
            300,
        )?;
        budget.charge(
            preferred_name.len(),
            limits.tool_name,
            "tool_name_too_large",
            "A staged tool name exceeds the byte-size limit.",
        )?;
        let display_name = validate_text(
            "invalid_tool_name",
            "Tool display names must contain between 1 and 300 characters.",
            &tool.display_name,
            300,
        )?;
        budget.charge(
            display_name.len(),
            limits.tool_name,
            "tool_name_too_large",
            "A staged tool name exceeds the byte-size limit.",
        )?;
        let description = validate_optional_text(
            "invalid_tool_description",
            "Tool descriptions may contain at most 4000 characters.",
            tool.description.as_deref(),
            4000,
        )?;
        if let Some(description) = &description {
            budget.charge(
                description.len(),
                limits.tool_description,
                "tool_description_too_large",
                "A staged tool description exceeds the byte-size limit.",
            )?;
        }
        validate_optional_text(
            "invalid_typescript",
            "TypeScript previews may contain at most 100000 characters.",
            tool.input_typescript.as_deref(),
            100_000,
        )?;
        if let Some(input_typescript) = &tool.input_typescript {
            budget.charge(
                input_typescript.len(),
                limits.typescript_preview,
                "typescript_too_large",
                "A staged TypeScript preview exceeds the byte-size limit.",
            )?;
        }
        validate_optional_text(
            "invalid_typescript",
            "TypeScript previews may contain at most 100000 characters.",
            tool.output_typescript.as_deref(),
            100_000,
        )?;
        if let Some(output_typescript) = &tool.output_typescript {
            budget.charge(
                output_typescript.len(),
                limits.typescript_preview,
                "typescript_too_large",
                "A staged TypeScript preview exceeds the byte-size limit.",
            )?;
        }
        let search_description = description
            .as_deref()
            .map(search::normalize_for_index)
            .unwrap_or_default();
        budget.charge(
            search_description.len(),
            limits.search_description,
            "search_description_too_large",
            "A normalized tool description exceeds the byte-size limit.",
        )?;
        let normalized_preferred_name = normalize_tool_name(&preferred_name);
        let search_short_grams =
            search::short_gram_document(&[&normalized_preferred_name, &search_description]);
        budget.charge(
            search_short_grams.len(),
            limits.short_gram_document,
            "search_index_too_large",
            "A staged tool search index exceeds the byte-size limit.",
        )?;
        budget.charge_aggregate(limits.local_name)?;
        budget.charge_aggregate(tool.intrinsic_mode.as_str().len())?;
        let input_schema_json = serde_json::to_string(&tool.input_schema)?;
        budget.charge(
            input_schema_json.len(),
            limits.schema,
            "schema_too_large",
            "A staged tool schema exceeds the serialized-size limit.",
        )?;
        super::schema::compile(&tool.input_schema).map_err(|()| {
            validation(
                "invalid_tool_input_schema",
                "A staged tool input schema is invalid or unsafe.",
            )
        })?;
        let output_schema_json = tool
            .output_schema
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        if let Some(output_schema_json) = &output_schema_json {
            budget.charge(
                output_schema_json.len(),
                limits.schema,
                "schema_too_large",
                "A staged tool schema exceeds the serialized-size limit.",
            )?;
        }
        let typescript_definitions_json = serde_json::to_string(&tool.typescript_definitions)?;
        budget.charge(
            typescript_definitions_json.len(),
            limits.typescript_definitions,
            "typescript_definitions_too_large",
            "Staged TypeScript definitions exceed the serialized-size limit.",
        )?;
        tools.push(PreparedTool {
            stable_key,
            preferred_name,
            display_name,
            search_description,
            search_short_grams,
            description,
            input_schema_json,
            output_schema_json,
            input_typescript: tool.input_typescript,
            output_typescript: tool.output_typescript,
            typescript_definitions_json,
            intrinsic_mode: tool.intrinsic_mode,
        });
    }
    tools.sort_by(|left, right| left.stable_key.cmp(&right.stable_key));
    Ok(PreparedSnapshot {
        tools,
        artifacts,
        payload_bytes: budget.consumed,
    })
}

fn parse_optional_mode(value: Option<String>) -> Result<Option<ToolMode>, CatalogError> {
    value.map(|value| ToolMode::from_str(&value)).transpose()
}

fn normalize_source_slug(value: &str) -> String {
    normalize_identifier(value, "source")
}

fn normalize_tool_name(value: &str) -> String {
    normalize_identifier(value, "tool")
}

fn normalize_identifier(value: &str, fallback: &str) -> String {
    let mut normalized = String::new();
    let mut separator_pending = false;
    let mut previous: Option<char> = None;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            let camel_boundary = character.is_ascii_uppercase()
                && previous.is_some_and(|previous| {
                    previous.is_ascii_lowercase() || previous.is_ascii_digit()
                });
            if (separator_pending || camel_boundary) && !normalized.is_empty() {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
            separator_pending = false;
        } else if !normalized.is_empty() {
            separator_pending = true;
        }
        previous = Some(character);
    }
    if normalized.is_empty() {
        normalized.push_str(fallback);
    }
    if !normalized.starts_with(|character: char| character.is_ascii_lowercase()) {
        normalized.insert_str(0, &format!("{fallback}_"));
    }
    normalized
}

impl PayloadBudget {
    fn new(limits: PayloadLimits) -> Self {
        Self {
            limits,
            consumed: 0,
        }
    }

    fn charge(
        &mut self,
        bytes: usize,
        item_limit: usize,
        item_code: &'static str,
        item_message: &'static str,
    ) -> Result<(), CatalogError> {
        if bytes > item_limit {
            return Err(validation(item_code, item_message));
        }
        self.charge_aggregate(bytes)
    }

    fn charge_aggregate(&mut self, bytes: usize) -> Result<(), CatalogError> {
        self.consumed = self.consumed.checked_add(bytes).ok_or_else(|| {
            validation(
                "catalog_payload_too_large",
                "The staged catalog payload exceeds the aggregate serialized-size limit.",
            )
        })?;
        if self.consumed > self.limits.aggregate {
            return Err(validation(
                "catalog_payload_too_large",
                "The staged catalog payload exceeds the aggregate serialized-size limit.",
            ));
        }
        Ok(())
    }
}

impl NameAllocator {
    fn new(used: HashSet<String>) -> Self {
        Self {
            used,
            next_suffix: HashMap::new(),
            candidate_probes: 0,
        }
    }

    fn allocate(&mut self, base: &str, maximum_length: usize, separator: char) -> String {
        let base = &base[..base.len().min(maximum_length)];
        if self.used.insert(base.to_owned()) {
            return base.to_owned();
        }

        let mut range_start = 2_u64;
        loop {
            let suffix_digits = range_start.ilog10() + 1;
            let range_end = 10_u64
                .checked_pow(suffix_digits)
                .map_or(u64::MAX, |next_power| next_power - 1);
            let prefix_length = maximum_length
                .saturating_sub(1 + suffix_digits as usize)
                .min(base.len());
            let namespace = CollisionNamespace {
                prefix: base[..prefix_length].to_owned(),
                separator,
                suffix_digits,
            };
            let next_suffix = self.next_suffix.entry(namespace).or_insert(range_start);
            while *next_suffix <= range_end {
                let index = *next_suffix;
                *next_suffix = index.saturating_add(1);
                let suffix = format!("{separator}{index}");
                let candidate = format!("{}{suffix}", &base[..prefix_length]);
                self.candidate_probes = self.candidate_probes.saturating_add(1);
                if self.used.insert(candidate.clone()) {
                    return candidate;
                }
            }
            range_start = range_end
                .checked_add(1)
                .expect("the integer suffix space is unbounded for catalog-sized allocations");
        }
    }

    #[cfg(test)]
    fn candidate_probes(&self) -> usize {
        self.candidate_probes
    }
}

fn validate_artifact_count(count: usize, maximum: usize) -> Result<(), CatalogError> {
    if count > maximum {
        Err(validation(
            "catalog_too_many_artifacts",
            format!("A catalog refresh may contain at most {maximum} artifacts."),
        ))
    } else {
        Ok(())
    }
}

fn validate_tool_history(
    existing: &HashMap<String, (String, bool)>,
    staged_keys: &HashSet<String>,
) -> Result<(), CatalogError> {
    let new_unique_count = staged_keys
        .iter()
        .filter(|stable_key| !existing.contains_key(*stable_key))
        .count();
    let projected_history = existing
        .len()
        .checked_add(new_unique_count)
        .ok_or_else(|| {
            validation(
                "catalog_too_large",
                "The source tool history exceeds the supported ceiling.",
            )
        })?;
    let projected_tombstones = existing
        .keys()
        .filter(|stable_key| !staged_keys.contains(*stable_key))
        .count();
    if projected_history > MAX_TOOL_HISTORY_PER_SOURCE
        || projected_tombstones > MAX_TOMBSTONED_TOOLS_PER_SOURCE
    {
        return Err(validation(
            "catalog_too_large",
            format!(
                "A source may retain at most {MAX_ACTIVE_TOOLS_PER_SOURCE} active tools and \
                 {MAX_TOMBSTONED_TOOLS_PER_SOURCE} tombstoned tools. Delete and recreate the \
                 source to intentionally discard retained tool history."
            ),
        ));
    }
    Ok(())
}

fn validate_text(
    code: &'static str,
    message: &'static str,
    value: &str,
    maximum_length: usize,
) -> Result<String, CatalogError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > maximum_length || value.contains('\0') {
        return Err(validation(code, message));
    }
    Ok(value.to_owned())
}

fn validate_stable_text(
    code: &'static str,
    message: &'static str,
    value: &str,
    maximum_length: usize,
) -> Result<String, CatalogError> {
    if value.trim().is_empty() || value.chars().count() > maximum_length || value.contains('\0') {
        return Err(validation(code, message));
    }
    Ok(value.to_owned())
}

fn validate_optional_text(
    code: &'static str,
    message: &'static str,
    value: Option<&str>,
    maximum_length: usize,
) -> Result<Option<String>, CatalogError> {
    value
        .map(|value| {
            if value.chars().count() > maximum_length || value.contains('\0') {
                Err(validation(code, message))
            } else {
                Ok(value.to_owned())
            }
        })
        .transpose()
}

fn validation(code: &'static str, message: impl Into<String>) -> CatalogError {
    CatalogError::Validation {
        code,
        message: message.into(),
    }
}

fn normalize_filter_query(query: &str) -> Vec<String> {
    query
        .to_lowercase()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

fn validate_search_input(label: &str, value: &str) -> Result<(), CatalogError> {
    if value.len() > MAX_SEARCH_QUERY_BYTES || value.chars().count() > MAX_SEARCH_QUERY_CHARACTERS {
        return Err(validation(
            "invalid_search_query",
            format!(
                "The search {label} may contain at most {MAX_SEARCH_QUERY_CHARACTERS} characters \
                 and {MAX_SEARCH_QUERY_BYTES} bytes."
            ),
        ));
    }
    let tokens = search::query_tokens(value);
    if tokens.len() > MAX_SEARCH_QUERY_TOKENS
        || tokens
            .iter()
            .any(|token| token.len() > MAX_SEARCH_TOKEN_BYTES)
    {
        return Err(validation(
            "invalid_search_query",
            format!(
                "The search {label} may contain at most {MAX_SEARCH_QUERY_TOKENS} tokens, with \
                 at most {MAX_SEARCH_TOKEN_BYTES} bytes per token."
            ),
        ));
    }
    Ok(())
}

fn page_limit(limit: u32) -> usize {
    let limit = if limit == 0 {
        DEFAULT_PAGE_LIMIT
    } else {
        limit
    };
    usize::try_from(limit.min(MAX_PAGE_LIMIT)).unwrap_or(MAX_PAGE_LIMIT as usize)
}

fn parse_tool_path(path: &str) -> Option<(&str, &str)> {
    let sandbox_path = path.strip_prefix("tools.").unwrap_or(path);
    let mut segments = sandbox_path.split('.');
    let source = segments.next()?;
    let tool = segments.next()?;
    (!source.is_empty() && !tool.is_empty() && segments.next().is_none()).then_some((source, tool))
}

fn normalize_sandbox_path(path: &str) -> String {
    path.strip_prefix("tools.").unwrap_or(path).to_owned()
}

#[allow(clippy::too_many_arguments)]
async fn finalize_catalog_apply(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    audit: AuditContext<'_>,
    source_id: &str,
    source_path: &str,
    kind: CatalogApplyKind<'_>,
    active_tool_count: usize,
    artifact_count: usize,
    tombstoned_tool_count: usize,
    now: i64,
) -> Result<(i64, i64, i64), CatalogError> {
    let revisions = match kind {
        CatalogApplyKind::Initial { .. } => {
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT revision, catalog_revision FROM sources WHERE id = ?",
            )
            .bind(source_id)
            .fetch_one(&mut **transaction)
            .await?
        }
        CatalogApplyKind::Refresh => {
            sqlx::query_as::<_, (i64, i64)>(
                "UPDATE sources SET revision = revision + 1, \
             catalog_revision = catalog_revision + 1, health_status = 'healthy', \
             health_error_code = NULL, updated_at = ?, last_refreshed_at = ? \
             WHERE id = ? RETURNING revision, catalog_revision",
            )
            .bind(now)
            .bind(now)
            .bind(source_id)
            .fetch_one(&mut **transaction)
            .await?
        }
    };
    let global_revision = bump_global_revision(transaction, now).await?;
    if let CatalogApplyKind::Initial {
        source_kind,
        slug,
        credential_schema_version,
    } = kind
    {
        insert_audit(
            transaction,
            audit,
            "source.created",
            Some(source_id),
            None,
            Some(source_path),
            json!({ "kind": source_kind, "slug": slug }),
            now,
        )
        .await?;
        insert_audit(
            transaction,
            audit,
            "source.credential_changed",
            Some(source_id),
            None,
            Some(source_path),
            json!({ "schemaVersion": credential_schema_version }),
            now,
        )
        .await?;
    }
    insert_audit(
        transaction,
        audit,
        "source.catalog_refreshed",
        Some(source_id),
        None,
        Some(source_path),
        json!({
            "catalogRevision": revisions.1,
            "activeToolCount": active_tool_count,
            "artifactCount": artifact_count,
            "tombstonedToolCount": tombstoned_tool_count,
            "globalRevision": global_revision
        }),
        now,
    )
    .await?;
    Ok((revisions.0, revisions.1, global_revision))
}

async fn apply_artifacts(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    artifacts: &[PreparedArtifact],
    now: i64,
) -> Result<(), CatalogError> {
    let staged_keys = artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.kind.as_str().to_owned(),
                artifact.stable_key.clone(),
            )
        })
        .collect::<HashSet<_>>();
    let existing_keys = sqlx::query_as::<_, (String, String)>(
        "SELECT artifact_kind, stable_key FROM source_artifacts WHERE source_id = ?",
    )
    .bind(source_id)
    .fetch_all(&mut **transaction)
    .await?;
    for artifact in artifacts {
        sqlx::query(
            "INSERT INTO source_artifacts \
             (id, source_id, artifact_kind, stable_key, content_json, revision, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, 0, ?, ?) \
             ON CONFLICT(source_id, artifact_kind, stable_key) DO UPDATE SET \
             content_json = excluded.content_json, revision = source_artifacts.revision + 1, \
             updated_at = excluded.updated_at",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(source_id)
        .bind(artifact.kind.as_str())
        .bind(&artifact.stable_key)
        .bind(&artifact.content_json)
        .bind(now)
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    }
    for (kind, stable_key) in existing_keys {
        if !staged_keys.contains(&(kind.clone(), stable_key.clone())) {
            sqlx::query(
                "DELETE FROM source_artifacts \
                 WHERE source_id = ? AND artifact_kind = ? AND stable_key = ?",
            )
            .bind(source_id)
            .bind(kind)
            .bind(stable_key)
            .execute(&mut **transaction)
            .await?;
        }
    }
    Ok(())
}

async fn apply_tools(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    tools: &[PreparedTool],
    now: i64,
) -> Result<Vec<String>, CatalogError> {
    let existing = sqlx::query_as::<_, (String, String, i64)>(
        "SELECT stable_key, local_name, present FROM tools WHERE source_id = ?",
    )
    .bind(source_id)
    .fetch_all(&mut **transaction)
    .await?;
    let existing_by_key = existing
        .into_iter()
        .map(|(stable_key, local_name, present)| (stable_key, (local_name, present != 0)))
        .collect::<HashMap<_, _>>();
    let staged_keys = tools
        .iter()
        .map(|tool| tool.stable_key.clone())
        .collect::<HashSet<_>>();
    validate_tool_history(&existing_by_key, &staged_keys)?;
    let used_names = existing_by_key
        .values()
        .map(|(local_name, _)| local_name.clone())
        .collect::<HashSet<_>>();
    let mut name_allocator = NameAllocator::new(used_names);
    for tool in tools {
        let local_name = existing_by_key
            .get(&tool.stable_key)
            .map(|(local_name, _)| local_name.clone())
            .unwrap_or_else(|| {
                let base = normalize_tool_name(&tool.preferred_name);
                name_allocator.allocate(&base, 128, '_')
            });
        sqlx::query(
            "INSERT INTO tools \
             (id, source_id, stable_key, local_name, display_name, description, search_description, \
              search_short_grams, input_schema_json, output_schema_json, input_typescript, \
              output_typescript, typescript_definitions_json, intrinsic_mode, present, revision, \
              created_at, updated_at, last_seen_at, tombstoned_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?, NULL) \
             ON CONFLICT(source_id, stable_key) DO UPDATE SET \
              display_name = excluded.display_name, description = excluded.description, \
              search_description = excluded.search_description, \
              search_short_grams = excluded.search_short_grams, \
              input_schema_json = excluded.input_schema_json, \
              output_schema_json = excluded.output_schema_json, \
              input_typescript = excluded.input_typescript, \
              output_typescript = excluded.output_typescript, \
              typescript_definitions_json = excluded.typescript_definitions_json, \
              intrinsic_mode = excluded.intrinsic_mode, present = 1, \
              revision = tools.revision + 1, updated_at = excluded.updated_at, \
              last_seen_at = excluded.last_seen_at, tombstoned_at = NULL",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(source_id)
        .bind(&tool.stable_key)
        .bind(local_name)
        .bind(&tool.display_name)
        .bind(&tool.description)
        .bind(&tool.search_description)
        .bind(&tool.search_short_grams)
        .bind(&tool.input_schema_json)
        .bind(&tool.output_schema_json)
        .bind(&tool.input_typescript)
        .bind(&tool.output_typescript)
        .bind(&tool.typescript_definitions_json)
        .bind(tool.intrinsic_mode.as_str())
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    }
    let missing = existing_by_key
        .iter()
        .filter(|(stable_key, (_, present))| *present && !staged_keys.contains(*stable_key))
        .map(|(stable_key, _)| stable_key.clone())
        .collect::<Vec<_>>();
    for stable_key in &missing {
        sqlx::query(
            "UPDATE tools SET present = 0, revision = revision + 1, updated_at = ?, \
             tombstoned_at = ? WHERE source_id = ? AND stable_key = ? AND present = 1",
        )
        .bind(now)
        .bind(now)
        .bind(source_id)
        .bind(stable_key)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(missing)
}

async fn apply_tool_bindings(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    bindings: &[PreparedToolBinding],
    now: i64,
) -> Result<(), CatalogError> {
    for binding in bindings {
        let changed = sqlx::query(
            "INSERT INTO tool_bindings \
             (tool_id, protocol, binding_version, definition_json, revision, created_at, updated_at) \
             SELECT id, ?, ?, ?, 0, ?, ? FROM tools \
             WHERE source_id = ? AND stable_key = ? AND present = 1 \
             ON CONFLICT(tool_id) DO UPDATE SET protocol = excluded.protocol, \
             binding_version = excluded.binding_version, \
             definition_json = excluded.definition_json, revision = tool_bindings.revision + 1, \
             updated_at = excluded.updated_at",
        )
        .bind(binding.protocol)
        .bind(binding.version)
        .bind(&binding.definition_json)
        .bind(now)
        .bind(now)
        .bind(source_id)
        .bind(&binding.stable_key)
        .execute(&mut **transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(validation(
                "invalid_tool_binding",
                "A tool binding does not match an active imported tool.",
            ));
        }
    }
    sqlx::query(
        "DELETE FROM tool_bindings WHERE tool_id IN (\
         SELECT id FROM tools WHERE source_id = ? AND present = 0)",
    )
    .bind(source_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn rebuild_search_indexes(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
) -> Result<(), CatalogError> {
    for table in ["tool_search", "tool_search_trigram", "tool_search_short"] {
        let statement = format!("DELETE FROM {table} WHERE source_id = ?");
        sqlx::query(&statement)
            .bind(source_id)
            .execute(&mut **transaction)
            .await?;
    }
    for table in ["tool_search", "tool_search_trigram"] {
        let statement = format!(
            "INSERT INTO {table} \
             (source_id, tool_id, source_slug, local_name, description, sandbox_path) \
             SELECT tools.source_id, tools.id, replace(sources.slug, '_', ' '), \
                    replace(tools.local_name, '_', ' '), tools.search_description, \
                    replace(sources.slug, '_', ' ') || ' ' || replace(tools.local_name, '_', ' ') \
             FROM tools JOIN sources ON sources.id = tools.source_id \
             WHERE tools.source_id = ? AND tools.present = 1"
        );
        sqlx::query(&statement)
            .bind(source_id)
            .execute(&mut **transaction)
            .await?;
    }
    sqlx::query(
        "INSERT INTO tool_search_short (source_id, tool_id, grams) \
         SELECT tools.source_id, tools.id, \
                sources.search_short_grams || ' ' || tools.search_short_grams \
         FROM tools JOIN sources ON sources.id = tools.source_id \
         WHERE tools.source_id = ? AND tools.present = 1",
    )
    .bind(source_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn ensure_source_exists(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
) -> Result<(), CatalogError> {
    let exists = sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM sources WHERE id = ?)")
        .bind(source_id)
        .fetch_one(&mut **transaction)
        .await?
        != 0;
    if exists {
        Ok(())
    } else {
        Err(CatalogError::NotFound { entity: "source" })
    }
}

async fn source_path_snapshot(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
) -> Result<String, CatalogError> {
    let slug = sqlx::query_scalar::<_, String>("SELECT slug FROM sources WHERE id = ?")
        .bind(source_id)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(format!("tools.{slug}"))
}

async fn revision_or_not_found(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    _table: &'static str,
    id: &str,
    scope: &'static str,
    expected: i64,
) -> Result<CatalogError, CatalogError> {
    let actual = sqlx::query_scalar::<_, i64>("SELECT revision FROM sources WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await?;
    Ok(match actual {
        Some(actual) => CatalogError::RevisionConflict {
            scope,
            expected,
            actual,
        },
        None => CatalogError::NotFound { entity: scope },
    })
}

async fn increment_source_revision(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    now: i64,
) -> Result<i64, CatalogError> {
    Ok(sqlx::query_scalar(
        "UPDATE sources SET revision = revision + 1, updated_at = ? \
         WHERE id = ? RETURNING revision",
    )
    .bind(now)
    .bind(source_id)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn increment_source_and_global(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
    now: i64,
) -> Result<(i64, i64), CatalogError> {
    let source_revision = increment_source_revision(transaction, source_id, now).await?;
    let global_revision = bump_global_revision(transaction, now).await?;
    Ok((source_revision, global_revision))
}

async fn bump_global_revision(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    now: i64,
) -> Result<i64, CatalogError> {
    Ok(sqlx::query_scalar(
        "UPDATE catalog_state SET revision = revision + 1, updated_at = ? \
         WHERE id = 1 RETURNING revision",
    )
    .bind(now)
    .fetch_one(&mut **transaction)
    .await?)
}

#[allow(clippy::too_many_arguments)]
async fn insert_audit(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    audit: AuditContext<'_>,
    action: &str,
    source_id: Option<&str>,
    tool_id: Option<&str>,
    target_path_snapshot: Option<&str>,
    metadata: Value,
    created_at: i64,
) -> Result<(), CatalogError> {
    insert_audit_with_limit(
        transaction,
        audit,
        action,
        source_id,
        tool_id,
        target_path_snapshot,
        metadata,
        created_at,
        MAX_AUDIT_EVENT_ROWS,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn insert_audit_with_limit(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    audit: AuditContext<'_>,
    action: &str,
    source_id: Option<&str>,
    tool_id: Option<&str>,
    target_path_snapshot: Option<&str>,
    metadata: Value,
    created_at: i64,
    maximum_rows: i64,
) -> Result<(), CatalogError> {
    let metadata_json = serde_json::to_string(&metadata)?;
    if metadata_json.len() > MAX_AUDIT_METADATA_BYTES {
        return Err(validation(
            "audit_metadata_too_large",
            format!(
                "Audit metadata may contain at most {MAX_AUDIT_METADATA_BYTES} serialized bytes."
            ),
        ));
    }
    sqlx::query(
        "INSERT INTO audit_events \
         (id, request_id, actor_admin_id, action, source_id, tool_id, \
          target_path_snapshot, metadata_json, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(audit.request_id())
    .bind(audit.actor_admin_id())
    .bind(action)
    .bind(source_id)
    .bind(tool_id)
    .bind(target_path_snapshot)
    .bind(metadata_json)
    .bind(created_at)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "DELETE FROM audit_events WHERE rowid IN ( \
         SELECT rowid FROM audit_events \
         ORDER BY rowid DESC LIMIT -1 OFFSET ?)",
    )
    .bind(maximum_rows)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(test)]
async fn source_kind(
    transaction: &mut Transaction<'_, sqlx::Sqlite>,
    source_id: &str,
) -> Result<SourceKind, CatalogError> {
    let kind = sqlx::query_scalar::<_, String>("SELECT kind FROM sources WHERE id = ?")
        .bind(source_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(CatalogError::NotFound { entity: "source" })?;
    SourceKind::from_str(&kind)
}

fn validate_log_text(label: &str, value: &str, maximum_length: usize) -> Result<(), CatalogError> {
    if value.is_empty() || value.len() > maximum_length || value.contains('\0') {
        Err(validation(
            "invalid_request_log",
            format!("The request log {label} is invalid."),
        ))
    } else {
        Ok(())
    }
}

fn validate_optional_log_text(
    label: &str,
    value: Option<&str>,
    maximum_length: usize,
) -> Result<(), CatalogError> {
    if let Some(value) = value {
        validate_log_text(label, value, maximum_length)?;
    }
    Ok(())
}

fn encode_cursor(created_at: i64, request_id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{created_at}\n{request_id}"))
}

fn decode_cursor(cursor: &str) -> Result<(i64, String), CatalogError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| validation("invalid_cursor", "The request-log cursor is malformed."))?;
    let decoded = String::from_utf8(decoded)
        .map_err(|_| validation("invalid_cursor", "The request-log cursor is malformed."))?;
    let (created_at, request_id) = decoded
        .split_once('\n')
        .ok_or_else(|| validation("invalid_cursor", "The request-log cursor is malformed."))?;
    let created_at = created_at
        .parse::<i64>()
        .map_err(|_| validation("invalid_cursor", "The request-log cursor is malformed."))?;
    validate_log_text("cursor request ID", request_id, 128)?;
    Ok((created_at, request_id.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashSet};

    use serde_json::json;

    use sqlx::sqlite::SqlitePoolOptions;

    use super::{
        CatalogSnapshot, NameAllocator, PayloadLimits, insert_audit_with_limit,
        prepare_snapshot_and_bindings_with_limits, prepare_snapshot_with_limits,
    };
    use crate::catalog::{
        ArtifactKind, AuditContext, CatalogError, CreateSource, SourceKind, StagedArtifact,
        StagedTool, StagedToolBinding, ToolBinding, ToolMode,
    };
    use crate::openapi::OpenApiBinding;
    use crate::{AppConfig, ExecutorApp};

    fn empty_snapshot() -> CatalogSnapshot {
        CatalogSnapshot {
            expected_source_revision: 0,
            expected_credential_revision: None,
            artifacts: Vec::new(),
            tools: Vec::new(),
        }
    }

    fn small_limits() -> PayloadLimits {
        PayloadLimits {
            artifact_count: 2,
            artifact: 128,
            artifact_key: 128,
            schema: 128,
            typescript_definitions: 128,
            typescript_preview: 128,
            tool_stable_key: 128,
            tool_name: 128,
            tool_description: 128,
            search_description: 128,
            short_gram_document: 1024,
            local_name: 16,
            aggregate: 256,
        }
    }

    fn staged_tool() -> StagedTool {
        StagedTool {
            stable_key: "tool".to_owned(),
            preferred_name: "Tool".to_owned(),
            display_name: "Tool".to_owned(),
            description: None,
            input_schema: json!({ "type": "object" }),
            output_schema: None,
            input_typescript: None,
            output_typescript: None,
            typescript_definitions: BTreeMap::new(),
            intrinsic_mode: ToolMode::Enabled,
        }
    }

    #[test]
    fn identical_tool_names_allocate_linearly_and_deterministically_at_the_catalog_limit() {
        let mut allocator = NameAllocator::new(HashSet::new());
        let mut allocated = HashSet::with_capacity(100_000);
        for index in 1..=100_000 {
            let name = allocator.allocate("run", 128, '_');
            assert!(allocated.insert(name.clone()));
            if index == 1 {
                assert_eq!(name, "run");
            } else if index == 100_000 {
                assert_eq!(name, "run_100000");
            }
        }
        assert_eq!(allocator.candidate_probes(), 99_999);
    }

    #[test]
    fn collapsing_max_length_bases_share_suffix_probe_progress() {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let common_prefix = "a".repeat(126);
        let mut bases = Vec::with_capacity(ALPHABET.len() * ALPHABET.len());
        for first in ALPHABET {
            for second in ALPHABET {
                bases.push(format!(
                    "{common_prefix}{}{}",
                    char::from(*first),
                    char::from(*second)
                ));
            }
        }
        assert_eq!(bases.len(), 1_296);

        let mut allocator = NameAllocator::new(HashSet::new());
        let mut terminal = String::new();
        for base in &bases {
            terminal = allocator.allocate(base, 128, '_');
            assert_eq!(terminal, *base);
            for _ in 0..76 {
                terminal = allocator.allocate(base, 128, '_');
            }
        }

        let suffix_allocations = bases.len() * 76;
        assert_eq!(allocator.candidate_probes(), suffix_allocations);
        assert_eq!(allocator.used.len(), bases.len() + suffix_allocations);
        assert_eq!(terminal, format!("{}_98497", &common_prefix[..122]));
    }

    #[test]
    fn snapshot_payload_limits_reject_each_bounded_payload_class() {
        let mut artifact_snapshot = empty_snapshot();
        artifact_snapshot.artifacts.push(StagedArtifact {
            kind: ArtifactKind::Metadata,
            stable_key: "large".to_owned(),
            content: json!({ "value": "x".repeat(256) }),
        });
        assert!(matches!(
            prepare_snapshot_with_limits(artifact_snapshot, small_limits()),
            Err(super::CatalogError::Validation {
                code: "artifact_too_large",
                ..
            })
        ));

        let mut schema_snapshot = empty_snapshot();
        let mut schema_tool = staged_tool();
        schema_tool.input_schema = json!({ "value": "x".repeat(256) });
        schema_snapshot.tools.push(schema_tool);
        assert!(matches!(
            prepare_snapshot_with_limits(schema_snapshot, small_limits()),
            Err(super::CatalogError::Validation {
                code: "schema_too_large",
                ..
            })
        ));

        let mut definitions_snapshot = empty_snapshot();
        let mut definitions_tool = staged_tool();
        definitions_tool
            .typescript_definitions
            .insert("Large".to_owned(), "x".repeat(256));
        definitions_snapshot.tools.push(definitions_tool);
        assert!(matches!(
            prepare_snapshot_with_limits(definitions_snapshot, small_limits()),
            Err(super::CatalogError::Validation {
                code: "typescript_definitions_too_large",
                ..
            })
        ));
    }

    #[test]
    fn snapshot_payload_limits_reject_aggregate_serialized_bytes() {
        let mut snapshot = empty_snapshot();
        for index in 0..3 {
            snapshot.artifacts.push(StagedArtifact {
                kind: ArtifactKind::Metadata,
                stable_key: format!("artifact-{index}"),
                content: json!({ "value": "x".repeat(90) }),
            });
        }
        let mut limits = small_limits();
        limits.artifact_count = 3;
        assert!(matches!(
            prepare_snapshot_with_limits(snapshot, limits),
            Err(super::CatalogError::Validation {
                code: "catalog_payload_too_large",
                ..
            })
        ));
    }

    #[test]
    fn snapshot_and_bindings_share_one_aggregate_payload_budget() {
        let snapshot = CatalogSnapshot {
            expected_source_revision: 0,
            expected_credential_revision: None,
            artifacts: Vec::new(),
            tools: vec![staged_tool()],
        };
        let bindings = vec![StagedToolBinding {
            stable_key: "tool".to_owned(),
            binding: ToolBinding::OpenapiV1(OpenApiBinding {
                version: 1,
                method: "GET".to_owned(),
                path_template: "/tool".to_owned(),
                server_url: format!("https://{}.example.test", "x".repeat(100)),
                parameters: Vec::new(),
                request_body: None,
                security: Vec::new(),
            }),
        }];
        let mut limits = small_limits();
        limits.schema = 256;
        limits.aggregate = 1_024;
        let snapshot_bytes = prepare_snapshot_with_limits(snapshot.clone(), limits)
            .expect("snapshot should fit independently")
            .payload_bytes;
        let binding_bytes = match &bindings[0].binding {
            ToolBinding::OpenapiV1(binding) => serde_json::to_string(binding)
                .expect("binding should serialize")
                .len(),
        };
        limits.aggregate = snapshot_bytes + binding_bytes - 1;
        assert!(prepare_snapshot_with_limits(snapshot.clone(), limits).is_ok());
        assert!(super::prepare_tool_bindings_with_limits(bindings.clone(), limits, 0).is_ok());
        assert!(matches!(
            prepare_snapshot_and_bindings_with_limits(snapshot, bindings, limits),
            Err(CatalogError::Validation {
                code: "catalog_payload_too_large",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn binding_replacement_rejects_non_openapi_sources() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let app = ExecutorApp::open(AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("Executor should open");
        let source = app
            .catalog()
            .create_source(
                CreateSource {
                    kind: SourceKind::Graphql,
                    preferred_slug: "graphql".to_owned(),
                    display_name: "GraphQL".to_owned(),
                    description: None,
                    configuration: serde_json::Map::new(),
                },
                AuditContext::system(None),
            )
            .await
            .expect("source should create");
        let error = app
            .catalog()
            .replace_tool_bindings(&source.id, Vec::new())
            .await
            .expect_err("non-OpenAPI source should reject binding replacement");
        assert!(matches!(
            error,
            CatalogError::Validation {
                code: "invalid_source_kind",
                ..
            }
        ));
    }

    #[test]
    fn snapshot_payload_budget_charges_typescript_and_text_copies() {
        let mut typescript_snapshot = empty_snapshot();
        let mut typescript_tool = staged_tool();
        typescript_tool.input_typescript = Some("i".repeat(110));
        typescript_tool.output_typescript = Some("o".repeat(110));
        typescript_snapshot.tools.push(typescript_tool);
        assert!(matches!(
            prepare_snapshot_with_limits(typescript_snapshot, small_limits()),
            Err(super::CatalogError::Validation {
                code: "catalog_payload_too_large",
                ..
            })
        ));

        let mut key_and_name_snapshot = empty_snapshot();
        let mut key_and_name_tool = staged_tool();
        key_and_name_tool.stable_key = "k".repeat(80);
        key_and_name_tool.preferred_name = "p".repeat(80);
        key_and_name_tool.display_name = "d".repeat(80);
        key_and_name_snapshot.tools.push(key_and_name_tool);
        assert!(matches!(
            prepare_snapshot_with_limits(key_and_name_snapshot, small_limits()),
            Err(super::CatalogError::Validation {
                code: "catalog_payload_too_large",
                ..
            })
        ));

        let mut description_snapshot = empty_snapshot();
        let mut description_tool = staged_tool();
        description_tool.description = Some("description".repeat(10));
        description_snapshot.tools.push(description_tool);
        assert!(matches!(
            prepare_snapshot_with_limits(description_snapshot, small_limits()),
            Err(super::CatalogError::Validation {
                code: "catalog_payload_too_large",
                ..
            })
        ));
    }

    #[test]
    fn snapshot_payload_limits_reject_preview_items_and_tiny_artifact_floods() {
        let mut preview_snapshot = empty_snapshot();
        let mut preview_tool = staged_tool();
        preview_tool.input_typescript = Some("x".repeat(129));
        preview_snapshot.tools.push(preview_tool);
        assert!(matches!(
            prepare_snapshot_with_limits(preview_snapshot, small_limits()),
            Err(super::CatalogError::Validation {
                code: "typescript_too_large",
                ..
            })
        ));

        assert!(matches!(
            super::validate_artifact_count(1_000_000, small_limits().artifact_count),
            Err(super::CatalogError::Validation {
                code: "catalog_too_many_artifacts",
                ..
            })
        ));
        let mut tiny_artifacts = empty_snapshot();
        for index in 0..3 {
            tiny_artifacts.artifacts.push(StagedArtifact {
                kind: ArtifactKind::Metadata,
                stable_key: format!("tiny-{index}"),
                content: json!(null),
            });
        }
        assert!(matches!(
            prepare_snapshot_with_limits(tiny_artifacts, small_limits()),
            Err(super::CatalogError::Validation {
                code: "catalog_too_many_artifacts",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn audit_insert_compacts_oldest_rows_and_preserves_context_atomically() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("test database should open");
        sqlx::query(
            "CREATE TABLE audit_events ( \
             id TEXT PRIMARY KEY NOT NULL, request_id TEXT, actor_admin_id INTEGER, \
             action TEXT NOT NULL, source_id TEXT, tool_id TEXT, target_path_snapshot TEXT, \
             metadata_json TEXT NOT NULL, created_at INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .expect("audit table should be created");

        for index in 1..=5 {
            let request_id = format!("request-{index}");
            let mut transaction = pool.begin().await.expect("transaction should begin");
            insert_audit_with_limit(
                &mut transaction,
                AuditContext::admin(&request_id, 7),
                &format!("action-{index}"),
                Some("source-1"),
                Some("tool-1"),
                Some("tools.source.tool"),
                json!({ "sequence": index }),
                index,
                3,
            )
            .await
            .expect("bounded audit insertion should succeed");
            transaction
                .commit()
                .await
                .expect("audit insertion and compaction should commit together");
        }

        let rows = sqlx::query_as::<_, (String, String, i64, String, String)>(
            "SELECT action, request_id, actor_admin_id, target_path_snapshot, metadata_json \
             FROM audit_events ORDER BY created_at",
        )
        .fetch_all(&pool)
        .await
        .expect("retained audit rows should read");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].0, "action-3");
        assert_eq!(rows[2].0, "action-5");
        assert_eq!(rows[2].1, "request-5");
        assert_eq!(rows[2].2, 7);
        assert_eq!(rows[2].3, "tools.source.tool");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rows[2].4)
                .expect("retained metadata should be valid JSON"),
            json!({ "sequence": 5 })
        );

        let mut transaction = pool.begin().await.expect("transaction should begin");
        insert_audit_with_limit(
            &mut transaction,
            AuditContext::system(Some("request-6")),
            "action-6",
            Some("source-1"),
            Some("tool-1"),
            Some("tools.source.tool"),
            json!({ "sequence": 6 }),
            6,
            3,
        )
        .await
        .expect("an uncommitted insertion should compact inside its transaction");
        let in_transaction = sqlx::query_scalar::<_, String>(
            "SELECT group_concat(action, ',') FROM ( \
             SELECT action FROM audit_events ORDER BY created_at)",
        )
        .fetch_one(&mut *transaction)
        .await
        .expect("transactional audit rows should read");
        assert_eq!(in_transaction, "action-4,action-5,action-6");
        transaction
            .rollback()
            .await
            .expect("audit insertion and compaction should roll back together");
        let after_rollback = sqlx::query_scalar::<_, String>(
            "SELECT group_concat(action, ',') FROM ( \
             SELECT action FROM audit_events ORDER BY created_at)",
        )
        .fetch_one(&pool)
        .await
        .expect("rolled-back audit rows should read");
        assert_eq!(after_rollback, "action-3,action-4,action-5");
    }

    #[tokio::test]
    async fn oversized_audit_metadata_is_rejected_without_inserting_a_row() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("test database should open");
        sqlx::query(
            "CREATE TABLE audit_events ( \
             id TEXT PRIMARY KEY NOT NULL, request_id TEXT, actor_admin_id INTEGER, \
             action TEXT NOT NULL, source_id TEXT, tool_id TEXT, target_path_snapshot TEXT, \
             metadata_json TEXT NOT NULL, created_at INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .expect("audit table should be created");
        let mut transaction = pool.begin().await.expect("transaction should begin");
        let error = insert_audit_with_limit(
            &mut transaction,
            AuditContext::system(Some("oversized-audit")),
            "oversized",
            None,
            None,
            None,
            json!({ "value": "x".repeat(super::MAX_AUDIT_METADATA_BYTES) }),
            1,
            3,
        )
        .await
        .expect_err("oversized metadata should fail before insertion");
        assert!(matches!(
            error,
            CatalogError::Validation {
                code: "audit_metadata_too_large",
                ..
            }
        ));
        transaction
            .commit()
            .await
            .expect("empty transaction should commit");
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .expect("audit count should read");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn audit_retention_uses_insertion_order_when_the_wall_clock_moves_backward() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("test database should open");
        sqlx::query(
            "CREATE TABLE audit_events ( \
             id TEXT PRIMARY KEY NOT NULL, request_id TEXT, actor_admin_id INTEGER, \
             action TEXT NOT NULL, source_id TEXT, tool_id TEXT, target_path_snapshot TEXT, \
             metadata_json TEXT NOT NULL, created_at INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .expect("audit table should be created");

        for (index, future_timestamp) in [10_000, 20_000, 30_000].into_iter().enumerate() {
            let mut transaction = pool.begin().await.expect("transaction should begin");
            insert_audit_with_limit(
                &mut transaction,
                AuditContext::system(None),
                &format!("future-{}", index + 1),
                None,
                None,
                None,
                json!({}),
                future_timestamp,
                3,
            )
            .await
            .expect("future-dated audit should insert");
            transaction.commit().await.expect("audit should commit");
        }

        let mut transaction = pool.begin().await.expect("transaction should begin");
        insert_audit_with_limit(
            &mut transaction,
            AuditContext::system(Some("backward-clock-request")),
            "new-after-clock-reset",
            None,
            None,
            Some("tools.source.tool"),
            json!({ "clock": "reset" }),
            1,
            3,
        )
        .await
        .expect("new audit should survive retention despite its lower timestamp");
        transaction.commit().await.expect("new audit should commit");

        let retained = sqlx::query_as::<_, (String, i64)>(
            "SELECT action, created_at FROM audit_events ORDER BY rowid",
        )
        .fetch_all(&pool)
        .await
        .expect("retained audits should read");
        assert_eq!(
            retained,
            vec![
                ("future-2".to_owned(), 20_000),
                ("future-3".to_owned(), 30_000),
                ("new-after-clock-reset".to_owned(), 1),
            ]
        );
    }
}
