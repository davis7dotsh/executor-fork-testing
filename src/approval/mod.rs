use std::{
    fmt,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, Sqlite, SqlitePool, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    actor::{ActorKind, ToolActor},
    catalog::{InvocationRevisionToken, ModeProvenance, NewRequestLog, RequestSurface},
    crypto::{CryptoError, Keyring},
};

#[path = "../invocation/mod.rs"]
pub mod invocation;

const APPROVAL_TTL_SECONDS: i64 = 10 * 60;
#[cfg(test)]
const APPROVAL_CORRELATION_TTL_SECONDS: i64 = 24 * 60 * 60;
const MAX_APPROVAL_ARGUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_APPROVAL_SCHEMA_BYTES: usize = 2 * 1024 * 1024;
const MAX_APPROVAL_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_APPROVAL_RESULT_BYTES: usize = 8 * 1024 * 1024;
const MAX_APPROVAL_PAGE_LIMIT: u32 = 100;
const MAX_ACTIVE_APPROVALS: i64 = 1_024;
const MAX_ACTIVE_APPROVALS_PER_OWNER: i64 = 128;
const MAX_ACTIVE_APPROVAL_CIPHERTEXT_BYTES: i64 = 64 * 1024 * 1024;
const MAX_TERMINAL_APPROVAL_CIPHERTEXT_BYTES: i64 = 64 * 1024 * 1024;
const MAX_APPROVAL_DELIVERY_PINS: i64 = 128;
const MAX_APPROVAL_DELIVERY_PIN_REFS: i64 = 128;
const MAX_PINNED_SNAPSHOT_CIPHERTEXT_BYTES: i64 = 64 * 1024 * 1024;
const MAX_APPROVAL_CORRELATIONS: i64 = 100_000;

const TERMINAL_RETENTION: i64 = 10_000;

trait Clock: Send + Sync + 'static {
    fn now(&self) -> i64;
}

#[derive(Clone, Copy, Debug, Default)]
struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after the Unix epoch")
            .as_secs() as i64
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Canceled,
    Executing,
    Succeeded,
    Failed,
    Stale,
    Interrupted,
}

impl ApprovalStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Canceled => "canceled",
            Self::Executing => "executing",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Stale => "stale",
            Self::Interrupted => "interrupted",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Denied
                | Self::Expired
                | Self::Canceled
                | Self::Succeeded
                | Self::Failed
                | Self::Stale
                | Self::Interrupted
        )
    }
}

impl fmt::Display for ApprovalStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ApprovalStatus {
    type Err = ApprovalError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            "canceled" => Ok(Self::Canceled),
            "executing" => Ok(Self::Executing),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "stale" => Ok(Self::Stale),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(ApprovalError::CorruptData("unknown approval status")),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

impl ApprovalDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }

    const fn status(self) -> ApprovalStatus {
        match self {
            Self::Approve => ApprovalStatus::Approved,
            Self::Deny => ApprovalStatus::Denied,
        }
    }
}

impl FromStr for ApprovalDecision {
    type Err = ApprovalError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "approve" => Ok(Self::Approve),
            "deny" => Ok(Self::Deny),
            _ => Err(ApprovalError::CorruptData("unknown approval decision")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionOutcome {
    Succeeded,
    Failed,
    Interrupted,
}

impl ExecutionOutcome {
    const fn status(self) -> ApprovalStatus {
        match self {
            Self::Succeeded => ApprovalStatus::Succeeded,
            Self::Failed => ApprovalStatus::Failed,
            Self::Interrupted => ApprovalStatus::Interrupted,
        }
    }
}

#[derive(Clone, Debug)]
struct NewApproval {
    pub execution_id: String,
    pub call_id: String,
    pub worker_generation: u64,
    pub actor: ToolActor,
    pub surface: RequestSurface,
    pub callable_path_snapshot: String,
    pub source_display_name_snapshot: Option<String>,
    pub tool_display_name_snapshot: Option<String>,
    pub mode_provenance: ModeProvenance,
    pub revisions: InvocationRevisionToken,
    pub arguments: Value,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub invocation_snapshot: Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRecord {
    pub sequence: i64,
    pub id: String,
    pub execution_id: String,
    pub call_id: String,
    pub worker_generation: u64,
    pub actor_kind: ActorKind,
    pub actor_id: String,
    pub actor_api_token_id: Option<String>,
    pub actor_name_snapshot: Option<String>,
    pub surface: RequestSurface,
    pub callable_path_snapshot: String,
    pub source_display_name: Option<String>,
    pub tool_display_name: Option<String>,
    pub mode_provenance: ModeProvenance,
    pub revisions: InvocationRevisionTokenSnapshot,
    pub status: ApprovalStatus,
    pub revision: i64,
    pub decision_id: Option<String>,
    pub decision: Option<ApprovalDecision>,
    pub decided_by_admin_id: Option<i64>,
    pub failure_code: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
    pub decided_at: Option<i64>,
    pub execution_started_at: Option<i64>,
    pub completed_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvocationRevisionTokenSnapshot {
    pub source_id: String,
    pub tool_id: String,
    pub source_revision: i64,
    pub catalog_revision: i64,
    pub tool_revision: i64,
    pub binding_revision: i64,
    pub credential_revision: Option<i64>,
}

impl From<&InvocationRevisionToken> for InvocationRevisionTokenSnapshot {
    fn from(value: &InvocationRevisionToken) -> Self {
        Self {
            source_id: value.source_id.clone(),
            tool_id: value.tool_id.clone(),
            source_revision: value.source_revision,
            catalog_revision: value.catalog_revision,
            tool_revision: value.tool_revision,
            binding_revision: value.binding_revision,
            credential_revision: value.credential_revision,
        }
    }
}

impl From<InvocationRevisionTokenSnapshot> for InvocationRevisionToken {
    fn from(value: InvocationRevisionTokenSnapshot) -> Self {
        Self {
            source_id: value.source_id,
            tool_id: value.tool_id,
            source_revision: value.source_revision,
            catalog_revision: value.catalog_revision,
            tool_revision: value.tool_revision,
            binding_revision: value.binding_revision,
            credential_revision: value.credential_revision,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalAdminDetail {
    #[serde(flatten)]
    pub record: ApprovalRecord,
    pub redacted_arguments: Value,
    pub input_schema: Value,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalOwnerDetail {
    #[serde(flatten)]
    pub record: ApprovalRecord,
    pub result: Option<Value>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct ApprovalExecutionSnapshot {
    pub record: ApprovalRecord,
    pub arguments: Value,
    pub input_schema: Value,
    pub output_schema: Option<Value>,
    pub invocation_snapshot: Value,
    pub result: Option<Value>,
}

#[derive(Clone, Debug, Default)]
pub struct ApprovalListQuery {
    pub before_sequence: Option<i64>,
    pub limit: u32,
    pub status: Option<ApprovalStatus>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalPage {
    pub items: Vec<ApprovalRecord>,
    pub next_cursor: Option<i64>,
}

#[derive(Clone, Debug)]
struct DecisionResult {
    pub record: ApprovalRecord,
    pub idempotent: bool,
}

#[derive(Clone, Debug)]
struct ApprovalCreateResult {
    pub record: ApprovalRecord,
    pub delivery_pin: bool,
    #[cfg(test)]
    pub redacted_arguments: Value,
    #[cfg(test)]
    pub input_schema: Value,
    #[cfg(test)]
    pub reused: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ApprovalDeliveryIdentity {
    pub approval_id: String,
    pub actor: ToolActor,
    pub execution_id: String,
    pub call_id: String,
}

impl ApprovalCreateResult {
    fn from_detail(detail: ApprovalAdminDetail, reused: bool, delivery_pin: bool) -> Self {
        #[cfg(not(test))]
        let _ = reused;
        Self {
            record: detail.record,
            delivery_pin,
            #[cfg(test)]
            redacted_arguments: detail.redacted_arguments,
            #[cfg(test)]
            input_schema: detail.input_schema,
            #[cfg(test)]
            reused,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct StartupRecovery {
    #[cfg(test)]
    pub interrupted_count: u64,
    pub approved_ids: Vec<String>,
}

#[derive(Clone)]
struct ApprovalStore {
    pool: SqlitePool,
    keyring: Keyring,
    clock: Arc<dyn Clock>,
    transition_slot: Arc<tokio::sync::Semaphore>,
}

struct Transition<'a> {
    from: ApprovalStatus,
    to: ApprovalStatus,
    failure_code: Option<&'a str>,
    result_ciphertext: Option<Vec<u8>>,
}

impl ApprovalStore {
    #[cfg(test)]
    fn new(pool: SqlitePool, keyring: Keyring, clock: Arc<dyn Clock>) -> Self {
        Self {
            pool,
            keyring,
            clock,
            transition_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    fn system(pool: SqlitePool, keyring: Keyring) -> Self {
        Self {
            pool,
            keyring,
            clock: Arc::new(SystemClock),
            transition_slot: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    async fn invocation_snapshot(&self, approval_id: &str) -> Result<Option<Value>, ApprovalError> {
        let ciphertext = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT invocation_snapshot_ciphertext FROM approvals WHERE id = ?",
        )
        .bind(approval_id)
        .fetch_optional(&self.pool)
        .await?;
        ciphertext
            .map(|ciphertext| {
                decrypt_json(
                    &self.keyring,
                    "approval-invocation-snapshot",
                    approval_id,
                    &ciphertext,
                )
            })
            .transpose()
    }

    async fn create(&self, new: NewApproval) -> Result<ApprovalCreateResult, ApprovalError> {
        validate_new(&new)?;
        let observed_now = self.advance_clock().await?;
        let id = Uuid::new_v4().to_string();
        let arguments = encode_json("arguments", &new.arguments, MAX_APPROVAL_ARGUMENT_BYTES)?;
        let redacted_arguments = encode_json(
            "redacted arguments",
            &redact_arguments(&new.arguments, &new.input_schema),
            MAX_APPROVAL_ARGUMENT_BYTES,
        )?;
        let input_schema =
            encode_json("input schema", &new.input_schema, MAX_APPROVAL_SCHEMA_BYTES)?;
        let output_schema = new
            .output_schema
            .as_ref()
            .map(|value| encode_json("output schema", value, MAX_APPROVAL_SCHEMA_BYTES))
            .transpose()?;
        let invocation_snapshot = encode_json(
            "invocation snapshot",
            &new.invocation_snapshot,
            MAX_APPROVAL_SNAPSHOT_BYTES,
        )?;
        let canonical_arguments = canonical_json_bytes(&new.arguments)?;
        let arguments_digest = self
            .keyring
            .digest("approval-arguments", &canonical_arguments)
            .to_vec();
        let arguments_ciphertext = self
            .keyring
            .encrypt("approval-arguments", &id, &arguments)?;
        let redacted_arguments_ciphertext =
            self.keyring
                .encrypt("approval-redacted-arguments", &id, &redacted_arguments)?;
        let input_schema_ciphertext =
            self.keyring
                .encrypt("approval-input-schema", &id, &input_schema)?;
        let output_schema_ciphertext = output_schema
            .as_deref()
            .map(|value| self.keyring.encrypt("approval-output-schema", &id, value))
            .transpose()?;
        let invocation_snapshot_ciphertext =
            self.keyring
                .encrypt("approval-invocation-snapshot", &id, &invocation_snapshot)?;
        let worker_generation =
            i64::try_from(new.worker_generation).map_err(|_| ApprovalError::Validation {
                code: "invalid_worker_generation",
                message: "worker generation exceeds the supported range".to_owned(),
            })?;
        let actor_kind = new.actor.kind().as_str();
        let actor_id = new.actor.id();
        let actor_api_token_id = new.actor.api_token_id();
        let actor_name_snapshot = new.actor.name_snapshot();
        let new_ciphertext_bytes = [
            arguments_ciphertext.len(),
            redacted_arguments_ciphertext.len(),
            input_schema_ciphertext.len(),
            output_schema_ciphertext.as_ref().map_or(0, Vec::len),
            invocation_snapshot_ciphertext.len(),
        ]
        .into_iter()
        .try_fold(0_i64, |total, length| {
            i64::try_from(length)
                .ok()
                .and_then(|length| total.checked_add(length))
        })
        .ok_or(ApprovalError::Capacity {
            scope: "active_bytes",
        })?;

        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        let expires_at =
            now.checked_add(APPROVAL_TTL_SECONDS)
                .ok_or(ApprovalError::Validation {
                    code: "invalid_approval_ttl",
                    message: "approval expiry exceeds the supported timestamp range".to_owned(),
                })?;
        expire_pending_in(&mut transaction, now).await?;
        enforce_retention(&mut transaction).await?;
        reclaim_expired_correlations_in(&mut transaction, now).await?;
        if let Some(correlation) = fetch_correlation_in(
            &mut transaction,
            actor_kind,
            &actor_id,
            &new.execution_id,
            &new.call_id,
        )
        .await?
        {
            ensure_same_correlation(
                &correlation,
                actor_kind,
                &actor_id,
                new.surface,
                worker_generation,
                &new.callable_path_snapshot,
                &arguments_digest,
            )?;
            let existing = fetch_row_in(&mut transaction, &correlation.approval_id)
                .await?
                .ok_or(ApprovalError::CorrelationRetired)?;
            let delivery_pin = if new.worker_generation > 0 {
                add_delivery_pin_in(
                    &mut transaction,
                    &correlation.approval_id,
                    existing_ciphertext_bytes(&existing)?,
                    now,
                )
                .await?;
                true
            } else {
                false
            };
            let detail = self.decode_admin_detail(existing)?;
            transaction.commit().await?;
            return Ok(ApprovalCreateResult::from_detail(
                detail,
                true,
                delivery_pin,
            ));
        }
        let correlation_count = sqlx::query_scalar::<_, i64>(
            "SELECT correlation_count FROM approval_correlation_state WHERE id = 1",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if correlation_count >= MAX_APPROVAL_CORRELATIONS {
            return Err(ApprovalError::Capacity {
                scope: "correlations",
            });
        }
        let global_active = active_count_in(&mut transaction, None).await?;
        if global_active >= MAX_ACTIVE_APPROVALS {
            return Err(ApprovalError::Capacity { scope: "global" });
        }
        let owner_active = active_count_in(&mut transaction, Some((actor_kind, &actor_id))).await?;
        if owner_active >= MAX_ACTIVE_APPROVALS_PER_OWNER {
            return Err(ApprovalError::Capacity { scope: "owner" });
        }
        let active_ciphertext_bytes = active_ciphertext_bytes_in(&mut transaction).await?;
        if active_ciphertext_bytes
            .checked_add(new_ciphertext_bytes)
            .is_none_or(|total| total > MAX_ACTIVE_APPROVAL_CIPHERTEXT_BYTES)
        {
            return Err(ApprovalError::Capacity {
                scope: "active_bytes",
            });
        }

        let inserted = sqlx::query(
            "INSERT INTO approvals (id, execution_id, call_id, worker_generation, \
             actor_kind, actor_id, actor_api_token_id, actor_name_snapshot, surface, source_id, tool_id, \
             callable_path_snapshot, source_display_name_snapshot, tool_display_name_snapshot, \
             mode_provenance, \
             source_revision, catalog_revision, tool_revision, binding_revision, credential_revision, \
             arguments_digest, arguments_ciphertext, redacted_arguments_ciphertext, input_schema_ciphertext, \
             output_schema_ciphertext, invocation_snapshot_ciphertext, status, revision, \
             created_at, updated_at, expires_at) \
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
             'pending', 0, ?, ?, ? WHERE (? <> 'api_token' OR EXISTS (SELECT 1 FROM api_tokens \
             WHERE id = ? AND revoked_at IS NULL)) \
             AND NOT EXISTS (SELECT 1 FROM approval_correlations \
             WHERE actor_kind = ? AND actor_id = ? AND execution_id = ? AND call_id = ?) \
             ON CONFLICT(actor_kind, actor_id, execution_id, call_id) DO NOTHING",
        )
        .bind(&id)
        .bind(&new.execution_id)
        .bind(&new.call_id)
        .bind(worker_generation)
        .bind(actor_kind)
        .bind(&actor_id)
        .bind(actor_api_token_id)
        .bind(actor_name_snapshot)
        .bind(new.surface.as_str())
        .bind(&new.revisions.source_id)
        .bind(&new.revisions.tool_id)
        .bind(&new.callable_path_snapshot)
        .bind(new.source_display_name_snapshot)
        .bind(new.tool_display_name_snapshot)
        .bind(mode_provenance_str(new.mode_provenance))
        .bind(new.revisions.source_revision)
        .bind(new.revisions.catalog_revision)
        .bind(new.revisions.tool_revision)
        .bind(new.revisions.binding_revision)
        .bind(new.revisions.credential_revision)
        .bind(&arguments_digest)
        .bind(arguments_ciphertext)
        .bind(redacted_arguments_ciphertext)
        .bind(input_schema_ciphertext)
        .bind(output_schema_ciphertext)
        .bind(invocation_snapshot_ciphertext)
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(actor_kind)
        .bind(actor_api_token_id)
        .bind(actor_kind)
        .bind(&actor_id)
        .bind(&new.execution_id)
        .bind(&new.call_id)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() != 1 {
            if let Some(correlation) = fetch_correlation_in(
                &mut transaction,
                actor_kind,
                &actor_id,
                &new.execution_id,
                &new.call_id,
            )
            .await?
            {
                ensure_same_correlation(
                    &correlation,
                    actor_kind,
                    &actor_id,
                    new.surface,
                    worker_generation,
                    &new.callable_path_snapshot,
                    &arguments_digest,
                )?;
                let existing = fetch_row_in(&mut transaction, &correlation.approval_id)
                    .await?
                    .ok_or(ApprovalError::CorrelationRetired)?;
                let delivery_pin = if new.worker_generation > 0 {
                    add_delivery_pin_in(
                        &mut transaction,
                        &correlation.approval_id,
                        existing_ciphertext_bytes(&existing)?,
                        now,
                    )
                    .await?;
                    true
                } else {
                    false
                };
                let detail = self.decode_admin_detail(existing)?;
                transaction.commit().await?;
                return Ok(ApprovalCreateResult::from_detail(
                    detail,
                    true,
                    delivery_pin,
                ));
            }
            return Err(ApprovalError::OwnerTokenInactive);
        }
        let row = fetch_row_in(&mut transaction, &id)
            .await?
            .ok_or(ApprovalError::NotFound)?;
        let delivery_pin = if new.worker_generation > 0 {
            add_delivery_pin_in(&mut transaction, &id, new_ciphertext_bytes, now).await?;
            true
        } else {
            false
        };
        let detail = self.decode_admin_detail(row)?;
        transaction.commit().await?;
        Ok(ApprovalCreateResult::from_detail(
            detail,
            false,
            delivery_pin,
        ))
    }

    async fn get_admin(&self, id: &str) -> Result<Option<ApprovalAdminDetail>, ApprovalError> {
        let row = fetch_row(&self.pool, id).await?;
        row.map(|row| self.decode_admin_detail(row)).transpose()
    }

    async fn release_delivery_pin(
        &self,
        identity: &ApprovalDeliveryIdentity,
    ) -> Result<bool, ApprovalError> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let pin = sqlx::query_scalar::<_, i64>(
            "SELECT pins.ref_count FROM approval_delivery_pins AS pins \
             JOIN approvals ON approvals.id = pins.approval_id \
             WHERE pins.approval_id = ? AND approvals.actor_kind = ? \
             AND approvals.actor_id = ? AND approvals.execution_id = ? AND approvals.call_id = ?",
        )
        .bind(&identity.approval_id)
        .bind(identity.actor.kind().as_str())
        .bind(identity.actor.id())
        .bind(&identity.execution_id)
        .bind(&identity.call_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let released = match pin {
            Some(1) => {
                sqlx::query("DELETE FROM approval_delivery_pins WHERE approval_id = ?")
                    .bind(&identity.approval_id)
                    .execute(&mut *transaction)
                    .await?;
                true
            }
            Some(_) => {
                sqlx::query(
                    "UPDATE approval_delivery_pins SET ref_count = ref_count - 1 \
                     WHERE approval_id = ?",
                )
                .bind(&identity.approval_id)
                .execute(&mut *transaction)
                .await?;
                true
            }
            None => false,
        };
        enforce_retention(&mut transaction).await?;
        transaction.commit().await?;
        Ok(released)
    }

    async fn delivery_pin_exists(&self, id: &str) -> Result<bool, ApprovalError> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM approval_delivery_pins WHERE approval_id = ?)",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?
            != 0)
    }

    async fn clear_delivery_pins(&self) -> Result<u64, ApprovalError> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let affected = sqlx::query("DELETE FROM approval_delivery_pins")
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        enforce_retention(&mut transaction).await?;
        transaction.commit().await?;
        Ok(affected)
    }

    async fn get_for_token(
        &self,
        id: &str,
        actor_api_token_id: &str,
    ) -> Result<Option<ApprovalOwnerDetail>, ApprovalError> {
        let row = sqlx::query_as::<_, ApprovalRow>(&format!(
            "{} WHERE id = ? AND actor_kind = 'api_token' AND actor_api_token_id = ?",
            APPROVAL_SELECT
        ))
        .bind(id)
        .bind(actor_api_token_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| self.decode_owner_detail(row)).transpose()
    }

    async fn get_for_actor(
        &self,
        id: &str,
        actor: &ToolActor,
    ) -> Result<Option<ApprovalOwnerDetail>, ApprovalError> {
        let row = sqlx::query_as::<_, ApprovalRow>(&format!(
            "{} WHERE id = ? AND actor_kind = ? AND actor_id = ?",
            APPROVAL_SELECT
        ))
        .bind(id)
        .bind(actor.kind().as_str())
        .bind(actor.id())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| self.decode_owner_detail(row)).transpose()
    }

    async fn list_admin(&self, query: ApprovalListQuery) -> Result<ApprovalPage, ApprovalError> {
        let limit = if query.limit == 0 {
            50
        } else {
            query.limit.min(MAX_APPROVAL_PAGE_LIMIT)
        };
        let before = query.before_sequence.unwrap_or(i64::MAX);
        if before <= 0 {
            return Err(ApprovalError::Validation {
                code: "invalid_approval_cursor",
                message: "approval cursor must be a positive integer".to_owned(),
            });
        }
        let fetch_limit = i64::from(limit) + 1;
        let rows = if let Some(status) = query.status {
            sqlx::query_as::<_, ApprovalRow>(&format!(
                "{} WHERE sequence < ? AND status = ? ORDER BY sequence DESC LIMIT ?",
                APPROVAL_SELECT
            ))
            .bind(before)
            .bind(status.as_str())
            .bind(fetch_limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, ApprovalRow>(&format!(
                "{} WHERE sequence < ? ORDER BY sequence DESC LIMIT ?",
                APPROVAL_SELECT
            ))
            .bind(before)
            .bind(fetch_limit)
            .fetch_all(&self.pool)
            .await?
        };
        let has_more = rows.len() > limit as usize;
        let mut items = rows
            .into_iter()
            .take(limit as usize)
            .map(|row| row.record())
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = has_more
            .then(|| items.last().map(|item| item.sequence))
            .flatten();
        items.shrink_to_fit();
        Ok(ApprovalPage { items, next_cursor })
    }

    async fn log_outbox(&self, limit: u32) -> Result<Vec<NewRequestLog>, ApprovalError> {
        let limit = i64::from(limit.clamp(1, 256));
        let rows = sqlx::query_as::<_, ApprovalLogOutboxRow>(
            "SELECT outbox.request_id, outbox.approval_id, outbox.actor_api_token_id, \
             outbox.surface, \
             CASE WHEN EXISTS(SELECT 1 FROM sources WHERE id = outbox.source_id) \
                  THEN outbox.source_id ELSE NULL END AS source_id, \
             CASE WHEN EXISTS(SELECT 1 FROM tools WHERE id = outbox.tool_id) \
                  THEN outbox.tool_id ELSE NULL END AS tool_id, \
             outbox.path_snapshot, outbox.outcome, outbox.error_code, outbox.created_at \
             FROM approval_log_outbox AS outbox ORDER BY rowid LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(NewRequestLog {
                    request_id: row.request_id,
                    actor_api_token_id: row.actor_api_token_id,
                    surface: row
                        .surface
                        .parse()
                        .map_err(|_| ApprovalError::CorruptData("approval log surface"))?,
                    source_id: row.source_id,
                    tool_id: row.tool_id,
                    path_snapshot: Some(row.path_snapshot),
                    outcome: row
                        .outcome
                        .parse()
                        .map_err(|_| ApprovalError::CorruptData("approval log outcome"))?,
                    error_code: row.error_code,
                    duration_ms: 0,
                    approval_id: Some(row.approval_id),
                    created_at: row.created_at,
                })
            })
            .collect()
    }

    async fn acknowledge_log_outbox(&self, request_id: &str) -> Result<(), ApprovalError> {
        validate_identifier("request ID", request_id, 128)?;
        sqlx::query("DELETE FROM approval_log_outbox WHERE request_id = ?")
            .bind(request_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn decide(
        &self,
        id: &str,
        decision_id: &str,
        expected_revision: i64,
        decision: ApprovalDecision,
        admin_id: i64,
    ) -> Result<DecisionResult, ApprovalError> {
        validate_identifier("decision ID", decision_id, 128)?;
        if expected_revision < 0 || admin_id <= 0 {
            return Err(ApprovalError::Validation {
                code: "invalid_approval_decision",
                message: "approval decision metadata is invalid".to_owned(),
            });
        }
        self.expire_pending().await?;
        let observed_now = self.advance_clock().await?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;

        let current = fetch_row_in(&mut transaction, id)
            .await?
            .ok_or(ApprovalError::NotFound)?;
        if let Some(existing) = current.decision.as_deref() {
            let existing: ApprovalDecision = existing.parse()?;
            if existing == decision {
                enforce_retention(&mut transaction).await?;
                transaction.commit().await?;
                return Ok(DecisionResult {
                    record: current.record()?,
                    idempotent: true,
                });
            }
            return Err(ApprovalError::DecisionConflict);
        }
        let current_status: ApprovalStatus = current.status.parse()?;
        if current_status == ApprovalStatus::Expired {
            return Err(ApprovalError::Expired);
        }
        if current_status != ApprovalStatus::Pending {
            return Err(ApprovalError::DecisionConflict);
        }
        if current.revision != expected_revision {
            return Err(ApprovalError::RevisionConflict {
                expected: expected_revision,
                actual: current.revision,
            });
        }
        let completed_at = (decision == ApprovalDecision::Deny).then_some(now);
        let updated = sqlx::query(
            "UPDATE approvals SET status = ?, revision = revision + 1, decision_id = ?, \
             decision = ?, decided_by_admin_id = ?, decided_at = ?, updated_at = ?, completed_at = ? \
             WHERE id = ? AND status = 'pending' AND revision = ? AND expires_at > ?",
        )
        .bind(decision.status().as_str())
        .bind(decision_id)
        .bind(decision.as_str())
        .bind(admin_id)
        .bind(now)
        .bind(now)
        .bind(completed_at)
        .bind(id)
        .bind(expected_revision)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            if fetch_row_in(&mut transaction, id)
                .await?
                .is_some_and(|row| row.status == "pending" && row.expires_at <= now)
            {
                expire_pending_in(&mut transaction, now).await?;
                enforce_retention(&mut transaction).await?;
                transaction.commit().await?;
                return Err(ApprovalError::Expired);
            }
            return Err(classify_cas_failure(&mut transaction, id, expected_revision).await?);
        }
        let audit_id = Uuid::new_v4().to_string();
        let audit_metadata = serde_json::to_string(&serde_json::json!({
            "approvalId": id,
            "from": ApprovalStatus::Pending.as_str(),
            "to": decision.status().as_str(),
            "revision": expected_revision + 1,
        }))?;
        sqlx::query(
            "INSERT INTO audit_events (id, request_id, actor_admin_id, action, source_id, tool_id, \
             target_path_snapshot, metadata_json, created_at) SELECT ?, ?, ?, ?, \
             CASE WHEN EXISTS (SELECT 1 FROM sources WHERE id = ?) THEN ? ELSE NULL END, \
             CASE WHEN EXISTS (SELECT 1 FROM tools WHERE id = ?) THEN ? ELSE NULL END, \
             callable_path_snapshot, ?, ? FROM approvals WHERE id = ?",
        )
        .bind(audit_id)
        .bind(decision_id)
        .bind(admin_id)
        .bind(match decision {
            ApprovalDecision::Approve => "approval.approve",
            ApprovalDecision::Deny => "approval.deny",
        })
        .bind(&current.source_id)
        .bind(&current.source_id)
        .bind(&current.tool_id)
        .bind(&current.tool_id)
        .bind(audit_metadata)
        .bind(now)
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        enforce_audit_retention(&mut transaction).await?;
        let record = fetch_row_in(&mut transaction, id)
            .await?
            .ok_or(ApprovalError::NotFound)?
            .record()?;
        enforce_retention(&mut transaction).await?;
        transaction.commit().await?;
        Ok(DecisionResult {
            record,
            idempotent: false,
        })
    }

    async fn claim_execution(
        &self,
        id: &str,
        worker_generation: u64,
        expected_revision: i64,
    ) -> Result<ApprovalExecutionSnapshot, ApprovalError> {
        let worker_generation =
            i64::try_from(worker_generation).map_err(|_| ApprovalError::Validation {
                code: "invalid_worker_generation",
                message: "worker generation exceeds the supported range".to_owned(),
            })?;
        self.expire_pending().await?;
        let observed_now = self.advance_clock().await?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        let updated = sqlx::query(
            "UPDATE approvals SET status = 'executing', revision = revision + 1, \
             updated_at = ?, execution_started_at = ? WHERE id = ? \
             AND worker_generation = ? AND status = 'approved' AND revision = ? \
             AND (actor_kind <> 'api_token' OR EXISTS ( \
                 SELECT 1 FROM api_tokens WHERE api_tokens.id = approvals.actor_api_token_id \
                 AND api_tokens.revoked_at IS NULL))",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .bind(worker_generation)
        .bind(expected_revision)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            let row = fetch_row_in(&mut transaction, id)
                .await?
                .ok_or(ApprovalError::NotFound)?;
            if row.worker_generation != worker_generation {
                return Err(ApprovalError::WorkerGenerationConflict);
            }
            if row.revision == expected_revision
                && row.status == ApprovalStatus::Approved.as_str()
                && row.actor_kind == ActorKind::ApiToken.as_str()
                && !token_active_in(
                    &mut transaction,
                    row.actor_api_token_id
                        .as_deref()
                        .ok_or(ApprovalError::CorruptData("missing actor token ID"))?,
                )
                .await?
            {
                return Err(ApprovalError::OwnerTokenInactive);
            }
            return Err(classify_row_cas_failure(&row, expected_revision));
        }
        let row = fetch_row_in(&mut transaction, id)
            .await?
            .ok_or(ApprovalError::NotFound)?;
        let snapshot = self.decode_execution_snapshot(row)?;
        transaction.commit().await?;
        Ok(snapshot)
    }

    async fn mark_stale(
        &self,
        id: &str,
        expected_revision: i64,
        failure_code: &str,
    ) -> Result<ApprovalRecord, ApprovalError> {
        validate_failure_code(failure_code)?;
        self.transition(
            id,
            expected_revision,
            Transition {
                from: ApprovalStatus::Approved,
                to: ApprovalStatus::Stale,
                failure_code: Some(failure_code),
                result_ciphertext: None,
            },
        )
        .await
    }

    async fn finish(
        &self,
        id: &str,
        expected_revision: i64,
        outcome: ExecutionOutcome,
        result: &Value,
        failure_code: Option<&str>,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let _transition_permit = self
            .transition_slot
            .acquire()
            .await
            .expect("approval transition semaphore is never closed");
        if let Some(code) = failure_code {
            validate_failure_code(code)?;
        }
        if outcome == ExecutionOutcome::Succeeded && failure_code.is_some() {
            return Err(ApprovalError::Validation {
                code: "invalid_approval_result",
                message: "a successful approval execution cannot have a failure code".to_owned(),
            });
        }
        let encoded = encode_json("result", result, MAX_APPROVAL_RESULT_BYTES)?;
        let ciphertext = self.keyring.encrypt("approval-result", id, &encoded)?;
        self.transition_inner(
            id,
            expected_revision,
            Transition {
                from: ApprovalStatus::Executing,
                to: outcome.status(),
                failure_code,
                result_ciphertext: Some(ciphertext),
            },
        )
        .await
    }

    async fn expire_pending(&self) -> Result<u64, ApprovalError> {
        let observed_now = self.advance_clock().await?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        let affected = expire_pending_in(&mut transaction, now).await?;
        enforce_retention(&mut transaction).await?;
        transaction.commit().await?;
        Ok(affected)
    }

    async fn cancel_token_owner(
        &self,
        id: &str,
        actor_api_token_id: &str,
        expected_revision: i64,
    ) -> Result<ApprovalRecord, ApprovalError> {
        self.expire_pending().await?;
        let observed_now = self.advance_clock().await?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        let updated = sqlx::query(
            "UPDATE approvals SET status = 'canceled', revision = revision + 1, \
             updated_at = ?, completed_at = ? \
             WHERE id = ? AND actor_kind = 'api_token' AND actor_api_token_id = ? AND revision = ? \
             AND status IN ('pending', 'approved')",
        )
        .bind(now)
        .bind(now)
        .bind(id)
        .bind(actor_api_token_id)
        .bind(expected_revision)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            let row = fetch_row_in(&mut transaction, id)
                .await?
                .ok_or(ApprovalError::NotFound)?;
            if row.actor_kind != ActorKind::ApiToken.as_str()
                || row.actor_api_token_id.as_deref() != Some(actor_api_token_id)
            {
                return Err(ApprovalError::NotFound);
            }
            if row.status == ApprovalStatus::Canceled.as_str() {
                let record = row.record()?;
                transaction.commit().await?;
                return Ok(record);
            }
            return Err(classify_row_cas_failure(&row, expected_revision));
        }
        let record = fetch_row_in(&mut transaction, id)
            .await?
            .ok_or(ApprovalError::NotFound)?
            .record()?;
        enforce_retention(&mut transaction).await?;
        transaction.commit().await?;
        Ok(record)
    }

    async fn cancel_execution(&self, execution_id: &str) -> Result<u64, ApprovalError> {
        validate_identifier("execution ID", execution_id, 128)?;
        self.cancel_where("execution_id", execution_id, true).await
    }

    #[cfg(test)]
    async fn cancel_token(&self, actor_api_token_id: &str) -> Result<u64, ApprovalError> {
        validate_identifier("owner token ID", actor_api_token_id, 128)?;
        self.cancel_where("actor_api_token_id", actor_api_token_id, false)
            .await
    }

    async fn revoke_owner_token(&self, actor_api_token_id: &str) -> Result<bool, ApprovalError> {
        validate_identifier("owner token ID", actor_api_token_id, 128)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let now = effective_now_in(&mut transaction, self.clock.now()).await?;
        let revoked =
            sqlx::query("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
                .bind(now)
                .bind(actor_api_token_id)
                .execute(&mut *transaction)
                .await?;
        if revoked.rows_affected() == 0 {
            transaction.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "UPDATE approvals SET status = 'canceled', revision = revision + 1, \
             updated_at = ?, completed_at = ? WHERE actor_kind = 'api_token' \
             AND actor_api_token_id = ? \
             AND status IN ('pending', 'approved')",
        )
        .bind(now)
        .bind(now)
        .bind(actor_api_token_id)
        .execute(&mut *transaction)
        .await?;
        enforce_retention(&mut transaction).await?;
        transaction.commit().await?;
        Ok(true)
    }

    async fn recover_startup(&self) -> Result<StartupRecovery, ApprovalError> {
        let observed_now = self.advance_clock().await?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        expire_pending_in(&mut transaction, now).await?;
        sqlx::query(
            "UPDATE approvals SET status = 'canceled', revision = revision + 1, \
             updated_at = ?, completed_at = ? WHERE status IN ('pending', 'approved') \
             AND actor_kind = 'api_token' \
             AND EXISTS (SELECT 1 FROM api_tokens WHERE api_tokens.id = approvals.actor_api_token_id \
                         AND api_tokens.revoked_at IS NOT NULL)",
        )
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let _interrupted_count = sqlx::query(
            "UPDATE approvals SET status = 'interrupted', revision = revision + 1, \
             failure_code = 'server_restart', updated_at = ?, completed_at = ? \
             WHERE status = 'executing'",
        )
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        sqlx::query(
            "UPDATE approvals SET status = 'canceled', revision = revision + 1, \
             failure_code = 'continuation_lost', updated_at = ?, completed_at = ? \
             WHERE status = 'pending' AND worker_generation > 0",
        )
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE approvals SET status = 'stale', revision = revision + 1, \
             failure_code = 'continuation_lost', updated_at = ?, completed_at = ? \
             WHERE status = 'approved' AND worker_generation > 0",
        )
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let approved_ids = sqlx::query_scalar::<_, String>(
            "SELECT id FROM approvals WHERE status = 'approved' AND worker_generation = 0 \
             ORDER BY sequence ASC",
        )
        .fetch_all(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM approval_delivery_pins")
            .execute(&mut *transaction)
            .await?;
        enforce_retention(&mut transaction).await?;
        transaction.commit().await?;
        Ok(StartupRecovery {
            #[cfg(test)]
            interrupted_count: _interrupted_count,
            approved_ids,
        })
    }

    async fn transition(
        &self,
        id: &str,
        expected_revision: i64,
        transition: Transition<'_>,
    ) -> Result<ApprovalRecord, ApprovalError> {
        let _transition_permit = self
            .transition_slot
            .acquire()
            .await
            .expect("approval transition semaphore is never closed");
        self.transition_inner(id, expected_revision, transition)
            .await
    }

    async fn transition_inner(
        &self,
        id: &str,
        expected_revision: i64,
        transition: Transition<'_>,
    ) -> Result<ApprovalRecord, ApprovalError> {
        if expected_revision < 0 {
            return Err(ApprovalError::Validation {
                code: "invalid_approval_revision",
                message: "approval revision cannot be negative".to_owned(),
            });
        }
        self.expire_pending().await?;
        let observed_now = self.advance_clock().await?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        let completed_at = transition.to.is_terminal().then_some(now);
        let updated = sqlx::query(
            "UPDATE approvals SET status = ?, revision = revision + 1, failure_code = ?, \
             result_ciphertext = COALESCE(?, result_ciphertext), updated_at = ?, \
             completed_at = ? WHERE id = ? AND status = ? AND revision = ?",
        )
        .bind(transition.to.as_str())
        .bind(transition.failure_code)
        .bind(transition.result_ciphertext)
        .bind(now)
        .bind(completed_at)
        .bind(id)
        .bind(transition.from.as_str())
        .bind(expected_revision)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(classify_cas_failure(&mut transaction, id, expected_revision).await?);
        }
        let record = fetch_row_in(&mut transaction, id)
            .await?
            .ok_or(ApprovalError::NotFound)?
            .record()?;
        enforce_retention(&mut transaction).await?;
        transaction.commit().await?;
        Ok(record)
    }

    async fn cancel_where(
        &self,
        column: &'static str,
        value: &str,
        release_delivery_pins: bool,
    ) -> Result<u64, ApprovalError> {
        let observed_now = self.advance_clock().await?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        expire_pending_in(&mut transaction, now).await?;
        if release_delivery_pins {
            sqlx::query(&format!(
                "DELETE FROM approval_delivery_pins WHERE approval_id IN ( \
                     SELECT id FROM approvals WHERE {column} = ? \
                     AND status IN ('pending', 'approved') \
                 )"
            ))
            .bind(value)
            .execute(&mut *transaction)
            .await?;
        }
        let result = sqlx::query(&format!(
            "UPDATE approvals SET status = 'canceled', revision = revision + 1, \
             updated_at = ?, completed_at = ? WHERE {column} = ? \
             AND status IN ('pending', 'approved')"
        ))
        .bind(now)
        .bind(now)
        .bind(value)
        .execute(&mut *transaction)
        .await?;
        enforce_retention(&mut transaction).await?;
        transaction.commit().await?;
        Ok(result.rows_affected())
    }

    async fn advance_clock(&self) -> Result<i64, ApprovalError> {
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, self.clock.now()).await?;
        transaction.commit().await?;
        Ok(now)
    }

    fn decode_admin_detail(&self, row: ApprovalRow) -> Result<ApprovalAdminDetail, ApprovalError> {
        let redacted_arguments = decrypt_json(
            &self.keyring,
            "approval-redacted-arguments",
            &row.id,
            &row.redacted_arguments_ciphertext,
        )?;
        let input_schema = decrypt_json(
            &self.keyring,
            "approval-input-schema",
            &row.id,
            &row.input_schema_ciphertext,
        )?;
        let record = row.record()?;
        Ok(ApprovalAdminDetail {
            record,
            redacted_arguments,
            input_schema,
        })
    }

    fn decode_owner_detail(&self, row: ApprovalRow) -> Result<ApprovalOwnerDetail, ApprovalError> {
        let result = row
            .result_ciphertext
            .as_deref()
            .map(|sealed| decrypt_json(&self.keyring, "approval-result", &row.id, sealed))
            .transpose()?;
        let record = row.record()?;
        Ok(ApprovalOwnerDetail { record, result })
    }

    fn decode_execution_snapshot(
        &self,
        row: ApprovalRow,
    ) -> Result<ApprovalExecutionSnapshot, ApprovalError> {
        let arguments = decrypt_json(
            &self.keyring,
            "approval-arguments",
            &row.id,
            &row.arguments_ciphertext,
        )?;
        let input_schema = decrypt_json(
            &self.keyring,
            "approval-input-schema",
            &row.id,
            &row.input_schema_ciphertext,
        )?;
        let output_schema = row
            .output_schema_ciphertext
            .as_deref()
            .map(|sealed| decrypt_json(&self.keyring, "approval-output-schema", &row.id, sealed))
            .transpose()?;
        let invocation_snapshot = decrypt_json(
            &self.keyring,
            "approval-invocation-snapshot",
            &row.id,
            &row.invocation_snapshot_ciphertext,
        )?;
        let result = row
            .result_ciphertext
            .as_deref()
            .map(|sealed| decrypt_json(&self.keyring, "approval-result", &row.id, sealed))
            .transpose()?;
        let record = row.record()?;
        Ok(ApprovalExecutionSnapshot {
            record,
            arguments,
            input_schema,
            output_schema,
            invocation_snapshot,
            result,
        })
    }
}

#[derive(FromRow)]
struct ApprovalRow {
    sequence: i64,
    id: String,
    execution_id: String,
    call_id: String,
    worker_generation: i64,
    actor_kind: String,
    actor_id: String,
    actor_api_token_id: Option<String>,
    actor_name_snapshot: Option<String>,
    surface: String,
    source_id: String,
    tool_id: String,
    callable_path_snapshot: String,
    source_display_name_snapshot: Option<String>,
    tool_display_name_snapshot: Option<String>,
    mode_provenance: String,
    source_revision: i64,
    catalog_revision: i64,
    tool_revision: i64,
    binding_revision: i64,
    credential_revision: Option<i64>,
    arguments_ciphertext: Vec<u8>,
    redacted_arguments_ciphertext: Vec<u8>,
    input_schema_ciphertext: Vec<u8>,
    output_schema_ciphertext: Option<Vec<u8>>,
    invocation_snapshot_ciphertext: Vec<u8>,
    result_ciphertext: Option<Vec<u8>>,
    status: String,
    revision: i64,
    decision_id: Option<String>,
    decision: Option<String>,
    decided_by_admin_id: Option<i64>,
    failure_code: Option<String>,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
    decided_at: Option<i64>,
    execution_started_at: Option<i64>,
    completed_at: Option<i64>,
}

#[derive(FromRow)]
struct ApprovalLogOutboxRow {
    request_id: String,
    approval_id: String,
    actor_api_token_id: Option<String>,
    surface: String,
    source_id: Option<String>,
    tool_id: Option<String>,
    path_snapshot: String,
    outcome: String,
    error_code: Option<String>,
    created_at: i64,
}

#[derive(FromRow)]
struct ApprovalCorrelationRow {
    approval_id: String,
    actor_kind: String,
    actor_id: String,
    surface: String,
    worker_generation: i64,
    callable_path: String,
    arguments_digest: Vec<u8>,
}

impl ApprovalRow {
    fn record(&self) -> Result<ApprovalRecord, ApprovalError> {
        let actor = ToolActor::from_stored(
            &self.actor_kind,
            self.actor_id.clone(),
            self.actor_api_token_id.clone(),
            self.actor_name_snapshot.clone(),
        )
        .ok_or(ApprovalError::CorruptData("invalid approval actor"))?;
        Ok(ApprovalRecord {
            sequence: self.sequence,
            id: self.id.clone(),
            execution_id: self.execution_id.clone(),
            call_id: self.call_id.clone(),
            worker_generation: u64::try_from(self.worker_generation)
                .map_err(|_| ApprovalError::CorruptData("negative worker generation"))?,
            actor_kind: actor.kind(),
            actor_id: actor.id(),
            actor_api_token_id: actor.api_token_id().map(str::to_owned),
            actor_name_snapshot: actor.name_snapshot().map(str::to_owned),
            surface: self
                .surface
                .parse()
                .map_err(|_| ApprovalError::CorruptData("unknown approval surface"))?,
            callable_path_snapshot: self.callable_path_snapshot.clone(),
            source_display_name: self.source_display_name_snapshot.clone(),
            tool_display_name: self.tool_display_name_snapshot.clone(),
            mode_provenance: parse_mode_provenance(&self.mode_provenance)?,
            revisions: InvocationRevisionTokenSnapshot {
                source_id: self.source_id.clone(),
                tool_id: self.tool_id.clone(),
                source_revision: self.source_revision,
                catalog_revision: self.catalog_revision,
                tool_revision: self.tool_revision,
                binding_revision: self.binding_revision,
                credential_revision: self.credential_revision,
            },
            status: self.status.parse()?,
            revision: self.revision,
            decision_id: self.decision_id.clone(),
            decision: self.decision.as_deref().map(str::parse).transpose()?,
            decided_by_admin_id: self.decided_by_admin_id,
            failure_code: self.failure_code.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            expires_at: self.expires_at,
            decided_at: self.decided_at,
            execution_started_at: self.execution_started_at,
            completed_at: self.completed_at,
        })
    }
}

const APPROVAL_SELECT: &str = "SELECT sequence, id, execution_id, call_id, worker_generation, \
    actor_kind, actor_id, actor_api_token_id, actor_name_snapshot, surface, source_id, tool_id, callable_path_snapshot, \
    source_display_name_snapshot, tool_display_name_snapshot, mode_provenance, source_revision, catalog_revision, \
    tool_revision, binding_revision, credential_revision, arguments_ciphertext, redacted_arguments_ciphertext, \
    input_schema_ciphertext, output_schema_ciphertext, invocation_snapshot_ciphertext, \
    result_ciphertext, status, revision, decision_id, decision, decided_by_admin_id, failure_code, \
    created_at, updated_at, expires_at, decided_at, execution_started_at, completed_at FROM approvals";

async fn fetch_row(pool: &SqlitePool, id: &str) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRow>(&format!("{} WHERE id = ?", APPROVAL_SELECT))
        .bind(id)
        .fetch_optional(pool)
        .await
}

async fn fetch_row_in(
    transaction: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalRow>(&format!("{} WHERE id = ?", APPROVAL_SELECT))
        .bind(id)
        .fetch_optional(&mut **transaction)
        .await
}

async fn fetch_correlation_in(
    transaction: &mut Transaction<'_, Sqlite>,
    actor_kind: &str,
    actor_id: &str,
    execution_id: &str,
    call_id: &str,
) -> Result<Option<ApprovalCorrelationRow>, sqlx::Error> {
    sqlx::query_as::<_, ApprovalCorrelationRow>(
        "SELECT approval_id, actor_kind, actor_id, surface, worker_generation, \
         callable_path, arguments_digest FROM approval_correlations \
         WHERE actor_kind = ? AND actor_id = ? AND execution_id = ? AND call_id = ?",
    )
    .bind(actor_kind)
    .bind(actor_id)
    .bind(execution_id)
    .bind(call_id)
    .fetch_optional(&mut **transaction)
    .await
}

fn ensure_same_correlation(
    existing: &ApprovalCorrelationRow,
    actor_kind: &str,
    actor_id: &str,
    surface: RequestSurface,
    worker_generation: i64,
    callable_path: &str,
    arguments_digest: &[u8],
) -> Result<(), ApprovalError> {
    if existing.actor_kind == actor_kind
        && existing.actor_id == actor_id
        && existing.surface == surface.as_str()
        && existing.worker_generation == worker_generation
        && existing.callable_path == callable_path
        && existing.arguments_digest == arguments_digest
    {
        Ok(())
    } else {
        Err(ApprovalError::CorrelationConflict)
    }
}

async fn effective_now_in(
    transaction: &mut Transaction<'_, Sqlite>,
    observed_now: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query("UPDATE approval_clock SET effective_now = MAX(effective_now, ?) WHERE id = 1")
        .bind(observed_now.max(0))
        .execute(&mut **transaction)
        .await?;
    sqlx::query_scalar("SELECT effective_now FROM approval_clock WHERE id = 1")
        .fetch_one(&mut **transaction)
        .await
}

async fn active_count_in(
    transaction: &mut Transaction<'_, Sqlite>,
    actor: Option<(&str, &str)>,
) -> Result<i64, sqlx::Error> {
    if let Some((actor_kind, actor_id)) = actor {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM approvals WHERE status IN ('pending', 'approved', 'executing') \
             AND actor_kind = ? AND actor_id = ?",
        )
        .bind(actor_kind)
        .bind(actor_id)
        .fetch_one(&mut **transaction)
        .await
    } else {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM approvals WHERE status IN ('pending', 'approved', 'executing')",
        )
        .fetch_one(&mut **transaction)
        .await
    }
}

async fn active_ciphertext_bytes_in(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COALESCE(SUM( \
             length(arguments_ciphertext) + length(redacted_arguments_ciphertext) \
             + length(input_schema_ciphertext) + COALESCE(length(output_schema_ciphertext), 0) \
             + length(invocation_snapshot_ciphertext) + COALESCE(length(result_ciphertext), 0) \
         ), 0) FROM approvals WHERE status IN ('pending', 'approved', 'executing')",
    )
    .fetch_one(&mut **transaction)
    .await
}

fn existing_ciphertext_bytes(row: &ApprovalRow) -> Result<i64, ApprovalError> {
    [
        row.arguments_ciphertext.len(),
        row.redacted_arguments_ciphertext.len(),
        row.input_schema_ciphertext.len(),
        row.output_schema_ciphertext.as_ref().map_or(0, Vec::len),
        row.invocation_snapshot_ciphertext.len(),
    ]
    .into_iter()
    .try_fold(0_i64, |total, length| {
        i64::try_from(length)
            .ok()
            .and_then(|length| total.checked_add(length))
    })
    .ok_or(ApprovalError::Capacity {
        scope: "delivery_pin_bytes",
    })
}

async fn add_delivery_pin_in(
    transaction: &mut Transaction<'_, Sqlite>,
    approval_id: &str,
    snapshot_ciphertext_bytes: i64,
    now: i64,
) -> Result<(), ApprovalError> {
    let (pin_count, ref_count, pinned_bytes) = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT COUNT(*), COALESCE(SUM(ref_count), 0), \
         COALESCE(SUM(snapshot_ciphertext_bytes), 0) FROM approval_delivery_pins",
    )
    .fetch_one(&mut **transaction)
    .await?;
    let existing = sqlx::query_as::<_, (i64, i64)>(
        "SELECT ref_count, snapshot_ciphertext_bytes FROM approval_delivery_pins \
         WHERE approval_id = ?",
    )
    .bind(approval_id)
    .fetch_optional(&mut **transaction)
    .await?;
    if ref_count >= MAX_APPROVAL_DELIVERY_PIN_REFS {
        return Err(ApprovalError::Capacity {
            scope: "delivery_pins",
        });
    }
    if let Some((approval_refs, stored_bytes)) = existing {
        if approval_refs >= MAX_APPROVAL_DELIVERY_PIN_REFS
            || stored_bytes != snapshot_ciphertext_bytes
        {
            return Err(ApprovalError::Capacity {
                scope: "delivery_pins",
            });
        }
        sqlx::query(
            "UPDATE approval_delivery_pins SET ref_count = ref_count + 1 WHERE approval_id = ?",
        )
        .bind(approval_id)
        .execute(&mut **transaction)
        .await?;
        return Ok(());
    }
    if pin_count >= MAX_APPROVAL_DELIVERY_PINS
        || pinned_bytes
            .checked_add(snapshot_ciphertext_bytes)
            .is_none_or(|bytes| bytes > MAX_PINNED_SNAPSHOT_CIPHERTEXT_BYTES)
    {
        return Err(ApprovalError::Capacity {
            scope: "delivery_pins",
        });
    }
    sqlx::query(
        "INSERT INTO approval_delivery_pins \
         (approval_id, ref_count, snapshot_ciphertext_bytes, created_at) VALUES (?, 1, ?, ?)",
    )
    .bind(approval_id)
    .bind(snapshot_ciphertext_bytes)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn token_active_in(
    transaction: &mut Transaction<'_, Sqlite>,
    actor_api_token_id: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM api_tokens WHERE id = ? AND revoked_at IS NULL)",
    )
    .bind(actor_api_token_id)
    .fetch_one(&mut **transaction)
    .await
    .map(|active| active != 0)
}

async fn expire_pending_in(
    transaction: &mut Transaction<'_, Sqlite>,
    now: i64,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "UPDATE approvals SET status = 'expired', revision = revision + 1, \
         updated_at = ?, completed_at = ? WHERE status = 'pending' AND expires_at <= ?",
    )
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
}

async fn reclaim_expired_correlations_in(
    transaction: &mut Transaction<'_, Sqlite>,
    now: i64,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "DELETE FROM approval_correlations \
         WHERE expires_at IS NOT NULL AND expires_at <= ? \
           AND NOT EXISTS ( \
               SELECT 1 FROM approval_delivery_pins \
               WHERE approval_delivery_pins.approval_id = approval_correlations.approval_id \
           ) \
           AND NOT EXISTS ( \
               SELECT 1 FROM gateway_invocation_idempotency \
               WHERE gateway_invocation_idempotency.approval_correlation_id = approval_correlations.approval_id \
                 AND (gateway_invocation_idempotency.expires_at IS NULL \
                      OR gateway_invocation_idempotency.expires_at > ?) \
           ) \
           AND NOT EXISTS ( \
               SELECT 1 FROM gateway_invocation_idempotency \
               WHERE gateway_invocation_idempotency.state IN ('reserved', 'executing') \
                 AND gateway_invocation_idempotency.owner_api_token_id = approval_correlations.actor_id \
                 AND approval_correlations.actor_kind = 'api_token' \
                 AND approval_correlations.call_id = 'gateway' \
                 AND approval_correlations.execution_id = \
                     'gateway-idempotency:' || gateway_invocation_idempotency.id \
           )",
    )
    .bind(now)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
}

async fn enforce_retention(transaction: &mut Transaction<'_, Sqlite>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR IGNORE INTO approval_terminal_order (approval_id) \
         SELECT id FROM approvals WHERE status IN ( \
             'denied', 'expired', 'canceled', 'succeeded', 'failed', 'stale', 'interrupted' \
         ) ORDER BY completed_at, sequence",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "DELETE FROM approvals WHERE id IN ( \
             SELECT approvals.id FROM approvals \
             JOIN approval_terminal_order ON approval_terminal_order.approval_id = approvals.id \
             WHERE NOT EXISTS (SELECT 1 FROM approval_delivery_pins \
                               WHERE approval_delivery_pins.approval_id = approvals.id) \
             ORDER BY approval_terminal_order.sequence DESC LIMIT -1 OFFSET ? \
         )",
    )
    .bind(TERMINAL_RETENTION)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "WITH terminal_usage AS ( \
             SELECT approvals.id, SUM( \
                 length(arguments_ciphertext) + length(redacted_arguments_ciphertext) \
                 + length(input_schema_ciphertext) + COALESCE(length(output_schema_ciphertext), 0) \
                 + length(invocation_snapshot_ciphertext) + COALESCE(length(result_ciphertext), 0) \
             ) OVER (ORDER BY approval_terminal_order.sequence DESC \
                     ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS retained_bytes \
             FROM approvals JOIN approval_terminal_order \
               ON approval_terminal_order.approval_id = approvals.id \
             WHERE NOT EXISTS (SELECT 1 FROM approval_delivery_pins \
                               WHERE approval_delivery_pins.approval_id = approvals.id) \
         ) DELETE FROM approvals WHERE id IN ( \
             SELECT id FROM terminal_usage WHERE retained_bytes > ? \
         )",
    )
    .bind(MAX_TERMINAL_APPROVAL_CIPHERTEXT_BYTES)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn enforce_audit_retention(
    transaction: &mut Transaction<'_, Sqlite>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM audit_events WHERE rowid IN (SELECT rowid FROM audit_events \
         ORDER BY rowid DESC LIMIT -1 OFFSET ?)",
    )
    .bind(TERMINAL_RETENTION)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn classify_cas_failure(
    transaction: &mut Transaction<'_, Sqlite>,
    id: &str,
    expected_revision: i64,
) -> Result<ApprovalError, sqlx::Error> {
    let Some(row) = fetch_row_in(transaction, id).await? else {
        return Ok(ApprovalError::NotFound);
    };
    Ok(classify_row_cas_failure(&row, expected_revision))
}

fn classify_row_cas_failure(row: &ApprovalRow, expected_revision: i64) -> ApprovalError {
    if row.revision != expected_revision {
        ApprovalError::RevisionConflict {
            expected: expected_revision,
            actual: row.revision,
        }
    } else {
        match row.status.parse() {
            Ok(status) => ApprovalError::InvalidTransition { status },
            Err(error) => error,
        }
    }
}

fn mode_provenance_str(provenance: ModeProvenance) -> &'static str {
    match provenance {
        ModeProvenance::ToolOverride => "tool_override",
        ModeProvenance::SourceOverride => "source_override",
        ModeProvenance::Intrinsic => "intrinsic",
    }
}

fn parse_mode_provenance(value: &str) -> Result<ModeProvenance, ApprovalError> {
    match value {
        "tool_override" => Ok(ModeProvenance::ToolOverride),
        "source_override" => Ok(ModeProvenance::SourceOverride),
        "intrinsic" => Ok(ModeProvenance::Intrinsic),
        _ => Err(ApprovalError::CorruptData("unknown mode provenance")),
    }
}

fn validate_new(new: &NewApproval) -> Result<(), ApprovalError> {
    validate_identifier("execution ID", &new.execution_id, 128)?;
    validate_identifier("call ID", &new.call_id, 128)?;
    validate_identifier("actor ID", &new.actor.id(), 128)?;
    if new.surface == RequestSurface::Admin {
        return Err(ApprovalError::Validation {
            code: "invalid_approval_surface",
            message: "admin requests cannot own tool approvals".to_owned(),
        });
    }
    if let Some(name) = new.actor.name_snapshot() {
        validate_identifier("actor name snapshot", name, 200)?;
    }
    validate_identifier("source ID", &new.revisions.source_id, 128)?;
    validate_identifier("tool ID", &new.revisions.tool_id, 128)?;
    validate_identifier("callable path snapshot", &new.callable_path_snapshot, 512)?;
    if let Some(name) = &new.source_display_name_snapshot {
        validate_identifier("source display name snapshot", name, 300)?;
    }
    if let Some(name) = &new.tool_display_name_snapshot {
        validate_identifier("tool display name snapshot", name, 300)?;
    }
    if [
        new.revisions.source_revision,
        new.revisions.catalog_revision,
        new.revisions.tool_revision,
        new.revisions.binding_revision,
    ]
    .into_iter()
    .any(|revision| revision < 0)
        || new
            .revisions
            .credential_revision
            .is_some_and(|revision| revision < 0)
    {
        return Err(ApprovalError::Validation {
            code: "invalid_invocation_revision",
            message: "invocation revisions cannot be negative".to_owned(),
        });
    }
    Ok(())
}

fn redact_arguments(arguments: &Value, schema: &Value) -> Value {
    match (arguments, schema.get("type").and_then(Value::as_str)) {
        (Value::Object(arguments), Some("object")) => {
            let properties = schema.get("properties").and_then(Value::as_object);
            Value::Object(
                properties
                    .into_iter()
                    .flat_map(|properties| properties.iter())
                    .filter_map(|(name, property_schema)| {
                        arguments
                            .get(name)
                            .map(|value| (name.clone(), redact_arguments(value, property_schema)))
                    })
                    .collect(),
            )
        }
        (Value::Array(arguments), Some("array")) => {
            let item_schema = schema.get("items").unwrap_or(&Value::Null);
            Value::Array(
                arguments
                    .iter()
                    .map(|value| redact_arguments(value, item_schema))
                    .collect(),
            )
        }
        (Value::Null, _) => Value::Null,
        _ => Value::String("[redacted]".to_owned()),
    }
}

fn validate_identifier(label: &'static str, value: &str, max: usize) -> Result<(), ApprovalError> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(ApprovalError::Validation {
            code: "invalid_approval_metadata",
            message: format!("{label} must contain between 1 and {max} safe bytes"),
        });
    }
    Ok(())
}

fn validate_failure_code(code: &str) -> Result<(), ApprovalError> {
    validate_identifier("failure code", code, 128)
}

fn encode_json(label: &'static str, value: &Value, limit: usize) -> Result<Vec<u8>, ApprovalError> {
    let encoded = serde_json::to_vec(value)?;
    if encoded.len() > limit {
        return Err(ApprovalError::PayloadTooLarge { label, limit });
    }
    Ok(encoded)
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ApprovalError> {
    fn canonicalize(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
            Value::Object(values) => {
                let mut entries = values.iter().collect::<Vec<_>>();
                entries.sort_unstable_by_key(|(key, _)| *key);
                Value::Object(
                    entries
                        .into_iter()
                        .map(|(key, value)| (key.clone(), canonicalize(value)))
                        .collect(),
                )
            }
            scalar => scalar.clone(),
        }
    }

    serde_json::to_vec(&canonicalize(value)).map_err(ApprovalError::Json)
}

fn decrypt_json(
    keyring: &Keyring,
    purpose: &str,
    id: &str,
    ciphertext: &[u8],
) -> Result<Value, ApprovalError> {
    let plaintext = keyring.decrypt(purpose, id, ciphertext)?;
    serde_json::from_slice(&plaintext).map_err(ApprovalError::Json)
}

#[derive(Debug, Error)]
pub enum ApprovalError {
    #[error("approval storage failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("approval protection failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("approval JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{message}")]
    Validation { code: &'static str, message: String },
    #[error("approval {label} exceeds the {limit}-byte limit")]
    PayloadTooLarge { label: &'static str, limit: usize },
    #[error("approval was not found")]
    NotFound,
    #[error("approval has expired")]
    Expired,
    #[error("the approval owner token is missing or revoked")]
    OwnerTokenInactive,
    #[error("the {scope} active approval capacity has been reached")]
    Capacity { scope: &'static str },
    #[error("the execution call is already correlated with a different approval request")]
    CorrelationConflict,
    #[error("the execution call is correlated with an approval outside the retention window")]
    CorrelationRetired,
    #[error("approval worker generation does not match")]
    WorkerGenerationConflict,
    #[error("approval revision conflict: expected {expected}, found {actual}")]
    RevisionConflict { expected: i64, actual: i64 },
    #[error("approval has already received a conflicting decision")]
    DecisionConflict,
    #[error("approval cannot transition from {status}")]
    InvalidTransition { status: ApprovalStatus },
    #[error("stored approval data is invalid: {0}")]
    CorruptData(&'static str),
}

#[cfg(test)]
mod tests;
