use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, SqlitePool};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::{CryptoError, Keyring};

pub(crate) const IDEMPOTENCY_KEY_MAX_BYTES: usize = 255;
pub(crate) const IDEMPOTENCY_TTL_SECONDS: i64 = 24 * 60 * 60;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_RESPONSE_CIPHERTEXT_BYTES: i64 = 12 * 1024 * 1024;
const MAX_TOTAL_RESPONSE_CIPHERTEXT_BYTES: i64 = 64 * 1024 * 1024;
const MAX_RECORDS: i64 = 10_000;
const MAX_RECORDS_PER_OWNER: i64 = 1_000;

#[derive(Clone, Copy)]
struct IdempotencyLimits {
    records: i64,
    records_per_owner: i64,
    response_ciphertext_bytes: i64,
}

impl Default for IdempotencyLimits {
    fn default() -> Self {
        Self {
            records: MAX_RECORDS,
            records_per_owner: MAX_RECORDS_PER_OWNER,
            response_ciphertext_bytes: MAX_TOTAL_RESPONSE_CIPHERTEXT_BYTES,
        }
    }
}

trait IdempotencyClock: Send + Sync + 'static {
    fn now(&self) -> i64;
}

#[derive(Clone, Copy, Default)]
struct SystemClock;

impl IdempotencyClock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after the Unix epoch")
            .as_secs() as i64
    }
}

#[derive(Clone)]
pub(crate) struct GatewayIdempotencyStore {
    pool: SqlitePool,
    keyring: Keyring,
    clock: Arc<dyn IdempotencyClock>,
    limits: IdempotencyLimits,
}

#[derive(Clone, Copy)]
pub(crate) struct IdempotencyOwner<'a> {
    pub owner_api_token_id: &'a str,
}

pub(crate) struct IdempotencyRequest<'a> {
    pub owner: IdempotencyOwner<'a>,
    pub key: &'a str,
    pub route: &'a str,
    pub callable_path: &'a str,
    pub arguments: &'a Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdempotencyState {
    Reserved,
    Executing,
    Completed,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdempotencyResponseKind {
    Tool,
    Approval,
}

impl IdempotencyResponseKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Approval => "approval",
        }
    }
}

impl IdempotencyState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Executing => "executing",
            Self::Completed => "completed",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdempotencyRecord {
    pub id: String,
    pub owner_api_token_id: String,
    pub state: IdempotencyState,
    pub approval_id: Option<String>,
    pub response_kind: Option<IdempotencyResponseKind>,
    pub created_at: i64,
    pub updated_at: i64,
    pub completed_at: Option<i64>,
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct IdempotencyResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IdempotencyClaim {
    Fresh(IdempotencyRecord),
    InProgress(IdempotencyRecord),
    Replay {
        record: IdempotencyRecord,
        response: IdempotencyResponse,
    },
    Indeterminate(IdempotencyRecord),
    Mismatch,
}

pub(crate) enum CorrelatedApproval {
    Live(String),
    Retired,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct IdempotencyRecovery {
    pub indeterminate_executions: u64,
    pub reserved: Vec<IdempotencyRecord>,
}

#[derive(Debug, Error)]
pub(crate) enum IdempotencyError {
    #[error("gateway idempotency storage failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("gateway idempotency protection failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("gateway idempotency JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the Idempotency-Key must contain between 1 and 255 visible ASCII bytes")]
    InvalidKey,
    #[error("gateway idempotency metadata is invalid")]
    InvalidMetadata,
    #[error("the gateway idempotency payload exceeds the allowed size")]
    PayloadTooLarge,
    #[error("gateway idempotency capacity has been reached")]
    Capacity,
    #[error("the gateway idempotency record was not found")]
    NotFound,
    #[error("the gateway idempotency record cannot transition from {0}")]
    InvalidTransition(&'static str),
    #[error("stored gateway idempotency data is invalid")]
    CorruptData,
}

impl GatewayIdempotencyStore {
    pub(crate) fn new(pool: SqlitePool, keyring: Keyring) -> Self {
        Self {
            pool,
            keyring,
            clock: Arc::new(SystemClock),
            limits: IdempotencyLimits::default(),
        }
    }

    #[cfg(test)]
    fn with_clock(pool: SqlitePool, keyring: Keyring, clock: Arc<dyn IdempotencyClock>) -> Self {
        Self {
            pool,
            keyring,
            clock,
            limits: IdempotencyLimits::default(),
        }
    }

    #[cfg(test)]
    fn with_limits(mut self, limits: IdempotencyLimits) -> Self {
        self.limits = limits;
        self
    }

    pub(crate) async fn claim(
        &self,
        request: IdempotencyRequest<'_>,
    ) -> Result<IdempotencyClaim, IdempotencyError> {
        validate_identifier(request.owner.owner_api_token_id, 128)?;
        validate_key(request.key)?;
        validate_identifier(request.route, 200)?;
        let callable_path = canonical_callable_path(request.callable_path)?;
        let canonical_arguments = canonical_json(request.arguments)?;
        if canonical_arguments.len() > MAX_ARGUMENT_BYTES {
            return Err(IdempotencyError::PayloadTooLarge);
        }
        let key_digest = self.key_digest(request.owner, request.key);
        let request_digest = self.request_digest(
            request.owner,
            request.route,
            &callable_path,
            &canonical_arguments,
        );
        let id = Uuid::new_v4().to_string();
        let observed_now = self.clock.now().max(0);
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        delete_expired(&mut transaction, now).await?;
        let inserted = sqlx::query(
            "INSERT INTO gateway_invocation_idempotency ( \
                 id, owner_api_token_id, key_digest, request_digest, state, created_at, updated_at \
             ) SELECT ?, ?, ?, ?, 'reserved', ?, ? \
             WHERE (SELECT COUNT(*) FROM gateway_invocation_idempotency) < ? \
               AND (SELECT COUNT(*) FROM gateway_invocation_idempotency \
                    WHERE owner_api_token_id = ?) < ? \
             ON CONFLICT(owner_api_token_id, key_digest) DO NOTHING",
        )
        .bind(&id)
        .bind(request.owner.owner_api_token_id)
        .bind(key_digest.to_vec())
        .bind(request_digest.to_vec())
        .bind(now)
        .bind(now)
        .bind(self.limits.records)
        .bind(request.owner.owner_api_token_id)
        .bind(self.limits.records_per_owner)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 1 {
            transaction.commit().await?;
            return Ok(IdempotencyClaim::Fresh(IdempotencyRecord {
                id,
                owner_api_token_id: request.owner.owner_api_token_id.to_owned(),
                state: IdempotencyState::Reserved,
                approval_id: None,
                response_kind: None,
                created_at: now,
                updated_at: now,
                completed_at: None,
                expires_at: None,
            }));
        }

        let existing = fetch_by_key(
            &mut transaction,
            request.owner.owner_api_token_id,
            &key_digest,
        )
        .await?;
        let Some(existing) = existing else {
            return Err(IdempotencyError::Capacity);
        };
        if !bool::from(
            existing
                .request_digest
                .as_slice()
                .ct_eq(request_digest.as_slice()),
        ) {
            transaction.commit().await?;
            return Ok(IdempotencyClaim::Mismatch);
        }
        transaction.commit().await?;
        let record = existing.record()?;
        match record.state {
            IdempotencyState::Reserved | IdempotencyState::Executing => {
                Ok(IdempotencyClaim::InProgress(record))
            }
            IdempotencyState::Indeterminate => Ok(IdempotencyClaim::Indeterminate(record)),
            IdempotencyState::Completed => {
                if record.response_kind == Some(IdempotencyResponseKind::Approval)
                    && record.approval_id.is_none()
                {
                    return Ok(IdempotencyClaim::Indeterminate(record));
                }
                let ciphertext = existing
                    .response_ciphertext
                    .as_deref()
                    .ok_or(IdempotencyError::CorruptData)?;
                let response = self.decrypt_response(&record.id, ciphertext)?;
                Ok(IdempotencyClaim::Replay { record, response })
            }
        }
    }

    pub(crate) async fn lookup(
        &self,
        request: IdempotencyRequest<'_>,
    ) -> Result<Option<IdempotencyClaim>, IdempotencyError> {
        validate_identifier(request.owner.owner_api_token_id, 128)?;
        validate_key(request.key)?;
        validate_identifier(request.route, 200)?;
        let callable_path = canonical_callable_path(request.callable_path)?;
        let canonical_arguments = canonical_json(request.arguments)?;
        if canonical_arguments.len() > MAX_ARGUMENT_BYTES {
            return Err(IdempotencyError::PayloadTooLarge);
        }
        let key_digest = self.key_digest(request.owner, request.key);
        let request_digest = self.request_digest(
            request.owner,
            request.route,
            &callable_path,
            &canonical_arguments,
        );
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, self.clock.now().max(0)).await?;
        delete_expired(&mut transaction, now).await?;
        let existing = fetch_by_key(
            &mut transaction,
            request.owner.owner_api_token_id,
            &key_digest,
        )
        .await?;
        transaction.commit().await?;
        let Some(existing) = existing else {
            return Ok(None);
        };
        if !bool::from(
            existing
                .request_digest
                .as_slice()
                .ct_eq(request_digest.as_slice()),
        ) {
            return Ok(Some(IdempotencyClaim::Mismatch));
        }
        let record = existing.record()?;
        Ok(Some(match record.state {
            IdempotencyState::Reserved | IdempotencyState::Executing => {
                IdempotencyClaim::InProgress(record)
            }
            IdempotencyState::Indeterminate => IdempotencyClaim::Indeterminate(record),
            IdempotencyState::Completed => {
                if record.response_kind == Some(IdempotencyResponseKind::Approval)
                    && record.approval_id.is_none()
                {
                    return Ok(Some(IdempotencyClaim::Indeterminate(record)));
                }
                let ciphertext = existing
                    .response_ciphertext
                    .as_deref()
                    .ok_or(IdempotencyError::CorruptData)?;
                let response = self.decrypt_response(&record.id, ciphertext)?;
                IdempotencyClaim::Replay { record, response }
            }
        }))
    }

    pub(crate) async fn mark_executing(&self, id: &str) -> Result<(), IdempotencyError> {
        validate_identifier(id, 128)?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, self.clock.now().max(0)).await?;
        let result = sqlx::query(
            "UPDATE gateway_invocation_idempotency \
             SET state = 'executing', updated_at = ? \
             WHERE id = ? AND state = 'reserved'",
        )
        .bind(now)
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            let error = transition_error_in(&mut transaction, id).await?;
            return Err(error);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn release_reserved(&self, id: &str) -> Result<bool, IdempotencyError> {
        validate_identifier(id, 128)?;
        let result = sqlx::query(
            "DELETE FROM gateway_invocation_idempotency AS idempotency \
             WHERE idempotency.id = ? AND idempotency.state = 'reserved' \
               AND NOT EXISTS ( \
                   SELECT 1 FROM approval_correlations \
                   WHERE approval_correlations.execution_id = 'gateway-idempotency:' || idempotency.id \
                     AND approval_correlations.call_id = 'gateway' \
                     AND approval_correlations.actor_kind = 'api_token' \
                     AND approval_correlations.actor_id = idempotency.owner_api_token_id \
               )",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    pub(crate) async fn abandon(&self, id: &str) -> Result<(), IdempotencyError> {
        validate_identifier(id, 128)?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, self.clock.now().max(0)).await?;
        let expires_at = now
            .checked_add(IDEMPOTENCY_TTL_SECONDS)
            .ok_or(IdempotencyError::InvalidMetadata)?;
        sqlx::query(
            "DELETE FROM gateway_invocation_idempotency AS idempotency \
             WHERE idempotency.id = ? AND idempotency.state = 'reserved' \
               AND NOT EXISTS ( \
                   SELECT 1 FROM approval_correlations AS correlation \
                   WHERE correlation.execution_id = 'gateway-idempotency:' || idempotency.id \
                     AND correlation.call_id = 'gateway' \
                     AND correlation.actor_kind = 'api_token' \
                     AND correlation.actor_id = idempotency.owner_api_token_id \
               )",
        )
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        mark_executing_indeterminate_in(&mut transaction, id, now, expires_at).await?;
        sqlx::query(
            "UPDATE gateway_invocation_idempotency AS idempotency \
             SET state = 'indeterminate', updated_at = ?, completed_at = ?, expires_at = ? \
             WHERE idempotency.id = ? AND idempotency.state = 'reserved' \
               AND EXISTS ( \
                   SELECT 1 FROM approval_correlations AS correlation \
                   LEFT JOIN approvals AS approval ON approval.id = correlation.approval_id \
                   WHERE correlation.execution_id = 'gateway-idempotency:' || idempotency.id \
                     AND correlation.call_id = 'gateway' \
                     AND correlation.actor_kind = 'api_token' \
                     AND correlation.actor_id = idempotency.owner_api_token_id \
                     AND approval.id IS NULL \
               )",
        )
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn mark_indeterminate(
        &self,
        id: &str,
    ) -> Result<IdempotencyRecord, IdempotencyError> {
        validate_identifier(id, 128)?;
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, self.clock.now().max(0)).await?;
        let expires_at = now
            .checked_add(IDEMPOTENCY_TTL_SECONDS)
            .ok_or(IdempotencyError::InvalidMetadata)?;
        let result = mark_indeterminate_in(&mut transaction, id, now, expires_at).await?;
        if result == 0 {
            let error = transition_error_in(&mut transaction, id).await?;
            return Err(error);
        }
        transaction.commit().await?;
        self.get(id).await?.ok_or(IdempotencyError::NotFound)
    }

    pub(crate) async fn complete(
        &self,
        id: &str,
        kind: IdempotencyResponseKind,
        response: &IdempotencyResponse,
        approval_id: Option<&str>,
    ) -> Result<IdempotencyRecord, IdempotencyError> {
        validate_identifier(id, 128)?;
        if let Err(error) = validate_response(response) {
            self.mark_indeterminate_if_executing(id).await?;
            return Err(error);
        }
        let encoded = encode_response(response)?;
        let ciphertext = match self
            .keyring
            .encrypt("gateway-idempotency-response-v1", id, &encoded)
        {
            Ok(ciphertext) => ciphertext,
            Err(error) => {
                self.mark_indeterminate_if_executing(id).await?;
                return Err(error.into());
            }
        };
        let ciphertext_len =
            i64::try_from(ciphertext.len()).map_err(|_| IdempotencyError::PayloadTooLarge)?;
        if ciphertext_len > MAX_RESPONSE_CIPHERTEXT_BYTES {
            self.mark_indeterminate_if_executing(id).await?;
            return Err(IdempotencyError::PayloadTooLarge);
        }
        let observed_now = self.clock.now().max(0);
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        let expires_at = now
            .checked_add(IDEMPOTENCY_TTL_SECONDS)
            .ok_or(IdempotencyError::InvalidMetadata)?;
        let result = sqlx::query(
            "UPDATE gateway_invocation_idempotency \
             SET state = 'completed', approval_id = ?, response_kind = ?, response_ciphertext = ?, \
                 updated_at = ?, completed_at = ?, expires_at = ? \
             WHERE id = ? AND state IN ('reserved', 'executing') \
               AND ? <= ? - ( \
                   SELECT COALESCE(SUM(length(response_ciphertext)), 0) \
                   FROM gateway_invocation_idempotency WHERE id <> ? \
               )",
        )
        .bind(approval_id)
        .bind(kind.as_str())
        .bind(ciphertext)
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(id)
        .bind(ciphertext_len)
        .bind(self.limits.response_ciphertext_bytes)
        .bind(id)
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            let state = sqlx::query_scalar::<_, String>(
                "SELECT state FROM gateway_invocation_idempotency WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(&mut *transaction)
            .await?;
            let error = match state.as_deref() {
                Some("executing") => {
                    mark_executing_indeterminate_in(&mut transaction, id, now, expires_at).await?;
                    transaction.commit().await?;
                    IdempotencyError::Capacity
                }
                Some("reserved") => IdempotencyError::Capacity,
                Some(state) => IdempotencyError::InvalidTransition(state_name(state)?),
                None => IdempotencyError::NotFound,
            };
            return Err(error);
        }
        transaction.commit().await?;
        self.get(id).await?.ok_or(IdempotencyError::NotFound)
    }

    async fn mark_indeterminate_if_executing(&self, id: &str) -> Result<(), IdempotencyError> {
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, self.clock.now().max(0)).await?;
        let expires_at = now
            .checked_add(IDEMPOTENCY_TTL_SECONDS)
            .ok_or(IdempotencyError::InvalidMetadata)?;
        mark_executing_indeterminate_in(&mut transaction, id, now, expires_at).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn recover_startup(&self) -> Result<IdempotencyRecovery, IdempotencyError> {
        let observed_now = self.clock.now().max(0);
        let mut transaction = self.pool.begin().await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        let expires_at = now
            .checked_add(IDEMPOTENCY_TTL_SECONDS)
            .ok_or(IdempotencyError::InvalidMetadata)?;
        delete_expired(&mut transaction, now).await?;
        let indeterminate = sqlx::query(
            "UPDATE gateway_invocation_idempotency \
             SET state = 'indeterminate', updated_at = ?, completed_at = ?, expires_at = ? \
             WHERE state = 'executing'",
        )
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let reserved = sqlx::query_as::<_, IdempotencyRow>(
            "SELECT id, owner_api_token_id, request_digest, state, approval_id, response_kind, \
                    response_ciphertext, created_at, updated_at, completed_at, expires_at \
             FROM gateway_invocation_idempotency WHERE state = 'reserved' ORDER BY sequence",
        )
        .fetch_all(&mut *transaction)
        .await?
        .into_iter()
        .map(|row| row.record())
        .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await?;
        Ok(IdempotencyRecovery {
            indeterminate_executions: indeterminate,
            reserved,
        })
    }

    pub(crate) async fn correlated_approval_id(
        &self,
        record: &IdempotencyRecord,
    ) -> Result<Option<CorrelatedApproval>, IdempotencyError> {
        let row = sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT correlation.approval_id, approval.id \
             FROM approval_correlations AS correlation \
             LEFT JOIN approvals AS approval ON approval.id = correlation.approval_id \
             WHERE correlation.execution_id = ? AND correlation.call_id = 'gateway' \
               AND correlation.actor_kind = 'api_token' AND correlation.actor_id = ?",
        )
        .bind(idempotency_execution_id(&record.id))
        .bind(&record.owner_api_token_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(IdempotencyError::Database)?;
        Ok(row.map(|(approval_id, live_id)| {
            if live_id.is_some() {
                CorrelatedApproval::Live(approval_id)
            } else {
                CorrelatedApproval::Retired
            }
        }))
    }

    async fn get(&self, id: &str) -> Result<Option<IdempotencyRecord>, IdempotencyError> {
        let row = sqlx::query_as::<_, IdempotencyRow>(
            "SELECT id, owner_api_token_id, request_digest, state, approval_id, response_kind, \
                    response_ciphertext, created_at, updated_at, completed_at, expires_at \
             FROM gateway_invocation_idempotency WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| row.record()).transpose()
    }

    fn key_digest(&self, owner: IdempotencyOwner<'_>, key: &str) -> [u8; 32] {
        let mut input = Vec::with_capacity(owner.owner_api_token_id.len() + key.len() + 16);
        append_field(&mut input, owner.owner_api_token_id.as_bytes());
        append_field(&mut input, key.as_bytes());
        self.keyring.digest("gateway-idempotency-key-v1", &input)
    }

    fn request_digest(
        &self,
        owner: IdempotencyOwner<'_>,
        route: &str,
        callable_path: &str,
        canonical_arguments: &[u8],
    ) -> [u8; 32] {
        let arguments_digest = self
            .keyring
            .digest("gateway-idempotency-arguments-v1", canonical_arguments);
        let mut input = Vec::with_capacity(
            owner.owner_api_token_id.len() + route.len() + callable_path.len() + 96,
        );
        input.extend_from_slice(b"executor-gateway-idempotency-request-v1");
        append_field(&mut input, owner.owner_api_token_id.as_bytes());
        append_field(&mut input, route.as_bytes());
        append_field(&mut input, callable_path.as_bytes());
        append_field(&mut input, &arguments_digest);
        self.keyring
            .digest("gateway-idempotency-request-v1", &input)
    }

    fn decrypt_response(
        &self,
        id: &str,
        ciphertext: &[u8],
    ) -> Result<IdempotencyResponse, IdempotencyError> {
        let encoded = self
            .keyring
            .decrypt("gateway-idempotency-response-v1", id, ciphertext)?;
        decode_response(&encoded)
    }
}

#[derive(FromRow)]
struct IdempotencyRow {
    id: String,
    owner_api_token_id: String,
    request_digest: Vec<u8>,
    state: String,
    approval_id: Option<String>,
    response_kind: Option<String>,
    response_ciphertext: Option<Vec<u8>>,
    created_at: i64,
    updated_at: i64,
    completed_at: Option<i64>,
    expires_at: Option<i64>,
}

impl IdempotencyRow {
    fn record(&self) -> Result<IdempotencyRecord, IdempotencyError> {
        Ok(IdempotencyRecord {
            id: self.id.clone(),
            owner_api_token_id: self.owner_api_token_id.clone(),
            state: parse_state(&self.state)?,
            approval_id: self.approval_id.clone(),
            response_kind: self
                .response_kind
                .as_deref()
                .map(parse_response_kind)
                .transpose()?,
            created_at: self.created_at,
            updated_at: self.updated_at,
            completed_at: self.completed_at,
            expires_at: self.expires_at,
        })
    }
}

async fn fetch_by_key(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    owner_api_token_id: &str,
    key_digest: &[u8],
) -> Result<Option<IdempotencyRow>, sqlx::Error> {
    sqlx::query_as::<_, IdempotencyRow>(
        "SELECT id, owner_api_token_id, request_digest, state, approval_id, response_kind, \
                response_ciphertext, created_at, updated_at, completed_at, expires_at \
         FROM gateway_invocation_idempotency \
         WHERE owner_api_token_id = ? AND key_digest = ?",
    )
    .bind(owner_api_token_id)
    .bind(key_digest)
    .fetch_optional(&mut **transaction)
    .await
}

async fn transition_error_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
) -> Result<IdempotencyError, IdempotencyError> {
    let state = sqlx::query_scalar::<_, String>(
        "SELECT state FROM gateway_invocation_idempotency WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await?;
    Ok(match state {
        Some(state) => IdempotencyError::InvalidTransition(state_name(&state)?),
        None => IdempotencyError::NotFound,
    })
}

async fn mark_indeterminate_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
    now: i64,
    expires_at: i64,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "UPDATE gateway_invocation_idempotency \
         SET state = 'indeterminate', updated_at = ?, completed_at = ?, expires_at = ? \
         WHERE id = ? AND state IN ('reserved', 'executing')",
    )
    .bind(now)
    .bind(now)
    .bind(expires_at)
    .bind(id)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
}

async fn mark_executing_indeterminate_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
    now: i64,
    expires_at: i64,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "UPDATE gateway_invocation_idempotency \
         SET state = 'indeterminate', updated_at = ?, completed_at = ?, expires_at = ? \
         WHERE id = ? AND state = 'executing'",
    )
    .bind(now)
    .bind(now)
    .bind(expires_at)
    .bind(id)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
}

async fn delete_expired(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM gateway_invocation_idempotency \
         WHERE state IN ('completed', 'indeterminate') AND expires_at <= ?",
    )
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn effective_now_in(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    observed_now: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "UPDATE gateway_idempotency_clock \
         SET effective_now = MAX(effective_now, ?) WHERE id = 1",
    )
    .bind(observed_now)
    .execute(&mut **transaction)
    .await?;
    sqlx::query_scalar("SELECT effective_now FROM gateway_idempotency_clock WHERE id = 1")
        .fetch_one(&mut **transaction)
        .await
}

pub(crate) fn validate_key(key: &str) -> Result<(), IdempotencyError> {
    let bytes = key.as_bytes();
    if bytes.is_empty()
        || bytes.len() > IDEMPOTENCY_KEY_MAX_BYTES
        || bytes.iter().any(|byte| !(0x21..=0x7e).contains(byte))
    {
        return Err(IdempotencyError::InvalidKey);
    }
    Ok(())
}

pub(crate) fn idempotency_execution_id(record_id: &str) -> String {
    format!("gateway-idempotency:{record_id}")
}

fn validate_identifier(value: &str, max: usize) -> Result<(), IdempotencyError> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(IdempotencyError::InvalidMetadata);
    }
    Ok(())
}

pub(crate) fn canonical_callable_path(path: &str) -> Result<String, IdempotencyError> {
    let path = path.strip_prefix("tools.").unwrap_or(path);
    let mut segments = path.split('.');
    let source = segments.next().unwrap_or_default();
    let tool = segments.next().unwrap_or_default();
    if source.is_empty()
        || tool.is_empty()
        || segments.next().is_some()
        || source.len() + tool.len() + 7 > 512
        || source.contains('\0')
        || tool.contains('\0')
    {
        return Err(IdempotencyError::InvalidMetadata);
    }
    Ok(format!("tools.{source}.{tool}"))
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, IdempotencyError> {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let sorted = object
                    .iter()
                    .map(|(key, value)| (key.clone(), sort(value)))
                    .collect::<BTreeMap<_, _>>();
                Value::Object(sorted.into_iter().collect())
            }
            Value::Array(values) => Value::Array(values.iter().map(sort).collect()),
            value => value.clone(),
        }
    }
    serde_json::to_vec(&sort(value)).map_err(IdempotencyError::Json)
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn validate_response(response: &IdempotencyResponse) -> Result<(), IdempotencyError> {
    if !(100..=599).contains(&response.status)
        || response.body.len() > MAX_RESPONSE_BODY_BYTES
        || response.headers.len() > MAX_RESPONSE_HEADERS
    {
        return Err(IdempotencyError::PayloadTooLarge);
    }
    let header_bytes = response
        .headers
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            if name.is_empty()
                || name.contains(['\0', '\r', '\n'])
                || value.contains(['\0', '\r', '\n'])
            {
                return None;
            }
            total.checked_add(name.len())?.checked_add(value.len())
        });
    if header_bytes.is_none_or(|bytes| bytes > MAX_RESPONSE_HEADER_BYTES) {
        return Err(IdempotencyError::PayloadTooLarge);
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
struct StoredResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    body_base64: String,
}

fn encode_response(response: &IdempotencyResponse) -> Result<Vec<u8>, IdempotencyError> {
    serde_json::to_vec(&StoredResponse {
        status: response.status,
        headers: response.headers.clone(),
        body_base64: STANDARD.encode(&response.body),
    })
    .map_err(IdempotencyError::Json)
}

fn decode_response(encoded: &[u8]) -> Result<IdempotencyResponse, IdempotencyError> {
    let stored: StoredResponse = serde_json::from_slice(encoded)?;
    validate_response(&IdempotencyResponse {
        status: stored.status,
        headers: stored.headers.clone(),
        body: Vec::new(),
    })?;
    let body = STANDARD
        .decode(stored.body_base64)
        .map_err(|_| IdempotencyError::CorruptData)?;
    let response = IdempotencyResponse {
        status: stored.status,
        headers: stored.headers,
        body,
    };
    validate_response(&response)?;
    Ok(response)
}

fn parse_state(state: &str) -> Result<IdempotencyState, IdempotencyError> {
    match state {
        "reserved" => Ok(IdempotencyState::Reserved),
        "executing" => Ok(IdempotencyState::Executing),
        "completed" => Ok(IdempotencyState::Completed),
        "indeterminate" => Ok(IdempotencyState::Indeterminate),
        _ => Err(IdempotencyError::CorruptData),
    }
}

fn parse_response_kind(value: &str) -> Result<IdempotencyResponseKind, IdempotencyError> {
    match value {
        "tool" => Ok(IdempotencyResponseKind::Tool),
        "approval" => Ok(IdempotencyResponseKind::Approval),
        _ => Err(IdempotencyError::CorruptData),
    }
}

fn state_name(state: &str) -> Result<&'static str, IdempotencyError> {
    Ok(parse_state(state)?.as_str())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    };

    use serde_json::json;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    use super::*;

    static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

    struct ManualClock(AtomicI64);

    impl ManualClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl IdempotencyClock for ManualClock {
        fn now(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    async fn store() -> (tempfile::TempDir, GatewayIdempotencyStore, Arc<ManualClock>) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let database_path = directory.path().join("idempotency.db");
        let options = SqliteConnectOptions::new()
            .filename(&database_path)
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .expect("database pool");
        MIGRATOR.run(&pool).await.expect("migrations");
        for owner in ["owner-a", "owner-b"] {
            sqlx::query(
                "INSERT INTO api_tokens (id, name, token_digest, token_prefix, token_suffix, created_at) \
                 VALUES (?, ?, ?, 'tok_', 'tail', 1)",
            )
            .bind(owner)
            .bind(owner)
            .bind(owner.as_bytes())
            .execute(&pool)
            .await
            .expect("owner token");
        }
        let clock = Arc::new(ManualClock::new(1_000));
        let store = GatewayIdempotencyStore::with_clock(
            pool,
            Keyring::from_master_key([7; 32]).expect("keyring"),
            clock.clone(),
        );
        (directory, store, clock)
    }

    fn request<'a>(
        owner: &'a str,
        key: &'a str,
        path: &'a str,
        arguments: &'a Value,
    ) -> IdempotencyRequest<'a> {
        IdempotencyRequest {
            owner: IdempotencyOwner {
                owner_api_token_id: owner,
            },
            key,
            route: "POST /api/v1/gateway/tools/invoke",
            callable_path: path,
            arguments,
        }
    }

    #[tokio::test]
    async fn matching_requests_replay_and_mismatches_do_not_reuse() {
        let (_directory, store, _clock) = store().await;
        let first_arguments = json!({"alpha": 1, "nested": {"z": 2, "a": 3}});
        let reordered_arguments = json!({"nested": {"a": 3, "z": 2}, "alpha": 1});
        let fresh = store
            .claim(request(
                "owner-a",
                "retry-key",
                "source.tool",
                &first_arguments,
            ))
            .await
            .expect("fresh claim");
        let IdempotencyClaim::Fresh(record) = fresh else {
            panic!("first claim must be fresh");
        };
        let response = IdempotencyResponse {
            status: 202,
            headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
            body: br#"{"approval":{"id":"approval-1"}}"#.to_vec(),
        };
        store
            .complete(&record.id, IdempotencyResponseKind::Tool, &response, None)
            .await
            .expect("completion");

        let replay = store
            .claim(request(
                "owner-a",
                "retry-key",
                "tools.source.tool",
                &reordered_arguments,
            ))
            .await
            .expect("replay");
        assert!(matches!(
            replay,
            IdempotencyClaim::Replay { response: replayed, .. } if replayed == response
        ));
        assert!(matches!(
            store
                .claim(request(
                    "owner-a",
                    "retry-key",
                    "source.other",
                    &first_arguments,
                ))
                .await
                .expect("path mismatch"),
            IdempotencyClaim::Mismatch
        ));
        assert!(matches!(
            store
                .claim(request(
                    "owner-a",
                    "retry-key",
                    "source.tool",
                    &json!({"alpha": 2}),
                ))
                .await
                .expect("argument mismatch"),
            IdempotencyClaim::Mismatch
        ));
        assert!(matches!(
            store
                .claim(request(
                    "owner-b",
                    "retry-key",
                    "source.tool",
                    &first_arguments,
                ))
                .await
                .expect("other owner"),
            IdempotencyClaim::Fresh(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_claims_elect_exactly_one_winner() {
        let (_directory, store, _clock) = store().await;
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let store = store.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                let arguments = json!({"value": 1});
                barrier.wait().await;
                store
                    .claim(request(
                        "owner-a",
                        "concurrent-key",
                        "source.tool",
                        &arguments,
                    ))
                    .await
            }));
        }
        barrier.wait().await;
        let mut fresh = 0;
        let mut in_progress = 0;
        for task in tasks {
            match task.await.expect("claim task").expect("claim") {
                IdempotencyClaim::Fresh(_) => fresh += 1,
                IdempotencyClaim::InProgress(_) => in_progress += 1,
                other => panic!("unexpected claim: {other:?}"),
            }
        }
        assert_eq!(fresh, 1);
        assert_eq!(in_progress, 31);
    }

    #[tokio::test]
    async fn startup_never_replays_an_uncertain_execution() {
        let (_directory, store, _clock) = store().await;
        let arguments = json!({"value": 1});
        let fresh = store
            .claim(request(
                "owner-a",
                "uncertain-key",
                "source.tool",
                &arguments,
            ))
            .await
            .expect("claim");
        let IdempotencyClaim::Fresh(record) = fresh else {
            panic!("fresh claim expected");
        };
        store
            .mark_executing(&record.id)
            .await
            .expect("execution boundary");
        let recovery = store.recover_startup().await.expect("startup recovery");
        assert_eq!(recovery.indeterminate_executions, 1);
        assert!(matches!(
            store
                .claim(request(
                    "owner-a",
                    "uncertain-key",
                    "source.tool",
                    &arguments,
                ))
                .await
                .expect("post-restart claim"),
            IdempotencyClaim::Indeterminate(_)
        ));
    }

    #[tokio::test]
    async fn abandoned_reservations_can_be_released_without_reusing_an_active_claim() {
        let (_directory, store, _clock) = store().await;
        let arguments = json!({"value": 1});
        let fresh = store
            .claim(request(
                "owner-a",
                "cancelled-key",
                "source.tool",
                &arguments,
            ))
            .await
            .expect("claim");
        let IdempotencyClaim::Fresh(record) = fresh else {
            panic!("fresh claim expected");
        };
        assert!(
            store
                .release_reserved(&record.id)
                .await
                .expect("reservation release")
        );
        assert!(
            !store
                .release_reserved(&record.id)
                .await
                .expect("second release")
        );
        assert!(matches!(
            store
                .claim(request(
                    "owner-a",
                    "cancelled-key",
                    "source.tool",
                    &arguments,
                ))
                .await
                .expect("replacement claim"),
            IdempotencyClaim::Fresh(_)
        ));
    }

    #[tokio::test]
    async fn capacity_is_fail_closed_before_and_after_the_execution_boundary() {
        let (_directory, store, _clock) = store().await;
        let store = store.with_limits(IdempotencyLimits {
            records: 2,
            records_per_owner: 1,
            response_ciphertext_bytes: 0,
        });
        let arguments = json!({"value": 1});
        let fresh = store
            .claim(request(
                "owner-a",
                "capacity-key",
                "source.tool",
                &arguments,
            ))
            .await
            .expect("claim");
        let IdempotencyClaim::Fresh(record) = fresh else {
            panic!("fresh claim expected");
        };
        assert!(matches!(
            store
                .claim(request("owner-a", "second-key", "source.tool", &arguments,))
                .await,
            Err(IdempotencyError::Capacity)
        ));
        store
            .mark_executing(&record.id)
            .await
            .expect("execution boundary");
        assert!(matches!(
            store
                .complete(
                    &record.id,
                    IdempotencyResponseKind::Tool,
                    &IdempotencyResponse {
                        status: 200,
                        headers: BTreeMap::new(),
                        body: b"observed response".to_vec(),
                    },
                    None,
                )
                .await,
            Err(IdempotencyError::Capacity)
        ));
        assert!(matches!(
            store
                .claim(request(
                    "owner-a",
                    "capacity-key",
                    "source.tool",
                    &arguments,
                ))
                .await
                .expect("uncertain replay"),
            IdempotencyClaim::Indeterminate(_)
        ));
    }

    #[tokio::test]
    async fn approval_retention_can_clear_a_terminal_reference() {
        let (_directory, store, _clock) = store().await;
        sqlx::query(
            "INSERT INTO approvals ( \
                 id, execution_id, call_id, worker_generation, actor_kind, actor_id, \
                 actor_api_token_id, surface, source_id, tool_id, callable_path_snapshot, \
                 mode_provenance, source_revision, catalog_revision, tool_revision, \
                 binding_revision, arguments_digest, arguments_ciphertext, \
                 redacted_arguments_ciphertext, input_schema_ciphertext, \
                 invocation_snapshot_ciphertext, status, created_at, updated_at, expires_at \
             ) VALUES ( \
                 'approval-1', 'execution-1', 'call-1', 0, 'api_token', 'owner-a', \
                 'owner-a', 'gateway', 'source-1', 'tool-1', 'tools.source.tool', \
                 'intrinsic', 0, 0, 0, 0, zeroblob(32), zeroblob(42), zeroblob(42), \
                 zeroblob(42), zeroblob(42), 'pending', 1, 1, 601 \
             )",
        )
        .execute(&store.pool)
        .await
        .expect("approval fixture");
        let arguments = json!({});
        let fresh = store
            .claim(request(
                "owner-a",
                "approval-key",
                "source.tool",
                &arguments,
            ))
            .await
            .expect("claim");
        let IdempotencyClaim::Fresh(record) = fresh else {
            panic!("fresh claim expected");
        };
        store
            .complete(
                &record.id,
                IdempotencyResponseKind::Approval,
                &IdempotencyResponse {
                    status: 202,
                    headers: BTreeMap::new(),
                    body: b"approval required".to_vec(),
                },
                Some("approval-1"),
            )
            .await
            .expect("completion");
        sqlx::query("DELETE FROM approvals WHERE id = 'approval-1'")
            .execute(&store.pool)
            .await
            .expect("approval retention deletion");
        let approval_id = sqlx::query_scalar::<_, Option<String>>(
            "SELECT approval_id FROM gateway_invocation_idempotency WHERE id = ?",
        )
        .bind(record.id)
        .fetch_one(&store.pool)
        .await
        .expect("idempotency record");
        assert_eq!(approval_id, None);
    }

    #[tokio::test]
    async fn retired_approval_correlation_never_reopens_a_reserved_key() {
        let (_directory, store, _clock) = store().await;
        let arguments = json!({});
        let claim = store
            .claim(request(
                "owner-a",
                "retired-approval-key",
                "source.tool",
                &arguments,
            ))
            .await
            .expect("claim");
        let IdempotencyClaim::Fresh(record) = claim else {
            panic!("claim must be fresh");
        };
        sqlx::query(
            "INSERT INTO approvals ( \
                 id, execution_id, call_id, worker_generation, actor_kind, actor_id, \
                 actor_api_token_id, surface, source_id, tool_id, callable_path_snapshot, \
                 mode_provenance, source_revision, catalog_revision, tool_revision, \
                 binding_revision, arguments_digest, arguments_ciphertext, \
                 redacted_arguments_ciphertext, input_schema_ciphertext, \
                 invocation_snapshot_ciphertext, status, created_at, updated_at, expires_at \
             ) VALUES ( \
                 'retired-approval', ?, 'gateway', 0, 'api_token', 'owner-a', \
                 'owner-a', 'gateway', 'source-1', 'tool-1', 'tools.source.tool', \
                 'intrinsic', 0, 0, 0, 0, zeroblob(32), zeroblob(42), zeroblob(42), \
                 zeroblob(42), zeroblob(42), 'pending', 1, 1, 601 \
             )",
        )
        .bind(idempotency_execution_id(&record.id))
        .execute(&store.pool)
        .await
        .expect("approval fixture");
        sqlx::query("DELETE FROM approvals WHERE id = 'retired-approval'")
            .execute(&store.pool)
            .await
            .expect("approval retention deletion");
        assert!(
            !store
                .release_reserved(&record.id)
                .await
                .expect("retired correlation blocks release")
        );
        let recovery = store.recover_startup().await.expect("startup recovery");
        assert_eq!(recovery.reserved, vec![record.clone()]);
        assert!(matches!(
            store
                .correlated_approval_id(&record)
                .await
                .expect("correlation lookup"),
            Some(CorrelatedApproval::Retired)
        ));
        store
            .mark_indeterminate(&record.id)
            .await
            .expect("retired reservation terminalizes");
        assert!(matches!(
            store
                .claim(request(
                    "owner-a",
                    "retired-approval-key",
                    "source.tool",
                    &arguments,
                ))
                .await
                .expect("post-restart retry"),
            IdempotencyClaim::Indeterminate(_)
        ));
    }

    #[tokio::test]
    async fn terminal_keys_expire_after_twenty_four_hours() {
        let (_directory, store, clock) = store().await;
        let arguments = json!({});
        let fresh = store
            .claim(request(
                "owner-a",
                "expiring-key",
                "source.tool",
                &arguments,
            ))
            .await
            .expect("claim");
        let IdempotencyClaim::Fresh(record) = fresh else {
            panic!("fresh claim expected");
        };
        store
            .complete(
                &record.id,
                IdempotencyResponseKind::Tool,
                &IdempotencyResponse {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: b"ok".to_vec(),
                },
                None,
            )
            .await
            .expect("completion");
        clock.set(1_000 + IDEMPOTENCY_TTL_SECONDS - 1);
        assert!(matches!(
            store
                .claim(request(
                    "owner-a",
                    "expiring-key",
                    "source.tool",
                    &arguments,
                ))
                .await
                .expect("retained replay"),
            IdempotencyClaim::Replay { .. }
        ));
        clock.set(1_000 + IDEMPOTENCY_TTL_SECONDS);
        assert!(matches!(
            store
                .claim(request(
                    "owner-a",
                    "expiring-key",
                    "source.tool",
                    &arguments,
                ))
                .await
                .expect("reused expired key"),
            IdempotencyClaim::Fresh(_)
        ));
    }

    #[tokio::test]
    async fn secrets_and_replay_payloads_are_not_stored_as_plaintext() {
        let (_directory, store, _clock) = store().await;
        let arguments = json!({"secret": "argument-plaintext-marker"});
        let fresh = store
            .claim(request(
                "owner-a",
                "raw-idempotency-key-marker",
                "source.tool",
                &arguments,
            ))
            .await
            .expect("claim");
        let IdempotencyClaim::Fresh(record) = fresh else {
            panic!("fresh claim expected");
        };
        store
            .complete(
                &record.id,
                IdempotencyResponseKind::Tool,
                &IdempotencyResponse {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: b"response-plaintext-marker".to_vec(),
                },
                None,
            )
            .await
            .expect("completion");
        let stored = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT key_digest, request_digest, response_ciphertext \
             FROM gateway_invocation_idempotency WHERE id = ?",
        )
        .bind(record.id)
        .fetch_one(&store.pool)
        .await
        .expect("stored row");
        let mut bytes = Vec::new();
        bytes.extend(stored.0);
        bytes.extend(stored.1);
        bytes.extend(stored.2);
        let storage = String::from_utf8_lossy(&bytes);
        assert!(!storage.contains("raw-idempotency-key-marker"));
        assert!(!storage.contains("argument-plaintext-marker"));
        assert!(!storage.contains("response-plaintext-marker"));
    }

    #[test]
    fn key_validation_is_bounded_and_visible_ascii_only() {
        assert!(validate_key("a").is_ok());
        assert!(validate_key(&"x".repeat(255)).is_ok());
        assert!(matches!(
            validate_key(""),
            Err(IdempotencyError::InvalidKey)
        ));
        assert!(matches!(
            validate_key(&"x".repeat(256)),
            Err(IdempotencyError::InvalidKey)
        ));
        assert!(matches!(
            validate_key("contains space"),
            Err(IdempotencyError::InvalidKey)
        ));
        assert!(matches!(
            validate_key("non-ascii-é"),
            Err(IdempotencyError::InvalidKey)
        ));
    }
}
