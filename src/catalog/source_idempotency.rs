use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::{HeaderName, HeaderValue};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, Sqlite, SqlitePool, Transaction};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use super::CatalogError;
use crate::crypto::{CryptoError, Keyring};

pub(crate) const SOURCE_CREATION_ROUTE: &str = "POST /api/v1/sources";
pub(crate) const SOURCE_CREATION_IDEMPOTENCY_KEY_MAX_BYTES: usize = 255;
pub(crate) const SOURCE_CREATION_IDEMPOTENCY_TTL_SECONDS: i64 = 24 * 60 * 60;
const SOURCE_CREATION_TOMBSTONE_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_RESPONSE_CIPHERTEXT_BYTES: i64 = 24 * 1024 * 1024;
const MAX_TOTAL_RESPONSE_CIPHERTEXT_BYTES: i64 = 64 * 1024 * 1024;
const MAX_RECORDS: i64 = 10_000;
const MAX_RECORDS_PER_ADMIN_ROUTE: i64 = 1_000;
const PURGE_BATCH: i64 = 1_024;
const KEY_DIGEST_PURPOSE: &str = "source-creation-idempotency-key-v1";
const REQUEST_BODY_DIGEST_PURPOSE: &str = "source-creation-idempotency-request-body-v1";
const REQUEST_DIGEST_PURPOSE: &str = "source-creation-idempotency-request-v1";
const RESPONSE_PURPOSE: &str = "source-creation-idempotency-response-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourceCreationIdempotencyLimits {
    records: i64,
    records_per_admin_route: i64,
    response_ciphertext_bytes: i64,
}

impl Default for SourceCreationIdempotencyLimits {
    fn default() -> Self {
        Self {
            records: MAX_RECORDS,
            records_per_admin_route: MAX_RECORDS_PER_ADMIN_ROUTE,
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
pub(crate) struct SourceCreationIdempotencyStore {
    pool: SqlitePool,
    keyring: Keyring,
    clock: Arc<dyn IdempotencyClock>,
    limits: SourceCreationIdempotencyLimits,
    #[cfg(test)]
    fail_next_lookup: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceCreationReservation {
    id: String,
    admin_id: i64,
    route: String,
    key_digest: [u8; 32],
    request_digest: [u8; 32],
    created_at: i64,
    limits: SourceCreationIdempotencyLimits,
}

impl SourceCreationReservation {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceCreationResponse {
    pub(crate) status: u16,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: Vec<u8>,
}

impl SourceCreationResponse {
    pub(crate) fn json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
            body,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SourceCreationResponseKind {
    Completed,
    Failed,
}

impl SourceCreationResponseKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceCreationReplay {
    pub(crate) kind: SourceCreationResponseKind,
    pub(crate) response: SourceCreationResponse,
}

#[derive(Clone, Debug)]
pub(crate) enum SourceCreationIdempotencyClaim {
    Fresh(SourceCreationReservation),
    InProgress,
    Replay(SourceCreationReplay),
    Mismatch,
    Abandoned,
    Interrupted,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SourceCreationIdempotencyStatus {
    InProgress,
    Replay(SourceCreationReplay),
    Abandoned,
    Interrupted,
    Expired,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SourceCreationIdempotencyRecovery {
    pub(crate) reservations_interrupted: u64,
    pub(crate) tombstones_purged: u64,
}

#[derive(Debug, Error)]
pub(crate) enum SourceCreationIdempotencyError {
    #[error("source creation idempotency storage failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("source creation idempotency protection failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("source creation idempotency JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the Idempotency-Key must contain between 1 and 255 visible ASCII bytes")]
    InvalidKey,
    #[error("source creation idempotency metadata is invalid")]
    InvalidMetadata,
    #[error("the source creation idempotency payload exceeds the allowed size")]
    PayloadTooLarge,
    #[error("source creation idempotency capacity has been reached")]
    Capacity,
    #[error("stored source creation idempotency data is invalid")]
    CorruptData,
}

#[derive(Clone, FromRow)]
struct SourceCreationIdempotencyRow {
    id: String,
    admin_id: i64,
    route: String,
    key_digest: Vec<u8>,
    request_digest: Option<Vec<u8>>,
    state: String,
    response_ciphertext: Option<Vec<u8>>,
    created_at: i64,
    updated_at: i64,
    completed_at: Option<i64>,
    expires_at: Option<i64>,
    purge_at: Option<i64>,
}

#[derive(Deserialize, Serialize)]
struct StoredResponse {
    kind: SourceCreationResponseKind,
    status: u16,
    headers: BTreeMap<String, String>,
    body_base64: String,
}

struct ResponseBinding<'a> {
    id: &'a str,
    admin_id: i64,
    route: &'a str,
    key_digest: &'a [u8],
    request_digest: &'a [u8],
    created_at: i64,
    kind: SourceCreationResponseKind,
    updated_at: i64,
    completed_at: i64,
    expires_at: i64,
    purge_at: i64,
}

impl SourceCreationIdempotencyStore {
    pub(crate) fn new(pool: SqlitePool, keyring: Keyring) -> Self {
        Self {
            pool,
            keyring,
            clock: Arc::new(SystemClock),
            limits: SourceCreationIdempotencyLimits::default(),
            #[cfg(test)]
            fail_next_lookup: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    fn with_clock(pool: SqlitePool, keyring: Keyring, clock: Arc<dyn IdempotencyClock>) -> Self {
        Self {
            pool,
            keyring,
            clock,
            limits: SourceCreationIdempotencyLimits::default(),
            fail_next_lookup: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(test)]
    fn with_limits(mut self, limits: SourceCreationIdempotencyLimits) -> Self {
        self.limits = limits;
        self
    }

    #[cfg(test)]
    pub(crate) fn fail_next_lookup_for_test(&self) {
        self.fail_next_lookup.store(true, Ordering::SeqCst);
    }

    pub(crate) async fn claim(
        &self,
        admin_id: i64,
        route: &str,
        key: &str,
        request: &Value,
    ) -> Result<SourceCreationIdempotencyClaim, SourceCreationIdempotencyError> {
        validate_admin_id(admin_id)?;
        validate_route(route)?;
        validate_key(key)?;
        let canonical_request = canonical_json(request)?;
        if canonical_request.len() > MAX_REQUEST_BYTES {
            return Err(SourceCreationIdempotencyError::PayloadTooLarge);
        }
        let key_digest = self.keyring.digest(KEY_DIGEST_PURPOSE, key.as_bytes());
        let request_digest = request_digest(&self.keyring, admin_id, route, &canonical_request);
        let observed_now = self.clock.now().max(0);
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let now = effective_now_in(&mut transaction, observed_now).await?;
        purge_tombstones_for_admission_in(&mut transaction, admin_id, route, now, PURGE_BATCH)
            .await?;
        let id = Uuid::new_v4().to_string();
        let inserted = sqlx::query(
            "INSERT INTO source_creation_idempotency ( \
                 id, admin_id, route, key_digest, request_digest, state, created_at, updated_at \
             ) SELECT ?, ?, ?, ?, ?, 'reserved', ?, ? \
             WHERE (SELECT COUNT(*) FROM source_creation_idempotency) < ? \
               AND (SELECT COUNT(*) FROM source_creation_idempotency \
                    WHERE admin_id = ? AND route = ?) < ? \
             ON CONFLICT(admin_id, route, key_digest) DO NOTHING",
        )
        .bind(&id)
        .bind(admin_id)
        .bind(route)
        .bind(key_digest.to_vec())
        .bind(request_digest.to_vec())
        .bind(now)
        .bind(now)
        .bind(self.limits.records)
        .bind(admin_id)
        .bind(route)
        .bind(self.limits.records_per_admin_route)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 1 {
            transaction.commit().await?;
            return Ok(SourceCreationIdempotencyClaim::Fresh(
                SourceCreationReservation {
                    id,
                    admin_id,
                    route: route.to_owned(),
                    key_digest,
                    request_digest,
                    created_at: now,
                    limits: self.limits,
                },
            ));
        }

        let existing = fetch_by_key(&mut transaction, admin_id, route, &key_digest).await?;
        let Some(existing) = existing else {
            transaction.commit().await?;
            return Err(SourceCreationIdempotencyError::Capacity);
        };
        validate_row_binding(&existing, admin_id, route, &key_digest)?;
        if let Some(expected) = existing.request_digest.as_deref() {
            if expected.len() != 32 {
                return Err(SourceCreationIdempotencyError::CorruptData);
            }
            if !bool::from(expected.ct_eq(request_digest.as_slice())) {
                transaction.commit().await?;
                return Ok(SourceCreationIdempotencyClaim::Mismatch);
            }
        }
        let status = classify_status(&self.keyring, &existing, now)?;
        transaction.commit().await?;
        Ok(match status {
            SourceCreationIdempotencyStatus::InProgress => {
                SourceCreationIdempotencyClaim::InProgress
            }
            SourceCreationIdempotencyStatus::Replay(replay) => {
                SourceCreationIdempotencyClaim::Replay(replay)
            }
            SourceCreationIdempotencyStatus::Abandoned => SourceCreationIdempotencyClaim::Abandoned,
            SourceCreationIdempotencyStatus::Interrupted => {
                SourceCreationIdempotencyClaim::Interrupted
            }
            SourceCreationIdempotencyStatus::Expired => SourceCreationIdempotencyClaim::Expired,
        })
    }

    pub(crate) async fn lookup(
        &self,
        admin_id: i64,
        route: &str,
        key: &str,
    ) -> Result<Option<SourceCreationIdempotencyStatus>, SourceCreationIdempotencyError> {
        validate_admin_id(admin_id)?;
        validate_route(route)?;
        validate_key(key)?;
        #[cfg(test)]
        if self.fail_next_lookup.swap(false, Ordering::SeqCst) {
            return Err(SourceCreationIdempotencyError::Database(
                sqlx::Error::Protocol("injected source creation lookup failure".into()),
            ));
        }
        let key_digest = self.keyring.digest(KEY_DIGEST_PURPOSE, key.as_bytes());
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let now = effective_now_in(&mut transaction, self.clock.now().max(0)).await?;
        purge_tombstones_in(&mut transaction, now, PURGE_BATCH).await?;
        let existing = fetch_by_key(&mut transaction, admin_id, route, &key_digest).await?;
        let status = existing
            .as_ref()
            .map(|row| {
                validate_row_binding(row, admin_id, route, &key_digest)?;
                classify_status(&self.keyring, row, now)
            })
            .transpose()?;
        transaction.commit().await?;
        Ok(status)
    }

    pub(crate) async fn seal_missing(
        &self,
        admin_id: i64,
        route: &str,
        key: &str,
    ) -> Result<SourceCreationIdempotencyStatus, SourceCreationIdempotencyError> {
        validate_admin_id(admin_id)?;
        validate_route(route)?;
        validate_key(key)?;
        let key_digest = self.keyring.digest(KEY_DIGEST_PURPOSE, key.as_bytes());
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let now = effective_now_in(&mut transaction, self.clock.now().max(0)).await?;
        purge_tombstones_for_admission_in(&mut transaction, admin_id, route, now, PURGE_BATCH)
            .await?;
        let expires_at = terminal_expiry(now)?;
        let purge_at = tombstone_expiry(now)?;
        sqlx::query(
            "INSERT INTO source_creation_idempotency ( \
                 id, admin_id, route, key_digest, request_digest, state, \
                 created_at, updated_at, completed_at, expires_at, purge_at \
             ) SELECT ?, ?, ?, ?, NULL, 'abandoned', ?, ?, ?, ?, ? \
             WHERE (SELECT COUNT(*) FROM source_creation_idempotency) < ? \
               AND (SELECT COUNT(*) FROM source_creation_idempotency \
                    WHERE admin_id = ? AND route = ?) < ? \
             ON CONFLICT(admin_id, route, key_digest) DO NOTHING",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(admin_id)
        .bind(route)
        .bind(key_digest.to_vec())
        .bind(now)
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(purge_at)
        .bind(self.limits.records)
        .bind(admin_id)
        .bind(route)
        .bind(self.limits.records_per_admin_route)
        .execute(&mut *transaction)
        .await?;
        let existing = fetch_by_key(&mut transaction, admin_id, route, &key_digest).await?;
        let Some(existing) = existing else {
            transaction.commit().await?;
            return Err(SourceCreationIdempotencyError::Capacity);
        };
        validate_row_binding(&existing, admin_id, route, &key_digest)?;
        let status = classify_status(&self.keyring, &existing, now)?;
        transaction.commit().await?;
        Ok(status)
    }

    pub(crate) async fn fail(
        &self,
        reservation: &SourceCreationReservation,
        response: &SourceCreationResponse,
    ) -> Result<SourceCreationIdempotencyStatus, SourceCreationIdempotencyError> {
        validate_reservation(reservation)?;
        if validate_response(response).is_err() {
            return self.interrupt(reservation).await;
        }
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let now = effective_now_in(&mut transaction, self.clock.now().max(0)).await?;
        let expires_at = terminal_expiry(now)?;
        let purge_at = tombstone_expiry(now)?;
        let response_ciphertext = match encrypt_response(
            &self.keyring,
            reservation,
            SourceCreationResponseKind::Failed,
            now,
            expires_at,
            purge_at,
            response,
        ) {
            Ok(ciphertext) => ciphertext,
            Err(_) => {
                interrupt_reservation_in(&mut transaction, reservation, now, expires_at, purge_at)
                    .await?;
                let row = fetch_by_id(&mut transaction, &reservation.id)
                    .await?
                    .ok_or(SourceCreationIdempotencyError::InvalidMetadata)?;
                validate_reservation_row(&row, reservation)?;
                let status = classify_status(&self.keyring, &row, now)?;
                transaction.commit().await?;
                return Ok(status);
            }
        };
        let ciphertext_len = i64::try_from(response_ciphertext.len())
            .map_err(|_| SourceCreationIdempotencyError::PayloadTooLarge)?;
        let failed = sqlx::query(
            "UPDATE source_creation_idempotency \
             SET state = 'failed', response_ciphertext = ?, updated_at = ?, \
                 completed_at = ?, expires_at = ?, purge_at = ? \
             WHERE id = ? AND admin_id = ? AND route = ? AND key_digest = ? \
               AND request_digest = ? AND created_at = ? AND state = 'reserved' \
               AND ? <= ? - ( \
                   SELECT COALESCE(SUM(length(response_ciphertext)), 0) \
                   FROM source_creation_idempotency WHERE id <> ? \
               )",
        )
        .bind(response_ciphertext)
        .bind(now)
        .bind(now)
        .bind(expires_at)
        .bind(purge_at)
        .bind(&reservation.id)
        .bind(reservation.admin_id)
        .bind(&reservation.route)
        .bind(reservation.key_digest.to_vec())
        .bind(reservation.request_digest.to_vec())
        .bind(reservation.created_at)
        .bind(ciphertext_len)
        .bind(reservation.limits.response_ciphertext_bytes)
        .bind(&reservation.id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let mut row = fetch_by_id(&mut transaction, &reservation.id)
            .await?
            .ok_or(SourceCreationIdempotencyError::InvalidMetadata)?;
        validate_reservation_row(&row, reservation)?;
        if failed == 0 && row.state == "reserved" {
            interrupt_reservation_in(&mut transaction, reservation, now, expires_at, purge_at)
                .await?;
            row = fetch_by_id(&mut transaction, &reservation.id)
                .await?
                .ok_or(SourceCreationIdempotencyError::InvalidMetadata)?;
            validate_reservation_row(&row, reservation)?;
        }
        let status = classify_status(&self.keyring, &row, now)?;
        transaction.commit().await?;
        Ok(status)
    }

    pub(crate) async fn interrupt(
        &self,
        reservation: &SourceCreationReservation,
    ) -> Result<SourceCreationIdempotencyStatus, SourceCreationIdempotencyError> {
        validate_reservation(reservation)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let now = effective_now_in(&mut transaction, self.clock.now().max(0)).await?;
        interrupt_reservation_in(
            &mut transaction,
            reservation,
            now,
            terminal_expiry(now)?,
            tombstone_expiry(now)?,
        )
        .await?;
        let row = fetch_by_id(&mut transaction, &reservation.id)
            .await?
            .ok_or(SourceCreationIdempotencyError::InvalidMetadata)?;
        validate_reservation_row(&row, reservation)?;
        let status = classify_status(&self.keyring, &row, now)?;
        transaction.commit().await?;
        Ok(status)
    }
}

pub(crate) async fn complete_source_creation_in(
    transaction: &mut Transaction<'_, Sqlite>,
    keyring: &Keyring,
    reservation: &SourceCreationReservation,
    response_body: &[u8],
    observed_now: i64,
) -> Result<(), CatalogError> {
    let response = SourceCreationResponse::json(201, response_body.to_vec());
    complete_in(transaction, keyring, reservation, &response, observed_now)
        .await
        .map_err(source_idempotency_catalog_error)
}

async fn complete_in(
    transaction: &mut Transaction<'_, Sqlite>,
    keyring: &Keyring,
    reservation: &SourceCreationReservation,
    response: &SourceCreationResponse,
    observed_now: i64,
) -> Result<(), SourceCreationIdempotencyError> {
    validate_reservation(reservation)?;
    let now = effective_now_in(transaction, observed_now.max(0)).await?;
    let expires_at = terminal_expiry(now)?;
    let purge_at = tombstone_expiry(now)?;
    let response_ciphertext = encrypt_response(
        keyring,
        reservation,
        SourceCreationResponseKind::Completed,
        now,
        expires_at,
        purge_at,
        response,
    )?;
    let ciphertext_len = i64::try_from(response_ciphertext.len())
        .map_err(|_| SourceCreationIdempotencyError::PayloadTooLarge)?;
    let completed = sqlx::query(
        "UPDATE source_creation_idempotency \
         SET state = 'completed', response_ciphertext = ?, updated_at = ?, \
             completed_at = ?, expires_at = ?, purge_at = ? \
         WHERE id = ? AND admin_id = ? AND route = ? AND key_digest = ? \
           AND request_digest = ? AND created_at = ? AND state = 'reserved' \
           AND ? <= ? - ( \
               SELECT COALESCE(SUM(length(response_ciphertext)), 0) \
               FROM source_creation_idempotency WHERE id <> ? \
           )",
    )
    .bind(response_ciphertext)
    .bind(now)
    .bind(now)
    .bind(expires_at)
    .bind(purge_at)
    .bind(&reservation.id)
    .bind(reservation.admin_id)
    .bind(&reservation.route)
    .bind(reservation.key_digest.to_vec())
    .bind(reservation.request_digest.to_vec())
    .bind(reservation.created_at)
    .bind(ciphertext_len)
    .bind(reservation.limits.response_ciphertext_bytes)
    .bind(&reservation.id)
    .execute(&mut **transaction)
    .await?;
    if completed.rows_affected() == 1 {
        Ok(())
    } else {
        Err(SourceCreationIdempotencyError::InvalidMetadata)
    }
}

pub(crate) async fn recover_source_creation_idempotency(
    pool: &SqlitePool,
) -> Result<SourceCreationIdempotencyRecovery, sqlx::Error> {
    recover_startup_at(pool, SystemClock.now().max(0)).await
}

async fn recover_startup_at(
    pool: &SqlitePool,
    observed_now: i64,
) -> Result<SourceCreationIdempotencyRecovery, sqlx::Error> {
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    let now = effective_now_in(&mut transaction, observed_now.max(0)).await?;
    let tombstones_purged = purge_tombstones_in(&mut transaction, now, PURGE_BATCH).await?;
    let expires_at =
        terminal_expiry(now).map_err(|_| sqlx::Error::Protocol("clock overflow".into()))?;
    let purge_at =
        tombstone_expiry(now).map_err(|_| sqlx::Error::Protocol("clock overflow".into()))?;
    let reservations_interrupted = sqlx::query(
        "UPDATE source_creation_idempotency \
         SET state = 'interrupted', updated_at = ?, completed_at = ?, expires_at = ?, purge_at = ? \
         WHERE state = 'reserved'",
    )
    .bind(now)
    .bind(now)
    .bind(expires_at)
    .bind(purge_at)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    transaction.commit().await?;
    Ok(SourceCreationIdempotencyRecovery {
        reservations_interrupted,
        tombstones_purged,
    })
}

pub(crate) fn source_creation_idempotency_key_is_valid(key: &str) -> bool {
    validate_key(key).is_ok()
}

fn source_idempotency_catalog_error(error: SourceCreationIdempotencyError) -> CatalogError {
    match error {
        SourceCreationIdempotencyError::Database(error) => CatalogError::Database(error),
        SourceCreationIdempotencyError::Crypto(error) => CatalogError::Crypto(error),
        SourceCreationIdempotencyError::Json(error) => CatalogError::Json(error),
        SourceCreationIdempotencyError::InvalidKey
        | SourceCreationIdempotencyError::InvalidMetadata
        | SourceCreationIdempotencyError::PayloadTooLarge
        | SourceCreationIdempotencyError::Capacity
        | SourceCreationIdempotencyError::CorruptData => {
            CatalogError::CorruptData("source creation idempotency completion failed")
        }
    }
}

async fn fetch_by_key(
    transaction: &mut Transaction<'_, Sqlite>,
    admin_id: i64,
    route: &str,
    key_digest: &[u8],
) -> Result<Option<SourceCreationIdempotencyRow>, sqlx::Error> {
    sqlx::query_as::<_, SourceCreationIdempotencyRow>(
        "SELECT id, admin_id, route, key_digest, request_digest, state, response_ciphertext, \
                created_at, updated_at, completed_at, expires_at, purge_at \
         FROM source_creation_idempotency \
         WHERE admin_id = ? AND route = ? AND key_digest = ?",
    )
    .bind(admin_id)
    .bind(route)
    .bind(key_digest)
    .fetch_optional(&mut **transaction)
    .await
}

async fn fetch_by_id(
    transaction: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<Option<SourceCreationIdempotencyRow>, sqlx::Error> {
    sqlx::query_as::<_, SourceCreationIdempotencyRow>(
        "SELECT id, admin_id, route, key_digest, request_digest, state, response_ciphertext, \
                created_at, updated_at, completed_at, expires_at, purge_at \
         FROM source_creation_idempotency WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&mut **transaction)
    .await
}

async fn effective_now_in(
    transaction: &mut Transaction<'_, Sqlite>,
    observed_now: i64,
) -> Result<i64, sqlx::Error> {
    sqlx::query(
        "UPDATE source_creation_idempotency_clock \
         SET effective_now = MAX(effective_now, ?) WHERE id = 1",
    )
    .bind(observed_now)
    .execute(&mut **transaction)
    .await?;
    sqlx::query_scalar("SELECT effective_now FROM source_creation_idempotency_clock WHERE id = 1")
        .fetch_one(&mut **transaction)
        .await
}

async fn interrupt_reservation_in(
    transaction: &mut Transaction<'_, Sqlite>,
    reservation: &SourceCreationReservation,
    now: i64,
    expires_at: i64,
    purge_at: i64,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "UPDATE source_creation_idempotency \
         SET state = 'interrupted', updated_at = ?, completed_at = ?, expires_at = ?, purge_at = ? \
         WHERE id = ? AND admin_id = ? AND route = ? AND key_digest = ? \
           AND request_digest = ? AND created_at = ? AND state = 'reserved'",
    )
    .bind(now)
    .bind(now)
    .bind(expires_at)
    .bind(purge_at)
    .bind(&reservation.id)
    .bind(reservation.admin_id)
    .bind(&reservation.route)
    .bind(reservation.key_digest.to_vec())
    .bind(reservation.request_digest.to_vec())
    .bind(reservation.created_at)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
}

async fn purge_tombstones_in(
    transaction: &mut Transaction<'_, Sqlite>,
    now: i64,
    maximum_rows: i64,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "DELETE FROM source_creation_idempotency WHERE sequence IN ( \
             SELECT sequence FROM source_creation_idempotency \
             WHERE state <> 'reserved' AND purge_at <= ? \
             ORDER BY purge_at, sequence LIMIT ? \
         )",
    )
    .bind(now)
    .bind(maximum_rows)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
}

async fn purge_tombstones_for_admission_in(
    transaction: &mut Transaction<'_, Sqlite>,
    admin_id: i64,
    route: &str,
    now: i64,
    maximum_rows: i64,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "DELETE FROM source_creation_idempotency WHERE sequence IN ( \
             SELECT sequence FROM source_creation_idempotency \
             WHERE state <> 'reserved' AND purge_at <= ? \
             ORDER BY CASE WHEN admin_id = ? AND route = ? THEN 0 ELSE 1 END, \
                      purge_at, sequence LIMIT ? \
         )",
    )
    .bind(now)
    .bind(admin_id)
    .bind(route)
    .bind(maximum_rows)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
}

fn classify_status(
    keyring: &Keyring,
    row: &SourceCreationIdempotencyRow,
    now: i64,
) -> Result<SourceCreationIdempotencyStatus, SourceCreationIdempotencyError> {
    if row.state != "reserved" && row.expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Ok(SourceCreationIdempotencyStatus::Expired);
    }
    match row.state.as_str() {
        "reserved" if row.request_digest.is_some() && row.response_ciphertext.is_none() => {
            Ok(SourceCreationIdempotencyStatus::InProgress)
        }
        "completed" => Ok(SourceCreationIdempotencyStatus::Replay(
            SourceCreationReplay {
                kind: SourceCreationResponseKind::Completed,
                response: decrypt_response(keyring, row)?,
            },
        )),
        "failed" => Ok(SourceCreationIdempotencyStatus::Replay(
            SourceCreationReplay {
                kind: SourceCreationResponseKind::Failed,
                response: decrypt_response(keyring, row)?,
            },
        )),
        "abandoned" if row.response_ciphertext.is_none() => {
            Ok(SourceCreationIdempotencyStatus::Abandoned)
        }
        "interrupted" if row.request_digest.is_some() && row.response_ciphertext.is_none() => {
            Ok(SourceCreationIdempotencyStatus::Interrupted)
        }
        _ => Err(SourceCreationIdempotencyError::CorruptData),
    }
}

fn request_digest(
    keyring: &Keyring,
    admin_id: i64,
    route: &str,
    canonical_request: &[u8],
) -> [u8; 32] {
    let body_digest = keyring.digest(REQUEST_BODY_DIGEST_PURPOSE, canonical_request);
    let mut input = Vec::with_capacity(route.len() + 80);
    input.extend_from_slice(b"executor-source-creation-idempotency-request-v1");
    append_field(&mut input, &admin_id.to_be_bytes());
    append_field(&mut input, route.as_bytes());
    append_field(&mut input, &body_digest);
    keyring.digest(REQUEST_DIGEST_PURPOSE, &input)
}

fn validate_row_binding(
    row: &SourceCreationIdempotencyRow,
    admin_id: i64,
    route: &str,
    key_digest: &[u8; 32],
) -> Result<(), SourceCreationIdempotencyError> {
    if row.id.is_empty()
        || row.id.len() > 128
        || row.admin_id != admin_id
        || row.route != route
        || row.key_digest.len() != 32
        || !bool::from(row.key_digest.as_slice().ct_eq(key_digest.as_slice()))
        || row.created_at < 0
        || row.purge_at.is_some_and(|purge_at| purge_at < 0)
    {
        return Err(SourceCreationIdempotencyError::CorruptData);
    }
    Ok(())
}

fn validate_reservation(
    reservation: &SourceCreationReservation,
) -> Result<(), SourceCreationIdempotencyError> {
    validate_admin_id(reservation.admin_id)?;
    validate_route(&reservation.route)?;
    if reservation.id.is_empty()
        || reservation.id.len() > 128
        || reservation.id.contains('\0')
        || reservation.created_at < 0
        || reservation.limits.records <= 0
        || reservation.limits.records_per_admin_route <= 0
        || reservation.limits.response_ciphertext_bytes < 0
    {
        return Err(SourceCreationIdempotencyError::InvalidMetadata);
    }
    Ok(())
}

fn validate_reservation_row(
    row: &SourceCreationIdempotencyRow,
    reservation: &SourceCreationReservation,
) -> Result<(), SourceCreationIdempotencyError> {
    let Some(request_digest) = row.request_digest.as_deref() else {
        return Err(SourceCreationIdempotencyError::InvalidMetadata);
    };
    if row.id != reservation.id
        || row.admin_id != reservation.admin_id
        || row.route != reservation.route
        || row.created_at != reservation.created_at
        || row.key_digest.len() != 32
        || request_digest.len() != 32
        || !bool::from(
            row.key_digest
                .as_slice()
                .ct_eq(reservation.key_digest.as_slice()),
        )
        || !bool::from(request_digest.ct_eq(reservation.request_digest.as_slice()))
    {
        return Err(SourceCreationIdempotencyError::InvalidMetadata);
    }
    Ok(())
}

fn validate_admin_id(admin_id: i64) -> Result<(), SourceCreationIdempotencyError> {
    if admin_id <= 0 {
        return Err(SourceCreationIdempotencyError::InvalidMetadata);
    }
    Ok(())
}

fn validate_route(route: &str) -> Result<(), SourceCreationIdempotencyError> {
    if route.is_empty() || route.len() > 200 || route.contains('\0') {
        return Err(SourceCreationIdempotencyError::InvalidMetadata);
    }
    Ok(())
}

fn validate_key(key: &str) -> Result<(), SourceCreationIdempotencyError> {
    let bytes = key.as_bytes();
    if bytes.is_empty()
        || bytes.len() > SOURCE_CREATION_IDEMPOTENCY_KEY_MAX_BYTES
        || bytes.iter().any(|byte| !(0x21..=0x7e).contains(byte))
    {
        return Err(SourceCreationIdempotencyError::InvalidKey);
    }
    Ok(())
}

fn validate_response(
    response: &SourceCreationResponse,
) -> Result<(), SourceCreationIdempotencyError> {
    if !(100..=599).contains(&response.status)
        || response.body.len() > MAX_RESPONSE_BODY_BYTES
        || response.headers.len() > MAX_RESPONSE_HEADERS
    {
        return Err(SourceCreationIdempotencyError::PayloadTooLarge);
    }
    let header_bytes = response
        .headers
        .iter()
        .try_fold(0_usize, |total, (name, value)| {
            if name.is_empty()
                || name.contains(['\0', '\r', '\n'])
                || value.contains(['\0', '\r', '\n'])
                || HeaderName::try_from(name.as_str()).is_err()
                || HeaderValue::try_from(value.as_str()).is_err()
            {
                return None;
            }
            total.checked_add(name.len())?.checked_add(value.len())
        });
    if header_bytes.is_none_or(|bytes| bytes > MAX_RESPONSE_HEADER_BYTES) {
        return Err(SourceCreationIdempotencyError::PayloadTooLarge);
    }
    Ok(())
}

fn encrypt_response(
    keyring: &Keyring,
    reservation: &SourceCreationReservation,
    kind: SourceCreationResponseKind,
    completed_at: i64,
    expires_at: i64,
    purge_at: i64,
    response: &SourceCreationResponse,
) -> Result<Vec<u8>, SourceCreationIdempotencyError> {
    validate_response(response)?;
    let encoded = serde_json::to_vec(&StoredResponse {
        kind,
        status: response.status,
        headers: response.headers.clone(),
        body_base64: STANDARD.encode(&response.body),
    })?;
    let binding = ResponseBinding {
        id: &reservation.id,
        admin_id: reservation.admin_id,
        route: &reservation.route,
        key_digest: &reservation.key_digest,
        request_digest: &reservation.request_digest,
        created_at: reservation.created_at,
        kind,
        updated_at: completed_at,
        completed_at,
        expires_at,
        purge_at,
    };
    let ciphertext = keyring.encrypt(RESPONSE_PURPOSE, &response_record_id(&binding), &encoded)?;
    if ciphertext.len() > MAX_RESPONSE_CIPHERTEXT_BYTES as usize {
        return Err(SourceCreationIdempotencyError::PayloadTooLarge);
    }
    Ok(ciphertext)
}

fn decrypt_response(
    keyring: &Keyring,
    row: &SourceCreationIdempotencyRow,
) -> Result<SourceCreationResponse, SourceCreationIdempotencyError> {
    let ciphertext = row
        .response_ciphertext
        .as_deref()
        .ok_or(SourceCreationIdempotencyError::CorruptData)?;
    if ciphertext.len() > MAX_RESPONSE_CIPHERTEXT_BYTES as usize {
        return Err(SourceCreationIdempotencyError::CorruptData);
    }
    let binding = response_binding_from_row(row)?;
    let plaintext = keyring.decrypt(RESPONSE_PURPOSE, &response_record_id(&binding), ciphertext)?;
    let stored: StoredResponse = serde_json::from_slice(&plaintext)?;
    if stored.kind != binding.kind {
        return Err(SourceCreationIdempotencyError::CorruptData);
    }
    let response = SourceCreationResponse {
        status: stored.status,
        headers: stored.headers,
        body: STANDARD
            .decode(stored.body_base64)
            .map_err(|_| SourceCreationIdempotencyError::CorruptData)?,
    };
    validate_response(&response)?;
    Ok(response)
}

fn response_binding_from_row(
    row: &SourceCreationIdempotencyRow,
) -> Result<ResponseBinding<'_>, SourceCreationIdempotencyError> {
    let kind = match row.state.as_str() {
        "completed" => SourceCreationResponseKind::Completed,
        "failed" => SourceCreationResponseKind::Failed,
        _ => return Err(SourceCreationIdempotencyError::CorruptData),
    };
    let request_digest = row
        .request_digest
        .as_deref()
        .ok_or(SourceCreationIdempotencyError::CorruptData)?;
    let completed_at = row
        .completed_at
        .ok_or(SourceCreationIdempotencyError::CorruptData)?;
    let expires_at = row
        .expires_at
        .ok_or(SourceCreationIdempotencyError::CorruptData)?;
    let purge_at = row
        .purge_at
        .ok_or(SourceCreationIdempotencyError::CorruptData)?;
    Ok(ResponseBinding {
        id: &row.id,
        admin_id: row.admin_id,
        route: &row.route,
        key_digest: &row.key_digest,
        request_digest,
        created_at: row.created_at,
        kind,
        updated_at: row.updated_at,
        completed_at,
        expires_at,
        purge_at,
    })
}

fn response_record_id(binding: &ResponseBinding<'_>) -> String {
    let mut encoded = Vec::with_capacity(
        160 + binding.id.len()
            + binding.route.len()
            + binding.key_digest.len()
            + binding.request_digest.len(),
    );
    encoded.extend_from_slice(b"executor-source-creation-response-binding-v2");
    append_field(&mut encoded, binding.id.as_bytes());
    append_field(&mut encoded, &binding.admin_id.to_be_bytes());
    append_field(&mut encoded, binding.route.as_bytes());
    append_field(&mut encoded, binding.key_digest);
    append_field(&mut encoded, binding.request_digest);
    append_field(&mut encoded, &binding.created_at.to_be_bytes());
    append_field(&mut encoded, binding.kind.as_str().as_bytes());
    append_field(&mut encoded, &binding.updated_at.to_be_bytes());
    append_field(&mut encoded, &binding.completed_at.to_be_bytes());
    append_field(&mut encoded, &binding.expires_at.to_be_bytes());
    append_field(&mut encoded, &binding.purge_at.to_be_bytes());
    format!("v2:{}", URL_SAFE_NO_PAD.encode(encoded))
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, SourceCreationIdempotencyError> {
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
    serde_json::to_vec(&sort(value)).map_err(Into::into)
}

fn terminal_expiry(now: i64) -> Result<i64, SourceCreationIdempotencyError> {
    now.checked_add(SOURCE_CREATION_IDEMPOTENCY_TTL_SECONDS)
        .ok_or(SourceCreationIdempotencyError::InvalidMetadata)
}

fn tombstone_expiry(now: i64) -> Result<i64, SourceCreationIdempotencyError> {
    now.checked_add(SOURCE_CREATION_TOMBSTONE_TTL_SECONDS)
        .ok_or(SourceCreationIdempotencyError::InvalidMetadata)
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    };

    use base64::Engine as _;
    use serde_json::{Value, json};

    use super::{
        IdempotencyClock, MAX_REQUEST_BYTES, MAX_RESPONSE_BODY_BYTES,
        SOURCE_CREATION_IDEMPOTENCY_TTL_SECONDS, SOURCE_CREATION_ROUTE,
        SOURCE_CREATION_TOMBSTONE_TTL_SECONDS, SourceCreationIdempotencyClaim,
        SourceCreationIdempotencyError, SourceCreationIdempotencyLimits,
        SourceCreationIdempotencyStatus, SourceCreationIdempotencyStore, SourceCreationReplay,
        SourceCreationResponse, SourceCreationResponseKind, canonical_json, complete_in,
        recover_startup_at, source_creation_idempotency_key_is_valid,
    };
    use crate::{
        AppConfig,
        catalog::{
            AuditContext, CatalogError, CatalogStore, CreateSource, CredentialPayload,
            InitialCatalogSnapshot, SourceKind,
        },
        database::Database,
    };

    struct TestClock(AtomicI64);

    impl TestClock {
        fn new(now: i64) -> Self {
            Self(AtomicI64::new(now))
        }

        fn set(&self, now: i64) {
            self.0.store(now, Ordering::SeqCst);
        }
    }

    impl IdempotencyClock for TestClock {
        fn now(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    async fn fixture() -> (
        tempfile::TempDir,
        crate::database::OpenedDatabase,
        SourceCreationIdempotencyStore,
        Arc<TestClock>,
    ) {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let opened = Database::open(&AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("test database should open");
        sqlx::query(
            "INSERT INTO admins (id, username, password_hash, created_at) \
             VALUES (1, 'admin', 'test-password-hash', 1)",
        )
        .execute(&opened.database.pool)
        .await
        .expect("test admin should be inserted");
        sqlx::query(
            "UPDATE source_creation_idempotency_clock SET effective_now = 1000 WHERE id = 1",
        )
        .execute(&opened.database.pool)
        .await
        .expect("test clock should reset");
        let clock = Arc::new(TestClock::new(1_000));
        let store = SourceCreationIdempotencyStore::with_clock(
            opened.database.pool.clone(),
            opened.database.keyring.clone(),
            clock.clone(),
        );
        (directory, opened, store, clock)
    }

    async fn complete(
        store: &SourceCreationIdempotencyStore,
        reservation: &super::SourceCreationReservation,
        response: &SourceCreationResponse,
    ) -> Result<(), SourceCreationIdempotencyError> {
        let mut transaction = store.pool.begin_with("BEGIN IMMEDIATE").await?;
        complete_in(
            &mut transaction,
            &store.keyring,
            reservation,
            response,
            store.clock.now(),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn fresh(
        store: &SourceCreationIdempotencyStore,
        key: &str,
        request: &Value,
    ) -> super::SourceCreationReservation {
        let SourceCreationIdempotencyClaim::Fresh(reservation) = store
            .claim(1, SOURCE_CREATION_ROUTE, key, request)
            .await
            .expect("claim should succeed")
        else {
            panic!("claim should be fresh");
        };
        reservation
    }

    fn completed_replay(body: &[u8]) -> SourceCreationIdempotencyStatus {
        SourceCreationIdempotencyStatus::Replay(SourceCreationReplay {
            kind: SourceCreationResponseKind::Completed,
            response: SourceCreationResponse::json(201, body.to_vec()),
        })
    }

    async fn insert_purgeable_tombstones(
        pool: &sqlx::SqlitePool,
        id_prefix: &str,
        route: &str,
        count: usize,
        purge_at: i64,
    ) {
        let mut transaction = pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("tombstone fixture transaction should begin");
        for index in 0..count {
            let mut key_digest = [0xff_u8; 32];
            key_digest[24..].copy_from_slice(
                &u64::try_from(index)
                    .expect("fixture index should fit in u64")
                    .to_be_bytes(),
            );
            sqlx::query(
                "INSERT INTO source_creation_idempotency ( \
                     id, admin_id, route, key_digest, request_digest, state, \
                     created_at, updated_at, completed_at, expires_at, purge_at \
                 ) VALUES (?, 1, ?, ?, NULL, 'abandoned', 1, 1, 1, 2, ?)",
            )
            .bind(format!("{id_prefix}-{index}"))
            .bind(route)
            .bind(key_digest.to_vec())
            .bind(purge_at)
            .execute(&mut *transaction)
            .await
            .expect("purgeable tombstone fixture should insert");
        }
        transaction
            .commit()
            .await
            .expect("tombstone fixture transaction should commit");
    }

    async fn seed_admission_starvation(
        pool: &sqlx::SqlitePool,
        id_prefix: &str,
        target_route: &str,
    ) {
        let unrelated_id_prefix = format!("{id_prefix}-older-unrelated");
        let unrelated_route = format!("POST /unrelated-{id_prefix}");
        insert_purgeable_tombstones(
            pool,
            &unrelated_id_prefix,
            &unrelated_route,
            usize::try_from(super::PURGE_BATCH + 1).expect("purge batch should fit usize"),
            3,
        )
        .await;
        let target_id_prefix = format!("{id_prefix}-target");
        insert_purgeable_tombstones(
            pool,
            &target_id_prefix,
            target_route,
            usize::try_from(super::MAX_RECORDS_PER_ADMIN_ROUTE)
                .expect("scope capacity should fit usize"),
            4,
        )
        .await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM source_creation_idempotency \
                 WHERE admin_id = 1 AND route = ?",
            )
            .bind(&unrelated_route)
            .fetch_one(pool)
            .await
            .expect("unrelated backlog count should read"),
            super::PURGE_BATCH + 1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM source_creation_idempotency \
                 WHERE admin_id = 1 AND route = ?",
            )
            .bind(target_route)
            .fetch_one(pool)
            .await
            .expect("target scope count should read"),
            super::MAX_RECORDS_PER_ADMIN_ROUTE
        );
    }

    #[test]
    fn keys_and_canonical_request_size_are_bounded_consistently_with_the_route() {
        assert!(source_creation_idempotency_key_is_valid("a"));
        assert!(source_creation_idempotency_key_is_valid(&"x".repeat(255)));
        assert!(!source_creation_idempotency_key_is_valid(""));
        assert!(!source_creation_idempotency_key_is_valid(&"x".repeat(256)));
        assert!(!source_creation_idempotency_key_is_valid("contains space"));
        assert!(!source_creation_idempotency_key_is_valid("non-ascii-é"));

        let at_limit = Value::String("x".repeat(MAX_REQUEST_BYTES - 2));
        assert_eq!(
            canonical_json(&at_limit)
                .expect("boundary request should encode")
                .len(),
            MAX_REQUEST_BYTES
        );
        let over_limit = Value::String("x".repeat(MAX_REQUEST_BYTES - 1));
        assert!(
            canonical_json(&over_limit)
                .expect("oversized request should still encode")
                .len()
                > MAX_REQUEST_BYTES
        );
    }

    #[tokio::test]
    async fn injected_lookup_failure_is_clone_shared_one_shot_and_precedes_database_work() {
        let (_directory, opened, store, clock) = fixture().await;
        let cloned = store.clone();
        clock.set(2_000);
        store.fail_next_lookup_for_test();
        assert!(matches!(
            cloned
                .lookup(1, SOURCE_CREATION_ROUTE, "injected-lookup")
                .await,
            Err(SourceCreationIdempotencyError::Database(
                sqlx::Error::Protocol(message)
            )) if message == "injected source creation lookup failure"
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT effective_now FROM source_creation_idempotency_clock WHERE id = 1",
            )
            .fetch_one(&opened.database.pool)
            .await
            .expect("clock should read after injected lookup failure"),
            1_000
        );
        assert_eq!(
            store
                .lookup(1, SOURCE_CREATION_ROUTE, "injected-lookup")
                .await
                .expect("second lookup should consume no fault"),
            None
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT effective_now FROM source_creation_idempotency_clock WHERE id = 1",
            )
            .fetch_one(&opened.database.pool)
            .await
            .expect("clock should read after successful lookup"),
            2_000
        );
    }

    #[tokio::test]
    async fn canonical_requests_match_while_secret_only_changes_conflict() {
        let (_directory, _opened, store, _clock) = fixture().await;
        let first = json!({
            "kind": "openapi",
            "credential": { "token": "secret-a" },
            "displayName": "Example"
        });
        let reordered = json!({
            "displayName": "Example",
            "credential": { "token": "secret-a" },
            "kind": "openapi"
        });
        let changed_secret = json!({
            "displayName": "Example",
            "credential": { "token": "secret-b" },
            "kind": "openapi"
        });
        fresh(&store, "canonical-key", &first).await;
        assert!(matches!(
            store
                .claim(1, SOURCE_CREATION_ROUTE, "canonical-key", &reordered)
                .await
                .expect("matching claim should classify"),
            SourceCreationIdempotencyClaim::InProgress
        ));
        assert!(matches!(
            store
                .claim(1, SOURCE_CREATION_ROUTE, "canonical-key", &changed_secret)
                .await
                .expect("mismatch should classify"),
            SourceCreationIdempotencyClaim::Mismatch
        ));
        assert!(matches!(
            store
                .claim(
                    1,
                    SOURCE_CREATION_ROUTE,
                    "canonical-key",
                    &json!({
                        "displayName": "Example",
                        "credential": { "token": "secret-a" },
                        "kind": "graphql"
                    }),
                )
                .await
                .expect("kind mismatch should classify"),
            SourceCreationIdempotencyClaim::Mismatch
        ));
        assert!(matches!(
            store
                .claim(1, "POST /different", "canonical-key", &first)
                .await
                .expect("different route should have an independent scope"),
            SourceCreationIdempotencyClaim::Fresh(_)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_claims_elect_exactly_one_owner() {
        let (_directory, _opened, store, _clock) = fixture().await;
        let barrier = Arc::new(tokio::sync::Barrier::new(17));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let store = store.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                let request = json!({ "kind": "graphql", "secret": "same" });
                barrier.wait().await;
                store
                    .claim(1, SOURCE_CREATION_ROUTE, "concurrent-key", &request)
                    .await
            }));
        }
        barrier.wait().await;
        let mut fresh = 0;
        let mut in_progress = 0;
        for task in tasks {
            match task
                .await
                .expect("claim task should finish")
                .expect("claim should succeed")
            {
                SourceCreationIdempotencyClaim::Fresh(_) => fresh += 1,
                SourceCreationIdempotencyClaim::InProgress => in_progress += 1,
                other => panic!("unexpected concurrent outcome: {other:?}"),
            }
        }
        assert_eq!(fresh, 1);
        assert_eq!(in_progress, 15);
    }

    #[tokio::test]
    async fn concurrent_claim_and_missing_seal_elect_exactly_one_winner() {
        let (_directory, opened, store, _clock) = fixture().await;
        for index in 0..32 {
            let key = format!("claim-seal-race-{index}");
            let barrier = Arc::new(tokio::sync::Barrier::new(3));
            let claim_store = store.clone();
            let claim_barrier = barrier.clone();
            let claim_key = key.clone();
            let claim = tokio::spawn(async move {
                let request = json!({ "kind": "mcp_http", "index": index });
                claim_barrier.wait().await;
                claim_store
                    .claim(1, SOURCE_CREATION_ROUTE, &claim_key, &request)
                    .await
            });
            let seal_store = store.clone();
            let seal_barrier = barrier.clone();
            let seal_key = key.clone();
            let seal = tokio::spawn(async move {
                seal_barrier.wait().await;
                seal_store
                    .seal_missing(1, SOURCE_CREATION_ROUTE, &seal_key)
                    .await
            });
            barrier.wait().await;
            let claim = claim
                .await
                .expect("claim task should finish")
                .expect("claim should classify");
            let seal = seal
                .await
                .expect("seal task should finish")
                .expect("seal should classify");
            match (claim, seal) {
                (
                    SourceCreationIdempotencyClaim::Fresh(_),
                    SourceCreationIdempotencyStatus::InProgress,
                )
                | (
                    SourceCreationIdempotencyClaim::Abandoned,
                    SourceCreationIdempotencyStatus::Abandoned,
                ) => {}
                other => panic!("claim/seal race elected an invalid pair: {other:?}"),
            }
            let rows = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM source_creation_idempotency WHERE route = ?",
            )
            .bind(SOURCE_CREATION_ROUTE)
            .fetch_one(&opened.database.pool)
            .await
            .expect("race row count should read");
            assert_eq!(rows, i64::from(index + 1));
        }
    }

    #[tokio::test]
    async fn seal_does_not_cancel_an_active_owner_and_replays_after_completion() {
        let (_directory, _opened, store, _clock) = fixture().await;
        let request = json!({ "kind": "mcp_stdio" });
        let reservation = fresh(&store, "active-seal", &request).await;
        assert_eq!(
            store
                .seal_missing(1, SOURCE_CREATION_ROUTE, "active-seal")
                .await
                .expect("active seal should classify"),
            SourceCreationIdempotencyStatus::InProgress
        );
        let body = br#"{"id":"active-source"}"#;
        complete(
            &store,
            &reservation,
            &SourceCreationResponse::json(201, body.to_vec()),
        )
        .await
        .expect("active owner should still complete");
        assert_eq!(
            store
                .seal_missing(1, SOURCE_CREATION_ROUTE, "active-seal")
                .await
                .expect("completed seal should replay"),
            completed_replay(body)
        );
    }

    #[tokio::test]
    async fn startup_interrupts_reservations_and_fences_delayed_completion() {
        let (_directory, opened, store, _clock) = fixture().await;
        let request = json!({ "kind": "graphql" });
        let reservation = fresh(&store, "restart-key", &request).await;
        let recovery = recover_startup_at(&store.pool, 1_001)
            .await
            .expect("startup recovery should succeed");
        assert_eq!(recovery.reservations_interrupted, 1);
        assert!(matches!(
            store
                .claim(1, SOURCE_CREATION_ROUTE, "restart-key", &request)
                .await
                .expect("delayed claim should classify"),
            SourceCreationIdempotencyClaim::Interrupted
        ));

        let catalog = CatalogStore::new(
            opened.database.pool.clone(),
            opened.database.keyring.clone(),
        );
        let error = create_empty_source(
            &catalog,
            &reservation,
            "restart-fenced",
            SourceKind::Graphql,
        )
        .await
        .expect_err("interrupted reservation must fence catalog commit");
        assert!(matches!(error, CatalogError::CorruptData(_)));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sources")
                .fetch_one(&opened.database.pool)
                .await
                .expect("source count should read"),
            0
        );
    }

    #[tokio::test]
    async fn database_reopen_runs_interruption_recovery_under_the_instance_lock() {
        let (directory, opened, store, _clock) = fixture().await;
        let request = json!({ "kind": "mcp_http" });
        fresh(&store, "real-restart-key", &request).await;
        store.pool.close().await;
        drop(store);
        drop(opened);

        let reopened = Database::open(&AppConfig::new(directory.path().to_path_buf()))
            .await
            .expect("database should reopen");
        let restarted = SourceCreationIdempotencyStore::new(
            reopened.database.pool.clone(),
            reopened.database.keyring.clone(),
        );
        assert_eq!(
            restarted
                .lookup(1, SOURCE_CREATION_ROUTE, "real-restart-key")
                .await
                .expect("recovered key should read"),
            Some(SourceCreationIdempotencyStatus::Interrupted)
        );
        reopened.database.pool.close().await;
    }

    #[tokio::test]
    async fn definitive_failure_replays_exact_bytes_and_never_stores_plaintext() {
        let (_directory, opened, store, _clock) = fixture().await;
        let request = json!({
            "kind": "openapi",
            "credential": "request-secret-marker"
        });
        let reservation = fresh(&store, "raw-key-marker", &request).await;
        let response = SourceCreationResponse {
            status: 400,
            headers: std::collections::BTreeMap::from([
                ("content-type".to_owned(), "application/json".to_owned()),
                ("x-safe".to_owned(), "stable".to_owned()),
            ]),
            body: br#"{"code":"definitive","marker":"response-secret-marker"}"#.to_vec(),
        };
        assert_eq!(
            store
                .fail(&reservation, &response)
                .await
                .expect("failure should persist"),
            SourceCreationIdempotencyStatus::Replay(SourceCreationReplay {
                kind: SourceCreationResponseKind::Failed,
                response: response.clone(),
            })
        );
        assert!(matches!(
            store
                .claim(1, SOURCE_CREATION_ROUTE, "raw-key-marker", &request)
                .await
                .expect("delayed duplicate should replay"),
            SourceCreationIdempotencyClaim::Replay(SourceCreationReplay {
                kind: SourceCreationResponseKind::Failed,
                response: replayed,
            }) if replayed == response
        ));

        let stored = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT key_digest, request_digest, response_ciphertext \
             FROM source_creation_idempotency WHERE id = ?",
        )
        .bind(reservation.id())
        .fetch_one(&opened.database.pool)
        .await
        .expect("stored row should read");
        let storage =
            String::from_utf8_lossy(&[stored.0, stored.1, stored.2].concat()).into_owned();
        assert!(!storage.contains("raw-key-marker"));
        assert!(!storage.contains("request-secret-marker"));
        assert!(!storage.contains("response-secret-marker"));
    }

    #[tokio::test]
    async fn copied_ciphertext_cannot_cross_its_admin_route_record_aad_scope() {
        let (_directory, opened, store, _clock) = fixture().await;
        let request = json!({ "kind": "openapi" });
        let reservation = fresh(&store, "aad-original", &request).await;
        complete(
            &store,
            &reservation,
            &SourceCreationResponse::json(201, br#"{"id":"aad-source"}"#.to_vec()),
        )
        .await
        .expect("original response should complete");
        let ciphertext = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT response_ciphertext FROM source_creation_idempotency WHERE id = ?",
        )
        .bind(reservation.id())
        .fetch_one(&opened.database.pool)
        .await
        .expect("original ciphertext should read");
        let copied_key_digest = store
            .keyring
            .digest(super::KEY_DIGEST_PURPOSE, b"aad-copied");
        sqlx::query(
            "INSERT INTO source_creation_idempotency ( \
                 id, admin_id, route, key_digest, request_digest, state, response_ciphertext, \
                 created_at, updated_at, completed_at, expires_at, purge_at \
             ) VALUES ( \
                 'copied-response', 1, 'POST /different', ?, ?, 'completed', ?, \
                 1000, 1000, 1000, 87400, 605800 \
             )",
        )
        .bind(copied_key_digest.to_vec())
        .bind(vec![7_u8; 32])
        .bind(ciphertext)
        .execute(&opened.database.pool)
        .await
        .expect("copied ciphertext fixture should insert");

        assert!(matches!(
            store.lookup(1, "POST /different", "aad-copied").await,
            Err(SourceCreationIdempotencyError::Crypto(_))
        ));
        assert!(matches!(
            store.lookup(1, "POST /different", "aad-copied").await,
            Err(SourceCreationIdempotencyError::Crypto(_))
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM source_creation_idempotency WHERE id = 'copied-response'",
            )
            .fetch_one(&opened.database.pool)
            .await
            .expect("copied row count should read"),
            1
        );
    }

    #[tokio::test]
    async fn response_envelope_rejects_every_immutable_binding_and_kind_substitution() {
        let (_directory, _opened, store, _clock) = fixture().await;
        let request = json!({ "kind": "openapi", "secret": "bound" });
        let reservation = fresh(&store, "full-aad-binding", &request).await;
        let response = SourceCreationResponse::json(201, br#"{"id":"bound-source"}"#.to_vec());
        complete(&store, &reservation, &response)
            .await
            .expect("bound response should complete");
        let mut transaction = store
            .pool
            .begin()
            .await
            .expect("binding read transaction should begin");
        let original = super::fetch_by_id(&mut transaction, reservation.id())
            .await
            .expect("bound row should read")
            .expect("bound row should exist");
        transaction
            .commit()
            .await
            .expect("binding read transaction should commit");
        assert_eq!(
            super::decrypt_response(&store.keyring, &original)
                .expect("untampered response should decrypt"),
            response
        );

        let mut substitutions = Vec::new();
        let mut row = original.clone();
        row.id.push_str("-changed");
        substitutions.push(("id", row));
        let mut row = original.clone();
        row.admin_id += 1;
        substitutions.push(("admin_id", row));
        let mut row = original.clone();
        row.route.push_str("/changed");
        substitutions.push(("route", row));
        let mut row = original.clone();
        row.key_digest[0] ^= 1;
        substitutions.push(("key_digest", row));
        let mut row = original.clone();
        row.request_digest
            .as_mut()
            .expect("completed row has a request digest")[0] ^= 1;
        substitutions.push(("request_digest", row));
        let mut row = original.clone();
        row.created_at += 1;
        substitutions.push(("created_at", row));
        let mut row = original.clone();
        row.state = "failed".to_owned();
        substitutions.push(("response_kind", row));
        let mut row = original.clone();
        row.updated_at += 1;
        substitutions.push(("updated_at", row));
        let mut row = original.clone();
        *row.completed_at
            .as_mut()
            .expect("completed row has a completion time") += 1;
        substitutions.push(("completed_at", row));
        let mut row = original.clone();
        *row.expires_at
            .as_mut()
            .expect("completed row has an expiry") += 1;
        substitutions.push(("expires_at", row));
        let mut row = original.clone();
        *row.purge_at
            .as_mut()
            .expect("completed row has a purge time") += 1;
        substitutions.push(("purge_at", row));
        let mut row = original.clone();
        row.response_ciphertext
            .as_mut()
            .expect("completed row has ciphertext")[0] ^= 1;
        substitutions.push(("response_ciphertext", row));

        for (field, row) in substitutions {
            assert!(
                super::decrypt_response(&store.keyring, &row).is_err(),
                "tampered {field} must fail closed"
            );
        }

        let binding = super::response_binding_from_row(&original)
            .expect("completed row should produce a response binding");
        let mismatched_envelope = serde_json::to_vec(&super::StoredResponse {
            kind: SourceCreationResponseKind::Failed,
            status: response.status,
            headers: response.headers.clone(),
            body_base64: super::STANDARD.encode(&response.body),
        })
        .expect("mismatched envelope should encode");
        let mismatched_ciphertext = store
            .keyring
            .encrypt(
                super::RESPONSE_PURPOSE,
                &super::response_record_id(&binding),
                &mismatched_envelope,
            )
            .expect("mismatched envelope fixture should encrypt");
        let mut mismatched_row = original;
        mismatched_row.response_ciphertext = Some(mismatched_ciphertext);
        assert!(matches!(
            super::decrypt_response(&store.keyring, &mismatched_row),
            Err(SourceCreationIdempotencyError::CorruptData)
        ));
    }

    #[tokio::test]
    async fn uncacheable_failure_becomes_an_interrupted_tombstone() {
        let (_directory, _opened, store, _clock) = fixture().await;
        let request = json!({ "kind": "openapi" });
        let reservation = fresh(&store, "oversized-failure", &request).await;
        let oversized = SourceCreationResponse::json(500, vec![b'x'; MAX_RESPONSE_BODY_BYTES + 1]);
        assert_eq!(
            store
                .fail(&reservation, &oversized)
                .await
                .expect("uncacheable failure should be fenced"),
            SourceCreationIdempotencyStatus::Interrupted
        );
        assert!(matches!(
            store
                .claim(1, SOURCE_CREATION_ROUTE, "oversized-failure", &request)
                .await
                .expect("retry should remain fenced"),
            SourceCreationIdempotencyClaim::Interrupted
        ));
    }

    #[tokio::test]
    async fn catalog_commit_is_atomic_correlated_and_replay_survives_source_deletion() {
        let (_directory, opened, store, _clock) = fixture().await;
        let request = json!({ "kind": "openapi", "displayName": "Atomic" });
        let reservation = fresh(&store, "catalog-key", &request).await;
        let catalog = CatalogStore::new(
            opened.database.pool.clone(),
            opened.database.keyring.clone(),
        );
        let (source, _) =
            create_empty_source(&catalog, &reservation, "atomic", SourceKind::Openapi)
                .await
                .expect("source and replay should commit");
        let expected_body = serde_json::to_vec(&source).expect("source should encode");
        assert!(matches!(
            store
                .claim(1, SOURCE_CREATION_ROUTE, "catalog-key", &request)
                .await
                .expect("completed key should replay"),
            SourceCreationIdempotencyClaim::Replay(SourceCreationReplay {
                kind: SourceCreationResponseKind::Completed,
                response,
            }) if response == SourceCreationResponse::json(201, expected_body.clone())
        ));
        let audit_metadata = sqlx::query_scalar::<_, String>(
            "SELECT metadata_json FROM audit_events \
             WHERE action = 'source.created' AND source_id = ?",
        )
        .bind(&source.id)
        .fetch_one(&opened.database.pool)
        .await
        .expect("creation audit should read");
        let audit_metadata: Value =
            serde_json::from_str(&audit_metadata).expect("audit metadata should decode");
        assert_eq!(audit_metadata["idempotencyRecordId"], reservation.id());
        assert!(!audit_metadata.to_string().contains("catalog-key"));
        let audit_count_before_replay =
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
                .fetch_one(&opened.database.pool)
                .await
                .expect("audit count should read");
        let revision_before_replay = catalog
            .global_revision()
            .await
            .expect("catalog revision should read");
        assert!(matches!(
            store
                .claim(1, SOURCE_CREATION_ROUTE, "catalog-key", &request)
                .await
                .expect("second replay should classify"),
            SourceCreationIdempotencyClaim::Replay(_)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_events")
                .fetch_one(&opened.database.pool)
                .await
                .expect("audit count should read"),
            audit_count_before_replay
        );
        assert_eq!(
            catalog
                .global_revision()
                .await
                .expect("catalog revision should read"),
            revision_before_replay
        );

        catalog
            .delete_source(&source.id, AuditContext::admin("delete-source", 1))
            .await
            .expect("source should delete");
        assert!(matches!(
            store
                .claim(1, SOURCE_CREATION_ROUTE, "catalog-key", &request)
                .await
                .expect("deleted source response should still replay"),
            SourceCreationIdempotencyClaim::Replay(SourceCreationReplay { response, .. })
                if response.body == expected_body
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sources")
                .fetch_one(&opened.database.pool)
                .await
                .expect("source count should read"),
            0
        );
    }

    #[tokio::test]
    async fn stale_reservation_cannot_complete_a_replacement_record() {
        let (_directory, opened, store, clock) = fixture().await;
        let request = json!({ "kind": "openapi" });
        let stale = fresh(&store, "stale-key", &request).await;
        store
            .interrupt(&stale)
            .await
            .expect("old reservation should terminalize");
        clock.set(1_000 + SOURCE_CREATION_TOMBSTONE_TTL_SECONDS);
        assert_eq!(
            store
                .lookup(1, SOURCE_CREATION_ROUTE, "stale-key")
                .await
                .expect("expired tombstone should purge"),
            None
        );
        let replacement = fresh(&store, "stale-key", &request).await;
        assert_ne!(stale.id(), replacement.id());
        let catalog = CatalogStore::new(
            opened.database.pool.clone(),
            opened.database.keyring.clone(),
        );
        assert!(
            create_empty_source(&catalog, &stale, "stale", SourceKind::Openapi)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .lookup(1, SOURCE_CREATION_ROUTE, "stale-key")
                .await
                .expect("replacement should remain"),
            Some(SourceCreationIdempotencyStatus::InProgress)
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sources")
                .fetch_one(&opened.database.pool)
                .await
                .expect("source count should read"),
            0
        );
    }

    #[tokio::test]
    async fn responses_expire_to_a_tombstone_before_the_key_can_be_purged() {
        let (_directory, _opened, store, clock) = fixture().await;
        let request = json!({ "kind": "openapi" });
        let reservation = fresh(&store, "expiry-key", &request).await;
        complete(
            &store,
            &reservation,
            &SourceCreationResponse::json(201, br#"{"id":"source"}"#.to_vec()),
        )
        .await
        .expect("completion should succeed");
        clock.set(1_000 + SOURCE_CREATION_IDEMPOTENCY_TTL_SECONDS);
        assert!(matches!(
            store
                .claim(1, SOURCE_CREATION_ROUTE, "expiry-key", &request)
                .await
                .expect("expired key should classify"),
            SourceCreationIdempotencyClaim::Expired
        ));
        clock.set(1_000 + SOURCE_CREATION_TOMBSTONE_TTL_SECONDS);
        assert_eq!(
            store
                .lookup(1, SOURCE_CREATION_ROUTE, "expiry-key")
                .await
                .expect("purge boundary should read"),
            None
        );
    }

    #[tokio::test]
    async fn claim_admission_prioritizes_scoped_tombstones_and_persists_monotonic_clock() {
        let (_directory, opened, store, clock) = fixture().await;
        seed_admission_starvation(
            &opened.database.pool,
            "claim-admission",
            SOURCE_CREATION_ROUTE,
        )
        .await;

        const ADVANCED_NOW: i64 = 20_000;
        clock.set(ADVANCED_NOW);
        let SourceCreationIdempotencyClaim::Fresh(reservation) = store
            .claim(
                1,
                SOURCE_CREATION_ROUTE,
                "scoped-claim-admission",
                &json!({ "kind": "openapi" }),
            )
            .await
            .expect("scoped cleanup should admit the claim")
        else {
            panic!("scoped cleanup should elect a fresh claim");
        };
        assert_eq!(reservation.created_at, ADVANCED_NOW);
        clock.set(2);
        assert_eq!(
            store
                .lookup(1, SOURCE_CREATION_ROUTE, "scoped-claim-admission")
                .await
                .expect("backward-clock claim lookup should succeed"),
            Some(SourceCreationIdempotencyStatus::InProgress)
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM source_creation_idempotency \
                 WHERE admin_id = 1 AND route = ?",
            )
            .bind(SOURCE_CREATION_ROUTE)
            .fetch_one(&opened.database.pool)
            .await
            .expect("admitted claim scope count should read"),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT effective_now FROM source_creation_idempotency_clock WHERE id = 1",
            )
            .fetch_one(&opened.database.pool)
            .await
            .expect("effective claim clock should read"),
            ADVANCED_NOW
        );
    }

    #[tokio::test]
    async fn seal_admission_prioritizes_scoped_tombstones_on_its_first_call() {
        let (_directory, opened, store, clock) = fixture().await;
        let seal_route = "POST /api/v1/sources/seal";
        seed_admission_starvation(&opened.database.pool, "seal-admission", seal_route).await;
        const ADVANCED_NOW: i64 = 20_000;
        clock.set(ADVANCED_NOW);
        assert_eq!(
            store
                .seal_missing(1, seal_route, "scoped-seal-admission")
                .await
                .expect("first seal should admit after scoped cleanup"),
            SourceCreationIdempotencyStatus::Abandoned
        );
        clock.set(2);
        assert_eq!(
            store
                .lookup(1, seal_route, "scoped-seal-admission")
                .await
                .expect("backward-clock seal lookup should succeed"),
            Some(SourceCreationIdempotencyStatus::Abandoned)
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT created_at FROM source_creation_idempotency \
                 WHERE admin_id = 1 AND route = ?",
            )
            .bind(seal_route)
            .fetch_one(&opened.database.pool)
            .await
            .expect("sealed row timestamp should read"),
            ADVANCED_NOW
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT effective_now FROM source_creation_idempotency_clock WHERE id = 1",
            )
            .fetch_one(&opened.database.pool)
            .await
            .expect("effective clock should read"),
            ADVANCED_NOW
        );
    }

    #[tokio::test]
    async fn row_and_response_capacity_fail_closed() {
        let (_directory, _opened, store, _clock) = fixture().await;
        let request = json!({ "kind": "openapi" });
        let row_limited = store.clone().with_limits(SourceCreationIdempotencyLimits {
            records: 1,
            records_per_admin_route: 1,
            response_ciphertext_bytes: 1_024,
        });
        fresh(&row_limited, "first-capacity", &request).await;
        assert!(matches!(
            row_limited
                .claim(1, SOURCE_CREATION_ROUTE, "second-capacity", &request)
                .await,
            Err(SourceCreationIdempotencyError::Capacity)
        ));

        let response_limited = store.with_limits(SourceCreationIdempotencyLimits {
            records: 10,
            records_per_admin_route: 10,
            response_ciphertext_bytes: 0,
        });
        let reservation = fresh(&response_limited, "response-capacity", &request).await;
        assert_eq!(
            response_limited
                .fail(
                    &reservation,
                    &SourceCreationResponse::json(400, br#"{"code":"failed"}"#.to_vec()),
                )
                .await
                .expect("response capacity should terminalize"),
            SourceCreationIdempotencyStatus::Interrupted
        );
    }

    async fn create_empty_source(
        catalog: &CatalogStore,
        reservation: &super::SourceCreationReservation,
        slug: &str,
        kind: SourceKind,
    ) -> Result<
        (
            crate::catalog::SourceRecord,
            crate::catalog::CatalogSyncResult,
        ),
        CatalogError,
    > {
        catalog
            .create_source_with_catalog(
                CreateSource {
                    kind,
                    preferred_slug: slug.to_owned(),
                    display_name: slug.to_owned(),
                    description: None,
                    configuration: serde_json::Map::new(),
                },
                &CredentialPayload {
                    schema_version: 1,
                    payload: json!({}),
                },
                InitialCatalogSnapshot {
                    artifacts: Vec::new(),
                    tools: Vec::new(),
                },
                Vec::new(),
                AuditContext::admin("source-create", 1)
                    .with_source_creation_idempotency(reservation),
            )
            .await
    }
}
