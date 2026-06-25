use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sqlx::{FromRow, SqlitePool};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::Keyring;

pub(crate) const IDEMPOTENCY_KEY_MAX_BYTES: usize = 255;

const KEY_DIGEST_PURPOSE: &str = "api-token-create-idempotency-key-v1";
const REQUEST_DIGEST_PURPOSE: &str = "api-token-create-request-v1";
const SECRET_DERIVATION_PURPOSE: &str = "api-token-create-secret-v1";
const TOKEN_DIGEST_PURPOSE: &str = "api-token";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeliveredToken {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) token: String,
    pub(crate) created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TokenCreationClaim {
    Fresh(DeliveredToken),
    Replay(DeliveredToken),
    Mismatch,
    Revoked,
}

#[derive(Debug, Error)]
pub(crate) enum TokenDeliveryError {
    #[error("API token delivery storage failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("stored API token delivery metadata is invalid")]
    CorruptData,
    #[error("the Idempotency-Key must contain between 1 and 255 visible ASCII bytes")]
    InvalidKey,
}

#[derive(FromRow)]
struct TokenCreationRow {
    record_id: String,
    admin_id: i64,
    key_digest: Vec<u8>,
    request_digest: Vec<u8>,
    token_id: String,
    created_at: i64,
    token_created_at: i64,
    name: String,
    token_digest: Vec<u8>,
    token_prefix: String,
    token_suffix: String,
    revoked_at: Option<i64>,
}

pub(crate) fn validate_idempotency_key(key: &str) -> Result<(), TokenDeliveryError> {
    if key.is_empty()
        || key.len() > IDEMPOTENCY_KEY_MAX_BYTES
        || !key.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(TokenDeliveryError::InvalidKey);
    }
    Ok(())
}

pub(crate) async fn claim_token_creation(
    pool: &SqlitePool,
    keyring: &Keyring,
    admin_id: i64,
    name: &str,
    key: &str,
    observed_now: i64,
) -> Result<TokenCreationClaim, TokenDeliveryError> {
    validate_idempotency_key(key)?;
    if admin_id <= 0 || name.is_empty() {
        return Err(TokenDeliveryError::CorruptData);
    }

    let key_digest = keyring.digest(KEY_DIGEST_PURPOSE, key.as_bytes());
    let request_digest = request_digest(keyring, admin_id, name);
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    let existing = sqlx::query_as::<_, TokenCreationRow>(
        "SELECT creation.record_id, creation.admin_id, creation.key_digest, \
         creation.request_digest, creation.token_id, creation.created_at, \
         token.created_at AS token_created_at, token.name, \
         token.token_digest, token.token_prefix, token.token_suffix, token.revoked_at \
         FROM api_token_creation_idempotency AS creation \
         JOIN api_tokens AS token ON token.id = creation.token_id \
         WHERE creation.admin_id = ? AND creation.key_digest = ?",
    )
    .bind(admin_id)
    .bind(key_digest.to_vec())
    .fetch_optional(&mut *transaction)
    .await?;

    if let Some(existing) = existing {
        let claim = replay_claim(keyring, existing, name, key, &key_digest, &request_digest)?;
        transaction.commit().await?;
        return Ok(claim);
    }

    let record_id = Uuid::new_v4().to_string();
    let token_id = Uuid::new_v4().to_string();
    let created_at = observed_now.max(0);
    let token = derive_token(
        keyring,
        admin_id,
        key,
        &record_id,
        &token_id,
        &request_digest,
        created_at,
    );
    let token_digest = keyring.digest(TOKEN_DIGEST_PURPOSE, token.as_bytes());
    let (token_prefix, token_suffix) = token_mask_parts(&token);

    sqlx::query(
        "INSERT INTO api_tokens \
         (id, name, token_digest, token_prefix, token_suffix, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&token_id)
    .bind(name)
    .bind(token_digest.to_vec())
    .bind(&token_prefix)
    .bind(&token_suffix)
    .bind(created_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO api_token_creation_idempotency \
         (record_id, admin_id, key_digest, request_digest, token_id, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&record_id)
    .bind(admin_id)
    .bind(key_digest.to_vec())
    .bind(request_digest.to_vec())
    .bind(&token_id)
    .bind(created_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    Ok(TokenCreationClaim::Fresh(DeliveredToken {
        id: token_id,
        name: name.to_owned(),
        token,
        created_at,
    }))
}

fn replay_claim(
    keyring: &Keyring,
    row: TokenCreationRow,
    name: &str,
    key: &str,
    key_digest: &[u8; 32],
    request_digest: &[u8; 32],
) -> Result<TokenCreationClaim, TokenDeliveryError> {
    if row.admin_id <= 0
        || row.created_at < 0
        || row.token_created_at != row.created_at
        || row.record_id.is_empty()
        || row.token_id.is_empty()
        || row.key_digest.len() != 32
        || row.request_digest.len() != 32
        || row.token_digest.len() != 32
        || !bool::from(row.key_digest.as_slice().ct_eq(key_digest.as_slice()))
    {
        return Err(TokenDeliveryError::CorruptData);
    }
    if !bool::from(
        row.request_digest
            .as_slice()
            .ct_eq(request_digest.as_slice()),
    ) {
        return Ok(TokenCreationClaim::Mismatch);
    }
    if row.name != name {
        return Err(TokenDeliveryError::CorruptData);
    }
    if row.revoked_at.is_some() {
        return Ok(TokenCreationClaim::Revoked);
    }

    let token = derive_token(
        keyring,
        row.admin_id,
        key,
        &row.record_id,
        &row.token_id,
        request_digest,
        row.created_at,
    );
    let expected_digest = keyring.digest(TOKEN_DIGEST_PURPOSE, token.as_bytes());
    let (expected_prefix, expected_suffix) = token_mask_parts(&token);
    if !bool::from(
        row.token_digest
            .as_slice()
            .ct_eq(expected_digest.as_slice()),
    ) || row.token_prefix != expected_prefix
        || row.token_suffix != expected_suffix
    {
        return Err(TokenDeliveryError::CorruptData);
    }

    Ok(TokenCreationClaim::Replay(DeliveredToken {
        id: row.token_id,
        name: row.name,
        token,
        created_at: row.created_at,
    }))
}

fn request_digest(keyring: &Keyring, admin_id: i64, name: &str) -> [u8; 32] {
    let mut binding = Vec::with_capacity(24 + name.len());
    binding.extend_from_slice(b"executor-api-token-create-request-v1");
    binding.extend_from_slice(&admin_id.to_be_bytes());
    append_length_prefixed(&mut binding, name.as_bytes());
    keyring.digest(REQUEST_DIGEST_PURPOSE, &binding)
}

fn derive_token(
    keyring: &Keyring,
    admin_id: i64,
    key: &str,
    record_id: &str,
    token_id: &str,
    request_digest: &[u8; 32],
    created_at: i64,
) -> String {
    let mut binding = Vec::with_capacity(128 + key.len() + record_id.len() + token_id.len());
    binding.extend_from_slice(b"executor-api-token-create-secret-v1");
    binding.extend_from_slice(&admin_id.to_be_bytes());
    append_length_prefixed(&mut binding, key.as_bytes());
    append_length_prefixed(&mut binding, record_id.as_bytes());
    append_length_prefixed(&mut binding, token_id.as_bytes());
    append_length_prefixed(&mut binding, request_digest);
    binding.extend_from_slice(&created_at.to_be_bytes());
    let secret = keyring.digest(SECRET_DERIVATION_PURPOSE, &binding);
    format!("exr_{}", URL_SAFE_NO_PAD.encode(secret))
}

fn token_mask_parts(token: &str) -> (String, String) {
    let prefix = token.chars().take(8).collect();
    let suffix = token
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (prefix, suffix)
}

fn append_length_prefixed(encoded: &mut Vec<u8>, value: &[u8]) {
    encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
    encoded.extend_from_slice(value);
}
