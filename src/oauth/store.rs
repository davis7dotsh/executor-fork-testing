use sqlx::{Row, SqlitePool};
use thiserror::Error;
use uuid::Uuid;

use crate::crypto::Keyring;

use super::{
    crypto::{OAuthCrypto, OAuthCryptoError},
    model::{
        AuthorizationExchangeClaim, OAuthClientSecretUpdate, OAuthConnection,
        OAuthConnectionConfig, OAuthConnectionStatus, OAuthCredential, OAuthSecretSet,
        PendingAuthorization, RefreshClaim,
    },
};

const AUTHORIZATION_ERROR_INTERRUPTED: &str = "exchange_interrupted";
const AUTHORIZATION_ERROR_EXPIRED: &str = "authorization_expired";
const AUTHORIZATION_ERROR_SUPERSEDED: &str = "authorization_superseded";
const AUTHORIZATION_ERROR_EXCHANGE_TIMEOUT: &str = "exchange_timeout";
const AUTHORIZATION_EXCHANGE_TTL_SECONDS: i64 = 60;
const REFRESH_ERROR_INVALID_GRANT: &str = "invalid_grant";
const REFRESH_ERROR_INTERRUPTED: &str = "refresh_interrupted";

#[derive(Debug, Error)]
pub(crate) enum OAuthStoreError {
    #[error("the OAuth connection was not found")]
    ConnectionNotFound,
    #[error("the OAuth connection changed concurrently")]
    Conflict,
    #[error("the OAuth authorization transaction is invalid, expired, or already consumed")]
    AuthorizationRejected,
    #[error("another refresh is already in progress")]
    RefreshInProgress,
    #[error("the OAuth connection requires authorization")]
    ReauthorizationRequired,
    #[error("the stored OAuth record is invalid")]
    InvalidStoredRecord,
    #[error("too many OAuth authorization transactions are active")]
    AuthorizationCapacity,
    #[error("could not encode OAuth configuration")]
    EncodeConfiguration(#[source] serde_json::Error),
    #[error("could not decode OAuth configuration")]
    DecodeConfiguration(#[source] serde_json::Error),
    #[error(transparent)]
    Crypto(#[from] OAuthCryptoError),
    #[error("OAuth persistence failed")]
    Database(#[source] sqlx::Error),
}

#[derive(Clone)]
pub(crate) struct OAuthStore {
    pool: SqlitePool,
    crypto: OAuthCrypto,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OAuthRecovery {
    pub(crate) interrupted_exchanges: u64,
    pub(crate) abandoned_refresh_leases: u64,
}

impl OAuthStore {
    pub(crate) fn new(pool: SqlitePool, keyring: Keyring) -> Self {
        Self {
            pool,
            crypto: OAuthCrypto::new(keyring),
        }
    }

    pub(crate) async fn create_connection(
        &self,
        source_id: &str,
        credential_key: &str,
        config: &OAuthConnectionConfig,
        initial_secrets: Option<&OAuthSecretSet>,
        now: i64,
    ) -> Result<OAuthCredential, OAuthStoreError> {
        let id = Uuid::new_v4().to_string();
        let config_json = encode_config(config)?;
        let secret_revision = initial_secrets.map(|_| 1_i64);
        let status = if initial_secrets.is_some_and(|secret| secret.access_token.is_some()) {
            OAuthConnectionStatus::Active
        } else {
            OAuthConnectionStatus::PendingAuthorization
        };
        let sealed = initial_secrets
            .map(|secret| self.crypto.seal_secrets(&id, 1, secret))
            .transpose()?;
        let granted_scopes_json = serde_json::to_string(
            &initial_secrets.map_or(&[][..], |secret| secret.granted_scopes.as_slice()),
        )
        .map_err(OAuthStoreError::EncodeConfiguration)?;
        let has_client_secret =
            initial_secrets.is_some_and(|secret| secret.client_secret.is_some());
        let has_refresh_token =
            initial_secrets.is_some_and(|secret| secret.refresh_token.is_some());
        let access_expires_at = initial_secrets.and_then(|secret| secret.access_token_expires_at);
        let authorized_at = initial_secrets
            .is_some_and(|secret| secret.access_token.is_some())
            .then_some(now);

        let mut transaction = self.pool.begin().await.map_err(database)?;
        sqlx::query(
            "INSERT INTO oauth_connections (
                id, source_id, credential_key, revision,
                current_config_revision, current_secret_revision, status,
                granted_scopes_json, has_client_secret, has_refresh_token,
                access_expires_at, authorized_at, last_refreshed_at, error_code,
                created_at, updated_at
             ) VALUES (?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)",
        )
        .bind(&id)
        .bind(source_id)
        .bind(credential_key)
        .bind(secret_revision)
        .bind(status.as_db_str())
        .bind(granted_scopes_json)
        .bind(has_client_secret)
        .bind(has_refresh_token)
        .bind(access_expires_at)
        .bind(authorized_at)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        sqlx::query(
            "INSERT INTO oauth_connection_config_revisions (
                connection_id, revision, config_json, created_at
             ) VALUES (?, 1, ?, ?)",
        )
        .bind(&id)
        .bind(config_json)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if let (Some(secret), Some(ciphertext)) = (initial_secrets, sealed) {
            insert_secret_revision(
                &mut transaction,
                &id,
                1,
                ciphertext,
                secret.access_token_expires_at,
                now,
            )
            .await?;
        }
        transaction.commit().await.map_err(database)?;

        Ok(OAuthCredential {
            connection: OAuthConnection {
                id,
                source_id: source_id.to_owned(),
                credential_key: credential_key.to_owned(),
                revision: 1,
                config_revision: 1,
                secret_revision,
                config: config.clone(),
                status,
                granted_scopes: initial_secrets
                    .map_or_else(Vec::new, |secret| secret.granted_scopes.clone()),
                has_client_secret,
                has_refresh_token,
                access_expires_at,
                authorized_at,
                last_refreshed_at: None,
                error_code: None,
                created_at: now,
                updated_at: now,
            },
            secrets: initial_secrets.cloned(),
        })
    }

    pub(crate) async fn upsert_connection(
        &self,
        source_id: &str,
        credential_key: &str,
        expected_revision: i64,
        config: &OAuthConnectionConfig,
        client_secret: OAuthClientSecretUpdate,
        now: i64,
    ) -> Result<OAuthCredential, OAuthStoreError> {
        if expected_revision == 0 {
            let initial_secrets = match client_secret {
                OAuthClientSecretUpdate::Preserve => return Err(OAuthStoreError::Conflict),
                OAuthClientSecretUpdate::Replace(None) => None,
                OAuthClientSecretUpdate::Replace(Some(client_secret)) => Some(OAuthSecretSet {
                    client_secret: Some(client_secret),
                    ..OAuthSecretSet::default()
                }),
            };
            return self
                .create_connection(
                    source_id,
                    credential_key,
                    config,
                    initial_secrets.as_ref(),
                    now,
                )
                .await
                .map_err(|error| match error {
                    OAuthStoreError::Database(ref database) if is_constraint(database) => {
                        OAuthStoreError::Conflict
                    }
                    other => other,
                });
        }

        let current = self
            .connection_by_source_key(source_id, credential_key)
            .await?;
        if current.connection.revision != expected_revision {
            return Err(OAuthStoreError::Conflict);
        }
        let existing_client_secret = current
            .secrets
            .as_ref()
            .and_then(|secrets| secrets.client_secret.clone());
        let client_secret = match client_secret {
            OAuthClientSecretUpdate::Preserve => existing_client_secret,
            OAuthClientSecretUpdate::Replace(replacement) => replacement,
        };
        let secrets = OAuthSecretSet {
            client_secret,
            ..OAuthSecretSet::default()
        };
        let secret_changed =
            current.connection.secret_revision.is_some() || secrets.client_secret.is_some();
        let next_config_revision = current
            .connection
            .config_revision
            .checked_add(1)
            .ok_or(OAuthStoreError::Conflict)?;
        let next_secret_revision = if secret_changed {
            Some(
                current
                    .connection
                    .secret_revision
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(OAuthStoreError::Conflict)?,
            )
        } else {
            current.connection.secret_revision
        };
        let config_json = encode_config(config)?;
        let sealed = if secret_changed {
            Some(self.crypto.seal_secrets(
                &current.connection.id,
                next_secret_revision.ok_or(OAuthStoreError::InvalidStoredRecord)?,
                &secrets,
            )?)
        } else {
            None
        };
        let granted_scopes_json = serde_json::to_string(&secrets.granted_scopes)
            .map_err(OAuthStoreError::EncodeConfiguration)?;
        let status = OAuthConnectionStatus::PendingAuthorization;

        let mut transaction = self.pool.begin().await.map_err(database)?;
        sqlx::query(
            "INSERT INTO oauth_connection_config_revisions (
                connection_id, revision, config_json, created_at
             ) VALUES (?, ?, ?, ?)",
        )
        .bind(&current.connection.id)
        .bind(next_config_revision)
        .bind(config_json)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(map_cas_database)?;
        if let Some(ciphertext) = sealed {
            insert_secret_revision(
                &mut transaction,
                &current.connection.id,
                next_secret_revision.ok_or(OAuthStoreError::InvalidStoredRecord)?,
                ciphertext,
                secrets.access_token_expires_at,
                now,
            )
            .await?;
        }
        let updated = sqlx::query(
            "UPDATE oauth_connections
             SET revision = revision + 1, current_config_revision = ?,
                 current_secret_revision = ?, status = ?, error_code = NULL,
                 granted_scopes_json = ?, has_client_secret = ?, has_refresh_token = ?,
                 access_expires_at = ?, authorized_at = NULL, last_refreshed_at = NULL,
                 updated_at = ?
             WHERE id = ? AND source_id = ? AND credential_key = ? AND revision = ?
               AND current_config_revision = ?
               AND ((current_secret_revision IS NULL AND ? IS NULL)
                    OR current_secret_revision = ?)",
        )
        .bind(next_config_revision)
        .bind(next_secret_revision)
        .bind(status.as_db_str())
        .bind(granted_scopes_json)
        .bind(secrets.client_secret.is_some())
        .bind(secrets.refresh_token.is_some())
        .bind(secrets.access_token_expires_at)
        .bind(now)
        .bind(&current.connection.id)
        .bind(source_id)
        .bind(credential_key)
        .bind(expected_revision)
        .bind(current.connection.config_revision)
        .bind(current.connection.secret_revision)
        .bind(current.connection.secret_revision)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(OAuthStoreError::Conflict);
        }
        prune_config_revisions(
            &mut transaction,
            &current.connection.id,
            next_config_revision,
        )
        .await?;
        if let Some(current_secret_revision) = next_secret_revision {
            prune_secret_revisions(
                &mut transaction,
                &current.connection.id,
                current_secret_revision,
            )
            .await?;
        }
        transaction.commit().await.map_err(database)?;
        self.connection(&current.connection.id).await
    }

    pub(crate) async fn connection(
        &self,
        connection_id: &str,
    ) -> Result<OAuthCredential, OAuthStoreError> {
        let row = sqlx::query(
            "SELECT c.id, c.source_id, c.credential_key, c.revision,
                    c.current_config_revision, c.current_secret_revision,
                    c.status, c.granted_scopes_json, c.has_client_secret,
                    c.has_refresh_token, c.access_expires_at, c.authorized_at,
                    c.last_refreshed_at, c.error_code, c.created_at, c.updated_at,
                    cfg.config_json, sec.payload_ciphertext
             FROM oauth_connections c
             JOIN oauth_connection_config_revisions cfg
               ON cfg.connection_id = c.id
              AND cfg.revision = c.current_config_revision
             LEFT JOIN oauth_connection_secret_revisions sec
               ON sec.connection_id = c.id
              AND sec.revision = c.current_secret_revision
             WHERE c.id = ?",
        )
        .bind(connection_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database)?
        .ok_or(OAuthStoreError::ConnectionNotFound)?;
        self.credential_from_row(&row)
    }

    pub(crate) async fn connection_by_source_key(
        &self,
        source_id: &str,
        credential_key: &str,
    ) -> Result<OAuthCredential, OAuthStoreError> {
        let id = sqlx::query_scalar::<_, String>(
            "SELECT id FROM oauth_connections WHERE source_id = ? AND credential_key = ?",
        )
        .bind(source_id)
        .bind(credential_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(database)?
        .ok_or(OAuthStoreError::ConnectionNotFound)?;
        self.connection(&id).await
    }

    pub(crate) async fn list_connections(
        &self,
        source_id: &str,
    ) -> Result<Vec<OAuthConnection>, OAuthStoreError> {
        let rows = sqlx::query(
            "SELECT c.id, c.source_id, c.credential_key, c.revision,
                    c.current_config_revision, c.current_secret_revision,
                    c.status, c.granted_scopes_json, c.has_client_secret,
                    c.has_refresh_token, c.access_expires_at, c.authorized_at,
                    c.last_refreshed_at, c.error_code, c.created_at, c.updated_at,
                    cfg.config_json
             FROM oauth_connections c
             JOIN oauth_connection_config_revisions cfg
               ON cfg.connection_id = c.id
              AND cfg.revision = c.current_config_revision
             WHERE c.source_id = ?
             ORDER BY c.credential_key",
        )
        .bind(source_id)
        .fetch_all(&self.pool)
        .await
        .map_err(database)?;
        rows.iter().map(connection_metadata_from_row).collect()
    }

    pub(crate) async fn delete_connection(
        &self,
        source_id: &str,
        credential_key: &str,
        expected_revision: i64,
    ) -> Result<(), OAuthStoreError> {
        let deleted = sqlx::query(
            "DELETE FROM oauth_connections
             WHERE source_id = ? AND credential_key = ? AND revision = ?",
        )
        .bind(source_id)
        .bind(credential_key)
        .bind(expected_revision)
        .execute(&self.pool)
        .await
        .map_err(database)?;
        if deleted.rows_affected() == 1 {
            return Ok(());
        }
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(
                SELECT 1 FROM oauth_connections
                WHERE source_id = ? AND credential_key = ?
             )",
        )
        .bind(source_id)
        .bind(credential_key)
        .fetch_one(&self.pool)
        .await
        .map_err(database)?
            != 0;
        if exists {
            Err(OAuthStoreError::Conflict)
        } else {
            Err(OAuthStoreError::ConnectionNotFound)
        }
    }

    pub(crate) async fn disconnect_connection(
        &self,
        source_id: &str,
        credential_key: &str,
        expected_revision: i64,
        now: i64,
    ) -> Result<OAuthCredential, OAuthStoreError> {
        let current = self
            .connection_by_source_key(source_id, credential_key)
            .await?;
        if current.connection.revision != expected_revision {
            return Err(OAuthStoreError::Conflict);
        }
        let disconnected = OAuthSecretSet {
            client_secret: current
                .secrets
                .as_ref()
                .and_then(|secrets| secrets.client_secret.clone()),
            ..OAuthSecretSet::default()
        };
        let next_secret_revision = current
            .connection
            .secret_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(OAuthStoreError::Conflict)?;
        let ciphertext = self.crypto.seal_secrets(
            &current.connection.id,
            next_secret_revision,
            &disconnected,
        )?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        insert_secret_revision(
            &mut transaction,
            &current.connection.id,
            next_secret_revision,
            ciphertext,
            None,
            now,
        )
        .await?;
        let updated = sqlx::query(
            "UPDATE oauth_connections
             SET revision = revision + 1, current_secret_revision = ?,
                 status = 'pending_authorization', error_code = NULL,
                 granted_scopes_json = '[]', has_client_secret = ?,
                 has_refresh_token = 0, access_expires_at = NULL,
                 authorized_at = NULL, last_refreshed_at = NULL, updated_at = ?
             WHERE id = ? AND source_id = ? AND credential_key = ? AND revision = ?
               AND current_config_revision = ?
               AND ((current_secret_revision IS NULL AND ? IS NULL)
                    OR current_secret_revision = ?)",
        )
        .bind(next_secret_revision)
        .bind(disconnected.client_secret.is_some())
        .bind(now)
        .bind(&current.connection.id)
        .bind(source_id)
        .bind(credential_key)
        .bind(expected_revision)
        .bind(current.connection.config_revision)
        .bind(current.connection.secret_revision)
        .bind(current.connection.secret_revision)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(OAuthStoreError::Conflict);
        }
        prune_secret_revisions(
            &mut transaction,
            &current.connection.id,
            next_secret_revision,
        )
        .await?;
        transaction.commit().await.map_err(database)?;
        self.connection(&current.connection.id).await
    }

    pub(crate) async fn begin_authorization(
        &self,
        source_id: &str,
        credential_key: &str,
        expected_revision: i64,
        admin_session_digest: &[u8; 32],
        now: i64,
        expires_at: i64,
    ) -> Result<PendingAuthorization, OAuthStoreError> {
        if expires_at <= now {
            return Err(OAuthStoreError::AuthorizationRejected);
        }
        let current = sqlx::query(
            "SELECT id, revision, current_config_revision, current_secret_revision
             FROM oauth_connections
             WHERE source_id = ? AND credential_key = ?",
        )
        .bind(source_id)
        .bind(credential_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(database)?
        .ok_or(OAuthStoreError::ConnectionNotFound)?;
        if current.get::<i64, _>("revision") != expected_revision {
            return Err(OAuthStoreError::Conflict);
        }
        let connection_id: String = current.get("id");
        let connection_revision = expected_revision
            .checked_add(1)
            .ok_or(OAuthStoreError::Conflict)?;
        let config_revision: i64 = current.get("current_config_revision");
        let base_secret_revision: Option<i64> = current.get("current_secret_revision");
        let transaction_id = Uuid::new_v4().to_string();
        let state = self.crypto.new_state();
        let verifier = self.crypto.new_pkce_verifier();
        let state_digest = self.crypto.state_digest(&state);
        let verifier_ciphertext = self.crypto.seal_pkce_verifier(&transaction_id, &verifier)?;

        let mut transaction = self.pool.begin().await.map_err(database)?;
        let exchange_in_progress = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(
                SELECT 1 FROM oauth_authorization_transactions
                WHERE connection_id = ? AND status = 'exchanging'
             )",
        )
        .bind(&connection_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(database)?
            != 0;
        if exchange_in_progress {
            return Err(OAuthStoreError::Conflict);
        }
        sqlx::query(
            "UPDATE oauth_authorization_transactions
             SET status = 'failed', error_code = ?, completed_at = ?
             WHERE connection_id = ? AND status = 'pending'",
        )
        .bind(AUTHORIZATION_ERROR_SUPERSEDED)
        .bind(now)
        .bind(&connection_id)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        let updated = sqlx::query(
            "UPDATE oauth_connections
             SET revision = revision + 1, status = 'connecting', error_code = NULL,
                 updated_at = ?
             WHERE id = ? AND revision = ? AND current_config_revision = ?
               AND ((current_secret_revision IS NULL AND ? IS NULL)
                    OR current_secret_revision = ?)",
        )
        .bind(now)
        .bind(&connection_id)
        .bind(expected_revision)
        .bind(config_revision)
        .bind(base_secret_revision)
        .bind(base_secret_revision)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(OAuthStoreError::Conflict);
        }
        let inserted = sqlx::query(
            "INSERT INTO oauth_authorization_transactions (
                id, connection_id, connection_revision, config_revision, base_secret_revision,
                state_digest, admin_session_digest, pkce_verifier_ciphertext,
                exchange_claim_digest, status, result_secret_revision, error_code,
                created_at, expires_at, claimed_at, completed_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 'pending', NULL, NULL, ?, ?, NULL, NULL)",
        )
        .bind(&transaction_id)
        .bind(&connection_id)
        .bind(connection_revision)
        .bind(config_revision)
        .bind(base_secret_revision)
        .bind(state_digest.to_vec())
        .bind(admin_session_digest.to_vec())
        .bind(verifier_ciphertext)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = inserted {
            if is_authorization_capacity(&error) {
                return Err(OAuthStoreError::AuthorizationCapacity);
            }
            return Err(database(error));
        }
        transaction.commit().await.map_err(database)?;

        Ok(PendingAuthorization {
            transaction_id,
            state,
            pkce_verifier: verifier,
            config_revision,
            expires_at,
        })
    }

    pub(crate) async fn claim_authorization_exchange(
        &self,
        expected_connection_id: &str,
        state: &str,
        admin_session_digest: &[u8; 32],
        now: i64,
    ) -> Result<AuthorizationExchangeClaim, OAuthStoreError> {
        let state_digest = self.crypto.state_digest(state);
        let claim_token = self.crypto.new_claim_token();
        let claim_digest = self.crypto.authorization_claim_digest(&claim_token);
        let exchange_expires_at = now
            .checked_add(AUTHORIZATION_EXCHANGE_TTL_SECONDS)
            .ok_or(OAuthStoreError::AuthorizationRejected)?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        sqlx::query(
            "UPDATE oauth_authorization_transactions
             SET status = 'expired', error_code = ?, completed_at = ?
             WHERE state_digest = ? AND connection_id = ?
               AND status = 'pending' AND expires_at <= ?",
        )
        .bind(AUTHORIZATION_ERROR_EXPIRED)
        .bind(now)
        .bind(state_digest.to_vec())
        .bind(expected_connection_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        sqlx::query(
            "UPDATE oauth_connections
             SET revision = revision + 1,
                 status = CASE
                    WHEN authorized_at IS NOT NULL
                     AND (access_expires_at IS NULL OR access_expires_at > ?)
                    THEN 'active'
                    ELSE 'pending_authorization'
                 END,
                 error_code = ?, updated_at = ?
             WHERE id = ? AND status = 'connecting'
               AND EXISTS (
                    SELECT 1 FROM oauth_authorization_transactions t
                    WHERE t.connection_id = oauth_connections.id
                      AND t.state_digest = ? AND t.status = 'expired'
                      AND t.connection_revision = oauth_connections.revision
               )",
        )
        .bind(now)
        .bind(AUTHORIZATION_ERROR_EXPIRED)
        .bind(now)
        .bind(expected_connection_id)
        .bind(state_digest.to_vec())
        .execute(&mut *transaction)
        .await
        .map_err(database)?;

        let row = sqlx::query(
            "SELECT t.id, t.connection_id, t.connection_revision,
                    t.config_revision, t.base_secret_revision,
                    t.pkce_verifier_ciphertext, cfg.config_json,
                    sec.payload_ciphertext
             FROM oauth_authorization_transactions t
             JOIN oauth_connection_config_revisions cfg
               ON cfg.connection_id = t.connection_id
              AND cfg.revision = t.config_revision
             JOIN oauth_connections c
               ON c.id = t.connection_id
              AND c.revision = t.connection_revision
              AND c.current_config_revision = t.config_revision
              AND ((c.current_secret_revision IS NULL AND t.base_secret_revision IS NULL)
                   OR c.current_secret_revision = t.base_secret_revision)
             LEFT JOIN oauth_connection_secret_revisions sec
               ON sec.connection_id = t.connection_id
              AND sec.revision = t.base_secret_revision
             WHERE t.state_digest = ?
               AND t.connection_id = ?
               AND t.admin_session_digest = ?
               AND t.status = 'pending'
               AND t.expires_at > ?",
        )
        .bind(state_digest.to_vec())
        .bind(expected_connection_id)
        .bind(admin_session_digest.to_vec())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?;
        let Some(row) = row else {
            transaction.commit().await.map_err(database)?;
            return Err(OAuthStoreError::AuthorizationRejected);
        };
        let transaction_id: String = row.get("id");
        let verifier_ciphertext: Vec<u8> = row.get("pkce_verifier_ciphertext");
        let base_secret_revision: Option<i64> = row.get("base_secret_revision");
        let secret_ciphertext: Option<Vec<u8>> = row.get("payload_ciphertext");
        let secrets = match (base_secret_revision, secret_ciphertext) {
            (Some(revision), Some(ciphertext)) => Some(self.crypto.open_secrets(
                expected_connection_id,
                revision,
                &ciphertext,
            )?),
            (None, None) => None,
            _ => return Err(OAuthStoreError::InvalidStoredRecord),
        };
        let config = decode_config(row.get("config_json"))?;
        let pkce_verifier = self
            .crypto
            .open_pkce_verifier(&transaction_id, &verifier_ciphertext)?;
        let updated = sqlx::query(
            "UPDATE oauth_authorization_transactions
             SET status = 'exchanging', exchange_claim_digest = ?, claimed_at = ?,
                 exchange_expires_at = ?
             WHERE id = ? AND status = 'pending' AND expires_at > ?
               AND EXISTS (
                    SELECT 1 FROM oauth_connections c
                    WHERE c.id = oauth_authorization_transactions.connection_id
                      AND c.revision = oauth_authorization_transactions.connection_revision
                      AND c.current_config_revision = oauth_authorization_transactions.config_revision
                      AND ((c.current_secret_revision IS NULL
                            AND oauth_authorization_transactions.base_secret_revision IS NULL)
                           OR c.current_secret_revision = oauth_authorization_transactions.base_secret_revision)
               )",
        )
        .bind(claim_digest.to_vec())
        .bind(now)
        .bind(exchange_expires_at)
        .bind(&transaction_id)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(OAuthStoreError::AuthorizationRejected);
        }
        transaction.commit().await.map_err(database)?;

        Ok(AuthorizationExchangeClaim {
            transaction_id: transaction_id.clone(),
            connection_id: row.get("connection_id"),
            connection_revision: row.get("connection_revision"),
            config_revision: row.get("config_revision"),
            config,
            base_secret_revision,
            secrets,
            claim_token,
            pkce_verifier,
        })
    }

    pub(crate) async fn complete_authorization_exchange(
        &self,
        claim: &AuthorizationExchangeClaim,
        secrets: &OAuthSecretSet,
        now: i64,
    ) -> Result<i64, OAuthStoreError> {
        if !valid_access_token(secrets) {
            return Err(OAuthStoreError::InvalidStoredRecord);
        }
        let claim_digest = self.crypto.authorization_claim_digest(&claim.claim_token);
        let mut effective_secrets = secrets.clone();
        effective_secrets.client_secret = claim
            .secrets
            .as_ref()
            .and_then(|secrets| secrets.client_secret.clone());
        let next_revision = claim
            .base_secret_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(OAuthStoreError::Conflict)?;
        let next_config_revision = claim
            .config_revision
            .checked_add(1)
            .ok_or(OAuthStoreError::Conflict)?;
        let ciphertext =
            self.crypto
                .seal_secrets(&claim.connection_id, next_revision, &effective_secrets)?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        let valid = exchange_claim_is_current(&mut transaction, claim, &claim_digest).await?;
        if !valid {
            return Err(OAuthStoreError::Conflict);
        }
        sqlx::query(
            "INSERT INTO oauth_connection_config_revisions (
                connection_id, revision, config_json, created_at
             ) VALUES (?, ?, ?, ?)",
        )
        .bind(&claim.connection_id)
        .bind(next_config_revision)
        .bind(encode_config(&claim.config)?)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(map_cas_database)?;
        insert_secret_revision(
            &mut transaction,
            &claim.connection_id,
            next_revision,
            ciphertext,
            effective_secrets.access_token_expires_at,
            now,
        )
        .await?;
        let granted_scopes_json = serde_json::to_string(&effective_secrets.granted_scopes)
            .map_err(OAuthStoreError::EncodeConfiguration)?;
        let connection_updated = sqlx::query(
            "UPDATE oauth_connections
             SET current_config_revision = ?, current_secret_revision = ?,
                 status = 'active', error_code = NULL,
                 revision = revision + 1, granted_scopes_json = ?,
                 has_client_secret = ?, has_refresh_token = ?, access_expires_at = ?,
                 authorized_at = ?, last_refreshed_at = NULL, updated_at = ?
             WHERE id = ? AND revision = ? AND current_config_revision = ?
               AND ((current_secret_revision IS NULL AND ? IS NULL)
                    OR current_secret_revision = ?)",
        )
        .bind(next_config_revision)
        .bind(next_revision)
        .bind(granted_scopes_json)
        .bind(effective_secrets.client_secret.is_some())
        .bind(effective_secrets.refresh_token.is_some())
        .bind(effective_secrets.access_token_expires_at)
        .bind(now)
        .bind(now)
        .bind(&claim.connection_id)
        .bind(claim.connection_revision)
        .bind(claim.config_revision)
        .bind(claim.base_secret_revision)
        .bind(claim.base_secret_revision)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if connection_updated.rows_affected() != 1 {
            return Err(OAuthStoreError::Conflict);
        }
        let transaction_updated = sqlx::query(
            "UPDATE oauth_authorization_transactions
             SET status = 'succeeded', result_secret_revision = ?, completed_at = ?
             WHERE id = ? AND status = 'exchanging' AND exchange_claim_digest = ?",
        )
        .bind(next_revision)
        .bind(now)
        .bind(&claim.transaction_id)
        .bind(claim_digest.to_vec())
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if transaction_updated.rows_affected() != 1 {
            return Err(OAuthStoreError::Conflict);
        }
        prune_config_revisions(&mut transaction, &claim.connection_id, next_config_revision)
            .await?;
        prune_secret_revisions(&mut transaction, &claim.connection_id, next_revision).await?;
        transaction.commit().await.map_err(database)?;
        Ok(next_revision)
    }

    pub(crate) async fn fail_authorization_exchange(
        &self,
        claim: &AuthorizationExchangeClaim,
        error_code: &str,
        now: i64,
    ) -> Result<(), OAuthStoreError> {
        if !valid_reason_code(error_code) {
            return Err(OAuthStoreError::InvalidStoredRecord);
        }
        let claim_digest = self.crypto.authorization_claim_digest(&claim.claim_token);
        let mut transaction = self.pool.begin().await.map_err(database)?;
        let updated = sqlx::query(
            "UPDATE oauth_authorization_transactions
             SET status = 'failed', error_code = ?, completed_at = ?
             WHERE id = ? AND status = 'exchanging' AND exchange_claim_digest = ?",
        )
        .bind(error_code)
        .bind(now)
        .bind(&claim.transaction_id)
        .bind(claim_digest.to_vec())
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(OAuthStoreError::Conflict);
        }
        let connection_status = if claim
            .secrets
            .as_ref()
            .is_some_and(|secrets| secrets.access_token.is_some())
        {
            OAuthConnectionStatus::Active
        } else {
            OAuthConnectionStatus::PendingAuthorization
        };
        let connection_updated = sqlx::query(
            "UPDATE oauth_connections
             SET revision = revision + 1, status = ?, error_code = ?, updated_at = ?
             WHERE id = ? AND revision = ?
               AND current_config_revision = ?
               AND ((current_secret_revision IS NULL AND ? IS NULL)
                    OR current_secret_revision = ?)",
        )
        .bind(connection_status.as_db_str())
        .bind(error_code)
        .bind(now)
        .bind(&claim.connection_id)
        .bind(claim.connection_revision)
        .bind(claim.config_revision)
        .bind(claim.base_secret_revision)
        .bind(claim.base_secret_revision)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        transaction.commit().await.map_err(database)?;
        if connection_updated.rows_affected() == 1 {
            Ok(())
        } else {
            Err(OAuthStoreError::Conflict)
        }
    }

    pub(crate) async fn claim_refresh(
        &self,
        connection_id: &str,
        now: i64,
        lease_expires_at: i64,
    ) -> Result<RefreshClaim, OAuthStoreError> {
        if lease_expires_at <= now {
            return Err(OAuthStoreError::Conflict);
        }
        let lease_token = self.crypto.new_refresh_lease_token();
        let lease_digest = self.crypto.refresh_lease_digest(&lease_token);
        let mut transaction = self.pool.begin().await.map_err(database)?;
        let expired_base = sqlx::query_scalar::<_, i64>(
            "SELECT base_secret_revision FROM oauth_refresh_leases
             WHERE connection_id = ? AND expires_at <= ?",
        )
        .bind(connection_id)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?;
        if let Some(expired_base) = expired_base {
            let marked = sqlx::query(
                "UPDATE oauth_connections
                 SET revision = revision + 1, status = 'reauth_required',
                     error_code = ?, updated_at = ?
                 WHERE id = ? AND current_secret_revision = ?",
            )
            .bind(REFRESH_ERROR_INTERRUPTED)
            .bind(now)
            .bind(connection_id)
            .bind(expired_base)
            .execute(&mut *transaction)
            .await
            .map_err(database)?;
            sqlx::query("DELETE FROM oauth_refresh_leases WHERE connection_id = ?")
                .bind(connection_id)
                .execute(&mut *transaction)
                .await
                .map_err(database)?;
            transaction.commit().await.map_err(database)?;
            if marked.rows_affected() == 1 {
                return Err(OAuthStoreError::ReauthorizationRequired);
            }
            transaction = self.pool.begin().await.map_err(database)?;
        }
        sqlx::query("DELETE FROM oauth_refresh_leases WHERE connection_id = ? AND expires_at <= ?")
            .bind(connection_id)
            .bind(now)
            .execute(&mut *transaction)
            .await
            .map_err(database)?;
        let row = sqlx::query(
            "SELECT c.revision, c.current_config_revision, c.current_secret_revision, c.status,
                    cfg.config_json, sec.payload_ciphertext
             FROM oauth_connections c
             JOIN oauth_connection_config_revisions cfg
               ON cfg.connection_id = c.id
              AND cfg.revision = c.current_config_revision
             LEFT JOIN oauth_connection_secret_revisions sec
               ON sec.connection_id = c.id
              AND sec.revision = c.current_secret_revision
             WHERE c.id = ?",
        )
        .bind(connection_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database)?
        .ok_or(OAuthStoreError::ConnectionNotFound)?;
        let status = status_from_row(&row)?;
        if status != OAuthConnectionStatus::Active {
            return Err(OAuthStoreError::ReauthorizationRequired);
        }
        let base_secret_revision: Option<i64> = row.get("current_secret_revision");
        let base_secret_revision =
            base_secret_revision.ok_or(OAuthStoreError::InvalidStoredRecord)?;
        let config = decode_config(row.get("config_json"))?;
        let ciphertext: Option<Vec<u8>> = row.get("payload_ciphertext");
        let ciphertext = ciphertext.ok_or(OAuthStoreError::InvalidStoredRecord)?;
        let secrets = self
            .crypto
            .open_secrets(connection_id, base_secret_revision, &ciphertext)?;
        let inserted = sqlx::query(
            "INSERT INTO oauth_refresh_leases (
                connection_id, lease_digest, base_secret_revision, claimed_at, expires_at
             ) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(connection_id)
        .bind(lease_digest.to_vec())
        .bind(base_secret_revision)
        .bind(now)
        .bind(lease_expires_at)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = inserted {
            if is_constraint(&error) {
                return Err(OAuthStoreError::RefreshInProgress);
            }
            return Err(database(error));
        }
        transaction.commit().await.map_err(database)?;

        Ok(RefreshClaim {
            connection_id: connection_id.to_owned(),
            connection_revision: row.get("revision"),
            config_revision: row.get("current_config_revision"),
            config,
            base_secret_revision,
            secrets,
            lease_token,
            expires_at: lease_expires_at,
        })
    }

    pub(crate) async fn complete_refresh(
        &self,
        claim: &RefreshClaim,
        rotated_secrets: &OAuthSecretSet,
        now: i64,
    ) -> Result<i64, OAuthStoreError> {
        if !valid_access_token(rotated_secrets) {
            return Err(OAuthStoreError::InvalidStoredRecord);
        }
        let mut effective_secrets = rotated_secrets.clone();
        effective_secrets.client_secret = claim.secrets.client_secret.clone();
        if effective_secrets.refresh_token.is_none() {
            effective_secrets.refresh_token = claim.secrets.refresh_token.clone();
        }
        let next_revision = claim
            .base_secret_revision
            .checked_add(1)
            .ok_or(OAuthStoreError::Conflict)?;
        let lease_digest = self.crypto.refresh_lease_digest(&claim.lease_token);
        let ciphertext =
            self.crypto
                .seal_secrets(&claim.connection_id, next_revision, &effective_secrets)?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        if !refresh_claim_is_current(&mut transaction, claim, &lease_digest, now).await? {
            return Err(OAuthStoreError::Conflict);
        }
        insert_secret_revision(
            &mut transaction,
            &claim.connection_id,
            next_revision,
            ciphertext,
            effective_secrets.access_token_expires_at,
            now,
        )
        .await?;
        let granted_scopes_json = serde_json::to_string(&effective_secrets.granted_scopes)
            .map_err(OAuthStoreError::EncodeConfiguration)?;
        let updated = sqlx::query(
            "UPDATE oauth_connections
             SET current_secret_revision = ?, status = 'active', error_code = NULL,
                 revision = revision + 1, granted_scopes_json = ?,
                 has_client_secret = ?, has_refresh_token = ?, access_expires_at = ?,
                 last_refreshed_at = ?, updated_at = ?
             WHERE id = ? AND revision = ?
               AND current_config_revision = ? AND current_secret_revision = ?",
        )
        .bind(next_revision)
        .bind(granted_scopes_json)
        .bind(effective_secrets.client_secret.is_some())
        .bind(effective_secrets.refresh_token.is_some())
        .bind(effective_secrets.access_token_expires_at)
        .bind(now)
        .bind(now)
        .bind(&claim.connection_id)
        .bind(claim.connection_revision)
        .bind(claim.config_revision)
        .bind(claim.base_secret_revision)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(OAuthStoreError::Conflict);
        }
        prune_secret_revisions(&mut transaction, &claim.connection_id, next_revision).await?;
        delete_refresh_lease(&mut transaction, &claim.connection_id, &lease_digest).await?;
        transaction.commit().await.map_err(database)?;
        Ok(next_revision)
    }

    pub(crate) async fn mark_refresh_invalid_grant(
        &self,
        claim: &RefreshClaim,
        now: i64,
    ) -> Result<(), OAuthStoreError> {
        let lease_digest = self.crypto.refresh_lease_digest(&claim.lease_token);
        let mut transaction = self.pool.begin().await.map_err(database)?;
        if !refresh_claim_is_current(&mut transaction, claim, &lease_digest, now).await? {
            return Err(OAuthStoreError::Conflict);
        }
        let updated = sqlx::query(
            "UPDATE oauth_connections
             SET status = 'reauth_required', error_code = ?,
                 revision = revision + 1, updated_at = ?
             WHERE id = ? AND revision = ?
               AND current_config_revision = ? AND current_secret_revision = ?",
        )
        .bind(REFRESH_ERROR_INVALID_GRANT)
        .bind(now)
        .bind(&claim.connection_id)
        .bind(claim.connection_revision)
        .bind(claim.config_revision)
        .bind(claim.base_secret_revision)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(OAuthStoreError::Conflict);
        }
        delete_refresh_lease(&mut transaction, &claim.connection_id, &lease_digest).await?;
        transaction.commit().await.map_err(database)?;
        Ok(())
    }

    pub(crate) async fn release_refresh(
        &self,
        claim: &RefreshClaim,
    ) -> Result<(), OAuthStoreError> {
        self.mark_refresh_reauthorization_required(claim, REFRESH_ERROR_INTERRUPTED)
            .await
    }

    pub(crate) async fn mark_refresh_reauthorization_required(
        &self,
        claim: &RefreshClaim,
        reason: &str,
    ) -> Result<(), OAuthStoreError> {
        if !valid_reason_code(reason) {
            return Err(OAuthStoreError::InvalidStoredRecord);
        }
        let now = crate::unix_timestamp();
        let lease_digest = self.crypto.refresh_lease_digest(&claim.lease_token);
        let mut transaction = self.pool.begin().await.map_err(database)?;
        if !refresh_claim_is_current(&mut transaction, claim, &lease_digest, now).await? {
            return Err(OAuthStoreError::Conflict);
        }
        let updated = sqlx::query(
            "UPDATE oauth_connections
             SET status = 'reauth_required', error_code = ?,
                 revision = revision + 1, updated_at = ?
             WHERE id = ? AND revision = ?
               AND current_config_revision = ? AND current_secret_revision = ?",
        )
        .bind(reason)
        .bind(now)
        .bind(&claim.connection_id)
        .bind(claim.connection_revision)
        .bind(claim.config_revision)
        .bind(claim.base_secret_revision)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        if updated.rows_affected() != 1 {
            return Err(OAuthStoreError::Conflict);
        }
        delete_refresh_lease(&mut transaction, &claim.connection_id, &lease_digest).await?;
        transaction.commit().await.map_err(database)?;
        Ok(())
    }

    pub(crate) async fn expire_authorizations(&self, now: i64) -> Result<u64, OAuthStoreError> {
        let mut transaction = self.pool.begin().await.map_err(database)?;
        let expired_pending = sqlx::query(
            "UPDATE oauth_authorization_transactions
             SET status = 'expired', error_code = ?, completed_at = ?
             WHERE status = 'pending' AND expires_at <= ?",
        )
        .bind(AUTHORIZATION_ERROR_EXPIRED)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?
        .rows_affected();
        let expired_exchanging = sqlx::query(
            "UPDATE oauth_authorization_transactions
             SET status = 'failed', error_code = ?, completed_at = ?
             WHERE status = 'exchanging' AND exchange_expires_at <= ?",
        )
        .bind(AUTHORIZATION_ERROR_EXCHANGE_TIMEOUT)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?
        .rows_affected();
        sqlx::query(
            "UPDATE oauth_connections
             SET revision = revision + 1,
                 status = CASE
                    WHEN authorized_at IS NOT NULL
                     AND (access_expires_at IS NULL OR access_expires_at > ?)
                    THEN 'active'
                    ELSE 'pending_authorization'
                 END,
                 error_code = CASE
                    WHEN EXISTS (
                        SELECT 1 FROM oauth_authorization_transactions t
                        WHERE t.connection_id = oauth_connections.id
                          AND t.status = 'failed' AND t.error_code = ?
                    ) THEN ?
                    ELSE ?
                 END,
                 updated_at = ?
             WHERE status = 'connecting'
               AND NOT EXISTS (
                    SELECT 1 FROM oauth_authorization_transactions t
                    WHERE t.connection_id = oauth_connections.id
                      AND t.status IN ('pending', 'exchanging')
               )",
        )
        .bind(now)
        .bind(AUTHORIZATION_ERROR_EXCHANGE_TIMEOUT)
        .bind(AUTHORIZATION_ERROR_EXCHANGE_TIMEOUT)
        .bind(AUTHORIZATION_ERROR_EXPIRED)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        transaction.commit().await.map_err(database)?;
        Ok(expired_pending + expired_exchanging)
    }

    pub(crate) async fn recover_startup(&self, now: i64) -> Result<OAuthRecovery, OAuthStoreError> {
        let mut transaction = self.pool.begin().await.map_err(database)?;
        let exchanges = sqlx::query(
            "UPDATE oauth_authorization_transactions
             SET status = 'failed', error_code = ?, completed_at = ?
             WHERE status = 'exchanging'",
        )
        .bind(AUTHORIZATION_ERROR_INTERRUPTED)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?
        .rows_affected();
        sqlx::query(
            "UPDATE oauth_connections
             SET revision = revision + 1, status = 'reauth_required',
                 error_code = ?, updated_at = ?
             WHERE EXISTS (
                SELECT 1 FROM oauth_refresh_leases l
                WHERE l.connection_id = oauth_connections.id
                  AND l.base_secret_revision = oauth_connections.current_secret_revision
             )",
        )
        .bind(REFRESH_ERROR_INTERRUPTED)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        let leases = sqlx::query("DELETE FROM oauth_refresh_leases")
            .execute(&mut *transaction)
            .await
            .map_err(database)?
            .rows_affected();
        sqlx::query(
            "UPDATE oauth_authorization_transactions
             SET status = 'expired', error_code = ?, completed_at = ?
             WHERE status = 'pending' AND expires_at <= ?",
        )
        .bind(AUTHORIZATION_ERROR_EXPIRED)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        sqlx::query(
            "UPDATE oauth_connections
             SET revision = revision + 1,
                 status = CASE
                    WHEN authorized_at IS NOT NULL
                     AND (access_expires_at IS NULL OR access_expires_at > ?)
                    THEN 'active'
                    ELSE 'pending_authorization'
                 END,
                 error_code = ?, updated_at = ?
             WHERE status = 'connecting'
               AND NOT EXISTS (
                    SELECT 1 FROM oauth_authorization_transactions t
                    WHERE t.connection_id = oauth_connections.id
                      AND t.status = 'pending' AND t.expires_at > ?
               )",
        )
        .bind(now)
        .bind(AUTHORIZATION_ERROR_INTERRUPTED)
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database)?;
        transaction.commit().await.map_err(database)?;
        Ok(OAuthRecovery {
            interrupted_exchanges: exchanges,
            abandoned_refresh_leases: leases,
        })
    }

    fn credential_from_row(
        &self,
        row: &sqlx::sqlite::SqliteRow,
    ) -> Result<OAuthCredential, OAuthStoreError> {
        let id: String = row.get("id");
        let secret_revision: Option<i64> = row.get("current_secret_revision");
        let ciphertext: Option<Vec<u8>> = row.get("payload_ciphertext");
        let secrets = match (secret_revision, ciphertext) {
            (Some(revision), Some(ciphertext)) => {
                Some(self.crypto.open_secrets(&id, revision, &ciphertext)?)
            }
            (None, None) => None,
            _ => return Err(OAuthStoreError::InvalidStoredRecord),
        };
        Ok(OAuthCredential {
            connection: connection_metadata_from_row(row)?,
            secrets,
        })
    }
}

async fn insert_secret_revision(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    connection_id: &str,
    revision: i64,
    ciphertext: Vec<u8>,
    access_token_expires_at: Option<i64>,
    now: i64,
) -> Result<(), OAuthStoreError> {
    sqlx::query(
        "INSERT INTO oauth_connection_secret_revisions (
            connection_id, revision, payload_ciphertext, access_token_expires_at, created_at
         ) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(connection_id)
    .bind(revision)
    .bind(ciphertext)
    .bind(access_token_expires_at)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_cas_database)?;
    Ok(())
}

async fn prune_secret_revisions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    connection_id: &str,
    current_revision: i64,
) -> Result<(), OAuthStoreError> {
    sqlx::query(
        "DELETE FROM oauth_connection_secret_revisions
         WHERE connection_id = ? AND revision <> ?",
    )
    .bind(connection_id)
    .bind(current_revision)
    .execute(&mut **transaction)
    .await
    .map_err(database)?;
    Ok(())
}

async fn prune_config_revisions(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    connection_id: &str,
    current_revision: i64,
) -> Result<(), OAuthStoreError> {
    sqlx::query(
        "DELETE FROM oauth_connection_config_revisions
         WHERE connection_id = ? AND revision <> ?",
    )
    .bind(connection_id)
    .bind(current_revision)
    .execute(&mut **transaction)
    .await
    .map_err(database)?;
    Ok(())
}

async fn exchange_claim_is_current(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    claim: &AuthorizationExchangeClaim,
    claim_digest: &[u8; 32],
) -> Result<bool, OAuthStoreError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(
            SELECT 1
            FROM oauth_authorization_transactions t
            JOIN oauth_connections c ON c.id = t.connection_id
            WHERE t.id = ? AND t.connection_id = ? AND t.status = 'exchanging'
              AND t.exchange_claim_digest = ? AND t.config_revision = ?
              AND t.connection_revision = ? AND c.revision = t.connection_revision
              AND ((t.base_secret_revision IS NULL AND ? IS NULL)
                   OR t.base_secret_revision = ?)
              AND c.current_config_revision = t.config_revision
              AND ((c.current_secret_revision IS NULL AND t.base_secret_revision IS NULL)
                   OR c.current_secret_revision = t.base_secret_revision)
         )",
    )
    .bind(&claim.transaction_id)
    .bind(&claim.connection_id)
    .bind(claim_digest.to_vec())
    .bind(claim.config_revision)
    .bind(claim.connection_revision)
    .bind(claim.base_secret_revision)
    .bind(claim.base_secret_revision)
    .fetch_one(&mut **transaction)
    .await
    .map(|exists| exists != 0)
    .map_err(database)
}

async fn refresh_claim_is_current(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    claim: &RefreshClaim,
    lease_digest: &[u8; 32],
    now: i64,
) -> Result<bool, OAuthStoreError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(
            SELECT 1
            FROM oauth_refresh_leases l
            JOIN oauth_connections c ON c.id = l.connection_id
            WHERE l.connection_id = ? AND l.lease_digest = ?
              AND l.base_secret_revision = ? AND l.expires_at > ?
              AND c.revision = ?
              AND c.current_config_revision = ?
              AND c.current_secret_revision = l.base_secret_revision
         )",
    )
    .bind(&claim.connection_id)
    .bind(lease_digest.to_vec())
    .bind(claim.base_secret_revision)
    .bind(now)
    .bind(claim.connection_revision)
    .bind(claim.config_revision)
    .fetch_one(&mut **transaction)
    .await
    .map(|exists| exists != 0)
    .map_err(database)
}

async fn delete_refresh_lease(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    connection_id: &str,
    lease_digest: &[u8; 32],
) -> Result<(), OAuthStoreError> {
    let deleted = sqlx::query(
        "DELETE FROM oauth_refresh_leases WHERE connection_id = ? AND lease_digest = ?",
    )
    .bind(connection_id)
    .bind(lease_digest.to_vec())
    .execute(&mut **transaction)
    .await
    .map_err(database)?;
    if deleted.rows_affected() != 1 {
        return Err(OAuthStoreError::Conflict);
    }
    Ok(())
}

fn status_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<OAuthConnectionStatus, OAuthStoreError> {
    let value: String = row.get("status");
    OAuthConnectionStatus::from_db(&value).ok_or(OAuthStoreError::InvalidStoredRecord)
}

fn connection_metadata_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<OAuthConnection, OAuthStoreError> {
    Ok(OAuthConnection {
        id: row.get("id"),
        source_id: row.get("source_id"),
        credential_key: row.get("credential_key"),
        revision: row.get("revision"),
        config_revision: row.get("current_config_revision"),
        secret_revision: row.get("current_secret_revision"),
        config: decode_config(row.get("config_json"))?,
        status: status_from_row(row)?,
        granted_scopes: serde_json::from_str(&row.get::<String, _>("granted_scopes_json"))
            .map_err(OAuthStoreError::DecodeConfiguration)?,
        has_client_secret: row.get("has_client_secret"),
        has_refresh_token: row.get("has_refresh_token"),
        access_expires_at: row.get("access_expires_at"),
        authorized_at: row.get("authorized_at"),
        last_refreshed_at: row.get("last_refreshed_at"),
        error_code: row.get("error_code"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn encode_config(config: &OAuthConnectionConfig) -> Result<String, OAuthStoreError> {
    serde_json::to_string(config).map_err(OAuthStoreError::EncodeConfiguration)
}

fn decode_config(value: String) -> Result<OAuthConnectionConfig, OAuthStoreError> {
    serde_json::from_str(&value).map_err(OAuthStoreError::DecodeConfiguration)
}

fn database(error: sqlx::Error) -> OAuthStoreError {
    OAuthStoreError::Database(error)
}

fn map_cas_database(error: sqlx::Error) -> OAuthStoreError {
    if is_constraint(&error) {
        OAuthStoreError::Conflict
    } else {
        database(error)
    }
}

fn is_constraint(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(error) if error.is_unique_violation())
}

fn is_authorization_capacity(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(error) if error.message().contains("OAuth authorization transaction capacity reached"))
}

fn valid_reason_code(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= 128
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_access_token(secrets: &OAuthSecretSet) -> bool {
    secrets
        .access_token
        .as_deref()
        .is_some_and(|token| !token.is_empty())
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    use crate::crypto::Keyring;

    use super::{OAuthStore, OAuthStoreError};
    use crate::catalog::{
        AuditContext, CatalogError, CatalogSnapshot, CatalogStore, CredentialPayload,
        OAuthBindingExpectation,
    };
    use crate::oauth::model::{
        OAuthClientAuthentication, OAuthClientSecretUpdate, OAuthConnectionConfig,
        OAuthConnectionStatus, OAuthSecretSet,
    };

    async fn test_store() -> (OAuthStore, sqlx::SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO sources (
                id, kind, slug, display_name, configuration_json, health_status,
                revision, catalog_revision, created_at, updated_at
             ) VALUES ('source-1', 'openapi', 'test', 'Test', '{}', 'unknown', 0, 0, 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let keyring = Keyring::from_master_key([11; 32]).unwrap();
        (OAuthStore::new(pool.clone(), keyring), pool)
    }

    fn config(display_name: &str) -> OAuthConnectionConfig {
        OAuthConnectionConfig {
            issuer: format!("https://{}.example", display_name.to_lowercase()),
            authorization_endpoint: "https://issuer.example/authorize".into(),
            token_endpoint: "https://issuer.example/token".into(),
            client_id: "executor".into(),
            client_authentication: OAuthClientAuthentication::ClientSecretBasic,
            token_endpoint_auth_methods_supported: vec!["client_secret_basic".into()],
            scopes: vec!["read".into()],
            allow_private_network: false,
            resource: Some("https://api.example".into()),
        }
    }

    fn secrets(access: &str, refresh: &str) -> OAuthSecretSet {
        OAuthSecretSet {
            client_secret: Some("client-secret".into()),
            access_token: Some(access.into()),
            refresh_token: Some(refresh.into()),
            token_type: Some("Bearer".into()),
            granted_scopes: vec!["read".into()],
            access_token_expires_at: Some(1_000),
        }
    }

    #[tokio::test]
    async fn config_and_secret_revisions_advance_independently() {
        let (store, pool) = test_store().await;
        let created = store
            .create_connection(
                "source-1",
                "default",
                &config("First"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        assert_eq!(created.connection.config_revision, 1);
        assert_eq!(created.connection.secret_revision, Some(1));

        let updated = store
            .upsert_connection(
                "source-1",
                "default",
                1,
                &config("Renamed"),
                OAuthClientSecretUpdate::Preserve,
                11,
            )
            .await
            .unwrap();
        assert_eq!(updated.connection.revision, 2);
        let loaded = store.connection(&created.connection.id).await.unwrap();
        assert_eq!(loaded.connection.config.issuer, "https://renamed.example");
        assert_eq!(loaded.connection.secret_revision, Some(2));
        assert_eq!(loaded.secrets.unwrap().refresh_token, None);
        let secret_history = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oauth_connection_secret_revisions WHERE connection_id = ?",
        )
        .bind(&created.connection.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(secret_history, 1);
        let config_history = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oauth_connection_config_revisions WHERE connection_id = ?",
        )
        .bind(&created.connection.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(config_history, 1);

        assert!(matches!(
            store
                .upsert_connection(
                    "source-1",
                    "default",
                    1,
                    &config("Stale"),
                    OAuthClientSecretUpdate::Preserve,
                    12,
                )
                .await,
            Err(OAuthStoreError::Conflict)
        ));
    }

    #[tokio::test]
    async fn authorization_state_is_one_shot_and_bound_to_the_admin_session() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection("source-1", "default", &config("New"), None, 10)
            .await
            .unwrap();
        let first_session = [1_u8; 32];
        let other_session = [2_u8; 32];
        let pending = store
            .begin_authorization("source-1", "default", 1, &first_session, 11, 100)
            .await
            .unwrap();

        assert!(matches!(
            store
                .claim_authorization_exchange(
                    "wrong-connection",
                    &pending.state,
                    &first_session,
                    12,
                )
                .await,
            Err(OAuthStoreError::AuthorizationRejected)
        ));
        assert!(matches!(
            store
                .claim_authorization_exchange(
                    &connection.connection.id,
                    &pending.state,
                    &other_session,
                    12,
                )
                .await,
            Err(OAuthStoreError::AuthorizationRejected)
        ));
        let claim = store
            .claim_authorization_exchange(
                &connection.connection.id,
                &pending.state,
                &first_session,
                12,
            )
            .await
            .unwrap();
        assert_eq!(claim.pkce_verifier, pending.pkce_verifier);
        assert!(matches!(
            store
                .claim_authorization_exchange(
                    &connection.connection.id,
                    &pending.state,
                    &first_session,
                    13,
                )
                .await,
            Err(OAuthStoreError::AuthorizationRejected)
        ));

        let revision = store
            .complete_authorization_exchange(&claim, &secrets("a1", "r1"), 14)
            .await
            .unwrap();
        assert_eq!(revision, 1);
        let loaded = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(loaded.connection.status, OAuthConnectionStatus::Active);
        assert_eq!(loaded.connection.secret_revision, Some(1));
        assert_eq!(loaded.connection.config_revision, 2);
        let refresh = store
            .claim_refresh(&connection.connection.id, 15, 25)
            .await
            .unwrap();
        store
            .complete_refresh(&refresh, &secrets("a2", "r2"), 16)
            .await
            .unwrap();
        let refreshed = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(refreshed.connection.config_revision, 2);
    }

    #[tokio::test]
    async fn a_new_authorization_supersedes_the_prior_pending_state() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection("source-1", "default", &config("New"), None, 10)
            .await
            .unwrap();
        let session = [1_u8; 32];
        let first = store
            .begin_authorization("source-1", "default", 1, &session, 11, 100)
            .await
            .unwrap();
        let after_first = store.connection(&connection.connection.id).await.unwrap();
        let second = store
            .begin_authorization(
                "source-1",
                "default",
                after_first.connection.revision,
                &session,
                12,
                100,
            )
            .await
            .unwrap();

        assert!(matches!(
            store
                .claim_authorization_exchange(
                    &connection.connection.id,
                    &first.state,
                    &session,
                    13,
                )
                .await,
            Err(OAuthStoreError::AuthorizationRejected)
        ));
        store
            .claim_authorization_exchange(&connection.connection.id, &second.state, &session, 13)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn runtime_expiry_resets_a_connecting_connection() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection("source-1", "default", &config("New"), None, 10)
            .await
            .unwrap();
        let session = [1_u8; 32];
        store
            .begin_authorization("source-1", "default", 1, &session, 11, 20)
            .await
            .unwrap();

        assert_eq!(store.expire_authorizations(20).await.unwrap(), 1);
        let loaded = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(
            loaded.connection.status,
            OAuthConnectionStatus::PendingAuthorization
        );
        assert_eq!(
            loaded.connection.error_code.as_deref(),
            Some("authorization_expired")
        );
    }

    #[tokio::test]
    async fn runtime_expiry_terminalizes_an_abandoned_exchange() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection("source-1", "default", &config("New"), None, 10)
            .await
            .unwrap();
        let session = [1_u8; 32];
        let pending = store
            .begin_authorization("source-1", "default", 1, &session, 11, 20)
            .await
            .unwrap();
        store
            .claim_authorization_exchange(&connection.connection.id, &pending.state, &session, 12)
            .await
            .unwrap();

        assert_eq!(store.expire_authorizations(72).await.unwrap(), 1);
        let loaded = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(
            loaded.connection.status,
            OAuthConnectionStatus::PendingAuthorization
        );
        assert_eq!(
            loaded.connection.error_code.as_deref(),
            Some("exchange_timeout")
        );
        store
            .begin_authorization(
                "source-1",
                "default",
                loaded.connection.revision,
                &session,
                73,
                90,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn exchange_claim_gets_a_fresh_bounded_deadline() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection("source-1", "default", &config("New"), None, 10)
            .await
            .unwrap();
        let session = [1_u8; 32];
        let pending = store
            .begin_authorization("source-1", "default", 1, &session, 11, 20)
            .await
            .unwrap();
        store
            .claim_authorization_exchange(&connection.connection.id, &pending.state, &session, 19)
            .await
            .unwrap();

        assert_eq!(store.expire_authorizations(20).await.unwrap(), 0);
        let still_connecting = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(
            still_connecting.connection.status,
            OAuthConnectionStatus::Connecting
        );
        assert_eq!(store.expire_authorizations(79).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn startup_recovery_never_replays_an_interrupted_code_exchange() {
        let (store, pool) = test_store().await;
        let connection = store
            .create_connection("source-1", "default", &config("New"), None, 10)
            .await
            .unwrap();
        let session = [1_u8; 32];
        let pending = store
            .begin_authorization("source-1", "default", 1, &session, 11, 100)
            .await
            .unwrap();
        let claim = store
            .claim_authorization_exchange(&connection.connection.id, &pending.state, &session, 12)
            .await
            .unwrap();

        let recovered = store.recover_startup(13).await.unwrap();
        assert_eq!(recovered.interrupted_exchanges, 1);
        assert!(matches!(
            store
                .complete_authorization_exchange(&claim, &secrets("a1", "r1"), 14)
                .await,
            Err(OAuthStoreError::Conflict)
        ));
        let state: (String, String) = sqlx::query_as(
            "SELECT status, error_code FROM oauth_authorization_transactions WHERE id = ?",
        )
        .bind(&claim.transaction_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, ("failed".into(), "exchange_interrupted".into()));
    }

    #[tokio::test]
    async fn clean_startup_recovery_is_a_noop() {
        let (store, _) = test_store().await;
        let recovered = store.recover_startup(10).await.unwrap();
        assert_eq!(recovered.interrupted_exchanges, 0);
        assert_eq!(recovered.abandoned_refresh_leases, 0);
    }

    #[tokio::test]
    async fn refresh_is_singleflight_and_rotation_is_compare_and_swap() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        let first = store
            .claim_refresh(&connection.connection.id, 20, 30)
            .await
            .unwrap();
        assert!(matches!(
            store.claim_refresh(&connection.connection.id, 21, 31).await,
            Err(OAuthStoreError::RefreshInProgress)
        ));

        let revision = store
            .complete_refresh(&first, &secrets("a2", "r2"), 22)
            .await
            .unwrap();
        assert_eq!(revision, 2);
        assert!(matches!(
            store
                .complete_refresh(&first, &secrets("a3", "r3"), 23)
                .await,
            Err(OAuthStoreError::Conflict)
        ));
        let loaded = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(loaded.connection.secret_revision, Some(2));
        assert_eq!(loaded.secrets.unwrap().refresh_token.as_deref(), Some("r2"));
    }

    #[tokio::test]
    async fn invalid_grant_requires_reauthorization_without_erasing_secrets() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        let claim = store
            .claim_refresh(&connection.connection.id, 20, 30)
            .await
            .unwrap();
        store.mark_refresh_invalid_grant(&claim, 21).await.unwrap();

        let loaded = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(
            loaded.connection.status,
            OAuthConnectionStatus::ReauthorizationRequired
        );
        assert_eq!(
            loaded.connection.error_code.as_deref(),
            Some("invalid_grant")
        );
        assert_eq!(loaded.connection.secret_revision, Some(1));
        assert!(matches!(
            store.claim_refresh(&connection.connection.id, 22, 32).await,
            Err(OAuthStoreError::ReauthorizationRequired)
        ));
    }

    #[tokio::test]
    async fn disconnect_preserves_only_the_client_secret() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        let disconnected = store
            .disconnect_connection("source-1", "default", 1, 11)
            .await
            .unwrap();

        assert_eq!(disconnected.connection.revision, 2);
        assert_eq!(
            disconnected.connection.status,
            OAuthConnectionStatus::PendingAuthorization
        );
        assert_eq!(disconnected.connection.authorized_at, None);
        let secrets = disconnected.secrets.unwrap();
        assert_eq!(secrets.client_secret.as_deref(), Some("client-secret"));
        assert_eq!(secrets.access_token, None);
        assert_eq!(secrets.refresh_token, None);
        assert!(matches!(
            store
                .disconnect_connection("source-1", "default", 1, 12)
                .await,
            Err(OAuthStoreError::Conflict)
        ));
        assert_eq!(connection.connection.id, disconnected.connection.id);
    }

    #[tokio::test]
    async fn switching_to_a_public_client_clears_every_secret_and_token() {
        let (store, _) = test_store().await;
        store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        let updated = store
            .upsert_connection(
                "source-1",
                "default",
                1,
                &config("Public"),
                OAuthClientSecretUpdate::Replace(None),
                11,
            )
            .await
            .unwrap();
        let secrets = updated.secrets.unwrap();
        assert_eq!(secrets.client_secret, None);
        assert_eq!(secrets.access_token, None);
        assert_eq!(secrets.refresh_token, None);
        assert!(!updated.connection.has_client_secret);
        assert!(!updated.connection.has_refresh_token);
    }

    #[tokio::test]
    async fn metadata_listing_never_decrypts_secret_ciphertext() {
        let (store, pool) = test_store().await;
        let connection = store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        sqlx::query("DROP TRIGGER oauth_secret_revisions_immutable")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE oauth_connection_secret_revisions
             SET payload_ciphertext = zeroblob(length(payload_ciphertext))
             WHERE connection_id = ?",
        )
        .bind(&connection.connection.id)
        .execute(&pool)
        .await
        .unwrap();

        let listed = store.list_connections("source-1").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].has_refresh_token);
    }

    #[tokio::test]
    async fn managed_tokens_are_encrypted_and_only_the_current_revision_is_retained() {
        let (store, pool) = test_store().await;
        let connection = store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets(
                    "access-plaintext-marker",
                    "refresh-plaintext-marker",
                )),
                10,
            )
            .await
            .unwrap();
        let first_ciphertext = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT payload_ciphertext FROM oauth_connection_secret_revisions
             WHERE connection_id = ?",
        )
        .bind(&connection.connection.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!contains_bytes(
            &first_ciphertext,
            b"access-plaintext-marker"
        ));
        assert!(!contains_bytes(
            &first_ciphertext,
            b"refresh-plaintext-marker"
        ));
        let config_json = sqlx::query_scalar::<_, String>(
            "SELECT config_json FROM oauth_connection_config_revisions
             WHERE connection_id = ?",
        )
        .bind(&connection.connection.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!config_json.contains("access-plaintext-marker"));
        assert!(!config_json.contains("refresh-plaintext-marker"));

        let claim = store
            .claim_refresh(&connection.connection.id, 20, 30)
            .await
            .unwrap();
        store
            .complete_refresh(
                &claim,
                &secrets("rotated-access-marker", "rotated-refresh-marker"),
                21,
            )
            .await
            .unwrap();
        let retained = sqlx::query_as::<_, (i64, Vec<u8>)>(
            "SELECT revision, payload_ciphertext
             FROM oauth_connection_secret_revisions WHERE connection_id = ?",
        )
        .bind(&connection.connection.id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].0, 2);
        assert!(!contains_bytes(&retained[0].1, b"rotated-access-marker"));
        assert!(!contains_bytes(&retained[0].1, b"rotated-refresh-marker"));
    }

    #[tokio::test]
    async fn restart_makes_an_in_flight_refresh_require_reauthorization() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        let _claim = store
            .claim_refresh(&connection.connection.id, 20, 200)
            .await
            .unwrap();
        let recovered = store.recover_startup(21).await.unwrap();
        assert_eq!(recovered.abandoned_refresh_leases, 1);
        assert!(matches!(
            store.claim_refresh(&connection.connection.id, 22, 32).await,
            Err(OAuthStoreError::ReauthorizationRequired)
        ));
        let loaded = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(
            loaded.connection.status,
            OAuthConnectionStatus::ReauthorizationRequired
        );
        assert_eq!(
            loaded.connection.error_code.as_deref(),
            Some("refresh_interrupted")
        );
    }

    #[tokio::test]
    async fn an_expired_live_refresh_lease_is_never_replayed() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        store
            .claim_refresh(&connection.connection.id, 20, 30)
            .await
            .unwrap();
        assert!(matches!(
            store.claim_refresh(&connection.connection.id, 30, 40).await,
            Err(OAuthStoreError::ReauthorizationRequired)
        ));
    }

    #[tokio::test]
    async fn an_ambiguous_refresh_failure_requires_reauthorization() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        let now = crate::unix_timestamp();
        let claim = store
            .claim_refresh(&connection.connection.id, now, now + 60)
            .await
            .unwrap();
        store.release_refresh(&claim).await.unwrap();

        let loaded = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(
            loaded.connection.status,
            OAuthConnectionStatus::ReauthorizationRequired
        );
        assert_eq!(
            loaded.connection.error_code.as_deref(),
            Some("refresh_interrupted")
        );
    }

    #[tokio::test]
    async fn missing_refresh_token_uses_one_terminal_compare_and_swap() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        let now = crate::unix_timestamp();
        let claim = store
            .claim_refresh(&connection.connection.id, now, now + 60)
            .await
            .unwrap();
        store
            .mark_refresh_reauthorization_required(&claim, "refresh_token_missing")
            .await
            .unwrap();
        let loaded = store.connection(&connection.connection.id).await.unwrap();
        assert_eq!(
            loaded.connection.error_code.as_deref(),
            Some("refresh_token_missing")
        );
    }

    #[tokio::test]
    async fn token_completion_rejects_a_missing_access_token() {
        let (store, _) = test_store().await;
        let connection = store
            .create_connection("source-1", "default", &config("New"), None, 10)
            .await
            .unwrap();
        let session = [1_u8; 32];
        let pending = store
            .begin_authorization("source-1", "default", 1, &session, 11, 100)
            .await
            .unwrap();
        let claim = store
            .claim_authorization_exchange(&connection.connection.id, &pending.state, &session, 12)
            .await
            .unwrap();
        assert!(matches!(
            store
                .complete_authorization_exchange(&claim, &OAuthSecretSet::default(), 13)
                .await,
            Err(OAuthStoreError::InvalidStoredRecord)
        ));
    }

    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[tokio::test]
    async fn catalog_sync_fences_the_oauth_binding_inside_its_write_transaction() {
        let (store, pool) = test_store().await;
        let created = store
            .create_connection(
                "source-1",
                "default",
                &config("New"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        let catalog = CatalogStore::new(pool, Keyring::from_master_key([11; 32]).unwrap());
        let snapshot = |expected_source_revision| CatalogSnapshot {
            expected_source_revision,
            expected_credential_revision: None,
            artifacts: Vec::new(),
            tools: Vec::new(),
        };
        let exact = OAuthBindingExpectation::Exact {
            credential_key: "default".into(),
            connection_id: created.connection.id.clone(),
            config_revision: created.connection.config_revision,
        };
        let refresh = store
            .claim_refresh(&created.connection.id, 11, 20)
            .await
            .unwrap();
        store
            .complete_refresh(&refresh, &secrets("a2", "r2"), 12)
            .await
            .unwrap();
        let after_refresh = store.connection(&created.connection.id).await.unwrap();
        assert_eq!(after_refresh.connection.config_revision, 1);
        let first = catalog
            .sync_catalog_with_bindings_and_oauth_binding(
                "source-1",
                snapshot(0),
                Vec::new(),
                exact.clone(),
                AuditContext::system(None),
            )
            .await
            .unwrap();
        assert_eq!(first.source_revision, 1);

        let updated = store
            .upsert_connection(
                "source-1",
                "default",
                after_refresh.connection.revision,
                &config("Changed"),
                OAuthClientSecretUpdate::Preserve,
                13,
            )
            .await
            .unwrap();
        let error = catalog
            .sync_catalog_with_bindings_and_oauth_binding(
                "source-1",
                snapshot(1),
                Vec::new(),
                exact,
                AuditContext::system(None),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            CatalogError::Validation {
                code: "oauth_binding_changed",
                ..
            }
        ));
        assert_eq!(catalog.source("source-1").await.unwrap().revision, 1);

        store
            .delete_connection("source-1", "default", updated.connection.revision)
            .await
            .unwrap();
        let absent = catalog
            .sync_catalog_with_bindings_and_oauth_binding(
                "source-1",
                snapshot(1),
                Vec::new(),
                OAuthBindingExpectation::Absent {
                    credential_key: "default".into(),
                },
                AuditContext::system(None),
            )
            .await
            .unwrap();
        assert_eq!(absent.source_revision, 2);
    }

    #[tokio::test]
    async fn credential_replace_rolls_back_when_the_oauth_binding_changed() {
        let (store, pool) = test_store().await;
        let catalog = CatalogStore::new(pool, Keyring::from_master_key([11; 32]).unwrap());
        let initial_credential = CredentialPayload {
            schema_version: 1,
            payload: serde_json::json!({ "token": "original" }),
        };
        catalog
            .put_credential(
                "source-1",
                &initial_credential,
                None,
                AuditContext::system(None),
            )
            .await
            .unwrap();
        let replacement = CredentialPayload {
            schema_version: 1,
            payload: serde_json::json!({}),
        };
        let snapshot = || CatalogSnapshot {
            expected_source_revision: 1,
            expected_credential_revision: Some(0),
            artifacts: Vec::new(),
            tools: Vec::new(),
        };
        let exact_error = catalog
            .replace_credential_and_sync_catalog_with_oauth_binding(
                "source-1",
                &replacement,
                snapshot(),
                Vec::new(),
                OAuthBindingExpectation::Exact {
                    credential_key: "default".into(),
                    connection_id: "missing".into(),
                    config_revision: 1,
                },
                AuditContext::system(None),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            exact_error,
            CatalogError::Validation {
                code: "oauth_binding_changed",
                ..
            }
        ));
        let stored = catalog.credential("source-1").await.unwrap().unwrap();
        assert_eq!(stored.revision, 0);
        assert_eq!(stored.credential.payload, initial_credential.payload);
        assert_eq!(catalog.source("source-1").await.unwrap().revision, 1);

        store
            .create_connection(
                "source-1",
                "default",
                &config("Active"),
                Some(&secrets("a1", "r1")),
                10,
            )
            .await
            .unwrap();
        let absent_error = catalog
            .replace_credential_and_sync_catalog_with_oauth_binding(
                "source-1",
                &replacement,
                snapshot(),
                Vec::new(),
                OAuthBindingExpectation::Absent {
                    credential_key: "default".into(),
                },
                AuditContext::system(None),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            absent_error,
            CatalogError::Validation {
                code: "oauth_binding_changed",
                ..
            }
        ));
        let stored = catalog.credential("source-1").await.unwrap().unwrap();
        assert_eq!(stored.revision, 0);
        assert_eq!(stored.credential.payload, initial_credential.payload);
        assert_eq!(catalog.source("source-1").await.unwrap().revision, 1);
    }
}
