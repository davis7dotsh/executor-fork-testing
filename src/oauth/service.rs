use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use url::Url;

use crate::{crypto::Keyring, outbound::OutboundPolicy, unix_timestamp};

use super::{
    discovery::{
        AuthorizationServerMetadata, TokenEndpointAuthMethod, ensure_scopes_supported,
        ensure_token_auth_method,
    },
    model::{
        OAuthClientAuthentication as StoredClientAuthentication, OAuthClientSecretUpdate,
        OAuthConnection, OAuthConnectionConfig, OAuthConnectionStatus, OAuthSecretSet,
    },
    store::{OAuthStore, OAuthStoreError},
    transport::{
        AuthorizationCodeExchange, AuthorizationRequest, OAuthClientAuthentication,
        OAuthHttpTransport, OAuthTransportError, RefreshTokenExchange, TokenResponse,
    },
};

const AUTHORIZATION_TTL_SECONDS: i64 = 10 * 60;
const REFRESH_LEASE_TTL_SECONDS: i64 = 60;
const MAX_DISPLAY_URL_BYTES: usize = 16 * 1024;
const MAX_CLIENT_ID_BYTES: usize = 4 * 1024;
const MAX_CLIENT_SECRET_BYTES: usize = 64 * 1024;
const MAX_CREDENTIAL_KEY_BYTES: usize = 128;
const MAX_SCOPES: usize = 64;
const MAX_SCOPE_BYTES: usize = 256;
const MAX_STATE_BYTES: usize = 256;
const MAX_AUTHORIZATION_CODE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClientAuthentication {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum OAuthDiscoveryInput {
    Issuer {
        issuer: String,
    },
    Mcp {
        authorization_server: Option<String>,
    },
}

#[derive(Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ClientSecretMutation {
    Preserve,
    Replace { value: String },
}

impl std::fmt::Debug for ClientSecretMutation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preserve => formatter.write_str("Preserve"),
            Self::Replace { .. } => formatter.write_str("Replace([REDACTED])"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(
    tag = "authentication",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum OAuthClientInput {
    None {
        client_id: String,
    },
    ClientSecretBasic {
        client_id: String,
        client_secret: ClientSecretMutation,
    },
    ClientSecretPost {
        client_id: String,
        client_secret: ClientSecretMutation,
    },
}

pub(crate) struct SaveConnectionRequest {
    pub(crate) expected_revision: i64,
    pub(crate) discovery: OAuthDiscoveryInput,
    pub(crate) client: OAuthClientInput,
    pub(crate) scopes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConnectionStatus {
    #[allow(dead_code)]
    NotConfigured,
    ReadyToConnect,
    Connecting,
    Connected,
    ReauthorizationRequired,
    Error,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionView {
    pub(crate) id: String,
    pub(crate) credential_key: String,
    pub(crate) revision: i64,
    pub(crate) status: ConnectionStatus,
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    pub(crate) client_auth_method: ClientAuthentication,
    pub(crate) callback_url: String,
    pub(crate) requested_scopes: Vec<String>,
    pub(crate) granted_scopes: Vec<String>,
    pub(crate) has_client_secret: bool,
    pub(crate) has_refresh_token: bool,
    pub(crate) access_expires_at: Option<i64>,
    pub(crate) authorized_at: Option<i64>,
    pub(crate) last_refreshed_at: Option<i64>,
    pub(crate) error_code: Option<String>,
}

pub(crate) struct AuthorizationStart {
    pub(crate) authorization_url: String,
}

pub(crate) struct CallbackRequest {
    pub(crate) connection_id: String,
    pub(crate) state: String,
    pub(crate) code: Option<String>,
    pub(crate) error: Option<String>,
}

pub(crate) struct CallbackResult {
    pub(crate) connection_id: String,
    pub(crate) source_id: String,
}

#[derive(Debug, Error)]
pub(crate) enum OAuthError {
    #[error("invalid OAuth input")]
    Validation {
        code: &'static str,
        message: &'static str,
    },
    #[error("the OAuth connection was not found")]
    NotFound,
    #[error("the OAuth connection changed concurrently")]
    Conflict {
        code: &'static str,
        message: &'static str,
    },
    #[error("the OAuth transaction is not valid for this session")]
    UnauthorizedTransaction,
    #[error("OAuth authorization was denied")]
    AuthorizationDenied { connection_id: String },
    #[error("the OAuth provider request failed")]
    Upstream { code: &'static str },
    #[error("OAuth persistence failed")]
    Internal,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthBinding {
    pub(crate) connection_id: String,
    pub(crate) credential_key: String,
    pub(crate) config_revision: i64,
}

pub(crate) struct OAuthAccessToken {
    token: String,
    connection_id: String,
    config_revision: i64,
    secret_revision: i64,
}

impl OAuthAccessToken {
    pub(crate) fn expose(&self) -> &str {
        &self.token
    }

    pub(crate) fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub(crate) const fn config_revision(&self) -> i64 {
        self.config_revision
    }

    pub(crate) const fn secret_revision(&self) -> i64 {
        self.secret_revision
    }
}

impl std::fmt::Debug for OAuthAccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OAuthAccessToken([REDACTED])")
    }
}

#[derive(Clone)]
pub(crate) struct OAuthService {
    store: OAuthStore,
    pool: SqlitePool,
    outbound_policy: OutboundPolicy,
    origin: Arc<str>,
    refresh_locks: Arc<Mutex<HashMap<String, Weak<AsyncMutex<()>>>>>,
}

impl OAuthService {
    pub(crate) fn new(
        pool: SqlitePool,
        keyring: Keyring,
        origin: String,
        outbound_policy: OutboundPolicy,
    ) -> Self {
        Self {
            store: OAuthStore::new(pool.clone(), keyring),
            pool,
            outbound_policy,
            origin: Arc::from(origin),
            refresh_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) async fn recover_startup(&self) -> Result<(), OAuthError> {
        self.store
            .recover_startup(unix_timestamp())
            .await
            .map(|_| ())
            .map_err(map_store_error)
    }

    pub(crate) async fn list_connections(
        &self,
        source_id: &str,
    ) -> Result<Vec<ConnectionView>, OAuthError> {
        self.require_source(source_id).await?;
        self.store
            .expire_authorizations(unix_timestamp())
            .await
            .map_err(map_store_error)?;
        self.store
            .list_connections(source_id)
            .await
            .map_err(map_store_error)?
            .into_iter()
            .map(|connection| self.connection_view(connection))
            .collect()
    }

    pub(crate) async fn binding(
        &self,
        source_id: &str,
        credential_key: &str,
    ) -> Result<Option<OAuthBinding>, OAuthError> {
        let credential = match self
            .store
            .connection_by_source_key(source_id, credential_key)
            .await
        {
            Ok(credential) => credential,
            Err(OAuthStoreError::ConnectionNotFound) => return Ok(None),
            Err(error) => return Err(map_store_error(error)),
        };
        Ok(Some(OAuthBinding {
            connection_id: credential.connection.id,
            credential_key: credential.connection.credential_key,
            config_revision: credential.connection.config_revision,
        }))
    }

    pub(crate) async fn binding_for_scopes(
        &self,
        source_id: &str,
        credential_key: &str,
        required_scopes: &[String],
    ) -> Result<Option<OAuthBinding>, OAuthError> {
        let credential = match self
            .store
            .connection_by_source_key(source_id, credential_key)
            .await
        {
            Ok(credential) => credential,
            Err(OAuthStoreError::ConnectionNotFound) => return Ok(None),
            Err(error) => return Err(map_store_error(error)),
        };
        if !required_scopes
            .iter()
            .all(|scope| credential.connection.config.scopes.contains(scope))
        {
            return Err(validation(
                "oauth_scope_not_requested",
                "The managed OAuth connection does not request every scope required by this tool.",
            ));
        }
        if credential.connection.status == OAuthConnectionStatus::Active
            && !required_scopes
                .iter()
                .all(|scope| credential.connection.granted_scopes.contains(scope))
        {
            return Err(OAuthError::Conflict {
                code: "oauth_scope_not_granted",
                message: "The OAuth provider did not grant every scope required by this tool.",
            });
        }
        Ok(Some(OAuthBinding {
            connection_id: credential.connection.id,
            credential_key: credential.connection.credential_key,
            config_revision: credential.connection.config_revision,
        }))
    }

    pub(crate) async fn ready_binding_for_scopes(
        &self,
        source_id: &str,
        credential_key: &str,
        required_scopes: &[String],
    ) -> Result<Option<OAuthBinding>, OAuthError> {
        let credential = match self
            .store
            .connection_by_source_key(source_id, credential_key)
            .await
        {
            Ok(credential) => credential,
            Err(OAuthStoreError::ConnectionNotFound) => return Ok(None),
            Err(error) => return Err(map_store_error(error)),
        };
        if credential.connection.status != OAuthConnectionStatus::Active {
            return Ok(None);
        }
        if !required_scopes
            .iter()
            .all(|scope| credential.connection.config.scopes.contains(scope))
        {
            return Err(validation(
                "oauth_scope_not_requested",
                "The managed OAuth connection does not request every scope required by this tool.",
            ));
        }
        if !required_scopes
            .iter()
            .all(|scope| credential.connection.granted_scopes.contains(scope))
        {
            return Err(OAuthError::Conflict {
                code: "oauth_scope_not_granted",
                message: "The OAuth provider did not grant every scope required by this tool.",
            });
        }
        let refreshable = credential
            .secrets
            .as_ref()
            .is_some_and(|secrets| secrets.refresh_token.is_some());
        if !token_is_usable(&credential.secrets, unix_timestamp()) && !refreshable {
            return Ok(None);
        }
        Ok(Some(OAuthBinding {
            connection_id: credential.connection.id,
            credential_key: credential.connection.credential_key,
            config_revision: credential.connection.config_revision,
        }))
    }

    pub(crate) async fn bindings_for_source(
        &self,
        source_id: &str,
    ) -> Result<Vec<OAuthBinding>, OAuthError> {
        let mut bindings = self
            .store
            .list_connections(source_id)
            .await
            .map_err(map_store_error)?
            .into_iter()
            .map(|connection| OAuthBinding {
                connection_id: connection.id,
                credential_key: connection.credential_key,
                config_revision: connection.config_revision,
            })
            .collect::<Vec<_>>();
        bindings.sort();
        Ok(bindings)
    }

    pub(crate) async fn bindings_match(
        &self,
        source_id: &str,
        expected: &[OAuthBinding],
    ) -> Result<bool, OAuthError> {
        Ok(self.bindings_for_source(source_id).await? == expected)
    }

    pub(crate) async fn access_token_for_binding(
        &self,
        binding: &OAuthBinding,
    ) -> Result<OAuthAccessToken, OAuthError> {
        self.access_token(&binding.connection_id, binding.config_revision)
            .await
    }

    pub(crate) async fn save_connection(
        &self,
        source_id: &str,
        credential_key: &str,
        request: SaveConnectionRequest,
    ) -> Result<ConnectionView, OAuthError> {
        self.require_source(source_id).await?;
        validate_credential_key(credential_key)?;
        if request.expected_revision < 0 {
            return Err(validation(
                "invalid_revision",
                "expectedRevision must not be negative.",
            ));
        }
        let scopes = validate_scopes(request.scopes)?;
        ensure_scopes_supported(&scopes).map_err(map_discovery_error)?;
        let (client_id, authentication, secret_update) = validate_client(request.client)?;
        let allow_private_network = self.source_allows_private_network(source_id).await?;
        let transport = self.transport(allow_private_network);
        let (issuer, resource) = self
            .resolve_discovery(source_id, request.discovery, &scopes, &transport)
            .await?;
        let metadata = transport
            .discover_authorization_server(&issuer)
            .await
            .map_err(map_transport_error)?;
        ensure_token_auth_method(&metadata, token_auth_method(authentication))
            .map_err(map_discovery_error)?;
        ensure_requested_scopes(&metadata.scopes_supported, &scopes)?;
        let config = OAuthConnectionConfig {
            issuer: metadata.issuer,
            authorization_endpoint: metadata.authorization_endpoint.to_string(),
            token_endpoint: metadata.token_endpoint.to_string(),
            client_id,
            client_authentication: stored_authentication(authentication),
            token_endpoint_auth_methods_supported: metadata.token_endpoint_auth_methods_supported,
            scopes,
            allow_private_network,
            resource,
        };
        if matches!(&secret_update, OAuthClientSecretUpdate::Preserve)
            && request.expected_revision > 0
        {
            let current = self
                .store
                .connection_by_source_key(source_id, credential_key)
                .await
                .map_err(map_store_error)?;
            if current.connection.revision != request.expected_revision {
                return Err(conflict());
            }
            if confidential_identity_changed(&current.connection.config, &config) {
                return Err(validation(
                    "oauth_client_secret_replacement_required",
                    "Replace the client secret when changing the OAuth issuer or client identity.",
                ));
            }
        }
        let connection = self
            .store
            .upsert_connection(
                source_id,
                credential_key,
                request.expected_revision,
                &config,
                secret_update,
                unix_timestamp(),
            )
            .await
            .map_err(map_store_error)?;
        self.connection_view(connection.connection)
    }

    pub(crate) async fn begin_authorization(
        &self,
        source_id: &str,
        credential_key: &str,
        expected_revision: i64,
        _admin_id: i64,
        admin_session_digest: &[u8],
    ) -> Result<AuthorizationStart, OAuthError> {
        let session_digest = fixed_digest(admin_session_digest)?;
        self.store
            .expire_authorizations(unix_timestamp())
            .await
            .map_err(map_store_error)?;
        let credential = self
            .store
            .connection_by_source_key(source_id, credential_key)
            .await
            .map_err(map_store_error)?;
        if credential.connection.revision != expected_revision {
            return Err(conflict());
        }
        let client =
            client_authentication(&credential.connection.config, credential.secrets.as_ref())?;
        ensure_token_auth_method(
            &metadata_from_config(&credential.connection.config)?,
            client.method(),
        )
        .map_err(map_discovery_error)?;
        let now = unix_timestamp();
        let expires_at = now
            .checked_add(AUTHORIZATION_TTL_SECONDS)
            .ok_or(OAuthError::Internal)?;
        let pending = self
            .store
            .begin_authorization(
                source_id,
                credential_key,
                expected_revision,
                &session_digest,
                now,
                expires_at,
            )
            .await
            .map_err(map_store_error)?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pending.pkce_verifier.as_bytes()));
        let callback_url = self.callback_url(&credential.connection.id)?;
        let authorization_url = self
            .transport(self.source_allows_private_network(source_id).await?)
            .authorization_url(
                &metadata_from_config(&credential.connection.config)?,
                &AuthorizationRequest {
                    client_id: credential.connection.config.client_id,
                    redirect_uri: callback_url,
                    scopes: credential.connection.config.scopes,
                    state: pending.state,
                    code_challenge: challenge,
                    resource: credential.connection.config.resource,
                },
            )
            .map_err(map_transport_error)?;
        Ok(AuthorizationStart {
            authorization_url: authorization_url.to_string(),
        })
    }

    pub(crate) async fn disconnect(
        &self,
        source_id: &str,
        credential_key: &str,
        expected_revision: i64,
    ) -> Result<ConnectionView, OAuthError> {
        let connection = self
            .store
            .disconnect_connection(
                source_id,
                credential_key,
                expected_revision,
                unix_timestamp(),
            )
            .await
            .map_err(map_store_error)?;
        self.connection_view(connection.connection)
    }

    pub(crate) async fn delete_connection(
        &self,
        source_id: &str,
        credential_key: &str,
        expected_revision: i64,
    ) -> Result<(), OAuthError> {
        self.store
            .delete_connection(source_id, credential_key, expected_revision)
            .await
            .map_err(map_store_error)
    }

    pub(crate) async fn complete_callback(
        &self,
        request: CallbackRequest,
        _admin_id: i64,
        admin_session_digest: &[u8],
    ) -> Result<CallbackResult, OAuthError> {
        validate_callback(&request)?;
        let session_digest = fixed_digest(admin_session_digest)?;
        let claim = self
            .store
            .claim_authorization_exchange(
                &request.connection_id,
                &request.state,
                &session_digest,
                unix_timestamp(),
            )
            .await
            .map_err(map_store_error)?;
        if let Some(provider_error) = request.error.as_deref() {
            self.store
                .fail_authorization_exchange(&claim, "authorization_denied", unix_timestamp())
                .await
                .map_err(map_store_error)?;
            if provider_error == "access_denied" {
                return Err(OAuthError::AuthorizationDenied {
                    connection_id: claim.connection_id,
                });
            }
            return Err(OAuthError::Upstream {
                code: "oauth_authorization_error",
            });
        }
        let code = request.code.ok_or_else(|| {
            validation(
                "invalid_oauth_callback",
                "The OAuth callback must include an authorization code.",
            )
        })?;
        let client = client_authentication(&claim.config, claim.secrets.as_ref())?;
        let callback_url = self.callback_url(&claim.connection_id)?;
        let current = self
            .store
            .connection(&claim.connection_id)
            .await
            .map_err(map_store_error)?;
        if current.connection.revision != claim.connection_revision {
            return Err(conflict());
        }
        let allow_private_network = self
            .source_allows_private_network(&current.connection.source_id)
            .await?;
        let exchanged = self
            .transport(allow_private_network)
            .exchange_authorization_code(
                &metadata_from_config(&claim.config)?,
                &AuthorizationCodeExchange {
                    code,
                    redirect_uri: callback_url,
                    code_verifier: claim.pkce_verifier.clone(),
                    resource: claim.config.resource.clone(),
                    client,
                },
            )
            .await;
        let token = match exchanged {
            Ok(token) => token,
            Err(error) => {
                let _ = self
                    .store
                    .fail_authorization_exchange(&claim, error.code(), unix_timestamp())
                    .await;
                return Err(map_transport_error(error));
            }
        };
        let secrets = token_secrets(
            token,
            claim
                .secrets
                .as_ref()
                .and_then(|secrets| secrets.client_secret.clone()),
            None,
            &claim.config.scopes,
            unix_timestamp(),
        )?;
        self.store
            .complete_authorization_exchange(&claim, &secrets, unix_timestamp())
            .await
            .map_err(map_store_error)?;
        Ok(CallbackResult {
            connection_id: claim.connection_id,
            source_id: current.connection.source_id,
        })
    }

    pub(crate) async fn access_token(
        &self,
        connection_id: &str,
        expected_config_revision: i64,
    ) -> Result<OAuthAccessToken, OAuthError> {
        let current = self
            .store
            .connection(connection_id)
            .await
            .map_err(map_store_error)?;
        require_config_revision(&current.connection, expected_config_revision)?;
        if token_is_usable(&current.secrets, unix_timestamp()) {
            return access_token_from(current);
        }
        let refresh_lock = self.refresh_lock(connection_id);
        let _guard = refresh_lock.lock().await;
        let current = self
            .store
            .connection(connection_id)
            .await
            .map_err(map_store_error)?;
        require_config_revision(&current.connection, expected_config_revision)?;
        if token_is_usable(&current.secrets, unix_timestamp()) {
            return access_token_from(current);
        }
        let now = unix_timestamp();
        let lease_expires_at = now
            .checked_add(REFRESH_LEASE_TTL_SECONDS)
            .ok_or(OAuthError::Internal)?;
        let claim = self
            .store
            .claim_refresh(connection_id, now, lease_expires_at)
            .await
            .map_err(map_store_error)?;
        let current = self
            .store
            .connection(&claim.connection_id)
            .await
            .map_err(map_store_error)?;
        if current.connection.revision != claim.connection_revision {
            let _ = self.store.release_refresh(&claim).await;
            return Err(conflict());
        }
        let allow_private_network = self
            .source_allows_private_network(&current.connection.source_id)
            .await?;
        let Some(refresh_token) = claim.secrets.refresh_token.clone() else {
            self.store
                .mark_refresh_reauthorization_required(&claim, "refresh_token_missing")
                .await
                .map_err(map_store_error)?;
            return Err(OAuthError::Conflict {
                code: "oauth_reauthorization_required",
                message: "The OAuth connection must be authorized again.",
            });
        };
        let client = client_authentication(&claim.config, Some(&claim.secrets))?;
        let refreshed = self
            .transport(allow_private_network)
            .refresh_access_token(
                &metadata_from_config(&claim.config)?,
                &RefreshTokenExchange {
                    refresh_token,
                    resource: claim.config.resource.clone(),
                    client,
                },
            )
            .await;
        let token = match refreshed {
            Ok(token) => token,
            Err(OAuthTransportError::InvalidGrant) => {
                self.store
                    .mark_refresh_invalid_grant(&claim, unix_timestamp())
                    .await
                    .map_err(map_store_error)?;
                return Err(OAuthError::Conflict {
                    code: "oauth_reauthorization_required",
                    message: "The OAuth connection must be authorized again.",
                });
            }
            Err(error) => {
                let _ = self.store.release_refresh(&claim).await;
                return Err(map_transport_error(error));
            }
        };
        let rotated = token_secrets(
            token,
            claim.secrets.client_secret.clone(),
            claim.secrets.refresh_token.clone(),
            &claim.secrets.granted_scopes,
            unix_timestamp(),
        )?;
        self.store
            .complete_refresh(&claim, &rotated, unix_timestamp())
            .await
            .map_err(map_store_error)?;
        let current = self
            .store
            .connection(connection_id)
            .await
            .map_err(map_store_error)?;
        require_config_revision(&current.connection, expected_config_revision)?;
        access_token_from(current)
    }

    async fn resolve_discovery(
        &self,
        source_id: &str,
        discovery: OAuthDiscoveryInput,
        scopes: &[String],
        transport: &OAuthHttpTransport,
    ) -> Result<(String, Option<String>), OAuthError> {
        match discovery {
            OAuthDiscoveryInput::Issuer { issuer } => {
                validate_url_length(&issuer)?;
                Ok((issuer, None))
            }
            OAuthDiscoveryInput::Mcp {
                authorization_server,
            } => {
                let resource = self.mcp_resource(source_id).await?;
                let metadata = transport
                    .discover_protected_resource(&resource)
                    .await
                    .map_err(map_transport_error)?;
                let issuer = match (authorization_server, metadata.as_ref()) {
                    (Some(issuer), Some(metadata)) => {
                        validate_url_length(&issuer)?;
                        if !metadata.authorization_servers.is_empty()
                            && !metadata
                                .authorization_servers
                                .iter()
                                .any(|candidate| candidate.as_str() == issuer)
                        {
                            return Err(validation(
                                "oauth_authorization_server_mismatch",
                                "The selected authorization server is not advertised by this MCP resource.",
                            ));
                        }
                        issuer
                    }
                    (Some(issuer), None) => issuer,
                    (None, Some(metadata)) if metadata.authorization_servers.len() == 1 => {
                        metadata.authorization_servers[0].to_string()
                    }
                    _ => {
                        return Err(validation(
                            "oauth_authorization_server_required",
                            "Select one authorization server advertised by the MCP resource.",
                        ));
                    }
                };
                if let Some(metadata) = metadata
                    && !metadata.scopes_supported.is_empty()
                {
                    ensure_requested_scopes(&metadata.scopes_supported, scopes)?;
                }
                Ok((issuer, Some(resource)))
            }
        }
    }

    async fn require_source(&self, source_id: &str) -> Result<(), OAuthError> {
        let exists =
            sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM sources WHERE id = ?)")
                .bind(source_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|_| OAuthError::Internal)?;
        if exists == 0 {
            Err(OAuthError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn mcp_resource(&self, source_id: &str) -> Result<String, OAuthError> {
        let row = sqlx::query("SELECT kind, configuration_json FROM sources WHERE id = ?")
            .bind(source_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| OAuthError::Internal)?
            .ok_or(OAuthError::NotFound)?;
        let kind: String = row.get("kind");
        if kind != "mcp_http" {
            return Err(validation(
                "oauth_mcp_discovery_unavailable",
                "MCP protected-resource discovery requires an MCP HTTP source.",
            ));
        }
        let configuration: serde_json::Value = serde_json::from_str(row.get("configuration_json"))
            .map_err(|_| OAuthError::Internal)?;
        let endpoint = configuration
            .get("endpoint")
            .and_then(serde_json::Value::as_str)
            .ok_or(OAuthError::Internal)?;
        validate_url_length(endpoint)?;
        Ok(endpoint.to_owned())
    }

    async fn source_allows_private_network(&self, source_id: &str) -> Result<bool, OAuthError> {
        let configuration =
            sqlx::query_scalar::<_, String>("SELECT configuration_json FROM sources WHERE id = ?")
                .bind(source_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| OAuthError::Internal)?
                .ok_or(OAuthError::NotFound)?;
        let configuration: serde_json::Value =
            serde_json::from_str(&configuration).map_err(|_| OAuthError::Internal)?;
        Ok(configuration
            .get("allowPrivateNetwork")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false))
    }

    fn transport(&self, allow_private_network: bool) -> OAuthHttpTransport {
        let mut policy = self.outbound_policy.clone();
        policy.allow_private_networks = allow_private_network;
        OAuthHttpTransport::new(policy)
    }

    fn connection_view(&self, connection: OAuthConnection) -> Result<ConnectionView, OAuthError> {
        let status = if connection.error_code.is_some()
            && connection.status != OAuthConnectionStatus::ReauthorizationRequired
        {
            ConnectionStatus::Error
        } else {
            match connection.status {
                OAuthConnectionStatus::PendingAuthorization => ConnectionStatus::ReadyToConnect,
                OAuthConnectionStatus::Connecting => ConnectionStatus::Connecting,
                OAuthConnectionStatus::Active => ConnectionStatus::Connected,
                OAuthConnectionStatus::ReauthorizationRequired => {
                    ConnectionStatus::ReauthorizationRequired
                }
            }
        };
        Ok(ConnectionView {
            callback_url: self.callback_url(&connection.id)?,
            id: connection.id,
            credential_key: connection.credential_key,
            revision: connection.revision,
            status,
            issuer: connection.config.issuer,
            client_id: connection.config.client_id,
            client_auth_method: public_authentication(connection.config.client_authentication),
            requested_scopes: connection.config.scopes,
            granted_scopes: connection.granted_scopes,
            has_client_secret: connection.has_client_secret,
            has_refresh_token: connection.has_refresh_token,
            access_expires_at: connection.access_expires_at,
            authorized_at: connection.authorized_at,
            last_refreshed_at: connection.last_refreshed_at,
            error_code: connection.error_code,
        })
    }

    fn callback_url(&self, connection_id: &str) -> Result<String, OAuthError> {
        let mut url = Url::parse(&self.origin).map_err(|_| OAuthError::Internal)?;
        url.set_path(&format!("/api/v1/oauth/callback/{connection_id}"));
        url.set_query(None);
        url.set_fragment(None);
        Ok(url.to_string())
    }

    fn refresh_lock(&self, connection_id: &str) -> Arc<AsyncMutex<()>> {
        let mut locks = self
            .refresh_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(connection_id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(connection_id.to_owned(), Arc::downgrade(&lock));
        lock
    }
}

fn validate_client(
    client: OAuthClientInput,
) -> Result<(String, ClientAuthentication, OAuthClientSecretUpdate), OAuthError> {
    let (client_id, authentication, secret) = match client {
        OAuthClientInput::None { client_id } => (
            client_id,
            ClientAuthentication::None,
            OAuthClientSecretUpdate::Replace(None),
        ),
        OAuthClientInput::ClientSecretBasic {
            client_id,
            client_secret,
        } => (
            client_id,
            ClientAuthentication::ClientSecretBasic,
            secret_update(client_secret)?,
        ),
        OAuthClientInput::ClientSecretPost {
            client_id,
            client_secret,
        } => (
            client_id,
            ClientAuthentication::ClientSecretPost,
            secret_update(client_secret)?,
        ),
    };
    let client_id = client_id.trim().to_owned();
    if client_id.is_empty() || client_id.len() > MAX_CLIENT_ID_BYTES {
        return Err(validation(
            "invalid_oauth_client_id",
            "The OAuth client ID is invalid.",
        ));
    }
    Ok((client_id, authentication, secret))
}

fn secret_update(mutation: ClientSecretMutation) -> Result<OAuthClientSecretUpdate, OAuthError> {
    match mutation {
        ClientSecretMutation::Preserve => Ok(OAuthClientSecretUpdate::Preserve),
        ClientSecretMutation::Replace { value }
            if !value.is_empty() && value.len() <= MAX_CLIENT_SECRET_BYTES =>
        {
            Ok(OAuthClientSecretUpdate::Replace(Some(value)))
        }
        ClientSecretMutation::Replace { .. } => Err(validation(
            "invalid_oauth_client_secret",
            "The OAuth client secret is invalid.",
        )),
    }
}

fn validate_scopes(scopes: Vec<String>) -> Result<Vec<String>, OAuthError> {
    if scopes.len() > MAX_SCOPES {
        return Err(validation(
            "invalid_oauth_scopes",
            "Too many OAuth scopes were requested.",
        ));
    }
    let mut normalized = Vec::with_capacity(scopes.len());
    for scope in scopes {
        if scope == "openid" {
            return Err(validation(
                "oauth_openid_unsupported",
                "OpenID Connect scopes are not supported.",
            ));
        }
        if scope.is_empty()
            || scope.len() > MAX_SCOPE_BYTES
            || !scope
                .bytes()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        {
            return Err(validation(
                "invalid_oauth_scopes",
                "An OAuth scope is invalid.",
            ));
        }
        if !normalized.contains(&scope) {
            normalized.push(scope);
        }
    }
    Ok(normalized)
}

fn validate_credential_key(credential_key: &str) -> Result<(), OAuthError> {
    if credential_key.is_empty()
        || credential_key.len() > MAX_CREDENTIAL_KEY_BYTES
        || credential_key.chars().any(char::is_control)
    {
        Err(validation(
            "invalid_oauth_credential_key",
            "The OAuth credential key is invalid.",
        ))
    } else {
        Ok(())
    }
}

fn validate_url_length(value: &str) -> Result<(), OAuthError> {
    if value.is_empty() || value.len() > MAX_DISPLAY_URL_BYTES {
        Err(validation("invalid_oauth_url", "The OAuth URL is invalid."))
    } else {
        Ok(())
    }
}

fn validate_callback(request: &CallbackRequest) -> Result<(), OAuthError> {
    if request.connection_id.is_empty()
        || request.connection_id.len() > 128
        || request.state.is_empty()
        || request.state.len() > MAX_STATE_BYTES
        || request
            .code
            .as_ref()
            .is_some_and(|code| code.is_empty() || code.len() > MAX_AUTHORIZATION_CODE_BYTES)
        || request
            .error
            .as_ref()
            .is_some_and(|error| error.is_empty() || error.len() > 256)
        || (request.code.is_some() == request.error.is_some())
    {
        Err(validation(
            "invalid_oauth_callback",
            "The OAuth callback parameters are invalid.",
        ))
    } else {
        Ok(())
    }
}

fn fixed_digest(value: &[u8]) -> Result<[u8; 32], OAuthError> {
    value
        .try_into()
        .map_err(|_| OAuthError::UnauthorizedTransaction)
}

fn ensure_requested_scopes(supported: &[String], requested: &[String]) -> Result<(), OAuthError> {
    if supported.is_empty() || requested.iter().all(|scope| supported.contains(scope)) {
        Ok(())
    } else {
        Err(validation(
            "oauth_scope_unsupported",
            "The OAuth provider does not advertise every requested scope.",
        ))
    }
}

fn metadata_from_config(
    config: &OAuthConnectionConfig,
) -> Result<AuthorizationServerMetadata, OAuthError> {
    Ok(AuthorizationServerMetadata {
        issuer: config.issuer.clone(),
        authorization_endpoint: Url::parse(&config.authorization_endpoint)
            .map_err(|_| OAuthError::Internal)?,
        token_endpoint: Url::parse(&config.token_endpoint).map_err(|_| OAuthError::Internal)?,
        scopes_supported: Vec::new(),
        token_endpoint_auth_methods_supported: config.token_endpoint_auth_methods_supported.clone(),
    })
}

fn client_authentication(
    config: &OAuthConnectionConfig,
    secrets: Option<&OAuthSecretSet>,
) -> Result<OAuthClientAuthentication, OAuthError> {
    match config.client_authentication {
        StoredClientAuthentication::None => Ok(OAuthClientAuthentication::Public {
            client_id: config.client_id.clone(),
        }),
        StoredClientAuthentication::ClientSecretBasic => {
            Ok(OAuthClientAuthentication::ClientSecretBasic {
                client_id: config.client_id.clone(),
                client_secret: required_client_secret(secrets)?,
            })
        }
        StoredClientAuthentication::ClientSecretPost => {
            Ok(OAuthClientAuthentication::ClientSecretPost {
                client_id: config.client_id.clone(),
                client_secret: required_client_secret(secrets)?,
            })
        }
    }
}

fn required_client_secret(secrets: Option<&OAuthSecretSet>) -> Result<String, OAuthError> {
    secrets
        .and_then(|secrets| secrets.client_secret.clone())
        .ok_or_else(|| {
            validation(
                "oauth_client_secret_required",
                "This OAuth client requires a saved client secret.",
            )
        })
}

fn token_secrets(
    token: TokenResponse,
    client_secret: Option<String>,
    previous_refresh_token: Option<String>,
    fallback_scopes: &[String],
    now: i64,
) -> Result<OAuthSecretSet, OAuthError> {
    let expires_at = match token.expires_in {
        Some(seconds) => Some(
            now.checked_add(i64::try_from(seconds).map_err(|_| OAuthError::Internal)?)
                .ok_or(OAuthError::Internal)?,
        ),
        None => None,
    };
    let granted_scopes = match token.scope {
        Some(scopes) => {
            let scopes =
                validate_scopes(scopes.split_ascii_whitespace().map(str::to_owned).collect())?;
            if !scopes.iter().all(|scope| fallback_scopes.contains(scope)) {
                return Err(OAuthError::Upstream {
                    code: "oauth_scope_escalation",
                });
            }
            scopes
        }
        None => fallback_scopes.to_vec(),
    };
    Ok(OAuthSecretSet {
        client_secret,
        access_token: Some(token.access_token),
        refresh_token: token.refresh_token.or(previous_refresh_token),
        token_type: Some(token.token_type),
        granted_scopes,
        access_token_expires_at: expires_at,
    })
}

fn token_is_usable(secrets: &Option<OAuthSecretSet>, now: i64) -> bool {
    secrets.as_ref().is_some_and(|secrets| {
        secrets.access_token.is_some()
            && secrets
                .access_token_expires_at
                .is_none_or(|expires_at| expires_at > now)
    })
}

fn access_token_from(
    credential: super::model::OAuthCredential,
) -> Result<OAuthAccessToken, OAuthError> {
    let secret_revision = credential
        .connection
        .secret_revision
        .ok_or_else(reauthorization_required)?;
    let token = credential
        .secrets
        .and_then(|secrets| secrets.access_token)
        .ok_or_else(reauthorization_required)?;
    Ok(OAuthAccessToken {
        token,
        connection_id: credential.connection.id,
        config_revision: credential.connection.config_revision,
        secret_revision,
    })
}

fn reauthorization_required() -> OAuthError {
    OAuthError::Conflict {
        code: "oauth_reauthorization_required",
        message: "The OAuth connection must be authorized again.",
    }
}

fn require_config_revision(
    connection: &OAuthConnection,
    expected_config_revision: i64,
) -> Result<(), OAuthError> {
    if connection.config_revision == expected_config_revision {
        Ok(())
    } else {
        Err(conflict())
    }
}

fn stored_authentication(authentication: ClientAuthentication) -> StoredClientAuthentication {
    match authentication {
        ClientAuthentication::None => StoredClientAuthentication::None,
        ClientAuthentication::ClientSecretBasic => StoredClientAuthentication::ClientSecretBasic,
        ClientAuthentication::ClientSecretPost => StoredClientAuthentication::ClientSecretPost,
    }
}

fn public_authentication(authentication: StoredClientAuthentication) -> ClientAuthentication {
    match authentication {
        StoredClientAuthentication::None => ClientAuthentication::None,
        StoredClientAuthentication::ClientSecretBasic => ClientAuthentication::ClientSecretBasic,
        StoredClientAuthentication::ClientSecretPost => ClientAuthentication::ClientSecretPost,
    }
}

fn confidential_identity_changed(
    current: &OAuthConnectionConfig,
    replacement: &OAuthConnectionConfig,
) -> bool {
    current.issuer != replacement.issuer
        || current.authorization_endpoint != replacement.authorization_endpoint
        || current.token_endpoint != replacement.token_endpoint
        || current.client_id != replacement.client_id
        || current.client_authentication != replacement.client_authentication
}

fn token_auth_method(authentication: ClientAuthentication) -> TokenEndpointAuthMethod {
    match authentication {
        ClientAuthentication::None => TokenEndpointAuthMethod::None,
        ClientAuthentication::ClientSecretBasic => TokenEndpointAuthMethod::ClientSecretBasic,
        ClientAuthentication::ClientSecretPost => TokenEndpointAuthMethod::ClientSecretPost,
    }
}

trait AuthenticationMethod {
    fn method(&self) -> TokenEndpointAuthMethod;
}

impl AuthenticationMethod for OAuthClientAuthentication {
    fn method(&self) -> TokenEndpointAuthMethod {
        match self {
            Self::Public { .. } => TokenEndpointAuthMethod::None,
            Self::ClientSecretBasic { .. } => TokenEndpointAuthMethod::ClientSecretBasic,
            Self::ClientSecretPost { .. } => TokenEndpointAuthMethod::ClientSecretPost,
        }
    }
}

fn map_store_error(error: OAuthStoreError) -> OAuthError {
    match error {
        OAuthStoreError::ConnectionNotFound => OAuthError::NotFound,
        OAuthStoreError::Conflict | OAuthStoreError::RefreshInProgress => conflict(),
        OAuthStoreError::AuthorizationRejected => OAuthError::UnauthorizedTransaction,
        OAuthStoreError::ReauthorizationRequired => OAuthError::Conflict {
            code: "oauth_reauthorization_required",
            message: "The OAuth connection must be authorized again.",
        },
        OAuthStoreError::AuthorizationCapacity => OAuthError::Conflict {
            code: "oauth_authorization_busy",
            message: "Too many OAuth authorization attempts are active.",
        },
        OAuthStoreError::InvalidStoredRecord
        | OAuthStoreError::EncodeConfiguration(_)
        | OAuthStoreError::DecodeConfiguration(_)
        | OAuthStoreError::Crypto(_)
        | OAuthStoreError::Database(_) => OAuthError::Internal,
    }
}

fn map_transport_error(error: OAuthTransportError) -> OAuthError {
    OAuthError::Upstream { code: error.code() }
}

fn map_discovery_error(error: super::discovery::OAuthDiscoveryError) -> OAuthError {
    use super::discovery::OAuthDiscoveryError;

    match error {
        OAuthDiscoveryError::OpenIdUnsupported => validation(
            "oauth_openid_unsupported",
            "OpenID Connect scopes are not supported.",
        ),
        OAuthDiscoveryError::TokenAuthMethodUnsupported => validation(
            "oauth_client_authentication_unsupported",
            "The OAuth provider does not support the selected client authentication method.",
        ),
        error => OAuthError::Upstream { code: error.code() },
    }
}

fn validation(code: &'static str, message: &'static str) -> OAuthError {
    OAuthError::Validation { code, message }
}

fn conflict() -> OAuthError {
    OAuthError::Conflict {
        code: "oauth_revision_conflict",
        message: "The OAuth connection changed. Reload it and try again.",
    }
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqlitePoolOptions;

    use super::*;

    async fn binding_test_service() -> OAuthService {
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
        OAuthService::new(
            pool,
            Keyring::from_master_key([17; 32]).unwrap(),
            "http://localhost:3000".into(),
            OutboundPolicy::default(),
        )
    }

    fn binding_test_config() -> OAuthConnectionConfig {
        OAuthConnectionConfig {
            issuer: "https://issuer.example".into(),
            authorization_endpoint: "https://issuer.example/authorize".into(),
            token_endpoint: "https://issuer.example/token".into(),
            client_id: "executor".into(),
            client_authentication: StoredClientAuthentication::ClientSecretBasic,
            token_endpoint_auth_methods_supported: vec!["client_secret_basic".into()],
            scopes: vec!["read".into()],
            allow_private_network: false,
            resource: Some("https://api.example".into()),
        }
    }

    fn binding_test_secrets(access_token: &str, refresh_token: &str) -> OAuthSecretSet {
        OAuthSecretSet {
            client_secret: Some("client-secret".into()),
            access_token: Some(access_token.into()),
            refresh_token: Some(refresh_token.into()),
            token_type: Some("Bearer".into()),
            granted_scopes: vec!["read".into()],
            access_token_expires_at: Some(10_000),
        }
    }

    #[test]
    fn public_client_is_an_explicit_secret_clear() {
        let (_, authentication, update) = validate_client(OAuthClientInput::None {
            client_id: "public-client".to_owned(),
        })
        .expect("public client is valid");
        assert_eq!(authentication, ClientAuthentication::None);
        assert!(matches!(update, OAuthClientSecretUpdate::Replace(None)));
    }

    #[test]
    fn access_tokens_are_redacted_from_debug_output() {
        assert_eq!(
            format!(
                "{:?}",
                OAuthAccessToken {
                    token: "secret-token".to_owned(),
                    connection_id: "connection".to_owned(),
                    config_revision: 1,
                    secret_revision: 1,
                }
            ),
            "OAuthAccessToken([REDACTED])"
        );
    }

    #[test]
    fn callback_requires_exactly_one_provider_result() {
        let base = CallbackRequest {
            connection_id: "connection".to_owned(),
            state: "state".to_owned(),
            code: None,
            error: None,
        };
        assert!(validate_callback(&base).is_err());
        assert!(
            validate_callback(&CallbackRequest {
                code: Some("code".to_owned()),
                error: Some("access_denied".to_owned()),
                ..base
            })
            .is_err()
        );
    }

    #[test]
    fn connection_statuses_have_stable_wire_names() {
        assert_eq!(
            serde_json::to_string(&ConnectionStatus::Connecting).unwrap(),
            "\"connecting\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectionStatus::ReauthorizationRequired).unwrap(),
            "\"reauthorization_required\""
        );
    }

    #[tokio::test]
    async fn binding_generation_changes_on_reauthorization_but_not_refresh() {
        let service = binding_test_service().await;
        let created = service
            .store
            .create_connection(
                "source-1",
                "default",
                &binding_test_config(),
                Some(&binding_test_secrets("access-before", "refresh-before")),
                10,
            )
            .await
            .unwrap();
        let captured = service
            .binding("source-1", "default")
            .await
            .unwrap()
            .unwrap();
        let serialized = serde_json::to_value(&captured).unwrap();
        assert_eq!(
            serialized,
            serde_json::json!({
                "connectionId": created.connection.id,
                "credentialKey": "default",
                "configRevision": 1,
            })
        );
        let serialized = serde_json::to_string(&captured).unwrap();
        assert!(!serialized.contains("access-before"));
        assert!(!serialized.contains("refresh-before"));
        assert!(!serialized.contains("client-secret"));

        let refresh = service
            .store
            .claim_refresh(&captured.connection_id, 11, 20)
            .await
            .unwrap();
        service
            .store
            .complete_refresh(
                &refresh,
                &binding_test_secrets("access-after-refresh", "refresh-after"),
                12,
            )
            .await
            .unwrap();
        assert_eq!(
            service.binding("source-1", "default").await.unwrap(),
            Some(captured.clone())
        );
        assert!(
            service
                .bindings_match("source-1", std::slice::from_ref(&captured))
                .await
                .unwrap()
        );

        let refreshed = service
            .store
            .connection(&captured.connection_id)
            .await
            .unwrap();
        let session_digest = [7_u8; 32];
        let pending = service
            .store
            .begin_authorization(
                "source-1",
                "default",
                refreshed.connection.revision,
                &session_digest,
                13,
                100,
            )
            .await
            .unwrap();
        let claim = service
            .store
            .claim_authorization_exchange(
                &captured.connection_id,
                &pending.state,
                &session_digest,
                14,
            )
            .await
            .unwrap();
        service
            .store
            .complete_authorization_exchange(
                &claim,
                &binding_test_secrets("access-after-reauth", "refresh-after-reauth"),
                15,
            )
            .await
            .unwrap();

        let reauthorized = service
            .binding("source-1", "default")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reauthorized.connection_id, captured.connection_id);
        assert_eq!(reauthorized.credential_key, captured.credential_key);
        assert_eq!(reauthorized.config_revision, captured.config_revision + 1);
        assert!(
            !service
                .bindings_match("source-1", &[captured])
                .await
                .unwrap()
        );
    }
}
