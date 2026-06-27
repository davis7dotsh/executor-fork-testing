use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OAuthClientAuthentication {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OAuthConnectionConfig {
    pub(crate) issuer: String,
    pub(crate) authorization_endpoint: String,
    pub(crate) token_endpoint: String,
    pub(crate) client_id: String,
    pub(crate) client_authentication: OAuthClientAuthentication,
    pub(crate) token_endpoint_auth_methods_supported: Vec<String>,
    pub(crate) scopes: Vec<String>,
    pub(crate) allow_private_network: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) resource: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OAuthSecretSet {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) token_type: Option<String>,
    #[serde(default)]
    pub(crate) granted_scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) access_token_expires_at: Option<i64>,
}

#[derive(Clone)]
pub(crate) enum OAuthClientSecretUpdate {
    Preserve,
    Replace(Option<String>),
}

impl std::fmt::Debug for OAuthClientSecretUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preserve => formatter.write_str("Preserve"),
            Self::Replace(value) => formatter
                .debug_tuple("Replace")
                .field(&value.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

impl std::fmt::Debug for OAuthSecretSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthSecretSet")
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("granted_scopes", &self.granted_scopes)
            .field("access_token_expires_at", &self.access_token_expires_at)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OAuthConnectionStatus {
    PendingAuthorization,
    Connecting,
    Active,
    ReauthorizationRequired,
}

impl OAuthConnectionStatus {
    pub(super) fn as_db_str(self) -> &'static str {
        match self {
            Self::PendingAuthorization => "pending_authorization",
            Self::Connecting => "connecting",
            Self::Active => "active",
            Self::ReauthorizationRequired => "reauth_required",
        }
    }

    pub(super) fn from_db(value: &str) -> Option<Self> {
        match value {
            "pending_authorization" => Some(Self::PendingAuthorization),
            "connecting" => Some(Self::Connecting),
            "active" => Some(Self::Active),
            "reauth_required" => Some(Self::ReauthorizationRequired),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OAuthConnection {
    pub(crate) id: String,
    pub(crate) source_id: String,
    pub(crate) credential_key: String,
    pub(crate) revision: i64,
    pub(crate) config_revision: i64,
    pub(crate) secret_revision: Option<i64>,
    pub(crate) config: OAuthConnectionConfig,
    pub(crate) status: OAuthConnectionStatus,
    pub(crate) granted_scopes: Vec<String>,
    pub(crate) has_client_secret: bool,
    pub(crate) has_refresh_token: bool,
    pub(crate) access_expires_at: Option<i64>,
    pub(crate) authorized_at: Option<i64>,
    pub(crate) last_refreshed_at: Option<i64>,
    pub(crate) error_code: Option<String>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Clone)]
pub(crate) struct OAuthCredential {
    pub(crate) connection: OAuthConnection,
    pub(crate) secrets: Option<OAuthSecretSet>,
}

impl std::fmt::Debug for OAuthCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthCredential")
            .field("connection", &self.connection)
            .field("secrets", &self.secrets)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct PendingAuthorization {
    pub(crate) transaction_id: String,
    pub(crate) state: String,
    pub(crate) pkce_verifier: String,
    pub(crate) config_revision: i64,
    pub(crate) expires_at: i64,
}

impl std::fmt::Debug for PendingAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingAuthorization")
            .field("transaction_id", &self.transaction_id)
            .field("state", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .field("config_revision", &self.config_revision)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct AuthorizationExchangeClaim {
    pub(crate) transaction_id: String,
    pub(crate) connection_id: String,
    pub(crate) connection_revision: i64,
    pub(crate) config_revision: i64,
    pub(crate) config: OAuthConnectionConfig,
    pub(crate) base_secret_revision: Option<i64>,
    pub(crate) secrets: Option<OAuthSecretSet>,
    pub(crate) claim_token: String,
    pub(crate) pkce_verifier: String,
}

impl std::fmt::Debug for AuthorizationExchangeClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationExchangeClaim")
            .field("transaction_id", &self.transaction_id)
            .field("connection_id", &self.connection_id)
            .field("connection_revision", &self.connection_revision)
            .field("config_revision", &self.config_revision)
            .field("config", &self.config)
            .field("base_secret_revision", &self.base_secret_revision)
            .field("secrets", &self.secrets)
            .field("claim_token", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub(crate) struct RefreshClaim {
    pub(crate) connection_id: String,
    pub(crate) connection_revision: i64,
    pub(crate) config_revision: i64,
    pub(crate) config: OAuthConnectionConfig,
    pub(crate) base_secret_revision: i64,
    pub(crate) secrets: OAuthSecretSet,
    pub(crate) lease_token: String,
    pub(crate) expires_at: i64,
}

impl std::fmt::Debug for RefreshClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RefreshClaim")
            .field("connection_id", &self.connection_id)
            .field("connection_revision", &self.connection_revision)
            .field("config_revision", &self.config_revision)
            .field("config", &self.config)
            .field("base_secret_revision", &self.base_secret_revision)
            .field("secrets", &self.secrets)
            .field("lease_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
