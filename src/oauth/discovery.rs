use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::outbound::{OutboundError, OutboundPolicy, parse_url};

#[derive(Clone)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Clone)]
pub struct ProtectedResourceMetadata {
    pub authorization_servers: Vec<Url>,
    pub scopes_supported: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenEndpointAuthMethod {
    None,
    ClientSecretBasic,
    ClientSecretPost,
}

#[derive(Debug, Error)]
pub enum OAuthDiscoveryError {
    #[error("the OAuth URL is invalid")]
    InvalidUrl,
    #[error("OAuth endpoints must use HTTPS, except loopback HTTP in local-test mode")]
    InsecureEndpoint,
    #[error("OAuth issuer URLs must not contain a query or fragment")]
    InvalidIssuer,
    #[error("OAuth metadata discovery failed")]
    Transport(#[source] OutboundError),
    #[error("OAuth metadata is malformed")]
    MalformedMetadata,
    #[error("authorization server metadata issuer does not exactly match the requested issuer")]
    IssuerMismatch,
    #[error("the authorization server does not advertise authorization code support")]
    AuthorizationCodeUnsupported,
    #[error("the authorization server does not advertise PKCE S256 support")]
    PkceS256Unsupported,
    #[error("the authorization server does not support the selected token authentication method")]
    TokenAuthMethodUnsupported,
    #[error("protected resource metadata does not match the requested resource")]
    ResourceMismatch,
    #[error("the requested OAuth scopes include the unsupported openid scope")]
    OpenIdUnsupported,
}

impl OAuthDiscoveryError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_oauth_url",
            Self::InsecureEndpoint => "insecure_oauth_endpoint",
            Self::InvalidIssuer => "invalid_oauth_issuer",
            Self::Transport(error) => error.code(),
            Self::MalformedMetadata => "malformed_oauth_metadata",
            Self::IssuerMismatch => "oauth_issuer_mismatch",
            Self::AuthorizationCodeUnsupported => "oauth_authorization_code_unsupported",
            Self::PkceS256Unsupported => "oauth_pkce_s256_unsupported",
            Self::TokenAuthMethodUnsupported => "oauth_token_auth_method_unsupported",
            Self::ResourceMismatch => "oauth_resource_mismatch",
            Self::OpenIdUnsupported => "oauth_openid_unsupported",
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct RawAuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct RawProtectedResourceMetadata {
    pub resource: Option<String>,
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
}

pub(crate) fn authorization_server_metadata_url(
    issuer: &str,
    policy: &OutboundPolicy,
) -> Result<Url, OAuthDiscoveryError> {
    let issuer_url = validate_issuer(issuer, policy)?;
    let path = issuer_url.path().trim_end_matches('/');
    let metadata = if path.is_empty() {
        format!(
            "{}/.well-known/oauth-authorization-server",
            issuer_url.origin().ascii_serialization()
        )
    } else {
        format!(
            "{}/.well-known/oauth-authorization-server{path}",
            issuer_url.origin().ascii_serialization()
        )
    };
    validate_oauth_url(&metadata, policy)
}

pub(crate) fn protected_resource_metadata_urls(
    resource: &str,
    policy: &OutboundPolicy,
) -> Result<Vec<Url>, OAuthDiscoveryError> {
    let resource = validate_oauth_url(resource, policy)?;
    let origin = resource.origin().ascii_serialization();
    let path = resource.path().trim_end_matches('/');
    let mut urls = Vec::with_capacity(2);
    if !path.is_empty() {
        urls.push(validate_oauth_url(
            &format!("{origin}/.well-known/oauth-protected-resource{path}"),
            policy,
        )?);
    }
    urls.push(validate_oauth_url(
        &format!("{origin}/.well-known/oauth-protected-resource"),
        policy,
    )?);
    Ok(urls)
}

pub(crate) fn validate_authorization_server_metadata(
    requested_issuer: &str,
    raw: RawAuthorizationServerMetadata,
    policy: &OutboundPolicy,
) -> Result<AuthorizationServerMetadata, OAuthDiscoveryError> {
    if raw.issuer != requested_issuer {
        return Err(OAuthDiscoveryError::IssuerMismatch);
    }
    validate_issuer(&raw.issuer, policy)?;
    let authorization_endpoint = validate_oauth_url(&raw.authorization_endpoint, policy)?;
    let token_endpoint = validate_oauth_url(&raw.token_endpoint, policy)?;

    if !raw.response_types_supported.is_empty()
        && !raw
            .response_types_supported
            .iter()
            .any(|value| value == "code")
    {
        return Err(OAuthDiscoveryError::AuthorizationCodeUnsupported);
    }
    if !raw.grant_types_supported.is_empty()
        && !raw
            .grant_types_supported
            .iter()
            .any(|value| value == "authorization_code")
    {
        return Err(OAuthDiscoveryError::AuthorizationCodeUnsupported);
    }
    if !raw
        .code_challenge_methods_supported
        .iter()
        .any(|value| value == "S256")
    {
        return Err(OAuthDiscoveryError::PkceS256Unsupported);
    }

    Ok(AuthorizationServerMetadata {
        issuer: raw.issuer,
        authorization_endpoint,
        token_endpoint,
        scopes_supported: raw.scopes_supported,
        token_endpoint_auth_methods_supported: raw.token_endpoint_auth_methods_supported,
    })
}

pub(crate) fn validate_protected_resource_metadata(
    requested_resource: &str,
    raw: RawProtectedResourceMetadata,
    policy: &OutboundPolicy,
) -> Result<ProtectedResourceMetadata, OAuthDiscoveryError> {
    let expected = canonical_resource(requested_resource, policy)?;
    let resource = raw.resource.ok_or(OAuthDiscoveryError::MalformedMetadata)?;
    let resource = canonical_resource(&resource, policy)?;
    if resource != expected {
        return Err(OAuthDiscoveryError::ResourceMismatch);
    }
    let authorization_servers = raw
        .authorization_servers
        .iter()
        .map(|issuer| validate_issuer(issuer, policy))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProtectedResourceMetadata {
        authorization_servers,
        scopes_supported: raw.scopes_supported,
    })
}

pub fn ensure_scopes_supported(scopes: &[String]) -> Result<(), OAuthDiscoveryError> {
    if scopes.iter().any(|scope| scope == "openid") {
        return Err(OAuthDiscoveryError::OpenIdUnsupported);
    }
    Ok(())
}

pub fn ensure_token_auth_method(
    metadata: &AuthorizationServerMetadata,
    method: TokenEndpointAuthMethod,
) -> Result<(), OAuthDiscoveryError> {
    let advertised = &metadata.token_endpoint_auth_methods_supported;
    let supported = match method {
        TokenEndpointAuthMethod::None => advertised.iter().any(|value| value == "none"),
        TokenEndpointAuthMethod::ClientSecretBasic => {
            advertised.is_empty()
                || advertised
                    .iter()
                    .any(|value| value == "client_secret_basic")
        }
        TokenEndpointAuthMethod::ClientSecretPost => {
            advertised.iter().any(|value| value == "client_secret_post")
        }
    };
    if supported {
        Ok(())
    } else {
        Err(OAuthDiscoveryError::TokenAuthMethodUnsupported)
    }
}

pub(crate) fn validate_oauth_url(
    value: &str,
    policy: &OutboundPolicy,
) -> Result<Url, OAuthDiscoveryError> {
    let url = parse_url(value, policy).map_err(map_url_error)?;
    if url.scheme() == "https"
        || (url.scheme() == "http" && policy.allow_private_networks && is_loopback(&url))
    {
        Ok(url)
    } else {
        Err(OAuthDiscoveryError::InsecureEndpoint)
    }
}

fn validate_issuer(value: &str, policy: &OutboundPolicy) -> Result<Url, OAuthDiscoveryError> {
    let url = validate_oauth_url(value, policy)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(OAuthDiscoveryError::InvalidIssuer);
    }
    Ok(url)
}

fn canonical_resource(value: &str, policy: &OutboundPolicy) -> Result<String, OAuthDiscoveryError> {
    let mut url = validate_oauth_url(value, policy)?;
    url.set_query(None);
    url.set_fragment(None);
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(hostname)) => hostname.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn map_url_error(error: OutboundError) -> OAuthDiscoveryError {
    match error {
        OutboundError::InvalidUrl
        | OutboundError::UnsupportedScheme
        | OutboundError::CredentialsNotAllowed
        | OutboundError::FragmentNotAllowed
        | OutboundError::MissingHost
        | OutboundError::MissingPort => OAuthDiscoveryError::InvalidUrl,
        error => OAuthDiscoveryError::Transport(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_policy() -> OutboundPolicy {
        OutboundPolicy {
            allow_private_networks: true,
            ..OutboundPolicy::default()
        }
    }

    fn raw_metadata(issuer: &str) -> RawAuthorizationServerMetadata {
        RawAuthorizationServerMetadata {
            issuer: issuer.to_owned(),
            authorization_endpoint: format!("{issuer}/authorize"),
            token_endpoint: format!("{issuer}/token"),
            scopes_supported: vec![],
            response_types_supported: vec!["code".to_owned()],
            grant_types_supported: vec!["authorization_code".to_owned()],
            code_challenge_methods_supported: vec!["S256".to_owned()],
            token_endpoint_auth_methods_supported: vec![
                "none".to_owned(),
                "client_secret_post".to_owned(),
            ],
        }
    }

    #[test]
    fn issuer_path_is_appended_after_the_well_known_segment() {
        let url = authorization_server_metadata_url("https://auth.example/tenant", &local_policy())
            .expect("metadata URL is valid");
        assert_eq!(
            url.as_str(),
            "https://auth.example/.well-known/oauth-authorization-server/tenant"
        );
    }

    #[test]
    fn metadata_issuer_requires_an_exact_string_match() {
        let error = validate_authorization_server_metadata(
            "https://auth.example",
            raw_metadata("https://auth.example/"),
            &local_policy(),
        )
        .err()
        .expect("different issuer spelling is rejected");
        assert!(matches!(error, OAuthDiscoveryError::IssuerMismatch));
    }

    #[test]
    fn only_loopback_http_is_allowed() {
        assert!(validate_oauth_url("http://localhost:9999/token", &local_policy()).is_ok());
        assert!(matches!(
            validate_oauth_url("http://10.0.0.2/token", &local_policy()),
            Err(OAuthDiscoveryError::InsecureEndpoint)
        ));
    }

    #[test]
    fn client_secret_post_must_be_explicitly_advertised() {
        let raw = raw_metadata("https://auth.example");
        let mut metadata =
            validate_authorization_server_metadata("https://auth.example", raw, &local_policy())
                .expect("metadata is valid");
        assert!(
            ensure_token_auth_method(&metadata, TokenEndpointAuthMethod::ClientSecretPost).is_ok()
        );
        metadata.token_endpoint_auth_methods_supported = vec![];
        assert!(matches!(
            ensure_token_auth_method(&metadata, TokenEndpointAuthMethod::ClientSecretPost),
            Err(OAuthDiscoveryError::TokenAuthMethodUnsupported)
        ));
        assert!(
            ensure_token_auth_method(&metadata, TokenEndpointAuthMethod::ClientSecretBasic).is_ok()
        );
    }

    #[test]
    fn openid_scope_is_rejected() {
        assert!(matches!(
            ensure_scopes_supported(&["read".to_owned(), "openid".to_owned()]),
            Err(OAuthDiscoveryError::OpenIdUnsupported)
        ));
    }

    #[test]
    fn protected_resource_metadata_requires_an_exact_resource() {
        let missing = RawProtectedResourceMetadata {
            resource: None,
            authorization_servers: vec![],
            scopes_supported: vec![],
        };
        assert!(matches!(
            validate_protected_resource_metadata(
                "https://api.example/v1",
                missing,
                &local_policy()
            ),
            Err(OAuthDiscoveryError::MalformedMetadata)
        ));

        let parent = RawProtectedResourceMetadata {
            resource: Some("https://api.example".to_owned()),
            authorization_servers: vec![],
            scopes_supported: vec![],
        };
        assert!(matches!(
            validate_protected_resource_metadata("https://api.example/v1", parent, &local_policy()),
            Err(OAuthDiscoveryError::ResourceMismatch)
        ));
    }
}
