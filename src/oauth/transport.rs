use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(test)]
use rand::RngCore;
use reqwest::{Method, StatusCode, header};
use serde::Deserialize;
#[cfg(test)]
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::{Url, form_urlencoded};

use super::discovery::{
    AuthorizationServerMetadata, OAuthDiscoveryError, ProtectedResourceMetadata,
    RawAuthorizationServerMetadata, RawProtectedResourceMetadata, TokenEndpointAuthMethod,
    authorization_server_metadata_url, ensure_scopes_supported, ensure_token_auth_method,
    protected_resource_metadata_urls, validate_authorization_server_metadata, validate_oauth_url,
    validate_protected_resource_metadata,
};
use crate::outbound::{HardenedHttpClient, OutboundError, OutboundPolicy, OutboundRequest};

const MAX_OAUTH_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_TOKEN_REQUEST_BYTES: usize = 64 * 1024;
const MAX_OAUTH_HEADER_BYTES: usize = 32 * 1024;
const OAUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone)]
pub struct OAuthHttpTransport {
    client: HardenedHttpClient,
    policy: OutboundPolicy,
}

#[derive(Clone)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub code_challenge: String,
    pub resource: Option<String>,
}

#[derive(Clone)]
pub struct AuthorizationCodeExchange {
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
    pub resource: Option<String>,
    pub client: OAuthClientAuthentication,
}

#[derive(Clone)]
pub struct RefreshTokenExchange {
    pub refresh_token: String,
    pub resource: Option<String>,
    pub client: OAuthClientAuthentication,
}

#[derive(Clone)]
pub enum OAuthClientAuthentication {
    Public {
        client_id: String,
    },
    ClientSecretBasic {
        client_id: String,
        client_secret: String,
    },
    ClientSecretPost {
        client_id: String,
        client_secret: String,
    },
}

#[cfg(test)]
#[derive(Clone)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Error)]
pub enum OAuthTransportError {
    #[error(transparent)]
    Discovery(#[from] OAuthDiscoveryError),
    #[error("OAuth HTTP request failed")]
    Transport(#[source] OutboundError),
    #[error("OAuth endpoint returned HTTP {0}")]
    HttpStatus(u16),
    #[error("OAuth endpoint returned an error: {0}")]
    OAuthError(String),
    #[error("the OAuth authorization grant is no longer valid")]
    InvalidGrant,
    #[error("OAuth response is malformed")]
    MalformedResponse,
    #[error("the PKCE value is invalid")]
    InvalidPkce,
    #[error("the OAuth redirect URI is invalid")]
    InvalidRedirectUri,
}

impl OAuthTransportError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Discovery(error) => error.code(),
            Self::Transport(error) => error.code(),
            Self::HttpStatus(_) => "oauth_http_error",
            Self::OAuthError(_) => "oauth_token_error",
            Self::InvalidGrant => "oauth_invalid_grant",
            Self::MalformedResponse => "malformed_oauth_response",
            Self::InvalidPkce => "invalid_oauth_pkce",
            Self::InvalidRedirectUri => "invalid_oauth_redirect_uri",
        }
    }
}

#[derive(Deserialize)]
struct OAuthErrorResponse {
    error: String,
}

impl OAuthHttpTransport {
    pub fn new(mut policy: OutboundPolicy) -> Self {
        policy.max_request_bytes = policy.max_request_bytes.min(MAX_TOKEN_REQUEST_BYTES);
        policy.max_response_bytes = policy.max_response_bytes.min(MAX_OAUTH_RESPONSE_BYTES);
        policy.max_header_bytes = policy.max_header_bytes.min(MAX_OAUTH_HEADER_BYTES);
        policy.max_redirects = 0;
        policy.request_timeout = policy.request_timeout.min(OAUTH_REQUEST_TIMEOUT);
        Self {
            client: HardenedHttpClient::new(policy.clone()),
            policy,
        }
    }

    pub async fn discover_authorization_server(
        &self,
        issuer: &str,
    ) -> Result<AuthorizationServerMetadata, OAuthTransportError> {
        let metadata_url = authorization_server_metadata_url(issuer, &self.policy)?;
        let body = self.get_json(metadata_url).await?;
        let raw = serde_json::from_slice::<RawAuthorizationServerMetadata>(&body)
            .map_err(|_| OAuthTransportError::MalformedResponse)?;
        validate_authorization_server_metadata(issuer, raw, &self.policy).map_err(Into::into)
    }

    pub async fn discover_protected_resource(
        &self,
        resource: &str,
    ) -> Result<Option<ProtectedResourceMetadata>, OAuthTransportError> {
        for metadata_url in protected_resource_metadata_urls(resource, &self.policy)? {
            let response = self
                .execute_json_request(Method::GET, metadata_url, vec![], None)
                .await?;
            if matches!(
                response.status,
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ) {
                continue;
            }
            if !response.status.is_success() {
                return Err(OAuthTransportError::HttpStatus(response.status.as_u16()));
            }
            let raw = serde_json::from_slice::<RawProtectedResourceMetadata>(&response.body)
                .map_err(|_| OAuthTransportError::MalformedResponse)?;
            let metadata = validate_protected_resource_metadata(resource, raw, &self.policy)?;
            return Ok(Some(metadata));
        }
        Ok(None)
    }

    pub fn authorization_url(
        &self,
        metadata: &AuthorizationServerMetadata,
        request: &AuthorizationRequest,
    ) -> Result<Url, OAuthTransportError> {
        ensure_scopes_supported(&request.scopes)?;
        validate_code_challenge(&request.code_challenge)?;
        validate_redirect_uri(&request.redirect_uri)?;
        let mut url = metadata.authorization_endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &request.client_id);
            query.append_pair("redirect_uri", &request.redirect_uri);
            query.append_pair("state", &request.state);
            query.append_pair("code_challenge", &request.code_challenge);
            query.append_pair("code_challenge_method", "S256");
            if !request.scopes.is_empty() {
                query.append_pair("scope", &request.scopes.join(" "));
            }
            if let Some(resource) = request.resource.as_deref() {
                let resource = validate_oauth_url(resource, &self.policy)?;
                query.append_pair("resource", resource.as_str());
            }
        }
        Ok(url)
    }

    pub async fn exchange_authorization_code(
        &self,
        metadata: &AuthorizationServerMetadata,
        request: &AuthorizationCodeExchange,
    ) -> Result<TokenResponse, OAuthTransportError> {
        validate_code_verifier(&request.code_verifier)?;
        validate_redirect_uri(&request.redirect_uri)?;
        let method = request.client.method();
        ensure_token_auth_method(metadata, method)?;

        let (headers, body) = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code");
            form.append_pair("code", &request.code);
            form.append_pair("redirect_uri", &request.redirect_uri);
            form.append_pair("code_verifier", &request.code_verifier);
            if let Some(resource) = request.resource.as_deref() {
                let resource = validate_oauth_url(resource, &self.policy)?;
                form.append_pair("resource", resource.as_str());
            }
            let mut headers = token_request_headers();
            apply_client_authentication(&mut form, &mut headers, &request.client)?;
            (headers, form.finish().into_bytes())
        };
        self.execute_token_request(metadata, headers, body).await
    }

    pub async fn refresh_access_token(
        &self,
        metadata: &AuthorizationServerMetadata,
        request: &RefreshTokenExchange,
    ) -> Result<TokenResponse, OAuthTransportError> {
        let method = request.client.method();
        ensure_token_auth_method(metadata, method)?;

        let (headers, body) = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "refresh_token");
            form.append_pair("refresh_token", &request.refresh_token);
            if let Some(resource) = request.resource.as_deref() {
                let resource = validate_oauth_url(resource, &self.policy)?;
                form.append_pair("resource", resource.as_str());
            }
            let mut headers = token_request_headers();
            apply_client_authentication(&mut form, &mut headers, &request.client)?;
            (headers, form.finish().into_bytes())
        };
        self.execute_token_request(metadata, headers, body).await
    }

    async fn execute_token_request(
        &self,
        metadata: &AuthorizationServerMetadata,
        headers: Vec<(header::HeaderName, header::HeaderValue)>,
        body: Vec<u8>,
    ) -> Result<TokenResponse, OAuthTransportError> {
        let response = self
            .execute_json_request(
                Method::POST,
                metadata.token_endpoint.clone(),
                headers,
                Some(body),
            )
            .await?;
        if !response.status.is_success() {
            if let Ok(error) = serde_json::from_slice::<OAuthErrorResponse>(&response.body) {
                let error = sanitize_error_code(&error.error);
                if error == "invalid_grant" {
                    return Err(OAuthTransportError::InvalidGrant);
                }
                return Err(OAuthTransportError::OAuthError(error));
            }
            return Err(OAuthTransportError::HttpStatus(response.status.as_u16()));
        }
        let token = serde_json::from_slice::<TokenResponse>(&response.body)
            .map_err(|_| OAuthTransportError::MalformedResponse)?;
        if token.access_token.is_empty() || !token.token_type.eq_ignore_ascii_case("bearer") {
            return Err(OAuthTransportError::MalformedResponse);
        }
        if token.scope.as_deref().is_some_and(|scope| {
            scope
                .split_ascii_whitespace()
                .any(|candidate| candidate == "openid")
        }) {
            return Err(OAuthDiscoveryError::OpenIdUnsupported.into());
        }
        Ok(token)
    }

    async fn get_json(&self, url: Url) -> Result<Vec<u8>, OAuthTransportError> {
        let response = self
            .execute_json_request(Method::GET, url, vec![], None)
            .await?;
        if !response.status.is_success() {
            return Err(OAuthTransportError::HttpStatus(response.status.as_u16()));
        }
        Ok(response.body)
    }

    async fn execute_json_request(
        &self,
        method: Method,
        url: Url,
        headers: Vec<(header::HeaderName, header::HeaderValue)>,
        body: Option<Vec<u8>>,
    ) -> Result<crate::outbound::OutboundResponse, OAuthTransportError> {
        let mut request = OutboundRequest::new(method, url);
        request.headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        for (name, value) in headers {
            request.headers.insert(name, value);
        }
        request.body = body.unwrap_or_default();
        self.client
            .execute(request)
            .await
            .map_err(OAuthTransportError::Transport)
    }
}

fn token_request_headers() -> Vec<(header::HeaderName, header::HeaderValue)> {
    vec![(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/x-www-form-urlencoded"),
    )]
}

fn apply_client_authentication(
    form: &mut form_urlencoded::Serializer<'_, String>,
    headers: &mut Vec<(header::HeaderName, header::HeaderValue)>,
    client: &OAuthClientAuthentication,
) -> Result<(), OAuthTransportError> {
    match client {
        OAuthClientAuthentication::Public { client_id } => {
            form.append_pair("client_id", client_id);
        }
        OAuthClientAuthentication::ClientSecretBasic {
            client_id,
            client_secret,
        } => {
            let username = percent_encode_form_component(client_id);
            let password = percent_encode_form_component(client_secret);
            let credential = STANDARD.encode(format!("{username}:{password}"));
            let mut value = header::HeaderValue::from_str(&format!("Basic {credential}"))
                .map_err(|_| OAuthTransportError::MalformedResponse)?;
            value.set_sensitive(true);
            headers.push((header::AUTHORIZATION, value));
        }
        OAuthClientAuthentication::ClientSecretPost {
            client_id,
            client_secret,
        } => {
            form.append_pair("client_id", client_id);
            form.append_pair("client_secret", client_secret);
        }
    }
    Ok(())
}

impl OAuthClientAuthentication {
    fn method(&self) -> TokenEndpointAuthMethod {
        match self {
            Self::Public { .. } => TokenEndpointAuthMethod::None,
            Self::ClientSecretBasic { .. } => TokenEndpointAuthMethod::ClientSecretBasic,
            Self::ClientSecretPost { .. } => TokenEndpointAuthMethod::ClientSecretPost,
        }
    }
}

#[cfg(test)]
pub fn generate_pkce() -> PkcePair {
    let mut random = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    PkcePair {
        verifier,
        challenge,
    }
}

fn validate_code_verifier(value: &str) -> Result<(), OAuthTransportError> {
    if (43..=128).contains(&value.len()) && value.bytes().all(is_pkce_unreserved) {
        Ok(())
    } else {
        Err(OAuthTransportError::InvalidPkce)
    }
}

fn validate_redirect_uri(value: &str) -> Result<(), OAuthTransportError> {
    let url = Url::parse(value).map_err(|_| OAuthTransportError::InvalidRedirectUri)?;
    if matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
    {
        Ok(())
    } else {
        Err(OAuthTransportError::InvalidRedirectUri)
    }
}

fn validate_code_challenge(value: &str) -> Result<(), OAuthTransportError> {
    if value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(OAuthTransportError::InvalidPkce)
    }
}

fn is_pkce_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn percent_encode_form_component(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn sanitize_error_code(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(128)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Arc};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::Mutex,
    };

    use super::*;

    struct TestServer {
        issuer: String,
        requests: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl TestServer {
        async fn start(responses: Vec<String>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("test listener binds");
            let issuer = format!(
                "http://{}",
                listener.local_addr().expect("listener address")
            );
            let requests = Arc::new(Mutex::new(Vec::new()));
            let captured = requests.clone();
            let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
            let task = tokio::spawn(async move {
                while let Some(response) = responses.lock().await.pop_front() {
                    let (mut stream, _) = listener.accept().await.expect("request accepted");
                    let mut bytes = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    loop {
                        let read = stream.read(&mut chunk).await.expect("request read");
                        if read == 0 {
                            break;
                        }
                        bytes.extend_from_slice(&chunk[..read]);
                        assert!(bytes.len() <= 64 * 1024, "test request remains bounded");
                        if request_is_complete(&bytes) {
                            break;
                        }
                    }
                    captured
                        .lock()
                        .await
                        .push(String::from_utf8_lossy(&bytes).into_owned());
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .expect("response written");
                }
            });
            Self {
                issuer,
                requests,
                task,
            }
        }

        async fn finish(self) -> Vec<String> {
            self.task.await.expect("server completes");
            Arc::try_unwrap(self.requests)
                .expect("single request owner")
                .into_inner()
        }
    }

    fn response(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn request_is_complete(bytes: &[u8]) -> bool {
        let Some(headers_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let body_start = headers_end + 4;
        let headers = String::from_utf8_lossy(&bytes[..headers_end]);
        let content_length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        });
        bytes.len() >= body_start + content_length.unwrap_or(0)
    }

    fn transport() -> OAuthHttpTransport {
        OAuthHttpTransport::new(OutboundPolicy {
            allow_private_networks: true,
            ..OutboundPolicy::default()
        })
    }

    fn metadata(issuer: &str, methods: &[&str]) -> String {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": methods,
        })
        .to_string()
    }

    #[test]
    fn generated_pkce_pair_is_valid_s256() {
        let pair = generate_pkce();
        validate_code_verifier(&pair.verifier).expect("verifier is valid");
        validate_code_challenge(&pair.challenge).expect("challenge is valid");
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(pair.verifier.as_bytes()));
        assert_eq!(pair.challenge, expected);
    }

    #[tokio::test]
    async fn discovery_uses_only_rfc_8414_and_requires_exact_issuer() {
        let server = TestServer::start(vec![response(
            "200 OK",
            &metadata("http://127.0.0.1:1", &["none"]),
        )])
        .await;
        let error = transport()
            .discover_authorization_server(&server.issuer)
            .await
            .err()
            .expect("issuer mismatch rejected");
        assert!(matches!(
            error,
            OAuthTransportError::Discovery(OAuthDiscoveryError::IssuerMismatch)
        ));
        let requests = server.finish().await;
        assert!(requests[0].starts_with("GET /.well-known/oauth-authorization-server "));
        assert!(!requests[0].contains("openid-configuration"));
    }

    #[tokio::test]
    async fn public_code_exchange_posts_pkce_without_a_secret() {
        let server = TestServer::start(vec![response(
            "200 OK",
            r#"{"access_token":"access","token_type":"Bearer","expires_in":60}"#,
        )])
        .await;
        let raw = serde_json::from_str::<RawAuthorizationServerMetadata>(&metadata(
            &server.issuer,
            &["none"],
        ))
        .expect("metadata JSON");
        let metadata =
            validate_authorization_server_metadata(&server.issuer, raw, &transport().policy)
                .expect("metadata valid");
        let pair = generate_pkce();
        let token = transport()
            .exchange_authorization_code(
                &metadata,
                &AuthorizationCodeExchange {
                    code: "code-value".to_owned(),
                    redirect_uri: "http://localhost/callback".to_owned(),
                    code_verifier: pair.verifier,
                    resource: None,
                    client: OAuthClientAuthentication::Public {
                        client_id: "public-client".to_owned(),
                    },
                },
            )
            .await
            .expect("exchange succeeds");
        assert_eq!(token.access_token, "access");
        let requests = server.finish().await;
        let token_request = &requests[0];
        assert!(token_request.starts_with("POST /token "));
        assert!(token_request.contains("client_id=public-client"));
        assert!(token_request.contains("code_verifier="));
        assert!(!token_request.contains("client_secret"));
        assert!(
            !token_request
                .to_ascii_lowercase()
                .contains("authorization:")
        );
    }

    #[tokio::test]
    async fn confidential_basic_uses_authorization_header_not_form_secret() {
        let server = TestServer::start(vec![response(
            "200 OK",
            r#"{"access_token":"access","token_type":"Bearer"}"#,
        )])
        .await;
        let raw = serde_json::from_str::<RawAuthorizationServerMetadata>(&metadata(
            &server.issuer,
            &["client_secret_basic"],
        ))
        .expect("metadata JSON");
        let metadata =
            validate_authorization_server_metadata(&server.issuer, raw, &transport().policy)
                .expect("metadata valid");
        let pair = generate_pkce();
        transport()
            .exchange_authorization_code(
                &metadata,
                &AuthorizationCodeExchange {
                    code: "code".to_owned(),
                    redirect_uri: "http://localhost/callback".to_owned(),
                    code_verifier: pair.verifier,
                    resource: None,
                    client: OAuthClientAuthentication::ClientSecretBasic {
                        client_id: "client:id".to_owned(),
                        client_secret: "secret value".to_owned(),
                    },
                },
            )
            .await
            .expect("exchange succeeds");
        let requests = server.finish().await;
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("authorization: basic ")
        );
        let body = requests[0].split("\r\n\r\n").nth(1).unwrap_or_default();
        assert!(!body.contains("client_secret"));
        assert!(!body.contains("secret"));
    }

    #[test]
    fn authorization_url_rejects_openid() {
        let raw = serde_json::from_str::<RawAuthorizationServerMetadata>(&metadata(
            "https://auth.example",
            &["none"],
        ))
        .expect("metadata JSON");
        let metadata = validate_authorization_server_metadata(
            "https://auth.example",
            raw,
            &OutboundPolicy::default(),
        )
        .expect("metadata valid");
        let pair = generate_pkce();
        let Err(error) = transport().authorization_url(
            &metadata,
            &AuthorizationRequest {
                client_id: "client".to_owned(),
                redirect_uri: "http://localhost/callback".to_owned(),
                scopes: vec!["openid".to_owned()],
                state: "state".to_owned(),
                code_challenge: pair.challenge,
                resource: None,
            },
        ) else {
            panic!("openid is rejected");
        };
        assert!(matches!(
            error,
            OAuthTransportError::Discovery(OAuthDiscoveryError::OpenIdUnsupported)
        ));
    }

    #[test]
    fn authorization_url_rejects_redirect_uri_ambiguity() {
        let raw = serde_json::from_str::<RawAuthorizationServerMetadata>(&metadata(
            "https://auth.example",
            &["none"],
        ))
        .expect("metadata JSON");
        let metadata = validate_authorization_server_metadata(
            "https://auth.example",
            raw,
            &OutboundPolicy::default(),
        )
        .expect("metadata valid");
        let pair = generate_pkce();
        let Err(error) = transport().authorization_url(
            &metadata,
            &AuthorizationRequest {
                client_id: "client".to_owned(),
                redirect_uri: "https://user@example.test/callback?next=evil".to_owned(),
                scopes: vec![],
                state: "state".to_owned(),
                code_challenge: pair.challenge,
                resource: None,
            },
        ) else {
            panic!("ambiguous redirect URI is rejected");
        };
        assert!(matches!(error, OAuthTransportError::InvalidRedirectUri));
    }

    #[tokio::test]
    async fn refresh_exchange_surfaces_invalid_grant_without_error_description() {
        let server = TestServer::start(vec![response(
            "400 Bad Request",
            r#"{"error":"invalid_grant","error_description":"refresh secret leaked"}"#,
        )])
        .await;
        let raw = serde_json::from_str::<RawAuthorizationServerMetadata>(&metadata(
            &server.issuer,
            &["none"],
        ))
        .expect("metadata JSON");
        let metadata =
            validate_authorization_server_metadata(&server.issuer, raw, &transport().policy)
                .expect("metadata valid");
        let error = transport()
            .refresh_access_token(
                &metadata,
                &RefreshTokenExchange {
                    refresh_token: "old-refresh".to_owned(),
                    resource: None,
                    client: OAuthClientAuthentication::Public {
                        client_id: "public-client".to_owned(),
                    },
                },
            )
            .await
            .err()
            .expect("invalid grant is surfaced");
        assert!(matches!(error, OAuthTransportError::InvalidGrant));
        assert!(!error.to_string().contains("refresh secret leaked"));
        let requests = server.finish().await;
        let body = requests[0].split("\r\n\r\n").nth(1).unwrap_or_default();
        assert!(body.contains("grant_type=refresh_token"));
        assert!(body.contains("refresh_token=old-refresh"));
    }

    #[test]
    fn oauth_response_bound_is_stricter_than_the_general_client() {
        let policy = OutboundPolicy {
            max_response_bytes: MAX_OAUTH_RESPONSE_BYTES * 100,
            ..OutboundPolicy::default()
        };
        let transport = OAuthHttpTransport::new(policy);
        assert_eq!(
            transport.policy.max_response_bytes,
            MAX_OAUTH_RESPONSE_BYTES
        );
        assert_eq!(transport.policy.max_redirects, 0);
    }
}
