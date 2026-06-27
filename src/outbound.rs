use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

#[cfg(test)]
use std::collections::HashMap;

use reqwest::{
    Method, StatusCode,
    header::{
        ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HeaderMap, HeaderName,
        LOCATION, REFERER, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
    },
    redirect::Policy,
};
use thiserror::Error;
use url::{Host, Url};

const DEFAULT_MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_REDIRECTS: usize = 3;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_URL_BYTES: usize = 16 * 1024;
const MAX_DNS_ADDRESSES: usize = 32;
const AWS_METADATA_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);
const GOOGLE_METADATA_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254);
const ORACLE_METADATA_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x00c1, 0, 0, 0, 0, 0xa9fe, 0xa9fe);

#[derive(Clone, Debug)]
pub struct OutboundPolicy {
    pub allow_private_networks: bool,
    pub require_https_or_loopback: bool,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_header_bytes: usize,
    pub max_redirects: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for OutboundPolicy {
    fn default() -> Self {
        Self {
            allow_private_networks: false,
            require_https_or_loopback: false,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressClass {
    Public,
    Private,
    Forbidden,
}

#[derive(Debug, Error)]
pub enum OutboundError {
    #[error("the outbound URL is invalid")]
    InvalidUrl,
    #[error("the outbound URL must use HTTP or HTTPS")]
    UnsupportedScheme,
    #[error("the outbound URL must not contain credentials")]
    CredentialsNotAllowed,
    #[error("the outbound URL must not contain a fragment")]
    FragmentNotAllowed,
    #[error("the outbound URL must contain a host")]
    MissingHost,
    #[error("plaintext outbound transport is allowed only for loopback addresses")]
    InsecureTransport,
    #[error("the outbound URL has no usable port")]
    MissingPort,
    #[error("the outbound host resolves to a private address")]
    PrivateAddress,
    #[error("the outbound host resolves to a forbidden address")]
    ForbiddenAddress,
    #[error("the outbound host could not be resolved")]
    DnsResolution,
    #[error("the outbound request contains a forbidden header")]
    ForbiddenHeader,
    #[error("the outbound request method is not allowed")]
    ForbiddenMethod,
    #[error("the outbound request headers are too large")]
    RequestHeadersTooLarge,
    #[error("the outbound request body is too large")]
    RequestBodyTooLarge,
    #[error("the outbound HTTP client could not be initialized")]
    ClientInitialization,
    #[error("the outbound request timed out")]
    Timeout,
    #[error("the outbound connection failed")]
    Connection,
    #[error("the outbound request failed")]
    Request,
    #[error("the upstream response headers are too large")]
    ResponseHeadersTooLarge,
    #[error("the upstream response body is too large")]
    ResponseBodyTooLarge,
    #[error("the upstream response uses an unsupported content encoding")]
    UnsupportedContentEncoding,
    #[error("the upstream redirect has no valid Location header")]
    InvalidRedirect,
    #[error("the upstream redirect would downgrade HTTPS to HTTP")]
    RedirectDowngrade,
    #[error("the upstream redirect looped")]
    RedirectLoop,
    #[error("the upstream response exceeded the redirect limit")]
    TooManyRedirects,
    #[error("the upstream server returned HTTP {status}")]
    UpstreamStatus { status: StatusCode },
}

impl OutboundError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidUrl => "invalid_outbound_url",
            Self::UnsupportedScheme => "unsupported_outbound_scheme",
            Self::CredentialsNotAllowed => "outbound_credentials_not_allowed",
            Self::FragmentNotAllowed => "outbound_fragment_not_allowed",
            Self::MissingHost | Self::MissingPort => "invalid_outbound_host",
            Self::InsecureTransport => "insecure_outbound_transport",
            Self::PrivateAddress => "private_network_denied",
            Self::ForbiddenAddress => "forbidden_network_target",
            Self::DnsResolution => "dns_resolution_failed",
            Self::ForbiddenHeader => "forbidden_outbound_header",
            Self::ForbiddenMethod => "forbidden_outbound_method",
            Self::RequestHeadersTooLarge => "outbound_headers_too_large",
            Self::RequestBodyTooLarge => "outbound_request_too_large",
            Self::ClientInitialization => "outbound_client_failed",
            Self::Timeout => "upstream_timeout",
            Self::Connection => "upstream_connection_failed",
            Self::Request => "upstream_request_failed",
            Self::ResponseHeadersTooLarge => "upstream_headers_too_large",
            Self::ResponseBodyTooLarge => "upstream_response_too_large",
            Self::UnsupportedContentEncoding => "unsupported_content_encoding",
            Self::InvalidRedirect => "invalid_upstream_redirect",
            Self::RedirectDowngrade => "redirect_downgrade_denied",
            Self::RedirectLoop => "upstream_redirect_loop",
            Self::TooManyRedirects => "too_many_upstream_redirects",
            Self::UpstreamStatus { .. } => "upstream_http_error",
        }
    }
}

#[derive(Clone)]
pub struct OutboundRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl OutboundRequest {
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: Vec::new(),
        }
    }
}

pub struct OutboundResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub final_url: Url,
}

pub struct OutboundStreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub final_url: Url,
    response: reqwest::Response,
    bytes_read: usize,
    max_response_bytes: usize,
    timeout: StreamTimeout,
    declared_response_too_large: bool,
}

enum StreamTimeout {
    Absolute(tokio::time::Instant),
    Idle(Duration),
}

impl OutboundStreamResponse {
    pub fn declared_response_too_large(&self) -> bool {
        self.declared_response_too_large
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, OutboundError> {
        let remaining = match self.timeout {
            StreamTimeout::Absolute(deadline) => deadline
                .checked_duration_since(tokio::time::Instant::now())
                .ok_or(OutboundError::Timeout)?,
            StreamTimeout::Idle(timeout) => timeout,
        };
        let Some(chunk) = tokio::time::timeout(remaining, self.response.chunk())
            .await
            .map_err(|_| OutboundError::Timeout)?
            .map_err(map_reqwest_error)?
        else {
            return Ok(None);
        };
        match self.timeout {
            StreamTimeout::Absolute(_) => {
                self.bytes_read = self
                    .bytes_read
                    .checked_add(chunk.len())
                    .ok_or(OutboundError::ResponseBodyTooLarge)?;
                if self.bytes_read > self.max_response_bytes {
                    return Err(OutboundError::ResponseBodyTooLarge);
                }
            }
            StreamTimeout::Idle(_) if chunk.len() > self.max_response_bytes => {
                return Err(OutboundError::ResponseBodyTooLarge);
            }
            StreamTimeout::Idle(_) => {}
        }
        Ok(Some(chunk.to_vec()))
    }
}

#[derive(Clone, Debug)]
pub struct HardenedHttpClient {
    policy: OutboundPolicy,
    #[cfg(test)]
    test_dns_resolutions: HashMap<String, Vec<IpAddr>>,
}

pub fn parse_url(input: &str, policy: &OutboundPolicy) -> Result<Url, OutboundError> {
    let url = Url::parse(input).map_err(|_| OutboundError::InvalidUrl)?;
    validate_url(&url, policy)?;
    Ok(url)
}

impl HardenedHttpClient {
    pub fn new(policy: OutboundPolicy) -> Self {
        Self {
            policy,
            #[cfg(test)]
            test_dns_resolutions: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_dns_resolution(
        mut self,
        hostname: impl Into<String>,
        addresses: Vec<IpAddr>,
    ) -> Self {
        self.test_dns_resolutions
            .insert(hostname.into().to_ascii_lowercase(), addresses);
        self
    }

    pub async fn execute(
        &self,
        request: OutboundRequest,
    ) -> Result<OutboundResponse, OutboundError> {
        validate_request(&request, &self.policy)?;
        tokio::time::timeout(self.policy.request_timeout, self.execute_once(request))
            .await
            .map_err(|_| OutboundError::Timeout)?
    }

    pub async fn execute_streaming(
        &self,
        request: OutboundRequest,
    ) -> Result<OutboundStreamResponse, OutboundError> {
        validate_request(&request, &self.policy)?;
        tokio::time::timeout(
            self.policy.request_timeout,
            self.execute_streaming_once(request, false, false),
        )
        .await
        .map_err(|_| OutboundError::Timeout)?
    }

    pub async fn execute_streaming_headers_first(
        &self,
        request: OutboundRequest,
    ) -> Result<OutboundStreamResponse, OutboundError> {
        validate_request(&request, &self.policy)?;
        tokio::time::timeout(
            self.policy.request_timeout,
            self.execute_streaming_once(request, false, true),
        )
        .await
        .map_err(|_| OutboundError::Timeout)?
    }

    pub async fn execute_long_lived_streaming(
        &self,
        request: OutboundRequest,
        idle_timeout: Duration,
    ) -> Result<OutboundStreamResponse, OutboundError> {
        validate_request(&request, &self.policy)?;
        tokio::time::timeout(
            self.policy.request_timeout,
            self.execute_streaming_once(request, true, true),
        )
        .await
        .map_err(|_| OutboundError::Timeout)?
        .map(|mut response| {
            response.timeout = StreamTimeout::Idle(idle_timeout);
            response
        })
    }

    pub async fn fetch_spec(
        &self,
        url: Url,
        headers: HeaderMap,
    ) -> Result<OutboundResponse, OutboundError> {
        self.fetch_spec_with_url_policy(url, headers, |_| Ok(()))
            .await
    }

    pub async fn fetch_spec_with_url_policy<F>(
        &self,
        url: Url,
        headers: HeaderMap,
        validate_url_policy: F,
    ) -> Result<OutboundResponse, OutboundError>
    where
        F: Fn(&Url) -> Result<(), OutboundError>,
    {
        tokio::time::timeout(
            self.policy.request_timeout,
            self.fetch_spec_with_redirects(url, headers, &validate_url_policy),
        )
        .await
        .map_err(|_| OutboundError::Timeout)?
    }

    async fn fetch_spec_with_redirects(
        &self,
        url: Url,
        headers: HeaderMap,
        validate_url_policy: &impl Fn(&Url) -> Result<(), OutboundError>,
    ) -> Result<OutboundResponse, OutboundError> {
        validate_headers(&headers, self.policy.max_header_bytes)?;
        let mut current = url;
        let mut headers = headers;
        let mut visited = HashSet::new();

        for redirect_count in 0..=self.policy.max_redirects {
            validate_url_policy(&current)?;
            validate_url(&current, &self.policy)?;
            if !visited.insert(current.as_str().to_owned()) {
                return Err(OutboundError::RedirectLoop);
            }

            let response = self
                .execute_once(OutboundRequest {
                    method: Method::GET,
                    url: current.clone(),
                    headers: headers.clone(),
                    body: Vec::new(),
                })
                .await?;
            if !is_redirect(response.status) {
                if response.status.is_success() {
                    return Ok(response);
                }
                return Err(OutboundError::UpstreamStatus {
                    status: response.status,
                });
            }
            if redirect_count == self.policy.max_redirects {
                return Err(OutboundError::TooManyRedirects);
            }

            let unchecked_next = joined_redirect_target(&current, response.headers.get(LOCATION))?;
            validate_url_policy(&unchecked_next)?;
            let next = redirect_target(&current, response.headers.get(LOCATION), &self.policy)?;
            if !same_origin(&current, &next) {
                strip_cross_origin_headers(&mut headers);
            }
            current = next;
        }

        Err(OutboundError::TooManyRedirects)
    }

    async fn execute_once(
        &self,
        request: OutboundRequest,
    ) -> Result<OutboundResponse, OutboundError> {
        let mut response = self.execute_streaming_once(request, false, false).await?;
        let mut body = Vec::new();
        while let Some(chunk) = response.next_chunk().await? {
            body.extend_from_slice(&chunk);
        }
        Ok(OutboundResponse {
            status: response.status,
            headers: response.headers,
            body,
            final_url: response.final_url,
        })
    }

    async fn execute_streaming_once(
        &self,
        mut request: OutboundRequest,
        long_lived: bool,
        allow_declared_oversize: bool,
    ) -> Result<OutboundStreamResponse, OutboundError> {
        validate_request(&request, &self.policy)?;
        let resolved = resolve_target(
            &request.url,
            &self.policy,
            #[cfg(test)]
            &self.test_dns_resolutions,
        )
        .await?;
        if !request.headers.contains_key(ACCEPT_ENCODING) {
            request.headers.insert(
                ACCEPT_ENCODING,
                "identity".parse().expect("static header is valid"),
            );
        }
        validate_headers(&request.headers, self.policy.max_header_bytes)?;

        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .referer(false)
            .connect_timeout(self.policy.connect_timeout)
            .pool_max_idle_per_host(0);
        if !long_lived {
            builder = builder.timeout(self.policy.request_timeout);
        }
        if let Some(hostname) = resolved.hostname.as_deref() {
            builder = builder.resolve_to_addrs(hostname, &resolved.addresses);
        }
        let client = builder
            .build()
            .map_err(|_| OutboundError::ClientInitialization)?;
        let response = client
            .request(request.method, request.url.clone())
            .headers(request.headers)
            .body(request.body)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let declared_response_too_large =
            match validate_response_headers(response.headers(), &self.policy) {
                Err(OutboundError::ResponseBodyTooLarge) if allow_declared_oversize => true,
                Err(error) => return Err(error),
                Ok(()) => false,
            };
        Ok(OutboundStreamResponse {
            status: response.status(),
            headers: response.headers().clone(),
            final_url: request.url,
            response,
            bytes_read: 0,
            max_response_bytes: self.policy.max_response_bytes,
            timeout: StreamTimeout::Absolute(
                tokio::time::Instant::now() + self.policy.request_timeout,
            ),
            declared_response_too_large,
        })
    }
}

struct ResolvedTarget {
    hostname: Option<String>,
    addresses: Vec<SocketAddr>,
}

async fn resolve_target(
    url: &Url,
    policy: &OutboundPolicy,
    #[cfg(test)] test_dns_resolutions: &HashMap<String, Vec<IpAddr>>,
) -> Result<ResolvedTarget, OutboundError> {
    validate_url(url, policy)?;
    let port = url
        .port_or_known_default()
        .ok_or(OutboundError::MissingPort)?;
    match url.host().ok_or(OutboundError::MissingHost)? {
        Host::Ipv4(address) => {
            validate_address(IpAddr::V4(address), policy)?;
            let resolved = ResolvedTarget {
                hostname: None,
                addresses: vec![SocketAddr::new(IpAddr::V4(address), port)],
            };
            validate_resolved_transport(url, &resolved.addresses, policy)?;
            Ok(resolved)
        }
        Host::Ipv6(address) => {
            let address = canonical_ip(IpAddr::V6(address));
            validate_address(address, policy)?;
            let resolved = ResolvedTarget {
                hostname: None,
                addresses: vec![SocketAddr::new(address, port)],
            };
            validate_resolved_transport(url, &resolved.addresses, policy)?;
            Ok(resolved)
        }
        Host::Domain(hostname) => {
            #[cfg(test)]
            if let Some(addresses) = test_dns_resolutions.get(hostname) {
                return resolved_domain_target(
                    url,
                    hostname,
                    port,
                    addresses
                        .iter()
                        .map(|address| SocketAddr::new(*address, port))
                        .collect(),
                    policy,
                );
            }
            let addresses = tokio::time::timeout(
                policy.connect_timeout,
                tokio::net::lookup_host((hostname, port)),
            )
            .await
            .map_err(|_| OutboundError::Timeout)?
            .map_err(|_| OutboundError::DnsResolution)?
            .map(|address| SocketAddr::new(canonical_ip(address.ip()), address.port()))
            .take(MAX_DNS_ADDRESSES + 1)
            .collect::<Vec<_>>();
            resolved_domain_target(url, hostname, port, addresses, policy)
        }
    }
}

fn resolved_domain_target(
    url: &Url,
    hostname: &str,
    port: u16,
    addresses: Vec<SocketAddr>,
    policy: &OutboundPolicy,
) -> Result<ResolvedTarget, OutboundError> {
    let mut addresses = addresses
        .into_iter()
        .map(|address| SocketAddr::new(canonical_ip(address.ip()), port))
        .take(MAX_DNS_ADDRESSES + 1)
        .collect::<Vec<_>>();
    if addresses.len() > MAX_DNS_ADDRESSES {
        return Err(OutboundError::DnsResolution);
    }
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(OutboundError::DnsResolution);
    }
    for address in &addresses {
        validate_address(address.ip(), policy)?;
    }
    validate_resolved_transport(url, &addresses, policy)?;
    Ok(ResolvedTarget {
        hostname: Some(hostname.to_owned()),
        addresses,
    })
}

fn validate_resolved_transport(
    url: &Url,
    addresses: &[SocketAddr],
    policy: &OutboundPolicy,
) -> Result<(), OutboundError> {
    if !policy.require_https_or_loopback || url.scheme() == "https" {
        return Ok(());
    }
    if url.scheme() == "http"
        && addresses
            .iter()
            .all(|address| canonical_ip(address.ip()).is_loopback())
    {
        Ok(())
    } else {
        Err(OutboundError::InsecureTransport)
    }
}

pub fn validate_url(url: &Url, policy: &OutboundPolicy) -> Result<(), OutboundError> {
    if url.as_str().len() > MAX_URL_BYTES {
        return Err(OutboundError::InvalidUrl);
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(OutboundError::UnsupportedScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OutboundError::CredentialsNotAllowed);
    }
    if url.fragment().is_some() {
        return Err(OutboundError::FragmentNotAllowed);
    }
    let host = url.host().ok_or(OutboundError::MissingHost)?;
    if url.port_or_known_default().is_none_or(|port| port == 0) {
        return Err(OutboundError::MissingPort);
    }
    match host {
        Host::Ipv4(address) => validate_address(IpAddr::V4(address), policy),
        Host::Ipv6(address) => validate_address(canonical_ip(IpAddr::V6(address)), policy),
        Host::Domain(_) => Ok(()),
    }
}

pub fn classify_ip(address: IpAddr) -> AddressClass {
    match canonical_ip(address) {
        IpAddr::V4(address) => classify_ipv4(address),
        IpAddr::V6(address) => classify_ipv6(address),
    }
}

fn classify_ipv4(address: Ipv4Addr) -> AddressClass {
    let octets = address.octets();
    if octets == [100, 100, 100, 200] {
        return AddressClass::Forbidden;
    }
    if octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
    {
        return AddressClass::Private;
    }
    if octets[0] == 0
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 224
    {
        AddressClass::Forbidden
    } else {
        AddressClass::Public
    }
}

fn classify_ipv6(address: Ipv6Addr) -> AddressClass {
    if matches!(
        address,
        AWS_METADATA_IPV6 | GOOGLE_METADATA_IPV6 | ORACLE_METADATA_IPV6
    ) {
        return AddressClass::Forbidden;
    }
    if address.is_loopback() || (address.segments()[0] & 0xfe00) == 0xfc00 {
        return AddressClass::Private;
    }
    let segments = address.segments();
    let globally_routable_prefix = (segments[0] & 0xe000) == 0x2000;
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let ietf_protocol_assignments = segments[0] == 0x2001 && segments[1] <= 0x01ff;
    let benchmarking = segments[0] == 0x2001 && segments[1] == 0x0002;
    let teredo = segments[0] == 0x2001 && segments[1] == 0;
    let orchid = segments[0] == 0x2001 && matches!(segments[1] & 0xfff0, 0x0010 | 0x0020);
    let documentation_v2 = segments[0] == 0x3fff && (segments[1] & 0xf000) == 0;
    let discard_only = segments[0] == 0x0100 && segments[1..4] == [0, 0, 0];
    let translation_private = segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 1;
    let link_local = (segments[0] & 0xffc0) == 0xfe80;
    let site_local = (segments[0] & 0xffc0) == 0xfec0;
    if !globally_routable_prefix
        || documentation
        || ietf_protocol_assignments
        || benchmarking
        || teredo
        || orchid
        || documentation_v2
        || discard_only
        || translation_private
        || link_local
        || site_local
        || address.is_multicast()
        || address.is_unspecified()
    {
        AddressClass::Forbidden
    } else if segments[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            segments[1] as u8,
            (segments[2] >> 8) as u8,
            segments[2] as u8,
        );
        classify_ipv4(embedded)
    } else {
        AddressClass::Public
    }
}

fn validate_address(address: IpAddr, policy: &OutboundPolicy) -> Result<(), OutboundError> {
    match classify_ip(address) {
        AddressClass::Public => Ok(()),
        AddressClass::Private if policy.allow_private_networks => Ok(()),
        AddressClass::Private => Err(OutboundError::PrivateAddress),
        AddressClass::Forbidden => Err(OutboundError::ForbiddenAddress),
    }
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

pub fn redirect_target(
    current: &Url,
    location: Option<&reqwest::header::HeaderValue>,
    policy: &OutboundPolicy,
) -> Result<Url, OutboundError> {
    let next = joined_redirect_target(current, location)?;
    validate_url(&next, policy)?;
    if current.scheme() == "https" && next.scheme() != "https" {
        return Err(OutboundError::RedirectDowngrade);
    }
    Ok(next)
}

fn joined_redirect_target(
    current: &Url,
    location: Option<&reqwest::header::HeaderValue>,
) -> Result<Url, OutboundError> {
    let location = location
        .and_then(|value| value.to_str().ok())
        .ok_or(OutboundError::InvalidRedirect)?;
    current
        .join(location)
        .map_err(|_| OutboundError::InvalidRedirect)
}

fn validate_request(
    request: &OutboundRequest,
    policy: &OutboundPolicy,
) -> Result<(), OutboundError> {
    validate_url(&request.url, policy)?;
    if matches!(request.method, Method::TRACE | Method::CONNECT) {
        return Err(OutboundError::ForbiddenMethod);
    }
    validate_headers(&request.headers, policy.max_header_bytes)?;
    if request.body.len() > policy.max_request_bytes {
        return Err(OutboundError::RequestBodyTooLarge);
    }
    Ok(())
}

fn validate_headers(headers: &HeaderMap, max_bytes: usize) -> Result<(), OutboundError> {
    let mut total = 0_usize;
    for (name, value) in headers {
        if forbidden_request_header(name) {
            return Err(OutboundError::ForbiddenHeader);
        }
        total = total
            .checked_add(name.as_str().len())
            .and_then(|length| length.checked_add(value.as_bytes().len()))
            .ok_or(OutboundError::RequestHeadersTooLarge)?;
        if total > max_bytes {
            return Err(OutboundError::RequestHeadersTooLarge);
        }
    }
    Ok(())
}

fn forbidden_request_header(name: &HeaderName) -> bool {
    name == CONNECTION
        || name == CONTENT_LENGTH
        || name == TE
        || name == TRAILER
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || name == REFERER
        || name == "host"
        || name == "keep-alive"
        || name.as_str().starts_with("proxy-")
}

fn validate_response_headers(
    headers: &HeaderMap,
    policy: &OutboundPolicy,
) -> Result<(), OutboundError> {
    let mut total = 0_usize;
    for (name, value) in headers {
        total = total
            .checked_add(name.as_str().len())
            .and_then(|length| length.checked_add(value.as_bytes().len()))
            .ok_or(OutboundError::ResponseHeadersTooLarge)?;
        if total > policy.max_header_bytes {
            return Err(OutboundError::ResponseHeadersTooLarge);
        }
    }
    for value in headers.get_all(CONTENT_ENCODING) {
        if !value.as_bytes().eq_ignore_ascii_case(b"identity") {
            return Err(OutboundError::UnsupportedContentEncoding);
        }
    }
    let mut declared_length = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let length = value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or(OutboundError::ResponseHeadersTooLarge)?;
        if declared_length.is_some_and(|previous| previous != length) {
            return Err(OutboundError::ResponseHeadersTooLarge);
        }
        if length > policy.max_response_bytes as u64 {
            return Err(OutboundError::ResponseBodyTooLarge);
        }
        declared_length = Some(length);
    }
    Ok(())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn strip_cross_origin_headers(headers: &mut HeaderMap) {
    headers.clear();
}

fn is_redirect(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    )
}

fn map_reqwest_error(error: reqwest::Error) -> OutboundError {
    if error.is_timeout() {
        OutboundError::Timeout
    } else if error.is_connect() {
        OutboundError::Connection
    } else {
        OutboundError::Request
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_override_still_runs_resolved_transport_policy() {
        let client = HardenedHttpClient::new(OutboundPolicy {
            allow_private_networks: true,
            require_https_or_loopback: true,
            ..OutboundPolicy::default()
        })
        .with_test_dns_resolution(
            "poison.localhost",
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        );
        let request = OutboundRequest::new(
            Method::GET,
            Url::parse("http://poison.localhost:8080/spec").expect("test URL parses"),
        );

        assert!(matches!(
            client.execute(request).await,
            Err(OutboundError::InsecureTransport)
        ));
    }

    #[test]
    fn resolved_plaintext_transport_requires_every_pinned_address_to_be_loopback() {
        let policy = OutboundPolicy {
            allow_private_networks: true,
            require_https_or_loopback: true,
            ..OutboundPolicy::default()
        };
        let http = Url::parse("http://localhost:8080/spec").expect("HTTP URL parses");
        let loopback = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
        ];
        assert!(validate_resolved_transport(&http, &loopback, &policy).is_ok());

        for poisoned in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
        ] {
            assert!(matches!(
                validate_resolved_transport(&http, &[poisoned], &policy),
                Err(OutboundError::InsecureTransport)
            ));
        }

        let https = Url::parse("https://api.example.test/spec").expect("HTTPS URL parses");
        assert!(
            validate_resolved_transport(
                &https,
                &[SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443,)],
                &policy,
            )
            .is_ok()
        );
    }
}
