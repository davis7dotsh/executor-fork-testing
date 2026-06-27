use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use executor::outbound::{
    AddressClass, HardenedHttpClient, OutboundError, OutboundPolicy, OutboundRequest, classify_ip,
    parse_url, redirect_target, validate_url,
};
use reqwest::{Method, header::HeaderValue};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use url::Url;

async fn read_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream
            .read(&mut buffer)
            .await
            .expect("test request is readable");
        assert!(read > 0, "test request ended before its headers");
        request.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(request).expect("test request headers are UTF-8")
}

#[test]
fn private_network_opt_in_never_allows_link_local_or_metadata_addresses() {
    let denied = OutboundPolicy::default();
    let allowed = OutboundPolicy {
        allow_private_networks: true,
        ..OutboundPolicy::default()
    };

    let private = Url::parse("http://10.20.30.40/spec.json").expect("private URL parses");
    assert!(matches!(
        validate_url(&private, &denied),
        Err(OutboundError::PrivateAddress)
    ));
    assert!(validate_url(&private, &allowed).is_ok());
    let tailscale = Url::parse("http://100.64.1.2/openapi.json").expect("tailnet URL parses");
    assert!(validate_url(&tailscale, &allowed).is_ok());

    for target in [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.170.2/credentials",
        "http://100.100.100.200/latest/meta-data/",
        "http://[fe80::1]/metadata",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://[fd20:ce::254]/computeMetadata/v1/",
        "http://[fd00:c1::a9fe:a9fe]/opc/v2/",
    ] {
        let target = Url::parse(target).expect("forbidden URL parses");
        assert!(matches!(
            validate_url(&target, &allowed),
            Err(OutboundError::ForbiddenAddress)
        ));
    }
}

#[test]
fn ipv4_mapped_ipv6_cannot_bypass_private_address_rules() {
    let mapped = IpAddr::V6(Ipv6Addr::from_bits(
        (0xffff_u128 << 32) | u32::from(Ipv4Addr::new(127, 0, 0, 1)) as u128,
    ));
    assert_eq!(classify_ip(mapped), AddressClass::Private);
}

#[test]
fn special_use_and_encapsulated_addresses_are_not_public() {
    let cases = [
        ("100.64.0.1", AddressClass::Private),
        ("100.100.100.200", AddressClass::Forbidden),
        ("192.0.2.1", AddressClass::Forbidden),
        ("198.18.0.1", AddressClass::Forbidden),
        ("203.0.113.1", AddressClass::Forbidden),
        ("224.0.0.1", AddressClass::Forbidden),
        ("2001:db8::1", AddressClass::Forbidden),
        ("2001:5::1", AddressClass::Forbidden),
        ("3fff:0fff:ffff::1", AddressClass::Forbidden),
        ("3fff:1000::1", AddressClass::Public),
        ("fc00::1", AddressClass::Private),
        ("fd00:ec2::254", AddressClass::Forbidden),
        ("fd20:ce::254", AddressClass::Forbidden),
        ("fd00:c1::a9fe:a9fe", AddressClass::Forbidden),
        ("2002:7f00:0001::", AddressClass::Private),
        ("2606:4700:4700::1111", AddressClass::Public),
        ("8.8.8.8", AddressClass::Public),
    ];
    for (address, expected) in cases {
        assert_eq!(
            classify_ip(address.parse().expect("test address parses")),
            expected,
            "unexpected class for {address}"
        );
    }
}

#[test]
fn urls_reject_credential_fragments_and_non_http_schemes() {
    let policy = OutboundPolicy::default();
    let cases = [
        (
            "https://user:secret@example.com/spec",
            "outbound_credentials_not_allowed",
        ),
        (
            "https://example.com/spec#secret",
            "outbound_fragment_not_allowed",
        ),
        ("file:///etc/passwd", "unsupported_outbound_scheme"),
    ];
    for (url, expected_code) in cases {
        let error = validate_url(&Url::parse(url).expect("test URL parses"), &policy)
            .expect_err("unsafe URL is denied");
        assert_eq!(error.code(), expected_code);
    }
}

#[test]
fn malformed_url_returns_a_stable_public_error() {
    let error =
        parse_url("not a URL", &OutboundPolicy::default()).expect_err("malformed URL is rejected");
    assert_eq!(error.code(), "invalid_outbound_url");
    assert_eq!(error.to_string(), "the outbound URL is invalid");
}

#[test]
fn redirects_resolve_relative_locations_and_deny_downgrades() {
    let policy = OutboundPolicy::default();
    let current = Url::parse("https://example.com/apis/openapi.json").expect("URL parses");
    let relative = HeaderValue::from_static("../v2/openapi.json?revision=2");
    let next = redirect_target(&current, Some(&relative), &policy).expect("redirect is valid");
    assert_eq!(
        next.as_str(),
        "https://example.com/v2/openapi.json?revision=2"
    );

    let downgrade = HeaderValue::from_static("http://example.com/openapi.json");
    assert!(matches!(
        redirect_target(&current, Some(&downgrade), &policy),
        Err(OutboundError::RedirectDowngrade)
    ));

    let secure_cross_origin = HeaderValue::from_static("https://cdn.example.net/openapi.json");
    assert_eq!(
        redirect_target(&current, Some(&secure_cross_origin), &policy)
            .expect("HTTPS redirects remain allowed")
            .as_str(),
        "https://cdn.example.net/openapi.json"
    );
}

#[test]
fn redirects_revalidate_literal_targets_at_every_hop() {
    let policy = OutboundPolicy::default();
    let current = Url::parse("https://example.com/openapi.json").expect("URL parses");
    let metadata = HeaderValue::from_static("https://169.254.169.254/latest/meta-data/");
    assert!(matches!(
        redirect_target(&current, Some(&metadata), &policy),
        Err(OutboundError::ForbiddenAddress)
    ));
}

#[tokio::test]
async fn cross_origin_redirects_drop_custom_credentials() {
    let destination = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("destination binds");
    let destination_address = destination
        .local_addr()
        .expect("destination has an address");
    let destination_task = tokio::spawn(async move {
        let (mut stream, _) = destination.accept().await.expect("destination accepts");
        let request = read_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
            .await
            .expect("destination responds");
        request
    });

    let redirector = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("redirector binds");
    let redirector_address = redirector.local_addr().expect("redirector has an address");
    let redirector_task = tokio::spawn(async move {
        let (mut stream, _) = redirector.accept().await.expect("redirector accepts");
        let _request = read_request(&mut stream).await;
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{destination_address}/final\r\nContent-Length: 0\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("redirector responds");
    });

    let policy = OutboundPolicy {
        allow_private_networks: true,
        ..OutboundPolicy::default()
    };
    let client = HardenedHttpClient::new(policy);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-api-key", HeaderValue::from_static("super-secret"));
    let response = client
        .fetch_spec(
            Url::parse(&format!("http://{redirector_address}/spec")).expect("redirect URL parses"),
            headers,
        )
        .await
        .expect("redirected fetch succeeds");
    assert_eq!(response.body, b"{}");
    assert_eq!(response.final_url.path(), "/final");
    redirector_task.await.expect("redirector task completes");
    let destination_request = destination_task
        .await
        .expect("destination task completes")
        .to_ascii_lowercase();
    assert!(!destination_request.contains("x-api-key"));
    assert!(!destination_request.contains("super-secret"));
}

#[tokio::test]
async fn custom_url_policy_rejects_a_multi_hop_target_before_request() {
    let blocked = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("blocked target binds");
    let blocked_address = blocked.local_addr().expect("blocked target has an address");

    let second = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("second redirector binds");
    let second_address = second
        .local_addr()
        .expect("second redirector has an address");
    let second_task = tokio::spawn(async move {
        let (mut stream, _) = second.accept().await.expect("second redirector accepts");
        let _request = read_request(&mut stream).await;
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{blocked_address}/blocked\r\nContent-Length: 0\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("second redirector responds");
    });

    let first = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("first redirector binds");
    let first_address = first.local_addr().expect("first redirector has an address");
    let first_task = tokio::spawn(async move {
        let (mut stream, _) = first.accept().await.expect("first redirector accepts");
        let _request = read_request(&mut stream).await;
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{second_address}/next\r\nContent-Length: 0\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("first redirector responds");
    });

    let client = HardenedHttpClient::new(OutboundPolicy {
        allow_private_networks: true,
        ..OutboundPolicy::default()
    });
    let error = match client
        .fetch_spec_with_url_policy(
            Url::parse(&format!("http://{first_address}/spec")).expect("spec URL parses"),
            reqwest::header::HeaderMap::new(),
            |candidate| {
                if candidate.port_or_known_default() == Some(blocked_address.port()) {
                    Err(OutboundError::RedirectDowngrade)
                } else {
                    Ok(())
                }
            },
        )
        .await
    {
        Err(error) => error,
        Ok(_) => panic!("the custom policy must reject the final redirect target"),
    };
    assert!(matches!(error, OutboundError::RedirectDowngrade));
    first_task.await.expect("first redirector completes");
    second_task.await.expect("second redirector completes");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), blocked.accept())
            .await
            .is_err(),
        "the rejected redirect target must receive no request"
    );
}

#[tokio::test]
async fn ordinary_execution_never_follows_a_credential_bearing_redirect() {
    let destination = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("redirect destination binds");
    let destination_address = destination
        .local_addr()
        .expect("redirect destination has an address");
    let redirector = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("redirector binds");
    let redirector_address = redirector.local_addr().expect("redirector has an address");
    let redirector_task = tokio::spawn(async move {
        let (mut stream, _) = redirector.accept().await.expect("redirector accepts");
        let request = read_request(&mut stream).await;
        assert!(request.to_ascii_lowercase().contains("x-api-key: secret"));
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{destination_address}/leak\r\nContent-Length: 0\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("redirector responds");
    });
    let client = HardenedHttpClient::new(OutboundPolicy {
        allow_private_networks: true,
        ..OutboundPolicy::default()
    });
    let mut request = OutboundRequest::new(
        Method::GET,
        Url::parse(&format!("http://{redirector_address}/start")).expect("redirector URL parses"),
    );
    request
        .headers
        .insert("x-api-key", HeaderValue::from_static("secret"));
    let response = client
        .execute(request)
        .await
        .expect("redirect response is returned without following it");
    assert_eq!(response.status, reqwest::StatusCode::FOUND);
    redirector_task.await.expect("redirector completes");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), destination.accept(),)
            .await
            .is_err(),
        "the credential-bearing redirect target must receive no request"
    );
}

#[tokio::test]
async fn response_size_cap_rejects_declared_oversize_before_returning_body() {
    let server = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("server binds");
    let address = server.local_addr().expect("server has an address");
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.expect("server accepts");
        let _request = read_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345")
            .await
            .expect("server responds");
    });
    let policy = OutboundPolicy {
        allow_private_networks: true,
        max_response_bytes: 4,
        ..OutboundPolicy::default()
    };
    let client = HardenedHttpClient::new(policy);
    let request = OutboundRequest::new(
        Method::GET,
        Url::parse(&format!("http://{address}/oversize")).expect("request URL parses"),
    );
    assert!(matches!(
        client.execute(request).await,
        Err(OutboundError::ResponseBodyTooLarge)
    ));
    server_task.await.expect("server task completes");
}

#[tokio::test]
async fn streaming_response_yields_before_connection_eof_and_keeps_byte_cap() {
    let server = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("server binds");
    let address = server.local_addr().expect("server has an address");
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.expect("server accepts");
        let _request = read_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfirst")
            .await
            .expect("first chunk writes");
        stream.flush().await.expect("first chunk flushes");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    });
    let policy = OutboundPolicy {
        allow_private_networks: true,
        max_response_bytes: 5,
        ..OutboundPolicy::default()
    };
    let client = HardenedHttpClient::new(policy);
    let request = OutboundRequest::new(
        Method::GET,
        Url::parse(&format!("http://{address}/stream")).expect("request URL parses"),
    );
    let mut response = client
        .execute_streaming(request)
        .await
        .expect("stream headers arrive");
    let first = tokio::time::timeout(std::time::Duration::from_millis(500), response.next_chunk())
        .await
        .expect("chunk arrives before EOF")
        .expect("chunk is valid")
        .expect("chunk exists");
    assert_eq!(first, b"first");
    server_task.abort();
}

#[tokio::test]
async fn long_lived_stream_uses_idle_timeout_instead_of_request_deadline() {
    let server = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("server binds");
    let address = server.local_addr().expect("server has an address");
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.expect("server accepts");
        let _request = read_request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\nfirst")
            .await
            .expect("headers write");
        stream.flush().await.expect("headers flush");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        stream.write_all(b"again").await.expect("event writes");
        stream.flush().await.expect("event flushes");
    });
    let policy = OutboundPolicy {
        allow_private_networks: true,
        request_timeout: std::time::Duration::from_millis(50),
        max_response_bytes: 5,
        ..OutboundPolicy::default()
    };
    let client = HardenedHttpClient::new(policy);
    let request = OutboundRequest::new(
        Method::GET,
        Url::parse(&format!("http://{address}/events")).expect("request URL parses"),
    );
    let mut response = client
        .execute_long_lived_streaming(request, std::time::Duration::from_millis(500))
        .await
        .expect("long-lived headers arrive");
    let first = response
        .next_chunk()
        .await
        .expect("idle deadline permits delayed event")
        .expect("event chunk exists");
    let second = response
        .next_chunk()
        .await
        .expect("cumulative lifetime bytes do not exhaust the per-chunk cap")
        .expect("second chunk exists");
    assert_eq!(first, b"first");
    assert_eq!(second, b"again");
    server_task.await.expect("server task completes");
}

#[tokio::test]
async fn trace_and_connect_are_rejected_before_network_work() {
    let policy = OutboundPolicy {
        allow_private_networks: true,
        ..OutboundPolicy::default()
    };
    let client = HardenedHttpClient::new(policy);
    let url = Url::parse("http://127.0.0.1:9/").expect("request URL parses");
    for method in [Method::TRACE, Method::CONNECT] {
        let error = match client
            .execute(OutboundRequest::new(method, url.clone()))
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("unsafe method is rejected"),
        };
        assert_eq!(error.code(), "forbidden_outbound_method");
    }
}
