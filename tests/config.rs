use std::net::SocketAddr;

use executor::{AppConfig, ConfigError};

#[test]
fn public_origins_are_canonicalized_and_reject_extra_components() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let config = AppConfig::new(directory.path().to_path_buf())
        .with_origin("HTTPS://Example.COM:443/")
        .expect("origin should be valid");
    assert_eq!(config.public_origin(), "https://example.com");

    for invalid in [
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com?query=1",
        "https://example.com#fragment",
    ] {
        assert!(matches!(
            AppConfig::new(directory.path().to_path_buf()).with_origin(invalid),
            Err(ConfigError::PublicOriginHasExtraComponents)
        ));
    }
    assert!(matches!(
        AppConfig::new(directory.path().to_path_buf()).with_origin("ftp://example.com"),
        Err(ConfigError::UnsupportedPublicOriginScheme)
    ));
}

#[test]
fn plaintext_http_requires_an_explicit_unsafe_non_loopback_override() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let http = AppConfig::new(directory.path().to_path_buf());
    let loopback: SocketAddr = "127.0.0.1:4788".parse().expect("address should parse");
    let public: SocketAddr = "0.0.0.0:4788".parse().expect("address should parse");
    assert!(http.validate_bind(loopback, false).is_ok());
    assert!(matches!(
        http.validate_bind(public, false),
        Err(ConfigError::UnsafePlaintextNonLoopbackBind(_))
    ));
    assert!(http.validate_bind(public, true).is_ok());

    let https = AppConfig::new(directory.path().to_path_buf())
        .with_origin("https://executor.example.com")
        .expect("HTTPS origin should be valid");
    assert!(https.validate_bind(public, false).is_ok());
}

#[test]
fn default_public_origin_tracks_the_actual_bind_address() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let loopback: SocketAddr = "127.0.0.1:5888".parse().expect("address should parse");
    let config = AppConfig::new(directory.path().to_path_buf())
        .with_default_origin_for_bind(loopback)
        .expect("loopback bind should produce an origin");
    assert_eq!(config.public_origin(), "http://127.0.0.1:5888");

    let unspecified: SocketAddr = "0.0.0.0:5888".parse().expect("address should parse");
    assert!(matches!(
        AppConfig::new(directory.path().to_path_buf()).with_default_origin_for_bind(unspecified),
        Err(ConfigError::PublicOriginRequiredForUnspecifiedBind(_))
    ));

    let explicit = AppConfig::new(directory.path().to_path_buf())
        .with_origin("https://executor.example.com")
        .expect("explicit public origin should remain supported");
    assert_eq!(explicit.public_origin(), "https://executor.example.com");
}
