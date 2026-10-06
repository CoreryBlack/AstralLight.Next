use ed25519_dalek::SigningKey;
use std::time::Duration;
use url::Url;

use super::{AccessToken, ClientConfig, SdkClient};

fn test_key() -> ed25519_dalek::VerifyingKey {
    SigningKey::from_bytes(&[42; 32]).verifying_key()
}

fn config(endpoint: &str, allow_loopback: bool) -> ClientConfig {
    ClientConfig::new(
        Url::parse(endpoint).unwrap(),
        Duration::from_secs(2),
        8 * 1024,
        "decision_key",
        test_key(),
    )
    .with_insecure_loopback_http(allow_loopback)
}

#[test]
fn cleartext_requires_explicit_literal_loopback() {
    assert!(SdkClient::new(config("http://localhost:9000", false)).is_err());
    assert!(SdkClient::new(config("http://localhost:9000", true)).is_err());
    assert!(SdkClient::new(config("http://127.0.0.1:9000", true)).is_ok());
    assert!(SdkClient::new(config("http://example.test:9000", true)).is_err());
}

#[test]
fn endpoint_credentials_are_rejected() {
    assert!(SdkClient::new(config("https://user:password@example.test", false)).is_err());
}

#[test]
fn access_token_debug_is_redacted() {
    let token = AccessToken::new("opaque-access-token").unwrap();
    assert_eq!(format!("{token:?}"), "AccessToken([REDACTED])");
}

#[test]
fn configuration_bounds_timeout_and_body_limit() {
    let mut invalid = config("https://example.test", false);
    invalid.timeout = Duration::from_secs(11);
    assert!(SdkClient::new(invalid).is_err());
    let mut too_large = config("https://example.test", false);
    too_large.max_response_bytes = 64 * 1024 + 1;
    assert!(SdkClient::new(too_large).is_err());
}
