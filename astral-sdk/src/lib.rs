//! HTTP client for the AstralLight integration authorization endpoint.

use astral_sdk_contracts::{
    ApiResponseEnvelope, AuthorizationRequest, ContractError, SignedAuthorizationDecision,
    SignedAuthorizationRequest, VerifiedAuthorizationDecision, AUTHORIZATION_PATH,
    MAX_REQUEST_BODY_BYTES, MAX_RESPONSE_BODY_BYTES,
};
use ed25519_dalek::VerifyingKey;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::{Client, StatusCode};
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use url::Url;

#[cfg(test)]
#[path = "../tests.rs"]
mod tests;

const MAX_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(10);

/// Secret header value used as the Gateway-validated bearer access token.
/// Its Debug representation is always redacted.
pub struct AccessToken(zeroize::Zeroizing<String>);

impl AccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, SdkError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 4096
            || !value.is_ascii()
            || value.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f)
        {
            return Err(SdkError::Configuration("invalid bearer access token"));
        }
        Ok(Self(zeroize::Zeroizing::new(value)))
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken([REDACTED])")
    }
}

impl AccessToken {
    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Error)]
pub enum SdkError {
    #[error("invalid SDK configuration: {0}")]
    Configuration(&'static str),
    #[error("request contract invalid: {0}")]
    Contract(#[from] ContractError),
    #[error("HTTP transport failed")]
    Transport,
    #[error("response body exceeds the configured size limit")]
    ResponseTooLarge,
    #[error("server returned HTTP status {0}")]
    HttpStatus(StatusCode),
    #[error("platform API response envelope is not a success")]
    PlatformFailure,
    #[error("platform response is malformed")]
    ResponseFormat,
    #[error("decision is not an allow")]
    NotAllowed,
}

impl fmt::Debug for SdkClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SdkClient([REDACTED])")
    }
}

pub struct SdkClient {
    endpoint: Url,
    http: Client,
    decision_key_id: String,
    decision_key: VerifyingKey,
    max_response_bytes: usize,
}

pub struct ClientConfig {
    pub endpoint: Url,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    /// Opt in to HTTP for literal loopback endpoints only. Defaults to false via `new`.
    pub allow_insecure_loopback: bool,
    pub decision_key_id: String,
    pub decision_public_key: VerifyingKey,
}

impl ClientConfig {
    pub fn new(
        endpoint: Url,
        timeout: Duration,
        max_response_bytes: usize,
        decision_key_id: impl Into<String>,
        decision_public_key: VerifyingKey,
    ) -> Self {
        Self {
            endpoint,
            timeout,
            max_response_bytes,
            allow_insecure_loopback: false,
            decision_key_id: decision_key_id.into(),
            decision_public_key,
        }
    }

    pub fn with_insecure_loopback_http(mut self, enabled: bool) -> Self {
        self.allow_insecure_loopback = enabled;
        self
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("endpoint", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .field("decision_key_id", &self.decision_key_id)
            .field("decision_public_key", &"[REDACTED]")
            .finish()
    }
}

impl SdkClient {
    pub fn new(config: ClientConfig) -> Result<Self, SdkError> {
        if config.endpoint.cannot_be_a_base()
            || !matches!(config.endpoint.scheme(), "http" | "https")
            || config.endpoint.query().is_some()
            || config.endpoint.fragment().is_some()
            || !config.endpoint.username().is_empty()
            || config.endpoint.password().is_some()
        {
            return Err(SdkError::Configuration(
                "endpoint must be an HTTP(S) base URL without userinfo",
            ));
        }
        if config.endpoint.scheme() == "http"
            && (!config.allow_insecure_loopback || !is_literal_loopback(&config.endpoint))
        {
            return Err(SdkError::Configuration(
                "cleartext HTTP requires explicit opt-in and a localhost/loopback IP literal",
            ));
        }
        if config.timeout.is_zero() || config.timeout > MAX_AUTHORIZATION_TIMEOUT {
            return Err(SdkError::Configuration("timeout must be within 1ms..=10s"));
        }
        if config.max_response_bytes == 0 || config.max_response_bytes > MAX_RESPONSE_BODY_BYTES {
            return Err(SdkError::Configuration(
                "response limit must be within 1..=64KiB",
            ));
        }
        if astral_sdk_contracts::identifier(&config.decision_key_id).is_err()
            || config.decision_key_id.len() > 64
        {
            return Err(SdkError::Configuration("invalid decision key id"));
        }
        let http = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.timeout.min(Duration::from_secs(3)))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never());
        let http = if is_literal_loopback(&config.endpoint) {
            http.no_proxy()
        } else {
            http
        };
        let http = http.build().map_err(|_| SdkError::Transport)?;
        Ok(Self {
            endpoint: config.endpoint,
            http,
            decision_key_id: config.decision_key_id,
            decision_key: config.decision_public_key,
            max_response_bytes: config.max_response_bytes,
        })
    }

    pub async fn authorize(
        &self,
        signed: &SignedAuthorizationRequest,
        access_token: &AccessToken,
    ) -> Result<VerifiedAuthorizationDecision, SdkError> {
        let request_now = unix_millis()?;
        signed.request.validate_at(request_now)?;
        let body = serde_json::to_vec(signed).map_err(|_| SdkError::ResponseFormat)?;
        if body.len() > MAX_REQUEST_BODY_BYTES {
            return Err(SdkError::Contract(ContractError::PayloadTooLarge));
        }
        let url = self
            .endpoint
            .join(AUTHORIZATION_PATH)
            .map_err(|_| SdkError::Configuration("invalid endpoint path"))?;
        let response = self
            .http
            .post(url)
            .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
            .bearer_auth(access_token.expose())
            .body(body)
            .send()
            .await
            .map_err(|_| SdkError::Transport)?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(SdkError::HttpStatus(status));
        }
        let bytes = read_bounded_response(response, self.max_response_bytes).await?;
        let envelope: ApiResponseEnvelope<SignedAuthorizationDecision> =
            serde_json::from_slice(&bytes).map_err(|_| SdkError::ResponseFormat)?;
        if !envelope.success || envelope.code != 200 {
            return Err(SdkError::PlatformFailure);
        }
        if envelope.trace_id.as_deref() != Some(signed.request.request_id.as_str()) {
            return Err(SdkError::PlatformFailure);
        }
        let signed_decision = envelope.data.ok_or(SdkError::PlatformFailure)?;
        // Re-read the system clock after all network and decode work. A stale
        // pre-request timestamp can never extend an ALLOW past its signed expiry.
        signed_decision
            .verify(
                &self.decision_key,
                &self.decision_key_id,
                &signed.request,
                unix_millis()?,
            )
            .map_err(SdkError::Contract)
    }

    /// Consume this non-Clone proof object at the local current time. This is
    /// not a cross-process replay ledger or a business commit acknowledgment.
    pub fn consume_allow(
        &self,
        verified: VerifiedAuthorizationDecision,
        request: &AuthorizationRequest,
    ) -> Result<(), SdkError> {
        verified
            .require_allow_current(request)
            .map_err(|error| match error {
                ContractError::DecisionNotAllowed => SdkError::NotAllowed,
                other => SdkError::Contract(other),
            })?;
        Ok(())
    }
}

fn is_literal_loopback(endpoint: &Url) -> bool {
    endpoint
        .host()
        .and_then(|host| match host {
            url::Host::Ipv4(address) => Some(IpAddr::V4(address).is_loopback()),
            url::Host::Ipv6(address) => Some(IpAddr::V6(address).is_loopback()),
            url::Host::Domain(_) => None,
        })
        .unwrap_or(false)
}

fn unix_millis() -> Result<u64, SdkError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SdkError::Configuration("system clock precedes Unix epoch"))?;
    u64::try_from(duration.as_millis())
        .map_err(|_| SdkError::Configuration("system clock is outside supported range"))
}

async fn read_bounded_response(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, SdkError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
        || response
            .headers()
            .get(reqwest::header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes() != b"identity")
    {
        return Err(SdkError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| SdkError::Transport)? {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(SdkError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
