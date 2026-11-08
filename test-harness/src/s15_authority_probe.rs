//! Read-only S15 adapter to the production `astral-authority` mTLS owner.
//!
//! Calls the real, cryptographically verifying AuthorityClient and its
//! linearizable `read_fence` API. It proves only the returned frontier, current
//! scope certificate and authority read-gate observation. It does not evaluate
//! policy, issue a proof, mutate state, or claim an ALLOW.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use astral_authority::client::{AuthorityClient, AuthorityClientConfig};
use astral_types::{
    AuthorityProtocolScope, AuthorityScopePublicationCertificate, AuthorizationAuthorityScope,
    AuthorizationDomainScope,
};
use serde::Serialize;

pub const ENV_AUTHORITY_URL: &str = "ASTRAL_S15_AUTHORITY_URL";
pub const ENV_AUTHORITY_CA_FILE: &str = "ASTRAL_S15_AUTHORITY_CA_FILE";
pub const ENV_AUTHORITY_CLIENT_IDENTITY_FILE: &str = "ASTRAL_S15_AUTHORITY_CLIENT_IDENTITY_FILE";
pub const ENV_AUTHORITY_SERVICE_ID: &str = "ASTRAL_S15_AUTHORITY_SERVICE_ID";
pub const ENV_AUTHORITY_GENESIS_PIN: &str = "ASTRAL_S15_AUTHORITY_GENESIS_TRUST_ROOT_DIGEST";
pub const ENV_AUTHORITY_TENANT_ID: &str = "ASTRAL_S15_AUTHORITY_TENANT_ID";
pub const ENV_AUTHORITY_CARD_ID: &str = "ASTRAL_S15_AUTHORITY_CARD_ID";
pub const ENV_AUTHORITY_USER_ID: &str = "ASTRAL_S15_AUTHORITY_USER_ID";
pub const ENV_AUTHORITY_DOMAIN_ID: &str = "ASTRAL_S15_AUTHORITY_DOMAIN_ID";
pub const AUTHORITY_ATTESTATION_PATH: &str = astral_types::AUTHORITY_PATH_ATTESTATION_STARTUP;
pub const AUTHORITY_FENCE_READ_PATH: &str = astral_types::AUTHORITY_PATH_FENCE_CURRENT;
pub const AUTHORITY_READ_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CERTIFICATE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorityConfigReport {
    pub missing: Vec<String>,
    pub invalid: Vec<String>,
}

impl fmt::Display for AuthorityConfigReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let missing = if self.missing.is_empty() {
            "-"
        } else {
            &self.missing.join(",")
        };
        let invalid = if self.invalid.is_empty() {
            "-"
        } else {
            &self.invalid.join(",")
        };
        write!(formatter, "missing={missing}; invalid={invalid}")
    }
}

pub struct S15AuthorityConfig {
    pub base_url: String,
    pub ca_file: PathBuf,
    pub client_identity_file: PathBuf,
    pub service_id: String,
    pub pinned_genesis_digest: String,
    pub scope: AuthorityProtocolScope,
}

impl fmt::Debug for S15AuthorityConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S15AuthorityConfig")
            .field("base_url", &"[protected-origin]")
            .field("ca_file", &"[protected-path]")
            .field("client_identity_file", &"[protected-path]")
            .field("service_id", &"[protected-identity]")
            .field("pinned_genesis_digest", &"[pinned]")
            .field("scope", &"[protected-scope]")
            .finish()
    }
}

impl S15AuthorityConfig {
    pub fn from_settings(
        settings: &BTreeMap<String, String>,
    ) -> Result<Self, AuthorityConfigReport> {
        let required = [
            ENV_AUTHORITY_URL,
            ENV_AUTHORITY_CA_FILE,
            ENV_AUTHORITY_CLIENT_IDENTITY_FILE,
            ENV_AUTHORITY_SERVICE_ID,
            ENV_AUTHORITY_GENESIS_PIN,
            ENV_AUTHORITY_TENANT_ID,
            ENV_AUTHORITY_CARD_ID,
            ENV_AUTHORITY_USER_ID,
        ];
        let mut report = AuthorityConfigReport::default();
        let mut values = BTreeMap::new();
        for name in required {
            match settings.get(name).map(|value| value.trim()) {
                Some(value) if !value.is_empty() => {
                    values.insert(name, value.to_owned());
                }
                Some(_) => report.invalid.push(format!("{name}:blank")),
                None => report.missing.push(name.to_owned()),
            }
        }
        if !report.missing.is_empty() || !report.invalid.is_empty() {
            return Err(report);
        }
        let value = |name: &str| values.get(name).expect("required setting").as_str();
        let base_url = value(ENV_AUTHORITY_URL).to_owned();
        let endpoint_is_valid = url::Url::parse(&base_url).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none()
        });
        if !endpoint_is_valid {
            report
                .invalid
                .push(format!("{ENV_AUTHORITY_URL}:invalid_https_origin"));
        }
        let digest = value(ENV_AUTHORITY_GENESIS_PIN);
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            report
                .invalid
                .push(format!("{ENV_AUTHORITY_GENESIS_PIN}:invalid_sha256"));
        }
        let positive_id = |name: &str| -> Option<i64> {
            value(name).parse::<i64>().ok().filter(|number| *number > 0)
        };
        let tenant_id = positive_id(ENV_AUTHORITY_TENANT_ID);
        let card_id = positive_id(ENV_AUTHORITY_CARD_ID);
        let user_id = positive_id(ENV_AUTHORITY_USER_ID);
        for (name, parsed) in [
            (ENV_AUTHORITY_TENANT_ID, tenant_id),
            (ENV_AUTHORITY_CARD_ID, card_id),
            (ENV_AUTHORITY_USER_ID, user_id),
        ] {
            if parsed.is_none() {
                report
                    .invalid
                    .push(format!("{name}:expected_positive_integer"));
            }
        }
        let domain = match settings
            .get(ENV_AUTHORITY_DOMAIN_ID)
            .map(|value| value.trim())
        {
            None | Some("") | Some("any") => AuthorizationDomainScope::Any,
            Some(raw) => match raw.parse::<i64>().ok().filter(|value| *value > 0) {
                Some(value) => AuthorizationDomainScope::Exact(value),
                None => {
                    report.invalid.push(format!(
                        "{ENV_AUTHORITY_DOMAIN_ID}:expected_any_or_positive_integer"
                    ));
                    AuthorizationDomainScope::Any
                }
            },
        };
        let ca_file = PathBuf::from(value(ENV_AUTHORITY_CA_FILE));
        let client_identity_file = PathBuf::from(value(ENV_AUTHORITY_CLIENT_IDENTITY_FILE));
        if ca_file.file_name().is_none() {
            report
                .invalid
                .push(format!("{ENV_AUTHORITY_CA_FILE}:invalid_path"));
        }
        if client_identity_file.file_name().is_none() {
            report
                .invalid
                .push(format!("{ENV_AUTHORITY_CLIENT_IDENTITY_FILE}:invalid_path"));
        }
        if !report.invalid.is_empty() {
            return Err(report);
        }
        Ok(Self {
            base_url,
            ca_file,
            client_identity_file,
            service_id: value(ENV_AUTHORITY_SERVICE_ID).to_owned(),
            pinned_genesis_digest: digest.to_owned(),
            scope: AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
                tenant_id: tenant_id.expect("validated tenant"),
                card_id: card_id.expect("validated card"),
                user_id,
                domain,
            }),
        })
    }

    pub fn from_env() -> Result<Self, AuthorityConfigReport> {
        let names = [
            ENV_AUTHORITY_URL,
            ENV_AUTHORITY_CA_FILE,
            ENV_AUTHORITY_CLIENT_IDENTITY_FILE,
            ENV_AUTHORITY_SERVICE_ID,
            ENV_AUTHORITY_GENESIS_PIN,
            ENV_AUTHORITY_TENANT_ID,
            ENV_AUTHORITY_CARD_ID,
            ENV_AUTHORITY_USER_ID,
            ENV_AUTHORITY_DOMAIN_ID,
        ];
        let settings = names
            .into_iter()
            .filter_map(|name| {
                std::env::var(name)
                    .ok()
                    .map(|value| (name.to_owned(), value))
            })
            .collect();
        Self::from_settings(&settings)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S15AuthorityObservation {
    pub run_id: String,
    /// Authority fence-read protocol has no S15 run-id field; run_id is
    /// artifact correlation only and must never satisfy run-scoped provenance.
    pub run_correlation_only: bool,
    pub observed_at_unix_ms: i64,
    pub service_id: String,
    pub scope: AuthorityProtocolScope,
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub global_chain_digest: String,
    pub frontier_digest: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub trust_root_digest: String,
    pub scope_certificate_hash: Option<String>,
    pub scope_certificate: Option<AuthorityScopePublicationCertificate>,
    pub positive_reads_allowed: bool,
    pub global_pending: bool,
    pub blocking_reservation_count: usize,
    /// This is deliberately separate from the read-gate signal; no live
    /// PolicyEngine ALLOW decision is made or inferred by this adapter.
    pub policy_allow_decision: Option<bool>,
}

pub async fn observe_production_authority(
    config: &S15AuthorityConfig,
    run_id: &str,
    now_unix_ms: i64,
) -> Result<S15AuthorityObservation, String> {
    let ca_pem = read_bounded_file(&config.ca_file, MAX_CERTIFICATE_BYTES, false)?;
    let client_identity_pem =
        read_bounded_file(&config.client_identity_file, MAX_CERTIFICATE_BYTES, true)?;
    let client = AuthorityClient::new(AuthorityClientConfig {
        base_url: config.base_url.clone(),
        server_ca_pem: ca_pem,
        client_identity_pem,
        service_id: config.service_id.clone(),
        pinned_genesis_trust_root_digest: config.pinned_genesis_digest.clone(),
        request_timeout: AUTHORITY_READ_TIMEOUT,
    })
    .map_err(|_| "authority_client_config_rejected".to_owned())?;
    // This production method is authenticated by mTLS, verifies startup
    // attestation/signatures and reads the quorum frontier without mutation.
    let response = client
        .read_fence(Some(config.scope.clone()), None, None)
        .await
        .map_err(|error| match error {
            astral_authority::AuthorityClientError::UnknownOutcome { .. } => {
                "authority_read_unknown".to_owned()
            }
            astral_authority::AuthorityClientError::Transport(_) => {
                "authority_transport_unknown".to_owned()
            }
            _ => "authority_fence_read_rejected".to_owned(),
        })?;
    if response.read_gate.positive_reads_allowed
        && (response.read_gate.global_pending
            || !response.read_gate.blocking_reservations.is_empty())
    {
        return Err("authority_read_gate_inconsistent".to_owned());
    }
    let certificate = response.scope_certificate;
    let certificate_hash = response.scope_certificate_hash;
    if let Some(certificate) = certificate.as_ref() {
        let computed_hash = certificate
            .record_digest()
            .map_err(|_| "authority_certificate_digest_invalid")?;
        if certificate.scope != config.scope
            || certificate_hash.as_deref() != Some(computed_hash.as_str())
        {
            return Err("authority_scope_certificate_binding_mismatch".to_owned());
        }
    } else if certificate_hash.is_some() {
        return Err("authority_scope_certificate_missing".to_owned());
    }
    let frontier = response.global_frontier;
    let frontier_bytes = serde_json::to_vec(&frontier)
        .map_err(|_| "authority_frontier_serialize_failed".to_owned())?;
    use sha2::Digest;
    let frontier_hash = sha2::Sha256::digest(&frontier_bytes);
    let frontier_digest = frontier_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(S15AuthorityObservation {
        run_id: run_id.to_owned(),
        run_correlation_only: true,
        observed_at_unix_ms: now_unix_ms,
        service_id: config.service_id.clone(),
        scope: config.scope.clone(),
        authority_id: frontier.authority_id,
        authority_term: frontier.authority_term,
        global_fence_sequence: frontier.global_fence_sequence,
        global_chain_digest: frontier.global_chain_digest,
        frontier_digest,
        key_id: frontier.key_id,
        key_epoch: frontier.key_epoch,
        trust_root_digest: frontier.trust_root_digest,
        scope_certificate_hash: certificate_hash,
        scope_certificate: certificate,
        positive_reads_allowed: response.read_gate.positive_reads_allowed,
        global_pending: response.read_gate.global_pending,
        blocking_reservation_count: response.read_gate.blocking_reservations.len(),
        policy_allow_decision: None,
    })
}

fn read_bounded_file(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|_| "authority_credential_unreadable".to_owned())?;
    if !metadata.is_file() || metadata.len() as usize > maximum {
        return Err("authority_credential_file_invalid".to_owned());
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err("authority_client_identity_mode_insecure".to_owned());
        }
    }
    let bytes = fs::read(path).map_err(|_| "authority_credential_unreadable".to_owned())?;
    if bytes.is_empty() {
        return Err("authority_credential_file_empty".to_owned());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                ENV_AUTHORITY_URL.to_owned(),
                "https://authority.internal".to_owned(),
            ),
            (
                ENV_AUTHORITY_CA_FILE.to_owned(),
                "/protected/authority-ca.pem".to_owned(),
            ),
            (
                ENV_AUTHORITY_CLIENT_IDENTITY_FILE.to_owned(),
                "/protected/client.pem".to_owned(),
            ),
            (
                ENV_AUTHORITY_SERVICE_ID.to_owned(),
                "s15-validation".to_owned(),
            ),
            (ENV_AUTHORITY_GENESIS_PIN.to_owned(), "a".repeat(64)),
            (ENV_AUTHORITY_TENANT_ID.to_owned(), "17".to_owned()),
            (ENV_AUTHORITY_CARD_ID.to_owned(), "29".to_owned()),
            (ENV_AUTHORITY_USER_ID.to_owned(), "31".to_owned()),
        ])
    }

    #[test]
    fn authority_scope_is_exact_and_protected_debug_redacts_inputs() {
        let config = S15AuthorityConfig::from_settings(&settings()).expect("valid settings");
        assert!(matches!(
            config.scope,
            AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
                tenant_id: 17,
                card_id: 29,
                user_id: Some(31),
                domain: AuthorizationDomainScope::Any,
            })
        ));
        let debug = format!("{config:?}");
        assert!(!debug.contains("authority.internal"));
        assert!(!debug.contains("/protected/client.pem"));
        assert!(!debug.contains("s15-validation"));
    }

    #[test]
    fn authority_config_rejects_non_tls_wrong_pin_and_invalid_scope_without_echoing_values() {
        let cases = [
            (
                ENV_AUTHORITY_URL,
                "http://authority.internal".to_owned(),
                "invalid_https_origin",
            ),
            (ENV_AUTHORITY_GENESIS_PIN, "Z".repeat(64), "invalid_sha256"),
            (
                ENV_AUTHORITY_TENANT_ID,
                "0".to_owned(),
                "expected_positive_integer",
            ),
        ];
        for (name, value, expected) in cases {
            let mut input = settings();
            input.insert(name.to_owned(), value.clone());
            let report = S15AuthorityConfig::from_settings(&input).unwrap_err();
            assert!(report.invalid.iter().any(|issue| issue.contains(expected)));
            assert!(!report.to_string().contains(&value));
        }
        let report = S15AuthorityConfig::from_settings(&BTreeMap::new()).unwrap_err();
        assert_eq!(report.missing.len(), 8);
    }
}
