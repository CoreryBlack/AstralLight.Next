//! Service configuration (TOML file plus selected environment overrides).
//!
//! Security-critical fields are mandatory: the listener refuses to start
//! without server certificate, key and client CA, and the trust root digest
//! pin must be present. Secrets are never stored in configuration values —
//! only paths or environment variable names.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::AuthorityStoreError;

/// Listener configuration. TLS with client authentication is mandatory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct AuthorityListenerConfig {
    pub bind_address: String,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    /// CA bundle used to verify client certificates (mTLS is mandatory).
    pub client_ca_path: PathBuf,
    pub max_body_bytes: usize,
    pub request_timeout_seconds: u64,
    pub max_concurrent_signing: usize,
}

impl Default for AuthorityListenerConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:24081".to_owned(),
            server_cert_path: PathBuf::from("/etc/astral/authority/tls/server.crt"),
            server_key_path: PathBuf::from("/etc/astral/authority/tls/server.key"),
            client_ca_path: PathBuf::from("/etc/astral/authority/tls/client-ca.crt"),
            max_body_bytes: 256 * 1024,
            request_timeout_seconds: 10,
            max_concurrent_signing: 64,
        }
    }
}

/// One registered trusted source process, pinned by certificate fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthorityTrustedSource {
    /// Logical service identity callers must present in request bodies.
    pub service_id: String,
    /// SHA-256 fingerprint (`sha256:<64 hex>`) of the client certificate DER.
    pub certificate_fingerprint: String,
    /// Registered database identities this source may commit against.
    pub allowed_database_ids: Vec<String>,
    /// Operations this source may call.
    pub allowed_operations: Vec<String>,
}

/// Quorum (etcd) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct AuthorityQuorumConfig {
    pub endpoints: Vec<String>,
    /// Key prefix for all authority state; must be dedicated per authority.
    pub key_prefix: String,
    pub authority_name: String,
    /// etcd TLS: CA bundle for server verification (mandatory when enabled).
    pub tls_enabled: bool,
    pub tls_ca_path: Option<PathBuf>,
    pub tls_client_cert_path: Option<PathBuf>,
    pub tls_client_key_path: Option<PathBuf>,
    pub tls_domain_name: Option<String>,
    /// Leader lease TTL in seconds; election renewals keep it alive.
    pub lease_ttl_seconds: i64,
}

impl Default for AuthorityQuorumConfig {
    fn default() -> Self {
        Self {
            endpoints: vec!["http://127.0.0.1:2379".to_owned()],
            key_prefix: "astral-authority/v1".to_owned(),
            authority_name: "astral-authority".to_owned(),
            tls_enabled: false,
            tls_ca_path: None,
            tls_client_cert_path: None,
            tls_client_key_path: None,
            tls_domain_name: None,
            lease_ttl_seconds: 15,
        }
    }
}

/// Signer configuration: the protected signing owner's key material source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
#[derive(Default)]
pub struct AuthoritySignerConfig {
    /// Path to the signer seed file (raw 32 bytes or 64-char hex), mode 0600.
    pub signing_key_path: Option<PathBuf>,
    /// Alternative: environment variable holding the 64-char hex seed.
    pub signing_key_env: Option<String>,
    /// Expected key id of the signer inside the active trust root.
    pub expected_signer_key_id: String,
}

/// Authority identity and protected trust-root pin.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct AuthorityIdentityConfig {
    pub authority_id: String,
    /// Out-of-band pin: the digest of the genesis trust root. Rotation keeps
    /// this pin stable because the chain is verified from genesis.
    pub pinned_genesis_trust_root_digest: String,
}

impl Default for AuthorityIdentityConfig {
    fn default() -> Self {
        Self {
            authority_id: "astral-authority-1".to_owned(),
            pinned_genesis_trust_root_digest: String::new(),
        }
    }
}

/// Policy switches. The conservative production defaults are listed here.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct AuthorityPolicyConfig {
    /// When false (default), every reservation blocks ALL scopes (GLOBAL
    /// coverage) until exact affected-scope coverage is established.
    pub exact_scope_coverage_enabled: bool,
    /// Default proof lifetime in seconds for read proofs.
    pub proof_ttl_seconds: i64,
    /// Genesis bootstrap: only the root-owned `genesis` tool may create the
    /// genesis record; the server never mints one implicitly.
    pub allow_genesis_bootstrap: bool,
}

impl Default for AuthorityPolicyConfig {
    fn default() -> Self {
        Self {
            exact_scope_coverage_enabled: false,
            proof_ttl_seconds: astral_types::AUTHORITY_DEFAULT_PROOF_TTL_SECONDS,
            allow_genesis_bootstrap: false,
        }
    }
}

/// Root configuration document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", default)]
pub struct AuthorityServiceConfig {
    pub listener: AuthorityListenerConfig,
    pub quorum: AuthorityQuorumConfig,
    pub signer: AuthoritySignerConfig,
    pub identity: AuthorityIdentityConfig,
    pub policy: AuthorityPolicyConfig,
    pub trusted_sources: Vec<AuthorityTrustedSource>,
}

impl AuthorityServiceConfig {
    /// Load configuration from a TOML file, then apply env overrides.
    ///
    /// Overrides (all optional):
    /// - `ASTRAL_AUTHORITY_SIGNING_KEY`  — hex seed for the protected signer.
    /// - `ASTRAL_AUTHORITY_ETCD_ENDPOINTS` — comma-separated endpoints.
    pub fn load(path: &Path) -> Result<Self, AuthorityStoreError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|error| AuthorityStoreError::Configuration(format!("read config: {error}")))?;
        let mut config: Self = toml::from_str(&raw).map_err(|error| {
            AuthorityStoreError::Configuration(format!("parse config: {error}"))
        })?;
        if let Ok(signing_key) = std::env::var("ASTRAL_AUTHORITY_SIGNING_KEY") {
            if !signing_key.trim().is_empty() {
                config.signer.signing_key_env = Some("ASTRAL_AUTHORITY_SIGNING_KEY".to_owned());
            }
        }
        if let Ok(endpoints) = std::env::var("ASTRAL_AUTHORITY_ETCD_ENDPOINTS") {
            let parsed: Vec<String> = endpoints
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect();
            if !parsed.is_empty() {
                config.quorum.endpoints = parsed;
            }
        }
        config.validate()?;
        Ok(config)
    }

    /// Fail-closed validation: mandatory TLS, pin, and registration checks.
    pub fn validate(&self) -> Result<(), AuthorityStoreError> {
        if self.listener.max_body_bytes == 0 || self.listener.max_body_bytes > 4 * 1024 * 1024 {
            return Err(AuthorityStoreError::Configuration(
                "listener.max_body_bytes must be within 1..=4MiB".to_owned(),
            ));
        }
        if self.listener.request_timeout_seconds == 0 || self.listener.request_timeout_seconds > 120
        {
            return Err(AuthorityStoreError::Configuration(
                "listener.request_timeout_seconds must be within 1..=120".to_owned(),
            ));
        }
        if self.listener.max_concurrent_signing == 0 {
            return Err(AuthorityStoreError::Configuration(
                "listener.max_concurrent_signing must be positive".to_owned(),
            ));
        }
        if self.quorum.endpoints.is_empty() {
            return Err(AuthorityStoreError::Configuration(
                "quorum.endpoints must not be empty".to_owned(),
            ));
        }
        if self.quorum.key_prefix.trim().is_empty()
            || self.quorum.key_prefix.starts_with('/')
            || self.quorum.key_prefix.ends_with('/')
        {
            return Err(AuthorityStoreError::Configuration(
                "quorum.key_prefix must be a relative, non-empty path".to_owned(),
            ));
        }
        if self.identity.authority_id.trim().is_empty() {
            return Err(AuthorityStoreError::Configuration(
                "identity.authority_id must not be empty".to_owned(),
            ));
        }
        if !astral_types::authority_protocol_digest_shape(
            &self.identity.pinned_genesis_trust_root_digest,
        ) {
            return Err(AuthorityStoreError::Configuration(
                "identity.pinned_genesis_trust_root_digest must be 64 lowercase hex".to_owned(),
            ));
        }
        if self.signer.signing_key_path.is_none() && self.signer.signing_key_env.is_none() {
            return Err(AuthorityStoreError::Configuration(
                "signer requires signing_key_path or signing_key_env".to_owned(),
            ));
        }
        if self.signer.expected_signer_key_id.trim().is_empty() {
            return Err(AuthorityStoreError::Configuration(
                "signer.expected_signer_key_id must not be empty".to_owned(),
            ));
        }
        if self.policy.proof_ttl_seconds <= 0
            || self.policy.proof_ttl_seconds > astral_types::AUTHORITY_MAX_PROOF_TTL_SECONDS
        {
            return Err(AuthorityStoreError::Configuration(
                "policy.proof_ttl_seconds out of range".to_owned(),
            ));
        }
        let mut seen_services = std::collections::BTreeSet::new();
        for source in &self.trusted_sources {
            if !seen_services.insert(source.service_id.clone()) {
                return Err(AuthorityStoreError::Configuration(format!(
                    "duplicate trusted source {}",
                    source.service_id
                )));
            }
            if !source
                .certificate_fingerprint
                .strip_prefix("sha256:")
                .is_some_and(|hex_part| {
                    hex_part.len() == 64
                        && hex_part
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            {
                return Err(AuthorityStoreError::Configuration(format!(
                    "trusted source {} fingerprint must be sha256:<64 lowercase hex>",
                    source.service_id
                )));
            }
            if source.allowed_operations.is_empty() {
                return Err(AuthorityStoreError::Configuration(format!(
                    "trusted source {} must declare allowed_operations",
                    source.service_id
                )));
            }
        }
        Ok(())
    }

    /// Look up a trusted source by TLS certificate fingerprint.
    pub fn trusted_source_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Option<&AuthorityTrustedSource> {
        self.trusted_sources
            .iter()
            .find(|source| source.certificate_fingerprint == fingerprint)
    }

    pub fn trusted_source_by_id(&self, service_id: &str) -> Option<&AuthorityTrustedSource> {
        self.trusted_sources
            .iter()
            .find(|source| source.service_id == service_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> AuthorityServiceConfig {
        AuthorityServiceConfig {
            identity: AuthorityIdentityConfig {
                authority_id: "authority-1".to_owned(),
                pinned_genesis_trust_root_digest: "ab".repeat(32),
            },
            signer: AuthoritySignerConfig {
                signing_key_path: Some(PathBuf::from("/keys/signer.seed")),
                signing_key_env: None,
                expected_signer_key_id: "signer-1".to_owned(),
            },
            listener: AuthorityListenerConfig {
                server_cert_path: PathBuf::from("/tls/server.crt"),
                server_key_path: PathBuf::from("/tls/server.key"),
                client_ca_path: PathBuf::from("/tls/client-ca.crt"),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn validation_enforces_mandatory_tls_pin_and_registrations() {
        assert!(base_config().validate().is_ok());

        let missing_pin = AuthorityServiceConfig {
            identity: AuthorityIdentityConfig {
                authority_id: "authority-1".to_owned(),
                pinned_genesis_trust_root_digest: String::new(),
            },
            ..base_config()
        };
        assert!(missing_pin.validate().is_err());

        let mut fingerprint = base_config();
        fingerprint.trusted_sources.push(AuthorityTrustedSource {
            service_id: "astral-db-primary".to_owned(),
            certificate_fingerprint: "sha256:ZZ".to_owned(),
            allowed_database_ids: vec!["db-1".to_owned()],
            allowed_operations: vec!["prepare".to_owned()],
        });
        assert!(fingerprint.validate().is_err());

        let mut duplicate = base_config();
        let source = AuthorityTrustedSource {
            service_id: "astral-db-primary".to_owned(),
            certificate_fingerprint: format!("sha256:{}", "aa".repeat(32)),
            allowed_database_ids: vec!["db-1".to_owned()],
            allowed_operations: vec!["prepare".to_owned()],
        };
        duplicate.trusted_sources.push(source.clone());
        duplicate.trusted_sources.push(source);
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn toml_round_trip_keeps_security_defaults() {
        let config = base_config();
        let text = toml::to_string(&config).unwrap();
        let parsed: AuthorityServiceConfig = toml::from_str(&text).unwrap();
        assert!(!parsed.policy.exact_scope_coverage_enabled);
        assert!(!parsed.policy.allow_genesis_bootstrap);
        assert_eq!(parsed.quorum.key_prefix, "astral-authority/v1");
    }
}
