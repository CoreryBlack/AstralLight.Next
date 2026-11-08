//! Protected signing owner.
//!
//! The signer is the only place authority key material exists in memory. It
//! is deliberately NOT `Clone`, deliberately has no key accessor, masks its
//! `Debug` output, and zeroizes the seed when dropped. It is constructed once
//! at startup, wrapped in one `Arc`, and never placed inside generic shared
//! request state; call sites receive only `Arc<ProtectedAuthoritySigner>` and
//! can ask it to sign exact domain-separated byte strings.
//!
//! Signing is additionally gated on the leader flag: a standby instance must
//! never sign even if it holds a copy of the key material, so `sign_checked`
//! takes the current leader state as an explicit parameter and the service
//! layer refuses mutations on non-leaders before reaching the signer.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroize;

use astral_types::{AuthorityRootKeyRole, AuthorityTrustRoot};

use crate::error::{AuthorityServiceError, AuthorityStoreError};

/// The protected signing owner. See module docs for the invariants.
pub struct ProtectedAuthoritySigner {
    signing_key: SigningKey,
    key_id: String,
    key_epoch: u64,
}

impl std::fmt::Debug for ProtectedAuthoritySigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedAuthoritySigner")
            .field("key_id", &self.key_id)
            .field("key_epoch", &self.key_epoch)
            .field("signing_key", &"<protected>")
            .finish()
    }
}

impl Drop for ProtectedAuthoritySigner {
    fn drop(&mut self) {
        // Zeroize the seed bytes; ed25519_dalek keeps them in a scalar which
        // we cannot reach directly, so we zeroize the raw seed we consumed.
        let mut seed = self.signing_key.to_bytes();
        seed.zeroize();
    }
}

impl ProtectedAuthoritySigner {
    /// Load the signer from a seed file (raw 32 bytes or 64-char hex).
    pub fn from_seed_file(
        path: &std::path::Path,
        expected_key_id: &str,
        trust_root: &AuthorityTrustRoot,
    ) -> Result<Self, AuthorityStoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(path).map_err(|error| {
                AuthorityStoreError::Configuration(format!(
                    "signing key {}: {error}",
                    path.display()
                ))
            })?;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(AuthorityStoreError::Configuration(format!(
                    "signing key {} must not be readable by group or others (mode {:o})",
                    path.display(),
                    mode & 0o777
                )));
            }
        }
        let raw = std::fs::read(path).map_err(|error| {
            AuthorityStoreError::Configuration(format!("read signing key: {error}"))
        })?;
        let seed = Self::parse_seed(&raw)?;
        Self::from_seed(seed, expected_key_id, trust_root)
    }

    /// Load the signer from a hex seed string (already read from an env var).
    pub fn from_seed_hex(
        seed_hex: &str,
        expected_key_id: &str,
        trust_root: &AuthorityTrustRoot,
    ) -> Result<Self, AuthorityStoreError> {
        let mut raw = seed_hex.trim().as_bytes().to_vec();
        let seed = Self::parse_seed(&raw);
        raw.zeroize();
        let seed = seed?;
        let signer = Self::from_seed(seed, expected_key_id, trust_root)?;
        // Bind the signer key id to the configuration expectation.
        if signer.key_id != expected_key_id {
            return Err(AuthorityStoreError::Configuration(format!(
                "signer key id {} does not match configured {}",
                signer.key_id, expected_key_id
            )));
        }
        Ok(signer)
    }

    fn parse_seed(raw: &[u8]) -> Result<[u8; 32], AuthorityStoreError> {
        let mut seed = [0u8; 32];
        if raw.len() == 32 {
            seed.copy_from_slice(raw);
            return Ok(seed);
        }
        if raw.len() == 64 {
            let text = std::str::from_utf8(raw).map_err(|_| {
                AuthorityStoreError::Configuration("seed file is not valid".to_owned())
            })?;
            let trimmed = text.trim();
            if trimmed.len() == 64
                && trimmed
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                for (index, pair) in trimmed.as_bytes().chunks(2).enumerate() {
                    let high = (pair[0] as char).to_digit(16).ok_or_else(|| {
                        AuthorityStoreError::Configuration("invalid seed hex".to_owned())
                    })? as u8;
                    let low = (pair[1] as char).to_digit(16).ok_or_else(|| {
                        AuthorityStoreError::Configuration("invalid seed hex".to_owned())
                    })? as u8;
                    seed[index] = (high << 4) | low;
                }
                return Ok(seed);
            }
        }
        Err(AuthorityStoreError::Configuration(
            "signing seed must be 32 raw bytes or 64 lowercase hex characters".to_owned(),
        ))
    }

    /// Construct and bind the signer to the active trust root: the key must
    /// be the current SIGNER-role key with the expected id and epoch.
    pub fn from_seed(
        seed: [u8; 32],
        expected_key_id: &str,
        trust_root: &AuthorityTrustRoot,
    ) -> Result<Self, AuthorityStoreError> {
        trust_root
            .validate()
            .map_err(|error| AuthorityStoreError::Configuration(error.to_string()))?;
        let signer_entry = trust_root.signer_key().map_err(|error| {
            AuthorityStoreError::Configuration(format!("trust root has no signer key: {error}"))
        })?;
        if signer_entry.key_id != expected_key_id {
            return Err(AuthorityStoreError::Configuration(format!(
                "trust root signer key {} does not match expected {}",
                signer_entry.key_id, expected_key_id
            )));
        }
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying = signing_key.verifying_key();
        if hex::encode(verifying.as_bytes()) != signer_entry.verifying_key_hex {
            return Err(AuthorityStoreError::Configuration(
                "signer seed does not match the trust root signer verifying key".to_owned(),
            ));
        }
        Ok(Self {
            signing_key,
            key_id: signer_entry.key_id.clone(),
            key_epoch: signer_entry.key_epoch,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// Verify this signer matches the active trust root's current signer key.
    pub fn matches_trust_root(
        &self,
        trust_root: &AuthorityTrustRoot,
    ) -> Result<bool, AuthorityServiceError> {
        trust_root
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let signer_entry = trust_root
            .signer_key()
            .map_err(AuthorityServiceError::Protocol)?;
        Ok(signer_entry.key_id == self.key_id
            && signer_entry.key_epoch == self.key_epoch
            && signer_entry.verifying_key_hex
                == hex::encode(self.signing_key.verifying_key().as_bytes()))
    }

    /// Sign only when `leader` is true. A standby never produces signatures.
    pub fn sign_checked(
        &self,
        message: &[u8],
        leader: bool,
    ) -> Result<String, AuthorityServiceError> {
        if !leader {
            return Err(AuthorityServiceError::NotLeader);
        }
        let signature: Signature = self.signing_key.sign(message);
        Ok(hex::encode(signature.to_bytes()))
    }

    /// The verifying key identity of this signer as a root key entry.
    pub fn as_root_key_entry(
        &self,
        role: AuthorityRootKeyRole,
        epoch: u64,
    ) -> astral_types::AuthorityRootKey {
        astral_types::AuthorityRootKey {
            key_id: self.key_id.clone(),
            key_epoch: epoch,
            role,
            verifying_key_hex: hex::encode(self.signing_key.verifying_key().as_bytes()),
        }
    }

    /// Expose the verifying key for attestation/verification helpers.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{AuthorityRootKey, AuthorityRootKeyRole};

    fn trust_root_with_signer(seed: u8, key_id: &str) -> (SigningKey, AuthorityTrustRoot) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let root = AuthorityTrustRoot {
            root_id: "root-1".to_owned(),
            keys: vec![
                AuthorityRootKey {
                    key_id: key_id.to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Signer,
                    verifying_key_hex: hex::encode(signing.verifying_key().as_bytes()),
                },
                AuthorityRootKey {
                    key_id: "root-1".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Root,
                    verifying_key_hex: hex::encode([2u8; 32]),
                },
                AuthorityRootKey {
                    key_id: "genesis-1".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Genesis,
                    verifying_key_hex: hex::encode([3u8; 32]),
                },
            ],
            created_at: 1_000,
        };
        (signing, root)
    }

    #[test]
    fn signer_binds_to_trust_root_and_never_signs_on_standby() {
        let (_key, root) = trust_root_with_signer(7, "signer-1");
        let signer = ProtectedAuthoritySigner::from_seed([7u8; 32], "signer-1", &root).unwrap();
        assert_eq!(signer.key_id(), "signer-1");
        assert_eq!(signer.key_epoch(), 1);
        assert!(signer.matches_trust_root(&root).unwrap());

        let signature = signer.sign_checked(b"message", true).unwrap();
        signer
            .verifying_key()
            .verify_strict(
                b"message",
                &ed25519_dalek::Signature::from_bytes(
                    &hex::decode(&signature).unwrap().try_into().unwrap(),
                ),
            )
            .unwrap();

        assert!(matches!(
            signer.sign_checked(b"message", false),
            Err(AuthorityServiceError::NotLeader)
        ));

        // Wrong seed must not bind to the trust root.
        assert!(ProtectedAuthoritySigner::from_seed([9u8; 32], "signer-1", &root).is_err());
        // Wrong key id must not bind.
        assert!(ProtectedAuthoritySigner::from_seed([7u8; 32], "signer-2", &root).is_err());
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let (_key, root) = trust_root_with_signer(7, "signer-1");
        let signer = ProtectedAuthoritySigner::from_seed([7u8; 32], "signer-1", &root).unwrap();
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("<protected>"));
        let seed_hex = hex::encode([7u8; 32]);
        assert!(!rendered.contains(&seed_hex));
    }

    #[test]
    fn seed_hex_parsing_is_strict_and_binds_expected_id() {
        let (_key, root) = trust_root_with_signer(0xA7, "signer-1");
        let seed_hex = hex::encode([0xA7u8; 32]);
        let signer = ProtectedAuthoritySigner::from_seed_hex(&seed_hex, "signer-1", &root).unwrap();
        assert_eq!(signer.key_id(), "signer-1");
        assert_eq!(seed_hex, "a7".repeat(32), "seed must contain letters");

        // Uppercase hex is not canonical and must be refused.
        assert!(ProtectedAuthoritySigner::from_seed_hex(
            &seed_hex.to_uppercase(),
            "signer-1",
            &root
        )
        .is_err());
    }
}
