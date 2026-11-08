//! Global frontier, trust root, genesis and root-authorized key rotation.
//!
//! The global frontier is the authority-wide sequencing identity. Its chain
//! digest is a digest of authority state transitions and is deliberately kept
//! distinct from any per-scope evidence snapshot hash. Genesis is explicitly
//! signed, and every later trust root is derived from the genesis root through
//! a strictly increasing chain of root-signed rotation certificates.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{
    authority_counter, authority_digest, authority_field, authority_signature_encoding,
    authority_text, authority_time_window, authority_timestamp, authority_verify_strict,
    AuthorityProtocolError,
};
use crate::AUTHORIZATION_EDITION;

const GENESIS_RECORD_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_GENESIS_RECORD_V1\0";
const KEY_ROTATION_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_KEY_ROTATION_V1\0";
const TRUST_ROOT_DIGEST_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_TRUST_ROOT_DIGEST_V1\0";
const GLOBAL_CHAIN_DIGEST_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_GLOBAL_CHAIN_DIGEST_V1\0";

/// Role of one key inside the authority trust root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityRootKeyRole {
    /// Signs authority control-plane artifacts (proofs, certificates).
    Signer,
    /// Authorizes trust-root rotation.
    Root,
    /// Signs the explicit genesis record; never used after genesis.
    Genesis,
}

impl AuthorityRootKeyRole {
    pub const fn as_text(self) -> &'static str {
        match self {
            Self::Signer => "SIGNER",
            Self::Root => "ROOT",
            Self::Genesis => "GENESIS",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "SIGNER" => Some(Self::Signer),
            "ROOT" => Some(Self::Root),
            "GENESIS" => Some(Self::Genesis),
            _ => None,
        }
    }
}

/// One verifying key bound to the trust root with a strictly increasing epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityRootKey {
    pub key_id: String,
    pub key_epoch: u64,
    pub role: AuthorityRootKeyRole,
    /// Lowercase hex of the 32-byte Ed25519 verifying key.
    pub verifying_key_hex: String,
}

impl AuthorityRootKey {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.key_id, "key_id")?;
        authority_counter(self.key_epoch, "key_epoch")?;
        authority_text(self.role.as_text(), "role")
            .map_err(|_| AuthorityProtocolError::InvalidText { field: "role" })?;
        if self.verifying_key_hex.len() != 64
            || !self
                .verifying_key_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AuthorityProtocolError::InvalidDigest {
                field: "verifying_key_hex",
            });
        }
        Ok(())
    }

    /// Parse the verifying key after structural validation.
    pub fn verifying_key(&self) -> Result<VerifyingKey, AuthorityProtocolError> {
        self.validate()?;
        let mut raw = [0u8; 32];
        for (index, pair) in self.verifying_key_hex.as_bytes().chunks(2).enumerate() {
            let high =
                (pair[0] as char)
                    .to_digit(16)
                    .ok_or(AuthorityProtocolError::InvalidDigest {
                        field: "verifying_key_hex",
                    })? as u8;
            let low =
                (pair[1] as char)
                    .to_digit(16)
                    .ok_or(AuthorityProtocolError::InvalidDigest {
                        field: "verifying_key_hex",
                    })? as u8;
            raw[index] = (high << 4) | low;
        }
        VerifyingKey::from_bytes(&raw).map_err(|_| AuthorityProtocolError::InvalidSignature)
    }
}

/// The pinned set of authority keys at one point in the rotation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityTrustRoot {
    pub root_id: String,
    pub keys: Vec<AuthorityRootKey>,
    pub created_at: i64,
}

impl AuthorityTrustRoot {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.root_id, "root_id")?;
        authority_timestamp(self.created_at, "created_at")?;
        if self.keys.is_empty() {
            return Err(AuthorityProtocolError::InvalidText { field: "keys" });
        }
        let mut seen_keys = std::collections::BTreeSet::new();
        for key in &self.keys {
            key.validate()?;
            if !seen_keys.insert(key.key_id.clone()) {
                return Err(AuthorityProtocolError::InvalidText { field: "key_id" });
            }
        }
        if !self
            .keys
            .iter()
            .any(|key| key.role == AuthorityRootKeyRole::Signer)
        {
            return Err(AuthorityProtocolError::InvalidText {
                field: "signer_key",
            });
        }
        if !self
            .keys
            .iter()
            .any(|key| key.role == AuthorityRootKeyRole::Root)
        {
            return Err(AuthorityProtocolError::InvalidText { field: "root_key" });
        }
        if !self
            .keys
            .iter()
            .any(|key| key.role == AuthorityRootKeyRole::Genesis)
        {
            return Err(AuthorityProtocolError::InvalidText {
                field: "genesis_key",
            });
        }
        Ok(())
    }

    /// Canonical, injective digest of the trust root. This is the value that
    /// operators pin out-of-band (configuration) to protect the trust root.
    pub fn digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(TRUST_ROOT_DIGEST_DOMAIN);
        authority_field(&mut bytes, &self.root_id);
        authority_field(&mut bytes, &self.created_at.to_string());
        for key in &self.keys {
            authority_field(&mut bytes, &key.key_id);
            authority_field(&mut bytes, &key.key_epoch.to_string());
            authority_field(&mut bytes, key.role.as_text());
            authority_field(&mut bytes, &key.verifying_key_hex);
        }
        Ok(super::authority_sha256_hex(&bytes))
    }

    /// The active signer key: the highest-epoch SIGNER-role key. Historical
    /// signer keys are retained for durable artifact verification.
    pub fn signer_key(&self) -> Result<&AuthorityRootKey, AuthorityProtocolError> {
        self.validate()?;
        self.keys
            .iter()
            .filter(|key| key.role == AuthorityRootKeyRole::Signer)
            .max_by_key(|key| key.key_epoch)
            .ok_or(AuthorityProtocolError::InvalidText {
                field: "signer_key",
            })
    }

    pub fn root_key(&self) -> Result<&AuthorityRootKey, AuthorityProtocolError> {
        self.validate()?;
        self.keys
            .iter()
            .find(|key| key.role == AuthorityRootKeyRole::Root)
            .ok_or(AuthorityProtocolError::InvalidText { field: "root_key" })
    }

    pub fn genesis_key(&self) -> Result<&AuthorityRootKey, AuthorityProtocolError> {
        self.validate()?;
        self.keys
            .iter()
            .find(|key| key.role == AuthorityRootKeyRole::Genesis)
            .ok_or(AuthorityProtocolError::InvalidText {
                field: "genesis_key",
            })
    }

    pub fn key_by_id(&self, key_id: &str) -> Option<&AuthorityRootKey> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }
}

/// The explicitly signed genesis record. It exists exactly once per authority
/// and anchors the rotation chain. The genesis signature is mandatory; an
/// unsigned or mismatched genesis must refuse to start any authority runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityGenesisRecord {
    pub authorization_edition: u16,
    pub authority_id: String,
    pub root_id: String,
    pub trust_root_digest: String,
    pub created_at: i64,
    pub genesis_nonce: String,
    pub signed_by_key_id: String,
    /// Lowercase hex Ed25519 signature by the genesis-role key.
    pub signature: String,
}

impl AuthorityGenesisRecord {
    /// Validate everything except the signature encoding; used on the
    /// unsigned signing path where the signature is not yet present.
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        authority_text(&self.root_id, "root_id")?;
        authority_digest(&self.trust_root_digest, "trust_root_digest")?;
        authority_timestamp(self.created_at, "created_at")?;
        authority_text(&self.genesis_nonce, "genesis_nonce")?;
        authority_text(&self.signed_by_key_id, "signed_by_key_id")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_signature_encoding(&self.signature)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(GENESIS_RECORD_DOMAIN);
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.root_id);
        authority_field(&mut bytes, &self.trust_root_digest);
        authority_field(&mut bytes, &self.created_at.to_string());
        authority_field(&mut bytes, &self.genesis_nonce);
        authority_field(&mut bytes, &self.signed_by_key_id);
        Ok(bytes)
    }

    /// Sign the genesis record in place with the genesis-role signing key.
    /// The record digest must equal the digest of the trust root being blessed.
    pub fn sign(
        &mut self,
        genesis_signing_key: &SigningKey,
        signed_by_key_id: &str,
    ) -> Result<(), AuthorityProtocolError> {
        self.signed_by_key_id = signed_by_key_id.to_owned();
        self.signature = String::new();
        self.validate_unsigned()?;
        let signature = genesis_signing_key.sign(&self.signing_bytes()?);
        self.signature = hex::encode(signature.to_bytes());
        Ok(())
    }

    /// Verify against the genesis-role verifying key of the blessed trust root.
    pub fn verify(
        &self,
        trust_root: &AuthorityTrustRoot,
        verifying_key: &VerifyingKey,
    ) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        trust_root.validate()?;
        if self.root_id != trust_root.root_id || self.trust_root_digest != trust_root.digest()? {
            return Err(AuthorityProtocolError::TrustRootMismatch);
        }
        authority_verify_strict(verifying_key, &self.signing_bytes()?, &self.signature)
    }
}

/// One root-authorized trust-root rotation. Strictly increasing epochs and the
/// previous/new root digest chain make rotations verifiable without trusting
/// the durability layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityKeyRotationCertificate {
    pub authorization_edition: u16,
    pub authority_id: String,
    pub root_id: String,
    pub previous_key_epoch: u64,
    pub new_key: AuthorityRootKey,
    pub previous_trust_root_digest: String,
    pub new_trust_root_digest: String,
    pub rotation_nonce: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub signed_by_key_id: String,
    /// Lowercase hex Ed25519 signature by the current root-role key.
    pub signature: String,
}

impl AuthorityKeyRotationCertificate {
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        authority_text(&self.root_id, "root_id")?;
        authority_counter(self.previous_key_epoch, "previous_key_epoch")?;
        self.new_key.validate()?;
        if self.new_key.key_epoch <= self.previous_key_epoch {
            return Err(AuthorityProtocolError::KeyEpochNonMonotonic);
        }
        authority_digest(
            &self.previous_trust_root_digest,
            "previous_trust_root_digest",
        )?;
        authority_digest(&self.new_trust_root_digest, "new_trust_root_digest")?;
        authority_text(&self.rotation_nonce, "rotation_nonce")?;
        authority_text(&self.signed_by_key_id, "signed_by_key_id")?;
        authority_time_window(self.not_before, self.issued_at, self.expires_at)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_signature_encoding(&self.signature)
    }

    pub fn validate_at(&self, now_seconds: i64) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        if now_seconds < self.not_before || now_seconds >= self.expires_at {
            return Err(AuthorityProtocolError::NotCurrentlyValid);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(KEY_ROTATION_DOMAIN);
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.root_id);
        authority_field(&mut bytes, &self.previous_key_epoch.to_string());
        authority_field(&mut bytes, &self.new_key.key_id);
        authority_field(&mut bytes, &self.new_key.key_epoch.to_string());
        authority_field(&mut bytes, self.new_key.role.as_text());
        authority_field(&mut bytes, &self.new_key.verifying_key_hex);
        authority_field(&mut bytes, &self.previous_trust_root_digest);
        authority_field(&mut bytes, &self.new_trust_root_digest);
        authority_field(&mut bytes, &self.rotation_nonce);
        authority_field(&mut bytes, &self.issued_at.to_string());
        authority_field(&mut bytes, &self.not_before.to_string());
        authority_field(&mut bytes, &self.expires_at.to_string());
        authority_field(&mut bytes, &self.signed_by_key_id);
        Ok(bytes)
    }

    pub fn sign(
        &mut self,
        root_signing_key: &SigningKey,
        signed_by_key_id: &str,
    ) -> Result<(), AuthorityProtocolError> {
        self.signed_by_key_id = signed_by_key_id.to_owned();
        self.signature = String::new();
        self.validate_unsigned()?;
        let signature = root_signing_key.sign(&self.signing_bytes()?);
        self.signature = hex::encode(signature.to_bytes());
        Ok(())
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        authority_verify_strict(verifying_key, &self.signing_bytes()?, &self.signature)
    }

    /// Verify that this rotation continues the chain rooted at `previous`.
    ///
    /// The contract is exact on every axis:
    /// - `previous_trust_root_digest` must equal the canonical digest of
    ///   `previous` (digest-chain continuity),
    /// - `signed_by_key_id` must name `previous`'s ROOT-role key with the
    ///   matching `previous_key_epoch` (the wire field keeps its meaning: the
    ///   ROOT authorizer epoch, never the signer epoch), and the signature
    ///   must verify under exactly that root entry's own verifying key,
    /// - the new key must be a SIGNER-role key whose epoch STRICTLY exceeds
    ///   the previous ACTIVE signer epoch (a rotation can never roll the
    ///   signer epoch back, not even to an unused lower epoch),
    /// - the new key id must be fresh across the entire chain history,
    /// - the fold retains the FULL previous key set: history is never
    ///   erased, so previously issued durable artifacts stay verifiable, and
    ///   the folded root digest must equal `new_trust_root_digest`.
    ///
    /// Historical chain replay must not depend on the wall clock, so time
    /// validity is NOT checked here; applying a NEW rotation at runtime must
    /// additionally call [`Self::validate_at`].
    pub fn verify_after(
        &self,
        previous: &AuthorityTrustRoot,
        verifying_key: &VerifyingKey,
    ) -> Result<AuthorityTrustRoot, AuthorityProtocolError> {
        self.validate()?;
        previous.validate()?;
        let previous_digest = previous.digest()?;
        if self.root_id != previous.root_id || self.previous_trust_root_digest != previous_digest {
            return Err(AuthorityProtocolError::TrustRootMismatch);
        }
        let root_entry = previous
            .key_by_id(&self.signed_by_key_id)
            .filter(|key| key.role == AuthorityRootKeyRole::Root)
            .ok_or(AuthorityProtocolError::InvalidText {
                field: "signed_by_key_id",
            })?;
        if root_entry.key_epoch != self.previous_key_epoch {
            return Err(AuthorityProtocolError::KeyEpochNonMonotonic);
        }
        // The signature must verify under exactly the previous root's own
        // ROOT-role key, not under any caller-supplied look-alike key.
        if root_entry.verifying_key()? != *verifying_key {
            return Err(AuthorityProtocolError::TrustRootMismatch);
        }
        // Only a SIGNER-role key may be installed by a rotation.
        if self.new_key.role != AuthorityRootKeyRole::Signer {
            return Err(AuthorityProtocolError::InvalidText {
                field: "new_key_role",
            });
        }
        // The new signer epoch must strictly exceed the previous ACTIVE
        // signer epoch — comparing against the root authorizer epoch alone
        // would accept rolling an epoch-3 signer back to epoch 2.
        if self.new_key.key_epoch <= previous.signer_key()?.key_epoch {
            return Err(AuthorityProtocolError::KeyEpochNonMonotonic);
        }
        // The rotation key id must not collide with any retained key.
        if previous.key_by_id(&self.new_key.key_id).is_some() {
            return Err(AuthorityProtocolError::AlreadyExists {
                record: "new_key_id",
            });
        }
        self.verify(verifying_key)?;
        // Full-history fold: every previous key is retained so previously
        // issued durable artifacts stay verifiable; `signer_key()` selects
        // the highest-epoch signer as the active key.
        let mut next_keys = previous.keys.clone();
        next_keys.push(self.new_key.clone());
        let next = AuthorityTrustRoot {
            root_id: previous.root_id.clone(),
            keys: next_keys,
            created_at: self.issued_at,
        };
        next.validate()?;
        if next.digest()? != self.new_trust_root_digest {
            return Err(AuthorityProtocolError::TrustRootMismatch);
        }
        Ok(next)
    }
}

/// The authority-wide frontier. One logical authority quorum advances this
/// frontier monotonically; linearizable proof reads observe it without
/// advancing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GlobalAuthorityFrontier {
    pub authorization_edition: u16,
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub key_id: String,
    pub key_epoch: u64,
    pub root_id: String,
    pub trust_root_digest: String,
    /// Digest of the authority state-transition chain. Distinct from any
    /// per-scope evidence snapshot hash by construction and by domain.
    pub global_chain_digest: String,
    pub updated_at: i64,
}

impl GlobalAuthorityFrontier {
    /// Construct the very first frontier at genesis, deriving the initial
    /// chain digest from the genesis identity so the chain has a fixed root.
    #[allow(clippy::too_many_arguments)]
    pub fn genesis(
        authority_id: &str,
        root_id: &str,
        trust_root_digest: &str,
        key_id: &str,
        key_epoch: u64,
        updated_at: i64,
    ) -> Result<Self, AuthorityProtocolError> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(GLOBAL_CHAIN_DIGEST_DOMAIN);
        authority_field(&mut bytes, "GENESIS");
        authority_field(&mut bytes, authority_id);
        authority_field(&mut bytes, root_id);
        authority_field(&mut bytes, trust_root_digest);
        let frontier = Self {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: authority_id.to_owned(),
            authority_term: 1,
            global_fence_sequence: 1,
            key_id: key_id.to_owned(),
            key_epoch,
            root_id: root_id.to_owned(),
            trust_root_digest: trust_root_digest.to_owned(),
            global_chain_digest: super::authority_sha256_hex(&bytes),
            updated_at,
        };
        frontier.validate()?;
        Ok(frontier)
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.global_fence_sequence, "global_fence_sequence")?;
        authority_text(&self.key_id, "key_id")?;
        authority_counter(self.key_epoch, "key_epoch")?;
        authority_text(&self.root_id, "root_id")?;
        authority_digest(&self.trust_root_digest, "trust_root_digest")?;
        authority_digest(&self.global_chain_digest, "global_chain_digest")?;
        authority_timestamp(self.updated_at, "updated_at")?;
        Ok(())
    }

    /// Verify the frontier carries exactly the active trust-root identity.
    pub fn matches_trust_root(
        &self,
        trust_root: &AuthorityTrustRoot,
    ) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        trust_root.validate()?;
        if self.root_id != trust_root.root_id || self.trust_root_digest != trust_root.digest()? {
            return Err(AuthorityProtocolError::TrustRootMismatch);
        }
        let signer = trust_root.signer_key()?;
        if self.key_id != signer.key_id || self.key_epoch != signer.key_epoch {
            return Err(AuthorityProtocolError::TrustRootMismatch);
        }
        Ok(())
    }

    /// Derive the next chain digest for one authority mutation.
    ///
    /// `mutation_digest` is a stable digest of the mutation record (operation
    /// id plus its durable payload digest). The chain is injective over the
    /// validated field set and never reuses a per-scope content domain.
    pub fn next_chain_digest(
        &self,
        mutation_operation_id: &str,
        mutation_digest: &str,
    ) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        authority_text(mutation_operation_id, "mutation_operation_id")?;
        authority_digest(mutation_digest, "mutation_digest")?;
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(GLOBAL_CHAIN_DIGEST_DOMAIN);
        authority_field(&mut bytes, &self.global_chain_digest);
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.authority_term.to_string());
        authority_field(&mut bytes, &self.global_fence_sequence.to_string());
        authority_field(&mut bytes, &self.key_epoch.to_string());
        authority_field(&mut bytes, mutation_operation_id);
        authority_field(&mut bytes, mutation_digest);
        Ok(super::authority_sha256_hex(&bytes))
    }

    /// The frontier value after one mutation, with derived chain digest.
    pub fn advance(
        &self,
        mutation_operation_id: &str,
        mutation_digest: &str,
        updated_at: i64,
    ) -> Result<Self, AuthorityProtocolError> {
        let chain_digest = self.next_chain_digest(mutation_operation_id, mutation_digest)?;
        Ok(Self {
            authorization_edition: self.authorization_edition,
            authority_id: self.authority_id.clone(),
            authority_term: self.authority_term,
            global_fence_sequence: self.global_fence_sequence.checked_add(1).ok_or(
                AuthorityProtocolError::InvalidCounter {
                    field: "global_fence_sequence",
                },
            )?,
            key_id: self.key_id.clone(),
            key_epoch: self.key_epoch,
            root_id: self.root_id.clone(),
            trust_root_digest: self.trust_root_digest.clone(),
            global_chain_digest: chain_digest,
            updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8, key_id: &str, epoch: u64, role: AuthorityRootKeyRole) -> AuthorityRootKey {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        AuthorityRootKey {
            key_id: key_id.to_owned(),
            key_epoch: epoch,
            role,
            verifying_key_hex: hex::encode(signing.verifying_key().as_bytes()),
        }
    }

    fn trust_root() -> AuthorityTrustRoot {
        AuthorityTrustRoot {
            root_id: "root-1".to_owned(),
            keys: vec![
                key(1, "signer-1", 1, AuthorityRootKeyRole::Signer),
                key(2, "root-1", 1, AuthorityRootKeyRole::Root),
                key(3, "genesis-1", 1, AuthorityRootKeyRole::Genesis),
            ],
            created_at: 1_000,
        }
    }

    #[test]
    fn trust_root_digest_is_injective_and_validated() {
        let root = trust_root();
        let digest = root.digest().unwrap();
        assert_eq!(digest, root.digest().unwrap());
        let mut other = root.clone();
        other.keys[0].key_epoch = 2;
        assert_ne!(digest, other.digest().unwrap());
        let mut empty = root.clone();
        empty.keys.clear();
        assert!(matches!(
            empty.digest(),
            Err(AuthorityProtocolError::InvalidText { field: "keys" })
        ));
    }

    #[test]
    fn genesis_signature_binds_trust_root_digest() {
        let root = trust_root();
        let genesis_key = SigningKey::from_bytes(&[3; 32]);
        let mut record = AuthorityGenesisRecord {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            root_id: root.root_id.clone(),
            trust_root_digest: root.digest().unwrap(),
            created_at: 1_000,
            genesis_nonce: "genesis-nonce-1".to_owned(),
            signed_by_key_id: String::new(),
            signature: String::new(),
        };
        record.sign(&genesis_key, "genesis-1").unwrap();
        record
            .verify(&root, &root.genesis_key().unwrap().verifying_key().unwrap())
            .unwrap();

        let mut other_root = root.clone();
        other_root.keys[0].key_epoch = 5;
        assert!(matches!(
            record.verify(
                &other_root,
                &root.genesis_key().unwrap().verifying_key().unwrap()
            ),
            Err(AuthorityProtocolError::TrustRootMismatch)
        ));

        let mut tampered = record.clone();
        tampered.authority_id = "authority-2".to_owned();
        assert!(matches!(
            tampered.verify(&root, &root.genesis_key().unwrap().verifying_key().unwrap()),
            Err(AuthorityProtocolError::InvalidSignature)
        ));
    }

    #[test]
    fn rotation_chain_requires_increasing_epochs_and_digest_continuity() {
        let root = trust_root();
        let root_key = SigningKey::from_bytes(&[2; 32]);
        let now = 2_000i64;

        let new_signer = key(4, "signer-2", 2, AuthorityRootKeyRole::Signer);
        // Fold semantics: historical signer keys are retained so previously
        // issued durable artifacts stay verifiable; signer_key() selects the
        // highest epoch.
        let mut next_keys = root.keys.clone();
        next_keys.push(new_signer.clone());
        let next_root = AuthorityTrustRoot {
            root_id: root.root_id.clone(),
            keys: next_keys,
            created_at: now,
        };

        let mut certificate = AuthorityKeyRotationCertificate {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            root_id: root.root_id.clone(),
            previous_key_epoch: 1,
            new_key: new_signer,
            previous_trust_root_digest: root.digest().unwrap(),
            new_trust_root_digest: next_root.digest().unwrap(),
            rotation_nonce: "rotation-nonce-1".to_owned(),
            issued_at: now,
            not_before: now,
            expires_at: now + 300,
            signed_by_key_id: String::new(),
            signature: String::new(),
        };
        certificate.sign(&root_key, "root-1").unwrap();
        let verified = certificate
            .verify_after(&root, &root.root_key().unwrap().verifying_key().unwrap())
            .unwrap();
        assert_eq!(verified.digest().unwrap(), next_root.digest().unwrap());
        assert_eq!(
            verified.signer_key().unwrap().key_id,
            "signer-2",
            "active signer must be the highest-epoch signer key"
        );

        let mut regressed = certificate.clone();
        regressed.previous_key_epoch = 2;
        regressed.signature = String::new();
        assert!(matches!(
            regressed.sign(&root_key, "root-1"),
            Err(AuthorityProtocolError::KeyEpochNonMonotonic)
        ));

        // Time validity is a separate, explicit check for NEW applications.
        let stale = certificate.clone();
        assert!(matches!(
            stale.validate_at(now + 1_000),
            Err(AuthorityProtocolError::NotCurrentlyValid)
        ));
    }

    /// Build and root-sign a rotation certificate over `active`, declaring
    /// `declared_digest` as the new trust root digest.
    fn signed_rotation(
        active: &AuthorityTrustRoot,
        new_key: AuthorityRootKey,
        declared_digest: String,
        now: i64,
    ) -> AuthorityKeyRotationCertificate {
        let root_signing = SigningKey::from_bytes(&[2; 32]);
        let mut certificate = AuthorityKeyRotationCertificate {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            root_id: active.root_id.clone(),
            previous_key_epoch: active.root_key().unwrap().key_epoch,
            new_key,
            previous_trust_root_digest: active.digest().unwrap(),
            new_trust_root_digest: declared_digest,
            rotation_nonce: "rotation-nonce".to_owned(),
            issued_at: now,
            not_before: now,
            expires_at: now + 300,
            signed_by_key_id: String::new(),
            signature: String::new(),
        };
        certificate.sign(&root_signing, "root-1").unwrap();
        certificate
    }

    /// The full-history fold: every previous key retained, new key appended.
    fn folded_root(
        active: &AuthorityTrustRoot,
        new_key: &AuthorityRootKey,
        now: i64,
    ) -> AuthorityTrustRoot {
        let mut keys = active.keys.clone();
        keys.push(new_key.clone());
        AuthorityTrustRoot {
            root_id: active.root_id.clone(),
            keys,
            created_at: now,
        }
    }

    #[test]
    fn two_consecutive_rotations_preserve_full_history_and_bind_digests() {
        let root = trust_root();
        let mut active = root.clone();
        for (now, (key_id, seed, epoch)) in
            (2_000i64..).zip([("signer-2", 4u8, 2u64), ("signer-3", 5u8, 3u64)])
        {
            let new_signer = key(seed, key_id, epoch, AuthorityRootKeyRole::Signer);
            let next_root = folded_root(&active, &new_signer, now);
            let certificate =
                signed_rotation(&active, new_signer, next_root.digest().unwrap(), now);
            let verified = certificate
                .verify_after(
                    &active,
                    &active.root_key().unwrap().verifying_key().unwrap(),
                )
                .unwrap();
            assert_eq!(verified, next_root);
            // The folded root is stamped from the same certificate clock.
            assert_eq!(verified.created_at, certificate.issued_at);
            assert_eq!(verified.signer_key().unwrap().key_id, key_id);
            // Root and genesis entries survive every rotation byte-exactly.
            assert_eq!(verified.root_key().unwrap(), root.root_key().unwrap());
            assert_eq!(verified.genesis_key().unwrap(), root.genesis_key().unwrap());
            active = verified;
        }
        // The full chain history is retained and every historical key still
        // parses: previously issued durable artifacts stay verifiable.
        for retained in ["signer-1", "signer-2", "signer-3"] {
            assert!(active.key_by_id(retained).is_some());
            assert!(active.key_by_id(retained).unwrap().verifying_key().is_ok());
        }
    }

    #[test]
    fn rotation_rejects_signer_epoch_rollback() {
        let root = trust_root();
        // A chain whose signer already rotated to epoch 3 while the root
        // authorizer epoch stayed at 1.
        let mut active = root.clone();
        for (key_id, seed, epoch) in [("signer-2", 4u8, 2u64), ("signer-3", 5u8, 3u64)] {
            let new_signer = key(seed, key_id, epoch, AuthorityRootKeyRole::Signer);
            let next_root = folded_root(&active, &new_signer, 2_000);
            let certificate =
                signed_rotation(&active, new_signer, next_root.digest().unwrap(), 2_000);
            active = certificate
                .verify_after(
                    &active,
                    &active.root_key().unwrap().verifying_key().unwrap(),
                )
                .unwrap();
        }
        assert_eq!(active.signer_key().unwrap().key_epoch, 3);
        // A properly signed rotation back to the still-unused epoch 2 must be
        // refused: epochs are compared against the ACTIVE signer, not the
        // root authorizer epoch.
        let rollback = key(9, "signer-2b", 2, AuthorityRootKeyRole::Signer);
        let declared = folded_root(&active, &rollback, 3_000);
        let certificate = signed_rotation(&active, rollback, declared.digest().unwrap(), 3_000);
        assert!(matches!(
            certificate.verify_after(
                &active,
                &active.root_key().unwrap().verifying_key().unwrap()
            ),
            Err(AuthorityProtocolError::KeyEpochNonMonotonic)
        ));
    }

    #[test]
    fn rotation_rejects_history_erasing_fold_digest() {
        let root = trust_root();
        let new_signer = key(4, "signer-2", 2, AuthorityRootKeyRole::Signer);
        // An attacker-declared digest over a fold that ERASES signer-1.
        let mut erasing_keys: Vec<AuthorityRootKey> = root
            .keys
            .iter()
            .filter(|key| key.role != AuthorityRootKeyRole::Signer)
            .cloned()
            .collect();
        erasing_keys.push(new_signer.clone());
        let erasing_root = AuthorityTrustRoot {
            root_id: root.root_id.clone(),
            keys: erasing_keys,
            created_at: 2_000,
        };
        let certificate = signed_rotation(&root, new_signer, erasing_root.digest().unwrap(), 2_000);
        // verify_after folds with full history, so the erasing digest cannot
        // match: history-deleting rotations are structurally unrepresentable.
        assert!(matches!(
            certificate.verify_after(&root, &root.root_key().unwrap().verifying_key().unwrap()),
            Err(AuthorityProtocolError::TrustRootMismatch)
        ));
    }

    #[test]
    fn rotation_requires_exact_root_authorizer_and_signature() {
        let root = trust_root();
        let root_signing = SigningKey::from_bytes(&[2; 32]);
        let signer_signing = SigningKey::from_bytes(&[1; 32]);
        let genesis_signing = SigningKey::from_bytes(&[3; 32]);
        let new_signer = key(4, "signer-2", 2, AuthorityRootKeyRole::Signer);
        let next_root = folded_root(&root, &new_signer, 2_000);

        // (a) signed_by_key_id naming the SIGNER-role key is refused by role,
        // even though that key produced a valid signature.
        let mut by_signer = signed_rotation(
            &root,
            new_signer.clone(),
            next_root.digest().unwrap(),
            2_000,
        );
        by_signer.signed_by_key_id = String::new();
        by_signer.signature = String::new();
        by_signer.sign(&signer_signing, "signer-1").unwrap();
        assert!(matches!(
            by_signer.verify_after(&root, &root.root_key().unwrap().verifying_key().unwrap()),
            Err(AuthorityProtocolError::InvalidText {
                field: "signed_by_key_id"
            })
        ));

        // (b) previous_key_epoch keeps its wire meaning: the ROOT authorizer
        // epoch. Claiming the signer epoch instead is non-monotonic.
        let signer3 = key(6, "signer-2", 3, AuthorityRootKeyRole::Signer);
        let next3 = folded_root(&root, &signer3, 2_000);
        let mut epoch_mismatch = signed_rotation(&root, signer3, next3.digest().unwrap(), 2_000);
        epoch_mismatch.signed_by_key_id = String::new();
        epoch_mismatch.signature = String::new();
        epoch_mismatch.previous_key_epoch = 2; // the SIGNER epoch, not the root epoch
        epoch_mismatch.sign(&root_signing, "root-1").unwrap();
        assert!(matches!(
            epoch_mismatch.verify_after(&root, &root.root_key().unwrap().verifying_key().unwrap()),
            Err(AuthorityProtocolError::KeyEpochNonMonotonic)
        ));

        // (c) the verifying key must be exactly the previous root's own ROOT
        // key; a caller passing the signer key cannot launder a rotation.
        let proper = signed_rotation(
            &root,
            new_signer.clone(),
            next_root.digest().unwrap(),
            2_000,
        );
        assert!(matches!(
            proper.verify_after(&root, &root.signer_key().unwrap().verifying_key().unwrap()),
            Err(AuthorityProtocolError::TrustRootMismatch)
        ));

        // (d) a signature over the same bytes by any other key is invalid.
        let mut forged = signed_rotation(&root, new_signer, next_root.digest().unwrap(), 2_000);
        let signature = genesis_signing.sign(&forged.signing_bytes().unwrap());
        forged.signature = hex::encode(signature.to_bytes());
        assert!(matches!(
            forged.verify_after(&root, &root.root_key().unwrap().verifying_key().unwrap()),
            Err(AuthorityProtocolError::InvalidSignature)
        ));
    }

    #[test]
    fn rotation_rejects_reused_key_id() {
        let root = trust_root();
        let reused = key(4, "signer-1", 2, AuthorityRootKeyRole::Signer);
        let certificate = signed_rotation(&root, reused, "ab".repeat(32), 2_000);
        assert!(matches!(
            certificate.verify_after(&root, &root.root_key().unwrap().verifying_key().unwrap()),
            Err(AuthorityProtocolError::AlreadyExists {
                record: "new_key_id"
            })
        ));
    }

    #[test]
    fn rotation_must_install_signer_role_key() {
        let root = trust_root();
        let root_role = key(7, "root-2", 2, AuthorityRootKeyRole::Root);
        let certificate = signed_rotation(&root, root_role, "ab".repeat(32), 2_000);
        assert!(matches!(
            certificate.verify_after(&root, &root.root_key().unwrap().verifying_key().unwrap()),
            Err(AuthorityProtocolError::InvalidText {
                field: "new_key_role"
            })
        ));
    }

    #[test]
    fn genesis_frontier_derives_chain_digest_and_validates() {
        let root = trust_root();
        let genesis = GlobalAuthorityFrontier::genesis(
            "authority-1",
            &root.root_id,
            &root.digest().unwrap(),
            "signer-1",
            1,
            1_000,
        )
        .unwrap();
        assert_eq!(genesis.global_fence_sequence, 1);
        assert_eq!(genesis.authority_term, 1);
        assert!(!genesis.global_chain_digest.is_empty());
        genesis.validate().unwrap();
        genesis.matches_trust_root(&root).unwrap();

        let mut other = GlobalAuthorityFrontier::genesis(
            "authority-1",
            &root.root_id,
            &root.digest().unwrap(),
            "signer-1",
            1,
            1_000,
        )
        .unwrap();
        other.updated_at = 2_000;
        assert_eq!(
            genesis.global_chain_digest, other.global_chain_digest,
            "genesis chain digest is clock-independent"
        );

        let mut tampered = genesis.clone();
        tampered.global_chain_digest = String::new();
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn global_frontier_advance_is_monotonic_with_distinct_chain_domain() {
        let root = trust_root();
        let frontier = GlobalAuthorityFrontier {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            authority_term: 1,
            global_fence_sequence: 3,
            key_id: "signer-1".to_owned(),
            key_epoch: 1,
            root_id: root.root_id.clone(),
            trust_root_digest: root.digest().unwrap(),
            global_chain_digest: "aa".repeat(32),
            updated_at: 1_000,
        };
        frontier.matches_trust_root(&root).unwrap();

        let next = frontier
            .advance("operation-1", &"bb".repeat(32), 1_100)
            .unwrap();
        assert_eq!(next.global_fence_sequence, 4);
        assert_ne!(next.global_chain_digest, frontier.global_chain_digest);
        assert_ne!(next.global_chain_digest, "bb".repeat(32));
        next.validate().unwrap();

        let mut mismatched = frontier.clone();
        mismatched.key_epoch = 9;
        assert!(matches!(
            mismatched.matches_trust_root(&root),
            Err(AuthorityProtocolError::TrustRootMismatch)
        ));
    }
}
