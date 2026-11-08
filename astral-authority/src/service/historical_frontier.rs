//! Historical signer identity for immutable authority receipts.
//!
//! Receipts retain the frontier committed with them. A later rotation changes
//! the active trust root, so replay must match one verified root in the retained
//! chain rather than require the genesis or current signer. The durable receipt
//! supplies the historical transition; this check does not recreate a missing
//! authority transition log.

use astral_types::{AuthoritySourceBootstrapCompletionReceipt, GlobalAuthorityFrontier};
use ed25519_dalek::VerifyingKey;

use super::VerifiedAuthorityState;
use crate::error::{AuthorityServiceError, AuthorityStoreError};

impl VerifiedAuthorityState {
    pub(super) fn verify_source_bootstrap_completion_receipt(
        &self,
        receipt: &AuthoritySourceBootstrapCompletionReceipt,
    ) -> Result<(), AuthorityServiceError> {
        receipt
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if receipt.authority_id != self.frontier.authority_id
            || receipt.authority_term != receipt.frontier.authority_term
            || receipt.global_fence_sequence != receipt.frontier.global_fence_sequence
            || receipt.key_id != receipt.frontier.key_id
            || receipt.key_epoch != receipt.frontier.key_epoch
        {
            return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "source bootstrap completion receipt binding is inconsistent".to_owned(),
            )));
        }
        let key = self.verify_historical_signer_key(&receipt.frontier)?;
        receipt
            .verify(&key)
            .map_err(AuthorityServiceError::Protocol)
    }

    pub(super) fn verify_historical_signer_key(
        &self,
        frontier: &GlobalAuthorityFrontier,
    ) -> Result<VerifyingKey, AuthorityServiceError> {
        self.verify_historical_frontier(frontier)?;
        let mut root = self.genesis_trust_root.clone();
        if frontier.matches_trust_root(&root).is_err() {
            for rotation in &self.rotations {
                if rotation.authority_id != self.frontier.authority_id {
                    return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "historical rotation belongs to another authority".to_owned(),
                    )));
                }
                let key = root
                    .root_key()
                    .and_then(|entry| entry.verifying_key())
                    .map_err(AuthorityServiceError::Protocol)?;
                root = rotation
                    .verify_after(&root, &key)
                    .map_err(AuthorityServiceError::Protocol)?;
                if frontier.matches_trust_root(&root).is_ok() {
                    break;
                }
            }
        }
        let signer = root
            .key_by_id(&frontier.key_id)
            .filter(|key| {
                key.role == astral_types::AuthorityRootKeyRole::Signer
                    && key.key_epoch == frontier.key_epoch
            })
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "historical receipt signer is absent from the verified authority history"
                        .to_owned(),
                ))
            })?;
        signer
            .verifying_key()
            .map_err(AuthorityServiceError::Protocol)
    }
}

impl VerifiedAuthorityState {
    pub(super) fn verify_historical_frontier(
        &self,
        frontier: &GlobalAuthorityFrontier,
    ) -> Result<(), AuthorityServiceError> {
        frontier
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if frontier.authority_id != self.frontier.authority_id
            || frontier.root_id != self.frontier.root_id
            || frontier.authority_term > self.frontier.authority_term
            || frontier.global_fence_sequence > self.frontier.global_fence_sequence
            || (frontier.global_fence_sequence == self.frontier.global_fence_sequence
                && frontier != &self.frontier)
        {
            return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "receipt frontier conflicts with the verified authority frontier".to_owned(),
            )));
        }

        let mut root = self.genesis_trust_root.clone();
        if frontier.matches_trust_root(&root).is_ok() {
            return Ok(());
        }
        for rotation in &self.rotations {
            if rotation.authority_id != self.frontier.authority_id {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "historical rotation belongs to another authority".to_owned(),
                )));
            }
            let key = root
                .root_key()
                .and_then(|entry| entry.verifying_key())
                .map_err(AuthorityServiceError::Protocol)?;
            root = rotation
                .verify_after(&root, &key)
                .map_err(AuthorityServiceError::Protocol)?;
            if frontier.matches_trust_root(&root).is_ok() {
                return Ok(());
            }
        }
        Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
            "receipt signer identity is absent from the verified authority history".to_owned(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{
        AuthorityKeyRotationCertificate, AuthorityRootKey, AuthorityRootKeyRole,
        AuthorityTrustRoot, AUTHORIZATION_EDITION,
    };
    use ed25519_dalek::SigningKey;

    fn fixture() -> (VerifiedAuthorityState, GlobalAuthorityFrontier) {
        let root_key = SigningKey::from_bytes(&[31; 32]);
        let first_signer = SigningKey::from_bytes(&[32; 32]);
        let second_signer = SigningKey::from_bytes(&[33; 32]);
        let genesis = AuthorityTrustRoot {
            root_id: "historical-root".to_owned(),
            keys: vec![
                AuthorityRootKey {
                    key_id: "historical-root".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Root,
                    verifying_key_hex: hex::encode(root_key.verifying_key().as_bytes()),
                },
                AuthorityRootKey {
                    key_id: "historical-signer-1".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Signer,
                    verifying_key_hex: hex::encode(first_signer.verifying_key().as_bytes()),
                },
                AuthorityRootKey {
                    key_id: "historical-genesis".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Genesis,
                    verifying_key_hex: hex::encode(
                        SigningKey::from_bytes(&[34; 32]).verifying_key().as_bytes(),
                    ),
                },
            ],
            created_at: 1_000,
        };
        let first = GlobalAuthorityFrontier::genesis(
            "historical-authority",
            &genesis.root_id,
            &genesis.digest().unwrap(),
            "historical-signer-1",
            1,
            1_000,
        )
        .unwrap();
        let new_key = AuthorityRootKey {
            key_id: "historical-signer-2".to_owned(),
            key_epoch: 2,
            role: AuthorityRootKeyRole::Signer,
            verifying_key_hex: hex::encode(second_signer.verifying_key().as_bytes()),
        };
        let mut active = genesis.clone();
        active.keys.push(new_key.clone());
        active.created_at = 1_001;
        let mut rotation = AuthorityKeyRotationCertificate {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: first.authority_id.clone(),
            root_id: genesis.root_id.clone(),
            previous_key_epoch: 1,
            new_key,
            previous_trust_root_digest: genesis.digest().unwrap(),
            new_trust_root_digest: active.digest().unwrap(),
            rotation_nonce: "historical-rotation".to_owned(),
            issued_at: 1_001,
            not_before: 1_001,
            expires_at: 2_000,
            signed_by_key_id: String::new(),
            signature: String::new(),
        };
        rotation.sign(&root_key, "historical-root").unwrap();
        let mut rotated = first.advance("rotation", &"aa".repeat(32), 1_001).unwrap();
        rotated.authority_term = 2;
        rotated.key_id = "historical-signer-2".to_owned();
        rotated.key_epoch = 2;
        rotated.trust_root_digest = active.digest().unwrap();
        let current = rotated
            .advance("later-operation", &"bb".repeat(32), 1_002)
            .unwrap();
        (
            VerifiedAuthorityState {
                genesis_trust_root: genesis,
                rotations: vec![rotation],
                trust_root: active,
                frontier: current,
                frontier_revision: 3,
                gate_epoch: 3,
                gate_epoch_revision: 3,
            },
            rotated,
        )
    }

    #[test]
    fn accepts_retained_genesis_and_rotated_signers_after_frontier_advance() {
        let (state, rotated) = fixture();
        state.verify_historical_frontier(&rotated).unwrap();
        state.verify_historical_frontier(&state.frontier).unwrap();
        let genesis = GlobalAuthorityFrontier::genesis(
            &state.frontier.authority_id,
            &state.genesis_trust_root.root_id,
            &state.genesis_trust_root.digest().unwrap(),
            "historical-signer-1",
            1,
            1_000,
        )
        .unwrap();
        state.verify_historical_frontier(&genesis).unwrap();
    }

    #[test]
    fn rejects_unknown_root_digest_key_and_epoch() {
        let (state, rotated) = fixture();
        let mut unknown_digest = rotated.clone();
        unknown_digest.trust_root_digest = "cc".repeat(32);
        assert!(state.verify_historical_frontier(&unknown_digest).is_err());
        let mut unknown_key = rotated.clone();
        unknown_key.key_id = "unregistered-signer".to_owned();
        assert!(state.verify_historical_frontier(&unknown_key).is_err());
        let mut wrong_epoch = rotated;
        wrong_epoch.key_epoch = 1;
        assert!(state.verify_historical_frontier(&wrong_epoch).is_err());
    }

    #[test]
    fn rejects_other_authority_future_and_divergent_current_frontier() {
        let (state, rotated) = fixture();
        let mut other = rotated.clone();
        other.authority_id = "other-authority".to_owned();
        assert!(state.verify_historical_frontier(&other).is_err());
        let mut future = rotated;
        future.global_fence_sequence = state.frontier.global_fence_sequence + 1;
        assert!(state.verify_historical_frontier(&future).is_err());
        let mut divergent = state.frontier.clone();
        divergent.global_chain_digest = "dd".repeat(32);
        assert!(state.verify_historical_frontier(&divergent).is_err());
    }

    #[test]
    fn rejects_corrupted_or_foreign_rotation_chain() {
        let (mut state, rotated) = fixture();
        state.rotations[0].signature = "00".repeat(64);
        assert!(state.verify_historical_frontier(&rotated).is_err());
        let (mut state, rotated) = fixture();
        state.rotations[0].authority_id = "other-authority".to_owned();
        assert!(state.verify_historical_frontier(&rotated).is_err());
    }
}
