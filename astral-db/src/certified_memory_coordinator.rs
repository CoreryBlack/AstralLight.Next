//! Local root/snapshot coordination for CertifiedMemory.
//!
//! This module accepts only already verified authority-root observations and
//! already materialized family completions. It never reads SQL, raw source,
//! mirrors, queues, heartbeats, or transport acknowledgements. Its purpose is
//! to make the final identity and readiness checks explicit before the existing
//! `CertifiedMemoryRuntime` can expose positive reads.

use std::sync::{Arc, RwLock};

use astral_types::authority_protocol::{
    AuthorityCertifiedMemoryFamily, AuthorityCertifiedMemoryRoot, AuthorityFamilyCompletion,
    AuthorityFamilyScope,
};
use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::certified_memory_authority::{
    CertifiedMemoryAttestation, CertifiedMemoryInvalidation, CertifiedMemorySnapshot,
};
use crate::certified_memory_readiness::{
    CertifiedMemoryLeaseBinding, CertifiedMemoryReadinessCapability, CertifiedMemoryReadinessOwner,
    ReadinessError,
};
use crate::certified_memory_snapshot_builder::{
    CertifiedMemoryReadiness, CertifiedMemoryRuntime, CertifiedMemoryRuntimeError,
    CertifiedMemoryRuntimeState,
};

/// An authority observation is created only after the caller has verified the
/// signed root with the pinned authority signer key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMemoryRootObservation {
    root: AuthorityCertifiedMemoryRoot,
    record_digest: String,
    observed_at_unix: i64,
    client_verified: bool,
}

impl CertifiedMemoryRootObservation {
    pub fn from_verified_root(
        root: AuthorityCertifiedMemoryRoot,
        verifying_key: &VerifyingKey,
        now_unix: i64,
    ) -> Result<Self, CertifiedMemoryCoordinatorError> {
        root.verify_at(verifying_key, now_unix)
            .map_err(|error| CertifiedMemoryCoordinatorError::RootInvalid(error.to_string()))?;
        let record_digest = root
            .record_digest()
            .map_err(|error| CertifiedMemoryCoordinatorError::RootInvalid(error.to_string()))?;
        Ok(Self {
            root,
            record_digest,
            observed_at_unix: now_unix,
            client_verified: false,
        })
    }

    pub(crate) fn from_client_verified_root(
        client: &astral_authority::client::AuthorityClient,
        observation: &astral_authority::client::VerifiedCertifiedMemoryRoot,
        now_unix: i64,
    ) -> Result<Self, CertifiedMemoryCoordinatorError> {
        let (root, key) = observation
            .verified_root_and_key(client)
            .map_err(|error| CertifiedMemoryCoordinatorError::RootInvalid(error.to_string()))?;
        let mut result = Self::from_verified_root(root.clone(), &key, now_unix)?;
        result.client_verified = true;
        Ok(result)
    }

    pub fn validate_at(&self, now_unix: i64) -> Result<(), CertifiedMemoryCoordinatorError> {
        self.root
            .validate()
            .map_err(|error| CertifiedMemoryCoordinatorError::RootInvalid(error.to_string()))?;
        if now_unix < self.observed_at_unix
            || now_unix < self.root.not_before
            || now_unix >= self.root.expires_at
        {
            return Err(CertifiedMemoryCoordinatorError::RootExpired);
        }
        let expected = self
            .root
            .record_digest()
            .map_err(|error| CertifiedMemoryCoordinatorError::RootInvalid(error.to_string()))?;
        if expected != self.record_digest {
            return Err(CertifiedMemoryCoordinatorError::RootRecordMismatch);
        }
        Ok(())
    }
}

/// A family bundle is valid only when every closed family is present exactly
/// once, terminal, and bound to one exact scope and generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMemoryFamilyBundle {
    pub scope: AuthorityFamilyScope,
    pub completions: Vec<AuthorityFamilyCompletion>,
    pub bundle_digest: String,
}

impl CertifiedMemoryFamilyBundle {
    pub fn build(
        scope: AuthorityFamilyScope,
        completions: Vec<AuthorityFamilyCompletion>,
    ) -> Result<Self, CertifiedMemoryCoordinatorError> {
        scope
            .validate()
            .map_err(|error| CertifiedMemoryCoordinatorError::FamilyInvalid(error.to_string()))?;
        if completions.len() != AuthorityCertifiedMemoryFamily::required().len() {
            return Err(CertifiedMemoryCoordinatorError::FamilyCoverageIncomplete);
        }
        let mut expected_generation = None;
        let mut expected_revoke = None;
        let mut seen = Vec::with_capacity(completions.len());
        let mut digests = Vec::with_capacity(completions.len());
        for completion in &completions {
            completion.validate().map_err(|error| {
                CertifiedMemoryCoordinatorError::FamilyInvalid(error.to_string())
            })?;
            if !completion.state.is_terminal_complete() {
                return Err(CertifiedMemoryCoordinatorError::FamilyNotComplete {
                    family: completion.family,
                });
            }
            if completion.scope != scope {
                return Err(CertifiedMemoryCoordinatorError::FamilyScopeMismatch);
            }
            if expected_generation
                .replace(completion.scope_generation)
                .is_some_and(|generation| generation != completion.scope_generation)
                || expected_revoke
                    .replace(completion.revoke_watermark)
                    .is_some_and(|watermark| watermark != completion.revoke_watermark)
            {
                return Err(CertifiedMemoryCoordinatorError::FamilyFrontierMismatch);
            }
            if seen.contains(&completion.family) {
                return Err(CertifiedMemoryCoordinatorError::DuplicateFamily {
                    family: completion.family,
                });
            }
            seen.push(completion.family);
            digests.push((
                completion.family,
                completion.completion_digest().map_err(|error| {
                    CertifiedMemoryCoordinatorError::FamilyInvalid(error.to_string())
                })?,
            ));
        }
        if AuthorityCertifiedMemoryFamily::required()
            .iter()
            .any(|family| !seen.contains(family))
        {
            return Err(CertifiedMemoryCoordinatorError::FamilyCoverageIncomplete);
        }
        digests.sort_by_key(|(family, _)| family.as_text());
        let mut bytes = Vec::with_capacity(64 + digests.len() * 80);
        bytes.extend_from_slice(b"ASTRAL_CERTIFIED_MEMORY_FAMILY_BUNDLE_V1\0");
        append_field(
            &mut bytes,
            &scope
                .tenant_id
                .map_or_else(|| "-".to_owned(), |id| id.to_string()),
        );
        append_field(&mut bytes, &scope.scope);
        for (family, digest) in digests {
            append_field(&mut bytes, family.as_text());
            append_field(&mut bytes, &digest);
        }
        let bundle_digest = sha256_hex(&bytes);
        Ok(Self {
            scope,
            completions,
            bundle_digest,
        })
    }

    pub fn generation(&self) -> u64 {
        self.completions[0].scope_generation
    }

    pub fn revoke_watermark(&self) -> u64 {
        self.completions[0].revoke_watermark
    }
}

/// Errors returned before a positive read gate can be opened.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifiedMemoryCoordinatorError {
    #[error("authority root is invalid: {0}")]
    RootInvalid(String),
    #[error("authority root is expired or was observed at the wrong time")]
    RootExpired,
    #[error("authority root record digest does not match the immutable root")]
    RootRecordMismatch,
    #[error("family completion is invalid: {0}")]
    FamilyInvalid(String),
    #[error("family coverage is incomplete")]
    FamilyCoverageIncomplete,
    #[error("family {family:?} is not terminally complete")]
    FamilyNotComplete {
        family: AuthorityCertifiedMemoryFamily,
    },
    #[error("family {family:?} is duplicated")]
    DuplicateFamily {
        family: AuthorityCertifiedMemoryFamily,
    },
    #[error("family scope bindings differ")]
    FamilyScopeMismatch,
    #[error("family generation or revoke watermark differs")]
    FamilyFrontierMismatch,
    #[error("snapshot content digest does not match authority root")]
    SnapshotDigestMismatch,
    #[error("snapshot identity fields do not match authority root")]
    SnapshotBindingMismatch,
    #[error("family bundle digest does not match authority source outcome")]
    FamilyBundleDigestMismatch,
    #[error("readiness proof is not complete")]
    ReadinessPending,
    #[error("coordinator generation does not match the installed candidate")]
    GenerationMismatch,
    #[error("runtime transition failed: {0}")]
    Runtime(#[from] CertifiedMemoryRuntimeError),
    #[error("readiness capability rejected: {0}")]
    Readiness(#[from] ReadinessError),
}

/// Local coordinator joining already verified authority evidence to the
/// immutable process-local store. It is intentionally not an HTTP or SQL owner.
#[derive(Debug)]
pub struct CertifiedMemoryCoordinator {
    runtime: Arc<CertifiedMemoryRuntime>,
    binding: RwLock<Option<PreparedBinding>>,
}

#[derive(Debug)]
struct PreparedBinding {
    root: CertifiedMemoryRootObservation,
    owner: Option<CertifiedMemoryReadinessOwner>,
}

impl CertifiedMemoryCoordinator {
    pub fn new(runtime: Arc<CertifiedMemoryRuntime>) -> Self {
        Self {
            runtime,
            binding: RwLock::new(None),
        }
    }

    pub fn runtime(&self) -> Arc<CertifiedMemoryRuntime> {
        Arc::clone(&self.runtime)
    }

    pub fn state(&self) -> CertifiedMemoryRuntimeState {
        self.runtime.state()
    }

    pub fn readiness(&self, now_unix: i64) -> CertifiedMemoryReadiness {
        self.runtime.readiness(now_unix)
    }

    /// Validate identity and install a candidate. This ends in FenceSyncing;
    /// callers must provide separate readiness proofs to open Serving.
    pub fn prepare(
        &self,
        snapshot: Arc<CertifiedMemorySnapshot>,
        families: &CertifiedMemoryFamilyBundle,
        root: CertifiedMemoryRootObservation,
        now_unix: i64,
    ) -> Result<u64, CertifiedMemoryCoordinatorError> {
        root.validate_at(now_unix)?;
        if !root.client_verified {
            return Err(CertifiedMemoryCoordinatorError::RootInvalid(
                "authority client verification required".to_owned(),
            ));
        }
        let verified_families = CertifiedMemoryFamilyBundle::build(
            families.scope.clone(),
            families.completions.clone(),
        )?;
        if &verified_families != families {
            return Err(CertifiedMemoryCoordinatorError::FamilyBundleDigestMismatch);
        }
        let snapshot_hash = snapshot
            .content_digest()
            .map_err(CertifiedMemoryCoordinatorError::RootInvalid)?;
        if snapshot_hash != root.root.snapshot_hash {
            return Err(CertifiedMemoryCoordinatorError::SnapshotDigestMismatch);
        }
        if root.root.family_bundle_digest != families.bundle_digest {
            return Err(CertifiedMemoryCoordinatorError::FamilyBundleDigestMismatch);
        }
        if snapshot.generation() != root.root.scope_generation
            || snapshot.generation() != families.generation()
            || root.root.revoke_watermark != families.revoke_watermark()
        {
            return Err(CertifiedMemoryCoordinatorError::SnapshotBindingMismatch);
        }
        if snapshot.expires_at_unix() > root.root.expires_at
            || snapshot.installed_at_unix() < root.root.not_before
        {
            return Err(CertifiedMemoryCoordinatorError::SnapshotBindingMismatch);
        }
        let attestation = snapshot
            .attestation()
            .ok_or(CertifiedMemoryCoordinatorError::SnapshotBindingMismatch)?;
        validate_attestation(&attestation, &root.root, snapshot.generation(), now_unix)?;

        let mut binding = self.binding.write().map_err(|_| {
            CertifiedMemoryCoordinatorError::Runtime(CertifiedMemoryRuntimeError::StateUnavailable)
        })?;
        if let Some(previous) = binding.take() {
            if let Some(owner) = previous.owner {
                owner.invalidate(CertifiedMemoryInvalidation::Unknown)?;
            }
        }
        if self.runtime.state() == CertifiedMemoryRuntimeState::Serving {
            self.runtime
                .invalidate(CertifiedMemoryInvalidation::Unknown)?;
        }
        let generation = snapshot.generation();
        self.runtime.install_coordinated(snapshot, now_unix)?;
        self.runtime.begin_fence_sync(generation)?;
        *binding = Some(PreparedBinding { root, owner: None });
        Ok(generation)
    }

    /// Create exactly one owner for this prepared authority observation.
    pub(crate) fn readiness_owner(
        &self,
        lease: CertifiedMemoryLeaseBinding,
    ) -> Result<CertifiedMemoryReadinessOwner, CertifiedMemoryCoordinatorError> {
        let mut binding = self
            .binding
            .write()
            .map_err(|_| CertifiedMemoryRuntimeError::StateUnavailable)?;
        let prepared = binding
            .as_mut()
            .ok_or(CertifiedMemoryCoordinatorError::RootRecordMismatch)?;
        if prepared.owner.is_some()
            || self.runtime.state() != CertifiedMemoryRuntimeState::FenceSyncing
        {
            return Err(CertifiedMemoryCoordinatorError::ReadinessPending);
        }
        let owner = CertifiedMemoryReadinessOwner::new(
            prepared.root.root.root_digest.clone(),
            prepared.root.root.scope_generation,
            lease,
            Arc::clone(&self.runtime),
        );
        prepared.owner = Some(owner.clone());
        Ok(owner)
    }

    /// Activate while holding both the prepared binding and owner evidence locks.
    pub(crate) fn complete_serving(
        &self,
        generation: u64,
        readiness: &CertifiedMemoryReadinessCapability,
        now_unix: i64,
    ) -> Result<(), CertifiedMemoryCoordinatorError> {
        let binding = self
            .binding
            .read()
            .map_err(|_| CertifiedMemoryRuntimeError::StateUnavailable)?;
        if self.runtime.state() != CertifiedMemoryRuntimeState::FenceSyncing
            || self.runtime.store().installed_generation() != Some(generation)
        {
            return Err(CertifiedMemoryCoordinatorError::GenerationMismatch);
        }
        let prepared = binding
            .as_ref()
            .ok_or(CertifiedMemoryCoordinatorError::RootRecordMismatch)?;
        let root = &prepared.root;
        root.validate_at(now_unix)?;
        if root.root.scope_generation != generation {
            return Err(CertifiedMemoryCoordinatorError::GenerationMismatch);
        }
        let owner = prepared
            .owner
            .as_ref()
            .ok_or(CertifiedMemoryCoordinatorError::ReadinessPending)?;
        owner.with_capability(readiness, &root.root.root_digest, generation, || {
            self.runtime.mark_serving_coordinated(generation, now_unix)
        })??;
        Ok(())
    }

    #[cfg(test)]
    fn complete_serving_assertion(
        &self,
        _generation: u64,
        _now_unix: i64,
    ) -> Result<(), CertifiedMemoryCoordinatorError> {
        Err(CertifiedMemoryCoordinatorError::ReadinessPending)
    }

    pub fn invalidate(
        &self,
        invalidation: CertifiedMemoryInvalidation,
    ) -> Result<(), CertifiedMemoryCoordinatorError> {
        let mut binding = match self.binding.write() {
            Ok(binding) => binding,
            Err(_) => {
                let _ = self.runtime.invalidate(invalidation);
                return Err(CertifiedMemoryRuntimeError::StateUnavailable.into());
            }
        };
        if let Some(prepared) = binding.as_mut() {
            if let Some(owner) = prepared.owner.as_ref() {
                owner.invalidate(invalidation)?;
            }
        }
        self.runtime.invalidate(invalidation)?;
        *binding = None;
        Ok(())
    }

    pub fn prepared_root_record_digest(&self) -> Option<String> {
        self.binding.read().ok().and_then(|binding| {
            binding
                .as_ref()
                .map(|prepared| prepared.root.record_digest.clone())
        })
    }
}

fn validate_attestation(
    attestation: &CertifiedMemoryAttestation,
    root: &AuthorityCertifiedMemoryRoot,
    generation: u64,
    now_unix: i64,
) -> Result<(), CertifiedMemoryCoordinatorError> {
    attestation
        .validate_at(generation, now_unix)
        .map_err(|_| CertifiedMemoryCoordinatorError::SnapshotBindingMismatch)?;
    if attestation.authority_term != root.authority_term
        || attestation.global_fence_sequence != root.global_fence_sequence
        || attestation.key_epoch != root.key_epoch
        || attestation.scope_generation != root.scope_generation
        || attestation.revoke_watermark != root.revoke_watermark
        || attestation.snapshot_hash != root.snapshot_hash
        || attestation.issued_at_unix < root.not_before
        || attestation.expires_at_unix > root.expires_at
    {
        return Err(CertifiedMemoryCoordinatorError::SnapshotBindingMismatch);
    }
    Ok(())
}

fn append_field(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::authority_protocol::{
        AuthorityCertifiedMemoryCoverage, AuthorityCertifiedMemoryRootProposal,
        AuthorityFamilyCompletionState, AuthorityFamilyDependencyFrontier,
    };
    use astral_types::AUTHORITY_PROTOCOL_VERSION;
    use ed25519_dalek::SigningKey;

    const NOW: i64 = 10_000;

    fn family(
        scope: &AuthorityFamilyScope,
        family: AuthorityCertifiedMemoryFamily,
    ) -> AuthorityFamilyCompletion {
        AuthorityFamilyCompletion {
            family,
            state: AuthorityFamilyCompletionState::CompleteEmpty,
            scope: scope.clone(),
            reservation_id: "reservation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            message_id: Some("message-1".to_owned()),
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            before_content_digest: None,
            after_content_digest: None,
            complete_content_digest: Some("33".repeat(32)),
            audit_correlation_id: "audit-1".to_owned(),
            inventory: Vec::new(),
            scope_generation: 1,
            revoke_watermark: 0,
            dependency_frontier: AuthorityFamilyDependencyFrontier {
                authority_term: 1,
                global_fence_sequence: 1,
                dependency_generation: 1,
            },
            authority_completion_receipt_id: format!("receipt-{}", family.as_text()),
        }
    }

    fn bundle() -> CertifiedMemoryFamilyBundle {
        let scope = AuthorityFamilyScope {
            tenant_id: Some(7),
            scope: "tenant:7".to_owned(),
        };
        CertifiedMemoryFamilyBundle::build(
            scope.clone(),
            AuthorityCertifiedMemoryFamily::required()
                .into_iter()
                .map(|family_kind| family(&scope, family_kind))
                .collect(),
        )
        .expect("bundle")
    }

    fn root(
        snapshot_hash: String,
        bundle_digest: String,
    ) -> (AuthorityCertifiedMemoryRoot, SigningKey) {
        let key = SigningKey::from_bytes(&[9; 32]);
        let proposal = AuthorityCertifiedMemoryRootProposal {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            reservation_id: "reservation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            family_bundle_digest: bundle_digest.clone(),
            snapshot_hash,
            scope_generation: 1,
            revoke_watermark: 0,
            parent_root_digest: None,
            coverage: AuthorityCertifiedMemoryCoverage::complete(),
            publication_proof: None,
            not_before: NOW,
            expires_at: NOW + 60,
        };
        let mut root = AuthorityCertifiedMemoryRoot {
            protocol_version: proposal.protocol_version,
            authorization_edition: proposal.authorization_edition,
            authority_id: proposal.authority_id.clone(),
            authority_term: 1,
            global_fence_sequence: 1,
            root_id: "root-1".to_owned(),
            reservation_id: proposal.reservation_id.clone(),
            operation_id: proposal.operation_id.clone(),
            event_id: proposal.event_id.clone(),
            source_commit_digest: proposal.source_commit_digest.clone(),
            source_outcome_digest: proposal.source_outcome_digest.clone(),
            family_bundle_digest: proposal.family_bundle_digest.clone(),
            snapshot_hash: proposal.snapshot_hash.clone(),
            scope_generation: proposal.scope_generation,
            revoke_watermark: proposal.revoke_watermark,
            parent_root_digest: None,
            coverage: proposal.coverage.clone(),
            key_id: "key-1".to_owned(),
            key_epoch: 1,
            issued_at: NOW,
            not_before: NOW,
            expires_at: NOW + 60,
            root_digest: "0".repeat(64),
            signature: "0".repeat(128),
        };
        root.sign_with(&key).expect("sign root");
        (root, key)
    }

    #[test]
    fn incomplete_or_non_terminal_family_bundle_is_rejected() {
        let scope = AuthorityFamilyScope {
            tenant_id: Some(7),
            scope: "tenant:7".to_owned(),
        };
        let mut completions: Vec<_> = AuthorityCertifiedMemoryFamily::required()
            .into_iter()
            .map(|family_kind| family(&scope, family_kind))
            .collect();
        completions[0].state = AuthorityFamilyCompletionState::Pending;
        assert!(matches!(
            CertifiedMemoryFamilyBundle::build(scope, completions),
            Err(CertifiedMemoryCoordinatorError::FamilyNotComplete { .. })
        ));
    }

    #[test]
    fn prepare_rejects_mutated_bundle_before_installation() {
        let original = bundle();
        let (root, key) = root("0".repeat(64), original.bundle_digest.clone());
        let mut observation =
            CertifiedMemoryRootObservation::from_verified_root(root, &key.verifying_key(), NOW)
                .unwrap();
        observation.client_verified = true;
        let runtime = Arc::new(CertifiedMemoryRuntime::new(Default::default()));
        let coordinator = CertifiedMemoryCoordinator::new(Arc::clone(&runtime));
        let snapshot = Arc::new(
            CertifiedMemorySnapshot::empty(
                1,
                NOW,
                NOW + 60,
                crate::certified_memory_authority::CertifiedMemoryCoverage::Complete,
            )
            .unwrap(),
        );

        let mut forged = original.clone();
        forged.completions[0].source_commit_digest = "aa".repeat(32);
        assert_eq!(
            coordinator.prepare(Arc::clone(&snapshot), &forged, observation.clone(), NOW),
            Err(CertifiedMemoryCoordinatorError::FamilyBundleDigestMismatch)
        );
        let mut missing = original;
        missing.completions.clear();
        assert_eq!(
            coordinator.prepare(snapshot, &missing, observation, NOW),
            Err(CertifiedMemoryCoordinatorError::FamilyCoverageIncomplete)
        );
        assert_eq!(runtime.state(), CertifiedMemoryRuntimeState::Cold);
    }

    #[test]
    fn caller_signed_root_is_not_client_verified() {
        let families = bundle();
        let (root, key) = root("0".repeat(64), families.bundle_digest.clone());
        let observation =
            CertifiedMemoryRootObservation::from_verified_root(root, &key.verifying_key(), NOW)
                .unwrap();
        let runtime = Arc::new(CertifiedMemoryRuntime::new(Default::default()));
        let coordinator = CertifiedMemoryCoordinator::new(Arc::clone(&runtime));
        let snapshot = Arc::new(
            CertifiedMemorySnapshot::empty(
                1,
                NOW,
                NOW + 60,
                crate::certified_memory_authority::CertifiedMemoryCoverage::Complete,
            )
            .unwrap(),
        );
        assert!(matches!(
            coordinator.prepare(snapshot, &families, observation, NOW),
            Err(CertifiedMemoryCoordinatorError::RootInvalid(_))
        ));
        assert_eq!(runtime.state(), CertifiedMemoryRuntimeState::Cold);
        assert!(runtime.store().begin_read(NOW).is_err());
    }

    #[test]
    fn arbitrary_proven_readiness_cannot_open_prepared_store() {
        use crate::certified_memory_authority::{
            CertifiedMemoryCoverage, CertifiedMemoryCoverageContract,
        };
        use crate::certified_memory_snapshot_builder::{
            CertifiedMemorySnapshotBuilder, CertifiedMemorySnapshotInput,
        };
        let runtime = Arc::new(CertifiedMemoryRuntime::new(Default::default()));
        let coordinator = CertifiedMemoryCoordinator::new(Arc::clone(&runtime));
        let snapshot = CertifiedMemorySnapshotBuilder::new(Default::default())
            .build(CertifiedMemorySnapshotInput {
                generation: 1,
                installed_at_unix: NOW,
                expires_at_unix: NOW + 60,
                attestation: CertifiedMemoryAttestation {
                    authority_term: 1,
                    global_fence_sequence: 1,
                    key_epoch: 1,
                    scope_generation: 1,
                    revoke_watermark: 0,
                    snapshot_hash: "a".repeat(64),
                    issued_at_unix: NOW,
                    expires_at_unix: NOW + 60,
                },
                coverage: CertifiedMemoryCoverage::Complete,
                coverage_contract: CertifiedMemoryCoverageContract::complete(),
                card_contexts: Vec::new(),
                global_admins: Vec::new(),
                org_reads: Vec::new(),
                ownership: Vec::new(),
                published_cards: Vec::new(),
                sod_policies: Vec::new(),
            })
            .unwrap();
        runtime.install_coordinated(snapshot, NOW).unwrap();
        runtime.begin_fence_sync(1).unwrap();
        let (root, key) = root("0".repeat(64), bundle().bundle_digest);
        *coordinator.binding.write().unwrap() = Some(PreparedBinding {
            root: CertifiedMemoryRootObservation::from_verified_root(
                root,
                &key.verifying_key(),
                NOW,
            )
            .unwrap(),
            owner: None,
        });
        assert_eq!(
            coordinator.complete_serving_assertion(1, NOW),
            Err(CertifiedMemoryCoordinatorError::ReadinessPending)
        );
        assert_eq!(runtime.state(), CertifiedMemoryRuntimeState::FenceSyncing);
        assert!(runtime.store().begin_read(NOW).is_err());
    }

    #[test]
    fn readiness_without_owner_stays_non_serving() {
        let runtime = Arc::new(CertifiedMemoryRuntime::new(Default::default()));
        let coordinator = CertifiedMemoryCoordinator::new(runtime);
        assert_eq!(coordinator.state(), CertifiedMemoryRuntimeState::Cold);
    }

    #[test]
    fn invalidation_waits_for_serving_transition_guard() {
        use std::sync::mpsc;
        use std::time::Duration;

        let runtime = Arc::new(CertifiedMemoryRuntime::new(Default::default()));
        let coordinator = Arc::new(CertifiedMemoryCoordinator::new(runtime));
        let guard = coordinator.binding.read().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = Arc::clone(&coordinator);
        let thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = worker.invalidate(CertifiedMemoryInvalidation::Unknown);
            done_tx.send(result).unwrap();
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(guard);
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        thread.join().unwrap();
    }

    fn prepared_coordinator() -> (CertifiedMemoryCoordinator, Arc<CertifiedMemoryRuntime>) {
        use crate::certified_memory_authority::{
            CertifiedMemoryCoverage, CertifiedMemoryCoverageContract,
        };
        use crate::certified_memory_snapshot_builder::{
            CertifiedMemorySnapshotBuilder, CertifiedMemorySnapshotInput,
        };
        let runtime = Arc::new(CertifiedMemoryRuntime::new(Default::default()));
        let coordinator = CertifiedMemoryCoordinator::new(Arc::clone(&runtime));
        let builder = CertifiedMemorySnapshotBuilder::new(Default::default());
        let mut input = CertifiedMemorySnapshotInput {
            generation: 1,
            installed_at_unix: NOW,
            expires_at_unix: NOW + 60,
            attestation: CertifiedMemoryAttestation {
                authority_term: 1,
                global_fence_sequence: 1,
                key_epoch: 1,
                scope_generation: 1,
                revoke_watermark: 0,
                snapshot_hash: "a".repeat(64),
                issued_at_unix: NOW,
                expires_at_unix: NOW + 60,
            },
            coverage: CertifiedMemoryCoverage::Complete,
            coverage_contract: CertifiedMemoryCoverageContract::complete(),
            card_contexts: Vec::new(),
            global_admins: Vec::new(),
            org_reads: Vec::new(),
            ownership: Vec::new(),
            published_cards: Vec::new(),
            sod_policies: Vec::new(),
        };
        input.attestation.snapshot_hash = builder
            .build(input.clone())
            .unwrap()
            .content_digest()
            .unwrap();
        let snapshot = builder.build(input).unwrap();
        let families = bundle();
        let (root, key) = root(
            snapshot.content_digest().unwrap(),
            families.bundle_digest.clone(),
        );
        let mut observation =
            CertifiedMemoryRootObservation::from_verified_root(root, &key.verifying_key(), NOW)
                .unwrap();
        // Model the verified client boundary in this unit test only.
        observation.client_verified = true;
        coordinator
            .prepare(snapshot, &families, observation, NOW)
            .unwrap();
        (coordinator, runtime)
    }

    #[cfg(test)]
    fn establish(owner: &CertifiedMemoryReadinessOwner) -> CertifiedMemoryReadinessCapability {
        let ports = owner.ports();
        owner
            .inject_worker_ownership(ports.worker_ownership())
            .unwrap();
        owner
            .inject_durable_frontier(ports.durable_frontier())
            .unwrap();
        owner.inject_transport(ports.transport()).unwrap();
        owner.capability().unwrap()
    }

    #[test]
    fn readiness_ports_require_all_three_bound_inputs() {
        let (coordinator, runtime) = prepared_coordinator();
        let owner = coordinator
            .readiness_owner(CertifiedMemoryLeaseBinding::new("lease", 4).unwrap())
            .unwrap();
        let ports = owner.ports();
        assert!(matches!(
            owner.capability(),
            Err(ReadinessError::Incomplete)
        ));
        owner
            .inject_worker_ownership(ports.worker_ownership())
            .unwrap();
        assert!(matches!(
            owner.capability(),
            Err(ReadinessError::Incomplete)
        ));
        owner
            .inject_durable_frontier(ports.durable_frontier())
            .unwrap();
        assert!(matches!(
            owner.capability(),
            Err(ReadinessError::Incomplete)
        ));
        owner.inject_transport(ports.transport()).unwrap();
        let capability = owner.capability().unwrap();
        coordinator
            .complete_serving(1, &capability, NOW + 1)
            .unwrap();
        assert!(runtime.readiness(NOW + 1).positive_reads_ready);
    }

    #[test]
    fn invalidation_after_serving_closes_runtime() {
        let (coordinator, runtime) = prepared_coordinator();
        let owner = coordinator
            .readiness_owner(CertifiedMemoryLeaseBinding::new("lease", 4).unwrap())
            .unwrap();
        assert!(matches!(
            owner.capability(),
            Err(ReadinessError::Incomplete)
        ));
        let ports = owner.ports();
        owner
            .inject_worker_ownership(ports.worker_ownership())
            .unwrap();
        owner
            .inject_durable_frontier(ports.durable_frontier())
            .unwrap();
        assert!(matches!(
            owner.capability(),
            Err(ReadinessError::Incomplete)
        ));
        owner.inject_transport(ports.transport()).unwrap();
        let capability = owner.capability().unwrap();
        coordinator
            .complete_serving(1, &capability, NOW + 1)
            .unwrap();
        assert!(runtime.readiness(NOW + 1).positive_reads_ready);
        owner
            .transport()
            .invalidate(CertifiedMemoryInvalidation::Unknown)
            .unwrap();
        assert!(!runtime.readiness(NOW + 1).positive_reads_ready);
        assert!(matches!(
            owner.capability(),
            Err(ReadinessError::Invalidated)
        ));
        assert!(coordinator
            .complete_serving(1, &capability, NOW + 1)
            .is_err());
    }

    #[test]
    fn capability_rejects_foreign_owner_root_generation_and_lease() {
        let (coordinator, runtime) = prepared_coordinator();
        let owner = coordinator
            .readiness_owner(CertifiedMemoryLeaseBinding::new("lease", 4).unwrap())
            .unwrap();
        let digest = owner.binding().root_digest().to_owned();
        for (root, generation, lease_id, lease_epoch) in [
            (digest.clone(), 1, "lease", 4),
            ("foreign".into(), 1, "lease", 4),
            (digest.clone(), 2, "lease", 4),
            (digest.clone(), 1, "foreign-lease", 4),
            (digest.clone(), 1, "lease", 5),
        ] {
            let foreign = CertifiedMemoryReadinessOwner::new(
                root,
                generation,
                CertifiedMemoryLeaseBinding::new(lease_id, lease_epoch).unwrap(),
                Arc::clone(&runtime),
            );
            let capability = establish(&foreign);
            assert!(matches!(
                coordinator.complete_serving(1, &capability, NOW + 1),
                Err(CertifiedMemoryCoordinatorError::Readiness(
                    ReadinessError::BindingMismatch
                ))
            ));
        }
        assert!(!runtime.readiness(NOW + 1).positive_reads_ready);
    }

    #[test]
    fn invalidation_before_activation_is_sticky() {
        let (coordinator, runtime) = prepared_coordinator();
        let owner = coordinator
            .readiness_owner(CertifiedMemoryLeaseBinding::new("lease", 1).unwrap())
            .unwrap();
        let capability = establish(&owner);
        owner
            .worker_ownership()
            .invalidate(CertifiedMemoryInvalidation::Gap)
            .unwrap();
        assert!(coordinator
            .complete_serving(1, &capability, NOW + 1)
            .is_err());
        let ports = owner.ports();
        assert!(matches!(
            owner.inject_worker_ownership(ports.worker_ownership()),
            Err(ReadinessError::Invalidated)
        ));
        assert!(!runtime.readiness(NOW + 1).positive_reads_ready);
    }

    #[test]
    fn owner_invalidation_serializes_with_activation() {
        use std::sync::mpsc;
        use std::time::Duration;
        let (coordinator, runtime) = prepared_coordinator();
        let owner = coordinator
            .readiness_owner(CertifiedMemoryLeaseBinding::new("lease", 1).unwrap())
            .unwrap();
        let capability = establish(&owner);
        let digest = owner.binding().root_digest().to_owned();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let other = owner.clone();
        owner
            .with_capability(&capability, &digest, 1, || {
                let thread = std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    done_tx
                        .send(other.invalidate(CertifiedMemoryInvalidation::Unknown))
                        .unwrap();
                });
                started_rx.recv().unwrap();
                assert!(matches!(
                    done_rx.recv_timeout(Duration::from_millis(50)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
                runtime.mark_serving_coordinated(1, NOW + 1).unwrap();
                thread
            })
            .unwrap()
            .join()
            .unwrap();
        done_rx.recv().unwrap().unwrap();
        assert!(!runtime.readiness(NOW + 1).positive_reads_ready);
    }

    #[test]
    fn direct_store_install_cannot_activate() {
        let runtime = CertifiedMemoryRuntime::new(Default::default());
        let snapshot = Arc::new(
            CertifiedMemorySnapshot::empty(
                1,
                NOW,
                NOW + 60,
                crate::certified_memory_authority::CertifiedMemoryCoverage::Complete,
            )
            .unwrap(),
        );
        assert!(runtime.store().install(Arc::clone(&snapshot), NOW).is_err());
        assert!(runtime.install(snapshot, NOW).is_err());
        assert!(runtime.store().mark_serving(1, NOW).is_err());
        assert!(runtime.store().begin_read(NOW).is_err());
    }

    #[test]
    fn root_observation_requires_verified_signature() {
        let bundle = bundle();
        let (mut root, key) = root("0".repeat(64), bundle.bundle_digest);
        root.snapshot_hash = "1".repeat(64);
        assert!(CertifiedMemoryRootObservation::from_verified_root(
            root,
            &key.verifying_key(),
            NOW
        )
        .is_err());
    }
}
