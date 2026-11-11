//! Durable-to-certified snapshot construction and lifecycle coordination.
//!
//! This module is the only boundary that may turn already verified durable facts
//! into a [`CertifiedMemorySnapshot`]. It never derives authority evidence, reads
//! raw source tables, consults a cache, or treats a local pointer/heartbeat as a
//! certificate. The pool-backed path intentionally remains pending until the
//! complete fact-family and external authority contracts are available.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use astral_types::{PublishedCardAuthorization, PublishedCardEvidenceScope};
use policy_engine::OrgAuthorityRead;
use sqlx::MySqlPool;
use thiserror::Error;

use crate::certified_memory_authority::{
    CardContextKey, CertifiedCardContext, CertifiedMemoryAttestation, CertifiedMemoryConfig,
    CertifiedMemoryCoverage, CertifiedMemoryCoverageContract, CertifiedMemoryFailure,
    CertifiedMemoryInvalidation, CertifiedMemoryServing, CertifiedMemorySnapshot,
    CertifiedMemoryStore, CertifiedSodPolicy, GlobalAdminStatus, OrgReadKey, OwnershipReadKey,
};
use crate::certified_memory_materializer::{
    CertifiedMemoryFamilyOwnerRequest, CertifiedMemoryMaterialization, CertifiedMemoryMaterializer,
    CertifiedMemoryMaterializerError,
};
use crate::resource_ownership::ResourceOwnershipResolution;
use crate::AuthorizationEvidenceError;

/// Maximum number of durable card evidence scopes accepted by one warm request.
/// The bound protects the reader from becoming an unbounded whole-database scan.
pub const MAX_DURABLE_CARD_SCOPES: usize = 4096;

/// A complete, already-certified input candidate for one immutable memory root.
///
/// The authority attestation must be supplied by the external authority owner.
/// This builder validates its shape and binds it to the snapshot generation and
/// residency window; it never creates, signs, or upgrades the attestation.
#[derive(Debug, Clone)]
pub struct CertifiedMemorySnapshotInput {
    pub generation: u64,
    pub installed_at_unix: i64,
    pub expires_at_unix: i64,
    pub attestation: CertifiedMemoryAttestation,
    pub coverage: CertifiedMemoryCoverage,
    pub coverage_contract: CertifiedMemoryCoverageContract,
    pub card_contexts: Vec<(CardContextKey, CertifiedCardContext)>,
    pub global_admins: Vec<(i64, GlobalAdminStatus)>,
    pub org_reads: Vec<(OrgReadKey, OrgAuthorityRead)>,
    pub ownership: Vec<(OwnershipReadKey, ResourceOwnershipResolution)>,
    pub published_cards: Vec<(PublishedCardEvidenceScope, Arc<PublishedCardAuthorization>)>,
    pub sod_policies: Vec<CertifiedSodPolicy>,
}

/// A durable warm request. Its scopes are exact strict-reader inputs, never
/// wildcard selectors or a request to enumerate raw source state.
#[derive(Debug, Clone, Default)]
pub struct CertifiedMemoryDurableBuildRequest {
    pub scopes: Vec<PublishedCardEvidenceScope>,
}

/// Builder failures are deliberately divided into caller input, pending durable
/// evidence, and unavailable infrastructure/authority outcomes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifiedMemoryBuildError {
    #[error("certified memory input is invalid: {0}")]
    InvalidInput(String),
    #[error("certified memory coverage is incomplete: {family}")]
    IncompleteCoverage { family: &'static str },
    #[error("certified memory snapshot exceeds configured bounds")]
    CapacityExceeded,
    #[error("certified memory build is pending: {code}")]
    Pending { code: &'static str },
    #[error("certified memory build is unavailable: {code}")]
    Unavailable { code: &'static str },
}

/// Validates bounded input and creates an immutable snapshot candidate.
#[derive(Debug, Clone, Copy)]
pub struct CertifiedMemorySnapshotBuilder {
    config: CertifiedMemoryConfig,
}

impl CertifiedMemorySnapshotBuilder {
    pub const fn new(config: CertifiedMemoryConfig) -> Self {
        Self { config }
    }

    pub const fn config(self) -> CertifiedMemoryConfig {
        self.config
    }

    /// Build only from complete fact-family input and an externally supplied
    /// attestation. No default or synthetic authority input is accepted.
    pub fn build(
        &self,
        input: CertifiedMemorySnapshotInput,
    ) -> Result<Arc<CertifiedMemorySnapshot>, CertifiedMemoryBuildError> {
        validate_input(&input, self.config)?;

        let mut snapshot = CertifiedMemorySnapshot::empty(
            input.generation,
            input.installed_at_unix,
            input.expires_at_unix,
            input.coverage,
        )
        .map_err(|detail| invalid_snapshot("root", detail))?;

        snapshot
            .set_coverage_contract(input.coverage_contract)
            .map_err(|detail| invalid_snapshot("coverage", detail))?;
        snapshot
            .attach_attestation(input.attestation)
            .map_err(|detail| invalid_snapshot("attestation", detail))?;

        for (key, value) in input.card_contexts {
            snapshot
                .insert_card_context(key, value)
                .map_err(|detail| invalid_snapshot("card_context", detail))?;
        }
        for (user_id, status) in input.global_admins {
            snapshot
                .insert_global_admin(user_id, status)
                .map_err(|detail| invalid_snapshot("global_admin", detail))?;
        }
        for (key, value) in input.org_reads {
            snapshot
                .insert_org_read(key, value)
                .map_err(|detail| invalid_snapshot("org_authorization", detail))?;
        }
        for (key, value) in input.ownership {
            snapshot
                .insert_ownership(key, value)
                .map_err(|detail| invalid_snapshot("ownership", detail))?;
        }
        for (scope, evidence) in input.published_cards {
            snapshot
                .insert_published_card(scope, evidence)
                .map_err(|detail| invalid_snapshot("published_evidence", detail))?;
        }
        for policy in input.sod_policies {
            snapshot
                .insert_sod_policy(policy)
                .map_err(|detail| invalid_snapshot("sod_policy", detail))?;
        }

        if snapshot.entry_count() > self.config.max_entries()
            || snapshot.estimated_bytes() > self.config.max_bytes()
        {
            return Err(CertifiedMemoryBuildError::CapacityExceeded);
        }

        Ok(Arc::new(snapshot))
    }

    pub fn build_from_materialization(
        &self,
        materialization: CertifiedMemoryMaterialization,
        attestation: CertifiedMemoryAttestation,
        installed_at_unix: i64,
        expires_at_unix: i64,
    ) -> Result<Arc<CertifiedMemorySnapshot>, CertifiedMemoryBuildError> {
        let input = materialization
            .into_snapshot_input(attestation, installed_at_unix, expires_at_unix)
            .map_err(map_materializer_error)?;
        self.build(input)
    }

    /// Materialize through the registered durable owners, then construct only
    /// from their authority-bound typed payloads. No owner result is upgraded by
    /// this method; pending/unknown/quarantined owners remain non-installable.
    pub async fn build_from_materializer(
        &self,
        materializer: &CertifiedMemoryMaterializer,
        request: &CertifiedMemoryFamilyOwnerRequest,
        attestation: CertifiedMemoryAttestation,
        installed_at_unix: i64,
        expires_at_unix: i64,
    ) -> Result<Arc<CertifiedMemorySnapshot>, CertifiedMemoryBuildError> {
        let materialization = materializer
            .materialize(request)
            .await
            .map_err(map_materializer_error)?;
        self.build_from_materialization(
            materialization,
            attestation,
            installed_at_unix,
            expires_at_unix,
        )
    }

    /// Read exact published evidence through the existing strict reader, then
    /// stop. There is intentionally no complete DB builder in this crate yet:
    /// card-context enumeration, GlobalAdmin, ORG, ownership, SoD and the
    /// external authority certificate cannot be proven by this call alone.
    pub async fn build_from_durable(
        &self,
        pool: &MySqlPool,
        request: &CertifiedMemoryDurableBuildRequest,
    ) -> Result<Arc<CertifiedMemorySnapshot>, CertifiedMemoryBuildError> {
        validate_durable_request(request)?;

        for scope in &request.scopes {
            crate::load_published_card_grant_evidence(pool, scope)
                .await
                .map_err(map_durable_error)?;
        }

        Err(CertifiedMemoryBuildError::Pending {
            code: "certified_memory.complete_fact_coverage_unavailable",
        })
    }
}

fn map_materializer_error(error: CertifiedMemoryMaterializerError) -> CertifiedMemoryBuildError {
    match error {
        CertifiedMemoryMaterializerError::Pending { .. } => CertifiedMemoryBuildError::Pending {
            code: "certified_memory.family_completion_pending",
        },
        CertifiedMemoryMaterializerError::Unknown { .. }
        | CertifiedMemoryMaterializerError::Quarantined { .. } => {
            CertifiedMemoryBuildError::Unavailable {
                code: "certified_memory.family_completion_unknown",
            }
        }
        CertifiedMemoryMaterializerError::Invalid(_)
        | CertifiedMemoryMaterializerError::OwnerRegistryIncomplete
        | CertifiedMemoryMaterializerError::OwnerRegistryInvalid { .. }
        | CertifiedMemoryMaterializerError::FrontierMismatch { .. }
        | CertifiedMemoryMaterializerError::FamilyOrderMismatch { .. }
        | CertifiedMemoryMaterializerError::Bundle(_) => CertifiedMemoryBuildError::Unavailable {
            code: "certified_memory.family_completion_invalid",
        },
    }
}
fn invalid_snapshot(family: &'static str, detail: String) -> CertifiedMemoryBuildError {
    CertifiedMemoryBuildError::InvalidInput(format!("{family}:{detail}"))
}

fn validate_input(
    input: &CertifiedMemorySnapshotInput,
    config: CertifiedMemoryConfig,
) -> Result<(), CertifiedMemoryBuildError> {
    if input.coverage != CertifiedMemoryCoverage::Complete {
        return Err(CertifiedMemoryBuildError::IncompleteCoverage { family: "snapshot" });
    }
    let contract = input.coverage_contract;
    let missing_family = [
        (contract.card_context, "card_context"),
        (contract.global_admin, "global_admin"),
        (contract.published_evidence, "published_evidence"),
        (contract.org_authorization, "org_authorization"),
        (contract.ownership, "ownership"),
        (contract.sod_policy, "sod_policy"),
    ]
    .into_iter()
    .find_map(|(present, family)| (!present).then_some(family));
    if let Some(family) = missing_family {
        return Err(CertifiedMemoryBuildError::IncompleteCoverage { family });
    }
    if input.generation == 0 {
        return Err(CertifiedMemoryBuildError::InvalidInput(
            "generation must be non-zero".to_owned(),
        ));
    }
    let ttl = input
        .expires_at_unix
        .checked_sub(input.installed_at_unix)
        .ok_or_else(|| {
            CertifiedMemoryBuildError::InvalidInput("snapshot time range overflow".to_owned())
        })?;
    if ttl <= 0 || ttl > config.ttl_seconds() {
        return Err(CertifiedMemoryBuildError::InvalidInput(
            "snapshot expiry is outside configured TTL".to_owned(),
        ));
    }

    validate_unique_keys(
        input.card_contexts.iter().map(|(key, _)| *key),
        "duplicate card context key",
    )?;
    validate_unique_keys(
        input.global_admins.iter().map(|(user_id, _)| *user_id),
        "duplicate global-admin key",
    )?;
    validate_unique_keys(
        input.org_reads.iter().map(|(key, _)| *key),
        "duplicate ORG read key",
    )?;
    validate_unique_keys(
        input.ownership.iter().map(|(key, _)| key.clone()),
        "duplicate ownership key",
    )?;
    validate_unique_keys(
        input.published_cards.iter().map(|(scope, _)| {
            crate::certified_memory_authority::PublishedCardEvidenceKey::from(scope)
        }),
        "duplicate published evidence scope",
    )?;
    validate_unique_keys(
        input
            .sod_policies
            .iter()
            .map(|policy| policy.policy_name.as_str()),
        "duplicate SoD policy name",
    )?;
    Ok(())
}

fn validate_unique_keys<I, K>(
    keys: I,
    duplicate: &'static str,
) -> Result<(), CertifiedMemoryBuildError>
where
    I: IntoIterator<Item = K>,
    K: Eq + std::hash::Hash,
{
    let mut seen = HashSet::new();
    for key in keys {
        if !seen.insert(key) {
            return Err(CertifiedMemoryBuildError::InvalidInput(
                duplicate.to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_durable_request(
    request: &CertifiedMemoryDurableBuildRequest,
) -> Result<(), CertifiedMemoryBuildError> {
    if request.scopes.is_empty() {
        return Err(CertifiedMemoryBuildError::Pending {
            code: "certified_memory.complete_scope_enumeration_unavailable",
        });
    }
    if request.scopes.len() > MAX_DURABLE_CARD_SCOPES {
        return Err(CertifiedMemoryBuildError::InvalidInput(
            "durable scope request exceeds its bound".to_owned(),
        ));
    }
    for scope in &request.scopes {
        scope
            .validate()
            .map_err(|error| CertifiedMemoryBuildError::InvalidInput(error.to_string()))?;
    }
    validate_unique_keys(
        request
            .scopes
            .iter()
            .map(crate::certified_memory_authority::PublishedCardEvidenceKey::from),
        "duplicate durable evidence scope",
    )
}

fn map_durable_error(error: AuthorizationEvidenceError) -> CertifiedMemoryBuildError {
    match error {
        AuthorizationEvidenceError::NotReady(_) => CertifiedMemoryBuildError::Pending {
            code: "certified_memory.durable_evidence_pending",
        },
        AuthorizationEvidenceError::InvalidRequest(message) => {
            CertifiedMemoryBuildError::InvalidInput(message)
        }
        AuthorizationEvidenceError::Query(_) => CertifiedMemoryBuildError::Unavailable {
            code: "certified_memory.durable_reader_unavailable",
        },
        AuthorizationEvidenceError::Corrupt(_) => CertifiedMemoryBuildError::Unavailable {
            code: "certified_memory.durable_evidence_corrupt",
        },
    }
}

/// Runtime lifecycle of the certified-memory root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedMemoryRuntimeState {
    Cold,
    Warming,
    FenceSyncing,
    Serving,
    Pending,
    Suspect,
    Quarantined,
}

impl CertifiedMemoryRuntimeState {
    pub const fn may_serve_positive(self) -> bool {
        matches!(self, Self::Serving)
    }
}

/// Readiness is positive only when both the coordinator and the store read gate
/// agree. A Serving coordinator state alone is never sufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertifiedMemoryReadiness {
    pub state: CertifiedMemoryRuntimeState,
    pub installed_generation: Option<u64>,
    pub positive_reads_ready: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifiedMemoryRuntimeError {
    #[error("invalid certified-memory runtime transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: CertifiedMemoryRuntimeState,
        to: CertifiedMemoryRuntimeState,
    },
    #[error("certified-memory runtime state is unavailable")]
    StateUnavailable,
    #[error("certified-memory generation does not match the installed root")]
    GenerationMismatch,
    #[error("certified-memory store failure: {0:?}")]
    Store(CertifiedMemoryFailure),
}

impl From<CertifiedMemoryFailure> for CertifiedMemoryRuntimeError {
    fn from(error: CertifiedMemoryFailure) -> Self {
        Self::Store(error)
    }
}

/// Coordinator for installation, authority-fence synchronization, and the
/// store's positive-read gate.
#[derive(Debug)]
pub struct CertifiedMemoryRuntime {
    store: Arc<CertifiedMemoryStore>,
    state: RwLock<CertifiedMemoryRuntimeState>,
}

impl CertifiedMemoryRuntime {
    pub fn new(config: CertifiedMemoryConfig) -> Self {
        Self::with_store(Arc::new(CertifiedMemoryStore::new(config)))
    }

    pub fn with_store(store: Arc<CertifiedMemoryStore>) -> Self {
        Self {
            store,
            state: RwLock::new(CertifiedMemoryRuntimeState::Cold),
        }
    }

    pub fn store(&self) -> Arc<CertifiedMemoryStore> {
        Arc::clone(&self.store)
    }

    pub fn state(&self) -> CertifiedMemoryRuntimeState {
        self.state
            .read()
            .map(|state| *state)
            .unwrap_or(CertifiedMemoryRuntimeState::Quarantined)
    }

    /// Direct installation cannot establish a verified authority binding.
    pub fn install(
        &self,
        _snapshot: Arc<CertifiedMemorySnapshot>,
        _now_unix: i64,
    ) -> Result<u64, CertifiedMemoryRuntimeError> {
        Err(CertifiedMemoryRuntimeError::Store(
            CertifiedMemoryFailure::Unknown,
        ))
    }

    pub(crate) fn install_coordinated(
        &self,
        snapshot: Arc<CertifiedMemorySnapshot>,
        now_unix: i64,
    ) -> Result<u64, CertifiedMemoryRuntimeError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| CertifiedMemoryRuntimeError::StateUnavailable)?;
        let from = *state;
        if from == CertifiedMemoryRuntimeState::Serving {
            return Err(CertifiedMemoryRuntimeError::InvalidTransition {
                from,
                to: CertifiedMemoryRuntimeState::Warming,
            });
        }
        let epoch = self.store.install_coordinated(snapshot, now_unix)?;
        *state = if self.store.serving_state() == CertifiedMemoryServing::Gap {
            CertifiedMemoryRuntimeState::Suspect
        } else {
            CertifiedMemoryRuntimeState::Warming
        };
        Ok(epoch)
    }

    /// Begin the explicit external authority/frontier synchronization phase.
    pub fn begin_fence_sync(&self, generation: u64) -> Result<(), CertifiedMemoryRuntimeError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| CertifiedMemoryRuntimeError::StateUnavailable)?;
        if *state != CertifiedMemoryRuntimeState::Warming {
            return Err(CertifiedMemoryRuntimeError::InvalidTransition {
                from: *state,
                to: CertifiedMemoryRuntimeState::FenceSyncing,
            });
        }
        if self.store.installed_generation() != Some(generation) {
            return Err(CertifiedMemoryRuntimeError::GenerationMismatch);
        }
        *state = CertifiedMemoryRuntimeState::FenceSyncing;
        Ok(())
    }

    /// Direct activation cannot establish independent readiness.
    pub fn mark_serving(
        &self,
        _generation: u64,
        _now_unix: i64,
    ) -> Result<(), CertifiedMemoryRuntimeError> {
        Err(CertifiedMemoryRuntimeError::Store(
            CertifiedMemoryFailure::Unknown,
        ))
    }

    pub(crate) fn mark_serving_coordinated(
        &self,
        generation: u64,
        now_unix: i64,
    ) -> Result<(), CertifiedMemoryRuntimeError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| CertifiedMemoryRuntimeError::StateUnavailable)?;
        if *state != CertifiedMemoryRuntimeState::FenceSyncing {
            return Err(CertifiedMemoryRuntimeError::InvalidTransition {
                from: *state,
                to: CertifiedMemoryRuntimeState::Serving,
            });
        }
        if let Err(error) = self.store.mark_serving_coordinated(generation, now_unix) {
            *state = state_for_store_failure(&error);
            return Err(error.into());
        }
        *state = CertifiedMemoryRuntimeState::Serving;
        Ok(())
    }

    /// Close the positive read gate for a known invalidation or loss of proof.
    pub fn invalidate(
        &self,
        invalidation: CertifiedMemoryInvalidation,
    ) -> Result<(), CertifiedMemoryRuntimeError> {
        let mut state = match self.state.write() {
            Ok(state) => state,
            Err(_) => {
                self.store.invalidate(invalidation)?;
                return Err(CertifiedMemoryRuntimeError::StateUnavailable);
            }
        };
        self.store.invalidate(invalidation)?;
        *state = match invalidation {
            CertifiedMemoryInvalidation::Stale => CertifiedMemoryRuntimeState::Pending,
            CertifiedMemoryInvalidation::Gap => CertifiedMemoryRuntimeState::Suspect,
            CertifiedMemoryInvalidation::Unknown | CertifiedMemoryInvalidation::Failed => {
                CertifiedMemoryRuntimeState::Quarantined
            }
        };
        Ok(())
    }

    pub fn readiness(&self, now_unix: i64) -> CertifiedMemoryReadiness {
        let state = self.state();
        let positive_reads_ready =
            state.may_serve_positive() && self.store.begin_read(now_unix).is_ok();
        CertifiedMemoryReadiness {
            state,
            installed_generation: self.store.installed_generation(),
            positive_reads_ready,
        }
    }

    pub fn is_ready(&self, now_unix: i64) -> bool {
        self.readiness(now_unix).positive_reads_ready
    }
}

fn state_for_store_failure(failure: &CertifiedMemoryFailure) -> CertifiedMemoryRuntimeState {
    match failure {
        CertifiedMemoryFailure::Gap => CertifiedMemoryRuntimeState::Suspect,
        CertifiedMemoryFailure::Unknown
        | CertifiedMemoryFailure::TokenNotCurrent
        | CertifiedMemoryFailure::Invalid { .. }
        | CertifiedMemoryFailure::CapacityExceeded => CertifiedMemoryRuntimeState::Quarantined,
        CertifiedMemoryFailure::Stale => CertifiedMemoryRuntimeState::Pending,
        CertifiedMemoryFailure::NotServing(_) | CertifiedMemoryFailure::Missing => {
            CertifiedMemoryRuntimeState::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 10_000;

    fn input(generation: u64) -> CertifiedMemorySnapshotInput {
        CertifiedMemorySnapshotInput {
            generation,
            installed_at_unix: NOW,
            expires_at_unix: NOW + 60,
            attestation: CertifiedMemoryAttestation {
                authority_term: 1,
                global_fence_sequence: 1,
                key_epoch: 1,
                scope_generation: generation,
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
        }
    }

    #[test]
    fn complete_input_builds_only_with_all_fact_families_declared() {
        let builder = CertifiedMemorySnapshotBuilder::new(
            CertifiedMemoryConfig::new(16, 64 * 1024, 60).expect("config"),
        );
        let snapshot = builder.build(input(1)).expect("complete input");
        assert_eq!(snapshot.generation(), 1);
        assert_eq!(
            snapshot.coverage_contract(),
            CertifiedMemoryCoverageContract::complete()
        );
        assert!(snapshot.attestation().is_some());
    }

    #[test]
    fn incomplete_coverage_is_rejected_before_installable_output() {
        let builder = CertifiedMemorySnapshotBuilder::new(CertifiedMemoryConfig::default());
        let mut candidate = input(1);
        candidate.coverage_contract.card_context = false;
        assert!(matches!(
            builder.build(candidate),
            Err(CertifiedMemoryBuildError::IncompleteCoverage {
                family: "card_context"
            })
        ));
    }

    #[test]
    fn duplicate_fact_keys_are_rejected_instead_of_overwritten() {
        let builder = CertifiedMemorySnapshotBuilder::new(CertifiedMemoryConfig::default());
        let mut candidate = input(1);
        candidate.global_admins = vec![
            (7, GlobalAdminStatus::Active),
            (7, GlobalAdminStatus::Inactive),
        ];
        assert!(matches!(
            builder.build(candidate),
            Err(CertifiedMemoryBuildError::InvalidInput(message))
                if message == "duplicate global-admin key"
        ));
    }

    #[tokio::test]
    async fn durable_builder_reports_pending_without_complete_authority_contract() {
        let builder = CertifiedMemorySnapshotBuilder::new(CertifiedMemoryConfig::default());
        let result = builder
            .build_from_durable(
                &sqlx::mysql::MySqlPoolOptions::new()
                    .connect_lazy_with(sqlx::mysql::MySqlConnectOptions::new()),
                &CertifiedMemoryDurableBuildRequest::default(),
            )
            .await;
        assert!(matches!(
            result,
            Err(CertifiedMemoryBuildError::Pending {
                code: "certified_memory.complete_scope_enumeration_unavailable"
            })
        ));
    }

    #[test]
    fn public_store_and_runtime_cannot_install_or_serve() {
        let builder = CertifiedMemorySnapshotBuilder::new(CertifiedMemoryConfig::default());
        let snapshot = builder.build(input(1)).expect("snapshot");
        let runtime = CertifiedMemoryRuntime::new(CertifiedMemoryConfig::default());
        let store = runtime.store();
        assert!(store.install(Arc::clone(&snapshot), NOW + 1).is_err());
        assert!(runtime.install(Arc::clone(&snapshot), NOW + 1).is_err());
        assert!(store.mark_serving(1, NOW + 1).is_err());
        assert!(runtime.mark_serving(1, NOW + 1).is_err());
        assert!(store.installed_generation().is_none());
        runtime.install_coordinated(snapshot, NOW + 1).unwrap();
        runtime.begin_fence_sync(1).unwrap();
        assert!(store.mark_serving(1, NOW + 1).is_err());
        assert!(runtime.mark_serving(1, NOW + 1).is_err());
        assert!(store.begin_read(NOW + 1).is_err());
    }

    #[test]
    fn concurrent_invalidation_cannot_leave_store_serving() {
        let builder = CertifiedMemorySnapshotBuilder::new(CertifiedMemoryConfig::default());
        let runtime = Arc::new(CertifiedMemoryRuntime::new(CertifiedMemoryConfig::default()));
        runtime
            .install_coordinated(builder.build(input(1)).expect("snapshot"), NOW + 1)
            .expect("install");
        runtime.begin_fence_sync(1).expect("fence sync");
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let serving_runtime = Arc::clone(&runtime);
        let serving_barrier = Arc::clone(&barrier);
        let serving = std::thread::spawn(move || {
            serving_barrier.wait();
            serving_runtime.mark_serving_coordinated(1, NOW + 1)
        });
        let invalidation_runtime = Arc::clone(&runtime);
        let invalidation_barrier = Arc::clone(&barrier);
        let invalidation = std::thread::spawn(move || {
            invalidation_barrier.wait();
            invalidation_runtime.invalidate(CertifiedMemoryInvalidation::Unknown)
        });
        barrier.wait();
        let _ = serving.join().expect("serving thread");
        invalidation
            .join()
            .expect("invalidation thread")
            .expect("invalidate");
        assert_eq!(runtime.state(), CertifiedMemoryRuntimeState::Quarantined);
        assert!(runtime.store().begin_read(NOW + 1).is_err());
    }

    #[test]
    fn poisoned_runtime_state_still_closes_serving_store() {
        let builder = CertifiedMemorySnapshotBuilder::new(CertifiedMemoryConfig::default());
        let runtime = Arc::new(CertifiedMemoryRuntime::new(CertifiedMemoryConfig::default()));
        runtime
            .install_coordinated(builder.build(input(1)).expect("snapshot"), NOW + 1)
            .expect("install");
        runtime.begin_fence_sync(1).expect("fence sync");
        runtime
            .mark_serving_coordinated(1, NOW + 1)
            .expect("serving");
        let poisoner = Arc::clone(&runtime);
        assert!(std::thread::spawn(move || {
            let _guard = poisoner.state.write().expect("state lock");
            panic!("poison runtime state");
        })
        .join()
        .is_err());
        assert_eq!(
            runtime.invalidate(CertifiedMemoryInvalidation::Unknown),
            Err(CertifiedMemoryRuntimeError::StateUnavailable)
        );
        assert!(runtime.store().begin_read(NOW + 1).is_err());
    }

    #[test]
    fn runtime_requires_fence_sync_and_closes_reads_on_invalidation() {
        let builder = CertifiedMemorySnapshotBuilder::new(CertifiedMemoryConfig::default());
        let runtime = CertifiedMemoryRuntime::new(CertifiedMemoryConfig::default());
        let snapshot = builder.build(input(1)).expect("snapshot");
        runtime
            .install_coordinated(snapshot, NOW + 1)
            .expect("install");
        assert_eq!(runtime.state(), CertifiedMemoryRuntimeState::Warming);
        assert!(!runtime.is_ready(NOW + 1));
        runtime.begin_fence_sync(1).expect("fence sync");
        runtime
            .mark_serving_coordinated(1, NOW + 1)
            .expect("serving");
        assert!(runtime.is_ready(NOW + 1));
        runtime
            .invalidate(CertifiedMemoryInvalidation::Unknown)
            .expect("invalidate");
        assert_eq!(runtime.state(), CertifiedMemoryRuntimeState::Quarantined);
        assert!(!runtime.is_ready(NOW + 1));
    }
}
