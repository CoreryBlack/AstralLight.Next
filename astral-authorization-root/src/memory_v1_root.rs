//! memory—v1: One process-local root over the prebuilt object relationships.
//!
//! The registry installs at most one root for its composition scope. The process
//! entry point uses the process registry; isolated registries exist for tests and
//! explicitly isolated compositions. A root snapshot owns the supplied objects
//! and the HAMT-derived relationship indexes. Readers load one immutable snapshot
//! and do not take a root `RwLock` while traversing it.
//!
//! This module does not establish database provenance, complete coverage,
//! confirmation validity, rule semantics, or formal authorization. The current
//! installer creates a candidate root; it does not mark it as production-serving.
//! A root becomes `Serving` only through an adoption path that publishes an
//! [`AdoptionRecord`] together with the snapshot: production evidence has no
//! issuer yet, so the reachable paths are the experimental one (explicit,
//! operator-acknowledged limits) and the test-only hook.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock, Weak};

use arc_swap::ArcSwap;
use thiserror::Error;
use uuid::Uuid;

use crate::memory_v1_adoption::{
    AdoptionCertificateSource, AdoptionEvidence, AdoptionGrade, AdoptionLimit, AdoptionRecord,
    ColdLoadFacts,
};
use crate::memory_v1_db_rows::{binding_is_active, BinaryId, CandidateRows, CurrentSelection};
use crate::memory_v1_digest::{ContentDigest, DigestIndex};
use crate::memory_v1_fence::{
    FenceControlError, FenceDeclaration, FenceError, FenceGuard, FencePremise, FenceReadError,
    FenceRegistry, MAX_FENCE_CHECK_OBJECTS,
};
use crate::memory_v1_hamt::{
    count_rows, CandidateBudget, CandidateError, CardCandidate, HamtCandidate,
    PublishableRetirement, RuleSetImpactCandidate,
};
#[cfg(any(test, feature = "test-support"))]
use crate::memory_v1_hamt_runtime::digest_candidate;
use crate::memory_v1_hamt_runtime::{digest_rows, RuntimeCardContext, RuntimeError};
use crate::memory_v1_registry::{RegistryDeclaration, RegistryError, RegistryState};
use crate::memory_v1_root_digest::prepare_root_digest;

/// Process-local identity of one installed root instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RootInstanceId(Uuid);

impl RootInstanceId {
    /// memory—v1: Construct a diagnostic root instance identity from its UUID.
    /// This does not establish ownership, freshness, serving status or adoption.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// memory—v1: Expose the UUID representation for diagnostics and correlation.
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// memory—v1 §4.7: one object dependency registered during a read phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationDependency {
    pub binding_id: BinaryId,
    pub rule_set_id: BinaryId,
    pub version_bytes: Vec<u8>,
}

/// memory—v1 §4.7: the registered dependency set of one evaluation.
///
/// The final recheck also compares the captured card's binding-set generation
/// and every non-removed rule-set generation, including bindings that did not
/// contribute a winning rule. Unrelated updates remain isolated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyRecord {
    pub card_id: BinaryId,
    pub instance_id: RootInstanceId,
    pub bindings: Vec<EvaluationDependency>,
    pub tenant_tree_version: u64,
    pub registry_version: u64,
}

/// Confirmation states derived from the same immutable facts as one binding.
/// These structural observations are not authority or scope proofs.
pub struct AuthorizationBindingContext<'a> {
    pub binding: &'a crate::memory_v1_db_rows::BindingRow,
    pub rule_set: &'a crate::memory_v1_db_rows::RuleSetRow,
    pub selected: Option<&'a crate::memory_v1_db_rows::RuleSetVersionRow>,
    pub confirmation_state: crate::memory_v1_rules::BindingConfirmationState,
    pub change_confirmation_state: crate::memory_v1_rules::ChangeConfirmationState,
}

/// A bounded authorization view from one immutable request snapshot.
pub struct AuthorizationCardContext<'a> {
    pub user: &'a crate::memory_v1_db_rows::UserRow,
    pub identity: &'a crate::memory_v1_db_rows::IdentityCardRow,
    pub card: &'a crate::memory_v1_db_rows::UserCardRow,
    pub tenant: &'a crate::memory_v1_db_rows::TenantRow,
    pub bindings: Vec<AuthorizationBindingContext<'a>>,
}

/// Lifecycle state carried by the current root snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootStatus {
    /// The object graph is installed as an experimental candidate.
    Candidate,
    /// The root has passed a separately implemented adoption gate.
    Serving,
    /// Positive authorization is unavailable until controlled recovery.
    Invalid,
    /// The owner is no longer accepting reads.
    Stopped,
}

/// Metadata captured atomically with one root snapshot load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootMetadata {
    /// Process-local instance identity; a restart creates a new value.
    pub instance_id: RootInstanceId,
    /// Monotonic root update sequence within this instance.
    pub version: u64,
    /// Digest of the explicitly supplied candidate fields and selections.
    pub digest: ContentDigest,
    /// Candidate limits used to build the object graph.
    pub budget: CandidateBudget,
    /// Number of rows in the nine supplied tables.
    pub row_count: usize,
    /// Current lifecycle state.
    pub status: RootStatus,
}

/// Opaque verifier output bound to one exact candidate snapshot and evidence
/// grade. Experimental and isolated-test outputs cannot authorize production.
/// No complete production evidence issuer exists yet.
pub struct ServingAdoptionCertificate {
    instance_id: RootInstanceId,
    version: u64,
    digest: ContentDigest,
    source: AdoptionCertificateSource,
}

impl ServingAdoptionCertificate {
    /// memory—v1: Bind a verifier's evidence source to an exact candidate.
    pub(crate) fn from_verified_snapshot(
        instance_id: RootInstanceId,
        version: u64,
        digest: ContentDigest,
        source: AdoptionCertificateSource,
    ) -> Self {
        Self {
            instance_id,
            version,
            digest,
            source,
        }
    }
}

/// An opaque capability for one exact, production-adopted root snapshot.
///
/// This is distinct from [`ServingAdoptionCertificate`]. The certificate is an
/// input to the adoption verifier; this value is minted only after the root has
/// published the verified production snapshot through its CAS boundary. The
/// private runtime and snapshot references make the capability unusable after a
/// root replacement, invalidation, or owner drop. No public constructor or
/// metadata conversion exists: `RootStatus::Serving` and `AdoptionRecord` are
/// diagnostic facts, not substitutes for this capability.
pub struct ProductionAdmission {
    runtime: Weak<RootRuntime>,
    /// The snapshot the admission was minted on. Validation binds to the
    /// admission's carried metadata as the chain anchor; this weak reference
    /// is retained for diagnostics but no longer needs to be alive.
    #[allow(dead_code)]
    snapshot: Weak<RootSnapshot>,
    metadata: RootMetadata,
}

impl std::fmt::Debug for ProductionAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProductionAdmission([REDACTED])")
    }
}

impl ProductionAdmission {
    fn for_published_snapshot(runtime: &Arc<RootRuntime>, snapshot: &Arc<RootSnapshot>) -> Self {
        Self {
            runtime: Arc::downgrade(runtime),
            snapshot: Arc::downgrade(snapshot),
            metadata: snapshot.metadata,
        }
    }
}

#[derive(Clone)]
pub struct RootObservation {
    owner: Weak<RootRuntime>,
    metadata: RootMetadata,
}

impl RootObservation {
    /// memory—v1: Return the metadata captured with a root read.
    pub fn metadata(self) -> RootMetadata {
        self.metadata
    }
}

/// A value produced from one coherent immutable root snapshot.
pub struct RootRead<T> {
    /// The callback result derived from one snapshot.
    pub value: T,
    /// The metadata observation to recheck before a positive decision.
    pub observation: RootObservation,
}

enum PublicationCandidate {
    Checked(HamtCandidate),
    Retirement(PublishableRetirement),
}

impl PublicationCandidate {
    // memory—v1: Only read candidate facts while preparing the digest.
    fn candidate(&self) -> &HamtCandidate {
        match self {
            Self::Checked(candidate) => candidate,
            Self::Retirement(retirement) => retirement.candidate(),
        }
    }

    // memory—v1: Move the checked candidate itself into the root snapshot.
    fn into_candidate(self) -> HamtCandidate {
        match self {
            Self::Checked(candidate) => candidate,
            Self::Retirement(retirement) => retirement.into_published_candidate(),
        }
    }
}

struct RootSnapshot {
    metadata: RootMetadata,
    objects: HamtCandidate,
    // The index is published with exactly the objects and digest it describes.
    digest_index: DigestIndex,
    // memory—v1: Published with the initial serving snapshot; later snapshots
    // may retain this adoption history without proving their own freshness.
    adoption: Option<Arc<AdoptionRecord>>,
}

// The private field prevents the parent module and its tests from manufacturing
// a proof or replacing its snapshot after validation.
mod validated_adoption_snapshot {
    use super::{Arc, CandidateError, RootError, RootSnapshot};

    pub(super) struct ValidatedAdoptionSnapshot {
        snapshot: Arc<RootSnapshot>,
    }

    impl ValidatedAdoptionSnapshot {
        // memory—v1: Validate every structural gate against this exact immutable snapshot.
        pub(super) fn validate(snapshot: &Arc<RootSnapshot>) -> Result<Self, RootError> {
            // memory—v1 §15.10.3: every path that can publish `Serving`, including
            // opaque isolated-test certificates, must reconcile each explicit row
            // current pointer with the selected version. `validate_for_serving`
            // validates the selected object itself but intentionally does not treat
            // a caller-provided selection as proof that the row pointer agrees.
            if !snapshot.objects.has_valid_current_pointers() {
                return Err(RootError::Candidate(CandidateError::InconsistentBinding));
            }
            snapshot
                .objects
                .validate_binding_indexes()
                .and_then(|()| snapshot.objects.validate_confirmation_indexes())
                .map_err(RootError::Candidate)?;
            snapshot
                .objects
                .validate_for_serving()
                .map_err(RootError::Candidate)?;
            Ok(Self {
                snapshot: Arc::clone(snapshot),
            })
        }

        // memory—v1: Expose only the exact snapshot held by this proof.
        pub(super) fn snapshot(&self) -> &Arc<RootSnapshot> {
            &self.snapshot
        }
    }
}

use validated_adoption_snapshot::ValidatedAdoptionSnapshot;

struct RootRuntime {
    current: ArcSwap<RootSnapshot>,
    // memory—v1 §4.12: Serialize writers while allowing independent final
    // checks to share a stable root observation without blocking one another.
    mutation_lock: RwLock<()>,
    // memory—v1 §4.9: the resource/action registry; every §4.9 state-machine
    // transition bumps its version, which participates in the §4.7 dependency set.
    registry: RegistryState,
    // memory—v1 §4.6: active modification fences keyed by rule set.
    fences: FenceRegistry,
    // memory—v1: An installed root accepts exactly one process-local session
    // authority for its lifetime; a dropped authority cannot be replaced here.
    session_authority: OnceLock<Arc<crate::memory_v1_session::SessionAuthorityToken>>,
    // memory—v1 §4.10: bumped whenever the tenant tree structure changes; the
    // tree itself is immutable inside one snapshot.
    tenant_tree_version: AtomicU64,
}

/// A cloneable read capability for the one installed root.
///
/// The weak reference prevents a consumer handle from extending the owner
/// lifetime. It points at the same runtime; it never contains an independent
/// object graph and exposes no mutation operation.
#[derive(Clone)]
pub struct RootHandle {
    runtime: Weak<RootRuntime>,
}

/// A candidate request-scoped owner for one lazily captured root reader.
///
/// Create one context per request and borrow its reader across participating
/// modules. Neither the context nor its request ID proves identity, authorization,
/// or production readiness. The context has no refresh operation; ending or
/// cancelling the request must drop it and all borrows of its reader.
pub struct RequestRootContext {
    handle: RootHandle,
    request_id: Uuid,
    reader: Option<Arc<RequestRootReader>>,
    failure: Option<RequestRootFailure>,
}

#[derive(Clone, Copy)]
enum RequestRootFailure {
    OwnerGone,
    Unavailable(RootStatus),
}

impl From<RequestRootFailure> for RootError {
    // memory—v1: Preserve the terminal failure without retaining its snapshot.
    fn from(failure: RequestRootFailure) -> Self {
        match failure {
            RequestRootFailure::OwnerGone => Self::OwnerGone,
            RequestRootFailure::Unavailable(status) => Self::Unavailable(status),
        }
    }
}

/// A request-scoped, read-only view of one immutable root snapshot.
///
/// Share this value by borrowing it within one request. It keeps the snapshot,
/// not the owner, alive. The request ID is only for correlation and is not an
/// identity or authorization proof. This candidate has no refresh operation;
/// a future controlled refill must first retire all users of the old phase.
pub struct RequestRootReader {
    request_id: Uuid,
    snapshot: Arc<RootSnapshot>,
    observation: RootObservation,
}

/// The non-cloneable lifetime owner of one installed root.
///
/// The composition root must retain this value until every consumer has
/// stopped. Dropping it invalidates weak consumer handles; the registry keeps
/// only the one-time installation marker and does not keep a second strong root.
pub struct RootOwner {
    runtime: Arc<RootRuntime>,
}

/// Installation and lifetime owner for one root in one composition scope.
///
/// The process-wide installer is the only production entry point. This registry
/// type remains private so another crate cannot create a second process root;
/// unit tests use it to isolate their own composition scopes.
struct RootRegistry {
    slot: OnceLock<Weak<RootRuntime>>,
}

/// memory—v1: An isolated installation scope for contract tests only.
///
/// This is not a production entry point: it never installs the process root
/// and exists so a test binary can hold one candidate at a time without
/// colliding with the process-wide installer.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn install_isolated_test_root(
    rows: CandidateRows,
    selections: Vec<CurrentSelection>,
    budget: CandidateBudget,
) -> Result<RootOwner, RootError> {
    RootRegistry::new().install_candidate(rows, selections, budget)
}

/// The process-wide installation slot used by the single-node composition root.
static PROCESS_ROOT: RootRegistry = RootRegistry::new();

/// Errors from root installation or immutable root reads.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RootError {
    /// A registry already has a root installed.
    #[error("memory-v1 root is already installed")]
    AlreadyInstalled,
    /// The registry has no installed root.
    #[error("memory-v1 root is not installed")]
    NotInstalled,
    /// The owner was dropped before the consumer read.
    #[error("memory-v1 root owner is gone")]
    OwnerGone,
    /// The root status does not permit the requested read.
    #[error("memory-v1 root status is not readable: {0:?}")]
    Unavailable(RootStatus),
    /// Candidate row validation failed.
    #[error("memory-v1 candidate validation failed: {0:?}")]
    Candidate(CandidateError),
    /// Candidate digest construction failed.
    #[error("memory-v1 candidate digest failed: {0:?}")]
    Runtime(RuntimeError),
    /// The resource registry could not prove the current rule references.
    #[error("memory-v1 registry validation failed: {0}")]
    Registry(RegistryError),
    /// Candidate row relationships were not closed.
    #[error("memory-v1 candidate relationships are incomplete")]
    InconsistentCandidate,
    /// Adoption evidence was incomplete or did not match the candidate snapshot.
    #[error("memory-v1 adoption evidence rejected: {0}")]
    AdoptionEvidence(#[from] crate::memory_v1_adoption::AdoptionEvidenceError),
    /// A certificate was issued for another root snapshot.
    #[error("memory-v1 serving adoption certificate does not match the root")]
    AdoptionCertificateMismatch,
    /// A production admission was not issued by the current root owner.
    #[error("memory-v1 production admission does not match the current root")]
    ProductionAdmissionMismatch,
    /// The current root has no complete production admission proof.
    #[error("memory-v1 production admission is unavailable")]
    ProductionAdmissionUnavailable,
    /// The root changed after adoption validation; no candidate was published.
    #[error("memory-v1 root changed during serving adoption")]
    AdoptionSnapshotChanged,
    /// A root observation belongs to a different installed root.
    #[error("memory-v1 root observation belongs to another owner")]
    ForeignOwner,
}

impl RootRegistry {
    /// memory—v1: Create an empty installation scope.
    pub const fn new() -> Self {
        Self {
            slot: OnceLock::new(),
        }
    }

    /// memory—v1: Install one candidate object graph and return its read handle.
    ///
    /// Construction validates the supplied references and builds all indexes
    /// before publication. The candidate remains non-authorizing; a future
    /// adoption gate must explicitly prove completeness before `Serving`.
    pub fn install_candidate(
        &self,
        rows: CandidateRows,
        selections: Vec<CurrentSelection>,
        budget: CandidateBudget,
    ) -> Result<RootOwner, RootError> {
        count_rows(&rows, budget.max_table_rows).map_err(RootError::Candidate)?;
        let digest_index = digest_rows(&rows, &selections).map_err(RootError::Runtime)?;
        let digest = digest_index.digest();
        let objects =
            HamtCandidate::build(rows, selections, budget).map_err(RootError::Candidate)?;
        let (actual_budget, row_count) = objects.budget_and_row_count();
        let metadata = RootMetadata {
            instance_id: RootInstanceId(Uuid::new_v4()),
            version: 0,
            digest,
            budget: actual_budget,
            row_count,
            status: RootStatus::Candidate,
        };
        let runtime = Arc::new(RootRuntime {
            current: ArcSwap::from_pointee(RootSnapshot {
                metadata,
                objects,
                digest_index,
                adoption: None,
            }),
            mutation_lock: RwLock::new(()),
            registry: RegistryState::default(),
            fences: FenceRegistry::default(),
            session_authority: OnceLock::new(),
            tenant_tree_version: AtomicU64::new(0),
        });
        self.slot
            .set(Arc::downgrade(&runtime))
            .map_err(|_| RootError::AlreadyInstalled)?;
        Ok(RootOwner { runtime })
    }

    /// memory—v1: Return a read handle for the already installed root.
    pub fn handle(&self) -> Result<RootHandle, RootError> {
        let runtime = self
            .slot
            .get()
            .ok_or(RootError::NotInstalled)?
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        Ok(RootHandle {
            runtime: Arc::downgrade(&runtime),
        })
    }
}

impl Default for RootRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// memory—v1: Install the one process-wide candidate root.
pub fn install_process_root(
    rows: CandidateRows,
    selections: Vec<CurrentSelection>,
    budget: CandidateBudget,
) -> Result<RootOwner, RootError> {
    PROCESS_ROOT.install_candidate(rows, selections, budget)
}

/// memory—v1: Obtain a handle to the process-wide root after installation.
pub fn process_root_handle() -> Result<RootHandle, RootError> {
    PROCESS_ROOT.handle()
}

impl RootOwner {
    /// memory—v1: Create the read capability distributed to consumers.
    pub fn handle(&self) -> RootHandle {
        RootHandle {
            runtime: Arc::downgrade(&self.runtime),
        }
    }

    // memory—v1: Bind both lifetime slots under this root's writer. A root can
    // never switch authorities, and an authority can never span two root instances.
    pub(crate) fn bind_session_authority(
        &self,
        authority_id: &Arc<crate::memory_v1_session::SessionAuthorityToken>,
    ) -> bool {
        let Ok(_guard) = self.runtime.mutation_lock.write() else {
            return false;
        };
        let current = self.runtime.current.load_full();
        if current.metadata.version == u64::MAX
            || !matches!(
                current.metadata.status,
                RootStatus::Candidate | RootStatus::Serving
            )
        {
            return false;
        }
        if let Some(bound) = self.runtime.session_authority.get() {
            return Arc::ptr_eq(bound, authority_id)
                && authority_id.bind_root(current.metadata.instance_id);
        }
        if !authority_id.bind_root(current.metadata.instance_id) {
            return false;
        }
        self.runtime
            .session_authority
            .set(Arc::clone(authority_id))
            .is_ok()
    }

    /// memory—v1: Adopt only after a complete verifier binds all evidence to
    /// this exact candidate metadata and the structural serving checks pass.
    pub fn adopt_with_evidence(
        &self,
        evidence: &crate::memory_v1_adoption::AdoptionEvidence,
    ) -> Result<RootMetadata, RootError> {
        self.adopt_with_evidence_and_admission(evidence)
            .map(|(metadata, _)| metadata)
    }

    /// memory—v1: The complete production adoption entry point.
    ///
    /// The bundle must carry a sealed fact for every non-structural family;
    /// the structural families are re-derived from this exact candidate. On
    /// success the exact snapshot is published `Serving` at the production
    /// grade and the root-owned [`ProductionAdmission`] capability is returned
    /// from the winning CAS. Any gap, mismatch or concurrent publication
    /// changes nothing and reports the failure.
    pub fn adopt_with_production_evidence(
        &self,
        facts: &crate::memory_v1_adoption::ColdLoadFacts,
        input: &crate::memory_v1_adoption::ProductionEvidenceInput,
    ) -> Result<(RootMetadata, ProductionAdmission), RootError> {
        let current = self.runtime.current.load_full();
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::production(
            current.metadata,
            current.objects.table_counts(),
            current.objects.has_valid_current_pointers(),
            facts,
            input,
        );
        self.adopt_with_evidence_and_admission(&evidence)
    }

    /// memory—v1: Mint a production admission only from the complete production
    /// evidence path. Experimental and isolated-test adoption never returns this
    /// capability.
    pub fn adopt_with_evidence_and_admission(
        &self,
        evidence: &crate::memory_v1_adoption::AdoptionEvidence,
    ) -> Result<(RootMetadata, ProductionAdmission), RootError> {
        let current = self.runtime.current.load_full();
        let verified = evidence.verify(current.metadata)?;
        let record = verified.record(AdoptionGrade::Production, None, None);
        self.adopt_snapshot_with_admission(&current, &verified.certificate, record)
    }

    /// memory—v1: Validate a production admission against this exact live root.
    ///
    /// The capability is deliberately opaque to callers. Validation therefore stays
    /// root-owned and compares both private runtime identity and exact snapshot
    /// identity before trusting its metadata or adoption record. A readable
    /// `Serving` status by itself is never sufficient.
    pub fn validate_production_admission(
        &self,
        admission: &ProductionAdmission,
    ) -> Result<RootMetadata, RootError> {
        self.handle().validate_production_admission(admission)
    }

    /// creates a record without schema, count or capture-time details; it is not
    /// evidence that a future production-adoption contract has been completed.
    pub fn adopt_serving(
        &self,
        certificate: &ServingAdoptionCertificate,
    ) -> Result<RootMetadata, RootError> {
        let current = self.runtime.current.load_full();
        let record = AdoptionRecord {
            grade: AdoptionGrade::Production,
            unverified: Vec::new(),
            schema_fingerprint: None,
            counts: None,
            captured_at_unix_seconds: None,
        };
        self.adopt_snapshot(&current, certificate, record)
    }

    /// memory—v1: Adopt the current candidate as `Serving` at **experimental**
    /// grade, for one explicitly isolated service run.
    ///
    /// This is not production adoption and does not prove the data. The root
    /// checks the caller-reported schema version and nonzero fingerprint, compares
    /// reported counts with its own rows, validates current-version pointers,
    /// and requires a nonnegative reported capture time. It does not independently
    /// authenticate the schema, scan or time. Other fact families stay unverified
    /// and require the caller to acknowledge each exact [`AdoptionLimit`]. The
    /// limits are published in the [`AdoptionRecord`] with the serving snapshot.
    pub fn adopt_experimental(
        &self,
        facts: &ColdLoadFacts,
        acknowledged: &[AdoptionLimit],
    ) -> Result<RootMetadata, RootError> {
        let current = self.runtime.current.load_full();
        let evidence = AdoptionEvidence::from_cold_load(
            current.metadata,
            current.objects.table_counts(),
            current.objects.has_valid_current_pointers(),
            facts,
        );
        let verified = evidence.verify_experimental(current.metadata, acknowledged)?;
        let record = verified.record(
            AdoptionGrade::Experimental,
            Some(facts.schema_fingerprint),
            Some(current.objects.table_counts()),
        );
        self.adopt_snapshot(&current, &verified.certificate, record)
    }

    /// memory—v1: Report, without adopting anything, every production evidence family the
    /// current candidate cannot prove, in decision order. An empty list means every family
    /// is proven. This changes no root status, publishes no snapshot and admits no listener;
    /// production adoption still needs the verifier to pass for the exact snapshot.
    pub fn unproven_production_families(&self, facts: &ColdLoadFacts) -> Vec<&'static str> {
        let current = self.runtime.current.load_full();
        AdoptionEvidence::from_cold_load(
            current.metadata,
            current.objects.table_counts(),
            current.objects.has_valid_current_pointers(),
            facts,
        )
        .unproven_families()
    }

    /// memory—v1: Apply one journaled mutation during crash recovery.
    ///
    /// This is the recovery owner's controlled replay path. It is refused
    /// unless the root is still a Candidate (recovery happens before adoption,
    /// before any session authority is bound, and before any listener exists).
    /// The precondition must name the exact current version, so a replayed
    /// sequence cannot skip or double-apply; each record advances the version
    /// by one, matching the journal's contiguous mutation sequence.
    ///
    /// Card disables are permitted here because no session can exist yet: the
    /// session authority binds only after adoption, so there is nothing to
    /// revoke. A later session issued against a re-enabled card would be
    /// validated against the replayed state, not against a stale credential.
    /// The journal record's complete audit value is the evidence of why the
    /// mutation happened; this path adds no new authorization.
    pub fn execute_recovery_mutation(
        &self,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
    ) -> Result<RootMetadata, MutationError> {
        let current = self.runtime.current.load_full();
        if current.metadata.status != RootStatus::Candidate {
            return Err(MutationError::ConcurrentModification);
        }
        if current.metadata.version != precondition.evaluated_root_version {
            return Err(MutationError::ConcurrentModification);
        }
        Self::execute_on_recovery(&self.runtime, mutation, precondition)
    }

    /// memory—v1: Adopt a fixture with the same structural and snapshot checks.
    /// The feature is not a security boundary and this record proves no data.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn adopt_serving_for_isolated_tests(&self) -> Result<RootMetadata, RootError> {
        let current = self.runtime.current.load_full();
        let evidence =
            crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(current.metadata);
        self.adopt_isolated_evidence(&evidence)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn adopt_isolated_evidence(
        &self,
        evidence: &crate::memory_v1_adoption::AdoptionEvidence,
    ) -> Result<RootMetadata, RootError> {
        let current = self.runtime.current.load_full();
        let verified = evidence.verify(current.metadata)?;
        let record = verified.record(AdoptionGrade::IsolatedTest, None, None);
        self.adopt_snapshot(&current, &verified.certificate, record)
    }

    // memory—v1: Bind validation and publication to the same captured snapshot.
    fn adopt_snapshot(
        &self,
        current: &Arc<RootSnapshot>,
        certificate: &ServingAdoptionCertificate,
        record: AdoptionRecord,
    ) -> Result<RootMetadata, RootError> {
        self.adopt_snapshot_internal(current, certificate, record, false)
            .map(|(metadata, _)| metadata)
    }

    // memory—v1: The production capability is created only after the exact
    // published snapshot has won the CAS. It cannot be derived from the record
    // later because later snapshots intentionally retain adoption history.
    fn adopt_snapshot_with_admission(
        &self,
        current: &Arc<RootSnapshot>,
        certificate: &ServingAdoptionCertificate,
        record: AdoptionRecord,
    ) -> Result<(RootMetadata, ProductionAdmission), RootError> {
        let (metadata, snapshot) =
            self.adopt_snapshot_internal(current, certificate, record, true)?;
        Ok((
            metadata,
            ProductionAdmission::for_published_snapshot(&self.runtime, &snapshot),
        ))
    }

    // memory—v1: Share the structural adoption gate while keeping the production
    // admission minting decision explicit at the call site.
    fn adopt_snapshot_internal(
        &self,
        current: &Arc<RootSnapshot>,
        certificate: &ServingAdoptionCertificate,
        record: AdoptionRecord,
        require_production_admission: bool,
    ) -> Result<(RootMetadata, Arc<RootSnapshot>), RootError> {
        let source_matches_grade = match (certificate.source, record.grade) {
            (AdoptionCertificateSource::Production, AdoptionGrade::Production)
            | (AdoptionCertificateSource::Experimental, AdoptionGrade::Experimental) => true,
            #[cfg(any(test, feature = "test-support"))]
            (AdoptionCertificateSource::IsolatedTest, AdoptionGrade::IsolatedTest) => true,
            _ => false,
        };
        if certificate.instance_id != current.metadata.instance_id
            || certificate.version != current.metadata.version
            || certificate.digest != current.metadata.digest
            || !source_matches_grade
            || (record.grade == AdoptionGrade::Production && !record.unverified.is_empty())
            || (require_production_admission && record.grade != AdoptionGrade::Production)
        {
            return Err(RootError::AdoptionCertificateMismatch);
        }
        if current.metadata.version == u64::MAX {
            // memory—v1 §15.10.3: exhausted metadata cannot become or remain
            // a positive-authorization serving snapshot.
            return Err(RootError::Unavailable(RootStatus::Invalid));
        }
        match current.metadata.status {
            RootStatus::Serving if require_production_admission => {
                return Err(RootError::ProductionAdmissionUnavailable)
            }
            RootStatus::Serving => return Ok((current.metadata, Arc::clone(current))),
            RootStatus::Candidate => {}
            status => return Err(RootError::Unavailable(status)),
        }
        let validated = ValidatedAdoptionSnapshot::validate(current)?;
        // Keep the registry and root stable together until the exact checked
        // snapshot is published, in the same order as final authorization.
        let _mutation_guard = self
            .runtime
            .mutation_lock
            .write()
            .map_err(|_| RootError::Runtime(RuntimeError::Poisoned))?;
        let registry = self
            .runtime
            .registry
            .read_for_publication()
            .map_err(RootError::Registry)?;
        validated
            .snapshot()
            .objects
            .validate_current_registry(&registry)
            .map_err(RootError::Candidate)?;
        let published = self.publish_adopted_snapshot_and_snapshot(&validated, record);
        drop(registry);
        published
    }

    // memory—v1: Keep the historical metadata-returning helper for root-local
    // callers while the production path retains the exact published snapshot.
    #[allow(dead_code)] // historical helper retained for the metadata-returning adoption path
    fn publish_adopted_snapshot(
        &self,
        validated: &ValidatedAdoptionSnapshot,
        record: AdoptionRecord,
    ) -> Result<RootMetadata, RootError> {
        self.publish_adopted_snapshot_and_snapshot(validated, record)
            .map(|(metadata, _)| metadata)
    }

    // memory—v1: Publish only the exact snapshot that passed structural validation,
    // with the record of how it was adopted.
    fn publish_adopted_snapshot_and_snapshot(
        &self,
        validated: &ValidatedAdoptionSnapshot,
        record: AdoptionRecord,
    ) -> Result<(RootMetadata, Arc<RootSnapshot>), RootError> {
        let validated = validated.snapshot();
        if validated.metadata.version == u64::MAX {
            // memory—v1 §15.10.3: an exhausted candidate cannot be promoted.
            return Err(RootError::Unavailable(RootStatus::Invalid));
        }
        let mut metadata = validated.metadata;
        metadata.status = RootStatus::Serving;
        let next = Arc::new(RootSnapshot {
            metadata,
            objects: validated.objects.clone(),
            digest_index: validated.digest_index.clone(),
            adoption: Some(Arc::new(record)),
        });
        let previous = self
            .runtime
            .current
            .compare_and_swap(validated, Arc::clone(&next));
        if !Arc::ptr_eq(&previous, validated) {
            return Err(RootError::AdoptionSnapshotChanged);
        }
        Ok((metadata, next))
    }

    // memory—v1 §15.10.3: Invalidate an exhausted serving snapshot while the
    // caller holds the mutation write lock. Facts, digest, adoption record, and
    // version stay unchanged; only positive authorization availability is withdrawn.
    fn publish_invalid_snapshot(runtime: &RootRuntime, current: &Arc<RootSnapshot>) {
        if current.metadata.status != RootStatus::Serving {
            return;
        }
        let mut metadata = current.metadata;
        metadata.status = RootStatus::Invalid;
        runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: current.objects.clone(),
            digest_index: current.digest_index.clone(),
            adoption: current.adoption.clone(),
        }));
    }
    // memory—v1: Read-side exhaustion refuses immediately. Publish Invalid only
    // if exclusive access can still be acquired for the exact observed snapshot.
    fn try_publish_exhausted_snapshot(runtime: &RootRuntime, observed: &Arc<RootSnapshot>) {
        if let Ok(_writer) = runtime.mutation_lock.try_write() {
            let latest = runtime.current.load_full();
            if Arc::ptr_eq(&latest, observed) && latest.metadata.version == u64::MAX {
                Self::publish_invalid_snapshot(runtime, &latest);
            }
        }
    }

    /// memory—v1 §4.9: Install aggregated declarations exactly once before
    /// adoption. Without an installed registry a candidate cannot serve.
    pub fn install_registry(
        &self,
        declarations: &[RegistryDeclaration],
    ) -> Result<(), RegistryError> {
        self.runtime.registry.install(declarations)
    }

    /// memory—v1 §4.9: Test a registry transition against a serving snapshot.
    /// This does not grant management authority and is absent from production builds.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn request_registry_retirement_for_test(
        &self,
        resource: &str,
    ) -> Result<(), RegistryError> {
        self.runtime.registry.request_retire(resource)
    }

    /// memory—v1 §4.9: the registry version participates in the §4.7 dependency set.
    pub fn registry_version(&self) -> u64 {
        self.runtime.registry.version()
    }

    /// memory—v1 §4.10: the tenant-tree version participates in the §4.7 dependency set.
    pub fn tenant_tree_version(&self) -> u64 {
        self.runtime.tenant_tree_version.load(Ordering::Relaxed)
    }

    /// memory—v1 §4.6: Open an owner-scoped modification window from the root's
    /// current snapshot. The root read lock remains held through fence insertion,
    /// preserving the root-lock -> fence-lock order and keeping the derived
    /// premise coherent. The guard is only a lifetime fence capability; it does
    /// not commit a mutation or authorize a request.
    pub fn begin_owned_modification_fence(
        &self,
        rule_set_id: BinaryId,
        declaration: &FenceDeclaration,
    ) -> Result<FenceGuard, FenceControlError> {
        let _root_guard = self
            .runtime
            .mutation_lock
            .read()
            .map_err(|_| FenceControlError::Poisoned)?;
        let premise = Self::current_fence_premise(&self.runtime, rule_set_id)?;
        let owner = self.runtime.fences.owner();
        self.runtime
            .fences
            .begin_owned(&owner, rule_set_id, declaration, &premise)
    }

    // memory—v1: Derive a fence premise only while the caller holds the root
    // lock. This is shared by the owned and legacy entry points.
    fn current_fence_premise(
        runtime: &RootRuntime,
        rule_set_id: BinaryId,
    ) -> Result<FencePremise, FenceError> {
        let current = runtime.current.load_full();
        Ok(FencePremise {
            root_version: current.metadata.version,
            digest: current.metadata.digest,
            selected_version: current
                .objects
                .selected_version(rule_set_id)
                .map_err(FenceError::Candidate)?
                .map(|row| row.version_bytes.clone()),
        })
    }

    /// memory—v1 §4.6: open a modification window after verifying the declared
    /// premises against the actual snapshot (same-object mutual exclusion).
    /// A shared root guard keeps the premise stable through fence insertion;
    /// immutable fence snapshots make an opening visible to final checks.
    pub fn begin_modification_fence(
        &self,
        rule_set_id: BinaryId,
        declaration: &FenceDeclaration,
    ) -> Result<(), FenceError> {
        let guard = self
            .runtime
            .mutation_lock
            .read()
            .expect("root mutation lock poisoned");
        let premise = Self::current_fence_premise(&self.runtime, rule_set_id)?;
        let result = self
            .runtime
            .fences
            .try_begin_legacy(rule_set_id, declaration, &premise);
        drop(guard);
        FenceRegistry::finish_legacy_begin(result)
    }

    /// memory—v1 §4.6: close the modification window without publishing.
    pub fn abort_modification_fence(&self, rule_set_id: BinaryId) -> Result<(), FenceError> {
        self.runtime.fences.abort(rule_set_id)
    }

    /// Legacy plans lack the admission and change confirmation required by the
    /// current management contract. Refuse them without changing the root.
    pub fn execute_mutation(
        &self,
        _mutation: &ManagementMutation,
    ) -> Result<RootMetadata, MutationError> {
        Err(MutationError::Candidate(
            CandidateError::InconsistentBinding,
        ))
    }

    /// memory—v1: Apply a mutation only while constructing a candidate root.
    ///
    /// This low-level operation is not an authorization-bound management path.
    /// Serving roots reject every mutation, including revocations and enables.
    /// A card disable is refused because session revocation must be coordinated.
    pub fn execute_mutation_with_precondition(
        &self,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
    ) -> Result<RootMetadata, MutationError> {
        Self::execute_on(&self.runtime, mutation, precondition, false)
    }

    /// memory—v1: Simulate a low-level write on an isolated test root.
    /// This bypasses authorization and is never a governance capability.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn execute_mutation_with_precondition_for_isolated_tests(
        &self,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
    ) -> Result<RootMetadata, MutationError> {
        Self::execute_on(&self.runtime, mutation, precondition, true)
    }

    /// memory—v1: Hand out a weak, low-level candidate mutation capability.
    ///
    /// This is not an authorization-bound management capability. It cannot keep
    /// the owner alive and does not establish admission, replay or audit proof.
    pub fn mutation_executor(&self) -> RootMutationExecutor {
        RootMutationExecutor {
            runtime: Arc::downgrade(&self.runtime),
        }
    }

    // memory—v1: The recovery replay path. It is reached only through
    // `execute_recovery_mutation`, which has already pinned the root to the
    // Candidate state and the exact precondition version under no session
    // authority; the card-disable session gate therefore does not apply here.
    fn execute_on_recovery(
        runtime: &RootRuntime,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
    ) -> Result<RootMetadata, MutationError> {
        let _mutation_guard = runtime
            .mutation_lock
            .write()
            .map_err(|_| MutationError::Runtime(RuntimeError::Poisoned))?;
        let current = runtime.current.load_full();
        if current.metadata.status != RootStatus::Candidate
            || current.metadata.version == u64::MAX
            || current.metadata.version != precondition.evaluated_root_version
        {
            return Err(MutationError::ConcurrentModification);
        }
        Self::execute_on_locked(runtime, mutation, precondition)
    }

    // memory—v1: The single low-level implementation shared by both callers.
    fn execute_on(
        runtime: &RootRuntime,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
        isolated_test: bool,
    ) -> Result<RootMetadata, MutationError> {
        let _mutation_guard = runtime
            .mutation_lock
            .write()
            .map_err(|_| MutationError::Runtime(RuntimeError::Poisoned))?;
        let current = runtime.current.load_full();
        if current.metadata.version == u64::MAX {
            // memory—v1 §15.10.3: no candidate construction may run after the
            // root has exhausted its successor space. Serving is invalidated
            // under the same writer lock, while Candidate remains diagnostic.
            if current.metadata.status == RootStatus::Serving {
                Self::publish_invalid_snapshot(runtime, &current);
            }
            return Err(MutationError::VersionOverflow);
        }
        match current.metadata.status {
            RootStatus::Candidate => {}
            RootStatus::Serving if isolated_test => {}
            RootStatus::Serving => return Err(MutationError::ConcurrentModification),
            RootStatus::Invalid | RootStatus::Stopped => {
                return Err(MutationError::Runtime(RuntimeError::OwnerGone));
            }
        }
        // memory—v1 §4.12: A serving card must not be disabled without the
        // session writer. Otherwise re-enabling it can revive old credentials.
        if matches!(
            mutation,
            ManagementMutationV2::UserCardStatus {
                status: crate::memory_v1_db_rows::UserCardStatus::Disabled,
                ..
            }
        ) && matches!(
            runtime.current.load().metadata.status,
            RootStatus::Candidate | RootStatus::Serving
        ) {
            return Err(MutationError::CardDisableRequiresSessionCoordinator);
        }
        Self::execute_on_locked(runtime, mutation, precondition)
    }

    /// memory—v1: Execute one governed mutation on a serving root through the
    /// root-owned production admission.
    ///
    /// This is the composition owner's controlled write path. The admission
    /// capability must validate against this exact runtime at call time; the
    /// precondition must name the version validated by that admission, so a
    /// stale commit is refused under the writer lock. Card disable keeps the
    /// session-coordinator requirement. Nothing here authorizes the mutation:
    /// the caller supplies the complete audit value and the durable prefix.
    pub fn execute_serving_mutation_with_admission(
        &self,
        admission: &ProductionAdmission,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
    ) -> Result<RootMetadata, MutationError> {
        let runtime = Arc::clone(&self.runtime);
        // The admission check and the writer lock are both root-owned: the
        // capability must match this runtime before any candidate construction.
        self.handle()
            .validate_production_admission(admission)
            .map_err(|error| match error {
                RootError::ProductionAdmissionMismatch => MutationError::ConcurrentModification,
                _ => MutationError::Runtime(RuntimeError::OwnerGone),
            })?;
        if runtime.current.load().metadata.version != precondition.evaluated_root_version {
            return Err(MutationError::ConcurrentModification);
        }
        if matches!(
            mutation,
            ManagementMutationV2::UserCardStatus {
                status: crate::memory_v1_db_rows::UserCardStatus::Disabled,
                ..
            }
        ) {
            return Err(MutationError::CardDisableRequiresSessionCoordinator);
        }
        Self::execute_on(&runtime, mutation, precondition, true)
    }

    // memory—v1: Only callers already holding the root writer may use this
    // implementation. The caller remains responsible for its other lock domains.
    fn execute_on_locked(
        runtime: &RootRuntime,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
    ) -> Result<RootMetadata, MutationError> {
        let current = runtime.current.load_full();
        if current.metadata.version == u64::MAX {
            // memory—v1 §15.10.3: once the root successor space is exhausted,
            // a serving root is invalidated before any candidate is built.
            if current.metadata.status == RootStatus::Serving {
                Self::publish_invalid_snapshot(runtime, &current);
            }
            return Err(MutationError::VersionOverflow);
        }
        if !matches!(
            current.metadata.status,
            RootStatus::Candidate | RootStatus::Serving
        ) {
            return Err(MutationError::Runtime(RuntimeError::OwnerGone));
        }
        // §15.10: 受限提交需再次核对根版本/CAS — a commit at stale version
        // is refused while holding the writer lock, before candidate construction.
        if current.metadata.version != precondition.evaluated_root_version {
            return Err(MutationError::ConcurrentModification);
        }
        let candidate = &current.objects;
        let old_version = current.metadata.version;
        // The retirement result is sealed around its exact candidate after the
        // current binding indexes are checked. Other mutations still validate
        // both index families on their newly constructed candidate.
        let next = if let ManagementMutationV2::RuleSetRetire { rule_set_id } = mutation {
            PublicationCandidate::Retirement(
                candidate
                    .prepare_validated_retirement(*rule_set_id)
                    .and_then(|retirement| retirement.validate_confirmations())
                    .map_err(MutationError::Candidate)?,
            )
        } else {
            let next = match mutation {
                ManagementMutationV2::BindingCreate { row, confirmation } => {
                    if confirmation.binding_id != row.binding_id
                        || confirmation.rule_set_id != row.rule_set_id
                    {
                        return Err(MutationError::Candidate(CandidateError::Rows(
                            crate::memory_v1_db_rows::ValidationError::MissingBindingPair {
                                binding_id: row.binding_id,
                                rule_set_id: row.rule_set_id,
                            },
                        )));
                    }
                    if confirmation.revoked_at.is_some() || confirmation.revoked_by.is_some() {
                        return Err(MutationError::Candidate(CandidateError::Rows(
                            crate::memory_v1_db_rows::ValidationError::MissingReference {
                                table: crate::memory_v1_db_rows::Table::BindingConfirmation,
                                field: "active_confirmation",
                                id: confirmation.confirmation_id,
                            },
                        )));
                    }
                    candidate
                        .with_binding_insert(row.clone())
                        .and_then(|c| c.with_confirmation_insert(confirmation.clone()))
                        .map_err(MutationError::Candidate)?
                }
                ManagementMutationV2::BindingRemove {
                    binding_id,
                    removed_at,
                    removed_by,
                } => candidate
                    .with_binding_removed(*binding_id, *removed_at, *removed_by)
                    .map_err(MutationError::Candidate)?,
                ManagementMutationV2::ConfirmationCreate { row } => candidate
                    .with_confirmation_insert(row.clone())
                    .map_err(MutationError::Candidate)?,
                ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id,
                    revoked_at,
                    revoked_by,
                } => candidate
                    .with_confirmation_revoked(*confirmation_id, *revoked_at, *revoked_by)
                    .map_err(MutationError::Candidate)?,
                ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    confirmation_id,
                    revoked_at,
                    revoked_by,
                } => candidate
                    .with_change_confirmation_revoked(*confirmation_id, *revoked_at, *revoked_by)
                    .map_err(MutationError::Candidate)?,
                // memory—v1 §4.11 N-10: one batch = one root CAS; all-or-nothing.
                ManagementMutationV2::ConfirmationBatch { rows } => candidate
                    .with_confirmations_batch(rows)
                    .map_err(MutationError::Candidate)?,
                ManagementMutationV2::UserCardCreate { row } => candidate
                    .with_user_card_create(row.clone())
                    .map_err(MutationError::Candidate)?,
                ManagementMutationV2::UserCardStatus {
                    user_card_id,
                    status,
                } => candidate
                    .with_user_card_status(*user_card_id, *status)
                    .map_err(MutationError::Candidate)?,
                // memory—v1 §4.11: 首版创建同事务携带变更确认（版本新鲜度不变式）。
                ManagementMutationV2::RuleSetCreate {
                    rule_set,
                    version,
                    change_confirmation,
                } => {
                    Self::require_change_confirmation_for(
                        change_confirmation,
                        rule_set.rule_set_id,
                        &version.version_bytes,
                    )?;
                    candidate
                        .with_rule_set_create(rule_set.clone(), version.clone())
                        .and_then(|c| {
                            c.with_change_confirmation_insert(change_confirmation.clone())
                        })
                        .map_err(MutationError::Candidate)?
                }
                ManagementMutationV2::RuleSetRetire { .. } => {
                    unreachable!("retirement handled above")
                }
                // memory—v1 §4.11: 发布 + confirm-change 同事务（单阶段）。
                ManagementMutationV2::VersionPublish {
                    rule_set_id,
                    version_row,
                    new_current_version,
                    change_confirmation,
                } => {
                    if version_row.rule_set_id != *rule_set_id
                        || version_row.version_bytes != *new_current_version
                    {
                        return Err(MutationError::Candidate(CandidateError::Rows(
                            crate::memory_v1_db_rows::ValidationError::MissingVersionReference {
                                table: crate::memory_v1_db_rows::Table::RuleSetVersion,
                                rule_set_id: *rule_set_id,
                                version_bytes: version_row.version_bytes.clone(),
                            },
                        )));
                    }
                    Self::require_change_confirmation_for(
                        change_confirmation,
                        *rule_set_id,
                        new_current_version,
                    )?;
                    candidate
                        .append_version(version_row.clone())
                        .and_then(|c| c.with_current_version(*rule_set_id, new_current_version))
                        .and_then(|c| {
                            c.with_change_confirmation_insert(change_confirmation.clone())
                        })
                        .map_err(MutationError::Candidate)?
                }
            };
            // Index coverage is verified independently of the content digest before CAS.
            next.validate_binding_indexes()
                .and_then(|()| next.validate_confirmation_indexes())
                .map_err(MutationError::Candidate)?;
            PublicationCandidate::Checked(next)
        };
        // Prepare the changed digest rows privately against this exact snapshot.
        // The matching index, facts and metadata are published by one CAS.
        let (budget, row_count) = next.candidate().budget_and_row_count();
        let digest_index = prepare_root_digest(&current.digest_index, next.candidate(), mutation)?;
        let digest = digest_index.digest();
        // Keep the registry stable from the complete rule check through CAS.
        let registry = match mutation {
            ManagementMutationV2::RuleSetCreate { version, .. }
            | ManagementMutationV2::VersionPublish {
                version_row: version,
                ..
            } => {
                let content = crate::memory_v1_rules::parse_version(version).map_err(|error| {
                    MutationError::Candidate(CandidateError::RuleIntegrity(error))
                })?;
                let registry = runtime
                    .registry
                    .read_for_publication()
                    .map_err(MutationError::Registry)?;
                registry
                    .validate_rules(&content)
                    .map_err(MutationError::Registry)?;
                Some(registry)
            }
            _ => None,
        };

        // §4.6/§15.10: version, candidate and its prepared digest index are
        // published together as one atomic root snapshot.
        let mut metadata = current.metadata;
        metadata.version = old_version
            .checked_add(1)
            .ok_or(MutationError::VersionOverflow)?;
        metadata.budget = budget;
        metadata.row_count = row_count;
        metadata.digest = digest;
        let next_snapshot = Arc::new(RootSnapshot {
            metadata,
            objects: next.into_candidate(),
            digest_index,
            adoption: current.adoption.clone(),
        });
        let previous = runtime.current.compare_and_swap(&current, next_snapshot);
        // Hold the registry observation through CAS; releasing it earlier lets
        // a concurrent retirement invalidate the rule before publication.
        drop(registry);
        if !Arc::ptr_eq(&previous, &current) {
            return Err(MutationError::ConcurrentModification);
        }
        Ok(metadata)
    }

    // memory—v1 §4.11: the change confirmation must reference exactly the
    // version being created/published — a mismatch is a malformed plan and is
    // refused before any candidate state is built.
    fn require_change_confirmation_for(
        change_confirmation: &crate::memory_v1_db_rows::RuleSetChangeConfirmationRow,
        rule_set_id: BinaryId,
        version_bytes: &[u8],
    ) -> Result<(), MutationError> {
        if change_confirmation.rule_set_id != rule_set_id
            || change_confirmation.version_bytes != version_bytes
            || change_confirmation.revoked_at.is_some()
            || change_confirmation.revoked_by.is_some()
        {
            return Err(MutationError::Candidate(CandidateError::Rows(
                crate::memory_v1_db_rows::ValidationError::MissingVersionReference {
                    table: crate::memory_v1_db_rows::Table::RuleSetChangeConfirmation,
                    rule_set_id,
                    version_bytes: change_confirmation.version_bytes.clone(),
                },
            )));
        }
        Ok(())
    }
}

/// memory—v1: A caller-supplied version precondition for low-level candidate CAS.
/// This value is not an admission and does not bind a change summary.
#[derive(Clone, Copy, Debug)]
pub struct MutationPrecondition {
    pub evaluated_root_version: u64,
}

/// memory—v1: A clonable low-level mutation handle that cannot extend the
/// root owner's lifetime. It carries no admission, mutation binding, replay
/// protection or audit proof, and must not be exposed as a governance write gate.
#[derive(Clone)]
pub struct RootMutationExecutor {
    runtime: std::sync::Weak<RootRuntime>,
}

impl RootMutationExecutor {
    /// memory—v1: Execute a candidate-only mutation through the CAS gate.
    /// Serving roots reject all writes; this handle does not authorize them.
    pub fn execute(
        &self,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
    ) -> Result<RootMetadata, MutationError> {
        let runtime = self
            .runtime
            .upgrade()
            .ok_or(MutationError::Runtime(RuntimeError::OwnerGone))?;
        RootOwner::execute_on(&runtime, mutation, precondition, false)
    }

    /// memory—v1: Simulate a low-level write in an isolated test only.
    /// This bypasses authorization and is never a governance capability.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn execute_for_isolated_tests(
        &self,
        mutation: &ManagementMutationV2,
        precondition: &MutationPrecondition,
    ) -> Result<RootMetadata, MutationError> {
        let runtime = self
            .runtime
            .upgrade()
            .ok_or(MutationError::Runtime(RuntimeError::OwnerGone))?;
        RootOwner::execute_on(&runtime, mutation, precondition, true)
    }

    /// memory—v1: The production card-disable coordinator.
    ///
    /// The session authority holds its writer before entering this
    /// coordinator. The authority must be the one bound to this root; the
    /// caller supplies the exact observed serving metadata so a stale commit
    /// is refused under the root writer lock. All fallible root work
    /// completes before the callback, which must only apply prevalidated,
    /// infallible session updates. This path is reached only through the
    /// durable commit owner's proof chain; it adds no authorization of its
    /// own.
    pub fn disable_card_with_session_updates(
        &self,
        authority: &crate::memory_v1_session_authority::MemoryV1SessionAuthority,
        user_card_id: BinaryId,
        expected: RootMetadata,
        apply_session_updates: impl FnOnce(),
    ) -> Result<RootMetadata, MutationError> {
        self.disable_card_with_session_updates_internal(
            authority.authority_token(),
            user_card_id,
            expected,
            apply_session_updates,
        )
    }

    // memory—v1: The session authority holds its writer before entering this
    // crate-private coordinator. All fallible root work completes before the
    // callback, which must only apply prevalidated, infallible session updates.
    pub(crate) fn disable_card_with_session_updates_internal(
        &self,
        authority_id: &Arc<crate::memory_v1_session::SessionAuthorityToken>,
        user_card_id: BinaryId,
        expected: RootMetadata,
        apply_session_updates: impl FnOnce(),
    ) -> Result<RootMetadata, MutationError> {
        let runtime = self
            .runtime
            .upgrade()
            .ok_or(MutationError::Runtime(RuntimeError::OwnerGone))?;
        let _guard = runtime
            .mutation_lock
            .try_write()
            .map_err(|_| MutationError::Runtime(RuntimeError::StaleToken))?;
        if !runtime
            .session_authority
            .get()
            .is_some_and(|bound| Arc::ptr_eq(bound, authority_id))
            || runtime.current.load_full().metadata != expected
            || expected.status != RootStatus::Serving
        {
            return Err(MutationError::ConcurrentModification);
        }
        let metadata = RootOwner::execute_on_locked(
            &runtime,
            &ManagementMutationV2::UserCardStatus {
                user_card_id,
                status: crate::memory_v1_db_rows::UserCardStatus::Disabled,
            },
            &MutationPrecondition {
                evaluated_root_version: expected.version,
            },
        )?;
        apply_session_updates();
        Ok(metadata)
    }
}

/// Legacy candidate mutation plan. It does not carry an admission or enough
/// information to authorize a governance write.
#[derive(Clone, Debug)]
pub enum ManagementMutation {
    BindingCreate {
        row: crate::memory_v1_db_rows::BindingRow,
        confirmation: crate::memory_v1_db_rows::BindingConfirmationRow,
    },
    BindingRemove {
        binding_id: BinaryId,
        removed_at: i64,
        removed_by: BinaryId,
    },
    ConfirmationCreate {
        row: crate::memory_v1_db_rows::BindingConfirmationRow,
    },
    ConfirmationRevoke {
        confirmation_id: BinaryId,
        revoked_at: i64,
        revoked_by: BinaryId,
    },
    UserCardStatus {
        user_card_id: BinaryId,
        status: crate::memory_v1_db_rows::UserCardStatus,
    },
    RuleSetCreate {
        rule_set: crate::memory_v1_db_rows::RuleSetRow,
        version: crate::memory_v1_db_rows::RuleSetVersionRow,
    },
    VersionPublish {
        rule_set_id: BinaryId,
        version_row: crate::memory_v1_db_rows::RuleSetVersionRow,
        new_current_version: Vec<u8>,
    },
}

/// memory—v1: A candidate mutation plan; this value carries no admission.
#[derive(Clone, Debug)]
pub enum ManagementMutationV2 {
    BindingCreate {
        row: crate::memory_v1_db_rows::BindingRow,
        confirmation: crate::memory_v1_db_rows::BindingConfirmationRow,
    },
    BindingRemove {
        binding_id: BinaryId,
        removed_at: i64,
        removed_by: BinaryId,
    },
    ConfirmationCreate {
        row: crate::memory_v1_db_rows::BindingConfirmationRow,
    },
    ConfirmationRevoke {
        confirmation_id: BinaryId,
        revoked_at: i64,
        revoked_by: BinaryId,
    },
    /// memory—v1 §4.12 B-2.4: revoke a rule-set change confirmation in a
    /// candidate; this value does not authorize a serving-root mutation.
    RuleSetChangeConfirmationRevoke {
        confirmation_id: BinaryId,
        revoked_at: i64,
        revoked_by: BinaryId,
    },
    /// memory—v1 §4.11 N-10: a whole batch of confirmations, published by one
    /// root CAS; the candidate layer refuses the batch on any invalid entry.
    ConfirmationBatch {
        rows: Vec<crate::memory_v1_db_rows::BindingConfirmationRow>,
    },
    /// memory—v1: An unbound new card candidate. Its user and tenant are part
    /// of the mutation value; this plan carries no authorization or admission.
    UserCardCreate {
        row: crate::memory_v1_db_rows::UserCardRow,
    },
    UserCardStatus {
        user_card_id: BinaryId,
        status: crate::memory_v1_db_rows::UserCardStatus,
    },
    RuleSetCreate {
        rule_set: crate::memory_v1_db_rows::RuleSetRow,
        version: crate::memory_v1_db_rows::RuleSetVersionRow,
        change_confirmation: crate::memory_v1_db_rows::RuleSetChangeConfirmationRow,
    },
    /// memory—v1 §4.12 B-2.5: candidate retirement; no admission is implied.
    RuleSetRetire { rule_set_id: BinaryId },
    VersionPublish {
        rule_set_id: BinaryId,
        version_row: crate::memory_v1_db_rows::RuleSetVersionRow,
        new_current_version: Vec<u8>,
        change_confirmation: crate::memory_v1_db_rows::RuleSetChangeConfirmationRow,
    },
}

/// Errors from the low-level candidate mutation path.
#[derive(Debug, Error)]
pub enum MutationError {
    #[error("candidate mutation failed: {0:?}")]
    Candidate(CandidateError),
    #[error("runtime error: {0:?}")]
    Runtime(RuntimeError),
    #[error("resource registry validation failed: {0}")]
    Registry(RegistryError),
    #[error("root version overflow")]
    VersionOverflow,
    #[error("concurrent modification: another writer published first")]
    ConcurrentModification,
    #[error("card disable requires the bound session coordinator")]
    CardDisableRequiresSessionCoordinator,
}

// memory—v1: Recompute a candidate digest for test fixtures.
#[cfg(test)]
fn digest_candidate_from_candidate(
    candidate: &HamtCandidate,
) -> Result<ContentDigest, MutationError> {
    let (rows, selections) = candidate.digest_inputs();
    digest_candidate(&rows, &selections).map_err(MutationError::Runtime)
}

impl Drop for RootOwner {
    // memory—v1: Serialize stopping with mutation CAS and preserve the latest snapshot.
    fn drop(&mut self) {
        let _guard = self
            .runtime
            .mutation_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = self.runtime.current.load_full();
        let mut metadata = current.metadata;
        metadata.status = RootStatus::Stopped;
        self.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: current.objects.clone(),
            digest_index: current.digest_index.clone(),
            adoption: current.adoption.clone(),
        }));
    }
}

impl RootHandle {
    fn runtime(&self) -> Result<Arc<RootRuntime>, RootError> {
        self.runtime.upgrade().ok_or(RootError::OwnerGone)
    }

    // memory—v1: An exhausted serving root cannot provide positive evidence.
    // Keep candidate metadata readable for diagnosis until an adoption attempt.
    fn snapshot(&self) -> Result<Arc<RootSnapshot>, RootError> {
        let runtime = self.runtime()?;
        let snapshot = runtime.current.load_full();
        match snapshot.metadata.status {
            RootStatus::Serving if snapshot.metadata.version == u64::MAX => {
                Err(RootError::Unavailable(RootStatus::Invalid))
            }
            RootStatus::Candidate | RootStatus::Serving => Ok(snapshot),
            status => Err(RootError::Unavailable(status)),
        }
    }

    /// memory—v1: Validate a production admission against this exact live root.
    ///
    /// The capability is deliberately opaque to callers. Validation therefore stays
    /// root-owned and compares both private runtime identity and exact snapshot
    /// identity before trusting its metadata or adoption record. A readable
    /// `Serving` status by itself is never sufficient.
    pub fn validate_production_admission(
        &self,
        admission: &ProductionAdmission,
    ) -> Result<RootMetadata, RootError> {
        let admission_runtime = admission
            .runtime
            .upgrade()
            .ok_or(RootError::ProductionAdmissionUnavailable)?;
        let current_runtime = self.runtime()?;
        if !Arc::ptr_eq(&admission_runtime, &current_runtime) {
            return Err(RootError::ProductionAdmissionMismatch);
        }
        let current = current_runtime.current.load_full();
        // The admission survives legitimate commits: every snapshot on this
        // runtime is derived from the admitted one by ordered CAS, and the
        // version advances monotonically. The admitted snapshot itself is a
        // weak reference and may be freed once no reader holds it; the
        // metadata carried by the admission remains the chain anchor. A
        // non-Serving current state or a version below the admitted one
        // breaks the chain and fails the check.
        if current.metadata.status != RootStatus::Serving {
            return Err(RootError::ProductionAdmissionUnavailable);
        }
        if current.metadata.version < admission.metadata.version {
            return Err(RootError::ProductionAdmissionMismatch);
        }
        let record = current
            .adoption
            .as_deref()
            .ok_or(RootError::ProductionAdmissionUnavailable)?;
        if record.grade != AdoptionGrade::Production || !record.unverified.is_empty() {
            return Err(RootError::ProductionAdmissionUnavailable);
        }
        Ok(current.metadata)
    }

    /// memory—v1: Load metadata from the current immutable root snapshot.
    pub fn metadata(&self) -> Result<RootMetadata, RootError> {
        Ok(self.snapshot()?.metadata)
    }

    /// memory—v1: Return the record of how this root first became serving.
    ///
    /// `Ok(None)` for a candidate root and for a serving root published without a
    /// record. Later snapshots may retain this adoption history; it is not
    /// evidence of the current snapshot's freshness or authorization.
    pub fn adoption_record(&self) -> Result<Option<Arc<AdoptionRecord>>, RootError> {
        let snapshot = self.snapshot()?;
        Ok(match snapshot.metadata.status {
            RootStatus::Serving => snapshot.adoption.clone(),
            _ => None,
        })
    }

    /// memory—v1: Capture one immutable read phase for a request.
    ///
    /// Create this once at the request's first root read and borrow it across
    /// participating modules. The identifier is diagnostic only.
    pub fn begin_request(&self, request_id: Uuid) -> Result<RequestRootReader, RootError> {
        let runtime = self.runtime()?;
        let snapshot = runtime.current.load_full();
        match snapshot.metadata.status {
            RootStatus::Serving if snapshot.metadata.version == u64::MAX => {
                Err(RootError::Unavailable(RootStatus::Invalid))
            }
            RootStatus::Candidate | RootStatus::Serving => Ok(RequestRootReader {
                request_id,
                observation: RootObservation {
                    owner: Arc::downgrade(&runtime),
                    metadata: snapshot.metadata,
                },
                snapshot,
            }),
            status => Err(RootError::Unavailable(status)),
        }
    }

    // memory—v1: Check the owner-bound authority without capturing a request
    // snapshot. This may be called while a session record guard is held.
    pub(crate) fn has_session_authority(
        &self,
        authority_id: &Arc<crate::memory_v1_session::SessionAuthorityToken>,
    ) -> Result<bool, RootError> {
        Ok(self
            .runtime()?
            .session_authority
            .get()
            .is_some_and(|bound| Arc::ptr_eq(bound, authority_id)))
    }

    /// memory—v1: Read one pre-indexed card relationship from one root snapshot.
    ///
    /// This single-read compatibility entry does not provide request-wide
    /// consistency. Request paths should instead share a `RequestRootReader`.
    pub fn read_card<T>(
        &self,
        card_id: BinaryId,
        f: impl for<'a> FnOnce(RuntimeCardContext<'a>) -> T,
    ) -> Result<RootRead<T>, RootError> {
        let reader = self.begin_request(Uuid::nil())?;
        let value = reader.read_card(card_id, f)?;
        Ok(RootRead {
            value,
            observation: reader.observation,
        })
    }

    /// memory—v1: Read direct reverse relationships from one root snapshot.
    pub fn read_impact(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<RootRead<RuleSetImpactCandidate>, RootError> {
        let reader = self.begin_request(Uuid::nil())?;
        let value = reader.read_impact(rule_set_id)?;
        Ok(RootRead {
            value,
            observation: reader.observation,
        })
    }

    /// memory—v1: Recheck the same root instance and snapshot metadata.
    pub fn is_current(&self, observation: &RootObservation) -> Result<bool, RootError> {
        if !Weak::ptr_eq(&self.runtime, &observation.owner) {
            return Err(RootError::ForeignOwner);
        }
        let runtime = self.runtime()?;
        let current = runtime.current.load_full();
        Ok(current.metadata == observation.metadata)
    }
}

impl RequestRootContext {
    /// memory—v1: Prepare a request context without reading or retaining a snapshot.
    pub fn new(handle: RootHandle, request_id: Uuid) -> Self {
        Self {
            handle,
            request_id,
            reader: None,
            failure: None,
        }
    }

    // memory—v1: Check authority identity without creating a request read phase.
    pub(crate) fn has_session_authority(
        &self,
        authority_id: &Arc<crate::memory_v1_session::SessionAuthorityToken>,
    ) -> Result<bool, RootError> {
        self.handle.has_session_authority(authority_id)
    }

    /// memory—v1: Lazily capture one reader and borrow it for this request.
    ///
    /// Repeated calls reuse the original snapshot. If its owner is no longer
    /// readable, the context releases that snapshot and permanently fails with
    /// the observed error. This context never refreshes a captured phase.
    pub fn reader(&mut self) -> Result<&RequestRootReader, RootError> {
        if let Some(failure) = self.failure {
            return Err(failure.into());
        }
        if self.reader.is_none() {
            self.reader = Some(Arc::new(self.handle.begin_request(self.request_id)?));
        }
        let reader = self.reader.as_ref().expect("reader was just initialized");
        if let Err(failure) = reader.ensure_readable() {
            self.reader = None;
            self.failure = Some(failure);
            return Err(failure.into());
        }
        Ok(self.reader.as_deref().expect("reader remains initialized"))
    }

    // memory—v1: Give the request-scoped adapter a temporary reader lease.
    pub(crate) fn reader_lease(&mut self) -> Result<Arc<RequestRootReader>, RootError> {
        self.reader()?;
        Ok(Arc::clone(
            self.reader.as_ref().expect("reader remains initialized"),
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernanceTargetFacts {
    /// The bound user card. Zero for a rule-set-only target.
    pub user_card_id: BinaryId,
    /// The bound rule set. Zero for a user-card-only target.
    pub rule_set_id: BinaryId,
    /// The card owner's user id. Zero for a rule-set-only target.
    pub owner_user_id: BinaryId,
    /// The trusted tenant containing the target.
    pub tenant_id: BinaryId,
}

impl RequestRootReader {
    // memory—v1: Reject reads after the owner stops or the current root is invalid.
    fn ensure_readable(&self) -> Result<Arc<RootRuntime>, RequestRootFailure> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RequestRootFailure::OwnerGone)?;
        let current = runtime.current.load_full();
        if current.metadata.status == RootStatus::Serving && current.metadata.version == u64::MAX {
            return Err(RequestRootFailure::Unavailable(RootStatus::Invalid));
        }
        match current.metadata.status {
            RootStatus::Candidate | RootStatus::Serving => Ok(runtime),
            status => Err(RequestRootFailure::Unavailable(status)),
        }
    }

    /// memory—v1: Return the correlation ID supplied by the request coordinator.
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    /// memory—v1: Return metadata captured with this read phase.
    pub fn metadata(&self) -> RootMetadata {
        self.snapshot.metadata
    }

    /// memory—v1: Report whether this read phase can use confirmation rows for
    /// positive authorization. An acknowledged experimental limit is not proof.
    ///
    /// This reports adoption state, not independent confirmation evidence. The
    /// isolated-test grade is usable only with the explicit test-support feature;
    /// it is a fixture assumption and not a security boundary. Production still
    /// requires its complete verifier and controlled mutation coverage.
    pub fn confirmation_authority_available_for_evaluation(&self) -> bool {
        if self.snapshot.metadata.status != RootStatus::Serving {
            return false;
        }
        match self.snapshot.adoption.as_deref() {
            Some(record) if record.grade == AdoptionGrade::Production => {
                record.unverified.is_empty()
            }
            #[cfg(feature = "test-support")]
            Some(record) if record.grade == AdoptionGrade::IsolatedTest => true,
            _ => false,
        }
    }

    /// memory—v1: Recheck owner and metadata without rereading the object graph.
    ///
    /// A true result only means the metadata is unchanged; candidate status,
    /// completeness, trusted time and authorization still require separate checks.
    pub fn is_current(&self) -> Result<bool, RootError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        Ok(runtime.current.load().metadata == self.observation.metadata)
    }

    // memory—v1: An unbound or foreign session cannot supply authenticated
    // request facts, even when the eventual outcome would be a denial.
    pub(crate) fn has_session_authority(
        &self,
        authority_id: &Arc<crate::memory_v1_session::SessionAuthorityToken>,
    ) -> bool {
        self.observation.owner.upgrade().is_some_and(|runtime| {
            runtime
                .session_authority
                .get()
                .is_some_and(|bound| Arc::ptr_eq(bound, authority_id))
        })
    }

    /// memory—v1: Recheck the serving card while the root writer is excluded.
    ///
    /// The caller must already hold the session authority write lock. The
    /// callback must not block or acquire another lock. This protects session
    /// issuance against a concurrent root mutation; it is not an authorization
    /// decision or a card-disable coordinator.
    pub(crate) fn try_with_current_login_card<T>(
        &self,
        identity: astral_types::memory_v1::CandidateIdentity,
        authority_id: &Arc<crate::memory_v1_session::SessionAuthorityToken>,
        f: impl FnOnce() -> T,
    ) -> Result<Option<T>, RootError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        let Ok(guard) = runtime.mutation_lock.try_read() else {
            return Ok(None);
        };
        let current = runtime.current.load_full();
        if current.metadata.status == RootStatus::Serving && current.metadata.version == u64::MAX {
            drop(guard);
            RootOwner::try_publish_exhausted_snapshot(&runtime, &current);
            return Ok(None);
        }
        let card_id = identity.user_card_id.into_bytes();
        if !runtime
            .session_authority
            .get()
            .is_some_and(|bound| Arc::ptr_eq(bound, authority_id))
            || self.snapshot.metadata.status != RootStatus::Serving
            || current.metadata.status != RootStatus::Serving
            || self.snapshot.metadata.version == u64::MAX
            || current.metadata.version == u64::MAX
            || runtime.tenant_tree_version.load(Ordering::Relaxed) == u64::MAX
            || self
                .snapshot
                .objects
                .card_authorization_dependency_exhausted(card_id)
                .unwrap_or(true)
            || current
                .objects
                .card_authorization_dependency_exhausted(card_id)
                .unwrap_or(true)
            || current.metadata.instance_id != self.snapshot.metadata.instance_id
            || current.metadata.version < self.snapshot.metadata.version
        {
            return Ok(None);
        }
        let Some(generation) = self.snapshot.objects.card_dependency_generation(card_id) else {
            return Ok(None);
        };
        if generation == u64::MAX
            || current.objects.card_dependency_generation(card_id) != Some(generation)
        {
            return Ok(None);
        }
        let Some(card) = current.objects.user_card(card_id) else {
            return Ok(None);
        };
        let user_id = identity.user_id.into_bytes();
        let tenant_id = identity.tenant_id.into_bytes();
        if card.status != crate::memory_v1_db_rows::UserCardStatus::Active
            || card.user_id != user_id
            || card.tenant_id != tenant_id
            || current.objects.user(user_id).is_none()
            || current.objects.tenant(tenant_id).is_none()
            || current
                .objects
                .identity_for_user(user_id)
                .is_none_or(|row| row.identity_card_id != identity.identity_card_id.into_bytes())
        {
            return Ok(None);
        }
        Ok(Some(f()))
    }

    /// memory—v1 §4.9: Copy the registry and its version under one read guard.
    pub fn registry_snapshot(
        &self,
    ) -> Result<crate::memory_v1_registry::RegistrySnapshot, RegistryError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RegistryError::NotInstalled)?;
        runtime.registry.snapshot()
    }

    /// memory—v1 §4.9: verify the (resource, action) pair against the registry.
    ///
    /// An unregistered, inactive or unknown-action pair is a structural refusal;
    /// an unavailable registry cannot establish membership.
    pub fn registry_check(&self, resource: &str, action: &str) -> Result<(), RegistryError> {
        self.registry_check_with_version(resource, action)
            .map(|_| ())
    }

    /// memory—v1 §4.7: Pair a successful registry check with its exact version.
    pub fn registry_check_with_version(
        &self,
        resource: &str,
        action: &str,
    ) -> Result<u64, RegistryError> {
        // A gone owner makes the registry unavailable; it cannot prove membership.
        let runtime = match self.observation.owner.upgrade() {
            Some(runtime) => runtime,
            None => return Err(RegistryError::NotInstalled),
        };
        runtime.registry.validate_with_version(resource, action)
    }

    /// memory—v1 §4.9: Check all entries in one version against one registry
    /// observation and return its version for the final authorization recheck.
    pub fn registry_check_rules_with_version(
        &self,
        content: &crate::memory_v1_rules::MemoryV1RuleSetContent,
    ) -> Result<u64, RegistryError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RegistryError::NotInstalled)?;
        runtime.registry.validate_rules_with_version(content)
    }

    /// memory—v1 §4.6: Read a modification fence without waiting. An unavailable
    /// table is an error, never proof that the rule set is unfenced.
    pub fn is_fenced(&self, rule_set_id: BinaryId) -> Result<bool, RootError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        runtime
            .fences
            .try_is_active(rule_set_id)
            .map_err(|error| match error {
                FenceReadError::Poisoned => RootError::Runtime(RuntimeError::Poisoned),
            })
    }

    /// memory—v1 §4.10: tenants strictly below the given tenant in this phase's
    /// snapshot; supports the `self+descendants` scope resolution.
    pub fn tenant_descendants(&self, tenant_id: BinaryId) -> Result<Vec<BinaryId>, RootError> {
        self.snapshot
            .objects
            .tenant_descendants(tenant_id)
            .map_err(RootError::Candidate)
    }

    /// memory—v1 §4.7: capture the non-object dependency versions of this phase.
    pub fn dependency_versions(&self) -> Result<(u64, u64), RootError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        let tenant_tree_version = runtime.tenant_tree_version.load(Ordering::Relaxed);
        if tenant_tree_version == u64::MAX {
            return Err(RootError::Unavailable(RootStatus::Invalid));
        }
        Ok((tenant_tree_version, runtime.registry.version()))
    }

    /// memory—v1: Measure isolated validation and full digest reconstruction on
    /// this immutable request snapshot. These timings are diagnostic only.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn publication_validation_timings_for_test(&self) -> Result<(u128, u128), RootError> {
        let _runtime = self.ensure_readable()?;
        let started = std::time::Instant::now();
        self.snapshot
            .objects
            .validate_binding_indexes()
            .and_then(|()| self.snapshot.objects.validate_confirmation_indexes())
            .map_err(RootError::Candidate)?;
        let validation_ns = started.elapsed().as_nanos();
        let started = std::time::Instant::now();
        let (rows, selections) = self.snapshot.objects.digest_inputs();
        let digest = digest_candidate(&rows, &selections).map_err(RootError::Runtime)?;
        let digest_ns = started.elapsed().as_nanos();
        if digest != self.snapshot.metadata.digest {
            return Err(RootError::InconsistentCandidate);
        }
        Ok((validation_ns, digest_ns))
    }

    /// memory—v1: Probe whether the three root-side final-check locks are free.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn final_check_locks_available_for_test(&self) -> Result<[bool; 3], RootError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        let root_available = runtime.mutation_lock.try_write().is_ok();
        Ok([
            root_available,
            runtime.registry.write_available_for_test(),
            runtime.fences.table_available_for_test(),
        ])
    }

    /// memory—v1: Exercise final-check contention in isolated test builds only.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn with_final_check_lock_for_test<T>(
        &self,
        lock: &str,
        f: impl FnOnce() -> T,
    ) -> Result<T, RootError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        match lock {
            "root" => {
                let _guard = runtime
                    .mutation_lock
                    .write()
                    .expect("test root lock poisoned");
                Ok(f())
            }
            "registry" => Ok(runtime.registry.with_write_lock_for_test(f)),
            "fence" => Ok(runtime.fences.with_table_lock_for_test(f)),
            _ => Err(RootError::InconsistentCandidate),
        }
    }

    /// memory—v1 §4.7: Recheck dependencies without waiting for writers.
    /// This compatibility observation is not a mutation authorization.
    pub fn recheck_dependencies(&self, record: &DependencyRecord) -> Result<bool, RootError> {
        self.try_with_rechecked_dependencies(record, || ())
            .map(|checked| checked.is_some())
    }

    /// memory—v1: Run a synchronous final-check callback while the root writer
    /// and registry version are stable. Object-specific fence observations bracket
    /// the callback and reject relevant transient windows. The caller must already
    /// hold its live-session guard and must not acquire blocking locks or enter a
    /// request scope from the callback. This does not authorize a later mutation.
    pub(crate) fn try_with_rechecked_dependencies<T>(
        &self,
        record: &DependencyRecord,
        f: impl FnOnce() -> T,
    ) -> Result<Option<T>, RootError> {
        self.try_with_rechecked_dependencies_and_target(record, None, None, f)
    }

    // memory—v1: Exact-root governance checks share the same lock boundary as
    // ordinary dependencies; target fences are independent of actor bindings.
    pub(crate) fn try_with_rechecked_dependencies_and_target<T>(
        &self,
        record: &DependencyRecord,
        exact_target: Option<(RootMetadata, &[BinaryId])>,
        authority_id: Option<&Arc<crate::memory_v1_session::SessionAuthorityToken>>,
        f: impl FnOnce() -> T,
    ) -> Result<Option<T>, RootError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        let Ok(guard) = runtime.mutation_lock.try_read() else {
            return Ok(None);
        };
        let current = runtime.current.load_full();
        if current.metadata.status == RootStatus::Serving && current.metadata.version == u64::MAX {
            drop(guard);
            RootOwner::try_publish_exhausted_snapshot(&runtime, &current);
            return Ok(None);
        }
        if current.metadata.instance_id != record.instance_id
            || self.snapshot.metadata.instance_id != record.instance_id
            || self.snapshot.metadata.status != RootStatus::Serving
            || current.metadata.status != RootStatus::Serving
            || !current.objects.is_user_card_active(record.card_id)
            || self.snapshot.objects.user_card(record.card_id).is_none()
        {
            return Ok(None);
        }
        let targets = exact_target.map_or(&[][..], |(_, targets)| targets);
        // The public dependency record is not a proof of complete coverage. Read
        // the actor card once and include every applicable binding independently.
        if record.bindings.len() > MAX_FENCE_CHECK_OBJECTS
            || targets.len() > MAX_FENCE_CHECK_OBJECTS
        {
            return Ok(None);
        }
        let actor_card = self
            .snapshot
            .objects
            .unremoved_card_candidate(record.card_id)
            .map_err(RootError::Candidate)?
            .0;
        let mut fence_dependencies = Vec::new();
        fence_dependencies.extend(
            actor_card
                .bindings
                .iter()
                .filter(|binding| binding_is_active(binding, Some(actor_card.card)))
                .map(|binding| binding.rule_set_id),
        );
        fence_dependencies.extend(
            record
                .bindings
                .iter()
                .map(|binding| binding.rule_set_id)
                .chain(targets.iter().copied()),
        );
        fence_dependencies.sort_unstable();
        fence_dependencies.dedup();
        if fence_dependencies.len() > MAX_FENCE_CHECK_OBJECTS {
            return Ok(None);
        }
        let result = runtime
            .registry
            .try_with_active_version(record.registry_version, || {
                runtime
                    .fences
                    .try_with_unfenced(&fence_dependencies, |unfenced| {
                        let current = runtime.current.load_full();
                        if authority_id.is_some_and(|authority_id| {
                            !runtime
                                .session_authority
                                .get()
                                .is_some_and(|bound| Arc::ptr_eq(bound, authority_id))
                        }) || current.metadata.instance_id != record.instance_id
                            || self.snapshot.metadata.instance_id != record.instance_id
                            || self.snapshot.metadata.status != RootStatus::Serving
                            || current.metadata.status != RootStatus::Serving
                            || self.snapshot.metadata.version == u64::MAX
                            || current.metadata.version == u64::MAX
                            || current.metadata.version < self.snapshot.metadata.version
                            || record.tenant_tree_version == u64::MAX
                            || record.registry_version == u64::MAX
                            || exact_target.is_some_and(|(expected, targets)| {
                                expected != self.snapshot.metadata
                                    || expected != current.metadata
                                    || targets.iter().any(|target| !unfenced(*target))
                            })
                            || runtime.tenant_tree_version.load(Ordering::Relaxed)
                                != record.tenant_tree_version
                            || !current.objects.is_user_card_active(record.card_id)
                        {
                            return Ok(None);
                        }
                        let Some(card_generation) = self
                            .snapshot
                            .objects
                            .card_dependency_generation(record.card_id)
                        else {
                            return Ok(None);
                        };
                        if self
                            .snapshot
                            .objects
                            .card_dependency_exhausted(record.card_id)
                            || current.objects.card_dependency_generation(record.card_id)
                                != Some(card_generation)
                            || current.objects.card_dependency_exhausted(record.card_id)
                            || self
                                .snapshot
                                .objects
                                .card_authorization_dependency_exhausted(record.card_id)
                                .unwrap_or(true)
                            || current
                                .objects
                                .card_authorization_dependency_exhausted(record.card_id)
                                .unwrap_or(true)
                        {
                            return Ok(None);
                        }
                        for binding in &actor_card.bindings {
                            if !binding_is_active(binding, Some(actor_card.card)) {
                                continue;
                            }
                            if !self
                                .snapshot
                                .objects
                                .rule_set(binding.rule_set_id)
                                .is_some_and(|row| {
                                    row.status == crate::memory_v1_db_rows::RuleSetStatus::Active
                                })
                                || !current.objects.rule_set(binding.rule_set_id).is_some_and(
                                    |row| {
                                        row.status
                                            == crate::memory_v1_db_rows::RuleSetStatus::Active
                                    },
                                )
                            {
                                return Ok(None);
                            }
                            let Some(generation) = self
                                .snapshot
                                .objects
                                .rule_set_dependency_generation(binding.rule_set_id)
                            else {
                                return Ok(None);
                            };
                            if self
                                .snapshot
                                .objects
                                .rule_set_dependency_exhausted(binding.rule_set_id)
                                || current
                                    .objects
                                    .rule_set_dependency_generation(binding.rule_set_id)
                                    != Some(generation)
                                || current
                                    .objects
                                    .rule_set_dependency_exhausted(binding.rule_set_id)
                                || !unfenced(binding.rule_set_id)
                            {
                                return Ok(None);
                            }
                            // Compare the selected version's stored hash even when
                            // the caller's public dependency record omits this binding.
                            // The rule body was validated during the read phase; this
                            // check detects a different selected version or hash, not
                            // an unauthorized rewrite that preserves the old hash.
                            let Some(observed) = self
                                .snapshot
                                .objects
                                .selected_version(binding.rule_set_id)
                                .map_err(RootError::Candidate)?
                            else {
                                return Ok(None);
                            };
                            let Some(selected) = current
                                .objects
                                .selected_version(binding.rule_set_id)
                                .map_err(RootError::Candidate)?
                            else {
                                return Ok(None);
                            };
                            if observed.version_bytes != selected.version_bytes
                                || observed.hash_bytes.is_empty()
                                || observed.hash_bytes != selected.hash_bytes
                            {
                                return Ok(None);
                            }
                        }
                        // Governance can touch a rule set outside the actor's card.
                        // A new rule set is absent in both exact-root observations.
                        if let Some((_, targets)) = exact_target {
                            for target in targets {
                                match (
                                    self.snapshot.objects.rule_set(*target),
                                    current.objects.rule_set(*target),
                                ) {
                                    (None, None) => {}
                                    (Some(_), Some(_)) => {
                                        let Some(generation) = self
                                            .snapshot
                                            .objects
                                            .rule_set_dependency_generation(*target)
                                        else {
                                            return Ok(None);
                                        };
                                        if generation == u64::MAX
                                            || current
                                                .objects
                                                .rule_set_dependency_generation(*target)
                                                != Some(generation)
                                        {
                                            return Ok(None);
                                        }
                                        let Some(observed) = self
                                            .snapshot
                                            .objects
                                            .selected_version(*target)
                                            .map_err(RootError::Candidate)?
                                        else {
                                            return Ok(None);
                                        };
                                        let Some(selected) = current
                                            .objects
                                            .selected_version(*target)
                                            .map_err(RootError::Candidate)?
                                        else {
                                            return Ok(None);
                                        };
                                        if observed.version_bytes != selected.version_bytes
                                            || observed.hash_bytes.is_empty()
                                            || observed.hash_bytes != selected.hash_bytes
                                        {
                                            return Ok(None);
                                        }
                                    }
                                    _ => return Ok(None),
                                }
                            }
                        }
                        for dependency in &record.bindings {
                            let Some(binding) = current
                                .objects
                                .binding(dependency.binding_id)
                                .map_err(RootError::Candidate)?
                            else {
                                return Ok(None);
                            };
                            if binding.user_card_id != record.card_id
                                || binding.rule_set_id != dependency.rule_set_id
                                || !binding_is_active(
                                    binding,
                                    current.objects.user_card(record.card_id),
                                )
                            {
                                return Ok(None);
                            }
                            let Some(selected) = current
                                .objects
                                .selected_version(dependency.rule_set_id)
                                .map_err(RootError::Candidate)?
                            else {
                                return Ok(None);
                            };
                            if selected.version_bytes != dependency.version_bytes {
                                return Ok(None);
                            }
                        }
                        Ok(Some(f()))
                    })
            })
            .flatten()
            .unwrap_or(Ok(None));
        drop(guard);
        result
    }

    /// memory—v1: Read a card and its relationships from this request's phase.
    ///
    /// Borrowed rows cannot escape the callback. The immutable snapshot is shared
    /// for all calls; no root lock is held during traversal.
    pub fn read_card<T>(
        &self,
        card_id: BinaryId,
        f: impl for<'a> FnOnce(RuntimeCardContext<'a>) -> T,
    ) -> Result<T, RootError> {
        let _runtime = self.ensure_readable()?;
        let card = self
            .snapshot
            .objects
            .card_candidate(card_id)
            .map_err(RootError::Candidate)?;
        self.with_card_context(card, f)
    }

    /// memory—v1: Read unremoved relationships for authorization, and report
    /// whether this card has any binding history, including tombstones.
    /// The history bit and the relationships come from the same verified snapshot.
    pub fn read_card_for_authorization<T>(
        &self,
        card_id: BinaryId,
        f: impl for<'a> FnOnce(RuntimeCardContext<'a>, bool) -> T,
    ) -> Result<T, RootError> {
        let _runtime = self.ensure_readable()?;
        let (card, has_binding_history) = self
            .snapshot
            .objects
            .unremoved_card_candidate(card_id)
            .map_err(RootError::Candidate)?;
        self.with_card_context(card, |context| f(context, has_binding_history))
    }

    /// memory—v1: Read the same card facts and confirmation classifications
    /// without materializing historical rows. The original aggregate reference
    /// budget and all relationship checks still apply.
    pub fn read_card_for_evaluation<T>(
        &self,
        card_id: BinaryId,
        f: impl for<'a> FnOnce(AuthorizationCardContext<'a>, bool) -> T,
    ) -> Result<T, RootError> {
        let _runtime = self.ensure_readable()?;
        let objects = &self.snapshot.objects;
        let (card, has_binding_history) = objects
            .unremoved_card_candidate(card_id)
            .map_err(RootError::Candidate)?;
        let user = objects
            .user(card.card.user_id)
            .ok_or(RootError::InconsistentCandidate)?;
        let identity = objects
            .identity_for_user(card.card.user_id)
            .ok_or(RootError::InconsistentCandidate)?;
        let tenant = objects
            .tenant(card.card.tenant_id)
            .ok_or(RootError::InconsistentCandidate)?;
        objects
            .check_card_confirmation_budget(&card.bindings)
            .map_err(RootError::Candidate)?;
        let mut bindings = Vec::with_capacity(card.bindings.len());
        for binding in card.bindings {
            let rule_set = objects
                .rule_set(binding.rule_set_id)
                .ok_or(RootError::InconsistentCandidate)?;
            let selected = objects
                .selected_version(binding.rule_set_id)
                .map_err(RootError::Candidate)?;
            let confirmation_state = objects
                .binding_confirmation_state(binding)
                .map_err(RootError::Candidate)?;
            let change_confirmation_state = match selected {
                Some(version) => objects
                    .change_confirmation_state(binding.rule_set_id, &version.version_bytes)
                    .map_err(RootError::Candidate)?,
                None => crate::memory_v1_rules::ChangeConfirmationState::Invalid,
            };
            bindings.push(AuthorizationBindingContext {
                binding,
                rule_set,
                selected,
                confirmation_state,
                change_confirmation_state,
            });
        }
        Ok(f(
            AuthorizationCardContext {
                user,
                identity,
                card: card.card,
                tenant,
                bindings,
            },
            has_binding_history,
        ))
    }

    // memory—v1: Assemble the shared context without changing either index's semantics.
    fn with_card_context<T>(
        &self,
        card: CardCandidate<'_>,
        f: impl for<'a> FnOnce(RuntimeCardContext<'a>) -> T,
    ) -> Result<T, RootError> {
        let snapshot = &self.snapshot;
        let user = snapshot
            .objects
            .user(card.card.user_id)
            .ok_or(RootError::InconsistentCandidate)?;
        let identity = snapshot
            .objects
            .identity_for_user(card.card.user_id)
            .ok_or(RootError::InconsistentCandidate)?;
        let tenant = snapshot
            .objects
            .tenant(card.card.tenant_id)
            .ok_or(RootError::InconsistentCandidate)?;
        snapshot
            .objects
            .check_card_confirmation_budget(&card.bindings)
            .map_err(RootError::Candidate)?;
        let mut bindings = Vec::with_capacity(card.bindings.len());
        for binding in card.bindings {
            bindings.push(crate::memory_v1_hamt_runtime::RuntimeBindingContext {
                binding,
                rule_set: snapshot
                    .objects
                    .rule_set(binding.rule_set_id)
                    .ok_or(RootError::InconsistentCandidate)?,
                selected: snapshot
                    .objects
                    .selected_version(binding.rule_set_id)
                    .map_err(RootError::Candidate)?,
                confirmations: snapshot
                    .objects
                    .binding_confirmations(binding.binding_id)
                    .map_err(RootError::Candidate)?,
                change_confirmations: snapshot
                    .objects
                    .change_confirmations(binding.rule_set_id)
                    .map_err(RootError::Candidate)?,
            });
        }
        Ok(f(RuntimeCardContext {
            user,
            identity,
            card: card.card,
            tenant,
            bindings,
        }))
    }

    /// memory—v1: Read reverse relationships from this request's same phase.
    pub fn read_impact(&self, rule_set_id: BinaryId) -> Result<RuleSetImpactCandidate, RootError> {
        let _runtime = self.ensure_readable()?;
        self.snapshot
            .objects
            .rule_set_impact(rule_set_id)
            .map_err(RootError::Candidate)
    }

    /// memory—v1 §4.11 N-6: Resolve a new binding target from root facts.
    pub fn binding_create_target(
        &self,
        user_card_id: BinaryId,
        rule_set_id: BinaryId,
    ) -> Result<GovernanceTargetFacts, RootError> {
        let _runtime = self.ensure_readable()?;
        self.active_rule_set_target(rule_set_id)?;
        self.snapshot
            .objects
            .selected_version(rule_set_id)
            .map_err(RootError::Candidate)?
            .ok_or(RootError::InconsistentCandidate)?;
        let facts = self.target_for_card(user_card_id, rule_set_id)?;
        let owner_tenant = self
            .snapshot
            .objects
            .rule_set(rule_set_id)
            .ok_or(RootError::InconsistentCandidate)?
            .owner_tenant_id;
        if facts.tenant_id != owner_tenant {
            return Err(RootError::InconsistentCandidate);
        }
        Ok(facts)
    }

    /// memory—v1 §4.15: Classify a proposed OVERLAY using root binding facts.
    pub fn overlay_only_target(&self, user_card_id: BinaryId) -> Result<bool, RootError> {
        let _runtime = self.ensure_readable()?;
        let card = self
            .snapshot
            .objects
            .unremoved_card_candidate(user_card_id)
            .map_err(RootError::Candidate)?
            .0;
        Ok(!card
            .bindings
            .iter()
            .any(|binding| binding.binding_layer == crate::memory_v1_db_rows::BindingLayer::Base))
    }

    /// memory—v1 §4.11 N-6: Resolve an existing confirmation through its binding.
    pub fn confirmation_target(
        &self,
        confirmation_id: BinaryId,
    ) -> Result<GovernanceTargetFacts, RootError> {
        let _runtime = self.ensure_readable()?;
        let binding = self
            .snapshot
            .objects
            .binding_for_confirmation(confirmation_id)
            .map_err(RootError::Candidate)?;
        self.target_for_card(binding.user_card_id, binding.rule_set_id)
    }

    /// memory—v1 §4.11 N-6: Resolve a proposed card against one captured root.
    /// An existing card establishes a historical user/tenant relationship; IDs
    /// supplied by a caller alone are never treated as ownership or authorization.
    /// This relationship does not prove current membership or user availability.
    /// The caller must bind these facts and this reader's root version to its
    /// admission and recheck them at a future restricted commit.
    pub fn user_card_create_target(
        &self,
        user_card_id: BinaryId,
        user_id: BinaryId,
        tenant_id: BinaryId,
    ) -> Result<GovernanceTargetFacts, RootError> {
        let _runtime = self.ensure_readable()?;
        self.snapshot
            .objects
            .validate_user_card_create_target(user_card_id, user_id, tenant_id)
            .map_err(RootError::Candidate)?;
        Ok(GovernanceTargetFacts {
            user_card_id,
            rule_set_id: [0; 16],
            owner_user_id: user_id,
            tenant_id,
        })
    }

    /// memory—v1 §4.11 N-6: Resolve a user-card target from root facts.
    pub fn user_card_target(
        &self,
        user_card_id: BinaryId,
    ) -> Result<GovernanceTargetFacts, RootError> {
        let _runtime = self.ensure_readable()?;
        self.target_for_card(user_card_id, [0; 16])
    }

    /// memory—v1 §4.11 N-6: Resolve a new rule-set target from the trusted
    /// owner tenant supplied by the candidate root. The rule-set ID must still
    /// be unused; the proposed ID itself is not treated as an existing fact.
    pub fn rule_set_create_target(
        &self,
        rule_set_id: BinaryId,
        owner_tenant_id: BinaryId,
    ) -> Result<GovernanceTargetFacts, RootError> {
        let _runtime = self.ensure_readable()?;
        if self.snapshot.objects.rule_set(rule_set_id).is_some()
            || self.snapshot.objects.tenant(owner_tenant_id).is_none()
        {
            return Err(RootError::InconsistentCandidate);
        }
        Ok(GovernanceTargetFacts {
            user_card_id: [0; 16],
            rule_set_id,
            owner_user_id: [0; 16],
            tenant_id: owner_tenant_id,
        })
    }

    /// memory—v1 §4.11 N-6: Resolve an existing rule-set target from root facts.
    pub fn rule_set_target(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<GovernanceTargetFacts, RootError> {
        let _runtime = self.ensure_readable()?;
        let rule_set = self
            .snapshot
            .objects
            .rule_set(rule_set_id)
            .ok_or(RootError::InconsistentCandidate)?;
        self.snapshot
            .objects
            .tenant(rule_set.owner_tenant_id)
            .ok_or(RootError::InconsistentCandidate)?;
        Ok(GovernanceTargetFacts {
            user_card_id: [0; 16],
            rule_set_id,
            owner_user_id: [0; 16],
            tenant_id: rule_set.owner_tenant_id,
        })
    }

    /// memory—v1 §4.12: Resolve a rule-set mutation target only while its retained
    /// row is active. This observation is not an admission or commit; callers
    /// must still recheck the exact root and relevant fences.
    pub fn active_rule_set_target(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<GovernanceTargetFacts, RootError> {
        let facts = self.rule_set_target(rule_set_id)?;
        if !self
            .snapshot
            .objects
            .rule_set(rule_set_id)
            .is_some_and(|row| row.status == crate::memory_v1_db_rows::RuleSetStatus::Active)
        {
            return Err(RootError::InconsistentCandidate);
        }
        Ok(facts)
    }

    /// memory—v1 §4.12: A retirement target must remain active at this read phase.
    pub fn rule_set_retirement_target(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<GovernanceTargetFacts, RootError> {
        self.active_rule_set_target(rule_set_id)
    }

    /// memory—v1 §4.11 N-6: Return the exact selected version row from root
    /// facts, including the stored digest bytes an audit observation binds.
    pub fn selected_version_row(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<crate::memory_v1_db_rows::RuleSetVersionRow, RootError> {
        let _runtime = self.ensure_readable()?;
        self.snapshot
            .objects
            .selected_version(rule_set_id)
            .map_err(RootError::Candidate)?
            .map(|version| (*version).clone())
            .ok_or(RootError::InconsistentCandidate)
    }

    /// memory—v1 §4.11 N-6: Resolve the selected version from root facts.
    pub fn selected_version_bytes(&self, rule_set_id: BinaryId) -> Result<Vec<u8>, RootError> {
        let _runtime = self.ensure_readable()?;
        self.snapshot
            .objects
            .selected_version(rule_set_id)
            .map_err(RootError::Candidate)?
            .map(|version| version.version_bytes.clone())
            .ok_or(RootError::InconsistentCandidate)
    }

    fn target_for_card(
        &self,
        user_card_id: BinaryId,
        rule_set_id: BinaryId,
    ) -> Result<GovernanceTargetFacts, RootError> {
        let card = self
            .snapshot
            .objects
            .user_card(user_card_id)
            .ok_or(RootError::InconsistentCandidate)?;
        self.snapshot
            .objects
            .user(card.user_id)
            .ok_or(RootError::InconsistentCandidate)?;
        self.snapshot
            .objects
            .tenant(card.tenant_id)
            .ok_or(RootError::InconsistentCandidate)?;
        Ok(GovernanceTargetFacts {
            user_card_id,
            rule_set_id,
            owner_user_id: card.user_id,
            tenant_id: card.tenant_id,
        })
    }

    /// memory—v1 §4.11 N-6: Resolve a binding target's attribution from root facts.
    pub fn binding_target(&self, binding_id: BinaryId) -> Result<GovernanceTargetFacts, RootError> {
        let _runtime = self.ensure_readable()?;
        let binding = self
            .snapshot
            .objects
            .binding(binding_id)
            .map_err(RootError::Candidate)?
            .ok_or(RootError::InconsistentCandidate)?;
        self.target_for_card(binding.user_card_id, binding.rule_set_id)
    }

    /// memory—v1: Observe whether a proposed new binding confirmation can be
    /// constructed from this snapshot. This is a structural observation only;
    /// it does not prove confirmation eligibility or authorize a later mutation.
    pub fn confirmation_target_is_available(
        &self,
        binding_id: BinaryId,
        confirmation_id: BinaryId,
    ) -> Result<bool, RootError> {
        let _runtime = self.ensure_readable()?;
        Ok(self
            .snapshot
            .objects
            .confirmation_target_is_available(binding_id, confirmation_id))
    }

    /// memory—v1: Resolve a rule set's owner tenant from root facts.
    pub fn rule_set_owner(&self, rule_set_id: BinaryId) -> Result<BinaryId, RootError> {
        Ok(self.rule_set_target(rule_set_id)?.tenant_id)
    }

    /// memory—v1 §4.11/§4.12/§4.13: Read the conservative change impact
    /// of a rule set from this request's immutable root phase.
    ///
    /// This is a structural SoD input only. The historical `read_impact` method
    /// remains unchanged and continues to include direct historical rows.
    pub fn read_change_impact(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<RuleSetImpactCandidate, RootError> {
        let _runtime = self.ensure_readable()?;
        self.snapshot
            .objects
            .rule_set_change_impact(rule_set_id)
            .map_err(RootError::Candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::UserCardStatus;
    use crate::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, IdentityCardRow, RuleSetRow,
        RuleSetVersionRow, TenantRow, UserCardRow, UserRow,
    };
    use crate::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};

    // memory—v1: Build an index from the exact rows in a synthetic snapshot.
    fn fixture_digest_index(objects: &HamtCandidate) -> DigestIndex {
        let (rows, selections) = objects.digest_inputs();
        digest_rows(&rows, &selections).unwrap()
    }

    fn id(value: u8) -> BinaryId {
        [value; 16]
    }

    fn rows() -> CandidateRows {
        CandidateRows {
            users: vec![UserRow { user_id: id(1) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            }],
            tenants: vec![TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: id(4),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                rule_set_id: id(5),
                owner_tenant_id: id(3),
                current_version_bytes: Vec::new(),
                status: crate::memory_v1_db_rows::RuleSetStatus::Active,
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(5),
                version_bytes: vec![1],
                content_bytes: vec![1],
                timestamp_bytes: vec![1],
                hash_input_bytes: vec![1],
                hash_bytes: vec![1],
            }],
            bindings: vec![BindingRow {
                binding_id: id(6),
                user_card_id: id(4),
                rule_set_id: id(5),
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            }],
            ..CandidateRows::default()
        }
    }

    fn budget() -> CandidateBudget {
        CandidateBudget {
            max_table_rows: 32,
            max_bindings_per_read: 4,
        }
    }

    // memory—v1: A candidate that passes the structural serving checks: a valid rule
    // body with its hash, one binding confirmation and one explicit selection.
    fn serving_ready() -> (CandidateRows, Vec<CurrentSelection>) {
        use crate::memory_v1_rules::canonical_version_bytes;
        use sha2::{Digest, Sha256};

        let mut candidate = rows();
        let version = &mut candidate.rule_set_versions[0];
        version.content_bytes =
            br#"{"rules":[{"ruleId":"R9","resource":"document","action":"read","effect":"ALLOW"}]}"#.to_vec();
        version.hash_input_bytes = canonical_version_bytes(
            &version.version_bytes,
            &version.content_bytes,
            &version.timestamp_bytes,
        );
        version.hash_bytes = Sha256::digest(&version.hash_input_bytes).to_vec();
        candidate
            .binding_confirmations
            .push(BindingConfirmationRow {
                confirmation_id: id(7),
                binding_id: id(6),
                rule_set_id: id(5),
                version_bytes: vec![1],
                confirmer_user_id: id(1),
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
        candidate.rule_sets[0].current_version_bytes = vec![1];
        candidate.rule_set_change_confirmations.push(
            crate::memory_v1_db_rows::RuleSetChangeConfirmationRow {
                confirmation_id: id(8),
                rule_set_id: id(5),
                version_bytes: vec![1],
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            },
        );
        let selections = vec![CurrentSelection {
            rule_set_id: id(5),
            version_bytes: vec![1],
        }];
        (candidate, selections)
    }

    // memory—v1: Install the declarations used by the serving-ready fixture.
    fn install_fixture_registry(owner: &RootOwner) {
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
    }

    // memory—v1: Build an isolated candidate root containing the selected rule set.
    fn owned_fence_owner() -> RootOwner {
        let (input, selections) = serving_ready();
        RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap()
    }

    // memory—v1: Derive the owned fence declaration from the current root facts.
    fn owned_fence_declaration(owner: &RootOwner) -> FenceDeclaration {
        let metadata = owner.handle().metadata().unwrap();
        FenceDeclaration {
            rule_set_version: vec![1],
            root_version: metadata.version,
            digest: metadata.digest,
        }
    }

    #[test]
    // memory—v1: Root-owned windows require the current declaration and release
    // only their own generation, including during unwinding.
    fn root_owned_fence_checks_premises_and_releases() {
        let owner = owned_fence_owner();
        let declaration = owned_fence_declaration(&owner);
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(reader.is_fenced(id(5)), Ok(false));

        let mut wrong_root = declaration.clone();
        wrong_root.root_version += 1;
        assert!(matches!(
            owner.begin_owned_modification_fence(id(5), &wrong_root),
            Err(FenceControlError::Fence(FenceError::RootMismatch { .. }))
        ));
        let mut wrong_digest = declaration.clone();
        wrong_digest.digest[0] ^= 1;
        assert!(matches!(
            owner.begin_owned_modification_fence(id(5), &wrong_digest),
            Err(FenceControlError::Fence(FenceError::RootMismatch { .. }))
        ));
        let mut wrong_selection = declaration.clone();
        wrong_selection.rule_set_version = vec![2];
        assert!(matches!(
            owner.begin_owned_modification_fence(id(5), &wrong_selection),
            Err(FenceControlError::Fence(
                FenceError::RuleSetVersionMismatch { .. }
            ))
        ));
        assert!(matches!(
            owner.begin_owned_modification_fence(id(99), &declaration),
            Err(FenceControlError::Fence(FenceError::Candidate(
                CandidateError::UnknownId {
                    table: crate::memory_v1_db_rows::Table::RuleSet,
                    id: missing,
                }
            ))) if missing == id(99)
        ));
        assert_eq!(reader.is_fenced(id(5)), Ok(false));

        let guard = owner
            .begin_owned_modification_fence(id(5), &declaration)
            .unwrap();
        assert_eq!(reader.is_fenced(id(5)), Ok(true));
        assert!(matches!(
            owner.begin_owned_modification_fence(id(5), &declaration),
            Err(FenceControlError::Fence(FenceError::AlreadyFenced(_)))
        ));
        assert_eq!(
            owner.abort_modification_fence(id(5)),
            Err(FenceError::AlreadyFenced(id(5)))
        );
        assert_eq!(reader.is_fenced(id(5)), Ok(true));
        drop(guard);
        assert_eq!(reader.is_fenced(id(5)), Ok(false));

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = owner
                .begin_owned_modification_fence(id(5), &declaration)
                .unwrap();
            assert_eq!(reader.is_fenced(id(5)), Ok(true));
            panic!("inject fence owner unwind");
        }));
        assert!(unwind.is_err());
        assert_eq!(reader.is_fenced(id(5)), Ok(false));
        let mut guard = owner
            .begin_owned_modification_fence(id(5), &declaration)
            .unwrap();
        assert_eq!(guard.release(), Ok(()));
        assert_eq!(reader.is_fenced(id(5)), Ok(false));
        assert!(matches!(
            guard.release(),
            Err(FenceControlError::Fence(FenceError::NotFenced(_)))
        ));
    }

    #[test]
    // memory—v1: Root-owned opening reports lock poison without panicking or
    // claiming that the target has no active window.
    fn root_owned_fence_reports_poison() {
        let owner = owned_fence_owner();
        let declaration = owned_fence_declaration(&owner);
        let runtime = Arc::clone(&owner.runtime);
        assert!(std::thread::spawn(move || {
            let _guard = runtime.mutation_lock.write().unwrap();
            panic!("inject root writer poison");
        })
        .join()
        .is_err());
        assert!(matches!(
            owner.begin_owned_modification_fence(id(5), &declaration),
            Err(FenceControlError::Poisoned)
        ));

        let owner = owned_fence_owner();
        let declaration = owned_fence_declaration(&owner);
        let runtime = Arc::clone(&owner.runtime);
        assert!(std::thread::spawn(move || {
            runtime.fences.with_table_lock_for_test(|| {
                panic!("inject fence writer poison");
            });
        })
        .join()
        .is_err());
        assert!(matches!(
            owner.begin_owned_modification_fence(id(5), &declaration),
            Err(FenceControlError::Poisoned)
        ));
    }

    // memory—v1: Cold-load facts that agree with the candidate schema and counts.
    fn cold_facts(counts: crate::memory_v1_db_rows::TableCounts) -> ColdLoadFacts {
        ColdLoadFacts {
            schema_contract_version: crate::memory_v1_adoption::MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
            schema_fingerprint: [7; 32],
            snapshot_counts: counts,
            scanned_counts: counts,
            captured_at_unix_seconds: 1_700_000_000,
        }
    }

    fn test_record() -> AdoptionRecord {
        AdoptionRecord {
            grade: AdoptionGrade::IsolatedTest,
            unverified: Vec::new(),
            schema_fingerprint: None,
            counts: None,
            captured_at_unix_seconds: None,
        }
    }

    #[test]
    // memory—v1: Authorization reads and final checks ignore tombstone budget,
    // while the old API retains its historical budget and old phases stay fixed.
    fn authorization_card_read_preserves_history_and_rechecks_after_removal() {
        let (mut input, selections) = serving_ready();
        for n in 20..25 {
            let mut historical = input.bindings[0].clone();
            historical.binding_id = id(n);
            historical.removed_at = Some(10);
            historical.removed_by = Some(id(1));
            input.bindings.push(historical);
        }
        let mut limits = budget();
        limits.max_bindings_per_read = 1;
        let owner = RootRegistry::new()
            .install_candidate(input, selections, limits)
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(
            reader.read_card_for_authorization(id(4), |context, history| (
                context.bindings.len(),
                history
            )),
            Ok((1, true))
        );
        assert!(matches!(
            reader.read_card(id(4), |_| ()),
            Err(RootError::Candidate(
                CandidateError::BindingBudgetExceeded { max: 1, actual: 6 }
            ))
        ));
        assert_eq!(reader.overlay_only_target(id(4)), Ok(false));
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![EvaluationDependency {
                binding_id: id(6),
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
            tenant_tree_version,
            registry_version,
        };
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::BindingRemove {
                    binding_id: id(6),
                    removed_at: 30,
                    removed_by: id(1),
                },
                &MutationPrecondition {
                    evaluated_root_version: reader.metadata().version,
                },
            )
            .unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        assert_eq!(
            reader.read_card_for_authorization(id(4), |context, history| (
                context.bindings.len(),
                history
            )),
            Ok((1, true))
        );
        let current = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(
            current.read_card_for_authorization(id(4), |context, history| (
                context.bindings.len(),
                history
            )),
            Ok((0, true))
        );
        assert_eq!(current.overlay_only_target(id(4)), Ok(true));
    }

    #[test]
    // memory—v1: A never-bound card is distinguishable from only-tombstone history.
    fn authorization_card_read_reports_absent_history() {
        let mut input = rows();
        input.bindings.clear();
        let owner = RootRegistry::new()
            .install_candidate(input, vec![], budget())
            .unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(
            reader.read_card_for_authorization(id(4), |context, history| (
                context.bindings.len(),
                history
            )),
            Ok((0, false))
        );
        assert_eq!(
            reader.read_card(id(4), |context| context.bindings.len()),
            Ok(0)
        );
    }

    #[test]
    // memory—v1: Neither adoption nor candidate CAS can publish an omitted index.
    fn publication_rejects_corrupt_card_index_without_changing_snapshot() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let before = owner.runtime.current.load_full();
        let mut objects = before.objects.clone();
        objects.omit_unremoved_binding_for_test(id(4));
        let corrupted = Arc::new(RootSnapshot {
            metadata: before.metadata,
            objects,
            digest_index: before.digest_index.clone(),
            adoption: None,
        });
        owner.runtime.current.store(Arc::clone(&corrupted));
        assert!(matches!(
            ValidatedAdoptionSnapshot::validate(&corrupted),
            Err(RootError::Candidate(CandidateError::InconsistentBinding))
        ));
        assert!(matches!(
            owner.adopt_serving_for_isolated_tests(),
            Err(RootError::Candidate(CandidateError::InconsistentBinding))
        ));
        assert!(Arc::ptr_eq(&owner.runtime.current.load_full(), &corrupted));
        assert!(matches!(
            owner.execute_mutation_with_precondition(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: UserCardStatus::Active
                },
                &MutationPrecondition {
                    evaluated_root_version: corrupted.metadata.version
                },
            ),
            Err(MutationError::Candidate(
                CandidateError::InconsistentBinding
            ))
        ));
        assert!(Arc::ptr_eq(&owner.runtime.current.load_full(), &corrupted));
    }

    #[test]
    // memory—v1: An omitted change-impact relationship cannot pass either publication.
    fn publication_rejects_corrupt_change_impact_index() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let before = owner.runtime.current.load_full();
        let mut objects = before.objects.clone();
        objects.omit_unremoved_rule_set_binding_for_test(id(5));
        let corrupted = Arc::new(RootSnapshot {
            metadata: before.metadata,
            objects,
            digest_index: before.digest_index.clone(),
            adoption: None,
        });
        owner.runtime.current.store(Arc::clone(&corrupted));
        assert!(matches!(
            ValidatedAdoptionSnapshot::validate(&corrupted),
            Err(RootError::Candidate(CandidateError::InconsistentBinding))
        ));
        assert!(matches!(
            owner.adopt_serving_for_isolated_tests(),
            Err(RootError::Candidate(CandidateError::InconsistentBinding))
        ));
        assert!(Arc::ptr_eq(&owner.runtime.current.load_full(), &corrupted));
        assert!(matches!(
            owner.execute_mutation_with_precondition(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: UserCardStatus::Active
                },
                &MutationPrecondition {
                    evaluated_root_version: corrupted.metadata.version
                },
            ),
            Err(MutationError::Candidate(
                CandidateError::InconsistentBinding
            ))
        ));
        assert!(Arc::ptr_eq(&owner.runtime.current.load_full(), &corrupted));
    }

    #[test]
    // memory—v1: Dangling relationships or incorrect derived confirmation states
    // fail before adoption and cannot be published by a candidate mutation.
    fn publication_rejects_corrupt_confirmation_indexes() {
        for corruption in 0..4 {
            let (input, selections) = serving_ready();
            let owner = RootRegistry::new()
                .install_candidate(input, selections, budget())
                .unwrap();
            install_fixture_registry(&owner);
            let before = owner.runtime.current.load_full();
            let mut objects = before.objects.clone();
            match corruption {
                0 => objects.insert_dangling_confirmation_for_test(id(6)),
                1 => objects.insert_dangling_change_for_test(id(5)),
                2 => objects.corrupt_binding_confirmation_state_for_test(id(6)),
                3 => objects.omit_change_confirmation_index_for_test(),
                _ => unreachable!(),
            }
            let corrupted = Arc::new(RootSnapshot {
                metadata: before.metadata,
                objects,
                digest_index: before.digest_index.clone(),
                adoption: None,
            });
            owner.runtime.current.store(Arc::clone(&corrupted));
            assert!(matches!(
                ValidatedAdoptionSnapshot::validate(&corrupted),
                Err(RootError::Candidate(CandidateError::InconsistentBinding))
            ));
            assert!(matches!(
                owner.adopt_serving_for_isolated_tests(),
                Err(RootError::Candidate(CandidateError::InconsistentBinding))
            ));
            assert!(Arc::ptr_eq(&owner.runtime.current.load_full(), &corrupted));
            assert!(matches!(
                owner.execute_mutation_with_precondition(
                    &ManagementMutationV2::UserCardStatus {
                        user_card_id: id(4),
                        status: UserCardStatus::Active,
                    },
                    &MutationPrecondition {
                        evaluated_root_version: corrupted.metadata.version,
                    },
                ),
                Err(MutationError::Candidate(
                    CandidateError::InconsistentBinding
                ))
            ));
            assert!(Arc::ptr_eq(&owner.runtime.current.load_full(), &corrupted));
        }
    }

    #[test]
    // memory—v1: The optimized evaluation view preserves history budgets,
    // complete classifications and immutable pre-revocation observations.
    fn evaluation_view_tracks_confirmation_states_and_budget() {
        use crate::memory_v1_rules::{
            classify_binding_confirmations, classify_change_confirmations,
            BindingConfirmationState, ChangeConfirmationState,
        };

        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let historical = reader
            .read_card_for_authorization(id(4), |context, history| {
                let binding = &context.bindings[0];
                (
                    history,
                    classify_binding_confirmations(
                        binding.confirmations.iter().copied(),
                        binding.binding.binding_id,
                        binding.binding.rule_set_id,
                    ),
                    classify_change_confirmations(
                        binding.change_confirmations.iter().copied(),
                        binding.binding.rule_set_id,
                        &binding.selected.unwrap().version_bytes,
                    ),
                )
            })
            .unwrap();
        let fast = |reader: &RequestRootReader| {
            reader
                .read_card_for_evaluation(id(4), |context, history| {
                    let binding = &context.bindings[0];
                    (
                        history,
                        binding.confirmation_state,
                        binding.change_confirmation_state,
                    )
                })
                .unwrap()
        };
        assert_eq!(fast(&reader), historical);
        assert_eq!(
            historical,
            (
                true,
                BindingConfirmationState::Active,
                ChangeConfirmationState::Active
            )
        );

        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id: id(7),
                    revoked_at: 42,
                    revoked_by: id(1),
                },
                &MutationPrecondition {
                    evaluated_root_version: reader.metadata().version,
                },
            )
            .unwrap();
        let after_revoke = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(fast(&reader), historical);
        assert_eq!(fast(&after_revoke).1, BindingConfirmationState::Withdrawn);

        let current = owner.runtime.current.load_full();
        let mut objects = current.objects.clone();
        objects.set_max_table_rows_for_test(1);
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata: current.metadata,
            objects,
            digest_index: current.digest_index.clone(),
            adoption: current.adoption.clone(),
        }));
        let limited = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        assert!(matches!(
            limited.read_card_for_evaluation(id(4), |_, _| ()),
            Err(RootError::Candidate(
                CandidateError::ConfirmationBudgetExceeded { max: 1 }
            ))
        ));
        assert!(matches!(
            limited.read_card_for_authorization(id(4), |_, _| ()),
            Err(RootError::Candidate(
                CandidateError::ConfirmationBudgetExceeded { max: 1 }
            ))
        ));
    }

    #[test]
    // memory—v1: Candidate construction remains usable through both public writers.
    fn candidate_writers_publish_but_refuse_uncoordinated_card_disable() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.handle().metadata().unwrap();
        let precondition = MutationPrecondition {
            evaluated_root_version: before.version,
        };
        let disable = ManagementMutationV2::UserCardStatus {
            user_card_id: id(4),
            status: UserCardStatus::Disabled,
        };
        assert!(matches!(
            owner.execute_mutation_with_precondition(&disable, &precondition),
            Err(MutationError::CardDisableRequiresSessionCoordinator)
        ));
        assert!(matches!(
            owner.mutation_executor().execute(&disable, &precondition),
            Err(MutationError::CardDisableRequiresSessionCoordinator)
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
        let first = owner
            .execute_mutation_with_precondition(
                &ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id: id(7),
                    revoked_at: 10,
                    revoked_by: id(1),
                },
                &precondition,
            )
            .unwrap();
        assert_eq!(first.version, before.version + 1);
        let second = owner
            .mutation_executor()
            .execute(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: UserCardStatus::Active,
                },
                &MutationPrecondition {
                    evaluated_root_version: first.version,
                },
            )
            .unwrap();
        assert_eq!(second.version, first.version + 1);
        assert_eq!(second.status, RootStatus::Candidate);
    }

    #[test]
    // memory—v1: Revoking a version confirmation publishes one candidate,
    // preserves its tombstone and invalidates in-flight rule dependencies.
    fn change_confirmation_revoke_publishes_once_and_invalidates_dependencies() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![EvaluationDependency {
                binding_id: id(6),
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
            tenant_tree_version,
            registry_version,
        };
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
        let before = reader.metadata();
        let mutation = ManagementMutationV2::RuleSetChangeConfirmationRevoke {
            confirmation_id: id(8),
            revoked_at: 42,
            revoked_by: id(1),
        };
        let precondition = MutationPrecondition {
            evaluated_root_version: before.version,
        };
        assert!(matches!(
            owner.execute_mutation_with_precondition(&mutation, &precondition),
            Err(MutationError::ConcurrentModification)
        ));
        let after = owner
            .execute_mutation_with_precondition_for_isolated_tests(&mutation, &precondition)
            .unwrap();
        assert_eq!(after.version, before.version + 1);
        assert_ne!(after.digest, before.digest);
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        assert_eq!(
            reader.read_card_for_evaluation(id(4), |context, _| context.bindings[0]
                .change_confirmation_state),
            Ok(crate::memory_v1_rules::ChangeConfirmationState::Active)
        );
        let current_reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(
            current_reader.read_card_for_evaluation(id(4), |context, _| context.bindings[0]
                .change_confirmation_state),
            Ok(crate::memory_v1_rules::ChangeConfirmationState::Withdrawn)
        );

        let snapshot = owner.runtime.current.load_full();
        let (rows, _) = snapshot.objects.digest_inputs();
        let confirmation = rows
            .rule_set_change_confirmations
            .iter()
            .find(|row| row.confirmation_id == id(8))
            .unwrap();
        assert_eq!(confirmation.revoked_at, Some(42));
        assert_eq!(confirmation.revoked_by, Some(id(1)));
        assert!(matches!(
            owner.execute_mutation_with_precondition_for_isolated_tests(
                &mutation,
                &MutationPrecondition {
                    evaluated_root_version: after.version,
                },
            ),
            Err(MutationError::Candidate(
                CandidateError::InconsistentBinding
            ))
        ));
        assert!(Arc::ptr_eq(&snapshot, &owner.runtime.current.load_full()));
    }

    #[test]
    // memory—v1: A cold candidate may retain disabled-card relationships,
    // but a serving candidate must never expose an active retired relationship.
    fn cold_adoption_rejects_active_binding_to_retired_rule_set() {
        let (mut input, selections) = serving_ready();
        input.rule_sets[0].status = crate::memory_v1_db_rows::RuleSetStatus::Retired;
        let owner = RootRegistry::new()
            .install_candidate(input.clone(), selections.clone(), budget())
            .unwrap();
        let snapshot = owner.runtime.current.load_full();
        assert!(ValidatedAdoptionSnapshot::validate(&snapshot).is_err());
        input.user_cards[0].status = UserCardStatus::Disabled;
        let disabled = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        assert!(ValidatedAdoptionSnapshot::validate(&disabled.runtime.current.load_full()).is_ok());
    }

    #[test]
    // memory—v1: Candidate retirement and its digest publish through the same
    // CAS. Stale and replayed mutations cannot replace the previous snapshot.
    fn retirement_cas_is_atomic_and_serving_writer_stays_closed() {
        let (mut input, selections) = serving_ready();
        input.user_cards[0].status = UserCardStatus::Disabled;
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.runtime.current.load_full();
        let mutation = ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) };
        let precondition = MutationPrecondition {
            evaluated_root_version: before.metadata.version,
        };
        let after = owner
            .execute_mutation_with_precondition(&mutation, &precondition)
            .unwrap();
        let current = owner.runtime.current.load_full();
        before
            .objects
            .assert_retirement_relationships_unchanged_for_test(&current.objects);
        assert_eq!(current.objects.validate_binding_indexes(), Ok(()));
        assert_eq!(current.objects.validate_confirmation_indexes(), Ok(()));
        assert_eq!(after.version, before.metadata.version + 1);
        assert_ne!(after.digest, before.metadata.digest);
        assert_eq!(
            after.digest,
            digest_candidate_from_candidate(&current.objects).unwrap()
        );
        assert_eq!(
            current.objects.rule_set_dependency_generation(id(5)),
            before
                .objects
                .rule_set_dependency_generation(id(5))
                .map(|n| n + 1)
        );
        assert_eq!(
            before.objects.rule_set(id(5)).unwrap().status,
            crate::memory_v1_db_rows::RuleSetStatus::Active
        );
        assert!(matches!(
            owner.execute_mutation_with_precondition(&mutation, &precondition),
            Err(MutationError::ConcurrentModification)
        ));
        assert!(matches!(
            owner.execute_mutation_with_precondition(
                &mutation,
                &MutationPrecondition {
                    evaluated_root_version: after.version
                }
            ),
            Err(MutationError::Candidate(
                CandidateError::InconsistentBinding
            ))
        ));
        assert!(Arc::ptr_eq(&current, &owner.runtime.current.load_full()));
        let validated = ValidatedAdoptionSnapshot::validate(&current).unwrap();
        owner
            .publish_adopted_snapshot(&validated, test_record())
            .unwrap();
        let serving = owner.runtime.current.load_full();
        assert!(matches!(
            owner.execute_mutation_with_precondition(
                &mutation,
                &MutationPrecondition {
                    evaluated_root_version: serving.metadata.version
                }
            ),
            Err(MutationError::ConcurrentModification)
        ));
        assert!(Arc::ptr_eq(&serving, &owner.runtime.current.load_full()));
    }

    #[test]
    // memory—v1: Retirement checks all four current indexes, including a
    // different rule set and card, and never publishes a damaged candidate.
    fn retirement_rejects_target_and_unrelated_binding_index_corruption() {
        for (card_id, rule_set_id) in [(id(4), id(5)), (id(10), id(11))] {
            for index in 0..4 {
                let (mut input, selections) = serving_ready();
                input.user_cards[0].status = UserCardStatus::Disabled;
                input.user_cards.push(UserCardRow {
                    user_card_id: id(10),
                    user_id: id(1),
                    tenant_id: id(3),
                    status: UserCardStatus::Disabled,
                });
                let mut other_rule_set = input.rule_sets[0].clone();
                other_rule_set.rule_set_id = id(11);
                other_rule_set.current_version_bytes.clear();
                input.rule_sets.push(other_rule_set);
                let mut other_binding = input.bindings[0].clone();
                other_binding.binding_id = id(12);
                other_binding.user_card_id = id(10);
                other_binding.rule_set_id = id(11);
                input.bindings.push(other_binding);
                let owner = RootRegistry::new()
                    .install_candidate(input, selections, budget())
                    .unwrap();
                let before = owner.runtime.current.load_full();
                let mut objects = before.objects.clone();
                objects.omit_binding_index_for_test(index, card_id, rule_set_id);
                let corrupted = Arc::new(RootSnapshot {
                    metadata: before.metadata,
                    objects,
                    digest_index: before.digest_index.clone(),
                    adoption: before.adoption.clone(),
                });
                owner.runtime.current.store(Arc::clone(&corrupted));
                assert!(
                    matches!(
                        owner.execute_mutation_with_precondition(
                            &ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) },
                            &MutationPrecondition {
                                evaluated_root_version: corrupted.metadata.version,
                            },
                        ),
                        Err(MutationError::Candidate(
                            CandidateError::InconsistentBinding
                        ))
                    ),
                    "index {index}, card {card_id:?}"
                );
                assert!(Arc::ptr_eq(&corrupted, &owner.runtime.current.load_full()));
            }
        }
    }

    #[test]
    // memory—v1: Retirement still checks confirmation indexes on next and
    // leaves the exact root snapshot in place when those checks fail.
    fn retirement_rejects_corrupt_confirmation_indexes() {
        for corruption in 0..4 {
            let (mut input, selections) = serving_ready();
            input.user_cards[0].status = UserCardStatus::Disabled;
            let owner = RootRegistry::new()
                .install_candidate(input, selections, budget())
                .unwrap();
            let before = owner.runtime.current.load_full();
            let mut objects = before.objects.clone();
            match corruption {
                0 => objects.insert_dangling_confirmation_for_test(id(6)),
                1 => objects.insert_dangling_change_for_test(id(5)),
                2 => objects.corrupt_binding_confirmation_state_for_test(id(6)),
                3 => objects.omit_change_confirmation_index_for_test(),
                _ => unreachable!(),
            }
            let corrupted = Arc::new(RootSnapshot {
                metadata: before.metadata,
                objects,
                digest_index: before.digest_index.clone(),
                adoption: before.adoption.clone(),
            });
            owner.runtime.current.store(Arc::clone(&corrupted));
            assert!(matches!(
                owner.execute_mutation_with_precondition(
                    &ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) },
                    &MutationPrecondition {
                        evaluated_root_version: corrupted.metadata.version,
                    },
                ),
                Err(MutationError::Candidate(
                    CandidateError::InconsistentBinding
                ))
            ));
            assert!(Arc::ptr_eq(&corrupted, &owner.runtime.current.load_full()));
        }
    }

    #[test]
    // memory—v1: Dependency generation exhaustion fails before publication.
    fn retirement_generation_overflow_preserves_root_snapshot() {
        let (mut input, selections) = serving_ready();
        input.user_cards[0].status = UserCardStatus::Disabled;
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.runtime.current.load_full();
        let mut objects = before.objects.clone();
        objects.set_rule_set_dependency_generation_for_test(id(5), u64::MAX);
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata: before.metadata,
            digest_index: before.digest_index.clone(),
            objects,
            adoption: before.adoption.clone(),
        }));
        let exhausted = owner.runtime.current.load_full();
        assert!(owner
            .execute_mutation_with_precondition(
                &ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) },
                &MutationPrecondition {
                    evaluated_root_version: exhausted.metadata.version
                },
            )
            .is_err());
        assert!(Arc::ptr_eq(&exhausted, &owner.runtime.current.load_full()));
    }

    #[test]
    // memory—v1: Competing candidate retirements share one root version;
    // exactly one can publish and the stale contender cannot overwrite it.
    fn concurrent_retirement_has_one_cas_winner() {
        let (mut input, selections) = serving_ready();
        input.user_cards[0].status = UserCardStatus::Disabled;
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.runtime.current.load_full();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let executor = owner.mutation_executor();
            let barrier = Arc::clone(&barrier);
            let version = before.metadata.version;
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                executor.execute(
                    &ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) },
                    &MutationPrecondition {
                        evaluated_root_version: version,
                    },
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(MutationError::ConcurrentModification)))
                .count(),
            1
        );
        let after = owner.runtime.current.load_full();
        assert_eq!(after.metadata.version, before.metadata.version + 1);
        assert_eq!(
            after.metadata.digest,
            digest_candidate_from_candidate(&after.objects).unwrap()
        );
    }

    #[test]
    // memory—v1: Retirement, enabling a related card and creating a new binding
    // serialize against the same root version and cannot publish an active
    // relationship to a retired rule set, whichever writer goes first.
    fn retirement_races_with_enable_and_binding_create() {
        use crate::memory_v1_db_rows::RuleSetStatus;

        for competing in ["enable", "binding"] {
            let (mut input, selections) = serving_ready();
            input.user_cards[0].status = UserCardStatus::Disabled;
            input.user_cards.push(UserCardRow {
                user_card_id: id(9),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            });
            let mut binding = input.bindings[0].clone();
            binding.binding_id = id(20);
            binding.user_card_id = id(9);
            let mut confirmation = input.binding_confirmations[0].clone();
            confirmation.binding_id = binding.binding_id;
            confirmation.confirmation_id = id(21);
            let other = match competing {
                "enable" => ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: UserCardStatus::Active,
                },
                "binding" => ManagementMutationV2::BindingCreate {
                    row: binding,
                    confirmation,
                },
                _ => unreachable!(),
            };
            let owner = RootRegistry::new()
                .install_candidate(input, selections, budget())
                .unwrap();
            let before = owner.runtime.current.load_full();
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let mut workers = Vec::new();
            for mutation in [
                ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) },
                other.clone(),
            ] {
                let executor = owner.mutation_executor();
                let barrier = Arc::clone(&barrier);
                let version = before.metadata.version;
                workers.push(std::thread::spawn(move || {
                    barrier.wait();
                    executor.execute(
                        &mutation,
                        &MutationPrecondition {
                            evaluated_root_version: version,
                        },
                    )
                }));
            }
            barrier.wait();
            let mut results = workers.into_iter().map(|worker| worker.join().unwrap());
            let retired = results.next().unwrap();
            let competed = results.next().unwrap();
            assert_ne!(retired.is_ok(), competed.is_ok(), "{competing}");
            let after = owner.runtime.current.load_full();
            assert_eq!(after.metadata.version, before.metadata.version + 1);
            assert_eq!(
                after.metadata.digest,
                digest_candidate_from_candidate(&after.objects).unwrap()
            );
            after.objects.validate_for_serving().unwrap();

            let version = after.metadata.version;
            let losing_mutation = if retired.is_ok() {
                assert_eq!(
                    after.objects.rule_set(id(5)).unwrap().status,
                    RuleSetStatus::Retired
                );
                other
            } else {
                assert_eq!(
                    after.objects.rule_set(id(5)).unwrap().status,
                    RuleSetStatus::Active
                );
                ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) }
            };
            assert!(owner
                .execute_mutation_with_precondition(
                    &losing_mutation,
                    &MutationPrecondition {
                        evaluated_root_version: version,
                    },
                )
                .is_err());
            assert!(Arc::ptr_eq(&after, &owner.runtime.current.load_full()));
        }
    }

    #[test]
    // memory—v1: A reader captured before removal cannot become fresh again
    // after retirement, and retirement advances the rule-set generation.
    fn retirement_keeps_pre_removal_reader_stale() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![EvaluationDependency {
                binding_id: id(6),
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
            tenant_tree_version,
            registry_version,
        };
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
        let removed = owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::BindingRemove {
                    binding_id: id(6),
                    removed_at: 10,
                    removed_by: id(1),
                },
                &MutationPrecondition {
                    evaluated_root_version: reader.metadata().version,
                },
            )
            .unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        let before_retire = owner.runtime.current.load_full();
        let generation = before_retire
            .objects
            .rule_set_dependency_generation(id(5))
            .unwrap();
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) },
                &MutationPrecondition {
                    evaluated_root_version: removed.version,
                },
            )
            .unwrap();
        assert_eq!(
            owner
                .runtime
                .current
                .load_full()
                .objects
                .rule_set_dependency_generation(id(5)),
            Some(generation + 1)
        );
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
    }

    #[test]
    // memory—v1: The proposed target and exact row share root-verified facts;
    // creation publishes no binding and leaves the old snapshot unchanged.
    fn user_card_create_publishes_unbound_card_and_digest() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.runtime.current.load_full();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let row = UserCardRow {
            user_card_id: id(40),
            user_id: id(1),
            tenant_id: id(3),
            status: UserCardStatus::Active,
        };
        let facts = reader
            .user_card_create_target(row.user_card_id, row.user_id, row.tenant_id)
            .unwrap();
        assert_eq!(facts.user_card_id, row.user_card_id);
        assert_eq!(facts.owner_user_id, row.user_id);
        assert_eq!(facts.tenant_id, row.tenant_id);
        assert!(reader.user_card_create_target(id(4), id(1), id(3)).is_err());
        let metadata = owner
            .execute_mutation_with_precondition(
                &ManagementMutationV2::UserCardCreate { row: row.clone() },
                &MutationPrecondition {
                    evaluated_root_version: before.metadata.version,
                },
            )
            .unwrap();
        let current = owner.runtime.current.load_full();
        assert_eq!(metadata.version, before.metadata.version + 1);
        assert_eq!(metadata.row_count, before.metadata.row_count + 1);
        assert_ne!(metadata.digest, before.metadata.digest);
        assert_eq!(
            metadata.digest,
            digest_candidate_from_candidate(&current.objects).unwrap()
        );
        assert_eq!(current.objects.user_card(id(40)), Some(&row));
        assert_eq!(current.objects.card_dependency_generation(id(40)), Some(0));
        assert!(current
            .objects
            .card_candidate(id(40))
            .unwrap()
            .bindings
            .is_empty());
        assert!(current
            .objects
            .user_cards(id(1))
            .unwrap()
            .unwrap()
            .contains(&id(40)));
        assert!(current
            .objects
            .tenant_cards(id(3))
            .unwrap()
            .unwrap()
            .contains(&id(40)));
        assert!(before.objects.user_card(id(40)).is_none());
        assert!(!reader.is_current().unwrap());
        assert!(owner
            .handle()
            .begin_request(Uuid::new_v4())
            .unwrap()
            .user_card_create_target(id(40), id(1), id(3))
            .is_err());
    }

    #[test]
    // memory—v1: Invalid creation does not publish, even when the user and
    // tenant independently exist but no root card relates them.
    fn user_card_create_rejects_unverified_targets_and_invalid_rows() {
        let (mut input, selections) = serving_ready();
        input.users.push(UserRow { user_id: id(20) });
        input.identity_cards.push(IdentityCardRow {
            identity_card_id: id(21),
            user_id: id(20),
        });
        input.tenants.push(TenantRow {
            tenant_id: id(22),
            parent_tenant_id: None,
        });
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.runtime.current.load_full();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        for (card, user, tenant, status) in [
            (id(4), id(1), id(3), UserCardStatus::Active),
            ([0; 16], id(1), id(3), UserCardStatus::Active),
            (id(40), [0; 16], id(3), UserCardStatus::Active),
            (id(40), id(1), [0; 16], UserCardStatus::Active),
            (id(40), id(99), id(3), UserCardStatus::Active),
            (id(40), id(1), id(99), UserCardStatus::Active),
            (id(40), id(20), id(3), UserCardStatus::Active),
            (id(40), id(1), id(22), UserCardStatus::Active),
            (id(40), id(1), id(3), UserCardStatus::Disabled),
        ] {
            let mutation = ManagementMutationV2::UserCardCreate {
                row: UserCardRow {
                    user_card_id: card,
                    user_id: user,
                    tenant_id: tenant,
                    status,
                },
            };
            if status == UserCardStatus::Active {
                assert!(reader.user_card_create_target(card, user, tenant).is_err());
            }
            assert!(owner
                .execute_mutation_with_precondition(
                    &mutation,
                    &MutationPrecondition {
                        evaluated_root_version: before.metadata.version,
                    }
                )
                .is_err());
            assert!(Arc::ptr_eq(&before, &owner.runtime.current.load_full()));
        }
    }

    #[test]
    // memory—v1: A full row budget rejects creation without publishing.
    fn user_card_create_budget_failure_preserves_root() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let original = owner.runtime.current.load_full();
        let mut objects = original.objects.clone();
        objects.set_max_table_rows_for_test(original.metadata.row_count);
        let limited = Arc::new(RootSnapshot {
            metadata: original.metadata,
            objects,
            digest_index: original.digest_index.clone(),
            adoption: original.adoption.clone(),
        });
        owner.runtime.current.store(Arc::clone(&limited));
        assert!(matches!(
            owner.execute_mutation_with_precondition(
                &ManagementMutationV2::UserCardCreate {
                    row: UserCardRow {
                        user_card_id: id(40),
                        user_id: id(1),
                        tenant_id: id(3),
                        status: UserCardStatus::Active,
                    }
                },
                &MutationPrecondition {
                    evaluated_root_version: limited.metadata.version
                },
            ),
            Err(MutationError::Candidate(
                CandidateError::RowBudgetExceeded { .. }
            ))
        ));
        assert!(Arc::ptr_eq(&limited, &owner.runtime.current.load_full()));
    }

    #[test]
    // memory—v1: Independent users or tenants competing at one version have
    // exactly one winner and a digest matching its published candidate.
    fn user_card_create_same_version_has_one_winner() {
        for different_user in [true, false] {
            let (mut input, selections) = serving_ready();
            input.users.push(UserRow { user_id: id(20) });
            input.identity_cards.push(IdentityCardRow {
                identity_card_id: id(21),
                user_id: id(20),
            });
            input.tenants.push(TenantRow {
                tenant_id: id(22),
                parent_tenant_id: None,
            });
            input.user_cards.push(UserCardRow {
                user_card_id: id(23),
                user_id: id(20),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            });
            input.user_cards.push(UserCardRow {
                user_card_id: id(24),
                user_id: id(1),
                tenant_id: id(22),
                status: UserCardStatus::Active,
            });
            let owner = RootRegistry::new()
                .install_candidate(input, selections, budget())
                .unwrap();
            let before = owner.runtime.current.load_full();
            let rows = [
                UserCardRow {
                    user_card_id: id(40),
                    user_id: id(1),
                    tenant_id: id(3),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(41),
                    user_id: if different_user { id(20) } else { id(1) },
                    tenant_id: if different_user { id(3) } else { id(22) },
                    status: UserCardStatus::Active,
                },
            ];
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let threads: Vec<_> = rows
                .into_iter()
                .map(|row| {
                    let executor = owner.mutation_executor();
                    let barrier = Arc::clone(&barrier);
                    let version = before.metadata.version;
                    std::thread::spawn(move || {
                        barrier.wait();
                        executor.execute(
                            &ManagementMutationV2::UserCardCreate { row },
                            &MutationPrecondition {
                                evaluated_root_version: version,
                            },
                        )
                    })
                })
                .collect();
            barrier.wait();
            let results: Vec<_> = threads
                .into_iter()
                .map(|thread| thread.join().unwrap())
                .collect();
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
            assert_eq!(
                results
                    .iter()
                    .filter(|r| matches!(r, Err(MutationError::ConcurrentModification)))
                    .count(),
                1
            );
            let after = owner.runtime.current.load_full();
            assert_eq!(after.metadata.version, before.metadata.version + 1);
            assert_eq!(
                usize::from(after.objects.user_card(id(40)).is_some())
                    + usize::from(after.objects.user_card(id(41)).is_some()),
                1
            );
            assert_eq!(
                after.metadata.digest,
                digest_candidate_from_candidate(&after.objects).unwrap()
            );
        }
    }

    #[test]
    // memory—v1: Serving raw writes cannot change any authorization fact or metadata.
    fn serving_public_writers_reject_all_raw_mutations() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let candidate = owner.runtime.current.load_full();
        let validated = ValidatedAdoptionSnapshot::validate(&candidate).unwrap();
        owner
            .publish_adopted_snapshot(&validated, test_record())
            .unwrap();
        let before = owner.runtime.current.load_full();
        let precondition = MutationPrecondition {
            evaluated_root_version: before.metadata.version,
        };
        let mutations = [
            ManagementMutationV2::UserCardCreate {
                row: UserCardRow {
                    user_card_id: id(40),
                    user_id: id(1),
                    tenant_id: id(3),
                    status: UserCardStatus::Active,
                },
            },
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: id(7),
                revoked_at: 10,
                revoked_by: id(1),
            },
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: id(8),
                revoked_at: 10,
                revoked_by: id(1),
            },
            ManagementMutationV2::BindingRemove {
                binding_id: id(6),
                removed_at: 10,
                removed_by: id(1),
            },
            ManagementMutationV2::UserCardStatus {
                user_card_id: id(4),
                status: UserCardStatus::Active,
            },
            ManagementMutationV2::UserCardStatus {
                user_card_id: id(4),
                status: UserCardStatus::Disabled,
            },
        ];
        for mutation in &mutations {
            assert!(matches!(
                owner.execute_mutation_with_precondition(mutation, &precondition),
                Err(MutationError::ConcurrentModification)
            ));
            assert!(matches!(
                owner.mutation_executor().execute(mutation, &precondition),
                Err(MutationError::ConcurrentModification)
            ));
            assert!(Arc::ptr_eq(&before, &owner.runtime.current.load_full()));
        }
        let after = owner
            .execute_mutation_with_precondition_for_isolated_tests(&mutations[1], &precondition)
            .unwrap();
        assert_eq!(after.version, before.metadata.version + 1);
        assert_ne!(after.digest, before.metadata.digest);
        let second = owner
            .mutation_executor()
            .execute_for_isolated_tests(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: UserCardStatus::Active,
                },
                &MutationPrecondition {
                    evaluated_root_version: after.version,
                },
            )
            .unwrap();
        assert_eq!(second.version, after.version + 1);
    }

    #[test]
    // memory—v1: Neither public nor test-only writers revive invalid or stopped roots.
    fn invalid_and_stopped_roots_reject_all_raw_writers() {
        for status in [RootStatus::Invalid, RootStatus::Stopped] {
            let (input, selections) = serving_ready();
            let owner = RootRegistry::new()
                .install_candidate(input, selections, budget())
                .unwrap();
            let current = owner.runtime.current.load_full();
            let mut metadata = current.metadata;
            metadata.status = status;
            let unavailable = Arc::new(RootSnapshot {
                metadata,
                objects: current.objects.clone(),
                digest_index: current.digest_index.clone(),
                adoption: current.adoption.clone(),
            });
            owner.runtime.current.store(Arc::clone(&unavailable));
            let mutation = ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: id(7),
                revoked_at: 10,
                revoked_by: id(1),
            };
            let precondition = MutationPrecondition {
                evaluated_root_version: metadata.version,
            };
            let executor = owner.mutation_executor();
            for result in [
                owner.execute_mutation_with_precondition(&mutation, &precondition),
                executor.execute(&mutation, &precondition),
                owner.execute_mutation_with_precondition_for_isolated_tests(
                    &mutation,
                    &precondition,
                ),
                executor.execute_for_isolated_tests(&mutation, &precondition),
            ] {
                assert!(matches!(
                    result,
                    Err(MutationError::Runtime(RuntimeError::OwnerGone))
                ));
            }
            assert!(Arc::ptr_eq(
                &unavailable,
                &owner.runtime.current.load_full()
            ));
        }
    }

    #[test]
    // memory—v1 §4.11 N-10: A candidate batch publishes one snapshot and
    // advances each affected card once, including when a card has two items.
    fn confirmation_batch_publishes_one_candidate_for_all_affected_cards() {
        let (mut input, mut selections) = serving_ready();
        input.binding_confirmations[0].revoked_at = Some(10);
        input.binding_confirmations[0].revoked_by = Some(id(1));
        for card_id in [id(9), id(10)] {
            let mut card = input.user_cards[0].clone();
            card.user_card_id = card_id;
            input.user_cards.push(card);
        }
        let mut other_rule_set = input.rule_sets[0].clone();
        other_rule_set.rule_set_id = id(11);
        input.rule_sets.push(other_rule_set);
        let mut other_version = input.rule_set_versions[0].clone();
        other_version.rule_set_id = id(11);
        input.rule_set_versions.push(other_version);
        selections.push(CurrentSelection {
            rule_set_id: id(11),
            version_bytes: vec![1],
        });
        let mut second_binding = input.bindings[0].clone();
        second_binding.binding_id = id(12);
        second_binding.user_card_id = id(9);
        input.bindings.push(second_binding);
        let mut third_binding = input.bindings[0].clone();
        third_binding.binding_id = id(13);
        third_binding.rule_set_id = id(11);
        input.bindings.push(third_binding);

        let mut confirmations = Vec::new();
        for (confirmation_id, binding_id, rule_set_id) in [
            (id(20), id(6), id(5)),
            (id(21), id(12), id(5)),
            (id(22), id(13), id(11)),
        ] {
            let mut confirmation = input.binding_confirmations[0].clone();
            confirmation.confirmation_id = confirmation_id;
            confirmation.binding_id = binding_id;
            confirmation.rule_set_id = rule_set_id;
            confirmation.revoked_at = None;
            confirmation.revoked_by = None;
            confirmations.push(confirmation);
        }
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.runtime.current.load_full();
        let mutation = ManagementMutationV2::ConfirmationBatch {
            rows: confirmations,
        };
        let precondition = MutationPrecondition {
            evaluated_root_version: before.metadata.version,
        };
        let after = owner
            .execute_mutation_with_precondition(&mutation, &precondition)
            .unwrap();
        let published = owner.runtime.current.load_full();

        assert_eq!(after.version, before.metadata.version + 1);
        assert_eq!(published.metadata, after);
        assert_ne!(after.digest, before.metadata.digest);
        assert_eq!(after.row_count, before.metadata.row_count + 3);
        for card_id in [id(4), id(9)] {
            assert_eq!(
                published.objects.card_dependency_generation(card_id),
                before
                    .objects
                    .card_dependency_generation(card_id)
                    .map(|v| v + 1)
            );
        }
        assert_eq!(
            published.objects.card_dependency_generation(id(10)),
            before.objects.card_dependency_generation(id(10))
        );
        for (binding_id, confirmation_id) in [(id(6), id(20)), (id(12), id(21)), (id(13), id(22))] {
            assert!(published
                .objects
                .binding_confirmations(binding_id)
                .unwrap()
                .iter()
                .any(|row| row.confirmation_id == confirmation_id));
            assert!(!before
                .objects
                .binding_confirmations(binding_id)
                .unwrap()
                .iter()
                .any(|row| row.confirmation_id == confirmation_id));
        }
        assert!(matches!(
            owner.execute_mutation_with_precondition(&mutation, &precondition),
            Err(MutationError::ConcurrentModification)
        ));
        assert!(Arc::ptr_eq(&published, &owner.runtime.current.load_full()));
    }

    #[test]
    // memory—v1: An empty batch cannot advance the root or card generations.
    fn empty_confirmation_batch_does_not_publish() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.handle().metadata().unwrap();
        let precondition = MutationPrecondition {
            evaluated_root_version: before.version,
        };
        let mutation = ManagementMutationV2::ConfirmationBatch { rows: vec![] };

        assert!(matches!(
            owner.execute_mutation_with_precondition(&mutation, &precondition),
            Err(MutationError::Candidate(
                CandidateError::InconsistentBinding
            ))
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
    }

    #[test]
    // memory—v1: Rejected tombstones cannot publish a root version or a batch prefix.
    fn incomplete_tombstone_mutations_leave_root_unchanged() {
        use crate::memory_v1_db_rows::{Table, ValidationError};

        let (input, selections) = serving_ready();
        let mut row = input.binding_confirmations[0].clone();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.handle().metadata().unwrap();
        let precondition = MutationPrecondition {
            evaluated_root_version: before.version,
        };
        let mut prefix = row.clone();
        prefix.confirmation_id = id(20);
        row.confirmation_id = id(21);

        for (revoked_at, revoked_by) in [(Some(10), None), (None, Some(id(1)))] {
            row.revoked_at = revoked_at;
            row.revoked_by = revoked_by;
            for mutation in [
                ManagementMutationV2::ConfirmationCreate { row: row.clone() },
                ManagementMutationV2::ConfirmationBatch {
                    rows: vec![prefix.clone(), row.clone()],
                },
            ] {
                assert!(matches!(
                    owner.execute_mutation_with_precondition(&mutation, &precondition),
                    Err(MutationError::Candidate(CandidateError::Rows(
                        ValidationError::MissingReference {
                            table: Table::BindingConfirmation,
                            field,
                            id: error_id,
                        }
                    ))) if error_id == row.confirmation_id
                        && field == if revoked_at.is_some() { "revoked_by" } else { "revoked_at" }
                ));
                assert_eq!(owner.handle().metadata().unwrap(), before);
                let snapshot = owner.runtime.current.load_full();
                let confirmations = snapshot.objects.binding_confirmations(id(6)).unwrap();
                assert_eq!(confirmations.len(), 1);
                assert_eq!(confirmations[0].confirmation_id, id(7));
            }
        }
    }

    #[test]
    // memory—v1: Binding creation cannot revive a revoked confirmation.
    fn binding_create_rejects_revoked_confirmation_without_publishing() {
        use crate::memory_v1_db_rows::{Table, ValidationError};

        let (mut input, selections) = serving_ready();
        let mut binding = input.bindings.remove(0);
        let mut confirmation = input.binding_confirmations.remove(0);
        binding.binding_id = id(20);
        confirmation.binding_id = binding.binding_id;
        confirmation.confirmation_id = id(21);
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.handle().metadata().unwrap();
        let precondition = MutationPrecondition {
            evaluated_root_version: before.version,
        };

        for (revoked_at, revoked_by) in [
            (Some(10), None),
            (None, Some(id(1))),
            (Some(10), Some(id(1))),
        ] {
            confirmation.revoked_at = revoked_at;
            confirmation.revoked_by = revoked_by;
            let mutation = ManagementMutationV2::BindingCreate {
                row: binding.clone(),
                confirmation: confirmation.clone(),
            };
            assert!(matches!(
                owner.execute_mutation_with_precondition(&mutation, &precondition),
                Err(MutationError::Candidate(CandidateError::Rows(
                    ValidationError::MissingReference {
                        table: Table::BindingConfirmation,
                        field: "active_confirmation",
                        id: error_id,
                    }
                ))) if error_id == confirmation.confirmation_id
            ));
            assert_eq!(owner.handle().metadata().unwrap(), before);
            let snapshot = owner.runtime.current.load_full();
            assert!(snapshot
                .objects
                .binding(binding.binding_id)
                .unwrap()
                .is_none());
            assert!(matches!(
                snapshot.objects.binding_confirmations(binding.binding_id),
                Err(CandidateError::UnknownId {
                    table: Table::Binding,
                    id: error_id,
                }) if error_id == binding.binding_id
            ));
        }

        confirmation.revoked_at = None;
        confirmation.revoked_by = None;
        let after = owner
            .execute_mutation_with_precondition(
                &ManagementMutationV2::BindingCreate {
                    row: binding,
                    confirmation,
                },
                &precondition,
            )
            .unwrap();
        assert_eq!(after.version, before.version + 1);
    }

    #[test]
    // memory—v1: The confirmation in a create plan must name the new binding.
    fn binding_create_rejects_confirmation_for_another_binding() {
        use crate::memory_v1_db_rows::{Table, ValidationError};

        let (mut input, selections) = serving_ready();
        input.user_cards.push(UserCardRow {
            user_card_id: id(9),
            user_id: id(1),
            tenant_id: id(3),
            status: UserCardStatus::Active,
        });
        let mut binding = input.bindings[0].clone();
        binding.binding_id = id(20);
        binding.user_card_id = id(9);
        let mut confirmation = input.binding_confirmations[0].clone();
        confirmation.confirmation_id = id(21);
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.handle().metadata().unwrap();
        let precondition = MutationPrecondition {
            evaluated_root_version: before.version,
        };
        for (binding_id, rule_set_id) in [(id(6), id(5)), (id(20), id(9))] {
            confirmation.binding_id = binding_id;
            confirmation.rule_set_id = rule_set_id;
            assert!(matches!(
                owner.execute_mutation_with_precondition(
                    &ManagementMutationV2::BindingCreate {
                        row: binding.clone(),
                        confirmation: confirmation.clone(),
                    },
                    &precondition,
                ),
                Err(MutationError::Candidate(CandidateError::Rows(
                    ValidationError::MissingBindingPair {
                        binding_id,
                        rule_set_id,
                    }
                ))) if binding_id == binding.binding_id && rule_set_id == binding.rule_set_id
            ));
            assert_eq!(owner.handle().metadata().unwrap(), before);
            assert!(matches!(
                owner.runtime.current.load_full().objects.binding_confirmations(id(20)),
                Err(CandidateError::UnknownId { table: Table::Binding, id: missing })
                    if missing == id(20)
            ));
            let snapshot = owner.runtime.current.load_full();
            assert_eq!(
                snapshot.objects.binding_confirmations(id(6)).unwrap().len(),
                1
            );
        }
        confirmation.binding_id = binding.binding_id;
        confirmation.rule_set_id = binding.rule_set_id;
        let after = owner
            .execute_mutation_with_precondition(
                &ManagementMutationV2::BindingCreate {
                    row: binding.clone(),
                    confirmation: confirmation.clone(),
                },
                &precondition,
            )
            .unwrap();
        assert_eq!(after.version, before.version + 1);
        let snapshot = owner.runtime.current.load_full();
        assert_eq!(
            snapshot.objects.binding(binding.binding_id).unwrap(),
            Some(&binding)
        );
        assert_eq!(
            snapshot
                .objects
                .binding_confirmations(binding.binding_id)
                .unwrap(),
            vec![&confirmation]
        );
        assert_eq!(
            snapshot.objects.binding_confirmations(id(6)).unwrap().len(),
            1
        );
    }

    #[test]
    // memory—v1: Fence lookup never waits and never mistakes unavailable for inactive.
    fn fence_read_fails_closed_on_contention_and_poison() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(
            owner.handle().metadata().unwrap(),
        );
        install_fixture_registry(&owner);
        owner.adopt_isolated_evidence(&evidence).unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![EvaluationDependency {
                binding_id: id(6),
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
            tenant_tree_version,
            registry_version,
        };
        assert_eq!(reader.is_fenced(id(5)), Ok(false));
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
        let metadata = owner.handle().metadata().unwrap();
        let declaration = FenceDeclaration {
            rule_set_version: vec![1],
            root_version: metadata.version,
            digest: metadata.digest,
        };
        owner.begin_modification_fence(id(5), &declaration).unwrap();
        assert_eq!(reader.is_fenced(id(5)), Ok(true));
        assert_eq!(reader.is_fenced(id(9)), Ok(false));
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        owner.abort_modification_fence(id(5)).unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));

        std::thread::scope(|threads| {
            let (held_tx, held_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let (result_tx, result_rx) = mpsc::channel();
            let runtime = Arc::clone(&owner.runtime);
            let holder = threads.spawn(move || {
                runtime.fences.with_table_lock_for_test(|| {
                    held_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                });
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let reader_ref = &reader;
            let record_ref = &record;
            let worker = threads.spawn(move || {
                result_tx
                    .send((
                        reader_ref.is_fenced(id(5)),
                        reader_ref.recheck_dependencies(record_ref),
                    ))
                    .unwrap();
            });
            let observed = result_rx.recv_timeout(Duration::from_secs(2));
            release_tx.send(()).unwrap();
            holder.join().unwrap();
            worker.join().unwrap();
            assert_eq!(observed.unwrap(), (Ok(false), Ok(true)));
        });
        assert_eq!(reader.is_fenced(id(5)), Ok(false));
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));

        let runtime = Arc::clone(&owner.runtime);
        assert!(std::thread::spawn(move || {
            runtime.fences.with_table_lock_for_test(|| {
                panic!("inject fence table poison");
            });
        })
        .join()
        .is_err());
        assert_eq!(
            reader.is_fenced(id(5)),
            Err(RootError::Runtime(RuntimeError::Poisoned))
        );
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
    }

    #[test]
    // memory—v1: A legacy capacity failure must not poison the enclosing root
    // writer; after a fence is released, authorization can recover.
    fn fence_capacity_failure_does_not_poison_root_writer() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        let metadata = reader.metadata();
        let declaration = FenceDeclaration {
            rule_set_version: vec![1],
            root_version: metadata.version,
            digest: metadata.digest,
        };
        let premise = FencePremise {
            root_version: metadata.version,
            digest: metadata.digest,
            selected_version: Some(vec![1]),
        };
        let mut ids = Vec::new();
        loop {
            let mut rule_set_id = [0; 16];
            rule_set_id[..8].copy_from_slice(&(ids.len() as u64).to_be_bytes());
            rule_set_id[15] = 200;
            match owner
                .runtime
                .fences
                .try_begin_legacy(rule_set_id, &declaration, &premise)
            {
                Ok(()) => ids.push(rule_set_id),
                Err(crate::memory_v1_fence::FenceControlError::CapacityExceeded { limit }) => {
                    assert_eq!(ids.len(), limit);
                    break;
                }
                Err(error) => panic!("unexpected fence error: {error}"),
            }
            assert!(ids.len() <= 4096);
        }
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.begin_modification_fence(id(5), &declaration)
        }));
        assert!(failure.is_err());
        owner.abort_modification_fence(ids.pop().unwrap()).unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
        owner.begin_modification_fence(id(5), &declaration).unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        owner.abort_modification_fence(id(5)).unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
    }

    #[test]
    // memory—v1 §4.7: A concurrent mutation makes final recheck fail closed.
    fn dependency_recheck_refuses_while_a_writer_holds_the_lock() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(
            owner.handle().metadata().unwrap(),
        );
        install_fixture_registry(&owner);
        owner.adopt_isolated_evidence(&evidence).unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![EvaluationDependency {
                binding_id: id(6),
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
            tenant_tree_version,
            registry_version,
        };
        let _writer = owner.runtime.mutation_lock.write().unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        drop(_writer);
    }

    #[test]
    // memory—v1: Concurrent read-side final checks must not reject each other.
    fn dependency_rechecks_share_a_stable_root_observation() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![EvaluationDependency {
                binding_id: id(6),
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
            tenant_tree_version,
            registry_version,
        };
        std::thread::scope(|threads| {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let (result_tx, result_rx) = mpsc::channel();
            let first_reader = &reader;
            let first_record = &record;
            let first = threads.spawn(move || {
                first_reader.try_with_rechecked_dependencies(first_record, || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let second_reader = &reader;
            let second_record = &record;
            let second = threads.spawn(move || {
                result_tx
                    .send(second_reader.recheck_dependencies(second_record))
                    .unwrap();
            });
            let observed = result_rx.recv_timeout(Duration::from_secs(2));
            release_tx.send(()).unwrap();
            assert_eq!(first.join().unwrap(), Ok(Some(())));
            second.join().unwrap();
            assert_eq!(observed.unwrap(), Ok(true));
        });
    }

    #[test]
    // memory—v1: Fence insertion can proceed while another root reader is active.
    fn fence_begin_shares_root_reads_and_preserves_the_premise() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        let metadata = reader.metadata();
        let declaration = FenceDeclaration {
            rule_set_version: vec![1],
            root_version: metadata.version,
            digest: metadata.digest,
        };

        std::thread::scope(|threads| {
            let (opened_tx, opened_rx) = mpsc::channel();
            let root_read = owner.runtime.mutation_lock.read().unwrap();
            let owner_ref = &owner;
            let declaration_ref = &declaration;
            let opener = threads.spawn(move || {
                opened_tx
                    .send(owner_ref.begin_modification_fence(id(5), declaration_ref))
                    .unwrap();
            });
            let opened = opened_rx.recv_timeout(Duration::from_secs(2));
            drop(root_read);
            opener.join().unwrap();
            assert_eq!(opened.unwrap(), Ok(()));
        });
        assert_eq!(reader.is_fenced(id(5)), Ok(true));
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        owner.abort_modification_fence(id(5)).unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));

        let stale = FenceDeclaration {
            root_version: metadata.version + 1,
            ..declaration
        };
        assert!(matches!(
            owner.begin_modification_fence(id(5), &stale),
            Err(FenceError::RootMismatch { .. })
        ));
        assert_eq!(reader.is_fenced(id(5)), Ok(false));
    }

    #[test]
    // memory—v1: A root writer cannot change the premise while a fence opener
    // waits to insert it, and a declaration becomes stale after publication.
    fn fence_begin_holds_root_premise_until_insertion() {
        use std::sync::{mpsc, TryLockError};
        use std::time::{Duration, Instant};

        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.handle().metadata().unwrap();
        let declaration = FenceDeclaration {
            rule_set_version: vec![1],
            root_version: before.version,
            digest: before.digest,
        };

        std::thread::scope(|threads| {
            let (held_tx, held_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let owner_ref = &owner;
            let holder = threads.spawn(move || {
                owner_ref.runtime.fences.with_table_lock_for_test(|| {
                    held_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                });
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();

            let (started_tx, started_rx) = mpsc::channel();
            let (opened_tx, opened_rx) = mpsc::channel();
            let owner_ref = &owner;
            let declaration_ref = &declaration;
            let opener = threads.spawn(move || {
                started_tx.send(()).unwrap();
                opened_tx
                    .send(owner_ref.begin_modification_fence(id(5), declaration_ref))
                    .unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let root_guard_held = loop {
                match owner.runtime.mutation_lock.try_write() {
                    Ok(guard) => drop(guard),
                    Err(TryLockError::WouldBlock) => break true,
                    Err(TryLockError::Poisoned(_)) => break false,
                }
                if Instant::now() >= deadline {
                    break false;
                }
                std::thread::yield_now();
            };
            let root_read_is_shared = owner.runtime.mutation_lock.try_read().is_ok();
            let insertion_waits = matches!(opened_rx.try_recv(), Err(mpsc::TryRecvError::Empty));
            release_tx.send(()).unwrap();
            holder.join().unwrap();
            let opened = opened_rx.recv_timeout(Duration::from_secs(5));
            opener.join().unwrap();
            assert!(root_guard_held);
            assert!(root_read_is_shared);
            assert!(insertion_waits);
            assert_eq!(opened.unwrap(), Ok(()));
        });
        owner.abort_modification_fence(id(5)).unwrap();
        let published = owner
            .execute_mutation_with_precondition(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: UserCardStatus::Active,
                },
                &MutationPrecondition {
                    evaluated_root_version: before.version,
                },
            )
            .unwrap();
        assert_eq!(published.version, before.version + 1);
        assert!(matches!(
            owner.begin_modification_fence(id(5), &declaration),
            Err(FenceError::RootMismatch { .. })
        ));
        assert!(!owner.runtime.fences.is_active(id(5)));
    }

    // memory—v1: A fence opening during the final clock invalidates that check.
    #[test]
    fn fence_begin_during_final_check_is_observed() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        let metadata = reader.metadata();
        let declaration = FenceDeclaration {
            rule_set_version: vec![1],
            root_version: metadata.version,
            digest: metadata.digest,
        };

        std::thread::scope(|threads| {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let reader_ref = &reader;
            let record_ref = &record;
            let checked = threads.spawn(move || {
                reader_ref.try_with_rechecked_dependencies(record_ref, || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                })
            });
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let (attempt_tx, attempt_rx) = mpsc::channel();
            let (opened_tx, opened_rx) = mpsc::channel();
            let owner_ref = &owner;
            let declaration_ref = &declaration;
            let opener = threads.spawn(move || {
                attempt_tx.send(()).unwrap();
                opened_tx
                    .send(owner_ref.begin_modification_fence(id(5), declaration_ref))
                    .unwrap();
            });
            attempt_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(
                opened_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                Ok(())
            );
            release_tx.send(()).unwrap();
            assert_eq!(checked.join().unwrap(), Ok(None));
            opener.join().unwrap();
        });
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        owner.abort_modification_fence(id(5)).unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
    }

    #[test]
    // memory—v1: A panic in a read-only final callback leaves the snapshot
    // usable; a panicking writer makes both final checks and issuance fail closed.
    fn root_writer_poison_refuses_rechecks_and_session_issuance() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = crate::memory_v1_session_authority::MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        let failed_callback = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = reader.try_with_rechecked_dependencies(&record, || panic!("read failure"));
        }));
        assert!(failed_callback.is_err());
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));

        let runtime = Arc::clone(&owner.runtime);
        assert!(std::thread::spawn(move || {
            let _writer = runtime.mutation_lock.write().unwrap();
            panic!("write failure");
        })
        .join()
        .is_err());
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        let identity = astral_types::memory_v1::CandidateIdentity {
            user_id: astral_types::memory_v1::MemoryId::from_bytes(id(1)),
            identity_card_id: astral_types::memory_v1::MemoryId::from_bytes(id(2)),
            user_card_id: astral_types::memory_v1::MemoryId::from_bytes(id(4)),
            tenant_id: astral_types::memory_v1::MemoryId::from_bytes(id(3)),
        };
        let now = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let scope =
            crate::memory_v1_request::RequestRootScope::new(owner.handle(), Default::default());
        assert!(authority
            .identity_session_adapter()
            .issue_verified_session_in_root(&scope.extension(), identity, now, 60)
            .is_err());
    }

    #[test]
    // memory—v1: An exhausted snapshot remains closed if another reader prevents
    // immediate invalidation; a later observation can publish its Invalid status.
    fn exhausted_recheck_fails_closed_while_invalidation_is_contended() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        let previous = owner.runtime.current.load_full();
        let mut metadata = previous.metadata;
        metadata.version = u64::MAX;
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: previous.objects.clone(),
            digest_index: previous.digest_index.clone(),
            adoption: previous.adoption.clone(),
        }));
        let guard = owner.runtime.mutation_lock.read().unwrap();
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        assert_eq!(
            owner.runtime.current.load().metadata.status,
            RootStatus::Serving
        );
        assert_eq!(
            owner.handle().metadata(),
            Err(RootError::Unavailable(RootStatus::Invalid))
        );
        drop(guard);
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        assert_eq!(
            owner.runtime.current.load().metadata.status,
            RootStatus::Invalid
        );
    }

    #[test]
    // memory—v1: Unknown cards and unreadable snapshots are rejected without
    // converting an ordinary failed recheck into a candidate lookup error.
    fn dependency_recheck_returns_false_for_unknown_card_and_unavailable_root() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let unknown = DependencyRecord {
            card_id: id(99),
            instance_id: reader.metadata().instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        assert_eq!(reader.recheck_dependencies(&unknown), Ok(false));
        let current = owner.runtime.current.load_full();
        let mut metadata = current.metadata;
        metadata.status = RootStatus::Invalid;
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: current.objects.clone(),
            digest_index: current.digest_index.clone(),
            adoption: current.adoption.clone(),
        }));
        assert_eq!(reader.recheck_dependencies(&unknown), Ok(false));
    }

    #[test]
    // memory—v1: The capacity applies to distinct fence dependencies; target
    // order and duplicates cannot hide an active fence or bypass the limit.
    fn dependency_recheck_bounds_distinct_fence_targets() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let metadata = reader.metadata();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: metadata.instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        let target_id = |value: u64| {
            let mut id = [0; 16];
            id[..8].copy_from_slice(&value.to_be_bytes());
            id[15] = 200;
            id
        };
        let mut targets: Vec<_> = (1..MAX_FENCE_CHECK_OBJECTS as u64)
            .rev()
            .map(target_id)
            .collect();
        let check = |targets: &[BinaryId]| {
            reader.try_with_rechecked_dependencies_and_target(
                &record,
                Some((metadata, targets)),
                None,
                || (),
            )
        };
        assert_eq!(check(&targets), Ok(Some(())));

        let declaration = FenceDeclaration {
            rule_set_version: vec![1],
            root_version: metadata.version,
            digest: metadata.digest,
        };
        owner.begin_modification_fence(id(5), &declaration).unwrap();
        assert_eq!(check(&targets), Ok(None));
        owner.abort_modification_fence(id(5)).unwrap();
        assert_eq!(check(&targets), Ok(Some(())));

        targets.push(targets[0]);
        assert_eq!(check(&targets), Ok(Some(())));
        *targets.last_mut().unwrap() = target_id(MAX_FENCE_CHECK_OBJECTS as u64);
        assert_eq!(check(&targets), Ok(None));
        targets.push(targets[0]);
        assert_eq!(check(&targets), Ok(None));
    }

    #[test]
    #[ignore = "isolated capacity timing; run explicitly with --ignored --nocapture"]
    // memory—v1: Measure reverse-ordered target checks without service or DB I/O.
    fn dependency_recheck_reverse_target_scale() {
        use std::hint::black_box;
        use std::time::Instant;

        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let metadata = reader.metadata();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: metadata.instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        for count in [128, 1024, MAX_FENCE_CHECK_OBJECTS - 1] {
            let targets: Vec<BinaryId> = (1..=count as u64)
                .rev()
                .map(|value| {
                    let mut id = [0; 16];
                    id[..8].copy_from_slice(&value.to_be_bytes());
                    id[15] = 200;
                    id
                })
                .collect();
            for _ in 0..4 {
                assert!(reader
                    .try_with_rechecked_dependencies_and_target(
                        &record,
                        Some((metadata, black_box(&targets))),
                        None,
                        || (),
                    )
                    .unwrap()
                    .is_some());
            }
            let mut elapsed = Vec::with_capacity(25);
            for _ in 0..25 {
                let start = Instant::now();
                assert!(reader
                    .try_with_rechecked_dependencies_and_target(
                        &record,
                        Some((metadata, black_box(&targets))),
                        None,
                        || (),
                    )
                    .unwrap()
                    .is_some());
                elapsed.push(start.elapsed().as_nanos());
            }
            elapsed.sort_unstable();
            println!(
                "scope=isolated_root_check targets={count} samples={} p50_ns={} p95_ns={} max_ns={}",
                elapsed.len(), elapsed[elapsed.len() / 2], elapsed[23], elapsed[24]
            );
        }
    }

    #[test]
    // memory—v1: Current lifecycle state is checked even if generations match.
    fn dependency_recheck_rejects_inactive_current_state_with_matching_generations() {
        for (disable_card, remove_binding, empty_record) in [
            (false, true, false),
            (true, false, false),
            (true, false, true),
        ] {
            let (input, selections) = serving_ready();
            let owner = RootRegistry::new()
                .install_candidate(input.clone(), selections.clone(), budget())
                .unwrap();
            let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(
                owner.handle().metadata().unwrap(),
            );
            install_fixture_registry(&owner);
            owner.adopt_isolated_evidence(&evidence).unwrap();
            let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
            let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
            let record = DependencyRecord {
                card_id: id(4),
                instance_id: reader.metadata().instance_id,
                bindings: if empty_record {
                    Vec::new()
                } else {
                    vec![EvaluationDependency {
                        binding_id: id(6),
                        rule_set_id: id(5),
                        version_bytes: vec![1],
                    }]
                },
                tenant_tree_version,
                registry_version,
            };
            assert_eq!(reader.recheck_dependencies(&record), Ok(true));

            // Inject a synthetic current snapshot with freshly initialized,
            // unchanged generations. Normal mutations advance the generation;
            // this deliberately isolates the independent lifecycle guard.
            let mut changed = input;
            if disable_card {
                changed.user_cards[0].status = UserCardStatus::Disabled;
            }
            if remove_binding {
                changed.bindings[0].removed_at = Some(10);
                changed.bindings[0].removed_by = Some(id(1));
            }
            let objects = HamtCandidate::build(changed, selections, budget()).unwrap();
            assert_eq!(
                objects.card_dependency_generation(id(4)),
                reader.snapshot.objects.card_dependency_generation(id(4))
            );
            assert_eq!(
                objects.rule_set_dependency_generation(id(5)),
                reader
                    .snapshot
                    .objects
                    .rule_set_dependency_generation(id(5))
            );
            let before = owner.runtime.current.load_full();
            let mut metadata = before.metadata;
            metadata.version += 1;
            metadata.digest = digest_candidate_from_candidate(&objects).unwrap();
            owner.runtime.current.store(Arc::new(RootSnapshot {
                metadata,
                digest_index: fixture_digest_index(&objects),
                objects,
                adoption: before.adoption.clone(),
            }));
            assert_eq!(
                reader.recheck_dependencies(&record),
                Ok(false),
                "disable_card={disable_card}, remove_binding={remove_binding}, empty_record={empty_record}"
            );
        }
    }

    #[test]
    // memory—v1: Even synthetic matching generations cannot hide a retired
    // actor dependency; the public record may omit that binding entirely.
    fn dependency_recheck_rejects_retired_actor_rule_set_with_matching_generation() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input.clone(), selections.clone(), budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.adopt_serving_for_isolated_tests().unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: Vec::new(),
            tenant_tree_version,
            registry_version,
        };
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
        let mut changed = input;
        changed.rule_sets[0].status = crate::memory_v1_db_rows::RuleSetStatus::Retired;
        let objects = HamtCandidate::build(changed, selections, budget()).unwrap();
        assert_eq!(
            objects.rule_set_dependency_generation(id(5)),
            reader
                .snapshot
                .objects
                .rule_set_dependency_generation(id(5))
        );
        let before = owner.runtime.current.load_full();
        let mut metadata = before.metadata;
        metadata.version += 1;
        metadata.digest = digest_candidate_from_candidate(&objects).unwrap();
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            digest_index: fixture_digest_index(&objects),
            objects,
            adoption: before.adoption.clone(),
        }));
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
    }

    #[test]
    // memory—v1: A historical removed binding outside the record is not required to be active.
    fn dependency_recheck_accepts_active_binding_with_historical_removed_binding() {
        let (mut input, mut selections) = serving_ready();
        let mut historical_set = input.rule_sets[0].clone();
        historical_set.rule_set_id = id(9);
        input.rule_sets.push(historical_set);
        let mut historical_version = input.rule_set_versions[0].clone();
        historical_version.rule_set_id = id(9);
        input.rule_set_versions.push(historical_version);
        let mut historical_confirmation = input.rule_set_change_confirmations[0].clone();
        historical_confirmation.confirmation_id = id(11);
        historical_confirmation.rule_set_id = id(9);
        input
            .rule_set_change_confirmations
            .push(historical_confirmation);
        let mut historical_binding = input.bindings[0].clone();
        historical_binding.binding_id = id(10);
        historical_binding.rule_set_id = id(9);
        historical_binding.removed_at = Some(10);
        historical_binding.removed_by = Some(id(1));
        input.bindings.push(historical_binding);
        selections.push(CurrentSelection {
            rule_set_id: id(9),
            version_bytes: vec![1],
        });
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(
            owner.handle().metadata().unwrap(),
        );
        install_fixture_registry(&owner);
        owner.adopt_isolated_evidence(&evidence).unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![EvaluationDependency {
                binding_id: id(6),
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
            tenant_tree_version,
            registry_version,
        };
        let original = owner.runtime.current.load_full();
        let mut objects = original.objects.clone();
        objects.set_rule_set_dependency_generation_for_test(id(9), u64::MAX);
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata: original.metadata,
            objects,
            digest_index: original.digest_index.clone(),
            adoption: original.adoption.clone(),
        }));
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
    }

    #[test]
    // memory—v1: Exhausting the root sequence closes new and in-flight reads.
    fn exhausted_root_closes_reads_before_another_increment() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(
            owner.handle().metadata().unwrap(),
        );
        install_fixture_registry(&owner);
        owner.adopt_isolated_evidence(&evidence).unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));

        let previous = owner.runtime.current.load_full();
        let mut metadata = previous.metadata;
        metadata.version = u64::MAX;
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: previous.objects.clone(),
            digest_index: previous.digest_index.clone(),
            adoption: previous.adoption.clone(),
        }));
        assert_eq!(
            owner.handle().metadata(),
            Err(RootError::Unavailable(RootStatus::Invalid))
        );
        assert!(matches!(
            owner.handle().begin_request(Uuid::new_v4()),
            Err(RootError::Unavailable(RootStatus::Invalid))
        ));
        assert_eq!(
            reader.read_card(id(4), |_| ()),
            Err(RootError::Unavailable(RootStatus::Invalid))
        );
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        let invalid = owner.runtime.current.load_full();
        assert_eq!(invalid.metadata.status, RootStatus::Invalid);
        assert_eq!(invalid.metadata.version, u64::MAX);
        assert_eq!(invalid.metadata.digest, previous.metadata.digest);
        assert_eq!(
            invalid.objects.card_dependency_generation(id(4)),
            previous.objects.card_dependency_generation(id(4))
        );
    }

    #[test]
    // memory—v1: A non-serving exhausted candidate stays diagnostic and unchanged.
    fn exhausted_candidate_cannot_adopt_or_build_a_mutation() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let previous = owner.runtime.current.load_full();
        let mut metadata = previous.metadata;
        metadata.version = u64::MAX;
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: previous.objects.clone(),
            digest_index: previous.digest_index.clone(),
            adoption: previous.adoption.clone(),
        }));
        assert_eq!(owner.handle().metadata().unwrap(), metadata);
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(metadata);
        assert_eq!(
            owner.adopt_isolated_evidence(&evidence),
            Err(RootError::Unavailable(RootStatus::Invalid))
        );
        assert!(matches!(
            owner.execute_mutation_with_precondition(
                &ManagementMutationV2::ConfirmationBatch { rows: vec![] },
                &MutationPrecondition {
                    evaluated_root_version: u64::MAX,
                },
            ),
            Err(MutationError::VersionOverflow)
        ));
        assert_eq!(owner.runtime.current.load().metadata, metadata);
    }

    #[test]
    // memory—v1: The last representable root publication is already exhausted.
    fn last_root_generation_cannot_be_used_for_positive_evidence() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let previous = owner.runtime.current.load_full();
        let mut metadata = previous.metadata;
        metadata.version = u64::MAX - 1;
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: previous.objects.clone(),
            digest_index: previous.digest_index.clone(),
            adoption: previous.adoption.clone(),
        }));
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(metadata);
        owner.adopt_isolated_evidence(&evidence).unwrap();
        let published = owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: UserCardStatus::Active,
                },
                &MutationPrecondition {
                    evaluated_root_version: u64::MAX - 1,
                },
            )
            .unwrap();
        assert_eq!(published.version, u64::MAX);
        assert!(matches!(
            owner.handle().begin_request(Uuid::new_v4()),
            Err(RootError::Unavailable(RootStatus::Invalid))
        ));
        assert!(matches!(
            owner.execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::ConfirmationBatch { rows: vec![] },
                &MutationPrecondition {
                    evaluated_root_version: u64::MAX,
                },
            ),
            Err(MutationError::VersionOverflow)
        ));
        assert_eq!(
            owner.runtime.current.load().metadata.status,
            RootStatus::Invalid
        );
    }

    #[test]
    // memory—v1: A dependency at MAX closes only the affected card or target.
    fn exhausted_dependencies_close_affected_scope() {
        let (mut input, mut selections) = serving_ready();
        input.users.push(UserRow { user_id: id(20) });
        input.identity_cards.push(IdentityCardRow {
            identity_card_id: id(21),
            user_id: id(20),
        });
        input.user_cards.push(UserCardRow {
            user_card_id: id(22),
            user_id: id(20),
            tenant_id: id(3),
            status: UserCardStatus::Active,
        });
        let mut other_set = input.rule_sets[0].clone();
        other_set.rule_set_id = id(23);
        input.rule_sets.push(other_set);
        let mut other_version = input.rule_set_versions[0].clone();
        other_version.rule_set_id = id(23);
        input.rule_set_versions.push(other_version);
        let mut other_binding = input.bindings[0].clone();
        other_binding.binding_id = id(24);
        other_binding.user_card_id = id(22);
        other_binding.rule_set_id = id(23);
        input.bindings.push(other_binding);
        let mut other_confirmation = input.binding_confirmations[0].clone();
        other_confirmation.confirmation_id = id(25);
        other_confirmation.binding_id = id(24);
        other_confirmation.rule_set_id = id(23);
        input.binding_confirmations.push(other_confirmation);
        let mut other_change = input.rule_set_change_confirmations[0].clone();
        other_change.confirmation_id = id(26);
        other_change.rule_set_id = id(23);
        input.rule_set_change_confirmations.push(other_change);
        selections.push(CurrentSelection {
            rule_set_id: id(23),
            version_bytes: vec![1],
        });
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(
            owner.handle().metadata().unwrap(),
        );
        owner.adopt_isolated_evidence(&evidence).unwrap();
        let original = owner.runtime.current.load_full();
        let authority = crate::memory_v1_session_authority::MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();

        for (card_exhausted, set_exhausted) in [(true, false), (false, true)] {
            let mut objects = original.objects.clone();
            if card_exhausted {
                objects.set_card_dependency_generation_for_test(id(4), u64::MAX);
            }
            if set_exhausted {
                objects.set_rule_set_dependency_generation_for_test(id(5), u64::MAX);
            }
            owner.runtime.current.store(Arc::new(RootSnapshot {
                metadata: original.metadata,
                objects,
                digest_index: original.digest_index.clone(),
                adoption: original.adoption.clone(),
            }));
            let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
            let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
            let record = |card_id| DependencyRecord {
                card_id,
                instance_id: reader.metadata().instance_id,
                bindings: vec![],
                tenant_tree_version,
                registry_version,
            };
            assert_eq!(reader.recheck_dependencies(&record(id(4))), Ok(false));
            assert_eq!(reader.recheck_dependencies(&record(id(22))), Ok(true));
            let identity = |user, identity_card, card| astral_types::memory_v1::CandidateIdentity {
                user_id: astral_types::memory_v1::MemoryId::from_bytes(id(user)),
                identity_card_id: astral_types::memory_v1::MemoryId::from_bytes(id(identity_card)),
                user_card_id: astral_types::memory_v1::MemoryId::from_bytes(id(card)),
                tenant_id: astral_types::memory_v1::MemoryId::from_bytes(id(3)),
            };
            let adapter = authority.identity_session_adapter();
            let affected_scope =
                crate::memory_v1_request::RequestRootScope::new(owner.handle(), Default::default());
            let unaffected_scope =
                crate::memory_v1_request::RequestRootScope::new(owner.handle(), Default::default());
            let now = i64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap();
            assert!(adapter
                .issue_verified_session_in_root(
                    &affected_scope.extension(),
                    identity(1, 2, 4),
                    now,
                    60,
                )
                .is_err());
            assert!(adapter
                .issue_verified_session_in_root(
                    &unaffected_scope.extension(),
                    identity(20, 21, 22),
                    now,
                    60,
                )
                .is_ok());
            if set_exhausted {
                assert_eq!(
                    reader.try_with_rechecked_dependencies_and_target(
                        &record(id(22)),
                        Some((reader.metadata(), &[id(5)])),
                        None,
                        || (),
                    ),
                    Ok(None)
                );
            }
        }
        owner.runtime.current.store(original);
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        owner
            .runtime
            .tenant_tree_version
            .store(u64::MAX, Ordering::Relaxed);
        assert_eq!(reader.recheck_dependencies(&record), Ok(false));
        assert_eq!(
            reader.dependency_versions(),
            Err(RootError::Unavailable(RootStatus::Invalid))
        );
    }

    #[test]
    // memory—v1: Same-generation fault injection cannot change a touched stored hash.
    fn dependency_recheck_compares_stored_hash_for_active_and_target_rules() {
        let (mut input, mut selections) = serving_ready();
        let mut other_set = input.rule_sets[0].clone();
        other_set.rule_set_id = id(9);
        input.rule_sets.push(other_set);
        let mut other_version = input.rule_set_versions[0].clone();
        other_version.rule_set_id = id(9);
        input.rule_set_versions.push(other_version);
        let mut other_change = input.rule_set_change_confirmations[0].clone();
        other_change.confirmation_id = id(11);
        other_change.rule_set_id = id(9);
        input.rule_set_change_confirmations.push(other_change);
        selections.push(CurrentSelection {
            rule_set_id: id(9),
            version_bytes: vec![1],
        });
        let owner = RootRegistry::new()
            .install_candidate(input.clone(), selections.clone(), budget())
            .unwrap();
        install_fixture_registry(&owner);
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(
            owner.handle().metadata().unwrap(),
        );
        owner.adopt_isolated_evidence(&evidence).unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
        // Public dependency records are not trusted as a complete list.
        let record = DependencyRecord {
            card_id: id(4),
            instance_id: reader.metadata().instance_id,
            bindings: vec![],
            tenant_tree_version,
            registry_version,
        };
        assert_eq!(reader.recheck_dependencies(&record), Ok(true));
        let original = owner.runtime.current.load_full();
        for (index, actor_result, target_result) in [(0, false, false), (1, true, false)] {
            let mut changed = input.clone();
            changed.rule_set_versions[index].hash_bytes[0] ^= 1;
            let objects = HamtCandidate::build(changed, selections.clone(), budget()).unwrap();
            assert_eq!(objects.rule_set_dependency_generation(id(5)), Some(0));
            assert_eq!(objects.rule_set_dependency_generation(id(9)), Some(0));
            let mut metadata = original.metadata;
            if index == 0 {
                metadata.version += 1;
            }
            owner.runtime.current.store(Arc::new(RootSnapshot {
                metadata,
                digest_index: fixture_digest_index(&objects),
                objects,
                adoption: original.adoption.clone(),
            }));
            assert_eq!(reader.recheck_dependencies(&record), Ok(actor_result));
            assert_eq!(
                reader
                    .try_with_rechecked_dependencies_and_target(
                        &record,
                        Some((reader.metadata(), &[id(9)])),
                        None,
                        || (),
                    )
                    .unwrap()
                    .is_some(),
                target_result
            );
        }
    }

    #[test]
    // memory—v1: One registry publishes one root and all handles read its graph.
    fn one_registry_shares_one_prebuilt_relationship_database() {
        let registry = RootRegistry::new();
        let owner = registry
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let first = owner.handle();
        let second = registry.handle().unwrap();
        let first_metadata = first.metadata().unwrap();
        assert_eq!(first_metadata.status, RootStatus::Candidate);
        assert_eq!(first_metadata.row_count, 7);
        let read = second
            .read_card(id(4), |context| {
                (
                    context.user.user_id,
                    context.identity.identity_card_id,
                    context.card.user_card_id,
                    context.tenant.tenant_id,
                    context.bindings.len(),
                )
            })
            .unwrap();
        assert_eq!(read.value, (id(1), id(2), id(4), id(3), 1));
        assert!(first.is_current(&read.observation).unwrap());
        assert_eq!(first.metadata().unwrap(), second.metadata().unwrap());
    }

    #[test]
    // memory—v1: Adoption requires exact instance, version and digest evidence.
    fn adoption_certificate_is_bound_to_one_candidate_snapshot() {
        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let metadata = owner.handle().metadata().unwrap();

        let wrong_instance = ServingAdoptionCertificate {
            instance_id: RootInstanceId(Uuid::new_v4()),
            version: metadata.version,
            digest: metadata.digest,
            source: AdoptionCertificateSource::Production,
        };
        assert_eq!(
            owner.adopt_serving(&wrong_instance),
            Err(RootError::AdoptionCertificateMismatch)
        );

        let wrong_version = ServingAdoptionCertificate {
            instance_id: metadata.instance_id,
            version: metadata.version + 1,
            digest: metadata.digest,
            source: AdoptionCertificateSource::Production,
        };
        assert_eq!(
            owner.adopt_serving(&wrong_version),
            Err(RootError::AdoptionCertificateMismatch)
        );

        let wrong_digest = ServingAdoptionCertificate {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: [0; 32],
            source: AdoptionCertificateSource::Production,
        };
        assert_eq!(
            owner.adopt_serving(&wrong_digest),
            Err(RootError::AdoptionCertificateMismatch)
        );

        let exact = ServingAdoptionCertificate {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
            source: AdoptionCertificateSource::Production,
        };
        assert!(matches!(
            owner.adopt_serving(&exact),
            Err(RootError::Candidate(_))
        ));
        assert_eq!(
            owner.handle().metadata().unwrap().status,
            RootStatus::Candidate
        );
    }

    #[test]
    // memory—v1: Every Serving certificate path rejects a row-pointer/selection
    // mismatch, while the diagnostic candidate remains installable.
    fn adoption_reconciles_explicit_current_pointers_before_serving() {
        use crate::memory_v1_rules::{canonical_version_bytes, version_digest};

        let build_malformed = |selection: Option<&[u8]>| {
            let (input, selections) = serving_ready();
            let owner = RootRegistry::new()
                .install_candidate(input, selections, budget())
                .unwrap();
            install_fixture_registry(&owner);
            let before = owner.runtime.current.load_full();
            let mut objects = before.objects.clone();
            if selection == Some(&[2][..]) {
                let mut historical = objects.version(id(5), &[1]).unwrap().clone();
                historical.version_bytes = vec![2];
                historical.timestamp_bytes = vec![2];
                historical.hash_input_bytes = canonical_version_bytes(
                    &historical.version_bytes,
                    &historical.content_bytes,
                    &historical.timestamp_bytes,
                );
                historical.hash_bytes = version_digest(&historical.hash_input_bytes);
                objects = objects.append_version(historical).unwrap();
            }
            objects = objects.with_selection(id(5), selection).unwrap();
            let malformed = Arc::new(RootSnapshot {
                metadata: before.metadata,
                digest_index: fixture_digest_index(&objects),
                objects,
                adoption: before.adoption.clone(),
            });
            owner.runtime.current.store(Arc::clone(&malformed));
            (owner, malformed)
        };

        let (owner, malformed) = build_malformed(Some(&[2]));
        let metadata = malformed.metadata;
        let isolated = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(metadata);
        assert_eq!(
            owner.adopt_isolated_evidence(&isolated),
            Err(RootError::Candidate(CandidateError::InconsistentBinding))
        );
        let exact = ServingAdoptionCertificate {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
            source: AdoptionCertificateSource::Production,
        };
        assert_eq!(
            owner.adopt_serving(&exact),
            Err(RootError::Candidate(CandidateError::InconsistentBinding))
        );
        assert_eq!(
            owner.handle().metadata().unwrap().status,
            RootStatus::Candidate
        );

        let (owner, malformed) = build_malformed(None);
        let metadata = malformed.metadata;
        let facts = ColdLoadFacts {
            schema_contract_version: crate::memory_v1_adoption::MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
            schema_fingerprint: [7; 32],
            snapshot_counts: malformed.objects.table_counts(),
            scanned_counts: malformed.objects.table_counts(),
            captured_at_unix_seconds: 1_700_000_000,
        };
        assert!(matches!(
            owner.adopt_experimental(&facts, &AdoptionLimit::EXPERIMENTAL),
            Err(RootError::AdoptionEvidence(
                crate::memory_v1_adoption::AdoptionEvidenceError::Missing(
                    "authoritative current selection"
                )
            ))
        ));
        assert_eq!(
            owner.handle().metadata().unwrap().status,
            RootStatus::Candidate
        );
        assert_eq!(metadata.status, RootStatus::Candidate);
    }
    #[test]
    // memory—v1: A serving snapshot cannot contain unregistered current rules.
    fn adoption_rechecks_registry_and_selected_history() {
        use crate::memory_v1_rules::{canonical_version_bytes, version_digest};

        for (content, expected) in [
            (
                br#"{"rules":[{"ruleId":"ok","resource":"document","action":"read","effect":"ALLOW"},{"ruleId":"bad","resource":"unknown","action":"read","effect":"ALLOW"}]}"#.as_slice(),
                RegistryError::Unregistered("unknown".to_owned()),
            ),
            (
                br#"{"rules":[{"ruleId":"bad","resource":"document","action":"write","effect":"ALLOW"}]}"#.as_slice(),
                RegistryError::UnknownAction("document".to_owned(), "write".to_owned()),
            ),
        ] {
            let (mut candidate, selections) = serving_ready();
            let row = &mut candidate.rule_set_versions[0];
            row.content_bytes = content.to_vec();
            row.hash_input_bytes = canonical_version_bytes(
                &row.version_bytes,
                &row.content_bytes,
                &row.timestamp_bytes,
            );
            row.hash_bytes = version_digest(&row.hash_input_bytes);
            let owner = RootRegistry::new()
                .install_candidate(candidate, selections, budget())
                .unwrap();
            let before = owner.handle().metadata().unwrap();
            let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(before);
            assert_eq!(
                owner.adopt_isolated_evidence(&evidence),
                Err(RootError::Registry(RegistryError::NotInstalled))
            );
            install_fixture_registry(&owner);
            assert_eq!(
                owner.adopt_isolated_evidence(&evidence),
                Err(RootError::Candidate(CandidateError::Registry(expected)))
            );
            assert_eq!(owner.handle().metadata().unwrap(), before);
        }

        let (candidate, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        owner.runtime.registry.request_retire("document").unwrap();
        let before = owner.handle().metadata().unwrap();
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(before);
        assert_eq!(
            owner.adopt_isolated_evidence(&evidence),
            Err(RootError::Candidate(CandidateError::Registry(
                RegistryError::Inactive(
                    "document".to_owned(),
                    crate::memory_v1_registry::RegistryStatus::RetireRequested
                )
            )))
        );
        assert_eq!(owner.handle().metadata().unwrap(), before);

        // Historical versions are archives and may reference retired resources;
        // only the explicitly selected version participates in this gate.
        let (mut candidate, selections) = serving_ready();
        let mut history = candidate.rule_set_versions[0].clone();
        history.version_bytes = vec![2];
        history.content_bytes = br#"{"rules":[{"ruleId":"archive","resource":"retired","action":"read","effect":"ALLOW"}]}"#.to_vec();
        history.hash_input_bytes = canonical_version_bytes(
            &history.version_bytes,
            &history.content_bytes,
            &history.timestamp_bytes,
        );
        history.hash_bytes = version_digest(&history.hash_input_bytes);
        candidate.rule_set_versions.push(history);
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let before = owner.handle().metadata().unwrap();
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(before);
        assert_eq!(
            owner.adopt_isolated_evidence(&evidence).unwrap().status,
            RootStatus::Serving
        );
    }

    #[test]
    // memory—v1: New rule versions cannot publish an unregistered pair.
    fn rule_version_publication_rechecks_registry_without_changing_root_on_failure() {
        use crate::memory_v1_rules::{canonical_version_bytes, version_digest};

        let (input, selections) = serving_ready();
        let mut version = input.rule_set_versions[0].clone();
        version.version_bytes = vec![2];
        version.content_bytes = br#"{"rules":[{"ruleId":"ok","resource":"document","action":"read","effect":"ALLOW"},{"ruleId":"bad","resource":"unknown","action":"read","effect":"DENY"}]}"#.to_vec();
        version.hash_input_bytes = canonical_version_bytes(
            &version.version_bytes,
            &version.content_bytes,
            &version.timestamp_bytes,
        );
        version.hash_bytes = version_digest(&version.hash_input_bytes);
        let mut confirmation = input.rule_set_change_confirmations[0].clone();
        confirmation.confirmation_id = id(20);
        confirmation.version_bytes = version.version_bytes.clone();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.handle().metadata().unwrap();
        let precondition = MutationPrecondition {
            evaluated_root_version: before.version,
        };
        let publish = ManagementMutationV2::VersionPublish {
            rule_set_id: id(5),
            version_row: version.clone(),
            new_current_version: version.version_bytes.clone(),
            change_confirmation: confirmation.clone(),
        };
        assert!(matches!(
            owner.execute_mutation_with_precondition(&publish, &precondition),
            Err(MutationError::Registry(RegistryError::NotInstalled))
        ));
        install_fixture_registry(&owner);
        assert!(matches!(
            owner.execute_mutation_with_precondition(&publish, &precondition),
            Err(MutationError::Registry(RegistryError::Unregistered(resource)))
                if resource == "unknown"
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);

        let mut rule_set = owner
            .runtime
            .current
            .load()
            .objects
            .rule_set(id(5))
            .unwrap()
            .clone();
        rule_set.rule_set_id = id(30);
        rule_set.current_version_bytes = version.version_bytes.clone();
        version.rule_set_id = rule_set.rule_set_id;
        confirmation.rule_set_id = rule_set.rule_set_id;
        let create = ManagementMutationV2::RuleSetCreate {
            rule_set,
            version,
            change_confirmation: confirmation,
        };
        assert!(matches!(
            owner.execute_mutation_with_precondition(&create, &precondition),
            Err(MutationError::Registry(RegistryError::Unregistered(resource)))
                if resource == "unknown"
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
        let current = owner.runtime.current.load_full();
        assert!(current.objects.version(id(5), &[2]).is_none());
        assert!(current.objects.rule_set(id(30)).is_none());
    }

    #[test]
    // memory—v1: Registry retirement cannot overtake a validated root publication.
    fn registry_read_guard_stays_held_through_root_publication() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (candidate, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let candidate = owner.runtime.current.load_full();
        let validated = ValidatedAdoptionSnapshot::validate(&candidate).unwrap();
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let root_guard = owner.runtime.mutation_lock.write().unwrap();
            let registry_guard = owner.runtime.registry.read_for_publication().unwrap();
            validated
                .snapshot()
                .objects
                .validate_current_registry(&registry_guard)
                .unwrap();
            let runtime = &owner.runtime;
            let worker = scope.spawn(move || {
                attempt_tx.send(()).unwrap();
                let result = runtime.registry.request_retire("document");
                done_tx.send(result).unwrap();
            });
            attempt_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
            let published = owner
                .publish_adopted_snapshot(&validated, test_record())
                .unwrap();
            assert_eq!(published.status, RootStatus::Serving);
            assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
            drop(registry_guard);
            drop(root_guard);
            assert_eq!(
                done_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                Ok(())
            );
            worker.join().unwrap();
        });
        assert!(matches!(
            owner.runtime.registry.validate("document", "read"),
            Err(RegistryError::Inactive(_, _))
        ));
    }

    #[test]
    // memory—v1: Neither acknowledged experimental evidence nor fabricated
    // test evidence may be promoted by the production adoption entrances.
    fn nonproduction_evidence_cannot_be_promoted() {
        let (candidate, selections) = serving_ready();
        let counts = candidate.table_counts();
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let before = owner.handle().metadata().unwrap();
        let evidence = AdoptionEvidence::from_cold_load(
            before,
            owner.runtime.current.load().objects.table_counts(),
            owner
                .runtime
                .current
                .load()
                .objects
                .has_valid_current_pointers(),
            &cold_facts(counts),
        );
        let experimental = evidence
            .verify_experimental(before, &AdoptionLimit::EXPERIMENTAL)
            .unwrap();
        assert_eq!(
            owner.adopt_serving(&experimental.certificate),
            Err(RootError::AdoptionCertificateMismatch)
        );
        assert_eq!(owner.handle().metadata().unwrap(), before);
        assert_eq!(owner.handle().adoption_record(), Ok(None));

        let fixture = AdoptionEvidence::complete_for_test(before);
        let test_verified = fixture.verify(before).unwrap();
        assert_eq!(
            owner.adopt_serving(&test_verified.certificate),
            Err(RootError::AdoptionCertificateMismatch)
        );
        assert_eq!(
            owner.adopt_with_evidence(&fixture),
            Err(RootError::AdoptionCertificateMismatch)
        );
        assert_eq!(owner.handle().metadata().unwrap(), before);
        assert_eq!(owner.handle().adoption_record(), Ok(None));

        let serving = owner
            .adopt_experimental(&cold_facts(counts), &AdoptionLimit::EXPERIMENTAL)
            .unwrap();
        assert_eq!(serving.status, RootStatus::Serving);
        assert_eq!(
            owner.handle().adoption_record().unwrap().unwrap().grade,
            AdoptionGrade::Experimental
        );
    }

    #[test]
    // memory—v1: Test-only evidence exercises adoption without exposing a production issuer.
    fn complete_test_evidence_adopts_one_snapshot_and_fences_old_reader() {
        let (candidate, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        let handle = owner.handle();
        assert_eq!(handle.adoption_record(), Ok(None));
        let old_reader = handle.begin_request(Uuid::new_v4()).unwrap();
        let before = old_reader.metadata();
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(before);
        install_fixture_registry(&owner);
        let serving = owner.adopt_isolated_evidence(&evidence).unwrap();

        assert_eq!(serving.status, RootStatus::Serving);
        assert_eq!(serving.instance_id, before.instance_id);
        assert_eq!(serving.version, before.version);
        assert_eq!(serving.digest, before.digest);
        assert_eq!(handle.metadata(), Ok(serving));
        assert_eq!(old_reader.is_current(), Ok(false));
        let new_reader = handle.begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(new_reader.metadata(), serving);
        #[cfg(feature = "test-support")]
        assert!(new_reader.confirmation_authority_available_for_evaluation());
        #[cfg(not(feature = "test-support"))]
        assert!(!new_reader.confirmation_authority_available_for_evaluation());
        assert_eq!(new_reader.is_current(), Ok(true));
        assert_eq!(
            new_reader.read_card(id(4), |context| context.bindings.len()),
            Ok(1)
        );
        let record = handle.adoption_record().unwrap().unwrap();
        assert_eq!(record.grade, AdoptionGrade::IsolatedTest);
        assert!(record.unverified.is_empty());
    }

    #[test]
    // memory—v1: The production report is read-only: it adopts nothing, names every unproven
    // family, and stops being readable together with its owner.
    fn production_report_is_read_only_and_names_unproven_families() {
        let (candidate, selections) = serving_ready();
        let counts = candidate.table_counts();
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        let handle = owner.handle();

        let unproven = owner.unproven_production_families(&cold_facts(counts));
        assert_eq!(unproven.len(), 10, "{unproven:?}");
        assert!(unproven.contains(&"eligibility"), "{unproven:?}");
        assert!(!unproven.contains(&"complete coverage"), "{unproven:?}");
        assert_eq!(handle.metadata().unwrap().status, RootStatus::Candidate);
        assert_eq!(handle.adoption_record(), Ok(None));

        drop(owner);
        assert_eq!(handle.metadata(), Err(RootError::OwnerGone));
    }

    #[test]
    // memory—v1: Experimental adoption publishes its acknowledged limits with the serving snapshot.
    fn experimental_adoption_publishes_record_with_serving_snapshot() {
        let (candidate, selections) = serving_ready();
        let counts = candidate.table_counts();
        assert_eq!(counts.total(), Some(9));
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        let handle = owner.handle();
        let old_reader = handle.begin_request(Uuid::new_v4()).unwrap();
        let before = old_reader.metadata();
        assert_eq!(before.row_count, 9);
        assert_eq!(handle.adoption_record(), Ok(None));
        install_fixture_registry(&owner);

        let serving = owner
            .adopt_experimental(&cold_facts(counts), &AdoptionLimit::EXPERIMENTAL)
            .unwrap();

        assert_eq!(serving.status, RootStatus::Serving);
        assert_eq!(serving.instance_id, before.instance_id);
        assert_eq!(serving.version, before.version);
        assert_eq!(serving.digest, before.digest);
        assert_eq!(old_reader.is_current(), Ok(false));
        assert!(!old_reader.confirmation_authority_available_for_evaluation());
        let record = handle.adoption_record().unwrap().unwrap();
        assert_eq!(record.grade, AdoptionGrade::Experimental);
        assert_eq!(record.unverified, AdoptionLimit::EXPERIMENTAL.to_vec());
        assert_eq!(record.schema_fingerprint, Some([7; 32]));
        assert_eq!(record.counts, Some(counts));
        assert_eq!(record.captured_at_unix_seconds, Some(1_700_000_000));
        let reader = handle.begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(reader.metadata(), serving);
        assert!(!reader.confirmation_authority_available_for_evaluation());
        assert_eq!(reader.read_card(id(4), |c| c.bindings.len()), Ok(1));

        // A second adoption never rewrites the record of a serving root.
        assert!(matches!(
            owner.adopt_experimental(&cold_facts(counts), &AdoptionLimit::EXPERIMENTAL),
            Err(RootError::AdoptionEvidence(
                crate::memory_v1_adoption::AdoptionEvidenceError::InvalidRootStatus
            ))
        ));
        assert_eq!(handle.adoption_record().unwrap().unwrap(), record);
    }

    // memory—v1: Seal every non-structural family with the matching fact.
    fn complete_production_input() -> crate::memory_v1_adoption::ProductionEvidenceInput {
        use crate::memory_v1_adoption::{AdoptionLimit, ProvenFamily};
        let sealed = ProvenFamily::proven_for;
        let mut input = crate::memory_v1_adoption::ProductionEvidenceInput::default();
        input
            .with_source_provenance(sealed(AdoptionLimit::SourceProvenance))
            .with_snapshot_identity(sealed(AdoptionLimit::SnapshotIdentity))
            .with_lifecycle_and_validity(sealed(AdoptionLimit::LifecycleAndValidity))
            .with_confirmation_authority(sealed(AdoptionLimit::ConfirmationAuthority))
            .with_resource_ownership(sealed(AdoptionLimit::ResourceOwnership))
            .with_eligibility(sealed(AdoptionLimit::Eligibility))
            .with_separation_of_duties(sealed(AdoptionLimit::SeparationOfDuties))
            .with_writer_coverage(sealed(AdoptionLimit::WriterCoverage))
            .with_audit_correlation(sealed(AdoptionLimit::AuditCorrelation))
            .with_persistence_recovery(sealed(AdoptionLimit::PersistenceRecovery))
            .with_trusted_time(1_700_000_000);
        input
    }

    #[test]
    // memory—v1: Complete sealed production evidence adopts the exact snapshot,
    // mints the capability from the winning CAS, and refuses any later adoption.
    fn production_adoption_mints_a_validated_capability() {
        let (candidate, selections) = serving_ready();
        let counts = candidate.table_counts();
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let handle = owner.handle();
        let before = handle.metadata().unwrap();

        let (serving, admission) = owner
            .adopt_with_production_evidence(&cold_facts(counts), &complete_production_input())
            .unwrap();
        assert_eq!(serving.status, RootStatus::Serving);
        assert_eq!(serving.instance_id, before.instance_id);
        assert_eq!(serving.version, before.version);
        assert_eq!(serving.digest, before.digest);
        // The capability validates against this exact root and refuses another.
        assert_eq!(
            handle.validate_production_admission(&admission),
            Ok(serving)
        );
        let record = handle.adoption_record().unwrap().unwrap();
        assert_eq!(record.grade, AdoptionGrade::Production);
        assert!(record.unverified.is_empty());
        let reader = handle.begin_request(Uuid::new_v4()).unwrap();
        assert!(reader.confirmation_authority_available_for_evaluation());

        // A second adoption attempt on a serving root fails closed.
        assert!(matches!(
            owner.adopt_with_production_evidence(&cold_facts(counts), &complete_production_input()),
            Err(RootError::AdoptionEvidence(
                crate::memory_v1_adoption::AdoptionEvidenceError::InvalidRootStatus
            ))
        ));
        assert_eq!(handle.adoption_record().unwrap().unwrap(), record);
    }

    #[test]
    // memory—v1: One missing or mismatched sealed family keeps the root a
    // candidate and names the exact gap; nothing is published.
    fn production_adoption_fails_closed_on_missing_family() {
        use crate::memory_v1_adoption::AdoptionEvidenceError;

        let (candidate, selections) = serving_ready();
        let counts = candidate.table_counts();
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        let handle = owner.handle();
        let before = handle.metadata().unwrap();

        // Drop exactly one sealed family (writer coverage).
        let mut partial = crate::memory_v1_adoption::ProductionEvidenceInput::default();
        partial
            .with_source_provenance(crate::memory_v1_adoption::ProvenFamily::proven_for(
                AdoptionLimit::SourceProvenance,
            ))
            .with_snapshot_identity(crate::memory_v1_adoption::ProvenFamily::proven_for(
                AdoptionLimit::SnapshotIdentity,
            ))
            .with_lifecycle_and_validity(crate::memory_v1_adoption::ProvenFamily::proven_for(
                AdoptionLimit::LifecycleAndValidity,
            ))
            .with_confirmation_authority(crate::memory_v1_adoption::ProvenFamily::proven_for(
                AdoptionLimit::ConfirmationAuthority,
            ))
            .with_resource_ownership(crate::memory_v1_adoption::ProvenFamily::proven_for(
                AdoptionLimit::ResourceOwnership,
            ))
            .with_eligibility(crate::memory_v1_adoption::ProvenFamily::proven_for(
                AdoptionLimit::Eligibility,
            ))
            .with_separation_of_duties(crate::memory_v1_adoption::ProvenFamily::proven_for(
                AdoptionLimit::SeparationOfDuties,
            ))
            .with_audit_correlation(crate::memory_v1_adoption::ProvenFamily::proven_for(
                AdoptionLimit::AuditCorrelation,
            ))
            .with_persistence_recovery(crate::memory_v1_adoption::ProvenFamily::proven_for(
                AdoptionLimit::PersistenceRecovery,
            ))
            .with_trusted_time(1_700_000_000);
        let result = owner.adopt_with_production_evidence(&cold_facts(counts), &partial);
        assert!(matches!(
            result,
            Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Missing(
                "writer coverage"
            )))
        ));
        // The root stays an unadopted candidate.
        assert_eq!(handle.metadata().unwrap(), before);
        assert_eq!(handle.adoption_record().unwrap(), None);

        // A fact bound to the wrong family is an unknown, not a proven value.
        let mut swapped = complete_production_input();
        swapped.with_writer_coverage(crate::memory_v1_adoption::ProvenFamily::proven_for(
            AdoptionLimit::Eligibility,
        ));
        assert!(matches!(
            owner.adopt_with_production_evidence(&cold_facts(counts), &swapped),
            Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Missing(
                "writer coverage"
            )))
        ));
        assert_eq!(handle.metadata().unwrap(), before);
        assert_eq!(handle.adoption_record().unwrap(), None);
    }

    #[test]
    // memory—v1: A limit nobody acknowledged by name keeps the root a non-serving candidate.
    fn experimental_adoption_requires_every_limit_acknowledged() {
        use crate::memory_v1_adoption::AdoptionEvidenceError;

        let (candidate, selections) = serving_ready();
        let counts = candidate.table_counts();
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        for omitted in AdoptionLimit::EXPERIMENTAL {
            let rest: Vec<_> = AdoptionLimit::EXPERIMENTAL
                .into_iter()
                .filter(|limit| *limit != omitted)
                .collect();
            assert!(
                matches!(
                    owner.adopt_experimental(&cold_facts(counts), &rest),
                    Err(RootError::AdoptionEvidence(
                        AdoptionEvidenceError::Unacknowledged(_)
                    ))
                ),
                "{omitted:?} must be acknowledged"
            );
        }
        assert!(matches!(
            owner.adopt_experimental(&cold_facts(counts), &[]),
            Err(RootError::AdoptionEvidence(
                AdoptionEvidenceError::Unacknowledged(_)
            ))
        ));
        let handle = owner.handle();
        assert_eq!(handle.metadata().unwrap().status, RootStatus::Candidate);
        assert_eq!(handle.adoption_record(), Ok(None));
    }

    #[test]
    // memory—v1: Counts the adapter reports are re-derived from the root's own rows, not trusted.
    fn experimental_adoption_rederives_coverage_from_root_rows() {
        use crate::memory_v1_adoption::AdoptionEvidenceError;

        let (candidate, selections) = serving_ready();
        let counts = candidate.table_counts();
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();

        let mut snapshot_drift = cold_facts(counts);
        snapshot_drift.snapshot_counts.users += 1;
        let mut scan_drift = cold_facts(counts);
        scan_drift.scanned_counts.bindings += 1;
        let mut forged = counts;
        forged.rule_sets += 1;
        let both_forged = ColdLoadFacts {
            snapshot_counts: forged,
            scanned_counts: forged,
            ..cold_facts(counts)
        };
        for facts in [snapshot_drift, scan_drift, both_forged] {
            assert_eq!(
                owner.adopt_experimental(&facts, &AdoptionLimit::EXPERIMENTAL),
                Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Missing(
                    "complete coverage"
                )))
            );
        }

        let mut no_schema = cold_facts(counts);
        no_schema.schema_fingerprint = [0; 32];
        assert_eq!(
            owner.adopt_experimental(&no_schema, &AdoptionLimit::EXPERIMENTAL),
            Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Missing(
                "schema manifest"
            )))
        );
        let mut before_epoch = cold_facts(counts);
        before_epoch.captured_at_unix_seconds = -1;
        assert_eq!(
            owner.adopt_experimental(&before_epoch, &AdoptionLimit::EXPERIMENTAL),
            Err(RootError::AdoptionEvidence(
                AdoptionEvidenceError::InvalidTrustedTime
            ))
        );
        let handle = owner.handle();
        assert_eq!(handle.metadata().unwrap().status, RootStatus::Candidate);
        assert_eq!(handle.adoption_record(), Ok(None));
    }

    #[test]
    // memory—v1: Historical versions are allowed only with an exact current pointer.
    fn experimental_adoption_checks_explicit_current_version() {
        use crate::memory_v1_adoption::AdoptionEvidenceError;
        use crate::memory_v1_db_rows::CurrentVersionPointerError;
        use crate::memory_v1_rules::{canonical_version_bytes, version_digest};

        let (mut candidate, selections) = serving_ready();
        let mut historical = candidate.rule_set_versions[0].clone();
        historical.version_bytes = vec![2];
        historical.hash_input_bytes = canonical_version_bytes(
            &historical.version_bytes,
            &historical.content_bytes,
            &historical.timestamp_bytes,
        );
        historical.hash_bytes = version_digest(&historical.hash_input_bytes);
        candidate.rule_set_versions.push(historical);
        assert_eq!(
            candidate.current_version_selections(),
            Ok(selections.clone())
        );
        let counts = candidate.table_counts();
        let owner = RootRegistry::new()
            .install_candidate(candidate.clone(), selections, budget())
            .unwrap();
        install_fixture_registry(&owner);
        assert_eq!(
            owner
                .adopt_experimental(&cold_facts(counts), &AdoptionLimit::EXPERIMENTAL)
                .unwrap()
                .status,
            RootStatus::Serving
        );

        candidate.rule_sets[0].current_version_bytes = vec![2];
        let owner = RootRegistry::new()
            .install_candidate(
                candidate.clone(),
                vec![CurrentSelection {
                    rule_set_id: id(5),
                    version_bytes: vec![1],
                }],
                budget(),
            )
            .unwrap();
        assert_eq!(
            owner.adopt_experimental(&cold_facts(counts), &AdoptionLimit::EXPERIMENTAL),
            Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Missing(
                "authoritative current selection"
            )))
        );
        assert_eq!(
            owner.handle().metadata().unwrap().status,
            RootStatus::Candidate
        );

        candidate.rule_sets[0].current_version_bytes.clear();
        assert_eq!(
            candidate.current_version_selections(),
            Err(CurrentVersionPointerError::EmptyCurrentVersionPointer { rule_set_id: id(5) })
        );
        candidate.rule_sets[0].current_version_bytes = vec![9];
        assert_eq!(
            candidate.current_version_selections(),
            Err(CurrentVersionPointerError::MissingCurrentVersion {
                rule_set_id: id(5),
                version_bytes: vec![9],
            })
        );
        candidate.rule_sets[0].current_version_bytes = vec![2];
        candidate.rule_set_versions[1].rule_set_id = id(9);
        assert_eq!(
            candidate.current_version_selections(),
            Err(CurrentVersionPointerError::CrossRuleSetCurrentVersion {
                rule_set_id: id(5),
                version_bytes: vec![2],
            })
        );
    }

    #[test]
    // memory—v1: A stale adoption cannot overwrite a newer root state.
    fn adoption_publication_rejects_changed_snapshot() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let candidate = owner.runtime.current.load_full();
        let validated = ValidatedAdoptionSnapshot::validate(&candidate).unwrap();
        let mut replacement_metadata = candidate.metadata;
        replacement_metadata.version += 1;
        replacement_metadata.status = RootStatus::Invalid;
        let replacement = Arc::new(RootSnapshot {
            metadata: replacement_metadata,
            objects: candidate.objects.clone(),
            digest_index: candidate.digest_index.clone(),
            adoption: None,
        });
        owner.runtime.current.store(Arc::clone(&replacement));

        assert_eq!(
            owner.publish_adopted_snapshot(&validated, test_record()),
            Err(RootError::AdoptionSnapshotChanged)
        );
        assert!(Arc::ptr_eq(
            &owner.runtime.current.load_full(),
            &replacement
        ));
        assert_eq!(owner.runtime.current.load().metadata, replacement_metadata);
    }

    #[test]
    // memory—v1: Equal metadata cannot substitute another snapshot for the validated Arc.
    fn adoption_publication_rejects_replacement_with_identical_metadata() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let candidate = owner.runtime.current.load_full();
        let validated = ValidatedAdoptionSnapshot::validate(&candidate).unwrap();
        let replacement = Arc::new(RootSnapshot {
            metadata: candidate.metadata,
            objects: candidate.objects.clone(),
            digest_index: candidate.digest_index.clone(),
            adoption: candidate.adoption.clone(),
        });
        owner.runtime.current.store(Arc::clone(&replacement));

        assert_eq!(
            owner.publish_adopted_snapshot(&validated, test_record()),
            Err(RootError::AdoptionSnapshotChanged)
        );
        assert!(Arc::ptr_eq(
            &owner.runtime.current.load_full(),
            &replacement
        ));
        assert_eq!(replacement.metadata, candidate.metadata);
        assert_eq!(replacement.metadata.status, RootStatus::Candidate);
    }

    #[test]
    // memory—v1: Idempotent adoption still requires the exact serving certificate.
    fn serving_root_rejects_foreign_adoption_certificate() {
        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let candidate = owner.runtime.current.load_full();
        let mut metadata = candidate.metadata;
        metadata.status = RootStatus::Serving;
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: candidate.objects.clone(),
            digest_index: candidate.digest_index.clone(),
            adoption: None,
        }));
        let foreign = ServingAdoptionCertificate {
            instance_id: RootInstanceId(Uuid::new_v4()),
            version: metadata.version,
            digest: metadata.digest,
            source: AdoptionCertificateSource::Production,
        };
        assert_eq!(
            owner.adopt_serving(&foreign),
            Err(RootError::AdoptionCertificateMismatch)
        );
        let exact = ServingAdoptionCertificate {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
            source: AdoptionCertificateSource::Production,
        };
        assert_eq!(owner.adopt_serving(&exact), Ok(metadata));
    }

    #[test]
    // memory—v1: Complete-evidence entry remains closed when any adoption fact is unknown.
    fn adoption_with_incomplete_evidence_keeps_candidate_non_serving() {
        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let metadata = owner.handle().metadata().unwrap();
        let evidence = crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(metadata)
            .with_unknown_coverage_for_test();
        assert!(matches!(
            owner.adopt_isolated_evidence(&evidence),
            Err(RootError::AdoptionEvidence(
                crate::memory_v1_adoption::AdoptionEvidenceError::Missing("complete coverage")
            ))
        ));
        assert_eq!(
            owner.handle().metadata().unwrap().status,
            RootStatus::Candidate
        );
    }

    #[test]
    // memory—v1: Extension clones capture one phase and never refresh on publication.
    fn request_extension_shares_lazy_phase_and_releases_on_scope_drop() {
        use crate::memory_v1_request::{RequestRootAccessError, RequestRootScope};

        fn require_extension_traits<T: Clone + Send + Sync + 'static>() {}
        require_extension_traits::<crate::memory_v1_request::RequestRootExtension>();

        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let request_id = Uuid::new_v4();
        let scope = RequestRootScope::new(owner.handle(), request_id);
        let first = scope.extension();
        let second = first.clone();
        let initial_snapshot = owner.runtime.current.load_full();
        assert_eq!(Arc::strong_count(&initial_snapshot), 2);
        let (reader_address, old_snapshot, initial) = first
            .with_reader(|reader| {
                assert_eq!(reader.request_id(), request_id);
                (
                    std::ptr::from_ref(reader) as usize,
                    Arc::downgrade(&reader.snapshot),
                    reader.metadata(),
                )
            })
            .unwrap();
        drop(initial_snapshot);

        let mut changed_rows = rows();
        changed_rows.bindings.clear();
        let digest = digest_candidate(&changed_rows, &[]).unwrap();
        let objects = HamtCandidate::build(changed_rows, vec![], budget()).unwrap();
        let (_, row_count) = objects.budget_and_row_count();
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata: RootMetadata {
                version: initial.version + 1,
                digest,
                row_count,
                ..initial
            },
            digest_index: fixture_digest_index(&objects),
            objects,
            adoption: None,
        }));
        second
            .with_reader(|reader| {
                assert_eq!(std::ptr::from_ref(reader) as usize, reader_address);
                assert_eq!(reader.metadata(), initial);
                assert_eq!(reader.read_card(id(4), |c| c.bindings.len()), Ok(1));
                assert_eq!(reader.is_current(), Ok(false));
                // Reentry must not deadlock and must observe the same reader.
                first
                    .with_reader(|nested| {
                        assert_eq!(std::ptr::from_ref(nested) as usize, reader_address);
                    })
                    .unwrap();
            })
            .unwrap();
        assert!(old_snapshot.upgrade().is_some());
        drop(scope);
        assert!(old_snapshot.upgrade().is_none());
        assert_eq!(
            first.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
        assert_eq!(
            second.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
    }

    #[test]
    // memory—v1: Concurrent extension clones initialize one reader for one request.
    fn request_extension_concurrent_first_access_shares_reader() {
        use crate::memory_v1_request::RequestRootScope;
        use std::sync::Barrier;
        use std::thread;

        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let extension = scope.extension();
        let ready = Barrier::new(9);
        let addresses = thread::scope(|threads| {
            let mut jobs = Vec::new();
            for _ in 0..8 {
                let extension = extension.clone();
                let ready = &ready;
                jobs.push(threads.spawn(move || {
                    ready.wait();
                    extension
                        .with_reader(|reader| std::ptr::from_ref(reader) as usize)
                        .unwrap()
                }));
            }
            ready.wait();
            jobs.into_iter()
                .map(|job| job.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(addresses.iter().all(|address| *address == addresses[0]));
    }

    #[test]
    // memory—v1: Dropping a pending request future revokes extensions and frees its old snapshot.
    fn request_extension_cancellation_drops_scope() {
        use crate::memory_v1_request::{RequestRootAccessError, RequestRootScope};
        use std::future::Future;
        use std::task::{Context, Poll, Waker};

        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let extension = scope.extension();
        let old_snapshot = extension
            .with_reader(|reader| Arc::downgrade(&reader.snapshot))
            .unwrap();
        let previous = owner.runtime.current.load_full();
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata: RootMetadata {
                version: previous.metadata.version + 1,
                ..previous.metadata
            },
            objects: previous.objects.clone(),
            digest_index: previous.digest_index.clone(),
            adoption: None,
        }));
        drop(previous);
        let mut request = Box::pin(async move {
            let _scope = scope;
            std::future::pending::<()>().await;
        });
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(request.as_mut().poll(&mut cx), Poll::Pending));
        assert!(old_snapshot.upgrade().is_some());
        drop(request);
        assert!(old_snapshot.upgrade().is_none());
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
    }

    #[test]
    // memory—v1: A callback admitted before cancellation finishes but cannot reenter.
    fn request_extension_inflight_callback_is_bounded_by_callback_lifetime() {
        use crate::memory_v1_request::{RequestRootAccessError, RequestRootScope};
        use std::sync::mpsc;
        use std::thread;

        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let extension = scope.extension();
        let worker_extension = extension.clone();
        let (started_tx, started_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            worker_extension
                .with_reader(|reader| {
                    started_tx.send(Arc::downgrade(&reader.snapshot)).unwrap();
                    resume_rx.recv().unwrap();
                    assert_eq!(
                        worker_extension.with_reader(|_| ()),
                        Err(RequestRootAccessError::ScopeEnded)
                    );
                })
                .unwrap();
        });
        let old_snapshot = started_rx.recv().unwrap();
        let previous = owner.runtime.current.load_full();
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata: RootMetadata {
                version: previous.metadata.version + 1,
                ..previous.metadata
            },
            objects: previous.objects.clone(),
            digest_index: previous.digest_index.clone(),
            adoption: None,
        }));
        drop(previous);
        drop(scope);
        assert!(old_snapshot.upgrade().is_some());
        assert_eq!(
            extension.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
        resume_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(old_snapshot.upgrade().is_none());
    }

    #[test]
    // memory—v1: A panic in caller code does not poison the initialization lock.
    fn request_extension_callback_panic_does_not_poison_context() {
        use crate::memory_v1_request::RequestRootScope;
        use std::panic::{catch_unwind, AssertUnwindSafe};

        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let extension = scope.extension();
        let original = extension.with_reader(|reader| reader.metadata()).unwrap();
        let failure = catch_unwind(AssertUnwindSafe(|| {
            let _ = extension.with_reader(|_| panic!("callback failure"));
        }));
        assert!(failure.is_err());
        assert_eq!(
            extension.with_reader(|reader| reader.metadata()),
            Ok(original)
        );
    }

    #[test]
    // memory—v1: A scope cannot keep a stopped owner readable or retain a retired phase.
    fn request_extension_fails_closed_after_owner_drop() {
        use crate::memory_v1_request::{RequestRootAccessError, RequestRootScope};

        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let extension = scope.extension();
        let old_snapshot = extension
            .with_reader(|reader| Arc::downgrade(&reader.snapshot))
            .unwrap();
        drop(owner);
        assert!(old_snapshot.upgrade().is_some());
        for _ in 0..2 {
            assert_eq!(
                extension.with_reader(|_| ()),
                Err(RequestRootAccessError::Root(RootError::OwnerGone))
            );
        }
        assert!(old_snapshot.upgrade().is_none());
    }

    #[test]
    // memory—v1: A context created before shutdown cannot lazily read a stopped owner.
    fn request_context_propagates_owner_failure_before_first_read() {
        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let mut context = RequestRootContext::new(owner.handle(), Uuid::new_v4());
        let runtime = Arc::clone(&owner.runtime);
        assert!(context.reader.is_none());
        drop(owner);
        assert!(matches!(
            context.reader(),
            Err(RootError::Unavailable(RootStatus::Stopped))
        ));
        assert!(context.reader.is_none());
        drop(runtime);
        assert!(matches!(context.reader(), Err(RootError::OwnerGone)));
        assert!(context.reader.is_none());
    }

    #[test]
    // memory—v1: A stopped owner retires the captured phase without refreshing it.
    fn request_context_releases_stopped_reader_and_never_recaptures() {
        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let handle = owner.handle();
        let runtime = Arc::clone(&owner.runtime);
        let mut context = RequestRootContext::new(handle.clone(), Uuid::new_v4());
        let (old_snapshot, initial) = {
            let reader = context.reader().unwrap();
            (Arc::downgrade(&reader.snapshot), reader.metadata())
        };
        drop(owner);
        assert!(old_snapshot.upgrade().is_some());
        assert!(matches!(
            context.reader(),
            Err(RootError::Unavailable(RootStatus::Stopped))
        ));
        assert!(context.reader.is_none());
        assert!(old_snapshot.upgrade().is_none());

        // Only this private fixture republishes after stop, to detect a recapture.
        let stopped = runtime.current.load_full();
        runtime.current.store(Arc::new(RootSnapshot {
            metadata: RootMetadata {
                version: initial.version + 1,
                status: RootStatus::Candidate,
                ..initial
            },
            objects: stopped.objects.clone(),
            digest_index: stopped.digest_index.clone(),
            adoption: None,
        }));
        drop(stopped);
        let fresh = handle.begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(fresh.metadata().version, initial.version + 1);
        drop(fresh);
        for _ in 0..2 {
            assert!(matches!(
                context.reader(),
                Err(RootError::Unavailable(RootStatus::Stopped))
            ));
            assert!(context.reader.is_none());
        }
        drop(runtime);
        assert!(matches!(
            context.reader(),
            Err(RootError::Unavailable(RootStatus::Stopped))
        ));
    }

    #[test]
    // memory—v1: A vanished owner also retires the captured phase permanently.
    fn request_context_releases_reader_when_owner_is_gone() {
        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let mut context = RequestRootContext::new(owner.handle(), Uuid::new_v4());
        let old_snapshot = Arc::downgrade(&context.reader().unwrap().snapshot);
        drop(owner);
        assert!(old_snapshot.upgrade().is_some());
        for _ in 0..2 {
            assert!(matches!(context.reader(), Err(RootError::OwnerGone)));
            assert!(context.reader.is_none());
            assert!(old_snapshot.upgrade().is_none());
        }
    }

    #[test]
    // memory—v1: Repeated context access shares one reader until the request drops it.
    fn request_context_reuses_reader_and_releases_snapshot() {
        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let request_id = Uuid::new_v4();
        let mut context = RequestRootContext::new(owner.handle(), request_id);
        assert!(context.reader.is_none());
        let (reader_ptr, old_snapshot, initial) = {
            let reader = context.reader().unwrap();
            assert_eq!(reader.request_id(), request_id);
            assert_eq!(reader.read_card(id(4), |c| c.bindings.len()).unwrap(), 1);
            (
                std::ptr::from_ref(reader),
                Arc::downgrade(&reader.snapshot),
                reader.metadata(),
            )
        };

        // Publish a different candidate only inside this private fixture.
        let mut changed_rows = rows();
        changed_rows.bindings.clear();
        let digest = digest_candidate(&changed_rows, &[]).unwrap();
        let objects = HamtCandidate::build(changed_rows, vec![], budget()).unwrap();
        let (_, row_count) = objects.budget_and_row_count();
        owner.runtime.current.store(Arc::new(RootSnapshot {
            metadata: RootMetadata {
                version: initial.version + 1,
                digest,
                row_count,
                ..initial
            },
            digest_index: fixture_digest_index(&objects),
            objects,
            adoption: None,
        }));

        let reader = context.reader().unwrap();
        assert_eq!(reader_ptr, std::ptr::from_ref(reader));
        assert!(Arc::ptr_eq(
            &reader.snapshot,
            &old_snapshot.upgrade().unwrap()
        ));
        assert_eq!(reader.metadata(), initial);
        assert_eq!(reader.read_card(id(4), |c| c.bindings.len()).unwrap(), 1);
        assert!(!reader.is_current().unwrap());
        assert!(old_snapshot.upgrade().is_some());
        drop(context);
        assert!(old_snapshot.upgrade().is_none());
    }

    #[test]
    // memory—v1: All modules borrowing one reader see the same phase after publication.
    fn request_reader_keeps_one_phase_across_concurrent_publication() {
        use std::sync::Barrier;
        use std::thread;

        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let handle = owner.handle();
        let request_id = Uuid::new_v4();
        let reader = handle.begin_request(request_id).unwrap();
        let old_snapshot = Arc::downgrade(&reader.snapshot);
        let initial = reader.metadata();
        let ready = Barrier::new(2);
        let published = Barrier::new(2);
        thread::scope(|scope| {
            scope.spawn(|| {
                ready.wait();
                let mut changed_rows = rows();
                changed_rows.bindings.clear();
                let digest = digest_candidate(&changed_rows, &[]).unwrap();
                let objects = HamtCandidate::build(changed_rows, vec![], budget()).unwrap();
                let (_, row_count) = objects.budget_and_row_count();
                owner.runtime.current.store(Arc::new(RootSnapshot {
                    metadata: RootMetadata {
                        version: initial.version + 1,
                        digest,
                        row_count,
                        ..initial
                    },
                    digest_index: fixture_digest_index(&objects),
                    objects,
                    adoption: None,
                }));
                published.wait();
            });
            assert_eq!(reader.request_id(), request_id);
            assert_eq!(reader.read_card(id(4), |c| c.bindings.len()).unwrap(), 1);
            ready.wait();
            published.wait();
            assert_eq!(reader.read_card(id(4), |c| c.bindings.len()).unwrap(), 1);
            assert!(reader.read_impact(id(5)).unwrap().card_ids.contains(&id(4)));
            assert_eq!(reader.metadata(), initial);
            assert!(!reader.is_current().unwrap());
            let next = handle.begin_request(Uuid::new_v4()).unwrap();
            assert_eq!(next.read_card(id(4), |c| c.bindings.len()).unwrap(), 0);
            assert!(!next.read_impact(id(5)).unwrap().card_ids.contains(&id(4)));
            assert!(next.is_current().unwrap());
            assert_ne!(next.metadata().digest, initial.digest);
        });
        assert!(old_snapshot.upgrade().is_some());
        drop(reader);
        assert!(old_snapshot.upgrade().is_none());
    }

    #[test]
    // memory—v1: A retained request snapshot cannot keep its root owner alive.
    fn request_reader_fails_after_owner_stops() {
        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
        let runtime = Arc::clone(&owner.runtime);
        drop(owner);
        assert_eq!(reader.is_current(), Ok(false));
        assert_eq!(
            reader.read_card(id(4), |_| ()),
            Err(RootError::Unavailable(RootStatus::Stopped))
        );
        drop(runtime);
        assert_eq!(reader.is_current(), Err(RootError::OwnerGone));
        assert_eq!(reader.read_card(id(4), |_| ()), Err(RootError::OwnerGone));
        assert_eq!(reader.read_impact(id(5)), Err(RootError::OwnerGone));
    }

    #[test]
    // memory—v1: An in-progress mutation finishes before the root stops.
    fn owner_stop_waits_for_the_inflight_mutation() {
        use std::sync::mpsc;

        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let runtime = Arc::clone(&owner.runtime);
        let before = runtime.current.load_full();
        let mut metadata = before.metadata;
        metadata.version += 1;
        let objects = before
            .objects
            .with_user_card_status(id(4), UserCardStatus::Disabled)
            .unwrap();
        metadata.digest = digest_candidate_from_candidate(&objects).unwrap();
        let updated = Arc::new(RootSnapshot {
            metadata,
            digest_index: fixture_digest_index(&objects),
            objects,
            adoption: before.adoption.clone(),
        });
        let (locked_tx, locked_rx) = mpsc::channel();
        let (publish_tx, publish_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let writer_runtime = Arc::clone(&runtime);
        let writer = std::thread::spawn(move || {
            let _guard = writer_runtime.mutation_lock.write().unwrap();
            locked_tx.send(()).unwrap();
            publish_rx.recv().unwrap();
            let previous = writer_runtime.current.compare_and_swap(&before, updated);
            assert!(Arc::ptr_eq(&previous, &before));
        });
        locked_rx.recv().unwrap();
        let stopping = std::thread::spawn(move || {
            drop(owner);
            finished_tx.send(()).unwrap();
        });
        assert!(matches!(
            finished_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        publish_tx.send(()).unwrap();
        writer.join().unwrap();
        stopping.join().unwrap();
        finished_rx.recv().unwrap();
        let stopped = runtime.current.load_full();
        assert_eq!(stopped.metadata.status, RootStatus::Stopped);
        assert_eq!(stopped.metadata.version, metadata.version);
        assert_eq!(
            stopped.objects.user_card(id(4)).unwrap().status,
            UserCardStatus::Disabled
        );
    }

    #[test]
    // memory—v1: Legacy plans remain source-compatible but cannot bypass admission.
    fn legacy_mutation_plan_refuses_without_publishing() {
        fn exhaustive(plan: &ManagementMutation) {
            match plan {
                ManagementMutation::BindingCreate {
                    row: _,
                    confirmation: _,
                }
                | ManagementMutation::BindingRemove {
                    binding_id: _,
                    removed_at: _,
                    removed_by: _,
                }
                | ManagementMutation::ConfirmationCreate { row: _ }
                | ManagementMutation::ConfirmationRevoke {
                    confirmation_id: _,
                    revoked_at: _,
                    revoked_by: _,
                }
                | ManagementMutation::UserCardStatus {
                    user_card_id: _,
                    status: _,
                }
                | ManagementMutation::RuleSetCreate {
                    rule_set: _,
                    version: _,
                }
                | ManagementMutation::VersionPublish {
                    rule_set_id: _,
                    version_row: _,
                    new_current_version: _,
                } => {}
            }
        }
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let before = owner.handle().metadata().unwrap();
        let plan = ManagementMutation::UserCardStatus {
            user_card_id: id(4),
            status: UserCardStatus::Disabled,
        };
        exhaustive(&plan);
        assert!(matches!(
            owner.execute_mutation(&plan),
            Err(MutationError::Candidate(
                CandidateError::InconsistentBinding
            ))
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
    }

    #[test]
    // memory—v1: Concurrent binding cannot share one authority across roots or
    // reserve the losing root, even when both candidates have identical facts.
    fn session_authority_binding_is_one_to_one_under_contention() {
        use crate::memory_v1_session_authority::{
            MemoryV1SessionAuthority, MemoryV1SessionAuthorityError,
        };
        use std::sync::Barrier;

        let first = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let second = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let authority = MemoryV1SessionAuthority::new();
        let replacement = MemoryV1SessionAuthority::new();
        let barrier = Barrier::new(3);
        let (first_result, second_result) = std::thread::scope(|threads| {
            let first_task = threads.spawn(|| {
                barrier.wait();
                authority.bind_to_root(&first)
            });
            let second_task = threads.spawn(|| {
                barrier.wait();
                authority.bind_to_root(&second)
            });
            barrier.wait();
            (first_task.join().unwrap(), second_task.join().unwrap())
        });
        assert_ne!(first_result.is_ok(), second_result.is_ok());
        let (winner, loser) = if first_result.is_ok() {
            (&first, &second)
        } else {
            (&second, &first)
        };
        assert_eq!(authority.bind_to_root(winner), Ok(()));
        assert_eq!(
            authority.bind_to_root(loser),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        );
        assert_eq!(replacement.bind_to_root(loser), Ok(()));
        assert_eq!(
            replacement.bind_to_root(winner),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        );
    }

    #[test]
    // memory—v1: A retained executor cannot publish after the owner stops.
    fn mutation_executor_refuses_after_owner_stops() {
        let (input, selections) = serving_ready();
        let owner = RootRegistry::new()
            .install_candidate(input, selections, budget())
            .unwrap();
        let executor = owner.mutation_executor();
        let runtime = Arc::clone(&owner.runtime);
        let before = owner.handle().metadata().unwrap();
        drop(owner);
        let stopped = runtime.current.load_full();
        assert_eq!(stopped.metadata.status, RootStatus::Stopped);
        assert_eq!(stopped.metadata.version, before.version);
        assert!(matches!(
            executor.execute(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: UserCardStatus::Disabled,
                },
                &MutationPrecondition {
                    evaluated_root_version: before.version,
                },
            ),
            Err(MutationError::Runtime(RuntimeError::OwnerGone))
        ));
        let after = runtime.current.load_full();
        assert!(Arc::ptr_eq(&stopped, &after));
        drop(after);
        drop(stopped);
        drop(runtime);
        assert!(matches!(
            executor.execute(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: UserCardStatus::Disabled,
                },
                &MutationPrecondition {
                    evaluated_root_version: before.version,
                },
            ),
            Err(MutationError::Runtime(RuntimeError::OwnerGone))
        ));
    }

    #[test]
    // memory—v1: A rejected cold candidate cannot claim the installation slot;
    // retry publishes the same digest as a direct build, exactly once.
    fn cold_preflight_precedes_digest_errors_and_preserves_root_slot() {
        use crate::memory_v1_digest::DigestError;

        let registry = RootRegistry::new();
        let invalid = CandidateRows {
            users: vec![UserRow { user_id: id(1) }, UserRow { user_id: id(1) }],
            ..CandidateRows::default()
        };
        let mut limits = CandidateBudget {
            max_table_rows: 1,
            max_bindings_per_read: 4,
        };
        assert!(matches!(
            digest_rows(&invalid, &[]),
            Err(RuntimeError::Digest(DigestError::DuplicateKey))
        ));
        assert!(matches!(
            registry.install_candidate(invalid.clone(), vec![], limits),
            Err(RootError::Candidate(CandidateError::RowBudgetExceeded {
                max: 1
            }))
        ));
        assert!(matches!(registry.handle(), Err(RootError::NotInstalled)));
        limits.max_table_rows = 2;
        assert!(matches!(
            registry.install_candidate(invalid, vec![], limits),
            Err(RootError::Runtime(RuntimeError::Digest(
                DigestError::DuplicateKey
            )))
        ));
        assert!(matches!(registry.handle(), Err(RootError::NotInstalled)));

        let valid = CandidateRows {
            users: vec![UserRow { user_id: id(1) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            }],
            ..CandidateRows::default()
        };
        let expected = digest_rows(&valid, &[]).unwrap().digest();
        let oversized_selection = vec![CurrentSelection {
            rule_set_id: id(3),
            version_bytes: vec![0; 256],
        }];
        assert!(matches!(
            digest_rows(&valid, &oversized_selection),
            Err(RuntimeError::Digest(DigestError::LimitExceeded))
        ));
        assert!(matches!(
            registry.install_candidate(
                valid.clone(),
                oversized_selection.clone(),
                CandidateBudget {
                    max_table_rows: 1,
                    ..limits
                }
            ),
            Err(RootError::Candidate(CandidateError::RowBudgetExceeded {
                max: 1
            }))
        ));
        assert!(matches!(
            registry.install_candidate(valid.clone(), oversized_selection, limits),
            Err(RootError::Runtime(RuntimeError::Digest(
                DigestError::LimitExceeded
            )))
        ));
        assert!(matches!(registry.handle(), Err(RootError::NotInstalled)));
        let owner = registry
            .install_candidate(valid.clone(), vec![], limits)
            .unwrap();
        let before = owner.runtime.current.load_full();
        assert_eq!(before.metadata.version, 0);
        assert_eq!(before.metadata.row_count, 2);
        assert_eq!(before.metadata.digest, expected);
        assert_eq!(before.metadata.budget, limits);
        assert!(matches!(
            registry.install_candidate(valid, vec![], limits),
            Err(RootError::AlreadyInstalled)
        ));
        assert!(Arc::ptr_eq(&before, &owner.runtime.current.load_full()));
        assert_eq!(
            registry.handle().unwrap().metadata().unwrap(),
            before.metadata
        );
    }

    #[test]
    // memory—v1: A second installation is rejected before another root is visible.
    fn duplicate_installation_is_rejected() {
        let registry = RootRegistry::new();
        registry
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        assert!(matches!(
            registry.install_candidate(rows(), vec![], budget()),
            Err(RootError::AlreadyInstalled)
        ));
    }

    #[test]
    // memory—v1: A consumer handle cannot keep a dropped composition owner alive.
    fn handle_does_not_extend_registry_lifetime() {
        let handle = {
            let registry = RootRegistry::new();
            let owner = registry
                .install_candidate(rows(), vec![], budget())
                .unwrap();
            owner.handle()
        };
        assert_eq!(handle.metadata(), Err(RootError::OwnerGone));
    }

    #[test]
    // memory—v1: Shared BASE stays shared while one card has an isolated OVERLAY.
    fn shared_base_and_card_overlay_are_indexed_in_one_root() {
        let rows = CandidateRows {
            users: vec![
                UserRow { user_id: id(1) },
                UserRow { user_id: id(2) },
                UserRow { user_id: id(3) },
            ],
            identity_cards: vec![
                IdentityCardRow {
                    identity_card_id: id(11),
                    user_id: id(1),
                },
                IdentityCardRow {
                    identity_card_id: id(12),
                    user_id: id(2),
                },
                IdentityCardRow {
                    identity_card_id: id(13),
                    user_id: id(3),
                },
            ],
            tenants: vec![TenantRow {
                tenant_id: id(20),
                parent_tenant_id: None,
            }],
            user_cards: vec![
                UserCardRow {
                    user_card_id: id(21),
                    user_id: id(1),
                    tenant_id: id(20),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(22),
                    user_id: id(2),
                    tenant_id: id(20),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(23),
                    user_id: id(3),
                    tenant_id: id(20),
                    status: UserCardStatus::Active,
                },
            ],
            rule_sets: vec![
                RuleSetRow {
                    rule_set_id: id(30),
                    owner_tenant_id: id(20),
                    current_version_bytes: Vec::new(),
                    status: crate::memory_v1_db_rows::RuleSetStatus::Active,
                },
                RuleSetRow {
                    rule_set_id: id(31),
                    owner_tenant_id: id(20),
                    current_version_bytes: Vec::new(),
                    status: crate::memory_v1_db_rows::RuleSetStatus::Active,
                },
            ],
            rule_set_versions: vec![
                RuleSetVersionRow {
                    rule_set_id: id(30),
                    version_bytes: vec![1],
                    content_bytes: vec![30],
                    timestamp_bytes: vec![1],
                    hash_input_bytes: vec![30],
                    hash_bytes: vec![30],
                },
                RuleSetVersionRow {
                    rule_set_id: id(31),
                    version_bytes: vec![1],
                    content_bytes: vec![31],
                    timestamp_bytes: vec![1],
                    hash_input_bytes: vec![31],
                    hash_bytes: vec![31],
                },
            ],
            bindings: vec![
                BindingRow {
                    binding_id: id(40),
                    user_card_id: id(21),
                    rule_set_id: id(30),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(41),
                    user_card_id: id(22),
                    rule_set_id: id(30),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(42),
                    user_card_id: id(23),
                    rule_set_id: id(30),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(43),
                    user_card_id: id(23),
                    rule_set_id: id(31),
                    binding_layer: BindingLayer::Overlay,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                },
            ],
            ..CandidateRows::default()
        };
        let owner = RootRegistry::new()
            .install_candidate(
                rows,
                vec![
                    CurrentSelection {
                        rule_set_id: id(30),
                        version_bytes: vec![1],
                    },
                    CurrentSelection {
                        rule_set_id: id(31),
                        version_bytes: vec![1],
                    },
                ],
                CandidateBudget {
                    max_table_rows: 64,
                    max_bindings_per_read: 4,
                },
            )
            .unwrap();
        let handle = owner.handle();

        let layers_for = |card_id| {
            handle
                .read_card(card_id, |context| {
                    context
                        .bindings
                        .iter()
                        .map(|binding| (binding.binding.rule_set_id, binding.binding.binding_layer))
                        .collect::<Vec<_>>()
                })
                .unwrap()
                .value
        };
        assert_eq!(layers_for(id(21)), vec![(id(30), BindingLayer::Base)]);
        assert_eq!(layers_for(id(22)), vec![(id(30), BindingLayer::Base)]);
        let mut special_layers = layers_for(id(23));
        special_layers.sort_by_key(|(rule_set_id, layer)| {
            (*rule_set_id, matches!(layer, BindingLayer::Overlay))
        });
        assert_eq!(
            special_layers,
            vec![
                (id(30), BindingLayer::Base),
                (id(31), BindingLayer::Overlay),
            ]
        );
    }

    #[test]
    // memory—v1: Different registries are isolated test scopes, not shared consumers.
    fn foreign_observation_is_rejected() {
        let first_registry = RootRegistry::new();
        let second_registry = RootRegistry::new();
        let first_owner = first_registry
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let first = first_owner.handle();
        let second_owner = second_registry
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let second = second_owner.handle();
        let observation = first
            .read_card(id(4), |context| context.card.user_card_id)
            .unwrap()
            .observation;
        assert_eq!(
            second.is_current(&observation),
            Err(RootError::ForeignOwner)
        );
    }
}
