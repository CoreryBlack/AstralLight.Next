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
use crate::memory_v1_db_rows::UserCardStatus;
use std::sync::{Arc, OnceLock, Weak};

use arc_swap::ArcSwap;
use thiserror::Error;
use uuid::Uuid;

use crate::memory_v1_adoption::{
    AdoptionEvidence, AdoptionGrade, AdoptionLimit, AdoptionRecord, ColdLoadFacts,
};
use crate::memory_v1_db_rows::{BinaryId, CandidateRows, CurrentSelection};
use crate::memory_v1_digest::ContentDigest;
use crate::memory_v1_fence::{FenceDeclaration, FenceError, FencePremise, FenceRegistry};
use crate::memory_v1_hamt::{
    CandidateBudget, CandidateError, HamtCandidate, RuleSetImpactCandidate,
};
use crate::memory_v1_hamt_runtime::{digest_candidate, RuntimeCardContext, RuntimeError};
use crate::memory_v1_registry::{RegistryDeclaration, RegistryError, RegistryState};

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
/// The final recheck compares exactly this set against the current snapshot —
/// no more, no less — so unrelated modifications no longer invalidate an
/// in-flight request while any touched object change does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyRecord {
    pub card_id: BinaryId,
    pub instance_id: RootInstanceId,
    pub bindings: Vec<EvaluationDependency>,
    pub tenant_tree_version: u64,
    pub registry_version: u64,
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

/// Opaque evidence that a complete memory—v1 adoption verifier approved one
/// exact candidate snapshot. No constructor exists while the current candidate
/// loader lacks complete coverage, provenance, lifecycle and authority proof.
pub struct ServingAdoptionCertificate {
    instance_id: RootInstanceId,
    version: u64,
    digest: ContentDigest,
}

impl ServingAdoptionCertificate {
    /// memory—v1: Construct only after the complete adoption verifier matched
    /// one exact candidate snapshot. This is crate-private by design.
    pub(crate) fn from_verified_snapshot(
        instance_id: RootInstanceId,
        version: u64,
        digest: ContentDigest,
    ) -> Self {
        Self {
            instance_id,
            version,
            digest,
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

struct RootSnapshot {
    metadata: RootMetadata,
    objects: HamtCandidate,
    // memory—v1: Set only by the adoption publication that made this snapshot
    // `Serving`, so a record can never describe another snapshot.
    adoption: Option<Arc<AdoptionRecord>>,
}

struct RootRuntime {
    current: ArcSwap<RootSnapshot>,
    // memory—v1 §4.9: the resource/action registry; every §4.9 state-machine
    // transition bumps its version, which participates in the §4.7 dependency set.
    registry: RegistryState,
    // memory—v1 §4.6: active modification fences keyed by rule set.
    fences: FenceRegistry,
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
    /// Candidate row relationships were not closed.
    #[error("memory-v1 candidate relationships are incomplete")]
    InconsistentCandidate,
    /// Adoption evidence was incomplete or did not match the candidate snapshot.
    #[error("memory-v1 adoption evidence rejected: {0}")]
    AdoptionEvidence(#[from] crate::memory_v1_adoption::AdoptionEvidenceError),
    /// A certificate was issued for another root snapshot.
    #[error("memory-v1 serving adoption certificate does not match the root")]
    AdoptionCertificateMismatch,
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
        let digest = digest_candidate(&rows, &selections).map_err(RootError::Runtime)?;
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
                adoption: None,
            }),
            registry: RegistryState::default(),
            fences: FenceRegistry::default(),
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
    /// memory—v1: Adopt only after a complete verifier binds all evidence to
    /// this exact candidate metadata and the structural serving checks pass.
    pub fn adopt_with_evidence(
        &self,
        evidence: &crate::memory_v1_adoption::AdoptionEvidence,
    ) -> Result<RootMetadata, RootError> {
        let current = self.runtime.current.load_full();
        let verified = evidence.verify(current.metadata)?;
        let record = verified.record(AdoptionGrade::Production, None, None);
        self.adopt_snapshot(&current, &verified.certificate, record)
    }

    /// memory—v1: Adopt only with an opaque certificate from the complete
    /// snapshot verifier. The current crate exposes no certificate constructor,
    /// so ordinary candidate roots remain Candidate/PENDING.
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
    /// re-derives what it can from the candidate it holds and refuses without
    /// waiver: the schema attestation, table coverage (snapshot `COUNT(*)`,
    /// ordered scan and the root's own rows must agree table by table), exactly
    /// one stored version per rule set, and a non-negative capture time. Every
    /// other fact family has no implemented contract and stays unverified; it is
    /// adopted only when the caller names that exact [`AdoptionLimit`] in
    /// `acknowledged`. The acknowledged limits are published in the
    /// [`AdoptionRecord`] together with the serving snapshot, in one
    /// compare-and-swap, and are readable through [`RootHandle::adoption_record`].
    pub fn adopt_experimental(
        &self,
        facts: &ColdLoadFacts,
        acknowledged: &[AdoptionLimit],
    ) -> Result<RootMetadata, RootError> {
        let current = self.runtime.current.load_full();
        let evidence = AdoptionEvidence::from_cold_load(
            current.metadata,
            current.objects.table_counts(),
            current.objects.has_single_version_per_rule_set(),
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
            current.objects.has_single_version_per_rule_set(),
            facts,
        )
        .unproven_families()
    }

    /// memory—v1: Adopt the current candidate as `Serving` for an isolated test
    /// composition only.
    ///
    /// Compiled exclusively with the `test-support` feature, which must be
    /// enabled only from `[dev-dependencies]` (absent from production builds
    /// under resolver 2). It supplies complete test evidence for the exact
    /// current snapshot and then runs the same snapshot-bound evidence check,
    /// structural serving validation and CAS publication as real adoption. It
    /// proves nothing about provenance, coverage or confirmer authority.
    #[cfg(feature = "test-support")]
    pub fn adopt_serving_for_isolated_tests(&self) -> Result<RootMetadata, RootError> {
        let current = self.runtime.current.load_full();
        let evidence =
            crate::memory_v1_adoption::AdoptionEvidence::complete_for_test(current.metadata);
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
        if certificate.instance_id != current.metadata.instance_id
            || certificate.version != current.metadata.version
            || certificate.digest != current.metadata.digest
        {
            return Err(RootError::AdoptionCertificateMismatch);
        }
        match current.metadata.status {
            RootStatus::Serving => return Ok(current.metadata),
            RootStatus::Candidate => {}
            status => return Err(RootError::Unavailable(status)),
        }
        current
            .objects
            .validate_for_serving()
            .map_err(RootError::Candidate)?;
        self.publish_adopted_snapshot(current, record)
    }

    // memory—v1: Publish only the exact snapshot that passed structural validation,
    // with the record of how it was adopted.
    fn publish_adopted_snapshot(
        &self,
        validated: &Arc<RootSnapshot>,
        record: AdoptionRecord,
    ) -> Result<RootMetadata, RootError> {
        let mut metadata = validated.metadata;
        metadata.status = RootStatus::Serving;
        let next = Arc::new(RootSnapshot {
            metadata,
            objects: validated.objects.clone(),
            adoption: Some(Arc::new(record)),
        });
        let previous = self.runtime.current.compare_and_swap(validated, next);
        if !Arc::ptr_eq(&previous, validated) {
            return Err(RootError::AdoptionSnapshotChanged);
        }
        Ok(metadata)
    }
    /// memory—v1 §4.9: install the aggregated registry declarations exactly
    /// once. Composition roots call this before any formal evaluation; an
    /// uninstalled registry makes every evaluation refuse deterministically.
    pub fn install_registry(
        &self,
        declarations: &[RegistryDeclaration],
    ) -> Result<(), RegistryError> {
        self.runtime.registry.install(declarations)
    }

    /// memory—v1 §4.9: the registry version participates in the §4.7 dependency set.
    pub fn registry_version(&self) -> u64 {
        self.runtime.registry.version()
    }

    /// memory—v1 §4.10: the tenant-tree version participates in the §4.7 dependency set.
    pub fn tenant_tree_version(&self) -> u64 {
        self.runtime.tenant_tree_version.load(Ordering::Relaxed)
    }

    /// memory—v1 §4.6: open a modification window after verifying the declared
    /// premises against the actual snapshot (same-object mutual exclusion).
    pub fn begin_modification_fence(
        &self,
        rule_set_id: BinaryId,
        declaration: &FenceDeclaration,
    ) -> Result<(), FenceError> {
        let current = self.runtime.current.load_full();
        let premise = FencePremise {
            root_version: current.metadata.version,
            digest: current.metadata.digest,
            selected_version: current
                .objects
                .selected_version(rule_set_id)
                .map_err(FenceError::Candidate)?
                .map(|row| row.version_bytes.clone()),
        };
        self.runtime
            .fences
            .begin(rule_set_id, declaration, &premise)
    }

    /// memory—v1 §4.6: close the modification window without publishing.
    pub fn abort_modification_fence(&self, rule_set_id: BinaryId) -> Result<(), FenceError> {
        self.runtime.fences.abort(rule_set_id)
    }
}

impl Drop for RootOwner {
    // memory—v1: Consumer handles become unavailable before a replacement root can exist.
    fn drop(&mut self) {
        let current = self.runtime.current.load_full();
        let mut metadata = current.metadata;
        metadata.status = RootStatus::Stopped;
        self.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: current.objects.clone(),
            adoption: current.adoption.clone(),
        }));
    }
}

impl RootHandle {
    fn runtime(&self) -> Result<Arc<RootRuntime>, RootError> {
        self.runtime.upgrade().ok_or(RootError::OwnerGone)
    }

    fn snapshot(&self) -> Result<Arc<RootSnapshot>, RootError> {
        let runtime = self.runtime()?;
        let snapshot = runtime.current.load_full();
        match snapshot.metadata.status {
            RootStatus::Candidate | RootStatus::Serving => Ok(snapshot),
            status => Err(RootError::Unavailable(status)),
        }
    }

    /// memory—v1: Load metadata from the current immutable root snapshot.
    pub fn metadata(&self) -> Result<RootMetadata, RootError> {
        Ok(self.snapshot()?.metadata)
    }

    /// memory—v1: How the current serving snapshot was adopted.
    ///
    /// `Ok(None)` for a candidate root and for a serving root published without a
    /// record. The record is part of the snapshot it describes, so it is never
    /// stale; it is a description of the adoption, not authorization evidence.
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

impl RequestRootReader {
    // memory—v1: Reject reads after the owner stops or the current root is invalid.
    fn ensure_readable(&self) -> Result<Arc<RootRuntime>, RequestRootFailure> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RequestRootFailure::OwnerGone)?;
        let status = runtime.current.load().metadata.status;
        match status {
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

    /// memory—v1 §4.9: verify the (resource, action) pair against the registry.
    ///
    /// Not installed, unregistered, inactive and unknown-action cases are all
    /// deterministic structural refusals for the formal engine.
    pub fn registry_check(&self, resource: &str, action: &str) -> Result<(), RegistryError> {
        // A gone owner makes the registry unavailable, which the formal engine
        // refuses deterministically like any other registry failure.
        let runtime = match self.observation.owner.upgrade() {
            Some(runtime) => runtime,
            None => return Err(RegistryError::NotInstalled),
        };
        runtime.registry.validate(resource, action)
    }

    /// memory—v1 §4.6: whether this rule set has an active modification fence;
    /// reads depending on a fenced object are refused immediately.
    pub fn is_fenced(&self, rule_set_id: BinaryId) -> Result<bool, RootError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        Ok(runtime.fences.is_active(rule_set_id))
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
        Ok((
            runtime.tenant_tree_version.load(Ordering::Relaxed),
            runtime.registry.version(),
        ))
    }

    /// memory—v1 §4.7: recheck exactly the registered dependency set — the
    /// bindings and versions this evaluation read, the tenant tree shape and
    /// the registry version — without requiring the global root version to be
    /// unchanged. Unrelated modifications no longer invalidate this request.
    pub fn recheck_dependencies(&self, record: &DependencyRecord) -> Result<bool, RootError> {
        let runtime = self
            .observation
            .owner
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        let current = runtime.current.load_full();
        if current.metadata.instance_id != record.instance_id {
            return Ok(false);
        }
        if current.metadata.status != RootStatus::Serving {
            return Ok(false);
        }
        if runtime.tenant_tree_version.load(Ordering::Relaxed) != record.tenant_tree_version {
            return Ok(false);
        }
        if runtime.registry.version() != record.registry_version {
            return Ok(false);
        }
        for dependency in &record.bindings {
            let Some(binding) = current
                .objects
                .binding(dependency.binding_id)
                .map_err(RootError::Candidate)?
            else {
                return Ok(false);
            };
            if binding.user_card_id != record.card_id
                || binding.rule_set_id != dependency.rule_set_id
            {
                return Ok(false);
            }
            let Some(selected) = current
                .objects
                .selected_version(dependency.rule_set_id)
                .map_err(RootError::Candidate)?
            else {
                return Ok(false);
            };
            if selected.version_bytes != dependency.version_bytes {
                return Ok(false);
            }
        }
        Ok(true)
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
        let snapshot = &self.snapshot;
        let card = snapshot
            .objects
            .card_candidate(card_id)
            .map_err(RootError::Candidate)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, IdentityCardRow, RuleSetRow,
        RuleSetVersionRow, TenantRow, UserCardRow, UserRow,
    };
    use crate::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};

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
                current_version_bytes: Vec::new(),            }],
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
                removed_by: None,            }],
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
                revoked_by: None,            });
        let selections = vec![CurrentSelection {
            rule_set_id: id(5),
            version_bytes: vec![1],
        }];
        (candidate, selections)
    }

    // memory—v1: Cold-load facts that agree with `counts` in every table.
    fn cold_facts(counts: crate::memory_v1_db_rows::TableCounts) -> ColdLoadFacts {
        ColdLoadFacts {
            schema_contract_version: 1,
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
        };
        assert_eq!(
            owner.adopt_serving(&wrong_instance),
            Err(RootError::AdoptionCertificateMismatch)
        );

        let wrong_version = ServingAdoptionCertificate {
            instance_id: metadata.instance_id,
            version: metadata.version + 1,
            digest: metadata.digest,
        };
        assert_eq!(
            owner.adopt_serving(&wrong_version),
            Err(RootError::AdoptionCertificateMismatch)
        );

        let wrong_digest = ServingAdoptionCertificate {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: [0; 32],
        };
        assert_eq!(
            owner.adopt_serving(&wrong_digest),
            Err(RootError::AdoptionCertificateMismatch)
        );

        let exact = ServingAdoptionCertificate {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
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
        let serving = owner.adopt_with_evidence(&evidence).unwrap();

        assert_eq!(serving.status, RootStatus::Serving);
        assert_eq!(serving.instance_id, before.instance_id);
        assert_eq!(serving.version, before.version);
        assert_eq!(serving.digest, before.digest);
        assert_eq!(handle.metadata(), Ok(serving));
        assert_eq!(old_reader.is_current(), Ok(false));
        let new_reader = handle.begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(new_reader.metadata(), serving);
        assert_eq!(new_reader.is_current(), Ok(true));
        assert_eq!(
            new_reader.read_card(id(4), |context| context.bindings.len()),
            Ok(1)
        );
        let record = handle.adoption_record().unwrap().unwrap();
        assert_eq!(record.grade, AdoptionGrade::Production);
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
        assert_eq!(counts.total(), Some(8));
        let owner = RootRegistry::new()
            .install_candidate(candidate, selections, budget())
            .unwrap();
        let handle = owner.handle();
        let old_reader = handle.begin_request(Uuid::new_v4()).unwrap();
        let before = old_reader.metadata();
        assert_eq!(before.row_count, 8);
        assert_eq!(handle.adoption_record(), Ok(None));

        let serving = owner
            .adopt_experimental(&cold_facts(counts), &AdoptionLimit::EXPERIMENTAL)
            .unwrap();

        assert_eq!(serving.status, RootStatus::Serving);
        assert_eq!(serving.instance_id, before.instance_id);
        assert_eq!(serving.version, before.version);
        assert_eq!(serving.digest, before.digest);
        assert_eq!(old_reader.is_current(), Ok(false));
        let record = handle.adoption_record().unwrap().unwrap();
        assert_eq!(record.grade, AdoptionGrade::Experimental);
        assert_eq!(record.unverified, AdoptionLimit::EXPERIMENTAL.to_vec());
        assert_eq!(record.schema_fingerprint, Some([7; 32]));
        assert_eq!(record.counts, Some(counts));
        assert_eq!(record.captured_at_unix_seconds, Some(1_700_000_000));
        let reader = handle.begin_request(Uuid::new_v4()).unwrap();
        assert_eq!(reader.metadata(), serving);
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
    // memory—v1: Two stored versions for one rule set are never resolved by guessing.
    fn experimental_adoption_refuses_ambiguous_or_missing_current_version() {
        use crate::memory_v1_adoption::AdoptionEvidenceError;
        use crate::memory_v1_db_rows::SelectionError;

        let (mut ambiguous, selections) = serving_ready();
        let mut second = ambiguous.rule_set_versions[0].clone();
        second.version_bytes = vec![2];
        ambiguous.rule_set_versions.push(second);
        assert_eq!(
            ambiguous.single_version_selections(),
            Err(SelectionError::AmbiguousVersions { rule_set_id: id(5) })
        );
        let counts = ambiguous.table_counts();
        let owner = RootRegistry::new()
            .install_candidate(ambiguous, selections, budget())
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

        let (mut none, _) = serving_ready();
        none.rule_set_versions.clear();
        assert_eq!(
            none.single_version_selections(),
            Err(SelectionError::NoVersion { rule_set_id: id(5) })
        );
    }

    #[test]
    // memory—v1: A stale adoption cannot overwrite a newer root state.
    fn adoption_publication_rejects_changed_snapshot() {
        let owner = RootRegistry::new()
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let validated = owner.runtime.current.load_full();
        let mut replacement_metadata = validated.metadata;
        replacement_metadata.version += 1;
        replacement_metadata.status = RootStatus::Invalid;
        let replacement = Arc::new(RootSnapshot {
            metadata: replacement_metadata,
            objects: validated.objects.clone(),
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
            adoption: None,
        }));
        let foreign = ServingAdoptionCertificate {
            instance_id: RootInstanceId(Uuid::new_v4()),
            version: metadata.version,
            digest: metadata.digest,
        };
        assert_eq!(
            owner.adopt_serving(&foreign),
            Err(RootError::AdoptionCertificateMismatch)
        );
        let exact = ServingAdoptionCertificate {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
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
            owner.adopt_with_evidence(&evidence),
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
                    current_version_bytes: Vec::new(),                },
                RuleSetRow {
                    rule_set_id: id(31),
                    owner_tenant_id: id(20),
                    current_version_bytes: Vec::new(),                },
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
                    removed_by: None,                },
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
                    removed_by: None,                },
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
                    removed_by: None,                },
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
                    removed_by: None,                },
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
