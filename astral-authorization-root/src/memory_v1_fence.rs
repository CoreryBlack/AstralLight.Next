//! memory—v1 §4.6: The generation fence over BASE/OVERLAY modification windows.
//!
//! While a rule set is being modified, the fence holds the declared premises
//! (observed rule-set version, root version and digest). A second modification
//! of the same object is rejected for the whole window, and reads that depend
//! on the object are refused immediately (§4.6 "立即 PENDING") instead of
//! queueing. Publication happens only when the declared premises still match
//! the actual snapshot; otherwise the window closes with zero side effects.
//! Correctness is carried by the atomic snapshot, the CAS publication and the
//! §4.7 dependency recheck — the fence adds explicit mutual exclusion and the
//! fail-closed refusal, never a request/writer shared gate.
//!
//! The owner/token API in this file is an in-process capability. It is not an
//! authenticated identity and is not a substitute for an operation id or an
//! audit correlation. The legacy `begin`/`abort` pair remains only as a
//! compatibility surface until its root caller is migrated.

use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

use arc_swap::ArcSwap;
use im::HashMap;
use thiserror::Error;

use crate::memory_v1_db_rows::BinaryId;
use crate::memory_v1_digest::ContentDigest;

/// The declaration captured when a modification window opens (§4.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FenceDeclaration {
    /// The rule-set version the modifier observed.
    pub rule_set_version: Vec<u8>,
    /// The root global version the modifier observed.
    pub root_version: u64,
    /// The root digest the modifier observed.
    pub digest: ContentDigest,
}

/// A process-local, monotonically increasing generation observation.
///
/// The zero value is the initial observation before a fence has ever been
/// opened. A revision is allocated while the registry table is locked and is
/// never reused within that registry. The value is deliberately opaque; it is
/// not an external identity or an authorization proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FenceRevision(u128);

impl FenceRevision {
    /// Return the process-local generation number for diagnostics and read
    /// observations. This is not an external identity or authorization proof.
    /// memory—v1
    pub const fn value(self) -> u128 {
        self.0
    }
}

/// A read-side observation of one rule set's modification window.
#[derive(Clone, Debug)]
pub struct FenceObservation {
    registry: Arc<RegistryMarker>,
    rule_set_id: BinaryId,
    revision: FenceRevision,
    active: bool,
}

impl FenceObservation {
    /// memory—v1: return the observed rule-set identifier.
    pub fn rule_set_id(&self) -> BinaryId {
        self.rule_set_id
    }

    /// memory—v1: return the observed registry revision.
    pub fn revision(&self) -> FenceRevision {
        self.revision
    }

    /// memory—v1: return whether the observed rule set is fenced.
    pub fn active(&self) -> bool {
        self.active
    }

    /// Whether a read that bracketed its work with these observations saw a
    /// stable, unfenced window. A transient begin/abort is detected because
    /// the monotonic revision remains recorded after release.
    /// memory—v1
    pub fn is_stable_with(&self, after: &Self) -> bool {
        Arc::ptr_eq(&self.registry, &after.registry)
            && self.rule_set_id == after.rule_set_id
            && self.revision == after.revision
            && !self.active
            && !after.active
    }
}

/// A process-local owner capability for a modification window.
///
/// The fields are intentionally private: an owner can only be minted by the
/// registry it belongs to, and an owner from another registry is rejected.
/// This is an in-process capability, not an authenticated identity or an
/// externally stable operation identifier.
pub struct FenceOwner {
    registry: std::sync::Weak<FenceState>,
    marker: Arc<OwnerMarker>,
}

impl Clone for FenceOwner {
    // memory—v1: retain the same registry and owner capability.
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            marker: Arc::clone(&self.marker),
        }
    }
}

/// An opaque generation token for one rule-set modification window.
///
/// Tokens are minted by [`FenceRegistry::begin_owned`] and cannot be
/// constructed by callers. Cloning a token is deliberate: it permits a
/// controlled owner to pass the same capability to a cleanup path, while the
/// owner and token are still checked together before release.
#[derive(Clone, Debug)]
pub struct FenceToken {
    registry: Arc<RegistryMarker>,
    revision: FenceRevision,
}

impl PartialEq for FenceToken {
    // memory—v1: equal generations from different registries are distinct.
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.registry, &other.registry) && self.revision == other.revision
    }
}

impl Eq for FenceToken {}

impl Hash for FenceToken {
    // memory—v1: registry identity and revision match the equality contract.
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.registry).hash(state);
        self.revision.hash(state);
    }
}

impl FenceToken {
    // memory—v1: expose the registry-local generation for read observations.
    fn revision(&self) -> FenceRevision {
        self.revision
    }
}

/// An owned modification window.
///
/// The guard is not cloneable. Dropping it attempts a conditional release
/// using both its owner marker and generation token; a stale guard can never
/// remove a newer window for the same rule set.
pub struct FenceGuard {
    registry: std::sync::Weak<FenceState>,
    rule_set_id: BinaryId,
    owner: Arc<OwnerMarker>,
    token: FenceToken,
    released: bool,
}

impl FenceGuard {
    /// Return a copy of this window's opaque token for an explicit cleanup
    /// path owned by the same caller.
    /// memory—v1
    pub fn token(&self) -> FenceToken {
        self.token.clone()
    }

    /// Return this window's non-reused revision.
    /// memory—v1
    pub fn revision(&self) -> FenceRevision {
        self.token.revision()
    }

    /// Release this exact owner/token pair.
    /// memory—v1
    pub fn release(&mut self) -> Result<(), FenceControlError> {
        if self.released {
            return Err(FenceControlError::Fence(FenceError::NotFenced(
                self.rule_set_id,
            )));
        }
        let Some(registry) = self.registry.upgrade() else {
            self.released = true;
            return Err(FenceControlError::OwnerGone);
        };
        let result = release_owned_locked(&registry, self.rule_set_id, &self.owner, &self.token);
        if !matches!(result, Err(FenceControlError::Poisoned)) {
            // These outcomes prove that this guard cannot safely release any
            // currently active window. Keep Drop idempotent.
            self.released = true;
        }
        result
    }
}

impl Drop for FenceGuard {
    // memory—v1: conditionally release the exact owned generation on drop.
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Some(registry) = self.registry.upgrade() {
            let _ = release_owned_locked(&registry, self.rule_set_id, &self.owner, &self.token);
        }
        // Drop cannot report a poisoned lock. The registry remains fail-closed
        // in that state, and the conditional match above prevents stale
        // cleanup from touching another generation.
    }
}

/// An active fence with its declared premises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModificationFence {
    pub declaration: FenceDeclaration,
}

#[derive(Debug)]
struct RegistryMarker;

#[derive(Debug)]
struct OwnerMarker;

#[derive(Clone)]
struct ActiveFence {
    owner: Arc<OwnerMarker>,
    token: FenceToken,
}

/// Fence operation failures retained for existing callers.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FenceError {
    #[error("rule set {0:?} already has an active modification fence")]
    AlreadyFenced(BinaryId),
    #[error("rule set {0:?} has no active modification fence")]
    NotFenced(BinaryId),
    #[error("declared rule-set version does not match the current selection")]
    RuleSetVersionMismatch {
        declared: Vec<u8>,
        actual: Option<Vec<u8>>,
    },
    #[error("declared root version/digest does not match the current snapshot")]
    RootMismatch {
        declared_root_version: u64,
        actual_root_version: u64,
    },
    #[error("candidate lookup failed while checking fence premises: {0:?}")]
    Candidate(crate::memory_v1_hamt::CandidateError),
}

/// Errors for the owner/token API and for states that the legacy error enum
/// cannot faithfully represent.
///
/// `FenceError` intentionally remains the exact HEAD shape for compatibility.
/// New callers must handle this separate type so poison, owner mismatch,
/// capacity and token exhaustion cannot be mistaken for `NotFenced` or a
/// candidate validation failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FenceControlError {
    #[error("fence operation premise failed: {0}")]
    Fence(#[from] FenceError),
    #[error("root or fence registry lock is poisoned")]
    Poisoned,
    #[error("fence owner does not belong to this registry")]
    ForeignOwner,
    #[error("fence owner was dropped with its registry")]
    OwnerGone,
    #[error("rule set {0:?} is fenced by another owner")]
    OwnerMismatch(BinaryId),
    #[error("rule set {0:?} has a different active fence token")]
    TokenMismatch(BinaryId),
    #[error("fence token/revision space is exhausted")]
    TokenExhausted,
    #[error("active fence capacity {limit} has been reached")]
    CapacityExceeded { limit: usize },
}

/// memory—v1: A fence observation cannot establish the registry's health.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FenceReadError {
    /// A panic poisoned the fence writer.
    Poisoned,
}

/// The actual snapshot premise a declaration is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FencePremise {
    pub root_version: u64,
    pub digest: ContentDigest,
    pub selected_version: Option<Vec<u8>>,
}

/// The active modification fences keyed by rule set (§4.6).
pub struct FenceRegistry {
    state: Arc<FenceState>,
}

/// A conservative bound for live fences. A caller that needs more concurrent
/// fences must choose a larger bound as part of the root capacity contract.
const MAX_ACTIVE_FENCES: usize = 4096;
// Bound caller-supplied dependency lists before processing a final check.
pub(crate) const MAX_FENCE_CHECK_OBJECTS: usize = 4096;
// The standalone registry accepts arbitrary IDs. Retaining at most this many
// inactive object generations bounds memory independently of ID churn. Existing
// rule sets fit within the root digest key limit, but churn through new IDs can
// still evict proof; an overlapping check then conservatively returns PENDING.
const MAX_INACTIVE_FENCE_HISTORY: usize = 4096;

#[derive(Clone)]
struct FenceTable {
    active: HashMap<BinaryId, ActiveFence>,
    /// The most recent opening for each retained object, including active ones.
    object_revisions: HashMap<BinaryId, FenceRevision>,
    /// Inactive objects ordered by their latest opening; at most one per ID.
    inactive_revisions: im::OrdMap<FenceRevision, BinaryId>,
    /// Openings no newer than this may have been forgotten. A check that
    /// started before the floor fails closed instead of guessing about them.
    history_floor: FenceRevision,
    /// Registry-wide epoch retains the conservative observation contract.
    revision: FenceRevision,
}

impl FenceTable {
    // memory—v1: initialize an empty table at the initial revision.
    fn new() -> Self {
        Self {
            active: HashMap::new(),
            object_revisions: HashMap::new(),
            inactive_revisions: im::OrdMap::new(),
            history_floor: FenceRevision(0),
            revision: FenceRevision(0),
        }
    }

    // memory—v1: Retain the latest opening for this object without keeping
    // duplicate history when the same object is opened repeatedly.
    fn record_open(&mut self, rule_set_id: BinaryId, revision: FenceRevision) {
        if let Some(previous) = self.object_revisions.insert(rule_set_id, revision) {
            self.inactive_revisions.remove(&previous);
        }
    }

    // memory—v1: Eviction advances a monotonic proof floor. Readers that began
    // earlier must retry, even when the evicted ID was unrelated to them.
    fn record_release(&mut self, rule_set_id: BinaryId, revision: FenceRevision) {
        self.inactive_revisions.insert(revision, rule_set_id);
        if self.inactive_revisions.len() > MAX_INACTIVE_FENCE_HISTORY {
            if let Some(&(old_revision, old_id)) = self.inactive_revisions.get_min() {
                self.inactive_revisions.remove(&old_revision);
                self.object_revisions.remove(&old_id);
                self.history_floor = self.history_floor.max(old_revision);
            }
        }
    }
}

struct FenceState {
    marker: Arc<RegistryMarker>,
    // The writer serializes complete immutable publications; readers never
    // wait for this lock and inspect one published snapshot instead.
    writer: RwLock<()>,
    table: ArcSwap<FenceTable>,
    legacy_owner: Arc<OwnerMarker>,
}

impl FenceState {
    // memory—v1: initialize registry identity, empty snapshot, and legacy owner.
    fn new() -> Self {
        Self {
            marker: Arc::new(RegistryMarker),
            writer: RwLock::new(()),
            table: ArcSwap::from_pointee(FenceTable::new()),
            legacy_owner: Arc::new(OwnerMarker),
        }
    }
}

impl Default for FenceRegistry {
    // memory—v1: create a registry with its own fence state.
    fn default() -> Self {
        Self {
            state: Arc::new(FenceState::new()),
        }
    }
}

impl FenceRegistry {
    /// Mint an owner capability scoped to this registry.
    /// memory—v1
    pub fn owner(&self) -> FenceOwner {
        FenceOwner {
            registry: Arc::downgrade(&self.state),
            marker: Arc::new(OwnerMarker),
        }
    }

    /// Open a modification window owned by `owner`.
    ///
    /// The returned guard is the preferred API. Its token is allocated once,
    /// recorded in the active entry, and never reused by this registry. The
    /// owner and token must both match for explicit or Drop release.
    /// memory—v1
    pub fn begin_owned(
        &self,
        owner: &FenceOwner,
        rule_set_id: BinaryId,
        declaration: &FenceDeclaration,
        premise: &FencePremise,
    ) -> Result<FenceGuard, FenceControlError> {
        let owner_registry = owner
            .registry
            .upgrade()
            .ok_or(FenceControlError::ForeignOwner)?;
        if !Arc::ptr_eq(&owner_registry, &self.state) {
            return Err(FenceControlError::ForeignOwner);
        }
        let token =
            self.open_owned(Arc::clone(&owner.marker), rule_set_id, declaration, premise)?;
        Ok(FenceGuard {
            registry: Arc::downgrade(&self.state),
            rule_set_id,
            owner: Arc::clone(&owner.marker),
            token,
            released: false,
        })
    }

    /// Open the legacy window used by the existing root call sites.
    ///
    /// This signature and its `FenceError` return type are intentionally
    /// unchanged. Known legacy outcomes map exactly to the HEAD variants:
    /// active -> `AlreadyFenced`, absent release -> `NotFenced`, and premise
    /// failures retain their original variants. Poison, capacity exhaustion,
    /// and revision exhaustion have no truthful `FenceError` representation;
    /// `legacy_unavailable` deliberately stops the legacy path instead of
    /// inventing `Candidate` or `NotFenced` facts. The table lock is released
    /// before this happens so exhaustion does not poison unrelated fences.
    /// New callers must use [`Self::begin_owned`].
    ///
    /// memory—v1: preserve the compatibility error contract and fail closed.
    pub fn begin(
        &self,
        rule_set_id: BinaryId,
        declaration: &FenceDeclaration,
        premise: &FencePremise,
    ) -> Result<(), FenceError> {
        Self::finish_legacy_begin(self.try_begin_legacy(rule_set_id, declaration, premise))
    }

    // memory—v1: Root callers defer compatibility panic until their own write
    // guard is dropped; the fence table guard is also released before return.
    pub(crate) fn try_begin_legacy(
        &self,
        rule_set_id: BinaryId,
        declaration: &FenceDeclaration,
        premise: &FencePremise,
    ) -> Result<(), FenceControlError> {
        self.open_owned(
            Arc::clone(&self.state.legacy_owner),
            rule_set_id,
            declaration,
            premise,
        )
        .map(drop)
    }

    // memory—v1: Preserve the legacy error shape without hiding failures.
    pub(crate) fn finish_legacy_begin(
        result: Result<(), FenceControlError>,
    ) -> Result<(), FenceError> {
        match result {
            Ok(()) => Ok(()),
            Err(FenceControlError::Fence(error)) => Err(error),
            Err(error) => legacy_unavailable(error),
        }
    }

    // memory—v1: open both compatibility and owner-scoped windows atomically.
    fn open_owned(
        &self,
        owner: Arc<OwnerMarker>,
        rule_set_id: BinaryId,
        declaration: &FenceDeclaration,
        premise: &FencePremise,
    ) -> Result<FenceToken, FenceControlError> {
        let _writer = self
            .state
            .writer
            .write()
            .map_err(|_| FenceControlError::Poisoned)?;
        let current = self.state.table.load_full();
        if current.active.contains_key(&rule_set_id) {
            return Err(FenceControlError::Fence(FenceError::AlreadyFenced(
                rule_set_id,
            )));
        }
        if current.active.len() >= MAX_ACTIVE_FENCES {
            return Err(FenceControlError::CapacityExceeded {
                limit: MAX_ACTIVE_FENCES,
            });
        }
        check_premise(declaration, premise).map_err(FenceControlError::Fence)?;
        let token = next_token(&current, &self.state.marker)?;
        let mut next = (*current).clone();
        next.active.insert(
            rule_set_id,
            ActiveFence {
                owner,
                token: token.clone(),
            },
        );
        next.record_open(rule_set_id, token.revision());
        next.revision = token.revision();
        self.state.table.store(Arc::new(next));
        Ok(token)
    }

    /// Read the current fence state and the registry-wide non-reused revision
    /// for one rule set.
    ///
    /// A caller should take one observation before reading its immutable
    /// snapshot and one after. The epoch is registry-wide, so a fence on an
    /// unrelated rule set also invalidates the observation. That is deliberate
    /// conservative behavior: it avoids an unbounded historical revision map
    /// and never turns unknown cross-object activity into a stable read.
    /// memory—v1
    pub fn observe(&self, rule_set_id: BinaryId) -> Result<FenceObservation, FenceControlError> {
        if self.state.writer.is_poisoned() {
            return Err(FenceControlError::Poisoned);
        }
        let table = self.state.table.load();
        let observation = FenceObservation {
            registry: Arc::clone(&self.state.marker),
            rule_set_id,
            revision: table.revision,
            active: table.active.contains_key(&rule_set_id),
        };
        if self.state.writer.is_poisoned() {
            return Err(FenceControlError::Poisoned);
        }
        Ok(observation)
    }

    /// memory—v1: Prove the commit still owns the live window in this registry.
    pub(crate) fn verify_guard(
        &self,
        rule_set_id: BinaryId,
        guard: &FenceGuard,
    ) -> Result<(), FenceControlError> {
        if guard.released
            || !guard
                .registry
                .upgrade()
                .is_some_and(|registry| Arc::ptr_eq(&registry, &self.state))
        {
            return Err(FenceControlError::ForeignOwner);
        }
        if !self.metadata_is_healthy() {
            return Err(FenceControlError::Poisoned);
        }
        if !self
            .state
            .table
            .load()
            .active
            .get(&rule_set_id)
            .is_some_and(|active| {
                active.token == guard.token && Arc::ptr_eq(&active.owner, &guard.owner)
            })
        {
            return Err(FenceControlError::TokenMismatch(rule_set_id));
        }
        if !self.metadata_is_healthy() {
            return Err(FenceControlError::Poisoned);
        }
        Ok(())
    }

    /// Release an exact owner/token pair without requiring a guard.
    /// memory—v1
    pub fn abort_owned(
        &self,
        rule_set_id: BinaryId,
        owner: &FenceOwner,
        token: &FenceToken,
    ) -> Result<(), FenceControlError> {
        let owner_registry = owner
            .registry
            .upgrade()
            .ok_or(FenceControlError::ForeignOwner)?;
        if !Arc::ptr_eq(&owner_registry, &self.state) {
            return Err(FenceControlError::ForeignOwner);
        }
        release_owned_locked(&self.state, rule_set_id, &owner.marker, token)
    }

    /// memory—v1: Probe writer availability in isolated tests.
    #[cfg(feature = "test-support")]
    pub(crate) fn table_available_for_test(&self) -> bool {
        self.state.writer.try_write().is_ok()
    }

    // memory—v1: A poisoned writer cannot establish a healthy fence snapshot.
    fn metadata_is_healthy(&self) -> bool {
        !self.state.writer.is_poisoned()
    }

    /// memory—v1: Hold the publication writer in isolated contention tests.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn with_table_lock_for_test<T>(&self, f: impl FnOnce() -> T) -> T {
        let _writer = self
            .state
            .writer
            .write()
            .expect("test fence writer poisoned");
        f()
    }

    /// memory—v1: Bracket the synchronous callback, including its trusted-time
    /// sample, with object-specific fence observations. No relevant opening may
    /// occur between snapshots, even if it closes before the second snapshot.
    /// The history floor refuses observations whose proof was evicted. Unknown
    /// keys and initially active dependencies fail closed.
    pub(crate) fn try_with_unfenced<T>(
        &self,
        rule_set_ids: &[BinaryId],
        f: impl FnOnce(&dyn Fn(BinaryId) -> bool) -> T,
    ) -> Option<T> {
        if rule_set_ids.len() > MAX_FENCE_CHECK_OBJECTS || !self.metadata_is_healthy() {
            return None;
        }
        // Root callers supply a sorted, deduplicated list. Refuse an ambiguous
        // list rather than copying it or accepting an undeclared dependency.
        if rule_set_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return None;
        }
        let initial = self.state.table.load();
        let result = f(&|rule_set_id| {
            rule_set_ids.binary_search(&rule_set_id).is_ok()
                && !initial.active.contains_key(&rule_set_id)
        });
        let current = self.state.table.load();
        if !self.metadata_is_healthy()
            || current.history_floor > initial.revision
            || rule_set_ids.iter().any(|rule_set_id| {
                initial.active.contains_key(rule_set_id)
                    || current.active.contains_key(rule_set_id)
                    || current
                        .object_revisions
                        .get(rule_set_id)
                        .is_some_and(|revision| *revision > initial.revision)
            })
        {
            return None;
        }
        Some(result)
    }

    /// memory—v1: Read one immutable fence snapshot without waiting for a writer.
    pub(crate) fn try_is_active(&self, rule_set_id: BinaryId) -> Result<bool, FenceReadError> {
        if !self.metadata_is_healthy() {
            return Err(FenceReadError::Poisoned);
        }
        let active = self.state.table.load().active.contains_key(&rule_set_id);
        if !self.metadata_is_healthy() {
            return Err(FenceReadError::Poisoned);
        }
        Ok(active)
    }

    /// §4.6: whether reads depending on this object must be refused.
    /// memory—v1
    pub fn is_active(&self, rule_set_id: BinaryId) -> bool {
        self.try_is_active(rule_set_id).unwrap_or(true)
    }

    /// Close the legacy window without publishing (abort/reinitiate path).
    ///
    /// A live owner-scoped window is conservatively reported as the existing
    /// `AlreadyFenced` variant. A missing legacy window is `NotFenced`. Poison
    /// is deliberately not converted to `NotFenced`, because that would claim
    /// a fact the registry could not prove.
    /// memory—v1
    pub fn abort(&self, rule_set_id: BinaryId) -> Result<(), FenceError> {
        let _writer = self
            .state
            .writer
            .write()
            .unwrap_or_else(|_| legacy_unavailable(FenceControlError::Poisoned));
        let current = self.state.table.load_full();
        let Some(active) = current.active.get(&rule_set_id) else {
            return Err(FenceError::NotFenced(rule_set_id));
        };
        if !Arc::ptr_eq(&active.owner, &self.state.legacy_owner) {
            return Err(FenceError::AlreadyFenced(rule_set_id));
        }
        let revision = active.token.revision();
        let mut next = (*current).clone();
        next.active.remove(&rule_set_id);
        next.record_release(rule_set_id, revision);
        self.state.table.store(Arc::new(next));
        Ok(())
    }
}

// memory—v1: never reuse a generation or accept a token from another registry.
fn next_token(
    table: &FenceTable,
    registry: &Arc<RegistryMarker>,
) -> Result<FenceToken, FenceControlError> {
    let next = table
        .revision
        .0
        .checked_add(1)
        .ok_or(FenceControlError::TokenExhausted)?;
    Ok(FenceToken {
        registry: Arc::clone(registry),
        revision: FenceRevision(next),
    })
}

// memory—v1: check the declared root and rule-set premises.
fn check_premise(declaration: &FenceDeclaration, premise: &FencePremise) -> Result<(), FenceError> {
    if premise.root_version != declaration.root_version || premise.digest != declaration.digest {
        return Err(FenceError::RootMismatch {
            declared_root_version: declaration.root_version,
            actual_root_version: premise.root_version,
        });
    }
    if premise.selected_version.as_deref() != Some(declaration.rule_set_version.as_slice()) {
        return Err(FenceError::RuleSetVersionMismatch {
            declared: declaration.rule_set_version.clone(),
            actual: premise.selected_version.clone(),
        });
    }
    Ok(())
}

// memory—v1: release only the matching owner and token in one publication.
fn release_owned_locked(
    state: &FenceState,
    rule_set_id: BinaryId,
    owner: &Arc<OwnerMarker>,
    token: &FenceToken,
) -> Result<(), FenceControlError> {
    let _writer = state
        .writer
        .write()
        .map_err(|_| FenceControlError::Poisoned)?;
    let current = state.table.load_full();
    let Some(active) = current.active.get(&rule_set_id) else {
        return Err(FenceControlError::Fence(FenceError::NotFenced(rule_set_id)));
    };
    if !Arc::ptr_eq(&active.owner, owner) {
        return Err(FenceControlError::OwnerMismatch(rule_set_id));
    }
    if active.token != *token {
        return Err(FenceControlError::TokenMismatch(rule_set_id));
    }
    let revision = active.token.revision();
    let mut next = (*current).clone();
    next.active.remove(&rule_set_id);
    next.record_release(rule_set_id, revision);
    state.table.store(Arc::new(next));
    Ok(())
}

/// The legacy enum has no faithful variant for an unknown lock state,
/// capacity exhaustion, or revision exhaustion. Stop the compatibility path
/// rather than returning a false `Candidate` or `NotFenced` result. The root
/// caller must migrate to the owner/token API before these states can be
/// handled as typed `FenceControlError` values.
// memory—v1: stop when the legacy error contract cannot represent the state.
fn legacy_unavailable(error: FenceControlError) -> ! {
    panic!("legacy modification fence API unavailable: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(version: &[u8]) -> FenceDeclaration {
        FenceDeclaration {
            rule_set_version: version.to_vec(),
            root_version: 7,
            digest: ContentDigest::default(),
        }
    }

    fn premise(version: &[u8]) -> FencePremise {
        FencePremise {
            root_version: 7,
            digest: ContentDigest::default(),
            selected_version: Some(version.to_vec()),
        }
    }

    // memory—v1: A held writer does not block snapshot reads; poison fails closed.
    #[test]
    fn snapshot_reads_continue_while_writer_is_held_and_reject_poison() {
        use std::sync::mpsc;
        use std::time::Duration;

        let fences = FenceRegistry::default();
        fences
            .begin([1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        std::thread::scope(|threads| {
            let (held_tx, held_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let fence_ref = &fences;
            let holder = threads.spawn(move || {
                fence_ref.with_table_lock_for_test(|| {
                    held_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                });
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(fences.try_is_active([1; 16]), Ok(true));
            assert_eq!(fences.try_is_active([2; 16]), Ok(false));
            assert_eq!(
                fences.try_with_unfenced(&[[2; 16]], |unfenced| unfenced([2; 16])),
                Some(true)
            );
            release_tx.send(()).unwrap();
            holder.join().unwrap();
        });
        let state = Arc::clone(&fences.state);
        assert!(std::thread::spawn(move || {
            let _guard = state.writer.write().unwrap();
            panic!("inject fence writer poison");
        })
        .join()
        .is_err());
        assert_eq!(fences.try_is_active([1; 16]), Err(FenceReadError::Poisoned));
        assert_eq!(fences.try_is_active([2; 16]), Err(FenceReadError::Poisoned));
        assert!(fences.is_active([2; 16]));
        assert!(fences.try_with_unfenced(&[[1; 16]], |_| ()).is_none());
    }

    // memory—v1: A relevant fence opened during the callback invalidates the
    // result; an unrelated window leaves the decision available.
    #[test]
    fn final_snapshot_checks_every_key_and_rejects_unlisted_keys() {
        let fences = FenceRegistry::default();
        let first = [1; 16];
        let second = [2; 16];
        let other = [3; 16];
        assert_eq!(
            fences.try_with_unfenced(&[first, second], |unfenced| {
                assert!(unfenced(first));
                assert!(!unfenced(other));
                fences
                    .begin(other, &declaration(b"v1"), &premise(b"v1"))
                    .unwrap();
                assert!(unfenced(second));
            }),
            Some(())
        );
        fences.abort(other).unwrap();
        assert_eq!(
            fences.try_with_unfenced(&[first, second], |unfenced| {
                assert!(unfenced(first));
                fences
                    .begin(second, &declaration(b"v1"), &premise(b"v1"))
                    .unwrap();
                assert!(unfenced(second));
            }),
            None
        );
        fences.abort(second).unwrap();
        assert!(fences
            .try_with_unfenced(&vec![first; MAX_FENCE_CHECK_OBJECTS + 1], |_| ())
            .is_none());
        assert!(fences.try_with_unfenced(&[first, first], |_| ()).is_none());
        assert!(fences.try_with_unfenced(&[second, first], |_| ()).is_none());
    }

    // memory—v1: independent read-side guards overlap without reporting contention.
    #[test]
    fn concurrent_readers_observe_the_same_fence_table() {
        use std::sync::mpsc;
        use std::time::Duration;

        let fences = FenceRegistry::default();
        fences
            .begin([1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        std::thread::scope(|threads| {
            let (held_tx, held_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let fence_ref = &fences;
            let reader = threads.spawn(move || {
                fence_ref
                    .try_with_unfenced(&[[2; 16]], |unfenced| {
                        assert!(!unfenced([1; 16]));
                        held_tx.send(()).unwrap();
                        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                        assert!(unfenced([2; 16]));
                    })
                    .unwrap();
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(fences.try_is_active([1; 16]), Ok(true));
            assert_eq!(fences.try_is_active([2; 16]), Ok(false));
            assert_eq!(
                fences.try_with_unfenced(&[[2; 16]], |unfenced| (
                    unfenced([1; 16]),
                    unfenced([2; 16])
                )),
                Some((false, true))
            );
            assert!(fences.observe([1; 16]).unwrap().active());
            release_tx.send(()).unwrap();
            reader.join().unwrap();
        });
    }

    // memory—v1: a fence opened during a final check invalidates that check.
    #[test]
    fn writer_opening_during_final_check_invalidates_result() {
        use std::sync::mpsc;
        use std::time::Duration;

        let fences = FenceRegistry::default();
        let before = fences.observe([1; 16]).unwrap();
        std::thread::scope(|threads| {
            let (go_tx, go_rx) = mpsc::channel();
            let (opened_tx, opened_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let fence_ref = &fences;
            let writer = threads.spawn(move || {
                go_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                let owner = fence_ref.owner();
                let guard = fence_ref
                    .begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
                    .unwrap();
                opened_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                drop(guard);
            });
            assert_eq!(
                fences.try_with_unfenced(&[[1; 16], [2; 16]], |unfenced| {
                    assert!(unfenced([1; 16]));
                    go_tx.send(()).unwrap();
                    opened_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                    assert!(fences.observe([1; 16]).unwrap().active());
                }),
                None
            );
            let during = fences.observe([1; 16]).unwrap();
            assert!(!before.is_stable_with(&during));
            release_tx.send(()).unwrap();
            writer.join().unwrap();
        });
        let after = fences.observe([1; 16]).unwrap();
        assert!(!after.active());
        assert!(!before.is_stable_with(&after));
    }

    // memory—v1: The initial and final checks cannot combine an old active
    // window with a newly opened window into an unfenced decision.
    #[test]
    fn final_check_rejects_a_window_replaced_during_callback() {
        let fences = FenceRegistry::default();
        fences
            .begin([2; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert_eq!(
            fences.try_with_unfenced(&[[1; 16], [2; 16]], |unfenced| {
                assert!(!unfenced([2; 16]));
                fences.abort([2; 16]).unwrap();
                fences
                    .begin([1; 16], &declaration(b"v1"), &premise(b"v1"))
                    .unwrap();
                assert!(unfenced([1; 16]));
            }),
            None
        );
        fences.abort([1; 16]).unwrap();
        assert_eq!(
            fences.try_with_unfenced(&[[1; 16], [2; 16]], |unfenced| unfenced([2; 16])),
            Some(true)
        );
    }

    // memory—v1: A complete window crossing the clock sample must be rejected,
    // even when both endpoint snapshots have no active fence. An unrelated
    // transient window leaves the same dependency available.
    #[test]
    fn transient_windows_are_checked_per_object_around_the_sample() {
        let fences = FenceRegistry::default();
        let relevant = [1; 16];
        let unrelated = [2; 16];
        let mut sampled = None;
        assert_eq!(
            fences.try_with_unfenced(&[relevant], |unfenced| {
                assert!(unfenced(relevant));
                fences
                    .begin(relevant, &declaration(b"v1"), &premise(b"v1"))
                    .unwrap();
                assert!(fences.is_active(relevant));
                sampled = Some(119);
                fences.abort(relevant).unwrap();
            }),
            None
        );
        assert_eq!(sampled, Some(119));
        assert!(!fences.is_active(relevant));

        assert_eq!(
            fences.try_with_unfenced(&[relevant], |unfenced| {
                assert!(unfenced(relevant));
                fences
                    .begin(unrelated, &declaration(b"v1"), &premise(b"v1"))
                    .unwrap();
                assert!(fences.is_active(unrelated));
                let trusted_time = 119;
                fences.abort(unrelated).unwrap();
                trusted_time
            }),
            Some(119)
        );
    }

    // memory—v1: History is bounded by distinct inactive objects, not by the
    // number of times one object opens. If a relevant opening is evicted while
    // a reader is in flight, the proof floor makes that reader fail closed.
    #[test]
    fn bounded_history_rejects_evicted_proof_and_recovers() {
        let fences = FenceRegistry::default();
        let relevant = u128::MAX.to_be_bytes();
        assert_eq!(
            fences.try_with_unfenced(&[relevant], |_| {
                fences
                    .begin(relevant, &declaration(b"v1"), &premise(b"v1"))
                    .unwrap();
                fences.abort(relevant).unwrap();
                for id in 0..MAX_INACTIVE_FENCE_HISTORY {
                    let other = (id as u128).to_be_bytes();
                    fences
                        .begin(other, &declaration(b"v1"), &premise(b"v1"))
                        .unwrap();
                    fences.abort(other).unwrap();
                }
            }),
            None
        );
        let table = fences.state.table.load();
        assert_eq!(table.inactive_revisions.len(), MAX_INACTIVE_FENCE_HISTORY);
        assert_eq!(table.object_revisions.len(), MAX_INACTIVE_FENCE_HISTORY);
        assert!(!table.object_revisions.contains_key(&relevant));
        assert!(table.history_floor > FenceRevision(0));
        drop(table);
        assert_eq!(fences.try_with_unfenced(&[relevant], |_| ()), Some(()));

        let repeated = (MAX_INACTIVE_FENCE_HISTORY as u128 + 1).to_be_bytes();
        for _ in 0..3 {
            fences
                .begin(repeated, &declaration(b"v1"), &premise(b"v1"))
                .unwrap();
            fences.abort(repeated).unwrap();
        }
        let table = fences.state.table.load();
        assert_eq!(table.inactive_revisions.len(), MAX_INACTIVE_FENCE_HISTORY);
        assert_eq!(table.object_revisions.len(), MAX_INACTIVE_FENCE_HISTORY);
    }

    // memory—v1: A released but old window cannot evict a newer object's proof
    // without advancing the floor beyond a reader that could have missed it.
    #[test]
    fn out_of_order_release_preserves_a_newer_opening() {
        let fences = FenceRegistry::default();
        let old = u128::MAX.to_be_bytes();
        fences
            .begin(old, &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        for id in 0..MAX_INACTIVE_FENCE_HISTORY {
            let other = (id as u128).to_be_bytes();
            fences
                .begin(other, &declaration(b"v1"), &premise(b"v1"))
                .unwrap();
            fences.abort(other).unwrap();
        }
        assert_eq!(
            fences.try_with_unfenced(&[[7; 16]], |_| {
                fences.abort(old).unwrap();
            }),
            Some(())
        );
        let table = fences.state.table.load();
        assert_eq!(table.history_floor, FenceRevision(1));
        assert_eq!(table.inactive_revisions.len(), MAX_INACTIVE_FENCE_HISTORY);
        assert!(!table.object_revisions.contains_key(&old));
    }

    // memory—v1 §4.6: one fence per object; a second modifier is rejected.
    #[test]
    fn same_object_fencing_is_mutually_exclusive() {
        let fences = FenceRegistry::default();
        fences
            .begin([1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert!(fences.is_active([1; 16]));
        assert_eq!(
            fences.begin([1; 16], &declaration(b"v1"), &premise(b"v1")),
            Err(FenceError::AlreadyFenced([1; 16]))
        );
        // A different object fences independently.
        fences
            .begin([2; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert!(fences.is_active([2; 16]));
    }

    // memory—v1 §4.6: declared premises must match the actual snapshot.
    #[test]
    fn declared_premises_are_checked_against_the_snapshot() {
        let fences = FenceRegistry::default();
        let stale_root = FenceDeclaration {
            rule_set_version: b"v1".to_vec(),
            root_version: 6,
            digest: ContentDigest::default(),
        };
        assert_eq!(
            fences.begin([1; 16], &stale_root, &premise(b"v1")),
            Err(FenceError::RootMismatch {
                declared_root_version: 6,
                actual_root_version: 7,
            })
        );
        assert_eq!(
            fences.begin([1; 16], &declaration(b"v0"), &premise(b"v1")),
            Err(FenceError::RuleSetVersionMismatch {
                declared: b"v0".to_vec(),
                actual: Some(b"v1".to_vec()),
            })
        );
        assert!(!fences.is_active([1; 16]));
    }

    // memory—v1 §4.6: abort releases the window; double abort is an error.
    #[test]
    fn abort_releases_and_is_strict() {
        let fences = FenceRegistry::default();
        fences
            .begin([1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        fences.abort([1; 16]).unwrap();
        assert!(!fences.is_active([1; 16]));
        assert_eq!(fences.abort([1; 16]), Err(FenceError::NotFenced([1; 16])));
    }

    // memory—v1 §4.6: an owner-scoped guard releases on Drop and its revision
    // is retained after release, so a later window cannot reuse it.
    #[test]
    fn owned_guard_drop_releases_and_revision_is_monotonic() {
        let fences = FenceRegistry::default();
        let owner = fences.owner();
        let initial = fences.observe([1; 16]).unwrap();
        assert_eq!(initial.revision().value(), 0);
        assert!(!initial.active());

        let first_revision = {
            let guard = fences
                .begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
                .unwrap();
            assert!(fences.is_active([1; 16]));
            guard.revision()
        };
        let after_drop = fences.observe([1; 16]).unwrap();
        assert_eq!(after_drop.revision(), first_revision);
        assert!(!after_drop.active());

        let second = fences
            .begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert!(second.revision() > first_revision);
        drop(second);
        assert!(!fences.is_active([1; 16]));
    }

    // memory—v1 §4.6: stale cleanup is conditional on both owner and token;
    // it cannot remove a newer window for the same rule set.
    #[test]
    fn stale_guard_cannot_release_newer_window() {
        let fences = FenceRegistry::default();
        let owner = fences.owner();
        let stale_guard = fences
            .begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        let stale_token = stale_guard.token();

        fences.abort_owned([1; 16], &owner, &stale_token).unwrap();
        let fresh_guard = fences
            .begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert_ne!(stale_guard.revision(), fresh_guard.revision());

        drop(stale_guard);
        assert!(fences.is_active([1; 16]));
        drop(fresh_guard);
        assert!(!fences.is_active([1; 16]));
    }

    // memory—v1 §4.6: another owner cannot release a live window, even when
    // it has the correct token; a foreign registry owner is rejected earlier.
    #[test]
    fn owner_and_registry_are_part_of_release_identity() {
        let fences = FenceRegistry::default();
        let other_fences = FenceRegistry::default();
        let owner = fences.owner();
        let other_owner = fences.owner();
        let foreign_owner = other_fences.owner();
        let guard = fences
            .begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        let token = guard.token();

        assert_eq!(
            fences.abort_owned([1; 16], &other_owner, &token),
            Err(FenceControlError::OwnerMismatch([1; 16]))
        );
        assert_eq!(
            other_fences.abort_owned([1; 16], &foreign_owner, &token),
            Err(FenceControlError::Fence(FenceError::NotFenced([1; 16])))
        );
        assert_eq!(
            other_fences.abort_owned([1; 16], &owner, &token),
            Err(FenceControlError::ForeignOwner)
        );
        assert!(fences.is_active([1; 16]));
        drop(guard);
    }

    // memory—v1 §4.6: the legacy release path refuses an owner-scoped window
    // with the truthful existing AlreadyFenced variant.
    #[test]
    fn legacy_abort_does_not_release_owned_window() {
        let fences = FenceRegistry::default();
        let owner = fences.owner();
        let guard = fences
            .begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert_eq!(
            fences.abort([1; 16]),
            Err(FenceError::AlreadyFenced([1; 16]))
        );
        assert!(fences.is_active([1; 16]));
        drop(guard);
    }

    // memory—v1 §4.6: read-side observations detect a fence that opens and
    // closes between two snapshot reads, while an unchanged unfenced window
    // can be accepted as stable. The unrelated-rule invalidation is
    // conservative and follows from the registry-wide epoch.
    #[test]
    fn observations_detect_transient_fence_generations() {
        let fences = FenceRegistry::default();
        let before = fences.observe([1; 16]).unwrap();
        let unchanged = fences.observe([1; 16]).unwrap();
        assert!(before.is_stable_with(&unchanged));

        {
            let owner = fences.owner();
            let _guard = fences
                .begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
                .unwrap();
        }
        let after = fences.observe([1; 16]).unwrap();
        assert!(!before.is_stable_with(&after));
        assert_eq!(after.revision().value(), 1);
        assert!(!after.active());

        let unrelated_before = fences.observe([2; 16]).unwrap();
        {
            let owner = fences.owner();
            let _guard = fences
                .begin_owned(&owner, [3; 16], &declaration(b"v1"), &premise(b"v1"))
                .unwrap();
        }
        let unrelated_after = fences.observe([2; 16]).unwrap();
        assert!(!unrelated_before.is_stable_with(&unrelated_after));
    }

    // memory—v1: another registry's same-numbered token cannot release a fence.
    #[test]
    fn foreign_token_cannot_release_matching_generation() {
        let first = FenceRegistry::default();
        let second = FenceRegistry::default();
        let first_owner = first.owner();
        let second_owner = second.owner();
        let first_guard = first
            .begin_owned(&first_owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        let second_guard = second
            .begin_owned(&second_owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert_eq!(first_guard.revision(), second_guard.revision());
        assert_ne!(first_guard.token(), second_guard.token());
        assert_eq!(
            second.abort_owned([1; 16], &second_owner, &first_guard.token()),
            Err(FenceControlError::TokenMismatch([1; 16]))
        );
        assert!(second.is_active([1; 16]));
        drop(second_guard);
        assert!(!second.is_active([1; 16]));
    }

    // memory—v1: stale tokens cannot release newer windows, even for the same owner.
    #[test]
    fn stale_token_and_legacy_owner_cannot_release_other_windows() {
        let fences = FenceRegistry::default();
        let owner = fences.owner();
        fences
            .begin([1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        let other_guard = fences
            .begin_owned(&owner, [2; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert_eq!(
            fences.abort_owned([1; 16], &owner, &other_guard.token()),
            Err(FenceControlError::OwnerMismatch([1; 16]))
        );
        assert!(fences.is_active([1; 16]));
        fences.abort([1; 16]).unwrap();

        let stale = other_guard.token();
        fences.abort_owned([2; 16], &owner, &stale).unwrap();
        let fresh = fences
            .begin_owned(&owner, [2; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert_eq!(
            fences.abort_owned([2; 16], &owner, &stale),
            Err(FenceControlError::TokenMismatch([2; 16]))
        );
        drop(other_guard);
        assert!(fences.is_active([2; 16]));
        drop(fresh);
        assert!(!fences.is_active([2; 16]));
    }

    // memory—v1: concurrent owners cannot simultaneously hold the same fence.
    #[test]
    fn concurrent_owners_have_one_winner() {
        use std::sync::{mpsc, Barrier};
        let fences = FenceRegistry::default();
        let start = Barrier::new(3);
        let finish = Barrier::new(3);
        let (tx, rx) = mpsc::channel();
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let tx = tx.clone();
                let fences = &fences;
                let start = &start;
                let finish = &finish;
                scope.spawn(move || {
                    let owner = fences.owner();
                    start.wait();
                    let result =
                        fences.begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"));
                    tx.send(match &result {
                        Ok(_) => true,
                        Err(FenceControlError::Fence(FenceError::AlreadyFenced(id))) => {
                            assert_eq!(*id, [1; 16]);
                            false
                        }
                        Err(error) => panic!("unexpected error: {error:?}"),
                    })
                    .unwrap();
                    finish.wait();
                    drop(result);
                });
            }
            start.wait();
            let results = [rx.recv().unwrap(), rx.recv().unwrap()];
            assert_eq!(results.iter().filter(|result| **result).count(), 1);
            assert!(fences.is_active([1; 16]));
            finish.wait();
        });
        assert!(!fences.is_active([1; 16]));
    }

    // memory—v1: capacity failure does not poison the lock or strand other guards.
    #[test]
    fn legacy_capacity_failure_preserves_live_fences_and_recovery() {
        let fences = FenceRegistry::default();
        let owner = fences.owner();
        let guards: Vec<_> = (0..MAX_ACTIVE_FENCES)
            .map(|id| {
                fences
                    .begin_owned(
                        &owner,
                        (id as u128).to_be_bytes(),
                        &declaration(b"v1"),
                        &premise(b"v1"),
                    )
                    .unwrap()
            })
            .collect();
        let extra = (MAX_ACTIVE_FENCES as u128).to_be_bytes();
        assert_eq!(
            fences
                .begin_owned(&owner, extra, &declaration(b"v1"), &premise(b"v1"))
                .err(),
            Some(FenceControlError::CapacityExceeded {
                limit: MAX_ACTIVE_FENCES
            })
        );
        assert!(std::panic::catch_unwind(|| {
            let _ = fences.begin(extra, &declaration(b"v1"), &premise(b"v1"));
        })
        .is_err());
        assert!(fences.observe(0_u128.to_be_bytes()).unwrap().active());
        drop(guards);
        assert!(!fences.is_active(0_u128.to_be_bytes()));
        fences
            .begin(extra, &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        fences.abort(extra).unwrap();
    }

    // memory—v1: epoch exhaustion refuses new windows without poisoning live ones.
    #[test]
    fn legacy_epoch_exhaustion_preserves_release_and_observation() {
        let fences = FenceRegistry::default();
        let mut table = (*fences.state.table.load_full()).clone();
        table.revision = FenceRevision(u128::MAX - 1);
        fences.state.table.store(Arc::new(table));
        fences
            .begin([1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert_eq!(
            fences.observe([1; 16]).unwrap().revision().value(),
            u128::MAX
        );
        assert!(std::panic::catch_unwind(|| {
            let _ = fences.begin([2; 16], &declaration(b"v1"), &premise(b"v1"));
        })
        .is_err());
        assert!(fences.observe([1; 16]).unwrap().active());
        let owner = fences.owner();
        assert_eq!(
            fences
                .begin_owned(&owner, [2; 16], &declaration(b"v1"), &premise(b"v1"))
                .err(),
            Some(FenceControlError::TokenExhausted)
        );
        fences.abort([1; 16]).unwrap();
        assert!(!fences.is_active([1; 16]));
    }

    // memory—v1: poisoned state cannot report a successful release or an unfenced read.
    #[test]
    fn poisoned_table_fails_closed_for_legacy_and_owned_paths() {
        let fences = FenceRegistry::default();
        let owner = fences.owner();
        let mut guard = fences
            .begin_owned(&owner, [1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        let token = guard.token();
        let state = Arc::clone(&fences.state);
        assert!(std::thread::spawn(move || {
            let _lock = state.writer.write().unwrap();
            panic!("inject fence table poison");
        })
        .join()
        .is_err());
        assert!(fences.is_active([1; 16]));
        assert!(fences.is_active([2; 16]));
        assert!(matches!(
            fences.observe([1; 16]),
            Err(FenceControlError::Poisoned)
        ));
        assert_eq!(
            fences.abort_owned([1; 16], &owner, &token),
            Err(FenceControlError::Poisoned)
        );
        assert_eq!(guard.release(), Err(FenceControlError::Poisoned));
        assert!(std::panic::catch_unwind(|| {
            let _ = fences.abort([1; 16]);
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            let _ = fences.begin([2; 16], &declaration(b"v1"), &premise(b"v1"));
        })
        .is_err());
        drop(guard);
        assert!(fences.is_active([1; 16]));
    }
}
