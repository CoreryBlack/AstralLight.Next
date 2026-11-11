//! Experimental, process-local runtime for supplied memory—v1 HAMT candidates.
//!
//! The single non-cloneable owner publishes candidate rows, a digest of the
//! explicitly supplied fields, and a monotonically increasing version together.
//! This is not a production authorization root, a database reader, or proof of
//! source provenance, completeness, confirmation validity, or permission.
//! Handles and tokens do not keep the owner alive. The digest is experimental;
//! callers must not treat it as a database hash or as evidence of missing facts.
//!
//! The candidate's row and per-query binding budgets apply. The digest index has
//! additional fixed limits; caller input, retained prepared writes and returned
//! owned rows require separate resource bounds. No global singleton is enforced.

use std::sync::{Arc, RwLock, Weak};

use crate::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserRow,
};
use crate::memory_v1_digest::{
    Change, ContentDigest, DigestError, DigestIndex, Fields, Key, Table,
};
use crate::memory_v1_hamt::{
    CandidateBudget, CandidateError, HamtCandidate, RuleSetImpactCandidate,
};

/// Failures of this isolated candidate runtime.
#[derive(Debug, PartialEq, Eq)]
pub enum RuntimeError {
    /// Candidate validation, row budget, or per-query binding budget failed.
    Candidate(CandidateError),
    /// The experimental digest index rejected the supplied fields or its limits.
    Digest(DigestError),
    /// The owner has been dropped.
    OwnerGone,
    /// A lock was poisoned; no state is returned or changed.
    Poisoned,
    /// The token or prepared write belongs to another owner.
    ForeignOwner,
    /// The observed version is no longer current.
    StaleToken,
    /// The monotonic version cannot advance without wrapping.
    VersionOverflow,
    /// A version row names a different rule set than the requested operation.
    RuleSetMismatch,
    /// A locally checked candidate is missing a required relationship.
    InconsistentCandidate,
    /// A write must request a version change or a selection change.
    EmptyChange,
}

/// Metadata captured atomically with one candidate query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeMetadata {
    /// Owner-local monotonic version, initially zero.
    pub version: u64,
    /// Digest of this runtime's explicit row-field and selection mapping only.
    pub digest: ContentDigest,
    /// Candidate limits, including the per-query binding limit.
    pub budget: CandidateBudget,
    /// Number of rows across the nine supplied tables, excluding selections.
    pub row_count: usize,
}

/// An owner-bound freshness observation, never an authorization capability.
#[derive(Clone)]
pub struct RuntimeToken {
    owner: Weak<RwLock<State>>,
    metadata: RuntimeMetadata,
}

/// An owned result and the token captured with it under the same read lock.
pub struct RuntimeRead<T> {
    /// The requested candidate data, with no authority semantics.
    pub value: T,
    /// A freshness observation for this exact read.
    pub token: RuntimeToken,
}

/// One binding and borrowed related rows from a single candidate state.
pub struct RuntimeBindingContext<'a> {
    /// Direct binding.
    pub binding: &'a BindingRow,
    /// Referenced supplied rule set.
    pub rule_set: &'a RuleSetRow,
    /// Explicitly selected version, or no selection.
    pub selected: Option<&'a RuleSetVersionRow>,
    /// All supplied confirmations for this binding, including historical versions.
    pub confirmations: Vec<&'a BindingConfirmationRow>,
    /// All supplied change confirmations for the rule set.
    pub change_confirmations: Vec<&'a RuleSetChangeConfirmationRow>,
}

/// A borrowed card context available during one callback over a captured candidate.
pub struct RuntimeCardContext<'a> {
    /// Referenced supplied user.
    pub user: &'a UserRow,
    /// The user's supplied identity card.
    pub identity: &'a IdentityCardRow,
    /// Requested card.
    pub card: &'a UserCardRow,
    /// Card's direct tenant.
    pub tenant: &'a TenantRow,
    /// Direct bindings and related rows, subject to the binding budget.
    pub bindings: Vec<RuntimeBindingContext<'a>>,
}

/// Version row change prepared together with an optional selection change.
pub enum VersionChange {
    /// Do not change a version row.
    Keep,
    /// Insert a version that does not already exist.
    Append(RuleSetVersionRow),
}

/// Explicit action for the same rule set's current selection.
pub enum SelectionChange {
    /// Preserve the existing selection.
    Keep,
    /// Select an existing version, including one appended in this write.
    Set(Vec<u8>),
    /// Remove the selection.
    Clear,
}

/// A single-use private candidate and digest prepared from an observed version.
pub struct PreparedWrite {
    owner: Weak<RwLock<State>>,
    base_version: u64,
    candidate: HamtCandidate,
    digest: DigestIndex,
}

struct State {
    live: bool,
    version: u64,
    candidate: HamtCandidate,
    digest: DigestIndex,
}

/// The only writer for this candidate state; this owner is not cloneable.
pub struct HamtRuntimeOwner {
    state: Arc<RwLock<State>>,
}

/// A cloneable read-only reference that does not keep the owner alive.
#[derive(Clone)]
pub struct HamtRuntimeHandle {
    state: Weak<RwLock<State>>,
}

impl State {
    // memory—v1: Capture the candidate limits, version and digest together.
    fn metadata(&self) -> RuntimeMetadata {
        let (budget, row_count) = self.candidate.budget_and_row_count();
        RuntimeMetadata {
            version: self.version,
            digest: self.digest.digest(),
            budget,
            row_count,
        }
    }
}

impl RuntimeToken {
    /// memory—v1: Return the metadata observed with this token.
    pub fn metadata(&self) -> RuntimeMetadata {
        self.metadata
    }
}

impl HamtRuntimeOwner {
    /// memory—v1: Validate and index the supplied rows and explicit selections.
    ///
    /// The digest is computed internally from every field in these row types,
    /// with an explicit NULL for an absent parent and exact opaque byte fields.
    /// This validates only the supplied candidate, never its completeness.
    pub fn new(
        rows: CandidateRows,
        selections: Vec<CurrentSelection>,
        budget: CandidateBudget,
    ) -> Result<Self, RuntimeError> {
        let digest = digest_rows(&rows, &selections)?;
        let candidate =
            HamtCandidate::build(rows, selections, budget).map_err(RuntimeError::Candidate)?;
        Ok(Self {
            state: Arc::new(RwLock::new(State {
                live: true,
                version: 0,
                candidate,
                digest,
            })),
        })
    }

    /// memory—v1: Create a read-only handle without transferring ownership.
    pub fn handle(&self) -> HamtRuntimeHandle {
        HamtRuntimeHandle {
            state: Arc::downgrade(&self.state),
        }
    }

    /// memory—v1: Prepare a structurally shared version and selection update.
    ///
    /// Preparation has no visible effects. A later commit must still compare
    /// the same owner and version; no retry is performed. Both changes target
    /// `rule_set_id`, and the selection is validated after the row change.
    pub fn prepare(
        &self,
        token: &RuntimeToken,
        rule_set_id: BinaryId,
        version: VersionChange,
        selection: SelectionChange,
    ) -> Result<PreparedWrite, RuntimeError> {
        let owner = Arc::downgrade(&self.state);
        if !Weak::ptr_eq(&owner, &token.owner) {
            return Err(RuntimeError::ForeignOwner);
        }
        if matches!(version, VersionChange::Keep) && matches!(selection, SelectionChange::Keep) {
            return Err(RuntimeError::EmptyChange);
        }
        let (candidate, digest) = {
            let state = self.state.read().map_err(|_| RuntimeError::Poisoned)?;
            if !state.live {
                return Err(RuntimeError::OwnerGone);
            }
            if state.version != token.metadata.version {
                return Err(RuntimeError::StaleToken);
            }
            state
                .version
                .checked_add(1)
                .ok_or(RuntimeError::VersionOverflow)?;
            (state.candidate.clone(), state.digest.clone())
        };
        let mut changes = Vec::with_capacity(2);
        let candidate = match version {
            VersionChange::Keep => candidate,
            VersionChange::Append(row) => {
                if row.rule_set_id != rule_set_id {
                    return Err(RuntimeError::RuleSetMismatch);
                }
                let next = candidate
                    .append_version(row.clone())
                    .map_err(RuntimeError::Candidate)?;
                changes.push(version_change(&row));
                next
            }
        };
        let candidate = match selection {
            SelectionChange::Keep => candidate,
            SelectionChange::Set(bytes) => {
                let next = candidate
                    .with_selection(rule_set_id, Some(&bytes))
                    .map_err(RuntimeError::Candidate)?;
                changes.push(Change::select_current(rule_set_id, bytes));
                next
            }
            SelectionChange::Clear => {
                let next = candidate
                    .with_selection(rule_set_id, None)
                    .map_err(RuntimeError::Candidate)?;
                changes.push(Change::clear_current(rule_set_id));
                next
            }
        };
        let digest = digest.prepare(changes).map_err(RuntimeError::Digest)?;
        Ok(PreparedWrite {
            owner,
            base_version: token.metadata.version,
            candidate,
            digest,
        })
    }

    /// memory—v1: Publish a prepared candidate and digest at one version fence.
    ///
    /// The prepared value is consumed on every outcome. No external side effect
    /// or production authorization is performed by this local operation.
    pub fn commit(&mut self, prepared: PreparedWrite) -> Result<RuntimeMetadata, RuntimeError> {
        if !Weak::ptr_eq(&Arc::downgrade(&self.state), &prepared.owner) {
            return Err(RuntimeError::ForeignOwner);
        }
        let mut state = self.state.write().map_err(|_| RuntimeError::Poisoned)?;
        if !state.live {
            return Err(RuntimeError::OwnerGone);
        }
        if state.version != prepared.base_version {
            return Err(RuntimeError::StaleToken);
        }
        let next_version = state
            .version
            .checked_add(1)
            .ok_or(RuntimeError::VersionOverflow)?;
        state.candidate = prepared.candidate;
        state.digest = prepared.digest;
        state.version = next_version;
        Ok(state.metadata())
    }
}

impl Drop for HamtRuntimeOwner {
    // memory—v1: Invalidate handles even when an in-flight reader holds an Arc.
    fn drop(&mut self) {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.live = false;
    }
}

impl HamtRuntimeHandle {
    // memory—v1: Execute one bounded candidate query and capture its metadata.
    fn query<T>(
        &self,
        f: impl FnOnce(&HamtCandidate) -> Result<T, CandidateError>,
    ) -> Result<RuntimeRead<T>, RuntimeError> {
        let owner = self.state.upgrade().ok_or(RuntimeError::OwnerGone)?;
        let state = owner.read().map_err(|_| RuntimeError::Poisoned)?;
        if !state.live {
            return Err(RuntimeError::OwnerGone);
        }
        let value = f(&state.candidate).map_err(RuntimeError::Candidate)?;
        let token = RuntimeToken {
            owner: self.state.clone(),
            metadata: state.metadata(),
        };
        Ok(RuntimeRead { value, token })
    }

    /// memory—v1: Observe metadata without reading candidate rows.
    pub fn token(&self) -> Result<RuntimeToken, RuntimeError> {
        Ok(self.query(|_| Ok(()))?.token)
    }

    /// memory—v1: Test owner identity and currentness at one instant.
    pub fn is_current(&self, token: &RuntimeToken) -> Result<bool, RuntimeError> {
        if !Weak::ptr_eq(&self.state, &token.owner) {
            return Err(RuntimeError::ForeignOwner);
        }
        let current = self.token()?;
        Ok(current.metadata == token.metadata)
    }

    /// memory—v1: Inspect one coherent card context without holding the live lock.
    ///
    /// A transient candidate clone shares HAMT nodes; borrowed rows cannot
    /// escape the callback. Confirmation counts are bounded by total row budget.
    pub fn read_card<T>(
        &self,
        card_id: BinaryId,
        f: impl for<'a> FnOnce(RuntimeCardContext<'a>) -> T,
    ) -> Result<RuntimeRead<T>, RuntimeError> {
        let owner = self.state.upgrade().ok_or(RuntimeError::OwnerGone)?;
        let (candidate, token) = {
            let state = owner.read().map_err(|_| RuntimeError::Poisoned)?;
            if !state.live {
                return Err(RuntimeError::OwnerGone);
            }
            (
                state.candidate.clone(),
                RuntimeToken {
                    owner: self.state.clone(),
                    metadata: state.metadata(),
                },
            )
        };
        let card = candidate
            .card_candidate(card_id)
            .map_err(RuntimeError::Candidate)?;
        let user = candidate
            .user(card.card.user_id)
            .ok_or(RuntimeError::InconsistentCandidate)?;
        let identity = candidate
            .identity_for_user(card.card.user_id)
            .ok_or(RuntimeError::InconsistentCandidate)?;
        let tenant = candidate
            .tenant(card.card.tenant_id)
            .ok_or(RuntimeError::InconsistentCandidate)?;
        let mut bindings = Vec::with_capacity(card.bindings.len());
        for binding in card.bindings {
            bindings.push(RuntimeBindingContext {
                binding,
                rule_set: candidate
                    .rule_set(binding.rule_set_id)
                    .ok_or(RuntimeError::InconsistentCandidate)?,
                selected: candidate
                    .selected_version(binding.rule_set_id)
                    .map_err(RuntimeError::Candidate)?,
                confirmations: candidate
                    .binding_confirmations(binding.binding_id)
                    .map_err(RuntimeError::Candidate)?,
                change_confirmations: candidate
                    .change_confirmations(binding.rule_set_id)
                    .map_err(RuntimeError::Candidate)?,
            });
        }
        let value = f(RuntimeCardContext {
            user,
            identity,
            card: card.card,
            tenant,
            bindings,
        });
        Ok(RuntimeRead { value, token })
    }

    /// memory—v1: Read direct reverse relationships under the binding budget.
    pub fn read_impact(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<RuntimeRead<RuleSetImpactCandidate>, RuntimeError> {
        self.query(|candidate| candidate.rule_set_impact(rule_set_id))
    }
}

// memory—v1: Encode every version field, including its composite identity.
fn version_change(row: &RuleSetVersionRow) -> Change {
    Change::Put {
        key: Key::rule_set_version(row.rule_set_id, row.version_bytes.clone()),
        fields: vec![
            Some(row.rule_set_id.to_vec()),
            Some(row.version_bytes.clone()),
            Some(row.content_bytes.clone()),
            Some(row.timestamp_bytes.clone()),
            Some(row.hash_input_bytes.clone()),
            Some(row.hash_bytes.clone()),
        ],
    }
}

// memory—v1: Encode a single-ID row's explicit fields without caller hashes.
fn row_change(table: Table, id: BinaryId, fields: Fields) -> Change {
    Change::Put {
        key: Key::row(table, id),
        fields,
    }
}

// memory—v1: Incrementally index the nine supplied tables and selections.
fn digest_rows(
    rows: &CandidateRows,
    selections: &[CurrentSelection],
) -> Result<DigestIndex, RuntimeError> {
    let mut digest = DigestIndex::new();
    // Each batch is within DigestIndex's fixed limit; the index itself enforces
    // its aggregate row and byte ceilings. Candidate validation rejects duplicates.
    let mut batch = Vec::with_capacity(128);
    let mut push = |change| -> Result<(), RuntimeError> {
        batch.push(change);
        if batch.len() == 128 {
            digest = digest
                .prepare(batch.drain(..))
                .map_err(RuntimeError::Digest)?;
        }
        Ok(())
    };
    for row in &rows.users {
        push(row_change(
            Table::User,
            row.user_id,
            vec![Some(row.user_id.to_vec())],
        ))?;
    }
    for row in &rows.identity_cards {
        push(row_change(
            Table::IdentityCard,
            row.identity_card_id,
            vec![
                Some(row.identity_card_id.to_vec()),
                Some(row.user_id.to_vec()),
            ],
        ))?;
    }
    for row in &rows.tenants {
        push(row_change(
            Table::Tenant,
            row.tenant_id,
            vec![
                Some(row.tenant_id.to_vec()),
                row.parent_tenant_id.map(|id| id.to_vec()),
            ],
        ))?;
    }
    for row in &rows.user_cards {
        push(row_change(
            Table::UserCard,
            row.user_card_id,
            vec![
                Some(row.user_card_id.to_vec()),
                Some(row.user_id.to_vec()),
                Some(row.tenant_id.to_vec()),
            ],
        ))?;
    }
    for row in &rows.rule_sets {
        push(row_change(
            Table::RuleSet,
            row.rule_set_id,
            vec![
                Some(row.rule_set_id.to_vec()),
                Some(row.owner_tenant_id.to_vec()),
            ],
        ))?;
    }
    for row in &rows.rule_set_versions {
        push(version_change(row))?;
    }
    for row in &rows.bindings {
        let layer = match row.binding_layer {
            BindingLayer::Base => b"BASE".to_vec(),
            BindingLayer::Overlay => b"OVERLAY".to_vec(),
        };
        push(row_change(
            Table::Binding,
            row.binding_id,
            vec![
                Some(row.binding_id.to_vec()),
                Some(row.user_card_id.to_vec()),
                Some(row.rule_set_id.to_vec()),
                Some(layer),
            ],
        ))?;
    }
    for row in &rows.binding_confirmations {
        push(row_change(
            Table::BindingConfirmation,
            row.confirmation_id,
            vec![
                Some(row.confirmation_id.to_vec()),
                Some(row.binding_id.to_vec()),
                Some(row.rule_set_id.to_vec()),
                Some(row.version_bytes.clone()),
                Some(row.confirmer_user_id.to_vec()),
                Some(row.scope_bytes.clone()),
                Some(row.operation_id.clone()),
                Some(row.confirmed_at_bytes.clone()),
            ],
        ))?;
    }
    for row in &rows.rule_set_change_confirmations {
        push(row_change(
            Table::RuleSetChangeConfirmation,
            row.confirmation_id,
            vec![
                Some(row.confirmation_id.to_vec()),
                Some(row.rule_set_id.to_vec()),
                Some(row.version_bytes.clone()),
                Some(row.confirmer_user_id.to_vec()),
                Some(row.affected_scope_bytes.clone()),
                Some(row.operation_id.clone()),
                Some(row.confirmed_at_bytes.clone()),
            ],
        ))?;
    }
    for selection in selections {
        push(Change::select_current(
            selection.rule_set_id,
            selection.version_bytes.clone(),
        ))?;
    }
    drop(push);
    if !batch.is_empty() {
        digest = digest.prepare(batch).map_err(RuntimeError::Digest)?;
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::{IdentityCardRow, RuleSetRow, TenantRow, UserRow};

    // memory—v1: Construct distinct candidate IDs.
    fn id(n: u8) -> BinaryId {
        [n; 16]
    }

    // memory—v1: Build a minimal complete version row.
    fn version(n: u8) -> RuleSetVersionRow {
        RuleSetVersionRow {
            rule_set_id: id(3),
            version_bytes: vec![n],
            content_bytes: vec![n],
            timestamp_bytes: vec![0],
            hash_input_bytes: vec![n],
            hash_bytes: vec![n],
        }
    }

    // memory—v1: Build a bounded candidate owner with a selected version.
    fn owner() -> HamtRuntimeOwner {
        let rows = CandidateRows {
            users: vec![UserRow { user_id: id(1) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            }],
            tenants: vec![TenantRow {
                tenant_id: id(4),
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: id(5),
                user_id: id(1),
                tenant_id: id(4),
            }],
            rule_sets: vec![RuleSetRow {
                rule_set_id: id(3),
                owner_tenant_id: id(4),
            }],
            rule_set_versions: vec![version(1)],
            bindings: vec![BindingRow {
                binding_id: id(6),
                user_card_id: id(5),
                rule_set_id: id(3),
                binding_layer: BindingLayer::Base,
            }],
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: id(7),
                binding_id: id(6),
                rule_set_id: id(3),
                version_bytes: vec![1],
                confirmer_user_id: id(1),
                scope_bytes: vec![],
                operation_id: vec![1],
                confirmed_at_bytes: vec![0],
            }],
            ..CandidateRows::default()
        };
        HamtRuntimeOwner::new(
            rows,
            vec![CurrentSelection {
                rule_set_id: id(3),
                version_bytes: vec![1],
            }],
            CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 4,
            },
        )
        .unwrap()
    }

    #[test]
    // memory—v1: Fence stale and foreign writes and atomically advance the digest.
    fn commit_fences_preparations_and_updates_digest() {
        let mut owner = owner();
        let handle = owner.handle();
        let token = handle.token().unwrap();
        let prepared = owner
            .prepare(
                &token,
                id(3),
                VersionChange::Append(version(2)),
                SelectionChange::Set(vec![2]),
            )
            .unwrap();
        let stale = owner
            .prepare(&token, id(3), VersionChange::Keep, SelectionChange::Clear)
            .unwrap();
        let metadata = owner.commit(prepared).unwrap();
        assert_eq!(metadata.version, 1);
        assert_eq!(metadata.row_count, token.metadata().row_count + 1);
        assert_ne!(metadata.digest, token.metadata().digest);
        assert!(matches!(owner.commit(stale), Err(RuntimeError::StaleToken)));
        assert!(!handle.is_current(&token).unwrap());
        let other = self::owner();
        assert!(matches!(
            other.prepare(&token, id(3), VersionChange::Keep, SelectionChange::Clear),
            Err(RuntimeError::ForeignOwner)
        ));
        drop(owner);
        assert!(matches!(handle.token(), Err(RuntimeError::OwnerGone)));
    }

    #[test]
    // memory—v1: Reject invalid preparation and overflow without changing state.
    fn failed_preparation_preserves_state() {
        let mut owner = owner();
        let handle = owner.handle();
        let token = handle.token().unwrap();
        assert!(matches!(
            owner.prepare(
                &token,
                id(3),
                VersionChange::Append(version(1)),
                SelectionChange::Set(vec![1])
            ),
            Err(RuntimeError::Candidate(
                CandidateError::DuplicateVersion { .. }
            ))
        ));
        assert!(handle.is_current(&token).unwrap());
        let prepared = owner
            .prepare(
                &token,
                id(3),
                VersionChange::Append(version(2)),
                SelectionChange::Set(vec![2]),
            )
            .unwrap();
        owner.state.write().unwrap().version = u64::MAX;
        assert!(matches!(
            owner.commit(prepared),
            Err(RuntimeError::StaleToken)
        ));
        let max_token = handle.token().unwrap();
        assert!(matches!(
            owner.prepare(
                &max_token,
                id(3),
                VersionChange::Keep,
                SelectionChange::Clear
            ),
            Err(RuntimeError::VersionOverflow)
        ));
        let read = handle
            .read_card(id(5), |context| {
                (
                    context.user.user_id,
                    context.identity.identity_card_id,
                    context.tenant.tenant_id,
                    context.bindings.len(),
                )
            })
            .unwrap();
        assert_eq!(read.value, (id(1), id(2), id(4), 1));
    }

    #[test]
    // memory—v1: A reader sees one version while a concurrent write completes.
    fn captured_context_remains_coherent_and_does_not_block_commit() {
        use std::sync::mpsc::sync_channel;
        use std::thread;

        let mut owner = owner();
        let handle = owner.handle();
        let reader = handle.clone();
        let token = handle.token().unwrap();
        let prepared = owner
            .prepare(
                &token,
                id(3),
                VersionChange::Append(version(2)),
                SelectionChange::Set(vec![2]),
            )
            .unwrap();
        let (entered_tx, entered_rx) = sync_channel(0);
        let (release_tx, release_rx) = sync_channel(0);
        let reader_thread = thread::spawn(move || {
            reader
                .read_card(id(5), |context| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    (
                        context.bindings[0].selected.unwrap().version_bytes.clone(),
                        context.bindings[0].confirmations[0].version_bytes.clone(),
                    )
                })
                .unwrap()
        });
        entered_rx.recv().unwrap();
        let (committed_tx, committed_rx) = sync_channel(1);
        let writer_thread = thread::spawn(move || {
            committed_tx.send(owner.commit(prepared)).unwrap();
            owner
        });
        let committed = committed_rx.recv_timeout(std::time::Duration::from_secs(5));
        release_tx.send(()).unwrap();
        let metadata = committed
            .expect("commit must not wait for the reader callback")
            .unwrap();
        let _owner = writer_thread.join().unwrap();
        let prior = reader_thread.join().unwrap();
        assert_eq!(prior.value, (vec![1], vec![1]));
        assert!(!handle.is_current(&prior.token).unwrap());
        let current = handle
            .read_card(id(5), |context| {
                (
                    context.bindings[0].selected.unwrap().version_bytes.clone(),
                    context.bindings[0].confirmations[0].version_bytes.clone(),
                )
            })
            .unwrap();
        assert_eq!(current.value, (vec![2], vec![1]));
        assert_eq!(current.token.metadata(), metadata);
    }
}
