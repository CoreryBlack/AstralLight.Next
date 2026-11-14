//! Offline row candidates for `Docs/memory-v1/数据库结构候选.sql`.
//!
//! These types neither read a database nor establish provenance, coverage,
//! freshness, persistence, confirmation validity, digest integrity, or authority.
//! The SQL is an unadopted candidate; these rows must not be used to authorize.
//! Validation checks only constraints over the supplied rows. In particular,
//! neither timestamps nor version bytes identify the current version, and no
//! hash algorithm or encoding is assumed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};

/// Exact bytes of a candidate `BINARY(16)` identifier, including zero bytes.
pub type BinaryId = [u8; 16];

/// Candidate `memory_user` row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRow {
    /// User identifier.
    pub user_id: BinaryId,
}

/// Candidate `memory_identity_card` row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCardRow {
    /// Identity-card identifier.
    pub identity_card_id: BinaryId,
    /// Referenced user.
    pub user_id: BinaryId,
}

/// Candidate `memory_tenant` row; parentage confers no rights.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRow {
    /// Tenant identifier.
    pub tenant_id: BinaryId,
    /// Optional referenced parent.
    pub parent_tenant_id: Option<BinaryId>,
}

/// Candidate `memory_user_card` row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCardRow {
    /// User-card identifier.
    pub user_card_id: BinaryId,
    /// Referenced user.
    pub user_id: BinaryId,
    /// Referenced tenant.
    pub tenant_id: BinaryId,
    /// §4.12 B-2.3: lifecycle status; DISABLED cards contribute nothing.
    pub status: UserCardStatus,
}

/// memory—v1 §4.12: user-card lifecycle status (B-2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserCardStatus {
    #[serde(rename = "ACTIVE")]
    Active,
    #[serde(rename = "DISABLED")]
    Disabled,
}

/// Candidate `memory_rule_set` row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetRow {
    /// Stable rule-set identifier.
    pub rule_set_id: BinaryId,
    /// Referenced administrative owner.
    pub owner_tenant_id: BinaryId,
    /// §4.13: explicit current-version pointer (B-3.1); never inferred.
    pub current_version_bytes: Vec<u8>,
}

/// Candidate `memory_rule_set_version` row, preserving all five byte fields.
///
/// The four-tuple is version, content, timestamp and hash; `hash_input_bytes`
/// separately preserves the exact purported input. No relationship between
/// these values is verified by this model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetVersionRow {
    /// Referenced rule-set identifier.
    pub rule_set_id: BinaryId,
    /// Exact version bytes.
    pub version_bytes: Vec<u8>,
    /// Exact content bytes.
    pub content_bytes: Vec<u8>,
    /// Exact timestamp bytes.
    pub timestamp_bytes: Vec<u8>,
    /// Exact purported hash input bytes.
    pub hash_input_bytes: Vec<u8>,
    /// Exact purported digest bytes.
    pub hash_bytes: Vec<u8>,
}

/// Candidate binding layer, without authorization semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingLayer {
    /// Base layer.
    Base,
    /// Overlay layer.
    Overlay,
}

/// Candidate `memory_card_rule_set_binding` row.
///
/// §4.4/§4.10: the optional binding-level validity window and visibility scope
/// are binding attributes; absent values default to an open window and the
/// strictest `self`/`self` scope at evaluation time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingRow {
    /// Binding identifier.
    pub binding_id: BinaryId,
    /// Referenced user card.
    pub user_card_id: BinaryId,
    /// Referenced rule set, without an implicit version pin.
    pub rule_set_id: BinaryId,
    /// Candidate binding layer.
    pub binding_layer: BindingLayer,
    /// Optional inclusive window start in trusted Unix seconds.
    pub valid_from: Option<i64>,
    /// Optional exclusive window end in trusted Unix seconds.
    pub valid_until: Option<i64>,
    /// Owner visibility scope; absent (loaded) value defaults to `self`.
    pub owner_scope: MemoryV1OwnerScope,
    /// Tenant visibility scope; absent (loaded) value defaults to `self`.
    pub tenant_scope: MemoryV1TenantScope,
    /// §4.12 B-2.2: removal tombstone (REMOVED bindings contribute nothing).
    pub removed_at: Option<i64>,
    /// §4.12 B-2.2: who removed this binding.
    pub removed_by: Option<BinaryId>,
}

/// Candidate `memory_binding_confirmation` traceability row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingConfirmationRow {
    /// Confirmation identifier, unique within this table.
    pub confirmation_id: BinaryId,
    /// Referenced binding.
    pub binding_id: BinaryId,
    /// Rule set in the binding and version composite references.
    pub rule_set_id: BinaryId,
    /// Exact referenced version bytes.
    pub version_bytes: Vec<u8>,
    /// Referenced confirmer; their authority is not verified.
    pub confirmer_user_id: BinaryId,
    /// Opaque scope.
    pub scope_bytes: Vec<u8>,
    /// Opaque operation correlation bytes.
    pub operation_id: Vec<u8>,
    /// Opaque confirmation time bytes.
    pub confirmed_at_bytes: Vec<u8>,
    /// §4.12 B-2.4: revocation tombstone (REVOKE = deterministic failure).
    pub revoked_at: Option<i64>,
    /// §4.12 B-2.4: who revoked this confirmation.
    pub revoked_by: Option<BinaryId>,
}

/// Candidate `memory_rule_set_change_confirmation` traceability row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetChangeConfirmationRow {
    /// Confirmation identifier, unique within this table.
    pub confirmation_id: BinaryId,
    /// Referenced rule set.
    pub rule_set_id: BinaryId,
    /// Exact referenced version bytes.
    pub version_bytes: Vec<u8>,
    /// Referenced confirmer; their authority is not verified.
    pub confirmer_user_id: BinaryId,
    /// Opaque affected scope.
    pub affected_scope_bytes: Vec<u8>,
    /// Opaque operation correlation bytes.
    pub operation_id: Vec<u8>,
    /// Opaque confirmation time bytes.
    pub confirmed_at_bytes: Vec<u8>,
    /// §4.12 B-2.4: revocation tombstone (REVOKE = deterministic failure).
    pub revoked_at: Option<i64>,
    /// §4.12 B-2.4: who revoked this confirmation.
    pub revoked_by: Option<BinaryId>,
}

/// The nine caller-supplied tables; deserialization does not validate them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRows {
    /// Supplied user rows.
    pub users: Vec<UserRow>,
    /// Supplied identity-card rows.
    pub identity_cards: Vec<IdentityCardRow>,
    /// Supplied tenant rows.
    pub tenants: Vec<TenantRow>,
    /// Supplied user-card rows.
    pub user_cards: Vec<UserCardRow>,
    /// Supplied rule-set rows.
    pub rule_sets: Vec<RuleSetRow>,
    /// Supplied rule-set version rows.
    pub rule_set_versions: Vec<RuleSetVersionRow>,
    /// Supplied binding rows.
    pub bindings: Vec<BindingRow>,
    /// Supplied binding-confirmation rows.
    pub binding_confirmations: Vec<BindingConfirmationRow>,
    /// Supplied change-confirmation rows.
    pub rule_set_change_confirmations: Vec<RuleSetChangeConfirmationRow>,
}

/// Row kinds used in errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    /// User table.
    User,
    /// Identity-card table.
    IdentityCard,
    /// Tenant table.
    Tenant,
    /// User-card table.
    UserCard,
    /// Rule-set table.
    RuleSet,
    /// Version table.
    RuleSetVersion,
    /// Binding table.
    Binding,
    /// Binding-confirmation table.
    BindingConfirmation,
    /// Change-confirmation table.
    RuleSetChangeConfirmation,
}

/// Row count of every candidate table; carries no completeness semantics by itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TableCounts {
    /// `memory_user` rows.
    pub users: usize,
    /// `memory_identity_card` rows.
    pub identity_cards: usize,
    /// `memory_tenant` rows.
    pub tenants: usize,
    /// `memory_user_card` rows.
    pub user_cards: usize,
    /// `memory_rule_set` rows.
    pub rule_sets: usize,
    /// `memory_rule_set_version` rows.
    pub rule_set_versions: usize,
    /// `memory_card_rule_set_binding` rows.
    pub bindings: usize,
    /// `memory_binding_confirmation` rows.
    pub binding_confirmations: usize,
    /// `memory_rule_set_change_confirmation` rows.
    pub rule_set_change_confirmations: usize,
}

impl TableCounts {
    /// memory—v1: Sum of the nine tables, or `None` if the sum would overflow.
    pub fn total(&self) -> Option<usize> {
        [
            self.users,
            self.identity_cards,
            self.tenants,
            self.user_cards,
            self.rule_sets,
            self.rule_set_versions,
            self.bindings,
            self.binding_confirmations,
            self.rule_set_change_confirmations,
        ]
        .into_iter()
        .try_fold(0_usize, usize::checked_add)
    }
}

/// Why no unambiguous current version can be named for a rule set.
///
/// The candidate schema defines no current-version pointer, and neither version
/// bytes nor timestamps order versions; the only unambiguous case is a rule set
/// that has exactly one stored version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionError {
    /// The rule set has no stored version.
    NoVersion {
        /// The rule set without a version.
        rule_set_id: BinaryId,
    },
    /// The rule set has several stored versions and the contract orders none of them.
    AmbiguousVersions {
        /// The rule set with more than one version.
        rule_set_id: BinaryId,
    },
}

impl CandidateRows {
    /// memory—v1: Row count of each supplied table.
    pub fn table_counts(&self) -> TableCounts {
        TableCounts {
            users: self.users.len(),
            identity_cards: self.identity_cards.len(),
            tenants: self.tenants.len(),
            user_cards: self.user_cards.len(),
            rule_sets: self.rule_sets.len(),
            rule_set_versions: self.rule_set_versions.len(),
            bindings: self.bindings.len(),
            binding_confirmations: self.binding_confirmations.len(),
            rule_set_change_confirmations: self.rule_set_change_confirmations.len(),
        }
    }

    /// memory—v1: Name the current version of each rule set without inferring an order.
    ///
    /// A rule set with exactly one stored version selects it. Zero or several
    /// versions are refused, because the candidate schema has no current-version
    /// pointer and version bytes or timestamps are not an ordering. The result is
    /// sorted by rule-set identifier so it is deterministic.
    pub fn single_version_selections(&self) -> Result<Vec<CurrentSelection>, SelectionError> {
        let mut by_rule_set: BTreeMap<BinaryId, (usize, &[u8])> = self
            .rule_sets
            .iter()
            .map(|rule_set| (rule_set.rule_set_id, (0_usize, &[][..])))
            .collect();
        for version in &self.rule_set_versions {
            if let Some(entry) = by_rule_set.get_mut(&version.rule_set_id) {
                entry.0 = entry.0.saturating_add(1);
                entry.1 = &version.version_bytes;
            }
        }
        by_rule_set
            .into_iter()
            .map(|(rule_set_id, (versions, version_bytes))| match versions {
                0 => Err(SelectionError::NoVersion { rule_set_id }),
                1 => Ok(CurrentSelection {
                    rule_set_id,
                    version_bytes: version_bytes.to_vec(),
                }),
                _ => Err(SelectionError::AmbiguousVersions { rule_set_id }),
            })
            .collect()
    }
}

/// A failure of a candidate row constraint or an explicit selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// Duplicate table-local identifier.
    DuplicateId { table: Table, id: BinaryId },
    /// More than one identity card refers to the same user.
    DuplicateIdentityCard { user_id: BinaryId },
    /// Duplicate composite version primary key.
    DuplicateVersion {
        rule_set_id: BinaryId,
        version_bytes: Vec<u8>,
    },
    /// A single-column reference is absent from the supplied rows.
    MissingReference {
        table: Table,
        field: &'static str,
        id: BinaryId,
    },
    /// A confirmation references a binding/rule-set pair that is not present.
    MissingBindingPair {
        binding_id: BinaryId,
        rule_set_id: BinaryId,
    },
    /// A confirmation references a version not present in the supplied rows.
    MissingVersionReference {
        table: Table,
        rule_set_id: BinaryId,
        version_bytes: Vec<u8>,
    },
    /// The candidate SQL forbids a tenant being its own direct parent.
    SelfParent { tenant_id: BinaryId },
    /// A binding window has both bounds with `from >= until` (§4.4).
    InvalidBindingWindow { binding_id: BinaryId },
    /// An opaque byte field exceeds the SQL candidate's storage capacity.
    FieldTooLong {
        table: Table,
        field: &'static str,
        max: u64,
        actual: u64,
    },
    /// A caller selected a current version for an unknown supplied rule set.
    UnknownSelectionRuleSet { rule_set_id: BinaryId },
    /// A caller selected more than one current version for a rule set.
    DuplicateSelection { rule_set_id: BinaryId },
}

/// Caller-provided selection; it does not itself establish currentness or trust.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentSelection {
    /// Supplied rule-set identity.
    pub rule_set_id: BinaryId,
    /// Exact version identity explicitly selected by the caller.
    pub version_bytes: Vec<u8>,
}

/// Result of looking up the caller's explicit selection in the supplied rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentVersion<'a> {
    /// The caller made no selection for this rule set.
    NotSelected,
    /// A selection was supplied, but its version row is absent.
    Missing { version_bytes: &'a [u8] },
    /// The selected row is present; its bytes and digest remain unverified.
    Present(&'a RuleSetVersionRow),
}

/// Traceability records for the selected, present version only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmationRecords<'a, T> {
    /// No selected version row is available; matching cannot be determined.
    NoCurrentVersion,
    /// The selected version is present, but no matching records were supplied.
    NoMatchingRecords,
    /// Matching supplied rows, without a claim that they are valid confirmations.
    Records(Vec<&'a T>),
}

/// Candidate data for a binding, with current selection and traceability separated.
pub struct BindingCandidate<'a> {
    /// Supplied binding row.
    pub binding: &'a BindingRow,
    /// Caller-selected version lookup, which may be absent.
    pub current: CurrentVersion<'a>,
    /// Binding confirmation records matching the selected, present version.
    pub binding_confirmations: ConfirmationRecords<'a, BindingConfirmationRow>,
    /// Change confirmation records matching the selected, present version.
    pub change_confirmations: ConfirmationRecords<'a, RuleSetChangeConfirmationRow>,
}

/// Immutable view of checked supplied rows and explicit caller selections.
///
/// It borrows the rows, preventing changes to them while the view exists. It is
/// neither a trusted snapshot nor a complete or authorization-ready data set.
pub struct CandidateView<'a> {
    rows: &'a CandidateRows,
    versions: BTreeMap<(BinaryId, &'a [u8]), &'a RuleSetVersionRow>,
    selections: BTreeMap<BinaryId, &'a [u8]>,
    rule_sets: BTreeSet<BinaryId>,
    bindings: BTreeMap<BinaryId, &'a BindingRow>,
}

// memory—v1: Reject duplicate primary keys without silently replacing rows.
fn unique(ids: &mut BTreeSet<BinaryId>, table: Table, id: BinaryId) -> Result<(), ValidationError> {
    if !ids.insert(id) {
        return Err(ValidationError::DuplicateId { table, id });
    }
    Ok(())
}

// memory—v1: Resolve an actual foreign key in the supplied rows only.
fn require(
    ids: &BTreeSet<BinaryId>,
    table: Table,
    field: &'static str,
    id: BinaryId,
) -> Result<(), ValidationError> {
    if !ids.contains(&id) {
        return Err(ValidationError::MissingReference { table, field, id });
    }
    Ok(())
}

// memory—v1: Enforce candidate column capacity without defining an encoding.
fn length(
    table: Table,
    field: &'static str,
    bytes: &[u8],
    max: u64,
) -> Result<(), ValidationError> {
    let actual = bytes.len() as u64;
    if actual > max {
        return Err(ValidationError::FieldTooLong {
            table,
            field,
            max,
            actual,
        });
    }
    Ok(())
}

// memory—v1: Check the opaque fields shared by both confirmation tables.
fn confirmation_lengths(
    table: Table,
    version: &[u8],
    scope: &[u8],
    operation: &[u8],
    time: &[u8],
    scope_field: &'static str,
) -> Result<(), ValidationError> {
    length(table, "version_bytes", version, 255)?;
    length(table, scope_field, scope, u32::MAX as u64)?;
    length(table, "operation_id", operation, 255)?;
    length(table, "confirmed_at_bytes", time, 255)
}

impl CandidateRows {
    /// memory—v1: Validate supplied SQL relations and build a read-only candidate.
    ///
    /// Selections must come explicitly from the caller; missing selection and a
    /// selected but absent row stay distinguishable. The caller is responsible
    /// for its selection source. Success proves no hash, coverage, currentness,
    /// valid confirmation, tenant eligibility, or authorization. Only a direct
    /// self-parent is rejected, as in the SQL; longer cycles remain unresolved.
    pub fn build_candidate<'a>(
        &'a self,
        selections: &'a [CurrentSelection],
    ) -> Result<CandidateView<'a>, ValidationError> {
        let mut users = BTreeSet::new();
        let mut tenants = BTreeSet::new();
        let mut identity_ids = BTreeSet::new();
        let mut identity_users = BTreeSet::new();
        let mut cards = BTreeSet::new();
        let mut rule_sets = BTreeSet::new();
        let mut binding_ids = BTreeSet::new();
        let mut binding_confirmation_ids = BTreeSet::new();
        let mut change_confirmation_ids = BTreeSet::new();
        let mut versions = BTreeMap::new();
        let mut bindings = BTreeMap::new();

        for row in &self.users {
            unique(&mut users, Table::User, row.user_id)?;
        }
        for row in &self.tenants {
            unique(&mut tenants, Table::Tenant, row.tenant_id)?;
        }
        for row in &self.tenants {
            if let Some(parent) = row.parent_tenant_id {
                if parent == row.tenant_id {
                    return Err(ValidationError::SelfParent {
                        tenant_id: row.tenant_id,
                    });
                }
                require(&tenants, Table::Tenant, "parent_tenant_id", parent)?;
            }
        }
        for row in &self.identity_cards {
            unique(&mut identity_ids, Table::IdentityCard, row.identity_card_id)?;
            require(&users, Table::IdentityCard, "user_id", row.user_id)?;
            if !identity_users.insert(row.user_id) {
                return Err(ValidationError::DuplicateIdentityCard {
                    user_id: row.user_id,
                });
            }
        }
        for row in &self.user_cards {
            unique(&mut cards, Table::UserCard, row.user_card_id)?;
            require(&users, Table::UserCard, "user_id", row.user_id)?;
            require(&tenants, Table::UserCard, "tenant_id", row.tenant_id)?;
        }
        for row in &self.rule_sets {
            unique(&mut rule_sets, Table::RuleSet, row.rule_set_id)?;
            require(
                &tenants,
                Table::RuleSet,
                "owner_tenant_id",
                row.owner_tenant_id,
            )?;
        }
        for row in &self.rule_set_versions {
            require(
                &rule_sets,
                Table::RuleSetVersion,
                "rule_set_id",
                row.rule_set_id,
            )?;
            length(
                Table::RuleSetVersion,
                "version_bytes",
                &row.version_bytes,
                255,
            )?;
            length(
                Table::RuleSetVersion,
                "content_bytes",
                &row.content_bytes,
                u32::MAX as u64,
            )?;
            length(
                Table::RuleSetVersion,
                "timestamp_bytes",
                &row.timestamp_bytes,
                255,
            )?;
            length(
                Table::RuleSetVersion,
                "hash_input_bytes",
                &row.hash_input_bytes,
                u32::MAX as u64,
            )?;
            length(Table::RuleSetVersion, "hash_bytes", &row.hash_bytes, 255)?;
            if versions
                .insert((row.rule_set_id, row.version_bytes.as_slice()), row)
                .is_some()
            {
                return Err(ValidationError::DuplicateVersion {
                    rule_set_id: row.rule_set_id,
                    version_bytes: row.version_bytes.clone(),
                });
            }
        }
        for row in &self.bindings {
            unique(&mut binding_ids, Table::Binding, row.binding_id)?;
            require(&cards, Table::Binding, "user_card_id", row.user_card_id)?;
            require(&rule_sets, Table::Binding, "rule_set_id", row.rule_set_id)?;
            if let (Some(from), Some(until)) = (row.valid_from, row.valid_until) {
                if from >= until {
                    return Err(ValidationError::InvalidBindingWindow {
                        binding_id: row.binding_id,
                    });
                }
            }
            bindings.insert(row.binding_id, row);
        }
        for row in &self.binding_confirmations {
            unique(
                &mut binding_confirmation_ids,
                Table::BindingConfirmation,
                row.confirmation_id,
            )?;
            confirmation_lengths(
                Table::BindingConfirmation,
                &row.version_bytes,
                &row.scope_bytes,
                &row.operation_id,
                &row.confirmed_at_bytes,
                "scope_bytes",
            )?;
            if !bindings
                .get(&row.binding_id)
                .is_some_and(|binding| binding.rule_set_id == row.rule_set_id)
            {
                return Err(ValidationError::MissingBindingPair {
                    binding_id: row.binding_id,
                    rule_set_id: row.rule_set_id,
                });
            }
            if !versions.contains_key(&(row.rule_set_id, row.version_bytes.as_slice())) {
                return Err(ValidationError::MissingVersionReference {
                    table: Table::BindingConfirmation,
                    rule_set_id: row.rule_set_id,
                    version_bytes: row.version_bytes.clone(),
                });
            }
            require(
                &users,
                Table::BindingConfirmation,
                "confirmer_user_id",
                row.confirmer_user_id,
            )?;
        }
        for row in &self.rule_set_change_confirmations {
            unique(
                &mut change_confirmation_ids,
                Table::RuleSetChangeConfirmation,
                row.confirmation_id,
            )?;
            confirmation_lengths(
                Table::RuleSetChangeConfirmation,
                &row.version_bytes,
                &row.affected_scope_bytes,
                &row.operation_id,
                &row.confirmed_at_bytes,
                "affected_scope_bytes",
            )?;
            if !versions.contains_key(&(row.rule_set_id, row.version_bytes.as_slice())) {
                return Err(ValidationError::MissingVersionReference {
                    table: Table::RuleSetChangeConfirmation,
                    rule_set_id: row.rule_set_id,
                    version_bytes: row.version_bytes.clone(),
                });
            }
            require(
                &users,
                Table::RuleSetChangeConfirmation,
                "confirmer_user_id",
                row.confirmer_user_id,
            )?;
        }
        let mut selected = BTreeMap::new();
        for selection in selections {
            if !rule_sets.contains(&selection.rule_set_id) {
                return Err(ValidationError::UnknownSelectionRuleSet {
                    rule_set_id: selection.rule_set_id,
                });
            }
            length(
                Table::RuleSetVersion,
                "version_bytes",
                &selection.version_bytes,
                255,
            )?;
            if selected
                .insert(selection.rule_set_id, selection.version_bytes.as_slice())
                .is_some()
            {
                return Err(ValidationError::DuplicateSelection {
                    rule_set_id: selection.rule_set_id,
                });
            }
        }
        Ok(CandidateView {
            rows: self,
            versions,
            selections: selected,
            rule_sets,
            bindings,
        })
    }
}

impl<'a> CandidateView<'a> {
    /// memory—v1: Return all supplied rows, including historical confirmations.
    pub fn rows(&self) -> &'a CandidateRows {
        self.rows
    }

    /// memory—v1: Look up only the version explicitly selected by the caller.
    ///
    /// `None` means the rule set itself is absent; no ordering or time-based
    /// inference is performed. A present row has not had its hash checked.
    pub fn current(&self, rule_set_id: BinaryId) -> Option<CurrentVersion<'a>> {
        if !self.rule_sets.contains(&rule_set_id) {
            return None;
        }
        Some(match self.selections.get(&rule_set_id) {
            None => CurrentVersion::NotSelected,
            Some(version) => match self.versions.get(&(rule_set_id, *version)) {
                Some(row) => CurrentVersion::Present(row),
                None => CurrentVersion::Missing {
                    version_bytes: version,
                },
            },
        })
    }

    /// memory—v1: Build a binding candidate without treating records as approval.
    ///
    /// Only records referring to the selected present version are returned here;
    /// older records remain accessible via `rows`. Neither record type establishes
    /// authorization, and a change confirmation has no defined effect on bindings.
    pub fn binding(&self, binding_id: BinaryId) -> Option<BindingCandidate<'a>> {
        let binding = *self.bindings.get(&binding_id)?;
        let current = self.current(binding.rule_set_id)?;
        let (binding_confirmations, change_confirmations) = match current {
            CurrentVersion::Present(version) => {
                let binding_rows: Vec<_> = self
                    .rows
                    .binding_confirmations
                    .iter()
                    .filter(|row| {
                        row.binding_id == binding_id
                            && row.rule_set_id == binding.rule_set_id
                            && row.version_bytes == version.version_bytes
                    })
                    .collect();
                let change_rows: Vec<_> = self
                    .rows
                    .rule_set_change_confirmations
                    .iter()
                    .filter(|row| {
                        row.rule_set_id == binding.rule_set_id
                            && row.version_bytes == version.version_bytes
                    })
                    .collect();
                let binding_records = if binding_rows.is_empty() {
                    ConfirmationRecords::NoMatchingRecords
                } else {
                    ConfirmationRecords::Records(binding_rows)
                };
                let change_records = if change_rows.is_empty() {
                    ConfirmationRecords::NoMatchingRecords
                } else {
                    ConfirmationRecords::Records(change_rows)
                };
                (binding_records, change_records)
            }
            _ => (
                ConfirmationRecords::NoCurrentVersion,
                ConfirmationRecords::NoCurrentVersion,
            ),
        };
        Some(BindingCandidate {
            binding,
            current,
            binding_confirmations,
            change_confirmations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1: Create opaque IDs containing both zero and high-bit bytes.
    fn id(n: u8) -> BinaryId {
        let mut value = [0; 16];
        value[0] = 0x80;
        value[15] = n;
        value
    }

    // memory—v1: Build one candidate containing all nine table kinds.
    fn rows() -> CandidateRows {
        CandidateRows {
            users: vec![UserRow { user_id: id(1) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            }],
            tenants: vec![
                TenantRow {
                    tenant_id: id(3),
                    parent_tenant_id: None,
                },
                TenantRow {
                    tenant_id: id(4),
                    parent_tenant_id: None,
                },
            ],
            user_cards: vec![UserCardRow {
                user_card_id: id(5),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                rule_set_id: id(6),
                owner_tenant_id: id(4),
                current_version_bytes: Vec::new(),
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(6),
                version_bytes: vec![0, 0xff],
                content_bytes: vec![0, 0x80, 1],
                timestamp_bytes: vec![0xff, 0],
                hash_input_bytes: vec![9, 0, 8],
                hash_bytes: vec![0, 7],
            }],
            bindings: vec![BindingRow {
                binding_id: id(7),
                user_card_id: id(5),
                rule_set_id: id(6),
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            }],
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: id(8),
                binding_id: id(7),
                rule_set_id: id(6),
                version_bytes: vec![0, 0xff],
                confirmer_user_id: id(1),
                scope_bytes: vec![0],
                operation_id: vec![0xff],
                confirmed_at_bytes: vec![0],
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                confirmation_id: id(8),
                rule_set_id: id(6),
                version_bytes: vec![0, 0xff],
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![0xff],
                operation_id: vec![0],
                confirmed_at_bytes: vec![0xff],
                revoked_at: None,
                revoked_by: None,
            }],
        }
    }

    #[test]
    // memory—v1: Preserve arbitrary IDs and tuple/input bytes across serialization.
    fn exact_bytes_round_trip_and_no_hash_assumption() {
        let candidate = rows();
        let encoded = serde_json::to_vec(&candidate).unwrap();
        let decoded: CandidateRows = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, candidate);
        let selection = [CurrentSelection {
            rule_set_id: id(6),
            version_bytes: vec![0, 0xff],
        }];
        let view = decoded.build_candidate(&selection).unwrap();
        let context = view.binding(id(7)).unwrap();
        assert_eq!(
            context.current,
            CurrentVersion::Present(&decoded.rule_set_versions[0])
        );
        assert_eq!(
            context.binding_confirmations,
            ConfirmationRecords::Records(vec![&decoded.binding_confirmations[0]])
        );
        assert_eq!(
            context.change_confirmations,
            ConfirmationRecords::Records(vec![&decoded.rule_set_change_confirmations[0]])
        );
    }

    #[test]
    // memory—v1: Separate unspecified, missing and present current selections.
    fn current_is_explicit_and_confirmation_absence_is_distinct() {
        let mut candidate = rows();
        candidate.rule_set_versions.push(RuleSetVersionRow {
            rule_set_id: id(6),
            version_bytes: vec![255],
            content_bytes: vec![],
            timestamp_bytes: vec![255],
            hash_input_bytes: vec![],
            hash_bytes: vec![],
        });
        let unselected = candidate.build_candidate(&[]).unwrap();
        assert_eq!(unselected.current(id(6)), Some(CurrentVersion::NotSelected));
        assert_eq!(
            unselected.binding(id(7)).unwrap().binding_confirmations,
            ConfirmationRecords::NoCurrentVersion
        );
        assert_eq!(unselected.current(id(99)), None);
        let missing = [CurrentSelection {
            rule_set_id: id(6),
            version_bytes: vec![3],
        }];
        let view = candidate.build_candidate(&missing).unwrap();
        assert_eq!(
            view.current(id(6)),
            Some(CurrentVersion::Missing {
                version_bytes: &[3]
            })
        );
        assert_eq!(
            view.binding(id(7)).unwrap().change_confirmations,
            ConfirmationRecords::NoCurrentVersion
        );
        let other = [CurrentSelection {
            rule_set_id: id(6),
            version_bytes: vec![255],
        }];
        let view = candidate.build_candidate(&other).unwrap();
        let binding = view.binding(id(7)).unwrap();
        assert_eq!(
            binding.current,
            CurrentVersion::Present(&candidate.rule_set_versions[1])
        );
        assert_eq!(
            binding.binding_confirmations,
            ConfirmationRecords::NoMatchingRecords
        );
        assert_eq!(
            binding.change_confirmations,
            ConfirmationRecords::NoMatchingRecords
        );
        assert_eq!(view.rows().binding_confirmations.len(), 1);
        let first = [CurrentSelection {
            rule_set_id: id(6),
            version_bytes: vec![0, 0xff],
        }];
        assert_eq!(
            candidate.build_candidate(&first).unwrap().current(id(6)),
            Some(CurrentVersion::Present(&candidate.rule_set_versions[0]))
        );
    }

    #[test]
    // memory—v1: Foreign keys refer only to actually supplied binding/version pairs.
    fn confirmation_composite_references_are_checked() {
        let mut candidate = rows();
        candidate.binding_confirmations[0].rule_set_id = id(9);
        assert!(matches!(
            candidate.build_candidate(&[]),
            Err(ValidationError::MissingBindingPair { .. })
        ));
        candidate = rows();
        candidate.binding_confirmations[0].version_bytes = vec![2];
        assert!(matches!(
            candidate.build_candidate(&[]),
            Err(ValidationError::MissingVersionReference {
                table: Table::BindingConfirmation,
                ..
            })
        ));
        candidate = rows();
        candidate.rule_set_change_confirmations[0].version_bytes = vec![2];
        assert!(matches!(
            candidate.build_candidate(&[]),
            Err(ValidationError::MissingVersionReference {
                table: Table::RuleSetChangeConfirmation,
                ..
            })
        ));
        candidate = rows();
        candidate.rule_set_change_confirmations[0].confirmer_user_id = id(99);
        assert!(matches!(
            candidate.build_candidate(&[]),
            Err(ValidationError::MissingReference {
                table: Table::RuleSetChangeConfirmation,
                field: "confirmer_user_id",
                ..
            })
        ));
    }

    #[test]
    // memory—v1: Candidate SQL permits repeated bindings and lacks coverage proofs.
    fn only_declared_relationship_constraints_are_assumed() {
        let mut candidate = rows();
        candidate.identity_cards.clear();
        let mut second = candidate.bindings[0].clone();
        second.binding_id = id(10);
        second.binding_layer = BindingLayer::Overlay;
        candidate.bindings.push(second);
        candidate.tenants[0].parent_tenant_id = Some(id(4));
        candidate.tenants[1].parent_tenant_id = Some(id(3));
        assert!(candidate.build_candidate(&[]).is_ok());
        candidate.tenants[0].parent_tenant_id = Some(id(3));
        assert!(matches!(
            candidate.build_candidate(&[]),
            Err(ValidationError::SelfParent { .. })
        ));
        candidate.tenants[0].parent_tenant_id = Some(id(99));
        assert!(matches!(
            candidate.build_candidate(&[]),
            Err(ValidationError::MissingReference {
                table: Table::Tenant,
                ..
            })
        ));
    }

    #[test]
    // memory—v1: Reject duplicates and oversized byte fields without inventing encodings.
    fn duplicate_and_length_constraints() {
        let mut candidate = rows();
        candidate
            .rule_set_versions
            .push(candidate.rule_set_versions[0].clone());
        assert!(matches!(
            candidate.build_candidate(&[]),
            Err(ValidationError::DuplicateVersion { .. })
        ));
        candidate = rows();
        candidate.identity_cards.push(IdentityCardRow {
            identity_card_id: id(10),
            user_id: id(1),
        });
        assert!(matches!(
            candidate.build_candidate(&[]),
            Err(ValidationError::DuplicateIdentityCard { .. })
        ));
        candidate = rows();
        candidate.binding_confirmations[0].operation_id = vec![0; 256];
        assert!(matches!(
            candidate.build_candidate(&[]),
            Err(ValidationError::FieldTooLong {
                table: Table::BindingConfirmation,
                field: "operation_id",
                ..
            })
        ));
        candidate = rows();
        let duplicate = [
            CurrentSelection {
                rule_set_id: id(6),
                version_bytes: vec![],
            },
            CurrentSelection {
                rule_set_id: id(6),
                version_bytes: vec![1],
            },
        ];
        assert!(matches!(
            candidate.build_candidate(&duplicate),
            Err(ValidationError::DuplicateSelection { .. })
        ));
        let unknown = [CurrentSelection {
            rule_set_id: id(99),
            version_bytes: vec![],
        }];
        assert!(matches!(
            candidate.build_candidate(&unknown),
            Err(ValidationError::UnknownSelectionRuleSet { .. })
        ));
    }
}
