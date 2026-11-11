//! Database-key-preserving candidate root model for a single-node read authority.
//!
//! This module intentionally has no SQL or authority-client dependency. A
//! consistent-snapshot loader supplies [`SingleNodeDatabaseSnapshot`] rows, and
//! this builder validates database identities and relationships before deriving
//! indexes. The derived indexes never replace the database keys carried by the
//! root objects. A built root is only a candidate; it does not prove publication,
//! coverage, readiness, or authorization.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::time::{Duration, Instant};

use serde::ser::SerializeSeq;

use astral_types::{BindingLayer, CertifiedSodPolicy, GrantEffect, ValidityWindow};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_TEXT_BYTES: usize = 4096;
const SHA256_HEX_LEN: usize = 64;

/// Limits work performed while building one candidate, not total process memory.
///
/// `max_snapshot_bytes` counts the JSON encoding of the supplied typed rows;
/// `max_canonical_bytes` counts the existing canonical digest encoding. Neither
/// measures allocator overhead, spare capacities, or other live roots. The caller
/// must bound loading before constructing the snapshot and manage process-wide
/// memory, concurrent builds and retained roots separately. Time is checked
/// cooperatively and cannot preempt an individual allocation or operation.
#[derive(Debug, Clone, Copy)]
pub struct SingleNodeRootBuildBudget {
    pub max_rows: usize,
    pub max_snapshot_bytes: usize,
    pub max_canonical_bytes: usize,
    pub max_build_time: Duration,
}

impl Default for SingleNodeRootBuildBudget {
    fn default() -> Self {
        Self {
            // The current loader allows 100,000 rows per table, across 14 sets.
            max_rows: 1_400_000,
            max_snapshot_bytes: 512 * 1024 * 1024,
            max_canonical_bytes: 768 * 1024 * 1024,
            max_build_time: Duration::from_secs(30),
        }
    }
}

struct BuildGuard {
    started: Instant,
    budget: SingleNodeRootBuildBudget,
}

impl BuildGuard {
    fn check_time(&self) -> Result<(), SingleNodeMemoryRootError> {
        if self.started.elapsed() >= self.budget.max_build_time {
            return Err(budget_error("build time exceeded"));
        }
        Ok(())
    }
}

fn budget_error(detail: &'static str) -> SingleNodeMemoryRootError {
    SingleNodeMemoryRootError::InvalidValue {
        entity: "root_budget",
        detail: detail.to_owned(),
    }
}

/// Count and optionally hash bytes without materializing a JSON buffer.
struct BudgetWriter<'a> {
    guard: &'a BuildGuard,
    limit: usize,
    count: usize,
    hasher: Option<Sha256>,
    failure: Option<&'static str>,
    limit_message: &'static str,
}

impl Write for BudgetWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let failure = if self.guard.check_time().is_err() {
            Some("build time exceeded")
        } else if bytes.len() > self.limit.saturating_sub(self.count) {
            Some(self.limit_message)
        } else {
            None
        };
        if let Some(failure) = failure {
            self.failure = Some(failure);
            return Err(io::Error::other(failure));
        }
        self.count += bytes.len();
        if let Some(hasher) = &mut self.hasher {
            hasher.update(bytes);
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_budgeted<T: serde::Serialize>(
    value: &T,
    guard: &BuildGuard,
    limit: usize,
    limit_message: &'static str,
    hash: bool,
) -> Result<Option<String>, SingleNodeMemoryRootError> {
    let mut writer = BudgetWriter {
        guard,
        limit,
        count: 0,
        hasher: hash.then(Sha256::new),
        failure: None,
        limit_message,
    };
    let result = serde_json::to_writer(&mut writer, value);
    if let Some(failure) = writer.failure {
        return Err(budget_error(failure));
    }
    result.map_err(|error| SingleNodeMemoryRootError::InvalidValue {
        entity: "root",
        detail: format!("encoding failed: {error}"),
    })?;
    guard.check_time()?;
    Ok(writer.hasher.map(|hasher| hex::encode(hasher.finalize())))
}

// Serialize map entries as the same sequence of pairs previously collected in
// canonical_bytes, but without allocating a Vec of references for each map.
struct MapPairs<'a, K, V>(&'a BTreeMap<K, V>);

impl<K: serde::Serialize, V: serde::Serialize> serde::Serialize for MapPairs<'_, K, V> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            seq.serialize_element(&entry)?;
        }
        seq.end()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SingleNodeMemoryRootError {
    #[error("single-node root field {entity}.{field} must be positive")]
    NonPositiveId {
        entity: &'static str,
        field: &'static str,
    },
    #[error("single-node root field {entity}.{field} is empty or exceeds its bound")]
    InvalidText {
        entity: &'static str,
        field: &'static str,
    },
    #[error("single-node root {entity} has duplicate database key {key}")]
    Duplicate { entity: &'static str, key: String },
    #[error("single-node root {entity} references missing {target} key {key}")]
    MissingReference {
        entity: &'static str,
        target: &'static str,
        key: String,
    },
    #[error("single-node root {entity} has inconsistent tenant scope: expected {expected}, got {actual}")]
    TenantMismatch {
        entity: &'static str,
        expected: i64,
        actual: i64,
    },
    #[error("single-node root {entity} has invalid value: {detail}")]
    InvalidValue {
        entity: &'static str,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeRootVersion {
    pub source_snapshot_id: String,
    pub generation: u64,
    pub dependency_frontier_digest: String,
    pub revoke_watermark: u64,
}

impl SingleNodeRootVersion {
    fn validate(&self) -> Result<(), SingleNodeMemoryRootError> {
        validate_text(
            "root_version",
            "source_snapshot_id",
            &self.source_snapshot_id,
        )?;
        validate_digest(
            "root_version",
            "dependency_frontier_digest",
            &self.dependency_frontier_digest,
        )?;
        if self.generation == 0 {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "root_version",
                detail: "generation must be positive".to_owned(),
            });
        }
        if self.revoke_watermark > self.generation {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "root_version",
                detail: "revoke watermark cannot exceed generation".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeUser {
    pub user_id: i64,
    pub status: String,
    pub deleted_at_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeIdentityCard {
    pub card_id: i64,
    pub user_id: i64,
    pub status: String,
    pub expires_at_unix: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeUserCard {
    pub card_id: i64,
    pub user_id: Option<i64>,
    pub tenant_id: i64,
    pub domain_id: Option<i64>,
    pub status: String,
    pub valid_from_unix: Option<i64>,
    pub valid_to_unix: Option<i64>,
}

impl SingleNodeUserCard {
    fn validate(&self) -> Result<(), SingleNodeMemoryRootError> {
        positive("user_card", "card_id", self.card_id)?;
        positive("user_card", "tenant_id", self.tenant_id)?;
        validate_text("user_card", "status", &self.status)?;
        validate_window("user_card", self.valid_from_unix, self.valid_to_unix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeTenant {
    pub tenant_id: i64,
    pub tenant_code: String,
    pub parent_tenant_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeDomain {
    pub domain_id: i64,
    pub domain_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeTenantDomain {
    pub id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeOrgMembership {
    pub membership_id: String,
    pub tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub revision: u64,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeRuleSet {
    pub rule_set_id: i64,
    pub code: String,
    pub tenant_id: Option<i64>,
    pub source_type: String,
    pub source_id: Option<i64>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeRuleSetEntry {
    pub entry_id: i64,
    pub rule_set_id: i64,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub action_code: String,
    pub effect: GrantEffect,
    pub condition_json: Option<String>,
    pub priority: i64,
    pub enabled: bool,
    pub validity: ValidityWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeCardRuleSetRef {
    /// `card_rule_set_ref.id`; this binding identity is retained in the root.
    pub binding_id: i64,
    pub card_id: i64,
    pub rule_set_id: i64,
    pub tenant_id: i64,
    pub binding_layer: BindingLayer,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodePermissionRule {
    pub rule_id: i64,
    pub card_id: i64,
    pub tenant_id: i64,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub action_code: String,
    pub effect: GrantEffect,
    pub condition_json: Option<String>,
    pub priority: i64,
    pub source_type: String,
    pub source_id: Option<i64>,
    pub enabled: bool,
    pub validity: ValidityWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodePublishedPointer {
    pub pointer_id: i64,
    pub tenant_id: i64,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub current_generation: u64,
    pub manifest_id: i64,
    pub manifest_digest: String,
    pub status: String,
    pub revoke_fence: u64,
    pub revoke_fence_proven: bool,
}

impl SingleNodePublishedPointer {
    fn validate(&self) -> Result<(), SingleNodeMemoryRootError> {
        positive(
            "authorization_projection_current",
            "pointer_id",
            self.pointer_id,
        )?;
        positive(
            "authorization_projection_current",
            "tenant_id",
            self.tenant_id,
        )?;
        positive(
            "authorization_projection_current",
            "aggregate_id",
            self.aggregate_id,
        )?;
        positive(
            "authorization_projection_current",
            "manifest_id",
            self.manifest_id,
        )?;
        validate_text(
            "authorization_projection_current",
            "aggregate_type",
            &self.aggregate_type,
        )?;
        validate_text("authorization_projection_current", "status", &self.status)?;
        validate_digest(
            "authorization_projection_current",
            "manifest_digest",
            &self.manifest_digest,
        )?;
        if self.status != "READY" {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "authorization_projection_current",
                detail: format!("status must be READY, got {:?}", self.status),
            });
        }
        if !self.revoke_fence_proven {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "authorization_projection_current",
                detail: "revoke fence is not proven".to_owned(),
            });
        }
        if self.current_generation == 0 {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "authorization_projection_current",
                detail: "current generation must be positive".to_owned(),
            });
        }
        if self.revoke_fence > self.current_generation {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "authorization_projection_current",
                detail: "revoke fence exceeds current generation".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct SingleNodePublishedPointerKey {
    pub tenant_id: i64,
    pub aggregate_type: String,
    pub aggregate_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleNodeGlobalAdmin {
    pub id: i64,
    pub user_id: i64,
    pub active: bool,
}

/// Rows read from one MySQL consistent snapshot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SingleNodeDatabaseSnapshot {
    pub version: SingleNodeRootVersion,
    pub users: Vec<SingleNodeUser>,
    pub identity_cards: Vec<SingleNodeIdentityCard>,
    pub user_cards: Vec<SingleNodeUserCard>,
    pub tenants: Vec<SingleNodeTenant>,
    pub domains: Vec<SingleNodeDomain>,
    pub tenant_domains: Vec<SingleNodeTenantDomain>,
    pub org_memberships: Vec<SingleNodeOrgMembership>,
    pub rule_sets: Vec<SingleNodeRuleSet>,
    pub rule_set_entries: Vec<SingleNodeRuleSetEntry>,
    pub card_rule_set_refs: Vec<SingleNodeCardRuleSetRef>,
    pub permission_rules: Vec<SingleNodePermissionRule>,
    pub published_pointers: Vec<SingleNodePublishedPointer>,
    pub global_admins: Vec<SingleNodeGlobalAdmin>,
    pub sod_policies: Vec<(i64, CertifiedSodPolicy)>,
}

/// Immutable, database-key-preserving local authorization root.
#[derive(Debug, Clone)]
pub struct SingleNodeMemoryRoot {
    version: SingleNodeRootVersion,
    content_digest: String,
    users: BTreeMap<i64, SingleNodeUser>,
    identity_cards: BTreeMap<i64, SingleNodeIdentityCard>,
    user_cards: BTreeMap<i64, SingleNodeUserCard>,
    tenants: BTreeMap<i64, SingleNodeTenant>,
    domains: BTreeMap<i64, SingleNodeDomain>,
    tenant_domains: BTreeMap<i64, SingleNodeTenantDomain>,
    org_memberships: BTreeMap<String, SingleNodeOrgMembership>,
    rule_sets: BTreeMap<i64, SingleNodeRuleSet>,
    rule_set_entries: BTreeMap<i64, SingleNodeRuleSetEntry>,
    card_rule_set_refs: BTreeMap<i64, SingleNodeCardRuleSetRef>,
    permission_rules: BTreeMap<i64, SingleNodePermissionRule>,
    published_pointers: BTreeMap<SingleNodePublishedPointerKey, SingleNodePublishedPointer>,
    global_admins: BTreeMap<i64, SingleNodeGlobalAdmin>,
    sod_policies: BTreeMap<i64, CertifiedSodPolicy>,
    identity_card_by_user: BTreeMap<i64, i64>,
    user_cards_by_user: BTreeMap<i64, Vec<i64>>,
    user_cards_by_tenant_domain: BTreeMap<(i64, Option<i64>), Vec<i64>>,
    rule_sets_by_card: BTreeMap<i64, Vec<i64>>,
    entries_by_rule_set: BTreeMap<i64, Vec<i64>>,
    permission_rules_by_card: BTreeMap<i64, Vec<i64>>,
}

impl SingleNodeMemoryRoot {
    pub fn build(snapshot: SingleNodeDatabaseSnapshot) -> Result<Self, SingleNodeMemoryRootError> {
        Self::build_with_budget(snapshot, SingleNodeRootBuildBudget::default())
    }

    /// Construct a candidate under per-build work limits. A successful build is
    /// not evidence of coverage, publication, readiness, or authorization.
    pub fn build_with_budget(
        snapshot: SingleNodeDatabaseSnapshot,
        budget: SingleNodeRootBuildBudget,
    ) -> Result<Self, SingleNodeMemoryRootError> {
        let guard = BuildGuard {
            started: Instant::now(),
            budget,
        };
        guard.check_time()?;
        let row_counts = [
            snapshot.users.len(),
            snapshot.identity_cards.len(),
            snapshot.user_cards.len(),
            snapshot.tenants.len(),
            snapshot.domains.len(),
            snapshot.tenant_domains.len(),
            snapshot.org_memberships.len(),
            snapshot.rule_sets.len(),
            snapshot.rule_set_entries.len(),
            snapshot.card_rule_set_refs.len(),
            snapshot.permission_rules.len(),
            snapshot.published_pointers.len(),
            snapshot.global_admins.len(),
            snapshot.sod_policies.len(),
        ];
        let row_count = row_counts
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .ok_or_else(|| budget_error("snapshot row count overflow"))?;
        if row_count > budget.max_rows {
            return Err(budget_error("snapshot row limit exceeded"));
        }
        write_budgeted(
            &snapshot,
            &guard,
            budget.max_snapshot_bytes,
            "snapshot byte limit exceeded",
            false,
        )?;
        snapshot.version.validate()?;

        let users = unique_map(snapshot.users, "platform_user", |row| row.user_id, &guard)?;
        let identity_cards = unique_map(
            snapshot.identity_cards,
            "identity_card",
            |row| row.card_id,
            &guard,
        )?;
        let user_cards = unique_map(snapshot.user_cards, "user_card", |row| row.card_id, &guard)?;
        let tenants = unique_map(snapshot.tenants, "tenant", |row| row.tenant_id, &guard)?;
        let domains = unique_map(
            snapshot.domains,
            "platform_domain",
            |row| row.domain_id,
            &guard,
        )?;
        let tenant_domains = unique_map(
            snapshot.tenant_domains,
            "tenant_domain_map",
            |row| row.id,
            &guard,
        )?;
        let org_memberships = unique_string_map(
            snapshot.org_memberships,
            "org_scope_membership",
            |row| row.membership_id.clone(),
            &guard,
        )?;
        let rule_sets = unique_map(
            snapshot.rule_sets,
            "rule_set",
            |row| row.rule_set_id,
            &guard,
        )?;
        let rule_set_entries = unique_map(
            snapshot.rule_set_entries,
            "rule_set_entry",
            |row| row.entry_id,
            &guard,
        )?;
        let card_rule_set_refs = unique_map(
            snapshot.card_rule_set_refs,
            "card_rule_set_ref",
            |row| row.binding_id,
            &guard,
        )?;
        let permission_rules = unique_map(
            snapshot.permission_rules,
            "permission_rule",
            |row| row.rule_id,
            &guard,
        )?;
        let global_admins = unique_map(
            snapshot.global_admins,
            "identity_global_admin",
            |row| row.id,
            &guard,
        )?;
        let mut sod_policies = BTreeMap::new();
        for (policy_id, policy) in snapshot.sod_policies {
            guard.check_time()?;
            if policy_id <= 0 {
                return Err(SingleNodeMemoryRootError::NonPositiveId {
                    entity: "sod_policy",
                    field: "policy_id",
                });
            }
            if sod_policies.insert(policy_id, policy).is_some() {
                return Err(SingleNodeMemoryRootError::Duplicate {
                    entity: "sod_policy",
                    key: policy_id.to_string(),
                });
            }
        }

        validate_users(&users)?;
        guard.check_time()?;
        let mut admin_users = BTreeSet::new();
        for admin in global_admins.values() {
            positive("identity_global_admin", "user_id", admin.user_id)?;
            if !users.contains_key(&admin.user_id) {
                missing("identity_global_admin", "platform_user", admin.user_id)?;
            }
            if !admin_users.insert(admin.user_id) {
                return Err(SingleNodeMemoryRootError::Duplicate {
                    entity: "identity_global_admin",
                    key: format!("user_id/{}", admin.user_id),
                });
            }
        }
        validate_tenants(&tenants, &guard)?;
        validate_identity_cards(&identity_cards, &users)?;
        validate_tenant_domains(&tenant_domains, &tenants, &domains)?;
        validate_user_cards(&user_cards, &users, &identity_cards, &tenants, &domains)?;
        validate_memberships(&org_memberships, &identity_cards, &user_cards, &tenants)?;
        validate_rule_sets(&rule_sets, &tenants)?;
        validate_rule_set_entries(&rule_set_entries, &rule_sets)?;
        validate_bindings(&card_rule_set_refs, &user_cards, &rule_sets)?;
        validate_permission_rules(&permission_rules, &user_cards)?;
        validate_sod_policies(&sod_policies)?;

        let mut published_pointers = BTreeMap::new();
        let mut pointer_ids = BTreeSet::new();
        for pointer in snapshot.published_pointers {
            guard.check_time()?;
            pointer.validate()?;
            if !pointer_ids.insert(pointer.pointer_id) {
                return Err(SingleNodeMemoryRootError::Duplicate {
                    entity: "authorization_projection_current",
                    key: format!("pointer_id/{}", pointer.pointer_id),
                });
            }
            let key = SingleNodePublishedPointerKey {
                tenant_id: pointer.tenant_id,
                aggregate_type: pointer.aggregate_type.clone(),
                aggregate_id: pointer.aggregate_id,
            };
            if published_pointers.insert(key.clone(), pointer).is_some() {
                return Err(SingleNodeMemoryRootError::Duplicate {
                    entity: "authorization_projection_current",
                    key: format!(
                        "{}/{}/{}",
                        key.tenant_id, key.aggregate_type, key.aggregate_id
                    ),
                });
            }
        }

        let identity_card_by_user = identity_cards
            .values()
            .map(|row| (row.user_id, row.card_id))
            .collect::<BTreeMap<_, _>>();
        if identity_card_by_user.len() != identity_cards.len() {
            return Err(SingleNodeMemoryRootError::Duplicate {
                entity: "identity_card",
                key: "user_id".to_owned(),
            });
        }

        let mut user_cards_by_user = BTreeMap::<i64, Vec<i64>>::new();
        let mut user_cards_by_tenant_domain = BTreeMap::<(i64, Option<i64>), Vec<i64>>::new();
        for row in user_cards.values() {
            if let Some(user_id) = row.user_id {
                user_cards_by_user
                    .entry(user_id)
                    .or_default()
                    .push(row.card_id);
            }
            user_cards_by_tenant_domain
                .entry((row.tenant_id, row.domain_id))
                .or_default()
                .push(row.card_id);
        }

        let mut rule_sets_by_card = BTreeMap::<i64, Vec<i64>>::new();
        let mut seen_card_rule_set_pairs = BTreeSet::new();
        for row in card_rule_set_refs.values() {
            if !seen_card_rule_set_pairs.insert((row.card_id, row.rule_set_id)) {
                return Err(SingleNodeMemoryRootError::Duplicate {
                    entity: "card_rule_set_ref",
                    key: format!("{}/{}", row.card_id, row.rule_set_id),
                });
            }
            rule_sets_by_card
                .entry(row.card_id)
                .or_default()
                .push(row.binding_id);
        }

        let mut entries_by_rule_set = BTreeMap::<i64, Vec<i64>>::new();
        for row in rule_set_entries.values() {
            entries_by_rule_set
                .entry(row.rule_set_id)
                .or_default()
                .push(row.entry_id);
        }

        let mut permission_rules_by_card = BTreeMap::<i64, Vec<i64>>::new();
        for row in permission_rules.values() {
            permission_rules_by_card
                .entry(row.card_id)
                .or_default()
                .push(row.rule_id);
        }

        for values in [
            user_cards_by_user.values_mut().collect::<Vec<_>>(),
            user_cards_by_tenant_domain.values_mut().collect::<Vec<_>>(),
            rule_sets_by_card.values_mut().collect::<Vec<_>>(),
            entries_by_rule_set.values_mut().collect::<Vec<_>>(),
            permission_rules_by_card.values_mut().collect::<Vec<_>>(),
        ] {
            for value in values {
                value.sort_unstable();
            }
        }

        let mut root = Self {
            version: snapshot.version,
            content_digest: String::new(),
            users,
            identity_cards,
            user_cards,
            tenants,
            domains,
            tenant_domains,
            org_memberships,
            rule_sets,
            rule_set_entries,
            card_rule_set_refs,
            permission_rules,
            published_pointers,
            global_admins,
            sod_policies,
            identity_card_by_user,
            user_cards_by_user,
            user_cards_by_tenant_domain,
            rule_sets_by_card,
            entries_by_rule_set,
            permission_rules_by_card,
        };
        root.content_digest = root.canonical_digest(&guard)?;
        Ok(root)
    }

    pub fn version(&self) -> &SingleNodeRootVersion {
        &self.version
    }

    pub fn content_digest(&self) -> &str {
        &self.content_digest
    }

    pub fn user(&self, user_id: i64) -> Option<&SingleNodeUser> {
        self.users.get(&user_id)
    }

    /// Returns candidate source data only; presence does not establish eligibility.
    pub fn user_card(&self, card_id: i64) -> Option<&SingleNodeUserCard> {
        self.user_cards.get(&card_id)
    }

    pub fn identity_card(&self, card_id: i64) -> Option<&SingleNodeIdentityCard> {
        self.identity_cards.get(&card_id)
    }

    pub fn tenant(&self, tenant_id: i64) -> Option<&SingleNodeTenant> {
        self.tenants.get(&tenant_id)
    }

    pub fn domain(&self, domain_id: i64) -> Option<&SingleNodeDomain> {
        self.domains.get(&domain_id)
    }

    pub(crate) fn tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Option<&SingleNodeTenantDomain> {
        self.tenant_domains
            .values()
            .find(|row| row.tenant_id == tenant_id && row.domain_id == domain_id)
    }

    pub(crate) fn rule_set(&self, rule_set_id: i64) -> Option<&SingleNodeRuleSet> {
        self.rule_sets.get(&rule_set_id)
    }

    pub fn identity_card_by_user(&self, user_id: i64) -> Option<&SingleNodeIdentityCard> {
        self.identity_card_by_user
            .get(&user_id)
            .and_then(|card_id| self.identity_cards.get(card_id))
    }

    pub fn user_cards_for_user(&self, user_id: i64) -> impl Iterator<Item = &SingleNodeUserCard> {
        self.user_cards_by_user
            .get(&user_id)
            .into_iter()
            .flatten()
            .filter_map(|card_id| self.user_cards.get(card_id))
    }

    pub fn user_cards_for_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: Option<i64>,
    ) -> impl Iterator<Item = &SingleNodeUserCard> {
        self.user_cards_by_tenant_domain
            .get(&(tenant_id, domain_id))
            .into_iter()
            .flatten()
            .filter_map(|card_id| self.user_cards.get(card_id))
    }

    pub fn rule_set_bindings_for_card(
        &self,
        card_id: i64,
    ) -> impl Iterator<Item = &SingleNodeCardRuleSetRef> {
        self.rule_sets_by_card
            .get(&card_id)
            .into_iter()
            .flatten()
            .filter_map(|binding_id| self.card_rule_set_refs.get(binding_id))
    }

    pub fn rule_set_entries(
        &self,
        rule_set_id: i64,
    ) -> impl Iterator<Item = &SingleNodeRuleSetEntry> {
        self.entries_by_rule_set
            .get(&rule_set_id)
            .into_iter()
            .flatten()
            .filter_map(|entry_id| self.rule_set_entries.get(entry_id))
    }

    pub fn permission_rules_for_card(
        &self,
        card_id: i64,
    ) -> impl Iterator<Item = &SingleNodePermissionRule> {
        self.permission_rules_by_card
            .get(&card_id)
            .into_iter()
            .flatten()
            .filter_map(|rule_id| self.permission_rules.get(rule_id))
    }

    fn canonical_digest(&self, guard: &BuildGuard) -> Result<String, SingleNodeMemoryRootError> {
        write_budgeted(
            &(
                &self.version,
                MapPairs(&self.users),
                MapPairs(&self.identity_cards),
                MapPairs(&self.user_cards),
                MapPairs(&self.tenants),
                MapPairs(&self.domains),
                MapPairs(&self.tenant_domains),
                MapPairs(&self.org_memberships),
                MapPairs(&self.rule_sets),
                MapPairs(&self.rule_set_entries),
                MapPairs(&self.card_rule_set_refs),
                MapPairs(&self.permission_rules),
                MapPairs(&self.published_pointers),
                MapPairs(&self.global_admins),
                MapPairs(&self.sod_policies),
            ),
            guard,
            guard.budget.max_canonical_bytes,
            "canonical byte limit exceeded",
            true,
        )?
        .ok_or_else(|| budget_error("canonical digest unavailable"))
    }
}

fn unique_map<T, F>(
    rows: Vec<T>,
    entity: &'static str,
    key: F,
    guard: &BuildGuard,
) -> Result<BTreeMap<i64, T>, SingleNodeMemoryRootError>
where
    F: Fn(&T) -> i64,
{
    let mut result = BTreeMap::new();
    for row in rows {
        guard.check_time()?;
        let value = key(&row);
        if value <= 0 {
            return Err(SingleNodeMemoryRootError::NonPositiveId {
                entity,
                field: "primary_key",
            });
        }
        if result.insert(value, row).is_some() {
            return Err(SingleNodeMemoryRootError::Duplicate {
                entity,
                key: value.to_string(),
            });
        }
    }
    Ok(result)
}

fn unique_string_map<T, F>(
    rows: Vec<T>,
    entity: &'static str,
    key: F,
    guard: &BuildGuard,
) -> Result<BTreeMap<String, T>, SingleNodeMemoryRootError>
where
    F: Fn(&T) -> String,
{
    let mut result = BTreeMap::new();
    for row in rows {
        guard.check_time()?;
        let value = key(&row);
        validate_text(entity, "primary_key", &value)?;
        if result.insert(value.clone(), row).is_some() {
            return Err(SingleNodeMemoryRootError::Duplicate { entity, key: value });
        }
    }
    Ok(result)
}

fn positive(
    entity: &'static str,
    field: &'static str,
    value: i64,
) -> Result<(), SingleNodeMemoryRootError> {
    (value > 0)
        .then_some(())
        .ok_or(SingleNodeMemoryRootError::NonPositiveId { entity, field })
}

fn validate_text(
    entity: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), SingleNodeMemoryRootError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(|character| character.is_control())
    {
        return Err(SingleNodeMemoryRootError::InvalidText { entity, field });
    }
    Ok(())
}

fn validate_digest(
    entity: &'static str,
    field: &'static str,
    value: &str,
) -> Result<(), SingleNodeMemoryRootError> {
    if value.len() != SHA256_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SingleNodeMemoryRootError::InvalidText { entity, field });
    }
    Ok(())
}

fn validate_window(
    entity: &'static str,
    from: Option<i64>,
    to: Option<i64>,
) -> Result<(), SingleNodeMemoryRootError> {
    if let (Some(from), Some(to)) = (from, to) {
        if from >= to {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity,
                detail: "validity window is empty or inverted".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_tenants(
    rows: &BTreeMap<i64, SingleNodeTenant>,
    guard: &BuildGuard,
) -> Result<(), SingleNodeMemoryRootError> {
    let mut done = BTreeSet::new();
    for &id in rows.keys() {
        guard.check_time()?;
        let mut path = BTreeSet::new();
        let mut current = Some(id);
        while let Some(tenant_id) = current {
            guard.check_time()?;
            if done.contains(&tenant_id) {
                break;
            }
            if !path.insert(tenant_id) {
                return Err(SingleNodeMemoryRootError::InvalidValue {
                    entity: "tenant",
                    detail: "parent relationship contains a cycle".to_owned(),
                });
            }
            let Some(tenant) = rows.get(&tenant_id) else {
                return missing("tenant", "tenant.parent_tenant_id", tenant_id);
            };
            current = tenant.parent_tenant_id;
        }
        done.extend(path);
    }
    Ok(())
}

fn validate_users(rows: &BTreeMap<i64, SingleNodeUser>) -> Result<(), SingleNodeMemoryRootError> {
    for row in rows.values() {
        positive("platform_user", "user_id", row.user_id)?;
        validate_text("platform_user", "status", &row.status)?;
    }
    Ok(())
}

fn validate_identity_cards(
    rows: &BTreeMap<i64, SingleNodeIdentityCard>,
    users: &BTreeMap<i64, SingleNodeUser>,
) -> Result<(), SingleNodeMemoryRootError> {
    for row in rows.values() {
        positive("identity_card", "card_id", row.card_id)?;
        positive("identity_card", "user_id", row.user_id)?;
        if !users.contains_key(&row.user_id) {
            return missing("identity_card", "platform_user", row.user_id);
        }
        validate_text("identity_card", "status", &row.status)?;
        if let Some(expires_at) = row.expires_at_unix {
            if expires_at <= 0 {
                return Err(SingleNodeMemoryRootError::InvalidValue {
                    entity: "identity_card",
                    detail: "expires_at_unix must be positive".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn validate_tenant_domains(
    rows: &BTreeMap<i64, SingleNodeTenantDomain>,
    tenants: &BTreeMap<i64, SingleNodeTenant>,
    domains: &BTreeMap<i64, SingleNodeDomain>,
) -> Result<(), SingleNodeMemoryRootError> {
    let mut pairs = BTreeSet::new();
    for row in rows.values() {
        positive("tenant_domain_map", "id", row.id)?;
        positive("tenant_domain_map", "tenant_id", row.tenant_id)?;
        positive("tenant_domain_map", "domain_id", row.domain_id)?;
        validate_text("tenant_domain_map", "status", &row.status)?;
        if tenants.get(&row.tenant_id).is_none() {
            return missing("tenant_domain_map", "tenant", row.tenant_id);
        }
        if domains.get(&row.domain_id).is_none() {
            return missing("tenant_domain_map", "platform_domain", row.domain_id);
        }
        if !pairs.insert((row.tenant_id, row.domain_id)) {
            return Err(SingleNodeMemoryRootError::Duplicate {
                entity: "tenant_domain_map",
                key: format!("{}/{}", row.tenant_id, row.domain_id),
            });
        }
    }
    Ok(())
}

fn validate_user_cards(
    rows: &BTreeMap<i64, SingleNodeUserCard>,
    users: &BTreeMap<i64, SingleNodeUser>,
    identity_cards: &BTreeMap<i64, SingleNodeIdentityCard>,
    tenants: &BTreeMap<i64, SingleNodeTenant>,
    domains: &BTreeMap<i64, SingleNodeDomain>,
) -> Result<(), SingleNodeMemoryRootError> {
    let identity_users: BTreeSet<_> = identity_cards.values().map(|card| card.user_id).collect();
    for row in rows.values() {
        row.validate()?;
        if let Some(user_id) = row.user_id {
            if !users.contains_key(&user_id) {
                return missing("user_card", "platform_user", user_id);
            }
        }
        if tenants.get(&row.tenant_id).is_none() {
            return missing("user_card", "tenant", row.tenant_id);
        }
        if let Some(domain_id) = row.domain_id {
            if domains.get(&domain_id).is_none() {
                return missing("user_card", "platform_domain", domain_id);
            }
        }
        if row.status == "ACTIVE" {
            let Some(user_id) = row.user_id else {
                return Err(SingleNodeMemoryRootError::InvalidValue {
                    entity: "user_card",
                    detail: format!("active card {} has no user_id", row.card_id),
                });
            };
            if !identity_users.contains(&user_id) {
                return missing("user_card", "identity_card.user_id", user_id);
            }
        }
    }
    Ok(())
}

fn validate_memberships(
    rows: &BTreeMap<String, SingleNodeOrgMembership>,
    identity_cards: &BTreeMap<i64, SingleNodeIdentityCard>,
    user_cards: &BTreeMap<i64, SingleNodeUserCard>,
    tenants: &BTreeMap<i64, SingleNodeTenant>,
) -> Result<(), SingleNodeMemoryRootError> {
    for row in rows.values() {
        positive("org_scope_membership", "tenant_id", row.tenant_id)?;
        positive("org_scope_membership", "user_id", row.user_id)?;
        positive(
            "org_scope_membership",
            "identity_card_id",
            row.identity_card_id,
        )?;
        positive("org_scope_membership", "card_id", row.card_id)?;
        if row.revision == 0 {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "org_scope_membership",
                detail: "revision must be positive".to_owned(),
            });
        }
        if tenants.get(&row.tenant_id).is_none() {
            return missing("org_scope_membership", "tenant", row.tenant_id);
        }
        let Some(identity) = identity_cards.get(&row.identity_card_id) else {
            return missing(
                "org_scope_membership",
                "identity_card",
                row.identity_card_id,
            );
        };
        let Some(card) = user_cards.get(&row.card_id) else {
            return missing("org_scope_membership", "user_card", row.card_id);
        };
        if identity.user_id != row.user_id || card.user_id != Some(row.user_id) {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "org_scope_membership",
                detail: "user/card/identity relationship is inconsistent".to_owned(),
            });
        }
        if card.tenant_id != row.tenant_id {
            return Err(SingleNodeMemoryRootError::TenantMismatch {
                entity: "org_scope_membership",
                expected: card.tenant_id,
                actual: row.tenant_id,
            });
        }
    }
    Ok(())
}

fn validate_rule_sets(
    rows: &BTreeMap<i64, SingleNodeRuleSet>,
    tenants: &BTreeMap<i64, SingleNodeTenant>,
) -> Result<(), SingleNodeMemoryRootError> {
    let mut codes = BTreeSet::new();
    for row in rows.values() {
        positive("rule_set", "rule_set_id", row.rule_set_id)?;
        validate_text("rule_set", "code", &row.code)?;
        validate_text("rule_set", "source_type", &row.source_type)?;
        validate_text("rule_set", "status", &row.status)?;
        if !codes.insert(row.code.clone()) {
            return Err(SingleNodeMemoryRootError::Duplicate {
                entity: "rule_set",
                key: row.code.clone(),
            });
        }
        if let Some(tenant_id) = row.tenant_id {
            if tenants.get(&tenant_id).is_none() {
                return missing("rule_set", "tenant", tenant_id);
            }
        }
        if let Some(source_id) = row.source_id {
            if source_id <= 0 {
                return Err(SingleNodeMemoryRootError::NonPositiveId {
                    entity: "rule_set",
                    field: "source_id",
                });
            }
        }
    }
    Ok(())
}

fn validate_rule_set_entries(
    rows: &BTreeMap<i64, SingleNodeRuleSetEntry>,
    rule_sets: &BTreeMap<i64, SingleNodeRuleSet>,
) -> Result<(), SingleNodeMemoryRootError> {
    for row in rows.values() {
        positive("rule_set_entry", "entry_id", row.entry_id)?;
        positive("rule_set_entry", "rule_set_id", row.rule_set_id)?;
        if rule_sets.get(&row.rule_set_id).is_none() {
            return missing("rule_set_entry", "rule_set", row.rule_set_id);
        }
        validate_text("rule_set_entry", "resource_type", &row.resource_type)?;
        validate_text("rule_set_entry", "action_code", &row.action_code)?;
        if let Some(resource_id) = row.resource_id {
            positive("rule_set_entry", "resource_id", resource_id)?;
        }
        if let Some(condition) = row.condition_json.as_deref() {
            validate_text("rule_set_entry", "condition_json", condition)?;
        }
        row.validity
            .validate()
            .map_err(|error| SingleNodeMemoryRootError::InvalidValue {
                entity: "rule_set_entry",
                detail: error.to_string(),
            })?;
    }
    Ok(())
}

fn validate_bindings(
    rows: &BTreeMap<i64, SingleNodeCardRuleSetRef>,
    user_cards: &BTreeMap<i64, SingleNodeUserCard>,
    rule_sets: &BTreeMap<i64, SingleNodeRuleSet>,
) -> Result<(), SingleNodeMemoryRootError> {
    let mut pairs = BTreeSet::new();
    for row in rows.values() {
        positive("card_rule_set_ref", "id", row.binding_id)?;
        positive("card_rule_set_ref", "card_id", row.card_id)?;
        positive("card_rule_set_ref", "rule_set_id", row.rule_set_id)?;
        positive("card_rule_set_ref", "tenant_id", row.tenant_id)?;
        let Some(card) = user_cards.get(&row.card_id) else {
            return missing("card_rule_set_ref", "user_card", row.card_id);
        };
        let Some(rule_set) = rule_sets.get(&row.rule_set_id) else {
            return missing("card_rule_set_ref", "rule_set", row.rule_set_id);
        };
        if card.tenant_id != row.tenant_id {
            return Err(SingleNodeMemoryRootError::TenantMismatch {
                entity: "card_rule_set_ref",
                expected: card.tenant_id,
                actual: row.tenant_id,
            });
        }
        if let Some(rule_set_tenant_id) = rule_set.tenant_id {
            if rule_set_tenant_id != row.tenant_id {
                return Err(SingleNodeMemoryRootError::TenantMismatch {
                    entity: "card_rule_set_ref",
                    expected: row.tenant_id,
                    actual: rule_set_tenant_id,
                });
            }
        }
        if !matches!(
            row.binding_layer,
            BindingLayer::Base | BindingLayer::Overlay
        ) {
            return Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "card_rule_set_ref",
                detail: "binding layer must be BASE or OVERLAY".to_owned(),
            });
        }
        if !pairs.insert((row.card_id, row.rule_set_id)) {
            return Err(SingleNodeMemoryRootError::Duplicate {
                entity: "card_rule_set_ref",
                key: format!("{}/{}", row.card_id, row.rule_set_id),
            });
        }
    }
    Ok(())
}

fn validate_permission_rules(
    rows: &BTreeMap<i64, SingleNodePermissionRule>,
    user_cards: &BTreeMap<i64, SingleNodeUserCard>,
) -> Result<(), SingleNodeMemoryRootError> {
    for row in rows.values() {
        positive("permission_rule", "rule_id", row.rule_id)?;
        positive("permission_rule", "card_id", row.card_id)?;
        positive("permission_rule", "tenant_id", row.tenant_id)?;
        let Some(card) = user_cards.get(&row.card_id) else {
            return missing("permission_rule", "user_card", row.card_id);
        };
        if card.tenant_id != row.tenant_id {
            return Err(SingleNodeMemoryRootError::TenantMismatch {
                entity: "permission_rule",
                expected: card.tenant_id,
                actual: row.tenant_id,
            });
        }
        validate_text("permission_rule", "resource_type", &row.resource_type)?;
        validate_text("permission_rule", "action_code", &row.action_code)?;
        validate_text("permission_rule", "source_type", &row.source_type)?;
        if let Some(condition) = row.condition_json.as_deref() {
            if condition.len() > MAX_TEXT_BYTES || condition.contains('\0') {
                return Err(SingleNodeMemoryRootError::InvalidText {
                    entity: "permission_rule",
                    field: "condition_json",
                });
            }
        }
        if let Some(resource_id) = row.resource_id {
            positive("permission_rule", "resource_id", resource_id)?;
        }
        if let Some(source_id) = row.source_id {
            positive("permission_rule", "source_id", source_id)?;
        }
        row.validity
            .validate()
            .map_err(|error| SingleNodeMemoryRootError::InvalidValue {
                entity: "permission_rule",
                detail: error.to_string(),
            })?;
    }
    Ok(())
}

fn validate_sod_policies(
    rows: &BTreeMap<i64, CertifiedSodPolicy>,
) -> Result<(), SingleNodeMemoryRootError> {
    for policy in rows.values() {
        policy
            .validate()
            .map_err(|error| SingleNodeMemoryRootError::InvalidValue {
                entity: "sod_policy",
                detail: error,
            })?;
    }
    Ok(())
}

fn missing(
    entity: &'static str,
    target: &'static str,
    key: i64,
) -> Result<(), SingleNodeMemoryRootError> {
    Err(SingleNodeMemoryRootError::MissingReference {
        entity,
        target,
        key: key.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version() -> SingleNodeRootVersion {
        SingleNodeRootVersion {
            source_snapshot_id: "mysql-snapshot-1".to_owned(),
            generation: 7,
            dependency_frontier_digest: "ab".repeat(32),
            revoke_watermark: 2,
        }
    }

    fn snapshot() -> SingleNodeDatabaseSnapshot {
        SingleNodeDatabaseSnapshot {
            version: version(),
            users: vec![SingleNodeUser {
                user_id: 20,
                status: "ACTIVE".to_owned(),
                deleted_at_unix: None,
            }],
            identity_cards: vec![SingleNodeIdentityCard {
                card_id: 10,
                user_id: 20,
                status: "ACTIVE".to_owned(),
                expires_at_unix: None,
            }],
            user_cards: vec![SingleNodeUserCard {
                card_id: 30,
                user_id: Some(20),
                tenant_id: 40,
                domain_id: Some(50),
                status: "ACTIVE".to_owned(),
                valid_from_unix: None,
                valid_to_unix: None,
            }],
            tenants: vec![SingleNodeTenant {
                tenant_id: 40,
                tenant_code: "tenant-a".to_owned(),
                parent_tenant_id: None,
            }],
            domains: vec![SingleNodeDomain {
                domain_id: 50,
                domain_code: Some("domain-a".to_owned()),
            }],
            tenant_domains: vec![SingleNodeTenantDomain {
                id: 60,
                tenant_id: 40,
                domain_id: 50,
                status: "ACTIVE".to_owned(),
            }],
            org_memberships: vec![],
            rule_sets: vec![SingleNodeRuleSet {
                rule_set_id: 70,
                code: "base-a".to_owned(),
                tenant_id: Some(40),
                source_type: "MANUAL".to_owned(),
                source_id: Some(70),
                status: "ACTIVE".to_owned(),
            }],
            rule_set_entries: vec![SingleNodeRuleSetEntry {
                entry_id: 80,
                rule_set_id: 70,
                resource_type: "device".to_owned(),
                resource_id: Some(90),
                action_code: "read".to_owned(),
                effect: GrantEffect::Allow,
                condition_json: None,
                priority: 1,
                enabled: true,
                validity: ValidityWindow::perpetual(),
            }],
            card_rule_set_refs: vec![SingleNodeCardRuleSetRef {
                binding_id: 100,
                card_id: 30,
                rule_set_id: 70,
                tenant_id: 40,
                binding_layer: BindingLayer::Base,
            }],
            permission_rules: vec![],
            published_pointers: vec![SingleNodePublishedPointer {
                pointer_id: 110,
                tenant_id: 40,
                aggregate_type: "CARD".to_owned(),
                aggregate_id: 30,
                current_generation: 7,
                manifest_id: 120,
                manifest_digest: "cd".repeat(32),
                status: "READY".to_owned(),
                revoke_fence: 2,
                revoke_fence_proven: true,
            }],
            global_admins: vec![SingleNodeGlobalAdmin {
                id: 130,
                user_id: 20,
                active: false,
            }],
            sod_policies: vec![],
        }
    }

    #[test]
    fn candidate_budget_rejects_truncation_and_expired_builds() {
        let budget = SingleNodeRootBuildBudget::default();
        for budget in [
            SingleNodeRootBuildBudget {
                max_rows: 0,
                ..budget
            },
            SingleNodeRootBuildBudget {
                max_snapshot_bytes: 1,
                ..budget
            },
            SingleNodeRootBuildBudget {
                max_canonical_bytes: 1,
                ..budget
            },
            SingleNodeRootBuildBudget {
                max_build_time: Duration::ZERO,
                ..budget
            },
        ] {
            assert!(matches!(
                SingleNodeMemoryRoot::build_with_budget(snapshot(), budget),
                Err(SingleNodeMemoryRootError::InvalidValue {
                    entity: "root_budget",
                    ..
                })
            ));
        }
        assert!(SingleNodeMemoryRoot::build_with_budget(snapshot(), budget).is_ok());
    }

    #[test]
    fn streamed_digest_preserves_previous_canonical_bytes() {
        let root = SingleNodeMemoryRoot::build(snapshot()).unwrap();
        let bytes = serde_json::to_vec(&(
            &root.version,
            root.users.iter().collect::<Vec<_>>(),
            root.identity_cards.iter().collect::<Vec<_>>(),
            root.user_cards.iter().collect::<Vec<_>>(),
            root.tenants.iter().collect::<Vec<_>>(),
            root.domains.iter().collect::<Vec<_>>(),
            root.tenant_domains.iter().collect::<Vec<_>>(),
            root.org_memberships.iter().collect::<Vec<_>>(),
            root.rule_sets.iter().collect::<Vec<_>>(),
            root.rule_set_entries.iter().collect::<Vec<_>>(),
            root.card_rule_set_refs.iter().collect::<Vec<_>>(),
            root.permission_rules.iter().collect::<Vec<_>>(),
            root.published_pointers.iter().collect::<Vec<_>>(),
            root.global_admins.iter().collect::<Vec<_>>(),
            root.sod_policies.iter().collect::<Vec<_>>(),
        ))
        .unwrap();
        assert_eq!(root.content_digest(), hex::encode(Sha256::digest(bytes)));
    }

    #[test]
    fn duplicate_publication_pointer_primary_key_is_rejected() {
        let mut candidate = snapshot();
        let mut other = candidate.published_pointers[0].clone();
        other.aggregate_id += 1;
        candidate.published_pointers.push(other);
        assert!(matches!(
            SingleNodeMemoryRoot::build(candidate),
            Err(SingleNodeMemoryRootError::Duplicate {
                entity: "authorization_projection_current",
                ..
            })
        ));
    }

    #[test]
    fn tenant_parent_requires_existing_acyclic_chain() {
        let mut candidate = snapshot();
        candidate.tenants[0].parent_tenant_id = Some(999);
        assert!(matches!(
            SingleNodeMemoryRoot::build(candidate),
            Err(SingleNodeMemoryRootError::MissingReference {
                entity: "tenant",
                ..
            })
        ));
        let mut candidate = snapshot();
        candidate.tenants[0].parent_tenant_id = Some(40);
        assert!(matches!(
            SingleNodeMemoryRoot::build(candidate),
            Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "tenant",
                ..
            })
        ));
    }

    #[test]
    fn builds_database_key_root_and_derived_indexes() {
        let root = SingleNodeMemoryRoot::build(snapshot()).expect("root should build");
        assert_eq!(
            root.identity_card_by_user(20).map(|row| row.card_id),
            Some(10)
        );
        assert_eq!(
            root.user_cards_for_user(20)
                .map(|row| row.card_id)
                .collect::<Vec<_>>(),
            vec![30]
        );
        assert_eq!(
            root.rule_set_bindings_for_card(30)
                .map(|row| row.binding_id)
                .collect::<Vec<_>>(),
            vec![100]
        );
        assert_eq!(
            root.rule_set_entries(70)
                .map(|row| row.entry_id)
                .collect::<Vec<_>>(),
            vec![80]
        );
        assert_eq!(root.content_digest().len(), SHA256_HEX_LEN);
    }

    #[test]
    fn digest_is_independent_of_snapshot_row_order() {
        let first = SingleNodeMemoryRoot::build(snapshot()).expect("first root");
        let mut second_snapshot = snapshot();
        second_snapshot.identity_cards.reverse();
        second_snapshot.user_cards.reverse();
        second_snapshot.rule_set_entries.reverse();
        second_snapshot.card_rule_set_refs.reverse();
        let second = SingleNodeMemoryRoot::build(second_snapshot).expect("second root");
        assert_eq!(first.content_digest(), second.content_digest());
    }

    #[test]
    fn user_state_changes_root_digest() {
        let first = SingleNodeMemoryRoot::build(snapshot()).expect("first root");
        let mut input = snapshot();
        input.users[0].status = "DISABLED".to_owned();
        input.users[0].deleted_at_unix = Some(123);
        let second = SingleNodeMemoryRoot::build(input).expect("second root");
        assert_ne!(first.content_digest(), second.content_digest());
        assert_eq!(
            second.user(20).and_then(|user| user.deleted_at_unix),
            Some(123)
        );
    }

    #[test]
    fn missing_user_references_are_rejected() {
        let mut input = snapshot();
        input.identity_cards[0].user_id = 999;
        assert!(matches!(
            SingleNodeMemoryRoot::build(input),
            Err(SingleNodeMemoryRootError::MissingReference {
                entity: "identity_card",
                target: "platform_user",
                ..
            })
        ));

        let mut input = snapshot();
        input.user_cards[0].status = "INACTIVE".to_owned();
        input.user_cards[0].user_id = Some(999);
        assert!(matches!(
            SingleNodeMemoryRoot::build(input),
            Err(SingleNodeMemoryRootError::MissingReference {
                entity: "user_card",
                target: "platform_user",
                ..
            })
        ));
    }

    #[test]
    fn direct_rule_preserves_condition_priority_and_effect() {
        let mut input = snapshot();
        input.permission_rules.push(SingleNodePermissionRule {
            rule_id: 121,
            card_id: 30,
            tenant_id: 40,
            resource_type: "device".to_owned(),
            resource_id: Some(90),
            action_code: "read".to_owned(),
            effect: GrantEffect::Allow,
            condition_json: Some("{\"region\":\"local\"}".to_owned()),
            priority: 3,
            source_type: "MANUAL".to_owned(),
            source_id: None,
            enabled: true,
            validity: ValidityWindow::perpetual(),
        });
        let root = SingleNodeMemoryRoot::build(input.clone()).expect("root");
        let rule = root.permission_rules_for_card(30).next().expect("rule");
        assert_eq!(
            rule.condition_json.as_deref(),
            Some("{\"region\":\"local\"}")
        );
        assert_eq!(rule.priority, 3);
        assert_eq!(rule.effect, GrantEffect::Allow);
        input.permission_rules[0].priority = 4;
        let changed = SingleNodeMemoryRoot::build(input).expect("changed root");
        assert_ne!(root.content_digest(), changed.content_digest());
    }

    #[test]
    fn global_admin_preserves_primary_key_and_user_uniqueness() {
        let first = SingleNodeMemoryRoot::build(snapshot()).expect("first root");
        let mut input = snapshot();
        input.global_admins[0].id = 131;
        let second = SingleNodeMemoryRoot::build(input.clone()).expect("second root");
        assert_ne!(first.content_digest(), second.content_digest());
        input.global_admins.push(SingleNodeGlobalAdmin {
            id: 132,
            user_id: 20,
            active: true,
        });
        assert!(matches!(
            SingleNodeMemoryRoot::build(input),
            Err(SingleNodeMemoryRootError::Duplicate {
                entity: "identity_global_admin",
                ..
            })
        ));
    }

    #[test]
    fn missing_rule_set_reference_blocks_serving_root() {
        let mut input = snapshot();
        input.rule_set_entries[0].rule_set_id = 999;
        assert!(matches!(
            SingleNodeMemoryRoot::build(input),
            Err(SingleNodeMemoryRootError::MissingReference {
                entity: "rule_set_entry",
                target: "rule_set",
                ..
            })
        ));
    }

    #[test]
    fn duplicate_card_rule_set_pair_is_rejected_even_with_different_binding_rows() {
        let mut input = snapshot();
        input.card_rule_set_refs.push(SingleNodeCardRuleSetRef {
            binding_id: 101,
            card_id: 30,
            rule_set_id: 70,
            tenant_id: 40,
            binding_layer: BindingLayer::Overlay,
        });
        assert!(matches!(
            SingleNodeMemoryRoot::build(input),
            Err(SingleNodeMemoryRootError::Duplicate {
                entity: "card_rule_set_ref",
                ..
            })
        ));
    }

    #[test]
    fn scope_generation_is_not_compared_to_root_version() {
        let mut input = snapshot();
        input.published_pointers[0].current_generation = input.version.generation + 1;
        assert!(SingleNodeMemoryRoot::build(input).is_ok());
    }

    #[test]
    fn unproven_publication_fence_blocks_root() {
        let mut input = snapshot();
        input.published_pointers[0].revoke_fence_proven = false;
        assert!(matches!(
            SingleNodeMemoryRoot::build(input),
            Err(SingleNodeMemoryRootError::InvalidValue {
                entity: "authorization_projection_current",
                ..
            })
        ));
    }
}
