//! Isolated memory—v1 candidate facts and derived lookup indexes.
//!
//! Validation covers only the supplied relationships. It does not prove input
//! coverage, provenance, freshness, eligibility, confirmation validity, audit,
//! persistence or authorization. This module is not an authorization reader.
//! Version, scope, operation and time fields are opaque bytes; in particular,
//! no rule-set version catalog is present to verify version references.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// A candidate user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub user_id: i64,
}

/// A candidate tenant; its parent relationship does not grant permissions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub tenant_id: i64,
    pub parent_tenant_id: Option<i64>,
}

/// A tenant-independent identity card.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityCard {
    pub identity_card_id: i64,
    pub user_id: i64,
}

/// A user's card in a particular tenant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCard {
    pub user_card_id: i64,
    pub user_id: i64,
    pub tenant_id: i64,
}

/// A rule-set identity and its administrative owner, without rule content.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSet {
    pub rule_set_id: i64,
    pub owner_tenant_id: i64,
}

/// The binding layer, not a rule-set source or an authorization decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingLayer {
    Base,
    Overlay,
}

/// An independent candidate binding; its tenant must match its card's tenant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub binding_id: i64,
    pub user_card_id: i64,
    pub tenant_id: i64,
    pub rule_set_id: i64,
    pub layer: BindingLayer,
}

/// A traceability candidate, not proof that a binding was validly confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingConfirmation {
    pub confirmation_id: i64,
    pub binding_id: i64,
    pub rule_set_id: i64,
    pub confirmer_user_id: i64,
    pub version_bytes: Vec<u8>,
    pub scope_bytes: Vec<u8>,
    pub operation_id: Vec<u8>,
    pub confirmed_at_bytes: Vec<u8>,
}

/// A traceability candidate for a rule-set change; its effect is unspecified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleSetChangeConfirmation {
    pub confirmation_id: i64,
    pub rule_set_id: i64,
    pub confirmer_user_id: i64,
    pub version_bytes: Vec<u8>,
    pub affected_scope_bytes: Vec<u8>,
    pub operation_id: Vec<u8>,
    pub confirmed_at_bytes: Vec<u8>,
}

/// Caller-supplied facts. Deserialization alone does not validate them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateFacts {
    pub users: Vec<User>,
    pub tenants: Vec<Tenant>,
    pub identity_cards: Vec<IdentityCard>,
    pub user_cards: Vec<UserCard>,
    pub rule_sets: Vec<RuleSet>,
    pub bindings: Vec<Binding>,
    pub binding_confirmations: Vec<BindingConfirmation>,
    pub rule_set_change_confirmations: Vec<RuleSetChangeConfirmation>,
}

/// Candidate row kinds. Confirmation identities are unique within each kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entity {
    User,
    Tenant,
    IdentityCard,
    UserCard,
    RuleSet,
    Binding,
    BindingConfirmation,
    RuleSetChangeConfirmation,
}

/// Internal consistency failure in the supplied candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    NonPositiveId {
        entity: Entity,
        field: &'static str,
        value: i64,
    },
    DuplicateId {
        entity: Entity,
        id: i64,
    },
    MissingReference {
        entity: Entity,
        target: Entity,
        id: i64,
    },
    MissingIdentityCard {
        user_id: i64,
    },
    DuplicateIdentityCard {
        user_id: i64,
    },
    TenantCycle {
        tenant_id: i64,
    },
    BindingTenantMismatch {
        binding_id: i64,
        binding_tenant_id: i64,
        card_tenant_id: i64,
    },
    ConfirmationRuleSetMismatch {
        confirmation_id: i64,
        binding_rule_set_id: i64,
        confirmation_rule_set_id: i64,
    },
}

/// A validated, immutable view derived from one borrowed candidate.
///
/// Borrowing prevents mutation of the candidate while this index exists. Empty
/// results describe this input only; they are not proof of complete coverage.
pub struct FactsIndex<'a> {
    users: BTreeMap<i64, &'a User>,
    tenants: BTreeMap<i64, &'a Tenant>,
    identities_by_user: BTreeMap<i64, &'a IdentityCard>,
    cards: BTreeMap<i64, &'a UserCard>,
    rule_sets: BTreeMap<i64, &'a RuleSet>,
    bindings_by_card: BTreeMap<i64, Vec<&'a Binding>>,
    confirmations_by_binding: BTreeMap<i64, Vec<&'a BindingConfirmation>>,
    changes_by_rule_set: BTreeMap<i64, Vec<&'a RuleSetChangeConfirmation>>,
}

/// Candidate relationships for one supplied user card.
pub struct CardFacts<'a> {
    pub card: &'a UserCard,
    pub user: &'a User,
    pub identity_card: &'a IdentityCard,
    pub tenant: &'a Tenant,
    pub bindings: &'a [&'a Binding],
}

// memory—v1: Reject nonpositive row and reference identifiers.
fn positive(entity: Entity, field: &'static str, value: i64) -> Result<(), ValidationError> {
    if value <= 0 {
        return Err(ValidationError::NonPositiveId {
            entity,
            field,
            value,
        });
    }
    Ok(())
}

// memory—v1: Index one row without replacing an earlier row of the same kind.
fn insert<'a, T>(
    map: &mut BTreeMap<i64, &'a T>,
    entity: Entity,
    field: &'static str,
    id: i64,
    row: &'a T,
) -> Result<(), ValidationError> {
    positive(entity, field, id)?;
    if map.insert(id, row).is_some() {
        return Err(ValidationError::DuplicateId { entity, id });
    }
    Ok(())
}

// memory—v1: Check positive references against the supplied candidate only.
fn require<'a, T>(
    map: &BTreeMap<i64, &'a T>,
    entity: Entity,
    field: &'static str,
    target: Entity,
    id: i64,
) -> Result<&'a T, ValidationError> {
    positive(entity, field, id)?;
    map.get(&id)
        .copied()
        .ok_or(ValidationError::MissingReference { entity, target, id })
}

impl CandidateFacts {
    /// memory—v1: Validate relationships and build an immutable per-card index.
    ///
    /// A successful result is internal consistency only. Rule-set and card
    /// owners may differ, and repeated card/rule-set pairs remain distinct.
    pub fn build_index(&self) -> Result<FactsIndex<'_>, ValidationError> {
        let mut users = BTreeMap::new();
        let mut tenants = BTreeMap::new();
        let mut identity_ids = BTreeMap::new();
        let mut identities_by_user = BTreeMap::new();
        let mut cards = BTreeMap::new();
        let mut rule_sets = BTreeMap::new();
        let mut bindings = BTreeMap::new();
        let mut binding_confirmation_ids = BTreeMap::new();
        let mut change_confirmation_ids = BTreeMap::new();
        let mut bindings_by_card: BTreeMap<i64, Vec<&Binding>> = BTreeMap::new();
        let mut confirmations_by_binding: BTreeMap<i64, Vec<&BindingConfirmation>> =
            BTreeMap::new();
        let mut changes_by_rule_set: BTreeMap<i64, Vec<&RuleSetChangeConfirmation>> =
            BTreeMap::new();

        for row in &self.users {
            insert(&mut users, Entity::User, "user_id", row.user_id, row)?;
        }
        for row in &self.tenants {
            insert(
                &mut tenants,
                Entity::Tenant,
                "tenant_id",
                row.tenant_id,
                row,
            )?;
        }
        for row in &self.tenants {
            if let Some(parent) = row.parent_tenant_id {
                require(
                    &tenants,
                    Entity::Tenant,
                    "parent_tenant_id",
                    Entity::Tenant,
                    parent,
                )?;
            }
        }
        // Iterative traversal avoids stack overflow on deeply nested tenants.
        let mut complete = BTreeSet::new();
        for id in tenants.keys() {
            let mut path = BTreeSet::new();
            let mut current = *id;
            while !complete.contains(&current) {
                if !path.insert(current) {
                    return Err(ValidationError::TenantCycle { tenant_id: current });
                }
                match tenants[&current].parent_tenant_id {
                    Some(parent) => current = parent,
                    None => break,
                }
            }
            complete.extend(path);
        }
        for row in &self.identity_cards {
            insert(
                &mut identity_ids,
                Entity::IdentityCard,
                "identity_card_id",
                row.identity_card_id,
                row,
            )?;
            require(
                &users,
                Entity::IdentityCard,
                "user_id",
                Entity::User,
                row.user_id,
            )?;
            if identities_by_user.insert(row.user_id, row).is_some() {
                return Err(ValidationError::DuplicateIdentityCard {
                    user_id: row.user_id,
                });
            }
        }
        for id in users.keys() {
            if !identities_by_user.contains_key(id) {
                return Err(ValidationError::MissingIdentityCard { user_id: *id });
            }
        }
        for row in &self.user_cards {
            insert(
                &mut cards,
                Entity::UserCard,
                "user_card_id",
                row.user_card_id,
                row,
            )?;
            require(
                &users,
                Entity::UserCard,
                "user_id",
                Entity::User,
                row.user_id,
            )?;
            require(
                &tenants,
                Entity::UserCard,
                "tenant_id",
                Entity::Tenant,
                row.tenant_id,
            )?;
        }
        for row in &self.rule_sets {
            insert(
                &mut rule_sets,
                Entity::RuleSet,
                "rule_set_id",
                row.rule_set_id,
                row,
            )?;
            require(
                &tenants,
                Entity::RuleSet,
                "owner_tenant_id",
                Entity::Tenant,
                row.owner_tenant_id,
            )?;
        }
        for row in &self.bindings {
            insert(
                &mut bindings,
                Entity::Binding,
                "binding_id",
                row.binding_id,
                row,
            )?;
            let card = require(
                &cards,
                Entity::Binding,
                "user_card_id",
                Entity::UserCard,
                row.user_card_id,
            )?;
            require(
                &tenants,
                Entity::Binding,
                "tenant_id",
                Entity::Tenant,
                row.tenant_id,
            )?;
            require(
                &rule_sets,
                Entity::Binding,
                "rule_set_id",
                Entity::RuleSet,
                row.rule_set_id,
            )?;
            if row.tenant_id != card.tenant_id {
                return Err(ValidationError::BindingTenantMismatch {
                    binding_id: row.binding_id,
                    binding_tenant_id: row.tenant_id,
                    card_tenant_id: card.tenant_id,
                });
            }
            bindings_by_card
                .entry(row.user_card_id)
                .or_default()
                .push(row);
        }
        for row in &self.binding_confirmations {
            insert(
                &mut binding_confirmation_ids,
                Entity::BindingConfirmation,
                "confirmation_id",
                row.confirmation_id,
                row,
            )?;
            let binding = require(
                &bindings,
                Entity::BindingConfirmation,
                "binding_id",
                Entity::Binding,
                row.binding_id,
            )?;
            require(
                &rule_sets,
                Entity::BindingConfirmation,
                "rule_set_id",
                Entity::RuleSet,
                row.rule_set_id,
            )?;
            require(
                &users,
                Entity::BindingConfirmation,
                "confirmer_user_id",
                Entity::User,
                row.confirmer_user_id,
            )?;
            if row.rule_set_id != binding.rule_set_id {
                return Err(ValidationError::ConfirmationRuleSetMismatch {
                    confirmation_id: row.confirmation_id,
                    binding_rule_set_id: binding.rule_set_id,
                    confirmation_rule_set_id: row.rule_set_id,
                });
            }
            confirmations_by_binding
                .entry(row.binding_id)
                .or_default()
                .push(row);
        }
        for row in &self.rule_set_change_confirmations {
            insert(
                &mut change_confirmation_ids,
                Entity::RuleSetChangeConfirmation,
                "confirmation_id",
                row.confirmation_id,
                row,
            )?;
            require(
                &rule_sets,
                Entity::RuleSetChangeConfirmation,
                "rule_set_id",
                Entity::RuleSet,
                row.rule_set_id,
            )?;
            require(
                &users,
                Entity::RuleSetChangeConfirmation,
                "confirmer_user_id",
                Entity::User,
                row.confirmer_user_id,
            )?;
            changes_by_rule_set
                .entry(row.rule_set_id)
                .or_default()
                .push(row);
        }
        Ok(FactsIndex {
            users,
            tenants,
            identities_by_user,
            cards,
            rule_sets,
            bindings_by_card,
            confirmations_by_binding,
            changes_by_rule_set,
        })
    }
}

impl<'a> FactsIndex<'a> {
    /// memory—v1: Look up one card and its directly related candidate rows.
    pub fn card(&self, card_id: i64) -> Option<CardFacts<'_>> {
        let card = *self.cards.get(&card_id)?;
        Some(CardFacts {
            card,
            user: self.users[&card.user_id],
            identity_card: self.identities_by_user[&card.user_id],
            tenant: self.tenants[&card.tenant_id],
            bindings: self
                .bindings_by_card
                .get(&card_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        })
    }

    /// memory—v1: Look up a rule-set identity without interpreting its ownership.
    pub fn rule_set(&self, rule_set_id: i64) -> Option<&RuleSet> {
        self.rule_sets.get(&rule_set_id).copied()
    }

    /// memory—v1: Return traceability candidates for a specific binding.
    pub fn binding_confirmations(&self, binding_id: i64) -> &[&BindingConfirmation] {
        self.confirmations_by_binding
            .get(&binding_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// memory—v1: Return traceability candidates for a rule-set change.
    pub fn rule_set_change_confirmations(&self, rule_set_id: i64) -> &[&RuleSetChangeConfirmation] {
        self.changes_by_rule_set
            .get(&rule_set_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1: Build facts with a hierarchy and two independent binding layers.
    fn sample() -> CandidateFacts {
        CandidateFacts {
            users: vec![User { user_id: 1 }, User { user_id: 2 }],
            tenants: vec![
                Tenant {
                    tenant_id: 10,
                    parent_tenant_id: None,
                },
                Tenant {
                    tenant_id: 11,
                    parent_tenant_id: Some(10),
                },
            ],
            identity_cards: vec![
                IdentityCard {
                    identity_card_id: 20,
                    user_id: 1,
                },
                IdentityCard {
                    identity_card_id: 21,
                    user_id: 2,
                },
            ],
            user_cards: vec![
                UserCard {
                    user_card_id: 30,
                    user_id: 1,
                    tenant_id: 11,
                },
                UserCard {
                    user_card_id: 31,
                    user_id: 2,
                    tenant_id: 10,
                },
            ],
            rule_sets: vec![
                RuleSet {
                    rule_set_id: 40,
                    owner_tenant_id: 10,
                },
                RuleSet {
                    rule_set_id: 41,
                    owner_tenant_id: 11,
                },
            ],
            bindings: vec![
                Binding {
                    binding_id: 50,
                    user_card_id: 30,
                    tenant_id: 11,
                    rule_set_id: 40,
                    layer: BindingLayer::Base,
                },
                Binding {
                    binding_id: 51,
                    user_card_id: 30,
                    tenant_id: 11,
                    rule_set_id: 40,
                    layer: BindingLayer::Overlay,
                },
            ],
            binding_confirmations: vec![BindingConfirmation {
                confirmation_id: 60,
                binding_id: 50,
                rule_set_id: 40,
                confirmer_user_id: 2,
                version_bytes: vec![0, 255],
                scope_bytes: vec![],
                operation_id: vec![1],
                confirmed_at_bytes: vec![2],
            }],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmation {
                confirmation_id: 60,
                rule_set_id: 40,
                confirmer_user_id: 1,
                version_bytes: vec![3],
                affected_scope_bytes: vec![4],
                operation_id: vec![],
                confirmed_at_bytes: vec![],
            }],
        }
    }

    #[test]
    // memory—v1: Preserve opaque bytes and both layers across serialization.
    fn serialization_and_card_index() {
        let facts = sample();
        let json = serde_json::to_string(&facts).unwrap();
        assert!(json.contains("\"BASE\""));
        assert!(json.contains("\"OVERLAY\""));
        let decoded: CandidateFacts = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, facts);
        let index = decoded.build_index().unwrap();
        let card = index.card(30).unwrap();
        assert_eq!(
            (
                card.user.user_id,
                card.identity_card.identity_card_id,
                card.tenant.tenant_id
            ),
            (1, 20, 11)
        );
        assert_eq!(
            card.bindings
                .iter()
                .map(|b| b.binding_id)
                .collect::<Vec<_>>(),
            vec![50, 51]
        );
        assert_eq!(index.rule_set(40).unwrap().owner_tenant_id, 10);
        assert_eq!(
            index.binding_confirmations(50)[0].version_bytes,
            vec![0, 255]
        );
        assert!(index.binding_confirmations(51).is_empty());
        assert_eq!(index.rule_set_change_confirmations(40).len(), 1);
        assert!(index.card(31).unwrap().bindings.is_empty());
        assert!(index.card(999).is_none());
        assert!(CandidateFacts::default().build_index().is_ok());
    }

    #[test]
    // memory—v1: Enforce exactly one identity card per supplied user.
    fn identity_card_constraints() {
        let mut facts = sample();
        facts.identity_cards.pop();
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingIdentityCard { user_id: 2 })
        ));
        facts = sample();
        facts.identity_cards[1].user_id = 1;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::DuplicateIdentityCard { user_id: 1 })
        ));
        facts = sample();
        facts.identity_cards[0].user_id = 99;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::IdentityCard,
                target: Entity::User,
                id: 99
            })
        ));
    }

    #[test]
    // memory—v1: Reject missing parents and both self and multi-node cycles.
    fn tenant_hierarchy_constraints() {
        let mut facts = sample();
        facts.tenants[0].parent_tenant_id = Some(99);
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::Tenant,
                target: Entity::Tenant,
                id: 99
            })
        ));
        facts.tenants[0].parent_tenant_id = Some(10);
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::TenantCycle { .. })
        ));
        facts.tenants[0].parent_tenant_id = Some(11);
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::TenantCycle { .. })
        ));
    }

    #[test]
    // memory—v1: Check tenant, card, rule-set and confirmation references.
    fn relationship_constraints() {
        let mut facts = sample();
        facts.user_cards[0].tenant_id = 99;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::UserCard,
                target: Entity::Tenant,
                id: 99
            })
        ));
        facts = sample();
        facts.rule_sets[0].owner_tenant_id = 99;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::RuleSet,
                target: Entity::Tenant,
                id: 99
            })
        ));
        facts = sample();
        facts.bindings[0].tenant_id = 10;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::BindingTenantMismatch { binding_id: 50, .. })
        ));
        facts = sample();
        facts.bindings[0].user_card_id = 99;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::Binding,
                target: Entity::UserCard,
                id: 99
            })
        ));
        facts = sample();
        facts.bindings[0].rule_set_id = 99;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::Binding,
                target: Entity::RuleSet,
                id: 99
            })
        ));
        facts = sample();
        facts.binding_confirmations[0].binding_id = 99;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::BindingConfirmation,
                target: Entity::Binding,
                id: 99
            })
        ));
        facts = sample();
        facts.binding_confirmations[0].rule_set_id = 41;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::ConfirmationRuleSetMismatch {
                confirmation_id: 60,
                ..
            })
        ));
        facts = sample();
        facts.binding_confirmations[0].confirmer_user_id = 99;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::BindingConfirmation,
                target: Entity::User,
                id: 99
            })
        ));
        facts = sample();
        facts.rule_set_change_confirmations[0].rule_set_id = 99;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::RuleSetChangeConfirmation,
                target: Entity::RuleSet,
                id: 99
            })
        ));
        facts = sample();
        facts.rule_set_change_confirmations[0].confirmer_user_id = 99;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::MissingReference {
                entity: Entity::RuleSetChangeConfirmation,
                target: Entity::User,
                id: 99
            })
        ));
    }

    #[test]
    // memory—v1: Reject invalid IDs and duplicate IDs without forbidding pairs.
    fn identifiers_are_positive_and_unique_per_kind() {
        let mut facts = sample();
        facts.bindings[0].rule_set_id = 0;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::NonPositiveId {
                entity: Entity::Binding,
                field: "rule_set_id",
                value: 0
            })
        ));
        facts = sample();
        facts.tenants[1].parent_tenant_id = Some(-1);
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::NonPositiveId {
                entity: Entity::Tenant,
                field: "parent_tenant_id",
                value: -1
            })
        ));
        facts = sample();
        facts.bindings[1].binding_id = 50;
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::DuplicateId {
                entity: Entity::Binding,
                id: 50
            })
        ));
        facts = sample();
        facts
            .binding_confirmations
            .push(facts.binding_confirmations[0].clone());
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::DuplicateId {
                entity: Entity::BindingConfirmation,
                id: 60
            })
        ));
        facts = sample();
        facts
            .rule_set_change_confirmations
            .push(facts.rule_set_change_confirmations[0].clone());
        assert!(matches!(
            facts.build_index(),
            Err(ValidationError::DuplicateId {
                entity: Entity::RuleSetChangeConfirmation,
                id: 60
            })
        ));
    }
}
