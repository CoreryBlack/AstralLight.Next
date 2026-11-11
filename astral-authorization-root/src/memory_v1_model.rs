//! memory—v1 candidate relationships for an in-memory authorization model.
//!
//! This is a minimal relationship model, not a complete source record or an
//! authorization reader. Validation establishes only internal consistency of
//! the supplied rows. It does not establish provenance, completeness,
//! eligibility, freshness, publication, or an authorization decision. Tenant
//! parent links describe structure only and never confer inherited permissions.

use std::collections::{BTreeMap, BTreeSet};

/// A user represented in the candidate input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    /// User identity.
    pub user_id: i64,
}

/// A tenant, optionally nested under another tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    /// Tenant identity.
    pub tenant_id: i64,
    /// Structural parent; this relationship grants no permissions.
    pub parent_tenant_id: Option<i64>,
}

/// The single identity card of a user, independent of any tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCard {
    /// Identity card identity.
    pub card_id: i64,
    /// Owner of this identity card.
    pub user_id: i64,
}

/// A user's permission carrier within exactly one tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserCard {
    /// User card identity.
    pub card_id: i64,
    /// Owner of this user card.
    pub user_id: i64,
    /// Tenant in which this card is scoped.
    pub tenant_id: i64,
}

/// A rule set owned by one tenant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSet {
    /// Rule set identity.
    pub rule_set_id: i64,
    /// Tenant owning the rule set.
    pub tenant_id: i64,
}

/// A rule set entry's relationship and ownership, without evaluation semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSetEntry {
    /// Entry identity.
    pub entry_id: i64,
    /// Containing rule set.
    pub rule_set_id: i64,
    /// Tenant owning the entry.
    pub tenant_id: i64,
}

/// The layer of a card-to-rule-set binding, not a rule-set source type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingLayer {
    /// Base binding layer.
    Base,
    /// Overlay binding layer.
    Overlay,
}

/// An independent binding between a user card and a rule set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardRuleSetBinding {
    /// Binding identity.
    pub binding_id: i64,
    /// Bound user card.
    pub card_id: i64,
    /// Bound rule set.
    pub rule_set_id: i64,
    /// Tenant owning the binding.
    pub tenant_id: i64,
    /// Layer of this binding.
    pub layer: BindingLayer,
}

/// Caller-supplied candidate relationships; fields may be changed after validation.
///
/// An empty candidate can be internally consistent but does not prove absence
/// or complete coverage. Callers must revalidate after any modification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CandidateModel {
    /// Users in this candidate.
    pub users: Vec<User>,
    /// Tenants in this candidate.
    pub tenants: Vec<Tenant>,
    /// Tenant-independent identity cards.
    pub identity_cards: Vec<IdentityCard>,
    /// Tenant-scoped user cards.
    pub user_cards: Vec<UserCard>,
    /// Tenant-owned rule sets.
    pub rule_sets: Vec<RuleSet>,
    /// Tenant-owned rule set entries.
    pub entries: Vec<RuleSetEntry>,
    /// Card-to-rule-set bindings.
    pub bindings: Vec<CardRuleSetBinding>,
}

/// Entity kinds used in validation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entity {
    /// User row.
    User,
    /// Tenant row.
    Tenant,
    /// Identity card row.
    IdentityCard,
    /// User card row.
    UserCard,
    /// Rule set row.
    RuleSet,
    /// Rule set entry row.
    Entry,
    /// Card-to-rule-set binding row.
    Binding,
}

/// A candidate relationship failed validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    /// An identity or referenced identity is not positive.
    NonPositiveId {
        /// Entity containing the invalid field.
        entity: Entity,
        /// Field containing the invalid value.
        field: &'static str,
        /// Invalid value.
        value: i64,
    },
    /// Two rows have the same identity within an entity kind.
    DuplicateId {
        /// Entity whose identity is duplicated.
        entity: Entity,
        /// Duplicated identity.
        id: i64,
    },
    /// A row references an entity absent from this candidate.
    MissingReference {
        /// Entity containing the reference.
        entity: Entity,
        /// Kind of referenced entity.
        target: Entity,
        /// Referenced identity.
        id: i64,
    },
    /// A user has more than one identity card.
    DuplicateIdentityCard {
        /// User with multiple identity cards.
        user_id: i64,
    },
    /// A user has no identity card in the supplied candidate.
    MissingIdentityCard {
        /// User without an identity card.
        user_id: i64,
    },
    /// Tenant parent references form a cycle.
    TenantCycle {
        /// A tenant belonging to the cycle.
        tenant_id: i64,
    },
    /// A relationship crosses tenant boundaries.
    TenantMismatch {
        /// Entity containing the inconsistent relationship.
        entity: Entity,
        /// Tenant of the containing entity.
        expected: i64,
        /// Tenant of the referenced entity.
        actual: i64,
    },
    /// The same card and rule set are bound more than once, regardless of layer.
    DuplicateBinding {
        /// Bound user card.
        card_id: i64,
        /// Bound rule set.
        rule_set_id: i64,
    },
}

// memory—v1: Reject invalid IDs before using them as keys or references.
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

// memory—v1: Record a unique row identity without silently replacing a row.
fn unique(ids: &mut BTreeSet<i64>, entity: Entity, id: i64) -> Result<(), ValidationError> {
    if !ids.insert(id) {
        return Err(ValidationError::DuplicateId { entity, id });
    }
    Ok(())
}

// memory—v1: Check a reference only within the supplied candidate.
fn require(
    ids: &BTreeSet<i64>,
    entity: Entity,
    target: Entity,
    id: i64,
) -> Result<(), ValidationError> {
    if !ids.contains(&id) {
        return Err(ValidationError::MissingReference { entity, target, id });
    }
    Ok(())
}

// memory—v1: Reject a relationship whose two tenant owners differ.
fn same_tenant(entity: Entity, expected: i64, actual: i64) -> Result<(), ValidationError> {
    if expected != actual {
        return Err(ValidationError::TenantMismatch {
            entity,
            expected,
            actual,
        });
    }
    Ok(())
}

impl CandidateModel {
    /// memory—v1: Validate candidate identities, references and tenant ownership.
    ///
    /// This checks the supplied rows only. Success is not a completeness proof,
    /// a permission decision, or a guarantee that a later mutation is valid.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut users = BTreeSet::new();
        for user in &self.users {
            positive(Entity::User, "user_id", user.user_id)?;
            unique(&mut users, Entity::User, user.user_id)?;
        }

        let mut tenants = BTreeSet::new();
        let mut parents = BTreeMap::new();
        for tenant in &self.tenants {
            positive(Entity::Tenant, "tenant_id", tenant.tenant_id)?;
            unique(&mut tenants, Entity::Tenant, tenant.tenant_id)?;
            if let Some(parent) = tenant.parent_tenant_id {
                positive(Entity::Tenant, "parent_tenant_id", parent)?;
                parents.insert(tenant.tenant_id, parent);
            }
        }
        for parent in parents.values() {
            require(&tenants, Entity::Tenant, Entity::Tenant, *parent)?;
        }
        // Iterative traversal prevents deep tenant hierarchies from overflowing
        // the call stack. Completed paths are not traversed again.
        let mut complete = BTreeSet::new();
        for tenant_id in &tenants {
            let mut path = BTreeSet::new();
            let mut current = *tenant_id;
            while !complete.contains(&current) {
                if !path.insert(current) {
                    return Err(ValidationError::TenantCycle { tenant_id: current });
                }
                match parents.get(&current) {
                    Some(parent) => current = *parent,
                    None => break,
                }
            }
            complete.extend(path);
        }

        let mut identity_ids = BTreeSet::new();
        let mut identity_users = BTreeSet::new();
        for card in &self.identity_cards {
            positive(Entity::IdentityCard, "card_id", card.card_id)?;
            positive(Entity::IdentityCard, "user_id", card.user_id)?;
            unique(&mut identity_ids, Entity::IdentityCard, card.card_id)?;
            require(&users, Entity::IdentityCard, Entity::User, card.user_id)?;
            if !identity_users.insert(card.user_id) {
                return Err(ValidationError::DuplicateIdentityCard {
                    user_id: card.user_id,
                });
            }
        }
        if let Some(user_id) = users.difference(&identity_users).next() {
            return Err(ValidationError::MissingIdentityCard { user_id: *user_id });
        }

        let mut user_card_ids = BTreeSet::new();
        let mut card_tenants = BTreeMap::new();
        for card in &self.user_cards {
            positive(Entity::UserCard, "card_id", card.card_id)?;
            positive(Entity::UserCard, "user_id", card.user_id)?;
            positive(Entity::UserCard, "tenant_id", card.tenant_id)?;
            unique(&mut user_card_ids, Entity::UserCard, card.card_id)?;
            require(&users, Entity::UserCard, Entity::User, card.user_id)?;
            require(&tenants, Entity::UserCard, Entity::Tenant, card.tenant_id)?;
            card_tenants.insert(card.card_id, card.tenant_id);
        }

        let mut rule_set_ids = BTreeSet::new();
        let mut rule_set_tenants = BTreeMap::new();
        for rule_set in &self.rule_sets {
            positive(Entity::RuleSet, "rule_set_id", rule_set.rule_set_id)?;
            positive(Entity::RuleSet, "tenant_id", rule_set.tenant_id)?;
            unique(&mut rule_set_ids, Entity::RuleSet, rule_set.rule_set_id)?;
            require(
                &tenants,
                Entity::RuleSet,
                Entity::Tenant,
                rule_set.tenant_id,
            )?;
            rule_set_tenants.insert(rule_set.rule_set_id, rule_set.tenant_id);
        }

        let mut entry_ids = BTreeSet::new();
        for entry in &self.entries {
            positive(Entity::Entry, "entry_id", entry.entry_id)?;
            positive(Entity::Entry, "rule_set_id", entry.rule_set_id)?;
            positive(Entity::Entry, "tenant_id", entry.tenant_id)?;
            unique(&mut entry_ids, Entity::Entry, entry.entry_id)?;
            require(&tenants, Entity::Entry, Entity::Tenant, entry.tenant_id)?;
            require(
                &rule_set_ids,
                Entity::Entry,
                Entity::RuleSet,
                entry.rule_set_id,
            )?;
            same_tenant(
                Entity::Entry,
                entry.tenant_id,
                rule_set_tenants[&entry.rule_set_id],
            )?;
        }

        let mut binding_ids = BTreeSet::new();
        let mut binding_pairs = BTreeSet::new();
        for binding in &self.bindings {
            positive(Entity::Binding, "binding_id", binding.binding_id)?;
            positive(Entity::Binding, "card_id", binding.card_id)?;
            positive(Entity::Binding, "rule_set_id", binding.rule_set_id)?;
            positive(Entity::Binding, "tenant_id", binding.tenant_id)?;
            unique(&mut binding_ids, Entity::Binding, binding.binding_id)?;
            require(&tenants, Entity::Binding, Entity::Tenant, binding.tenant_id)?;
            require(
                &user_card_ids,
                Entity::Binding,
                Entity::UserCard,
                binding.card_id,
            )?;
            require(
                &rule_set_ids,
                Entity::Binding,
                Entity::RuleSet,
                binding.rule_set_id,
            )?;
            same_tenant(
                Entity::Binding,
                binding.tenant_id,
                card_tenants[&binding.card_id],
            )?;
            same_tenant(
                Entity::Binding,
                binding.tenant_id,
                rule_set_tenants[&binding.rule_set_id],
            )?;
            if !binding_pairs.insert((binding.card_id, binding.rule_set_id)) {
                return Err(ValidationError::DuplicateBinding {
                    card_id: binding.card_id,
                    rule_set_id: binding.rule_set_id,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1: Construct a candidate with a three-level tenant hierarchy.
    fn candidate() -> CandidateModel {
        CandidateModel {
            users: vec![User { user_id: 1 }],
            tenants: vec![
                Tenant {
                    tenant_id: 10,
                    parent_tenant_id: None,
                },
                Tenant {
                    tenant_id: 11,
                    parent_tenant_id: Some(10),
                },
                Tenant {
                    tenant_id: 12,
                    parent_tenant_id: Some(11),
                },
            ],
            identity_cards: vec![IdentityCard {
                card_id: 20,
                user_id: 1,
            }],
            user_cards: vec![
                UserCard {
                    card_id: 30,
                    user_id: 1,
                    tenant_id: 10,
                },
                UserCard {
                    card_id: 31,
                    user_id: 1,
                    tenant_id: 12,
                },
            ],
            rule_sets: vec![
                RuleSet {
                    rule_set_id: 40,
                    tenant_id: 10,
                },
                RuleSet {
                    rule_set_id: 41,
                    tenant_id: 12,
                },
            ],
            entries: vec![RuleSetEntry {
                entry_id: 50,
                rule_set_id: 40,
                tenant_id: 10,
            }],
            bindings: vec![
                CardRuleSetBinding {
                    binding_id: 60,
                    card_id: 30,
                    rule_set_id: 40,
                    tenant_id: 10,
                    layer: BindingLayer::Base,
                },
                CardRuleSetBinding {
                    binding_id: 61,
                    card_id: 31,
                    rule_set_id: 41,
                    tenant_id: 12,
                    layer: BindingLayer::Overlay,
                },
            ],
        }
    }

    #[test]
    // memory—v1: A single identity card supports multiple tenant-scoped cards.
    fn validates_hierarchy_and_multiple_cards_without_inheritance() {
        let model = candidate();
        assert_eq!(model.validate(), Ok(()));
        assert_eq!(CandidateModel::default().validate(), Ok(()));
        let mut cross_parent = model;
        cross_parent.bindings[0].rule_set_id = 41;
        assert_eq!(
            cross_parent.validate(),
            Err(ValidationError::TenantMismatch {
                entity: Entity::Binding,
                expected: 10,
                actual: 12,
            })
        );
    }

    #[test]
    // memory—v1: Users require exactly one identity card and valid references.
    fn rejects_invalid_identity_card_relations() {
        let mut model = candidate();
        model.identity_cards.clear();
        assert_eq!(
            model.validate(),
            Err(ValidationError::MissingIdentityCard { user_id: 1 })
        );
        model = candidate();
        model.identity_cards.push(IdentityCard {
            card_id: 21,
            user_id: 1,
        });
        assert_eq!(
            model.validate(),
            Err(ValidationError::DuplicateIdentityCard { user_id: 1 })
        );
        model = candidate();
        model.identity_cards[0].user_id = 2;
        assert_eq!(
            model.validate(),
            Err(ValidationError::MissingReference {
                entity: Entity::IdentityCard,
                target: Entity::User,
                id: 2,
            })
        );
        model = candidate();
        model.user_cards[0].user_id = 2;
        assert_eq!(
            model.validate(),
            Err(ValidationError::MissingReference {
                entity: Entity::UserCard,
                target: Entity::User,
                id: 2,
            })
        );
    }

    #[test]
    // memory—v1: Parent links require existing tenants and cannot form cycles.
    fn rejects_missing_parent_and_cycles() {
        let mut model = candidate();
        model.tenants[0].parent_tenant_id = Some(99);
        assert_eq!(
            model.validate(),
            Err(ValidationError::MissingReference {
                entity: Entity::Tenant,
                target: Entity::Tenant,
                id: 99,
            })
        );
        model.tenants[0].parent_tenant_id = Some(10);
        assert_eq!(
            model.validate(),
            Err(ValidationError::TenantCycle { tenant_id: 10 })
        );
        model.tenants[0].parent_tenant_id = Some(12);
        assert_eq!(
            model.validate(),
            Err(ValidationError::TenantCycle { tenant_id: 10 })
        );
    }

    #[test]
    // memory—v1: Missing and cross-tenant references are rejected at each relation.
    fn rejects_invalid_scoped_relations() {
        let mut model = candidate();
        model.user_cards[0].tenant_id = 99;
        assert_eq!(
            model.validate(),
            Err(ValidationError::MissingReference {
                entity: Entity::UserCard,
                target: Entity::Tenant,
                id: 99,
            })
        );
        model = candidate();
        model.rule_sets[0].tenant_id = 99;
        assert_eq!(
            model.validate(),
            Err(ValidationError::MissingReference {
                entity: Entity::RuleSet,
                target: Entity::Tenant,
                id: 99,
            })
        );
        model = candidate();
        model.entries[0].rule_set_id = 99;
        assert_eq!(
            model.validate(),
            Err(ValidationError::MissingReference {
                entity: Entity::Entry,
                target: Entity::RuleSet,
                id: 99,
            })
        );
        model = candidate();
        model.entries[0].tenant_id = 12;
        assert_eq!(
            model.validate(),
            Err(ValidationError::TenantMismatch {
                entity: Entity::Entry,
                expected: 12,
                actual: 10,
            })
        );
        model = candidate();
        model.bindings[0].card_id = 99;
        assert_eq!(
            model.validate(),
            Err(ValidationError::MissingReference {
                entity: Entity::Binding,
                target: Entity::UserCard,
                id: 99,
            })
        );
        model = candidate();
        model.bindings[0].rule_set_id = 99;
        assert_eq!(
            model.validate(),
            Err(ValidationError::MissingReference {
                entity: Entity::Binding,
                target: Entity::RuleSet,
                id: 99,
            })
        );
        model = candidate();
        model.bindings[0].tenant_id = 12;
        assert_eq!(
            model.validate(),
            Err(ValidationError::TenantMismatch {
                entity: Entity::Binding,
                expected: 12,
                actual: 10,
            })
        );
    }

    #[test]
    // memory—v1: Duplicate IDs and duplicate card-to-rule-set pairs are rejected.
    fn rejects_duplicate_rows_and_bindings_across_layers() {
        let mut model = candidate();
        model.tenants.push(model.tenants[0].clone());
        assert_eq!(
            model.validate(),
            Err(ValidationError::DuplicateId {
                entity: Entity::Tenant,
                id: 10
            })
        );
        model = candidate();
        model.entries.push(model.entries[0].clone());
        assert_eq!(
            model.validate(),
            Err(ValidationError::DuplicateId {
                entity: Entity::Entry,
                id: 50
            })
        );
        model = candidate();
        let mut duplicate = model.bindings[0].clone();
        duplicate.binding_id = 62;
        duplicate.layer = BindingLayer::Overlay;
        model.bindings.push(duplicate);
        assert_eq!(
            model.validate(),
            Err(ValidationError::DuplicateBinding {
                card_id: 30,
                rule_set_id: 40
            })
        );
    }

    #[test]
    // memory—v1: Nonpositive IDs fail before they can be treated as references.
    fn rejects_nonpositive_ids() {
        let mut model = candidate();
        model.tenants[0].parent_tenant_id = Some(0);
        assert_eq!(
            model.validate(),
            Err(ValidationError::NonPositiveId {
                entity: Entity::Tenant,
                field: "parent_tenant_id",
                value: 0,
            })
        );
        model = candidate();
        model.bindings[0].card_id = -1;
        assert_eq!(
            model.validate(),
            Err(ValidationError::NonPositiveId {
                entity: Entity::Binding,
                field: "card_id",
                value: -1,
            })
        );
    }
}
