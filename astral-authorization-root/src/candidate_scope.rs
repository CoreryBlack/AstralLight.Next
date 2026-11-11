//! Non-production, read-only candidate facts for one caller-claimed card pair.
//!
//! The caller supplies both the root and all scope values. Matching them to
//! rows checks only relationships in that candidate: it does not authenticate
//! the caller, establish authorization, eligibility, validity, provenance,
//! publication, completeness, or an ALLOW decision. In particular, an
//! `Uncovered` result never proves that a row or permission does not exist.

use crate::model::{
    SingleNodeCardRuleSetRef, SingleNodeMemoryRoot, SingleNodePermissionRule,
    SingleNodeRuleSetEntry,
};

/// Caller-claimed identifiers, not a verified identity or authorization context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateCardScope {
    pub tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
    pub domain_id: Option<i64>,
}

/// Facts from one matched candidate card; no completeness or validity is implied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateCardFacts {
    pub bindings: Vec<SingleNodeCardRuleSetRef>,
    pub entries: Vec<SingleNodeRuleSetEntry>,
    pub direct_rules: Vec<SingleNodePermissionRule>,
}

/// A candidate, or a scope that this view cannot safely cover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateCardRead {
    Candidate(CandidateCardFacts),
    Uncovered,
}

/// A view bound to one caller-claimed card pair. It never returns the root.
///
/// Neither the supplied root nor the supplied identifiers are authenticated.
/// Matching rows does not establish identity, authority, freshness, validity,
/// source provenance, complete coverage, or an authorization decision.
pub struct CandidateCardView<'a> {
    root: &'a SingleNodeMemoryRoot,
    scope: CandidateCardScope,
}

impl<'a> CandidateCardView<'a> {
    /// Bind caller-supplied values; relationship checks occur in [`Self::read`].
    pub fn new(root: &'a SingleNodeMemoryRoot, scope: CandidateCardScope) -> Self {
        Self { root, scope }
    }

    /// Return bounded candidate facts only after checking every relationship.
    /// Empty, missing, mismatched, unprovable and oversized results are all
    /// `Uncovered`, never proof of absence. No caller-selected rule-set lookup
    /// or cross-card enumeration is provided by this view.
    pub fn read(&self) -> CandidateCardRead {
        const MAX_FACTS: usize = 1024;
        let scope = self.scope;
        let root = self.root;
        if scope.tenant_id <= 0
            || scope.user_id <= 0
            || scope.identity_card_id <= 0
            || scope.user_card_id <= 0
            || scope.domain_id.is_some_and(|id| id <= 0)
        {
            return CandidateCardRead::Uncovered;
        }
        let (Some(tenant), Some(user), Some(identity), Some(card)) = (
            root.tenant(scope.tenant_id),
            root.user(scope.user_id),
            root.identity_card(scope.identity_card_id),
            root.user_card(scope.user_card_id),
        ) else {
            return CandidateCardRead::Uncovered;
        };
        if tenant.tenant_id != scope.tenant_id
            || user.user_id != scope.user_id
            || identity.card_id != scope.identity_card_id
            || identity.user_id != scope.user_id
            || card.card_id != scope.user_card_id
            || card.user_id != Some(scope.user_id)
            || card.tenant_id != scope.tenant_id
            || card.domain_id != scope.domain_id
        {
            return CandidateCardRead::Uncovered;
        }
        if let Some(domain_id) = scope.domain_id {
            if root.domain(domain_id).is_none()
                || !matches!(root.tenant_domain(scope.tenant_id, domain_id), Some(mapping) if mapping.status == "ACTIVE")
            {
                return CandidateCardRead::Uncovered;
            }
        }

        let mut facts = CandidateCardFacts {
            bindings: Vec::new(),
            entries: Vec::new(),
            direct_rules: Vec::new(),
        };
        let mut count = 0usize;
        for binding in root.rule_set_bindings_for_card(scope.user_card_id) {
            if binding.card_id != scope.user_card_id || binding.tenant_id != scope.tenant_id {
                return CandidateCardRead::Uncovered;
            }
            // A NULL/global tenant is shareable across tenants in the model;
            // a binding alone cannot establish safe ownership of its entries.
            if !matches!(root.rule_set(binding.rule_set_id), Some(rule_set) if rule_set.rule_set_id == binding.rule_set_id && rule_set.tenant_id == Some(scope.tenant_id))
            {
                return CandidateCardRead::Uncovered;
            }
            count += 1;
            if count > MAX_FACTS {
                return CandidateCardRead::Uncovered;
            }
            facts.bindings.push(binding.clone());
            for entry in root.rule_set_entries(binding.rule_set_id) {
                if entry.rule_set_id != binding.rule_set_id {
                    return CandidateCardRead::Uncovered;
                }
                count += 1;
                if count > MAX_FACTS {
                    return CandidateCardRead::Uncovered;
                }
                facts.entries.push(entry.clone());
            }
        }
        for rule in root.permission_rules_for_card(scope.user_card_id) {
            if rule.card_id != scope.user_card_id || rule.tenant_id != scope.tenant_id {
                return CandidateCardRead::Uncovered;
            }
            count += 1;
            if count > MAX_FACTS {
                return CandidateCardRead::Uncovered;
            }
            facts.direct_rules.push(rule.clone());
        }
        if count == 0 {
            CandidateCardRead::Uncovered
        } else {
            CandidateCardRead::Candidate(facts)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{
        SingleNodeDatabaseSnapshot, SingleNodeDomain, SingleNodeIdentityCard,
        SingleNodeRootVersion, SingleNodeRuleSet, SingleNodeTenant, SingleNodeTenantDomain,
        SingleNodeUser, SingleNodeUserCard,
    };
    use astral_types::{BindingLayer, GrantEffect, ValidityWindow};

    pub(crate) fn scope() -> CandidateCardScope {
        CandidateCardScope {
            tenant_id: 1,
            user_id: 2,
            identity_card_id: 3,
            user_card_id: 4,
            domain_id: Some(5),
        }
    }

    pub(crate) fn snapshot() -> SingleNodeDatabaseSnapshot {
        SingleNodeDatabaseSnapshot {
            version: SingleNodeRootVersion {
                source_snapshot_id: "candidate".into(),
                generation: 1,
                dependency_frontier_digest: "ab".repeat(32),
                revoke_watermark: 0,
            },
            users: vec![
                SingleNodeUser {
                    user_id: 2,
                    status: "ACTIVE".into(),
                    deleted_at_unix: None,
                },
                SingleNodeUser {
                    user_id: 12,
                    status: "ACTIVE".into(),
                    deleted_at_unix: None,
                },
            ],
            identity_cards: vec![
                SingleNodeIdentityCard {
                    card_id: 3,
                    user_id: 2,
                    status: "ACTIVE".into(),
                    expires_at_unix: None,
                },
                SingleNodeIdentityCard {
                    card_id: 13,
                    user_id: 12,
                    status: "ACTIVE".into(),
                    expires_at_unix: None,
                },
            ],
            user_cards: vec![
                SingleNodeUserCard {
                    card_id: 4,
                    user_id: Some(2),
                    tenant_id: 1,
                    domain_id: Some(5),
                    status: "ACTIVE".into(),
                    valid_from_unix: None,
                    valid_to_unix: None,
                },
                SingleNodeUserCard {
                    card_id: 14,
                    user_id: Some(12),
                    tenant_id: 11,
                    domain_id: Some(5),
                    status: "ACTIVE".into(),
                    valid_from_unix: None,
                    valid_to_unix: None,
                },
            ],
            tenants: vec![
                SingleNodeTenant {
                    tenant_id: 1,
                    tenant_code: "a".into(),
                    parent_tenant_id: None,
                },
                SingleNodeTenant {
                    tenant_id: 11,
                    tenant_code: "b".into(),
                    parent_tenant_id: None,
                },
            ],
            domains: vec![
                SingleNodeDomain {
                    domain_id: 5,
                    domain_code: None,
                },
                SingleNodeDomain {
                    domain_id: 15,
                    domain_code: None,
                },
            ],
            tenant_domains: vec![SingleNodeTenantDomain {
                id: 6,
                tenant_id: 1,
                domain_id: 5,
                status: "ACTIVE".into(),
            }],
            org_memberships: vec![],
            rule_sets: vec![
                SingleNodeRuleSet {
                    rule_set_id: 7,
                    code: "a".into(),
                    tenant_id: Some(1),
                    source_type: "MANUAL".into(),
                    source_id: None,
                    status: "ACTIVE".into(),
                },
                SingleNodeRuleSet {
                    rule_set_id: 17,
                    code: "b".into(),
                    tenant_id: Some(11),
                    source_type: "MANUAL".into(),
                    source_id: None,
                    status: "ACTIVE".into(),
                },
            ],
            rule_set_entries: vec![entry(8, 7), entry(18, 17)],
            card_rule_set_refs: vec![
                SingleNodeCardRuleSetRef {
                    binding_id: 9,
                    card_id: 4,
                    rule_set_id: 7,
                    tenant_id: 1,
                    binding_layer: BindingLayer::Base,
                },
                SingleNodeCardRuleSetRef {
                    binding_id: 19,
                    card_id: 14,
                    rule_set_id: 17,
                    tenant_id: 11,
                    binding_layer: BindingLayer::Base,
                },
            ],
            permission_rules: vec![],
            published_pointers: vec![],
            global_admins: vec![],
            sod_policies: vec![],
        }
    }

    fn entry(entry_id: i64, rule_set_id: i64) -> SingleNodeRuleSetEntry {
        SingleNodeRuleSetEntry {
            entry_id,
            rule_set_id,
            resource_type: "device".into(),
            resource_id: None,
            action_code: "read".into(),
            effect: GrantEffect::Allow,
            condition_json: None,
            priority: 1,
            enabled: true,
            validity: ValidityWindow::perpetual(),
        }
    }

    fn read(snapshot: SingleNodeDatabaseSnapshot, scope: CandidateCardScope) -> CandidateCardRead {
        let root = SingleNodeMemoryRoot::build(snapshot).unwrap();
        CandidateCardView::new(&root, scope).read()
    }

    #[test]
    fn returns_only_facts_bound_to_exact_card_and_tenant() {
        let CandidateCardRead::Candidate(facts) = read(snapshot(), scope()) else {
            panic!("candidate expected")
        };
        assert_eq!(
            facts
                .bindings
                .iter()
                .map(|r| r.binding_id)
                .collect::<Vec<_>>(),
            vec![9]
        );
        assert_eq!(
            facts.entries.iter().map(|r| r.entry_id).collect::<Vec<_>>(),
            vec![8]
        );
        assert!(facts.direct_rules.is_empty());
    }

    #[test]
    fn rejects_nonpositive_and_mismatched_claims() {
        let original = scope();
        for changed in [
            CandidateCardScope {
                tenant_id: 0,
                ..original
            },
            CandidateCardScope {
                user_id: -1,
                ..original
            },
            CandidateCardScope {
                identity_card_id: 0,
                ..original
            },
            CandidateCardScope {
                user_card_id: -1,
                ..original
            },
            CandidateCardScope {
                domain_id: Some(0),
                ..original
            },
            CandidateCardScope {
                tenant_id: 11,
                ..original
            },
            CandidateCardScope {
                user_id: 12,
                ..original
            },
            CandidateCardScope {
                identity_card_id: 13,
                ..original
            },
            CandidateCardScope {
                user_card_id: 14,
                ..original
            },
            CandidateCardScope {
                domain_id: None,
                ..original
            },
            CandidateCardScope {
                domain_id: Some(15),
                ..original
            },
            CandidateCardScope {
                user_card_id: 999,
                ..original
            },
        ] {
            assert_eq!(read(snapshot(), changed), CandidateCardRead::Uncovered);
        }
    }

    #[test]
    fn requires_exact_active_tenant_domain_mapping() {
        let mut input = snapshot();
        input.tenant_domains.clear();
        assert_eq!(read(input, scope()), CandidateCardRead::Uncovered);
        let mut input = snapshot();
        input.tenant_domains[0].tenant_id = 11;
        assert_eq!(read(input, scope()), CandidateCardRead::Uncovered);
        let mut input = snapshot();
        input.tenant_domains[0].status = "INACTIVE".into();
        assert_eq!(read(input, scope()), CandidateCardRead::Uncovered);
        let mut input = snapshot();
        input.user_cards[0].domain_id = None;
        assert!(matches!(
            read(
                input,
                CandidateCardScope {
                    domain_id: None,
                    ..scope()
                }
            ),
            CandidateCardRead::Candidate(_)
        ));
    }

    #[test]
    fn rejects_unbound_shared_and_uncovered_facts() {
        let mut input = snapshot();
        input.rule_sets[0].tenant_id = None;
        assert_eq!(read(input, scope()), CandidateCardRead::Uncovered);
        let mut input = snapshot();
        input
            .card_rule_set_refs
            .retain(|binding| binding.card_id != 4);
        assert_eq!(read(input, scope()), CandidateCardRead::Uncovered);
        let mut input = snapshot();
        input.user_cards[0].status = "INACTIVE".into();
        input.user_cards[0].user_id = None;
        assert_eq!(read(input, scope()), CandidateCardRead::Uncovered);
    }

    #[test]
    fn over_budget_is_uncovered_without_partial_facts() {
        let mut input = snapshot();
        input
            .rule_set_entries
            .extend((100..1125).map(|id| entry(id, 7)));
        assert_eq!(read(input, scope()), CandidateCardRead::Uncovered);
    }
}
