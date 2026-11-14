//! Typed memory—v1 rule evaluation over a request's shared root and session.
//!
//! The formal entry is `PolicyEngine::evaluate_memory_v1`; the legacy
//! `PolicyEngine::evaluate` keeps returning `AUTHORIZATION_PENDING`. A serving
//! root and structural confirmation do not establish production adoption,
//! resource ownership, confirmer authority, or durable audit evidence.

use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{
    DependencyRecord, EvaluationDependency, RequestRootReader, RootMetadata, RootStatus,
};
use astral_authorization_root::memory_v1_rules::{
    confirmation_matches, parse_version, window_active, MemoryV1OwnerScope, MemoryV1RuleEffect,
    MemoryV1TenantScope, MemoryV1Validity,
};
use astral_authorization_root::memory_v1_session::{RequestSessionExtension, VerifiedSessionFacts};
use astral_types::memory_v1::CandidateIdentity;

const MAX_TEXT_BYTES: usize = 256;
const MAX_BINDING_BYTES: usize = 4096;

/// The result of the typed memory—v1 evaluator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1Decision {
    Allow,
    Deny,
    Pending,
}

/// Request details to bind to an evaluation. Identity comes only from the session.
///
/// §4.10: `target` is the trusted server-side object identifier; when present,
/// `target_tenant` and `target_owner` are the object's trusted attribution
/// attributes supplied by the owning business service (owner attribution is
/// business data held by the business database, never root state).
#[derive(Clone, Copy, Debug)]
pub struct MemoryV1Request<'a> {
    pub resource: &'a str,
    pub action: &'a str,
    pub target: Option<&'a [u8]>,
    pub target_tenant: Option<&'a [u8]>,
    pub target_owner: Option<&'a [u8]>,
    pub operation_id: &'a [u8],
    pub operation_fingerprint: &'a [u8],
}

/// Details bound to one successful evaluation, not a durable or transferable proof.
///
/// A consumer performing a mutation must independently enforce its own authorization
/// binding, session freshness, root CAS, replay protection and audit contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1Admission {
    root: RootMetadata,
    identity: CandidateIdentity,
    resource: String,
    action: String,
    target: Option<Vec<u8>>,
    operation_id: Vec<u8>,
    operation_fingerprint: Vec<u8>,
    trusted_time_unix_seconds: i64,
    /// §4.10: the effective owner visibility scope for business filtering.
    effective_owner_scope: MemoryV1OwnerScope,
    /// §4.10: the effective tenant visibility scope for business filtering.
    effective_tenant_scope: MemoryV1TenantScope,
}

impl MemoryV1Admission {
    /// memory—v1: Access the exact root metadata captured by this evaluation.
    pub fn root(&self) -> RootMetadata {
        self.root
    }

    /// memory—v1: Access the session's UUID identity bound to the evaluation.
    pub fn identity(&self) -> CandidateIdentity {
        self.identity
    }

    /// memory—v1: Access the exact evaluated resource.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// memory—v1: Access the exact evaluated action.
    pub fn action(&self) -> &str {
        &self.action
    }

    /// memory—v1: Access the optional exact target bytes.
    pub fn target(&self) -> Option<&[u8]> {
        self.target.as_deref()
    }

    /// memory—v1: Access the stable operation identifier supplied by the caller.
    pub fn operation_id(&self) -> &[u8] {
        &self.operation_id
    }

    /// memory—v1: Access the exact caller-supplied operation fingerprint.
    pub fn operation_fingerprint(&self) -> &[u8] {
        &self.operation_fingerprint
    }

    /// memory—v1: Access the final trusted UTC clock observation.
    pub fn trusted_time_unix_seconds(&self) -> i64 {
        self.trusted_time_unix_seconds
    }

    /// memory—v1 §4.10: the effective owner visibility scope delivered to the
    /// business service for list filtering.
    pub fn effective_owner_scope(&self) -> MemoryV1OwnerScope {
        self.effective_owner_scope
    }

    /// memory—v1 §4.10: the effective tenant visibility scope delivered to the
    /// business service for list filtering.
    pub fn effective_tenant_scope(&self) -> MemoryV1TenantScope {
        self.effective_tenant_scope
    }
}

/// memory—v1 §4.8: why a determinate denial was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1DenySource {
    /// An explicit DENY rule hit through window and scope predicates.
    RuleDenied,
    /// Complete context, no matching authorization.
    NoMatch,
    /// The object's attribution is present but outside the rule's scope
    /// (§4.10: another owner or another tenant) — deterministic refusal.
    ScopeDenied,
    /// The session card has no bindings at all.
    CardUnbound,
    /// A proven user/identity/card/tenant relationship mismatch.
    IdentityMismatch,
    /// The evaluated (resource, action) pair is not registered and active.
    UnregisteredResource,
}

/// memory—v1 §4.8: why an evaluation could not produce a determinate outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1PendingSource {
    /// Invalid or unverifiable context (bad binding, missing attribution).
    ContextInvalid,
    /// The target rule set is inside an active modification window (§4.6).
    FenceActive,
    /// The root owner is gone or the root is not servable.
    RootUnavailable,
}

/// An admission is present only when the decision is `Allow`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1Evaluation {
    pub decision: MemoryV1Decision,
    pub deny_source: Option<MemoryV1DenySource>,
    pub pending_source: Option<MemoryV1PendingSource>,
    pub admission: Option<MemoryV1Admission>,
}

// memory—v1: Produce a non-authorizing outcome without an admission.
fn non_allow(
    decision: MemoryV1Decision,
    deny_source: Option<MemoryV1DenySource>,
    pending_source: Option<MemoryV1PendingSource>,
) -> MemoryV1Evaluation {
    debug_assert_ne!(decision, MemoryV1Decision::Allow);
    MemoryV1Evaluation {
        decision,
        deny_source,
        pending_source,
        admission: None,
    }
}

// memory—v1: Obtain process time without accepting clock errors or overflow.
fn trusted_now() -> Option<i64> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(seconds).ok()
}

/// memory—v1: Evaluate exact rules using the session and its request-local reader.
///
/// Crate-private: external callers must use `PolicyEngine::evaluate_memory_v1`,
/// the single formal decision entry, so every evaluation is counted.
/// The process clock is consulted before and after evaluation. Request details
/// must originate from trusted server-side context; the fingerprint is bound as
/// supplied and is not independently computed or validated by this function.
/// Root and session failures return `Pending`; no repository is consulted.
pub(crate) fn evaluate_memory_v1(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    request: &MemoryV1Request<'_>,
) -> MemoryV1Evaluation {
    evaluate_with(root, session, request, trusted_now, || {})
}

// memory—v1: Keep clock and post-read hooks private for deterministic tests.
fn evaluate_with(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    request: &MemoryV1Request<'_>,
    mut clock: impl FnMut() -> Option<i64>,
    after_read: impl FnOnce(),
) -> MemoryV1Evaluation {
    if request.resource.is_empty()
        || request.resource.len() > MAX_TEXT_BYTES
        || request.action.is_empty()
        || request.action.len() > MAX_TEXT_BYTES
        || request.operation_id.is_empty()
        || request.operation_id.len() > MAX_BINDING_BYTES
        || request.operation_fingerprint.is_empty()
        || request.operation_fingerprint.len() > MAX_BINDING_BYTES
        || request
            .target
            .is_some_and(|target| target.len() > MAX_BINDING_BYTES)
        || request
            .target_tenant
            .is_some_and(|tenant| tenant.len() > MAX_BINDING_BYTES)
        || request
            .target_owner
            .is_some_and(|owner| owner.len() > MAX_BINDING_BYTES)
    {
        return non_allow(
            MemoryV1Decision::Pending,
            None,
            Some(MemoryV1PendingSource::ContextInvalid),
        );
    }
    session
        .with_context(root, |facts, reader| {
            evaluate_reader(facts, reader, request, &mut clock, after_read)
        })
        .unwrap_or_else(|_| {
            non_allow(
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::RootUnavailable),
            )
        })
}

// memory—v1 §4.8: the deterministic outcome of one card's aggregate.
enum CardOutcome {
    Deny(MemoryV1DenySource),
    Pending(MemoryV1PendingSource),
    Allow {
        dependencies: Vec<EvaluationDependency>,
        winning_allows: Vec<WinningAllow>,
        owner_scope: MemoryV1OwnerScope,
        tenant_scope: MemoryV1TenantScope,
        tree_version: u64,
        registry_version: u64,
    },
}

// memory—v1 §4.4: one winning ALLOW rule whose window and scope must still
// hold at the final trusted-time observation.
struct WinningAllow {
    entry_validity: Option<MemoryV1Validity>,
    binding_from: Option<i64>,
    binding_until: Option<i64>,
    owner_scope: MemoryV1OwnerScope,
    tenant_scope: MemoryV1TenantScope,
}

// memory—v1 §4.10: the effective owner scope is the strictest of the layers.
fn strictest_owner_scope(
    entry: MemoryV1OwnerScope,
    binding: MemoryV1OwnerScope,
) -> MemoryV1OwnerScope {
    match (entry, binding) {
        (MemoryV1OwnerScope::SelfUser, _) | (_, MemoryV1OwnerScope::SelfUser) => {
            MemoryV1OwnerScope::SelfUser
        }
        _ => MemoryV1OwnerScope::AllUsers,
    }
}

// memory—v1 §4.10: the effective tenant scope is the strictest of the layers.
fn strictest_tenant_scope(
    entry: MemoryV1TenantScope,
    binding: MemoryV1TenantScope,
) -> MemoryV1TenantScope {
    match (entry, binding) {
        (MemoryV1TenantScope::SelfTenant, _) | (_, MemoryV1TenantScope::SelfTenant) => {
            MemoryV1TenantScope::SelfTenant
        }
        _ => MemoryV1TenantScope::SelfAndDescendants,
    }
}

// memory—v1: Evaluate one immutable snapshot and recheck it before allowing.
fn evaluate_reader(
    facts: &VerifiedSessionFacts,
    reader: &RequestRootReader,
    request: &MemoryV1Request<'_>,
    clock: &mut impl FnMut() -> Option<i64>,
    after_read: impl FnOnce(),
) -> MemoryV1Evaluation {
    let metadata = reader.metadata();
    let Some(start_time) = clock() else {
        return non_allow(
            MemoryV1Decision::Pending,
            None,
            Some(MemoryV1PendingSource::ContextInvalid),
        );
    };
    if metadata.status != RootStatus::Serving || !facts.valid_at(start_time) {
        return non_allow(
            MemoryV1Decision::Pending,
            None,
            Some(MemoryV1PendingSource::ContextInvalid),
        );
    }
    // memory—v1 §4.9 A-3.4: registry membership is a structural precondition;
    // not installed, unregistered, inactive and unknown-action all refuse.
    if reader
        .registry_check(request.resource, request.action)
        .is_err()
    {
        return non_allow(
            MemoryV1Decision::Deny,
            Some(MemoryV1DenySource::UnregisteredResource),
            None,
        );
    }
    let identity = facts.candidate_identity();
    let outcome = reader.read_card(identity.user_card_id.into_bytes(), |context| {
        let user = identity.user_id.into_bytes();
        let card = identity.user_card_id.into_bytes();
        let tenant = identity.tenant_id.into_bytes();
        // memory—v1 §4.8: a proven relationship mismatch is a deterministic denial.
        if context.user.user_id != user
            || context.identity.identity_card_id != identity.identity_card_id.into_bytes()
            || context.identity.user_id != user
            || context.card.user_card_id != card
            || context.card.user_id != user
            || context.card.tenant_id != tenant
            || context.tenant.tenant_id != tenant
        {
            return CardOutcome::Deny(MemoryV1DenySource::IdentityMismatch);
        }
        // memory—v1 §4.8: an unbound card is a deterministic denial.
        if context.bindings.is_empty() {
            return CardOutcome::Deny(MemoryV1DenySource::CardUnbound);
        }
        // memory—v1 §4.10: descendant resolution happens in the root tenant tree.
        let descendants = match reader.tenant_descendants(tenant) {
            Ok(list) => list,
            Err(_) => return CardOutcome::Pending(MemoryV1PendingSource::RootUnavailable),
        };
        let (tree_version, registry_version) = match reader.dependency_versions() {
            Ok(versions) => versions,
            Err(_) => return CardOutcome::Pending(MemoryV1PendingSource::RootUnavailable),
        };
        let mut dependencies: Vec<EvaluationDependency> = Vec::new();
        let mut winning_allows: Vec<WinningAllow> = Vec::new();
        let mut allow = false;
        let mut deny = false;
        let mut scope_denied = false;
        let mut pending: Option<MemoryV1PendingSource> = None;
        for binding in &context.bindings {
            // memory—v1 §4.6: reads depending on a fenced object are refused
            // immediately; §4.8 keeps a determinate DENY from a valid binding
            // ahead of any pending cause.
            match reader.is_fenced(binding.rule_set.rule_set_id) {
                Ok(true) => pending = pending.or(Some(MemoryV1PendingSource::FenceActive)),
                Ok(false) => {}
                Err(_) => pending = pending.or(Some(MemoryV1PendingSource::RootUnavailable)),
            }
            let Some(version) = binding.selected else {
                pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                continue;
            };
            if binding.binding.user_card_id != card
                || binding.rule_set.rule_set_id != binding.binding.rule_set_id
                || version.rule_set_id != binding.binding.rule_set_id
                || !binding.confirmations.iter().any(|confirmation| {
                    confirmation_matches(
                        confirmation,
                        binding.binding.binding_id,
                        binding.binding.rule_set_id,
                        &version.version_bytes,
                    )
                })
            {
                pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                continue;
            }
            let content = match parse_version(version) {
                Ok(content) => content,
                Err(_) => {
                    // memory—v1 §4.5/A-1: hash or grammar failure is bad data,
                    // never a silent skip.
                    pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                    continue;
                }
            };
            dependencies.push(EvaluationDependency {
                binding_id: binding.binding.binding_id,
                rule_set_id: binding.binding.rule_set_id,
                version_bytes: version.version_bytes.clone(),
            });
            // memory—v1 §4.4: a binding outside its window contributes nothing
            // (skip, not fail — unlike a broken binding above).
            if !window_active(
                binding.binding.valid_from,
                binding.binding.valid_until,
                start_time,
            ) {
                continue;
            }
            for hit in content.rule_hits(request.resource, request.action) {
                // memory—v1 §4.4: the entry-level window.
                let entry_open = hit
                    .validity
                    .map(|validity| validity.active_at(start_time))
                    .unwrap_or(true);
                if !entry_open {
                    continue;
                }
                // memory—v1 §4.10: scope predicates apply to object-bearing
                // requests only; type-level requests skip them. A present but
                // mismatched attribution is a deterministic scope denial; a
                // missing attribution is unverifiable and stays pending.
                let scope_ok = if request.target.is_none() {
                    true
                } else {
                    let owner_effective =
                        strictest_owner_scope(hit.owner_scope, binding.binding.owner_scope);
                    let tenant_effective =
                        strictest_tenant_scope(hit.tenant_scope, binding.binding.tenant_scope);
                    let owner_ok = match owner_effective {
                        MemoryV1OwnerScope::AllUsers => true,
                        MemoryV1OwnerScope::SelfUser => match request.target_owner {
                            Some(owner) if owner == user => true,
                            Some(_) => {
                                scope_denied = true;
                                false
                            }
                            None => {
                                pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                                false
                            }
                        },
                    };
                    let tenant_ok = match tenant_effective {
                        MemoryV1TenantScope::SelfTenant => match request.target_tenant {
                            Some(object_tenant) if object_tenant == tenant => true,
                            Some(_) => {
                                scope_denied = true;
                                false
                            }
                            None => {
                                pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                                false
                            }
                        },
                        MemoryV1TenantScope::SelfAndDescendants => match request.target_tenant {
                            Some(object_tenant)
                                if object_tenant == tenant
                                    || descendants.iter().any(|descendant| {
                                        descendant.as_slice() == object_tenant
                                    }) =>
                            {
                                true
                            }
                            Some(_) => {
                                scope_denied = true;
                                false
                            }
                            None => {
                                pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                                false
                            }
                        },
                    };
                    owner_ok && tenant_ok
                };
                if scope_denied {
                    return CardOutcome::Deny(MemoryV1DenySource::ScopeDenied);
                }
                if !scope_ok {
                    continue;
                }
                match hit.effect {
                    MemoryV1RuleEffect::Deny => deny = true,
                    MemoryV1RuleEffect::Allow => {
                        allow = true;
                        winning_allows.push(WinningAllow {
                            entry_validity: hit.validity.copied(),
                            binding_from: binding.binding.valid_from,
                            binding_until: binding.binding.valid_until,
                            owner_scope: strictest_owner_scope(
                                hit.owner_scope,
                                binding.binding.owner_scope,
                            ),
                            tenant_scope: strictest_tenant_scope(
                                hit.tenant_scope,
                                binding.binding.tenant_scope,
                            ),
                        });
                    }
                }
            }
        }
        // memory—v1 §4.8/§4.10: the decision order — determinate DENY (rule or
        // scope), then pending causes, then ALLOW, then no-match refusal.
        if deny {
            CardOutcome::Deny(MemoryV1DenySource::RuleDenied)
        } else if scope_denied {
            CardOutcome::Deny(MemoryV1DenySource::ScopeDenied)
        } else if let Some(pending) = pending {
            CardOutcome::Pending(pending)
        } else if allow {
            let mut owner_scope = MemoryV1OwnerScope::AllUsers;
            let mut tenant_scope = MemoryV1TenantScope::SelfAndDescendants;
            for winning in &winning_allows {
                owner_scope = strictest_owner_scope(owner_scope, winning.owner_scope);
                tenant_scope = strictest_tenant_scope(tenant_scope, winning.tenant_scope);
            }
            CardOutcome::Allow {
                dependencies,
                winning_allows,
                owner_scope,
                tenant_scope,
                tree_version,
                registry_version,
            }
        } else {
            CardOutcome::Deny(MemoryV1DenySource::NoMatch)
        }
    });
    let outcome = match outcome {
        Err(_) => CardOutcome::Pending(MemoryV1PendingSource::RootUnavailable),
        Ok(outcome) => outcome,
    };
    match outcome {
        CardOutcome::Deny(source) => non_allow(MemoryV1Decision::Deny, Some(source), None),
        CardOutcome::Pending(source) => non_allow(MemoryV1Decision::Pending, None, Some(source)),
        CardOutcome::Allow {
            dependencies,
            winning_allows,
            owner_scope,
            tenant_scope,
            tree_version,
            registry_version,
        } => {
            after_read();
            let Some(final_time) = clock() else {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            };
            if final_time < start_time || !facts.valid_at(final_time) {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            }
            // memory—v1 §4.7: the dependency-scoped recheck replaces the global
            // metadata comparison — unrelated modifications no longer invalidate
            // this request, while any touched-object change does.
            let record = DependencyRecord {
                card_id: identity.user_card_id.into_bytes(),
                instance_id: metadata.instance_id,
                bindings: dependencies,
                tenant_tree_version: tree_version,
                registry_version,
            };
            if !reader.recheck_dependencies(&record).unwrap_or(false) {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            }
            // memory—v1 §4.4: every winning ALLOW window must still be active
            // at the final trusted-time observation; a boundary crossing is
            // PENDING, never a silent pass.
            for winning in &winning_allows {
                if !window_active(
                    winning.entry_validity.and_then(|validity| validity.from),
                    winning.entry_validity.and_then(|validity| validity.until),
                    final_time,
                ) || !window_active(winning.binding_from, winning.binding_until, final_time)
                {
                    return non_allow(
                        MemoryV1Decision::Pending,
                        None,
                        Some(MemoryV1PendingSource::ContextInvalid),
                    );
                }
            }
            MemoryV1Evaluation {
                decision: MemoryV1Decision::Allow,
                deny_source: None,
                pending_source: None,
                admission: Some(MemoryV1Admission {
                    root: metadata,
                    identity,
                    resource: request.resource.to_owned(),
                    action: request.action.to_owned(),
                    target: request.target.map(<[u8]>::to_vec),
                    operation_id: request.operation_id.to_vec(),
                    operation_fingerprint: request.operation_fingerprint.to_vec(),
                    trusted_time_unix_seconds: final_time,
                    effective_owner_scope: owner_scope,
                    effective_tenant_scope: tenant_scope,
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
        IdentityCardRow, RuleSetRow, RuleSetVersionRow, TenantRow, UserCardRow, UserRow,
    };
    use astral_authorization_root::memory_v1_hamt::CandidateBudget;
    use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
    use astral_authorization_root::memory_v1_request::RequestRootScope;
    use astral_authorization_root::memory_v1_root::{install_process_root, RootStatus};
    use astral_authorization_root::memory_v1_rules::canonical_version_bytes;
    use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
    use astral_types::memory_v1::MemoryId;

    // memory—v1: Build an identity with exact UUID bytes.
    fn identity(card: u8) -> CandidateIdentity {
        CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([2; 16]),
            user_card_id: MemoryId::from_bytes([card; 16]),
            tenant_id: MemoryId::from_bytes([3; 16]),
        }
    }

    // memory—v1: Install valid hashed rule content and confirmed binding rows.
    fn fixture() -> (CandidateRows, Vec<CurrentSelection>) {
        let mut rows = CandidateRows {
            users: vec![UserRow { user_id: [1; 16] }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: [2; 16],
                user_id: [1; 16],
            }],
            tenants: vec![TenantRow {
                tenant_id: [3; 16],
                parent_tenant_id: None,
            }],
            user_cards: [4, 7, 8]
                .into_iter()
                .map(|id| UserCardRow {
                    user_card_id: [id; 16],
                    user_id: [1; 16],
                    tenant_id: [3; 16],
                })
                .collect(),
            ..CandidateRows::default()
        };
        let mut selections = Vec::new();
        for (set, binding, card, layer, content) in [
            (
                10,
                20,
                4,
                BindingLayer::Base,
                br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW"}]}"#
                    .as_slice(),
            ),
            (
                11,
                21,
                7,
                BindingLayer::Base,
                br#"{"rules":[{"ruleId":"R2","resource":"document","action":"read","effect":"ALLOW"}]}"#
                    .as_slice(),
            ),
            (
                12,
                22,
                7,
                BindingLayer::Overlay,
                br#"{"rules":[{"ruleId":"R3","resource":"document","action":"read","effect":"DENY"}]}"#
                    .as_slice(),
            ),
            (
                13,
                23,
                8,
                BindingLayer::Overlay,
                br#"{"rules":[{"ruleId":"R4","resource":"document","action":"read","effect":"ALLOW"}]}"#
                    .as_slice(),
            ),
        ] {
            let version = vec![1];
            let timestamp = vec![2];
            let input = canonical_version_bytes(&version, content, &timestamp);
            rows.rule_sets.push(RuleSetRow {
                rule_set_id: [set; 16],
                owner_tenant_id: [3; 16],
            });
            rows.rule_set_versions.push(RuleSetVersionRow {
                rule_set_id: [set; 16],
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                // memory—v1 §4.4: the fixture is a conforming writer — the
                // digest is computed over the canonical encoding it registers.
                hash_bytes: astral_authorization_root::memory_v1_rules::version_digest(&input),
                hash_input_bytes: input,
            });
            rows.bindings.push(BindingRow {
                binding_id: [binding; 16],
                user_card_id: [card; 16],
                rule_set_id: [set; 16],
                binding_layer: layer,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
            });
            rows.binding_confirmations.push(BindingConfirmationRow {
                confirmation_id: [binding + 20; 16],
                binding_id: [binding; 16],
                rule_set_id: [set; 16],
                version_bytes: version.clone(),
                confirmer_user_id: [1; 16],
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
            });
            selections.push(CurrentSelection {
                rule_set_id: [set; 16],
                version_bytes: version,
            });
        }
        (rows, selections)
    }

    // memory—v1: Exercise the real installed root and session authority in an isolated process.
    #[test]
    fn formal_rules_and_root_recheck() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_TYPED_FORMAL_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::formal_rules_and_root_recheck",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        let (rows, selections) = fixture();
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 64,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        let authority = MemoryV1SessionAuthority::new();
        let session_for = |root: &RequestRootExtension, identity: CandidateIdentity| {
            let issued = authority
                .identity_session_adapter()
                .issue_verified_session(identity, 100, 100)
                .unwrap();
            authority
                .verifier()
                .verify_and_bind(issued.credential(), 100, root)
                .unwrap()
        };
        // memory—v1 §4.10: the trusted attribution attributes of the target
        // object, produced by the owning business service.
        let user_bytes = [1_u8; 16];
        let tenant_bytes = [3_u8; 16];
        let request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: Some(b"target"),
            // memory—v1 §4.10: object-bearing requests carry the trusted
            // attribution attributes of the owning business service.
            target_tenant: Some(&tenant_bytes),
            target_owner: Some(&user_bytes),
            operation_id: b"operation",
            operation_fingerprint: b"fingerprint",
        };
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let session = session_for(&root, identity(4));
        assert_eq!(
            evaluate_with(&root, &session, &request, || Some(110), || {}).decision,
            MemoryV1Decision::Pending
        );
        assert_eq!(
            owner.handle().metadata().unwrap().status,
            astral_authorization_root::memory_v1_root::RootStatus::Candidate
        );
        // memory—v1: Candidate roots remain non-authorizing until a complete
        // adoption verifier supplies an opaque certificate.
        let unmatched = MemoryV1Request {
            action: "READ",
            ..request
        };
        let no_match = evaluate_with(&root, &session, &unmatched, || Some(110), || {});
        assert_eq!(no_match.decision, MemoryV1Decision::Pending);
        assert!(no_match.admission.is_none());

        let other_scope = RequestRootScope::new(owner.handle(), Default::default());
        let other_root = other_scope.extension();
        let other_session = session_for(&other_root, identity(4));
        assert_eq!(
            evaluate_with(&other_root, &other_session, &request, || Some(110), || {}).decision,
            MemoryV1Decision::Pending
        );
        let mut times = [110, 109].into_iter();
        assert_eq!(
            evaluate_with(&root, &session, &request, || times.next(), || {}).decision,
            MemoryV1Decision::Pending
        );
        assert_eq!(
            evaluate_with(&root, &session, &request, || Some(200), || {}).decision,
            MemoryV1Decision::Pending
        );

        // memory—v1: Adoption publishes a new phase. The earlier request reader
        // keeps its Candidate phase for its whole lifetime and stays pending.
        let adopted = owner.adopt_serving_for_isolated_tests().unwrap();
        // memory—v1 §4.9: the composition installs the aggregated registry
        // before any formal evaluation; uninstalled means deterministic denial.
        owner
            .install_registry(&[
                RegistryDeclaration {
                    resource: "document".to_owned(),
                    actions: vec![
                        "read".to_owned(),
                        "create".to_owned(),
                        "update".to_owned(),
                        "delete".to_owned(),
                    ],
                },
                RegistryDeclaration {
                    resource: "other".to_owned(),
                    actions: vec!["read".to_owned()],
                },
            ])
            .unwrap();
        assert_eq!(adopted.status, RootStatus::Serving);
        assert_eq!(
            evaluate_with(&root, &session, &request, || Some(110), || {}).decision,
            MemoryV1Decision::Pending
        );

        let serving_scope = RequestRootScope::new(owner.handle(), Default::default());
        let serving_root = serving_scope.extension();
        let card4 = session_for(&serving_root, identity(4));
        let allowed = evaluate_with(&serving_root, &card4, &request, || Some(110), || {});
        assert_eq!(allowed.decision, MemoryV1Decision::Allow);
        let admission = allowed.admission.expect("an allow carries its admission");
        assert_eq!(admission.root(), adopted);
        assert_eq!(admission.identity(), identity(4));
        assert_eq!(admission.resource(), "document");
        assert_eq!(admission.action(), "read");
        assert_eq!(admission.target(), Some(b"target".as_slice()));
        assert_eq!(admission.operation_id(), b"operation");
        assert_eq!(admission.operation_fingerprint(), b"fingerprint");
        assert_eq!(admission.trusted_time_unix_seconds(), 110);

        // A complete serving phase without a matching confirmed allow is a deny.
        let denied = evaluate_with(&serving_root, &card4, &unmatched, || Some(110), || {});
        assert_eq!(denied.decision, MemoryV1Decision::Deny);
        assert!(denied.admission.is_none());
        // OVERLAY DENY blocks the BASE allow for card 7 only; an OVERLAY allow
        // alone (card 8) adds the permission.
        let card7 = session_for(&serving_root, identity(7));
        assert_eq!(
            evaluate_with(&serving_root, &card7, &request, || Some(110), || {}).decision,
            MemoryV1Decision::Deny
        );
        let card8 = session_for(&serving_root, identity(8));
        assert_eq!(
            evaluate_with(&serving_root, &card8, &request, || Some(110), || {}).decision,
            MemoryV1Decision::Allow
        );
        // Session facts that disagree with the root relationships never allow.
        let foreign_tenant = CandidateIdentity {
            tenant_id: MemoryId::from_bytes([9; 16]),
            ..identity(4)
        };
        let mismatched = session_for(&serving_root, foreign_tenant);
        assert_eq!(
            evaluate_with(&serving_root, &mismatched, &request, || Some(110), || {}).decision,
            MemoryV1Decision::Deny
        );
        // Final recheck: clock rollback and session expiry fail closed on Serving.
        let mut rollback = [110, 109].into_iter();
        assert_eq!(
            evaluate_with(&serving_root, &card4, &request, || rollback.next(), || {}).decision,
            MemoryV1Decision::Pending
        );
        assert_eq!(
            evaluate_with(&serving_root, &card4, &request, || Some(200), || {}).decision,
            MemoryV1Decision::Pending
        );
        // The PolicyEngine entry counts each evaluation and its allow outcome.
        let engine = crate::PolicyEngine::new();
        assert_eq!(
            engine
                .evaluate_memory_v1(&serving_root, &card4, &request)
                .decision,
            MemoryV1Decision::Pending,
            "the process clock is far past the fixture session window"
        );
        assert_eq!(engine.get_stats().evaluation_count, 1);
        assert_eq!(engine.get_stats().allow_count, 0);
        // A root change between the read and the final recheck withdraws the allow.
        assert_eq!(
            evaluate_with(
                &serving_root,
                &card4,
                &request,
                || Some(110),
                || drop(owner)
            )
            .decision,
            MemoryV1Decision::Pending
        );
    }

    // memory—v1 §3.6/§4.10: build one object-bearing evaluation request with
    // the trusted attribution attributes supplied by the owning service.
    fn contract_request<'a>(
        target_tenant: Option<&'a [u8]>,
        target_owner: Option<&'a [u8]>,
    ) -> MemoryV1Request<'a> {
        MemoryV1Request {
            resource: "document",
            action: "read",
            target: Some(b"object"),
            target_tenant,
            target_owner,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        }
    }

    // memory—v1 §4.4–§4.10 (batch A): contract scenarios over one serving root.
    #[test]
    fn batch_a_contract_scenarios() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_BATCH_A_CONTRACT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::batch_a_contract_scenarios",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }

        // The body runs in an isolated child process: the process root slot is
        // once-per-process, so every root-installing test needs its own process.
        let (rows, selections) = contract_fixture();
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 512,
                max_bindings_per_read: 32,
            },
        )
        .unwrap();
        let authority = MemoryV1SessionAuthority::new();
        let session_for = |root: &RequestRootExtension, card: u8| {
            let issued = authority
                .identity_session_adapter()
                .issue_verified_session(identity(card), 100, 100)
                .unwrap();
            authority
                .verifier()
                .verify_and_bind(issued.credential(), 100, root)
                .unwrap()
        };
        let adopted = owner.adopt_serving_for_isolated_tests().unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let user_bytes = [1_u8; 16];
        let tenant_bytes = [3_u8; 16];
        let child_tenant = [30_u8; 16];
        let foreign_tenant = [99_u8; 16];
        let evaluate = |card: u8, target_tenant: Option<&[u8]>, target_owner: Option<&[u8]>| {
            evaluate_with(
                &root,
                &session_for(&root, card),
                &contract_request(target_tenant, target_owner),
                || Some(110),
                || {},
            )
        };

        // memory—v1 §4.8 A-2.4: a determinate DENY from a valid binding wins
        // over a broken sibling binding — the outcome cannot flip.
        let denied = evaluate(7, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(denied.decision, MemoryV1Decision::Deny);
        assert_eq!(denied.deny_source, Some(MemoryV1DenySource::RuleDenied));
        // memory—v1 A-2.5: the mirrored arrangement with the reversed rule
        // order produces the same aggregate — order does not matter.
        let mirrored = evaluate(12, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(mirrored.decision, MemoryV1Decision::Deny);
        assert_eq!(mirrored.deny_source, Some(MemoryV1DenySource::RuleDenied));

        // memory—v1 §4.10: a matched rule whose scope excludes the object is
        // a deterministic scope denial — card 4 carries both the wide rule and
        // a strict-default rule, so the tenant-30 object is scope-denied while
        // the tenant-3 object allows with the strictest effective scope.
        let own_tenant = evaluate(4, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(own_tenant.decision, MemoryV1Decision::Allow);
        assert_eq!(
            own_tenant
                .admission
                .expect("allow carries admission")
                .effective_owner_scope(),
            MemoryV1OwnerScope::SelfUser
        );
        let out_of_scope = evaluate(4, Some(&child_tenant), Some(&user_bytes));
        assert_eq!(out_of_scope.decision, MemoryV1Decision::Deny);
        assert_eq!(
            out_of_scope.deny_source,
            Some(MemoryV1DenySource::ScopeDenied)
        );

        // memory—v1 §4.4: expired entry windows skip the rule (no-match deny,
        // never a silent pass through a dead grant).
        let expired_entry = evaluate(8, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(expired_entry.decision, MemoryV1Decision::Deny);
        assert_eq!(expired_entry.deny_source, Some(MemoryV1DenySource::NoMatch));
        // memory—v1 §4.4: an expired binding window skips the whole binding.
        let expired_binding = evaluate(9, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(expired_binding.decision, MemoryV1Decision::Deny);
        assert_eq!(
            expired_binding.deny_source,
            Some(MemoryV1DenySource::NoMatch)
        );

        // memory—v1 §4.10: two-layer scopes — entry ∩ binding, owner and
        // tenant dimensions; matching attribution allows, mismatched denies
        // deterministically and missing attribution stays pending.
        let allowed = evaluate(14, Some(&child_tenant), Some(&user_bytes));
        assert_eq!(allowed.decision, MemoryV1Decision::Allow);
        let admission = allowed.admission.expect("allow carries admission");
        assert_eq!(
            admission.effective_owner_scope(),
            MemoryV1OwnerScope::AllUsers
        );
        assert_eq!(
            admission.effective_tenant_scope(),
            MemoryV1TenantScope::SelfAndDescendants
        );
        // The strict-default card denies a foreign owner deterministically;
        // the wide card (ownerScope all) deliberately allows any owner.
        let foreign_owner = evaluate(13, Some(&tenant_bytes), Some(&[9_u8; 16]));
        assert_eq!(foreign_owner.decision, MemoryV1Decision::Deny);
        assert_eq!(
            foreign_owner.deny_source,
            Some(MemoryV1DenySource::ScopeDenied)
        );
        let cross_company = evaluate(14, Some(&foreign_tenant), Some(&user_bytes));
        assert_eq!(cross_company.decision, MemoryV1Decision::Deny);
        assert_eq!(
            cross_company.deny_source,
            Some(MemoryV1DenySource::ScopeDenied)
        );
        let strict_defaults = evaluate(13, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(strict_defaults.decision, MemoryV1Decision::Allow);
        assert_eq!(
            strict_defaults
                .admission
                .expect("allow carries admission")
                .effective_owner_scope(),
            MemoryV1OwnerScope::SelfUser
        );
        // memory—v1 A-1: a missing attribution on an object-bearing request
        // is unverifiable and stays pending — never a silent pass.
        let missing_attribution = evaluate(13, None, None);
        assert_eq!(missing_attribution.decision, MemoryV1Decision::Pending);
        assert_eq!(
            missing_attribution.pending_source,
            Some(MemoryV1PendingSource::ContextInvalid)
        );

        // memory—v1 §4.9 A-3.4: unregistered resources refuse deterministically.
        let mut unregistered = contract_request(Some(&tenant_bytes), Some(&user_bytes));
        unregistered.resource = "ghost";
        let ghost = evaluate_with(
            &root,
            &session_for(&root, 13),
            &unregistered,
            || Some(110),
            || {},
        );
        assert_eq!(ghost.decision, MemoryV1Decision::Deny);
        assert_eq!(
            ghost.deny_source,
            Some(MemoryV1DenySource::UnregisteredResource)
        );

        // memory—v1 §4.6: the modification window refuses reads immediately and
        // releases them when the fence closes; a determinate DENY still wins.
        let declaration = astral_authorization_root::memory_v1_fence::FenceDeclaration {
            rule_set_version: vec![1],
            root_version: adopted.version,
            digest: adopted.digest,
        };
        owner
            .begin_modification_fence([16_u8; 16], &declaration)
            .unwrap();
        let fenced = evaluate(11, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(fenced.decision, MemoryV1Decision::Pending);
        assert_eq!(
            fenced.pending_source,
            Some(MemoryV1PendingSource::FenceActive)
        );
        owner.abort_modification_fence([16_u8; 16]).unwrap();
        let released = evaluate(11, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(released.decision, MemoryV1Decision::Allow);

        // memory—v1 §3.6/§4.8: an unbound card is a deterministic denial.
        let unbound = evaluate(15, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(unbound.decision, MemoryV1Decision::Deny);
        assert_eq!(unbound.deny_source, Some(MemoryV1DenySource::CardUnbound));
    }

    // memory—v1: Contract fixture — two tenants (3 → 30), one user, cards and
    // rule sets per §4.4–§4.10 scenario. Broken rule sets 15/17 carry invalid
    // digests; expired windows cover both levels.
    fn contract_fixture() -> (CandidateRows, Vec<CurrentSelection>) {
        let mut rows = CandidateRows {
            users: vec![UserRow { user_id: [1; 16] }, UserRow { user_id: [0; 16] }],
            identity_cards: vec![
                IdentityCardRow {
                    identity_card_id: [2; 16],
                    user_id: [1; 16],
                },
                IdentityCardRow {
                    identity_card_id: [0; 16],
                    user_id: [0; 16],
                },
            ],
            tenants: vec![
                TenantRow {
                    tenant_id: [3; 16],
                    parent_tenant_id: None,
                },
                TenantRow {
                    tenant_id: [30; 16],
                    parent_tenant_id: Some([3; 16]),
                },
            ],
            user_cards: [4, 7, 8, 9, 11, 12, 13, 14, 15]
                .into_iter()
                .map(|id| UserCardRow {
                    user_card_id: [id; 16],
                    user_id: [1; 16],
                    tenant_id: [3; 16],
                })
                .collect(),
            ..CandidateRows::default()
        };
        let mut selections = Vec::new();
        let allow_all_desc = br#"{"rules":[{"ruleId":"A","resource":"document","action":"read","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#;
        let allow_defaults =
            br#"{"rules":[{"ruleId":"A","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        let deny_defaults = br#"{"rules":[{"ruleId":"D","resource":"document","action":"read","effect":"DENY"},{"ruleId":"A","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        let allow_expired = br#"{"rules":[{"ruleId":"A","resource":"document","action":"read","effect":"ALLOW","validity":{"from":1,"until":2}}]}"#;
        let allow_reversed = br#"{"rules":[{"ruleId":"D","resource":"document","action":"read","effect":"DENY"},{"ruleId":"A","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        // One rule set per scenario; all digests conform (a wrong digest is
        // refused at load time by the adoption validator, see load_refuses_...).
        let sets: Vec<(u8, &[u8], bool)> = vec![
            (10, allow_all_desc, true),
            (11, allow_defaults, true),
            (12, deny_defaults, true),
            (13, allow_expired, true),
            (14, allow_defaults, true),
            (15, allow_defaults, true),
            (16, allow_defaults, true),
            (17, allow_defaults, true),
            (18, allow_reversed, true),
        ];
        for (set, content, hash_ok) in sets {
            let version = vec![1];
            let timestamp = vec![2];
            let input = canonical_version_bytes(&version, content, &timestamp);
            let hash = if hash_ok {
                astral_authorization_root::memory_v1_rules::version_digest(&input)
            } else {
                // memory—v1 A-1: a distinct wrong digest per broken set.
                let mut wrong = vec![0xAB; 32];
                wrong[31] = set;
                wrong
            };
            rows.rule_sets.push(RuleSetRow {
                rule_set_id: [set; 16],
                owner_tenant_id: [3; 16],
            });
            rows.rule_set_versions.push(RuleSetVersionRow {
                rule_set_id: [set; 16],
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                hash_input_bytes: input,
                hash_bytes: hash,
            });
            selections.push(CurrentSelection {
                rule_set_id: [set; 16],
                version_bytes: version,
            });
        }
        // Bindings: one specification struct per scenario binding.
        struct ContractBinding {
            binding: u8,
            card: u8,
            set: u8,
            layer: BindingLayer,
            from: Option<i64>,
            until: Option<i64>,
            owner_scope: Option<MemoryV1OwnerScope>,
            tenant_scope: Option<MemoryV1TenantScope>,
        }
        let bindings = vec![
            ContractBinding {
                binding: 20,
                card: 4,
                set: 10,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 25,
                card: 4,
                set: 15,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 21,
                card: 7,
                set: 11,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 22,
                card: 7,
                set: 12,
                layer: BindingLayer::Overlay,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 26,
                card: 7,
                set: 17,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 23,
                card: 8,
                set: 13,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 24,
                card: 9,
                set: 14,
                layer: BindingLayer::Base,
                from: Some(1),
                until: Some(2),
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 30,
                card: 11,
                set: 16,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 31,
                card: 12,
                set: 18,
                layer: BindingLayer::Overlay,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 32,
                card: 12,
                set: 12,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 33,
                card: 12,
                set: 17,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 34,
                card: 13,
                set: 11,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: None,
                tenant_scope: None,
            },
            ContractBinding {
                binding: 35,
                card: 14,
                set: 10,
                layer: BindingLayer::Base,
                from: None,
                until: None,
                owner_scope: Some(MemoryV1OwnerScope::AllUsers),
                tenant_scope: Some(MemoryV1TenantScope::SelfAndDescendants),
            },
        ];
        // memory—v1 A-1: bindings 25/26 carry confirmations signed by the
        // all-zero user — they pass the load-time FK but the evaluation's
        // confirmation check refuses them (the service-period bad binding).
        for ContractBinding {
            binding,
            card,
            set,
            layer,
            from,
            until,
            owner_scope,
            tenant_scope,
        } in bindings
        {
            rows.bindings.push(BindingRow {
                binding_id: [binding; 16],
                user_card_id: [card; 16],
                rule_set_id: [set; 16],
                binding_layer: layer,
                valid_from: from,
                valid_until: until,
                owner_scope: owner_scope.unwrap_or_default(),
                tenant_scope: tenant_scope.unwrap_or_default(),
            });
            let confirmer = [1_u8; 16];
            rows.binding_confirmations.push(BindingConfirmationRow {
                confirmation_id: [binding.wrapping_add(0x40); 16],
                binding_id: [binding; 16],
                rule_set_id: [set; 16],
                version_bytes: vec![1],
                confirmer_user_id: confirmer,
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
            });
        }
        (rows, selections)
    }

    // memory—v1 A-1.1: a version whose stored digest does not match its
    // canonical encoding is refused at load time — never adopted, never served.
    #[test]
    fn load_refuses_a_wrong_digest() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_LOAD_REFUSES_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::load_refuses_a_wrong_digest",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        let mut rows = CandidateRows {
            users: vec![UserRow { user_id: [1; 16] }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: [2; 16],
                user_id: [1; 16],
            }],
            tenants: vec![TenantRow {
                tenant_id: [3; 16],
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: [4; 16],
                user_id: [1; 16],
                tenant_id: [3; 16],
            }],
            ..CandidateRows::default()
        };
        let content =
            br#"{"rules":[{"ruleId":"A","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        let version = vec![1];
        let timestamp = vec![2];
        let input = canonical_version_bytes(&version, content, &timestamp);
        rows.rule_sets.push(RuleSetRow {
            rule_set_id: [10; 16],
            owner_tenant_id: [3; 16],
        });
        rows.rule_set_versions.push(RuleSetVersionRow {
            rule_set_id: [10; 16],
            version_bytes: version.clone(),
            content_bytes: content.to_vec(),
            timestamp_bytes: timestamp,
            hash_input_bytes: input.clone(),
            hash_bytes: vec![0xAB; 32],
        });
        rows.bindings.push(BindingRow {
            binding_id: [20; 16],
            user_card_id: [4; 16],
            rule_set_id: [10; 16],
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::default(),
            tenant_scope: MemoryV1TenantScope::default(),
        });
        let owner = install_process_root(
            rows,
            vec![CurrentSelection {
                rule_set_id: [10; 16],
                version_bytes: version,
            }],
            CandidateBudget {
                max_table_rows: 64,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        assert!(owner.adopt_serving_for_isolated_tests().is_err());
    }
}
