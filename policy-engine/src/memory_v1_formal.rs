//! Typed memory—v1 rule evaluation over a request's shared root and session.
//!
//! The formal entry is `PolicyEngine::evaluate_memory_v1`; the legacy
//! `PolicyEngine::evaluate` keeps returning `AUTHORIZATION_PENDING`. A serving
//! root and structural confirmation do not establish production adoption,
//! resource ownership, confirmer authority, or durable audit evidence.

use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    binding_is_active, RuleSetStatus, UserCardStatus,
};
use astral_authorization_root::memory_v1_registry::RegistryError;
use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{
    DependencyRecord, EvaluationDependency, GovernanceTargetFacts, RequestRootReader, RootMetadata,
    RootStatus,
};
use astral_authorization_root::memory_v1_rules::{
    window_active, BindingConfirmationState, ChangeConfirmationState, MemoryV1OwnerScope,
    MemoryV1RuleEffect, MemoryV1TenantScope, MemoryV1Validity,
};
use astral_authorization_root::memory_v1_session::{
    FinalCheckTimeConstraints, FinalCheckWindow, RequestSessionExtension, SessionFinalCheck,
    VerifiedSessionFacts,
};
use astral_types::memory_v1::CandidateIdentity;
use astral_types::memory_v1_audit::MemoryV1AuditDenySource;

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

/// memory—v1: Explicit intended operation for a rule-set change confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1RuleSetChangeIntent {
    Create,
    Publish,
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
    target_tenant: Option<Vec<u8>>,
    target_owner: Option<Vec<u8>>,
    operation_id: Vec<u8>,
    operation_fingerprint: Vec<u8>,
    trusted_time_unix_seconds: i64,
    change_intent: Option<MemoryV1RuleSetChangeIntent>,
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

    /// memory—v1: Access the exact target tenant attribution bound at evaluation.
    pub fn target_tenant(&self) -> Option<&[u8]> {
        self.target_tenant.as_deref()
    }

    /// memory—v1: Access the exact target owner attribution bound at evaluation.
    pub fn target_owner(&self) -> Option<&[u8]> {
        self.target_owner.as_deref()
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

    /// memory—v1: Return the explicit change-confirmation intent, if any.
    pub fn change_intent(&self) -> Option<MemoryV1RuleSetChangeIntent> {
        self.change_intent
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
    /// §4.11 B-1.3 N-7: confirm-class action targeting the operator's own authority.
    SelfConfirmation,
    /// §4.12 B-2.3: the session card is DISABLED.
    CardDisabled,
}

impl MemoryV1DenySource {
    /// memory—v1: Map the observed decision source to the frozen audit vocabulary.
    /// This conversion does not supply a trusted observation or persist an audit event.
    pub const fn audit_source(self) -> MemoryV1AuditDenySource {
        match self {
            Self::RuleDenied => MemoryV1AuditDenySource::RuleDeny,
            Self::NoMatch => MemoryV1AuditDenySource::NoMatch,
            Self::ScopeDenied => MemoryV1AuditDenySource::ScopeDenied,
            Self::CardUnbound => MemoryV1AuditDenySource::CardUnbound,
            Self::IdentityMismatch => MemoryV1AuditDenySource::IdentityMismatch,
            Self::UnregisteredResource => MemoryV1AuditDenySource::UnregisteredResource,
            Self::SelfConfirmation => MemoryV1AuditDenySource::SelfConfirmation,
            Self::CardDisabled => MemoryV1AuditDenySource::CardDisabled,
        }
    }
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

impl MemoryV1PendingSource {
    /// memory—v1: Return the frozen internal source for log and metric correlation.
    /// PENDING remains non-persistable under the audit contract.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContextInvalid => "context_invalid",
            Self::FenceActive => "fence_active",
            Self::RootUnavailable => "root_unavailable",
        }
    }
}

/// memory—v1: A root-derived binding checked as part of a rule-set change.
///
/// This is a read-phase association, not proof of authorization or durable audit.
/// Its values are kept separate from the rule-set request target.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MemoryV1AffectedBindingObservation {
    binding_id: [u8; 16],
    user_card_id: [u8; 16],
    owner_user_id: [u8; 16],
    tenant_id: [u8; 16],
}

impl std::fmt::Debug for MemoryV1AffectedBindingObservation {
    // memory—v1: Avoid exposing affected identities through nested debug output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryV1AffectedBindingObservation(<redacted>)")
    }
}

impl MemoryV1AffectedBindingObservation {
    /// memory—v1: Return the impacted binding's identifier.
    pub fn binding_id(&self) -> [u8; 16] {
        self.binding_id
    }
    /// memory—v1: Return the impacted authorization card's identifier.
    pub fn user_card_id(&self) -> [u8; 16] {
        self.user_card_id
    }
    /// memory—v1: Return the impacted card owner's identifier.
    pub fn owner_user_id(&self) -> [u8; 16] {
        self.owner_user_id
    }
    /// memory—v1: Return the impacted binding's tenant identifier.
    pub fn tenant_id(&self) -> [u8; 16] {
        self.tenant_id
    }
}

/// A bounded snapshot of a DENY from one authoritative read phase.
///
/// This value is not an audit event, a final trusted-time observation, durable
/// evidence, or an authorization to allow or commit. Its fields can only be
/// populated by the evaluator. Debug output deliberately omits request data.
#[derive(Clone, PartialEq, Eq)]
pub struct MemoryV1DenyObservation {
    root: RootMetadata,
    identity: CandidateIdentity,
    read_started_at_unix_seconds: i64,
    resource: String,
    action: String,
    target: Option<Vec<u8>>,
    target_tenant: Option<Vec<u8>>,
    target_owner: Option<Vec<u8>>,
    affected_binding: Option<MemoryV1AffectedBindingObservation>,
    operation_id: Vec<u8>,
    operation_fingerprint: Vec<u8>,
    source: MemoryV1DenySource,
    batch_sequence: Option<u32>,
}

impl std::fmt::Debug for MemoryV1DenyObservation {
    // memory—v1: Do not expose any request, identity, or root data in logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryV1DenyObservation(<redacted>)")
    }
}

impl MemoryV1DenyObservation {
    /// memory—v1: Return the metadata of the root read during the decision.
    pub fn root(&self) -> RootMetadata {
        self.root
    }
    /// memory—v1: Return the verified session identity used in that read.
    pub fn identity(&self) -> CandidateIdentity {
        self.identity
    }
    /// memory—v1: Return the read-start clock sample, not a final trusted time.
    pub fn read_started_at_unix_seconds(&self) -> i64 {
        self.read_started_at_unix_seconds
    }
    /// memory—v1: Return the resource of the selected denial.
    pub fn resource(&self) -> &str {
        &self.resource
    }
    /// memory—v1: Return the action of the selected denial.
    pub fn action(&self) -> &str {
        &self.action
    }
    /// memory—v1: Return the selected target, if known to the evaluation.
    pub fn target(&self) -> Option<&[u8]> {
        self.target.as_deref()
    }
    /// memory—v1: Return the selected target's tenant, when supplied.
    pub fn target_tenant(&self) -> Option<&[u8]> {
        self.target_tenant.as_deref()
    }
    /// memory—v1: Return the selected target's owner, when supplied.
    pub fn target_owner(&self) -> Option<&[u8]> {
        self.target_owner.as_deref()
    }
    /// memory—v1: Return a separately identified binding when its evaluation
    /// caused a rule-set change denial. This is absent for a rule-set-level
    /// denial or when no single binding was selected.
    pub fn affected_binding(&self) -> Option<&MemoryV1AffectedBindingObservation> {
        self.affected_binding.as_ref()
    }
    /// memory—v1: Return the raw caller-supplied operation binding.
    pub fn operation_id(&self) -> &[u8] {
        &self.operation_id
    }
    /// memory—v1: Return the raw caller-supplied fingerprint binding.
    pub fn operation_fingerprint(&self) -> &[u8] {
        &self.operation_fingerprint
    }
    /// memory—v1: Return the actual denial source.
    pub fn source(&self) -> MemoryV1DenySource {
        self.source
    }
    /// memory—v1: Return the selected batch item's original sequence, if applicable.
    pub fn batch_sequence(&self) -> Option<u32> {
        self.batch_sequence
    }
}

// memory—v1: Capture only after a real denial has been selected in this reader.
pub(crate) fn capture_deny_observation(
    metadata: RootMetadata,
    facts: &VerifiedSessionFacts,
    read_started_at_unix_seconds: i64,
    request: &MemoryV1Request<'_>,
    source: MemoryV1DenySource,
    batch_sequence: Option<u32>,
) -> Box<MemoryV1DenyObservation> {
    Box::new(MemoryV1DenyObservation {
        root: metadata,
        identity: facts.candidate_identity(),
        read_started_at_unix_seconds,
        resource: request.resource.to_owned(),
        action: request.action.to_owned(),
        target: request.target.map(<[u8]>::to_vec),
        target_tenant: request.target_tenant.map(<[u8]>::to_vec),
        target_owner: request.target_owner.map(<[u8]>::to_vec),
        affected_binding: None,
        operation_id: request.operation_id.to_vec(),
        operation_fingerprint: request.operation_fingerprint.to_vec(),
        source,
        batch_sequence,
    })
}

// memory—v1: A checked impact binding is an association, not a replacement for
// the original rule-set target or its ownerless attribution.
pub(crate) fn capture_rule_set_binding_deny_observation(
    metadata: RootMetadata,
    facts: &VerifiedSessionFacts,
    read_started_at_unix_seconds: i64,
    request: &MemoryV1Request<'_>,
    source: MemoryV1DenySource,
    binding_id: [u8; 16],
    target: GovernanceTargetFacts,
) -> Box<MemoryV1DenyObservation> {
    let mut observation = capture_deny_observation(
        metadata,
        facts,
        read_started_at_unix_seconds,
        request,
        source,
        None,
    );
    observation.affected_binding = Some(MemoryV1AffectedBindingObservation {
        binding_id,
        user_card_id: target.user_card_id,
        owner_user_id: target.owner_user_id,
        tenant_id: target.tenant_id,
    });
    observation
}

/// Evaluation values remain publicly constructible, so consumers must not treat
/// an observation attached to a result as proof of the result's origin. A captured
/// observation itself has private fields and cannot be fabricated by callers.
/// An admission is present only when the decision is `Allow`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1Evaluation {
    pub decision: MemoryV1Decision,
    pub deny_source: Option<MemoryV1DenySource>,
    pub pending_source: Option<MemoryV1PendingSource>,
    pub admission: Option<MemoryV1Admission>,
    /// Read-phase data, present only when a DENY was attributable in that phase.
    pub deny_observation: Option<Box<MemoryV1DenyObservation>>,
}

// memory—v1: A planned action contains all inputs needed for one shared final
// check. It deliberately does not expose a mutation capability or a commit gate.
#[derive(Clone)]
pub(crate) struct MemoryV1ActionDraft {
    root: RootMetadata,
    identity: CandidateIdentity,
    resource: String,
    action: String,
    target: Option<Vec<u8>>,
    target_tenant: Option<Vec<u8>>,
    target_owner: Option<Vec<u8>>,
    operation_id: Vec<u8>,
    operation_fingerprint: Vec<u8>,
    change_intent: Option<MemoryV1RuleSetChangeIntent>,
    effective_owner_scope: MemoryV1OwnerScope,
    effective_tenant_scope: MemoryV1TenantScope,
    dependency: DependencyRecord,
    future_boundaries: Vec<i64>,
    winning_windows: Vec<FinalCheckWindow>,
    target_rule_sets: Vec<[u8; 16]>,
}

impl MemoryV1ActionDraft {
    // memory—v1: Expose only the shared evaluator's final-check inputs.
    pub(crate) fn root(&self) -> RootMetadata {
        self.root
    }

    pub(crate) fn identity(&self) -> CandidateIdentity {
        self.identity
    }

    pub(crate) fn dependency(&self) -> &DependencyRecord {
        &self.dependency
    }

    pub(crate) fn future_boundaries(&self) -> &[i64] {
        &self.future_boundaries
    }

    pub(crate) fn winning_windows(&self) -> &[FinalCheckWindow] {
        &self.winning_windows
    }

    pub(crate) fn target_rule_sets(&self) -> &[[u8; 16]] {
        &self.target_rule_sets
    }

    pub(crate) fn into_admission(self, trusted_time_unix_seconds: i64) -> MemoryV1Admission {
        MemoryV1Admission {
            root: self.root,
            identity: self.identity,
            resource: self.resource,
            action: self.action,
            target: self.target,
            target_tenant: self.target_tenant,
            target_owner: self.target_owner,
            operation_id: self.operation_id,
            operation_fingerprint: self.operation_fingerprint,
            trusted_time_unix_seconds,
            change_intent: self.change_intent,
            effective_owner_scope: self.effective_owner_scope,
            effective_tenant_scope: self.effective_tenant_scope,
        }
    }
}

pub(crate) enum MemoryV1DenyTarget {
    Request,
    AffectedBinding {
        binding_id: [u8; 16],
        facts: GovernanceTargetFacts,
    },
    Unavailable,
}

pub(crate) enum MemoryV1DraftResult {
    Allow(Box<MemoryV1ActionDraft>),
    Deny(MemoryV1DenySource, MemoryV1DenyTarget),
    Pending(MemoryV1PendingSource),
}

// memory—v1: Keep request shape validation identical for ordinary and compound
// entries before any rule or root fact can influence the result.
pub(crate) fn memory_v1_request_is_well_formed(request: &MemoryV1Request<'_>) -> bool {
    request.resource.len() <= MAX_TEXT_BYTES
        && !request.resource.is_empty()
        && request.action.len() <= MAX_TEXT_BYTES
        && !request.action.is_empty()
        && !request.operation_id.is_empty()
        && request.operation_id.len() <= MAX_BINDING_BYTES
        && !request.operation_fingerprint.is_empty()
        && request.operation_fingerprint.len() <= MAX_BINDING_BYTES
        && request
            .target
            .is_none_or(|target| target.len() <= MAX_BINDING_BYTES)
        && request
            .target_tenant
            .is_none_or(|tenant| tenant.len() <= MAX_BINDING_BYTES)
        && request
            .target_owner
            .is_none_or(|owner| owner.len() <= MAX_BINDING_BYTES)
}

pub(crate) fn memory_v1_rule_set_change_is_well_formed(request: &MemoryV1Request<'_>) -> bool {
    request.resource == "rule_set"
        && request.action == "confirm-change"
        && request.target_owner.is_none()
        && !request.operation_id.is_empty()
        && request.operation_id.len() <= MAX_BINDING_BYTES
        && !request.operation_fingerprint.is_empty()
        && request.operation_fingerprint.len() <= MAX_BINDING_BYTES
        && request.target.is_some_and(|target| target.len() == 16)
        && request
            .target_tenant
            .is_some_and(|tenant| tenant.len() == 16)
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
        deny_observation: None,
    }
}

// memory—v1: Attach an observation only to a denial selected in this read phase.
fn observed_deny(
    facts: &VerifiedSessionFacts,
    reader: &RequestRootReader,
    start_time: i64,
    request: &MemoryV1Request<'_>,
    source: MemoryV1DenySource,
) -> MemoryV1Evaluation {
    let mut result = non_allow(MemoryV1Decision::Deny, Some(source), None);
    result.deny_observation = Some(capture_deny_observation(
        reader.metadata(),
        facts,
        start_time,
        request,
        source,
        None,
    ));
    result
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
    evaluate_with_final(
        root,
        session,
        request,
        trusted_now,
        || {},
        |check, record, constraints, _| check.try_final_time(record, constraints),
    )
}

/// memory—v1: Evaluate one explicit rule-set confirmation against its full
/// root-derived impact. This does not authorize a compound mutation or commit.
pub(crate) fn evaluate_memory_v1_rule_set_change(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    request: &MemoryV1Request<'_>,
    intent: MemoryV1RuleSetChangeIntent,
) -> MemoryV1Evaluation {
    evaluate_rule_set_change_with(
        root,
        session,
        request,
        intent,
        trusted_now,
        || {},
        |check, record, constraints, metadata, target, _| {
            check.try_final_time_exact_root(record, constraints, metadata, target)
        },
    )
}

// memory—v1: The request's intent is explicit; no caller supplies beneficiaries.
fn evaluate_rule_set_change_with(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    request: &MemoryV1Request<'_>,
    intent: MemoryV1RuleSetChangeIntent,
    mut clock: impl FnMut() -> Option<i64>,
    after_read: impl FnOnce(),
    final_time: impl FnOnce(
        &SessionFinalCheck<'_>,
        &DependencyRecord,
        &FinalCheckTimeConstraints<'_>,
        RootMetadata,
        [u8; 16],
        &mut dyn FnMut() -> Option<i64>,
    ) -> Option<i64>,
) -> MemoryV1Evaluation {
    let pending = || {
        non_allow(
            MemoryV1Decision::Pending,
            None,
            Some(MemoryV1PendingSource::ContextInvalid),
        )
    };
    if request.resource != "rule_set"
        || request.action != "confirm-change"
        || request.target_owner.is_some()
        || request.operation_id.is_empty()
        || request.operation_id.len() > MAX_BINDING_BYTES
        || request.operation_fingerprint.is_empty()
        || request.operation_fingerprint.len() > MAX_BINDING_BYTES
    {
        return pending();
    }
    let Some(target): Option<[u8; 16]> = request.target.and_then(|value| value.try_into().ok())
    else {
        return pending();
    };
    let Some(tenant): Option<[u8; 16]> = request
        .target_tenant
        .and_then(|value| value.try_into().ok())
    else {
        return pending();
    };
    if target == [0; 16] || tenant == [0; 16] {
        return pending();
    }
    session
        .with_authoritative_context(root, |facts, reader, check| {
            if check.is_none() {
                return pending();
            }
            let metadata = reader.metadata();
            let Some(start_time) = clock() else {
                return pending();
            };
            if metadata.status != RootStatus::Serving || !facts.valid_at(start_time) {
                return pending();
            }
            match reader.is_fenced(target) {
                Ok(true) => {
                    return non_allow(
                        MemoryV1Decision::Pending,
                        None,
                        Some(MemoryV1PendingSource::FenceActive),
                    );
                }
                Ok(false) => {}
                Err(_) => {
                    return non_allow(
                        MemoryV1Decision::Pending,
                        None,
                        Some(MemoryV1PendingSource::RootUnavailable),
                    );
                }
            }
            let target_facts = match intent {
                MemoryV1RuleSetChangeIntent::Create => {
                    reader.rule_set_create_target(target, tenant)
                }
                MemoryV1RuleSetChangeIntent::Publish => reader.active_rule_set_target(target),
            };
            let Ok(target_facts) = target_facts else {
                return pending();
            };
            if target_facts.rule_set_id != target || target_facts.tenant_id != tenant {
                return pending();
            }
            let mut beneficiaries = Vec::new();
            if intent == MemoryV1RuleSetChangeIntent::Publish {
                let Ok(impact) = reader.read_change_impact(target) else {
                    return pending();
                };
                let mut cards = std::collections::HashSet::new();
                let mut users = std::collections::HashSet::new();
                let mut tenants = std::collections::HashSet::new();
                for binding_id in &impact.binding_ids {
                    let Ok(bound) = reader.binding_target(*binding_id) else {
                        return pending();
                    };
                    if bound.rule_set_id != target
                        || bound.tenant_id != tenant
                        || bound.user_card_id == [0; 16]
                        || bound.owner_user_id == [0; 16]
                    {
                        return pending();
                    }
                    cards.insert(bound.user_card_id);
                    users.insert(bound.owner_user_id);
                    tenants.insert(bound.tenant_id);
                    beneficiaries.push((*binding_id, bound));
                }
                if cards.len() != impact.card_ids.len()
                    || users.len() != impact.user_ids.len()
                    || tenants.len() != impact.tenant_ids.len()
                    || !impact.card_ids.iter().all(|id| cards.contains(id))
                    || !impact.user_ids.iter().all(|id| users.contains(id))
                    || !impact.tenant_ids.iter().all(|id| tenants.contains(id))
                {
                    return pending();
                }
                if users.contains(&facts.candidate_identity().user_id.into_bytes()) {
                    return observed_deny(
                        facts,
                        reader,
                        start_time,
                        request,
                        MemoryV1DenySource::SelfConfirmation,
                    );
                }
            }
            beneficiaries.sort_unstable_by_key(|(binding_id, _)| *binding_id);
            let mut candidate_requests = Vec::with_capacity(beneficiaries.len() + 1);
            candidate_requests.push((target, tenant, None, None));
            candidate_requests.extend(beneficiaries.iter().map(|(binding_id, facts)| {
                (
                    *binding_id,
                    facts.tenant_id,
                    Some(facts.owner_user_id),
                    Some((*binding_id, *facts)),
                )
            }));
            let mut dependency_record = None;
            let mut windows = Vec::new();
            let mut boundaries = Vec::new();
            let mut owner_scope = MemoryV1OwnerScope::AllUsers;
            let mut tenant_scope = MemoryV1TenantScope::SelfAndDescendants;
            let mut pending_source = None;
            let mut deny_source = None;
            for (target_id, target_tenant, target_owner, affected_binding) in &candidate_requests {
                let candidate_request = MemoryV1Request {
                    target: Some(target_id),
                    target_tenant: Some(target_tenant),
                    target_owner: target_owner.as_ref().map(|value| value.as_slice()),
                    ..*request
                };
                match evaluate_card_candidate(
                    facts,
                    reader,
                    &candidate_request,
                    start_time,
                    target_owner.is_none(),
                ) {
                    CardOutcome::Deny(source) => {
                        deny_source.get_or_insert((source, *affected_binding));
                    }
                    CardOutcome::Pending(source) => {
                        pending_source.get_or_insert(source);
                    }
                    CardOutcome::Allow {
                        dependencies,
                        winning_allows,
                        future_boundaries,
                        owner_scope: owner,
                        tenant_scope: scope,
                        tree_version,
                        registry_version,
                    } => {
                        let record = DependencyRecord {
                            card_id: facts.candidate_identity().user_card_id.into_bytes(),
                            instance_id: metadata.instance_id,
                            bindings: dependencies,
                            tenant_tree_version: tree_version,
                            registry_version,
                        };
                        if let Some(existing) = &dependency_record {
                            if existing != &record {
                                pending_source.get_or_insert(MemoryV1PendingSource::ContextInvalid);
                            }
                        } else {
                            dependency_record = Some(record);
                        }
                        owner_scope = strictest_owner_scope(owner_scope, owner);
                        tenant_scope = strictest_tenant_scope(tenant_scope, scope);
                        boundaries.extend(future_boundaries);
                        windows.extend(winning_allows.into_iter().map(|winner| FinalCheckWindow {
                            entry_validity: winner.entry_validity,
                            binding_from: winner.binding_from,
                            binding_until: winner.binding_until,
                        }));
                    }
                }
            }
            if let Some((source, affected_binding)) = deny_source {
                return match affected_binding {
                    Some((binding_id, _target_facts)) => {
                        let mut result = non_allow(MemoryV1Decision::Deny, Some(source), None);
                        if let Some(target_facts) = attributable_rule_set_binding_deny(
                            facts,
                            reader,
                            request,
                            start_time,
                            &beneficiaries,
                            binding_id,
                            source,
                        ) {
                            result.deny_observation =
                                Some(capture_rule_set_binding_deny_observation(
                                    metadata,
                                    facts,
                                    start_time,
                                    request,
                                    source,
                                    binding_id,
                                    target_facts,
                                ));
                        } else {
                            // A selected beneficiary is not enough to establish unique
                            // attribution: another beneficiary may deny or remain pending.
                            result.deny_observation = Some(capture_deny_observation(
                                metadata, facts, start_time, request, source, None,
                            ));
                        }
                        result
                    }
                    None => observed_deny(facts, reader, start_time, request, source),
                };
            }
            if let Some(source) = pending_source {
                return non_allow(MemoryV1Decision::Pending, None, Some(source));
            }
            let Some(record) = dependency_record else {
                return pending();
            };
            after_read();
            let constraints = FinalCheckTimeConstraints {
                start_time,
                future_boundaries: &boundaries,
                winning_windows: &windows,
            };
            let Some(now) = check.as_ref().and_then(|check| {
                final_time(check, &record, &constraints, metadata, target, &mut clock)
            }) else {
                return pending();
            };
            MemoryV1Evaluation {
                decision: MemoryV1Decision::Allow,
                deny_source: None,
                pending_source: None,
                deny_observation: None,
                admission: Some(MemoryV1Admission {
                    root: metadata,
                    identity: facts.candidate_identity(),
                    resource: request.resource.to_owned(),
                    action: request.action.to_owned(),
                    target: Some(target.to_vec()),
                    target_tenant: Some(tenant.to_vec()),
                    target_owner: None,
                    operation_id: request.operation_id.to_vec(),
                    operation_fingerprint: request.operation_fingerprint.to_vec(),
                    trusted_time_unix_seconds: now,
                    change_intent: Some(intent),
                    effective_owner_scope: owner_scope,
                    effective_tenant_scope: tenant_scope,
                }),
            }
        })
        .unwrap_or_else(|_| {
            non_allow(
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::RootUnavailable),
            )
        })
}

// memory—v1: Keep clock and post-read hooks private for deterministic tests.
#[cfg(test)]
fn evaluate_with(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    request: &MemoryV1Request<'_>,
    clock: impl FnMut() -> Option<i64>,
    after_read: impl FnOnce(),
) -> MemoryV1Evaluation {
    evaluate_with_final(
        root,
        session,
        request,
        clock,
        after_read,
        |check, record, constraints, clock| {
            check.try_final_time_for_test(record, constraints, clock)
        },
    )
}

// memory—v1: Share evaluation while keeping production clock sampling inside the root crate.
fn evaluate_with_final(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    request: &MemoryV1Request<'_>,
    mut clock: impl FnMut() -> Option<i64>,
    after_read: impl FnOnce(),
    final_time: impl FnOnce(
        &SessionFinalCheck<'_>,
        &DependencyRecord,
        &FinalCheckTimeConstraints<'_>,
        &mut dyn FnMut() -> Option<i64>,
    ) -> Option<i64>,
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
        .with_authoritative_context(root, |facts, reader, final_check| {
            if final_check.is_none() {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            }
            evaluate_reader(
                facts,
                reader,
                final_check,
                request,
                &mut clock,
                after_read,
                final_time,
            )
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
pub(crate) enum CardOutcome {
    Deny(MemoryV1DenySource),
    Pending(MemoryV1PendingSource),
    Allow {
        dependencies: Vec<EvaluationDependency>,
        winning_allows: Vec<WinningAllow>,
        future_boundaries: Vec<i64>,
        owner_scope: MemoryV1OwnerScope,
        tenant_scope: MemoryV1TenantScope,
        tree_version: u64,
        registry_version: u64,
    },
}

// memory—v1 §4.4: one winning ALLOW rule whose window and scope must still
// hold at the final trusted-time observation.
pub(crate) struct WinningAllow {
    pub(crate) entry_validity: Option<MemoryV1Validity>,
    pub(crate) binding_from: Option<i64>,
    pub(crate) binding_until: Option<i64>,
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

// memory—v1: Convert one already evaluated card aggregate into a draft. No
// clock or final check is performed here; the compound owner performs exactly
// one final check after all action drafts have succeeded.
fn draft_from_card_outcome(
    facts: &VerifiedSessionFacts,
    metadata: RootMetadata,
    request: &MemoryV1Request<'_>,
    outcome: CardOutcome,
    target_rule_sets: Option<&[[u8; 16]]>,
) -> MemoryV1DraftResult {
    let CardOutcome::Allow {
        dependencies,
        winning_allows,
        future_boundaries,
        owner_scope,
        tenant_scope,
        tree_version,
        registry_version,
    } = outcome
    else {
        return match outcome {
            CardOutcome::Deny(source) => {
                MemoryV1DraftResult::Deny(source, MemoryV1DenyTarget::Request)
            }
            CardOutcome::Pending(source) => MemoryV1DraftResult::Pending(source),
            CardOutcome::Allow { .. } => unreachable!(),
        };
    };
    if winning_allows.is_empty() {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    }
    let Some(target_rule_sets) = target_rule_sets.filter(|targets| {
        targets.iter().all(|target| *target != [0; 16])
            && (!targets.is_empty()
                || (request.resource == "user_card"
                    && matches!(request.action, "create" | "disable" | "enable")))
    }) else {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    };
    let mut target_rule_sets = target_rule_sets.to_vec();
    target_rule_sets.sort_unstable();
    target_rule_sets.dedup();
    MemoryV1DraftResult::Allow(Box::new(MemoryV1ActionDraft {
        root: metadata,
        identity: facts.candidate_identity(),
        resource: request.resource.to_owned(),
        action: request.action.to_owned(),
        target: request.target.map(<[u8]>::to_vec),
        target_tenant: request.target_tenant.map(<[u8]>::to_vec),
        target_owner: request.target_owner.map(<[u8]>::to_vec),
        operation_id: request.operation_id.to_vec(),
        operation_fingerprint: request.operation_fingerprint.to_vec(),
        change_intent: None,
        effective_owner_scope: owner_scope,
        effective_tenant_scope: tenant_scope,
        dependency: DependencyRecord {
            card_id: facts.candidate_identity().user_card_id.into_bytes(),
            instance_id: metadata.instance_id,
            bindings: dependencies,
            tenant_tree_version: tree_version,
            registry_version,
        },
        future_boundaries,
        winning_windows: winning_allows
            .into_iter()
            .map(|winning| FinalCheckWindow {
                entry_validity: winning.entry_validity,
                binding_from: winning.binding_from,
                binding_until: winning.binding_until,
            })
            .collect(),
        target_rule_sets,
    }))
}

// memory—v1: Plan one ordinary action against one immutable request phase.
pub(crate) fn plan_memory_v1_action_reader(
    facts: &VerifiedSessionFacts,
    reader: &RequestRootReader,
    request: &MemoryV1Request<'_>,
    start_time: i64,
    target_rule_sets: &[[u8; 16]],
    ownerless_rule_set_target: bool,
) -> MemoryV1DraftResult {
    if !memory_v1_request_is_well_formed(request) {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    }
    draft_from_card_outcome(
        facts,
        reader.metadata(),
        request,
        evaluate_card_candidate(
            facts,
            reader,
            request,
            start_time,
            ownerless_rule_set_target,
        ),
        Some(target_rule_sets),
    )
}

// memory—v1: Plan the dedicated confirm-change action while retaining its
// impact-set, self-confirmation, scope and dependency semantics. The caller
// supplies the actual nonzero rule-set target from the bound request.
pub(crate) fn plan_memory_v1_rule_set_change_reader(
    facts: &VerifiedSessionFacts,
    reader: &RequestRootReader,
    request: &MemoryV1Request<'_>,
    intent: MemoryV1RuleSetChangeIntent,
    start_time: i64,
) -> MemoryV1DraftResult {
    if !memory_v1_rule_set_change_is_well_formed(request) {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    }
    let metadata = reader.metadata();
    let actor = facts.candidate_identity();
    let actor_matches = match reader.read_card_for_evaluation(
        actor.user_card_id.into_bytes(),
        |context, _has_binding_history| {
            context.user.user_id == actor.user_id.into_bytes()
                && context.identity.identity_card_id == actor.identity_card_id.into_bytes()
                && context.identity.user_id == actor.user_id.into_bytes()
                && context.card.user_card_id == actor.user_card_id.into_bytes()
                && context.card.user_id == actor.user_id.into_bytes()
                && context.card.tenant_id == actor.tenant_id.into_bytes()
                && context.tenant.tenant_id == actor.tenant_id.into_bytes()
        },
    ) {
        Ok(matches) => matches,
        Err(_) => return MemoryV1DraftResult::Pending(MemoryV1PendingSource::RootUnavailable),
    };
    if !actor_matches {
        return MemoryV1DraftResult::Deny(
            MemoryV1DenySource::IdentityMismatch,
            MemoryV1DenyTarget::Unavailable,
        );
    }
    let Some(target): Option<[u8; 16]> = request.target.and_then(|id| id.try_into().ok()) else {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    };
    let Some(tenant): Option<[u8; 16]> = request
        .target_tenant
        .and_then(|tenant| tenant.try_into().ok())
    else {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    };
    if target == [0; 16] || tenant == [0; 16] {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    }
    match reader.is_fenced(target) {
        Ok(true) => return MemoryV1DraftResult::Pending(MemoryV1PendingSource::FenceActive),
        Ok(false) => {}
        Err(_) => return MemoryV1DraftResult::Pending(MemoryV1PendingSource::RootUnavailable),
    }
    let target_facts = match intent {
        MemoryV1RuleSetChangeIntent::Create => reader.rule_set_create_target(target, tenant),
        MemoryV1RuleSetChangeIntent::Publish => reader.active_rule_set_target(target),
    };
    let Ok(target_facts) = target_facts else {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    };
    if target_facts.rule_set_id != target || target_facts.tenant_id != tenant {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    }

    let mut beneficiaries = Vec::new();
    if intent == MemoryV1RuleSetChangeIntent::Publish {
        let Ok(impact) = reader.read_change_impact(target) else {
            return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
        };
        let mut cards = std::collections::HashSet::new();
        let mut users = std::collections::HashSet::new();
        let mut tenants = std::collections::HashSet::new();
        for binding_id in &impact.binding_ids {
            let Ok(bound) = reader.binding_target(*binding_id) else {
                return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
            };
            if bound.rule_set_id != target
                || bound.tenant_id != tenant
                || bound.user_card_id == [0; 16]
                || bound.owner_user_id == [0; 16]
            {
                return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
            }
            cards.insert(bound.user_card_id);
            users.insert(bound.owner_user_id);
            tenants.insert(bound.tenant_id);
            beneficiaries.push((*binding_id, bound));
        }
        if cards.len() != impact.card_ids.len()
            || users.len() != impact.user_ids.len()
            || tenants.len() != impact.tenant_ids.len()
            || !impact.card_ids.iter().all(|id| cards.contains(id))
            || !impact.user_ids.iter().all(|id| users.contains(id))
            || !impact.tenant_ids.iter().all(|id| tenants.contains(id))
        {
            return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
        }
        if users.contains(&actor.user_id.into_bytes()) {
            return MemoryV1DraftResult::Deny(
                MemoryV1DenySource::SelfConfirmation,
                MemoryV1DenyTarget::Request,
            );
        }
    }
    beneficiaries.sort_unstable_by_key(|(binding_id, _)| *binding_id);
    let mut candidate_requests = Vec::with_capacity(beneficiaries.len() + 1);
    candidate_requests.push((target, tenant, None, None));
    candidate_requests.extend(beneficiaries.iter().map(|(binding_id, facts)| {
        (
            *binding_id,
            facts.tenant_id,
            Some(facts.owner_user_id),
            Some((*binding_id, *facts)),
        )
    }));

    let mut dependency_record = None;
    let mut windows = Vec::new();
    let mut boundaries = Vec::new();
    let mut owner_scope = MemoryV1OwnerScope::AllUsers;
    let mut tenant_scope = MemoryV1TenantScope::SelfAndDescendants;
    for (target_id, target_tenant, target_owner, affected_binding) in &candidate_requests {
        let candidate_request = MemoryV1Request {
            target: Some(target_id),
            target_tenant: Some(target_tenant),
            target_owner: target_owner.as_ref().map(|value| value.as_slice()),
            ..*request
        };
        match evaluate_card_candidate(
            facts,
            reader,
            &candidate_request,
            start_time,
            target_owner.is_none(),
        ) {
            CardOutcome::Deny(source) => {
                let target = match affected_binding {
                    Some((binding_id, _target_facts)) => {
                        if let Some(target_facts) = attributable_rule_set_binding_deny(
                            facts,
                            reader,
                            request,
                            start_time,
                            &beneficiaries,
                            *binding_id,
                            source,
                        ) {
                            MemoryV1DenyTarget::AffectedBinding {
                                binding_id: *binding_id,
                                facts: target_facts,
                            }
                        } else {
                            MemoryV1DenyTarget::Request
                        }
                    }
                    None => MemoryV1DenyTarget::Request,
                };
                return MemoryV1DraftResult::Deny(source, target);
            }
            CardOutcome::Pending(source) => return MemoryV1DraftResult::Pending(source),
            CardOutcome::Allow {
                dependencies,
                winning_allows,
                future_boundaries,
                owner_scope: action_owner_scope,
                tenant_scope: action_tenant_scope,
                tree_version,
                registry_version,
            } => {
                let record = DependencyRecord {
                    card_id: actor.user_card_id.into_bytes(),
                    instance_id: metadata.instance_id,
                    bindings: dependencies,
                    tenant_tree_version: tree_version,
                    registry_version,
                };
                if let Some(existing) = &dependency_record {
                    if existing != &record {
                        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
                    }
                } else {
                    dependency_record = Some(record);
                }
                owner_scope = strictest_owner_scope(owner_scope, action_owner_scope);
                tenant_scope = strictest_tenant_scope(tenant_scope, action_tenant_scope);
                boundaries.extend(future_boundaries);
                windows.extend(winning_allows.into_iter().map(|winning| FinalCheckWindow {
                    entry_validity: winning.entry_validity,
                    binding_from: winning.binding_from,
                    binding_until: winning.binding_until,
                }));
            }
        }
    }
    let Some(dependency) = dependency_record else {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    };
    if windows.is_empty() {
        return MemoryV1DraftResult::Pending(MemoryV1PendingSource::ContextInvalid);
    }
    MemoryV1DraftResult::Allow(Box::new(MemoryV1ActionDraft {
        root: metadata,
        identity: actor,
        resource: request.resource.to_owned(),
        action: request.action.to_owned(),
        target: Some(target.to_vec()),
        target_tenant: Some(tenant.to_vec()),
        target_owner: None,
        operation_id: request.operation_id.to_vec(),
        operation_fingerprint: request.operation_fingerprint.to_vec(),
        change_intent: Some(intent),
        effective_owner_scope: owner_scope,
        effective_tenant_scope: tenant_scope,
        target_rule_sets: vec![target],
        dependency,
        future_boundaries: boundaries,
        winning_windows: windows,
    }))
}

// memory—v1: A binding attribution requires evidence that the selected DENY is
// specific to exactly one beneficiary check. The ownerless rule-set check and
// every other beneficiary are read only for attribution after the caller has
// already selected DENY; their results never change the decision or source.
fn attributable_rule_set_binding_deny(
    facts: &VerifiedSessionFacts,
    reader: &RequestRootReader,
    request: &MemoryV1Request<'_>,
    start_time: i64,
    targets: &[([u8; 16], GovernanceTargetFacts)],
    selected_binding_id: [u8; 16],
    source: MemoryV1DenySource,
) -> Option<GovernanceTargetFacts> {
    if !matches!(
        source,
        MemoryV1DenySource::RuleDenied
            | MemoryV1DenySource::NoMatch
            | MemoryV1DenySource::ScopeDenied
    ) {
        return None;
    }
    if !matches!(
        evaluate_card_candidate(facts, reader, request, start_time, true),
        CardOutcome::Allow { .. }
    ) {
        return None;
    }
    for (binding_id, target) in targets {
        if *binding_id == selected_binding_id {
            continue;
        }
        let beneficiary_request = MemoryV1Request {
            target: Some(binding_id),
            target_tenant: Some(&target.tenant_id),
            target_owner: Some(&target.owner_user_id),
            ..*request
        };
        if !matches!(
            evaluate_card_candidate(facts, reader, &beneficiary_request, start_time, false),
            CardOutcome::Allow { .. }
        ) {
            return None;
        }
    }
    targets
        .iter()
        .find(|(binding_id, _)| *binding_id == selected_binding_id)
        .map(|(_, target)| *target)
}

// memory—v1: A rule-set change has many root-owned beneficiaries. Until the
// root exposes an impact-set dependency that its final check can fence, no
// evaluation of that set may issue an admission. Determinate denials can still
// be established from the immutable request phase.
fn evaluate_reader(
    facts: &VerifiedSessionFacts,
    reader: &RequestRootReader,
    final_check: Option<SessionFinalCheck<'_>>,
    request: &MemoryV1Request<'_>,
    clock: &mut impl FnMut() -> Option<i64>,
    after_read: impl FnOnce(),
    final_time: impl FnOnce(
        &SessionFinalCheck<'_>,
        &DependencyRecord,
        &FinalCheckTimeConstraints<'_>,
        &mut dyn FnMut() -> Option<i64>,
    ) -> Option<i64>,
) -> MemoryV1Evaluation {
    if request.resource != "rule_set" || request.action != "confirm-change" {
        return evaluate_reader_single(
            facts,
            reader,
            final_check,
            request,
            clock,
            after_read,
            final_time,
        );
    }

    let pending = || {
        non_allow(
            MemoryV1Decision::Pending,
            None,
            Some(MemoryV1PendingSource::ContextInvalid),
        )
    };
    let Some(start_time) = clock() else {
        return pending();
    };
    if reader.metadata().status != RootStatus::Serving || !facts.valid_at(start_time) {
        return pending();
    }
    let actor = facts.candidate_identity();
    let Ok(actor_matches) = reader.read_card_for_evaluation(
        actor.user_card_id.into_bytes(),
        |context, _has_binding_history| {
            context.user.user_id == actor.user_id.into_bytes()
                && context.identity.identity_card_id == actor.identity_card_id.into_bytes()
                && context.identity.user_id == actor.user_id.into_bytes()
                && context.card.user_card_id == actor.user_card_id.into_bytes()
                && context.card.user_id == actor.user_id.into_bytes()
                && context.card.tenant_id == actor.tenant_id.into_bytes()
                && context.tenant.tenant_id == actor.tenant_id.into_bytes()
        },
    ) else {
        return pending();
    };
    if !actor_matches {
        return non_allow(
            MemoryV1Decision::Deny,
            Some(MemoryV1DenySource::IdentityMismatch),
            None,
        );
    }
    let Some(rule_set_id): Option<[u8; 16]> = request.target.and_then(|id| id.try_into().ok())
    else {
        return pending();
    };
    match reader.is_fenced(rule_set_id) {
        Ok(true) => {
            return non_allow(
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::FenceActive),
            );
        }
        Ok(false) => {}
        Err(_) => {
            return non_allow(
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::RootUnavailable),
            );
        }
    }
    // A caller-supplied owner is never a trusted beneficiary for this action.
    let owner_was_supplied = request.target_owner.is_some();
    let Ok(rule_set) = reader.rule_set_target(rule_set_id) else {
        return pending();
    };
    if request.target_tenant != Some(rule_set.tenant_id.as_slice()) {
        return pending();
    }
    let Ok(impact) = reader.read_change_impact(rule_set_id) else {
        return pending();
    };
    let mut targets = Vec::with_capacity(impact.binding_ids.len());
    let mut cards = std::collections::HashSet::new();
    let mut users = std::collections::HashSet::new();
    let mut tenants = std::collections::HashSet::new();
    for binding_id in &impact.binding_ids {
        let Ok(target) = reader.binding_target(*binding_id) else {
            return pending();
        };
        if target.rule_set_id != rule_set_id
            || target.tenant_id != rule_set.tenant_id
            || target.user_card_id == [0; 16]
            || target.owner_user_id == [0; 16]
        {
            return pending();
        }
        cards.insert(target.user_card_id);
        users.insert(target.owner_user_id);
        tenants.insert(target.tenant_id);
        targets.push((*binding_id, target));
    }
    if cards.len() != impact.card_ids.len()
        || users.len() != impact.user_ids.len()
        || tenants.len() != impact.tenant_ids.len()
        || !impact.card_ids.iter().all(|id| cards.contains(id))
        || !impact.user_ids.iter().all(|id| users.contains(id))
        || !impact.tenant_ids.iter().all(|id| tenants.contains(id))
    {
        return pending();
    }
    // Inspect all beneficiaries first so self-signing wins regardless of set order.
    if users.contains(&facts.candidate_identity().user_id.into_bytes()) {
        // A caller-supplied owner is not a trusted beneficiary on this path.
        let denied_request = MemoryV1Request {
            target_owner: None,
            ..*request
        };
        return observed_deny(
            facts,
            reader,
            start_time,
            &denied_request,
            MemoryV1DenySource::SelfConfirmation,
        );
    }
    if owner_was_supplied {
        return pending();
    }
    targets.sort_unstable_by_key(|(binding_id, _)| *binding_id);
    for (binding_id, target) in targets.iter().copied() {
        let beneficiary_request = MemoryV1Request {
            target: Some(&binding_id),
            target_tenant: Some(&target.tenant_id),
            target_owner: Some(&target.owner_user_id),
            ..*request
        };
        if let CardOutcome::Deny(source) =
            evaluate_card_candidate(facts, reader, &beneficiary_request, start_time, false)
        {
            let mut result = non_allow(MemoryV1Decision::Deny, Some(source), None);
            if let Some(target) = attributable_rule_set_binding_deny(
                facts, reader, request, start_time, &targets, binding_id, source,
            ) {
                result.deny_observation = Some(capture_rule_set_binding_deny_observation(
                    reader.metadata(),
                    facts,
                    start_time,
                    request,
                    source,
                    binding_id,
                    target,
                ));
            } else {
                result.deny_observation = Some(capture_deny_observation(
                    reader.metadata(),
                    facts,
                    start_time,
                    request,
                    source,
                    None,
                ));
            }
            return result;
        }
    }
    pending()
}

// memory—v1: Compute one target without sampling a clock or issuing admission.
pub(crate) fn evaluate_card_candidate(
    facts: &VerifiedSessionFacts,
    reader: &RequestRootReader,
    request: &MemoryV1Request<'_>,
    start_time: i64,
    ownerless_governance_target: bool,
) -> CardOutcome {
    // memory—v1 §4.9 A-3.4: a proven missing or inactive entry is a
    // structural denial; an unavailable registry cannot establish that fact.
    let registry_version =
        match reader.registry_check_with_version(request.resource, request.action) {
            Ok(version) => version,
            Err(
                RegistryError::Unregistered(_)
                | RegistryError::Inactive(_, _)
                | RegistryError::UnknownAction(_, _),
            ) => {
                return CardOutcome::Deny(MemoryV1DenySource::UnregisteredResource);
            }
            Err(_) => {
                return CardOutcome::Pending(MemoryV1PendingSource::RootUnavailable);
            }
        };
    let identity = facts.candidate_identity();
    let outcome = reader.read_card_for_evaluation(
        identity.user_card_id.into_bytes(),
        |context, has_binding_history| {
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
            // memory—v1 §4.12 B-2.3: a DISABLED card is deterministically denied,
            // including when the card has no bindings.
            if context.card.status != UserCardStatus::Active {
                return CardOutcome::Deny(MemoryV1DenySource::CardDisabled);
            }
            // memory—v1 §4.8: an unbound active card is a deterministic denial.
            if context.bindings.is_empty() && !has_binding_history {
                return CardOutcome::Deny(MemoryV1DenySource::CardUnbound);
            }
            // memory—v1 §4.11 B-1.3 N-7: SoD self-sign ban is a structural rule —
            // confirm-class actions can never target the operator's own authority,
            // regardless of scope width.
            if request.action.starts_with("confirm") || request.action == "create-overlay-only" {
                if let Some(owner) = request.target_owner {
                    if owner == user {
                        return CardOutcome::Deny(MemoryV1DenySource::SelfConfirmation);
                    }
                }
            }
            // memory—v1 §4.10: Only object-bearing scope checks use descendants.
            // The card context already proves this tenant exists in the same snapshot.
            let descendants = if request.target.is_some() {
                match reader.tenant_descendants(tenant) {
                    Ok(list) => list,
                    Err(_) => return CardOutcome::Pending(MemoryV1PendingSource::RootUnavailable),
                }
            } else {
                Vec::new()
            };
            let (tree_version, _) = match reader.dependency_versions() {
                Ok(versions) => versions,
                Err(_) => return CardOutcome::Pending(MemoryV1PendingSource::RootUnavailable),
            };
            let mut dependencies: Vec<EvaluationDependency> = Vec::new();
            let mut winning_allows: Vec<WinningAllow> = Vec::new();
            let mut future_boundaries = Vec::new();
            let mut allow = false;
            let mut deny = false;
            let mut scope_denied = false;
            let mut pending: Option<MemoryV1PendingSource> = None;
            for binding in &context.bindings {
                // memory—v1 §4.13 N-19: only an active binding of this active
                // card contributes; inconsistent ownership remains bad data.
                if binding.binding.user_card_id != card {
                    pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                    continue;
                }
                if !binding_is_active(binding.binding, Some(context.card)) {
                    continue;
                }
                // memory—v1 §4.6: readers of a fenced rule set fail closed as
                // soon as the modification window is observed.
                match reader.is_fenced(binding.rule_set.rule_set_id) {
                    Ok(true) => return CardOutcome::Pending(MemoryV1PendingSource::FenceActive),
                    Ok(false) => {}
                    Err(_) => return CardOutcome::Pending(MemoryV1PendingSource::RootUnavailable),
                }
                let Some(version) = binding.selected else {
                    pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                    continue;
                };
                if binding.rule_set.rule_set_id != binding.binding.rule_set_id
                    || binding.rule_set.owner_tenant_id != context.card.tenant_id
                    || binding.rule_set.status != RuleSetStatus::Active
                    || version.rule_set_id != binding.binding.rule_set_id
                {
                    pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                    continue;
                }
                // memory—v1 §4.11/§4.12: A revoked set withdraws the whole
                // binding; bad active data is pending and cannot be concealed by
                // another valid confirmation.
                match binding.confirmation_state {
                    BindingConfirmationState::Active => {}
                    BindingConfirmationState::Withdrawn => continue,
                    BindingConfirmationState::Invalid => {
                        pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                        continue;
                    }
                }
                // memory—v1 §4.11/§4.5 (N-16 版本新鲜度不变式): the CURRENT version
                // is servable only with a non-revoked change confirmation for
                // exactly that version; 首版与每次发布同事务确认（一次确认覆盖全部
                // 既有绑定，逐卡不重确认）.
                match binding.change_confirmation_state {
                    ChangeConfirmationState::Active => {}
                    ChangeConfirmationState::Withdrawn | ChangeConfirmationState::Missing => {
                        pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                        continue;
                    }
                    ChangeConfirmationState::Invalid => {
                        pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                        continue;
                    }
                }
                // memory—v1: Without authority and scope evidence the active
                // confirmation might not contribute any rule. A confirmed denial
                // from another binding may still win, but this binding cannot prove
                // an ALLOW, a rule DENY, or a complete no-match result.
                if !reader.confirmation_authority_available_for_evaluation() {
                    pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                    continue;
                }
                let Some(content) = reader.prepared_selected_rules(version) else {
                    // The selected immutable version failed its canonical hash
                    // or grammar check, or is not from this reader's snapshot.
                    pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                    continue;
                };
                // memory—v1 §4.9: A valid matching rule cannot conceal another
                // reference to an inactive or unregistered resource in this version.
                // The same registry generation must cover the request and all rules.
                match reader.registry_check_prepared_with_version(content) {
                    Ok(version) if version == registry_version => {}
                    Err(RegistryError::NotInstalled) => {
                        pending = pending.or(Some(MemoryV1PendingSource::RootUnavailable));
                        continue;
                    }
                    _ => {
                        pending = pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                        continue;
                    }
                }
                dependencies.push(EvaluationDependency {
                    binding_id: binding.binding.binding_id,
                    rule_set_id: binding.binding.rule_set_id,
                    version_bytes: version.version_bytes.clone(),
                });
                // Any later transition can change the aggregate, including a DENY
                // whose binding or entry window has not opened yet.
                if let Some(from) = binding.binding.valid_from.filter(|from| *from > start_time) {
                    future_boundaries.push(from);
                }
                if !window_active(
                    binding.binding.valid_from,
                    binding.binding.valid_until,
                    start_time,
                ) {
                    continue;
                }
                for hit in content.rule_hits(request.resource, request.action) {
                    if let Some(from) = hit.validity.and_then(|validity| validity.from) {
                        if from > start_time {
                            future_boundaries.push(from);
                        }
                    }
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
                            MemoryV1OwnerScope::AllUsers => match request.target_owner {
                                Some(_) => true,
                                None if ownerless_governance_target => true,
                                None => {
                                    pending =
                                        pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                                    false
                                }
                            },
                            MemoryV1OwnerScope::SelfUser => match request.target_owner {
                                Some(owner) if owner == user => true,
                                Some(_) => {
                                    scope_denied = true;
                                    false
                                }
                                None if ownerless_governance_target => {
                                    scope_denied = true;
                                    false
                                }
                                None => {
                                    pending =
                                        pending.or(Some(MemoryV1PendingSource::ContextInvalid));
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
                                    pending =
                                        pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                                    false
                                }
                            },
                            MemoryV1TenantScope::SelfAndDescendants => {
                                match request.target_tenant {
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
                                        pending =
                                            pending.or(Some(MemoryV1PendingSource::ContextInvalid));
                                        false
                                    }
                                }
                            }
                        };
                        owner_ok && tenant_ok
                    };
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
            // memory—v1 §4.8/§4.10: out-of-scope rules do not contribute.
            // A matching DENY wins, followed by pending causes and matching ALLOWs.
            // ScopeDenied describes a complete evaluation with no applicable allow.
            if deny {
                CardOutcome::Deny(MemoryV1DenySource::RuleDenied)
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
                    future_boundaries,
                    owner_scope,
                    tenant_scope,
                    tree_version,
                    registry_version,
                }
            } else if scope_denied {
                CardOutcome::Deny(MemoryV1DenySource::ScopeDenied)
            } else {
                CardOutcome::Deny(MemoryV1DenySource::NoMatch)
            }
        },
    );
    outcome.unwrap_or(CardOutcome::Pending(MemoryV1PendingSource::RootUnavailable))
}

// memory—v1: Evaluate one immutable snapshot and recheck it before allowing.
fn evaluate_reader_single(
    facts: &VerifiedSessionFacts,
    reader: &RequestRootReader,
    final_check: Option<SessionFinalCheck<'_>>,
    request: &MemoryV1Request<'_>,
    clock: &mut impl FnMut() -> Option<i64>,
    after_read: impl FnOnce(),
    final_time: impl FnOnce(
        &SessionFinalCheck<'_>,
        &DependencyRecord,
        &FinalCheckTimeConstraints<'_>,
        &mut dyn FnMut() -> Option<i64>,
    ) -> Option<i64>,
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
    let identity = facts.candidate_identity();
    let outcome = evaluate_card_candidate(facts, reader, request, start_time, false);
    match outcome {
        CardOutcome::Deny(source) => observed_deny(facts, reader, start_time, request, source),
        CardOutcome::Pending(source) => non_allow(MemoryV1Decision::Pending, None, Some(source)),
        CardOutcome::Allow {
            dependencies,
            winning_allows,
            future_boundaries,
            owner_scope,
            tenant_scope,
            tree_version,
            registry_version,
        } => {
            after_read();
            let record = DependencyRecord {
                card_id: identity.user_card_id.into_bytes(),
                instance_id: metadata.instance_id,
                bindings: dependencies,
                tenant_tree_version: tree_version,
                registry_version,
            };
            // memory—v1: The root crate samples the final clock only while the
            // live session, root, registry and complete fence table are stable.
            let windows: Vec<_> = winning_allows
                .iter()
                .map(|winning| FinalCheckWindow {
                    entry_validity: winning.entry_validity,
                    binding_from: winning.binding_from,
                    binding_until: winning.binding_until,
                })
                .collect();
            let constraints = FinalCheckTimeConstraints {
                start_time,
                future_boundaries: &future_boundaries,
                winning_windows: &windows,
            };
            let final_time = final_check
                .as_ref()
                .and_then(|check| final_time(check, &record, &constraints, clock));
            let Some(final_time) = final_time else {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            };
            MemoryV1Evaluation {
                decision: MemoryV1Decision::Allow,
                deny_source: None,
                pending_source: None,
                deny_observation: None,
                admission: Some(MemoryV1Admission {
                    root: metadata,
                    identity,
                    resource: request.resource.to_owned(),
                    action: request.action.to_owned(),
                    target: request.target.map(<[u8]>::to_vec),
                    target_tenant: request.target_tenant.map(<[u8]>::to_vec),
                    target_owner: request.target_owner.map(<[u8]>::to_vec),
                    operation_id: request.operation_id.to_vec(),
                    operation_fingerprint: request.operation_fingerprint.to_vec(),
                    trusted_time_unix_seconds: final_time,
                    change_intent: None,
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
        IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
        UserCardRow, UserCardStatus, UserRow,
    };
    use astral_authorization_root::memory_v1_hamt::{CandidateBudget, CandidateError};
    use astral_authorization_root::memory_v1_registry::{RegistryDeclaration, RegistryError};
    use astral_authorization_root::memory_v1_request::RequestRootScope;
    use astral_authorization_root::memory_v1_root::{
        install_process_root, ManagementMutationV2, MutationPrecondition, RootError, RootStatus,
    };
    use astral_authorization_root::memory_v1_rules::{canonical_version_bytes, MemoryV1RuleError};
    use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
    use astral_types::memory_v1::MemoryId;

    // memory—v1: Every engine DENY has the corresponding frozen audit source;
    // converting a source does not manufacture the remaining audit evidence.
    #[test]
    fn deny_sources_map_to_frozen_audit_vocabulary() {
        for (source, expected, name) in [
            (
                MemoryV1DenySource::RuleDenied,
                MemoryV1AuditDenySource::RuleDeny,
                "rule_deny",
            ),
            (
                MemoryV1DenySource::NoMatch,
                MemoryV1AuditDenySource::NoMatch,
                "no_match",
            ),
            (
                MemoryV1DenySource::ScopeDenied,
                MemoryV1AuditDenySource::ScopeDenied,
                "scope_denied",
            ),
            (
                MemoryV1DenySource::CardUnbound,
                MemoryV1AuditDenySource::CardUnbound,
                "card_unbound",
            ),
            (
                MemoryV1DenySource::IdentityMismatch,
                MemoryV1AuditDenySource::IdentityMismatch,
                "identity_mismatch",
            ),
            (
                MemoryV1DenySource::UnregisteredResource,
                MemoryV1AuditDenySource::UnregisteredResource,
                "unregistered_resource",
            ),
            (
                MemoryV1DenySource::SelfConfirmation,
                MemoryV1AuditDenySource::SelfConfirmation,
                "self_confirmation",
            ),
            (
                MemoryV1DenySource::CardDisabled,
                MemoryV1AuditDenySource::CardDisabled,
                "card_disabled",
            ),
        ] {
            assert_eq!(source.audit_source(), expected);
            assert_eq!(source.audit_source().as_str(), name);
        }
        // OVERLAY-only is a separate T2 audit marker, not inferred from a generic DENY.
        assert_eq!(
            MemoryV1AuditDenySource::OverlayOnlyCreation.as_str(),
            "overlay_only_creation"
        );
    }

    // memory—v1: A pending source stays distinguishable in logs even when
    // multiple sources share one external retry response.
    #[test]
    fn pending_sources_map_to_frozen_log_vocabulary() {
        assert_eq!(
            MemoryV1PendingSource::ContextInvalid.as_str(),
            "context_invalid"
        );
        assert_eq!(MemoryV1PendingSource::FenceActive.as_str(), "fence_active");
        assert_eq!(
            MemoryV1PendingSource::RootUnavailable.as_str(),
            "root_unavailable"
        );
    }

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
                    status: UserCardStatus::Active,
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
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: [set; 16],
                owner_tenant_id: [3; 16],
                current_version_bytes: version.clone(),
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
                removed_at: None,
                removed_by: None,
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
                revoked_at: None,
                revoked_by: None,
            });
            // memory—v1 §4.11/§4.5 (N-16): the fixture is a conforming writer —
            // 首版创建同事务携带变更确认（版本新鲜度不变式）.
            rows.rule_set_change_confirmations.push(
                RuleSetChangeConfirmationRow {
                    confirmation_id: [set + 200; 16],
                    rule_set_id: [set; 16],
                    version_bytes: version.clone(),
                    confirmer_user_id: [1; 16],
                    affected_scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
            );
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
        authority.bind_to_root(&owner).unwrap();
        let session_for = |root: &RequestRootExtension, identity: CandidateIdentity| {
            let issued = authority
                .identity_session_adapter()
                .issue_unchecked_for_test(identity, 100, 100)
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
        assert!(no_match.deny_observation.is_none());

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

        // memory—v1: The candidate and its uninstalled registry cannot authorize.
        assert_eq!(
            root.with_reader(|reader| reader.registry_check("document", "read"))
                .unwrap(),
            Err(RegistryError::NotInstalled)
        );
        // memory—v1 §4.9: install the aggregated registry before adoption.
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
        // The earlier reader remains bound to Candidate after adoption.
        let adopted = owner.adopt_serving_for_isolated_tests().unwrap();
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
        assert_eq!(
            denied.deny_source,
            Some(MemoryV1DenySource::UnregisteredResource)
        );
        assert!(denied.pending_source.is_none());
        assert!(denied.admission.is_none());
        let observation = denied
            .deny_observation
            .as_deref()
            .expect("read-phase denial");
        assert_eq!(observation.root(), adopted);
        assert_eq!(observation.identity(), identity(4));
        assert_eq!(observation.read_started_at_unix_seconds(), 110);
        assert_eq!(
            (observation.resource(), observation.action()),
            ("document", "READ")
        );
        assert_eq!(observation.target(), Some(b"target".as_slice()));
        assert_eq!(observation.target_tenant(), Some(tenant_bytes.as_slice()));
        assert_eq!(observation.target_owner(), Some(user_bytes.as_slice()));
        assert_eq!(observation.operation_id(), b"operation");
        assert_eq!(observation.operation_fingerprint(), b"fingerprint");
        assert_eq!(
            observation.source(),
            MemoryV1DenySource::UnregisteredResource
        );
        assert_eq!(observation.batch_sequence(), None);
        assert_eq!(
            format!("{observation:?}"),
            "MemoryV1DenyObservation(<redacted>)"
        );
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
        authority.bind_to_root(&owner).unwrap();
        let session_for = |root: &RequestRootExtension, card: u8| {
            let issued = authority
                .identity_session_adapter()
                .issue_unchecked_for_test(identity(card), 100, 100)
                .unwrap();
            authority
                .verifier()
                .verify_and_bind(issued.credential(), 100, root)
                .unwrap()
        };
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        let adopted = owner.adopt_serving_for_isolated_tests().unwrap();
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

        // memory—v1 §4.10: the strict binding excludes the child tenant, so
        // neither of card 4's rules contributes for that target.
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
        // releases them when the fence closes.
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
        // memory—v1 §4.7: the released window stays recorded against this
        // scope's read-phase stamp; the touched dependency is not re-allowed
        // in the same read phase. A fresh read phase may evaluate again.
        let released = evaluate(11, Some(&tenant_bytes), Some(&user_bytes));
        assert_eq!(released.decision, MemoryV1Decision::Pending);
        assert_eq!(
            released.pending_source,
            Some(MemoryV1PendingSource::ContextInvalid)
        );
        let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
        let fresh_root = fresh_scope.extension();
        let fresh_issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(identity(11), 100, 100)
            .unwrap();
        let fresh_session = authority
            .verifier()
            .verify_and_bind(fresh_issued.credential(), 100, &fresh_root)
            .unwrap();
        let released_fresh = evaluate_with(
            &fresh_root,
            &fresh_session,
            &contract_request(Some(&tenant_bytes), Some(&user_bytes)),
            || Some(110),
            || {},
        );
        assert_eq!(released_fresh.decision, MemoryV1Decision::Allow);
        assert!(released_fresh.admission.is_some());

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
                    status: UserCardStatus::Active,
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
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: [set; 16],
                owner_tenant_id: [3; 16],
                current_version_bytes: version.clone(),
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
                removed_at: None,
                removed_by: None,
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
                revoked_at: None,
                revoked_by: None,
            });
            // memory—v1 §4.11/§4.5 N-16: every selected version in a serving
            // fixture has its required active change confirmation. Broken
            // binding confirmations remain the service-period bad-data cases;
            // malformed versions remain rejected by parse/hash validation.
            if !rows
                .rule_set_change_confirmations
                .iter()
                .any(|confirmation| confirmation.rule_set_id == [set; 16])
            {
                rows.rule_set_change_confirmations
                    .push(RuleSetChangeConfirmationRow {
                        confirmation_id: [set.wrapping_add(0x80); 16],
                        rule_set_id: [set; 16],
                        version_bytes: vec![1],
                        confirmer_user_id: [1; 16],
                        affected_scope_bytes: vec![1],
                        operation_id: vec![1],
                        confirmed_at_bytes: vec![1],
                        revoked_at: None,
                        revoked_by: None,
                    });
            }
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
                status: UserCardStatus::Active,
            }],
            ..CandidateRows::default()
        };
        let content =
            br#"{"rules":[{"ruleId":"A","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        let version = vec![1];
        let timestamp = vec![2];
        let input = canonical_version_bytes(&version, content, &timestamp);
        rows.rule_sets.push(RuleSetRow {
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
            rule_set_id: [10; 16],
            owner_tenant_id: [3; 16],
            current_version_bytes: version.clone(),
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
            removed_at: None,
            removed_by: None,
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
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        assert_eq!(
            owner.adopt_serving_for_isolated_tests(),
            Err(RootError::Candidate(CandidateError::RuleIntegrity(
                MemoryV1RuleError::HashMismatch,
            )))
        );
    }

    // memory—v1 §4.11/§4.12 (batch B): SoD self-sign ban, card DISABLED,
    // REMOVED binding skip, revocation → deterministic skip, deterministic
    // DENY priority — the contract tests for the batch-B evaluation changes.
    #[test]
    fn batch_b_evaluation_contract_tests() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_BATCH_B_EVAL_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::batch_b_evaluation_contract_tests",
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

        // Cards 7 and 9 are disabled; card 9 has no bindings.
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
            user_cards: [4, 7, 8, 9]
                .into_iter()
                .map(|id| UserCardRow {
                    user_card_id: [id; 16],
                    user_id: [1; 16],
                    tenant_id: [3; 16],
                    status: if id == 7 || id == 9 {
                        UserCardStatus::Disabled
                    } else {
                        UserCardStatus::Active
                    },
                })
                .collect(),
            ..CandidateRows::default()
        };
        let mut selections = Vec::new();
        let content = br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        for (set, binding, card) in [(10_u8, 20_u8, 4_u8), (11, 21, 7), (12, 22, 8)] {
            let version = vec![1];
            let timestamp = vec![2];
            let input = canonical_version_bytes(&version, content, &timestamp);
            rows.rule_sets.push(RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: [set; 16],
                owner_tenant_id: [3; 16],
                current_version_bytes: version.clone(),
            });
            rows.rule_set_versions.push(RuleSetVersionRow {
                rule_set_id: [set; 16],
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                hash_input_bytes: input.clone(),
                hash_bytes: astral_authorization_root::memory_v1_rules::version_digest(&input),
            });
            rows.bindings.push(BindingRow {
                binding_id: [binding; 16],
                user_card_id: [card; 16],
                rule_set_id: [set; 16],
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            });
            rows.binding_confirmations.push(BindingConfirmationRow {
                confirmation_id: [binding.wrapping_add(20); 16],
                binding_id: [binding; 16],
                rule_set_id: [set; 16],
                version_bytes: version.clone(),
                confirmer_user_id: [1; 16],
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
            // memory—v1 §4.11/§4.5 (N-16): 首版同事务变更确认（版本新鲜度不变式）.
            rows.rule_set_change_confirmations
                .push(RuleSetChangeConfirmationRow {
                    confirmation_id: [set.wrapping_add(200); 16],
                    rule_set_id: [set; 16],
                    version_bytes: version.clone(),
                    confirmer_user_id: [1; 16],
                    affected_scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                });
            selections.push(CurrentSelection {
                rule_set_id: [set; 16],
                version_bytes: version,
            });
        }
        // Card 7's binding is additionally marked REMOVED (B-2.2).
        if let Some(binding) = rows.bindings.iter_mut().find(|b| b.user_card_id == [7; 16]) {
            binding.removed_at = Some(100);
            binding.removed_by = Some([1; 16]);
        }
        // Card 8's confirmation is additionally marked REVOKED (B-2.4).
        if let Some(confirmation) = rows
            .binding_confirmations
            .iter_mut()
            .find(|c| c.binding_id == [22; 16])
        {
            confirmation.revoked_at = Some(100);
            confirmation.revoked_by = Some([1; 16]);
        }

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
        authority.bind_to_root(&owner).unwrap();
        let session_for = |root: &RequestRootExtension, card: u8| {
            let issued = authority
                .identity_session_adapter()
                .issue_unchecked_for_test(identity(card), 100, 100)
                .unwrap();
            authority
                .verifier()
                .verify_and_bind(issued.credential(), 100, root)
                .unwrap()
        };
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec![
                    "read".to_owned(),
                    "create".to_owned(),
                    "confirm".to_owned(),
                    "create-overlay-only".to_owned(),
                ],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let user_bytes = [1_u8; 16];
        let tenant_bytes = [3_u8; 16];

        let read_request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: None,
            target_tenant: None,
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };

        // memory—v1 §4.12 B-2.3: DISABLED card → all bindings skipped → NoMatch.
        let disabled_card = session_for(&root, 7);
        let result = evaluate_with(&root, &disabled_card, &read_request, || Some(110), || {});
        assert_eq!(result.decision, MemoryV1Decision::Deny);
        assert_eq!(result.deny_source, Some(MemoryV1DenySource::CardDisabled));
        let observation = result.deny_observation.as_deref().unwrap();
        assert_eq!(observation.identity(), identity(7));
        assert_eq!(observation.source(), MemoryV1DenySource::CardDisabled);
        assert_eq!(observation.read_started_at_unix_seconds(), 110);
        let unbound_disabled = session_for(&root, 9);
        let result = evaluate_with(&root, &unbound_disabled, &read_request, || Some(110), || {});
        assert_eq!(result.decision, MemoryV1Decision::Deny);
        assert_eq!(result.deny_source, Some(MemoryV1DenySource::CardDisabled));

        // memory—v1 §4.12 B-2.2: REMOVED bindings follow the same
        // skip→NoMatch code path as DISABLED cards (deterministic skip).

        // memory—v1 §4.11 B-1.3 N-7: SoD self-sign ban — confirm action
        // targeting the operator's own authority is deterministically denied,
        // regardless of scope width.
        let confirm_request = MemoryV1Request {
            resource: "document",
            action: "confirm",
            target: Some(b"document"),
            target_tenant: Some(&tenant_bytes),
            target_owner: Some(&user_bytes),
            operation_id: b"sod-op",
            operation_fingerprint: b"sod-fp",
        };
        let active_card = session_for(&root, 4);
        let sod_denied = evaluate_with(&root, &active_card, &confirm_request, || Some(110), || {});
        assert_eq!(sod_denied.decision, MemoryV1Decision::Deny);
        assert_eq!(
            sod_denied.deny_source,
            Some(MemoryV1DenySource::SelfConfirmation)
        );
        let observation = sod_denied.deny_observation.as_deref().unwrap();
        assert_eq!(observation.source(), MemoryV1DenySource::SelfConfirmation);
        assert_eq!(observation.target_owner(), Some(user_bytes.as_slice()));
        assert_eq!(observation.operation_id(), b"sod-op");
        let overlay_request = MemoryV1Request {
            action: "create-overlay-only",
            ..confirm_request
        };
        let overlay_denied =
            evaluate_with(&root, &active_card, &overlay_request, || Some(110), || {});
        assert_eq!(overlay_denied.decision, MemoryV1Decision::Deny);
        assert_eq!(
            overlay_denied.deny_source,
            Some(MemoryV1DenySource::SelfConfirmation)
        );

        // A non-confirm action by the same card on the same resource works.
        let allowed = evaluate_with(&root, &active_card, &read_request, || Some(110), || {});
        assert_eq!(allowed.decision, MemoryV1Decision::Allow);
        assert!(allowed.admission.is_some());
    }

    // memory—v1 §4.12/§4.11 (batch B): REMOVED binding skip, confirmation
    // revocation → binding skip, revocation vs bad-data distinction, and
    // dual-layer governance grants.
    #[test]
    fn batch_b_lifecycle_state_tests() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_BATCH_B_LIFECYCLE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::batch_b_lifecycle_state_tests",
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

        // Fixture: 2 rulesets (10-11), each with its own version (vn 1-2),
        // bound to 2 different cards. Binding states:
        //   card 4 → set 10: normal (baseline ALLOW)
        //   card 7 → set 11: REMOVED (removed_at set) → NoMatch
        // Revocation is exercised below through the real RootOwner mutation
        // path; a valid revoked confirmation is also accepted on cold adoption.
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
            user_cards: [4, 7]
                .into_iter()
                .map(|id| UserCardRow {
                    user_card_id: [id; 16],
                    user_id: [1; 16],
                    tenant_id: [3; 16],
                    status: UserCardStatus::Active,
                })
                .collect(),
            ..CandidateRows::default()
        };
        let mut selections = Vec::new();
        let content = br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        for (set, binding, card, removed, vn) in
            [(10u8, 20u8, 4u8, false, 1u8), (11, 21, 7, true, 2)]
        {
            let version = vec![vn];
            let timestamp = vec![vn];
            let input = canonical_version_bytes(&version, content, &timestamp);
            rows.rule_sets.push(RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: [set; 16],
                owner_tenant_id: [3; 16],
                current_version_bytes: version.clone(),
            });
            rows.rule_set_versions.push(RuleSetVersionRow {
                rule_set_id: [set; 16],
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                hash_input_bytes: input.clone(),
                hash_bytes: astral_authorization_root::memory_v1_rules::version_digest(&input),
            });
            rows.bindings.push(BindingRow {
                binding_id: [binding; 16],
                user_card_id: [card; 16],
                rule_set_id: [set; 16],
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: if removed { Some(100) } else { None },
                removed_by: if removed { Some([1; 16]) } else { None },
            });
            rows.binding_confirmations.push(BindingConfirmationRow {
                confirmation_id: [binding.wrapping_add(20); 16],
                binding_id: [binding; 16],
                rule_set_id: [set; 16],
                version_bytes: version.clone(),
                confirmer_user_id: [1; 16],
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
            // memory—v1 §4.11/§4.5 (N-16): 首版同事务变更确认（版本新鲜度不变式）.
            rows.rule_set_change_confirmations
                .push(RuleSetChangeConfirmationRow {
                    confirmation_id: [set.wrapping_add(200); 16],
                    rule_set_id: [set; 16],
                    version_bytes: version.clone(),
                    confirmer_user_id: [1; 16],
                    affected_scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                });
            selections.push(CurrentSelection {
                rule_set_id: [set; 16],
                version_bytes: version.clone(),
            });
        }

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
        authority.bind_to_root(&owner).unwrap();
        let session_for = |root: &RequestRootExtension, card: u8| {
            let issued = authority
                .identity_session_adapter()
                .issue_unchecked_for_test(identity(card), 100, 100)
                .unwrap();
            authority
                .verifier()
                .verify_and_bind(issued.credential(), 100, root)
                .unwrap()
        };
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: None,
            target_tenant: None,
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };

        // Card 4 (normal binding): Allow — baseline.
        let card4 = session_for(&root, 4);
        let result = evaluate_with(&root, &card4, &request, || Some(110), || {});
        assert_eq!(result.decision, MemoryV1Decision::Allow);

        // memory—v1 §4.12 B-2.2: REMOVED binding → skipped → NoMatch.
        // The tombstone row is loaded but the evaluation skips it.
        let card7 = session_for(&root, 7);
        let result = evaluate_with(&root, &card7, &request, || Some(110), || {});
        assert_eq!(result.decision, MemoryV1Decision::Deny);
        assert_eq!(result.deny_source, Some(MemoryV1DenySource::NoMatch));

        // memory—v1 §4.12 B-2.4: REVOKED confirmation is a deliberate
        // management withdrawal → the binding contributes nothing →
        // deterministic NoMatch. Simulate the mutation through the explicit
        // isolated-test hook; this is not an authorized governance commit.
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id: [40; 16],
                    revoked_at: 120,
                    revoked_by: [1; 16],
                },
                &MutationPrecondition {
                    evaluated_root_version: owner.handle().metadata().unwrap().version,
                },
            )
            .unwrap();
        // A new request reader binds the post-mutation snapshot (§4.7).
        let scope_after = RequestRootScope::new(owner.handle(), Default::default());
        let root_after = scope_after.extension();
        let card4_after = session_for(&root_after, 4);
        let result = evaluate_with(&root_after, &card4_after, &request, || Some(110), || {});
        assert_eq!(result.decision, MemoryV1Decision::Deny);
        assert_eq!(result.deny_source, Some(MemoryV1DenySource::NoMatch));

        // The old immutable reader cannot authorize after its confirmation was
        // revoked, even though it still sees the original relationship.
        let result = evaluate_with(&root, &card4, &request, || Some(110), || {});
        assert_eq!(result.decision, MemoryV1Decision::Pending);
    }

    // memory—v1 §4.11/§4.12: A cold-adopted revoked OVERLAY DENY leaves
    // BASE active, and a new confirmation restores the OVERLAY contribution.
    #[test]
    fn withdrawn_overlay_survives_adoption_and_reconfirmation() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_WITHDRAWN_OVERLAY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::withdrawn_overlay_survives_adoption_and_reconfirmation",
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
        let (mut rows, selections) = fixture();
        let confirmation = rows
            .binding_confirmations
            .iter_mut()
            .find(|row| row.confirmation_id == [42; 16])
            .unwrap();
        confirmation.revoked_at = Some(100);
        confirmation.revoked_by = Some([1; 16]);
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 64,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: None,
            target_tenant: None,
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };
        let evaluate = || {
            let scope = RequestRootScope::new(owner.handle(), Default::default());
            let root = scope.extension();
            let issued = authority
                .identity_session_adapter()
                .issue_unchecked_for_test(identity(7), 100, 100)
                .unwrap();
            let session = authority
                .verifier()
                .verify_and_bind(issued.credential(), 100, &root)
                .unwrap();
            evaluate_with(&root, &session, &request, || Some(110), || {})
        };
        assert_eq!(evaluate().decision, MemoryV1Decision::Allow);
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::ConfirmationCreate {
                    row: BindingConfirmationRow {
                        confirmation_id: [90; 16],
                        binding_id: [22; 16],
                        rule_set_id: [12; 16],
                        version_bytes: vec![1],
                        confirmer_user_id: [1; 16],
                        scope_bytes: vec![1],
                        operation_id: vec![1],
                        confirmed_at_bytes: vec![1],
                        revoked_at: None,
                        revoked_by: None,
                    },
                },
                &MutationPrecondition {
                    evaluated_root_version: owner.handle().metadata().unwrap().version,
                },
            )
            .unwrap();
        let restored = evaluate();
        assert_eq!(restored.decision, MemoryV1Decision::Deny);
        assert_eq!(restored.deny_source, Some(MemoryV1DenySource::RuleDenied));
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id: [90; 16],
                    revoked_at: 120,
                    revoked_by: [1; 16],
                },
                &MutationPrecondition {
                    evaluated_root_version: owner.handle().metadata().unwrap().version,
                },
            )
            .unwrap();
        assert_eq!(evaluate().decision, MemoryV1Decision::Allow);
    }

    // memory—v1 §4.4: an ALLOW cannot cross a later DENY activation boundary.
    #[test]
    fn future_deny_activation_invalidates_inflight_allow() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_FUTURE_DENY_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::future_deny_activation_invalidates_inflight_allow",
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
        let (mut rows, selections) = fixture();
        let deny = rows
            .rule_set_versions
            .iter_mut()
            .find(|version| version.rule_set_id == [12; 16])
            .unwrap();
        deny.content_bytes = br#"{"rules":[{"ruleId":"D","resource":"document","action":"read","effect":"DENY","validity":{"from":120}}]}"#.to_vec();
        deny.hash_input_bytes = canonical_version_bytes(
            &deny.version_bytes,
            &deny.content_bytes,
            &deny.timestamp_bytes,
        );
        deny.hash_bytes =
            astral_authorization_root::memory_v1_rules::version_digest(&deny.hash_input_bytes);
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 128,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(identity(7), 100, 100)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: None,
            target_tenant: None,
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };
        let mut before_boundary = [110, 119].into_iter();
        assert_eq!(
            evaluate_with(&root, &session, &request, || before_boundary.next(), || {}).decision,
            MemoryV1Decision::Allow
        );
        let mut crossing_boundary = [110, 120].into_iter();
        let crossing = evaluate_with(
            &root,
            &session,
            &request,
            || crossing_boundary.next(),
            || {},
        );
        assert_eq!(crossing.decision, MemoryV1Decision::Pending);
        assert!(crossing.admission.is_none());
        assert_eq!(
            evaluate_with(&root, &session, &request, || Some(120), || {}).decision,
            MemoryV1Decision::Deny
        );
    }

    // memory—v1: Exact-root confirmation samples the clock with the live
    // session, root and registry guarded; fences use a subsequent snapshot.
    #[test]
    fn rule_set_change_exact_root_time_and_races() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_CHANGE_EXACT_ROOT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::rule_set_change_exact_root_time_and_races",
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
        let (mut rows, selections) = fixture();
        let version = rows
            .rule_set_versions
            .iter_mut()
            .find(|row| row.rule_set_id == [10; 16])
            .unwrap();
        version.content_bytes = br#"{"rules":[{"ruleId":"confirm","resource":"rule_set","action":"confirm-change","effect":"ALLOW","ownerScope":"all","validity":{"until":120}}]}"#.to_vec();
        version.hash_input_bytes = canonical_version_bytes(
            &version.version_bytes,
            &version.content_bytes,
            &version.timestamp_bytes,
        );
        version.hash_bytes =
            astral_authorization_root::memory_v1_rules::version_digest(&version.hash_input_bytes);
        rows.bindings
            .iter_mut()
            .find(|row| row.binding_id == [20; 16])
            .unwrap()
            .owner_scope = MemoryV1OwnerScope::AllUsers;
        let removed = rows
            .bindings
            .iter_mut()
            .find(|row| row.binding_id == [21; 16])
            .unwrap();
        removed.removed_at = Some(100);
        removed.removed_by = Some([1; 16]);
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 128,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[
                RegistryDeclaration {
                    resource: "rule_set".to_owned(),
                    actions: vec!["confirm-change".to_owned()],
                },
                RegistryDeclaration {
                    resource: "document".to_owned(),
                    actions: vec!["read".to_owned()],
                },
            ])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let target = [11; 16];
        let tenant = [3; 16];
        let request = MemoryV1Request {
            resource: "rule_set",
            action: "confirm-change",
            target: Some(&target),
            target_tenant: Some(&tenant),
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let execute = |start, end, hook: &mut dyn FnMut()| {
            let mut times = [Some(start), end].into_iter();
            evaluate_rule_set_change_with(
                &root,
                &session,
                &request,
                MemoryV1RuleSetChangeIntent::Publish,
                || times.next().flatten(),
                hook,
                |check, record, constraints, metadata, target, clock| {
                    check.try_final_time_exact_root_for_test(
                        record,
                        constraints,
                        metadata,
                        target,
                        clock,
                    )
                },
            )
        };
        let pass = execute(110, Some(111), &mut || {});
        assert_eq!(pass.decision, MemoryV1Decision::Allow);
        assert_eq!(pass.admission.unwrap().trusted_time_unix_seconds(), 111);
        for (start, end) in [
            (110, Some(120)),
            (110, Some(109)),
            (110, None),
            (110, Some(200)),
        ] {
            let result = execute(start, end, &mut || {});
            assert_eq!(result.decision, MemoryV1Decision::Pending);
            assert!(result.admission.is_none());
        }
        let protected = root
            .with_reader(|reader| {
                evaluate_rule_set_change_with(
                    &root,
                    &session,
                    &request,
                    MemoryV1RuleSetChangeIntent::Publish,
                    || Some(110),
                    || {},
                    |check, record, constraints, metadata, target, _| {
                        check.try_final_time_exact_root_for_test(
                            record,
                            constraints,
                            metadata,
                            target,
                            || {
                                assert!(!authority.write_available_for_test());
                                assert_eq!(
                                    reader.final_check_locks_available_for_test().unwrap(),
                                    [false, false, true]
                                );
                                Some(111)
                            },
                        )
                    },
                )
            })
            .unwrap();
        assert_eq!(protected.decision, MemoryV1Decision::Allow);
        // memory—v1: Every batch target shares the same final root, session,
        // registry and fence observation, including targets unrelated to the actor.
        let batch_check = root
            .with_reader(|reader| {
                evaluate_rule_set_change_with(
                    &root,
                    &session,
                    &request,
                    MemoryV1RuleSetChangeIntent::Publish,
                    || Some(110),
                    || {},
                    |check, record, constraints, metadata, target, _| {
                        assert_eq!(
                            check.try_final_time_exact_batch_for_test(
                                record,
                                constraints,
                                metadata,
                                &[],
                                || Some(111),
                            ),
                            None
                        );
                        assert_eq!(
                            check.try_final_time_exact_batch_for_test(
                                record,
                                constraints,
                                metadata,
                                &[target, [0; 16]],
                                || Some(111),
                            ),
                            None
                        );
                        check.try_final_time_exact_batch_for_test(
                            record,
                            constraints,
                            metadata,
                            &[target, [10; 16]],
                            || {
                                assert!(!authority.write_available_for_test());
                                assert_eq!(
                                    reader.final_check_locks_available_for_test().unwrap(),
                                    [false, false, true]
                                );
                                Some(111)
                            },
                        )
                    },
                )
            })
            .unwrap();
        assert_eq!(batch_check.decision, MemoryV1Decision::Allow);
        let metadata = owner.handle().metadata().unwrap();
        let declaration = astral_authorization_root::memory_v1_fence::FenceDeclaration {
            rule_set_version: vec![1],
            root_version: metadata.version,
            digest: metadata.digest,
        };
        owner
            .begin_modification_fence(target, &declaration)
            .unwrap();
        let ordinary_fenced = evaluate_with(&root, &session, &request, || Some(110), || {});
        assert_eq!(ordinary_fenced.decision, MemoryV1Decision::Pending);
        assert_eq!(
            ordinary_fenced.pending_source,
            Some(MemoryV1PendingSource::FenceActive)
        );
        assert!(ordinary_fenced.admission.is_none());
        let mut after_read_called = false;
        let already_fenced = execute(110, Some(111), &mut || {
            after_read_called = true;
            owner.abort_modification_fence(target).unwrap();
        });
        assert_eq!(already_fenced.decision, MemoryV1Decision::Pending);
        assert_eq!(
            already_fenced.pending_source,
            Some(MemoryV1PendingSource::FenceActive)
        );
        assert!(already_fenced.admission.is_none());
        assert!(!after_read_called);
        owner.abort_modification_fence(target).unwrap();
        owner
            .begin_modification_fence([10; 16], &declaration)
            .unwrap();
        let batch_target_fenced = evaluate_rule_set_change_with(
            &root,
            &session,
            &request,
            MemoryV1RuleSetChangeIntent::Publish,
            || Some(110),
            || {},
            |check, record, constraints, metadata, target, _| {
                check.try_final_time_exact_batch_for_test(
                    record,
                    constraints,
                    metadata,
                    &[target, [10; 16]],
                    || Some(111),
                )
            },
        );
        assert_eq!(batch_target_fenced.decision, MemoryV1Decision::Pending);
        assert!(batch_target_fenced.admission.is_none());
        owner.abort_modification_fence([10; 16]).unwrap();
        let mut target_fence = false;
        let fenced = execute(110, Some(111), &mut || {
            let meta = owner.handle().metadata().unwrap();
            owner
                .begin_modification_fence(
                    target,
                    &astral_authorization_root::memory_v1_fence::FenceDeclaration {
                        rule_set_version: vec![1],
                        root_version: meta.version,
                        digest: meta.digest,
                    },
                )
                .unwrap();
            target_fence = true;
        });
        assert_eq!(fenced.decision, MemoryV1Decision::Pending);
        assert!(target_fence);
        owner.abort_modification_fence(target).unwrap();
        let revoked = execute(110, Some(111), &mut || {
            adapter.revoke(issued.credential()).unwrap();
        });
        assert_eq!(revoked.decision, MemoryV1Decision::Pending);
        let issued2 = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let session2 = authority
            .verifier()
            .verify_and_bind(issued2.credential(), 100, &root)
            .unwrap();
        let stale = evaluate_rule_set_change_with(
            &root,
            &session2,
            &request,
            MemoryV1RuleSetChangeIntent::Publish,
            || Some(110),
            || {
                let before = owner.handle().metadata().unwrap();
                authority
                    .disable_card_with_sessions_for_isolated_tests(
                        &owner.mutation_executor(),
                        astral_types::memory_v1::MemoryId::from_bytes([8; 16]),
                        before,
                    )
                    .unwrap();
            },
            |check, record, constraints, metadata, target, clock| {
                check.try_final_time_exact_root_for_test(
                    record,
                    constraints,
                    metadata,
                    target,
                    clock,
                )
            },
        );
        assert_eq!(stale.decision, MemoryV1Decision::Pending);
        assert!(stale.admission.is_none());
        let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
        let fresh_root = fresh_scope.extension();
        let fresh_session = authority
            .verifier()
            .verify_and_bind(issued2.credential(), 100, &fresh_root)
            .unwrap();
        let registry_changed = evaluate_rule_set_change_with(
            &fresh_root,
            &fresh_session,
            &request,
            MemoryV1RuleSetChangeIntent::Publish,
            || Some(110),
            || {
                owner
                    .request_registry_retirement_for_test("document")
                    .unwrap();
            },
            |check, record, constraints, metadata, target, clock| {
                check.try_final_time_exact_root_for_test(
                    record,
                    constraints,
                    metadata,
                    target,
                    clock,
                )
            },
        );
        assert_eq!(registry_changed.decision, MemoryV1Decision::Pending);
        assert!(registry_changed.admission.is_none());
    }

    // memory—v1: Final observations cover time boundaries and every lock domain.
    #[test]
    fn final_check_time_and_contention_fail_closed() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_FINAL_CHECK_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::final_check_time_and_contention_fail_closed",
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

        let (mut rows, selections) = fixture();
        let version = rows
            .rule_set_versions
            .iter_mut()
            .find(|version| version.rule_set_id == [10; 16])
            .unwrap();
        version.content_bytes = br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW","validity":{"until":120}}]}"#.to_vec();
        version.hash_input_bytes = canonical_version_bytes(
            &version.version_bytes,
            &version.content_bytes,
            &version.timestamp_bytes,
        );
        version.hash_bytes =
            astral_authorization_root::memory_v1_rules::version_digest(&version.hash_input_bytes);
        rows.bindings
            .iter_mut()
            .find(|binding| binding.binding_id == [23; 16])
            .unwrap()
            .valid_until = Some(130);
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 128,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 15)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: None,
            target_tenant: None,
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };
        let assert_pending = |result: MemoryV1Evaluation| {
            assert_eq!(result.decision, MemoryV1Decision::Pending);
            assert!(result.admission.is_none());
        };
        // memory—v1: Probe the guards and fence writer at final clock sampling.
        let protected = root
            .with_reader(|reader| {
                evaluate_with_final(
                    &root,
                    &session,
                    &request,
                    || Some(110),
                    || {},
                    |check, record, constraints, _| {
                        check.try_final_time_for_test(record, constraints, || {
                            assert!(!authority.write_available_for_test());
                            assert_eq!(
                                reader.final_check_locks_available_for_test().unwrap(),
                                [false, false, true]
                            );
                            Some(114)
                        })
                    },
                )
            })
            .unwrap();
        assert_eq!(protected.decision, MemoryV1Decision::Allow);
        let mut before = [110, 114].into_iter();
        let allowed = evaluate_with(&root, &session, &request, || before.next(), || {});
        assert_eq!(allowed.decision, MemoryV1Decision::Allow);
        assert_eq!(allowed.admission.unwrap().trusted_time_unix_seconds(), 114);
        let mut expired = [110, 115].into_iter();
        assert_pending(evaluate_with(
            &root,
            &session,
            &request,
            || expired.next(),
            || {},
        ));
        let mut rollback = [110, 109].into_iter();
        assert_pending(evaluate_with(
            &root,
            &session,
            &request,
            || rollback.next(),
            || {},
        ));
        let mut unavailable = [Some(110), None].into_iter();
        assert_pending(evaluate_with(
            &root,
            &session,
            &request,
            || unavailable.next().flatten(),
            || {},
        ));

        let long_issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let long_session = authority
            .verifier()
            .verify_and_bind(long_issued.credential(), 100, &root)
            .unwrap();
        let mut rule_expired = [110, 120].into_iter();
        assert_pending(evaluate_with(
            &root,
            &long_session,
            &request,
            || rule_expired.next(),
            || {},
        ));
        let card8_issued = adapter
            .issue_unchecked_for_test(identity(8), 100, 100)
            .unwrap();
        let card8 = authority
            .verifier()
            .verify_and_bind(card8_issued.credential(), 100, &root)
            .unwrap();
        let mut binding_expired = [110, 130].into_iter();
        assert_pending(evaluate_with(
            &root,
            &card8,
            &request,
            || binding_expired.next(),
            || {},
        ));

        let metadata = owner.handle().metadata().unwrap();
        let declaration = astral_authorization_root::memory_v1_fence::FenceDeclaration {
            rule_set_version: vec![1],
            root_version: metadata.version,
            digest: metadata.digest,
        };
        // memory—v1 §4.7: a window opened and released during the read phase is
        // recorded against the reader's read-phase stamp, so the touched
        // dependency stays refused in this phase even without a publication.
        let aborted = evaluate_with(
            &root,
            &long_session,
            &request,
            || Some(110),
            || {
                owner
                    .begin_modification_fence([10; 16], &declaration)
                    .unwrap();
                owner.abort_modification_fence([10; 16]).unwrap();
            },
        );
        assert_eq!(aborted.decision, MemoryV1Decision::Pending);

        // memory—v1: Even if the window closes before the final snapshot, a
        // sample taken inside it must not produce an admission at the edge of
        // the winning rule's validity interval.
        let transient_at_final_time = evaluate_with_final(
            &root,
            &long_session,
            &request,
            || Some(110),
            || {},
            |check, record, constraints, _| {
                check.try_final_time_for_test(record, constraints, || {
                    owner
                        .begin_modification_fence([10; 16], &declaration)
                        .unwrap();
                    let sampled = Some(119);
                    owner.abort_modification_fence([10; 16]).unwrap();
                    sampled
                })
            },
        );
        assert_pending(transient_at_final_time);
        // An unrelated window (card 4 does not depend on rule set 13) leaves
        // a fresh phase's decision available; the earlier touched [10;16]
        // windows keep the shared reader refused regardless.
        let unrelated_scope = RequestRootScope::new(owner.handle(), Default::default());
        let unrelated_root = unrelated_scope.extension();
        let unrelated_issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let unrelated_session = authority
            .verifier()
            .verify_and_bind(unrelated_issued.credential(), 100, &unrelated_root)
            .unwrap();
        let unrelated_at_final_time = evaluate_with_final(
            &unrelated_root,
            &unrelated_session,
            &request,
            || Some(110),
            || {},
            |check, record, constraints, _| {
                check.try_final_time_for_test(record, constraints, || {
                    owner
                        .begin_modification_fence([13; 16], &declaration)
                        .unwrap();
                    let sampled = Some(119);
                    owner.abort_modification_fence([13; 16]).unwrap();
                    sampled
                })
            },
        );
        assert_eq!(unrelated_at_final_time.decision, MemoryV1Decision::Allow);
        assert_eq!(
            unrelated_at_final_time
                .admission
                .unwrap()
                .trusted_time_unix_seconds(),
            119
        );
        owner
            .begin_modification_fence([10; 16], &declaration)
            .unwrap();
        assert_pending(evaluate_with(
            &root,
            &long_session,
            &request,
            || Some(110),
            || {},
        ));
        owner.abort_modification_fence([10; 16]).unwrap();
        owner
            .begin_modification_fence([13; 16], &declaration)
            .unwrap();
        // memory—v1 §4.7: this phase already observed windows on its touched
        // dependency [10;16]; releasing them does not revive an ALLOW here,
        // and the unrelated [13;16] window is isolated from fresh phases.
        let unrelated = evaluate_with(&root, &long_session, &request, || Some(110), || {});
        assert_eq!(unrelated.decision, MemoryV1Decision::Pending);
        owner.abort_modification_fence([13; 16]).unwrap();
        // A fresh reader does not depend on the unrelated open window.
        let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
        let fresh_root = fresh_scope.extension();
        let fresh_issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let fresh_session = authority
            .verifier()
            .verify_and_bind(fresh_issued.credential(), 100, &fresh_root)
            .unwrap();
        owner
            .begin_modification_fence([13; 16], &declaration)
            .unwrap();
        let unrelated_fresh =
            evaluate_with(&fresh_root, &fresh_session, &request, || Some(110), || {});
        assert_eq!(unrelated_fresh.decision, MemoryV1Decision::Allow);
        owner.abort_modification_fence([13; 16]).unwrap();
    }

    // memory—v1 §4.7: Guarded final-clock sampling and overlap semantics on a
    // read phase whose dependency set was never fenced, so the Allow baseline
    // holds and only the injected contention fails closed.
    #[test]
    fn final_check_lock_contention_fail_closed() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_LOCK_CONTENTION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::final_check_lock_contention_fail_closed",
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
                max_table_rows: 128,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let long_issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let long_session = authority
            .verifier()
            .verify_and_bind(long_issued.credential(), 100, &root)
            .unwrap();
        let request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: None,
            target_tenant: None,
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };
        let assert_pending = |result: MemoryV1Evaluation| {
            assert_eq!(result.decision, MemoryV1Decision::Pending);
            assert!(result.admission.is_none());
        };

        for lock in ["session", "root", "registry"] {
            let result = evaluate_with(&root, &long_session, &request, || Some(110), || {});
            assert_eq!(result.decision, MemoryV1Decision::Allow);
            let result = evaluate_with_final(
                &root,
                &long_session,
                &request,
                || Some(110),
                || {},
                |check, record, constraints, clock| {
                    let final_check = || check.try_final_time_for_test(record, constraints, clock);
                    std::thread::scope(|threads| {
                        let (held_tx, held_rx) = std::sync::mpsc::channel();
                        let (release_tx, release_rx) = std::sync::mpsc::channel();
                        let authority_ref = &authority;
                        let root_ref = &root;
                        let holder = threads.spawn(move || {
                            let hold = || {
                                held_tx.send(()).unwrap();
                                release_rx
                                    .recv_timeout(std::time::Duration::from_secs(5))
                                    .unwrap();
                            };
                            if lock == "session" {
                                authority_ref.with_write_lock_for_test(hold);
                            } else {
                                root_ref
                                    .with_reader(|reader| {
                                        reader.with_final_check_lock_for_test(lock, hold).unwrap()
                                    })
                                    .unwrap();
                            }
                        });
                        held_rx
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .unwrap();
                        let result = final_check();
                        release_tx.send(()).unwrap();
                        holder.join().unwrap();
                        result
                    })
                },
            );
            assert_pending(result);
        }
        // memory—v1: Two final readers may overlap, but revocation cannot
        // linearize until both guarded clock observations have finished.
        let raced_scope = RequestRootScope::new(owner.handle(), Default::default());
        let raced_root = raced_scope.extension();
        let raced_issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let raced_session = authority
            .verifier()
            .verify_and_bind(raced_issued.credential(), 100, &raced_root)
            .unwrap();
        std::thread::scope(|threads| {
            use std::sync::mpsc;
            use std::time::Duration;

            let (entered_tx, entered_rx) = mpsc::channel();
            let (attempt_tx, attempt_rx) = mpsc::channel();
            let (revoked_tx, revoked_rx) = mpsc::channel();
            let mut releases = Vec::new();
            let mut readers = Vec::new();
            for _ in 0..2 {
                let entered = entered_tx.clone();
                let (release_tx, release_rx) = mpsc::channel();
                releases.push(release_tx);
                let root_ref = &raced_root;
                let session_ref = &raced_session;
                let request_ref = &request;
                readers.push(threads.spawn(move || {
                    evaluate_with_final(
                        root_ref,
                        session_ref,
                        request_ref,
                        || Some(110),
                        || {},
                        |check, record, constraints, _| {
                            check.try_final_time_for_test(record, constraints, || {
                                entered.send(()).unwrap();
                                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                                Some(110)
                            })
                        },
                    )
                }));
            }
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let adapter_ref = &adapter;
            let credential = raced_issued.credential();
            let writer = threads.spawn(move || {
                attempt_tx.send(()).unwrap();
                let result = adapter_ref.revoke(credential);
                revoked_tx.send(result).unwrap();
            });
            attempt_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(matches!(
                revoked_rx.try_recv(),
                Err(mpsc::TryRecvError::Empty)
            ));
            for release in releases {
                release.send(()).unwrap();
            }
            for reader in readers {
                assert_eq!(reader.join().unwrap().decision, MemoryV1Decision::Allow);
            }
            revoked_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            writer.join().unwrap();
        });
        assert_pending(evaluate_with(
            &raced_root,
            &raced_session,
            &request,
            || Some(110),
            || {},
        ));
        assert_pending(evaluate_with(
            &raced_root,
            &long_session,
            &request,
            || Some(110),
            || adapter.revoke(long_issued.credential()).unwrap(),
        ));
    }

    // memory—v1 §4.7: publishing a rule set only invalidates readers that
    // actually depend on it, even though both publications change the root.
    #[test]
    fn rule_set_dependency_recheck_isolates_unrelated_publications() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_RULE_SET_ISOLATION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            for scenario in ["unrelated", "affected"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "memory_v1_formal::tests::rule_set_dependency_recheck_isolates_unrelated_publications",
                        "--nocapture",
                    ])
                    .env(CHILD, scenario)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "scenario: {scenario}\nstdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            }
            return;
        }
        let (card, expected) = match std::env::var(CHILD).as_deref() {
            Ok("unrelated") => (4, MemoryV1Decision::Allow),
            Ok("affected") => (8, MemoryV1Decision::Pending),
            other => panic!("unexpected isolation scenario: {other:?}"),
        };

        let (rows, selections) = fixture();
        for (card, set) in [(4, 10), (8, 13)] {
            let bindings: Vec<_> = rows
                .bindings
                .iter()
                .filter(|binding| binding.user_card_id == [card; 16])
                .collect();
            assert_eq!(bindings.len(), 1);
            assert_eq!(bindings[0].rule_set_id, [set; 16]);
        }
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 128,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: None,
            target_tenant: None,
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };

        // Both scenarios start from the same fixture in separate processes.
        // Card 4 depends only on A; card 8 depends only on B.
        let version = 2;
        let confirmation_id = 90;
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(identity(card), 100, 100)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let baseline = evaluate_with(&root, &session, &request, || Some(110), || {});
        assert_eq!(baseline.decision, MemoryV1Decision::Allow);
        assert!(baseline.admission.is_some());

        let content = br#"{"rules":[{"ruleId":"R4","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        let version_bytes = vec![version];
        let timestamp_bytes = vec![version];
        let hash_input_bytes = canonical_version_bytes(&version_bytes, content, &timestamp_bytes);
        let mutation = ManagementMutationV2::VersionPublish {
            rule_set_id: [13; 16],
            version_row: RuleSetVersionRow {
                rule_set_id: [13; 16],
                version_bytes: version_bytes.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes,
                hash_bytes: astral_authorization_root::memory_v1_rules::version_digest(
                    &hash_input_bytes,
                ),
                hash_input_bytes,
            },
            new_current_version: version_bytes.clone(),
            change_confirmation: RuleSetChangeConfirmationRow {
                confirmation_id: [confirmation_id; 16],
                rule_set_id: [13; 16],
                version_bytes,
                confirmer_user_id: [1; 16],
                affected_scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            },
        };
        let before = owner.handle().metadata().unwrap();
        let unregistered_request = MemoryV1Request {
            action: "unknown",
            ..request
        };
        let denied_before =
            evaluate_with(&root, &session, &unregistered_request, || Some(110), || {});
        let deny_observation = denied_before.deny_observation.as_deref().unwrap();
        assert_eq!(deny_observation.root(), before);
        let mut after_read_called = false;
        let result = evaluate_with(
            &root,
            &session,
            &request,
            || Some(110),
            || {
                after_read_called = true;
                owner
                    .execute_mutation_with_precondition_for_isolated_tests(
                        &mutation,
                        &MutationPrecondition {
                            evaluated_root_version: before.version,
                        },
                    )
                    .unwrap();
            },
        );
        assert!(after_read_called);
        assert!(owner.handle().metadata().unwrap().version > before.version);
        assert_eq!(deny_observation.root(), before);
        assert_ne!(deny_observation.root(), owner.handle().metadata().unwrap());
        assert_eq!(deny_observation.action(), "unknown");
        assert_eq!(result.decision, expected);
        if expected == MemoryV1Decision::Allow {
            let admission = result
                .admission
                .expect("unrelated publish retains admission");
            assert_eq!(admission.identity(), identity(card));
        } else {
            assert_eq!(
                result.pending_source,
                Some(MemoryV1PendingSource::ContextInvalid)
            );
            assert!(result.admission.is_none());
        }
    }

    // memory—v1 §4.7: in-flight decisions recheck card and rule-set
    // generations, while changes to an unrelated card remain isolated.
    #[test]
    fn dependency_recheck_covers_inflight_mutations() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_DEPENDENCY_RECHECK_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::dependency_recheck_covers_inflight_mutations",
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
                max_table_rows: 128,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: None,
            target_tenant: None,
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let adapter = authority.identity_session_adapter();
        let issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let compatibility = root
            .bind_session_facts(
                authority
                    .verifier()
                    .verify(issued.credential(), 100)
                    .unwrap()
                    .facts_for_test(),
            )
            .unwrap();
        let unregistered = MemoryV1Request {
            resource: "unregistered",
            ..request
        };
        let compatibility_result =
            evaluate_with(&root, &compatibility, &unregistered, || Some(110), || {});
        assert_eq!(compatibility_result.decision, MemoryV1Decision::Pending);
        assert_eq!(
            compatibility_result.pending_source,
            Some(MemoryV1PendingSource::ContextInvalid)
        );
        assert!(compatibility_result.admission.is_none());
        let target = [11; 16];
        let tenant = [3; 16];
        let change_request = MemoryV1Request {
            resource: "rule_set",
            action: "confirm-change",
            target: Some(&target),
            target_tenant: Some(&tenant),
            ..request
        };
        let compatibility_change = evaluate_rule_set_change_with(
            &root,
            &compatibility,
            &change_request,
            MemoryV1RuleSetChangeIntent::Publish,
            || Some(110),
            || {},
            |_, _, _, _, _, _| panic!("compatibility facts must not reach final admission"),
        );
        assert_eq!(compatibility_change.decision, MemoryV1Decision::Pending);
        assert!(compatibility_change.admission.is_none());
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let revoked_in_flight = evaluate_with(
            &root,
            &session,
            &request,
            || Some(110),
            || {
                adapter.revoke(issued.credential()).unwrap();
            },
        );
        assert_eq!(revoked_in_flight.decision, MemoryV1Decision::Pending);
        assert!(revoked_in_flight.admission.is_none());

        let run = |mutation: ManagementMutationV2, expected| {
            let scope = RequestRootScope::new(owner.handle(), Default::default());
            let root = scope.extension();
            let issued = authority
                .identity_session_adapter()
                .issue_unchecked_for_test(identity(4), 100, 100)
                .unwrap();
            let session = authority
                .verifier()
                .verify_and_bind(issued.credential(), 100, &root)
                .unwrap();
            let result = evaluate_with(
                &root,
                &session,
                &request,
                || Some(110),
                || {
                    let before = owner.handle().metadata().unwrap();
                    if let ManagementMutationV2::UserCardStatus {
                        user_card_id,
                        status: UserCardStatus::Disabled,
                    } = &mutation
                    {
                        authority
                            .disable_card_with_sessions_for_isolated_tests(
                                &owner.mutation_executor(),
                                astral_types::memory_v1::MemoryId::from_bytes(*user_card_id),
                                before,
                            )
                            .unwrap();
                    } else {
                        owner
                            .execute_mutation_with_precondition_for_isolated_tests(
                                &mutation,
                                &MutationPrecondition {
                                    evaluated_root_version: before.version,
                                },
                            )
                            .unwrap();
                    }
                },
            );
            assert_eq!(result.decision, expected);
        };

        run(
            ManagementMutationV2::UserCardStatus {
                user_card_id: [8; 16],
                status: UserCardStatus::Disabled,
            },
            MemoryV1Decision::Allow,
        );
        run(
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: [40; 16],
                revoked_at: 110,
                revoked_by: [1; 16],
            },
            MemoryV1Decision::Pending,
        );
        let restore = ManagementMutationV2::ConfirmationCreate {
            row: BindingConfirmationRow {
                confirmation_id: [90; 16],
                binding_id: [20; 16],
                rule_set_id: [10; 16],
                version_bytes: vec![1],
                confirmer_user_id: [1; 16],
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            },
        };
        let before = owner.handle().metadata().unwrap();
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &restore,
                &MutationPrecondition {
                    evaluated_root_version: before.version,
                },
            )
            .unwrap();

        let content =
            br#"{"rules":[{"ruleId":"R","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        let version_bytes = vec![2];
        let timestamp_bytes = vec![2];
        let hash_input_bytes = canonical_version_bytes(&version_bytes, content, &timestamp_bytes);
        run(
            ManagementMutationV2::VersionPublish {
                rule_set_id: [10; 16],
                version_row: RuleSetVersionRow {
                    rule_set_id: [10; 16],
                    version_bytes: version_bytes.clone(),
                    content_bytes: content.to_vec(),
                    timestamp_bytes,
                    hash_bytes: astral_authorization_root::memory_v1_rules::version_digest(
                        &hash_input_bytes,
                    ),
                    hash_input_bytes,
                },
                new_current_version: version_bytes.clone(),
                change_confirmation: RuleSetChangeConfirmationRow {
                    confirmation_id: [91; 16],
                    rule_set_id: [10; 16],
                    version_bytes: version_bytes.clone(),
                    confirmer_user_id: [1; 16],
                    affected_scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
            },
            MemoryV1Decision::Pending,
        );
        run(
            ManagementMutationV2::BindingCreate {
                row: BindingRow {
                    binding_id: [91; 16],
                    user_card_id: [4; 16],
                    rule_set_id: [12; 16],
                    binding_layer: BindingLayer::Overlay,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                },
                confirmation: BindingConfirmationRow {
                    confirmation_id: [92; 16],
                    binding_id: [91; 16],
                    rule_set_id: [12; 16],
                    version_bytes: vec![1],
                    confirmer_user_id: [1; 16],
                    scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
            },
            MemoryV1Decision::Pending,
        );
        let remove_overlay = ManagementMutationV2::BindingRemove {
            binding_id: [91; 16],
            removed_at: 110,
            removed_by: [1; 16],
        };
        let before = owner.handle().metadata().unwrap();
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &remove_overlay,
                &MutationPrecondition {
                    evaluated_root_version: before.version,
                },
            )
            .unwrap();
        let before = owner.handle().metadata().unwrap();
        let declaration = astral_authorization_root::memory_v1_fence::FenceDeclaration {
            rule_set_version: version_bytes,
            root_version: before.version,
            digest: before.digest,
        };
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let fenced_in_flight = evaluate_with(
            &root,
            &session,
            &request,
            || Some(110),
            || {
                owner
                    .begin_modification_fence([10; 16], &declaration)
                    .unwrap();
            },
        );
        assert_eq!(fenced_in_flight.decision, MemoryV1Decision::Pending);
        assert!(fenced_in_flight.admission.is_none());
        owner.abort_modification_fence([10; 16]).unwrap();
        let admitted_scope = RequestRootScope::new(owner.handle(), Default::default());
        let admitted_root = admitted_scope.extension();
        let admitted_issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let admitted_session = authority
            .verifier()
            .verify_and_bind(admitted_issued.credential(), 100, &admitted_root)
            .unwrap();
        let already_admitted = evaluate_with(
            &admitted_root,
            &admitted_session,
            &request,
            || Some(110),
            || {},
        );
        assert_eq!(already_admitted.decision, MemoryV1Decision::Allow);
        assert!(already_admitted.admission.is_some());

        let before_revoke = owner.handle().metadata().unwrap();
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id: [90; 16],
                    revoked_at: 110,
                    revoked_by: [1; 16],
                },
                &MutationPrecondition {
                    evaluated_root_version: before_revoke.version,
                },
            )
            .unwrap();
        // A later revoke does not retroactively cancel an admission.
        assert_eq!(already_admitted.decision, MemoryV1Decision::Allow);
        assert!(already_admitted.admission.is_some());
        let next_scope = RequestRootScope::new(owner.handle(), Default::default());
        let next_root = next_scope.extension();
        let next_session = authority
            .verifier()
            .verify_and_bind(admitted_issued.credential(), 110, &next_root)
            .unwrap();
        let after_revoke = evaluate_with(&next_root, &next_session, &request, || Some(110), || {});
        assert_eq!(after_revoke.decision, MemoryV1Decision::Deny);
        assert_eq!(after_revoke.deny_source, Some(MemoryV1DenySource::NoMatch));
        assert!(after_revoke.admission.is_none());
        let latest = owner.handle().metadata().unwrap();
        let replacement = ManagementMutationV2::ConfirmationCreate {
            row: BindingConfirmationRow {
                confirmation_id: [93; 16],
                binding_id: [20; 16],
                rule_set_id: [10; 16],
                version_bytes: vec![1],
                confirmer_user_id: [1; 16],
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            },
        };
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &replacement,
                &MutationPrecondition {
                    evaluated_root_version: latest.version,
                },
            )
            .unwrap();
        run(
            ManagementMutationV2::UserCardStatus {
                user_card_id: [4; 16],
                status: UserCardStatus::Disabled,
            },
            MemoryV1Decision::Pending,
        );
    }

    // memory—v1 §4.6/§4.7: The dependency read side follows the per-rule-set
    // FenceRevision. A window opened and released on a touched rule set keeps
    // the same read phase refused across a publication (the begin->abort ABA,
    // even when the root version moves), while an unrelated rule set's window
    // is isolated from its own phase.
    #[test]
    fn fence_revision_recheck_detects_aborted_window_across_publication() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_FENCE_REVISION_ABA_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_formal::tests::fence_revision_recheck_detects_aborted_window_across_publication",
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
                max_table_rows: 128,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let request = MemoryV1Request {
            resource: "document",
            action: "read",
            target: None,
            target_tenant: None,
            target_owner: None,
            operation_id: b"op",
            operation_fingerprint: b"fp",
        };
        let assert_pending = |result: &MemoryV1Evaluation| {
            assert_eq!(result.decision, MemoryV1Decision::Pending);
            assert!(result.admission.is_none());
        };

        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();

        // 1. A live window on the touched rule set refuses reads immediately.
        let before = owner.handle().metadata().unwrap();
        let declaration = astral_authorization_root::memory_v1_fence::FenceDeclaration {
            rule_set_version: vec![1],
            root_version: before.version,
            digest: before.digest,
        };
        owner
            .begin_modification_fence([10; 16], &declaration)
            .unwrap();
        let active = evaluate_with(&root, &session, &request, || Some(110), || {});
        assert_eq!(active.decision, MemoryV1Decision::Pending);
        assert_eq!(
            active.pending_source,
            Some(MemoryV1PendingSource::FenceActive)
        );
        owner.abort_modification_fence([10; 16]).unwrap();

        // 2. The released window is recorded against this phase's stamp: the
        // same reader stays refused even though the root version did not move
        // and nothing was published.
        let after_abort = evaluate_with(&root, &session, &request, || Some(110), || {});
        assert_pending(&after_abort);

        // 3. The refusal survives a publication on the same rule set: an old
        // ALLOW cannot be obtained across begin/abort + publish.
        let content =
            br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        let version_bytes = vec![2];
        let timestamp_bytes = vec![2];
        let hash_input_bytes = canonical_version_bytes(&version_bytes, content, &timestamp_bytes);
        let mutation = ManagementMutationV2::VersionPublish {
            rule_set_id: [10; 16],
            version_row: RuleSetVersionRow {
                rule_set_id: [10; 16],
                version_bytes: version_bytes.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes,
                hash_bytes: astral_authorization_root::memory_v1_rules::version_digest(
                    &hash_input_bytes,
                ),
                hash_input_bytes,
            },
            new_current_version: version_bytes.clone(),
            change_confirmation: RuleSetChangeConfirmationRow {
                confirmation_id: [95; 16],
                rule_set_id: [10; 16],
                version_bytes,
                confirmer_user_id: [1; 16],
                affected_scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            },
        };
        let before_publish = owner.handle().metadata().unwrap();
        let published = evaluate_with(
            &root,
            &session,
            &request,
            || Some(110),
            || {
                owner
                    .execute_mutation_with_precondition_for_isolated_tests(
                        &mutation,
                        &MutationPrecondition {
                            evaluated_root_version: before_publish.version,
                        },
                    )
                    .unwrap();
            },
        );
        assert_pending(&published);
        assert!(owner.handle().metadata().unwrap().version > before_publish.version);

        // The fresh request sees the new ALLOW rule and its matching confirmation.
        let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
        let fresh_root = fresh_scope.extension();
        let fresh_issued = adapter
            .issue_unchecked_for_test(identity(4), 100, 100)
            .unwrap();
        let fresh_session = authority
            .verifier()
            .verify_and_bind(fresh_issued.credential(), 100, &fresh_root)
            .unwrap();
        let fresh = evaluate_with(&fresh_root, &fresh_session, &request, || Some(110), || {});
        assert_eq!(fresh.decision, MemoryV1Decision::Allow);
        assert!(fresh.admission.is_some());

        // The old phase still cannot admit, even after the new phase has done so.
        let still_refused = evaluate_with(&root, &session, &request, || Some(110), || {});
        assert_pending(&still_refused);
    }

    mod abc_benchmark;
    mod paper_evidence;
}
