//! memory—v1: Compound TrustGraph authorization with one shared final check.
//!
//! Each action is planned against the same request root and authenticated
//! session. An active or unavailable target fence returns PENDING immediately;
//! otherwise DENY wins over PENDING for the complete action set. Once every
//! action has a valid draft, one exact-root, exact-target final check stamps all
//! admissions with the same trusted time. The result is an authorization
//! observation, never a mutation, replay, audit, or commit capability.

use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    binding_is_active, BinaryId, RuleSetStatus, UserCardStatus,
};
use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{
    DependencyRecord, GovernanceTargetFacts, RequestRootReader, RootStatus,
};
use astral_authorization_root::memory_v1_session::{
    FinalCheckTimeConstraints, RequestSessionExtension,
};

use crate::memory_v1_formal::{
    capture_deny_observation, capture_rule_set_binding_deny_observation,
    memory_v1_request_is_well_formed, plan_memory_v1_action_reader,
    plan_memory_v1_rule_set_change_reader, MemoryV1ActionDraft, MemoryV1Decision,
    MemoryV1DenyObservation, MemoryV1DenySource, MemoryV1DenyTarget, MemoryV1DraftResult,
    MemoryV1PendingSource, MemoryV1Request, MemoryV1RuleSetChangeIntent,
};

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
    // memory—v1: The hook exists only in unit-test builds and runs after all
    // planning reads, immediately before the shared final recheck.
    static AFTER_PLANNING_HOOK: RefCell<Option<Box<dyn FnMut()>>> = RefCell::new(None);
}

#[cfg(test)]
fn invoke_after_planning_hook() {
    let mut hook = AFTER_PLANNING_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook.as_mut() {
        hook();
    }
}

#[cfg(test)]
fn with_after_planning_hook<T>(hook: impl FnMut() + 'static, evaluate: impl FnOnce() -> T) -> T {
    let previous = AFTER_PLANNING_HOOK.with(|slot| slot.replace(Some(Box::new(hook))));
    let result = evaluate();
    AFTER_PLANNING_HOOK.with(|slot| {
        let active = slot.replace(previous);
        debug_assert!(active.is_none());
    });
    result
}

/// Upper bound for the actions in one same-request compound authorization.
pub const MAX_MEMORY_V1_COMPOUND_ACTIONS: usize = 8;

/// Root target interpretation used by the trusted route adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1CompoundTargetKind {
    /// Resolve an already existing binding, confirmation, or rule set from root facts.
    Existing,
    /// Resolve a proposed binding through its trusted card and rule-set facts.
    BindingCreate,
    /// Resolve a proposed rule set through its trusted owner tenant.
    RuleSetCreate,
    /// Resolve a proposed card against an existing user/tenant relationship.
    UserCardCreate,
    /// Resolve a user card and enumerate every active binding rule set.
    UserCardDisable,
    /// Resolve a disabled card and all unremoved rule-set relationships.
    UserCardEnable,
}

/// One action in a same-request compound authorization.
#[derive(Clone, Copy, Debug)]
pub struct MemoryV1CompoundAction<'a> {
    /// The exact server-bound request facts for this action.
    pub request: MemoryV1Request<'a>,
    /// The dedicated change-confirmation intent, when this is `confirm-change`.
    pub change_intent: Option<MemoryV1RuleSetChangeIntent>,
    /// Root-derived target facts captured by the trusted request middleware.
    ///
    /// The compound evaluator re-resolves these facts from its same request
    /// reader before deriving target fences. A caller-supplied nonzero ID alone
    /// is never accepted as a fence proof.
    pub target_facts: GovernanceTargetFacts,
    /// How the target is interpreted by the route adapter.
    pub target_kind: MemoryV1CompoundTargetKind,
}

/// The complete ordered same-request action set.
#[derive(Clone, Copy, Debug)]
pub struct MemoryV1CompoundRequest<'a> {
    /// Primary action followed by any required additional actions.
    pub actions: &'a [MemoryV1CompoundAction<'a>],
}

/// Result of one common compound authorization evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1CompoundEvaluation {
    /// Aggregate decision for all actions.
    pub decision: MemoryV1Decision,
    /// Deterministic denial source, when any action is denied.
    pub deny_source: Option<MemoryV1DenySource>,
    /// Safe-pending source, when no action is denied but at least one is pending.
    pub pending_source: Option<MemoryV1PendingSource>,
    /// Admissions stamped with one common trusted final time. Empty unless allowed.
    pub admissions: Vec<crate::memory_v1_formal::MemoryV1Admission>,
    /// The selected DENY's read-phase facts, when attributable.
    pub deny_observation: Option<Box<MemoryV1DenyObservation>>,
}

fn non_allow(
    decision: MemoryV1Decision,
    deny_source: Option<MemoryV1DenySource>,
    pending_source: Option<MemoryV1PendingSource>,
) -> MemoryV1CompoundEvaluation {
    debug_assert_ne!(decision, MemoryV1Decision::Allow);
    MemoryV1CompoundEvaluation {
        decision,
        deny_source,
        pending_source,
        admissions: Vec::new(),
        deny_observation: None,
    }
}

fn trusted_now() -> Option<i64> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    i64::try_from(seconds).ok()
}

fn valid_target_fences(targets: &[BinaryId]) -> bool {
    !targets.is_empty() && targets.iter().all(|target| *target != [0; 16])
}

fn target_id(request: &MemoryV1Request<'_>) -> Option<BinaryId> {
    request
        .target
        .and_then(|target| target.try_into().ok())
        .filter(|target| *target != [0; 16])
}

fn request_matches_target_facts(
    request: &MemoryV1Request<'_>,
    facts: GovernanceTargetFacts,
    target: BinaryId,
) -> bool {
    let owner_matches = match request.target_owner {
        Some(owner) if facts.owner_user_id != [0; 16] => owner == facts.owner_user_id.as_slice(),
        None if facts.owner_user_id == [0; 16] => true,
        _ => false,
    };
    request.target == Some(target.as_slice())
        && request.target_tenant == Some(facts.tenant_id.as_slice())
        && owner_matches
}

fn one_rule_set(rule_set_id: BinaryId) -> Option<Vec<BinaryId>> {
    (rule_set_id != [0; 16]).then_some(vec![rule_set_id])
}

/// memory—v1: Resolve active rule sets from the complete card read. An empty
/// set is permitted only for an active card with no unremoved bindings.
fn active_card_rule_sets(reader: &RequestRootReader, card_id: BinaryId) -> Option<Vec<BinaryId>> {
    let (card_active, mut targets) = reader
        .read_card_for_evaluation(card_id, |context, _has_binding_history| {
            let card_active = context.card.status
                == astral_authorization_root::memory_v1_db_rows::UserCardStatus::Active;
            (
                card_active,
                context
                    .bindings
                    .iter()
                    .filter(|binding| binding_is_active(binding.binding, Some(context.card)))
                    .map(|binding| binding.binding.rule_set_id)
                    .collect::<Vec<_>>(),
            )
        })
        .ok()?;
    if !card_active {
        return None;
    }
    targets.sort_unstable();
    targets.dedup();
    (!targets.contains(&[0; 16])).then_some(targets)
}

// memory—v1: Validate every unremoved relationship that could become active
// when a disabled card is enabled, even if its confirmation was revoked.
fn disabled_card_rule_sets(
    reader: &RequestRootReader,
    expected: GovernanceTargetFacts,
) -> Option<Vec<BinaryId>> {
    let mut targets = reader
        .read_card_for_evaluation(expected.user_card_id, |context, _history| {
            if expected.user_card_id == [0; 16]
                || expected.owner_user_id == [0; 16]
                || expected.tenant_id == [0; 16]
                || expected.rule_set_id != [0; 16]
                || context.card.user_card_id != expected.user_card_id
                || context.card.user_id != expected.owner_user_id
                || context.card.tenant_id != expected.tenant_id
                || context.card.status != UserCardStatus::Disabled
                || context.user.user_id != expected.owner_user_id
                || context.identity.user_id != expected.owner_user_id
                || context.tenant.tenant_id != expected.tenant_id
            {
                return None;
            }
            context
                .bindings
                .iter()
                .map(|entry| {
                    let binding = entry.binding;
                    let rule_set = entry.rule_set;
                    if binding.binding_id == [0; 16]
                        || binding.user_card_id != expected.user_card_id
                        || binding.removed_at.is_some()
                        || binding.removed_by.is_some()
                        || binding.rule_set_id == [0; 16]
                        || rule_set.rule_set_id != binding.rule_set_id
                        || rule_set.owner_tenant_id != expected.tenant_id
                        || rule_set.status != RuleSetStatus::Active
                    {
                        None
                    } else {
                        Some(rule_set.rule_set_id)
                    }
                })
                .collect::<Option<Vec<_>>>()
        })
        .ok()??;
    targets.sort_unstable();
    targets.dedup();
    Some(targets)
}

// memory—v1: Only registered governance actions may select a target interpretation.
fn target_kind_matches_action(action: &MemoryV1CompoundAction<'_>) -> bool {
    match action.target_kind {
        MemoryV1CompoundTargetKind::BindingCreate => {
            action.request.resource == "binding"
                && matches!(
                    action.request.action,
                    "create" | "confirm" | "create-overlay-only"
                )
                && action.change_intent.is_none()
        }
        MemoryV1CompoundTargetKind::RuleSetCreate => {
            action.request.resource == "rule_set"
                && ((action.request.action == "create" && action.change_intent.is_none())
                    || (action.request.action == "confirm-change"
                        && action.change_intent == Some(MemoryV1RuleSetChangeIntent::Create)))
        }
        MemoryV1CompoundTargetKind::Existing => {
            (action.change_intent.is_none()
                && ((action.request.resource == "binding"
                    && matches!(
                        action.request.action,
                        "confirm" | "remove" | "revoke-confirmation"
                    ))
                    || (action.request.resource == "rule_set"
                        && matches!(action.request.action, "version-publish" | "retire"))))
                || (action.request.resource == "rule_set"
                    && action.request.action == "confirm-change"
                    && action.change_intent == Some(MemoryV1RuleSetChangeIntent::Publish))
        }
        MemoryV1CompoundTargetKind::UserCardCreate => {
            action.request.resource == "user_card"
                && action.request.action == "create"
                && action.change_intent.is_none()
        }
        MemoryV1CompoundTargetKind::UserCardDisable => {
            action.request.resource == "user_card"
                && action.request.action == "disable"
                && action.change_intent.is_none()
        }
        MemoryV1CompoundTargetKind::UserCardEnable => {
            action.request.resource == "user_card"
                && action.request.action == "enable"
                && action.change_intent.is_none()
        }
    }
}

/// memory—v1: Re-resolve the target facts and derive the complete exact-final-check fence
/// set. The supplied facts are only an expected value; they never establish a
/// target fence by themselves.
fn target_rule_sets_for_action(
    reader: &RequestRootReader,
    action: &MemoryV1CompoundAction<'_>,
) -> Option<Vec<BinaryId>> {
    let target = target_id(&action.request)?;
    let expected = match action.target_kind {
        MemoryV1CompoundTargetKind::BindingCreate => reader
            .binding_create_target(
                action.target_facts.user_card_id,
                action.target_facts.rule_set_id,
            )
            .ok()?,
        MemoryV1CompoundTargetKind::RuleSetCreate => reader
            .rule_set_create_target(target, action.target_facts.tenant_id)
            .ok()?,
        MemoryV1CompoundTargetKind::UserCardCreate => reader
            .user_card_create_target(
                target,
                action.target_facts.owner_user_id,
                action.target_facts.tenant_id,
            )
            .ok()?,
        MemoryV1CompoundTargetKind::UserCardDisable
        | MemoryV1CompoundTargetKind::UserCardEnable => reader.user_card_target(target).ok()?,
        MemoryV1CompoundTargetKind::Existing => match (
            action.request.resource,
            action.request.action,
            action.change_intent,
        ) {
            ("binding", "confirm" | "remove", None) => reader.binding_target(target).ok()?,
            ("binding", "revoke-confirmation", None) => reader.confirmation_target(target).ok()?,
            ("rule_set", "retire", None) => reader.rule_set_retirement_target(target).ok()?,
            ("rule_set", "version-publish", None) => reader.active_rule_set_target(target).ok()?,
            ("rule_set", "confirm-change", Some(MemoryV1RuleSetChangeIntent::Publish)) => {
                reader.active_rule_set_target(target).ok()?
            }
            _ => return None,
        },
    };
    if expected != action.target_facts
        || !request_matches_target_facts(&action.request, expected, target)
    {
        return None;
    }
    match action.target_kind {
        MemoryV1CompoundTargetKind::UserCardCreate => Some(Vec::new()),
        MemoryV1CompoundTargetKind::UserCardDisable => {
            active_card_rule_sets(reader, expected.user_card_id)
        }
        MemoryV1CompoundTargetKind::UserCardEnable => disabled_card_rule_sets(reader, expected),
        _ => one_rule_set(expected.rule_set_id),
    }
}

fn merge_draft_dependencies(
    combined: &mut Option<DependencyRecord>,
    draft: &MemoryV1ActionDraft,
) -> bool {
    let source = draft.dependency();
    let Some(existing) = combined else {
        *combined = Some(source.clone());
        return true;
    };
    if existing.card_id != source.card_id
        || existing.instance_id != source.instance_id
        || existing.tenant_tree_version != source.tenant_tree_version
        || existing.registry_version != source.registry_version
    {
        return false;
    }
    for dependency in &source.bindings {
        let existing_index = existing
            .bindings
            .iter()
            .position(|previous| previous.binding_id == dependency.binding_id);
        match existing_index {
            Some(index) if existing.bindings[index] != *dependency => return false,
            Some(_) => {}
            None => existing.bindings.push(dependency.clone()),
        }
    }
    existing
        .bindings
        .sort_unstable_by_key(|dependency| dependency.binding_id);
    true
}

fn normalize_targets(targets: &mut Vec<BinaryId>) -> bool {
    if targets.contains(&[0; 16]) {
        return false;
    }
    targets.sort_unstable();
    targets.dedup();
    valid_target_fences(targets)
}

/// memory—v1: Evaluate all actions in one root phase and perform one final check.
///
/// Each action retains its own rule, scope, SoD, impact, dependency and winning
/// window result. No action is allowed to borrow another action's admission.
/// The final check uses the union of the action dependencies and reader-derived
/// target fences; all collected winning windows must remain valid at one time.
#[allow(clippy::too_many_lines)]
pub(crate) fn evaluate_memory_v1_compound(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    request: &MemoryV1CompoundRequest<'_>,
) -> MemoryV1CompoundEvaluation {
    if request.actions.is_empty() || request.actions.len() > MAX_MEMORY_V1_COMPOUND_ACTIONS {
        return non_allow(
            MemoryV1Decision::Pending,
            None,
            Some(MemoryV1PendingSource::ContextInvalid),
        );
    }
    let first = request.actions[0];
    if !memory_v1_request_is_well_formed(&first.request) {
        return non_allow(
            MemoryV1Decision::Pending,
            None,
            Some(MemoryV1PendingSource::ContextInvalid),
        );
    }
    for action in request.actions {
        if !memory_v1_request_is_well_formed(&action.request)
            || !target_kind_matches_action(action)
            || action.request.target != first.request.target
            || action.request.target_tenant != first.request.target_tenant
            || action.request.target_owner != first.request.target_owner
            || action.target_facts != first.target_facts
            || action.target_kind != first.target_kind
            || action.request.operation_id != first.request.operation_id
            || action.request.operation_fingerprint != first.request.operation_fingerprint
            || action.change_intent.is_some_and(|intent| {
                action.request.resource != "rule_set"
                    || action.request.action != "confirm-change"
                    || !matches!(
                        intent,
                        MemoryV1RuleSetChangeIntent::Create | MemoryV1RuleSetChangeIntent::Publish
                    )
            })
        {
            return non_allow(
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::ContextInvalid),
            );
        }
        if action.request.action == "confirm-change" {
            if action.change_intent.is_none() {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            }
        } else if action.change_intent.is_some() {
            return non_allow(
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::ContextInvalid),
            );
        }
    }

    session
        .with_authoritative_context(root, |facts, reader, final_check| {
            let Some(final_check) = final_check else {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            };
            let Some(start_time) = trusted_now() else {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            };
            let metadata = reader.metadata();
            if metadata.status != RootStatus::Serving || !facts.valid_at(start_time) {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            }

            // Resolve and check every action's actual target before any action
            // uses target attribution for eligibility or separation of duties.
            // A completed earlier window is not treated as an active fence.
            let mut resolved_targets = Vec::with_capacity(request.actions.len());
            for action in request.actions {
                let targets = target_rule_sets_for_action(reader, action);
                if let Some(targets) = &targets {
                    for target in targets {
                        match reader.is_fenced(*target) {
                            Ok(false) => {}
                            Ok(true) => {
                                return non_allow(
                                    MemoryV1Decision::Pending,
                                    None,
                                    Some(MemoryV1PendingSource::FenceActive),
                                );
                            }
                            Err(_) => {
                                return non_allow(
                                    MemoryV1Decision::Pending,
                                    None,
                                    Some(MemoryV1PendingSource::RootUnavailable),
                                );
                            }
                        }
                    }
                }
                resolved_targets.push(targets);
            }

            let mut drafts = Vec::with_capacity(request.actions.len());
            let mut deny_source = None;
            let mut pending_source = None;
            let mut combined_dependency = None;
            let mut future_boundaries = Vec::new();
            let mut winning_windows = Vec::new();
            let mut target_rule_sets = Vec::new();
            for (action, action_targets) in request.actions.iter().zip(resolved_targets) {
                let Some(action_targets) = action_targets else {
                    pending_source.get_or_insert(MemoryV1PendingSource::ContextInvalid);
                    continue;
                };
                target_rule_sets.extend_from_slice(&action_targets);
                let planned = match action.change_intent {
                    Some(intent) => plan_memory_v1_rule_set_change_reader(
                        facts,
                        reader,
                        &action.request,
                        intent,
                        start_time,
                    ),
                    None => plan_memory_v1_action_reader(
                        facts,
                        reader,
                        &action.request,
                        start_time,
                        &action_targets,
                        action.request.resource == "rule_set"
                            && matches!(
                                action.request.action,
                                "create" | "version-publish" | "retire"
                            )
                            && action.target_facts.owner_user_id == [0; 16],
                    ),
                };
                match planned {
                    MemoryV1DraftResult::Allow(draft) => {
                        if draft.root() != metadata
                            || draft.identity() != facts.candidate_identity()
                            || draft.target_rule_sets() != action_targets.as_slice()
                        {
                            pending_source.get_or_insert(MemoryV1PendingSource::ContextInvalid);
                            continue;
                        }
                        if !merge_draft_dependencies(&mut combined_dependency, &draft) {
                            pending_source.get_or_insert(MemoryV1PendingSource::ContextInvalid);
                            continue;
                        }
                        future_boundaries.extend_from_slice(draft.future_boundaries());
                        winning_windows.extend_from_slice(draft.winning_windows());
                        drafts.push(draft);
                    }
                    MemoryV1DraftResult::Deny(source, target) => {
                        if deny_source.is_none() {
                            deny_source = Some((source, action.request, target));
                        }
                    }
                    MemoryV1DraftResult::Pending(source) => {
                        pending_source.get_or_insert(source);
                    }
                }
            }
            if let Some((source, action_request, target)) = deny_source {
                let mut result = non_allow(MemoryV1Decision::Deny, Some(source), None);
                result.deny_observation = match target {
                    MemoryV1DenyTarget::Request => Some(capture_deny_observation(
                        metadata,
                        facts,
                        start_time,
                        &action_request,
                        source,
                        None,
                    )),
                    MemoryV1DenyTarget::AffectedBinding {
                        binding_id,
                        facts: target_facts,
                    } => Some(capture_rule_set_binding_deny_observation(
                        metadata,
                        facts,
                        start_time,
                        &action_request,
                        source,
                        binding_id,
                        target_facts,
                    )),
                    MemoryV1DenyTarget::Unavailable => None,
                };
                return result;
            }
            if let Some(source) = pending_source {
                return non_allow(MemoryV1Decision::Pending, None, Some(source));
            }
            if drafts.len() != request.actions.len() || winning_windows.is_empty() {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            }
            let Some(record) = combined_dependency else {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            };
            let empty_card_disable = target_rule_sets.is_empty()
                && request.actions.iter().all(|action| {
                    action.target_kind == MemoryV1CompoundTargetKind::UserCardDisable
                });
            let empty_card_enable = target_rule_sets.is_empty()
                && request
                    .actions
                    .iter()
                    .all(|action| action.target_kind == MemoryV1CompoundTargetKind::UserCardEnable);
            let empty_card_create = target_rule_sets.is_empty()
                && request
                    .actions
                    .iter()
                    .all(|action| action.target_kind == MemoryV1CompoundTargetKind::UserCardCreate);
            if !empty_card_disable
                && !empty_card_enable
                && !empty_card_create
                && !normalize_targets(&mut target_rule_sets)
            {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            }
            let constraints = FinalCheckTimeConstraints {
                start_time,
                future_boundaries: &future_boundaries,
                winning_windows: &winning_windows,
            };
            #[cfg(test)]
            invoke_after_planning_hook();
            let final_time = if empty_card_disable {
                final_check.try_final_time_exact_empty_card(
                    &record,
                    &constraints,
                    metadata,
                    first.target_facts,
                )
            } else if empty_card_enable {
                final_check.try_final_time_exact_empty_disabled_card(
                    &record,
                    &constraints,
                    metadata,
                    first.target_facts,
                )
            } else if empty_card_create {
                final_check.try_final_time_exact_user_card_create(
                    &record,
                    &constraints,
                    metadata,
                    first.target_facts,
                )
            } else {
                final_check.try_final_time_exact_batch(
                    &record,
                    &constraints,
                    metadata,
                    &target_rule_sets,
                )
            };
            let Some(final_time) = final_time else {
                return non_allow(
                    MemoryV1Decision::Pending,
                    None,
                    Some(MemoryV1PendingSource::ContextInvalid),
                );
            };
            MemoryV1CompoundEvaluation {
                decision: MemoryV1Decision::Allow,
                deny_source: None,
                pending_source: None,
                deny_observation: None,
                admissions: drafts
                    .into_iter()
                    .map(|draft| (*draft).into_admission(final_time))
                    .collect(),
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

// The compound result deliberately carries only admissions. It does not expose
// a mutation, CAS, audit, replay, or commit capability.

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::process::Command;
    use std::rc::Rc;

    use astral_authorization_root::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
        IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
        UserCardRow, UserCardStatus, UserRow,
    };
    use astral_authorization_root::memory_v1_fence::FenceDeclaration;
    use astral_authorization_root::memory_v1_hamt::CandidateBudget;
    use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
    use astral_authorization_root::memory_v1_request::RequestRootScope;
    use astral_authorization_root::memory_v1_root::{
        install_process_root, ManagementMutationV2, MutationPrecondition,
    };
    use astral_authorization_root::memory_v1_rules::{
        canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
    };
    use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
    use astral_types::memory_v1::{CandidateIdentity, MemoryId};

    const DRIFT_CHILD: &str = "ASTRAL_COMPOUND_DRIFT_2_CHILD";

    fn id(value: u8) -> [u8; 16] {
        [value; 16]
    }

    fn version(rule_set_id: u8, content: &[u8]) -> RuleSetVersionRow {
        let version_bytes = vec![1];
        let timestamp_bytes = vec![2];
        let hash_input_bytes = canonical_version_bytes(&version_bytes, content, &timestamp_bytes);
        RuleSetVersionRow {
            rule_set_id: id(rule_set_id),
            version_bytes,
            content_bytes: content.to_vec(),
            timestamp_bytes,
            hash_bytes: version_digest(&hash_input_bytes),
            hash_input_bytes,
        }
    }

    // memory—v1: Each isolated scenario plans once, then injects an authority drift.
    fn post_planning_drift(scenario: &'static str, test_name: &str) {
        if std::env::var_os(DRIFT_CHILD).is_none() {
            let output = Command::new(std::env::current_exe().expect("test executable"))
                .args(["--exact", test_name, "--nocapture"])
                .env(DRIFT_CHILD, scenario)
                .output()
                .expect("start isolated drift test");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success() && stdout.contains("1 passed; 0 failed; 0 ignored"),
                "isolated {scenario} failed: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                output.status
            );
            return;
        }
        assert_eq!(std::env::var(DRIFT_CHILD).as_deref(), Ok(scenario));

        let content = br#"{"rules":[{"ruleId":"create","resource":"binding","action":"create","effect":"ALLOW","ownerScope":"all","tenantScope":"self"},{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all","tenantScope":"self"},{"ruleId":"disable","resource":"user_card","action":"disable","effect":"ALLOW","ownerScope":"all","tenantScope":"self"},{"ruleId":"enable","resource":"user_card","action":"enable","effect":"ALLOW","ownerScope":"all","tenantScope":"self"},{"ruleId":"create-card","resource":"user_card","action":"create","effect":"ALLOW","ownerScope":"all","tenantScope":"self"},{"ruleId":"retire","resource":"rule_set","action":"retire","effect":"ALLOW","ownerScope":"all","tenantScope":"self"}]}"#;
        let without_retire = br#"{"rules":[{"ruleId":"update","resource":"rule_set","action":"update","effect":"ALLOW","ownerScope":"all","tenantScope":"self"}]}"#;
        let rows = CandidateRows {
            users: vec![
                UserRow { user_id: id(1) },
                UserRow { user_id: id(2) },
                UserRow { user_id: id(5) },
                UserRow { user_id: id(7) },
            ],
            identity_cards: vec![
                IdentityCardRow {
                    identity_card_id: id(3),
                    user_id: id(1),
                },
                IdentityCardRow {
                    identity_card_id: id(4),
                    user_id: id(2),
                },
                IdentityCardRow {
                    identity_card_id: id(6),
                    user_id: id(5),
                },
                IdentityCardRow {
                    identity_card_id: id(8),
                    user_id: id(7),
                },
            ],
            tenants: vec![TenantRow {
                tenant_id: id(10),
                parent_tenant_id: None,
            }],
            user_cards: vec![
                UserCardRow {
                    user_card_id: id(20),
                    user_id: id(1),
                    tenant_id: id(10),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(21),
                    user_id: id(2),
                    tenant_id: id(10),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(22),
                    user_id: id(2),
                    tenant_id: id(10),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(23),
                    user_id: id(2),
                    tenant_id: id(10),
                    status: UserCardStatus::Disabled,
                },
                UserCardRow {
                    user_card_id: id(24),
                    user_id: id(2),
                    tenant_id: id(10),
                    status: UserCardStatus::Disabled,
                },
                UserCardRow {
                    user_card_id: id(25),
                    user_id: id(2),
                    tenant_id: id(10),
                    status: UserCardStatus::Disabled,
                },
                UserCardRow {
                    user_card_id: id(26),
                    user_id: id(7),
                    tenant_id: id(10),
                    status: UserCardStatus::Disabled,
                },
            ],
            rule_sets: vec![
                RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: id(30),
                    owner_tenant_id: id(10),
                    current_version_bytes: vec![1],
                },
                RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: id(31),
                    owner_tenant_id: id(10),
                    current_version_bytes: vec![1],
                },
                RuleSetRow {
                    status: RuleSetStatus::Retired,
                    rule_set_id: id(32),
                    owner_tenant_id: id(10),
                    current_version_bytes: vec![1],
                },
            ],
            rule_set_versions: vec![
                version(30, content),
                version(31, without_retire),
                version(32, without_retire),
            ],
            bindings: vec![
                BindingRow {
                    binding_id: id(40),
                    user_card_id: id(20),
                    rule_set_id: id(30),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::AllUsers,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(41),
                    user_card_id: id(22),
                    rule_set_id: id(31),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::AllUsers,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(43),
                    user_card_id: id(24),
                    rule_set_id: id(30),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::AllUsers,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(44),
                    user_card_id: id(24),
                    rule_set_id: id(31),
                    binding_layer: BindingLayer::Overlay,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::AllUsers,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(45),
                    user_card_id: id(25),
                    rule_set_id: id(32),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::AllUsers,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(46),
                    user_card_id: id(23),
                    rule_set_id: id(32),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::AllUsers,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: Some(1),
                    removed_by: Some(id(1)),
                },
            ],
            binding_confirmations: vec![
                BindingConfirmationRow {
                    confirmation_id: id(50),
                    binding_id: id(40),
                    rule_set_id: id(30),
                    version_bytes: vec![1],
                    confirmer_user_id: id(2),
                    scope_bytes: vec![1],
                    operation_id: vec![50],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
                BindingConfirmationRow {
                    confirmation_id: id(51),
                    binding_id: id(41),
                    rule_set_id: id(31),
                    version_bytes: vec![1],
                    confirmer_user_id: id(1),
                    scope_bytes: vec![1],
                    operation_id: vec![51],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
                BindingConfirmationRow {
                    confirmation_id: id(53),
                    binding_id: id(43),
                    rule_set_id: id(30),
                    version_bytes: vec![1],
                    confirmer_user_id: id(1),
                    scope_bytes: vec![1],
                    operation_id: vec![53],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
                BindingConfirmationRow {
                    confirmation_id: id(54),
                    binding_id: id(44),
                    rule_set_id: id(31),
                    version_bytes: vec![1],
                    confirmer_user_id: id(1),
                    scope_bytes: vec![1],
                    operation_id: vec![54],
                    confirmed_at_bytes: vec![1],
                    revoked_at: Some(1),
                    revoked_by: Some(id(1)),
                },
                BindingConfirmationRow {
                    confirmation_id: id(55),
                    binding_id: id(45),
                    rule_set_id: id(32),
                    version_bytes: vec![1],
                    confirmer_user_id: id(1),
                    scope_bytes: vec![1],
                    operation_id: vec![55],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
            ],
            rule_set_change_confirmations: [30, 31, 32]
                .into_iter()
                .map(|rule_set_id| RuleSetChangeConfirmationRow {
                    confirmation_id: id(rule_set_id + 30),
                    rule_set_id: id(rule_set_id),
                    version_bytes: vec![1],
                    confirmer_user_id: id(2),
                    affected_scope_bytes: vec![1],
                    operation_id: vec![rule_set_id + 30],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                })
                .collect(),
        };
        let owner = install_process_root(
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
                CurrentSelection {
                    rule_set_id: id(32),
                    version_bytes: vec![1],
                },
            ],
            CandidateBudget {
                max_table_rows: 128,
                max_bindings_per_read: 16,
            },
        )
        .expect("install isolated root");
        owner
            .install_registry(&[
                RegistryDeclaration {
                    resource: "binding".to_owned(),
                    actions: vec!["create".to_owned(), "confirm".to_owned()],
                },
                RegistryDeclaration {
                    resource: "user_card".to_owned(),
                    actions: vec![
                        "disable".to_owned(),
                        "enable".to_owned(),
                        "create".to_owned(),
                    ],
                },
                RegistryDeclaration {
                    resource: "rule_set".to_owned(),
                    actions: vec!["retire".to_owned(), "update".to_owned()],
                },
                RegistryDeclaration {
                    resource: "other".to_owned(),
                    actions: vec!["read".to_owned()],
                },
            ])
            .expect("install registry");
        owner
            .adopt_serving_for_isolated_tests()
            .expect("adopt test root");
        let authority = MemoryV1SessionAuthority::new();
        authority
            .bind_to_root(&owner)
            .expect("bind session authority");
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let identity = CandidateIdentity {
            user_id: MemoryId::from_bytes(id(1)),
            identity_card_id: MemoryId::from_bytes(id(3)),
            user_card_id: MemoryId::from_bytes(id(20)),
            tenant_id: MemoryId::from_bytes(id(10)),
        };
        let now = trusted_now().expect("trusted clock");
        let issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(identity, now - 60, 3_600)
            .expect("issue session");
        let credential = issued.credential().to_owned();
        let session = authority
            .verifier()
            .verify_and_bind(&credential, now, &root)
            .expect("bind session");
        let facts = root
            .with_reader(|reader| reader.binding_create_target(id(21), id(31)))
            .expect("read root")
            .expect("target facts");
        let target = id(70);
        let tenant = id(10);
        let beneficiary = id(2);
        let action = |name| MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "binding",
                action: name,
                target: Some(&target),
                target_tenant: Some(&tenant),
                target_owner: Some(&beneficiary),
                operation_id: b"compound-drift-2",
                operation_fingerprint: b"compound-drift-2-fingerprint",
            },
            change_intent: None,
            target_facts: facts,
            target_kind: MemoryV1CompoundTargetKind::BindingCreate,
        };
        let actions = [action("create"), action("confirm")];
        let card_target = id(21);
        let card_facts = root
            .with_reader(|reader| reader.user_card_target(card_target))
            .unwrap()
            .unwrap();
        let disable_actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "user_card",
                action: "disable",
                target: Some(&card_target),
                target_tenant: Some(&tenant),
                target_owner: Some(&beneficiary),
                operation_id: b"empty-card-drift",
                operation_fingerprint: b"empty-card-drift-fingerprint",
            },
            change_intent: None,
            target_facts: card_facts,
            target_kind: MemoryV1CompoundTargetKind::UserCardDisable,
        }];
        let retire_target = id(31);
        let retire_facts = root
            .with_reader(|reader| reader.rule_set_target(retire_target))
            .unwrap()
            .unwrap();
        let retire_actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "rule_set",
                action: "retire",
                target: Some(&retire_target),
                target_tenant: Some(&tenant),
                target_owner: None,
                operation_id: b"retire-drift",
                operation_fingerprint: b"retire-drift-fingerprint",
            },
            change_intent: None,
            target_facts: retire_facts,
            target_kind: MemoryV1CompoundTargetKind::Existing,
        }];
        let is_empty_card = scenario.starts_with("empty-");
        let is_retire = scenario.starts_with("retire-");
        let is_enable = scenario.starts_with("enable-");
        let is_card_create = scenario.starts_with("card-create-");
        let new_card_id = id(75);
        let new_card_facts = root
            .with_reader(|reader| reader.user_card_create_target(new_card_id, beneficiary, tenant))
            .unwrap()
            .unwrap();
        let card_create_actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "user_card",
                action: "create",
                target: Some(&new_card_id),
                target_tenant: Some(&tenant),
                target_owner: Some(&beneficiary),
                operation_id: b"card-create-drift",
                operation_fingerprint: b"card-create-drift-fingerprint",
            },
            change_intent: None,
            target_facts: new_card_facts,
            target_kind: MemoryV1CompoundTargetKind::UserCardCreate,
        }];
        let enable_target = if scenario.starts_with("enable-empty-") {
            id(23)
        } else {
            id(24)
        };
        let enable_facts = root
            .with_reader(|reader| reader.user_card_target(enable_target))
            .unwrap()
            .unwrap();
        let enable_actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "user_card",
                action: "enable",
                target: Some(&enable_target),
                target_tenant: Some(&tenant),
                target_owner: Some(&beneficiary),
                operation_id: b"enable-drift",
                operation_fingerprint: b"enable-drift-fingerprint",
            },
            change_intent: None,
            target_facts: enable_facts,
            target_kind: MemoryV1CompoundTargetKind::UserCardEnable,
        }];
        let request = MemoryV1CompoundRequest {
            actions: if is_empty_card {
                &disable_actions
            } else if is_retire {
                &retire_actions
            } else if is_enable {
                &enable_actions
            } else if is_card_create {
                &card_create_actions
            } else {
                &actions
            },
        };
        let baseline_hook = Rc::new(Cell::new(0));
        let baseline_observed = Rc::clone(&baseline_hook);
        let baseline = with_after_planning_hook(
            move || baseline_observed.set(baseline_observed.get() + 1),
            || evaluate_memory_v1_compound(&root, &session, &request),
        );
        assert_eq!(baseline_hook.get(), 1, "baseline completed all planning");
        assert_eq!(baseline.decision, MemoryV1Decision::Allow);
        assert_eq!(baseline.admissions.len(), request.actions.len());
        if is_retire {
            let admission = &baseline.admissions[0];
            assert_eq!(admission.action(), "retire");
            assert_eq!(admission.target(), Some(retire_target.as_slice()));
            assert_eq!(admission.operation_id(), b"retire-drift");
            assert_eq!(
                admission.operation_fingerprint(),
                b"retire-drift-fingerprint"
            );
            let wrong_tenant = id(99);
            let wrong_target = id(30);
            for bad_request in [
                MemoryV1Request {
                    target_tenant: Some(&wrong_tenant),
                    ..retire_actions[0].request
                },
                MemoryV1Request {
                    target: Some(&wrong_target),
                    ..retire_actions[0].request
                },
            ] {
                let bad = [MemoryV1CompoundAction {
                    request: bad_request,
                    ..retire_actions[0]
                }];
                let result = evaluate_memory_v1_compound(
                    &root,
                    &session,
                    &MemoryV1CompoundRequest { actions: &bad },
                );
                assert_ne!(result.decision, MemoryV1Decision::Allow);
                assert!(result.admissions.is_empty());
            }
            let other_identity = CandidateIdentity {
                user_id: MemoryId::from_bytes(id(2)),
                identity_card_id: MemoryId::from_bytes(id(4)),
                user_card_id: MemoryId::from_bytes(id(22)),
                tenant_id: MemoryId::from_bytes(tenant),
            };
            let other_issued = authority
                .identity_session_adapter()
                .issue_unchecked_for_test(other_identity, now - 60, 3_600)
                .unwrap();
            let other_session = authority
                .verifier()
                .verify_and_bind(other_issued.credential(), now, &root)
                .unwrap();
            let result = evaluate_memory_v1_compound(&root, &other_session, &request);
            assert_ne!(result.decision, MemoryV1Decision::Allow);
            assert!(result.admissions.is_empty());
        }
        if is_enable {
            assert_eq!(baseline.admissions[0].action(), "enable");
            assert_eq!(
                baseline.admissions[0].target(),
                Some(enable_target.as_slice())
            );
            assert_eq!(baseline.admissions[0].operation_id(), b"enable-drift");
            let targets = root
                .with_reader(|reader| disabled_card_rule_sets(reader, enable_facts))
                .unwrap()
                .unwrap();
            if enable_target == id(23) {
                assert!(targets.is_empty());
            } else {
                assert_eq!(targets, vec![id(30), id(31)]);
            }
            let bad_tenant = id(99);
            let bad_target = id(21);
            for bad_request in [
                MemoryV1Request {
                    target_tenant: Some(&bad_tenant),
                    ..enable_actions[0].request
                },
                MemoryV1Request {
                    target: Some(&bad_target),
                    ..enable_actions[0].request
                },
            ] {
                let bad = [MemoryV1CompoundAction {
                    request: bad_request,
                    ..enable_actions[0]
                }];
                assert_ne!(
                    evaluate_memory_v1_compound(
                        &root,
                        &session,
                        &MemoryV1CompoundRequest { actions: &bad }
                    )
                    .decision,
                    MemoryV1Decision::Allow
                );
            }
            let active_facts = root
                .with_reader(|reader| reader.user_card_target(bad_target))
                .unwrap()
                .unwrap();
            let active = [MemoryV1CompoundAction {
                request: MemoryV1Request {
                    target: Some(&bad_target),
                    ..enable_actions[0].request
                },
                target_facts: active_facts,
                ..enable_actions[0]
            }];
            assert_ne!(
                evaluate_memory_v1_compound(
                    &root,
                    &session,
                    &MemoryV1CompoundRequest { actions: &active }
                )
                .decision,
                MemoryV1Decision::Allow
            );
            let wrong_action = [MemoryV1CompoundAction {
                request: MemoryV1Request {
                    action: "disable",
                    ..enable_actions[0].request
                },
                ..enable_actions[0]
            }];
            assert_ne!(
                evaluate_memory_v1_compound(
                    &root,
                    &session,
                    &MemoryV1CompoundRequest {
                        actions: &wrong_action
                    }
                )
                .decision,
                MemoryV1Decision::Allow
            );
            let retired_target = id(25);
            let retired_facts = root
                .with_reader(|reader| reader.user_card_target(retired_target))
                .unwrap()
                .unwrap();
            let retired = [MemoryV1CompoundAction {
                request: MemoryV1Request {
                    target: Some(&retired_target),
                    ..enable_actions[0].request
                },
                target_facts: retired_facts,
                ..enable_actions[0]
            }];
            assert_ne!(
                evaluate_memory_v1_compound(
                    &root,
                    &session,
                    &MemoryV1CompoundRequest { actions: &retired }
                )
                .decision,
                MemoryV1Decision::Allow
            );
            let other_identity = CandidateIdentity {
                user_id: MemoryId::from_bytes(id(2)),
                identity_card_id: MemoryId::from_bytes(id(4)),
                user_card_id: MemoryId::from_bytes(id(22)),
                tenant_id: MemoryId::from_bytes(tenant),
            };
            let other_issued = authority
                .identity_session_adapter()
                .issue_unchecked_for_test(other_identity, now - 60, 3_600)
                .unwrap();
            let other_session = authority
                .verifier()
                .verify_and_bind(other_issued.credential(), now, &root)
                .unwrap();
            assert_ne!(
                evaluate_memory_v1_compound(&root, &other_session, &request).decision,
                MemoryV1Decision::Allow
            );
        }
        if is_card_create {
            let admission = &baseline.admissions[0];
            assert_eq!(admission.action(), "create");
            assert_eq!(admission.target(), Some(new_card_id.as_slice()));
            assert_eq!(admission.target_owner(), Some(beneficiary.as_slice()));
            assert_eq!(admission.target_tenant(), Some(tenant.as_slice()));
            assert_eq!(admission.operation_id(), b"card-create-drift");
            assert_eq!(
                admission.operation_fingerprint(),
                b"card-create-drift-fingerprint"
            );
            let wrong_tenant = id(99);
            let wrong_owner = id(1);
            let other_target = id(76);
            for bad_request in [
                MemoryV1Request {
                    target_tenant: Some(&wrong_tenant),
                    ..card_create_actions[0].request
                },
                MemoryV1Request {
                    target_owner: Some(&wrong_owner),
                    ..card_create_actions[0].request
                },
                MemoryV1Request {
                    target: Some(&other_target),
                    ..card_create_actions[0].request
                },
            ] {
                let bad = [MemoryV1CompoundAction {
                    request: bad_request,
                    ..card_create_actions[0]
                }];
                let evaluation = evaluate_memory_v1_compound(
                    &root,
                    &session,
                    &MemoryV1CompoundRequest { actions: &bad },
                );
                assert_ne!(evaluation.decision, MemoryV1Decision::Allow);
                assert!(evaluation.admissions.is_empty());
            }
            root.with_reader(|reader| {
                assert!(reader
                    .user_card_create_target(id(20), beneficiary, tenant)
                    .is_err());
                assert!(reader
                    .user_card_create_target(id(76), beneficiary, wrong_tenant)
                    .is_err());
                assert!(reader
                    .user_card_create_target(id(76), id(5), tenant)
                    .is_err());
                assert!(reader
                    .user_card_create_target(id(76), id(99), tenant)
                    .is_err());
            })
            .unwrap();
            // memory—v1: Disabled history proves only a user/tenant relationship.
            let disabled_owner = id(7);
            let disabled_target = id(77);
            let disabled_facts = root
                .with_reader(|reader| {
                    reader.user_card_create_target(disabled_target, disabled_owner, tenant)
                })
                .unwrap()
                .unwrap();
            let disabled_history_action = [MemoryV1CompoundAction {
                request: MemoryV1Request {
                    target: Some(&disabled_target),
                    target_owner: Some(&disabled_owner),
                    ..card_create_actions[0].request
                },
                target_facts: disabled_facts,
                ..card_create_actions[0]
            }];
            let disabled_history = evaluate_memory_v1_compound(
                &root,
                &session,
                &MemoryV1CompoundRequest {
                    actions: &disabled_history_action,
                },
            );
            assert_eq!(disabled_history.decision, MemoryV1Decision::Allow);
            assert_eq!(disabled_history.admissions.len(), 1);
            let other_identity = CandidateIdentity {
                user_id: MemoryId::from_bytes(id(2)),
                identity_card_id: MemoryId::from_bytes(id(4)),
                user_card_id: MemoryId::from_bytes(id(22)),
                tenant_id: MemoryId::from_bytes(tenant),
            };
            let other_issued = authority
                .identity_session_adapter()
                .issue_unchecked_for_test(other_identity, now - 60, 3_600)
                .unwrap();
            let other_session = authority
                .verifier()
                .verify_and_bind(other_issued.credential(), now, &root)
                .unwrap();
            let evaluation = evaluate_memory_v1_compound(&root, &other_session, &request);
            assert_ne!(evaluation.decision, MemoryV1Decision::Allow);
            assert!(evaluation.admissions.is_empty());
        }
        if !is_empty_card && !is_retire && !is_enable && !is_card_create {
            assert_eq!(
                baseline.admissions[0].trusted_time_unix_seconds(),
                baseline.admissions[1].trusted_time_unix_seconds()
            );
        }

        let observed = Rc::new(Cell::new(0));
        let hook_observed = Rc::clone(&observed);
        let result = with_after_planning_hook(
            move || {
                hook_observed.set(hook_observed.get() + 1);
                match scenario {
                    "session" | "card-create-session" => authority
                        .identity_session_adapter()
                        .revoke(&credential)
                        .expect("revoke live session"),
                    "fence" | "retire-fence" | "enable-fence" => {
                        let metadata = owner.handle().metadata().expect("root metadata");
                        owner
                            .begin_modification_fence(
                                id(31),
                                &FenceDeclaration {
                                    rule_set_version: vec![1],
                                    root_version: metadata.version,
                                    digest: metadata.digest,
                                },
                            )
                            .expect("open target fence");
                    }
                    "registry" => {
                        let before = owner.registry_version();
                        owner
                            .request_registry_retirement_for_test("other")
                            .expect("change unrelated registry entry");
                        assert!(owner.registry_version() > before);
                    }
                    "root" | "retire-root" | "enable-root" | "enable-empty-root"
                    | "card-create-root" => {
                        let before = owner.handle().metadata().expect("root metadata");
                        let after = owner
                            .execute_mutation_with_precondition_for_isolated_tests(
                                &ManagementMutationV2::BindingRemove {
                                    binding_id: id(41),
                                    removed_at: now,
                                    removed_by: id(1),
                                },
                                &MutationPrecondition {
                                    evaluated_root_version: before.version,
                                },
                            )
                            .expect("publish unrelated binding removal");
                        assert!(after.version > before.version);
                        assert_ne!(after.digest, before.digest);
                    }
                    "empty-binding" => {
                        let before = owner.handle().metadata().unwrap();
                        owner
                            .execute_mutation_with_precondition_for_isolated_tests(
                                &ManagementMutationV2::BindingCreate {
                                    row: BindingRow {
                                        binding_id: id(42),
                                        user_card_id: id(21),
                                        rule_set_id: id(31),
                                        binding_layer: BindingLayer::Base,
                                        valid_from: None,
                                        valid_until: None,
                                        owner_scope: MemoryV1OwnerScope::AllUsers,
                                        tenant_scope: MemoryV1TenantScope::SelfTenant,
                                        removed_at: None,
                                        removed_by: None,
                                    },
                                    confirmation: BindingConfirmationRow {
                                        confirmation_id: id(52),
                                        binding_id: id(42),
                                        rule_set_id: id(31),
                                        version_bytes: vec![1],
                                        confirmer_user_id: id(1),
                                        scope_bytes: vec![1],
                                        operation_id: vec![52],
                                        confirmed_at_bytes: vec![1],
                                        revoked_at: None,
                                        revoked_by: None,
                                    },
                                },
                                &MutationPrecondition {
                                    evaluated_root_version: before.version,
                                },
                            )
                            .expect("publish target binding");
                    }
                    "empty-status" => {
                        let before = owner.handle().metadata().unwrap();
                        authority
                            .disable_card_with_sessions_for_isolated_tests(
                                &owner.mutation_executor(),
                                MemoryId::from_bytes(id(21)),
                                before,
                            )
                            .expect("disable target card");
                    }
                    "empty-fence" | "card-create-fence" => {
                        let metadata = owner.handle().metadata().unwrap();
                        owner
                            .begin_modification_fence(
                                id(30),
                                &FenceDeclaration {
                                    rule_set_version: vec![1],
                                    root_version: metadata.version,
                                    digest: metadata.digest,
                                },
                            )
                            .expect("open actor fence");
                    }
                    _ => panic!("unknown drift scenario"),
                }
            },
            || evaluate_memory_v1_compound(&root, &session, &request),
        );
        assert_eq!(
            observed.get(),
            1,
            "drift occurred after every action was planned"
        );
        assert_eq!(result.decision, MemoryV1Decision::Pending);
        assert_eq!(
            result.pending_source,
            Some(MemoryV1PendingSource::ContextInvalid)
        );
        assert!(result.admissions.is_empty());
    }

    #[test]
    fn post_planning_session_revoke_is_pending() {
        post_planning_drift(
            "session",
            "memory_v1_compound::tests::post_planning_session_revoke_is_pending",
        );
    }

    #[test]
    fn post_planning_target_fence_is_pending() {
        post_planning_drift(
            "fence",
            "memory_v1_compound::tests::post_planning_target_fence_is_pending",
        );
    }

    #[test]
    fn post_planning_registry_drift_is_pending() {
        post_planning_drift(
            "registry",
            "memory_v1_compound::tests::post_planning_registry_drift_is_pending",
        );
    }

    #[test]
    fn post_planning_root_drift_is_pending() {
        post_planning_drift(
            "root",
            "memory_v1_compound::tests::post_planning_root_drift_is_pending",
        );
    }

    #[test]
    // memory—v1: A target binding added after planning invalidates the empty proof.
    fn empty_card_binding_drift_is_pending() {
        post_planning_drift(
            "empty-binding",
            "memory_v1_compound::tests::empty_card_binding_drift_is_pending",
        );
    }

    #[test]
    // memory—v1: A target status change after planning invalidates the empty proof.
    fn empty_card_status_drift_is_pending() {
        post_planning_drift(
            "empty-status",
            "memory_v1_compound::tests::empty_card_status_drift_is_pending",
        );
    }

    #[test]
    // memory—v1: An actor fence opening after planning prevents an admission.
    fn empty_card_actor_fence_drift_is_pending() {
        post_planning_drift(
            "empty-fence",
            "memory_v1_compound::tests::empty_card_actor_fence_drift_is_pending",
        );
    }

    // memory—v1: A new target fence invalidates a retirement admission.
    #[test]
    fn retire_target_fence_drift_is_pending() {
        post_planning_drift(
            "retire-fence",
            "memory_v1_compound::tests::retire_target_fence_drift_is_pending",
        );
    }

    // memory—v1: A target binding change invalidates a retirement admission.
    #[test]
    fn retire_target_binding_drift_is_pending() {
        post_planning_drift(
            "retire-root",
            "memory_v1_compound::tests::retire_target_binding_drift_is_pending",
        );
    }

    // memory—v1: Opening a fence on a revoked relationship still blocks enable.
    #[test]
    fn enable_target_fence_drift_is_pending() {
        post_planning_drift(
            "enable-fence",
            "memory_v1_compound::tests::enable_target_fence_drift_is_pending",
        );
    }

    // memory—v1: Exact-root checking rejects drift for populated disabled cards.
    #[test]
    fn enable_target_root_drift_is_pending() {
        post_planning_drift(
            "enable-root",
            "memory_v1_compound::tests::enable_target_root_drift_is_pending",
        );
    }

    // memory—v1: Empty disabled cards use their dedicated exact-root recheck.
    #[test]
    fn enable_empty_target_root_drift_is_pending() {
        post_planning_drift(
            "enable-empty-root",
            "memory_v1_compound::tests::enable_empty_target_root_drift_is_pending",
        );
    }

    // memory—v1: A new-card admission is invalidated by session revocation.
    #[test]
    fn card_create_session_drift_is_pending() {
        post_planning_drift(
            "card-create-session",
            "memory_v1_compound::tests::card_create_session_drift_is_pending",
        );
    }

    // memory—v1: An actor rule-set fence prevents a new-card admission.
    #[test]
    fn card_create_actor_fence_drift_is_pending() {
        post_planning_drift(
            "card-create-fence",
            "memory_v1_compound::tests::card_create_actor_fence_drift_is_pending",
        );
    }

    // memory—v1: A changed root invalidates the observed creation candidate.
    #[test]
    fn card_create_root_drift_is_pending() {
        post_planning_drift(
            "card-create-root",
            "memory_v1_compound::tests::card_create_root_drift_is_pending",
        );
    }

    #[test]
    fn compound_rejects_zero_or_missing_fence_facts() {
        let facts = GovernanceTargetFacts {
            user_card_id: [0; 16],
            rule_set_id: [0; 16],
            owner_user_id: [0; 16],
            tenant_id: [1; 16],
        };
        assert!(!valid_target_fences(&[]));
        assert!(one_rule_set(facts.rule_set_id).is_none());
    }
}
