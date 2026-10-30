//! CURRENT V6 formal authorization evaluation.
//!
//! Every unmanaged card-scope decision consumes strict published evidence; managed
//! ORG_SCOPE decisions use their own published authority proof. No legacy snapshot,
//! raw-source, or consistency-oracle evaluator is reachable from this module.

use crate::hit_stats::TimingBreakdown;
use astral_types::registry::build_resource_key;
use astral_types::{
    GlobalAccessRequirement, PolicyContext, PolicyDecision, ResourceOwnershipScope,
};

use super::decision::*;
use super::ports::RuleRepository;
use super::published::*;
use super::PolicyEngine;

impl PolicyEngine {
    /// Evaluate one request through the CURRENT V6 authorization contract.
    ///
    /// The ordered gates are AUTHN → CARD_CONTEXT → target ownership →
    /// GlobalAdmin (when required) → ORG_SCOPE admission (when managed) →
    /// published CARD evidence. Every failed or unavailable authority proof denies.
    pub async fn evaluate<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        let start = std::time::Instant::now();
        let mut steps = Vec::new();
        let mut timing = TimingBreakdown::default();

        if let Some(fallback) = self.check_circuit_breaker(ctx) {
            return fallback;
        }

        let decision: PolicyDecision = 'evaluation: {
            if ctx.user_id.is_none() {
                steps.push(step("AUTHN", "DENY", "no user context", None));
                self.finish_evaluation(false, &mut timing, start, false, ctx.resource.as_deref());
                break 'evaluation deny("AUTHN_REQUIRED", "authn", steps);
            }
            steps.push(step(
                "AUTHN",
                "PASS",
                &format!("userId={}", ctx.user_id.unwrap()),
                None,
            ));

            let Some(card_id) = ctx.card_id else {
                steps.push(step("AUTHN", "DENY", "no card selected", None));
                self.finish_evaluation(false, &mut timing, start, false, ctx.resource.as_deref());
                break 'evaluation deny("CARD_REQUIRED", "no-card-selected", steps);
            };

            let card_check_start = std::time::Instant::now();
            match repo.check_card_active(ctx).await {
                Ok(true) => {}
                Ok(false) => {
                    timing.card_context_check_ns = card_check_start.elapsed().as_nanos() as u64;
                    steps.push(step(
                        "CARD_CONTEXT",
                        "DENY",
                        &format!("Card {card_id} is inactive or context mismatch"),
                        None,
                    ));
                    self.finish_evaluation(
                        false,
                        &mut timing,
                        start,
                        false,
                        ctx.resource.as_deref(),
                    );
                    break 'evaluation deny(
                        "CARD_DISABLED",
                        &format!("card:{card_id}:disabled"),
                        steps,
                    );
                }
                Err(error) => {
                    tracing::warn!(card_id, error = %error, "card context dependency unavailable");
                    timing.card_context_check_ns = card_check_start.elapsed().as_nanos() as u64;
                    steps.push(step(
                        "CARD_CONTEXT",
                        "DENY",
                        "card context dependency unavailable",
                        None,
                    ));
                    self.finish_evaluation(
                        false,
                        &mut timing,
                        start,
                        true,
                        ctx.resource.as_deref(),
                    );
                    break 'evaluation deny(
                        "DEPENDENCY_UNAVAILABLE",
                        &format!("card:{card_id}:unavailable"),
                        steps,
                    );
                }
            }
            timing.card_context_check_ns = card_check_start.elapsed().as_nanos() as u64;
            steps.push(step("CARD_CONTEXT", "PASS", "card active", None));

            if ctx.resource.as_deref().is_none_or(str::is_empty) {
                steps.push(step("AUTHN", "DENY", "no resource", None));
                self.finish_evaluation(false, &mut timing, start, false, ctx.resource.as_deref());
                break 'evaluation deny("RESOURCE_REQUIRED", "no-resource", steps);
            }
            if ctx.action.is_empty() {
                steps.push(step("AUTHN", "DENY", "no action", None));
                self.finish_evaluation(false, &mut timing, start, false, ctx.resource.as_deref());
                break 'evaluation deny("ACTION_REQUIRED", "no-action", steps);
            }

            // Gateway identity does not establish ownership of the protected target.
            // A target classified as unresolved or unavailable always fails closed.
            match ctx.resource_ownership_scope {
                ResourceOwnershipScope::Internal => {}
                ResourceOwnershipScope::TenantScoped => {
                    if ctx
                        .resource_tenant_id
                        .is_none_or(|tenant_id| tenant_id <= 0)
                        || ctx
                            .resource_domain_id
                            .is_some_and(|domain_id| domain_id <= 0)
                        || ctx.resource_owner_id.is_some_and(|owner_id| owner_id <= 0)
                    {
                        steps.push(step(
                            "RESOURCE_OWNERSHIP",
                            "DENY",
                            "tenant-scoped target carried invalid authoritative facts",
                            None,
                        ));
                        self.finish_evaluation(
                            false,
                            &mut timing,
                            start,
                            false,
                            ctx.resource.as_deref(),
                        );
                        break 'evaluation deny(
                            "AUTHORIZATION_PENDING",
                            "resource_ownership:invalid_tenant_scope",
                            steps,
                        );
                    }
                }
                ResourceOwnershipScope::Global => {
                    if ctx.resource_tenant_id.is_some()
                        || ctx.resource_domain_id.is_some()
                        || ctx.resource_owner_id.is_some()
                    {
                        steps.push(step(
                            "RESOURCE_OWNERSHIP",
                            "DENY",
                            "global target carried tenant or owner facts",
                            None,
                        ));
                        self.finish_evaluation(
                            false,
                            &mut timing,
                            start,
                            false,
                            ctx.resource.as_deref(),
                        );
                        break 'evaluation deny(
                            "AUTHORIZATION_PENDING",
                            "resource_ownership:invalid_global_scope",
                            steps,
                        );
                    }

                    match ctx.global_access_requirement {
                        GlobalAccessRequirement::Unspecified => {
                            steps.push(step(
                                "RESOURCE_OWNERSHIP",
                                "DENY",
                                "global target omitted its resolver access contract",
                                None,
                            ));
                            self.finish_evaluation(
                                false,
                                &mut timing,
                                start,
                                false,
                                ctx.resource.as_deref(),
                            );
                            break 'evaluation deny(
                                "AUTHORIZATION_PENDING",
                                "resource_ownership:global_access_unspecified",
                                steps,
                            );
                        }
                        GlobalAccessRequirement::PolicyEvidence => {}
                        GlobalAccessRequirement::ActiveGlobalAdmin => {
                            let Some(user_id) = ctx.user_id.filter(|user_id| *user_id > 0) else {
                                steps.push(step(
                                    "GLOBAL_ADMIN",
                                    "DENY",
                                    "global control-plane request lacked a verified user",
                                    None,
                                ));
                                self.finish_evaluation(
                                    false,
                                    &mut timing,
                                    start,
                                    false,
                                    ctx.resource.as_deref(),
                                );
                                break 'evaluation deny(
                                    "AUTHORIZATION_PENDING",
                                    "global_admin:identity_missing",
                                    steps,
                                );
                            };
                            match repo.is_active_global_admin(user_id).await {
                                Ok(true) => steps.push(step(
                                    "GLOBAL_ADMIN",
                                    "PASS",
                                    "active global administrator confirmed",
                                    None,
                                )),
                                Ok(false) => {
                                    steps.push(step(
                                        "GLOBAL_ADMIN",
                                        "DENY",
                                        "active global administrator required",
                                        None,
                                    ));
                                    self.finish_evaluation(
                                        false,
                                        &mut timing,
                                        start,
                                        false,
                                        ctx.resource.as_deref(),
                                    );
                                    break 'evaluation deny(
                                        "GLOBAL_ADMIN_REQUIRED",
                                        "global_admin:inactive",
                                        steps,
                                    );
                                }
                                Err(error) => {
                                    tracing::warn!(user_id, error = %error,
                                        "global administrator gate unavailable; denying");
                                    steps.push(step(
                                        "GLOBAL_ADMIN",
                                        "DENY",
                                        "global administrator gate unavailable",
                                        None,
                                    ));
                                    self.finish_evaluation(
                                        false,
                                        &mut timing,
                                        start,
                                        true,
                                        ctx.resource.as_deref(),
                                    );
                                    break 'evaluation deny(
                                        "AUTHORIZATION_PENDING",
                                        "global_admin:unavailable",
                                        steps,
                                    );
                                }
                            }
                        }
                    }
                }
                ResourceOwnershipScope::Unresolved => {
                    steps.push(step(
                        "RESOURCE_OWNERSHIP",
                        "DENY",
                        "target resource ownership was not resolved",
                        None,
                    ));
                    self.finish_evaluation(
                        false,
                        &mut timing,
                        start,
                        false,
                        ctx.resource.as_deref(),
                    );
                    break 'evaluation deny(
                        "AUTHORIZATION_PENDING",
                        "resource_ownership:unresolved",
                        steps,
                    );
                }
                ResourceOwnershipScope::Unavailable => {
                    steps.push(step(
                        "RESOURCE_OWNERSHIP",
                        "DENY",
                        "target resource ownership resolver unavailable",
                        None,
                    ));
                    self.finish_evaluation(
                        false,
                        &mut timing,
                        start,
                        true,
                        ctx.resource.as_deref(),
                    );
                    break 'evaluation deny(
                        "AUTHORIZATION_PENDING",
                        "resource_ownership:unavailable",
                        steps,
                    );
                }
            }

            // ORG_SCOPE has its own published authorization proof and takes
            // precedence over ordinary card evidence for managed tenants.
            if !matches!(ctx.resource_ownership_scope, ResourceOwnershipScope::Global) {
                match repo.load_org_authorization(ctx).await {
                    Ok(crate::org_admission::OrgAuthorityRead::Unmanaged) => {
                        // A foreign-tenant target cannot fall through to evidence
                        // scoped to the actor's card.
                        if matches!(
                            ctx.resource_ownership_scope,
                            ResourceOwnershipScope::TenantScoped
                        ) && ctx.resource_tenant_id != ctx.tenant_id
                        {
                            steps.push(step(
                                "RESOURCE_OWNERSHIP",
                                "DENY",
                                "foreign tenant target cannot use actor-card evidence",
                                None,
                            ));
                            self.finish_evaluation(
                                false,
                                &mut timing,
                                start,
                                false,
                                ctx.resource.as_deref(),
                            );
                            break 'evaluation deny(
                                "AUTHORIZATION_PENDING",
                                "resource_ownership:foreign_tenant_target",
                                steps,
                            );
                        }
                    }
                    Ok(crate::org_admission::OrgAuthorityRead::Ready(evidence)) => {
                        let decision =
                            crate::org_admission::evaluate(ctx, repo, &evidence, steps).await;
                        self.finish_evaluation(
                            decision.allowed,
                            &mut timing,
                            start,
                            org_admission_decision_is_dependency_failure(&decision),
                            ctx.resource.as_deref(),
                        );
                        break 'evaluation decision;
                    }
                    Ok(crate::org_admission::OrgAuthorityRead::Disabled) => {
                        let decision = crate::org_admission::unavailable(
                            "ORG_AUTHORITY_DISABLED",
                            "managed authority cannot fall back to card evidence",
                            steps,
                        );
                        self.finish_evaluation(
                            false,
                            &mut timing,
                            start,
                            false,
                            ctx.resource.as_deref(),
                        );
                        break 'evaluation decision;
                    }
                    Ok(crate::org_admission::OrgAuthorityRead::Pending { code }) => {
                        let decision = crate::org_admission::unavailable(
                            "AUTHORIZATION_PENDING",
                            &code,
                            steps,
                        );
                        self.finish_evaluation(
                            false,
                            &mut timing,
                            start,
                            false,
                            ctx.resource.as_deref(),
                        );
                        break 'evaluation decision;
                    }
                    Ok(crate::org_admission::OrgAuthorityRead::Unavailable { code }) => {
                        tracing::warn!(code = %code,
                            "org authority gate or evidence read unavailable, denying");
                        let decision = crate::org_admission::unavailable(
                            "AUTHORIZATION_PENDING",
                            &code,
                            steps,
                        );
                        self.finish_evaluation(
                            false,
                            &mut timing,
                            start,
                            true,
                            ctx.resource.as_deref(),
                        );
                        break 'evaluation decision;
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "org authority read failed, denying");
                        let decision = crate::org_admission::unavailable(
                            "AUTHORIZATION_PENDING",
                            "org_scope.read_unavailable",
                            steps,
                        );
                        self.finish_evaluation(
                            false,
                            &mut timing,
                            start,
                            true,
                            ctx.resource.as_deref(),
                        );
                        break 'evaluation decision;
                    }
                }
            }

            // CURRENT V6 is the only ordinary card authorization route. The strict
            // helper revalidates evidence and performs mandatory ALLOW-time rereads.
            let resource_key =
                build_resource_key(ctx.resource.as_deref().unwrap_or(""), ctx.target_id);
            break 'evaluation self
                .evaluate_published_card_evidence(
                    ctx,
                    repo,
                    &resource_key,
                    start,
                    &mut steps,
                    &mut timing,
                )
                .await;
        };

        decision
    }

    /// Record a completed V6/ORG evaluation and update the dependency circuit breaker.
    pub(super) fn finish_evaluation(
        &self,
        allowed: bool,
        timing: &mut TimingBreakdown,
        start: std::time::Instant,
        repo_had_error: bool,
        resource: Option<&str>,
    ) {
        timing.total_ns = start.elapsed().as_nanos() as u64;
        record_policy_phase_metrics(timing);
        self.record_evaluation(allowed, timing);
        if repo_had_error {
            self.record_failure_on_evaluate(resource);
        } else {
            self.record_success_on_evaluate(resource);
        }
    }

    /// Return the stable source category for an ALLOW decision.
    pub fn allow_source_phase(decision: &PolicyDecision) -> Option<&'static str> {
        if !decision.allowed {
            return None;
        }
        decision
            .evaluation_path
            .iter()
            .rev()
            .find(|step| step.result == astral_types::Effect::Allow)
            .and_then(|step| {
                if step.phase == "PUBLISHED_EVIDENCE" {
                    return match step.source.as_deref() {
                        Some("RULE_SET_BASE") | Some("RULE_SET_OVERLAY") | Some("RULE_SET") => {
                            Some("RULE_SET")
                        }
                        Some("DIRECT") => Some("DIRECT"),
                        Some("APPROVAL") => Some("APPROVAL"),
                        Some("DELEGATION") => Some("DELEGATION"),
                        _ => None,
                    };
                }
                match step.phase.as_str() {
                    "ORG_AUTHORITY" => Some("ORG_AUTHORITY"),
                    _ => None,
                }
            })
    }

    /// Simulated permission evaluation follows the same strict CURRENT V6 path.
    pub async fn simulate<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        self.evaluate(ctx, repo).await
    }

    /// Circuit-breaker fallback is always DENY; stale evidence is never consulted.
    pub fn evaluate_fallback(&self, _ctx: &PolicyContext) -> PolicyDecision {
        PolicyDecision {
            allowed: false,
            reason: "CIRCUIT_BREAKER_OPEN".into(),
            matched_rule: None,
            audit_required: true,
            evaluation_path: vec![],
            matched_rule_id: None,
            condition_results: None,
            snapshot_version: None,
            org_provenance: None,
        }
    }
}
