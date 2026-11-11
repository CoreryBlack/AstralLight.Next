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
    /// Positive ALLOWs additionally require the repository's node-level
    /// `positive_authorization_ready` reconciliation proof; a not-serving node
    /// fails closed to `AUTHORIZATION_PENDING` on both the ORG_SCOPE and the
    /// published CARD evidence path.
    pub async fn evaluate<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        self.evaluate_with_admission(ctx, repo).await.decision
    }

    /// Evaluate a request and retain the final certified F1 capability when the
    /// selected path can produce one. Existing `evaluate` callers intentionally
    /// continue to receive only the serializable decision.
    pub async fn evaluate_with_admission<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> crate::engine::PolicyEvaluation {
        self.evaluate_internal(ctx, repo).await
    }

    async fn evaluate_internal<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> crate::engine::PolicyEvaluation {
        let start = std::time::Instant::now();
        let mut steps = Vec::new();
        let mut timing = TimingBreakdown::default();

        #[cfg(feature = "performance-attribution")]
        let breaker_fallback = self.check_circuit_breaker_attributed(ctx);
        #[cfg(not(feature = "performance-attribution"))]
        let breaker_fallback = self.check_circuit_breaker(ctx);
        if let Some(fallback) = breaker_fallback {
            return crate::engine::PolicyEvaluation::without_admission(fallback);
        }

        let mut admission = None;
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
                    Ok(crate::org_admission::OrgAuthorityRead::Ready(mut evidence)) => {
                        let certified = matches!(
                            repo.published_evidence_read_mode(),
                            super::ports::PublishedEvidenceReadMode::CertifiedMemory
                        );
                        let initial_proof = if certified {
                            let nonce = super::published::next_authority_nonce("org-f0");
                            match repo
                                .read_org_authorization_fence(ctx, &evidence, &nonce)
                                .await
                            {
                                Ok(proof)
                                    if astral_types::validate_org_authority_proof(
                                        &proof,
                                        ctx,
                                        &evidence,
                                        &nonce,
                                        time::OffsetDateTime::now_utc().unix_timestamp(),
                                    )
                                    .is_ok() =>
                                {
                                    Some(proof)
                                }
                                _ => {
                                    self.finish_evaluation(
                                        false,
                                        &mut timing,
                                        start,
                                        true,
                                        ctx.resource.as_deref(),
                                    );
                                    break 'evaluation deny(
                                        "AUTHORIZATION_PENDING",
                                        "org_scope.initial_authority_unavailable",
                                        steps,
                                    );
                                }
                            }
                        } else {
                            None
                        };
                        if let Some(proof) = initial_proof.as_ref() {
                            let current = repo.load_org_authorization(ctx).await;
                            match current {
                                Ok(crate::org_admission::OrgAuthorityRead::Ready(current))
                                    if astral_types::validate_org_authority_proof(
                                        proof,
                                        ctx,
                                        &current,
                                        &proof.request_nonce,
                                        time::OffsetDateTime::now_utc().unix_timestamp(),
                                    )
                                    .is_ok() =>
                                {
                                    evidence = current
                                }
                                _ => {
                                    steps.push(step(
                                        "ORG_AUTHORITY",
                                        "DENY",
                                        "org_scope.initial_evidence_changed",
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
                                        "org_scope.initial_evidence_changed",
                                        steps,
                                    );
                                }
                            }
                        }
                        let mut decision =
                            crate::org_admission::evaluate(ctx, repo, &evidence, steps).await;
                        if decision.allowed && certified {
                            let nonce = super::published::next_authority_nonce("org-f1");
                            let next = match repo.load_org_authorization(ctx).await {
                                Ok(crate::org_admission::OrgAuthorityRead::Ready(next)) => {
                                    Some(next)
                                }
                                _ => None,
                            };
                            let final_proof = match next.as_deref() {
                                Some(next) => repo
                                    .read_org_authorization_fence(ctx, next, &nonce)
                                    .await
                                    .ok(),
                                None => None,
                            };
                            let stable = match (
                                initial_proof.as_ref(),
                                final_proof.as_ref(),
                                next.as_deref(),
                            ) {
                                (Some(initial), Some(final_proof), Some(next)) => {
                                    initial.request_nonce != final_proof.request_nonce
                                        && initial.proof_id != final_proof.proof_id
                                        && initial.same_frontier_as(final_proof).is_ok()
                                        && astral_types::validate_org_authority_proof(
                                            final_proof,
                                            ctx,
                                            next,
                                            &nonce,
                                            time::OffsetDateTime::now_utc().unix_timestamp(),
                                        )
                                        .is_ok()
                                }
                                _ => false,
                            };
                            if stable {
                                admission = final_proof.and_then(|proof| {
                                    astral_types::AuthorizationAdmission::from_verified_request_bound_proof(proof)
                                        .ok()
                                });
                            }
                            if !stable || admission.is_none() {
                                let mut pending_steps = decision.evaluation_path;
                                pending_steps.push(step(
                                    "ORG_AUTHORITY",
                                    "DENY",
                                    "org_scope.final_authority_changed",
                                    None,
                                ));
                                decision = deny(
                                    "AUTHORIZATION_PENDING",
                                    "org_scope.final_authority_changed",
                                    pending_steps,
                                );
                            }
                        }
                        // Node-level readiness gate: ORG_SCOPE published authority is a
                        // positive authorization input, so an ALLOW may only be returned
                        // while the repository's authority reconciliation is serving —
                        // the same contract as the published-evidence ALLOW gate. A
                        // not-serving node fails closed to AUTHORIZATION_PENDING and is
                        // recorded as a dependency failure; deterministic DENY/PENDING
                        // outcomes and the final evidence reread above stay unchanged.
                        if decision.allowed && !repo.positive_authorization_ready() {
                            let mut pending_steps = decision.evaluation_path;
                            pending_steps.push(step(
                                "ORG_AUTHORITY",
                                "DENY",
                                "authority fence reconciliation is not serving",
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
                                "org_scope:authority-not-serving",
                                pending_steps,
                            );
                        }
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
                    &mut admission,
                )
                .await;
        };

        crate::engine::PolicyEvaluation::from_parts(decision, admission)
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
        #[cfg(feature = "performance-attribution")]
        let stats_started = std::time::Instant::now();
        #[cfg(feature = "performance-attribution")]
        crate::hit_stats::publish_evaluation_attribution(timing);
        self.record_evaluation(allowed, timing);
        if repo_had_error {
            self.record_failure_on_evaluate(resource);
        } else {
            self.record_success_on_evaluate(resource);
        }
        #[cfg(feature = "performance-attribution")]
        {
            let stats_and_breaker_ns = stats_started.elapsed().as_nanos() as u64;
            crate::hit_stats::add_evaluation_stats_and_breaker(stats_and_breaker_ns);
            timing.total_ns = timing.total_ns.saturating_add(stats_and_breaker_ns);
            crate::hit_stats::publish_evaluation_attribution(timing);
        }
        record_policy_phase_metrics(timing);
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
