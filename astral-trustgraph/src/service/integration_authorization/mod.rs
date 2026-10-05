//! Remote admission: app proof and mapping cannot replace PolicyEngine evidence.

mod config;
mod session;

pub(crate) use config::IntegrationConfig;
use std::sync::Arc;

use astral_common::middleware::permission_check_shared::physical_policy_context;
use astral_db::{
    claim_replay_guard, read_integration_identity_mapping, GuardClaim, IntegrationIdentityKey,
    SqlxRuleRepository,
};
use astral_sdk_contracts::{
    sign_decision, verify_request, AuthorizationDecision, AuthorizationRequest, DecisionOutcome,
    SignedAuthorizationDecision, SignedAuthorizationRequest,
};
use astral_types::{PolicyContext, ResourceOwnershipScope};
use axum::http::HeaderMap;
use policy_engine::PolicyEngine;
use sha2::Digest;
use sqlx::MySqlPool;

use super::admission_checks;

fn utc_millis() -> Result<u64, &'static str> {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| "AUTHORIZATION_PENDING")
}

#[derive(Clone)]
pub(crate) struct IntegrationAuthorizationService {
    pub db: MySqlPool,
    pub engine: Arc<PolicyEngine>,
    pub config: Arc<IntegrationConfig>,
    pub org_scope_enabled: bool,
}

fn same_policy(
    current: &astral_types::PolicyDecision,
    expected: &astral_types::PolicyDecision,
) -> bool {
    current.allowed
        && expected.allowed
        && current.reason == expected.reason
        && current.matched_rule == expected.matched_rule
        && current.matched_rule_id == expected.matched_rule_id
        && current.audit_required == expected.audit_required
        && current.snapshot_version == expected.snapshot_version
        && current.org_provenance == expected.org_provenance
        && serde_json::to_value(&current.condition_results)
            .ok()
            .zip(serde_json::to_value(&expected.condition_results).ok())
            .is_some_and(|(current, expected)| current == expected)
}

struct AdmissionProof<'a> {
    mapping_key: &'a IntegrationIdentityKey,
    mapping: &'a astral_db::IntegrationIdentityMapping,
    owner: &'a Option<(
        IntegrationIdentityKey,
        astral_db::IntegrationIdentityMapping,
    )>,
    session: &'a astral_common::session_projection_store::AccessSessionDurableFact,
    ctx: &'a PolicyContext,
    request: &'a AuthorizationRequest,
    repo: &'a SqlxRuleRepository,
    policy: &'a astral_types::PolicyDecision,
    fence: Option<astral_db::AuthorityReadFence>,
}

impl IntegrationAuthorizationService {
    pub async fn authorize(
        &self,
        headers: &HeaderMap,
        signed: &SignedAuthorizationRequest,
    ) -> Result<SignedAuthorizationDecision, &'static str> {
        let started = std::time::Instant::now();
        let result = self.authorize_inner(headers, signed).await;
        if let Err(code) = &result {
            tracing::warn!(
                reason_code = *code,
                retry_count = 0u32,
                phase_elapsed_micros = started.elapsed().as_micros() as u64,
                "integration admission refused"
            );
            if signed.request.validate().is_ok() && *code != "INTEGRATION_REPLAY_REJECTED" {
                self.rejection_audit(headers, &signed.request, code).await;
            }
        }
        result
    }

    async fn authorize_inner(
        &self,
        headers: &HeaderMap,
        signed: &SignedAuthorizationRequest,
    ) -> Result<SignedAuthorizationDecision, &'static str> {
        let start = std::time::Instant::now();
        let request = &signed.request;
        let now = utc_millis()?;
        request
            .validate_at(now)
            .map_err(|_| "INVALID_INTEGRATION_REQUEST")?;
        let app = self
            .config
            .application(&request.app_id)
            .ok_or("INTEGRATION_NOT_AUTHORIZED")?;
        if app.key_id != request.key_id
            || app.issuer != request.subject.issuer
            || app.manifest.revision != request.revision
            || app.manifest.digest().map_err(|_| "INVALID_MANIFEST")? != request.manifest_digest
            || !app.manifest.permits_request(request)
        {
            return Err("INTEGRATION_NOT_AUTHORIZED");
        }
        let key = app
            .verifying_key()
            .map_err(|_| "INTEGRATION_NOT_AUTHORIZED")?;
        verify_request(&key, request, &signed.signature)
            .map_err(|_| "INTEGRATION_NOT_AUTHORIZED")?;
        let mut ctx = physical_policy_context(
            headers,
            &request.facts.resource_type,
            &request.action,
            Some(
                request
                    .facts
                    .target_id
                    .parse::<i64>()
                    .ok()
                    .filter(|id| *id > 0)
                    .ok_or("INVALID_INTEGRATION_REQUEST")?,
            ),
        )
        .map_err(|_| "IDENTITY_REQUIRED")?;
        let gateway_token_id = headers.get("x-token-id").and_then(|v| v.to_str().ok());
        if gateway_token_id != Some(request.session_token_id.as_str())
            || ctx.principal_kind.as_deref() != Some("PLATFORM_USER")
        {
            return Err("IDENTITY_REQUIRED");
        }
        let replay_key = hex::encode(sha2::Sha256::digest(
            serde_json::to_vec(&(&request.app_id, &request.nonce))
                .map_err(|_| "INVALID_INTEGRATION_REQUEST")?,
        ));
        match claim_replay_guard(&self.db, "sdk-integration-v1", &replay_key, 90).await {
            Ok(GuardClaim::Claimed) => {}
            Ok(GuardClaim::Duplicate) => return Err("INTEGRATION_REPLAY_REJECTED"),
            Err(_) => return Err("AUTHORIZATION_PENDING"),
        }
        let fence = admission_checks::capture_fence()?;
        let mapping_key = IntegrationIdentityKey::new(
            request.app_id.clone(),
            request.subject.issuer.clone(),
            request.subject.subject.clone(),
        )
        .map_err(|_| "INTEGRATION_NOT_AUTHORIZED")?;
        let mapping = read_integration_identity_mapping(&self.db, &mapping_key)
            .await
            .map_err(|_| "AUTHORIZATION_PENDING")?
            .ok_or("INTEGRATION_NOT_AUTHORIZED")?;
        if ctx.user_id != Some(mapping.user_id)
            || ctx.identity_card_id != Some(mapping.identity_card_id)
        {
            return Err("INTEGRATION_NOT_AUTHORIZED");
        }
        let initial_session =
            session::read_session(&self.db, &request.session_token_id, &ctx).await?;
        let scope = app
            .tenant_binding(
                &request.facts.external_tenant_id,
                &request.facts.external_domain_id,
            )
            .ok_or("INTEGRATION_NOT_AUTHORIZED")?;
        // V1 is same-tenant only. A future cross-organization contract must prove
        // actor-app admission separately from the target owner's registration.
        if ctx.tenant_id != Some(scope.tenant_id) || ctx.domain_id != Some(scope.domain_id) {
            return Err("INTEGRATION_NOT_AUTHORIZED");
        }
        ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
        if matches!(
            request.facts.operation,
            astral_sdk_contracts::ResourceOperation::ScopedCollection
        ) {
            // Object grants cannot authorize every row of a collection. The SDK
            // still binds its parent/scope ID, while policy must prove type scope.
            ctx.target_id = None;
            if request.facts.owner.is_some() {
                return Err("INVALID_INTEGRATION_REQUEST");
            }
        }
        ctx.resource_tenant_id = Some(scope.tenant_id);
        ctx.resource_domain_id = Some(scope.domain_id);
        let owner_key = if let Some(owner) = &request.facts.owner {
            if owner.issuer != app.issuer {
                return Err("INTEGRATION_NOT_AUTHORIZED");
            }
            let owner_key = IntegrationIdentityKey::new(
                request.app_id.clone(),
                owner.issuer.clone(),
                owner.subject.clone(),
            )
            .map_err(|_| "INTEGRATION_NOT_AUTHORIZED")?;
            let owner_mapping = read_integration_identity_mapping(&self.db, &owner_key)
                .await
                .map_err(|_| "AUTHORIZATION_PENDING")?
                .ok_or("INTEGRATION_NOT_AUTHORIZED")?;
            ctx.resource_owner_id = Some(owner_mapping.user_id);
            Some((owner_key, owner_mapping))
        } else {
            None
        };
        let repo =
            SqlxRuleRepository::new(self.db.clone()).with_org_scope_enabled(self.org_scope_enabled);
        let policy = self.engine.evaluate(&ctx, &repo).await;
        let (mut outcome, mut reason) = if policy.allowed {
            (DecisionOutcome::Allow, "ADMITTED")
        } else if policy.reason == "AUTHORIZATION_PENDING"
            || policy.reason == "DEPENDENCY_UNAVAILABLE"
        {
            (DecisionOutcome::Pending, "AUTHORIZATION_PENDING")
        } else {
            (DecisionOutcome::Deny, "POLICY_DENIED")
        };
        if policy.allowed {
            match admission_checks::check_sod(&self.db, &ctx, &policy).await {
                Ok(result) if result.has_conflict => {
                    outcome = DecisionOutcome::Deny;
                    reason = "SOD_CONFLICT";
                }
                Ok(_) => {}
                Err(_) => {
                    outcome = DecisionOutcome::Pending;
                    reason = "AUTHORIZATION_PENDING";
                }
            }
        }
        if matches!(outcome, DecisionOutcome::Allow) {
            let next_mapping = read_integration_identity_mapping(&self.db, &mapping_key)
                .await
                .map_err(|_| "AUTHORIZATION_PENDING")?;
            let next_session =
                session::read_session(&self.db, &request.session_token_id, &ctx).await?;
            let owner_stable = if let Some((owner_key, owner_mapping)) = &owner_key {
                read_integration_identity_mapping(&self.db, owner_key)
                    .await
                    .map_err(|_| "AUTHORIZATION_PENDING")?
                    .as_ref()
                    == Some(owner_mapping)
            } else {
                true
            };
            if next_mapping.as_ref() != Some(&mapping)
                || next_session != initial_session
                || !owner_stable
                || !admission_checks::fence_holds(fence)
            {
                outcome = DecisionOutcome::Pending;
                reason = "AUTHORIZATION_PENDING";
            }
        }
        let proof = AdmissionProof {
            mapping_key: &mapping_key,
            mapping: &mapping,
            owner: &owner_key,
            session: &initial_session,
            ctx: &ctx,
            request,
            repo: &repo,
            policy: &policy,
            fence,
        };
        let now = utc_millis()?;
        request
            .validate_at(now)
            .map_err(|_| "AUTHORIZATION_PENDING")?;
        if matches!(outcome, DecisionOutcome::Allow) {
            match self.final_check(&proof).await {
                Ok(()) => {}
                Err(code) => {
                    outcome = DecisionOutcome::Pending;
                    reason = code;
                }
            }
        }
        let mut signed_decision = self.sign(request, mapping.revision, outcome, reason)?;
        self.audit(&ctx, request, &signed_decision, "ASSESSED")
            .await?;
        // Audit persistence cannot be atomic with response delivery. Any failed
        // post-audit check invalidates the assessed candidate before it can leave.
        if matches!(signed_decision.decision.outcome, DecisionOutcome::Allow) {
            if let Err(code) = self.final_check(&proof).await {
                reason = code;
                signed_decision =
                    self.sign(request, mapping.revision, DecisionOutcome::Pending, code)?;
                self.audit(&ctx, request, &signed_decision, "INVALIDATED")
                    .await?;
            }
        }
        let final_now = utc_millis()?;
        request
            .validate_at(final_now)
            .map_err(|_| "AUTHORIZATION_PENDING")?;
        if signed_decision.decision.expires_at_ms <= final_now {
            return Err("AUTHORIZATION_PENDING");
        }
        tracing::info!(
            app_id = %request.app_id,
            request_id = %request.request_id,
            reason_code = reason,
            phase_elapsed_micros = start.elapsed().as_micros() as u64,
            retry_count = 0u32,
            "integration admission completed"
        );
        Ok(signed_decision)
    }

    async fn rejection_audit(
        &self,
        headers: &HeaderMap,
        request: &AuthorizationRequest,
        code: &str,
    ) {
        let Ok(ctx) =
            physical_policy_context(headers, &request.facts.resource_type, &request.action, None)
        else {
            return;
        };
        if ctx.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return;
        }
        let (Some(user_id), Some(card_id), Some(tenant_id), Some(domain_id)) =
            (ctx.user_id, ctx.card_id, ctx.tenant_id, ctx.domain_id)
        else {
            return;
        };
        let detail = serde_json::json!({
            "requestDigest": request.digest().ok(), "operationId": request.operation_id,
            "phase": "REFUSED", "scope": "GATEWAY_ACTOR_NOT_CLAIMED_EXTERNAL_SUBJECT",
        });
        let result = astral_db::record_integration_admission_audit(
            &self.db,
            astral_db::IntegrationAdmissionAudit {
                user_id,
                card_id,
                tenant_id,
                domain_id,
                resource: request.facts.resource_type.clone(),
                action: request.action.clone(),
                decision: "PENDING".into(),
                reason: code.into(),
                request_id: request.request_id.clone(),
                detail: detail.to_string(),
            },
        )
        .await;
        if result.is_err() {
            tracing::warn!(
                reason_code = "REFUSAL_AUDIT_UNKNOWN",
                "integration refusal audit not proven"
            );
        }
    }

    fn sign(
        &self,
        request: &AuthorizationRequest,
        mapping_revision: u64,
        outcome: DecisionOutcome,
        reason: &str,
    ) -> Result<SignedAuthorizationDecision, &'static str> {
        let decision = AuthorizationDecision::bound_to(
            request,
            mapping_revision.to_string(),
            outcome,
            Some(reason.to_string()),
            utc_millis()?,
        )
        .map_err(|_| "AUTHORIZATION_PENDING")?;
        sign_decision(
            self.config.decision_key_id.clone(),
            &self.config.decision_key,
            decision,
        )
        .map_err(|_| "AUTHORIZATION_PENDING")
    }

    async fn final_check(&self, proof: &AdmissionProof<'_>) -> Result<(), &'static str> {
        self.recheck_identity(
            proof.mapping_key,
            proof.mapping,
            proof.owner,
            proof.session,
            proof.ctx,
            proof.request,
        )
        .await?;
        let final_policy = self.engine.evaluate(proof.ctx, proof.repo).await;
        if !same_policy(&final_policy, proof.policy) {
            return Err("AUTHORIZATION_PENDING");
        }
        let final_sod = admission_checks::check_sod(&self.db, proof.ctx, &final_policy)
            .await
            .map_err(|_| "AUTHORIZATION_PENDING")?;
        self.recheck_identity(
            proof.mapping_key,
            proof.mapping,
            proof.owner,
            proof.session,
            proof.ctx,
            proof.request,
        )
        .await?;
        proof
            .request
            .validate_at(utc_millis()?)
            .map_err(|_| "AUTHORIZATION_PENDING")?;
        if final_sod.has_conflict || !admission_checks::fence_holds(proof.fence) {
            return Err("AUTHORIZATION_PENDING");
        }
        Ok(())
    }

    async fn recheck_identity(
        &self,
        key: &IntegrationIdentityKey,
        mapping: &astral_db::IntegrationIdentityMapping,
        owner: &Option<(
            IntegrationIdentityKey,
            astral_db::IntegrationIdentityMapping,
        )>,
        session: &astral_common::session_projection_store::AccessSessionDurableFact,
        ctx: &PolicyContext,
        request: &AuthorizationRequest,
    ) -> Result<(), &'static str> {
        let mapping_stable = read_integration_identity_mapping(&self.db, key)
            .await
            .map_err(|_| "AUTHORIZATION_PENDING")?
            .as_ref()
            == Some(mapping);
        let session_stable =
            session::read_session(&self.db, &request.session_token_id, ctx).await? == *session;
        let owner_stable = match owner {
            Some((key, expected)) => {
                read_integration_identity_mapping(&self.db, key)
                    .await
                    .map_err(|_| "AUTHORIZATION_PENDING")?
                    .as_ref()
                    == Some(expected)
            }
            None => true,
        };
        if mapping_stable && session_stable && owner_stable {
            Ok(())
        } else {
            Err("AUTHORIZATION_PENDING")
        }
    }

    async fn audit(
        &self,
        ctx: &PolicyContext,
        request: &AuthorizationRequest,
        decision: &SignedAuthorizationDecision,
        phase: &str,
    ) -> Result<(), &'static str> {
        let detail = serde_json::json!({
            "appId": request.app_id,
            "requestDigest": decision.decision.request_digest,
            "mappingRevision": decision.decision.mapping_revision,
            "factsDigest": decision.decision.facts_digest,
            "operationId": request.operation_id,
            "decisionDigest": hex::encode(sha2::Sha256::digest(
                serde_json::to_vec(decision).map_err(|_| "AUTHORIZATION_PENDING")?,
            )),
            "phase": phase,
            "scope": "PLATFORM_ASSESSMENT_NOT_RESPONSE_DELIVERY_OR_BUSINESS_COMMIT",
        });
        astral_db::record_integration_admission_audit(
            &self.db,
            astral_db::IntegrationAdmissionAudit {
                user_id: ctx.user_id.ok_or("AUTHORIZATION_PENDING")?,
                card_id: ctx.card_id.ok_or("AUTHORIZATION_PENDING")?,
                tenant_id: ctx.tenant_id.ok_or("AUTHORIZATION_PENDING")?,
                domain_id: ctx.domain_id.ok_or("AUTHORIZATION_PENDING")?,
                resource: request.facts.resource_type.clone(),
                action: request.action.clone(),
                decision: match decision.decision.outcome {
                    DecisionOutcome::Allow => "ALLOW",
                    DecisionOutcome::Deny => "DENY",
                    DecisionOutcome::Pending => "PENDING",
                }
                .into(),
                reason: decision
                    .decision
                    .reason
                    .clone()
                    .unwrap_or_else(|| "AUTHORIZATION_PENDING".into()),
                request_id: request.request_id.clone(),
                detail: detail.to_string(),
            },
        )
        .await
        .map_err(|_| "AUTHORIZATION_PENDING")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> astral_types::PolicyDecision {
        astral_types::PolicyDecision {
            allowed: true,
            reason: "RULE_SET_ALLOW".into(),
            matched_rule: Some("rule".into()),
            audit_required: true,
            evaluation_path: Vec::new(),
            matched_rule_id: Some(1),
            condition_results: None,
            snapshot_version: Some(2),
            org_provenance: None,
        }
    }

    #[test]
    fn changed_final_policy_never_preserves_allow() {
        let baseline = policy();
        assert!(same_policy(&baseline, &baseline));
        let mut changed = policy();
        changed.allowed = false;
        assert!(!same_policy(&changed, &baseline));
        let mut changed = policy();
        changed.matched_rule_id = Some(99);
        assert!(!same_policy(&changed, &baseline));
        let mut changed = policy();
        changed.snapshot_version = Some(3);
        assert!(!same_policy(&changed, &baseline));
        let mut changed = policy();
        changed.audit_required = false;
        assert!(!same_policy(&changed, &baseline));
    }

    #[test]
    fn original_fence_and_final_checks_cover_the_audit_window() {
        let source = include_str!("mod.rs").split("#[cfg(test)]").next().unwrap();
        let capture = source
            .find("let fence = admission_checks::capture_fence()")
            .unwrap();
        let mapping = source
            .find("let mapping = read_integration_identity_mapping")
            .unwrap();
        assert!(capture < mapping);
        assert_eq!(source.matches("capture_fence()").count(), 1);
        let candidate = source.find("let mut signed_decision = self.sign").unwrap();
        let before = source[..candidate]
            .rfind("self.final_check(&proof)")
            .unwrap();
        let audit = source.find("&signed_decision, \"ASSESSED\"").unwrap();
        let after = source[audit..].find("self.final_check(&proof)").unwrap() + audit;
        let invalidation = source.find("&signed_decision, \"INVALIDATED\"").unwrap();
        assert!(before < candidate && candidate < audit && audit < after && after < invalidation);
        assert!(!source.contains("FINAL_PLATFORM_ADMISSION_NOT_BUSINESS_COMMIT"));
    }
}
