use astral_types::org_scope::{
    org_build_segment, org_manifest_digest_hex, OrgAdmissionEvidence, OrgContribution, OrgGrant,
    OrgGrantRef, OrgManifestDigestMaterial, OrgMembership, OrgNode, OrgProvenance, OrgPublication,
    OrgRootActivation, OrgScope, OrgScopeKey, OrgSegmentContent,
};
use astral_types::{
    CanonicalGrant, DomainScopeRequirement, Effect, EvaluationStep, GlobalAccessRequirement,
    PolicyContext, PolicyDecision, PolicyError, PublicationSeal, PublishedCardAuthorization,
    PublishedCardEvidenceScope, ResourceOwnershipScope, ValidityWindow,
};

use super::decision::*;
use super::ports::RuleRepository;
use super::published::*;
use super::*;
use crate::org_admission::OrgAuthorityRead;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// ===== CURRENT V6 strict published-evidence evaluator =====

/// strict gate 上下文：PLATFORM 域完整身份（tenant/domain 与 fixture 对齐）。
fn strict_ctx() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build()
}

/// 类型级请求上下文（无 target_id → resource_key = `learn_subject:*`）。
fn strict_ctx_type_level() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .build()
}

/// Resolver-classified target context for strict published-evidence domain
/// boundary tests. The actor card stays in domain 11; callers choose the
/// authoritative target domain independently.
fn strict_tenant_scoped_ctx(resource_domain_id: Option<i64>) -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .resource_tenant_id(Some(7))
        .resource_domain_id(resource_domain_id)
        .resource_ownership_scope(ResourceOwnershipScope::TenantScoped)
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build()
}

fn strict_global_ctx(access_requirement: GlobalAccessRequirement) -> PolicyContext {
    let mut context = strict_ctx();
    context.resource_ownership_scope = ResourceOwnershipScope::Global;
    context.global_access_requirement = access_requirement;
    context
}

/// 构造一条合同有效的 CanonicalGrant（tenant 7/domain 11/card 1/user 1）。
fn strict_published_grant(
    grant_id: &str,
    source_kind: astral_types::GrantSourceKind,
    binding_layer: astral_types::BindingLayer,
    resource: &str,
    action: &str,
) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: astral_types::GrantId::parse(grant_id).unwrap(),
        revision: astral_types::GrantRevision::new(1).unwrap(),
        state: astral_types::GrantState::Active,
        source_kind,
        binding_layer,
        tenant: astral_types::TenantScope::new(7, Some(11)).unwrap(),
        card_id: 1,
        user_id: 1,
        resource: resource.to_string(),
        action: action.to_string(),
        effect: astral_types::GrantEffect::Allow,
        validity: astral_types::ValidityWindow::perpetual(),
        provenance: astral_types::GrantProvenance {
            source_id: "source-1".to_string(),
            source_entry: Some("entry-1".to_string()),
            binding_id: if source_kind == astral_types::GrantSourceKind::RuleSet {
                Some("binding-1".to_string())
            } else {
                None
            },
            delegation_id: if source_kind == astral_types::GrantSourceKind::Delegation {
                Some("delegation-1".to_string())
            } else {
                None
            },
            operation_id: "op-1".to_string(),
            event_id: Some("event-1".to_string()),
            actor_user_id: None,
        },
    }
}

/// 手工 Ready 证据 fixture（仅测试用；真实构造者是严格 DB reader）。
fn strict_ready_evidence(grants: Vec<CanonicalGrant>) -> PublishedCardAuthorization {
    let record_count = grants.len();
    let manifest = astral_types::PublishedAggregateManifestSummary {
        seal: PublicationSeal::from_unix_seconds(1_700_000_000).unwrap(),
        tenant_id: 7,
        card_id: 1,
        aggregate_type: "CARD".to_string(),
        aggregate_id: 1,
        manifest_id: 1,
        generation: 1,
        source_generation: 1,
        projected_generation: 1,
        revoke_fence: 0,
        cas_version: 1,
        semantic_hash_hex: "a".repeat(64),
        dependency_hash_hex: "b".repeat(64),
        manifest_digest_hex: "c".repeat(64),
        compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_string(),
        event_id: "event-1".to_string(),
        operation_id: "op-1".to_string(),
        parent_manifest_id: None,
        segment_count: 1,
        declared_grant_row_count: record_count as u64,
    };
    let records = grants
        .iter()
        .map(|grant| astral_types::VerifiedPublishedGrantRecord {
            aggregate_type: "CARD".to_string(),
            aggregate_id: 1,
            publication_generation: 1,
            revoke_fence: 0,
            manifest_id: 1,
            event_id: "event-1".to_string(),
            operation_id: "op-1".to_string(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_string(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant: grant.clone(),
            accepted_into_effective_set: true,
            unaccepted_reason: None,
        })
        .collect();
    PublishedCardAuthorization {
        tenant_id: 7,
        card_id: 1,
        read_unix_seconds: 1_700_000_000,
        gate: astral_types::PublishedCardAuthorizationGate {
            status: astral_types::PublishedEvidenceGateStatus::Ready,
            aggregate_manifest_count: 1,
            verified_record_count: record_count,
            effective_grant_count: record_count,
            not_in_effective_count: 0,
            equivalent_duplicate_collapsed_count: 0,
        },
        manifests: vec![manifest],
        records,
        effective_grants: grants,
    }
}

/// CURRENT V6 test repository: publish evidence reads are scripted and identity
/// gates have explicit outcomes. No legacy authorization ports are available.
struct StrictPublishedRepo {
    outcomes:
        Mutex<VecDeque<Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError>>>,
    fallback: Option<std::sync::Arc<PublishedCardAuthorization>>,
    global_admin_outcomes: Mutex<VecDeque<Result<bool, PolicyError>>>,
    global_admin_fallback: bool,
    global_admin_reads: AtomicUsize,
    card_checks: AtomicUsize,
    published_reads: AtomicUsize,
    published_scopes: Mutex<Vec<PublishedCardEvidenceScope>>,
}

impl StrictPublishedRepo {
    fn with_evidence(evidence: PublishedCardAuthorization) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::new()),
            fallback: Some(std::sync::Arc::new(evidence)),
            global_admin_outcomes: Mutex::new(VecDeque::new()),
            global_admin_fallback: false,
            global_admin_reads: AtomicUsize::new(0),
            card_checks: AtomicUsize::new(0),
            published_reads: AtomicUsize::new(0),
            published_scopes: Mutex::new(vec![]),
        }
    }

    fn with_evidence_and_global_admin_outcomes(
        evidence: PublishedCardAuthorization,
        global_admin_outcomes: Vec<Result<bool, PolicyError>>,
    ) -> Self {
        Self {
            outcomes: Mutex::new(VecDeque::new()),
            fallback: Some(std::sync::Arc::new(evidence)),
            global_admin_outcomes: Mutex::new(global_admin_outcomes.into()),
            global_admin_fallback: false,
            global_admin_reads: AtomicUsize::new(0),
            card_checks: AtomicUsize::new(0),
            published_reads: AtomicUsize::new(0),
            published_scopes: Mutex::new(vec![]),
        }
    }

    fn with_outcomes(
        outcomes: Vec<Result<Option<PublishedCardAuthorization>, PolicyError>>,
    ) -> Self {
        let outcomes: Vec<Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError>> =
            outcomes
                .into_iter()
                .map(|outcome| outcome.map(|option| option.map(std::sync::Arc::new)))
                .collect();
        Self {
            outcomes: Mutex::new(outcomes.into()),
            fallback: None,
            global_admin_outcomes: Mutex::new(VecDeque::new()),
            global_admin_fallback: false,
            global_admin_reads: AtomicUsize::new(0),
            card_checks: AtomicUsize::new(0),
            published_reads: AtomicUsize::new(0),
            published_scopes: Mutex::new(vec![]),
        }
    }

    fn published_reads(&self) -> usize {
        self.published_reads.load(Ordering::SeqCst)
    }

    fn global_admin_reads(&self) -> usize {
        self.global_admin_reads.load(Ordering::SeqCst)
    }

    fn published_scopes(&self) -> Vec<PublishedCardEvidenceScope> {
        self.published_scopes.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl RuleRepository for StrictPublishedRepo {
    async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
        self.card_checks.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
        self.global_admin_reads.fetch_add(1, Ordering::SeqCst);
        if let Some(outcome) = self.global_admin_outcomes.lock().unwrap().pop_front() {
            return outcome;
        }
        Ok(self.global_admin_fallback)
    }

    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError> {
        self.published_scopes.lock().unwrap().push(scope.clone());
        self.published_reads.fetch_add(1, Ordering::SeqCst);
        if let Some(outcome) = self.outcomes.lock().unwrap().pop_front() {
            return outcome;
        }
        match &self.fallback {
            Some(evidence) => Ok(Some(std::sync::Arc::clone(evidence))),
            None => panic!("unexpected extra published evidence read"),
        }
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        Ok(OrgAuthorityRead::Unmanaged)
    }
}

const STRICT_RULESET_BASE_GRANT_ID: &str = "550e8400-e29b-41d4-a716-446655440001";

#[tokio::test]
async fn strict_missing_context_denies_before_published_authority_read() {
    let cases = [
        ("user", "AUTHN_REQUIRED", 0),
        ("card", "CARD_REQUIRED", 0),
        ("resource", "RESOURCE_REQUIRED", 1),
        ("action", "ACTION_REQUIRED", 1),
    ];
    for (missing, reason, expected_card_checks) in cases {
        let mut ctx = strict_ctx();
        match missing {
            "user" => ctx.user_id = None,
            "card" => ctx.card_id = None,
            "resource" => ctx.resource = None,
            "action" => ctx.action.clear(),
            _ => unreachable!(),
        }
        let repo = StrictPublishedRepo::with_outcomes(vec![]);
        let decision = PolicyEngine::new().evaluate(&ctx, &repo).await;
        assert!(!decision.allowed, "missing {missing} must deny");
        assert_eq!(decision.reason, reason, "missing {missing}");
        assert_eq!(repo.published_reads(), 0, "missing {missing}");
        assert_eq!(repo.global_admin_reads(), 0, "missing {missing}");
        assert_eq!(
            repo.card_checks.load(Ordering::SeqCst),
            expected_card_checks,
            "missing {missing}"
        );
    }
}

#[test]
fn published_not_ready_is_business_pending_but_query_is_failure() {
    assert!(published_evidence_error_is_business_pending(
        &PolicyError::Repository("published_card_evidence_not_ready;code=x".into(),)
    ));
    assert!(!published_evidence_error_is_business_pending(
        &PolicyError::Repository("published_card_evidence_query_failed;timeout".into(),)
    ));
    assert!(!published_evidence_error_is_business_pending(
        &PolicyError::Repository("published_card_evidence_corrupt;digest".into(),)
    ));
}

#[tokio::test]
async fn strict_not_ready_does_not_open_breaker_after_repeated_pending() {
    let repo = StrictPublishedRepo::with_outcomes(
            (0..(crate::circuit_breaker::CB_THRESHOLD + 1))
                .map(|_| {
                    Err(PolicyError::Repository(
                        "published_card_evidence_not_ready;code=published_card_evidence.source_freshness_pending"
                            .into(),
                    ))
                })
                .collect(),
        );
    let engine = PolicyEngine::new();
    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Closed);
}
#[tokio::test]
async fn test_strict_published_evidence_allows_matching_grant() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = strict_ctx();

    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(
        decision.allowed,
        "expected ALLOW, got {:?}",
        decision.reason
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    let timing = engine.get_stats().timing_ns;
    assert!(timing.initial_evidence_load_ns > 0);
    assert!(timing.final_evidence_reload_ns > 0);
    assert_eq!(
        repo.published_reads(),
        2,
        "ALLOW requires initial + final strict read"
    );
    // ALLOW 复读发生在返回前：initial + recheck 两次读取，无第三次。
    let allow_step = decision
        .evaluation_path
        .iter()
        .rev()
        .find(|s| s.result == Effect::Allow)
        .expect("ALLOW step must exist");
    assert_eq!(allow_step.phase, "PUBLISHED_EVIDENCE");
    assert_eq!(allow_step.source.as_deref(), Some("RULE_SET_BASE"));
    assert_eq!(
        PolicyEngine::allow_source_phase(&decision),
        Some("RULE_SET")
    );
}

#[tokio::test]
async fn global_control_plane_requires_active_admin_before_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::ActiveGlobalAdmin),
            &repo,
        )
        .await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "GLOBAL_ADMIN_REQUIRED");
    assert_eq!(repo.global_admin_reads(), 1);
    assert_eq!(repo.published_reads(), 0);
    assert_eq!(
        decision
            .evaluation_path
            .last()
            .map(|step| step.phase.as_str()),
        Some("GLOBAL_ADMIN")
    );
}

#[tokio::test]
async fn global_utility_keeps_rule_evidence_without_global_admin_lookup() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::PolicyEvidence),
            &repo,
        )
        .await;

    assert!(
        decision.allowed,
        "self-service global utility remains rule-gated"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.global_admin_reads(), 0);
    assert_eq!(repo.published_reads(), 2);
}

#[tokio::test]
async fn global_control_plane_rechecks_active_admin_before_allow() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence_and_global_admin_outcomes(
        evidence,
        vec![Ok(true), Ok(false)],
    );
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::ActiveGlobalAdmin),
            &repo,
        )
        .await;

    assert!(
        !decision.allowed,
        "a disable during evaluation rejects stale ALLOW"
    );
    assert_eq!(decision.reason, "GLOBAL_ADMIN_REQUIRED");
    assert_eq!(repo.global_admin_reads(), 2);
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(
        decision
            .evaluation_path
            .last()
            .map(|step| step.detail.as_str()),
        Some("global administrator changed during evaluation")
    );
}

#[tokio::test]
async fn global_control_plane_active_admin_still_requires_matching_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_course:42",
        "read",
    )]);
    let repo =
        StrictPublishedRepo::with_evidence_and_global_admin_outcomes(evidence, vec![Ok(true)]);
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::ActiveGlobalAdmin),
            &repo,
        )
        .await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
    assert_eq!(repo.global_admin_reads(), 1);
    assert_eq!(repo.published_reads(), 1);
}

#[tokio::test]
async fn global_control_plane_unavailable_gate_opens_breaker_without_evidence_reads() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence_and_global_admin_outcomes(
        evidence,
        (0..crate::circuit_breaker::CB_THRESHOLD)
            .map(|_| {
                Err(PolicyError::Repository(
                    "global_admin_gate_query_failed;timeout".into(),
                ))
            })
            .collect(),
    );
    let engine = PolicyEngine::new();
    let ctx = strict_global_ctx(GlobalAccessRequirement::ActiveGlobalAdmin);

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);
    assert_eq!(
        repo.global_admin_reads(),
        crate::circuit_breaker::CB_THRESHOLD as usize
    );
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn global_target_without_resolver_contract_fails_before_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(
            &strict_global_ctx(GlobalAccessRequirement::Unspecified),
            &repo,
        )
        .await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.global_admin_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn strict_tenant_scoped_target_domain_denies_actor_domain_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(&strict_tenant_scoped_ctx(Some(12)), &repo)
        .await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
    assert_eq!(
        repo.published_reads(),
        1,
        "a target-domain mismatch must not begin an ALLOW recheck"
    );
}

#[tokio::test]
async fn strict_tenant_scoped_target_domain_allows_matching_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(&strict_tenant_scoped_ctx(Some(11)), &repo)
        .await;

    assert!(
        decision.allowed,
        "matching target domain must remain authorizable"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(
        repo.published_scopes(),
        vec![
            PublishedCardEvidenceScope {
                tenant_id: 7,
                card_id: 1,
                user_filter: Some(1),
                domain: DomainScopeRequirement::ExactlySome(11),
            },
            PublishedCardEvidenceScope {
                tenant_id: 7,
                card_id: 1,
                user_filter: Some(1),
                domain: DomainScopeRequirement::ExactlySome(11),
            },
        ],
        "both strict reads retain the actor-card provenance lens; target-domain enforcement belongs in the matcher"
    );
}

#[tokio::test]
async fn strict_tenant_scoped_domainless_target_keeps_tenant_level_evidence() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = PolicyEngine::new()
        .evaluate(&strict_tenant_scoped_ctx(None), &repo)
        .await;

    assert!(
        decision.allowed,
        "a domainless tenant target must not require a domainless card grant"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.published_reads(), 2);
}

#[tokio::test]
async fn test_strict_published_evidence_default_denies_without_match() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        "550e8400-e29b-41d4-a716-446655440002",
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_course:9",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

#[tokio::test]
async fn test_strict_missing_evidence_is_fail_closed_pending() {
    let repo = StrictPublishedRepo::with_outcomes(vec![Ok(None)]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
}

#[tokio::test]
async fn test_strict_evidence_error_is_fail_closed_pending() {
    let repo = StrictPublishedRepo::with_outcomes(vec![Err(PolicyError::Repository(
        "published_card_evidence_not_ready;code=published_card_evidence.current_pointer_missing"
            .into(),
    ))]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
}

#[tokio::test]
async fn test_strict_non_ready_gate_is_fail_closed_pending() {
    // 合同只允许 Ready 证据进入正式授权；非 Ready 即合同违规 → fail-closed。
    let mut evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    evidence.gate.status = astral_types::PublishedEvidenceGateStatus::Pending;
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
}

#[tokio::test]
async fn test_strict_evidence_scope_mismatch_is_fail_closed_pending() {
    let mut evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    evidence.tenant_id = 8; // 与请求 tenant 7 不符
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
}

#[tokio::test]
async fn test_strict_missing_tenant_scope_is_fail_closed_pending() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();

    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
}

#[tokio::test]
async fn test_strict_type_wildcard_grant_matches_object_request() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Overlay,
        "learn_subject:*",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(
        decision.allowed,
        "expected ALLOW, got {:?}",
        decision.reason
    );
    let allow_step = decision
        .evaluation_path
        .iter()
        .rev()
        .find(|s| s.result == Effect::Allow)
        .expect("ALLOW step must exist");
    assert_eq!(allow_step.source.as_deref(), Some("RULE_SET_OVERLAY"));
    assert_eq!(
        PolicyEngine::allow_source_phase(&decision),
        Some("RULE_SET")
    );
}

#[tokio::test]
async fn test_strict_object_grant_never_authorizes_type_request() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx_type_level(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

#[tokio::test]
async fn test_strict_object_grant_does_not_match_other_object() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("read".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(43))
        .build();

    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

#[tokio::test]
async fn test_strict_star_grant_matches_object_and_type_requests() {
    let star_object = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::Direct,
        astral_types::BindingLayer::None,
        "*",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(star_object);
    let engine = PolicyEngine::new();
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(decision.allowed, "object request must match '*' grant");
    assert_eq!(PolicyEngine::allow_source_phase(&decision), Some("DIRECT"));

    let star_type = strict_ready_evidence(vec![strict_published_grant(
        "550e8400-e29b-41d4-a716-446655440003",
        astral_types::GrantSourceKind::Direct,
        astral_types::BindingLayer::None,
        "*",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(star_type);
    let decision = engine.evaluate(&strict_ctx_type_level(), &repo).await;
    assert!(decision.allowed, "type request must match '*' grant");
    assert_eq!(PolicyEngine::allow_source_phase(&decision), Some("DIRECT"));
}

#[tokio::test]
async fn test_strict_write_alias_matches_create_and_delete() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::Approval,
        astral_types::BindingLayer::None,
        "learn_subject:42",
        "write",
    )]);

    // create / delete 请求命中 write 别名；read 无别名关联 → 默认拒绝。
    let engine = PolicyEngine::new();
    for action in ["create", "delete"] {
        let repo = StrictPublishedRepo::with_evidence(evidence.clone());
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .tenant_id(Some(7))
            .domain_id(Some(11))
            .action(action.into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed, "{action} must match write alias");
        assert_eq!(
            PolicyEngine::allow_source_phase(&decision),
            Some("APPROVAL")
        );
    }

    let repo = StrictPublishedRepo::with_evidence(evidence);
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed, "read must not match write alias");
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

#[tokio::test]
async fn test_strict_star_action_grant_matches_any_action() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::Delegation,
        astral_types::BindingLayer::None,
        "learn_subject:*",
        "*",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("archive".into())
        .resource(Some("learn_subject".into()))
        .target_id(Some(42))
        .build();

    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(decision.allowed);
    assert_eq!(
        PolicyEngine::allow_source_phase(&decision),
        Some("DELEGATION")
    );
}

#[tokio::test]
async fn test_strict_expired_grant_does_not_authorize() {
    let mut grant = strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    );
    grant.validity = astral_types::ValidityWindow::between(100, 200);
    let evidence = strict_ready_evidence(vec![grant]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed, "expired grant must not authorize");
    assert_eq!(decision.reason, "DEFAULT_DENY");
}

#[tokio::test]
async fn test_strict_stale_allow_rejected_when_evidence_changes() {
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut second = first.clone();
    // 投影在评估期间推进：manifest 代数变化 → 复读身份不等 → 旧 ALLOW 拒绝。
    second.manifests[0].generation = 2;
    second.manifests[0].source_generation = 2;
    second.manifests[0].projected_generation = 2;
    second.manifests[0].cas_version = 2;
    let repo = StrictPublishedRepo::with_outcomes(vec![Ok(Some(first)), Ok(Some(second))]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
}

fn unsafe_allow_omitting_final_reload(
    ctx: &PolicyContext,
    evidence: &std::sync::Arc<PublishedCardAuthorization>,
) -> bool {
    match_published_effective_grant(ctx, evidence, "learn_subject:42").is_some()
}

#[tokio::test]
async fn e2_final_reload_omission_accepts_removed_candidate_while_full_contract_reloads() {
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut narrowed = strict_ready_evidence(vec![]);
    narrowed.manifests[0].generation = 2;
    narrowed.manifests[0].source_generation = 2;
    narrowed.manifests[0].projected_generation = 2;
    narrowed.manifests[0].cas_version = 2;
    assert!(first.validate().is_ok());
    assert!(narrowed.validate().is_ok());
    let first = std::sync::Arc::new(first);
    assert!(
        unsafe_allow_omitting_final_reload(&strict_ctx(), &first),
        "omitting the final reload admits the initial stale candidate"
    );

    let repo =
        StrictPublishedRepo::with_outcomes(vec![Ok(Some((*first).clone())), Ok(Some(narrowed))]);
    let decision = PolicyEngine::new().evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.published_reads(), 2);
}

fn unsafe_recheck_by_resource_action_only(
    next: &PublishedCardAuthorization,
    matched: &CanonicalGrant,
) -> bool {
    next.effective_grants
        .iter()
        .any(|grant| grant.resource == matched.resource && grant.action == matched.action)
}

#[tokio::test]
async fn test_strict_successor_revision_cannot_replace_original_candidate() {
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut successor = first.clone();
    let successor_revision = astral_types::GrantRevision::new(2).unwrap();

    // Synthetic omission schedule: keep the publication identity fixed and
    // replace only the matched grant revision. This isolates the exact-candidate
    // check; a real publisher must also advance its manifest identity.
    successor.records[0].grant.revision = successor_revision;
    successor.effective_grants[0].revision = successor_revision;
    assert!(successor.validate().is_ok());
    assert_eq!(
        first.effective_grants[0].grant_id,
        successor.effective_grants[0].grant_id
    );
    assert_eq!(
        first.effective_grants[0].resource,
        successor.effective_grants[0].resource
    );
    assert_eq!(
        first.effective_grants[0].action,
        successor.effective_grants[0].action
    );
    assert_ne!(
        first.effective_grants[0].revision,
        successor.effective_grants[0].revision
    );
    let matched = first.effective_grants[0].clone();
    assert!(
        unsafe_recheck_by_resource_action_only(&successor, &matched),
        "resource/action-only omission accepts a successor revision"
    );
    assert!(
        !published_recheck_identity_stable(&first, &successor, 7, 1, &matched),
        "full contract must reject the successor revision"
    );

    let repo = StrictPublishedRepo::with_outcomes(vec![Ok(Some(first)), Ok(Some(successor))]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.published_reads(), 2);
}

#[tokio::test]
async fn test_strict_recheck_error_is_fail_closed() {
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_outcomes(vec![
        Ok(Some(first)),
        Err(PolicyError::Repository(
            "published_card_evidence_not_ready".into(),
        )),
    ]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
}

#[tokio::test]
async fn test_strict_final_reload_missing_evidence_is_fail_closed_without_breaker_failure() {
    // 复读返回 Ok(None)（证据暂不可用）是业务 pending，不是 repository
    // 硬错误：拒绝放行，且不得计入断路器失败。
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_outcomes(vec![Ok(Some(first)), Ok(None)]);
    let engine = PolicyEngine::new();

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(repo.published_reads(), 2);
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Closed);
}

#[tokio::test]
async fn test_strict_final_reload_business_pending_repeats_keep_breaker_closed() {
    // 复读阶段的 business-pending 错误无论重复多少次都只是
    // AUTHORIZATION_PENDING，不得累积为断路器失败。
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut outcomes = Vec::new();
    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD + 1) {
        outcomes.push(Ok(Some(first.clone())));
        outcomes.push(Err(PolicyError::Repository(
                "published_card_evidence_not_ready;code=published_card_evidence.source_freshness_pending"
                    .into(),
            )));
    }
    let repo = StrictPublishedRepo::with_outcomes(outcomes);
    let engine = PolicyEngine::new();

    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD + 1) {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(
        repo.published_reads(),
        2 * (crate::circuit_breaker::CB_THRESHOLD as usize + 1)
    );
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Closed);
}

#[tokio::test]
async fn test_strict_final_reload_hard_errors_open_breaker() {
    // 复读阶段的 repository 硬错误连续达到阈值后，入口断路器直接拒绝，
    // 且不再触碰 repository（复读读取次数停在阈值×2）。
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let mut outcomes = Vec::new();
    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        outcomes.push(Ok(Some(first.clone())));
        outcomes.push(Err(PolicyError::Repository(
            "published_card_evidence_query_failed;timeout".into(),
        )));
    }
    let repo = StrictPublishedRepo::with_outcomes(outcomes);
    let engine = PolicyEngine::new();

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(
        repo.published_reads(),
        2 * crate::circuit_breaker::CB_THRESHOLD as usize
    );

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "CIRCUIT_BREAKER_OPEN");
    assert_eq!(
        repo.published_reads(),
        2 * crate::circuit_breaker::CB_THRESHOLD as usize
    );
}

#[tokio::test]
async fn test_strict_initial_load_hard_errors_open_breaker() {
    // 初次证据读取的硬错误同样计入断路器失败；达到阈值后入口直接拒绝。
    let repo = StrictPublishedRepo::with_outcomes(
        (0..crate::circuit_breaker::CB_THRESHOLD)
            .map(|_| {
                Err(PolicyError::Repository(
                    "published_card_evidence_query_failed;timeout".into(),
                ))
            })
            .collect(),
    );
    let engine = PolicyEngine::new();

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    }
    assert_eq!(
        repo.published_reads(),
        crate::circuit_breaker::CB_THRESHOLD as usize
    );

    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert_eq!(decision.reason, "CIRCUIT_BREAKER_OPEN");
}

#[tokio::test]
async fn test_strict_success_resets_hard_error_streak_before_threshold() {
    // 成功评估清零失败连击：两段各 (阈值-1) 次硬错误之间夹一次完整
    // 成功，断路器全程不得打开。
    let first = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let hard_error = || {
        Err::<Option<PublishedCardAuthorization>, PolicyError>(PolicyError::Repository(
            "published_card_evidence_query_failed;timeout".into(),
        ))
    };
    let mut outcomes = Vec::new();
    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD - 1) {
        outcomes.push(Ok(Some(first.clone())));
        outcomes.push(hard_error());
    }
    // 成功评估：initial load 与 final reload 返回同一证据。
    outcomes.push(Ok(Some(first.clone())));
    outcomes.push(Ok(Some(first.clone())));
    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD - 1) {
        outcomes.push(Ok(Some(first.clone())));
        outcomes.push(hard_error());
    }
    let repo = StrictPublishedRepo::with_outcomes(outcomes);
    let engine = PolicyEngine::new();

    for _ in 0..(2 * (crate::circuit_breaker::CB_THRESHOLD as usize - 1) + 1) {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert_ne!(
            decision.reason, "CIRCUIT_BREAKER_OPEN",
            "success must reset the failure streak"
        );
    }
}

// ===== strict gate evidence-read behavior =====

/// Repeated evaluations verify that the current gate performs only the
/// authoritative evidence reads required by the decision.
const STRICT_EVALUATION_LOOP: usize = 1000;

#[tokio::test]
async fn test_strict_allow_loop_uses_only_initial_and_final_evidence_reads() {
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();
    let ctx = strict_ctx();

    for _ in 0..STRICT_EVALUATION_LOOP {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "published ALLOW must remain correct, got {:?}",
            decision.reason
        );
        assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    }

    // Each strict ALLOW reads initial evidence and rereads it before returning.
    assert_eq!(repo.published_reads(), STRICT_EVALUATION_LOOP * 2);
}

#[tokio::test]
async fn test_strict_fail_closed_loop_uses_initial_evidence_read_only() {
    // Evidence without a matching grant returns DEFAULT_DENY after the initial read.
    let evidence = strict_ready_evidence(vec![strict_published_grant(
        "550e8400-e29b-41d4-a716-446655440002",
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_course:9",
        "read",
    )]);
    let repo = StrictPublishedRepo::with_evidence(evidence);
    let engine = PolicyEngine::new();

    for _ in 0..STRICT_EVALUATION_LOOP {
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert!(
            !decision.allowed,
            "no-match must stay fail-closed, got {:?}",
            decision.reason
        );
        assert_eq!(decision.reason, "DEFAULT_DENY");
    }

    // No match reads initial evidence only; there is no ALLOW-time reread.
    assert_eq!(repo.published_reads(), STRICT_EVALUATION_LOOP);
}

#[test]
fn published_recheck_identity_rejects_tenant_card_drift() {
    let baseline = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let matched = baseline.effective_grants[0].clone();

    // next == baseline 且与请求身份一致 → 复读稳定。
    assert!(published_recheck_identity_stable(
        &baseline, &baseline, 7, 1, &matched
    ));

    // 请求身份漂移（即使 next == baseline）→ 复读不稳定。
    assert!(!published_recheck_identity_stable(
        &baseline, &baseline, 8, 1, &matched
    ));
    assert!(!published_recheck_identity_stable(
        &baseline, &baseline, 7, 2, &matched
    ));

    // next 证据自身携带漂移的 tenant/card → 与 baseline 身份不等，拒绝。
    let mut tenant_drifted = baseline.clone();
    tenant_drifted.tenant_id = 9;
    assert!(!published_recheck_identity_stable(
        &baseline,
        &tenant_drifted,
        9,
        1,
        &matched
    ));
    let mut card_drifted = baseline.clone();
    card_drifted.card_id = 2;
    assert!(!published_recheck_identity_stable(
        &baseline,
        &card_drifted,
        7,
        2,
        &matched
    ));
}

#[test]
fn published_recheck_rejects_same_generation_seal_drift() {
    let baseline = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let matched = baseline.effective_grants[0].clone();
    let mut next = baseline.clone();
    next.manifests[0].seal = astral_types::PublicationSeal::from_unix_seconds(
        baseline.manifests[0].seal.unix_seconds() + 1,
    )
    .unwrap();
    assert_eq!(
        baseline.manifests[0].generation,
        next.manifests[0].generation
    );
    assert!(!published_recheck_identity_stable(
        &baseline, &next, 7, 1, &matched
    ));
}

#[test]
fn published_recheck_rejects_same_generation_hash_drift_and_invalid_stamp() {
    let baseline = strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )]);
    let matched = baseline.effective_grants[0].clone();
    for digest in ["d".repeat(64), "D".repeat(64), String::new()] {
        let mut next = baseline.clone();
        next.manifests[0].manifest_digest_hex = digest;
        assert_eq!(
            baseline.manifests[0].generation,
            next.manifests[0].generation
        );
        assert!(!published_recheck_identity_stable(
            &baseline, &next, 7, 1, &matched
        ));
    }
    let mut next = baseline.clone();
    next.manifests[0].generation = 0;
    assert!(!published_recheck_identity_stable(
        &baseline, &next, 7, 1, &matched
    ));
}

// ===== allow_source_phase 命中来源归因（hit-stat source）=====

#[test]
fn test_allow_source_phase_org_allow_reports_org_authority() {
    // ORG_SCOPE ALLOW steps carry ORG_PERSONAL/ORG_SHARED and map to the
    // dedicated ORG_AUTHORITY hit category.
    for org_source in ["ORG_PERSONAL", "ORG_SHARED"] {
        let decision = allow(
            "ORG_PUBLISHED_EVIDENCE_ALLOW",
            "org-grant-1",
            vec![
                step("AUTHN", "ALLOW", "card active", None),
                step(
                    "ORG_AUTHORITY",
                    "ALLOW",
                    "org_scope contribution matched",
                    Some(org_source.to_string()),
                ),
            ],
        );
        assert_eq!(
            PolicyEngine::allow_source_phase(&decision),
            Some("ORG_AUTHORITY"),
            "ORG_ALLOW (source={org_source}) must be attributed to ORG_AUTHORITY"
        );
    }

    // Hit attribution follows the latest ALLOW: an earlier phase cannot mask
    // the subsequent ORG_AUTHORITY ALLOW.
    let decision = allow(
        "ORG_PUBLISHED_EVIDENCE_ALLOW",
        "org-grant-1",
        vec![
            step("PUBLISHED_EVIDENCE", "ALLOW", "earlier allow", None),
            step("ORG_AUTHORITY", "DENY", "recheck pending", None),
            step(
                "ORG_AUTHORITY",
                "ALLOW",
                "org_scope contribution matched",
                Some("ORG_SHARED".to_string()),
            ),
        ],
    );
    assert_eq!(
        PolicyEngine::allow_source_phase(&decision),
        Some("ORG_AUTHORITY")
    );
}

#[test]
fn allow_source_phase_reports_only_current_v6_sources() {
    let published_cases: &[(&str, &str)] = &[
        ("RULE_SET_BASE", "RULE_SET"),
        ("RULE_SET_OVERLAY", "RULE_SET"),
        ("DIRECT", "DIRECT"),
        ("APPROVAL", "APPROVAL"),
        ("DELEGATION", "DELEGATION"),
    ];
    for (source, expected) in published_cases {
        let decision = allow(
            "PUBLISHED_EVIDENCE_ALLOW",
            "grant-1",
            vec![step(
                "PUBLISHED_EVIDENCE",
                "ALLOW",
                "hit",
                Some(source.to_string()),
            )],
        );
        assert_eq!(
            PolicyEngine::allow_source_phase(&decision),
            Some(*expected),
            "CURRENT V6 source {source} mapping"
        );
    }

    let org_allow = allow(
        "ORG_PUBLISHED_EVIDENCE_ALLOW",
        "org-grant-1",
        vec![step(
            "ORG_AUTHORITY",
            "ALLOW",
            "org_scope contribution matched",
            Some("ORG_SHARED".to_owned()),
        )],
    );
    assert_eq!(
        PolicyEngine::allow_source_phase(&org_allow),
        Some("ORG_AUTHORITY")
    );

    // Retired phases and reserved SYSTEM provenance have no current hit source.
    let retired = allow(
        "ALLOW",
        "retired-rule",
        vec![step("SNAPSHOT", "ALLOW", "hit", None)],
    );
    assert_eq!(PolicyEngine::allow_source_phase(&retired), None);
    let reserved_system = allow(
        "PUBLISHED_EVIDENCE_ALLOW",
        "grant-1",
        vec![step(
            "PUBLISHED_EVIDENCE",
            "ALLOW",
            "hit",
            Some("SYSTEM".to_owned()),
        )],
    );
    assert_eq!(PolicyEngine::allow_source_phase(&reserved_system), None);

    let denied = deny(
        "DEFAULT_DENY",
        "denied",
        vec![step(
            "ORG_AUTHORITY",
            "DENY",
            "org_scope.no_matching_contribution",
            None,
        )],
    );
    assert_eq!(PolicyEngine::allow_source_phase(&denied), None);
}

// ===== ORG_SCOPE admission gate regression coverage =====
//
// Cover public evaluate() scheduling for authoritative ORG reads:
// managed states fail closed before card evidence, Unmanaged uses strict CURRENT V6
// evidence, and Ready requires the ORG proof's final reread.

/// 行政单元（签名 actor）租户与身份四元组（org_admission 夹具同源）。
const ORG_GATE_TENANT: i64 = 100;
const ORG_GATE_USER_ID: i64 = 11;
const ORG_GATE_IDENTITY_CARD_ID: i64 = 111;
const ORG_GATE_CARD_ID: i64 = 222;
/// 统一读取时钟：落在 grant validity (1000..2000) 与 membership 窗口内。
const ORG_GATE_READ_CLOCK: i64 = 1_500;

/// ORG_SCOPE test repository with a potentially authorizing CURRENT V6 card
/// evidence fixture. Tests assert that managed ORG outcomes take precedence.
struct OrgGateSwitchRepo {
    org_read: OrgAuthorityRead,
    published_evidence: std::sync::Arc<PublishedCardAuthorization>,
    org_reads: AtomicUsize,
    published_reads: AtomicUsize,
}

impl OrgGateSwitchRepo {
    fn new(org_read: OrgAuthorityRead) -> Self {
        Self {
            org_read,
            published_evidence: std::sync::Arc::new(org_gate_strict_allow_evidence()),
            org_reads: AtomicUsize::new(0),
            published_reads: AtomicUsize::new(0),
        }
    }

    fn org_reads(&self) -> usize {
        self.org_reads.load(Ordering::SeqCst)
    }

    fn published_reads(&self) -> usize {
        self.published_reads.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl RuleRepository for OrgGateSwitchRepo {
    async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
        Ok(true)
    }

    async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
        Ok(false)
    }

    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError> {
        self.published_reads.fetch_add(1, Ordering::SeqCst);
        Ok(Some(std::sync::Arc::clone(&self.published_evidence)))
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        self.org_reads.fetch_add(1, Ordering::SeqCst);
        Ok(self.org_read.clone())
    }
}

/// 与 `strict_ctx` 身份逐项匹配的 would-allow published evidence 夹具。
fn org_gate_strict_allow_evidence() -> PublishedCardAuthorization {
    strict_ready_evidence(vec![strict_published_grant(
        STRICT_RULESET_BASE_GRANT_ID,
        astral_types::GrantSourceKind::RuleSet,
        astral_types::BindingLayer::Base,
        "learn_subject:42",
        "read",
    )])
}

/// Public-entry fixture aligned with admission evidence membership. It uses
/// resolver-equivalent tenant-scoped target facts rather than the internal
/// compatibility fallback.
fn org_gate_ctx() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(ORG_GATE_USER_ID))
        .identity_card_id(Some(ORG_GATE_IDENTITY_CARD_ID))
        .card_id(Some(ORG_GATE_CARD_ID))
        .tenant_id(Some(ORG_GATE_TENANT))
        .resource_tenant_id(Some(ORG_GATE_TENANT))
        .resource_ownership_scope(ResourceOwnershipScope::TenantScoped)
        .resource(Some("doc".into()))
        .target_id(Some(42))
        .action("read".into())
        .build()
}

/// 密封的单贡献 admission 证据（根单元自源共享 grant，org_admission 夹具同源）。
fn org_gate_admission_evidence() -> OrgAdmissionEvidence {
    let grant_value = OrgGrant {
        grant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
        revision: 1,
        receiving_tenant_id: ORG_GATE_TENANT,
        origin_tenant_id: ORG_GATE_TENANT,
        root_tenant_id: ORG_GATE_TENANT,
        scope: OrgScope {
            resource_tenant_id: ORG_GATE_TENANT,
            domain_id: None,
            resource: "doc:42".to_owned(),
            action: "read".to_owned(),
            validity: ValidityWindow::between(1_000, 2_000),
        },
        delegable: true,
        parent: None,
        subject: None,
        active: true,
        operation_id: "op-grant-1".to_owned(),
    };
    let contribution = OrgContribution {
        grant_ref: OrgGrantRef {
            tenant_id: grant_value.receiving_tenant_id,
            grant_id: grant_value.grant_id.clone(),
            revision: grant_value.revision,
        },
        scope: grant_value.scope.clone(),
        delegable: grant_value.delegable,
        subject: grant_value.subject,
        provenance: OrgProvenance {
            origin_tenant_id: grant_value.origin_tenant_id,
            parent_chain: Vec::new(),
            operation_id: grant_value.operation_id.clone(),
        },
    };
    let segment = org_build_segment(
        0,
        OrgSegmentContent {
            key: OrgScopeKey {
                resource: "doc:42".to_owned(),
                action: "read".to_owned(),
            },
            contributions: vec![contribution],
        },
    )
    .expect("segment must build");
    let publication = OrgPublication {
        tenant_id: ORG_GATE_TENANT,
        root_tenant_id: ORG_GATE_TENANT,
        generation: 3,
        relationship_revision: 2,
        revoke_fence: 1,
        dependencies: Vec::new(),
        manifest_digest_hex: String::new(),
        compiler_version: astral_types::AUTHORIZATION_ORG_COMPILER_VERSION.to_owned(),
        segments: vec![segment],
        operation_id: "op-publish-1".to_owned(),
    };
    let manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
        tenant_id: publication.tenant_id,
        root_tenant_id: publication.root_tenant_id,
        generation: publication.generation,
        relationship_revision: publication.relationship_revision,
        revoke_fence: publication.revoke_fence,
        dependencies: &publication.dependencies,
        segments: &publication.segments,
        compiler_version: &publication.compiler_version,
        operation_id: &publication.operation_id,
    })
    .expect("manifest digest must compute");
    OrgAdmissionEvidence {
        publication: OrgPublication {
            manifest_digest_hex,
            ..publication
        },
        node: OrgNode {
            tenant_id: ORG_GATE_TENANT,
            root_tenant_id: ORG_GATE_TENANT,
            parent_tenant_id: None,
            generation: 3,
            revoke_fence: 1,
            relationship_revision: 2,
            active: true,
            operation_id: "op-node-1".to_owned(),
            root_activation: Some(OrgRootActivation {
                operator_user_id: 7,
                approval_operation_id: "op-approve-root".to_owned(),
            }),
        },
        membership: OrgMembership {
            membership_id: "00000000-0000-0000-0000-000000000009".to_owned(),
            tenant_id: ORG_GATE_TENANT,
            root_tenant_id: ORG_GATE_TENANT,
            user_id: ORG_GATE_USER_ID,
            identity_card_id: ORG_GATE_IDENTITY_CARD_ID,
            card_id: ORG_GATE_CARD_ID,
            revision: 1,
            active: true,
            validity: ValidityWindow::between(0, 9_999),
            operation_id: "op-member-1".to_owned(),
        },
        checked_at_unix: ORG_GATE_READ_CLOCK,
    }
}

fn org_gate_last_step(decision: &PolicyDecision) -> &EvaluationStep {
    decision
        .evaluation_path
        .last()
        .expect("decision must carry at least one evaluation step")
}

#[tokio::test]
async fn test_org_gate_disabled_denies_before_card_evidence() {
    // A managed tenant whose ORG gate is disabled must deny before consulting
    // otherwise authorizing CURRENT V6 card evidence.
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Disabled);
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed, "Disabled 必须拒绝: {decision:?}");
    assert_eq!(decision.reason, "ORG_AUTHORITY_DISABLED");
    assert!(decision.matched_rule.is_none());
    assert!(decision.org_provenance.is_none());
    assert!(decision.audit_required);
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "ORG_AUTHORITY");
    assert_eq!(last.result, Effect::Deny);
    assert_eq!(last.source, None);
    assert_eq!(
        last.detail,
        "managed authority cannot fall back to card evidence"
    );
    let phases: Vec<&str> = decision
        .evaluation_path
        .iter()
        .map(|s| s.phase.as_str())
        .collect();
    assert_eq!(
        phases,
        vec!["AUTHN", "CARD_CONTEXT", "ORG_AUTHORITY"],
        "Disabled must short-circuit before card evidence"
    );
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(
        repo.published_reads(),
        0,
        "Disabled 不得触碰 strict published evidence 读取器"
    );
}

#[tokio::test]
async fn test_org_gate_pending_fails_closed_without_card_fallback() {
    // Pending preserves the stable ORG detail and rejects despite a matching
    // CURRENT V6 card grant, proving that managed tenants cannot fall back.
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Pending {
        code: "org_gate.membership_pending".to_owned(),
    });
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert!(!decision.allowed, "Pending 必须 fail-closed: {decision:?}");
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert!(decision.matched_rule.is_none());
    assert!(decision.org_provenance.is_none());
    assert!(decision.audit_required);
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "ORG_AUTHORITY");
    assert_eq!(last.result, Effect::Deny);
    assert_eq!(last.detail, "org_gate.membership_pending");
    let phases: Vec<&str> = decision
        .evaluation_path
        .iter()
        .map(|s| s.phase.as_str())
        .collect();
    assert_eq!(
        phases,
        vec!["AUTHN", "CARD_CONTEXT", "ORG_AUTHORITY"],
        "Pending must short-circuit before card evidence"
    );
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn test_resource_ownership_unresolved_short_circuits_before_org_or_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::Unresolved;

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "RESOURCE_OWNERSHIP");
    assert_eq!(last.detail, "target resource ownership was not resolved");
    assert_eq!(repo.org_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn test_resource_ownership_invalid_tenant_scope_short_circuits_before_org_or_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    ctx.resource_tenant_id = None;

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "RESOURCE_OWNERSHIP");
    assert_eq!(
        last.detail,
        "tenant-scoped target carried invalid authoritative facts"
    );
    assert_eq!(repo.org_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn test_resource_ownership_non_positive_tenant_scoped_domain_or_owner_short_circuits() {
    for (resource_domain_id, resource_owner_id) in [(Some(0), None), (None, Some(-1))] {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged);
        let mut ctx = strict_ctx();
        ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
        ctx.resource_tenant_id = Some(7);
        ctx.resource_domain_id = resource_domain_id;
        ctx.resource_owner_id = resource_owner_id;

        let decision = engine.evaluate(&ctx, &repo).await;

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            org_gate_last_step(&decision).detail,
            "tenant-scoped target carried invalid authoritative facts"
        );
        assert_eq!(repo.org_reads(), 0);
        assert_eq!(repo.published_reads(), 0);
    }
}

#[tokio::test]
async fn test_resource_ownership_invalid_global_scope_short_circuits_before_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::Global;
    ctx.resource_owner_id = Some(99);

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "RESOURCE_OWNERSHIP");
    assert_eq!(last.detail, "global target carried tenant or owner facts");
    assert_eq!(repo.org_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn test_global_target_skips_org_admission_but_keeps_strict_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Disabled);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::Global;
    ctx.global_access_requirement = GlobalAccessRequirement::PolicyEvidence;

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(
        decision.allowed,
        "global target must remain authorizable: {decision:?}"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.org_reads(), 0, "global target must skip ORG admission");
    assert_eq!(repo.published_reads(), 2);
}

#[tokio::test]
async fn test_resource_ownership_unavailable_accrues_breaker_failures() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::Unavailable;

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            org_gate_last_step(&decision).detail,
            "target resource ownership resolver unavailable"
        );
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);
    assert_eq!(repo.org_reads(), 0);
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn test_org_gate_unmanaged_foreign_tenant_without_actor_tenant_short_circuits() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged);
    let mut ctx = strict_ctx();
    ctx.tenant_id = None;
    ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    ctx.resource_tenant_id = Some(900);

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(
        org_gate_last_step(&decision).detail,
        "foreign tenant target cannot use actor-card evidence"
    );
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn test_org_gate_unmanaged_foreign_tenant_target_short_circuits_strict_evidence() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    ctx.resource_tenant_id = Some(900);

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "RESOURCE_OWNERSHIP");
    assert_eq!(last.result, Effect::Deny);
    assert_eq!(
        last.detail,
        "foreign tenant target cannot use actor-card evidence"
    );
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(repo.published_reads(), 0);
}

#[tokio::test]
async fn test_org_gate_unmanaged_same_tenant_target_keeps_strict_evidence_path() {
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged);
    let mut ctx = strict_ctx();
    ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    ctx.resource_tenant_id = ctx.tenant_id;

    let decision = engine.evaluate(&ctx, &repo).await;

    assert!(
        decision.allowed,
        "same-tenant target must retain strict authorization"
    );
    assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(repo.org_reads(), 1);
    assert_eq!(repo.published_reads(), 2);
}

#[tokio::test]
async fn test_org_gate_ready_evidence_allows_via_public_entry() {
    // Ready ORG evidence takes precedence over an independently authorizing V6
    // card-evidence fixture, and is reread before ALLOW.
    let engine = PolicyEngine::new();
    let grant_id = "00000000-0000-0000-0000-000000000001";
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Ready(Box::new(
        org_gate_admission_evidence(),
    )));
    let decision = engine.evaluate(&org_gate_ctx(), &repo).await;
    assert!(
        decision.allowed,
        "Ready ORG evidence should allow: {decision:?}"
    );
    assert_eq!(decision.reason, "ORG_PUBLISHED_EVIDENCE_ALLOW");
    assert_eq!(decision.matched_rule.as_deref(), Some(grant_id));
    assert!(decision.org_provenance.is_some());
    let last = org_gate_last_step(&decision);
    assert_eq!(last.phase, "ORG_AUTHORITY");
    assert_eq!(last.result, Effect::Allow);
    assert_eq!(last.source.as_deref(), Some("ORG_SHARED"));
    let phases: Vec<&str> = decision
        .evaluation_path
        .iter()
        .map(|s| s.phase.as_str())
        .collect();
    assert_eq!(phases, vec!["AUTHN", "CARD_CONTEXT", "ORG_AUTHORITY"]);
    assert_eq!(
        repo.org_reads(),
        2,
        "Ready requires initial + final ORG reads"
    );
    assert_eq!(repo.published_reads(), 0);
}

// ===== ORG_SCOPE 门禁记账（stats/断路器，进程内 stub，不触碰数据库） =====
//
// 修复回归：门禁 Disabled/Pending/Err/Ready 分支此前不做任何
// record_evaluation / 断路器记账，导致 ORG 决策从统计中消失、org 读取
// 失败永不累计断路器失败。以下测试经公共 seam（get_stats /
// circuit_breaker_state）证明每个门禁结局都恰好记账一次，且成败归类正确。

/// ORG 权威读取恒失败的仓库：断路器失败累计/成功清零的对照。
struct OrgGateErrRepo {
    org_reads: AtomicUsize,
}

impl OrgGateErrRepo {
    fn new() -> Self {
        Self {
            org_reads: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl RuleRepository for OrgGateErrRepo {
    async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
        Ok(true)
    }

    async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
        Ok(false)
    }

    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError> {
        Ok(None)
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        self.org_reads.fetch_add(1, Ordering::SeqCst);
        Err(PolicyError::Repository("org_authority_read_failed".into()))
    }
}

/// Ready 分支内部读取行为可控的仓库：首次 org 读取恒 Ready（预置证据），
/// 之后的读取返回预设结果（ALLOW 前复读触发），首次之后的卡片上下文校验
/// 可设为 Err。每次评估需使用全新实例（读取/校验计数区分初次与终局）。
struct OrgGateReadyProbeRepo {
    evidence: OrgAdmissionEvidence,
    /// 首次之后的 org 读取：`Some(read)` → `Ok(read)`；`None` → Err
    /// （复读不可用；PolicyError 未实现 Clone，错误侧按同义错误重建）。
    reread: Option<OrgAuthorityRead>,
    /// 首次之后的卡片上下文校验是否失败（admission 内终局校验 Err）。
    card_active_err: bool,
    org_reads: AtomicUsize,
    card_checks: AtomicUsize,
}

impl OrgGateReadyProbeRepo {
    fn new(reread: Option<OrgAuthorityRead>, card_active_err: bool) -> Self {
        Self {
            evidence: org_gate_admission_evidence(),
            reread,
            card_active_err,
            org_reads: AtomicUsize::new(0),
            card_checks: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl RuleRepository for OrgGateReadyProbeRepo {
    async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
        let check_index = self.card_checks.fetch_add(1, Ordering::SeqCst);
        if self.card_active_err && check_index > 0 {
            Err(PolicyError::Repository("card_context_read_failed".into()))
        } else {
            Ok(true)
        }
    }

    async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
        Ok(false)
    }

    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError> {
        Ok(None)
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        // 以读取计数区分初始读取与复读（单线程单评估断言，无并发竞争）。
        let read_index = self.org_reads.fetch_add(1, Ordering::SeqCst);
        if read_index == 0 {
            Ok(OrgAuthorityRead::Ready(Box::new(self.evidence.clone())))
        } else {
            match &self.reread {
                Some(read) => Ok(read.clone()),
                None => Err(PolicyError::Repository("org_reread_failed".into())),
            }
        }
    }
}

/// 断路器失败计数预热：阈值-1 次门禁 Err 失败（仍闭合，计数=阈值-1）。
async fn seed_breaker_failures_below_threshold(engine: &PolicyEngine) {
    let repo = OrgGateErrRepo::new();
    let ctx = strict_ctx();
    for _ in 0..(crate::circuit_breaker::CB_THRESHOLD - 1) {
        engine.evaluate(&ctx, &repo).await;
    }
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "阈值之下的失败不得打开断路器"
    );
}

#[tokio::test]
async fn test_org_gate_read_error_accrues_breaker_failures_and_opens() {
    // Err：org 权威读取不可用必须累计断路器失败并打开断路器。
    let engine = PolicyEngine::new();
    let repo = OrgGateErrRepo::new();
    let ctx = strict_ctx();

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            org_gate_last_step(&decision).detail,
            "org_scope.read_unavailable"
        );
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);

    // 打开后短路降级：不再触达 org 读取器，返回降级 DENY。
    let fallback = engine.evaluate(&ctx, &repo).await;
    assert_eq!(fallback.reason, "CIRCUIT_BREAKER_OPEN");
    assert_eq!(
        repo.org_reads.load(Ordering::SeqCst),
        crate::circuit_breaker::CB_THRESHOLD as usize,
    );

    // Every completed evaluation is counted once, and all outcomes denied.
    let stats = engine.get_stats();
    assert_eq!(
        stats.evaluation_count,
        crate::circuit_breaker::CB_THRESHOLD as u64
    );
    assert_eq!(stats.allow_count, 0);
    assert_eq!(
        stats.deny_count,
        crate::circuit_breaker::CB_THRESHOLD as u64
    );
    assert!(stats.timing_ns.total_ns > 0);
}

#[tokio::test]
async fn test_org_gate_unavailable_accrues_breaker_failures_and_opens() {
    // Unavailable is an explicit infrastructure failure, distinct from
    // completed business Pending, and contributes to the breaker.
    let engine = PolicyEngine::new();
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unavailable {
        code: "org_scope.pending.reader_unavailable".into(),
    });
    let ctx = strict_ctx();

    for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            org_gate_last_step(&decision).detail,
            "org_scope.pending.reader_unavailable"
        );
    }
    assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);

    let fallback = engine.evaluate(&ctx, &repo).await;
    assert_eq!(fallback.reason, "CIRCUIT_BREAKER_OPEN");
    assert_eq!(
        repo.org_reads(),
        crate::circuit_breaker::CB_THRESHOLD as usize,
        "the open breaker must short-circuit before another ORG read"
    );
    assert_eq!(repo.published_reads(), 0);

    let stats = engine.get_stats();
    assert_eq!(
        stats.evaluation_count,
        crate::circuit_breaker::CB_THRESHOLD as u64
    );
    assert_eq!(stats.allow_count, 0);
    assert_eq!(
        stats.deny_count,
        crate::circuit_breaker::CB_THRESHOLD as u64
    );
}

#[tokio::test]
async fn test_org_gate_disabled_records_success_not_failure() {
    // Disabled：确定性管理态关闭 → 记成功 + 记账恰好一次。
    // 模式：阈值-1 次 Err 失败 → 被测评估（记成功则清零计数）→ 1 次 Err
    // 失败；若被测评估未记成功，最后一次失败会到阈值并打开断路器。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Disabled);
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert_eq!(decision.reason, "ORG_AUTHORITY_DISABLED");
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "Disabled 必须记成功（清零失败计数），不得记依赖失败"
    );
    // Threshold-1 failed reads, Disabled, and one final failed read are counted.
    let stats = engine.get_stats();
    assert_eq!(
        stats.evaluation_count,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.allow_count, 0);
    assert_eq!(
        stats.deny_count,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert!(stats.timing_ns.total_ns > 0);
}

#[tokio::test]
async fn test_org_gate_pending_records_success_not_failure() {
    // Pending：读取已成功（Ok），业务 pending 是确定性授权结果 → 记成功。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Pending {
        code: "org_gate.membership_pending".into(),
    });
    let decision = engine.evaluate(&strict_ctx(), &repo).await;
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(
        org_gate_last_step(&decision).detail,
        "org_gate.membership_pending"
    );
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "Pending 必须记成功（清零失败计数），不得记依赖失败"
    );
    let stats = engine.get_stats();
    assert_eq!(
        stats.evaluation_count,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.allow_count, 0);
    assert_eq!(
        stats.deny_count,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
}

#[tokio::test]
async fn test_org_gate_ready_allow_records_success_and_evaluation() {
    // Ready ALLOW：确定性授权结果 → 记成功，且记账恰好一次。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Ready(Box::new(
        org_gate_admission_evidence(),
    )));
    let decision = engine.evaluate(&org_gate_ctx(), &repo).await;
    assert!(decision.allowed);
    assert_eq!(decision.reason, "ORG_PUBLISHED_EVIDENCE_ALLOW");
    assert!(decision.org_provenance.is_some());
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "Ready ALLOW 必须记成功（清零失败计数），不得记依赖失败"
    );
    let stats = engine.get_stats();
    assert_eq!(
        stats.evaluation_count,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.allow_count, 1);
    assert_eq!(
        stats.deny_count,
        crate::circuit_breaker::CB_THRESHOLD as u64
    );
    assert!(stats.timing_ns.total_ns > 0);
}

#[tokio::test]
async fn test_org_gate_ready_default_deny_records_success_not_failure() {
    // Ready 分支的正常 DEFAULT_DENY（无匹配贡献）是确定性授权结果，
    // 绝不能记为依赖失败。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Ready(Box::new(
        org_gate_admission_evidence(),
    )));
    // 请求 doc:43 → 段键 doc:42 无匹配贡献 → DEFAULT_DENY。
    let mut ctx = org_gate_ctx();
    ctx.target_id = Some(43);
    let decision = engine.evaluate(&ctx, &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "DEFAULT_DENY");
    assert_eq!(
        org_gate_last_step(&decision).detail,
        "org_scope.no_matching_contribution"
    );
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "正常 DEFAULT_DENY 必须记成功，不得记依赖失败"
    );
    let stats = engine.get_stats();
    assert_eq!(
        stats.evaluation_count,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.allow_count, 0);
    assert_eq!(
        stats.deny_count,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
}

#[tokio::test]
async fn test_org_gate_ready_identity_drift_records_success_not_failure() {
    // 复读身份漂移（final_identity_changed）是确定性复检拒绝 → 记成功。
    let engine = PolicyEngine::new();
    seed_breaker_failures_below_threshold(&engine).await;
    let mut drifted = org_gate_admission_evidence();
    drifted.membership.revision += 1;
    let repo = OrgGateReadyProbeRepo::new(Some(OrgAuthorityRead::Ready(Box::new(drifted))), false);
    let decision = engine.evaluate(&org_gate_ctx(), &repo).await;
    assert!(!decision.allowed);
    assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
    assert_eq!(
        org_gate_last_step(&decision).detail,
        "org_scope.final_identity_changed"
    );
    let tail = OrgGateErrRepo::new();
    engine.evaluate(&strict_ctx(), &tail).await;
    assert_eq!(
        engine.circuit_breaker_state(),
        CircuitBreakerState::Closed,
        "确定性复检拒绝必须记成功，不得记依赖失败"
    );
    let stats = engine.get_stats();
    assert_eq!(
        stats.evaluation_count,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
    assert_eq!(stats.allow_count, 0);
    assert_eq!(
        stats.deny_count,
        crate::circuit_breaker::CB_THRESHOLD as u64 + 1
    );
}

#[tokio::test]
async fn test_org_gate_ready_internal_read_unavailable_accrues_breaker_failures() {
    // Ready 分支内两类终局读取不可用（ALLOW 前权威复读 Err / 终局卡片
    // 上下文 Err）都是基础设施路径 → 累计断路器失败并最终打开断路器。
    for (label, expected_detail, reread, card_active_err) in [
        (
            "final reread Err",
            "org_scope.final_read_unavailable",
            None,
            false,
        ),
        (
            "final card context Err",
            "org_scope.final_card_context_unavailable",
            Some(OrgAuthorityRead::Ready(Box::new(
                org_gate_admission_evidence(),
            ))),
            true,
        ),
    ] {
        let engine = PolicyEngine::new();
        let ctx = org_gate_ctx();
        for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
            // 每次评估使用全新 probe 仓库：首次读取恒 Ready，复读/卡片
            // 上下文按场景预设——保证每次评估都命中 Ready 分支内部的
            // 同一失败点（读取计数在实例内区分初始读取与复读）。
            let repo = OrgGateReadyProbeRepo::new(reread.clone(), card_active_err);
            let decision = engine.evaluate(&ctx, &repo).await;
            assert!(!decision.allowed, "{label}");
            assert_eq!(decision.reason, "AUTHORIZATION_PENDING", "{label}");
            assert_eq!(
                org_gate_last_step(&decision).detail,
                expected_detail,
                "{label}"
            );
        }
        assert_eq!(
            engine.circuit_breaker_state(),
            CircuitBreakerState::Open,
            "{label} 必须累计断路器失败"
        );
        // Every final-read/card-context infrastructure failure is counted as DENY.
        let stats = engine.get_stats();
        assert_eq!(
            stats.evaluation_count,
            crate::circuit_breaker::CB_THRESHOLD as u64,
            "{label}"
        );
        assert_eq!(stats.allow_count, 0, "{label}");
        assert_eq!(
            stats.deny_count,
            crate::circuit_breaker::CB_THRESHOLD as u64,
            "{label}"
        );
    }
}
