//! Admission of published administrative-authority evidence.

use astral_types::org_scope::{
    org_admission_recheck_stable, org_contribution_matches_request, org_decode_segment_content,
    OrgAdmissionEvidence, OrgBranchKind, OrgBranchProvenance, OrgContribution, OrgReadRequest,
    OrgSubjectFilter,
};
use astral_types::{
    build_resource_key, Effect, EvaluationStep, PolicyContext, PolicyDecision,
    ResourceOwnershipScope,
};

use crate::RuleRepository;

#[derive(Debug, Clone)]
pub enum OrgAuthorityRead {
    /// The tenant is outside durable ORG_SCOPE management, so the caller may
    /// continue through the pre-existing authorization path.
    Unmanaged,
    /// The tenant is durably managed but the startup-frozen feature is disabled.
    Disabled,
    /// A completed ORG read established a deterministic business pending state
    /// (for example stale publication, membership mismatch, or missing proof).
    /// This remains fail-closed but is not an infrastructure dependency failure.
    Pending {
        code: String,
    },
    /// The ORG gate or authoritative evidence reader was unavailable. The engine
    /// must fail closed and record a dependency failure so outages remain visible
    /// to the circuit breaker instead of being laundered into business pending.
    Unavailable {
        code: String,
    },
    Ready(Box<OrgAdmissionEvidence>),
}

fn deny(reason: &str, detail: &str, mut steps: Vec<EvaluationStep>) -> PolicyDecision {
    steps.push(EvaluationStep {
        phase: "ORG_AUTHORITY".to_owned(),
        result: Effect::Deny,
        detail: detail.to_owned(),
        matched_rule_id: None,
        source: None,
    });
    PolicyDecision {
        allowed: false,
        reason: reason.to_owned(),
        matched_rule: None,
        audit_required: true,
        evaluation_path: steps,
        matched_rule_id: None,
        condition_results: None,
        snapshot_version: None,
        org_provenance: None,
    }
}

fn request(ctx: &PolicyContext, evidence: &OrgAdmissionEvidence) -> Option<OrgReadRequest> {
    if evidence.validate().is_err()
        || ctx.tenant_id != Some(evidence.node.tenant_id)
        || ctx.user_id != Some(evidence.membership.user_id)
        || ctx.identity_card_id != Some(evidence.membership.identity_card_id)
        || ctx.card_id != Some(evidence.membership.card_id)
        || evidence.node.generation != evidence.publication.generation
        || evidence.node.revoke_fence != evidence.publication.revoke_fence
        || evidence.node.relationship_revision != evidence.publication.relationship_revision
    {
        return None;
    }
    let (resource_tenant_id, domain_id) = match ctx.resource_ownership_scope {
        // External tenant-owned requests must consume only the facts produced by
        // the server-side resolver. `None` is never actor-tenant ownership.
        ResourceOwnershipScope::TenantScoped => (ctx.resource_tenant_id?, ctx.resource_domain_id),
        // Internal typed callers predate HTTP target resolution and remain
        // intentionally compatible; the engine rejects all unresolved HTTP
        // contexts before this function can run.
        ResourceOwnershipScope::Internal => (
            ctx.resource_tenant_id.or(ctx.tenant_id)?,
            ctx.resource_domain_id.or(ctx.domain_id),
        ),
        ResourceOwnershipScope::Global
        | ResourceOwnershipScope::Unresolved
        | ResourceOwnershipScope::Unavailable => return None,
    };
    let request = OrgReadRequest {
        resource: build_resource_key(ctx.resource.as_deref()?, ctx.target_id),
        action: ctx.action.clone(),
        resource_tenant_id,
        domain_id,
        now_unix_seconds: evidence.checked_at_unix,
    };
    request.validate().ok()?;
    Some(request)
}

fn winner(
    ctx: &PolicyContext,
    evidence: &OrgAdmissionEvidence,
) -> Result<Option<OrgContribution>, ()> {
    let request = request(ctx, evidence).ok_or(())?;
    let user_id = ctx.user_id.ok_or(())?;
    let card_id = ctx.card_id.ok_or(())?;
    for segment in &evidence.publication.segments {
        let content = org_decode_segment_content(segment).map_err(|_| ())?;
        if !astral_types::org_scope::org_resource_matches(&request.resource, &content.key.resource)
            || !astral_types::org_scope::org_action_matches(&request.action, &content.key.action)
        {
            continue;
        }
        for contribution in content.contributions {
            let subject = if contribution.subject.is_some() {
                OrgSubjectFilter::PersonalOf { user_id, card_id }
            } else {
                OrgSubjectFilter::SharedOnly
            };
            if org_contribution_matches_request(&contribution, &request, subject) {
                return Ok(Some(contribution));
            }
        }
    }
    Ok(None)
}

pub(crate) async fn evaluate<R: RuleRepository>(
    ctx: &PolicyContext,
    repo: &R,
    evidence: &OrgAdmissionEvidence,
    mut steps: Vec<EvaluationStep>,
) -> PolicyDecision {
    let selected = match winner(ctx, evidence) {
        Ok(Some(selected)) => selected,
        Ok(None) => return deny("DEFAULT_DENY", "org_scope.no_matching_contribution", steps),
        Err(()) => return deny("AUTHORIZATION_PENDING", "org_scope.evidence_invalid", steps),
    };
    let next = match repo.load_org_authorization(ctx).await {
        Ok(OrgAuthorityRead::Ready(next)) => next,
        _ => {
            return deny(
                "AUTHORIZATION_PENDING",
                "org_scope.final_read_unavailable",
                steps,
            )
        }
    };
    if !org_admission_recheck_stable(evidence, &next, &selected)
        || winner(ctx, &next).ok().flatten().as_ref() != Some(&selected)
    {
        return deny(
            "AUTHORIZATION_PENDING",
            "org_scope.final_identity_changed",
            steps,
        );
    }
    match repo.check_card_active(ctx).await {
        Ok(true) => {}
        Ok(false) => {
            return deny(
                "CARD_DISABLED",
                "org_scope.final_card_context_invalid",
                steps,
            )
        }
        Err(_) => {
            return deny(
                "AUTHORIZATION_PENDING",
                "org_scope.final_card_context_unavailable",
                steps,
            )
        }
    }
    let provenance = OrgBranchProvenance {
        receiving_tenant_id: next.publication.tenant_id,
        source_tenant_id: selected.provenance.origin_tenant_id,
        resource_tenant_id: selected.scope.resource_tenant_id,
        root_tenant_id: next.publication.root_tenant_id,
        membership_id: next.membership.membership_id.clone(),
        membership_revision: next.membership.revision,
        branch_kind: if selected.subject.is_some() {
            OrgBranchKind::Personal
        } else {
            OrgBranchKind::Shared
        },
        grant_ref: selected.grant_ref.clone(),
        publication_generation: next.publication.generation,
        manifest_digest_hex: next.publication.manifest_digest_hex.clone(),
        approval_operation_id: selected.provenance.operation_id.clone(),
    };
    if provenance.validate().is_err() {
        return deny(
            "AUTHORIZATION_PENDING",
            "org_scope.provenance_invalid",
            steps,
        );
    }
    steps.push(EvaluationStep {
        phase: "ORG_AUTHORITY".to_owned(),
        result: Effect::Allow,
        detail: format!(
            "root={};tenant={};membership_revision={};grant={};revision={}",
            provenance.root_tenant_id,
            provenance.receiving_tenant_id,
            provenance.membership_revision,
            provenance.grant_ref.grant_id,
            provenance.grant_ref.revision,
        ),
        matched_rule_id: None,
        source: Some(format!("ORG_{}", provenance.branch_kind.as_str())),
    });
    PolicyDecision {
        allowed: true,
        reason: "ORG_PUBLISHED_EVIDENCE_ALLOW".to_owned(),
        matched_rule: Some(selected.grant_ref.grant_id),
        audit_required: true,
        evaluation_path: steps,
        matched_rule_id: None,
        condition_results: None,
        snapshot_version: i64::try_from(next.publication.generation).ok(),
        org_provenance: Some(provenance),
    }
}

pub(crate) fn unavailable(
    reason: &str,
    detail: &str,
    steps: Vec<EvaluationStep>,
) -> PolicyDecision {
    deny(reason, detail, steps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::org_scope::{
        org_build_segment, org_manifest_digest_hex, OrgGrant, OrgGrantRef,
        OrgManifestDigestMaterial, OrgMembership, OrgNode, OrgProvenance, OrgPublication,
        OrgRootActivation, OrgScope, OrgScopeKey, OrgSegmentContent, OrgSubject,
    };
    use astral_types::{PolicyError, ValidityWindow};

    use crate::PermissionRule;

    /// 权威单元（行政根）租户，即签名 actor 的租户与 publication 归属租户。
    const TENANT: i64 = 100;
    /// 与本单元无关的资源租户（fail-closed 对照）。
    const FOREIGN_RESOURCE_TENANT: i64 = 900;
    const USER_ID: i64 = 11;
    const IDENTITY_CARD_ID: i64 = 111;
    const CARD_ID: i64 = 222;
    /// 统一读取时钟：落在 grant validity (1000..2000) 与 membership 窗口内。
    const READ_CLOCK: i64 = 1_500;

    /// 规范小写连字符 UUID（org_validate_stable_uuid 接受的形态；seed != 0 保证非 nil）。
    fn uuid(seed: u8) -> String {
        format!("00000000-0000-0000-0000-{seed:012}")
    }

    fn scope(resource_tenant_id: i64, domain_id: Option<i64>) -> OrgScope {
        OrgScope {
            resource_tenant_id,
            domain_id,
            resource: "doc:42".to_owned(),
            action: "read".to_owned(),
            validity: ValidityWindow::between(1_000, 2_000),
        }
    }

    /// 根单元自源共享 grant（parent None ⟹ origin == receiving）。
    fn grant(scope_value: OrgScope, seed: u8) -> OrgGrant {
        OrgGrant {
            grant_id: uuid(seed),
            revision: 1,
            receiving_tenant_id: TENANT,
            origin_tenant_id: TENANT,
            root_tenant_id: TENANT,
            scope: scope_value,
            delegable: true,
            parent: None,
            subject: None,
            active: true,
            operation_id: format!("op-grant-{seed}"),
        }
    }

    fn contribution(grant_value: &OrgGrant) -> OrgContribution {
        OrgContribution {
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
        }
    }

    /// 密封 publication（manifest digest 与段内容逐项绑定，对齐 org_scope 测试夹具）。
    fn publication_with(contributions: Vec<OrgContribution>) -> OrgPublication {
        let content = OrgSegmentContent {
            key: OrgScopeKey {
                resource: "doc:42".to_owned(),
                action: "read".to_owned(),
            },
            contributions,
        };
        let segment = org_build_segment(0, content).unwrap();
        let publication = OrgPublication {
            tenant_id: TENANT,
            root_tenant_id: TENANT,
            generation: 3,
            relationship_revision: 2,
            revoke_fence: 1,
            dependencies: Vec::new(),
            manifest_digest_hex: String::new(),
            compiler_version: "org-compiler-v1".to_owned(),
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
        .unwrap();
        OrgPublication {
            manifest_digest_hex,
            ..publication
        }
    }

    fn node() -> OrgNode {
        OrgNode {
            tenant_id: TENANT,
            root_tenant_id: TENANT,
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
        }
    }

    fn membership() -> OrgMembership {
        OrgMembership {
            membership_id: uuid(9),
            tenant_id: TENANT,
            root_tenant_id: TENANT,
            user_id: USER_ID,
            identity_card_id: IDENTITY_CARD_ID,
            card_id: CARD_ID,
            revision: 1,
            active: true,
            validity: ValidityWindow::between(0, 9_999),
            operation_id: "op-member-1".to_owned(),
        }
    }

    fn evidence(publication: OrgPublication) -> OrgAdmissionEvidence {
        OrgAdmissionEvidence {
            publication,
            node: node(),
            membership: membership(),
            checked_at_unix: READ_CLOCK,
        }
    }

    /// Internal typed-call fixture: actor fallback remains compatible only for
    /// `ResourceOwnershipScope::Internal`; HTTP contexts must use the explicit
    /// tenant-scoped helper below.
    fn ctx(
        tenant_id: Option<i64>,
        resource_tenant_id: Option<i64>,
        domain_id: Option<i64>,
        resource_domain_id: Option<i64>,
    ) -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(USER_ID))
            .identity_card_id(Some(IDENTITY_CARD_ID))
            .card_id(Some(CARD_ID))
            .tenant_id(tenant_id)
            .resource_tenant_id(resource_tenant_id)
            .domain_id(domain_id)
            .resource_domain_id(resource_domain_id)
            .resource_ownership_scope(ResourceOwnershipScope::Internal)
            .resource(Some("doc".to_owned()))
            .target_id(Some(42))
            .action("read".to_owned())
            .build()
    }

    fn tenant_scoped_ctx(
        tenant_id: Option<i64>,
        resource_tenant_id: Option<i64>,
        domain_id: Option<i64>,
        resource_domain_id: Option<i64>,
    ) -> PolicyContext {
        let mut context = ctx(tenant_id, resource_tenant_id, domain_id, resource_domain_id);
        context.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
        context
    }

    /// 最小测试仓库：复读返回固定证据，卡片上下文可控。
    struct OrgTestRepo {
        next: OrgAuthorityRead,
        card_active: bool,
    }

    #[async_trait::async_trait]
    impl RuleRepository for OrgTestRepo {
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }

        async fn load_org_authorization(
            &self,
            _ctx: &PolicyContext,
        ) -> Result<OrgAuthorityRead, PolicyError> {
            Ok(self.next.clone())
        }

        async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
            Ok(self.card_active)
        }
    }

    fn ready(evidence_value: OrgAdmissionEvidence) -> OrgAuthorityRead {
        OrgAuthorityRead::Ready(Box::new(evidence_value))
    }

    fn last_step(decision: &PolicyDecision) -> &EvaluationStep {
        decision
            .evaluation_path
            .last()
            .expect("decision must carry at least one evaluation step")
    }

    fn single_contribution_evidence(resource_tenant_id: i64) -> OrgAdmissionEvidence {
        let grant_value = grant(scope(resource_tenant_id, None), 1);
        evidence(publication_with(vec![contribution(&grant_value)]))
    }

    fn personal_contribution_evidence(user_id: i64, card_id: i64) -> OrgAdmissionEvidence {
        let mut grant_value = grant(scope(TENANT, None), 5);
        grant_value.subject = Some(OrgSubject { user_id, card_id });
        evidence(publication_with(vec![contribution(&grant_value)]))
    }

    // ── 1) Internal typed callers retain actor fallback only ──

    #[test]
    fn internal_request_falls_back_to_signed_actor_tenant_and_domain() {
        let evidence_value = single_contribution_evidence(TENANT);

        let base = ctx(Some(TENANT), None, None, None);
        let request_value = request(&base, &evidence_value)
            .expect("actor-tenant fallback must produce a valid request");
        assert_eq!(request_value.resource, "doc:42");
        assert_eq!(request_value.action, "read");
        assert_eq!(request_value.resource_tenant_id, TENANT);
        assert_eq!(request_value.domain_id, None);
        assert_eq!(request_value.now_unix_seconds, READ_CLOCK);

        // domain 同样回退：resource_domain_id 缺失时使用签名 actor 的 domain_id。
        let with_actor_domain = ctx(Some(TENANT), None, Some(5), None);
        let request_value = request(&with_actor_domain, &evidence_value).unwrap();
        assert_eq!(request_value.domain_id, Some(5));
    }

    // ── 2) TenantScoped requests use only resolver facts ──

    #[test]
    fn tenant_scoped_request_requires_authoritative_target_facts() {
        let evidence_value = single_contribution_evidence(TENANT);

        let missing_target = tenant_scoped_ctx(Some(TENANT), None, Some(5), None);
        assert!(
            request(&missing_target, &evidence_value).is_none(),
            "tenant-scoped HTTP context must not fall back to actor tenant"
        );

        let scoped = tenant_scoped_ctx(Some(TENANT), Some(TENANT), Some(5), None);
        let request_value = request(&scoped, &evidence_value)
            .expect("resolver tenant must form an admission request");
        assert_eq!(request_value.resource_tenant_id, TENANT);
        assert_eq!(request_value.domain_id, None);
    }

    #[test]
    fn tenant_scoped_request_never_falls_back_to_actor_domain() {
        let domain_evidence = evidence(publication_with(vec![contribution(&grant(
            scope(TENANT, Some(5)),
            2,
        ))]));
        let scoped = tenant_scoped_ctx(Some(TENANT), Some(TENANT), Some(5), None);
        let request_value = request(&scoped, &domain_evidence)
            .expect("tenant-scoped resolver facts must form a request");
        assert_eq!(request_value.domain_id, None);
        assert!(winner(&scoped, &domain_evidence).ok().flatten().is_none());
    }

    #[test]
    fn non_target_scopes_do_not_form_org_admission_requests() {
        let evidence_value = single_contribution_evidence(TENANT);
        for scope in [
            ResourceOwnershipScope::Global,
            ResourceOwnershipScope::Unresolved,
            ResourceOwnershipScope::Unavailable,
        ] {
            let mut context = ctx(Some(TENANT), Some(TENANT), Some(5), Some(5));
            context.resource_ownership_scope = scope;
            assert!(
                request(&context, &evidence_value).is_none(),
                "{scope:?} must not enter ORG admission"
            );
        }
    }

    // ── 3) Explicit authoritative target facts take precedence ──

    #[test]
    fn explicit_resource_tenant_and_domain_take_precedence() {
        // 显式值与单元作用域一致 → 正常匹配。
        let evidence_value = single_contribution_evidence(TENANT);
        let agreeing = tenant_scoped_ctx(Some(TENANT), Some(TENANT), None, None);
        assert!(winner(&agreeing, &evidence_value).ok().flatten().is_some());

        // 显式权威 resource_tenant_id 覆盖签名 actor 租户：请求按权威值构造，
        // 与作用域不一致时绝不回退 actor 租户匹配。
        let conflicting = tenant_scoped_ctx(Some(TENANT), Some(999), None, None);
        let request_value = request(&conflicting, &evidence_value)
            .expect("explicit tenant must still form a request");
        assert_eq!(request_value.resource_tenant_id, 999);
        assert!(winner(&conflicting, &evidence_value)
            .ok()
            .flatten()
            .is_none());

        // domain：显式 resource_domain_id 覆盖 actor domain_id。
        let domain_evidence = evidence(publication_with(vec![contribution(&grant(
            scope(TENANT, Some(5)),
            2,
        ))]));
        let actor_domain = tenant_scoped_ctx(Some(TENANT), Some(TENANT), Some(5), Some(5));
        assert!(winner(&actor_domain, &domain_evidence)
            .ok()
            .flatten()
            .is_some());

        let resource_domain = tenant_scoped_ctx(Some(TENANT), Some(TENANT), Some(5), Some(7));
        let request_value = request(&resource_domain, &domain_evidence).unwrap();
        assert_eq!(request_value.domain_id, Some(7));
        assert!(winner(&resource_domain, &domain_evidence)
            .ok()
            .flatten()
            .is_none());
    }

    // ── 3) 作用域钉在其他资源租户的贡献绝不匹配（fail closed）──

    #[tokio::test]
    async fn foreign_resource_tenant_contribution_fails_closed() {
        let foreign = single_contribution_evidence(FOREIGN_RESOURCE_TENANT);
        let content = org_decode_segment_content(&foreign.publication.segments[0]).unwrap();
        let scoped = &content.contributions[0];

        // 纯匹配器单元证明：请求解析为 actor 租户 100 ≠ 作用域租户 900 → 不匹配。
        let fallback_ctx = ctx(Some(TENANT), None, None, None);
        let request_value = request(&fallback_ctx, &foreign).unwrap();
        assert_eq!(request_value.resource_tenant_id, TENANT);
        assert!(!org_contribution_matches_request(
            scoped,
            &request_value,
            OrgSubjectFilter::SharedOnly
        ));

        // evaluate 端到端：无匹配贡献 → DEFAULT_DENY，绝不 ALLOW。
        let repo = OrgTestRepo {
            next: ready(foreign.clone()),
            card_active: true,
        };
        let decision = evaluate(&fallback_ctx, &repo, &foreign, Vec::new()).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "DEFAULT_DENY");
        assert!(decision.matched_rule.is_none());
        assert!(decision.org_provenance.is_none());
        assert_eq!(
            last_step(&decision).detail,
            "org_scope.no_matching_contribution"
        );
        assert_eq!(last_step(&decision).result, Effect::Deny);

        // 显式权威解析为 actor 租户同样无法命中异租户作用域。
        let explicit_ctx = tenant_scoped_ctx(Some(TENANT), Some(TENANT), None, None);
        let decision = evaluate(&explicit_ctx, &repo, &foreign, Vec::new()).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "DEFAULT_DENY");
        assert_eq!(
            last_step(&decision).detail,
            "org_scope.no_matching_contribution"
        );
    }

    // ── 4) 畸形 / 身份不一致证据 → Pending/Deny，绝不 ALLOW ──

    #[tokio::test]
    async fn malformed_or_identity_inconsistent_evidence_never_allows() {
        let base_publication = publication_with(vec![contribution(&grant(scope(TENANT, None), 4))]);
        let evidence_value = evidence(base_publication.clone());
        let repo = OrgTestRepo {
            next: ready(evidence_value.clone()),
            card_active: true,
        };

        let assert_pending = |decision: &PolicyDecision, detail: &str| {
            assert!(!decision.allowed, "expected deny, got ALLOW: {decision:?}");
            assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
            assert!(decision.matched_rule.is_none());
            assert!(decision.org_provenance.is_none());
            assert_eq!(last_step(decision).phase, "ORG_AUTHORITY");
            assert_eq!(last_step(decision).result, Effect::Deny);
            assert_eq!(last_step(decision).detail, detail);
        };

        // (a) 节点头栅栏与 publication 失配（证据畸形）。
        let mut drifted = evidence(base_publication.clone());
        drifted.node.generation += 1;
        let decision = evaluate(
            &ctx(Some(TENANT), None, None, None),
            &repo,
            &drifted,
            Vec::new(),
        )
        .await;
        assert_pending(&decision, "org_scope.evidence_invalid");

        // (b) 签名 actor 用户与已证明 membership 不一致。
        let mut wrong_user = ctx(Some(TENANT), None, None, None);
        wrong_user.user_id = Some(999);
        let decision = evaluate(&wrong_user, &repo, &evidence_value, Vec::new()).await;
        assert_pending(&decision, "org_scope.evidence_invalid");

        // (c) 签名 actor 租户与证据单元租户不一致。
        let mut wrong_tenant = ctx(Some(TENANT), None, None, None);
        wrong_tenant.tenant_id = Some(200);
        let decision = evaluate(&wrong_tenant, &repo, &evidence_value, Vec::new()).await;
        assert_pending(&decision, "org_scope.evidence_invalid");

        // (d) 段 digest 被篡改（证据不再绑定其内容）。
        let mut tampered = evidence(base_publication.clone());
        tampered.publication.segments[0].digest_hex = "0".repeat(64);
        let decision = evaluate(
            &ctx(Some(TENANT), None, None, None),
            &repo,
            &tampered,
            Vec::new(),
        )
        .await;
        assert_pending(&decision, "org_scope.evidence_invalid");

        // (e) 签名 actor 租户缺失（身份不完整）。
        let mut missing_tenant = ctx(Some(TENANT), None, None, None);
        missing_tenant.tenant_id = None;
        let decision = evaluate(&missing_tenant, &repo, &evidence_value, Vec::new()).await;
        assert_pending(&decision, "org_scope.evidence_invalid");
    }

    #[tokio::test]
    async fn personal_contribution_requires_exact_user_and_card_pair() {
        let evidence_value = personal_contribution_evidence(USER_ID, CARD_ID);
        let repo = OrgTestRepo {
            next: ready(evidence_value.clone()),
            card_active: true,
        };
        let matching = evaluate(
            &ctx(Some(TENANT), None, None, None),
            &repo,
            &evidence_value,
            Vec::new(),
        )
        .await;
        assert!(matching.allowed);
        assert_eq!(last_step(&matching).source, Some("ORG_PERSONAL".to_owned()));
        assert_eq!(
            matching
                .org_provenance
                .as_ref()
                .expect("personal allow must carry provenance")
                .branch_kind,
            OrgBranchKind::Personal
        );

        let mismatched_subject = personal_contribution_evidence(USER_ID + 1, CARD_ID);
        let mismatch_repo = OrgTestRepo {
            next: ready(mismatched_subject.clone()),
            card_active: true,
        };
        let denied = evaluate(
            &ctx(Some(TENANT), None, None, None),
            &mismatch_repo,
            &mismatched_subject,
            Vec::new(),
        )
        .await;
        assert!(!denied.allowed);
        assert_eq!(denied.reason, "DEFAULT_DENY");
        assert_eq!(
            last_step(&denied).detail,
            "org_scope.no_matching_contribution"
        );

        let mut wrong_card = ctx(Some(TENANT), None, None, None);
        wrong_card.card_id = Some(CARD_ID + 1);
        let denied = evaluate(&wrong_card, &repo, &evidence_value, Vec::new()).await;
        assert!(!denied.allowed);
        assert_eq!(denied.reason, "AUTHORIZATION_PENDING");
        assert_eq!(last_step(&denied).detail, "org_scope.evidence_invalid");

        let mut wrong_user = ctx(Some(TENANT), None, None, None);
        wrong_user.user_id = Some(USER_ID + 1);
        let denied = evaluate(&wrong_user, &repo, &evidence_value, Vec::new()).await;
        assert!(!denied.allowed);
        assert_eq!(denied.reason, "AUTHORIZATION_PENDING");
        assert_eq!(last_step(&denied).detail, "org_scope.evidence_invalid");
    }

    // ── 正向基线：签名 actor 租户回退 + 复读稳定 + 卡片有效 → ALLOW ──

    #[tokio::test]
    async fn evaluate_allows_matching_evidence_via_actor_tenant_fallback() {
        let evidence_value = single_contribution_evidence(TENANT);
        let grant_id = uuid(1);
        let repo = OrgTestRepo {
            next: ready(evidence_value.clone()),
            card_active: true,
        };

        // resource_tenant_id 缺失 → 回退签名 actor 租户 → 命中本单元共享贡献。
        let decision = evaluate(
            &ctx(Some(TENANT), None, None, None),
            &repo,
            &evidence_value,
            Vec::new(),
        )
        .await;
        assert!(decision.allowed, "expected ALLOW, got: {decision:?}");
        assert_eq!(decision.reason, "ORG_PUBLISHED_EVIDENCE_ALLOW");
        assert_eq!(decision.matched_rule.as_deref(), Some(grant_id.as_str()));
        assert_eq!(last_step(&decision).result, Effect::Allow);
        assert_eq!(last_step(&decision).source, Some("ORG_SHARED".to_owned()));

        let provenance = decision
            .org_provenance
            .as_ref()
            .expect("ALLOW must carry org provenance");
        assert_eq!(provenance.resource_tenant_id, TENANT);
        assert_eq!(provenance.branch_kind, OrgBranchKind::Shared);
        assert!(provenance.validate().is_ok());
    }
}
