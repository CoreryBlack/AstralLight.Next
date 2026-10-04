//! PolicyEngine published-evidence strict gate 与 ALLOW 前复检。
//!
//! 仅当 repository 声明 `requires_published_card_evidence` 时可达；证据缺失、
//! 读取失败、gate 非 Ready 或复检漂移一律 PENDING，绝不回退 raw/source/cache。

use crate::hit_stats::TimingBreakdown;
use astral_types::registry::{get_alias_sources, parse_resource_key};
use astral_types::{
    BindingLayer, CanonicalGrant, DomainScopeRequirement, EvaluationStep, GlobalAccessRequirement,
    GrantEffect, GrantSourceKind, GrantState, PolicyContext, PolicyDecision, PolicyError,
    PublishedCardAuthorization, PublishedCardEvidenceScope, ResourceOwnershipScope,
};

use super::decision::*;
use super::ports::RuleRepository;
use super::types::*;
use super::PolicyEngine;

impl PolicyEngine {
    // ==================== 正式已发布证据路径（strict gate） ====================

    /// Published-evidence formal evaluation（strict gate）。
    ///
    /// 仅当 repository 声明
    /// [`RuleRepository::requires_published_card_evidence`] == true 时可达。
    /// 链路：AUTHN/CARD_CONTEXT（`evaluate` 已强制）→ published evidence 读取
    /// → 统一 ALLOW-only 匹配器 → ALLOW 返回前复读。
    ///
    /// Fail-closed 契约：
    /// - 请求缺 tenant scope → AUTHORIZATION_PENDING；
    /// - `Ok(None)`（legacy/test unavailable 标记）、`Err(_)`、非 Ready gate、
    ///   证据畸形（合同校验失败）或证据 tenant/card 与请求不符 →
    ///   AUTHORIZATION_PENDING；
    /// - 无命中的 effective grant → DEFAULT_DENY（绝不回退 L1/L2/L2.5 读取器、
    ///   raw/source 表或 cache）；
    /// - 任何有效 ALLOW 返回前必须复读证据，且 tenant/card 身份、gate 计数、
    ///   manifest 摘要、被命中 grant 必须与评估起点及本次请求完全一致，否则
    ///   AUTHORIZATION_PENDING。
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn evaluate_published_card_evidence<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
        resource_key: &str,
        start: std::time::Instant,
        steps: &mut Vec<EvaluationStep>,
        timing: &mut TimingBreakdown,
        repo_had_error: &mut bool,
    ) -> PolicyDecision {
        let card_id = ctx.card_id.unwrap_or(0);

        // 请求租户边界必须存在；卡片边界已由 AUTHN 保证。缺 tenant scope 属于
        // 授权边界缺失 → fail-closed（生产上下文由 Gateway 强制携带 tenant）。
        let Some(tenant_id) = ctx.tenant_id else {
            steps.push(step(
                "PUBLISHED_EVIDENCE",
                "DENY",
                "missing tenant scope",
                None,
            ));
            finish_published_evaluation(self, timing, start, "L3", false, ctx.resource.as_deref());
            return deny(
                "AUTHORIZATION_PENDING",
                "published:missing-tenant-scope",
                steps.clone(),
            );
        };

        let scope = PublishedCardEvidenceScope {
            tenant_id,
            card_id,
            user_filter: ctx.user_id,
            domain: match ctx.domain_id {
                Some(domain_id) => DomainScopeRequirement::ExactlySome(domain_id),
                None => DomainScopeRequirement::Unconstrained,
            },
        };
        if scope.validate().is_err() {
            steps.push(step(
                "PUBLISHED_EVIDENCE",
                "DENY",
                "invalid evidence scope",
                None,
            ));
            finish_published_evaluation(self, timing, start, "L3", false, ctx.resource.as_deref());
            return deny(
                "AUTHORIZATION_PENDING",
                "published:invalid-scope",
                steps.clone(),
            );
        }

        let t_evidence = std::time::Instant::now();
        let read = repo.load_published_card_authorization(&scope).await;
        let initial_evidence_load_ns = t_evidence.elapsed().as_nanos() as u64;
        timing.initial_evidence_load_ns = initial_evidence_load_ns;
        timing.refs_load_ns = initial_evidence_load_ns;

        let evidence = match read {
            Ok(Some(evidence)) => evidence,
            Ok(None) => {
                // Legacy/test unavailable 标记在 strict gate 下同样绝不放行。
                steps.push(step(
                    "PUBLISHED_EVIDENCE",
                    "DENY",
                    "published evidence unavailable",
                    None,
                ));
                finish_published_evaluation(
                    self,
                    timing,
                    start,
                    "L3",
                    false,
                    ctx.resource.as_deref(),
                );
                return deny(
                    "AUTHORIZATION_PENDING",
                    "published:unavailable",
                    steps.clone(),
                );
            }
            Err(e) => {
                let business_pending = published_evidence_error_is_business_pending(&e);
                tracing::warn!(card_id, error = %e, business_pending,
                    "published card evidence read failed");
                *repo_had_error = !business_pending;
                steps.push(step(
                    "PUBLISHED_EVIDENCE",
                    "DENY",
                    if business_pending {
                        "published evidence not ready"
                    } else {
                        "published evidence read failed"
                    },
                    None,
                ));
                finish_published_evaluation(
                    self,
                    timing,
                    start,
                    "L3",
                    *repo_had_error,
                    ctx.resource.as_deref(),
                );
                return deny(
                    "AUTHORIZATION_PENDING",
                    "published:unavailable",
                    steps.clone(),
                );
            }
        };

        // 畸形证据（合同校验失败）→ fail-closed，不区分内部形态。
        if evidence.validate().is_err() {
            steps.push(step(
                "PUBLISHED_EVIDENCE",
                "DENY",
                "published evidence malformed",
                None,
            ));
            finish_published_evaluation(self, timing, start, "L3", false, ctx.resource.as_deref());
            return deny(
                "AUTHORIZATION_PENDING",
                "published:malformed",
                steps.clone(),
            );
        }
        // 非 Ready gate 不是授权证据（合同层面 validate 已要求 Ready，此处为
        // 纵深防御）。
        if !evidence.gate.status.is_authorization_usable() {
            steps.push(step(
                "PUBLISHED_EVIDENCE",
                "DENY",
                &format!(
                    "published evidence gate not ready ({})",
                    evidence.gate.status.code()
                ),
                None,
            ));
            finish_published_evaluation(self, timing, start, "L3", false, ctx.resource.as_deref());
            return deny(
                "AUTHORIZATION_PENDING",
                "published:not-ready",
                steps.clone(),
            );
        }

        // 证据必须属于本次请求的 (tenant, card) 范围，否则 scope 污染 → fail-closed。
        if evidence.tenant_id != tenant_id || evidence.card_id != card_id {
            steps.push(step(
                "PUBLISHED_EVIDENCE",
                "DENY",
                "published evidence scope mismatch",
                None,
            ));
            finish_published_evaluation(self, timing, start, "L3", false, ctx.resource.as_deref());
            return deny(
                "AUTHORIZATION_PENDING",
                "published:scope-mismatch",
                steps.clone(),
            );
        }

        steps.push(step(
            "PUBLISHED_EVIDENCE",
            "PASS",
            &format!(
                "published evidence ready (manifests={}, verified={}, effective={})",
                evidence.gate.aggregate_manifest_count,
                evidence.gate.verified_record_count,
                evidence.gate.effective_grant_count
            ),
            None,
        ));

        // 统一 ALLOW-only 匹配器：effective_grants 即完整有效授权集合，
        // 无命中即 DEFAULT_DENY，不存在任何回退层。
        let Some(matched) = match_published_effective_grant(ctx, &evidence, resource_key) else {
            steps.push(step(
                "DEFAULT",
                "DENY",
                &format!("no published grant for {resource_key}:{}", ctx.action),
                None,
            ));
            finish_published_evaluation(self, timing, start, "L1", false, ctx.resource.as_deref());
            return deny(
                "DEFAULT_DENY",
                &format!("published:{resource_key}:{}:cardId={card_id}", ctx.action),
                steps.clone(),
            );
        };

        let source_label = published_source_label(matched);
        #[cfg(feature = "e1-observability")]
        {
            let stamp = crate::e1_observation::stamp();
            tracing::info!(
                target: "authz_e1",
                event = "candidate_match",
                request_id = stamp.request_id.as_deref().unwrap_or(""),
                process_observation_id = %stamp.process_observation_id,
                event_sequence = stamp.event_sequence,
                wall_unix_ns = %stamp.wall_unix_ns,
                tenant_id,
                card_id,
                grant_id = %matched.grant_id,
                grant_revision = matched.revision.value(),
                grant_hash = %matched.canonical_hash().unwrap_or_default(),
                grant_source = matched.source_kind.as_str(),
                binding_layer = matched.binding_layer.as_str(),
                "e1 authorization observation"
            );
        }
        steps.push(step(
            "PUBLISHED_EVIDENCE",
            "ALLOW",
            &format!("{resource_key}:{} via {source_label}", ctx.action),
            Some(source_label.to_string()),
        ));

        // ALLOW 返回前强制复读：证据/gate 身份必须与评估起点完全一致，
        // 否则旧 ALLOW 转 AUTHORIZATION_PENDING（Err 计入断路器失败）。
        #[cfg(feature = "e1-observability")]
        {
            let stamp = crate::e1_observation::stamp();
            tracing::info!(
                target: "authz_e1",
                event = "final_reload_start",
                request_id = stamp.request_id.as_deref().unwrap_or(""),
                process_observation_id = %stamp.process_observation_id,
                event_sequence = stamp.event_sequence,
                wall_unix_ns = %stamp.wall_unix_ns,
                tenant_id,
                card_id,
                grant_id = %matched.grant_id,
                grant_revision = matched.revision.value(),
                grant_hash = %matched.canonical_hash().unwrap_or_default(),
                "e1 authorization observation"
            );
        }
        let t_recheck = std::time::Instant::now();
        let recheck = repo.load_published_card_authorization(&scope).await;
        let final_evidence_reload_ns = t_recheck.elapsed().as_nanos() as u64;
        timing.final_evidence_reload_ns = final_evidence_reload_ns;
        timing.refs_load_ns += final_evidence_reload_ns;
        let recheck_outcome = match recheck {
            Ok(Some(next))
                if published_recheck_identity_stable(
                    &evidence, &next, tenant_id, card_id, matched,
                ) =>
            {
                None
            }
            Ok(Some(_)) | Ok(None) => Some(false),
            Err(e) => {
                let business_pending = published_evidence_error_is_business_pending(&e);
                tracing::warn!(
                    card_id,
                    error = %e,
                    business_pending,
                    "published card evidence recheck read failed"
                );
                Some(!business_pending)
            }
        };
        #[cfg(feature = "e1-observability")]
        {
            let stamp = crate::e1_observation::stamp();
            tracing::info!(
                target: "authz_e1",
                event = "stable_check_end",
                request_id = stamp.request_id.as_deref().unwrap_or(""),
                process_observation_id = %stamp.process_observation_id,
                event_sequence = stamp.event_sequence,
                wall_unix_ns = %stamp.wall_unix_ns,
                tenant_id,
                card_id,
                stable = recheck_outcome.is_none(),
                grant_id = %matched.grant_id,
                grant_revision = matched.revision.value(),
                grant_hash = %matched.canonical_hash().unwrap_or_default(),
                "e1 authorization observation"
            );
        }
        if let Some(is_error) = recheck_outcome {
            if is_error {
                *repo_had_error = true;
            }
            steps.push(step(
                "PUBLISHED_EVIDENCE",
                "DENY",
                "published evidence changed during evaluation (stale ALLOW rejected)",
                None,
            ));
            finish_published_evaluation(
                self,
                timing,
                start,
                "L3",
                *repo_had_error,
                ctx.resource.as_deref(),
            );
            return deny(
                "AUTHORIZATION_PENDING",
                "published:stale-allow",
                steps.clone(),
            );
        }

        // A control-plane Global target must prove ACTIVE GlobalAdmin again after
        // the evidence recheck. Both reads are deliberately repository calls:
        // a disable that commits during evaluation must turn an otherwise valid
        // ALLOW into a fail-closed result rather than rely on a handler cache.
        if matches!(
            ctx.global_access_requirement,
            GlobalAccessRequirement::ActiveGlobalAdmin
        ) {
            let user_id = ctx.user_id.unwrap_or(0);
            match repo.is_active_global_admin(user_id).await {
                Ok(true) => steps.push(step(
                    "GLOBAL_ADMIN",
                    "PASS",
                    "active global administrator confirmed at ALLOW recheck",
                    None,
                )),
                Ok(false) => {
                    steps.push(step(
                        "GLOBAL_ADMIN",
                        "DENY",
                        "global administrator changed during evaluation",
                        None,
                    ));
                    finish_published_evaluation(
                        self,
                        timing,
                        start,
                        "L3",
                        false,
                        ctx.resource.as_deref(),
                    );
                    return deny(
                        "GLOBAL_ADMIN_REQUIRED",
                        "global_admin:stale-allow",
                        steps.clone(),
                    );
                }
                Err(error) => {
                    tracing::warn!(user_id, error = %error,
                        "global administrator final gate unavailable; denying");
                    *repo_had_error = true;
                    steps.push(step(
                        "GLOBAL_ADMIN",
                        "DENY",
                        "global administrator gate unavailable at ALLOW recheck",
                        None,
                    ));
                    finish_published_evaluation(
                        self,
                        timing,
                        start,
                        "L3",
                        true,
                        ctx.resource.as_deref(),
                    );
                    return deny(
                        "AUTHORIZATION_PENDING",
                        "global_admin:recheck_unavailable",
                        steps.clone(),
                    );
                }
            }
        }

        finish_published_evaluation(self, timing, start, "L1", false, ctx.resource.as_deref());
        allow(
            "PUBLISHED_EVIDENCE_ALLOW",
            &format!("published:{resource_key}:{}:cardId={card_id}", ctx.action),
            steps.clone(),
        )
    }

    // ==================== 一致性检查：实时评估路径 ====================

    /// ALLOW 返回前投影复检（对齐 Java：规则读取期间投影推进或 revoke-fence 变化
    /// → 旧 ALLOW 转 AUTHORIZATION_PENDING，且不增加 L1/L2 命中统计）。
    ///
    /// 若 repository 未提供 durable gate，复检时仍返回 `None` 才视为稳定；生产 SQLx
    /// repository 会将缺失 head 表达为 `ready=false`，因此不会走该默认兼容语义。
    /// head 新出现、版本变化、未 READY 或读取失败都保守拒绝。
    ///
    /// 返回三态：`Valid`（投影稳定）/ `Stale`（版本推进，旧 ALLOW 拒绝）/
    /// `Error`（gate 读取失败，fail-closed 且应计入断路器失败）。
    pub(crate) async fn projection_still_valid<R: RuleRepository>(
        &self,
        repo: &R,
        card_id: i64,
        baseline: &Option<ProjectionGate>,
    ) -> ProjectionCheck {
        match repo.get_projection_gate(card_id).await {
            Ok(None) => {
                if baseline.is_none() {
                    ProjectionCheck::Valid
                } else {
                    ProjectionCheck::Stale
                }
            }
            Ok(Some(current)) => {
                let Some(expected) = baseline else {
                    return ProjectionCheck::Stale;
                };
                if current.ready
                    && current.source_generation == expected.source_generation
                    && current.revoke_fence == expected.revoke_fence
                {
                    ProjectionCheck::Valid
                } else {
                    ProjectionCheck::Stale
                }
            }
            Err(_) => ProjectionCheck::Error,
        }
    }
}

// ==================== ORG_SCOPE 准入门禁记账 ====================

/// ORG_SCOPE 准入决策在 [`PolicyEngine::record_evaluation`] 中的稳定记账类别。
///
/// 不冒领 legacy L1/L2/L3 层命中：该串与评估步 phase、
/// [`PolicyEngine::allow_source_phase`] 命中来源使用的 `ORG_AUTHORITY` 同名。
/// `HitStats` 公共 schema（l1/l2/l3 命中计数）没有专属 ORG 桶，
/// `record_evaluation` 将其保守映射进终局 fail-closed 层 `l3_hits`
/// （与未知 layer 的既有兜底一致）；timing 明细照常累计。
pub(crate) const ORG_AUTHORITY_EVAL_LAYER: &str = "ORG_AUTHORITY";

/// ORG_SCOPE Ready 分支返回决策的断路器归类。
///
/// `org_admission::evaluate` 对引擎只暴露 `PolicyDecision`，引擎无法直接区分
/// 仓库 Err 与确定性拒绝，因此依据 reason 与终步 detail 的稳定常量归类：
/// - 确定性授权结果（ALLOW、`DEFAULT_DENY`、`CARD_DISABLED`，以及证据畸形 /
///   身份漂移 / provenance 畸形等业务 PENDING）→ 成功（对齐引擎既有约定：
///   业务拒绝与复检状态变化不计依赖故障，正常 `DEFAULT_DENY` 不是依赖失败）；
/// - 读取不可用路径（`org_scope.final_read_unavailable`：ALLOW 前权威复读
///   失败/非 Ready；`org_scope.final_card_context_unavailable`：终局卡片
///   上下文读取失败）→ 失败，累计断路器失败。注意 `org_admission` 把复读
///   `Err` 与管理态翻转并入 `final_read_unavailable`，保守按失败计；
/// - 未知 PENDING detail 保守按成功处理（与 `repo_had_error` 默认 false 的
///   既有取向一致），避免把未来新增的确定性拒绝误计为依赖故障。
pub(crate) fn org_admission_decision_is_dependency_failure(decision: &PolicyDecision) -> bool {
    if decision.reason != "AUTHORIZATION_PENDING" {
        return false;
    }
    matches!(
        decision.evaluation_path.last().map(|s| s.detail.as_str()),
        Some("org_scope.final_read_unavailable" | "org_scope.final_card_context_unavailable")
    )
}

// ==================== 已发布证据 strict gate 辅助函数 ====================

/// strict gate 收尾：统一计时/统计/断路器记账（对齐 evaluate 其余分支的记账语义）。
pub(crate) fn published_evidence_error_is_business_pending(error: &PolicyError) -> bool {
    matches!(error, PolicyError::Repository(message)
        if message.starts_with("published_card_evidence_not_ready;"))
}

pub(crate) fn record_policy_phase_metrics(timing: &TimingBreakdown) {
    for (phase, nanos) in [
        ("total", timing.total_ns),
        ("card_active", timing.card_active_check_ns),
        ("initial_evidence_load", timing.initial_evidence_load_ns),
        ("final_evidence_reload", timing.final_evidence_reload_ns),
        ("overlay", timing.overlay_eval_ns),
        ("base", timing.base_eval_ns),
        ("permission_rule", timing.perm_rule_eval_ns),
    ] {
        if nanos > 0 {
            metrics::histogram!("astral_authz_policy_phase_duration_seconds", "phase" => phase)
                .record(std::time::Duration::from_nanos(nanos).as_secs_f64());
        }
    }
}

pub(crate) fn finish_published_evaluation(
    engine: &PolicyEngine,
    timing: &mut TimingBreakdown,
    start: std::time::Instant,
    layer: &str,
    repo_had_error: bool,
    resource: Option<&str>,
) {
    timing.total_ns = start.elapsed().as_nanos() as u64;
    record_policy_phase_metrics(timing);
    engine.record_evaluation(layer, timing);
    if repo_had_error {
        engine.record_failure_on_evaluate(resource);
    } else {
        engine.record_success_on_evaluate(resource);
    }
}

/// 统一 ALLOW-only 匹配器：在已发布证据的 `effective_grants` 中找第一条同时
/// 满足身份/有效期/资源/动作约束的 grant（evidence 顺序确定性遍历，首中即胜）。
///
/// # 匹配语义（fail-closed）
///
/// - 身份：grant 必须`card_id`/`user_id`/`tenant_id` 与请求完全一致；actor 卡携带
///   domain 时，grant 必须保留同一张卡的溯源 domain。对 resolver 已分类且带
///   domain 的 `TenantScoped` 目标，grant 还必须属于该权威目标 domain；无 domain
///   的租户级目标不把 `None` 解释为“只能匹配无 domain grant”。
/// - 有效期：以本次证据读取的统一 UTC 时钟（`read_unix_seconds`）为准。
/// - 状态/效果：合同只允许 ACTIVE+ALLOW 进入 effective 集合；任何漂移一律不匹配。
/// - 资源（`parse_resource_key` 语义）：对象请求（`type:id`）可命中同一对象的
///   对象级 grant 或类型级 grant（`type:*`/裸 `type`/`*`）；类型级请求
///   （`type:*`）绝不命中对象级 grant，只命中类型级 grant（含全局 `*`）。
/// - 动作：exact → `write` 别名（write→create/update/delete）→ `'*'`。
/// - 条件：`CanonicalGrant` 合同当前不含 condition 字段，所有 effective grant
///   均为无条件 ALLOW；匹配器不得把任何未来/非法 condition 表示当作已满足
///   （合同层 serde/ledger 对新字段 fail-closed），本函数只消费无条件集合。
pub(crate) fn match_published_effective_grant<'a>(
    ctx: &PolicyContext,
    evidence: &'a PublishedCardAuthorization,
    resource_key: &str,
) -> Option<&'a CanonicalGrant> {
    let card_id = ctx.card_id.unwrap_or(0);
    let request_tenant = ctx.tenant_id.unwrap_or(0);
    let (request_type, request_id) = parse_resource_key(resource_key);
    let type_level_request = request_id.is_none();
    let now = evidence.read_unix_seconds;

    evidence.effective_grants.iter().find(|grant| {
        // 身份/租户边界：grant 必须属于本次请求的卡、用户、租户。
        if grant.card_id != card_id
            || ctx.user_id.is_none_or(|user_id| grant.user_id != user_id)
            || grant.tenant.tenant_id != request_tenant
        {
            return false;
        }
        // Card-domain provenance: a grant must remain bound to the active actor
        // card domain. This is distinct from the protected target's domain below.
        if let Some(domain_id) = ctx.domain_id {
            if grant.tenant.domain_id != Some(domain_id) {
                return false;
            }
        }
        // A resolver-classified tenant target with a domain may consume ordinary
        // card evidence only from that same authoritative target domain. A
        // domainless target remains tenant-level; `None` is not a requirement
        // that the actor card's grant itself be domainless.
        if matches!(
            ctx.resource_ownership_scope,
            ResourceOwnershipScope::TenantScoped
        ) {
            if let Some(resource_domain_id) = ctx.resource_domain_id {
                if grant.tenant.domain_id != Some(resource_domain_id) {
                    return false;
                }
            }
        }
        // 有效期（统一 UTC 时钟）。
        if !grant.validity.is_valid_at(now) {
            return false;
        }
        // 合同只允许 ACTIVE+ALLOW 形态进入 effective_grants；漂移 fail-closed。
        if grant.state != GrantState::Active || grant.effect != GrantEffect::Allow {
            return false;
        }
        // 资源匹配：类型级 grant 通配本类型，`*` 全局通配；对象级 grant 只命中
        // 同一对象；类型级请求绝不命中对象级 grant。
        let (grant_type, grant_id) = parse_resource_key(&grant.resource);
        if grant_type != request_type && grant_type != "*" {
            return false;
        }
        if type_level_request {
            if grant_id.is_some() {
                return false;
            }
        } else if grant_id.is_some() && grant_id != request_id {
            return false;
        }
        // 动作匹配：exact / write 别名 / '*'。
        let action = ctx.action.as_str();
        grant.action == action
            || grant.action == "*"
            || get_alias_sources(action).contains(&grant.action.as_str())
    })
}

/// 已发布 grant 的来源标签：区分 RULE_SET BASE/OVERLAY、DIRECT、APPROVAL、
/// DELEGATION（SYSTEM 为系统回填语义，仅展示/审计）。
pub(crate) fn published_source_label(grant: &CanonicalGrant) -> &'static str {
    match (grant.source_kind, grant.binding_layer) {
        (GrantSourceKind::RuleSet, BindingLayer::Base) => "RULE_SET_BASE",
        (GrantSourceKind::RuleSet, BindingLayer::Overlay) => "RULE_SET_OVERLAY",
        (GrantSourceKind::RuleSet, _) => "RULE_SET",
        (GrantSourceKind::Direct, _) => "DIRECT",
        (GrantSourceKind::Approval, _) => "APPROVAL",
        (GrantSourceKind::Delegation, _) => "DELEGATION",
        (GrantSourceKind::System, _) => "SYSTEM",
    }
}

/// ALLOW 复读的身份等价判定：请求/baseline/next 三方的 tenant/card 身份、
/// gate 计数、manifest 摘要与被命中 grant 必须与评估起点完全一致。
/// `read_unix_seconds` 是逐次变化的读取时钟，不参与身份比较；但新证据必须
/// 先通过合同校验，且被命中 grant 必须仍在新证据的 effective 集合中
/// （含有效期在新读取时钟下仍然有效）。
pub(crate) fn published_recheck_identity_stable(
    baseline: &PublishedCardAuthorization,
    next: &PublishedCardAuthorization,
    request_tenant_id: i64,
    request_card_id: i64,
    matched: &CanonicalGrant,
) -> bool {
    next.validate().is_ok()
        && next.tenant_id == baseline.tenant_id
        && next.card_id == baseline.card_id
        && next.tenant_id == request_tenant_id
        && next.card_id == request_card_id
        && baseline.gate == next.gate
        && baseline.manifests == next.manifests
        && next.effective_grants.iter().any(|grant| grant == matched)
}
