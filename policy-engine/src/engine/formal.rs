//! PolicyEngine 正式/实时评估路径。
//!
//! 承载正式 `evaluate()` 主链、realtime oracle 一致性路径、L1 规则集与 L2
//! permission-rule 匹配助手、simulate 与 fallback；决策纯函数见
//! [`super::decision`]，published strict gate 见 [`super::published`]。

use crate::consistency::get_consistency_checker;
use crate::hit_stats::TimingBreakdown;
use astral_types::registry::{build_resource_key, get_alias_sources, is_wildcard_key};
use astral_types::{
    Effect, EvaluationStep, GlobalAccessRequirement, PolicyContext, PolicyDecision, PolicyError,
    ResourceOwnershipScope,
};

use super::decision::*;
use super::ports::RuleRepository;
use super::published::*;
use super::types::*;
use super::PolicyEngine;

impl PolicyEngine {
    /// 三层评估主入口
    ///
    /// 评估链（对齐 Java PolicyEngine.evaluate()）：
    /// AUTHN → CARD_CONTEXT → RULESET(OVERLAY>BASE) → PERMISSION_RULE → DEFAULT_DENY
    ///
    /// 断路器集成（对齐 Java resilience4j @CircuitBreaker）：
    /// - `record_success_on_evaluate()` — 每次正常完成时调用，重置失败计数器
    /// - `record_failure_on_evaluate()` — 仓库调用返回错误时调用，累计失败计数
    /// - `check_circuit_breaker()` — 评估入口处检查，断路器打开时直接返回 DENY
    pub async fn evaluate<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        let start = std::time::Instant::now();
        let mut steps: Vec<EvaluationStep> = Vec::new();
        let mut timing = TimingBreakdown::default();
        let mut repo_had_error = false;
        // 快照 gate 只在 eval_block 内可见；一致性检查在块外执行，需在此捕获。
        // 块内 gate 读取前的早期失败（AUTHN/CARD 等）保持 None → 不生成冲突信号。
        let mut arbiter_gate: Option<ProjectionGate> = None;

        // 断路器检查
        if let Some(fallback) = self.check_circuit_breaker(ctx) {
            return fallback;
        }

        // Capability marker 一次性读取：strict published-evidence repository 的
        // 正式授权只消费 published evidence，不存在可与一致性采样 realtime oracle
        // 比对的快照/raw source 双路径；eval_block 之后的一致性采样会调用
        // evaluate_realtime 触碰 raw source 读取器，必须对该仓库整体跳过。
        let strict_published_evidence = repo.requires_published_card_evidence();

        let decision: PolicyDecision = 'eval_block: {
            // ========== AUTHN 验证（对齐 Java PolicyEngine AUTHN phase） ==========
            if ctx.user_id.is_none() {
                steps.push(step("AUTHN", "DENY", "no user context", None));
                timing.total_ns = start.elapsed().as_nanos() as u64;
                self.record_evaluation("L3", &timing);
                self.record_success_on_evaluate(ctx.resource.as_deref());
                break 'eval_block deny("AUTHN_REQUIRED", "authn", steps);
            }
            steps.push(step(
                "AUTHN",
                "PASS",
                &format!("userId={}", ctx.user_id.unwrap()),
                None,
            ));

            if ctx.card_id.is_none() {
                steps.push(step("AUTHN", "DENY", "no card selected", None));
                timing.total_ns = start.elapsed().as_nanos() as u64;
                self.record_evaluation("L3", &timing);
                self.record_success_on_evaluate(ctx.resource.as_deref());
                break 'eval_block deny("CARD_REQUIRED", "no-card-selected", steps);
            }

            // 卡片上下文验证（含状态/用户/租户/域交叉校验）
            if let Some(card_id) = ctx.card_id {
                let t_card = std::time::Instant::now();
                match repo.check_card_active(ctx).await {
                    Ok(true) => {}
                    Ok(false) => {
                        timing.card_active_check_ns = t_card.elapsed().as_nanos() as u64;
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation("L3", &timing);
                        // 卡片未激活/不存在属于业务拒绝，不累计断路器失败计数。
                        self.record_success_on_evaluate(ctx.resource.as_deref());
                        steps.push(step(
                            "CARD_CONTEXT",
                            "DENY",
                            &format!("Card {card_id} is inactive or context mismatch"),
                            None,
                        ));
                        break 'eval_block deny(
                            "CARD_DISABLED",
                            &format!("card:{card_id}:disabled"),
                            steps,
                        );
                    }
                    Err(e) => {
                        tracing::warn!(card_id, error = %e, "card context dependency unavailable");
                        timing.card_active_check_ns = t_card.elapsed().as_nanos() as u64;
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation("L3", &timing);
                        self.record_failure_on_evaluate(ctx.resource.as_deref());
                        steps.push(step(
                            "CARD_CONTEXT",
                            "DENY",
                            "card context dependency unavailable",
                            None,
                        ));
                        break 'eval_block deny(
                            "DEPENDENCY_UNAVAILABLE",
                            &format!("card:{card_id}:unavailable"),
                            steps,
                        );
                    }
                }
                timing.card_active_check_ns = t_card.elapsed().as_nanos() as u64;
            }
            steps.push(step("CARD_CONTEXT", "PASS", "card active", None));

            if ctx.resource.as_deref().is_none_or(|r| r.is_empty()) {
                steps.push(step("AUTHN", "DENY", "no resource", None));
                timing.total_ns = start.elapsed().as_nanos() as u64;
                self.record_evaluation("L3", &timing);
                self.record_success_on_evaluate(ctx.resource.as_deref());
                break 'eval_block deny("RESOURCE_REQUIRED", "no-resource", steps);
            }
            if ctx.action.is_empty() {
                steps.push(step("AUTHN", "DENY", "no action", None));
                timing.total_ns = start.elapsed().as_nanos() as u64;
                self.record_evaluation("L3", &timing);
                self.record_success_on_evaluate(ctx.resource.as_deref());
                break 'eval_block deny("ACTION_REQUIRED", "no-action", steps);
            }

            // ========== HTTP target-resource ownership gate ==========
            // Gateway proves actor identity only. External HTTP callers must carry a
            // resolver classification before target-sensitive authorization begins:
            // tenant-owned facts come exclusively from a server-side resolver;
            // explicitly global control-plane resources bypass ORG_SCOPE admission;
            // unresolved/unavailable targets never inherit actor tenant/domain.
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
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation("L3", &timing);
                        self.record_success_on_evaluate(ctx.resource.as_deref());
                        break 'eval_block deny(
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
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation("L3", &timing);
                        self.record_success_on_evaluate(ctx.resource.as_deref());
                        break 'eval_block deny(
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
                            timing.total_ns = start.elapsed().as_nanos() as u64;
                            self.record_evaluation("L3", &timing);
                            self.record_success_on_evaluate(ctx.resource.as_deref());
                            break 'eval_block deny(
                                "AUTHORIZATION_PENDING",
                                "resource_ownership:global_access_unspecified",
                                steps,
                            );
                        }
                        GlobalAccessRequirement::PolicyEvidence => {}
                        GlobalAccessRequirement::ActiveGlobalAdmin => {
                            // The final GlobalAdmin recheck is coupled to the strict
                            // published-evidence ALLOW fence below. Legacy/test readers
                            // have no equivalent durable evidence recheck, so they must
                            // never authorize a Global control-plane request merely
                            // because an initial admin read happened to succeed.
                            if !strict_published_evidence {
                                steps.push(step(
                                    "GLOBAL_ADMIN",
                                    "DENY",
                                    "global control-plane requests require strict published evidence",
                                    None,
                                ));
                                timing.total_ns = start.elapsed().as_nanos() as u64;
                                self.record_evaluation("L3", &timing);
                                self.record_success_on_evaluate(ctx.resource.as_deref());
                                break 'eval_block deny(
                                    "AUTHORIZATION_PENDING",
                                    "global_admin:strict_evidence_required",
                                    steps,
                                );
                            }

                            let Some(user_id) = ctx.user_id.filter(|user_id| *user_id > 0) else {
                                steps.push(step(
                                    "GLOBAL_ADMIN",
                                    "DENY",
                                    "global control-plane request lacked a verified user",
                                    None,
                                ));
                                timing.total_ns = start.elapsed().as_nanos() as u64;
                                self.record_evaluation("L3", &timing);
                                self.record_success_on_evaluate(ctx.resource.as_deref());
                                break 'eval_block deny(
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
                                    timing.total_ns = start.elapsed().as_nanos() as u64;
                                    self.record_evaluation("L3", &timing);
                                    self.record_success_on_evaluate(ctx.resource.as_deref());
                                    break 'eval_block deny(
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
                                    timing.total_ns = start.elapsed().as_nanos() as u64;
                                    self.record_evaluation("L3", &timing);
                                    self.record_failure_on_evaluate(ctx.resource.as_deref());
                                    break 'eval_block deny(
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
                    timing.total_ns = start.elapsed().as_nanos() as u64;
                    self.record_evaluation("L3", &timing);
                    self.record_success_on_evaluate(ctx.resource.as_deref());
                    break 'eval_block deny(
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
                    timing.total_ns = start.elapsed().as_nanos() as u64;
                    self.record_evaluation("L3", &timing);
                    self.record_failure_on_evaluate(ctx.resource.as_deref());
                    break 'eval_block deny(
                        "AUTHORIZATION_PENDING",
                        "resource_ownership:unavailable",
                        steps,
                    );
                }
            }

            // ========== ORG_SCOPE 准入门禁 ==========
            // Global control-plane resources have no tenant-owned target and
            // therefore must not be interpreted through an actor tenant's
            // organization branch. Tenant-scoped and in-process typed calls keep
            // the existing admission path; unresolved/unavailable HTTP contexts
            // were rejected by the ownership gate above.
            if !matches!(ctx.resource_ownership_scope, ResourceOwnershipScope::Global) {
                // 记账语义（与 evaluate 其余分支一致，且恰好一次）：
                // - Unmanaged：落入既有 legacy/strict 路径，由其既有记账收尾，此处不预记；
                // - Ready：org_admission 正式准入返回后统一记账（layer=ORG_AUTHORITY）；
                //   确定性授权结果记成功，终局读取不可用（org 复读/卡片上下文）记失败；
                // - Disabled / Pending：管理态关闭与已证实业务 pending 都是确定性授权结果 → 成功；
                // - Unavailable / Err：org gate 或权威读取不可用 → 失败，累计断路器失败。
                // 断路器归类判据见 org_admission_decision_is_dependency_failure()。
                match repo.load_org_authorization(ctx).await {
                    Ok(crate::org_admission::OrgAuthorityRead::Unmanaged) => {
                        // Ordinary actor-card evidence is scoped to the actor's
                        // current card tenant. A resolver-classified foreign
                        // target may proceed only through the Ready ORG branch
                        // above; otherwise legacy/strict matching would turn an
                        // actor-tenant grant into cross-tenant authority.
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
                            timing.total_ns = start.elapsed().as_nanos() as u64;
                            self.record_evaluation("L3", &timing);
                            self.record_success_on_evaluate(ctx.resource.as_deref());
                            break 'eval_block deny(
                                "AUTHORIZATION_PENDING",
                                "resource_ownership:foreign_tenant_target",
                                steps,
                            );
                        }
                    }
                    Ok(crate::org_admission::OrgAuthorityRead::Ready(evidence)) => {
                        let decision =
                            crate::org_admission::evaluate(ctx, repo, &evidence, steps).await;
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation(ORG_AUTHORITY_EVAL_LAYER, &timing);
                        if org_admission_decision_is_dependency_failure(&decision) {
                            self.record_failure_on_evaluate(ctx.resource.as_deref());
                        } else {
                            self.record_success_on_evaluate(ctx.resource.as_deref());
                        }
                        break 'eval_block decision;
                    }
                    Ok(crate::org_admission::OrgAuthorityRead::Disabled) => {
                        let decision = crate::org_admission::unavailable(
                            "ORG_AUTHORITY_DISABLED",
                            "managed authority cannot fall back to legacy evidence",
                            steps,
                        );
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation(ORG_AUTHORITY_EVAL_LAYER, &timing);
                        // 确定性管理态关闭（非依赖故障）：不累计断路器失败。
                        self.record_success_on_evaluate(ctx.resource.as_deref());
                        break 'eval_block decision;
                    }
                    Ok(crate::org_admission::OrgAuthorityRead::Pending { code }) => {
                        let decision = crate::org_admission::unavailable(
                            "AUTHORIZATION_PENDING",
                            &code,
                            steps,
                        );
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation(ORG_AUTHORITY_EVAL_LAYER, &timing);
                        // 读取已成功（Ok），Pending 是授权业务态而非仓库故障：记成功。
                        self.record_success_on_evaluate(ctx.resource.as_deref());
                        break 'eval_block decision;
                    }
                    Ok(crate::org_admission::OrgAuthorityRead::Unavailable { code }) => {
                        tracing::warn!(
                            code = %code,
                            "org authority gate or evidence read unavailable, denying (AUTHORIZATION_PENDING)"
                        );
                        let decision = crate::org_admission::unavailable(
                            "AUTHORIZATION_PENDING",
                            &code,
                            steps,
                        );
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation(ORG_AUTHORITY_EVAL_LAYER, &timing);
                        // A fail-closed unavailable gate is distinct from durable business
                        // Pending: the dependency outage must accrue breaker failures.
                        self.record_failure_on_evaluate(ctx.resource.as_deref());
                        break 'eval_block decision;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "org authority read failed, denying (AUTHORIZATION_PENDING)"
                        );
                        let decision = crate::org_admission::unavailable(
                            "AUTHORIZATION_PENDING",
                            "org_scope.read_unavailable",
                            steps,
                        );
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation(ORG_AUTHORITY_EVAL_LAYER, &timing);
                        // 仓库级读取失败计入断路器失败（对齐 CARD_CONTEXT/PROJECTION
                        // gate 的既有约定），否则 DB 故障会被后续成功清零，断路器打不开。
                        self.record_failure_on_evaluate(ctx.resource.as_deref());
                        break 'eval_block decision;
                    }
                }
            }

            // ========== 构建 resourceKey ==========
            let resource_type = ctx.resource.as_deref().unwrap_or("");
            let resource_key = build_resource_key(resource_type, ctx.target_id);

            // ========== 正式已发布证据路径（strict gate） ==========
            // Capability marker 为 true 的生产 repository：AUTHN/CARD_CONTEXT 与
            // resource/action 校验之后直接读取 Rust-owned published evidence，
            // 并以统一 ALLOW-only 匹配器消费 effective_grants。该请求不再触碰
            // L1/L2/L2.5 读取器或任何 raw/source/cache 回退；Ok(None)/Err/非
            // Ready/证据畸形/scope 不符一律 fail-closed（AUTHORIZATION_PENDING）。
            if strict_published_evidence {
                let decision = self
                    .evaluate_published_card_evidence(
                        ctx,
                        repo,
                        &resource_key,
                        start,
                        &mut steps,
                        &mut timing,
                        &mut repo_had_error,
                    )
                    .await;
                break 'eval_block decision;
            }

            // ========== 投影门禁（对齐 Java AuthorizationReadPort.getCardProjectionStatus） ==========
            // 已存在 head 的卡必须 READY 且 source==projected，否则 AUTHORIZATION_PENDING；
            // 无 head 历史卡按 legacy-compatible 放行；读取失败 fail-closed（PENDING）。
            let card_id = ctx.card_id.unwrap_or(0);
            let projection_gate = match repo.get_projection_gate(card_id).await {
                Ok(gate) => gate,
                Err(e) => {
                    tracing::warn!(
                        card_id, error = %e,
                        "projection gate read failed, denying (AUTHORIZATION_PENDING)"
                    );
                    steps.push(step(
                        "PROJECTION",
                        "DENY",
                        "projection state unavailable",
                        None,
                    ));
                    timing.total_ns = start.elapsed().as_nanos() as u64;
                    self.record_evaluation("L3", &timing);
                    // gate 读取失败是仓库级故障：必须计入断路器失败（对齐 Java
                    // Resilience4j 仓库异常计失败）。此处 repo_had_error 恒为 false
                    // （无任何先于门禁的仓库调用），直接记 failure，否则 DB 故障
                    // 会被 record_success 清零，断路器永远打不开。
                    self.record_failure_on_evaluate(ctx.resource.as_deref());
                    break 'eval_block deny(
                        "AUTHORIZATION_PENDING",
                        "projection:unavailable",
                        steps,
                    );
                }
            };
            // 捕获快照决策所基于的 gate（供块外一致性检查/执剑人哨兵使用）
            arbiter_gate = projection_gate;
            if let Some(gate) = &projection_gate {
                if !gate.ready {
                    steps.push(step(
                        "PROJECTION",
                        "DENY",
                        &format!(
                            "card projection not ready (source={})",
                            gate.source_generation
                        ),
                        None,
                    ));
                    timing.total_ns = start.elapsed().as_nanos() as u64;
                    self.record_evaluation("L3", &timing);
                    if repo_had_error {
                        self.record_failure_on_evaluate(ctx.resource.as_deref());
                    } else {
                        self.record_success_on_evaluate(ctx.resource.as_deref());
                    }
                    break 'eval_block deny("AUTHORIZATION_PENDING", "projection:not-ready", steps);
                }
            }
            steps.push(step(
                "PROJECTION",
                "PASS",
                "projection ready or legacy-compatible",
                None,
            ));

            // ========== L1: RuleSet 评估（对齐 Java checkRuleSetEffect 只读快照） ==========
            // 仅依赖预编译 rule_set_snapshot 胜者；无源表兜底。
            // 【读链切换批次 3.5】旧 RuleSet 依赖门禁（load_rule_set_dependency_statuses
            // 快照 ready 门禁 + ALLOW 前依赖复检）已退役：strict 生产路径从不经过本
            // legacy 分支，测试仓库的依赖状态读取器不再被引擎消费。ALLOW 前的旧
            // ALLOW 拒绝仍由 CARD 投影复检（projection_still_valid）承担。
            let l1_decision = self
                .evaluate_rule_sets(
                    ctx,
                    repo,
                    &resource_key,
                    &mut steps,
                    &mut timing,
                    &mut repo_had_error,
                )
                .await;
            if let Some(decision) = l1_decision {
                let projection_check = if decision.allowed {
                    self.projection_still_valid(repo, card_id, &projection_gate)
                        .await
                } else {
                    ProjectionCheck::Valid
                };
                if !matches!(projection_check, ProjectionCheck::Valid) {
                    if matches!(projection_check, ProjectionCheck::Error) {
                        repo_had_error = true;
                    }
                    steps.push(step(
                        "PROJECTION",
                        "DENY",
                        "projection advanced during evaluation (stale ALLOW rejected)",
                        None,
                    ));
                    timing.total_ns = start.elapsed().as_nanos() as u64;
                    self.record_evaluation("L3", &timing);
                    if repo_had_error {
                        self.record_failure_on_evaluate(ctx.resource.as_deref());
                    } else {
                        self.record_success_on_evaluate(ctx.resource.as_deref());
                    }
                    break 'eval_block deny(
                        "AUTHORIZATION_PENDING",
                        "projection:stale-allow",
                        steps,
                    );
                }
                timing.total_ns = start.elapsed().as_nanos() as u64;
                self.record_evaluation("L1", &timing);
                if repo_had_error {
                    self.record_failure_on_evaluate(ctx.resource.as_deref());
                } else {
                    self.record_success_on_evaluate(ctx.resource.as_deref());
                }
                break 'eval_block decision;
            }

            // ========== L2: PermissionRule 回退 ==========
            let t_l2 = std::time::Instant::now();
            match self
                .evaluate_permission_rules(ctx, repo, &resource_key, resource_type, &mut steps)
                .await
            {
                Err(error) => {
                    tracing::warn!(card_id, error = %error, "load_permission_rules failed");
                    steps.push(step(
                        "PERMISSION_RULE",
                        "DENY",
                        "permission rule dependency unavailable",
                        None,
                    ));
                    timing.perm_rule_eval_ns = t_l2.elapsed().as_nanos() as u64;
                    timing.total_ns = start.elapsed().as_nanos() as u64;
                    self.record_evaluation("L3", &timing);
                    self.record_failure_on_evaluate(ctx.resource.as_deref());
                    break 'eval_block deny(
                        "DEPENDENCY_UNAVAILABLE",
                        "permission-rule:unavailable",
                        steps,
                    );
                }
                Ok(Some(decision)) => {
                    let projection_check = if decision.allowed {
                        self.projection_still_valid(repo, card_id, &projection_gate)
                            .await
                    } else {
                        ProjectionCheck::Valid
                    };
                    if !matches!(projection_check, ProjectionCheck::Valid) {
                        if matches!(projection_check, ProjectionCheck::Error) {
                            repo_had_error = true;
                        }
                        steps.push(step(
                            "PROJECTION",
                            "DENY",
                            "projection advanced during evaluation (stale ALLOW rejected)",
                            None,
                        ));
                        timing.perm_rule_eval_ns = t_l2.elapsed().as_nanos() as u64;
                        timing.total_ns = start.elapsed().as_nanos() as u64;
                        self.record_evaluation("L3", &timing);
                        if repo_had_error {
                            self.record_failure_on_evaluate(ctx.resource.as_deref());
                        } else {
                            self.record_success_on_evaluate(ctx.resource.as_deref());
                        }
                        break 'eval_block deny(
                            "AUTHORIZATION_PENDING",
                            "projection:stale-allow",
                            steps,
                        );
                    }
                    timing.perm_rule_eval_ns = t_l2.elapsed().as_nanos() as u64;
                    timing.total_ns = start.elapsed().as_nanos() as u64;
                    self.record_evaluation("L2", &timing);
                    if repo_had_error {
                        self.record_failure_on_evaluate(ctx.resource.as_deref());
                    } else {
                        self.record_success_on_evaluate(ctx.resource.as_deref());
                    }
                    break 'eval_block decision;
                }
                Ok(None) => {}
            }

            // ========== L2.5: 委托降级评估 ==========
            // Formal evaluation must consume the same durable CARD projection as
            // L2. A source-table delegation read is intentionally not a fallback.
            // The delegate identity is the selected user_card, never platform user_id.
            if let Some(card_id_ctx) = ctx.card_id {
                match repo
                    .load_projected_delegated_rules(card_id_ctx, resource_type, &ctx.action)
                    .await
                {
                    Ok(delegated) if !delegated.is_empty() => {
                        steps.push(step(
                            "DELEGATION",
                            "EVALUATING",
                            &format!("checking {} delegated rules", delegated.len()),
                            None,
                        ));
                        if let Some(effect) = self
                            .try_match_rules_single_pass(
                                &delegated,
                                &resource_key,
                                resource_type,
                                &ctx.action,
                                ctx,
                            )
                            .await
                        {
                            // ALLOW 返回前投影复检（对齐 Java：防止规则读取期间投影推进产生旧 ALLOW；
                            // gate 读取失败计入断路器失败，避免 DB 故障被 L2.5 成功清零）
                            let mut projection_check = ProjectionCheck::Valid;
                            if matches!(effect, Effect::Allow) {
                                projection_check = self
                                    .projection_still_valid(repo, card_id, &projection_gate)
                                    .await;
                            }
                            let stale = !matches!(projection_check, ProjectionCheck::Valid);
                            if matches!(projection_check, ProjectionCheck::Error) {
                                repo_had_error = true;
                            }
                            let decision = if stale {
                                steps.push(step(
                                    "PROJECTION",
                                    "DENY",
                                    "projection advanced during evaluation (stale ALLOW rejected)",
                                    None,
                                ));
                                deny(
                                    "AUTHORIZATION_PENDING",
                                    "projection:stale-allow",
                                    steps.clone(),
                                )
                            } else {
                                match effect {
                                    Effect::Allow => {
                                        steps.push(step(
                                            "DELEGATION",
                                            "ALLOW",
                                            &resource_key,
                                            None,
                                        ));
                                        allow(
                                            "DELEGATION_ALLOW",
                                            &format!(
                                                "delegation:{resource_key}:{}:cardId={card_id_ctx}",
                                                ctx.action
                                            ),
                                            steps.clone(),
                                        )
                                    }
                                    Effect::Deny => {
                                        steps.push(step("DELEGATION", "DENY", &resource_key, None));
                                        deny(
                                            "DELEGATION_DENY",
                                            &format!(
                                                "delegation:{resource_key}:{}:cardId={card_id_ctx}",
                                                ctx.action
                                            ),
                                            steps.clone(),
                                        )
                                    }
                                    Effect::NotMatch => {
                                        steps.push(step(
                                            "DELEGATION",
                                            "NOT_MATCH",
                                            &resource_key,
                                            None,
                                        ));
                                        deny("DEFAULT_DENY", "delegation:no-match", steps.clone())
                                    }
                                }
                            };
                            timing.perm_rule_eval_ns = t_l2.elapsed().as_nanos() as u64;
                            timing.total_ns = start.elapsed().as_nanos() as u64;
                            self.record_evaluation("L2.5", &timing);
                            if repo_had_error {
                                self.record_failure_on_evaluate(ctx.resource.as_deref());
                            } else {
                                self.record_success_on_evaluate(ctx.resource.as_deref());
                            }
                            break 'eval_block decision;
                        }
                    }
                    Ok(_) => { /* 无委托规则，跳过 L2.5 */ }
                    Err(e) => {
                        tracing::warn!(card_id_ctx, error = %e, "L2.5 projected delegation read failed");
                        repo_had_error = true;
                    }
                }
            }

            // ========== L3: 默认拒绝（fail-closed） ==========
            steps.push(step(
                "DEFAULT",
                "DENY",
                &format!("no matching rule found for {resource_key}:{}", ctx.action),
                None,
            ));

            timing.total_ns = start.elapsed().as_nanos() as u64;
            self.record_evaluation("L3", &timing);

            // L1 仓库错误累计断路器失败计数（对齐 Java Resilience4j：仓库异常计入失败，
            // 否则 DB 故障时断路器永远无法打开）。此处已 fail-closed → DENY，仍记失败。
            if repo_had_error {
                self.record_failure_on_evaluate(ctx.resource.as_deref());
            } else {
                self.record_success_on_evaluate(ctx.resource.as_deref());
            }
            break 'eval_block deny(
                "DEFAULT_DENY",
                &format!(
                    "default:{resource_key}:{}:cardId={}",
                    ctx.action,
                    ctx.card_id.unwrap_or(0)
                ),
                steps,
            );
        }; // end 'eval_block

        // 一致性检查（1% 采样，对齐 Java SnapshotConsistencyChecker.checkConsistencyAsync）
        // 使用全局单例 CHECKER，与 consistency_monitor 端点共享同一实例。
        // strict published-evidence repository 必须整体跳过：其正式授权只消费
        // published evidence，采样会调用 evaluate_realtime 触碰 raw source 读取器
        // （raw rule_set_entry / raw permission_rule / legacy delegation），违反
        // strict gate "不触碰任何 raw/source/cache 回退" 的契约；其决策也没有
        // 可与 realtime oracle 比对的快照路径。非 strict 仓库行为不变。
        // 测试构建同样整体跳过：采样相位是进程级共享状态，隔离运行的
        // 首个 evaluate 恒命中采样边界，采样重评估会污染 crate 内测试对
        // repo 调用次数的精确断言（顺序依赖缺陷）。采样器语义由
        // consistency.rs 的单元测试与 monitor 端点覆盖。
        if cfg!(test) {
        } else if !strict_published_evidence && decision.org_provenance.is_none() {
            if let Some(violation) = get_consistency_checker()
                .check_consistency(ctx, &decision, self, repo)
                .await
            {
                // 执剑人哨兵（阶段 A）：快照/实时分歧且快照 gate 可证明时生成冲突信号。
                // 阶段 A 只发布信号（默认 no-op sink），仲裁执行由阶段 B 的 runner 挂接。
                if let Some(signal) = crate::arbiter::detect_conflict(&violation, arbiter_gate) {
                    crate::arbiter::emit_conflict_signal(&signal);
                }
            }
        }

        // ALLOW 命中统计（对齐 Java：ALLOW 命中异步写入 permission_hit_stat）。
        // 纯函数提取 phase 供 DB upsert；DB 不可用仅记 debug，不阻塞主链。
        if decision.allowed {
            if let Some(phase) = decision
                .evaluation_path
                .iter()
                .rev()
                .find(|s| s.result == astral_types::Effect::Allow)
                .map(|s| s.phase.clone())
            {
                if let Some(card_id) = ctx.card_id {
                    tracing::debug!(
                        card_id,
                        resource = %ctx.resource.as_deref().unwrap_or(""),
                        action = %ctx.action,
                        phase = %phase,
                        "permission hit recorded"
                    );
                }
            }
        }

        decision
    }

    /// Canonical hit-stat source value. Physical SNAPSHOT reads are mapped to
    /// the underlying RULE_SET source, while internal phase names stay private.
    /// Published-evidence ALLOWs are mapped by their per-grant source label:
    /// RULE_SET_BASE / RULE_SET_OVERLAY → RULE_SET，DIRECT / APPROVAL /
    /// DELEGATION 保持同名单独成值，其余（含 SYSTEM）沿用 PERMISSION_RULE 兜底。
    /// ORG_SCOPE 准入的 ALLOW 步（phase=`ORG_AUTHORITY`，source=`ORG_PERSONAL`/
    /// `ORG_SHARED`，见 `org_admission::evaluate`）必须上报为 `ORG_AUTHORITY`
    /// 精确来源，不得落入 PERMISSION_RULE 兜底；分支细分（PERSONAL/SHARED）
    /// 不进入 hit-stat source。其余未知 phase 继续沿用 PERMISSION_RULE 兜底，
    /// legacy 映射保持不变。
    pub fn allow_source_phase(decision: &PolicyDecision) -> Option<&'static str> {
        if !decision.allowed {
            return None;
        }
        decision
            .evaluation_path
            .iter()
            .rev()
            .find(|s| s.result == astral_types::Effect::Allow)
            .map(|step| {
                if step.phase == "PUBLISHED_EVIDENCE" {
                    return match step.source.as_deref() {
                        Some("RULE_SET_BASE") | Some("RULE_SET_OVERLAY") | Some("RULE_SET") => {
                            "RULE_SET"
                        }
                        Some("DIRECT") => "DIRECT",
                        Some("APPROVAL") => "APPROVAL",
                        Some("DELEGATION") => "DELEGATION",
                        _ => "PERMISSION_RULE",
                    };
                }
                match step.phase.as_str() {
                    "RULESET" | "RULE_SET" | "SNAPSHOT" => "RULE_SET",
                    "PERMISSION_RULE" => "PERMISSION_RULE",
                    "DELEGATION" => "DELEGATION",
                    "TEMPLATE" => "TEMPLATE",
                    "ORG_AUTHORITY" => "ORG_AUTHORITY",
                    _ => "PERMISSION_RULE",
                }
            })
    }

    /// 一致性检查专用评估：绕过所有快照/缓存层，直接查原始表
    ///
    /// 对齐 Java `SnapshotConsistencyChecker.evaluateRealtime()`。
    ///
    /// 【读链切换批次 3.5 起为纯 raw oracle】三层全部走 raw 源表读取器，
    /// 不触碰任何快照/投影/依赖门禁：
    /// - L1 raw：[`RuleRepository::load_rule_set_entries_raw`]（`rule_set_entry` 源表）；
    /// - L2 raw：[`RuleRepository::load_permission_rules_raw`]（`permission_rule` 源表）；
    /// - L2.5 raw：[`RuleRepository::load_delegated_rules`]（仅一致性路径保留）。
    ///
    /// 唯一的 gate 是 CARD 投影门禁（`get_projection_gate`）及其 ALLOW 前复检
    /// （`projection_still_valid`）：raw 源表只有在与 durable 投影同步时才可与
    /// oracle 比对；旧 RuleSet 快照 ready 依赖门禁不适用于 raw oracle，已随
    /// 批次 3.5 从引擎移除。本路径永不产生授权放行（一致性采样/oracle 专用）。
    pub async fn evaluate_realtime<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        let mut steps: Vec<EvaluationStep> = Vec::new();

        // AUTHN + CARD_CONTEXT（与 evaluate() 共享相同的前置校验逻辑）
        if ctx.user_id.is_none() {
            steps.push(step("AUTHN", "DENY", "no user context (realtime)", None));
            return deny("AUTHN_REQUIRED", "authn", steps);
        }
        if ctx.card_id.is_none() {
            steps.push(step("AUTHN", "DENY", "no card selected (realtime)", None));
            return deny("CARD_REQUIRED", "no-card-selected", steps);
        }
        // CARD_CONTEXT（对齐 evaluate() 的卡片活跃性校验）
        if let Some(card_id) = ctx.card_id {
            match repo.check_card_active(ctx).await {
                Ok(true) => {}
                Ok(false) => {
                    steps.push(step(
                        "CARD_CONTEXT",
                        "DENY",
                        &format!("card {card_id} is inactive (realtime)"),
                        None,
                    ));
                    return deny("CARD_DISABLED", &format!("card:{card_id}:disabled"), steps);
                }
                Err(e) => {
                    tracing::warn!(card_id, error = %e, "realtime card context dependency unavailable");
                    steps.push(step(
                        "CARD_CONTEXT",
                        "DENY",
                        "card context dependency unavailable (realtime)",
                        None,
                    ));
                    return deny(
                        "DEPENDENCY_UNAVAILABLE",
                        &format!("card:{card_id}:unavailable"),
                        steps,
                    );
                }
            }
        }
        if ctx.resource.as_deref().is_none_or(|r| r.is_empty()) {
            steps.push(step("AUTHN", "DENY", "no resource (realtime)", None));
            return deny("RESOURCE_REQUIRED", "no-resource", steps);
        }
        if ctx.action.is_empty() {
            steps.push(step("AUTHN", "DENY", "no action (realtime)", None));
            return deny("ACTION_REQUIRED", "no-action", steps);
        }

        let card_id = ctx.card_id.unwrap_or(0);
        // Realtime consistency checks must use the same projection barrier as
        // the normal authorization path. Raw source tables are not safe to
        // compare while the durable projection is catching up.
        let projection_gate = match repo.get_projection_gate(card_id).await {
            Ok(gate) => gate,
            Err(e) => {
                tracing::debug!(card_id, error = %e, "realtime projection gate unavailable");
                steps.push(step(
                    "PROJECTION",
                    "DENY",
                    "projection state unavailable (realtime)",
                    None,
                ));
                return deny("AUTHORIZATION_PENDING", "projection:unavailable", steps);
            }
        };
        if let Some(gate) = projection_gate {
            if !gate.ready {
                steps.push(step(
                    "PROJECTION",
                    "DENY",
                    &format!(
                        "card projection not ready (realtime, source={})",
                        gate.source_generation
                    ),
                    None,
                ));
                return deny("AUTHORIZATION_PENDING", "projection:not-ready", steps);
            }
        }
        steps.push(step(
            "PROJECTION",
            "PASS",
            "projection ready or legacy-compatible (realtime)",
            None,
        ));

        let resource_type = ctx.resource.as_deref().unwrap_or("");
        let resource_key = build_resource_key(resource_type, ctx.target_id);
        let action = &ctx.action;

        // L1: 强制原始 rule_set_entry 扫描（跳过快照预计算层）
        if let Ok(snapshots) = repo.load_rule_set_entries_raw(ctx.card_id.unwrap()).await {
            if !snapshots.is_empty() {
                let overlays: Vec<&RuleSetSnapshot> = snapshots
                    .iter()
                    .filter(|s| s.ref_type == "OVERLAY")
                    .collect();
                let bases: Vec<&RuleSetSnapshot> =
                    snapshots.iter().filter(|s| s.ref_type == "BASE").collect();

                // OVERLAY 层
                if let Some(effect) = self
                    .first_matching_effect(
                        &overlays,
                        ctx,
                        &resource_key,
                        resource_type,
                        "OVERLAY_REALTIME",
                        &mut steps,
                    )
                    .await
                {
                    if !matches!(
                        self.projection_still_valid(repo, card_id, &projection_gate)
                            .await,
                        ProjectionCheck::Valid
                    ) {
                        return self.realtime_pending_decision(
                            "projection changed during realtime evaluation",
                            steps,
                        );
                    }
                    return self.realtime_decision(&effect, &resource_key, action, steps);
                }
                // BASE 层
                if let Some(effect) = self
                    .first_matching_effect(
                        &bases,
                        ctx,
                        &resource_key,
                        resource_type,
                        "BASE_REALTIME",
                        &mut steps,
                    )
                    .await
                {
                    if !matches!(
                        self.projection_still_valid(repo, card_id, &projection_gate)
                            .await,
                        ProjectionCheck::Valid
                    ) {
                        return self.realtime_pending_decision(
                            "projection changed during realtime evaluation",
                            steps,
                        );
                    }
                    return self.realtime_decision(&effect, &resource_key, action, steps);
                }
            }
        }

        // L2: 强制原始 permission_rule 扫描（跳过 permission_rule_snapshot）。
        // 源表行携带 priority：单 pass 优先级匹配（对齐 Java `evaluateRules` 同池竞争）。
        let rules = match repo.load_permission_rules_raw(ctx.card_id.unwrap()).await {
            Ok(rules) => rules,
            Err(error) => {
                tracing::warn!(card_id, error = %error, "load_permission_rules_raw failed");
                steps.push(step(
                    "PERMISSION_RULE",
                    "DENY",
                    "permission rule dependency unavailable (realtime)",
                    None,
                ));
                return deny(
                    "DEPENDENCY_UNAVAILABLE",
                    "realtime:permission-rule-unavailable",
                    steps,
                );
            }
        };
        {
            if let Some(effect) = self
                .try_match_rules_single_pass(&rules, &resource_key, resource_type, action, ctx)
                .await
            {
                if !matches!(
                    self.projection_still_valid(repo, card_id, &projection_gate)
                        .await,
                    ProjectionCheck::Valid
                ) {
                    return self.realtime_pending_decision(
                        "projection changed during realtime evaluation",
                        steps,
                    );
                }
                return self.realtime_decision(&effect, &resource_key, action, steps);
            }
            // 别名展开
            for alias_action in get_alias_sources(action) {
                if let Some(effect) = self
                    .try_match_rules_single_pass(
                        &rules,
                        &resource_key,
                        resource_type,
                        alias_action,
                        ctx,
                    )
                    .await
                {
                    if !matches!(
                        self.projection_still_valid(repo, card_id, &projection_gate)
                            .await,
                        ProjectionCheck::Valid
                    ) {
                        return self.realtime_pending_decision(
                            "projection changed during realtime evaluation",
                            steps,
                        );
                    }
                    return self.realtime_decision(&effect, &resource_key, action, steps);
                }
            }
        }

        // L2.5: 委托评估（与 evaluate() 保持一致）。
        // 注意：委托对象是 user_card（delegate_card_id），不是平台用户（user_id），
        // 必须用 ctx.card_id 绑定，防止 ID 空间错位导致的跨卡误授（对齐正式路径）。
        if let Some(card_id_ctx) = ctx.card_id {
            if let Ok(delegated) = repo
                .load_delegated_rules(card_id_ctx, resource_type, action)
                .await
            {
                if !delegated.is_empty() {
                    steps.push(step(
                        "DELEGATION",
                        "EVALUATING_REALTIME",
                        &format!("checking {} delegated rules", delegated.len()),
                        None,
                    ));
                    if let Some(effect) = self
                        .try_match_rules_single_pass(
                            &delegated,
                            &resource_key,
                            resource_type,
                            action,
                            ctx,
                        )
                        .await
                    {
                        if !matches!(
                            self.projection_still_valid(repo, card_id, &projection_gate)
                                .await,
                            ProjectionCheck::Valid
                        ) {
                            return self.realtime_pending_decision(
                                "projection changed during realtime evaluation",
                                steps,
                            );
                        }
                        return self.realtime_decision(&effect, &resource_key, action, steps);
                    }
                }
            }
        }

        // L3: DEFAULT_DENY
        steps.push(step(
            "DEFAULT",
            "DENY",
            &format!("realtime: no matching rule for {resource_key}:{action}"),
            None,
        ));
        deny(
            "DEFAULT_DENY",
            &format!("realtime:default:{resource_key}:{action}"),
            steps,
        )
    }

    fn realtime_pending_decision(
        &self,
        detail: &str,
        mut steps: Vec<EvaluationStep>,
    ) -> PolicyDecision {
        steps.push(step("PROJECTION", "DENY", detail, None));
        deny("AUTHORIZATION_PENDING", "projection:stale-allow", steps)
    }

    fn realtime_decision(
        &self,
        effect: &Effect,
        resource_key: &str,
        action: &str,
        mut steps: Vec<EvaluationStep>,
    ) -> PolicyDecision {
        match effect {
            Effect::Allow => {
                steps.push(step("PERMISSION_RULE", "ALLOW", resource_key, None));
                allow(
                    "REALTIME_ALLOW",
                    &format!("realtime:rule:{resource_key}:{action}"),
                    steps,
                )
            }
            Effect::Deny => {
                steps.push(step("PERMISSION_RULE", "DENY", resource_key, None));
                deny(
                    "REALTIME_DENY",
                    &format!("realtime:rule:{resource_key}:{action}"),
                    steps,
                )
            }
            Effect::NotMatch => deny("DEFAULT_DENY", "realtime:no-match", vec![]),
        }
    }

    // ==================== L1: RuleSet 评估 ====================

    /// RuleSet 评估 — 对齐 Java PolicyEngine 行为
    ///
    /// 各层内 first-match-wins（第一个匹配的 ref 决定该层效果）。
    /// 跨层优先级: OVERLAY > BASE
    /// 即：OVERLAY 的 DENY 和 ALLOW 都优先于 BASE 的任何效果。
    #[allow(clippy::too_many_arguments)]
    /// L1: 规则集评估（对齐 Java `PolicyEngine` 逐 ref `checkRuleSetEffect`）
    ///
    /// Java 权威语义：
    /// - 只读预编译 `rule_set_snapshot`（含 BASE/OVERLAY 绑定与 winnerMap 胜者）；
    ///   无 `rule_set_entry` 源表兜底（Java `checkRuleSetEffect` 一律 selectOne 快照）。
    /// - 每层（OVERLAY 先行、BASE 后行）按 refs 顺序 **逐 ref first-match-wins**：
    ///   第一个返回非 null 效果的 ref 即定该层效果（对齐 `PolicyEngine` 双层循环的
    ///   `layerEffect == null` 守卫）。
    /// - 单 ref 内匹配顺序（对齐 `RuleSetService.checkRuleSetEffect`）：
    ///   exact → forward wildcard（请求为具体 ID）→ reverse wildcard（请求为
    ///   `type:*` 且快照有对象级条目，DENY 优先）→ 动作别名（exact→forward→reverse）。
    /// - 快照读取失败（仓库异常）→ 立即 DENY（对齐 Java 异常传播 → 断路器 fallback），
    ///   不得继续 L2：快照不可用可能掩盖已撤销权限，继续评估会宽松化。
    #[allow(clippy::too_many_arguments)]
    async fn evaluate_rule_sets<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
        resource_key: &str,
        steps: &mut Vec<EvaluationStep>,
        timing: &mut TimingBreakdown,
        repo_error: &mut bool,
    ) -> Option<PolicyDecision> {
        let card_id = ctx.card_id?;
        let t_refs = std::time::Instant::now();

        let winners = match repo.load_snapshot_winners(card_id).await {
            Ok(winners) => winners,
            Err(e) => {
                tracing::error!(error = %e, card_id, "load_snapshot_winners failed");
                *repo_error = true;
                timing.refs_load_ns = t_refs.elapsed().as_nanos() as u64;
                return Some(deny(
                    "RULE_SET_UNAVAILABLE",
                    "ruleset:load-failed",
                    steps.clone(),
                ));
            }
        };
        timing.refs_load_ns = t_refs.elapsed().as_nanos() as u64;
        if winners.is_empty() {
            // 无快照条目（含 legacy 卡无快照）→ L1 无匹配，落 L2
            // （对齐 Java checkRuleSetEffect 返回 null；Java 无源表兜底）。
            return None;
        }

        // 按 ref_type 分组，组内保持 refs 顺序（SQL ORDER BY ref_type, id；
        // 对齐 Java `getCardRuleSetRefs` orderByAsc(ref_type) 的逐层 ref 顺序）。
        let mut overlay_groups: Vec<(i64, Vec<&SnapshotWinner>)> = Vec::new();
        let mut base_groups: Vec<(i64, Vec<&SnapshotWinner>)> = Vec::new();
        for winner in &winners {
            let groups = if winner.ref_type == "OVERLAY" {
                &mut overlay_groups
            } else {
                &mut base_groups
            };
            match groups.iter_mut().find(|(id, _)| *id == winner.rule_set_id) {
                Some((_, list)) => list.push(winner),
                None => groups.push((winner.rule_set_id, vec![winner])),
            }
        }

        steps.push(step(
            "RULESET",
            "EVALUATING",
            &format!(
                "snapshot path: {} OVERLAY refs, {} BASE refs",
                overlay_groups.len(),
                base_groups.len()
            ),
            None,
        ));

        // OVERLAY 层：逐 ref first-match-wins（Java 首个命中即定该层效果）
        if let Some(decision) = self.match_layer_first_match(
            &overlay_groups,
            resource_key,
            &ctx.action,
            "OVERLAY",
            steps,
        ) {
            return Some(decision);
        }
        // BASE 层
        if let Some(decision) =
            self.match_layer_first_match(&base_groups, resource_key, &ctx.action, "BASE", steps)
        {
            return Some(decision);
        }
        None
    }

    /// 逐 ref first-match-wins：按 Java `getCardRuleSetRefs` 顺序遍历 refs，
    /// 第一个命中即返回决策；无命中继续下一个 ref（对齐 `PolicyEngine` 双层循环
    /// 中 `layerEffect == null` 才评估下一个 ref 的语义）。
    fn match_layer_first_match(
        &self,
        groups: &[(i64, Vec<&SnapshotWinner>)],
        resource_key: &str,
        action: &str,
        layer: &str,
        steps: &mut Vec<EvaluationStep>,
    ) -> Option<PolicyDecision> {
        for (rule_set_id, winners) in groups {
            if let Some(decision) =
                self.match_ref_snapshot(*rule_set_id, winners, resource_key, action, layer, steps)
            {
                return Some(decision);
            }
            steps.push(step(
                "RULESET",
                "NO_MATCH",
                &format!("{layer} ruleSetId={rule_set_id} no match"),
                Some(layer.to_string()),
            ));
        }
        None
    }

    /// 单 ref 内快照匹配（对齐 Java `RuleSetService.checkRuleSetEffect`）：
    ///
    /// 1. exact：`resourceKey + actionCode` 完全一致
    /// 2. forward wildcard：请求为具体 ID（`type:id`）→ 尝试 `type:*`
    /// 3. reverse wildcard：请求为 `type:*` → 扫描对象级条目（`type:<anyId>`），
    ///    按 DENY 优先取确定性结果（对齐 Java `scanSnapshotEffect` 的
    ///    `orderByDesc(final_effect) LIMIT 1`）
    /// 4. 动作别名：对 write→create/update/delete 依次重复 exact→forward→reverse
    fn match_ref_snapshot(
        &self,
        rule_set_id: i64,
        winners: &[&SnapshotWinner],
        resource_key: &str,
        action: &str,
        layer: &str,
        steps: &mut Vec<EvaluationStep>,
    ) -> Option<PolicyDecision> {
        // Step 1: exact
        if let Some(decision) =
            self.winner_exact_match(winners, rule_set_id, resource_key, action, layer, steps)
        {
            return Some(decision);
        }

        // Step 2: forward wildcard
        if !is_wildcard_key(resource_key) {
            if let Some(colon) = resource_key.rfind(':') {
                let wildcard_key = format!("{}:*", &resource_key[..colon]);
                if let Some(decision) = self.winner_exact_match(
                    winners,
                    rule_set_id,
                    &wildcard_key,
                    action,
                    layer,
                    steps,
                ) {
                    return Some(decision);
                }
            }
        }

        // Step 3: reverse wildcard — 请求 `type:*`，快照有对象级条目
        if is_wildcard_key(resource_key) {
            if let Some(prefix) = resource_key.strip_suffix(":*") {
                if let Some(decision) =
                    self.winner_reverse_match(winners, rule_set_id, prefix, action, layer, steps)
                {
                    return Some(decision);
                }
            }
        }

        // Step 4: 动作别名展开（write → create/update/delete）
        for alias_action in get_alias_sources(action) {
            if let Some(decision) = self.winner_exact_match(
                winners,
                rule_set_id,
                resource_key,
                alias_action,
                layer,
                steps,
            ) {
                return Some(decision);
            }
            if !is_wildcard_key(resource_key) {
                if let Some(colon) = resource_key.rfind(':') {
                    let wildcard_key = format!("{}:*", &resource_key[..colon]);
                    if let Some(decision) = self.winner_exact_match(
                        winners,
                        rule_set_id,
                        &wildcard_key,
                        alias_action,
                        layer,
                        steps,
                    ) {
                        return Some(decision);
                    }
                }
            }
            if is_wildcard_key(resource_key) {
                if let Some(prefix) = resource_key.strip_suffix(":*") {
                    if let Some(decision) = self.winner_reverse_match(
                        winners,
                        rule_set_id,
                        prefix,
                        alias_action,
                        layer,
                        steps,
                    ) {
                        return Some(decision);
                    }
                }
            }
        }

        None
    }

    /// 在预计算快照胜者中做精确的 (resource_key, action_code) 匹配
    fn winner_exact_match(
        &self,
        winners: &[&SnapshotWinner],
        rule_set_id: i64,
        target_key: &str,
        target_action: &str,
        layer: &str,
        steps: &mut Vec<EvaluationStep>,
    ) -> Option<PolicyDecision> {
        for winner in winners {
            if winner.resource_key == target_key && winner.action_code == target_action {
                let effect = winner.final_effect.as_str();
                steps.push(step(
                    "RULESET",
                    effect,
                    &format!(
                        "{layer} ruleSetId={rule_set_id} snapshot {} for {target_key}:{target_action}",
                        effect
                    ),
                    Some(layer.to_string()),
                ));
                return Some(decision_from_effect(
                    effect,
                    &format!("snapshot:{target_key}:{target_action}"),
                    steps.clone(),
                ));
            }
        }
        None
    }

    /// reverse wildcard 匹配（对齐 Java `scanSnapshotEffect`）：请求为 `type:*`，
    /// 扫描该 ref 快照中 `type:<anyId>` 的对象级条目，DENY 优先于 ALLOW。
    ///
    /// 注意：快照中同一 (resource_key, action_code) 已由投影器编译为唯一胜者，
    /// 因此这里只需要在对象级条目中找“是否存在 DENY / 是否存在 ALLOW”。
    fn winner_reverse_match(
        &self,
        winners: &[&SnapshotWinner],
        rule_set_id: i64,
        resource_prefix: &str,
        target_action: &str,
        layer: &str,
        steps: &mut Vec<EvaluationStep>,
    ) -> Option<PolicyDecision> {
        let mut any = false;
        for winner in winners {
            if winner.action_code == target_action
                && winner
                    .resource_key
                    .strip_prefix(resource_prefix)
                    .is_some_and(|rest| rest.starts_with(':'))
                && !winner.resource_key.ends_with(":*")
            {
                any = true;
                if winner.final_effect == "DENY" {
                    steps.push(step(
                        "RULESET",
                        "DENY",
                        &format!(
                            "{layer} ruleSetId={rule_set_id} reverse wildcard DENY via {}",
                            winner.resource_key
                        ),
                        Some(layer.to_string()),
                    ));
                    return Some(decision_from_effect(
                        "DENY",
                        &format!("snapshot:{resource_prefix}:*"),
                        steps.clone(),
                    ));
                }
            }
        }
        if any {
            steps.push(step(
                "RULESET",
                "ALLOW",
                &format!(
                    "{layer} ruleSetId={rule_set_id} reverse wildcard ALLOW (object ALLOW, no DENY)"
                ),
                Some(layer.to_string()),
            ));
            return Some(decision_from_effect(
                "ALLOW",
                &format!("snapshot:{resource_prefix}:*"),
                steps.clone(),
            ));
        }
        None
    }

    /// 遍历 refs 列表，返回第一个匹配的 effect（first-match-wins per ref type）
    ///
    /// 对齐 Java `checkRuleSetEffect` 循环：
    /// ```java
    /// for (CardRuleSetRef ref : refs) {
    ///     if ("OVERLAY".equals(ref.getRefType()) && overlayEffect == null) {
    ///         String effect = checkRuleSetEffect(ref.getRuleSetId(), ...);
    ///         if (effect != null) overlayEffect = effect;
    ///     }
    /// }
    /// ```
    async fn first_matching_effect(
        &self,
        snapshots: &[&RuleSetSnapshot],
        ctx: &PolicyContext,
        resource_key: &str,
        resource_type: &str,
        layer: &str,
        steps: &mut Vec<EvaluationStep>,
    ) -> Option<Effect> {
        for snapshot in snapshots {
            let matched = self
                .match_in_snapshot(snapshot, ctx, resource_key, resource_type)
                .await;

            match matched {
                Some(Effect::Allow) => {
                    steps.push(step(
                        "RULESET",
                        "ALLOW",
                        &format!("{layer} ruleSetId={} matched ALLOW", snapshot.rule_set_id),
                        Some(layer.to_string()),
                    ));
                    return Some(Effect::Allow);
                }
                Some(Effect::Deny) => {
                    steps.push(step(
                        "RULESET",
                        "DENY",
                        &format!("{layer} ruleSetId={} matched DENY", snapshot.rule_set_id),
                        Some(layer.to_string()),
                    ));
                    return Some(Effect::Deny);
                }
                _ => {
                    steps.push(step(
                        "RULESET",
                        "NO_MATCH",
                        &format!("{layer} ruleSetId={} no match", snapshot.rule_set_id),
                        Some(layer.to_string()),
                    ));
                }
            }
        }
        None
    }

    /// 在单个规则集快照中扫描匹配条目
    ///
    /// 按 priority 顺序 first-match-wins（对齐 Java snapshot 语义）。
    /// 条目已由 SQL `ORDER BY priority ASC` 排序，第一个匹配即胜出。
    async fn match_in_snapshot(
        &self,
        snapshot: &RuleSetSnapshot,
        ctx: &PolicyContext,
        resource_key: &str,
        resource_type: &str,
    ) -> Option<Effect> {
        let action = &ctx.action;

        // Phase 1: 按 priority 顺序扫描，第一个匹配即返回
        if let Some(effect) = self
            .scan_entries_first_match(&snapshot.entries, resource_key, resource_type, action, ctx)
            .await
        {
            return Some(effect);
        }

        // Phase 2: 别名展开
        for alias_action in get_alias_sources(action) {
            if let Some(effect) = self
                .scan_entries_first_match(
                    &snapshot.entries,
                    resource_key,
                    resource_type,
                    alias_action,
                    ctx,
                )
                .await
            {
                return Some(effect);
            }
        }

        None
    }

    /// 按 priority 顺序扫描 entries，返回第一个匹配的 effect
    ///
    /// Java 对齐：`RuleSetService.evaluateRealtimeByAction()` —— 单个
    /// `ORDER BY priority DESC` 结果集（对象级 resource_id=? 与类型级 resource_id IS NULL
    /// 同池竞争），第一个匹配（无运行时条件、窗口内）即胜出；**不存在对象优先于类型的
    /// 两段式**。Rust 等效：entries 已由 SQL `ORDER BY priority DESC, effect DESC` 排序，
    /// 单一 pass 按行序 first-match-wins，最高 priority 的匹配条目胜出（无论对象/类型级）。
    ///
    /// ⚠️ 对齐 Java 行为：带运行时条件的条目被视为「不在 snapshot 中」而被跳过。
    /// 如果所有条目都有运行时条件，则 L1 无匹配 → 降级到 L2。
    async fn scan_entries_first_match(
        &self,
        entries: &[RuleSetEntry],
        resource_key: &str,
        resource_type: &str,
        action: &str,
        _ctx: &PolicyContext,
    ) -> Option<Effect> {
        let is_wildcard = is_wildcard_key(resource_key);

        for entry in entries {
            let entry_res = entry.resource.as_deref().unwrap_or("*");
            let entry_act = entry.action.as_deref().unwrap_or("*");

            if entry_act != "*" && entry_act != action {
                continue;
            }

            // 对象级与类型级同池按 priority 竞争：具体请求可命中对象规则
            // （learn_subject:42）或类型级规则（learn_subject:* / learn_subject / *）；
            // 类型级请求只命中类型级规则（防止类型级请求被对象级规则放大授权，
            // 对齐 Java `resource_id IS NULL OR resource_id = ?` 的候选集）。
            let resource_match = if is_wildcard {
                entry_res == resource_key || entry_res == resource_type || entry_res == "*"
            } else {
                entry_res == resource_key
                    || entry_res == format!("{resource_type}:*")
                    || entry_res == resource_type
                    || entry_res == "*"
            };
            if !resource_match {
                continue;
            }

            // 对齐 Java `RuleSetService.hasRuntimeCondition()`：带运行时条件的条目
            // 被排除出 snapshot，L1 评估中跳过。
            if has_runtime_condition(&entry.condition) {
                tracing::trace!(
                    "skipping entry with runtime condition: type={:?}",
                    entry
                        .condition
                        .as_ref()
                        .and_then(|c| c.get("condition_type").and_then(|v| v.as_str()))
                );
                continue;
            }

            return Some(entry.effect.clone());
        }

        None
    }

    // ==================== L2: PermissionRule 回退 ====================

    /// PermissionRule 回退评估（L2）
    ///
    /// 同样支持 resourceKey 匹配和别名展开。
    async fn evaluate_permission_rules<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
        resource_key: &str,
        resource_type: &str,
        steps: &mut Vec<EvaluationStep>,
    ) -> Result<Option<PolicyDecision>, PolicyError> {
        let Some(card_id) = ctx.card_id else {
            return Ok(None);
        };

        steps.push(step(
            "PERMISSION_RULE",
            "EVALUATING",
            &format!("checking permission_rule for cardId={card_id}"),
            None,
        ));

        let rules = repo.load_permission_rules(card_id).await?;
        let action = &ctx.action;

        // 分派：快照行（id==0，预编译胜者）按精确键 selectOne 语义两段式匹配；
        // 源表行（id!=0，携带 priority）按 Java `evaluateRules` 单 pass 优先级语义。
        // Java 两条路径语义不同，混用会破坏优先级（具体对象 ALLOW 遮蔽高优先级类型 DENY
        // 或反之），必须按数据来源分派。
        if rules.iter().all(|r| r.id == 0) {
            // 两段式精确优先匹配（对齐 Java `PermissionSnapshotService.findSnapshot`
            // 按精确 resource_key selectOne 的语义）：具体对象规则（如 learn_subject:42 DENY）
            // 必须先于类型级通配规则（learn_subject:* ALLOW）判定。快照行是预编译胜者，
            // 每 (resource_key, action) 仅一行，精确优先即 Java 语义。
            if let Some(effect) = self
                .try_match_rules_exact_first(&rules, resource_key, resource_type, action, ctx)
                .await
            {
                return Ok(Some(self.build_rule_decision(
                    &effect,
                    resource_key,
                    action,
                    card_id,
                    steps,
                )));
            }

            // 别名展开（同样的精确优先两段式）
            let alias_sources = get_alias_sources(action);
            for alias_action in &alias_sources {
                if let Some(effect) = self
                    .try_match_rules_exact_first(
                        &rules,
                        resource_key,
                        resource_type,
                        alias_action,
                        ctx,
                    )
                    .await
                {
                    return Ok(Some(self.build_rule_decision(
                        &effect,
                        resource_key,
                        action,
                        card_id,
                        steps,
                    )));
                }
            }
        } else {
            // 单 pass 优先级匹配（对齐 Java `PermissionCheckService.evaluateRules`：
            // 对象级与类型级同池 `ORDER BY priority DESC, effect DESC`，第一个条件满足者胜出）。
            if let Some(effect) = self
                .try_match_rules_single_pass(&rules, resource_key, resource_type, action, ctx)
                .await
            {
                return Ok(Some(self.build_rule_decision(
                    &effect,
                    resource_key,
                    action,
                    card_id,
                    steps,
                )));
            }

            // 别名展开（同样的单 pass 语义）
            let alias_sources = get_alias_sources(action);
            for alias_action in &alias_sources {
                if let Some(effect) = self
                    .try_match_rules_single_pass(
                        &rules,
                        resource_key,
                        resource_type,
                        alias_action,
                        ctx,
                    )
                    .await
                {
                    return Ok(Some(self.build_rule_decision(
                        &effect,
                        resource_key,
                        action,
                        card_id,
                        steps,
                    )));
                }
            }
        }

        Ok(None)
    }

    /// 两段式匹配：先精确 pass（仅完全一致的 resource_key），再通配 pass。
    ///
    /// **仅用于快照行（`PermissionRule.id == 0`，预编译胜者）**，对齐 Java
    /// `checkRuleSetEffect` Step 1 精确 + Step 2 正向通配：
    /// - 具体请求（learn_subject:42）：精确 pass 命中 learn_subject:42；通配 pass 命中
    ///   learn_subject:* / learn_subject / *
    /// - 类型请求（learn_subject:*）：仅类型级规则（learn_subject:* / learn_subject / *），
    ///   不命中具体对象规则（防止类型级请求被对象级规则放大授权）
    ///
    /// 注意：permission_rule_snapshot 行是预编译胜者（每 (resource_key, action) 仅一行），
    /// 行内无 priority，精确优先即 Java 语义；源表行（id != 0，携带 priority）必须走
    /// [`Self::try_match_rules_single_pass`]（对齐 Java `evaluateRules` 同池优先级竞争）。
    async fn try_match_rules_exact_first(
        &self,
        rules: &[PermissionRule],
        resource_key: &str,
        resource_type: &str,
        action: &str,
        ctx: &PolicyContext,
    ) -> Option<Effect> {
        let is_wildcard = is_wildcard_key(resource_key);
        let type_wildcard = format!("{resource_type}:*");

        for exact_only in [true, false] {
            for rule in rules {
                let rule_res = rule.resource.as_str();
                let rule_act = rule.action.as_str();

                if rule_act != "*" && rule_act != action {
                    continue;
                }

                let resource_match = if !is_wildcard && exact_only {
                    rule_res == resource_key
                } else if exact_only {
                    false
                } else if is_wildcard {
                    // 类型级请求只匹配类型级规则
                    rule_res == resource_key || rule_res == resource_type || rule_res == "*"
                } else {
                    // 具体对象规则优先；通配 pass 只匹配类型级/通配规则
                    rule_res == type_wildcard || rule_res == resource_type || rule_res == "*"
                };
                if !resource_match {
                    continue;
                }

                // 条件评估（不满足继续扫描，对齐 try_match_rules 行为）
                if !evaluate_entry_condition_raw(&rule.condition, ctx).await {
                    continue;
                }
                return Some(rule.effect.clone());
            }
        }

        None
    }

    /// 单 pass 优先级匹配（对齐 Java `PermissionCheckService.evaluateRules`）。
    ///
    /// 输入按 `ORDER BY priority DESC, effect DESC` 排序（高 priority 先匹配；
    /// 同 priority 时 DENY 胜出——effect DESC 使 DENY 排在 ALLOW 之前）。
    /// 对象级规则（resource_id 非空，resource 为 `type:id`）与类型级规则
    /// （resource_id 为空，resource 为 `type` / `type:*` / `*`）**同池竞争**，
    /// 第一个 resource+action 匹配且条件满足者即胜出，不存在对象优先于类型的
    /// 两段式（Java 无该语义）。类型级请求不命中对象级规则。
    async fn try_match_rules_single_pass(
        &self,
        rules: &[PermissionRule],
        resource_key: &str,
        resource_type: &str,
        action: &str,
        ctx: &PolicyContext,
    ) -> Option<Effect> {
        let is_wildcard = is_wildcard_key(resource_key);

        for rule in rules {
            let rule_res = rule.resource.as_str();
            let rule_act = rule.action.as_str();

            if rule_act != "*" && rule_act != action {
                continue;
            }

            let resource_match = if is_wildcard {
                rule_res == resource_key || rule_res == resource_type || rule_res == "*"
            } else {
                rule_res == resource_key
                    || rule_res == format!("{resource_type}:*")
                    || rule_res == resource_type
                    || rule_res == "*"
            };
            if !resource_match {
                continue;
            }

            // 条件评估（不满足继续扫描）
            if !evaluate_entry_condition_raw(&rule.condition, ctx).await {
                continue;
            }
            return Some(rule.effect.clone());
        }

        None
    }

    fn build_rule_decision(
        &self,
        effect: &Effect,
        resource_key: &str,
        _action: &str,
        card_id: i64,
        steps: &mut Vec<EvaluationStep>,
    ) -> PolicyDecision {
        match effect {
            Effect::Allow => {
                steps.push(step("PERMISSION_RULE", "ALLOW", resource_key, None));
                allow(
                    "RULE_ALLOW",
                    &format!("rule:{resource_key}:cardId={card_id}"),
                    steps.clone(),
                )
            }
            Effect::Deny => {
                steps.push(step("PERMISSION_RULE", "DENY", resource_key, None));
                deny(
                    "RULE_DENY",
                    &format!("rule:{resource_key}:cardId={card_id}"),
                    steps.clone(),
                )
            }
            Effect::NotMatch => deny("DEFAULT_DENY", "no-match", vec![]),
        }
    }

    // ==================== 模拟评估 ====================

    /// 模拟评估（What-If 场景，不影响计数器）
    pub async fn simulate<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        self.evaluate(ctx, repo).await
    }

    // ==================== 断路器 ====================

    /// 降级路径（断路器打开时调用，fail-closed）
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
