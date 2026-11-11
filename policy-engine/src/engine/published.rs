//! PolicyEngine published-evidence strict gate 与 ALLOW 前复检。
//!
//! The only ordinary card-evidence route. Missing evidence, read failures,
//! non-Ready gates, malformed scope, or ALLOW-time drift always deny/PENDING.

use crate::hit_stats::TimingBreakdown;
use astral_types::registry::{get_alias_sources, parse_resource_key};
use astral_types::{
    AuthorizationAdmission, AuthorizationFenceProof, BindingLayer, CanonicalGrant,
    DomainScopeRequirement, EvaluationStep, GlobalAccessRequirement, GrantEffect, GrantSourceKind,
    GrantState, PolicyContext, PolicyDecision, PolicyError, PublishedCardAuthorization,
    PublishedCardEvidenceScope, ResourceOwnershipScope,
};
use time::OffsetDateTime;

use super::decision::*;
use super::ports::{PublishedEvidenceReadMode, RuleRepository};
use super::PolicyEngine;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

static AUTHORITY_NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_authority_nonce(phase: &str) -> String {
    let sequence = AUTHORITY_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "policy-{phase}-{}-{sequence}-{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    )
}

fn validate_authority_proof_response(
    proof: &AuthorizationFenceProof,
    expected_nonce: &str,
    phase: &str,
) -> Result<(), PolicyError> {
    if proof.request_nonce != expected_nonce {
        return Err(PolicyError::Repository(format!(
            "authorization fence {phase} nonce mismatch"
        )));
    }
    proof.validate().map_err(|error| {
        PolicyError::Repository(format!("authorization fence {phase} is malformed: {error}"))
    })
}

async fn read_fenced_evidence<R: RuleRepository>(
    repo: &R,
    context: &PolicyContext,
    scope: &PublishedCardEvidenceScope,
    phase: &str,
) -> Result<
    Option<(
        Arc<PublishedCardAuthorization>,
        Arc<AuthorizationFenceProof>,
    )>,
    PolicyError,
> {
    let nonce = next_authority_nonce(phase);
    let proof = repo
        .read_request_authorization_fence(context, scope, &nonce)
        .await?;
    validate_authority_proof_response(&proof, &nonce, phase)?;
    let Some(evidence) = repo.load_published_card_authorization(scope).await? else {
        return Ok(None);
    };
    let certified = repo.certify_authorization_evidence(
        proof,
        evidence,
        scope,
        OffsetDateTime::now_utc().unix_timestamp(),
    )?;
    let certified_proof = certified.proof();
    if certified_proof.request_nonce != nonce {
        return Err(PolicyError::Repository(format!(
            "authorization fence {phase} certifier changed request nonce"
        )));
    }
    Ok(Some((certified.evidence(), certified_proof)))
}

#[cfg(test)]
#[path = "matcher_curve.rs"]
mod matcher_curve;

impl PolicyEngine {
    // ==================== 正式已发布证据路径（strict gate） ====================

    /// CURRENT V6 published-evidence formal evaluation.
    ///
    /// The caller has already enforced AUTHN/CARD_CONTEXT and ownership gates;
    /// this method loads published evidence, applies the ALLOW-only matcher, and
    /// performs mandatory evidence and GlobalAdmin rereads before ALLOW.
    ///
    /// Fail-closed 契约：
    /// - 请求缺 tenant scope → AUTHORIZATION_PENDING；
    /// - `Ok(None)` (evidence unavailable), `Err(_)`, non-Ready gates,
    ///   证据畸形（合同校验失败）或证据 tenant/card 与请求不符 →
    ///   AUTHORIZATION_PENDING；
    /// - 无命中的 effective grant → DEFAULT_DENY; no legacy, raw-source, or cache fallback;
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
        admission: &mut Option<AuthorizationAdmission>,
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
            self.finish_evaluation(false, timing, start, false, ctx.resource.as_deref());
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
            self.finish_evaluation(false, timing, start, false, ctx.resource.as_deref());
            return deny(
                "AUTHORIZATION_PENDING",
                "published:invalid-scope",
                steps.clone(),
            );
        }

        let certified_memory = matches!(
            repo.published_evidence_read_mode(),
            PublishedEvidenceReadMode::CertifiedMemory
        );
        let t_evidence = std::time::Instant::now();
        let initial_read = if certified_memory {
            read_fenced_evidence(repo, ctx, &scope, "f0")
                .await
                .map(|result| result.map(|(evidence, proof)| (evidence, Some(proof))))
        } else {
            repo.load_published_card_authorization(&scope)
                .await
                .map(|result| result.map(|evidence| (evidence, None)))
        };
        let initial_evidence_load_ns = t_evidence.elapsed().as_nanos() as u64;
        timing.initial_evidence_load_ns = initial_evidence_load_ns;

        let (evidence, initial_proof) = match initial_read {
            Ok(Some((evidence, proof))) => (evidence, proof),
            Ok(None) => {
                // An explicit unavailable repository result never authorizes.
                steps.push(step(
                    "PUBLISHED_EVIDENCE",
                    "DENY",
                    "published evidence unavailable",
                    None,
                ));
                self.finish_evaluation(false, timing, start, false, ctx.resource.as_deref());
                return deny(
                    "AUTHORIZATION_PENDING",
                    "published:unavailable",
                    steps.clone(),
                );
            }
            Err(e) => {
                let business_pending = published_evidence_error_is_business_pending(&e);
                tracing::warn!(card_id, error = %e, business_pending,
                    certified_memory,
                    "published card evidence read failed");
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
                self.finish_evaluation(
                    false,
                    timing,
                    start,
                    !business_pending,
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
        #[cfg(feature = "performance-attribution")]
        let validation_started = std::time::Instant::now();
        let validation = PublishedCardAuthorization::validate_shared(&evidence);
        #[cfg(feature = "performance-attribution")]
        {
            timing.attribution.initial_validation_ns +=
                validation_started.elapsed().as_nanos() as u64;
        }
        if validation.is_err() {
            steps.push(step(
                "PUBLISHED_EVIDENCE",
                "DENY",
                "published evidence malformed",
                None,
            ));
            self.finish_evaluation(false, timing, start, false, ctx.resource.as_deref());
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
            self.finish_evaluation(false, timing, start, false, ctx.resource.as_deref());
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
            self.finish_evaluation(false, timing, start, false, ctx.resource.as_deref());
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
        let match_start = std::time::Instant::now();
        let matched = match_published_effective_grant(ctx, &evidence, resource_key);
        timing.evidence_match_ns += match_start.elapsed().as_nanos() as u64;
        let Some(matched) = matched else {
            steps.push(step(
                "DEFAULT",
                "DENY",
                &format!("no published grant for {resource_key}:{}", ctx.action),
                None,
            ));
            self.finish_evaluation(false, timing, start, false, ctx.resource.as_deref());
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
        let mut final_proof: Option<Arc<AuthorizationFenceProof>> = None;
        let recheck = if certified_memory {
            read_fenced_evidence(repo, ctx, &scope, "f1")
                .await
                .map(|result| result.map(|(next, proof)| (next, Some(proof))))
        } else {
            repo.load_published_card_authorization(&scope)
                .await
                .map(|result| result.map(|next| (next, None)))
        };
        let final_evidence_reload_ns = t_recheck.elapsed().as_nanos() as u64;
        timing.final_evidence_reload_ns = final_evidence_reload_ns;
        let (recheck_outcome, recheck_had_error) = match recheck {
            Ok(Some((next, next_proof))) => {
                #[cfg(feature = "performance-attribution")]
                let stable = {
                    let validation_started = std::time::Instant::now();
                    let validation = next.validate();
                    timing.attribution.final_recheck_validation_ns +=
                        validation_started.elapsed().as_nanos() as u64;
                    let scan_started = std::time::Instant::now();
                    let stable = validation.is_ok()
                        && next.tenant_id == evidence.tenant_id
                        && next.card_id == evidence.card_id
                        && next.tenant_id == tenant_id
                        && next.card_id == card_id
                        && evidence.gate == next.gate
                        && evidence.manifests == next.manifests
                        && next.effective_grants.iter().any(|grant| grant == matched)
                        && certified_frontier_stable(
                            certified_memory,
                            initial_proof.as_deref(),
                            next_proof.as_deref(),
                        );
                    timing.attribution.final_recheck_scan_ns +=
                        scan_started.elapsed().as_nanos() as u64;
                    stable
                };
                #[cfg(not(feature = "performance-attribution"))]
                let stable = published_recheck_identity_stable(
                    &evidence, &next, tenant_id, card_id, matched,
                ) && certified_frontier_stable(
                    certified_memory,
                    initial_proof.as_deref(),
                    next_proof.as_deref(),
                );
                if stable {
                    final_proof = next_proof;
                    (None, false)
                } else {
                    (Some(false), false)
                }
            }
            Ok(None) => (Some(false), false),
            Err(error) => {
                let business_pending = published_evidence_error_is_business_pending(&error);
                tracing::warn!(
                    card_id,
                    error = %error,
                    business_pending,
                    certified_memory,
                    "published card evidence recheck read failed"
                );
                (Some(!business_pending), !business_pending)
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
        if recheck_outcome.is_some() {
            steps.push(step(
                "PUBLISHED_EVIDENCE",
                "DENY",
                "published evidence changed during evaluation (stale ALLOW rejected)",
                None,
            ));
            self.finish_evaluation(
                false,
                timing,
                start,
                recheck_had_error,
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
                    self.finish_evaluation(false, timing, start, false, ctx.resource.as_deref());
                    return deny(
                        "GLOBAL_ADMIN_REQUIRED",
                        "global_admin:stale-allow",
                        steps.clone(),
                    );
                }
                Err(error) => {
                    tracing::warn!(user_id, error = %error,
                        "global administrator final gate unavailable; denying");
                    steps.push(step(
                        "GLOBAL_ADMIN",
                        "DENY",
                        "global administrator gate unavailable at ALLOW recheck",
                        None,
                    ));
                    self.finish_evaluation(false, timing, start, true, ctx.resource.as_deref());
                    return deny(
                        "AUTHORIZATION_PENDING",
                        "global_admin:recheck_unavailable",
                        steps.clone(),
                    );
                }
            }
        }

        if !repo.positive_authorization_ready() {
            steps.push(step(
                "PUBLISHED_EVIDENCE",
                "DENY",
                "authority fence reconciliation is not serving",
                None,
            ));
            self.finish_evaluation(false, timing, start, true, ctx.resource.as_deref());
            return deny(
                "AUTHORIZATION_PENDING",
                "published:authority-not-serving",
                steps.clone(),
            );
        }
        let verified_admission = if certified_memory {
            let Some(proof) = final_proof else {
                self.finish_evaluation(false, timing, start, true, ctx.resource.as_deref());
                return deny(
                    "AUTHORIZATION_PENDING",
                    "published:f1-proof-missing",
                    steps.clone(),
                );
            };
            match AuthorizationAdmission::from_verified_request_bound_proof((*proof).clone()) {
                Ok(admission_value) => Some(admission_value),
                Err(error) => {
                    tracing::error!(%error, "final certified authority proof could not become admission");
                    self.finish_evaluation(false, timing, start, true, ctx.resource.as_deref());
                    return deny(
                        "AUTHORIZATION_PENDING",
                        "published:f1-proof-invalid",
                        steps.clone(),
                    );
                }
            }
        } else {
            None
        };
        *admission = verified_admission;

        self.finish_evaluation(true, timing, start, false, ctx.resource.as_deref());
        allow(
            "PUBLISHED_EVIDENCE_ALLOW",
            &format!("published:{resource_key}:{}:cardId={card_id}", ctx.action),
            steps.clone(),
        )
    }
}

// ==================== ORG_SCOPE 准入门禁记账 ====================

/// ORG_SCOPE Ready 分支返回决策的断路器归类。
///
/// `org_admission::evaluate` 对引擎只暴露 `PolicyDecision`，引擎无法直接区分
/// repository errors from deterministic denials, so it classifies stable detail codes:
/// - 确定性授权结果（ALLOW、`DEFAULT_DENY`、`CARD_DISABLED`，以及证据畸形 /
///   身份漂移 / provenance 畸形等业务 PENDING）→ 成功（对齐引擎既有约定：
///   业务拒绝与复检状态变化不计依赖故障，正常 `DEFAULT_DENY` 不是依赖失败）；
/// - 读取不可用路径（`org_scope.final_read_unavailable`：ALLOW 前权威复读
///   失败/非 Ready；`org_scope.final_card_context_unavailable`：终局卡片
///   上下文读取失败）→ 失败，累计断路器失败。注意 `org_admission` 把复读
///   `Err` 与管理态翻转并入 `final_read_unavailable`，保守按失败计；
/// - Unknown PENDING details conservatively count as completed outcomes; new
///   deterministic denials must not be misclassified as dependency failures.
pub(crate) fn org_admission_decision_is_dependency_failure(decision: &PolicyDecision) -> bool {
    if decision.reason != "AUTHORIZATION_PENDING" {
        return false;
    }
    matches!(
        decision.evaluation_path.last().map(|s| s.detail.as_str()),
        Some(
            "org_scope.final_read_unavailable"
                | "org_scope.final_card_context_unavailable"
                | "org_scope.final_authority_changed"
        )
    )
}

// ==================== 已发布证据 strict gate 辅助函数 ====================

/// Repository errors that represent a completed business `PENDING` outcome.
pub(crate) fn published_evidence_error_is_business_pending(error: &PolicyError) -> bool {
    matches!(error, PolicyError::Repository(message)
        if message.starts_with("published_card_evidence_not_ready;"))
}

pub(crate) fn record_policy_phase_metrics(timing: &TimingBreakdown) {
    for (phase, nanos) in [
        ("total", timing.total_ns),
        ("card_context_check", timing.card_context_check_ns),
        ("initial_evidence_load", timing.initial_evidence_load_ns),
        ("final_evidence_reload", timing.final_evidence_reload_ns),
        ("evidence_match", timing.evidence_match_ns),
    ] {
        if nanos > 0 {
            metrics::histogram!("astral_authz_policy_phase_duration_seconds", "phase" => phase)
                .record(std::time::Duration::from_nanos(nanos).as_secs_f64());
        }
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
///
/// 匹配器接力的技术 B：按资源类型（`parse_resource_key` 语义的类型段）
/// 预索引 effective_grants。技术 A（线性扫描）小 N 最优（零构建成本），
/// 大 N/尾部命中退化为 O(N) 逐条字符串解析；技术 B 构建 O(N) 一次、每
/// 判定 O(桶大小 + 通配桶)。证据经 Arc 跨判定复用后构建成本摊销。
///
/// The thread-local four-slot cache retains strong evidence Arcs to prevent pointer
/// reuse (ABA). A new Arc is matched linearly once; its index is built only when
/// the same Arc is seen again. The index stores positions and never clones grants.
pub(crate) const MATCHER_INDEX_THRESHOLD: usize = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MatcherPath {
    LinearThreshold,
    FirstSeenLinear,
    IndexBuild,
    IndexHit,
}

impl MatcherPath {
    fn label(self) -> &'static str {
        match self {
            Self::LinearThreshold => "linear_threshold",
            Self::FirstSeenLinear => "first_seen_linear",
            Self::IndexBuild => "index_build",
            Self::IndexHit => "index_hit",
        }
    }
}

fn record_matcher_path(path: MatcherPath) {
    metrics::counter!("astral_authz_matcher_paths_total", "path" => path.label()).increment(1);
}

fn record_matcher_evidence_size(grant_count: usize) {
    metrics::histogram!("astral_authz_matcher_effective_grants").record(grant_count as f64);
}

fn record_matcher_candidate_telemetry(telemetry: MatcherCandidateTelemetry) {
    metrics::counter!(
        "astral_authz_matcher_candidate_routes_total",
        "route" => telemetry.route.label()
    )
    .increment(1);
    metrics::histogram!("astral_authz_matcher_candidate_count")
        .record(telemetry.candidate_count as f64);
}

fn build_matcher_index(evidence: &PublishedCardAuthorization) -> MatcherIndex {
    let mut by_type: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    let mut wildcard = Vec::new();
    for (index, grant) in evidence.effective_grants.iter().enumerate() {
        let (grant_type, _) = parse_resource_key(&grant.resource);
        if grant_type == "*" {
            wildcard.push(index);
        } else {
            by_type
                .entry(grant_type.to_owned())
                .or_default()
                .push(index);
        }
    }
    let by_type = by_type
        .into_iter()
        .map(|(grant_type, positions)| {
            let secondary = (positions.len() > SECONDARY_INDEX_THRESHOLD).then(|| {
                let mut by_resource_id = std::collections::HashMap::new();
                let mut type_level = Vec::new();
                for &position in &positions {
                    let (_, resource_id) =
                        parse_resource_key(&evidence.effective_grants[position].resource);
                    if let Some(resource_id) = resource_id {
                        by_resource_id
                            .entry(resource_id.to_owned())
                            .or_insert_with(Vec::new)
                            .push(position);
                    } else {
                        type_level.push(position);
                    }
                }
                TypeBucketSecondary {
                    by_resource_id,
                    type_level,
                }
            });
            (
                grant_type,
                MatcherTypeBucket {
                    positions,
                    secondary,
                },
            )
        })
        .collect();
    MatcherIndex { by_type, wildcard }
}

pub(crate) const SECONDARY_INDEX_THRESHOLD: usize = 128;

struct MatcherIndex {
    /// 解析后的类型段 → 该类型全部 grant 的下标（含对象级与类型级）。
    by_type: std::collections::HashMap<String, MatcherTypeBucket>,
    /// `*` 全局通配段下标（可命中任何请求类型）。
    wildcard: Vec<usize>,
}

struct MatcherTypeBucket {
    positions: Vec<usize>,
    secondary: Option<TypeBucketSecondary>,
}

struct TypeBucketSecondary {
    by_resource_id: std::collections::HashMap<String, Vec<usize>>,
    type_level: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MatcherCandidateRoute {
    Linear,
    TypeBucket,
    SecondaryExact,
    SecondaryFallback,
}

impl MatcherCandidateRoute {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Linear => "linear",
            Self::TypeBucket => "type_bucket",
            Self::SecondaryExact => "secondary_exact",
            Self::SecondaryFallback => "secondary_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MatcherCandidateTelemetry {
    pub(crate) route: MatcherCandidateRoute,
    pub(crate) candidate_count: usize,
}

impl MatcherCandidateTelemetry {
    fn linear(candidate_count: usize) -> Self {
        Self {
            route: MatcherCandidateRoute::Linear,
            candidate_count,
        }
    }
}

impl MatcherIndex {
    /// 显式缩短借用生命周期：调用方拿到索引借用后立即使用，槽位借用
    /// 随作用域结束（匹配器在返回前只读下标，不持有槽引用）。
    fn borrow_index(&self) -> &Self {
        self
    }

    fn select_candidates(
        &self,
        request_type: &str,
        request_id: Option<&str>,
    ) -> (MatcherCandidates<'_>, MatcherCandidateTelemetry) {
        let Some(bucket) = self.by_type.get(request_type) else {
            let candidates = MatcherCandidates::new([&[], &self.wildcard, &[]]);
            return (
                candidates,
                MatcherCandidateTelemetry {
                    route: MatcherCandidateRoute::TypeBucket,
                    candidate_count: self.wildcard.len(),
                },
            );
        };
        let Some(request_id) = request_id else {
            let candidates =
                MatcherCandidates::new([bucket.positions.as_slice(), &self.wildcard, &[]]);
            return (
                candidates,
                MatcherCandidateTelemetry {
                    route: MatcherCandidateRoute::TypeBucket,
                    candidate_count: bucket.positions.len() + self.wildcard.len(),
                },
            );
        };
        let Some(secondary) = bucket.secondary.as_ref() else {
            let candidates =
                MatcherCandidates::new([bucket.positions.as_slice(), &self.wildcard, &[]]);
            return (
                candidates,
                MatcherCandidateTelemetry {
                    route: MatcherCandidateRoute::TypeBucket,
                    candidate_count: bucket.positions.len() + self.wildcard.len(),
                },
            );
        };
        let exact = secondary
            .by_resource_id
            .get(request_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let route = if exact.is_empty() {
            MatcherCandidateRoute::SecondaryFallback
        } else {
            MatcherCandidateRoute::SecondaryExact
        };
        let candidates = MatcherCandidates::new([exact, &secondary.type_level, &self.wildcard]);
        (
            candidates,
            MatcherCandidateTelemetry {
                route,
                candidate_count: exact.len() + secondary.type_level.len() + self.wildcard.len(),
            },
        )
    }
}

struct MatcherCandidates<'a> {
    buckets: [&'a [usize]; 3],
    offsets: [usize; 3],
}

impl<'a> MatcherCandidates<'a> {
    fn new(buckets: [&'a [usize]; 3]) -> Self {
        Self {
            buckets,
            offsets: [0; 3],
        }
    }
}

impl Iterator for MatcherCandidates<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let mut selected: Option<usize> = None;
        for bucket in 0..self.buckets.len() {
            if self.buckets[bucket]
                .get(self.offsets[bucket])
                .is_some_and(|candidate| {
                    selected
                        .and_then(|selected| {
                            self.buckets[selected].get(self.offsets[selected]).copied()
                        })
                        .is_none_or(|current| *candidate < current)
                })
            {
                selected = Some(bucket);
            }
        }
        let bucket = selected?;
        let position = self.buckets[bucket][self.offsets[bucket]];
        self.offsets[bucket] += 1;
        Some(position)
    }
}

thread_local! {
    /// Each thread retains four strong evidence Arcs to prevent pointer reuse (ABA).
    static MATCHER_INDEX_CACHE: std::cell::RefCell<MatcherCacheState> =
        const { std::cell::RefCell::new(MatcherCacheState::new()) };
}

const MATCHER_CACHE_SLOTS: usize = 4;

struct MatcherCacheState {
    slots: [Option<MatcherCacheSlot>; MATCHER_CACHE_SLOTS],
    next_victim: usize,
}

struct MatcherCacheSlot {
    evidence: std::sync::Arc<PublishedCardAuthorization>,
    index: Option<MatcherIndex>,
}

impl MatcherCacheState {
    const fn new() -> Self {
        Self {
            slots: [None, None, None, None],
            next_victim: 0,
        }
    }

    fn lookup_or_build(
        &mut self,
        evidence: &std::sync::Arc<PublishedCardAuthorization>,
    ) -> (Option<&MatcherIndex>, MatcherPath) {
        let position = self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|slot| std::sync::Arc::ptr_eq(&slot.evidence, evidence))
        });
        let (position, first_seen) = match position {
            Some(position) => (position, false),
            None => {
                let position = self.next_victim;
                self.slots[position] = Some(MatcherCacheSlot {
                    evidence: std::sync::Arc::clone(evidence),
                    index: None,
                });
                self.next_victim = (position + 1) % MATCHER_CACHE_SLOTS;
                (position, true)
            }
        };

        if first_seen {
            return (None, MatcherPath::FirstSeenLinear);
        }
        let slot = self.slots[position]
            .as_mut()
            .expect("matcher slot has just been selected");
        if slot.index.is_none() {
            slot.index = Some(build_matcher_index(evidence));
            return (
                slot.index.as_ref().map(MatcherIndex::borrow_index),
                MatcherPath::IndexBuild,
            );
        }
        (
            slot.index.as_ref().map(MatcherIndex::borrow_index),
            MatcherPath::IndexHit,
        )
    }
}

// The indexed path combines the request-type bucket and global wildcard bucket.
// Both buckets are kept in evidence order and merged without allocation, so
// first-match semantics are preserved at O(bucket + wildcard).
fn find_linear_published_grant<'a>(
    ctx: &PolicyContext,
    evidence: &'a PublishedCardAuthorization,
    request_type: &str,
    request_id: Option<&str>,
) -> Option<&'a CanonicalGrant> {
    let type_level_request = request_id.is_none();
    evidence.effective_grants.iter().find(|grant| {
        grant_matches_request(
            ctx,
            request_type,
            request_id,
            type_level_request,
            evidence.read_unix_seconds,
            grant,
        )
    })
}

/// 资源段之外的完整匹配谓词（身份/租户/domain/有效期/状态效果/资源/动作）。
/// 线性与索引两条路径共用同一谓词——语义等价由结构保证而非逐行对照。
#[allow(clippy::too_many_arguments)]
fn grant_matches_request(
    ctx: &PolicyContext,
    request_type: &str,
    request_id: Option<&str>,
    type_level_request: bool,
    now: i64,
    grant: &CanonicalGrant,
) -> bool {
    let card_id = ctx.card_id.unwrap_or(0);
    let request_tenant = ctx.tenant_id.unwrap_or(0);
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
}

#[cfg(test)]
fn match_indexed_with_state<'a>(
    ctx: &PolicyContext,
    evidence: &'a std::sync::Arc<PublishedCardAuthorization>,
    request_type: &str,
    request_id: Option<&str>,
    state: &mut MatcherCacheState,
) -> (Option<&'a CanonicalGrant>, MatcherPath) {
    let (matched, path, _) =
        match_indexed_with_state_detailed(ctx, evidence, request_type, request_id, state);
    (matched, path)
}

fn match_indexed_with_state_detailed<'a>(
    ctx: &PolicyContext,
    evidence: &'a std::sync::Arc<PublishedCardAuthorization>,
    request_type: &str,
    request_id: Option<&str>,
    state: &mut MatcherCacheState,
) -> (
    Option<&'a CanonicalGrant>,
    MatcherPath,
    MatcherCandidateTelemetry,
) {
    let (index, path) = state.lookup_or_build(evidence);
    let Some(index) = index else {
        return (
            find_linear_published_grant(ctx, evidence, request_type, request_id),
            path,
            MatcherCandidateTelemetry::linear(evidence.effective_grants.len()),
        );
    };
    let (candidates, telemetry) = index.select_candidates(request_type, request_id);
    for position in candidates {
        let grant = &evidence.effective_grants[position];
        if grant_matches_request(
            ctx,
            request_type,
            request_id,
            request_id.is_none(),
            evidence.read_unix_seconds,
            grant,
        ) {
            return (Some(grant), path, telemetry);
        }
    }
    (None, path, telemetry)
}

pub(crate) fn match_published_effective_grant<'a>(
    ctx: &PolicyContext,
    evidence: &'a std::sync::Arc<PublishedCardAuthorization>,
    resource_key: &str,
) -> Option<&'a CanonicalGrant> {
    match_published_effective_grant_with_path(ctx, evidence, resource_key).0
}

fn match_published_effective_grant_with_path<'a>(
    ctx: &PolicyContext,
    evidence: &'a std::sync::Arc<PublishedCardAuthorization>,
    resource_key: &str,
) -> (Option<&'a CanonicalGrant>, MatcherPath) {
    let matched = match_published_effective_grant_with_telemetry(ctx, evidence, resource_key);
    record_matcher_candidate_telemetry(matched.telemetry);
    matched.map_path()
}

fn match_published_effective_grant_with_telemetry<'a>(
    ctx: &PolicyContext,
    evidence: &'a std::sync::Arc<PublishedCardAuthorization>,
    resource_key: &str,
) -> MatcherMatch<'a> {
    let (request_type, request_id) = parse_resource_key(resource_key);
    record_matcher_evidence_size(evidence.effective_grants.len());

    // 接力：小 N 线性扫描（技术 A，零构建成本）；大 N 走类型索引（技术
    // B，构建 O(N) 一次、跨判定摊销。大桶在有具体对象 ID 时再走二级
    // resource-ID 索引，仍通过完整谓词确认，无法安全窄化时回到类型桶。
    if evidence.effective_grants.len() <= MATCHER_INDEX_THRESHOLD {
        record_matcher_path(MatcherPath::LinearThreshold);
        return MatcherMatch {
            matched: find_linear_published_grant(ctx, evidence, request_type, request_id),
            path: MatcherPath::LinearThreshold,
            telemetry: MatcherCandidateTelemetry::linear(evidence.effective_grants.len()),
        };
    }
    MATCHER_INDEX_CACHE.with(|cache| {
        let mut state = cache.borrow_mut();
        let (matched, path, telemetry) =
            match_indexed_with_state_detailed(ctx, evidence, request_type, request_id, &mut state);
        record_matcher_path(path);
        MatcherMatch {
            matched,
            path,
            telemetry,
        }
    })
}

struct MatcherMatch<'a> {
    matched: Option<&'a CanonicalGrant>,
    path: MatcherPath,
    telemetry: MatcherCandidateTelemetry,
}

impl<'a> MatcherMatch<'a> {
    fn map_path(self) -> (Option<&'a CanonicalGrant>, MatcherPath) {
        (self.matched, self.path)
    }
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

fn certified_frontier_stable(
    certified_memory: bool,
    initial: Option<&AuthorizationFenceProof>,
    final_proof: Option<&AuthorizationFenceProof>,
) -> bool {
    if !certified_memory {
        return true;
    }
    let (Some(initial), Some(final_proof)) = (initial, final_proof) else {
        return false;
    };
    if initial.request_nonce == final_proof.request_nonce
        || initial.proof_id == final_proof.proof_id
    {
        return false;
    }
    initial.same_frontier_as(final_proof).is_ok()
}

/// gate 计数、manifest 摘要与被命中 grant 必须与评估起点完全一致。
/// `read_unix_seconds` 是逐次变化的读取时钟，不参与身份比较；但新证据必须
/// 先通过合同校验，且被命中 grant 必须仍在新证据的 effective 集合中
/// （含有效期在新读取时钟下仍然有效）。
#[cfg(any(not(feature = "performance-attribution"), test))]
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
