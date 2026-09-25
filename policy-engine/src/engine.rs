//! PolicyEngine 评估引擎
//!
//! 三层评估主入口，对齐 Java MergeSemantics.evaluateFormal 正式规范：
//! L1: RuleSet（OVERLAY > BASE，每层内 DENY-OVERRIDES）
//! L2: PermissionRule 回退
//! L3: DEFAULT_DENY（fail-closed）
//!
//! 评估链（对齐 Java PolicyEngine.evaluate()）：
//! AUTHN → CARD_CONTEXT → RULESET(OVERLAY>BASE) → PERMISSION_RULE → DEFAULT_DENY

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use astral_types::registry::{
    build_resource_key, get_alias_sources, is_wildcard_key, parse_resource_key,
};
use astral_types::{
    BindingLayer, CanonicalGrant, DomainScopeRequirement, Effect, EvaluationStep,
    GlobalAccessRequirement, GrantEffect, GrantSourceKind, GrantState, PolicyContext,
    PolicyDecision, PolicyError, PublishedCardAuthorization, PublishedCardEvidenceScope,
    ResourceOwnershipScope,
};

use crate::circuit_breaker::{AutoCircuitBreaker, CircuitBreakerState};
use crate::condition::evaluator_for;
use crate::consistency::get_consistency_checker;
use crate::hit_stats::{HitStats, TimingBreakdown};

/// 规则集快照（由 astral-db 加载，引擎层仅定义接口）
///
/// 引擎通过 `RuleRepository` trait 获取数据，不直接访问数据库。
#[async_trait::async_trait]
pub trait RuleRepository: Send + Sync {
    /// 加载卡片关联的规则集快照（含 OVERLAY + BASE）
    ///
    /// 【读链切换批次 3 退役】引擎自身不再消费本读取器：正式 `evaluate()` 的 L1
    /// 使用 [`RuleRepository::load_snapshot_winners`]，`evaluate_realtime` 的 L1
    /// 使用 [`RuleRepository::load_rule_set_entries_raw`]；strict published
    /// evidence 路径则完全不触碰 L1/L2/L2.5 读取器。生产实现（astral-db
    /// `SqlxRuleRepository`）的旧 MAX(version_no) 快照读取器及其 `perm:refs`
    /// cache-aside 已随旧读链下线。trait 默认实现保留为显式空集（fail-closed），
    /// 仅为兼容既有测试仓库的必选成员；空集把旧读链调用方引向 L2/L3，不产生
    /// 任何授权放行。
    async fn load_rule_set_snapshots(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        Ok(vec![])
    }

    /// 回退路径：加载 permission_rule
    async fn load_permission_rules(&self, card_id: i64)
        -> Result<Vec<PermissionRule>, PolicyError>;

    /// 【读链切换批次 3.5 退役】RuleSet 依赖门禁读取器。
    ///
    /// 引擎（`evaluate`/`evaluate_realtime`/strict published evidence）已不再
    /// 消费本端口：realtime 的 L1 走 [`RuleRepository::load_rule_set_entries_raw`]，
    /// 正式授权走 published evidence。默认实现保留为显式 `Ok(None)`，仅为兼容
    /// `astral-cache` 装饰器转发与既有测试仓库；空结果绝不产生任何授权放行。
    async fn load_rule_set_dependency_statuses(
        &self,
        _card_id: i64,
    ) -> Result<Option<Vec<RuleSetDependencyStatus>>, PolicyError> {
        Ok(None)
    }

    /// 检查卡片上下文是否有效（默认实现仅服务于无物理请求身份的纯策略测试）。
    /// 真实 `PLATFORM_USER` 请求必须由具体 repository 执行双卡权威校验。
    async fn check_card_active(&self, ctx: &PolicyContext) -> Result<bool, PolicyError> {
        if ctx.principal_kind.as_deref() == Some("PLATFORM_USER") {
            return Ok(ctx.identity_card_id.is_some() && ctx.card_id.is_some());
        }
        Ok(true)
    }

    /// Fresh server-side GlobalAdmin proof for a resolver-classified platform
    /// control-plane request. The default is deny-only so a test/legacy
    /// repository cannot accidentally turn ordinary rule evidence into global
    /// authority. Production implementations must query the authoritative
    /// `identity_global_admin` source rather than a client role or stale cache.
    async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
        Ok(false)
    }

    /// 加载预计算快照胜者条目（O(1) lookup 路径）
    /// 返回每个 (resource_key, action_code) 的预计算胜者效应
    async fn load_snapshot_winners(
        &self,
        _card_id: i64,
    ) -> Result<Vec<SnapshotWinner>, PolicyError> {
        // 默认实现：返回空，回退到 load_rule_set_snapshots
        Ok(vec![])
    }

    /// 一致性检查专用：加载原始 rule_set_entry（跳过快照表）
    async fn load_rule_set_entries_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        // 默认实现：返回空（一致性检查跳过 L1）
        Ok(vec![])
    }

    /// 一致性检查专用：加载原始 permission_rule（跳过快照表和 permission_rule_snapshot）
    async fn load_permission_rules_raw(
        &self,
        _card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        // 默认实现：返回空（一致性检查跳过 L2）
        Ok(vec![])
    }

    /// Raw/realtime delegation reader retained for consistency paths only.
    /// Formal evaluation must override `load_projected_delegated_rules` instead.
    async fn load_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        // Legacy/raw delegation reads are disabled for formal evaluation.
        // Production repositories must override load_projected_delegated_rules.
        Ok(vec![])
    }

    /// Load delegation winners from the durable, generation-gated projection.
    /// The default is an explicit empty result for lightweight test repositories;
    /// production repositories must override this method.
    async fn load_projected_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        Ok(vec![])
    }

    /// 投影门禁（对齐 Java `AuthorizationReadPort.getCardProjectionStatus`）
    ///
    /// 生产 repository 应返回显式的投影状态；未接入 durable gate 的 test/default
    /// repository 才允许返回 `Ok(None)`，且其余调用方必须将 `ready=false` 视为拒绝。
    /// `Ok(Some(gate))` 时必须 `ready`（READY 且 source==projected）才允许继续评估，
    /// 且 ALLOW 返回前需与评估起点复检（防止投影在规则读取期间推进产生旧 ALLOW）。
    /// 读取失败视为投影状态不可用 → 评估侧 fail-closed 返回 AUTHORIZATION_PENDING。
    async fn get_projection_gate(
        &self,
        _card_id: i64,
    ) -> Result<Option<ProjectionGate>, PolicyError> {
        // 默认实现仅供 test/default repository；生产实现必须返回显式 ready=false。
        Ok(None)
    }

    /// Capability marker：生产 repository 是否要求正式授权必须走本 trait 的
    /// published evidence strict gate。
    ///
    /// 默认 `false` 只服务 legacy/test repository（继续走既有 snapshot 路径，
    /// 行为不变）。生产实现（astral-db `SqlxRuleRepository`）必须返回 `true`：
    /// `evaluate()` 随后在 AUTHN/CARD_CONTEXT 之后读取
    /// [`RuleRepository::load_published_card_authorization`]，并且该请求
    /// 不再触碰 L1/L2/L2.5 读取器或任何 raw/source/cache 回退。
    fn requires_published_card_evidence(&self) -> bool {
        false
    }

    /// Published evidence read port：Rust-owned published card authorization
    /// evidence（严格 reader，migration 20260825000002/20260827000001 链路）。
    ///
    /// # 状态边界（重要）
    ///
    /// - **正式 strict gate 入口**：当 repository 声明
    ///   [`RuleRepository::requires_published_card_evidence`] == true 时，
    ///   `evaluate()` 在 AUTHN/CARD_CONTEXT 之后读取本端口，并以统一
    ///   ALLOW-only 匹配器消费 `effective_grants`；该请求不再触碰
    ///   L1/L2/L2.5 读取器或任何 raw/source/cache 回退。
    ///   `evaluate_realtime` 仍仅作一致性/oracle 路径，不消费本端口。
    /// - 成功形态是整体三态 gate 中唯一可授权的 `Ready` 证据：
    ///   [`astral_types::PublishedCardAuthorization`] 携带 per-aggregate
    ///   manifest/current 摘要与完整 verified grant records（含被安全排除项），
    ///   且 DB 侧保证"缺 current 指针 ⇒ NotReady"，不存在 empty-ALLOW 形态。
    /// - `Ok(None)` 是 legacy/test 默认实现的显式 unavailable 标记，
    ///   **不是授权证据**；strict gate 下同样 fail-closed（AUTHORIZATION_PENDING）。
    /// - `Err(_)` 表示 pending/corrupt/query 失败（稳定 code 内嵌于消息），
    ///   一律按 PENDING/DENY 处理，禁止回退旧快照/raw source/cache。
    /// 生产 repository（如 astral-db 的 SqlxRuleRepository）必须 override 本方法；
    /// 任何把 default 结果当作可用证据的调用都是契约违规。
    ///
    /// 真实 MySQL integration 仍属后续门禁；当前以 typed 测试覆盖 strict gate。
    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
        // Legacy/test 默认实现：显式 unavailable。绝不返回伪 Ready 证据，
        // 也绝不产生任何可用于放行的结果。
        Ok(None)
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<crate::org_admission::OrgAuthorityRead, PolicyError> {
        Ok(crate::org_admission::OrgAuthorityRead::Unmanaged)
    }
}

/// Shadow-read 结果的统一分类器（[`RuleRepository::load_published_card_authorization`]）。
///
/// 这是"缺失/未知/不可用绝不等于 empty ALLOW"的唯一判据入口：只有
/// `Ok(Some(evidence))` 且整体 gate 处于可授权状态才返回 `true`。
/// - `Ok(None)`（legacy/test unavailable 标记）→ `false`；
/// - `Err(_)`（pending/corrupt/query 失败）→ `false`；
/// - 非 Ready gate → `false`。
///
/// strict gate 与 shadow/read 路径共用同一判据：只有 Ready 证据可参与授权。
pub fn published_card_shadow_evidence_is_usable(
    outcome: &Result<Option<PublishedCardAuthorization>, PolicyError>,
) -> bool {
    match outcome {
        Ok(Some(evidence)) => evidence.gate.status.is_authorization_usable(),
        Ok(None) | Err(_) => false,
    }
}

/// 投影门禁快照（对齐 Java `AuthorizationReadPort.ProjectionStatusView`）
///
/// 旧链状态列（projected_generation/projection_status）已随迁移
/// 20260831000001 退役：`ready` 语义收敛为"head 存在且 source_generation > 0"
/// （投影通道已建立），CARD 正式授权的权威读取是 strict published evidence
/// gate；本快照保留 (source_generation, revoke_fence) 作为 ALLOW 复检与
/// realtime 一致性巡检的版本栅栏。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionGate {
    /// head 存在且 source_generation > 0（投影通道已建立）
    pub ready: bool,
    pub source_generation: i64,
    pub revoke_fence: i64,
}

/// A dependency is readable only when its RuleSet head is READY and
/// synchronized, and every row in the current RuleSet snapshot carries the
/// same projection generation as that head. An empty current snapshot is
/// readable only when the query has supplied the projected generation as an
/// explicit empty-projection signal. Missing heads, unproven missing
/// snapshots, stale rows, and query failures are therefore authorization-
/// pending states.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleSetDependencyStatus {
    pub rule_set_id: i64,
    pub ref_type: String,
    pub rule_set_active: bool,
    pub head_ready: bool,
    pub source_generation: i64,
    pub projected_generation: i64,
    pub revoke_fence: i64,
    pub snapshot_generation: Option<i64>,
    pub snapshot_row_count: i64,
    pub stale_snapshot_rows: i64,
}

impl RuleSetDependencyStatus {
    /// Returns whether the current RuleSet snapshot has a generation proof.
    ///
    /// The query uses `Some(projected_generation)` for both non-empty rows and
    /// a worker-committed empty projection. `None` therefore means that the
    /// snapshot result is unproven, including when the RuleSet is active,
    /// disabled, or deleted.
    pub fn snapshot_is_proven(&self) -> bool {
        self.snapshot_generation == Some(self.projected_generation)
    }

    /// Returns whether this dependency is safe for formal authorization.
    pub fn is_ready(&self) -> bool {
        self.head_ready
            && self.source_generation > 0
            && self.source_generation == self.projected_generation
            && self.stale_snapshot_rows == 0
            && self.snapshot_is_proven()
    }
}

/// ALLOW 返回前投影复检结果（三态）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectionCheck {
    /// 投影稳定，ALLOW 可返回
    Valid,
    /// 投影推进/未 READY/head 新出现 → 旧 ALLOW 转 AUTHORIZATION_PENDING
    Stale,
    /// gate 读取失败 → fail-closed 且计入断路器失败
    Error,
}

/// 预计算快照胜者条目（快速路径）
#[derive(Debug, Clone)]
pub struct SnapshotWinner {
    pub ref_type: String, // "OVERLAY" | "BASE"
    pub rule_set_id: i64,
    pub resource_key: String,
    pub action_code: String,
    pub final_effect: String, // "ALLOW" | "DENY"
}

/// 规则集快照（由 astral-db 加载，引擎层仅定义接口）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetSnapshot {
    pub rule_set_id: i64,
    pub ref_type: String, // "OVERLAY" | "BASE"
    pub entries: Vec<RuleSetEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetEntry {
    pub effect: Effect,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub condition: Option<serde_json::Value>,
}

/// 权限规则（L2 回退路径）
#[derive(Debug, Clone)]
pub struct PermissionRule {
    pub id: i64,
    pub effect: Effect,
    pub resource: String,
    pub action: String,
    pub condition: Option<serde_json::Value>,
}

/// PolicyEngine（线程安全，ArcSwap 实现运行时配置热更新）
pub struct PolicyEngine {
    stats: ArcSwap<HitStats>,
    /// per-resource 断路器（对齐 Java Resilience4j per-endpoint 隔离），
    /// key = resource_type 字符串，"__global__" 为默认兜底
    circuit_breakers: std::sync::RwLock<HashMap<String, AutoCircuitBreaker>>,
}

impl PolicyEngine {
    /// 创建 PolicyEngine 实例
    pub fn new() -> Self {
        let mut breakers = HashMap::new();
        breakers.insert("__global__".to_string(), AutoCircuitBreaker::new());
        Self {
            stats: ArcSwap::new(Arc::new(HitStats::default())),
            circuit_breakers: std::sync::RwLock::new(breakers),
        }
    }

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
        if !strict_published_evidence && decision.org_provenance.is_none() {
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
    async fn evaluate_published_card_evidence<R: RuleRepository>(
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

    /// ALLOW 返回前投影复检（对齐 Java：规则读取期间投影推进或 revoke-fence 变化
    /// → 旧 ALLOW 转 AUTHORIZATION_PENDING，且不增加 L1/L2 命中统计）。
    ///
    /// 若 repository 未提供 durable gate，复检时仍返回 `None` 才视为稳定；生产 SQLx
    /// repository 会将缺失 head 表达为 `ready=false`，因此不会走该默认兼容语义。
    /// head 新出现、版本变化、未 READY 或读取失败都保守拒绝。
    ///
    /// 返回三态：`Valid`（投影稳定）/ `Stale`（版本推进，旧 ALLOW 拒绝）/
    /// `Error`（gate 读取失败，fail-closed 且应计入断路器失败）。
    async fn projection_still_valid<R: RuleRepository>(
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

    ///
    /// 自动从 Open → HalfOpen 超时恢复（30 秒），
    /// 从 HalfOpen → Closed（成功探测时由 record_success_on_evaluate 触发）。
    fn check_circuit_breaker(&self, ctx: &PolicyContext) -> Option<PolicyDecision> {
        let resource = ctx.resource.as_deref();
        let key = resource.filter(|r| !r.is_empty()).unwrap_or("__global__");
        // 惰性创建 per-resource 断路器
        {
            let mut map = self
                .circuit_breakers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            map.entry(key.to_string()).or_default();
        }
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let resource_open = guard
            .get(key)
            .map(AutoCircuitBreaker::is_open)
            .unwrap_or(false);
        let global_open = key != "__global__"
            && guard
                .get("__global__")
                .map(AutoCircuitBreaker::is_open)
                .unwrap_or(false);
        if resource_open || global_open {
            Some(self.evaluate_fallback(ctx))
        } else {
            None
        }
    }

    /// 记录一次成功的评估（重置断路器失败计数器 / 关闭 HalfOpen 状态）
    fn record_success_on_evaluate(&self, resource: Option<&str>) {
        let key = resource.unwrap_or("__global__");
        // 惰性创建 per-resource 断路器
        {
            let mut map = self
                .circuit_breakers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            map.entry(key.to_string()).or_default();
        }
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(breaker) = guard.get(key) {
            breaker.record_success();
        }
        // Also reset global breaker
        if key != "__global__" {
            if let Some(breaker) = guard.get("__global__") {
                breaker.record_success();
            }
        }
    }

    /// 记录一次失败的评估（递增失败计数器，达到阈值自动打开断路器）
    fn record_failure_on_evaluate(&self, resource: Option<&str>) {
        let key = resource.unwrap_or("__global__");
        // 惰性创建 per-resource 断路器
        {
            let mut map = self
                .circuit_breakers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            map.entry(key.to_string()).or_default();
        }
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(breaker) = guard.get(key) {
            breaker.record_failure();
        }
        // Also increment global breaker
        if key != "__global__" {
            if let Some(breaker) = guard.get("__global__") {
                breaker.record_failure();
            }
        }
    }

    /// 返回全局断路器状态（兼容旧 API）
    pub fn circuit_breaker_state(&self) -> CircuitBreakerState {
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .get("__global__")
            .map(|b| b.state())
            .unwrap_or(CircuitBreakerState::Closed)
    }

    /// 强制打开所有断路器（仅测试用途）
    pub fn force_open_circuit_breaker(&self) {
        let guard = self
            .circuit_breakers
            .read()
            .unwrap_or_else(|e| e.into_inner());
        for breaker in guard.values() {
            for _ in 0..crate::circuit_breaker::CB_THRESHOLD {
                breaker.record_failure();
            }
        }
    }

    // ==================== 统计 ====================

    /// 累加单次评估的命中计数与时序数据到全局统计（对齐 Java PolicyEngine 的 AtomicLong 计数器 + 时序字段）
    ///
    /// `layer` 表示本次评估命中的层次："L1" / "L2" / "L3"，或 ORG_SCOPE 准入
    /// 决策的稳定类别 "ORG_AUTHORITY"（见 [`ORG_AUTHORITY_EVAL_LAYER`]，不冒领
    /// legacy 层命中；`HitStats` 公共 schema 无专属 ORG 桶，保守计入 l3_hits）。
    fn record_evaluation(&self, layer: &str, timing: &TimingBreakdown) {
        let mut stats = HitStats::clone(self.stats.load().as_ref());
        match layer {
            "L1" => stats.l1_hits += 1,
            "L2" => stats.l2_hits += 1,
            // ORG_SCOPE 准入决策：稳定类别 ORG_AUTHORITY；公共 schema 无专属
            // ORG 桶 → 保守映射进终局 fail-closed 层 l3_hits（同未知 layer 兜底）。
            "ORG_AUTHORITY" => stats.l3_hits += 1,
            _ => stats.l3_hits += 1,
        }
        stats.timing_ns.card_active_check_ns += timing.card_active_check_ns;
        stats.timing_ns.refs_load_ns += timing.refs_load_ns;
        stats.timing_ns.initial_evidence_load_ns += timing.initial_evidence_load_ns;
        stats.timing_ns.final_evidence_reload_ns += timing.final_evidence_reload_ns;
        stats.timing_ns.overlay_eval_ns += timing.overlay_eval_ns;
        stats.timing_ns.base_eval_ns += timing.base_eval_ns;
        stats.timing_ns.perm_rule_eval_ns += timing.perm_rule_eval_ns;
        stats.timing_ns.total_ns += timing.total_ns;
        self.stats.store(Arc::new(stats));
    }

    /// 获取当前统计数据的快照（对齐 Java `getCacheHitStats()` + `getBreakdownStats()`）
    pub fn get_stats(&self) -> HitStats {
        HitStats::clone(self.stats.load().as_ref())
    }

    /// 重置所有统计数据（对齐 Java `resetCacheHitStats()` + `resetBreakdownStats()`）
    pub fn reset_stats(&self) {
        self.stats.store(Arc::new(HitStats::default()));
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
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
const ORG_AUTHORITY_EVAL_LAYER: &str = "ORG_AUTHORITY";

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
fn org_admission_decision_is_dependency_failure(decision: &PolicyDecision) -> bool {
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
fn published_evidence_error_is_business_pending(error: &PolicyError) -> bool {
    matches!(error, PolicyError::Repository(message)
        if message.starts_with("published_card_evidence_not_ready;"))
}

fn record_policy_phase_metrics(timing: &TimingBreakdown) {
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

fn finish_published_evaluation(
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
fn match_published_effective_grant<'a>(
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
fn published_source_label(grant: &CanonicalGrant) -> &'static str {
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
fn published_recheck_identity_stable(
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

// ==================== 工具函数 ====================

/// 创建 EvaluationStep
fn step(phase: &str, result: &str, detail: &str, source: Option<String>) -> EvaluationStep {
    let result_effect = match result {
        "ALLOW" => Effect::Allow,
        "DENY" => Effect::Deny,
        _ => Effect::NotMatch,
    };
    EvaluationStep {
        phase: phase.to_string(),
        result: result_effect,
        detail: detail.to_string(),
        matched_rule_id: None,
        source,
    }
}

/// 创建 ALLOW 决策
fn allow(reason: &str, matched_rule: &str, path: Vec<EvaluationStep>) -> PolicyDecision {
    PolicyDecision {
        allowed: true,
        reason: reason.to_string(),
        matched_rule: Some(matched_rule.to_string()),
        audit_required: false,
        evaluation_path: path,
        matched_rule_id: None,
        condition_results: None,
        snapshot_version: None,
        org_provenance: None,
    }
}

/// 创建 DENY 决策
fn deny(reason: &str, matched_rule: &str, path: Vec<EvaluationStep>) -> PolicyDecision {
    PolicyDecision {
        allowed: false,
        reason: reason.to_string(),
        matched_rule: Some(matched_rule.to_string()),
        audit_required: true,
        evaluation_path: path,
        matched_rule_id: None,
        condition_results: None,
        snapshot_version: None,
        org_provenance: None,
    }
}

/// 按快照 effect 字符串创建决策（"ALLOW" → 放行，其余 → DENY）
fn decision_from_effect(
    effect: &str,
    matched_rule: &str,
    path: Vec<EvaluationStep>,
) -> PolicyDecision {
    if effect == "ALLOW" {
        allow("RULE_SET_ALLOW", matched_rule, path)
    } else {
        deny("RULE_SET_DENY", matched_rule, path)
    }
}

/// 运行时条件类型名称集合
///
/// 对应 Java `ConditionRegistry.REGISTRY` 中注册的所有条件类型。
/// 在 L1 规则集评估中，带运行时条件的条目被排除（对齐 Java rebuildSnapshot 行为）。
const RUNTIME_CONDITION_TYPES: &[&str] = &[
    "TimeRangeCondition",
    "timeRange",
    "IpRangeCondition",
    "ipRange",
    "RateLimitCondition",
    "rateLimit",
    "DeviceTypeCondition",
    "deviceType",
    "ResourcePropertyCondition",
    "resourceProperty",
    "OwnerOnlyCondition",
    "ownerOnly",
    "BelongsToTenantCondition",
    "belongsToTenant",
    "ScopeCondition",
    "scope",
];

/// 检查 JSON 条件是否包含运行时条件（对齐 Java `RuleSetService.hasRuntimeCondition()`）
///
/// 同时识别 Rust 内部格式（`conditionType`+`params`）与 Java 顶层键格式
/// （`timeRange`/`ownerOnly`/`conditionGroup`），保证 Java 写入的条件规则在 L1
/// 快照编译时同样被正确排除。
fn has_runtime_condition(condition: &Option<serde_json::Value>) -> bool {
    let Some(condition_json) = condition else {
        return false;
    };

    // 唯一的解析入口：严格拒绝未知键、混合格式和不支持的嵌套组。
    let Some(group) = crate::condition::normalize_condition_json(condition_json) else {
        return true;
    };
    condition_group_has_runtime(&group)
}

/// 判断归一化后的条件组是否包含运行时条件
fn condition_group_has_runtime(group: &crate::condition::ConditionGroup) -> bool {
    match group {
        crate::condition::ConditionGroup::AllOf(conds)
        | crate::condition::ConditionGroup::AnyOf(conds) => conds
            .iter()
            .any(|c| RUNTIME_CONDITION_TYPES.contains(&c.condition_type.as_str())),
        crate::condition::ConditionGroup::Not(cond) => {
            RUNTIME_CONDITION_TYPES.contains(&cond.condition_type.as_str())
        }
    }
}

/// 评估原始条件 JSON（异步）
///
/// 先尝试 Rust 内部格式（`conditionType`+`params`），再尝试 Java 顶层键格式
/// （`timeRange`/`ownerOnly`/`conditionGroup` 等）归一化，保证共享库中 Java 写入的
/// 条件规则在 Rust 侧同样求值（此前解析失败恒 DENY，行为对齐性断裂）。
async fn evaluate_entry_condition_raw(
    condition: &Option<serde_json::Value>,
    ctx: &PolicyContext,
) -> bool {
    let condition_json = match condition {
        None => return true,
        Some(v) => v,
    };

    let Some(group) = crate::condition::normalize_condition_json(condition_json) else {
        tracing::warn!(
            "Failed to parse condition JSON (strict normalization): {}",
            condition_json
        );
        return false;
    };
    evaluate_condition_group(&group, ctx).await
}

/// 评估条件组（AllOf / AnyOf / Not）
async fn evaluate_condition_group(
    group: &crate::condition::ConditionGroup,
    ctx: &PolicyContext,
) -> bool {
    match group {
        crate::condition::ConditionGroup::AllOf(conditions) => {
            for cond in conditions {
                match evaluator_for(&cond.condition_type) {
                    Ok(evaluator) => {
                        if !evaluator.evaluate(cond, ctx).await.unwrap_or(false) {
                            return false;
                        }
                    }
                    Err(_) => return false,
                }
            }
            true
        }
        crate::condition::ConditionGroup::AnyOf(conditions) => {
            if conditions.is_empty() {
                return false;
            }
            let mut matched = false;
            let mut had_invalid = false;
            for cond in conditions {
                match evaluator_for(&cond.condition_type) {
                    Ok(evaluator) => match evaluator.evaluate(cond, ctx).await {
                        Ok(true) => matched = true,
                        Ok(false) => {}
                        Err(_) => had_invalid = true,
                    },
                    Err(_) => had_invalid = true,
                }
            }
            matched && !had_invalid
        }
        crate::condition::ConditionGroup::Not(cond) => match evaluator_for(&cond.condition_type) {
            Ok(evaluator) => evaluator.evaluate(cond, ctx).await.unwrap_or(false),
            Err(_) => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// 模拟 RuleRepository（空数据，L1/L2 无匹配 → L3 DEFAULT_DENY）
    struct EmptyRepo;

    #[async_trait::async_trait]
    impl RuleRepository for EmptyRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![])
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }

        async fn load_projected_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }
    }

    // ===== 工具函数 =====

    fn allow_entry(resource: &str, action: &str) -> RuleSetEntry {
        RuleSetEntry {
            effect: Effect::Allow,
            resource: Some(resource.to_string()),
            action: Some(action.to_string()),
            condition: None,
        }
    }

    fn deny_entry(resource: &str, action: &str) -> RuleSetEntry {
        RuleSetEntry {
            effect: Effect::Deny,
            resource: Some(resource.to_string()),
            action: Some(action.to_string()),
            condition: None,
        }
    }

    fn allow_rule(resource: &str, action: &str) -> PermissionRule {
        PermissionRule {
            id: 0,
            effect: Effect::Allow,
            resource: resource.to_string(),
            action: action.to_string(),
            condition: None,
        }
    }

    fn deny_rule(resource: &str, action: &str) -> PermissionRule {
        PermissionRule {
            id: 0,
            effect: Effect::Deny,
            resource: resource.to_string(),
            action: action.to_string(),
            condition: None,
        }
    }

    /// 默认策略上下文（card_id=1, action=read, resource=learn_subject）
    fn test_ctx() -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build()
    }

    /// 模拟仓库（指定 snapshots 和 rules）
    struct MockRepo {
        snapshots: Vec<RuleSetSnapshot>,
        rules: Vec<PermissionRule>,
    }

    #[async_trait::async_trait]
    impl RuleRepository for MockRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(self.snapshots.clone())
        }
        async fn load_snapshot_winners(
            &self,
            _card_id: i64,
        ) -> Result<Vec<SnapshotWinner>, PolicyError> {
            // 从源表条目编译胜者（对齐投影器语义）：跳过带运行时条件的条目，
            // 裸资源名视为类型级 `type:*`，同 (resource_key, action) DENY 优先。
            let mut winners: Vec<SnapshotWinner> = Vec::new();
            for snapshot in &self.snapshots {
                for entry in &snapshot.entries {
                    if entry.condition.is_some() {
                        continue;
                    }
                    let resource = entry.resource.clone().unwrap_or_default();
                    // 已含 `:` 的是完整 key（`type:*` 或 `type:id`）原样保留；
                    // 裸类型名视为类型级 `type:*`。
                    let resource_key = if resource.contains(':') {
                        resource
                    } else {
                        format!("{resource}:*")
                    };
                    let action = entry.action.clone().unwrap_or_default();
                    if let Some(existing) = winners.iter_mut().find(|w: &&mut SnapshotWinner| {
                        w.rule_set_id == snapshot.rule_set_id
                            && w.resource_key == resource_key
                            && w.action_code == action
                    }) {
                        if entry.effect == Effect::Deny {
                            existing.final_effect = "DENY".into();
                        }
                    } else {
                        winners.push(SnapshotWinner {
                            ref_type: snapshot.ref_type.clone(),
                            rule_set_id: snapshot.rule_set_id,
                            resource_key,
                            action_code: action,
                            final_effect: match entry.effect {
                                Effect::Allow => "ALLOW".into(),
                                _ => "DENY".into(),
                            },
                        });
                    }
                }
            }
            Ok(winners)
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(self.rules.clone())
        }

        async fn load_projected_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }
    }

    /// 带投影门禁的模拟仓库：gate 可配置；advance_on_read 在读取规则后推进
    /// 版本（模拟 worker 在评估期间完成投影 → 验证 ALLOW 前复检拒绝旧 ALLOW）
    struct GateRepo {
        gate: Option<ProjectionGate>,
        advance_on_read: bool,
        reads: std::sync::atomic::AtomicUsize,
        gate_override: Mutex<Option<ProjectionGate>>,
    }

    impl GateRepo {
        fn ready(gate: ProjectionGate) -> Self {
            Self {
                gate: Some(gate),
                advance_on_read: false,
                reads: std::sync::atomic::AtomicUsize::new(0),
                gate_override: Mutex::new(None),
            }
        }
        fn pending() -> Self {
            Self {
                gate: Some(ProjectionGate {
                    ready: false,
                    source_generation: 2,
                    revoke_fence: 0,
                }),
                advance_on_read: false,
                reads: std::sync::atomic::AtomicUsize::new(0),
                gate_override: Mutex::new(None),
            }
        }
        fn legacy() -> Self {
            Self {
                gate: None,
                advance_on_read: false,
                reads: std::sync::atomic::AtomicUsize::new(0),
                gate_override: Mutex::new(None),
            }
        }
        fn advancing(initial: ProjectionGate) -> Self {
            Self {
                gate: Some(initial),
                advance_on_read: true,
                reads: std::sync::atomic::AtomicUsize::new(0),
                gate_override: Mutex::new(None),
            }
        }
        fn current_gate(&self) -> ProjectionGate {
            self.gate_override
                .lock()
                .unwrap()
                .unwrap_or(self.gate.unwrap_or(ProjectionGate {
                    ready: true,
                    source_generation: 0,
                    revoke_fence: 0,
                }))
        }
    }

    #[async_trait::async_trait]
    impl RuleRepository for GateRepo {
        async fn load_snapshot_winners(
            &self,
            _card_id: i64,
        ) -> Result<Vec<SnapshotWinner>, PolicyError> {
            // 首次读取后推进（模拟 worker 在评估期间完成重建）。
            // 投影托管卡（有 head）走快照胜者快速路径，推进点放在此处与
            // 真实 worker 重建时序一致。
            if self.advance_on_read
                && self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
            {
                *self.gate_override.lock().unwrap() = Some(ProjectionGate {
                    ready: true,
                    source_generation: 2,
                    revoke_fence: 0,
                });
            }
            Ok(vec![SnapshotWinner {
                ref_type: "BASE".into(),
                rule_set_id: 1,
                resource_key: "learn_subject:*".into(),
                action_code: "read".into(),
                final_effect: "ALLOW".into(),
            }])
        }
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![RuleSetEntry {
                    effect: Effect::Allow,
                    resource: Some("learn_subject".into()),
                    action: Some("read".into()),
                    condition: None,
                }],
            }])
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }
        async fn get_projection_gate(
            &self,
            _card_id: i64,
        ) -> Result<Option<ProjectionGate>, PolicyError> {
            Ok(Some(self.current_gate()))
        }

        async fn load_projected_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }
    }

    // ===== 投影门禁测试（对齐 Java AuthorizationReadPort gate 语义） =====

    #[tokio::test]
    async fn test_projection_pending_denies_before_evaluation() {
        // head 存在但未 READY（source=2, projected=1）→ AUTHORIZATION_PENDING，
        // 即使规则集包含 ALLOW 也不放行
        let engine = PolicyEngine::new();
        let repo = GateRepo::pending();
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        let phases: Vec<&str> = decision
            .evaluation_path
            .iter()
            .map(|s| s.phase.as_str())
            .collect();
        assert!(phases.contains(&"PROJECTION"));
    }

    #[tokio::test]
    async fn test_projection_ready_allows_rule_set() {
        // head READY 且 source==projected → 正常评估，BASE ALLOW 生效
        let engine = PolicyEngine::new();
        let repo = GateRepo::ready(ProjectionGate {
            ready: true,
            source_generation: 2,
            revoke_fence: 0,
        });
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "expected ALLOW, got {:?}",
            decision.reason
        );
        assert_eq!(decision.reason, "RULE_SET_ALLOW");
    }

    #[tokio::test]
    async fn test_default_repository_without_projection_gate_allows() {
        // 未接入 durable gate 的 test repository 保持其显式默认行为。
        let engine = PolicyEngine::new();
        let repo = GateRepo::legacy();
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed);
        assert_eq!(decision.reason, "RULE_SET_ALLOW");
    }

    #[tokio::test]
    async fn test_stale_allow_rejected_when_projection_advances() {
        // 规则读取期间投影推进（source 1→2, projected 1→2）→ 旧 ALLOW 转 AUTHORIZATION_PENDING
        let engine = PolicyEngine::new();
        let repo = GateRepo::advancing(ProjectionGate {
            ready: true,
            source_generation: 1,
            revoke_fence: 0,
        });
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        let phases: Vec<&str> = decision
            .evaluation_path
            .iter()
            .map(|s| s.phase.as_str())
            .collect();
        assert!(phases.contains(&"PROJECTION"));
    }

    #[test]
    fn test_ruleset_dependency_readiness_allows_generation_stamped_empty_projection() {
        let base = RuleSetDependencyStatus {
            rule_set_id: 7,
            ref_type: "BASE".into(),
            rule_set_active: true,
            head_ready: true,
            source_generation: 4,
            projected_generation: 4,
            revoke_fence: 0,
            snapshot_generation: Some(4),
            snapshot_row_count: 0,
            stale_snapshot_rows: 0,
        };
        assert!(base.is_ready());

        let mut disabled = base.clone();
        disabled.rule_set_active = false;
        assert!(disabled.is_ready());

        let mut missing = base;
        missing.snapshot_generation = None;
        assert!(!missing.is_ready());

        let mut residual = disabled;
        residual.snapshot_row_count = 1;
        assert!(residual.is_ready());
    }

    #[tokio::test]
    async fn test_default_deny() {
        let engine = PolicyEngine::new();
        let repo = EmptyRepo;
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "DEFAULT_DENY");
    }

    #[tokio::test]
    async fn test_missing_user_id() {
        let engine = PolicyEngine::new();
        let repo = EmptyRepo;
        let ctx = PolicyContext::builder()
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("test".into()))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHN_REQUIRED");
    }

    #[tokio::test]
    async fn test_missing_card_id() {
        let engine = PolicyEngine::new();
        let repo = EmptyRepo;
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .action("read".into())
            .resource(Some("test".into()))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "CARD_REQUIRED");
    }

    #[tokio::test]
    async fn test_missing_resource() {
        let engine = PolicyEngine::new();
        let repo = EmptyRepo;
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "RESOURCE_REQUIRED");
    }

    #[tokio::test]
    async fn test_empty_action_rejected() {
        let engine = PolicyEngine::new();
        let repo = EmptyRepo;
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .resource(Some("test".into()))
            .action("".into())
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "ACTION_REQUIRED");
    }

    // ===== L1 BASE 测试 =====

    #[tokio::test]
    async fn test_l1_base_allow() {
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject", "read")],
            }],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed);
        assert_eq!(decision.reason, "RULE_SET_ALLOW");
    }

    #[tokio::test]
    async fn test_l1_base_deny() {
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![deny_entry("learn_subject:*", "read")],
            }],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "RULE_SET_DENY");
    }

    // ===== L1 OVERLAY > BASE 优先级测试 =====

    #[tokio::test]
    async fn test_overlay_deny_overrides_base_allow() {
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![
                RuleSetSnapshot {
                    rule_set_id: 1,
                    ref_type: "OVERLAY".into(),
                    entries: vec![deny_entry("learn_subject:*", "read")],
                },
                RuleSetSnapshot {
                    rule_set_id: 2,
                    ref_type: "BASE".into(),
                    entries: vec![allow_entry("learn_subject", "read")],
                },
            ],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed, "OVERLAY DENY must override BASE ALLOW");
        assert_eq!(decision.reason, "RULE_SET_DENY");
    }

    #[tokio::test]
    async fn test_overlay_allow_beats_base_deny() {
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![
                RuleSetSnapshot {
                    rule_set_id: 1,
                    ref_type: "OVERLAY".into(),
                    entries: vec![allow_entry("learn_subject", "read")],
                },
                RuleSetSnapshot {
                    rule_set_id: 2,
                    ref_type: "BASE".into(),
                    entries: vec![deny_entry("learn_subject", "read")],
                },
            ],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed, "OVERLAY ALLOW must beat BASE DENY");
        assert_eq!(decision.reason, "RULE_SET_ALLOW");
    }

    // ===== 层内 DENY-OVERRIDES 测试（评估正式语义） =====

    #[tokio::test]
    async fn test_priority_based_within_overlay() {
        let engine = PolicyEngine::new();
        // 同一 overlay snapshot 中同 key 的 ALLOW 与 DENY：快照唯一键约束
        // （rule_set_id, resource_key, action_code）下由投影器编译胜者，
        // 同优先级冲突 DENY 优先（对齐 Java `MergeSemantics.resolveConflict`）。
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "OVERLAY".into(),
                entries: vec![
                    allow_entry("learn_subject", "read"),
                    deny_entry("learn_subject", "read"),
                ],
            }],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            !decision.allowed,
            "same-key conflict must compile to DENY (resolveConflict)"
        );
        assert_eq!(decision.reason, "RULE_SET_DENY");
    }

    #[tokio::test]
    async fn test_priority_based_within_base() {
        let engine = PolicyEngine::new();
        // BASE 中：类型级 ALLOW 与对象级 DENY 并存。
        // 请求 learn_subject:42 → L1 逐 ref 匹配：exact 命中对象级 DENY
        // （快照胜者含 learn_subject:42 DENY），DENY 优先于类型级 ALLOW。
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![
                    allow_entry("learn_subject:*", "read"),
                    deny_entry("learn_subject:42", "read"),
                ],
            }],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            !decision.allowed,
            "exact object DENY must beat type-level ALLOW in L1"
        );
        assert_eq!(decision.reason, "RULE_SET_DENY");
    }

    #[tokio::test]
    async fn test_multi_overlay_first_match_wins() {
        let engine = PolicyEngine::new();
        // 两个 overlay 规则集：第一个有 allow，第二个有 deny
        // Java 行为：第一个匹配的 overlay 生效（first-match-wins per ref type）
        let repo = MockRepo {
            snapshots: vec![
                RuleSetSnapshot {
                    rule_set_id: 1,
                    ref_type: "OVERLAY".into(),
                    entries: vec![allow_entry("learn_subject", "read")],
                },
                RuleSetSnapshot {
                    rule_set_id: 2,
                    ref_type: "OVERLAY".into(),
                    entries: vec![deny_entry("learn_subject", "read")],
                },
            ],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "Java behavior: first OVERLAY ref with ALLOW wins"
        );
    }

    #[tokio::test]
    async fn test_l1_low_order_ref_wildcard_deny_beats_high_order_ref_exact_allow() {
        // A4 回归：跨 ref 匹配必须按 Java 逐 ref first-match-wins，
        // 而不是跨 ref 的 exact-first（exact 优先会让高序 ref 的精确 ALLOW
        // 遮蔽低序 ref 的通配 DENY，造成越权方向不一致）。
        // 低序 ref(id=1) 类型级 DENY 命中 → 层效果 DENY，高序 ref(id=2) 不再评估。
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![
                RuleSetSnapshot {
                    rule_set_id: 1,
                    ref_type: "OVERLAY".into(),
                    entries: vec![deny_entry("learn_subject:*", "read")],
                },
                RuleSetSnapshot {
                    rule_set_id: 2,
                    ref_type: "OVERLAY".into(),
                    entries: vec![allow_entry("learn_subject", "read")],
                },
            ],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            !decision.allowed,
            "per-ref first-match: low-order ref DENY must win over high-order ref ALLOW"
        );
        assert_eq!(decision.reason, "RULE_SET_DENY");
    }

    #[tokio::test]
    async fn test_l1_snapshot_load_failure_denies_without_l2_fallback() {
        // A1 回归：快照加载失败必须立即 DENY（RULE_SET_UNAVAILABLE），
        // 不得继续 L2 评估——即使 L2 存在旧 ALLOW 规则（快照不可用可能掩盖已撤销权限）。
        struct ErrorWinnersRepo {
            rules: Vec<PermissionRule>,
        }

        #[async_trait::async_trait]
        impl RuleRepository for ErrorWinnersRepo {
            async fn load_snapshot_winners(
                &self,
                _card_id: i64,
            ) -> Result<Vec<SnapshotWinner>, PolicyError> {
                Err(PolicyError::Repository("simulated snapshot failure".into()))
            }
            async fn load_permission_rules(
                &self,
                _card_id: i64,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Ok(self.rules.clone())
            }
            async fn load_rule_set_snapshots(
                &self,
                _card_id: i64,
            ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
                Ok(vec![])
            }
        }

        let engine = PolicyEngine::new();
        let repo = ErrorWinnersRepo {
            rules: vec![allow_rule("learn_subject:*", "read")],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            !decision.allowed,
            "snapshot load failure must deny without falling back to L2"
        );
        assert_eq!(decision.reason, "RULE_SET_UNAVAILABLE");
    }

    // ===== Forward/Reverse Wildcard 测试 =====

    #[tokio::test]
    async fn test_forward_wildcard_type_matches_instance() {
        let engine = PolicyEngine::new();
        // entry 是类型级通配 "learn_subject:*", request 是 "learn_subject:42"
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject:*", "read")],
            }],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "Forward wildcard: type:* must match type:42"
        );
    }

    #[tokio::test]
    async fn test_forward_wildcard_type_name_matches() {
        let engine = PolicyEngine::new();
        // entry 用裸类型名 "learn_subject"（不含 :），request 是 "learn_subject:42"
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject", "read")],
            }],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "Forward wildcard: bare type name must match type:id"
        );
    }

    #[tokio::test]
    async fn test_object_rule_does_not_match_type_request() {
        let engine = PolicyEngine::new();
        // 类型级请求（无 target_id，key=`learn_subject:*`）+ 对象级快照条目。
        // Java `checkRuleSetEffect` Step3 reverse wildcard：请求为 `type:*` 时扫描
        // 对象级条目，DENY 优先；此处只有对象级 ALLOW → 返回 ALLOW。
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject:42", "read")],
            }],
            rules: vec![],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "reverse wildcard: type request matches object ALLOW (Java scanSnapshotEffect)"
        );
    }

    #[tokio::test]
    async fn test_reverse_wildcard_object_deny_beats_type_request() {
        let engine = PolicyEngine::new();
        // 类型级请求 + 对象级 DENY → L1 reverse wildcard 返回 DENY（DENY 优先，
        // 对齐 Java `scanSnapshotEffect` orderByDesc(final_effect)）。
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![deny_entry("learn_subject:42", "read")],
            }],
            rules: vec![],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            !decision.allowed,
            "reverse wildcard: object DENY must block type request"
        );
        assert_eq!(decision.reason, "RULE_SET_DENY");
    }

    // ===== 动作别名测试 =====

    #[tokio::test]
    async fn test_action_alias_write_matches_create() {
        let engine = PolicyEngine::new();
        // entry 定义 write，request 要 create
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject:*", "write")],
            }],
            rules: vec![],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("create".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed, "Alias 'write' must match 'create'");
    }

    #[tokio::test]
    async fn test_action_alias_write_matches_delete() {
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject:*", "write")],
            }],
            rules: vec![],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("delete".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed, "Alias 'write' must match 'delete'");
    }

    #[tokio::test]
    async fn test_alias_forward_wildcard_combined() {
        let engine = PolicyEngine::new();
        // entry 是类型级 write, request 是具体 ID 的 delete
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject", "write")],
            }],
            rules: vec![],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("delete".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "Alias + forward wildcard: write + type matches delete + instance"
        );
    }

    // ===== L2 PermissionRule 回退测试 =====

    #[tokio::test]
    async fn test_l2_fallback() {
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![],
            rules: vec![allow_rule("learn_subject:*", "read")],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed);
        assert_eq!(decision.reason, "RULE_ALLOW");
    }

    #[tokio::test]
    async fn test_l2_fallback_alias() {
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![],
            rules: vec![allow_rule("learn_subject:*", "write")],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("update".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed, "L2 alias: 'write' must match 'update'");
    }

    #[tokio::test]
    async fn test_l2_exact_object_deny_beats_type_allow() {
        // 对齐 Java `findSnapshot` 精确 selectOne：具体对象 DENY 必须先于类型级 ALLOW 判定，
        // 否则 learn_subject:42 的 DENY 会被 learn_subject:* ALLOW 按行序遮蔽（越权）。
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![],
            rules: vec![
                allow_rule("learn_subject:*", "read"),
                deny_rule("learn_subject:42", "read"),
            ],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            !decision.allowed,
            "exact object DENY must beat type-level ALLOW"
        );
        assert_eq!(decision.reason, "RULE_DENY");
    }

    #[tokio::test]
    async fn test_l2_exact_object_allow_beats_type_deny() {
        // 具体对象 ALLOW 优先于类型级 DENY（精确优先两段式的正向用例）
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![],
            rules: vec![
                deny_rule("learn_subject:*", "read"),
                allow_rule("learn_subject:42", "read"),
            ],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "exact object ALLOW must beat type-level DENY"
        );
        assert_eq!(decision.reason, "RULE_ALLOW");
    }

    #[tokio::test]
    async fn test_l2_type_request_ignores_object_rule() {
        // 类型级请求（无 target_id）不能命中具体对象规则：
        // 仅有 learn_subject:42 DENY 时，learn_subject:* 请求不得被对象规则拒绝。
        let engine = PolicyEngine::new();
        let repo = MockRepo {
            snapshots: vec![],
            rules: vec![deny_rule("learn_subject:42", "read")],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed, "no type-level rule should match");
        assert_eq!(decision.reason, "DEFAULT_DENY");
    }

    // ===== 条件评估测试 =====
    //
    // 对齐 Java：运行时条件仅在 L2（permission_rule）级别评估，
    // L1（rule_set）中带运行时条件的条目被跳过（如同 Java snapshot 编译时排除）。

    #[tokio::test]
    async fn test_condition_time_range_passes_at_l2() {
        let engine = PolicyEngine::new();
        let condition = serde_json::json!({
            "condition_type": "TimeRangeCondition",
            "params": { "start": "00:00", "end": "23:59" }
        });
        let repo = MockRepo {
            snapshots: vec![],
            rules: vec![PermissionRule {
                id: 1,
                effect: Effect::Allow,
                resource: "learn_subject:*".into(),
                action: "read".into(),
                condition: Some(condition),
            }],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "TimeRange 00:00-23:59 should pass at any time (L2)"
        );
    }

    #[tokio::test]
    async fn test_condition_owner_only_pass_at_l2() {
        let engine = PolicyEngine::new();
        let condition = serde_json::json!({
            "condition_type": "OwnerOnlyCondition",
            "params": {}
        });
        let repo = MockRepo {
            snapshots: vec![],
            rules: vec![PermissionRule {
                id: 1,
                effect: Effect::Allow,
                resource: "learn_subject:*".into(),
                action: "read".into(),
                condition: Some(condition),
            }],
        };
        // 对齐 Java ConditionEvaluator.ownerOnly：resourceOwnerId == currentUserId → allow
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(100))
            .resource_owner_id(Some(1))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "OwnerOnly with matching resource owner should pass at L2"
        );
    }

    #[tokio::test]
    async fn test_condition_owner_only_blocks_at_l2() {
        let engine = PolicyEngine::new();
        let condition = serde_json::json!({
            "condition_type": "OwnerOnlyCondition",
            "params": {}
        });
        let repo = MockRepo {
            snapshots: vec![],
            rules: vec![PermissionRule {
                id: 1,
                effect: Effect::Allow,
                resource: "learn_subject:*".into(),
                action: "read".into(),
                condition: Some(condition),
            }],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            !decision.allowed,
            "OwnerOnly without target_id should block at L2"
        );
    }

    #[tokio::test]
    async fn test_l1_skips_condition_entry_falls_to_unconditional() {
        let engine = PolicyEngine::new();
        // 第一个 entry 有时间范围条件（L1 中跳过），第二个无条件（L1 匹配）
        let past_condition = serde_json::json!({
            "condition_type": "TimeRangeCondition",
            "params": { "start": "00:00", "end": "01:00" }
        });
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![
                    RuleSetEntry {
                        effect: Effect::Allow,
                        resource: Some("learn_subject:*".into()),
                        action: Some("read".into()),
                        condition: Some(past_condition),
                    },
                    allow_entry("learn_subject:*", "read"), // 无条件，兜底
                ],
            }],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        // 第一个 entry 带运行时条件被 L1 跳过，第二个无条件 entry 应匹配
        assert!(
            decision.allowed,
            "L1 should skip condition entry and match unconditional fallback"
        );
    }

    #[tokio::test]
    async fn test_l1_condition_entry_skipped_falls_to_l2() {
        let engine = PolicyEngine::new();
        let condition = serde_json::json!({
            "condition_type": "TimeRangeCondition",
            "params": { "start": "00:00", "end": "23:59" }
        });
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![RuleSetEntry {
                    effect: Effect::Allow,
                    resource: Some("learn_subject:*".into()),
                    action: Some("read".into()),
                    condition: Some(condition),
                }],
            }],
            // 带条件的 entry 被 L1 跳过，L2 无条件 fallback 匹配
            rules: vec![allow_rule("learn_subject:*", "read")],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "L1 condition entry skipped, L2 fallback should match"
        );
    }

    #[tokio::test]
    async fn test_l2_repository_error_terminates_before_l2_5() {
        struct ErrorL2DelegationRepo {
            projected_delegation_reads: std::sync::atomic::AtomicUsize,
        }

        #[async_trait::async_trait]
        impl RuleRepository for ErrorL2DelegationRepo {
            async fn load_rule_set_snapshots(
                &self,
                _card_id: i64,
            ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
                Ok(vec![])
            }

            async fn load_permission_rules(
                &self,
                _card_id: i64,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Err(PolicyError::Repository("L2 unavailable".into()))
            }

            async fn load_delegated_rules(
                &self,
                _delegate_id: i64,
                _resource: &str,
                _action: &str,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Ok(vec![allow_rule("learn_subject:*", "read")])
            }

            async fn load_projected_delegated_rules(
                &self,
                _delegate_id: i64,
                _resource: &str,
                _action: &str,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                self.projected_delegation_reads
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(vec![allow_rule("learn_subject:*", "read")])
            }
        }

        let engine = PolicyEngine::new();
        let repo = ErrorL2DelegationRepo {
            projected_delegation_reads: std::sync::atomic::AtomicUsize::new(0),
        };
        let ctx = test_ctx();

        for _ in 0..10 {
            let decision = engine.evaluate(&ctx, &repo).await;
            assert!(!decision.allowed);
            assert_eq!(decision.reason, "DEPENDENCY_UNAVAILABLE");
            assert!(decision
                .evaluation_path
                .iter()
                .all(|step| step.phase != "DELEGATION"));
        }
        assert_eq!(
            repo.projected_delegation_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "L2 errors must terminate before projected delegation fallback"
        );
        assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);

        let decision = engine.evaluate(&ctx, &repo).await;
        assert_eq!(decision.reason, "CIRCUIT_BREAKER_OPEN");
    }

    #[tokio::test]
    async fn test_projected_delegation_is_evaluated_only_at_l2_5() {
        struct ProjectedDelegationRepo;

        #[async_trait::async_trait]
        impl RuleRepository for ProjectedDelegationRepo {
            async fn load_rule_set_snapshots(
                &self,
                _card_id: i64,
            ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
                Ok(vec![])
            }

            async fn load_permission_rules(
                &self,
                _card_id: i64,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Ok(vec![])
            }

            async fn load_delegated_rules(
                &self,
                _delegate_id: i64,
                _resource: &str,
                _action: &str,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Ok(vec![])
            }

            async fn load_projected_delegated_rules(
                &self,
                _delegate_id: i64,
                _resource: &str,
                _action: &str,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Ok(vec![allow_rule("learn_subject:*", "read")])
            }
        }

        let engine = PolicyEngine::new();
        let decision = engine.evaluate(&test_ctx(), &ProjectedDelegationRepo).await;

        assert!(decision.allowed);
        assert_eq!(decision.reason, "DELEGATION_ALLOW");
        assert!(decision
            .evaluation_path
            .iter()
            .any(|step| step.phase == "DELEGATION" && step.result == Effect::Allow));
        assert!(!decision
            .evaluation_path
            .iter()
            .any(|step| step.phase == "PERMISSION_RULE" && step.result == Effect::Allow));
        assert_eq!(engine.get_stats().l2_hits, 0);
    }

    #[tokio::test]
    async fn test_l2_5_repository_error_counts_as_failure() {
        struct ErrorDelegationRepo;

        #[async_trait::async_trait]
        impl RuleRepository for ErrorDelegationRepo {
            async fn load_rule_set_snapshots(
                &self,
                _card_id: i64,
            ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
                Ok(vec![])
            }

            async fn load_permission_rules(
                &self,
                _card_id: i64,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Ok(vec![])
            }

            async fn load_projected_delegated_rules(
                &self,
                _delegate_id: i64,
                _resource: &str,
                _action: &str,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Err(PolicyError::Repository("delegation unavailable".into()))
            }
        }

        let engine = PolicyEngine::new();
        let repo = ErrorDelegationRepo;
        let ctx = test_ctx();

        for _ in 0..10 {
            let decision = engine.evaluate(&ctx, &repo).await;
            assert!(!decision.allowed);
            assert_eq!(decision.reason, "DEFAULT_DENY");
        }
        assert_eq!(engine.circuit_breaker_state(), CircuitBreakerState::Open);
    }

    #[tokio::test]
    async fn test_alias_plus_wildcard_at_l1() {
        let engine = PolicyEngine::new();
        // 别名 write + 类型级通配（无条件 → L1 正常匹配）
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![RuleSetEntry {
                    effect: Effect::Allow,
                    resource: Some("learn_subject".into()), // 类型级
                    action: Some("write".into()),           // 别名
                    condition: None,                        // 无条件
                }],
            }],
            rules: vec![],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("delete".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(
            decision.allowed,
            "L1: alias+wildcard without condition should pass"
        );
    }

    #[tokio::test]
    async fn test_alias_plus_condition_at_l2() {
        let engine = PolicyEngine::new();
        // 别名 write + 时间范围条件 → L2 匹配（L1 无条件则 fall through）
        let condition = serde_json::json!({
            "condition_type": "TimeRangeCondition",
            "params": { "start": "00:00", "end": "23:59" }
        });
        let repo = MockRepo {
            snapshots: vec![],
            rules: vec![PermissionRule {
                id: 1,
                effect: Effect::Allow,
                resource: "learn_subject:*".into(),
                action: "write".into(),
                condition: Some(condition),
            }],
        };
        let ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(1))
            .action("delete".into())
            .resource(Some("learn_subject".into()))
            .target_id(Some(42))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed, "L2: alias+condition+wildcard should pass");
    }

    #[tokio::test]
    async fn test_wildcard_action_match() {
        let engine = PolicyEngine::new();
        // 快照胜者 action 为 read，请求 read → 精确匹配。
        // （Java 快照/引擎均不支持 `*` 动作通配，此处验证类型级资源匹配。）
        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("learn_subject:*", "read")],
            }],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(decision.allowed);
    }

    // ===== 断路器 + 并发测试 =====

    #[tokio::test]
    async fn test_circuit_breaker_fall_closed() {
        let engine = PolicyEngine::new();
        engine.force_open_circuit_breaker();

        let repo = MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("anything", "read")],
            }],
            rules: vec![],
        };
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed, "circuit breaker open must deny");
        assert_eq!(decision.reason, "CIRCUIT_BREAKER_OPEN");
    }

    #[tokio::test]
    async fn test_inactive_card_rejected() {
        struct InactiveRepo;
        #[async_trait::async_trait]
        impl RuleRepository for InactiveRepo {
            async fn load_rule_set_snapshots(
                &self,
                _card_id: i64,
            ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
                Ok(vec![])
            }
            async fn load_permission_rules(
                &self,
                _card_id: i64,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Ok(vec![])
            }
            async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
                Ok(false)
            }
        }

        let engine = PolicyEngine::new();
        let repo = InactiveRepo;
        let ctx = test_ctx();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "CARD_DISABLED");
    }

    #[tokio::test]
    async fn test_concurrent_evaluations() {
        let engine = std::sync::Arc::new(PolicyEngine::new());
        let repo = std::sync::Arc::new(MockRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![allow_entry("test:*", "read")],
            }],
            rules: vec![],
        });

        let mut handles = vec![];
        for i in 0..10 {
            let engine = engine.clone();
            let repo = repo.clone();
            handles.push(tokio::spawn(async move {
                let ctx = PolicyContext::builder()
                    .user_id(Some(i))
                    .card_id(Some(i))
                    .action("read".into())
                    .resource(Some("test".into()))
                    .target_id(Some(i))
                    .build();
                engine.evaluate(&ctx, repo.as_ref()).await
            }));
        }

        for handle in handles {
            let decision = handle.await.unwrap();
            assert!(decision.allowed);
        }
    }

    // ===== Published-card shadow read port（非正式 evaluate 端口） =====

    /// Minimal Ready-gate evidence fixture for classifier tests ONLY.
    ///
    /// The real strict reader is the sole legitimate constructor of
    /// [`astral_types::PublishedCardAuthorization`] with non-empty collections;
    /// this hand-made empty collection fixture must never leak outside tests.
    fn ready_shadow_evidence(scope: &PublishedCardEvidenceScope) -> PublishedCardAuthorization {
        PublishedCardAuthorization {
            tenant_id: scope.tenant_id,
            card_id: scope.card_id,
            read_unix_seconds: 1_700_000_000,
            gate: astral_types::PublishedCardAuthorizationGate {
                status: astral_types::PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 0,
                verified_record_count: 0,
                effective_grant_count: 0,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![],
            records: vec![],
            effective_grants: vec![],
        }
    }

    #[test]
    fn formal_evaluate_switches_to_published_evidence_only_behind_capability_marker() {
        let source = include_str!("engine.rs");

        // evaluate() gates the strict published-evidence path on the capability
        // marker and delegates to the dedicated strict-gate helper.
        let evaluate_region = source
            .split("pub async fn evaluate<R: RuleRepository>")
            .nth(1)
            .and_then(|body| {
                body.split("async fn evaluate_rule_sets<R: RuleRepository>")
                    .next()
            })
            .expect("formal evaluate entry must exist");
        assert!(
            evaluate_region.contains("requires_published_card_evidence"),
            "formal evaluate must gate the strict path on the capability marker"
        );
        assert!(
            evaluate_region.contains("evaluate_published_card_evidence"),
            "formal evaluate must delegate the strict path to the published-evidence helper"
        );

        // The L1/L2 union helpers themselves stay free of the published-evidence
        // port: only the strict gate consumes it, never the rule readers.
        let rule_set_union_region = source
            .split("async fn evaluate_rule_sets<R: RuleRepository>")
            .nth(1)
            .and_then(|body| {
                body.split("async fn evaluate_permission_rules<R: RuleRepository>")
                    .next()
            })
            .expect("rule set union region must exist");
        let permission_rules_region = source
            .split("async fn evaluate_permission_rules<R: RuleRepository>")
            .nth(1)
            .and_then(|body| body.split("pub fn evaluate_fallback").next())
            .expect("permission rules L2 region must exist");
        for body in [rule_set_union_region, permission_rules_region] {
            assert!(
                !body.contains("load_published_card_authorization"),
                "L1/L2 union paths must never consult the published-evidence port"
            );
            assert!(
                !body.contains("published_card_shadow_evidence_is_usable"),
                "L1/L2 union paths must never consult the shadow classifier"
            );
        }

        // The trait default stays an explicit unavailable marker (`Ok(None)`),
        // never a synthetic Ready payload.
        let default_impl = source
            .split("async fn load_published_card_authorization")
            .nth(1)
            .expect("published evidence port declaration must exist");
        let default_impl_body = default_impl.split('}').next().unwrap_or(default_impl);
        assert!(
            default_impl_body.contains("Ok(None)"),
            "trait default must remain the explicit legacy/test unavailable marker"
        );
        assert!(
            !default_impl_body.contains("PublishedEvidenceGateStatus::Ready"),
            "trait default must never fabricate a Ready gate"
        );

        // The capability marker defaults to false for test/default repositories.
        let marker_default = source
            .split("fn requires_published_card_evidence")
            .nth(1)
            .and_then(|body| body.split('}').next())
            .expect("capability marker declaration must exist");
        assert!(
            marker_default.contains("false"),
            "capability marker must default to false for test/default repositories"
        );
    }

    #[tokio::test]
    async fn shadow_port_default_is_unavailable_and_never_authorizes() {
        let repo = EmptyRepo;
        let scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 17,
            user_filter: Some(42),
            domain: astral_types::DomainScopeRequirement::ExactlySome(11),
        };
        let outcome = repo
            .load_published_card_authorization(&scope)
            .await
            .unwrap();
        assert_eq!(outcome, None);
        // Ok(None) is an unavailable marker, NOT an empty-but-valid ALLOW.
        assert!(!published_card_shadow_evidence_is_usable(&Ok(None)));
        // Repository failures classify as unusable too (pending/deny upstream).
        assert!(!published_card_shadow_evidence_is_usable(&Err(PolicyError::Repository(
            "published_card_evidence_not_ready;code=published_card_evidence.current_pointer_missing"
                .into(),
        ))));
        assert!(!published_card_shadow_evidence_is_usable(&Err(
            PolicyError::InvalidContext("published_card_evidence_invalid_request;code=x".into(),)
        )));
    }

    /// A repository overriding the port must receive the exact caller scope
    /// (tenant/card/user/domain lens unchanged) and a Ready gate result is the
    /// only outcome classified usable.
    #[tokio::test]
    async fn shadow_scope_passthrough_keeps_tenant_card_user_domain() {
        struct ScopeCaptureRepo {
            captured: Mutex<Vec<PublishedCardEvidenceScope>>,
        }

        #[async_trait::async_trait]
        impl RuleRepository for ScopeCaptureRepo {
            async fn load_rule_set_snapshots(
                &self,
                _card_id: i64,
            ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
                Ok(vec![])
            }
            async fn load_permission_rules(
                &self,
                _card_id: i64,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                Ok(vec![])
            }
            async fn load_published_card_authorization(
                &self,
                scope: &PublishedCardEvidenceScope,
            ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
                self.captured.lock().unwrap().push(scope.clone());
                Ok(Some(ready_shadow_evidence(scope)))
            }
        }

        let repo = ScopeCaptureRepo {
            captured: Mutex::new(vec![]),
        };
        let scope = PublishedCardEvidenceScope {
            tenant_id: 9,
            card_id: 33,
            user_filter: None,
            domain: astral_types::DomainScopeRequirement::ExactlyNone,
        };
        let outcome = repo
            .load_published_card_authorization(&scope)
            .await
            .unwrap();
        assert!(outcome.is_some());
        assert!(published_card_shadow_evidence_is_usable(&Ok(outcome)));
        let captured = repo.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], scope);
        assert_eq!(captured[0].tenant_id, 9);
        assert_eq!(captured[0].card_id, 33);
        assert_eq!(captured[0].user_filter, None);
        assert_eq!(
            captured[0].domain,
            astral_types::DomainScopeRequirement::ExactlyNone
        );
    }

    #[test]
    fn shadow_classifier_only_accepts_ready_gated_some() {
        let usable = ready_shadow_evidence(&PublishedCardEvidenceScope {
            tenant_id: 1,
            card_id: 1,
            user_filter: None,
            domain: astral_types::DomainScopeRequirement::Unconstrained,
        });
        assert!(published_card_shadow_evidence_is_usable(&Ok(Some(usable))));

        let mut corrupt = ready_shadow_evidence(&PublishedCardEvidenceScope {
            tenant_id: 1,
            card_id: 1,
            user_filter: None,
            domain: astral_types::DomainScopeRequirement::Unconstrained,
        });
        corrupt.gate.status = astral_types::PublishedEvidenceGateStatus::Corrupt;
        assert!(!published_card_shadow_evidence_is_usable(&Ok(Some(
            corrupt
        ))));
    }

    // ===== Published-evidence strict gate（正式路径，capability marker = true） =====

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            compiler_version: "test".to_string(),
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
                compiler_version: "test".to_string(),
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

    /// strict gate 测试仓库：capability marker = true，按序返回预置读取结果，
    /// 预置耗尽后复用 fallback 证据；L1/L2/L2.5 读取器一旦被调用即计数。
    /// 一致性采样/realtime oracle 专用读取器（projection gate、raw rule_set、
    /// raw permission_rule、legacy delegation）同样计数：strict 路径唯一合法
    /// 的仓库读取是 `load_published_card_authorization`，任何其余读取计数
    /// 非零都意味着 evaluate() 泄漏到了 legacy consistency/realtime 路径。
    struct StrictPublishedRepo {
        outcomes: Mutex<VecDeque<Result<Option<PublishedCardAuthorization>, PolicyError>>>,
        fallback: Option<PublishedCardAuthorization>,
        global_admin_outcomes: Mutex<VecDeque<Result<bool, PolicyError>>>,
        global_admin_fallback: bool,
        global_admin_reads: AtomicUsize,
        legacy_reader_calls: AtomicUsize,
        published_reads: AtomicUsize,
        published_scopes: Mutex<Vec<PublishedCardEvidenceScope>>,
    }

    impl StrictPublishedRepo {
        fn with_evidence(evidence: PublishedCardAuthorization) -> Self {
            Self {
                outcomes: Mutex::new(VecDeque::new()),
                fallback: Some(evidence),
                global_admin_outcomes: Mutex::new(VecDeque::new()),
                global_admin_fallback: false,
                global_admin_reads: AtomicUsize::new(0),
                legacy_reader_calls: AtomicUsize::new(0),
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
                fallback: Some(evidence),
                global_admin_outcomes: Mutex::new(global_admin_outcomes.into()),
                global_admin_fallback: false,
                global_admin_reads: AtomicUsize::new(0),
                legacy_reader_calls: AtomicUsize::new(0),
                published_reads: AtomicUsize::new(0),
                published_scopes: Mutex::new(vec![]),
            }
        }

        fn with_outcomes(
            outcomes: Vec<Result<Option<PublishedCardAuthorization>, PolicyError>>,
        ) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                fallback: None,
                global_admin_outcomes: Mutex::new(VecDeque::new()),
                global_admin_fallback: false,
                global_admin_reads: AtomicUsize::new(0),
                legacy_reader_calls: AtomicUsize::new(0),
                published_reads: AtomicUsize::new(0),
                published_scopes: Mutex::new(vec![]),
            }
        }

        fn legacy_calls(&self) -> usize {
            self.legacy_reader_calls.load(Ordering::SeqCst)
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
        fn requires_published_card_evidence(&self) -> bool {
            true
        }

        async fn load_published_card_authorization(
            &self,
            scope: &PublishedCardEvidenceScope,
        ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
            self.published_scopes.lock().unwrap().push(scope.clone());
            self.published_reads.fetch_add(1, Ordering::SeqCst);
            if let Some(outcome) = self.outcomes.lock().unwrap().pop_front() {
                return outcome;
            }
            match &self.fallback {
                Some(evidence) => Ok(Some(evidence.clone())),
                None => panic!("unexpected extra published evidence read"),
            }
        }

        async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
            self.global_admin_reads.fetch_add(1, Ordering::SeqCst);
            if let Some(outcome) = self.global_admin_outcomes.lock().unwrap().pop_front() {
                return outcome;
            }
            Ok(self.global_admin_fallback)
        }

        // 一致性采样/realtime oracle 专用读取器：strict 路径绝不调用；
        // 计数非零即说明 evaluate() 触碰了 legacy consistency/realtime 路径。
        async fn get_projection_gate(
            &self,
            _card_id: i64,
        ) -> Result<Option<ProjectionGate>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }
        async fn load_rule_set_entries_raw(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }
        async fn load_permission_rules_raw(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }
        async fn load_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }

        // strict 路径绝不触碰 L1/L2/L2.5 读取器；调用即被计数并在断言中失败。
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }
        async fn load_snapshot_winners(
            &self,
            _card_id: i64,
        ) -> Result<Vec<SnapshotWinner>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }
        async fn load_projected_delegated_rules(
            &self,
            _delegate_id: i64,
            _resource: &str,
            _action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![])
        }
    }

    const STRICT_RULESET_BASE_GRANT_ID: &str = "550e8400-e29b-41d4-a716-446655440001";

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
            timing.refs_load_ns,
            timing.initial_evidence_load_ns + timing.final_evidence_reload_ns,
            "legacy aggregate must equal the separately observed strict reads"
        );
        assert_eq!(
            repo.published_reads(),
            2,
            "ALLOW requires initial + final strict read"
        );
        // ALLOW 复读发生在返回前：initial + recheck 两次读取，无第三次。
        assert_eq!(
            repo.legacy_calls(),
            0,
            "strict path must not read L1/L2/L2.5"
        );
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
    async fn global_control_plane_requires_strict_evidence_before_legacy_reads() {
        struct LegacyGlobalRepo {
            global_admin_reads: AtomicUsize,
            legacy_reads: AtomicUsize,
        }

        #[async_trait::async_trait]
        impl RuleRepository for LegacyGlobalRepo {
            async fn load_rule_set_snapshots(
                &self,
                _card_id: i64,
            ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
                self.legacy_reads.fetch_add(1, Ordering::SeqCst);
                Ok(vec![RuleSetSnapshot {
                    rule_set_id: 1,
                    ref_type: "BASE".into(),
                    entries: vec![allow_entry("learn_subject", "read")],
                }])
            }

            async fn load_permission_rules(
                &self,
                _card_id: i64,
            ) -> Result<Vec<PermissionRule>, PolicyError> {
                self.legacy_reads.fetch_add(1, Ordering::SeqCst);
                Ok(vec![allow_rule("learn_subject", "read")])
            }

            async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
                self.global_admin_reads.fetch_add(1, Ordering::SeqCst);
                Ok(true)
            }
        }

        let repo = LegacyGlobalRepo {
            global_admin_reads: AtomicUsize::new(0),
            legacy_reads: AtomicUsize::new(0),
        };
        let mut ctx = test_ctx();
        ctx.resource_ownership_scope = ResourceOwnershipScope::Global;
        ctx.global_access_requirement = GlobalAccessRequirement::ActiveGlobalAdmin;

        let decision = PolicyEngine::new().evaluate(&ctx, &repo).await;

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(
            decision
                .evaluation_path
                .last()
                .map(|step| step.detail.as_str()),
            Some("global control-plane requests require strict published evidence")
        );
        assert_eq!(repo.global_admin_reads.load(Ordering::SeqCst), 0);
        assert_eq!(repo.legacy_reads.load(Ordering::SeqCst), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
    }

    #[tokio::test]
    async fn test_strict_missing_evidence_is_fail_closed_pending() {
        let repo = StrictPublishedRepo::with_outcomes(vec![Ok(None)]);
        let engine = PolicyEngine::new();

        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
    }

    fn unsafe_allow_omitting_final_reload(
        ctx: &PolicyContext,
        evidence: &PublishedCardAuthorization,
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
        assert!(
            unsafe_allow_omitting_final_reload(&strict_ctx(), &first),
            "omitting the final reload admits the initial stale candidate"
        );

        let repo = StrictPublishedRepo::with_outcomes(vec![Ok(Some(first)), Ok(Some(narrowed))]);
        let decision = PolicyEngine::new().evaluate(&strict_ctx(), &repo).await;
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(repo.published_reads(), 2);
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
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
        assert_eq!(repo.legacy_calls(), 0);
    }

    // ===== strict gate 与 legacy 一致性采样隔离 =====

    /// 一致性采样窗口：`SnapshotConsistencyChecker` 按 1% 采样（间隔 100），
    /// 连续 1000 次 evaluate() 在未跳过采样的实现下期望触发约 10 次采样，
    /// 每次采样都会调用 projection gate / evaluate_realtime 的 raw 读取器并在
    /// StrictPublishedRepo 留下 legacy 计数。整个窗口内计数保持 0 才能证明
    /// strict 评估与 legacy consistency/realtime 路径完全隔离。
    const CONSISTENCY_SAMPLE_WINDOW: usize = 1000;

    #[tokio::test]
    async fn test_strict_allow_loop_never_invokes_legacy_consistency_or_realtime() {
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

        for _ in 0..CONSISTENCY_SAMPLE_WINDOW {
            let decision = engine.evaluate(&ctx, &repo).await;
            assert!(
                decision.allowed,
                "published ALLOW must remain correct, got {:?}",
                decision.reason
            );
            assert_eq!(decision.reason, "PUBLISHED_EVIDENCE_ALLOW");
            assert_eq!(
                repo.legacy_calls(),
                0,
                "strict evaluation must not invoke legacy consistency/realtime/raw readers"
            );
        }

        // 每次 strict ALLOW 恰好两次 published 读取（initial + ALLOW 前复读）；
        // 一致性/realtime 路径不消费 published evidence，计数不得超出。
        assert_eq!(repo.published_reads(), CONSISTENCY_SAMPLE_WINDOW * 2);
    }

    #[tokio::test]
    async fn test_strict_fail_closed_loop_never_invokes_legacy_consistency_or_realtime() {
        // 证据不包含本次请求的 grant → DEFAULT_DENY（fail-closed，无复读）。
        // fail-closed 决策同样不得触碰 legacy consistency/realtime/raw 读取器。
        let evidence = strict_ready_evidence(vec![strict_published_grant(
            "550e8400-e29b-41d4-a716-446655440002",
            astral_types::GrantSourceKind::RuleSet,
            astral_types::BindingLayer::Base,
            "learn_course:9",
            "read",
        )]);
        let repo = StrictPublishedRepo::with_evidence(evidence);
        let engine = PolicyEngine::new();

        for _ in 0..CONSISTENCY_SAMPLE_WINDOW {
            let decision = engine.evaluate(&strict_ctx(), &repo).await;
            assert!(
                !decision.allowed,
                "no-match must stay fail-closed, got {:?}",
                decision.reason
            );
            assert_eq!(decision.reason, "DEFAULT_DENY");
            assert_eq!(
                repo.legacy_calls(),
                0,
                "strict fail-closed path must not invoke legacy consistency/realtime/raw readers"
            );
        }

        // 无命中 → 仅 initial 读取，无复读，也无一额外读取。
        assert_eq!(repo.published_reads(), CONSISTENCY_SAMPLE_WINDOW);
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

    // ===== allow_source_phase 命中来源归因（hit-stat source）=====

    #[test]
    fn test_allow_source_phase_org_allow_reports_org_authority() {
        // ORG_SCOPE 准入的 ALLOW 步（org_admission 产生的 ORG_AUTHORITY 步，
        // source=ORG_PERSONAL/ORG_SHARED）必须精确上报为 ORG_AUTHORITY，
        // 不得落入 PERMISSION_RULE 兜底。
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

        // 命中来源取“最近一个 ALLOW”步：更早的 PERMISSION_RULE ALLOW 不遮蔽
        // 其后的 ORG_AUTHORITY ALLOW。
        let decision = allow(
            "ORG_PUBLISHED_EVIDENCE_ALLOW",
            "org-grant-1",
            vec![
                step("PERMISSION_RULE", "ALLOW", "earlier allow", None),
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
    fn test_allow_source_phase_legacy_mappings_unchanged() {
        // ORG 之外的 phase → source 映射（含 PERMISSION_RULE 兜底）保持不变。
        let phase_cases: &[(&str, &str)] = &[
            ("RULESET", "RULE_SET"),
            ("RULE_SET", "RULE_SET"),
            ("SNAPSHOT", "RULE_SET"),
            ("PERMISSION_RULE", "PERMISSION_RULE"),
            ("DELEGATION", "DELEGATION"),
            ("TEMPLATE", "TEMPLATE"),
            ("SOME_FUTURE_PHASE", "PERMISSION_RULE"),
        ];
        for (phase, expected) in phase_cases {
            let decision = allow("ALLOW", "rule-1", vec![step(phase, "ALLOW", "hit", None)]);
            assert_eq!(
                PolicyEngine::allow_source_phase(&decision),
                Some(*expected),
                "phase {phase} mapping must stay intact"
            );
        }

        // PUBLISHED_EVIDENCE 分支按 grant source 归因，未知 source 兜底
        // PERMISSION_RULE；ORG_PERSONAL/ORG_SHARED 只属于 ORG_AUTHORITY 步，
        // 不影响本分支。
        let published_cases: &[(&str, &str)] = &[
            ("RULE_SET_BASE", "RULE_SET"),
            ("RULE_SET_OVERLAY", "RULE_SET"),
            ("RULE_SET", "RULE_SET"),
            ("DIRECT", "DIRECT"),
            ("APPROVAL", "APPROVAL"),
            ("DELEGATION", "DELEGATION"),
            ("SYSTEM", "PERMISSION_RULE"),
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
                "published source {source} mapping must stay intact"
            );
        }

        // DENY 决策无命中来源（含 ORG_AUTHORITY DENY 步）。
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

    // ===== ORG_SCOPE 准入门禁（load_org_authorization 五态切换回归） =====
    //
    // 覆盖 `PolicyEngine.evaluate()` 在 AUTHN/CARD_CONTEXT/resource/action 校验
    // 之后对 `RuleRepository::load_org_authorization` 五态的调度：
    // - Disabled → ORG_AUTHORITY_DISABLED（先于 legacy L1/L2 与 strict published
    //   evidence 两条证据路径，绝不放行）；
    // - Pending → AUTHORIZATION_PENDING（已确认业务态，fail-closed，无 legacy 回落）；
    // - Unavailable → AUTHORIZATION_PENDING（依赖不可用，fail-closed 且累计断路器失败）；
    // - Unmanaged → 保持既有 legacy 评估路由行为（既有兼容 ALLOW 夹具）；
    // - Ready → 经公共入口走 org_admission 正式准入（初始读取 + ALLOW 前复读）。
    // 全部为进程内 stub 仓库，不触碰数据库/网络/运行时配置。
    use crate::org_admission::OrgAuthorityRead;
    use astral_types::org_scope::{
        org_build_segment, org_manifest_digest_hex, OrgAdmissionEvidence, OrgContribution,
        OrgGrant, OrgGrantRef, OrgManifestDigestMaterial, OrgMembership, OrgNode, OrgProvenance,
        OrgPublication, OrgRootActivation, OrgScope, OrgScopeKey, OrgSegmentContent,
    };
    use astral_types::ValidityWindow;

    /// 行政单元（签名 actor）租户与身份四元组（org_admission 夹具同源）。
    const ORG_GATE_TENANT: i64 = 100;
    const ORG_GATE_USER_ID: i64 = 11;
    const ORG_GATE_IDENTITY_CARD_ID: i64 = 111;
    const ORG_GATE_CARD_ID: i64 = 222;
    /// 统一读取时钟：落在 grant validity (1000..2000) 与 membership 窗口内。
    const ORG_GATE_READ_CLOCK: i64 = 1_500;

    /// ORG_SCOPE 门禁测试仓库：`load_org_authorization` 恒返回预置三态；
    /// strict published-evidence 读取器与 legacy L1/L2 读取器全部计数，用于证明
    /// Disabled/Pending 在两条证据路径之前短路、Ready 短路整个旧链、Unmanaged
    /// 继续消费既有 legacy 评估路由。
    struct OrgGateSwitchRepo {
        org_read: OrgAuthorityRead,
        strict_published_evidence: bool,
        /// published evidence 读取器被（错误）触达时的返回：true = 与请求身份
        /// 逐项匹配的 would-allow Ready 夹具（门禁一旦失效即放行，测试立即
        /// 失败），false = 显式 unavailable（Ok(None)）。
        published_would_allow: bool,
        snapshot_winners: Vec<SnapshotWinner>,
        permission_rules: Vec<PermissionRule>,
        org_reads: AtomicUsize,
        published_reads: AtomicUsize,
        legacy_reader_calls: AtomicUsize,
    }

    impl OrgGateSwitchRepo {
        fn new(org_read: OrgAuthorityRead, strict_published_evidence: bool) -> Self {
            Self {
                org_read,
                strict_published_evidence,
                published_would_allow: strict_published_evidence,
                snapshot_winners: vec![org_gate_legacy_allow_winner()],
                permission_rules: vec![allow_rule("learn_subject:42", "read")],
                org_reads: AtomicUsize::new(0),
                published_reads: AtomicUsize::new(0),
                legacy_reader_calls: AtomicUsize::new(0),
            }
        }

        fn org_reads(&self) -> usize {
            self.org_reads.load(Ordering::SeqCst)
        }

        fn published_reads(&self) -> usize {
            self.published_reads.load(Ordering::SeqCst)
        }

        fn legacy_reader_calls(&self) -> usize {
            self.legacy_reader_calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl RuleRepository for OrgGateSwitchRepo {
        fn requires_published_card_evidence(&self) -> bool {
            self.strict_published_evidence
        }

        async fn load_published_card_authorization(
            &self,
            _scope: &PublishedCardEvidenceScope,
        ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
            self.published_reads.fetch_add(1, Ordering::SeqCst);
            if self.published_would_allow {
                Ok(Some(org_gate_strict_allow_evidence()))
            } else {
                Ok(None)
            }
        }

        async fn load_org_authorization(
            &self,
            _ctx: &PolicyContext,
        ) -> Result<OrgAuthorityRead, PolicyError> {
            self.org_reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.org_read.clone())
        }

        // 以下均为 legacy 一致性/评估读取器：Disabled/Pending/Ready 分支必须
        // 保持零调用，否则对应断言失败。
        async fn get_projection_gate(
            &self,
            _card_id: i64,
        ) -> Result<Option<ProjectionGate>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        async fn load_snapshot_winners(
            &self,
            _card_id: i64,
        ) -> Result<Vec<SnapshotWinner>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.snapshot_winners.clone())
        }

        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            self.legacy_reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.permission_rules.clone())
        }
    }

    /// 与既有 GateRepo 一致的 BASE 类型级 ALLOW 胜者（learn_subject:* / read）。
    fn org_gate_legacy_allow_winner() -> SnapshotWinner {
        SnapshotWinner {
            ref_type: "BASE".into(),
            rule_set_id: 1,
            resource_key: "learn_subject:*".into(),
            action_code: "read".into(),
            final_effect: "ALLOW".into(),
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
    async fn test_org_gate_disabled_denies_before_legacy_and_strict_evidence() {
        // Disabled：仓库同时声明 strict published-evidence 能力（且预置
        // would-allow 证据）与 legacy L2 ALLOW 规则——若门禁失效，任一路径都会
        // 放行。断言 ORG_AUTHORITY_DISABLED 先于两者短路。
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Disabled, true);
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
            "managed authority cannot fall back to legacy evidence"
        );
        let phases: Vec<&str> = decision
            .evaluation_path
            .iter()
            .map(|s| s.phase.as_str())
            .collect();
        assert_eq!(
            phases,
            vec!["AUTHN", "CARD_CONTEXT", "ORG_AUTHORITY"],
            "Disabled 必须先于 legacy/strict 证据路径短路"
        );
        assert_eq!(repo.org_reads(), 1);
        assert_eq!(
            repo.published_reads(),
            0,
            "Disabled 不得触碰 strict published evidence 读取器"
        );
        assert_eq!(
            repo.legacy_reader_calls(),
            0,
            "Disabled 不得回落 legacy L1/L2 读取器"
        );
    }

    #[tokio::test]
    async fn test_org_gate_pending_fail_closed_without_legacy_fallback() {
        // Pending：稳定 code 原样透传为 ORG_AUTHORITY 步 detail；fail-closed
        // AUTHORIZATION_PENDING，绝不回落 legacy（would-allow 夹具确保回归即失败）。
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(
            OrgAuthorityRead::Pending {
                code: "org_gate.membership_pending".to_owned(),
            },
            true,
        );
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
            "Pending 必须先于 legacy/strict 证据路径短路"
        );
        assert_eq!(repo.org_reads(), 1);
        assert_eq!(repo.published_reads(), 0);
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_org_gate_unmanaged_retains_legacy_route() {
        // Unmanaged：保持既有 legacy 路由行为——既有兼容 ALLOW 夹具
        // （legacy-compatible 无 head + BASE 类型级快照胜者）照常放行，
        // 不因门禁接入而改变既有严格证据假设。
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, false);
        let decision = engine.evaluate(&test_ctx(), &repo).await;
        assert!(
            decision.allowed,
            "Unmanaged 必须保留 legacy 路由: {:?}",
            decision.reason
        );
        assert_eq!(decision.reason, "RULE_SET_ALLOW");
        assert_eq!(repo.org_reads(), 1);
        assert!(
            repo.legacy_reader_calls() >= 1,
            "Unmanaged 必须继续走 legacy 评估链"
        );
        assert_eq!(repo.published_reads(), 0);
    }

    #[tokio::test]
    async fn test_resource_ownership_unresolved_short_circuits_before_org_or_evidence() {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
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
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_resource_ownership_invalid_tenant_scope_short_circuits_before_org_or_evidence() {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
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
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_resource_ownership_non_positive_tenant_scoped_domain_or_owner_short_circuits() {
        for (resource_domain_id, resource_owner_id) in [(Some(0), None), (None, Some(-1))] {
            let engine = PolicyEngine::new();
            let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
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
            assert_eq!(repo.legacy_reader_calls(), 0);
        }
    }

    #[tokio::test]
    async fn test_resource_ownership_invalid_global_scope_short_circuits_before_evidence() {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
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
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_global_target_skips_org_admission_but_keeps_strict_evidence() {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Disabled, true);
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
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_resource_ownership_unavailable_accrues_breaker_failures() {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
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
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_org_gate_unmanaged_foreign_tenant_without_actor_tenant_short_circuits() {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
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
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_org_gate_unmanaged_foreign_tenant_target_short_circuits_strict_evidence() {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
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
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_org_gate_unmanaged_foreign_tenant_target_short_circuits_legacy_evidence() {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, false);
        let mut ctx = strict_ctx();
        ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
        ctx.resource_tenant_id = Some(900);

        let decision = engine.evaluate(&ctx, &repo).await;

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
        assert_eq!(org_gate_last_step(&decision).phase, "RESOURCE_OWNERSHIP");
        assert_eq!(repo.org_reads(), 1);
        assert_eq!(repo.published_reads(), 0);
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_org_gate_unmanaged_same_tenant_target_keeps_strict_evidence_path() {
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Unmanaged, true);
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
        assert_eq!(repo.legacy_reader_calls(), 0);
    }

    #[tokio::test]
    async fn test_org_gate_ready_evidence_allows_via_public_entry() {
        // Ready：公共入口端到端走 org_admission 正式准入——初始读取 +
        // ALLOW 前复读共 2 次 org 读取；legacy L1/L2 与 strict published
        // evidence 都绝不被触碰（Ready 短路整个旧链，不被 legacy 夹具遮蔽）。
        let engine = PolicyEngine::new();
        let grant_id = "00000000-0000-0000-0000-000000000001";
        let repo = OrgGateSwitchRepo::new(
            OrgAuthorityRead::Ready(Box::new(org_gate_admission_evidence())),
            false,
        );
        let decision = engine.evaluate(&org_gate_ctx(), &repo).await;
        assert!(
            decision.allowed,
            "Ready ORG 证据应经公共入口放行: {:?}",
            decision.reason
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
        assert_eq!(repo.org_reads(), 2, "Ready 需要初始读取 + ALLOW 前复读");
        assert_eq!(repo.legacy_reader_calls(), 0);
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

        async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
            // 首次校验是门禁前的 CARD_CONTEXT，必须成功；仅 admission 内的
            // 终局校验按预设失败，保证评估命中 Ready 分支内部失败点。
            let check_index = self.card_checks.fetch_add(1, Ordering::SeqCst);
            if self.card_active_err && check_index > 0 {
                Err(PolicyError::Repository("card_context_read_failed".into()))
            } else {
                Ok(true)
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
        // Err：org 权威读取不可用必须累计断路器失败并打开断路器（修复核心）。
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

        // 每次失败评估都恰好记账一次（layer=ORG_AUTHORITY → 保守 l3 桶）。
        let stats = engine.get_stats();
        assert_eq!(stats.l3_hits, crate::circuit_breaker::CB_THRESHOLD as u64);
        assert_eq!(stats.l1_hits, 0);
        assert_eq!(stats.l2_hits, 0);
        assert!(stats.timing_ns.total_ns > 0);
    }

    #[tokio::test]
    async fn test_org_gate_unavailable_accrues_breaker_failures_and_opens() {
        // Unavailable is an explicit fail-closed infrastructure outcome, distinct
        // from a completed business Pending read. It must therefore affect the
        // breaker exactly like an Err rather than being laundered into success.
        let engine = PolicyEngine::new();
        let repo = OrgGateSwitchRepo::new(
            OrgAuthorityRead::Unavailable {
                code: "org_scope.pending.reader_unavailable".into(),
            },
            true,
        );
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
        assert_eq!(repo.legacy_reader_calls(), 0);

        let stats = engine.get_stats();
        assert_eq!(stats.l3_hits, crate::circuit_breaker::CB_THRESHOLD as u64);
        assert_eq!(stats.l1_hits, 0);
        assert_eq!(stats.l2_hits, 0);
    }

    #[tokio::test]
    async fn test_org_gate_disabled_records_success_not_failure() {
        // Disabled：确定性管理态关闭 → 记成功 + 记账恰好一次。
        // 模式：阈值-1 次 Err 失败 → 被测评估（记成功则清零计数）→ 1 次 Err
        // 失败；若被测评估未记成功，最后一次失败会到阈值并打开断路器。
        let engine = PolicyEngine::new();
        seed_breaker_failures_below_threshold(&engine).await;
        let repo = OrgGateSwitchRepo::new(OrgAuthorityRead::Disabled, true);
        let decision = engine.evaluate(&strict_ctx(), &repo).await;
        assert_eq!(decision.reason, "ORG_AUTHORITY_DISABLED");
        let tail = OrgGateErrRepo::new();
        engine.evaluate(&strict_ctx(), &tail).await;
        assert_eq!(
            engine.circuit_breaker_state(),
            CircuitBreakerState::Closed,
            "Disabled 必须记成功（清零失败计数），不得记依赖失败"
        );
        // 记账恰好一次：阈值-1（Err 预热）+ 1（Disabled）+ 1（Err 收尾）。
        let stats = engine.get_stats();
        assert_eq!(
            stats.l3_hits,
            crate::circuit_breaker::CB_THRESHOLD as u64 + 1
        );
        assert_eq!(stats.l1_hits, 0);
        assert_eq!(stats.l2_hits, 0);
        assert!(stats.timing_ns.total_ns > 0);
    }

    #[tokio::test]
    async fn test_org_gate_pending_records_success_not_failure() {
        // Pending：读取已成功（Ok），业务 pending 是确定性授权结果 → 记成功。
        let engine = PolicyEngine::new();
        seed_breaker_failures_below_threshold(&engine).await;
        let repo = OrgGateSwitchRepo::new(
            OrgAuthorityRead::Pending {
                code: "org_gate.membership_pending".into(),
            },
            true,
        );
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
            stats.l3_hits,
            crate::circuit_breaker::CB_THRESHOLD as u64 + 1
        );
        assert_eq!(stats.l1_hits, 0);
        assert_eq!(stats.l2_hits, 0);
    }

    #[tokio::test]
    async fn test_org_gate_ready_allow_records_success_and_evaluation() {
        // Ready ALLOW：确定性授权结果 → 记成功，且记账恰好一次。
        let engine = PolicyEngine::new();
        seed_breaker_failures_below_threshold(&engine).await;
        let repo = OrgGateSwitchRepo::new(
            OrgAuthorityRead::Ready(Box::new(org_gate_admission_evidence())),
            false,
        );
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
            stats.l3_hits,
            crate::circuit_breaker::CB_THRESHOLD as u64 + 1
        );
        assert_eq!(stats.l1_hits, 0);
        assert_eq!(stats.l2_hits, 0);
        assert!(stats.timing_ns.total_ns > 0);
    }

    #[tokio::test]
    async fn test_org_gate_ready_default_deny_records_success_not_failure() {
        // Ready 分支的正常 DEFAULT_DENY（无匹配贡献）是确定性授权结果，
        // 绝不能记为依赖失败。
        let engine = PolicyEngine::new();
        seed_breaker_failures_below_threshold(&engine).await;
        let repo = OrgGateSwitchRepo::new(
            OrgAuthorityRead::Ready(Box::new(org_gate_admission_evidence())),
            false,
        );
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
            stats.l3_hits,
            crate::circuit_breaker::CB_THRESHOLD as u64 + 1
        );
        assert_eq!(stats.l1_hits, 0);
        assert_eq!(stats.l2_hits, 0);
    }

    #[tokio::test]
    async fn test_org_gate_ready_identity_drift_records_success_not_failure() {
        // 复读身份漂移（final_identity_changed）是确定性复检拒绝 → 记成功。
        let engine = PolicyEngine::new();
        seed_breaker_failures_below_threshold(&engine).await;
        let mut drifted = org_gate_admission_evidence();
        drifted.membership.revision += 1;
        let repo =
            OrgGateReadyProbeRepo::new(Some(OrgAuthorityRead::Ready(Box::new(drifted))), false);
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
            stats.l3_hits,
            crate::circuit_breaker::CB_THRESHOLD as u64 + 1
        );
        assert_eq!(stats.l1_hits, 0);
        assert_eq!(stats.l2_hits, 0);
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
            // 每次失败评估都恰好记账一次（layer=ORG_AUTHORITY → 保守 l3 桶）。
            let stats = engine.get_stats();
            assert_eq!(
                stats.l3_hits,
                crate::circuit_breaker::CB_THRESHOLD as u64,
                "{label}"
            );
            assert_eq!(stats.l1_hits, 0, "{label}");
            assert_eq!(stats.l2_hits, 0, "{label}");
        }
    }
}
