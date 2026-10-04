//! 授权数据读取端口（`RuleRepository`）。
//!
//! 引擎通过本 trait 获取数据，不直接访问数据库；生产实现见 astral-db
//! `SqlxRuleRepository`，strict published evidence 语义见 trait 文档。

use astral_types::{
    PolicyContext, PolicyError, PublishedCardAuthorization, PublishedCardEvidenceScope,
};

use super::types::*;

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
