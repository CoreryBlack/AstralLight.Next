//! 评估层共享 DTO（投影门禁快照、规则/规则集条目、快照胜者等）。

use astral_types::Effect;

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
