//! 权限投影聚合类型与投影事件常量（无基础设施依赖）
//!
//! durable 投影（`authorization_projection_head` + `authorization_projection_outbox`）
//! 以 `aggregate_type` 区分通道。本模块是聚合类型与事件类型常量的唯一事实源，
//! 避免各写路径/worker 散落裸字符串。不依赖数据库、缓存、MQ 等外部基础设施。

use std::fmt;
use std::str::FromStr;

/// 权限投影聚合类型（`authorization_projection_head`/`authorization_projection_outbox`
/// 的 `aggregate_type` 取值，DB 存储为大写字符串）。
///
/// 每个聚合在 head 表独立维护 source/projected 代次与 REVOKE 围栏：
/// - `Card`（`CARD`）：user_card 授权投影。durable worker 全量重建规则快照 +
///   完整 CARD 缓存 evict + 发布 CARD permission.refresh。
/// - `Eligibility`（`ELIGIBILITY`）：资格状态投影。durable worker 仅失效
///   `perm:card:active:{id}` 资格缓存，不重建规则快照、不清理规则快照、
///   不发布 CARD refresh；资格读侧通过 ELIGIBILITY gate 的版本检查放行。
/// - `RuleSet`（`RULE_SET`）：规则集投影。聚合 id 为 `rule_set.rule_set_id`，
///   tenant/payload source 取 `rule_set`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionAggregate {
    Card,
    Eligibility,
    RuleSet,
}

impl ProjectionAggregate {
    /// CARD 聚合的 DB 存储值
    pub const CARD: &'static str = "CARD";
    /// ELIGIBILITY 聚合的 DB 存储值
    pub const ELIGIBILITY: &'static str = "ELIGIBILITY";
    /// RULE_SET 聚合的 DB 存储值
    pub const RULE_SET: &'static str = "RULE_SET";

    /// 已知聚合全集（供遍历/校验）
    pub const ALL: &'static [ProjectionAggregate] = &[
        ProjectionAggregate::Card,
        ProjectionAggregate::Eligibility,
        ProjectionAggregate::RuleSet,
    ];

    /// DB 存储值（与 `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` 输出一致）
    pub fn as_str(self) -> &'static str {
        match self {
            ProjectionAggregate::Card => Self::CARD,
            ProjectionAggregate::Eligibility => Self::ELIGIBILITY,
            ProjectionAggregate::RuleSet => Self::RULE_SET,
        }
    }

    /// 从 DB 存储值解析聚合类型；未知值返回 `None`。
    ///
    /// worker 对未知聚合必须 fail-closed/retry（绝不当作成功 mark processed），
    /// 以阻止未注册通道的事件静默吞掉。
    pub fn parse_static(value: &str) -> Option<Self> {
        match value {
            Self::CARD => Some(ProjectionAggregate::Card),
            Self::ELIGIBILITY => Some(ProjectionAggregate::Eligibility),
            Self::RULE_SET => Some(ProjectionAggregate::RuleSet),
            _ => None,
        }
    }
}

/// 解析 `ProjectionAggregate` 失败（未知 aggregate_type）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownProjectionAggregate(pub String);

impl fmt::Display for UnknownProjectionAggregate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown projection aggregate_type: '{}'", self.0)
    }
}

impl std::error::Error for UnknownProjectionAggregate {}

impl FromStr for ProjectionAggregate {
    type Err = UnknownProjectionAggregate;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_static(value).ok_or_else(|| UnknownProjectionAggregate(value.to_string()))
    }
}

impl fmt::Display for ProjectionAggregate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Aggregate identities accepted by the published-card evidence reader.
///
/// These are deliberately distinct from [`ProjectionAggregate`], which names
/// the head/outbox worker channels (`CARD`, `ELIGIBILITY`, `RULE_SET`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublishedEvidenceAggregate {
    UserCard,
    RuleSet,
    Approval,
    Delegation,
}

impl PublishedEvidenceAggregate {
    pub const USER_CARD: &'static str = "USER_CARD";
    pub const RULE_SET: &'static str = "RULE_SET";
    pub const APPROVAL: &'static str = "APPROVAL";
    pub const DELEGATION: &'static str = "DELEGATION";

    pub const ALL: &'static [Self] = &[
        Self::UserCard,
        Self::RuleSet,
        Self::Approval,
        Self::Delegation,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserCard => Self::USER_CARD,
            Self::RuleSet => Self::RULE_SET,
            Self::Approval => Self::APPROVAL,
            Self::Delegation => Self::DELEGATION,
        }
    }

    pub fn parse_static(value: &str) -> Option<Self> {
        match value {
            Self::USER_CARD => Some(Self::UserCard),
            Self::RULE_SET => Some(Self::RuleSet),
            Self::APPROVAL => Some(Self::Approval),
            Self::DELEGATION => Some(Self::Delegation),
            _ => None,
        }
    }
}

impl fmt::Display for PublishedEvidenceAggregate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 投影事件类型常量（对齐 Java `PermissionRefreshEventType`）。
///
/// 事件类型的语义在各聚合通道一致：
/// - `REVOKE` 是唯一递增 head `revoke_fence` 围栏的事件（consumer 用其判断消息是否过期）。
pub const EVENT_TYPE_REVOKE: &str = "REVOKE";
/// 规则集更新事件（对绑定卡触发 CARD 投影）
pub const EVENT_TYPE_RULE_SET_UPDATE: &str = "RULE_SET_UPDATE";
/// 卡片信息更新事件
pub const EVENT_TYPE_CARD_UPDATE: &str = "CARD_UPDATE";
/// 资格状态变更事件（ELIGIBILITY 通道；worker 仅失效资格缓存）
pub const EVENT_TYPE_ELIGIBILITY_UPDATE: &str = "ELIGIBILITY_UPDATE";

/// Explicit actor for genuinely system-initiated startup/migration operations.
/// HTTP request paths must always carry a positive Gateway-verified user id.
pub const SYSTEM_ACTOR_ID: i64 = -1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_as_str_and_parse_round_trip() {
        for aggregate in ProjectionAggregate::ALL {
            assert_eq!(
                ProjectionAggregate::parse_static(aggregate.as_str()),
                Some(*aggregate)
            );
            assert_eq!(aggregate.to_string(), aggregate.as_str());
        }
        assert_eq!(ProjectionAggregate::Card.as_str(), "CARD");
        assert_eq!(ProjectionAggregate::Eligibility.as_str(), "ELIGIBILITY");
        assert_eq!(ProjectionAggregate::RuleSet.as_str(), "RULE_SET");
    }

    #[test]
    fn unknown_aggregate_rejected() {
        assert_eq!(ProjectionAggregate::parse_static("WIDGET"), None);
        assert_eq!(ProjectionAggregate::parse_static("card"), None); // 大小写敏感
        let error = ProjectionAggregate::from_str("WIDGET").unwrap_err();
        assert!(error.to_string().contains("WIDGET"));
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn aggregate_serde_uses_screaming_snake_case() {
        assert_eq!(
            serde_json::to_string(&ProjectionAggregate::Card).unwrap(),
            "\"CARD\""
        );
        assert_eq!(
            serde_json::to_string(&ProjectionAggregate::Eligibility).unwrap(),
            "\"ELIGIBILITY\""
        );
        assert_eq!(
            serde_json::to_string(&ProjectionAggregate::RuleSet).unwrap(),
            "\"RULE_SET\""
        );
        let parsed: ProjectionAggregate = serde_json::from_str("\"ELIGIBILITY\"").unwrap();
        assert_eq!(parsed, ProjectionAggregate::Eligibility);
        let parsed: ProjectionAggregate = serde_json::from_str("\"RULE_SET\"").unwrap();
        assert_eq!(parsed, ProjectionAggregate::RuleSet);
    }

    #[test]
    fn published_evidence_aggregate_contract_is_closed_and_wire_stable() {
        let expected = [
            (PublishedEvidenceAggregate::UserCard, "USER_CARD"),
            (PublishedEvidenceAggregate::RuleSet, "RULE_SET"),
            (PublishedEvidenceAggregate::Approval, "APPROVAL"),
            (PublishedEvidenceAggregate::Delegation, "DELEGATION"),
        ];
        for (aggregate, wire) in expected {
            assert_eq!(aggregate.as_str(), wire);
            assert_eq!(
                PublishedEvidenceAggregate::parse_static(wire),
                Some(aggregate)
            );
            assert_eq!(
                serde_json::to_string(&aggregate).unwrap(),
                format!("\"{wire}\"")
            );
        }
        assert_eq!(PublishedEvidenceAggregate::parse_static("CARD"), None);
        assert_eq!(PublishedEvidenceAggregate::parse_static("WIDGET"), None);
    }

    #[test]
    fn event_type_constants_stable() {
        assert_eq!(EVENT_TYPE_REVOKE, "REVOKE");
        assert_eq!(EVENT_TYPE_RULE_SET_UPDATE, "RULE_SET_UPDATE");
        assert_eq!(EVENT_TYPE_CARD_UPDATE, "CARD_UPDATE");
        assert_eq!(EVENT_TYPE_ELIGIBILITY_UPDATE, "ELIGIBILITY_UPDATE");
        // 仅 REVOKE 递增围栏（对齐 Java isObsoleteVersionedCardRefresh）
        assert_ne!(EVENT_TYPE_CARD_UPDATE, EVENT_TYPE_REVOKE);
        assert_ne!(EVENT_TYPE_RULE_SET_UPDATE, EVENT_TYPE_REVOKE);
    }
}
