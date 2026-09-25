//! 卡资格校验服务契约类型
//!
//! 供签发层（identity login / refresh / switch-card）与运行期（Chat / PolicyEngine）
//! 共享的公共卡资格契约。物理双卡模型下：
//! - `identity_card`（身份卡）只承担身份事实（归属/状态/过期），**不承担** tenant/domain；
//! - `user_card`（用户卡）独立承载授权事实（状态/有效期/tenant/domain）。
//!
//! 权威校验实现见 `astral-db::CardEligibilityService`。

/// 平台双卡对校验请求。
///
/// 三个 ID 必须来自同一次认证：`identity_card.user_id == user_card.user_id == user_id`，
/// 由权威 JOIN 的对应关系证明保证（详见 `astral-db::CardEligibilityService`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformCardPairRequest {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
}

impl PlatformCardPairRequest {
    /// 所有字段必须为正，避免 0/NULL 幻值进入权威查询。
    pub fn is_positive(&self) -> bool {
        self.user_id > 0 && self.identity_card_id > 0 && self.user_card_id > 0
    }
}

/// 卡资格校验结果（通过即携带签发所需的组织事实）。
///
/// `effective_expiry` 为自然到期时间（unix 秒，`min(identity.expires_at, user_card.valid_until)`），
/// 用于写入时间感知缓存并做读取侧到期截断；None 表示两卡均无到期时间。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardEligibility {
    pub identity_card_id: i64,
    pub user_card_id: i64,
    /// 组织事实唯一来源：user_card 的 tenant/domain（身份卡不承担组织事实）。
    pub user_card_tenant_id: i64,
    pub user_card_domain_id: i64,
    pub effective_expiry: Option<i64>,
}

/// 运行期资格缓存检查选项。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardEligibilityCheckOptions {
    /// 缓存基础 TTL（秒）。
    pub base_ttl_seconds: u64,
    /// TTL 抖动上限（秒），防止缓存雪崩。
    pub jitter_max_seconds: u64,
    /// `true` 时 ELIGIBILITY 投影 head 未 READY 直接拒绝（Chat 短 TTL 语义）；
    /// `false` 时未 READY 只导致缓存 miss，不影响权威 SQL 结果（PolicyEngine 语义）。
    pub require_projection_ready: bool,
}

impl Default for CardEligibilityCheckOptions {
    fn default() -> Self {
        Self {
            base_ttl_seconds: 300,
            jitter_max_seconds: 60,
            require_projection_ready: false,
        }
    }
}
