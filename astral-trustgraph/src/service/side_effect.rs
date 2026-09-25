//! 快照/缓存副作用执行器 — PermissionSideEffects
//!
//! 把 `side_effects.rs` 的编排函数封装为可注入依赖，service 层通过该 trait
//! 触发 durable 投影事件、快照重建与缓存失效；生产实现走 `SqlxPermissionSideEffects`，
//! 测试注入 no-op 记录器，避免连接真实 DB。
//!
//! 批 A 后写路径语义：source mutation 后调用 `request_card_projection` 落 durable 事件
//! （不再同步 rebuild），由 `projection_worker` 统一重建快照并失效缓存。

use async_trait::async_trait;
use sqlx::MySqlPool;

use crate::api::side_effects;

/// 写路径副作用端口（durable 投影事件 + 兼容保留的快照重建/缓存失效）
#[async_trait]
pub trait PermissionSideEffects: Send + Sync {
    /// 卡片授权变更落 durable 投影事件（head 递增 + outbox PENDING）。
    /// `event_type == "REVOKE"` 时 revoke_fence 递增（对齐 Java PermissionRefreshService）。
    async fn request_card_projection(
        &self,
        card_id: i64,
        event_type: &str,
    ) -> Result<(), astral_types::AstralError>;
    async fn rebuild_card_snapshot(&self, card_id: i64);
    async fn rebuild_rule_set_snapshot(
        &self,
        rule_set_id: i64,
    ) -> Result<(), astral_types::AstralError>;
    /// 清除卡片级缓存（user_cards delete 后 post-commit 使用）
    async fn evict_card_cache(&self, card_id: i64);
}

/// 生产实现：durable 事件委托 `ProjectionRepository`，其余委托 `side_effects.rs`
pub struct SqlxPermissionSideEffects {
    db: MySqlPool,
}

impl SqlxPermissionSideEffects {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl PermissionSideEffects for SqlxPermissionSideEffects {
    async fn request_card_projection(
        &self,
        card_id: i64,
        event_type: &str,
    ) -> Result<(), astral_types::AstralError> {
        side_effects::request_card_projection(&self.db, card_id, event_type).await
    }

    async fn rebuild_card_snapshot(&self, card_id: i64) {
        side_effects::rebuild_card_snapshot(&self.db, card_id).await;
    }

    async fn rebuild_rule_set_snapshot(
        &self,
        rule_set_id: i64,
    ) -> Result<(), astral_types::AstralError> {
        side_effects::rebuild_rule_set_snapshot(&self.db, rule_set_id).await
    }

    async fn evict_card_cache(&self, card_id: i64) {
        side_effects::evict_card_cache(card_id).await;
    }
}
