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

    /// ELIGIBILITY 失效意图接缝（**默认显式未接线，fail-closed**）。
    ///
    /// 语义合同（对齐《Rust内存权威读面与失效通道架构方案_V0.1》§6/§7 与
    /// AGENTS §3.2：凡影响有效授权的 source mutation 必须进入 durable source
    /// path，ELIGIBILITY 走其自身记录的资格/缓存失效路径，不能被遗漏）：
    /// 源资格变化（user_card 状态/删除等）需要把 **durable invalidation
    /// intent 与 source mutation 写入同一 source 事务**，并在 commit 后触发
    /// dispatch（进程内 `astral_db::evict_l1_card_active_cache(card_id)` 已由
    /// 既有 evict 家族与 projection_worker ELIGIBILITY 通道承担；跨节点由
    /// 失效通知通道 `ELIGIBILITY_INVALIDATED { card_id }` 承担）。
    ///
    /// **默认实现返回 `Err`**：在 source mutation owner（独立切片，经主
    /// Agent 请求钩子接线）完成同事务落盘之前，任何调用方得到的是显式失败
    /// 而不是"失效已完成"的伪证明——绝不静默减少 contract。接线方必须在
    /// `SqlxPermissionSideEffects` 覆写本方法并把调用点放进 source 事务边界。
    async fn dispatch_eligibility_invalidation_intent(
        &self,
        card_id: i64,
    ) -> Result<(), astral_types::AstralError> {
        let _ = card_id;
        Err(astral_types::AstralError::Internal(
            "code=eligibility_invalidation.intent_seam_unwired; \
             durable invalidation intent must be written in the same source \
             transaction by the source-mutation owner before dispatch"
                .into(),
        ))
    }
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

    // `dispatch_eligibility_invalidation_intent` 保持 trait 默认实现（显式
    // Err，见 trait 文档）：durable invalidation intent 的同事务落盘由 source
    // mutation owner 接线（经主 Agent 请求钩子；本切片不越权写
    // api/side_effects.rs / repository 层文件）。
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 接缝默认态 fail-closed：生产实现（lazy 池构造，不触真实 DB）在 source
    /// owner 接线前必须显式报"未接线"，绝不伪报"失效已完成"。
    #[tokio::test]
    async fn eligibility_invalidation_intent_seam_is_fail_closed_until_wired() {
        let pool = MySqlPool::connect_lazy("mysql://user:pass@127.0.0.1:1/none")
            .expect("lazy pool must construct without connecting");
        let effects = SqlxPermissionSideEffects::new(pool);
        let error = effects
            .dispatch_eligibility_invalidation_intent(42)
            .await
            .expect_err("unwired seam must fail closed");
        assert!(
            error.to_string().contains("intent_seam_unwired"),
            "error must carry the stable seam code, got: {error}"
        );
    }

    /// 依赖本 trait 的既有测试 mock（RecordingSideEffects 家族）未覆写接缝时
    /// 仍可编译并继承 fail-closed 默认态（contract 不被静默减少）。
    struct SeamInheritingSideEffects;

    #[async_trait]
    impl PermissionSideEffects for SeamInheritingSideEffects {
        async fn request_card_projection(
            &self,
            _card_id: i64,
            _event_type: &str,
        ) -> Result<(), astral_types::AstralError> {
            Ok(())
        }
        async fn rebuild_card_snapshot(&self, _card_id: i64) {}
        async fn rebuild_rule_set_snapshot(
            &self,
            _rule_set_id: i64,
        ) -> Result<(), astral_types::AstralError> {
            Ok(())
        }
        async fn evict_card_cache(&self, _card_id: i64) {}
    }

    #[tokio::test]
    async fn inheriting_implementors_get_the_fail_closed_default() {
        let error = SeamInheritingSideEffects
            .dispatch_eligibility_invalidation_intent(7)
            .await
            .expect_err("inherited default must stay fail-closed");
        assert!(error.to_string().contains("intent_seam_unwired"));
    }
}
