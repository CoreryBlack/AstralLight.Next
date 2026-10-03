//! 用户卡编排 — UserCardService
//!
//! create/restore/bind 的 durable 投影事件编排；delete 级联事务在 repository。
//! delete 后 post-commit evict 对齐 Java 语义。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::user_card_repository::{
    DeleteCascadeResult, NewUserCard, UserCardPatch, UserCardRecord, UserCardRepository,
};
use crate::service::side_effect::PermissionSideEffects;

/// UserCardService
pub struct UserCardService {
    repo: Arc<dyn UserCardRepository>,
    side_effects: Arc<dyn PermissionSideEffects>,
}

impl UserCardService {
    pub fn new(
        repo: Arc<dyn UserCardRepository>,
        side_effects: Arc<dyn PermissionSideEffects>,
    ) -> Self {
        Self { repo, side_effects }
    }

    /// 创建卡（含模板规则集绑定）→ 落 durable 投影事件，返回卡
    pub async fn create_card(&self, new: &NewUserCard) -> Result<UserCardRecord, AstralError> {
        let new_id = self.repo.create_card(new).await?;
        let row = self.repo.get_card(new_id).await?.ok_or_else(|| {
            AstralError::Database(format!("user_card {new_id} not found after insert"))
        })?;
        tracing::info!(card_id = new_id, user_id = ?new.user_id, "user card created");
        Ok(row)
    }

    /// 更新卡（部分字段）
    ///
    /// 状态变更（禁用/挂起等离开 ACTIVE）是对有效授权的 source mutation：
    /// 落 durable 投影事件（REVOKE 语义，围栏递增）+ 清理 `perm:card:active` 缓存，
    /// 否则 `check_card_active` 正缓存命中会放行最长 ~300s（对齐 Java 用户卡状态回收）。
    pub async fn update_card(
        &self,
        card_id: i64,
        patch: &UserCardPatch,
    ) -> Result<(), AstralError> {
        self.repo.update_card(card_id, patch).await?;
        // Repository 已将 source mutation 与 projection append 放入同一事务。
        // 这里仅清理运行时状态缓存，不再重复追加 head/outbox 事件。
        self.side_effects.evict_card_cache(card_id).await;
        Ok(())
    }

    /// 删除卡（级联事务）→ post-commit evict 缓存 + 落 durable 投影事件（对齐 Java evictCardCache）
    pub async fn delete_card(&self, card_id: i64) -> Result<DeleteCascadeResult, AstralError> {
        let result = self.repo.delete_with_cascade(card_id).await?;
        self.side_effects.evict_card_cache(card_id).await;
        tracing::warn!(
            card_id,
            permission_rule_deleted = result.permission_rule_deleted,
            snapshot_deleted = result.snapshot_deleted,
            rule_set_ref_deleted = result.rule_set_ref_deleted,
            "user card deleted (soft) + cascade cleanup"
        );
        Ok(result)
    }

    /// 恢复已删除卡 → 落 durable 投影事件
    pub async fn restore_card(&self, card_id: i64) -> Result<UserCardRecord, AstralError> {
        let restored = self.repo.restore_card(card_id).await?;
        if !restored {
            return Err(AstralError::NotFound(format!(
                "user_card {card_id} (not found or not in DISABLED status)"
            )));
        }
        let row = self.repo.get_card(card_id).await?.ok_or_else(|| {
            AstralError::Database(format!("user_card {card_id} not found after restore"))
        })?;
        tracing::info!(card_id, "user card restored");
        Ok(row)
    }

    /// 绑定单卡 → 落 durable 投影事件
    pub async fn bind_card(
        &self,
        card_id: i64,
        user_id: i64,
    ) -> Result<UserCardRecord, AstralError> {
        let bound = self.repo.bind_card(card_id, user_id).await?;
        if !bound {
            return Err(AstralError::NotFound(format!(
                "user_card {card_id} (not found or deleted)"
            )));
        }
        let row = self.repo.get_card(card_id).await?.ok_or_else(|| {
            AstralError::Database(format!("user_card {card_id} not found after bind"))
        })?;
        tracing::info!(card_id, user_id, "user card bound");
        Ok(row)
    }

    /// 异步绑定单卡（PENDING/INACTIVE → ACTIVE），命中才落 durable 投影事件。
    /// 卡不在可绑定状态（返回 false）时返回明确错误，避免异步 batch tracker
    /// 把失败计为完成（对齐 `bind_card` 的 not-found 语义）。
    pub async fn bind_card_async_one(&self, card_id: i64, user_id: i64) -> Result<(), AstralError> {
        let bound = self.repo.bind_card_async_one(card_id, user_id).await?;
        if !bound {
            return Err(AstralError::NotFound(format!(
                "user card {card_id} is not in a bindable state (PENDING/INACTIVE)"
            )));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn bind_card_async_batch_item(
        &self,
        card_id: i64,
        user_id: i64,
        actor_id: i64,
        actor_card_id: i64,
        actor_tenant_id: i64,
        actor_domain_id: i64,
        task_id: &str,
        operation_id: &str,
        expected_tenant_id: i64,
        expected_domain_id: i64,
    ) -> Result<(), AstralError> {
        let bound = self
            .repo
            .bind_card_async_batch_item(
                card_id,
                user_id,
                actor_id,
                actor_card_id,
                actor_tenant_id,
                actor_domain_id,
                task_id,
                operation_id,
                expected_tenant_id,
                expected_domain_id,
            )
            .await?;
        if !bound {
            return Err(AstralError::NotFound(format!(
                "user card {card_id} is not in a bindable state (PENDING/INACTIVE)"
            )));
        }
        Ok(())
    }
}
