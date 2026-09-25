//! 等级模板编排 — LevelTemplateService
//!
//! delete 的级联清理 + 逐卡快照重建编排（对齐 Java 删除语义）。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::level_template_repository::{
    DeleteOutcome, LevelTemplateMutationContext, LevelTemplateRepository,
};
use crate::service::side_effect::PermissionSideEffects;

/// 删除结果（供 handler 组装响应）
#[derive(Debug, Clone)]
pub struct DeleteResult {
    pub deleted: bool,
    pub affected_card_ids: Vec<i64>,
}

/// LevelTemplateService
pub struct LevelTemplateService {
    repo: Arc<dyn LevelTemplateRepository>,
    side_effects: Arc<dyn PermissionSideEffects>,
}

impl LevelTemplateService {
    pub fn new(
        repo: Arc<dyn LevelTemplateRepository>,
        side_effects: Arc<dyn PermissionSideEffects>,
    ) -> Self {
        Self { repo, side_effects }
    }

    /// 删除等级模板：级联清理两表 + 删除 + 逐卡重建快照。
    ///
    /// `context` 是 handler 提供的可信 actor/operation 身份，原样透传给
    /// repository 的授权 mutation 事务（CARD REVOKE metadata + 同事务审计关联）；
    /// 身份缺失或非法由 repository fail-closed，service 不做任何回退。
    pub async fn delete(
        &self,
        id: i64,
        context: &LevelTemplateMutationContext,
    ) -> Result<DeleteResult, AstralError> {
        let DeleteOutcome {
            deleted,
            affected_card_ids,
        } = self.repo.delete_with_cascade(id, context).await?;

        // SQLx 聚合已在删除事务内登记 REVOKE；旧 repository 仍走兼容补偿路径。
        if !self.repo.writes_projection_in_transaction() {
            for card_id in &affected_card_ids {
                self.side_effects
                    .request_card_projection(*card_id, "REVOKE")
                    .await?;
            }
        }

        tracing::warn!(
            id,
            affected_cards = affected_card_ids.len(),
            "level template deleted with cascade"
        );

        Ok(DeleteResult {
            deleted,
            affected_card_ids,
        })
    }
}
