//! Level-template governance mutation orchestration.
//!
//! Level-template source changes are audited, but do not create authorization
//! projection deltas; they are not canonical grant sources.

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::level_template_repository::{
    DeleteOutcome, LevelTemplateMutationContext, LevelTemplateRepository,
};

/// 删除结果（供 handler 组装响应）
#[derive(Debug, Clone)]
pub struct DeleteResult {
    pub deleted: bool,
    pub affected_card_ids: Vec<i64>,
}

/// LevelTemplateService
pub struct LevelTemplateService {
    repo: Arc<dyn LevelTemplateRepository>,
}

impl LevelTemplateService {
    pub fn new(repo: Arc<dyn LevelTemplateRepository>) -> Self {
        Self { repo }
    }

    /// Delete a level template and its dependent governance rows.
    ///
    /// `context` is the trusted actor/operation identity supplied by the handler;
    /// the repository persists it with the source mutation audit correlation.
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
