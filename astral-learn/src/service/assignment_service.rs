//! 作业编排 — AssignmentService
//!
//! 对齐 Java `AssignmentServiceImpl`：提交（ON DUPLICATE KEY UPDATE 幂等）、
//! 批改、课程统计。授权（require_same_user）保留在 handler。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::assignment_repository::AssignmentRepository;
use crate::srv::assignments::Submission;

/// AssignmentService（依赖注入 repository）
pub struct AssignmentService {
    repo: Arc<dyn AssignmentRepository>,
}

impl AssignmentService {
    pub fn new(repo: Arc<dyn AssignmentRepository>) -> Self {
        Self { repo }
    }

    /// 提交作业（幂等 upsert；重复提交 last_insert_id 可能为 0，保留原语义）
    pub async fn submit_assignment(
        &self,
        assignment_id: i64,
        user_id: i64,
        content: String,
    ) -> Result<Submission, AstralError> {
        let id = self
            .repo
            .submit_assignment(assignment_id, user_id, &content)
            .await?;
        Ok(Submission {
            id,
            assignment_id,
            user_id,
            content: Some(content),
            score: None,
            graded: 0,
        })
    }

    /// 批改（assignment_id + user_id 定位）
    pub async fn grade_submission(
        &self,
        assignment_id: i64,
        user_id: i64,
        score: f64,
    ) -> Result<(), AstralError> {
        self.repo
            .grade_submission(assignment_id, user_id, score)
            .await
    }
}
