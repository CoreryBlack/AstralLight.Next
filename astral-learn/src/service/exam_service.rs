//! 考试提交编排 — ExamService
//!
//! 对齐 Java `ExamServiceImpl.submitExam`：计分 passed = score >= 60
//! （阈值常量 60）；状态标记 SUBMITTED（原 handler 吞错，此处告警不阻断）。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::exam_repository::ExamRepository;

/// 及格阈值（对齐 Java ExamService 常量）
pub const PASS_THRESHOLD: i32 = 60;

/// 考试提交结果
#[derive(Debug, Clone)]
pub struct ExamSubmitOutcome {
    pub exam_id: i64,
    pub user_id: i64,
    pub score: i32,
    pub passed: bool,
}

/// ExamService（依赖注入 repository）
pub struct ExamService {
    repo: Arc<dyn ExamRepository>,
}

impl ExamService {
    pub fn new(repo: Arc<dyn ExamRepository>) -> Self {
        Self { repo }
    }

    /// Exam question/result storage is absent from the supported Learn schema.
    /// Never accept a client score or mark an exam submitted without a durable,
    /// server-scored result record.
    pub async fn submit_exam(
        &self,
        _exam_id: i64,
        _user_id: i64,
        _score: i32,
    ) -> Result<ExamSubmitOutcome, AstralError> {
        Err(AstralError::NotImplemented(
            "Exam submissions require a durable server-scored result model".into(),
        ))
    }

    /// 考试是否存在（submit_exam_app 前置校验）
    pub async fn exists(&self, exam_id: i64) -> Result<bool, AstralError> {
        self.repo.exists(exam_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::exam_repository::{ExamInfoRecord, ExamInput, ExamRecord};
    use async_trait::async_trait;

    struct FakeExamRepository;

    #[async_trait]
    impl ExamRepository for FakeExamRepository {
        async fn count_all(&self) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_all(
            &self,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<ExamRecord>, AstralError> {
            Ok(vec![])
        }

        async fn get(&self, _id: i64) -> Result<Option<ExamRecord>, AstralError> {
            Ok(None)
        }

        async fn create(&self, _input: &ExamInput) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn update(&self, _id: i64, _input: &ExamInput) -> Result<(), AstralError> {
            Ok(())
        }

        async fn archive(&self, _id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn exists(&self, _id: i64) -> Result<bool, AstralError> {
            Ok(true)
        }

        async fn mark_submitted(&self, _id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn get_info(&self, _id: i64) -> Result<Option<ExamInfoRecord>, AstralError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn submit_exam_is_explicitly_not_implemented_without_result_model() {
        let repo = Arc::new(FakeExamRepository);
        let svc = ExamService::new(repo.clone());
        let error = svc.submit_exam(1, 7, 100).await.unwrap_err();
        assert!(matches!(error, AstralError::NotImplemented(_)));
    }
}
