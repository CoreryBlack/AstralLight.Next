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

    /// 提交考试：标记 SUBMITTED（失败仅告警，对齐原 handler .ok() 吞错）+ 计分
    pub async fn submit_exam(
        &self,
        exam_id: i64,
        user_id: i64,
        score: i32,
    ) -> Result<ExamSubmitOutcome, AstralError> {
        if let Err(e) = self.repo.mark_submitted(exam_id).await {
            tracing::warn!(exam_id, error = %e, "mark exam submitted failed (non-critical)");
        }
        Ok(ExamSubmitOutcome {
            exam_id,
            user_id,
            score,
            passed: score >= PASS_THRESHOLD,
        })
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
    use std::sync::Mutex;

    struct FakeExamRepository {
        mark_fails: Mutex<bool>,
    }

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
            if *self.mark_fails.lock().unwrap() {
                Err(AstralError::Database("boom".into()))
            } else {
                Ok(())
            }
        }

        async fn get_info(&self, _id: i64) -> Result<Option<ExamInfoRecord>, AstralError> {
            Ok(None)
        }
    }

    #[tokio::test]
    async fn submit_scores_passed_at_threshold() {
        // 及格边界：>= 60 通过，< 60 不通过
        let svc = ExamService::new(Arc::new(FakeExamRepository {
            mark_fails: Mutex::new(false),
        }));
        let pass = svc.submit_exam(1, 7, 60).await.unwrap();
        assert!(pass.passed);
        let fail = svc.submit_exam(1, 7, 59).await.unwrap();
        assert!(!fail.passed);
        assert_eq!(fail.exam_id, 1);
        assert_eq!(fail.user_id, 7);
        assert_eq!(fail.score, 59);
    }

    #[tokio::test]
    async fn submit_swallows_mark_submitted_failure() {
        // 标记 SUBMITTED 失败：告警不阻断，仍返回计分结果（对齐原 handler .ok() 吞错）
        let svc = ExamService::new(Arc::new(FakeExamRepository {
            mark_fails: Mutex::new(true),
        }));
        let outcome = svc.submit_exam(1, 7, 80).await.unwrap();
        assert!(outcome.passed);
    }
}
