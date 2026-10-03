//! 学习进度编排 — ProgressService
//!
//! 对齐 Java `LearningProgressServiceImpl`：准确率计算、连续打卡天数（窗口 CTE）、
//! INSERT IGNORE 幂等首次作答后重算进度（对齐原 handler update → get 重新编排）。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::progress_repository::ProgressRepository;
use crate::srv::progress::LearningProgress;

/// ProgressService（依赖注入 repository）
pub struct ProgressService {
    repo: Arc<dyn ProgressRepository>,
}

impl ProgressService {
    pub fn new(repo: Arc<dyn ProgressRepository>) -> Self {
        Self { repo }
    }

    /// 查询学习进度（total/completed/accuracy/streak）
    pub async fn get_progress(
        &self,
        user_id: i64,
        subject_id: i64,
    ) -> Result<LearningProgress, AstralError> {
        let total_questions = self.repo.count_active_questions(subject_id).await?;
        let (completed_questions, correct_count) =
            self.repo.attempt_stats(user_id, subject_id).await?;
        let accuracy = if completed_questions > 0 {
            correct_count as f64 / completed_questions as f64
        } else {
            0.0
        };
        let streak_days = self.repo.compute_streak_days(user_id, subject_id).await?;
        Ok(LearningProgress {
            user_id,
            subject_id,
            total_questions,
            completed_questions,
            accuracy,
            streak_days,
        })
    }

    /// Client-provided correctness is not a scoring proof. The current Learn
    /// schema has no authoritative server-side answer evaluation transaction.
    pub async fn update_progress(
        &self,
        _user_id: i64,
        _subject_id: i64,
        _question_id: i64,
        _correct: bool,
    ) -> Result<LearningProgress, AstralError> {
        Err(AstralError::NotImplemented(
            "Progress updates require server-scored persisted answers; client correctness is not accepted".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::progress_repository::FirstAttemptRecord;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Fake ProgressRepository（记录插入 + 重算编排）
    struct FakeProgressRepository {
        calls: Mutex<Vec<String>>,
        total: i32,
        completed: i32,
        correct: i32,
        streak: i32,
    }

    impl FakeProgressRepository {
        fn new(total: i32, completed: i32, correct: i32, streak: i32) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                total,
                completed,
                correct,
                streak,
            }
        }
    }

    #[async_trait]
    impl ProgressRepository for FakeProgressRepository {
        async fn count_active_questions(&self, subject_id: i64) -> Result<i32, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("count_questions:{subject_id}"));
            Ok(self.total)
        }

        async fn attempt_stats(
            &self,
            user_id: i64,
            subject_id: i64,
        ) -> Result<(i32, i32), AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("attempt_stats:{user_id}:{subject_id}"));
            Ok((self.completed, self.correct))
        }

        async fn insert_ignore_first_attempt(
            &self,
            user_id: i64,
            question_id: i64,
            subject_id: i64,
            correct: bool,
        ) -> Result<(), AstralError> {
            self.calls.lock().unwrap().push(format!(
                "insert:{user_id}:{question_id}:{subject_id}:{correct}"
            ));
            Ok(())
        }

        async fn compute_streak_days(
            &self,
            user_id: i64,
            subject_id: i64,
        ) -> Result<i32, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("streak:{user_id}:{subject_id}"));
            Ok(self.streak)
        }

        async fn count_first_attempts(&self, _user_id: i64) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list_first_attempts(
            &self,
            _user_id: i64,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<FirstAttemptRecord>, AstralError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn accuracy_computed_from_stats() {
        // 50 题完成 40 对 → 准确率 0.8
        let repo = Arc::new(FakeProgressRepository::new(100, 50, 40, 3));
        let svc = ProgressService::new(repo.clone());
        let p = svc.get_progress(7, 1).await.unwrap();
        assert_eq!(p.total_questions, 100);
        assert_eq!(p.completed_questions, 50);
        assert_eq!(p.accuracy, 0.8);
        assert_eq!(p.streak_days, 3);
    }

    #[tokio::test]
    async fn accuracy_zero_when_no_attempts() {
        let repo = Arc::new(FakeProgressRepository::new(100, 0, 0, 0));
        let svc = ProgressService::new(repo);
        let p = svc.get_progress(7, 1).await.unwrap();
        assert_eq!(p.completed_questions, 0);
        assert_eq!(p.accuracy, 0.0);
    }

    #[tokio::test]
    async fn update_progress_rejects_client_supplied_correctness() {
        let repo = Arc::new(FakeProgressRepository::new(100, 0, 0, 0));
        let svc = ProgressService::new(repo.clone());
        let error = svc.update_progress(7, 1, 5, true).await.unwrap_err();
        assert!(matches!(error, AstralError::NotImplemented(_)));
        assert!(repo.calls.lock().unwrap().is_empty());
    }
}
