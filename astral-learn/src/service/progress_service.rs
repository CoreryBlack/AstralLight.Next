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

    /// 更新进度：INSERT IGNORE 幂等记录首次作答 → 重算进度（对齐原 handler 编排）
    pub async fn update_progress(
        &self,
        user_id: i64,
        subject_id: i64,
        question_id: i64,
        correct: bool,
    ) -> Result<LearningProgress, AstralError> {
        self.repo
            .insert_ignore_first_attempt(user_id, question_id, subject_id, correct)
            .await?;
        tracing::info!(user_id, question_id, correct, "learning progress updated");
        self.get_progress(user_id, subject_id).await
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
    async fn update_progress_inserts_then_recomputes() {
        // INSERT IGNORE → 重算（对齐原 handler update → get 重新编排）
        let repo = Arc::new(FakeProgressRepository::new(100, 50, 40, 3));
        let svc = ProgressService::new(repo.clone());
        let p = svc.update_progress(7, 1, 5, true).await.unwrap();
        assert_eq!(p.accuracy, 0.8);
        assert_eq!(
            repo.calls.lock().unwrap().clone(),
            vec![
                "insert:7:5:1:true".to_string(),
                "count_questions:1".to_string(),
                "attempt_stats:7:1".to_string(),
                "streak:7:1".to_string(),
            ]
        );
    }
}
