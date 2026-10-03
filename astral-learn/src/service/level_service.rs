//! 关卡编排 — LevelService
//!
//! 对齐 Java `LevelPlayServiceImpl`：关卡进度状态机
//! start（校验活跃关卡 → 建 IN_PROGRESS）→ submit_answer（守卫 IN_PROGRESS）→
//! finish（IN_PROGRESS → COMPLETED + score）。授权（require_same_user）保留在 handler。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::level_repository::LevelRepository;
use crate::srv::levels::LevelStatus;

/// LevelService（依赖注入 repository）
pub struct LevelService {
    _repo: Arc<dyn LevelRepository>,
}

impl LevelService {
    pub fn new(repo: Arc<dyn LevelRepository>) -> Self {
        Self { _repo: repo }
    }

    /// The Learn schema contains no authoritative answer scorer for level play.
    /// Do not create progress or report an unscored start as a successful run.
    pub async fn start_level(
        &self,
        _user_id: i64,
        _level_id: i64,
    ) -> Result<LevelStatus, AstralError> {
        Err(AstralError::NotImplemented(
            "Level play requires a server-side scorer and durable attempt contract".into(),
        ))
    }

    /// No accepted answer path may claim completion without server scoring.
    pub async fn submit_answer(
        &self,
        _user_id: i64,
        _level_status_id: i64,
    ) -> Result<(), AstralError> {
        Err(AstralError::NotImplemented(
            "Level play answer submission requires a server-side scorer".into(),
        ))
    }

    /// A client-supplied score is not grading authority.
    pub async fn finish_level(
        &self,
        _user_id: i64,
        _level_status_id: i64,
        _score: i32,
    ) -> Result<(), AstralError> {
        Err(AstralError::NotImplemented(
            "Level play completion requires a server-side scorer".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::level_repository::{LevelInput, LevelRecord};
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Fake LevelRepository（记录调用顺序与参数）
    struct FakeLevelRepository {
        calls: Mutex<Vec<String>>,
        active: Mutex<Option<LevelRecord>>,
        status: Mutex<Option<String>>,
        finish_hit: Mutex<bool>,
    }

    impl FakeLevelRepository {
        fn new(active: Option<LevelRecord>, status: Option<String>, finish_hit: bool) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                active: Mutex::new(active),
                status: Mutex::new(status),
                finish_hit: Mutex::new(finish_hit),
            }
        }
    }

    #[async_trait]
    impl LevelRepository for FakeLevelRepository {
        async fn count(&self, _subject_id: Option<i64>) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list(
            &self,
            _subject_id: Option<i64>,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<LevelRecord>, AstralError> {
            Ok(vec![])
        }

        async fn create(&self, _input: &LevelInput) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn update(&self, _id: i64, _input: &LevelInput) -> Result<(), AstralError> {
            Ok(())
        }

        async fn soft_delete(&self, _id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn get_active(&self, id: i64) -> Result<Option<LevelRecord>, AstralError> {
            self.calls.lock().unwrap().push(format!("get_active:{id}"));
            Ok(self.active.lock().unwrap().clone())
        }

        async fn list_questions(
            &self,
            _level_id: i64,
        ) -> Result<Vec<crate::repository::level_repository::LevelQuestionRecord>, AstralError>
        {
            Ok(vec![])
        }

        async fn create_level_status(
            &self,
            level_id: i64,
            user_id: i64,
        ) -> Result<i64, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("create_status:{level_id}:{user_id}"));
            Ok(99)
        }

        async fn get_status_for_user(
            &self,
            level_status_id: i64,
            user_id: i64,
        ) -> Result<Option<String>, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("get_status:{level_status_id}:{user_id}"));
            Ok(self.status.lock().unwrap().clone())
        }

        async fn finish_level(
            &self,
            level_status_id: i64,
            user_id: i64,
            score: i32,
        ) -> Result<bool, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("finish:{level_status_id}:{user_id}:{score}"));
            Ok(*self.finish_hit.lock().unwrap())
        }
    }

    fn active_level(id: i64) -> LevelRecord {
        LevelRecord {
            id,
            subject_id: 1,
            name: "L".into(),
            sequence: 0,
            level_type: "NORMAL".into(),
            config_json: None,
            status: "ACTIVE".into(),
            created_at: None,
        }
    }

    #[tokio::test]
    async fn start_level_is_not_implemented_without_server_scoring_contract() {
        let repo = Arc::new(FakeLevelRepository::new(Some(active_level(5)), None, false));
        let svc = LevelService::new(repo.clone());
        let err = svc.start_level(7, 5).await.unwrap_err();
        assert!(matches!(err, AstralError::NotImplemented(_)));
        assert!(repo.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn level_play_answers_and_client_scores_are_not_accepted() {
        let repo = Arc::new(FakeLevelRepository::new(
            Some(active_level(5)),
            Some("IN_PROGRESS".into()),
            true,
        ));
        let svc = LevelService::new(repo.clone());

        assert!(matches!(
            svc.submit_answer(7, 99).await,
            Err(AstralError::NotImplemented(_))
        ));
        assert!(matches!(
            svc.finish_level(7, 99, 100).await,
            Err(AstralError::NotImplemented(_))
        ));
        assert!(repo.calls.lock().unwrap().is_empty());
    }
}
