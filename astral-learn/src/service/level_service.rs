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
    repo: Arc<dyn LevelRepository>,
}

impl LevelService {
    pub fn new(repo: Arc<dyn LevelRepository>) -> Self {
        Self { repo }
    }

    /// 开始关卡：校验活跃关卡存在 → 创建进度（IN_PROGRESS）
    pub async fn start_level(
        &self,
        user_id: i64,
        level_id: i64,
    ) -> Result<LevelStatus, AstralError> {
        self.repo
            .get_active(level_id)
            .await?
            .ok_or_else(|| AstralError::Validation("Level not found".into()))?;
        let id = self.repo.create_level_status(level_id, user_id).await?;
        Ok(LevelStatus {
            id,
            level_id,
            user_id,
            status: "IN_PROGRESS".into(),
            score: None,
            started_at: None,
            finished_at: None,
        })
    }

    /// 提交答案：仅 IN_PROGRESS 状态可提交
    pub async fn submit_answer(
        &self,
        user_id: i64,
        level_status_id: i64,
    ) -> Result<(), AstralError> {
        match self
            .repo
            .get_status_for_user(level_status_id, user_id)
            .await?
        {
            Some(s) if s == "IN_PROGRESS" => Ok(()),
            Some(s) => Err(AstralError::Validation(format!(
                "Level status is '{s}', cannot submit answer"
            ))),
            None => Err(AstralError::Validation("Level status not found".into())),
        }
    }

    /// 完成关卡：IN_PROGRESS → COMPLETED（守卫式 UPDATE）
    pub async fn finish_level(
        &self,
        user_id: i64,
        level_status_id: i64,
        score: i32,
    ) -> Result<(), AstralError> {
        let hit = self
            .repo
            .finish_level(level_status_id, user_id, score)
            .await?;
        if !hit {
            return Err(AstralError::Validation(
                "Level status not found or not in progress".into(),
            ));
        }
        Ok(())
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
    async fn start_level_rejects_missing_level() {
        let svc = LevelService::new(Arc::new(FakeLevelRepository::new(None, None, false)));
        let err = svc.start_level(7, 5).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
    }

    #[tokio::test]
    async fn start_level_creates_in_progress_status() {
        let repo = Arc::new(FakeLevelRepository::new(Some(active_level(5)), None, false));
        let svc = LevelService::new(repo.clone());
        let status = svc.start_level(7, 5).await.unwrap();
        assert_eq!(status.status, "IN_PROGRESS");
        assert_eq!(status.id, 99);
        assert_eq!(status.level_id, 5);
        assert_eq!(status.user_id, 7);
        assert_eq!(
            repo.calls.lock().unwrap().clone(),
            vec!["get_active:5", "create_status:5:7"]
        );
    }

    #[tokio::test]
    async fn submit_answer_rejects_non_in_progress() {
        // COMPLETED 状态不能提交答案
        let repo = Arc::new(FakeLevelRepository::new(
            None,
            Some("COMPLETED".into()),
            false,
        ));
        let svc = LevelService::new(repo);
        let err = svc.submit_answer(7, 99).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
    }

    #[tokio::test]
    async fn submit_answer_missing_status_rejected() {
        let repo = Arc::new(FakeLevelRepository::new(None, None, false));
        let svc = LevelService::new(repo);
        let err = svc.submit_answer(7, 99).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
    }

    #[tokio::test]
    async fn finish_level_guarded_update() {
        // IN_PROGRESS → COMPLETED 成功
        let repo = Arc::new(FakeLevelRepository::new(
            None,
            Some("IN_PROGRESS".into()),
            true,
        ));
        let svc = LevelService::new(repo.clone());
        svc.finish_level(7, 99, 80).await.unwrap();
        assert_eq!(repo.calls.lock().unwrap().clone(), vec!["finish:99:7:80"]);
    }

    #[tokio::test]
    async fn finish_level_no_match_rejected() {
        // 守卫 UPDATE 未命中（不存在或非 IN_PROGRESS）→ Validation
        let repo = Arc::new(FakeLevelRepository::new(None, None, false));
        let svc = LevelService::new(repo);
        let err = svc.finish_level(7, 99, 80).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
    }
}
