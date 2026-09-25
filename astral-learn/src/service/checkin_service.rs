//! 打卡编排 — CheckinService
//!
//! 对齐 Java `CheckinServiceImpl`：今日幂等守卫（已打卡拒绝）、
//! reward_points=10 常量、月过滤查询、管理端统计。

use std::sync::Arc;

use astral_types::AstralError;

use crate::repository::checkin_repository::CheckinRepository;
use crate::srv::checkins::Checkin;

/// 单次打卡奖励积分（对齐 Java 常量）
pub const CHECKIN_REWARD_POINTS: i32 = 10;

/// CheckinService（依赖注入 repository）
pub struct CheckinService {
    repo: Arc<dyn CheckinRepository>,
}

impl CheckinService {
    pub fn new(repo: Arc<dyn CheckinRepository>) -> Self {
        Self { repo }
    }

    /// 打卡：今日已打卡 → Validation 拒绝；否则插入（reward_points=10）
    pub async fn app_checkin(&self, user_id: i64) -> Result<Checkin, AstralError> {
        if self.repo.exists_today(user_id).await? {
            return Err(AstralError::Validation("Already checked in today".into()));
        }
        let id = self.repo.create_checkin(user_id).await?;
        Ok(Checkin {
            id,
            user_id,
            checkin_date: None,
            reward_points: CHECKIN_REWARD_POINTS,
            created_at: None,
        })
    }

    /// 打卡列表（可选按 month 过滤）
    pub async fn list_checkins(
        &self,
        user_id: i64,
        month: Option<String>,
        page: i64,
        size: i64,
    ) -> Result<(Vec<Checkin>, i64), AstralError> {
        let offset = (page - 1) * size;
        let month_ref = month.as_deref();
        let total = self.repo.count(user_id, month_ref).await?;
        let rows = self
            .repo
            .list(user_id, month_ref, size, offset)
            .await?
            .into_iter()
            .map(|r| Checkin {
                id: r.id,
                user_id: r.user_id,
                checkin_date: r.checkin_date,
                reward_points: r.reward_points,
                created_at: r.created_at,
            })
            .collect();
        Ok((rows, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::checkin_repository::CheckinRecord;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Fake CheckinRepository（今日幂等状态可配置）
    struct FakeCheckinRepository {
        exists_today: Mutex<bool>,
        created: Mutex<Vec<i64>>,
    }

    impl FakeCheckinRepository {
        fn new(exists_today: bool) -> Self {
            Self {
                exists_today: Mutex::new(exists_today),
                created: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl CheckinRepository for FakeCheckinRepository {
        async fn exists_today(&self, _user_id: i64) -> Result<bool, AstralError> {
            Ok(*self.exists_today.lock().unwrap())
        }

        async fn create_checkin(&self, user_id: i64) -> Result<i64, AstralError> {
            self.created.lock().unwrap().push(user_id);
            Ok(9)
        }

        async fn count(&self, _user_id: i64, _month: Option<&str>) -> Result<i64, AstralError> {
            Ok(0)
        }

        async fn list(
            &self,
            _user_id: i64,
            _month: Option<&str>,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<CheckinRecord>, AstralError> {
            Ok(vec![])
        }

        async fn admin_stats(
            &self,
        ) -> Result<crate::repository::checkin_repository::CheckinStats, AstralError> {
            Ok(Default::default())
        }
    }

    #[tokio::test]
    async fn app_checkin_rejects_when_already_checked_today() {
        // 今日已打卡 → Validation（幂等守卫）
        let repo = Arc::new(FakeCheckinRepository::new(true));
        let svc = CheckinService::new(repo.clone());
        let err = svc.app_checkin(7).await.unwrap_err();
        assert!(matches!(err, AstralError::Validation(_)));
        assert!(repo.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn app_checkin_awards_reward_points() {
        // 未打卡 → 插入并返回 reward_points=10
        let repo = Arc::new(FakeCheckinRepository::new(false));
        let svc = CheckinService::new(repo.clone());
        let checkin = svc.app_checkin(7).await.unwrap();
        assert_eq!(checkin.id, 9);
        assert_eq!(checkin.user_id, 7);
        assert_eq!(checkin.reward_points, CHECKIN_REWARD_POINTS);
        assert_eq!(checkin.reward_points, 10);
        assert_eq!(repo.created.lock().unwrap().clone(), vec![7]);
    }
}
