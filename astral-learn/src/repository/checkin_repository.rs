//! 打卡数据访问 — CheckinRepository
//!
//! 对齐 Java `CheckinMapper` 边界（learn_checkin 表）。
//! checkin_date 为 DATE 列（time::Date）；reward_points 常量 10 在 service 层。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 打卡行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CheckinRecord {
    pub id: i64,
    pub user_id: i64,
    pub checkin_date: Option<time::Date>,
    pub reward_points: i32,
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// 管理端统计（total, today, points）
#[derive(Debug, Clone, Default)]
pub struct CheckinStats {
    pub total_checkins: i64,
    pub today_checkins: i64,
    pub total_reward_points: i64,
}

#[async_trait]
pub trait CheckinRepository: Send + Sync {
    /// 今日是否已打卡（幂等检查）
    async fn exists_today(&self, user_id: i64) -> Result<bool, AstralError>;
    /// 打卡（reward_points=10），返回新 id
    async fn create_checkin(&self, user_id: i64) -> Result<i64, AstralError>;
    /// 总数（可选按 month 'YYYY-MM' 过滤）
    async fn count(&self, user_id: i64, month: Option<&str>) -> Result<i64, AstralError>;
    /// 分页列表（可选按 month 过滤）
    async fn list(
        &self,
        user_id: i64,
        month: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CheckinRecord>, AstralError>;
    /// 管理端统计
    async fn admin_stats(&self) -> Result<CheckinStats, AstralError>;
}

pub struct SqlxCheckinRepository {
    db: MySqlPool,
}

impl SqlxCheckinRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const CHECKIN_SELECT: &str =
    "SELECT id, user_id, checkin_date, reward_points, created_at FROM learn_checkin";

#[async_trait]
impl CheckinRepository for SqlxCheckinRepository {
    async fn exists_today(&self, user_id: i64) -> Result<bool, AstralError> {
        let exists: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) > 0 FROM learn_checkin WHERE user_id = ? AND checkin_date = CURDATE()",
        )
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;
        Ok(exists.0 > 0)
    }

    async fn create_checkin(&self, user_id: i64) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO learn_checkin (user_id, checkin_date, reward_points, created_at) \
             VALUES (?, CURDATE(), 10, NOW())",
        )
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn count(&self, user_id: i64, month: Option<&str>) -> Result<i64, AstralError> {
        match month {
            Some(m) => sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM learn_checkin WHERE user_id = ? AND DATE_FORMAT(checkin_date, '%Y-%m') = ?",
            )
            .bind(user_id)
            .bind(m)
            .fetch_one(&self.db)
            .await
            .map_err(db_error),
            None => {
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM learn_checkin WHERE user_id = ?")
                    .bind(user_id)
                    .fetch_one(&self.db)
                    .await
                    .map_err(db_error)
            }
        }
    }

    async fn list(
        &self,
        user_id: i64,
        month: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CheckinRecord>, AstralError> {
        match month {
            Some(m) => sqlx::query_as::<_, CheckinRecord>(&format!(
                "{CHECKIN_SELECT} WHERE user_id = ? AND DATE_FORMAT(checkin_date, '%Y-%m') = ? \
                 ORDER BY checkin_date DESC LIMIT ? OFFSET ?"
            ))
            .bind(user_id)
            .bind(m)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_as::<_, CheckinRecord>(&format!(
                "{CHECKIN_SELECT} WHERE user_id = ? ORDER BY checkin_date DESC LIMIT ? OFFSET ?"
            ))
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
        }
    }

    async fn admin_stats(&self) -> Result<CheckinStats, AstralError> {
        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM learn_checkin")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;
        let today: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM learn_checkin WHERE checkin_date = CURDATE()")
                .fetch_one(&self.db)
                .await
                .map_err(db_error)?;
        let points: (i64,) =
            sqlx::query_as("SELECT COALESCE(SUM(reward_points), 0) FROM learn_checkin")
                .fetch_one(&self.db)
                .await
                .map_err(db_error)?;
        Ok(CheckinStats {
            total_checkins: total.0,
            today_checkins: today.0,
            total_reward_points: points.0,
        })
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Checkin repository query failed: {error}"))
}
