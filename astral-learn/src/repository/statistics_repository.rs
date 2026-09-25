//! 统计聚合数据访问 — StatisticsRepository
//!
//! 对齐 Java `StatisticsController` 的实时聚合（learn_subject / learn_question /
//! learn_course / learn_user_subject，platform_v4）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 概览计数
#[derive(Debug, Clone, Default)]
pub struct OverviewStats {
    pub subject_count: i64,
    pub question_count: i64,
    pub course_count: i64,
    pub user_count: i64,
}

/// 状态/类型计数（subject_dist / question_dist / question_types 共用）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GroupCount {
    pub name: String,
    pub cnt: i64,
}

#[async_trait]
pub trait StatisticsRepository: Send + Sync {
    /// 概览计数（4 表 COUNT）
    async fn overview(&self) -> Result<OverviewStats, AstralError>;
    /// 学科按状态分布
    async fn subject_distribution(&self) -> Result<Vec<GroupCount>, AstralError>;
    /// 题目按类型分布（ACTIVE）
    async fn question_type_distribution(&self) -> Result<Vec<GroupCount>, AstralError>;
}

pub struct SqlxStatisticsRepository {
    db: MySqlPool,
}

impl SqlxStatisticsRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl StatisticsRepository for SqlxStatisticsRepository {
    async fn overview(&self) -> Result<OverviewStats, AstralError> {
        let subject_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM learn_subject WHERE status = 'ACTIVE'")
                .fetch_one(&self.db)
                .await
                .map_err(db_error)?;
        let question_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM learn_question WHERE status = 'ACTIVE'")
                .fetch_one(&self.db)
                .await
                .map_err(db_error)?;
        let course_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM learn_course WHERE status != 'ARCHIVED'")
                .fetch_one(&self.db)
                .await
                .map_err(db_error)?;
        let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM learn_user_subject")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)?;
        Ok(OverviewStats {
            subject_count,
            question_count,
            course_count,
            user_count,
        })
    }

    async fn subject_distribution(&self) -> Result<Vec<GroupCount>, AstralError> {
        sqlx::query_as::<_, GroupCount>(
            "SELECT status AS name, COUNT(*) AS cnt FROM learn_subject GROUP BY status",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn question_type_distribution(&self) -> Result<Vec<GroupCount>, AstralError> {
        sqlx::query_as::<_, GroupCount>(
            "SELECT question_type AS name, COUNT(*) AS cnt FROM learn_question \
             WHERE status = 'ACTIVE' GROUP BY question_type ORDER BY cnt DESC",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Statistics repository query failed: {error}"))
}
