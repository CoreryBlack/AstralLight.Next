//! 命中统计数据访问 — HitStatRepository
//!
//! 对齐 Java `HitStatMapper` 边界（permission_hit_stat + permission_rule 只读）。

use async_trait::async_trait;
use sqlx::{MySqlPool, Row};

use astral_types::AstralError;

/// 命中统计概览
#[derive(Debug, Clone, Default)]
pub struct HitStatSummaryRecord {
    pub total_hits: i64,
    pub rules_with_hits: i64,
    pub zero_hit_rules: i64,
    pub total_rules: i64,
}

/// Top/按卡命中行
#[derive(Debug, Clone)]
pub struct HitStatTopRow {
    pub resource_type: String,
    pub action_code: String,
    pub hit_count: i64,
    pub last_hit_at: Option<i64>,
}

/// 零命中权限行
#[derive(Debug, Clone)]
pub struct HitStatZeroHitRow {
    pub resource_type: String,
    pub action_code: String,
    pub rule_count: i64,
}

#[async_trait]
pub trait HitStatRepository: Send + Sync {
    /// 概览（total_hits / rules_with_hits / zero_hit_rules / total_rules）
    async fn summary(&self) -> Result<HitStatSummaryRecord, AstralError>;
    /// 零命中权限（permission_rule 有但 permission_hit_stat 无）
    async fn zero_hit_permissions(&self) -> Result<Vec<HitStatZeroHitRow>, AstralError>;
    /// 按卡命中 Top N
    async fn by_card(&self, card_id: i64, limit: i64) -> Result<Vec<HitStatTopRow>, AstralError>;
}

pub struct SqlxHitStatRepository {
    db: MySqlPool,
}

impl SqlxHitStatRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl HitStatRepository for SqlxHitStatRepository {
    async fn summary(&self) -> Result<HitStatSummaryRecord, AstralError> {
        // 总命中次数（CAST DECIMAL→SIGNED 兼容 hit_count 可能为 DECIMAL 类型）
        let total_hits: Option<i64> = sqlx::query_scalar(
            "SELECT COALESCE(CAST(SUM(hit_count) AS SIGNED), 0) FROM permission_hit_stat",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;

        // 有命中记录的 (resource, action) 组合数
        let rules_with_hits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM (SELECT DISTINCT resource_type, action_code FROM permission_hit_stat) t",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;

        // 零命中规则数：permission_rule 中有但 permission_hit_stat 中无
        // 使用 COLLATE 统一排序规则（permission_rule=utf8mb4_0900_ai_ci, permission_hit_stat=utf8mb4_unicode_ci）
        let zero_hit_rules: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ( \
             SELECT DISTINCT pr.resource_type, pr.action_code FROM permission_rule pr \
             WHERE pr.effect = 'ALLOW' \
             AND NOT EXISTS ( \
                 SELECT 1 FROM permission_hit_stat phs \
                 WHERE phs.resource_type = pr.resource_type COLLATE utf8mb4_unicode_ci \
                 AND phs.action_code = pr.action_code COLLATE utf8mb4_unicode_ci \
             ) \
             ) t",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;

        // 总规则组合数
        let total_rules: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM (SELECT DISTINCT resource_type, action_code FROM permission_rule WHERE effect = 'ALLOW') t",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)?;

        Ok(HitStatSummaryRecord {
            total_hits: total_hits.unwrap_or(0),
            rules_with_hits,
            zero_hit_rules,
            total_rules,
        })
    }

    async fn zero_hit_permissions(&self) -> Result<Vec<HitStatZeroHitRow>, AstralError> {
        let rows = sqlx::query(
            "SELECT pr.resource_type, pr.action_code, COUNT(*) as rule_count \
             FROM permission_rule pr \
             WHERE pr.effect = 'ALLOW' \
             AND NOT EXISTS ( \
                 SELECT 1 FROM permission_hit_stat phs \
                 WHERE phs.resource_type COLLATE utf8mb4_unicode_ci = pr.resource_type COLLATE utf8mb4_unicode_ci \
                 AND phs.action_code COLLATE utf8mb4_unicode_ci = pr.action_code COLLATE utf8mb4_unicode_ci \
             ) \
             GROUP BY pr.resource_type, pr.action_code \
             ORDER BY rule_count DESC",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;

        Ok(rows
            .iter()
            .map(|r| HitStatZeroHitRow {
                resource_type: r.get("resource_type"),
                action_code: r.get("action_code"),
                rule_count: r.get("rule_count"),
            })
            .collect())
    }

    async fn by_card(&self, card_id: i64, limit: i64) -> Result<Vec<HitStatTopRow>, AstralError> {
        let rows = sqlx::query(
            "SELECT card_id, resource_type, action_code, \
             CAST(hit_count AS SIGNED) as hit_count, \
             UNIX_TIMESTAMP(last_hit_at) as last_hit_at \
             FROM permission_hit_stat WHERE card_id = ? \
             ORDER BY hit_count DESC LIMIT ?",
        )
        .bind(card_id)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;

        Ok(rows
            .iter()
            .map(|r| HitStatTopRow {
                resource_type: r.get("resource_type"),
                action_code: r.get("action_code"),
                hit_count: r.get("hit_count"),
                last_hit_at: r.get("last_hit_at"),
            })
            .collect())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Hit stat repository query failed: {error}"))
}
