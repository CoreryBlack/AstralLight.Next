//! 权限投影 durable 事件 — ProjectionRepository
//!
//! 对齐 Java `AuthorizationProjectionServiceImpl` + `PermissionRefreshService.requestCardProjection`：
//! 以 `authorization_projection_head` + `authorization_projection_outbox` 两张 durable 表驱动
//! 投影事件链。写侧 source mutation 调用 `request_card_projection`/`request_aggregate_projection`
//! 落 durable 事件（head 递增 + outbox PENDING）；worker 轮询 outbox 消费：ELIGIBILITY
//! 仅失效资格缓存，CARD/RULE_SET 事件终态 mark_processed（旧链快照重建已退役，
//! 新链 authorization_projector delta 队列是唯一权威消费者）。
//!
//! 旧链 head 投影状态列（`projected_generation`/`projection_status`）及其 READY 推进状态机
//! （`ProjectionAdvance`、`classify_projection_advance`、`get_*_projection_status`）已随迁移
//! 20260831000001 退役删除：head 现保留 `source_generation`/`revoke_fence`/`last_event_id`
//! 作为 writer correlation 与写侧代次锚点，读侧版本栅栏收敛为 (source_generation,
//! revoke_fence) 二元组。
//!
//! 事件（outbox）与 head 的版本语义：
//! - `source_generation`：授权变更的代次，从 1 递增（每个聚合首个事件为 1）
//! - `revoke_fence`：仅 `REVOKE` 类事件递增的围栏计数（consumer 用其判断消息是否过期）
//! - `sequence_number` = `source_generation`（outbox 幂等唯一键的一部分）

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;
use astral_types::ProjectionAggregate;

// 事件类型常量唯一事实源在 astral-types；此处 re-export 保持既有调用方导入不变。
pub use astral_types::{
    EVENT_TYPE_CARD_UPDATE, EVENT_TYPE_ELIGIBILITY_UPDATE, EVENT_TYPE_REVOKE,
    EVENT_TYPE_RULE_SET_UPDATE,
};

/// 投影 head 记录（authorization_projection_head）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProjectionHeadRecord {
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub source_generation: i64,
    pub revoke_fence: i64,
}

/// outbox 事件记录（authorization_projection_outbox）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OutboxEventRecord {
    pub outbox_id: i64,
    pub event_id: String,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub tenant_id: Option<i64>,
    pub event_type: String,
    pub source_generation: i64,
    pub sequence_number: i64,
    pub revoke_fence: i64,
    pub status: String,
    pub attempts: i32,
}

const PROJECTION_LEASE_LOST_PREFIX: &str = "projection lease lost:";

pub(crate) fn projection_lease_lost_error(operation: &str) -> AstralError {
    AstralError::Internal(format!(
        "{PROJECTION_LEASE_LOST_PREFIX} {operation} did not match one live claim"
    ))
}

pub(crate) fn is_projection_lease_lost(error: &AstralError) -> bool {
    matches!(error, AstralError::Internal(message) if message.starts_with(PROJECTION_LEASE_LOST_PREFIX))
}

pub(crate) fn classify_fenced_update(
    rows_affected: u64,
    operation: &str,
) -> Result<(), AstralError> {
    if rows_affected == 1 {
        Ok(())
    } else {
        Err(projection_lease_lost_error(operation))
    }
}

const MARK_PROCESSED_SQL: &str = concat!(
    "UPDATE authorization_projection_outbox ",
    "SET status = 'PROCESSED', processed_at = NOW(), processed_by = ?, ",
    "terminal_transitions = terminal_transitions + 1, ",
    "lease_owner = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = NOW() ",
    "WHERE outbox_id = ? AND status = 'PENDING' ",
    "AND lease_owner = ? AND lease_expires_at > NOW()",
);
const MARK_OBSOLETE_SQL: &str = concat!(
    "UPDATE authorization_projection_outbox ",
    "SET status = 'PROCESSED', processed_at = NOW(), processed_by = ?, ",
    "terminal_transitions = terminal_transitions + 1, ",
    "lease_owner = NULL, lease_expires_at = NULL, last_error = ",
    "'SUPERSEDED_BY_NEWER_GENERATION', updated_at = NOW() ",
    "WHERE outbox_id = ? AND status = 'PENDING' ",
    "AND lease_owner = ? AND lease_expires_at > NOW()",
);
const RELEASE_FAILED_SQL: &str = concat!(
    "UPDATE authorization_projection_outbox ",
    "SET status = 'PENDING', attempts = attempts + 1, ",
    "terminal_transitions = terminal_transitions + 1, ",
    "next_attempt_at = DATE_ADD(NOW(), INTERVAL ? SECOND), ",
    "lease_owner = NULL, lease_expires_at = NULL, last_error = ?, updated_at = NOW() ",
    "WHERE outbox_id = ? AND status = 'PENDING' ",
    "AND lease_owner = ? AND lease_expires_at > NOW()",
);
/// 投影 repository 端口
///
/// head/outbox 读写按 `ProjectionAggregate` + aggregate id 参数化，支持 `CARD` / `ELIGIBILITY`
/// 两条类型安全通道；CARD 命名入口为默认实现包装（行为不变，既有调用方无需改动）。
/// 事务内只写 head/outbox，不访问 Redis/MQ。
#[async_trait]
pub trait ProjectionRepository: Send + Sync {
    /// 卡片授权变更落 durable 事件（CARD 通道兼容入口，委托 `request_aggregate_projection`）。
    async fn request_card_projection(
        &self,
        card_id: i64,
        event_type: &str,
    ) -> Result<(), AstralError> {
        self.request_aggregate_projection(ProjectionAggregate::Card, card_id, event_type)
            .await
    }

    /// 任一聚合（CARD/ELIGIBILITY）变更落 durable 事件
    /// （单事务：head selectForUpdate → 递增 → 插 outbox PENDING）。
    /// `event_type == "REVOKE"` 时 revoke_fence 递增，其余事件保持围栏不变。
    async fn request_aggregate_projection(
        &self,
        aggregate: ProjectionAggregate,
        aggregate_id: i64,
        event_type: &str,
    ) -> Result<(), AstralError>;

    /// worker 认领待处理事件（按 aggregate,id,generation 排序，最多 batch 条），
    /// 租约 lease_secs 内未处理完成会被其他 worker 重新认领
    async fn claim_pending_events(
        &self,
        batch: i64,
        worker_id: &str,
        lease_secs: i64,
    ) -> Result<Vec<OutboxEventRecord>, AstralError>;

    /// 卡片当前 head（CARD 通道兼容入口，worker 校验旧代 + 读侧门禁）。
    async fn get_head(&self, card_id: i64) -> Result<Option<ProjectionHeadRecord>, AstralError> {
        self.get_aggregate_head(ProjectionAggregate::Card, card_id)
            .await
    }

    /// 聚合当前 head（worker 校验旧代 + 读侧门禁）。
    async fn get_aggregate_head(
        &self,
        aggregate: ProjectionAggregate,
        aggregate_id: i64,
    ) -> Result<Option<ProjectionHeadRecord>, AstralError>;

    /// outbox 处理完成（仅持有租约的 worker 生效）
    async fn mark_processed(&self, outbox_id: i64, worker_id: &str) -> Result<(), AstralError>;
    /// 旧代事件按既有终态契约标记为 PROCESSED，并保留 SUPERSEDED_BY_NEWER_GENERATION 原因（仅持有租约的 worker 生效）
    async fn mark_obsolete(&self, outbox_id: i64, worker_id: &str) -> Result<(), AstralError>;
    /// 处理失败：attempts+1、terminal_transitions+1、退避 next_attempt_at、释放租约（仅持有租约的 worker 生效）
    async fn release_failed(
        &self,
        outbox_id: i64,
        worker_id: &str,
        backoff_secs: i64,
        error_msg: &str,
    ) -> Result<(), AstralError>;
}

pub struct SqlxProjectionRepository {
    db: MySqlPool,
}

impl SqlxProjectionRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 在调用方已有的 source transaction 中追加任一聚合投影事件。
///
/// source mutation 与 head/outbox 必须共用同一事务；提交后的快照重建、缓存
/// 失效和 MQ 发布仍由 projection worker 负责。调用方不得在此事务内触发
/// Redis 或 RabbitMQ 副作用。事务内仅写 head/outbox，不访问 Redis/MQ。
///
/// 兼容入口：委托到公共实现 `astral_db::append_projection_event_in_tx`
/// （语义完全一致，见 astral-db `projection` 模块），本函数保留原签名以便
/// 既有调用方与 re-export 路径不变。
pub async fn append_aggregate_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    aggregate: ProjectionAggregate,
    aggregate_id: i64,
    event_type: &str,
) -> Result<(), AstralError> {
    astral_db::append_projection_event_in_tx(tx, aggregate, aggregate_id, event_type).await
}

/// Append a RuleSet projection event with trusted actor and operation metadata.
///
/// This public compatibility helper is retained for the existing RuleSet, template,
/// GlobalAdmin, compensation, and side-effect call sites. The source transaction
/// remains the caller's responsibility; no commit or external side effect occurs here.
pub async fn append_rule_set_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    event_type: &str,
    metadata: astral_db::ProjectionEventMetadata<'_>,
) -> Result<astral_db::ProjectionEventIdentity, AstralError> {
    append_rule_set_projection_with_tenant_in_tx(tx, rule_set_id, event_type, metadata, None).await
}

/// Append a RuleSet projection event while preserving a captured tenant for deletes.
///
/// `tenant_id` is only used when the RuleSet source row has already been deleted;
/// otherwise the shared database writer resolves the tenant from the source row.
pub async fn append_rule_set_projection_with_tenant_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    event_type: &str,
    metadata: astral_db::ProjectionEventMetadata<'_>,
    tenant_id: Option<i64>,
) -> Result<astral_db::ProjectionEventIdentity, AstralError> {
    astral_db::append_projection_event_with_metadata_and_tenant_in_tx(
        tx,
        ProjectionAggregate::RuleSet,
        rule_set_id,
        event_type,
        Some(metadata),
        tenant_id,
    )
    .await
}

/// 在调用方已有的 source transaction 中追加 CARD 投影事件（兼容入口）。
///
/// 行为与旧实现完全一致，委托参数化实现（aggregate = `CARD`）。
pub async fn append_card_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
    event_type: &str,
) -> Result<(), AstralError> {
    append_aggregate_projection_in_tx(tx, ProjectionAggregate::Card, card_id, event_type).await
}

/// 追加携带可信 actor/operation 元数据的 CARD 投影事件，返回 durable 事件身份。
///
/// 审批事务把返回的 `ProjectionEventIdentity`（event/generation/fence）绑定进
/// 授权账本 delta；旧的丢身份兼容入口不得再用于该路径。本函数不 commit，
/// 由调用方决定事务提交或回滚，也不触碰 Redis/MQ。
pub async fn append_card_projection_with_metadata_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
    event_type: &str,
    metadata: astral_db::ProjectionEventMetadata<'_>,
) -> Result<astral_db::ProjectionEventIdentity, AstralError> {
    astral_db::append_projection_event_with_metadata_in_tx(
        tx,
        ProjectionAggregate::Card,
        card_id,
        event_type,
        Some(metadata),
    )
    .await
}

#[async_trait]
impl ProjectionRepository for SqlxProjectionRepository {
    async fn request_aggregate_projection(
        &self,
        aggregate: ProjectionAggregate,
        aggregate_id: i64,
        event_type: &str,
    ) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        append_aggregate_projection_in_tx(&mut tx, aggregate, aggregate_id, event_type).await?;
        tx.commit().await.map_err(db_error)?;
        tracing::debug!(
            aggregate = %aggregate,
            aggregate_id,
            event_type,
            "aggregate projection requested"
        );
        Ok(())
    }

    async fn claim_pending_events(
        &self,
        batch: i64,
        worker_id: &str,
        lease_secs: i64,
    ) -> Result<Vec<OutboxEventRecord>, AstralError> {
        // MySQL 不允许 UPDATE 直接 LIMIT，用双层子查询选出候选后按序标记租约。
        // 已持有未过期租约的行（其他 worker 正在处理）不参与认领。
        sqlx::query(
            "UPDATE authorization_projection_outbox \
             SET lease_owner = ?, lease_expires_at = DATE_ADD(NOW(), INTERVAL ? SECOND) \
             WHERE status = 'PENDING' \
               AND (next_attempt_at IS NULL OR next_attempt_at <= NOW()) \
               AND (lease_owner IS NULL OR lease_expires_at IS NULL OR lease_expires_at <= NOW()) \
               AND outbox_id IN ( \
                   SELECT outbox_id FROM ( \
                       SELECT outbox_id FROM authorization_projection_outbox \
                       WHERE status = 'PENDING' \
                         AND (next_attempt_at IS NULL OR next_attempt_at <= NOW()) \
                         AND (lease_owner IS NULL OR lease_expires_at IS NULL OR lease_expires_at <= NOW()) \
                       ORDER BY aggregate_type, outbox_id, source_generation \
                       LIMIT ? \
                   ) AS claim_candidates \
               )",
        )
        .bind(worker_id)
        .bind(lease_secs)
        .bind(batch)
        .execute(&self.db)
        .await
        .map_err(db_error)?;

        sqlx::query_as::<_, OutboxEventRecord>(
            "SELECT outbox_id, event_id, aggregate_type, aggregate_id, tenant_id, event_type, \
                    source_generation, sequence_number, revoke_fence, status, attempts \
             FROM authorization_projection_outbox \
             WHERE lease_owner = ? AND status = 'PENDING' \
             ORDER BY aggregate_type, outbox_id, source_generation",
        )
        .bind(worker_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_aggregate_head(
        &self,
        aggregate: ProjectionAggregate,
        aggregate_id: i64,
    ) -> Result<Option<ProjectionHeadRecord>, AstralError> {
        sqlx::query_as::<_, ProjectionHeadRecord>(
            "SELECT aggregate_type, aggregate_id, source_generation, revoke_fence \
             FROM authorization_projection_head \
             WHERE aggregate_type = ? AND aggregate_id = ?",
        )
        .bind(aggregate.as_str())
        .bind(aggregate_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn mark_processed(&self, outbox_id: i64, worker_id: &str) -> Result<(), AstralError> {
        let result = sqlx::query(MARK_PROCESSED_SQL)
            .bind(worker_id)
            .bind(outbox_id)
            .bind(worker_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        classify_fenced_update(result.rows_affected(), "mark_processed")
    }

    async fn mark_obsolete(&self, outbox_id: i64, worker_id: &str) -> Result<(), AstralError> {
        let result = sqlx::query(MARK_OBSOLETE_SQL)
            .bind(worker_id)
            .bind(outbox_id)
            .bind(worker_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        classify_fenced_update(result.rows_affected(), "mark_obsolete")
    }

    async fn release_failed(
        &self,
        outbox_id: i64,
        worker_id: &str,
        backoff_secs: i64,
        error_msg: &str,
    ) -> Result<(), AstralError> {
        let result = sqlx::query(RELEASE_FAILED_SQL)
            .bind(backoff_secs)
            .bind(error_msg)
            .bind(outbox_id)
            .bind(worker_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        classify_fenced_update(result.rows_affected(), "release_failed")
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Projection repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 事件类型语义：仅 REVOKE 递增围栏（对齐 Java 幂等判断 isObsoleteVersionedCardRefresh）
    #[test]
    fn revoke_event_bumps_fence_only_for_revoke() {
        assert_eq!(EVENT_TYPE_REVOKE, "REVOKE");
        // 其余事件类型（CARD_UPDATE / RULE_SET_UPDATE / ELIGIBILITY_UPDATE）不递增围栏，
        // 由 SQL 分支保证
        assert_ne!(EVENT_TYPE_CARD_UPDATE, EVENT_TYPE_REVOKE);
        assert_ne!(EVENT_TYPE_RULE_SET_UPDATE, EVENT_TYPE_REVOKE);
        assert_ne!(EVENT_TYPE_ELIGIBILITY_UPDATE, EVENT_TYPE_REVOKE);
    }

    /// 聚合类型常量与 CARD 行为绑定：CARD 通道的 DB 存储值恒为 "CARD"。
    #[test]
    fn card_aggregate_contract_is_stable() {
        assert_eq!(ProjectionAggregate::Card.as_str(), "CARD");
        assert_eq!(
            ProjectionAggregate::parse_static("CARD"),
            Some(ProjectionAggregate::Card)
        );
        assert_eq!(
            ProjectionAggregate::parse_static("ELIGIBILITY"),
            Some(ProjectionAggregate::Eligibility)
        );
        // 未知聚合（fail-closed 的输入）必须被拒绝
        assert_eq!(ProjectionAggregate::parse_static("UNKNOWN"), None);
    }

    #[test]
    fn fenced_sql_preserves_terminal_contract_and_exact_claim() {
        assert!(MARK_PROCESSED_SQL.contains("status = 'PROCESSED'"));
        assert!(MARK_PROCESSED_SQL.contains("processed_at = NOW()"));
        assert!(MARK_PROCESSED_SQL.contains("processed_by = ?"));
        assert!(MARK_PROCESSED_SQL.contains("terminal_transitions = terminal_transitions + 1"));
        assert!(MARK_OBSOLETE_SQL.contains("status = 'PROCESSED'"));
        assert!(MARK_OBSOLETE_SQL.contains("processed_at = NOW()"));
        assert!(MARK_OBSOLETE_SQL.contains("processed_by = ?"));
        assert!(MARK_OBSOLETE_SQL.contains("terminal_transitions = terminal_transitions + 1"));
        assert!(MARK_OBSOLETE_SQL.contains("SUPERSEDED_BY_NEWER_GENERATION"));
        assert!(RELEASE_FAILED_SQL.contains("status = 'PENDING'"));
        assert!(RELEASE_FAILED_SQL.contains("terminal_transitions = terminal_transitions + 1"));
        assert!(RELEASE_FAILED_SQL.contains("lease_expires_at > NOW()"));
    }
}
