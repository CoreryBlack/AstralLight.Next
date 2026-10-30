//! Source-correlation and eligibility outbox persistence.
//!
//! Source owners append head/outbox records in their existing short transactions.
//! The consumer handles CARD/RULE_SET correlation and physical ELIGIBILITY
//! invalidation. Its terminal state never proves owned V6 publication.
//! Source generation, revoke fence and last event identity remain durable facts.

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;
use astral_types::ProjectionAggregate;

use crate::repository::authorization_source_transaction::AuthorizationSourceTransaction;

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
/// Source-correlation and eligibility outbox consumer port.
/// Source owners append in their own transactions; this port cannot create work.
#[async_trait]
pub trait ProjectionRepository: Send + Sync {
    /// worker 认领待处理事件（按 aggregate,id,generation 排序，最多 batch 条），
    /// 租约 lease_secs 内未处理完成会被其他 worker 重新认领
    async fn claim_pending_events(
        &self,
        batch: i64,
        worker_id: &str,
        lease_secs: i64,
    ) -> Result<Vec<OutboxEventRecord>, AstralError>;

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

/// Append a RuleSet source-correlation event with trusted actor and operation metadata.
/// The caller owns the source transaction and the matching ledger/audit writes.
pub(crate) async fn append_rule_set_projection_in_tx(
    tx: &mut AuthorizationSourceTransaction,
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
pub(crate) async fn append_rule_set_projection_with_tenant_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    rule_set_id: i64,
    event_type: &str,
    metadata: astral_db::ProjectionEventMetadata<'_>,
    tenant_id: Option<i64>,
) -> Result<astral_db::ProjectionEventIdentity, AstralError> {
    let identity = astral_db::append_projection_event_with_metadata_and_tenant_in_tx(
        tx,
        ProjectionAggregate::RuleSet,
        rule_set_id,
        event_type,
        Some(metadata),
        tenant_id,
    )
    .await?;
    tx.record_source_projection_identity(
        ProjectionAggregate::RuleSet,
        rule_set_id,
        identity.clone(),
    )?;
    Ok(identity)
}

/// Append CARD source correlation in the caller's existing source transaction.
pub(crate) async fn append_card_projection_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    card_id: i64,
    event_type: &str,
) -> Result<astral_db::ProjectionEventIdentity, AstralError> {
    let identity = astral_db::append_projection_event_with_metadata_in_tx(
        tx,
        ProjectionAggregate::Card,
        card_id,
        event_type,
        None,
    )
    .await?;
    tx.record_source_projection_identity(ProjectionAggregate::Card, card_id, identity.clone())?;
    Ok(identity)
}

/// 追加携带可信 actor/operation 元数据的 CARD 投影事件，返回 durable 事件身份。
///
/// 审批事务把返回的 `ProjectionEventIdentity`（event/generation/fence）绑定进
/// 授权账本 delta 必须使用返回的 ProjectionEventIdentity 绑定 event/generation/fence。
/// 本函数不 commit，也不触发网络或物化；调用方负责事务提交或回滚。
pub(crate) async fn append_card_projection_with_metadata_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    card_id: i64,
    event_type: &str,
    metadata: astral_db::ProjectionEventMetadata<'_>,
) -> Result<astral_db::ProjectionEventIdentity, AstralError> {
    let identity = astral_db::append_projection_event_with_metadata_in_tx(
        tx,
        ProjectionAggregate::Card,
        card_id,
        event_type,
        Some(metadata),
    )
    .await?;
    tx.record_source_projection_identity(ProjectionAggregate::Card, card_id, identity.clone())?;
    Ok(identity)
}

#[async_trait]
impl ProjectionRepository for SqlxProjectionRepository {
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
