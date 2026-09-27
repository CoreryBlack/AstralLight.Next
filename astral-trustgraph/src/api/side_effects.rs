//! 写操作副作用编排
//!
//! 写路径 source mutation 后调用 `request_card_projection` 落 durable 事件（head
//! 递增 + outbox PENDING）。读链切换批次 3 起，CARD/RULE_SET 的快照重建与缓存
//! 失效职责已移交新链 `authorization_projector` delta 队列；本 worker
//! （`service::projection_worker`）仅保留 ELIGIBILITY 资格缓存失效通道（存续
//! 职责，决策见 Docs/架构/Rust架构设计/Rust增量重建与实时授权边界_V1.0.md §3.4）。
//!
//! 这些函数不阻塞主操作，失败仅记日志（side-effect-only 语义）。

use std::sync::OnceLock;

use lapin::Channel;
use redis::AsyncCommands;
use sqlx::MySqlPool;

use astral_db::permission_cache_key;
use astral_mq::producer::{AuthSessionRevocationPayload, Producer};
use astral_types::{ProjectionAggregate, EVENT_TYPE_RULE_SET_UPDATE};

use crate::repository::projection_repository::{ProjectionRepository, SqlxProjectionRepository};

/// 全局 MQ producer（由 main.rs 在初始化时设置）
static MQ_PRODUCER: OnceLock<Producer> = OnceLock::new();

/// 设置全局 MQ producer（在 main.rs 完成 MQ 连接后调用）
pub fn init_mq_producer(channel: Channel) {
    let producer = Producer::new(channel);
    let _ = MQ_PRODUCER.set(producer);
}

/// 卡片授权变更落 durable 投影事件（对齐 Java `PermissionRefreshService.requestCardProjection`）。
///
/// 由写 service 的副作用适配层调用；失败记补偿记录，由 worker 或补偿任务兜底。
pub(crate) async fn request_card_projection(
    pool: &MySqlPool,
    card_id: i64,
    event_type: &str,
) -> Result<(), astral_types::AstralError> {
    let repo = SqlxProjectionRepository::new(pool.clone());
    match repo.request_card_projection(card_id, event_type).await {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::error!(
                card_id,
                event_type,
                error = %error,
                "request_card_projection failed, recording compensation"
            );
            record_compensation(
                pool,
                card_id,
                &format!("REQUEST_PROJECTION:{event_type}"),
                &error.to_string(),
            )
            .await
            .map_err(|compensation_error| {
                astral_types::AstralError::Database(format!(
                    "projection failed: {error}; compensation recording failed: {compensation_error}"
                ))
            })?;
            Err(error)
        }
    }
}

/// 发布会话撤销命令。MQ 不可用时写入 durable compensation，调用方可据此
/// 将管理员禁用响应标记为 pending，而不是把未发送的撤销当作成功。
pub(crate) async fn publish_auth_session_revocation(
    pool: &MySqlPool,
    user_id: i64,
    reason: &str,
) -> Result<(), astral_types::AstralError> {
    let operation_id = uuid::Uuid::new_v4().to_string();
    let Some(producer) = MQ_PRODUCER.get() else {
        record_compensation(
            pool,
            user_id,
            &format!("AUTH_SESSION_REVOCATION:{operation_id}:{reason}"),
            "MQ producer not initialized",
        )
        .await
        .map_err(|error| {
            astral_types::AstralError::Database(format!(
                "auth session revocation compensation failed: {error}"
            ))
        })?;
        return Err(astral_types::AstralError::Internal(
            "auth session revocation pending".into(),
        ));
    };
    match producer
        .publish_auth_session_revocation(AuthSessionRevocationPayload {
            message_id: Some(operation_id.clone()),
            operation_id: Some(operation_id.clone()),
            user_id,
            reason: reason.to_string(),
            timestamp: astral_mq::producer::now_timestamp(),
        })
        .await
    {
        Ok(()) => Ok(()),
        Err(error) => {
            record_compensation(
                pool,
                user_id,
                &format!("AUTH_SESSION_REVOCATION:{operation_id}:{reason}"),
                &error.to_string(),
            )
            .await
            .map_err(|compensation_error| {
                astral_types::AstralError::Database(format!(
                    "auth session revocation failed: {error}; compensation recording failed: {compensation_error}"
                ))
            })?;
            Err(astral_types::AstralError::Internal(
                "auth session revocation pending".into(),
            ))
        }
    }
}

/// 构造 CARD 维度需要失效的 Redis keys。
///
/// `permission_cache_key` 是正式 permission_query/read path 的唯一 key builder：
/// 无租户时只返回 `perm:card:{card_id}`；租户已知时同时返回无租户键和当前租户
/// 的精确键，绝不使用跨租户 pattern。租户缺失时不能安全推导 scoped key，调用方
/// 必须依赖 projection generation gate 拒绝旧缓存，而不是误删其他租户的键。
///
/// 【孤儿键清理】`permission:snapshot:{card_id}`（旧 head/snapshot 读链遗留）
/// 与 `perm:refs:{card_id}`（旧 MAX(version_no) 引用缓存遗留）在 Rust 生产
/// 零读写（读链切换批次 3 起，无任何 crate 依赖 astral-cache 旧缓存实现），
/// 不再进入失效清单；残留条目无读取方，按各自 TTL 自然过期。Java 共享契约
/// 键（`perm:card:status` / `astral:permission:card`）必须保留，禁止清理。
pub fn card_cache_keys(card_id: i64, tenant_id: Option<i64>) -> Vec<String> {
    let mut keys = vec![
        format!("perm:card:active:{card_id}"),
        // 正式 permission_query/read path 的 unscoped key。
        permission_cache_key(card_id, None),
        // Java 共享 Redis 契约键（对齐 MQConstants 与 PermissionCacheService）：
        // 卡状态缓存与卡快照遗留键，Java 读侧 TTL 3600，卡状态/授权变更后必须
        // 清理，否则 Java 读侧最长 1 小时 stale-ACTIVE / 旧权限。
        format!("perm:card:status:{card_id}"),
        format!("astral:permission:card:{card_id}"),
    ];
    if let Some(tenant_id) = tenant_id {
        keys.push(permission_cache_key(card_id, Some(tenant_id)));
    }
    keys
}

/// 清除卡片级 Redis 缓存（fire-and-forget，对齐 Java `PermissionCacheService.evictCardCache`）。
///
/// 兼容没有租户上下文的既有调用方：只删除安全的 unscoped permission key，
/// 不猜测租户，不扫描 `perm:card:*:{card_id}`。
pub async fn evict_card_cache(card_id: i64) {
    evict_card_cache_for_tenant(card_id, None).await;
}

/// 清除带有可信租户上下文的卡片级 Redis 缓存。
///
/// projection outbox 的 `tenant_id` 来源于 `user_card` source row；租户存在时
/// 只删除该租户的精确 `perm:card:{tenant_id}:{card_id}`，同时删除 unscoped
/// 兼容键。Redis 失败仍仅记录 warning，读侧 generation gate 保持 fail-closed。
pub async fn evict_card_cache_for_tenant(card_id: i64, tenant_id: Option<i64>) {
    // 同进程 L1 资格缓存即时 evict（性能优化卡点 1）：card_cache_keys 含
    // `perm:card:active:{card_id}`，user_card 状态变更/删除路径经此失效；
    // 跨实例依赖 astral-db L1 层 5s TTL 自然过期（显式取舍，见 eligibility 模块文档）。
    astral_db::evict_l1_card_active_cache(card_id);
    let keys = card_cache_keys(card_id, tenant_id);
    delete_redis_keys(&keys, card_id, "evict_card_cache").await;
}

/// 清除 ELIGIBILITY 资格门禁缓存（fire-and-forget，对齐 `check_card_active` 的
/// `perm:card:active:{card_id}` 正/负缓存键）。
///
/// ELIGIBILITY 通道是轻量投影：只失效资格缓存，**不**重建 `permission_rule_snapshot`，
/// **不**清理规则快照。资格读侧通过 ELIGIBILITY
/// gate 的版本检查放行（head READY 且 source==projected 才读，见
/// `astral-db::CardEligibilityService` 的投影门禁）。
pub async fn evict_eligibility_gate_cache(card_id: i64) {
    // 同进程 L1 资格缓存即时 evict（性能优化卡点 1）：跨实例依赖 astral-db
    // L1 层 5s TTL 自然过期（显式取舍，见 eligibility 模块文档）。
    astral_db::evict_l1_card_active_cache(card_id);
    let keys = [format!("perm:card:active:{card_id}")];
    delete_redis_keys(&keys, card_id, "evict_eligibility_gate_cache").await;
}

/// Redis 连接地址选择（纯函数）：`REDIS_URL` 优先，其次 `ASTRAL_REDIS_URL`；
/// 两者均未设置时返回 `None`，调用方保留 fail-closed 观测而不尝试 localhost。
fn redis_url_from_env(
    redis_url: Option<String>,
    astral_redis_url: Option<String>,
) -> Option<String> {
    redis_url
        .or(astral_redis_url)
        .filter(|value| !value.trim().is_empty())
}

/// 共享 Redis DEL 执行器（fire-and-forget）：打不开客户端/连接失败仅记 warning，
/// 单 key 删除失败不阻断其余 key（side-effect-only 语义）。
async fn delete_redis_keys(keys: &[String], aggregate_id: i64, op: &str) {
    if keys.is_empty() {
        return;
    }
    let Some(redis_url) = redis_url_from_env(
        std::env::var("REDIS_URL").ok(),
        std::env::var("ASTRAL_REDIS_URL").ok(),
    ) else {
        tracing::warn!(
            aggregate_id,
            op,
            "Redis URL is not configured; cache eviction skipped"
        );
        return;
    };
    let Ok(client) = redis::Client::open(redis_url.as_str()) else {
        tracing::warn!(aggregate_id, op, "failed to open Redis client");
        return;
    };
    let Ok(mut conn) = client.get_connection_manager().await else {
        tracing::warn!(aggregate_id, op, "failed to connect Redis");
        return;
    };
    for key in keys {
        if let Err(e) = conn.del::<_, ()>(key).await {
            tracing::warn!(aggregate_id, op, key = %key, error = %e, "Redis DEL failed");
        }
    }
}

// 【读链切换批次 3.5 退役】旧 `evict_rule_set_cache`
// （`permission:ruleset:{rule_set_id}` 同步 DEL）已删除：规则集读链不再存在
// 任何 Redis 快照缓存可失效（唯一消费者 PermissionSideEffects 端口同步退役）；
// 缓存失效由 worker 的 ELIGIBILITY 通道与写服务同步 evict 承担。

/// 兼容 service trait 的副作用适配器：仅追加 durable projection 事件。
///
/// 快照重建职责已移交新链 authorization_projector delta 队列（读链切换批次 3）；
/// 缓存失效由 worker 的 ELIGIBILITY 通道与写服务同步 evict 承担，禁止同步旁路。
pub(crate) async fn rebuild_card_snapshot(pool: &MySqlPool, card_id: i64) {
    if let Err(error) = request_card_projection(pool, card_id, "CARD_REBUILD").await {
        tracing::error!(card_id, error = %error, "durable card projection request failed");
    }
}

/// Compatibility adapter retained for the existing service trait.
///
/// RuleSet source mutations append the RULE_SET projection event in their source
/// transaction. Snapshot rebuild and cache eviction are owned by the new-chain
/// authorization_projector delta queue (legacy worker rebuild retired in read-chain
/// switch batch 3), so this post-commit method intentionally performs no synchronous
/// database or cache side effect.
pub async fn rebuild_rule_set_snapshot(
    _pool: &MySqlPool,
    _rule_set_id: i64,
) -> Result<(), astral_types::AstralError> {
    Ok(())
}

// 删除规则集后的级联副作用已由 RuleSetRepository 的删除事务完成；
// 删除后再回查绑定关系无法证明数据完整性，故不再提供该兼容入口。

// 【读链切换批次 3】旧链快照重建家族（CARD/RULE_SET 快照 rebuild 内部函数、
// 胜者选择、evidence/claim/manifest 锁、以及规则集投影缓存批量失效）已整体
// 退役：CARD/RULE_SET 投影的权威消费者是新链 authorization_projector delta
// 队列，本模块不再持有任何 permission_rule_snapshot / rule_set_snapshot 写
// 路径（决策见 Docs/架构/Rust架构设计/Rust增量重建与实时授权边界_V1.0.md §3.4）。
// 保留面：ELIGIBILITY 资格缓存失效（worker 存续职责）、user_card_service
// 同步 evict 所需的 card_cache_keys / evict_card_cache 家族，以及
// retry_pending_compensations 的既有补偿行类型（含 REBUILD_SNAPSHOT 兼容处置）。

/// 补偿租约窗口（秒）：worker 领取后该窗口内其他 worker 不重复处理。
const COMPENSATION_LEASE_SECS: i64 = 60;
/// 补偿最大重试次数（超出置 FAILED）。
const MAX_COMPENSATION_RETRY: i32 = 10;

/// 记录补偿信息（失败时写入 pending_compensation 表，供后续补偿任务重试）
///
/// `op_type` may include a colon-delimited event type, for example
/// `REQUEST_PROJECTION:CARD_REVOKE`, so the retry path can preserve revoke
/// semantics without changing the existing table contract.
pub(crate) async fn record_compensation(
    pool: &MySqlPool,
    entity_id: i64,
    op_type: &str,
    error_msg: &str,
) -> Result<(), astral_types::AstralError> {
    sqlx::query(
        "INSERT INTO pending_compensation (entity_id, op_type, error_msg, status, created_at) VALUES (?, ?, ?, 'PENDING', NOW())",
    )
    .bind(entity_id)
    .bind(op_type)
    .bind(error_msg)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|error| {
        tracing::error!(entity_id, op_type, error = %error, "failed to record compensation");
        astral_types::AstralError::Database(format!("compensation insert failed: {error}"))
    })
}

async fn retry_auth_session_revocation(
    _pool: &MySqlPool,
    user_id: i64,
    operation_id: &str,
    reason: &str,
) -> Result<(), astral_types::AstralError> {
    if operation_id.trim().is_empty() {
        return Err(astral_types::AstralError::Validation(
            "auth session revocation operation id is empty".into(),
        ));
    }
    let Some(producer) = MQ_PRODUCER.get() else {
        return Err(astral_types::AstralError::Internal(
            "MQ producer not initialized".into(),
        ));
    };
    producer
        .publish_auth_session_revocation(AuthSessionRevocationPayload {
            message_id: Some(operation_id.to_string()),
            operation_id: Some(operation_id.to_string()),
            user_id,
            reason: reason.to_string(),
            timestamp: astral_mq::producer::now_timestamp(),
        })
        .await
        .map_err(|error| astral_types::AstralError::Internal(error.to_string()))
}

async fn retry_find_bound_cards(pool: &MySqlPool, rule_set_id: i64) -> Result<(), String> {
    let cards: Vec<i64> =
        sqlx::query_scalar("SELECT DISTINCT card_id FROM card_rule_set_ref WHERE rule_set_id = ?")
            .bind(rule_set_id)
            .fetch_all(pool)
            .await
            .map_err(|error| error.to_string())?;
    for card_id in cards {
        SqlxProjectionRepository::new(pool.clone())
            .request_card_projection(card_id, EVENT_TYPE_RULE_SET_UPDATE)
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// 新 crate。语义（对齐本批次审查要求）：
/// - claim/lease：无 lease 列，用 `updated_at` 时间窗模拟租约——领取后先将
///   `updated_at = NOW()` 作为租约标记，`COMPENSATION_LEASE_SECS` 内其他 worker
///   不会重复处理；处理失败更新 `retry_count` + `updated_at` 进入冷却，超
///   `MAX_COMPENSATION_RETRY` 置 `FAILED`。
/// - 未知操作：结构化告警并置 `FAILED` 明确终态（此前会永远滞留 PENDING）。
/// - 幂等兜底：`request_card_projection` 本身幂等（head+outbox 递增；CARD/RULE_SET
///   事件由旧 worker 终态 mark_processed 跳过，ELIGIBILITY 走 superseded 判定），
///   并发窗口内的重复处理无害。
/// - 退役处置（读链切换批次 3）：历史 `REBUILD_SNAPSHOT` 补偿行按兼容处置标记
///   COMPLETED（快照重建职责已移交新链 authorization_projector delta 队列）。
pub async fn retry_pending_compensations(
    pool: &MySqlPool,
    batch_size: i64,
) -> Result<u64, sqlx::Error> {
    let batch_size = batch_size.clamp(1, 100);
    let rows = sqlx::query_as::<_, (i64, i64, String, i32)>(
        "SELECT id, entity_id, op_type, retry_count \
         FROM pending_compensation \
         WHERE (status = 'PENDING' \
                AND (retry_count = 0 OR updated_at <= NOW() - INTERVAL ? SECOND)) \
            OR (status = 'PROCESSING' AND updated_at <= NOW() - INTERVAL ? SECOND) \
         ORDER BY id LIMIT ?",
    )
    .bind(COMPENSATION_LEASE_SECS)
    .bind(COMPENSATION_LEASE_SECS)
    .bind(batch_size)
    .fetch_all(pool)
    .await?;

    let mut completed = 0u64;
    for (id, entity_id, op_type, retry_count) in rows {
        // 抢租约：仅当仍 PENDING 且租约窗口已过时更新，防止并发 worker 重复处理。
        let claimed = sqlx::query(
            "UPDATE pending_compensation SET status = 'PROCESSING', updated_at = NOW() \
             WHERE id = ? AND ( \
               (status = 'PENDING' AND (retry_count = 0 OR updated_at <= NOW() - INTERVAL ? SECOND)) \
               OR (status = 'PROCESSING' AND updated_at <= NOW() - INTERVAL ? SECOND) \
             )",
        )
        .bind(id)
        .bind(COMPENSATION_LEASE_SECS)
        .bind(COMPENSATION_LEASE_SECS)
        .execute(pool)
        .await?
        .rows_affected();
        if claimed != 1 {
            // 另一 worker 已认领，跳过
            continue;
        }

        let result: Result<(), String> = {
            let mut parts = op_type.splitn(4, ':');
            let base_type = parts.next().unwrap_or_default();
            let detail = parts.next().unwrap_or_default();
            let reason = if base_type == "AUTH_SESSION_REVOCATION" {
                parts
                    .next()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or("GLOBAL_ADMIN_DISABLED")
            } else {
                "GLOBAL_ADMIN_DISABLED"
            };
            let event_type = if base_type == "REQUEST_PROJECTION" {
                detail
            } else {
                EVENT_TYPE_RULE_SET_UPDATE
            };
            match base_type {
                "REQUEST_PROJECTION" => SqlxProjectionRepository::new(pool.clone())
                    .request_card_projection(entity_id, event_type)
                    .await
                    .map_err(|e| e.to_string()),
                // Compensation has no verified HTTP actor. Use the explicit
                // documented system context rather than silently creating a
                // metadata-free RuleSet event.
                "REQUEST_RULE_SET_PROJECTION" => {
                    let operation_id = format!("compensation:ruleset-projection:{id}");
                    let context =
                        crate::repository::audit_log_repository::RuleSetMutationContext::system(
                            &operation_id,
                        )
                        .map_err(|e| e.to_string())
                        .map_err(sqlx::Error::Protocol)?;
                    let mut tx = pool.begin().await?;
                    let projection =
                        crate::repository::projection_repository::append_rule_set_projection_in_tx(
                            &mut tx,
                            entity_id,
                            EVENT_TYPE_RULE_SET_UPDATE,
                            astral_db::ProjectionEventMetadata {
                                actor_id: context.actor_id(),
                                operation_id: context.operation_id(),
                            },
                        )
                        .await
                        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                    crate::repository::audit_log_repository::insert_rule_set_projection_audit_in_tx(
                        &mut tx,
                        &crate::repository::audit_log_repository::RuleSetProjectionAuditEntry {
                            rule_set_id: entity_id,
                            entry_id: None,
                            aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                            aggregate_id: entity_id,
                            event_id: &projection.event_id,
                            source_generation: projection.source_generation,
                            operation_id: context.operation_id(),
                            actor_id: context.actor_id(),
                            change_type: "COMPENSATION_REQUEST",
                            old_value_json: None,
                            new_value_json: None,
                            tenant_id: projection.tenant_id,
                        },
                    )
                    .await
                    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
                    tx.commit().await.map_err(|e| e.to_string())
                }
                // 兼容处置（读链切换批次 3）：旧链卡快照重建已退役，新链
                // authorization_projector delta 队列是快照重建的唯一权威
                // owner。pending_compensation 表可能仍存在历史 REBUILD_SNAPSHOT
                // 待重试行（现行写路径已不再产生该类型），其对应动作不可再执行、
                // 也不应重试——标记 COMPLETED 终态并留痕，防止无限重试；审计
                // 对账以本日志与 authorization_projector 的发布证据为准。
                "REBUILD_SNAPSHOT" => {
                    tracing::warn!(
                        id,
                        entity_id,
                        op_type,
                        "legacy REBUILD_SNAPSHOT compensation retired; snapshot rebuild ownership moved to authorization_projector delta queue"
                    );
                    Ok(())
                }
                "AUTH_SESSION_REVOCATION" => {
                    retry_auth_session_revocation(pool, entity_id, detail, reason)
                        .await
                        .map_err(|e| e.to_string())
                }
                "FIND_BOUND_CARDS" => retry_find_bound_cards(pool, entity_id).await,
                _ => {
                    // 未知操作：结构化告警 + 明确终态，不再滞留 PROCESSING
                    tracing::error!(
                        id,
                        entity_id,
                        op_type,
                        "compensation: unknown op, marking FAILED for manual review"
                    );
                    sqlx::query(
                        "UPDATE pending_compensation SET status = 'FAILED', \
                         error_msg = ?, updated_at = NOW() \
                         WHERE id = ? AND status = 'PROCESSING'",
                    )
                    .bind(format!("unknown compensation op: {op_type}"))
                    .bind(id)
                    .execute(pool)
                    .await?;
                    continue;
                }
            }
        };

        match result {
            Ok(()) => {
                sqlx::query(
                    "UPDATE pending_compensation SET status = 'COMPLETED', updated_at = NOW() WHERE id = ? AND status = 'PROCESSING'",
                )
                .bind(id)
                .execute(pool)
                .await?;
                completed += 1;
            }
            Err(error) => {
                let next_retry = retry_count.saturating_add(1);
                if next_retry >= MAX_COMPENSATION_RETRY {
                    tracing::error!(id, entity_id, op_type, error = %error, "compensation exhausted");
                    sqlx::query(
                        "UPDATE pending_compensation SET status = 'FAILED', retry_count = ?, error_msg = ?, updated_at = NOW() WHERE id = ? AND status = 'PROCESSING'",
                    )
                    .bind(next_retry)
                    .bind(error)
                    .bind(id)
                    .execute(pool)
                    .await?;
                } else {
                    // 释放租约并进入冷却（updated_at = NOW() → 租约窗口内不重复处理）
                    sqlx::query(
                        "UPDATE pending_compensation SET retry_count = ?, error_msg = ?, updated_at = NOW() WHERE id = ? AND status = 'PROCESSING'",
                    )
                    .bind(next_retry)
                    .bind(error)
                    .bind(id)
                    .execute(pool)
                    .await?;
                }
            }
        }
    }
    Ok(completed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_cache_keys_without_tenant_only_include_safe_unscoped_permission_key() {
        let keys = card_cache_keys(7, None);

        assert_eq!(
            keys,
            vec![
                "perm:card:active:7",
                "perm:card:7",
                "perm:card:status:7",
                "astral:permission:card:7",
            ]
        );
        assert!(!keys.iter().any(|key| key == "perm:card:3:7"));
    }

    #[test]
    fn card_cache_keys_with_tenant_include_only_that_scoped_permission_key() {
        let keys = card_cache_keys(7, Some(3));

        assert_eq!(
            keys,
            vec![
                "perm:card:active:7",
                "perm:card:7",
                "perm:card:status:7",
                "astral:permission:card:7",
                "perm:card:3:7",
            ]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
        );
        assert!(!keys.iter().any(|key| key == "perm:card:4:7"));
    }

    /// 【孤儿键清理锁定】Rust 生产零读写的遗留键族不再进入失效清单；
    /// Java 共享契约键必须保留（Java 读侧 TTL 3600 内的 stale 防线）。
    #[test]
    fn card_cache_keys_drop_orphan_legacy_families_but_keep_java_contract_keys() {
        let keys = card_cache_keys(7, Some(3));

        // 孤儿键族：Rust 生产零读写，evict 已随读链切换退役。
        assert!(!keys.iter().any(|key| key == "permission:snapshot:7"));
        assert!(!keys.iter().any(|key| key == "perm:refs:7"));

        // Java 共享契约键：evict 必须保留，禁止加前缀/改格式。
        assert!(keys.iter().any(|key| key == "perm:card:status:7"));
        assert!(keys.iter().any(|key| key == "astral:permission:card:7"));
        assert!(keys.iter().any(|key| key == "perm:card:active:7"));
    }

    #[test]
    fn redis_url_selection_prefers_redis_url_then_astral_then_none() {
        // REDIS_URL 优先于 ASTRAL_REDIS_URL
        assert_eq!(
            redis_url_from_env(
                Some("redis://primary:6379".into()),
                Some("redis://secondary:6379".into())
            ),
            Some("redis://primary:6379".into())
        );
        // REDIS_URL 未设置时回退 ASTRAL_REDIS_URL
        assert_eq!(
            redis_url_from_env(None, Some("redis://secondary:6379".into())),
            Some("redis://secondary:6379".into())
        );
        // 两者均未设置时不尝试 localhost，返回 None。
        assert_eq!(redis_url_from_env(None, None), None);
    }

    /// 【读链切换批次 3 结构锁定】快照重建家族退役后，本模块不得再出现任何
    /// `permission_rule_snapshot` / `rule_set_snapshot` 写路径符号；ELIGIBILITY
    /// 资格缓存失效与补偿 REBUILD_SNAPSHOT 兼容处置必须保留（worker 存续职责，
    /// 决策见 Rust增量重建与实时授权边界_V1.0.md §3.4）。
    /// （禁用符号用 concat! 拼接，避免 include_str 扫描命中测试自身的字面量。）
    #[test]
    fn legacy_snapshot_rebuild_family_is_retired_with_compensation_compat() {
        let source = include_str!("side_effects.rs");
        for retired in [
            concat!("rebuild_", "card_snapshot_inner"),
            concat!("rebuild_", "rule_set_snapshot_inner"),
            concat!("select_", "card_snapshot_winners"),
            concat!("select_", "rule_set_snapshot_winners"),
            concat!("evict_", "rule_set_projection_caches"),
            concat!("RuleSetProjection", "Claim"),
            concat!("RuleSetSnapshot", "Rebuild"),
            concat!("rule_set_snapshot_", "manifest"),
        ] {
            assert!(
                !source.contains(retired),
                "retired legacy symbol must not reappear in side_effects: {retired}"
            );
        }
        assert!(
            source.contains("\"REBUILD_SNAPSHOT\" =>"),
            "pending_compensation may still hold legacy REBUILD_SNAPSHOT rows; a compatible disposition must remain"
        );
        assert!(
            source.contains("fn evict_eligibility_gate_cache"),
            "ELIGIBILITY gate cache eviction is the worker's survival responsibility (§3.4)"
        );
        assert!(
            source.contains("fn card_cache_keys"),
            "user_card_service 同步 evict 依赖 card_cache_keys 键集，不得随退役误删"
        );
    }
}
