//! 公共投影事务写入器 — 与 source mutation 同事务落 durable 投影事件
//!
//! 投影链写侧的**唯一公共实现**：source mutation（user_card 增删改、资格状态变更、
//! starter-card 注册等）必须在同一事务内调用 `append_projection_event_in_tx` 落
//! `authorization_projection_head` + `authorization_projection_outbox` durable 事件，
//! 由 projection worker 在提交后重建快照、显式失效缓存并发布刷新消息。
//!
//! 语义与 TrustGraph `append_aggregate_projection_in_tx` 完全一致：
//! - tenant_id 取对应聚合 source row（CARD/ELIGIBILITY 为 `user_card`，RULE_SET 为
//!   `rule_set`），避免使用不可信的请求上下文；
//! - head `FOR UPDATE` 串行化；`source_generation` +1（首事件为 1）；
//! - 仅 `event_type == EVENT_TYPE_REVOKE` 时 `revoke_fence` +1（其余事件围栏不变）；
//! - head 置 `PENDING`；outbox 落 `PENDING` 事件（event_id=UUID、
//!   `sequence_number` = `source_generation`、payload JSON）。
//!
//! 事务内仅写 head/outbox，**不访问 Redis/MQ**；提交后的快照重建、缓存失效与 MQ 发布
//! 全部由 projection worker 负责。本模块不依赖 TrustGraph/MQ，仅依赖 astral-types 的
//! `ProjectionAggregate` / 事件常量与 sqlx/serde_json/uuid。

use sqlx::MySql;

use astral_types::{
    AstralError, ProjectionAggregate, EVENT_TYPE_CARD_UPDATE, EVENT_TYPE_ELIGIBILITY_UPDATE,
    EVENT_TYPE_REVOKE, EVENT_TYPE_RULE_SET_UPDATE, SYSTEM_ACTOR_ID,
};

const CARD_PROJECTION_EVENT_TYPES: &[&str] = &[
    "CARD_CREATED",
    EVENT_TYPE_CARD_UPDATE,
    EVENT_TYPE_REVOKE,
    "CARD_RESTORED",
    "CARD_BOUND",
    "DELEGATION_CREATED",
    "DELEGATION_UPDATED",
    "RULE_SET_BOUND",
    "SUPER_ADMIN_GRANTED",
    "APPROVED",
    "RULE_CREATED",
    "RULE_UPDATED",
    "CARD_REBUILD",
    "GRANT",
    EVENT_TYPE_RULE_SET_UPDATE,
];
const ELIGIBILITY_PROJECTION_EVENT_TYPES: &[&str] = &[EVENT_TYPE_ELIGIBILITY_UPDATE];
const RULE_SET_PROJECTION_EVENT_TYPES: &[&str] = &[EVENT_TYPE_RULE_SET_UPDATE, EVENT_TYPE_REVOKE];

fn event_type_allowed(aggregate: ProjectionAggregate, event_type: &str) -> bool {
    let allowed = match aggregate {
        ProjectionAggregate::Card => CARD_PROJECTION_EVENT_TYPES,
        ProjectionAggregate::Eligibility => ELIGIBILITY_PROJECTION_EVENT_TYPES,
        ProjectionAggregate::RuleSet => RULE_SET_PROJECTION_EVENT_TYPES,
    };
    allowed.contains(&event_type)
}

fn validate_projection_event(
    aggregate: ProjectionAggregate,
    aggregate_id: i64,
    event_type: &str,
) -> Result<(), AstralError> {
    if aggregate_id <= 0 {
        return Err(AstralError::Validation(format!(
            "projection aggregate_id must be positive: {aggregate_id}"
        )));
    }
    if !event_type_allowed(aggregate, event_type) {
        return Err(AstralError::Validation(format!(
            "event type '{event_type}' is not allowed for {aggregate} projection"
        )));
    }
    Ok(())
}

/// Durable identity returned when a source mutation appends a projection event.
/// RuleSet audit rows use this identity to bind source audit evidence to the
/// exact head/outbox generation created by the same transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionEventIdentity {
    pub event_id: String,
    pub source_generation: i64,
    pub revoke_fence: i64,
    pub tenant_id: Option<i64>,
}

/// Trusted mutation metadata serialized into a durable outbox payload. The
/// projection worker uses it to write the post-snapshot audit evidence without
/// inventing an HTTP actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionEventMetadata<'a> {
    pub actor_id: i64,
    pub operation_id: &'a str,
}

const USER_CARD_TENANT_QUERY: &str = "SELECT tenant_id FROM user_card WHERE card_id = ?";
const RULE_SET_TENANT_QUERY: &str = "SELECT tenant_id FROM rule_set WHERE rule_set_id = ?";
const CARD_ID_PAYLOAD_KEY: &str = "cardId";
const RULE_SET_ID_PAYLOAD_KEY: &str = "ruleSetId";
const TENANT_ID_PAYLOAD_KEY: &str = "tenantId";
const GENERATION_PAYLOAD_KEY: &str = "generation";

/// Narrow selector for transaction-scoped ELIGIBILITY fanout.
///
/// Each variant maps to a fixed, parameterized `user_card` predicate. The
/// selected rows are authoritative source rows, locked and ordered by
/// `card_id` before any head/outbox mutation is appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EligibilityCardSelector {
    ByUserId { user_id: i64 },
    ByTenantId { tenant_id: i64 },
    ByTenantAndDomain { tenant_id: i64, domain_id: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::FromRow)]
struct EligibilityCardSourceRow {
    card_id: i64,
    tenant_id: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenantResolution {
    SourceRow,
    Captured(Option<i64>),
}

const ELIGIBILITY_BY_USER_ID_QUERY: &str = "SELECT card_id, tenant_id FROM user_card \\
    WHERE user_id = ? AND card_status = 'ACTIVE' ORDER BY card_id FOR UPDATE";
const ELIGIBILITY_BY_TENANT_ID_QUERY: &str = "SELECT card_id, tenant_id FROM user_card \\
    WHERE tenant_id = ? AND card_status = 'ACTIVE' ORDER BY card_id FOR UPDATE";
const ELIGIBILITY_BY_TENANT_AND_DOMAIN_QUERY: &str = "SELECT card_id, tenant_id FROM user_card \\
    WHERE tenant_id = ? AND domain_id = ? AND card_status = 'ACTIVE' \\
    ORDER BY card_id FOR UPDATE";

fn eligibility_selector_query(selector: EligibilityCardSelector) -> &'static str {
    match selector {
        EligibilityCardSelector::ByUserId { .. } => ELIGIBILITY_BY_USER_ID_QUERY,
        EligibilityCardSelector::ByTenantId { .. } => ELIGIBILITY_BY_TENANT_ID_QUERY,
        EligibilityCardSelector::ByTenantAndDomain { .. } => ELIGIBILITY_BY_TENANT_AND_DOMAIN_QUERY,
    }
}

/// 聚合 source 查询与 payload 身份字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProjectionSource {
    tenant_query: &'static str,
    payload_id_key: &'static str,
}

impl ProjectionSource {
    fn for_aggregate(aggregate: ProjectionAggregate) -> Self {
        match aggregate {
            ProjectionAggregate::Card | ProjectionAggregate::Eligibility => Self {
                tenant_query: USER_CARD_TENANT_QUERY,
                payload_id_key: CARD_ID_PAYLOAD_KEY,
            },
            ProjectionAggregate::RuleSet => Self {
                tenant_query: RULE_SET_TENANT_QUERY,
                payload_id_key: RULE_SET_ID_PAYLOAD_KEY,
            },
        }
    }
}

fn projection_payload(
    aggregate: ProjectionAggregate,
    aggregate_id: i64,
    tenant_id: Option<i64>,
    generation: i64,
) -> serde_json::Value {
    let source = ProjectionSource::for_aggregate(aggregate);
    let mut payload = serde_json::Map::new();
    payload.insert(
        source.payload_id_key.to_owned(),
        serde_json::json!(aggregate_id),
    );
    payload.insert(
        TENANT_ID_PAYLOAD_KEY.to_owned(),
        serde_json::json!(tenant_id),
    );
    payload.insert(
        GENERATION_PAYLOAD_KEY.to_owned(),
        serde_json::json!(generation),
    );
    serde_json::Value::Object(payload)
}

fn validate_projection_head_state(
    source_generation: i64,
    revoke_fence: i64,
) -> Result<(), AstralError> {
    if source_generation < 0 || revoke_fence < 0 || revoke_fence > source_generation {
        return Err(AstralError::Internal(format!(
            "invalid projection head state: source_generation={source_generation}, revoke_fence={revoke_fence}"
        )));
    }
    Ok(())
}

/// 计算给定 head 状态下的新 `source_generation` 与 `revoke_fence`（纯函数，便于单元测试）。
/// `source_generation`=1，`revoke_fence` 视事件类型为 0（非 REVOKE）/1（REVOKE）。
/// 仅 `event_type == EVENT_TYPE_REVOKE` 递增围栏（对齐 Java `isObsoleteVersionedCardRefresh`）。
fn next_projection_generation(
    head: Option<(i64, i64)>,
    event_type: &str,
) -> Result<(i64, i64), AstralError> {
    match head {
        Some((source, fence)) => {
            validate_projection_head_state(source, fence)?;
            let new_source = source.checked_add(1).ok_or_else(|| {
                AstralError::Internal(
                    "projection source_generation overflow while appending event".into(),
                )
            })?;
            let revoke_fence = if event_type == EVENT_TYPE_REVOKE {
                fence.checked_add(1).ok_or_else(|| {
                    AstralError::Internal(
                        "projection revoke_fence overflow while appending event".into(),
                    )
                })?
            } else {
                fence
            };
            Ok((new_source, revoke_fence))
        }
        None => Ok((
            1,
            if event_type == EVENT_TYPE_REVOKE {
                1
            } else {
                0
            },
        )),
    }
}

/// 在调用方已有的 source transaction 中追加任一聚合（CARD/ELIGIBILITY/RULE_SET）投影事件。
///
/// source mutation 与 head/outbox 必须共用同一事务；提交后的快照重建、缓存失效和 MQ
/// 发布仍由 projection worker 负责。调用方不得在此事务内触发 Redis 或 RabbitMQ 副作用。
///
/// # 参数
/// - `tx`：调用方已持有的 source transaction（本函数不 commit，由调用方决定提交/回滚）；
/// - `aggregate`：投影聚合通道（`ProjectionAggregate::Card` / `::Eligibility` /
///   `::RuleSet`），head/outbox 按 `aggregate_type` 分离；
/// - `aggregate_id`：聚合 id（CARD 与 ELIGIBILITY 为 `user_card.card_id`，RULE_SET 为
///   `rule_set.rule_set_id`）；
/// - `event_type`：事件类型字符串（CARD 既有事件类型由调用方传入；公共 REVOKE 判断
///   使用公共常量 `EVENT_TYPE_REVOKE`）。
pub async fn append_projection_event_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    aggregate: ProjectionAggregate,
    aggregate_id: i64,
    event_type: &str,
) -> Result<(), AstralError> {
    append_projection_event_with_metadata_in_tx(tx, aggregate, aggregate_id, event_type, None)
        .await
        .map(|_| ())
}

/// Variant used by RuleSet mutations, which must persist trusted actor and
/// operation metadata in the outbox before the source transaction commits.
pub async fn append_projection_event_with_metadata_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    aggregate: ProjectionAggregate,
    aggregate_id: i64,
    event_type: &str,
    metadata: Option<ProjectionEventMetadata<'_>>,
) -> Result<ProjectionEventIdentity, AstralError> {
    append_projection_event_with_metadata_and_tenant_in_tx(
        tx,
        aggregate,
        aggregate_id,
        event_type,
        metadata,
        None,
    )
    .await
}

/// Append one ELIGIBILITY event for every authoritative ACTIVE user card
/// selected in the caller's existing transaction.
///
/// The selector query locks source rows with `FOR UPDATE` and orders them by
/// `card_id`. Each row's tenant is captured by that same query and passed to
/// the event writer, so this helper performs no per-card source lookup/N+1.
/// The helper does not commit and never touches Redis or MQ.
pub async fn append_eligibility_events_for_cards_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    selector: EligibilityCardSelector,
) -> Result<(), AstralError> {
    let cards = match selector {
        EligibilityCardSelector::ByUserId { user_id } => {
            sqlx::query_as::<_, EligibilityCardSourceRow>(eligibility_selector_query(selector))
                .bind(user_id)
                .fetch_all(&mut **tx)
                .await
        }
        EligibilityCardSelector::ByTenantId { tenant_id } => {
            sqlx::query_as::<_, EligibilityCardSourceRow>(eligibility_selector_query(selector))
                .bind(tenant_id)
                .fetch_all(&mut **tx)
                .await
        }
        EligibilityCardSelector::ByTenantAndDomain {
            tenant_id,
            domain_id,
        } => {
            sqlx::query_as::<_, EligibilityCardSourceRow>(eligibility_selector_query(selector))
                .bind(tenant_id)
                .bind(domain_id)
                .fetch_all(&mut **tx)
                .await
        }
    }
    .map_err(db_error)?;

    for card in cards {
        append_projection_event_with_tenant_in_tx(
            tx,
            ProjectionAggregate::Eligibility,
            card.card_id,
            EVENT_TYPE_ELIGIBILITY_UPDATE,
            card.tenant_id,
        )
        .await?;
    }
    Ok(())
}

/// RuleSet delete variant: the source tenant may have been captured before the
/// source row was deleted, so the caller can preserve that trusted identity in
/// the durable outbox event and its payload.
pub async fn append_projection_event_with_metadata_and_tenant_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    aggregate: ProjectionAggregate,
    aggregate_id: i64,
    event_type: &str,
    metadata: Option<ProjectionEventMetadata<'_>>,
    tenant_id_override: Option<i64>,
) -> Result<ProjectionEventIdentity, AstralError> {
    let tenant_resolution = match tenant_id_override {
        Some(tenant_id) => TenantResolution::Captured(Some(tenant_id)),
        None => TenantResolution::SourceRow,
    };
    append_projection_event_with_tenant_resolution_in_tx(
        tx,
        aggregate,
        aggregate_id,
        event_type,
        metadata,
        tenant_resolution,
    )
    .await
}

async fn append_projection_event_with_tenant_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    aggregate: ProjectionAggregate,
    aggregate_id: i64,
    event_type: &str,
    tenant_id: Option<i64>,
) -> Result<ProjectionEventIdentity, AstralError> {
    append_projection_event_with_tenant_resolution_in_tx(
        tx,
        aggregate,
        aggregate_id,
        event_type,
        None,
        TenantResolution::Captured(tenant_id),
    )
    .await
}

async fn append_projection_event_with_tenant_resolution_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    aggregate: ProjectionAggregate,
    aggregate_id: i64,
    event_type: &str,
    metadata: Option<ProjectionEventMetadata<'_>>,
    tenant_resolution: TenantResolution,
) -> Result<ProjectionEventIdentity, AstralError> {
    validate_projection_event(aggregate, aggregate_id, event_type)?;
    let aggregate_type = aggregate.as_str();
    let source = ProjectionSource::for_aggregate(aggregate);
    if aggregate == ProjectionAggregate::RuleSet {
        let metadata = metadata.ok_or_else(|| {
            AstralError::Auth(
                "RuleSet projection requires a verified actor and operation context".into(),
            )
        })?;
        if metadata.actor_id != SYSTEM_ACTOR_ID && metadata.actor_id <= 0 {
            return Err(AstralError::Auth(
                "RuleSet projection actor must be a positive verified user or SYSTEM_ACTOR_ID"
                    .into(),
            ));
        }
        if metadata.operation_id.trim().is_empty() {
            return Err(AstralError::Validation(
                "RuleSet projection operation id must not be empty".into(),
            ));
        }
    }

    // tenant_id 必须取对应聚合的 source row，避免消息 payload 使用不可信的请求上下文。
    // Bulk ELIGIBILITY fanout 传入同一查询锁定时捕获的值，避免每张卡再次查询 source。
    let tenant_id = match tenant_resolution {
        TenantResolution::SourceRow => {
            let tenant: Option<(Option<i64>,)> = sqlx::query_as(source.tenant_query)
                .bind(aggregate_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(db_error)?;
            tenant.and_then(|row| row.0)
        }
        TenantResolution::Captured(tenant_id) => tenant_id,
    };

    let head: Option<(i64, i64)> = sqlx::query_as(
        "SELECT source_generation, revoke_fence \
         FROM authorization_projection_head \
         WHERE aggregate_type = ? AND aggregate_id = ? FOR UPDATE",
    )
    .bind(aggregate_type)
    .bind(aggregate_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;

    let event_id = uuid::Uuid::new_v4().to_string();
    let (new_source, new_fence) = next_projection_generation(head, event_type)?;
    match head {
        Some(_) => {
            // 旧链投影状态列（projected_generation/projection_status）已退役
            // （迁移 20260831000001）：writer correlation 只维护代次、围栏与
            // last_event_id，CARD/RULE_SET 消费权威在新链 delta 队列。
            sqlx::query(
                "UPDATE authorization_projection_head \
                 SET source_generation = ?, revoke_fence = ?, \
                     last_event_id = ?, updated_at = NOW() \
                 WHERE aggregate_type = ? AND aggregate_id = ?",
            )
            .bind(new_source)
            .bind(new_fence)
            .bind(&event_id)
            .bind(aggregate_type)
            .bind(aggregate_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        }
        None => {
            sqlx::query(
                "INSERT INTO authorization_projection_head \
                 (aggregate_type, aggregate_id, source_generation, \
                  revoke_fence, last_event_id) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(aggregate_type)
            .bind(aggregate_id)
            .bind(new_source)
            .bind(new_fence)
            .bind(&event_id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        }
    }

    let mut payload = projection_payload(aggregate, aggregate_id, tenant_id, new_source);
    if let Some(metadata) = metadata {
        let object = payload.as_object_mut().ok_or_else(|| {
            AstralError::Internal("projection payload must be a JSON object".into())
        })?;
        object.insert("actorId".into(), serde_json::json!(metadata.actor_id));
        object.insert(
            "operationId".into(),
            serde_json::Value::String(metadata.operation_id.to_owned()),
        );
    }
    sqlx::query(
        "INSERT INTO authorization_projection_outbox \
         (event_id, aggregate_type, aggregate_id, tenant_id, event_type, source_generation, \
          sequence_number, revoke_fence, payload_json, status) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')",
    )
    .bind(&event_id)
    .bind(aggregate_type)
    .bind(aggregate_id)
    .bind(tenant_id)
    .bind(event_type)
    .bind(new_source)
    .bind(new_source)
    .bind(new_fence)
    .bind(payload.to_string())
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;

    Ok(ProjectionEventIdentity {
        event_id,
        source_generation: new_source,
        revoke_fence: new_fence,
        tenant_id,
    })
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Projection repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 首事件（head 缺失）：source_generation=1，非 REVOKE 围栏为 0。
    #[test]
    fn first_event_starts_generation_at_one() {
        assert_eq!(
            next_projection_generation(None, "CARD_CREATED").unwrap(),
            (1, 0)
        );
        assert_eq!(
            next_projection_generation(None, EVENT_TYPE_CARD_UPDATE).unwrap(),
            (1, 0)
        );
        assert_eq!(
            next_projection_generation(None, EVENT_TYPE_ELIGIBILITY_UPDATE).unwrap(),
            (1, 0)
        );
        assert_eq!(
            next_projection_generation(None, EVENT_TYPE_RULE_SET_UPDATE).unwrap(),
            (1, 0)
        );
    }

    /// 仅 REVOKE 递增围栏（对齐 Java isObsoleteVersionedCardRefresh）。
    #[test]
    fn revoke_bumps_fence_only_for_revoke() {
        assert_eq!(EVENT_TYPE_REVOKE, "REVOKE");
        assert_ne!(EVENT_TYPE_CARD_UPDATE, EVENT_TYPE_REVOKE);
        assert_ne!(EVENT_TYPE_ELIGIBILITY_UPDATE, EVENT_TYPE_REVOKE);

        // 既有 head (source=2, fence=1)：非 REVOKE 只加代次，REVOKE 同时加围栏。
        assert_eq!(
            next_projection_generation(Some((2, 1)), EVENT_TYPE_CARD_UPDATE).unwrap(),
            (3, 1)
        );
        assert_eq!(
            next_projection_generation(Some((2, 1)), EVENT_TYPE_ELIGIBILITY_UPDATE).unwrap(),
            (3, 1)
        );
        assert_eq!(
            next_projection_generation(Some((2, 1)), EVENT_TYPE_REVOKE).unwrap(),
            (3, 2)
        );
        // 首事件即 REVOKE：围栏从 0 到 1。
        assert_eq!(
            next_projection_generation(None, EVENT_TYPE_REVOKE).unwrap(),
            (1, 1)
        );
    }

    #[test]
    fn projection_event_allowlists_match_active_callers_and_reject_mismatches() {
        // This inventory mirrors every event string currently passed to a CARD
        // projection writer, including compatibility/service fallback paths.
        let card_event_types = [
            "CARD_CREATED",
            EVENT_TYPE_CARD_UPDATE,
            EVENT_TYPE_REVOKE,
            "CARD_RESTORED",
            "CARD_BOUND",
            "DELEGATION_CREATED",
            "DELEGATION_UPDATED",
            "RULE_SET_BOUND",
            "SUPER_ADMIN_GRANTED",
            "APPROVED",
            "RULE_CREATED",
            "RULE_UPDATED",
            "CARD_REBUILD",
            "GRANT",
            EVENT_TYPE_RULE_SET_UPDATE,
        ];
        assert_eq!(CARD_PROJECTION_EVENT_TYPES, card_event_types);
        for event_type in card_event_types {
            assert!(event_type_allowed(ProjectionAggregate::Card, event_type));
            assert!(validate_projection_event(ProjectionAggregate::Card, 1, event_type).is_ok());
        }

        assert_eq!(
            ELIGIBILITY_PROJECTION_EVENT_TYPES,
            &[EVENT_TYPE_ELIGIBILITY_UPDATE]
        );
        assert!(event_type_allowed(
            ProjectionAggregate::Eligibility,
            EVENT_TYPE_ELIGIBILITY_UPDATE
        ));
        assert!(validate_projection_event(
            ProjectionAggregate::Eligibility,
            1,
            EVENT_TYPE_ELIGIBILITY_UPDATE
        )
        .is_ok());

        assert_eq!(
            RULE_SET_PROJECTION_EVENT_TYPES,
            &[EVENT_TYPE_RULE_SET_UPDATE, EVENT_TYPE_REVOKE]
        );
        for event_type in RULE_SET_PROJECTION_EVENT_TYPES {
            assert!(event_type_allowed(ProjectionAggregate::RuleSet, event_type));
            assert!(validate_projection_event(ProjectionAggregate::RuleSet, 1, event_type).is_ok());
        }

        assert!(!event_type_allowed(
            ProjectionAggregate::Card,
            EVENT_TYPE_ELIGIBILITY_UPDATE
        ));
        assert!(!event_type_allowed(
            ProjectionAggregate::Eligibility,
            EVENT_TYPE_CARD_UPDATE
        ));
        assert!(!event_type_allowed(
            ProjectionAggregate::RuleSet,
            EVENT_TYPE_CARD_UPDATE
        ));
        assert!(!event_type_allowed(ProjectionAggregate::Card, "UNKNOWN"));
    }

    #[test]
    fn projection_event_validation_rejects_non_positive_ids_and_unknown_types() {
        for aggregate in ProjectionAggregate::ALL {
            assert!(validate_projection_event(*aggregate, 0, EVENT_TYPE_REVOKE).is_err());
            assert!(validate_projection_event(*aggregate, -1, EVENT_TYPE_REVOKE).is_err());
            assert!(validate_projection_event(*aggregate, 1, "UNKNOWN_EVENT").is_err());
        }
        assert!(validate_projection_event(
            ProjectionAggregate::Card,
            1,
            EVENT_TYPE_ELIGIBILITY_UPDATE
        )
        .is_err());
        assert!(validate_projection_event(
            ProjectionAggregate::Eligibility,
            1,
            EVENT_TYPE_CARD_UPDATE
        )
        .is_err());
        assert!(
            validate_projection_event(ProjectionAggregate::RuleSet, 1, EVENT_TYPE_CARD_UPDATE)
                .is_err()
        );
    }

    #[test]
    fn projection_generation_rejects_invalid_head_state() {
        for head in [Some((-1, 0)), Some((1, -1)), Some((0, 1)), Some((1, 2))] {
            assert!(next_projection_generation(head, EVENT_TYPE_CARD_UPDATE).is_err());
        }
        // A zeroed head is the schema's initial state and may append its first event.
        assert_eq!(
            next_projection_generation(Some((0, 0)), EVENT_TYPE_CARD_UPDATE).unwrap(),
            (1, 0)
        );
    }

    #[test]
    fn projection_generation_overflow_fails_closed() {
        assert!(next_projection_generation(Some((i64::MAX, 0)), EVENT_TYPE_CARD_UPDATE).is_err());
        assert!(next_projection_generation(Some((i64::MAX, i64::MAX)), EVENT_TYPE_REVOKE).is_err());
    }

    #[test]
    fn aggregate_source_contract_selects_table_and_payload_id() {
        let card_source = ProjectionSource::for_aggregate(ProjectionAggregate::Card);
        assert_eq!(card_source.tenant_query, USER_CARD_TENANT_QUERY);
        assert_eq!(card_source.payload_id_key, CARD_ID_PAYLOAD_KEY);

        let eligibility_source = ProjectionSource::for_aggregate(ProjectionAggregate::Eligibility);
        assert_eq!(eligibility_source.tenant_query, USER_CARD_TENANT_QUERY);
        assert_eq!(eligibility_source.payload_id_key, CARD_ID_PAYLOAD_KEY);

        let rule_set_source = ProjectionSource::for_aggregate(ProjectionAggregate::RuleSet);
        assert_eq!(rule_set_source.tenant_query, RULE_SET_TENANT_QUERY);
        assert_eq!(rule_set_source.payload_id_key, RULE_SET_ID_PAYLOAD_KEY);
    }

    #[test]
    fn eligibility_selector_queries_lock_active_cards_in_card_order() {
        let selectors = [
            (
                EligibilityCardSelector::ByUserId { user_id: 7 },
                ELIGIBILITY_BY_USER_ID_QUERY,
                "user_id = ?",
            ),
            (
                EligibilityCardSelector::ByTenantId { tenant_id: 11 },
                ELIGIBILITY_BY_TENANT_ID_QUERY,
                "tenant_id = ?",
            ),
            (
                EligibilityCardSelector::ByTenantAndDomain {
                    tenant_id: 11,
                    domain_id: 13,
                },
                ELIGIBILITY_BY_TENANT_AND_DOMAIN_QUERY,
                "tenant_id = ? AND domain_id = ?",
            ),
        ];

        for (selector, query, predicate) in selectors {
            assert_eq!(eligibility_selector_query(selector), query);
            assert!(query.contains("SELECT card_id, tenant_id FROM user_card"));
            assert!(query.contains(predicate));
            assert!(query.contains("card_status = 'ACTIVE'"));
            assert!(query.contains("ORDER BY card_id"));
            assert!(query.ends_with("FOR UPDATE"));
        }
    }

    #[test]
    fn projection_payload_uses_aggregate_specific_identifier() {
        let card = projection_payload(ProjectionAggregate::Card, 41, Some(7), 3);
        assert_eq!(card["cardId"], 41);
        assert_eq!(card["tenantId"], 7);
        assert_eq!(card["generation"], 3);
        assert!(card.get("ruleSetId").is_none());

        let rule_set = projection_payload(ProjectionAggregate::RuleSet, 99, None, 4);
        assert_eq!(rule_set["ruleSetId"], 99);
        assert!(rule_set.get("cardId").is_none());
        assert!(rule_set["tenantId"].is_null());
        assert_eq!(rule_set["generation"], 4);
    }

    /// `append_projection_event_in_tx` 的 aggregate 参数经 `as_str()` 映射到
    /// head/outbox 的 aggregate_type 存储值，三类聚合通道彼此分离。
    #[test]
    fn aggregate_parameter_binds_to_db_storage_values() {
        assert_eq!(ProjectionAggregate::Card.as_str(), "CARD");
        assert_eq!(ProjectionAggregate::Eligibility.as_str(), "ELIGIBILITY");
        assert_eq!(ProjectionAggregate::RuleSet.as_str(), "RULE_SET");
        assert_ne!(
            ProjectionAggregate::Card.as_str(),
            ProjectionAggregate::Eligibility.as_str()
        );
        assert_ne!(
            ProjectionAggregate::Card.as_str(),
            ProjectionAggregate::RuleSet.as_str()
        );
        assert_eq!(
            ProjectionAggregate::parse_static(ProjectionAggregate::Card.as_str()),
            Some(ProjectionAggregate::Card)
        );
        assert_eq!(
            ProjectionAggregate::parse_static(ProjectionAggregate::Eligibility.as_str()),
            Some(ProjectionAggregate::Eligibility)
        );
        assert_eq!(
            ProjectionAggregate::parse_static(ProjectionAggregate::RuleSet.as_str()),
            Some(ProjectionAggregate::RuleSet)
        );
        assert_eq!(EVENT_TYPE_RULE_SET_UPDATE, "RULE_SET_UPDATE");
    }
}
