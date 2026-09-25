//! e2e 一次性引导 v2：为 e2e 卡产生 gen-1 已发布证据——通过**真实账本路径**。
//!
//! v1（已废弃）以裸 publish 原语（stage → claim → finalize → publish）直接
//! 发布 gen-1，但不产生 impact plan/delta event/grant revision——与 frontier
//! 契约（plans 1..=G 连续、每代映射 delta、每 delta 映射 ledger revision）
//! 不兼容：该聚合上任何后续 delta 都会 `frontier_missing_generation` 确定性
//! 无法发布（三节点 CS 战役实测）。
//!
//! v2 只做 **source 侧写入**：permission_rule source 行 + CARD 投影事件
//! （head 推进 → generation/fence 身份）+ grant revision + delta event
//! （PENDING），然后由运行中的 projector 以标准发布事务推进——impact plan、
//! delta SUCCEEDED、manifest、pointer 全链一致，frontier 契约由构造满足。
//!
//! 幂等：source 规则行已存在的卡跳过。投影为异步（projector 5s 轮询），
//! 调用方（部署脚本就绪探针）自带收敛等待。

use astral_db::grant_ledger::{build_direct_add_draft, DirectRuleLedgerFacts};
use astral_types::ProjectionAggregate;
use astral_db::{
    append_delta_event, append_grant_revision_in_tx, append_projection_event_with_metadata_in_tx,
    connect_and_validate_schema, next_delta_version, ProjectionEventMetadata,
};

async fn bootstrap_card(
    pool: &sqlx::MySqlPool,
    tenant_id: i64,
    domain_id: i64,
    card_id: i64,
    user_id: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    // 幂等门：source 规则行已存在 ⟺ 该卡已完成引导。
    let existing: (i64,) = sqlx::query_as::<_, (i64,)>(
        "SELECT COUNT(*) FROM permission_rule \
         WHERE card_id = ? AND resource_type = 'permission_rule' AND action_code = '*'",
    )
    .bind(card_id)
    .fetch_one(pool)
    .await?;
    if existing.0 > 0 {
        println!("card {card_id}: already bootstrapped, skip");
        return Ok(());
    }

    let mut tx = pool.begin().await?;

    // 1) source 事实行：permission_rule 类型级通配（管理 API 全动作）。
    // rule_id 用 INSERT 的 last_insert_id（与 create_rule 同一模式）。
    let rule_id = i64::try_from(
        sqlx::query(
            "INSERT INTO permission_rule (card_id, tenant_id, resource_type, action_code, effect, \
             priority, enabled) VALUES (?, ?, 'permission_rule', '*', 'ALLOW', 100, 1)",
        )
        .bind(card_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?
        .last_insert_id(),
    )
    .map_err(|_| "permission_rule insert returned an unusable rule id")?;

    // 2) CARD 投影事件：head 推进（source_generation/revoke_fence 身份来源）。
    let operation_id = format!("e2e-f3-bootstrap-{card_id}");
    let projection = append_projection_event_with_metadata_in_tx(
        &mut tx,
        ProjectionAggregate::Card,
        card_id,
        "RULE_CREATED",
        Some(ProjectionEventMetadata {
            actor_id: user_id,
            operation_id: &operation_id,
        }),
    )
    .await?;

    // 3) 账本组装（canonical grant + evidence 校验）+ revision + delta。
    let facts = DirectRuleLedgerFacts {
        tenant_id: Some(tenant_id),
        domain_id: Some(domain_id),
        card_id,
        user_id,
        rule_id,
        resource: "permission_rule",
        resource_id: None,
        action: "*",
        condition_json: None,
        valid_from: None,
        valid_to: None,
    };
    let draft = build_direct_add_draft(&facts, &operation_id, user_id, &projection)?;
    let (base_version, target_version) = next_delta_version(None)?;
    append_grant_revision_in_tx(&mut tx, &draft.revision_request())
        .await
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("revision append: {e}")))?;
    append_delta_event(&mut *tx, &draft.delta_event_request(base_version, target_version)?)
        .await
        .map_err(|e| Box::<dyn std::error::Error>::from(format!("delta append: {e}")))?;

    tx.commit().await?;
    println!(
        "card {card_id}: source rule {rule_id} + revision + delta committed \
         (gen {} fence {}); projector owns publication",
        projection.source_generation, projection.revoke_fence
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = connect_and_validate_schema(&url).await?;
    bootstrap_card(&pool, 9001, 9011, 9061, 9031).await?;
    bootstrap_card(&pool, 9002, 9012, 9062, 9032).await?;
    println!("e2e bootstrap done");
    Ok(())
}
