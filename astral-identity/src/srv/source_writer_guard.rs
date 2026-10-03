//! Session/user/credential source-writer fence helpers（Identity 侧共享）。
//!
//! 会话/用户/凭证 source mutation（auth_device_session、auth_token_family、
//! auth_session_outbox、identity_card 注册事务、platform_user 状态事务、
//! user_local_credential）在内存投影 hub 已安装时必须持有
//! [`SourceTransactionGuard`]：writer-active 期间 hub 辅助读面/会话正向快照
//! fail-closed，drop 时统一失效正向读缓存并推进纪元（与 card/org writer 同一
//! 语义，见 `astral_db::memory_projection_hub`）。
//!
//! 契约（与 `card_repository::begin_card_source_transaction` 一致）：
//! - hub 未安装（独立 Identity 部署）→ `Ok(None)`，行为完全不变；
//! - hub 已安装而栅栏不可得 → `Err`（写点 `?` 拒绝写入，绝不静默 no-op）；
//! - autocommit 单语句：await 窗口前武装（`mark_commit_started`），结果判定后
//!   settle（Ok → proven 清私有 atomic；Err → sticky uncertain）；
//! - 多语句 source 事务：`pool.begin()` 前取得栅栏，**COMMIT await 前**武装，
//!   commit 证明成功后 proven；pre-commit 错误（已知回滚）不武装、随 Drop 干净
//!   释放；commit await 窗口内取消/掉线 → Drop 见 atomic=true → sticky
//!   `uncertain_source`（只有独立 durable 对账可清除）。
//! - 栅栏只围 tx/SQL：绝不跨 Redis/MQ/LocalBus 网络段持有；嵌套栅栏允许。

use std::time::{Duration, Instant};

use sqlx::{MySql, Transaction};

use astral_db::memory_projection_hub::SourceTransactionGuard;
use astral_db::{
    append_in_tx, append_projection_event_with_metadata_and_tenant_in_tx,
    evict_l1_card_active_cache, LocalMessageInput,
};
use astral_mq::config::{QUEUE_AUTHORIZATION_INVALIDATION, ROUTING_KEY_AUTHORIZATION_INVALIDATION};
use astral_mq::invalidation::{
    origin_region, EligibilityInvalidated, InvalidationEvent, ELIGIBILITY_INVALIDATED,
    INVALIDATION_QUEUE,
};
use astral_mq::{local_bus, MessageEnvelope};
use astral_types::{AstralError, ProjectionAggregate, EVENT_TYPE_ELIGIBILITY_UPDATE};

/// 已取得的 hub source writer 栅栏；`None` = hub 未安装（no-op）。
pub(crate) type SourceWriterGuard = Option<SourceTransactionGuard>;

/// fail-closed 取得栅栏：委托 canonical
/// `astral_db::memory_projection_hub::acquire_source_guard`，本文件不留第二份
/// begin 语义。hub 已装而栅栏不可得 → `Err`（由写点 `?` 拒绝写入）。
pub(crate) fn begin_source_write() -> Result<SourceWriterGuard, AstralError> {
    astral_db::memory_projection_hub::acquire_source_guard()
}

/// commit/autocommit await 前武装取消栅栏：guard 私有 `commit_unproven=true`。
/// await 窗口内任务被取消/连接掉线时 Drop 见 atomic=true → sticky uncertain
/// ——覆盖"结果后标记"无法覆盖的取消窗口。hub 未装（None）为 no-op。
pub(crate) fn arm_commit_fence(source_guard: &SourceWriterGuard) {
    if let Some(guard) = source_guard {
        guard.mark_commit_started();
    }
}

/// 写结果已判定后的栅栏收尾：proven → `mark_commit_proven` 清私有 atomic（Drop
/// 正常释放）；非 proven → 显式 `mark_uncertain`（uncertain_source sticky，
/// Drop 的 atomic 分支同向幂等）。
pub(crate) fn settle_commit_fence(source_guard: &SourceWriterGuard, proven: bool) {
    if let Some(guard) = source_guard {
        if proven {
            guard.mark_commit_proven();
        } else {
            guard.mark_uncertain();
        }
    }
}

/// 单条 autocommit source 语句的围栏执行：武装 → await → settle → 返回。
///
/// 栅栏被移入本 future：write 处于 pending 时任务被取消，本 future 连同已武装
/// 的栅栏一起被 Drop → sticky uncertain（hub Drop 语义），正好覆盖
/// "语句可能已提交但结果未知"的窗口。`None` 栅栏（hub 未装）为纯透传。
pub(crate) async fn fenced_source_write<T, E, F>(
    source_guard: SourceWriterGuard,
    write: F,
) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    arm_commit_fence(&source_guard);
    let result = write.await;
    settle_commit_fence(&source_guard, result.is_ok());
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// user 资格变更 typed invalidation 闭合（user 三事务专用，形状与 frozen org
// append/dispatch helper 对等；canonical 原语全部来自 astral-db / astral-mq，
// 消息构造只在 Identity 侧进行——DB 不依赖 MQ）。
// ─────────────────────────────────────────────────────────────────────────────

/// user 资格扇出上限（与 frozen org `ELIGIBILITY_FANOUT_CAP` 同值 512）：选择器
/// SQL 取 cap+1 行，超限在任何 source mutation 之前 fail-closed 拒绝。
pub(crate) const USER_ELIGIBILITY_FANOUT_CAP: usize = 512;

/// 整批 receipts 共享的提交后直投总预算（与 frozen org 同值 5s）；耗尽后剩余
/// receipts 停止直投，durable `al_message_outbox` 行保持 PENDING 作为 relay
/// 恢复路径。
pub(crate) const USER_INVALIDATION_DISPATCH_BUDGET: Duration = Duration::from_secs(5);

/// 提交后待直投的 typed invalidation receipt：同一 envelope 实例落
/// `al_message_outbox` + receipt（与 frozen org `InvalidationReceipt` 同形状）。
#[derive(Debug, Clone)]
pub(crate) struct UserInvalidationReceipt {
    pub(crate) event_id: String,
    pub(crate) operation_id: String,
    pub(crate) envelope: MessageEnvelope,
}

/// 与 astral-db `append_eligibility_events_for_cards_in_tx` 的 `ByUserId` 选择器
/// 同谓词：ACTIVE 卡、`card_id` 升序、事务内 `FOR UPDATE`、同条查询捕获 tenant
/// （无逐卡二次 source 读）；`LIMIT ?` 绑定 cap+1，超限在任何 mutation 之前
/// 拒绝（锁序：调用方先锁 platform_user 行，再锁本批 user_card 行）。
const ELIGIBILITY_CARDS_BY_USER_SQL: &str = "SELECT card_id, tenant_id FROM user_card \
     WHERE user_id = ? AND card_status = 'ACTIVE' \
     ORDER BY card_id LIMIT ? FOR UPDATE";

/// 事务内 user ELIGIBILITY 扇出扫描（仅锁读，零 mutation）：取 cap+1 窗口，
/// 超过 cap 即拒绝——调用方在任何写入之前拿到裁决，绝不落半途 mutation。
pub(crate) async fn scan_user_eligibility_cards_in_tx(
    tx: &mut Transaction<'_, MySql>,
    user_id: i64,
) -> Result<Vec<(i64, Option<i64>)>, AstralError> {
    if user_id <= 0 {
        return Err(AstralError::Validation(format!(
            "user eligibility fanout requires a positive user id, got {user_id}"
        )));
    }
    let window = i64::try_from(USER_ELIGIBILITY_FANOUT_CAP + 1)
        .map_err(|_| AstralError::Internal("user eligibility fanout cap overflow".into()))?;
    let cards: Vec<(i64, Option<i64>)> = sqlx::query_as(ELIGIBILITY_CARDS_BY_USER_SQL)
        .bind(user_id)
        .bind(window)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("Scan user eligibility cards failed: {error}"))
        })?;
    if cards.len() > USER_ELIGIBILITY_FANOUT_CAP {
        return Err(AstralError::Validation(format!(
            "user {user_id} has more than {USER_ELIGIBILITY_FANOUT_CAP} ACTIVE cards; \
             refusing the mutation before any write (eligibility fanout cap)"
        )));
    }
    Ok(cards)
}

/// 稳定 source operation id（纯函数）：用户状态迁移的确定性派生（与 frozen org
/// 的 `tenant_status_operation_id` 同模式）。同一 mutation 语义共享同一
/// operation id（相关性）；intent 唯一性由 messageId（投影事件 id）承担。
pub(crate) fn user_status_operation_id(user_id: i64, from: &str, to: &str) -> String {
    format!("identity:user-status:{user_id}:{from}->{to}")
}

/// 软删除路径的稳定 source operation id（纯函数）。
pub(crate) fn user_delete_operation_id(user_id: i64) -> String {
    format!("identity:user-delete:{user_id}")
}

/// 纯组装 ELIGIBILITY typed invalidation envelope（无 IO，可单测）。
///
/// `projection_event_id` 是同一事务内刚落库的 ELIGIBILITY 投影事件 id：它同时
/// 充当 intent 的稳定 messageId（outbox 唯一性由它承担，同一事务内每个资格
/// 事件各自对应一条 intent）。
fn user_eligibility_invalidation_envelope(
    card_id: i64,
    operation_id: &str,
    projection_event_id: &str,
    region: &str,
) -> Result<MessageEnvelope, AstralError> {
    if card_id <= 0 {
        return Err(AstralError::Validation(format!(
            "eligibility invalidation requires a positive card id, got {card_id}"
        )));
    }
    if operation_id.trim().is_empty() || projection_event_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "eligibility invalidation requires stable source operation and projection event ids"
                .into(),
        ));
    }
    let event = InvalidationEvent::EligibilityInvalidated(EligibilityInvalidated { card_id });
    event
        .to_envelope(projection_event_id, operation_id, region)
        .map_err(|error| AstralError::Validation(error.to_string()))
}

/// 同事务 per-card ELIGIBILITY 事件 + typed invalidation intent 成对落库（不
/// commit）。
///
/// `cards` 必须来自 [`scan_user_eligibility_cards_in_tx`]（cap 内、事务内
/// `FOR UPDATE` 锁定）。每张卡：提交前进程内 evict 正向 L1 资格缓存（单调，
/// commit 未知绝不恢复旧条目）→ 一条 ELIGIBILITY 投影事件（durable 事实，
/// head + authorization_projection_outbox，tenant 走 Captured 语义）→ 一条
/// typed intent（durable 通知，`al_message_outbox`，同一 envelope 实例落
/// outbox + receipt）。receipts 上限与扫描 cap 对等。任一步失败
/// Validation/Database fail-closed，整个 source 事务回滚。
pub(crate) async fn append_user_eligibility_with_invalidation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    user_id: i64,
    operation_id: &str,
    cards: Vec<(i64, Option<i64>)>,
    receipts: &mut Vec<UserInvalidationReceipt>,
) -> Result<(), AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "user eligibility fanout requires a stable source operation id".into(),
        ));
    }
    let region = origin_region().map_err(|error| AstralError::Config(error.to_string()))?;
    for (card_id, card_tenant_id) in cards {
        if receipts.len() >= USER_ELIGIBILITY_FANOUT_CAP {
            return Err(AstralError::Validation(format!(
                "user {user_id} eligibility receipts exceeded the fanout cap \
                 {USER_ELIGIBILITY_FANOUT_CAP}; refusing before any further write"
            )));
        }
        // 0) 提交前进程内失效：正向 L1 卡缓存（单调失效；回滚/未知只多失效，
        //    绝不恢复旧条目）。
        evict_l1_card_active_cache(card_id);
        // 1) ELIGIBILITY 投影事件（head + authorization_projection_outbox），
        //    取回 durable 事件身份（tenant 走 Captured 语义，与公共批量 helper
        //    对 `ByUserId` 的行为一致；该 helper 不返回事件 id，无法配对 intent，
        //    故本路径逐卡成对落库）。
        let identity = append_projection_event_with_metadata_and_tenant_in_tx(
            tx,
            ProjectionAggregate::Eligibility,
            card_id,
            EVENT_TYPE_ELIGIBILITY_UPDATE,
            None,
            card_tenant_id,
        )
        .await?;
        // 2) typed invalidation intent：同一 envelope 实例落 al_message_outbox
        //    + receipt（messageId = 投影事件 id）。
        let envelope = user_eligibility_invalidation_envelope(
            card_id,
            operation_id,
            &identity.event_id,
            &region,
        )?;
        let payload_json = envelope.envelope_json().map_err(AstralError::Internal)?;
        let input = LocalMessageInput {
            message_id: &envelope.message_id,
            operation_id: &envelope.operation_id,
            message_type: ELIGIBILITY_INVALIDATED,
            queue_name: INVALIDATION_QUEUE,
            ordering_key: envelope.ordering_key.as_deref(),
            tenant_id: envelope.tenant_id,
            origin_region: &envelope.origin_region,
            target_region: envelope.target_region.as_deref(),
            schema_version: envelope.schema_version,
            payload_json: &payload_json,
            headers_json: None,
            payload_sha256: &envelope.payload_sha256,
        };
        append_in_tx(tx, &input)
            .await
            .map_err(|error| AstralError::Database(error.to_string()))?;
        receipts.push(UserInvalidationReceipt {
            event_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            envelope,
        });
    }
    Ok(())
}

/// 只投递被证明成功的 commit 的 receipts；commit 未知/失败一律返回空集——
/// "源提交未知绝不发送" 的唯一决策点（与 frozen org / trustgraph 同语义）。
pub(crate) fn receipts_for_proven_commit(
    receipts: &mut Vec<UserInvalidationReceipt>,
    commit_result: &Result<(), sqlx::Error>,
) -> Vec<UserInvalidationReceipt> {
    match commit_result {
        Ok(()) => std::mem::take(receipts),
        Err(_) => Vec::new(),
    }
}

/// 单次有界 LocalBus 投递（deadline 参数化便于测试；生产走预算常量）。
async fn dispatch_user_invalidation_receipt_with_deadline(
    bus: &local_bus::LocalBus,
    receipt: UserInvalidationReceipt,
    deadline: Duration,
) -> Result<(), String> {
    bus.publish_and_wait(
        QUEUE_AUTHORIZATION_INVALIDATION,
        ROUTING_KEY_AUTHORIZATION_INVALIDATION,
        receipt.envelope,
        deadline,
    )
    .await
    .map_err(|error| error.to_string())
}

/// 纯函数：给定整批已耗时长，单条投递可用的剩余预算（可为 0 = 停止直投）。
fn user_dispatch_budget_remaining(elapsed: Duration) -> Duration {
    USER_INVALIDATION_DISPATCH_BUDGET.saturating_sub(elapsed)
}

/// 整批共享一个 5s 总预算的逐条直投：预算耗尽后剩余 receipts 停止直投并记录，
/// durable `al_message_outbox` 行（事务内已 append）保持 PENDING 作为 relay
/// 恢复路径。单次有界尝试：任何失败（无 in-process LocalBus / admission 拒绝 /
/// handler 报错 / 剩余预算到期）只记录日志，不向上传播，不重试——绝不伪装源
/// 回滚，绝不 replay source（unknown 不重放）。
pub(crate) async fn dispatch_proven_user_invalidation_receipts(
    receipts: Vec<UserInvalidationReceipt>,
) {
    let Some(bus) = local_bus::global_local_bus() else {
        tracing::debug!(
            receipts = receipts.len(),
            "no in-process LocalBus installed; user eligibility invalidations stay on the \
             durable outbox relay"
        );
        return;
    };
    let started = Instant::now();
    for receipt in receipts {
        let remaining = user_dispatch_budget_remaining(started.elapsed());
        if remaining.is_zero() {
            tracing::warn!(
                event_id = %receipt.event_id,
                "user invalidation dispatch budget exhausted; remaining receipts stay durable \
                 pending on the outbox relay (no rollback, no replay)"
            );
            break;
        }
        let event_id = receipt.event_id.clone();
        let operation_id = receipt.operation_id.clone();
        match dispatch_user_invalidation_receipt_with_deadline(&bus, receipt, remaining).await {
            Ok(()) => tracing::debug!(
                event_id = %event_id,
                operation_id = %operation_id,
                "user eligibility invalidation receipt dispatched on the local bus"
            ),
            Err(reason) => tracing::warn!(
                event_id = %event_id,
                operation_id = %operation_id,
                reason = %reason,
                "user eligibility invalidation dispatch failed after a proven commit; \
                 keeping the durable outbox row as the recovery path (no rollback, no replay)"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 生命周期（Ok）：autocommit 语句成功 → proven 清私有 atomic，Drop 干净
    /// 释放 writer gate，hub 不进入 sticky suspect。
    #[tokio::test]
    async fn fenced_source_write_ok_proves_and_releases_the_writer_gate() {
        let hub = astral_db::memory_projection_hub::MemoryProjectionHub::default();
        assert!(!hub.has_active_source_writer());
        assert!(!hub.channel_is_suspect());

        let guard = hub.begin_source_transaction();
        let result: Result<u8, ()> = fenced_source_write(guard, std::future::ready(Ok(7))).await;
        assert_eq!(result, Ok(7));

        assert!(!hub.has_active_source_writer(), "guard must be released");
        assert!(
            !hub.channel_is_suspect(),
            "proven commit must not stay suspect"
        );
    }

    /// 生命周期（Err）：已判定的语句失败 → 显式 `mark_uncertain`，sticky
    /// suspect 只能由独立 durable 对账清除（本测试断言其不被普通 drop 清除）。
    #[tokio::test]
    async fn fenced_source_write_err_marks_uncertain_sticky() {
        let hub = astral_db::memory_projection_hub::MemoryProjectionHub::default();

        let guard = hub.begin_source_transaction();
        let result: Result<(), u8> = fenced_source_write(guard, std::future::ready(Err(1))).await;
        assert_eq!(result, Err(1));

        assert!(
            !hub.has_active_source_writer(),
            "guard must still be released"
        );
        assert!(
            hub.channel_is_suspect(),
            "failed autocommit must stay suspect"
        );
    }

    /// 取消窗口（真实 pending future 纯缝）：write 在 pending 时任务被 abort，
    /// 已武装的栅栏随 future 一起 Drop → sticky uncertain。栅栏取自**本地
    /// 构造的 hub 实例**（非进程级 GLOBAL 安装），不污染其他测试。
    #[tokio::test]
    async fn cancellation_mid_await_drops_the_armed_guard_uncertain() {
        let hub = astral_db::memory_projection_hub::MemoryProjectionHub::default();

        let guard = hub.begin_source_transaction();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        let (_gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            // 真实 pending 缝：先通知"已进入武装 await"，再停在永不 resolve 的
            // gate 上，等待测试方 abort。
            let _ = fenced_source_write(guard, async move {
                let _ = started_tx.send(());
                let _ = gate_rx.await;
                Ok::<(), ()>(())
            })
            .await;
        });

        // 等待任务真正停在 pending future 上（武装已发生）。
        started_rx
            .await
            .expect("the fenced write must start and signal");
        task.abort();
        let _ = task.await;

        assert!(
            !hub.has_active_source_writer(),
            "cancelled task must release the writer gate via Drop"
        );
        assert!(
            hub.channel_is_suspect(),
            "cancelling an armed autocommit await must leave sticky uncertain_source"
        );
    }

    /// hub 未安装（`None` 栅栏）：围栏执行为纯透传，行为不变、无 hub 交互。
    #[tokio::test]
    async fn missing_hub_guard_is_a_passthrough() {
        let result: Result<&str, ()> =
            fenced_source_write(None, std::future::ready(Ok("ok"))).await;
        assert_eq!(result, Ok("ok"));

        let result: Result<(), ()> = fenced_source_write(None, std::future::ready(Err(()))).await;
        assert!(result.is_err());
    }

    /// 契约形状：helper 只委托 canonical `acquire_source_guard`，不复制第二份
    /// begin 语义；错误信息不携带任何秘密（固定短语）。
    #[test]
    fn acquisition_delegates_to_the_canonical_shared_helper() {
        let source = include_str!("source_writer_guard.rs");
        let begin = source
            .find("pub(crate) fn begin_source_write()")
            .expect("begin helper must stay");
        let body = &source[begin..];
        assert!(
            body.find("acquire_source_guard")
                .expect("must delegate to astral_db acquire_source_guard")
                < body
                    .find("hub.begin_source_transaction")
                    .unwrap_or(usize::MAX),
            "begin_source_write must not re-implement hub begin semantics"
        );
        let fn_end = body
            .find("pub(crate) fn arm_commit_fence")
            .expect("arm helper must follow begin helper");
        let delegate = &body[..fn_end];
        assert!(
            delegate.contains("astral_db::memory_projection_hub::acquire_source_guard()"),
            "acquisition must go through the shared exported helper"
        );
    }

    /// 纯组装：ELIGIBILITY typed envelope 绑定正卡号与稳定身份；非法输入
    /// fail-closed（Validation，无秘密）。
    #[test]
    fn user_eligibility_envelope_binds_card_operation_and_projection_event() {
        let envelope = user_eligibility_invalidation_envelope(
            42,
            "identity:user-status:7:ACTIVE->DISABLED",
            "event-1",
            "region-a",
        )
        .expect("valid inputs must assemble");
        assert_eq!(envelope.message_id, "event-1");
        assert_eq!(
            envelope.operation_id,
            "identity:user-status:7:ACTIVE->DISABLED"
        );

        assert!(user_eligibility_invalidation_envelope(0, "op", "event", "region").is_err());
        assert!(
            user_eligibility_invalidation_envelope(1, " ", "event-1", "region").is_err(),
            "empty operation id must be refused"
        );
        assert!(
            user_eligibility_invalidation_envelope(1, "op", " ", "region").is_err(),
            "empty projection event id must be refused"
        );
    }

    /// 纯判定：receipts 只在 commit 证明成功后放行；unknown/失败一律零投递。
    #[test]
    fn receipts_dispatch_only_after_a_proven_commit() {
        let mut receipts = vec![UserInvalidationReceipt {
            event_id: "event-1".into(),
            operation_id: "op-1".into(),
            envelope: user_eligibility_invalidation_envelope(9, "op-1", "event-1", "region-a")
                .expect("valid envelope"),
        }];
        let proven: Result<(), sqlx::Error> = Ok(());
        let dispatched = receipts_for_proven_commit(&mut receipts, &proven);
        assert_eq!(dispatched.len(), 1);
        assert!(receipts.is_empty(), "proven receipts must be taken");

        let mut receipts = vec![UserInvalidationReceipt {
            event_id: "event-2".into(),
            operation_id: "op-2".into(),
            envelope: user_eligibility_invalidation_envelope(9, "op-2", "event-2", "region-a")
                .expect("valid envelope"),
        }];
        let unknown: Result<(), sqlx::Error> =
            Err(sqlx::Error::Protocol("commit outcome unknown".into()));
        let dispatched = receipts_for_proven_commit(&mut receipts, &unknown);
        assert!(
            dispatched.is_empty(),
            "unknown/failed commit must dispatch nothing"
        );
        assert_eq!(receipts.len(), 1, "receipts stay buffered for the caller");
    }

    /// 纯判定：整批共享预算单调递减，耗尽即 0（停止直投，不越界）。
    #[test]
    fn dispatch_budget_is_shared_and_never_negative() {
        assert_eq!(
            user_dispatch_budget_remaining(Duration::ZERO),
            USER_INVALIDATION_DISPATCH_BUDGET
        );
        assert_eq!(
            user_dispatch_budget_remaining(USER_INVALIDATION_DISPATCH_BUDGET),
            Duration::ZERO
        );
        let huge = USER_INVALIDATION_DISPATCH_BUDGET + Duration::from_secs(3600);
        assert_eq!(user_dispatch_budget_remaining(huge), Duration::ZERO);
    }

    /// 稳定 operation id：同语义迁移同 id（相关性），不同迁移语义相互区分。
    #[test]
    fn user_operation_ids_are_stable_and_semantically_distinct() {
        assert_eq!(
            user_status_operation_id(7, "ACTIVE", "DISABLED"),
            user_status_operation_id(7, "ACTIVE", "DISABLED")
        );
        assert_ne!(
            user_status_operation_id(7, "ACTIVE", "DISABLED"),
            user_status_operation_id(7, "DISABLED", "ACTIVE")
        );
        assert_ne!(
            user_status_operation_id(7, "ACTIVE", "DISABLED"),
            user_delete_operation_id(7)
        );
    }
}
