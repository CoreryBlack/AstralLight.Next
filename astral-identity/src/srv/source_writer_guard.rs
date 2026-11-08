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
//! - 栅栏只围 tx/SQL：绝不跨 cache/MQ/LocalBus 网络段持有；嵌套栅栏允许。

use std::time::{Duration, Instant};

use sqlx::{MySql, Transaction};

use astral_db::authority_eligibility_completion::{
    EligibilitySourceCapture, EligibilitySourceEvidenceReceipt,
};
use astral_db::invalidation_delivery::InvalidationDeliveryContext;
use astral_db::memory_projection_hub::SourceTransactionGuard;
use astral_db::{
    append_in_tx, append_projection_event_with_metadata_and_tenant_in_tx,
    evict_l1_card_active_cache, LocalMessageInput, WriteKind,
};
use astral_db::{IdentityPresence, IdentityReceipt, IdentityStagedEvidence, IdentityTargetImage};
use astral_mq::config::{QUEUE_AUTHORIZATION_INVALIDATION, ROUTING_KEY_AUTHORIZATION_INVALIDATION};
use astral_mq::invalidation::{
    origin_region, EligibilityInvalidated, InvalidationEvent, ELIGIBILITY_INVALIDATED,
    INVALIDATION_QUEUE,
};
use astral_mq::{local_bus, MessageEnvelope};
use astral_types::{
    AstralError, AuthorityMutationKind, AuthorizationAdmission, ProjectionAggregate,
    EVENT_TYPE_ELIGIBILITY_UPDATE,
};

pub(super) enum EligibilityTransaction<'tx, 'conn> {
    Captured(Box<EligibilitySourceCapture<'tx, 'conn>>),
    Direct(&'tx mut Transaction<'conn, MySql>),
}

impl<'conn> EligibilityTransaction<'_, 'conn> {
    pub(super) fn with_tx_mut(&mut self) -> &mut Transaction<'conn, MySql> {
        match self {
            Self::Captured(capture) => capture.with_tx_mut(),
            Self::Direct(tx) => tx,
        }
    }

    pub(super) fn selected_cards(&self) -> &[(i64, Option<i64>)] {
        match self {
            Self::Captured(capture) => capture.selected_cards(),
            Self::Direct(_) => &[],
        }
    }

    pub(super) async fn finish_in_tx(
        self,
    ) -> Result<Option<EligibilitySourceEvidenceReceipt>, AstralError> {
        match self {
            Self::Captured(capture) => capture
                .finish_in_tx()
                .await
                .map(Some)
                .map_err(|error| AstralError::Pending(error.to_string())),
            Self::Direct(_) => Ok(None),
        }
    }
}

/// Lock and validate the caller card bound to an authorization admission.
/// Target aggregate ownership is checked by each writer before this helper so all
/// Identity source writers retain the canonical `platform_user -> user_card` lock order.
pub(crate) async fn validate_admission_caller_card(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
) -> Result<(), AstralError> {
    let scope = &admission.proof().scope;
    let row = sqlx::query_as::<_, (i64, Option<i64>, Option<i64>, Option<i64>, String)>(
        "SELECT card_id, user_id, tenant_id, domain_id, card_status \
         FROM user_card WHERE card_id = ? FOR UPDATE",
    )
    .bind(scope.card_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| AstralError::Database(format!("Lock admission card failed: {error}")))?
    .ok_or_else(|| AstralError::Permission("authorization admission card is missing".into()))?;

    let domain_matches = match scope.domain {
        astral_types::AuthorizationDomainScope::Any => true,
        astral_types::AuthorizationDomainScope::NoDomain => row.3.is_none(),
        astral_types::AuthorizationDomainScope::Exact(domain_id) => row.3 == Some(domain_id),
    };
    if row.0 != scope.card_id
        || row.1 != scope.user_id
        || row.2 != Some(scope.tenant_id)
        || !domain_matches
        || row.4 != "ACTIVE"
    {
        return Err(AstralError::Permission(
            "authorization admission card scope does not match the active caller card".into(),
        ));
    }
    Ok(())
}

/// Revalidate durable authority and reserve a proof-bound admission exactly once.
pub(crate) async fn validate_and_consume_admission(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
) -> Result<(), AstralError> {
    astral_db::consume_authorization_admission_in_tx(tx, admission)
        .await
        .map_err(|error| AstralError::Pending(error.to_string()))?;
    admission
        .consume_once()
        .map_err(|error| AstralError::Pending(error.to_string()))
}

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

/// user 资格扇出上限与共享 eligibility-completion 协议一致：选择器
/// SQL 取 cap+1 行，超限在任何 source mutation 之前 fail-closed 拒绝。
pub(crate) const USER_ELIGIBILITY_FANOUT_CAP: usize =
    astral_db::authority_eligibility_completion::ELIGIBILITY_COMPLETION_MAX_CARDS;

/// 整批 receipts 共享的提交后直投总预算（与 frozen org 同值 5s）；耗尽后剩余
/// receipts 停止直投，durable `al_message_outbox` 行保持 PENDING 作为 relay
/// 恢复路径。
pub(crate) const USER_INVALIDATION_DISPATCH_BUDGET: Duration = Duration::from_secs(5);

/// 提交后待直投的 typed invalidation receipt：同一 envelope 实例落
/// `al_message_outbox` + receipt（与 frozen org `InvalidationReceipt` 同形状）。
#[derive(Debug, Clone)]
pub(crate) struct UserInvalidationReceipt {
    pub(crate) event_id: String,
    pub(crate) projection_event_id: String,
    pub(crate) operation_id: String,
    pub(crate) card_id: i64,
    pub(crate) tenant_id: Option<i64>,
    pub(crate) generation: u64,
    pub(crate) revoke_watermark: u64,
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
pub(crate) async fn append_card_eligibility_with_invalidation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    delivery_context: &InvalidationDeliveryContext,
    card_id: i64,
    tenant_id: Option<i64>,
    operation_id: &str,
) -> Result<UserInvalidationReceipt, AstralError> {
    let region = origin_region().map_err(|error| AstralError::Config(error.to_string()))?;
    evict_l1_card_active_cache(card_id);
    let identity = append_projection_event_with_metadata_and_tenant_in_tx(
        tx,
        ProjectionAggregate::Eligibility,
        card_id,
        EVENT_TYPE_ELIGIBILITY_UPDATE,
        None,
        tenant_id,
    )
    .await?;
    let envelope =
        user_eligibility_invalidation_envelope(card_id, operation_id, &identity.event_id, &region)?;
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
        authority_metadata_json: None,
        payload_sha256: &envelope.payload_sha256,
    };
    append_in_tx(tx, &input)
        .await
        .map_err(|error| AstralError::Database(error.to_string()))?;
    astral_db::invalidation_delivery::stage_invalidation_delivery_with_context_in_tx(
        tx,
        delivery_context,
        &envelope.message_id,
    )
    .await
    .map_err(|error| {
        AstralError::Pending(format!("stage invalidation delivery failed: {error}"))
    })?;
    Ok(UserInvalidationReceipt {
        event_id: envelope.message_id.clone(),
        projection_event_id: identity.event_id.clone(),
        operation_id: envelope.operation_id.clone(),
        card_id,
        tenant_id,
        generation: u64::try_from(identity.source_generation).map_err(|_| {
            AstralError::Internal("eligibility generation is outside the supported range".into())
        })?,
        revoke_watermark: u64::try_from(identity.revoke_fence).map_err(|_| {
            AstralError::Internal(
                "eligibility revoke watermark is outside the supported range".into(),
            )
        })?,
        envelope,
    })
}

pub(crate) async fn append_user_eligibility_with_invalidation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    delivery_context: &InvalidationDeliveryContext,
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
            authority_metadata_json: None,
            payload_sha256: &envelope.payload_sha256,
        };
        append_in_tx(tx, &input)
            .await
            .map_err(|error| AstralError::Database(error.to_string()))?;
        astral_db::invalidation_delivery::stage_invalidation_delivery_with_context_in_tx(
            tx,
            delivery_context,
            &envelope.message_id,
        )
        .await
        .map_err(|error| {
            AstralError::Pending(format!("stage invalidation delivery failed: {error}"))
        })?;
        receipts.push(UserInvalidationReceipt {
            event_id: envelope.message_id.clone(),
            projection_event_id: identity.event_id.clone(),
            operation_id: envelope.operation_id.clone(),
            card_id,
            tenant_id: card_tenant_id,
            generation: u64::try_from(identity.source_generation).map_err(|_| {
                AstralError::Internal(
                    "eligibility generation is outside the supported range".into(),
                )
            })?,
            revoke_watermark: u64::try_from(identity.revoke_fence).map_err(|_| {
                AstralError::Internal(
                    "eligibility revoke watermark is outside the supported range".into(),
                )
            })?,
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

// ─────────────────────────────────────────────────────────────────────────────
// Identity admitted source outcome（已 admitted 敏感写路径的真实 source 证据）。
//
// 契约（对照 astral_db::stage_admitted_source_outcome_in_tx 与 trustgraph
// authorization source owner；本仓 Identity 侧无 canonical delta owner，绝不
// 以 ProtectedBusiness 绕过 —— 一律按 reservation intent 的
// `AuthorizationSource` stage/promote，coverage 沿共享入口保持 None）：
// - 只采集事务**实际**读取/写入的事实：目标行 before/after 镜像（锁定读 +
//   同事务回读；`Absent` 是真实探针结果，证明 create/delete 真值）、真实语句
//   receipt（实际主键 + 类型化写类型 + rows_affected + 实际 durable id）、以及
//   同事务 outbox 行的 `FOR UPDATE` 读回（缺失/不匹配 fail-closed）；
// - actor 授权快照、operation id 或审计 detail 绝不替代目标证据；
// - 网络 authority 不进事务：stage 只做同事务 durable 读写；COMMIT 未知不重放
//   （outcome 行由既有 reconciler 对账，本文件不做任何重试/重放）；
// - 共享 `ProtectedSourceEvidence` 的 receipt 上限（64）小于 user/org 资格
//   扇出（512 卡 × 2 outbox 行）：Identity 侧组装自己的有界 typed staged
//   artifact——按类确定性窗口 + 显式 total 计数，绝不伪造、绝不因此拒绝合法
//   扇出；canonical hash / finite coverage 由共享 API（主 Agent）负责。
// ─────────────────────────────────────────────────────────────────────────────

/// staged artifact 字节上界（与 authority source outcome 校验器的 256 KiB
/// 一致；超界 PENDING fail-closed，绝不裁剪事实）。
pub(crate) const SOURCE_OUTCOME_MAX_STAGED_BYTES: usize = 256 * 1024;

/// 每类 receipt 的确定性窗口上界：按 durable id 升序取前 N 条进入 evidence，
/// 溢出量以显式 total 计入 staged artifact（不丢弃、不伪造、不拒绝扇出）。
/// 上界远小于共享 outcome 校验器上限（1024），保证 artifact 有界。
pub(crate) const SOURCE_OUTCOME_RECEIPT_WINDOW: usize = 128;

/// Identity source outcome 证据序列化域（仅为分隔域标签，不是秘密盐）。
const IDENTITY_OUTCOME_DOMAIN: &[u8] = b"ASTRAL_IDENTITY_SOURCE_OUTCOME_V7\0";

/// 目标行单侧真实状态：`Absent` 是事务内真实探针结果（create/delete 真值），
/// `Present` 携带该侧实际行镜像（只含被本 mutation 触及的列 + 身份列）。
/// Identity 侧装配用内部类型——serde 契约唯一属于共享 DTO
/// `astral_db::authority_publication::identity`（finalize 时收敛转换，绝不
/// 维护第二份 JSON contract）。
#[derive(Debug, Clone)]
pub(crate) enum SourceRowPresence {
    Absent,
    Present(serde_json::Value),
}

impl SourceRowPresence {
    pub(crate) fn present(value: serde_json::Value) -> Self {
        SourceRowPresence::Present(value)
    }
}

/// 一个目标行的 before/after 真实镜像对（两侧探针都在 mutation 事务内取得）。
#[derive(Debug, Clone)]
pub(crate) struct SourceTargetImage {
    pub(crate) entity: &'static str,
    /// 实际主键字段。
    pub(crate) key: serde_json::Value,
    pub(crate) before: SourceRowPresence,
    pub(crate) after: SourceRowPresence,
}

/// 一条真实 durable 语句 receipt：实际主键、类型化写类型、影响行数与该行的
/// 实际 durable id（PK 值 / 投影事件号 / 消息号）。语句标签本身绝不是身份。
#[derive(Debug, Clone)]
pub(crate) struct SourceStatementReceipt {
    pub(crate) entity: &'static str,
    pub(crate) key: serde_json::Value,
    pub(crate) kind: WriteKind,
    pub(crate) rows_affected: u64,
    pub(crate) durable_id: String,
}

// ── 内部装配类型 → 共享 DTO 的唯一收敛点（serde 形状只属于共享 DTO）────────

fn shared_presence(presence: &SourceRowPresence) -> IdentityPresence {
    match presence {
        SourceRowPresence::Absent => IdentityPresence::Absent,
        SourceRowPresence::Present(value) => IdentityPresence::Present(value.clone()),
    }
}

fn shared_target(target: &SourceTargetImage) -> IdentityTargetImage {
    IdentityTargetImage {
        entity: target.entity.to_owned(),
        key: target.key.clone(),
        before: shared_presence(&target.before),
        after: shared_presence(&target.after),
    }
}

pub(crate) fn source_target_from_eligibility_receipt(
    receipt: &EligibilitySourceEvidenceReceipt,
) -> SourceTargetImage {
    let target = receipt.source_target();
    let entity = match target.entity.as_str() {
        "user_card" => "user_card",
        "platform_user" => "platform_user",
        "tenant" => "tenant",
        _ => "unknown",
    };
    SourceTargetImage {
        entity,
        key: target.key.clone(),
        before: match &target.before {
            IdentityPresence::Absent => SourceRowPresence::Absent,
            IdentityPresence::Present(value) => SourceRowPresence::Present(value.clone()),
        },
        after: match &target.after {
            IdentityPresence::Absent => SourceRowPresence::Absent,
            IdentityPresence::Present(value) => SourceRowPresence::Present(value.clone()),
        },
    }
}

fn shared_receipt(receipt: &SourceStatementReceipt) -> IdentityReceipt {
    IdentityReceipt {
        entity: receipt.entity.to_owned(),
        key: receipt.key.clone(),
        kind: receipt.kind.as_text().to_owned(),
        rows_affected: receipt.rows_affected,
        durable_id: receipt.durable_id.clone(),
    }
}

/// 从事务内真实采集组装的完整 source outcome。`fanout` 携带窗口化 receipt
/// 类的显式 total 计数（bounded window 的溢出透明化）；`delta` 只接受**本事务
/// 内真实捕获**的 `DeltaSourceOutcomeEvidence`（card create/rebind 的 grant
/// revision 链），绝不从 publication 侧猜测或现读自签；`coverage` 是同一事务
/// 锁定集派生的 finite scope（≤256，超出必须保持 None）。
#[derive(Debug, Default)]
pub(crate) struct IdentitySourceOutcome {
    targets: Vec<SourceTargetImage>,
    receipts: Vec<SourceStatementReceipt>,
    fanout: serde_json::Value,
    delta: Option<astral_db::DeltaSourceOutcomeEvidence>,
    coverage: Option<astral_types::AuthorityStagedScopeCoverage>,
    eligibility_completion:
        Vec<astral_db::authority_eligibility_completion::EligibilityCompletionCapture>,
    eligibility_receipt: Option<EligibilitySourceEvidenceReceipt>,
    publication_receipt: Option<EligibilitySourceEvidenceReceipt>,
}

impl IdentitySourceOutcome {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn target(mut self, target: SourceTargetImage) -> Self {
        self.targets.push(target);
        self
    }

    pub(crate) fn receipt(mut self, receipt: SourceStatementReceipt) -> Self {
        self.receipts.push(receipt);
        self
    }

    /// 有界窗口类的显式 total（如 `{"eligibilityEvents": 512, …}`）。
    pub(crate) fn fanout_totals(mut self, totals: serde_json::Value) -> Self {
        self.fanout = totals;
        self
    }

    /// 本事务内真实捕获的 canonical delta 证据（card create/rebind）。
    pub(crate) fn with_delta(mut self, delta: astral_db::DeltaSourceOutcomeEvidence) -> Self {
        self.delta = Some(delta);
        self
    }

    /// 同一事务锁定集派生的 finite coverage（≤256；超界保持 None）。
    pub(crate) fn with_coverage(
        mut self,
        coverage: astral_types::AuthorityStagedScopeCoverage,
    ) -> Self {
        self.coverage = Some(coverage);
        self
    }

    pub(crate) fn with_eligibility_receipt(
        mut self,
        receipt: EligibilitySourceEvidenceReceipt,
    ) -> Self {
        self.eligibility_receipt = Some(receipt);
        self
    }

    pub(crate) fn with_publication_receipt(
        mut self,
        receipt: EligibilitySourceEvidenceReceipt,
    ) -> Self {
        self.publication_receipt = Some(receipt);
        self
    }

    /// 组装有界 staged artifact + authority promotion 证据（纯函数，可单测）。
    ///
    /// staged artifact 直接由共享 DTO `astral_db::authority_publication::
    /// identity::IdentityStagedEvidence` 序列化 —— JSON 契约唯一属于 DB 侧
    /// 共享 DTO，本文件不维护第二份 serde contract（内部装配类型只做内存
    /// 形状，finalize 时收敛转换）。source_commit_digest 复用共享
    /// `astral_db::source_commit_digest`（staged artifact + durable result 联合
    /// 摘要）；before/after image digest 覆盖真实行镜像字节（本文件自有域）。
    /// receipt identity 是实际 durable id（不是派生标记）。
    pub(crate) fn finalize(
        self,
        result: &serde_json::Value,
    ) -> Result<
        (
            String,
            astral_db::authority_source_outcome::AuthoritySourceOutcomeEvidence,
            Option<astral_types::AuthorityStagedScopeCoverage>,
        ),
        AstralError,
    > {
        if self.receipts.is_empty() {
            return Err(AstralError::Pending(
                "identity source outcome requires the actual durable statement receipts".into(),
            ));
        }
        if self.targets.is_empty() {
            return Err(AstralError::Pending(
                "identity source outcome requires actual target row probes".into(),
            ));
        }
        let staged_artifact = IdentityStagedEvidence {
            targets: self.targets.iter().map(shared_target).collect(),
            receipts: self.receipts.iter().map(shared_receipt).collect(),
            fanout: self.fanout.clone(),
            delta: self.delta.clone(),
        };
        let staged_value = serde_json::to_value(&staged_artifact).map_err(|error| {
            AstralError::Internal(format!(
                "identity source evidence serialization failed: {error}"
            ))
        })?;
        let digest_targets: Vec<IdentityTargetImage> = self
            .publication_receipt
            .as_ref()
            .or(self.eligibility_receipt.as_ref())
            .map(|receipt| vec![receipt.source_target().clone()])
            .unwrap_or_else(|| self.targets.iter().map(shared_target).collect());
        let (before_image_digest, after_image_digest) =
            astral_db::identity_image_digests(&digest_targets)
                .map_err(|error| AstralError::Pending(error.to_string()))?;
        let captured_source_receipts: Vec<IdentityReceipt> = self
            .publication_receipt
            .as_ref()
            .or(self.eligibility_receipt.as_ref())
            .map(|receipt| receipt.source_receipts().to_vec())
            .unwrap_or_default();
        let staged_value = if let Some(receipt) = self.publication_receipt {
            let mut evidence = staged_value;
            evidence["targets"] = serde_json::json!([receipt.source_target()]);
            let captured_receipts =
                serde_json::to_value(receipt.source_receipts()).map_err(|error| {
                    AstralError::Internal(format!(
                        "publication source receipt serialization failed: {error}"
                    ))
                })?;
            if let Some(receipt_array) = evidence
                .get_mut("receipts")
                .and_then(serde_json::Value::as_array_mut)
            {
                if let Some(captured_array) = captured_receipts.as_array() {
                    for captured in captured_array {
                        let duplicate = receipt_array.iter().any(|existing| {
                            existing.get("entity") == captured.get("entity")
                                && existing.get("durableId") == captured.get("durableId")
                        });
                        if !duplicate {
                            receipt_array.push(captured.clone());
                        }
                    }
                }
            }
            evidence
        } else if let Some(receipt) = self.eligibility_receipt {
            let mut evidence = receipt
                .into_staged_envelope()
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .evidence;
            if let Some(object) = staged_value.as_object() {
                if let Some(staged_receipts) =
                    object.get("receipts").and_then(serde_json::Value::as_array)
                {
                    if let Some(receipt_array) = evidence
                        .get_mut("receipts")
                        .and_then(serde_json::Value::as_array_mut)
                    {
                        for staged_receipt in staged_receipts {
                            let duplicate = receipt_array.iter().any(|existing| {
                                existing.get("entity") == staged_receipt.get("entity")
                                    && existing.get("durableId") == staged_receipt.get("durableId")
                            });
                            if !duplicate {
                                receipt_array.push(staged_receipt.clone());
                            }
                        }
                    }
                }
            }
            if let Some(delta) = &self.delta {
                let delta_value = serde_json::to_value(delta).map_err(|error| {
                    AstralError::Internal(format!(
                        "identity delta evidence serialization failed: {error}"
                    ))
                })?;
                evidence["delta"] = delta_value;
            }
            evidence
        } else if self.eligibility_completion.is_empty()
            || self.eligibility_completion.len()
                > astral_db::authority_eligibility_completion::ELIGIBILITY_COMPLETION_MAX_CARDS
        {
            staged_value
        } else {
            let completion =
                astral_db::authority_eligibility_completion::build_eligibility_completion_evidence(
                    &self.eligibility_completion,
                )
                .map_err(|_| {
                    AstralError::Pending(
                        "eligibility completion could not bind the exact in-transaction card set"
                            .into(),
                    )
                })?;
            completion
                .to_staged_envelope(staged_value)
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .evidence
        };
        let staged_json = serde_json::to_string(&staged_value).map_err(|error| {
            AstralError::Internal(format!(
                "identity source evidence serialization failed: {error}"
            ))
        })?;
        if staged_json.len() > SOURCE_OUTCOME_MAX_STAGED_BYTES {
            return Err(AstralError::Pending(
                "identity source evidence exceeds its staging byte bound".into(),
            ));
        }
        let source_commit_digest =
            astral_db::source_commit_digest(&staged_json, &result.to_string());
        let mut source_receipts = self
            .receipts
            .iter()
            .map(
                |receipt| astral_db::authority_source_outcome::AuthoritySourceReceiptIdentity {
                    identity_kind: format!("{}:{}", receipt.entity, receipt.kind.as_text()),
                    identity: receipt.durable_id.clone(),
                },
            )
            .collect::<Vec<_>>();
        for receipt in captured_source_receipts {
            let identity = astral_db::authority_source_outcome::AuthoritySourceReceiptIdentity {
                identity_kind: format!("{}:{}", receipt.entity, receipt.kind),
                identity: receipt.durable_id.clone(),
            };
            if !source_receipts.iter().any(|existing| {
                existing.identity_kind == identity.identity_kind
                    && existing.identity == identity.identity
            }) {
                source_receipts.push(identity);
            }
        }
        Ok((
            staged_json,
            astral_db::authority_source_outcome::AuthoritySourceOutcomeEvidence {
                source_commit_digest,
                before_image_digest,
                after_image_digest,
                source_receipts,
            },
            self.coverage,
        ))
    }
}

/// 纯函数：确定性有界 receipt 窗口——durable id 升序排序后取前 `window` 条，
/// 返回（窗口内 ids, 总数）。溢出量由调用方以 fanout totals 显式进入 staged
/// artifact；绝不伪造、绝不丢弃计数、绝不因窗口拒绝合法扇出。
pub(crate) fn bounded_receipt_window(mut ids: Vec<String>, window: usize) -> (Vec<String>, usize) {
    ids.sort();
    let total = ids.len();
    ids.truncate(window);
    (ids, total)
}

/// 同事务 `FOR UPDATE` 读回本事务写入的投影 outbox 行（按 event_id）：缺失或
/// 身份不匹配即 PENDING fail-closed——绝不允许 evidence 引用不存在的 durable
/// 行。返回确认的 event id（顺序与输入一致）。
pub(crate) async fn read_back_projection_outbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    event_ids: &[String],
) -> Result<Vec<String>, AstralError> {
    let mut confirmed = Vec::with_capacity(event_ids.len());
    for event_id in event_ids {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT event_id FROM authorization_projection_outbox \
             WHERE event_id = ? FOR UPDATE",
        )
        .bind(event_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!(
                "source outcome projection readback failed: {error}"
            ))
        })?
        .filter(|(stored,)| stored == event_id);
        confirmed.push(row.map(|(stored,)| stored).ok_or_else(|| {
            AstralError::Pending(
                "source outcome projection receipt is missing its durable row".into(),
            )
        })?);
    }
    Ok(confirmed)
}

/// 同事务 `FOR UPDATE` 读回本事务写入的 `al_message_outbox` typed intent 行
/// （按 message_id，且 operation_id 必须与本次 mutation 一致）：缺失或不匹配
/// PENDING fail-closed。返回确认的 message id。
pub(crate) async fn read_back_message_outbox_in_tx(
    tx: &mut Transaction<'_, MySql>,
    message_ids: &[String],
    operation_id: &str,
) -> Result<Vec<String>, AstralError> {
    let mut confirmed = Vec::with_capacity(message_ids.len());
    for message_id in message_ids {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT message_id, operation_id FROM al_message_outbox \
             WHERE message_id = ? FOR UPDATE",
        )
        .bind(message_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("source outcome message readback failed: {error}"))
        })?;
        let Some((stored_id, stored_operation)) = row else {
            return Err(AstralError::Pending(
                "source outcome message receipt is missing its durable row".into(),
            ));
        };
        if stored_id != *message_id || stored_operation != operation_id {
            return Err(AstralError::Pending(
                "source outcome message receipt differs from its durable row".into(),
            ));
        }
        confirmed.push(stored_id);
    }
    Ok(confirmed)
}

/// 已 admitted source mutation 的 stage/promote 闭合（COMMIT await 前调用）。
///
/// 委托 canonical `astral_db::stage_admitted_source_outcome_with_coverage_in_tx`：
/// 校验 RESERVED reservation intent（operation/event/proof/request digest/kind）、
/// 同事务 admission use、随后 stage + promote。mutation kind 固定
/// `AuthorizationSource`（Identity user/card/org 路由的 reservation intent
/// 语义，绝不以 ProtectedBusiness 绕过 canonical 授权链）。coverage 只在调用方
/// 能以**同事务锁定集**证明 finite scope（≤256）时为 Some；其余（含超界扇出、
/// eligibility-only 路由）保持 None —— 该行保持 operator-owned，绝不猜测。
/// 无网络 IO。
pub(crate) async fn stage_identity_source_outcome_in_tx(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
    outcome: IdentitySourceOutcome,
    result: &serde_json::Value,
) -> Result<(), AstralError> {
    let (staged_evidence_json, evidence, coverage) = outcome.finalize(result)?;
    astral_db::stage_admitted_source_outcome_with_coverage_in_tx(
        tx,
        admission,
        AuthorityMutationKind::AuthorizationSource,
        staged_evidence_json,
        &evidence,
        coverage,
    )
    .await
    .map_err(|error| AstralError::Pending(error.to_string()))
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
            projection_event_id: "event-1".into(),
            operation_id: "op-1".into(),
            card_id: 9,
            tenant_id: Some(3),
            generation: 4,
            revoke_watermark: 1,
            envelope: user_eligibility_invalidation_envelope(9, "op-1", "event-1", "region-a")
                .expect("valid envelope"),
        }];
        let proven: Result<(), sqlx::Error> = Ok(());
        let dispatched = receipts_for_proven_commit(&mut receipts, &proven);
        assert_eq!(dispatched.len(), 1);
        assert!(receipts.is_empty(), "proven receipts must be taken");

        let mut receipts = vec![UserInvalidationReceipt {
            event_id: "event-2".into(),
            projection_event_id: "event-2".into(),
            operation_id: "op-2".into(),
            card_id: 9,
            tenant_id: Some(3),
            generation: 5,
            revoke_watermark: 2,
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

    #[test]
    fn user_mutations_propagate_admission_operation_identity_into_capture_and_stage() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/srv/user_repository.rs"
        ));
        let implementation = &source[source
            .find("impl UserRepository for SqlxUserRepository")
            .expect("UserRepository impl must stay in user_repository.rs")..];
        for (method, next_method, subject, label) in [
            (
                "async fn update_user(",
                "async fn update_user_status(",
                "EligibilitySourceSubject::UserStatus { user_id }",
                "update_user",
            ),
            (
                "async fn update_user_status(",
                "async fn soft_delete_user(",
                "EligibilitySourceSubject::UserStatus { user_id }",
                "update_user_status",
            ),
            (
                "async fn soft_delete_user(",
                "async fn list_user_cards(",
                "EligibilitySourceSubject::UserDelete { user_id }",
                "soft_delete_user",
            ),
        ] {
            let body = implementation
                .split(method)
                .nth(1)
                .and_then(|body| body.split(next_method).next())
                .unwrap_or_else(|| panic!("{label} body must be delimited"));
            let identity = body
                .find("admission.operation_id()")
                .unwrap_or_else(|| panic!("{label} must use the proof-bound operation identity"));
            let capture = body
                .find("EligibilitySourceCapture::begin_in_tx")
                .unwrap_or_else(|| panic!("{label} must use the DB-owned capture"));
            let subject_at = body
                .find(subject)
                .unwrap_or_else(|| panic!("{label} must use its typed capture subject"));
            let tx_mut = body.find("capture.with_tx_mut()").unwrap_or_else(|| {
                panic!("{label} must route the source mutation through capture")
            });
            let fanout = body
                .find("apply_user_eligibility_mutation_in_tx(")
                .unwrap_or_else(|| {
                    panic!("{label} must route mutation and typed eligibility fanout through the helper")
                });
            let finish = body
                .find("finish_in_tx()")
                .unwrap_or_else(|| panic!("{label} must finish the opaque capture receipt"));
            let stage = body
                .find("stage_user_source_outcome(")
                .unwrap_or_else(|| panic!("{label} must stage its real source outcome"));
            assert!(
                identity < capture
                    && capture < subject_at
                    && subject_at < fanout
                    && fanout < tx_mut,
                "{label}: admission identity, typed capture, and helper must precede its transaction borrow"
            );
            assert!(
                tx_mut < finish && finish < stage,
                "{label}: mutation helper, opaque finish, and stage must remain same-transaction ordered"
            );
            assert!(
                body.contains("&operation_id"),
                "{label}: the stable admission operation id must bind downstream evidence"
            );
        }
        let mutation_start = source
            .find("async fn apply_user_eligibility_mutation_in_tx(")
            .expect("the user mutation helper must remain in the production region");
        let mutation_end = source[mutation_start..]
            .find("\n/// 锁定行镜像")
            .map(|end| mutation_start + end)
            .unwrap_or(source.len());
        let mutation_helper = &source[mutation_start..mutation_end];
        assert!(
            mutation_helper.contains("append_user_eligibility_with_invalidation_in_tx(")
                && mutation_helper.contains("insert_user_mutation_audit_in_tx(")
                && mutation_helper.contains("read_back_user_row_in_tx(tx, user_id)"),
            "the user helper must keep fanout, audit, and after-image readback in the source transaction"
        );
    }

    /// DTO 收敛契约钉：finalize 产物必须能反序列化回共享
    /// （同型、单一 serde contract），且探针真值（absent/present 镜像）完整
    /// 保留——Identity 侧不再持有第二份序列化形状。
    #[test]
    fn finalize_output_round_trips_through_the_shared_db_dto() {
        let (staged_json, _, _) = IdentitySourceOutcome::new()
            .target(SourceTargetImage {
                entity: "user_card",
                key: serde_json::json!({ "cardId": 7 }),
                before: SourceRowPresence::Absent,
                after: SourceRowPresence::present(
                    serde_json::json!({"cardId": 7, "cardStatus": "ACTIVE"}),
                ),
            })
            .receipt(SourceStatementReceipt {
                entity: "user_card",
                key: serde_json::json!({ "cardId": 7 }),
                kind: WriteKind::Insert,
                rows_affected: 1,
                durable_id: "7".into(),
            })
            .finalize(&serde_json::json!({ "operationId": "op-1" }))
            .expect("valid bundle");
        let shared: astral_db::IdentityStagedEvidence = serde_json::from_str(&staged_json)
            .expect("the artifact must be the shared DB DTO verbatim");
        assert_eq!(shared.targets.len(), 1);
        assert_eq!(shared.targets[0].entity, "user_card");
        assert!(matches!(shared.targets[0].before, IdentityPresence::Absent));
        match &shared.targets[0].after {
            IdentityPresence::Present(row) => {
                assert_eq!(row["cardStatus"], "ACTIVE", "the real row image survives");
            }
            IdentityPresence::Absent => panic!("the after probe must stay present"),
        }
        assert_eq!(shared.receipts[0].durable_id, "7");
        assert_eq!(shared.receipts[0].kind, "INSERT");
        assert!(shared.delta.is_none(), "no delta must never be fabricated");
    }

    /// finalize 契约：无 receipt 或无目标探针即 PENDING fail-closed；合法
    /// bundle 的 promotion 证据携带真实 durable id、镜像摘要与联合 commit
    /// 摘要（staged artifact + result，绝不只是 result）。
    #[test]
    fn identity_source_outcome_requires_real_probes_and_binds_real_ids() {
        let outcome = IdentitySourceOutcome::new();
        assert!(
            outcome.finalize(&serde_json::json!({})).is_err(),
            "no receipts = no source outcome"
        );

        let outcome = IdentitySourceOutcome::new().receipt(SourceStatementReceipt {
            entity: "platform_user",
            key: serde_json::json!({"userId": 7}),
            kind: WriteKind::Update,
            rows_affected: 1,
            durable_id: "7".into(),
        });
        assert!(
            outcome.finalize(&serde_json::json!({})).is_err(),
            "no target probes = no source outcome"
        );

        let outcome = IdentitySourceOutcome::new()
            .target(SourceTargetImage {
                entity: "platform_user",
                key: serde_json::json!({"userId": 7}),
                before: SourceRowPresence::present(serde_json::json!({
                    "userId": 7, "status": "ACTIVE"
                })),
                after: SourceRowPresence::present(serde_json::json!({
                    "userId": 7, "status": "DISABLED"
                })),
            })
            .receipt(SourceStatementReceipt {
                entity: "platform_user",
                key: serde_json::json!({"userId": 7}),
                kind: WriteKind::Update,
                rows_affected: 1,
                durable_id: "7".into(),
            })
            .receipt(SourceStatementReceipt {
                entity: "al_message_outbox",
                key: serde_json::json!({"messageId": "evt-1"}),
                kind: WriteKind::Insert,
                rows_affected: 1,
                durable_id: "evt-1".into(),
            });
        let result = serde_json::json!({"operationId": "op-1"});
        let (staged_json, evidence, _) = outcome.finalize(&result).expect("valid bundle");
        assert!(staged_json.contains("\"userId\":7"), "{staged_json}");
        assert!(staged_json.contains("evt-1"), "{staged_json}");
        assert_ne!(evidence.before_image_digest, evidence.after_image_digest);
        assert_eq!(evidence.source_receipts.len(), 2);
        assert_eq!(evidence.source_receipts[0].identity, "7");
        assert_eq!(
            evidence.source_receipts[0].identity_kind,
            "platform_user:UPDATE"
        );
        assert_eq!(evidence.source_receipts[1].identity, "evt-1");

        // commit 摘要联合绑定 staged artifact 与 durable result：任一变化即
        // 摘要变化（对照共享 source_commit_digest 语义）。
        let (_, evidence_again, _) = IdentitySourceOutcome::new()
            .target(SourceTargetImage {
                entity: "platform_user",
                key: serde_json::json!({"userId": 7}),
                before: SourceRowPresence::present(serde_json::json!({
                    "userId": 7, "status": "ACTIVE"
                })),
                after: SourceRowPresence::present(serde_json::json!({
                    "userId": 7, "status": "DISABLED"
                })),
            })
            .receipt(SourceStatementReceipt {
                entity: "platform_user",
                key: serde_json::json!({"userId": 7}),
                kind: WriteKind::Update,
                rows_affected: 1,
                durable_id: "7".into(),
            })
            .receipt(SourceStatementReceipt {
                entity: "al_message_outbox",
                key: serde_json::json!({"messageId": "evt-1"}),
                kind: WriteKind::Insert,
                rows_affected: 1,
                durable_id: "evt-1".into(),
            })
            .finalize(&result)
            .expect("valid bundle");
        assert_eq!(
            evidence.source_commit_digest,
            evidence_again.source_commit_digest
        );
        let (_, changed_result, _) = IdentitySourceOutcome::new()
            .target(SourceTargetImage {
                entity: "platform_user",
                key: serde_json::json!({"userId": 7}),
                before: SourceRowPresence::present(serde_json::json!({
                    "userId": 7, "status": "ACTIVE"
                })),
                after: SourceRowPresence::present(serde_json::json!({
                    "userId": 7, "status": "DISABLED"
                })),
            })
            .receipt(SourceStatementReceipt {
                entity: "platform_user",
                key: serde_json::json!({"userId": 7}),
                kind: WriteKind::Update,
                rows_affected: 1,
                durable_id: "7".into(),
            })
            .receipt(SourceStatementReceipt {
                entity: "al_message_outbox",
                key: serde_json::json!({"messageId": "evt-1"}),
                kind: WriteKind::Insert,
                rows_affected: 1,
                durable_id: "evt-1".into(),
            })
            .finalize(&serde_json::json!({"operationId": "op-2"}))
            .expect("valid bundle");
        assert_ne!(
            evidence.source_commit_digest, changed_result.source_commit_digest,
            "the commit digest must bind the durable result too"
        );

        // before/after 镜像字节绑定 entity/key/状态：换 key 或换 entity 必须
        // 改变摘要（不可跨目标重用镜像）。
        let (_, other_key, _) = IdentitySourceOutcome::new()
            .target(SourceTargetImage {
                entity: "platform_user",
                key: serde_json::json!({"userId": 8}),
                before: SourceRowPresence::present(serde_json::json!({
                    "userId": 7, "status": "ACTIVE"
                })),
                after: SourceRowPresence::present(serde_json::json!({
                    "userId": 7, "status": "DISABLED"
                })),
            })
            .receipt(SourceStatementReceipt {
                entity: "platform_user",
                key: serde_json::json!({"userId": 8}),
                kind: WriteKind::Update,
                rows_affected: 1,
                durable_id: "8".into(),
            })
            .finalize(&result)
            .expect("valid bundle");
        assert_ne!(evidence.before_image_digest, other_key.before_image_digest);
    }

    #[test]
    fn opaque_eligibility_receipts_bind_targets_digests_and_top_level_receipts() {
        let source = include_str!("source_writer_guard.rs");
        let production = &source[..source
            .find("#[cfg(test)]")
            .expect("source writer tests must follow production helpers")];
        assert!(
            production.contains("pub(crate) fn with_eligibility_receipt(")
                && production.contains("pub(crate) fn with_publication_receipt("),
            "IdentitySourceOutcome must expose separate opaque eligibility and publication lanes"
        );
        assert!(
            production.contains("receipt.source_target()")
                && production.contains("evidence[\"targets\"]"),
            "staged targets must be relayed from the opaque receipt"
        );
        assert!(
            production.contains("let digest_targets: Vec<IdentityTargetImage>")
                && production.contains("receipt.source_target().clone()"),
            "image digests must bind to the opaque receipt target"
        );
        assert!(
            production.contains("let captured_source_receipts")
                && production.contains("receipt.source_receipts().to_vec()")
                && production.contains("source_receipts.push(identity)"),
            "captured receipt identities must be relayed into top-level evidence"
        );
        let capture_source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../astral-db/src/authority_eligibility_completion.rs"
        ));
        let capture_production = &capture_source[..capture_source
            .find("#[cfg(test)]")
            .expect("eligibility capture tests must follow production source")];
        assert!(
            capture_production.contains("pub struct EligibilitySourceEvidenceReceipt")
                && capture_production.contains("pub async fn finish_in_tx(")
                && capture_production.contains("pub async fn finish_publication_in_tx("),
            "the source writer must consume the DB-owned opaque receipt API"
        );
        assert!(
            capture_production.contains("publication origin requires a closed card INSERT")
                && capture_production
                    .contains("card eligibility mutation cannot prove an empty selector"),
            "publication and empty-selector lanes must remain fail-closed"
        );
    }
    /// 确定性有界窗口：durable id 升序、截断到窗口、报告真实总数（溢出透明
    /// 计数，不伪造不丢弃）。
    #[test]
    fn bounded_receipt_window_is_deterministic_and_reports_totals() {
        let ids: Vec<String> = ["evt-3", "evt-1", "evt-2", "evt-5", "evt-4"]
            .iter()
            .map(|id| (*id).to_string())
            .collect();
        let (window, total) = bounded_receipt_window(ids, 3);
        assert_eq!(total, 5);
        assert_eq!(
            window,
            vec![
                "evt-1".to_string(),
                "evt-2".to_string(),
                "evt-3".to_string()
            ]
        );
        let (window, total) = bounded_receipt_window(Vec::new(), 3);
        assert_eq!((window.as_slice(), total), (&[][..], 0));
        let (window, total) =
            bounded_receipt_window(vec!["a".to_string()], SOURCE_OUTCOME_RECEIPT_WINDOW);
        assert_eq!((window.as_slice(), total), (&["a".to_string()][..], 1));
    }

    /// stage/promote 契约钉（源形状，无 IO）：委托 canonical
    /// `astral_db::stage_admitted_source_outcome_with_coverage_in_tx`，kind 固定
    /// `AuthorizationSource`（绝不以 ProtectedBusiness 绕过 canonical 授权链），
    /// coverage 只能来自同事务锁定集（超界/不可证即 None），错误统一 PENDING
    /// fail-closed。
    #[test]
    fn staging_delegates_to_the_canonical_entry_with_authorization_source_kind() {
        let source = include_str!("source_writer_guard.rs");
        let stage = source
            .find("pub(crate) async fn stage_identity_source_outcome_in_tx(")
            .expect("stage helper must stay");
        let body = &source[stage..];
        let end = body
            .find("#[cfg(test)]")
            .expect("tests must follow the toolkit");
        let body = &body[..end];
        assert!(
            body.contains("astral_db::stage_admitted_source_outcome_with_coverage_in_tx("),
            "staging must delegate to the shared canonical coverage entry"
        );
        assert!(
            body.contains("AuthorityMutationKind::AuthorizationSource"),
            "identity source outcomes must stage as AuthorizationSource"
        );
        assert!(
            !body.contains("AuthorityMutationKind::ProtectedBusiness"),
            "identity must never bypass the canonical chain via ProtectedBusiness"
        );
        assert!(
            body.find("outcome.finalize(result)")
                .expect("finalize must run first")
                < body
                    .find("astral_db::stage_admitted_source_outcome_with_coverage_in_tx(")
                    .unwrap(),
            "the typed evidence must be finalized before the canonical stage call"
        );
    }

    /// coverage/delta 契约钉（纯函数）：coverage 只承载 finite card scope，
    /// delta 只进 staged artifact（与共享 DTO 同一 contract），二者都绝不伪造。
    #[test]
    fn finalize_binds_delta_into_the_shared_artifact_and_carries_coverage() {
        use astral_types::{AuthorityProtocolScope, AuthorizationAuthorityScope};
        let card_scope = AuthorizationAuthorityScope {
            tenant_id: 3,
            card_id: 7,
            user_id: Some(5),
            domain: astral_types::AuthorizationDomainScope::Exact(4),
        };
        let coverage = astral_types::AuthorityStagedScopeCoverage {
            scopes: vec![AuthorityProtocolScope::Card(card_scope)],
        };
        let (staged_json, _, carried) = IdentitySourceOutcome::new()
            .target(SourceTargetImage {
                entity: "user_card",
                key: serde_json::json!({ "cardId": 7 }),
                before: SourceRowPresence::Absent,
                after: SourceRowPresence::present(serde_json::json!({ "cardId": 7 })),
            })
            .receipt(SourceStatementReceipt {
                entity: "user_card",
                key: serde_json::json!({ "cardId": 7 }),
                kind: WriteKind::Insert,
                rows_affected: 1,
                durable_id: "7".into(),
            })
            .with_coverage(coverage)
            .finalize(&serde_json::json!({ "operationId": "op-1" }))
            .expect("valid bundle");
        assert!(
            carried.is_some(),
            "the declared coverage must be carried to the stage entry"
        );
        let staged: serde_json::Value = serde_json::from_str(&staged_json).unwrap();
        assert!(
            staged.get("delta").is_none(),
            "an outcome without a captured delta must not fabricate one"
        );
    }

    /// outbox 读回契约钉（源形状）：投影 outbox 按 event_id `FOR UPDATE` 读回
    /// 且身份必须一致；消息 outbox 还必须核对 operation_id——缺失/不匹配一律
    /// PENDING，绝不把不存在的行当 receipt。
    #[test]
    fn outbox_readbacks_verify_durable_rows_fail_closed() {
        let source = include_str!("source_writer_guard.rs");
        let start = source
            .find("pub(crate) async fn read_back_projection_outbox_in_tx(")
            .expect("projection readback must stay");
        let end = source[start..]
            .find("#[cfg(test)]")
            .expect("tests must follow the toolkit");
        let body = &source[start..start + end];
        assert!(
            body.contains("FROM authorization_projection_outbox")
                && body.contains("FOR UPDATE")
                && body.contains("stored == event_id"),
            "projection readback must lock and verify the durable row"
        );
        assert!(
            body.contains("FROM al_message_outbox")
                && body.contains("stored_operation != operation_id"),
            "message readback must verify the durable row and its operation"
        );
    }
}
