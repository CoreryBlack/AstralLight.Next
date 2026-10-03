//! 授权源事务包装器：携带 typed invalidation receipts 的短事务边界。
//!
//! 影响有效授权的 source mutation 必须在同一短事务内把 typed invalidation
//! envelope 追加进 durable `al_message_outbox`。本包装器在事务内收集与 durable
//! outbox **逐字节相同**的 envelope（receipts），并在 `tx.commit()` 取得成功证明
//! 之后，通过 exact outbox claim、LocalBus handler 和 lease-CAS completion
//! 证明本地完成。提交后只做有界 claim/settlement，不重建 envelope；低频
//! MySQL relay 承担未直发、失败或崩溃后的恢复。
//!
//! 合同（fail-closed，Exec-L2 语义）：
//! - **只有 commit 被证明成功才发送**。`commit()` 返回 `Err`（包括连接中断导致的
//!   未知结果）时 receipts 原地丢弃、一律不发送；绝不把未知提交当作已回滚，也绝不
//!   重放 source mutation。
//! - **发送是有界单次尝试**。dispatch 失败或结果未知只记录日志并保留 durable
//!   outbox 行（事务内已 append），由 relay/transport 的恢复路径负责重试、IN_DOUBT
//!   与隔离；本层不重试、不伪装源回滚、不阻塞调用方返回。
//! - **rollback（显式或 drop）不发送**。显式 `rollback_consuming` 与从未到达
//!   commit await 的 drop 都只丢弃 receipts；sqlx 对 drop 发起的隐式回滚完成
//!   与否不由本层证明（本层不断言其完成）。此时栅栏未 arm，Drop 不制造
//!   hub uncertain。
//! - **身份冻结在事务内**：receipts 的 event/operation id 与 origin region 在
//!   envelope 构造时（事务内）即已固化；post-commit 只读取 exact durable row
//!   取得 ownership 和验证内容，不重新读取配置或改写事务事实。
//! - **hub 活动栅栏先于 DB 事务获取**：`begin` 在 `pool.begin()` 之前取得
//!   source-activity fence 并持有到 commit/rollback（含 commit 后 dispatch）完成，
//!   阻止在线 repair 在活跃 source writer 期间替换 pending 状态。hub 已安装但
//!   拒绝发证时在开启事务**之前** fail-closed 报错，绝不产生无栅栏 writer；
//!   COMMIT await 之前先 arm、Ok 证明才 disarm —— commit 等待期间 future 被
//!   取消时栅栏携带 unproven Drop，hub 置 sticky uncertain（提交结果未知，
//!   绝不当作已回滚）；任何 writer 的 proven 都不清除他人造成的 uncertain。

use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use astral_mq::envelope::MessageEnvelope;
use astral_mq::{EligibilityInvalidated, InvalidationEvent};
use astral_types::{AstralError, ProjectionAggregate, EVENT_TYPE_ELIGIBILITY_UPDATE};
use sqlx::{MySql, Transaction};

/// One direct invalidation dispatch budget, including exact DB claim, the shared
/// LocalBus handler deadline, and owned completion CAS. The underlying calls
/// each have a stricter bound; this outer deadline makes the receipt path finite.
pub(crate) const INVALIDATION_DISPATCH_DEADLINE: Duration = Duration::from_secs(15);

/// 单事务 projection delta receipts 的容量上限。
///
/// 正常 mutation 每事务产生个位数 delta；批量/级联路径的规模由上游输入界决定。
/// 超过上限说明调用链异常扩大，Validation fail-closed 让整个事务回滚，绝不
/// 把 receipt 通道变成无界队列。
pub(crate) const PROJECTION_RECEIPT_CAP: usize = 1024;

/// 一条已追加进 durable outbox 的 typed invalidation 证据。
///
/// `envelope` 就是事务内写入 `al_message_outbox` 的同一 envelope 实例；
/// `event_id`/`operation_id` 是稳定的源 mutation 身份（与 outbox 行一致），
/// 仅用于日志与诊断，绝不在 commit 后重新推导。
#[derive(Debug, Clone)]
pub(crate) struct InvalidationReceipt {
    pub event_id: String,
    pub operation_id: String,
    pub envelope: MessageEnvelope,
}

/// Post-commit invalidation dispatch result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvalidationDispatchOutcome {
    /// Exact Local outbox row was already processed or handler + token-owned CAS
    /// completion were proven.
    CompletedLocally,
    /// The row remains durable and is owned by the configured recovery relay.
    DeferredToRecovery,
}

/// Post-commit invalidation dispatcher.
///
/// In Local mode this includes an exact-row durable claim after commit, one
/// bounded LocalBus handler delivery, and a token-owned completion CAS. It never
/// edits source state, retries a dispatch, or turns LocalBus admission into proof;
/// any unknown/failed transition stays fail-closed for the recovery reconciler.
/// Non-Local mode explicitly reports that the row remains for its durable relay.
pub(crate) trait InvalidationDispatcher: Send + Sync {
    fn dispatch(
        &self,
        receipt: InvalidationReceipt,
    ) -> impl Future<Output = Result<InvalidationDispatchOutcome, String>> + Send;
}

/// Post-commit projection delta 投递器。
///
/// 实现必须有界：单次 try-admission（入队成功 ≠ 业务完成，完成归投影 worker）。
pub(crate) trait ProjectionDeltaDispatcher: Send + Sync {
    fn dispatch(&self, request: astral_db::DeltaEventAppendRequest) -> Result<(), String>;
}

/// 生产投递器：commit 证明后把事务内 append 过的完整 delta request 直接交给
/// astral-db 的 committed-projection 发送接口（bounded try-admission）。
pub(crate) struct AstralDbProjectionDeltaDispatcher;

impl ProjectionDeltaDispatcher for AstralDbProjectionDeltaDispatcher {
    fn dispatch(&self, request: astral_db::DeltaEventAppendRequest) -> Result<(), String> {
        astral_db::dispatch_committed_projection_delta(request).map_err(|error| error.to_string())
    }
}

/// 生产投递器：先对事务内已提交的 outbox exact row 获取 durable CAS lease，
/// 再经 LocalBus 调用同一 invalidation handler 并用拥有者 token 完成。没有
/// LocalBus 时保持 Rabbit/relay 恢复腿为该 outbox 行的唯一 owner。
pub(crate) struct LocalBusInvalidationDispatcher {
    pool: sqlx::MySqlPool,
}

impl InvalidationDispatcher for LocalBusInvalidationDispatcher {
    async fn dispatch(
        &self,
        receipt: InvalidationReceipt,
    ) -> Result<InvalidationDispatchOutcome, String> {
        let Some(bus) = astral_mq::local_bus::global_local_bus() else {
            // 进程内未安装 LocalBus（Rabbit transport）：不能 claim 或误报
            // 完成；保留 PENDING 行交给该 transport 的 durable recovery leg。
            tracing::debug!(
                event_id = %receipt.event_id,
                operation_id = %receipt.operation_id,
                "no in-process LocalBus installed; invalidation stays on the durable outbox relay"
            );
            return Ok(InvalidationDispatchOutcome::DeferredToRecovery);
        };
        let outcome = tokio::time::timeout(
            INVALIDATION_DISPATCH_DEADLINE,
            astral_mq::consumers::dispatch_committed_local_invalidation(
                self.pool.clone(),
                bus,
                &receipt.envelope,
            ),
        )
        .await
        .map_err(|_| {
            format!(
                "direct invalidation dispatch timed out after {:?}; outcome unknown",
                INVALIDATION_DISPATCH_DEADLINE
            )
        })??;
        match outcome {
            astral_mq::consumers::LocalInvalidationDispatchOutcome::Completed
            | astral_mq::consumers::LocalInvalidationDispatchOutcome::AlreadyProcessed => {
                Ok(InvalidationDispatchOutcome::CompletedLocally)
            }
            astral_mq::consumers::LocalInvalidationDispatchOutcome::NotClaimed {
                status,
                reason,
            } => Err(format!(
                "direct invalidation remains recovery-owned ({status}): {reason}"
            )),
            astral_mq::consumers::LocalInvalidationDispatchOutcome::NotFound => {
                Err("committed direct invalidation has no matching durable outbox row".into())
            }
        }
    }
}

/// 决定哪些 receipts 允许离开本进程：**只有被证明成功的 commit** 才允许投递。
///
/// `Err`（已知失败或连接中断导致的未知提交结果）一律返回空集 —— 这是
/// "源提交未知绝不发送" 的唯一决策点。对 projection deltas 与 invalidation
/// receipts 同一决策。
pub(crate) fn receipts_for_proven_commit<T>(
    receipts: &mut Vec<T>,
    commit_result: &Result<(), sqlx::Error>,
) -> Vec<T> {
    match commit_result {
        Ok(()) => std::mem::take(receipts),
        Err(_) => Vec::new(),
    }
}

/// 逐条投递已证明 commit 的 receipts。
///
/// Single bounded, non-replaying attempt after a proven source commit. Any failure
/// (claim unavailable, FIFO conflict, handler error, timeout, or missing owner) is
/// logged and the durable outbox remains the recovery/reconciliation path; it
/// never fabricates source rollback or triggers source replay.
pub(crate) async fn dispatch_proven_receipts<D: InvalidationDispatcher>(
    receipts: Vec<InvalidationReceipt>,
    dispatcher: &D,
) {
    for receipt in receipts {
        let event_id = receipt.event_id.clone();
        let operation_id = receipt.operation_id.clone();
        let dispatch_started = Instant::now();
        match dispatcher.dispatch(receipt).await {
            Ok(InvalidationDispatchOutcome::CompletedLocally) => {
                tracing::debug!(
                    event_id = %event_id,
                    operation_id = %operation_id,
                    dispatch_elapsed_ms = dispatch_started.elapsed().as_millis() as u64,
                    "authorization invalidation applied locally and durable outbox completion proven"
                );
            }
            Ok(InvalidationDispatchOutcome::DeferredToRecovery) => {
                tracing::debug!(
                    event_id = %event_id,
                    operation_id = %operation_id,
                    dispatch_elapsed_ms = dispatch_started.elapsed().as_millis() as u64,
                    "authorization invalidation remains pending for durable recovery relay"
                );
            }
            Err(reason) => {
                tracing::warn!(
                    event_id = %event_id,
                    operation_id = %operation_id,
                    reason = %reason,
                    "authorization invalidation receipt dispatch failed after a proven commit; \
                     keeping the durable outbox row as the recovery path (no rollback, no replay)"
                );
            }
        }
    }
}

/// 逐条投递已证明 commit 的 projection delta receipts。
///
/// 单次有界 try-admission：失败（missing owner/队列满/校验拒绝）只记录并把 hub
/// 标记 suspect —— durable delta 行（事务内已 append）保持为投影 worker 的恢复
/// 路径，状态回到 PENDING 语义；绝不回滚已证明的 commit，绝不重放 source。
pub(crate) fn dispatch_proven_projection_deltas<D: ProjectionDeltaDispatcher>(
    deltas: Vec<astral_db::DeltaEventAppendRequest>,
    dispatcher: &D,
) {
    for request in deltas {
        let event_id = request.event_id.clone();
        let operation_id = request.operation_id.clone();
        let aggregate_type = request.aggregate_type.clone();
        match dispatcher.dispatch(request) {
            Ok(()) => {
                tracing::debug!(
                    event_id = %event_id,
                    operation_id = %operation_id,
                    aggregate_type = %aggregate_type,
                    "committed projection delta admitted on the local bus"
                );
            }
            Err(reason) => {
                if let Some(hub) = astral_db::memory_projection_hub() {
                    hub.mark_channel_suspect(format!(
                        "projection delta dispatch admission failed: {reason}"
                    ));
                }
                tracing::warn!(
                    event_id = %event_id,
                    operation_id = %operation_id,
                    aggregate_type = %aggregate_type,
                    reason = %reason,
                    "committed projection delta admission failed; the durable delta row stays \
                     the recovery path for the projection worker (no rollback, no replay)"
                );
            }
        }
    }
}

/// typed validation for a staged projection delta receipt.
/// 与 `astral_db` append 路径的合同一致：稳定身份、正租户、严格递增版本、
/// fence 不超过 source generation、非空 delta 载荷。staged request 必须已经
/// 通过 append 路径落成 durable 行；此处的校验是发送前的最后一道类型门。
fn validate_projection_receipt(
    request: &astral_db::DeltaEventAppendRequest,
) -> Result<(), AstralError> {
    if request.event_id.trim().is_empty() || request.operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "projection delta receipt requires stable event and operation ids".into(),
        ));
    }
    if request.aggregate_type.trim().is_empty() {
        return Err(AstralError::Validation(
            "projection delta receipt requires an aggregate type".into(),
        ));
    }
    if request.tenant_id <= 0 {
        return Err(AstralError::Validation(
            "projection delta receipt requires a positive tenant id".into(),
        ));
    }
    if request.base_version < 0 || request.target_version <= request.base_version {
        return Err(AstralError::Validation(
            "projection delta receipt target version must strictly advance from a non-negative base"
                .into(),
        ));
    }
    if request.revoke_fence > request.source_generation {
        return Err(AstralError::Validation(
            "projection delta receipt revoke fence must not exceed its source generation".into(),
        ));
    }
    if request.delta_json.trim().is_empty() {
        return Err(AstralError::Validation(
            "projection delta receipt requires a serialized delta payload".into(),
        ));
    }
    Ok(())
}

/// 将一条 delta request 登记进 staged ledger：容量上限 + typed validation。
fn stage_projection_receipt_into(
    ledger: &mut Vec<astral_db::DeltaEventAppendRequest>,
    request: astral_db::DeltaEventAppendRequest,
) -> Result<(), AstralError> {
    if ledger.len() >= PROJECTION_RECEIPT_CAP {
        return Err(AstralError::Validation(format!(
            "authorization source transaction exceeded its projection receipt cap ({PROJECTION_RECEIPT_CAP})"
        )));
    }
    validate_projection_receipt(&request)?;
    ledger.push(request);
    Ok(())
}

/// 授权源事务的进程内活动栅栏。
///
/// 直接持有 hub 的 owned RAII `SourceTransactionGuard`（begin 先增
/// `active_source_writers` + `mutation_revision`，Drop 减计数并 bump
/// revision，供在线 reconcile 识别"活跃 source writer / revision 变化"）。
/// 完整合同：DB 事务开始**之前**取得，持有到 commit/rollback（含 commit 后
/// dispatch）完成；COMMIT await 之前 arm、Ok 证明才 disarm，取消/未知 Drop 使
/// hub uncertain sticky。hub 未安装（纯测试、离线工具、Rabbit 模式）时为
/// `None`，行为不变。
pub(crate) type SourceTransactionActivityFence = Option<astral_db::SourceTransactionGuard>;

/// 取得源事务活动栅栏：委托进程级中心入口
/// `astral_db::memory_projection_hub::acquire_source_guard`（该 API 非 root
/// 导出，必须走完整模块路径）去重 guard match，本 crate 不重写安装/拒绝
/// 判定，只保留本 wrapper 的 Result 合同与测试契约：
/// - hub 未安装（纯测试、离线工具、Rabbit 模式）：`Ok(None)`，行为不变；
/// - hub 已安装但拒绝发证：**fail-closed Err**，绝不静默降级为无栅栏
///   source writer（旧 no-op 语义已废弃）。
pub(crate) fn acquire_source_transaction_activity_fence(
) -> Result<SourceTransactionActivityFence, AstralError> {
    astral_db::memory_projection_hub::acquire_source_guard()
}

/// 携带 invalidation receipts 的授权源事务。
///
/// `Deref`/`DerefMut` 到 `sqlx::Transaction<'static, MySql>`：既有 helper 调用点
/// 通过 deref 强制转换继续工作（`&mut tx` 自动强转为 `&mut Transaction` 参数；
/// executor 位置 `&mut **tx` 解析为 `&mut MySqlConnection` —— sqlx 0.8 中只有
/// connection 实现 `Executor`）。commit/rollback 必须走本类型的 consuming 方法，
/// 以保证 receipts 只在 commit 证明后投递；绕过 Deref 直呼 `tx.commit()` 无法
/// 移出字段，编译期即被拒绝。
pub(crate) struct AuthorizationSourceTransaction {
    tx: Transaction<'static, MySql>,
    /// Pool retained only for the post-commit exact-row claim, after tx is consumed.
    pool: sqlx::MySqlPool,
    /// typed invalidation envelopes appended to the durable outbox in-tx.
    receipts: Vec<InvalidationReceipt>,
    /// 完整 projection delta requests 已在事务内 append 成 durable 行，
    /// commit 证明后直接发送；与 durable 行同一请求，commit 后不 reload。
    projection_receipts: Vec<astral_db::DeltaEventAppendRequest>,
    _activity_fence: SourceTransactionActivityFence,
}

impl Deref for AuthorizationSourceTransaction {
    type Target = Transaction<'static, MySql>;

    fn deref(&self) -> &Self::Target {
        &self.tx
    }
}

impl DerefMut for AuthorizationSourceTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tx
    }
}

impl AuthorizationSourceTransaction {
    /// 在取得 hub 活动栅栏**之后**开启数据库事务。
    ///
    /// 栅栏先于 DB begin 获取，阻止在线 repair 把本 writer 尚未提交的 pending
    /// 误当作回滚清理；hub 已安装但拒绝发证时在开启事务**之前** fail-closed，
    /// 绝不留下无栅栏 source writer。栅栏随本包装器 drop（commit/rollback/
    /// dispatch 全程持有）。
    pub(crate) async fn begin(pool: &sqlx::MySqlPool) -> Result<Self, AstralError> {
        let _activity_fence = acquire_source_transaction_activity_fence()?;
        let tx = pool
            .begin()
            .await
            .map_err(|error| AstralError::Database(error.to_string()))?;
        Ok(Self {
            tx,
            pool: pool.clone(),
            receipts: Vec::new(),
            projection_receipts: Vec::new(),
            _activity_fence,
        })
    }

    /// 登记一条已在**本事务内** append 进 durable outbox 的 invalidation receipt。
    ///
    /// envelope 必须与 outbox 行逐字节同源（同一构造实例）；没有 published
    /// pointer 的路径不产生 receipt。
    pub(crate) fn record_invalidation_receipt(&mut self, receipt: InvalidationReceipt) {
        self.receipts.push(receipt);
    }

    /// 登记一条已在**本事务内** append 成 durable 行的完整 projection delta
    /// request（与 durable 行同一请求，commit 后不 reload、不重建）。
    ///
    /// typed validation + 容量上限：校验失败或超限即 Validation fail-closed，
    /// 调用方错误上抛触发整个事务回滚（append 过的 durable 行一并丢弃）。
    pub(crate) fn stage_projection_receipt(
        &mut self,
        request: astral_db::DeltaEventAppendRequest,
    ) -> Result<(), AstralError> {
        stage_projection_receipt_into(&mut self.projection_receipts, request)
    }

    /// 提交源事务；仅在 commit 被证明成功后按序投递 receipts。
    pub(crate) async fn commit_consuming(self) -> Result<(), AstralError> {
        let invalidation_dispatcher = LocalBusInvalidationDispatcher {
            pool: self.pool.clone(),
        };
        self.commit_consuming_with_dispatchers(
            &AstralDbProjectionDeltaDispatcher,
            &invalidation_dispatcher,
        )
        .await
    }

    /// 可注入两类 dispatcher 的 `commit_consuming`（测试用）。
    ///
    /// 投递次序：commit 证明后**先 projection delta**（投影先追平），**后
    /// invalidation**（再失效读取门）；两者都只有 commit 被证明才发送。
    pub(crate) async fn commit_consuming_with_dispatchers<
        P: ProjectionDeltaDispatcher,
        D: InvalidationDispatcher,
    >(
        mut self,
        projection_dispatcher: &P,
        invalidation_dispatcher: &D,
    ) -> Result<(), AstralError> {
        let commit_started = Instant::now();
        // 取消安全：在 await COMMIT **之前** arm 栅栏。COMMIT 等待期间本 future
        // 被取消时，guard 携带 unproven Drop，hub 置 sticky uncertain —— 提交
        // 结果未知即保持未知，绝不当作已回滚，也绝不投递 receipts。
        if let Some(guard) = self._activity_fence.as_ref() {
            guard.mark_commit_started();
        }
        let commit_result = self.tx.commit().await;
        let commit_elapsed = commit_started.elapsed();
        // 唯一发送决策点：commit 未知/失败 ⇒ 两类 receipts 都是空集，绝不发送。
        let deltas = receipts_for_proven_commit(&mut self.projection_receipts, &commit_result);
        let invalidations = receipts_for_proven_commit(&mut self.receipts, &commit_result);
        let (delta_count, invalidation_count) = (deltas.len(), invalidations.len());
        if let Err(error) = commit_result {
            // SQL commit Err 无法证明回滚（真实结果可能已提交）：保守把 hub 标记为
            // uncertain（sticky），在线 reconcile 不得清理与本 writer 相关的 pending；
            // 绝不重放 source，也绝不伪装回滚 —— 由独立 event 线性化对账收口。
            if let Some(guard) = self._activity_fence.as_ref() {
                guard.mark_uncertain();
            }
            return Err(AstralError::Database(error.to_string()));
        }
        // 只有 Ok 证明才 disarm：disarm 只复位本 guard 自身的 unproven 标志，
        // 另一 writer 造成的 hub uncertain 是 sticky 的，绝不在本 writer 的
        // proven 路径上清除。
        if let Some(guard) = self._activity_fence.as_ref() {
            guard.mark_commit_proven();
        }
        tracing::debug!(
            projection_receipts = delta_count,
            invalidation_receipts = invalidation_count,
            commit_elapsed_ms = commit_elapsed.as_millis() as u64,
            "authorization source commit proven; dispatching projection deltas and invalidation receipts"
        );
        dispatch_proven_projection_deltas(deltas, projection_dispatcher);
        dispatch_proven_receipts(invalidations, invalidation_dispatcher).await;
        Ok(())
    }

    /// 显式回滚：receipts 归零丢弃，绝不投递。
    ///
    /// 回滚路径从未 arm 栅栏（无未知提交结果），guard Drop 不制造 hub
    /// uncertain；`rollback()` 自身 `Err` 仅上抛，不伪造完成证明。
    pub(crate) async fn rollback_consuming(self) -> Result<(), AstralError> {
        self.tx
            .rollback()
            .await
            .map_err(|error| AstralError::Database(error.to_string()))
    }
}

/// 纯组装 ELIGIBILITY durable invalidation intent（无 IO，可单测）。
///
/// `projection_event_id` 是**同一事务内**刚落库的 ELIGIBILITY 投影事件 id
/// （每事件新 UUID）：它同时充当 invalidation envelope 的稳定 messageId ——
/// outbox 唯一性由它承担，同一事务内每个资格事件各自对应一条 intent，绝不
/// 复用随机 fallback 或调用方请求头之外的易变身份。`operation_id` 是源
/// mutation 的稳定操作身份（锁定 durable 代次/行派生），进 envelope 与
/// receipt 做关联，commit 后不再重推。
fn eligibility_invalidation_envelope(
    card_id: i64,
    operation_id: &str,
    projection_event_id: &str,
    origin_region: &str,
) -> Result<(InvalidationEvent, MessageEnvelope), AstralError> {
    if card_id <= 0 {
        return Err(AstralError::Validation(format!(
            "eligibility invalidation requires a positive card id, got {card_id}"
        )));
    }
    if operation_id.trim().is_empty() || projection_event_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "eligibility invalidation requires stable source operation and projection \
             event ids"
                .into(),
        ));
    }
    let event = InvalidationEvent::EligibilityInvalidated(EligibilityInvalidated { card_id });
    let envelope = event
        .to_envelope(projection_event_id, operation_id, origin_region)
        .map_err(|error| AstralError::Validation(error.to_string()))?;
    Ok((event, envelope))
}

/// ELIGIBILITY 资格失效的 durable invalidation source-transaction 接线。
///
/// 影响资格的 user_card source mutation（create/delete/status/restore/bind/
/// reassignment）必须在**同一短事务**内成对落库：
/// 1. ELIGIBILITY 投影事件（head + `authorization_projection_outbox`，tenant
///    取同一事务内已锁定/已写入的 `user_card` source row，不引入第二份租户
///    读取），并取回其 durable 事件身份；
/// 2. durable invalidation intent：`ELIGIBILITY_INVALIDATED` envelope 以该
///    事件身份为 messageId 落 `al_message_outbox`（与 evidence invalidation
///    同一 append 契约、同一队列），并把**同一 envelope 实例**登记为 receipt。
///
/// 投递语义由 [`AuthorizationSourceTransaction::commit_consuming`] 统一保证：
/// 只有 commit 被证明成功才按序直投（先 projection delta、后 invalidation）；
/// commit 未知/失败一律不发送，durable outbox 行保持为 relay 恢复路径。显式
/// rollback / drop 同样绝不投递。任一步失败 Validation/Database fail-closed，
/// 整个事务回滚（含已 append 的 source mutation 与投影事件）。
///
/// 放置说明：与 `invalidation_repository::append_evidence_invalidation_if_published`
/// 同族（envelope 构造一次 + 逐字节同源落 outbox + receipt），本 helper 服务
/// 于两条 user_card/global_admin 变更面的成对接线，随授权源事务包装器同址。
pub(crate) async fn append_eligibility_projection_with_invalidation_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    card_id: i64,
    operation_id: &str,
) -> Result<(), AstralError> {
    // 1) ELIGIBILITY 投影事件（durable head/outbox），取回事件身份。
    //    reborrow + DerefMut 强制转换到 `&mut Transaction`。
    let identity = astral_db::append_projection_event_with_metadata_in_tx(
        &mut *tx,
        ProjectionAggregate::Eligibility,
        card_id,
        EVENT_TYPE_ELIGIBILITY_UPDATE,
        None,
    )
    .await?;
    // 2) durable invalidation intent：同一 envelope 实例落 outbox + receipt。
    let origin_region = crate::repository::invalidation_repository::origin_region()?;
    let (event, envelope) = eligibility_invalidation_envelope(
        card_id,
        operation_id,
        &identity.event_id,
        &origin_region,
    )?;
    let payload_json = envelope.envelope_json().map_err(AstralError::Internal)?;
    let input = astral_db::LocalMessageInput {
        message_id: &envelope.message_id,
        operation_id: &envelope.operation_id,
        message_type: event.message_type(),
        queue_name: astral_mq::invalidation::INVALIDATION_QUEUE,
        ordering_key: envelope.ordering_key.as_deref(),
        tenant_id: envelope.tenant_id,
        origin_region: &envelope.origin_region,
        target_region: envelope.target_region.as_deref(),
        schema_version: envelope.schema_version,
        payload_json: &payload_json,
        headers_json: None,
        payload_sha256: &envelope.payload_sha256,
    };
    astral_db::append_in_tx(&mut *tx, &input)
        .await
        .map_err(|error| AstralError::Database(error.to_string()))?;
    tx.record_invalidation_receipt(InvalidationReceipt {
        event_id: envelope.message_id.clone(),
        operation_id: envelope.operation_id.clone(),
        envelope,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_mq::invalidation::InvalidationEvent;
    use astral_types::PublishedEvidenceAggregate;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    const OPERATION: &str = "op-test-1";

    fn evidence_event(
        aggregate_type: PublishedEvidenceAggregate,
        aggregate_id: i64,
        published_generation: u64,
    ) -> InvalidationEvent {
        InvalidationEvent::EvidenceInvalidated(astral_mq::EvidenceInvalidated {
            tenant_id: 7,
            card_id: Some(42),
            aggregate_type,
            aggregate_id,
            published_generation,
            source_generation: 11,
            revoke_fence: 0,
        })
    }

    fn receipt(
        event_id: &str,
        aggregate_type: PublishedEvidenceAggregate,
        aggregate_id: i64,
        published_generation: u64,
    ) -> InvalidationReceipt {
        let envelope = evidence_event(aggregate_type, aggregate_id, published_generation)
            .to_envelope(event_id, OPERATION, "city-a")
            .expect("valid invalidation envelope");
        InvalidationReceipt {
            event_id: event_id.to_owned(),
            operation_id: OPERATION.to_owned(),
            envelope,
        }
    }

    #[derive(Default)]
    struct MockDispatcher {
        calls: Mutex<Vec<(String, String)>>,
        results: Mutex<VecDeque<Result<InvalidationDispatchOutcome, String>>>,
    }

    impl MockDispatcher {
        fn failing(times: usize) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                results: Mutex::new(
                    std::iter::repeat_n(
                        Err::<InvalidationDispatchOutcome, String>("handler refused".into()),
                        times,
                    )
                    .collect(),
                ),
            }
        }
    }

    impl InvalidationDispatcher for MockDispatcher {
        async fn dispatch(
            &self,
            receipt: InvalidationReceipt,
        ) -> Result<InvalidationDispatchOutcome, String> {
            self.calls
                .lock()
                .unwrap()
                .push((receipt.event_id.clone(), receipt.operation_id.clone()));
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(InvalidationDispatchOutcome::CompletedLocally))
        }
    }

    // ── commit 决策：未知/失败绝不发送 ─────────────────────────────────────

    #[test]
    fn proven_commit_hands_over_every_receipt() {
        let mut receipts = vec![
            receipt("e-1", PublishedEvidenceAggregate::UserCard, 42, 10),
            receipt("e-2", PublishedEvidenceAggregate::RuleSet, 6001, 11),
        ];
        let handed = receipts_for_proven_commit(&mut receipts, &Ok(()));
        assert_eq!(handed.len(), 2);
        assert!(receipts.is_empty(), "ledger must be drained once proven");
    }

    #[test]
    fn unknown_or_failed_commit_dispatches_nothing() {
        let mut receipts = vec![receipt("e-1", PublishedEvidenceAggregate::UserCard, 42, 10)];
        // 连接中断/提交失败都表现为 Err：未知结果按未知处理，绝不发送。
        let handed = receipts_for_proven_commit(&mut receipts, &Err(sqlx::Error::RowNotFound));
        assert!(handed.is_empty());
        assert_eq!(receipts.len(), 1, "receipts stay un-dispatched with the tx");
    }

    // ── 投递：顺序、稳定 ID、有界单次尝试 ─────────────────────────────────

    #[tokio::test]
    async fn proven_receipts_dispatch_in_order_with_stable_ids() {
        let receipts = vec![
            receipt("e-direct", PublishedEvidenceAggregate::UserCard, 42, 10),
            receipt("e-ruleset", PublishedEvidenceAggregate::RuleSet, 6001, 11),
            receipt(
                "e-delegation",
                PublishedEvidenceAggregate::Delegation,
                9001,
                12,
            ),
        ];
        let dispatcher = MockDispatcher::default();
        dispatch_proven_receipts(receipts, &dispatcher).await;
        let calls = dispatcher.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                ("e-direct".to_owned(), OPERATION.to_owned()),
                ("e-ruleset".to_owned(), OPERATION.to_owned()),
                ("e-delegation".to_owned(), OPERATION.to_owned()),
            ],
            "receipts must keep source order and stable operation identity"
        );
    }

    #[tokio::test]
    async fn dispatch_failure_is_bounded_single_attempt_and_never_propagates() {
        let receipts = vec![
            receipt("e-1", PublishedEvidenceAggregate::UserCard, 42, 10),
            receipt("e-2", PublishedEvidenceAggregate::RuleSet, 6001, 11),
            receipt("e-3", PublishedEvidenceAggregate::Delegation, 9001, 12),
        ];
        let dispatcher = MockDispatcher::failing(2);
        // 前两条失败、第三条成功：函数必须正常返回，不 panic、不重试、不扩散错误。
        dispatch_proven_receipts(receipts, &dispatcher).await;
        let calls = dispatcher.calls.lock().unwrap().clone();
        assert_eq!(
            calls.len(),
            3,
            "each receipt gets exactly one bounded attempt"
        );
        assert_eq!(
            calls[2].0, "e-3",
            "a failed dispatch never blocks later receipts"
        );
    }

    // ── receipt envelope：pointer generation、CARD lineage 与各源路径类型 ──

    #[test]
    fn receipt_envelopes_cover_every_source_path_type_with_pointer_generation() {
        // direct/approval remove → UserCard 聚合（CARD lineage: card_id 保留）；
        // ruleset → RuleSet 聚合；delegation → Delegation 聚合。
        let paths = [
            ("e-direct", PublishedEvidenceAggregate::UserCard, 42),
            ("e-approval", PublishedEvidenceAggregate::UserCard, 42),
            ("e-ruleset", PublishedEvidenceAggregate::RuleSet, 6001),
            ("e-delegation", PublishedEvidenceAggregate::Delegation, 9001),
        ];
        for (event_id, aggregate_type, aggregate_id) in paths {
            let receipt = receipt(
                event_id,
                aggregate_type,
                aggregate_id,
                10, // pointer generation 固化在事务内，dispatch 不再读取
            );
            assert_eq!(receipt.event_id, event_id);
            assert_eq!(receipt.operation_id, OPERATION);
            let decoded = InvalidationEvent::from_envelope(&receipt.envelope)
                .expect("receipt envelope must satisfy the typed invalidation contract");
            match decoded {
                InvalidationEvent::EvidenceInvalidated(value) => {
                    assert_eq!(value.aggregate_type, aggregate_type);
                    assert_eq!(value.aggregate_id, aggregate_id);
                    assert_eq!(
                        value.card_id,
                        Some(42),
                        "CARD lineage must survive the receipt round trip"
                    );
                    assert_eq!(
                        value.published_generation, 10,
                        "payload must carry the locked pointer generation"
                    );
                }
                other => panic!("unexpected invalidation variant: {other:?}"),
            }
        }
    }

    #[test]
    fn distinct_source_paths_produce_distinct_ordering_keys() {
        let card = receipt("e-a", PublishedEvidenceAggregate::UserCard, 42, 10).envelope;
        let rule_set = receipt("e-b", PublishedEvidenceAggregate::RuleSet, 6001, 10).envelope;
        let delegation = receipt("e-c", PublishedEvidenceAggregate::Delegation, 9001, 10).envelope;
        assert_ne!(card.ordering_key, rule_set.ordering_key);
        assert_ne!(rule_set.ordering_key, delegation.ordering_key);
        assert_eq!(
            card.ordering_key.as_deref(),
            Some("authorization:evidence:tenant/7/aggregate/USER_CARD/42/card/42")
        );
    }

    // ── projection delta receipts：typed validation、容量上限与有界投递 ────

    fn delta_request(event_id: &str, target_version: i64) -> astral_db::DeltaEventAppendRequest {
        astral_db::DeltaEventAppendRequest {
            tenant_id: 7,
            card_id: Some(42),
            aggregate_type: "USER_CARD".into(),
            aggregate_id: 42,
            grant_id: astral_types::GrantId::new(uuid::Uuid::new_v4())
                .expect("random uuid is a valid grant id"),
            event_id: event_id.into(),
            operation_id: OPERATION.into(),
            event_type: astral_db::DeltaEventType::Remove,
            base_version: 0,
            target_version,
            source_generation: 11,
            revoke_fence: 0,
            invalidates_published_evidence: false,
            before_image_json: None,
            before_digest_hex: None,
            delta_json: "{\"delta\":\"x\"}".into(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: "test".into(),
            next_attempt_at: None,
        }
    }

    #[test]
    fn staging_validates_typed_receipt_contract() {
        let mut ledger = Vec::new();
        stage_projection_receipt_into(&mut ledger, delta_request("d-1", 1))
            .expect("a well-formed delta request must stage");
        assert_eq!(ledger.len(), 1);

        let mut broken = delta_request("d-2", 0);
        broken.target_version = 0; // 必须严格前进
        assert!(stage_projection_receipt_into(&mut ledger, broken).is_err());

        let mut empty_ids = delta_request("  ", 2);
        empty_ids.operation_id = String::new();
        assert!(stage_projection_receipt_into(&mut ledger, empty_ids).is_err());

        let mut fence_breach = delta_request("d-3", 3);
        fence_breach.revoke_fence = fence_breach.source_generation + 1;
        assert!(stage_projection_receipt_into(&mut ledger, fence_breach).is_err());

        // 校验失败绝不把请求留在 ledger 里。
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn staging_enforces_a_finite_per_transaction_cap() {
        let mut ledger: Vec<astral_db::DeltaEventAppendRequest> = Vec::new();
        for index in 0..PROJECTION_RECEIPT_CAP {
            let target_version =
                i64::try_from(index + 1).expect("cap-bounded version index always fits i64");
            stage_projection_receipt_into(&mut ledger, delta_request("d", target_version))
                .expect("within the cap must stage");
        }
        assert!(
            stage_projection_receipt_into(&mut ledger, delta_request("d", 1)).is_err(),
            "beyond the cap staging must fail closed so the whole tx rolls back"
        );
    }

    #[derive(Default)]
    struct MockProjectionDispatcher {
        calls: Mutex<Vec<String>>,
        results: Mutex<VecDeque<Result<(), String>>>,
    }

    impl ProjectionDeltaDispatcher for MockProjectionDispatcher {
        fn dispatch(&self, request: astral_db::DeltaEventAppendRequest) -> Result<(), String> {
            self.calls.lock().unwrap().push(request.event_id.clone());
            self.results.lock().unwrap().pop_front().unwrap_or(Ok(()))
        }
    }

    #[test]
    fn proven_projection_deltas_dispatch_in_order_and_failures_are_bounded() {
        let deltas = vec![
            delta_request("d-1", 1),
            delta_request("d-2", 2),
            delta_request("d-3", 3),
        ];
        let dispatcher = MockProjectionDispatcher {
            results: Mutex::new(VecDeque::from(vec![
                Err("no local owner".into()),
                Err("local queue is full".into()),
                Ok(()),
            ])),
            ..MockProjectionDispatcher::default()
        };
        // 失败只记录（durable 行保留、hub suspect），不 panic、不重试、不扩散。
        dispatch_proven_projection_deltas(deltas, &dispatcher);
        let calls = dispatcher.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec!["d-1".to_owned(), "d-2".to_owned(), "d-3".to_owned()]
        );
    }

    #[test]
    fn unknown_commit_gates_projection_deltas_too() {
        let mut deltas = vec![delta_request("d-1", 1)];
        let handed = receipts_for_proven_commit(&mut deltas, &Err(sqlx::Error::RowNotFound));
        assert!(
            handed.is_empty(),
            "commit unknown: no projection delta may fire"
        );
    }

    // ── ELIGIBILITY durable invalidation intent：身份冻结与 commit 门 ──────

    fn eligibility_receipt(card_id: i64) -> InvalidationReceipt {
        let (_, envelope) =
            eligibility_invalidation_envelope(card_id, OPERATION, "elig-proj-event-1", "city-a")
                .expect("valid eligibility invalidation envelope");
        InvalidationReceipt {
            event_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            envelope,
        }
    }

    #[test]
    fn eligibility_invalidation_envelope_binds_projection_identity_and_scope() {
        let (event, envelope) = eligibility_invalidation_envelope(
            42,
            "user-card:bind:42:user:7",
            "elig-proj-event-1",
            "city-a",
        )
        .expect("valid eligibility invalidation envelope");
        assert_eq!(
            event.message_type(),
            astral_mq::invalidation::ELIGIBILITY_INVALIDATED
        );
        // messageId 冻结为同事务 ELIGIBILITY 投影事件身份：outbox 唯一性由它
        // 承担，post-commit dispatch 不再重推任何身份。
        assert_eq!(envelope.message_id, "elig-proj-event-1");
        assert_eq!(envelope.operation_id, "user-card:bind:42:user:7");
        assert_eq!(
            envelope.tenant_id, None,
            "eligibility scope is globally card-keyed by contract; no invented tenant filter"
        );
        assert_eq!(
            envelope.ordering_key.as_deref(),
            Some("authorization:eligibility/card/42")
        );
        let decoded = InvalidationEvent::from_envelope(&envelope)
            .expect("receipt envelope must satisfy the typed invalidation contract");
        assert_eq!(
            decoded,
            InvalidationEvent::EligibilityInvalidated(EligibilityInvalidated { card_id: 42 })
        );
    }

    #[test]
    fn eligibility_invalidation_identity_fails_closed() {
        // 非正 card id 一律拒绝（与投影 writer 的 aggregate 校验同向）。
        assert!(eligibility_invalidation_envelope(0, "op", "evt", "city-a").is_err());
        assert!(eligibility_invalidation_envelope(-1, "op", "evt", "city-a").is_err());
        // 空白 operation / projection event / origin 身份一律拒绝，绝不降级。
        assert!(eligibility_invalidation_envelope(42, "  ", "evt", "city-a").is_err());
        assert!(eligibility_invalidation_envelope(42, "op", "", "city-a").is_err());
        assert!(eligibility_invalidation_envelope(42, "op", "evt", " ").is_err());
    }

    #[test]
    fn eligibility_receipts_only_leave_on_a_proven_commit() {
        let mut receipts = vec![eligibility_receipt(42)];
        let handed = receipts_for_proven_commit(&mut receipts, &Ok(()));
        assert_eq!(handed.len(), 1);
        assert_eq!(handed[0].event_id, "elig-proj-event-1");
        assert_eq!(handed[0].operation_id, OPERATION);

        let mut receipts = vec![eligibility_receipt(42)];
        let handed = receipts_for_proven_commit(&mut receipts, &Err(sqlx::Error::RowNotFound));
        assert!(
            handed.is_empty(),
            "commit unknown: no eligibility invalidation intent may fire"
        );
    }

    // ── 活动栅栏：fail-closed 获取与取消安全次序（纯测试，不连 DB）────────
    //
    // hub 侧 sticky uncertain 的完整观测（arm→drop→uncertain、proven 不清除
    // 他人 uncertain）属于 astral-db hub 自己的测试（crate 私有状态）；此处
    // pin 的是本文件的获取合同与 commit 次序本地合同。

    #[test]
    fn fence_without_hub_is_ok_none_and_never_refuses() {
        // 前置事实：本测试二进制不安装进程级 hub（fanout 启动路径需要真实
        // MySQL pool，纯单测不可达）。hub 未安装（纯测试、离线工具、Rabbit
        // 模式）必须 Ok(None)、绝不报错 —— 若未来有单测安装全局 hub，此断言
        // 会失败并暴露测试间全局状态污染。
        let fence =
            acquire_source_transaction_activity_fence().expect("a missing hub must not refuse");
        assert!(fence.is_none(), "no hub must yield no guard");
    }

    /// include_str! 结构断言：wrapper 只委托中心入口
    /// `astral_db::memory_projection_hub::acquire_source_guard`（非 root
    /// 导出）去重 guard match，不在本 crate 重写安装/拒绝判定；拒绝
    /// fail-closed 语义由中心 API 的测试负责。
    #[test]
    fn fence_acquisition_delegates_to_the_central_guard_api() {
        let source = include_str!("authorization_source_transaction.rs");
        let start = source
            .find("pub(crate) fn acquire_source_transaction_activity_fence")
            .expect("the acquisition entry must exist");
        let end = source[start..]
            .find("pub(crate) struct AuthorizationSourceTransaction")
            .expect("the transaction wrapper must follow the acquisition entry");
        let body = &source[start..start + end];
        assert!(
            body.contains("astral_db::memory_projection_hub::acquire_source_guard()"),
            "the wrapper must delegate to the central acquisition API via its full \
             module path (not a root re-export) instead of rewriting the hub match locally"
        );
        assert!(
            !body.contains("begin_source_transaction"),
            "the wrapper must not duplicate the hub guard acquisition match"
        );
    }

    /// include_str! 结构断言（不连 DB）：pin commit 路径的取消安全次序 ——
    /// arm 先于 COMMIT await；Err 分支 mark_uncertain 后立即 fail-closed 返回；
    /// 只有 Ok 证明才 disarm；dispatch 只发生在 proven 之后。
    #[test]
    fn commit_arms_fence_before_await_and_disarms_only_after_proven_ok() {
        let source = include_str!("authorization_source_transaction.rs");
        let start = source
            .find("pub(crate) async fn commit_consuming_with_dispatchers<")
            .expect("commit_consuming_with_dispatchers must exist");
        let end = source[start..]
            .find("pub(crate) async fn rollback_consuming")
            .expect("rollback_consuming must follow the commit fn");
        let body = &source[start..start + end];
        let arm = body
            .find("guard.mark_commit_started()")
            .expect("the commit path must arm the fence");
        let commit_await = body
            .find("self.tx.commit().await")
            .expect("the COMMIT await must exist");
        let uncertain = body
            .find("guard.mark_uncertain()")
            .expect("a commit Err must mark the hub uncertain");
        let err_return = body
            .find("return Err(AstralError::Database(error.to_string()))")
            .expect("a commit Err must fail closed before any dispatch");
        let proven = body
            .find("guard.mark_commit_proven()")
            .expect("a proven Ok must disarm the fence");
        let dispatch = body
            .find("dispatch_proven_projection_deltas(deltas, projection_dispatcher)")
            .expect("the proven dispatch must exist");
        assert!(
            arm < commit_await,
            "the fence must be armed before awaiting COMMIT so a cancellation \
             during the await keeps the outcome unknown"
        );
        assert!(
            commit_await < uncertain && uncertain < err_return,
            "a commit Err must mark the hub uncertain and return before any dispatch"
        );
        assert!(
            err_return < proven,
            "the fence may only be disarmed after the Err branch has returned (proven Ok only)"
        );
        assert!(
            proven < dispatch,
            "dispatch must only run after the fence is disarmed by a proven commit"
        );
    }

    /// include_str! 结构断言：`begin` 以 `?` 传播栅栏获取错误，且取得栅栏在
    /// `pool.begin()` 之前 —— 拒绝发证时绝不开启无栅栏事务。
    #[test]
    fn begin_acquires_the_fence_before_pool_begin_and_propagates_refusal() {
        let source = include_str!("authorization_source_transaction.rs");
        let start = source
            .find("pub(crate) async fn begin(pool: &sqlx::MySqlPool)")
            .expect("begin must exist");
        let end = source[start..]
            .find("pub(crate) fn record_invalidation_receipt")
            .expect("record_invalidation_receipt must follow begin");
        let body = &source[start..start + end];
        let acquire = body
            .find("acquire_source_transaction_activity_fence()?")
            .expect("begin must propagate the fence acquisition error");
        let pool_begin = body
            .find(".begin()")
            .expect("begin must open the pool transaction");
        assert!(
            acquire < pool_begin,
            "the fence must be acquired (and its refusal propagated) before pool.begin()"
        );
    }
}
