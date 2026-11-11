//! 授权源事务包装器：携带 typed invalidation receipts 的短事务边界。
//!
//! 影响有效授权的 source mutation 必须在同一短事务内把 typed invalidation
//! envelope 追加进 durable `al_message_outbox`。本包装器在事务内收集与 durable
//! outbox **逐字节相同**的 envelope（receipts），并在 `tx.commit()` 取得成功证明
//! 之后按既有顺序执行一次有界 post-commit dispatch；普通提交入口随后以完整
//! source receipt 批次只读等待 WorkerOwned completion，receipt-returning 入口把
//! 同一批次交给调用方等待一次。所有等待均在 source 事务结束之后，不重建
//! envelope；低频 MySQL relay 承担未直发、失败或崩溃后的恢复。
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
use std::sync::Arc;
use std::time::{Duration, Instant};

use astral_mq::envelope::MessageEnvelope;
use astral_mq::{EligibilityInvalidated, InvalidationEvent};
use astral_types::{
    AstralError, AuthorizationAdmission, AuthorizationMessageMetadata, ProjectionAggregate,
    EVENT_TYPE_ELIGIBILITY_UPDATE,
};
use sqlx::{MySql, Transaction};

use astral_db::authority_eligibility_completion::EligibilitySourceEvidenceReceipt;
use astral_db::invalidation_delivery::InvalidationDeliveryContext;
use astral_db::{
    TypedRowOperation, TypedSourceAuditReceipt, TypedSourceRowImageReceipt, TypedSourceTable,
};

mod source_outcome;
pub(crate) use source_outcome::card_create::CardCreateBindingStart;

/// One direct invalidation dispatch budget, including exact DB claim and the shared
/// LocalBus handler deadline. Projection completion is observed separately by the
/// worker-owned request path from its complete source receipts.
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

/// Exact legacy source projection event receipt staged in one source transaction.
///
/// This is the identity of the row in `authorization_projection_outbox`, not a
/// completion proof. The waiter proves the same row reached `PROCESSED`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceProjectionReceipt {
    pub event_id: String,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub tenant_id: Option<i64>,
    pub source_generation: i64,
    pub revoke_fence: i64,
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

/// Exact projection requests staged in one source transaction and returned only
/// after COMMIT was proven. This is a correlation batch, not a completion proof.
#[derive(Debug, Clone, Default)]
pub struct CommittedProjectionReceipts {
    pub(crate) requests: Vec<astral_db::DeltaEventAppendRequest>,
    pub(crate) source_projection_receipts: Vec<SourceProjectionReceipt>,
    pub(crate) invalidation_receipts: Vec<InvalidationReceipt>,
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

// ─────────────────────────────────────────────────────────────────────────────
// Source-owner completion staging/reconciliation seam.
//
// 此 seam 只做两件事：把 commit 证明后交回的 receipt 批次转换成稳定关联身份
// （`CommittedBatchIdentity`），以及提供显式的 pending/unknown/reconciliation
// staging 入口。它绝不把 dispatch admission、ACK、current pointer 或有界等待
// 当作 family completion 证明；terminal completion 只能由
// astral_db::orchestrate_family_completion 在独立验证 authority receipt 之后
// 产生，再经 proof-only ledger writer 以 exact idempotency 落库。
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a committed receipt batch (released only after a PROVEN COMMIT)
/// into the stable correlation identity consumed by
/// `astral_db::orchestrate_family_completion`.
///
/// `commit_proven` is hardcoded `true` at this call boundary because the
/// compiler-visible type `CommittedProjectionReceipts` only leaves
/// `commit_consuming_with_dispatchers_and_receipts` on the proven-Ok path.
/// The identity is correlation only — it never proves projection dispatch,
/// ACK, current pointer, or family completion.
///
/// Seam status: the only approved caller is the reconciliation staging entry
/// below. Wiring an eager production caller would require authority-client
/// injection into runtime/service owners outside this seam's approved scope,
/// so until that injection lands the seam stays deliberately unwired
/// (`dead_code` allowed with this rationale, never removed silently).
#[allow(dead_code)]
pub(crate) fn committed_batch_identity_from_receipts(
    receipts: &CommittedProjectionReceipts,
) -> astral_db::CommittedBatchIdentity {
    // A completion correlation must describe one source operation. Reusing the
    // first value from a mixed batch would silently bind evidence from different
    // mutations, so every operation-bearing receipt must agree exactly.
    let operation_ids: Vec<&str> = receipts
        .requests
        .iter()
        .map(|request| request.operation_id.as_str())
        .chain(
            receipts
                .invalidation_receipts
                .iter()
                .map(|receipt| receipt.operation_id.as_str()),
        )
        .collect();
    let Some(operation_id) = operation_ids.first().copied().filter(|value| {
        !value.is_empty() && operation_ids.iter().all(|candidate| *candidate == *value)
    }) else {
        return astral_db::CommittedBatchIdentity::default();
    };

    // A delta batch may contain several projection rows, but this seam carries
    // one event identity. Refuse multiple delta/source identities instead of
    // selecting whichever row happens to be first. Invalidation-only identity
    // is accepted only when a durable source projection receipt supplies it.
    let event_ids: Vec<&str> = if receipts.requests.is_empty() {
        receipts
            .source_projection_receipts
            .iter()
            .map(|receipt| receipt.event_id.as_str())
            .collect()
    } else {
        receipts
            .requests
            .iter()
            .map(|request| request.event_id.as_str())
            .collect()
    };
    let Some(event_id) = event_ids.first().copied().filter(|value| {
        !value.is_empty() && event_ids.iter().all(|candidate| *candidate == *value)
    }) else {
        return astral_db::CommittedBatchIdentity::default();
    };

    let mut message_id: Option<&str> = None;
    for receipt in &receipts.invalidation_receipts {
        let envelope_message_id = receipt.envelope.message_id.as_str();
        if receipt.event_id != envelope_message_id
            || envelope_message_id.is_empty()
            || receipt.envelope.operation_id != operation_id
            || envelope_message_id != event_id
        {
            return astral_db::CommittedBatchIdentity::default();
        }
        if message_id.is_some_and(|existing| existing != envelope_message_id) {
            return astral_db::CommittedBatchIdentity::default();
        }
        message_id = Some(envelope_message_id);
    }

    astral_db::CommittedBatchIdentity::from_committed_receipt_batch(
        operation_id,
        event_id,
        message_id.unwrap_or_default(),
        // COMMIT was proven: this function is only reachable with a batch
        // returned from the proven-Ok commit path.
        true,
    )
}

/// The explicit reconciliation seam outcome for one committed batch.
///
/// This mirrors `astral_db::FamilyCompletionOrchestrationOutcome`'s
/// non-positive boundaries on the source-transaction side: a committed batch
/// without an independently verified authority receipt stays PENDING and must
/// never be promoted to a terminal family completion by this layer.
///
/// Seam status: consumed by the staging entry below and its tests; a broader
/// production consumer requires authority-client injection outside this
/// seam's approved scope.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FamilyCompletionSeamOutcome {
    /// The batch carries only proven-commit correlation identities; family
    /// completion remains owned by reconciliation.
    PendingReconciliation {
        batch: astral_db::CommittedBatchIdentity,
    },
    /// Identity construction or receipt verification failed; nothing was
    /// staged. The stable identities are returned for reconciliation.
    Unknown {
        batch: astral_db::CommittedBatchIdentity,
    },
}

/// Stage one committed batch at the reconciliation seam WITHOUT an authority
/// receipt producer.
///
/// This is the only safe production path today: no authority client surface
/// can independently verify a family-completion receipt inside this crate, so
/// the seam refuses to fabricate evidence and returns the batch as
/// PENDING/Unknown for reconciliation. The durable proof-only ledger writer
/// (`astral_db::record_independently_proven_family_completion_in_tx`) remains
/// the only write path, and only for a terminal completion produced by
/// `astral_db::orchestrate_family_completion` behind a verified receipt.
///
/// Seam status: deliberately unwired in production callers — wiring requires
/// authority-client injection into runtime/service owners outside this seam's
/// approved scope; tests exercise the exact contract until then.
#[allow(dead_code)]
pub(crate) fn stage_family_completion_for_reconciliation(
    receipts: &CommittedProjectionReceipts,
) -> FamilyCompletionSeamOutcome {
    let batch = committed_batch_identity_from_receipts(receipts);
    if batch.operation_id.is_empty() && batch.event_id.is_empty() {
        // An empty correlation identity cannot be reconciled; report Unknown
        // rather than inventing an identity.
        return FamilyCompletionSeamOutcome::Unknown { batch };
    }
    FamilyCompletionSeamOutcome::PendingReconciliation { batch }
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

fn append_unique_source_projection_receipt(
    receipts: &mut Vec<SourceProjectionReceipt>,
    receipt: SourceProjectionReceipt,
) -> Result<(), AstralError> {
    if receipts
        .iter()
        .any(|existing| existing.event_id == receipt.event_id)
    {
        return Err(AstralError::Validation(format!(
            "duplicate source projection receipt event id: {}",
            receipt.event_id
        )));
    }
    receipts.push(receipt);
    Ok(())
}

/// typed receipt 与既有 receipt 家族共享同一有限事务容量：超过即 Validation
/// fail-closed 回滚整个事务，绝不把任一 receipt 通道变成无界队列。
fn ensure_typed_source_receipt_capacity(total: usize) -> Result<(), AstralError> {
    if total >= PROJECTION_RECEIPT_CAP {
        return Err(AstralError::Validation(format!(
            "authorization source transaction exceeded its receipt cap ({PROJECTION_RECEIPT_CAP})"
        )));
    }
    Ok(())
}

///
/// 直接持有 hub 的 owned RAII `SourceTransactionGuard`（begin 先增
/// `active_source_writers` + `mutation_revision`，Drop 减计数并 bump
/// revision，供在线 reconcile 识别"活跃 source writer / revision 变化"）。
/// 完整合同：DB 事务开始**之前**取得，持有到 commit/rollback（含 commit 后
/// dispatch）完成；COMMIT await 之前 arm、Ok 证明才 disarm，取消/未知 Drop 使
/// hub uncertain sticky。hub 未安装（纯测试、离线工具、Rabbit 模式）时为
/// `None`，行为不变。
pub(crate) type SourceTransactionActivityFence = Option<astral_db::SourceTransactionGuard>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemMutationOwner {
    DelegationExpiry,
    AuditLog,
}

/// Capability classification carried by mutation contexts.
///
/// `UserPending` is retained only for legacy/unit context construction and is
/// rejected before a user source transaction opens. It must never be treated
/// as equivalent to a verified admission. System capability is restricted to
/// named internal owners so an advisory decision cannot be turned into an
/// unqualified source transaction by ordinary request code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SourceMutationCapability {
    UserPending,
    User(AuthorizationAdmission),
    System(SystemMutationOwner),
}

impl SourceMutationCapability {
    pub(crate) fn user(admission: AuthorizationAdmission) -> Self {
        Self::User(admission)
    }

    pub(crate) fn system_for_delegation_expiry() -> Self {
        Self::System(SystemMutationOwner::DelegationExpiry)
    }

    pub(crate) fn system_for_audit_log() -> Self {
        Self::System(SystemMutationOwner::AuditLog)
    }
}

/// Open the source transaction appropriate for the explicit mutation capability.
pub(crate) async fn begin_source_transaction_with_capability(
    pool: &sqlx::MySqlPool,
    capability: &SourceMutationCapability,
) -> Result<AuthorizationSourceTransaction, AstralError> {
    match capability {
        SourceMutationCapability::User(admission) => {
            AuthorizationSourceTransaction::begin_with_admission(pool, admission.clone()).await
        }
        SourceMutationCapability::System(_) => AuthorizationSourceTransaction::begin(pool).await,
        SourceMutationCapability::UserPending => Err(AstralError::Pending(
            "authorization admission is required for user source mutation".into(),
        )),
    }
}

/// Open a source transaction with a startup-frozen delivery context.
///
/// The context is supplied by the composition root as an immutable `Arc`; this
/// factory never reads environment/configuration and never consults a mutable
/// recipient roster. Callers that can append invalidation intents must use this
/// entry point. Config-only and delta-only owners may keep the context-free
/// factory above because their source-outcome lanes do not stage delivery rows.
pub(crate) async fn begin_source_transaction_with_capability_and_delivery_context(
    pool: &sqlx::MySqlPool,
    capability: &SourceMutationCapability,
    delivery_context: Arc<InvalidationDeliveryContext>,
) -> Result<AuthorizationSourceTransaction, AstralError> {
    match capability {
        SourceMutationCapability::User(admission) => {
            AuthorizationSourceTransaction::begin_with_admission_and_delivery_context(
                pool,
                admission.clone(),
                delivery_context,
            )
            .await
        }
        SourceMutationCapability::System(_) => {
            AuthorizationSourceTransaction::begin_with_delivery_context(pool, delivery_context)
                .await
        }
        SourceMutationCapability::UserPending => Err(AstralError::Pending(
            "authorization admission is required for user source mutation".into(),
        )),
    }
}

/// Open through the immutable context when the owner was constructed with one;
/// otherwise retain the legacy context-free constructor and let any attempted
/// delivery-dependent append fail closed inside the source transaction.
pub(crate) async fn begin_source_transaction_with_capability_and_optional_delivery_context(
    pool: &sqlx::MySqlPool,
    capability: &SourceMutationCapability,
    delivery_context: Option<&Arc<InvalidationDeliveryContext>>,
) -> Result<AuthorizationSourceTransaction, AstralError> {
    match delivery_context {
        Some(context) => {
            begin_source_transaction_with_capability_and_delivery_context(
                pool,
                capability,
                Arc::clone(context),
            )
            .await
        }
        None => match capability {
            // All request-bound source mutations in the expanded repository set
            // can reach a delivery-producing path. Do not let the compatibility
            // constructor silently commit a user mutation without its frozen
            // journal context; the composition root must use the new constructor.
            SourceMutationCapability::User(_) => Err(AstralError::Pending(
                "user source mutation requires an injected immutable invalidation delivery context"
                    .into(),
            )),
            SourceMutationCapability::System(_) => {
                begin_source_transaction_with_capability(pool, capability).await
            }
            SourceMutationCapability::UserPending => Err(AstralError::Pending(
                "authorization admission is required for user source mutation".into(),
            )),
        },
    }
}

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
    /// Optional proof-bound capability. `begin` remains for controlled internal
    /// system/projector paths; user-facing source mutations must use
    /// `begin_with_admission`.
    admission: Option<AuthorizationAdmission>,
    /// typed invalidation envelopes appended to the durable outbox in-tx.
    receipts: Vec<InvalidationReceipt>,
    /// exact legacy source projection identities appended in the same tx.
    source_projection_receipts: Vec<SourceProjectionReceipt>,
    /// 完整 projection delta requests 已在事务内 append 成 durable 行，
    /// commit 证明后直接发送；与 durable 行同一请求，commit 后不 reload。
    projection_receipts: Vec<astral_db::DeltaEventAppendRequest>,
    /// typed（config）owner 在本事务内密封的真实 before/after 行镜像
    /// receipt（opaque，唯一构造点是 astral_db 的 capture delegate）。
    typed_source_images: Vec<TypedSourceRowImageReceipt>,
    /// typed（config）owner 的同事务 audit_log 关联 receipt（真实 id）。
    typed_source_audits: Vec<TypedSourceAuditReceipt>,
    /// Eligibility owner 的 opaque source evidence；只能由其同事务 capture
    /// delegate 生成，不能由 config/delta writer 自行改写成资格完成。
    eligibility_source: Option<EligibilitySourceEvidenceReceipt>,
    /// Closed CardCreate INSERT origin retained for real grant publication.
    publication_origin: Option<EligibilitySourceEvidenceReceipt>,
    /// Closed new-card RuleSet binding receipts. These are constructed only by
    /// the child after same-transaction before/after and correlation readback.
    card_create_bindings: Vec<source_outcome::card_create::CardCreateBindingReceipt>,
    /// Immutable startup-frozen delivery context. Writers never inspect env or
    /// a mutable recipient roster while this source transaction is open.
    delivery_context: Option<Arc<InvalidationDeliveryContext>>,
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
        Self::begin_with_context(pool, None).await
    }

    /// Open a source transaction with the startup-frozen delivery context. The
    /// context is injected by the composition root and is immutable for the
    /// whole source transaction.
    pub(crate) async fn begin_with_delivery_context(
        pool: &sqlx::MySqlPool,
        delivery_context: Arc<InvalidationDeliveryContext>,
    ) -> Result<Self, AstralError> {
        Self::begin_with_context(pool, Some(delivery_context)).await
    }

    async fn begin_with_context(
        pool: &sqlx::MySqlPool,
        delivery_context: Option<Arc<InvalidationDeliveryContext>>,
    ) -> Result<Self, AstralError> {
        let _activity_fence = acquire_source_transaction_activity_fence()?;
        let tx = pool
            .begin()
            .await
            .map_err(|error| AstralError::Database(error.to_string()))?;
        Ok(Self {
            tx,
            pool: pool.clone(),
            admission: None,
            receipts: Vec::new(),
            source_projection_receipts: Vec::new(),
            projection_receipts: Vec::new(),
            typed_source_images: Vec::new(),
            typed_source_audits: Vec::new(),
            eligibility_source: None,
            card_create_bindings: Vec::new(),
            publication_origin: None,
            delivery_context,
            _activity_fence,
        })
    }

    /// Open a source transaction carrying a request-bound authorization
    /// capability. The capability is revalidated against the locked durable
    /// authority frontier/proof immediately before COMMIT.
    pub(crate) async fn begin_with_admission(
        pool: &sqlx::MySqlPool,
        admission: AuthorizationAdmission,
    ) -> Result<Self, AstralError> {
        let _activity_fence = acquire_source_transaction_activity_fence()?;
        let tx = pool
            .begin()
            .await
            .map_err(|error| AstralError::Database(error.to_string()))?;
        Ok(Self {
            tx,
            pool: pool.clone(),
            admission: Some(admission),
            receipts: Vec::new(),
            source_projection_receipts: Vec::new(),
            projection_receipts: Vec::new(),
            typed_source_images: Vec::new(),
            typed_source_audits: Vec::new(),
            eligibility_source: None,
            card_create_bindings: Vec::new(),
            publication_origin: None,
            delivery_context: None,
            _activity_fence,
        })
    }

    /// Open an admission-bound source transaction with the immutable delivery
    /// context supplied by the composition root.
    pub(crate) async fn begin_with_admission_and_delivery_context(
        pool: &sqlx::MySqlPool,
        admission: AuthorizationAdmission,
        delivery_context: Arc<InvalidationDeliveryContext>,
    ) -> Result<Self, AstralError> {
        let _activity_fence = acquire_source_transaction_activity_fence()?;
        let tx = pool
            .begin()
            .await
            .map_err(|error| AstralError::Database(error.to_string()))?;
        Ok(Self {
            tx,
            pool: pool.clone(),
            admission: Some(admission),
            receipts: Vec::new(),
            source_projection_receipts: Vec::new(),
            projection_receipts: Vec::new(),
            typed_source_images: Vec::new(),
            typed_source_audits: Vec::new(),
            eligibility_source: None,
            card_create_bindings: Vec::new(),
            publication_origin: None,
            delivery_context: Some(delivery_context),
            _activity_fence,
        })
    }

    pub(crate) fn stage_card_create_binding(
        &mut self,
        receipt: source_outcome::card_create::CardCreateBindingReceipt,
    ) -> Result<(), AstralError> {
        if self.publication_origin.is_none() && self.eligibility_source.is_none() {
            return Err(AstralError::Pending(
                "CardCreate RuleSet binding evidence requires a captured card origin".into(),
            ));
        }
        if self
            .card_create_bindings
            .iter()
            .any(|existing| existing.rule_set_id() == receipt.rule_set_id())
        {
            return Err(AstralError::Validation(
                "duplicate CardCreate RuleSet binding receipt".into(),
            ));
        }
        if self.card_create_bindings.len() >= PROJECTION_RECEIPT_CAP {
            return Err(AstralError::Validation(
                "CardCreate RuleSet binding receipt capacity exceeded".into(),
            ));
        }
        self.card_create_bindings.push(receipt);
        Ok(())
    }

    pub(crate) async fn begin_card_create_binding(
        &mut self,
        start: source_outcome::card_create::CardCreateBindingStart,
    ) -> Result<source_outcome::card_create::CardCreateBindingBefore, AstralError> {
        source_outcome::card_create::begin_card_create_binding_in_raw_tx(&mut self.tx, start).await
    }

    pub(crate) async fn finish_card_create_binding(
        &mut self,
        before: source_outcome::card_create::CardCreateBindingBefore,
        ref_id: i64,
        rule_projection: &astral_db::ProjectionEventIdentity,
        parent_projection: &astral_db::ProjectionEventIdentity,
        addition: &crate::repository::rule_set_repository::CardCreateRulesetAddition,
        actor_id: i64,
    ) -> Result<(), AstralError> {
        let receipt = source_outcome::card_create::finish_card_create_binding_in_tx(
            self,
            before,
            ref_id,
            rule_projection,
            parent_projection,
            addition,
            actor_id,
        )
        .await?;
        self.stage_card_create_binding(receipt)
    }

    pub(crate) fn record_source_projection_receipt(
        &mut self,
        receipt: SourceProjectionReceipt,
    ) -> Result<(), AstralError> {
        if receipt.event_id.trim().is_empty()
            || receipt.aggregate_type.trim().is_empty()
            || receipt.aggregate_id <= 0
            || receipt.tenant_id.is_some_and(|tenant_id| tenant_id <= 0)
            || receipt.source_generation <= 0
            || receipt.revoke_fence < 0
            || receipt.revoke_fence > receipt.source_generation
        {
            return Err(AstralError::Validation(
                "source projection receipt identity is invalid".into(),
            ));
        }
        append_unique_source_projection_receipt(&mut self.source_projection_receipts, receipt)
    }

    /// Return proof-derived message provenance for user-authorized source paths.
    /// Internal/projector transactions have no user admission and therefore
    /// cannot emit evidence invalidations that claim authorization provenance.
    pub(crate) fn authority_message_metadata(
        &self,
        operation_id: &str,
        event_id: &str,
    ) -> Result<AuthorizationMessageMetadata, AstralError> {
        let admission = self.admission.as_ref().ok_or_else(|| {
            AstralError::Pending(
                "evidence invalidation requires proof-bound authorization admission".into(),
            )
        })?;
        let proof = admission.proof();
        let staged = self
            .projection_receipts
            .iter()
            .any(|receipt| receipt.operation_id == operation_id && receipt.event_id == event_id);
        if !staged || operation_id.is_empty() || event_id.is_empty() {
            return Err(AstralError::Pending(
                "evidence invalidation has no exact delta receipt in this source transaction"
                    .into(),
            ));
        }
        AuthorizationMessageMetadata::from_verified_proof(proof)
            .map_err(|error| AstralError::Pending(error.to_string()))
    }

    /// 登记一条已在**本事务内** append 进 durable outbox 的 invalidation receipt。    ///
    /// envelope 必须与 outbox 行逐字节同源（同一构造实例）；没有 published
    /// pointer 的路径不产生 receipt。
    pub(crate) fn record_invalidation_receipt(&mut self, receipt: InvalidationReceipt) {
        self.receipts.push(receipt);
    }

    /// Register an exact source projection identity returned by the shared
    /// append helper. This keeps source correlation in the same commit batch as
    /// deltas and invalidation receipts.
    pub(crate) fn record_source_projection_identity(
        &mut self,
        aggregate: ProjectionAggregate,
        aggregate_id: i64,
        identity: astral_db::ProjectionEventIdentity,
    ) -> Result<(), AstralError> {
        self.record_source_projection_receipt(SourceProjectionReceipt {
            event_id: identity.event_id,
            aggregate_type: aggregate.as_str().to_owned(),
            aggregate_id,
            tenant_id: identity.tenant_id,
            source_generation: identity.source_generation,
            revoke_fence: identity.revoke_fence,
        })
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

    /// 打开一个结构性绑定**本事务**的 typed config 行镜像捕获句柄。
    ///
    /// 捕获期间事务的独占可变借用归 delegate 所有；writer 的 mutation SQL
    /// 只能经 `with_tx_mut` 在该事务上执行，before/after 捕获与 mutation
    /// 不可能跨事务。seal 消费句柄后借用归还，audit 关联与登记随后进行。
    pub(crate) fn typed_row_capture(
        &mut self,
        table: TypedSourceTable,
        operation: TypedRowOperation,
    ) -> astral_db::TypedSourceRowCapture<'_> {
        astral_db::TypedSourceRowCapture::begin_in_tx(&mut self.tx, table, operation)
    }

    /// 登记一条本事务内密封的 typed config 行镜像 receipt（finite capacity）。
    pub(crate) fn stage_typed_source_image(
        &mut self,
        receipt: TypedSourceRowImageReceipt,
    ) -> Result<(), AstralError> {
        ensure_typed_source_receipt_capacity(
            self.projection_receipts.len()
                + self.source_projection_receipts.len()
                + self.receipts.len()
                + self.typed_source_images.len()
                + self.typed_source_audits.len(),
        )?;
        let identity = (receipt.table().as_str().to_owned(), receipt.key());
        if self
            .typed_source_images
            .iter()
            .any(|existing| (existing.table().as_str().to_owned(), existing.key()) == identity)
        {
            return Err(AstralError::Validation(
                "duplicate typed source image receipt identity".into(),
            ));
        }
        self.typed_source_images.push(receipt);
        Ok(())
    }

    /// Record the actual source audit insert id as an opaque same-transaction receipt.
    pub(crate) fn stage_typed_source_audit_insert_id(
        &mut self,
        audit_log_id: i64,
    ) -> Result<(), AstralError> {
        let receipt = astral_db::TypedSourceAuditReceipt::from_same_tx_insert_id(audit_log_id)?;
        self.stage_typed_source_audit(receipt)
    }

    /// 登记一条同事务 audit_log 关联 receipt（真实 durable id）。
    pub(crate) fn stage_typed_source_audit(
        &mut self,
        receipt: TypedSourceAuditReceipt,
    ) -> Result<(), AstralError> {
        ensure_typed_source_receipt_capacity(
            self.projection_receipts.len()
                + self.source_projection_receipts.len()
                + self.receipts.len()
                + self.typed_source_images.len()
                + self.typed_source_audits.len(),
        )?;
        self.typed_source_audits.push(receipt);
        Ok(())
    }

    /// Stage the opaque eligibility source evidence produced by the eligibility
    /// owner. The parent only owns the single-slot boundary; construction and
    /// validation remain in `authority_eligibility_completion`.
    pub(crate) fn stage_eligibility_source(
        &mut self,
        receipt: EligibilitySourceEvidenceReceipt,
    ) -> Result<(), AstralError> {
        if self.eligibility_source.is_some()
            || self.publication_origin.is_some()
            || receipt.is_publication_origin()
        {
            return Err(AstralError::Validation(
                "authorization source transaction requires one independent eligibility receipt"
                    .into(),
            ));
        }
        self.eligibility_source = Some(receipt);
        Ok(())
    }

    pub(crate) fn stage_card_publication_origin(
        &mut self,
        receipt: EligibilitySourceEvidenceReceipt,
    ) -> Result<(), AstralError> {
        if self.eligibility_source.is_some()
            || self.publication_origin.is_some()
            || !receipt.is_publication_origin()
        {
            return Err(AstralError::Validation(
                "card publication requires one closed publication origin".into(),
            ));
        }
        self.publication_origin = Some(receipt);
        Ok(())
    }

    /// Consume the staged eligibility evidence after the parent transaction has
    /// handed it to the owner-specific source-outcome path.
    pub(crate) fn take_eligibility_source(&mut self) -> Option<EligibilitySourceEvidenceReceipt> {
        self.eligibility_source.take()
    }

    /// Validate that the eligibility owner's opaque receipt accounts for the
    /// projection and invalidation rows already staged by the parent helper.
    /// Those receipts remain in the parent for post-commit dispatch; the opaque
    /// receipt is the separate source-outcome proof and must not be used to
    /// replace or duplicate those dispatch vectors.
    fn validate_eligibility_side_effect_receipts(
        &self,
        receipt: &EligibilitySourceEvidenceReceipt,
    ) -> Result<(), AstralError> {
        let expected_projection: std::collections::BTreeSet<&str> = self
            .source_projection_receipts
            .iter()
            // An eligibility opaque receipt proves the eligibility projection
            // identities only. Other source streams (for example CARD_REVOKE)
            // remain parent-owned dispatch receipts and are intentionally kept
            // outside this lane's exact-match set.
            .filter(|entry| entry.aggregate_type == ProjectionAggregate::Eligibility.as_str())
            .map(|entry| entry.event_id.as_str())
            .collect();
        if expected_projection.len()
            != self
                .source_projection_receipts
                .iter()
                .filter(|entry| entry.aggregate_type == ProjectionAggregate::Eligibility.as_str())
                .count()
        {
            return Err(AstralError::Pending(
                "parent eligibility projection receipts contain duplicate identities".into(),
            ));
        }
        let expected_invalidation: std::collections::BTreeSet<&str> = self
            .receipts
            .iter()
            .map(|entry| entry.event_id.as_str())
            .collect();
        if expected_invalidation.len() != self.receipts.len() {
            return Err(AstralError::Pending(
                "parent invalidation receipts contain duplicate identities".into(),
            ));
        }
        let mut actual_projection = std::collections::BTreeSet::new();
        let mut actual_invalidation = std::collections::BTreeSet::new();
        for source in receipt.source_receipts() {
            match source.entity.as_str() {
                "authorization_projection_outbox" => {
                    if !actual_projection.insert(source.durable_id.as_str()) {
                        return Err(AstralError::Pending(
                            "eligibility source receipt contains duplicate projection identity"
                                .into(),
                        ));
                    }
                }
                "al_message_outbox" if !actual_invalidation.insert(source.durable_id.as_str()) => {
                    return Err(AstralError::Pending(
                        "eligibility source receipt contains duplicate invalidation identity"
                            .into(),
                    ));
                }
                "al_message_outbox" => {}
                // audit_log and any other identity-owned source receipts belong
                // to the opaque eligibility contract and are checked by its
                // source-outcome owner, not by the parent dispatch vectors.
                _ => {}
            }
        }
        if actual_projection != expected_projection {
            return Err(AstralError::Pending(
                "eligibility source receipt does not exactly cover staged projection identities"
                    .into(),
            ));
        }
        if actual_invalidation != expected_invalidation {
            return Err(AstralError::Pending(
                "eligibility source receipt does not exactly cover staged invalidation identities"
                    .into(),
            ));
        }
        Ok(())
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

    /// Commit and return the exact staged delta batch only after COMMIT is proven.
    /// The established source dispatcher remains the sole post-commit hand-off;
    /// completion waiting is performed once by the receipt-aware writer path.
    pub(crate) async fn commit_consuming_with_receipts(
        self,
    ) -> Result<CommittedProjectionReceipts, AstralError> {
        let invalidation_dispatcher = LocalBusInvalidationDispatcher {
            pool: self.pool.clone(),
        };
        self.commit_consuming_with_dispatchers_and_receipts(
            &AstralDbProjectionDeltaDispatcher,
            &invalidation_dispatcher,
        )
        .await
    }

    /// Commit through injected dispatchers, then observe exact durable completion.
    /// Dispatch order is projection delta followed by invalidation; dispatch
    /// admission never proves projection completion.
    pub(crate) async fn commit_consuming_with_dispatchers<
        P: ProjectionDeltaDispatcher,
        D: InvalidationDispatcher,
    >(
        self,
        projection_dispatcher: &P,
        invalidation_dispatcher: &D,
    ) -> Result<(), AstralError> {
        let pool = self.pool.clone();
        let receipts = self
            .commit_consuming_with_dispatchers_and_receipts(
                projection_dispatcher,
                invalidation_dispatcher,
            )
            .await?;
        crate::service::sync_publish::require_committed_receipts(&pool, &receipts).await?;
        Ok(())
    }

    /// Receipt-returning form for writers that await exact post-commit completion.
    pub(crate) async fn commit_consuming_with_dispatchers_and_receipts<
        P: ProjectionDeltaDispatcher,
        D: InvalidationDispatcher,
    >(
        mut self,
        projection_dispatcher: &P,
        invalidation_dispatcher: &D,
    ) -> Result<CommittedProjectionReceipts, AstralError> {
        // Consume the opaque eligibility slot before entering the config/delta
        // source-outcome lane. The two lanes are mutually exclusive: eligibility
        // completion owns its identity/target/evidence contract, while config and
        // delta completion must never reinterpret that receipt.
        let eligibility_source = self.take_eligibility_source();
        let publication_origin = self.publication_origin.take();
        if let Some(receipt) = publication_origin.as_ref() {
            self.validate_eligibility_side_effect_receipts(receipt)?;
            if eligibility_source.is_some()
                || self.projection_receipts.is_empty()
                || !self.typed_source_images.is_empty()
                || !self.typed_source_audits.is_empty()
                || self.admission.is_none()
            {
                return Err(AstralError::Pending(
                    "new-card publication origin requires an admitted real grant delta batch"
                        .into(),
                ));
            }
        }
        if let Some(receipt) = eligibility_source.as_ref() {
            self.validate_eligibility_side_effect_receipts(receipt)?;
            if !self.projection_receipts.is_empty()
                || !self.typed_source_images.is_empty()
                || !self.typed_source_audits.is_empty()
            {
                return Err(AstralError::Pending(
                    "eligibility source evidence cannot mix with grant delta or config evidence"
                        .into(),
                ));
            }
        }
        if eligibility_source.is_some() && self.admission.is_none() {
            return Err(AstralError::Pending(
                "eligibility source evidence requires a proof-bound admission".into(),
            ));
        }
        if let Some(admission) = self.admission.as_ref() {
            astral_db::consume_authorization_admission_in_tx(&mut self.tx, admission)
                .await
                .map_err(AstralError::from)?;
            if let Some(receipt) = eligibility_source {
                let empty_card = if receipt.operation()
                    == astral_db::authority_eligibility_completion::EligibilitySourceOperation::CardCreate
                {
                    receipt.completion().cards.first().map(|card| &card.scope).and_then(|scope| {
                        match scope {
                            astral_types::AuthorityProtocolScope::Card(card) => {
                                Some((card.tenant_id, card.card_id))
                            }
                            _ => None,
                        }
                    })
                } else {
                    None
                };
                source_outcome::stage_eligibility_source_outcome(
                    &mut self.tx,
                    admission,
                    receipt,
                    &self.card_create_bindings,
                )
                .await?;
                if let Some((tenant_id, card_id)) = empty_card {
                    astral_db::stage_empty_card_origin_in_tx(
                        &mut self.tx,
                        admission,
                        tenant_id,
                        card_id,
                    )
                    .await
                    .map_err(AstralError::from)?;
                }
            } else {
                source_outcome::stage_source_outcome(
                    &mut self.tx,
                    source_outcome::SourceOutcomeBatch {
                        admission,
                        deltas: &self.projection_receipts,
                        sources: &self.source_projection_receipts,
                        invalidations: &self.receipts,
                        source_images: &self.typed_source_images,
                        source_audits: &self.typed_source_audits,
                        publication_origin: publication_origin.as_ref(),
                        card_create_bindings: &self.card_create_bindings,
                    },
                )
                .await?;
            }
            admission
                .consume_once()
                .map_err(|error| AstralError::Pending(error.to_string()))?;
        } else if eligibility_source.is_some() {
            return Err(AstralError::Pending(
                "eligibility source evidence cannot be staged without admission".into(),
            ));
        }
        let commit_started = Instant::now();
        // 取消安全：在 await COMMIT **之前** arm 栅栏。COMMIT 等待期间本 future
        // 被取消时，guard 携带 unproven Drop，hub 置 sticky uncertain —— 提交
        // 结果未知即保持未知，绝不当作已回滚，也绝不投递 receipts。
        if let Some(guard) = self._activity_fence.as_ref() {
            guard.mark_commit_started();
        }
        let commit_result = self.tx.commit().await;
        let commit_elapsed = commit_started.elapsed();
        // 唯一发送决策点：commit 未知/失败 ⇒ 三类 receipts 都是空集，绝不发送。
        let deltas = receipts_for_proven_commit(&mut self.projection_receipts, &commit_result);
        let source_projection_receipts =
            receipts_for_proven_commit(&mut self.source_projection_receipts, &commit_result);
        let invalidations = receipts_for_proven_commit(&mut self.receipts, &commit_result);
        let (delta_count, source_projection_count, invalidation_count) = (
            deltas.len(),
            source_projection_receipts.len(),
            invalidations.len(),
        );
        if let Err(error) = commit_result {
            // SQL commit Err 无法证明回滚（真实结果可能已提交）：保守把 hub 标记为
            // uncertain（sticky），在线 reconcile 不得清理与本 writer 相关的 pending；
            // 绝不重放 source，也绝不伪装回滚 —— 由独立 event 线性化对账收口。
            if let Some(guard) = self._activity_fence.as_ref() {
                guard.mark_uncertain();
            }
            return Err(AstralError::Database(error.to_string()));
        }
        let committed_projection_receipts = CommittedProjectionReceipts {
            requests: deltas.clone(),
            source_projection_receipts: source_projection_receipts.clone(),
            invalidation_receipts: invalidations.clone(),
        };
        // 只有 Ok 证明才 disarm：disarm 只复位本 guard 自身的 unproven 标志，
        // 另一 writer 造成的 hub uncertain 是 sticky 的，绝不在本 writer 的
        // proven 路径上清除。
        if let Some(guard) = self._activity_fence.as_ref() {
            guard.mark_commit_proven();
        }
        tracing::debug!(
            projection_receipts = delta_count,
            source_projection_receipts = source_projection_count,
            invalidation_receipts = invalidation_count,
            commit_elapsed_ms = commit_elapsed.as_millis() as u64,
            "authorization source commit proven; dispatching projection deltas and invalidation receipts"
        );
        dispatch_proven_projection_deltas(deltas, projection_dispatcher);
        dispatch_proven_receipts(invalidations, invalidation_dispatcher).await;
        Ok(committed_projection_receipts)
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

/// Append eligibility projection and invalidation while a DB-owned capture owns
/// the raw transaction borrow. The caller registers both returned identities on
/// the parent only after the capture is finished.
pub(crate) async fn append_eligibility_projection_with_invalidation_on_raw_tx(
    tx: &mut Transaction<'_, MySql>,
    delivery_context: &InvalidationDeliveryContext,
    card_id: i64,
    operation_id: &str,
) -> Result<(SourceProjectionReceipt, InvalidationReceipt), AstralError> {
    let identity = astral_db::append_projection_event_with_metadata_in_tx(
        tx,
        ProjectionAggregate::Eligibility,
        card_id,
        EVENT_TYPE_ELIGIBILITY_UPDATE,
        None,
    )
    .await?;
    let source_projection = SourceProjectionReceipt {
        event_id: identity.event_id.clone(),
        aggregate_type: ProjectionAggregate::Eligibility.as_str().to_owned(),
        aggregate_id: card_id,
        tenant_id: identity.tenant_id,
        source_generation: identity.source_generation,
        revoke_fence: identity.revoke_fence,
    };
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
        authority_metadata_json: None,
        payload_sha256: &envelope.payload_sha256,
    };
    astral_db::append_in_tx(tx, &input)
        .await
        .map_err(|error| AstralError::Database(error.to_string()))?;
    astral_db::invalidation_delivery::stage_invalidation_delivery_with_context_in_tx(
        tx,
        delivery_context,
        &envelope.message_id,
    )
    .await
    .map_err(|error| {
        AstralError::Pending(format!("invalidation delivery staging failed: {error}"))
    })?;
    Ok((
        source_projection,
        InvalidationReceipt {
            event_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            envelope,
        },
    ))
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
    let delivery_context = tx.delivery_context.clone().ok_or_else(|| {
        AstralError::Pending(
            "eligibility invalidation requires an injected immutable delivery context".into(),
        )
    })?;
    let (source_projection, invalidation) =
        append_eligibility_projection_with_invalidation_on_raw_tx(
            &mut *tx,
            &delivery_context,
            card_id,
            operation_id,
        )
        .await?;
    tx.record_source_projection_receipt(source_projection)?;
    tx.record_invalidation_receipt(invalidation);
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
            stamp: astral_types::PublicationStamp::new(
                published_generation,
                "ab".repeat(32),
                astral_types::PublicationSeal::from_unix_seconds(1_700_000_000).unwrap(),
            )
            .unwrap(),
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
            compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.into(),
            next_attempt_at: None,
        }
    }

    #[test]
    fn duplicate_source_projection_receipts_fail_closed() {
        let receipt = SourceProjectionReceipt {
            event_id: "source-event-1".into(),
            aggregate_type: ProjectionAggregate::CARD.to_owned(),
            aggregate_id: 42,
            tenant_id: Some(7),
            source_generation: 1,
            revoke_fence: 0,
        };
        let mut receipts = vec![receipt.clone()];
        assert!(matches!(
            append_unique_source_projection_receipt(&mut receipts, receipt),
            Err(AstralError::Validation(message))
                if message.contains("duplicate source projection receipt")
        ));
        assert_eq!(receipts.len(), 1);
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

    // ── source-owner completion staging/reconciliation seam（纯逻辑测试）──

    #[test]
    fn committed_batch_identity_carries_stable_frozen_identities() {
        let receipts = CommittedProjectionReceipts {
            requests: vec![delta_request("d-1", 1)],
            source_projection_receipts: vec![SourceProjectionReceipt {
                event_id: "src-event-1".into(),
                aggregate_type: ProjectionAggregate::CARD.to_owned(),
                aggregate_id: 42,
                tenant_id: Some(7),
                source_generation: 11,
                revoke_fence: 0,
            }],
            invalidation_receipts: vec![],
        };
        let batch = committed_batch_identity_from_receipts(&receipts);
        assert!(
            batch.commit_proven,
            "this conversion only runs on the proven-Ok commit path"
        );
        assert_eq!(batch.operation_id, OPERATION);
        assert_eq!(batch.event_id, "d-1");
        assert!(
            batch.message_id.is_empty(),
            "no invalidation staged: no message id is invented"
        );
    }

    #[test]
    fn committed_batch_identity_prefers_first_source_identity_when_no_deltas() {
        // Build the invalidation receipt from the SAME frozen projection event
        // id as the staged source receipt: the message id equals the
        // projection event id by envelope construction contract.
        let (_, envelope) =
            eligibility_invalidation_envelope(42, OPERATION, "src-event-1", "city-a")
                .expect("valid eligibility invalidation envelope");
        let receipts = CommittedProjectionReceipts {
            requests: vec![],
            source_projection_receipts: vec![SourceProjectionReceipt {
                event_id: "src-event-1".into(),
                aggregate_type: ProjectionAggregate::CARD.to_owned(),
                aggregate_id: 42,
                tenant_id: Some(7),
                source_generation: 11,
                revoke_fence: 0,
            }],
            invalidation_receipts: vec![InvalidationReceipt {
                event_id: envelope.message_id.clone(),
                operation_id: envelope.operation_id.clone(),
                envelope,
            }],
        };
        let batch = committed_batch_identity_from_receipts(&receipts);
        assert_eq!(batch.event_id, "src-event-1");
        assert_eq!(
            batch.message_id, "src-event-1",
            "the invalidation message id is the same projection event id by contract"
        );
    }

    #[test]
    fn committed_batch_identity_rejects_mixed_operation_identities() {
        let mut second = delta_request("d-2", 2);
        second.operation_id = "different-operation".into();
        let receipts = CommittedProjectionReceipts {
            requests: vec![delta_request("d-1", 1), second],
            source_projection_receipts: vec![],
            invalidation_receipts: vec![],
        };
        assert_eq!(
            committed_batch_identity_from_receipts(&receipts),
            astral_db::CommittedBatchIdentity::default(),
            "mixed source operations must remain unknown"
        );
    }

    #[test]
    fn committed_batch_identity_rejects_multiple_event_identities() {
        let receipts = CommittedProjectionReceipts {
            requests: vec![delta_request("d-1", 1), delta_request("d-2", 2)],
            source_projection_receipts: vec![],
            invalidation_receipts: vec![],
        };
        assert_eq!(
            committed_batch_identity_from_receipts(&receipts),
            astral_db::CommittedBatchIdentity::default(),
            "a correlation seam must not select the first event from a multi-event batch"
        );
    }

    #[test]
    fn committed_batch_identity_rejects_invalidation_identity_drift() {
        let mut invalidation = eligibility_receipt(42);
        invalidation.envelope.operation_id = "different-operation".into();
        let receipts = CommittedProjectionReceipts {
            requests: vec![delta_request("elig-proj-event-1", 1)],
            source_projection_receipts: vec![],
            invalidation_receipts: vec![invalidation],
        };
        assert_eq!(
            committed_batch_identity_from_receipts(&receipts),
            astral_db::CommittedBatchIdentity::default(),
            "invalidation drift must not be promoted to a reconciliable identity"
        );
    }

    #[test]
    fn committed_batch_identity_rejects_operationless_batches() {
        let receipts = CommittedProjectionReceipts {
            requests: vec![],
            source_projection_receipts: vec![SourceProjectionReceipt {
                event_id: "source-event".into(),
                aggregate_type: ProjectionAggregate::CARD.to_owned(),
                aggregate_id: 42,
                tenant_id: Some(7),
                source_generation: 11,
                revoke_fence: 0,
            }],
            invalidation_receipts: vec![],
        };
        assert_eq!(
            committed_batch_identity_from_receipts(&receipts),
            astral_db::CommittedBatchIdentity::default(),
            "a source event without a durable operation identity is unknown"
        );
    }

    #[test]
    fn seam_stages_a_committed_batch_as_pending_reconciliation() {
        let receipts = CommittedProjectionReceipts {
            requests: vec![delta_request("d-1", 1)],
            source_projection_receipts: vec![],
            invalidation_receipts: vec![],
        };
        match stage_family_completion_for_reconciliation(&receipts) {
            FamilyCompletionSeamOutcome::PendingReconciliation { batch } => {
                assert!(batch.commit_proven);
                assert_eq!(batch.operation_id, OPERATION);
                assert_eq!(batch.event_id, "d-1");
            }
            other => panic!("a committed batch stays reconcilable: {other:?}"),
        }
    }

    #[test]
    fn seam_refuses_to_invent_identities_for_an_empty_batch() {
        let receipts = CommittedProjectionReceipts::default();
        match stage_family_completion_for_reconciliation(&receipts) {
            FamilyCompletionSeamOutcome::Unknown { batch } => {
                assert!(batch.operation_id.is_empty() && batch.event_id.is_empty());
            }
            other => panic!("an empty batch must not produce a reconcilable identity: {other:?}"),
        }
    }

    /// include_str! 结构断言：seam 只把批次转换成关联身份并显式 pending/unknown，
    /// 绝不在 trustgraph 侧构造 terminal family completion 或持久化 PROVEN 行。
    #[test]
    fn seam_never_constructs_terminal_family_completion_in_this_crate() {
        let source = include_str!("authorization_source_transaction.rs");
        let seam_start = source
            .find("Source-owner completion staging/reconciliation seam")
            .expect("the seam section must exist");
        let seam_end = source[seam_start..]
            .find("fn validate_projection_receipt")
            .expect("the seam section must end before the delta validator");
        let seam = &source[seam_start..seam_start + seam_end];
        assert!(
            !seam.contains("AuthorityFamilyCompletionState::Complete"),
            "the source transaction seam must never mint a terminal completion state"
        );
        assert!(
            !seam.contains("record_proven_certified_memory_completion_in_tx"),
            "the proof-only writer must not be called from this seam without a verified receipt"
        );
        assert!(
            seam.contains("PendingReconciliation"),
            "the seam must expose an explicit pending/reconciliation boundary"
        );
        assert!(
            seam.contains("commit_proven"),
            "the seam identity must carry the proven-commit flag explicitly"
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
