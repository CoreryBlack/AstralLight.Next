//! 授权 source 提交后的有界发布观察与 legacy 同步发布兼容入口。
//!
//! `WorkerOwned` 只接受已证明 source COMMIT 的完整 receipt 批次，并按每条
//! receipt 的完整不可变绑定验证历史 durable completion。请求不认领、编译、
//! 发布、释放或取消 worker lease；超时仅委派，不改变 source 结果或执行预算。
//! LocalBus admission、ACK、单个 SUCCEEDED 状态和最新 pointer 都不是完成证明。
//!
//! `LegacyHybrid` 保留请求侧 claim/process/publish 的兼容行为；仅有 event id 的
//! 入口在 `WorkerOwned` 中直接委派，不能据此重新进入公共候选集合。任一模式
//! 超过事件上限都整批委派，不截断批次后报告 Published。
//!
//! 发布/等待发生在 source 短事务结束之后。失败只记录，不反转已提交写入的返回
//! 合同。撤销/收窄仍由 strict pending-invalidates gate 阻止旧授权放行。

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::MySqlPool;

use super::authorization_projector::{
    process_one_event, AuthorizationProjectorConfig, AuthorizationProjectorRuntime,
    ProjectorCancellationToken, SqlxAuthorizationProjectorRuntime, WorkerRunSummary,
};
use crate::observability::{
    record_projector_event, record_sync_publish, ProjectorEventOutcome, SyncPublishMetricOutcome,
};
use crate::repository::authorization_source_transaction::CommittedProjectionReceipts;

/// 影响面阈值：legacy 模式下限制请求内同步发布；worker-owned 模式下限制有界
/// completion 等待。超过阈值时整批交由 worker，避免请求延迟随扇出扩大。
pub const SYNC_PUBLISH_MAX_AFFECTED_CARDS: usize = 50;

/// post-commit 请求侧工作的整体墙钟预算：legacy 模式覆盖 claim/发布，worker-owned
/// 模式覆盖只读 completion 等待。到期后写请求继续返回，事件仍由 worker 收敛。
pub const SYNC_PUBLISH_BUDGET: Duration = Duration::from_secs(5);

/// 单次同步发布的事件预算（防御上限）：超过上限时整批委派给 worker，绝不截断
/// 目标后把部分成功误报为完整 Published。
pub const SYNC_PUBLISH_MAX_EVENTS: usize = 32;

/// exact completion reread 的轮询间隔；LocalBus admission/ACK 不作为完成证据。
const OWNED_COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// LegacyHybrid 请求侧 claim 的租约窗口（秒）。WorkerOwned 不使用此租约；owned
/// completion 等待超时只委派给 worker，不释放或改变 worker lease。
pub const SYNC_PUBLISH_CLAIM_LEASE_SECS: i64 = 30;

/// 超时后 best-effort 释放的单次尝试预算；超过即放弃（lease 服务端过期自愈）。
const RELEASE_BUDGET: Duration = Duration::from_secs(1);

/// LegacyHybrid 请求侧同步发布的目标：一张卡在本请求内刚入账的 delta 事件集合。
///
/// `event_ids` 是 `authorization_delta_event.event_id`（各 writer 以稳定维度
/// 派生、审计已关联的 contribution 事件号），用于在 claim 队列中精确识别
/// 「本次写入的事件」——claim 原语按 `(tenant_id, card_id)` 作用域返回最老可
/// claim 事件，逐个与本集合比对，绝不对无关事件执行发布。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPublishTarget {
    pub tenant_id: i64,
    pub card_id: i64,
    pub event_ids: Vec<String>,
}

impl SyncPublishTarget {
    /// 单卡单事件目标（rule_repository 单条写路径的接线形态）。
    pub(crate) fn single(tenant_id: i64, card_id: i64, event_id: String) -> Self {
        Self {
            tenant_id,
            card_id,
            event_ids: vec![event_id],
        }
    }
}

/// 把 `(tenant_id, card_id, event_id)` 三元组按卡聚合为目标集合（去重事件号，
/// 保持出现顺序）。rule_set 扇出路径的贡献面经此归一。
pub(crate) fn group_targets(triples: Vec<(i64, i64, String)>) -> Vec<SyncPublishTarget> {
    let mut order: Vec<(i64, i64)> = Vec::new();
    let mut by_card: std::collections::HashMap<(i64, i64), Vec<String>> =
        std::collections::HashMap::new();
    for (tenant_id, card_id, event_id) in triples {
        if event_id.trim().is_empty() {
            continue;
        }
        let key = (tenant_id, card_id);
        if !by_card.contains_key(&key) {
            order.push(key);
        }
        let slot = by_card.entry(key).or_default();
        if !slot.contains(&event_id) {
            slot.push(event_id);
        }
    }
    order
        .into_iter()
        .map(|key| {
            let (tenant_id, card_id) = key;
            SyncPublishTarget {
                tenant_id,
                card_id,
                event_ids: by_card.remove(&key).unwrap_or_default(),
            }
        })
        .collect()
}

/// 阈值分流（纯逻辑）：受影响卡数落在 `(0, 阈值]` 才允许请求侧工作。
pub fn should_attempt_synchronous_publish(affected_card_count: usize) -> bool {
    affected_card_count > 0 && affected_card_count <= SYNC_PUBLISH_MAX_AFFECTED_CARDS
}

/// 同步发布结果分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPublishOutcome {
    /// 全部目标已发布（LegacyHybrid）或完整 receipt 批次的历史 durable completion
    /// proof 均已验证（WorkerOwned）。
    Published,
    /// 目标尚未全部完成，或本入口没有足够的完整 receipt；由 worker 保持所有权
    /// 并继续收敛。这也是超限或 completion 等待超时的结果。
    Delegated,
    /// 请求侧发布或 exact completion 读取失败。source COMMIT 结果不变，worker
    /// 保留 durable 恢复责任；绝不影响已提交写请求的返回值。
    Failed,
}

/// LegacyHybrid id-only 入口。WorkerOwned 没有完整 source receipt 时直接委派；
/// 其他情况下执行阈值分流和同步发布。失败不上抛，不影响请求返回值。
pub(crate) async fn after_commit_sync_publish(pool: &MySqlPool, targets: Vec<SyncPublishTarget>) {
    if astral_db::projection_execution_mode() == astral_db::ProjectionExecutionMode::WorkerOwned {
        record_sync_publish(SyncPublishMetricOutcome::Delegated, Duration::ZERO);
        return;
    }
    let started = Instant::now();
    if targets.is_empty() {
        // 本次写入没有可同步发布的 contribution（如零绑定卡/零 ALLOW 条目）：
        // 队列无新增事件，worker 无需消化，直接返回。
        record_sync_publish(SyncPublishMetricOutcome::SkippedEmpty, started.elapsed());
        return;
    }
    let distinct_cards = targets
        .iter()
        .map(|target| (target.tenant_id, target.card_id))
        .collect::<HashSet<_>>()
        .len();
    if !should_attempt_synchronous_publish(distinct_cards) {
        tracing::debug!(
            affected_cards = distinct_cards,
            threshold = SYNC_PUBLISH_MAX_AFFECTED_CARDS,
            "sync publish skipped: impact above threshold (worker digests the queue)"
        );
        record_sync_publish(
            SyncPublishMetricOutcome::SkippedImpactThreshold,
            started.elapsed(),
        );
        return;
    }
    let runtime: Arc<dyn AuthorizationProjectorRuntime> =
        Arc::new(SqlxAuthorizationProjectorRuntime::new(pool.clone()));
    let outcome = try_synchronous_publish_with_runtime(runtime, &targets).await;
    record_sync_publish(
        match outcome {
            SyncPublishOutcome::Published => SyncPublishMetricOutcome::Published,
            SyncPublishOutcome::Delegated => SyncPublishMetricOutcome::Delegated,
            SyncPublishOutcome::Failed => SyncPublishMetricOutcome::Failed,
        },
        started.elapsed(),
    );
    match outcome {
        SyncPublishOutcome::Published => {
            tracing::debug!(
                targets = targets.len(),
                "post-commit sync publish flipped the affected card(s) within the request"
            );
        }
        SyncPublishOutcome::Delegated => {
            tracing::debug!(
                targets = targets.len(),
                "post-commit sync publish delegated to the projector worker (healthy handoff)"
            );
        }
        SyncPublishOutcome::Failed => {
            tracing::warn!(
                targets = targets.len(),
                "post-commit sync publish failed; the delta event(s) stay queued and \
                 the projector worker owns convergence (write request unaffected)"
            );
        }
    }
}

/// Commit-receipt-aware post-commit path used by canonical authorization writers.
/// WorkerOwned mode only rereads durable proof for each full request; LegacyHybrid
/// keeps the existing request-side claim/publish behavior and its target set.
pub(crate) async fn after_commit_sync_publish_with_receipts(
    pool: &MySqlPool,
    targets: Vec<SyncPublishTarget>,
    receipts: CommittedProjectionReceipts,
) {
    if astral_db::projection_execution_mode() == astral_db::ProjectionExecutionMode::WorkerOwned {
        let started = Instant::now();
        let outcome =
            wait_for_owned_completion(pool, &receipts.requests, SYNC_PUBLISH_BUDGET).await;
        record_sync_publish(
            match outcome {
                SyncPublishOutcome::Published => SyncPublishMetricOutcome::Published,
                SyncPublishOutcome::Delegated => SyncPublishMetricOutcome::Delegated,
                SyncPublishOutcome::Failed => SyncPublishMetricOutcome::Failed,
            },
            started.elapsed(),
        );
        match outcome {
            SyncPublishOutcome::Published => tracing::debug!(
                receipts = receipts.requests.len(),
                "worker-owned projection completion proven for the entire source receipt batch"
            ),
            SyncPublishOutcome::Delegated => tracing::debug!(
                receipts = receipts.requests.len(),
                "worker-owned projection completion remains delegated to the durable worker"
            ),
            SyncPublishOutcome::Failed => tracing::warn!(
                receipts = receipts.requests.len(),
                "worker-owned completion waiter failed; durable worker retains ownership"
            ),
        }
        return;
    }

    after_commit_sync_publish(pool, targets).await;
}

/// Bounded read-only waiter. `Some` is accepted only from astral-db's exact
/// request-bound historical completion proof; no bus admission or ACK is proof.
pub(crate) async fn wait_for_owned_completion(
    pool: &MySqlPool,
    requests: &[astral_db::DeltaEventAppendRequest],
    budget: Duration,
) -> SyncPublishOutcome {
    wait_for_owned_completion_with(requests, budget, |request| async move {
        match astral_db::load_owned_delta_completion(pool, &request).await {
            Ok(proof) => Ok(proof.is_some()),
            Err(error) => {
                tracing::warn!(event_id = %request.event_id, error = %error,
                    "exact projection completion proof unavailable; worker ownership unchanged");
                Err(())
            }
        }
    })
    .await
}

async fn wait_for_owned_completion_with<F, Fut>(
    requests: &[astral_db::DeltaEventAppendRequest],
    budget: Duration,
    mut exact_completion: F,
) -> SyncPublishOutcome
where
    F: FnMut(astral_db::DeltaEventAppendRequest) -> Fut,
    Fut: std::future::Future<Output = Result<bool, ()>>,
{
    if requests.is_empty() {
        return SyncPublishOutcome::Delegated;
    }
    if requests.len() > SYNC_PUBLISH_MAX_EVENTS {
        return SyncPublishOutcome::Delegated;
    }
    let affected_cards = requests
        .iter()
        .filter_map(|request| request.card_id.map(|card_id| (request.tenant_id, card_id)))
        .collect::<HashSet<_>>()
        .len();
    if affected_cards > SYNC_PUBLISH_MAX_AFFECTED_CARDS {
        return SyncPublishOutcome::Delegated;
    }

    let deadline = tokio::time::Instant::now() + budget;
    let mut proven = vec![false; requests.len()];
    loop {
        for (index, request) in requests.iter().enumerate() {
            if proven[index] {
                continue;
            }
            match tokio::time::timeout_at(deadline, exact_completion(request.clone())).await {
                Ok(Ok(true)) => proven[index] = true,
                Ok(Ok(false)) => {}
                Ok(Err(())) => return SyncPublishOutcome::Failed,
                Err(_) => return SyncPublishOutcome::Delegated,
            }
        }
        if proven.iter().all(|is_proven| *is_proven) {
            return SyncPublishOutcome::Published;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return SyncPublishOutcome::Delegated;
        }
        tokio::time::sleep(OWNED_COMPLETION_POLL_INTERVAL.min(deadline - now)).await;
    }
}

/// 同步发布入口：以与 worker 相同的原语尝试在请求内发布目标事件。
///
/// `pool` 仅用于构造 sqlx runtime（与 worker 同一实现，发布 commit 后自动尝试
/// L2 evidence 推送）；测试经 [`try_synchronous_publish_with_runtime`] 注入替身。
pub async fn try_synchronous_publish(
    pool: &MySqlPool,
    targets: &[SyncPublishTarget],
) -> SyncPublishOutcome {
    if astral_db::projection_execution_mode() == astral_db::ProjectionExecutionMode::WorkerOwned {
        return SyncPublishOutcome::Delegated;
    }
    let runtime: Arc<dyn AuthorizationProjectorRuntime> =
        Arc::new(SqlxAuthorizationProjectorRuntime::new(pool.clone()));
    try_synchronous_publish_with_runtime(runtime, targets).await
}

/// 注入 runtime 的同步发布入口（测试与未来复用面）。
///
/// 发布动作复用 worker 的 `process_one_event` 完整管线（readback → 观察发布
/// 上下文 → 账本分区 → 纯编译判定 → 单事务发布 → L2 推送），因此同步路径的
/// fail-closed 语义与 worker 逐分支一致。
pub async fn try_synchronous_publish_with_runtime(
    runtime: Arc<dyn AuthorizationProjectorRuntime>,
    targets: &[SyncPublishTarget],
) -> SyncPublishOutcome {
    if astral_db::projection_execution_mode() == astral_db::ProjectionExecutionMode::WorkerOwned
        || runtime.worker_owned_execution()
    {
        return SyncPublishOutcome::Delegated;
    }
    let runtime_for_publish = Arc::clone(&runtime);
    // manifest 租约 owner 与 delta claim owner 属不同租约域；同为 run-scoped。
    let manifest_owner = format!("sync-publish-manifest:{}", uuid::Uuid::new_v4());
    let publish_claimed = move |claimed: astral_db::DeltaEventClaim| {
        let runtime = Arc::clone(&runtime_for_publish);
        let manifest_owner = manifest_owner.clone();
        async move {
            let mut summary = WorkerRunSummary::default();
            let config = AuthorizationProjectorConfig::default();
            let cancellation = ProjectorCancellationToken::default();
            process_one_event(
                &runtime,
                &config,
                &manifest_owner,
                &cancellation,
                &claimed,
                &mut summary,
            )
            .await;
            summary.events_published == 1
        }
    };
    run_synchronous_publish(&runtime, targets, SYNC_PUBLISH_BUDGET, publish_claimed).await
}

/// 同步发布编排核心（claim 循环 + 目标识别 + 预算收口），发布动作经
/// `publish_claimed` 注入：入参为按目标匹配到的 claim，返回 `true` 表示该事件
/// 已 durable 发布。事件级失败/释放语义由真实管线或测试替身各自负责，本函数只
/// 负责：目标匹配、超时收口、超时后 best-effort 释放与结果聚合。`budget` 单独
/// 注入（生产路径恒为 [`SYNC_PUBLISH_BUDGET`]；测试注入更小预算以验证超时路径，
/// 避免依赖 tokio test-util）。
///
/// 契约：
/// - 绝不 publish 未匹配目标的 claim（无关事件一律立即释放交还 worker）；
/// - 绝不在发布失败/超时后对同一事件做第二次 mutation（除超时后的单次
///   best-effort 释放——正常失败路径的 fail/release 已由 worker 语义处理）；
/// - claim 返回 `None`（无可 claim：目标已被 worker 持有/终态/退避调度）→
///   结束本次同步发布遍历；当前及剩余目标归入
///   [`SyncPublishOutcome::Delegated`]，由 worker 收敛。
pub(crate) async fn run_synchronous_publish<F, Fut>(
    runtime: &Arc<dyn AuthorizationProjectorRuntime>,
    targets: &[SyncPublishTarget],
    budget: Duration,
    mut publish_claimed: F,
) -> SyncPublishOutcome
where
    F: FnMut(astral_db::DeltaEventClaim) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    if astral_db::projection_execution_mode() == astral_db::ProjectionExecutionMode::WorkerOwned
        || runtime.worker_owned_execution()
    {
        return SyncPublishOutcome::Delegated;
    }
    let total_targets = targets.iter().try_fold(0usize, |total, target| {
        total.checked_add(target.event_ids.len())
    });
    let Some(total_targets) = total_targets else {
        return SyncPublishOutcome::Delegated;
    };
    if total_targets == 0 || total_targets > SYNC_PUBLISH_MAX_EVENTS {
        return SyncPublishOutcome::Delegated;
    }
    let scheduled = targets.iter().filter(|target| !target.event_ids.is_empty());

    let deadline = tokio::time::Instant::now() + budget;
    // run-scoped claim owner（与 worker 的 `auth-projector:{run_id}` 同形态，
    // 长度受 astral-db MAX_GRANT_LEASE_OWNER_LENGTH 校验）。
    let claim_owner = format!("sync-publish:{}", uuid::Uuid::new_v4());
    let mut published = 0usize;
    let mut failed = false;

    'targets: for target in scheduled {
        let mut pending: HashSet<&str> = target.event_ids.iter().map(String::as_str).collect();
        let mut claim_attempts_left = pending.len();
        while !pending.is_empty() && claim_attempts_left > 0 {
            claim_attempts_left -= 1;
            let scope = astral_db::DeltaEventClaimScope {
                tenant_id: target.tenant_id,
                card_id: Some(target.card_id),
            };
            // 1) claim：与 worker 同一原语；live lease 天然互斥。
            let claimed = match tokio::time::timeout_at(
                deadline,
                runtime.claim_next_event(&scope, &claim_owner, SYNC_PUBLISH_CLAIM_LEASE_SECS),
            )
            .await
            {
                Err(_elapsed) => {
                    // 预算耗尽：claim 事务随 future 丢弃而回滚（未持有任何行锁
                    // 出事务），事件未被动过，留在队列由 worker 消化。
                    failed = true;
                    break 'targets;
                }
                Ok(Err(error)) => {
                    tracing::warn!(
                        tenant_id = target.tenant_id,
                        card_id = target.card_id,
                        error = %error,
                        "sync publish claim failed; the delta event(s) stay queued \
                         for the projector worker"
                    );
                    failed = true;
                    break 'targets;
                }
                Ok(Ok(None)) => {
                    // 无可 claim 事件：目标要么已被 worker claim（live lease 被
                    // 谓词排除），要么已终态/退避调度 → worker 拥有收敛。
                    break 'targets;
                }
                Ok(Ok(Some(claimed))) => claimed,
            };
            record_projector_event(ProjectorEventOutcome::Claimed);

            if pending.remove(claimed.event_id.as_str()) {
                // 2) 命中本次写入的目标事件：执行完整发布管线。
                match tokio::time::timeout_at(deadline, publish_claimed(claimed.clone())).await {
                    Err(_elapsed) => {
                        // 超时：发布结果未知。对仍持有的 lease 做一次守卫式
                        // best-effort 释放：发布事务若已 commit → 0 行 no-op；
                        // 若未 commit → 事件立即回到 PENDING；lease 已丢 → no-op。
                        release_best_effort(runtime, &claimed).await;
                        failed = true;
                        break 'targets;
                    }
                    Ok(true) => {
                        published += 1;
                    }
                    Ok(false) => {
                        // 发布未成功：fail/release/隔离等处置已由 worker 统一
                        // 语义在管线内完成（事件留在队列），这里零额外 mutation。
                        failed = true;
                        break 'targets;
                    }
                }
            } else {
                // 3) 排在目标之前的更早事件：不是本次写入的目标，立即释放交还
                //    worker，保持队列顺序消化（绝不越序发布无关事件）。
                release_best_effort(runtime, &claimed).await;
                break 'targets;
            }
        }
    }

    if failed {
        SyncPublishOutcome::Failed
    } else if published == total_targets {
        SyncPublishOutcome::Published
    } else {
        SyncPublishOutcome::Delegated
    }
}

/// 超时后对仍持有的 lease 做一次 best-effort 守卫式释放。
///
/// `release_delta_event_lease` 只在 `lease_owner + token + status=LEASED + 未过期`
/// 全部匹配时才生效：发布事务实际已 commit（SUCCEEDED）或 lease 已被接管/过期
/// 时都是 0 行 no-op，绝不会撤销一次已成功的发布；未知结果只记录 warn，交给
/// lease 服务端过期自愈（worker 原样 reclaim，attempts+1）。
async fn release_best_effort(
    runtime: &Arc<dyn AuthorizationProjectorRuntime>,
    claimed: &astral_db::DeltaEventClaim,
) {
    let identity = astral_db::DeltaLeaseIdentity {
        delta_event_id: claimed.delta_event_id,
        event_id: claimed.event_id.clone(),
        lease_owner: claimed.lease_owner.clone(),
        lease_token: claimed.lease_token.clone(),
    };
    if tokio::time::timeout(RELEASE_BUDGET, runtime.release_event(&identity))
        .await
        .is_err()
    {
        tracing::warn!(
            event_id = %claimed.event_id,
            delta_event_id = claimed.delta_event_id,
            "sync publish timed out and its best-effort release also timed out; \
             the lease expires server-side and the worker reclaims it (self-healing)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::authorization_projector::{PublicationContext, RuntimeAccessError};
    use astral_db::{
        ClaimedDeltaEvent, DeltaEventClaim, DeltaEventType, DeltaLeaseIdentity, DeltaLeaseToken,
        DeltaProjectorPublishCommand, DeltaProjectorPublishOutcome, ProjectionAggregateIdentity,
        RawLedgerRow, Sha256Digest,
    };
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use time::PrimitiveDateTime;

    const TENANT: i64 = 7;
    const CARD_A: i64 = 101;
    const CARD_B: i64 = 202;

    /// 测试替身 runtime：claim 队列按脚本弹出，release/fail 记录调用。
    /// 其余管线方法在本模块的编排测试中不应被触达（publish 动作由注入闭包替身）。
    struct ScriptedRuntime {
        claims: Mutex<VecDeque<Result<Option<DeltaEventClaim>, RuntimeAccessError>>>,
        claims_requested: Mutex<Vec<(i64, i64)>>,
        released: Mutex<Vec<i64>>,
        failed: Mutex<Vec<i64>>,
        claim_delay: Option<Duration>,
        worker_owned: bool,
    }

    impl ScriptedRuntime {
        fn new(claims: Vec<Result<Option<DeltaEventClaim>, RuntimeAccessError>>) -> Arc<Self> {
            Arc::new(Self {
                claims: Mutex::new(claims.into()),
                claims_requested: Mutex::new(Vec::new()),
                released: Mutex::new(Vec::new()),
                failed: Mutex::new(Vec::new()),
                claim_delay: None,
                worker_owned: false,
            })
        }

        fn with_claim_delay(
            claims: Vec<Result<Option<DeltaEventClaim>, RuntimeAccessError>>,
            delay: Duration,
        ) -> Arc<Self> {
            Arc::new(Self {
                claims: Mutex::new(claims.into()),
                claims_requested: Mutex::new(Vec::new()),
                released: Mutex::new(Vec::new()),
                failed: Mutex::new(Vec::new()),
                claim_delay: Some(delay),
                worker_owned: false,
            })
        }

        fn worker_owned() -> Arc<Self> {
            Arc::new(Self {
                claims: Mutex::new(VecDeque::new()),
                claims_requested: Mutex::new(Vec::new()),
                released: Mutex::new(Vec::new()),
                failed: Mutex::new(Vec::new()),
                claim_delay: None,
                worker_owned: true,
            })
        }

        fn requested_scopes(&self) -> Vec<(i64, i64)> {
            self.claims_requested.lock().unwrap().clone()
        }

        fn released_ids(&self) -> Vec<i64> {
            self.released.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl AuthorizationProjectorRuntime for ScriptedRuntime {
        fn worker_owned_execution(&self) -> bool {
            self.worker_owned
        }

        async fn claim_next_event(
            &self,
            scope: &astral_db::DeltaEventClaimScope,
            _lease_owner: &str,
            _lease_seconds: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            self.claims_requested
                .lock()
                .unwrap()
                .push((scope.tenant_id, scope.card_id.unwrap_or(-1)));
            if let Some(delay) = self.claim_delay {
                tokio::time::sleep(delay).await;
            }
            let mut queue = self.claims.lock().unwrap();
            queue.pop_front().unwrap_or(Ok(None))
        }

        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            Err(RuntimeAccessError::Database(
                "sync publish test: read_claimed_event must not be reached".to_owned(),
            ))
        }

        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            Err(RuntimeAccessError::Database(
                "sync publish test: observe_publication_context must not be reached".to_owned(),
            ))
        }

        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            Err(RuntimeAccessError::Database(
                "sync publish test: load_scope_ledger must not be reached".to_owned(),
            ))
        }

        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            Err(RuntimeAccessError::Database(
                "sync publish test: execute_projection_publish must not be reached".to_owned(),
            ))
        }

        async fn fail_event(
            &self,
            identity: &DeltaLeaseIdentity,
            _backoff_seconds: i64,
            _message: &str,
        ) {
            self.failed.lock().unwrap().push(identity.delta_event_id);
        }

        async fn release_event(&self, identity: &DeltaLeaseIdentity) {
            self.released.lock().unwrap().push(identity.delta_event_id);
        }

        async fn mark_event_quarantined(
            &self,
            _lease: &DeltaLeaseIdentity,
            _reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            Err(RuntimeAccessError::Database(
                "sync publish test: mark_event_quarantined must not be reached".to_owned(),
            ))
        }
    }

    /// 构造一个形状完整、语义上代表「刚入账的可 claim delta 事件」的 claim。
    fn scripted_claim(delta_event_id: i64, event_id: &str, card_id: i64) -> DeltaEventClaim {
        DeltaEventClaim {
            delta_event_id,
            event_id: event_id.to_owned(),
            operation_id: format!("op-{delta_event_id}"),
            event_type: DeltaEventType::Add,
            tenant_id: TENANT,
            card_id: Some(card_id),
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: card_id,
            grant_id: astral_types::GrantId::random(),
            base_version: 0,
            target_version: 1,
            source_generation: 1,
            revoke_fence: 0,
            before_image_json: None,
            before_digest: None,
            delta_json: "{}".to_owned(),
            semantic_hash: Sha256Digest::from_hex(&"a".repeat(64)).expect("valid sha256 hex"),
            dependency_hash: Sha256Digest::from_hex(&"b".repeat(64)).expect("valid sha256 hex"),
            compiler_version: "sync-publish-test".to_owned(),
            attempts: 1,
            cas_version: 1,
            lease_owner: "sync-publish-test-owner".to_owned(),
            lease_token: DeltaLeaseToken::placeholder_for_assembly(),
            lease_expires_at: PrimitiveDateTime::MIN,
        }
    }

    /// 编排入口期望 trait 对象；替身状态经同一 Arc 的具体类型断言读取。
    fn as_runtime(scripted: &Arc<ScriptedRuntime>) -> Arc<dyn AuthorizationProjectorRuntime> {
        let cloned: Arc<dyn AuthorizationProjectorRuntime> = scripted.clone();
        cloned
    }

    fn target(card_id: i64, event_ids: &[&str]) -> SyncPublishTarget {
        SyncPublishTarget {
            tenant_id: TENANT,
            card_id,
            event_ids: event_ids.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    /// 发布动作替身：恒定结果（全部视为已 durable 发布 / 全部失败）。
    fn constant_publisher(
        published: bool,
    ) -> impl FnMut(DeltaEventClaim) -> std::future::Ready<bool> {
        move |_claimed| std::future::ready(published)
    }

    fn completion_request(
        event_id: &str,
        target_version: i64,
    ) -> astral_db::DeltaEventAppendRequest {
        astral_db::DeltaEventAppendRequest {
            tenant_id: TENANT,
            card_id: Some(CARD_A),
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: CARD_A,
            grant_id: astral_types::GrantId::random(),
            event_id: event_id.to_owned(),
            operation_id: "op-shared".to_owned(),
            event_type: DeltaEventType::Add,
            base_version: target_version - 1,
            target_version,
            source_generation: target_version as u64,
            revoke_fence: 0,
            invalidates_published_evidence: false,
            before_image_json: None,
            before_digest_hex: None,
            delta_json: "{}".to_owned(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: "sync-publish-test".to_owned(),
            next_attempt_at: None,
        }
    }

    fn same_operation_requests() -> Vec<astral_db::DeltaEventAppendRequest> {
        vec![
            completion_request("evt-a", 1),
            completion_request("evt-b", 2),
        ]
    }

    #[tokio::test]
    async fn owned_completion_requires_every_receipt_and_does_not_reread_proven_events() {
        let requests = same_operation_requests();
        assert_eq!(requests[0].operation_id, requests[1].operation_id);
        let reads = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let outcome = wait_for_owned_completion_with(&requests, Duration::from_secs(1), {
            let reads = Arc::clone(&reads);
            move |request| {
                let reads = Arc::clone(&reads);
                async move {
                    let count = {
                        let mut reads = reads.lock().unwrap();
                        let count = reads.entry(request.event_id.clone()).or_default();
                        *count += 1;
                        *count
                    };
                    Ok(request.event_id == "evt-a" || count >= 2)
                }
            }
        })
        .await;

        assert_eq!(outcome, SyncPublishOutcome::Published);
        let reads = reads.lock().unwrap();
        assert_eq!(reads.get("evt-a"), Some(&1));
        assert_eq!(reads.get("evt-b"), Some(&2));
    }

    #[tokio::test]
    async fn owned_completion_delegates_when_one_receipt_never_publishes() {
        let requests = same_operation_requests();
        let reads = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let outcome = wait_for_owned_completion_with(&requests, Duration::from_millis(80), {
            let reads = Arc::clone(&reads);
            move |request| {
                let reads = Arc::clone(&reads);
                async move {
                    let mut reads = reads.lock().unwrap();
                    *reads.entry(request.event_id.clone()).or_default() += 1;
                    Ok(request.event_id == "evt-a")
                }
            }
        })
        .await;

        assert_eq!(outcome, SyncPublishOutcome::Delegated);
        let reads = reads.lock().unwrap();
        assert_eq!(reads.get("evt-a"), Some(&1));
        assert!(reads.get("evt-b").copied().unwrap_or_default() > 0);
    }

    #[tokio::test]
    async fn owned_completion_empty_and_oversized_batches_do_not_read() {
        let reads = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            wait_for_owned_completion_with(&[], Duration::from_millis(20), {
                let reads = Arc::clone(&reads);
                move |_| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(true))
                }
            })
            .await,
            SyncPublishOutcome::Delegated
        );
        let oversized = (0..=SYNC_PUBLISH_MAX_EVENTS)
            .map(|index| completion_request(&format!("evt-{index}"), index as i64 + 1))
            .collect::<Vec<_>>();
        assert_eq!(
            wait_for_owned_completion_with(&oversized, Duration::from_millis(20), {
                let reads = Arc::clone(&reads);
                move |_| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(true))
                }
            })
            .await,
            SyncPublishOutcome::Delegated
        );
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn owned_completion_database_error_fails_closed() {
        let reads = AtomicUsize::new(0);
        let outcome = wait_for_owned_completion_with(
            &same_operation_requests()[..1],
            Duration::from_secs(1),
            |_| {
                reads.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err(()))
            },
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Failed);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn owned_completion_slow_read_times_out_as_delegated() {
        let reads = AtomicUsize::new(0);
        let outcome = wait_for_owned_completion_with(
            &same_operation_requests()[..1],
            Duration::from_millis(10),
            |_| {
                reads.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok(true)
                }
            },
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Delegated);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn worker_owned_runtime_guard_keeps_legacy_id_only_path_mutation_free() {
        let runtime = ScriptedRuntime::worker_owned();
        let publish_calls = AtomicUsize::new(0);
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[target(CARD_A, &["evt-id-only"])],
            SYNC_PUBLISH_BUDGET,
            |_| {
                publish_calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(true)
            },
        )
        .await;

        assert_eq!(outcome, SyncPublishOutcome::Delegated);
        assert!(runtime.requested_scopes().is_empty());
        assert_eq!(publish_calls.load(Ordering::SeqCst), 0);
        assert!(runtime.released_ids().is_empty());
        assert!(runtime.failed.lock().unwrap().is_empty());
    }

    #[test]
    fn threshold_gate_boundaries_pin_the_documented_semantics() {
        assert!(!should_attempt_synchronous_publish(0));
        assert!(should_attempt_synchronous_publish(1));
        assert!(should_attempt_synchronous_publish(
            SYNC_PUBLISH_MAX_AFFECTED_CARDS
        ));
        assert!(!should_attempt_synchronous_publish(
            SYNC_PUBLISH_MAX_AFFECTED_CARDS + 1
        ));
    }

    #[test]
    fn group_targets_merges_by_card_and_dedupes_event_ids() {
        let grouped = group_targets(vec![
            (TENANT, CARD_A, "evt-1".to_owned()),
            (TENANT, CARD_A, "evt-1".to_owned()),
            (TENANT, CARD_A, "evt-2".to_owned()),
            (TENANT, CARD_B, "evt-3".to_owned()),
            (TENANT, CARD_A, "  ".to_owned()),
        ]);
        assert_eq!(
            grouped,
            vec![
                target(CARD_A, &["evt-1", "evt-2"]),
                target(CARD_B, &["evt-3"]),
            ]
        );
    }

    #[tokio::test]
    async fn every_target_published_reports_published() {
        let runtime = ScriptedRuntime::new(vec![Ok(Some(scripted_claim(1, "evt-1", CARD_A)))]);
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[target(CARD_A, &["evt-1"])],
            SYNC_PUBLISH_BUDGET,
            constant_publisher(true),
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Published);
        assert_eq!(runtime.requested_scopes(), vec![(TENANT, CARD_A)]);
        // 成功路径绝不释放/失败任何事件。
        assert!(runtime.released_ids().is_empty());
        assert!(runtime.failed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn worker_already_claimed_delegates_without_mutation() {
        // claim 恒 None：目标已被 worker claim（live lease 被谓词排除）、已终态
        // 或退避调度 —— 归入 Delegated，绝不 release/fail 任何事件。
        let runtime = ScriptedRuntime::new(vec![Ok(None)]);
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[target(CARD_A, &["evt-1"])],
            SYNC_PUBLISH_BUDGET,
            constant_publisher(true),
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Delegated);
        assert!(runtime.released_ids().is_empty());
        assert!(runtime.failed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unrelated_older_sibling_is_released_and_delegates() {
        // 更早的无关兄弟事件排在目标前：立即释放交还 worker，保持队列顺序。
        let sibling = scripted_claim(1, "older-sibling", CARD_A);
        let runtime = ScriptedRuntime::new(vec![Ok(Some(sibling))]);
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[target(CARD_A, &["evt-1"])],
            SYNC_PUBLISH_BUDGET,
            constant_publisher(true),
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Delegated);
        assert_eq!(runtime.released_ids(), vec![1]);
        // 绝不越序发布无关事件（发布闭包未被触达 —— 由 claimed 匹配失败保证）。
        assert!(runtime.failed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn publish_failure_reports_failed_without_second_mutation() {
        // 发布未成功：fail/release 处置已由 worker 语义（process_one_event）在
        // 管线内完成，编排层绝不做第二次 mutation。
        let runtime = ScriptedRuntime::new(vec![Ok(Some(scripted_claim(1, "evt-1", CARD_A)))]);
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[target(CARD_A, &["evt-1"])],
            SYNC_PUBLISH_BUDGET,
            constant_publisher(false),
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Failed);
        assert!(runtime.released_ids().is_empty());
        assert!(runtime.failed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn claim_infra_failure_reports_failed_and_never_panics() {
        let runtime = ScriptedRuntime::new(vec![Err(RuntimeAccessError::Database(
            "connection refused".to_owned(),
        ))]);
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[target(CARD_A, &["evt-1"])],
            SYNC_PUBLISH_BUDGET,
            constant_publisher(true),
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Failed);
    }

    #[tokio::test]
    async fn claim_timeout_reports_failed_without_lease_side_effects() {
        // claim 悬挂超过总预算（注入 50ms 小预算 + 真实长 sleep，避免依赖
        // tokio test-util）：超时 → Failed；claim 事务随 future 丢弃回滚（未
        // claim 成功），不释放任何 lease。
        let runtime = ScriptedRuntime::with_claim_delay(vec![Ok(None)], Duration::from_secs(10));
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[target(CARD_A, &["evt-1"])],
            Duration::from_millis(50),
            constant_publisher(true),
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Failed);
        assert!(runtime.released_ids().is_empty());
    }

    #[tokio::test]
    async fn publish_timeout_best_effort_releases_the_claimed_lease() {
        // 发布悬挂超过总预算：超时 → 对仍持有的 lease best-effort 释放一次
        // （守卫式 CAS：已 commit 则 0 行 no-op），归类 Failed。
        let runtime = ScriptedRuntime::new(vec![Ok(Some(scripted_claim(9, "evt-1", CARD_A)))]);
        let slow_publisher = |_claimed: DeltaEventClaim| async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            true
        };
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[target(CARD_A, &["evt-1"])],
            Duration::from_millis(50),
            slow_publisher,
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Failed);
        assert_eq!(runtime.released_ids(), vec![9]);
    }

    #[tokio::test]
    async fn event_budget_keeps_oversized_targets_on_the_worker_path() {
        // 整批超过上限时连首项也不认领，不能把已完成前缀误报成整批成功。
        let oversized: Vec<String> = (0..(SYNC_PUBLISH_MAX_EVENTS + 2))
            .map(|index| format!("evt-bulk-{index}"))
            .collect();
        let claims: Vec<Result<Option<DeltaEventClaim>, RuntimeAccessError>> =
            vec![Ok(Some(scripted_claim(1, "evt-1", CARD_A)))];
        let runtime = ScriptedRuntime::new(claims);
        let first = target(CARD_A, &["evt-1"]);
        let second = SyncPublishTarget {
            tenant_id: TENANT,
            card_id: CARD_B,
            event_ids: oversized,
        };
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[first, second],
            SYNC_PUBLISH_BUDGET,
            constant_publisher(true),
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Delegated);
        assert!(runtime.requested_scopes().is_empty());
        assert!(runtime.released_ids().is_empty());
    }

    #[tokio::test]
    async fn multi_card_targets_publish_in_order_and_aggregate_published() {
        let runtime = ScriptedRuntime::new(vec![
            Ok(Some(scripted_claim(1, "evt-a1", CARD_A))),
            Ok(Some(scripted_claim(2, "evt-a2", CARD_A))),
            Ok(Some(scripted_claim(3, "evt-b1", CARD_B))),
        ]);
        let outcome = run_synchronous_publish(
            &as_runtime(&runtime),
            &[
                target(CARD_A, &["evt-a1", "evt-a2"]),
                target(CARD_B, &["evt-b1"]),
            ],
            SYNC_PUBLISH_BUDGET,
            constant_publisher(true),
        )
        .await;
        assert_eq!(outcome, SyncPublishOutcome::Published);
        assert_eq!(
            runtime.requested_scopes(),
            vec![(TENANT, CARD_A), (TENANT, CARD_A), (TENANT, CARD_B)]
        );
        assert!(runtime.released_ids().is_empty());
    }
}
