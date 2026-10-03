//! 权限投影 durable worker — ProjectionWorker（ELIGIBILITY-only，纯恢复角色）
//!
//! 【读写分离降级】ELIGIBILITY 资格缓存失效的主路径是各写点在 source
//! mutation 提交后的同步资格缓存 evict 家族（覆盖全部同进程变更点，符号见
//! side_effects 模块）；CARD/RULE_SET 投影的权威消费者是新链
//! authorization_projector delta 队列。本循环因此降级为纯恢复/对账角色：
//! 兜底同步失效遗漏的 ELIGIBILITY 事件、终结已退役通道的 outbox 行、并按轮
//! 驱动补偿重试——热路径零参与，轮询周期相应放宽。
//!
//! 周期轮询 `authorization_projection_outbox`（claim/lease 形态；周期从对齐
//! Java @Scheduled 5s 放宽至 15s，属记录在案的刻意偏离：主路径同步化后本
//! 循环只承担恢复职责，放宽只增加兜底延迟、不影响任何 fail-closed 语义），
//! 对每条 PENDING 事件执行：
//!
//! ```text
//! claim（租约 30s，batch 100）→ 按 aggregate_type 解析
//!   → CARD / RULE_SET: 直接 mark_processed（终态跳过，不重建快照、不 evict、
//!                      不 fail_event 退避）——旧链快照重建职责已在读链切换
//!                      批次 3 下线，新链 authorization_projector delta 队列
//!                      是 CARD/RULE_SET 投影的唯一权威消费者（决策见
//!                      Docs/架构/Rust架构设计/Rust增量重建与实时授权边界_V1.0.md §3.4）；
//!                      writer correlation 仍会继续写入这两类 outbox 事件，
//!                      本 worker 只负责把它们终结，避免永久滞留 PENDING。
//!   → ELIGIBILITY:   旧代校验（supersede → mark_obsolete 终态）→ only evict
//!                      `perm:card:active:{id}` → markProcessed（不发 MQ；
//!                      ELIGIBILITY gate 版本栅栏控制缓存读取）。
//!                      【存续职责】ELIGIBILITY head/outbox 通道与本分支不随
//!                      旧读链下线（决策与替代方案否决记录见 §3.4）；
//!                      旧链 READY 推进已随迁移 20260831000001 退役——
//!                      source mutation 与 head 代次/围栏在同一 source 事务
//!                      提交，栅栏失配即缓存 miss 回权威 SQL，无需 worker
//!                      消费证明即可保持 fail-closed。
//! 失败 → release_failed（attempts+1 + next_attempt_at 指数退避 2^(n-1) 截断 [1,300]s）
//! ```
//!
//! 未知 `aggregate_type` 必须 fail-closed（release_failed 重试），绝不 mark processed 成功，
//! 以阻止未注册通道的事件被静默吞掉。CARD/RULE_SET 是已注册但已退役重建的通道：
//! 终态 mark_processed 不是授权放行，也不产生任何快照/缓存副作用。保持单一
//! TrustGraph worker owner，不新增第二个 worker。
//!
//! 单次周期失败只记 warning 不中断后续周期（对齐 monitor collector 的 interval 模式）。

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::MySqlPool;
use tokio::sync::Notify;
use tokio::time::interval;

use astral_types::ProjectionAggregate;

use crate::api::side_effects;
use crate::repository::projection_repository::{
    is_projection_lease_lost, OutboxEventRecord, ProjectionRepository,
};

/// 轮询周期（纯恢复角色，见模块文档；从对齐 Java 的 5s 放宽至 15s——
/// 主路径已同步化，本循环只兜底恢复与对账）。
const POLL_INTERVAL_SECS: u64 = 15;
/// 单批认领上限（对齐 Java batchSize = 100）
const CLAIM_BATCH: i64 = 100;
/// 认领租约时长（秒，对齐 Java claimLeaseSeconds = 30）
const CLAIM_LEASE_SECS: i64 = 30;
/// 退避上限（秒，对齐 Java backoff 截断 [1, 300]）
const BACKOFF_MAX_SECS: i64 = 300;

/// 指数退避：2^attempts 截断 [1, 300]（attempts 为已失败次数，首次失败 1s）
pub fn backoff_secs(attempts: i32) -> i64 {
    let exp = 1i64 << attempts.min(9); // 2^9 = 512 > 300
    exp.clamp(1, BACKOFF_MAX_SECS)
}

/// 旧代判定：事件代次早于 head 当前代次 → 已被更新事件取代，跳过重建
pub fn should_supersede(event_source_generation: i64, head_source_generation: i64) -> bool {
    event_source_generation < head_source_generation
}

/// 本 worker 私有的取消令牌（与 audit replay / delegation expiry worker 同一模式）：
/// `main` 与测试只见 `cancel()`；run 循环用 crate 内私有 wait/check seam。
#[derive(Clone, Default)]
pub struct ProjectionWorkerCancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ProjectionWorkerCancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // notify_one retains a permit when cancellation races waiter setup.
        self.notify.notify_one();
    }

    async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        self.notify.notified().await;
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

/// Handle held by `main`; graceful shutdown cancels then joins with a bound.
/// Timeout and task panic surface explicitly through
/// [`shutdown_projection_worker`].
pub struct ProjectionWorkerHandle {
    pub cancellation: ProjectionWorkerCancellationToken,
    pub join: tokio::task::JoinHandle<()>,
}

#[derive(Debug)]
pub struct ProjectionWorkerShutdownReport {
    pub summary: Result<(), String>,
    pub join_elapsed: Duration,
}

/// Retains the worker join if the shutdown future itself is dropped. Drop
/// requests cancellation/abort and transfers the join to a Tokio reaper task.
struct ProjectionWorkerShutdownGuard {
    cancellation: ProjectionWorkerCancellationToken,
    join: Option<tokio::task::JoinHandle<()>>,
    runtime: tokio::runtime::Handle,
}

impl ProjectionWorkerShutdownGuard {
    fn join_mut(&mut self) -> &mut tokio::task::JoinHandle<()> {
        self.join
            .as_mut()
            .expect("shutdown guard retains the join until completion")
    }

    fn release_join(&mut self) {
        self.join.take();
    }
}

impl Drop for ProjectionWorkerShutdownGuard {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
            self.runtime.spawn(async move {
                if tokio::time::timeout(Duration::from_secs(1), join)
                    .await
                    .is_err()
                {
                    tracing::error!("projection worker abort remains unproven");
                }
            });
        }
    }
}

/// Cancel the legacy projection worker and await termination within a bounded
/// timeout.
///
/// `Err(summary)` covers worker panic/join failure and timeout. A dying or
/// stuck worker can never be reported as a clean shutdown — the caller turns
/// non-clean shutdowns into process errors.
pub async fn shutdown_projection_worker(
    handle: ProjectionWorkerHandle,
    timeout: Duration,
) -> ProjectionWorkerShutdownReport {
    let mut ownership = ProjectionWorkerShutdownGuard {
        cancellation: handle.cancellation.clone(),
        join: Some(handle.join),
        runtime: tokio::runtime::Handle::current(),
    };
    handle.cancellation.cancel();
    let started = Instant::now();
    let summary = match tokio::time::timeout(timeout, ownership.join_mut()).await {
        Ok(Ok(())) => {
            ownership.release_join();
            Ok(())
        }
        Ok(Err(join_error)) => {
            ownership.release_join();
            Err(format!("worker task failed: {join_error}"))
        }
        Err(_) => {
            ownership.join_mut().abort();
            if tokio::time::timeout(Duration::from_secs(1), ownership.join_mut())
                .await
                .is_ok()
            {
                ownership.release_join();
            }
            Err(format!(
                "legacy projection worker did not stop within {timeout:?}; aborted; possibly \
                 wedged inside a projection/compensation cycle"
            ))
        }
    };
    tracing::info!(
        join_elapsed_ms = started.elapsed().as_millis() as u64,
        clean = summary.is_ok(),
        "legacy projection worker shutdown completed"
    );
    ProjectionWorkerShutdownReport {
        summary,
        join_elapsed: started.elapsed(),
    }
}

/// 启动旧代投影 worker 后台任务。`main` 必须持有返回的 handle 并在关闭时调用
/// [`shutdown_projection_worker`]（cancel → bounded join）；handle 绝不能被
/// 丢弃，否则旧 worker 将脱离关闭序列管理。
pub fn spawn_worker(db: MySqlPool, repo: Arc<dyn ProjectionRepository>) -> ProjectionWorkerHandle {
    let cancellation = ProjectionWorkerCancellationToken::default();
    let worker_cancellation = cancellation.clone();
    let join = tokio::spawn(async move {
        let worker_id = uuid::Uuid::new_v4().to_string();
        let mut ticker = interval(Duration::from_secs(POLL_INTERVAL_SECS));
        loop {
            // 取消只发生在轮与轮之间：select 在 ticker 等待点同步响应取消，
            // 进行中的 claim/投影/补偿事务绝不半途中断；若取消发生在周期
            // 执行期间，下一轮 select 立即命中取消并退出，join 超时内必然返回。
            tokio::select! {
                _ = worker_cancellation.cancelled() => break,
                _ = ticker.tick() => {}
            }
            run_cycle(repo.as_ref(), &worker_id).await;
            if let Err(error) =
                crate::api::side_effects::retry_pending_compensations(&db, CLAIM_BATCH).await
            {
                tracing::warn!(error = %error, "compensation retry cycle failed");
            }
        }
        tracing::info!(worker_id, "legacy projection worker stopped");
    });
    ProjectionWorkerHandle { cancellation, join }
}
pub async fn run_cycle(repo: &dyn ProjectionRepository, worker_id: &str) {
    let events = match repo
        .claim_pending_events(CLAIM_BATCH, worker_id, CLAIM_LEASE_SECS)
        .await
    {
        Ok(events) if events.is_empty() => return,
        Ok(events) => events,
        Err(e) => {
            tracing::warn!(error = %e, "projection worker claim failed");
            return;
        }
    };
    tracing::debug!(
        worker_id,
        batch = events.len(),
        "projection worker claimed batch"
    );

    for event in events {
        project_one(repo, worker_id, &event).await;
    }
}

/// 投影单条 outbox 事件。
///
/// 按 `event.aggregate_type` 分派：
/// - `CARD` / `RULE_SET`：终态 mark_processed 跳过（旧链快照重建已退役，见模块文档）；
/// - `ELIGIBILITY`：`project_eligibility`（存续职责：仅失效资格缓存，不重建/清理规则快照）；
/// - 未知 `aggregate_type` → fail-closed（release_failed 重试），不 mark processed 成功。
async fn project_one(repo: &dyn ProjectionRepository, worker_id: &str, event: &OutboxEventRecord) {
    let aggregate = match ProjectionAggregate::parse_static(&event.aggregate_type) {
        Some(aggregate) => aggregate,
        None => {
            // 未知聚合：fail-closed，走退避重试（绝不当作成功），等待人工介入或注册。
            fail_event(
                repo,
                worker_id,
                event,
                &format!(
                    "unknown projection aggregate_type: {}",
                    event.aggregate_type
                ),
            )
            .await;
            return;
        }
    };

    match aggregate {
        // 已退役的旧链快照重建通道：writer correlation 仍会继续写入 CARD/RULE_SET
        // outbox 事件，但其投影的权威消费者是新链 authorization_projector delta
        // 队列（决策见 Rust增量重建与实时授权边界_V1.0.md §3.4）。本 worker 对
        // 这两类事件只做终态 mark_processed，绝不重建快照、绝不 evict、也绝不
        // fail_event 退避（否则无人重建的旧通道事件会永远重试）；不读 head、
        // 不比较代次——退役通道的处置与 head 状态无关。
        ProjectionAggregate::Card | ProjectionAggregate::RuleSet => {
            tracing::info!(
                aggregate_type = %event.aggregate_type,
                aggregate_id = event.aggregate_id,
                outbox_id = event.outbox_id,
                "legacy snapshot rebuild retired, ownership moved to authorization_projector delta queue"
            );
            mark_event_processed(repo, worker_id, event).await;
        }
        // 【存续职责】ELIGIBILITY 分支是 worker 的存续职责（决策见 §3.4）。
        ProjectionAggregate::Eligibility => project_eligibility(repo, worker_id, event).await,
    }
}

/// ELIGIBILITY 通道投影（【存续职责】，决策见 Rust增量重建与实时授权边界_V1.0.md §3.4）：
/// 旧代校验 → 仅失效 `perm:card:active:{card_id}` 资格缓存 → PROCESSED。
///
/// 不调用任何快照重建（CARD/RULE_SET 快照重建已退役，新链 authorization_projector
/// delta 队列是其唯一权威消费者）、不清理规则快照、不再推进 head READY（旧链
/// 状态列已随迁移 20260831000001 删除）。不发布 MQ——资格读侧的缓存协议由
/// (source_generation, revoke_fence) 版本栅栏 + 时代栅栏保护（source mutation
/// 与 head 代次/围栏同事务提交，未消费事件必然栅栏失配 → miss 回权威 SQL），
/// 见 `astral-db::CardEligibilityService` 的投影门禁语义。
async fn project_eligibility(
    repo: &dyn ProjectionRepository,
    worker_id: &str,
    event: &OutboxEventRecord,
) {
    // 旧代校验：head 已推进到更新的代次 → 本事件被取代，mark_obsolete 终态
    // （绝不 mark processed 成功，也绝不当作成功吞掉）；head 读取失败 → fail-closed。
    match repo
        .get_aggregate_head(ProjectionAggregate::Eligibility, event.aggregate_id)
        .await
    {
        Ok(Some(head)) if should_supersede(event.source_generation, head.source_generation) => {
            mark_event_obsolete(repo, worker_id, event).await;
            return;
        }
        Ok(_) => {}
        Err(e) => {
            fail_event(repo, worker_id, event, &e.to_string()).await;
            return;
        }
    }

    // Production always supplies the real Redis eviction operation. Tests use the
    // same worker state machine through `project_eligibility_with_eviction` with a
    // deterministic no-op, so they never depend on an external Redis endpoint.
    project_eligibility_with_eviction(
        repo,
        worker_id,
        event,
        side_effects::evict_eligibility_gate_cache,
    )
    .await;
}

async fn project_eligibility_with_eviction<E, F>(
    repo: &dyn ProjectionRepository,
    worker_id: &str,
    event: &OutboxEventRecord,
    evict_cache: E,
) where
    E: FnOnce(i64) -> F,
    F: Future<Output = ()>,
{
    let card_id = event.aggregate_id;

    // 1. 仅失效 `perm:card:active:{card_id}` 资格缓存（fire-and-forget）
    evict_cache(card_id).await;

    // 1b.【P3 拆线接缝】进程内失效绑定 astral-db 失效事件语义：直接调用
    // `astral_db::evict_l1_card_active_cache`（同进程 L1 卡正缓存 + L1
    // ELIGIBILITY head 条目删除 + per-card 失效纪元推进），使 L1 资格头随
    // 失效事件失效（R3），且独立于 api::side_effects 的 Redis compat 失效
    // 路径（default 无 Redis 时本调用即完整进程内失效）。幂等、无网络、
    // 锁中毒静默（条目由 TTL 兜底），重复调用无害。
    astral_db::evict_l1_card_active_cache(card_id);

    // 2. 标记 PROCESSED（仅持有租约的 worker 生效）。旧"head READY 推进"已随
    //    迁移 20260831000001 退役：读侧安全由 (source_generation, revoke_fence)
    //    版本栅栏 + 时代栅栏保证，不依赖 worker 消费证明。
    //    不发 MQ：资格读侧经 ELIGIBILITY gate 版本检查放行。
    mark_event_processed(repo, worker_id, event).await;
}

/// 标记事件为 PROCESSED（仅持有租约的 worker 生效），失败仅记 warning。
async fn mark_event_processed(
    repo: &dyn ProjectionRepository,
    worker_id: &str,
    event: &OutboxEventRecord,
) {
    if let Err(e) = repo.mark_processed(event.outbox_id, worker_id).await {
        if is_projection_lease_lost(&e) {
            tracing::warn!(
                aggregate_id = event.aggregate_id,
                outbox_id = event.outbox_id,
                error = %e,
                "projection lease lost before marking event processed"
            );
        } else {
            tracing::warn!(
                aggregate_id = event.aggregate_id,
                outbox_id = event.outbox_id,
                error = %e,
                "failed to mark projection event processed"
            );
        }
    } else {
        tracing::debug!(
            aggregate_id = event.aggregate_id,
            outbox_id = event.outbox_id,
            "projection event marked processed"
        );
    }
}

/// 标记旧代事件为 SUPERSEDED_BY_NEWER_GENERATION（仅持有租约的 worker 生效）。
async fn mark_event_obsolete(
    repo: &dyn ProjectionRepository,
    worker_id: &str,
    event: &OutboxEventRecord,
) {
    if let Err(e) = repo.mark_obsolete(event.outbox_id, worker_id).await {
        if is_projection_lease_lost(&e) {
            tracing::warn!(
                aggregate_id = event.aggregate_id,
                outbox_id = event.outbox_id,
                error = %e,
                "projection lease lost before marking event obsolete"
            );
        } else {
            tracing::warn!(
                aggregate_id = event.aggregate_id,
                outbox_id = event.outbox_id,
                error = %e,
                "failed to mark obsolete projection event"
            );
        }
    } else {
        tracing::info!(
            aggregate_id = event.aggregate_id,
            outbox_id = event.outbox_id,
            event_generation = event.source_generation,
            "projection event superseded by newer generation"
        );
    }
}

/// 失败处理：attempts+1 + 指数退避 + 释放租约（对齐 Java backoff 2^(n-1) 截断 [1,300]）
async fn fail_event(
    repo: &dyn ProjectionRepository,
    worker_id: &str,
    event: &OutboxEventRecord,
    error_msg: &str,
) {
    let backoff = backoff_secs(event.attempts);
    tracing::warn!(
        aggregate_id = event.aggregate_id,
        aggregate_type = %event.aggregate_type,
        outbox_id = event.outbox_id,
        attempts = event.attempts + 1,
        backoff_secs = backoff,
        error = %error_msg,
        "projection event failed, scheduling retry"
    );
    if let Err(e) = repo
        .release_failed(event.outbox_id, worker_id, backoff, error_msg)
        .await
    {
        if is_projection_lease_lost(&e) {
            tracing::warn!(
                outbox_id = event.outbox_id,
                error = %e,
                "projection lease lost before releasing failed event"
            );
        } else {
            tracing::error!(
                outbox_id = event.outbox_id,
                error = %e,
                "failed to release failed projection event"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};

    use astral_types::AstralError;
    use async_trait::async_trait;

    use super::*;
    use crate::repository::projection_repository::{
        projection_lease_lost_error, ProjectionHeadRecord, EVENT_TYPE_CARD_UPDATE,
    };

    /// 内存 mock：仅驱动 worker 分支逻辑，不触碰 DB/MQ/Redis。
    ///
    /// `head_source` 模拟 `get_aggregate_head` 返回的 source_generation（None = head 缺失）。
    struct MockProjectionRepository {
        head_source: Mutex<Option<i64>>,
        processed: Mutex<Vec<i64>>,
        obsolete: Mutex<Vec<i64>>,
        failed: Mutex<Vec<(i64, String)>>,
    }

    impl MockProjectionRepository {
        fn new(head_source: Option<i64>) -> Self {
            Self {
                head_source: Mutex::new(head_source),
                processed: Mutex::new(Vec::new()),
                obsolete: Mutex::new(Vec::new()),
                failed: Mutex::new(Vec::new()),
            }
        }

        fn snapshot(&self) -> (Vec<i64>, Vec<i64>, Vec<(i64, String)>) {
            let processed = self.processed.lock().unwrap().clone();
            let obsolete = self.obsolete.lock().unwrap().clone();
            let failed = self.failed.lock().unwrap().clone();
            (processed, obsolete, failed)
        }
    }

    fn card_event(outbox_id: i64, source_generation: i64) -> OutboxEventRecord {
        OutboxEventRecord {
            outbox_id,
            event_id: format!("evt-{outbox_id}"),
            aggregate_type: ProjectionAggregate::Card.as_str().into(),
            aggregate_id: 42,
            tenant_id: None,
            event_type: EVENT_TYPE_CARD_UPDATE.into(),
            source_generation,
            sequence_number: source_generation,
            revoke_fence: 0,
            status: "PENDING".into(),
            attempts: 0,
        }
    }

    #[async_trait]
    impl ProjectionRepository for MockProjectionRepository {
        async fn request_aggregate_projection(
            &self,
            _aggregate: ProjectionAggregate,
            _aggregate_id: i64,
            _event_type: &str,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn claim_pending_events(
            &self,
            _batch: i64,
            _worker_id: &str,
            _lease_secs: i64,
        ) -> Result<Vec<OutboxEventRecord>, AstralError> {
            Ok(Vec::new())
        }

        async fn get_aggregate_head(
            &self,
            _aggregate: ProjectionAggregate,
            _aggregate_id: i64,
        ) -> Result<Option<ProjectionHeadRecord>, AstralError> {
            let source = *self.head_source.lock().unwrap();
            Ok(source.map(|source_generation| ProjectionHeadRecord {
                aggregate_type: ProjectionAggregate::Card.as_str().into(),
                aggregate_id: 0,
                source_generation,
                revoke_fence: 0,
            }))
        }

        async fn mark_processed(
            &self,
            outbox_id: i64,
            _worker_id: &str,
        ) -> Result<(), AstralError> {
            self.processed.lock().unwrap().push(outbox_id);
            Ok(())
        }

        async fn mark_obsolete(&self, outbox_id: i64, _worker_id: &str) -> Result<(), AstralError> {
            self.obsolete.lock().unwrap().push(outbox_id);
            Ok(())
        }

        async fn release_failed(
            &self,
            outbox_id: i64,
            _worker_id: &str,
            _backoff_secs: i64,
            error_msg: &str,
        ) -> Result<(), AstralError> {
            self.failed
                .lock()
                .unwrap()
                .push((outbox_id, error_msg.to_string()));
            Ok(())
        }
    }

    struct DropObservedFuture {
        entered: Option<Arc<AtomicBool>>,
        dropped: Arc<AtomicBool>,
    }

    impl Future for DropObservedFuture {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            if let Some(entered) = &self.entered {
                entered.store(true, Ordering::Release);
            }
            Poll::Pending
        }
    }

    impl Drop for DropObservedFuture {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn dropping_shutdown_future_aborts_and_reaps_worker() {
        let dropped = Arc::new(AtomicBool::new(false));
        let worker_dropped = Arc::clone(&dropped);
        let entered = Arc::new(AtomicBool::new(false));
        let worker_entered = Arc::clone(&entered);
        let handle = ProjectionWorkerHandle {
            cancellation: ProjectionWorkerCancellationToken::default(),
            join: tokio::spawn(async move {
                DropObservedFuture {
                    entered: Some(worker_entered),
                    dropped: worker_dropped,
                }
                .await;
            }),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !entered.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "worker did not start");
            tokio::task::yield_now().await;
        }

        let shutdown_cancellation = handle.cancellation.clone();
        let shutdown = tokio::spawn(shutdown_projection_worker(handle, Duration::from_secs(30)));
        while !shutdown_cancellation.is_cancelled() {
            assert!(
                Instant::now() < deadline,
                "shutdown did not acquire ownership"
            );
            tokio::task::yield_now().await;
        }
        shutdown.abort();
        let _ = shutdown.await;

        let deadline = Instant::now() + Duration::from_secs(2);
        while !dropped.load(Ordering::Acquire) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            dropped.load(Ordering::Acquire),
            "worker must be aborted on drop"
        );
    }

    #[tokio::test]
    async fn shutdown_timeout_aborts_and_reaps_worker() {
        let entered = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let handle = ProjectionWorkerHandle {
            cancellation: ProjectionWorkerCancellationToken::default(),
            join: tokio::spawn({
                let entered = Arc::clone(&entered);
                let dropped = Arc::clone(&dropped);
                async move {
                    DropObservedFuture {
                        entered: Some(entered),
                        dropped,
                    }
                    .await;
                }
            }),
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while !entered.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "worker did not start");
            tokio::task::yield_now().await;
        }

        let report = shutdown_projection_worker(handle, Duration::from_millis(20)).await;
        assert!(
            report.summary.is_err(),
            "timed-out worker must fail shutdown"
        );
        assert!(
            dropped.load(Ordering::Acquire),
            "timed-out worker must be reaped"
        );
        assert!(report.join_elapsed < Duration::from_secs(2));
    }

    #[test]
    fn backoff_grows_exponentially_and_clamps() {
        // 首次失败 2^0=1s；第二次 2^1=2s；第三次 2^2=4s
        assert_eq!(backoff_secs(0), 1);
        assert_eq!(backoff_secs(1), 2);
        assert_eq!(backoff_secs(2), 4);
        assert_eq!(backoff_secs(3), 8);
        // 截断上限 300s（2^9=512 > 300），且不会溢出
        assert_eq!(backoff_secs(9), 300);
        assert_eq!(backoff_secs(100), 300);
    }

    #[test]
    fn supersede_requires_event_generation_behind_head() {
        // 事件代次 2 < head 代次 3 → 旧代，跳过
        assert!(should_supersede(2, 3));
        // 事件代次等于 head → 当前代，需投影
        assert!(!should_supersede(3, 3));
        // head 不存在（0 代）→ 无旧代，需投影
        assert!(!should_supersede(1, 0));
    }

    /// 分派解析：worker 按 event.aggregate_type 解析聚合策略。
    /// ELIGIBILITY 是存续职责通道；CARD / RULE_SET 是已注册但已退役重建的通道
    /// （终态 mark_processed 跳过，不重建）；未知值必须被拒绝（fail-closed）。
    #[test]
    fn aggregate_dispatch_resolution() {
        // CARD：退役重建通道，仍必须是已知类型（否则会被 fail_event 永久重试）
        assert_eq!(
            ProjectionAggregate::parse_static("CARD"),
            Some(ProjectionAggregate::Card)
        );
        // ELIGIBILITY：存续职责通道
        assert_eq!(
            ProjectionAggregate::parse_static("ELIGIBILITY"),
            Some(ProjectionAggregate::Eligibility)
        );
        // RULE_SET：退役重建通道，仍必须是已知类型
        assert_eq!(
            ProjectionAggregate::parse_static("RULE_SET"),
            Some(ProjectionAggregate::RuleSet)
        );
        // 未知聚合：worker 必须 fail-closed（release_failed 重试），不 mark processed
        assert_eq!(ProjectionAggregate::parse_static("UNKNOWN"), None);
        assert_eq!(ProjectionAggregate::parse_static(""), None);
    }

    #[test]
    fn rule_set_strategy_is_distinct_from_card_and_eligibility() {
        assert_ne!(ProjectionAggregate::RuleSet, ProjectionAggregate::Card);
        assert_ne!(
            ProjectionAggregate::RuleSet,
            ProjectionAggregate::Eligibility
        );
        assert_eq!(ProjectionAggregate::RuleSet.as_str(), "RULE_SET");
    }

    /// ELIGIBILITY 通道不得误入 CARD 语义：两通道在枚举上互斥。
    #[test]
    fn eligibility_strategy_is_distinct_from_card() {
        assert_ne!(ProjectionAggregate::Card, ProjectionAggregate::Eligibility);
        assert_ne!(ProjectionAggregate::Card.as_str(), "ELIGIBILITY");
        assert_eq!(ProjectionAggregate::Eligibility.as_str(), "ELIGIBILITY");
    }

    #[test]
    fn lease_loss_is_not_reported_as_success() {
        let error = projection_lease_lost_error("mark_processed");
        assert!(is_projection_lease_lost(&error));
        assert!(!is_projection_lease_lost(&AstralError::Internal(
            "database failure".into()
        )));
    }

    // 读链切换批次 3：CARD/RULE_SET 快照重建通道已退役。project_one 对这两类
    // 事件直接 mark_processed 终态跳过（不读 head、不 evict、不重建、绝不
    // fail_event 退避），其投影权威消费者是新链 authorization_projector delta
    // 队列，见 retired_card_rule_set_event_is_marked_processed_without_retry 与
    // retired_card_rule_set_channels_have_no_rebuild_surface。
    //
    // project_eligibility 通过注入的缓存失效操作直接驱动 worker 流程，
    // 覆盖正常处理、同代重放与 Superseded 终态，不依赖 DB/MQ/Redis，见
    // project_eligibility_evicts_then_processes /
    // project_eligibility_same_generation_replay_processes_without_mq /
    // project_eligibility_superseded_is_obsolete_not_processed。

    /// CARD/RULE_SET 退役通道：project_one 必须终态 mark_processed，绝不
    /// release_failed 退避（否则 writer correlation 持续写入的旧通道事件会
    /// 永远重试），也绝不 mark_obsolete（退役处置与 head 代次无关）。
    #[tokio::test]
    async fn retired_card_rule_set_event_is_marked_processed_without_retry() {
        for aggregate_type in [
            ProjectionAggregate::Card.as_str().to_string(),
            ProjectionAggregate::RuleSet.as_str().to_string(),
        ] {
            let repo = MockProjectionRepository::new(Some(3));
            let mut event = card_event(21, 3);
            event.aggregate_type = aggregate_type;
            project_one(&repo, "worker-1", &event).await;

            let (processed, obsolete, failed) = repo.snapshot();
            assert_eq!(
                processed,
                vec![21],
                "retired channel must be terminal PROCESSED"
            );
            assert!(
                obsolete.is_empty(),
                "retired channel must not consult head fencing"
            );
            assert!(
                failed.is_empty(),
                "retired channel must never re-enter the backoff loop"
            );
        }
    }

    /// 【批次 3 结构锁定】worker 源码不得再引用已退役的快照重建表面：
    /// 两个旧通道投影函数与 side_effects 的重建内部函数必须彻底缺席，
    /// 防止重构时静默复活旧链重建路径。
    /// （禁用符号用 concat! 拼接，避免 include_str 扫描命中测试自身的字面量。）
    #[test]
    fn retired_card_rule_set_channels_have_no_rebuild_surface() {
        let worker_src = include_str!("projection_worker.rs");
        for retired in [
            concat!("project_", "card"),
            concat!("project_", "rule_set"),
            concat!("rebuild_", "card_snapshot_inner"),
            concat!("rebuild_", "rule_set_snapshot_inner"),
            concat!("RuleSetProjection", "Claim"),
            concat!("evict_", "card_cache_for_tenant"),
        ] {
            assert!(
                !worker_src.contains(retired),
                "worker must not reference retired rebuild symbol {retired}"
            );
        }
        // 终态跳过路径必须保留其可观测日志锚点（退役原因可追溯）。
        assert!(
            worker_src.contains("ownership moved to authorization_projector delta queue"),
            "retired-channel skip must keep its audit log anchor"
        );
    }

    /// project_eligibility：同代事件重放（mark_processed 失败后的安全重试）→
    /// 直接 mark_processed，不发 MQ、不 mark_obsolete、不 release_failed。
    #[tokio::test]
    async fn project_eligibility_same_generation_replay_processes_without_mq() {
        let repo = MockProjectionRepository::new(Some(3));
        let event = card_event(12, 3);
        project_eligibility_with_eviction(&repo, "worker-1", &event, |_card_id| async {}).await;

        let (processed, obsolete, failed) = repo.snapshot();
        assert_eq!(processed, vec![12], "same-generation replay → PROCESSED");
        assert!(obsolete.is_empty());
        assert!(failed.is_empty());
    }

    /// project_eligibility：head 已推进到更新代次（supersede）→ mark_obsolete
    /// 终态，不 mark processed、不 evict、不 release_failed。
    #[tokio::test]
    async fn project_eligibility_superseded_is_obsolete_not_processed() {
        let repo = MockProjectionRepository::new(Some(3));
        let event = card_event(13, 2);
        // supersede 分派位于 project_eligibility 的旧代校验（head 读取）步骤，
        // 早于任何缓存失效操作，不触碰外部 Redis。
        project_eligibility(&repo, "worker-1", &event).await;

        let (processed, obsolete, failed) = repo.snapshot();
        assert!(processed.is_empty(), "superseded must never be PROCESSED");
        assert_eq!(obsolete, vec![13]);
        assert!(failed.is_empty());
    }

    /// project_eligibility：正常路径——先失效 `perm:card:active:{card_id}`
    /// 资格缓存，再 mark_processed。
    ///
    /// 【存续职责守卫】ELIGIBILITY 分支是 worker 的存续职责：读链切换批次 2 正式
    /// 决策（方案 b）保留 ELIGIBILITY head/outbox 通道与 worker ELIGIBILITY 分支，
    /// 不随旧 CARD/RULE_SET 读链下线；决策依据与替代方案否决记录见
    /// Docs/架构/Rust架构设计/Rust增量重建与实时授权边界_V1.0.md §3.4。
    #[tokio::test]
    async fn project_eligibility_advanced_evicts_then_advances_then_processes() {
        let repo = MockProjectionRepository::new(Some(3));
        let event = card_event(11, 3);
        let evicted = Arc::new(Mutex::new(Vec::new()));
        let evicted_in_closure = evicted.clone();
        project_eligibility_with_eviction(&repo, "worker-1", &event, move |card_id| {
            evicted_in_closure.lock().unwrap().push(card_id);
            async {}
        })
        .await;

        assert_eq!(
            *evicted.lock().unwrap(),
            vec![42],
            "必须按 aggregate_id 失效 perm:card:active 资格缓存"
        );
        let (processed, obsolete, failed) = repo.snapshot();
        assert_eq!(processed, vec![11], "normal path → PROCESSED");
        assert!(obsolete.is_empty());
        assert!(failed.is_empty());
    }

    /// 【存续职责结构锁定】读链切换批次 2 正式决策（方案 b）：ELIGIBILITY head/outbox
    /// 通道与 worker 的 ELIGIBILITY 分支是 ProjectionWorker 的存续职责；CARD/RULE_SET
    /// 分支在批次 3 下线后 worker 收敛为 ELIGIBILITY-only，但不得误删 ELIGIBILITY 分支。
    /// 决策依据、替代方案（a/c'）否决理由与 c' 后续切片前置条件见
    /// Docs/架构/Rust架构设计/Rust增量重建与实时授权边界_V1.0.md §3.4。
    ///
    /// 锁定层次：
    /// - 行为锁定：project_eligibility 流程测试（正常 / 同代重放 / Superseded）
    ///   锁定 旧代校验 → evict → mark_processed 状态机；
    /// - 编译期锁定：`project_one` 对 `ProjectionAggregate` 三变体的 match 必须穷尽，
    ///   删除 ELIGIBILITY 分派臂即无法编译；
    /// - 源码结构锁定（本测试）：断言 worker 源码仍保留 ELIGIBILITY 分派与生产
    ///   Redis 失效绑定，防止批次 3 重构时静默移除（同
    ///   `rule_set_worker_keeps_rebuild_audit_out_of_post_commit_flow` 的源码锁定模式）。
    #[test]
    fn eligibility_branch_is_survival_responsibility_of_worker() {
        let worker_src = include_str!("projection_worker.rs");
        assert!(
            worker_src.contains("ProjectionAggregate::Eligibility => project_eligibility"),
            "project_one 必须保留 ELIGIBILITY 分派臂（决策见 Rust增量重建与实时授权边界_V1.0.md §3.4）"
        );
        assert!(
            worker_src.contains("side_effects::evict_eligibility_gate_cache"),
            "project_eligibility 生产路径必须绑定 perm:card:active 资格缓存失效（决策见 §3.4）"
        );
        assert!(
            worker_src.contains("fn project_eligibility("),
            "ELIGIBILITY 通道函数不得随批次 3 下线误删（决策见 §3.4）"
        );
    }

    /// 【P3 拆线接缝锁定】project_eligibility 的 ELIGIBILITY 通道必须直接绑定
    /// `astral_db::evict_l1_card_active_cache`：失效事件在进程内驱动 L1 卡正
    /// 缓存 + L1 ELIGIBILITY head 条目删除 + per-card 失效纪元推进（R3"资格头
    /// 随失效事件"），且独立于 api::side_effects 的 Redis compat 失效路径
    /// （默认 Redis-free 路径下这就是完整的进程内失效面）。
    #[test]
    fn eligibility_channel_binds_the_in_process_invalidation_seam() {
        let worker_src = include_str!("projection_worker.rs");
        assert!(
            worker_src.contains("astral_db::evict_l1_card_active_cache(card_id);"),
            "ELIGIBILITY channel must bind astral_db::evict_l1_card_active_cache \
             (in-process L1 card-active + head + per-card epoch invalidation)"
        );
    }
}
