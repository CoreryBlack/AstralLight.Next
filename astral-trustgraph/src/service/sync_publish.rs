//! 读链规模化 Batch E —— 授权投影「同步发布混合模式」。
//!
//! # 背景与语义（模块文档 = 本切片的行为契约）
//!
//! writer 的 source 事务提交（durable delta 入账 `authorization_delta_event`）后
//! 返回，发布（111→112 翻转）此前完全由 [`super::authorization_projector`] worker
//! 异步消化：delta 入账到发布之间存在 worker 轮询窗口（秒级），期间已撤销/已变更
//! 授权仍按旧 manifest 判定（撤销传播延迟窗口）。
//!
//! 本模块在 **不影响 fail-closed 语义** 的前提下消除单卡/小变更的生效延迟：
//!
//! - **混合模式**：writer source 事务 **commit 成功之后**（独立事务，绝不进入
//!   source 事务边界），若本次写入的影响面（受影响卡数）≤
//!   [`SYNC_PUBLISH_MAX_AFFECTED_CARDS`]，则以 **与 worker 完全相同的原语**
//!   （`claim_next_delta_event_in_tx` → `process_one_event` → 发布事务
//!   `project_authorization_delta_in_tx` → commit 后 L2 evidence 推送）在请求内
//!   尝试把该卡刚入账的 delta 事件发布出去；影响面 > 阈值 → 跳过（现状语义，
//!   worker 异步消化，秒到分钟级收敛）。
//! - **零延迟路径**：同步发布成功（[`SyncPublishOutcome::Published`]）⇒ 目标
//!   delta 事件已在请求内 durable 发布（发布事务 commit 证明 + L2 推送已尝试），
//!   本请求的授权变更立即生效。
//! - **大扇出路径**：> 阈值的写入保持纯异步，由 worker 在秒到分钟级收敛。
//! - **两者都 fail-closed**：同步发布与 worker 使用同一发布事务与同一判定管线
//!   （[`super::authorization_projector::process_one_event`]），Conflict / 哈希漂移 /
//!   版本不一致 / unproven history 一律拒绝发布（PENDING/退避/隔离），绝不伪造
//!   成功，也绝不因同步发布让写请求报错。
//!
//! # 失败不阻塞（最高优先级契约）
//!
//! source 事务已提交后同步发布才启动，因此同步发布的 **任何** 失败都不允许影响
//! 写请求结果：本模块不返回 `Result`，调用方（repository 接线点）拿到的是普通的
//! 单元返回值。失败分类全部降级为「worker 兜底消化」：
//!
//! - 目标事件已被 worker claim（live lease 被 claim 谓词排除 → claim 拿到
//!   `None` 或更早的兄弟事件）→ [`SyncPublishOutcome::Delegated`]（worker 正在
//!   处理，收敛由 worker 保证）；
//! - 发布错误 / 判定 Blocked / 预算耗尽 → [`super::authorization_projector`] 的
//!   统一 attempt-budget 语义已把事件留在队列（PENDING + 有界退避），本模块返回
//!   [`SyncPublishOutcome::Failed`]；
//! - 总预算（[`SYNC_PUBLISH_BUDGET`]）超时 → 对仍持有 lease 的事件做一次
//!   best-effort 释放（守卫式 CAS：若发布事务实际已 commit 则 0 行 no-op；若
//!   未 commit 则事件立即回到 PENDING），随后返回 [`SyncPublishOutcome::Failed`]。
//!   极端情况下（释放也失败/未知）lease 按服务端过期时间自愈，worker 原样
//!   reclaim（attempts+1）——绝不盲目重放、绝不伪造终态。
//!
//! # worker 不变性
//!
//! worker 循环零改动。claim 原语的资格谓词（astral-db
//! `claim_next_delta_event_in_tx` + `DELTA_CLAIM_ELIGIBLE_PREDICATE`，由
//! grant_repository 的 `claim_predicate_gates_future_pending_rows_but_takes_over_expired_leases`
//! 等测试钉死）保证 **live lease 永不被偷**：worker 对已被同步发布持有 lease 的
//! 事件只能跳过（claim 返回其它事件或 `None`），绝不会报错或重复发布；反之亦然。
//!
//! # 日志级别约定
//!
//! `Failed` → `warn`（真实失败，需要关注）；`Delegated` → `debug`（worker 竞争
//! 获胜/队列让行是健康路径，warn 级别会在正常运行时淹没真实失败）；`Published`
//! → `debug`（正常成功路径）。

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::MySqlPool;

use crate::observability::{
    record_projector_event, record_sync_publish, ProjectorEventOutcome, SyncPublishMetricOutcome,
};

use super::authorization_projector::{
    process_one_event, AuthorizationProjectorConfig, AuthorizationProjectorRuntime,
    ProjectorCancellationToken, SqlxAuthorizationProjectorRuntime, WorkerRunSummary,
};

/// 影响面阈值：受影响卡数 ≤ 阈值 → 请求内同步发布；> 阈值 → 保持 worker 异步
/// 消化（现状语义）。扇出越大，请求内串行发布事务越多，超过阈值的写入不应为
/// 生效延迟付出请求延迟。
pub const SYNC_PUBLISH_MAX_AFFECTED_CARDS: usize = 50;

/// 同步发布的整体时间预算（含全部 claim + 发布事务）。超时同失败处理，绝不
/// 阻塞写请求；预算按墙钟计，逐事件用 `timeout_at(deadline, ...)` 收口。
pub const SYNC_PUBLISH_BUDGET: Duration = Duration::from_secs(5);

/// 单次同步发布的事件预算（防御上限）：预算内的目标逐卡尝试，超出部分保持
/// worker 消化。防止「小卡数 × 大条目数」的写入把请求变成发布风暴。
pub const SYNC_PUBLISH_MAX_EVENTS: usize = 32;

/// 同步发布 claim 的租约窗口（秒）。短于 worker 的 120s：同步发布的 lease 最坏
/// 情况是「超时 + 释放未知」，短窗口把该尾巴收敛到 30s 自愈（worker 过期 reclaim），
/// 而发布事务内部的 `extend_delta_event_lease` 心跳会照常把进行中的发布续到完整
/// worker 窗口。
pub const SYNC_PUBLISH_CLAIM_LEASE_SECS: i64 = 30;

/// 超时后 best-effort 释放的单次尝试预算；超过即放弃（lease 服务端过期自愈）。
const RELEASE_BUDGET: Duration = Duration::from_secs(1);

/// 同步发布的单个目标：一张卡在本请求内刚入账的 delta 事件集合。
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

/// 阈值分流（纯逻辑）：受影响卡数落在 `(0, 阈值]` 才尝试同步发布。
pub fn should_attempt_synchronous_publish(affected_card_count: usize) -> bool {
    affected_card_count > 0 && affected_card_count <= SYNC_PUBLISH_MAX_AFFECTED_CARDS
}

/// 同步发布结果分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPublishOutcome {
    /// 全部目标事件都在请求内 durable 发布（发布事务 commit 证明 + L2 推送已
    /// 尝试）；本请求的授权变更零延迟生效。
    Published,
    /// 未全部在请求内发布，但没有任何失败：目标事件（或排在它之前的兄弟事件）
    /// 由 worker 队列保证收敛——可能已被 worker 抢先 claim（AlreadyClaimed）、
    /// 已处于终态/退避调度，或存在必须先消化的更早事件。这是健康路径。
    Delegated,
    /// 同步发布失败（发布错误 / 判定拒绝 / 预算或 claim 基础设施失败 / 超时）。
    /// 事件已按 worker 统一 attempt-budget 语义留在队列（或超时后 best-effort
    /// 释放回 PENDING），收敛由 worker 重试机制兜底；绝不影响写请求结果。
    Failed,
}

/// repository 接线点入口：在 writer source 事务 **commit 成功之后** 调用。
///
/// 执行阈值分流 → 同步发布 → 按结果分类记录日志；任何失败都不上抛、不重试、
/// 不影响已提交的 source 事务与本次请求的返回值。
pub(crate) async fn after_commit_sync_publish(pool: &MySqlPool, targets: Vec<SyncPublishTarget>) {
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

/// 同步发布入口：以与 worker 相同的原语尝试在请求内发布目标事件。
///
/// `pool` 仅用于构造 sqlx runtime（与 worker 同一实现，发布 commit 后自动尝试
/// L2 evidence 推送）；测试经 [`try_synchronous_publish_with_runtime`] 注入替身。
pub async fn try_synchronous_publish(
    pool: &MySqlPool,
    targets: &[SyncPublishTarget],
) -> SyncPublishOutcome {
    let runtime: Arc<dyn AuthorizationProjectorRuntime> =
        Arc::new(SqlxAuthorizationProjectorRuntime::new(pool.clone()));
    try_synchronous_publish_with_runtime(runtime, targets).await
}

/// 注入 runtime 的同步发布入口（测试与未来复用面）。
///
/// 发布动作复用 worker 的 [`process_one_event`] 完整管线（readback → 观察发布
/// 上下文 → 账本分区 → 纯编译判定 → 单事务发布 → L2 推送），因此同步路径的
/// fail-closed 语义与 worker 逐分支一致。
pub async fn try_synchronous_publish_with_runtime(
    runtime: Arc<dyn AuthorizationProjectorRuntime>,
    targets: &[SyncPublishTarget],
) -> SyncPublishOutcome {
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
    // 事件预算内的目标才纳入本次同步发布；超出预算的目标保持 worker 消化。
    let mut scheduled: Vec<&SyncPublishTarget> = Vec::new();
    let mut total_targets = 0usize;
    let mut event_budget = SYNC_PUBLISH_MAX_EVENTS;
    for target in targets {
        if target.event_ids.is_empty() {
            continue;
        }
        if target.event_ids.len() > event_budget {
            break;
        }
        event_budget -= target.event_ids.len();
        total_targets += target.event_ids.len();
        scheduled.push(target);
    }
    if scheduled.is_empty() {
        return SyncPublishOutcome::Delegated;
    }

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
    use std::collections::VecDeque;
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
    }

    impl ScriptedRuntime {
        fn new(claims: Vec<Result<Option<DeltaEventClaim>, RuntimeAccessError>>) -> Arc<Self> {
            Arc::new(Self {
                claims: Mutex::new(claims.into()),
                claims_requested: Mutex::new(Vec::new()),
                released: Mutex::new(Vec::new()),
                failed: Mutex::new(Vec::new()),
                claim_delay: None,
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
        // 目标 1 事件 + 目标 34 事件 > SYNC_PUBLISH_MAX_EVENTS：第二个目标整体
        // 不纳入本次同步发布（零 claim），保持 worker 消化。
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
        assert_eq!(outcome, SyncPublishOutcome::Published);
        assert_eq!(runtime.requested_scopes(), vec![(TENANT, CARD_A)]);
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
