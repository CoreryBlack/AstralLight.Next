//! 授权投影 durable worker（新队列唯一消费者）— AuthorizationProjector
//!
//! 消费 migration `20260825000002` 新增的 Rust-owned 表：
//! `authorization_delta_event`（typed grant delta 队列）→ 事务外编译 → 经
//! `authorization_impact_plan` / `authorization_projection_manifest` /
//! `authorization_projection_current` / `authorization_archive_outbox` 发布。
//!
//! 硬边界（对齐 AGENTS §3 与本任务门禁）：
//! - 不触碰旧表职责：不调用旧 CARD/RULE_SET 快照重建入口（`*snapshot_inner`
//!   家族），不写两张旧快照表，不消费旧 outbox 队列表，不发布旧 refresh MQ，
//!   不做旧 cache evict；具体符号清单由 shape tests 锁定。
//! - 每个 event 使用稳定 `event_id`/`operation_id` + run-scoped lease token；
//!   claim 用独立短事务；发布由 `project_authorization_delta_in_tx` 在单事务内
//!   重新校验租约/链接/指针/fence 并完成 complete impact-plan + complete delta，
//!   durable pointer/manifest proof 提交后才向调用方返回成功。
//! - 纯编译阶段全部在事务外：scope ledger 全量读取 →
//!   `latest_entries_from_history`（tombstone 不授权）→ 复核 claimed DTO ↔
//!   ledger ↔ 依赖向量哈希 → `AuthorizationCompiler` 增量编译；
//!   `FullRebuildRequired` 只作为显式 oracle 分支并记录 reason。
//! - Conflict / 哈希漂移 / 版本不一致一律 fail-closed：bounded backoff 或隔离
//!   （QUARANTINE 决策记录在日志与 last_error），绝不发布、绝不伪造成功。
//! - Archive intent 由发布事务内部自动追加（仅当存在 parent、保持 PENDING）；
//!   ArchiveWorker 属于后续独立 slice，本文件绝不引用 archive-intent 终态 API
//!   （具体符号由 shape tests 锁定）。
//! - worker panic / 断流不能静默报成功：句柄 join 结果与 shutdown 耗时全部上抛
//!   给 main（见 [`shutdown_authorization_projector`]）。
//!
//! 当前切片边界（slice-2 已接线，行为契约如下）：
//! 1. **Publication context 观察**：[`AuthorizationProjectorRuntime::
//!    observe_publication_context`] 在一次短事务内经 astral-db 公开 loader 同时
//!    加载严格 published frontier（generation 1..=G）与当前 parent reference
//!    快照；无 pointer 返回 `None`，有 pointer 而 parent 快照缺失按 Corrupt 处理。
//!    结果只作为 planning hint——发布事务 [`project_authorization_delta_in_tx`]
//!    内部重锁指针/fence/parent 做二次权威复核，观察值永远不充当放行证明。
//! 2. **多 grant ledger 分区**：claim/readback 之后加载完整 aggregate ledger，
//!    调用 `partition_ledger_at_published_frontier(rows, frontier,
//!    [current_event])`。base 只能由 partition 的 `published_heads` 构建（每
//!    grant 仅最后一个已被 frontier 证明的 head；tombstone 保留在 HotState
//!    ledger 中但不授权）。遇到未发布兄弟 tail 不再 Blocked：普通
//!    `NotProvenPublished` 排除项不污染 base 且允许当前 candidate 发布；own
//!    event 落在 `ClaimedBehindUnpublishedSiblings` → Blocked；落在
//!    `StaleClaimBehindPublishedFrontier` 或 own missing/ambiguous/partition
//!    corruption → Quarantine。frontier 为 None 时只要求 claimed grant 自身
//!    链从 rev1 连续且含 claimed revision（兄弟 grant 的独立初始链忽略——
//!    per-grant 版本域下跨 grant 发布顺序无歧义，各自 claim 收口；兄弟未发
//!    布期间授权读由 source-freshness 门保持 PENDING，绝不放行中间态）。
//!    aggregate generation 与 per-grant version 永不直接比较：successor 关系
//!    只对照该 grant 自己的 frontier last delta target。
//! 3. **Segment reuse**：观察到 parent references 时将 digest 匹配的 unchanged
//!    segment 计划为 [`StagedSegmentContent::ReuseParent`]（digest 判等 + ordinal
//!    去重），changed/new 用 New。planning view 只是 hint，staging 事务内部全部
//!    重验（指针代差 → PointerMoved 快速 retry，不用旧 refs 强行发布）；无
//!    parent 视图全 New（同内容 segment 行仍由存储层按 digest 去重复用，绝无
//!    delete/reinsert）。
//! 4. **真 QUARANTINED 终态**：确定性 divergence（dependency drift、编译器
//!    DuplicateDelta/ExistingGrant、publish 阶段 immutable conflict 家族等）经
//!    [`AuthorizationProjectorRuntime::mark_event_quarantined`]（live-lease
//!    guarded CAS）写入真实 `QUARANTINED` 状态并离开 claim 队列；成功才计
//!    quarantined。lease/CAS 丢失或查询失败记 UNKNOWN（见
//!    [`WorkerRunSummary::events_quarantine_unknown`]）并停止一切后续 mutation，
//!    绝不 fail/retry/伪装成功。attempt 预算耗尽仍保持 PENDING + 最大退避 +
//!    [`ATTEMPT_BUDGET_EXHAUSTED_CODE`]（持续基础设施故障可能自愈），不转隔离；
//!    无 operator HTTP requeue（requeue API 属 repository/operator 层）。
//! 5. **Publish 租约心跳与 unproven-history 阻塞**：发布事务开始时先在同一
//!    事务内以 owner+token+status CAS + 服务端时间续租
//!    （astral-db `extend_delta_event_lease`，不改 attempts/cas_version），
//!    完成不再仅因原 claim 120s 窗口耗尽而失败；CAS 失败 = 丢失所有权 →
//!    LeaseLost/UNKNOWN，零后续写入（typed `GrantRepositoryError` 变体跨
//!    [`RepositoryRejection`] 保留，绝不按 Display 文本分类）。过期 `LEASED`
//!    行只能被原样 reclaim（attempts+1），其后的每条失败路径都经统一
//!    attempt 预算退避（`next_attempt_at`/cap），绝不热循环。
//!    `backfill_or_rehearsal_required` 属 unproven history（等待 operator
//!    backfill/rehearsal 提供带证明的指针），按 Blocked 在预算内退避，绝不
//!    消耗终态隔离。

mod config;
mod planning;
mod runtime;
mod worker;

#[cfg(feature = "e3-observability")]
fn log_e3_attempt_event(
    event: &'static str,
    claimed: &astral_db::DeltaEventClaim,
    outcome: &'static str,
    durable: bool,
    backoff_seconds: Option<i64>,
) {
    let stamp = astral_common::experiment_observation::stamp();
    tracing::info!(
        target: "authz_e3",
        event,
        process_observation_id = %stamp.process_observation_id,
        event_sequence = stamp.event_sequence,
        wall_unix_ns = %stamp.wall_unix_ns,
        delta_event_id = claimed.delta_event_id,
        event_id = %claimed.event_id,
        attempt_id = %format!("{}:{}", claimed.delta_event_id, claimed.attempts),
        operation_id = %claimed.operation_id,
        tenant_id = claimed.tenant_id,
        card_id = ?claimed.card_id,
        aggregate_type = %claimed.aggregate_type,
        aggregate_id = claimed.aggregate_id,
        grant_id = %claimed.grant_id,
        target_version = claimed.target_version,
        attempts = claimed.attempts,
        outcome,
        durable,
        backoff_seconds = ?backoff_seconds,
        "e3 projector observation"
    );
}

#[cfg(feature = "e3-observability")]
fn log_e3_identity_event(
    event: &'static str,
    identity: &astral_db::DeltaLeaseIdentity,
    outcome: &'static str,
    durable: bool,
    backoff_seconds: Option<i64>,
) {
    let stamp = astral_common::experiment_observation::stamp();
    tracing::info!(
        target: "authz_e3",
        event,
        process_observation_id = %stamp.process_observation_id,
        event_sequence = stamp.event_sequence,
        wall_unix_ns = %stamp.wall_unix_ns,
        delta_event_id = identity.delta_event_id,
        event_id = %identity.event_id,
        outcome,
        durable,
        backoff_seconds = ?backoff_seconds,
        "e3 projector observation"
    );
}

pub use config::*;
pub use runtime::*;
pub use worker::*;

pub(crate) use planning::*;

#[cfg(test)]
mod tests;
