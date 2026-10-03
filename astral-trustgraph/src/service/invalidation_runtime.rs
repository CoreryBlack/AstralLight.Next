//! TrustGraph 失效 fanout 与 MQ bootstrap 的 runtime 接线（P3/P4，DEFAULT-OFF）。
//!
//! 本模块是唯一的接线层（不复制 astral-mq / astral-db 实现，不新增 HTTP 路由，
//! 不改变 Audit/DLQ 旧语义）：
//!
//! 1. **有界 MQ bootstrap**：fire-and-forget 的「无限重试 + pending 永驻
//!    keepalive 任务」替换为有限 `MQ_BOOTSTRAP_MAX_ATTEMPTS` 次尝试 + capped
//!    backoff；每次尝试持有 owned 连接，失败/放弃必须 close（未知连接结果绝不
//!    留活连接）；连接成功后由 [`RabbitMqRuntime`] 持有到 `run_with_listen_addr`
//!    作用域结束（bind 失败 / 正常关闭 / 错误路径全部 RAII 覆盖），keepalive
//!    任务被所有权本身取代（不再 spawn `pending()` 任务）。
//! 2. **失效 fanout runtime**（仅 `ASTRAL_INVALIDATION_FANOUT_ENABLED=true`
//!    时装配）：安装进程级内存投影中心 → `warm_from_durable` →
//!    **markSuspect**（strict 门：channel 证明活跃 + durable 全量对账成功之前，
//!    读面保持 fail-closed）→ 每节点 topology + relay（durable outbox 发布）+
//!    inbox（durable per-node inbox proof 先于 ACK）→ 2s 周期 reconcile
//!    supervisor。单写者 ownership 是部署预条件（TrustGraph 唯一授权 owner），
//!    不以单节点锁强制（多节点共库 fanout / composite 已持租约都会被阻塞）；
//!    分叉风险由周期 durable 水位对账兜底。
//! 3. **supervisor 清门协议**（与 hub 的 mutation_revision 封印协同）：
//!    liveness OK（owned 连接实际可用——真实 connect/订阅成功的
//!    Arc<AtomicBool>，绝非 lapin auto-recover 的 `is_connected`——且心跳新鲜
//!    3s 窗口）时**每个 tick** 都执行 bounded durable 全量对账：suspect 清门
//!    与健康态漏通知兜底共用同一条 durable 证明路径（水位对账是必要 DB 兜底，
//!    不是正常消息热路径）。连接关闭/超时/心跳缺失一律保持/拉起 suspect 且
//!    绝不对账；对账期间任何 `on_channel_suspect` 引起的 revision 变化都会让
//!    hub 拒绝清门。对账 Err 中 hub 的两类正常暂缓（source writer 在途 /
//!    revision 竞态）下一 tick 重试，其余异常拉起 suspect。
//! 4. **Local 传输**：hub/supervisor 同样只在旗标开启时装配；活跃信号是
//!    `bus.owners_ready()` 的实际监控，绝不以定时器伪装心跳。
//!
//! 关闭语义：fanout relay/inbox/supervisor 句柄持有到 runtime shutdown，
//! 正常路径按启动逆序 bounded `shutdown_and_join`；启动失败与外层提前返回
//! 由 [`InvalidationFanoutRuntime::Drop`]（RAII）信号 + abort 覆盖。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use astral_db::MemoryProjectionHub;

use astral_mq::config::declare_invalidation_fanout_topology;
use astral_mq::envelope::MessageEnvelope;
use astral_mq::invalidation::InvalidationEvent;
use astral_mq::invalidation_fanout::{HeartbeatScope, ScopeGapReport};
use astral_mq::invalidation_fanout_worker::{
    spawn_invalidation_fanout_inbox_worker, spawn_invalidation_fanout_relay,
    InvalidationFanoutRelaySettings, InvalidationInboxWorkerSettings, LocalMessageOutboxSource,
};
use astral_mq::{
    InvalidationApply, InvalidationFanoutListener, LapinFanoutPublisher, LapinInboxSession,
    MySqlInvalidationInbox, NodeIdentity,
};

/// 失效 fanout 部署旗标的唯一 env 名（严格 bool，default-off）。
pub const ENV_INVALIDATION_FANOUT_ENABLED: &str = "ASTRAL_INVALIDATION_FANOUT_ENABLED";

/// MQ bootstrap 的有限重试预算：超过即拒绝启动（fail-closed），绝不回到
/// fire-and-forget 的无限重试。
pub const MQ_BOOTSTRAP_MAX_ATTEMPTS: u32 = 5;

/// MQ bootstrap backoff 上限（指数 2^n 秒，n 为尝试序号，封顶于此值）。
pub const MQ_BOOTSTRAP_BACKOFF_CAP: Duration = Duration::from_secs(60);

/// reconcile supervisor 周期（2s）。liveness OK 时每 tick 发起 bounded
/// durable 全量对账（suspect 清门与健康态漏通知兜底同路径）；liveness 丢失
/// 时只保持/拉起 suspect，绝不对账。
pub const RECONCILE_SUPERVISOR_INTERVAL: Duration = Duration::from_secs(2);

/// Durable reconcile 的单次总预算。行数上限限制内存，不限制 SQL 等待；超时必须
/// 终止本次只读对账并保持 suspect，下一 tick 重新对账，绝不重放任何 durable 事件。
pub const RECONCILE_DEADLINE: Duration = Duration::from_secs(5);

/// 心跳新鲜窗口（3s）：relay 以 2s 间隔发布心跳，3s 内无新鲜心跳即视为
/// 活跃度缺失（连接关闭/超时/心跳缺失一律保持 suspect）。
pub const FRESH_HEARTBEAT_WINDOW_MS: u64 = 3_000;

/// fanout relay 心跳发布间隔（2s）：与本节点 inbox 收到的真实帧共同构成
/// 「实际 checked conn」的活跃度证据；hub 自身的 5s 静默窗口留有余量。
pub const FANOUT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// fanout 组件启动失败中途回收的有界 join 上限。
pub const FANOUT_STOP_JOIN_CAP: Duration = Duration::from_secs(5);

/// warm 完成后、channel 证明活跃且 durable 对账成功之前的 strict 门理由。
const FANOUT_STARTUP_GATE_REASON: &str =
    "fanout startup: channel liveness and durable reconcile not yet proven";

// ─────────────────────────────────────────────────────────────────────────────
// 部署旗标（严格 bool，与 astral-common::parse_org_scope_enabled 同一契约）
// ─────────────────────────────────────────────────────────────────────────────

/// 严格解析失效 fanout 旗标：unset/空白/`"false"` → `Ok(false)`（default-off）；
/// `"true"`（trim 后精确匹配，区分大小写）→ `Ok(true)`；其他任何非空值 →
/// `Err`（fail-fast，调用方必须拒绝启动，绝不静默降级）。错误信息只含期望
/// 格式，不回显原始值。
pub fn parse_invalidation_fanout_enabled(raw: Option<&str>) -> Result<bool, String> {
    match raw.map(str::trim) {
        None | Some("") | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(format!(
            "{ENV_INVALIDATION_FANOUT_ENABLED} must be exactly \"true\" or \"false\" \
             (blank/unset means default-off)"
        )),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 单调时钟（心跳只记录单调活跃度，绝不清除 suspect）
// ─────────────────────────────────────────────────────────────────────────────

static FANOUT_CLOCK_ORIGIN: OnceLock<Instant> = OnceLock::new();

/// 进程内单调毫秒时钟：心跳/新鲜度只在这一个时间域里比较，不受墙钟跳变影响。
pub fn monotonic_millis() -> u64 {
    let origin = FANOUT_CLOCK_ORIGIN.get_or_init(Instant::now);
    // 下限 1ms：保证「已记录心跳」与「从未有心跳（0 哨兵）」在首次调用即
    // 可区分——record_heartbeat(0) 绝不会被误判为无心跳。
    origin.elapsed().as_millis().max(1).min(u64::MAX as u128) as u64
}

// ─────────────────────────────────────────────────────────────────────────────
// 连接健康（Arc<AtomicBool> 的实际 checked conn；liveness 绝不单独放行授权）
// ─────────────────────────────────────────────────────────────────────────────

/// MQ 连接健康 + 单调心跳新鲜度。`conn_alive` 只能由「真实在 owned 连接上
/// 完成的操作」置位（成功订阅/成功 bootstrap）；lapin auto-recover 恢复的
/// socket 绝不单独置位，更绝不清除 hub suspect（清门只有 durable 对账一条路）。
#[derive(Debug, Clone, Default)]
pub struct ChannelLiveness {
    conn_alive: Arc<AtomicBool>,
    last_heartbeat_ms: Arc<AtomicU64>,
}

impl ChannelLiveness {
    pub fn new() -> Self {
        Self::default()
    }

    /// 仅在真实成功操作（owned 连接上的订阅/bootstrap 完成）后调用。
    pub fn mark_alive(&self) {
        self.conn_alive.store(true, Ordering::Release);
    }

    /// 通道 suspect / 连接失败 / 尝试放弃时调用：liveness 不可用。
    pub fn mark_dead(&self) {
        self.conn_alive.store(false, Ordering::Release);
    }

    pub fn conn_alive(&self) -> bool {
        self.conn_alive.load(Ordering::Acquire)
    }

    /// 记录一次真实心跳帧（单调时钟取 max；绝不清除任何 suspect 状态）。
    pub fn record_heartbeat(&self, now_ms: u64) {
        self.last_heartbeat_ms.fetch_max(now_ms, Ordering::AcqRel);
    }

    /// 心跳新鲜：必须存在过心跳，且距今不超过 [`FRESH_HEARTBEAT_WINDOW_MS`]。
    pub fn heartbeat_fresh(&self, now_ms: u64) -> bool {
        let last = self.last_heartbeat_ms.load(Ordering::Acquire);
        last > 0 && now_ms.saturating_sub(last) <= FRESH_HEARTBEAT_WINDOW_MS
    }
}

/// supervisor 的活跃度探针。Rabbit：连接健康 + 心跳新鲜（bounded match 实际
/// checked conn）；Local：`bus.owners_ready()` 实际监控（owner 队列真实注册且
/// 未关闭），绝不以定时器伪装心跳。
#[derive(Clone)]
pub enum LivenessProbe {
    Rabbit(ChannelLiveness),
    LocalBus(astral_mq::local_bus::LocalBus),
}

impl LivenessProbe {
    pub fn is_alive(&self, now_ms: u64) -> bool {
        match self {
            Self::Rabbit(liveness) => liveness.conn_alive() && liveness.heartbeat_fresh(now_ms),
            Self::LocalBus(bus) => bus.owners_ready(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// supervisor 决策（纯函数，单测覆盖矩阵）
// ─────────────────────────────────────────────────────────────────────────────

/// supervisor 单个 tick 的决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorAction {
    /// suspect 但连接不可用/心跳不新鲜：保持 suspect；没有 channel alive 的
    /// reconcile 绝不允许清门（连接关闭/超时/心跳缺失一律保持 suspect）。
    HoldSuspect,
    /// 非 suspect 但活跃度丢失：主动拉起 suspect（fail-closed strict 读面）。
    MarkSuspect,
    /// Durable recovery for startup/suspect state, and periodic Rabbit watermarks.
    Reconcile,
    /// Local owners are healthy; refresh liveness without database polling.
    Observe,
}

/// 纯决策函数：`(suspect, liveness_ok) -> action`。
/// 连接关闭/超时/心跳缺失时（`liveness_ok == false`）永不返回 `Reconcile`；
/// liveness OK 时无论 suspect 与否都执行 durable 对账（健康态漏通知兜底）。
pub fn supervisor_tick(liveness_ok: bool, suspect: bool) -> SupervisorAction {
    if liveness_ok {
        SupervisorAction::Reconcile
    } else if suspect {
        SupervisorAction::HoldSuspect
    } else {
        SupervisorAction::MarkSuspect
    }
}

fn supervisor_tick_for_transport(
    liveness_ok: bool,
    suspect: bool,
    local: bool,
) -> SupervisorAction {
    if local && liveness_ok && !suspect {
        SupervisorAction::Observe
    } else {
        supervisor_tick(liveness_ok, suspect)
    }
}

/// supervisor 对 reconcile `Err` 的分类：hub 的两类**正常暂缓**（source
/// transaction 在途 / 对账期间 mutation 竞态触发 revision 封印）不是健康
/// 信号——写负载下几乎每个采样点都会出现，拉起 suspect 会让 strict 门在
/// 正常写入时反复关闭；这两类下一 tick 重试即可。其余失败（读失败/镜像
/// 不完整/unknown source commit 无证据）一律拉起 suspect（fail-closed；
/// hub 自身失败路径已内部 suspect，此处是防御性兜底）。字符串耦合于
/// astral-db 的稳定错误文案，source guard 与单测共同钉住。
pub fn is_reconcile_deferral(error: &str) -> bool {
    error.contains("source transaction is active")
        || error.contains("memory mutation raced durable reconciliation")
}

/// Local owner liveness refreshes healthy memory state without polling MySQL.
/// Startup/suspect recovery and Rabbit watermark repair share the bounded durable
/// reconciliation path. A heartbeat alone cannot clear suspect state.
pub fn spawn_reconcile_supervisor(
    pool: sqlx::MySqlPool,
    hub: MemoryProjectionHub,
    probe: LivenessProbe,
    worker_id: String,
) -> RuntimeTaskHandle {
    RuntimeTaskHandle::spawn("invalidation-fanout-reconcile-supervisor", async move {
        let mut ticker = tokio::time::interval(RECONCILE_SUPERVISOR_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let now_ms = monotonic_millis();
            let suspect = hub.channel_is_suspect();
            let alive = probe.is_alive(now_ms);
            match supervisor_tick_for_transport(
                alive,
                suspect,
                matches!(probe, LivenessProbe::LocalBus(_)),
            ) {
                SupervisorAction::Observe => hub.record_channel_heartbeat(),
                SupervisorAction::HoldSuspect => {}
                SupervisorAction::MarkSuspect => {
                    hub.mark_channel_suspect(
                        "fanout channel liveness lost (connection closed or heartbeat stale); strict fail-closed read path engaged",
                    );
                }
                SupervisorAction::Reconcile => {
                    hub.record_channel_heartbeat();
                    match tokio::time::timeout(
                        RECONCILE_DEADLINE,
                        hub.reconcile_from_durable(&pool),
                    )
                    .await
                    {
                        Ok(Ok(report)) => tracing::info!(
                            worker_id = %worker_id,
                            identities = report.identities,
                            pending_restored = report.pending_restored,
                            "invalidation fanout hub proved against durable reconcile; suspect gate cleared"
                        ),
                        Ok(Err(error)) => {
                            if is_reconcile_deferral(&error) {
                                tracing::debug!(
                                    worker_id = %worker_id,
                                    reason = %error,
                                    "durable reconcile deferred; retrying next tick"
                                );
                            } else {
                                hub.mark_channel_suspect(
                                "durable reconcile failed; strict fail-closed read path engaged",
                            );
                                tracing::warn!(
                                    worker_id = %worker_id,
                                    reason = %error,
                                    "durable reconcile did not prove the memory mirror; suspect gate stays closed"
                                );
                            }
                        }
                        Err(_) => {
                            hub.mark_channel_suspect(
                            "durable reconcile exceeded its bounded deadline; strict fail-closed read path engaged",
                        );
                            tracing::warn!(
                                worker_id = %worker_id,
                                deadline_ms = RECONCILE_DEADLINE.as_millis() as u64,
                                "durable reconcile timed out; no replay attempted"
                            );
                        }
                    }
                }
            }
        }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// listener / apply 适配（fanout 事件面 → hub 健康面 / 既有 consumer 语义）
// ─────────────────────────────────────────────────────────────────────────────

/// [`InvalidationFanoutListener`] 的 hub 健康适配：
/// - `on_channel_suspect`：唯一允许拉起 suspect 的钩子（sticky），同时把 owned
///   连接健康置为不可用；
/// - `on_heartbeat_alive`：只记录单调活跃度——hub 拒绝在此清除 suspect；
/// - `on_scope_gap`：strict——scope gap 是 suspect 级信号，读面回到 strict
///   路径直到 durable 对账证明一致，绝不吞掉。
#[derive(Clone)]
pub struct HubFanoutHealthListener {
    hub: MemoryProjectionHub,
    liveness: ChannelLiveness,
}

impl HubFanoutHealthListener {
    pub fn new(hub: MemoryProjectionHub, liveness: ChannelLiveness) -> Self {
        Self { hub, liveness }
    }
}

#[async_trait::async_trait]
impl InvalidationFanoutListener for HubFanoutHealthListener {
    async fn on_channel_suspect(&self, identity: &NodeIdentity, reason: &str) {
        self.liveness.mark_dead();
        self.hub.mark_channel_suspect(format!(
            "fanout channel suspect (region={}, node={}): {reason}",
            identity.region(),
            identity.node()
        ));
        tracing::warn!(
            region = identity.region(),
            node = identity.node(),
            "fanout channel suspect; strict fail-closed read path engaged"
        );
    }

    async fn on_heartbeat_alive(&self, identity: &NodeIdentity, heartbeat: &HeartbeatScope) {
        // liveness only：hub 内部保证 suspect 状态下心跳不改写任何状态；
        // supervisor 的新鲜度判断使用本地单调时钟。
        self.hub.record_channel_heartbeat();
        self.liveness.record_heartbeat(monotonic_millis());
        tracing::debug!(
            region = identity.region(),
            node = identity.node(),
            sent_at = %heartbeat.sent_at,
            "fanout heartbeat recorded (liveness only)"
        );
    }

    async fn on_scope_gap(&self, identity: &NodeIdentity, report: &ScopeGapReport) {
        tracing::warn!(
            region = identity.region(),
            node = identity.node(),
            ordering_key = %report.ordering_key,
            observed_message_id = %report.observed_message_id,
            has_pending_earlier = report.has_pending_earlier,
            scope_regressed = report.scope_regressed,
            "fanout scope gap flagged; hub enters suspect until durable reconcile"
        );
        self.hub.mark_channel_suspect(format!(
            "fanout scope gap (region={}, node={}, ordering_key={})",
            identity.region(),
            identity.node(),
            report.ordering_key
        ));
    }
}

/// 消费端 apply 适配器：typed invalidation 委派给 astral-mq consumers 的统一
/// 进程内入口（与 local bus / Rabbit 直连 consumer 完全同一 apply 语义：
/// evidence freshness fence / L1 eligibility evict / session registry），
/// 绝不复制实现、绝不改变既有 apply 契约。
pub struct ConsumerDispatchInvalidationApply;

#[async_trait::async_trait]
impl InvalidationApply for ConsumerDispatchInvalidationApply {
    async fn apply(
        &self,
        envelope: &MessageEnvelope,
        _event: &InvalidationEvent,
    ) -> Result<(), String> {
        astral_mq::consumers::dispatch_invalidation_event(envelope).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 有界 MQ bootstrap（owned 连接尝试 + 有限重试 + capped backoff）
// ─────────────────────────────────────────────────────────────────────────────

/// 一次 MQ bootstrap 尝试的 owned 资源生命周期。生产实现包裹真实 lapin
/// Connection；测试可注入 fake open/close 验证「失败/放弃必须 close」契约。
#[async_trait::async_trait]
pub trait MqConnectionAttempt: Send {
    type Runtime;

    /// 打开一次尝试的全部资源；失败时返回 `Err`，owned 资源仍登记在尝试内，
    /// 由 bootstrap 循环统一调用 [`Self::close_owned`] 回收。
    async fn open(&mut self) -> Result<Self::Runtime, String>;

    /// 关闭本次尝试持有的全部 owned 连接资源：失败、放弃、未知结果一律调用，
    /// 绝不把活连接泄漏到重试预算之外。
    async fn close_owned(&mut self, reason: &str);
}

/// 指数 backoff（2^n 秒，n 为已完成尝试数），封顶于 `cap`。
pub fn backoff_for_attempt(attempt: u32, cap: Duration) -> Duration {
    let exponent = attempt.min(16);
    let capped = 2u64.saturating_pow(exponent).min(cap.as_secs().max(1));
    Duration::from_secs(capped)
}

/// 有界 bootstrap：最多 `max_attempts` 次 open；每次失败先 `close_owned` 回收
/// owned 连接，再按 capped backoff 等待后重试。预算耗尽返回 `Err`（调用方必须
/// 拒绝启动）。每次尝试独立记账，无跨尝试预算残留；被放弃/未知结果的尝试不
/// 计入成功，也绝不遗留活连接。
pub async fn bootstrap_mq_with_bounded_retry<A, T>(
    mut attempt: A,
    max_attempts: u32,
    backoff_cap: Duration,
) -> Result<T, String>
where
    A: MqConnectionAttempt<Runtime = T>,
{
    let mut count: u32 = 0;
    loop {
        count = count.saturating_add(1);
        match attempt.open().await {
            Ok(runtime) => return Ok(runtime),
            Err(error) => {
                attempt.close_owned("mq bootstrap attempt failed").await;
                tracing::warn!(
                    attempt = count,
                    max_attempts,
                    "mq bootstrap attempt failed; bounded retry with capped backoff"
                );
                if count >= max_attempts {
                    return Err(format!(
                        "mq bootstrap failed after {count} bounded attempts: {error}"
                    ));
                }
                tokio::time::sleep(backoff_for_attempt(count, backoff_cap)).await;
            }
        }
    }
}

/// 关闭一次 bootstrap 尝试持有的 owned 连接（未知/失败结果绝不留活连接）。
/// lapin 4 的 `Connection` 不可 Clone：连接以 `Arc` 共享（RabbitMqRuntime /
/// fanout wiring），回收与关闭都经由同一 Arc 所有权。
pub async fn close_owned_connection(connection: Arc<lapin::Connection>, reason: &str) {
    if let Err(error) = connection.close(200, reason.into()).await {
        tracing::warn!(
            %error,
            "owned mq connection close during bootstrap cleanup failed; dropping anyway"
        );
    }
}

/// 成功 bootstrap 后的 Rabbit MQ runtime：连接与确认通道由本结构持有到
/// `run_with_listen_addr` 作用域结束——bind 失败、启动失败回滚、正常关闭、
/// 错误路径全部 RAII 覆盖（Drop 即关闭连接与通道，consumer 循环随通道终止），
/// 因此不需要任何 keepalive 任务。连接以 `Arc` 持有（lapin 4 无 Clone），
/// fanout wiring 与 inbox 重连闭包通过 `Arc` 克隆共享同一连接所有权。
pub struct RabbitMqRuntime {
    connection: Arc<lapin::Connection>,
    channel: lapin::Channel,
    liveness: ChannelLiveness,
}

impl RabbitMqRuntime {
    /// bootstrap 尝试成功后的唯一构造点（字段私有，模块外不得直接构造）。
    pub fn from_bootstrap(
        connection: Arc<lapin::Connection>,
        channel: lapin::Channel,
        liveness: ChannelLiveness,
    ) -> Self {
        Self {
            connection,
            channel,
            liveness,
        }
    }

    pub fn connection_handle(&self) -> Arc<lapin::Connection> {
        Arc::clone(&self.connection)
    }

    pub fn channel(&self) -> &lapin::Channel {
        &self.channel
    }

    pub fn liveness(&self) -> ChannelLiveness {
        self.liveness.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RAII runtime 任务句柄（Drop abort；正常关闭走有界 join）
// ─────────────────────────────────────────────────────────────────────────────

/// Owns a runtime task through cancellation and bounded shutdown.
/// Aborting a consumer leaves unproved durable effects unknown.
pub struct RuntimeTaskHandle {
    name: &'static str,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl RuntimeTaskHandle {
    pub fn spawn(
        name: &'static str,
        task: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Self {
        Self {
            name,
            join: Some(tokio::spawn(task)),
        }
    }

    /// The task remains owned if this shutdown future is cancelled.
    pub async fn shutdown_join(mut self, timeout: Duration) -> Result<(), String> {
        let name = self.name;
        let Some(join) = self.join.as_mut() else {
            return Ok(());
        };
        match tokio::time::timeout(timeout, &mut *join).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("runtime task {name} join failed: {error}")),
            Err(_) => {
                join.abort();
                let _ = tokio::time::timeout(Duration::from_secs(1), &mut *join).await;
                Err(format!(
                    "runtime task {name} shutdown timed out; final outcome unknown"
                ))
            }
        }
    }
}

impl Drop for RuntimeTaskHandle {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// fanout runtime 装配（旗标开启时唯一启动点）
// ─────────────────────────────────────────────────────────────────────────────

/// 传输装配参数：Rabbit 携带已证明的 owned 连接与共享连接健康；
/// Local 携带 composite LocalBus（owners_ready 实际监控）。
pub enum FanoutWiring {
    Rabbit {
        connection: Arc<lapin::Connection>,
        liveness: ChannelLiveness,
    },
    LocalBus {
        bus: astral_mq::local_bus::LocalBus,
    },
}

/// 运行期状态快照（runtime-facing status；纯读取，无副作用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidationFanoutStatus {
    pub started: bool,
    pub transport: &'static str,
    pub region: Option<String>,
    pub node: Option<String>,
    pub conn_alive: bool,
    pub heartbeat_fresh: bool,
    pub channel_suspect: bool,
    pub relay_active: bool,
    pub inbox_active: bool,
}

struct InvalidationFanoutMembers {
    transport: &'static str,
    identity: NodeIdentity,
    liveness: ChannelLiveness,
    relay: Option<astral_mq::invalidation_fanout_worker::InvalidationFanoutRelayHandle>,
    inbox: Option<astral_mq::invalidation_fanout_worker::InvalidationInboxWorkerHandle>,
    supervisor: RuntimeTaskHandle,
}

/// 失效 fanout runtime 句柄：持有 relay/inbox/supervisor 直到 runtime
/// shutdown。正常路径 [`InvalidationFanoutRuntime::shutdown`]（有界逆序
/// join）；启动失败与外层提前返回由 [`Drop`] RAII 覆盖（relay/inbox 收到协作
/// 关闭信号后在一个 poll tick 内退出，supervisor 直接 abort）。
///
/// 单写者 ownership 是部署预条件（TrustGraph 是唯一授权 owner），**不**以
/// `acquire_single_writer_lease` 之类的单节点锁强制：Rabbit 多节点 fanout
/// 允许同城多节点共库启动，且 composite 进程已持有该租约；重复获取会互相
/// 阻塞。多写者分叉风险由 supervisor 的周期 durable 水位对账兜底。
pub struct InvalidationFanoutRuntime {
    members: Option<InvalidationFanoutMembers>,
}

impl Drop for InvalidationFanoutRuntime {
    fn drop(&mut self) {
        if let Some(members) = &self.members {
            if let Some(relay) = &members.relay {
                relay.signal_shutdown();
            }
            if let Some(inbox) = &members.inbox {
                inbox.signal_shutdown();
            }
            // supervisor：RuntimeTaskHandle::Drop abort。
        }
    }
}

impl InvalidationFanoutRuntime {
    /// 有界关闭（启动严格逆序：supervisor → inbox → relay；单写者租约在
    /// members 丢弃时最后释放）。任一组件未在时限内静止即返回 `Err`。
    pub async fn shutdown(mut self, timeout: Duration) -> Result<(), String> {
        let Some(members) = self.members.take() else {
            return Err("invalidation fanout runtime already shut down".to_owned());
        };
        let mut failures: Vec<String> = Vec::new();
        if let Err(error) = members.supervisor.shutdown_join(timeout).await {
            failures.push(error);
        }
        if let Some(inbox) = members.inbox {
            if tokio::time::timeout(timeout, inbox.shutdown_and_join())
                .await
                .is_err()
            {
                failures.push("invalidation fanout inbox worker did not stop in time".to_owned());
            }
        }
        if let Some(relay) = members.relay {
            if tokio::time::timeout(timeout, relay.shutdown_and_join())
                .await
                .is_err()
            {
                failures.push("invalidation fanout relay did not stop in time".to_owned());
            }
        }
        // members 在此 drop：任务已静止后结束。
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }

    /// runtime-facing 状态快照（纯读取）。
    pub fn status(&self, now_ms: u64) -> InvalidationFanoutStatus {
        let Some(members) = &self.members else {
            return InvalidationFanoutStatus {
                started: false,
                transport: "none",
                region: None,
                node: None,
                conn_alive: false,
                heartbeat_fresh: false,
                channel_suspect: false,
                relay_active: false,
                inbox_active: false,
            };
        };
        let channel_suspect = astral_db::memory_projection_hub()
            .map(|hub| hub.channel_is_suspect())
            .unwrap_or(true);
        InvalidationFanoutStatus {
            started: true,
            transport: members.transport,
            region: Some(members.identity.region().to_owned()),
            node: Some(members.identity.node().to_owned()),
            conn_alive: members.liveness.conn_alive(),
            heartbeat_fresh: members.liveness.heartbeat_fresh(now_ms),
            channel_suspect,
            relay_active: members.relay.is_some(),
            inbox_active: members.inbox.is_some(),
        }
    }
}

/// 安装进程级内存投影中心（幂等：已安装则返回既有句柄）。
/// 仅在 fanout 旗标开启的启动路径调用。
pub fn install_projection_hub_for_fanout() -> Result<MemoryProjectionHub, String> {
    if astral_db::install_memory_projection_hub() {
        tracing::info!("memory projection hub installed for the invalidation fanout runtime");
    }
    astral_db::memory_projection_hub()
        .cloned()
        .ok_or_else(|| "memory projection hub install failed".to_owned())
}

/// 启动 warm：恢复 durable pending 与完整聚合清单；失败必须拒绝启动（读面
/// 保持关闭）。warm 成功后立即 markSuspect——warm 本身不是清门证明，strict
/// 门保持到「channel 实际活跃 + durable 全量对账成功」。
pub async fn warm_and_gate_projection_hub(
    pool: &sqlx::MySqlPool,
    hub: &MemoryProjectionHub,
) -> Result<astral_db::WarmReport, String> {
    let report = astral_db::warm_from_durable(pool).await.map_err(|error| {
        format!("projection hub warm-up failed; refusing fanout startup: {error}")
    })?;
    hub.mark_channel_suspect(FANOUT_STARTUP_GATE_REASON);
    Ok(report)
}

/// Assemble the LocalBus-only supervisor after the composite runtime has already
/// warmed the global hub. This path never installs or warms the hub again, so it
/// cannot clear an active mirror while service tasks are starting.
pub fn start_local_projection_supervisor(
    pool: sqlx::MySqlPool,
    bus: astral_mq::local_bus::LocalBus,
    identity: NodeIdentity,
) -> Result<InvalidationFanoutRuntime, String> {
    let hub = astral_db::memory_projection_hub()
        .cloned()
        .ok_or_else(|| "local projection supervisor requires an installed memory hub".to_owned())?;
    let supervisor = spawn_reconcile_supervisor(
        pool,
        hub,
        LivenessProbe::LocalBus(bus),
        format!(
            "invalidation-local-supervisor-{}-{}",
            identity.region(),
            identity.node()
        ),
    );
    Ok(InvalidationFanoutRuntime {
        members: Some(InvalidationFanoutMembers {
            transport: "local",
            identity,
            liveness: ChannelLiveness::new(),
            relay: None,
            inbox: None,
            supervisor,
        }),
    })
}

/// 失效 fanout runtime 的唯一启动点（Rabbit 旗标开启时或兼容调用方使用）：
///
/// 1. 安装 hub → `warm_from_durable` → markSuspect（strict 门）。
///    单写者 ownership 是部署预条件（TrustGraph 是唯一授权 owner），不以
///    单节点锁强制——多节点共库 fanout 与 composite 已持租约都会被阻塞；
///    分叉风险由 supervisor 的周期 durable 水位对账兜底。
/// 2. Rabbit：每节点 topology（fanout exchange + 本节点 durable 队列 + DLX，
///    幂等）→ relay（durable outbox 发布，2s 心跳）→ inbox（durable per-node
///    inbox proof 先于 ACK）。
///    Local：不启动 relay/inbox（跨节点 Rabbit 语义），supervisor 以
///    `owners_ready()` 为活跃信号。
/// 3. 2s reconcile supervisor（liveness OK 时每 tick durable 全量对账；清门
///    协议见模块文档）。
///
/// 中途失败：按已启动成员的有界 join 回收后返回 `Err`（调用方拒绝启动）。
pub async fn start_invalidation_fanout_runtime(
    pool: sqlx::MySqlPool,
    wiring: FanoutWiring,
    identity: NodeIdentity,
) -> Result<InvalidationFanoutRuntime, String> {
    // 单写者 ownership 是部署预条件（见 InvalidationFanoutRuntime 文档），不
    // 以单节点锁强制：多节点共库 fanout 与 composite 已持租约都会被
    // acquire_single_writer_lease 阻塞；分叉风险由周期 durable 水位对账兜底。
    let hub = install_projection_hub_for_fanout()?;
    let warm = warm_and_gate_projection_hub(&pool, &hub).await?;
    tracing::info!(
        region = identity.region(),
        node = identity.node(),
        identities = warm.identities,
        installed = warm.installed,
        failed = warm.failed,
        pending_restored = warm.pending_restored,
        "invalidation fanout hub warmed from durable; suspect gate engaged until channel is alive and reconcile proves durable"
    );

    let (transport, liveness, relay, inbox, probe) = match wiring {
        FanoutWiring::Rabbit {
            connection,
            liveness,
        } => {
            let relay_settings = InvalidationFanoutRelaySettings {
                enabled: true,
                heartbeat_interval: Some(FANOUT_HEARTBEAT_INTERVAL),
                ..Default::default()
            };
            let inbox_settings = InvalidationInboxWorkerSettings {
                enabled: true,
                ..Default::default()
            };
            // 每节点专用 publisher channel（confirm 由构造器启用并验证）。
            let publisher_channel = connection
                .create_channel()
                .await
                .map_err(|error| format!("fanout publisher channel failed: {error}"))?;
            // 每节点 topology：fanout exchange + 本节点 durable 订阅队列 +
            // DLX 队列（creator-guarded，重连可重跑；绝不共享竞争队列）。
            declare_invalidation_fanout_topology(&publisher_channel, &identity)
                .await
                .map_err(|error| format!("fanout topology declare failed: {error}"))?;
            let publisher = LapinFanoutPublisher::new(publisher_channel)
                .await
                .map_err(|error| error.to_string())?;
            let relay = spawn_invalidation_fanout_relay(
                LocalMessageOutboxSource::new(pool.clone()),
                publisher,
                identity.clone(),
                format!(
                    "invalidation-fanout-relay-{}-{}",
                    identity.region(),
                    identity.node()
                ),
                relay_settings,
            )?;
            let connect = {
                let connection = connection.clone();
                let identity = identity.clone();
                let liveness = liveness.clone();
                let prefetch = inbox_settings.prefetch;
                move || {
                    let connection = connection.clone();
                    let identity = identity.clone();
                    let liveness = liveness.clone();
                    async move {
                        // 实际 checked conn：只有真实在 owned 连接上完成的
                        // 订阅才把 liveness 置回 alive；auto-recover 的
                        // is_connected 绝不单独作为清 suspect 的依据。
                        match LapinInboxSession::connect(&connection, &identity, prefetch).await {
                            Ok(session) => {
                                liveness.mark_alive();
                                Ok(session)
                            }
                            Err(error) => {
                                liveness.mark_dead();
                                Err(error.to_string())
                            }
                        }
                    }
                }
            };
            let listener = HubFanoutHealthListener::new(hub.clone(), liveness.clone());
            let inbox = match spawn_invalidation_fanout_inbox_worker(
                connect,
                MySqlInvalidationInbox::new(pool.clone()),
                ConsumerDispatchInvalidationApply,
                listener,
                identity.clone(),
                inbox_settings,
            ) {
                Ok(handle) => handle,
                Err(error) => {
                    // 启动失败：有界回收已启动的 relay 后拒绝。
                    let _ =
                        tokio::time::timeout(FANOUT_STOP_JOIN_CAP, relay.shutdown_and_join()).await;
                    return Err(format!("fanout inbox worker failed to start: {error}"));
                }
            };
            let probe = LivenessProbe::Rabbit(liveness.clone());
            ("rabbit", liveness, Some(relay), Some(inbox), probe)
        }
        FanoutWiring::LocalBus { bus } => {
            // Local 传输：local message 是正常失效路径；supervisor 活跃信号为
            // bus.owners_ready() 实际监控。单机 TrustGraph 只注册自己的 owner
            // 队列，owners 未全部就位时保持 suspect（fail-closed strict 读面）。
            (
                "local",
                ChannelLiveness::new(),
                None,
                None,
                LivenessProbe::LocalBus(bus),
            )
        }
    };

    let supervisor = spawn_reconcile_supervisor(
        pool.clone(),
        hub.clone(),
        probe,
        format!(
            "invalidation-fanout-supervisor-{}-{}",
            identity.region(),
            identity.node()
        ),
    );
    Ok(InvalidationFanoutRuntime {
        members: Some(InvalidationFanoutMembers {
            transport,
            identity,
            liveness,
            relay,
            inbox,
            supervisor,
        }),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// 测试：严格解析 / 有界 bootstrap（fake open/close）/ liveness / supervisor
// 决策矩阵 / listener 契约（真实 hub 实例 + fake 事件）
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cancelling_runtime_task_shutdown_aborts_its_owned_consumer() {
        struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                if let Some(signal) = self.0.take() {
                    let _ = signal.send(());
                }
            }
        }
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let handle = RuntimeTaskHandle::spawn("cancel-consumer-test", async move {
            let _drop = DropSignal(Some(dropped_tx));
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.unwrap();
        {
            let mut shutdown = std::pin::pin!(handle.shutdown_join(Duration::from_secs(5)));
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                    .await
                    .is_err()
            );
        }
        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("cancelled shutdown must not detach the consumer")
            .expect("consumer Drop must be observed");
    }

    #[test]
    fn fanout_flag_is_strict_bool_and_default_off() {
        assert!(!parse_invalidation_fanout_enabled(None).unwrap());
        assert!(!parse_invalidation_fanout_enabled(Some("")).unwrap());
        assert!(!parse_invalidation_fanout_enabled(Some("   ")).unwrap());
        assert!(!parse_invalidation_fanout_enabled(Some("false")).unwrap());
        assert!(parse_invalidation_fanout_enabled(Some("true")).unwrap());
        // trim 后精确匹配：带空白的 "false" 合法归为 off（与
        // parse_org_scope_enabled 同一契约），其余非 "true"/"false" 值拒绝。
        assert!(!parse_invalidation_fanout_enabled(Some(" false ")).unwrap());
        for rejected in ["True", "TRUE", "1", "0", "yes", "on", "enabled"] {
            assert!(
                parse_invalidation_fanout_enabled(Some(rejected)).is_err(),
                "value {rejected:?} must be rejected fail-closed"
            );
        }
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(
            backoff_for_attempt(1, MQ_BOOTSTRAP_BACKOFF_CAP),
            Duration::from_secs(2)
        );
        assert_eq!(
            backoff_for_attempt(2, MQ_BOOTSTRAP_BACKOFF_CAP),
            Duration::from_secs(4)
        );
        assert_eq!(
            backoff_for_attempt(3, MQ_BOOTSTRAP_BACKOFF_CAP),
            Duration::from_secs(8)
        );
        assert_eq!(
            backoff_for_attempt(10, MQ_BOOTSTRAP_BACKOFF_CAP),
            MQ_BOOTSTRAP_BACKOFF_CAP,
            "backoff must saturate at the cap"
        );
        assert_eq!(
            backoff_for_attempt(30, Duration::from_secs(3)),
            Duration::from_secs(3),
            "a smaller cap must win"
        );
    }

    /// fake attempt：计数 open/close，前 `failures` 次 open 失败（owned 资源
    /// 模拟为计数，不持有真实连接）。
    struct FakeMqAttempt {
        failures: u32,
        opens: u32,
        closes: u32,
        leaked: bool,
    }

    impl FakeMqAttempt {
        fn new(failures: u32) -> Self {
            Self {
                failures,
                opens: 0,
                closes: 0,
                leaked: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl MqConnectionAttempt for FakeMqAttempt {
        type Runtime = ();

        async fn open(&mut self) -> Result<(), String> {
            self.opens = self.opens.saturating_add(1);
            self.leaked = true; // open 即视为持有 owned 资源
            if self.opens <= self.failures {
                Err(format!("open failed (attempt {})", self.opens))
            } else {
                Ok(())
            }
        }

        async fn close_owned(&mut self, _reason: &str) {
            self.closes = self.closes.saturating_add(1);
            self.leaked = false;
        }
    }

    #[tokio::test]
    async fn bounded_bootstrap_success_after_failures_never_leaks_owned_connection() {
        // 成功前失败两次：close 必须恰好等于失败次数，且成功时不再 close。
        let (result, report) = {
            // helper 消费 attempt；为观察计数，用共享计数器包裹一层。
            let opens = Arc::new(AtomicU64::new(0));
            let closes = Arc::new(AtomicU64::new(0));
            struct Shared {
                inner: FakeMqAttempt,
                opens: Arc<AtomicU64>,
                closes: Arc<AtomicU64>,
            }
            #[async_trait::async_trait]
            impl MqConnectionAttempt for Shared {
                type Runtime = ();
                async fn open(&mut self) -> Result<(), String> {
                    self.opens.fetch_add(1, Ordering::SeqCst);
                    self.inner.open().await
                }
                async fn close_owned(&mut self, reason: &str) {
                    self.closes.fetch_add(1, Ordering::SeqCst);
                    self.inner.close_owned(reason).await;
                }
            }
            let inner = FakeMqAttempt::new(2);
            let shared = Shared {
                inner,
                opens: opens.clone(),
                closes: closes.clone(),
            };
            let result = bootstrap_mq_with_bounded_retry(
                shared,
                MQ_BOOTSTRAP_MAX_ATTEMPTS,
                Duration::from_millis(1),
            )
            .await;
            (
                result,
                (opens.load(Ordering::SeqCst), closes.load(Ordering::SeqCst)),
            )
        };
        assert!(result.is_ok());
        assert_eq!(
            report,
            (3, 2),
            "3 opens, exactly one close per failed attempt"
        );
    }

    #[tokio::test]
    async fn bounded_bootstrap_exhaustion_closes_every_owned_attempt() {
        let opens = Arc::new(AtomicU64::new(0));
        let closes = Arc::new(AtomicU64::new(0));
        struct AlwaysFail {
            opens: Arc<AtomicU64>,
            closes: Arc<AtomicU64>,
        }
        #[async_trait::async_trait]
        impl MqConnectionAttempt for AlwaysFail {
            type Runtime = ();
            async fn open(&mut self) -> Result<(), String> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                Err("broker unreachable".to_owned())
            }
            async fn close_owned(&mut self, _reason: &str) {
                self.closes.fetch_add(1, Ordering::SeqCst);
            }
        }
        let result = bootstrap_mq_with_bounded_retry(
            AlwaysFail {
                opens: opens.clone(),
                closes: closes.clone(),
            },
            3,
            Duration::from_millis(1),
        )
        .await;
        assert!(result.is_err());
        assert!(result.err().unwrap().contains("3 bounded attempts"));
        assert_eq!(opens.load(Ordering::SeqCst), 3);
        assert_eq!(
            closes.load(Ordering::SeqCst),
            3,
            "every failed attempt must close its owned connection"
        );
    }

    #[test]
    fn channel_liveness_tracks_actual_checked_conn_and_fresh_heartbeat() {
        let liveness = ChannelLiveness::new();
        assert!(!liveness.conn_alive(), "starts unproven");
        assert!(
            !liveness.heartbeat_fresh(monotonic_millis()),
            "no heartbeat yet"
        );

        liveness.mark_alive();
        assert!(liveness.conn_alive());
        assert!(
            !liveness.heartbeat_fresh(monotonic_millis()),
            "alive without a fresh heartbeat must not read as fully alive"
        );

        let sent = monotonic_millis();
        liveness.record_heartbeat(sent);
        assert!(liveness.heartbeat_fresh(sent + FRESH_HEARTBEAT_WINDOW_MS));
        assert!(
            !liveness.heartbeat_fresh(sent + FRESH_HEARTBEAT_WINDOW_MS + 1),
            "beyond the fresh window the heartbeat is stale"
        );
        liveness.record_heartbeat(sent.saturating_sub(100));
        assert!(
            liveness.heartbeat_fresh(sent + FRESH_HEARTBEAT_WINDOW_MS),
            "older heartbeats must never roll the monotonic max backwards"
        );

        liveness.mark_dead();
        assert!(!liveness.conn_alive());
    }

    #[test]
    fn healthy_local_owners_observe_without_database_reconciliation() {
        assert_eq!(
            supervisor_tick_for_transport(true, false, true),
            SupervisorAction::Observe
        );
        assert_eq!(
            supervisor_tick_for_transport(true, true, true),
            SupervisorAction::Reconcile
        );
        assert_eq!(
            supervisor_tick_for_transport(false, false, true),
            SupervisorAction::MarkSuspect
        );
        assert_eq!(
            supervisor_tick_for_transport(false, true, true),
            SupervisorAction::HoldSuspect
        );
        for suspect in [false, true] {
            assert_eq!(
                supervisor_tick_for_transport(true, suspect, false),
                SupervisorAction::Reconcile
            );
        }
    }

    #[test]
    fn rabbit_supervisor_reconciles_every_alive_tick() {
        // suspect + alive/fresh → durable reconcile 是唯一清门路径。
        assert_eq!(supervisor_tick(true, true), SupervisorAction::Reconcile);
        // 连接关闭/心跳缺失：保持 suspect，绝不 reconcile。
        assert_eq!(supervisor_tick(false, true), SupervisorAction::HoldSuspect);
        // 健康且活跃：同样执行 durable 全量对账——水位对账是必要的漏通知
        // DB 兜底，不是正常消息热路径。
        assert_eq!(supervisor_tick(true, false), SupervisorAction::Reconcile);
        // 健康但活跃度丢失：主动拉起 suspect（fail-closed）。
        assert_eq!(supervisor_tick(false, false), SupervisorAction::MarkSuspect);
    }

    #[test]
    fn reconcile_deferral_classification_only_covers_hub_transient_deferrals() {
        // hub 的两类正常暂缓：写负载下常见，不是健康信号，下一 tick 重试。
        assert!(is_reconcile_deferral(
            "source transaction is active; reconciliation deferred"
        ));
        assert!(is_reconcile_deferral(
            "memory mutation raced durable reconciliation"
        ));
        // 其余失败一律视为异常 → supervisor 拉起 suspect（fail-closed）。
        assert!(!is_reconcile_deferral(
            "memory projection hub lock poisoned"
        ));
        assert!(!is_reconcile_deferral(
            "unknown source commit has no event proof for online recovery"
        ));
        assert!(!is_reconcile_deferral(
            "incomplete reconciled memory mirror"
        ));
        assert!(!is_reconcile_deferral(""));
    }

    #[tokio::test]
    async fn listener_raises_suspect_and_heartbeat_never_clears_it() {
        let hub = MemoryProjectionHub::default();
        let liveness = ChannelLiveness::new();
        let listener = HubFanoutHealthListener::new(hub.clone(), liveness.clone());
        let identity = NodeIdentity::try_from_parts("city-a", "node-1").unwrap();

        assert!(
            !hub.channel_is_suspect(),
            "a fresh hub starts Unmonitored (not blocking)"
        );

        listener
            .on_channel_suspect(&identity, "consume stream ended")
            .await;
        assert!(
            hub.channel_is_suspect(),
            "suspect is raised by the only authorized hook"
        );
        assert!(
            !liveness.conn_alive(),
            "channel loss marks the owned conn dead"
        );

        liveness.mark_alive();
        liveness.record_heartbeat(monotonic_millis());
        listener
            .on_heartbeat_alive(
                &identity,
                &HeartbeatScope {
                    node_region: "city-a".to_owned(),
                    node_id: "node-1".to_owned(),
                    sent_at: "2026-10-01T00:00:00Z".to_owned(),
                },
            )
            .await;
        assert!(
            hub.channel_is_suspect(),
            "a heartbeat is monotonic liveness only; it must never clear suspect"
        );
        assert!(
            liveness.heartbeat_fresh(monotonic_millis()),
            "heartbeat must be recorded for the supervisor freshness gate"
        );
    }

    #[tokio::test]
    async fn listener_treats_scope_gap_as_strict_suspect_signal() {
        let hub = MemoryProjectionHub::default();
        let liveness = ChannelLiveness::new();
        let listener = HubFanoutHealthListener::new(hub.clone(), liveness.clone());
        let identity = NodeIdentity::try_from_parts("city-a", "node-1").unwrap();
        let report = ScopeGapReport {
            ordering_key: "tenant-7|USER_CARD|42|card-42".to_owned(),
            observed_created_at: "2026-10-01T00:00:00Z".to_owned(),
            observed_message_id: "m-1".to_owned(),
            observed_payload_sha256: "deadbeef".to_owned(),
            has_pending_earlier: true,
            scope_regressed: false,
        };
        listener.on_scope_gap(&identity, &report).await;
        assert!(
            hub.channel_is_suspect(),
            "scope gaps are suspect-grade; they must surface to the strict read path"
        );
    }

    #[test]
    fn status_snapshot_reports_not_started_without_members() {
        let runtime = InvalidationFanoutRuntime { members: None };
        let status = runtime.status(monotonic_millis());
        assert!(!status.started);
        assert_eq!(status.transport, "none");
        assert!(!status.relay_active && !status.inbox_active);
    }

    // ── source guards：runtime.rs 必须保持接线契约（行尾归一化 + 截掉测试
    // 模块，与 runtime.rs 既有守卫的 production_source 约定一致）──

    fn runtime_source() -> &'static str {
        static NORMALIZED: OnceLock<String> = OnceLock::new();
        NORMALIZED.get_or_init(|| {
            include_str!("../runtime.rs")
                .replace("\r\n", "\n")
                .split("#[cfg(test)]")
                .next()
                .expect("production source must precede tests")
                .to_string()
        })
    }

    fn runtime_mq_block() -> &'static str {
        static BLOCK: OnceLock<String> = OnceLock::new();
        BLOCK.get_or_init(|| {
            let source = runtime_source();
            let start = source
                .find("let audit_replay_worker: Option<AuditReplayWorkerHandle>")
                .expect("MQ bootstrap block must remain");
            let end = source[start..]
                .find("// 将 /main/api/v1 下的所有路由合并到一个子路由")
                .map(|offset| start + offset)
                .expect("MQ bootstrap block must have a stable end marker");
            source[start..end].to_string()
        })
    }

    #[test]
    fn runtime_uses_durable_idempotency_db_and_bounded_bootstrap() {
        let source = runtime_source();
        let mq_block = runtime_mq_block();
        // DB 幂等后端是默认要求；Redis compat 保持 default-off，新 runtime 禁止回退。
        assert!(source.contains("init_idempotency_db("));
        assert!(
            !source.contains("init_idempotency_redis("),
            "the Redis compat idempotency path must not come back on the runtime"
        );
        // fire-and-forget 无限重试与 pending 永驻 keepalive 任务必须消失
        // （MQ bootstrap 块内；shutdown_signal 的非 unix 分支另有合法 pending）。
        assert!(mq_block.contains("bootstrap_mq_with_bounded_retry("));
        assert!(mq_block.contains("MQ_BOOTSTRAP_MAX_ATTEMPTS"));
        assert!(
            !mq_block.contains("std::future::pending::<()>()"),
            "the pending-forever keepalive task must stay replaced by RAII ownership"
        );
        assert!(
            !source.contains("Keep the connection and channel alive"),
            "the old keepalive-task comment/ownership must not come back"
        );
        assert!(
            !source.contains("retrying with backoff"),
            "the unbounded retry loop must not come back"
        );
        // 未知/失败的连接尝试必须关闭 owned 连接。
        assert!(source.contains("close_owned_connection("));
        assert!(source.contains("MqConnectionAttempt for RabbitMqBootstrapAttempt"));
    }

    #[test]
    fn runtime_freezes_fanout_flag_before_any_worker_and_gates_install() {
        let source = runtime_source();
        assert!(source.contains(ENV_INVALIDATION_FANOUT_ENABLED));
        assert!(source.contains("parse_invalidation_fanout_enabled"));
        let flag_freeze = source
            .find("parse_invalidation_fanout_enabled")
            .expect("fanout flag freeze must remain");
        let db_connect = source
            .find("let db = connect_and_validate_schema_with_pool_options(")
            .expect("DB connect must remain on the startup path");
        assert!(
            flag_freeze < db_connect,
            "the fanout flag must be frozen before any worker can start"
        );
        // 旗标判定恰好两处：NodeIdentity 启动门 + Rabbit 传输分支的 fanout
        // 装配门。Local 传输的 LocalBus supervisor 由 runtime.rs 无条件装配
        //（hub 健康监督是 Local 默认必需品，绝不依赖本旗标——见 runtime.rs
        // 的 local_transport_supervision_is_unconditional 守卫）。
        assert_eq!(
            source.matches("if invalidation_fanout_enabled {").count(),
            2,
            "identity gate + rabbit transport-branch install gate must stay"
        );
        assert!(source.contains("let local_fanout = {"));
        assert!(source.contains("let rabbit_fanout = if invalidation_fanout_enabled {"));
        assert_eq!(
            source.matches("start_invalidation_fanout_runtime(").count(),
            1,
            "the full fanout runtime is only started for the Rabbit branch"
        );
    }

    #[test]
    fn runtime_shuts_fan_down_first_and_rolls_back_on_bootstrap_failure() {
        let source = runtime_source();
        // 正常关闭：fanout 最后启动 → 最先有界关闭（在既有 worker 关闭序列之前）。
        let fanout_shutdown = source
            .find("invalidation_fanout_runtime.take()")
            .expect("normal shutdown must consume the fanout runtime");
        let worker_shutdown = source
            .find("let worker_result = if let Some(worker) = audit_replay_worker")
            .expect("existing worker shutdown sequence must remain");
        assert!(
            fanout_shutdown < worker_shutdown,
            "the fanout runtime started last must shut down first"
        );
        // bootstrap / fanout 启动失败：按启动逆序回滚已启动 worker 后拒绝启动。
        assert!(source.contains("rollback_started_workers_after_mq_bootstrap_failure("));
        assert!(source.contains("MQ_BOOTSTRAP_EXHAUSTED"));
        assert!(source.contains("INVALIDATION_FANOUT_START_FAILED"));
    }
}
