//! 单写者租约运行期监督（writer lease runtime supervision）。
//!
//! `acquire_single_writer_lease` 返回的 `PoolConnection` 由本模块的监督任务
//! 持有到进程结束：启动时在同一连接上捕获初始 `CONNECTION_ID()`，之后每 1
//! 秒在同一连接上执行
//! `SELECT CONNECTION_ID(), IS_USED_LOCK('astral_single_node_writer')`
//!（单次 <= 2 秒超时）。只有"存活连接仍是初始连接，且写者锁持有者仍是该
//! 连接"才允许继续运行；探针失败/超时/锁易主/锁无人持有/连接被更换一律
//! 致命：监督任务立即对全局 hub `mark_channel_suspect(...)` 并通知 main
//! 终止全部服务（有界 join abort）。绝不自动重连、绝不重新拿新租约、绝不
//! 提前释放连接。

use std::time::Duration;

use sqlx::{pool::PoolConnection, MySql};
use tokio::time::MissedTickBehavior;

/// 监督探针间隔：每 1 秒一次。
pub const WRITER_LEASE_PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// 单次探针硬超时：<= 2 秒；超时视为 `ProbeReading::Unknown`（致命）。
pub const WRITER_LEASE_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// 运行期监督探针：与 `SINGLE_NODE_WRITER_LEASE_SQL` 同一把会话级咨询锁。
/// `CAST(... AS SIGNED)` 把结果固定为有符号 BIGINT，保证 `(i64, Option<i64>)`
/// 解码确定（`IS_USED_LOCK` 在无人持锁时返回 NULL）。
pub const WRITER_LEASE_PROBE_SQL: &str = "SELECT CAST(CONNECTION_ID() AS SIGNED), \
     CAST(IS_USED_LOCK('astral_single_node_writer') AS SIGNED)";

/// 启动期初始连接身份查询：必须在租约连接本身上执行。
pub const WRITER_LEASE_CONNECTION_ID_SQL: &str = "SELECT CAST(CONNECTION_ID() AS SIGNED)";

/// 租约获取时锁定的连接身份；后续所有探针必须与它一致才允许存活。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseIdentity {
    pub connection_id: i64,
}

/// 一次探针读数：同一连接上的 `CONNECTION_ID()` 与 `IS_USED_LOCK(...)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseObservation {
    /// 存活连接当前 id；若连接被更换，则与 `LeaseIdentity` 不再一致。
    pub connection_id: i64,
    /// 写者锁当前持有者的连接 id；`None` = 无人持有。
    pub lock_holder: Option<i64>,
}

/// 一次探针的原始结果：确定读数，或因失败/超时无法证明。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeReading {
    Observed(LeaseObservation),
    /// 探针失败或超时：租约状态无法证明，fail-closed。
    Unknown,
}

/// 分类结论。只有 `Held` 允许继续运行；其余全部致命。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseVerdict {
    /// 存活连接未变，且写者锁仍由该连接持有。
    Held,
    /// 写者锁被另一个会话持有：出现第二个写者。
    StolenByOtherSession,
    /// 写者锁无人持有：租约已随连接释放或被服务端清除。
    LockMissing,
    /// 存活连接 id 与初始租约连接不一致：租约身份不可证明。
    ConnectionChanged,
    /// 探针失败或超时：无法证明仍然持有。
    Unknown,
}

impl LeaseVerdict {
    /// 是否致命：除 `Held` 外全部致命，绝不以"未知"续命。
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        !matches!(self, LeaseVerdict::Held)
    }

    /// 审计与 hub suspect 记录使用的原因串。
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            LeaseVerdict::Held => "writer lease held".to_owned(),
            LeaseVerdict::StolenByOtherSession => {
                "writer lock is held by a different session".to_owned()
            }
            LeaseVerdict::LockMissing => "writer lock is not held by anyone".to_owned(),
            LeaseVerdict::ConnectionChanged => {
                "lease connection was replaced; writer identity unprovable".to_owned()
            }
            LeaseVerdict::Unknown => "writer lease probe failed or timed out".to_owned(),
        }
    }
}

/// 纯分类器：把一次探针读数与初始租约身份对照成结论。
///
/// 判定顺序：先看存活连接是否仍是初始连接——连接被更换时无论锁状态如何
/// 一律 `ConnectionChanged`（不同会话上的 `IS_USED_LOCK` 读数无法证明本
/// 会话仍持有租约）；再看锁持有者：等于本连接 id 才是 `Held`，他人持有是
/// `StolenByOtherSession`，无人持有是 `LockMissing`。
#[must_use]
pub fn classify(reading: ProbeReading, identity: LeaseIdentity) -> LeaseVerdict {
    match reading {
        ProbeReading::Unknown => LeaseVerdict::Unknown,
        ProbeReading::Observed(observation) => {
            if observation.connection_id != identity.connection_id {
                return LeaseVerdict::ConnectionChanged;
            }
            match observation.lock_holder {
                Some(holder) if holder == identity.connection_id => LeaseVerdict::Held,
                Some(_) => LeaseVerdict::StolenByOtherSession,
                None => LeaseVerdict::LockMissing,
            }
        }
    }
}

/// 监督器句柄：main 侧用它等待租约丢失。健康期间永远不解析。
pub struct WriterLeaseSupervisor {
    loss_rx: tokio::sync::watch::Receiver<Option<String>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for WriterLeaseSupervisor {
    fn drop(&mut self) {
        if let Some(join) = &self.join {
            join.abort();
        }
    }
}

impl WriterLeaseSupervisor {
    /// 阻塞直到租约被证明丢失（返回原因）。监督任务未发信号就死亡
    /// （panic/abort）同样按致命处理：fail-closed，绝不静默续命。
    pub async fn wait_for_loss(&mut self) -> String {
        loop {
            if let Some(reason) = self.loss_rx.borrow().clone() {
                return reason;
            }
            if self.loss_rx.changed().await.is_err() {
                return "writer lease supervisor stopped without a loss signal".to_owned();
            }
        }
    }

    /// 非阻塞查询当前已确认的丢失原因（测试与状态检查用）。
    #[cfg(test)]
    #[must_use]
    pub fn loss_reason_if_any(&self) -> Option<String> {
        self.loss_rx.borrow().clone()
    }

    #[cfg(test)]
    fn from_receiver(loss_rx: tokio::sync::watch::Receiver<Option<String>>) -> Self {
        Self {
            loss_rx,
            join: None,
        }
    }
}

/// 启动租约监督：在租约连接本身上捕获初始 `CONNECTION_ID()`，随后派生
/// 监督任务并移交连接所有权。连接由监督任务持有到进程结束；返回的监督
/// 句柄交给 main 在预热/readiness/运行循环中等待丢失信号。
pub async fn start_writer_lease_supervisor(
    mut connection: PoolConnection<MySql>,
) -> Result<WriterLeaseSupervisor, sqlx::Error> {
    let (connection_id,): (i64,) = tokio::time::timeout(
        WRITER_LEASE_PROBE_TIMEOUT,
        sqlx::query_as(WRITER_LEASE_CONNECTION_ID_SQL).fetch_one(&mut *connection),
    )
    .await
    .map_err(|_| sqlx::Error::Protocol("writer lease identity probe timed out".to_owned()))??;
    let identity = LeaseIdentity { connection_id };
    let (loss_tx, loss_rx) = tokio::sync::watch::channel(None::<String>);
    let join = tokio::spawn(async move {
        let mut interval = tokio::time::interval(WRITER_LEASE_PROBE_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // interval 的首个 tick 立即完成；跳过它，让第一次真实探针落在
        // 1 秒之后，与"每秒一次"的监督节奏对齐。
        interval.tick().await;
        loop {
            interval.tick().await;
            let reading = probe_lease(&mut connection).await;
            let verdict = classify(reading, identity);
            if !verdict.is_fatal() {
                if let Some(hub) = astral_db::memory_projection_hub::memory_projection_hub() {
                    hub.record_channel_heartbeat();
                }
                continue;
            }
            let reason = format!("single-node writer lease lost: {}", verdict.reason());
            tracing::error!(
                connection_id,
                verdict = ?verdict,
                "single-node writer lease supervision failed; entering fail-closed shutdown"
            );
            // Sticky required-owner failure AT the detection instant, BEFORE
            // the loss signal: lost writer ownership must be permanent for
            // this process (guards/tokens/reconcile refuse until exit), so no
            // source writer can run on and no reconcile tick can clear the
            // gate during the abort window. Ordinary channel-suspect semantics
            // are deliberately NOT used here.
            if let Some(hub) = astral_db::memory_projection_hub::memory_projection_hub() {
                hub.mark_runtime_owner_failed(reason.clone());
            }
            // 通知 main 终止全部服务；接收方已放弃时发送失败也无妨，
            // 进程本身即将退出。
            let _ = loss_tx.send(Some(reason));
            // 致命即终态：永久 park，连接持有到进程结束。绝不重连、
            // 绝不拿新租约、绝不把连接释放回池子给后续实例使用。
            std::future::pending::<()>().await;
        }
    });
    Ok(WriterLeaseSupervisor {
        loss_rx,
        join: Some(join),
    })
}

/// 在租约连接上执行一次有界探针；失败/超时一律 `ProbeReading::Unknown`。
async fn probe_lease(connection: &mut PoolConnection<MySql>) -> ProbeReading {
    let query = sqlx::query_as::<_, (i64, Option<i64>)>(WRITER_LEASE_PROBE_SQL)
        .fetch_one(&mut **connection);
    match tokio::time::timeout(WRITER_LEASE_PROBE_TIMEOUT, query).await {
        Ok(Ok((connection_id, lock_holder))) => ProbeReading::Observed(LeaseObservation {
            connection_id,
            lock_holder,
        }),
        // 查询失败与超时同样不可证明：分类为 Unknown，fail-closed。
        Ok(Err(_)) | Err(_) => ProbeReading::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEASE: LeaseIdentity = LeaseIdentity { connection_id: 42 };

    /// Fatal lease loss must raise the STICKY required-owner failure at the
    /// detection instant (before the loss signal reaches main) — ordinary
    /// channel-suspect semantics would leave source writers able to run and
    /// reconcile ticks able to clear the gate during the abort window.
    #[test]
    fn lease_loss_raises_sticky_runtime_owner_failure_before_signalling() {
        let source = include_str!("writer_lease.rs");
        let fatal_branch = source
            .find("if !verdict.is_fatal()")
            .expect("the fatal branch must exist");
        // Production window only: from the fatal branch up to (and including)
        // the loss signal, so the test module below cannot trip its own
        // assertion.
        let after_fatal = &source[fatal_branch..];
        let signal_rel = after_fatal
            .find("let _ = loss_tx.send(Some(reason));")
            .expect("the loss signal must remain");
        let window = &after_fatal[..signal_rel];
        let sticky = window
            .find("hub.mark_runtime_owner_failed(")
            .expect("fatal lease loss must raise the sticky required-owner failure");
        assert!(
            sticky < signal_rel,
            "the sticky required-owner failure must be raised BEFORE the loss signal"
        );
        assert!(
            !window.contains("mark_channel_suspect"),
            "fatal lease loss must not use ordinary channel-suspect semantics"
        );
    }

    #[test]
    fn matching_connection_and_lock_holder_survives() {
        let verdict = classify(
            ProbeReading::Observed(LeaseObservation {
                connection_id: 42,
                lock_holder: Some(42),
            }),
            LEASE,
        );
        assert_eq!(verdict, LeaseVerdict::Held);
        assert!(!verdict.is_fatal());
    }

    #[test]
    fn lock_held_by_other_session_is_fatal_mismatch() {
        let verdict = classify(
            ProbeReading::Observed(LeaseObservation {
                connection_id: 42,
                lock_holder: Some(99),
            }),
            LEASE,
        );
        assert_eq!(verdict, LeaseVerdict::StolenByOtherSession);
        assert!(verdict.is_fatal());
        assert!(verdict.reason().contains("different session"));
    }

    #[test]
    fn missing_lock_holder_is_fatal() {
        let verdict = classify(
            ProbeReading::Observed(LeaseObservation {
                connection_id: 42,
                lock_holder: None,
            }),
            LEASE,
        );
        assert_eq!(verdict, LeaseVerdict::LockMissing);
        assert!(verdict.is_fatal());
    }

    #[test]
    fn changed_connection_is_fatal_even_if_lock_reports_our_old_id() {
        // 连接被更换后，即使 IS_USED_LOCK 报告的持有者 id 恰好等于初始 id，
        // 也无法证明本会话仍持有租约：监督必须 fail-closed。
        let verdict = classify(
            ProbeReading::Observed(LeaseObservation {
                connection_id: 43,
                lock_holder: Some(42),
            }),
            LEASE,
        );
        assert_eq!(verdict, LeaseVerdict::ConnectionChanged);
        assert!(verdict.is_fatal());
    }

    #[test]
    fn changed_connection_with_foreign_holder_still_classifies_as_connection_changed() {
        let verdict = classify(
            ProbeReading::Observed(LeaseObservation {
                connection_id: 43,
                lock_holder: Some(99),
            }),
            LEASE,
        );
        assert_eq!(verdict, LeaseVerdict::ConnectionChanged);
        assert!(verdict.is_fatal());
    }

    #[test]
    fn unknown_probe_is_fatal() {
        let verdict = classify(ProbeReading::Unknown, LEASE);
        assert_eq!(verdict, LeaseVerdict::Unknown);
        assert!(verdict.is_fatal());
    }

    #[test]
    fn probe_targets_the_same_lease_lock_as_the_acquire_gate() {
        // 监督探针与启动门禁必须命中同一把锁，否则监督的是另一把锁。
        let acquire_sql = astral_db::memory_projection_hub::SINGLE_NODE_WRITER_LEASE_SQL;
        assert!(acquire_sql.contains("astral_single_node_writer"));
        assert!(WRITER_LEASE_PROBE_SQL.contains("astral_single_node_writer"));
    }

    #[tokio::test]
    async fn supervisor_death_without_signal_is_fatal() {
        let (tx, rx) = tokio::sync::watch::channel(None::<String>);
        drop(tx);
        let mut supervisor = WriterLeaseSupervisor::from_receiver(rx);
        let reason = supervisor.wait_for_loss().await;
        assert!(reason.contains("without a loss signal"));
        // 通道内没有可确认的丢失原因；致命结论由监督任务死亡本身推出。
        assert!(supervisor.loss_reason_if_any().is_none());
    }

    #[tokio::test]
    async fn supervisor_reports_loss_reason_once_signalled() {
        let (tx, rx) = tokio::sync::watch::channel(None::<String>);
        let mut supervisor = WriterLeaseSupervisor::from_receiver(rx);
        assert!(supervisor.loss_reason_if_any().is_none());
        tx.send(Some("probe timed out".to_owned()))
            .expect("receiver alive");
        let reason = supervisor.wait_for_loss().await;
        assert_eq!(reason, "probe timed out");
        assert_eq!(
            supervisor.loss_reason_if_any().as_deref(),
            Some("probe timed out")
        );
    }
}
