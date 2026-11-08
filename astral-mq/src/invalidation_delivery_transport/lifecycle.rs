//! Lifecycle supervision and retained ownership for cancelled transport tasks.

use std::collections::HashSet;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::FutureExt;
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{timeout, Instant};

const REAP_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidationTransportLifecycleState {
    Starting,
    Ready,
    Failed(String),
    Stopping,
    Stopped,
}

#[derive(Debug)]
enum TransportReaper {
    Owner {
        component: String,
        join: JoinHandle<()>,
    },
    Connections {
        component: String,
        joins: JoinSet<()>,
    },
}

impl TransportReaper {
    fn poll(&mut self) -> Option<Result<(), String>> {
        match self {
            Self::Owner { component, join } => {
                if !join.is_finished() {
                    return None;
                }
                (&mut *join).now_or_never().map(|result| match result {
                    Ok(()) => Ok(()),
                    Err(error) if error.is_cancelled() => Ok(()),
                    Err(error) => Err(format!("{component} join failed: {error}")),
                })
            }
            Self::Connections { component, joins } => {
                let mut failures = Vec::new();
                while let Some(result) = joins.try_join_next() {
                    if let Err(error) = result {
                        if !error.is_cancelled() {
                            failures.push(format!("{component} connection join failed: {error}"));
                        }
                    }
                }
                if !failures.is_empty() {
                    // Report failures while retaining the remaining connection ownership.
                    return Some(Err(failures.join("; ")));
                }
                joins.is_empty().then_some(Ok(()))
            }
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Owner { join, .. } => join.is_finished(),
            Self::Connections { joins, .. } => joins.is_empty(),
        }
    }
}

#[derive(Debug)]
struct LifecycleSnapshot {
    expected: usize,
    ready: HashSet<&'static str>,
    failed: Option<String>,
    stopping: bool,
    stopped: bool,
    reapers: Vec<TransportReaper>,
    reaper_running: bool,
    reaper_failure: Option<String>,
    shutdown_deadline: Option<Instant>,
}

#[derive(Debug)]
struct LifecycleInner {
    snapshot: Mutex<LifecycleSnapshot>,
    changed: Notify,
}

#[derive(Clone, Debug)]
pub struct InvalidationTransportLifecycle {
    inner: Arc<LifecycleInner>,
}

impl InvalidationTransportLifecycle {
    pub fn new(expected: usize) -> Self {
        Self {
            inner: Arc::new(LifecycleInner {
                snapshot: Mutex::new(LifecycleSnapshot {
                    expected,
                    ready: HashSet::new(),
                    failed: None,
                    stopping: false,
                    stopped: false,
                    reapers: Vec::new(),
                    reaper_running: false,
                    reaper_failure: None,
                    shutdown_deadline: None,
                }),
                changed: Notify::new(),
            }),
        }
    }

    fn lock_snapshot(&self) -> std::sync::MutexGuard<'_, LifecycleSnapshot> {
        match self.inner.snapshot.lock() {
            Ok(snapshot) => snapshot,
            Err(poisoned) => {
                let mut snapshot = poisoned.into_inner();
                if snapshot.failed.is_none() {
                    snapshot.failed =
                        Some("invalidation transport lifecycle mutex poisoned".into());
                    self.inner.changed.notify_waiters();
                }
                snapshot
            }
        }
    }

    pub fn state(&self) -> InvalidationTransportLifecycleState {
        let snapshot = self.lock_snapshot();
        if let Some(reason) = &snapshot.failed {
            InvalidationTransportLifecycleState::Failed(reason.clone())
        } else if snapshot.stopped {
            InvalidationTransportLifecycleState::Stopped
        } else if snapshot.stopping {
            InvalidationTransportLifecycleState::Stopping
        } else if snapshot.ready.len() == snapshot.expected {
            InvalidationTransportLifecycleState::Ready
        } else {
            InvalidationTransportLifecycleState::Starting
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.state(), InvalidationTransportLifecycleState::Ready)
    }

    pub(super) fn mark_ready(&self, component: &'static str) {
        let mut snapshot = self.lock_snapshot();
        if !snapshot.stopping && snapshot.failed.is_none() {
            snapshot.ready.insert(component);
        }
        drop(snapshot);
        self.inner.changed.notify_waiters();
    }

    fn mark_stopped(&self, component: &'static str) {
        if !self.lock_snapshot().stopping {
            self.mark_failed(component, "stopped before shutdown");
        }
    }

    fn mark_failed(&self, component: &'static str, reason: impl Into<String>) {
        let mut snapshot = self.lock_snapshot();
        if snapshot.failed.is_none() {
            snapshot.failed = Some(format!(
                "invalidation transport owner {component} failed: {}",
                reason.into()
            ));
        }
        drop(snapshot);
        self.inner.changed.notify_waiters();
    }

    pub fn begin_shutdown(&self) {
        self.lock_snapshot().stopping = true;
        self.inner.changed.notify_waiters();
    }

    pub(super) fn set_shutdown_deadline(&self, deadline: Instant) {
        let mut snapshot = self.lock_snapshot();
        snapshot.shutdown_deadline = Some(
            snapshot
                .shutdown_deadline
                .map_or(deadline, |old| old.min(deadline)),
        );
    }

    pub(super) fn mark_shutdown_complete(&self) -> Result<(), String> {
        let mut snapshot = self.lock_snapshot();
        let result = if let Some(reason) = snapshot.failed.clone() {
            Err(reason)
        } else if snapshot.reapers.is_empty() && snapshot.reaper_failure.is_none() {
            snapshot.stopped = true;
            Ok(())
        } else {
            let reason = "invalidation transport shutdown completion unknown".to_owned();
            snapshot.failed = Some(reason.clone());
            Err(reason)
        };
        drop(snapshot);
        self.inner.changed.notify_waiters();
        result
    }

    pub(super) fn mark_shutdown_failed(&self, reason: impl Into<String>) {
        let mut snapshot = self.lock_snapshot();
        if snapshot.failed.is_none() {
            snapshot.failed = Some(format!(
                "invalidation transport shutdown failed: {}",
                reason.into()
            ));
        }
        drop(snapshot);
        self.inner.changed.notify_waiters();
    }

    fn retain_reaper(&self, reaper: TransportReaper) {
        let mut snapshot = self.lock_snapshot();
        snapshot.reapers.push(reaper);
        let start = !snapshot.reaper_running;
        snapshot.reaper_running = true;
        drop(snapshot);
        self.inner.changed.notify_waiters();
        if start {
            let lifecycle = self.clone();
            // The registry retains every task handle beyond the caller's deadline. This
            // supervisor only observes aborted tasks; it never repeats their operations.
            tokio::spawn(async move {
                loop {
                    if lifecycle.poll_reapers() {
                        return;
                    }
                    tokio::time::sleep(REAP_POLL_INTERVAL).await;
                }
            });
        }
    }

    fn poll_reapers(&self) -> bool {
        let mut snapshot = self.lock_snapshot();
        let mut failures = Vec::new();
        snapshot.reapers.retain_mut(|reaper| match reaper.poll() {
            Some(Ok(())) => false,
            Some(Err(reason)) => {
                failures.push(reason);
                !reaper.is_empty()
            }
            None => true,
        });
        if snapshot.reaper_failure.is_none() && !failures.is_empty() {
            snapshot.reaper_failure = Some(failures.join("; "));
        }
        let empty = snapshot.reapers.is_empty();
        if empty {
            snapshot.reaper_running = false;
        }
        drop(snapshot);
        self.inner.changed.notify_waiters();
        empty
    }

    pub(super) async fn wait_for_reapers(&self, deadline: Instant) -> Result<(), String> {
        loop {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (empty, failure) = {
                let snapshot = self.lock_snapshot();
                (snapshot.reapers.is_empty(), snapshot.reaper_failure.clone())
            };
            if empty {
                return failure.map_or(Ok(()), Err);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || timeout(remaining, notified).await.is_err() {
                return Err("transport reaper completion unknown; task ownership retained".into());
            }
        }
    }

    pub async fn wait_until_ready(&self, budget: Duration) -> Result<(), String> {
        let deadline = Instant::now() + budget;
        loop {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.state() {
                InvalidationTransportLifecycleState::Ready => return Ok(()),
                InvalidationTransportLifecycleState::Failed(reason) => return Err(reason),
                InvalidationTransportLifecycleState::Stopping
                | InvalidationTransportLifecycleState::Stopped => {
                    return Err("invalidation transport stopped before readiness".into());
                }
                InvalidationTransportLifecycleState::Starting => {}
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || timeout(remaining, notified).await.is_err() {
                return Err("invalidation transport readiness timed out".into());
            }
        }
    }

    pub async fn wait_for_failure(&self) -> String {
        loop {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let InvalidationTransportLifecycleState::Failed(reason) = self.state() {
                return reason;
            }
            notified.await;
        }
    }
}

struct OwnerCompletionGuard {
    lifecycle: InvalidationTransportLifecycle,
    component: &'static str,
    completed: bool,
}

impl Drop for OwnerCompletionGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.lifecycle
                .mark_failed(self.component, "owner task cancelled");
        }
    }
}

pub(super) async fn run_owned_transport_task<F>(
    lifecycle: InvalidationTransportLifecycle,
    component: &'static str,
    task: F,
) where
    F: std::future::Future<Output = Result<(), String>>,
{
    let mut guard = OwnerCompletionGuard {
        lifecycle: lifecycle.clone(),
        component,
        completed: false,
    };
    match AssertUnwindSafe(task).catch_unwind().await {
        Ok(Ok(())) => lifecycle.mark_stopped(component),
        Ok(Err(reason)) => lifecycle.mark_failed(component, reason),
        Err(_) => lifecycle.mark_failed(component, "owner task panicked"),
    }
    guard.completed = true;
}

pub(super) async fn wait_for_transport_join(
    join: &mut Option<JoinHandle<()>>,
    component: &str,
) -> Result<(), String> {
    let Some(handle) = join.as_mut() else {
        return Ok(());
    };
    let result = (&mut *handle).await;
    join.take();
    result.map_err(|error| format!("{component} join failed: {error}"))
}

pub(super) fn retain_transport_join(
    lifecycle: &InvalidationTransportLifecycle,
    component: &str,
    join: JoinHandle<()>,
) {
    join.abort();
    lifecycle.retain_reaper(TransportReaper::Owner {
        component: component.into(),
        join,
    });
}

pub(super) async fn abort_and_reap_transport_join(
    join: &mut Option<JoinHandle<()>>,
    component: &str,
    deadline: Instant,
    lifecycle: &InvalidationTransportLifecycle,
) -> String {
    let Some(handle) = join.take() else {
        return format!("{component} shutdown unknown; join handle unavailable");
    };
    retain_transport_join(lifecycle, component, handle);
    match lifecycle.wait_for_reapers(deadline).await {
        Ok(()) => format!("{component} shutdown timed out; task aborted and reaped"),
        Err(reason) => format!("{component} shutdown unknown; {reason}"),
    }
}

pub(super) struct MtlsConnectionsGuard {
    lifecycle: InvalidationTransportLifecycle,
    connections: Option<JoinSet<()>>,
}

impl MtlsConnectionsGuard {
    pub(super) fn new(lifecycle: InvalidationTransportLifecycle) -> Self {
        Self {
            lifecycle,
            connections: Some(JoinSet::new()),
        }
    }

    pub(super) fn finish(mut self) -> JoinSet<()> {
        self.connections
            .take()
            .expect("connection set remains owned")
    }
}

impl std::ops::Deref for MtlsConnectionsGuard {
    type Target = JoinSet<()>;
    fn deref(&self) -> &Self::Target {
        self.connections
            .as_ref()
            .expect("connection set remains owned")
    }
}
impl std::ops::DerefMut for MtlsConnectionsGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.connections
            .as_mut()
            .expect("connection set remains owned")
    }
}
impl Drop for MtlsConnectionsGuard {
    fn drop(&mut self) {
        if let Some(mut joins) = self.connections.take() {
            if !joins.is_empty() {
                joins.abort_all();
                self.lifecycle.retain_reaper(TransportReaper::Connections {
                    component: "mTLS receiver".into(),
                    joins,
                });
            }
        }
    }
}

pub(super) async fn drain_mtls_connections(
    connections: &mut MtlsConnectionsGuard,
    budget: Duration,
) -> Result<(), String> {
    let deadline = {
        let snapshot = connections.lifecycle.lock_snapshot();
        let local = Instant::now() + budget;
        snapshot
            .shutdown_deadline
            .map_or(local, |shared| shared.min(local))
    };
    let mut failures = Vec::new();
    while !connections.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("mTLS receiver connection drain unknown; ownership retained".into());
        }
        match timeout(remaining, connections.join_next()).await {
            Ok(Some(Ok(()))) => {}
            Ok(Some(Err(error))) if error.is_cancelled() => {}
            Ok(Some(Err(error))) => failures.push(format!("connection task failed: {error}")),
            Ok(None) => break,
            Err(_) => {
                return Err("mTLS receiver connection drain unknown; ownership retained".into())
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[cfg(test)]
mod tests;
