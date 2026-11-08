//! Production lifecycle wiring for durable authority source outcome
//! reconciliation.
//!
//! This module owns the background lifecycle only. The reconciliation body
//! (lease/CAS/generation fence, unknown-outcome stable-identity
//! reconciliation, finite per-row retry) lives in
//! `crate::authority_source_outcome` and is driven through
//! `SqlxAuthorizationFenceProvider::reconcile_source_outcomes`; this module
//! never duplicates it and never adds a generic retry budget of its own. A
//! failed or timed-out cycle is surfaced through logs and the status snapshot;
//! the loop re-ticks at its bounded interval and each new cycle re-proves
//! ownership through the durable CAS lease and generation fence.
//!
//! Lifecycle contract:
//!
//! - One stable run UUID is generated per process task and reused as
//!   `run_instance_id` for every cycle, so two live runs of one worker can
//!   never share a lease.
//! - Bounded work: the production provider independently reconciles source
//!   acknowledgement, publication, eligibility completion, and configuration
//!   completion under distinct status predicates and lease owners. Per-row
//!   leases and attempt limits belong to their respective workers; each cycle
//!   is additionally bounded by
//!   [`SOURCE_OUTCOME_RUN_DEADLINE`]. Exceeding the deadline cancels an
//!   unknown-state cycle: the durable lease stays pending until DB-UTC expiry
//!   and the source mutation is never replayed.
//! - Pacing: cycles are delay-paced by [`SOURCE_OUTCOME_RECONCILE_INTERVAL`]
//!   (sleep between cycles, so a slow cycle never stacks ticks).
//! - Graceful stop/drain: the stop flag is checked at loop top and immediately
//!   after each bounded cycle, so an in-flight cycle always finishes within
//!   its deadline before the loop exits. Dropping the handle aborts (RAII);
//!   an abort that lands inside a cycle is the same unknown-lease state,
//!   never a source replay.
//! - Ownership/death: the handle keeps the task owned (no detached task);
//!   `wait_for_death` surfaces panic and unexpected termination, including an
//!   unexpected clean exit, so composition roots can fail readiness closed.
//! - Fail-closed posture: composition roots spawn this runtime only when the
//!   production fence provider exists. An absent provider keeps the existing
//!   fail-closed behavior and must never be turned into a positive readiness
//!   signal.
//!
//! The same owned cycle runs all four reconciliation stages concurrently;
//! cancellation retains each stage's durable lease and never replays source.
//! Safe abort recovery only considers durable ABORTED tombstones and has a
//! separate bounded budget within the cycle.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use crate::authority_source_outcome::AuthoritySourceOutcomeReconcileReport;
use crate::authorization_fence_repository::SqlxAuthorizationFenceProvider;

/// Delay between reconciliation cycles. Cycles are sleep-paced (delay), not
/// fixed-interval ticks, so a slow cycle never stacks backlog.
pub const SOURCE_OUTCOME_RECONCILE_INTERVAL: Duration = Duration::from_secs(2);

/// Per-cycle deadline. Unknown cancellation inside the deadline leaves the
/// durable lease pending until its DB-UTC expiry and reclaims only through
/// the generation fence; the source is never replayed. Must stay at or below
/// 10 seconds.
pub const SOURCE_OUTCOME_RUN_DEADLINE: Duration = Duration::from_secs(10);

/// Recommended bounded shutdown join deadline for composition roots. It must
/// cover at most one in-flight cycle (<= [`SOURCE_OUTCOME_RUN_DEADLINE`]) plus
/// join overhead.
pub const SOURCE_OUTCOME_SHUTDOWN_JOIN_TIMEOUT: Duration = Duration::from_secs(15);

/// Post-abort re-join bound: an aborted task stops at its next await point,
/// so the re-join is expected to be quick; the bound only caps pathological
/// scheduler stalls.
const ABORT_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Log every Nth consecutive failure after the first, so a persistently
/// unavailable authority/DB cannot flood logs at the 2s cadence.
const CONSECUTIVE_FAILURE_LOG_EVERY: u32 = 15;

/// Immutable lifecycle status snapshot for observability/readiness wiring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySourceOutcomeRuntimeStatus {
    /// Stable per-process-task run UUID used as the reconciler lease
    /// correlation id.
    pub run_instance_id: String,
    pub running: bool,
    pub cycles_started: u64,
    pub cycles_completed: u64,
    pub consecutive_failures: u32,
    pub last_report: Option<AuthoritySourceOutcomeReconcileReport>,
    pub last_error: Option<String>,
}

#[derive(Debug)]
struct RuntimeStatusMutable {
    running: bool,
    cycles_started: u64,
    cycles_completed: u64,
    consecutive_failures: u32,
    last_report: Option<AuthoritySourceOutcomeReconcileReport>,
    last_error: Option<String>,
}

#[derive(Debug)]
struct RuntimeStatusShared {
    run_instance_id: String,
    mutable: Mutex<RuntimeStatusMutable>,
}

impl RuntimeStatusShared {
    fn new(run_instance_id: String) -> Self {
        Self {
            run_instance_id,
            mutable: Mutex::new(RuntimeStatusMutable {
                running: true,
                cycles_started: 0,
                cycles_completed: 0,
                consecutive_failures: 0,
                last_report: None,
                last_error: None,
            }),
        }
    }

    fn begin_cycle(&self) {
        if let Ok(mut mutable) = self.mutable.lock() {
            mutable.cycles_started += 1;
        }
    }

    fn complete_cycle_ok(&self, report: AuthoritySourceOutcomeReconcileReport) {
        if let Ok(mut mutable) = self.mutable.lock() {
            mutable.cycles_completed += 1;
            mutable.consecutive_failures = 0;
            mutable.last_report = Some(report);
            mutable.last_error = None;
        }
    }

    /// Returns the new consecutive failure count for bounded logging.
    fn complete_cycle_error(&self, error: &str) -> u32 {
        self.mutable
            .lock()
            .map(|mut mutable| {
                mutable.consecutive_failures = mutable.consecutive_failures.saturating_add(1);
                mutable.last_error = Some(error.to_owned());
                mutable.consecutive_failures
            })
            .unwrap_or(0)
    }

    fn mark_stopped(&self) {
        if let Ok(mut mutable) = self.mutable.lock() {
            mutable.running = false;
        }
    }

    fn snapshot(&self) -> AuthoritySourceOutcomeRuntimeStatus {
        self.mutable
            .lock()
            .map(|mutable| AuthoritySourceOutcomeRuntimeStatus {
                run_instance_id: self.run_instance_id.clone(),
                running: mutable.running,
                cycles_started: mutable.cycles_started,
                cycles_completed: mutable.cycles_completed,
                consecutive_failures: mutable.consecutive_failures,
                last_report: mutable.last_report,
                last_error: mutable.last_error.clone(),
            })
            .unwrap_or_else(|_| AuthoritySourceOutcomeRuntimeStatus {
                run_instance_id: self.run_instance_id.clone(),
                running: false,
                cycles_started: 0,
                cycles_completed: 0,
                consecutive_failures: 0,
                last_report: None,
                last_error: Some("authority source outcome runtime status lock poisoned".into()),
            })
    }
}

/// Owned runtime handle: cooperative stop, bounded graceful shutdown, and an
/// observable death signal. `Drop` requests shutdown and aborts the task so a
/// dropped owner can never leave a detached worker behind.
pub struct AuthoritySourceOutcomeRuntimeHandle {
    stop: watch::Sender<bool>,
    join: Option<tokio::task::JoinHandle<Result<(), String>>>,
    status: Arc<RuntimeStatusShared>,
    terminal_result: Option<Result<(), String>>,
}

impl AuthoritySourceOutcomeRuntimeHandle {
    /// Request cooperative shutdown. The owner must still call `shutdown` to
    /// observe the terminal result.
    pub fn request_shutdown(&self) {
        let _ = self.stop.send(true);
    }

    /// Current lifecycle status snapshot.
    pub fn status(&self) -> AuthoritySourceOutcomeRuntimeStatus {
        self.status.snapshot()
    }

    /// Wait for the owned task to terminate unexpectedly (panic, an abort by
    /// an external owner, or an unexpected clean exit) and surface the
    /// terminal reason. The result is cached so `shutdown` does not join the
    /// completed task a second time.
    pub async fn wait_for_death(&mut self) -> String {
        let Some(join) = self.join.as_mut() else {
            return "authority source outcome runtime task handle unavailable".into();
        };
        let result = match (&mut *join).await {
            Ok(result) => result,
            Err(error) => Err(format!(
                "authority source outcome runtime task failed: {error}"
            )),
        };
        let reason = result.as_ref().err().cloned().unwrap_or_else(|| {
            "authority source outcome runtime reached an unexpected clean \
                 termination (no fatal error reported)"
                .into()
        });
        self.terminal_result = Some(result);
        self.join.take();
        reason
    }

    /// Stop and join the runtime within `deadline`. An in-flight cycle is
    /// deadline-bounded (<= [`SOURCE_OUTCOME_RUN_DEADLINE`]) and always drains
    /// before exit; a timeout aborts the task, which leaves any interrupted
    /// cycle in the documented unknown-leased state. Panics and join failures
    /// are reported, never silent.
    pub async fn shutdown(mut self, deadline: Duration) -> Result<(), String> {
        self.request_shutdown();
        if let Some(result) = self.terminal_result.take() {
            return result;
        }
        let Some(join) = self.join.as_mut() else {
            return Ok(());
        };
        match tokio::time::timeout(deadline, &mut *join).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(format!(
                "authority source outcome runtime task failed during shutdown: {error}"
            )),
            Err(_) => {
                join.abort();
                match tokio::time::timeout(ABORT_JOIN_TIMEOUT, &mut *join).await {
                    Ok(Err(error)) if error.is_cancelled() => {
                        Err("authority source outcome runtime shutdown timed out; an \
                         interrupted cycle stays in the unknown-leased state until \
                         DB-UTC lease expiry"
                            .into())
                    }
                    Ok(Ok(Ok(()))) => Err(
                        "authority source outcome runtime shutdown timed out before \
                         the deadline-bounded cycle drained"
                            .into(),
                    ),
                    Ok(Ok(Err(error))) => Err(format!(
                        "authority source outcome runtime shutdown timed out; \
                         drain failed: {error}"
                    )),
                    Ok(Err(error)) => Err(format!(
                        "authority source outcome runtime shutdown timed out and \
                         join failed: {error}"
                    )),
                    Err(_) => Err("authority source outcome runtime abort did not join; task \
                         outcome unknown"
                        .into()),
                }
            }
        }
    }
}

impl Drop for AuthoritySourceOutcomeRuntimeHandle {
    fn drop(&mut self) {
        self.request_shutdown();
        if let Some(join) = self.join.take() {
            // Do not let dropping the owner turn its worker into a detached
            // task. An abort that lands inside a cycle leaves the durable
            // lease pending (unknown state) — never a source replay.
            join.abort();
        }
    }
}

/// Start the reconciliation runtime under an explicit owner. Composition roots
/// call this only when the production fence provider exists; an absent
/// provider must keep the existing fail-closed behavior (no runtime, no
/// positive readiness signal). Keep the handle alive and call `shutdown` in
/// the owner's shutdown tail.
pub fn spawn_authority_source_outcome_runtime(
    provider: Arc<SqlxAuthorizationFenceProvider>,
) -> AuthoritySourceOutcomeRuntimeHandle {
    let run_instance_id = uuid::Uuid::new_v4().to_string();
    let (stop, stop_rx) = watch::channel(false);
    let status = Arc::new(RuntimeStatusShared::new(run_instance_id));
    let task_status = Arc::clone(&status);
    let task_run_instance_id = status.run_instance_id.clone();
    let join = tokio::spawn(run_source_outcome_runtime(
        provider,
        stop_rx,
        task_status,
        task_run_instance_id,
    ));
    AuthoritySourceOutcomeRuntimeHandle {
        stop,
        join: Some(join),
        status,
        terminal_result: None,
    }
}

async fn run_source_outcome_runtime(
    provider: Arc<SqlxAuthorizationFenceProvider>,
    mut stop: watch::Receiver<bool>,
    status: Arc<RuntimeStatusShared>,
    run_instance_id: String,
) -> Result<(), String> {
    tracing::info!(
        run_instance_id = %run_instance_id,
        "authority source outcome reconciliation runtime started"
    );
    loop {
        if *stop.borrow() {
            break;
        }
        status.begin_cycle();
        let cycle = run_source_outcome_cycle(&provider, &run_instance_id).await;
        match cycle {
            Ok(report) => {
                status.complete_cycle_ok(report);
                if report.leased > 0 {
                    tracing::info!(
                        run_instance_id = %run_instance_id,
                        leased = report.leased,
                        marked_committed = report.marked_committed,
                        confirmed_committed = report.confirmed_committed,
                        retried_after_unknown = report.retried_after_unknown,
                        stayed_pending = report.stayed_pending,
                        quarantined = report.quarantined,
                        skipped = report.skipped,
                        "authority source outcome reconciliation cycle processed work"
                    );
                } else {
                    tracing::debug!(
                        run_instance_id = %run_instance_id,
                        "authority source outcome reconciliation cycle found no \
                         pending outcomes"
                    );
                }
            }
            Err(error) => {
                let consecutive = status.complete_cycle_error(&error);
                if consecutive == 1 || consecutive.is_multiple_of(CONSECUTIVE_FAILURE_LOG_EVERY) {
                    tracing::error!(
                        error_code = "AUTHORITY_SOURCE_OUTCOME_RECONCILE_FAILED",
                        run_instance_id = %run_instance_id,
                        consecutive_failures = consecutive,
                        error = %error,
                        "authority source outcome reconciliation cycle failed; \
                         durable leases stay pending and the source is never replayed"
                    );
                }
            }
        }
        // Drain check immediately after the bounded cycle: a shutdown request
        // never waits an extra interval behind an already-finished cycle.
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(SOURCE_OUTCOME_RECONCILE_INTERVAL) => {}
        }
    }
    status.mark_stopped();
    tracing::info!(
        run_instance_id = %run_instance_id,
        "authority source outcome reconciliation runtime stopped"
    );
    Ok(())
}

/// One deadline-bounded reconciliation cycle. The reconcile body (SQL lease,
/// CAS/generation fence, finite unknown-outcome retry) lives in the source
/// outcome owner behind the provider; this wrapper only enforces the cycle
/// deadline so an unknown cancellation always resolves to the durable
/// lease-pending state — the source mutation is never replayed.
///
/// The provider independently reconciles publication, eligibility completion,
/// and configuration completion alongside source acknowledgement. Cancellation
/// preserves the durable leases of all four stages.
async fn run_source_outcome_cycle(
    provider: &SqlxAuthorizationFenceProvider,
    run_instance_id: &str,
) -> Result<AuthoritySourceOutcomeReconcileReport, String> {
    match tokio::time::timeout(
        SOURCE_OUTCOME_RUN_DEADLINE,
        provider.reconcile_source_outcomes(run_instance_id),
    )
    .await
    {
        Ok(result) => result
            .map_err(|error| format!("authority source outcome reconciliation failed: {error}")),
        Err(_elapsed) => Err(format!(
            "authority source outcome reconciliation cycle exceeded the \
             {SOURCE_OUTCOME_RUN_DEADLINE:?} deadline; the interrupted cycle \
             stays in the unknown-leased state until DB-UTC lease expiry"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn lazy_provider() -> Arc<SqlxAuthorizationFenceProvider> {
        // Library-default MySqlConnectOptions through a lazy pool: no
        // credentials, host string or connection string are hardcoded. This
        // test is not external dependency verification — the provider built
        // here has no quorum authority, so every cycle fails fast at the
        // provider boundary BEFORE any SQL is issued, exercising exactly the
        // non-fatal cycle error path under test.
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .acquire_timeout(Duration::from_millis(50))
            .connect_lazy_with(sqlx::mysql::MySqlConnectOptions::new());
        let signing_key = SigningKey::from_bytes(&[87_u8; 32]);
        let trust_root = crate::authorization_fence_repository::AuthorizationTrustRoot::new(
            "authority".to_owned(),
            "key-1".to_owned(),
            1,
            signing_key.verifying_key(),
        )
        .expect("trust root");
        let provider = SqlxAuthorizationFenceProvider::new(pool, trust_root).expect("provider");
        Arc::new(provider)
    }

    #[test]
    fn lifecycle_bounds_stay_bounded() {
        assert_eq!(SOURCE_OUTCOME_RECONCILE_INTERVAL, Duration::from_secs(2));
        assert!(
            SOURCE_OUTCOME_RUN_DEADLINE <= Duration::from_secs(10),
            "the cycle deadline must stay at or below 10 seconds"
        );
        assert!(SOURCE_OUTCOME_SHUTDOWN_JOIN_TIMEOUT >= SOURCE_OUTCOME_RUN_DEADLINE);
    }

    #[tokio::test]
    async fn cycle_errors_do_not_kill_the_loop_and_shutdown_drains() {
        let handle = spawn_authority_source_outcome_runtime(lazy_provider());
        assert!(handle.status().running);
        let mut waited_ms = 0_u64;
        while handle.status().consecutive_failures == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            waited_ms += 50;
            assert!(
                waited_ms <= 5_000,
                "runtime did not surface the first cycle failure in time"
            );
        }
        let status = handle.status();
        assert!(
            status
                .last_error
                .as_deref()
                .unwrap_or_default()
                .contains("quorum"),
            "unexpected first error: {:?}",
            status.last_error
        );
        assert!(status.last_report.is_none());
        assert!(status.cycles_completed == 0);
        handle.request_shutdown();
        let result = handle.shutdown(Duration::from_secs(15)).await;
        assert!(
            result.is_ok(),
            "graceful shutdown must drain cleanly: {result:?}"
        );
    }

    #[tokio::test]
    async fn wait_for_death_surfaces_unexpected_clean_termination() {
        let mut handle = spawn_authority_source_outcome_runtime(lazy_provider());
        handle.request_shutdown();
        let reason = tokio::time::timeout(Duration::from_secs(15), handle.wait_for_death())
            .await
            .expect("death observed in time");
        assert!(
            reason.contains("unexpected clean termination"),
            "unexpected death reason: {reason}"
        );
    }
}
