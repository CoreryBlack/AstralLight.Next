//! In-process local projection worker (single-node composition path).
//!
//! # Pipeline contract
//!
//! ```text
//! source tx commit (source wrapper)
//!   └─ astral_db::dispatch_committed_projection_delta(request)   [bounded bus]
//!        └─ LOCAL WORKER recv → acknowledge
//!             └─ claim_event_by_dispatch (ONE DB tx: durable CAS lease install
//!                 + field-by-field payload binding; SUCCEEDED/QUARANTINED skip;
//!                 Busy/InDoubt never replay)
//!                  └─ process_verified_claim (same pure decide pipeline as the
//!                      DB-poll worker: observe → ledger → pure decide →
//!                      single-transaction durable publish)
//!                       └─ mirror advance from the PROVEN publish outcome
//! ```
//!
//! # Scope mirror (planning hints, never proofs)
//!
//! [`ScopePlanMirror`] keeps bounded per-scope planning state so a normal
//! delta compiles WITHOUT per-event DB reads:
//!
//! - **Frontier**: after each DURABLE publish (commit-proven outcome), the
//!   frontier advances in memory from the [`DeltaProjectorPublishOutcome`]'s
//!   strictly verified `published_state` (pointer read back inside the publish
//!   transaction) plus the claimed event's provenance. No raw facts are
//!   invented; every field traces to the durable outcome or the payload-bound
//!   claim.
//! - **Scope ledger**: the ledger row of a published event is appended from
//!   the published state's verified segments (the tombstone-inclusive
//!   canonical grant content the publish transaction itself verified). If the
//!   grant is absent or its revision drifts, the scope is POISONED: the mirror
//!   drops it and the next event re-establishes a strict cold baseline.
//!
//! Any uncertainty is fail-closed by construction: a poisoned/missing scope
//! falls back to the strict cold DB reads (`observe_publication_context` +
//! `load_scope_ledger`) exactly like the DB-poll worker, and the durable
//! publish transaction re-verifies pointers, fences, lineage and counters
//! regardless of what the mirror claimed. Per-grant versions and aggregate
//! generations are never compared across domains.
//!
//! # Recovery
//!
//! The Rabbit/DB-poll worker stays unchanged for multi-node deployments. A
//! low-frequency recovery pass (default 15s) re-claims queue-side events the
//! bus may have missed (overflow / rejected dispatch — e.g. a missed ADD
//! receipt) through the SAME verified pipeline; only deltas the durable claim
//! predicates prove claimable are recovered, and mirror provenance gaps
//! compile from strict cold reads.
//!
//! # Liveness supervision (worker-supervision-20261002)
//!
//! The worker task is owned by [`supervise_local_projection_worker`]: an
//! unexpected exit (panic, abort, or a bus close that no shutdown requested)
//! is recorded into the process-global [`WorkerLivenessCell`] as
//! [`LocalProjectionWorkerLiveness::Dead`] and raises the memory projection
//! hub's sticky required-owner failure (`mark_runtime_owner_failed`: suspect +
//! positive read caches cleared + every guard/token acquisition and durable
//! reconciliation refuse until process restart). The composite supervisor
//! reads the same cell and stops every service; there is deliberately NO
//! automatic blind restart (an unknown-effect worker restart is strictly worse
//! than a loud, restartable process failure). The liveness flag is explicit
//! and separate from source-writer statistics.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sqlx::MySqlPool;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use astral_db::{
    local_projection_bus, memory_mirror_is_installed, memory_projection_hub,
    take_global_local_projection_receiver, AuthorizationCurrentPointerRecord,
    AuthorizationPublishedState, ClaimedDeltaEvent, ClaimedStableEventOutcome, CommitDeltaEnvelope,
    DeltaEventAppendRequest, DeltaEventClaim, DeltaEventClaimScope, DeltaEventType,
    DeltaLeaseIdentity, DeltaProjectorPublishOutcome, LocalProjectionBus,
    LocalProjectionOwnerTaken, ProjectionAggregateIdentity, PublishedAggregateFrontier,
    PublishedFrontierEvent, PublishedGenerationSummary, RawLedgerRow, STATUS_ACTIVE,
};

use super::authorization_projector::{
    process_verified_claim, AuthorizationProjectorConfig, AuthorizationProjectorHandle,
    AuthorizationProjectorRuntime, ProjectorCancellationToken, ProjectorHealthShared,
    ProjectorProgress, PublicationContext, RepositoryRejection, RuntimeAccessError,
    SqlxAuthorizationProjectorRuntime, WorkerRunSummary,
};

/// Bounded number of scopes the plan mirror keeps. Eviction is
/// insert-ordered (oldest scope dropped first); an evicted scope simply
/// re-establishes a strict cold baseline on its next event.
pub const LOCAL_PROJECTION_MIRROR_MAX_SCOPES: usize = 1024;

/// Mirror ledger growth cap per scope; hitting it poisons the scope (the
/// durable ledger load remains bounded by `MAX_LEDGER_ROWS`, so a scope near
/// that size must not keep an unbounded memory copy).
const MIRROR_MAX_LEDGER_ROWS_PER_SCOPE: usize = 4000;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration / handle
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LocalProjectionWorkerConfig {
    /// Projector policy (lease seconds, deadlines, attempt budgets) reused
    /// verbatim from the DB-poll worker so both paths share one budget shape.
    pub projector: AuthorizationProjectorConfig,
    /// Low-frequency recovery pass interval. The default (15s) keeps
    /// queue-side deltas that missed the bus (overflow / dispatch rejected)
    /// converging: a missed ADD receipt must never be stranded. Only deltas
    /// the durable claim predicates prove claimable are recovered; mirror
    /// provenance gaps compile from strict cold reads.
    pub recovery_poll: Option<Duration>,
    /// Upper bound on events reclaimed per recovery pass.
    pub max_recovery_events_per_pass: usize,
}

/// Default low-frequency recovery cadence (worker-internal; never a hot poll).
pub const LOCAL_PROJECTION_RECOVERY_POLL_DEFAULT: Duration = Duration::from_secs(15);

impl Default for LocalProjectionWorkerConfig {
    fn default() -> Self {
        Self {
            projector: AuthorizationProjectorConfig::default(),
            recovery_poll: Some(LOCAL_PROJECTION_RECOVERY_POLL_DEFAULT),
            max_recovery_events_per_pass: 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalProjectionWorkerStartError {
    /// No bus installed: start the bus before the worker (single-node
    /// composition order), or run the DB-poll projector instead.
    BusNotInstalled,
    /// The single receiver was already taken by another owner.
    ReceiverTaken,
    /// Recovery poll configured below its 1s floor.
    InvalidConfig { reason: String },
}

impl std::fmt::Display for LocalProjectionWorkerStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BusNotInstalled => write!(
                formatter,
                "code=local_projection_worker.bus_not_installed;expected=installed_local_projection_bus"
            ),
            Self::ReceiverTaken => write!(
                formatter,
                "code=local_projection_worker.receiver_taken;expected=single_worker_owner"
            ),
            Self::InvalidConfig { reason } => {
                write!(formatter, "code=local_projection_worker.invalid_config;reason={reason}")
            }
        }
    }
}

impl std::error::Error for LocalProjectionWorkerStartError {}

// ─────────────────────────────────────────────────────────────────────────────
// Worker liveness (worker-supervision-20261002)
// ─────────────────────────────────────────────────────────────────────────────

/// Process-visible liveness of the single-node in-process projection worker.
///
/// `Alive` is set only after the supervised worker task has been spawned; the
/// cell is never demoted from `Dead`. The composite supervisor
/// (`astral-single-node`) reads this state every 250 ms and treats `Dead` as
/// fatal: mark the hub suspect, bounded-abort every service, fail the process.
/// This is the required liveness gate the LocalBus-only reconcile supervisor
/// cannot provide (its `owners_ready()` probe watches the four LocalBus owner
/// channels, never the projection worker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalProjectionWorkerLiveness {
    /// The worker was never started (or its start was rejected before spawn).
    NotStarted,
    /// A supervised worker task is running.
    Alive,
    /// The worker died or its start was terminally rejected. The reason is a
    /// stable diagnostic only (`code=` prefixed), never an authorization
    /// identity; it is safe to log and surface to readiness probes.
    Dead(String),
}

/// Shared liveness cell. Isolated instances exist for pure tests; production
/// reads and writes go through the process-global [`worker_liveness_cell`].
#[derive(Debug, Default)]
pub struct WorkerLivenessCell(Mutex<Option<LocalProjectionWorkerLiveness>>);

impl WorkerLivenessCell {
    /// Record a liveness transition. `Dead` is sticky: a later non-`Dead`
    /// write is refused so nothing inside the same process can resurrect a
    /// declared-dead worker (restarts are process-level by contract).
    pub fn set_liveness(&self, state: LocalProjectionWorkerLiveness) {
        if let Ok(mut slot) = self.0.lock() {
            if matches!(slot.as_ref(), Some(LocalProjectionWorkerLiveness::Dead(_)))
                && !matches!(state, LocalProjectionWorkerLiveness::Dead(_))
            {
                return;
            }
            *slot = Some(state);
        }
    }

    /// Current liveness; `NotStarted` while nothing was recorded yet. A
    /// poisoned lock is reported as an explicit sticky `Dead` (fatal), never
    /// as `NotStarted` — an unreadable required-owner state must fail the
    /// composite closed instead of looking merely "not started yet".
    pub fn liveness(&self) -> LocalProjectionWorkerLiveness {
        match self.0.lock() {
            Ok(slot) => slot
                .clone()
                .unwrap_or(LocalProjectionWorkerLiveness::NotStarted),
            Err(_) => LocalProjectionWorkerLiveness::Dead(
                "code=local_projection_worker.liveness_cell_poisoned".to_owned(),
            ),
        }
    }
}

static WORKER_LIVENESS: WorkerLivenessCell = WorkerLivenessCell(Mutex::new(None));

/// Process-global worker liveness cell (composite supervision entry point).
pub fn worker_liveness_cell() -> &'static WorkerLivenessCell {
    &WORKER_LIVENESS
}

/// Convenience read of the process-global worker liveness state.
pub fn local_projection_worker_liveness() -> LocalProjectionWorkerLiveness {
    worker_liveness_cell().liveness()
}

/// Terminal start failure recording: publish `Dead` globally and fail the
/// memory read face closed immediately, so a rejected start (e.g. the
/// empty-tenant-scope contract) is a loud composite-level startup failure
/// instead of a process serving strict-DB reads with no projection owner.
pub fn record_local_worker_start_failure(reason: &str) {
    let full = format!("code=local_projection_worker.start_rejected;reason={reason}");
    worker_liveness_cell().set_liveness(LocalProjectionWorkerLiveness::Dead(full.clone()));
    if let Some(hub) = astral_db::memory_projection_hub() {
        hub.mark_runtime_owner_failed(full.clone());
    }
    tracing::error!(
        reason = %full,
        "local projection worker start rejected terminally; sticky required-owner failure \
         and composite liveness Dead (no DB-poll fallback, no silent disable)"
    );
}

/// The single-node empty-tenant-scope contract: the recovery pass iterates the
/// configured tenant scopes, so an empty list must be REJECTED at start, never
/// silently disabled (a crashed/overflowed delta would then never converge).
/// Pure so the contract stays unit-testable without a database.
fn validate_recovery_scope(tenants: &[i64]) -> Result<(), LocalProjectionWorkerStartError> {
    if tenants.is_empty() {
        return Err(LocalProjectionWorkerStartError::InvalidConfig {
            reason: "code=local_projection_worker.empty_tenants;expected=\
                     ASTRAL_PROJECTOR_TENANTS;scope=recovery_pass"
                .to_owned(),
        });
    }
    Ok(())
}

/// Death fail-closed actions shared by the supervisor: publish `Dead`, and
/// raise the hub's sticky required-owner failure (`mark_runtime_owner_failed`
/// sets suspect + clears positive read caches and makes every guard/token
/// acquisition and durable reconciliation refuse until process restart). The
/// flag is the explicit required-owner health lever — it deliberately does NOT
/// fabricate a source-writer guard, so liveness stays separate from source
/// statistics. Recovery is restart-only; there is no blind restart here.
fn fail_closed_worker_death(cell: &WorkerLivenessCell, run_id: &str, reason: &str) {
    let full = format!("code=local_projection_worker.died;run_id={run_id};reason={reason}");
    cell.set_liveness(LocalProjectionWorkerLiveness::Dead(full.clone()));
    tracing::error!(
        run_id = %run_id,
        reason = %full,
        "local projection worker died without a shutdown request; sticky required-owner \
         failure raised (restart-only, no blind restart)"
    );
    if let Some(hub) = astral_db::memory_projection_hub() {
        hub.mark_runtime_owner_failed(full.clone());
    }
}

/// Ownership guard for a supervised inner generation: when the supervisor
/// future is dropped for ANY reason (abort, early return), the inner task is
/// aborted instead of silently detaching. Aborting a finished task is a no-op,
/// so the normal paths are unaffected.
struct AbortOnDropJoin<T> {
    join: JoinHandle<T>,
}

impl<T> Drop for AbortOnDropJoin<T> {
    fn drop(&mut self) {
        self.join.abort();
    }
}

/// Supervise one worker generation. Propagates a shutdown-requested exit and
/// converts ANY other exit (panic, abort, unexpected bus close/drain) into a
/// sticky fail-closed death. Never restarts the worker: an unknown-effect
/// restart is forbidden by contract; recovery is a process-level restart.
///
/// `cell` is the liveness cell the death is recorded into; `mirror_to_global`
/// additionally records the death into the process-global cell (production).
/// Tests pass an isolated cell with `mirror_to_global = false` so parallel
/// tests never pollute global state.
fn supervise_local_projection_worker(
    inner: JoinHandle<Result<WorkerRunSummary, String>>,
    shutdown: ProjectorCancellationToken,
    cell: Arc<WorkerLivenessCell>,
    mirror_to_global: bool,
    run_id: String,
) -> impl std::future::Future<Output = Result<WorkerRunSummary, String>> + Send {
    // Take ownership before the returned future can be cancelled unpolled.
    let mut inner = AbortOnDropJoin { join: inner };
    async move {
        tokio::select! {
            _ = shutdown.cancelled() => {
                // Normal shutdown: propagate the inner result; the caller applies
                // its own bounded join timeout.
                match (&mut inner.join).await {
                    Ok(result) => result,
                    Err(join_error) => Err(format!(
                        "code=local_projection_worker.join_failed_on_shutdown;run_id={run_id};error={join_error}"
                    )),
                }
            }
            outcome = &mut inner.join => {
                if shutdown.is_cancelled() {
                    // The cancel raced the exit: treat as a shutdown-requested end.
                    return match outcome {
                        Ok(result) => result,
                        Err(join_error) => Err(format!(
                            "code=local_projection_worker.join_failed_on_shutdown;run_id={run_id};error={join_error}"
                        )),
                    };
                }
                let reason = match outcome {
                    Ok(Ok(_)) => "worker loop exited while no shutdown was requested \
                                  (bus closed/drained unexpectedly)"
                        .to_owned(),
                    Ok(Err(failure)) => format!("worker run failed: {failure}"),
                    Err(join_error) => format!("worker task failed: {join_error}"),
                };
                fail_closed_worker_death(&cell, &run_id, &reason);
                if mirror_to_global {
                    worker_liveness_cell().set_liveness(LocalProjectionWorkerLiveness::Dead(
                        format!("code=local_projection_worker.died;run_id={run_id};sticky_fail_closed"),
                    ));
                }
                // Park holding the fail-closed state until the composite shutdown
                // requests the stop; the composite supervisor aborts all services
                // on the Dead signal well before this await matters. Returning Err
                // after the cancel keeps the existing shutdown report loud about
                // the death instead of a silent clean summary.
                shutdown.cancelled().await;
                Err(format!(
                    "code=local_projection_worker.died;run_id={run_id};sticky_fail_closed"
                ))
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scope plan mirror
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ScopeKey {
    tenant_id: i64,
    aggregate_type: String,
    aggregate_id: i64,
}

impl ScopeKey {
    fn of(identity: &ProjectionAggregateIdentity) -> Self {
        Self {
            tenant_id: identity.tenant_id,
            aggregate_type: identity.aggregate_type.clone(),
            aggregate_id: identity.aggregate_id,
        }
    }
}

/// Per-scope planning state. Every field is a PLANNING HINT derived from
/// durable proofs; the publish transaction re-verifies the world durably.
#[derive(Debug, Clone)]
struct ScopeMirror {
    /// Strict cold-read publication world (or its memory-advanced successor).
    publication: PublicationContext,
    /// Strict cold-read scope ledger (or its proven-successor extension).
    ledger_rows: Arc<Vec<RawLedgerRow>>,
}

/// Provenance result of the claim-time ledger upsert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorRowProvenance {
    /// The claimed event's row is already tracked (nothing to do).
    AlreadyPresent,
    /// The row was upserted from the in-hand commit-proven request with
    /// per-grant continuity proven against the mirror head.
    Upserted,
    /// Continuity or payload derivation could not be proven: the scope was
    /// poisoned and this event compiles from strict cold reads instead.
    StrictFallback,
}

/// Advance report for one durable publish (worker diagnostics only).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MirrorAdvanceReport {
    pub frontier_advanced: bool,
    pub ledger_row_appended: bool,
    /// `true` when the scope could not be advanced from proven facts and was
    /// dropped back to strict cold reads (fail-closed, never a wrong compile).
    pub scope_poisoned: bool,
}

#[derive(Debug, Default)]
struct ScopePlanMirrorInner {
    scopes: HashMap<ScopeKey, ScopeMirror>,
    /// Insert order for bounded eviction (oldest first).
    order: Vec<ScopeKey>,
    /// Publication baselines observed before their ledger half loaded; both
    /// halves are required before a scope becomes mirror-served.
    pending_publications: HashMap<ScopeKey, PublicationContext>,
}

/// Bounded per-scope plan mirror (interior mutability via `Mutex`; the worker
/// task is the only runtime caller, but `Arc<dyn Runtime>` shares `&self`).
#[derive(Debug, Default)]
struct ScopePlanMirror {
    inner: Mutex<ScopePlanMirrorInner>,
}

impl ScopePlanMirror {
    fn get(&self, key: &ScopeKey) -> Option<(PublicationContext, Arc<Vec<RawLedgerRow>>)> {
        let inner = self.inner.lock().ok()?;
        let scope = inner.scopes.get(key)?;
        Some((scope.publication.clone(), Arc::clone(&scope.ledger_rows)))
    }

    fn publication(&self, key: &ScopeKey) -> Option<PublicationContext> {
        self.inner
            .lock()
            .ok()?
            .scopes
            .get(key)
            .map(|scope| scope.publication.clone())
    }

    fn ledger(&self, key: &ScopeKey) -> Option<Arc<Vec<RawLedgerRow>>> {
        self.inner
            .lock()
            .ok()?
            .scopes
            .get(key)
            .map(|scope| Arc::clone(&scope.ledger_rows))
    }

    /// Record the strict cold-read publication world. Seeding completes only
    /// when the ledger half arrives (both baselines are strict reads).
    fn note_publication(
        &self,
        identity: &ProjectionAggregateIdentity,
        publication: PublicationContext,
    ) {
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return,
        };
        let key = ScopeKey::of(identity);
        if let Some(scope) = inner.scopes.get_mut(&key) {
            // Refresh the publication half of an already-seeded scope (e.g.
            // after poisoning it only removes one half... poisoning removes
            // the whole scope, so this arm is a baseline refresh).
            scope.publication = publication;
            return;
        }
        inner.pending_publications.insert(key, publication);
    }

    /// Record the strict cold-read scope ledger; completes the seed when the
    /// publication half is pending.
    fn note_ledger(
        &self,
        identity: &ProjectionAggregateIdentity,
        ledger_rows: impl Into<Arc<Vec<RawLedgerRow>>>,
    ) {
        let ledger_rows = ledger_rows.into();
        if ledger_rows.len() > MIRROR_MAX_LEDGER_ROWS_PER_SCOPE {
            // Oversized scope: refuse to mirror (stay strict) instead of
            // storing an unbounded copy.
            self.poison(identity);
            return;
        }
        let mut inner = match self.inner.lock() {
            Ok(inner) => inner,
            Err(_) => return,
        };
        let key = ScopeKey::of(identity);
        if let Some(scope) = inner.scopes.get_mut(&key) {
            scope.ledger_rows = ledger_rows;
            return;
        }
        let Some(publication) = inner.pending_publications.remove(&key) else {
            return;
        };
        if inner.scopes.len() >= LOCAL_PROJECTION_MIRROR_MAX_SCOPES {
            if let Some(oldest) = inner.order.first().cloned() {
                inner.scopes.remove(&oldest);
                inner.order.remove(0);
            }
        }
        inner.order.push(key.clone());
        inner.scopes.insert(
            key,
            ScopeMirror {
                publication,
                ledger_rows,
            },
        );
    }

    fn poison(&self, identity: &ProjectionAggregateIdentity) {
        if let Ok(mut inner) = self.inner.lock() {
            let key = ScopeKey::of(identity);
            inner.scopes.remove(&key);
            inner.pending_publications.remove(&key);
            inner.order.retain(|existing| existing != &key);
        }
    }

    /// Advance one scope after a PROVEN durable publish.
    ///
    /// `published` is the outcome the publish transaction returned after its
    /// commit was proven; `claimed` supplies the event provenance (grant id,
    /// event type, per-grant version window) that the frontier event carries.
    fn advance(
        &self,
        claimed: &ClaimedDeltaEvent,
        published: &DeltaProjectorPublishOutcome,
    ) -> MirrorAdvanceReport {
        let identity = match ProjectionAggregateIdentity::new(
            claimed.tenant_id,
            claimed.aggregate_type.clone(),
            claimed.aggregate_id,
        ) {
            Ok(identity) => identity,
            Err(_) => {
                return MirrorAdvanceReport {
                    frontier_advanced: false,
                    ledger_row_appended: false,
                    scope_poisoned: true,
                }
            }
        };
        let Some((mut publication, mut ledger_rows)) = self.get(&ScopeKey::of(&identity)) else {
            // Never seeded (strict mode): nothing to advance.
            return MirrorAdvanceReport::default();
        };
        let state = &published.publish.published_state;

        // ── Frontier event: provenance from the payload-bound claim ──
        let frontier_event = PublishedFrontierEvent {
            generation: state.generation,
            // plan_id is a staging-row fact consumed only by durable
            // re-verification; planning treats 0 as "not asserted".
            plan_id: 0,
            event_id: claimed.event_id.clone(),
            operation_id: claimed.operation_id.clone(),
            grant_id: claimed.grant_id,
            event_type: claimed.event_type,
            delta_base_version: claimed.base_version,
            delta_target_version: claimed.target_version,
            source_generation: claimed.source_generation,
            revoke_fence: claimed.revoke_fence,
            semantic_hash: claimed.semantic_hash,
            dependency_hash: claimed.dependency_hash,
            compiler_version: claimed.compiler_version.clone(),
        };

        // ── Ledger row of the published event: canonical grant content as
        //    verified inside the publish transaction's own readback. The
        //    claim-time request-derived upsert (if any) is REPLACED by this
        //    proof-based content; otherwise the row is inserted sorted. ──
        let ledger_row = match published_state_ledger_row(claimed, state) {
            Ok(row) => row,
            Err(reason) => {
                tracing::warn!(
                    event_id = %claimed.event_id,
                    reason = %reason,
                    "scope mirror advance failed; scope reverts to strict cold reads"
                );
                self.poison(&identity);
                return MirrorAdvanceReport {
                    frontier_advanced: false,
                    ledger_row_appended: false,
                    scope_poisoned: true,
                };
            }
        };
        let rows = Arc::make_mut(&mut ledger_rows);
        match rows
            .iter_mut()
            .find(|row| row.event_id == ledger_row.event_id)
        {
            Some(slot) => *slot = ledger_row,
            None => insert_ledger_row_sorted(rows, ledger_row),
        }

        // ── Frontier assembly from the verified published state ──
        let mut events = publication.frontier.events.clone();
        events.push(frontier_event);
        publication.frontier = PublishedAggregateFrontier {
            identity: publication.frontier.identity,
            card_id: publication.frontier.card_id,
            pointer: AuthorizationCurrentPointerRecord {
                pointer_id: state.pointer.pointer_id,
                identity: state.pointer.identity.clone(),
                card_id: state.pointer.card_id,
                current_generation: state.pointer.current_generation,
                manifest_id: state.pointer.manifest_id,
                event_id: state.pointer.event_id.clone(),
                operation_id: state.pointer.operation_id.clone(),
                semantic_hash: state.pointer.semantic_hash,
                dependency_hash: state.pointer.dependency_hash,
                compiler_version: state.pointer.compiler_version.clone(),
                revoke_fence: state.pointer.revoke_fence,
                revoke_fence_proven: state.pointer.revoke_fence_proven,
                cas_version: state.pointer.cas_version,
            },
            manifest: PublishedGenerationSummary {
                manifest_id: state.manifest_id,
                generation: state.generation,
                source_generation: state.source_generation,
                projected_generation: state.projected_generation,
                event_id: state.event_id.clone(),
                operation_id: state.operation_id.clone(),
                semantic_hash: state.semantic_hash,
                dependency_hash: state.dependency_hash,
                compiler_version: state.compiler_version.clone(),
                manifest_digest: state.manifest_digest,
                parent_manifest_id: state.parent_manifest_id,
                revoke_fence: state.revoke_fence,
                card_id: state.pointer.card_id,
            },
            events,
        };
        // Parent reference hints are dropped on advance: staging then plans
        // every segment as New (the documented production reality), which can
        // never falsely reuse a parent row. Digest-based reuse remains
        // available on strict cold reads.
        publication.parent_references = Vec::new();

        let report = MirrorAdvanceReport {
            frontier_advanced: true,
            ledger_row_appended: true,
            scope_poisoned: false,
        };
        if let Ok(mut inner) = self.inner.lock() {
            let key = ScopeKey::of(&identity);
            inner.pending_publications.remove(&key);
            if !inner.order.contains(&key)
                && inner.scopes.len() >= LOCAL_PROJECTION_MIRROR_MAX_SCOPES
            {
                if let Some(oldest) = inner.order.first().cloned() {
                    inner.scopes.remove(&oldest);
                    inner.order.remove(0);
                }
            }
            if !inner.order.contains(&key) {
                inner.order.push(key.clone());
            }
            inner.scopes.insert(
                key,
                ScopeMirror {
                    publication,
                    ledger_rows,
                },
            );
        }
        report
    }

    /// Fail-closed gate for RECOVERY events (no request in hand): the
    /// claimed event's own ledger row must already be tracked. A missing row
    /// poisons the scope so the event compiles from strict cold reads.
    fn ensure_claimed_row_present(&self, claimed: &ClaimedDeltaEvent) -> bool {
        let identity = match ProjectionAggregateIdentity::new(
            claimed.tenant_id,
            claimed.aggregate_type.clone(),
            claimed.aggregate_id,
        ) {
            Ok(identity) => identity,
            Err(_) => return false,
        };
        let Some(ledger_rows) = self.ledger(&ScopeKey::of(&identity)) else {
            // No mirror entry: the caller will strict-read and seed fresh,
            // which includes this event's row by construction.
            return true;
        };
        if ledger_rows
            .iter()
            .any(|row| row.event_id == claimed.event_id)
        {
            return true;
        }
        tracing::info!(
            event_id = %claimed.event_id,
            "claimed event absent from scope mirror provenance; scope reverts to strict cold reads"
        );
        self.poison(&identity);
        false
    }

    /// Claim-time provenance upsert for DIRECT-dispatch events (request in
    /// hand): the claimed event's own ledger row is inserted from the strict
    /// durable source facts the request carries, ONLY while per-grant
    /// continuity against the mirror head is proven:
    ///
    /// - the mirror's last row for the claimed grant must sit exactly at
    ///   `base_version` (grant absent ⇔ `base_version == 0`);
    /// - `Add`/`Update` deltas carry the resulting canonical grant;
    ///   `Remove`/`Revoke` derive it from the digest-verified before-image
    ///   with the terminal state and target revision applied.
    ///
    /// Any drift (base mismatch, absent before-image, non-canonical payload,
    /// revision mismatch) poisons the scope: siblings with PENDING revisions
    /// are repaired by the strict cold read, never by a silent update.
    fn upsert_claimed_row(
        &self,
        request: &DeltaEventAppendRequest,
        claimed: &ClaimedDeltaEvent,
    ) -> MirrorRowProvenance {
        let identity = match ProjectionAggregateIdentity::new(
            claimed.tenant_id,
            claimed.aggregate_type.clone(),
            claimed.aggregate_id,
        ) {
            Ok(identity) => identity,
            Err(_) => return MirrorRowProvenance::StrictFallback,
        };
        let Some(mut ledger_rows) = self.ledger(&ScopeKey::of(&identity)) else {
            // No mirror scope: strict seeding will include this row.
            return MirrorRowProvenance::AlreadyPresent;
        };
        if ledger_rows
            .iter()
            .any(|row| row.event_id == claimed.event_id)
        {
            return MirrorRowProvenance::AlreadyPresent;
        }
        // Per-grant continuity: the mirror head for THIS grant must be the
        // claimed base. A PENDING sibling in between means the mirror cannot
        // prove continuity → strict cold repair.
        let head_revision = ledger_rows
            .iter()
            .filter(|row| row.grant_id == claimed.grant_id.as_str())
            .map(|row| row.revision_no)
            .max();
        let expected_head = if claimed.base_version == 0 {
            None
        } else {
            Some(claimed.base_version)
        };
        if head_revision != expected_head {
            tracing::info!(
                event_id = %claimed.event_id,
                grant_id = %claimed.grant_id,
                mirror_head = ?head_revision,
                claimed_base = claimed.base_version,
                "mirror head does not match the claimed base (pending sibling); \
                 scope reverts to strict cold reads"
            );
            self.poison(&identity);
            return MirrorRowProvenance::StrictFallback;
        }
        let row = match request_derived_ledger_row(request, claimed) {
            Ok(row) => row,
            Err(reason) => {
                tracing::info!(
                    event_id = %claimed.event_id,
                    reason = %reason,
                    "claimed row unprovable from the request; scope reverts to strict cold reads"
                );
                self.poison(&identity);
                return MirrorRowProvenance::StrictFallback;
            }
        };
        insert_ledger_row_sorted(Arc::make_mut(&mut ledger_rows), row);
        if ledger_rows.len() > MIRROR_MAX_LEDGER_ROWS_PER_SCOPE {
            self.poison(&identity);
            return MirrorRowProvenance::StrictFallback;
        }
        // Store the extended ledger back into the scope (publication half is
        // untouched).
        if let Ok(mut inner) = self.inner.lock() {
            if let Some(scope) = inner.scopes.get_mut(&ScopeKey::of(&identity)) {
                scope.ledger_rows = ledger_rows;
            }
        }
        MirrorRowProvenance::Upserted
    }
}

/// Derive the claimed event's own ledger row from the commit-proven request
/// (strict durable source facts). `Add`/`Update` carry the resulting canonical
/// grant directly; `Remove`/`Revoke` derive it from the digest-verified
/// before-image with the terminal state and target revision applied. Any
/// derivation failure is a strict fallback, never a guessed row.
fn request_derived_ledger_row(
    request: &DeltaEventAppendRequest,
    claimed: &ClaimedDeltaEvent,
) -> Result<RawLedgerRow, String> {
    let grant = match astral_db::decode_delta_event_payload(&request.delta_json)
        .map_err(|error| format!("code=local_projection_worker.delta_undecodable;error={error}"))?
    {
        astral_types::GrantDelta::Add { grant }
        | astral_types::GrantDelta::Update { grant, .. } => grant,
        astral_types::GrantDelta::Remove { .. } | astral_types::GrantDelta::Revoke { .. } => {
            let before_image = request.before_image_json.as_deref().ok_or_else(|| {
                "code=local_projection_worker.terminal_delta_without_before_image".to_owned()
            })?;
            let mut grant =
                astral_db::decode_stored_grant_payload(before_image).map_err(|error| {
                    format!("code=local_projection_worker.before_image_undecodable;error={error}")
                })?;
            grant.state = match request.event_type {
                DeltaEventType::Remove => astral_types::GrantState::Removed,
                DeltaEventType::Revoke => astral_types::GrantState::Revoked,
                DeltaEventType::Add | DeltaEventType::Update => {
                    return Err(
                        "code=local_projection_worker.terminal_event_type_mismatch".to_owned()
                    )
                }
            };
            grant.revision = astral_types::GrantRevision::new(claimed.target_version as u64)
                .map_err(|error| {
                    format!("code=local_projection_worker.revision_invalid;error={error}")
                })?;
            grant
        }
    };
    if grant.grant_id != claimed.grant_id {
        return Err("code=local_projection_worker.delta_grant_mismatch".to_owned());
    }
    if grant.revision.value() != claimed.target_version as u64 {
        return Err(format!(
            "code=local_projection_worker.delta_revision_mismatch;delta={};claimed={}",
            grant.revision.value(),
            claimed.target_version
        ));
    }
    let is_tombstone = matches!(
        grant.state,
        astral_types::GrantState::Removed | astral_types::GrantState::Revoked
    );
    let grant_payload = grant.canonical_input().map_err(|error| {
        format!(
            "code=local_projection_worker.delta_payload_uncanonical;grant={};error={error}",
            claimed.grant_id
        )
    })?;
    Ok(RawLedgerRow {
        revision_no: claimed.target_version,
        tenant_id: claimed.tenant_id,
        card_id: claimed.card_id,
        aggregate_type: claimed.aggregate_type.clone(),
        aggregate_id: claimed.aggregate_id,
        grant_id: claimed.grant_id.as_str().to_owned(),
        status: STATUS_ACTIVE.to_owned(),
        is_tombstone: i8::from(is_tombstone),
        grant_payload,
        semantic_hash: claimed.semantic_hash.as_bytes().to_vec(),
        dependency_hash: claimed.dependency_hash.as_bytes().to_vec(),
        operation_id: claimed.operation_id.clone(),
        event_id: claimed.event_id.clone(),
        compiler_version: claimed.compiler_version.clone(),
    })
}

/// Build the ledger row of a published event from the verified published
/// state: the tombstone-inclusive canonical grant content the publish
/// transaction itself read back. Any drift poisons the scope (fail-closed).
fn published_state_ledger_row(
    claimed: &ClaimedDeltaEvent,
    state: &AuthorizationPublishedState,
) -> Result<RawLedgerRow, String> {
    let grant = state
        .segments
        .iter()
        .flat_map(|segment| segment.grants.iter())
        .find(|grant| grant.grant_id == claimed.grant_id)
        .ok_or_else(|| {
            format!(
                "code=local_projection_worker.published_grant_absent;grant={}",
                claimed.grant_id
            )
        })?;
    if grant.revision.value() != claimed.target_version as u64 {
        return Err(format!(
            "code=local_projection_worker.published_revision_mismatch;grant={};published={};claimed={}",
            claimed.grant_id,
            grant.revision.value(),
            claimed.target_version
        ));
    }
    let is_tombstone = matches!(
        grant.state,
        astral_types::GrantState::Removed | astral_types::GrantState::Revoked
    );
    let grant_payload = grant.canonical_input().map_err(|error| {
        format!(
            "code=local_projection_worker.published_payload_uncanonical;grant={};error={error}",
            claimed.grant_id
        )
    })?;
    Ok(RawLedgerRow {
        revision_no: claimed.target_version,
        tenant_id: claimed.tenant_id,
        card_id: claimed.card_id,
        aggregate_type: claimed.aggregate_type.clone(),
        aggregate_id: claimed.aggregate_id,
        grant_id: claimed.grant_id.as_str().to_owned(),
        status: STATUS_ACTIVE.to_owned(),
        is_tombstone: i8::from(is_tombstone),
        grant_payload,
        semantic_hash: claimed.semantic_hash.as_bytes().to_vec(),
        dependency_hash: claimed.dependency_hash.as_bytes().to_vec(),
        operation_id: claimed.operation_id.clone(),
        event_id: claimed.event_id.clone(),
        compiler_version: claimed.compiler_version.clone(),
    })
}

/// The partition walker requires `(grant_id, revision_no)` sorted input;
/// proven appends are per-grant monotonic, so a sorted insert keeps the
/// baseline ordering intact.
fn insert_ledger_row_sorted(rows: &mut Vec<RawLedgerRow>, row: RawLedgerRow) {
    let position = rows.partition_point(|existing| {
        (existing.grant_id.as_str(), existing.revision_no)
            < (row.grant_id.as_str(), row.revision_no)
    });
    rows.insert(position, row);
}

// ─────────────────────────────────────────────────────────────────────────────
// In-process runtime
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime adapter for the direct-dispatch path: delegates ALL durable
/// mutations and strict reads to [`SqlxAuthorizationProjectorRuntime`], and
/// serves the two planning reads from the scope mirror when a proven baseline
/// exists. The publish outcome is stashed so the worker can advance the
/// mirror after the pipeline reports a durable publish.
pub struct LocalProjectionRuntime {
    pool: MySqlPool,
    inner: SqlxAuthorizationProjectorRuntime,
    mirror: ScopePlanMirror,
    /// Publish outcomes of THIS runtime instance keyed by event id (single
    /// worker task; drained by the worker after each processed event).
    published: Mutex<HashMap<String, DeltaProjectorPublishOutcome>>,
}

impl LocalProjectionRuntime {
    pub fn new(pool: MySqlPool) -> Self {
        Self {
            inner: SqlxAuthorizationProjectorRuntime::new(pool.clone()),
            pool,
            mirror: ScopePlanMirror::default(),
            published: Mutex::new(HashMap::new()),
        }
    }

    /// Drain the publish outcome recorded for `event_id` (if any) and advance
    /// the scope mirror from it. Called by the worker once per processed
    /// event; unknown results simply leave the mirror untouched.
    pub fn advance_mirror_after_publish(&self, claimed: &ClaimedDeltaEvent) -> MirrorAdvanceReport {
        let outcome = match self.published.lock() {
            Ok(mut published) => published.remove(&claimed.event_id),
            Err(_) => None,
        };
        let Some(outcome) = outcome else {
            return MirrorAdvanceReport::default();
        };
        self.mirror.advance(claimed, &outcome)
    }

    /// Fail-closed provenance gate before serving a claimed event from the
    /// mirror: the event's own ledger row (written by the source transaction
    /// before dispatch) must be present. A missing row poisons the scope so
    /// this event compiles from strict cold reads instead. Used by the
    /// RECOVERY path where no request DTO is in hand.
    pub fn mirror_ensure_claimed_row_present(&self, claimed: &ClaimedDeltaEvent) -> bool {
        self.mirror.ensure_claimed_row_present(claimed)
    }

    /// Claim-time provenance upsert for DIRECT-dispatch events (request in
    /// hand): inserts the claimed event's own ledger row from the strict
    /// durable request facts while per-grant continuity holds; any doubt
    /// poisons the scope to strict cold reads. See
    /// [`ScopePlanMirror::upsert_claimed_row`].
    pub fn mirror_upsert_claimed_row(
        &self,
        request: &DeltaEventAppendRequest,
        claimed: &ClaimedDeltaEvent,
    ) -> MirrorRowProvenance {
        self.mirror.upsert_claimed_row(request, claimed)
    }
}

#[async_trait::async_trait]
impl AuthorizationProjectorRuntime for LocalProjectionRuntime {
    async fn claim_event_by_dispatch(
        &self,
        request: &DeltaEventAppendRequest,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<ClaimedStableEventOutcome, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        let outcome = astral_db::claim_delta_event_by_stable_event_in_tx(
            &mut tx,
            request,
            lease_owner,
            lease_seconds,
        )
        .await?;
        match tx.commit().await {
            Ok(()) => Ok(outcome),
            Err(error) => resolve_claim_commit(outcome, &error.to_string(), &request.event_id),
        }
    }

    async fn claim_next_event(
        &self,
        scope: &DeltaEventClaimScope,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        self.inner
            .claim_next_event(scope, lease_owner, lease_seconds)
            .await
    }

    async fn read_claimed_event(
        &self,
        identity: &astral_db::DeltaLeaseIdentity,
    ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
        self.inner.read_claimed_event(identity).await
    }

    async fn observe_publication_context(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
        if let Some(publication) = self.mirror.publication(&ScopeKey::of(identity)) {
            return Ok(Some(publication));
        }
        let observed = self.inner.observe_publication_context(identity).await?;
        if let Some(publication) = observed.clone() {
            self.mirror.note_publication(identity, publication);
        }
        Ok(observed)
    }

    async fn load_scope_ledger(
        &self,
        tenant_id: i64,
        aggregate_type: &str,
        aggregate_id: i64,
        card_id: Option<i64>,
    ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
        self.load_scope_ledger_shared(tenant_id, aggregate_type, aggregate_id, card_id)
            .await
            .map(|rows| (*rows).clone())
    }

    async fn load_scope_ledger_shared(
        &self,
        tenant_id: i64,
        aggregate_type: &str,
        aggregate_id: i64,
        card_id: Option<i64>,
    ) -> Result<Arc<Vec<RawLedgerRow>>, RuntimeAccessError> {
        let identity =
            ProjectionAggregateIdentity::new(tenant_id, aggregate_type.to_owned(), aggregate_id)?;
        if let Some(ledger_rows) = self.mirror.ledger(&ScopeKey::of(&identity)) {
            return Ok(ledger_rows);
        }
        let rows = Arc::new(
            self.inner
                .load_scope_ledger(tenant_id, aggregate_type, aggregate_id, card_id)
                .await?,
        );
        self.mirror.note_ledger(&identity, Arc::clone(&rows));
        Ok(rows)
    }

    async fn execute_projection_publish(
        &self,
        command: &astral_db::DeltaProjectorPublishCommand,
    ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
        match self.inner.execute_projection_publish(command).await {
            Ok(outcome) => {
                if let Ok(mut published) = self.published.lock() {
                    published.insert(command.expectation.event_id.clone(), outcome.clone());
                }
                Ok(outcome)
            }
            Err(error) => {
                // F3: ANY durable publish failure invalidates the planning
                // world of the EXACT aggregate the command targeted. The
                // observed frontier/context may no longer describe the
                // durable world — commit proven with an unavailable mirror,
                // unknown outcome, pointer moved, or any other context
                // drift. Serving the stale context would replan
                // PointerMoved until the attempt budget bleeds out; instead
                // the scope (and any pending seed halves) is dropped so the
                // NEXT event re-establishes a strict cold baseline. No
                // unknown event is ever blindly replayed against it.
                self.mirror.poison(&command.expectation.identity);
                Err(error)
            }
        }
    }

    async fn fail_event(
        &self,
        identity: &astral_db::DeltaLeaseIdentity,
        backoff_seconds: i64,
        message: &str,
    ) {
        self.inner
            .fail_event(identity, backoff_seconds, message)
            .await;
    }

    async fn release_event(&self, identity: &astral_db::DeltaLeaseIdentity) {
        self.inner.release_event(identity).await;
    }

    async fn mark_event_quarantined(
        &self,
        lease: &astral_db::DeltaLeaseIdentity,
        reason_code: &str,
        reason_detail: &str,
    ) -> Result<(), RuntimeAccessError> {
        self.inner
            .mark_event_quarantined(lease, reason_code, reason_detail)
            .await
    }

    async fn has_claimable_work(&self, scope: &DeltaEventClaimScope) -> bool {
        self.inner.has_claimable_work(scope).await
    }

    async fn reclaim_budget_exhausted_events(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Result<u64, RuntimeAccessError> {
        self.inner.reclaim_budget_exhausted_events(identity).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure claim-tail / classification helpers (unit-tested without a database)
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve the tail of the direct-claim transaction.
///
/// Commit-unknown status semantics: a FAILED commit after a lease install is
/// an UNRESOLVABLE state — the install may be durable (an orphaned lease
/// token this process never learned) or rolled back, and the caller cannot
/// distinguish the two. The resolution therefore NEVER implies rollback
/// success: a `Claimed` outcome becomes
/// [`ClaimedStableEventOutcome::InDoubt`] (no replay, hub suspect) while the
/// durable lease is left in place for server-side expiry reclaim. Read-only
/// arms (no mutation attempted) fail transiently instead.
fn resolve_claim_commit(
    outcome: ClaimedStableEventOutcome,
    commit_error: &str,
    event_id: &str,
) -> Result<ClaimedStableEventOutcome, RuntimeAccessError> {
    match outcome {
        ClaimedStableEventOutcome::Claimed { .. } => Ok(ClaimedStableEventOutcome::InDoubt {
            event_id: event_id.to_owned(),
            reason: format!(
                "code=local_projection_worker.claim_commit_unknown;event_id={event_id};\
                     durable_lease=left_for_expiry_reclaim;error={commit_error}"
            ),
        }),
        other => {
            // Read-only arms never mutated the row; a failed commit only
            // discards the read snapshot.
            let _ = commit_error;
            Ok(other)
        }
    }
}

/// Whether a direct-claim refusal is a durable CONTRACT divergence between
/// the commit-proven envelope and the durable row (field-by-field payload
/// mismatch, referenced row missing). Those mark the hub channel suspect —
/// the bus admit path and the durable world disagree until reconciled —
/// while transient database failures stay plain warnings (recovery
/// converges). Matches ONLY on the typed seam: the grant-repository refusal
/// variant with its stable `code=` token, never on free-form text.
fn claim_error_marks_hub_suspect(error: &RuntimeAccessError) -> bool {
    const PAYLOAD_MISMATCH_CODE: &str = "claim_by_event_payload_mismatch";
    const ROW_MISSING_CODE: &str = "claim_by_event_row_missing";
    match error {
        RuntimeAccessError::Repository(RepositoryRejection::Grant(
            astral_db::GrantRepositoryError::ScopeViolation(message),
        )) => message.contains(PAYLOAD_MISMATCH_CODE) || message.contains(ROW_MISSING_CODE),
        _ => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker loop
// ─────────────────────────────────────────────────────────────────────────────

/// Start the in-process projection worker. Requires an installed
/// [`astral_db::LocalProjectionBus`] (single-node composition order) and takes
/// the bus's single receiver; a second worker start fails with
/// [`LocalProjectionWorkerStartError::ReceiverTaken`].
///
/// The task is supervised ( [`supervise_local_projection_worker`]): an
/// unexpected exit is sticky fail-closed (global liveness `Dead` + hub
/// `mark_runtime_owner_failed`) and is never blindly restarted. The
/// empty-tenant-scope contract is enforced BEFORE the single receiver is
/// taken, so a rejected start cannot burn the one-owner receiver.
pub fn start_local_projection_worker(
    pool: MySqlPool,
    config: LocalProjectionWorkerConfig,
) -> Result<AuthorizationProjectorHandle, LocalProjectionWorkerStartError> {
    let bus = local_projection_bus().ok_or(LocalProjectionWorkerStartError::BusNotInstalled)?;
    if config
        .recovery_poll
        .is_some_and(|interval| interval < Duration::from_secs(1))
    {
        return Err(LocalProjectionWorkerStartError::InvalidConfig {
            reason: "code=local_projection_worker.recovery_poll_below_floor;floor_secs=1"
                .to_owned(),
        });
    }
    // Empty-tenant-scope reject (F2): the recovery pass iterates exactly these
    // scopes, so an empty list would silently disable crash/overflow recovery.
    // Checked before the receiver takeover so the rejection is clean.
    validate_recovery_scope(&config.projector.tenants)?;
    let receiver = take_global_local_projection_receiver()
        .map_err(|LocalProjectionOwnerTaken| LocalProjectionWorkerStartError::ReceiverTaken)?;

    let cancellation = ProjectorCancellationToken::default();
    let run_cancellation = cancellation.clone();
    let run_id = uuid::Uuid::new_v4().to_string();
    let health = Arc::new(ProjectorHealthShared::new());
    let runtime = Arc::new(LocalProjectionRuntime::new(pool));
    let owner = format!("local-projection:{}", uuid::Uuid::new_v4());
    tracing::info!(
        run_id = %run_id,
        owner = %owner,
        tenants = config.projector.tenants.len(),
        "local projection worker starting (in-process bus consumer, supervised liveness)"
    );
    let health_for_task = health.clone();
    let inner: JoinHandle<Result<WorkerRunSummary, String>> =
        tokio::spawn(run_local_projection_worker(
            runtime,
            config,
            owner,
            bus,
            receiver,
            run_cancellation,
            health_for_task,
        ));
    // Supervision: unexpected death is sticky fail-closed (isolated cell +
    // mirrored into the process-global cell) and is never blindly restarted;
    // shutdown-requested exits propagate the inner summary unchanged.
    let supervisor_run_id = run_id.clone();
    let join: JoinHandle<Result<WorkerRunSummary, String>> =
        tokio::spawn(supervise_local_projection_worker(
            inner,
            cancellation.clone(),
            Arc::new(WorkerLivenessCell(Mutex::new(None))),
            true,
            supervisor_run_id,
        ));
    // Publish liveness only after the supervised task exists: the global cell
    // is the composite supervision entry point.
    worker_liveness_cell().set_liveness(LocalProjectionWorkerLiveness::Alive);
    Ok(AuthorizationProjectorHandle {
        cancellation,
        join,
        run_id,
        health,
    })
}

/// Recovery-pass wait future: ticks the interval when enabled, otherwise
/// pending forever so the select arm stays disabled.
async fn recovery_wait(ticker: Option<&mut tokio::time::Interval>) {
    match ticker {
        Some(ticker) => {
            let _ = ticker.tick().await;
        }
        None => std::future::pending().await,
    }
}

/// True when the single-node in-process path may own projection for this
/// process (bus installed AND memory mirror installed). Caller decides the
/// fallback (DB-poll worker) on `false`.
pub fn local_projection_direct_path_ready() -> bool {
    astral_db::local_projection_bus_installed() && memory_mirror_is_installed()
}

#[allow(clippy::too_many_arguments)]
async fn run_local_projection_worker(
    runtime: Arc<LocalProjectionRuntime>,
    config: LocalProjectionWorkerConfig,
    claim_owner: String,
    bus: LocalProjectionBus,
    mut receiver: mpsc::Receiver<CommitDeltaEnvelope>,
    shutdown: ProjectorCancellationToken,
    health: Arc<ProjectorHealthShared>,
) -> Result<WorkerRunSummary, String> {
    let manifest_owner = format!("local-projection-manifest:{}", uuid::Uuid::new_v4());
    let mut summary = WorkerRunSummary::default();
    let progress = Arc::new(ProjectorProgress::default());
    progress.touch();
    health.swap_progress(progress);
    let mut recovery_tick = config.recovery_poll.map(|interval| {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker
    });

    loop {
        tokio::select! {
        _ = shutdown.cancelled() => {
            return Ok(health.take_summary());
        }
        _ = recovery_wait(recovery_tick.as_mut()), if recovery_tick.is_some() => {
            run_recovery_pass(
                &runtime,
                &config,
                &claim_owner,
                &manifest_owner,
                &shutdown,
                &mut summary,
            )
            .await;
            health.note_progress();
        }
        delivery = receiver.recv() => {
            let Some(envelope) = delivery else {
                // Bus closed and drained: worker exits cleanly. Durable
                // pending rows stay convergent via the DB-poll recovery.
                tracing::info!(
                    events_published = summary.events_published,
                    "local projection bus closed and drained; worker exiting"
                );
                return Ok(summary);
            };
            // Release the admission bookkeeping slot immediately: the
            // envelope is out of the queue and owned by this loop.
            bus.acknowledge(&envelope);
            handle_dispatched_envelope(
                &runtime,
                &config,
                &claim_owner,
                &manifest_owner,
                &shutdown,
                &mut summary,
                envelope,
            )
            .await;
            health.note_progress();
        }        }
    }
}

async fn handle_dispatched_envelope(
    runtime: &Arc<LocalProjectionRuntime>,
    config: &LocalProjectionWorkerConfig,
    claim_owner: &str,
    manifest_owner: &str,
    shutdown: &ProjectorCancellationToken,
    summary: &mut WorkerRunSummary,
    envelope: CommitDeltaEnvelope,
) {
    let request: &DeltaEventAppendRequest = &envelope.request;
    match runtime
        .claim_event_by_dispatch(request, claim_owner, config.projector.claim_lease_seconds)
        .await
    {
        Err(error) => {
            if claim_error_marks_hub_suspect(&error) {
                // Durable contract divergence (envelope ⇆ durable row payload
                // binding / referenced row missing): the commit-proven admit
                // path and the durable world disagree until reconciled —
                // sticky hub suspect, never a silent warn-and-continue.
                tracing::error!(
                    event_id = %envelope.request.event_id,
                    operation_id = %envelope.request.operation_id,
                    error = %error,
                    "direct-dispatch claim refused by durable contract binding; \
                     hub suspect until reconciliation, no replay"
                );
                if let Some(hub) = memory_projection_hub() {
                    hub.mark_channel_suspect(format!(
                        "code=local_projection_worker.claim_contract_refusal;error={error}"
                    ));
                }
            } else {
                // Transient failure (database / connection): the durable
                // pending delta stays queued and recovery converges.
                tracing::warn!(
                    event_id = %envelope.request.event_id,
                    operation_id = %envelope.request.operation_id,
                    error = %error,
                    "direct-dispatch claim failed transiently; durable pending \
                     delta stays queued for recovery"
                );
            }
        }
        Ok(ClaimedStableEventOutcome::AlreadyProcessed { event_id }) => {
            tracing::debug!(
                event_id = %event_id,
                "dispatched delta already durably processed; skip without replay"
            );
        }
        Ok(ClaimedStableEventOutcome::TerminalGated { event_id, status }) => {
            // NOT a success skip: the durable terminal gate stays in force and
            // the redispatch is surfaced for reconciliation.
            tracing::error!(
                event_id = %event_id,
                status = %status,
                "dispatched delta is durably gated (quarantined); no replay, \
                 operator reconciliation required"
            );
        }
        Ok(ClaimedStableEventOutcome::Busy { event_id }) => {
            tracing::debug!(
                event_id = %event_id,
                "dispatched delta not claimable now (live lease / backoff window); recovery converges"
            );
        }
        Ok(ClaimedStableEventOutcome::InDoubt { event_id, reason }) => {
            tracing::error!(
                event_id = %event_id,
                reason = %reason,
                "dispatched delta row state unresolvable; NO blind replay, hub suspect until reconciliation"
            );
            if let Some(hub) = memory_projection_hub() {
                hub.mark_channel_suspect(reason);
            }
        }
        Ok(ClaimedStableEventOutcome::Claimed { claim, event }) => {
            summary.events_claimed += 1;
            // Claim-time provenance upsert from the commit-proven request:
            // inserts the event's own ledger row while per-grant continuity
            // against the mirror head holds; any doubt poisons the scope so
            // the compile falls back to strict cold reads.
            runtime.mirror_upsert_claimed_row(&envelope.request, &event);
            let identity = match ProjectionAggregateIdentity::new(
                claim.tenant_id,
                claim.aggregate_type.clone(),
                claim.aggregate_id,
            ) {
                Ok(identity) => identity,
                Err(error) => {
                    // Shape corruption of a payload-bound claim: quarantine is
                    // impossible without a valid identity, so record UNKNOWN
                    // and leave the leased row to expire for reclaim.
                    tracing::error!(
                        event_id = %claim.event_id,
                        error = %error,
                        "claimed identity invalid on the direct path; lease left to expire"
                    );
                    return;
                }
            };
            let projector_config = config.projector.clone();
            let as_dyn: Arc<dyn AuthorizationProjectorRuntime> = runtime.clone();
            process_verified_claim(
                &as_dyn,
                &projector_config,
                manifest_owner,
                shutdown,
                &claim,
                &event,
                identity,
                0,
                summary,
            )
            .await;
            runtime.advance_mirror_after_publish(&event);
        }
    }
}

/// Low-frequency recovery pass: reclaim queue-side events the bus may have
/// missed, through the SAME verified pipeline (strict reads whenever the
/// mirror lacks their provenance; missing memory proofs compile PENDING/DB
/// strict, never from guessed inputs).
async fn run_recovery_pass(
    runtime: &Arc<LocalProjectionRuntime>,
    config: &LocalProjectionWorkerConfig,
    claim_owner: &str,
    manifest_owner: &str,
    shutdown: &ProjectorCancellationToken,
    summary: &mut WorkerRunSummary,
) {
    let Some(interval) = config.recovery_poll else {
        return;
    };
    let _ = interval;
    for tenant_id in &config.projector.tenants {
        if shutdown.is_cancelled() {
            return;
        }
        let scope = DeltaEventClaimScope {
            tenant_id: *tenant_id,
            card_id: None,
        };
        for _ in 0..config.max_recovery_events_per_pass {
            match runtime
                .claim_next_event(&scope, claim_owner, config.projector.claim_lease_seconds)
                .await
            {
                Ok(Some(claim)) => {
                    summary.events_claimed += 1;
                    let identity = match ProjectionAggregateIdentity::new(
                        claim.tenant_id,
                        claim.aggregate_type.clone(),
                        claim.aggregate_id,
                    ) {
                        Ok(identity) => identity,
                        Err(_) => return,
                    };
                    let _ = identity;
                    // Recovery events bypass the direct claim path and carry
                    // no request DTO: the readback pipeline verifies the lease
                    // and loads the payload strictly. If the mirror exists for
                    // the scope but lacks this event's provenance row, the
                    // scope is poisoned back to strict cold reads first.
                    recovery_process_claimed(
                        runtime,
                        &config.projector,
                        manifest_owner,
                        shutdown,
                        claim,
                        summary,
                    )
                    .await;
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(
                        tenant_id,
                        error = %error,
                        "recovery pass claim failed; remaining events stay queued"
                    );
                    break;
                }
            }
        }
    }
}

async fn recovery_process_claimed(
    runtime: &Arc<LocalProjectionRuntime>,
    projector_config: &AuthorizationProjectorConfig,
    manifest_owner: &str,
    shutdown: &ProjectorCancellationToken,
    claim: DeltaEventClaim,
    summary: &mut WorkerRunSummary,
) {
    let as_dyn: Arc<dyn AuthorizationProjectorRuntime> = runtime.clone();
    // Queue-side claims carry no payload in hand: run the standard pipeline
    // (readback → observe → ledger → decide → publish).
    let delta_lease_identity = DeltaLeaseIdentity {
        delta_event_id: claim.delta_event_id,
        event_id: claim.event_id.clone(),
        lease_owner: claim.lease_owner.clone(),
        lease_token: claim.lease_token.clone(),
    };
    match as_dyn.read_claimed_event(&delta_lease_identity).await {
        Ok(claimed_row) => {
            let identity = match ProjectionAggregateIdentity::new(
                claimed_row.tenant_id,
                claimed_row.aggregate_type.clone(),
                claimed_row.aggregate_id,
            ) {
                Ok(identity) => identity,
                Err(error) => {
                    tracing::error!(
                        event_id = %claim.event_id,
                        error = %error,
                        "recovery claim identity invalid; lease left to expire"
                    );
                    return;
                }
            };
            // Provenance gate: a mirror that lacks this event's row cannot
            // serve the compile — poison to strict cold reads (never a silent
            // update from guessed inputs).
            runtime.mirror_ensure_claimed_row_present(&claimed_row);
            process_verified_claim(
                &as_dyn,
                projector_config,
                manifest_owner,
                shutdown,
                &claim,
                &claimed_row,
                identity,
                0,
                summary,
            )
            .await;
            runtime.advance_mirror_after_publish(&claimed_row);
        }
        Err(error) => {
            tracing::warn!(
                event_id = %claim.event_id,
                error = %error,
                "recovery claim readback refused; event stays for lease-expiry reclaim"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (pure: mirror mechanics; no DB)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
