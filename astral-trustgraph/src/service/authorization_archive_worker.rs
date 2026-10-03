//! Rust-owned asynchronous authorization ARCHIVE worker (Exec-L2 durable
//! internal consumer of `authorization_archive_outbox`).
//!
//! Scope of this slice (first片 per the approved "版本化热状态+异步旧版本归档"
//! plan) — exactly ONE external behavior family:
//!
//! 1. Claims `PENDING` (or expired-`LEASED`) archive intents per configured
//!    tenant with the REAL repository claim primitive inside its own short
//!    transaction (`uk_aao_event`/`uk_aao_generation` are the stable identities).
//! 2. For a claimed intent, opens ONE short durable transaction that:
//!    - locks the superseded parent projection manifest FIRST through the
//!      claim's immutable `manifest_id` (a lock-acquisition key only, never
//!      evidence) and reads its sealed chain digest ONLY in an archivable
//!      terminal state (`COMMITTED`/`SUPERSEDED`) — the archive family's
//!      unified parent-manifest→outbox lock order shared with ensure/record/
//!      complete in astral-db, so no ABBA cycle can form;
//!    - re-locks and re-decodes the outbox intent by its stable event
//!      identity, cross-checks it against the locked parent, and keeps
//!      proceeding only while it is still `LEASED` for OUR lease;
//!    - heartbeats (renews) the live lease BEFORE any expensive chain/proof
//!      work and AGAIN after the proof record immediately before the terminal
//!      flip, always with the CONFIGURED claim lease seconds (never a magic
//!      constant); any refused renewal propagates as a Repository error and
//!      classifies UNKNOWN with zero follow-up;
//!    - builds the typed proof request STRICTLY from those in-transaction
//!      re-read facts (the claim payload is an expectation, never evidence);
//!    - records the DB-resident archive proof (immutable-equal replay is a
//!      documented resume path) — which re-verifies the ENTIRE old chain
//!      (parent lineage/fence, ordered references, every segment payload +
//!      content digest + local seal, manifest global seal) under locks;
//!    - THEN flips the intent `SUCCEEDED` through the live-lease guarded
//!      repository boundary. Proof precedes ACK; commit precedes every success
//!      counter. A rollback removes proof AND completion together.
//! 3. Classifies failures: deterministic corruption/conflict AND missing
//!    durable evidence (the intent or its parent manifest row is gone — a
//!    retry can never restore absent rows) → REAL terminal quarantine;
//!    transient races/preconditions (including unexpected intent status
//!    drift) → bounded exponential backoff honoring future `next_attempt_at`;
//!    lost leases → UNKNOWN with ZERO follow-up mutation.
//!
//! Hard boundaries (source-shape guarded below):
//! - This worker NEVER publishes current state, never fabricates generation 0
//!   evidence, never performs retention/GC on manifests/references/segments/
//!   before-images, never speaks HTTP/S3/filesystem/MQ/Redis, and never touches
//!   legacy snapshot/head/outbox/cache surfaces. `archive_key` is a
//!   deterministic storage key, not an identity: the stable intent identities
//!   remain `uk_aao_event`/`uk_aao_generation`, and the proof content lives
//!   entirely inside this database as the sealed OLD chain.
//! - Archive failures NEVER roll back or degrade an already-published current
//!   pointer: publication stays authoritative while archive work retries.
//! - First publications create no intent, therefore this worker neither sees
//!   nor synthesizes a generation 0 artifact.
//!
//! Cancellation/shutdown discipline: `main` owns the handle, cancels first,
//! joins within [`SHUTDOWN_JOIN_TIMEOUT_SECS`]; timeout/panic/Err surface as an
//! explicit process error. Shutdown between claims leaves the short lease to
//! expire server-side instead of racing a mutation (unknown-result avoidance).
//! `worker_id`/`run_id` are run-scoped log/owner strings — never business or
//! authorization identity. Lease tokens are secret-derived hashes in the DB and
//! are NEVER logged.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sqlx::MySqlPool;
use tokio::task::JoinHandle;

use astral_db::{
    claim_next_authorization_archive_intent_in_tx, complete_authorization_archive_intent,
    fail_authorization_archive_intent, heartbeat_authorization_archive_intent_lease,
    load_archivable_manifest_chain_digest_in_tx, load_authorization_archive_intent_in_tx,
    load_authorization_archive_proof_in_tx, mark_authorization_archive_intent_quarantined,
    record_authorization_archive_proof_in_tx, ArchiveLeaseProof, AuthorizationArchiveIntentClaim,
    AuthorizationArchiveManifestProof, AuthorizationArchiveOutboxStatus,
    AuthorizationArchiveProofRequest, AuthorizationProjectionError, MAX_ARCHIVE_BACKOFF_SECONDS,
    MAX_ARCHIVE_LEASE_SECONDS,
};

// ─────────────────────────────────────────────────────────────────────────────
// Worker policy constants (Exec-L2 budgets)
// ─────────────────────────────────────────────────────────────────────────────

/// Idle poll period between cycles.
pub const POLL_INTERVAL_SECS: u64 = 5;
/// One claimed archive intent's lease window (≤ `MAX_ARCHIVE_LEASE_SECONDS`).
pub const ARCHIVE_CLAIM_LEASE_SECS: i64 = 120;
/// Hard attempt budget per archive intent, judged against the durable
/// POST-install `attempts` value returned by the claim readback. Attempts
/// `1..=4` schedule short exponential steps; a failure observed at
/// `attempts >= 5` switches to the maximal backoff plus the stable exhaustion
/// marker (the row deliberately STAYS PENDING: infrastructure may recover, and
/// this slice refuses to fake a terminal state it does not own).
pub const MAX_ARCHIVE_INTENT_ATTEMPTS: i64 = 5;
/// Backoff ceiling handed to the failure primitive (within the repository's
/// own 3600s clamp).
pub const ARCHIVE_BACKOFF_CAP_SECS: i64 = 900;
/// Maximum intents processed per tenant within one poll cycle (bounded batch
/// prevents one hot tenant from starving the round-robin).
const MAX_INTENTS_PER_TENANT_PER_CYCLE: usize = 8;
/// Bounded join window shared by every graceful shutdown path (main bind-failure
/// and normal signal shutdown alike).
pub const SHUTDOWN_JOIN_TIMEOUT_SECS: u64 = 30;

/// Stable operator-facing marker appended to `last_error` when the attempt
/// budget is exhausted. PENDING on purpose: this slice never relabels exhaustion
/// into terminal quarantine or fake success.
const ATTEMPT_BUDGET_EXHAUSTED_CODE: &str = "code=auth_archive_worker.attempt_budget_exhausted";
/// Generic fallback code when a quarantine reason lacks a parseable `code=`
/// prefix (operator evidence keeps the FULL original text as detail).
const GENERIC_QUARANTINE_FALLBACK_CODE: &str = "auth_archive_worker.quarantine";

/// Upper character bound for the machine-stable `code=` part composed into
/// durable reasons; keeping codes short guarantees the code prefix survives
/// the repository's whole-string truncation clamp.
const QUARANTINE_REASON_CODE_LIMIT: usize = 64;

fn clamp_backoff(secs: i64) -> i64 {
    secs.clamp(1, ARCHIVE_BACKOFF_CAP_SECS.min(MAX_ARCHIVE_BACKOFF_SECONDS))
}

/// Bounded exponential backoff for an intent whose durable post-install
/// attempts counter reached `n` (first failure n=1 → 1s, doubling, saturating).
/// Used ONLY via [`plan_archive_retry`] (+ its tests).
fn archive_backoff_secs(attempts: i64) -> i64 {
    let floor = if attempts < 1 { 1 } else { attempts };
    if floor >= MAX_ARCHIVE_INTENT_ATTEMPTS {
        return clamp_backoff(ARCHIVE_BACKOFF_CAP_SECS);
    }
    let exp = 1i64
        .checked_shl((floor - 1).min(10) as u32)
        .unwrap_or(i64::MAX);
    clamp_backoff(exp)
}

/// Disposition of the unified attempt-budget policy for one failing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArchiveRetrySchedule {
    /// Within budget: keep the intent PENDING, schedule the next attempt after
    /// this bounded backoff (the claim predicate respects the future stamp).
    Continue { backoff_secs: i64 },
    /// Budget exhausted (`current_attempts >= MAX_ARCHIVE_INTENT_ATTEMPTS`):
    /// maximal cap backoff + the stable [`ATTEMPT_BUDGET_EXHAUSTED_CODE`]
    /// marker in `last_error`, row remains PENDING for operator/infra recovery.
    AttemptBudgetExhausted { backoff_secs: i64 },
}

/// THE single retry/backoff policy for every non-terminal failure path.
///
/// `attempts_current` MUST be the durable CURRENT value — the post-install
/// counter surfaced by the strict claim readback; pre-increment views are
/// forbidden because they would overpay one extra backoff step.
fn plan_archive_retry(attempts_current: i64) -> ArchiveRetrySchedule {
    let attempts = attempts_current.max(1);
    if attempts >= MAX_ARCHIVE_INTENT_ATTEMPTS {
        return ArchiveRetrySchedule::AttemptBudgetExhausted {
            backoff_secs: clamp_backoff(ARCHIVE_BACKOFF_CAP_SECS),
        };
    }
    ArchiveRetrySchedule::Continue {
        backoff_secs: archive_backoff_secs(attempts),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Run summary, failure model and classification (all unit-tested without MySQL)
// ─────────────────────────────────────────────────────────────────────────────

/// Run-scoped counters reported through shutdown. NONE of these carry
/// authorization semantics (no tenant/card/grant payloads); they exist purely
/// for observability and reconciliation triage.
#[derive(Debug, Default)]
pub struct ArchiveRunSummary {
    pub intents_claimed: u64,
    /// Intents durably flipped `SUCCEEDED` behind a freshly recorded proof.
    pub intents_archived: u64,
    /// Intents completed against an ALREADY-existing byte-equal durable proof
    /// (documented recovery path: proof transaction committed in a prior run
    /// while the intent still needed its terminal flip).
    pub intents_resumed: u64,
    /// Transient failures that scheduled exactly one bounded-backoff retry.
    pub intents_retried: u64,
    /// Real terminal quarantines whose write was PROVEN durable (live-lease
    /// CAS matched exactly one row).
    pub intents_quarantined: u64,
    /// Outcomes that could NOT be proven either way: lost/doubtful lease,
    /// failed commit, interrupted stream. Zero follow-up mutations were issued
    /// for them; reconciliation happens from durable state alone.
    pub intents_unknown: u64,
    /// Orthogonal exhaustion marker count (a retried failure may ALSO hit the
    /// budget; both counters advance for the same intent).
    pub intents_budget_exhausted: u64,
    /// Poll cycles that observed no claimable work (empty scope or queue).
    pub no_work_cycles: u64,
}

/// Everything a failed archive attempt reports back to the policy layer.
///
/// Variants preserve the typed repository cause so classification stays
/// structural (never string-scraped) while remaining fully fake-able.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveAttemptFailure {
    /// Query/connection-level failure inside the archive transaction. The
    /// proof/flip writes rolled back together; the committed CLAIM survives.
    #[error("database access failed: {0}")]
    Database(String),
    /// Typed repository refusal; classification decides retry vs quarantine.
    #[error("repository rejected the archive transaction: {0}")]
    Repository(#[from] AuthorizationProjectionError),
    /// Durable evidence went MISSING between the claim and the proof
    /// transaction: the claimed intent row or its referenced parent manifest
    /// row no longer exists under lock. Rows are never deleted by this
    /// worker, so the absence is deterministic — a retry can never restore
    /// what is gone — and the disposition is terminal quarantine.
    #[error("archive durable evidence is missing: {0}")]
    EvidenceMissing(String),
    /// Worker-side contract anomaly detected on re-read (unexpected absence or
    /// status drift between claim and proof transaction).
    #[error("archive contract violated: {0}")]
    Contract(String),
}

impl From<sqlx::Error> for ArchiveAttemptFailure {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value.to_string())
    }
}

/// Claim-phase access failures (no intent data assigned yet; cycle aborts).
#[derive(Debug, thiserror::Error)]
pub enum ArchiveAccessError {
    #[error("database access failed: {0}")]
    Database(String),
    #[error("repository rejected the operation: {0}")]
    Repository(String),
}

impl From<sqlx::Error> for ArchiveAccessError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value.to_string())
    }
}

impl From<AuthorizationProjectionError> for ArchiveAccessError {
    fn from(value: AuthorizationProjectionError) -> Self {
        match value {
            AuthorizationProjectionError::Query(inner) => Self::Database(inner.to_string()),
            other => Self::Repository(other.to_string()),
        }
    }
}

/// Structural outcome classes for a failed archive attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureClass {
    /// Immutable divergence or corrupt evidence: EXACTLY ONE live-lease
    /// guarded terminal quarantine write; budgets never gate this path.
    Quarantine,
    /// Race winner/mid-flight precondition/db-level doubt: ONE bounded-backoff
    /// retry scheduling through the unified budget funnel.
    Retry,
    /// Ownership/result UNKNOWN (lost lease, doubtful CAS): zero follow-up
    /// mutation until reconciliation from durable state.
    Unknown,
}

/// THE single structural classifier. Rationale per branch:
/// - query/connection trouble inside the rolled-back transaction → retry;
/// - lease/CAS refusals mean expired/stolen/terminal ownership → UNKNOWN,
///   never blindly repeated;
/// - immutable conflict, corrupt state, identity mismatch, digest collision,
///   malformed stored shapes → deterministic corruption → quarantine (they
///   recur identically on every attempt);
/// - missing durable evidence (intent/parent rows absent under lock) →
///   terminal quarantine: rows are never deleted by this worker, so absence
///   is deterministic and no bounded retry can restore it;
/// - unproven unique-race winners and not-ready mid-flight preconditions →
///   retry (safe, evidence-preserving default).
fn classify_archive_failure(failure: &ArchiveAttemptFailure) -> FailureClass {
    match failure {
        ArchiveAttemptFailure::Database(_) | ArchiveAttemptFailure::Contract(_) => {
            FailureClass::Retry
        }
        ArchiveAttemptFailure::EvidenceMissing(_) => FailureClass::Quarantine,
        ArchiveAttemptFailure::Repository(error) => match error {
            AuthorizationProjectionError::Query(_) => FailureClass::Retry,
            AuthorizationProjectionError::LeaseCasFailed(_)
            | AuthorizationProjectionError::ClaimRace => FailureClass::Unknown,
            AuthorizationProjectionError::ImmutableConflict(_)
            | AuthorizationProjectionError::Corrupt(_)
            | AuthorizationProjectionError::IdentityMismatch(_)
            | AuthorizationProjectionError::SegmentDigestCollision(_)
            | AuthorizationProjectionError::Mapping(_)
            | AuthorizationProjectionError::ScopeViolation(_)
            | AuthorizationProjectionError::IllegalStatusTransition { .. } => {
                FailureClass::Quarantine
            }
            AuthorizationProjectionError::DuplicateRow(_)
            | AuthorizationProjectionError::NotReady(_)
            | AuthorizationProjectionError::Contract(_)
            | AuthorizationProjectionError::CurrentPointerCasConflict(_)
            | AuthorizationProjectionError::ManifestPublishConflict(_) => FailureClass::Retry,
        },
    }
}

/// Machine-stable `code=` fragment for one failure, guaranteed short enough
/// that the prefix survives the repository's durable `last_error` truncation.
fn archive_error_code(error: &AuthorizationProjectionError) -> &'static str {
    match error {
        AuthorizationProjectionError::Contract(_) => "contract_rejected",
        AuthorizationProjectionError::Mapping(_) => "stored_shape_mapping_refused",
        AuthorizationProjectionError::Query(_) => "database_query_failed",
        AuthorizationProjectionError::ScopeViolation(_) => "scope_violation",
        AuthorizationProjectionError::DuplicateRow(_) => "duplicate_row_unproven_winner",
        AuthorizationProjectionError::ImmutableConflict(_) => "immutable_conflict",
        AuthorizationProjectionError::SegmentDigestCollision(_) => "segment_digest_collision",
        AuthorizationProjectionError::IdentityMismatch(_) => "identity_mismatch",
        AuthorizationProjectionError::LeaseCasFailed(_) => "lease_cas_failed",
        AuthorizationProjectionError::ClaimRace => "claim_race",
        AuthorizationProjectionError::CurrentPointerCasConflict(_) => "pointer_cas_conflict",
        AuthorizationProjectionError::ManifestPublishConflict(_) => "manifest_publish_conflict",
        AuthorizationProjectionError::NotReady(_) => "state_not_ready",
        AuthorizationProjectionError::Corrupt(_) => "corrupt_projection_state",
        AuthorizationProjectionError::IllegalStatusTransition { .. } => "illegal_status_transition",
    }
}

/// Compose the durable failure reason: a short machine-stable `code=` prefix
/// plus free-form detail (byte-truncation belongs to the repository boundary).
fn archive_failure_reason(failure: &ArchiveAttemptFailure) -> String {
    let code = match failure {
        ArchiveAttemptFailure::Database(_) => "database_query_failed",
        ArchiveAttemptFailure::Contract(_) => "contract_anomaly",
        ArchiveAttemptFailure::EvidenceMissing(_) => "evidence_missing",
        ArchiveAttemptFailure::Repository(error) => archive_error_code(error),
    };
    format!("code=auth_archive_worker.{code};detail={failure}")
}

/// Stable decomposition of one quarantine reason into `(code, detail)`,
/// mirroring the projector-side contract: leading `code=<token>` up to the
/// first `;` becomes the machine-stable code (trimmed, ≤64 chars, no
/// whitespace); everything else becomes detail. Unparseable reasons fall back
/// to [`GENERIC_QUARANTINE_FALLBACK_CODE`] with the FULL original text kept as
/// detail so operator evidence never shrinks.
fn quarantine_reason_parts(reason: &str) -> (String, String) {
    let Some(body) = reason.strip_prefix("code=") else {
        return (
            GENERIC_QUARANTINE_FALLBACK_CODE.to_owned(),
            reason.to_owned(),
        );
    };
    let (raw_code, raw_detail) = body.split_once(';').unwrap_or((body, ""));
    let code = raw_code.trim();
    if code.is_empty()
        || code.chars().count() > QUARANTINE_REASON_CODE_LIMIT
        || code.chars().any(char::is_whitespace)
    {
        (
            GENERIC_QUARANTINE_FALLBACK_CODE.to_owned(),
            reason.to_owned(),
        )
    } else {
        (code.to_owned(), raw_detail.to_owned())
    }
}

/// Proven success of one archive attempt.
#[derive(Debug, Clone)]
pub struct ArchiveOutcome {
    /// The durable proof recorded in this transaction (or replay-equal winner
    /// resumed from a prior complete transaction).
    pub proof: AuthorizationArchiveManifestProof,
    /// True when an identical durable proof already existed before the record
    /// step (resume semantics — the intent completion was still outstanding).
    pub resumed_existing_proof: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Lifecycle handle (owned by main; cancel → bounded join → explicit failure)
// ─────────────────────────────────────────────────────────────────────────────

/// A small cancellation token kept local to the archive worker (same pattern
/// as the audit replay worker): `main` and tests only ever see `cancel()`;
/// internal run-loop coordination uses the crate-private wait/check seam.
#[derive(Clone, Default)]
pub struct ArchiveCancellationToken {
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl ArchiveCancellationToken {
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
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
        self.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Handle held by `main`; graceful shutdown cancels then joins with a bound.
/// Timeout, task panic and worker `Err` all surface explicitly.
pub struct AuthorizationArchiveWorkerHandle {
    pub cancellation: ArchiveCancellationToken,
    pub join: JoinHandle<Result<ArchiveRunSummary, tokio::task::JoinError>>,
    /// Run-scoped identifier used in logs and the lease-owner string; never
    /// stable across restarts and never usable as authorization identity.
    pub run_id: String,
}

#[derive(Debug)]
pub struct ArchiveShutdownReport {
    pub summary: Result<ArchiveRunSummary, String>,
    pub join_elapsed: Duration,
}

/// Retains the join if shutdown is cancelled while waiting. Drop cancels and
/// aborts the worker, then keeps ownership while a reaper awaits task completion.
struct ArchiveWorkerShutdownGuard {
    cancellation: ArchiveCancellationToken,
    join: Option<JoinHandle<Result<ArchiveRunSummary, tokio::task::JoinError>>>,
    runtime: tokio::runtime::Handle,
}

impl ArchiveWorkerShutdownGuard {
    fn join_mut(&mut self) -> &mut JoinHandle<Result<ArchiveRunSummary, tokio::task::JoinError>> {
        self.join
            .as_mut()
            .expect("shutdown guard retains the join until completion")
    }

    fn release_join(&mut self) {
        self.join.take();
    }
}

impl Drop for ArchiveWorkerShutdownGuard {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(join) = self.join.take() {
            join.abort();
            self.runtime.spawn(async move {
                if tokio::time::timeout(Duration::from_secs(1), join)
                    .await
                    .is_err()
                {
                    tracing::error!("authorization archive worker abort remains unproven");
                }
            });
        }
    }
}

/// Cancel the worker and await termination within a bounded timeout.
///
/// `Err(summary)` forms cover: worker panic/join failure, propagated worker
/// `Err`, timeout. A dying or stuck archive worker can never be reported as a
/// clean shutdown — the caller turns non-clean shutdowns into process errors.
pub async fn shutdown_authorization_archive_worker(
    handle: AuthorizationArchiveWorkerHandle,
    timeout: Duration,
) -> ArchiveShutdownReport {
    let mut ownership = ArchiveWorkerShutdownGuard {
        cancellation: handle.cancellation.clone(),
        join: Some(handle.join),
        runtime: tokio::runtime::Handle::current(),
    };
    handle.cancellation.cancel();
    let started = Instant::now();
    let summary = match tokio::time::timeout(timeout, ownership.join_mut()).await {
        Ok(Ok(Ok(summary))) => {
            ownership.release_join();
            Ok(summary)
        }
        Ok(Ok(Err(join_error))) => {
            ownership.release_join();
            Err(format!("worker task failed: {join_error}"))
        }
        Ok(Err(_)) => {
            ownership.release_join();
            Err("shutdown summary unavailable".to_owned())
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
                "archive worker did not stop within {timeout:?}; aborted; possibly wedged \
                 inside an archive transaction"
            ))
        }
    };
    tracing::info!(
        run_id = %handle.run_id,
        join_elapsed_ms = started.elapsed().as_millis() as u64,
        clean = summary.is_ok(),
        "authorization archive worker shutdown completed"
    );
    ArchiveShutdownReport {
        summary,
        join_elapsed: started.elapsed(),
    }
}

#[derive(Debug, Clone)]
pub struct AuthorizationArchiveConfig {
    /// Tenant ids polled round-robin. Supplied from the SAME fail-fast parsed
    /// `ASTRAL_PROJECTOR_TENANTS` result the new projector consumed — archive
    /// intents originate from those tenants' publications, so a second config
    /// source is deliberately avoided. An empty list keeps the consumer idle
    /// with a startup warning (shared documented gap).
    pub tenants: Vec<i64>,
    pub poll_interval_secs: u64,
    /// Claim-lease window in seconds; the SAME value is reused as the
    /// in-flight heartbeat renewal budget so renewals always track the
    /// configured claim lease instead of a magic constant. Validated by
    /// both fallible constructors against `1..=MAX_ARCHIVE_LEASE_SECONDS`:
    /// an out-of-range value makes them return [`ArchiveConfigError`]
    /// before any task is spawned instead of failing every claim/heartbeat
    /// mid-flight.
    pub claim_lease_seconds: i64,
}

impl Default for AuthorizationArchiveConfig {
    fn default() -> Self {
        Self {
            tenants: Vec::new(),
            poll_interval_secs: POLL_INTERVAL_SECS,
            claim_lease_seconds: ARCHIVE_CLAIM_LEASE_SECS,
        }
    }
}

/// Startup configuration rejection for both archive worker constructors
/// (Exec-L2 fail-fast gate).
///
/// Produced before ANY task is spawned and before any pool/repository use:
/// an invalid configuration has zero runtime, durable or external side
/// effects — the caller simply refuses startup with this explicit error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "authorization archive worker config rejected: \
     claim_lease_seconds={claim_lease_seconds} must be within \
     1..={MAX_ARCHIVE_LEASE_SECONDS}"
)]
pub struct ArchiveConfigError {
    /// The offending configured claim-lease value.
    pub claim_lease_seconds: i64,
}

/// Start one owned archive task backed by the sqlx runtime. The caller MUST
/// keep the handle and invoke [`shutdown_authorization_archive_worker`].
///
/// # Errors
/// Returns [`ArchiveConfigError`] without spawning any task and without
/// touching `db` when `config.claim_lease_seconds` is outside
/// `1..=MAX_ARCHIVE_LEASE_SECONDS`.
pub fn start_authorization_archive_worker(
    db: MySqlPool,
    config: AuthorizationArchiveConfig,
) -> Result<AuthorizationArchiveWorkerHandle, ArchiveConfigError> {
    validate_claim_lease_seconds(config.claim_lease_seconds)?;
    let runtime: Arc<dyn AuthorizationArchiveRuntime> = Arc::new(
        SqlxAuthorizationArchiveRuntime::new(db, config.claim_lease_seconds),
    );
    start_authorization_archive_worker_with_runtime(runtime, config)
}

/// Fallible guard for the configured claim-lease window (Exec-L2 startup
/// validation). The repository's claim and heartbeat primitives both reject
/// lease seconds outside `1..=MAX_ARCHIVE_LEASE_SECONDS` mid-flight; this
/// gate converts that delayed, per-attempt failure mode into ONE explicit
/// [`ArchiveConfigError`] that both constructors return before any task is
/// spawned.
fn validate_claim_lease_seconds(claim_lease_seconds: i64) -> Result<(), ArchiveConfigError> {
    if (1..=MAX_ARCHIVE_LEASE_SECONDS).contains(&claim_lease_seconds) {
        Ok(())
    } else {
        Err(ArchiveConfigError {
            claim_lease_seconds,
        })
    }
}

/// Start one owned archive task on the supplied runtime seam. The caller MUST
/// keep the handle and invoke [`shutdown_authorization_archive_worker`].
///
/// # Errors
/// Returns [`ArchiveConfigError`] without spawning any task (the supplied
/// runtime stays completely untouched) when `config.claim_lease_seconds` is
/// outside `1..=MAX_ARCHIVE_LEASE_SECONDS`.
pub fn start_authorization_archive_worker_with_runtime(
    runtime: Arc<dyn AuthorizationArchiveRuntime>,
    config: AuthorizationArchiveConfig,
) -> Result<AuthorizationArchiveWorkerHandle, ArchiveConfigError> {
    validate_claim_lease_seconds(config.claim_lease_seconds)?;
    let cancellation = ArchiveCancellationToken::default();
    let run_cancellation = cancellation.clone();
    let run_id = uuid::Uuid::new_v4().to_string();
    let lease_owner = format!("auth-archive:{run_id}");
    if config.tenants.is_empty() {
        tracing::warn!(
            run_id = %run_id,
            "authorization archive worker started WITHOUT tenant scopes; \
             superseded generations stay unarchived until configuration exists"
        );
    }
    let join =
        tokio::spawn(
            async move { run_worker(runtime, config, lease_owner, run_cancellation).await },
        );
    Ok(AuthorizationArchiveWorkerHandle {
        cancellation,
        join,
        run_id,
    })
}

async fn run_worker(
    runtime: Arc<dyn AuthorizationArchiveRuntime>,
    config: AuthorizationArchiveConfig,
    lease_owner: String,
    cancellation: ArchiveCancellationToken,
) -> Result<ArchiveRunSummary, tokio::task::JoinError> {
    let mut ticker = tokio::time::interval(Duration::from_secs(config.poll_interval_secs.max(1)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut summary = ArchiveRunSummary::default();
    tracing::info!(
        workers_owner = %lease_owner,
        tenants = ?config.tenants,
        poll_interval_secs = config.poll_interval_secs,
        claim_lease_seconds = config.claim_lease_seconds,
        batch_per_tenant_per_cycle = MAX_INTENTS_PER_TENANT_PER_CYCLE,
        "authorization archive worker loop started"
    );
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = cancellation.cancelled() => {
                tracing::info!("authorization archive worker stopped cleanly");
                return Ok(summary);
            }
        }
        if cancellation.is_cancelled() {
            tracing::info!("authorization archive worker stopped between ticks");
            return Ok(summary);
        }
        if config.tenants.is_empty() {
            summary.no_work_cycles += 1;
            continue;
        }
        // Round-robin per tenant: an empty queue or claim failure skips only
        // THIS tenant's drain step, never the whole cycle.
        'tenant_cycle: for tenant_id in &config.tenants {
            for _ in 0..MAX_INTENTS_PER_TENANT_PER_CYCLE {
                if cancellation.is_cancelled() {
                    tracing::info!("authorization archive worker stopped mid-cycle");
                    return Ok(summary);
                }
                let claim_started = Instant::now();
                let claimed = match runtime
                    .claim_next_intent(*tenant_id, &lease_owner, config.claim_lease_seconds)
                    .await
                {
                    Ok(Some(claimed)) => claimed,
                    // No claimable intent right now (the claim predicate also
                    // hides future-scheduled PENDING rows): stop draining THIS
                    // tenant this cycle.
                    Ok(None) => {
                        summary.no_work_cycles += 1;
                        continue 'tenant_cycle;
                    }
                    Err(error) => {
                        // Transient DB failure on the claim path aborts THIS
                        // tenant's cycle (bounded, observed, retried next tick
                        // with fresh lease state). Never counted as claimed.
                        tracing::warn!(
                            tenant_id = *tenant_id,
                            error = %error,
                            claim_elapsed_us = claim_started.elapsed().as_micros() as u64,
                            "archive claim cycle failed"
                        );
                        continue 'tenant_cycle;
                    }
                };
                summary.intents_claimed += 1;
                process_one_intent(
                    &runtime,
                    &claimed,
                    &cancellation,
                    claim_started,
                    &mut summary,
                )
                .await;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-intent disposition funnels (single-write guarantees per class)
// ─────────────────────────────────────────────────────────────────────────────

async fn process_one_intent(
    runtime: &Arc<dyn AuthorizationArchiveRuntime>,
    claimed: &AuthorizationArchiveIntentClaim,
    cancellation: &ArchiveCancellationToken,
    claim_started: Instant,
    summary: &mut ArchiveRunSummary,
) {
    let total_started = Instant::now();
    tracing::debug!(
        event_id = %claimed.event_id,
        operation_id = %claimed.operation_id,
        archive_outbox_id = claimed.archive_outbox_id,
        archived_manifest_id = claimed.archived_manifest_id,
        archived_generation = claimed.archived_generation,
        attempts = claimed.attempts_after_install,
        claim_elapsed_us = claim_started.elapsed().as_micros() as u64,
        "archive intent claimed"
    );

    if cancellation.is_cancelled() {
        // Leave the short lease to expire server-side rather than racing a
        // mutation during shutdown (unknown-result avoidance beats busywork).
        tracing::info!(
            event_id = %claimed.event_id,
            archive_outbox_id = claimed.archive_outbox_id,
            "shutdown observed after claim; leaving archive lease to expire"
        );
        return;
    }

    let archive_started = Instant::now();
    let outcome = runtime.archive_claimed_intent(claimed).await;
    let archive_us = archive_started.elapsed().as_micros() as u64;

    match outcome {
        Ok(proven) => {
            if proven.resumed_existing_proof {
                summary.intents_resumed += 1;
            } else {
                summary.intents_archived += 1;
            }
            tracing::info!(
                event_id = %claimed.event_id,
                operation_id = %claimed.operation_id,
                archive_outbox_id = claimed.archive_outbox_id,
                archived_manifest_id = claimed.archived_manifest_id,
                archived_generation = claimed.archived_generation,
                archive_key = %claimed.archive_key,
                archive_digest = proven.proof.archive_digest.as_hex(),
                resumed_existing_proof = proven.resumed_existing_proof,
                attempts = claimed.attempts_after_install,
                archive_phase_us = archive_us,
                total_elapsed_us = total_started.elapsed().as_micros() as u64,
                "superseded generation durably archived (proof recorded and \
                 intent SUCCEEDED in one committed transaction)"
            );
        }
        Err(failure) => {
            // Phase timing evidence even for failures; details flow into the
            // per-class funnels below with stable observable reasons.
            tracing::debug!(
                event_id = %claimed.event_id,
                archive_outbox_id = claimed.archive_outbox_id,
                attempts = claimed.attempts_after_install,
                archive_phase_us = archive_us,
                total_elapsed_us = total_started.elapsed().as_micros() as u64,
                failure_class = ?classify_archive_failure(&failure),
                reason = %archive_failure_reason(&failure),
                "archive transaction refused; dispatching unified disposition"
            );
            dispatch_failure(runtime, claimed, &failure, summary).await;
        }
    }
}

/// THE single dispatch for every failed attempt. Each class issues AT MOST one
/// durable mutation (or none) and counts exactly once.
async fn dispatch_failure(
    runtime: &Arc<dyn AuthorizationArchiveRuntime>,
    claimed: &AuthorizationArchiveIntentClaim,
    failure: &ArchiveAttemptFailure,
    summary: &mut ArchiveRunSummary,
) {
    let lease = lease_proof_from_claim(claimed);
    match classify_archive_failure(failure) {
        FailureClass::Unknown => {
            // Lease/CAS outcome undetermined: NO further mutation of any kind
            // (no fail, no release-equivalent, no quarantine). The expired
            // lease expires server-side; reconciliation relies on durable
            // state exclusively.
            summary.intents_unknown += 1;
            tracing::warn!(
                event_id = %claimed.event_id,
                archive_outbox_id = claimed.archive_outbox_id,
                attempts = claimed.attempts_after_install,
                reason = %archive_failure_reason(failure),
                "archive lease/result UNKNOWN; zero follow-up mutation until \
                 reconciliation"
            );
        }
        FailureClass::Quarantine => {
            // Deterministic corruption/divergence: terminal QUARANTINED via
            // the REAL repository boundary. Attempt budgets NEVER gate this
            // path and exhausted budgets are never relabeled into it.
            let reason = archive_failure_reason(failure);
            let (reason_code, reason_detail) = quarantine_reason_parts(&reason);
            match runtime
                .quarantine_intent(&lease, &reason_code, &reason_detail)
                .await
            {
                Ok(()) => {
                    summary.intents_quarantined += 1;
                    tracing::error!(
                        event_id = %claimed.event_id,
                        operation_id = %claimed.operation_id,
                        archive_outbox_id = claimed.archive_outbox_id,
                        archived_manifest_id = claimed.archived_manifest_id,
                        archived_generation = claimed.archived_generation,
                        attempts = claimed.attempts_after_install,
                        quarantine_code = %reason_code,
                        "archive intent durably quarantined (terminal status \
                         written; off the claim queue until intervention)"
                    );
                }
                Err(quarantine_error) => {
                    summary.intents_unknown += 1;
                    tracing::warn!(
                        event_id = %claimed.event_id,
                        archive_outbox_id = claimed.archive_outbox_id,
                        attempts = claimed.attempts_after_install,
                        error = %quarantine_error,
                        "archive quarantine write refused/failed; outcome \
                         UNKNOWN, reconciliation required"
                    );
                }
            }
        }
        FailureClass::Retry => {
            let reason = archive_failure_reason(failure);
            fail_with_budget(
                runtime,
                &lease,
                claimed.attempts_after_install,
                &reason,
                summary,
            )
            .await;
        }
    }
}

/// THE single funnel every retryable archive failure flows through.
///
/// Reads the durable CURRENT attempts (post-install claim value), plans the
/// backoff exclusively via [`plan_archive_retry`], and issues EXACTLY ONE
/// failure mutation. Exhausted budgets hold the intent PENDING under the cap
/// backoff carrying the stable marker (infrastructure-recoverable; this slice
/// owns no operator requeue and never fakes terminality).
async fn fail_with_budget(
    runtime: &Arc<dyn AuthorizationArchiveRuntime>,
    lease: &ArchiveLeaseProof,
    attempts_current: i64,
    reason: &str,
    summary: &mut ArchiveRunSummary,
) {
    summary.intents_retried += 1;
    match plan_archive_retry(attempts_current) {
        ArchiveRetrySchedule::Continue { backoff_secs } => {
            tracing::debug!(
                event_id = %lease.event_id,
                archive_outbox_id = lease.archive_outbox_id,
                attempts = attempts_current,
                backoff_secs,
                "archive retry budget scheduled the next attempt"
            );
            runtime.fail_intent(lease, backoff_secs, reason).await;
        }
        ArchiveRetrySchedule::AttemptBudgetExhausted { backoff_secs } => {
            summary.intents_budget_exhausted += 1;
            let marked_reason =
                format!("{reason};{ATTEMPT_BUDGET_EXHAUSTED_CODE};attempts={attempts_current}");
            tracing::warn!(
                event_id = %lease.event_id,
                archive_outbox_id = lease.archive_outbox_id,
                attempts = attempts_current,
                backoff_secs,
                reason = %marked_reason,
                "archive attempt budget exhausted; holding PENDING under the \
                 maximal backoff with a stable exhaustion marker"
            );
            runtime
                .fail_intent(lease, backoff_secs, &marked_reason)
                .await;
        }
    }
}

/// Build the lease guard exactly once from the strict claim DTO; never logged
/// (token Debug is redacted, and the raw token is not part of any trace call).
fn lease_proof_from_claim(claimed: &AuthorizationArchiveIntentClaim) -> ArchiveLeaseProof {
    ArchiveLeaseProof {
        archive_outbox_id: claimed.archive_outbox_id,
        event_id: claimed.event_id.clone(),
        lease_owner: claimed.lease_owner.clone(),
        lease_token: claimed.lease_token.clone(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Runtime seam: every DB transaction boundary lives behind this trait so each
// disposition branch stays unit-testable without MySQL.
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait AuthorizationArchiveRuntime: Send + Sync + 'static {
    /// One short-lived claim transaction over the REAL repository primitive:
    /// installs the LEASED owner/run-scoped token (expired leases reclaimable),
    /// commits BOTH arms (`Some(installed lease)` and `Ok(None)` snapshot) so
    /// the claim itself is always durable-or-absent, never half-open.
    ///
    /// The claim DTO embeds a strict decode/readback performed by astral-db
    /// inside the SAME transaction (candidate lock → install → expiry+
    /// counters readback), so callers MUST NOT second-guess it with
    /// hand-written SQL.
    async fn claim_next_intent(
        &self,
        tenant_id: i64,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<AuthorizationArchiveIntentClaim>, ArchiveAccessError>;

    /// ONE short durable transaction proving and closing one claimed intent:
    /// lock the archived parent manifest FIRST through the claim's immutable
    /// manifest id (the archive family's unified parent→outbox lock order),
    /// re-lock the intent, strictly re-read the archivable parent chain
    /// digest, heartbeat the live lease before and after the expensive work,
    /// assemble the typed proof request from THOSE locked facts, record the
    /// durable proof (immutable-equal replay resumes), flip the intent
    /// `SUCCEEDED` behind the live-lease guard, commit once. Any intermediate
    /// error rolls proof AND flip back together atomically.
    async fn archive_claimed_intent(
        &self,
        claimed: &AuthorizationArchiveIntentClaim,
    ) -> Result<ArchiveOutcome, ArchiveAttemptFailure>;

    /// Record a durable failure + bounded backoff honoring future
    /// `next_attempt_at`. Loss of the lease CAS is reconciled (logged, UNKNOWN)
    /// instead of retried blindly.
    async fn fail_intent(&self, lease: &ArchiveLeaseProof, backoff_seconds: i64, last_error: &str);

    /// Durable terminal quarantine of one leased intent via the live-lease
    /// guarded repository boundary.
    ///
    /// `Ok(())` proves the row left the claimable queue as QUARANTINED. Any
    /// error means UNKNOWN: callers record it and issue NO further mutation
    /// for that intent until reconciliation. Quarantine keeps `cas_version`
    /// untouched so a future operator tooling path retains its fence anchor.
    async fn quarantine_intent(
        &self,
        lease: &ArchiveLeaseProof,
        reason_code: &str,
        reason_detail: &str,
    ) -> Result<(), ArchiveAccessError>;
}

pub struct SqlxAuthorizationArchiveRuntime {
    pool: MySqlPool,
    /// The configured claim-lease window in seconds. Reused verbatim as the
    /// in-transaction heartbeat renewal budget, so lease renewals always
    /// extend the lease by exactly the same window the claim granted (never a
    /// magic constant).
    lease_seconds: i64,
}

impl SqlxAuthorizationArchiveRuntime {
    pub fn new(pool: MySqlPool, lease_seconds: i64) -> Self {
        Self {
            pool,
            lease_seconds,
        }
    }

    /// The fixed in-transaction proof sequence. Kept as one private helper so
    /// the ordering contract lives in exactly one place and the source scan
    /// can pin it.
    ///
    /// Lock order = the archive family's unified parent-manifest→outbox
    /// direction (mirroring ensure/record/complete in astral-db), so a
    /// concurrent publish/ensure can never AB-BA against this transaction:
    /// 1. the archived parent manifest is locked FIRST through the claim's
    ///    IMMUTABLE `archived_manifest_id` — a lock-acquisition key only,
    ///    never evidence;
    /// 2. the outbox intent is re-locked by its stable event identity and
    ///    authoritatively re-validated (cross-checked against the locked
    ///    parent, still `LEASED` for OUR lease);
    /// 3. the lease is heartbeated (renewed) BEFORE any expensive chain/proof
    ///    work and AGAIN after the proof record immediately before the
    ///    terminal flip, using the configured claim lease seconds; every
    ///    lease/CAS refusal propagates as a Repository error (`LeaseCasFailed`
    ///    classifies UNKNOWN with zero follow-up);
    /// 4. the typed proof request is built STRICTLY from the in-transaction
    ///    locked facts, the durable proof is recorded, and only then is the
    ///    intent flipped `SUCCEEDED`. Proof precedes ACK; a rollback removes
    ///    proof AND completion together.
    async fn record_and_flip_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        claimed: &AuthorizationArchiveIntentClaim,
        lease_seconds: i64,
    ) -> Result<ArchiveOutcome, ArchiveAttemptFailure> {
        let lease = lease_proof_from_claim(claimed);

        // (1) Parent manifest lock FIRST, keyed by the claim's immutable
        // manifest id (lock acquisition only — every proof fact below is
        // re-made on authoritative locked reads). `Ok(None)` means the
        // referenced manifest row no longer exists: deterministic dangling
        // evidence that no retry can restore.
        let chain_digest =
            load_archivable_manifest_chain_digest_in_tx(tx, claimed.archived_manifest_id)
                .await?
                .ok_or_else(|| {
                    ArchiveAttemptFailure::EvidenceMissing(format!(
                        "code=auth_archive_worker.parent_manifest_readback_missing;manifest={}",
                        claimed.archived_manifest_id
                    ))
                })?;

        // (2) Authoritative intent validation: re-lock and strictly re-decode
        // the intent by its stable event identity, cross-check it against the
        // locked parent, and proceed only while it is still LEASED for OUR
        // lease. Anything else is a contract anomaly relative to OUR claim
        // (another owner won after the lease expired) and must not be
        // laundered; unexpected status drift stays a transient retry.
        let intent =
            load_authorization_archive_intent_in_tx(tx, &claimed.identity, &claimed.event_id)
                .await?
                .ok_or_else(|| {
                    ArchiveAttemptFailure::EvidenceMissing(format!(
                        "code=auth_archive_worker.intent_readback_missing;event={}",
                        claimed.event_id
                    ))
                })?;
        if intent.archived_manifest_id != claimed.archived_manifest_id {
            return Err(ArchiveAttemptFailure::Contract(format!(
                "code=auth_archive_worker.intent_manifest_crosscheck_failed;event={};\
                 claimed_manifest={};intent_manifest={}",
                claimed.event_id, claimed.archived_manifest_id, intent.archived_manifest_id
            )));
        }
        if !matches!(intent.status, AuthorizationArchiveOutboxStatus::Leased) {
            return Err(ArchiveAttemptFailure::Contract(format!(
                "code=auth_archive_worker.intent_unexpected_status;event={};status={}",
                claimed.event_id, intent.status
            )));
        }

        // (3) Lease heartbeat BEFORE the expensive parent-chain/proof work:
        // renew the live lease inside this transaction by the configured
        // window, and fail closed when the lease already expired (never
        // renew an expired lease into a proof session — the refusal
        // classifies UNKNOWN with zero follow-up and everything rolls back).
        heartbeat_authorization_archive_intent_lease(&mut **tx, &lease, lease_seconds).await?;

        // (4) Typed proof request built EXCLUSIVELY from THIS transaction's
        // locked facts (intent row + parent manifest row). The claim payload
        // participates nowhere except as the claim expectation that earlier
        // verification cross-checked; record re-proves EVERY immutable
        // dimension (identity/card/provenance/fence/generation/key/hashes)
        // against the locked intent AND the entire sealed chain again.
        let request = AuthorizationArchiveProofRequest {
            identity: intent.identity.clone(),
            card_id: intent.card_id,
            archived_manifest_id: intent.archived_manifest_id,
            archived_generation: intent.archived_generation,
            event_id: intent.event_id.clone(),
            operation_id: intent.operation_id.clone(),
            archive_key: intent.archive_key.clone(),
            semantic_hash_hex: intent.semantic_hash.as_hex(),
            dependency_hash_hex: intent.dependency_hash.as_hex(),
            compiler_version: intent.compiler_version.clone(),
            archived_revoke_fence: intent.archived_revoke_fence,
            manifest_chain_digest_hex: chain_digest.as_hex(),
        };

        // Resume detection INSIDE the same locked transaction: an existing
        // byte-equal proof from a previously committed transaction means this
        // attempt completes a resume (the terminal flip was still owed).
        let resumed_existing_proof = load_authorization_archive_proof_in_tx(
            tx,
            &intent.identity,
            intent.archived_generation,
        )
        .await?
        .is_some();

        // (5) Durable proof FIRST. Immutable-equal replay is supported and
        // returns the existing winner; any divergence raises an explicit
        // conflict (classified deterministically).
        let proof = record_authorization_archive_proof_in_tx(tx, &request).await?;

        // (6) Lease heartbeat AGAIN after the proof record: the full-chain
        // verification above can outlive the remaining lease window, and the
        // terminal flip below re-checks `lease_expires_at > UTC_TIMESTAMP()`.
        heartbeat_authorization_archive_intent_lease(&mut **tx, &lease, lease_seconds).await?;

        // (7) Terminal flip LAST, guarded by the live lease. Proof always
        // precedes the ACK-only-looking terminal write; both die together on
        // rollback before commit.
        complete_authorization_archive_intent(tx, &lease).await?;
        Ok(ArchiveOutcome {
            proof,
            resumed_existing_proof,
        })
    }
}

#[async_trait]
impl AuthorizationArchiveRuntime for SqlxAuthorizationArchiveRuntime {
    async fn claim_next_intent(
        &self,
        tenant_id: i64,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<AuthorizationArchiveIntentClaim>, ArchiveAccessError> {
        let mut tx = self.pool.begin().await?;
        // Card-scoped intents have no separate queue today: publisher intents
        // are written unscoped-by-card ordering key (COALESCE(next_attempt_at,
        // created_at)), so the unscaled claim scope observes all of them; card
        // filtering stays a repository concern wired when a scoped producer
        // exists. `None` documents that contract explicitly.
        let claim = claim_next_authorization_archive_intent_in_tx(
            &mut tx,
            tenant_id,
            None,
            lease_owner,
            lease_seconds,
        )
        .await?;
        tx.commit().await?;
        Ok(claim)
    }

    async fn archive_claimed_intent(
        &self,
        claimed: &AuthorizationArchiveIntentClaim,
    ) -> Result<ArchiveOutcome, ArchiveAttemptFailure> {
        let mut tx = self.pool.begin().await?;
        // Renewals reuse the CONFIGURED claim-lease window (validated at
        // worker startup), never a magic constant.
        let outcome = Self::record_and_flip_in_tx(&mut tx, claimed, self.lease_seconds).await?;
        tx.commit().await?;
        Ok(outcome)
    }

    async fn fail_intent(&self, lease: &ArchiveLeaseProof, backoff_seconds: i64, last_error: &str) {
        if let Err(error) =
            fail_authorization_archive_intent(&self.pool, lease, backoff_seconds, last_error).await
        {
            reconcile_archive_mutation_loss(&lease.event_id, "fail", &error);
        }
    }

    async fn quarantine_intent(
        &self,
        lease: &ArchiveLeaseProof,
        reason_code: &str,
        reason_detail: &str,
    ) -> Result<(), ArchiveAccessError> {
        let composed_reason = format!("code={reason_code};detail={reason_detail}");
        mark_authorization_archive_intent_quarantined(&self.pool, lease, &composed_reason)
            .await
            .map_err(ArchiveAccessError::from)
    }
}

/// A lease-guarded archive mutation matched zero rows (expired/stolen/
/// terminal/doubtful). That is an UNKNOWN result requiring reconciliation
/// BEFORE any further mutation on the intent — never a blind repetition.
fn reconcile_archive_mutation_loss(
    event_id: &str,
    mutation: &str,
    error: &AuthorizationProjectionError,
) {
    tracing::warn!(
        event_id = %event_id,
        mutation,
        error = %error,
        "archive lease mutation matched zero rows; treating as UNKNOWN, \
         reconciliation required before any retry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (pure + fake-runtime; MySQL-backed integration is an explicit suite,
// NEVER pretended by unit shape tests)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use astral_db::{ProjectionAggregateIdentity, Sha256Digest};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use time::{Date, Month, PrimitiveDateTime, Time};

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn stamp() -> PrimitiveDateTime {
        PrimitiveDateTime::new(
            Date::from_calendar_date(2026, Month::August, 26).unwrap(),
            Time::MIDNIGHT,
        )
    }

    fn digest(hex: &'static str) -> Sha256Digest {
        Sha256Digest::from_hex(hex).unwrap()
    }

    fn identity() -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap()
    }

    fn proof_fixture() -> AuthorizationArchiveManifestProof {
        AuthorizationArchiveManifestProof {
            archive_manifest_id: 5001,
            identity: identity(),
            card_id: None,
            archived_manifest_id: 44,
            archived_generation: 3,
            event_id: "evt-parent-3".to_owned(),
            operation_id: "op-parent-3".to_owned(),
            archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
            semantic_hash: digest(HASH_A),
            dependency_hash: digest(HASH_B),
            compiler_version: "compiler-v1".to_owned(),
            archived_revoke_fence: 2,
            archive_digest: digest(HASH_C),
            status: astral_db::AuthorizationArchiveManifestStatus::Archived,
            cas_version: 1,
            archived_at: Some(stamp()),
        }
    }

    fn claim_fixture(attempts: i64) -> AuthorizationArchiveIntentClaim {
        AuthorizationArchiveIntentClaim {
            archive_outbox_id: 900,
            identity: identity(),
            card_id: None,
            archived_manifest_id: 44,
            archived_generation: 3,
            event_id: "evt-parent-3".to_owned(),
            operation_id: "op-parent-3".to_owned(),
            archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
            semantic_hash: digest(HASH_A),
            dependency_hash: digest(HASH_B),
            compiler_version: "compiler-v1".to_owned(),
            archived_revoke_fence: 2,
            status_before_claim_str: "PENDING".to_owned(),
            attempts_after_install: attempts,
            cas_version_after_claim: attempts + 10,
            lease_owner: "auth-archive:test-run".to_owned(),
            lease_token: astral_db::ArchiveLeaseToken::for_test("secret-run-token"),
            lease_expires_at: stamp(),
        }
    }

    // ── Bounded backoff / attempt-budget policy ─────────────────────────────

    #[test]
    fn backoff_schedule_is_bounded_and_doubles() {
        assert_eq!(archive_backoff_secs(0), 1);
        assert_eq!(archive_backoff_secs(1), 1);
        assert_eq!(archive_backoff_secs(2), 2);
        assert_eq!(archive_backoff_secs(4), 8);
        let cap = clamp_backoff(i64::MAX);
        assert_eq!(cap, ARCHIVE_BACKOFF_CAP_SECS);
        assert!(cap <= MAX_ARCHIVE_BACKOFF_SECONDS);
        for attempts in [-5i64, 0, 5, 6, 100] {
            assert!(
                archive_backoff_secs(attempts) >= 1 && archive_backoff_secs(attempts) <= cap,
                "backoff must stay within bounds"
            );
        }
    }

    #[test]
    fn retry_plan_marks_budget_exhaustion_at_the_cap() {
        for within in [1i64, 2, 3, MAX_ARCHIVE_INTENT_ATTEMPTS - 1] {
            match plan_archive_retry(within) {
                ArchiveRetrySchedule::Continue { backoff_secs } => {
                    assert_eq!(backoff_secs, archive_backoff_secs(within));
                }
                other => panic!("attempts={within} must stay in-budget, got {other:?}"),
            }
        }
        for exhausted in [MAX_ARCHIVE_INTENT_ATTEMPTS, 6, 50] {
            match plan_archive_retry(exhausted) {
                ArchiveRetrySchedule::AttemptBudgetExhausted { backoff_secs } => {
                    assert_eq!(backoff_secs, ARCHIVE_BACKOFF_CAP_SECS);
                }
                other => panic!("attempts={exhausted} must be exhausted, got {other:?}"),
            }
        }
    }

    // ── Fallible claim-lease configuration gate ─────────────────────────────

    #[test]
    fn claim_lease_gate_accepts_the_closed_valid_range() {
        for valid in [
            1,
            2,
            ARCHIVE_CLAIM_LEASE_SECS,
            MAX_ARCHIVE_LEASE_SECONDS - 1,
            MAX_ARCHIVE_LEASE_SECONDS,
        ] {
            assert!(
                validate_claim_lease_seconds(valid).is_ok(),
                "claim_lease_seconds={valid} must be accepted"
            );
        }
    }

    #[test]
    fn claim_lease_gate_rejects_every_out_of_range_value_as_a_normal_error() {
        for invalid in [
            0,
            -1,
            -120,
            MAX_ARCHIVE_LEASE_SECONDS + 1,
            i64::MIN,
            i64::MAX,
        ] {
            let error = validate_claim_lease_seconds(invalid)
                .expect_err("out-of-range claim_lease_seconds must be rejected fallibly");
            assert_eq!(error.claim_lease_seconds, invalid);
            let message = error.to_string();
            assert!(
                message.contains(&format!("claim_lease_seconds={invalid}")),
                "rejection must name the offending value, got: {message}"
            );
            assert!(
                message.contains(&format!("1..={MAX_ARCHIVE_LEASE_SECONDS}")),
                "rejection must name the accepted closed range, got: {message}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_lease_config_returns_error_without_spawning_or_touching_the_runtime() {
        // Any touch (the interval's immediate first tick would claim at once)
        // flips this flag: an invalid config must return a NORMAL startup
        // error and leave the runtime completely untouched — no spawned task,
        // no panic.
        struct TouchedOnClaimRuntime(Arc<AtomicBool>);
        #[async_trait]
        impl AuthorizationArchiveRuntime for TouchedOnClaimRuntime {
            async fn claim_next_intent(
                &self,
                _t: i64,
                _o: &str,
                _l: i64,
            ) -> Result<Option<AuthorizationArchiveIntentClaim>, ArchiveAccessError> {
                self.0.store(true, Ordering::Release);
                Ok(None)
            }
            async fn archive_claimed_intent(
                &self,
                _: &AuthorizationArchiveIntentClaim,
            ) -> Result<ArchiveOutcome, ArchiveAttemptFailure> {
                unreachable!()
            }
            async fn fail_intent(&self, _: &ArchiveLeaseProof, _: i64, _: &str) {
                unreachable!()
            }
            async fn quarantine_intent(
                &self,
                _: &ArchiveLeaseProof,
                _: &str,
                _: &str,
            ) -> Result<(), ArchiveAccessError> {
                unreachable!()
            }
        }
        for invalid in [0, MAX_ARCHIVE_LEASE_SECONDS + 1] {
            let touched = Arc::new(AtomicBool::new(false));
            let Err(error) = start_authorization_archive_worker_with_runtime(
                Arc::new(TouchedOnClaimRuntime(touched.clone()))
                    as Arc<dyn AuthorizationArchiveRuntime>,
                AuthorizationArchiveConfig {
                    tenants: vec![7],
                    poll_interval_secs: 1,
                    claim_lease_seconds: invalid,
                },
            ) else {
                panic!("invalid claim_lease_seconds={invalid} must refuse to start");
            };
            assert_eq!(error.claim_lease_seconds, invalid);
            assert!(
                error
                    .to_string()
                    .contains(&format!("claim_lease_seconds={invalid}")),
                "the startup error must name the offending value: {error}"
            );
            // Give a hypothetically spawned task ample chance to run its
            // immediate first tick; the runtime must remain untouched.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !touched.load(Ordering::Acquire),
                "invalid config must not spawn a task that reaches the runtime"
            );
        }
    }

    #[tokio::test]
    async fn invalid_lease_config_refuses_the_sqlx_constructor_before_any_pool_use() {
        // `connect_lazy` never touches the network during construction; the
        // sqlx-backed constructor must reject the config BEFORE the pool is
        // even moved into the runtime, so nothing can be spawned and no
        // connection can possibly be attempted.
        let pool = MySqlPool::connect_lazy("mysql://localhost:1/astral_test").unwrap();
        let Err(error) = start_authorization_archive_worker(
            pool,
            AuthorizationArchiveConfig {
                tenants: vec![7],
                poll_interval_secs: 1,
                claim_lease_seconds: MAX_ARCHIVE_LEASE_SECONDS + 1,
            },
        ) else {
            panic!("invalid config must refuse the sqlx-backed constructor");
        };
        assert_eq!(error.claim_lease_seconds, MAX_ARCHIVE_LEASE_SECONDS + 1);
    }

    #[tokio::test]
    async fn valid_config_starts_and_propagates_the_configured_lease_to_the_runtime() {
        // The started task must hand the CONFIGURED claim-lease seconds to
        // the runtime seam (the same value the heartbeat renewals reuse), and
        // the fallible constructor must return a usable Ok handle.
        struct LeaseRecordingRuntime(Mutex<Vec<i64>>);
        #[async_trait]
        impl AuthorizationArchiveRuntime for LeaseRecordingRuntime {
            async fn claim_next_intent(
                &self,
                _tenant_id: i64,
                _owner: &str,
                lease_seconds: i64,
            ) -> Result<Option<AuthorizationArchiveIntentClaim>, ArchiveAccessError> {
                self.0.lock().unwrap().push(lease_seconds);
                Ok(None)
            }
            async fn archive_claimed_intent(
                &self,
                _: &AuthorizationArchiveIntentClaim,
            ) -> Result<ArchiveOutcome, ArchiveAttemptFailure> {
                unreachable!()
            }
            async fn fail_intent(&self, _: &ArchiveLeaseProof, _: i64, _: &str) {
                unreachable!()
            }
            async fn quarantine_intent(
                &self,
                _: &ArchiveLeaseProof,
                _: &str,
                _: &str,
            ) -> Result<(), ArchiveAccessError> {
                unreachable!()
            }
        }
        let configured = ARCHIVE_CLAIM_LEASE_SECS + 1;
        let runtime = Arc::new(LeaseRecordingRuntime(Mutex::new(Vec::new())));
        let handle = start_authorization_archive_worker_with_runtime(
            runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>,
            AuthorizationArchiveConfig {
                tenants: vec![7],
                poll_interval_secs: 1,
                claim_lease_seconds: configured,
            },
        )
        .expect("in-range config must start the worker");
        assert!(!handle.run_id.is_empty(), "run-scoped id must be present");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let report = shutdown_authorization_archive_worker(handle, Duration::from_secs(3)).await;
        assert!(report.summary.is_ok(), "worker must stop cleanly");
        assert_eq!(
            *runtime.0.lock().unwrap(),
            vec![configured],
            "the started worker must hand the CONFIGURED lease seconds to the runtime"
        );
    }

    #[test]
    fn default_claim_lease_stays_within_the_repository_lease_bounds() {
        let config = AuthorizationArchiveConfig::default();
        validate_claim_lease_seconds(config.claim_lease_seconds)
            .expect("default claim lease must stay within repository bounds");
        assert!(config.claim_lease_seconds >= 1);
        assert!(config.claim_lease_seconds <= MAX_ARCHIVE_LEASE_SECONDS);
    }

    // ── Structural classification ───────────────────────────────────────────

    fn repository(error: AuthorizationProjectionError) -> ArchiveAttemptFailure {
        ArchiveAttemptFailure::Repository(error)
    }

    #[test]
    fn classification_routes_every_variant_structurally() {
        let quarantine_cases = [
            repository(AuthorizationProjectionError::ImmutableConflict(
                "code=x".to_owned(),
            )),
            repository(AuthorizationProjectionError::Corrupt("code=y".to_owned())),
            repository(AuthorizationProjectionError::IdentityMismatch(
                "code=z".to_owned(),
            )),
            repository(AuthorizationProjectionError::SegmentDigestCollision(
                "code=w".to_owned(),
            )),
            repository(AuthorizationProjectionError::Mapping(
                "unknown_status".to_owned(),
            )),
            repository(AuthorizationProjectionError::ScopeViolation(
                "invalid_field".to_owned(),
            )),
            repository(AuthorizationProjectionError::IllegalStatusTransition {
                from: "A".to_owned(),
                to: "B".to_owned(),
            }),
            // Missing durable evidence (intent or parent row absent under
            // lock) is deterministic: retry can never restore absent rows.
            ArchiveAttemptFailure::EvidenceMissing(
                "code=auth_archive_worker.intent_readback_missing;event=evt-1".to_owned(),
            ),
            ArchiveAttemptFailure::EvidenceMissing(
                "code=auth_archive_worker.parent_manifest_readback_missing;manifest=44".to_owned(),
            ),
        ];
        for case in &quarantine_cases {
            assert_eq!(
                classify_archive_failure(case),
                FailureClass::Quarantine,
                "{case:?} must route deterministically to terminal quarantine"
            );
        }

        let unknown_cases = [
            repository(AuthorizationProjectionError::LeaseCasFailed(
                "lost_lease".to_owned(),
            )),
            repository(AuthorizationProjectionError::ClaimRace),
        ];
        for case in &unknown_cases {
            assert_eq!(
                classify_archive_failure(case),
                FailureClass::Unknown,
                "{case:?} must route to UNKNOWN zero-follow-up"
            );
        }

        let retry_cases = [
            repository(AuthorizationProjectionError::NotReady(
                "parent_not_archivable".to_owned(),
            )),
            repository(AuthorizationProjectionError::DuplicateRow(
                "race_unknown_winner".to_owned(),
            )),
            repository(AuthorizationProjectionError::Query(
                sqlx::Error::RowNotFound,
            )),
            ArchiveAttemptFailure::Database("connection refused".to_owned()),
            // Unexpected intent status drift (e.g. another owner won the
            // expired lease) stays a transient retry — the durable state may
            // legitimately move on without this attempt.
            ArchiveAttemptFailure::Contract(
                "code=auth_archive_worker.intent_unexpected_status;event=evt-1;status=PENDING"
                    .to_owned(),
            ),
            ArchiveAttemptFailure::Contract(
                "code=auth_archive_worker.intent_manifest_crosscheck_failed;event=evt-1;\
                 claimed_manifest=44;intent_manifest=45"
                    .to_owned(),
            ),
        ];
        for case in &retry_cases {
            assert_eq!(
                classify_archive_failure(case),
                FailureClass::Retry,
                "{case:?} must route to bounded-backoff retry"
            );
        }
    }

    #[test]
    fn failure_reasons_keep_a_stable_short_code_prefix() {
        let reason = archive_failure_reason(&repository(AuthorizationProjectionError::ClaimRace));
        assert!(reason.starts_with("code=auth_archive_worker.claim_race;detail="));
        let (code, detail) = quarantine_reason_parts(&reason);
        assert_eq!(code, "auth_archive_worker.claim_race");
        assert!(!detail.is_empty());
        // Database/Contract/EvidenceMissing anomalies get their own stable
        // codes.
        assert!(
            archive_failure_reason(&ArchiveAttemptFailure::Database("x".into()))
                .starts_with("code=auth_archive_worker.database_query_failed")
        );
        assert!(
            archive_failure_reason(&ArchiveAttemptFailure::Contract("y".into()))
                .starts_with("code=auth_archive_worker.contract_anomaly")
        );
        let missing_reason = archive_failure_reason(&ArchiveAttemptFailure::EvidenceMissing(
            "code=auth_archive_worker.intent_readback_missing;event=evt-1".into(),
        ));
        assert!(
            missing_reason.starts_with("code=auth_archive_worker.evidence_missing;detail="),
            "missing evidence must compose its own stable code: {missing_reason}"
        );
        // The code prefix must always survive the repository's durable clamp.
        assert!(
            code.chars().count() <= QUARANTINE_REASON_CODE_LIMIT,
            "codes must stay short enough for the durable last_error column"
        );
        // The composed quarantine decomposition keeps the stable code intact.
        let (missing_code, missing_detail) = quarantine_reason_parts(&missing_reason);
        assert_eq!(missing_code, "auth_archive_worker.evidence_missing");
        assert!(
            missing_detail.contains("intent_readback_missing"),
            "full evidence must survive into the quarantine detail"
        );
    }

    #[test]
    fn quarantine_reason_parts_fallback_keeps_full_evidence() {
        let (code, detail) = quarantine_reason_parts("free-form operator text");
        assert_eq!(code, GENERIC_QUARANTINE_FALLBACK_CODE);
        assert_eq!(detail, "free-form operator text");

        let long_code = format!("code={}", "x".repeat(80));
        let (code, detail) = quarantine_reason_parts(&long_code);
        assert_eq!(code, GENERIC_QUARANTINE_FALLBACK_CODE);
        assert_eq!(detail, long_code);

        let (code, _) = quarantine_reason_parts("code=stable_code;some detail;more");
        assert_eq!(code, "stable_code");
    }

    // ── Source-shape guards: banned legacy/publish symbols in this file ────

    /// Symbols whose appearance ANYWHERE in this file's production half would
    /// break the slice's hard boundaries: legacy snapshot/outbox surfaces,
    /// cache/MQ side channels, and the delta publish pipeline (the archive
    /// worker must NEVER publish current authorization state).
    const FORBIDDEN_PRODUCTION_SYMBOLS: [&str; 16] = [
        "rebuild_card_snapshot_inner",
        "rebuild_rule_set_snapshot_inner",
        "permission_rule_snapshot",
        "rule_set_snapshot",
        "authorization_projection_outbox\"",
        "observe_current_pointer",
        "publish_permission_refresh",
        "PermissionRefreshPayload",
        "evict_card_cache",
        "mark_aggregate_projected_for_event",
        "project_authorization_delta_in_tx",
        "complete_delta_event",
        "claim_next_delta_event_in_tx",
        "load_claimed_delta_event_for_update_in_tx",
        "release_delta_event_lease",
        "fail_delta_event",
    ];

    /// Reusable extraction of the FULL production source (everything before
    /// the unique module-level test section), mirroring the projector guard.
    fn production_source_slice(full_source: &'static str) -> &'static str {
        const TEST_SECTION_MARKER: &str = "\n#[cfg(test)]\nmod tests";
        let first = full_source.find(TEST_SECTION_MARKER).unwrap_or_else(|| {
            panic!("module-level test section marker missing; production scan refused")
        });
        assert!(
            !full_source[first + TEST_SECTION_MARKER.len()..].contains(TEST_SECTION_MARKER),
            "multiple module-level test sections detected; slice would be ambiguous"
        );
        &full_source[..first + 1]
    }

    fn assert_no_forbidden_symbols(production: &str, context: &str) {
        for banned in FORBIDDEN_PRODUCTION_SYMBOLS {
            assert!(
                !production.contains(banned),
                "{context}: archive worker must not reference forbidden symbol {banned}"
            );
        }
    }

    #[test]
    fn archive_worker_source_is_clean_of_legacy_and_publish_symbols() {
        let source = include_str!("authorization_archive_worker.rs");
        let production = production_source_slice(source);
        assert!(
            !production.contains("#[cfg(test)]"),
            "production slice must be cut at the unique module-level test section"
        );

        // Coverage anchors across the whole file so late-file symbols are seen.
        assert!(production.contains("fn plan_archive_retry("));
        assert!(production.contains("async fn run_worker("));
        assert!(production.contains("async fn dispatch_failure("));
        assert!(production.contains("fn classify_archive_failure("));

        assert_no_forbidden_symbols(production, "authorization_archive_worker.rs");

        // The REAL durable archive primitives are required in the production
        // half (never mocks-only shapes): claim → parent lock → strict
        // reads → heartbeat renewals → proof → flip.
        for required in [
            "claim_next_authorization_archive_intent_in_tx(",
            "load_authorization_archive_intent_in_tx(",
            "load_archivable_manifest_chain_digest_in_tx(",
            "load_authorization_archive_proof_in_tx(",
            "heartbeat_authorization_archive_intent_lease(",
            "record_authorization_archive_proof_in_tx(",
            "complete_authorization_archive_intent(",
            "fail_authorization_archive_intent(",
            "mark_authorization_archive_intent_quarantined(",
        ] {
            assert!(
                production.contains(required),
                "production half must contain {required}"
            );
        }
        // Proof strictly precedes the terminal flip inside the source order
        // (belt-and-braces over the compiler-enforced call ordering).
        let record_at = production
            .find("record_authorization_archive_proof_in_tx(tx, &request)")
            .expect("record call must exist in the fixed sequence");
        let complete_at = production
            .find("complete_authorization_archive_intent(tx,")
            .expect("complete call must exist in the fixed sequence");
        assert!(record_at < complete_at, "proof MUST precede the flip");

        // Unified archive lock order pinned in source: the parent manifest is
        // locked through the claimed IMMUTABLE manifest id BEFORE the
        // authoritative outbox intent re-read (no ABBA against ensure/record/
        // complete).
        let parent_lock_at = production
            .find("load_archivable_manifest_chain_digest_in_tx(tx, claimed.archived_manifest_id)")
            .expect("parent manifest must be locked via the claimed immutable manifest id");
        let intent_read_at = production
            .find("load_authorization_archive_intent_in_tx(tx, &claimed.identity")
            .expect("authoritative intent re-read must exist");
        let manifest_crosscheck_at = production
            .find("intent_manifest_crosscheck_failed")
            .expect("parent/intent manifest cross-check must exist");
        assert!(
            parent_lock_at < intent_read_at,
            "parent manifest lock MUST precede the outbox intent re-read"
        );
        assert!(
            intent_read_at < manifest_crosscheck_at,
            "manifest cross-check MUST follow the authoritative intent re-read"
        );

        // Both lease heartbeats pinned in source: the first renewal follows
        // the intent validation and precedes the expensive proof record; the
        // second renewal follows the proof record and precedes the terminal
        // flip (so the flip's live-lease expiry re-check passes after long
        // chain work).
        let heartbeat_needle = "heartbeat_authorization_archive_intent_lease(";
        let heartbeat_first = production
            .find(heartbeat_needle)
            .expect("pre-proof lease heartbeat must exist");
        let heartbeat_last = production
            .rfind(heartbeat_needle)
            .expect("post-proof lease heartbeat must exist");
        assert_ne!(
            heartbeat_first, heartbeat_last,
            "exactly two heartbeat call sites are required (pre-proof and pre-flip)"
        );
        assert!(
            intent_read_at < heartbeat_first && heartbeat_first < record_at,
            "the first heartbeat MUST sit between intent validation and the proof record"
        );
        assert!(
            record_at < heartbeat_last && heartbeat_last < complete_at,
            "the second heartbeat MUST sit between the proof record and the terminal flip"
        );
    }

    #[test]
    fn symbol_guard_self_test_proves_late_production_symbol_detection() {
        let fixture_source: &'static str = concat!(
            "fn plan_archive_retry() {}\n",
            "async fn run_worker(runtime) {}\n",
            "\n",
            "// late-half offender:\n",
            "evict_card_cache();\n",
        );
        let panic_payload = std::panic::catch_unwind(|| {
            assert_no_forbidden_symbols(fixture_source, "fixture");
        })
        .expect_err("scanner MUST reject forbidden symbols appearing late");
        let message = panic_payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| {
                panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
            })
            .unwrap_or_default();
        assert!(
            message.contains("evict_card_cache"),
            "panic must name the offending symbol, got: {message}"
        );
    }

    // ── Fake-runtime lifecycle tests ────────────────────────────────────────

    #[derive(Debug, Clone)]
    enum RecordedCall {
        RecordAndFlipOk,
        RecordAndFlipErr,
        Fail {
            backoff_seconds: i64,
            reason: String,
        },
        Quarantine {
            code: String,
            detail: String,
        },
    }

    #[derive(Debug)]
    enum ClaimStep {
        Claim(Box<AuthorizationArchiveIntentClaim>),
        AccessError(String),
    }

    struct RecordingRuntime {
        claims: Mutex<VecDeque<ClaimStep>>,
        calls: Mutex<Vec<RecordedCall>>,
        outcome: Mutex<Option<ArchiveOutcome>>,
        failure: Mutex<Option<ArchiveAttemptFailure>>,
    }

    impl Default for RecordingRuntime {
        fn default() -> Self {
            Self {
                claims: Mutex::new(VecDeque::new()),
                calls: Mutex::new(Vec::new()),
                outcome: Mutex::new(None),
                failure: Mutex::new(None),
            }
        }
    }

    impl RecordingRuntime {
        fn take_calls(&self) -> Vec<RecordedCall> {
            self.calls.lock().unwrap().clone()
        }

        fn count_failures(&self) -> usize {
            self.take_calls()
                .iter()
                .filter(|call| matches!(call, RecordedCall::Fail { .. }))
                .count()
        }

        fn count_quarantines(&self) -> usize {
            self.take_calls()
                .iter()
                .filter(|call| matches!(call, RecordedCall::Quarantine { .. }))
                .count()
        }
    }

    /// Unit-level stand-in for the runtime trait that records which seam was
    /// touched: success ALWAYS lands as exactly one recorded attempt closure;
    /// quarantine/fail decisions happen OUTSIDE it (service layer funnels).
    #[async_trait]
    impl AuthorizationArchiveRuntime for RecordingRuntime {
        async fn claim_next_intent(
            &self,
            _tenant_id: i64,
            _owner: &str,
            _lease_seconds: i64,
        ) -> Result<Option<AuthorizationArchiveIntentClaim>, ArchiveAccessError> {
            match self.claims.lock().unwrap().pop_front() {
                Some(ClaimStep::Claim(claimed)) => Ok(Some(*claimed)),
                None => Ok(None),
                Some(ClaimStep::AccessError(detail)) => Err(ArchiveAccessError::Database(detail)),
            }
        }

        async fn archive_claimed_intent(
            &self,
            claimed: &AuthorizationArchiveIntentClaim,
        ) -> Result<ArchiveOutcome, ArchiveAttemptFailure> {
            // Ordering proof embedded in the FAKE too: a successful closure is
            // observed only when the injected result says so; failures surface
            // before any counting can happen.
            let failure = self.failure.lock().unwrap().take();
            match failure {
                Some(failure) => {
                    self.calls
                        .lock()
                        .unwrap()
                        .push(RecordedCall::RecordAndFlipErr);
                    Err(failure)
                }
                None => {
                    let outcome = self.outcome.lock().unwrap().take().ok_or_else(|| {
                        ArchiveAttemptFailure::Contract("fixture missing outcome".to_owned())
                    })?;
                    assert_eq!(
                        claimed.event_id, "evt-parent-3",
                        "fake receives exactly its scripted claim"
                    );
                    self.calls
                        .lock()
                        .unwrap()
                        .push(RecordedCall::RecordAndFlipOk);
                    Ok(outcome)
                }
            }
        }

        async fn fail_intent(
            &self,
            lease: &ArchiveLeaseProof,
            backoff_seconds: i64,
            last_error: &str,
        ) {
            self.calls.lock().unwrap().push(RecordedCall::Fail {
                backoff_seconds,
                reason: format!("{last_error} [outbox={}]", lease.archive_outbox_id),
            });
        }

        async fn quarantine_intent(
            &self,
            _lease: &ArchiveLeaseProof,
            reason_code: &str,
            reason_detail: &str,
        ) -> Result<(), ArchiveAccessError> {
            self.calls.lock().unwrap().push(RecordedCall::Quarantine {
                code: reason_code.to_owned(),
                detail: reason_detail.to_owned(),
            });
            Ok(())
        }
    }

    async fn drive_one(
        runtime: &Arc<dyn AuthorizationArchiveRuntime>,
        claimed: &AuthorizationArchiveIntentClaim,
    ) -> ArchiveRunSummary {
        let mut summary = ArchiveRunSummary::default();
        process_one_intent(
            runtime,
            claimed,
            &ArchiveCancellationToken::default(),
            Instant::now(),
            &mut summary,
        )
        .await;
        summary
    }

    #[tokio::test]
    async fn successful_attempt_records_proof_then_flips_exactly_once() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.outcome.lock().unwrap() = Some(ArchiveOutcome {
            proof: proof_fixture(),
            resumed_existing_proof: false,
        });
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(1),
        )
        .await;

        assert_eq!(summary.intents_archived, 1);
        assert_eq!(summary.intents_resumed, 0);
        assert_eq!(summary.intents_retried, 0);
        assert_eq!(summary.intents_quarantined, 0);
        assert_eq!(summary.intents_unknown, 0);
        assert_eq!(summary.intents_budget_exhausted, 0);

        let calls = runtime.take_calls();
        assert_eq!(
            calls
                .iter()
                .filter(|c| matches!(c, RecordedCall::RecordAndFlipOk))
                .count(),
            1,
            "exactly ONE successful proof+flip closure per archived intent"
        );
        assert_eq!(runtime.count_failures(), 0, "success must never fail");
        assert_eq!(
            runtime.count_quarantines(),
            0,
            "success must never quarantine"
        );
    }

    #[tokio::test]
    async fn replay_equal_existing_proof_counts_as_resume_not_new_archive() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.outcome.lock().unwrap() = Some(ArchiveOutcome {
            proof: proof_fixture(),
            resumed_existing_proof: true,
        });
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(2),
        )
        .await;
        assert_eq!(summary.intents_resumed, 1);
        assert_eq!(summary.intents_archived, 0);
        assert_eq!(summary.intents_quarantined, 0);
        assert_eq!(runtime.count_failures(), 0);
    }

    #[tokio::test]
    async fn database_failure_schedules_exactly_one_bounded_retry() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.failure.lock().unwrap() = Some(ArchiveAttemptFailure::Database(
            "server closed connection".to_owned(),
        ));
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(2),
        )
        .await;

        assert_eq!(summary.intents_retried, 1);
        assert_eq!(summary.intents_unknown, 0);
        assert_eq!(summary.intents_quarantined, 0);
        assert_eq!(runtime.count_failures(), 1, "EXACTLY one fail mutation");
        let calls = runtime.take_calls();
        let fail_calls: Vec<&RecordedCall> = calls
            .iter()
            .filter(|call| matches!(call, RecordedCall::Fail { .. }))
            .collect();
        match &fail_calls[..] {
            [RecordedCall::Fail {
                backoff_seconds,
                reason,
            }] => {
                assert_eq!(*backoff_seconds, archive_backoff_secs(2));
                assert!(reason.contains("code=auth_archive_worker."));
                assert!(!reason.contains("attempt_budget_exhausted"));
            }
            other => panic!("unexpected fail sequence: {other:?}"),
        }
        // No further mutation beyond the single fail.
        assert_eq!(runtime.count_quarantines(), 0);
    }

    #[tokio::test]
    async fn immutable_conflict_quarantines_terminally_never_retries() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.failure.lock().unwrap() =
            Some(repository(AuthorizationProjectionError::ImmutableConflict(
                "code=authorization_projection.archive_replay_generation".to_owned(),
            )));
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(1),
        )
        .await;

        assert_eq!(summary.intents_quarantined, 1);
        assert_eq!(summary.intents_unknown, 0);
        assert_eq!(runtime.count_failures(), 0, "corruption never retries");
        match &runtime.take_calls()[..] {
            [RecordedCall::RecordAndFlipErr, RecordedCall::Quarantine { code, detail }] => {
                assert_eq!(code, "auth_archive_worker.immutable_conflict");
                assert!(detail.contains("archive_replay_generation"));
            }
            other => panic!("unexpected call sequence: {other:?}"),
        }
    }

    #[tokio::test]
    async fn lease_loss_records_unknown_with_zero_follow_up_mutations() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.failure.lock().unwrap() =
            Some(repository(AuthorizationProjectionError::LeaseCasFailed(
                "code=authorization_projection.archive_complete_lost_lease".to_owned(),
            )));
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(3),
        )
        .await;

        assert_eq!(summary.intents_unknown, 1);
        assert_eq!(summary.intents_retried, 0);
        assert_eq!(summary.intents_quarantined, 0);
        assert_eq!(runtime.count_failures(), 0, "UNKNOWN means NO fail call");
        assert_eq!(
            runtime.count_quarantines(),
            0,
            "UNKNOWN means NO quarantine"
        );
        // Only the recorded attempt remains as evidence.
        assert_eq!(runtime.take_calls().len(), 1);
    }

    #[tokio::test]
    async fn attempt_budget_exhaustion_holds_pending_with_cap_marker() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.failure.lock().unwrap() = Some(ArchiveAttemptFailure::Database(
            "persistent db fault".to_owned(),
        ));
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(MAX_ARCHIVE_INTENT_ATTEMPTS + 2),
        )
        .await;

        assert_eq!(summary.intents_retried, 1);
        assert_eq!(summary.intents_budget_exhausted, 1);
        assert_eq!(summary.intents_quarantined, 0);
        let calls = runtime.take_calls();
        let fail_calls: Vec<&RecordedCall> = calls
            .iter()
            .filter(|call| matches!(call, RecordedCall::Fail { .. }))
            .collect();
        match &fail_calls[..] {
            [RecordedCall::Fail {
                backoff_seconds,
                reason,
            }] => {
                assert_eq!(*backoff_seconds, ARCHIVE_BACKOFF_CAP_SECS);
                assert!(
                    reason.contains(ATTEMPT_BUDGET_EXHAUSTED_CODE),
                    "stable exhaustion marker must reach the durable last_error"
                );
                assert!(reason.contains("attempts="));
            }
            other => panic!("unexpected fail sequence: {other:?}"),
        }
    }

    #[tokio::test]
    async fn budgets_never_gate_terminal_quarantine_even_when_exhausted() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.failure.lock().unwrap() = Some(repository(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_parent_fence_mismatch".to_owned(),
        )));
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(99),
        )
        .await;

        assert_eq!(summary.intents_quarantined, 1);
        assert_eq!(summary.intents_budget_exhausted, 0);
        assert_eq!(runtime.count_failures(), 0);
    }

    #[tokio::test]
    async fn corrupt_classification_routes_to_quarantine_with_stable_code() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.failure.lock().unwrap() = Some(repository(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.archive_proof_digest_seal_broken".to_owned(),
        )));
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(1),
        )
        .await;
        assert_eq!(summary.intents_quarantined, 1);
        match &runtime.take_calls()[..] {
            [_, RecordedCall::Quarantine { code, detail }] => {
                assert_eq!(code, "auth_archive_worker.corrupt_projection_state");
                assert!(
                    detail.contains("seal_broken"),
                    "evidence preserved: {detail}"
                );
            }
            other => panic!("unexpected call sequence: {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_durable_evidence_quarantines_without_any_retry_write() {
        // Both missing-evidence states the reordered proof transaction can
        // observe under lock: the claimed intent row gone, or its referenced
        // parent manifest row gone. Rows are never deleted by this worker, so
        // both are deterministic and must terminate in quarantine — NEVER in
        // a bounded retry loop.
        for missing in [
            ArchiveAttemptFailure::EvidenceMissing(
                "code=auth_archive_worker.intent_readback_missing;event=evt-parent-3".to_owned(),
            ),
            ArchiveAttemptFailure::EvidenceMissing(
                "code=auth_archive_worker.parent_manifest_readback_missing;manifest=44".to_owned(),
            ),
        ] {
            let runtime = Arc::new(RecordingRuntime::default());
            *runtime.failure.lock().unwrap() = Some(missing);
            let summary = drive_one(
                &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
                &claim_fixture(1),
            )
            .await;

            assert_eq!(
                summary.intents_quarantined, 1,
                "missing evidence is terminal"
            );
            assert_eq!(
                summary.intents_retried, 0,
                "retry can never restore absent rows"
            );
            assert_eq!(summary.intents_unknown, 0);
            assert_eq!(
                runtime.count_failures(),
                0,
                "missing evidence never retries"
            );
            match &runtime.take_calls()[..] {
                [RecordedCall::RecordAndFlipErr, RecordedCall::Quarantine { code, detail }] => {
                    assert_eq!(code, "auth_archive_worker.evidence_missing");
                    assert!(
                        detail.contains("readback_missing"),
                        "exact missing-state evidence preserved: {detail}"
                    );
                }
                other => panic!("unexpected call sequence: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn unexpected_intent_status_stays_transient_retry_not_quarantine() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.failure.lock().unwrap() = Some(ArchiveAttemptFailure::Contract(
            "code=auth_archive_worker.intent_unexpected_status;event=evt-parent-3;status=PENDING"
                .to_owned(),
        ));
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(2),
        )
        .await;

        assert_eq!(summary.intents_retried, 1, "status drift stays transient");
        assert_eq!(
            summary.intents_quarantined, 0,
            "status drift must NOT quarantine"
        );
        assert_eq!(summary.intents_unknown, 0);
        assert_eq!(
            runtime.count_failures(),
            1,
            "EXACTLY one bounded-backoff fail"
        );
        assert_eq!(runtime.count_quarantines(), 0);
    }

    #[tokio::test]
    async fn quarantine_write_refusal_degrades_to_unknown_without_retry_writes() {
        struct RefusingQuarantineRuntime {
            inner: RecordingRuntime,
        }
        #[async_trait]
        impl AuthorizationArchiveRuntime for RefusingQuarantineRuntime {
            async fn claim_next_intent(
                &self,
                tenant_id: i64,
                owner: &str,
                lease_seconds: i64,
            ) -> Result<Option<AuthorizationArchiveIntentClaim>, ArchiveAccessError> {
                self.inner
                    .claim_next_intent(tenant_id, owner, lease_seconds)
                    .await
            }
            async fn archive_claimed_intent(
                &self,
                _claimed: &AuthorizationArchiveIntentClaim,
            ) -> Result<ArchiveOutcome, ArchiveAttemptFailure> {
                Err(repository(AuthorizationProjectionError::Corrupt(
                    "code=authorization_projection.archive_parent_missing".to_owned(),
                )))
            }
            async fn fail_intent(&self, _lease: &ArchiveLeaseProof, _b: i64, _r: &str) {
                panic!("quarantine refusal must NOT degrade into a retry/fail write");
            }
            async fn quarantine_intent(
                &self,
                _lease: &ArchiveLeaseProof,
                _code: &str,
                _detail: &str,
            ) -> Result<(), ArchiveAccessError> {
                Err(ArchiveAccessError::Repository(
                    "lease CAS matched zero rows".to_owned(),
                ))
            }
        }
        let runtime = Arc::new(RefusingQuarantineRuntime {
            inner: RecordingRuntime::default(),
        });
        let summary = drive_one(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(1),
        )
        .await;
        assert_eq!(summary.intents_unknown, 1);
        assert_eq!(summary.intents_quarantined, 0);
    }

    #[tokio::test]
    async fn claim_db_error_aborts_cycle_without_any_mutation() {
        let runtime = Arc::new(RecordingRuntime::default());
        runtime
            .claims
            .lock()
            .unwrap()
            .push_back(ClaimStep::AccessError("pool timed out".to_owned()));
        let handle = start_authorization_archive_worker_with_runtime(
            runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>,
            AuthorizationArchiveConfig {
                tenants: vec![7],
                poll_interval_secs: 1,
                ..Default::default()
            },
        )
        .expect("valid default config must start");
        tokio::time::sleep(Duration::from_millis(40)).await;
        let report = shutdown_authorization_archive_worker(handle, Duration::from_secs(3)).await;
        assert!(report.summary.is_ok());
        let summary = report.summary.unwrap();
        assert_eq!(summary.intents_claimed, 0);
        assert_eq!(runtime.count_failures(), 0);
        assert_eq!(runtime.count_quarantines(), 0);
        assert!(
            runtime.take_calls().is_empty(),
            "no intent ever reached processing"
        );
    }

    #[tokio::test]
    async fn loop_claims_and_archives_the_scripted_intent_exactly_once() {
        let runtime = Arc::new(RecordingRuntime::default());
        *runtime.outcome.lock().unwrap() = Some(ArchiveOutcome {
            proof: proof_fixture(),
            resumed_existing_proof: false,
        });
        runtime
            .claims
            .lock()
            .unwrap()
            .push_back(ClaimStep::Claim(Box::new(claim_fixture(1))));
        // After the scripted claim is consumed, pop_front() yields None and the
        // cycle idles until shutdown.
        let handle = start_authorization_archive_worker_with_runtime(
            runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>,
            AuthorizationArchiveConfig {
                tenants: vec![7],
                poll_interval_secs: 1,
                ..Default::default()
            },
        )
        .expect("valid default config must start");
        tokio::time::sleep(Duration::from_millis(60)).await;
        let report = shutdown_authorization_archive_worker(handle, Duration::from_secs(3)).await;
        let summary = report.summary.expect("clean stop");
        assert_eq!(summary.intents_claimed, 1);
        assert_eq!(summary.intents_archived, 1);
        assert_eq!(summary.intents_resumed, 0);
        assert_eq!(runtime.count_failures(), 0);
        assert_eq!(runtime.count_quarantines(), 0);
        let calls = runtime.take_calls();
        assert!(
            matches!(&calls[..], [RecordedCall::RecordAndFlipOk]),
            "exactly one proof+flip closure: {calls:?}"
        );
    }

    #[tokio::test]
    async fn empty_tenant_scope_stays_idle_without_touching_the_runtime() {
        // Every trait method PANICS on touch: an empty scope must never reach
        // the runtime at all while still reporting idle cycles.
        struct PanicOnTouchRuntime;
        #[async_trait]
        impl AuthorizationArchiveRuntime for PanicOnTouchRuntime {
            async fn claim_next_intent(
                &self,
                _t: i64,
                _o: &str,
                _l: i64,
            ) -> Result<Option<AuthorizationArchiveIntentClaim>, ArchiveAccessError> {
                panic!("empty tenant scope must not claim")
            }
            async fn archive_claimed_intent(
                &self,
                _: &AuthorizationArchiveIntentClaim,
            ) -> Result<ArchiveOutcome, ArchiveAttemptFailure> {
                unreachable!()
            }
            async fn fail_intent(&self, _: &ArchiveLeaseProof, _: i64, _: &str) {
                unreachable!()
            }
            async fn quarantine_intent(
                &self,
                _: &ArchiveLeaseProof,
                _: &str,
                _: &str,
            ) -> Result<(), ArchiveAccessError> {
                unreachable!()
            }
        }
        let handle = start_authorization_archive_worker_with_runtime(
            Arc::new(PanicOnTouchRuntime),
            AuthorizationArchiveConfig {
                tenants: Vec::new(),
                poll_interval_secs: 1,
                ..Default::default()
            },
        )
        .expect("valid default lease config must start even with an empty scope");
        tokio::time::sleep(Duration::from_millis(30)).await;
        let report = shutdown_authorization_archive_worker(handle, Duration::from_secs(3)).await;
        let summary = report.summary.expect("idle worker stops cleanly");
        assert_eq!(summary.intents_claimed, 0);
        assert!(summary.no_work_cycles >= 1, "idle ticks must be observable");
    }

    #[tokio::test]
    async fn worker_polls_and_reports_no_work_when_queue_is_empty() {
        let runtime = Arc::new(RecordingRuntime::default());
        let handle = start_authorization_archive_worker_with_runtime(
            runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>,
            AuthorizationArchiveConfig {
                tenants: vec![42],
                poll_interval_secs: 1,
                ..Default::default()
            },
        )
        .expect("valid default config must start");
        tokio::time::sleep(Duration::from_millis(30)).await;
        let report = shutdown_authorization_archive_worker(handle, Duration::from_secs(3)).await;
        let summary = report.summary.expect("worker stops cleanly");
        assert_eq!(summary.intents_claimed, 0);
        assert!(summary.no_work_cycles >= 1);
        assert!(runtime.take_calls().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_times_out_when_worker_refuses_to_stop() {
        struct StickyRuntime {
            wedged: Arc<AtomicBool>,
        }
        #[async_trait]
        impl AuthorizationArchiveRuntime for StickyRuntime {
            async fn claim_next_intent(
                &self,
                _t: i64,
                _o: &str,
                _l: i64,
            ) -> Result<Option<AuthorizationArchiveIntentClaim>, ArchiveAccessError> {
                // Signal "inside the claim transaction" then simulate a DB
                // wedged against a lost connection: cancellation cannot rescue
                // it and only the bounded shutdown timeout can.
                self.wedged.store(true, Ordering::Release);
                std::future::pending::<()>().await;
                unreachable!("pending future never resolves")
            }
            async fn archive_claimed_intent(
                &self,
                _: &AuthorizationArchiveIntentClaim,
            ) -> Result<ArchiveOutcome, ArchiveAttemptFailure> {
                unreachable!()
            }
            async fn fail_intent(&self, _: &ArchiveLeaseProof, _: i64, _: &str) {}
            async fn quarantine_intent(
                &self,
                _: &ArchiveLeaseProof,
                _: &str,
                _: &str,
            ) -> Result<(), ArchiveAccessError> {
                unreachable!()
            }
        }
        let wedged = Arc::new(AtomicBool::new(false));
        let handle = start_authorization_archive_worker_with_runtime(
            Arc::new(StickyRuntime {
                wedged: wedged.clone(),
            }),
            AuthorizationArchiveConfig {
                tenants: vec![1],
                poll_interval_secs: 60,
                ..Default::default()
            },
        )
        .expect("valid default config must start");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !wedged.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "worker never reached claim");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let report =
            shutdown_authorization_archive_worker(handle, Duration::from_millis(120)).await;
        assert!(report.summary.is_err(), "stuck worker must surface as Err");
        assert!(report.join_elapsed < Duration::from_secs(2));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_shutdown_future_aborts_and_reaps_worker() {
        struct DroppedSignal(Arc<AtomicBool>);
        impl Drop for DroppedSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        struct StickyRuntime {
            entered: Arc<AtomicBool>,
            dropped: Arc<AtomicBool>,
        }
        #[async_trait]
        impl AuthorizationArchiveRuntime for StickyRuntime {
            async fn claim_next_intent(
                &self,
                _tenant_id: i64,
                _owner: &str,
                _lease_seconds: i64,
            ) -> Result<Option<AuthorizationArchiveIntentClaim>, ArchiveAccessError> {
                let _dropped = DroppedSignal(Arc::clone(&self.dropped));
                self.entered.store(true, Ordering::Release);
                std::future::pending::<()>().await;
                unreachable!("pending future never resolves")
            }
            async fn archive_claimed_intent(
                &self,
                _: &AuthorizationArchiveIntentClaim,
            ) -> Result<ArchiveOutcome, ArchiveAttemptFailure> {
                unreachable!()
            }
            async fn fail_intent(&self, _: &ArchiveLeaseProof, _: i64, _: &str) {}
            async fn quarantine_intent(
                &self,
                _: &ArchiveLeaseProof,
                _: &str,
                _: &str,
            ) -> Result<(), ArchiveAccessError> {
                unreachable!()
            }
        }

        let entered = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let handle = start_authorization_archive_worker_with_runtime(
            Arc::new(StickyRuntime {
                entered: Arc::clone(&entered),
                dropped: Arc::clone(&dropped),
            }),
            AuthorizationArchiveConfig {
                tenants: vec![1],
                poll_interval_secs: 60,
                ..Default::default()
            },
        )
        .expect("valid config must start");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !entered.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline, "worker never reached claim");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let shutdown_cancellation = handle.cancellation.clone();
        let shutdown = tokio::spawn(shutdown_authorization_archive_worker(
            handle,
            Duration::from_secs(30),
        ));
        while !shutdown_cancellation.is_cancelled() {
            assert!(
                Instant::now() < deadline,
                "shutdown did not acquire ownership"
            );
            tokio::task::yield_now().await;
        }
        shutdown.abort();
        let _ = shutdown.await;

        while !dropped.load(Ordering::Acquire) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            dropped.load(Ordering::Acquire),
            "worker must be aborted on drop"
        );
    }

    #[tokio::test]
    async fn scripted_intents_archive_then_resume_with_single_flip_each() {
        // Two sequentially processed claims: the first archives against a
        // freshly recorded proof, the second completes a RESUME against an
        // already-durable byte-equal proof. Each closure flips exactly once.
        let runtime = Arc::new(RecordingRuntime::default());
        let mut summary = ArchiveRunSummary::default();
        let token = ArchiveCancellationToken::default();

        *runtime.outcome.lock().unwrap() = Some(ArchiveOutcome {
            proof: proof_fixture(),
            resumed_existing_proof: false,
        });
        process_one_intent(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(1),
            &token,
            Instant::now(),
            &mut summary,
        )
        .await;
        *runtime.outcome.lock().unwrap() = Some(ArchiveOutcome {
            proof: proof_fixture(),
            resumed_existing_proof: true,
        });
        process_one_intent(
            &(runtime.clone() as Arc<dyn AuthorizationArchiveRuntime>),
            &claim_fixture(1),
            &token,
            Instant::now(),
            &mut summary,
        )
        .await;

        assert_eq!(summary.intents_archived, 1);
        assert_eq!(summary.intents_resumed, 1);
        assert_eq!(summary.intents_retried, 0);
        assert_eq!(runtime.count_failures(), 0);
        assert_eq!(runtime.count_quarantines(), 0);
        assert_eq!(
            runtime
                .take_calls()
                .iter()
                .filter(|c| matches!(c, RecordedCall::RecordAndFlipOk))
                .count(),
            2
        );
    }
}
