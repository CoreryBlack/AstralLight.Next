//! Bounded workers for the invalidation fanout transport.
//!
//! Two long-running tasks, both shutdown-aware with join handles:
//!
//! - **Relay** ([`spawn_invalidation_fanout_relay`]): claims committed
//!   invalidation rows from the durable outbox and publishes their canonical
//!   envelope bytes to the fanout exchange. Per-scope FIFO is preserved by
//!   publishing strictly sequentially in claim order; the claim query itself
//!   blocks a scope's later rows behind unprocessed earlier rows. Publish
//!   outcomes are classified: admission completes the row, known failures
//!   use the bounded retry/quarantine state machine, and unknown outcomes go
//!   to `IN_DOUBT` for reconciliation — never blind retries.
//! - **Inbox** ([`spawn_invalidation_fanout_inbox_worker`]): consumes the
//!   node's own durable subscription queue. ACK happens only after the
//!   durable per-node inbox commit and a successful in-memory apply; apply
//!   failures keep the receipt `PENDING` and requeue with bounded backoff,
//!   dead-lettering after the attempt cap. Channel breaks raise the suspect
//!   listener (which triggers the strict fail-closed read path); heartbeats
//!   only record liveness and can never clear a proof.
//!
//! Everything here is generic over its ports so pure mock tests can drive
//! the full classification, ordering, and multi-subscriber behavior without
//! a broker or database.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;

use crate::config::NodeIdentity;
use crate::invalidation::InvalidationEvent;
use crate::invalidation_fanout::{
    CommittedInvalidationEnvelope, FanoutDelivery, FanoutDeliverySource, FanoutFrame,
    HeartbeatScope, InboxCommitOutcome, InvalidationApply, InvalidationFanoutListener,
    InvalidationFanoutPublishOutcome, InvalidationFanoutTransport, InvalidationInboxAdapter,
    InvalidationInboxFailure, InvalidationInboxRecord, ScopeGapReport, ScopeWatermarkTracker,
    WatermarkAdvance,
};

/// Exponential backoff with a hard cap. Deterministic (no jitter) so tests
/// can assert exact delays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffConfig {
    pub initial: Duration,
    pub cap: Duration,
    pub factor: u32,
}

impl BackoffConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.initial.is_zero() || self.cap < self.initial || self.factor < 1 {
            return Err("backoff requires initial > 0, cap >= initial and factor >= 1".into());
        }
        Ok(())
    }

    pub fn value_for(&self, attempt: u32) -> Duration {
        let steps = attempt.saturating_sub(1).min(63);
        let multiplier = self.factor.saturating_pow(steps);
        self.initial
            .saturating_mul(multiplier)
            .min(self.cap)
            .max(self.initial)
    }
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            cap: Duration::from_secs(60),
            factor: 2,
        }
    }
}

const FANOUT_DB_CLAIM_BUDGET: Duration = Duration::from_secs(5);
const FANOUT_DB_SETTLEMENT_BUDGET: Duration = Duration::from_secs(5);
const FANOUT_DB_HEARTBEAT_BUDGET: Duration = Duration::from_secs(5);
const FANOUT_RELAY_CLAIM_ROWS: u32 = 1;

async fn bounded_fanout_db_call<T, F, E>(
    operation: &'static str,
    budget: Duration,
    future: F,
) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    match tokio::time::timeout(budget, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!(
            "{operation} failed; durable result may be unknown: {error}"
        )),
        Err(_) => Err(format!(
            "{operation} timed out after {budget:?}; durable result is unknown"
        )),
    }
}

fn fanout_publish_timeout_ceiling() -> Duration {
    // The heartbeat resets the lease to its full duration. Keep enough room
    // after confirmation for one bounded settlement and a clock/transport
    // margin so settlement still runs before the renewed lease expires.
    Duration::from_secs(
        astral_db::LOCAL_MESSAGE_LEASE_SECONDS
            .saturating_sub(FANOUT_DB_HEARTBEAT_BUDGET.as_secs())
            .saturating_sub(FANOUT_DB_SETTLEMENT_BUDGET.as_secs())
            .saturating_sub(2),
    )
}

#[derive(Debug)]
pub struct Backoff {
    config: BackoffConfig,
    attempt: u32,
}

impl Backoff {
    pub fn new(config: BackoffConfig) -> Self {
        Self { config, attempt: 0 }
    }

    pub fn next_delay(&mut self) -> Duration {
        self.attempt = self.attempt.saturating_add(1);
        self.config.value_for(self.attempt)
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

// ===== relay source (durable outbox claim port) =====

/// The relay's durable source port. The production implementation claims
/// committed invalidation rows from `al_message_outbox` through
/// [`astral_db::LocalMessageRepository`], which keeps the row state machine
/// (lease, bounded retry, quarantine, IN_DOUBT) in one owner.
#[async_trait]
pub trait InvalidationFanoutSource: Send + Sync {
    async fn claim_batch(
        &self,
        owner: &str,
        limit: u32,
    ) -> Result<Vec<astral_db::LocalMessageRow>, String>;
    async fn complete(&self, message_id: &str, lease_token: &str) -> Result<(), String>;
    /// Renew the claim lease with a token-checked CAS. The relay requires a
    /// bounded successful renewal immediately before publication; its bounded
    /// confirm wait is shorter than the renewed lease and needs no background
    /// renewal task.
    async fn heartbeat(&self, message_id: &str, lease_token: &str) -> Result<(), String>;
    async fn schedule_retry(
        &self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> Result<(), String>;
    async fn quarantine(
        &self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> Result<(), String>;
    async fn mark_in_doubt(
        &self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> Result<(), String>;
}

/// Production relay source: the durable invalidation outbox rows, claimed
/// with the repository's lease/CAS semantics. Write ownership of the outbox
/// state machine stays with `astral_db::LocalMessageRepository`; in Rabbit
/// transport mode exactly one relay (this one) may run for the invalidation
/// queue — the composite-process local relay must not also be started.
#[derive(Clone)]
pub struct LocalMessageOutboxSource {
    repository: astral_db::LocalMessageRepository,
}

impl LocalMessageOutboxSource {
    pub fn new(pool: sqlx::MySqlPool) -> Self {
        Self {
            repository: astral_db::LocalMessageRepository::new(pool),
        }
    }
}

#[async_trait]
impl InvalidationFanoutSource for LocalMessageOutboxSource {
    async fn claim_batch(
        &self,
        owner: &str,
        limit: u32,
    ) -> Result<Vec<astral_db::LocalMessageRow>, String> {
        self.repository
            .claim_batch(owner, crate::invalidation::INVALIDATION_QUEUE, limit)
            .await
            .map_err(|error| error.to_string())
    }

    async fn complete(&self, message_id: &str, lease_token: &str) -> Result<(), String> {
        self.repository
            .complete(message_id, lease_token)
            .await
            .map_err(|error| error.to_string())
    }

    async fn heartbeat(&self, message_id: &str, lease_token: &str) -> Result<(), String> {
        self.repository
            .heartbeat(message_id, lease_token)
            .await
            .map_err(|error| error.to_string())
    }

    async fn schedule_retry(
        &self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> Result<(), String> {
        self.repository
            .schedule_retry(message_id, lease_token, error)
            .await
            .map_err(|error| error.to_string())
    }

    async fn quarantine(
        &self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> Result<(), String> {
        self.repository
            .quarantine(message_id, lease_token, error)
            .await
            .map_err(|error| error.to_string())
    }

    async fn mark_in_doubt(
        &self,
        message_id: &str,
        lease_token: &str,
        error: &str,
    ) -> Result<(), String> {
        self.repository
            .mark_in_doubt(message_id, lease_token, error)
            .await
            .map_err(|error| error.to_string())
    }
}

// ===== relay worker =====

/// Relay settings. `enabled` defaults to `false`: the fanout relay never
/// starts implicitly, and no assembly may enable it before a node identity,
/// the declared topology, and full adapters exist.
///
/// Batch safety: `batch_size` remains a compatible setting, but the relay
/// claims one row at a time because later rows in a multi-row claim cannot be
/// kept live while they wait behind earlier publishes. Before each publish it
/// proves a token-fenced lease renewal within a finite DB budget; unknown claim
/// or transition results are never replayed in this run.
#[derive(Debug, Clone)]
pub struct InvalidationFanoutRelaySettings {
    pub enabled: bool,
    /// Retained and validated for settings compatibility; claims are capped to
    /// one row so unprocessed claims never age while waiting behind a publish.
    pub batch_size: u32,
    pub idle_poll: Duration,
    pub error_backoff: BackoffConfig,
    pub publish_confirm_timeout: Duration,
    /// Liveness-only heartbeat cadence onto the fanout channel. The default
    /// (2s) is sized for health owners with short liveness windows; failures
    /// are logged and never retried blindly.
    /// `None` disables heartbeat publishing entirely.
    pub heartbeat_interval: Option<Duration>,
}

impl Default for InvalidationFanoutRelaySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            batch_size: 16,
            idle_poll: Duration::from_millis(250),
            error_backoff: BackoffConfig::default(),
            publish_confirm_timeout: Duration::from_secs(10),
            heartbeat_interval: Some(Duration::from_secs(2)),
        }
    }
}

fn validate_relay_settings(settings: &InvalidationFanoutRelaySettings) -> Result<(), String> {
    if !settings.enabled {
        return Err(
            "invalidation fanout relay is disabled by configuration; enabling it is an explicit \
             cross-node transport decision"
                .into(),
        );
    }
    if settings.batch_size == 0 || settings.batch_size > 64 {
        return Err("relay batch_size must be within 1..=64".into());
    }
    if settings.idle_poll.is_zero() {
        return Err("relay idle_poll must be positive".into());
    }
    if settings.publish_confirm_timeout.is_zero() {
        return Err("relay publish_confirm_timeout must be positive".into());
    }
    settings.error_backoff.validate()?;
    if settings
        .heartbeat_interval
        .is_some_and(|interval| interval.is_zero())
    {
        return Err("relay heartbeat_interval must be positive when present".into());
    }
    Ok(())
}

const FANOUT_TASK_REAPER_TIMEOUT: Duration = Duration::from_secs(1);

fn abort_and_reap_fanout_task(mut join: tokio::task::JoinHandle<()>, name: &'static str) {
    join.abort();
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        tracing::error!(
            task = name,
            "fanout task join could not be scheduled for bounded reaping"
        );
        return;
    };
    runtime.spawn(async move {
        if tokio::time::timeout(FANOUT_TASK_REAPER_TIMEOUT, &mut join)
            .await
            .is_err()
        {
            tracing::warn!(
                task = name,
                "fanout task abort join remained unknown after bounded reaping"
            );
        }
    });
}

/// Handle for one relay worker. Shutdown is cooperative; `join` resolves when
/// the relay loop and its heartbeat task have both finished. Dropping/cancelling
/// its join path signals shutdown, aborts remaining work, then reaps it boundedly.
#[derive(Debug)]
pub struct InvalidationFanoutRelayHandle {
    shutdown: watch::Sender<bool>,
    relay_join: Option<tokio::task::JoinHandle<()>>,
    heartbeat_join: Option<tokio::task::JoinHandle<()>>,
}

impl InvalidationFanoutRelayHandle {
    pub fn signal_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn shutdown_and_join(mut self) -> Result<(), String> {
        self.signal_shutdown();
        let mut failures = Vec::new();
        if let Some(join) = self.heartbeat_join.as_mut() {
            if let Err(error) = join.await {
                failures.push(format!("fanout heartbeat join failed: {error}"));
            }
            self.heartbeat_join.take();
        }
        if let Some(join) = self.relay_join.as_mut() {
            if let Err(error) = join.await {
                failures.push(format!("fanout relay join failed: {error}"));
            }
            self.relay_join.take();
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

impl Drop for InvalidationFanoutRelayHandle {
    fn drop(&mut self) {
        self.signal_shutdown();
        if let Some(join) = self.heartbeat_join.take() {
            abort_and_reap_fanout_task(join, "fanout-heartbeat");
        }
        if let Some(join) = self.relay_join.take() {
            abort_and_reap_fanout_task(join, "fanout-relay");
        }
    }
}

/// Spawn the fanout relay for one node. Requires `settings.enabled == true`
/// and a validated node identity. The source and transport are held as
/// owned `Arc`s; each row's lease renewal is driven alongside its publish so
/// an unproven lease stops further publication.
pub fn spawn_invalidation_fanout_relay<S, T>(
    source: S,
    transport: T,
    identity: NodeIdentity,
    worker_id: impl Into<String>,
    settings: InvalidationFanoutRelaySettings,
) -> Result<InvalidationFanoutRelayHandle, String>
where
    S: InvalidationFanoutSource + 'static,
    T: InvalidationFanoutTransport + 'static,
{
    validate_relay_settings(&settings)?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let worker_id = worker_id.into();
    let source = Arc::new(source);
    let transport = Arc::new(transport);
    let relay_join = tokio::spawn(run_relay_loop(
        Arc::clone(&source),
        Arc::clone(&transport),
        identity.clone(),
        worker_id,
        settings.clone(),
        shutdown_rx.clone(),
    ));
    let heartbeat_join = settings.heartbeat_interval.map(|interval| {
        tokio::spawn(run_heartbeat_task(
            Arc::clone(&transport),
            identity,
            interval,
            shutdown_rx,
        ))
    });
    Ok(InvalidationFanoutRelayHandle {
        shutdown,
        relay_join: Some(relay_join),
        heartbeat_join,
    })
}

async fn shutdown_or_sleep(shutdown: &mut watch::Receiver<bool>, duration: Duration) -> bool {
    tokio::select! {
        changed = shutdown.changed() => match changed {
            Ok(()) => !*shutdown.borrow(),
            Err(_) => false,
        },
        _ = tokio::time::sleep(duration) => !*shutdown.borrow(),
    }
}

async fn run_relay_loop<S, T>(
    source: Arc<S>,
    transport: Arc<T>,
    identity: NodeIdentity,
    worker_id: String,
    settings: InvalidationFanoutRelaySettings,
    mut shutdown: watch::Receiver<bool>,
) where
    S: InvalidationFanoutSource + 'static,
    T: InvalidationFanoutTransport,
{
    let mut backoff = Backoff::new(settings.error_backoff);
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        let claim = bounded_fanout_db_call(
            "fanout outbox claim",
            FANOUT_DB_CLAIM_BUDGET,
            source.claim_batch(&worker_id, FANOUT_RELAY_CLAIM_ROWS),
        )
        .await;
        match claim {
            Ok(rows) if rows.is_empty() => {
                if !shutdown_or_sleep(&mut shutdown, settings.idle_poll).await {
                    return;
                }
            }
            Ok(rows) => {
                backoff.reset();
                for row in rows {
                    if *shutdown.borrow_and_update() {
                        return;
                    }
                    if process_relay_row(&source, &transport, &identity, &settings, row).await
                        == RelayRowDisposition::Stop
                    {
                        return;
                    }
                }
            }
            Err(error) => {
                tracing::error!(
                    worker_id = %worker_id,
                    queue = crate::invalidation::INVALIDATION_QUEUE,
                    error = %error,
                    "invalidation fanout relay claim failed"
                );
                let delay = backoff.next_delay();
                if !shutdown_or_sleep(&mut shutdown, delay).await {
                    return;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayRowDisposition {
    Continue,
    Stop,
}

/// Process one claimed row. The publish returns broker admission only:
/// `Admitted` completes the outbox row (relayed), while per-node apply
/// completion is proven separately by each node's durable inbox receipt.
/// A bounded token-CAS heartbeat must succeed immediately before publish;
/// failure/timeout leaves the lease result unknown and suppresses publication.
/// Every durable transition has a finite budget. If a transition after publish
/// is unknown, this run never republishes the source row; the durable lease
/// state machine owns later reconciliation and the inbox receipt is the
/// per-node deduplication proof.
async fn process_relay_row<S, T>(
    source: &Arc<S>,
    transport: &Arc<T>,
    identity: &NodeIdentity,
    settings: &InvalidationFanoutRelaySettings,
    row: astral_db::LocalMessageRow,
) -> RelayRowDisposition
where
    S: InvalidationFanoutSource + 'static,
    T: InvalidationFanoutTransport,
{
    let Some(lease_token) = row.lease_owner.clone() else {
        tracing::error!(
            message_id = %row.message_id,
            "claimed fanout relay row has no lease owner"
        );
        return RelayRowDisposition::Stop;
    };

    // Canonical bytes seam: rejects anything that is not a committed,
    // contract-valid invalidation row without ever rebuilding createdAt.
    let request = match CommittedInvalidationEnvelope::from_durable_row(&row) {
        Ok(request) => request,
        Err(error) => {
            tracing::error!(
                message_id = %row.message_id,
                error = %error,
                "invalidation fanout row violates the canonical contract; quarantining"
            );
            if let Err(transition_error) = bounded_fanout_db_call(
                "fanout quarantine",
                FANOUT_DB_SETTLEMENT_BUDGET,
                source.quarantine(&row.message_id, &lease_token, &error.to_string()),
            )
            .await
            {
                tracing::error!(
                    message_id = %row.message_id,
                    error = %transition_error,
                    "invalidation fanout quarantine transition failed or is unknown"
                );
                return RelayRowDisposition::Stop;
            }
            return RelayRowDisposition::Continue;
        }
    };

    // The broker must not see this row until a bounded, token-fenced database
    // renewal proves we still own a live lease. A timeout/error is unknown:
    // do not publish and let durable reconciliation decide the row's fate.
    if let Err(error) = bounded_fanout_db_call(
        "fanout prepublish lease renewal",
        FANOUT_DB_HEARTBEAT_BUDGET,
        source.heartbeat(&row.message_id, &lease_token),
    )
    .await
    {
        tracing::error!(
            message_id = %row.message_id,
            error = %error,
            "invalidation fanout lease is not proven; suppressing publication"
        );
        return RelayRowDisposition::Stop;
    }

    // Leave room in the DB lease for the worst-case bounded renewal and
    // settlement round trips. Public timeout settings remain accepted, but
    // cannot keep a row in flight beyond its proven lease window.
    let safe_publish_timeout = settings
        .publish_confirm_timeout
        .min(fanout_publish_timeout_ceiling());
    let outcome = match tokio::time::timeout(
        safe_publish_timeout,
        transport.publish_committed_invalidation(&request),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => InvalidationFanoutPublishOutcome::Unknown {
            reason: format!(
                "publish confirm did not settle within {:?} (configured {:?})",
                safe_publish_timeout, settings.publish_confirm_timeout
            ),
        },
    };

    match outcome {
        InvalidationFanoutPublishOutcome::Admitted => {
            match bounded_fanout_db_call(
                "fanout completion",
                FANOUT_DB_SETTLEMENT_BUDGET,
                source.complete(&row.message_id, &lease_token),
            )
            .await
            {
                Ok(()) => tracing::debug!(
                    message_id = %row.message_id,
                    region = identity.region(),
                    node = identity.node(),
                    "invalidation relayed to fanout exchange (broker admission)"
                ),
                Err(error) => {
                    // Broker admission is proven; the durable completion is
                    // unknown. Do not reset or re-publish within this run —
                    // the durable outbox state machine reconciles, and any
                    // eventual replay is deduplicated per node by the inbox.
                    tracing::error!(
                        message_id = %row.message_id,
                        error = %error,
                        "invalidation fanout completion is unknown after broker admission"
                    );
                    return RelayRowDisposition::Stop;
                }
            }
            RelayRowDisposition::Continue
        }
        InvalidationFanoutPublishOutcome::Unknown { reason } => {
            tracing::error!(
                message_id = %row.message_id,
                reason = %reason,
                "invalidation fanout publish outcome unknown; marking IN_DOUBT for reconciliation"
            );
            match bounded_fanout_db_call(
                "fanout IN_DOUBT transition",
                FANOUT_DB_SETTLEMENT_BUDGET,
                source.mark_in_doubt(&row.message_id, &lease_token, &reason),
            )
            .await
            {
                Ok(()) => RelayRowDisposition::Continue,
                Err(transition_error) => {
                    tracing::error!(
                        message_id = %row.message_id,
                        error = %transition_error,
                        "invalidation fanout IN_DOUBT transition failed or is unknown"
                    );
                    RelayRowDisposition::Stop
                }
            }
        }
        known_failure @ (InvalidationFanoutPublishOutcome::ReturnedUnroutable { .. }
        | InvalidationFanoutPublishOutcome::Rejected { .. }
        | InvalidationFanoutPublishOutcome::ConfirmsNotEnabled) => {
            let error = known_failure.to_string();
            let transition = if row.attempts >= astral_db::LOCAL_MESSAGE_MAX_ATTEMPTS {
                bounded_fanout_db_call(
                    "fanout quarantine",
                    FANOUT_DB_SETTLEMENT_BUDGET,
                    source.quarantine(&row.message_id, &lease_token, &error),
                )
                .await
            } else {
                bounded_fanout_db_call(
                    "fanout retry scheduling",
                    FANOUT_DB_SETTLEMENT_BUDGET,
                    source.schedule_retry(&row.message_id, &lease_token, &error),
                )
                .await
            };
            if let Err(transition_error) = transition {
                tracing::error!(
                    message_id = %row.message_id,
                    error = %transition_error,
                    "invalidation fanout retry/quarantine transition failed or is unknown"
                );
                RelayRowDisposition::Stop
            } else {
                RelayRowDisposition::Continue
            }
        }
    }
}

async fn run_heartbeat_task<T>(
    transport: Arc<T>,
    identity: NodeIdentity,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) where
    T: InvalidationFanoutTransport,
{
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = tokio::time::sleep(interval) => {
                let sent_at = now_rfc3339();
                let outcome = transport.publish_heartbeat(&identity, sent_at).await;
                match outcome {
                    InvalidationFanoutPublishOutcome::Admitted => tracing::debug!(
                        region = identity.region(),
                        node = identity.node(),
                        "fanout heartbeat admitted"
                    ),
                    InvalidationFanoutPublishOutcome::Unknown { reason } => tracing::warn!(
                        region = identity.region(),
                        node = identity.node(),
                        reason = %reason,
                        "fanout heartbeat outcome unknown"
                    ),
                    other => tracing::warn!(
                        region = identity.region(),
                        node = identity.node(),
                        outcome = %other,
                        "fanout heartbeat publish failed"
                    ),
                }
            }
        }
    }
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

// ===== inbox worker =====

/// Inbox worker settings. `enabled` defaults to `false`: the per-node inbox
/// consumer never starts implicitly.
#[derive(Debug, Clone)]
pub struct InvalidationInboxWorkerSettings {
    pub enabled: bool,
    pub prefetch: u16,
    pub connect_backoff: BackoffConfig,
    pub apply_retry_backoff: BackoffConfig,
    /// Requeue attempts granted to one message before it is dead-lettered.
    /// The durable receipt stays `PENDING` either way.
    pub max_apply_attempts: u32,
}

impl Default for InvalidationInboxWorkerSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            prefetch: 16,
            connect_backoff: BackoffConfig::default(),
            apply_retry_backoff: BackoffConfig {
                initial: Duration::from_millis(100),
                cap: Duration::from_secs(5),
                factor: 2,
            },
            max_apply_attempts: 5,
        }
    }
}

fn validate_inbox_settings(settings: &InvalidationInboxWorkerSettings) -> Result<(), String> {
    if !settings.enabled {
        return Err(
            "invalidation fanout inbox worker is disabled by configuration; enabling it is an \
             explicit cross-node transport decision"
                .into(),
        );
    }
    if settings.prefetch == 0 {
        return Err("inbox prefetch must be positive".into());
    }
    if settings.max_apply_attempts == 0 {
        return Err("inbox max_apply_attempts must be positive".into());
    }
    settings.connect_backoff.validate()?;
    settings.apply_retry_backoff.validate()?;
    Ok(())
}

/// Handle for one inbox worker.
#[derive(Debug)]
pub struct InvalidationInboxWorkerHandle {
    shutdown: watch::Sender<bool>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl InvalidationInboxWorkerHandle {
    pub fn signal_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn shutdown_and_join(mut self) -> Result<(), String> {
        self.signal_shutdown();
        let Some(join) = self.join.as_mut() else {
            return Ok(());
        };
        let result = join
            .await
            .map_err(|error| format!("fanout inbox worker join failed: {error}"));
        self.join.take();
        result
    }
}

impl Drop for InvalidationInboxWorkerHandle {
    fn drop(&mut self) {
        self.signal_shutdown();
        if let Some(join) = self.join.take() {
            abort_and_reap_fanout_task(join, "fanout-inbox");
        }
    }
}

/// Spawn the per-node inbox worker. `connect` must produce one subscribed
/// session (for Rabbit: [`crate::invalidation_fanout::LapinInboxSession::connect`]);
/// it is called again on every reconnect. Channel breaks and stream errors
/// raise `on_channel_suspect` — the strict fail-closed read path — and are
/// never cleared by heartbeats (that is the health owner's decision).
pub fn spawn_invalidation_fanout_inbox_worker<F, Fut, S, I, A, L>(
    connect: F,
    inbox: I,
    apply: A,
    listener: L,
    identity: NodeIdentity,
    settings: InvalidationInboxWorkerSettings,
) -> Result<InvalidationInboxWorkerHandle, String>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<S, String>> + Send + 'static,
    S: FanoutDeliverySource + 'static,
    I: InvalidationInboxAdapter + 'static,
    A: InvalidationApply + 'static,
    L: InvalidationFanoutListener + 'static,
{
    validate_inbox_settings(&settings)?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let join = tokio::spawn(run_inbox_loop(
        connect,
        inbox,
        apply,
        listener,
        identity,
        settings,
        shutdown_rx,
    ));
    Ok(InvalidationInboxWorkerHandle {
        shutdown,
        join: Some(join),
    })
}

async fn run_inbox_loop<F, Fut, S, I, A, L>(
    connect: F,
    inbox: I,
    apply: A,
    listener: L,
    identity: NodeIdentity,
    settings: InvalidationInboxWorkerSettings,
    mut shutdown: watch::Receiver<bool>,
) where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<S, String>>,
    S: FanoutDeliverySource,
    I: InvalidationInboxAdapter,
    A: InvalidationApply,
    L: InvalidationFanoutListener,
{
    let mut connect_backoff = Backoff::new(settings.connect_backoff);
    let mut apply_backoff = Backoff::new(settings.apply_retry_backoff);
    let mut watermark = ScopeWatermarkTracker::default();
    let mut attempts: HashMap<String, u32> = HashMap::new();
    loop {
        if *shutdown.borrow_and_update() {
            return;
        }
        let connected = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
            connected = connect() => connected,
        };
        match connected {
            Ok(mut session) => {
                connect_backoff.reset();
                loop {
                    tokio::select! {
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                return;
                            }
                        }
                        delivery = session.next_delivery() => match delivery {
                            None => {
                                listener
                                    .on_channel_suspect(
                                        &identity,
                                        "fanout consume stream ended; strict read path required",
                                    )
                                    .await;
                                break;
                            }
                            Some(Err(error)) => {
                                listener
                                    .on_channel_suspect(
                                        &identity,
                                        &format!("fanout consume stream error: {error}"),
                                    )
                                    .await;
                                break;
                            }
                            Some(Ok(delivery)) => {
                                let settlement = process_inbox_delivery(
                                    &delivery.payload,
                                    &identity,
                                    &inbox,
                                    &apply,
                                    &listener,
                                    &mut watermark,
                                    &mut attempts,
                                    &settings,
                                    &mut apply_backoff,
                                )
                                .await;
                                apply_settlement(delivery, settlement).await;
                            }
                        },
                    }
                }
            }
            Err(error) => {
                listener
                    .on_channel_suspect(&identity, &format!("fanout inbox connect failed: {error}"))
                    .await;
            }
        }
        if !shutdown_or_sleep(&mut shutdown, connect_backoff.next_delay()).await {
            return;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboxSettlement {
    Ack,
    Requeue { delay: Duration },
    DeadLetter,
}

/// Core per-delivery pipeline. Contract order:
/// 1. typed frame decode (malformed → dead-letter, nothing committed),
/// 2. heartbeat → `on_heartbeat_alive` only, no durable state touched, ACK,
/// 3. invalidation → durable inbox commit (the ACK gate),
/// 4. in-memory apply (failure keeps the receipt `PENDING`),
/// 5. mark receipt APPLIED,
/// 6. watermark advance + exact-scope gap detection,
/// 7. ACK.
#[allow(clippy::too_many_arguments)]
async fn process_inbox_delivery(
    payload: &[u8],
    identity: &NodeIdentity,
    inbox: &dyn InvalidationInboxAdapter,
    apply: &dyn InvalidationApply,
    listener: &dyn InvalidationFanoutListener,
    watermark: &mut ScopeWatermarkTracker,
    attempts: &mut HashMap<String, u32>,
    settings: &InvalidationInboxWorkerSettings,
    apply_backoff: &mut Backoff,
) -> InboxSettlement {
    let frame = match FanoutFrame::decode(payload) {
        Ok(frame) => frame,
        Err(error) => {
            tracing::error!(
                region = identity.region(),
                node = identity.node(),
                error = %error,
                "malformed fanout frame dead-lettered without any inbox commit"
            );
            return InboxSettlement::DeadLetter;
        }
    };

    let envelope = match &frame {
        FanoutFrame::Heartbeat(envelope) => {
            let Ok(scope) = serde_json::from_value::<HeartbeatScope>(envelope.payload.clone())
            else {
                tracing::error!(
                    region = identity.region(),
                    node = identity.node(),
                    "heartbeat payload re-parse failed; dead-lettering"
                );
                return InboxSettlement::DeadLetter;
            };
            // Liveness only: no inbox write, no watermark touch, no proof
            // cleared, no suspect state cleared.
            listener.on_heartbeat_alive(identity, &scope).await;
            return InboxSettlement::Ack;
        }
        FanoutFrame::Invalidation(envelope) => envelope,
    };

    let message_id = envelope.message_id.clone();
    let event = match InvalidationEvent::from_envelope(envelope) {
        Ok(event) => event,
        Err(error) => {
            tracing::error!(
                region = identity.region(),
                node = identity.node(),
                message_id = %message_id,
                error = %error,
                "typed invalidation contract violated; dead-lettering without inbox commit"
            );
            return InboxSettlement::DeadLetter;
        }
    };

    let record = InvalidationInboxRecord {
        node_region: identity.region().to_owned(),
        node_id: identity.node().to_owned(),
        envelope: envelope.clone(),
    };
    match inbox.commit_delivery(&record).await {
        Err(InvalidationInboxFailure::PayloadConflict) => {
            tracing::error!(
                region = identity.region(),
                node = identity.node(),
                message_id = %message_id,
                "inbox receipt payload conflict; dead-lettering"
            );
            return InboxSettlement::DeadLetter;
        }
        Err(InvalidationInboxFailure::Storage(error)) => {
            tracing::error!(
                region = identity.region(),
                node = identity.node(),
                message_id = %message_id,
                error = %error,
                "durable inbox commit unavailable; requeueing without apply"
            );
            return requeue_decision(attempts, &message_id, settings, apply_backoff);
        }
        Ok(InboxCommitOutcome::ExistingApplied) => {
            tracing::debug!(
                message_id = %message_id,
                "duplicate invalidation delivery; receipt already applied"
            );
            attempts.remove(&message_id);
            return InboxSettlement::Ack;
        }
        Ok(InboxCommitOutcome::InsertedPending | InboxCommitOutcome::ExistingPending) => {}
    }

    if let Err(reason) = apply.apply(envelope, &event).await {
        tracing::error!(
            region = identity.region(),
            node = identity.node(),
            message_id = %message_id,
            reason = %reason,
            "in-memory invalidation apply failed; receipt stays PENDING"
        );
        return requeue_decision(attempts, &message_id, settings, apply_backoff);
    }

    if let Err(error) = inbox.mark_applied(identity, &message_id).await {
        tracing::error!(
            region = identity.region(),
            node = identity.node(),
            message_id = %message_id,
            error = %error,
            "receipt could not be marked applied; requeueing"
        );
        return requeue_decision(attempts, &message_id, settings, apply_backoff);
    }

    advance_watermark_and_report(identity, inbox, listener, watermark, envelope, &message_id).await;
    attempts.remove(&message_id);
    InboxSettlement::Ack
}

fn requeue_decision(
    attempts: &mut HashMap<String, u32>,
    message_id: &str,
    settings: &InvalidationInboxWorkerSettings,
    apply_backoff: &mut Backoff,
) -> InboxSettlement {
    let count = attempts.entry(message_id.to_owned()).or_insert(0);
    *count = count.saturating_add(1);
    if *count > settings.max_apply_attempts {
        tracing::error!(
            message_id = %message_id,
            attempts = *count,
            "apply retry cap reached; dead-lettering while the durable receipt stays PENDING"
        );
        attempts.remove(message_id);
        InboxSettlement::DeadLetter
    } else {
        InboxSettlement::Requeue {
            delay: apply_backoff.next_delay(),
        }
    }
}

async fn advance_watermark_and_report(
    identity: &NodeIdentity,
    inbox: &dyn InvalidationInboxAdapter,
    listener: &dyn InvalidationFanoutListener,
    watermark: &mut ScopeWatermarkTracker,
    envelope: &crate::envelope::MessageEnvelope,
    message_id: &str,
) {
    let Some(ordering_key) = envelope.ordering_key.as_ref() else {
        return;
    };
    let advance = watermark.advance(ordering_key, &envelope.created_at, message_id);
    let has_pending_earlier = match inbox
        .has_pending_before(identity, ordering_key, &envelope.created_at, message_id)
        .await
    {
        Ok(has_pending_earlier) => has_pending_earlier,
        Err(error) => {
            tracing::warn!(
                region = identity.region(),
                node = identity.node(),
                message_id = %message_id,
                error = %error,
                "scope gap probe failed; flagging reconciliation for this scope"
            );
            true
        }
    };
    let scope_regressed = matches!(advance, WatermarkAdvance::ScopeRegressed { .. });
    if scope_regressed || has_pending_earlier {
        let report = ScopeGapReport {
            ordering_key: ordering_key.clone(),
            observed_created_at: envelope.created_at.clone(),
            observed_message_id: message_id.to_owned(),
            observed_payload_sha256: envelope.payload_sha256.clone(),
            has_pending_earlier,
            scope_regressed,
        };
        tracing::warn!(
            region = identity.region(),
            node = identity.node(),
            ordering_key = %report.ordering_key,
            observed_message_id = %report.observed_message_id,
            has_pending_earlier = report.has_pending_earlier,
            scope_regressed = report.scope_regressed,
            "per-scope invalidation gap flagged for reconciliation"
        );
        listener.on_scope_gap(identity, &report).await;
    }
}

async fn apply_settlement(delivery: FanoutDelivery, settlement: InboxSettlement) {
    match settlement {
        InboxSettlement::Ack => {
            if let Err(error) = delivery.settlement.ack().await {
                tracing::error!(error = %error, "fanout delivery ack failed");
            }
        }
        InboxSettlement::Requeue { delay } => {
            // Bounded in-process backpressure before the requeue; the broker
            // redelivers only after the nack below.
            tokio::time::sleep(delay).await;
            if let Err(error) = delivery.settlement.nack_requeue().await {
                tracing::error!(error = %error, "fanout delivery nack(requeue) failed");
            }
        }
        InboxSettlement::DeadLetter => {
            if let Err(error) = delivery.settlement.nack_dead_letter().await {
                tracing::error!(error = %error, "fanout delivery dead-letter nack failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::INVALIDATION_HEARTBEAT_MESSAGE_TYPE;
    use crate::envelope::MessageEnvelope;
    use crate::invalidation::EvidenceInvalidated;
    use crate::invalidation_fanout::InboxMarkApplied;
    use astral_types::PublishedEvidenceAggregate;
    use std::collections::{HashSet, VecDeque};
    use std::sync::{Arc, Mutex};
    use time::PrimitiveDateTime;

    const PENDING_EARLIER_CREATED_AT: &str = "2026-10-01T00:00:00Z";

    fn identity(region: &str, node: &str) -> NodeIdentity {
        NodeIdentity::try_from_parts(region, node).unwrap()
    }

    fn evidence_envelope(message_id: &str, created_at: &str, card_id: i64) -> MessageEnvelope {
        let event = InvalidationEvent::EvidenceInvalidated(EvidenceInvalidated {
            tenant_id: 7,
            card_id: Some(card_id),
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: card_id,
            published_generation: 10,
            source_generation: 10,
            revoke_fence: 0,
        });
        let mut envelope = event
            .to_envelope(message_id, format!("op-{message_id}"), "city-a")
            .unwrap();
        envelope.created_at = created_at.to_owned();
        envelope
    }

    fn heartbeat_payload_envelope() -> MessageEnvelope {
        let scope = HeartbeatScope {
            node_region: "city-a".into(),
            node_id: "node-1".into(),
            sent_at: "2026-10-01T00:00:00Z".into(),
        };
        let payload = serde_json::to_value(&scope).unwrap();
        let envelope = MessageEnvelope::new(
            "heartbeat-1",
            "heartbeat-op",
            INVALIDATION_HEARTBEAT_MESSAGE_TYPE,
            1,
            "city-a",
            payload,
        )
        .unwrap();
        envelope.validate().unwrap();
        envelope
    }

    fn outbox_row(
        envelope: &MessageEnvelope,
        status: &str,
        attempts: i32,
    ) -> astral_db::LocalMessageRow {
        let stamp = PrimitiveDateTime::new(
            time::Date::from_calendar_date(2026, time::Month::October, 1).unwrap(),
            time::Time::MIDNIGHT,
        );
        astral_db::LocalMessageRow {
            message_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            message_type: envelope.message_type.clone(),
            queue_name: crate::invalidation::INVALIDATION_QUEUE.to_owned(),
            ordering_key: envelope.ordering_key.clone(),
            tenant_id: envelope.tenant_id,
            origin_region: envelope.origin_region.clone(),
            target_region: envelope.target_region.clone(),
            schema_version: envelope.schema_version,
            payload_json: envelope.envelope_json().unwrap(),
            headers_json: None,
            payload_sha256: envelope.payload_sha256.clone(),
            status: status.to_owned(),
            attempts,
            next_attempt_at: None,
            lease_owner: Some("lease-1".into()),
            lease_expires_at: None,
            processed_at: None,
            last_error: None,
            created_at: stamp,
            updated_at: stamp,
        }
    }

    async fn wait_for(predicate: impl Fn() -> bool, label: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !predicate() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timeout waiting for {label}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // ===== mocks =====

    #[derive(Clone, Default)]
    struct MockTransport {
        published: Arc<Mutex<Vec<(String, String)>>>,
        outcomes: Arc<Mutex<VecDeque<InvalidationFanoutPublishOutcome>>>,
    }

    impl MockTransport {
        fn with_outcomes(outcomes: Vec<InvalidationFanoutPublishOutcome>) -> Self {
            Self {
                published: Arc::new(Mutex::new(Vec::new())),
                outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
            }
        }

        fn published(&self) -> Vec<(String, String)> {
            self.published.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl InvalidationFanoutTransport for MockTransport {
        async fn publish_canonical(
            &self,
            body: &[u8],
            message_id: &str,
        ) -> InvalidationFanoutPublishOutcome {
            self.published.lock().unwrap().push((
                String::from_utf8_lossy(body).to_string(),
                message_id.to_owned(),
            ));
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(InvalidationFanoutPublishOutcome::Admitted)
        }
    }

    #[derive(Clone, Default)]
    struct MockSource {
        pending: Arc<Mutex<Vec<astral_db::LocalMessageRow>>>,
        actions: Arc<Mutex<Vec<String>>>,
        claim_limits: Arc<Mutex<Vec<u32>>>,
    }

    impl MockSource {
        fn with_rows(rows: Vec<astral_db::LocalMessageRow>) -> Self {
            Self {
                pending: Arc::new(Mutex::new(rows)),
                actions: Arc::new(Mutex::new(Vec::new())),
                claim_limits: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn actions(&self) -> Vec<String> {
            self.actions.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl InvalidationFanoutSource for MockSource {
        async fn claim_batch(
            &self,
            _owner: &str,
            limit: u32,
        ) -> Result<Vec<astral_db::LocalMessageRow>, String> {
            self.claim_limits.lock().unwrap().push(limit);
            let mut pending = self.pending.lock().unwrap();
            let take = pending.len().min(limit as usize);
            Ok(pending.drain(..take).collect())
        }

        async fn complete(&self, message_id: &str, _lease_token: &str) -> Result<(), String> {
            self.actions
                .lock()
                .unwrap()
                .push(format!("complete:{message_id}"));
            Ok(())
        }

        async fn heartbeat(&self, message_id: &str, _lease_token: &str) -> Result<(), String> {
            self.actions
                .lock()
                .unwrap()
                .push(format!("heartbeat:{message_id}"));
            Ok(())
        }

        async fn schedule_retry(
            &self,
            message_id: &str,
            _lease_token: &str,
            _error: &str,
        ) -> Result<(), String> {
            self.actions
                .lock()
                .unwrap()
                .push(format!("retry:{message_id}"));
            Ok(())
        }

        async fn quarantine(
            &self,
            message_id: &str,
            _lease_token: &str,
            _error: &str,
        ) -> Result<(), String> {
            self.actions
                .lock()
                .unwrap()
                .push(format!("quarantine:{message_id}"));
            Ok(())
        }

        async fn mark_in_doubt(
            &self,
            message_id: &str,
            _lease_token: &str,
            _error: &str,
        ) -> Result<(), String> {
            self.actions
                .lock()
                .unwrap()
                .push(format!("in_doubt:{message_id}"));
            Ok(())
        }
    }

    struct MockReceipt {
        record: InvalidationInboxRecord,
        status: &'static str,
    }

    type InboxKey = (String, String, String);

    type InboxRowMap = Arc<Mutex<HashMap<InboxKey, MockReceipt>>>;

    #[derive(Clone, Default)]
    struct MockInbox {
        rows: InboxRowMap,
        storage_failures: Arc<Mutex<HashSet<String>>>,
    }

    impl MockInbox {
        fn status_of(&self, region: &str, node: &str, message_id: &str) -> Option<String> {
            self.rows
                .lock()
                .unwrap()
                .get(&(region.to_owned(), node.to_owned(), message_id.to_owned()))
                .map(|row| row.status.to_owned())
        }

        fn seed_pending(&self, identity: &NodeIdentity, envelope: &MessageEnvelope) {
            self.rows.lock().unwrap().insert(
                (
                    identity.region().to_owned(),
                    identity.node().to_owned(),
                    envelope.message_id.clone(),
                ),
                MockReceipt {
                    record: InvalidationInboxRecord {
                        node_region: identity.region().to_owned(),
                        node_id: identity.node().to_owned(),
                        envelope: envelope.clone(),
                    },
                    status: "PENDING",
                },
            );
        }
    }

    fn storage_failure_tag(message_id: &str) -> String {
        format!("storage:{message_id}")
    }

    #[async_trait]
    impl InvalidationInboxAdapter for MockInbox {
        async fn commit_delivery(
            &self,
            record: &InvalidationInboxRecord,
        ) -> Result<InboxCommitOutcome, InvalidationInboxFailure> {
            let key = (
                record.node_region.clone(),
                record.node_id.clone(),
                record.envelope.message_id.clone(),
            );
            let payload_json = record
                .payload_json()
                .map_err(InvalidationInboxFailure::Storage)?;
            let mut rows = self.rows.lock().unwrap();
            match rows.get(&key) {
                Some(existing) => {
                    let existing_json = existing
                        .record
                        .payload_json()
                        .map_err(InvalidationInboxFailure::Storage)?;
                    if existing_json == payload_json {
                        if existing.status == "APPLIED" {
                            Ok(InboxCommitOutcome::ExistingApplied)
                        } else {
                            Ok(InboxCommitOutcome::ExistingPending)
                        }
                    } else {
                        Err(InvalidationInboxFailure::PayloadConflict)
                    }
                }
                None => {
                    rows.insert(
                        key,
                        MockReceipt {
                            record: record.clone(),
                            status: "PENDING",
                        },
                    );
                    Ok(InboxCommitOutcome::InsertedPending)
                }
            }
        }

        async fn mark_applied(
            &self,
            identity: &NodeIdentity,
            message_id: &str,
        ) -> Result<InboxMarkApplied, InvalidationInboxFailure> {
            if self
                .storage_failures
                .lock()
                .unwrap()
                .contains(&storage_failure_tag(message_id))
            {
                return Err(InvalidationInboxFailure::Storage(format!(
                    "storage:{message_id}"
                )));
            }
            let mut rows = self.rows.lock().unwrap();
            match rows.get_mut(&(
                identity.region().to_owned(),
                identity.node().to_owned(),
                message_id.to_owned(),
            )) {
                Some(row) => {
                    row.status = "APPLIED";
                    Ok(InboxMarkApplied::Applied)
                }
                None => Err(InvalidationInboxFailure::Storage(format!(
                    "missing receipt {message_id}"
                ))),
            }
        }

        async fn has_pending_before(
            &self,
            identity: &NodeIdentity,
            ordering_key: &str,
            envelope_created_at: &str,
            message_id: &str,
        ) -> Result<bool, InvalidationInboxFailure> {
            let rows = self.rows.lock().unwrap();
            Ok(rows.values().any(|row| {
                row.status == "PENDING"
                    && row.record.node_region == identity.region()
                    && row.record.node_id == identity.node()
                    && row.record.envelope.ordering_key.as_deref() == Some(ordering_key)
                    && (
                        row.record.envelope.created_at.as_str(),
                        row.record.envelope.message_id.as_str(),
                    ) < (envelope_created_at, message_id)
            }))
        }
    }

    #[derive(Clone, Default)]
    struct MockApply {
        applied: Arc<Mutex<Vec<String>>>,
        fail_message_ids: Arc<Mutex<HashSet<String>>>,
    }

    impl MockApply {
        fn fail_for(&self, message_id: &str) {
            self.fail_message_ids
                .lock()
                .unwrap()
                .insert(message_id.to_owned());
        }

        fn applied(&self) -> Vec<String> {
            self.applied.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl InvalidationApply for MockApply {
        async fn apply(
            &self,
            envelope: &MessageEnvelope,
            _event: &InvalidationEvent,
        ) -> Result<(), String> {
            if self
                .fail_message_ids
                .lock()
                .unwrap()
                .contains(&envelope.message_id)
            {
                return Err(format!("apply failed for {}", envelope.message_id));
            }
            self.applied
                .lock()
                .unwrap()
                .push(envelope.message_id.clone());
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct MockListener {
        suspects: Arc<Mutex<Vec<String>>>,
        alive: Arc<Mutex<Vec<HeartbeatScope>>>,
        gaps: Arc<Mutex<Vec<ScopeGapReport>>>,
    }

    impl MockListener {
        fn suspect_count(&self) -> usize {
            self.suspects.lock().unwrap().len()
        }

        fn suspects(&self) -> Vec<String> {
            self.suspects.lock().unwrap().clone()
        }

        fn alive_count(&self) -> usize {
            self.alive.lock().unwrap().len()
        }

        fn gaps(&self) -> Vec<ScopeGapReport> {
            self.gaps.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl InvalidationFanoutListener for MockListener {
        async fn on_channel_suspect(&self, identity: &NodeIdentity, reason: &str) {
            self.suspects.lock().unwrap().push(format!(
                "{}:{}:{}",
                identity.region(),
                identity.node(),
                reason
            ));
        }

        async fn on_heartbeat_alive(&self, _identity: &NodeIdentity, heartbeat: &HeartbeatScope) {
            self.alive.lock().unwrap().push(heartbeat.clone());
        }

        async fn on_scope_gap(&self, _identity: &NodeIdentity, report: &ScopeGapReport) {
            self.gaps.lock().unwrap().push(report.clone());
        }
    }

    struct MockSettlement {
        events: Arc<Mutex<Vec<String>>>,
        tag: String,
    }

    #[async_trait]
    impl crate::invalidation_fanout::FanoutDeliverySettlement for MockSettlement {
        async fn ack(&self) -> Result<(), String> {
            self.events
                .lock()
                .unwrap()
                .push(format!("ack:{}", self.tag));
            Ok(())
        }

        async fn nack_requeue(&self) -> Result<(), String> {
            self.events
                .lock()
                .unwrap()
                .push(format!("requeue:{}", self.tag));
            Ok(())
        }

        async fn nack_dead_letter(&self) -> Result<(), String> {
            self.events
                .lock()
                .unwrap()
                .push(format!("dead_letter:{}", self.tag));
            Ok(())
        }
    }

    struct MockSession {
        deliveries: Arc<Mutex<VecDeque<FanoutDelivery>>>,
    }

    #[async_trait]
    impl FanoutDeliverySource for MockSession {
        async fn next_delivery(&mut self) -> Option<Result<FanoutDelivery, String>> {
            self.deliveries.lock().unwrap().pop_front().map(Ok)
        }
    }

    type SharedDeliveries = Arc<Mutex<VecDeque<FanoutDelivery>>>;

    fn session_connect(
        deliveries: SharedDeliveries,
    ) -> impl Fn() -> std::future::Ready<Result<MockSession, String>> + Send + Sync + 'static {
        move || {
            std::future::ready(Ok(MockSession {
                deliveries: deliveries.clone(),
            }))
        }
    }

    fn inbox_settings(enabled: bool) -> InvalidationInboxWorkerSettings {
        InvalidationInboxWorkerSettings {
            enabled,
            prefetch: 8,
            connect_backoff: BackoffConfig {
                initial: Duration::from_millis(5),
                cap: Duration::from_millis(20),
                factor: 2,
            },
            apply_retry_backoff: BackoffConfig {
                initial: Duration::from_millis(5),
                cap: Duration::from_millis(20),
                factor: 2,
            },
            max_apply_attempts: 3,
        }
    }

    fn relay_settings(enabled: bool) -> InvalidationFanoutRelaySettings {
        InvalidationFanoutRelaySettings {
            enabled,
            batch_size: 8,
            idle_poll: Duration::from_millis(5),
            error_backoff: BackoffConfig {
                initial: Duration::from_millis(5),
                cap: Duration::from_millis(20),
                factor: 2,
            },
            publish_confirm_timeout: Duration::from_secs(1),
            heartbeat_interval: None,
        }
    }

    fn process_settings() -> (InvalidationInboxWorkerSettings, Backoff) {
        (
            inbox_settings(true),
            Backoff::new(BackoffConfig {
                initial: Duration::from_millis(1),
                cap: Duration::from_millis(5),
                factor: 2,
            }),
        )
    }

    // ===== relay =====

    #[tokio::test]
    async fn relay_completes_row_on_broker_admission_and_publishes_canonical_bytes() {
        let envelope = evidence_envelope("event-1", "2026-10-01T00:00:01Z", 42);
        let row = outbox_row(&envelope, "PENDING", 0);
        let canonical = row.payload_json.clone();
        let source = Arc::new(MockSource::default());
        let transport = Arc::new(MockTransport::default());
        let identity = identity("city-a", "node-1");
        let settings = relay_settings(true);

        process_relay_row(&source, &transport, &identity, &settings, row).await;

        assert_eq!(
            source.actions(),
            vec![
                "heartbeat:event-1".to_owned(),
                "complete:event-1".to_owned()
            ]
        );
        let published = transport.published();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].1, "event-1");
        assert_eq!(
            published[0].0, canonical,
            "wire body must be the exact outbox bytes"
        );
    }

    #[tokio::test]
    async fn relay_classifies_known_failures_with_bounded_retry_then_quarantine() {
        let identity = identity("city-a", "node-1");
        let settings = relay_settings(true);

        // Below the attempt cap: bounded retry, never completion.
        let envelope = evidence_envelope("event-retry", "2026-10-01T00:00:02Z", 42);
        let transport = Arc::new(MockTransport::with_outcomes(vec![
            InvalidationFanoutPublishOutcome::Rejected {
                reason: "nack".into(),
            },
        ]));
        let source = Arc::new(MockSource::default());
        process_relay_row(
            &source,
            &transport,
            &identity,
            &settings,
            outbox_row(
                &envelope,
                "PENDING",
                astral_db::LOCAL_MESSAGE_MAX_ATTEMPTS - 1,
            ),
        )
        .await;
        assert_eq!(
            source.actions(),
            vec![
                "heartbeat:event-retry".to_owned(),
                "retry:event-retry".to_owned()
            ]
        );

        // At the attempt cap: quarantine.
        let envelope = evidence_envelope("event-quarantine", "2026-10-01T00:00:03Z", 42);
        let transport = Arc::new(MockTransport::with_outcomes(vec![
            InvalidationFanoutPublishOutcome::ReturnedUnroutable {
                reply_code: 312,
                reply_text: "NO_ROUTE".into(),
            },
        ]));
        let source = Arc::new(MockSource::default());
        process_relay_row(
            &source,
            &transport,
            &identity,
            &settings,
            outbox_row(&envelope, "PENDING", astral_db::LOCAL_MESSAGE_MAX_ATTEMPTS),
        )
        .await;
        assert_eq!(
            source.actions(),
            vec![
                "heartbeat:event-quarantine".to_owned(),
                "quarantine:event-quarantine".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn relay_marks_unknown_outcome_in_doubt_and_never_retries_blindly() {
        let envelope = evidence_envelope("event-unknown", "2026-10-01T00:00:04Z", 42);
        let transport = Arc::new(MockTransport::with_outcomes(vec![
            InvalidationFanoutPublishOutcome::Unknown {
                reason: "transport error".into(),
            },
        ]));
        let source = Arc::new(MockSource::default());
        let identity = identity("city-a", "node-1");
        process_relay_row(
            &source,
            &transport,
            &identity,
            &relay_settings(true),
            outbox_row(&envelope, "PENDING", 0),
        )
        .await;

        assert_eq!(
            source.actions(),
            vec![
                "heartbeat:event-unknown".to_owned(),
                "in_doubt:event-unknown".to_owned()
            ]
        );
        let actions = source.actions();
        assert!(
            !actions.iter().any(|action| action.starts_with("retry:")),
            "unknown outcomes must not be retried blindly"
        );
        assert!(
            !actions.iter().any(|action| action.starts_with("complete:")),
            "unknown outcomes must not be treated as admitted"
        );
    }

    #[tokio::test]
    async fn relay_quarantines_rows_that_violate_the_canonical_contract() {
        let mut envelope = evidence_envelope("event-bad", "2026-10-01T00:00:05Z", 42);
        envelope.created_at = "not-a-timestamp".into();
        let mut row = outbox_row(&envelope, "PENDING", 0);
        row.payload_json = "{\"broken\": true}".into();
        let source = Arc::new(MockSource::default());
        let transport = Arc::new(MockTransport::default());
        process_relay_row(
            &source,
            &transport,
            &identity("city-a", "node-1"),
            &relay_settings(true),
            row,
        )
        .await;

        assert_eq!(source.actions(), vec!["quarantine:event-bad".to_owned()]);
        assert!(
            transport.published().is_empty(),
            "a contract-violating row must never reach the broker"
        );
    }

    #[tokio::test]
    async fn relay_publishes_sequentially_preserving_claim_order() {
        let rows: Vec<astral_db::LocalMessageRow> = ["e-1", "e-2", "e-3"]
            .iter()
            .enumerate()
            .map(|(index, message_id)| {
                outbox_row(
                    &evidence_envelope(
                        message_id,
                        &format!("2026-10-01T00:00:0{}Z", index + 1),
                        42 + index as i64,
                    ),
                    "PENDING",
                    0,
                )
            })
            .collect();
        let expected_order: Vec<String> = rows.iter().map(|row| row.message_id.clone()).collect();
        let source = MockSource::with_rows(rows);
        let transport = MockTransport::default();
        let handle = spawn_invalidation_fanout_relay(
            source.clone(),
            transport.clone(),
            identity("city-a", "node-1"),
            "relay-fifo-test",
            relay_settings(true),
        )
        .unwrap();

        wait_for(
            || {
                let published = transport.published();
                published.len() == 3
                    && published
                        .iter()
                        .map(|(_, message_id)| message_id.clone())
                        .collect::<Vec<_>>()
                        == expected_order
            },
            "sequential publish order",
        )
        .await;
        handle
            .shutdown_and_join()
            .await
            .expect("relay and heartbeat tasks join cleanly");
        assert_eq!(
            source.actions(),
            expected_order
                .iter()
                .flat_map(|message_id| {
                    [
                        format!("heartbeat:{message_id}"),
                        format!("complete:{message_id}"),
                    ]
                })
                .collect::<Vec<_>>()
        );
        assert!(source
            .claim_limits
            .lock()
            .unwrap()
            .iter()
            .all(|limit| *limit == 1));
    }

    #[tokio::test]
    async fn relay_spawn_is_default_off_and_validates_settings() {
        let source = MockSource::default();
        let transport = MockTransport::default();
        let identity = identity("city-a", "node-1");

        let error = spawn_invalidation_fanout_relay(
            source.clone(),
            transport.clone(),
            identity.clone(),
            "disabled",
            InvalidationFanoutRelaySettings::default(),
        )
        .unwrap_err();
        assert!(error.contains("disabled"), "unexpected: {error}");
        assert!(transport.published().is_empty());

        let mut settings = relay_settings(true);
        settings.batch_size = 0;
        assert!(spawn_invalidation_fanout_relay(
            source,
            transport,
            identity,
            "bad-batch",
            settings
        )
        .is_err());
    }

    #[tokio::test]
    async fn cancelling_fanout_handle_shutdown_aborts_and_reaps_owned_tasks() {
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let (shutdown, _shutdown_rx) = watch::channel(false);
        let handle = InvalidationFanoutRelayHandle {
            shutdown,
            relay_join: Some(tokio::spawn(async move {
                struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
                impl Drop for DropSignal {
                    fn drop(&mut self) {
                        if let Some(signal) = self.0.take() {
                            let _ = signal.send(());
                        }
                    }
                }
                let _drop = DropSignal(Some(dropped_tx));
                std::future::pending::<()>().await;
            })),
            heartbeat_join: None,
        };
        {
            let mut shutdown = std::pin::pin!(handle.shutdown_and_join());
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut shutdown)
                    .await
                    .is_err()
            );
        }
        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("cancelled shutdown must abort and reap the owned relay")
            .expect("relay task drop must be observed");
    }

    #[tokio::test]
    async fn relay_shutdown_joins_and_heartbeat_publishes_scope_metadata() {
        let transport = MockTransport::default();
        let handle = spawn_invalidation_fanout_relay(
            MockSource::default(),
            transport.clone(),
            identity("city-a", "node-1"),
            "relay-heartbeat-test",
            InvalidationFanoutRelaySettings {
                heartbeat_interval: Some(Duration::from_millis(30)),
                ..relay_settings(true)
            },
        )
        .unwrap();
        wait_for(|| !transport.published().is_empty(), "heartbeat published").await;
        handle
            .shutdown_and_join()
            .await
            .expect("relay and heartbeat tasks join cleanly");
        assert!(!transport.published().is_empty());
        let (_, message_id) = &transport.published()[0];
        assert!(message_id.starts_with("heartbeat-"));
    }

    // ===== inbox pipeline (direct) =====

    #[tokio::test]
    async fn inbox_acks_only_after_commit_apply_and_marked_receipt() {
        let identity = identity("city-a", "node-1");
        let inbox = MockInbox::default();
        let apply = MockApply::default();
        let listener = MockListener::default();
        let (settings, mut backoff) = process_settings();
        let mut watermark = ScopeWatermarkTracker::default();
        let mut attempts = HashMap::new();

        let envelope = evidence_envelope("event-1", "2026-10-01T00:00:01Z", 42);
        let body = envelope.envelope_json().unwrap();
        let settlement = process_inbox_delivery(
            body.as_bytes(),
            &identity,
            &inbox,
            &apply,
            &listener,
            &mut watermark,
            &mut attempts,
            &settings,
            &mut backoff,
        )
        .await;

        assert_eq!(settlement, InboxSettlement::Ack);
        assert_eq!(
            inbox.status_of("city-a", "node-1", "event-1"),
            Some("APPLIED".into())
        );
        assert_eq!(apply.applied(), vec!["event-1".to_owned()]);
        assert_eq!(listener.suspect_count(), 0);
        assert_eq!(listener.gaps().len(), 0);
    }

    #[tokio::test]
    async fn inbox_duplicate_delivery_acks_without_reapplying() {
        let identity = identity("city-a", "node-1");
        let inbox = MockInbox::default();
        let apply = MockApply::default();
        let listener = MockListener::default();
        let (settings, mut backoff) = process_settings();
        let mut watermark = ScopeWatermarkTracker::default();
        let mut attempts = HashMap::new();

        let envelope = evidence_envelope("event-1", "2026-10-01T00:00:01Z", 42);
        inbox.seed_pending(&identity, &envelope);
        // Force commit_delivery to report ExistingApplied by marking applied.
        inbox.mark_applied(&identity, "event-1").await.unwrap();

        let body = envelope.envelope_json().unwrap();
        let settlement = process_inbox_delivery(
            body.as_bytes(),
            &identity,
            &inbox,
            &apply,
            &listener,
            &mut watermark,
            &mut attempts,
            &settings,
            &mut backoff,
        )
        .await;

        assert_eq!(settlement, InboxSettlement::Ack);
        assert!(
            apply.applied().is_empty(),
            "an already-applied receipt must not trigger a second apply"
        );
    }

    #[tokio::test]
    async fn inbox_apply_failure_keeps_receipt_pending_and_dead_letters_after_cap() {
        let identity = identity("city-a", "node-1");
        let inbox = MockInbox::default();
        let apply = MockApply::default();
        apply.fail_for("event-1");
        let listener = MockListener::default();
        let (settings, mut backoff) = process_settings();
        let mut watermark = ScopeWatermarkTracker::default();
        let mut attempts = HashMap::new();

        let envelope = evidence_envelope("event-1", "2026-10-01T00:00:01Z", 42);
        let body = envelope.envelope_json().unwrap();
        for attempt in 1..=settings.max_apply_attempts {
            let settlement = process_inbox_delivery(
                body.as_bytes(),
                &identity,
                &inbox,
                &apply,
                &listener,
                &mut watermark,
                &mut attempts,
                &settings,
                &mut backoff,
            )
            .await;
            assert!(
                matches!(settlement, InboxSettlement::Requeue { .. }),
                "attempt {attempt} must requeue"
            );
            assert_eq!(
                inbox.status_of("city-a", "node-1", "event-1"),
                Some("PENDING".into()),
                "apply failure must keep the durable receipt PENDING"
            );
        }
        let settlement = process_inbox_delivery(
            body.as_bytes(),
            &identity,
            &inbox,
            &apply,
            &listener,
            &mut watermark,
            &mut attempts,
            &settings,
            &mut backoff,
        )
        .await;
        assert_eq!(settlement, InboxSettlement::DeadLetter);
        assert_eq!(
            inbox.status_of("city-a", "node-1", "event-1"),
            Some("PENDING".into()),
            "dead-lettering must not clear the durable receipt"
        );
        assert!(apply.applied().is_empty());
    }

    #[tokio::test]
    async fn inbox_mark_applied_storage_failure_requeues_with_pending_receipt() {
        let identity = identity("city-a", "node-1");
        let inbox = MockInbox::default();
        inbox
            .storage_failures
            .lock()
            .unwrap()
            .insert(storage_failure_tag("event-1"));
        let apply = MockApply::default();
        let listener = MockListener::default();
        let (settings, mut backoff) = process_settings();
        let mut watermark = ScopeWatermarkTracker::default();
        let mut attempts = HashMap::new();

        let envelope = evidence_envelope("event-1", "2026-10-01T00:00:01Z", 42);
        let body = envelope.envelope_json().unwrap();
        let settlement = process_inbox_delivery(
            body.as_bytes(),
            &identity,
            &inbox,
            &apply,
            &listener,
            &mut watermark,
            &mut attempts,
            &settings,
            &mut backoff,
        )
        .await;
        assert!(matches!(settlement, InboxSettlement::Requeue { .. }));
        assert_eq!(
            inbox.status_of("city-a", "node-1", "event-1"),
            Some("PENDING".into())
        );
        assert!(
            apply.applied().is_empty() || apply.applied() == vec!["event-1".to_owned()],
            "apply may have succeeded but the receipt proof is missing, so the delivery requeues"
        );
    }

    #[tokio::test]
    async fn inbox_malformed_frame_dead_letters_without_any_commit() {
        let identity = identity("city-a", "node-1");
        let inbox = MockInbox::default();
        let apply = MockApply::default();
        let listener = MockListener::default();
        let (settings, mut backoff) = process_settings();
        let mut watermark = ScopeWatermarkTracker::default();
        let mut attempts = HashMap::new();

        let settlement = process_inbox_delivery(
            b"not-json",
            &identity,
            &inbox,
            &apply,
            &listener,
            &mut watermark,
            &mut attempts,
            &settings,
            &mut backoff,
        )
        .await;
        assert_eq!(settlement, InboxSettlement::DeadLetter);
        assert!(
            inbox
                .rows
                .lock()
                .unwrap()
                .keys()
                .collect::<Vec<_>>()
                .is_empty(),
            "malformed frames must never create a durable receipt"
        );
        assert!(apply.applied().is_empty());
    }

    #[tokio::test]
    async fn inbox_heartbeat_records_alive_without_touching_any_proof() {
        let identity = identity("city-a", "node-1");
        let inbox = MockInbox::default();
        let apply = MockApply::default();
        let listener = MockListener::default();
        let (settings, mut backoff) = process_settings();
        let mut watermark = ScopeWatermarkTracker::default();
        let mut attempts = HashMap::new();

        let envelope = heartbeat_payload_envelope();
        let body = envelope.envelope_json().unwrap();
        let settlement = process_inbox_delivery(
            body.as_bytes(),
            &identity,
            &inbox,
            &apply,
            &listener,
            &mut watermark,
            &mut attempts,
            &settings,
            &mut backoff,
        )
        .await;

        assert_eq!(settlement, InboxSettlement::Ack);
        assert_eq!(listener.alive_count(), 1);
        assert_eq!(listener.alive.lock().unwrap()[0].node_id, "node-1");
        assert!(
            inbox.rows.lock().unwrap().is_empty(),
            "heartbeats must not create durable receipts"
        );
        assert!(apply.applied().is_empty());
        assert!(
            listener.gaps().is_empty(),
            "heartbeats must not interact with watermark state"
        );
    }

    #[tokio::test]
    async fn inbox_gap_report_is_scope_exact_and_never_crosses_aggregates() {
        let identity = identity("city-a", "node-1");
        let inbox = MockInbox::default();
        let apply = MockApply::default();
        let listener = MockListener::default();
        let (settings, mut backoff) = process_settings();
        let mut watermark = ScopeWatermarkTracker::default();
        let mut attempts = HashMap::new();

        // An earlier event in the same scope is still PENDING (e.g. apply
        // retries outstanding) while the later event arrives first.
        let earlier = evidence_envelope("event-1", PENDING_EARLIER_CREATED_AT, 42);
        let later = evidence_envelope("event-2", "2026-10-01T00:00:05Z", 42);
        inbox.seed_pending(&identity, &earlier);

        let later_body = later.envelope_json().unwrap();
        let settlement = process_inbox_delivery(
            later_body.as_bytes(),
            &identity,
            &inbox,
            &apply,
            &listener,
            &mut watermark,
            &mut attempts,
            &settings,
            &mut backoff,
        )
        .await;
        assert_eq!(settlement, InboxSettlement::Ack);
        let gaps = listener.gaps();
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].has_pending_earlier);
        assert!(!gaps[0].scope_regressed);
        assert_eq!(gaps[0].observed_message_id, "event-2");
        assert_eq!(gaps[0].observed_payload_sha256, later.payload_sha256);
        assert_eq!(
            gaps[0].ordering_key,
            later.ordering_key.clone().unwrap(),
            "gap reports must be bound to the exact scope"
        );

        // A different aggregate scope with pending state must not leak into
        // this scope's report.
        let other_card = evidence_envelope("event-other", PENDING_EARLIER_CREATED_AT, 43);
        inbox.seed_pending(&identity, &other_card);
        let settlement = process_inbox_delivery(
            earlier.envelope_json().unwrap().as_bytes(),
            &identity,
            &inbox,
            &apply,
            &listener,
            &mut watermark,
            &mut attempts,
            &settings,
            &mut backoff,
        )
        .await;
        assert_eq!(settlement, InboxSettlement::Ack);
        let gaps = listener.gaps();
        assert_eq!(gaps.len(), 2);
        assert!(
            !gaps[1].has_pending_earlier,
            "pending rows of a different card scope must not be compared across aggregates"
        );
        assert!(
            gaps[1].scope_regressed,
            "applying an older message after a newer one flags the scope regression"
        );
    }

    // ===== inbox worker (spawned) =====

    fn fanout_delivery(
        body: Vec<u8>,
        tag: &str,
        events: &Arc<Mutex<Vec<String>>>,
    ) -> FanoutDelivery {
        FanoutDelivery {
            payload: body,
            settlement: Box::new(MockSettlement {
                events: events.clone(),
                tag: tag.to_owned(),
            }),
        }
    }

    #[tokio::test]
    async fn spawned_inbox_worker_processes_delivery_and_shuts_down() {
        let identity = identity("city-a", "node-1");
        let inbox = MockInbox::default();
        let apply = MockApply::default();
        let listener = MockListener::default();
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let deliveries: SharedDeliveries = Arc::new(Mutex::new(VecDeque::new()));
        let envelope = evidence_envelope("event-1", "2026-10-01T00:00:01Z", 42);
        deliveries.lock().unwrap().push_back(fanout_delivery(
            envelope.envelope_json().unwrap().into_bytes(),
            "city-a/node-1",
            &events,
        ));

        let handle = spawn_invalidation_fanout_inbox_worker(
            session_connect(deliveries),
            inbox.clone(),
            apply.clone(),
            listener.clone(),
            identity,
            inbox_settings(true),
        )
        .unwrap();
        wait_for(
            || inbox.status_of("city-a", "node-1", "event-1") == Some("APPLIED".into()),
            "receipt applied",
        )
        .await;
        wait_for(
            || {
                events
                    .lock()
                    .unwrap()
                    .contains(&"ack:city-a/node-1".to_owned())
            },
            "delivery acked",
        )
        .await;
        handle
            .shutdown_and_join()
            .await
            .expect("inbox worker joins cleanly");
        // The mock session ends once its deliveries drain, so the worker must
        // have raised the suspect callback before shutdown (stream-end
        // contract); it must never silently keep consuming a dead stream.
        assert!(listener.suspect_count() >= 1);
        assert!(listener
            .suspects()
            .iter()
            .all(|reason| reason.contains("stream ended")));
    }

    #[tokio::test]
    async fn spawned_inbox_worker_raises_suspect_on_connect_failure_and_stream_end() {
        let identity = identity("city-a", "node-1");
        let inbox = MockInbox::default();
        let apply = MockApply::default();
        let listener = MockListener::default();
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        // First connect attempt fails; the second returns a session whose
        // stream ends immediately; the third delivers one valid event.
        let attempt = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_deliveries: SharedDeliveries = Arc::new(Mutex::new(VecDeque::new()));
        let second_deliveries: SharedDeliveries = Arc::new(Mutex::new(VecDeque::new()));
        let envelope = evidence_envelope("event-1", "2026-10-01T00:00:01Z", 42);
        second_deliveries.lock().unwrap().push_back(fanout_delivery(
            envelope.envelope_json().unwrap().into_bytes(),
            "city-a/node-1",
            &events,
        ));
        let first = first_deliveries.clone();
        let second = second_deliveries.clone();
        let connect = move || {
            let attempt_index = attempt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let first = first.clone();
            let second = second.clone();
            async move {
                match attempt_index {
                    0 => Err("broker unreachable".to_owned()),
                    1 => Ok(MockSession { deliveries: first }),
                    _ => Ok(MockSession { deliveries: second }),
                }
            }
        };

        let handle = spawn_invalidation_fanout_inbox_worker(
            connect,
            inbox.clone(),
            apply.clone(),
            listener.clone(),
            identity,
            inbox_settings(true),
        )
        .unwrap();
        wait_for(
            || inbox.status_of("city-a", "node-1", "event-1") == Some("APPLIED".into()),
            "receipt applied after reconnect",
        )
        .await;
        handle
            .shutdown_and_join()
            .await
            .expect("inbox worker joins cleanly");

        let suspects = listener.suspects();
        assert!(
            suspects
                .iter()
                .any(|reason| reason.contains("fanout inbox connect failed")),
            "connect failure must raise the suspect callback: {suspects:?}"
        );
        assert!(
            suspects
                .iter()
                .any(|reason| reason.contains("stream ended")),
            "stream end must raise the suspect callback: {suspects:?}"
        );
    }

    /// 极端场景（多订阅者）：一个 fanout 发布，两个节点各自的 durable 订阅
    /// 队列都独立收到同一帧；每个节点独立走 commit→apply→mark→ACK，各自
    /// 持有自己的 APPLIED receipt —— 不存在共享队列竞争吞通知。
    #[tokio::test]
    async fn multisubscriber_fanout_delivers_independently_per_node() {
        let envelope = evidence_envelope("event-1", "2026-10-01T00:00:01Z", 42);
        let body = envelope.envelope_json().unwrap().into_bytes();

        // Mock broker: two independent subscriptions.
        let node_a_events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let node_b_events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let mut broker_subscriptions: Vec<SharedDeliveries> = Vec::new();
        let settlement_events = [node_a_events.clone(), node_b_events.clone()];
        for (index, events) in settlement_events.iter().enumerate() {
            let queue: SharedDeliveries = Arc::new(Mutex::new(VecDeque::new()));
            queue.lock().unwrap().push_back(fanout_delivery(
                body.clone(),
                &format!("node-{index}"),
                events,
            ));
            broker_subscriptions.push(queue);
        }
        assert_eq!(broker_subscriptions.len(), 2);

        let inbox = MockInbox::default();
        let apply = MockApply::default();
        let listener = MockListener::default();

        let spawn_worker = |region: &'static str,
                            node: &'static str,
                            deliveries: SharedDeliveries|
         -> InvalidationInboxWorkerHandle {
            spawn_invalidation_fanout_inbox_worker(
                session_connect(deliveries),
                inbox.clone(),
                apply.clone(),
                listener.clone(),
                identity(region, node),
                inbox_settings(true),
            )
            .unwrap()
        };
        let handle_a = spawn_worker("city-a", "node-a", broker_subscriptions[0].clone());
        let handle_b = spawn_worker("city-b", "node-b", broker_subscriptions[1].clone());

        wait_for(
            || {
                inbox.status_of("city-a", "node-a", "event-1") == Some("APPLIED".into())
                    && inbox.status_of("city-b", "node-b", "event-1") == Some("APPLIED".into())
            },
            "both nodes applied the invalidation independently",
        )
        .await;
        wait_for(
            || {
                node_a_events
                    .lock()
                    .unwrap()
                    .contains(&"ack:node-0".to_owned())
                    && node_b_events
                        .lock()
                        .unwrap()
                        .contains(&"ack:node-1".to_owned())
            },
            "both settlements acked",
        )
        .await;

        handle_a
            .shutdown_and_join()
            .await
            .expect("first inbox worker joins cleanly");
        handle_b
            .shutdown_and_join()
            .await
            .expect("second inbox worker joins cleanly");

        assert_eq!(
            apply.applied(),
            vec!["event-1".to_owned(), "event-1".to_owned()]
        );
        // Per-node receipts exist independently; neither node's receipt is
        // another node's proof.
        let rows = inbox.rows.lock().unwrap();
        assert!(rows.contains_key(&("city-a".into(), "node-a".into(), "event-1".into())));
        assert!(rows.contains_key(&("city-b".into(), "node-b".into(), "event-1".into())));
        assert_eq!(rows.len(), 2);
        drop(rows);

        // Sanity: each mock subscription settled exactly once.
        assert_eq!(node_a_events.lock().unwrap().len(), 1);
        assert_eq!(node_b_events.lock().unwrap().len(), 1);

        // Each node's mock stream ends after draining, so each worker must
        // have raised suspect on stream end (never silently re-subscribe a
        // dead stream without the suspect signal).
        assert!(listener.suspect_count() >= 2);
        assert!(
            listener
                .suspects()
                .iter()
                .all(|reason| reason.contains("stream ended")),
            "suspects: {:?}",
            listener.suspects()
        );
    }

    #[test]
    fn backoff_values_follow_exponential_cap() {
        let config = BackoffConfig {
            initial: Duration::from_secs(1),
            cap: Duration::from_secs(5),
            factor: 2,
        };
        assert_eq!(config.value_for(1), Duration::from_secs(1));
        assert_eq!(config.value_for(2), Duration::from_secs(2));
        assert_eq!(config.value_for(3), Duration::from_secs(4));
        assert_eq!(config.value_for(4), Duration::from_secs(5));
        assert_eq!(config.value_for(50), Duration::from_secs(5));

        let mut backoff = Backoff::new(config);
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));

        assert!(BackoffConfig {
            initial: Duration::ZERO,
            cap: Duration::from_secs(1),
            factor: 2
        }
        .validate()
        .is_err());
        assert!(BackoffConfig {
            initial: Duration::from_secs(2),
            cap: Duration::from_secs(1),
            factor: 2
        }
        .validate()
        .is_err());
        assert!(BackoffConfig {
            initial: Duration::from_secs(1),
            cap: Duration::from_secs(5),
            factor: 0
        }
        .validate()
        .is_err());
    }
}
