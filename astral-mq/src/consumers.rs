//! 具体消费者实现
//!
//! 各业务域的 MQ 消费者，在对应服务的 main.rs 中调用 `start()` 启动。
//! 每个消费者在独立的 tokio 任务中运行，互不阻塞。

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use astral_db::{
    insert_or_increment_terminal, AuditQuarantineInput, AuditQuarantineStatus, LocalMessageError,
    LocalMessageExactClaim, LocalMessageRepository, LOCAL_MESSAGE_MAX_ATTEMPTS,
};
use futures_util::StreamExt;
use lapin::message::Delivery;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicQosOptions};
use lapin::types::{FieldTable, ShortString};
use lapin::{Channel, Confirmation};
#[cfg(feature = "redis-compat")]
use redis::AsyncCommands;
use serde_json::Value;
use sqlx::MySqlPool;
use tokio::sync::{oneshot, watch};
use tokio::time::timeout;
use uuid::Uuid;

use crate::config::{
    QueueDef, EXCHANGE_DLX, MAX_RETRY, QUEUES, QUEUE_AUDIT_LOG, QUEUE_AUTHORIZATION_INVALIDATION,
    QUEUE_AUTH_SESSION_REVOCATION, QUEUE_LOGIN_EVENT,
};
use crate::consumer::{
    canonical_legacy_message_id, claim_message, complete_message, decode_delivery,
    delivery_message_id, message_type_for_queue, release_message, retry_count_from_delivery,
    terminal_canonical_message_id, validate_delivery_envelope, CompletionPolicy, Consumer,
    IdempotencyClaim,
};
use crate::error::MqError;
use crate::local_bus::{LocalBus, LocalBusError};
use crate::producer::{AuditLogPayload, AuthSessionRevocationPayload, LoginEventPayload};

/// Hard bound for a single recovery-loop database call. A hung statement must
/// never stall the fallback loop, and a timed-out call is an unproven outcome
/// (suspect + backoff), never a success.
const LOCAL_INVALIDATION_DB_CALL_BOUND: Duration = Duration::from_secs(3);

/// 会话撤销消费所需 DB（由 identity main.rs 注入）
static SESSION_REVOCATION_DB: OnceLock<MySqlPool> = OnceLock::new();

/// 会话撤销消费所需 Redis projection manager（由 identity runtime 注入；仅
/// redis-compat feature 编译——feature-off 构建中 compat 投影面不存在）。
#[cfg(feature = "redis-compat")]
static SESSION_REVOCATION_REDIS: OnceLock<redis::aio::ConnectionManager> = OnceLock::new();

/// 登录事件消费所需 DB（由 identity main.rs 注入）
static LOGIN_EVENT_DB: OnceLock<MySqlPool> = OnceLock::new();

/// 审计日志消费所需 DB（由 trustgraph main.rs 注入）
static AUDIT_LOG_DB: OnceLock<MySqlPool> = OnceLock::new();

/// 注入会话撤销 consumer 使用的 DB pool（仅 identity main.rs 调用一次）
pub fn set_session_revocation_db(pool: MySqlPool) {
    let _ = SESSION_REVOCATION_DB.set(pool);
}

/// 注入会话撤销 consumer 使用的 Redis projection manager（仅 identity runtime
/// 调用一次）。仅 redis-compat feature 编译；feature-off 构建中本 API 不存在
/// ——redis 编译层退役的显式 BREAKING 收敛点，登记于架构文档。
#[cfg(feature = "redis-compat")]
pub fn set_session_revocation_redis(redis: redis::aio::ConnectionManager) {
    let _ = SESSION_REVOCATION_REDIS.set(redis);
}

/// 注入登录事件 consumer 使用的 DB pool（仅 identity main.rs 调用一次）
pub fn set_login_event_db(pool: MySqlPool) {
    let _ = LOGIN_EVENT_DB.set(pool);
}

/// 注入审计日志 consumer 使用的 DB pool（仅 trustgraph main.rs 调用一次）
pub fn set_audit_log_db(pool: MySqlPool) {
    let _ = AUDIT_LOG_DB.set(pool);
}

/// Dispatch one delivery from the composite process bus. The bus admission is
/// transient; the handlers retain their existing durable/idempotent boundaries.
pub async fn dispatch_local_delivery(
    delivery: &crate::local_bus::LocalDelivery,
) -> Result<(), String> {
    match delivery.queue_name {
        QUEUE_AUDIT_LOG => {
            let payload: AuditLogPayload =
                serde_json::from_value(delivery.envelope.payload.clone())
                    .map_err(|error| error.to_string())?;
            handle_audit_log(&delivery.envelope.message_id, &payload)
                .await
                .map_err(|error| error.to_string())
        }
        QUEUE_LOGIN_EVENT => {
            let payload: LoginEventPayload =
                serde_json::from_value(delivery.envelope.payload.clone())
                    .map_err(|error| error.to_string())?;
            handle_login_event(&delivery.envelope.message_id, &payload)
                .await
                .map_err(|error| error.to_string())
        }
        QUEUE_AUTH_SESSION_REVOCATION => {
            let payload: AuthSessionRevocationPayload =
                serde_json::from_value(delivery.envelope.payload.clone())
                    .map_err(|error| error.to_string())?;
            handle_auth_session_revocation(&delivery.envelope.message_id, &payload)
                .await
                .map_err(|error| error.to_string())
        }
        QUEUE_AUTHORIZATION_INVALIDATION => dispatch_invalidation_event(&delivery.envelope).await,
        _ => Err("local queue has no owner".into()),
    }
}

/// Apply one delivery from the composite process bus on the in-process side of
/// a typed invalidation notification.
///
/// Public for the fanout runtime adapter: the Rabbit fanout inbox worker reuses
/// this exact entrypoint, so the local bus and the cross-node transport share
/// one invalidation contract and one ownership boundary.
///
/// The envelope is revalidated before any mutation. Evidence notifications
/// create a pending freshness fence; eligibility notifications invalidate the
/// node's source-derived auxiliary/session mirrors (hub-installed runtimes bump
/// the auxiliary epochs and clear positive read caches) and evict the L1
/// card-activity cache; session notifications update the local acceleration
/// registry. None of these operations is a durable completion proof, and
/// applying an invalidation is never an authorization READY signal — the read
/// gate stays PENDING/DENY until the authorization projection path itself
/// proves READY. Every branch is idempotent, so a recovery replay of the same
/// committed event is safe.
pub async fn dispatch_invalidation_event(
    envelope: &crate::envelope::MessageEnvelope,
) -> Result<(), String> {
    let event = crate::invalidation::InvalidationEvent::from_envelope(envelope)
        .map_err(|error| error.to_string())?;
    dispatch_typed_invalidation(event, &envelope.message_id, &envelope.operation_id)
}

/// Typed invalidation dispatch shared by the local bus and the fanout adapter.
///
/// `event_id` / `operation_id` are the stable provenance ids committed with the
/// event (envelope message/operation ids); the evidence fence dedupes on them,
/// so a recovery replay of the same committed event is idempotent.
pub fn dispatch_typed_invalidation(
    event: crate::invalidation::InvalidationEvent,
    event_id: &str,
    operation_id: &str,
) -> Result<(), String> {
    match event {
        crate::invalidation::InvalidationEvent::EvidenceInvalidated(value) => {
            let hub = astral_db::memory_projection_hub()
                .ok_or_else(|| "memory projection hub is not installed".to_owned())?;
            hub.apply_evidence_invalidation(astral_db::EvidenceInvalidationRequest {
                tenant_id: value.tenant_id,
                card_id: value.card_id,
                aggregate_type: value.aggregate_type,
                aggregate_id: value.aggregate_id,
                event_id: event_id.to_owned(),
                operation_id: operation_id.to_owned(),
                source_generation: value.source_generation,
                revoke_fence: value.revoke_fence,
                published_generation: value.published_generation,
            })
        }
        crate::invalidation::InvalidationEvent::EligibilityInvalidated(value) => {
            // 多节点通知镜像失效：hub 已装时先推进辅助纪元/失效本节点的正向读
            // 缓存（org/GlobalAdmin 辅助镜像与会话正向快照同步失效；幂等，重放
            // 安全），再对目标卡做幂等 L1 evict；hub 未装（无镜像可失效的独立
            // 部署）保持原 evict 行为不变。
            if let Some(hub) = astral_db::memory_projection_hub() {
                hub.apply_auxiliary_invalidation()?;
            }
            astral_db::evict_l1_card_active_cache(value.card_id);
            Ok(())
        }
        crate::invalidation::InvalidationEvent::SessionRevoked(value) => {
            dispatch_session_revocation(value.revoked_jtis)
        }
    }
}

/// In-process TTL shared by every session-revocation acceleration surface
/// (7 days, aligned with the legacy `jwt:revoked:{jti}` coverage window).
const SESSION_REVOCATION_MARKER_TTL_SECS: i64 = 7 * 24 * 3600;
/// `u64` view for the surfaces that count seconds as `u64` (projection store
/// note and Redis `set_ex`); the 7-day value is a positive constant.
const SESSION_REVOCATION_MARKER_TTL_SECS_U64: u64 = 7 * 24 * 3600;

/// Session-revocation acceleration dispatch, strict about registry misses.
///
/// A missing registry is never an implicit Allow: the registry-less composite
/// runtime mirrors the revocation into the global session projection store,
/// and when neither acceleration surface is installed the dispatch fails
/// closed. The durable authority is the strict DB path
/// (`astral_db::apply_revocation_projection_mysql`); these surfaces only
/// accelerate proven revocations.
fn dispatch_session_revocation(revoked_jtis: Vec<String>) -> Result<(), String> {
    if let Some(registry) =
        astral_common::session_revocation_registry::global_session_revocation_registry()
    {
        for jti in &revoked_jtis {
            registry.mark_revoked(jti, SESSION_REVOCATION_MARKER_TTL_SECS);
        }
        return Ok(());
    }
    if astral_common::session_projection_store::global_session_projection_store().is_some() {
        astral_db::note_revocations_in_process(
            &revoked_jtis,
            SESSION_REVOCATION_MARKER_TTL_SECS_U64,
        );
        return Ok(());
    }
    Err(
        "no session revocation acceleration surface is installed; refusing to acknowledge \
         SESSION_REVOKED"
            .into(),
    )
}

/// Recovery-fallback settings for the local invalidation relay.
///
/// The relay is ONLY the recovery leg for `al_message_outbox` invalidation
/// rows whose normal post-commit direct `LocalBus` delivery never completed.
/// It must never become a hot-path mechanism: idle polling and error backoff
/// stay inside the low-frequency 5–30s window, each claim takes a single row,
/// and the handler deadline (default 5s) stays far below the durable lease
/// (30s) so no heartbeat task is required and a row is always settled by its
/// owner. Every repository call is bounded (3s) so a hung statement can never
/// stall the loop.
#[derive(Debug, Clone)]
pub struct LocalInvalidationRelaySettings {
    /// Idle poll interval; bounded to the low-frequency 5–30s window.
    pub idle_poll_interval: Duration,
    /// Backoff after unproven claims; same low-frequency window.
    pub error_backoff: Duration,
    /// Handler deadline; must stay below `LOCAL_MESSAGE_LEASE_SECONDS`.
    pub handler_deadline: Duration,
    /// Hard bound for one repository call; at most 3s.
    pub db_call_deadline: Duration,
    /// Bounded join deadline used by [`LocalInvalidationRelayHandle::join`].
    pub shutdown_join_deadline: Duration,
}

impl Default for LocalInvalidationRelaySettings {
    fn default() -> Self {
        Self {
            idle_poll_interval: Duration::from_secs(15),
            error_backoff: Duration::from_secs(15),
            handler_deadline: Duration::from_secs(5),
            db_call_deadline: LOCAL_INVALIDATION_DB_CALL_BOUND,
            shutdown_join_deadline: Duration::from_secs(5),
        }
    }
}

fn local_invalidation_lease_budget_fits(
    handler_deadline: Duration,
    db_call_deadline: Duration,
    lease: Duration,
) -> bool {
    // Reserve one bounded claim plus the largest bounded post-handler path:
    // settlement followed by the best-effort IN_DOUBT write.
    let database_budget = db_call_deadline.saturating_mul(3);
    let Some(total_budget) = handler_deadline.checked_add(database_budget) else {
        return false;
    };
    total_budget < lease
}

impl LocalInvalidationRelaySettings {
    pub fn validate(&self) -> Result<(), String> {
        let idle = self.idle_poll_interval.as_secs();
        if !(5..=30).contains(&idle) {
            return Err(format!(
                "relay idle_poll_interval must stay within the 5-30s low-frequency window, got {idle}s"
            ));
        }
        let backoff = self.error_backoff.as_secs();
        if !(5..=30).contains(&backoff) {
            return Err(format!(
                "relay error_backoff must stay within the 5-30s low-frequency window, got {backoff}s"
            ));
        }
        if self.handler_deadline.is_zero() {
            return Err("relay handler_deadline must be positive".into());
        }
        if self.db_call_deadline.is_zero()
            || self.db_call_deadline > LOCAL_INVALIDATION_DB_CALL_BOUND
        {
            return Err(format!(
                "relay db_call_deadline must be within (0, {LOCAL_INVALIDATION_DB_CALL_BOUND:?}]"
            ));
        }
        if !local_invalidation_lease_budget_fits(
            self.handler_deadline,
            self.db_call_deadline,
            Duration::from_secs(astral_db::LOCAL_MESSAGE_LEASE_SECONDS),
        ) {
            return Err(format!(
                "relay claim + handler + settlement + IN_DOUBT budget ({:?} + 3 x {:?}) must stay below the durable lease ({}s)",
                self.handler_deadline,
                self.db_call_deadline,
                astral_db::LOCAL_MESSAGE_LEASE_SECONDS
            ));
        }
        if self.shutdown_join_deadline.is_zero() {
            return Err("relay shutdown_join_deadline must be positive".into());
        }
        Ok(())
    }
}

/// RAII handle for one recovery-only invalidation relay.
///
/// `cancel` marks the hub suspect and requests a cooperative stop (the loop
/// finishes its current row before exiting); `join` waits a bounded deadline
/// for the loop to exit and aborts on deadline; `Drop` marks the hub suspect
/// and aborts immediately. A relay that disappears without settling its rows
/// can therefore never leave the read gate trusting an unmonitored fallback —
/// the sticky suspect state forces `reconcile_from_durable` before any exact
/// envelope can be settled from memory.
#[must_use]
pub struct LocalInvalidationRelayHandle {
    shutdown: watch::Sender<bool>,
    join: Mutex<Option<tokio::task::JoinHandle<()>>>,
    join_deadline: Duration,
}

struct LocalRelayJoinGuard {
    join: Option<tokio::task::JoinHandle<()>>,
    shutdown: watch::Sender<bool>,
}

impl Drop for LocalRelayJoinGuard {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            self.shutdown.send_replace(true);
            mark_relay_suspect("local invalidation relay join interrupted; outcome unknown");
            join.abort();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    if timeout(Duration::from_secs(1), join).await.is_err() {
                        tracing::error!("local invalidation relay abort remains unproven");
                    }
                });
            }
        }
    }
}

impl LocalInvalidationRelayHandle {
    /// Cooperative stop: mark the hub suspect, then signal the loop.
    pub fn cancel(&self) {
        mark_relay_suspect("local invalidation relay cancelled");
        let _ = self.shutdown.send(true);
    }

    /// Bounded join: `Ok` once the loop exited cooperatively; `Err` (after
    /// aborting the task) when the join deadline elapsed or the task panicked.
    pub async fn join(self) -> Result<(), String> {
        let join = self
            .join
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| "relay join handle already taken".to_owned())?;
        let mut guard = LocalRelayJoinGuard {
            join: Some(join),
            shutdown: self.shutdown.clone(),
        };
        match timeout(self.join_deadline, guard.join.as_mut().unwrap()).await {
            Ok(Ok(())) => {
                guard.join.take();
                Ok(())
            }
            Ok(Err(join_error)) => {
                // The JoinHandle has completed (and been consumed by JoinError),
                // so the guard no longer owns a task to abort or observe. A panic
                // may have interrupted a row after its local effect but before
                // durable settlement; keep the read gate suspect for reconciliation.
                guard.join.take();
                mark_relay_suspect("local invalidation relay join failed; outcome unknown");
                Err(format!("relay task ended abnormally: {join_error}"))
            }
            Err(_elapsed) => {
                guard.join.as_ref().unwrap().abort();
                if timeout(Duration::from_secs(1), guard.join.as_mut().unwrap())
                    .await
                    .is_ok()
                {
                    guard.join.take();
                }
                mark_relay_suspect("local invalidation relay join timed out; outcome unknown");
                Err(format!(
                    "relay join deadline ({:?}) elapsed; task aborted; outcome unknown",
                    self.join_deadline
                ))
            }
        }
    }

    #[cfg(test)]
    fn for_tests(join: tokio::task::JoinHandle<()>, join_deadline: Duration) -> Self {
        let (shutdown, _shutdown_rx) = watch::channel(false);
        Self {
            shutdown,
            join: Mutex::new(Some(join)),
            join_deadline,
        }
    }
}

impl Drop for LocalInvalidationRelayHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(join) = self.join.lock().unwrap().take() {
            mark_relay_suspect("local invalidation relay handle dropped without join");
            join.abort();
        }
    }
}

/// Sticky-suspect propagation for the recovery relay. Cancellation, unproven
/// claims, unknown handler outcomes and lease failures all land here; the hub
/// only clears suspect through a full durable reconciliation.
fn mark_relay_suspect(reason: impl Into<String>) {
    if let Some(hub) = astral_db::memory_projection_hub() {
        hub.mark_channel_suspect(reason);
    }
}

/// Spawn the recovery-only local invalidation relay.
///
/// Source transactions append typed invalidations to `al_message_outbox` and
/// the normal path is the direct post-commit `LocalBus` delivery; this worker
/// is the fallback that advances only committed rows the direct leg never
/// settled. It claims one row at a time at a low-frequency idle poll, delivers
/// the exact committed envelope through the bounded LocalBus, and advances the
/// row only on a proven lease transition. Cancellation, unproven claims,
/// unknown handler outcomes and lease failures mark the memory projection hub
/// suspect instead of replaying anything blindly; malformed envelopes are
/// quarantined immediately; IN_DOUBT rows leave the state machine only through
/// the explicit reconciliation interface.
pub fn spawn_local_invalidation_relay(
    pool: MySqlPool,
    bus: LocalBus,
    worker_id: impl Into<String>,
) -> LocalInvalidationRelayHandle {
    spawn_local_invalidation_relay_with_settings(
        pool,
        bus,
        worker_id,
        LocalInvalidationRelaySettings::default(),
    )
    .expect("default local invalidation relay settings are valid")
}

/// [`spawn_local_invalidation_relay`] with explicit, validated settings.
pub fn spawn_local_invalidation_relay_with_settings(
    pool: MySqlPool,
    bus: LocalBus,
    worker_id: impl Into<String>,
    settings: LocalInvalidationRelaySettings,
) -> Result<LocalInvalidationRelayHandle, String> {
    settings.validate()?;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let join = tokio::spawn(run_local_invalidation_relay(
        pool,
        bus,
        worker_id.into(),
        settings.clone(),
        shutdown_rx,
    ));
    Ok(LocalInvalidationRelayHandle {
        shutdown,
        join: Mutex::new(Some(join)),
        join_deadline: settings.shutdown_join_deadline,
    })
}

async fn run_local_invalidation_relay(
    pool: MySqlPool,
    bus: LocalBus,
    worker_id: String,
    settings: LocalInvalidationRelaySettings,
    mut shutdown: watch::Receiver<bool>,
) {
    let repository = LocalMessageRepository::new(pool);
    loop {
        if *shutdown.borrow() {
            tracing::info!(
                worker_id = %worker_id,
                "local invalidation recovery relay stopped cooperatively"
            );
            return;
        }
        // Claim-one: the handler deadline stays far below the durable lease, so
        // no heartbeat task exists and every settlement is owner-proven.
        let claimed = match bounded_db(
            settings.db_call_deadline,
            repository.claim_batch(&worker_id, QUEUE_AUTHORIZATION_INVALIDATION, 1),
            "claim",
        )
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                // The claim is unproven: mark suspect and back off instead of
                // replaying anything blindly.
                mark_relay_suspect("local invalidation relay claim is unproven");
                tracing::error!(
                    worker_id = %worker_id,
                    queue = QUEUE_AUTHORIZATION_INVALIDATION,
                    error = %error,
                    "local invalidation recovery relay claim failed"
                );
                if shutdown_or_sleep(&mut shutdown, settings.error_backoff).await {
                    tracing::info!(
                        worker_id = %worker_id,
                        "local invalidation recovery relay stopped cooperatively"
                    );
                    return;
                }
                continue;
            }
        };
        if claimed.is_empty() {
            if shutdown_or_sleep(&mut shutdown, settings.idle_poll_interval).await {
                tracing::info!(
                    worker_id = %worker_id,
                    "local invalidation recovery relay stopped cooperatively"
                );
                return;
            }
            continue;
        }
        for row in claimed {
            if let Err(error) =
                process_local_invalidation_row(&repository, &bus, row, &settings).await
            {
                tracing::warn!(
                    worker_id = %worker_id,
                    error = %error,
                    "local invalidation recovery row did not reach a proven successful settlement"
                );
            }
        }
    }
}

/// True when the relay should stop: either a shutdown was signalled (or the
/// handle dropped, closing the channel) or the sleep completed with no signal.
async fn shutdown_or_sleep(shutdown: &mut watch::Receiver<bool>, duration: Duration) -> bool {
    tokio::select! {
        changed = shutdown.changed() => match changed {
            Ok(()) => *shutdown.borrow(),
            Err(_) => true,
        },
        _ = tokio::time::sleep(duration) => false,
    }
}

/// Bound one repository call. A timed-out call is an unproven outcome, not a
/// success; the caller marks the hub suspect for every error.
async fn bounded_db<T>(
    deadline: Duration,
    future: impl std::future::Future<Output = Result<T, LocalMessageError>>,
    label: &'static str,
) -> Result<T, String> {
    match timeout(deadline, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_elapsed) => Err(format!(
            "{label} exceeded the {deadline:?} database call bound; outcome unknown"
        )),
    }
}

/// Classified result of one recovery delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalInvalidationRelayOutcome {
    /// The typed handler completed; the row may be settled by its owner.
    Delivered,
    /// Malformed or tampered envelope: quarantine immediately, never retry.
    Malformed(String),
    /// Deterministic failure that provably applied no local side effect
    /// (admission refusal, handler rejection before mutation, duplicate
    /// in-flight): bounded retry, quarantine at the attempt ceiling.
    KnownFailure(String),
    /// The outcome cannot be proven (deadline, disappearing consumer,
    /// unproven settle): IN_DOUBT plus hub suspect; reconcile before re-run.
    Unknown(String),
}

/// Durable state transition selected for one classified outcome. Pure so the
/// classification contract stays unit-testable without a database.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalInvalidationRowTransition {
    Complete,
    MarkInDoubt(String),
    Quarantine(String),
    Retry(String),
}

fn local_invalidation_transition(
    attempts: i32,
    outcome: LocalInvalidationRelayOutcome,
) -> LocalInvalidationRowTransition {
    match outcome {
        LocalInvalidationRelayOutcome::Delivered => LocalInvalidationRowTransition::Complete,
        LocalInvalidationRelayOutcome::Unknown(reason) => {
            LocalInvalidationRowTransition::MarkInDoubt(reason)
        }
        // Malformed rows quarantine immediately regardless of the attempt
        // budget: retrying tampered bytes can never succeed.
        LocalInvalidationRelayOutcome::Malformed(reason) => {
            LocalInvalidationRowTransition::Quarantine(reason)
        }
        LocalInvalidationRelayOutcome::KnownFailure(reason)
            if attempts >= LOCAL_MESSAGE_MAX_ATTEMPTS =>
        {
            LocalInvalidationRowTransition::Quarantine(format!("attempt ceiling reached: {reason}"))
        }
        LocalInvalidationRelayOutcome::KnownFailure(reason) => {
            LocalInvalidationRowTransition::Retry(reason)
        }
    }
}

const LOCAL_INVALIDATION_OWNER: &str = "local-invalidation-direct";
// Keep claim (3s) + handler (5s) + an owner settlement (3s) and a
// best-effort IN_DOUBT write (3s) below the source dispatcher's 15s outer
// deadline and the 30s durable lease.
const LOCAL_INVALIDATION_DISPATCH_DEADLINE: Duration = Duration::from_secs(5);
const LOCAL_INVALIDATION_CLAIM_DEADLINE: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalInvalidationDispatchOutcome {
    Completed,
    AlreadyProcessed,
    NotClaimed { status: String, reason: String },
    NotFound,
}

/// Direct post-commit dispatcher and durable relay share the same exact-row
/// lease, handler, and completion contract. The caller supplies only the stable
/// message identity; the envelope always comes from the committed outbox row.
pub async fn dispatch_committed_local_invalidation(
    pool: MySqlPool,
    bus: LocalBus,
    envelope: &crate::envelope::MessageEnvelope,
) -> Result<LocalInvalidationDispatchOutcome, String> {
    let repository = LocalMessageRepository::new(pool);
    let claim = match timeout(
        LOCAL_INVALIDATION_CLAIM_DEADLINE,
        repository.claim_exact(
            LOCAL_INVALIDATION_OWNER,
            QUEUE_AUTHORIZATION_INVALIDATION,
            &envelope.message_id,
        ),
    )
    .await
    {
        Ok(Ok(claim)) => claim,
        Ok(Err(error)) => {
            mark_relay_suspect("direct invalidation exact claim failed");
            return Err(format!("direct invalidation claim failed: {error}"));
        }
        Err(_) => {
            mark_relay_suspect("direct invalidation exact claim timed out; outcome unknown");
            return Err("direct invalidation claim timed out; outcome unknown".into());
        }
    };
    let expected_bytes = match envelope.envelope_json() {
        Ok(bytes) => bytes,
        Err(error) => {
            mark_relay_suspect("direct invalidation receipt serialization failed");
            return Err(format!(
                "direct invalidation receipt serialization failed: {error}"
            ));
        }
    };
    let (row, already_processed) = match claim {
        LocalMessageExactClaim::Claimed(row) => (row, false),
        LocalMessageExactClaim::AlreadyProcessed(row) => (row, true),
        LocalMessageExactClaim::NotClaimable { status, reason } => {
            mark_relay_suspect(format!(
                "direct invalidation not claimable ({status}): {reason}"
            ));
            return Ok(LocalInvalidationDispatchOutcome::NotClaimed { status, reason });
        }
        LocalMessageExactClaim::NotFound => {
            mark_relay_suspect("direct invalidation exact outbox row missing after commit");
            return Ok(LocalInvalidationDispatchOutcome::NotFound);
        }
    };
    match bind_relay_envelope(&row) {
        Ok(committed) if row.payload_json == expected_bytes && committed == *envelope => {}
        Ok(_) => {
            let reason = "direct invalidation receipt differs from exact committed outbox bytes";
            mark_relay_suspect(reason);
            if !already_processed {
                let token = row.lease_owner.as_deref().ok_or_else(|| {
                    "direct invalidation mismatch row has no lease owner".to_owned()
                })?;
                bounded_db(
                    LOCAL_INVALIDATION_CLAIM_DEADLINE,
                    repository.quarantine(&row.message_id, token, reason),
                    "quarantine_mismatched_receipt",
                )
                .await?;
            }
            return Err(reason.into());
        }
        Err(reason) => {
            mark_relay_suspect("direct invalidation durable envelope failed validation");
            if !already_processed {
                let token = row.lease_owner.as_deref().ok_or_else(|| {
                    "direct invalidation malformed row has no lease owner".to_owned()
                })?;
                bounded_db(
                    LOCAL_INVALIDATION_CLAIM_DEADLINE,
                    repository.quarantine(&row.message_id, token, &reason),
                    "quarantine_malformed_row",
                )
                .await?;
            }
            return Err(format!(
                "direct invalidation durable row rejected: {reason}"
            ));
        }
    };
    if already_processed {
        return Ok(LocalInvalidationDispatchOutcome::AlreadyProcessed);
    }
    let settings = LocalInvalidationRelaySettings {
        handler_deadline: LOCAL_INVALIDATION_DISPATCH_DEADLINE,
        ..Default::default()
    };
    process_local_invalidation_row(&repository, &bus, row, &settings).await?;
    Ok(LocalInvalidationDispatchOutcome::Completed)
}

async fn process_local_invalidation_row(
    repository: &LocalMessageRepository,
    bus: &LocalBus,
    row: astral_db::LocalMessageRow,
    settings: &LocalInvalidationRelaySettings,
) -> Result<(), String> {
    let Some(lease_token) = row.lease_owner.clone() else {
        tracing::error!(
            message_id = %row.message_id,
            "claimed local invalidation row has no lease owner"
        );
        mark_relay_suspect("claimed local invalidation row has no lease owner");
        return Err("claimed local invalidation row has no lease owner".into());
    };
    let outcome = match relay_local_invalidation_row(bus, &row, settings.handler_deadline).await {
        Ok(()) => LocalInvalidationRelayOutcome::Delivered,
        Err(outcome) => outcome,
    };
    match local_invalidation_transition(row.attempts, outcome) {
        LocalInvalidationRowTransition::Complete => {
            match bounded_db(
                settings.db_call_deadline,
                repository.complete(&row.message_id, &lease_token),
                "complete",
            )
            .await
            {
                Ok(()) => Ok(()),
                Err(error) => {
                    // Completion is unproven: never declare success after a lost
                    // owner. Best-effort IN_DOUBT, suspect either way.
                    mark_relay_suspect("local invalidation completion is unproven");
                    tracing::error!(
                        message_id = %row.message_id,
                        error = %error,
                        "local invalidation completion is unknown after handler success"
                    );
                    let _ = bounded_db(
                        settings.db_call_deadline,
                        repository.mark_in_doubt(
                            &row.message_id,
                            &lease_token,
                            "completion unproven",
                        ),
                        "mark_in_doubt",
                    )
                    .await;
                    Err(format!("local invalidation completion unproven: {error}"))
                }
            }
        }
        LocalInvalidationRowTransition::MarkInDoubt(reason) => {
            mark_relay_suspect("local invalidation handler outcome is unknown");
            match bounded_db(
                settings.db_call_deadline,
                repository.mark_in_doubt(&row.message_id, &lease_token, &reason),
                "mark_in_doubt",
            )
            .await
            {
                Ok(()) => Err(format!("local invalidation outcome unknown: {reason}")),
                Err(error) => {
                    mark_relay_suspect("local invalidation IN_DOUBT transition failed");
                    tracing::error!(
                        message_id = %row.message_id,
                        error = %error,
                        "local invalidation unknown outcome could not be recorded"
                    );
                    Err(format!(
                        "local invalidation IN_DOUBT transition unproven: {error}"
                    ))
                }
            }
        }
        LocalInvalidationRowTransition::Quarantine(reason) => {
            // A quarantined committed invalidation did not reach a proven
            // freshness apply, so the mirror stays fail-closed until durable
            // reconciliation establishes a safe frontier.
            mark_relay_suspect("local invalidation was quarantined before apply");
            match bounded_db(
                settings.db_call_deadline,
                repository.quarantine(&row.message_id, &lease_token, &reason),
                "quarantine",
            )
            .await
            {
                Ok(()) => {
                    tracing::warn!(
                        message_id = %row.message_id,
                        reason = %reason,
                        "malformed local invalidation envelope quarantined immediately"
                    );
                    Err(format!("local invalidation quarantined: {reason}"))
                }
                Err(error) => {
                    mark_relay_suspect("local invalidation quarantine transition failed");
                    tracing::error!(
                        message_id = %row.message_id,
                        error = %error,
                        "local invalidation quarantine transition failed"
                    );
                    Err(format!("local invalidation quarantine unproven: {error}"))
                }
            }
        }
        LocalInvalidationRowTransition::Retry(reason) => {
            // Keep the strict read gate closed while the durable retry is
            // pending; LocalBus admission failure cannot imply freshness apply.
            mark_relay_suspect("local invalidation retry scheduled before apply");
            match bounded_db(
                settings.db_call_deadline,
                repository.schedule_retry(&row.message_id, &lease_token, &reason),
                "schedule_retry",
            )
            .await
            {
                Ok(()) => Err(format!(
                    "local invalidation will retry after known failure: {reason}"
                )),
                Err(error) => {
                    mark_relay_suspect("local invalidation retry transition failed");
                    tracing::error!(
                        message_id = %row.message_id,
                        error = %error,
                        "local invalidation retry transition failed"
                    );
                    Err(format!(
                        "local invalidation retry transition unproven: {error}"
                    ))
                }
            }
        }
    }
}

async fn relay_local_invalidation_row(
    bus: &LocalBus,
    row: &astral_db::LocalMessageRow,
    handler_deadline: Duration,
) -> Result<(), LocalInvalidationRelayOutcome> {
    let envelope = bind_relay_envelope(row).map_err(LocalInvalidationRelayOutcome::Malformed)?;
    match bus
        .publish_and_wait(
            QUEUE_AUTHORIZATION_INVALIDATION,
            crate::config::ROUTING_KEY_AUTHORIZATION_INVALIDATION,
            envelope,
            handler_deadline,
        )
        .await
    {
        Ok(()) => Ok(()),
        Err(LocalBusError::UnknownOutcome(reason)) => {
            Err(LocalInvalidationRelayOutcome::Unknown(reason.to_string()))
        }
        Err(error) => Err(classify_relay_bus_failure(error)),
    }
}

/// Bind the durable row to its exact committed envelope before any delivery.
///
/// Binding covers the full envelope contract: queue domain, transport headers,
/// envelope parse + validation, canonical committed bytes, every identity and
/// scope field (stable ids, type, schema version, tenant, regions, ordering
/// key, payload digest) and the typed invalidation contract. Any divergence is
/// `Err` and the caller quarantines immediately — the relay never delivers
/// bytes it cannot prove.
fn bind_relay_envelope(
    row: &astral_db::LocalMessageRow,
) -> Result<crate::envelope::MessageEnvelope, String> {
    // Domain separation: this relay only advances typed invalidation rows.
    if row.queue_name != QUEUE_AUTHORIZATION_INVALIDATION {
        return Err(format!(
            "row queue {} is not the typed invalidation queue",
            row.queue_name
        ));
    }
    // The source append writes headers_json = NULL; transport headers on a
    // committed invalidation row are tampering.
    if row.headers_json.is_some() {
        return Err("local invalidation row carries unexpected transport headers".into());
    }
    let envelope: crate::envelope::MessageEnvelope =
        serde_json::from_str(&row.payload_json).map_err(|error| error.to_string())?;
    envelope.validate()?;
    // Canonical bytes: the durable payload must be exactly the canonical
    // envelope JSON the source transaction committed.
    if envelope.envelope_json()? != row.payload_json {
        return Err(
            "local invalidation payload is not the canonical committed envelope bytes".into(),
        );
    }
    if envelope.message_id != row.message_id
        || envelope.operation_id != row.operation_id
        || envelope.message_type != row.message_type
        || envelope.tenant_id != row.tenant_id
        || envelope.origin_region != row.origin_region
        || envelope.target_region.as_deref() != row.target_region.as_deref()
        || envelope.schema_version != row.schema_version
        || envelope.ordering_key.as_deref() != row.ordering_key.as_deref()
        || envelope.payload_sha256 != row.payload_sha256
    {
        return Err("local invalidation envelope does not match durable row".into());
    }
    // Typed contract: unknown types, scope tampering and malformed payloads
    // fail closed here instead of reaching any handler.
    crate::invalidation::InvalidationEvent::from_envelope(&envelope)
        .map_err(|error| error.to_string())?;
    Ok(envelope)
}

/// Bus failures that provably applied no local side effect are bounded-retry
/// known failures — re-applying an invalidation is idempotent by contract, so
/// these never need the IN_DOUBT path. Anything that could have mutated stays
/// unknown, and contract-invalid bytes are quarantined, not retried.
fn classify_relay_bus_failure(error: LocalBusError) -> LocalInvalidationRelayOutcome {
    match error {
        // Admission refusals: the envelope never reached a handler.
        LocalBusError::InvalidLimits
        | LocalBusError::InvalidOwner(_)
        | LocalBusError::InvalidRoute(_)
        | LocalBusError::NoOwner(_)
        | LocalBusError::Closed(_)
        | LocalBusError::Full(_)
        | LocalBusError::TooLarge { .. } => {
            LocalInvalidationRelayOutcome::KnownFailure(error.to_string())
        }
        // The same message id is already in flight on the direct-delivery leg;
        // this attempt applied nothing and a later recovery pass settles it.
        LocalBusError::Duplicate(_) => {
            LocalInvalidationRelayOutcome::KnownFailure(error.to_string())
        }
        // A handler error can be returned after a freshness fence or another
        // idempotent local mutation was applied. Its side-effect position is
        // therefore unproven; quarantine/reconcile before any replay.
        LocalBusError::Handler(_) => LocalInvalidationRelayOutcome::Unknown(error.to_string()),
        // The bus re-validated the typed contract and refused: contract-invalid
        // bytes are quarantined immediately, not retried.
        LocalBusError::InvalidMessage(_) => {
            LocalInvalidationRelayOutcome::Malformed(error.to_string())
        }
        // Deadlines and disappearing consumers leave the outcome unprovable.
        LocalBusError::UnknownOutcome(_) => {
            LocalInvalidationRelayOutcome::Unknown(error.to_string())
        }
    }
}

/// Legacy database-polling worker retained only for migration/reconciliation
/// tooling. Production `local` transport must use `LocalBus` in the composite
/// runtime; this function is intentionally not called by service entrypoints.
#[deprecated(note = "use LocalBus owner consumers in the composite runtime")]
pub fn spawn_local_message_worker(
    pool: MySqlPool,
    queue_name: &'static str,
    worker_id: impl Into<String>,
) {
    let worker_id = worker_id.into();
    tokio::spawn(async move {
        let repository = LocalMessageRepository::new(pool.clone());
        loop {
            match repository.claim_batch(&worker_id, queue_name, 16).await {
                Ok(rows) if rows.is_empty() => tokio::time::sleep(Duration::from_millis(250)).await,
                Ok(rows) => {
                    for row in rows {
                        let lease_token = row.lease_owner.clone().unwrap_or_default();
                        let heartbeat_repository = repository.clone();
                        let heartbeat_message_id = row.message_id.clone();
                        let heartbeat_token = lease_token.clone();
                        let heartbeat = tokio::spawn(async move {
                            let interval = Duration::from_secs(
                                astral_db::LOCAL_MESSAGE_LEASE_SECONDS
                                    .saturating_div(3)
                                    .max(1),
                            );
                            loop {
                                tokio::time::sleep(interval).await;
                                if heartbeat_repository
                                    .heartbeat(&heartbeat_message_id, &heartbeat_token)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        });
                        let result = dispatch_local_message(&pool, &row).await;
                        heartbeat.abort();
                        match result {
                            Ok(()) => {
                                if let Err(error) =
                                    repository.complete(&row.message_id, &lease_token).await
                                {
                                    tracing::error!(queue = queue_name, message_id = %row.message_id, error = %error, "local message completion failed; durable result is unknown");
                                }
                            }
                            Err(error) if row.attempts >= LOCAL_MESSAGE_MAX_ATTEMPTS => {
                                if let Err(transition_error) = repository
                                    .quarantine(&row.message_id, &lease_token, &error)
                                    .await
                                {
                                    tracing::error!(queue = queue_name, message_id = %row.message_id, error = %transition_error, "local message quarantine transition failed");
                                }
                            }
                            Err(error) => {
                                if let Err(transition_error) = repository
                                    .schedule_retry(&row.message_id, &lease_token, &error)
                                    .await
                                {
                                    tracing::error!(queue = queue_name, message_id = %row.message_id, error = %transition_error, "local message retry transition failed");
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(queue = queue_name, error = %error, "local message claim failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    });
}

async fn dispatch_local_message(
    _pool: &MySqlPool,
    row: &astral_db::LocalMessageRow,
) -> Result<(), String> {
    let envelope: crate::envelope::MessageEnvelope =
        serde_json::from_str(&row.payload_json).map_err(|error| error.to_string())?;
    envelope.validate().map_err(|error| error.to_string())?;
    if envelope.message_id != row.message_id || envelope.payload_sha256 != row.payload_sha256 {
        return Err("local message envelope identity mismatch".into());
    }
    match row.queue_name.as_str() {
        QUEUE_AUDIT_LOG => {
            let payload: AuditLogPayload = serde_json::from_value(envelope.payload.clone())
                .map_err(|error| error.to_string())?;
            handle_audit_log(&envelope.message_id, &payload)
                .await
                .map_err(|error| error.to_string())
        }
        QUEUE_LOGIN_EVENT => {
            let payload: LoginEventPayload = serde_json::from_value(envelope.payload.clone())
                .map_err(|error| error.to_string())?;
            handle_login_event(&envelope.message_id, &payload)
                .await
                .map_err(|error| error.to_string())
        }
        QUEUE_AUTH_SESSION_REVOCATION => {
            let payload: AuthSessionRevocationPayload =
                serde_json::from_value(envelope.payload.clone())
                    .map_err(|error| error.to_string())?;
            handle_auth_session_revocation(&envelope.message_id, &payload)
                .await
                .map_err(|error| error.to_string())
        }
        QUEUE_AUTHORIZATION_INVALIDATION => dispatch_invalidation_event(&envelope).await,
        _ => Err("local queue has no owner".into()),
    }
}

/// inspect an untyped message. Business consumers must use a typed payload.
#[allow(dead_code)]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericMessage {
    pub message_id: String,
    pub message_type: Option<String>,
    #[allow(dead_code)]
    pub card_id: Option<i64>,
    #[allow(dead_code)]
    pub user_id: Option<i64>,
    pub payload: Option<serde_json::Value>,
}

/// 启动通用业务消费者。
///
/// 审计、登录、权限刷新和会话撤销由各自 owner 服务显式启动；这里不再
/// 注册会 ACK 丢弃 payload 的通用 handler。
pub async fn start_all_consumers(_channel: &Channel) -> Result<Vec<String>, MqError> {
    Ok(Vec::new())
}

/// DLQ 消费归属。
///
/// `start_dlq_consumers` 只接受这两个当前有明确 owner 的值；没有 owner 的
/// Learn/Chat/Duo 队列仍保留在 topology，但不会被任何当前服务消费。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DlqOwner {
    Identity,
    TrustGraph,
}

impl DlqOwner {
    fn quarantine_queue(self, queue_name: &str) -> bool {
        matches!(
            (self, queue_name),
            (Self::Identity, QUEUE_LOGIN_EVENT)
                | (Self::Identity, QUEUE_AUTH_SESSION_REVOCATION)
                | (Self::TrustGraph, QUEUE_AUDIT_LOG)
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DlqStartupError {
    #[error("invalid DLQ owner mapping: {0}")]
    InvalidMapping(String),
    #[error("DLQ consumer startup failed: {0}")]
    Consume(String),
}

impl From<DlqStartupError> for MqError {
    fn from(error: DlqStartupError) -> Self {
        MqError::Consume(error.to_string())
    }
}

impl DlqOwner {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::TrustGraph => "trustgraph",
        }
    }
}

/// 启动指定 owner 的 DLQ 消费者，不允许默认全量消费。
///
/// 死信消息按 `x-retry-count` 预算重投回原业务队列（经 astral.dlx → 业务队列，携带递增计数）。
/// republish/confirm 失败使用独立 `x-dlq-republish-count` 预算；失败副本先确认写回 durable DLQ
/// 后 ACK 当前 delivery，无法确认保留时走结构化 terminal nack(requeue=false)。超过业务预算后进入终态并记录结构化告警。所有 `basic_consume` 在 starter 返回前完成；
/// 任一队列声明消费者失败都会返回错误，避免启动成功但静默缺 consumer。
///
/// owner mapping 是进程内静态契约：每个已声明业务队列必须出现且只能出现一次；
/// 未分配给当前 owner 的队列显式标记为 `None`，不会被 Identity 或 TrustGraph 领取。
/// 不使用隐式环境变量，也不依赖 broker-side leader election。
pub async fn start_dlq_consumers(
    channel: &Channel,
    owner: DlqOwner,
    quarantine_db: Option<MySqlPool>,
) -> Result<(), DlqStartupError> {
    use lapin::options::BasicConsumeOptions;
    use lapin::types::{FieldTable, ShortString};

    let queue_defs = dlq_queue_defs_for_owner(owner).map_err(DlqStartupError::InvalidMapping)?;
    let mut consumers = Vec::with_capacity(queue_defs.len());

    // 先完成全部 basic_consume，再创建后台任务。这样任何一个队列失败时
    // starter 都返回 Err，调用方不会把"部分启动"误判为成功。
    for def in queue_defs {
        let dlq = crate::config::dlx_routing_key(def.name);
        let consumer_tag = dlq_consumer_tag(owner, def.name);
        channel
            .basic_qos(
                crate::consumer::DEFAULT_PREFETCH,
                BasicQosOptions { global: false },
            )
            .await
            .map_err(|error| {
                DlqStartupError::Consume(format!(
                    "owner={} queue={} consumer_tag={} qos: {error}",
                    owner.as_str(),
                    dlq,
                    consumer_tag
                ))
            })?;
        let consumer = channel
            .basic_consume(
                ShortString::from(dlq.as_str()),
                ShortString::from(consumer_tag.as_str()),
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|error| {
                DlqStartupError::Consume(format!(
                    "owner={} queue={} consumer_tag={}: {error}",
                    owner.as_str(),
                    dlq,
                    consumer_tag
                ))
            })?;
        consumers.push((def, dlq, consumer_tag, consumer));
    }

    for (def, dlq, consumer_tag, consumer) in consumers {
        let channel = channel.clone();
        let business_queue = def.name.to_string();
        let business_rk = def.routing_key.to_string();
        let business_exchange = def.exchange_name.to_string();
        let owner_name = owner.as_str();
        let log_dlq = dlq.clone();
        let quarantine_db = quarantine_db.clone();
        let log_consumer_tag = consumer_tag.clone();
        tracing::info!(
            owner = owner_name,
            queue = %dlq,
            consumer_tag = %consumer_tag,
            "DLQ re-drive consumer started"
        );
        let context = DlqConsumerContext {
            owner: owner_name,
            dlq,
            consumer_tag,
            business_queue,
            business_rk,
            business_exchange,
            quarantine_db,
            quarantine_enabled: owner.quarantine_queue(def.name),
        };
        tokio::spawn(async move {
            if let Err(error) = run_dlq_consumer(channel, consumer, context).await {
                tracing::error!(
                    owner = owner_name,
                    queue = %log_dlq,
                    consumer_tag = %log_consumer_tag,
                    error = %error,
                    "DLQ consumer stopped"
                );
            }
        });
    }

    Ok(())
}

struct DlqConsumerContext {
    owner: &'static str,
    dlq: String,
    consumer_tag: String,
    business_queue: String,
    business_rk: String,
    business_exchange: String,
    quarantine_db: Option<MySqlPool>,
    quarantine_enabled: bool,
}

const HEADER_REPUBLISH_COUNT: &str = "x-dlq-republish-count";
const MAX_REPUBLISH_ATTEMPTS: u32 = 3;

#[derive(Debug, PartialEq, Eq)]
enum RepublishFailureAction {
    RetainAndRequeue { attempt: u32 },
    Terminal { attempt: u32 },
}

fn next_republish_failure_action(current_attempt: u32) -> RepublishFailureAction {
    let attempt = current_attempt
        .min(MAX_REPUBLISH_ATTEMPTS.saturating_sub(1))
        .saturating_add(1);
    if attempt >= MAX_REPUBLISH_ATTEMPTS {
        RepublishFailureAction::Terminal { attempt }
    } else {
        RepublishFailureAction::RetainAndRequeue { attempt }
    }
}

fn dlq_republish_count(delivery: &lapin::message::Delivery) -> u32 {
    delivery
        .properties
        .headers()
        .as_ref()
        .and_then(|headers| headers.inner().get(HEADER_REPUBLISH_COUNT))
        .and_then(|value| value.as_long_long_int())
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0)
}

#[derive(Debug, PartialEq, Eq)]
enum TerminalCaptureResult {
    NotSelected,
    Captured { quarantine_id: i64 },
    Failed { reason: String },
}

/// The action after a terminal quarantine attempt. A capture-enabled queue
/// never falls through to the ordinary terminal ACK path.
#[derive(Debug, PartialEq, Eq)]
enum TerminalCaptureAction {
    AckAfterCapture,
    AckWithoutCapture,
    RetainAndRequeue { attempt: u32 },
    PreserveUnacked,
}

fn quarantine_owner_queue(queue_name: &str) -> bool {
    matches!(
        queue_name,
        QUEUE_AUDIT_LOG | QUEUE_LOGIN_EVENT | QUEUE_AUTH_SESSION_REVOCATION
    )
}

fn terminal_capture_selected(context: &DlqConsumerContext) -> bool {
    quarantine_owner_queue(&context.business_queue) && context.quarantine_enabled
}

/// Once a quarantine write fails, use the existing durable DLQ budget while it
/// still has room. At the saturated count, leaving the delivery unacked is the
/// only fail-closed action: ACK would lose it and another same-count publish
/// would create an unbounded terminal loop.
fn capture_failure_action(current_attempt: u32) -> TerminalCaptureAction {
    if current_attempt < MAX_REPUBLISH_ATTEMPTS {
        TerminalCaptureAction::RetainAndRequeue {
            attempt: current_attempt.saturating_add(1),
        }
    } else {
        TerminalCaptureAction::PreserveUnacked
    }
}

fn terminal_capture_action(
    context: &DlqConsumerContext,
    result: &TerminalCaptureResult,
    current_attempt: u32,
) -> TerminalCaptureAction {
    if !quarantine_owner_queue(&context.business_queue) {
        return TerminalCaptureAction::AckWithoutCapture;
    }
    if !terminal_capture_selected(context) {
        return capture_failure_action(current_attempt);
    }
    match result {
        TerminalCaptureResult::Captured { .. } => TerminalCaptureAction::AckAfterCapture,
        TerminalCaptureResult::NotSelected | TerminalCaptureResult::Failed { .. } => {
            capture_failure_action(current_attempt)
        }
    }
}

fn quarantine_failure_reason(reason: &str, republish_count: u32) -> String {
    format!("{reason};dlq_republish_count={republish_count}")
}

/// Capture one terminal delivery only for the queues whose owner has the
/// quarantine repository. The original bytes and routing metadata are kept;
/// legacy login identities are resolved by `terminal_canonical_message_id`.
async fn capture_terminal_delivery(
    context: &DlqConsumerContext,
    delivery: &lapin::message::Delivery,
    retry_count: u32,
    republish_count: u32,
    failure_reason: &str,
) -> TerminalCaptureResult {
    if !quarantine_owner_queue(&context.business_queue) {
        return TerminalCaptureResult::NotSelected;
    }
    if !context.quarantine_enabled {
        return TerminalCaptureResult::Failed {
            reason: "quarantine_disabled".to_owned(),
        };
    }
    let Some(pool) = context.quarantine_db.as_ref() else {
        return TerminalCaptureResult::Failed {
            reason: "quarantine_db_unavailable".to_owned(),
        };
    };

    let input = AuditQuarantineInput {
        source_queue: context.business_queue.clone(),
        message_type: message_type_for_queue(&context.business_queue).to_owned(),
        canonical_message_id: terminal_canonical_message_id(delivery, &context.business_queue),
        raw_payload: delivery.data.clone(),
        source_exchange: context.business_exchange.clone(),
        source_routing_key: context.business_rk.clone(),
        retry_count,
        failure_reason: quarantine_failure_reason(failure_reason, republish_count),
    };
    match insert_or_increment_terminal(pool, &input).await {
        Ok(row) => TerminalCaptureResult::Captured {
            quarantine_id: row.id,
        },
        Err(error) => TerminalCaptureResult::Failed {
            reason: format!("quarantine_capture_error: {error}"),
        },
    }
}

struct RepublishFailureContext<'a> {
    context: &'a DlqConsumerContext,
    retry_count: u32,
    failure_reason: &'a str,
}

fn capture_failure_reason(result: &TerminalCaptureResult) -> &str {
    match result {
        TerminalCaptureResult::Failed { reason } => reason.as_str(),
        TerminalCaptureResult::NotSelected => "quarantine_capture_not_selected",
        TerminalCaptureResult::Captured { .. } => "quarantine_capture_succeeded",
    }
}

async fn retain_delivery(
    channel: &Channel,
    delivery: &lapin::message::Delivery,
    dlq: &str,
    current_attempt: u32,
) -> Result<u32, String> {
    use lapin::options::BasicPublishOptions;
    use lapin::types::{AMQPValue, ShortString};

    let action = next_republish_failure_action(current_attempt);
    let attempt = match action {
        RepublishFailureAction::RetainAndRequeue { attempt }
        | RepublishFailureAction::Terminal { attempt } => attempt,
    };
    let mut headers = delivery.properties.headers().clone().unwrap_or_default();
    headers.insert(
        ShortString::from(HEADER_REPUBLISH_COUNT),
        AMQPValue::LongLongInt(i64::from(attempt)),
    );
    let confirm = channel
        .basic_publish(
            ShortString::from(EXCHANGE_DLX),
            ShortString::from(dlq),
            BasicPublishOptions::default(),
            &delivery.data,
            delivery.properties.clone().with_headers(headers),
        )
        .await
        .map_err(|error| format!("durable_dlq_retention_publish_error: {error}"))?;
    match confirm.await {
        Ok(Confirmation::Ack(_)) => Ok(attempt),
        Ok(Confirmation::Nack(_)) => Err("durable_dlq_retention_nack".to_owned()),
        Ok(Confirmation::NotRequested) => Err("durable_dlq_retention_not_confirmed".to_owned()),
        Err(error) => Err(format!("durable_dlq_retention_confirmation_error: {error}")),
    }
}

async fn settle_capture_failure(
    channel: &Channel,
    delivery: &lapin::message::Delivery,
    context: &DlqConsumerContext,
    current_attempt: u32,
    failure_reason: &str,
) -> Result<(), MqError> {
    match capture_failure_action(current_attempt) {
        TerminalCaptureAction::RetainAndRequeue { attempt } => {
            match retain_delivery(channel, delivery, &context.dlq, current_attempt).await {
                Ok(retained_attempt) => {
                    tracing::error!(
                        owner = context.owner,
                        queue = %context.dlq,
                        consumer_tag = %context.consumer_tag,
                        business_queue = %context.business_queue,
                        retry = retry_count_from_delivery(delivery),
                        republish_attempt = retained_attempt,
                        capture_failure = failure_reason,
                        durable_retention = true,
                        ack_reason = "confirmed_bounded_dlq_retention_after_capture_failure",
                        "terminal quarantine capture failed; retained bounded DLQ copy"
                    );
                    debug_assert_eq!(attempt, retained_attempt);
                    channel
                        .basic_ack(
                            delivery.delivery_tag,
                            lapin::options::BasicAckOptions::default(),
                        )
                        .await
                        .map_err(|error| MqError::Consume(error.to_string()))?;
                }
                Err(retention_error) => {
                    // No ACK/NACK is issued: the current delivery remains the
                    // only known copy. This avoids both data loss and an
                    // unbounded same-header requeue loop.
                    tracing::error!(
                        owner = context.owner,
                        queue = %context.dlq,
                        consumer_tag = %context.consumer_tag,
                        business_queue = %context.business_queue,
                        retry = retry_count_from_delivery(delivery),
                        republish_attempt = current_attempt,
                        capture_failure = failure_reason,
                        retention_error = %retention_error,
                        terminal = true,
                        durable_retention = false,
                        fail_closed = true,
                        "terminal quarantine and bounded DLQ retention both failed; preserving unacked delivery"
                    );
                }
            }
        }
        TerminalCaptureAction::PreserveUnacked => {
            tracing::error!(
                owner = context.owner,
                queue = %context.dlq,
                consumer_tag = %context.consumer_tag,
                business_queue = %context.business_queue,
                retry = retry_count_from_delivery(delivery),
                republish_attempt = current_attempt,
                capture_failure = failure_reason,
                terminal = true,
                durable_retention = false,
                fail_closed = true,
                "terminal quarantine capture failed at bounded DLQ limit; preserving unacked delivery"
            );
        }
        TerminalCaptureAction::AckAfterCapture | TerminalCaptureAction::AckWithoutCapture => {
            unreachable!("capture failure must select a retention or preserve action")
        }
    }
    Ok(())
}

async fn settle_terminal_capture(
    channel: &Channel,
    delivery: &lapin::message::Delivery,
    context: &DlqConsumerContext,
    capture: TerminalCaptureResult,
    current_attempt: u32,
) -> Result<(), MqError> {
    let capture_reason = capture_failure_reason(&capture);
    match terminal_capture_action(context, &capture, current_attempt) {
        TerminalCaptureAction::AckAfterCapture => {
            if let TerminalCaptureResult::Captured { quarantine_id } = capture {
                tracing::error!(
                    owner = context.owner,
                    queue = %context.dlq,
                    consumer_tag = %context.consumer_tag,
                    business_queue = %context.business_queue,
                    quarantine_id,
                    retry = retry_count_from_delivery(delivery),
                    republish_attempt = current_attempt,
                    terminal = true,
                    quarantine = true,
                    quarantine_status = %AuditQuarantineStatus::Quarantined.as_str(),
                    "DLQ terminal delivery durably quarantined"
                );
            }
            channel
                .basic_ack(
                    delivery.delivery_tag,
                    lapin::options::BasicAckOptions::default(),
                )
                .await
                .map_err(|error| MqError::Consume(error.to_string()))?;
        }
        TerminalCaptureAction::AckWithoutCapture => {
            channel
                .basic_ack(
                    delivery.delivery_tag,
                    lapin::options::BasicAckOptions::default(),
                )
                .await
                .map_err(|error| MqError::Consume(error.to_string()))?;
        }
        TerminalCaptureAction::RetainAndRequeue { .. } | TerminalCaptureAction::PreserveUnacked => {
            settle_capture_failure(channel, delivery, context, current_attempt, capture_reason)
                .await?;
        }
    }
    Ok(())
}

async fn handle_republish_failure(
    channel: &Channel,
    delivery: &lapin::message::Delivery,
    context: RepublishFailureContext<'_>,
) -> Result<(), MqError> {
    let RepublishFailureContext {
        context,
        retry_count,
        failure_reason,
    } = context;
    use lapin::options::{BasicAckOptions, BasicNackOptions};

    let current_attempt = dlq_republish_count(delivery);
    let action = next_republish_failure_action(current_attempt);
    let retained_attempt =
        match retain_delivery(channel, delivery, &context.dlq, current_attempt).await {
            Ok(attempt) => attempt,
            Err(retention_error) => {
                if quarantine_owner_queue(&context.business_queue) {
                    let capture = capture_terminal_delivery(
                        context,
                        delivery,
                        retry_count,
                        current_attempt,
                        &format!("durable_dlq_retention_failure:{retention_error}"),
                    )
                    .await;
                    return settle_terminal_capture(
                        channel,
                        delivery,
                        context,
                        capture,
                        current_attempt,
                    )
                    .await;
                }
                tracing::error!(
                    owner = context.owner,
                    queue = %context.dlq,
                    consumer_tag = %context.consumer_tag,
                    business_queue = %context.business_queue,
                    retry = retry_count,
                    republish_attempt = current_attempt,
                    failure_reason,
                    retention_error = %retention_error,
                    terminal = true,
                    quarantine = false,
                    structured_evidence = true,
                    "DLQ republish terminal block; durable retention was not confirmed"
                );
                channel
                    .basic_nack(
                        delivery.delivery_tag,
                        BasicNackOptions {
                            multiple: false,
                            requeue: false,
                        },
                    )
                    .await
                    .map_err(|error| MqError::Consume(error.to_string()))?;
                return Ok(());
            }
        };

    match action {
        RepublishFailureAction::RetainAndRequeue { attempt } => {
            tracing::error!(
                owner = context.owner,
                queue = %context.dlq,
                consumer_tag = %context.consumer_tag,
                business_queue = %context.business_queue,
                retry = retry_count,
                republish_attempt = attempt,
                failure_reason,
                terminal = false,
                durable_retention = true,
                ack_reason = "confirmed_durable_dlq_retention",
                "DLQ republish failed; bounded attempt retained in durable DLQ"
            );
            debug_assert_eq!(attempt, retained_attempt);
            channel
                .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                .await
                .map_err(|error| MqError::Consume(error.to_string()))?;
        }
        RepublishFailureAction::Terminal { attempt } => {
            let capture = capture_terminal_delivery(
                context,
                delivery,
                retry_count,
                attempt,
                "republish_attempt_budget_exhausted",
            )
            .await;
            if quarantine_owner_queue(&context.business_queue) {
                return settle_terminal_capture(channel, delivery, context, capture, attempt).await;
            }
            tracing::error!(
                owner = context.owner,
                queue = %context.dlq,
                consumer_tag = %context.consumer_tag,
                business_queue = %context.business_queue,
                retry = retry_count,
                republish_attempt = attempt,
                failure_reason,
                terminal = true,
                durable_retention = true,
                ack_reason = "confirmed_durable_dlq_retention",
                quarantine = false,
                "DLQ republish poison terminal retained in durable DLQ"
            );
            debug_assert_eq!(attempt, retained_attempt);
            channel
                .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                .await
                .map_err(|error| MqError::Consume(error.to_string()))?;
        }
    }
    Ok(())
}

async fn run_dlq_consumer(
    channel: Channel,
    mut consumer: lapin::Consumer,
    context: DlqConsumerContext,
) -> Result<(), MqError> {
    let DlqConsumerContext {
        owner,
        dlq,
        consumer_tag,
        business_queue,
        business_rk,
        business_exchange,
        quarantine_db,
        quarantine_enabled,
    } = context;
    use futures_util::StreamExt;
    use lapin::options::{BasicAckOptions, BasicNackOptions};
    use lapin::types::{AMQPValue, ShortString};

    while let Some(delivery) = consumer.next().await {
        let delivery = delivery.map_err(|error| MqError::Consume(error.to_string()))?;
        let retry_count = retry_count_from_delivery(&delivery);
        let message_id = delivery_message_id(&delivery);
        let republish_count = dlq_republish_count(&delivery);
        let context = DlqConsumerContext {
            owner,
            dlq: dlq.clone(),
            consumer_tag: consumer_tag.clone(),
            business_queue: business_queue.clone(),
            business_rk: business_rk.clone(),
            business_exchange: business_exchange.clone(),
            quarantine_db: quarantine_db.clone(),
            quarantine_enabled,
        };
        if republish_count >= MAX_REPUBLISH_ATTEMPTS {
            let capture = capture_terminal_delivery(
                &context,
                &delivery,
                retry_count,
                republish_count,
                "republish_attempt_budget_exhausted",
            )
            .await;
            if quarantine_owner_queue(&business_queue) {
                settle_terminal_capture(&channel, &delivery, &context, capture, republish_count)
                    .await?;
            } else {
                channel
                    .basic_nack(
                        delivery.delivery_tag,
                        BasicNackOptions {
                            multiple: false,
                            requeue: false,
                        },
                    )
                    .await
                    .map_err(|error| MqError::Consume(error.to_string()))?;
            }
            continue;
        }
        if retry_count >= crate::config::MAX_RETRY {
            let context = DlqConsumerContext {
                owner,
                dlq: dlq.clone(),
                consumer_tag: consumer_tag.clone(),
                business_queue: business_queue.clone(),
                business_rk: business_rk.clone(),
                business_exchange: business_exchange.clone(),
                quarantine_db: quarantine_db.clone(),
                quarantine_enabled,
            };
            let failure_reason = terminal_failure_reason(&delivery);
            let capture = capture_terminal_delivery(
                &context,
                &delivery,
                retry_count,
                republish_count,
                &failure_reason,
            )
            .await;
            if quarantine_owner_queue(&business_queue) {
                settle_terminal_capture(&channel, &delivery, &context, capture, republish_count)
                    .await?;
            } else {
                // Preserve the existing ordinary-queue terminal ACK semantics.
                tracing::error!(
                    owner,
                    queue = %dlq,
                    consumer_tag = %consumer_tag,
                    message_id = %message_id,
                    retry = retry_count,
                    failure_reason = %failure_reason,
                    message_bytes = delivery.data.len(),
                    terminal = true,
                    quarantine = false,
                    "DLQ terminal drop after max retries"
                );
                channel
                    .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                    .await
                    .map_err(|error| MqError::Consume(error.to_string()))?;
            }
            continue;
        }
        // 重投：携带递增 x-retry-count 头，经业务交换机回投业务队列。
        // 小延迟避免立即回队造成热循环（近似 DLX/TTL 重试节奏）。
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut headers = delivery.properties.headers().clone().unwrap_or_default();
        headers.insert(
            ShortString::from("x-retry-count"),
            AMQPValue::LongLongInt((retry_count + 1) as i64),
        );
        let properties = delivery.properties.clone().with_headers(headers);
        let published = channel
            .basic_publish(
                ShortString::from(business_exchange.as_str()),
                ShortString::from(business_rk.as_str()),
                lapin::options::BasicPublishOptions::default(),
                &delivery.data,
                properties,
            )
            .await;
        match published {
            Ok(confirm) => match confirm.await {
                Ok(Confirmation::Ack(_)) => {
                    tracing::warn!(
                        owner,
                        queue = %dlq,
                        consumer_tag = %consumer_tag,
                        business_queue = %business_queue,
                        message_id = %message_id,
                        retry = retry_count + 1,
                        failure_reason = "handler_or_malformed_delivery_retry",
                        terminal = false,
                        "DLQ re-driven message back to business queue"
                    );
                    channel
                        .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                        .await
                        .map_err(|error| MqError::Consume(error.to_string()))?;
                }
                Ok(Confirmation::Nack(_)) | Ok(Confirmation::NotRequested) => {
                    let context = DlqConsumerContext {
                        owner,
                        dlq: dlq.clone(),
                        consumer_tag: consumer_tag.clone(),
                        business_queue: business_queue.clone(),
                        business_rk: business_rk.clone(),
                        business_exchange: business_exchange.clone(),
                        quarantine_db: quarantine_db.clone(),
                        quarantine_enabled,
                    };
                    handle_republish_failure(
                        &channel,
                        &delivery,
                        RepublishFailureContext {
                            context: &context,
                            retry_count,
                            failure_reason: "republish_not_confirmed",
                        },
                    )
                    .await?;
                }
                Err(error) => {
                    tracing::error!(
                        owner,
                        queue = %dlq,
                        consumer_tag = %consumer_tag,
                        message_id = %message_id,
                        retry = retry_count,
                        failure_reason = "republish_confirmation_error",
                        error = %error,
                        "DLQ republish not confirmed"
                    );
                    let context = DlqConsumerContext {
                        owner,
                        dlq: dlq.clone(),
                        consumer_tag: consumer_tag.clone(),
                        business_queue: business_queue.clone(),
                        business_rk: business_rk.clone(),
                        business_exchange: business_exchange.clone(),
                        quarantine_db: quarantine_db.clone(),
                        quarantine_enabled,
                    };
                    handle_republish_failure(
                        &channel,
                        &delivery,
                        RepublishFailureContext {
                            context: &context,
                            retry_count,
                            failure_reason: "republish_confirmation_error",
                        },
                    )
                    .await?;
                }
            },
            Err(error) => {
                tracing::error!(
                    owner,
                    queue = %dlq,
                    consumer_tag = %consumer_tag,
                    message_id = %message_id,
                    retry = retry_count,
                    failure_reason = "republish_error",
                    error = %error,
                    "DLQ republish failed"
                );
                let context = DlqConsumerContext {
                    owner,
                    dlq: dlq.clone(),
                    consumer_tag: consumer_tag.clone(),
                    business_queue: business_queue.clone(),
                    business_rk: business_rk.clone(),
                    business_exchange: business_exchange.clone(),
                    quarantine_db: quarantine_db.clone(),
                    quarantine_enabled,
                };
                handle_republish_failure(
                    &channel,
                    &delivery,
                    RepublishFailureContext {
                        context: &context,
                        retry_count,
                        failure_reason: "republish_error",
                    },
                )
                .await?;
            }
        }
    }

    Err(MqError::Consume(format!(
        "DLQ consumer stream ended: owner={owner} queue={dlq} consumer_tag={consumer_tag}"
    )))
}

const IDENTITY_DLQ_QUEUES: &[&str] = &[QUEUE_LOGIN_EVENT, QUEUE_AUTH_SESSION_REVOCATION];

const TRUSTGRAPH_DLQ_QUEUES: &[&str] = &[QUEUE_AUDIT_LOG];

struct DlqOwnerMapping {
    queue_name: &'static str,
    owner: Option<DlqOwner>,
}

/// Complete static classification of all topology queues. `None` is an explicit
/// no-current-owner classification, not permission for either service to consume.
const DLQ_OWNER_MAP: &[DlqOwnerMapping] = &[
    DlqOwnerMapping {
        queue_name: QUEUE_AUDIT_LOG,
        owner: Some(DlqOwner::TrustGraph),
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_NOTIFICATION,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_LEARNING_PROGRESS,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: QUEUE_LOGIN_EVENT,
        owner: Some(DlqOwner::Identity),
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_SUBJECT_DELETE,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: QUEUE_AUTH_SESSION_REVOCATION,
        owner: Some(DlqOwner::Identity),
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_CHAT_MESSAGE,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_BUSINESS_CHAT,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_DELIVERY_ACK,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_READ_RECEIPT,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_QUESTION_COMMENT,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_QUESTION_SHARE,
        owner: None,
    },
];

fn dlq_consumer_tag(owner: DlqOwner, queue_name: &str) -> String {
    format!(
        "astral_dlq_{}_{}",
        owner.as_str(),
        queue_name.replace('.', "_")
    )
}

fn dlq_queue_defs_for_owner(owner: DlqOwner) -> Result<Vec<&'static QueueDef>, String> {
    validate_dlq_owner_mapping()?;
    let names = match owner {
        DlqOwner::Identity => IDENTITY_DLQ_QUEUES,
        DlqOwner::TrustGraph => TRUSTGRAPH_DLQ_QUEUES,
    };
    names
        .iter()
        .map(|name| {
            QUEUES
                .iter()
                .find(|def| def.name == *name)
                .ok_or_else(|| format!("owner={} references unknown queue={name}", owner.as_str()))
        })
        .collect()
}

fn validate_dlq_owner_mapping() -> Result<(), String> {
    let queue_names: HashSet<&str> = QUEUES.iter().map(|def| def.name).collect();
    if queue_names.len() != QUEUES.len() {
        return Err("topology contains duplicate queue names".into());
    }

    let mut mapped_names = HashSet::new();
    for mapping in DLQ_OWNER_MAP {
        if !queue_names.contains(mapping.queue_name) {
            return Err(format!(
                "mapping references unknown queue={}",
                mapping.queue_name
            ));
        }
        if !mapped_names.insert(mapping.queue_name) {
            return Err(format!(
                "queue mapped more than once: {}",
                mapping.queue_name
            ));
        }
    }
    if mapped_names.len() != QUEUES.len() {
        let omitted: Vec<_> = queue_names.difference(&mapped_names).copied().collect();
        return Err(format!("queue owner mapping omitted queues: {omitted:?}"));
    }

    validate_owner_queue_set(DlqOwner::Identity, IDENTITY_DLQ_QUEUES)?;
    validate_owner_queue_set(DlqOwner::TrustGraph, TRUSTGRAPH_DLQ_QUEUES)?;
    Ok(())
}

fn validate_owner_queue_set(owner: DlqOwner, names: &[&str]) -> Result<(), String> {
    let mut names_seen = HashSet::new();
    for name in names {
        if !names_seen.insert(*name) {
            return Err(format!(
                "owner={} queue listed more than once: {name}",
                owner.as_str()
            ));
        }
        let mapping = DLQ_OWNER_MAP
            .iter()
            .find(|mapping| mapping.queue_name == *name)
            .ok_or_else(|| format!("owner={} references unmapped queue={name}", owner.as_str()))?;
        if mapping.owner != Some(owner) {
            return Err(format!(
                "owner={} does not match queue={} mapping",
                owner.as_str(),
                name
            ));
        }
    }
    Ok(())
}

fn terminal_failure_reason(delivery: &lapin::message::Delivery) -> String {
    match validate_delivery_envelope(&delivery.data) {
        Ok(_) => "max_retries_exceeded".to_owned(),
        Err(reason) => reason,
    }
}

/// 启动 audit.log 消费者（仅 TrustGraph 消费）。
pub async fn start_audit_log_consumer(channel: &Channel) -> Result<(), MqError> {
    let audit_q = queue_name("audit.log");
    if audit_q.is_empty() {
        return Ok(());
    }
    let q = audit_q.to_string();
    let (ready_tx, ready_rx) = oneshot::channel();
    let owned_channel = channel.clone();
    tokio::spawn(async move {
        if let Err(error) = run_audit_log_batch_consumer(owned_channel, q, Some(ready_tx)).await {
            tracing::error!(queue = %audit_q, error = %error, "audit log consumer failed");
        }
    });
    ready_rx
        .await
        .map_err(|_| {
            MqError::Consume(format!(
                "audit log consumer startup task ended: queue={audit_q}"
            ))
        })?
        .map_err(|error| {
            MqError::Consume(format!(
                "audit log consumer registration failed: queue={audit_q}: {error}"
            ))
        })?;
    tracing::info!(queue = %audit_q, "AuditLogConsumer started (batched)");
    Ok(())
}

// ==================== AUDIT_LOG 消费者批量合并（性能优化卡点 3） ====================
//
// F3 压测：audit 消费者逐条持久化每条消息产生 3 次 DB 命令（mq_idempotent_log
// INSERT IGNORE + audit_log INSERT + mq_idempotent_log UPDATE），10 万 QPS 下
// 约占 DB 总容量 ~28%（不在请求延迟路径，但占吞吐）。批量合并将整批消息收敛
// 为**单事务 4 条批量 SQL**（幂等预检锁定读 + 幂等 claim 多行 + audit_log 多行
// + mark PROCESSED 多行），DB 命令数从 3×N 降为 4/批。
//
// 幂等与失败语义（与逐条路径一致，at-least-once 保持）：
// - Redis 租约 claim 层（`crate::consumer::claim_message`）逐条不变：
//   Completed → ack；InFlight → requeue（不消耗重试预算）；Claimed → 批量持久化
//   → complete → ack；
// - DB 幂等预检使用 `SELECT ... FOR UPDATE` 锁定既有行（与在途写者互斥）：行已
//   存在（已 PROCESSED 或崩溃残留 PROCESSING）等价于旧逐条语义的
//   `INSERT IGNORE` claim 失败 → 跳过 audit 行、仍 ack；
// - **批内任一 SQL 失败 → 整批回退逐条处理**（文档化选择）：单条毒消息不阻塞
//   整批；回退中仍失败的单条走 release 租约 + nack → DLX 预算重试；
// - ACK 前该消息的 durable 状态已随批事务落盘（durable proof 先于 ACK）。

/// 单批最大消息数。
const AUDIT_BATCH_MAX_MESSAGES: usize = 50;

/// 首条消息后继续凑批的窗口：低速率下最多增加 25ms 消费延迟（审计消费不在
/// 请求延迟路径）；高速率下 delivery 流已缓冲，窗口内即可凑满整批。
const AUDIT_BATCH_COLLECT_WINDOW: Duration = Duration::from_millis(25);

/// 已 claim 且待批量持久化的审计投递。
struct ClaimedAuditDelivery {
    delivery: Delivery,
    /// MQ 信封 messageId（Redis 租约键使用该 id）。
    message_id: String,
    /// Redis 处理租约 owner（complete/release 需要证明占有）。
    owner: String,
    payload: AuditLogPayload,
}

/// AUDIT_LOG 批量消费者主循环：凑批 → 逐条 decode/claim → 批量持久化 → 逐条确认。
async fn run_audit_log_batch_consumer(
    channel: Channel,
    audit_q: String,
    ready: Option<oneshot::Sender<Result<(), String>>>,
) -> Result<(), MqError> {
    let mut consumer = match channel
        .basic_qos(
            crate::consumer::DEFAULT_PREFETCH.max(AUDIT_BATCH_MAX_MESSAGES as u16),
            BasicQosOptions { global: false },
        )
        .await
        .map(|_| ())
    {
        Ok(()) => match channel
            .basic_consume(
                ShortString::from(audit_q.as_str()),
                ShortString::from(format!("consumer_{audit_q}")),
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
        {
            Ok(consumer) => consumer,
            Err(error) => {
                if let Some(ready) = ready {
                    let _ = ready.send(Err(error.to_string()));
                }
                return Err(error.into());
            }
        },
        Err(error) => {
            if let Some(ready) = ready {
                let _ = ready.send(Err(error.to_string()));
            }
            return Err(error.into());
        }
    };
    if let Some(ready) = ready {
        let _ = ready.send(Ok(()));
    }

    tracing::info!(queue = %audit_q, "batched consumer started");

    let message_type = message_type_for_queue(&audit_q);
    let mut batch: Vec<Delivery> = Vec::with_capacity(AUDIT_BATCH_MAX_MESSAGES);
    loop {
        batch.clear();
        // 首条阻塞等待：流错误向上返回、流关闭正常结束（与逐条消费者一致）。
        match consumer.next().await {
            Some(Ok(delivery)) => batch.push(delivery),
            Some(Err(error)) => return Err(MqError::Consume(error.to_string())),
            None => return Ok(()),
        }
        // 窗口内继续凑批（高速率下 stream 已缓冲，凑满即走）。
        let deadline = Instant::now() + AUDIT_BATCH_COLLECT_WINDOW;
        while batch.len() < AUDIT_BATCH_MAX_MESSAGES {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, consumer.next()).await {
                Err(_elapsed) => break,
                Ok(None) => break,
                Ok(Some(Err(error))) => return Err(MqError::Consume(error.to_string())),
                Ok(Some(Ok(delivery))) => batch.push(delivery),
            }
        }
        process_audit_delivery_batch(&channel, &audit_q, message_type, &mut batch).await?;
    }
}

/// 对一批投递执行逐条 decode/claim，然后批量持久化并逐条确认。
async fn process_audit_delivery_batch(
    channel: &Channel,
    audit_q: &str,
    message_type: &'static str,
    batch: &mut Vec<Delivery>,
) -> Result<(), MqError> {
    let mut claimed: Vec<ClaimedAuditDelivery> = Vec::new();
    for delivery in batch.drain(..) {
        let retry_count = retry_count_from_delivery(&delivery);
        // Parse before invoking Redis or business handlers（与逐条路径一致）。
        let msg = match decode_delivery::<AuditLogPayload>(&delivery.data, audit_q) {
            Ok(msg) => msg,
            Err(failure_reason) => {
                let message_id = delivery_message_id(&delivery);
                tracing::error!(
                    queue = %audit_q,
                    message_id = %message_id,
                    retry = retry_count,
                    failure_reason = %failure_reason,
                    "malformed delivery sent to DLX"
                );
                dead_letter_delivery(channel, &delivery).await?;
                continue;
            }
        };
        if retry_count >= MAX_RETRY {
            tracing::warn!(
                queue = %audit_q,
                message_id = %msg.message_id,
                retry = retry_count,
                failure_reason = "max_retries_exceeded",
                "max retries exceeded; delivery sent to DLX"
            );
            dead_letter_delivery(channel, &delivery).await?;
            continue;
        }
        match claim_message(&msg.message_id, message_type).await {
            Err(error) => {
                tracing::error!(
                    queue = %audit_q,
                    message_id = %msg.message_id,
                    error = %error,
                    "idempotency claim unavailable, retrying message"
                );
                nack_delivery(channel, &delivery).await?;
            }
            Ok(IdempotencyClaim::Completed) => {
                tracing::debug!(
                    queue = %audit_q,
                    message_id = %msg.message_id,
                    "message already completed, acking"
                );
                ack_delivery(channel, &delivery).await?;
            }
            Ok(IdempotencyClaim::InFlight) => {
                tracing::debug!(
                    queue = %audit_q,
                    message_id = %msg.message_id,
                    "message processing lease is active, requeueing without consuming retry budget"
                );
                requeue_delivery(channel, &delivery).await?;
            }
            Ok(IdempotencyClaim::Claimed(owner)) => {
                claimed.push(ClaimedAuditDelivery {
                    delivery,
                    message_id: msg.message_id.clone(),
                    owner,
                    payload: msg.payload,
                });
            }
        }
    }
    if claimed.is_empty() {
        return Ok(());
    }
    flush_claimed_audit_batch(channel, audit_q, message_type, claimed).await;
    Ok(())
}

/// 批量持久化成功 → 逐条 complete + ack；失败 → 逐条回退（见节文档）。
async fn flush_claimed_audit_batch(
    channel: &Channel,
    audit_q: &str,
    message_type: &'static str,
    claimed: Vec<ClaimedAuditDelivery>,
) {
    let Some(pool) = AUDIT_LOG_DB.get() else {
        // DB 未初始化：与逐条路径一致按失败处理 → 释放租约 + nack（DLX 重试）。
        for item in claimed {
            let error: Box<dyn std::error::Error + Send> = box_err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "audit log consumer DB not initialized",
            ));
            release_and_nack(channel, audit_q, message_type, item, error).await;
        }
        return;
    };
    let started = Instant::now();
    match persist_audit_record_batch(pool, &claimed).await {
        Ok(()) => {
            tracing::debug!(
                queue = %audit_q,
                count = claimed.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "audit batch persisted"
            );
            for item in claimed {
                // complete（Redis 幂等标记 '1'）→ ack；complete 失败与逐条路径
                // 一致：不 ack（redelivery 后由 DB 幂等 claim 去重兜底）。
                match complete_message(&item.message_id, message_type, &item.owner).await {
                    Ok(true) | Ok(false) | Err(_) => {
                        if let Err(error) = ack_delivery(channel, &item.delivery).await {
                            tracing::error!(
                                queue = %audit_q,
                                message_id = %item.message_id,
                                error = %error,
                                "audit batch ack failed"
                            );
                        }
                    }
                }
            }
        }
        Err(batch_error) => {
            // 整批失败 → 逐条回退（文档化选择）：单条毒消息不阻塞整批；仍失败
            // 的单条走 release + nack → DLX 预算重试（at-least-once 保持）。
            tracing::warn!(
                queue = %audit_q,
                count = claimed.len(),
                error = %batch_error,
                "audit batch persist failed; falling back to per-record persistence"
            );
            for item in claimed {
                match handle_audit_log(&item.message_id, &item.payload).await {
                    Ok(()) => {
                        match complete_message(&item.message_id, message_type, &item.owner).await {
                            Ok(true) | Ok(false) | Err(_) => {
                                if let Err(error) = ack_delivery(channel, &item.delivery).await {
                                    tracing::error!(
                                        queue = %audit_q,
                                        message_id = %item.message_id,
                                        error = %error,
                                        "audit fallback ack failed"
                                    );
                                }
                            }
                        }
                    }
                    Err(error) => {
                        release_and_nack(channel, audit_q, message_type, item, error).await;
                    }
                }
            }
        }
    }
}

/// 释放 Redis 处理租约并 nack（requeue=false → DLX），对齐逐条失败语义。
async fn release_and_nack(
    channel: &Channel,
    audit_q: &str,
    message_type: &'static str,
    item: ClaimedAuditDelivery,
    handler_error: Box<dyn std::error::Error + Send>,
) {
    tracing::warn!(
        queue = %audit_q,
        message_id = %item.message_id,
        error = %handler_error,
        "nacking for DLX retry"
    );
    if let Err(release_error) = release_message(&item.message_id, message_type, &item.owner).await {
        tracing::error!(
            queue = %audit_q,
            message_id = %item.message_id,
            error = %release_error,
            "failed to release message processing lease"
        );
    }
    if let Err(error) = nack_delivery(channel, &item.delivery).await {
        tracing::error!(
            queue = %audit_q,
            message_id = %item.message_id,
            error = %error,
            "audit batch nack failed"
        );
    }
}

/// 批量持久化：单事务 4 条批量 SQL。任何失败向上返回 → 整批回退逐条路径。
async fn persist_audit_record_batch(
    pool: &MySqlPool,
    claimed: &[ClaimedAuditDelivery],
) -> Result<(), Box<dyn std::error::Error + Send>> {
    if claimed.is_empty() {
        return Ok(());
    }
    // 批内同 message_id 去重：首条胜出（极端重复投递场景下避免重复 audit 行；
    // 未持久化的重复项由调用方按已完成消息确认，后续 redelivery 由 DB claim 去重）。
    let mut seen: HashSet<&str> = HashSet::with_capacity(claimed.len());
    let mut deduped: Vec<&ClaimedAuditDelivery> = Vec::with_capacity(claimed.len());
    for item in claimed {
        if seen.insert(item.message_id.as_str()) {
            deduped.push(item);
        }
    }
    let resolved_ids: Vec<String> = deduped
        .iter()
        .map(|item| resolve_audit_message_id(&item.message_id, &item.payload))
        .collect();
    let records: Vec<AuditRecord> = deduped
        .iter()
        .zip(&resolved_ids)
        .map(|(item, message_id)| audit_record_for_batch(message_id, &item.payload))
        .collect();

    let mut tx = pool.begin().await.map_err(box_err)?;
    // 1. 幂等预检（锁定读）：行已存在（已 PROCESSED 或崩溃残留 PROCESSING）
    //    等价于旧逐条语义的 INSERT IGNORE claim 失败 → 跳过 audit 行、仍 ack。
    //    FOR UPDATE 与在途写者互斥，锁定读看到的是提交后的最新版本。
    let select_sql = format!(
        "SELECT message_id FROM mq_idempotent_log WHERE message_type = ? AND message_id IN ({}) FOR UPDATE",
        sql_placeholders(records.len())
    );
    let mut select = sqlx::query_as::<_, (String,)>(&select_sql).bind(AUDIT_MESSAGE_TYPE);
    for record in &records {
        select = select.bind(record.message_id);
    }
    let existing: HashSet<String> = select
        .fetch_all(&mut *tx)
        .await
        .map_err(box_err)?
        .into_iter()
        .map(|(message_id,)| message_id)
        .collect();
    let fresh: Vec<&AuditRecord> = records
        .iter()
        .filter(|record| !existing.contains(record.message_id))
        .collect();
    if !fresh.is_empty() {
        // 2. 幂等 claim 多行（INSERT IGNORE 对齐逐条语义）。
        let claim_sql = format!(
            "INSERT IGNORE INTO mq_idempotent_log (message_type, message_id, status) VALUES {}",
            sql_repeated_values("(?, ?, 'PROCESSING')", fresh.len())
        );
        let mut claim = sqlx::query(&claim_sql);
        for record in &fresh {
            claim = claim.bind(AUDIT_MESSAGE_TYPE).bind(record.message_id);
        }
        claim.execute(&mut *tx).await.map_err(box_err)?;
        // 3. audit_log 多行。
        let audit_sql = format!(
            "INSERT INTO audit_log \
             (user_id, card_id, action, resource, decision, reason, event_type, source_ip, request_id, domain_id, tenant_id, detail) \
             VALUES {}",
            sql_repeated_values("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", fresh.len())
        );
        let mut insert = sqlx::query(&audit_sql);
        for record in &fresh {
            insert = insert
                .bind(record.user_id)
                .bind(record.card_id)
                .bind(record.action)
                .bind(record.resource)
                .bind(record.decision)
                .bind(record.reason)
                .bind(record.event_type)
                .bind(record.source_ip)
                .bind(record.request_id)
                .bind(record.domain_id)
                .bind(record.tenant_id)
                .bind(&record.detail);
        }
        insert.execute(&mut *tx).await.map_err(box_err)?;
        // 4. mark PROCESSED 多行。
        let mark_sql = format!(
            "UPDATE mq_idempotent_log SET status = 'PROCESSED' WHERE message_type = ? AND message_id IN ({})",
            sql_placeholders(fresh.len())
        );
        let mut mark = sqlx::query(&mark_sql).bind(AUDIT_MESSAGE_TYPE);
        for record in &fresh {
            mark = mark.bind(record.message_id);
        }
        mark.execute(&mut *tx).await.map_err(box_err)?;
    }
    tx.commit().await.map_err(box_err)?;
    Ok(())
}

/// 从信封 id + payload 解析最终幂等 id（与 `handle_audit_log` 同规则：信封 id
/// 缺失时回退 canonical legacy id）。
fn resolve_audit_message_id(envelope_message_id: &str, msg: &AuditLogPayload) -> String {
    if !envelope_message_id.is_empty() {
        return envelope_message_id.to_owned();
    }
    msg.message_id.clone().unwrap_or_else(|| {
        let fields = [
            (
                "userId",
                msg.user_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "null".to_owned()),
            ),
            (
                "cardId",
                msg.card_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "null".to_owned()),
            ),
            ("action", msg.action.clone()),
            ("resource", msg.resource.clone()),
            ("decision", msg.decision.clone()),
            ("eventType", msg.event_type.clone()),
            (
                "requestId",
                msg.request_id.clone().unwrap_or_else(|| "null".to_owned()),
            ),
        ];
        canonical_legacy_message_id("audit", &fields)
    })
}

/// audit_log detail 字段（与 `handle_audit_log` 同规则）。
fn audit_detail_for_message_id(message_id: &str) -> Option<String> {
    Some(if message_id.starts_with("legacy-audit-v1-") {
        format!("messageId={message_id};legacyMessageIdFallback=true")
    } else {
        format!("messageId={message_id}")
    })
}

/// audit_log detail 落库规则：producer 提供的非空白 detail 优先（例如
/// ORG_SCOPE ALLOW 的结构化 JSON provenance，不得被 messageId-only 文本覆盖）；
/// 未提供时回退既有 messageId 关联文本（含 legacy 回退标记）。message-id 关联
/// 本身始终由 `mq_idempotent_log (message_type, message_id)` 持久化，不依赖
/// detail 列，因此保留 producer detail 不损失幂等/关联语义。
fn audit_record_detail(payload_detail: Option<&str>, message_id: &str) -> Option<String> {
    match payload_detail {
        Some(detail) if !detail.trim().is_empty() => Some(detail.to_owned()),
        _ => audit_detail_for_message_id(message_id),
    }
}

/// 以最终幂等 id + payload 构造批量插入用的审计记录（借用入参，无克隆）。
fn audit_record_for_batch<'a>(
    message_id: &'a str,
    payload: &'a AuditLogPayload,
) -> AuditRecord<'a> {
    AuditRecord {
        message_type: AUDIT_MESSAGE_TYPE,
        message_id,
        user_id: payload.user_id.unwrap_or(0),
        card_id: payload.card_id,
        action: &payload.action,
        resource: &payload.resource,
        decision: &payload.decision,
        reason: &payload.reason,
        event_type: &payload.event_type,
        source_ip: &payload.source_ip,
        request_id: &payload.request_id,
        domain_id: payload.domain_id,
        tenant_id: payload.tenant_id,
        detail: audit_record_detail(payload.detail.as_deref(), message_id),
    }
}

/// 生成 n 个 `?` 的逗号连接（IN 列表占位）。
fn sql_placeholders(n: usize) -> String {
    vec!["?"; n].join(",")
}

/// 生成 n 份 values 模板的逗号连接（多行 VALUES 占位）。
fn sql_repeated_values(template: &str, n: usize) -> String {
    vec![template; n].join(",")
}

/// 逐条投递确认原语（与 `Consumer` 的 ack/nack/DLX 处置一致，供批量循环复用）。
async fn ack_delivery(channel: &Channel, delivery: &Delivery) -> Result<(), MqError> {
    channel
        .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
        .await?;
    Ok(())
}

async fn requeue_delivery(channel: &Channel, delivery: &Delivery) -> Result<(), MqError> {
    channel
        .basic_nack(
            delivery.delivery_tag,
            BasicNackOptions {
                multiple: false,
                requeue: true,
            },
        )
        .await?;
    Ok(())
}

async fn dead_letter_delivery(channel: &Channel, delivery: &Delivery) -> Result<(), MqError> {
    channel
        .basic_nack(
            delivery.delivery_tag,
            BasicNackOptions {
                multiple: false,
                requeue: false,
            },
        )
        .await?;
    Ok(())
}

async fn nack_delivery(channel: &Channel, delivery: &Delivery) -> Result<(), MqError> {
    dead_letter_delivery(channel, delivery).await
}

pub(crate) const AUDIT_MESSAGE_TYPE: &str = "AUDIT_LOG";
pub(crate) const LOGIN_EVENT_MESSAGE_TYPE: &str = "LOGIN_EVENT";

type AuditResult<T> = Result<T, Box<dyn std::error::Error + Send>>;

const AUDIT_IDEMPOTENCY_CLAIM_SQL: &str =
    "INSERT IGNORE INTO mq_idempotent_log (message_type, message_id, status) \
     VALUES (?, ?, 'PROCESSING')";
const AUDIT_LOG_INSERT_SQL: &str =
    "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, source_ip, request_id, domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
const AUDIT_IDEMPOTENCY_MARK_PROCESSED_SQL: &str =
    "UPDATE mq_idempotent_log SET status = 'PROCESSED' \
     WHERE message_type = ? AND message_id = ?";

struct AuditRecord<'a> {
    message_type: &'a str,
    message_id: &'a str,
    user_id: i64,
    card_id: Option<i64>,
    action: &'a str,
    resource: &'a str,
    decision: &'a str,
    reason: &'a Option<String>,
    event_type: &'a str,
    source_ip: &'a Option<String>,
    request_id: &'a Option<String>,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
    detail: Option<String>,
}

#[async_trait::async_trait]
trait AuditTransaction {
    async fn claim(&mut self, message_type: &str, message_id: &str) -> AuditResult<bool>;
    async fn insert(&mut self, record: &AuditRecord<'_>) -> AuditResult<()>;
    async fn mark_processed(&mut self, message_type: &str, message_id: &str) -> AuditResult<()>;
}

async fn persist_audit_record<T: AuditTransaction + ?Sized>(
    tx: &mut T,
    record: &AuditRecord<'_>,
) -> AuditResult<bool> {
    if !tx.claim(record.message_type, record.message_id).await? {
        return Ok(false);
    }
    tx.insert(record).await?;
    tx.mark_processed(record.message_type, record.message_id)
        .await?;
    Ok(true)
}

struct SqlxAuditTransaction<'a, 'tx> {
    tx: &'a mut sqlx::Transaction<'tx, sqlx::MySql>,
}

#[async_trait::async_trait]
impl AuditTransaction for SqlxAuditTransaction<'_, '_> {
    async fn claim(&mut self, message_type: &str, message_id: &str) -> AuditResult<bool> {
        let result = sqlx::query(AUDIT_IDEMPOTENCY_CLAIM_SQL)
            .bind(message_type)
            .bind(message_id)
            .execute(&mut **self.tx)
            .await
            .map_err(box_err)?;
        Ok(result.rows_affected() != 0)
    }

    async fn insert(&mut self, record: &AuditRecord<'_>) -> AuditResult<()> {
        sqlx::query(AUDIT_LOG_INSERT_SQL)
            .bind(record.user_id)
            .bind(record.card_id)
            .bind(record.action)
            .bind(record.resource)
            .bind(record.decision)
            .bind(record.reason)
            .bind(record.event_type)
            .bind(record.source_ip)
            .bind(record.request_id)
            .bind(record.domain_id)
            .bind(record.tenant_id)
            .bind(&record.detail)
            .execute(&mut **self.tx)
            .await
            .map_err(box_err)?;
        Ok(())
    }

    async fn mark_processed(&mut self, message_type: &str, message_id: &str) -> AuditResult<()> {
        sqlx::query(AUDIT_IDEMPOTENCY_MARK_PROCESSED_SQL)
            .bind(message_type)
            .bind(message_id)
            .execute(&mut **self.tx)
            .await
            .map_err(box_err)?;
        Ok(())
    }
}

async fn handle_audit_log(
    message_id: &str,
    msg: &AuditLogPayload,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let Some(pool) = AUDIT_LOG_DB.get() else {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "audit log consumer DB not initialized",
        )));
    };
    let message_id = resolve_audit_message_id(message_id, msg);
    let mut tx = pool.begin().await.map_err(box_err)?;
    let mut audit_tx = SqlxAuditTransaction { tx: &mut tx };
    persist_audit_record(
        &mut audit_tx,
        &AuditRecord {
            message_type: AUDIT_MESSAGE_TYPE,
            message_id: &message_id,
            user_id: msg.user_id.unwrap_or(0),
            card_id: msg.card_id,
            action: &msg.action,
            resource: &msg.resource,
            decision: &msg.decision,
            reason: &msg.reason,
            event_type: &msg.event_type,
            source_ip: &msg.source_ip,
            request_id: &msg.request_id,
            domain_id: msg.domain_id,
            tenant_id: msg.tenant_id,
            detail: audit_record_detail(msg.detail.as_deref(), &message_id),
        },
    )
    .await?;
    tx.commit().await.map_err(box_err)?;
    Ok(())
}

/// 启动 login.event 消费者（仅 Identity 消费，对齐 Java LoginEventConsumer 归属）。
///
/// 处理登录事件 → 写 audit_log（LOGIN_SUCCESS/LOGIN_FAILURE），失败返回 Err →
/// Consumer 框架 nack/DLX 重试（不吞失败）。调用方须先 `set_login_event_db`。
pub async fn start_login_event_consumer(channel: &Channel) -> Result<(), MqError> {
    let login_q = queue_name("login.event");
    if login_q.is_empty() {
        return Ok(());
    }
    let consumer = Consumer::new_with_message_id(
        channel.clone(),
        |message_id: &str, msg: &LoginEventPayload| {
            let msg = msg.clone();
            let message_id = message_id.to_owned();
            async move { handle_login_event(&message_id, &msg).await }
        },
        login_q,
    )
    .with_completion_policy(CompletionPolicy::DurableHandler);
    let q = login_q.to_string();
    let (ready_tx, ready_rx) = oneshot::channel();
    tokio::spawn(async move {
        if let Err(e) = consumer.start_with_readiness(Some(ready_tx)).await {
            tracing::error!(queue = %q, error = %e, "consumer failed");
        }
    });
    ready_rx
        .await
        .map_err(|_| {
            MqError::Consume(format!(
                "login event consumer startup task ended: queue={login_q}"
            ))
        })?
        .map_err(|error| {
            MqError::Consume(format!(
                "login event consumer registration failed: queue={login_q}: {error}"
            ))
        })?;
    tracing::info!(queue = %login_q, "LoginEventConsumer started");
    Ok(())
}

/// 登录事件入库（对齐 Java LoginEventConsumer → audit_log）。
async fn handle_login_event(
    message_id: &str,
    msg: &LoginEventPayload,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let Some(pool) = LOGIN_EVENT_DB.get() else {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "login event consumer DB not initialized",
        )));
    };
    let event_type = if msg.success {
        "LOGIN_SUCCESS"
    } else {
        "LOGIN_FAILURE"
    };
    let decision = if msg.success { "ALLOW" } else { "DENY" };
    let (message_id, legacy) = if message_id.is_empty() {
        let message_id = msg.message_id.clone().ok_or_else(|| {
            box_err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "login event messageId missing after envelope normalization",
            ))
        })?;
        (message_id, false)
    } else {
        (
            message_id.to_owned(),
            message_id.starts_with("legacy-login-v1-"),
        )
    };
    let mut tx = pool.begin().await.map_err(box_err)?;
    let mut audit_tx = SqlxAuditTransaction { tx: &mut tx };
    persist_audit_record(
        &mut audit_tx,
        &AuditRecord {
            message_type: LOGIN_EVENT_MESSAGE_TYPE,
            message_id: &message_id,
            user_id: msg.user_id,
            card_id: msg.card_id,
            action: "login",
            resource: "identity",
            decision,
            reason: &None,
            event_type,
            source_ip: &msg.ip_address,
            request_id: &None,
            domain_id: None,
            tenant_id: None,
            detail: Some(if legacy {
                format!("loginType={};legacyMessageIdFallback=true", msg.login_type)
            } else {
                format!("loginType={}", msg.login_type)
            }),
        },
    )
    .await?;
    tx.commit().await.map_err(box_err)?;
    tracing::debug!(
        user_id = msg.user_id,
        success = msg.success,
        "login event persisted"
    );
    Ok(())
}

/// 启动 auth.session.revocation 消费者（仅 Identity 消费，对齐 Java AuthSessionRevocationConsumer 归属）。
///
/// 调用方须先 `set_session_revocation_db`。
pub async fn start_auth_session_revocation_consumer(channel: &Channel) -> Result<(), MqError> {
    let revocation_q = queue_name("auth.session.revocation");
    if revocation_q.is_empty() {
        return Ok(());
    }
    let consumer = Consumer::new_with_message_id(
        channel.clone(),
        |message_id: &str, msg: &AuthSessionRevocationPayload| {
            let msg = msg.clone();
            let message_id = message_id.to_owned();
            async move { handle_auth_session_revocation(&message_id, &msg).await }
        },
        revocation_q,
    )
    .with_completion_policy(CompletionPolicy::DurableHandler);
    let q = revocation_q.to_string();
    let (ready_tx, ready_rx) = oneshot::channel();
    tokio::spawn(async move {
        if let Err(e) = consumer.start_with_readiness(Some(ready_tx)).await {
            tracing::error!(queue = %q, error = %e, "consumer failed");
        }
    });
    ready_rx
        .await
        .map_err(|_| {
            MqError::Consume(format!(
                "auth session revocation consumer startup task ended: queue={revocation_q}"
            ))
        })?
        .map_err(|error| {
            MqError::Consume(format!(
                "auth session revocation consumer registration failed: queue={revocation_q}: {error}"
            ))
        })?;
    tracing::info!(queue = %revocation_q, "AuthSessionRevocationConsumer started");
    Ok(())
}

/// 按名称查找队列（供各专属 starter 复用）
fn queue_name(suffix: &str) -> &'static str {
    QUEUES
        .iter()
        .find(|q| q.name.contains(suffix))
        .map(|q| q.name)
        .unwrap_or("")
}

// ===== AuthSessionRevocationConsumer（对齐 Java AuthSessionRevocationConsumer）=====

/// 处理 auth.session.revocation 命令：在同一 source 事务中保存 session/family/
/// JTI/outbox，提交后走 strict DB 撤销投影（Redis-free 权威路径），可选 Redis
/// compat 投影仅在运行时显式注入 manager 时调用。未安装 Redis 时 strict DB
/// 路径必须照常完成，命令不会因缺 Redis 而失败。
///
/// 对齐 Java `AuthDeviceSessionService.revokeAllForUser`：DB 撤销 + session outbox
/// +（可选）Redis projection delete。失败返回 Err → Consumer 框架 nack/DLX 重试（不吞失败）。
async fn handle_auth_session_revocation(
    envelope_message_id: &str,
    msg: &AuthSessionRevocationPayload,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let Some(pool) = SESSION_REVOCATION_DB.get() else {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "auth session revocation consumer DB not initialized",
        )));
    };
    // Redis is an optional compat projection, never a hard requirement: the
    // strict DB path below is the authority and must complete without it.
    #[cfg(feature = "redis-compat")]
    let redis_compat = SESSION_REVOCATION_REDIS.get().cloned();
    let operation_id = revocation_operation_id(envelope_message_id, msg)?;
    let reason = msg.reason.trim();
    if reason.is_empty() {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "auth session revocation reason is empty",
        )));
    }
    // Revocation source transaction hub writer fence: acquired before begin
    // (fail-closed and refuses to process when the fence is unavailable; no hub installed means
    // no-op), writer-active keeps the auxiliary read side fail-closed for the entire
    // transaction; pre-commit errors (known rollback) are released cleanly along with Drop.
    let source_guard = astral_db::memory_projection_hub::acquire_source_guard().map_err(box_err)?;
    let mut tx = pool.begin().await.map_err(box_err)?;
    // Typed SESSION_REVOKED shard envelopes appended inside this source
    // transaction. They are dispatched ONLY after a proven commit below; an
    // unknown/failed commit keeps zero dispatch and never replays source.
    let mut committed_shards: Vec<crate::envelope::MessageEnvelope> = Vec::new();

    // The outbox row is the idempotent boundary for the command. A retry after
    // the first commit reuses its immutable JTI snapshot instead of querying
    // the mutable ACTIVE index again.
    let existing: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT projection_key, payload_json FROM auth_session_outbox \
         WHERE operation_id = ? AND sequence_number = 1 FOR UPDATE",
    )
    .bind(&operation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(box_err)?;
    let expected_projection_key = format!("user:{}", msg.user_id);
    let (jti_keys, is_new_operation) = if let Some((projection_key, payload_json)) = existing {
        if projection_key != expected_projection_key {
            return Err(box_err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "auth session revocation operation id is bound to another user",
            )));
        }
        let payload = payload_json.ok_or_else(|| {
            box_err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "auth session revocation outbox payload is missing",
            ))
        })?;
        (revocation_jtis_from_payload(&payload, msg.user_id)?, false)
    } else {
        // Finite fact boundary: one operation's notification snapshot is
        // bounded. Beyond the capacity the command fails closed BEFORE any
        // source mutation (this transaction rolls back, so nothing can commit
        // without a fully representable, sharded notification intent). The
        // system does not promise an unbounded single-operation snapshot;
        // larger populations need upstream chunked operations.
        let snapshot: Vec<(String,)> = sqlx::query_as(
            "SELECT jti FROM auth_session_jti_index \
             WHERE user_id = ? AND status = 'ACTIVE' \
             ORDER BY jti LIMIT ? FOR UPDATE",
        )
        .bind(msg.user_id)
        .bind(i64::try_from(MAX_REVOCATION_SNAPSHOT_JTIS + 1).unwrap_or(i64::MAX))
        .fetch_all(&mut *tx)
        .await
        .map_err(box_err)?;
        if snapshot.len() > MAX_REVOCATION_SNAPSHOT_JTIS {
            return Err(box_err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "auth session revocation snapshot exceeds the bounded capacity \
                     {MAX_REVOCATION_SNAPSHOT_JTIS}; nothing was mutated and the \
                     command is not acknowledged"
                ),
            )));
        }
        (snapshot.into_iter().map(|(jti,)| jti).collect(), true)
    };

    if is_new_operation {
        // Keep session state, version and epoch in lockstep with the local
        // revoke path. The predicates make retries idempotent after commit.
        sqlx::query(
            "UPDATE auth_device_session SET status = 'REVOKED', session_state = 'REVOKED', \
             session_version = session_version + 1, session_epoch = session_epoch + 1, \
             revoked_at = UTC_TIMESTAMP(), revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
             WHERE user_id = ? AND status IN ('ACTIVE', 'PENDING') \
               AND session_state IN ('ACTIVE', 'PENDING')",
        )
        .bind(reason)
        .bind(msg.user_id)
        .execute(&mut *tx)
        .await
        .map_err(box_err)?;
        sqlx::query(
            "UPDATE auth_token_family SET status = 'REVOKED', revoked_at = UTC_TIMESTAMP(), \
             revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
             WHERE user_id = ? AND status = 'ACTIVE'",
        )
        .bind(reason)
        .bind(msg.user_id)
        .execute(&mut *tx)
        .await
        .map_err(box_err)?;
        sqlx::query(
            "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
             WHERE user_id = ? AND status = 'ACTIVE'",
        )
        .bind(msg.user_id)
        .execute(&mut *tx)
        .await
        .map_err(box_err)?;

        let payload = serde_json::json!({
            "v": 2,
            "reason": reason,
            "userId": msg.user_id,
            "jtis": jti_keys,
        })
        .to_string();
        sqlx::query(
            "INSERT INTO auth_session_outbox \
             (operation_id, session_id, event_type, sequence_number, projection_key, payload_json, status, created_at) \
             VALUES (?, NULL, 'REVOKE', 1, ?, ?, 'PENDING', NOW())",
        )
        .bind(&operation_id)
        .bind(&expected_projection_key)
        .bind(payload)
        .execute(&mut *tx)
        .await
        .map_err(box_err)?;

        // Typed invalidation durable intent: bounded stable shards derived
        // from the same in-transaction JTI snapshot, appended in THIS source
        // transaction (no MQ/network inside the boundary). Delivery is owned
        // by the post-commit direct dispatch below plus the relay/fanout
        // recovery leg; a retry of this command reuses the committed
        // operation snapshot and never re-appends (is_new_operation=false).
        committed_shards = crate::invalidation::append_session_revocation_shards_in_tx(
            &mut tx,
            msg.user_id,
            &jti_keys,
            &operation_id,
        )
        .await
        .map_err(box_err)?;
    }

    // Arm the cancellation fence: a task cancellation/connection drop within the COMMIT await window is witnessed by Drop
    // with atomic=true → sticky uncertain_source (unknown commit result, zero dispatch,
    // zero source replay, can only be cleared by independent durable reconciliation).
    if let Some(guard) = &source_guard {
        guard.mark_commit_started();
    }
    tx.commit().await.map_err(box_err)?;

    // Proven commit: first disarm and release the writer gate, then proceed with any
    // direct dispatch/projection—zero dispatch on unknown/failed commit, this point is only reachable
    // when the commit has been proven.
    if let Some(guard) = &source_guard {
        guard.mark_commit_proven();
    }
    drop(source_guard);

    // Proven commit: source mutations, auth_session_outbox and the sharded
    // typed invalidation rows are now durable together. The normal single-node
    // path delivers the committed SESSION_REVOKED envelopes directly on the
    // LocalBus (acceleration only — admission is not a durable proof); any
    // refusal is covered by the committed outbox rows for the recovery relay.
    // An unknown/failed commit never reaches this point: zero dispatch, no
    // source replay.
    deliver_committed_session_shards(&committed_shards).await;

    // Strict durable revocation projection (Redis-free authority): close each
    // JTI proof and mirror the revocation into the in-process acceleration
    // store. Errors escape so the command is retried, never acknowledged
    // half-applied. This runs before any optional compat surface.
    astral_db::apply_revocation_projection_mysql(pool, &jti_keys)
        .await
        .map_err(box_err)?;

    // Optional Redis compat projection: only invoked when the runtime
    // explicitly installed a compat manager. Its failure still fails the
    // command (nack + retry) — a deployment that declares the Redis
    // access-session contract must not acknowledge while its projections stay
    // live. Without the compat manager this block is skipped entirely.
    #[cfg(feature = "redis-compat")]
    if let Some(mut conn) = redis_compat {
        for jti in &jti_keys {
            conn.del::<_, ()>((format!("access:jti:{jti}"), format!("access:grant:{jti}")))
                .await
                .map_err(box_err)?;
            conn.set_ex::<_, _, ()>(
                format!("jwt:revoked:{jti}"),
                "1",
                SESSION_REVOCATION_MARKER_TTL_SECS_U64,
            )
            .await
            .map_err(box_err)?;
        }
    }

    // Redis projection and the in-process registry are now complete. Close the
    // durable outbox in the same operation identity so the caller can distinguish
    // business completion from LocalBus/Rabbit admission. A lost CAS is unknown;
    // do not acknowledge it as success until the status is reconciled.
    mark_revocation_outbox_processed(pool, &operation_id).await?;

    tracing::warn!(
        user_id = msg.user_id,
        operation_id = %operation_id,
        reason,
        "auth session revocation command processed"
    );
    Ok(())
}

/// Finite per-operation notification snapshot capacity (JTI entries).
///
/// Fact boundary, not an aspiration: one revocation operation captures at most
/// this many JTIs for its `auth_session_outbox` snapshot and its sharded typed
/// invalidation intent (at most `ceil(cap / 1024)` shards of <=1024 JTIs).
/// Exceeding it fails the command closed BEFORE any source mutation instead of
/// growing a single transaction without bound. 32768 entries map to at most 32
/// shard rows (~140KB payload each) — comfortably inside one short source
/// transaction and the MEDIUMTEXT outbox columns.
const MAX_REVOCATION_SNAPSHOT_JTIS: usize = 32_768;

/// Post-commit direct delivery of the committed typed SESSION_REVOKED shards.
///
/// Best-effort acceleration only — LocalBus admission is not a durable proof.
/// A missing bus, admission refusal, or queue overflow is logged and left to
/// the committed `al_message_outbox` rows, whose recovery relay owns durable
/// completion (per-scope FIFO, idempotent re-application). This function runs
/// strictly after `tx.commit()` returned Ok, so an unknown commit outcome can
/// never reach it: zero dispatch, no source replay.
async fn deliver_committed_session_shards(envelopes: &[crate::envelope::MessageEnvelope]) {
    if envelopes.is_empty() {
        return;
    }
    let Some(bus) = crate::local_bus::global_local_bus() else {
        tracing::warn!(
            count = envelopes.len(),
            "global local bus is not installed; committed session revocation shards rely on the recovery relay"
        );
        return;
    };
    let Some(pool) = SESSION_REVOCATION_DB.get() else {
        if let Some(hub) = astral_db::memory_projection_hub() {
            hub.mark_channel_suspect(
                "committed session invalidations lack the identity outbox dispatch pool",
            );
        }
        tracing::error!("identity session invalidation direct claim has no database pool");
        return;
    };
    for envelope in envelopes {
        match dispatch_committed_local_invalidation(pool.clone(), bus.clone(), envelope).await {
            Ok(LocalInvalidationDispatchOutcome::Completed)
            | Ok(LocalInvalidationDispatchOutcome::AlreadyProcessed) => {}
            Ok(LocalInvalidationDispatchOutcome::NotClaimed { status, reason }) => {
                tracing::warn!(
                    message_id = %envelope.message_id,
                    status = %status,
                    reason = %reason,
                    "session invalidation stays recovery-owned"
                );
            }
            Ok(LocalInvalidationDispatchOutcome::NotFound) => {
                if let Some(hub) = astral_db::memory_projection_hub() {
                    hub.mark_channel_suspect(
                        "committed session invalidation missing its exact outbox row",
                    );
                }
                tracing::error!(
                    message_id = %envelope.message_id,
                    "committed session invalidation has no exact outbox row"
                );
            }
            Err(error) => {
                tracing::warn!(
                    message_id = %envelope.message_id,
                    error = %error,
                    "session invalidation direct claim/dispatch/completion is unproven; durable recovery required"
                );
            }
        }
    }
}

const REVOCATION_OUTBOX_COMPLETE_SQL: &str =
    "UPDATE auth_session_outbox SET status = 'PROCESSED', \
    processed_at = UTC_TIMESTAMP(), processed_by = 'revocation-handler', \
    lease_owner = NULL, lease_expires_at = NULL, updated_at = UTC_TIMESTAMP() \
    WHERE operation_id = ? AND sequence_number = 1 AND status = 'PENDING'";

fn revocation_completion_is_proven(affected: u64, status: Option<&str>) -> bool {
    affected == 1 || (affected == 0 && status == Some("PROCESSED"))
}

async fn mark_revocation_outbox_processed(
    pool: &MySqlPool,
    operation_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let result = sqlx::query(REVOCATION_OUTBOX_COMPLETE_SQL)
        .bind(operation_id)
        .execute(pool)
        .await
        .map_err(box_err)?;
    if result.rows_affected() > 1 {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "auth session revocation outbox matched multiple rows",
        )));
    }
    if result.rows_affected() == 0 {
        let status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM auth_session_outbox \
             WHERE operation_id = ? AND sequence_number = 1",
        )
        .bind(operation_id)
        .fetch_optional(pool)
        .await
        .map_err(box_err)?;
        if !revocation_completion_is_proven(result.rows_affected(), status.as_deref()) {
            return Err(box_err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "auth session revocation outbox completion is unknown",
            )));
        }
    }
    Ok(())
}

fn revocation_operation_id(
    envelope_message_id: &str,
    msg: &AuthSessionRevocationPayload,
) -> Result<String, Box<dyn std::error::Error + Send>> {
    let candidate = msg
        .operation_id
        .as_deref()
        .or_else(|| (!envelope_message_id.trim().is_empty()).then_some(envelope_message_id))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            let seed = format!("{}\n{}\n{}", msg.user_id, msg.reason.trim(), msg.timestamp);
            format!(
                "legacy-revoke-{}",
                Uuid::new_v5(&Uuid::NAMESPACE_URL, seed.as_bytes())
            )
        });
    if candidate.len() > 64 || candidate.contains('\0') {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "auth session revocation operation id is invalid",
        )));
    }
    Ok(candidate)
}

fn revocation_jtis_from_payload(
    payload: &str,
    user_id: i64,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send>> {
    let value: Value = serde_json::from_str(payload).map_err(box_err)?;
    if value.get("v").and_then(Value::as_i64) != Some(2)
        || value.get("userId").and_then(Value::as_i64) != Some(user_id)
    {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "auth session revocation outbox payload is incompatible",
        )));
    }
    let Some(jtis) = value.get("jtis").and_then(Value::as_array) else {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "auth session revocation JTI snapshot is missing",
        )));
    };
    jtis.iter()
        .map(|jti| {
            jti.as_str()
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    box_err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "auth session revocation JTI snapshot is invalid",
                    ))
                })
        })
        .collect()
}

/// 将 sqlx/IO 错误装箱为 `Box<dyn std::error::Error + Send>`（Consumer handler 签名要求）
fn box_err(e: impl std::error::Error + Send + 'static) -> Box<dyn std::error::Error + Send> {
    Box::new(e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_bus::{LocalBusLimits, LocalOwner};

    // ===== recovery-only relay contracts =====

    fn evidence_event() -> crate::invalidation::InvalidationEvent {
        crate::invalidation::InvalidationEvent::EvidenceInvalidated(
            crate::invalidation::EvidenceInvalidated {
                tenant_id: 7,
                card_id: Some(42),
                aggregate_type: astral_types::PublishedEvidenceAggregate::UserCard,
                aggregate_id: 42,
                published_generation: 10,
                source_generation: 10,
                revoke_fence: 0,
            },
        )
    }

    /// A durable row whose payload bytes are the canonical committed envelope.
    fn relay_test_row(envelope: &crate::envelope::MessageEnvelope) -> astral_db::LocalMessageRow {
        astral_db::LocalMessageRow {
            message_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            message_type: envelope.message_type.clone(),
            queue_name: QUEUE_AUTHORIZATION_INVALIDATION.to_owned(),
            ordering_key: envelope.ordering_key.clone(),
            tenant_id: envelope.tenant_id,
            origin_region: envelope.origin_region.clone(),
            target_region: envelope.target_region.clone(),
            schema_version: envelope.schema_version,
            payload_json: envelope.envelope_json().unwrap(),
            headers_json: None,
            payload_sha256: envelope.payload_sha256.clone(),
            status: "PROCESSING".into(),
            attempts: 1,
            next_attempt_at: None,
            lease_owner: Some("relay-test:lease".into()),
            lease_expires_at: None,
            processed_at: None,
            last_error: None,
            created_at: time::PrimitiveDateTime::MIN,
            updated_at: time::PrimitiveDateTime::MIN,
        }
    }

    #[test]
    fn relay_binding_rejects_rows_outside_the_invalidation_domain() {
        // Domain separation: rows from any other queue never enter this state
        // machine, even when their bytes parse as a valid envelope.
        let envelope = evidence_event()
            .to_envelope("relay-domain-1", "relay-op", "local")
            .unwrap();
        let mut row = relay_test_row(&envelope);
        row.queue_name = QUEUE_AUDIT_LOG.to_owned();
        let error = bind_relay_envelope(&row).unwrap_err();
        assert!(
            error.contains("not the typed invalidation queue"),
            "{error}"
        );
    }

    #[test]
    fn relay_binding_rejects_unexpected_transport_headers() {
        let envelope = evidence_event()
            .to_envelope("relay-headers-1", "relay-op", "local")
            .unwrap();
        let mut row = relay_test_row(&envelope);
        row.headers_json = Some("{\"x-custom\":\"1\"}".into());
        let error = bind_relay_envelope(&row).unwrap_err();
        assert!(error.contains("unexpected transport headers"), "{error}");
    }

    #[test]
    fn relay_binding_rejects_every_metadata_divergence() {
        let envelope = evidence_event()
            .to_envelope("relay-meta-1", "relay-op", "local")
            .unwrap();
        let other_digest = crate::envelope::payload_digest(&serde_json::json!({"x": 1})).unwrap();

        let mut row = relay_test_row(&envelope);
        row.message_id = "other".into();
        assert!(bind_relay_envelope(&row)
            .unwrap_err()
            .contains("does not match durable row"));

        let mut row = relay_test_row(&envelope);
        row.operation_id = "other".into();
        assert!(bind_relay_envelope(&row)
            .unwrap_err()
            .contains("does not match durable row"));

        let mut row = relay_test_row(&envelope);
        row.message_type = "ELIGIBILITY_INVALIDATED".into();
        assert!(bind_relay_envelope(&row)
            .unwrap_err()
            .contains("does not match durable row"));

        let mut row = relay_test_row(&envelope);
        row.tenant_id = Some(8);
        assert!(bind_relay_envelope(&row)
            .unwrap_err()
            .contains("does not match durable row"));

        let mut row = relay_test_row(&envelope);
        row.origin_region = "city-b".into();
        assert!(bind_relay_envelope(&row)
            .unwrap_err()
            .contains("does not match durable row"));

        let mut row = relay_test_row(&envelope);
        row.target_region = Some("city-b".into());
        assert!(bind_relay_envelope(&row)
            .unwrap_err()
            .contains("does not match durable row"));

        let mut row = relay_test_row(&envelope);
        row.schema_version = 2;
        assert!(bind_relay_envelope(&row)
            .unwrap_err()
            .contains("does not match durable row"));

        let mut row = relay_test_row(&envelope);
        row.ordering_key = Some("authorization:eligibility/card/1".into());
        assert!(bind_relay_envelope(&row)
            .unwrap_err()
            .contains("does not match durable row"));

        let mut row = relay_test_row(&envelope);
        row.payload_sha256 = other_digest;
        assert!(bind_relay_envelope(&row)
            .unwrap_err()
            .contains("does not match durable row"));
    }

    #[test]
    fn relay_binding_rejects_non_canonical_committed_bytes() {
        let envelope = evidence_event()
            .to_envelope("relay-bytes-1", "relay-op", "local")
            .unwrap();
        let mut row = relay_test_row(&envelope);
        // Parses and validates fine, but is not the exact committed bytes.
        row.payload_json = serde_json::to_string_pretty(&envelope).unwrap();
        let error = bind_relay_envelope(&row).unwrap_err();
        assert!(
            error.contains("canonical committed envelope bytes"),
            "{error}"
        );
    }

    #[test]
    fn relay_binding_rejects_typed_payload_corruption() {
        let mut envelope = evidence_event()
            .to_envelope("relay-corrupt-1", "relay-op", "local")
            .unwrap();
        envelope.payload["unexpected"] = serde_json::json!(true);
        envelope.payload_sha256 = crate::envelope::payload_digest(&envelope.payload).unwrap();
        let mut row = relay_test_row(&envelope);
        row.payload_json = envelope.envelope_json().unwrap();
        row.payload_sha256 = envelope.payload_sha256.clone();
        let error = bind_relay_envelope(&row).unwrap_err();
        assert!(error.contains("unknown field"), "{error}");
    }

    #[test]
    fn relay_binding_rejects_unsupported_message_type() {
        let mut envelope = evidence_event()
            .to_envelope("relay-type-1", "relay-op", "local")
            .unwrap();
        envelope.message_type = "LOGIN_EVENT".into();
        let mut row = relay_test_row(&envelope);
        row.message_type = "LOGIN_EVENT".into();
        row.payload_json = envelope.envelope_json().unwrap();
        let error = bind_relay_envelope(&row).unwrap_err();
        assert!(
            error.contains("unsupported invalidation message type"),
            "{error}"
        );
    }

    #[test]
    fn relay_binding_accepts_the_exact_committed_envelope() {
        let envelope = evidence_event()
            .to_envelope("relay-ok-1", "relay-op-1", "local")
            .unwrap();
        let row = relay_test_row(&envelope);
        assert_eq!(bind_relay_envelope(&row).unwrap(), envelope);
    }

    #[test]
    fn bus_failures_classify_admission_refusal_separately_from_unknown() {
        for error in [
            LocalBusError::InvalidLimits,
            LocalBusError::InvalidOwner("q".into()),
            LocalBusError::InvalidRoute("q".into()),
            LocalBusError::NoOwner("q".into()),
            LocalBusError::Closed("q".into()),
            LocalBusError::Full("q".into()),
            LocalBusError::TooLarge {
                actual: 2,
                limit: 1,
            },
            LocalBusError::Duplicate("m".into()),
        ] {
            assert!(
                matches!(
                    classify_relay_bus_failure(error),
                    LocalInvalidationRelayOutcome::KnownFailure(_)
                ),
                "admission failure without a handler remains a bounded retry"
            );
        }
        assert!(matches!(
            classify_relay_bus_failure(LocalBusError::Handler(
                "handler failed after possible mutation".into()
            )),
            LocalInvalidationRelayOutcome::Unknown(_)
        ));
        assert!(matches!(
            classify_relay_bus_failure(LocalBusError::InvalidMessage(
                "typed contract refused".into()
            )),
            LocalInvalidationRelayOutcome::Malformed(_)
        ));
        assert!(matches!(
            classify_relay_bus_failure(LocalBusError::UnknownOutcome("m".into())),
            LocalInvalidationRelayOutcome::Unknown(_)
        ));
    }

    #[test]
    fn transition_contract_quarantines_malformed_immediately_and_unknown_always() {
        assert_eq!(
            local_invalidation_transition(
                0,
                LocalInvalidationRelayOutcome::Malformed("tampered".into())
            ),
            LocalInvalidationRowTransition::Quarantine("tampered".into())
        );
        assert_eq!(
            local_invalidation_transition(
                1,
                LocalInvalidationRelayOutcome::Unknown("deadline".into())
            ),
            LocalInvalidationRowTransition::MarkInDoubt("deadline".into())
        );
        assert_eq!(
            local_invalidation_transition(
                i32::MAX,
                LocalInvalidationRelayOutcome::Unknown("deadline".into())
            ),
            LocalInvalidationRowTransition::MarkInDoubt("deadline".into())
        );
        assert_eq!(
            local_invalidation_transition(1, LocalInvalidationRelayOutcome::Delivered),
            LocalInvalidationRowTransition::Complete
        );
    }

    #[test]
    fn transition_contract_bounds_known_failures_by_the_attempt_ceiling() {
        assert_eq!(
            local_invalidation_transition(
                1,
                LocalInvalidationRelayOutcome::KnownFailure("full".into())
            ),
            LocalInvalidationRowTransition::Retry("full".into())
        );
        assert!(matches!(
            local_invalidation_transition(
                LOCAL_MESSAGE_MAX_ATTEMPTS,
                LocalInvalidationRelayOutcome::KnownFailure("full".into())
            ),
            LocalInvalidationRowTransition::Quarantine(reason) if reason.contains("attempt ceiling")
        ));
    }

    #[test]
    fn relay_settings_enforce_low_frequency_and_lease_safe_deadlines() {
        LocalInvalidationRelaySettings::default()
            .validate()
            .expect("default settings are valid");

        let mut settings = LocalInvalidationRelaySettings {
            idle_poll_interval: Duration::from_secs(4),
            ..Default::default()
        };
        assert!(settings.validate().unwrap_err().contains("5-30s"));
        settings.idle_poll_interval = Duration::from_secs(31);
        assert!(settings.validate().unwrap_err().contains("5-30s"));

        let settings = LocalInvalidationRelaySettings {
            error_backoff: Duration::from_secs(2),
            ..Default::default()
        };
        assert!(settings.validate().unwrap_err().contains("5-30s"));

        let settings = LocalInvalidationRelaySettings {
            handler_deadline: Duration::from_secs(astral_db::LOCAL_MESSAGE_LEASE_SECONDS),
            ..Default::default()
        };
        assert!(settings
            .validate()
            .unwrap_err()
            .contains("must stay below the durable lease"));

        let settings = LocalInvalidationRelaySettings {
            handler_deadline: Duration::from_secs(25),
            db_call_deadline: Duration::from_secs(2),
            ..Default::default()
        };
        assert!(settings
            .validate()
            .unwrap_err()
            .contains("handler + settlement + IN_DOUBT budget"));

        assert!(local_invalidation_lease_budget_fits(
            Duration::from_secs(5),
            Duration::from_secs(3),
            Duration::from_secs(30),
        ));
        assert!(!local_invalidation_lease_budget_fits(
            Duration::from_secs(24),
            Duration::from_secs(2),
            Duration::from_secs(30),
        ));
        assert!(!local_invalidation_lease_budget_fits(
            Duration::from_secs(u64::MAX),
            Duration::from_secs(1),
            Duration::from_secs(30),
        ));

        let mut settings = LocalInvalidationRelaySettings {
            db_call_deadline: Duration::from_secs(4),
            ..Default::default()
        };
        assert!(settings
            .validate()
            .unwrap_err()
            .contains("db_call_deadline"));
        settings.db_call_deadline = Duration::ZERO;
        assert!(settings
            .validate()
            .unwrap_err()
            .contains("db_call_deadline"));

        let settings = LocalInvalidationRelaySettings {
            shutdown_join_deadline: Duration::ZERO,
            ..Default::default()
        };
        assert!(settings
            .validate()
            .unwrap_err()
            .contains("shutdown_join_deadline"));
    }

    #[tokio::test]
    async fn relay_delivery_classifies_handler_duplicate_and_unknown_outcomes() {
        let bus = LocalBus::new(LocalBusLimits::default()).unwrap();
        // LocalReceiver is not Clone, so the receiver stays in this test task
        // and each delivery is driven inline while the relay runs spawned.
        let mut receiver = bus
            .register(
                QUEUE_AUTHORIZATION_INVALIDATION,
                LocalOwner::AuthorizationInvalidation,
            )
            .unwrap();

        // Handler success -> Delivered.
        let envelope = evidence_event()
            .to_envelope("relay-bus-ok", "relay-bus-op-1", "local")
            .unwrap();
        let row = relay_test_row(&envelope);
        let relay_task = tokio::spawn({
            let bus = bus.clone();
            async move { relay_local_invalidation_row(&bus, &row, Duration::from_millis(500)).await }
        });
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "relay-bus-ok");
        delivery.complete(Ok(()));
        assert_eq!(relay_task.await.unwrap(), Ok(()));

        // In-flight duplicate on the direct leg -> KnownFailure (no side
        // effect here; a later recovery pass re-applies idempotently).
        let envelope = evidence_event()
            .to_envelope("relay-bus-dup", "relay-bus-op-2", "local")
            .unwrap();
        let row = relay_test_row(&envelope);
        bus.try_publish(
            QUEUE_AUTHORIZATION_INVALIDATION,
            crate::config::ROUTING_KEY_AUTHORIZATION_INVALIDATION,
            envelope,
        )
        .unwrap();
        let relay_task = tokio::spawn({
            let bus = bus.clone();
            async move { relay_local_invalidation_row(&bus, &row, Duration::from_millis(500)).await }
        });
        match relay_task.await.unwrap() {
            Err(LocalInvalidationRelayOutcome::KnownFailure(reason)) => {
                assert!(reason.contains("already in flight"), "{reason}");
            }
            other => panic!("expected duplicate-known failure, got {other:?}"),
        }
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "relay-bus-dup");
        delivery.complete(Ok(()));

        // Handler rejection can occur after an idempotent pending fence was
        // applied, so it is unknown and must be reconciled before any retry.
        let envelope = evidence_event()
            .to_envelope("relay-bus-err", "relay-bus-op-3", "local")
            .unwrap();
        let row = relay_test_row(&envelope);
        let relay_task = tokio::spawn({
            let bus = bus.clone();
            async move { relay_local_invalidation_row(&bus, &row, Duration::from_millis(500)).await }
        });
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "relay-bus-err");
        delivery.complete(Err("handler failed after possible local apply".into()));
        match relay_task.await.unwrap() {
            Err(LocalInvalidationRelayOutcome::Unknown(reason)) => {
                assert!(
                    reason.contains("handler failed after possible local apply"),
                    "{reason}"
                );
            }
            other => panic!("expected handler-unknown outcome, got {other:?}"),
        }

        // Disappearing consumer -> UnknownOutcome -> Unknown.
        let envelope = evidence_event()
            .to_envelope("relay-bus-unknown", "relay-bus-op-4", "local")
            .unwrap();
        let row = relay_test_row(&envelope);
        let relay_task = tokio::spawn({
            let bus = bus.clone();
            async move { relay_local_invalidation_row(&bus, &row, Duration::from_millis(200)).await }
        });
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "relay-bus-unknown");
        drop(delivery);
        match relay_task.await.unwrap() {
            Err(LocalInvalidationRelayOutcome::Unknown(_)) => {}
            other => panic!("expected unknown outcome, got {other:?}"),
        }
    }

    /// Drop of the parked task's probe future proves the handle aborted it.
    struct RelayAbortProbe {
        tx: Option<oneshot::Sender<&'static str>>,
    }

    impl Drop for RelayAbortProbe {
        fn drop(&mut self) {
            if let Some(tx) = self.tx.take() {
                let _ = tx.send("aborted");
            }
        }
    }

    #[tokio::test]
    async fn relay_handle_drop_aborts_the_parked_task() {
        let (probe_tx, probe_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _probe = RelayAbortProbe { tx: Some(probe_tx) };
            futures_util::future::pending::<()>().await;
        });
        let handle = LocalInvalidationRelayHandle::for_tests(join, Duration::from_secs(1));
        drop(handle);
        let outcome = timeout(Duration::from_secs(1), probe_rx)
            .await
            .expect("abort probe resolves within the timeout window");
        // Either the parked future was dropped mid-flight ("aborted") or the
        // task was cancelled before its first poll (the captured sender is
        // dropped without sending). Both outcomes prove Drop aborted the task;
        // with no abort this receive would hang into the timeout.
        assert!(matches!(outcome, Ok("aborted") | Err(_)));
    }

    #[tokio::test]
    async fn relay_handle_cancel_then_bounded_join_aborts_on_deadline() {
        let (probe_tx, probe_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _probe = RelayAbortProbe { tx: Some(probe_tx) };
            futures_util::future::pending::<()>().await;
        });
        let handle = LocalInvalidationRelayHandle::for_tests(join, Duration::from_millis(50));
        handle.cancel();
        let error = handle
            .join()
            .await
            .expect_err("parked task must hit the join deadline");
        assert!(error.contains("deadline"), "{error}");
        let outcome = probe_rx.await.expect("probe sender alive until abort");
        assert_eq!(outcome, "aborted");
    }

    #[tokio::test]
    async fn cancelling_local_relay_join_aborts_the_owned_task() {
        let (probe_tx, probe_rx) = oneshot::channel();
        let (started_tx, started_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            let _probe = RelayAbortProbe { tx: Some(probe_tx) };
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        let handle = LocalInvalidationRelayHandle::for_tests(join, Duration::from_secs(5));
        {
            let mut joining = std::pin::pin!(handle.join());
            assert!(timeout(Duration::from_millis(1), &mut joining)
                .await
                .is_err());
        }
        assert_eq!(
            timeout(Duration::from_secs(1), probe_rx)
                .await
                .unwrap()
                .unwrap(),
            "aborted"
        );
    }

    #[tokio::test]
    async fn relay_handle_joins_a_cooperative_exit() {
        let join = tokio::spawn(async {});
        let handle = LocalInvalidationRelayHandle::for_tests(join, Duration::from_secs(1));
        handle.join().await.expect("cooperative exit joins");
    }

    #[tokio::test]
    async fn relay_handle_join_error_returns_failure_and_drops_the_owned_task() {
        let join = tokio::spawn(async { panic!("injected relay panic") });
        let handle = LocalInvalidationRelayHandle::for_tests(join, Duration::from_secs(1));
        let error = handle
            .join()
            .await
            .expect_err("a panicked relay must never be reported as cooperative success");
        assert!(error.contains("ended abnormally"), "{error}");
    }

    #[test]
    fn relay_join_error_path_marks_unknown_outcome_suspect() {
        let source = include_str!("consumers.rs");
        let start = source
            .find("pub async fn join(self) -> Result<(), String>")
            .expect("owned relay join must exist");
        let end = source[start..]
            .find("#[cfg(test)]")
            .expect("test helper follows relay join");
        let body = &source[start..start + end];
        let error_branch = body
            .split("Ok(Err(join_error)) =>")
            .nth(1)
            .expect("JoinError branch must be handled explicitly");
        let error_branch = error_branch
            .split("Err(_elapsed) =>")
            .next()
            .expect("JoinError branch must end before timeout handling");
        assert!(error_branch.contains("guard.join.take()"));
        assert!(error_branch.contains("mark_relay_suspect("));
        assert!(error_branch.contains("outcome unknown"));
    }

    #[test]
    fn republish_failure_attempts_progress_to_explicit_terminal() {
        assert_eq!(
            next_republish_failure_action(0),
            RepublishFailureAction::RetainAndRequeue { attempt: 1 }
        );
        assert_eq!(
            next_republish_failure_action(1),
            RepublishFailureAction::RetainAndRequeue { attempt: 2 }
        );
        assert_eq!(
            next_republish_failure_action(2),
            RepublishFailureAction::Terminal { attempt: 3 }
        );
        assert_eq!(
            next_republish_failure_action(99),
            RepublishFailureAction::Terminal { attempt: 3 }
        );
    }

    fn test_context(queue: &str, enabled: bool) -> DlqConsumerContext {
        DlqConsumerContext {
            owner: "test",
            dlq: "astral.dlx.test".to_owned(),
            consumer_tag: "test-consumer".to_owned(),
            business_queue: queue.to_owned(),
            business_rk: "test.routing".to_owned(),
            business_exchange: "astral.direct".to_owned(),
            quarantine_db: None,
            quarantine_enabled: enabled,
        }
    }

    #[test]
    fn terminal_capture_selection_is_limited_to_enabled_owner_queues() {
        assert!(terminal_capture_selected(&test_context(
            QUEUE_AUDIT_LOG,
            true
        )));
        assert!(terminal_capture_selected(&test_context(
            QUEUE_LOGIN_EVENT,
            true
        )));
        assert!(!terminal_capture_selected(&test_context(
            QUEUE_AUDIT_LOG,
            false
        )));
        assert!(!terminal_capture_selected(&test_context(
            crate::config::QUEUE_SUBJECT_DELETE,
            true
        )));
    }

    #[test]
    fn terminal_capture_success_acks_only_after_capture() {
        let audit = test_context(QUEUE_AUDIT_LOG, true);
        let login = test_context(QUEUE_LOGIN_EVENT, true);
        let ordinary = test_context(crate::config::QUEUE_SUBJECT_DELETE, false);
        assert_eq!(
            terminal_capture_action(
                &audit,
                &TerminalCaptureResult::Captured { quarantine_id: 7 },
                0,
            ),
            TerminalCaptureAction::AckAfterCapture
        );
        assert_eq!(
            terminal_capture_action(
                &login,
                &TerminalCaptureResult::Failed {
                    reason: "db".to_owned(),
                },
                0,
            ),
            TerminalCaptureAction::RetainAndRequeue { attempt: 1 }
        );
        assert_eq!(
            terminal_capture_action(&ordinary, &TerminalCaptureResult::NotSelected, 0,),
            TerminalCaptureAction::AckWithoutCapture
        );
    }

    #[test]
    fn terminal_capture_failure_uses_bounded_action() {
        assert_eq!(
            capture_failure_action(0),
            TerminalCaptureAction::RetainAndRequeue { attempt: 1 }
        );
        assert_eq!(
            capture_failure_action(MAX_REPUBLISH_ATTEMPTS - 1),
            TerminalCaptureAction::RetainAndRequeue {
                attempt: MAX_REPUBLISH_ATTEMPTS
            }
        );
        assert_eq!(
            capture_failure_action(MAX_REPUBLISH_ATTEMPTS),
            TerminalCaptureAction::PreserveUnacked
        );
        assert_eq!(
            capture_failure_action(u32::MAX),
            TerminalCaptureAction::PreserveUnacked
        );
    }

    #[test]
    fn quarantine_failure_reason_keeps_republish_evidence() {
        assert_eq!(
            quarantine_failure_reason("max_retries_exceeded", 3),
            "max_retries_exceeded;dlq_republish_count=3"
        );
    }

    #[test]
    fn idempotency_namespaces_are_distinct_and_schema_key_is_composite() {
        assert_eq!(AUDIT_MESSAGE_TYPE, "AUDIT_LOG");
        assert_eq!(LOGIN_EVENT_MESSAGE_TYPE, "LOGIN_EVENT");
        assert_ne!(AUDIT_MESSAGE_TYPE, LOGIN_EVENT_MESSAGE_TYPE);
        let schema = include_str!("../../astral-db/migrations/20240630000001_baseline.sql");
        assert!(schema.contains("UNIQUE KEY uk_mq_msg (message_type, message_id)"));
    }

    #[test]
    fn inline_revocation_completion_never_steals_worker_owned_rows() {
        assert!(REVOCATION_OUTBOX_COMPLETE_SQL.contains("operation_id = ? AND sequence_number = 1"));
        assert!(REVOCATION_OUTBOX_COMPLETE_SQL.contains("AND status = 'PENDING'"));
        assert!(!REVOCATION_OUTBOX_COMPLETE_SQL.contains("PROCESSING"));
        assert!(revocation_completion_is_proven(1, None));
        assert!(revocation_completion_is_proven(0, Some("PROCESSED")));
        for status in [None, Some("PENDING"), Some("PROCESSING"), Some("FAILED")] {
            assert!(!revocation_completion_is_proven(0, status));
        }
        assert!(!revocation_completion_is_proven(2, Some("PROCESSED")));
    }

    #[test]
    fn revocation_completion_follows_source_commit_strict_db_then_optional_redis() {
        let source = include_str!("consumers.rs");
        let body = source
            .split("async fn handle_auth_session_revocation(")
            .nth(1)
            .unwrap()
            .split("const REVOCATION_OUTBOX_COMPLETE_SQL")
            .next()
            .unwrap();
        let commit = body.find("tx.commit()").unwrap();
        let strict_db = body.find("apply_revocation_projection_mysql(pool").unwrap();
        let redis = body.find("conn.set_ex").unwrap();
        let complete = body.find("mark_revocation_outbox_processed(pool").unwrap();
        // Source tx commit → strict DB projection → optional Redis compat →
        // outbox completion proof. The outbox stays the only completion proof.
        assert!(commit < strict_db && strict_db < redis && redis < complete);
        // Redis compat is optional: a missing projection manager must not fail
        // the handler, and the strict DB path must be unconditional.
        assert!(!body.contains("Redis projection manager not initialized"));
        assert!(body.contains("if let Some(mut conn) = redis_compat"));
        assert!(body.contains("astral_db::apply_revocation_projection_mysql(pool, &jti_keys)"));
    }

    #[test]
    fn typed_session_revocation_dispatch_fails_closed_without_acceleration_surface() {
        // Neither the revocation registry nor the projection store is installed
        // in this unit-test process; the typed dispatch must refuse (a registry
        // miss is never an implicit Allow). The guard keeps the test stable if
        // a future test process installs a surface.
        if astral_common::session_revocation_registry::global_session_revocation_registry()
            .is_some()
            || astral_common::session_projection_store::global_session_projection_store().is_some()
        {
            return;
        }
        let event = crate::invalidation::InvalidationEvent::SessionRevoked(
            crate::invalidation::SessionRevoked {
                user_id: 9,
                revoked_jtis: vec!["jti-1".into()],
            },
        );
        let error = dispatch_typed_invalidation(event, "event-1", "operation-1")
            .expect_err("missing acceleration surface must fail closed");
        assert!(error.contains("no session revocation acceleration surface"));
    }

    #[test]
    fn audit_consumer_sql_does_not_include_rust_escape_artifacts() {
        for query in [
            AUDIT_IDEMPOTENCY_CLAIM_SQL,
            AUDIT_LOG_INSERT_SQL,
            AUDIT_IDEMPOTENCY_MARK_PROCESSED_SQL,
        ] {
            assert!(
                !query.contains('\\'),
                "audit SQL contains a literal backslash: {query:?}"
            );
        }
    }

    #[test]
    fn batch_sql_fragments_are_placeholder_correct_and_escape_free() {
        assert_eq!(sql_placeholders(1), "?");
        assert_eq!(sql_placeholders(3), "?,?,?");
        assert_eq!(sql_repeated_values("(?, ?)", 2), "(?, ?),(?, ?)");
        let claim_values = sql_repeated_values("(?, ?, 'PROCESSING')", 2);
        let audit_values = sql_repeated_values("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 3);
        for fragment in [claim_values, audit_values, sql_placeholders(50)] {
            assert!(
                !fragment.contains('\\'),
                "batch SQL fragment contains a literal backslash: {fragment:?}"
            );
        }
    }

    fn sample_audit_payload() -> AuditLogPayload {
        AuditLogPayload {
            message_id: None,
            user_id: Some(7),
            card_id: Some(70),
            action: "read".into(),
            resource: "card".into(),
            decision: "ALLOW".into(),
            reason: Some("ok".into()),
            event_type: "PermissionCheck".into(),
            source_ip: Some("127.0.0.1".into()),
            request_id: Some("req-1".into()),
            domain_id: Some(2),
            tenant_id: Some(1),
            detail: None,
        }
    }

    #[test]
    fn audit_message_id_resolution_prefers_envelope_and_falls_back_to_legacy() {
        // 信封 id 存在 → 直接使用（Redis 租约与 DB 幂等键同源）。
        assert_eq!(
            resolve_audit_message_id("envelope-1", &sample_audit_payload()),
            "envelope-1"
        );
        // 信封 id 缺失且 payload 无 id → canonical legacy id（与逐条路径同规则）。
        let resolved = resolve_audit_message_id("", &sample_audit_payload());
        assert!(resolved.starts_with("legacy-audit-v1-"));
        // 相同 payload 的解析结果必须稳定（幂等键确定性）。
        assert_eq!(
            resolved,
            resolve_audit_message_id("", &sample_audit_payload())
        );
    }

    #[test]
    fn batch_audit_record_mapping_matches_per_record_path() {
        let payload = sample_audit_payload();
        let message_id = "envelope-9";
        let record = audit_record_for_batch(message_id, &payload);
        assert_eq!(record.message_type, AUDIT_MESSAGE_TYPE);
        assert_eq!(record.message_id, message_id);
        assert_eq!(record.user_id, 7);
        assert_eq!(record.card_id, Some(70));
        assert_eq!(record.action, "read");
        assert_eq!(record.resource, "card");
        assert_eq!(record.decision, "ALLOW");
        assert_eq!(record.reason, &Some("ok".into()));
        assert_eq!(record.event_type, "PermissionCheck");
        assert_eq!(record.source_ip, &Some("127.0.0.1".into()));
        assert_eq!(record.request_id, &Some("req-1".into()));
        assert_eq!(record.domain_id, Some(2));
        assert_eq!(record.tenant_id, Some(1));
        assert_eq!(record.detail.as_deref(), Some("messageId=envelope-9"));
        // legacy 前缀 id 携带回退标记（与逐条路径 detail 规则一致）。
        let legacy = audit_record_for_batch("legacy-audit-v1-abc", &payload);
        assert_eq!(
            legacy.detail.as_deref(),
            Some("messageId=legacy-audit-v1-abc;legacyMessageIdFallback=true")
        );
    }

    #[test]
    fn producer_supplied_detail_is_preserved_and_not_overwritten_by_message_id_text() {
        // producer 提供的结构化 detail（例如 ORG_SCOPE provenance JSON）必须
        // 原样落库，不得被 messageId-only 文本覆盖；幂等键仍走信封 message_id。
        let mut payload = sample_audit_payload();
        payload.detail = Some("{\"schema\":\"audit-detail-org-v1\",\"path\":\"/stats\"}".into());
        let record = audit_record_for_batch("envelope-10", &payload);
        assert_eq!(
            record.detail.as_deref(),
            Some("{\"schema\":\"audit-detail-org-v1\",\"path\":\"/stats\"}")
        );
        // 逐条回退路径同规则。
        assert_eq!(
            audit_record_detail(payload.detail.as_deref(), "legacy-audit-v1-abc").as_deref(),
            Some("{\"schema\":\"audit-detail-org-v1\",\"path\":\"/stats\"}")
        );
    }

    #[test]
    fn blank_or_missing_detail_falls_back_to_message_id_correlation_text() {
        // 旧消息（detail 缺失）与空白 detail 都回退 messageId 关联文本。
        let payload = sample_audit_payload();
        assert_eq!(
            audit_record_detail(payload.detail.as_deref(), "envelope-11").as_deref(),
            Some("messageId=envelope-11")
        );
        let mut blank = sample_audit_payload();
        blank.detail = Some("   ".into());
        assert_eq!(
            audit_record_detail(blank.detail.as_deref(), "envelope-12").as_deref(),
            Some("messageId=envelope-12")
        );
        assert_eq!(
            audit_record_detail(blank.detail.as_deref(), "legacy-audit-v1-abc").as_deref(),
            Some("messageId=legacy-audit-v1-abc;legacyMessageIdFallback=true")
        );
    }

    #[test]
    fn dlq_owner_mapping_is_complete_and_disjoint() {
        validate_dlq_owner_mapping().expect("static DLQ owner mapping must be valid");
        let identity: HashSet<_> = IDENTITY_DLQ_QUEUES.iter().copied().collect();
        let trustgraph: HashSet<_> = TRUSTGRAPH_DLQ_QUEUES.iter().copied().collect();
        assert!(identity.is_disjoint(&trustgraph));
        assert_eq!(identity.len(), IDENTITY_DLQ_QUEUES.len());
        assert_eq!(trustgraph.len(), TRUSTGRAPH_DLQ_QUEUES.len());
    }

    #[test]
    fn dlq_owner_sets_are_exact() {
        assert_eq!(
            IDENTITY_DLQ_QUEUES,
            &[QUEUE_LOGIN_EVENT, QUEUE_AUTH_SESSION_REVOCATION]
        );
        assert_eq!(TRUSTGRAPH_DLQ_QUEUES, &[QUEUE_AUDIT_LOG]);
        assert!(!IDENTITY_DLQ_QUEUES.contains(&crate::config::QUEUE_CHAT_MESSAGE));
        assert!(!TRUSTGRAPH_DLQ_QUEUES.contains(&crate::config::QUEUE_LEARNING_PROGRESS));
    }

    #[test]
    fn dlq_consumer_tags_are_owner_and_queue_specific() {
        assert_eq!(
            dlq_consumer_tag(DlqOwner::Identity, QUEUE_LOGIN_EVENT),
            "astral_dlq_identity_astral_login_event"
        );
        assert_ne!(
            dlq_consumer_tag(DlqOwner::Identity, QUEUE_LOGIN_EVENT),
            dlq_consumer_tag(DlqOwner::TrustGraph, QUEUE_LOGIN_EVENT)
        );
    }

    #[test]
    fn auth_session_revocation_queue_contract() {
        // 队列/路由键与 Java AuthSessionRevocationCommandService 一致
        assert_eq!(
            crate::config::QUEUE_AUTH_SESSION_REVOCATION,
            "astral.auth.session.revocation"
        );
        assert_eq!(
            crate::config::QUEUES
                .iter()
                .find(|q| q.name == crate::config::QUEUE_AUTH_SESSION_REVOCATION)
                .map(|q| q.routing_key),
            Some("auth.session.revocation")
        );
    }

    /// 【撤销事务 source writer 栅栏】栅栏在事务 begin 之前取得；COMMIT await
    /// 前武装取消栅栏；commit 证明成功后先 proven 释放栅栏，再进行任何直投/
    /// 投影——unknown/取消路径以已武装 Drop 保持 sticky uncertain（零投递）。
    #[test]
    fn revocation_tx_guard_is_acquired_before_begin_and_released_before_dispatch() {
        let source = include_str!("consumers.rs");
        let handler = source
            .split("async fn handle_auth_session_revocation(")
            .nth(1)
            .expect("revocation handler must remain")
            .split("const MAX_REVOCATION_SNAPSHOT_JTIS: usize")
            .next()
            .expect("handler body must stay bounded");

        let guard = handler
            .find("memory_projection_hub::acquire_source_guard()")
            .expect("the revocation tx must acquire the hub source writer guard");
        let begin = handler
            .find("pool.begin()")
            .expect("the revocation tx must open with pool.begin()");
        let arm = handler
            .find("guard.mark_commit_started()")
            .expect("the commit await must be armed");
        let commit = handler
            .find("tx.commit()")
            .expect("the source tx must commit");
        let proven = handler
            .find("guard.mark_commit_proven()")
            .expect("a proven commit must disarm the fence");
        let drop = handler
            .find("drop(source_guard);")
            .expect("the writer gate must be released explicitly");
        let dispatch = handler
            .find("deliver_committed_session_shards(&committed_shards).await;")
            .expect("post-commit direct dispatch must remain");

        assert!(
            guard < begin,
            "the hub source writer guard must be acquired before the transaction opens"
        );
        assert!(
            arm < commit,
            "the cancellation fence must arm before awaiting COMMIT"
        );
        assert!(
            proven < drop && drop < dispatch,
            "the gate is released (proven, then dropped) strictly before any dispatch"
        );
    }

    /// 【分片 durable intent 结构锁定】撤销 handler 的 source 事务只允许
    /// durable source/outbox 写入（含同事务追加的 typed SESSION_REVOKED 分片
    /// intent，事务内零 MQ/网络）；typed 直投只允许出现在 commit 证明成功
    /// 之后；快照读取必须有有限容量边界；重试路径（is_new_operation=false）
    /// 不得重复追加。
    #[test]
    fn session_revocation_shard_intent_is_in_tx_and_direct_delivery_only_after_commit() {
        let source = include_str!("consumers.rs");
        let handler_start = source
            .find("async fn handle_auth_session_revocation(")
            .expect("revocation handler must remain");
        let helper_start = source
            .find("const MAX_REVOCATION_SNAPSHOT_JTIS: usize")
            .expect("snapshot capacity constant must remain");
        let handler = &source[handler_start..helper_start];

        let snapshot_read = handler
            .find("ORDER BY jti LIMIT ? FOR UPDATE")
            .expect("bounded snapshot read must remain");
        let snapshot_over = handler
            .find("snapshot.len() > MAX_REVOCATION_SNAPSHOT_JTIS")
            .expect("over-capacity must fail closed before any mutation");
        let append = handler
            .find("append_session_revocation_shards_in_tx(")
            .expect("same-transaction typed shard append must remain");
        let commit = handler
            .find("tx.commit().await.map_err(box_err)?;")
            .expect("commit proof must remain");
        let dispatch = handler
            .find("deliver_committed_session_shards(&committed_shards).await;")
            .expect("post-commit direct dispatch must remain");

        assert!(
            snapshot_read < snapshot_over,
            "the capacity check must guard the bounded snapshot read"
        );
        assert!(
            snapshot_over < append,
            "over-capacity fails closed before the shard append"
        );
        assert!(
            append < commit,
            "typed shard intent is appended inside the source transaction, before commit"
        );
        assert!(
            commit < dispatch,
            "direct delivery happens strictly after a proven commit"
        );

        // The retry path must not re-append: the only append call site sits
        // after the is_new_operation outbox insert inside the same branch.
        let is_new_operation_block = handler
            .find("if is_new_operation {")
            .expect("is_new_operation branch must remain");
        assert!(
            is_new_operation_block < append,
            "shard append only happens for a fresh operation, never on replay"
        );

        // The dispatcher refuses to act without envelopes and never fails the
        // command on refusal; keep it admission-only by contract.
        let dispatcher = source
            .find("async fn deliver_committed_session_shards(")
            .expect("post-commit dispatcher must remain");
        assert!(
            dispatcher > helper_start,
            "dispatcher stays a separate post-commit helper, not an in-transaction step"
        );
    }

    /// 【有限事实边界】单 operation 通知快照容量必须有限且换算成分片数后
    /// 仍落在短事务/单行 payload 的舒适区间内。
    #[test]
    fn revocation_snapshot_capacity_is_finite_and_shard_friendly() {
        assert_eq!(MAX_REVOCATION_SNAPSHOT_JTIS, 32_768);
        assert_eq!(
            MAX_REVOCATION_SNAPSHOT_JTIS.div_ceil(crate::invalidation::MAX_REVOKED_JTIS),
            32
        );
        assert!(MAX_REVOCATION_SNAPSHOT_JTIS.is_multiple_of(crate::invalidation::MAX_REVOKED_JTIS));
    }
}
