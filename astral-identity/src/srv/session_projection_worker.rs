//! Distributed auth-session projection recovery worker.
//!
//! Every Identity replica runs the same loop. MySQL lease ownership is the
//! only coordinator and the durable `auth_session_jti_index` close is the
//! authoritative fact; Redis operations (only present when the explicit
//! compat adapter is enabled) are idempotent and never reopen durable
//! sessions. In the default Redis-free path the loop only reconciles the
//! in-process accelerator surfaces (mirror / revocation registry) for rows
//! left behind by a crash, then closes the outbox.
//!
//! 【单机降级：纯恢复角色】热路径已由组合进程内的 LocalBus 撤销 handler
//! 承担（同一请求内完成 durable 撤销 + 投影清理 + 进程内登记），本循环只
//! 收口"handler 中途失败/进程崩溃"遗留的 outbox 行，不再参与任何主处理
//! 路径；轮询周期相应放宽以消除空闲 DB 轮询开销。

use std::time::Duration;

#[cfg(feature = "redis-compat")]
use redis::aio::ConnectionManager;
#[cfg(feature = "redis-compat")]
use redis::AsyncCommands;
use serde_json::Value;
use sqlx::MySqlPool;
use time::PrimitiveDateTime;
use uuid::Uuid;

use astral_types::AstralError;

/// compat adapter 句柄（所有权形态，供 spawn 装配传入）：仅 redis-compat
/// feature 编译时为 `Option<ConnectionManager>`；feature-off 构建为
/// `Option<()>` 空标记——API 形状零 redis 类型（redis 编译层退役接缝）。
#[cfg(feature = "redis-compat")]
type CompatRedis = Option<ConnectionManager>;
#[cfg(not(feature = "redis-compat"))]
type CompatRedis = Option<()>;

/// compat adapter 借用形态（process/apply 链传参用），语义同 [`CompatRedis`]。
#[cfg(feature = "redis-compat")]
type CompatRedisRef<'a> = Option<&'a ConnectionManager>;
#[cfg(not(feature = "redis-compat"))]
type CompatRedisRef<'a> = Option<&'a ()>;

const LEASE_SECONDS: i64 = 30;
/// 恢复兜底轮询周期（毫秒）：纯恢复角色（见模块文档），主路径是进程内
/// LocalBus 撤销 handler 的同步完成；放宽周期只影响崩溃遗留行的收口延迟，
/// 不影响任何正确性（outbox 幂等 + 撤销完成证明以 durable 状态为准）。
const POLL_MILLIS: u64 = 5000;
const MAX_BACKOFF_SECONDS: i64 = 300;

#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
struct OutboxRow {
    outbox_id: i64,
    operation_id: String,
    event_type: String,
    projection_key: String,
    payload_json: Option<String>,
    created_at: PrimitiveDateTime,
    attempts: i32,
}

/// Redis-free 默认装配入口（无 compat adapter 的构建/部署使用）：行为等价于
/// `spawn(pool, None)`，但 API 形状不引用 compat 类型（redis 编译层退役）。
pub fn spawn_without_redis(pool: MySqlPool) {
    spawn_inner(pool, None);
}

/// compat legacy 装配入口（`redis` 为 `Some` 时追加历史 Redis 投影，
/// default-off）。仅 redis-compat feature 编译；feature-off 构建使用
/// [`spawn_without_redis`]（BREAKING 收敛点，登记于架构文档）。
#[cfg(feature = "redis-compat")]
pub fn spawn(pool: MySqlPool, redis: CompatRedis) {
    spawn_inner(pool, redis);
}

fn spawn_inner(pool: MySqlPool, redis: CompatRedis) {
    let worker_id = format!("identity-{}", Uuid::new_v4());
    // Legacy detached entry: exactly the historical behavior (fire-and-forget).
    // The keep-alive stop sender is moved into the task so the stop channel
    // never closes and the loop runs until process exit, as before. Death
    // observability and bounded shutdown live on the owned flavor
    // ([`spawn_without_redis_owned`] / [`spawn_owned`]).
    let (keep_alive_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _keep_alive = keep_alive_tx;
        run_recovery_loop(pool, redis, worker_id, stop_rx).await;
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Owned handle (worker-supervision-20261002): RAII + death observability
// ─────────────────────────────────────────────────────────────────────────────

/// Owns the required recovery loop and reports its terminal outcome.
/// Cooperative shutdown is bounded; Drop or deadline aborts both tasks and
/// leaves any unproved durable settlement unknown. Legacy detached entries
/// retain their compatibility behavior.
#[must_use]
pub struct SessionProjectionWorkerHandle {
    stop: tokio::sync::watch::Sender<bool>,
    join: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    death: tokio::sync::watch::Receiver<Option<String>>,
    join_deadline: Duration,
}

impl SessionProjectionWorkerHandle {
    /// Terminal-outcome signal: `Some(reason)` once the supervised loop
    /// reached a terminal state (cooperative stop, unexpected exit, or panic).
    /// Never reset to `None`.
    pub fn death_signal(&self) -> tokio::sync::watch::Receiver<Option<String>> {
        self.death.clone()
    }

    /// Cooperative stop then bounded join of the supervisor. `Ok` is returned
    /// ONLY on a proven cooperative stop; panics, abnormal exits and deadline
    /// aborts report a stable terminal reason (timeout/unknown) instead.
    pub async fn shutdown_join(self) -> Result<(), String> {
        let this = self;
        let _ = this.stop.send(true);
        // Keep ownership if the shutdown future itself is cancelled.
        let mut join =
            AbortOnDropJoin {
                join: this.join.lock().unwrap().take().ok_or_else(|| {
                    "session projection worker join handle already taken".to_owned()
                })?,
            };
        match tokio::time::timeout(this.join_deadline, &mut join.join).await {
            Ok(Ok(())) => {
                let reason = this.death.borrow().clone();
                match reason {
                    Some(text) if text.contains("stopped cooperatively") => Ok(()),
                    other => Err(format!(
                        "session projection recovery worker did not prove a cooperative stop: \
                         {other:?}"
                    )),
                }
            }
            Ok(Err(join_error)) => Err(format!(
                "session projection worker supervisor join failed: {join_error}"
            )),
            Err(_) => {
                // Deadline: abort the supervisor (its inner-ownership guard
                // aborts the recovery loop) and reap before reporting unknown.
                join.join.abort();
                let _ = tokio::time::timeout(Duration::from_secs(1), &mut join.join).await;
                Err(format!(
                    "session projection worker did not stop within {:?}; supervisor and \
                     recovery loop aborted; final outcome unknown",
                    this.join_deadline
                ))
            }
        }
    }
}

impl Drop for SessionProjectionWorkerHandle {
    fn drop(&mut self) {
        // Cooperative stop signal first, then abort the supervisor task; the
        // supervisor's inner-ownership guard aborts the recovery loop, so no
        // Drop path can leave the required loop detached.
        let _ = self.stop.send(true);
        if let Some(join) = self.join.lock().unwrap().take() {
            join.abort();
        }
    }
}

/// Ownership guard for the supervised inner loop: when the supervisor future
/// is dropped for ANY reason (handle Drop aborting the supervisor, deadline
/// abort), the inner recovery loop is aborted instead of silently detaching.
/// Aborting a finished task is a no-op, so cooperative paths are unaffected.
struct AbortOnDropJoin {
    join: tokio::task::JoinHandle<()>,
}

impl Drop for AbortOnDropJoin {
    fn drop(&mut self) {
        self.join.abort();
    }
}

/// Death/exit supervisor seam: resolves the inner loop's terminal outcome into
/// the death channel. EVERY exit sends a stable terminal reason; a stop whose
/// grace deadline elapses aborts the loop and reports timeout/unknown — never
/// a cooperative success. Isolated from process-global surfaces so panic/exit
/// propagation is testable without a database.
fn supervise_session_worker(
    inner: tokio::task::JoinHandle<()>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    death: tokio::sync::watch::Sender<Option<String>>,
) -> impl std::future::Future<Output = ()> + Send {
    let mut inner = AbortOnDropJoin { join: inner };
    async move {
        tokio::select! {
            outcome = &mut inner.join => {
                // Race-proof labeling: an exit while a stop was requested IS a
                // cooperative stop, whichever select arm observed it first.
                let reason = match outcome {
                    Ok(()) if *stop.borrow() => {
                        "session projection recovery worker stopped cooperatively".to_owned()
                    }
                    Ok(()) => {
                        "session projection recovery worker stopped unexpectedly".to_owned()
                    }
                    Err(join_error) => format!(
                        "session projection recovery worker died: {join_error}"
                    ),
                };
                let _ = death.send(Some(reason));
            }
            changed = stop.changed() => {
                if changed.is_ok() && *stop.borrow() {
                    match tokio::time::timeout(Duration::from_secs(2), &mut inner.join).await {
                        Ok(Ok(())) => {
                            let _ = death.send(Some(
                                "session projection recovery worker stopped cooperatively"
                                    .to_owned(),
                            ));
                        }
                        Ok(Err(join_error)) => {
                            let _ = death.send(Some(format!(
                                "session projection recovery worker died: {join_error}"
                            )));
                        }
                        Err(_) => {
                            // An interrupted settlement remains unknown until
                            // its durable result and lease are reconciled.
                            inner.join.abort();
                            let _ =
                                tokio::time::timeout(Duration::from_secs(1), &mut inner.join).await;
                            let _ = death.send(Some(
                                "session projection recovery worker stop deadline exceeded; \
                                 recovery loop aborted; final outcome unknown"
                                    .to_owned(),
                            ));
                        }
                    }
                } else {
                    // Sender dropped without a stop signal: report the loop
                    // outcome so no exit stays unobservable.
                    match (&mut inner.join).await {
                        Ok(()) => {
                            let _ = death.send(Some(
                                "session projection recovery worker stopped unexpectedly"
                                    .to_owned(),
                            ));
                        }
                        Err(join_error) => {
                            let _ = death.send(Some(format!(
                                "session projection recovery worker died: {join_error}"
                            )));
                        }
                    }
                }
            }
        }
    }
}

fn spawn_owned_inner(pool: MySqlPool, redis: CompatRedis) -> SessionProjectionWorkerHandle {
    let worker_id = format!("identity-{}", Uuid::new_v4());
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (death_tx, death_rx) = tokio::sync::watch::channel(None::<String>);
    let inner = tokio::spawn(run_recovery_loop(pool, redis, worker_id, stop_rx.clone()));
    let join = tokio::spawn(supervise_session_worker(inner, stop_rx, death_tx));
    SessionProjectionWorkerHandle {
        stop: stop_tx,
        join: std::sync::Mutex::new(Some(join)),
        death: death_rx,
        join_deadline: Duration::from_secs(5),
    }
}

/// Redis-free default owned flavor: identical recovery loop to
/// [`spawn_without_redis`], plus a RAII handle (cooperative stop, bounded
/// shutdown, death observability).
pub fn spawn_without_redis_owned(pool: MySqlPool) -> SessionProjectionWorkerHandle {
    spawn_owned_inner(pool, None)
}

/// compat legacy owned flavor (`redis-compat` feature only). Only the stop
/// signal and handle differ from [`spawn`]; the recovery semantics are
/// identical.
#[cfg(feature = "redis-compat")]
pub fn spawn_owned(pool: MySqlPool, redis: CompatRedis) -> SessionProjectionWorkerHandle {
    spawn_owned_inner(pool, redis)
}

/// The shared recovery loop body. Identical claim/process behavior to the
/// historical inline loop, plus a cooperative stop signal checked at the loop
/// top and interrupting both sleeps (a stop never tears down a mid-flight
/// `process_one` row settlement; it only prevents the NEXT claim).
async fn run_recovery_loop(
    pool: MySqlPool,
    redis: CompatRedis,
    worker_id: String,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    // Bounded stop-aware sleep: returns true when a stop was requested.
    loop {
        if *stop.borrow() {
            tracing::info!(
                worker_id = %worker_id,
                "auth session recovery worker stopped cooperatively"
            );
            return;
        }
        match claim_one(&pool, &worker_id).await {
            Ok(Some(row)) => {
                if let Err(error) = process_one(&pool, redis.as_ref(), &worker_id, row).await {
                    tracing::warn!(worker_id = %worker_id, %error, "auth session outbox item will retry");
                }
            }
            Ok(None) => {
                if stop_sleep(&mut stop, Duration::from_millis(POLL_MILLIS)).await {
                    tracing::info!(
                        worker_id = %worker_id,
                        "auth session recovery worker stopped cooperatively"
                    );
                    return;
                }
            }
            Err(error) => {
                tracing::error!(worker_id = %worker_id, %error, "auth session outbox claim failed");
                if stop_sleep(&mut stop, std::time::Duration::from_secs(2)).await {
                    tracing::info!(
                        worker_id = %worker_id,
                        "auth session recovery worker stopped cooperatively"
                    );
                    return;
                }
            }
        }
    }
}

/// Bounded stop-aware sleep shared by [`run_recovery_loop`]: returns true when
/// a stop was requested; a dropped sender (legacy keep-alive flavor) keeps the
/// historical behavior.
async fn stop_sleep(
    stop: &mut tokio::sync::watch::Receiver<bool>,
    duration: std::time::Duration,
) -> bool {
    tokio::select! {
        changed = stop.changed() => match changed {
            Ok(()) => *stop.borrow(),
            Err(_) => false,
        },
        _ = tokio::time::sleep(duration) => false,
    }
}

async fn claim_one(pool: &MySqlPool, worker_id: &str) -> Result<Option<OutboxRow>, AstralError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| AstralError::Database(format!("Begin outbox claim failed: {error}")))?;
    let row = sqlx::query_as::<_, OutboxRow>(
        "SELECT outbox_id, operation_id, event_type, projection_key, payload_json, created_at, attempts \
         FROM auth_session_outbox \
         WHERE (status = 'PENDING' OR (status = 'PROCESSING' AND lease_expires_at < UTC_TIMESTAMP())) \
           AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP()) \
         ORDER BY created_at ASC, outbox_id ASC LIMIT 1 FOR UPDATE SKIP LOCKED",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| AstralError::Database(format!("Load outbox item failed: {error}")))?;
    let Some(row) = row else {
        tx.commit().await.map_err(|error| {
            AstralError::Database(format!("Commit empty outbox claim failed: {error}"))
        })?;
        return Ok(None);
    };
    let updated = sqlx::query(
        "UPDATE auth_session_outbox SET status = 'PROCESSING', lease_owner = ?, \
         lease_expires_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), attempts = attempts + 1, \
         updated_at = UTC_TIMESTAMP() WHERE outbox_id = ? \
         AND (status = 'PENDING' OR (status = 'PROCESSING' AND lease_expires_at < UTC_TIMESTAMP()))",
    )
    .bind(worker_id)
    .bind(LEASE_SECONDS)
    .bind(row.outbox_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| AstralError::Database(format!("Claim outbox item failed: {error}")))?;
    if updated.rows_affected() != 1 {
        tx.rollback().await.ok();
        return Ok(None);
    }
    tx.commit()
        .await
        .map_err(|error| AstralError::Database(format!("Commit outbox claim failed: {error}")))?;
    Ok(Some(row))
}

async fn process_one(
    pool: &MySqlPool,
    redis: CompatRedisRef<'_>,
    worker_id: &str,
    row: OutboxRow,
) -> Result<(), AstralError> {
    let projection_result = apply_revocation_projection(pool, redis, &row).await;
    match projection_result {
        Ok(()) => {
            let result = sqlx::query(
                "UPDATE auth_session_outbox SET status = 'PROCESSED', processed_at = UTC_TIMESTAMP(), \
                 processed_by = ?, lease_owner = NULL, lease_expires_at = NULL, updated_at = UTC_TIMESTAMP() \
                 WHERE outbox_id = ? AND status = 'PROCESSING' AND lease_owner = ?",
            )
            .bind(worker_id)
            .bind(row.outbox_id)
            .bind(worker_id)
            .execute(pool)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Complete outbox item failed: {error}"))
            })?;
            if result.rows_affected() != 1 {
                return Err(AstralError::Internal(
                    "outbox completion lease was lost".into(),
                ));
            }
            Ok(())
        }
        Err(error) => {
            let delay = (2_i64.pow((row.attempts.max(0) as u32).min(8))).min(MAX_BACKOFF_SECONDS);
            sqlx::query(
                "UPDATE auth_session_outbox SET status = 'PENDING', next_attempt_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), \
                 lease_owner = NULL, lease_expires_at = NULL, last_error = ?, updated_at = UTC_TIMESTAMP() \
                 WHERE outbox_id = ? AND status = 'PROCESSING' AND lease_owner = ?",
            )
            .bind(delay)
            .bind(error.to_string())
            .bind(row.outbox_id)
            .bind(worker_id)
            .execute(pool)
            .await
            .map_err(|db_error| AstralError::Database(format!("Release outbox lease failed: {db_error}")))?;
            Err(error)
        }
    }
}

async fn apply_revocation_projection(
    pool: &MySqlPool,
    _redis: CompatRedisRef<'_>,
    row: &OutboxRow,
) -> Result<(), AstralError> {
    const REVOKED_TTL_SECS: u64 = 7 * 24 * 3600;
    let indexed_jtis = load_projection_jtis(pool, row).await?;
    if indexed_jtis.is_empty() {
        if !(row.event_type == "REVOKE"
            && row
                .payload_json
                .as_deref()
                .and_then(|payload| serde_json::from_str::<Value>(payload).ok())
                .is_some_and(|payload| payload.get("v").and_then(Value::as_i64) == Some(2)))
        {
            return Err(AstralError::Internal(
                "auth revocation projection has no proven JTI snapshot".into(),
            ));
        }
        return Ok(());
    }
    // 兼容 adapter（显式启用 Redis 时）保留历史投影清理；Redis-free 默认路径
    // 只登记进程内加速面（durable close 已由撤销主路径完成，是权威事实）。
    // 仅 redis-compat feature 编译（feature-off 构建无 redis 类型）。
    #[cfg(feature = "redis-compat")]
    if let Some(redis) = _redis {
        let mut conn = redis.clone();
        for jti in &indexed_jtis {
            let _: () = conn
                .del((format!("access:jti:{jti}"), format!("access:grant:{jti}")))
                .await
                .map_err(|error| {
                    AstralError::Cache(format!("Delete auth projections failed: {error}"))
                })?;
            let _: () = conn
                .set_ex::<_, _, ()>(format!("jwt:revoked:{jti}"), "1", REVOKED_TTL_SECS)
                .await
                .map_err(|error| AstralError::Cache(format!("Mark revoked JTI failed: {error}")))?;
        }
    }
    // 恢复路径与主撤销路径同点登记进程内加速面（镜像 + 既有注册表）。
    astral_db::note_revocations_in_process(&indexed_jtis, REVOKED_TTL_SECS);
    Ok(())
}

async fn load_projection_jtis(
    pool: &MySqlPool,
    row: &OutboxRow,
) -> Result<Vec<String>, AstralError> {
    if row.event_type != "REVOKE" {
        return Err(AstralError::Validation(format!(
            "Unsupported auth projection event type: {}",
            row.event_type
        )));
    }
    if let Some(payload) = row.payload_json.as_deref() {
        let value: Value = serde_json::from_str(payload).map_err(|_| {
            AstralError::Validation("Auth revocation outbox payload is malformed".into())
        })?;
        match value.get("v") {
            Some(Value::Number(version)) if version.as_i64() == Some(2) => {
                let expected_user = row
                    .projection_key
                    .strip_prefix("user:")
                    .and_then(|id| id.parse::<i64>().ok())
                    .filter(|id| *id > 0)
                    .ok_or_else(|| {
                        AstralError::Validation("Auth revocation snapshot has invalid scope".into())
                    })?;
                if value.get("userId").and_then(Value::as_i64) != Some(expected_user) {
                    return Err(AstralError::Validation(
                        "Auth revocation snapshot user does not match projection key".into(),
                    ));
                }
                let jtis = value
                    .get("jtis")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        AstralError::Validation("Auth revocation snapshot is missing jtis".into())
                    })?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .filter(|jti| !jti.trim().is_empty())
                            .map(ToOwned::to_owned)
                            .ok_or_else(|| {
                                AstralError::Validation(
                                    "Auth revocation snapshot contains invalid jti".into(),
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(jtis);
            }
            Some(_) => {
                return Err(AstralError::Validation(
                    "Unsupported auth revocation outbox version".into(),
                ));
            }
            None => {}
        }
    }

    let (kind, value) = row
        .projection_key
        .split_once(':')
        .ok_or_else(|| AstralError::Validation("Invalid auth projection key".into()))?;
    let id = value
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AstralError::Validation("Invalid auth projection id".into()))?;
    let rows = match kind {
        "session" => {
            sqlx::query_scalar::<_, String>(
                "SELECT jti FROM auth_session_jti_index \
             WHERE session_id = ? AND issued_at <= ? \
               AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
            )
            .bind(id)
            .bind(row.created_at)
            .fetch_all(pool)
            .await
        }
        "family" => {
            sqlx::query_scalar::<_, String>(
                "SELECT i.jti FROM auth_session_jti_index i \
             INNER JOIN auth_device_session s ON s.session_id = i.session_id \
             WHERE s.family_id = ? AND i.issued_at <= ? \
               AND (i.expires_at IS NULL OR i.expires_at > UTC_TIMESTAMP())",
            )
            .bind(id)
            .bind(row.created_at)
            .fetch_all(pool)
            .await
        }
        "user" => {
            sqlx::query_scalar::<_, String>(
                "SELECT i.jti FROM auth_session_jti_index i \
             WHERE i.user_id = ? AND i.issued_at <= ? \
               AND (i.expires_at IS NULL OR i.expires_at > UTC_TIMESTAMP())",
            )
            .bind(id)
            .bind(row.created_at)
            .fetch_all(pool)
            .await
        }
        _ => {
            return Err(AstralError::Validation(
                "Unknown auth projection key".into(),
            ))
        }
    };
    rows.map_err(|error| {
        AstralError::Database(format!("Load auth projection JTIs failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::{load_projection_jtis, OutboxRow};
    use time::{Date, Month, PrimitiveDateTime, Time};

    #[tokio::test]
    async fn projection_key_validation_fails_before_database_access() {
        let pool = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/identity").unwrap();
        let row = OutboxRow {
            outbox_id: 1,
            operation_id: "op".into(),
            event_type: "REVOKE".into(),
            projection_key: "session:0".into(),
            payload_json: None,
            created_at: PrimitiveDateTime::new(
                Date::from_calendar_date(2026, Month::January, 1).unwrap(),
                Time::MIDNIGHT,
            ),
            attempts: 0,
        };
        assert!(load_projection_jtis(&pool, &row).await.is_err());
        let mut invalid = row;
        invalid.projection_key = "card:1".into();
        assert!(load_projection_jtis(&pool, &invalid).await.is_err());
    }
}

#[cfg(test)]
mod supervision_tests {
    use super::{supervise_session_worker, SessionProjectionWorkerHandle};

    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }

    async fn pending_worker(
        deadline: std::time::Duration,
    ) -> (
        SessionProjectionWorkerHandle,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let inner = tokio::spawn(async move {
            let _drop = DropSignal(Some(dropped_tx));
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.unwrap();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (death_tx, death_rx) = tokio::sync::watch::channel(None);
        let join = tokio::spawn(supervise_session_worker(inner, stop_rx, death_tx));
        (
            SessionProjectionWorkerHandle {
                stop: stop_tx,
                join: std::sync::Mutex::new(Some(join)),
                death: death_rx,
                join_deadline: deadline,
            },
            dropped_rx,
        )
    }

    #[tokio::test]
    async fn dropping_owned_handle_aborts_the_actual_recovery_loop() {
        let (handle, dropped) = pending_worker(std::time::Duration::from_secs(5)).await;
        drop(handle);
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped)
            .await
            .expect("inner recovery loop must not detach")
            .expect("inner Drop must be observed");
    }

    #[tokio::test]
    async fn cancelling_shutdown_after_join_take_aborts_the_recovery_loop() {
        let (handle, dropped) = pending_worker(std::time::Duration::from_secs(5)).await;
        {
            let mut shutdown = std::pin::pin!(handle.shutdown_join());
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(20), &mut shutdown)
                    .await
                    .is_err()
            );
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped)
            .await
            .expect("cancelled shutdown must keep ownership")
            .expect("inner Drop must be observed");
    }

    #[tokio::test]
    async fn shutdown_deadline_aborts_and_reports_unknown() {
        let (handle, dropped) = pending_worker(std::time::Duration::from_millis(20)).await;
        let outcome = handle.shutdown_join().await;
        assert!(outcome.unwrap_err().contains("final outcome unknown"));
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped)
            .await
            .expect("deadline must abort the inner loop")
            .expect("inner Drop must be observed");
    }

    #[tokio::test]
    async fn dropping_unpolled_supervisor_aborts_its_inner_loop() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let inner = tokio::spawn(async move {
            let _drop = DropSignal(Some(dropped_tx));
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.unwrap();
        let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (death_tx, _death_rx) = tokio::sync::watch::channel(None);
        drop(supervise_session_worker(inner, stop_rx, death_tx));
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .expect("ownership must exist before the supervisor's first poll")
            .expect("inner Drop must be observed");
    }

    /// Real panic in the recovery loop: the supervisor publishes an observable
    /// death reason ("died") instead of leaving a detached corpse.
    #[tokio::test]
    async fn supervisor_reports_real_panic_as_death() {
        let (death_tx, death_rx) = tokio::sync::watch::channel(None::<String>);
        let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let inner: tokio::task::JoinHandle<()> = tokio::spawn(async move {
            panic!("simulated session recovery loop panic");
        });
        let supervisor = tokio::spawn(supervise_session_worker(inner, stop_rx, death_tx));
        tokio::time::timeout(std::time::Duration::from_secs(5), supervisor)
            .await
            .expect("supervisor must resolve")
            .expect("supervisor join");
        let reason = death_rx.borrow().clone();
        assert!(
            matches!(&reason, Some(text) if text.contains("died")),
            "panic must surface as an observable death: {reason:?}"
        );
    }

    /// Cooperative stop: the supervisor gives the loop a grace window, the
    /// loop exits on its own signal check, and the death reason reports the
    /// cooperative stop (not a crash).
    #[tokio::test]
    async fn supervisor_reports_cooperative_stop() {
        let (death_tx, death_rx) = tokio::sync::watch::channel(None::<String>);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let loop_stop = stop_rx.clone();
        let inner: tokio::task::JoinHandle<()> = tokio::spawn(async move {
            // Loop seam: exits only on the stop signal, like run_recovery_loop.
            loop {
                if *loop_stop.borrow() {
                    return;
                }
                let mut stop_select = loop_stop.clone();
                let changed = tokio::select! {
                    changed = stop_select.changed() => changed.is_ok(),
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => false,
                };
                if !changed {
                    return;
                }
            }
        });
        let supervisor = tokio::spawn(supervise_session_worker(inner, stop_rx, death_tx));
        stop_tx.send(true).expect("stop channel open");
        tokio::time::timeout(std::time::Duration::from_secs(5), supervisor)
            .await
            .expect("supervisor must resolve")
            .expect("supervisor join");
        let reason = death_rx.borrow().clone();
        assert!(
            matches!(&reason, Some(text) if text.contains("stopped cooperatively")),
            "cooperative stop must be observable as such: {reason:?}"
        );
    }

    /// Unexpected exit without any stop signal is reported as a death, never
    /// confused with a sanctioned shutdown.
    #[tokio::test]
    async fn supervisor_reports_unexpected_exit_as_death() {
        let (death_tx, death_rx) = tokio::sync::watch::channel(None::<String>);
        let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let inner: tokio::task::JoinHandle<()> = tokio::spawn(async move {});
        let supervisor = tokio::spawn(supervise_session_worker(inner, stop_rx, death_tx));
        tokio::time::timeout(std::time::Duration::from_secs(5), supervisor)
            .await
            .expect("supervisor must resolve")
            .expect("supervisor join");
        let reason = death_rx.borrow().clone();
        assert!(
            matches!(&reason, Some(text) if text.contains("stopped unexpectedly")),
            "unexpected exit must be observable: {reason:?}"
        );
    }
}
