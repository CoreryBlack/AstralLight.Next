//! Projector runtime seam：所有 DB 事务边界经由本 trait，决策分支可在无
//! MySQL 环境下单测；生产实现 `SqlxAuthorizationProjectorRuntime` 直连
//! astral-db durable 原语，提交后镜像安装与 L2 推送保持既有顺序。

use std::sync::Arc;

#[cfg(feature = "e3-observability")]
use super::{log_e3_attempt_event, log_e3_identity_event};
use super::{reconcile_lease_mutation_loss, CLAIM_LEASE_SECS};

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_db::{
    claim_delta_event_by_stable_event_in_tx, claim_next_delta_event_in_partition_tx,
    claim_next_delta_event_in_tx, extend_delta_event_lease, fail_delta_event,
    load_claimed_delta_event_for_update_in_tx, load_grant_ledger_rows,
    load_published_aggregate_frontier_in_tx, load_published_parent_reference_views_in_tx,
    mark_delta_event_quarantined, project_authorization_delta_in_tx, release_delta_event_lease,
    AuthorizationProjectionError, ClaimedDeltaEvent, ClaimedStableEventOutcome,
    DeltaEventAppendRequest, DeltaEventClaim, DeltaEventClaimScope, DeltaLeaseIdentity,
    DeltaProjectorPublishCommand, DeltaProjectorPublishOutcome, ParentReferenceView,
    PartitionLeaseHandle, ProjectionAggregateIdentity, PublishedAggregateFrontier, RawLedgerRow,
};

// ─────────────────────────────────────────────────────────────────────────────
// Runtime seam: every DB transaction boundary lives behind this trait so each
// decision branch stays unit-testable without MySQL.

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RuntimeAccessError {
    #[error("database access failed: {0}")]
    Database(String),
    /// The publication may already be committed. No lease mutation or replay
    /// is permitted until durable state has been reconciled.
    #[error("publication outcome requires reconciliation: {0}")]
    PublicationUnknown(String),
    /// Durable commit succeeded, but the local read mirror is unavailable.
    /// Reads defer to the strict repository; this event must not be replayed.
    #[error("publication committed with unavailable local mirror: {0}")]
    CommittedMirrorUnavailable(String),
    #[error("repository rejected the operation: {0}")]
    Repository(RepositoryRejection),
}

/// Typed payload of [`RuntimeAccessError::Repository`]. Repository error
/// variants are kept INTACT across the runtime seam so downstream failure
/// classification matches on the typed variant plus its embedded stable
/// machine code — never on rendered `Display` text, whose wording is not a
/// contract and whose dynamic detail may legitimately contain foreign tokens.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryRejection {
    /// Typed projection-repository refusal (variant + stable `code=` token).
    #[error("{0}")]
    Projection(AuthorizationProjectionError),
    /// Typed astral-db grant-repository refusal (delta-lease claim/lease
    /// primitives and any future non-projection primitive). The variant is
    /// preserved intact — `ClaimRace` and `LeaseCasFailed` in particular — so
    /// lost-lease classification can never be flattened into generic text and
    /// a lost lease can never be misrouted into a `fail_delta_event` write.
    #[error("{0}")]
    Grant(astral_db::GrantRepositoryError),
    /// Non-typed refusal text raised by this module itself (projector-side
    /// stable `code=` tokens), rendered here; carries a stable token when
    /// available.
    #[error("{0}")]
    Other(String),
}

impl From<sqlx::Error> for RuntimeAccessError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value.to_string())
    }
}

impl From<astral_db::GrantRepositoryError> for RuntimeAccessError {
    fn from(value: astral_db::GrantRepositoryError) -> Self {
        match value {
            astral_db::GrantRepositoryError::Query(inner) => Self::Database(inner.to_string()),
            // Every non-query grant refusal keeps its variant across the seam
            // (M2): `ClaimRace`/`LeaseCasFailed` must stay classifiable as
            // lost ownership instead of dissolving into rendered text.
            other => Self::Repository(RepositoryRejection::Grant(other)),
        }
    }
}

impl From<AuthorizationProjectionError> for RuntimeAccessError {
    fn from(value: AuthorizationProjectionError) -> Self {
        match value {
            AuthorizationProjectionError::Query(inner) => Self::Database(inner.to_string()),
            other => Self::Repository(RepositoryRejection::Projection(other)),
        }
    }
}

#[async_trait]
pub trait AuthorizationProjectorRuntime: Send + Sync + 'static {
    /// One short-lived claim transaction: installs LEASED + owner + fresh
    /// run-scoped token. Commit happens inside (also for `Ok(None)`).
    async fn claim_next_event(
        &self,
        scope: &DeltaEventClaimScope,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError>;

    /// Direct-dispatch claim port (local in-process projector path): claim
    /// ONE event by its stable event identity inside ONE transaction,
    /// re-binding the commit-proven [`DeltaEventAppendRequest`] payload
    /// field-by-field against the durable row. The transaction commits inside
    /// (both for `Claimed` and for the no-mutation outcomes). Default fails
    /// closed: runtimes that have not opted into the direct-dispatch path
    /// never claim by dispatch.
    async fn claim_event_by_dispatch(
        &self,
        _request: &DeltaEventAppendRequest,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<ClaimedStableEventOutcome, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.claim_by_dispatch_unsupported".to_owned(),
        )))
    }

    /// Strict re-read of the leased row (lease proof re-verified inside SQL).
    async fn read_claimed_event(
        &self,
        identity: &DeltaLeaseIdentity,
    ) -> Result<ClaimedDeltaEvent, RuntimeAccessError>;

    /// One short read-only transaction loading the strict published frontier
    /// AND the current parent reference snapshot for one aggregate.
    ///
    /// - `Ok(None)`: no current pointer exists (aggregate never published);
    ///   nothing is locked or written.
    /// - `Ok(Some([`PublicationContext`]))`: frontier generations `1..=G`
    ///   passed the strict plan⇆delta⇆manifest⇆pointer assembly plus the
    ///   verified parent reference views of the CURRENT publication, loaded in
    ///   ONE transaction so both facets describe the same committed world.
    /// - A live pointer whose parent snapshot cannot be observed is reported
    ///   as Corrupt — never as a degraded partial view usable by planning.
    async fn observe_publication_context(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Result<Option<PublicationContext>, RuntimeAccessError>;

    /// Complete revision history for `(tenant, aggregate[, card])`, ordered by
    /// (`grant_id`, `revision_no`); read-only, no raw-source fallback.
    async fn load_scope_ledger(
        &self,
        tenant_id: i64,
        aggregate_type: &str,
        aggregate_id: i64,
        card_id: Option<i64>,
    ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError>;

    /// Share an immutable complete ledger when the adapter has one. The default
    /// preserves the existing owned-read contract and all repository failures.
    async fn load_scope_ledger_shared(
        &self,
        tenant_id: i64,
        aggregate_type: &str,
        aggregate_id: i64,
        card_id: Option<i64>,
    ) -> Result<Arc<Vec<RawLedgerRow>>, RuntimeAccessError> {
        self.load_scope_ledger(tenant_id, aggregate_type, aggregate_id, card_id)
            .await
            .map(Arc::new)
    }

    /// Execute the fixed publish sequence and commit. A statement failure rolls
    /// back; commit errors require reconciliation, and local-mirror failure may
    /// occur after durable commit without permitting any event replay.
    async fn execute_projection_publish(
        &self,
        command: &DeltaProjectorPublishCommand,
    ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError>;

    /// Record a durable failure + bounded backoff. Loss of the lease CAS is
    /// reconciled (logged) instead of retried blindly.
    async fn fail_event(&self, identity: &DeltaLeaseIdentity, backoff_seconds: i64, message: &str);

    /// Relinquish the lease without recording failure.
    async fn release_event(&self, identity: &DeltaLeaseIdentity);

    /// Durable terminal quarantine of one leased event via the live-lease
    /// guarded repository boundary.
    ///
    /// `Ok(())` is durable proof that the row left the claimable queue as
    /// `QUARANTINED`. A `LeaseCasFailed`-flavored error or a database query
    /// failure means the terminal state is UNKNOWN: callers must record the
    /// unknown result and issue NO further mutation for that event (no fail,
    /// no release, no retry) until reconciliation. Quarantine deliberately
    /// keeps the row's `cas_version` untouched, which is exactly what the
    /// operator requeue path pins later; this worker never requeues.
    async fn mark_event_quarantined(
        &self,
        lease: &DeltaLeaseIdentity,
        reason_code: &str,
        reason_detail: &str,
    ) -> Result<(), RuntimeAccessError>;

    /// 诊断启发（F5 修复 1d 看门狗，非授权路径）：作用域内是否存在当前可
    /// claim 的事件（PENDING 且 backoff 期满，或租约已过期的 LEASED）。默认
    /// `false`（无积压，看门狗保守不动作）仅适用于测试/空闲 runtime；生产
    /// sqlx runtime 必须覆盖。
    async fn has_claimable_work(&self, _scope: &DeltaEventClaimScope) -> bool {
        false
    }

    // ── Partition scheduling ports (multi-tenant redesign Phase 1). Defaults
    // fail closed: a runtime that has not opted into partitioned scheduling
    // must never be silently scheduled as if it had. The production sqlx
    // runtime and partition-mode test fakes override all four; TenantSerial
    // mode never calls them.

    /// Discover partitions (inside the validated tenant allowlist) that hold
    /// at least one claimable event right now, oldest due first. The ledger
    /// query mirrors the claim eligibility + sibling-ordering gate verbatim.
    async fn discover_partitions(
        &self,
        _tenants: &[i64],
        _limit: i64,
    ) -> Result<Vec<ProjectionAggregateIdentity>, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Acquire (or self-renew / expired-takeover) the exclusive scheduling
    /// lease for one partition. `Ok(None)` = live lease held by another worker
    /// (Busy): skip, never wait.
    async fn acquire_partition_lease(
        &self,
        _identity: &ProjectionAggregateIdentity,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<PartitionLeaseHandle>, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Heartbeat the partition lease before each claim iteration. An error
    /// means the lease was lost (another worker took over after expiry): the
    /// worker must stop touching the partition immediately.
    async fn renew_partition_lease(
        &self,
        _handle: &PartitionLeaseHandle,
        _lease_seconds: i64,
    ) -> Result<(), RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Best-effort release; expiry is the crash safety net.
    async fn release_partition_lease(
        &self,
        _handle: &PartitionLeaseHandle,
    ) -> Result<(), RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Claim the next claimable event of ONE partition (identical contract to
    /// [`Self::claim_next_event`], narrowed to the partition identity).
    async fn claim_next_event_in_partition(
        &self,
        _identity: &ProjectionAggregateIdentity,
        _scope: &DeltaEventClaimScope,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }

    /// Pointer-advance reclaim (M3, the ~898s finding): after a DURABLE
    /// publication of this aggregate, pull the `next_attempt_at` of its
    /// budget-exhausted parked events back to now. Returns the number of rows
    /// pulled forward. Default fails closed like the other partition ports.
    async fn reclaim_budget_exhausted_events(
        &self,
        _identity: &ProjectionAggregateIdentity,
    ) -> Result<u64, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_ports_unsupported".to_owned(),
        )))
    }
}

/// Planning-time publication world observed in ONE short committed read
/// transaction (never a publish proof).
#[derive(Debug, Clone)]
pub struct PublicationContext {
    /// Strictly verified published frontier of the aggregate: generations
    /// `1..=G`, embedding the locked pointer record (authoritative base
    /// generation + previous revoke fence) and the `G`-th manifest summary.
    pub frontier: PublishedAggregateFrontier,
    /// Verified `(ordinal, view)` parent reference pairs of the CURRENT
    /// publication in ascending ordinal order. Planning hint only: staging
    /// re-locks and re-verifies every digest/seal/lineage byte inside its own
    /// transaction before any reuse becomes durable.
    pub parent_references: Vec<(u64, ParentReferenceView)>,
}

pub struct SqlxAuthorizationProjectorRuntime {
    pool: MySqlPool,
}

/// Watchdog diagnostics probe (F5 修复 1d): "does this tenant scope hold any
/// event the claim path could serve right now?" — same shape as the claim
/// candidate statements, INCLUDING the per-grant sibling-ordering gate (pinned
/// byte-equal to [`astral_db::DELTA_CLAIM_SIBLING_ORDER_GATE`] by
/// `watchdog_probe_carries_the_claim_sibling_order_gate`). A gate-free probe
/// would report a backlog that the claim can never serve while one chain
/// serializes behind a backoff'd predecessor, and the stall detector would
/// rebuild worker generations in a loop.
pub(crate) const WATCHDOG_CLAIMABLE_PROBE_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM authorization_delta_event \
    WHERE tenant_id = ? \
      AND ((status = 'PENDING' \
           AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())) \
          OR (status = 'LEASED' \
              AND lease_expires_at IS NOT NULL \
              AND lease_expires_at <= UTC_TIMESTAMP())) \
      AND NOT EXISTS (SELECT 1 FROM authorization_delta_event pred \
          WHERE pred.tenant_id = authorization_delta_event.tenant_id \
            AND pred.grant_id = authorization_delta_event.grant_id \
            AND pred.target_version < authorization_delta_event.target_version \
            AND pred.status IN ('PENDING', 'LEASED')))";

impl SqlxAuthorizationProjectorRuntime {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthorizationProjectorRuntime for SqlxAuthorizationProjectorRuntime {
    async fn claim_event_by_dispatch(
        &self,
        request: &DeltaEventAppendRequest,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<ClaimedStableEventOutcome, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        let outcome =
            claim_delta_event_by_stable_event_in_tx(&mut tx, request, lease_owner, lease_seconds)
                .await?;
        // Commit every arm: Claimed installs the lease; AlreadyProcessed /
        // Busy / InDoubt made no mutation (read-only lock released by commit).
        tx.commit().await?;
        Ok(outcome)
    }

    async fn claim_next_event(
        &self,
        scope: &DeltaEventClaimScope,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        let claim =
            claim_next_delta_event_in_tx(&mut tx, *scope, lease_owner, lease_seconds).await?;
        // Commit both arms: Some(installed lease) and None(read-only snapshot).
        tx.commit().await?;
        #[cfg(feature = "e3-observability")]
        if let Some(claimed) = claim.as_ref() {
            log_e3_attempt_event("claim_committed", claimed, "leased", true, None);
        }
        Ok(claim)
    }

    async fn discover_partitions(
        &self,
        tenants: &[i64],
        limit: i64,
    ) -> Result<Vec<ProjectionAggregateIdentity>, RuntimeAccessError> {
        let rows = astral_db::discover_claimable_partitions(&self.pool, tenants, limit).await?;
        let mut identities = Vec::with_capacity(rows.len());
        for row in rows {
            identities.push(ProjectionAggregateIdentity::new(
                row.tenant_id,
                row.aggregate_type,
                row.aggregate_id,
            )?);
        }
        Ok(identities)
    }

    async fn acquire_partition_lease(
        &self,
        identity: &ProjectionAggregateIdentity,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<PartitionLeaseHandle>, RuntimeAccessError> {
        astral_db::acquire_partition_lease(&self.pool, identity, lease_owner, lease_seconds)
            .await
            .map_err(RuntimeAccessError::from)
    }

    async fn renew_partition_lease(
        &self,
        handle: &PartitionLeaseHandle,
        lease_seconds: i64,
    ) -> Result<(), RuntimeAccessError> {
        astral_db::renew_partition_lease(&self.pool, handle, lease_seconds)
            .await
            .map_err(RuntimeAccessError::from)
    }

    async fn release_partition_lease(
        &self,
        handle: &PartitionLeaseHandle,
    ) -> Result<(), RuntimeAccessError> {
        astral_db::release_partition_lease(&self.pool, handle)
            .await
            .map_err(RuntimeAccessError::from)
    }

    async fn claim_next_event_in_partition(
        &self,
        identity: &ProjectionAggregateIdentity,
        scope: &DeltaEventClaimScope,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        let claim = claim_next_delta_event_in_partition_tx(
            &mut tx,
            *scope,
            identity,
            lease_owner,
            lease_seconds,
        )
        .await?;
        // Commit both arms: Some(installed lease) and None (read-only snapshot).
        tx.commit().await?;
        #[cfg(feature = "e3-observability")]
        if let Some(claimed) = claim.as_ref() {
            log_e3_attempt_event("claim_committed", claimed, "leased", true, None);
        }
        Ok(claim)
    }

    async fn reclaim_budget_exhausted_events(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Result<u64, RuntimeAccessError> {
        astral_db::reclaim_budget_exhausted_events(&self.pool, identity)
            .await
            .map_err(RuntimeAccessError::from)
    }

    async fn read_claimed_event(
        &self,
        identity: &DeltaLeaseIdentity,
    ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        let claimed = load_claimed_delta_event_for_update_in_tx(&mut tx, identity).await?;
        tx.commit().await?;
        Ok(claimed)
    }

    async fn observe_publication_context(
        &self,
        identity: &ProjectionAggregateIdentity,
    ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        // One short transaction, two strictly verifying public loaders: the
        // frontier loader already proves pointer/manifest/plan/delta agreement
        // (and returns None only when NO current pointer exists); the parent
        // reference loader then re-locks the same committed world. Only
        // astral-db's documented API surface is used — no hand-written SQL.
        let context = match load_published_aggregate_frontier_in_tx(&mut tx, identity).await? {
            None => None,
            Some(frontier) => {
                let snapshot = load_published_parent_reference_views_in_tx(&mut tx, identity)
                    .await?
                    .ok_or_else(|| {
                        RuntimeAccessError::Repository(RepositoryRejection::Other(
                            "code=auth_projector.parent_snapshot_missing_for_live_pointer"
                                .to_owned(),
                        ))
                    })?;
                Some(PublicationContext {
                    frontier,
                    parent_references: snapshot.references,
                })
            }
        };
        tx.commit().await?;
        Ok(context)
    }

    async fn load_scope_ledger(
        &self,
        tenant_id: i64,
        aggregate_type: &str,
        aggregate_id: i64,
        card_id: Option<i64>,
    ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
        let rows = load_grant_ledger_rows(
            &self.pool,
            astral_db::GrantLedgerLoadScope {
                tenant_id,
                card_id,
                aggregate: Some((aggregate_type, aggregate_id)),
            },
        )
        .await?;
        Ok(rows)
    }

    async fn execute_projection_publish(
        &self,
        command: &DeltaProjectorPublishCommand,
    ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
        let mut tx = self.pool.begin().await?;
        // Lease heartbeat INSIDE the publish transaction (H2): the claim
        // window can elapse while pure planning/compile work runs before this
        // transaction even starts, and a large transaction can outlast the
        // remaining window; without a renewal the in-transaction completion's
        // live-expiry guard would roll back an otherwise valid publication
        // merely because the original 120s elapsed. The owner+token+status
        // CAS renews from SERVER time for one more full claim window
        // ([`CLAIM_LEASE_SECS`]) and fails closed on any real takeover. A CAS
        // loss surfaces as `LeaseCasFailed` → LeaseLost/UNKNOWN with zero
        // writes (the transaction holds no locks yet — nothing to roll back).
        extend_delta_event_lease(&mut *tx, &command.delta_lease_identity, CLAIM_LEASE_SECS).await?;
        let outcome = project_authorization_delta_in_tx(&mut tx, command).await?;
        tx.commit().await.map_err(|error| {
            RuntimeAccessError::PublicationUnknown(format!(
                "code=auth_projector.publish_commit_unknown;event={};error={error}",
                command.expectation.event_id
            ))
        })?;
        #[cfg(feature = "e3-observability")]
        log_e3_identity_event(
            "publish_committed",
            &command.delta_lease_identity,
            "succeeded",
            true,
            None,
        );
        if let Some(hub) = astral_db::memory_projection_hub::memory_projection_hub() {
            hub.install_committed_publication(&outcome)
                .map_err(|error| {
                    RuntimeAccessError::CommittedMirrorUnavailable(format!(
                        "code=auth_projector.memory_install_after_commit_failed;{error}"
                    ))
                })?;
        }
        // L2 is optional distribution; it cannot delay installation of the
        // committed local state or act as its completion proof.
        push_published_evidence_to_l2_after_commit(&self.pool, command).await;
        Ok(outcome)
    }

    async fn fail_event(&self, identity: &DeltaLeaseIdentity, backoff_seconds: i64, message: &str) {
        match fail_delta_event(&self.pool, identity, backoff_seconds, message).await {
            Ok(()) => {
                #[cfg(feature = "e3-observability")]
                log_e3_identity_event(
                    "backoff_committed",
                    identity,
                    "pending",
                    true,
                    Some(backoff_seconds),
                );
            }
            Err(error) => {
                #[cfg(feature = "e3-observability")]
                log_e3_identity_event(
                    "terminal_unknown",
                    identity,
                    "backoff_cas_unknown",
                    false,
                    Some(backoff_seconds),
                );
                reconcile_lease_mutation_loss(identity, "fail", &error);
            }
        }
    }

    async fn release_event(&self, identity: &DeltaLeaseIdentity) {
        match release_delta_event_lease(&self.pool, identity).await {
            Ok(()) => {
                #[cfg(feature = "e3-observability")]
                log_e3_identity_event("release_committed", identity, "pending", true, None);
            }
            Err(error) => {
                #[cfg(feature = "e3-observability")]
                log_e3_identity_event(
                    "terminal_unknown",
                    identity,
                    "release_cas_unknown",
                    false,
                    None,
                );
                reconcile_lease_mutation_loss(identity, "release", &error);
            }
        }
    }

    async fn has_claimable_work(&self, scope: &DeltaEventClaimScope) -> bool {
        // 诊断启发（F5 修复 1d 看门狗，非授权路径）：与 claim 候选谓词同形的
        // 存在性探测（同形由 WATCHDOG_CLAIMABLE_PROBE_SQL 常量 +
        // `watchdog_probe_carries_the_claim_sibling_order_gate` 钉死），区分
        // "空队列"与"有积压但停滞"。查询失败 → false（看门狗保守不动作，
        // 绝不因诊断查询失败而重建 worker）。
        matches!(
            sqlx::query_scalar::<_, i64>(WATCHDOG_CLAIMABLE_PROBE_SQL)
                .bind(scope.tenant_id)
                .fetch_one(&self.pool)
                .await,
            Ok(1)
        )
    }

    async fn mark_event_quarantined(
        &self,
        lease: &DeltaLeaseIdentity,
        reason_code: &str,
        reason_detail: &str,
    ) -> Result<(), RuntimeAccessError> {
        let result = mark_delta_event_quarantined(&self.pool, lease, reason_code, reason_detail)
            .await
            .map_err(RuntimeAccessError::from);
        #[cfg(feature = "e3-observability")]
        match &result {
            Ok(()) => {
                log_e3_identity_event("quarantine_committed", lease, "quarantined", true, None)
            }
            Err(_) => log_e3_identity_event(
                "terminal_unknown",
                lease,
                "quarantine_cas_unknown",
                false,
                None,
            ),
        }
        result
    }
}

/// 发布事务提交后的 L2 evidence 推送（读链规模化 Batch D）。
///
/// 受影响卡由发布命令的卡作用域得出：仅 CARD 聚合且携带卡作用域的事件推送
/// （ELIGIBILITY/RULE_SET 等其它聚合不推 —— L2 只承载 CARD 聚合的评估
/// evidence）；卡作用域缺失（None）无法定位卡级 evidence 键，同样不推。
/// 内容来源 = 发布后自读严格 reader（pool 版，与 miss 回源同源同实现，天然
/// parity）；推送到内嵌当前时代的 L2 键（TTL 300s）。任何失败一律静默 warn。
async fn push_published_evidence_to_l2_after_commit(
    pool: &MySqlPool,
    command: &DeltaProjectorPublishCommand,
) {
    if let Some((tenant_id, card_id)) = astral_db::publish_affected_card_scope(
        &command.expectation.identity,
        command.expectation.card_id,
    ) {
        astral_db::push_published_card_evidence_to_l2(pool, tenant_id, card_id).await;
    }
}
