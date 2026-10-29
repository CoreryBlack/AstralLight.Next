//! Projector runtime seam：所有 DB 事务边界经由本 trait，决策分支可在无
//! MySQL 环境下单测；生产实现 `SqlxAuthorizationProjectorRuntime` 直连
//! astral-db durable 原语；提交后只安装已证明的本地镜像。

use std::sync::Arc;

use super::CLAIM_LEASE_SECS;
#[cfg(feature = "e3-observability")]
use super::{log_e3_attempt_event, log_e3_identity_event};
use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_db::{
    load_grant_ledger_rows, load_published_aggregate_frontier_in_tx,
    load_published_parent_reference_views_in_tx, AuthorizationProjectionError, ClaimedDeltaEvent,
    DeltaEventAppendRequest, DeltaEventClaim, DeltaEventClaimScope, DeltaLeaseIdentity,
    DeltaProjectorPublishCommand, DeltaProjectorPublishOutcome, OwnedStableEventOutcome,
    ParentReferenceView, ProjectionAggregateIdentity, PublishedAggregateFrontier, RawLedgerRow,
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
        if astral_db::owned_execution_outcome_is_unknown(&value) {
            return Self::PublicationUnknown(value.to_string());
        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedTransitionProof {
    /// The durable transition committed and the capability may be retired.
    Applied,
    /// The guarded CAS proved that this owner no longer holds the episode.
    LeaseLost,
    /// The database or commit outcome was not proven. No follow-up mutation is safe.
    Unknown,
}

/// Direct-dispatch result after the DB adapter has installed its opaque owned capability.
/// The terminal status is the durable DB value and must not be normalized or flattened.
#[derive(Debug)]
pub enum DispatchedClaimOutcome {
    Claimed {
        claim: Box<DeltaEventClaim>,
        event: Box<ClaimedDeltaEvent>,
    },
    AlreadyProcessed {
        event_id: String,
    },
    TerminalGated {
        event_id: String,
        status: String,
    },
    Busy {
        event_id: String,
    },
    InDoubt {
        event_id: String,
        reason: String,
    },
}

#[async_trait]
pub trait AuthorizationProjectorRuntime: Send + Sync + 'static {
    /// Record actual execution once per live episode.
    async fn begin_event_execution(
        &self,
        _identity: &DeltaLeaseIdentity,
    ) -> Result<u32, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.owned_execution_unsupported".to_owned(),
        )))
    }

    /// Authoritative failure budget; claim statistics must never substitute for it.
    fn event_execution_failures(&self, _identity: &DeltaLeaseIdentity) -> Option<u32> {
        None
    }

    /// Typed proof port for owned retry/defer transitions.
    async fn owned_fail_transition(
        &self,
        _identity: &DeltaLeaseIdentity,
        _backoff_seconds: i64,
        _message: &str,
        _count_failure: bool,
    ) -> OwnedTransitionProof {
        OwnedTransitionProof::Unknown
    }

    /// Typed proof port for relinquishing an owned episode.
    async fn owned_release_transition(
        &self,
        _identity: &DeltaLeaseIdentity,
    ) -> OwnedTransitionProof {
        OwnedTransitionProof::Unknown
    }

    /// Claim the next candidate using the owned aggregate capability protocol.
    async fn claim_next_event(
        &self,
        _scope: &DeltaEventClaimScope,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.owned_claim_unsupported".to_owned(),
        )))
    }

    /// Claim one exact commit-proven receipt using the owned capability protocol.
    async fn claim_event_by_dispatch(
        &self,
        _request: &DeltaEventAppendRequest,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<DispatchedClaimOutcome, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.owned_dispatch_unsupported".to_owned(),
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

    // ── Topology-only scheduling ports. WorkerOwned aggregate ownership is
    // acquired atomically with every claim; topology must not add a second
    // partition lease protocol.

    /// Discover claimable aggregate scopes within the validated tenant allowlist.
    async fn discover_partitions(
        &self,
        _tenants: &[i64],
        _limit: i64,
    ) -> Result<Vec<ProjectionAggregateIdentity>, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_discovery_unsupported".to_owned(),
        )))
    }

    /// Claim the next claimable event of ONE discovered aggregate using the
    /// same owned lane capability as TenantSerial scheduling.
    async fn claim_next_event_in_partition(
        &self,
        _identity: &ProjectionAggregateIdentity,
        _scope: &DeltaEventClaimScope,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.partition_claim_unsupported".to_owned(),
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
    owned: super::owned_runtime::OwnedCapabilities,
}

/// Watchdog diagnostics probe (F5 修复 1d): "does this tenant scope hold any
/// event the claim path could serve right now?" — same shape as the claim
/// candidate statements, INCLUDING the per-grant sibling-ordering gate (pinned
/// byte-equal to [`astral_db::OWNED_DELTA_CLAIM_SIBLING_ORDER_GATE`] by
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
        Self {
            pool,
            owned: super::owned_runtime::OwnedCapabilities::default(),
        }
    }

    async fn owned_claim_reservation(
        &self,
    ) -> Result<super::owned_runtime::OwnedCapabilityReservation, RuntimeAccessError> {
        self.owned.reconcile_expired(&self.pool).await;
        self.owned.reserve()
    }

    async fn finish_owned_event(
        &self,
        identity: &DeltaLeaseIdentity,
        backoff_seconds: i64,
        message: &str,
        count_failure: bool,
    ) -> OwnedTransitionProof {
        let lease = match self.owned.get(identity) {
            Ok(lease) => lease,
            Err(error) => {
                tracing::warn!(event_id = %identity.event_id, %error, "owned capability unavailable; no mutation");
                return OwnedTransitionProof::Unknown;
            }
        };
        match astral_db::fail_owned_delta_event(
            &self.pool,
            &lease,
            message,
            backoff_seconds,
            count_failure,
        )
        .await
        {
            Ok(true) => {
                self.owned.remove(identity);
                OwnedTransitionProof::Applied
            }
            Ok(false) => {
                tracing::warn!(event_id = %identity.event_id, "owned transition guard did not match; reconciliation required");
                OwnedTransitionProof::LeaseLost
            }
            Err(error) => {
                tracing::warn!(event_id = %identity.event_id, %error, "owned transition unknown; capability retained");
                OwnedTransitionProof::Unknown
            }
        }
    }

    async fn finish_owned_release(&self, identity: &DeltaLeaseIdentity) -> OwnedTransitionProof {
        let lease = match self.owned.get(identity) {
            Ok(lease) => lease,
            Err(error) => {
                tracing::warn!(event_id = %identity.event_id, %error, "owned capability unavailable; no release");
                return OwnedTransitionProof::Unknown;
            }
        };
        match astral_db::release_owned_delta_event(&self.pool, &lease).await {
            Ok(true) => {
                self.owned.remove(identity);
                OwnedTransitionProof::Applied
            }
            Ok(false) => {
                tracing::warn!(event_id = %identity.event_id, "owned release guard did not match; reconciliation required");
                OwnedTransitionProof::LeaseLost
            }
            Err(error) => {
                tracing::warn!(event_id = %identity.event_id, %error, "owned release unknown; capability retained");
                OwnedTransitionProof::Unknown
            }
        }
    }
}

#[async_trait]
impl AuthorizationProjectorRuntime for SqlxAuthorizationProjectorRuntime {
    async fn begin_event_execution(
        &self,
        identity: &DeltaLeaseIdentity,
    ) -> Result<u32, RuntimeAccessError> {
        let lease = self.owned.get(identity)?;
        Ok(astral_db::begin_owned_delta_execution(&self.pool, &lease).await?)
    }

    fn event_execution_failures(&self, identity: &DeltaLeaseIdentity) -> Option<u32> {
        self.owned
            .get(identity)
            .ok()
            .map(|lease| lease.execution_failures())
    }

    async fn owned_fail_transition(
        &self,
        identity: &DeltaLeaseIdentity,
        backoff_seconds: i64,
        message: &str,
        count_failure: bool,
    ) -> OwnedTransitionProof {
        self.finish_owned_event(identity, backoff_seconds, message, count_failure)
            .await
    }

    async fn owned_release_transition(
        &self,
        identity: &DeltaLeaseIdentity,
    ) -> OwnedTransitionProof {
        self.finish_owned_release(identity).await
    }

    async fn claim_event_by_dispatch(
        &self,
        request: &DeltaEventAppendRequest,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<DispatchedClaimOutcome, RuntimeAccessError> {
        let reservation = self.owned_claim_reservation().await?;
        let outcome = match astral_db::claim_owned_delta_event_by_stable_event(
            &self.pool,
            request,
            lease_owner,
            lease_seconds,
        )
        .await
        .map_err(RuntimeAccessError::from)
        {
            Ok(outcome) => outcome,
            Err(error) => {
                if matches!(&error, RuntimeAccessError::PublicationUnknown(_)) {
                    tracing::warn!(
                        event_id = %request.event_id,
                        operation_id = %request.operation_id,
                        "owned direct claim commit unknown; no release or replay"
                    );
                }
                return Err(error);
            }
        };
        match outcome {
            OwnedStableEventOutcome::Claimed(owned) => {
                let owned = *owned;
                if let Err(error) = self.owned.insert_reserved(reservation, owned.lease) {
                    tracing::error!(
                        event_id = %request.event_id,
                        operation_id = %request.operation_id,
                        %error,
                        "owned direct claim committed but capability registration is unknown; no release"
                    );
                    return Err(error);
                }
                Ok(DispatchedClaimOutcome::Claimed {
                    claim: Box::new(owned.claim),
                    event: Box::new(owned.event),
                })
            }
            OwnedStableEventOutcome::AlreadyProcessed { event_id } => {
                Ok(DispatchedClaimOutcome::AlreadyProcessed { event_id })
            }
            OwnedStableEventOutcome::Busy { event_id } => {
                Ok(DispatchedClaimOutcome::Busy { event_id })
            }
            OwnedStableEventOutcome::TerminalGated { event_id, status } => {
                Ok(DispatchedClaimOutcome::TerminalGated { event_id, status })
            }
            OwnedStableEventOutcome::InDoubt { event_id, reason } => {
                Ok(DispatchedClaimOutcome::InDoubt { event_id, reason })
            }
        }
    }

    async fn claim_next_event(
        &self,
        scope: &DeltaEventClaimScope,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        let reservation = self.owned_claim_reservation().await?;
        let owned =
            astral_db::claim_next_owned_delta_event(&self.pool, *scope, lease_owner, lease_seconds)
                .await
                .map_err(RuntimeAccessError::from)?;
        match owned {
            Some(owned) => {
                if let Err(error) = self.owned.insert_reserved(reservation, owned.lease) {
                    tracing::error!(
                        tenant_id = scope.tenant_id,
                        %error,
                        "owned polling claim committed but capability registration is unknown; no release"
                    );
                    Err(error)
                } else {
                    #[cfg(feature = "e3-observability")]
                    log_e3_attempt_event("claim_committed", &owned.claim, "leased", true, None);
                    Ok(Some(owned.claim))
                }
            }
            None => Ok(None),
        }
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

    async fn claim_next_event_in_partition(
        &self,
        identity: &ProjectionAggregateIdentity,
        scope: &DeltaEventClaimScope,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        let reservation = self.owned_claim_reservation().await?;
        let owned = astral_db::claim_next_owned_delta_event_in_partition(
            &self.pool,
            *scope,
            identity,
            lease_owner,
            lease_seconds,
        )
        .await
        .map_err(RuntimeAccessError::from)?;
        match owned {
            Some(owned) => {
                if let Err(error) = self.owned.insert_reserved(reservation, owned.lease) {
                    tracing::error!(
                        tenant_id = identity.tenant_id,
                        aggregate_type = %identity.aggregate_type,
                        aggregate_id = identity.aggregate_id,
                        %error,
                        "owned partition claim committed but capability registration is unknown; no release"
                    );
                    Err(error)
                } else {
                    #[cfg(feature = "e3-observability")]
                    log_e3_attempt_event("claim_committed", &owned.claim, "leased", true, None);
                    Ok(Some(owned.claim))
                }
            }
            None => Ok(None),
        }
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
        let lease = self.owned.get(identity)?;
        Ok(astral_db::load_owned_claimed_delta_event(&self.pool, &lease).await?)
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
        // The separate bounded renewal transaction refreshes both worker-owned
        // fences before the publication transaction checks their live expiry.
        let lease = self.owned.get(&command.delta_lease_identity)?;
        if !astral_db::extend_owned_delta_execution_lease(&self.pool, &lease, CLAIM_LEASE_SECS)
            .await?
        {
            return Err(RuntimeAccessError::Repository(RepositoryRejection::Grant(
                astral_db::GrantRepositoryError::LeaseCasFailed(
                    "code=projection_execution.publish_lease_renewal_lost".to_owned(),
                ),
            )));
        }
        let mut tx = self.pool.begin().await?;
        let outcome =
            astral_db::project_owned_authorization_delta_in_tx(&mut tx, command, &lease).await?;
        tx.commit().await.map_err(|error| {
            RuntimeAccessError::PublicationUnknown(format!(
                "code=auth_projector.publish_commit_unknown;event={};error={error}",
                command.expectation.event_id
            ))
        })?;
        self.owned.remove(&command.delta_lease_identity);
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
        Ok(outcome)
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
        let capability = self.owned.get(lease)?;
        let result = match astral_db::quarantine_owned_delta_event(
            &self.pool,
            &capability,
            reason_code,
            Some(reason_detail),
        )
        .await
        {
            Ok(true) => {
                self.owned.remove(lease);
                Ok(())
            }
            Ok(false) => Err(RuntimeAccessError::PublicationUnknown(
                "code=auth_projector.owned_quarantine_not_proven".to_owned(),
            )),
            Err(error) => Err(RuntimeAccessError::from(error)),
        };
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
