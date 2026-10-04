use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use super::worker::{
    budget_exhausted_error, clamp_backoff, event_backoff_secs, fail_with_budget,
    plan_retry_schedule, quarantine_event_terminal, quarantine_reason_parts, run_partition_worker,
    DispositionKind, RetrySchedule, ATTEMPT_BUDGET_EXHAUSTED_CODE,
};
use super::*;
use astral_db::{
    decode_ledger_row, hot_state_from_entries, AuthorizationCurrentPointerRecord,
    AuthorizationImpactItemType, AuthorizationProjectionError, ClaimedDeltaEvent, DeltaEventClaim,
    DeltaEventClaimScope, DeltaLeaseIdentity, DeltaProjectorPublishCommand,
    DeltaProjectorPublishOutcome, GrantLedgerEntry, ParentReferenceView, PartitionLeaseHandle,
    PartitionedGrantLedgerAtFrontier, ProjectionAggregateIdentity, PublishedAggregateFrontier,
    RawLedgerRow, Sha256Digest, StagedSegmentContent, MAX_BACKOFF_SECONDS, MAX_DELTA_LEASE_SECONDS,
    SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE,
};
use astral_types::{
    BindingLayer, DependencyVector, DependencyVersion, GrantEffect, GrantId, GrantProvenance,
    GrantRevision, GrantSourceKind, GrantState, TenantScope, ValidityWindow,
};
use async_trait::async_trait;
use policy_engine::HotState;
use sha2::{Digest, Sha256};

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// ── Partitioned scheduling (Phase 1) typed contracts ─────────────────────

type PartitionJournal = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

/// Minimal partition-mode runtime: claims always return `None`, so the
/// per-event processing path stays unreachable; the contracts under test
/// are discovery fairness, lease exclusivity (Busy), lost-lease abort, and
/// release discipline.
struct PartitionSchedulingFake {
    journal: PartitionJournal,
    partitions: Vec<ProjectionAggregateIdentity>,
    busy: Vec<(i64, String, i64)>,
    lose_renewal_on: Vec<i64>,
    fail_first_discovery: bool,
    discovery_calls: std::sync::atomic::AtomicUsize,
}

impl PartitionSchedulingFake {
    fn journal(&self) -> Vec<String> {
        self.journal.lock().unwrap().clone()
    }

    fn note(&self, entry: String) {
        self.journal.lock().unwrap().push(entry);
    }

    fn key(tenant: i64, kind: &str, id: i64) -> String {
        format!("{tenant}:{kind}:{id}")
    }
}

#[async_trait::async_trait]
impl AuthorizationProjectorRuntime for PartitionSchedulingFake {
    async fn claim_next_event(
        &self,
        _scope: &DeltaEventClaimScope,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        unreachable!("tenant-serial claim is not exercised by partition scheduling tests")
    }

    async fn read_claimed_event(
        &self,
        _identity: &DeltaLeaseIdentity,
    ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
        unreachable!("no event is ever claimed by the partition scheduling fake")
    }

    async fn observe_publication_context(
        &self,
        _identity: &ProjectionAggregateIdentity,
    ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
        unreachable!("no event is ever claimed by the partition scheduling fake")
    }

    async fn load_scope_ledger(
        &self,
        _tenant_id: i64,
        _aggregate_type: &str,
        _aggregate_id: i64,
        _card_id: Option<i64>,
    ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
        unreachable!("no event is ever claimed by the partition scheduling fake")
    }

    async fn execute_projection_publish(
        &self,
        _command: &DeltaProjectorPublishCommand,
    ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
        unreachable!("no event is ever claimed by the partition scheduling fake")
    }

    async fn fail_event(
        &self,
        _identity: &DeltaLeaseIdentity,
        _backoff_seconds: i64,
        _message: &str,
    ) {
        unreachable!("no event is ever claimed by the partition scheduling fake")
    }

    async fn release_event(&self, _identity: &DeltaLeaseIdentity) {
        unreachable!("no event is ever claimed by the partition scheduling fake")
    }

    async fn mark_event_quarantined(
        &self,
        _lease: &DeltaLeaseIdentity,
        _reason_code: &str,
        _reason_detail: &str,
    ) -> Result<(), RuntimeAccessError> {
        unreachable!("no event is ever claimed by the partition scheduling fake")
    }

    async fn discover_partitions(
        &self,
        _tenants: &[i64],
        _limit: i64,
    ) -> Result<Vec<ProjectionAggregateIdentity>, RuntimeAccessError> {
        self.note("discover".to_owned());
        if self.fail_first_discovery
            && self
                .discovery_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
        {
            return Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
                "code=test.discovery_unavailable".to_owned(),
            )));
        }
        Ok(self.partitions.clone())
    }

    async fn acquire_partition_lease(
        &self,
        identity: &ProjectionAggregateIdentity,
        lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<PartitionLeaseHandle>, RuntimeAccessError> {
        let key = Self::key(
            identity.tenant_id,
            &identity.aggregate_type,
            identity.aggregate_id,
        );
        if self.busy.iter().any(|(tenant, kind, id)| {
            *tenant == identity.tenant_id
                && kind == &identity.aggregate_type
                && *id == identity.aggregate_id
        }) {
            self.note(format!("busy:{key}"));
            return Ok(None);
        }
        self.note(format!("acquire:{key}"));
        Ok(Some(PartitionLeaseHandle {
            identity: identity.clone(),
            lease_owner: lease_owner.to_owned(),
            token: astral_db::DeltaLeaseToken::new_run_scoped(),
        }))
    }

    async fn renew_partition_lease(
        &self,
        handle: &PartitionLeaseHandle,
        _lease_seconds: i64,
    ) -> Result<(), RuntimeAccessError> {
        let key = Self::key(
            handle.identity.tenant_id,
            &handle.identity.aggregate_type,
            handle.identity.aggregate_id,
        );
        if self.lose_renewal_on.contains(&handle.identity.aggregate_id) {
            self.note(format!("renew_lost:{key}"));
            return Err(RuntimeAccessError::Repository(RepositoryRejection::Other(
                "code=test.partition_lease_lost".to_owned(),
            )));
        }
        self.note(format!("renew:{key}"));
        Ok(())
    }

    async fn release_partition_lease(
        &self,
        handle: &PartitionLeaseHandle,
    ) -> Result<(), RuntimeAccessError> {
        self.note(format!(
            "release:{}",
            Self::key(
                handle.identity.tenant_id,
                &handle.identity.aggregate_type,
                handle.identity.aggregate_id,
            )
        ));
        Ok(())
    }

    async fn claim_next_event_in_partition(
        &self,
        identity: &ProjectionAggregateIdentity,
        _scope: &DeltaEventClaimScope,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        self.note(format!(
            "claim:{}",
            Self::key(
                identity.tenant_id,
                &identity.aggregate_type,
                identity.aggregate_id,
            )
        ));
        Ok(None)
    }
}

fn partition_config() -> AuthorizationProjectorConfig {
    AuthorizationProjectorConfig {
        tenants: vec![1],
        poll_interval_secs: 1,
        scheduling_mode: ProjectorSchedulingMode::Partitioned,
        ..Default::default()
    }
}

async fn run_partition_worker_until(
    fake: std::sync::Arc<PartitionSchedulingFake>,
    marker: &str,
    config: AuthorizationProjectorConfig,
) {
    let runtime: std::sync::Arc<dyn AuthorizationProjectorRuntime> = fake.clone();
    let cancellation = ProjectorCancellationToken::default();
    let progress = Arc::new(ProjectorProgress::default());
    let task = tokio::spawn(run_partition_worker(
        runtime,
        config,
        "partition-owner".to_owned(),
        cancellation.clone(),
        progress,
    ));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if fake.journal().iter().any(|entry| entry.contains(marker)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    cancellation.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
}

fn partition_identity(id: i64) -> ProjectionAggregateIdentity {
    ProjectionAggregateIdentity::new(1, "CARD", id).expect("valid partition identity")
}

#[tokio::test]
async fn partition_worker_drains_discovered_partitions_in_order_and_releases() {
    let fake = std::sync::Arc::new(PartitionSchedulingFake {
        journal: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        partitions: vec![partition_identity(1), partition_identity(2)],
        busy: Vec::new(),
        lose_renewal_on: Vec::new(),
        fail_first_discovery: false,
        discovery_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    run_partition_worker_until(fake.clone(), "release:1:CARD:2", partition_config()).await;
    let journal = fake.journal();
    // 公平序：发现 → 按 oldest_due 序逐分区 acquire/renew/claim(None)/release。
    let expected_prefix = [
        "discover".to_owned(),
        "acquire:1:CARD:1".to_owned(),
        "renew:1:CARD:1".to_owned(),
        "claim:1:CARD:1".to_owned(),
        "release:1:CARD:1".to_owned(),
        "acquire:1:CARD:2".to_owned(),
        "renew:1:CARD:2".to_owned(),
        "claim:1:CARD:2".to_owned(),
        "release:1:CARD:2".to_owned(),
    ];
    assert!(
        journal.len() >= expected_prefix.len(),
        "journal too short: {journal:?}"
    );
    assert_eq!(journal[..expected_prefix.len()], expected_prefix[..]);
}

#[tokio::test]
async fn partition_worker_skips_busy_partitions_without_waiting() {
    let fake = std::sync::Arc::new(PartitionSchedulingFake {
        journal: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        partitions: vec![partition_identity(1), partition_identity(2)],
        busy: vec![(1, "CARD".to_owned(), 1)],
        lose_renewal_on: Vec::new(),
        fail_first_discovery: false,
        discovery_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    run_partition_worker_until(fake.clone(), "release:1:CARD:2", partition_config()).await;
    let journal = fake.journal();
    assert!(journal.contains(&"busy:1:CARD:1".to_owned()));
    // Busy 分区绝不 renew/claim/release：拿不到租约就跳过，绝不等待。
    assert!(!journal.iter().any(|entry| entry.contains("renew:1:CARD:1")));
    assert!(!journal.iter().any(|entry| entry.contains("claim:1:CARD:1")));
    assert!(!journal
        .iter()
        .any(|entry| entry.contains("release:1:CARD:1")));
    assert!(journal.contains(&"release:1:CARD:2".to_owned()));
}

#[tokio::test]
async fn partition_worker_stops_touching_a_partition_when_the_lease_is_lost() {
    let fake = std::sync::Arc::new(PartitionSchedulingFake {
        journal: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        partitions: vec![partition_identity(1)],
        busy: Vec::new(),
        lose_renewal_on: vec![1],
        fail_first_discovery: false,
        discovery_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    run_partition_worker_until(fake.clone(), "release:1:CARD:1", partition_config()).await;
    let journal = fake.journal();
    // 续租失败 = 分区已被接管：立即弃置（release 仍尽力执行），绝不 claim。
    assert!(journal.contains(&"renew_lost:1:CARD:1".to_owned()));
    assert!(journal.contains(&"release:1:CARD:1".to_owned()));
    assert!(!journal.iter().any(|entry| entry.contains("claim:1:CARD:1")));
}

#[tokio::test]
async fn partition_worker_survives_transient_discovery_failures() {
    let fake = std::sync::Arc::new(PartitionSchedulingFake {
        journal: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        partitions: vec![partition_identity(1)],
        busy: Vec::new(),
        lose_renewal_on: Vec::new(),
        fail_first_discovery: true,
        discovery_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    run_partition_worker_until(fake.clone(), "acquire:1:CARD:1", partition_config()).await;
    let journal = fake.journal();
    // 瞬态失败：第一轮 discovery 失败只跳过本轮，第二轮照常调度。
    let discovers = journal
        .iter()
        .filter(|entry| entry.as_str() == "discover")
        .count();
    assert!(
        discovers >= 2,
        "expected a retried discovery round: {journal:?}"
    );
    assert!(journal.contains(&"acquire:1:CARD:1".to_owned()));
}

#[test]
fn partitioned_scheduling_defaults_to_tenant_serial_until_accepted() {
    let config = AuthorizationProjectorConfig::default();
    assert_eq!(
        config.scheduling_mode,
        ProjectorSchedulingMode::TenantSerial,
        "default-off discipline: partitioned mode must be explicitly opted in"
    );
    assert_eq!(config.worker_count, DEFAULT_PARTITION_WORKER_COUNT);
}

#[test]
fn scheduling_mode_and_worker_count_parsers_fail_fast() {
    assert_eq!(
        parse_projector_scheduling_mode("").unwrap(),
        ProjectorSchedulingMode::TenantSerial
    );
    assert_eq!(
        parse_projector_scheduling_mode("partitioned").unwrap(),
        ProjectorSchedulingMode::Partitioned
    );
    assert!(parse_projector_scheduling_mode("bogus")
        .unwrap_err()
        .contains("invalid_scheduling_mode"));

    assert_eq!(parse_projector_worker_count("").unwrap(), 4);
    assert_eq!(parse_projector_worker_count("4").unwrap(), 4);
    assert!(parse_projector_worker_count("0")
        .unwrap_err()
        .contains("worker_count"));
    assert!(parse_projector_worker_count("33")
        .unwrap_err()
        .contains("worker_count"));
    assert!(parse_projector_worker_count("x")
        .unwrap_err()
        .contains("invalid_worker_count"));
}

#[test]
fn partition_worker_budget_guard_rejects_pool_overflow() {
    assert!(validate_partition_worker_budget(4, 100).is_ok());
    assert!(validate_partition_worker_budget(32, 100).is_ok());
    assert!(validate_partition_worker_budget(0, 100)
        .unwrap_err()
        .contains("worker_count_out_of_bounds"));
    assert!(validate_partition_worker_budget(33, 100)
        .unwrap_err()
        .contains("worker_count_out_of_bounds"));
    // 30 workers × 2 connections > 50 pool budget (within the count bound).
    assert!(validate_partition_worker_budget(30, 50)
        .unwrap_err()
        .contains("worker_count_exceeds_pool_budget"));
}

const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// Production code drives WorkerRunSummary.record directly; the disposition
// → counter mapping stays unit-test-visible only. This impl deliberately
// lives INSIDE the test module so the production source contains exactly
// one `#[cfg(test)]` marker — the section boundary every source-shape scan
// cuts at.
impl EventDisposition {
    fn kind(&self) -> DispositionKind {
        match self {
            Self::Publish(_) => DispositionKind::Published,
            Self::Retry { .. } => DispositionKind::ReleasedRetry,
            Self::Quarantine { .. } => DispositionKind::Quarantined,
            Self::Blocked { .. } => DispositionKind::Blocked,
            Self::Superseded { .. } => DispositionKind::SupersededRelease,
        }
    }
}

// ── Fixtures mirroring the shared contract test grants ───────────────────

fn tenant_of(card: i64) -> TenantScope {
    TenantScope::new(7, Some(card)).unwrap()
}

fn grant(unique_tail: u16, revision: u64, state: GrantState) -> astral_types::CanonicalGrant {
    astral_types::CanonicalGrant {
        grant_id: GrantId::parse(&format!(
            "550e8400-e29b-41d4-a716-44665544{unique_tail:04x}"
        ))
        .unwrap(),
        revision: GrantRevision::new(revision).unwrap(),
        state,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: tenant_of(17),
        card_id: 17,
        user_id: 42,
        resource: "learn_subject:1".to_owned(),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: "rule-set-entry-9".to_owned(),
            source_entry: None,
            binding_id: Some("binding-3".to_owned()),
            delegation_id: None,
            operation_id: "op-1".to_owned(),
            event_id: Some("event-1".to_owned()),
            actor_user_id: Some(42),
        },
    }
}

fn raw_row(
    grant: &astral_types::CanonicalGrant,
    event: &str,
    op: &str,
    revoke_fence: u64,
) -> RawLedgerRow {
    let payload = serde_json::to_string(grant).unwrap();
    let semantic = grant.canonical_hash().unwrap();
    // The revision's dependency hash follows the same producer
    // reconstruction the projector performs, pinned to one CARD batch.
    let dep_hash = active_card_dependency_hash(5, revoke_fence).1;
    RawLedgerRow {
        revision_no: grant.revision.value() as i64,
        tenant_id: grant.tenant.tenant_id,
        card_id: Some(grant.card_id),
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 17,
        grant_id: grant.grant_id.as_str().to_owned(),
        status: "ACTIVE".to_owned(),
        is_tombstone: i8::from(matches!(
            grant.state,
            GrantState::Removed | GrantState::Revoked
        )),
        grant_payload: payload,
        semantic_hash: {
            let digest = Sha256Digest::from_hex(&semantic).unwrap();
            digest.as_bytes().to_vec()
        },
        dependency_hash: {
            let digest = Sha256Digest::from_hex(&dep_hash).unwrap();
            digest.as_bytes().to_vec()
        },
        operation_id: op.to_owned(),
        event_id: event.to_owned(),
        // fixture 版本必须与本地 AuthorizationCompiler 一致（prepare_compile_inputs
        // 强制 producer/consumer 同版本），引用导出常量避免 bump 时漂移。
        compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
    }
}

// ── Policy helpers ───────────────────────────────────────────────────────

#[test]
fn backoff_policy_is_bounded_and_exponential() {
    assert_eq!(event_backoff_secs(1), 1);
    assert_eq!(event_backoff_secs(2), 2);
    assert_eq!(event_backoff_secs(3), 4);
    assert_eq!(event_backoff_secs(4), 8);
    // Attempt budget exhaustion switches to the capped maximum.
    assert_eq!(
        event_backoff_secs(MAX_EVENT_ATTEMPTS),
        clamp_backoff(BACKOFF_CAP_SECS)
    );
    assert_eq!(event_backoff_secs(50), clamp_backoff(BACKOFF_CAP_SECS));
    assert!(clamp_backoff(i64::MAX) <= MAX_BACKOFF_SECONDS);
}

#[test]
fn worker_constants_respect_repository_limits() {
    const _: () = {
        assert!(CLAIM_LEASE_SECS <= MAX_DELTA_LEASE_SECONDS);
        assert!(BACKOFF_CAP_SECS <= MAX_BACKOFF_SECONDS);
        // MAX_MANIFEST_LEASE_SECONDS.min(600) is a stable bound by
        // construction; the runtime comparison stays in `Default`.
    };
    assert_eq!(
        event_backoff_secs(MAX_EVENT_ATTEMPTS),
        clamp_backoff(BACKOFF_CAP_SECS)
    );
    assert_eq!(MAX_EVENT_ATTEMPTS, 5);
}

#[test]
fn unified_retry_budget_pins_attempt_boundaries_one_through_five() {
    // In-budget attempts 1..=4 follow the pinned exponential ladder.
    assert_eq!(
        plan_retry_schedule(1, 0),
        RetrySchedule::Continue { backoff_secs: 1 }
    );
    assert_eq!(
        plan_retry_schedule(2, 0),
        RetrySchedule::Continue { backoff_secs: 2 }
    );
    assert_eq!(
        plan_retry_schedule(3, 0),
        RetrySchedule::Continue { backoff_secs: 4 }
    );
    assert_eq!(
        plan_retry_schedule(4, 0),
        RetrySchedule::Continue { backoff_secs: 8 }
    );
    // Strict monotonicity across the whole in-budget ladder.
    let ladder = [1i64, 2, 3, 4].map(|attempt| match plan_retry_schedule(attempt, 0) {
        RetrySchedule::Continue { backoff_secs } => backoff_secs,
        other => panic!("attempt {attempt} must stay in budget, got {other:?}"),
    });
    assert!(ladder.windows(2).all(|pair| pair[0] < pair[1]));

    // Fifth-failure onward: exhausted. A hypothetical sixth claim can only
    // arrive after a full cap delay and can NEVER short-backoff again.
    let exhausted_backoff = |attempts: i64| -> i64 {
        match plan_retry_schedule(attempts, 0) {
            RetrySchedule::AttemptBudgetExhausted { backoff_secs } => backoff_secs,
            other => panic!("attempt {attempts} must be exhausted, got {other:?}"),
        }
    };
    let cap = clamp_backoff(BACKOFF_CAP_SECS);
    assert_eq!(exhausted_backoff(MAX_EVENT_ATTEMPTS), cap);
    assert_eq!(exhausted_backoff(MAX_EVENT_ATTEMPTS + 1), cap);
    assert_eq!(exhausted_backoff(i64::MAX), cap);
    assert!(cap > 8, "cap must dominate every short step");

    // Defensive floors: zero/negative attempts degrade to attempt 1.
    assert_eq!(
        plan_retry_schedule(0, 0),
        RetrySchedule::Continue { backoff_secs: 1 }
    );
    assert_eq!(
        plan_retry_schedule(-7, 0),
        RetrySchedule::Continue { backoff_secs: 1 }
    );
}

#[test]
fn unified_retry_budget_accepts_long_backoffs_only_within_budget() {
    let long_request = clamp_backoff(MAX_BACKOFF_SECONDS);
    // ImmutableDivergence-grade paths may demand the maximal long cool-down
    // while the budget lasts…
    assert_eq!(
        plan_retry_schedule(1, long_request),
        RetrySchedule::Continue {
            backoff_secs: long_request
        }
    );
    // …but the request can never rescue an exhausted budget: the exhausted
    // disposition wins with its capped backoff.
    assert_eq!(
        plan_retry_schedule(5, long_request),
        RetrySchedule::AttemptBudgetExhausted {
            backoff_secs: clamp_backoff(BACKOFF_CAP_SECS)
        }
    );
}

#[test]
fn attempt_budget_exhausted_marker_is_stable_for_operators() {
    assert_eq!(
        ATTEMPT_BUDGET_EXHAUSTED_CODE,
        "code=auth_projector.attempt_budget_exhausted"
    );
}

#[test]
fn budget_exhaustion_marker_survives_repository_error_truncation() {
    for reason in ["x".repeat(2_048), "数据库错误".repeat(512)] {
        let marked = budget_exhausted_error(&reason, MAX_EVENT_ATTEMPTS);
        let stored: String = marked
            .chars()
            .take(astral_db::MAX_LAST_ERROR_LENGTH)
            .collect();
        assert!(stored.starts_with(ATTEMPT_BUDGET_EXHAUSTED_CODE));
        assert!(stored.contains(&format!("attempts={MAX_EVENT_ATTEMPTS}")));
    }
}

#[test]
fn tenant_scope_parser_is_fail_fast_and_order_preserving() {
    // Empty env / whitespace-only ⇒ empty consumer set (idle warn upstream).
    assert_eq!(parse_projector_tenants("").unwrap(), Vec::<i64>::new());
    assert_eq!(
        parse_projector_tenants("   \t ").unwrap(),
        Vec::<i64>::new()
    );
    // Whitespace-tolerant, order-preserving dedupe of repeats.
    assert_eq!(parse_projector_tenants("7, 9 ,3").unwrap(), vec![7, 9, 3]);
    assert_eq!(parse_projector_tenants("7,7,7").unwrap(), vec![7]);

    let bad_inputs = [
        ",",                   // empty token pair
        "7,,9",                // interior empty token
        "7,",                  // trailing separator leaves an empty token
        ",7",                  // leading separator
        "7,abc",               // non-numeric token
        "7,-3",                // negative id
        "0",                   // zero id
        "9223372036854775808", // out-of-range (i64 overflow)
        "7,9,oops",            // mixed valid + garbage must poison all
    ];
    for raw in bad_inputs {
        let parsed = parse_projector_tenants(raw);
        assert!(parsed.is_err(), "{raw:?} must fail startup parsing");
        let message = parsed.unwrap_err();
        assert!(
            message.starts_with("code=config."),
            "{raw:?} must surface a stable error code, got: {message}"
        );
    }
}

// ── Dependency vector reconstruction ────────────────────────────────────

#[test]
fn dependency_vector_matches_producer_shape_and_hashes() {
    let (vector, hash) =
        reconstruct_dependency_vector(Some(17), 5, 1).expect("scoped card must rebuild");
    let expected =
        DependencyVector::new(vec![DependencyVersion::new("card:17", 5, 1).unwrap()]).unwrap();
    assert_eq!(vector, expected);
    assert_eq!(hash, expected.canonical_hash().unwrap());

    assert!(reconstruct_dependency_vector(None, 5, 1)
        .unwrap_err()
        .contains("card_scoped_dependency_required"));
}

// ── Segment planning ─────────────────────────────────────────────────────

fn parent_view(ordinal: u64, digest_hex: &str) -> (u64, ParentReferenceView) {
    (
        ordinal,
        ParentReferenceView {
            ordinal,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
            segment_id: 100 + ordinal as i64,
            content_digest_hex: digest_hex.to_owned(),
        },
    )
}

#[tokio::test]
async fn stage_planning_defaults_to_all_new_without_parent_references() {
    let state = HotState::from_grants(
        tenant_of(17),
        3,
        vec![
            grant(1, 1, GrantState::Active),
            grant(2, 1, GrantState::Active),
        ],
        DependencyVector::default(),
    )
    .unwrap();
    let plan = plan_stage_segments(&state, None).unwrap();
    assert_eq!(plan.len(), state.segments.len());
    assert!(plan
        .iter()
        .all(|entry| matches!(entry, StagedSegmentContent::New(_))));
}

#[tokio::test]
async fn stage_planning_reuses_only_exact_content_matched_unused_ordinals() {
    let changed = grant(1, 2, GrantState::Active);
    let unchanged = grant(2, 1, GrantState::Active);
    let candidate = HotState::from_grants(
        tenant_of(17),
        4,
        vec![changed, unchanged.clone()],
        DependencyVector::default(),
    )
    .unwrap();

    let payload_a =
        astral_db::encode_segment_payload(&candidate.segments.iter().next().unwrap().1.grants)
            .unwrap();
    let other_digest = hex_lower(&Sha256::digest(b"unrelated"));

    let references = vec![
        parent_view(0, &other_digest),
        parent_view(1, &hex_lower(&Sha256::digest(&payload_a))),
    ];
    let plan = plan_stage_segments(&candidate, Some(&references)).unwrap();
    // Only the segment whose digest matches an unused parent ordinal is
    // reused; everything else stays New.
    let reused: Vec<&StagedSegmentContent> = plan
        .iter()
        .filter(|entry| matches!(entry, StagedSegmentContent::ReuseParent { .. }))
        .collect();
    assert_eq!(reused.len(), 1);

    // Duplicate ordinal claims collapse: two candidate segments with equal
    // content share one parent row, so the second must fall back to New.
    let twin_state = HotState::from_grants(
        tenant_of(17),
        5,
        vec![unchanged.clone()],
        DependencyVector::default(),
    )
    .unwrap();
    let twin_payload =
        astral_db::encode_segment_payload(&twin_state.segments.iter().next().unwrap().1.grants)
            .unwrap();
    let shared_references = [parent_view(0, &hex_lower(&Sha256::digest(&payload_a)))];
    let _ = twin_payload;
    let duplicate_candidates = [parent_view(3, &other_digest)];
    // Foreign identity views must never be selected even if digests match.
    let foreign = ParentReferenceView {
        identity: ProjectionAggregateIdentity::new(9, "CARD", 88).unwrap(),
        ..parent_view(7, &hex_lower(&Sha256::digest(&payload_a))).1
    };
    let mixed = vec![
        shared_references[0].clone(),
        (foreign.ordinal, foreign),
        duplicate_candidates[0].clone(),
    ];
    let plan_foreign = plan_stage_segments(&candidate, Some(&mixed)).unwrap();
    assert!(plan_foreign.iter().all(|entry| matches!(
        entry,
        StagedSegmentContent::New(_) | StagedSegmentContent::ReuseParent { parent_ordinal: 0 }
    )));
}

fn legacy_stage_plan(
    candidate: &HotState,
    references: &[(u64, ParentReferenceView)],
) -> Vec<StagedSegmentContent> {
    let mut plan = Vec::new();
    for (_, segment) in candidate.segments.iter() {
        let payload = astral_db::encode_segment_payload(&segment.grants).unwrap();
        let digest = hex_lower(&Sha256::digest(&payload));
        let reused = references.iter().find_map(|(ordinal, view)| {
            if view.content_digest_hex == digest
                && !plan.iter().any(|entry| {
                    matches!(entry, StagedSegmentContent::ReuseParent { parent_ordinal } if parent_ordinal == ordinal)
                })
            {
                Some(*ordinal)
            } else {
                None
            }
        });
        plan.push(match reused {
            Some(parent_ordinal) => StagedSegmentContent::ReuseParent { parent_ordinal },
            None => StagedSegmentContent::New(segment.grants.clone()),
        });
    }
    plan
}

#[test]
fn stage_planning_matches_legacy_output_for_mixed_references() {
    for size in [1_u16, 8, 128, 512] {
        let grants: Vec<_> = (0..size)
            .map(|id| {
                let mut grant = grant(id, 1, GrantState::Active);
                grant.resource = format!("learn_subject:{id}");
                grant
            })
            .collect();
        let candidate =
            HotState::from_grants(tenant_of(17), 4, grants, DependencyVector::default()).unwrap();
        let mut references = vec![parent_view(
            99_999,
            &hex_lower(&Sha256::digest(b"unrelated")),
        )];
        for (index, (_, segment)) in candidate.segments.iter().enumerate() {
            let digest = hex_lower(&Sha256::digest(
                astral_db::encode_segment_payload(&segment.grants).unwrap(),
            ));
            let ordinal = (size as usize - index) as u64;
            references.push(parent_view(ordinal % 7, &digest));
            references.push(parent_view(ordinal % 7, &digest));
            references.push(parent_view(ordinal + 10, &digest));
        }
        references.reverse();
        assert_eq!(
            plan_stage_segments(&candidate, Some(&references)).unwrap(),
            legacy_stage_plan(&candidate, &references),
        );
    }
}

// ── Publish-failure taxonomy ─────────────────────────────────────────────

/// Typed construction helper: the projection rejection as the runtime seam
/// actually delivers it (variant preserved, never re-parsed from text).
fn projection_failure(error: AuthorizationProjectionError) -> RuntimeAccessError {
    RuntimeAccessError::Repository(RepositoryRejection::Projection(error))
}

#[test]
fn publish_failure_classification_routes_each_family() {
    let pointer_moved = [
        // Variant-classified: the pointer/manifest pair disagrees with the
        // claimed world.
        projection_failure(AuthorizationProjectionError::CurrentPointerCasConflict(
            "code=authorization_projection.previous_fence_not_authoritative;durable=3;evidence=2"
                .to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::IdentityMismatch(
            "code=authorization_projection.pointer_target_identity_mismatch".to_owned(),
        )),
        // Exact machine code inside ManifestPublishConflict.
        projection_failure(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_generation_gap;expected=5;actual=7".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_same_manifest".to_owned(),
        )),
        // Exact machine code inside NotReady / Mapping.
        projection_failure(AuthorizationProjectionError::NotReady(
            "code=authorization_projection.stage_generation_gap;expected=4;actual=5".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::NotReady(
            "code=authorization_projection.current_pointer_missing".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::Mapping(
            "code=authorization_projection.generation_overflow".to_owned(),
        )),
        // A pointer-generation race is a fresh-world replan even though
        // the repository exposes it through the generic scope variant.
        projection_failure(AuthorizationProjectionError::ScopeViolation(
            "code=authorization_projection.command_base_generation_mismatch;expected=4;actual=5"
                .to_owned(),
        )),
    ];
    for case in pointer_moved {
        assert!(
            matches!(
                classify_publish_failure(&case),
                PublishFailureHandling::PointerMoved { .. }
            ),
            "{case:?} must route to PointerMoved"
        );
    }

    let lease_lost = [
        projection_failure(AuthorizationProjectionError::LeaseCasFailed(
            "code=grant_repository.complete_lost_lease;event=e".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::LeaseCasFailed(
            "code=grant_repository.claimed_readback_not_leased;event=e".to_owned(),
        )),
        // Variant-classified: the old `ClaimRace` Display needle was dead.
        projection_failure(AuthorizationProjectionError::ClaimRace),
    ];
    for case in lease_lost {
        assert!(
            matches!(
                classify_publish_failure(&case),
                PublishFailureHandling::LeaseLost { .. }
            ),
            "{case:?} must route to LeaseLost"
        );
    }

    let immutable = [
        projection_failure(AuthorizationProjectionError::DuplicateRow(
            "code=authorization_projection.manifest_identity_conflict".to_owned(),
        )),
        // Variant-classified: the old `DuplicateRow` Display needle was
        // dead, so unproven unique-race winners silently retried before.
        projection_failure(AuthorizationProjectionError::DuplicateRow(
            "code=authorization_projection.segment_insert_not_applied".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::ImmutableConflict(
            "code=authorization_projection.replay_field_divergence;field=semantic_hash".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::Corrupt(
            "code=authorization_projection.parent_fence_split;manifest=1;pointer=2".to_owned(),
        )),
        // Collision codes OTHER than the compiler-stamp carve-out stay in
        // the corruption family.
        projection_failure(AuthorizationProjectionError::SegmentDigestCollision(
            "code=authorization_projection.cross_card_digest_collision".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::SegmentDigestCollision(
            "code=authorization_projection.digest_metadata_collision".to_owned(),
        )),
    ];
    for case in immutable {
        assert!(
            matches!(
                classify_publish_failure(&case),
                PublishFailureHandling::ImmutableDivergence { .. }
            ),
            "{case:?} must route to ImmutableDivergence"
        );
    }

    let generic = [
        RuntimeAccessError::Database("connection refused".to_owned()),
        // Projector-side non-typed refusal (grant errors now arrive typed
        // via RepositoryRejection::Grant — see the dedicated test below).
        RuntimeAccessError::Repository(RepositoryRejection::Other(
            "code=auth_projector.parent_snapshot_missing_for_live_pointer".to_owned(),
        )),
        RuntimeAccessError::Repository(RepositoryRejection::Grant(
            astral_db::GrantRepositoryError::Mapping(
                "code=grant_repository.claim_expiry_missing".to_owned(),
            ),
        )),
        projection_failure(AuthorizationProjectionError::NotReady(
            "code=authorization_projection.target_not_ready;status=BUILDING".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_target_semantic_mismatch".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::ScopeViolation(
            "authorization_projection.payload_size_overflow".to_owned(),
        )),
        projection_failure(AuthorizationProjectionError::Mapping(
            "code=authorization_projection.grant_ledger_conflict;conflict=revision".to_owned(),
        )),
    ];
    for case in generic {
        assert!(
            matches!(
                classify_publish_failure(&case),
                PublishFailureHandling::GenericRetry { .. }
            ),
            "{case:?} must route to GenericRetry"
        );
    }
}

#[test]
fn typed_grant_rejections_preserve_lease_loss_across_the_seam() {
    // M2: astral-db grant errors keep their variants across
    // `RepositoryRejection::Grant`, so a lost lease classifies as
    // LeaseLost/UNKNOWN by VARIANT — never by Display text — and can never
    // be misrouted into a `fail_delta_event` write after ownership died.
    let lease_lost = [
        RuntimeAccessError::from(astral_db::GrantRepositoryError::LeaseCasFailed(
            "code=grant_repository.heartbeat_lost_lease;event=e".to_owned(),
        )),
        RuntimeAccessError::from(astral_db::GrantRepositoryError::LeaseCasFailed(
            "code=grant_repository.complete_lost_lease;event=e".to_owned(),
        )),
        RuntimeAccessError::from(astral_db::GrantRepositoryError::LeaseCasFailed(
            "code=grant_repository.claimed_readback_not_leased;event=e".to_owned(),
        )),
        // Variant-classified: the claim race never had a Display needle.
        RuntimeAccessError::from(astral_db::GrantRepositoryError::ClaimRace),
    ];
    for case in lease_lost {
        assert!(
            matches!(
                classify_publish_failure(&case),
                PublishFailureHandling::LeaseLost { .. }
            ),
            "{case:?} must route to LeaseLost"
        );
    }

    // Every other typed grant refusal proves no deterministic divergence
    // and stays under the unified attempt budget.
    let generic = [
        RuntimeAccessError::from(astral_db::GrantRepositoryError::Mapping(
            "code=grant_repository.claim_expiry_missing".to_owned(),
        )),
        RuntimeAccessError::from(astral_db::GrantRepositoryError::ScopeViolation(
            "code=grant_repository.invalid_lease_seconds;value=0".to_owned(),
        )),
        RuntimeAccessError::from(astral_db::GrantRepositoryError::DuplicateDeltaEvent(
            "duplicate delta event: evt-x".to_owned(),
        )),
    ];
    for case in generic {
        assert!(
            matches!(
                classify_publish_failure(&case),
                PublishFailureHandling::GenericRetry { .. }
            ),
            "{case:?} must route to GenericRetry"
        );
    }
}

#[test]
fn backfill_or_rehearsal_required_blocks_instead_of_quarantining() {
    // astral-db refuses publication on unproven pointer-proof history via
    // `AuthorizationProjectionError::NotReady` carrying the stable machine
    // code `backfill_or_rehearsal_required` (validate_pointer_proof_state);
    // the exact LEADING token routes to Blocked, never to terminal
    // quarantine.
    let error = projection_failure(AuthorizationProjectionError::NotReady(
            "code=authorization_projection.backfill_or_rehearsal_required;pointer_proof_unproven;pointer_fence=0"
                .to_owned(),
        ));
    let PublishFailureHandling::Blocked { reason } = classify_publish_failure(&error) else {
        panic!("unproven pointer history must block, never quarantine");
    };
    // The full evidence (including the pointer-proof detail) survives into
    // the durable failure text handed to the retry funnel.
    assert!(reason.contains("backfill_or_rehearsal_required"));
    assert!(reason.contains("pointer_proof_unproven"));

    // Exact-token discipline inside the NotReady arm: the same token in
    // the DETAIL of another code must NOT flip to Blocked — only the
    // leading token decides, and an unknown code keeps the bounded-retry
    // default.
    let detail_flip = projection_failure(AuthorizationProjectionError::NotReady(
        "code=authorization_projection.parent_fence_split;hint=backfill_or_rehearsal_required"
            .to_owned(),
    ));
    assert!(matches!(
        classify_publish_failure(&detail_flip),
        PublishFailureHandling::GenericRetry { .. }
    ));

    // Corruption quarantine retained: the same token in the detail of a
    // CORRUPT refusal (e.g. the real `parent_fence_split` emission) stays
    // terminal divergence — unproven-history wording never downgrades
    // proven corruption into a blocked retry.
    let corrupt = projection_failure(AuthorizationProjectionError::Corrupt(
        "code=authorization_projection.parent_fence_split;hint=backfill_or_rehearsal_required"
            .to_owned(),
    ));
    assert!(matches!(
        classify_publish_failure(&corrupt),
        PublishFailureHandling::ImmutableDivergence { .. }
    ));
}

#[test]
fn blocked_history_ladder_stays_on_bounded_budget_never_hot_loops() {
    // A permanently-blocked event is reclaimed once per scheduled retry;
    // every reclaim increments the durable `attempts` and every failure
    // schedules the next attempt through [`plan_retry_schedule`]. The
    // ladder must be strictly positive and growing, then pin the event
    // under the maximal cap backoff once the budget is exhausted — never a
    // zero-second hot loop and never a terminal quarantine.
    let mut previous: i64 = 0;
    for attempts in 1..MAX_EVENT_ATTEMPTS {
        match plan_retry_schedule(attempts, 0) {
            RetrySchedule::Continue { backoff_secs } => {
                assert!(backoff_secs >= 1, "no zero-second hot loop");
                assert!(backoff_secs > previous, "ladder must grow at {attempts}");
                previous = backoff_secs;
            }
            other => panic!("attempt {attempts} must stay in budget, got {other:?}"),
        }
    }
    let cap = clamp_backoff(BACKOFF_CAP_SECS);
    for attempts in [
        MAX_EVENT_ATTEMPTS,
        MAX_EVENT_ATTEMPTS + 1,
        MAX_EVENT_ATTEMPTS * 10,
    ] {
        match plan_retry_schedule(attempts, 0) {
            RetrySchedule::AttemptBudgetExhausted { backoff_secs } => {
                assert_eq!(backoff_secs, cap);
                assert!(backoff_secs > previous, "cap dominates the ladder");
            }
            other => panic!("attempt {attempts} must be exhausted, got {other:?}"),
        }
    }
    // The exhaustion marker stays machine-stable for operators.
    let marked = format!("reason;{ATTEMPT_BUDGET_EXHAUSTED_CODE};attempts={MAX_EVENT_ATTEMPTS}");
    assert!(marked.contains(ATTEMPT_BUDGET_EXHAUSTED_CODE));
}

#[test]
fn compiler_stamp_divergence_routes_to_dedicated_quarantine_path() {
    let error = projection_failure(AuthorizationProjectionError::SegmentDigestCollision(
        SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE.to_owned(),
    ));
    let PublishFailureHandling::CompilerStampDivergence { reason } =
        classify_publish_failure(&error)
    else {
        panic!("compiler stamp divergence must take the dedicated path");
    };
    // The durable quarantine reason decomposes into a dedicated, short
    // machine-stable code plus the full evidence as detail.
    let (code, detail) = quarantine_reason_parts(&reason);
    assert_eq!(code, "auth_projector.compiler_stamp_divergence");
    assert!(detail.contains(SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE));
}

#[test]
fn publish_classification_never_scans_dynamic_detail_tokens() {
    // The exact-token router only ever reads the FIRST machine code, so a
    // foreign token inside free-form detail can no longer flip a
    // disposition the way the previous substring matching could.
    let detail_flip = projection_failure(AuthorizationProjectionError::Mapping(
        "code=authorization_projection.grant_ledger_conflict;conflict=generation_overflow"
            .to_owned(),
    ));
    assert!(matches!(
        classify_publish_failure(&detail_flip),
        PublishFailureHandling::GenericRetry { .. }
    ));
    let detail_flip_conflict = projection_failure(
            AuthorizationProjectionError::ManifestPublishConflict(
                "code=authorization_projection.publish_target_compiler_mismatch;detail=manifest_identity_conflict"
                    .to_owned(),
            ),
        );
    assert!(matches!(
        classify_publish_failure(&detail_flip_conflict),
        PublishFailureHandling::GenericRetry { .. }
    ));
    // The leading token itself still decides, whatever follows it.
    let leading_gap = projection_failure(AuthorizationProjectionError::ManifestPublishConflict(
            "code=authorization_projection.publish_generation_gap;expected=1;actual=generation_overflow"
                .to_owned(),
        ));
    assert!(matches!(
        classify_publish_failure(&leading_gap),
        PublishFailureHandling::PointerMoved { .. }
    ));
}

#[test]
fn compile_stage_classification_is_exact_token() {
    let divergence_codes = [
        "code=auth_projector.unsupported_producer_compiler;expected=v1;claimed=v2",
        "code=auth_projector.generation_overflow",
        "code=auth_projector.first_publication_requires_initial_chain",
        "code=auth_projector.full_rebuild_stuck;reason=BaseBehindFrontier",
        "code=auth_projector.compile_version_fence_broken",
        "code=auth_projector.first_publication_rebuild_failed;error=boom",
        "code=auth_projector.base_state_build_failed;error=boom",
        "code=auth_projector.continuation_requires_published_frontier",
    ];
    for reason in divergence_codes {
        assert!(
            matches!(
                classify_compile_stage_error(reason.to_owned()),
                EventDisposition::Quarantine { .. }
            ),
            "{reason} must route to Quarantine"
        );
    }

    let retry_codes = [
        "code=auth_projector.compile_error;error=boom",
        "code=auth_projector.full_rebuild_failed;error=boom",
        "code=auth_projector.delta_payload_invalid;error=boom",
        "code=auth_projector.tenant_scope_invalid;error=boom",
        "code=auth_projector.card_scoped_dependency_required",
        // Unparseable / foreign codes keep the bounded-retry default.
        "code=auth_projector.not_a_known_divergence",
        "no code prefix at all",
        "",
    ];
    for reason in retry_codes {
        assert!(
            matches!(
                classify_compile_stage_error(reason.to_owned()),
                EventDisposition::Retry { .. }
            ),
            "{reason} must route to Retry"
        );
    }

    // Regression pin for the substring hazard: a dynamic detail token can
    // no longer flip a transient failure into terminal quarantine.
    let detail_flip = "code=auth_projector.compile_error;error=inner base_state_build_failed burst";
    assert!(matches!(
        classify_compile_stage_error(detail_flip.to_owned()),
        EventDisposition::Retry { .. }
    ));
}

// ── Source-shape guards: no legacy-table/MQ symbols leak into the new
//    worker (boundary #8, reviewable without running anything).

/// Banned legacy-channel symbols; ANY occurrence inside scanned production
/// source fails the suite.
const LEGACY_CHANNEL_SYMBOLS: [&str; 11] = [
    "rebuild_card_snapshot_inner",
    "rebuild_rule_set_snapshot_inner",
    "permission_rule_snapshot",
    "rule_set_snapshot",
    "authorization_projection_outbox\"",
    "publish_permission_refresh",
    "PermissionRefreshPayload",
    "complete_authorization_archive_intent",
    "evict_card_cache",
    "mark_aggregate_projected_for_event",
    // The old pointer-only observation seam is fully superseded; a
    // reintroduction would silently drop parent-reference hints.
    "observe_current_pointer",
];

/// Reusable extraction of the FULL production source of this file:
/// everything before the single module-level test section.
///
/// History note: the first implementation cut at the FIRST `#[cfg(test)]`
/// in the file, which used to sit mid-production (`impl EventDisposition`);
/// the scan therefore ended around line ~570 and every later symbol —
/// `run_worker`, `act_on_disposition`, publish-failure handlers — was
/// invisible to it. This extractor cuts at the true module-level
/// `#[cfg(test)] mod tests` marker, asserts that marker is unique, and is
/// proven end-to-end by
/// [`legacy_guard_self_test_proves_late_production_symbol_detection`].
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

fn assert_no_legacy_channel_symbols(production: &str, context: &str) {
    for banned in LEGACY_CHANNEL_SYMBOLS {
        assert!(
            !production.contains(banned),
            "{context}: new worker must not reference legacy symbol {banned}"
        );
    }
}

#[test]
fn worker_source_has_no_legacy_channel_symbols() {
    // 拆分后生产代码分属 worker.rs、planning.rs、config.rs 与 runtime.rs（主文件
    // 为 façade）；禁用符号扫描必须覆盖全部四个生产文件。
    let main_source = include_str!("../authorization_projector.rs");
    let config_source = include_str!("../authorization_projector/config.rs");
    let runtime_source = include_str!("../authorization_projector/runtime.rs");
    let worker_source = include_str!("../authorization_projector/worker.rs");
    let planning_source = include_str!("../authorization_projector/planning.rs");
    let ordinal_source = production_source_slice(include_str!(
        "../authorization_projector/planning/parent_ordinals.rs"
    ));
    assert!(ordinal_source.contains("fn take("));
    let production = production_source_slice(main_source);
    // The cut must land exactly on the single test-section marker: no
    // cfg(test)/test-mod text may survive into the scanned production half.
    assert!(
        !production.contains("#[cfg(test)]"),
        "production slice must be cut at the unique module-level test section"
    );
    for (name, source) in [
        ("config.rs", config_source),
        ("runtime.rs", runtime_source),
        ("worker.rs", worker_source),
        ("planning.rs", planning_source),
    ] {
        assert!(
            !source.contains("#[cfg(test)]"),
            "{name} must not carry a test section"
        );
    }

    // Coverage proof across the whole runtime half (fixed scan regression):
    // early constants/policy, the loop body, the disposition actuator and
    // the final production surface before `mod tests` must ALL be present,
    // so any late-file forbidden symbol is now guaranteed to be seen.
    assert!(worker_source.contains("fn plan_retry_schedule("));
    assert!(worker_source.contains("async fn run_worker("));
    assert!(worker_source.contains("async fn act_on_disposition("));
    assert!(worker_source.contains("fn quarantine_reason_parts("));
    assert!(
        planning_source.contains("plan_stage_segments(&assembled.candidate, parent_references)")
    );
    // 配置解析归属 config.rs，纯计划归属 planning.rs（拆分后从主文件移出）。
    assert!(config_source.contains("fn parse_projector_tenants("));
    assert!(planning_source.contains("partition_ledger_at_published_frontier("));

    for (name, source) in [
        ("authorization_projector.rs", production),
        ("config.rs", config_source),
        ("runtime.rs", runtime_source),
        ("worker.rs", worker_source),
        ("planning.rs", planning_source),
        ("parent_ordinals.rs", ordinal_source),
    ] {
        assert_no_legacy_channel_symbols(source, name);
    }
    // The fixed publish sequence helper IS required (runtime seam)。
    assert!(runtime_source.contains("project_authorization_delta_in_tx"));
    assert!(runtime_source.contains("load_claimed_delta_event_for_update_in_tx"));
    assert!(runtime_source.contains("claim_next_delta_event_in_tx"));

    // Slice-2 wiring must stay present: one-transaction publication
    // context, strict frontier loader, parent reference loader, multi-
    // grant partition planning and the real terminal quarantine boundary.
    assert!(runtime_source.contains("async fn observe_publication_context("));
    assert!(runtime_source.contains("load_published_aggregate_frontier_in_tx"));
    assert!(runtime_source.contains("load_published_parent_reference_views_in_tx"));
    assert!(planning_source.contains("partition_ledger_at_published_frontier("));
    assert!(runtime_source.contains("async fn mark_event_quarantined("));
    assert!(runtime_source.contains("mark_delta_event_quarantined("));
    assert!(worker_source.contains("fn quarantine_reason_parts("));
    // Segment reuse is driven by observed parent references (never hard
    // coded None in the production decide path).
    assert!(
        planning_source.contains("plan_stage_segments(&assembled.candidate, parent_references)")
    );
}

/// Watchdog probe / claim-candidate same-shape guard (10.D-2 companion).
///
/// `has_claimable_work` feeds the F5-1d stall detector: "backlog exists but
/// no progress" forces a worker generation rebuild. The claim candidates
/// gate out events whose same-grant chain predecessor is non-terminal, so
/// a probe WITHOUT the same gate would report a backlog that the claim can
/// never serve (a chain serializing behind one backoff'd predecessor) and
/// the watchdog would rebuild workers in a loop. The production probe must
/// embed the reference gate byte-equal.
#[test]
fn watchdog_probe_carries_the_claim_sibling_order_gate() {
    // Const-to-const comparison: both sides are compiled string values, so
    // the `\`-continuation whitespace rule applies identically and the
    // equality claim is byte-exact (a raw-source scan would compare a
    // compiled value against un-collapsed source text and be meaningless).
    assert!(
        WATCHDOG_CLAIMABLE_PROBE_SQL.contains(astral_db::DELTA_CLAIM_SIBLING_ORDER_GATE),
        "watchdog probe must embed the claim sibling-ordering gate \
             byte-equal to astral_db::DELTA_CLAIM_SIBLING_ORDER_GATE"
    );
    // The probe stays tenant-scoped and never widens to a cross-tenant
    // backlog signal.
    assert!(WATCHDOG_CLAIMABLE_PROBE_SQL.contains("tenant_id = ?"));
    assert_eq!(WATCHDOG_CLAIMABLE_PROBE_SQL.matches('?').count(), 1);
}

/// Self-test fixture proving the scanner really trips when a banned legacy
/// symbol appears in the LATE half of a production source — after the
/// mid-file run_worker/act_on_disposition markers that used to hide it.
#[test]
fn legacy_guard_self_test_proves_late_production_symbol_detection() {
    let fixture_source: &'static str = concat!(
        "fn plan_retry_schedule() {}\n",
        "async fn run_worker(runtime) {}\n",
        "async fn act_on_disposition(ctx) {}\n",
        "\n",
        "// late-half offender:\n",
        "rebuild_rule_set_snapshot_inner();\n",
    );
    let panic_payload = std::panic::catch_unwind(|| {
        assert_no_legacy_channel_symbols(fixture_source, "fixture");
    })
    .expect_err(
        "scanner MUST reject legacy symbols appearing after the mid-file \
             markers",
    );
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
        message.contains("rebuild_rule_set_snapshot_inner"),
        "panic must name the offending symbol, got: {message}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_times_out_when_worker_refuses_to_stop() {
    struct StickyRuntime {
        wedged: Arc<AtomicBool>,
    }
    #[async_trait]
    impl AuthorizationProjectorRuntime for StickyRuntime {
        async fn claim_next_event(
            &self,
            _scope: &DeltaEventClaimScope,
            _owner: &str,
            _lease: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            // Signal "inside the publish transaction", then simulate a DB
            // wedged against a lost connection: yields, but never resolves;
            // cancellation cannot rescue it and only the bounded shutdown
            // timeout can.
            self.wedged.store(true, Ordering::Release);
            std::future::pending::<()>().await;
            unreachable!("pending future never resolves")
        }
        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            unreachable!()
        }
        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            unreachable!()
        }
        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            unreachable!()
        }
        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            unreachable!()
        }
        async fn fail_event(
            &self,
            _identity: &DeltaLeaseIdentity,
            _backoff_seconds: i64,
            _message: &str,
        ) {
        }
        async fn release_event(&self, _identity: &DeltaLeaseIdentity) {}
        async fn mark_event_quarantined(
            &self,
            _lease: &DeltaLeaseIdentity,
            _reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            unreachable!()
        }
    }

    let wedged = Arc::new(AtomicBool::new(false));
    let handle = start_authorization_projector_with_runtime(
        Arc::new(StickyRuntime {
            wedged: wedged.clone(),
        }),
        AuthorizationProjectorConfig {
            tenants: vec![1],
            poll_interval_secs: 60,
            ..Default::default()
        },
    );
    // Wait until the runtime PROVABLY sits inside the unresolved claim
    // (publish-transaction stand-in); cancelling earlier would legitimately
    // exit between polls and defeat the bounded-timeout coverage.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !wedged.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "worker never reached claim");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let report = shutdown_authorization_projector(handle, Duration::from_millis(120)).await;
    assert!(report.summary.is_err(), "stuck worker must surface as Err");
    assert!(report.join_elapsed < Duration::from_secs(2));
}

#[tokio::test]
async fn worker_stops_cleanly_on_cancellation_between_claims() {
    use std::sync::Mutex;
    struct QuietRuntime {
        claims: Mutex<u32>,
    }
    #[async_trait]
    impl AuthorizationProjectorRuntime for QuietRuntime {
        async fn claim_next_event(
            &self,
            _scope: &DeltaEventClaimScope,
            _owner: &str,
            _lease: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            *self.claims.lock().unwrap() += 1;
            Ok(None)
        }
        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            unreachable!()
        }
        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            unreachable!()
        }
        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            unreachable!()
        }
        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            unreachable!()
        }
        async fn fail_event(
            &self,
            _identity: &DeltaLeaseIdentity,
            _backoff_seconds: i64,
            _message: &str,
        ) {
        }
        async fn release_event(&self, _identity: &DeltaLeaseIdentity) {}
        async fn mark_event_quarantined(
            &self,
            _lease: &DeltaLeaseIdentity,
            _reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            unreachable!()
        }
    }

    let runtime = Arc::new(QuietRuntime {
        claims: Mutex::new(0),
    });
    let handle = start_authorization_projector_with_runtime(
        runtime.clone(),
        AuthorizationProjectorConfig {
            tenants: vec![42],
            poll_interval_secs: 1,
            ..Default::default()
        },
    );
    // Allow a couple of empty cycles, then cancel and join promptly.
    tokio::time::sleep(Duration::from_millis(30)).await;
    let report = shutdown_authorization_projector(handle, Duration::from_secs(3)).await;
    assert!(report.summary.is_ok());
    let summary = report.summary.unwrap();
    assert_eq!(summary.events_claimed, 0);
    assert!(
        *runtime.claims.lock().unwrap() >= 1,
        "worker must have polled"
    );
}

// ── Pure decision pipeline (no DB): claim-shape ↔ ledger ↔ compiler ─────

fn active_card_dependency_hash(source_generation: u64, fence: u64) -> (DependencyVector, String) {
    reconstruct_dependency_vector(Some(17), source_generation, fence).unwrap()
}

struct Fixture {
    grant_rev1: astral_types::CanonicalGrant,
}

fn fixture() -> Fixture {
    Fixture {
        grant_rev1: grant(1, 1, GrantState::Active),
    }
}

// ── Published-frontier / publication-context fixtures ───────────────────

fn grant_id_for(unique_tail: u16) -> GrantId {
    GrantId::parse(&format!(
        "550e8400-e29b-41d4-a716-44665544{unique_tail:04x}"
    ))
    .unwrap()
}

/// One frontier event mirroring the strict loader's contract: generation
/// ascending, per-grant chaining, per-grant target equal to the ledger
/// revision the event proves.
struct FixtureDelta {
    generation: u64,
    event_id: &'static str,
    grant_id: GrantId,
    delta_base_version: i64,
    delta_target_version: i64,
}

fn delta_fixture(
    generation: u64,
    event_id: &'static str,
    grant_tail: u16,
    base: i64,
    target: i64,
) -> FixtureDelta {
    FixtureDelta {
        generation,
        event_id,
        grant_id: grant_id_for(grant_tail),
        delta_base_version: base,
        delta_target_version: target,
    }
}

fn frontier_fixture(card_id: Option<i64>, deltas: &[FixtureDelta]) -> PublishedAggregateFrontier {
    use astral_db::{PublishedFrontierEvent, PublishedGenerationSummary};
    let identity = ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap();
    let (last_event, last_op) = deltas
        .last()
        .map(|delta| (delta.event_id.to_owned(), format!("op-{}", delta.event_id)))
        .unwrap_or_default();
    let pointer = AuthorizationCurrentPointerRecord {
        pointer_id: 3,
        identity: identity.clone(),
        card_id,
        current_generation: deltas.last().map(|delta| delta.generation).unwrap_or(0),
        manifest_id: 90,
        event_id: last_event,
        operation_id: last_op,
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
        revoke_fence: 0,
        revoke_fence_proven: true,
        cas_version: 4,
    };
    let manifest = PublishedGenerationSummary {
        manifest_id: pointer.manifest_id,
        generation: pointer.current_generation,
        source_generation: 5,
        projected_generation: 5,
        event_id: pointer.event_id.clone(),
        operation_id: pointer.operation_id.clone(),
        semantic_hash: pointer.semantic_hash,
        dependency_hash: pointer.dependency_hash,
        compiler_version: pointer.compiler_version.clone(),
        manifest_digest: Sha256Digest::from_hex(HASH_B).unwrap(),
        parent_manifest_id: if pointer.current_generation > 1 {
            Some(89)
        } else {
            None
        },
        revoke_fence: pointer.revoke_fence,
        card_id,
    };
    let events = deltas
        .iter()
        .map(|delta| PublishedFrontierEvent {
            generation: delta.generation,
            plan_id: delta.generation as i64 + 1000,
            event_id: delta.event_id.to_owned(),
            operation_id: format!("op-{}", delta.event_id),
            grant_id: delta.grant_id,
            event_type: astral_db::DeltaEventType::Add,
            delta_base_version: delta.delta_base_version,
            delta_target_version: delta.delta_target_version,
            source_generation: 5,
            revoke_fence: 0,
            semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
            dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
            compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
        })
        .collect();
    PublishedAggregateFrontier {
        identity,
        card_id,
        pointer,
        manifest,
        events,
    }
}

/// Observed publication context with NO parent reference hints — the
/// planning then plans every segment as content-addressed `New`, exactly
/// like the pre-reuse production behavior.
fn context_without_references(card_id: Option<i64>, deltas: &[FixtureDelta]) -> PublicationContext {
    PublicationContext {
        frontier: frontier_fixture(card_id, deltas),
        parent_references: Vec::new(),
    }
}

fn claimed_event(
    base: &astral_types::CanonicalGrant,
    delta: &astral_types::GrantDelta,
    source_generation: u64,
    fence: u64,
    event_id: &str,
    operation_id: &str,
    dep_hash_hex: &str,
) -> ClaimedDeltaEvent {
    ClaimedDeltaEvent {
        delta_event_id: 77,
        event_id: event_id.to_owned(),
        operation_id: operation_id.to_owned(),
        event_type: astral_db::DeltaEventType::Add,
        tenant_id: base.tenant.tenant_id,
        card_id: Some(base.card_id),
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 17,
        grant_id: base.grant_id,
        base_version: if matches!(delta, astral_types::GrantDelta::Add { .. }) {
            (base.revision.value().saturating_sub(1)) as i64
        } else {
            (base.revision.value() - 1) as i64
        },
        target_version: base.revision.value() as i64,
        source_generation,
        revoke_fence: fence,
        before_image_json: None,
        before_digest: None,
        delta_json: serde_json::to_string(delta).unwrap(),
        semantic_hash: Sha256Digest::from_hex(&base.canonical_hash().unwrap()).unwrap(),
        dependency_hash: Sha256Digest::from_hex(dep_hash_hex).unwrap(),
        compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
        attempts: 1,
        cas_version: 2,
        lease_owner: "auth-projector:test-run".to_owned(),
        lease_expires_at: time::PrimitiveDateTime::MIN,
    }
}

#[tokio::test]
async fn decide_first_publication_replays_oracle_and_assembles_publish() {
    let fx = fixture();
    let initial = fx.grant_rev1;
    let (_, dep_hash) = active_card_dependency_hash(5, 1);
    let delta = astral_types::GrantDelta::add(initial.clone());
    let claimed = claimed_event(&initial, &delta, 5, 1, "evt-first", "op-first", &dep_hash);
    let rows = vec![raw_row(&initial, "evt-first", "op-first", 1)];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: None,
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            assert_eq!(command.expectation.identity.aggregate_id, 17);
            assert_eq!(command.stage.target_generation, 1);
            assert_eq!(command.impact_plan.base_generation, 0);
            // REPLAY-mode evidence with no fabricated full-rebuild reason.
            assert_eq!(
                command.mode.compile_mode,
                astral_types::ProjectionCompileMode::Replay
            );
            assert!(command.mode.full_rebuild_reason.is_none());
            assert!(!command.impact_plan.items.is_empty());
            assert!(!command.stage.segments.is_empty());
            // Content-addressed staging starts all-New without parent refs.
            assert!(command
                .stage
                .segments
                .iter()
                .all(|entry| matches!(entry, StagedSegmentContent::New(_))));
            // First publication pins previous fence at the zero sentinel.
            assert_eq!(command.fences.previous_revoke_fence, 0);
            assert_eq!(command.fences.new_revoke_fence, 1);
        }
        other => panic!("expected Publish, got {other:?}"),
    }
}

#[tokio::test]
async fn decide_incremental_second_revision_targets_next_generation() {
    let fx = fixture();
    let rev1 = fx.grant_rev1;
    let mut rev2 = rev1.clone();
    rev2.revision = GrantRevision::new(2).unwrap();
    rev2.provenance.source_id = "rule-set-entry-10".to_owned();
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    // Strict publication context: generation 1 is proven by the rev-1
    // delta event itself, per-grant target 1.
    let context = context_without_references(Some(17), &[delta_fixture(1, "evt-first", 1, 0, 1)]);
    let delta = astral_types::GrantDelta::update(rev2.clone(), rev1.revision);
    let mut claimed = claimed_event(&rev2, &delta, 5, 0, "evt-second", "op-second", &dep_hash);
    claimed.event_type = astral_db::DeltaEventType::Update;
    let rows = vec![
        raw_row(&rev1, "evt-first", "op-first", 0),
        raw_row(&rev2, "evt-second", "op-second", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            assert_eq!(command.stage.target_generation, 2);
            assert_eq!(command.expectation.base_version, 1);
            assert_eq!(command.expectation.target_version, 2);
            assert_eq!(
                command.mode.compile_mode,
                astral_types::ProjectionCompileMode::Incremental
            );
            assert!(command.mode.full_rebuild_reason.is_none());
            // INCREMENTAL plan items carry REAL compiler evidence: an
            // unchanged exact-key position that changed content yields one
            // upsert item holding both before and after digests.
            let evidence_upsert =
                command.impact_plan.items.iter().find(|item| {
                    item.before_digest_hex.is_some() && item.after_digest_hex.is_some()
                });
            assert!(
                evidence_upsert.is_some(),
                "content-only change must yield a before+after upsert item"
            );
            // Fence continuity stays monotonic against the locked baseline.
            assert_eq!(command.fences.previous_revoke_fence, 0);
            assert_eq!(command.fences.new_revoke_fence, 0);
        }
        other => panic!("expected Publish, got {other:?}"),
    }
}

#[tokio::test]
async fn decide_full_rebuild_only_through_compiler_outcome_and_records_reason() {
    let fx = fixture();
    let rev1 = fx.grant_rev1;
    let mut wildcarded = rev1.clone();
    wildcarded.revision = GrantRevision::new(2).unwrap();
    wildcarded.resource = "*".to_owned();
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let context = context_without_references(Some(17), &[delta_fixture(1, "evt-first", 1, 0, 1)]);
    let delta = astral_types::GrantDelta::update(wildcarded.clone(), rev1.revision);
    let mut claimed = claimed_event(&wildcarded, &delta, 5, 0, "evt-wild", "op-wild", &dep_hash);
    claimed.event_type = astral_db::DeltaEventType::Update;
    let rows = vec![
        raw_row(&rev1, "evt-first", "op-first", 0),
        raw_row(&wildcarded, "evt-wild", "op-wild", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            // ONLY a genuine compiler FullRebuildRequired outcome may set
            // FULL_REBUILD mode — always paired with its explicit reason.
            assert_eq!(
                command.mode.compile_mode,
                astral_types::ProjectionCompileMode::FullRebuild
            );
            assert_eq!(
                command.mode.full_rebuild_reason,
                Some(policy_engine::FullRebuildReason::WildcardImpact)
            );
            assert!(!command.impact_plan.items.is_empty());
        }
        other => panic!("expected Publish with recorded reason, got {other:?}"),
    }
}

/// The flipped slice-1 case: a legal frontier proving TWO grant chains in
/// one scope now PUBLISHES. Domain isolation is pinned at the same time:
/// the aggregate base generation (pointer G + 1) and the per-grant
/// projection window (base/target on THIS grant's chain) stay separate.
#[test]
fn decide_publishes_multi_grant_scope_from_verified_frontier() {
    let own_head = grant(1, 1, GrantState::Active);
    let mut own_next = own_head.clone();
    own_next.revision = GrantRevision::new(2).unwrap();
    own_next.provenance.source_id = "rule-set-entry-next".to_owned();
    let sibling = grant(9, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    // Frontier: gen1 = own grant revision 1, gen2 = sibling initial.
    let context = context_without_references(
        Some(17),
        &[
            delta_fixture(1, "evt-own-rev1", 1, 0, 1),
            delta_fixture(2, "evt-sibling-init", 9, 0, 1),
        ],
    );
    let delta = astral_types::GrantDelta::update(own_next.clone(), own_head.revision);
    let mut claimed = claimed_event(&own_next, &delta, 5, 0, "evt-mixed", "op-mixed", &dep_hash);
    claimed.event_type = astral_db::DeltaEventType::Update;
    // Ledger ordering follows (grant_id ASC, revision_no ASC):
    // …0001 rows stay grouped before …0009.
    let rows = vec![
        raw_row(&own_head, "evt-own-rev1", "op-own-rev1", 0),
        raw_row(&own_next, "evt-mixed", "op-mixed", 0),
        raw_row(&sibling, "evt-sibling-init", "op-sibling", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            // Aggregate domain: pointer G=2 ⇒ target G+1=3.
            assert_eq!(command.stage.target_generation, 3);
            assert_eq!(command.impact_plan.base_generation, 2);
            // Per-grant domain: this claim chains rev1 → rev2 of its OWN
            // grant only; never compared against aggregate generations.
            assert_eq!(command.expectation.base_version, 1);
            assert_eq!(command.expectation.target_version, 2);
            assert_eq!(
                command.mode.compile_mode,
                astral_types::ProjectionCompileMode::Incremental
            );
            assert!(!command.stage.segments.is_empty());
        }
        other => panic!("verified multi-grant frontier must publish, got {other:?}"),
    }
}

// ── T2 regression: published wildcard continuation REMOVE/REVOKE ────────
//
// SQL-seed shape: the grant's Active revision is already PUBLISHED
// (frontier-proven) and the claimed event appends a tombstone revision.
// A type-level wildcard that is the card's ONLY Active contribution
// forces FullRebuildRequired; the rebuilt candidate has NO segment left,
// so the vanished base key must be planned as an explicit SegmentRemove
// instead of degrading into the empty-impact quarantine.

fn wildcard_grant(
    unique_tail: u16,
    revision: u64,
    state: GrantState,
) -> astral_types::CanonicalGrant {
    let mut wildcarded = grant(unique_tail, revision, state);
    wildcarded.resource = "learn_subject:*".to_owned();
    wildcarded
}

fn tombstone_from(
    source: &astral_types::CanonicalGrant,
    revision: u64,
    state: GrantState,
) -> astral_types::CanonicalGrant {
    let mut tombstone = source.clone();
    tombstone.revision = GrantRevision::new(revision).unwrap();
    tombstone.state = state;
    tombstone
}

#[test]
fn decide_continuation_remove_of_only_wildcard_publishes_segment_remove() {
    let published = wildcard_grant(1, 1, GrantState::Active);
    let tombstone = tombstone_from(&published, 2, GrantState::Removed);
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let context = context_without_references(Some(17), &[delta_fixture(1, "evt-w-add", 1, 0, 1)]);
    let delta = astral_types::GrantDelta::remove(published.grant_id, published.revision);
    let mut claimed = claimed_event(
        &tombstone,
        &delta,
        5,
        0,
        "evt-w-remove",
        "op-w-remove",
        &dep_hash,
    );
    claimed.event_type = astral_db::DeltaEventType::Remove;
    let rows = vec![
        raw_row(&published, "evt-w-add", "op-w-add", 0),
        raw_row(&tombstone, "evt-w-remove", "op-w-remove", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            assert_eq!(
                command.mode.compile_mode,
                astral_types::ProjectionCompileMode::FullRebuild
            );
            assert_eq!(
                command.mode.full_rebuild_reason,
                Some(policy_engine::FullRebuildReason::WildcardImpact)
            );
            // Exactly one item: the vanished wildcard key, base digest as
            // `before`, NO `after` — compiler-plan evidence, not synthesis.
            assert_eq!(command.impact_plan.items.len(), 1);
            let item = &command.impact_plan.items[0];
            assert_eq!(item.item_type, AuthorizationImpactItemType::SegmentRemove);
            assert!(item.projection_key.contains("learn_subject:*"), "{item:?}");
            assert!(item.before_digest_hex.is_some());
            assert!(item.after_digest_hex.is_none());
            // Nothing stays Active: the removal-only manifest stages no
            // segment content at all.
            assert!(command.stage.segments.is_empty());
        }
        other => panic!("wildcard removal must publish with SegmentRemove, got {other:?}"),
    }
}

#[test]
fn decide_continuation_revoke_of_only_wildcard_publishes_and_advances_fence() {
    let published = wildcard_grant(1, 1, GrantState::Active);
    let tombstone = tombstone_from(&published, 2, GrantState::Revoked);
    let (_, dep_hash) = active_card_dependency_hash(5, 1);
    let context = context_without_references(Some(17), &[delta_fixture(1, "evt-r-add", 1, 0, 1)]);
    let delta = astral_types::GrantDelta::revoke(published.grant_id, published.revision);
    let mut claimed = claimed_event(
        &tombstone,
        &delta,
        5,
        1,
        "evt-r-revoke",
        "op-r-revoke",
        &dep_hash,
    );
    claimed.event_type = astral_db::DeltaEventType::Revoke;
    let rows = vec![
        raw_row(&published, "evt-r-add", "op-r-add", 0),
        raw_row(&tombstone, "evt-r-revoke", "op-r-revoke", 1),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            assert_eq!(
                command.mode.compile_mode,
                astral_types::ProjectionCompileMode::FullRebuild
            );
            // Exact compiler-trigger evidence, same as the REMOVE path.
            assert_eq!(
                command.mode.full_rebuild_reason,
                Some(policy_engine::FullRebuildReason::WildcardImpact)
            );
            assert!(
                command
                    .impact_plan
                    .items
                    .iter()
                    .any(|item| item.item_type == AuthorizationImpactItemType::SegmentRemove),
                "revoked wildcard key must yield a SegmentRemove item"
            );
            assert!(
                !command.impact_plan.items.is_empty()
                    && command.impact_plan.items.iter().all(|item| {
                        item.item_type == AuthorizationImpactItemType::SegmentRemove
                    })
            );
            // REVOKE fence progress: previous fence from the locked
            // pointer, new fence is the claimed max.
            assert_eq!(command.fences.previous_revoke_fence, 0);
            assert_eq!(command.fences.new_revoke_fence, 1);
            // Nothing stays Active: the revoke-only manifest stages no
            // segment content at all (same empty stage as the REMOVE
            // path — the revoked wildcard was the only contribution).
            assert!(command.stage.segments.is_empty());
        }
        other => panic!("wildcard revoke must publish, got {other:?}"),
    }
}

#[test]
fn decide_continuation_remove_wildcard_publishes_and_keeps_object_level_segment() {
    let wildcard = wildcard_grant(1, 1, GrantState::Active);
    let wildcard_tombstone = tombstone_from(&wildcard, 2, GrantState::Removed);
    // Sibling object-level grant on a DIFFERENT exact key stays untouched.
    let object_level = grant(9, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let context = context_without_references(
        Some(17),
        &[
            delta_fixture(1, "evt-a-add", 1, 0, 1),
            delta_fixture(2, "evt-b-add", 9, 0, 1),
        ],
    );
    let delta = astral_types::GrantDelta::remove(wildcard.grant_id, wildcard.revision);
    let mut claimed = claimed_event(
        &wildcard_tombstone,
        &delta,
        5,
        0,
        "evt-a-remove",
        "op-a-remove",
        &dep_hash,
    );
    claimed.event_type = astral_db::DeltaEventType::Remove;
    // Ledger ordering: grant …0001 rows grouped before …0009.
    let rows = vec![
        raw_row(&wildcard, "evt-a-add", "op-a-add", 0),
        raw_row(&wildcard_tombstone, "evt-a-remove", "op-a-remove", 0),
        raw_row(&object_level, "evt-b-add", "op-b-add", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            assert_eq!(command.stage.target_generation, 3);
            // Only the vanished wildcard key is removed; the untouched
            // object-level key produces NO impact item (content unchanged
            // ⇒ no durable evidence line) and no removal either.
            assert_eq!(command.impact_plan.items.len(), 1);
            let item = &command.impact_plan.items[0];
            assert_eq!(item.item_type, AuthorizationImpactItemType::SegmentRemove);
            assert!(item.projection_key.contains("learn_subject:*"), "{item:?}");
            // The object-level segment is still staged into the new
            // generation, so published evidence keeps authorizing it.
            assert_eq!(command.stage.segments.len(), 1);
            assert!(matches!(
                command.stage.segments[0],
                StagedSegmentContent::New(_)
            ));
        }
        other => panic!("multi-segment wildcard removal must publish, got {other:?}"),
    }
}

/// A genuinely empty-impact event keeps the no_effective_change
/// quarantine. Inside the legal delta contract every incremental delta
/// changes at least one affected segment (the grant revision is part of
/// the segment content hash), so the reachable empty-impact shape is the
/// tombstone-seed FIRST publication: the oracle rebuilds generation 1
/// from a single removed/revoked seed row, the candidate has no segments,
/// no base digest exists to cite as `before`, and publishing an empty
/// generation is forbidden — the event stays terminal for operator
/// reconciliation instead. (A no-effective INCREMENTAL delta cannot even
/// reach this guard: the one such shape, an Add whose payload already
/// carries a tombstone state, is refused by `GrantDelta::validate` at the
/// durable decode gate — pinned by the next test.)
#[test]
fn decide_tombstone_seed_first_publication_keeps_empty_impact_quarantine() {
    // Seed row: revision 1 already carries a tombstone state.
    let seed = tombstone_from(&grant(1, 1, GrantState::Active), 1, GrantState::Removed);
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let delta = astral_types::GrantDelta::remove(seed.grant_id, seed.revision);
    let mut claimed = claimed_event(&seed, &delta, 5, 0, "evt-t1", "op-t1", &dep_hash);
    claimed.event_type = astral_db::DeltaEventType::Remove;
    let rows = vec![raw_row(&seed, "evt-t1", "op-t1", 0)];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: None,
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Quarantine { reason } => {
            // Exact stable machine token, not a substring scan.
            assert_eq!(reason, "code=auth_projector.no_effective_change");
        }
        other => panic!("tombstone first publication must stay quarantined, got {other:?}"),
    }
}

/// The one delta shape that WOULD be genuinely no-effective — an Add
/// whose payload already carries a tombstone state (records durable
/// history, authorizes nothing) — is refused by the durable decode gate
/// BEFORE any compile or impact stage (`GrantDelta::validate` demands an
/// Active payload for `Add`). Combined with the segment content hash
/// covering the full canonical grant (revision included), this proves the
/// incremental arm can never map to an empty item list: every legal
/// incremental delta changes at least one affected segment, so the
/// `no_effective_change` guard is unreachable there and the T2
/// continuation mapping cannot loosen what legal inputs never hit. The
/// refused shape stays fail-closed under the bounded attempt budget — it
/// never publishes, never fabricates evidence and never reaches the
/// impact-plan stage.
#[test]
fn decide_tombstone_payload_add_is_refused_before_any_impact_stage() {
    // Published sibling: grant …0001 Active rev 1 (frontier-proven, gen 1).
    let published_sibling = grant(1, 1, GrantState::Active);
    // Claimed: FIRST revision of a NEW grant whose payload is already a
    // tombstone — the shape SQL-seeded history could produce.
    let tombstone_add = tombstone_from(&grant(2, 1, GrantState::Active), 1, GrantState::Removed);
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let context = context_without_references(Some(17), &[delta_fixture(1, "evt-s-add", 1, 0, 1)]);
    let delta = astral_types::GrantDelta::add(tombstone_add.clone());
    let claimed = claimed_event(
        &tombstone_add,
        &delta,
        5,
        0,
        "evt-t-add",
        "op-t-add",
        &dep_hash,
    );
    // Ledger ordering mirrors load_grant_ledger_rows: grant …0001 first.
    let rows = vec![
        raw_row(&published_sibling, "evt-s-add", "op-s-add", 0),
        raw_row(&tombstone_add, "evt-t-add", "op-t-add", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Retry { reason } => {
            // Exact-token machine code prefix (classifier contract); the
            // embedded astral-db detail after `;` is never matched.
            assert!(
                reason.starts_with("code=auth_projector.delta_payload_invalid"),
                "unexpected refusal reason: {reason}"
            );
        }
        other => {
            panic!("tombstone-payload add must be refused before any impact stage, got {other:?}")
        }
    }
}

/// F6 修复回归：无 pointer 多链并存不再互相卡死——claimed grant 自身链
/// 可证明即发布，兄弟 grant 行（独立初始链）忽略，各自 claim 收口。兄弟
/// 未发布期间授权读由 source-freshness 门保持 PENDING，中间态不外泄。
#[test]
fn decide_publishes_own_initial_chain_despite_sibling_grant_rows() {
    let own = grant(1, 1, GrantState::Active);
    let foreign = grant(9, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 1);
    let delta = astral_types::GrantDelta::add(own.clone());
    let claimed = claimed_event(&own, &delta, 5, 1, "evt-mixed", "op-mixed", &dep_hash);
    // 兄弟行在前：证明只按 grant 归属过滤，与行序无关。
    let rows = vec![
        raw_row(&foreign, "evt-foreign", "op-foreign", 1),
        raw_row(&own, "evt-mixed", "op-mixed", 1),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: None,
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            assert_eq!(command.stage.target_generation, 1);
            assert_eq!(command.impact_plan.base_generation, 0);
            // 发布候选只含 claimed grant——兄弟行绝不进入候选。
            for entry in &command.stage.segments {
                match entry {
                    StagedSegmentContent::New(grants) => {
                        assert!(
                            grants.iter().all(|grant| grant.grant_id == own.grant_id),
                            "sibling grants must never enter the candidate"
                        );
                    }
                    StagedSegmentContent::ReuseParent { .. } => {
                        panic!("first publication must plan all-New segments")
                    }
                }
            }
        }
        other => {
            panic!("own provable initial chain must publish despite sibling rows, got {other:?}")
        }
    }
}

/// 对称 case：兄弟 grant 先被 claim 同样放行——per-grant 版本域下跨
/// grant 发布顺序无歧义，两种 claim 顺序都收敛。
#[test]
fn decide_publishes_sibling_initial_chain_symmetrically() {
    let own = grant(1, 1, GrantState::Active);
    let foreign = grant(9, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 1);
    let delta = astral_types::GrantDelta::add(foreign.clone());
    let claimed = claimed_event(
        &foreign,
        &delta,
        5,
        1,
        "evt-foreign",
        "op-foreign",
        &dep_hash,
    );
    let rows = vec![
        raw_row(&own, "evt-mixed", "op-mixed", 1),
        raw_row(&foreign, "evt-foreign", "op-foreign", 1),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: None,
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            assert_eq!(command.stage.target_generation, 1);
        }
        other => panic!("symmetric sibling claim must publish, got {other:?}"),
    }
}

/// Some 臂第三形态（F6 深层回归钉子）：A 已发布 gen1，兄弟 grant B 的
/// 初始链（rev1，无任何已发布 head）经 per-grant 回退（expected=0）准入，
/// 以 Continuation 发布为聚合 gen2（base=A head，per-grant 0→1）。
#[test]
fn decide_admits_second_initial_chain_after_published_frontier() {
    let own_head = grant(1, 1, GrantState::Active);
    let sibling = grant(9, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 1);
    // frontier 只证明 A 的 gen1；B 尚无任何已发布事件。
    let context =
        context_without_references(Some(17), &[delta_fixture(1, "evt-own-rev1", 1, 0, 1)]);
    let delta = astral_types::GrantDelta::add(sibling.clone());
    let claimed = claimed_event(
        &sibling,
        &delta,
        5,
        1,
        "evt-sibling-init",
        "op-sibling-init",
        &dep_hash,
    );
    let rows = vec![
        raw_row(&own_head, "evt-own-rev1", "op-own-rev1", 1),
        raw_row(&sibling, "evt-sibling-init", "op-sibling-init", 1),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            assert_eq!(command.stage.target_generation, 2);
            assert_eq!(command.impact_plan.base_generation, 1);
            assert_eq!(command.expectation.base_version, 0);
            assert_eq!(command.expectation.target_version, 1);
            assert_eq!(
                command.mode.compile_mode,
                astral_types::ProjectionCompileMode::Incremental
            );
        }
        other => panic!(
            "second initial chain must be admitted after a published frontier, got {other:?}"
        ),
    }
}

/// 自身链断档（rev1、rev3，缺 rev2）仍 Quarantine——兄弟行在场不改变
/// fail-closed 结果。
#[test]
fn decide_quarantines_own_chain_gap_even_with_sibling_rows() {
    let own_rev1 = grant(1, 1, GrantState::Active);
    let own_rev3 = grant(1, 3, GrantState::Active);
    let sibling = grant(9, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 1);
    let delta = astral_types::GrantDelta::add(own_rev3.clone());
    let claimed = claimed_event(
        &own_rev3,
        &delta,
        5,
        1,
        "evt-own-rev3",
        "op-own-rev3",
        &dep_hash,
    );
    let rows = vec![
        raw_row(&own_rev1, "evt-own-rev1", "op-own-rev1", 1),
        raw_row(&sibling, "evt-sibling", "op-sibling", 1),
        raw_row(&own_rev3, "evt-own-rev3", "op-own-rev3", 1),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: None,
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Quarantine { reason } => {
            assert!(reason.contains("first_publication_chain_gap"), "{reason}");
        }
        other => panic!("own chain gap must quarantine, got {other:?}"),
    }
}

/// 自身后继行（rev2 未发布）存在时，claimed rev1 仍发布 rev1 状态；
/// 后继行随后经 Some 臂 Continuation 收口，绝不进入首发候选。
#[test]
fn decide_publishes_claimed_revision_ignoring_own_later_revisions() {
    let own_rev1 = grant(1, 1, GrantState::Active);
    let mut own_rev2 = own_rev1.clone();
    own_rev2.revision = GrantRevision::new(2).unwrap();
    own_rev2.provenance.source_entry = Some("rule-2".to_owned());
    let (_, dep_hash) = active_card_dependency_hash(5, 1);
    let delta = astral_types::GrantDelta::add(own_rev1.clone());
    let claimed = claimed_event(
        &own_rev1,
        &delta,
        5,
        1,
        "evt-own-rev1",
        "op-own-rev1",
        &dep_hash,
    );
    let rows = vec![
        raw_row(&own_rev1, "evt-own-rev1", "op-own-rev1", 1),
        raw_row(&own_rev2, "evt-own-rev2", "op-own-rev2", 1),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: None,
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            assert_eq!(command.stage.target_generation, 1);
            for entry in &command.stage.segments {
                match entry {
                    StagedSegmentContent::New(grants) => {
                        assert!(
                            grants.iter().all(|grant| grant.revision.value() == 1),
                            "later own revisions must never enter the first publication"
                        );
                    }
                    StagedSegmentContent::ReuseParent { .. } => {
                        panic!("first publication must plan all-New segments")
                    }
                }
            }
        }
        other => panic!("claimed revision must publish ignoring later rows, got {other:?}"),
    }
}

#[test]
fn decide_blocks_own_claim_behind_unpublished_siblings() {
    let rev1 = grant(1, 1, GrantState::Active);
    let mut intermediate = rev1.clone();
    intermediate.revision = GrantRevision::new(2).unwrap();
    let mut latecomer = rev1.clone();
    latecomer.revision = GrantRevision::new(3).unwrap();
    latecomer.provenance.source_id = "rule-set-entry-late".to_owned();
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let context = context_without_references(Some(17), &[delta_fixture(1, "evt-a1", 1, 0, 1)]);
    let delta = astral_types::GrantDelta::update(latecomer.clone(), intermediate.revision);
    let mut claimed = claimed_event(&latecomer, &delta, 5, 0, "evt-late", "op-late", &dep_hash);
    claimed.event_type = astral_db::DeltaEventType::Update;
    claimed.base_version = 2; // honest producer chaining behind sibling rev2
    let rows = vec![
        raw_row(&rev1, "evt-a1", "op-a1", 0),
        raw_row(
            &intermediate,
            "evt-intermediate-pending",
            "op-intermediate",
            0,
        ),
        raw_row(&latecomer, "evt-late", "op-late", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Blocked { reason } => {
            assert!(
                reason.contains("claimed_behind_unpublished_siblings"),
                "{reason}"
            );
        }
        other => panic!("own claim behind siblings must block, got {other:?}"),
    }
}

#[test]
fn decide_quarantines_partition_corruption_and_missing_candidates() {
    let rev1 = grant(1, 1, GrantState::Active);
    let foreign = grant(9, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let context = context_without_references(
        Some(17),
        &[
            delta_fixture(1, "evt-foreign", 9, 0, 1),
            delta_fixture(2, "evt-own-rev1", 1, 0, 1),
        ],
    );

    // Corrupt world #1: unsorted ledger input fails closed instead of
    // being silently repaired. grant …0009 appears BEFORE …0001.
    let claimed = claimed_event(
        &rev1,
        &astral_types::GrantDelta::add(rev1.clone()),
        5,
        0,
        "evt-own-rev1",
        "op-own-rev1",
        &dep_hash,
    );
    let unsorted = vec![
        raw_row(&foreign, "evt-foreign", "op-f", 0),
        raw_row(&rev1, "evt-own-rev1", "op-o", 0),
    ];
    let corrupt_input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &unsorted,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&corrupt_input) {
        EventDisposition::Quarantine { reason } => {
            assert!(reason.contains("partition_corrupt"), "{reason}");
            assert!(reason.contains("partition_unsorted_input"), "{reason}");
        }
        other => panic!("unsorted partition must quarantine, got {other:?}"),
    }

    // Missing candidate: every frontier event is fully consumed by the
    // ledger, yet our claimed event has no revision row anywhere — the
    // queue row and history disagree and reconciliation wins.
    let claimed_missing = claimed_event(
        &foreign,
        &astral_types::GrantDelta::add(foreign.clone()),
        5,
        0,
        "evt-nowhere",
        "op-nowhere",
        &dep_hash,
    );
    let complete_world_context = context_without_references(
        Some(17),
        &[
            delta_fixture(1, "evt-a1", 1, 0, 1),
            delta_fixture(2, "evt-b1", 9, 0, 1),
        ],
    );
    let rows_without_ours = vec![
        raw_row(&rev1, "evt-a1", "op-a1", 0),
        raw_row(&foreign, "evt-b1", "op-b1", 0),
    ];
    let missing_input = EventDecisionInput {
        claimed: &claimed_missing,
        publication: Some(&complete_world_context),
        ledger_rows: &rows_without_ours,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&missing_input) {
        EventDisposition::Quarantine { reason } => {
            assert!(reason.contains("own_revision_missing"), "{reason}");
        }
        other => panic!("missing candidate must quarantine, got {other:?}"),
    }
}

#[test]
fn decide_quarantines_per_grant_chain_gap_against_frontier_target() {
    let rev1 = grant(1, 1, GrantState::Active);
    let mut rev2 = rev1.clone();
    rev2.revision = GrantRevision::new(2).unwrap();
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let context =
        context_without_references(Some(17), &[delta_fixture(1, "evt-own-rev1", 1, 0, 1)]);
    let delta = astral_types::GrantDelta::update(rev2.clone(), rev1.revision);
    let mut claimed = claimed_event(&rev2, &delta, 5, 0, "evt-gap", "op-gap", &dep_hash);
    claimed.event_type = astral_db::DeltaEventType::Update;
    claimed.base_version = 9; // drift from the frontier-proven target 1
    let rows = vec![
        raw_row(&rev1, "evt-own-rev1", "op-r1", 0),
        raw_row(&rev2, "evt-gap", "op-gap", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Quarantine { reason } => {
            assert!(reason.contains("per_grant_chain_gap"), "{reason}");
        }
        other => panic!("per-grant chain gap must quarantine, got {other:?}"),
    }
}

#[test]
fn plan_ledger_builds_base_only_from_frontier_proven_heads() {
    let own_head = grant(1, 1, GrantState::Active);
    let sibling_head = grant(9, 1, GrantState::Active);
    let stranger_tail = grant(4, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let context = context_without_references(
        Some(17),
        &[
            delta_fixture(1, "evt-own-head", 1, 0, 1),
            delta_fixture(2, "evt-sibling-head", 9, 0, 1),
        ],
    );
    let mut own_rev2 = own_head.clone();
    own_rev2.revision = GrantRevision::new(2).unwrap();
    let delta = astral_types::GrantDelta::update(own_rev2.clone(), own_head.revision);
    let mut claimed = claimed_event(
        &own_rev2,
        &delta,
        5,
        0,
        "evt-candidate",
        "op-candidate",
        &dep_hash,
    );
    claimed.event_type = astral_db::DeltaEventType::Update;
    // Sorted ledger: own-grant rows first (…0001), then the stranger's
    // unproven tail (…0004), then the proven sibling head (…0009).
    let rows = vec![
        raw_row(&own_head, "evt-own-head", "op-h1", 0),
        raw_row(&own_rev2, "evt-candidate", "op-candidate", 0),
        raw_row(&stranger_tail, "evt-stranger-tail", "op-tail", 0),
        raw_row(&sibling_head, "evt-sibling-head", "op-h2", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match plan_ledger_against_publication(&input) {
        LedgerPlan::Continuation { base_entries } => {
            // EXACTLY the two frontier-proven heads form the base; the
            // stranger's unproven tail never leaks into compilation.
            let mut ids: Vec<&str> = base_entries
                .iter()
                .map(|entry| entry.event_id.as_str())
                .collect();
            ids.sort_unstable();
            assert_eq!(ids, ["evt-own-head", "evt-sibling-head"]);
        }
        other => panic!("expected Continuation base planning, got {other:?}"),
    }
}

#[test]
fn decide_reuses_parent_segments_by_digest_and_keeps_changes_new() {
    let rev_a1 = {
        let mut image = grant(1, 1, GrantState::Active);
        image.resource = "learn_subject:a".to_owned();
        image
    };
    let rev_b1 = {
        let mut image = grant(9, 1, GrantState::Active);
        image.resource = "learn_subject:b".to_owned();
        image
    };
    let mut rev_a2 = rev_a1.clone();
    rev_a2.revision = GrantRevision::new(2).unwrap();
    rev_a2.resource = "learn_subject:a-changed".to_owned(); // distinct new key
    let (_, dep_hash) = active_card_dependency_hash(5, 0);

    // Build the PRE-state exactly like the assembler does (both proven
    // heads at aggregate generation 2) and take the TRUE content digest
    // of the untouched B segment as a parent-reference hint.
    let tenant = TenantScope::new(7, Some(17)).unwrap();
    let dep_vector = reconstruct_dependency_vector(Some(17), 5, 0).unwrap().0;
    let base_state = hot_state_from_entries(
        &tenant,
        2,
        dep_vector,
        policy_engine::COMPILER_VERSION.to_owned(),
        &[
            decode_ledger_row(&raw_row(&rev_a1, "evt-a1", "op-a1", 0)).unwrap(),
            decode_ledger_row(&raw_row(&rev_b1, "evt-b1", "op-b1", 0)).unwrap(),
        ],
    )
    .unwrap();
    let b_segment_payload = astral_db::encode_segment_payload(
        &base_state
            .segments
            .iter()
            .find(|(key, _)| key.resource == "learn_subject:b")
            .map(|(_, segment)| segment.grants.clone())
            .expect("B-key base segment exists"),
    )
    .unwrap();
    let parent_reference = (
        0u64,
        ParentReferenceView {
            ordinal: 0,
            identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
            segment_id: 500,
            content_digest_hex: hex_lower(&Sha256::digest(&b_segment_payload)),
        },
    );
    let context_with_refs = PublicationContext {
        parent_references: vec![parent_reference],
        frontier: frontier_fixture(
            Some(17),
            &[
                delta_fixture(1, "evt-a1", 1, 0, 1),
                delta_fixture(2, "evt-b1", 9, 0, 1),
            ],
        ),
    };

    let delta = astral_types::GrantDelta::update(rev_a2.clone(), rev_a1.revision);
    let mut claimed = claimed_event(&rev_a2, &delta, 5, 0, "evt-a2", "op-a2", &dep_hash);
    claimed.event_type = astral_db::DeltaEventType::Update;
    // Sorted ledger: A rows first (…0001), then B (…0009).
    let rows = vec![
        raw_row(&rev_a1, "evt-a1", "op-a1", 0),
        raw_row(&rev_a2, "evt-a2", "op-a2", 0),
        raw_row(&rev_b1, "evt-b1", "op-b1", 0),
    ];
    let input = EventDecisionInput {
        claimed: &claimed,
        publication: Some(&context_with_refs),
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&input) {
        EventDisposition::Publish(command) => {
            let reused: Vec<u64> = command
                .stage
                .segments
                .iter()
                .filter_map(|entry| match entry {
                    StagedSegmentContent::ReuseParent { parent_ordinal } => Some(*parent_ordinal),
                    StagedSegmentContent::New(_) => None,
                })
                .collect();
            assert_eq!(reused, vec![0], "unchanged B segment reuses ordinal 0");
            assert!(
                command
                    .stage
                    .segments
                    .iter()
                    .any(|entry| matches!(entry, StagedSegmentContent::New(_))),
                "changed/new segments must be written New"
            );
        }
        other => panic!("reuse planning must still publish, got {other:?}"),
    }
}

#[test]
fn decide_quarantines_dependency_drift_and_unsupported_compilers() {
    let fx = fixture();
    let own = fx.grant_rev1;
    let (_, dep_hash) = active_card_dependency_hash(5, 1);

    // Drifted stored dependency hash ⇒ immutable producer/reader divergence.
    let drifted_bytes = {
        let mut bytes = vec![7u8; 32];
        bytes[0] ^= 0xFF;
        bytes
    };
    let delta = astral_types::GrantDelta::add(own.clone());
    let mut drifted = claimed_event(&own, &delta, 5, 1, "evt-drift", "op-drift", &dep_hash);
    drifted.dependency_hash = astral_db::Sha256Digest::from_bytes(drifted_bytes).unwrap();
    let rows = vec![raw_row(&own, "evt-drift", "op-drift", 1)];
    let drift_input = EventDecisionInput {
        claimed: &drifted,
        publication: None,
        ledger_rows: &rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&drift_input) {
        EventDisposition::Quarantine { reason } => {
            assert!(
                reason.contains("dependency_hash_drift"),
                "unexpected quarantine reason: {reason}"
            );
        }
        other => panic!("expected quarantine on hash drift, got {other:?}"),
    }

    // Unknown producer compiler version refuses before any compilation.
    // Row and claim stay MUTUALLY consistent so only the kernel gate fires.
    let mut foreign_compiler = claimed_event(&own, &delta, 5, 1, "evt-cv", "op-cv", &dep_hash);
    foreign_compiler.compiler_version = "rogue-compiler-v0".to_owned();
    let mut rogue_row = raw_row(&own, "evt-cv", "op-cv", 1);
    rogue_row.compiler_version = "rogue-compiler-v0".to_owned();
    let compiler_rows = vec![rogue_row];
    let compiler_input = EventDecisionInput {
        claimed: &foreign_compiler,
        publication: None,
        ledger_rows: &compiler_rows,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
    };
    match decide_event_disposition(&compiler_input) {
        EventDisposition::Quarantine { reason } => {
            assert!(
                reason.contains("unsupported_producer_compiler"),
                "unexpected quarantine reason: {reason}"
            );
        }
        other => panic!("expected quarantine on unknown compiler, got {other:?}"),
    }
}

#[test]
fn quarantine_reason_parts_keep_stable_code_and_free_detail() {
    // Canonical shape: stable code + free detail pass through untouched.
    let (code, detail) = quarantine_reason_parts(
        "code=auth_projector.dependency_hash_drift;stored=aa;reconstructed=bb",
    );
    assert_eq!(code, "auth_projector.dependency_hash_drift");
    assert_eq!(detail, "stored=aa;reconstructed=bb");

    // Exactly-64-char code stays within contract…
    let max_code = "a".repeat(QUARANTINE_REASON_CODE_MAX_CHARS);
    let (code, _) = quarantine_reason_parts(&format!("code={max_code};tail"));
    assert_eq!(code, max_code);

    // …while anything longer falls back with FULL original reason kept as
    // detail for operator evidence.
    let (code, detail) = quarantine_reason_parts(&format!("code={}-x;detail-part", max_code));
    assert_eq!(code, "auth_projector.quarantine");
    assert_eq!(detail, format!("code={}-x;detail-part", max_code));

    // Unprefixed/empty reasons degrade safely without losing evidence.
    let (code, detail) = quarantine_reason_parts("   ");
    assert_eq!(code, "auth_projector.quarantine");
    assert_eq!(detail, "   ");
    let (code, detail) = quarantine_reason_parts("just some text");
    assert_eq!(code, "auth_projector.quarantine");
    assert_eq!(detail, "just some text");

    // Prefix-without-token still lands on the generic fallback.
    let (code, _) = quarantine_reason_parts("code=;kept-detail");
    assert_eq!(code, "auth_projector.quarantine");
}

/// Harness recording every mutation call so terminal-quarantine behavior
/// can be asserted without any database.
struct QuarantineHarness {
    outcome: Result<(), String>,
    calls: std::sync::Mutex<Vec<&'static str>>,
}

impl QuarantineHarness {
    fn new(outcome: Result<(), String>) -> Self {
        Self {
            outcome,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn recorded(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl AuthorizationProjectorRuntime for QuarantineHarness {
    async fn claim_next_event(
        &self,
        _scope: &DeltaEventClaimScope,
        _owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        Ok(None)
    }
    async fn read_claimed_event(
        &self,
        _identity: &DeltaLeaseIdentity,
    ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
        unreachable!("harness drives quarantining directly")
    }
    async fn observe_publication_context(
        &self,
        _identity: &ProjectionAggregateIdentity,
    ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
        unreachable!("harness drives quarantining directly")
    }
    async fn load_scope_ledger(
        &self,
        _tenant_id: i64,
        _aggregate_type: &str,
        _aggregate_id: i64,
        _card_id: Option<i64>,
    ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
        unreachable!("harness drives quarantining directly")
    }
    async fn execute_projection_publish(
        &self,
        _command: &DeltaProjectorPublishCommand,
    ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
        unreachable!("harness drives quarantining directly")
    }
    async fn fail_event(
        &self,
        _identity: &DeltaLeaseIdentity,
        backoff_seconds: i64,
        message: &str,
    ) {
        self.calls.lock().unwrap().push("fail");
        let _ = (backoff_seconds, message);
    }
    async fn release_event(&self, _identity: &DeltaLeaseIdentity) {
        self.calls.lock().unwrap().push("release");
    }
    async fn mark_event_quarantined(
        &self,
        _lease: &DeltaLeaseIdentity,
        reason_code: &str,
        _reason_detail: &str,
    ) -> Result<(), RuntimeAccessError> {
        self.calls.lock().unwrap().push("mark");
        assert!(
            !reason_code.is_empty(),
            "stable code part must always reach the repository boundary"
        );
        match self.outcome.clone() {
            Ok(()) => Ok(()),
            Err(text) if text.contains("cas") => Err(RuntimeAccessError::Repository(
                RepositoryRejection::Other(text),
            )),
            Err(text) => Err(RuntimeAccessError::Database(text)),
        }
    }
}

/// F5 修复 1b：任何处理步骤挂起都必须被 event_deadline 收口——计数、
/// 尽力释放租约、循环继续，worker 永不永久停在当次事件内。
#[tokio::test]
async fn event_deadline_releases_lease_and_keeps_the_worker_looping() {
    use std::sync::Mutex as StdMutex;
    struct HangingReadbackRuntime {
        claims: StdMutex<u32>,
        released: StdMutex<Vec<String>>,
    }
    #[async_trait]
    impl AuthorizationProjectorRuntime for HangingReadbackRuntime {
        async fn claim_next_event(
            &self,
            _scope: &DeltaEventClaimScope,
            _owner: &str,
            _lease: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            let mut claims = self.claims.lock().unwrap();
            *claims += 1;
            if *claims == 1 {
                Ok(Some(harness_claim()))
            } else {
                Ok(None)
            }
        }
        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            // 挂起形态（S15 F5 实测）：处理的第一步即永久 pending。
            std::future::pending().await
        }
        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            unreachable!("readback hangs before this seam")
        }
        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            unreachable!("readback hangs before this seam")
        }
        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            unreachable!("readback hangs before this seam")
        }
        async fn fail_event(
            &self,
            _identity: &DeltaLeaseIdentity,
            _backoff_seconds: i64,
            _message: &str,
        ) {
        }
        async fn release_event(&self, identity: &DeltaLeaseIdentity) {
            self.released
                .lock()
                .unwrap()
                .push(identity.event_id.clone());
        }
        async fn mark_event_quarantined(
            &self,
            _lease: &DeltaLeaseIdentity,
            _reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            unreachable!("readback hangs before this seam")
        }
    }

    let runtime = Arc::new(HangingReadbackRuntime {
        claims: StdMutex::new(0),
        released: StdMutex::new(Vec::new()),
    });
    let config = AuthorizationProjectorConfig {
        tenants: vec![1],
        poll_interval_secs: 60,
        event_deadline: Duration::from_millis(60),
        ..Default::default()
    };
    let handle = start_authorization_projector_with_runtime(runtime.clone(), config);
    // 第一轮循环内完成：claim → readback 挂起 → deadline 触发 → 释放 →
    // 下一次 claim 返回空 → 空闲等待 cancellation。
    tokio::time::sleep(Duration::from_millis(400)).await;
    let report = shutdown_authorization_projector(handle, Duration::from_secs(2)).await;
    let summary = report
        .summary
        .expect("worker must stop cleanly after a deadline event");
    assert_eq!(
        summary.events_deadline_exceeded, 1,
        "a hanging step must be converted into exactly one deadline event"
    );
    // 批次 B 调研纪律：deadline 超时不得发布任何租约 mutation——不释放，
    // 由租约过期 reclaim 门接管；因此这里绝不出现 release 记录。
    assert!(
        runtime.released.lock().unwrap().is_empty(),
        "deadline timeout must NOT issue a lease release (unknown commit result)"
    );
    assert!(
        report.join_elapsed < Duration::from_secs(2),
        "cancellation must still stop the worker promptly"
    );
}

/// F5 修复 1d 看门狗：claim 卡死 + 存在可 claim 积压 → 监督循环必须
/// 在停滞阈值后重建 worker 代（generation 前进、restarts 计数）。
#[tokio::test]
async fn watchdog_rebuilds_stalled_generation_when_claimable_backlog_exists() {
    use std::sync::atomic::AtomicBool;
    struct WedgedClaimRuntime {
        claimable: AtomicBool,
    }
    #[async_trait]
    impl AuthorizationProjectorRuntime for WedgedClaimRuntime {
        async fn claim_next_event(
            &self,
            _scope: &DeltaEventClaimScope,
            _owner: &str,
            _lease: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            // 卡死形态：claim 永不返回，进展永不推进（S15 F5 残余面）。
            std::future::pending().await
        }
        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn fail_event(
            &self,
            _identity: &DeltaLeaseIdentity,
            _backoff_seconds: i64,
            _message: &str,
        ) {
        }
        async fn release_event(&self, _identity: &DeltaLeaseIdentity) {}
        async fn mark_event_quarantined(
            &self,
            _lease: &DeltaLeaseIdentity,
            _reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn has_claimable_work(&self, _scope: &DeltaEventClaimScope) -> bool {
            self.claimable.load(Ordering::Acquire)
        }
    }

    let runtime = Arc::new(WedgedClaimRuntime {
        claimable: AtomicBool::new(true),
    });
    let config = AuthorizationProjectorConfig {
        tenants: vec![1],
        poll_interval_secs: 60,
        watchdog_stall_threshold: Duration::from_millis(150),
        watchdog_tick: Duration::from_millis(50),
        ..Default::default()
    };
    let handle = start_authorization_projector_with_runtime(runtime, config);
    // 看门狗应在停滞阈值后重建当前代：generation 前进且 restarts 计数。
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = handle.health_snapshot();
        if snapshot.generation >= 2 && snapshot.restarts >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "watchdog never rebuilt the stalled generation (gen={} restarts={})",
            snapshot.generation,
            snapshot.restarts
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // 当前代卡死且忽略取消 → shutdown 有界宽限后如实上报失败。
    let report = shutdown_authorization_projector(handle, Duration::from_secs(2)).await;
    assert!(
        report.summary.is_err(),
        "wedged generation must surface as Err on shutdown"
    );
}

/// F5 修复 1d 看门狗负例：无积压（runtime 报告无可 claim 事件）→ 停滞
/// 不触发重建，空队列的挂起不会制造无意义的代重启。
#[tokio::test]
async fn watchdog_does_not_rebuild_without_claimable_backlog() {
    use std::sync::atomic::AtomicBool;
    struct WedgedClaimRuntimeNoBacklog {
        claimable: AtomicBool,
    }
    #[async_trait]
    impl AuthorizationProjectorRuntime for WedgedClaimRuntimeNoBacklog {
        async fn claim_next_event(
            &self,
            _scope: &DeltaEventClaimScope,
            _owner: &str,
            _lease: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            std::future::pending().await
        }
        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn fail_event(
            &self,
            _identity: &DeltaLeaseIdentity,
            _backoff_seconds: i64,
            _message: &str,
        ) {
        }
        async fn release_event(&self, _identity: &DeltaLeaseIdentity) {}
        async fn mark_event_quarantined(
            &self,
            _lease: &DeltaLeaseIdentity,
            _reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            unreachable!("claim wedges before this seam")
        }
        async fn has_claimable_work(&self, _scope: &DeltaEventClaimScope) -> bool {
            self.claimable.load(Ordering::Acquire)
        }
    }

    let runtime = Arc::new(WedgedClaimRuntimeNoBacklog {
        claimable: AtomicBool::new(false),
    });
    let config = AuthorizationProjectorConfig {
        tenants: vec![1],
        poll_interval_secs: 60,
        watchdog_stall_threshold: Duration::from_millis(100),
        watchdog_tick: Duration::from_millis(40),
        ..Default::default()
    };
    let handle = start_authorization_projector_with_runtime(runtime, config);
    // 远超停滞阈值：无积压 → 不得重建（generation 恒为 1、restarts 为 0）。
    tokio::time::sleep(Duration::from_millis(400)).await;
    let snapshot = handle.health_snapshot();
    assert_eq!(
        snapshot.generation, 1,
        "no backlog must never trigger a forced rebuild"
    );
    assert_eq!(snapshot.restarts, 0);
    let report = shutdown_authorization_projector(handle, Duration::from_secs(2)).await;
    assert!(
        report.summary.is_err(),
        "wedged child must still fail shutdown honestly"
    );
}

fn harness_claim() -> DeltaEventClaim {
    let owner = grant(1, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let delta = astral_types::GrantDelta::add(owner.clone());
    let readback = claimed_event(&owner, &delta, 5, 0, "evt-q", "op-q", &dep_hash);
    DeltaEventClaim {
        delta_event_id: readback.delta_event_id,
        event_id: readback.event_id,
        operation_id: readback.operation_id,
        event_type: readback.event_type,
        tenant_id: readback.tenant_id,
        card_id: readback.card_id,
        aggregate_type: readback.aggregate_type,
        aggregate_id: readback.aggregate_id,
        grant_id: readback.grant_id,
        base_version: readback.base_version,
        target_version: readback.target_version,
        source_generation: readback.source_generation,
        revoke_fence: readback.revoke_fence,
        before_image_json: readback.before_image_json.clone(),
        before_digest: readback.before_digest,
        delta_json: readback.delta_json.clone(),
        semantic_hash: readback.semantic_hash,
        dependency_hash: readback.dependency_hash,
        compiler_version: readback.compiler_version.clone(),
        attempts: readback.attempts,
        cas_version: readback.cas_version,
        lease_owner: readback.lease_owner.clone(),
        lease_token: astral_db::DeltaLeaseToken::for_test("secret-test-token"),
        lease_expires_at: readback.lease_expires_at,
    }
}

struct ReplanHarness {
    publish_steps: std::sync::Mutex<std::collections::VecDeque<ReplanPublishStep>>,
    calls: std::sync::Mutex<Vec<&'static str>>,
}

enum ReplanPublishStep {
    PointerMoved,
    GenericRetry,
    LeaseLost,
    CommitUnknown,
    InstallAfterCommitFailed,
    Success,
}

impl ReplanHarness {
    fn new(steps: impl IntoIterator<Item = ReplanPublishStep>) -> Self {
        Self {
            publish_steps: std::sync::Mutex::new(steps.into_iter().collect()),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

fn replan_readback() -> ClaimedDeltaEvent {
    let owner = grant(1, 1, GrantState::Active);
    let (_, dep_hash) = active_card_dependency_hash(5, 0);
    let delta = astral_types::GrantDelta::add(owner.clone());
    claimed_event(&owner, &delta, 5, 0, "evt-q", "op-q", &dep_hash)
}

fn replan_success() -> DeltaProjectorPublishOutcome {
    let identity = ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap();
    let pointer = AuthorizationCurrentPointerRecord {
        pointer_id: 1,
        identity,
        card_id: Some(17),
        current_generation: 1,
        manifest_id: 1,
        event_id: "evt-q".to_owned(),
        operation_id: "op-q".to_owned(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
        revoke_fence: 0,
        revoke_fence_proven: true,
        cas_version: 1,
    };
    let published_state = Arc::new(astral_db::AuthorizationPublishedState {
        pointer: pointer.clone(),
        manifest_id: pointer.manifest_id,
        generation: pointer.current_generation,
        source_generation: 5,
        projected_generation: 5,
        event_id: pointer.event_id.clone(),
        operation_id: pointer.operation_id.clone(),
        semantic_hash: pointer.semantic_hash,
        dependency_hash: pointer.dependency_hash,
        compiler_version: pointer.compiler_version.clone(),
        manifest_digest: Sha256Digest::from_hex(HASH_A).unwrap(),
        parent_manifest_id: None,
        revoke_fence: pointer.revoke_fence,
        segments: Vec::new(),
        references: Vec::new(),
        total_grant_count: 1,
    });
    DeltaProjectorPublishOutcome {
        impact_plan: astral_db::AuthorizationImpactPlanOutcome {
            plan_id: 1,
            resumed_existing_plan: false,
            item_count: 1,
        },
        stage: astral_db::AuthorizationStageOutcome {
            manifest_id: 1,
            manifest_digest: Sha256Digest::from_hex(HASH_A).unwrap(),
            target_generation: 1,
            total_grant_count: 1,
            new_segment_count: 1,
            reused_segment_count: 0,
            resumed_existing_manifest: false,
            base_pointer: None,
        },
        archive_intent: None,
        publish: astral_db::AuthorizationPublishOutcome {
            pointer,
            published_state,
            published_manifest_id: 1,
            previous_superseded_manifest_id: None,
            initialized_first_pointer: true,
        },
    }
}

#[async_trait]
impl AuthorizationProjectorRuntime for ReplanHarness {
    async fn claim_next_event(
        &self,
        _scope: &DeltaEventClaimScope,
        _lease_owner: &str,
        _lease_seconds: i64,
    ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
        unreachable!("replan tests call process_one_event directly")
    }

    async fn read_claimed_event(
        &self,
        _identity: &DeltaLeaseIdentity,
    ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
        self.calls.lock().unwrap().push("read");
        Ok(replan_readback())
    }

    async fn observe_publication_context(
        &self,
        _identity: &ProjectionAggregateIdentity,
    ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
        self.calls.lock().unwrap().push("observe");
        Ok(None)
    }

    async fn load_scope_ledger(
        &self,
        _tenant_id: i64,
        _aggregate_type: &str,
        _aggregate_id: i64,
        _card_id: Option<i64>,
    ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
        self.calls.lock().unwrap().push("ledger");
        let owner = grant(1, 1, GrantState::Active);
        Ok(vec![raw_row(&owner, "evt-q", "op-q", 0)])
    }

    async fn execute_projection_publish(
        &self,
        _command: &DeltaProjectorPublishCommand,
    ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
        self.calls.lock().unwrap().push("publish");
        match self
                .publish_steps
                .lock()
                .unwrap()
                .pop_front()
                .expect("test supplied a publish step for every attempt")
            {
                ReplanPublishStep::PointerMoved => Err(projection_failure(
                    AuthorizationProjectionError::ScopeViolation(
                        "code=authorization_projection.command_base_generation_mismatch;expected=1;actual=2"
                            .to_owned(),
                    ),
                )),
                ReplanPublishStep::GenericRetry => {
                    Err(RuntimeAccessError::Database("synthetic query failure".to_owned()))
                }
                ReplanPublishStep::LeaseLost => Err(projection_failure(
                    AuthorizationProjectionError::LeaseCasFailed(
                        "code=grant_repository.complete_lost_lease;event=evt-q".to_owned(),
                    ),
                )),
                ReplanPublishStep::CommitUnknown => Err(RuntimeAccessError::PublicationUnknown(
                    "code=auth_projector.publish_commit_unknown;event=evt-q".to_owned(),
                )),
                ReplanPublishStep::InstallAfterCommitFailed => Err(RuntimeAccessError::CommittedMirrorUnavailable(
                    "code=auth_projector.memory_install_after_commit_failed;event=evt-q".to_owned(),
                )),
                ReplanPublishStep::Success => Ok(replan_success()),
            }
    }

    async fn fail_event(
        &self,
        _identity: &DeltaLeaseIdentity,
        _backoff_seconds: i64,
        _message: &str,
    ) {
        self.calls.lock().unwrap().push("fail");
    }

    async fn release_event(&self, _identity: &DeltaLeaseIdentity) {
        self.calls.lock().unwrap().push("release");
    }

    async fn mark_event_quarantined(
        &self,
        _lease: &DeltaLeaseIdentity,
        _reason_code: &str,
        _reason_detail: &str,
    ) -> Result<(), RuntimeAccessError> {
        self.calls.lock().unwrap().push("mark");
        unreachable!("replan tests do not enter quarantine")
    }
}

#[tokio::test]
async fn shared_ledger_default_preserves_the_owned_runtime_contract() {
    let harness = ReplanHarness::new([]);
    let owned = harness
        .load_scope_ledger(7, "CARD", 17, Some(17))
        .await
        .unwrap();
    let shared = harness
        .load_scope_ledger_shared(7, "CARD", 17, Some(17))
        .await
        .unwrap();
    assert_eq!(owned.len(), shared.len());
    for (owned, shared) in owned.iter().zip(shared.iter()) {
        assert_eq!(owned.grant_payload, shared.grant_payload);
        assert_eq!(owned.semantic_hash, shared.semantic_hash);
        assert_eq!(owned.event_id, shared.event_id);
        assert_eq!(owned.revision_no, shared.revision_no);
    }
    assert_eq!(harness.calls(), ["ledger", "ledger"]);
}

async fn run_replan_test(
    harness: &std::sync::Arc<ReplanHarness>,
    summary: &mut WorkerRunSummary,
    claimed: &DeltaEventClaim,
) {
    let runtime: std::sync::Arc<dyn AuthorizationProjectorRuntime> = harness.clone();
    let config = AuthorizationProjectorConfig {
        tenants: vec![7],
        ..Default::default()
    };
    let cancellation = ProjectorCancellationToken::default();
    process_one_event(
        &runtime,
        &config,
        "auth-projector:test-run",
        &cancellation,
        claimed,
        summary,
    )
    .await;
}

#[tokio::test]
async fn pointer_moved_replans_under_one_lease_then_publishes() {
    let harness = std::sync::Arc::new(ReplanHarness::new([
        ReplanPublishStep::PointerMoved,
        ReplanPublishStep::PointerMoved,
        ReplanPublishStep::Success,
    ]));
    let claimed = harness_claim();
    let mut summary = WorkerRunSummary::default();
    run_replan_test(&harness, &mut summary, &claimed).await;

    assert_eq!(summary.events_pointer_moved_replanned, 2);
    assert_eq!(summary.events_published, 1);
    assert_eq!(summary.events_released_retry, 0);
    assert_eq!(summary.events_budget_exhausted, 0);
    assert_eq!(
        harness.calls(),
        vec![
            "read", "observe", "ledger", "publish", "observe", "ledger", "publish", "observe",
            "ledger", "publish",
        ]
    );
    assert!(
        !harness.calls().contains(&"fail") && !harness.calls().contains(&"release"),
        "in-place replans must not mutate the lease"
    );
}

#[tokio::test]
async fn pointer_moved_replan_exhaustion_enters_budget_once() {
    let harness = std::sync::Arc::new(ReplanHarness::new([
        ReplanPublishStep::PointerMoved,
        ReplanPublishStep::PointerMoved,
        ReplanPublishStep::PointerMoved,
        ReplanPublishStep::PointerMoved,
    ]));
    let claimed = harness_claim();
    let mut summary = WorkerRunSummary::default();
    run_replan_test(&harness, &mut summary, &claimed).await;

    assert_eq!(
        summary.events_pointer_moved_replanned,
        MAX_POINTER_MOVED_REPLANS as u64
    );
    assert_eq!(summary.events_released_retry, 1);
    assert_eq!(summary.events_budget_exhausted, 0);
    assert_eq!(
        harness
            .calls()
            .iter()
            .filter(|call| **call == "publish")
            .count(),
        4
    );
    assert_eq!(
        harness
            .calls()
            .iter()
            .filter(|call| **call == "fail")
            .count(),
        1
    );
    assert!(!harness.calls().contains(&"release"));
}

#[tokio::test]
async fn generic_publish_failure_does_not_enter_replan() {
    let harness = std::sync::Arc::new(ReplanHarness::new([ReplanPublishStep::GenericRetry]));
    let claimed = harness_claim();
    let mut summary = WorkerRunSummary::default();
    run_replan_test(&harness, &mut summary, &claimed).await;

    assert_eq!(summary.events_pointer_moved_replanned, 0);
    assert_eq!(summary.events_released_retry, 1);
    assert_eq!(
        harness.calls(),
        vec!["read", "observe", "ledger", "publish", "fail"]
    );
}

#[tokio::test]
async fn lease_loss_during_replan_stops_without_followup_mutation() {
    let harness = std::sync::Arc::new(ReplanHarness::new([
        ReplanPublishStep::PointerMoved,
        ReplanPublishStep::LeaseLost,
    ]));
    let claimed = harness_claim();
    let mut summary = WorkerRunSummary::default();
    run_replan_test(&harness, &mut summary, &claimed).await;

    assert_eq!(summary.events_pointer_moved_replanned, 1);
    assert_eq!(summary.events_lease_lost, 1);
    assert_eq!(summary.events_released_retry, 0);
    assert_eq!(summary.events_budget_exhausted, 0);
    assert_eq!(
        harness
            .calls()
            .iter()
            .filter(|call| **call == "publish")
            .count(),
        2
    );
    assert!(!harness.calls().contains(&"fail"));
    assert!(!harness.calls().contains(&"release"));
    assert!(!harness.calls().contains(&"mark"));
}

#[tokio::test]
async fn unknown_commit_or_post_commit_install_never_replays_or_mutates_lease() {
    for (step, commit_unknown) in [
        (ReplanPublishStep::CommitUnknown, true),
        (ReplanPublishStep::InstallAfterCommitFailed, false),
    ] {
        let harness = Arc::new(ReplanHarness::new([step]));
        let claimed = harness_claim();
        let mut summary = WorkerRunSummary::default();
        run_replan_test(&harness, &mut summary, &claimed).await;
        assert_eq!(summary.events_published, 0);
        assert_eq!(
            summary.events_publication_unknown,
            u64::from(commit_unknown)
        );
        assert_eq!(
            summary.events_committed_mirror_unavailable,
            u64::from(!commit_unknown)
        );
        assert_eq!(summary.events_lease_lost, 0);
        assert_eq!(summary.events_released_retry, 0);
        assert_eq!(
            harness.calls(),
            vec!["read", "observe", "ledger", "publish"]
        );
    }
}

#[test]
fn local_mirror_install_follows_commit_and_precedes_optional_l2() {
    // 拆分后该发布时序位于 runtime seam 模块（SqlxAuthorizationProjectorRuntime）。
    let source = include_str!("../authorization_projector/runtime.rs");
    let body = source
        .split("let outcome = project_authorization_delta_in_tx")
        .nth(1)
        .unwrap()
        .split("async fn fail_event")
        .next()
        .unwrap();
    let commit = body.find("tx.commit()").unwrap();
    let install = body.find("install_committed_publication").unwrap();
    let l2 = body
        .find("push_published_evidence_to_l2_after_commit")
        .unwrap();
    assert!(commit < install && install < l2);
    assert!(!body.contains("refresh_from_durable"));
}

#[test]
fn pointer_moved_replan_summary_merges() {
    let mut aggregate = WorkerRunSummary::default();
    let one = WorkerRunSummary {
        events_pointer_moved_replanned: 2,
        ..WorkerRunSummary::default()
    };
    aggregate.merge(&one);
    assert_eq!(aggregate.events_pointer_moved_replanned, 2);
}
#[tokio::test]
async fn terminal_quarantine_writes_mark_and_records_success() {
    let harness = Arc::new(QuarantineHarness::new(Ok(())));
    let runtime: Arc<dyn AuthorizationProjectorRuntime> = harness.clone();
    let identity = DeltaLeaseIdentity {
        delta_event_id: 77,
        event_id: "evt-q".to_owned(),
        lease_owner: "auth-projector:test-run".to_owned(),
        lease_token: astral_db::DeltaLeaseToken::for_test("secret-test-token"),
    };
    let claimed = harness_claim();
    let mut summary = WorkerRunSummary::default();
    let started = Instant::now();
    quarantine_event_terminal(
        &runtime,
        &identity,
        &claimed,
        "code=auth_projector.no_effective_change;fenced",
        &started,
        &mut summary,
    )
    .await;
    assert_eq!(summary.events_quarantined, 1);
    assert_eq!(summary.events_quarantine_unknown, 0);
    assert_eq!(harness.recorded(), vec!["mark"], "exactly one CAS write");
}

#[tokio::test]
async fn terminal_quarantine_unknown_results_issue_no_followup_mutation() {
    for flavor in ["cas", "query"] {
        let outcome_text = if flavor == "cas" {
            Err("cas: code=grant_repository.quarantine_lost_lease;event=x".to_owned())
        } else {
            Err(String::from("query: connection reset during write"))
        };
        let harness = Arc::new(QuarantineHarness::new(outcome_text));
        let runtime: Arc<dyn AuthorizationProjectorRuntime> = harness.clone();
        let identity = DeltaLeaseIdentity {
            delta_event_id: 77,
            event_id: "evt-q".to_owned(),
            lease_owner: "auth-projector:test-run".to_owned(),
            lease_token: astral_db::DeltaLeaseToken::for_test("secret-test-token"),
        };
        let claimed = harness_claim();
        let mut summary = WorkerRunSummary::default();
        let started = Instant::now();
        quarantine_event_terminal(
            &runtime,
            &identity,
            &claimed,
            "code=auth_projector.compile_conflict;conflict=DuplicateDelta",
            &started,
            &mut summary,
        )
        .await;
        assert_eq!(
            summary.events_quarantine_unknown, 1,
            "{flavor}: UNKNOWN outcome must be counted"
        );
        assert_eq!(
            summary.events_quarantined, 0,
            "{flavor}: nothing proven durable may count as quarantined"
        );
        assert_eq!(
            harness.recorded(),
            vec!["mark"],
            "{flavor}: no fail/release/retry after an unknown terminal write"
        );
    }
}

#[tokio::test]
async fn budget_exhaustion_stays_pending_and_never_fakes_terminal_states() {
    let harness = Arc::new(QuarantineHarness::new(Ok(())));
    let runtime: Arc<dyn AuthorizationProjectorRuntime> = harness.clone();
    let identity = DeltaLeaseIdentity {
        delta_event_id: 77,
        event_id: "evt-q".to_owned(),
        lease_owner: "auth-projector:test-run".to_owned(),
        lease_token: astral_db::DeltaLeaseToken::for_test("secret-test-token"),
    };
    let mut claimed = harness_claim();
    claimed.attempts = MAX_EVENT_ATTEMPTS; // exhausted budget
    let mut summary = WorkerRunSummary::default();
    fail_with_budget(
        &runtime,
        &identity,
        &claimed,
        DispositionKind::Blocked,
        0,
        "code=auth_projector.blocked_forever",
        &mut summary,
    )
    .await;
    assert_eq!(summary.events_budget_exhausted, 1);
    assert_eq!(summary.events_blocked, 1);
    assert_eq!(
        harness.recorded(),
        vec!["fail"],
        "budget exhaustion keeps the PENDING fail path alive"
    );
    // The exhaustion marker rides along inside the durable last_error.
}

#[test]
fn locate_claimed_candidate_maps_every_exclusion_kind() {
    use astral_db::{CandidateLedgerRow, ExcludedLedgerRow};

    fn synthetic_entry(event_id: &str) -> GrantLedgerEntry {
        let row = RawLedgerRow {
            revision_no: 1,
            tenant_id: 7,
            card_id: Some(17),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 17,
            grant_id: grant_id_for(1).to_string(),
            status: "ACTIVE".to_owned(),
            is_tombstone: 0,
            grant_payload: serde_json::to_string(&grant(1, 1, GrantState::Active)).unwrap(),
            semantic_hash: {
                let digest = Sha256Digest::from_hex(HASH_A).unwrap();
                digest.as_bytes().to_vec()
            },
            dependency_hash: {
                let digest = Sha256Digest::from_hex(HASH_B).unwrap();
                digest.as_bytes().to_vec()
            },
            operation_id: "op".to_owned(),
            event_id: event_id.to_owned(),
            compiler_version: policy_engine::COMPILER_VERSION.to_owned(),
        };
        decode_ledger_row(&row).unwrap()
    }

    fn empty_partition() -> PartitionedGrantLedgerAtFrontier {
        PartitionedGrantLedgerAtFrontier::default()
    }

    // Missing entirely.
    match locate_claimed_candidate(&empty_partition(), "evt-x") {
        LocatedCandidate::MissingFromLedger => {}
        other => panic!("empty partition must miss, got {other:?}"),
    }

    // Stale classification maps to reconciliation-grade quarantine intent.
    let stale = PartitionedGrantLedgerAtFrontier {
        excluded_rows: vec![ExcludedLedgerRow {
            entry: synthetic_entry("evt-x"),
            kind: astral_db::LedgerExclusionKind::StaleClaimBehindPublishedFrontier,
        }],
        ..PartitionedGrantLedgerAtFrontier::default()
    };
    match locate_claimed_candidate(&stale, "evt-x") {
        LocatedCandidate::StaleBehindPublishedFrontier => {}
        other => panic!("stale claim must classify, got {other:?}"),
    }

    // Sibling-blocked classification keeps its Blocked semantics.
    let behind = PartitionedGrantLedgerAtFrontier {
        excluded_rows: vec![ExcludedLedgerRow {
            entry: synthetic_entry("evt-y"),
            kind: astral_db::LedgerExclusionKind::ClaimedBehindUnpublishedSiblings,
        }],
        ..PartitionedGrantLedgerAtFrontier::default()
    };
    match locate_claimed_candidate(&behind, "evt-y") {
        LocatedCandidate::BehindUnpublishedSiblings => {}
        other => panic!("behind-sibling claim must classify, got {other:?}"),
    }

    // NotProvenPublished on OUR id contradicts claimed-set membership.
    let contradictory = PartitionedGrantLedgerAtFrontier {
        excluded_rows: vec![ExcludedLedgerRow {
            entry: synthetic_entry("evt-z"),
            kind: astral_db::LedgerExclusionKind::NotProvenPublished,
        }],
        ..PartitionedGrantLedgerAtFrontier::default()
    };
    match locate_claimed_candidate(&contradictory, "evt-z") {
        LocatedCandidate::OwnClaimNotRecognized => {}
        other => panic!("contradiction must surface defensively, got {other:?}"),
    }

    // Duplicate candidates are ambiguous even though the partitioner
    // aborts them first — the contradiction never collapses silently.
    let ambiguous = PartitionedGrantLedgerAtFrontier {
        candidate_rows: vec![
            CandidateLedgerRow {
                entry: synthetic_entry("evt-dup"),
            },
            CandidateLedgerRow {
                entry: synthetic_entry("evt-dup2"),
            },
        ],
        ..PartitionedGrantLedgerAtFrontier::default()
    };
    let second = locate_claimed_candidate(&ambiguous, "evt-dup2");
    match second {
        LocatedCandidate::Found(_) => {}
        other => panic!("distinct second candidate stays found, got {other:?}"),
    }
    let doubled_same = PartitionedGrantLedgerAtFrontier {
        candidate_rows: vec![
            CandidateLedgerRow {
                entry: synthetic_entry("evt-dup"),
            },
            CandidateLedgerRow {
                entry: {
                    let mut e = synthetic_entry("evt-dup");
                    e.revision_no += 1;
                    e
                },
            },
        ],
        ..PartitionedGrantLedgerAtFrontier::default()
    };
    match locate_claimed_candidate(&doubled_same, "evt-dup") {
        LocatedCandidate::Ambiguous => {}
        other => panic!("duplicate candidates must be ambiguous, got {other:?}"),
    }
}

#[test]
fn disposition_kind_mapping_is_total() {
    let cases: [(EventDisposition, DispositionKind); 4] = [
        (
            EventDisposition::Retry { reason: "x".into() },
            DispositionKind::ReleasedRetry,
        ),
        (
            EventDisposition::Quarantine { reason: "y".into() },
            DispositionKind::Quarantined,
        ),
        (
            EventDisposition::Blocked { reason: "z".into() },
            DispositionKind::Blocked,
        ),
        (
            EventDisposition::Superseded { reason: "w".into() },
            DispositionKind::SupersededRelease,
        ),
    ];
    for (disposition, expected) in cases {
        assert_eq!(disposition.kind(), expected);
    }
}
