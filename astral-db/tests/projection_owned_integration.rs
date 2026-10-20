//! Real-MySQL contract tests for worker-owned projection execution.
//!
//! This binary has one ignored tokio test because execution mode is process-global
//! and frozen through `OnceLock`. It accepts only the approved run-scoped
//! loopback:3308 clone and never runs DDL or migrations. Every source row uses
//! UUID-derived tenant, aggregate, event, operation and grant identity. Cleanup
//! is reached only after all assertions and a final quiescence proof; any panic,
//! timeout or uncertain result leaves the fixture intact for reconciliation.
//!
//! Required environment: `RUST_INTEGRATION_REQUIRED=1`, `TEST_USE_EXISTING=1`,
//! `ASTRAL_MIGRATION_ENV=isolated`, `ASTRAL_TEST_DATABASE_NAME`, and `DATABASE_URL`.

use astral_db::{
    acquire_partition_lease, append_delta_event, begin_owned_delta_execution,
    claim_delta_event_by_stable_event_in_tx, claim_next_delta_event_in_tx,
    claim_next_owned_delta_event, claim_owned_delta_event_by_stable_event, complete_delta_event,
    extend_delta_event_lease, extend_owned_delta_execution_lease, fail_delta_event,
    fail_owned_delta_event, freeze_projection_execution_mode, mark_delta_event_quarantined,
    project_owned_authorization_delta_in_tx, publish_current_pointer_in_tx,
    quarantine_owned_delta_event, release_delta_event_lease, release_owned_delta_event,
    validate_projection_owned_schema, AuthorizationImpactPlanAppendRequest,
    AuthorizationPublishRequest, AuthorizationStageRequest, CompileModeEvidence,
    DeltaEventAppendRequest, DeltaEventClaimScope, DeltaEventType, DeltaLeaseIdentity,
    DeltaLeaseToken, DeltaProjectorExpectation, DeltaProjectorPublishCommand, GrantRepositoryError,
    OwnedStableEventOutcome, ProjectionAggregateIdentity, ProjectionExecutionMode,
    PublishRevokeFenceEvidence,
};
use astral_types::{
    BindingLayer, CanonicalGrant, GrantDelta, GrantEffect, GrantId, GrantProvenance, GrantRevision,
    GrantSourceKind, GrantState, ProjectionCompileMode, TenantScope, ValidityWindow,
};
use sha2::Digest;
use sqlx::{
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
    FromRow, MySqlPool,
};
use std::{env, str::FromStr, sync::Arc, time::Duration};
use time::PrimitiveDateTime;
use tokio::sync::Barrier;
use uuid::Uuid;

const REQUIRED_MIGRATION_VERSION: i64 = 20261015000001;
const REQUIRED_DATABASE_PREFIX: &str = "astral_rehearsal_";
const TEST_DEADLINE: Duration = Duration::from_secs(110);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const CLAIM_LEASE_SECONDS: i64 = 90;

#[derive(Clone)]
struct Namespace {
    salt: u128,
    tenant_id: i64,
    card_id: i64,
    aggregate_id: i64,
    user_id: i64,
}

impl Namespace {
    fn new() -> Self {
        let salt = Uuid::new_v4().as_u128();
        let base = 8_000_000_000_000_i64 + ((salt % 1_000_000_000) as i64) * 1_000;
        Self {
            salt,
            tenant_id: base,
            card_id: base + 1,
            aggregate_id: base + 2,
            user_id: base + 3,
        }
    }

    fn identity(&self) -> ProjectionAggregateIdentity {
        ProjectionAggregateIdentity::new(self.tenant_id, "USER_CARD", self.aggregate_id)
            .expect("run-owned aggregate identity is valid")
    }

    fn event_id(&self, tag: &str) -> String {
        format!("evt-po-{:032x}-{tag}", self.salt)
    }

    fn operation_id(&self, tag: &str) -> String {
        format!("op-po-{:032x}-{tag}", self.salt)
    }

    fn owner(&self, tag: &str) -> String {
        format!("worker-po-{:032x}-{tag}", self.salt)
    }

    fn grant_id(&self, ordinal: u64) -> GrantId {
        let tail = ((self.salt as u64).wrapping_add(ordinal)) & 0x0000_ffff_ffff_ffff;
        GrantId::parse(&format!("550e8400-e29b-41d4-a716-{tail:012x}"))
            .expect("fixture grant id is a valid UUID")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
struct EventState {
    attempts: i64,
    execution_attempts: i64,
    execution_failures: i64,
    execution_accounting_version: i32,
    status: String,
    lease_owner: Option<String>,
    lease_token_hash: Option<Vec<u8>>,
    lease_expires_at: Option<PrimitiveDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
struct LaneState {
    execution_epoch: i64,
    lease_owner: String,
    lease_token_hash: Vec<u8>,
    lease_expires_at: PrimitiveDateTime,
    active_delta_event_id: Option<i64>,
    active_delta_token_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, FromRow)]
struct PointerState {
    pointer_id: i64,
    current_generation: i64,
    manifest_id: i64,
    event_id: String,
    operation_id: String,
    cas_version: i64,
}

fn request_for(
    namespace: &Namespace,
    tag: &str,
    grant_id: GrantId,
    event_type: DeltaEventType,
    base_version: i64,
    target_version: i64,
    source_generation: u64,
    delta: GrantDelta,
) -> DeltaEventAppendRequest {
    DeltaEventAppendRequest {
        tenant_id: namespace.tenant_id,
        card_id: Some(namespace.card_id),
        aggregate_type: "USER_CARD".to_owned(),
        aggregate_id: namespace.aggregate_id,
        grant_id,
        event_id: namespace.event_id(tag),
        operation_id: namespace.operation_id(tag),
        event_type,
        base_version,
        target_version,
        source_generation,
        revoke_fence: 0,
        invalidates_published_evidence: false,
        before_image_json: None,
        before_digest_hex: None,
        delta_json: serde_json::to_string(&delta).expect("typed delta serializes"),
        semantic_hash_hex: format!("{:x}", sha2::Sha256::digest(namespace.event_id(tag))),
        dependency_hash_hex: format!("{:x}", sha2::Sha256::digest(namespace.operation_id(tag))),
        compiler_version: "owned-contract-test-v1".to_owned(),
        next_attempt_at: None,
    }
}

fn add_request(namespace: &Namespace, tag: &str, ordinal: u64) -> DeltaEventAppendRequest {
    let grant_id = namespace.grant_id(ordinal);
    let operation_id = namespace.operation_id(tag);
    let event_id = namespace.event_id(tag);
    let grant = CanonicalGrant {
        grant_id,
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: TenantScope::new(namespace.tenant_id, None).expect("fixture tenant scope"),
        card_id: namespace.card_id,
        user_id: namespace.user_id,
        resource: format!("owned_contract_resource_{ordinal}"),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: format!("owned-contract-source-{ordinal}"),
            source_entry: Some(format!("owned-contract-entry-{ordinal}")),
            binding_id: Some(format!("owned-contract-binding-{}", namespace.card_id)),
            delegation_id: None,
            operation_id,
            event_id: Some(event_id),
            actor_user_id: Some(namespace.user_id),
        },
    };
    request_for(
        namespace,
        tag,
        grant_id,
        DeltaEventType::Add,
        0,
        1,
        1,
        GrantDelta::add(grant),
    )
}

fn successor_request(
    namespace: &Namespace,
    predecessor: &DeltaEventAppendRequest,
) -> DeltaEventAppendRequest {
    let tag = "first-successor";
    let GrantDelta::Add { mut grant } =
        serde_json::from_str(&predecessor.delta_json).expect("predecessor is a typed ADD")
    else {
        panic!("predecessor fixture must remain an ADD");
    };
    grant.revision = GrantRevision::initial()
        .next()
        .expect("successor revision exists");
    grant.provenance.operation_id = namespace.operation_id(tag);
    grant.provenance.event_id = Some(namespace.event_id(tag));
    request_for(
        namespace,
        tag,
        predecessor.grant_id,
        DeltaEventType::Update,
        1,
        2,
        2,
        GrantDelta::update(grant, GrantRevision::initial()),
    )
}

async fn required_pool() -> MySqlPool {
    assert_eq!(
        env::var("RUST_INTEGRATION_REQUIRED").as_deref(),
        Ok("1"),
        "RUST_INTEGRATION_REQUIRED=1 is mandatory; this test never silently skips"
    );
    assert_eq!(
        env::var("TEST_USE_EXISTING").as_deref(),
        Ok("1"),
        "the caller must supply the already-created run-owned database"
    );
    assert_eq!(
        env::var("ASTRAL_MIGRATION_ENV").as_deref(),
        Ok("isolated"),
        "the caller must identify the isolated test environment"
    );

    let expected_database = env::var("ASTRAL_TEST_DATABASE_NAME")
        .expect("ASTRAL_TEST_DATABASE_NAME must name the approved clone");
    let suffix = expected_database
        .strip_prefix(REQUIRED_DATABASE_PREFIX)
        .expect("database must use the projection-owner run-scoped prefix");
    assert!(
        !suffix.is_empty()
            && suffix.len() <= 47
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
        "database name must have a bounded lowercase run suffix"
    );

    let url = env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("DATABASE_URL is mandatory when RUST_INTEGRATION_REQUIRED=1");
    assert!(
        !url.contains('?') && !url.contains('#'),
        "database URL query parameters and fragments are not allowed"
    );
    let options = MySqlConnectOptions::from_str(&url).expect("DATABASE_URL must parse");
    assert!(
        matches!(options.get_host(), "localhost" | "127.0.0.1" | "::1"),
        "owned contract tests may only use loopback MySQL"
    );
    assert_eq!(
        options.get_port(),
        3308,
        "expected isolated MySQL port 3308"
    );
    assert!(
        options.get_socket().is_none(),
        "socket URLs are not accepted"
    );
    assert_eq!(
        options.get_database(),
        Some(expected_database.as_str()),
        "DATABASE_URL must select exactly ASTRAL_TEST_DATABASE_NAME"
    );

    let pool = MySqlPoolOptions::new()
        .max_connections(6)
        .acquire_timeout(CONNECT_TIMEOUT)
        .connect_with(options)
        .await
        .expect("required isolated MySQL connection must succeed");
    validate_projection_owned_schema(&pool)
        .await
        .expect("owned execution schema and existing rows must validate read-only");
    let migration: Option<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE version = ? AND success = TRUE",
    )
    .bind(REQUIRED_MIGRATION_VERSION)
    .fetch_optional(&pool)
    .await
    .expect("read the already-applied owned execution migration marker");
    assert_eq!(
        migration,
        Some(REQUIRED_MIGRATION_VERSION),
        "the owned execution migration must already be applied"
    );
    pool
}

async fn event_state(pool: &MySqlPool, request: &DeltaEventAppendRequest) -> EventState {
    sqlx::query_as(
        "SELECT attempts, execution_attempts, execution_failures, execution_accounting_version, \
         status, lease_owner, lease_token_hash, lease_expires_at \
         FROM authorization_delta_event WHERE tenant_id = ? AND aggregate_type = ? \
           AND aggregate_id = ? AND event_id = ?",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .bind(&request.event_id)
    .fetch_one(pool)
    .await
    .expect("read exact run-owned delta state")
}

async fn lane_state(pool: &MySqlPool, namespace: &Namespace) -> Option<LaneState> {
    sqlx::query_as(
        "SELECT execution_epoch, lease_owner, lease_token_hash, lease_expires_at, \
         active_delta_event_id, active_delta_token_hash \
         FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ?",
    )
    .bind(namespace.tenant_id)
    .bind(namespace.aggregate_id)
    .fetch_optional(pool)
    .await
    .expect("read exact run-owned aggregate lane")
}

async fn assert_lane_inactive(pool: &MySqlPool, namespace: &Namespace, epoch: i64) {
    let lane = lane_state(pool, namespace)
        .await
        .expect("released lane row must be preserved, not deleted");
    assert_eq!(
        lane.execution_epoch, epoch,
        "release must preserve ownership epoch"
    );
    assert_eq!(lane.lease_owner, "");
    assert_eq!(lane.lease_token_hash, vec![0_u8; 32]);
    assert!(lane.active_delta_event_id.is_none());
    assert!(lane.active_delta_token_hash.is_none());
    let expired: i64 = sqlx::query_scalar(
        "SELECT CAST(lease_expires_at <= UTC_TIMESTAMP(6) AS SIGNED) \
         FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ?",
    )
    .bind(namespace.tenant_id)
    .bind(namespace.aggregate_id)
    .fetch_one(pool)
    .await
    .expect("check inactive lease expiry");
    assert_eq!(expired, 1, "released lane expiry must be in the past");
}

async fn append_fixture_events(pool: &MySqlPool, requests: &[DeltaEventAppendRequest]) -> Vec<i64> {
    let mut ids = Vec::with_capacity(requests.len());
    for request in requests {
        let appended = append_delta_event(pool, request)
            .await
            .expect("canonical typed delta append must succeed");
        ids.push(appended.delta_event_id);
    }
    ids
}

async fn pointer_state(pool: &MySqlPool, namespace: &Namespace) -> Option<PointerState> {
    let pointer = sqlx::query_as(
        "SELECT pointer_id, current_generation, manifest_id, event_id, operation_id, \
         cas_version FROM authorization_projection_current \
         WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ?",
    );
    pointer
        .bind(namespace.tenant_id)
        .bind(namespace.aggregate_id)
        .fetch_optional(pool)
        .await
        .expect("read exact run-owned current pointer")
}

fn set_before_image(request: &mut DeltaEventAppendRequest, image: &str) {
    request.before_image_json = Some(image.to_owned());
    request.before_digest_hex = Some(format!("{:x}", sha2::Sha256::digest(image.as_bytes())));
}

async fn assert_receipt_drift_rejected(
    pool: &MySqlPool,
    namespace: &Namespace,
    stored: &DeltaEventAppendRequest,
    drift: DeltaEventAppendRequest,
    event_before: &EventState,
    lane_before: &Option<LaneState>,
    owner_tag: &str,
    expected_code: &str,
) {
    let error = claim_owned_delta_event_by_stable_event(
        pool,
        &drift,
        &namespace.owner(owner_tag),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect_err("immutable receipt drift must be rejected");
    assert!(
        error.to_string().contains(expected_code),
        "expected {expected_code} rejection, got {error}"
    );
    assert_eq!(event_state(pool, stored).await, *event_before);
    assert_eq!(lane_state(pool, namespace).await, *lane_before);
}

async fn simultaneous_same_aggregate_claims(
    pool: &MySqlPool,
    earliest: &DeltaEventAppendRequest,
    later: &DeltaEventAppendRequest,
    earliest_owner: &str,
    later_owner: &str,
) -> (
    Result<OwnedStableEventOutcome, GrantRepositoryError>,
    Result<OwnedStableEventOutcome, GrantRepositoryError>,
) {
    let barrier = Arc::new(Barrier::new(3));
    let left_barrier = barrier.clone();
    let right_barrier = barrier.clone();
    let left_pool = pool.clone();
    let right_pool = pool.clone();
    let left_request = earliest.clone();
    let right_request = later.clone();
    let left_owner = earliest_owner.to_owned();
    let right_owner = later_owner.to_owned();
    let left = tokio::spawn(async move {
        left_barrier.wait().await;
        claim_owned_delta_event_by_stable_event(
            &left_pool,
            &left_request,
            &left_owner,
            CLAIM_LEASE_SECONDS,
        )
        .await
    });
    let right = tokio::spawn(async move {
        right_barrier.wait().await;
        claim_owned_delta_event_by_stable_event(
            &right_pool,
            &right_request,
            &right_owner,
            CLAIM_LEASE_SECONDS,
        )
        .await
    });
    barrier.wait().await;
    let (left, right) = tokio::join!(left, right);
    (
        left.expect("earliest claim task must not panic"),
        right.expect("later claim task must not panic"),
    )
}

async fn assert_simultaneous_same_aggregate_claim(
    pool: &MySqlPool,
    namespace: &Namespace,
    earliest: &DeltaEventAppendRequest,
    later: &DeltaEventAppendRequest,
    earliest_owner: &str,
    later_owner: &str,
) {
    let (left, right) =
        simultaneous_same_aggregate_claims(pool, earliest, later, earliest_owner, later_owner)
            .await;
    let mut winner = None;
    for outcome in [left, right] {
        match outcome.expect("simultaneous exact claim must reach a protocol outcome") {
            OwnedStableEventOutcome::Claimed(claimed) => {
                assert!(winner.is_none(), "same aggregate admitted two live claims");
                winner = Some(*claimed);
            }
            OwnedStableEventOutcome::Busy { event_id } => {
                assert_eq!(
                    event_id, later.event_id,
                    "only the later receipt may be Busy"
                );
            }
            other => panic!("same aggregate race must be Claimed/Busy, got {other:?}"),
        }
    }
    let winner = winner.expect("same aggregate race must have one winner");
    assert_eq!(winner.claim.event_id, earliest.event_id);
    let loser_state = event_state(pool, later).await;
    assert_eq!(loser_state.attempts, 0);
    assert_eq!(loser_state.execution_attempts, 0);
    assert_eq!(loser_state.execution_failures, 0);
    assert_eq!(loser_state.execution_accounting_version, 1);
    assert!(release_owned_delta_event(pool, &winner.lease)
        .await
        .expect("winner must release its exact aggregate capability"));
    let winner_state = event_state(pool, earliest).await;
    assert_eq!(winner_state.attempts, 1);
    assert_eq!(winner_state.execution_attempts, 0);
    assert_eq!(winner_state.execution_failures, 0);
    assert_lane_inactive(pool, namespace, winner.lease.ownership_epoch()).await;
}

async fn assert_simultaneous_independent_claims(
    pool: &MySqlPool,
    left_namespace: &Namespace,
    left_request: &DeltaEventAppendRequest,
    right_namespace: &Namespace,
    right_request: &DeltaEventAppendRequest,
) {
    let barrier = Arc::new(Barrier::new(3));
    let left_barrier = barrier.clone();
    let right_barrier = barrier.clone();
    let left_pool = pool.clone();
    let right_pool = pool.clone();
    let left_request_owned = left_request.clone();
    let right_request_owned = right_request.clone();
    let left = tokio::spawn(async move {
        left_barrier.wait().await;
        claim_owned_delta_event_by_stable_event(
            &left_pool,
            &left_request_owned,
            "worker-po-independent-left",
            CLAIM_LEASE_SECONDS,
        )
        .await
    });
    let right = tokio::spawn(async move {
        right_barrier.wait().await;
        claim_owned_delta_event_by_stable_event(
            &right_pool,
            &right_request_owned,
            "worker-po-independent-right",
            CLAIM_LEASE_SECONDS,
        )
        .await
    });
    barrier.wait().await;
    let (left, right) = tokio::join!(left, right);
    let left = left.expect("independent left claim task must not panic");
    let right = right.expect("independent right claim task must not panic");
    let left_claim = left
        .expect("independent left claim must reach a protocol outcome")
        .expect_claimed("independent left aggregate must claim");
    let right_claim = right
        .expect("independent right claim must reach a protocol outcome")
        .expect_claimed("independent right aggregate must claim");
    assert_eq!(left_claim.claim.event_id, left_request.event_id);
    assert_eq!(right_claim.claim.event_id, right_request.event_id);
    assert!(release_owned_delta_event(pool, &left_claim.lease)
        .await
        .expect("left independent capability releases exactly"));
    assert!(release_owned_delta_event(pool, &right_claim.lease)
        .await
        .expect("right independent capability releases exactly"));
    assert_eq!(event_state(pool, left_request).await.attempts, 1);
    assert_eq!(event_state(pool, right_request).await.attempts, 1);
    assert_lane_inactive(pool, left_namespace, left_claim.lease.ownership_epoch()).await;
    assert_lane_inactive(pool, right_namespace, right_claim.lease.ownership_epoch()).await;
}

trait OwnedStableEventOutcomeExt {
    fn expect_claimed(self, message: &str) -> Box<astral_db::OwnedDeltaClaim>;
}

impl OwnedStableEventOutcomeExt for OwnedStableEventOutcome {
    fn expect_claimed(self, message: &str) -> Box<astral_db::OwnedDeltaClaim> {
        match self {
            OwnedStableEventOutcome::Claimed(claimed) => claimed,
            other => panic!("{message}, got {other:?}"),
        }
    }
}

fn stale_publication_command(claim: &astral_db::OwnedDeltaClaim) -> DeltaProjectorPublishCommand {
    let identity = claim.lease.aggregate_identity().clone();
    let event = &claim.event;
    let semantic_hash_hex = event.semantic_hash.as_hex();
    let dependency_hash_hex = event.dependency_hash.as_hex();
    DeltaProjectorPublishCommand {
        delta_lease_identity: claim.lease.identity().clone(),
        expectation: DeltaProjectorExpectation {
            identity: identity.clone(),
            card_id: event.card_id,
            event_id: event.event_id.clone(),
            operation_id: event.operation_id.clone(),
            base_version: event.base_version,
            target_version: event.target_version,
            source_generation: event.source_generation,
            semantic_hash_hex: semantic_hash_hex.clone(),
            dependency_hash_hex: dependency_hash_hex.clone(),
            compiler_version: event.compiler_version.clone(),
        },
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence: event.revoke_fence,
            new_revoke_fence: event.revoke_fence,
        },
        mode: CompileModeEvidence {
            compile_mode: ProjectionCompileMode::Incremental,
            full_rebuild_reason: None,
        },
        stage: AuthorizationStageRequest {
            identity: identity.clone(),
            card_id: event.card_id,
            target_generation: 1,
            source_generation: event.source_generation,
            projected_generation: event.source_generation,
            event_id: event.event_id.clone(),
            operation_id: event.operation_id.clone(),
            semantic_hash_hex: semantic_hash_hex.clone(),
            dependency_hash_hex: dependency_hash_hex.clone(),
            compiler_version: event.compiler_version.clone(),
            revoke_fence: event.revoke_fence,
            segments: Vec::new(),
        },
        finalize_expected_reference_count: None,
        impact_plan: AuthorizationImpactPlanAppendRequest {
            identity,
            card_id: event.card_id,
            event_id: event.event_id.clone(),
            operation_id: event.operation_id.clone(),
            base_generation: 0,
            target_generation: 1,
            base_version: event.base_version,
            target_version: event.target_version,
            semantic_hash_hex,
            dependency_hash_hex,
            compiler_version: event.compiler_version.clone(),
            items: Vec::new(),
        },
        manifest_lease_owner: event.lease_owner.clone(),
        manifest_lease_seconds: CLAIM_LEASE_SECONDS,
    }
}

fn grant_repository_error_contains<T: std::fmt::Debug>(
    result: Result<T, GrantRepositoryError>,
    code: &str,
) {
    let error = result.expect_err("operation must be rejected");
    assert!(
        error.to_string().contains(code),
        "expected {code} rejection, got {error}"
    );
}

async fn assert_legacy_bypass_is_denied(
    pool: &MySqlPool,
    namespace: &Namespace,
    sample_request: &DeltaEventAppendRequest,
) {
    let owner = namespace.owner("legacy-bypass");
    let identity = namespace.identity();
    grant_repository_error_contains(
        acquire_partition_lease(pool, &identity, &owner, CLAIM_LEASE_SECONDS).await,
        "legacy_execution_refused",
    );

    let fake_identity = DeltaLeaseIdentity {
        delta_event_id: 1,
        event_id: namespace.event_id("not-present-legacy-probe"),
        lease_owner: owner.clone(),
        lease_token: DeltaLeaseToken::new_run_scoped(),
    };
    grant_repository_error_contains(
        complete_delta_event(pool, &fake_identity).await,
        "legacy_execution_refused",
    );
    grant_repository_error_contains(
        fail_delta_event(pool, &fake_identity, 0, "legacy probe").await,
        "legacy_execution_refused",
    );
    grant_repository_error_contains(
        release_delta_event_lease(pool, &fake_identity).await,
        "legacy_execution_refused",
    );
    grant_repository_error_contains(
        extend_delta_event_lease(pool, &fake_identity, CLAIM_LEASE_SECONDS).await,
        "legacy_execution_refused",
    );
    grant_repository_error_contains(
        mark_delta_event_quarantined(pool, &fake_identity, "legacy-probe", "probe").await,
        "legacy_execution_refused",
    );

    let mut tx = pool.begin().await.expect("legacy claim guard transaction");
    let claim_result = claim_next_delta_event_in_tx(
        &mut tx,
        DeltaEventClaimScope {
            tenant_id: namespace.tenant_id,
            card_id: Some(namespace.card_id),
        },
        &owner,
        CLAIM_LEASE_SECONDS,
    )
    .await;
    tx.rollback()
        .await
        .expect("rollback guard-only transaction");
    grant_repository_error_contains(claim_result, "legacy_execution_refused");

    let mut tx = pool
        .begin()
        .await
        .expect("legacy stable-claim guard transaction");
    let stable_claim = claim_delta_event_by_stable_event_in_tx(
        &mut tx,
        sample_request,
        &owner,
        CLAIM_LEASE_SECONDS,
    )
    .await;
    tx.rollback()
        .await
        .expect("rollback stable-claim guard-only transaction");
    grant_repository_error_contains(stable_claim, "legacy_execution_refused");

    let legacy_publish_request = AuthorizationPublishRequest {
        identity,
        card_id: Some(namespace.card_id),
        target_manifest_id: 9_000_000_000_001,
        target_generation: 1,
        current_pointer: None,
        expected_target_semantic_hash_hex: "aa".repeat(32),
        expected_target_dependency_hash_hex: "bb".repeat(32),
        expected_target_compiler_version: "owned-contract-test-v1".to_owned(),
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence: 0,
            new_revoke_fence: 0,
        },
    };
    let mut tx = pool
        .begin()
        .await
        .expect("legacy publish guard transaction");
    let publish_result = publish_current_pointer_in_tx(&mut tx, &legacy_publish_request).await;
    tx.rollback().await.expect("rollback legacy publish probe");
    let publish_error =
        publish_result.expect_err("legacy publication must be denied in WorkerOwned");
    assert!(
        publish_error
            .to_string()
            .contains("legacy_execution_refused"),
        "legacy publication must stop at the mode guard, got {publish_error}"
    );
}

async fn wait_until_due(pool: &MySqlPool, request: &DeltaEventAppendRequest) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let due: i64 = sqlx::query_scalar(
                "SELECT CAST(next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP(6) AS SIGNED) \
                 FROM authorization_delta_event WHERE tenant_id = ? AND event_id = ?",
            )
            .bind(request.tenant_id)
            .bind(&request.event_id)
            .fetch_one(pool)
            .await
            .expect("read the exact fixture event retry deadline");
            if due == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("zero-backoff fixture must become due within its stored timestamp precision");
}

async fn expire_owned_episode(
    pool: &MySqlPool,
    namespace: &Namespace,
    request: &DeltaEventAppendRequest,
) {
    let lane = sqlx::query(
        "UPDATE authorization_projection_partition_lease \
         SET lease_expires_at = TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP(6)) \
         WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ? \
           AND active_delta_event_id = (SELECT delta_event_id FROM authorization_delta_event \
             WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ? AND event_id = ?) \
           AND lease_expires_at > UTC_TIMESTAMP(6)",
    )
    .bind(namespace.tenant_id)
    .bind(namespace.aggregate_id)
    .bind(request.tenant_id)
    .bind(request.aggregate_id)
    .bind(&request.event_id)
    .execute(pool)
    .await
    .expect("expire only this run-owned active lane");
    assert_eq!(lane.rows_affected(), 1, "exact active lane must expire");
    let event = sqlx::query(
        "UPDATE authorization_delta_event \
         SET lease_expires_at = TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP(6)) \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND event_id = ? \
           AND status = 'LEASED' AND lease_owner IS NOT NULL \
           AND lease_expires_at > UTC_TIMESTAMP(6)",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .bind(&request.event_id)
    .execute(pool)
    .await
    .expect("expire only this run-owned event lease");
    assert_eq!(
        event.rows_affected(),
        1,
        "exact active event lease must expire"
    );
}

async fn cleanup_after_proven_success(
    pool: &MySqlPool,
    namespace: &Namespace,
    requests: &[DeltaEventAppendRequest],
) {
    let lane = lane_state(pool, namespace)
        .await
        .expect("run-owned lane exists before cleanup");
    assert!(lane.execution_epoch > 0);
    assert_eq!(lane.lease_owner, "");
    assert_eq!(lane.lease_token_hash, vec![0_u8; 32]);
    assert!(lane.active_delta_event_id.is_none());
    assert!(lane.active_delta_token_hash.is_none());
    for request in requests {
        let state = event_state(pool, request).await;
        assert_eq!(
            state.status, "PENDING",
            "all fixture events must be quiescent"
        );
        assert!(state.lease_owner.is_none());
        assert!(state.lease_token_hash.is_none());
        assert!(state.lease_expires_at.is_none());
    }

    let placeholders = vec!["?"; requests.len()].join(",");
    let mut tx = pool.begin().await.expect("begin exact fixture cleanup");
    let audit_sql = format!(
        "DELETE FROM audit_log WHERE tenant_id = ? AND event_type = 'AUTHZ_OWNED_PROJECTION_LANE' \
         AND resource = 'authorization_projection_owned_lane' \
         AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.eventId')) IN ({placeholders})"
    );
    let mut audit = sqlx::query(&audit_sql).bind(namespace.tenant_id);
    for request in requests {
        audit = audit.bind(&request.event_id);
    }
    audit
        .execute(&mut *tx)
        .await
        .expect("delete only audit rows correlated to fixture event ids");

    let events_sql = format!(
        "DELETE FROM authorization_delta_event WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' \
         AND aggregate_id = ? AND event_id IN ({placeholders})"
    );
    let mut events = sqlx::query(&events_sql)
        .bind(namespace.tenant_id)
        .bind(namespace.aggregate_id);
    for request in requests {
        events = events.bind(&request.event_id);
    }
    let deleted_events = events
        .execute(&mut *tx)
        .await
        .expect("delete only the proven run-owned fixture events");
    assert_eq!(
        deleted_events.rows_affected(),
        requests.len() as u64,
        "cleanup must match exactly the fixture events"
    );
    let deleted_lane = sqlx::query(
        "DELETE FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ? \
           AND execution_epoch = ? AND lease_owner = '' AND lease_token_hash = ? \
           AND active_delta_event_id IS NULL AND active_delta_token_hash IS NULL \
           AND lease_expires_at <= UTC_TIMESTAMP(6)",
    )
    .bind(namespace.tenant_id)
    .bind(namespace.aggregate_id)
    .bind(lane.execution_epoch)
    .bind(vec![0_u8; 32])
    .execute(&mut *tx)
    .await
    .expect("delete only this proven inactive run-owned lane during final cleanup");
    assert_eq!(deleted_lane.rows_affected(), 1);
    tx.commit()
        .await
        .expect("commit exact successful-fixture cleanup");
}

async fn run_contract() {
    assert_eq!(
        freeze_projection_execution_mode(ProjectionExecutionMode::WorkerOwned),
        Ok(ProjectionExecutionMode::WorkerOwned),
        "this binary freezes exactly one process-wide execution mode"
    );
    let pool = required_pool().await;
    let namespace = Namespace::new();
    let sibling_namespace = Namespace::new();
    let concurrency_namespace = Namespace::new();
    let same_owner_namespace = Namespace::new();
    let ordering_namespace = Namespace::new();
    let independent_left_namespace = Namespace::new();
    let independent_right_namespace = Namespace::new();
    let binding_namespace = Namespace::new();
    let normalized_namespace = Namespace::new();
    let first = add_request(&namespace, "first", 1);
    let sibling = add_request(&sibling_namespace, "independent-sibling", 2);
    let successor = successor_request(&namespace, &first);
    let concurrent_earliest = add_request(&concurrency_namespace, "concurrent-earliest", 4);
    let concurrent_later = add_request(&concurrency_namespace, "concurrent-later", 5);
    let same_owner_earliest = add_request(&same_owner_namespace, "same-owner-earliest", 6);
    let same_owner_later = add_request(&same_owner_namespace, "same-owner-later", 7);
    let mut ordering_earliest = add_request(&ordering_namespace, "ordering-earliest", 8);
    ordering_earliest.source_generation = 7;
    let mut ordering_later = add_request(&ordering_namespace, "ordering-later", 9);
    ordering_later.source_generation = 64;
    let independent_left = add_request(&independent_left_namespace, "independent-left", 10);
    let independent_right = add_request(&independent_right_namespace, "independent-right", 11);
    let mut binding = add_request(&binding_namespace, "binding", 12);
    set_before_image(&mut binding, r#"{"before":true,"ordinal":12}"#);
    let mut normalized = add_request(&normalized_namespace, "normalized", 13);
    set_before_image(&mut normalized, r#"{"before":true,"ordinal":13}"#);
    assert_legacy_bypass_is_denied(&pool, &namespace, &first).await;

    let event_ids = append_fixture_events(&pool, &[first.clone(), successor.clone()]).await;
    assert_eq!(event_ids.len(), 2);
    append_fixture_events(&pool, &[sibling.clone()]).await;
    append_fixture_events(
        &pool,
        &[concurrent_earliest.clone(), concurrent_later.clone()],
    )
    .await;
    append_fixture_events(
        &pool,
        &[same_owner_earliest.clone(), same_owner_later.clone()],
    )
    .await;
    append_fixture_events(&pool, &[ordering_later.clone(), ordering_earliest.clone()]).await;
    append_fixture_events(&pool, &[independent_left.clone()]).await;
    append_fixture_events(&pool, &[independent_right.clone()]).await;
    append_fixture_events(&pool, &[binding.clone()]).await;
    append_fixture_events(&pool, &[normalized.clone()]).await;
    let first_before = event_state(&pool, &first).await;
    assert_eq!(first_before.attempts, 0);
    assert_eq!(first_before.execution_attempts, 0);
    assert_eq!(first_before.execution_failures, 0);
    assert_eq!(first_before.execution_accounting_version, 1);
    assert!(lane_state(&pool, &namespace).await.is_none());

    // Every immutable source field is rebound before lane insertion. Neither a
    // same-aggregate payload mismatch nor forged tenant/aggregate scope can
    // touch claim counters or create an owner slot.
    let mut mismatched = first.clone();
    mismatched.operation_id.push_str("-forged");
    let mismatch = claim_owned_delta_event_by_stable_event(
        &pool,
        &mismatched,
        &namespace.owner("mismatch"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect_err("complete operation binding drift must fail closed");
    assert!(mismatch
        .to_string()
        .contains("claim_by_event_payload_mismatch"));
    assert_eq!(event_state(&pool, &first).await, first_before);
    assert!(lane_state(&pool, &namespace).await.is_none());

    for (index, mut forged) in [first.clone(), first.clone()].into_iter().enumerate() {
        if index == 0 {
            forged.tenant_id += 1;
        } else {
            forged.aggregate_id += 1;
        }
        assert!(claim_owned_delta_event_by_stable_event(
            &pool,
            &forged,
            &namespace.owner("scope-mismatch"),
            CLAIM_LEASE_SECONDS,
        )
        .await
        .is_err());
        assert_eq!(event_state(&pool, &first).await, first_before);
        assert!(lane_state(&pool, &namespace).await.is_none());
    }
    assert!(claim_next_owned_delta_event(
        &pool,
        DeltaEventClaimScope {
            tenant_id: namespace.tenant_id + 1,
            card_id: Some(namespace.card_id),
        },
        &namespace.owner("foreign-tenant"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("foreign tenant scope is a safe empty scan")
    .is_none());

    let first_claim = match claim_owned_delta_event_by_stable_event(
        &pool,
        &first,
        &namespace.owner("primary"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("exact source receipt claim")
    {
        OwnedStableEventOutcome::Claimed(claimed) => *claimed,
        other => panic!("fresh canonical source event must claim, got {other:?}"),
    };
    assert_eq!(first_claim.claim.event_id, first.event_id);
    assert_eq!(first_claim.event.event_id, first.event_id);
    assert_eq!(first_claim.claim.attempts, 1);
    assert_eq!(first_claim.lease.ownership_epoch(), 1);
    assert_eq!(
        first_claim.lease.aggregate_identity(),
        &namespace.identity()
    );
    assert_eq!(first_claim.lease.execution_failures(), 0);
    let first_claimed_state = event_state(&pool, &first).await;
    assert_eq!(first_claimed_state.attempts, first_before.attempts + 1);
    assert_eq!(first_claimed_state.execution_attempts, 0);
    assert_eq!(first_claimed_state.execution_failures, 0);
    assert_eq!(first_claimed_state.execution_accounting_version, 2);
    let active_lane = lane_state(&pool, &namespace)
        .await
        .expect("successful event claim installs its aggregate lane");
    assert_eq!(
        active_lane.execution_epoch,
        first_claim.lease.ownership_epoch()
    );
    assert_eq!(active_lane.lease_owner, namespace.owner("primary"));
    assert_eq!(
        active_lane.active_delta_event_id,
        Some(first_claim.claim.delta_event_id)
    );
    assert!(active_lane.active_delta_token_hash.is_some());

    assert_simultaneous_same_aggregate_claim(
        &pool,
        &concurrency_namespace,
        &concurrent_earliest,
        &concurrent_later,
        &concurrency_namespace.owner("same-aggregate-earliest"),
        &concurrency_namespace.owner("same-aggregate-later"),
    )
    .await;
    assert_simultaneous_same_aggregate_claim(
        &pool,
        &same_owner_namespace,
        &same_owner_earliest,
        &same_owner_later,
        &same_owner_namespace.owner("same-owner"),
        &same_owner_namespace.owner("same-owner"),
    )
    .await;
    assert_simultaneous_independent_claims(
        &pool,
        &independent_left_namespace,
        &independent_left,
        &independent_right_namespace,
        &independent_right,
    )
    .await;
    let ordering_later_before = event_state(&pool, &ordering_later).await;
    let ordering_lane_before = lane_state(&pool, &ordering_namespace).await;
    let ordering_busy = claim_owned_delta_event_by_stable_event(
        &pool,
        &ordering_later,
        &ordering_namespace.owner("ordering-later"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("out-of-order aggregate predecessor must return Busy");
    assert!(matches!(
        ordering_busy,
        OwnedStableEventOutcome::Busy { .. }
    ));
    assert_eq!(
        event_state(&pool, &ordering_later).await,
        ordering_later_before
    );
    assert_eq!(
        lane_state(&pool, &ordering_namespace).await,
        ordering_lane_before
    );
    let ordering_claim = match claim_owned_delta_event_by_stable_event(
        &pool,
        &ordering_earliest,
        &ordering_namespace.owner("ordering-earliest"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("aggregate predecessor earliest receipt must claim")
    {
        OwnedStableEventOutcome::Claimed(claimed) => *claimed,
        other => panic!("earliest ordering receipt must claim, got {other:?}"),
    };
    assert!(release_owned_delta_event(&pool, &ordering_claim.lease)
        .await
        .expect("ordering winner releases exactly"));

    let predecessor_busy = claim_owned_delta_event_by_stable_event(
        &pool,
        &successor,
        &namespace.owner("successor"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("predecessor check returns an explicit non-claim outcome");
    assert!(matches!(
        predecessor_busy,
        OwnedStableEventOutcome::Busy { .. }
    ));
    let successor_before = event_state(&pool, &successor).await;
    assert_eq!(successor_before.attempts, 0);
    assert_eq!(successor_before.execution_attempts, 0);
    assert_eq!(successor_before.execution_failures, 0);

    assert_eq!(
        begin_owned_delta_execution(&pool, &first_claim.lease)
            .await
            .expect("first execution episode begins"),
        0
    );
    assert_eq!(
        begin_owned_delta_execution(&pool, &first_claim.lease)
            .await
            .expect("same-token begin is idempotent"),
        0
    );
    assert_eq!(event_state(&pool, &first).await.execution_attempts, 1);
    assert_eq!(event_state(&pool, &first).await.execution_failures, 0);
    assert!(release_owned_delta_event(&pool, &first_claim.lease)
        .await
        .expect("yield an unfailed execution episode"));
    assert!(!release_owned_delta_event(&pool, &first_claim.lease)
        .await
        .expect("a stale release is a fenced no-op"));
    let after_release = event_state(&pool, &first).await;
    assert_eq!(after_release.status, "PENDING");
    assert_eq!(after_release.attempts, 1);
    assert_eq!(after_release.execution_attempts, 1);
    assert_eq!(after_release.execution_failures, 0);
    assert_lane_inactive(&pool, &namespace, first_claim.lease.ownership_epoch()).await;

    let predecessor_still_pending = claim_owned_delta_event_by_stable_event(
        &pool,
        &successor,
        &namespace.owner("successor-after-release"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("pending predecessor leaves successor explicitly gated");
    assert!(matches!(
        predecessor_still_pending,
        OwnedStableEventOutcome::Busy { .. }
    ));
    assert_eq!(event_state(&pool, &successor).await, successor_before);

    let sibling_claim = match claim_owned_delta_event_by_stable_event(
        &pool,
        &sibling,
        &sibling_namespace.owner("defer"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("independent aggregate claim is a protocol outcome")
    {
        OwnedStableEventOutcome::Claimed(claimed) => *claimed,
        other => panic!("released lane must admit independent event, got {other:?}"),
    };
    assert_eq!(sibling_claim.claim.attempts, 1);
    assert_eq!(
        begin_owned_delta_execution(&pool, &sibling_claim.lease)
            .await
            .expect("sibling episode begins"),
        0
    );
    assert!(fail_owned_delta_event(
        &pool,
        &sibling_claim.lease,
        "owned.defer_without_failure",
        0,
        false,
    )
    .await
    .expect("defer is distinct from a proven execution failure"));
    let deferred_state = event_state(&pool, &sibling).await;
    assert_eq!(deferred_state.status, "PENDING");
    assert_eq!(deferred_state.attempts, 1);
    assert_eq!(deferred_state.execution_attempts, 1);
    assert_eq!(deferred_state.execution_failures, 0);

    let failed_claim = match claim_owned_delta_event_by_stable_event(
        &pool,
        &first,
        &namespace.owner("transient-failure"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("released first event is claimable again")
    {
        OwnedStableEventOutcome::Claimed(claimed) => *claimed,
        other => panic!("released first event must be claimable, got {other:?}"),
    };
    assert_eq!(failed_claim.claim.attempts, 2);
    assert_eq!(
        begin_owned_delta_execution(&pool, &failed_claim.lease)
            .await
            .expect("transient attempt begins"),
        0
    );
    assert!(fail_owned_delta_event(
        &pool,
        &failed_claim.lease,
        "owned.transient_failure",
        0,
        true,
    )
    .await
    .expect("proven transient failure is charged once"));
    assert!(!fail_owned_delta_event(
        &pool,
        &failed_claim.lease,
        "owned.transient_failure.replay",
        0,
        true,
    )
    .await
    .expect("stale/repeated failure is fenced without a second charge"));
    let transient_state = event_state(&pool, &first).await;
    assert_eq!(transient_state.status, "PENDING");
    assert_eq!(transient_state.attempts, 2);
    assert_eq!(transient_state.execution_attempts, 2);
    assert_eq!(transient_state.execution_failures, 1);
    assert_lane_inactive(&pool, &namespace, failed_claim.lease.ownership_epoch()).await;

    wait_until_due(&pool, &first).await;
    let expiring_claim = match claim_owned_delta_event_by_stable_event(
        &pool,
        &first,
        &namespace.owner("abandoned"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("event with immediate retry schedule can be claimed")
    {
        OwnedStableEventOutcome::Claimed(claimed) => *claimed,
        other => panic!("due event must be claimable, got {other:?}"),
    };
    assert_eq!(expiring_claim.claim.attempts, 3);
    assert_eq!(
        begin_owned_delta_execution(&pool, &expiring_claim.lease)
            .await
            .expect("abandoned attempt begins"),
        1
    );
    let epoch_before_takeover = expiring_claim.lease.ownership_epoch();
    expire_owned_episode(&pool, &namespace, &first).await;

    let takeover = match claim_owned_delta_event_by_stable_event(
        &pool,
        &first,
        &namespace.owner("takeover"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("expired unknown episode is reconciled before takeover")
    {
        OwnedStableEventOutcome::Claimed(claimed) => *claimed,
        other => panic!("unpublished expired event must be safely reclaimable, got {other:?}"),
    };
    assert!(takeover.lease.ownership_epoch() > epoch_before_takeover);
    assert_eq!(takeover.claim.attempts, 4);
    assert_eq!(takeover.lease.execution_failures(), 1);
    assert!(
        !extend_owned_delta_execution_lease(&pool, &expiring_claim.lease, 30)
            .await
            .expect("stale renewal is a fenced no-op")
    );
    assert!(!release_owned_delta_event(&pool, &expiring_claim.lease)
        .await
        .expect("stale release is a fenced no-op"));
    assert!(
        !fail_owned_delta_event(&pool, &expiring_claim.lease, "owned.stale_failure", 0, true,)
            .await
            .expect("stale failure is a fenced no-op")
    );
    assert!(!quarantine_owned_delta_event(
        &pool,
        &expiring_claim.lease,
        "owned.stale_quarantine",
        None,
    )
    .await
    .expect("stale quarantine is a fenced no-op"));
    let event_before_stale_publish = event_state(&pool, &first).await;
    let lane_before_stale_publish = lane_state(&pool, &namespace).await;
    let pointer_before_stale_publish = pointer_state(&pool, &namespace).await;
    let stale_command = stale_publication_command(&expiring_claim);
    let mut stale_tx = pool.begin().await.expect("begin stale publication probe");
    let stale_publish = project_owned_authorization_delta_in_tx(
        &mut stale_tx,
        &stale_command,
        &expiring_claim.lease,
    )
    .await
    .expect_err("superseded capability must not enter the publication transaction");
    assert!(
        stale_publish.to_string().contains("publication_lane_lost"),
        "stale publication must stop at the capability guard: {stale_publish}"
    );
    stale_tx
        .rollback()
        .await
        .expect("rollback stale publication probe");
    assert_eq!(event_state(&pool, &first).await, event_before_stale_publish);
    assert_eq!(
        lane_state(&pool, &namespace).await,
        lane_before_stale_publish
    );
    assert_eq!(
        pointer_state(&pool, &namespace).await,
        pointer_before_stale_publish
    );
    let after_stale_calls = event_state(&pool, &first).await;
    assert_eq!(after_stale_calls.status, "LEASED");
    assert_eq!(after_stale_calls.attempts, 4);
    assert_eq!(after_stale_calls.execution_attempts, 3);
    assert_eq!(after_stale_calls.execution_failures, 1);
    let takeover_lane = lane_state(&pool, &namespace)
        .await
        .expect("takeover lane row remains durable");
    assert_eq!(
        takeover_lane.execution_epoch,
        takeover.lease.ownership_epoch()
    );
    assert_eq!(
        takeover_lane.active_delta_event_id,
        Some(takeover.claim.delta_event_id)
    );
    assert_eq!(
        begin_owned_delta_execution(&pool, &takeover.lease)
            .await
            .expect("takeover starts a new actual execution episode"),
        1
    );
    assert_eq!(
        begin_owned_delta_execution(&pool, &takeover.lease)
            .await
            .expect("same takeover token is idempotent"),
        1
    );
    assert_eq!(event_state(&pool, &first).await.execution_attempts, 4);
    assert_eq!(event_state(&pool, &first).await.execution_failures, 1);
    assert!(release_owned_delta_event(&pool, &takeover.lease)
        .await
        .expect("takeover owner releases its live episode"));
    assert_lane_inactive(&pool, &namespace, takeover.lease.ownership_epoch()).await;

    let binding_before = event_state(&pool, &binding).await;
    let binding_lane_before = lane_state(&pool, &binding_namespace).await;
    for (index, (drift, expected_field)) in [
        {
            let mut value = binding.clone();
            value.event_id.push_str("-drift");
            (value, "event_id")
        },
        {
            let mut value = binding.clone();
            value.operation_id.push_str("-drift");
            (value, "operation_id")
        },
        {
            let mut value = binding.clone();
            value.event_type = DeltaEventType::Update;
            (value, "event_type")
        },
        {
            let mut value = binding.clone();
            value.tenant_id += 1;
            (value, "tenant_id")
        },
        {
            let mut value = binding.clone();
            value.card_id = None;
            (value, "card_id")
        },
        {
            let mut value = binding.clone();
            value.aggregate_type = "ORG".to_owned();
            (value, "aggregate_identity")
        },
        {
            let mut value = binding.clone();
            value.aggregate_id += 1;
            (value, "aggregate_identity")
        },
        {
            let mut value = binding.clone();
            value.grant_id = binding_namespace.grant_id(99);
            (value, "grant_id")
        },
        {
            let mut value = binding.clone();
            value.base_version = 1;
            (value, "base_version")
        },
        {
            let mut value = binding.clone();
            value.target_version = 2;
            (value, "target_version")
        },
        {
            let mut value = binding.clone();
            value.source_generation = 2;
            (value, "source_generation")
        },
        {
            let mut value = binding.clone();
            value.revoke_fence = 1;
            (value, "revoke_fence")
        },
        {
            let mut value = binding.clone();
            value.invalidates_published_evidence = true;
            (value, "invalidates_published_evidence")
        },
        {
            let mut value = binding.clone();
            value.before_image_json = Some(r#"{"before":true,"ordinal":99}"#.to_owned());
            (value, "before_image_json")
        },
        {
            let mut value = binding.clone();
            value.before_digest_hex = Some("00".repeat(32));
            (value, "before_digest")
        },
        {
            let mut value = binding.clone();
            value.delta_json = r#"{"kind":"ADD","grant":null}"#.to_owned();
            (value, "delta_json")
        },
        {
            let mut value = binding.clone();
            value.semantic_hash_hex = "00".repeat(32);
            (value, "semantic_hash")
        },
        {
            let mut value = binding.clone();
            value.dependency_hash_hex = "00".repeat(32);
            (value, "dependency_hash")
        },
        {
            let mut value = binding.clone();
            value.compiler_version.push_str("-drift");
            (value, "compiler_version")
        },
    ]
    .into_iter()
    .enumerate()
    {
        let expected_code = if matches!(expected_field, "event_id" | "tenant_id") {
            "stable_event_missing"
        } else {
            "claim_by_event_payload_mismatch"
        };
        assert_receipt_drift_rejected(
            &pool,
            &binding_namespace,
            &binding,
            drift,
            &binding_before,
            &binding_lane_before,
            &format!("binding-drift-{index}-{expected_field}"),
            expected_code,
        )
        .await;
    }
    let mut whitespace_only = normalized.clone();
    whitespace_only.before_image_json =
        Some("  {\n  \"ordinal\": 13, \"before\": true\n}  ".to_owned());
    let delta_value: serde_json::Value = serde_json::from_str(&normalized.delta_json).unwrap();
    let reordered_fields: Vec<String> = delta_value
        .as_object()
        .expect("typed delta is an object")
        .iter()
        .rev()
        .map(|(key, value)| format!(" {} : {} ", serde_json::to_string(key).unwrap(), value))
        .collect();
    whitespace_only.delta_json = format!("{{ {} }}", reordered_fields.join(",\n"));
    assert_ne!(whitespace_only.delta_json, normalized.delta_json);
    let whitespace_outcome = claim_owned_delta_event_by_stable_event(
        &pool,
        &whitespace_only,
        &normalized_namespace.owner("binding-whitespace"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("JSON key order and whitespace must preserve immutable receipt binding");
    let whitespace_claim = match whitespace_outcome {
        OwnedStableEventOutcome::Claimed(claimed) => *claimed,
        other => panic!("normalized JSON receipt must claim, got {other:?}"),
    };
    assert!(release_owned_delta_event(&pool, &whitespace_claim.lease)
        .await
        .expect("normalized JSON claim releases exactly"));
    let sibling_before_corruption = event_state(&pool, &sibling).await;
    let corrupted = sqlx::query(
        "UPDATE authorization_projection_partition_lease \
         SET active_delta_event_id = ?, active_delta_token_hash = ?, \
             lease_owner = '', lease_token_hash = ?, \
             lease_expires_at = TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP(6)) \
         WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ? \
           AND active_delta_event_id IS NULL AND lease_owner = '' \
           AND execution_epoch = ?",
    )
    .bind(sibling_claim.claim.delta_event_id)
    .bind(vec![0xA5_u8; 32])
    .bind(vec![0_u8; 32])
    .bind(sibling_namespace.tenant_id)
    .bind(sibling_namespace.aggregate_id)
    .bind(sibling_claim.lease.ownership_epoch())
    .execute(&pool)
    .await
    .expect("inject one run-owned corrupt active-slot association");
    assert_eq!(corrupted.rows_affected(), 1);
    let in_doubt = claim_owned_delta_event_by_stable_event(
        &pool,
        &sibling,
        &sibling_namespace.owner("in-doubt-probe"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("corrupt ownership is a durable gated result");
    assert!(matches!(
        in_doubt,
        OwnedStableEventOutcome::InDoubt { ref event_id, .. } if event_id == &sibling.event_id
    ));
    assert_eq!(
        event_state(&pool, &sibling).await,
        sibling_before_corruption
    );
    let restore = sqlx::query(
        "UPDATE authorization_projection_partition_lease \
         SET active_delta_event_id = NULL, active_delta_token_hash = NULL, \
             lease_owner = '', lease_token_hash = ?, \
             lease_expires_at = TIMESTAMPADD(SECOND, -1, UTC_TIMESTAMP(6)) \
         WHERE tenant_id = ? AND aggregate_type = 'USER_CARD' AND aggregate_id = ? \
           AND active_delta_event_id = ? AND active_delta_token_hash = ? \
           AND lease_owner = ''",
    )
    .bind(vec![0_u8; 32])
    .bind(sibling_namespace.tenant_id)
    .bind(sibling_namespace.aggregate_id)
    .bind(sibling_claim.claim.delta_event_id)
    .bind(vec![0xA5_u8; 32])
    .execute(&pool)
    .await
    .expect("restore only the just-injected fixture lane corruption");
    assert_eq!(restore.rows_affected(), 1);
    assert_lane_inactive(
        &pool,
        &sibling_namespace,
        sibling_claim.lease.ownership_epoch(),
    )
    .await;

    let next_claim = claim_next_owned_delta_event(
        &pool,
        DeltaEventClaimScope {
            tenant_id: namespace.tenant_id,
            card_id: Some(namespace.card_id),
        },
        &namespace.owner("queue-claim"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("scoped worker-owned queue claim")
    .expect("an independent due event is available after lane restoration");
    assert_eq!(next_claim.claim.event_id, first.event_id);
    assert!(release_owned_delta_event(&pool, &next_claim.lease)
        .await
        .expect("queue claim releases cleanly"));
    assert_lane_inactive(&pool, &namespace, next_claim.lease.ownership_epoch()).await;

    let binding_claim = claim_owned_delta_event_by_stable_event(
        &pool,
        &binding,
        &binding_namespace.owner("binding-valid"),
        CLAIM_LEASE_SECONDS,
    )
    .await
    .expect("original immutable receipt remains claimable after all rejected drifts")
    .expect_claimed("valid binding receipt must claim");
    assert!(release_owned_delta_event(&pool, &binding_claim.lease)
        .await
        .expect("valid binding claim releases exactly"));

    for (scope, requests) in [
        (&namespace, vec![first, successor]),
        (&sibling_namespace, vec![sibling]),
        (
            &concurrency_namespace,
            vec![concurrent_earliest, concurrent_later],
        ),
        (
            &same_owner_namespace,
            vec![same_owner_earliest, same_owner_later],
        ),
        (&ordering_namespace, vec![ordering_earliest, ordering_later]),
        (&independent_left_namespace, vec![independent_left]),
        (&independent_right_namespace, vec![independent_right]),
        (&binding_namespace, vec![binding]),
        (&normalized_namespace, vec![normalized]),
    ] {
        cleanup_after_proven_success(&pool, scope, &requests).await;
    }
    pool.close().await;
}

#[tokio::test]
#[ignore = "real MySQL; run-owned loopback:3308 clone required; RUST_INTEGRATION_REQUIRED=1"]
async fn worker_owned_projection_sql_contract() {
    tokio::time::timeout(TEST_DEADLINE, run_contract())
        .await
        .expect("projection-owned SQL contract exceeded its 110-second deadline");
}
