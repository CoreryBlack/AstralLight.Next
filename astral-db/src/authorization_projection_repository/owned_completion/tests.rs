use std::{str::FromStr, time::Duration};

use astral_types::{
    BindingLayer, CanonicalGrant, GrantDelta, GrantEffect, GrantId, GrantProvenance, GrantRevision,
    GrantSourceKind, GrantState, ProjectionCompileMode, TenantScope, ValidityWindow,
};
use sha2::{Digest, Sha384};
use sqlx::{
    mysql::{MySqlArguments, MySqlConnectOptions, MySqlPoolOptions},
    query::Query,
    MySql, MySqlPool, Transaction,
};
use uuid::Uuid;

use super::{super::*, *};
use crate::{DeltaEventAppendRequest, DeltaEventType, OwnedDeltaClaim, OwnedStableEventOutcome};

const DATABASE: &str = "astral_rehearsal_projection_owner_20261015_sql";
const MIGRATION_VERSION: i64 = 20261015000001;
const MIGRATION_CHECKSUM: &str = "283fc5847f61d2d116ece1f7b1ae691f19d667f9bd79f068ac1087bcd5f1697f09c9255df26a52829b159a60ed1a1d76";

struct Fixture {
    salt: String,
    identity: ProjectionAggregateIdentity,
    card_id: i64,
    user_id: i64,
}

impl Fixture {
    fn new() -> Self {
        let salt = Uuid::new_v4();
        let base = 9_000_000_000_000_i64 + (salt.as_u128() % 1_000_000_000) as i64 * 1_000;
        Self {
            salt: salt.simple().to_string(),
            identity: ProjectionAggregateIdentity::new(base, "USER_CARD", base + 1).unwrap(),
            card_id: base + 1,
            user_id: base + 2,
        }
    }

    fn grant(&self, resource: &str, ordinal: u64) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(&Uuid::new_v4().to_string()).unwrap(),
            revision: GrantRevision::initial(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Base,
            tenant: TenantScope::new(self.identity.tenant_id, None).unwrap(),
            card_id: self.card_id,
            user_id: self.user_id,
            resource: resource.to_owned(),
            action: "read".to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: format!("seal-source-{}", self.salt),
                source_entry: None,
                binding_id: Some(format!("seal-binding-{}", self.salt)),
                delegation_id: None,
                operation_id: format!("seal-op-{}-{ordinal}", self.salt),
                event_id: Some(format!("seal-event-{}-{ordinal}", self.salt)),
                actor_user_id: Some(self.user_id),
            },
        }
    }

    fn request(
        &self,
        ordinal: u64,
        grant: &CanonicalGrant,
        before: Option<&CanonicalGrant>,
    ) -> DeltaEventAppendRequest {
        let before_image_json = before.map(|value| serde_json::to_string(value).unwrap());
        let before_digest_hex = before_image_json
            .as_ref()
            .map(|image| hex::encode(sha2::Sha256::digest(image.as_bytes())));
        let delta = match before {
            Some(value) => GrantDelta::update(grant.clone(), value.revision),
            None => GrantDelta::add(grant.clone()),
        };
        DeltaEventAppendRequest {
            tenant_id: self.identity.tenant_id,
            card_id: Some(self.card_id),
            aggregate_type: self.identity.aggregate_type.clone(),
            aggregate_id: self.identity.aggregate_id,
            grant_id: grant.grant_id,
            event_id: format!("seal-event-{}-{ordinal}", self.salt),
            operation_id: format!("seal-op-{}-{ordinal}", self.salt),
            event_type: if before.is_some() {
                DeltaEventType::Update
            } else {
                DeltaEventType::Add
            },
            base_version: ordinal
                .checked_sub(2)
                .filter(|_| before.is_some())
                .unwrap_or(0) as i64,
            target_version: if before.is_some() {
                (ordinal - 1) as i64
            } else {
                1
            },
            source_generation: ordinal,
            revoke_fence: 0,
            invalidates_published_evidence: false,
            before_image_json,
            before_digest_hex,
            delta_json: serde_json::to_string(&delta).unwrap(),
            semantic_hash_hex: hex::encode(sha2::Sha256::digest(format!(
                "semantic-{}-{ordinal}",
                self.salt
            ))),
            dependency_hash_hex: hex::encode(sha2::Sha256::digest(format!(
                "dependency-{}-{ordinal}",
                self.salt
            ))),
            compiler_version: "owned-completion-contract-v1".to_owned(),
            next_attempt_at: None,
        }
    }
}

async fn pool() -> MySqlPool {
    for (key, expected) in [
        ("RUST_INTEGRATION_REQUIRED", "1"),
        ("TEST_USE_EXISTING", "1"),
        ("ASTRAL_MIGRATION_ENV", "isolated"),
        ("ASTRAL_TEST_DATABASE_NAME", DATABASE),
    ] {
        assert_eq!(
            std::env::var(key).as_deref(),
            Ok(expected),
            "required isolated environment: {key}"
        );
    }
    assert_eq!(
        crate::freeze_projection_execution_mode(crate::ProjectionExecutionMode::WorkerOwned),
        Ok(crate::ProjectionExecutionMode::WorkerOwned)
    );
    let url = std::env::var("DATABASE_URL").expect("required run-owned MySQL URL");
    assert!(!url.contains('?') && !url.contains('#'));
    let options = MySqlConnectOptions::from_str(&url).expect("parse private connection options");
    assert_eq!(options.get_host(), "127.0.0.1");
    assert_eq!(options.get_port(), 3308);
    assert_eq!(options.get_database(), Some(DATABASE));
    assert!(options.get_socket().is_none());
    let pool = MySqlPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(8))
        .connect_with(options)
        .await
        .expect("connect to the approved isolated clone");
    crate::validate_projection_owned_schema(&pool)
        .await
        .unwrap();
    let source = include_str!(
        "../../../migrations/20261015000001_authorization_projection_owned_execution.sql"
    )
    .replace("\r\n", "\n");
    assert_eq!(
        hex::encode(Sha384::digest(source.as_bytes())),
        MIGRATION_CHECKSUM
    );
    let checksum: (i64, Vec<u8>) = sqlx::query_as(
        "SELECT CAST(success AS SIGNED), checksum FROM _sqlx_migrations WHERE version = ?",
    )
    .bind(MIGRATION_VERSION)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(checksum.0, 1);
    assert_eq!(hex::encode(checksum.1), MIGRATION_CHECKSUM);
    pool
}

fn item(grant: &CanonicalGrant, remove: bool) -> AuthorizationImpactItemInput {
    let digest = hex::encode(sha2::Sha256::digest(
        encode_segment_payload(std::slice::from_ref(grant)).unwrap(),
    ));
    AuthorizationImpactItemInput {
        projection_key: policy_engine::ProjectionKey::from_grant(grant)
            .unwrap()
            .canonical_input()
            .unwrap(),
        item_type: if remove {
            AuthorizationImpactItemType::SegmentRemove
        } else {
            AuthorizationImpactItemType::SegmentUpsert
        },
        grant_id: Some(grant.grant_id),
        before_digest_hex: remove.then(|| digest.clone()),
        after_digest_hex: (!remove).then_some(digest),
    }
}

fn command(
    claim: &OwnedDeltaClaim,
    generation: u64,
    grants: &[CanonicalGrant],
    items: Vec<AuthorizationImpactItemInput>,
) -> DeltaProjectorPublishCommand {
    let event = &claim.event;
    let identity = claim.lease.aggregate_identity().clone();
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
            semantic_hash_hex: event.semantic_hash.as_hex(),
            dependency_hash_hex: event.dependency_hash.as_hex(),
            compiler_version: event.compiler_version.clone(),
        },
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence: 0,
            new_revoke_fence: 0,
        },
        mode: CompileModeEvidence {
            compile_mode: ProjectionCompileMode::Replay,
            full_rebuild_reason: None,
        },
        stage: AuthorizationStageRequest {
            identity: identity.clone(),
            card_id: event.card_id,
            target_generation: generation,
            source_generation: event.source_generation,
            projected_generation: event.source_generation,
            event_id: event.event_id.clone(),
            operation_id: event.operation_id.clone(),
            semantic_hash_hex: event.semantic_hash.as_hex(),
            dependency_hash_hex: event.dependency_hash.as_hex(),
            compiler_version: event.compiler_version.clone(),
            revoke_fence: 0,
            segments: grants
                .iter()
                .cloned()
                .map(|grant| StagedSegmentContent::New(vec![grant]))
                .collect(),
        },
        finalize_expected_reference_count: Some(grants.len() as u64),
        impact_plan: AuthorizationImpactPlanAppendRequest {
            identity,
            card_id: event.card_id,
            event_id: event.event_id.clone(),
            operation_id: event.operation_id.clone(),
            base_generation: generation - 1,
            target_generation: generation,
            base_version: event.base_version,
            target_version: event.target_version,
            semantic_hash_hex: event.semantic_hash.as_hex(),
            dependency_hash_hex: event.dependency_hash.as_hex(),
            compiler_version: event.compiler_version.clone(),
            items,
        },
        manifest_lease_owner: event.lease_owner.clone(),
        manifest_lease_seconds: 90,
    }
}

async fn claim_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: &DeltaEventAppendRequest,
) -> Box<OwnedDeltaClaim> {
    match crate::grant_repository::claim_owned_exact_in_tx(
        tx,
        request,
        "owned-completion-contract",
        90,
    )
    .await
    .unwrap()
    {
        OwnedStableEventOutcome::Claimed(claim) => claim,
        other => panic!("fresh exact fixture must claim: {other:?}"),
    }
}

async fn probe(
    pool: &MySqlPool,
    request: &DeltaEventAppendRequest,
    label: &str,
    mutation: Query<'_, MySql, MySqlArguments>,
) {
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(
        mutation.execute(&mut *tx).await.unwrap().rows_affected(),
        1,
        "negative control must mutate exactly its intended row: {label}"
    );
    let result = load_in_tx(&mut tx, request).await;
    tx.rollback()
        .await
        .expect("negative-control rollback must be proven before another probe");
    assert!(
        !matches!(result, Ok(Some(_))),
        "corrupt durable evidence produced completion: {label}"
    );
    assert!(
        crate::load_owned_delta_completion(pool, request)
            .await
            .unwrap()
            .is_some(),
        "rollback must restore exact proof: {label}"
    );
    eprintln!(
        "[OWNED_COMPLETION_NEGATIVE] {label}: rejected; rollback and restored proof verified"
    );
}

async fn wait_for_completion_lock(
    pool: &MySqlPool,
    connection_id: u64,
    table: &str,
) -> Result<(), sqlx::Error> {
    loop {
        let statement: Option<Option<String>> = sqlx::query_scalar(
            "SELECT CAST(INFO AS CHAR CHARACTER SET utf8mb4) \
             FROM information_schema.PROCESSLIST WHERE ID = ?",
        )
        .bind(connection_id)
        .fetch_optional(pool)
        .await?;
        if statement
            .flatten()
            .is_some_and(|statement| statement.contains(table) && statement.ends_with("FOR UPDATE"))
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn completion_pointer_lock_order(
    pool: &MySqlPool,
    request: &DeltaEventAppendRequest,
    inverted_control: bool,
) {
    let identity = ProjectionAggregateIdentity::new(
        request.tenant_id,
        request.aggregate_type.clone(),
        request.aggregate_id,
    )
    .unwrap();
    let mut planner = pool.begin().await.unwrap();
    assert!(lock_current_pointer_in_tx(&mut planner, &identity)
        .await
        .unwrap()
        .is_some());
    let mut completion = pool.begin().await.unwrap();
    let connection_id: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
        .fetch_one(&mut *completion)
        .await
        .unwrap();
    let completion_future = async {
        let result = if inverted_control {
            assert!(crate::grant_repository::exact_owned_event_succeeded_in_tx(
                &mut completion,
                request,
            )
            .await
            .unwrap());
            lock_current_pointer_in_tx(&mut completion, &identity)
                .await
                .map(|pointer| pointer.is_some())
        } else {
            load_in_tx(&mut completion, request)
                .await
                .map(|proof| proof.is_some())
        };
        completion
            .rollback()
            .await
            .expect("completion observation must release its locks explicitly");
        result
    };
    let planner_future = async {
        let waiting = tokio::time::timeout(
            Duration::from_secs(4),
            wait_for_completion_lock(pool, connection_id, "FROM authorization_projection_current"),
        )
        .await;
        let locked_delta = if matches!(waiting, Ok(Ok(()))) {
            Some(
                sqlx::query_scalar::<_, i64>(
                    "SELECT delta_event_id FROM authorization_delta_event \
                     WHERE tenant_id = ? AND event_id = ? FOR UPDATE NOWAIT",
                )
                .bind(request.tenant_id)
                .bind(&request.event_id)
                .fetch_one(&mut *planner)
                .await,
            )
        } else {
            None
        };
        let frontier = if matches!(locked_delta, Some(Ok(_))) {
            Some(load_published_aggregate_frontier_in_tx(&mut planner, &identity).await)
        } else {
            None
        };
        planner
            .rollback()
            .await
            .expect("planner observation must rollback before the completion resumes");
        (waiting, locked_delta, frontier)
    };
    let (completion_result, (waiting, locked_delta, frontier)) =
        tokio::time::timeout(Duration::from_secs(12), async {
            tokio::join!(completion_future, planner_future)
        })
        .await
        .expect("lock-order regression exceeded its bounded read-only episode");
    waiting
        .expect("completion must reach a real pointer-lock wait")
        .expect("same-user process observation must succeed");
    let locked_delta = locked_delta.expect("pointer-lock wait was not observed");
    if inverted_control {
        assert!(matches!(
            locked_delta,
            Err(sqlx::Error::Database(ref error)) if error
                .try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>()
                .is_some_and(|database| database.number() == 3572)
        ));
        assert!(frontier.is_none());
    } else {
        locked_delta.expect("completion must not lock a published delta before the pointer");
        assert!(frontier
            .expect("the real planning reader must run while completion waits")
            .unwrap()
            .is_some());
    }
    assert!(completion_result.unwrap());
    assert!(crate::load_owned_delta_completion(pool, request)
        .await
        .unwrap()
        .is_some());
    eprintln!(
        "[OWNED_COMPLETION_LOCK_ORDER] inverted_control={inverted_control}; real pointer wait, delta NOWAIT and planning progress verified; observations rolled back"
    );
}

async fn completion_lane_lock_order(
    pool: &MySqlPool,
    request: &DeltaEventAppendRequest,
    historical_request: &DeltaEventAppendRequest,
    lease: &crate::OwnedDeltaLease,
) {
    assert!(crate::load_owned_delta_completion(pool, request)
        .await
        .unwrap()
        .is_none());
    assert!(crate::load_owned_delta_completion(pool, historical_request)
        .await
        .unwrap()
        .is_some());
    let mut publisher = pool.begin().await.unwrap();
    let epoch: i64 = sqlx::query_scalar(
        "SELECT execution_epoch FROM authorization_projection_partition_lease \
         WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? FOR UPDATE",
    )
    .bind(request.tenant_id)
    .bind(&request.aggregate_type)
    .bind(request.aggregate_id)
    .fetch_one(&mut *publisher)
    .await
    .unwrap();
    assert_eq!(epoch, lease.ownership_epoch());
    let mut completion = pool.begin().await.unwrap();
    let connection_id: u64 = sqlx::query_scalar("SELECT CONNECTION_ID()")
        .fetch_one(&mut *completion)
        .await
        .unwrap();
    let completion_future = async {
        let result = load_in_tx(&mut completion, request).await;
        completion
            .rollback()
            .await
            .expect("active completion observation must rollback explicitly");
        result
    };
    let publisher_future = async {
        let waiting = tokio::time::timeout(
            Duration::from_secs(4),
            wait_for_completion_lock(
                pool,
                connection_id,
                "FROM authorization_projection_partition_lease",
            ),
        )
        .await;
        let observations = if matches!(waiting, Ok(Ok(()))) {
            let event = sqlx::query_scalar::<_, i64>(
                "SELECT delta_event_id FROM authorization_delta_event \
                 WHERE tenant_id = ? AND event_id = ? FOR UPDATE NOWAIT",
            )
            .bind(request.tenant_id)
            .bind(&request.event_id)
            .fetch_one(&mut *publisher)
            .await;
            let pointer = sqlx::query_scalar::<_, i64>(
                "SELECT current_generation FROM authorization_projection_current \
                 WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? \
                 FOR UPDATE NOWAIT",
            )
            .bind(request.tenant_id)
            .bind(&request.aggregate_type)
            .bind(request.aggregate_id)
            .fetch_one(&mut *publisher)
            .await;
            Some((event, pointer))
        } else {
            None
        };
        publisher
            .rollback()
            .await
            .expect("lane holder must rollback before completion resumes");
        (waiting, observations)
    };
    let (completion_result, (waiting, observations)) =
        tokio::time::timeout(Duration::from_secs(12), async {
            tokio::join!(completion_future, publisher_future)
        })
        .await
        .expect("lane serialization regression exceeded its bounded episode");
    waiting
        .expect("completion must reach a real lane-lock wait")
        .expect("same-user process observation must succeed");
    let (event, pointer) = observations.expect("lane-lock wait must be observed");
    assert_eq!(event.unwrap(), lease.identity().delta_event_id);
    assert!(pointer.unwrap() > 0);
    assert!(completion_result.unwrap().is_none());
    let mut planner = pool.begin().await.unwrap();
    let frontier =
        load_published_aggregate_frontier_in_tx(&mut planner, lease.aggregate_identity()).await;
    let mut active_probe = pool.begin().await.unwrap();
    let active_available = sqlx::query_scalar::<_, i64>(
        "SELECT delta_event_id FROM authorization_delta_event \
         WHERE tenant_id = ? AND event_id = ? FOR UPDATE NOWAIT",
    )
    .bind(request.tenant_id)
    .bind(&request.event_id)
    .fetch_one(&mut *active_probe)
    .await;
    active_probe.rollback().await.unwrap();
    planner.rollback().await.unwrap();
    assert!(frontier.unwrap().is_some());
    assert_eq!(active_available.unwrap(), lease.identity().delta_event_id);
    let state: (String, i64, i64, i64) = sqlx::query_as(
        "SELECT status, attempts, execution_attempts, execution_failures \
         FROM authorization_delta_event WHERE tenant_id = ? AND event_id = ?",
    )
    .bind(request.tenant_id)
    .bind(&request.event_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(state, ("LEASED".to_owned(), 1, 1, 0));
    eprintln!("[OWNED_COMPLETION_LANE] real lane wait; active delta and pointer remain available to owner; active completion refused; historical proof and frontier retained; no accounting mutation");
}

async fn run_integrity_contract() {
    let pool = pool().await;
    let fixture = Fixture::new();
    eprintln!(
        "[OWNED_COMPLETION_SETUP] tenant={} salt={}",
        fixture.identity.tenant_id, fixture.salt
    );
    let first = fixture.grant("completion_a", 1);
    let second = fixture.grant("completion_b", 2);
    let mut moved = first.clone();
    moved.resource = "completion_c".to_owned();
    moved.revision = first.revision.next().unwrap();
    moved.provenance.operation_id = format!("seal-op-{}-3", fixture.salt);
    moved.provenance.event_id = Some(format!("seal-event-{}-3", fixture.salt));
    let mut last = moved.clone();
    last.resource = "completion_d".to_owned();
    last.revision = moved.revision.next().unwrap();
    last.provenance.operation_id = format!("seal-op-{}-4", fixture.salt);
    last.provenance.event_id = Some(format!("seal-event-{}-4", fixture.salt));
    let requests = [
        fixture.request(1, &first, None),
        fixture.request(2, &second, None),
        fixture.request(3, &moved, Some(&first)),
        fixture.request(4, &last, Some(&moved)),
    ];
    let mut setup = pool.begin().await.unwrap();
    for request in &requests {
        crate::append_delta_event(&mut *setup, request)
            .await
            .unwrap();
    }
    let mut manifest_ids = Vec::new();
    for (index, grants, items) in [
        (0, vec![first.clone()], vec![item(&first, false)]),
        (
            1,
            vec![first.clone(), second.clone()],
            vec![item(&second, false)],
        ),
        (
            2,
            vec![second.clone(), moved.clone()],
            vec![item(&first, true), item(&moved, false)],
        ),
    ] {
        let claim = claim_in_tx(&mut setup, &requests[index]).await;
        let command = command(&claim, index as u64 + 1, &grants, items);
        let outcome =
            crate::project_owned_authorization_delta_in_tx(&mut setup, &command, &claim.lease)
                .await
                .unwrap();
        manifest_ids.push(outcome.stage.manifest_id);
    }
    setup
        .commit()
        .await
        .expect("setup publication COMMIT must be proven; never replay an unknown result");
    for request in &requests[..3] {
        assert!(crate::load_owned_delta_completion(&pool, request)
            .await
            .unwrap()
            .is_some());
    }
    let target = &requests[2];
    completion_pointer_lock_order(&pool, target, true).await;
    completion_pointer_lock_order(&pool, target, false).await;
    let item_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_impact_plan_item WHERE tenant_id = ? AND event_id = ?",
    )
    .bind(target.tenant_id)
    .bind(&target.event_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(item_count, 2, "subset control needs a real multi-item plan");
    let archive_state: Vec<(String,)> = sqlx::query_as(
        "SELECT status FROM authorization_archive_outbox WHERE tenant_id = ? ORDER BY generation",
    )
    .bind(target.tenant_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        archive_state,
        vec![("PENDING".to_owned(),), ("PENDING".to_owned(),)]
    );
    let proofs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authorization_archive_manifest WHERE tenant_id = ?",
    )
    .bind(target.tenant_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        proofs, 0,
        "retained publication proof must not invent completed archives"
    );
    let mut drift = target.clone();
    drift.operation_id.push_str("-drift");
    assert!(crate::load_owned_delta_completion(&pool, &drift)
        .await
        .is_err());

    probe(&pool, target, "partial item deletion", sqlx::query("DELETE FROM authorization_impact_plan_item WHERE tenant_id = ? AND event_id = ? ORDER BY item_id LIMIT 1").bind(target.tenant_id).bind(&target.event_id)).await;
    probe(&pool, target, "item field drift", sqlx::query("UPDATE authorization_impact_plan_item SET before_digest = UNHEX(REPEAT('ee', 32)) WHERE tenant_id = ? AND event_id = ? ORDER BY item_id LIMIT 1").bind(target.tenant_id).bind(&target.event_id)).await;
    probe(&pool, target, "missing completion seal", sqlx::query("DELETE FROM audit_log WHERE tenant_id = ? AND action = 'owned_lane_COMPLETION_SEAL' AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.eventId')) = ?").bind(target.tenant_id).bind(&target.event_id)).await;
    probe(&pool, target, "completion audit dimension drift", sqlx::query("UPDATE audit_log SET action = LOWER(action) WHERE tenant_id = ? AND action = 'owned_lane_COMPLETION_SEAL' AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.eventId')) = ?").bind(target.tenant_id).bind(&target.event_id)).await;
    probe(&pool, target, "corrupt completion seal", sqlx::query("UPDATE audit_log SET detail = JSON_SET(detail, '$.digest', REPEAT('0', 64)) WHERE tenant_id = ? AND action = 'owned_lane_COMPLETION_SEAL' AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.eventId')) = ?").bind(target.tenant_id).bind(&target.event_id)).await;
    probe(&pool, target, "duplicate completion seal", sqlx::query("INSERT INTO audit_log (user_id, card_id, action, resource, decision, reason, event_type, request_id, tenant_id, detail) SELECT user_id, card_id, action, resource, decision, reason, event_type, request_id, tenant_id, detail FROM audit_log WHERE tenant_id = ? AND action = 'owned_lane_COMPLETION_SEAL' AND JSON_UNQUOTE(JSON_EXTRACT(detail, '$.eventId')) = ?").bind(target.tenant_id).bind(&target.event_id)).await;
    probe(&pool, target, "current pointer provenance drift", sqlx::query("UPDATE authorization_projection_current SET event_id = 'completion-corrupt-pointer' WHERE tenant_id = ? AND aggregate_id = ?").bind(target.tenant_id).bind(target.aggregate_id)).await;
    probe(&pool, target, "ancestor manifest seal drift", sqlx::query("UPDATE authorization_projection_manifest SET manifest_digest = UNHEX(REPEAT('00', 32)) WHERE tenant_id = ? AND manifest_id = ?").bind(target.tenant_id).bind(manifest_ids[0])).await;
    probe(&pool, target, "ancestor reference deletion", sqlx::query("DELETE FROM authorization_projection_manifest_segment WHERE tenant_id = ? AND manifest_id = ? ORDER BY segment_ordinal LIMIT 1").bind(target.tenant_id).bind(manifest_ids[0])).await;
    probe(&pool, target, "ancestor parent deletion", sqlx::query("UPDATE authorization_projection_manifest SET parent_manifest_id = NULL WHERE tenant_id = ? AND manifest_id = ?").bind(target.tenant_id).bind(manifest_ids[1])).await;
    let segment_id: i64 = sqlx::query_scalar("SELECT segment_id FROM authorization_projection_manifest_segment WHERE tenant_id = ? AND manifest_id = ? ORDER BY segment_ordinal LIMIT 1")
        .bind(target.tenant_id).bind(manifest_ids[0]).fetch_one(&pool).await.unwrap();
    probe(&pool, target, "ancestor segment local seal drift", sqlx::query("UPDATE authorization_projection_segment SET semantic_hash = UNHEX(REPEAT('00', 32)) WHERE tenant_id = ? AND segment_id = ?").bind(target.tenant_id).bind(segment_id)).await;
    probe(
        &pool,
        target,
        "missing archive intent",
        sqlx::query(
            "DELETE FROM authorization_archive_outbox WHERE tenant_id = ? AND generation = ?",
        )
        .bind(target.tenant_id)
        .bind(1_i64),
    )
    .await;
    probe(&pool, target, "archive key drift", sqlx::query("UPDATE authorization_archive_outbox SET archive_key = 'completion-corrupt-key' WHERE tenant_id = ? AND generation = ?").bind(target.tenant_id).bind(1_i64)).await;
    probe(&pool, target, "archive success without proof", sqlx::query("UPDATE authorization_archive_outbox SET status = 'SUCCEEDED', archived_at = UTC_TIMESTAMP() WHERE tenant_id = ? AND generation = ?").bind(target.tenant_id).bind(1_i64)).await;
    probe(&pool, target, "missing ownership tombstone", sqlx::query("DELETE FROM authorization_projection_partition_lease WHERE tenant_id = ? AND aggregate_id = ?").bind(target.tenant_id).bind(target.aggregate_id)).await;

    let mut archive_read = pool.begin().await.unwrap();
    let archive_manifest = fetch_manifest_for_update(&mut archive_read, manifest_ids[0])
        .await
        .unwrap()
        .unwrap();
    archive_read
        .rollback()
        .await
        .expect("release archive observation locks explicitly");
    let archive_request = AuthorizationArchiveProofRequest {
        identity: fixture.identity.clone(),
        card_id: Some(fixture.card_id),
        archived_manifest_id: manifest_ids[0],
        archived_generation: 1,
        event_id: requests[0].event_id.clone(),
        operation_id: requests[0].operation_id.clone(),
        archive_key: derive_archive_key(&fixture.identity, 1).unwrap(),
        semantic_hash_hex: requests[0].semantic_hash_hex.clone(),
        dependency_hash_hex: requests[0].dependency_hash_hex.clone(),
        compiler_version: requests[0].compiler_version.clone(),
        archived_revoke_fence: 0,
        manifest_chain_digest_hex: archive_manifest.decode_hashes().unwrap().2.as_hex(),
    };
    for (label, mutation, accepted) in [
        ("terminal archive proof", "UPDATE authorization_archive_outbox SET status = 'SUCCEEDED', archived_at = UTC_TIMESTAMP() WHERE tenant_id = ? AND generation = 1", true),
        ("succeeded archive with staged proof", "UPDATE authorization_archive_manifest SET status = 'STAGED', archived_at = NULL WHERE tenant_id = ? AND generation = 1", false),
        ("corrupt archive digest", "UPDATE authorization_archive_manifest SET archive_digest = UNHEX(REPEAT('00', 32)) WHERE tenant_id = ? AND generation = 1", false),
    ] {
        let mut tx = pool.begin().await.unwrap();
        record_authorization_archive_proof_in_tx(&mut tx, &archive_request).await.unwrap();
        sqlx::query("UPDATE authorization_archive_outbox SET status = 'SUCCEEDED', archived_at = UTC_TIMESTAMP() WHERE tenant_id = ? AND generation = 1")
            .bind(target.tenant_id).execute(&mut *tx).await.unwrap();
        let changed = sqlx::query(mutation).bind(target.tenant_id).execute(&mut *tx).await.unwrap();
        if !accepted { assert_eq!(changed.rows_affected(), 1); }
        let actual = load_in_tx(&mut tx, target).await;
        tx.rollback().await.expect("archive proof probe must rollback before its successor");
        assert_eq!(matches!(actual, Ok(Some(_))), accepted, "archive proof control: {label}");
        assert!(crate::load_owned_delta_completion(&pool, target).await.unwrap().is_some());
        eprintln!("[OWNED_COMPLETION_ARCHIVE] {label}: accepted={accepted}; rollback verified");
    }

    let claim = match crate::claim_owned_delta_event_by_stable_event(
        &pool,
        &requests[3],
        "owned-completion-contract",
        90,
    )
    .await
    .unwrap()
    {
        OwnedStableEventOutcome::Claimed(claim) => claim,
        other => panic!("fourth exact fixture must claim: {other:?}"),
    };
    crate::begin_owned_delta_execution(&pool, &claim.lease)
        .await
        .unwrap();
    completion_lane_lock_order(&pool, &requests[3], target, &claim.lease).await;
    let final_command = command(
        &claim,
        4,
        &[second, last.clone()],
        vec![item(&moved, true), item(&last, false)],
    );
    let mut failed = pool.begin().await.unwrap();
    let outcome =
        crate::project_owned_authorization_delta_in_tx(&mut failed, &final_command, &claim.lease)
            .await
            .unwrap();
    assert_eq!(sqlx::query("DELETE FROM authorization_impact_plan_item WHERE tenant_id = ? AND event_id = ? ORDER BY item_id LIMIT 1")
        .bind(target.tenant_id).bind(&requests[3].event_id).execute(&mut *failed).await.unwrap().rows_affected(), 1);
    let rejected = record_publication_in_tx(&mut failed, &final_command, &outcome).await;
    assert!(
        rejected.is_err(),
        "late seal rejection must abort the publication unit"
    );
    failed
        .rollback()
        .await
        .expect("publication failure must have a proven whole-transaction rollback");
    let frontier: (i64, i64) = sqlx::query_as("SELECT current_generation, manifest_id FROM authorization_projection_current WHERE tenant_id = ? AND aggregate_id = ?")
        .bind(target.tenant_id).bind(target.aggregate_id).fetch_one(&pool).await.unwrap();
    assert_eq!(frontier, (3, manifest_ids[2]));
    let state: (String, i64, i64, i64) = sqlx::query_as("SELECT status, attempts, execution_attempts, execution_failures FROM authorization_delta_event WHERE tenant_id = ? AND event_id = ?")
        .bind(target.tenant_id).bind(&requests[3].event_id).fetch_one(&pool).await.unwrap();
    assert_eq!(state, ("LEASED".to_owned(), 1, 1, 0));
    for table in [
        "authorization_impact_plan",
        "authorization_projection_manifest",
    ] {
        let count: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {table} WHERE tenant_id = ? AND event_id = ?"
        ))
        .bind(target.tenant_id)
        .bind(&requests[3].event_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            count, 0,
            "no partial fourth publication may survive: {table}"
        );
    }
    let mut success = pool.begin().await.unwrap();
    crate::project_owned_authorization_delta_in_tx(&mut success, &final_command, &claim.lease)
        .await
        .unwrap();
    success
        .commit()
        .await
        .expect("re-execution is permitted only after the earlier rollback was proven");
    for request in &requests {
        assert!(crate::load_owned_delta_completion(&pool, request)
            .await
            .unwrap()
            .is_some());
    }
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM authorization_projection_partition_lease WHERE tenant_id = ? AND (lease_owner <> '' OR active_delta_event_id IS NOT NULL OR active_delta_token_hash IS NOT NULL OR lease_expires_at > UTC_TIMESTAMP(6))")
        .bind(target.tenant_id).fetch_one(&pool).await.unwrap();
    assert_eq!(active, 0);
    let mut cleanup = pool.begin().await.unwrap();
    for table in [
        "authorization_projection_manifest_segment",
        "authorization_projection_current",
        "authorization_projection_manifest",
        "authorization_projection_segment",
        "authorization_impact_plan_item",
        "authorization_impact_plan",
        "authorization_archive_manifest",
        "authorization_archive_outbox",
        "authorization_projection_partition_lease",
        "audit_log",
        "authorization_delta_event",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE tenant_id = ?"))
            .bind(target.tenant_id)
            .execute(&mut *cleanup)
            .await
            .unwrap();
    }
    cleanup
        .commit()
        .await
        .expect("only this proven successful UUID-owned fixture is cleaned");
    eprintln!("[OWNED_COMPLETION] exact historical proof, 15 corruption controls, late failure rollback and successful fixture cleanup verified");
    pool.close().await;
}

#[tokio::test]
#[ignore = "real MySQL; approved migrated run-owned loopback clone and required integration environment"]
async fn owned_completion_real_mysql_integrity_contract() {
    tokio::time::timeout(Duration::from_secs(110), run_integrity_contract())
        .await
        .expect(
            "owned completion integrity contract exceeded its bounded deadline; retain fixture",
        );
}
