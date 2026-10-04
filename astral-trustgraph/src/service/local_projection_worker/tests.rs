//! Pure (no-DB) tests for the local projection worker's scope-plan mirror:
//! proven advance, poisoning, provenance gate, and bounded sorted insertion.

use super::{
    insert_ledger_row_sorted, published_state_ledger_row, supervise_local_projection_worker,
    validate_recovery_scope, AbortOnDropJoin, MirrorAdvanceReport, PublicationContext, ScopeKey,
    ScopePlanMirror, WorkerLivenessCell,
};
use crate::service::authorization_projector::{ProjectorCancellationToken, WorkerRunSummary};
use astral_db::{
    AuthorizationArchiveIntentOutcome, AuthorizationCurrentPointerRecord,
    AuthorizationImpactPlanOutcome, AuthorizationPublishOutcome, AuthorizationPublishedState,
    AuthorizationSegmentSnapshot, AuthorizationStageOutcome, ClaimedDeltaEvent,
    DeltaEventAppendRequest, DeltaEventType, DeltaProjectorPublishOutcome,
    ProjectionAggregateIdentity, PublishedAggregateFrontier, PublishedGenerationSummary,
    RawLedgerRow, Sha256Digest,
};
use astral_types::{
    BindingLayer, CanonicalGrant, GrantEffect, GrantId, GrantProvenance, GrantRevision,
    GrantSourceKind, GrantState, TenantScope, ValidityWindow,
};
use std::sync::Arc;

const GRANT_UUID: &str = "550e8400-e29b-41d4-a716-446655440004";

fn identity() -> ProjectionAggregateIdentity {
    ProjectionAggregateIdentity::new(7, "card".to_owned(), 42).expect("identity")
}

fn canonical_grant(revision: u64, state: GrantState) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: GrantId::parse(GRANT_UUID).expect("grant id"),
        revision: GrantRevision::new(revision).expect("revision"),
        state,
        source_kind: GrantSourceKind::Direct,
        binding_layer: BindingLayer::None,
        tenant: TenantScope::new(7, Some(11)).expect("tenant"),
        card_id: 11,
        user_id: 3,
        resource: "learn_subject".to_owned(),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::between(100, 200),
        provenance: GrantProvenance {
            source_id: "personal-card-11".to_owned(),
            source_entry: Some("personal-card-11".to_owned()),
            binding_id: Some("binding-1".to_owned()),
            delegation_id: None,
            operation_id: "op-evt-1".to_owned(),
            event_id: Some("evt-1".to_owned()),
            actor_user_id: Some(3),
        },
    }
}

fn ledger_row_for(grant: &CanonicalGrant, event_id: &str, revision: u64) -> RawLedgerRow {
    RawLedgerRow {
        revision_no: revision as i64,
        tenant_id: 7,
        card_id: Some(11),
        aggregate_type: "card".to_owned(),
        aggregate_id: 42,
        grant_id: grant.grant_id.as_str().to_owned(),
        status: "ACTIVE".to_owned(),
        is_tombstone: i8::from(matches!(
            grant.state,
            GrantState::Removed | GrantState::Revoked
        )),
        grant_payload: grant.canonical_input().expect("canonical payload"),
        semantic_hash: vec![1u8; 32],
        dependency_hash: vec![2u8; 32],
        operation_id: format!("op-{event_id}"),
        event_id: event_id.to_owned(),
        compiler_version: "test-compiler".to_owned(),
    }
}

fn claimed_for(event_id: &str, target_version: i64) -> ClaimedDeltaEvent {
    ClaimedDeltaEvent {
        delta_event_id: 7,
        event_id: event_id.to_owned(),
        operation_id: format!("op-{event_id}"),
        event_type: DeltaEventType::Update,
        tenant_id: 7,
        card_id: Some(11),
        aggregate_type: "card".to_owned(),
        aggregate_id: 42,
        grant_id: GrantId::parse(GRANT_UUID).expect("grant id"),
        base_version: target_version - 1,
        target_version,
        source_generation: 9,
        revoke_fence: 0,
        before_image_json: None,
        before_digest: None,
        delta_json: r#"{"op":"UPDATE"}"#.to_owned(),
        semantic_hash: Sha256Digest::from_bytes(vec![1u8; 32]).expect("semantic"),
        dependency_hash: Sha256Digest::from_bytes(vec![2u8; 32]).expect("dependency"),
        compiler_version: "test-compiler".to_owned(),
        attempts: 1,
        cas_version: 5,
        lease_owner: "local-projection:test".to_owned(),
        lease_expires_at: time::PrimitiveDateTime::new(
            time::Date::from_calendar_date(2026, time::Month::January, 1).expect("date"),
            time::Time::MIDNIGHT,
        ),
    }
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes(vec![byte; 32]).expect("digest")
}

fn pointer(generation: u64, manifest_id: i64, event_id: &str) -> AuthorizationCurrentPointerRecord {
    AuthorizationCurrentPointerRecord {
        pointer_id: 1,
        identity: identity(),
        card_id: Some(11),
        current_generation: generation,
        manifest_id,
        event_id: event_id.to_owned(),
        operation_id: format!("op-{event_id}"),
        semantic_hash: digest(1),
        dependency_hash: digest(2),
        compiler_version: "test-compiler".to_owned(),
        revoke_fence: 0,
        revoke_fence_proven: true,
        cas_version: 4,
    }
}

fn summary_for(generation: u64, manifest_id: i64, event_id: &str) -> PublishedGenerationSummary {
    PublishedGenerationSummary {
        manifest_id,
        generation,
        source_generation: 5,
        projected_generation: generation,
        event_id: event_id.to_owned(),
        operation_id: format!("op-{event_id}"),
        semantic_hash: digest(1),
        dependency_hash: digest(2),
        compiler_version: "test-compiler".to_owned(),
        manifest_digest: digest(3),
        parent_manifest_id: None,
        revoke_fence: 0,
        card_id: Some(11),
    }
}

fn published_state(grant: &CanonicalGrant) -> AuthorizationPublishedState {
    AuthorizationPublishedState {
        pointer: pointer(2, 22, "evt-2"),
        manifest_id: 22,
        generation: 2,
        source_generation: 9,
        projected_generation: 2,
        event_id: "evt-2".to_owned(),
        operation_id: "op-evt-2".to_owned(),
        semantic_hash: digest(1),
        dependency_hash: digest(2),
        compiler_version: "test-compiler".to_owned(),
        manifest_digest: digest(3),
        parent_manifest_id: Some(11),
        revoke_fence: 0,
        segments: vec![AuthorizationSegmentSnapshot {
            segment_id: 1,
            identity: identity(),
            card_id: Some(11),
            content_digest: digest(4),
            semantic_hash: digest(1),
            dependency_hash: digest(2),
            compiler_version: "test-compiler".to_owned(),
            format: "v1".to_owned(),
            row_count: 1,
            byte_size: 64,
            grants: vec![grant.clone()],
        }],
        references: Vec::new(),
        total_grant_count: 1,
    }
}

fn publish_outcome(state: AuthorizationPublishedState) -> DeltaProjectorPublishOutcome {
    DeltaProjectorPublishOutcome {
        impact_plan: AuthorizationImpactPlanOutcome {
            plan_id: 1,
            resumed_existing_plan: false,
            item_count: 1,
        },
        stage: AuthorizationStageOutcome {
            manifest_id: 22,
            manifest_digest: digest(3),
            target_generation: 2,
            total_grant_count: 1,
            new_segment_count: 1,
            reused_segment_count: 0,
            resumed_existing_manifest: false,
            base_pointer: None,
        },
        archive_intent: Some(AuthorizationArchiveIntentOutcome {
            archive_outbox_id: 1,
            resumed_existing_intent: false,
        }),
        publish: AuthorizationPublishOutcome {
            pointer: state.pointer.clone(),
            published_state: Arc::new(state),
            published_manifest_id: 22,
            previous_superseded_manifest_id: Some(11),
            initialized_first_pointer: false,
        },
    }
}

fn seeded_mirror(grant: &CanonicalGrant) -> ScopePlanMirror {
    let mirror = ScopePlanMirror::default();
    mirror.note_publication(
        &identity(),
        PublicationContext {
            frontier: PublishedAggregateFrontier {
                identity: identity(),
                card_id: Some(11),
                pointer: pointer(1, 11, "evt-1"),
                manifest: summary_for(1, 11, "evt-1"),
                events: Vec::new(),
            },
            parent_references: Vec::new(),
        },
    );
    mirror.note_ledger(&identity(), vec![ledger_row_for(grant, "evt-1", 1)]);
    mirror
}

#[test]
fn shared_ledger_reads_reuse_storage_and_keep_old_snapshots_immutable() {
    let mirror = seeded_mirror(&canonical_grant(1, GrantState::Active));
    let key = ScopeKey::of(&identity());
    let original = mirror.ledger(&key).unwrap();
    let next_read = mirror.ledger(&key).unwrap();
    assert!(Arc::ptr_eq(&original, &next_read));
    let claimed = claimed_for("evt-2", 2);
    let revision_2 = canonical_grant(2, GrantState::Active);
    let request = dispatch_request_for(&claimed, &revision_2);
    assert_eq!(
        mirror.upsert_claimed_row(&request, &claimed),
        super::MirrorRowProvenance::Upserted
    );
    let extended = mirror.ledger(&key).unwrap();
    assert!(!Arc::ptr_eq(&original, &extended));
    assert_eq!(original.len(), 1);
    assert_eq!(extended.len(), 2);
    mirror.advance(&claimed, &publish_outcome(published_state(&revision_2)));
    assert_eq!(original.len(), 1);
    assert_eq!(extended[1].revision_no, 2);
    assert_eq!(mirror.ledger(&key).unwrap().len(), 2);
}

#[test]
#[ignore = "local CPU-only ledger sharing performance probe"]
fn shared_ledger_performance_probe() {
    use std::hint::black_box;
    use std::time::Instant;

    for size in [128, 512, 2_048] {
        let mirror = seeded_mirror(&canonical_grant(1, GrantState::Active));
        let row = ledger_row_for(&canonical_grant(1, GrantState::Active), "evt-1", 1);
        mirror.note_ledger(&identity(), vec![row; size]);
        let key = ScopeKey::of(&identity());
        let shared = mirror.ledger(&key).unwrap();
        let start = Instant::now();
        for _ in 0..100 {
            black_box((*shared).clone());
        }
        let owned_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        for _ in 0..100 {
            black_box(mirror.ledger(&key).unwrap());
        }
        let shared_ns = start.elapsed().as_nanos();
        eprintln!("ledger_reads size={size} reads=100 owned_ns={owned_ns} shared_ns={shared_ns}");
    }
}

#[test]
fn proven_publish_advances_frontier_and_ledger() {
    let revision_1 = canonical_grant(1, GrantState::Active);
    let mirror = seeded_mirror(&revision_1);

    // Event 2 updates the same grant to revision 2 (published state verified).
    let revision_2 = canonical_grant(2, GrantState::Active);
    let claimed = claimed_for("evt-2", 2);
    let report = mirror.advance(&claimed, &publish_outcome(published_state(&revision_2)));
    assert_eq!(
        report,
        MirrorAdvanceReport {
            frontier_advanced: true,
            ledger_row_appended: true,
            scope_poisoned: false,
        }
    );

    let (publication, ledger_rows) = mirror
        .get(&ScopeKey::of(&identity()))
        .expect("scope served from mirror");
    // Frontier advanced to generation 2 with the new event.
    assert_eq!(publication.frontier.pointer.current_generation, 2);
    assert_eq!(publication.frontier.events.len(), 1);
    assert_eq!(publication.frontier.events[0].event_id, "evt-2");
    assert_eq!(publication.frontier.events[0].generation, 2);
    // Ledger now carries both revisions of the grant, sorted.
    assert_eq!(ledger_rows.len(), 2);
    assert_eq!(ledger_rows[0].event_id, "evt-1");
    assert_eq!(ledger_rows[1].event_id, "evt-2");
    assert_eq!(ledger_rows[1].revision_no, 2);
}

#[test]
fn published_state_ledger_row_rejects_revision_drift() {
    let stale = canonical_grant(1, GrantState::Active);
    let state = published_state(&stale);
    let claimed = claimed_for("evt-2", 2);
    let error = published_state_ledger_row(&claimed, &state).expect_err("revision drift");
    assert!(error.contains("published_revision_mismatch"), "{error}");
}

fn dispatch_request_for(
    claimed: &ClaimedDeltaEvent,
    grant: &CanonicalGrant,
) -> DeltaEventAppendRequest {
    DeltaEventAppendRequest {
        tenant_id: claimed.tenant_id,
        card_id: claimed.card_id,
        aggregate_type: claimed.aggregate_type.clone(),
        aggregate_id: claimed.aggregate_id,
        grant_id: claimed.grant_id,
        event_id: claimed.event_id.clone(),
        operation_id: claimed.operation_id.clone(),
        event_type: claimed.event_type,
        base_version: claimed.base_version,
        target_version: claimed.target_version,
        source_generation: claimed.source_generation,
        revoke_fence: claimed.revoke_fence,
        invalidates_published_evidence: false,
        before_image_json: None,
        before_digest_hex: None,
        delta_json: serde_json::to_string(&astral_types::GrantDelta::Update {
            grant: grant.clone(),
            expected_revision: GrantRevision::new(claimed.base_version as u64).expect("expected"),
        })
        .expect("delta json"),
        semantic_hash_hex: claimed.semantic_hash.as_hex(),
        dependency_hash_hex: claimed.dependency_hash.as_hex(),
        compiler_version: claimed.compiler_version.clone(),
        next_attempt_at: None,
    }
}

#[test]
fn upsert_inserts_claimed_row_while_continuity_holds() {
    let revision_1 = canonical_grant(1, GrantState::Active);
    let mirror = seeded_mirror(&revision_1);

    // Event 2 chains directly above the mirror head (base 1 == head rev 1).
    let revision_2 = canonical_grant(2, GrantState::Active);
    let claimed = claimed_for("evt-2", 2);
    let request = dispatch_request_for(&claimed, &revision_2);
    assert_eq!(
        mirror.upsert_claimed_row(&request, &claimed),
        super::MirrorRowProvenance::Upserted
    );
    let (_, ledger_rows) = mirror
        .get(&ScopeKey::of(&identity()))
        .expect("scope served");
    assert_eq!(ledger_rows.len(), 2);
    assert_eq!(ledger_rows[1].event_id, "evt-2");
    assert_eq!(ledger_rows[1].revision_no, 2);

    // The later durable publish REPLACES the request-derived content with the
    // verified published content (no duplicate event rows).
    let report = mirror.advance(&claimed, &publish_outcome(published_state(&revision_2)));
    assert!(report.frontier_advanced && report.ledger_row_appended);
    let (_, ledger_rows) = mirror
        .get(&ScopeKey::of(&identity()))
        .expect("scope served");
    assert_eq!(ledger_rows.len(), 2, "advance must not duplicate the row");
}

#[test]
fn upsert_with_pending_sibling_falls_back_to_strict() {
    let revision_1 = canonical_grant(1, GrantState::Active);
    let mirror = seeded_mirror(&revision_1);

    // A sibling already sits at revision 2 in the source (PENDING, absent from
    // the mirror); claiming revision 3 breaks base continuity (mirror head 1
    // != claimed base 2): cold strict repair, never a silent update.
    let revision_3 = canonical_grant(3, GrantState::Active);
    let claimed = claimed_for("evt-3", 3);
    let request = dispatch_request_for(&claimed, &revision_3);
    assert_eq!(
        mirror.upsert_claimed_row(&request, &claimed),
        super::MirrorRowProvenance::StrictFallback
    );
    assert!(
        mirror.get(&ScopeKey::of(&identity())).is_none(),
        "scope poisoned"
    );
}

#[test]
fn recovery_gate_rejects_untracked_events() {
    let revision_1 = canonical_grant(1, GrantState::Active);
    let mirror = seeded_mirror(&revision_1);

    // A recovery event that never rode the mirror is absent from the
    // provenance ledger: the gate poisons the scope (strict reads follow).
    let untracked = claimed_for("evt-recovery", 2);
    assert!(!mirror.ensure_claimed_row_present(&untracked));
    assert!(mirror.get(&ScopeKey::of(&identity())).is_none());

    // After re-seeding, the gate passes only for rows the mirror carries.
    let mirror = seeded_mirror(&revision_1);
    let tracked = claimed_for("evt-1", 1);
    assert!(mirror.ensure_claimed_row_present(&tracked));
}

#[test]
fn sorted_insert_keeps_partition_order() {
    let grant_a = canonical_grant(1, GrantState::Active);
    let mut rows = vec![
        ledger_row_for(&grant_a, "a-1", 1),
        ledger_row_for(&grant_a, "a-2", 2),
    ];
    // Same grant, revision 3 → appended after.
    insert_ledger_row_sorted(&mut rows, ledger_row_for(&grant_a, "a-3", 3));
    // Lexicographically smaller grant id → sorted BEFORE grant A's rows.
    let mut smaller = ledger_row_for(&grant_a, "b-1", 1);
    smaller.grant_id = "00000000-0000-0000-0000-000000000000".to_owned();
    insert_ledger_row_sorted(&mut rows, smaller);

    let keys: Vec<(String, i64)> = rows
        .iter()
        .map(|row| (row.grant_id.clone(), row.revision_no))
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "partition walker requires sorted input");
}

#[test]
fn tombstone_publish_advances_with_tombstone_flag() {
    let revision_1 = canonical_grant(1, GrantState::Active);
    let mirror = seeded_mirror(&revision_1);

    let tombstoned = canonical_grant(2, GrantState::Revoked);
    let claimed = claimed_for("evt-revoke", 2);
    let report = mirror.advance(&claimed, &publish_outcome(published_state(&tombstoned)));
    assert!(report.frontier_advanced && report.ledger_row_appended);
    let (_, ledger_rows) = mirror
        .get(&ScopeKey::of(&identity()))
        .expect("scope served");
    assert_eq!(ledger_rows[1].is_tombstone, 1);
}

// ── F3 regressions ──

#[test]
fn publish_failure_poisons_exact_aggregate_and_pending_halves() {
    let revision_1 = canonical_grant(1, GrantState::Active);
    let mirror = seeded_mirror(&revision_1);

    // Fully-seeded sibling scope must stay intact.
    let sibling = ProjectionAggregateIdentity::new(7, "card".to_owned(), 43).expect("identity");
    let sibling_grant = canonical_grant(1, GrantState::Active);
    mirror.note_publication(&sibling, {
        let seed = seeded_mirror(&sibling_grant);
        seed.get(&ScopeKey::of(&identity())).expect("seeded").0
    });
    mirror.note_ledger(&sibling, vec![ledger_row_for(&sibling_grant, "evt-1", 1)]);

    // HALF-SEEDED scope: the observe arm ran (pending publication half) but
    // the ledger arm never did — this is the state a publish failure can
    // interrupt mid-seed.
    let half_seeded = ProjectionAggregateIdentity::new(7, "card".to_owned(), 44).expect("identity");
    mirror.note_publication(&half_seeded, {
        let seed = seeded_mirror(&revision_1);
        seed.get(&ScopeKey::of(&identity())).expect("seeded").0
    });

    // F3: the durable publish failed for the exact aggregate (pointer moved /
    // committed-mirror-unavailable / unknown outcome / any context drift) —
    // the planning world of THAT aggregate is invalidated including its
    // pending seed halves.
    mirror.poison(&identity());
    assert!(
        mirror.get(&ScopeKey::of(&identity())).is_none(),
        "failed aggregate must not keep serving a stale planning context"
    );
    // Sibling scope unaffected: poison is exact to the failing aggregate.
    assert!(
        mirror.get(&ScopeKey::of(&sibling)).is_some(),
        "poison must be exact to the failing aggregate"
    );

    // The poisoned scope's PENDING publication half was cleaned with it: a
    // later ledger-only note must NOT silently complete a seed against the
    // poisoned world — strict cold reads re-seed both halves.
    mirror.note_ledger(&identity(), vec![ledger_row_for(&revision_1, "evt-1", 1)]);
    assert!(
        mirror.get(&ScopeKey::of(&identity())).is_none(),
        "pending halves must be cleaned on poison; no orphaned-seed completion"
    );

    // The half-seeded scope still pending on an UNTOUCHED aggregate completes
    // normally (poison did not over-reach).
    mirror.note_ledger(&half_seeded, vec![ledger_row_for(&revision_1, "evt-1", 1)]);
    assert!(
        mirror.get(&ScopeKey::of(&half_seeded)).is_some(),
        "poison must not over-reach to other pending scopes"
    );
}

#[test]
fn claim_commit_unknown_resolves_in_doubt_and_keeps_lease() {
    use super::resolve_claim_commit;
    use astral_db::ClaimedStableEventOutcome as Outcome;

    // A claimed lease whose commit failed: UNRESOLVABLE — never assume
    // rollback success. InDoubt carries no replay and the durable lease is
    // left for server-side expiry reclaim.
    let claimed = Outcome::Claimed {
        claim: Box::new(astral_db::DeltaEventClaim {
            delta_event_id: 1,
            event_id: "evt-1".to_owned(),
            operation_id: "op-evt-1".to_owned(),
            event_type: astral_db::DeltaEventType::Add,
            tenant_id: 7,
            card_id: Some(11),
            aggregate_type: "card".to_owned(),
            aggregate_id: 42,
            grant_id: GrantId::parse(GRANT_UUID).expect("grant id"),
            base_version: 0,
            target_version: 1,
            source_generation: 5,
            revoke_fence: 0,
            before_image_json: None,
            before_digest: None,
            delta_json: "{}".to_owned(),
            semantic_hash: digest(1),
            dependency_hash: digest(2),
            compiler_version: "test-compiler".to_owned(),
            attempts: 1,
            cas_version: 2,
            lease_owner: "local-projection:test".to_owned(),
            lease_token: astral_db::DeltaLeaseToken::new_run_scoped(),
            lease_expires_at: time::PrimitiveDateTime::new(
                time::Date::from_calendar_date(2026, time::Month::January, 1).expect("date"),
                time::Time::MIDNIGHT,
            ),
        }),
        event: Box::new(claimed_for("evt-1", 1)),
    };
    let resolved = resolve_claim_commit(claimed, "connection reset during commit", "evt-1")
        .expect("commit-unknown must not surface as a hard error");
    match resolved {
        Outcome::InDoubt { event_id, reason } => {
            assert_eq!(event_id, "evt-1");
            assert!(
                reason.contains("claim_commit_unknown"),
                "reason must carry the stable commit-unknown token: {reason}"
            );
            assert!(
                reason.contains("durable_lease=left_for_expiry_reclaim"),
                "the durable-lease disposition must be explicit: {reason}"
            );
        }
        other => panic!("commit-unknown must resolve InDoubt, got {other:?}"),
    }

    // Read-only arms (no mutation) pass through: no fake unknown.
    let busy = Outcome::Busy {
        event_id: "evt-2".to_owned(),
    };
    let resolved = resolve_claim_commit(busy, "connection reset", "evt-2").expect("passthrough");
    assert!(matches!(resolved, Outcome::Busy { .. }));
}

#[test]
fn claim_contract_refusals_mark_hub_suspect_but_transient_do_not() {
    use super::claim_error_marks_hub_suspect;
    use super::RepositoryRejection;
    use super::RuntimeAccessError;
    use astral_db::GrantRepositoryError;

    let payload_mismatch = RuntimeAccessError::Repository(RepositoryRejection::Grant(
        GrantRepositoryError::ScopeViolation(
            "code=grant_repository.claim_by_event_payload_mismatch;field=delta_json".to_owned(),
        ),
    ));
    assert!(claim_error_marks_hub_suspect(&payload_mismatch));

    let row_missing = RuntimeAccessError::Repository(RepositoryRejection::Grant(
        GrantRepositoryError::ScopeViolation(
            "code=grant_repository.claim_by_event_row_missing;event_id=evt-1".to_owned(),
        ),
    ));
    assert!(claim_error_marks_hub_suspect(&row_missing));

    // Unrelated scope violation (not the direct-claim binding contract):
    // stays a transient warn, not a suspect.
    let other_violation = RuntimeAccessError::Repository(RepositoryRejection::Grant(
        GrantRepositoryError::ScopeViolation("code=grant_repository.negative_version".to_owned()),
    ));
    assert!(!claim_error_marks_hub_suspect(&other_violation));

    // Transient database failures never mark suspect.
    let transient = RuntimeAccessError::Database("connection refused".to_owned());
    assert!(!claim_error_marks_hub_suspect(&transient));

    // Lost-lease races are ownership unknowns, not contract refusals.
    let lost_lease =
        RuntimeAccessError::Repository(RepositoryRejection::Grant(GrantRepositoryError::ClaimRace));
    assert!(!claim_error_marks_hub_suspect(&lost_lease));
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker liveness supervision (worker-supervision-20261002) — pure seams, no DB
// ─────────────────────────────────────────────────────────────────────────────

/// `Dead` is sticky in the cell: a later non-Dead write is refused, a later
/// Dead write (another observer recording the same death) is allowed.
#[test]
fn worker_liveness_cell_dead_is_sticky() {
    let cell = WorkerLivenessCell::default();
    assert_eq!(
        cell.liveness(),
        super::LocalProjectionWorkerLiveness::NotStarted
    );
    cell.set_liveness(super::LocalProjectionWorkerLiveness::Alive);
    assert_eq!(cell.liveness(), super::LocalProjectionWorkerLiveness::Alive);
    cell.set_liveness(super::LocalProjectionWorkerLiveness::Dead(
        "code=test.died".to_owned(),
    ));
    assert_eq!(
        cell.liveness(),
        super::LocalProjectionWorkerLiveness::Dead("code=test.died".to_owned())
    );
    // A later Alive must NOT resurrect a declared-dead worker.
    cell.set_liveness(super::LocalProjectionWorkerLiveness::Alive);
    assert_eq!(
        cell.liveness(),
        super::LocalProjectionWorkerLiveness::Dead("code=test.died".to_owned())
    );
}

/// The empty-tenant-scope contract: the recovery pass iterates exactly the
/// configured scopes, so an empty list is a start rejection, never a silent
/// disable; a configured scope list is accepted.
#[test]
fn recovery_scope_contract_rejects_empty_and_accepts_configured() {
    let empty: Vec<i64> = Vec::new();
    assert!(matches!(
        validate_recovery_scope(&empty),
        Err(super::LocalProjectionWorkerStartError::InvalidConfig { reason })
            if reason.contains("empty_tenants")
    ));
    assert!(validate_recovery_scope(&[7, 11]).is_ok());
}

/// Real panic in the worker generation: the supervisor records sticky Dead in
/// its cell (no global mirror in this test) and, once shutdown is requested,
/// returns a loud Err instead of a clean summary. No restart is attempted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_marks_death_on_real_panic_and_reports_after_cancel() {
    let cell = std::sync::Arc::new(WorkerLivenessCell::default());
    let shutdown = ProjectorCancellationToken::default();
    let inner: tokio::task::JoinHandle<Result<WorkerRunSummary, String>> =
        tokio::spawn(async move {
            panic!("simulated projection worker panic");
            #[allow(unreachable_code)]
            Ok(WorkerRunSummary::default())
        });
    let supervisor = tokio::spawn(supervise_local_projection_worker(
        inner,
        shutdown.clone(),
        std::sync::Arc::clone(&cell),
        false,
        "run-test-1".to_owned(),
    ));
    // Death must become observable while the supervisor parks.
    let mut observed_dead = false;
    for _ in 0..100 {
        if matches!(
            cell.liveness(),
            super::LocalProjectionWorkerLiveness::Dead(_)
        ) {
            observed_dead = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(observed_dead, "panic must be recorded as sticky Dead");
    // Shutdown resolves the parked supervisor with a loud death report.
    shutdown.cancel();
    let report = tokio::time::timeout(std::time::Duration::from_secs(5), supervisor)
        .await
        .expect("supervisor must resolve after cancel")
        .expect("supervisor task must not fail to join");
    assert!(
        report.is_err(),
        "a worker death must surface as an Err shutdown report"
    );
}

/// A shutdown-requested exit propagates the inner summary unchanged and never
/// records death: cancel is the only sanctioned end of a worker generation.
#[tokio::test]
async fn supervisor_propagates_shutdown_without_recording_death() {
    let cell = std::sync::Arc::new(WorkerLivenessCell::default());
    let shutdown = ProjectorCancellationToken::default();
    let run_shutdown = shutdown.clone();
    let inner: tokio::task::JoinHandle<Result<WorkerRunSummary, String>> =
        tokio::spawn(async move {
            run_shutdown.cancelled().await;
            Ok(WorkerRunSummary::default())
        });
    shutdown.cancel();
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        supervise_local_projection_worker(
            inner,
            shutdown,
            std::sync::Arc::clone(&cell),
            false,
            "run-test-2".to_owned(),
        ),
    )
    .await
    .expect("supervisor must resolve after cancel");
    assert!(report.is_ok(), "shutdown-requested exit must stay clean");
    assert_eq!(
        cell.liveness(),
        super::LocalProjectionWorkerLiveness::NotStarted,
        "a sanctioned shutdown must never be recorded as death"
    );
}

/// An unexpected exit WITHOUT a shutdown request (e.g. the bus closed and
/// drained during normal operation) is a death, not a clean exit.
#[tokio::test]
async fn supervisor_marks_unexpected_bus_close_as_death() {
    let cell = std::sync::Arc::new(WorkerLivenessCell::default());
    let shutdown = ProjectorCancellationToken::default();
    let inner: tokio::task::JoinHandle<Result<WorkerRunSummary, String>> =
        tokio::spawn(async move { Ok(WorkerRunSummary::default()) });
    // Give the inner task a moment to finish on its own, then supervise.
    let supervisor = tokio::spawn(supervise_local_projection_worker(
        inner,
        shutdown.clone(),
        std::sync::Arc::clone(&cell),
        false,
        "run-test-3".to_owned(),
    ));
    let mut observed_dead = false;
    for _ in 0..100 {
        if matches!(
            cell.liveness(),
            super::LocalProjectionWorkerLiveness::Dead(_)
        ) {
            observed_dead = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(observed_dead, "unexpected exit must be recorded as death");
    shutdown.cancel();
    let report = tokio::time::timeout(std::time::Duration::from_secs(5), supervisor)
        .await
        .expect("supervisor must resolve after cancel")
        .expect("supervisor task must not fail to join");
    assert!(report.is_err());
}

/// The inner-ownership guard must abort the inner task when the supervisor
/// future is dropped for any reason: no supervisor exit path may leave the
/// worker generation detached. Pure seam: a task that would flip the marker
/// after a delay must never flip it once the guard is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn abort_on_drop_join_aborts_the_inner_generation_on_outer_drop() {
    let marker = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let join: tokio::task::JoinHandle<()> = {
        let marker = std::sync::Arc::clone(&marker);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            marker.store(true, std::sync::atomic::Ordering::Release);
        })
    };
    let guard = AbortOnDropJoin { join };
    // Drop the supervisor-side guard while the inner task is still pending:
    // the inner generation must be aborted, never detached.
    drop(guard);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !marker.load(std::sync::atomic::Ordering::Acquire),
        "a dropped guard must abort the inner generation instead of detaching it"
    );
}

/// A poisoned liveness cell reads as an explicit sticky Dead (fatal), never as
/// a benign NotStarted that readiness could wait on forever.
#[tokio::test]
async fn dropping_unpolled_supervisor_aborts_its_started_inner_generation() {
    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
    let inner = tokio::spawn(async move {
        let _drop = DropSignal(Some(dropped_tx));
        let _ = ready_tx.send(());
        std::future::pending::<Result<WorkerRunSummary, String>>().await
    });
    ready_rx.await.unwrap();
    drop(supervise_local_projection_worker(
        inner,
        ProjectorCancellationToken::default(),
        Arc::new(WorkerLivenessCell::default()),
        false,
        "unpolled-owner-test".into(),
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
        .await
        .expect("inner ownership must exist before the first supervisor poll")
        .expect("inner generation Drop must be observed");
}

#[tokio::test]
async fn projector_runtime_and_shutdown_guards_abort_the_nested_generation() {
    use crate::service::authorization_projector::{
        shutdown_authorization_projector, AuthorizationProjectorHandle, ProjectorHealthShared,
    };
    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }
    for path in ["runtime_drop", "shutdown_cancel", "shutdown_deadline"] {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let inner = tokio::spawn(async move {
            let _drop = DropSignal(Some(dropped_tx));
            let _ = ready_tx.send(());
            std::future::pending::<Result<WorkerRunSummary, String>>().await
        });
        ready_rx.await.unwrap();
        let cancellation = ProjectorCancellationToken::default();
        let join = tokio::spawn(supervise_local_projection_worker(
            inner,
            cancellation.clone(),
            Arc::new(WorkerLivenessCell::default()),
            false,
            "projection-owner-drop-test".into(),
        ));
        let handle = AuthorizationProjectorHandle {
            cancellation,
            join,
            run_id: "projection-owner-drop-test".into(),
            health: Arc::new(ProjectorHealthShared::new()),
        };
        match path {
            "runtime_drop" => drop(handle.ownership_guard()),
            "shutdown_cancel" => {
                let mut shutdown = std::pin::pin!(shutdown_authorization_projector(
                    handle,
                    std::time::Duration::from_secs(5),
                ));
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(20), &mut shutdown)
                        .await
                        .is_err()
                );
            }
            "shutdown_deadline" => {
                let report =
                    shutdown_authorization_projector(handle, std::time::Duration::from_millis(20))
                        .await;
                assert!(report
                    .summary
                    .unwrap_err()
                    .contains("final durable outcome unknown"));
            }
            _ => unreachable!(),
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), dropped_rx)
            .await
            .unwrap_or_else(|_| panic!("nested generation detached after {path}"))
            .expect("inner generation Drop must be observed");
    }
}

#[test]
fn poisoned_liveness_cell_reads_as_dead() {
    let cell = std::sync::Arc::new(WorkerLivenessCell::default());
    let for_poison = std::sync::Arc::clone(&cell);
    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = for_poison.0.lock().expect("fresh cell locks");
        panic!("poison the liveness cell mutex");
    }));
    assert!(poison.is_err(), "the poison panic must be contained");
    assert_eq!(
        cell.liveness(),
        super::LocalProjectionWorkerLiveness::Dead(
            "code=local_projection_worker.liveness_cell_poisoned".to_owned()
        )
    );
}
