use super::*;
use crate::{DeltaEventType, GrantRevisionAppendRequest};
use astral_types::{
    BindingLayer, GrantEffect, GrantId, GrantProvenance, GrantRevision, GrantSourceKind,
    TenantScope, ValidityWindow,
};

fn grant(revision: u64) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: GrantId::parse("00000000-0000-4000-8000-000000000001").unwrap(),
        revision: GrantRevision::new(revision).unwrap(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Overlay,
        tenant: TenantScope::new(7, Some(11)).unwrap(),
        card_id: 17,
        user_id: 42,
        resource: "learn_subject".into(),
        action: "read".into(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::between(100, 200),
        provenance: GrantProvenance {
            source_id: "rule-set-entry-9".into(),
            source_entry: Some("rule-set-entry-9".into()),
            binding_id: Some("binding-3".into()),
            delegation_id: None,
            operation_id: "operation".into(),
            event_id: Some("event".into()),
            actor_user_id: Some(42),
        },
    }
}

fn request(delta: &GrantDelta, before: Option<&CanonicalGrant>) -> DeltaEventAppendRequest {
    let before_image_json = before.map(|grant| grant.canonical_input().unwrap());
    DeltaEventAppendRequest {
        tenant_id: 7,
        card_id: Some(17),
        aggregate_type: "RULE_SET".into(),
        aggregate_id: 9,
        grant_id: delta.target_grant_id().unwrap(),
        event_id: "event".into(),
        operation_id: "operation".into(),
        event_type: DeltaEventType::from_sql(delta.operation_name()).unwrap(),
        base_version: 98,
        target_version: 99,
        source_generation: 101,
        revoke_fence: 5,
        invalidates_published_evidence: true,
        before_digest_hex: before_image_json
            .as_ref()
            .map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
        before_image_json,
        delta_json: serde_json::to_string(delta).unwrap(),
        semantic_hash_hex: "22".repeat(32),
        dependency_hash_hex: "33".repeat(32),
        compiler_version: AUTHORIZATION_COMPILER_VERSION.into(),
        next_attempt_at: None,
    }
}

fn row(grant: &CanonicalGrant, request: &DeltaEventAppendRequest) -> EvidenceRevisionRow {
    EvidenceRevisionRow {
        revision_id: grant.revision.value() as i64,
        ledger: RawLedgerRow {
            revision_no: grant.revision.value() as i64,
            tenant_id: request.tenant_id,
            card_id: request.card_id,
            aggregate_type: request.aggregate_type.clone(),
            aggregate_id: request.aggregate_id,
            grant_id: grant.grant_id.as_str(),
            status: "ACTIVE".into(),
            is_tombstone: i8::from(matches!(
                grant.state,
                GrantState::Removed | GrantState::Revoked
            )),
            grant_payload: grant.canonical_input().unwrap(),
            semantic_hash: hex::decode(&request.semantic_hash_hex).unwrap(),
            dependency_hash: hex::decode(&request.dependency_hash_hex).unwrap(),
            operation_id: request.operation_id.clone(),
            event_id: request.event_id.clone(),
            compiler_version: AUTHORIZATION_COMPILER_VERSION.into(),
        },
    }
}

#[test]
fn projection_version_is_independent_of_exact_grant_revision() {
    let before = grant(1);
    let delta = GrantDelta::update(grant(2), before.revision);
    let request = request(&delta, Some(&before));
    let target = row(&grant(2), &request);
    let predecessor = row(&before, &request);
    assert_ne!(request.target_version, target.ledger.revision_no);
    assert!(bind_transition(&request, &delta, &target, Some(&predecessor)).is_ok());
    let gap = row(&grant(3), &request);
    assert!(bind_transition(&request, &delta, &target, Some(&gap)).is_err());
}

#[test]
fn complete_after_payload_and_tombstone_provenance_must_match() {
    let before = grant(1);
    for delta in [
        GrantDelta::remove(before.grant_id, before.revision),
        GrantDelta::revoke(before.grant_id, before.revision),
    ] {
        let request = request(&delta, Some(&before));
        let predecessor = row(&before, &request);
        let mut tombstone = before.clone();
        tombstone.revision = delta.revision().unwrap();
        tombstone.state = if matches!(delta, GrantDelta::Remove { .. }) {
            GrantState::Removed
        } else {
            GrantState::Revoked
        };
        let target = row(&tombstone, &request);
        assert!(bind_transition(&request, &delta, &target, Some(&predecessor)).is_ok());
        tombstone.resource = "another_resource".into();
        assert!(bind_transition(
            &request,
            &delta,
            &row(&tombstone, &request),
            Some(&predecessor)
        )
        .is_err());
        tombstone.resource = before.resource.clone();
        tombstone.provenance.operation_id = "forged-operation".into();
        assert!(bind_transition(
            &request,
            &delta,
            &row(&tombstone, &request),
            Some(&predecessor)
        )
        .is_err());
    }
    let delta = GrantDelta::add(before.clone());
    let request = request(&delta, None);
    let mut forged = before.clone();
    forged.action = "write".into();
    assert!(bind_transition(&request, &delta, &row(&forged, &request), None).is_err());
}

#[test]
fn before_image_absence_digest_and_scope_are_exact() {
    let before = grant(1);
    let delta = GrantDelta::update(grant(2), before.revision);
    let mut request = request(&delta, Some(&before));
    let target = row(&grant(2), &request);
    let mut predecessor = row(&before, &request);
    assert!(bind_transition(&request, &delta, &target, None).is_err());
    request.before_digest_hex = Some("ff".repeat(32));
    assert!(bind_transition(&request, &delta, &target, Some(&predecessor)).is_err());
    request.before_digest_hex = Some(hex::encode(Sha256::digest(
        before.canonical_input().unwrap().as_bytes(),
    )));
    predecessor.ledger.tenant_id = 8;
    assert!(bind_transition(&request, &delta, &target, Some(&predecessor)).is_err());
    let add = GrantDelta::add(grant(2));
    let add_request = self::request(&add, None);
    assert!(bind_transition(
        &add_request,
        &add,
        &target,
        Some(&row(&before, &add_request))
    )
    .is_err());
}

#[test]
fn unfiltered_ruleset_receipt_still_checks_the_actual_grant_card() {
    let delta = GrantDelta::add(grant(1));
    let mut request = request(&delta, None);
    let mut target = row(&grant(1), &request);
    request.card_id = None;
    assert!(bind_transition(&request, &delta, &target, None).is_ok());
    target.ledger.card_id = Some(18);
    assert!(bind_transition(&request, &delta, &target, None).is_err());
}

#[test]
fn batches_preserve_all_aggregate_and_grant_identities() {
    let first = request(&GrantDelta::add(grant(1)), None);
    let mut second = first.clone();
    second.event_id = "second".into();
    second.aggregate_id = 22;
    second.tenant_id = 8;
    assert!(validate_evidence_batch(&[first.clone(), second]).is_ok());
    assert!(validate_evidence_batch(&[first.clone(), first.clone()]).is_err());
    assert!(validate_evidence_batch(&[]).is_err());
    assert!(validate_evidence_batch(&vec![first; MAX_DELTA_EVIDENCE_EVENTS + 1]).is_err());
}

#[test]
fn complete_card_coverage_preserves_all_owners_and_refuses_shared_aggregates() {
    let event = DeltaSourceEventEvidence {
        tenant_id: 7,
        card_id: Some(17),
        aggregate_type: "USER_CARD".into(),
        aggregate_id: 17,
        event_id: "event".into(),
        operation_id: "operation".into(),
        event_type: "ADD".into(),
        grant_id: "grant".into(),
        base_version: 0,
        target_version: 1,
        source_generation: 1,
        revoke_fence: 0,
        invalidates_published_evidence: false,
        delta_event_id: 1,
        revision_id: 1,
        predecessor_revision_id: None,
        grant_revision: 1,
        is_tombstone: false,
        delta_json: "{}".into(),
        semantic_hash_hex: "11".repeat(32),
        dependency_hash_hex: "22".repeat(32),
        compiler_version: AUTHORIZATION_COMPILER_VERSION.into(),
        before_digest_hex: None,
        after_digest_hex: "33".repeat(32),
    };
    let mut batch = DeltaSourceOutcomeEvidence {
        events: vec![event.clone(), event.clone()],
        receipts: Vec::new(),
        before_digest_hex: "44".repeat(32),
        after_digest_hex: "55".repeat(32),
        commit_digest_hex: "66".repeat(32),
    };
    assert_eq!(
        batch
            .complete_card_coverage()
            .unwrap()
            .unwrap()
            .scopes
            .len(),
        1
    );
    batch.events[1].tenant_id = 8;
    assert_eq!(
        batch
            .complete_card_coverage()
            .unwrap()
            .unwrap()
            .scopes
            .len(),
        2
    );
    batch.events[1].card_id = None;
    assert!(batch.complete_card_coverage().unwrap().is_none());
    batch.events = (1..=257)
        .map(|id| {
            let mut event = event.clone();
            event.card_id = Some(id);
            event
        })
        .collect();
    assert!(batch.complete_card_coverage().unwrap().is_none());
    batch.events = vec![event];
    batch.events[0].card_id = Some(0);
    assert!(batch.complete_card_coverage().is_err());
    batch.events.clear();
    assert!(batch.complete_card_coverage().is_err());
}

#[tokio::test]
#[ignore = "requires isolated ASTRAL_DELTA_EVIDENCE_TEST_MYSQL_URL with grant ledger schema"]
async fn capture_binds_real_rows_and_rolls_back_its_fixture() {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let Ok(url) = std::env::var("ASTRAL_DELTA_EVIDENCE_TEST_MYSQL_URL") else {
        assert!(!required, "required isolated MySQL dependency is missing");
        eprintln!("[SKIP] isolated MySQL dependency is missing");
        return;
    };
    let pool = sqlx::MySqlPool::connect(&url).await.unwrap();
    let mut tx = pool.begin().await.unwrap();
    let mut initial = grant(1);
    initial.grant_id = GrantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let run = uuid::Uuid::new_v4().simple().to_string();
    initial.provenance.operation_id = format!("delta:{run}");
    initial.provenance.event_id = Some(format!("delta:{run}:add"));
    let mut previous = None;
    let mut requests = Vec::new();
    for revision in 1..=2 {
        let mut current = initial.clone();
        current.revision = GrantRevision::new(revision).unwrap();
        current.provenance.event_id = Some(format!("delta:{run}:{revision}"));
        let delta = if revision == 1 {
            GrantDelta::add(current.clone())
        } else {
            GrantDelta::update(current.clone(), GrantRevision::new(1).unwrap())
        };
        let mut request = self::request(&delta, previous.as_ref());
        request.operation_id = current.provenance.operation_id.clone();
        request.event_id = current.provenance.event_id.clone().unwrap();
        request.base_version = revision as i64 + 90;
        request.target_version = revision as i64 + 91;
        super::super::append_grant_revision_in_tx(
            &mut tx,
            &GrantRevisionAppendRequest {
                tenant_id: request.tenant_id,
                card_id_scope: request.card_id,
                aggregate_type: request.aggregate_type.clone(),
                aggregate_id: request.aggregate_id,
                delta,
                event_id: request.event_id.clone(),
                operation_id: request.operation_id.clone(),
                semantic_hash_hex: request.semantic_hash_hex.clone(),
                dependency_hash_hex: request.dependency_hash_hex.clone(),
                compiler_version: AUTHORIZATION_COMPILER_VERSION.into(),
            },
        )
        .await
        .unwrap();
        super::super::append_delta_event(&mut *tx, &request)
            .await
            .unwrap();
        requests.push(request);
        previous = Some(current);
    }
    let captured = capture_delta_source_outcome_in_tx(&mut tx, &requests)
        .await
        .unwrap();
    assert_eq!(captured.events.len(), 2);
    assert_eq!(captured.receipts.len(), 2);
    assert_eq!(captured.events[1].grant_revision, 2);
    assert_eq!(captured.events[1].target_version, 93);
    assert!(captured.events[0].before_digest_hex.is_none());
    let mut tampered = requests.clone();
    tampered[1].before_digest_hex = Some("00".repeat(32));
    assert!(capture_delta_source_outcome_in_tx(&mut tx, &tampered)
        .await
        .is_err());
    let (_, core) = captured.into_source_outcome().unwrap();
    assert_eq!(core.source_receipts.len(), 2);
    tx.rollback().await.unwrap();
    pool.close().await;
}
