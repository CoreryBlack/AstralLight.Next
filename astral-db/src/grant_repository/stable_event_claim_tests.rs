//! Pure (no-DB) tests for the stable-event claim payload binding
//! (`grant_repository::verify_stable_event_request_binding` and its outcome
//! vocabulary). Durable SQL behavior is covered by the integration suites;
//! these tests pin the fail-closed field-by-field contract without a database.

use super::verify_stable_event_request_binding;
use super::{StableEventClaimRow, DELTA_STATUS_PENDING};
use crate::grant_repository::DeltaEventAppendRequest;
use astral_types::GrantId;

const GRANT_UUID: &str = "550e8400-e29b-41d4-a716-446655440002";
const OTHER_GRANT_UUID: &str = "550e8400-e29b-41d4-a716-446655440003";

fn request() -> DeltaEventAppendRequest {
    DeltaEventAppendRequest {
        tenant_id: 7,
        card_id: Some(11),
        aggregate_type: "card".to_owned(),
        aggregate_id: 42,
        grant_id: GrantId::parse(GRANT_UUID).expect("grant id"),
        event_id: "evt-bind-1".to_owned(),
        operation_id: "op-bind-1".to_owned(),
        event_type: super::DeltaEventType::Add,
        base_version: 0,
        target_version: 1,
        source_generation: 5,
        revoke_fence: 0,
        invalidates_published_evidence: false,
        before_image_json: None,
        before_digest_hex: None,
        delta_json: r#"{"op":"ADD"}"#.to_owned(),
        semantic_hash_hex: "aa".repeat(32),
        dependency_hash_hex: "bb".repeat(32),
        compiler_version: "test-compiler".to_owned(),
        next_attempt_at: None,
    }
}

fn row_for(request: &DeltaEventAppendRequest) -> StableEventClaimRow {
    StableEventClaimRow {
        delta_event_id: 101,
        event_id: request.event_id.clone(),
        operation_id: request.operation_id.clone(),
        event_type: request.event_type.as_str().to_owned(),
        tenant_id: request.tenant_id,
        card_id: request.card_id,
        aggregate_type: request.aggregate_type.clone(),
        aggregate_id: request.aggregate_id,
        grant_id: request.grant_id.as_str().to_owned(),
        base_version: request.base_version,
        target_version: request.target_version,
        source_generation: request.source_generation as i64,
        revoke_fence: request.revoke_fence as i64,
        invalidates_published_evidence: if request.invalidates_published_evidence {
            1
        } else {
            0
        },
        before_image_json: request.before_image_json.clone(),
        before_digest: request.before_digest_hex.as_ref().map(|digest| {
            crate::Sha256Digest::from_hex(digest)
                .expect("digest hex")
                .as_bytes()
                .to_vec()
        }),
        delta_json: request.delta_json.clone(),
        semantic_hash: crate::Sha256Digest::from_hex(&request.semantic_hash_hex)
            .expect("semantic hex")
            .as_bytes()
            .to_vec(),
        dependency_hash: crate::Sha256Digest::from_hex(&request.dependency_hash_hex)
            .expect("dependency hex")
            .as_bytes()
            .to_vec(),
        compiler_version: request.compiler_version.clone(),
        status: DELTA_STATUS_PENDING.to_owned(),
        attempts: 0,
        cas_version: 1,
    }
}

#[test]
fn binding_accepts_fully_matching_row() {
    let request = request();
    let row = row_for(&request);
    verify_stable_event_request_binding(&request, &row).expect("matching row must bind");
}

fn assert_mismatch(request: &DeltaEventAppendRequest, row: &StableEventClaimRow, field: &str) {
    let error =
        verify_stable_event_request_binding(request, row).expect_err("drift must fail closed");
    let message = error.to_string();
    assert!(
        message.contains("claim_by_event_payload_mismatch"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains(field),
        "field {field} not named: {message}"
    );
}

#[test]
fn binding_rejects_every_drifting_field() {
    let request = request();

    let mut drift = row_for(&request);
    drift.operation_id = "op-other".to_owned();
    assert_mismatch(&request, &drift, "operation_id");

    let mut drift = row_for(&request);
    drift.event_type = "UPDATE".to_owned();
    assert_mismatch(&request, &drift, "event_type");

    let mut drift = row_for(&request);
    drift.tenant_id = 8;
    assert_mismatch(&request, &drift, "tenant_id");

    let mut drift = row_for(&request);
    drift.card_id = None;
    assert_mismatch(&request, &drift, "card_id");

    let mut drift = row_for(&request);
    drift.aggregate_type = "org".to_owned();
    assert_mismatch(&request, &drift, "aggregate_identity");

    let mut drift = row_for(&request);
    drift.aggregate_id = 43;
    assert_mismatch(&request, &drift, "aggregate_identity");

    let mut drift = row_for(&request);
    drift.grant_id = GrantId::parse(OTHER_GRANT_UUID)
        .expect("other grant id")
        .as_str()
        .to_owned();
    assert_mismatch(&request, &drift, "grant_id");

    let mut drift = row_for(&request);
    drift.base_version = 1;
    assert_mismatch(&request, &drift, "base_version");

    let mut drift = row_for(&request);
    drift.target_version = 2;
    assert_mismatch(&request, &drift, "target_version");

    let mut drift = row_for(&request);
    drift.source_generation = 6;
    assert_mismatch(&request, &drift, "source_generation");

    let mut drift = row_for(&request);
    drift.revoke_fence = 7;
    assert_mismatch(&request, &drift, "revoke_fence");

    let mut drift = row_for(&request);
    drift.invalidates_published_evidence = 1;
    assert_mismatch(&request, &drift, "invalidates_published_evidence");

    let mut drift = row_for(&request);
    drift.delta_json = r#"{"op":"TAMPERED"}"#.to_owned();
    assert_mismatch(&request, &drift, "delta_json");

    let mut drift = row_for(&request);
    drift.semantic_hash = vec![0u8; 32];
    assert_mismatch(&request, &drift, "semantic_hash");

    let mut drift = row_for(&request);
    drift.dependency_hash = vec![0u8; 32];
    assert_mismatch(&request, &drift, "dependency_hash");

    let mut drift = row_for(&request);
    drift.compiler_version = "other-compiler".to_owned();
    assert_mismatch(&request, &drift, "compiler_version");
}

#[test]
fn binding_rejects_unexpected_before_image() {
    let request = request();
    let mut drift = row_for(&request);
    drift.before_image_json = Some(r#"{"before":true}"#.to_owned());
    assert_mismatch(&request, &drift, "before_image_absent");
}

#[test]
fn binding_accepts_paired_before_image() {
    let mut request = request();
    let image = r#"{"before":true}"#;
    let digest = crate::Sha256Digest::from_raw_bytes(super::sha256_digest_bytes(image.as_bytes()));
    request.before_image_json = Some(image.to_owned());
    request.before_digest_hex = Some(digest.as_hex().to_owned());
    let row = row_for(&request);
    verify_stable_event_request_binding(&request, &row).expect("paired before image binds");

    let mut drift = row_for(&request);
    drift.before_digest = Some(vec![0u8; 32]);
    assert_mismatch(&request, &drift, "before_digest");
}
