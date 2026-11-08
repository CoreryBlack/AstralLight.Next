//! Pure coverage-derivation contract tests; no database or transport I/O.
//!
//! The fixtures mirror the REAL channels: delta events are published
//! aggregates (USER_CARD) with their own event ids, while source-projection
//! rows are head/outbox channel rows (CARD/ELIGIBILITY/RULE_SET) whose event
//! ids are independent of the delta batch.

use super::*;

const USER_CARD: &str = "USER_CARD";
const RULE_SET: &str = "RULE_SET";

fn delta_event(
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_type: &str,
    aggregate_id: i64,
    event_id: &str,
) -> astral_db::DeltaSourceEventEvidence {
    astral_db::DeltaSourceEventEvidence {
        tenant_id,
        card_id,
        aggregate_type: aggregate_type.to_owned(),
        aggregate_id,
        event_id: event_id.to_owned(),
        operation_id: format!("operation-{event_id}"),
        event_type: "ADD".to_owned(),
        grant_id: "grant-1".to_owned(),
        base_version: 0,
        target_version: 1,
        source_generation: 2,
        revoke_fence: 0,
        invalidates_published_evidence: true,
        delta_event_id: 1,
        revision_id: 1,
        predecessor_revision_id: None,
        grant_revision: 1,
        is_tombstone: false,
        delta_json: "{}".to_owned(),
        semantic_hash_hex: "aa".repeat(32),
        dependency_hash_hex: "bb".repeat(32),
        compiler_version: "test".to_owned(),
        before_digest_hex: None,
        after_digest_hex: "cc".repeat(32),
    }
}

fn delta_batch(
    events: Vec<astral_db::DeltaSourceEventEvidence>,
) -> astral_db::DeltaSourceOutcomeEvidence {
    astral_db::DeltaSourceOutcomeEvidence {
        events,
        receipts: vec![],
        before_digest_hex: "00".repeat(32),
        after_digest_hex: "11".repeat(32),
        commit_digest_hex: "22".repeat(32),
    }
}

/// One head/outbox channel row; its event id is the outbox identity and is
/// deliberately independent of any delta event id.
fn projection_row(
    event_id: &str,
    tenant_id: Option<i64>,
    aggregate_type: &str,
    aggregate_id: i64,
) -> SourceProjectionEvidence {
    SourceProjectionEvidence {
        outbox_id: 1,
        event_id: event_id.to_owned(),
        aggregate_type: aggregate_type.to_owned(),
        aggregate_id,
        tenant_id,
        event_type: "UPDATE".to_owned(),
        source_generation: 2,
        sequence_number: 1,
        revoke_fence: 0,
        payload: serde_json::json!({}),
    }
}

fn stamp() -> astral_types::PublicationStamp {
    astral_types::PublicationStamp::new(
        1,
        "aa".repeat(32),
        astral_types::PublicationSeal::from_unix_seconds(1_790_000_000).unwrap(),
    )
    .unwrap()
}

fn evidence_envelope(
    tenant_id: i64,
    card_id: Option<i64>,
    aggregate_id: i64,
) -> astral_mq::MessageEnvelope {
    astral_mq::invalidation::InvalidationEvent::EvidenceInvalidated(
        astral_mq::invalidation::EvidenceInvalidated {
            tenant_id,
            card_id,
            aggregate_type: astral_types::PublishedEvidenceAggregate::UserCard,
            aggregate_id,
            published_generation: 1,
            stamp: stamp(),
            source_generation: 2,
            revoke_fence: 0,
        },
    )
    .to_envelope("msg-1", "operation-1", "region-1")
    .unwrap()
}

fn eligibility_envelope(card_id: i64) -> astral_mq::MessageEnvelope {
    astral_mq::invalidation::InvalidationEvent::EligibilityInvalidated(
        astral_mq::invalidation::EligibilityInvalidated { card_id },
    )
    .to_envelope("msg-2", "operation-1", "region-1")
    .unwrap()
}

fn session_envelope() -> astral_mq::MessageEnvelope {
    astral_mq::invalidation::InvalidationEvent::SessionRevoked(
        astral_mq::invalidation::SessionRevoked {
            user_id: 1,
            revoked_jtis: vec!["jti-1".to_owned()],
        },
    )
    .to_envelope("msg-3", "operation-1", "region-1")
    .unwrap()
}

fn owners(envelopes: &[astral_mq::MessageEnvelope]) -> Vec<InvalidationOwner> {
    envelopes
        .iter()
        .map(|envelope| typed_invalidation_owner(envelope).unwrap())
        .collect()
}

/// Real single-card batch: one USER_CARD delta event plus its independent
/// CARD head/outbox channel row for the same card owner.
fn single_card_batch() -> (
    astral_db::DeltaSourceOutcomeEvidence,
    Vec<SourceProjectionEvidence>,
) {
    let batch = delta_batch(vec![delta_event(
        7,
        Some(17),
        USER_CARD,
        17,
        "delta-event-1",
    )]);
    let rows = vec![projection_row("outbox-card-1", Some(7), "CARD", 17)];
    (batch, rows)
}

fn two_card_batch() -> (
    astral_db::DeltaSourceOutcomeEvidence,
    Vec<SourceProjectionEvidence>,
) {
    let batch = delta_batch(vec![
        delta_event(7, Some(17), USER_CARD, 17, "delta-event-1"),
        delta_event(8, Some(18), USER_CARD, 18, "delta-event-2"),
    ]);
    let rows = vec![
        projection_row("outbox-card-1", Some(7), "CARD", 17),
        projection_row("outbox-card-2", Some(8), "CARD", 18),
    ];
    (batch, rows)
}

#[test]
fn single_owner_batch_declares_complete_coverage() {
    let (batch, rows) = single_card_batch();
    let owners = owners(&[evidence_envelope(7, Some(17), 17)]);
    let coverage = derive_finite_coverage(&batch, &rows, &owners)
        .unwrap()
        .unwrap();
    assert_eq!(coverage.scopes.len(), 1);
    assert_eq!(
        coverage.scopes[0].store_key_text().unwrap(),
        "CARD:7:17:-:ANY"
    );
}

#[test]
fn cross_tenant_batch_declares_every_proven_owner() {
    let (batch, rows) = two_card_batch();
    let owners = owners(&[
        evidence_envelope(7, Some(17), 17),
        evidence_envelope(8, Some(18), 18),
    ]);
    let coverage = derive_finite_coverage(&batch, &rows, &owners)
        .unwrap()
        .unwrap();
    assert_eq!(coverage.scopes.len(), 2);
}

#[test]
fn card_projection_rows_never_join_by_delta_event_identity() {
    // The CARD channel row keeps its own outbox event id and still attributes
    // purely by typed owner (tenant, card).
    let (batch, rows) = single_card_batch();
    assert_eq!(rows[0].event_id, "outbox-card-1");
    let owners = owners(&[evidence_envelope(7, Some(17), 17)]);
    assert!(derive_finite_coverage(&batch, &rows, &owners)
        .unwrap()
        .is_some());
}

#[test]
fn shared_delta_aggregate_without_card_owner_stays_global() {
    let batch = delta_batch(vec![
        delta_event(7, Some(17), USER_CARD, 17, "delta-event-1"),
        delta_event(7, None, RULE_SET, 3, "delta-event-2"),
    ]);
    let rows = vec![projection_row("outbox-card-1", Some(7), "CARD", 17)];
    let owners = owners(&[evidence_envelope(7, Some(17), 17)]);
    assert!(derive_finite_coverage(&batch, &rows, &owners)
        .unwrap()
        .is_none());
}

#[test]
fn card_projection_outside_owner_set_fails() {
    let (batch, _) = single_card_batch();
    // Different tenant, same card id.
    let rows = vec![projection_row("outbox-card-1", Some(8), "CARD", 17)];
    assert!(derive_finite_coverage(&batch, &rows, &[]).is_err());
    // Same tenant, different card.
    let rows = vec![projection_row("outbox-card-1", Some(7), "CARD", 18)];
    assert!(derive_finite_coverage(&batch, &rows, &[]).is_err());
}

#[test]
fn card_projection_without_tenant_stays_global() {
    let (batch, _) = single_card_batch();
    let rows = vec![projection_row("outbox-card-1", None, "CARD", 17)];
    assert!(derive_finite_coverage(&batch, &rows, &[])
        .unwrap()
        .is_none());
}

#[test]
fn eligibility_row_with_tenant_inside_owner_set_covers() {
    let (batch, _) = single_card_batch();
    let rows = vec![
        projection_row("outbox-card-1", Some(7), "CARD", 17),
        projection_row("outbox-elig-1", Some(7), "ELIGIBILITY", 17),
    ];
    assert!(derive_finite_coverage(&batch, &rows, &[])
        .unwrap()
        .is_some());
}

#[test]
fn eligibility_row_without_tenant_uses_unique_owner_map() {
    let (batch, _) = single_card_batch();
    let rows = vec![projection_row("outbox-elig-1", None, "ELIGIBILITY", 17)];
    assert!(derive_finite_coverage(&batch, &rows, &[])
        .unwrap()
        .is_some());

    // With two proven owners the tenant-less eligibility row cannot map.
    let (batch, _) = two_card_batch();
    let rows = vec![projection_row("outbox-elig-1", None, "ELIGIBILITY", 17)];
    assert!(derive_finite_coverage(&batch, &rows, &[])
        .unwrap()
        .is_none());
}

#[test]
fn eligibility_row_contradiction_fails() {
    let (batch, _) = single_card_batch();
    let rows = vec![projection_row("outbox-elig-1", Some(7), "ELIGIBILITY", 18)];
    assert!(derive_finite_coverage(&batch, &rows, &[]).is_err());
    let rows = vec![projection_row("outbox-elig-1", Some(8), "ELIGIBILITY", 17)];
    assert!(derive_finite_coverage(&batch, &rows, &[]).is_err());
    let rows = vec![projection_row("outbox-elig-1", None, "ELIGIBILITY", 18)];
    assert!(derive_finite_coverage(&batch, &rows, &[]).is_err());
}

#[test]
fn shared_rule_set_channel_row_stays_global() {
    let (batch, _) = single_card_batch();
    let rows = vec![projection_row("outbox-ruleset-1", Some(7), "RULE_SET", 3)];
    assert!(derive_finite_coverage(&batch, &rows, &[])
        .unwrap()
        .is_none());
}

#[test]
fn unknown_channel_row_stays_global() {
    let (batch, _) = single_card_batch();
    let rows = vec![projection_row("outbox-mystery-1", Some(7), "MYSTERY", 3)];
    assert!(derive_finite_coverage(&batch, &rows, &[])
        .unwrap()
        .is_none());
}

#[test]
fn evidence_invalidation_without_card_owner_stays_global() {
    let (batch, rows) = single_card_batch();
    let owners = owners(&[evidence_envelope(7, None, 17)]);
    assert!(derive_finite_coverage(&batch, &rows, &owners)
        .unwrap()
        .is_none());
}

#[test]
fn contradicting_evidence_owner_across_tenants_fails_the_batch() {
    let (batch, rows) = single_card_batch();
    // (8, 17) is not in the captured owner set {(7, 17)}: a positive claim
    // outside the batch is an integrity failure, never a silent Global.
    let owners = owners(&[evidence_envelope(8, Some(17), 17)]);
    assert!(derive_finite_coverage(&batch, &rows, &owners).is_err());
}

#[test]
fn contradicting_evidence_card_fails_the_batch() {
    let (batch, rows) = single_card_batch();
    // USER_CARD keeps card_id == aggregate_id; (7, 18) is outside the set.
    let owners = owners(&[evidence_envelope(7, Some(18), 18)]);
    assert!(derive_finite_coverage(&batch, &rows, &owners).is_err());
}

#[test]
fn unique_eligibility_invalidation_map_covers() {
    let (batch, rows) = single_card_batch();
    let owners = owners(&[eligibility_envelope(17)]);
    assert!(derive_finite_coverage(&batch, &rows, &owners)
        .unwrap()
        .is_some());
}

#[test]
fn ambiguous_eligibility_invalidation_stays_global() {
    let (batch, rows) = two_card_batch();
    let owners = owners(&[eligibility_envelope(17)]);
    assert!(derive_finite_coverage(&batch, &rows, &owners)
        .unwrap()
        .is_none());
}

#[test]
fn contradicting_eligibility_invalidation_fails_the_batch() {
    let (batch, rows) = single_card_batch();
    let owners = owners(&[eligibility_envelope(18)]);
    assert!(derive_finite_coverage(&batch, &rows, &owners).is_err());
}

#[test]
fn session_revocation_stays_global() {
    let (batch, rows) = single_card_batch();
    let owners = owners(&[session_envelope()]);
    assert!(derive_finite_coverage(&batch, &rows, &owners)
        .unwrap()
        .is_none());
}

#[test]
fn bad_typed_envelope_fails_the_batch_instead_of_narrowing() {
    let (batch, rows) = single_card_batch();
    // Wrong schema version: the durable envelope contradicts its family.
    let mut envelope = evidence_envelope(7, Some(17), 17);
    envelope.schema_version = 999;
    assert!(typed_invalidation_owner(&envelope).is_err());
    // Undecodable typed payload under a known family.
    let mut undecodable = evidence_envelope(7, Some(17), 17);
    undecodable.payload = serde_json::json!({ "tenantId": 7 });
    assert!(typed_invalidation_owner(&undecodable).is_err());
    // Unknown family: the single decode owner refuses it.
    let mut unknown = evidence_envelope(7, Some(17), 17);
    unknown.message_type = "SOMETHING_ELSE".to_owned();
    assert!(typed_invalidation_owner(&unknown).is_err());
    let owners = owners(&[evidence_envelope(7, Some(17), 17)]);
    assert!(derive_finite_coverage(&batch, &rows, &owners)
        .unwrap()
        .is_some());
}

#[test]
fn empty_delta_batch_never_derives_coverage() {
    let batch = delta_batch(vec![]);
    let (rows, owners) = (Vec::new(), Vec::new());
    assert!(derive_finite_coverage(&batch, &rows, &owners).is_err());
}

/// Wire-type fixture: mirrors exactly what `wire_image` projects out of a
/// sealed opaque receipt, so these tests never depend on the opaque type's
/// internals (there is deliberately no way to fabricate one). The retained
/// canonical images are carried verbatim and their digests are the real
/// hashes of those bytes, matching the delegate contract.
fn image_evidence(table: &str, key: i64, operation: &str) -> AuthorityConfigSourceImage {
    let before_image = format!(r#"{{"table":"{table}","key":{key},"phase":"before"}}"#);
    let after_image = format!(r#"{{"table":"{table}","key":{key},"phase":"after"}}"#);
    AuthorityConfigSourceImage {
        table: serde_json::from_value(serde_json::json!(match table {
            "SOD_POLICY" => "sod_policy",
            "ADMIN_GROUP" => "admin_group",
            "GRADING" => "identity_user_grading",
            _ => panic!("unregistered fixture table"),
        }))
        .unwrap(),
        key,
        lookup: serde_json::json!({"kind": "primary_id", "id": key}).to_string(),
        operation: serde_json::from_value(serde_json::json!(operation)).unwrap(),
        before_image_digest: hex_sha256(before_image.as_bytes()),
        after_image_digest: hex_sha256(after_image.as_bytes()),
        before_image,
        after_image,
    }
}

fn hex_sha256(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(content))
}

#[test]
fn typed_image_digests_are_order_independent_and_domain_separated() {
    let images = vec![
        image_evidence("SOD_POLICY", 1, "UPDATE"),
        image_evidence("ADMIN_GROUP", 2, "INSERT"),
    ];
    let (before_a, after_a) = typed_image_digests(&images).unwrap();
    let mut reversed = images.clone();
    reversed.reverse();
    let (before_b, after_b) = typed_image_digests(&reversed).unwrap();
    assert_eq!(before_a, before_b);
    assert_eq!(after_a, after_b);
    // Before and after sides never collapse into one digest.
    assert_ne!(before_a, after_a);
    // A different retained image content changes the synthesized digest.
    let mut other = images.clone();
    other[0].after_image = r#"{"table":"SOD_POLICY","key":1,"phase":"after","v":2}"#.to_owned();
    other[0].after_image_digest = hex_sha256(other[0].after_image.as_bytes());
    let (_, after_c) = typed_image_digests(&other).unwrap();
    assert_ne!(after_a, after_c);
}
#[test]
fn typed_image_digests_reject_malformed_or_unbound_hashes() {
    let mut images = vec![image_evidence("GRADING", 3, "DELETE")];
    images[0].before_image_digest = "ZZ".repeat(32);
    assert!(typed_image_digests(&images).is_err());
    images[0].before_image_digest = "aa".repeat(31);
    assert!(typed_image_digests(&images).is_err());
    // A digest that does not bind its retained image bytes is refused.
    images[0].before_image_digest = "dd".repeat(32);
    assert!(typed_image_digests(&images).is_err());
    // Same for the after side.
    images[0].before_image_digest = hex_sha256(images[0].before_image.as_bytes());
    images[0].after_image_digest = "ee".repeat(32);
    assert!(typed_image_digests(&images).is_err());
}
