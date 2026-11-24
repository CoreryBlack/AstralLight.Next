//! memory—v1: Ordinary admission across serving publications and adoption gates.

use astral_authorization_root::memory_v1_adoption::AdoptionEvidenceError;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{RootError, RootStatus};
use astral_types::memory_v1::CandidateIdentity;
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1PendingSource, MemoryV1Request};
use policy_engine::PolicyEngine;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

#[test]
fn production_adoption_checks_each_count_and_requires_evidence() {
    let (rows, selections) = fixture_rows();
    let counts = rows.table_counts();
    let owner = install_isolated_test_root(rows, selections, budget()).unwrap();
    owner.install_registry(&registry_declarations()).unwrap();
    let before = owner.handle().metadata().unwrap();
    assert_eq!(before.status, RootStatus::Candidate);

    let mut variants = Vec::new();
    macro_rules! count_disagreements {
        ($($field:ident),+ $(,)?) => {
            $(
                let mut capture = cold_facts(counts);
                capture.snapshot_counts.$field += 1;
                variants.push(capture);
                let mut scan = cold_facts(counts);
                scan.scanned_counts.$field += 1;
                variants.push(scan);
            )+
        };
    }
    count_disagreements!(
        users,
        identity_cards,
        tenants,
        user_cards,
        rule_sets,
        rule_set_versions,
        bindings,
        binding_confirmations,
        rule_set_change_confirmations,
    );
    // Equal total and agreement between the two reports are insufficient if
    // individual input table counts differ from the installed root.
    let mut redistributed = cold_facts(counts);
    redistributed.snapshot_counts.users += 1;
    redistributed.snapshot_counts.identity_cards -= 1;
    redistributed.scanned_counts = redistributed.snapshot_counts;
    variants.push(redistributed);
    assert_eq!(variants.len(), 19);
    for facts in variants {
        assert!(matches!(
            owner.adopt_with_production_evidence(&facts, &sealed_input()),
            Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Missing(
                "complete coverage"
            )))
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
    }

    let facts = cold_facts(counts);
    assert!(matches!(
        owner.adopt_with_production_evidence(&facts, &ProductionEvidenceInput::default()),
        Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Missing(
            "source provenance"
        )))
    ));
    assert_eq!(owner.handle().metadata().unwrap(), before);
    let (after, capability) = owner
        .adopt_with_production_evidence(&facts, &sealed_input())
        .unwrap();
    assert_eq!(after.status, RootStatus::Serving);
    assert_eq!(
        owner.validate_production_admission(&capability).unwrap(),
        after
    );
    println!("adoption: 19 count refusals, 1 missing-evidence refusal, 1 serving control");
}

#[test]
fn serving_writer_distinguishes_unrelated_publication_from_revocation() {
    let root = production_root("ordinary-writer");
    let foreign = production_root("ordinary-foreign");
    assert!(matches!(
        RootMutationWriter::new(Arc::clone(&root.owner), Arc::clone(&foreign.admission)),
        Err(RootMutationWriterError::AdmissionMismatch)
    ));
    let writer = writer_for(&root);
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&root.owner).unwrap();
    let handle = root.owner.handle();
    let scope = RequestRootScope::new(handle.clone(), uuid::Uuid::new_v4());
    let context = scope.extension();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let credential = authority
        .identity_session_adapter()
        .issue_verified_session_in_root(
            &context,
            CandidateIdentity {
                user_id: MemoryId::from_bytes(ACTOR),
                identity_card_id: MemoryId::from_bytes([2; 16]),
                user_card_id: MemoryId::from_bytes(CARD),
                tenant_id: MemoryId::from_bytes(TENANT),
            },
            now - 1,
            300,
        )
        .unwrap();
    let session = authority
        .verifier()
        .verify_and_bind(credential.credential(), now, &context)
        .unwrap();
    let request = MemoryV1Request {
        resource: "document",
        action: "read",
        target: None,
        target_owner: None,
        target_tenant: None,
        operation_id: b"paper-ordinary-read",
        operation_fingerprint: b"paper-ordinary-read-fingerprint",
    };
    let engine = PolicyEngine::new();
    let baseline = engine.evaluate_memory_v1(&context, &session, &request);
    assert_eq!(baseline.decision, MemoryV1Decision::Allow);
    let observed = baseline.admission.unwrap().root();
    assert!(writer.verified_admission(&observed).is_ok());

    let unrelated = writer
        .publish(&ManagementMutationV2::UserCardCreate {
            row: UserCardRow {
                user_card_id: [21; 16],
                user_id: ACTOR,
                tenant_id: TENANT,
                status: UserCardStatus::Active,
            },
        })
        .unwrap();
    assert_eq!(unrelated.version, observed.version + 1);
    assert!(matches!(
        writer.verified_admission(&observed),
        Err(RootMutationWriterError::StaleObservation)
    ));
    assert_eq!(
        context.with_reader(|reader| reader.metadata()).unwrap(),
        observed
    );
    assert_eq!(
        engine
            .evaluate_memory_v1(&context, &session, &request)
            .decision,
        MemoryV1Decision::Allow
    );

    let revoked = writer
        .publish(&ManagementMutationV2::BindingRemove {
            binding_id: [6; 16],
            removed_by: ACTOR,
            removed_at: now,
        })
        .unwrap();
    assert_eq!(revoked.version, unrelated.version + 1);
    assert_eq!(revoked.instance_id, observed.instance_id);
    assert_ne!(revoked.digest, unrelated.digest);
    let held = engine.evaluate_memory_v1(&context, &session, &request);
    assert_eq!(held.decision, MemoryV1Decision::Pending);
    assert!(held.admission.is_none());
    assert_eq!(
        context.with_reader(|reader| reader.metadata()).unwrap(),
        observed
    );

    let fresh_scope = RequestRootScope::new(handle, uuid::Uuid::new_v4());
    let fresh = fresh_scope.extension();
    let session = authority
        .verifier()
        .verify_and_bind(credential.credential(), now, &fresh)
        .unwrap();
    let fresh_result = engine.evaluate_memory_v1(&fresh, &session, &request);
    assert_eq!(fresh_result.decision, MemoryV1Decision::Deny);
    assert!(fresh_result.admission.is_none());
    assert_eq!(
        fresh.with_reader(|reader| reader.metadata()).unwrap(),
        revoked
    );
    println!("serving writer: baseline ALLOW; held view ALLOW after unrelated publication, PENDING after removal; fresh DENY; foreign capability and stale observation refused");
}

// memory—v1: Drive the ordinary entry with controlled kernel-style reports,
// not a replacement final check. Every invocation gets a fresh request scope.
#[test]
fn bounded_clock_refuses_ambiguous_denial_and_latches_a_later_backstep() {
    use astral_authorization_root::memory_v1_rules::{canonical_version_bytes, version_digest};
    use std::cell::Cell;
    thread_local! { static SAMPLE: Cell<Option<(i128, i128)>> = const { Cell::new(None) }; }
    const S: i128 = 1_000_000_000;
    let (mut rows, selections) = fixture_rows();
    let version = &mut rows.rule_set_versions[0];
    version.content_bytes = br#"{"rules":[{"ruleId":"A","resource":"document","action":"read","effect":"ALLOW"},{"ruleId":"D","resource":"document","action":"read","effect":"DENY","validity":{"from":120,"until":130}}]}"#.to_vec();
    version.hash_input_bytes = canonical_version_bytes(
        &version.version_bytes,
        &version.content_bytes,
        &version.timestamp_bytes,
    );
    version.hash_bytes = version_digest(&version.hash_input_bytes);
    let counts = rows.table_counts();
    let owner = install_isolated_test_root(rows, selections, budget()).unwrap();
    owner.install_registry(&registry_declarations()).unwrap();
    owner
        .adopt_with_production_evidence(&cold_facts(counts), &sealed_input())
        .unwrap();
    let authority = MemoryV1SessionAuthority::with_clock_for_test(|| SAMPLE.get());
    authority.bind_to_root(&owner).unwrap();
    let credential = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(
            CandidateIdentity {
                user_id: MemoryId::from_bytes(ACTOR),
                identity_card_id: MemoryId::from_bytes([2; 16]),
                user_card_id: MemoryId::from_bytes(CARD),
                tenant_id: MemoryId::from_bytes(TENANT),
            },
            100,
            100,
        )
        .unwrap();
    let engine = PolicyEngine::new();
    let read = |sample, expected| {
        SAMPLE.set(sample);
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        let context = scope.extension();
        let session = authority
            .verifier()
            .verify_and_bind(credential.credential(), 110, &context)
            .unwrap();
        let result = engine.evaluate_memory_v1(
            &context,
            &session,
            &MemoryV1Request {
                resource: "document",
                action: "read",
                target: None,
                target_tenant: None,
                target_owner: None,
                operation_id: b"bounded-clock",
                operation_fingerprint: b"document-read",
            },
        );
        assert_eq!(result.decision, expected);
        assert_eq!(
            result.admission.is_some(),
            expected == MemoryV1Decision::Allow
        );
        assert_eq!(
            result.deny_observation.is_some(),
            expected == MemoryV1Decision::Deny
        );
    };
    use MemoryV1Decision::{Allow, Deny, Pending};
    read(None, Pending);
    read(Some((110 * S, 1)), Allow); // both 109 and 110 permit
    read(Some((120 * S - 1, 1)), Pending); // center permits, upper tick denies
    read(Some((120 * S + 1, 1)), Deny);
    read(Some((125 * S, 1)), Deny); // both adjacent ticks prove the same denial
    read(Some((130 * S - 1, 1)), Pending); // center denies, upper tick permits
    read(Some((131 * S, 1)), Allow);
    read(Some((200 * S - 1, 1)), Pending); // upper tick reaches session expiry
    read(Some((110 * S, 0)), Pending); // rollback between requests
    read(Some((200 * S - 1, 0)), Pending); // catching up cannot release the latch
}

// memory—v1: Login and gateway verification truncate the host clock to a whole
// second. Admission plans at the earliest tick inside the error radius. A session
// issued in the current second is therefore not yet valid when that radius reaches
// the previous second. This is not a denial and must not become ALLOW.
#[test]
fn fresh_issue_is_pending_when_the_trusted_interval_reaches_the_previous_second() {
    use std::cell::Cell;
    thread_local! { static SAMPLE: Cell<Option<(i128, i128)>> = const { Cell::new(None) }; }
    const S: i128 = 1_000_000_000;
    let (rows, selections) = fixture_rows();
    let counts = rows.table_counts();
    let owner = install_isolated_test_root(rows, selections, budget()).unwrap();
    owner.install_registry(&registry_declarations()).unwrap();
    owner
        .adopt_with_production_evidence(&cold_facts(counts), &sealed_input())
        .unwrap();
    let identity = CandidateIdentity {
        user_id: MemoryId::from_bytes(ACTOR),
        identity_card_id: MemoryId::from_bytes([2; 16]),
        user_card_id: MemoryId::from_bytes(CARD),
        tenant_id: MemoryId::from_bytes(TENANT),
    };
    let engine = PolicyEngine::new();
    let request = MemoryV1Request {
        resource: "document",
        action: "read",
        target: None,
        target_tenant: None,
        target_owner: None,
        operation_id: b"fresh-issue-clock",
        operation_fingerprint: b"document-read",
    };
    let evaluate = |authority: &MemoryV1SessionAuthority, credential: &str, verify_at, sample| {
        SAMPLE.set(sample);
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        let context = scope.extension();
        let session = authority
            .verifier()
            .verify_and_bind(credential, verify_at, &context)
            .expect("gateway whole-second verification accepts the issued session");
        engine.evaluate_memory_v1(&context, &session, &request)
    };

    let authority = MemoryV1SessionAuthority::with_clock_for_test(|| SAMPLE.get());
    authority.bind_to_root(&owner).unwrap();
    let adapter = authority.identity_session_adapter();
    // Issue the older session first. The authority rejects a later issue time
    // that moves backwards, and one root accepts only this authority.
    let established = adapter.issue_unchecked_for_test(identity, 90, 300).unwrap();
    let fresh = adapter
        .issue_unchecked_for_test(identity, 100, 300)
        .unwrap();
    // Samples must advance. Both stay inside the 500ms bound and cover ticks 99 and 100.
    let still_allowed = evaluate(
        &authority,
        established.credential(),
        100,
        Some((100 * S + 100_000_000, 200_000_000)),
    );
    assert_eq!(still_allowed.decision, MemoryV1Decision::Allow);
    assert!(still_allowed.admission.is_some());
    let pending = evaluate(
        &authority,
        fresh.credential(),
        100,
        Some((100 * S + 150_000_000, 200_000_000)),
    );
    assert_eq!(pending.decision, MemoryV1Decision::Pending);
    assert_eq!(
        pending.pending_source,
        Some(MemoryV1PendingSource::ContextInvalid)
    );
    assert!(pending.admission.is_none());
    assert!(pending.deny_source.is_none());
    assert!(pending.deny_observation.is_none());
    // The same fresh session admits once the whole interval is at or after issuance.
    let allowed = evaluate(
        &authority,
        fresh.credential(),
        100,
        Some((100 * S + 500_000_000, 0)),
    );
    assert_eq!(allowed.decision, MemoryV1Decision::Allow);
    assert!(allowed.admission.is_some());
}
