//! memory—v1: Ordinary admission across serving publications and adoption gates.

use astral_authorization_root::memory_v1_adoption::AdoptionEvidenceError;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{RootError, RootStatus};
use astral_types::memory_v1::CandidateIdentity;
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};
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
