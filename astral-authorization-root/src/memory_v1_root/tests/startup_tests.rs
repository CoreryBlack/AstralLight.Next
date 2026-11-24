use super::*;
use crate::memory_v1_adoption::{
    startup::{
        startup_registry_digest, AuthenticatedStartupEvidence, StartupEvidenceContext,
        StartupEvidenceError, StartupEvidencePayload, StartupEvidenceReports,
        StartupEvidenceSubject,
    },
    AdoptionEvidenceError,
};
use ring::signature::{Ed25519KeyPair, KeyPair};

#[test]
// memory—v1: Exercise the real process root, not the registry that accepts fixture declarations.
fn signed_startup_adopts_only_the_exact_process_candidate() {
    const CHILD: &str = "ASTRAL_MEMORY_V1_SIGNED_STARTUP_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "memory_v1_root::tests::startup_tests::signed_startup_adopts_only_the_exact_process_candidate",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed; 0 failed"),
            "signed startup child: {}\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
        return;
    }

    let (rows, selections) = serving_ready();
    let counts = rows.table_counts();
    let owner = install_process_root(rows, selections, budget()).unwrap();
    let handle = owner.handle();
    install_fixture_registry(&owner);
    let registry = owner.runtime.registry.snapshot().unwrap();
    let declarations: Vec<_> = registry
        .entries
        .into_iter()
        .map(|entry| RegistryDeclaration {
            resource: entry.resource,
            actions: entry.actions,
        })
        .collect();
    let before = handle.metadata().unwrap();
    let mut facts = cold_facts(counts);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Keep the subject-binding control away from the current uncertain tick.
    // The capture-time refusal is asserted separately below.
    facts.captured_at_unix_seconds = now - 2;
    let install = MemoryId::from_bytes([1; 16]);
    let epoch = MemoryId::from_bytes([2; 16]);
    let stream = MemoryId::from_bytes([3; 16]);
    let tail = JournalAnchor::new(stream, 0, 0, [4; 32]).unwrap();
    let scope = [5; 32];
    let payload = StartupEvidencePayload {
        version: 1,
        subject: StartupEvidenceSubject {
            installation_id: install,
            database_scope: scope,
            schema_fingerprint: facts.schema_fingerprint,
            candidate_digest: before.digest,
            registry_digest: startup_registry_digest(&declarations),
            journal_stream: stream,
            journal_epoch: epoch,
            journal_sequence: 0,
            mutation_sequence: 0,
            journal_tail_hash: *tail.frame_hash(),
        },
        issued_at: now - 5,
        expires_at: now + 60,
        reports: StartupEvidenceReports {
            source_provenance: [11; 32],
            snapshot_identity: [12; 32],
            lifecycle_and_validity: [13; 32],
            confirmation_authority: [14; 32],
            resource_ownership: [15; 32],
            eligibility: [16; 32],
            separation_of_duties: [17; 32],
            writer_coverage: [18; 32],
            audit_correlation: [19; 32],
            persistence_recovery: [20; 32],
        },
    };
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let signature = key.sign(&payload.signing_bytes().unwrap());
    let bytes = serde_json::to_vec(
        &serde_json::json!({"payload":payload,"signature":hex::encode(signature)}),
    )
    .unwrap();
    let proof = AuthenticatedStartupEvidence::authenticate(
        key.public_key().as_ref().try_into().unwrap(),
        &bytes,
    )
    .unwrap();
    let context = |database_scope| StartupEvidenceContext {
        installation_id: install,
        database_scope,
        epoch,
        checkpoint_tail: tail,
        evidence: &proof,
    };

    assert!(matches!(
        owner.adopt_with_production_evidence(&facts, &complete_production_input()),
        Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Missing(
            "source provenance"
        )))
    ));
    assert!(matches!(
        owner.adopt_with_signed_startup(&facts, context([99; 32])),
        Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Startup(
            StartupEvidenceError::SubjectMismatch
        )))
    ));
    let mut future_capture = facts;
    future_capture.captured_at_unix_seconds = now + 60;
    assert!(matches!(
        owner.adopt_with_signed_startup(&future_capture, context(scope)),
        Err(RootError::AdoptionEvidence(
            AdoptionEvidenceError::InvalidTrustedTime
        ))
    ));
    let mut wrong_counts = facts;
    wrong_counts.scanned_counts.users += 1;
    assert!(matches!(
        owner.adopt_with_signed_startup(&wrong_counts, context(scope)),
        Err(RootError::AdoptionEvidence(AdoptionEvidenceError::Missing(
            "complete coverage"
        )))
    ));
    assert_eq!(handle.metadata().unwrap(), before);
    assert_eq!(handle.adoption_record().unwrap(), None);
    let (serving, admission, digest) = owner
        .adopt_with_signed_startup(&facts, context(scope))
        .unwrap();
    assert_eq!(serving.status, RootStatus::Serving);
    assert_eq!(serving.instance_id, before.instance_id);
    assert_eq!(serving.digest, before.digest);
    assert_eq!(
        handle.validate_production_admission(&admission),
        Ok(serving)
    );
    assert_eq!(
        handle.adoption_record().unwrap().unwrap().grade,
        AdoptionGrade::Production
    );
    assert_ne!(digest, [0; 32]);
    assert!(matches!(
        owner.adopt_with_signed_startup(&facts, context(scope)),
        Err(RootError::AdoptionEvidence(
            AdoptionEvidenceError::InvalidRootStatus
        ))
    ));
}
