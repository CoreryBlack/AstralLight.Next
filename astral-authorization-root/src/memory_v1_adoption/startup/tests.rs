use super::*;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn subject() -> StartupEvidenceSubject {
    StartupEvidenceSubject {
        installation_id: MemoryId::from_bytes([1; 16]),
        database_scope: [2; 32],
        schema_fingerprint: [3; 32],
        candidate_digest: [4; 32],
        registry_digest: [5; 32],
        journal_stream: MemoryId::from_bytes([6; 16]),
        journal_epoch: MemoryId::from_bytes([7; 16]),
        journal_sequence: 9,
        mutation_sequence: 8,
        journal_tail_hash: [10; 32],
    }
}

fn payload() -> StartupEvidencePayload {
    StartupEvidencePayload {
        version: VERSION,
        subject: subject(),
        issued_at: 100,
        expires_at: 200,
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
    }
}

fn signed(payload: &StartupEvidencePayload) -> ([u8; 32], serde_json::Value) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let sig = key.sign(&payload.signing_bytes().unwrap());
    (
        key.public_key().as_ref().try_into().unwrap(),
        serde_json::json!({"payload": payload, "signature": hex::encode(sig.as_ref())}),
    )
}

fn authenticate(
    key: &[u8; 32],
    envelope: &serde_json::Value,
) -> Result<AuthenticatedStartupEvidence, StartupEvidenceError> {
    AuthenticatedStartupEvidence::authenticate(key, &serde_json::to_vec(envelope).unwrap())
}

#[test]
fn signature_and_every_observed_scope_field_must_match() {
    use StartupEvidenceError as ErrKind;
    let (key, envelope) = signed(&payload());
    let verified = authenticate(&key, &envelope).unwrap();
    let observed = subject();
    let digest = verified.bind(&observed, 130).unwrap().envelope_digest;
    assert_ne!(digest, [0; 32]);
    assert_eq!(
        verified.bind(&observed, 200).unwrap_err(),
        ErrKind::InvalidWindow
    );
    assert_eq!(
        verified.bind(&observed, 99).unwrap_err(),
        ErrKind::InvalidWindow
    );
    let tail =
        JournalAnchor::new(observed.journal_stream, 9, 8, observed.journal_tail_hash).unwrap();
    assert_eq!(
        verified.check_checkpoint(observed.installation_id, observed.journal_epoch, tail),
        Ok(())
    );
    assert_eq!(
        verified.check_database_scope(&observed.database_scope),
        Ok(())
    );
    assert_eq!(
        verified.check_database_scope(&[30; 32]),
        Err(ErrKind::SubjectMismatch)
    );
    for wrong in [
        StartupEvidenceSubject {
            installation_id: MemoryId::from_bytes([31; 16]),
            ..observed.clone()
        },
        StartupEvidenceSubject {
            database_scope: [32; 32],
            ..observed.clone()
        },
        StartupEvidenceSubject {
            schema_fingerprint: [33; 32],
            ..observed.clone()
        },
        StartupEvidenceSubject {
            candidate_digest: [34; 32],
            ..observed.clone()
        },
        StartupEvidenceSubject {
            registry_digest: [35; 32],
            ..observed.clone()
        },
        StartupEvidenceSubject {
            journal_stream: MemoryId::from_bytes([36; 16]),
            ..observed.clone()
        },
        StartupEvidenceSubject {
            journal_epoch: MemoryId::from_bytes([37; 16]),
            ..observed.clone()
        },
        StartupEvidenceSubject {
            journal_sequence: 10,
            ..observed.clone()
        },
        StartupEvidenceSubject {
            mutation_sequence: 7,
            ..observed.clone()
        },
        StartupEvidenceSubject {
            journal_tail_hash: [38; 32],
            ..observed
        },
    ] {
        assert_eq!(
            verified.bind(&wrong, 130).unwrap_err(),
            ErrKind::SubjectMismatch
        );
    }
    let (unknown_key, _) = signed(&payload());
    assert!(matches!(
        authenticate(&unknown_key, &envelope),
        Err(ErrKind::InvalidSignature)
    ));
    let mut changed = envelope;
    changed["payload"]["issued_at"] = 101.into();
    assert!(matches!(
        authenticate(&key, &changed),
        Err(ErrKind::InvalidSignature)
    ));
}

#[test]
fn a_signed_but_incomplete_or_long_lived_bundle_is_refused() {
    use StartupEvidenceError as ErrKind;
    let mut invalid = payload();
    invalid.reports.writer_coverage = [0; 32];
    let (key, envelope) = signed(&invalid);
    assert!(matches!(
        authenticate(&key, &envelope),
        Err(ErrKind::InvalidReports)
    ));
    invalid.reports.writer_coverage = invalid.reports.audit_correlation;
    let (key, envelope) = signed(&invalid);
    assert!(matches!(
        authenticate(&key, &envelope),
        Err(ErrKind::InvalidReports)
    ));
    invalid = payload();
    invalid.expires_at = invalid.issued_at + MAX_VALIDITY_SECONDS + 1;
    let (key, mut envelope) = signed(&invalid);
    assert!(matches!(
        authenticate(&key, &envelope),
        Err(ErrKind::InvalidWindow)
    ));
    envelope["pinned_key"] = serde_json::json!(key);
    assert!(matches!(
        authenticate(&key, &envelope),
        Err(ErrKind::InvalidEnvelope)
    ));
    assert!(matches!(
        AuthenticatedStartupEvidence::authenticate(&key, &[0; MAX_STARTUP_EVIDENCE_BYTES + 1]),
        Err(ErrKind::InvalidEnvelope)
    ));
}
