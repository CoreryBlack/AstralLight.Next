//! memory—v1: Isolated E2E issuer. This signer is never linked into the service.

use super::*;
use astral_authorization_root::memory_v1_adoption::startup::{
    StartupEvidencePayload, StartupEvidenceReports, StartupEvidenceSubject,
};
use ed25519_dalek::{Signer, SigningKey};

// memory—v1: Ask the real executable to inspect the exact applied snapshot.
pub(super) async fn inspect_fixture_subject(
    env: &[(String, String)],
    cwd: &Path,
    expected_database_scope: [u8; 32],
) -> StartupEvidenceSubject {
    let result = timeout(
        Duration::from_secs(60),
        Command::new(BIN)
            .arg("inspect-startup-subject")
            .env_clear()
            .envs(env.iter().map(|(key, value)| (key, value)))
            .current_dir(cwd)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("startup inspection deadline")
    .expect("run startup inspection");
    assert!(
        result.status.success(),
        "{}",
        redact(&String::from_utf8_lossy(&result.stderr), env)
    );
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(!stdout.lines().any(|line| line.starts_with(READY_PREFIX)));
    let subject: StartupEvidenceSubject = stdout
        .lines()
        .find_map(|line| serde_json::from_str(line).ok())
        .expect("exact inspected subject");
    assert_eq!(subject.database_scope, expected_database_scope);
    let installation = env
        .iter()
        .find(|(key, _)| key == "ASTRAL_MEMORY_V1_INSTALLATION_ID")
        .unwrap()
        .1
        .parse::<MemoryId>()
        .unwrap();
    assert_eq!(subject.installation_id, installation);
    subject
}

// memory—v1: Issue a fixture-only authorization from an independently applied genesis.
pub(super) async fn provision(
    env: Vec<(String, String)>,
    cwd: &Path,
    dir: &Path,
    expected_database_scope: [u8; 32],
) -> Vec<(String, String)> {
    let subject = inspect_fixture_subject(&env, cwd, expected_database_scope).await;
    assert_eq!(subject.journal_sequence, 0);
    assert_eq!(subject.mutation_sequence, 0);
    sign_fixture(env, dir, subject)
}

// memory—v1: Sign only disposable test subjects; callers establish the fixture observations.
pub(super) fn sign_fixture(
    env: Vec<(String, String)>,
    dir: &Path,
    subject: StartupEvidenceSubject,
) -> Vec<(String, String)> {
    build_fixture_envelope(env, dir, subject, |_: &mut StartupEvidencePayload| {}, true)
}

pub(super) fn fixture_envelope(
    env: Vec<(String, String)>,
    dir: &Path,
    subject: StartupEvidenceSubject,
    amend: impl FnOnce(&mut StartupEvidencePayload),
) -> Vec<(String, String)> {
    build_fixture_envelope(env, dir, subject, amend, false)
}

// memory—v1: Negative envelopes intentionally bypass the positive handoff wait.
fn build_fixture_envelope(
    env: Vec<(String, String)>,
    dir: &Path,
    subject: StartupEvidenceSubject,
    amend: impl FnOnce(&mut StartupEvidencePayload),
    wait_for_validity: bool,
) -> Vec<(String, String)> {
    let installation = subject.installation_id;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let fixture_report = |name: &[u8]| {
        use sha2::{Digest, Sha256};
        Sha256::new()
            .chain_update(b"darkstar/isolated-startup-issuer/1\0")
            .chain_update(installation.as_bytes())
            .chain_update(name)
            .finalize()
            .into()
    };
    let mut payload = StartupEvidencePayload {
        version: 1,
        subject,
        issued_at: now,
        expires_at: now + 300,
        reports: StartupEvidenceReports {
            source_provenance: fixture_report(b"source"),
            snapshot_identity: fixture_report(b"snapshot"),
            lifecycle_and_validity: fixture_report(b"lifecycle"),
            confirmation_authority: fixture_report(b"confirmation"),
            resource_ownership: fixture_report(b"ownership"),
            eligibility: fixture_report(b"eligibility"),
            separation_of_duties: fixture_report(b"separation"),
            writer_coverage: fixture_report(b"writers"),
            audit_correlation: fixture_report(b"audit"),
            persistence_recovery: fixture_report(b"recovery"),
        },
    };
    amend(&mut payload);
    let (issued_at, expires_at) = (payload.issued_at, payload.expires_at);
    let env = write_envelope(env, dir, payload);
    if wait_for_validity {
        wait_for_fixture_window(issued_at, expires_at, Duration::from_secs(5), || {
            astral_authorization_root::memory_v1_policy_time::PolicyTime::sample_host()
                .map(|time| (time.earliest(), time.latest()))
        })
        .expect("fixture issuer could not hand off evidence inside the trusted window");
    }
    println!(
        "memory-v1 e2e: signed evidence from an ephemeral fixture issuer, not a production issuer"
    );
    env
}

// memory—v1: The issuer keeps its original signed times. Only a trusted interval
// overlapping the start can settle; an unavailable clock or expired window fails.
fn wait_for_fixture_window(
    issued_at: i64,
    expires_at: i64,
    budget: Duration,
    mut sample: impl FnMut() -> Option<(i64, i64)>,
) -> Result<(), &'static str> {
    let deadline = std::time::Instant::now()
        .checked_add(budget)
        .ok_or("invalid handoff deadline")?;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("fixture handoff timed out");
        }
        let (earliest, latest) = sample().ok_or("trusted clock unavailable")?;
        if std::time::Instant::now() >= deadline {
            return Err("fixture handoff timed out");
        }
        if issued_at <= 0 || issued_at >= expires_at || earliest < 0 || earliest > latest {
            return Err("invalid trusted interval or signed window");
        }
        if latest >= expires_at || issued_at > latest {
            return Err("fixture window expired or definitely in the future");
        }
        if earliest >= issued_at {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("fixture handoff timed out");
        }
        std::thread::sleep(Duration::from_millis(25).min(remaining));
    }
}

// memory—v1: The private key stays local to this one Rust test process.
fn write_envelope(
    env: Vec<(String, String)>,
    dir: &Path,
    payload: StartupEvidencePayload,
) -> Vec<(String, String)> {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let key = SigningKey::from_bytes(&seed);
    let signature = key.sign(&payload.signing_bytes().unwrap());
    let bytes = serde_json::to_vec(
        &json!({"payload":payload,"signature":hex::encode(signature.to_bytes())}),
    )
    .unwrap();
    let path = dir.join(format!("startup-evidence-{}.json", uuid::Uuid::new_v4()));
    std::fs::write(&path, bytes).unwrap();
    let env = with_var(
        env,
        "ASTRAL_MEMORY_V1_STARTUP_EVIDENCE_FILE",
        path.to_str().unwrap(),
    );
    with_var(
        env,
        "ASTRAL_MEMORY_V1_STARTUP_EVIDENCE_PUBLIC_KEY",
        &hex::encode(key.verifying_key().as_bytes()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1: The signed payload retains the issuer's real issuance second.
    #[test]
    fn fixture_signature_keeps_real_issuance_time() {
        let dir = TempDir::new("issuer-time");
        let subject = StartupEvidenceSubject {
            installation_id: MemoryId::from_bytes([1; 16]),
            database_scope: [2; 32],
            schema_fingerprint: [3; 32],
            candidate_digest: [4; 32],
            registry_digest: [5; 32],
            journal_stream: MemoryId::from_bytes([6; 16]),
            journal_epoch: MemoryId::from_bytes([7; 16]),
            journal_sequence: 0,
            mutation_sequence: 0,
            journal_tail_hash: [8; 32],
        };
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        };
        let before = now();
        let env = fixture_envelope(Vec::new(), dir.path(), subject, |_| {});
        let after = now();
        let value = |name: &str| env.iter().find(|(key, _)| key == name).unwrap().1.as_str();
        let bytes = std::fs::read(value("ASTRAL_MEMORY_V1_STARTUP_EVIDENCE_FILE")).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let issued_at = document["payload"]["issued_at"].as_i64().unwrap();
        assert!((before..=after).contains(&issued_at));
        assert_eq!(
            document["payload"]["expires_at"].as_i64(),
            Some(issued_at + 300)
        );
        let mut key = [0; 32];
        hex::decode_to_slice(
            value("ASTRAL_MEMORY_V1_STARTUP_EVIDENCE_PUBLIC_KEY"),
            &mut key,
        )
        .unwrap();
        let evidence = astral_authorization_root::memory_v1_adoption::startup::AuthenticatedStartupEvidence::authenticate(&key, &bytes).unwrap();
        assert!(evidence.check_window(issued_at).is_ok());
        assert!(evidence.check_window(issued_at - 1).is_err());
    }

    // memory—v1: Handoff keeps the signed boundaries and only waits on overlap.
    #[test]
    fn fixture_window_handoff_requires_the_whole_interval() {
        let mut samples = [(99, 100), (100, 101)].into_iter();
        let mut calls = 0;
        wait_for_fixture_window(100, 200, Duration::from_millis(100), || {
            calls += 1;
            samples.next()
        })
        .unwrap();
        assert_eq!(calls, 2);
        for sample in [None, Some((98, 99)), Some((199, 200)), Some((101, 100))] {
            let mut calls = 0;
            assert!(
                wait_for_fixture_window(100, 200, Duration::from_millis(50), || {
                    calls += 1;
                    sample
                })
                .is_err()
            );
            assert_eq!(calls, 1);
        }
        assert!(
            wait_for_fixture_window(100, 200, Duration::from_millis(5), || { Some((99, 100)) })
                .is_err()
        );
    }
}
