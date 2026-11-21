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
    fixture_envelope(env, dir, subject, |_: &mut StartupEvidencePayload| {})
}

pub(super) fn fixture_envelope(
    env: Vec<(String, String)>,
    dir: &Path,
    subject: StartupEvidenceSubject,
    amend: impl FnOnce(&mut StartupEvidencePayload),
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
    let env = write_envelope(env, dir, payload);
    println!(
        "memory-v1 e2e: signed evidence from an ephemeral fixture issuer, not a production issuer"
    );
    env
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
