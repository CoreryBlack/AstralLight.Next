//! memory—v1: Two-stage, run-scoped synthetic startup material for the paper lane.
//! This issuer is a test fixture, not a production source of adoption evidence.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use astral_authorization_root::memory_v1_adoption::startup::{
    startup_registry_digest, AuthenticatedStartupEvidence, StartupEvidencePayload,
    StartupEvidenceReports, StartupEvidenceSubject,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::install_isolated_test_root;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

// memory—v1: The operator owns this private, exclusive, run-scoped directory.
fn bundle_dir(run: &str, empty: bool) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(scope::BUNDLE_ENV).expect("missing paper startup bundle directory"),
    );
    assert!(
        path.is_absolute(),
        "paper startup bundle path must be absolute"
    );
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(format!("paper-startup-{run}").as_str()),
        "bundle directory name must bind the run"
    );
    assert_eq!(
        std::fs::canonicalize(&path).expect("canonical paper startup bundle"),
        path,
        "bundle path must be canonical"
    );
    let metadata = std::fs::symlink_metadata(&path).expect("inspect paper startup bundle");
    assert!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "bundle must be a real directory"
    );
    assert_eq!(
        metadata.mode() & 0o7777,
        0o700,
        "bundle must have mode 0700"
    );
    assert_eq!(
        metadata.uid(),
        unsafe { libc::geteuid() },
        "bundle must belong to this user"
    );
    if empty {
        assert!(
            std::fs::read_dir(&path).unwrap().next().is_none(),
            "new run requires an empty bundle"
        );
    }
    path
}

// memory—v1: Never replace a prior result or follow an existing artifact.
fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create exclusive paper startup artifact");
    file.write_all(bytes).expect("write paper startup artifact");
    file.sync_all().expect("sync paper startup artifact");
}

// memory—v1: Refuse non-private or non-regular trust material.
fn read_private(path: &Path) -> Vec<u8> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .expect("open paper startup artifact");
    let metadata = file.metadata().expect("inspect paper startup artifact");
    assert!(metadata.is_file(), "artifact must be regular");
    assert_eq!(
        metadata.mode() & 0o7777,
        0o600,
        "artifact must have mode 0600"
    );
    assert_eq!(
        metadata.uid(),
        unsafe { libc::geteuid() },
        "artifact owner mismatch"
    );
    assert!(
        metadata.len() <= 16 * 1024,
        "paper startup artifact too large"
    );
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .expect("read paper startup artifact");
    assert!(
        bytes.len() <= 16 * 1024,
        "paper startup artifact grew beyond its limit"
    );
    bytes
}

fn registry() -> Vec<RegistryDeclaration> {
    let mut resources: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for route in astral_trustgraph::api::permission_check::MEMORY_V1_ROUTE_REGISTRATIONS {
        let actions = resources.entry(route.resource).or_default();
        actions.insert(route.action);
        actions.extend(route.additional_actions.iter().copied());
    }
    resources
        .into_iter()
        .map(|(resource, actions)| RegistryDeclaration {
            resource: resource.to_owned(),
            actions: actions.into_iter().map(str::to_owned).collect(),
        })
        .collect()
}

// memory—v1: The candidate comes from the independent literal oracle, never the inspector.
fn expected_candidate_digest() -> [u8; 32] {
    let rows = expected::expected_rows();
    let selections = rows
        .current_version_selections()
        .expect("oracle version pointers");
    let owner = install_isolated_test_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 32,
            max_bindings_per_read: 4,
        },
    )
    .expect("construct literal oracle candidate");
    owner
        .handle()
        .metadata()
        .expect("read literal candidate digest")
        .digest
}

fn base_env(
    url: &str,
    credentials: &Path,
    bundle: &Path,
    installation: &str,
) -> Vec<(String, String)> {
    let (env, temporary_journal) = service_env(url, credentials);
    drop(temporary_journal);
    let env = super::super::with_var(
        env,
        "ASTRAL_MEMORY_V1_JOURNAL_DIR",
        bundle.join("journal").to_str().unwrap(),
    );
    super::super::with_var(env, "ASTRAL_MEMORY_V1_INSTALLATION_ID", installation)
}

// memory—v1: Generate reports describing only the synthetic observations made here.
fn reports(dir: &Path, run: &str, subject: &StartupEvidenceSubject) -> StartupEvidenceReports {
    let observations = [
        (
            "source",
            "approved run-scoped synthetic schema; operator supplies exclusive fixture ownership",
        ),
        (
            "snapshot",
            "nine tables scanned; 23 rows exactly matched independent literal oracle",
        ),
        (
            "lifecycle",
            "literal fixture contains only the stated synthetic active records",
        ),
        (
            "confirmation",
            "literal confirmation rows matched the synthetic oracle",
        ),
        (
            "ownership",
            "literal tenant and owner fields matched the synthetic oracle",
        ),
        (
            "eligibility",
            "only literal synthetic fixture facts were checked",
        ),
        (
            "separation",
            "synthetic fixture identities and confirmation rows were checked",
        ),
        (
            "writers",
            "fixture account grants checked; exclusive ownership is an operator prerequisite",
        ),
        (
            "audit",
            "new recovery tables were empty before synthetic initialization",
        ),
        (
            "recovery",
            "fresh journal and matching applied genesis; no suffix or recovery replay",
        ),
    ];
    let mut hashes = Vec::new();
    for (name, observation) in observations {
        let text = format!("synthetic test only; not production evidence\nrun={run}\ncategory={name}\nobservation={observation}\nsubject={}\n", serde_json::to_string(subject).unwrap());
        write_new(&dir.join(format!("{name}.txt")), text.as_bytes());
        hashes.push(Sha256::digest(text.as_bytes()).into());
    }
    StartupEvidenceReports {
        source_provenance: hashes[0],
        snapshot_identity: hashes[1],
        lifecycle_and_validity: hashes[2],
        confirmation_authority: hashes[3],
        resource_ownership: hashes[4],
        eligibility: hashes[5],
        separation_of_duties: hashes[6],
        writer_coverage: hashes[7],
        audit_correlation: hashes[8],
        persistence_recovery: hashes[9],
    }
}

// memory—v1: Seed only a fresh approved fixture and sign an independently checked subject.
pub(super) async fn prepare(run: &str, schema: &str, url: &Url) {
    assert_eq!(
        std::env::var(scope::PREPARE_ENV).as_deref(),
        Ok(run),
        "paper preparation approval must match the run"
    );
    let bundle = bundle_dir(run, true);
    let journal = bundle.join("journal");
    std::fs::create_dir(&journal).expect("create new journal directory");
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700)).unwrap();
    let report_dir = bundle.join("reports");
    std::fs::create_dir(&report_dir).expect("create new report directory");
    std::fs::set_permissions(&report_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let install = uuid::Uuid::new_v4().to_string();
    write_new(&bundle.join("installation-id"), install.as_bytes());

    let direct = options(url, schema, scope::PORT);
    seed(&direct, schema).await;
    let observer = pool(&direct).await;
    let captured = capture(&observer, &expected::expected_rows(), expected::COUNTS).await;
    let schema_fingerprint = captured
        .report
        .as_ref()
        .unwrap()
        .schema
        .fingerprint
        .as_bytes();
    let mut connection = observer
        .acquire()
        .await
        .expect("read fixture database identity");
    let database_scope =
        astral_db::memory_v1_candidate_loader::read_startup_database_scope(&mut connection)
            .await
            .expect("read fixture database scope");
    drop(connection);

    let credentials_dir = TempDir::new("paper-provision-credentials");
    let credentials = write_credentials(credentials_dir.path(), 0o600);
    let env = base_env(url.as_str(), &credentials, &bundle, &install);
    let installation = uuid::Uuid::parse_str(&install).expect("valid installation id");
    let (stream, epoch, genesis) =
        super::super::stage_retained_journal(&journal, *installation.as_bytes());
    use astral_db::memory_v1_apply::{
        initialize_memory_v1_apply_progress, MemoryV1ApplyProgressInit,
    };
    match initialize_memory_v1_apply_progress(&observer, stream, epoch, genesis).await {
        Ok(MemoryV1ApplyProgressInit::Initialized) => {}
        Ok(MemoryV1ApplyProgressInit::Verified) => {
            unknown("fresh fixture unexpectedly contained an existing progress row")
        }
        Err(_) => unknown("fixture apply progress initialization was not confirmed"),
    }
    let progress = astral_db::memory_v1_apply::read_memory_v1_apply_progress(&observer, stream)
        .await
        .unwrap_or_else(|_| unknown("cannot read initialized fixture progress"))
        .unwrap_or_else(|| unknown("initialized fixture progress is missing"));
    assert_eq!(
        (
            progress.epoch_id,
            progress.last_journal_sequence,
            progress.last_mutation_sequence,
            progress.last_frame_hash
        ),
        (epoch, 0, 0, genesis)
    );
    observer.close().await;

    let cwd = TempDir::new("paper-provision-cwd");
    let inspected =
        super::super::startup_issuer::inspect_fixture_subject(&env, cwd.path(), database_scope)
            .await;
    let expected_subject = StartupEvidenceSubject {
        installation_id: MemoryId::from_bytes(*uuid::Uuid::parse_str(&install).unwrap().as_bytes()),
        database_scope,
        schema_fingerprint,
        candidate_digest: expected_candidate_digest(),
        registry_digest: startup_registry_digest(&registry()),
        journal_stream: stream,
        journal_epoch: epoch,
        journal_sequence: 0,
        mutation_sequence: 0,
        journal_tail_hash: genesis,
    };
    assert_eq!(
        inspected, expected_subject,
        "inspected subject differs from independently checked fixture"
    );
    let reports = reports(&report_dir, run, &expected_subject);
    let sample = astral_authorization_root::memory_v1_policy_time::PolicyTime::sample_host()
        .expect("trusted host time is required to issue fixture evidence");
    let issued_at = sample.latest();
    let payload = StartupEvidencePayload {
        version: 1,
        subject: expected_subject,
        issued_at,
        expires_at: issued_at + 600,
        reports,
    };
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    let key = SigningKey::from_bytes(&seed);
    let signature = key.sign(&payload.signing_bytes().unwrap());
    let envelope = serde_json::to_vec(
        &json!({"payload":payload, "signature":hex::encode(signature.to_bytes())}),
    )
    .unwrap();
    let verified =
        AuthenticatedStartupEvidence::authenticate(key.verifying_key().as_bytes(), &envelope)
            .expect("verify fixture signature");
    // Wait for the complete trusted-time interval to enter the non-backdated window.
    timeout(Duration::from_secs(10), async {
        loop {
            let sample =
                astral_authorization_root::memory_v1_policy_time::PolicyTime::sample_host()
                    .expect("trusted host time disappeared before fixture handoff");
            if sample.earliest() >= issued_at {
                verified.check_window(sample.earliest()).unwrap();
                verified.check_window(sample.latest()).unwrap();
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("trusted time did not enter the fixture evidence window");
    write_new(
        &bundle.join("startup-public-key"),
        hex::encode(key.verifying_key().as_bytes()).as_bytes(),
    );
    write_new(&bundle.join("startup-evidence.json"), &envelope);
    write_new(&bundle.join("prepared-run"), run.as_bytes());
    println!("paper-mysql: prepared run={run} synthetic_only=true journal_sequence=0");
}

// memory—v1: Bind the consumer to the same private run material and pinned key.
pub(super) fn service_environment(
    run: &str,
    url: &str,
    credentials: &Path,
) -> Vec<(String, String)> {
    let bundle = bundle_dir(run, false);
    assert_eq!(
        read_private(&bundle.join("prepared-run")),
        run.as_bytes(),
        "bundle run mismatch"
    );
    let installation = String::from_utf8(read_private(&bundle.join("installation-id"))).unwrap();
    let _ = uuid::Uuid::parse_str(&installation).expect("valid bundle installation id");
    let key = String::from_utf8(read_private(&bundle.join("startup-public-key"))).unwrap();
    let key_bytes: [u8; 32] = hex::decode(&key)
        .expect("valid bundle public key")
        .try_into()
        .expect("32 byte public key");
    assert_eq!(key, hex::encode(key_bytes));
    let envelope = read_private(&bundle.join("startup-evidence.json"));
    let authenticated = AuthenticatedStartupEvidence::authenticate(&key_bytes, &envelope)
        .expect("verify bundle signature");
    authenticated
        .check_current_window()
        .expect("fixture evidence window or trusted host time is invalid");
    let envelope_value: Value = serde_json::from_slice(&envelope).expect("parse fixture envelope");
    let payload: StartupEvidencePayload = serde_json::from_value(envelope_value["payload"].clone())
        .expect("parse fixture evidence payload");
    for (name, digest) in [
        ("source", payload.reports.source_provenance),
        ("snapshot", payload.reports.snapshot_identity),
        ("lifecycle", payload.reports.lifecycle_and_validity),
        ("confirmation", payload.reports.confirmation_authority),
        ("ownership", payload.reports.resource_ownership),
        ("eligibility", payload.reports.eligibility),
        ("separation", payload.reports.separation_of_duties),
        ("writers", payload.reports.writer_coverage),
        ("audit", payload.reports.audit_correlation),
        ("recovery", payload.reports.persistence_recovery),
    ] {
        let report = read_private(&bundle.join("reports").join(format!("{name}.txt")));
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(report)),
            digest,
            "fixture report digest mismatch: {name}"
        );
    }
    let env = base_env(url, credentials, &bundle, &installation);
    let env = super::super::with_var(env, "ASTRAL_MEMORY_V1_STARTUP_EVIDENCE_PUBLIC_KEY", &key);
    super::super::with_var(
        env,
        "ASTRAL_MEMORY_V1_STARTUP_EVIDENCE_FILE",
        bundle.join("startup-evidence.json").to_str().unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // memory—v1: Reject substituted, over-permissive and oversized trust files.
    fn private_artifact_reader_refuses_unsafe_files() {
        let dir = TempDir::new("paper-private-artifact-check");
        let file = dir.path().join("private");
        write_new(&file, b"fixture");
        assert_eq!(read_private(&file), b"fixture");
        let symlink = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &symlink).unwrap();
        assert!(std::panic::catch_unwind(|| read_private(&symlink)).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(std::panic::catch_unwind(|| read_private(&file)).is_err());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&file, vec![0; 16 * 1024 + 1]).unwrap();
        assert!(std::panic::catch_unwind(|| read_private(&file)).is_err());
        assert!(std::panic::catch_unwind(|| write_new(&file, b"replace")).is_err());
    }

    #[test]
    // memory—v1: The independent literal oracle is a valid, bounded candidate.
    fn literal_oracle_builds_candidate_without_database() {
        assert_ne!(expected_candidate_digest(), [0; 32]);
    }
}
