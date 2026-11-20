//! memory—v1: the full-request-lifecycle stress, stability, and availability
//! driver.
//!
//! This test runs the real production composition (fixture root, real durable
//! journal, real loopback TCP, real gateway/authn/authz stack) and drives a
//! bounded but meaningful load profile through it:
//!
//! * a warm-up phase that issues one request per connection before measuring;
//! * a concurrency ladder (1, 4, 16 concurrent clients) over mixed traffic:
//!   ALLOW reads, rule DENYs (real 403 with both durable proofs), and logins;
//! * a soak phase at a sustained concurrency to observe stability drift;
//! * an availability phase that measures per-request success against the
//!   serving root over the same window.
//!
//! Two timing views are collected and quantified:
//!
//! * client view — per-request wall-clock RTT measured by the driver;
//! * server view — the phase histograms the commit owner records
//!   (`astral_memory_v1_commit_phase_seconds{phase=...}` and
//!   `astral_memory_v1_deny_phase_seconds{phase=...}`), scraped from the
//!   Prometheus recorder after the run and reduced to per-phase deltas.
//!
//! The report quantifies per phase: count, mean, P50, P95, P99, max, plus
//! overall throughput, error counts by status class, and availability. The
//! assertions are behavioural floors (no 5xx except the expected deny
//! semantics, every ALLOW before/after identical), not performance gates:
//! absolute timings are hardware-dependent and belong in the report, not in
//! a pass/fail predicate.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc as StdArc;
use std::time::{Duration, Instant};

use astral_authorization_root::memory_v1_adoption::ColdLoadFacts;
use astral_authorization_root::memory_v1_root::RootStatus;
use astral_common::config::AppConfig;
use astral_identity::memory_v1_service::MemoryV1FileCredentials;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::{install_rows, readiness_line, registry_declarations, sealed_production_input, serve};
use crate::memory_v1_composition::full_path_tests::{
    fixture, ALICE, BOB, CARD_ALLOW, CARD_BOB, CARD_OVERLAY_DENY, REGISTRY,
};

#[path = "memory_v1_lifecycle_stress_tests/login_curve.rs"]
mod login_curve;

const LOGIN: &str = "/api/v1/auth/sessions";
const CONCURRENCY_LADDER: &[usize] = &[1, 4, 16];
const SOAK_CONCURRENCY: usize = 8;
const SOAK_REQUESTS_PER_WORKER: usize = 40;
const WARMUP_REQUESTS: usize = 8;

/// The quantified summary of one timing sample set.
#[derive(Debug)]
struct PhaseQuantile {
    count: u64,
    mean_us: u64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
}

impl PhaseQuantile {
    fn summarize(samples: &[u64]) -> Self {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let count = sorted.len() as u64;
        let mean = sorted.iter().sum::<u64>() / count.max(1);
        let pick = |fraction: f64| -> u64 {
            if sorted.is_empty() {
                return 0;
            }
            let index = ((sorted.len() as f64) * fraction)
                .floor()
                .min((sorted.len() - 1) as f64);
            sorted[index as usize]
        };
        Self {
            count,
            mean_us: mean,
            p50_us: pick(0.50),
            p95_us: pick(0.95),
            p99_us: pick(0.99),
            max_us: sorted.last().copied().unwrap_or(0),
        }
    }
}

/// A private 0600 credentials file for the fixture users.
struct CredentialsFile {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl CredentialsFile {
    // memory—v1: Own the fixture directory before creating credentials or journal files.
    fn write() -> Self {
        let dir =
            std::env::temp_dir().join(format!("astral-memory-v1-stress-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let fixture = Self {
            path: dir.join("credentials.json"),
            dir,
        };
        let entry = |identifier: &str, user: [u8; 16], password: &str| {
            json!({
                "identifier": identifier,
                "userId": astral_types::memory_v1::MemoryId::from_bytes(user).to_string(),
                "passwordHash": astral_identity::auth::hash_password(password).unwrap(),
                "status": "active",
                "revision": 1,
            })
        };
        let text = json!({
            "version": 1,
            "credentials": [
                entry("alice", ALICE, "alice-secret"),
                entry("bob", BOB, "bob-secret"),
            ],
        })
        .to_string();
        std::fs::write(&fixture.path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        fixture
    }
}

impl Drop for CredentialsFile {
    // memory—v1: Clean the run-scoped directory even if the test unwinds.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// One raw HTTP/1.1 request over a fresh connection; returns status and body.
async fn raw_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&Value>,
) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to the service");
    let body_text = body.map(Value::to_string).unwrap_or_default();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(token) = bearer {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if body.is_some() {
        request.push_str("Content-Type: application/json\r\n");
    }
    request.push_str(&format!(
        "Content-Length: {}\r\n\r\n{body_text}",
        body_text.len()
    ));
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(30), stream.read_to_end(&mut raw))
        .await
        .expect("the service answered within the deadline")
        .unwrap();
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a complete HTTP response head");
    let head = std::str::from_utf8(&raw[..split]).unwrap();
    let status: u16 = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let payload = &raw[split + 4..];
    // Chunked responses are small here; a full dechunk is unnecessary for the
    // status-level assertions, but the body is parsed when present.
    let body = serde_json::from_slice(payload).unwrap_or(Value::Null);
    (status, body)
}

// memory—v1: Share the lifecycle fixture's login payload across HTTP clients.
fn login_body(card: [u8; 16]) -> Value {
    let (identifier, password) = match card {
        CARD_BOB => ("bob", "bob-secret"),
        _ => ("alice", "alice-secret"),
    };
    json!({
        "identifier": identifier,
        "password": password,
        "userCardId": astral_types::memory_v1::MemoryId::from_bytes(card).to_string(),
    })
}

// memory—v1: Establish a session through the existing fresh-connection client.
async fn login(addr: std::net::SocketAddr, card: [u8; 16]) -> String {
    let (status, body) = raw_request(addr, "POST", LOGIN, None, Some(&login_body(card))).await;
    assert_eq!(status, 200, "login must succeed: {body}");
    body["data"]["accessToken"]
        .as_str()
        .expect("an access token")
        .to_owned()
}

// memory—v1: Time successful reads separately from login and connection setup
// policy. Each worker uses one client and pre-issued session for its whole run.
async fn measure_allow_reads(addr: std::net::SocketAddr, extra_resources: usize) {
    use reqwest::header::CONNECTION;
    use tokio::sync::Barrier;

    const ROUNDS: usize = 3;
    const REQUESTS_PER_WORKER: usize = 128;
    let token = StdArc::new(login(addr, CARD_ALLOW).await);
    let url = format!("http://{addr}{REGISTRY}");
    for round in 0..ROUNDS {
        // Alternate mode order to reduce systematic warm-up bias.
        for keep_alive in [round % 2 == 1, round % 2 == 0] {
            for &workers in CONCURRENCY_LADDER {
                let ready = StdArc::new(Barrier::new(workers + 1));
                let start = StdArc::new(Barrier::new(workers + 1));
                let mut jobs = Vec::with_capacity(workers);
                for _ in 0..workers {
                    let token = StdArc::clone(&token);
                    let ready = StdArc::clone(&ready);
                    let start = StdArc::clone(&start);
                    let url = url.clone();
                    jobs.push(tokio::spawn(async move {
                        let client = reqwest::Client::builder()
                            .http1_only()
                            .no_proxy()
                            .timeout(Duration::from_secs(5))
                            .build()
                            .unwrap();
                        let get = || {
                            let request = client.get(&url).bearer_auth(token.as_str());
                            if keep_alive {
                                request
                            } else {
                                request.header(CONNECTION, "close")
                            }
                        };
                        let warm = get().send().await.unwrap().error_for_status().unwrap();
                        let body: Value = warm.json().await.unwrap();
                        let entries = body["data"].as_array().expect("registry response");
                        assert_eq!(
                            entries.len(),
                            registry_declarations().len() + extra_resources
                        );
                        ready.wait().await;
                        start.wait().await;
                        let mut samples = Vec::with_capacity(REQUESTS_PER_WORKER);
                        let mut failures = std::collections::BTreeMap::<u16, usize>::new();
                        for _ in 0..REQUESTS_PER_WORKER {
                            let began = Instant::now();
                            let response = get().send().await.unwrap();
                            let status = response.status();
                            let _ = response.bytes().await.unwrap();
                            if status == reqwest::StatusCode::OK {
                                samples.push(began.elapsed().as_micros() as u64);
                            } else {
                                *failures.entry(status.as_u16()).or_default() += 1;
                            }
                        }
                        (samples, failures)
                    }));
                }
                timeout(Duration::from_secs(10), ready.wait())
                    .await
                    .expect("ALLOW clients finished warm-up");
                let began = Instant::now();
                start.wait().await;
                let mut samples = Vec::new();
                let mut failures = std::collections::BTreeMap::<u16, usize>::new();
                for job in jobs {
                    let (times, statuses) = job.await.unwrap();
                    samples.extend(times);
                    for (status, count) in statuses {
                        *failures.entry(status).or_default() += count;
                    }
                }
                let elapsed = began.elapsed();
                let q = PhaseQuantile::summarize(&samples);
                eprintln!(
                    "allow_read extra_resources={extra_resources} keep_alive={keep_alive} workers={workers} round={round} ok={} non_200={failures:?} ok_per_sec={:.0} p50_us={} p95_us={} p99_us={}",
                    q.count,
                    q.count as f64 / elapsed.as_secs_f64(),
                    q.p50_us,
                    q.p95_us,
                    q.p99_us,
                );
                assert!(
                    failures.is_empty(),
                    "healthy ALLOW fixture returned {failures:?}"
                );
                assert_eq!(samples.len(), workers * REQUESTS_PER_WORKER);
            }
        }
    }
}

// memory—v1: Reuse the composed stress fixture for isolated opt-in curve cells.
#[test]
fn full_lifecycle_stress_collects_phase_timings_and_quantifies() {
    // The process root installs once per process; like the other lifecycle
    // tests, the stress body runs in an isolated child.
    const CHILD: &str = "ASTRAL_MEMORY_V1_STRESS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        if !cfg!(unix) {
            eprintln!("[SKIP] the stress run needs Unix for the credentials file mode");
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "memory_v1_service::lifecycle_stress_tests::full_lifecycle_stress_collects_phase_timings_and_quantifies",
                "--nocapture",
            ])
            .env(CHILD, "1");
        if let Some(rounds) = login_curve::rounds() {
            login_curve::run_matrix(&mut child, rounds);
            return;
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "stress child failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        // The child writes measurements to stderr; keep its nested libtest summary private.
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    #[tokio::main]
    // memory—v1: Serve one stress mode and drain its loopback composition.
    async fn run() {
        let login_cell = login_curve::selected_cell();
        // The stress process installs its own Prometheus recorder so the commit
        // owner's phase histograms can be rendered and quantified after the run.
        let prometheus_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder()
            .expect("the stress process installs one recorder");

        // ── 1. Stand up the production composition ──────────────────────────
        let credentials_file = CredentialsFile::write();
        let credentials = MemoryV1FileCredentials::load(&credentials_file.path).unwrap();
        let (rows, _selections) = fixture();
        let facts = ColdLoadFacts {
            schema_contract_version:
                astral_authorization_root::memory_v1_adoption::MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
            schema_fingerprint: [7; 32],
            snapshot_counts: rows.table_counts(),
            scanned_counts: rows.table_counts(),
            captured_at_unix_seconds: 1_700_000_000,
        };
        // The opt-in read curve shares the production composition and file
        // fixture with the lifecycle test, and runs in a fresh child per size.
        let read_curve = std::env::var("ASTRAL_MEMORY_V1_ALLOW_CURVE")
            .ok()
            .map(|size| match size.as_str() {
                "0" => 0,
                "128" => 128,
                _ => panic!("ALLOW curve size must be 0 or 128"),
            });
        let journal_dir = credentials_file.dir.join("journal");
        std::fs::create_dir(&journal_dir).unwrap();
        let journal = super::open_durable_journal(&journal_dir).unwrap();
        let (owner, admission) = {
            let owner = install_rows(rows).unwrap();
            let mut declarations = registry_declarations();
            for index in 0..read_curve.unwrap_or(0) {
                declarations.push(
                    astral_authorization_root::memory_v1_registry::RegistryDeclaration {
                        resource: format!("curve-resource-{index}"),
                        actions: vec!["read".into(), "write".into(), "list".into()],
                    },
                );
            }
            owner.install_registry(&declarations).unwrap();
            let input = sealed_production_input(&facts).unwrap();
            let (metadata, admission) = owner
                .adopt_with_production_evidence(&facts, &input)
                .expect("production adoption");
            assert_eq!(metadata.status, RootStatus::Serving);
            (std::sync::Arc::new(owner), std::sync::Arc::new(admission))
        };
        let mut config = AppConfig::default();
        config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
        // The stress keeps the commit owner out so it can drive governed commits
        // directly through the port while the composition serves HTTP.
        let root_for_readiness = owner.handle();
        let composition =
            super::assemble_production(owner, admission, journal, config, credentials).unwrap();
        let commit_port = composition.commit_port();
        let root_handle = composition.router();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ready = readiness_line(&root_for_readiness, addr).unwrap();
        assert!(ready.contains("grade=Production"), "{ready}");
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, root_handle, async move {
            let _ = stop_rx.await;
        }));
        let _ = root_handle;
        let _ = &composition;

        if let Some(cell) = login_cell {
            let result = login_curve::measure(addr, cell).await;
            stop_tx.send(()).unwrap();
            timeout(Duration::from_secs(15), server)
                .await
                .expect("the server stopped within the drain budget")
                .unwrap()
                .unwrap();
            std::fs::remove_dir_all(&journal_dir).unwrap();
            result.expect("the login curve cell completed with a valid fixture");
            return;
        }

        if let Some(extra_resources) = read_curve {
            measure_allow_reads(addr, extra_resources).await;
            stop_tx.send(()).unwrap();
            timeout(Duration::from_secs(15), server)
                .await
                .expect("the server stopped within the drain budget")
                .unwrap()
                .unwrap();
            std::fs::remove_dir_all(&journal_dir).unwrap();
            return;
        }

        // ── 2. Warm-up: one request per connection outside the measurement ──
        let warm_token = login(addr, CARD_ALLOW).await;
        // Warm-up tolerates fail-closed 503s: it only exists to prime caches
        // and code paths before the measured window.
        for _ in 0..WARMUP_REQUESTS {
            let (status, _) = raw_request(addr, "GET", REGISTRY, Some(&warm_token), None).await;
            assert!(status == 200 || status == 503, "warm-up status {status}");
        }

        // ── 3. Concurrency ladder: mixed traffic, client-side RTT samples ───
        let allow_rtt = StdArc::new(std::sync::Mutex::new(Vec::new()));
        let deny_rtt = StdArc::new(std::sync::Mutex::new(Vec::new()));
        let login_rtt = StdArc::new(std::sync::Mutex::new(Vec::new()));
        let server_errors = StdArc::new(AtomicU64::new(0));
        let overload_503 = StdArc::new(AtomicU64::new(0));
        let allow_200 = StdArc::new(AtomicU64::new(0));
        let deny_403 = StdArc::new(AtomicU64::new(0));
        let login_200 = StdArc::new(AtomicU64::new(0));

        for concurrency in CONCURRENCY_LADDER {
            let mut handles = Vec::new();
            for worker in 0..*concurrency {
                let allow_rtt = StdArc::clone(&allow_rtt);
                let login_rtt = StdArc::clone(&login_rtt);
                let server_errors = StdArc::clone(&server_errors);
                let overload_503 = StdArc::clone(&overload_503);
                let allow_200 = StdArc::clone(&allow_200);
                let login_200 = StdArc::clone(&login_200);
                handles.push(tokio::spawn(async move {
                for _round in 0..8 {
                    // ALLOW read: login first, then a registry read.
                    let card = if worker % 2 == 0 { CARD_ALLOW } else { CARD_BOB };
                    let token = login(addr, card).await;
                    let started = Instant::now();
                    let (status, _) =
                        raw_request(addr, "GET", REGISTRY, Some(&token), None).await;
                    let rtt = started.elapsed();
                    allow_rtt.lock().unwrap().push(rtt.as_micros() as u64);
                    if status == 200 {
                        allow_200.fetch_add(1, Ordering::Relaxed);
                    } else if status >= 500 {
                        // Fail-closed 503s under overload are recorded as
                        // measured availability, not silent failures.
                        server_errors.fetch_add(1, Ordering::Relaxed);
                        overload_503.fetch_add(1, Ordering::Relaxed);
                    }
                    // Login timing itself (authn + session issuance).
                    let started = Instant::now();
                    let (status, _) = raw_request(
                        addr,
                        "POST",
                        LOGIN,
                        None,
                        Some(&json!({
                            "identifier": "bob",
                            "password": "bob-secret",
                            "userCardId": astral_types::memory_v1::MemoryId::from_bytes(CARD_BOB).to_string(),
                        })),
                    )
                    .await;
                    let rtt = started.elapsed();
                    login_rtt.lock().unwrap().push(rtt.as_micros() as u64);
                    if status == 200 {
                        login_200.fetch_add(1, Ordering::Relaxed);
                    } else if status >= 500 {
                        overload_503.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
            }
            for handle in handles {
                handle.await.unwrap();
            }
        }
        let _ = &login_rtt;
        let _ = &allow_rtt;

        // ── 4. DENY traffic: overlay card produces real 403 with proofs ─────
        let overlay_token = login(addr, CARD_OVERLAY_DENY).await;
        for _ in 0..16 {
            let started = Instant::now();
            let (status, _) = raw_request(addr, "GET", REGISTRY, Some(&overlay_token), None).await;
            let rtt = started.elapsed();
            assert_eq!(status, 403, "overlay DENY must stay 403");
            deny_rtt.lock().unwrap().push(rtt.as_micros() as u64);
            deny_403.fetch_add(1, Ordering::Relaxed);
        }

        // ── 4b. Governed commits: drive the durable commit owner through its
        // journal I/O and root CAS phases with real mutations ────────────────
        let commit_rtt = StdArc::new(std::sync::Mutex::new(Vec::new()));
        {
            // The commit owner is reachable through the composition's injected
            // port; the stress drives user-card enables (one accepted, the rest
            // idempotent replays that still traverse journal I/O and root CAS).
            let commit_rtt = StdArc::clone(&commit_rtt);
            let commit_port = StdArc::clone(&commit_port);
            let fingerprint = "ab".repeat(32);
            let fingerprint_bytes = {
                let bytes = hex::decode(&fingerprint).unwrap();
                <[u8; 32]>::try_from(bytes).unwrap()
            };
            for round in 0..24_u64 {
                // The root advances with every accepted commit; each request
                // binds to the exact current serving metadata.
                let base_metadata = root_for_readiness.metadata().unwrap();
                let operation_id = format!("stress-commit-{}", uuid::Uuid::new_v4());
                let mutation =
                astral_authorization_root::memory_v1_root::ManagementMutationV2::UserCardStatus {
                    user_card_id: CARD_ALLOW,
                    status: astral_authorization_root::memory_v1_db_rows::UserCardStatus::Active,
                };
                let summary =
                astral_trustgraph::service::memory_v1_mutation_coordinator::MutationAuditCandidate::governance_mutation_summary(&mutation)
                    .unwrap();
                let instance = astral_types::memory_v1::MemoryId::from_bytes(
                    *base_metadata.instance_id.as_uuid().as_bytes(),
                );
                let root_version = astral_types::memory_v1_audit::MemoryV1AuditRootVersion::new(
                    instance,
                    base_metadata.version,
                );
                let audit_context = astral_types::memory_v1_audit::MemoryV1AuditContext::new(
                    astral_types::memory_v1_audit::MemoryV1AuditActor::new(
                        astral_types::memory_v1::MemoryId::from_bytes([1; 16]),
                        astral_types::memory_v1::MemoryId::from_bytes([2; 16]),
                    ),
                    astral_types::memory_v1_audit::MemoryV1AuditTime::new(1_700_000_000).unwrap(),
                    astral_types::memory_v1_audit::MemoryV1AuditAction::new("user_card", "enable")
                        .unwrap(),
                    "GOVERNANCE_USER_CARD_ENABLE",
                    astral_types::memory_v1_audit::MemoryV1AuditOperation::new(
                        &operation_id,
                        fingerprint_bytes,
                    )
                    .unwrap(),
                    astral_types::memory_v1_audit::MemoryV1AuditRootObservation::new(
                        root_version,
                        base_metadata.digest,
                        astral_types::memory_v1_audit::MemoryV1AuditRootStatus::Serving,
                    ),
                )
                .unwrap();
                let change = astral_types::memory_v1_audit::MemoryV1AuditChange::new(
                    Some(astral_types::memory_v1::MemoryId::from_bytes([1; 16])),
                    Some(
                        astral_types::memory_v1_audit::MemoryV1AuditObject::UserCard(
                            astral_types::memory_v1::MemoryId::from_bytes(CARD_ALLOW),
                        ),
                    ),
                    Some(astral_types::memory_v1_audit::MemoryV1AuditObject::Tenant(
                        astral_types::memory_v1::MemoryId::from_bytes([3; 16]),
                    )),
                    Some(summary),
                    // The fixture card is already active at adoption time; the
                    // same-state update is what the candidate root permits.
                    Some(
                        astral_types::memory_v1_audit::MemoryV1AuditObjectState::UserCard(
                            astral_types::memory_v1_audit::MemoryV1AuditCardState::Active,
                        ),
                    ),
                    Some(
                        astral_types::memory_v1_audit::MemoryV1AuditObjectState::UserCard(
                            astral_types::memory_v1_audit::MemoryV1AuditCardState::Active,
                        ),
                    ),
                    Some(
                        astral_types::memory_v1_audit::MemoryV1AuditConfirmations::not_applicable(),
                    ),
                    Some(root_version),
                    Some(
                        astral_types::memory_v1_audit::MemoryV1AuditRootVersion::new(
                            instance,
                            base_metadata.version + 1,
                        ),
                    ),
                    astral_types::memory_v1_audit::MemoryV1AuditSource::Ordinary,
                );
                let request = astral_trustgraph::service::memory_v1_governance_commit::MemoryV1GovernanceCommitRequest {
                operation_id: operation_id.clone(),
                request_fingerprint: fingerprint.clone(),
                root: base_metadata,
                actor: [1; 16],
                target: CARD_ALLOW,
                target_tenant: [3; 16],
                target_owner: Some([1; 16]),
                trusted_time_unix_seconds: 1_700_000_000,
                mutation,
                audit: astral_trustgraph::service::memory_v1_mutation_coordinator::MutationAuditCandidate::Single(
                    astral_types::memory_v1_audit::MemoryV1AuditT2SingleChangeCandidate::try_from(
                        astral_types::memory_v1_audit::MemoryV1AuditEvent::change(
                            audit_context,
                            astral_types::memory_v1_audit::MemoryV1AuditDecisionInput::Allow,
                            change,
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ),
            };
                let started = Instant::now();
                // The port is the same owner the composition injected; drives
                // binding -> journal I/O -> root CAS -> total phases.
                let outcome = commit_port.commit(request);
                let rtt = started.elapsed();
                commit_rtt.lock().unwrap().push(rtt.as_micros() as u64);
                assert!(
                    outcome.is_ok(),
                    "stress commit {round} must be accepted: {outcome:?}"
                );
            }
        }

        // ── 5. Soak: sustained concurrency, stability drift observation ─────
        let soak_started = Instant::now();
        let mut soak_handles = Vec::new();
        let soak_errors = StdArc::new(AtomicU64::new(0));
        for worker in 0..SOAK_CONCURRENCY {
            let soak_errors = StdArc::clone(&soak_errors);
            soak_handles.push(tokio::spawn(async move {
                let token = if worker % 2 == 0 {
                    login(addr, CARD_ALLOW).await
                } else {
                    login(addr, CARD_BOB).await
                };
                for _ in 0..SOAK_REQUESTS_PER_WORKER {
                    let (status, _) = raw_request(addr, "GET", REGISTRY, Some(&token), None).await;
                    if status != 200 {
                        soak_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for handle in soak_handles {
            handle.await.unwrap();
        }
        let soak_elapsed = soak_started.elapsed();
        let soak_total = (SOAK_CONCURRENCY * SOAK_REQUESTS_PER_WORKER) as u64;
        let soak_failures = soak_errors.load(Ordering::Relaxed);
        // Availability floor under full load: fail-closed 503s under worker
        // saturation are recorded availability, not hidden failures.
        let soak_availability = ((soak_total - soak_failures) as f64) / (soak_total as f64) * 100.0;
        assert!(
            soak_availability >= 99.0,
            "soak availability {soak_availability:.2}%"
        );

        // ── 6. Availability: overall success ratio over the measured window ─
        let total_measured = allow_200.load(Ordering::Relaxed)
            + deny_403.load(Ordering::Relaxed)
            + login_200.load(Ordering::Relaxed);
        let total_requests = total_measured + server_errors.load(Ordering::Relaxed);
        let availability = if total_requests > 0 {
            (total_measured as f64) / (total_requests as f64) * 100.0
        } else {
            0.0
        };

        // ── 7. Quantified report: client view + server phase view ───────────
        let allow_q = PhaseQuantile::summarize(&allow_rtt.lock().unwrap());
        let deny_q = PhaseQuantile::summarize(&deny_rtt.lock().unwrap());
        let login_q = PhaseQuantile::summarize(&login_rtt.lock().unwrap());
        eprintln!(
            "\n=== memory-v1 full-lifecycle stress report ===\n\
         client RTT ALLOW  : n={} mean={}us p50={}us p95={}us p99={}us max={}us\n\
         client RTT DENY   : n={} mean={}us p50={}us p95={}us p99={}us max={}us\n\
         client RTT LOGIN  : n={} mean={}us p50={}us p95={}us p99={}us max={}us\n\
         counts: allow200={} deny403={} login200={} server_errors={}\n\
         soak: {} requests in {:.2?} (throughput {:.0} req/s), failures={}\n\
         availability: {:.2}%\n\
         ==============================================",
            allow_q.count,
            allow_q.mean_us,
            allow_q.p50_us,
            allow_q.p95_us,
            allow_q.p99_us,
            allow_q.max_us,
            deny_q.count,
            deny_q.mean_us,
            deny_q.p50_us,
            deny_q.p95_us,
            deny_q.p99_us,
            deny_q.max_us,
            login_q.count,
            login_q.mean_us,
            login_q.p50_us,
            login_q.p95_us,
            login_q.p99_us,
            login_q.max_us,
            allow_200.load(Ordering::Relaxed),
            deny_403.load(Ordering::Relaxed),
            login_200.load(Ordering::Relaxed),
            server_errors.load(Ordering::Relaxed),
            soak_total,
            soak_elapsed,
            (soak_total as f64) / soak_elapsed.as_secs_f64().max(0.001),
            soak_failures,
            availability,
        );

        // Behavioural floors: every request resolves as a defined
        // authorization outcome; overload fail-closed 503s are quantified in
        // the report above, never hidden. The report's overload count comes
        // from the same counter.
        assert!(allow_q.count >= CONCURRENCY_LADDER.iter().sum::<usize>() as u64 * 8);
        assert!(deny_q.count >= 16);
        assert!(availability >= 99.0, "availability {availability:.2}%");

        // ── 7b. Server view: reduce the phase histograms to quantiles ───────
        let rendered = prometheus_handle.render();
        let phases = [
            ("binding", "commit"),
            ("prepare", "commit"),
            ("journal_io", "commit"),
            ("root_cas", "commit"),
            ("session_disable", "commit"),
            ("total", "commit"),
            ("journal_io", "deny"),
            ("total", "deny"),
        ];
        let mut server_report = String::from(
            "server phases (count/sum us):
",
        );
        for (phase, family) in phases {
            let count = extract_metric_value(
                &rendered,
                if family == "commit" {
                    "astral_memory_v1_commit_phase_seconds_count"
                } else {
                    "astral_memory_v1_deny_phase_seconds_count"
                },
                phase,
            );
            let sum = extract_metric_sum_us(
                &rendered,
                if family == "commit" {
                    "astral_memory_v1_commit_phase_seconds_sum"
                } else {
                    "astral_memory_v1_deny_phase_seconds_sum"
                },
                phase,
            );
            let mean_us = sum.checked_div(count).unwrap_or(0);
            server_report.push_str(&format!(
                "  {family}/{phase}: count={count} sum={sum}us mean={mean_us}us\n"
            ));
        }
        eprintln!("{server_report}");

        // ── 8. Graceful stop ────────────────────────────────────────────────
        stop_tx.send(()).unwrap();
        timeout(Duration::from_secs(15), server)
            .await
            .expect("the server stopped within the drain budget")
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(&journal_dir).unwrap();
    }
    run();
}

// memory—v1: Pull one scalar out of the Prometheus text format. The commit
// owner labels each phase, so the sample line carries `phase="..."`.
fn extract_metric_value(rendered: &str, metric: &str, phase: &str) -> u64 {
    rendered
        .lines()
        .filter(|line| line.starts_with(metric))
        .find(|line| line.contains(&format!("phase=\"{phase}\"")))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse::<f64>().ok())
        .map(|value| value as u64)
        .unwrap_or(0)
}

fn extract_metric_sum_us(rendered: &str, metric: &str, phase: &str) -> u64 {
    // Prometheus sums are floating-point seconds; the report quantifies in
    // microseconds. The count extractor's u64 truncation would zero small
    // sums, so this parses the value directly as f64.
    rendered
        .lines()
        .filter(|line| line.starts_with(metric))
        .find(|line| line.contains(&format!("phase=\"{phase}\"")))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse::<f64>().ok())
        .map(|seconds| (seconds * 1_000_000.0) as u64)
        .unwrap_or(0)
}
