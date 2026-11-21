//! memory—v1: bounded mixed read/write authorization coverage over the real
//! `PolicyEngine::evaluate_memory_v1` entry point.
//!
//! This test-support fixture uses no listener, service, container or database.
//! It does not establish production adoption or durable authorization.

use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc, OnceLock,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_fence::FenceDeclaration;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::{RequestRootExtension, RequestRootScope};
use astral_authorization_root::memory_v1_root::{RootHandle, RootOwner};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session::RequestSessionExtension;
use astral_authorization_root::memory_v1_session_authority::{
    MemoryV1SessionAuthority, MemoryV1SessionAuthorityError, MemoryV1SessionVerifier,
};
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::{
    MemoryV1Decision, MemoryV1Evaluation, MemoryV1PendingSource, MemoryV1Request,
};
use policy_engine::PolicyEngine;

const TARGET_RULE_SET: [u8; 16] = [10; 16];
const UNRELATED_RULE_SET: [u8; 16] = [11; 16];
const USER_ID: [u8; 16] = [1; 16];
const IDENTITY_CARD_ID: [u8; 16] = [2; 16];
const TENANT_ID: [u8; 16] = [3; 16];
const USER_CARD_ID: [u8; 16] = [4; 16];
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

struct Fixture {
    owner: RootOwner,
    authority: MemoryV1SessionAuthority,
}

// memory—v1: One test-support root and one bound session authority per test binary.
static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock is after unix epoch")
            .as_secs(),
    )
    .expect("test clock fits in i64")
}

// memory—v1: Both rule sets share the fixture's immutable root and fence table.
fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| {
        let content =
            br#"{"rules":[{"ruleId":"read","resource":"document","action":"read","effect":"ALLOW"}]}"#;
        let version = vec![1];
        let timestamp = vec![2];
        let hash_input = canonical_version_bytes(&version, content, &timestamp);
        let rows = CandidateRows {
            users: vec![UserRow { user_id: USER_ID }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: IDENTITY_CARD_ID,
                user_id: USER_ID,
            }],
            tenants: vec![TenantRow {
                tenant_id: TENANT_ID,
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: USER_CARD_ID,
                user_id: USER_ID,
                tenant_id: TENANT_ID,
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![
                RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: TARGET_RULE_SET,
                    owner_tenant_id: TENANT_ID,
                    current_version_bytes: version.clone(),
                },
                RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: UNRELATED_RULE_SET,
                    owner_tenant_id: TENANT_ID,
                    current_version_bytes: version.clone(),
                },
            ],
            rule_set_versions: vec![
                RuleSetVersionRow {
                    rule_set_id: TARGET_RULE_SET,
                    version_bytes: version.clone(),
                    content_bytes: content.to_vec(),
                    timestamp_bytes: timestamp.clone(),
                    hash_bytes: version_digest(&hash_input),
                    hash_input_bytes: hash_input.clone(),
                },
                RuleSetVersionRow {
                    rule_set_id: UNRELATED_RULE_SET,
                    version_bytes: version.clone(),
                    content_bytes: content.to_vec(),
                    timestamp_bytes: timestamp.clone(),
                    hash_bytes: version_digest(&hash_input),
                    hash_input_bytes: hash_input,
                },
            ],
            bindings: vec![BindingRow {
                binding_id: id(20),
                user_card_id: USER_CARD_ID,
                rule_set_id: TARGET_RULE_SET,
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::SelfUser,
                tenant_scope: MemoryV1TenantScope::SelfTenant,
                removed_at: None,
                removed_by: None,
            }],
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: id(120),
                binding_id: id(20),
                rule_set_id: TARGET_RULE_SET,
                version_bytes: version.clone(),
                confirmer_user_id: USER_ID,
                scope_bytes: vec![1],
                operation_id: vec![120],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: vec![
                RuleSetChangeConfirmationRow {
                    confirmation_id: id(220),
                    rule_set_id: TARGET_RULE_SET,
                    version_bytes: version.clone(),
                    confirmer_user_id: USER_ID,
                    affected_scope_bytes: vec![1],
                    operation_id: vec![220],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
                RuleSetChangeConfirmationRow {
                    confirmation_id: id(221),
                    rule_set_id: UNRELATED_RULE_SET,
                    version_bytes: version.clone(),
                    confirmer_user_id: USER_ID,
                    affected_scope_bytes: vec![1],
                    operation_id: vec![221],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
            ],
        };
        let owner = astral_authorization_root::memory_v1_root::install_process_root(
            rows,
            vec![
                CurrentSelection {
                    rule_set_id: TARGET_RULE_SET,
                    version_bytes: version.clone(),
                },
                CurrentSelection {
                    rule_set_id: UNRELATED_RULE_SET,
                    version_bytes: version,
                },
            ],
            CandidateBudget {
                max_table_rows: 256,
                max_bindings_per_read: 16,
            },
        )
        .expect("memory-v1 test root installs");
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .expect("memory-v1 test registry installs");
        owner
            .adopt_serving_for_isolated_tests()
            .expect("memory-v1 test root becomes serving");
        let authority = MemoryV1SessionAuthority::new();
        authority
            .bind_to_root(&owner)
            .expect("memory-v1 session authority binds to root");
        Fixture { owner, authority }
    })
}

fn principal() -> CandidateIdentity {
    CandidateIdentity {
        user_id: MemoryId::from_bytes(USER_ID),
        identity_card_id: MemoryId::from_bytes(IDENTITY_CARD_ID),
        user_card_id: MemoryId::from_bytes(USER_CARD_ID),
        tenant_id: MemoryId::from_bytes(TENANT_ID),
    }
}

fn request(target_owner: &[u8; 16]) -> MemoryV1Request<'_> {
    MemoryV1Request {
        resource: "document",
        action: "read",
        target: Some(b"object"),
        target_tenant: Some(&TENANT_ID),
        target_owner: Some(target_owner),
        operation_id: b"memory-v1-mixed-load",
        operation_fingerprint: b"memory-v1-mixed-load-fingerprint",
    }
}

fn bind_session(
    authority: &MemoryV1SessionAuthority,
    root: &RequestRootExtension,
) -> (String, RequestSessionExtension) {
    let issued = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal(), now() - 60, 3_600)
        .expect("memory-v1 test session issues");
    let credential = issued.credential().to_owned();
    let session = authority
        .verifier()
        .verify_and_bind(issued.credential(), now(), root)
        .expect("memory-v1 test session binds");
    (credential, session)
}

fn evaluate_once(
    engine: &PolicyEngine,
    handle: &RootHandle,
    verifier: &MemoryV1SessionVerifier,
    credential: &str,
    target_owner: [u8; 16],
) -> MemoryV1Evaluation {
    let scope = RequestRootScope::new(handle.clone(), Default::default());
    let root = scope.extension();
    let session = verifier
        .verify_and_bind(credential, now(), &root)
        .expect("live memory-v1 test session verifies");
    engine.evaluate_memory_v1(&root, &session, &request(&target_owner))
}

fn declaration(owner: &RootOwner) -> FenceDeclaration {
    let metadata = owner
        .handle()
        .metadata()
        .expect("memory-v1 test root metadata is readable");
    FenceDeclaration {
        rule_set_version: vec![1],
        root_version: metadata.version,
        digest: metadata.digest,
    }
}

fn assert_allow(result: &MemoryV1Evaluation) {
    assert_eq!(result.decision, MemoryV1Decision::Allow);
    assert!(result.admission.is_some());
    assert!(result.deny_source.is_none());
    assert!(result.pending_source.is_none());
}

fn assert_pending_fence(result: &MemoryV1Evaluation) {
    assert_eq!(result.decision, MemoryV1Decision::Pending);
    assert_eq!(
        result.pending_source,
        Some(MemoryV1PendingSource::FenceActive)
    );
    assert!(result.admission.is_none());
    assert!(result.deny_source.is_none());
}

// memory—v1: Stable fence and revoke observations are checked in explicit order.
#[test]
fn memory_v1_fence_and_session_controls_are_deterministic() {
    let fixture = fixture();
    let scope = RequestRootScope::new(fixture.owner.handle(), Default::default());
    let root = scope.extension();
    let (credential, session) = bind_session(&fixture.authority, &root);
    let engine = PolicyEngine::new();
    let target_owner = USER_ID;
    assert_allow(&engine.evaluate_memory_v1(&root, &session, &request(&target_owner)));

    fixture
        .owner
        .begin_modification_fence(TARGET_RULE_SET, &declaration(&fixture.owner))
        .unwrap();
    assert_pending_fence(&engine.evaluate_memory_v1(&root, &session, &request(&target_owner)));
    fixture
        .owner
        .abort_modification_fence(TARGET_RULE_SET)
        .unwrap();
    let held = engine.evaluate_memory_v1(&root, &session, &request(&target_owner));
    assert_eq!(held.decision, MemoryV1Decision::Pending);
    assert!(held.admission.is_none());
    let fresh_scope = RequestRootScope::new(fixture.owner.handle(), Default::default());
    let root = fresh_scope.extension();
    let session = fixture
        .authority
        .verifier()
        .verify_and_bind(&credential, now(), &root)
        .unwrap();
    assert_allow(&engine.evaluate_memory_v1(&root, &session, &request(&target_owner)));

    fixture
        .owner
        .begin_modification_fence(UNRELATED_RULE_SET, &declaration(&fixture.owner))
        .unwrap();
    assert_allow(&engine.evaluate_memory_v1(&root, &session, &request(&target_owner)));
    fixture
        .owner
        .abort_modification_fence(UNRELATED_RULE_SET)
        .unwrap();

    fixture
        .authority
        .identity_session_adapter()
        .revoke(&credential)
        .unwrap();
    let revoked = engine.evaluate_memory_v1(&root, &session, &request(&target_owner));
    assert_ne!(revoked.decision, MemoryV1Decision::Allow);
    assert!(revoked.admission.is_none());
    assert_eq!(
        fixture.authority.verifier().verify(&credential, now()),
        Err(MemoryV1SessionAuthorityError::Revoked)
    );
}

#[derive(Debug)]
struct ReaderReport {
    counts: [usize; 3],
    pending_sources: [usize; 4],
    pending_targets: [usize; 2],
    sampled_latencies_ns: [Vec<u64>; 3],
    concurrent_counts: [usize; 3],
}

#[derive(Debug)]
struct WriterReport {
    cycles: usize,
    latencies_ns: Vec<u64>,
    writes_with_active_readers: usize,
}

// memory—v1: Reader and writer workloads are finite and opt-in.
#[test]
#[ignore = "bounded memory-v1 mixed load; run explicitly with --ignored"]
fn memory_v1_mixed_load() {
    let fixture = fixture();
    let configured = |name: &str, default: usize, min: usize, max: usize| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
            .clamp(min, max)
    };
    let readers = configured("MEMORY_V1_MIXED_LOAD_READERS", 8, 1, 32);
    let iterations = configured(
        "MEMORY_V1_MIXED_LOAD_READER_ITERATIONS",
        20_000,
        1_000,
        100_000,
    );
    let cycles = configured("MEMORY_V1_MIXED_LOAD_WRITER_CYCLES", 2_000, 100, 20_000);
    let fence_mode = std::env::var("MEMORY_V1_MIXED_LOAD_FENCE_MODE")
        .unwrap_or_else(|_| "alternating".to_owned());
    assert!(matches!(
        fence_mode.as_str(),
        "alternating" | "target" | "unrelated"
    ));
    let handle = fixture.owner.handle();
    let verifier = fixture.authority.verifier();
    let credential = Arc::new(
        fixture
            .authority
            .identity_session_adapter()
            .issue_unchecked_for_test(principal(), now() - 60, 3_600)
            .expect("mixed-load session issues")
            .credential()
            .to_owned(),
    );
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let (writer_done_tx, writer_done_rx) = mpsc::channel();
    let mut starts = Vec::with_capacity(readers);
    let mut handles = Vec::with_capacity(readers);
    let active = Arc::new(AtomicUsize::new(0));
    let writer_active = Arc::new(AtomicBool::new(false));
    let writer_go = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));
    let observed_concurrent = Arc::new(AtomicUsize::new(0));
    let deadline = Instant::now() + Duration::from_secs(60);

    for _ in 0..readers {
        let handle = handle.clone();
        let verifier = verifier.clone();
        let credential = Arc::clone(&credential);
        let active = Arc::clone(&active);
        let writer_active = Arc::clone(&writer_active);
        let writer_go = Arc::clone(&writer_go);
        let cancel = Arc::clone(&cancel);
        let observed_concurrent = Arc::clone(&observed_concurrent);
        let ready_tx = ready_tx.clone();
        let done_tx = done_tx.clone();
        let (start_tx, start_rx) = mpsc::channel();
        starts.push(start_tx);
        handles.push(thread::spawn(move || {
            let engine = PolicyEngine::new();
            ready_tx.send(()).unwrap();
            if start_rx.recv_timeout(CONTROL_TIMEOUT).is_err() {
                return;
            }
            active.fetch_add(1, Ordering::SeqCst);
            while !writer_go.load(Ordering::SeqCst)
                && !cancel.load(Ordering::Relaxed)
                && Instant::now() < deadline
            {
                thread::yield_now();
            }
            let mut report = ReaderReport {
                counts: [0; 3],
                pending_sources: [0; 4],
                pending_targets: [0; 2],
                sampled_latencies_ns: std::array::from_fn(|_| Vec::new()),
                concurrent_counts: [0; 3],
            };
            for iteration in 0..iterations {
                if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
                    break;
                }
                let during_writes = writer_active.load(Ordering::SeqCst);
                let owner = if iteration % 2 == 0 { USER_ID } else { id(2) };
                let sampled_start = (iteration % 64 < 2).then(Instant::now);
                let result = evaluate_once(&engine, &handle, &verifier, &credential, owner);
                let sampled_elapsed = sampled_start
                    .map(|started| u64::try_from(started.elapsed().as_nanos()).unwrap());
                let decision_index = match result.decision {
                    MemoryV1Decision::Allow => {
                        assert_eq!(owner, USER_ID, "unexpected ALLOW for another owner");
                        assert!(result.admission.is_some());
                        0
                    }
                    MemoryV1Decision::Deny => {
                        assert_eq!(owner, id(2), "valid owner must not be denied");
                        assert!(result.admission.is_none());
                        1
                    }
                    MemoryV1Decision::Pending => {
                        assert!(result.admission.is_none());
                        let source_index = match result.pending_source {
                            Some(MemoryV1PendingSource::ContextInvalid) => 0,
                            Some(MemoryV1PendingSource::FenceActive) => 1,
                            Some(MemoryV1PendingSource::RootUnavailable) => 2,
                            None => 3,
                        };
                        report.pending_sources[source_index] += 1;
                        report.pending_targets[usize::from(owner != USER_ID)] += 1;
                        2
                    }
                };
                report.counts[decision_index] += 1;
                if let Some(elapsed_ns) = sampled_elapsed {
                    report.sampled_latencies_ns[decision_index].push(elapsed_ns);
                }
                if during_writes && writer_active.load(Ordering::SeqCst) {
                    report.concurrent_counts[decision_index] += 1;
                    observed_concurrent.fetch_add(1, Ordering::SeqCst);
                }
            }
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = done_tx.send(report);
        }));
    }
    drop(ready_tx);
    drop(done_tx);
    for _ in 0..readers {
        ready_rx
            .recv_timeout(CONTROL_TIMEOUT)
            .expect("reader becomes ready");
    }

    let writer_active_flag = Arc::clone(&writer_active);
    let writer_go_flag = Arc::clone(&writer_go);
    let writer_cancel = Arc::clone(&cancel);
    let writer_readers = Arc::clone(&active);
    let writer_observed = Arc::clone(&observed_concurrent);
    let writer_mode = fence_mode.clone();
    let owner = &fixture.owner;
    let writer = thread::spawn(move || {
        while writer_readers.load(Ordering::SeqCst) != readers {
            if writer_cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
                return;
            }
            thread::yield_now();
        }
        writer_active_flag.store(true, Ordering::SeqCst);
        writer_go_flag.store(true, Ordering::SeqCst);
        let mut report = WriterReport {
            cycles: 0,
            latencies_ns: Vec::with_capacity(cycles),
            writes_with_active_readers: 0,
        };
        while report.cycles < cycles || writer_observed.load(Ordering::SeqCst) == 0 {
            if report.cycles >= cycles + 1_000
                || writer_cancel.load(Ordering::Relaxed)
                || Instant::now() >= deadline
            {
                break;
            }
            let rule_set = match writer_mode.as_str() {
                "target" => TARGET_RULE_SET,
                "unrelated" => UNRELATED_RULE_SET,
                _ if report.cycles.is_multiple_of(2) => TARGET_RULE_SET,
                _ => UNRELATED_RULE_SET,
            };
            let started = Instant::now();
            owner
                .begin_modification_fence(rule_set, &declaration(owner))
                .expect("mixed-load fence opens");
            owner
                .abort_modification_fence(rule_set)
                .expect("mixed-load fence closes");
            report
                .latencies_ns
                .push(u64::try_from(started.elapsed().as_nanos()).unwrap());
            report.writes_with_active_readers +=
                usize::from(writer_readers.load(Ordering::SeqCst) > 0);
            report.cycles += 1;
        }
        writer_active_flag.store(false, Ordering::SeqCst);
        let _ = writer_done_tx.send(report);
    });

    let started = Instant::now();
    for start in starts {
        start.send(()).expect("reader remains ready");
    }
    let mut total = [0usize; 3];
    let mut pending_sources = [0usize; 4];
    let mut pending_targets = [0usize; 2];
    let mut sampled_latencies_ns: [Vec<u64>; 3] = std::array::from_fn(|_| Vec::new());
    let mut concurrent_counts = [0usize; 3];
    let mut reports = 0usize;
    while reports < readers {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match done_rx.recv_timeout(remaining) {
            Ok(report) => {
                for (total, part) in total.iter_mut().zip(report.counts) {
                    *total += part;
                }
                for (total, part) in pending_sources.iter_mut().zip(report.pending_sources) {
                    *total += part;
                }
                for (total, part) in pending_targets.iter_mut().zip(report.pending_targets) {
                    *total += part;
                }
                for (total, mut part) in sampled_latencies_ns
                    .iter_mut()
                    .zip(report.sampled_latencies_ns)
                {
                    total.append(&mut part);
                }
                for (total, part) in concurrent_counts.iter_mut().zip(report.concurrent_counts) {
                    *total += part;
                }
                reports += 1;
            }
            Err(_) => break,
        }
    }
    let writer_report = deadline
        .checked_duration_since(Instant::now())
        .and_then(|remaining| writer_done_rx.recv_timeout(remaining).ok());
    if reports != readers || writer_report.is_none() {
        cancel.store(true, Ordering::SeqCst);
        panic!("mixed-load worker failed or exceeded its deadline: readers={reports}/{readers}, writer_reported={}", writer_report.is_some());
    }
    let mut report = writer_report.unwrap();
    writer.join().expect("mixed-load writer joins");
    for handle in handles {
        handle.join().expect("mixed-load reader joins");
    }
    let elapsed = started.elapsed();
    assert_eq!(total.iter().sum::<usize>(), readers * iterations);
    assert_eq!(pending_sources.iter().sum::<usize>(), total[2]);
    assert_eq!(pending_targets.iter().sum::<usize>(), total[2]);
    assert!(report.cycles >= cycles && report.writes_with_active_readers > 0);
    assert_eq!(report.latencies_ns.len(), report.cycles);
    assert!(
        concurrent_counts.iter().sum::<usize>() > 0,
        "reader evaluations must occur during the writer phase"
    );
    assert!(total[0] > 0 && total[1] > 0);
    for latencies in &mut sampled_latencies_ns {
        latencies.sort_unstable();
    }
    report.latencies_ns.sort_unstable();
    let percentile = |times: &[u64], p: usize| {
        times
            .get((times.len() * p).div_ceil(100).saturating_sub(1))
            .copied()
            .unwrap_or_default()
    };
    println!("memory—v1 mixed_load fence_mode={fence_mode} readers={readers} iterations={iterations} elapsed_ms={} reads={} attempts_per_sec={:.2} allow={} deny={} pending={} pending_context_invalid={} pending_fence_active={} pending_root_unavailable={} pending_unclassified={} pending_valid_owner={} pending_other_owner={} concurrent_allow={} concurrent_deny={} concurrent_pending={} writes={} writes_with_active_readers={} write_p50_ns={} write_p95_ns={} write_p99_ns={} write_max_ns={} allow_samples={} allow_p99_ns={} deny_samples={} deny_p99_ns={} pending_samples={} pending_p99_ns={}", elapsed.as_millis(), total.iter().sum::<usize>(), total.iter().sum::<usize>() as f64 / elapsed.as_secs_f64(), total[0], total[1], total[2], pending_sources[0], pending_sources[1], pending_sources[2], pending_sources[3], pending_targets[0], pending_targets[1], concurrent_counts[0], concurrent_counts[1], concurrent_counts[2], report.cycles, report.writes_with_active_readers, percentile(&report.latencies_ns, 50), percentile(&report.latencies_ns, 95), percentile(&report.latencies_ns, 99), report.latencies_ns.last().copied().unwrap_or_default(), sampled_latencies_ns[0].len(), percentile(&sampled_latencies_ns[0], 99), sampled_latencies_ns[1].len(), percentile(&sampled_latencies_ns[1], 99), sampled_latencies_ns[2].len(), percentile(&sampled_latencies_ns[2], 99));
}
