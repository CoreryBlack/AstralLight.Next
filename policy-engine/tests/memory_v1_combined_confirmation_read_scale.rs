//! memory—v1: Concurrent evaluator scaling with both confirmation histories.
//!
//! Each size runs in a fresh child process. Timed requests include root scope,
//! credential verification, session binding and the actual evaluator; fixture
//! construction, history checks and preflight are outside the timed interval.

use std::process::Command;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_digest::MAX_ROOT_DIGEST_KEYS;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::install_process_root;
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, classify_binding_confirmations, classify_change_confirmations,
    version_digest, BindingConfirmationState, ChangeConfirmationState, MemoryV1OwnerScope,
    MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};
use policy_engine::PolicyEngine;

const HISTORIES: [usize; 4] = [0, 500, 1_000, 2_000];
const WARMUP: usize = 20;
const REQUESTS_PER_WORKER: usize = 2_000;
const DEADLINE: Duration = Duration::from_secs(110);
const USER: u64 = 1;
const IDENTITY: u64 = 2;
const TENANT: u64 = 3;
const CARD: u64 = 4;
const RULE_SET: u64 = 10;
const BINDING: u64 = 20;
const ACTIVE_CONFIRMATION: u64 = 120;
const HISTORY_FIRST: u64 = 1_000;

// memory—v1: Construct deterministic table-local identifiers without collisions.
fn id(value: u64) -> BinaryId {
    (value as u128).to_be_bytes()
}

// memory—v1: Read the same trusted wall clock input as the existing load test.
fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// memory—v1: Generate one active confirmation or one complete revocation tombstone.
fn confirmation(value: u64, revoked: bool) -> BindingConfirmationRow {
    BindingConfirmationRow {
        confirmation_id: id(value),
        binding_id: id(BINDING),
        rule_set_id: id(RULE_SET),
        version_bytes: vec![1],
        confirmer_user_id: id(USER),
        scope_bytes: vec![1],
        operation_id: value.to_be_bytes().to_vec(),
        confirmed_at_bytes: vec![1],
        revoked_at: revoked.then_some(10),
        revoked_by: revoked.then_some(id(USER)),
    }
}

// memory—v1: Generate an independent version-change confirmation history row.
fn change_confirmation(value: u64, revoked: bool) -> RuleSetChangeConfirmationRow {
    RuleSetChangeConfirmationRow {
        confirmation_id: id(value),
        rule_set_id: id(RULE_SET),
        version_bytes: vec![1],
        confirmer_user_id: id(USER),
        affected_scope_bytes: vec![1],
        operation_id: value.to_be_bytes().to_vec(),
        confirmed_at_bytes: vec![1],
        revoked_at: revoked.then_some(10),
        revoked_by: revoked.then_some(id(USER)),
    }
}

// memory—v1: Keep all facts except the two confirmation histories fixed.
fn fixture(history: usize) -> (CandidateRows, Vec<CurrentSelection>) {
    let content =
        br#"{"rules":[{"ruleId":"read","resource":"document","action":"read","effect":"ALLOW"}]}"#;
    let version = vec![1];
    let timestamp = vec![2];
    let input = canonical_version_bytes(&version, content, &timestamp);
    let mut confirmations = Vec::with_capacity(history + 1);
    confirmations.push(confirmation(ACTIVE_CONFIRMATION, false));
    confirmations.extend((0..history).map(|n| confirmation(HISTORY_FIRST + n as u64, true)));
    let mut changes = Vec::with_capacity(history + 1);
    changes.push(change_confirmation(ACTIVE_CONFIRMATION, false));
    changes.extend((0..history).map(|n| change_confirmation(HISTORY_FIRST + n as u64, true)));
    (
        CandidateRows {
            users: vec![UserRow { user_id: id(USER) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(IDENTITY),
                user_id: id(USER),
            }],
            tenants: vec![TenantRow {
                tenant_id: id(TENANT),
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: id(CARD),
                user_id: id(USER),
                tenant_id: id(TENANT),
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: id(RULE_SET),
                owner_tenant_id: id(TENANT),
                current_version_bytes: version.clone(),
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(RULE_SET),
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                hash_bytes: version_digest(&input),
                hash_input_bytes: input,
            }],
            bindings: vec![BindingRow {
                binding_id: id(BINDING),
                user_card_id: id(CARD),
                rule_set_id: id(RULE_SET),
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::SelfUser,
                tenant_scope: MemoryV1TenantScope::SelfTenant,
                removed_at: None,
                removed_by: None,
            }],
            binding_confirmations: confirmations,
            rule_set_change_confirmations: changes,
        },
        vec![CurrentSelection {
            rule_set_id: id(RULE_SET),
            version_bytes: version,
        }],
    )
}

// memory—v1: Return nearest-rank latency in nanoseconds from sorted observations.
fn percentile(sorted: &[u128], percentage: usize) -> u128 {
    sorted[(sorted.len() * percentage).div_ceil(100) - 1]
}

// memory—v1: Run one size on its own root with warmup and independent measured batches.
fn measure(history: usize) {
    let execution_started = Instant::now();
    let setup_started = Instant::now();
    let (rows, selections) = fixture(history);
    let row_count = rows.users.len()
        + rows.identity_cards.len()
        + rows.tenants.len()
        + rows.user_cards.len()
        + rows.rule_sets.len()
        + rows.rule_set_versions.len()
        + rows.bindings.len()
        + rows.binding_confirmations.len()
        + rows.rule_set_change_confirmations.len();
    let digest_keys = row_count + selections.len();
    assert!(digest_keys <= MAX_ROOT_DIGEST_KEYS);
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 2 * history + 32,
            max_bindings_per_read: 1,
        },
    )
    .expect("install candidate root");
    assert_eq!(owner.handle().metadata().unwrap().row_count, row_count);
    owner
        .install_registry(&[RegistryDeclaration {
            resource: "document".into(),
            actions: vec!["read".into()],
        }])
        .expect("install test registry");
    owner
        .adopt_serving_for_isolated_tests()
        .expect("adopt isolated root");
    let authority = MemoryV1SessionAuthority::new();
    authority
        .bind_to_root(&owner)
        .expect("bind session authority");
    let principal = CandidateIdentity {
        user_id: MemoryId::from_bytes(id(USER)),
        identity_card_id: MemoryId::from_bytes(id(IDENTITY)),
        user_card_id: MemoryId::from_bytes(id(CARD)),
        tenant_id: MemoryId::from_bytes(id(TENANT)),
    };
    let credential = authority
        .identity_session_adapter()
        .issue_unchecked_for_test(principal, now() - 60, 3_600)
        .expect("issue isolated test session")
        .credential()
        .to_owned();
    let handle = owner.handle();
    let snapshot = handle
        .begin_request(Default::default())
        .expect("capture root");
    snapshot
        .read_card(id(CARD), |context| {
            assert_eq!(context.bindings.len(), 1);
            let binding = &context.bindings[0];
            assert_eq!(binding.binding.binding_id, id(BINDING));
            let mut actual = binding
                .confirmations
                .iter()
                .map(|row| (*row).clone())
                .collect::<Vec<_>>();
            actual.sort_unstable_by_key(|row| row.confirmation_id);
            let mut expected = vec![confirmation(ACTIVE_CONFIRMATION, false)];
            expected.extend((0..history).map(|n| confirmation(HISTORY_FIRST + n as u64, true)));
            expected.sort_unstable_by_key(|row| row.confirmation_id);
            assert_eq!(actual, expected);
            assert_eq!(
                classify_binding_confirmations(
                    binding.confirmations.iter().copied(),
                    id(BINDING),
                    id(RULE_SET)
                ),
                BindingConfirmationState::Active
            );
            let mut actual_changes = binding
                .change_confirmations
                .iter()
                .map(|row| (*row).clone())
                .collect::<Vec<_>>();
            actual_changes.sort_unstable_by_key(|row| row.confirmation_id);
            let mut expected_changes = vec![change_confirmation(ACTIVE_CONFIRMATION, false)];
            expected_changes
                .extend((0..history).map(|n| change_confirmation(HISTORY_FIRST + n as u64, true)));
            expected_changes.sort_unstable_by_key(|row| row.confirmation_id);
            assert_eq!(actual_changes, expected_changes);
            assert_eq!(
                classify_change_confirmations(
                    binding.change_confirmations.iter().copied(),
                    id(RULE_SET),
                    &[1]
                ),
                ChangeConfirmationState::Active
            );
        })
        .expect("read complete confirmation history");
    snapshot
        .publication_validation_timings_for_test()
        .expect("validate fixture indexes and digest");
    drop(snapshot);
    let setup_ns = setup_started.elapsed().as_nanos();
    let credential = Arc::new(credential);
    for workers in [1, 4, 8, 16] {
        let worker_setup_started = Instant::now();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (results_tx, results_rx) = mpsc::channel();
        let mut starts = Vec::with_capacity(workers);
        let mut threads = Vec::with_capacity(workers);
        for _ in 0..workers {
            let ready_tx = ready_tx.clone();
            let results_tx = results_tx.clone();
            let (start_tx, start_rx) = mpsc::channel();
            starts.push(start_tx);
            let handle = handle.clone();
            let verifier = authority.verifier();
            let credential = Arc::clone(&credential);
            threads.push(thread::spawn(move || {
                let engine = PolicyEngine::new();
                let target_tenant = id(TENANT);
                let target_owner = id(USER);
                let request = MemoryV1Request {
                    resource: "document",
                    action: "read",
                    target: Some(b"object"),
                    target_tenant: Some(&target_tenant),
                    target_owner: Some(&target_owner),
                    operation_id: b"combined-confirmation-read-scale",
                    operation_fingerprint: b"combined-confirmation-read-scale-fingerprint",
                };
                // The scope remains alive through evaluation and drops before timing stops.
                let evaluate = || {
                    let scope = RequestRootScope::new(handle.clone(), Default::default());
                    let root = scope.extension();
                    let session = verifier
                        .verify_and_bind(&credential, now(), &root)
                        .expect("verify and bind session");
                    let result = engine.evaluate_memory_v1(&root, &session, &request);
                    assert_eq!(result.decision, MemoryV1Decision::Allow);
                    assert!(result.admission.is_some(), "ALLOW must include admission");
                };
                for _ in 0..WARMUP {
                    evaluate();
                }
                let mut latencies = Vec::with_capacity(REQUESTS_PER_WORKER);
                ready_tx.send(()).expect("coordinator remains active");
                start_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("coordinator starts worker");
                for _ in 0..REQUESTS_PER_WORKER {
                    let started = Instant::now();
                    evaluate();
                    latencies.push(started.elapsed().as_nanos());
                }
                let completed = Instant::now();
                results_tx
                    .send((completed, latencies))
                    .expect("coordinator receives measurements");
            }));
        }
        drop(ready_tx);
        drop(results_tx);
        for _ in 0..workers {
            ready_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("each warmed worker is ready");
        }
        let worker_setup_ns = worker_setup_started.elapsed().as_nanos();
        let started = Instant::now();
        for start in starts {
            start.send(()).expect("worker remains active");
        }
        let mut completed = started;
        let mut latencies = Vec::with_capacity(workers * REQUESTS_PER_WORKER);
        for _ in 0..workers {
            let (finished, samples) = results_rx
                .recv_timeout(DEADLINE)
                .expect("each worker reports measurements");
            completed = completed.max(finished);
            latencies.extend(samples);
        }
        for worker in threads {
            worker.join().expect("worker completed without panic");
        }
        let elapsed = completed.duration_since(started);
        assert_eq!(latencies.len(), workers * REQUESTS_PER_WORKER);
        latencies.sort_unstable();
        println!("history_per_kind={history} digest_keys={digest_keys} workers={workers} warmup_per_worker={WARMUP} worker_setup_and_warmup_ns={worker_setup_ns} requests={} allow={} measured_elapsed_ns={} requests_per_sec={:.2} p50_ns={} p95_ns={} p99_ns={} fixture_setup_ns={setup_ns} outcome=MEASURED", latencies.len(), latencies.len(), elapsed.as_nanos(), latencies.len() as f64 / elapsed.as_secs_f64(), percentile(&latencies, 50), percentile(&latencies, 95), percentile(&latencies, 99));
    }
    println!(
        "history_per_kind={history} size_execution_ns={} outcome=COMPLETE",
        execution_started.elapsed().as_nanos()
    );
}

#[test]
#[ignore = "offline performance experiment; run explicitly"]
// memory—v1: Isolate each root and bound total test execution with a parent deadline.
fn combined_confirmation_read_scale() {
    if let Ok(value) = std::env::var("MEMORY_V1_COMBINED_CONFIRMATION_READ_CHILD") {
        let history = value.parse::<usize>().expect("valid child history");
        assert!(HISTORIES.contains(&history));
        measure(history);
        return;
    }
    let started = Instant::now();
    let mut expired = false;
    let mut skipped = false;
    println!("scope=offline_isolated clock=Instant workers=1,4,8,16 deadline_s={} warmup_per_worker={WARMUP} measured_requests_per_worker={REQUESTS_PER_WORKER}", DEADLINE.as_secs());
    for history in HISTORIES {
        // Nine table rows plus one selection are fixed in this fixture.
        if 2 * history + 10 > MAX_ROOT_DIGEST_KEYS {
            skipped = true;
            println!("history={history} outcome=SKIP_DIGEST_KEY_LIMIT");
            continue;
        }
        if expired || started.elapsed() >= DEADLINE {
            expired = true;
            skipped = true;
            println!("history={history} outcome=SKIP_EXECUTION_TIME_LIMIT");
            continue;
        }
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "--ignored",
                "--exact",
                "combined_confirmation_read_scale",
                "--nocapture",
            ])
            .env(
                "MEMORY_V1_COMBINED_CONFIRMATION_READ_CHILD",
                history.to_string(),
            )
            .spawn()
            .expect("start isolated size process");
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                assert!(status.success(), "history={history} child failed: {status}");
                break;
            }
            if started.elapsed() >= DEADLINE {
                child.kill().expect("stop overdue child");
                child.wait().expect("reap overdue child");
                expired = true;
                skipped = true;
                println!("history={history} outcome=SKIP_EXECUTION_TIME_LIMIT");
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    println!(
        "total_execution_ns={} outcome={}",
        started.elapsed().as_nanos(),
        if skipped { "SKIP" } else { "COMPLETE" }
    );
}
