//! memory—v1: Offline evaluator read scaling for revoked rule-set change confirmations.
//!
//! Run alone with `cargo test --offline --locked --release -p policy-engine
//! --test memory_v1_change_confirmation_read_scale -- --ignored --nocapture
//! --test-threads=1`, using an isolated `CARGO_TARGET_DIR`. Each history size
//! has a fresh subprocess and process-local root. The measured request includes
//! request-scope construction and destruction, session verification/binding,
//! and the real evaluator; it excludes fixture setup and business handlers.
//! Throughput is single-threaded and includes timing and assertion overhead.

use std::process::Command;
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
    canonical_version_bytes, classify_change_confirmations, version_digest,
    ChangeConfirmationState, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};
use policy_engine::PolicyEngine;

const HISTORIES: [usize; 4] = [0, 100, 1_000, 4_000];
const WARMUP: usize = 20;
const BATCHES: usize = 3;
const REQUESTS_PER_BATCH: usize = 100;
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

// memory—v1: Generate one active change confirmation or one complete revocation tombstone.
fn confirmation(value: u64, revoked: bool) -> RuleSetChangeConfirmationRow {
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

// memory—v1: Keep all facts except same-rule-set, current-version change history fixed.
fn fixture(history: usize) -> (CandidateRows, Vec<CurrentSelection>) {
    let content =
        br#"{"rules":[{"ruleId":"read","resource":"document","action":"read","effect":"ALLOW"}]}"#;
    let version = vec![1];
    let timestamp = vec![2];
    let input = canonical_version_bytes(&version, content, &timestamp);
    let mut confirmations = Vec::with_capacity(history + 1);
    confirmations.push(confirmation(ACTIVE_CONFIRMATION, false));
    confirmations.extend((0..history).map(|n| confirmation(HISTORY_FIRST + n as u64, true)));
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
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: id(120),
                binding_id: id(BINDING),
                rule_set_id: id(RULE_SET),
                version_bytes: version.clone(),
                confirmer_user_id: id(USER),
                scope_bytes: vec![1],
                operation_id: 120_u64.to_be_bytes().to_vec(),
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: confirmations,
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
            max_table_rows: history + 32,
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
            assert_eq!(binding.binding.rule_set_id, id(RULE_SET));
            assert_eq!(binding.selected.unwrap().version_bytes, vec![1]);
            assert_eq!(binding.confirmations.len(), 1);
            let mut actual = binding
                .change_confirmations
                .iter()
                .map(|row| (*row).clone())
                .collect::<Vec<_>>();
            actual.sort_unstable_by_key(|row| row.confirmation_id);
            let mut expected = vec![confirmation(ACTIVE_CONFIRMATION, false)];
            expected.extend((0..history).map(|n| confirmation(HISTORY_FIRST + n as u64, true)));
            expected.sort_unstable_by_key(|row| row.confirmation_id);
            assert_eq!(actual, expected);
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
    let engine = PolicyEngine::new();
    let verifier = authority.verifier();
    let target_tenant = id(TENANT);
    let target_owner = id(USER);
    let request = MemoryV1Request {
        resource: "document",
        action: "read",
        target: Some(b"object"),
        target_tenant: Some(&target_tenant),
        target_owner: Some(&target_owner),
        operation_id: b"confirmation-read-scale",
        operation_fingerprint: b"confirmation-read-scale-fingerprint",
    };
    // The scope stays alive through evaluation and is dropped before the timer stops.
    let evaluate = || {
        let scope = RequestRootScope::new(handle.clone(), Default::default());
        let root = scope.extension();
        let session = verifier
            .verify_and_bind(&credential, now(), &root)
            .expect("verify and bind session");
        let result = engine.evaluate_memory_v1(&root, &session, &request);
        assert_eq!(
            result.decision,
            MemoryV1Decision::Allow,
            "every request must ALLOW"
        );
        assert!(result.admission.is_some(), "ALLOW must include admission");
    };
    let warmup_started = Instant::now();
    for _ in 0..WARMUP {
        evaluate();
    }
    let warmup_ns = warmup_started.elapsed().as_nanos();
    println!("history={history} digest_keys={digest_keys} warmup_requests={WARMUP} warmup_ns={warmup_ns} setup_ns={setup_ns} workers=1 batches={BATCHES} requests_per_batch={REQUESTS_PER_BATCH}");
    let mut all = Vec::with_capacity(BATCHES * REQUESTS_PER_BATCH);
    let mut total_measured = Duration::ZERO;
    for batch in 0..BATCHES {
        let batch_started = Instant::now();
        let mut latencies = Vec::with_capacity(REQUESTS_PER_BATCH);
        for _ in 0..REQUESTS_PER_BATCH {
            let started = Instant::now();
            evaluate();
            latencies.push(started.elapsed().as_nanos());
        }
        let elapsed = batch_started.elapsed();
        total_measured += elapsed;
        latencies.sort_unstable();
        println!("history={history} batch={batch} requests={REQUESTS_PER_BATCH} allow={REQUESTS_PER_BATCH} elapsed_ns={} requests_per_sec={:.2} p50_ns={} p95_ns={} p99_ns={}", elapsed.as_nanos(), REQUESTS_PER_BATCH as f64 / elapsed.as_secs_f64(), percentile(&latencies, 50), percentile(&latencies, 95), percentile(&latencies, 99));
        all.extend(latencies);
    }
    all.sort_unstable();
    println!("history={history} outcome=MEASURED warmup={WARMUP} requests={} allow={} measured_elapsed_ns={} requests_per_sec={:.2} p50_ns={} p95_ns={} p99_ns={} size_execution_ns={}", all.len(), all.len(), total_measured.as_nanos(), all.len() as f64 / total_measured.as_secs_f64(), percentile(&all, 50), percentile(&all, 95), percentile(&all, 99), execution_started.elapsed().as_nanos());
}

#[test]
#[ignore = "offline performance experiment; run explicitly"]
// memory—v1: Isolate each root and bound total test execution with a parent deadline.
fn change_confirmation_read_scale() {
    if let Ok(value) = std::env::var("MEMORY_V1_CHANGE_CONFIRMATION_READ_CHILD") {
        let history = value.parse::<usize>().expect("valid child history");
        assert!(HISTORIES.contains(&history));
        measure(history);
        return;
    }
    let started = Instant::now();
    let mut expired = false;
    let mut skipped = false;
    println!("scope=offline_isolated clock=Instant workers=1 deadline_s={} warmup={WARMUP} measured_requests_per_size={} batches={BATCHES}", DEADLINE.as_secs(), BATCHES * REQUESTS_PER_BATCH);
    for history in HISTORIES {
        // Nine table rows plus one selection are fixed in this fixture.
        if history + 10 > MAX_ROOT_DIGEST_KEYS {
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
                "change_confirmation_read_scale",
                "--nocapture",
            ])
            .env(
                "MEMORY_V1_CHANGE_CONFIRMATION_READ_CHILD",
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
