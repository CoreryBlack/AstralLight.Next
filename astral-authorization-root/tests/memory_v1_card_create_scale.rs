//! memory—v1: Measure proposed-card target resolution at bounded card counts.
//!
//! This opt-in experiment uses isolated child processes and an in-memory test root.
//! It measures neither an authorized commit nor durable messaging.

#![cfg(feature = "test-support")]

use std::hint::black_box;
use std::process::Command;
use std::time::Instant;

use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, CandidateRows, IdentityCardRow, TenantRow, UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_root::install_process_root;
use uuid::Uuid;

const CARD_COUNTS: [usize; 3] = [10, 1_000, 3_500];
const WARMUP: usize = 10;
const SAMPLES: usize = 100;
const CHILD_COUNT: &str = "ASTRAL_MEMORY_V1_CARD_CREATE_SCALE_CHILD_COUNT";

// memory—v1: Distinct deterministic IDs keep fixture construction out of measurements.
fn id(value: u64) -> BinaryId {
    (value as u128).to_be_bytes()
}

// memory—v1: Report nearest-rank latency for a sorted, nonempty sample set.
fn percentile(samples: &[u128], percentage: usize) -> u128 {
    samples[(samples.len() * percentage).div_ceil(100) - 1]
}

// memory—v1: Measure the real request-reader validation on one immutable root.
fn measure(count: usize) {
    let rows = CandidateRows {
        users: vec![UserRow { user_id: id(1) }],
        identity_cards: vec![IdentityCardRow {
            identity_card_id: id(2),
            user_id: id(1),
        }],
        tenants: vec![TenantRow {
            tenant_id: id(3),
            parent_tenant_id: None,
        }],
        user_cards: (0..count)
            .map(|index| UserCardRow {
                user_card_id: id(100 + index as u64),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            })
            .collect(),
        ..CandidateRows::default()
    };
    let owner = install_process_root(
        rows,
        vec![],
        CandidateBudget {
            max_table_rows: count + 16,
            max_bindings_per_read: 16,
        },
    )
    .expect("install isolated card fixture");
    let reader = owner
        .handle()
        .begin_request(Uuid::nil())
        .expect("capture fixture root");
    let target = id(1_000_000);
    let resolve = || reader.user_card_create_target(black_box(target), id(1), id(3));
    for _ in 0..WARMUP {
        assert!(resolve().is_ok(), "warmup must resolve the target");
    }
    let mut latencies = Vec::with_capacity(SAMPLES);
    let mut successes = 0;
    let mut failures = 0;
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let result = resolve();
        latencies.push(started.elapsed().as_nanos());
        match black_box(result) {
            Ok(facts) => {
                assert_eq!(facts.user_card_id, target);
                assert_eq!(facts.owner_user_id, id(1));
                assert_eq!(facts.tenant_id, id(3));
                successes += 1;
            }
            Err(_) => failures += 1,
        }
    }
    latencies.sort_unstable();
    println!(
        "cards={count} warmup={WARMUP} samples={SAMPLES} success={successes} failure={failures} p50_ns={} p95_ns={} p99_ns={} max_ns={} outcome=COMPLETE",
        percentile(&latencies, 50),
        percentile(&latencies, 95),
        percentile(&latencies, 99),
        latencies.last().unwrap(),
    );
    assert_eq!(successes, SAMPLES);
    assert_eq!(failures, 0);
}

// memory—v1: The process root is installed once; each size gets its own child.
#[test]
#[ignore = "bounded card-target performance experiment; run without heavy workloads"]
fn user_card_create_target_scale() {
    if let Ok(value) = std::env::var(CHILD_COUNT) {
        let count: usize = value.parse().expect("valid child card count");
        assert!(CARD_COUNTS.contains(&count));
        measure(count);
        return;
    }
    println!("scope=isolated_test clock=Instant unit=ns fixture_and_compilation_excluded=true");
    for count in CARD_COUNTS {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "user_card_create_target_scale",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD_COUNT, count.to_string())
            .output()
            .expect("start isolated card fixture");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.contains("1 passed")
                && stdout.contains("outcome=COMPLETE"),
            "cards={count} child failed\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{stdout}");
    }
}
