//! memory—v1: Execution-only measurements of the experimental candidate root.
//! This does not measure production authorization, database loading or audit.

use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use astral_authorization_root::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetRow, RuleSetVersionRow, TenantRow, UserCardRow, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_hamt_runtime::{
    HamtRuntimeOwner, SelectionChange, VersionChange,
};
use serde_json::json;

// memory—v1: Use table-local deterministic identifiers in generated candidate rows.
fn id(n: u64) -> BinaryId {
    (n as u128).to_be_bytes()
}

// memory—v1: Generate explicitly supplied facts, without asserting their authority.
fn fixture(
    bindings: usize,
    cards: usize,
) -> (CandidateRows, Vec<CurrentSelection>, CandidateBudget) {
    let mut rows = CandidateRows::default();
    rows.tenants.push(TenantRow {
        tenant_id: id(1),
        parent_tenant_id: None,
    });
    for n in 0..cards {
        let user = id(n as u64 + 1);
        rows.users.push(UserRow { user_id: user });
        rows.identity_cards.push(IdentityCardRow {
            identity_card_id: user,
            user_id: user,
        });
        rows.user_cards.push(UserCardRow {
            user_card_id: user,
            user_id: user,
            tenant_id: id(1),
        });
    }
    let mut selections = Vec::new();
    for n in 0..bindings {
        let rule = id(n as u64 + 1);
        rows.rule_sets.push(RuleSetRow {
            rule_set_id: rule,
            owner_tenant_id: id(1),
        });
        rows.rule_set_versions.push(RuleSetVersionRow {
            rule_set_id: rule,
            version_bytes: vec![1],
            content_bytes: vec![1; 64],
            timestamp_bytes: vec![0],
            hash_input_bytes: vec![1],
            hash_bytes: vec![1; 32],
        });
        selections.push(CurrentSelection {
            rule_set_id: rule,
            version_bytes: vec![1],
        });
        for card in 0..cards {
            let binding = id((n * cards + card + 1) as u64);
            rows.bindings.push(BindingRow {
                binding_id: binding,
                user_card_id: id(card as u64 + 1),
                rule_set_id: rule,
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
            });
            rows.binding_confirmations.push(BindingConfirmationRow {
                confirmation_id: binding,
                binding_id: binding,
                rule_set_id: rule,
                version_bytes: vec![1],
                confirmer_user_id: id(card as u64 + 1),
                scope_bytes: vec![],
                operation_id: vec![1],
                confirmed_at_bytes: vec![0],
            });
        }
    }
    let budget = CandidateBudget {
        max_table_rows: 100_000,
        max_bindings_per_read: bindings.max(cards),
    };
    (rows, selections, budget)
}

// memory—v1: Record raw batch nanoseconds and nearest-rank batch-mean percentiles.
fn measure(
    name: &str,
    dimension: usize,
    warmup: usize,
    samples: usize,
    mut operation: impl FnMut(),
) {
    let batch = if name.starts_with("metadata_") {
        256
    } else {
        1
    };
    for _ in 0..warmup * batch {
        operation();
    }
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..batch {
            operation();
        }
        times.push(start.elapsed().as_nanos());
    }
    times.sort_unstable();
    let percentile =
        |p: usize| times[(samples * p).div_ceil(100).saturating_sub(1)] as f64 / batch as f64;
    let total: u128 = times.iter().sum();
    println!(
        "{}",
        json!({"case":name,"dimension":dimension,"warmup_ops":warmup * batch,"samples":samples,"ops_per_sample":batch,"operations":samples * batch,"counter_unit":"ns","elapsed_sum_ns":total,"min_batch_ns":times[0],"max_batch_ns":times[samples-1],"p50_batch_mean_ns_per_op":percentile(50),"p95_batch_mean_ns_per_op":percentile(95),"p99_batch_mean_ns_per_op":percentile(99),"mean_ns_per_op":total as f64 / (samples * batch) as f64,"timing":"batch_mean_includes_clock_and_loop_overhead"})
    );
}

// memory—v1: Time publication separately; prepare and freshness assertions are outside the clock.
fn commit_only(owner: &mut HamtRuntimeOwner, warmup: usize, samples: usize) {
    let handle = owner.handle();
    let mut times = Vec::with_capacity(samples);
    for iteration in 0..warmup + samples {
        let token = handle.token().unwrap();
        let selection = if iteration % 2 == 0 {
            SelectionChange::Clear
        } else {
            SelectionChange::Set(vec![1])
        };
        let prepared = owner
            .prepare(&token, id(1), VersionChange::Keep, selection)
            .unwrap();
        let start = Instant::now();
        let metadata = owner.commit(prepared).unwrap();
        let elapsed = start.elapsed().as_nanos();
        assert_eq!(metadata.version, token.metadata().version + 1);
        assert!(!handle.is_current(&token).unwrap());
        if iteration >= warmup {
            times.push(elapsed);
        }
    }
    times.sort_unstable();
    let percentile = |p: usize| times[(samples * p).div_ceil(100) - 1];
    let total: u128 = times.iter().sum();
    println!(
        "{}",
        json!({"case":"selection_commit_only","samples":samples,"warmup_ops":warmup,"operations":samples,"counter_unit":"ns","elapsed_sum_ns":total,"min_ns":times[0],"max_ns":times[samples - 1],"p50_ns":percentile(50),"p95_ns":percentile(95),"p99_ns":percentile(99),"mean_ns_per_op":total as f64 / samples as f64,"timing":"commit_includes_clock_overhead_preparation_excluded"})
    );
}

// memory—v1: Run fixed reader workloads after threads reach a shared start barrier.
fn readers(owner: &HamtRuntimeOwner, workers: usize, per_worker: usize, samples: usize) {
    for sample in 0..samples.min(10) {
        let barrier = Arc::new(Barrier::new(workers + 1));
        let mut threads = Vec::new();
        for _ in 0..workers {
            let handle = owner.handle();
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..per_worker {
                    let read = handle
                        .read_card(id(1), |context| context.bindings.len())
                        .unwrap();
                    assert_eq!(black_box(read.value), 1);
                }
            }));
        }
        let start = Instant::now();
        barrier.wait();
        for worker in threads {
            worker.join().unwrap();
        }
        let elapsed = start.elapsed().as_nanos();
        let operations = workers * per_worker;
        println!(
            "{}",
            json!({"case":"concurrent_read_card","sample":sample,"workers":workers,"operations":operations,"elapsed_wall_ns":elapsed,"ops_per_second":operations as f64 * 1_000_000_000.0 / elapsed.max(1) as f64,"counter_unit":"ns","timing":"barrier_release_through_thread_join","warmup_ops":0})
        );
    }
}

// memory—v1: Exercise readers against one writer and validate each captured candidate.
fn mixed_read_write(workers: usize, per_worker: usize, writes: usize) {
    let (rows, selections, budget) = fixture(1, 1);
    let mut owner = HamtRuntimeOwner::new(rows, selections, budget).unwrap();
    let barrier = Arc::new(Barrier::new(workers + 1));
    let mut threads = Vec::new();
    for _ in 0..workers {
        let handle = owner.handle();
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            barrier.wait();
            let mut stale = 0;
            for _ in 0..per_worker {
                let read = handle
                    .read_card(id(1), |context| {
                        assert_eq!(context.bindings.len(), 1);
                        let binding = &context.bindings[0];
                        assert_eq!(binding.binding.rule_set_id, id(1));
                        assert_eq!(binding.confirmations.len(), 1);
                        if let Some(version) = binding.selected {
                            assert_eq!(version.version_bytes, [1]);
                        }
                    })
                    .unwrap();
                if !handle.is_current(&read.token).unwrap() {
                    stale += 1;
                }
            }
            stale
        }));
    }
    let handle = owner.handle();
    let start = Instant::now();
    barrier.wait();
    for iteration in 0..writes {
        let token = handle.token().unwrap();
        let selection = if iteration % 2 == 0 {
            SelectionChange::Clear
        } else {
            SelectionChange::Set(vec![1])
        };
        let prepared = owner
            .prepare(&token, id(1), VersionChange::Keep, selection)
            .unwrap();
        owner.commit(prepared).unwrap();
    }
    let stale_reads: usize = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .sum();
    let elapsed = start.elapsed().as_nanos();
    assert_eq!(handle.token().unwrap().metadata().version, writes as u64);
    println!(
        "{}",
        json!({"case":"mixed_read_write","reader_workers":workers,"read_operations":workers * per_worker,"write_operations":writes,"stale_observations":stale_reads,"elapsed_wall_ns":elapsed,"counter_unit":"ns","timing":"barrier_release_through_thread_join","write_timing":"includes_prepare_and_commit","warmup_ops":0})
    );
}

// memory—v1: Measure implemented candidate operations only, never an ALLOW path.
fn main() {
    let samples = std::env::var("MEMORY_V1_BENCH_SAMPLES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200)
        .clamp(10, 10_000);
    let warmup = samples / 10;
    println!(
        "{}",
        json!({"suite":"memory_v1_candidate","scope":"experimental_candidate_not_authorization","clock":"std::time::Instant","counter_unit":"ns","cpu_time":"unavailable","performance_efficiency_cores":"unavailable","build_time_included":false})
    );
    measure("timer_loop_baseline", 0, warmup, samples, || {
        black_box(());
    });
    for count in [1, 8, 32] {
        let (rows, selections, budget) = fixture(count, 1);
        measure(
            "candidate_build",
            count,
            warmup.min(3),
            samples.min(30),
            || {
                let owner =
                    HamtRuntimeOwner::new(rows.clone(), selections.clone(), budget).unwrap();
                black_box(owner.handle().token().unwrap());
            },
        );
        let owner = HamtRuntimeOwner::new(rows, selections, budget).unwrap();
        let handle = owner.handle();
        let token = handle.token().unwrap();
        measure("read_card", count, warmup, samples, || {
            let read = handle.read_card(id(1), |ctx| ctx.bindings.len()).unwrap();
            assert_eq!(black_box(read.value), count);
        });
        measure(
            "read_card_then_metadata_recheck",
            count,
            warmup,
            samples,
            || {
                let read = handle.read_card(id(1), |ctx| ctx.bindings.len()).unwrap();
                assert_eq!(black_box(read.value), count);
                assert!(handle.is_current(&read.token).unwrap());
            },
        );
        measure("metadata_token", count, warmup, samples, || {
            black_box(handle.token().unwrap());
        });
        measure("metadata_is_current", count, warmup, samples, || {
            assert!(black_box(handle.is_current(&token).unwrap()));
        });
    }
    for fanout in [1, 8, 32] {
        let (rows, selections, budget) = fixture(1, fanout);
        let owner = HamtRuntimeOwner::new(rows, selections, budget).unwrap();
        let handle = owner.handle();
        measure("read_impact", fanout, warmup, samples, || {
            let read = handle.read_impact(id(1)).unwrap();
            assert_eq!(black_box(read.value.card_ids.len()), fanout);
        });
    }
    let (rows, selections, budget) = fixture(1, 1);
    let mut owner = HamtRuntimeOwner::new(rows, selections, budget).unwrap();
    let handle = owner.handle();
    let token = handle.token().unwrap();
    measure("selection_prepare_only", 1, warmup, samples, || {
        black_box(
            owner
                .prepare(&token, id(1), VersionChange::Keep, SelectionChange::Clear)
                .unwrap(),
        );
    });
    let prepared = owner
        .prepare(&token, id(1), VersionChange::Keep, SelectionChange::Clear)
        .unwrap();
    owner.commit(prepared).unwrap();
    measure("stale_prepare_rejected", 1, warmup, samples, || {
        assert!(matches!(
            owner.prepare(&token, id(1), VersionChange::Keep, SelectionChange::Clear),
            Err(astral_authorization_root::memory_v1_hamt_runtime::RuntimeError::StaleToken)
        ));
    });
    commit_only(&mut owner, warmup, samples);
    let mut selected = samples.wrapping_add(warmup).is_multiple_of(2);
    measure("selection_prepare_commit", 1, warmup, samples, || {
        let token = handle.token().unwrap();
        let change = if selected {
            SelectionChange::Set(vec![1])
        } else {
            SelectionChange::Clear
        };
        let prepared = owner
            .prepare(&token, id(1), VersionChange::Keep, change)
            .unwrap();
        let metadata = owner.commit(prepared).unwrap();
        assert!(!handle.is_current(&token).unwrap());
        black_box(metadata);
        selected = !selected;
    });
    measure(
        "commit_then_stale_prepare_rejected",
        1,
        warmup,
        samples,
        || {
            let stale = handle.token().unwrap();
            let prepared = owner
                .prepare(&stale, id(1), VersionChange::Keep, SelectionChange::Clear)
                .unwrap();
            owner.commit(prepared).unwrap();
            assert!(matches!(
                owner.prepare(&stale, id(1), VersionChange::Keep, SelectionChange::Clear),
                Err(astral_authorization_root::memory_v1_hamt_runtime::RuntimeError::StaleToken)
            ));
        },
    );
    let (rows, selections, budget) = fixture(1, 1);
    let owner = HamtRuntimeOwner::new(rows, selections, budget).unwrap();
    let max_workers = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(8);
    for workers in [1, 2, 4, 8] {
        if workers <= max_workers {
            readers(&owner, workers, samples * 10, samples);
            mixed_read_write(workers, samples * 10, samples);
        }
    }
}
