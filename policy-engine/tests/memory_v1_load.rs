//! memory—v1: Offline concurrent evaluator measurement using an isolated test root.
//! This fixture does not establish production adoption or durable authorization.

use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
    IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
    UserCardRow, UserCardStatus, UserRow,
};
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::install_process_root;
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1PendingSource, MemoryV1Request};
use policy_engine::PolicyEngine;

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// memory—v1: One matching pair plus registered nonmatching pairs. Keep the
// policy/result fixed while varying the size of the selected rule version.
fn fixture(rule_count: usize) -> (CandidateRows, Vec<CurrentSelection>) {
    let mut content = String::from(
        r#"{"rules":[{"ruleId":"read","resource":"document","action":"read","effect":"ALLOW"}"#,
    );
    for rule in 1..rule_count {
        use std::fmt::Write as _;
        write!(
            content,
            r#",{{"ruleId":"other-{rule}","resource":"other-{}","action":"read","effect":"DENY"}}"#,
            rule % rule_count.min(128)
        )
        .unwrap();
    }
    content.push_str("]}");
    let content = content.into_bytes();
    let version = vec![1];
    let timestamp = vec![2];
    let input = canonical_version_bytes(&version, &content, &timestamp);
    (
        CandidateRows {
            users: vec![UserRow { user_id: id(1) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            }],
            tenants: vec![TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: id(4),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: id(10),
                owner_tenant_id: id(3),
                current_version_bytes: version.clone(),
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(10),
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                hash_bytes: version_digest(&input),
                hash_input_bytes: input,
            }],
            bindings: vec![BindingRow {
                binding_id: id(20),
                user_card_id: id(4),
                rule_set_id: id(10),
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
                rule_set_id: id(10),
                version_bytes: version.clone(),
                confirmer_user_id: id(1),
                scope_bytes: vec![1],
                operation_id: vec![120],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                confirmation_id: id(220),
                rule_set_id: id(10),
                version_bytes: version.clone(),
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![1],
                operation_id: vec![220],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
        },
        vec![CurrentSelection {
            rule_set_id: id(10),
            version_bytes: version,
        }],
    )
}

// memory—v1: Each sample includes request scope, credential, session and formal evaluation.
fn run_evaluator_load(rule_count: usize) {
    let (rows, selections) = fixture(rule_count);
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 256,
            max_bindings_per_read: 16,
        },
    )
    .unwrap();
    let mut declarations = vec![RegistryDeclaration {
        resource: "document".into(),
        actions: vec!["read".into()],
    }];
    if rule_count > 1 {
        declarations.extend((0..rule_count.min(128)).map(|index| RegistryDeclaration {
            resource: format!("other-{index}"),
            actions: vec!["read".into()],
        }));
    }
    owner.install_registry(&declarations).unwrap();
    owner.adopt_serving_for_isolated_tests().unwrap();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let principal = CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(2)),
        user_card_id: MemoryId::from_bytes(id(4)),
        tenant_id: MemoryId::from_bytes(id(3)),
    };
    let credential = Arc::new(
        authority
            .identity_session_adapter()
            .issue_unchecked_for_test(principal, now() - 60, 3600)
            .unwrap()
            .credential()
            .to_owned(),
    );
    let handle = owner.handle();
    let iterations = std::env::var("MEMORY_V1_LOAD_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20_000)
        .clamp(1_000, 200_000);
    let rounds = std::env::var("MEMORY_V1_LOAD_ROUNDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3)
        .clamp(1, 20);
    // memory—v1: Report exact completed rounds for bounded soak runs.
    for workers in [1, 2, 4, 8, 16] {
        for round in 0..rounds {
            let (ready_tx, ready_rx) = mpsc::channel();
            let mut starts = Vec::with_capacity(workers);
            let mut threads = Vec::with_capacity(workers);
            for _ in 0..workers {
                let ready_tx = ready_tx.clone();
                let (start_tx, start_rx) = mpsc::channel();
                starts.push(start_tx);
                let handle = handle.clone();
                let verifier = authority.verifier();
                let credential = Arc::clone(&credential);
                threads.push(thread::spawn(move || {
                    let engine = PolicyEngine::new();
                    let target_tenant = id(3);
                    let target_owner = id(1);
                    let request = MemoryV1Request {
                        resource: "document",
                        action: "read",
                        target: Some(b"object"),
                        target_tenant: Some(&target_tenant),
                        target_owner: Some(&target_owner),
                        operation_id: b"load-operation",
                        operation_fingerprint: b"load-fingerprint",
                    };
                    let mut counts = [0usize; 3];
                    let mut pending_sources = [0usize; 4];
                    let mut allow_latencies = Vec::with_capacity(iterations);
                    let mut pending_latencies = Vec::with_capacity(iterations);
                    ready_tx.send(()).expect("load coordinator remains active");
                    start_rx
                        .recv_timeout(Duration::from_secs(5))
                        .expect("load coordinator starts each worker");
                    for _ in 0..iterations {
                        let start = Instant::now();
                        let scope = RequestRootScope::new(handle.clone(), Default::default());
                        let root = scope.extension();
                        let session = verifier
                            .verify_and_bind(&credential, now(), &root)
                            .expect("valid test session binds");
                        let result = engine.evaluate_memory_v1(&root, &session, &request);
                        let elapsed_ns = u64::try_from(start.elapsed().as_nanos()).unwrap();
                        match result.decision {
                            MemoryV1Decision::Allow => {
                                assert!(result.admission.is_some());
                                counts[0] += 1;
                                allow_latencies.push(elapsed_ns);
                            }
                            MemoryV1Decision::Deny => {
                                assert!(result.admission.is_none());
                                counts[1] += 1;
                            }
                            MemoryV1Decision::Pending => {
                                assert!(result.admission.is_none());
                                counts[2] += 1;
                                let index = match result.pending_source {
                                    Some(MemoryV1PendingSource::ContextInvalid) => 0,
                                    Some(MemoryV1PendingSource::FenceActive) => 1,
                                    Some(MemoryV1PendingSource::RootUnavailable) => 2,
                                    None => 3,
                                };
                                pending_sources[index] += 1;
                                pending_latencies.push(elapsed_ns);
                            }
                        }
                    }
                    (counts, pending_sources, allow_latencies, pending_latencies)
                }));
            }
            drop(ready_tx);
            for _ in 0..workers {
                ready_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("each load worker becomes ready");
            }
            let start = Instant::now();
            for start_tx in starts {
                start_tx.send(()).expect("load worker remains active");
            }
            let mut counts = [0usize; 3];
            let mut pending_sources = [0usize; 4];
            let mut allow_times = Vec::new();
            let mut pending_times = Vec::new();
            for thread in threads {
                let (part, sources, mut allows, mut pendings) = thread.join().unwrap();
                for (total, count) in counts.iter_mut().zip(part) {
                    *total += count;
                }
                for (total, count) in pending_sources.iter_mut().zip(sources) {
                    *total += count;
                }
                allow_times.append(&mut allows);
                pending_times.append(&mut pendings);
            }
            let elapsed = start.elapsed();
            allow_times.sort_unstable();
            pending_times.sort_unstable();
            let percentile = |times: &[u64], p: usize| {
                times
                    .get((times.len() * p).div_ceil(100).saturating_sub(1))
                    .copied()
                    .unwrap_or_default()
            };
            let operations = counts.iter().sum::<usize>();
            println!(
                "rules={rule_count} workers={workers} round={round} operations={operations} elapsed_ms={} attempts_per_sec={:.2} allow={} deny={} pending={} allow_per_sec={:.2} pending_context_invalid={} pending_fence_active={} pending_root_unavailable={} pending_unclassified={} allow_p50_ns={} allow_p95_ns={} allow_p99_ns={} pending_p50_ns={} pending_p95_ns={} pending_p99_ns={}",
                elapsed.as_millis(), operations as f64 / elapsed.as_secs_f64(),
                counts[0], counts[1], counts[2], counts[0] as f64 / elapsed.as_secs_f64(),
                pending_sources[0], pending_sources[1], pending_sources[2], pending_sources[3],
                percentile(&allow_times, 50), percentile(&allow_times, 95), percentile(&allow_times, 99),
                percentile(&pending_times, 50), percentile(&pending_times, 95), percentile(&pending_times, 99),
            );
            assert_eq!(counts[1], 0, "a valid ALLOW fixture must never be denied");
            assert_eq!(
                counts[2], 0,
                "a healthy read-only ALLOW fixture must not return PENDING"
            );
            assert_eq!(counts[0], iterations * workers);
            assert_eq!(pending_sources.iter().sum::<usize>(), counts[2]);
        }
    }
}

// memory—v1: Child isolation allows a fresh immutable process root per size.
#[test]
#[ignore = "memory-v1 evaluator load; run explicitly with --ignored"]
fn evaluator_concurrency_and_sustained_load() {
    const SIZE_ENV: &str = "ASTRAL_MEMORY_V1_LOAD_CHILD_RULES";
    if let Ok(value) = std::env::var(SIZE_ENV) {
        let size = value.parse::<usize>().unwrap();
        assert!((1..=4096).contains(&size));
        run_evaluator_load(size);
        return;
    }
    for size in [1, 8, 9, 32, 128, 129, 512, 1024] {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "evaluator_concurrency_and_sustained_load",
                "--ignored",
                "--nocapture",
            ])
            .env(SIZE_ENV, size.to_string())
            .status()
            .unwrap();
        assert!(status.success(), "evaluator load failed at {size} rules");
    }
}
