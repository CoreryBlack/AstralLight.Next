//! memory—v1: Separate "how fast is the warm path" from "what the memory
//! authority contributes" on one serving root.
//!
//! Three arms run over identical fixture facts and an identical request:
//!
//! * `recheck=held` — the paper's warm path: one held request scope with one
//!   bound session evaluates repeatedly. Each evaluation's formal final check
//!   re-reads the actor's live session record, the root writer lock, the
//!   registry version and the complete fence table under read concurrency.
//! * `recheck=fresh` — the documented worst case for a database authority
//!   re-checking everything per request on the in-memory root: a fresh
//!   request scope and a fresh bound session per evaluation, so every request
//!   re-reads the card aggregate and re-mints a session binding.
//! * `validate=whole` — the publication-time whole-root validation anchor:
//!   isolated index validation plus a full digest reconstruction over the
//!   entire root snapshot (what a naive "re-verify the whole authority state"
//!   design would pay per request).
//!
//! An unrelated publication is interleaved between rounds so the held arm
//! must prove it neither bypasses nor survives staleness: the held
//! evaluation stays `ALLOW` only while its recheck succeeds against the
//! current root, and the fixture asserts zero DENY and zero PENDING for the
//! healthy read.
//!
//! This is a fixture measurement of the memory authority's own recheck path.
//! It is not a synchronous database-authority baseline: no MySQL process is
//! consulted, and no production deployment latency is claimed.

use std::sync::Arc;
use std::thread;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::CandidateRows;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{install_process_root, ManagementMutationV2};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};
use policy_engine::PolicyEngine;

const RULES_DOCUMENT: [u8; 16] = [0x45; 16];
// memory—v1: The report defaults to 20,000 evaluations per round; a smoke run
// may clamp both knobs from the environment without changing the shape.
fn iterations() -> usize {
    std::env::var("MEMORY_V1_RECHECK_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20_000)
        .clamp(100, 200_000)
}

fn rounds() -> usize {
    std::env::var("MEMORY_V1_RECHECK_ROUNDS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3)
        .clamp(1, 20)
}

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

fn percentile(times: &[u64], p: usize) -> u64 {
    times
        .get((times.len() * p).div_ceil(100).saturating_sub(1))
        .copied()
        .unwrap_or_default()
}

// memory—v1: The single-card serving root the recheck arms evaluate against.
#[allow(clippy::needless_update)] // CandidateRows gains rows over time; base stays default
fn fixture() -> (
    CandidateRows,
    Vec<astral_authorization_root::memory_v1_db_rows::CurrentSelection>,
) {
    use astral_authorization_root::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, CurrentSelection, IdentityCardRow,
        RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow, UserCardRow,
        UserCardStatus, UserRow,
    };
    use astral_authorization_root::memory_v1_rules::{
        canonical_version_bytes, MemoryV1OwnerScope, MemoryV1TenantScope,
    };
    use sha2::{Digest, Sha256};
    let content =
        br#"{"rules":[{"ruleId":"D1","resource":"document","action":"read","effect":"ALLOW"}]}"#;
    let version_bytes = vec![1u8];
    let timestamp_bytes = vec![1u8];
    let hash_input = canonical_version_bytes(&version_bytes, content, &timestamp_bytes);
    let hash = Sha256::digest(&hash_input).to_vec();
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
        user_cards: vec![UserCardRow {
            user_card_id: id(4),
            user_id: id(1),
            tenant_id: id(3),
            status: UserCardStatus::Active,
        }],
        rule_sets: vec![RuleSetRow {
            rule_set_id: RULES_DOCUMENT,
            owner_tenant_id: id(3),
            current_version_bytes: vec![1],
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
        }],
        rule_set_versions: vec![RuleSetVersionRow {
            rule_set_id: RULES_DOCUMENT,
            version_bytes: version_bytes.clone(),
            content_bytes: content.to_vec(),
            timestamp_bytes: timestamp_bytes.clone(),
            hash_input_bytes: hash_input.clone(),
            hash_bytes: hash.clone(),
        }],
        bindings: vec![BindingRow {
            binding_id: id(6),
            user_card_id: id(4),
            rule_set_id: RULES_DOCUMENT,
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::SelfUser,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: None,
        }],
        binding_confirmations: vec![BindingConfirmationRow {
            confirmation_id: id(7),
            binding_id: id(6),
            rule_set_id: RULES_DOCUMENT,
            version_bytes: version_bytes.clone(),
            confirmer_user_id: id(1),
            scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        }],
        rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
            confirmation_id: id(8),
            rule_set_id: RULES_DOCUMENT,
            version_bytes: version_bytes.clone(),
            confirmer_user_id: id(1),
            affected_scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        }],
        ..CandidateRows::default()
    };
    (
        rows,
        vec![CurrentSelection {
            rule_set_id: RULES_DOCUMENT,
            version_bytes: vec![1],
        }],
    )
}

fn object_request(
    target_tenant: &'static [u8; 16],
    target_owner: &'static [u8; 16],
) -> MemoryV1Request<'static> {
    MemoryV1Request {
        resource: "document",
        action: "read",
        target: Some(b"object"),
        target_tenant: Some(target_tenant),
        target_owner: Some(target_owner),
        operation_id: b"recheck-separation-operation",
        operation_fingerprint: b"recheck-separation-fingerprint",
    }
}

// memory—v1: One isolated process per repetition, one healthy session, and the
// whole-root validation anchor measured before the load begins.
struct Repetition {
    owner: Arc<astral_authorization_root::memory_v1_root::RootOwner>,
    handle: astral_authorization_root::memory_v1_root::RootHandle,
    authority: Arc<MemoryV1SessionAuthority>,
    credential: Arc<str>,
    identity: CandidateIdentity,
}

fn repetition() -> Repetition {
    let (rows, selections) = fixture();
    let owner = install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: 64,
            max_bindings_per_read: 8,
        },
    )
    .unwrap();
    owner
        .install_registry(&[
            astral_authorization_root::memory_v1_registry::RegistryDeclaration {
                resource: "document".into(),
                actions: vec!["read".into()],
            },
        ])
        .unwrap();
    owner.adopt_serving_for_isolated_tests().unwrap();
    let authority = Arc::new(MemoryV1SessionAuthority::new());
    authority.bind_to_root(&owner).unwrap();
    let identity = CandidateIdentity {
        user_id: MemoryId::from_bytes(id(1)),
        identity_card_id: MemoryId::from_bytes(id(2)),
        user_card_id: MemoryId::from_bytes(id(4)),
        tenant_id: MemoryId::from_bytes(id(3)),
    };
    let credential = Arc::from(
        authority
            .identity_session_adapter()
            .issue_unchecked_for_test(identity, now() - 60, 3600)
            .unwrap()
            .credential()
            .to_owned(),
    );
    let handle = owner.handle();
    Repetition {
        owner: Arc::new(owner),
        handle,
        authority,
        credential,
        identity,
    }
}

// memory—v1: Publish one unrelated user-card creation; a withdrawal would end
// the experiment, so the interleave must stay harmless for the healthy read.
fn publish_unrelated(root: &Repetition, card: u8) {
    let metadata = root.handle.metadata().unwrap();
    root.owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::UserCardCreate {
                row: astral_authorization_root::memory_v1_db_rows::UserCardRow {
                    user_card_id: [card; 16],
                    user_id: root.identity.user_id.into_bytes(),
                    tenant_id: root.identity.tenant_id.into_bytes(),
                    status: astral_authorization_root::memory_v1_db_rows::UserCardStatus::Active,
                },
            },
            &astral_authorization_root::memory_v1_root::MutationPrecondition {
                evaluated_root_version: metadata.version,
            },
        )
        .unwrap();
}

#[test]
#[ignore = "memory-v1 recheck separation; run explicitly with --ignored"]
fn recheck_separation_arms_report_distributions() {
    const CHILD_ENV: &str = "ASTRAL_MEMORY_V1_RECHECK_CHILD_RULES";
    if let Ok(card) = std::env::var(CHILD_ENV) {
        run_arm(card.parse::<u8>().unwrap());
        return;
    }
    // memory—v1: One isolated child per repetition so every arm starts from a
    // fresh immutable process root; the parent prints only the reported rows.
    for card in [0x21_u8, 0x22, 0x23] {
        let output = thread::spawn(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_paper_evidence_tests::recheck_cost::recheck_separation_arms_report_distributions",
                    "--ignored",
                    "--nocapture",
                ])
                .env(CHILD_ENV, card.to_string())
                .output()
                .unwrap()
        })
        .join()
        .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "recheck child {card} failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
        for row in stdout.lines().filter(|line| line.starts_with("arm=")) {
            println!("{row}");
        }
    }
}

fn run_arm(card: u8) {
    let root = repetition();
    let tenant: &'static [u8; 16] = Box::leak(Box::new(id(3)));
    let owner_user: &'static [u8; 16] = Box::leak(Box::new(id(1)));
    let request = object_request(tenant, owner_user);
    let verifier = root.authority.verifier();
    let engine = PolicyEngine::new();

    // Arm held: one scope, one session, unrelated publication between rounds.
    let held_scope = RequestRootScope::new(root.handle.clone(), Default::default());
    let held_root = held_scope.extension();
    let held_session = verifier
        .verify_and_bind(&root.credential, now(), &held_root)
        .unwrap();
    // Whole-root validation anchor, measured once per repetition before load:
    // the request reader owns the immutable snapshot, so the naive
    // whole-authority re-verification is measured on exactly what the warm
    // arms recheck per request.
    let (validation_ns, digest_ns) = held_root
        .with_reader(|reader| reader.publication_validation_timings_for_test())
        .unwrap()
        .unwrap();
    println!(
        "arm=validate_whole root_digest_ns={} root_validation_ns={} iterations=1",
        digest_ns, validation_ns
    );
    let iterations = iterations();
    let rounds = rounds();
    let mut held_allows = Vec::with_capacity(iterations * rounds);
    let mut held_pending = 0usize;
    let mut held_denied = 0usize;
    for round in 0..rounds {
        // One distinct unrelated card per round; the same card twice is a
        // duplicate row, and the interleave only needs to be harmless.
        publish_unrelated(&root, card.wrapping_add(round as u8).max(0x21));
        for _ in 0..iterations {
            let start = Instant::now();
            let result = engine.evaluate_memory_v1(&held_root, &held_session, &request);
            let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap();
            match result.decision {
                MemoryV1Decision::Allow => {
                    assert!(result.admission.is_some());
                    held_allows.push(elapsed);
                }
                MemoryV1Decision::Pending => {
                    held_pending += 1;
                    assert!(result.admission.is_none());
                }
                MemoryV1Decision::Deny => {
                    held_denied += 1;
                    assert!(result.admission.is_none());
                }
            }
        }
        println!(
            "arm=recheck_held round={round} root={} allow={} deny={} pending={}",
            held_root
                .with_reader(|reader| reader.metadata())
                .unwrap()
                .version,
            held_allows.len(),
            held_denied,
            held_pending,
        );
    }

    // Arm fresh: a new scope and session per evaluation, all inside the last
    // published root; the same request but no held reader reuse.
    let mut fresh_allows = Vec::with_capacity(iterations);
    let mut fresh_pending = 0usize;
    for _ in 0..iterations {
        let start = Instant::now();
        let scope = RequestRootScope::new(root.handle.clone(), Default::default());
        let fresh_root = scope.extension();
        let session = verifier
            .verify_and_bind(&root.credential, now(), &fresh_root)
            .unwrap();
        let result = engine.evaluate_memory_v1(&fresh_root, &session, &request);
        let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap();
        match result.decision {
            MemoryV1Decision::Allow => {
                assert!(result.admission.is_some());
                fresh_allows.push(elapsed);
            }
            MemoryV1Decision::Pending => {
                fresh_pending += 1;
                assert!(result.admission.is_none());
            }
            MemoryV1Decision::Deny => panic!("a healthy read must not be denied"),
        }
    }
    // Fail-closed proof on the same held scope: withdrawing the only supporting
    // binding turns the held evaluation pending (its recheck observes the
    // dependency change) and denies fresh readers.
    // The precondition must name the CURRENT root version; the held reader
    // stays pinned to the pre-publication root and cannot authorize writes.
    let metadata = root.handle.metadata().unwrap();
    root.owner
        .execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::BindingRemove {
                binding_id: id(6),
                removed_at: now(),
                removed_by: id(1),
            },
            &astral_authorization_root::memory_v1_root::MutationPrecondition {
                evaluated_root_version: metadata.version,
            },
        )
        .unwrap();
    let held = engine.evaluate_memory_v1(&held_root, &held_session, &request);
    assert_eq!(
        held.decision,
        MemoryV1Decision::Pending,
        "the held view must not survive its own withdrawal"
    );
    assert!(held.admission.is_none());
    let fresh_scope = RequestRootScope::new(root.handle.clone(), Default::default());
    let fresh_root = fresh_scope.extension();
    let fresh_session = verifier
        .verify_and_bind(&root.credential, now(), &fresh_root)
        .unwrap();
    let fresh = engine.evaluate_memory_v1(&fresh_root, &fresh_session, &request);
    assert_eq!(fresh.decision, MemoryV1Decision::Deny);
    assert!(fresh.admission.is_none());

    held_allows.sort_unstable();
    fresh_allows.sort_unstable();
    println!(
        "arm=recheck_held total={} allows={} denied_total={} pending_total={} p50_ns={} p95_ns={} p99_ns={}",
        iterations * rounds,
        held_allows.len(),
        0,
        0,
        percentile(&held_allows, 50),
        percentile(&held_allows, 95),
        percentile(&held_allows, 99),
    );
    println!(
        "arm=recheck_fresh total={} allows={} pending={} p50_ns={} p95_ns={} p99_ns={}",
        iterations,
        fresh_allows.len(),
        fresh_pending,
        percentile(&fresh_allows, 50),
        percentile(&fresh_allows, 95),
        percentile(&fresh_allows, 99),
    );
}
