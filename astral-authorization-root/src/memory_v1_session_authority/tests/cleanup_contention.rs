//! memory—v1: Measure the live-session guard while issuing into a populated authority.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Barrier,
};
use std::thread;
use std::time::{Duration, Instant};

use super::*;

const ISSUES: usize = 400;
const ISSUE_INTERVAL: Duration = Duration::from_millis(2);
const READERS: usize = 4;
const NOW: i64 = 100;
const LIFETIME: i64 = 300;

// memory—v1: Exercise the production issuer and nonblocking live-record guard
// without password hashing, HTTP, expiry, revocation or table resizing.
#[test]
#[ignore = "isolated session contention measurement, run explicitly"]
fn login_contention_at_live_session_scale() {
    const CHILD: &str = "ASTRAL_SESSION_CONTENTION_CHILD";
    const NAME: &str = "memory_v1_session_authority::tests::cleanup_contention::login_contention_at_live_session_scale";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--ignored", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .expect("start isolated session contention measurement");
        let stdout = String::from_utf8_lossy(&output.stdout);
        print!("{stdout}");
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "isolated session contention measurement did not pass: {}",
            output.status
        );
        return;
    }

    let owner = binding_security_serving_root();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let adapter = authority.identity_session_adapter();
    let verifier = authority.verifier();
    for live_count in [64, 50_000] {
        for round in 1..=3 {
            let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
            let root = scope.extension();
            let issued = issue_at(&adapter, &root, identity(), NOW, LIFETIME).unwrap();
            let bound = verifier
                .verify_and_bind(issued.credential(), NOW, &root)
                .unwrap();
            let (facts, binding) = bound.authority_binding_material(&root).unwrap();
            {
                let mut state = authority.state.write().unwrap();
                // All fixture records share the first issued session's absolute expiry.
                let digest = binding.credential_digest();
                let anchor = state.records.remove(&digest).unwrap();
                state.records = HashMap::new();
                state.records.try_reserve(live_count + ISSUES).unwrap();
                MemoryV1SessionIssuer::insert_prepared(&mut state, digest, anchor);
                for _ in 1..live_count {
                    let (digest, record, _) = adapter
                        .session_issuer
                        .prepare_issue(
                            adapter.proof_issuer.prove_verified_identity(identity()),
                            NOW,
                            LIFETIME,
                        )
                        .unwrap();
                    assert!(!state.records.contains_key(&digest));
                    MemoryV1SessionIssuer::insert_prepared(&mut state, digest, record);
                }
            }

            let barrier = Barrier::new(READERS + 1);
            let complete = AtomicBool::new(false);
            let mut issuer_ns = Vec::with_capacity(ISSUES);
            let (ok, unavailable, missed_slots, elapsed) = thread::scope(|threads| {
                let readers: Vec<_> = (0..READERS)
                    .map(|_| {
                        threads.spawn(|| {
                            barrier.wait();
                            let end = Instant::now() + Duration::from_secs(3);
                            let mut ok = 0_u64;
                            let mut unavailable = 0_u64;
                            while !complete.load(Ordering::Relaxed) && Instant::now() < end {
                                match verifier.try_with_live_record(&facts, &binding, |live| {
                                    live.valid_at(NOW)
                                }) {
                                    Ok(true) => ok += 1,
                                    Err(MemoryV1SessionAuthorityError::Unavailable) => {
                                        unavailable += 1
                                    }
                                    other => panic!("unexpected live-session outcome: {other:?}"),
                                }
                            }
                            (ok, unavailable)
                        })
                    })
                    .collect();
                barrier.wait();
                let began = Instant::now();
                let mut missed_slots = 0;
                for index in 0..ISSUES {
                    let slot = began + ISSUE_INTERVAL * index as u32;
                    thread::sleep(slot.saturating_duration_since(Instant::now()));
                    let start = Instant::now();
                    issue_at(&adapter, &root, identity(), NOW, LIFETIME).unwrap();
                    issuer_ns.push(start.elapsed().as_nanos());
                    missed_slots += usize::from(Instant::now() >= slot + ISSUE_INTERVAL);
                }
                let elapsed = began.elapsed();
                complete.store(true, Ordering::Relaxed);
                let (ok, unavailable) = readers
                    .into_iter()
                    .map(|reader| reader.join().unwrap())
                    .fold((0, 0), |(ok, unavailable), (read_ok, read_unavailable)| {
                        (ok + read_ok, unavailable + read_unavailable)
                    });
                (ok, unavailable, missed_slots, elapsed)
            });
            assert!(ok > 0);
            assert_eq!(
                authority.state.read().unwrap().records.len(),
                live_count + ISSUES
            );
            assert!(verifier.verify(issued.credential(), NOW).is_ok());
            issuer_ns.sort_unstable();
            eprintln!(
                "session_contention live={live_count} round={round} issues={ISSUES} elapsed_us={} missed_slots={missed_slots} read_ok={ok} read_unavailable={unavailable} unavailable_pct={:.5} issue_p50_ns={} issue_p95_ns={}",
                elapsed.as_micros(),
                100.0 * unavailable as f64 / (ok + unavailable) as f64,
                issuer_ns[ISSUES / 2 - 1],
                issuer_ns[ISSUES * 95 / 100 - 1],
            );
        }
    }
}
