//! memory—v1: Isolated ordinary-read comparison. Each arm and repetition starts a fresh process.
//! Only A/B use the outer reader/writer lock; every changing fixture input obeys it in those arms.
//! The attribution, registry, live sessions and clock are fixed in the timed workload.

use super::*;
use astral_authorization_root::memory_v1_db_rows::binding_is_active;
use astral_authorization_root::memory_v1_fence::FenceDeclaration;
use astral_authorization_root::memory_v1_root::{
    measure_abc_lock_for_test as native_timing, RootOwner,
};
use astral_authorization_root::memory_v1_rules::version_digest;
use std::sync::{Barrier, RwLock};
use std::time::Instant;

const SELECTOR: &str = "memory_v1_formal::tests::abc_benchmark::ordinary_read_comparison";
const CHILD: &str = "ASTRAL_ABC_CASE";
const ALLOW: &[u8] = br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW"},{"ruleId":"D","resource":"document","action":"read","effect":"DENY","validity":{"from":120}}]}"#;
const OTHER: &[u8] =
    br#"{"rules":[{"ruleId":"R4","resource":"document","action":"read","effect":"ALLOW"}]}"#;
const REVOKED: &[u8] =
    br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"DENY"}]}"#;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum Arm {
    A,
    B,
    C,
}
use Arm::*;
use MemoryV1Decision::{Allow, Deny, Pending};

struct Bench {
    owner: RootOwner,
    authority: MemoryV1SessionAuthority,
    credentials: [String; 2],
    gate: RwLock<()>,
}

#[derive(Clone, Copy, Debug)]
struct Timing {
    /// The full synchronized final-call interval. A/B measure the benchmark
    /// gate hold; C measures the complete production final-check call.
    final_call_wall_ns: u64,
    /// The benchmark gate's wait and hold, present only for A/B.
    benchmark_gate: Option<(u64, u64)>,
    /// C's instrumented native root-lock wait and hold. This is only the inner
    /// `mutation_lock` interval, not the complete synchronized final call.
    native_root_lock: Option<(u64, u64)>,
}
fn ns(start: Instant) -> u64 {
    start.elapsed().as_nanos().try_into().unwrap()
}

fn version(set: u8, seq: &[u8], content: &[u8]) -> RuleSetVersionRow {
    let input = canonical_version_bytes(seq, content, &[2]);
    RuleSetVersionRow {
        rule_set_id: [set; 16],
        version_bytes: seq.to_vec(),
        content_bytes: content.to_vec(),
        timestamp_bytes: vec![2],
        hash_bytes: version_digest(&input),
        hash_input_bytes: input,
    }
}

impl Bench {
    fn new() -> Self {
        let (mut rows, selections) = fixture();
        *rows
            .rule_set_versions
            .iter_mut()
            .find(|r| r.rule_set_id == [10; 16])
            .unwrap() = version(10, &[1], ALLOW);
        for binding in &mut rows.bindings {
            binding.owner_scope = MemoryV1OwnerScope::SelfUser;
            binding.tenant_scope = MemoryV1TenantScope::SelfTenant;
        }
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 8192,
                max_bindings_per_read: 32,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".into(),
                actions: vec!["read".into()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let credentials = [4, 7].map(|card| {
            authority
                .identity_session_adapter()
                .issue_unchecked_for_test(identity(card), 100, 100)
                .unwrap()
                .credential()
                .to_owned()
        });
        Self {
            owner,
            authority,
            credentials,
            gate: RwLock::default(),
        }
    }

    fn publish(&self, mutation: &ManagementMutationV2) {
        let before = self.owner.handle().metadata().unwrap();
        let after = self
            .owner
            .execute_mutation_with_precondition_for_isolated_tests(
                mutation,
                &MutationPrecondition {
                    evaluated_root_version: before.version,
                },
            )
            .unwrap();
        assert_eq!(after.version, before.version + 1);
    }

    fn open(&self) {
        let m = self.owner.handle().metadata().unwrap();
        self.owner
            .begin_modification_fence(
                [10; 16],
                &FenceDeclaration {
                    rule_set_version: vec![1],
                    root_version: m.version,
                    digest: m.digest,
                },
            )
            .unwrap();
    }

    // The cut precedes A's fresh lock acquisition, and follows the initial candidate for B/C.
    fn read(
        &self,
        arm: Arm,
        card: u8,
        req: &MemoryV1Request<'_>,
        first: i64,
        last: i64,
        cut: impl FnOnce(),
    ) -> (MemoryV1Evaluation, Option<Timing>) {
        let mut cut = Some(cut);
        // A deliberately creates a fresh scope after the cut. This prevents a
        // pre-cut request reader from pinning stale root state while A waits
        // for its benchmark gate. B/C retain their initial read before `cut`
        // because their final-check race is the workload under comparison.
        let mut timing = None;
        let lock_read = || {
            let wait = Instant::now();
            let lock = self.gate.read().unwrap();
            (lock, ns(wait), Instant::now())
        };
        let result = if arm == A {
            // The cut precedes A's fresh scope/session and benchmark-gate
            // acquisition, so the gated indexed reevaluation cannot use a
            // pre-cut request snapshot or session binding.
            cut.take().unwrap()();
            let scope = RequestRootScope::new(self.owner.handle(), Default::default());
            let root = scope.extension();
            let session = self
                .authority
                .verifier()
                .verify_and_bind(&self.credentials[usize::from(card == 7)], first, &root)
                .unwrap();
            // Keep credential verification and request-scope setup outside the
            // measured final call. A's lock protects the full indexed
            // reevaluation, but is not charged for setup that B/C also do.
            let final_call = Instant::now();
            let (lock, wait, hold_start) = lock_read();
            // A is the shared indexed evaluator baseline under one gate. It
            // still builds the evaluator's winning/dependency vectors even
            // though this path does not consume a final dependency record.
            let result = session
                .with_authoritative_context(&root, |facts, reader, live| {
                    let now = std::hint::black_box(last);
                    if live.is_none()
                        || now < first
                        || !facts.valid_at(now)
                        || reader.metadata().status != RootStatus::Serving
                    {
                        return pending();
                    }
                    match evaluate_card_candidate(facts, reader, req, now, false) {
                        CardOutcome::Deny(reason) => observed_deny(facts, reader, now, req, reason),
                        CardOutcome::Pending(reason) => non_allow(Pending, None, Some(reason)),
                        CardOutcome::Allow {
                            owner_scope,
                            tenant_scope,
                            ..
                        } => MemoryV1Evaluation {
                            decision: Allow,
                            deny_source: None,
                            pending_source: None,
                            deny_observation: None,
                            admission: Some(MemoryV1Admission {
                                root: reader.metadata(),
                                identity: facts.candidate_identity(),
                                resource: req.resource.to_owned(),
                                action: req.action.to_owned(),
                                target: req.target.map(<[u8]>::to_vec),
                                target_owner: req.target_owner.map(<[u8]>::to_vec),
                                target_tenant: req.target_tenant.map(<[u8]>::to_vec),
                                operation_id: req.operation_id.to_vec(),
                                operation_fingerprint: req.operation_fingerprint.to_vec(),
                                trusted_time_unix_seconds: now,
                                change_intent: None,
                                effective_owner_scope: owner_scope,
                                effective_tenant_scope: tenant_scope,
                            }),
                        },
                    }
                })
                .unwrap_or_else(|_| pending());
            let held = ns(hold_start);
            drop(lock);
            timing = Some(Timing {
                final_call_wall_ns: ns(final_call),
                benchmark_gate: Some((wait, held)),
                native_root_lock: None,
            });
            result
        } else {
            let scope = RequestRootScope::new(self.owner.handle(), Default::default());
            let root = scope.extension();
            let session = self
                .authority
                .verifier()
                .verify_and_bind(&self.credentials[usize::from(card == 7)], first, &root)
                .unwrap();
            let mut initial = Some(first);
            evaluate_with_final(
                &root,
                &session,
                req,
                || Some(std::hint::black_box(initial.take().unwrap_or(last))),
                cut.take().unwrap(),
                |check, record, constraints, clock| {
                    // B/C time the entire synchronized final-call callback.
                    // C's native probe below remains an inner root-lock sample.
                    let final_call = Instant::now();
                    if arm == C {
                        let (result, sample) = native_timing(|| {
                            check.try_final_time_for_test(record, constraints, clock)
                        });
                        timing = Some(Timing {
                            final_call_wall_ns: ns(final_call),
                            benchmark_gate: None,
                            native_root_lock: sample,
                        });
                        result
                    } else {
                        let (lock, wait, hold_start) = lock_read();
                        let result = root
                            .with_reader(|reader| {
                                let m = reader.metadata();
                                if m.status != RootStatus::Serving
                                    || m.version == u64::MAX
                                    || self.owner.handle().metadata().ok()? != m
                                    || record.instance_id != m.instance_id
                                    || record.registry_version == u64::MAX
                                    || reader
                                        .registry_check_with_version(req.resource, req.action)
                                        .ok()?
                                        != record.registry_version
                                {
                                    return None;
                                }
                                let clear = reader
                                    .read_card_for_evaluation(record.card_id, |ctx, _| {
                                        ctx.bindings
                                            .iter()
                                            .filter(|b| {
                                                binding_is_active(b.binding, Some(ctx.card))
                                            })
                                            .all(|b| {
                                                reader.is_fenced(b.binding.rule_set_id) == Ok(false)
                                            })
                                    })
                                    .ok()?;
                                let now = clock()?;
                                (clear
                                    && session.revalidate_authority(&root, now).is_ok()
                                    && within_envelope(constraints, now))
                                .then_some(now)
                            })
                            .ok()
                            .flatten();
                        let held = ns(hold_start);
                        drop(lock);
                        timing = Some(Timing {
                            final_call_wall_ns: ns(final_call),
                            benchmark_gate: Some((wait, held)),
                            native_root_lock: None,
                        });
                        result
                    }
                },
            )
        };
        (result, timing)
    }
}

fn pending() -> MemoryV1Evaluation {
    non_allow(Pending, None, Some(MemoryV1PendingSource::ContextInvalid))
}
fn within_envelope(c: &FinalCheckTimeConstraints<'_>, now: i64) -> bool {
    now >= c.start_time
        && c.future_boundaries.iter().all(|&b| now < b)
        && !c.winning_windows.is_empty()
        && c.winning_windows.iter().all(|w| {
            window_active(w.binding_from, w.binding_until, now)
                && w.entry_validity.is_none_or(|v| v.active_at(now))
        })
}
fn request() -> MemoryV1Request<'static> {
    MemoryV1Request {
        resource: "document",
        action: "read",
        target: Some(b"target"),
        target_owner: Some(&[1; 16]),
        target_tenant: Some(&[3; 16]),
        operation_id: b"abc-read",
        operation_fingerprint: b"abc-read-document",
    }
}

fn oracle(e: &MemoryV1Evaluation, card: u8, now: i64, expected: MemoryV1Decision) {
    assert_eq!(e.decision, expected, "unexpected decision: {e:?}");
    if e.decision != Allow {
        assert!(e.admission.is_none());
        return;
    }
    let a = e.admission.as_ref().unwrap();
    let req = request();
    assert_eq!(a.identity(), identity(card));
    assert_eq!(a.target(), req.target);
    assert_eq!(a.target_owner(), req.target_owner);
    assert_eq!(a.target_tenant(), req.target_tenant);
    assert_eq!(a.resource(), req.resource);
    assert_eq!(a.action(), req.action);
    assert_eq!(a.operation_id(), req.operation_id);
    assert_eq!(a.operation_fingerprint(), req.operation_fingerprint);
    assert_eq!(a.effective_owner_scope(), MemoryV1OwnerScope::SelfUser);
    assert_eq!(a.effective_tenant_scope(), MemoryV1TenantScope::SelfTenant);
    assert_eq!(a.trusted_time_unix_seconds(), now);
    assert_eq!(a.root().status, RootStatus::Serving);
}

fn publication(set: u8, i: u32, content: &[u8]) -> ManagementMutationV2 {
    let seq = (i + 2).to_be_bytes();
    let mut id = [0xAB; 16];
    id[4] = set;
    id[12..].copy_from_slice(&seq);
    ManagementMutationV2::VersionPublish {
        rule_set_id: [set; 16],
        version_row: version(set, &seq, content),
        new_current_version: seq.to_vec(),
        change_confirmation: RuleSetChangeConfirmationRow {
            confirmation_id: id,
            rule_set_id: [set; 16],
            version_bytes: seq.to_vec(),
            confirmer_user_id: [1; 16],
            affected_scope_bytes: vec![1],
            operation_id: id.to_vec(),
            confirmed_at_bytes: vec![2],
            revoked_at: None,
            revoked_by: None,
        },
    }
}

fn controls(b: &Bench, arm: Arm) {
    let check = |name: &str,
                 card,
                 req: &MemoryV1Request<'_>,
                 first,
                 last,
                 expected,
                 cut: &mut dyn FnMut()| {
        let (e, _) = b.read(arm, card, req, first, last, || cut());
        oracle(&e, card, last, expected);
        if expected == Deny && name != "wrong-owner" {
            assert_eq!(e.deny_source, Some(MemoryV1DenySource::RuleDenied));
        }
        println!(
            "ABC_CONTROL arm={arm:?} case={name} outcome={:?}",
            e.decision
        );
    };
    let req = request();
    let mut noop = || {};
    let write = |f: &mut dyn FnMut()| {
        let _g = (arm != C).then(|| b.gate.write().unwrap());
        f()
    };
    check("positive", 4, &req, 110, 110, Allow, &mut noop);
    check("negative", 7, &req, 110, 110, Deny, &mut noop);
    check(
        "missing-owner",
        4,
        &MemoryV1Request {
            target_owner: None,
            ..req
        },
        110,
        110,
        Pending,
        &mut noop,
    );
    check(
        "wrong-owner",
        4,
        &MemoryV1Request {
            target_owner: Some(&[9; 16]),
            ..req
        },
        110,
        110,
        Deny,
        &mut noop,
    );
    check(
        "scheduled-deny",
        4,
        &req,
        119,
        120,
        if arm == A { Deny } else { Pending },
        &mut noop,
    );
    check("rollback", 4, &req, 110, 109, Pending, &mut noop);
    check("expired", 4, &req, 110, 200, Pending, &mut noop);
    check(
        "unrelated",
        4,
        &req,
        110,
        110,
        if arm == B { Pending } else { Allow },
        &mut || write(&mut || b.publish(&publication(13, 0, OTHER))),
    );
    check(
        "fence-pulse",
        4,
        &req,
        110,
        110,
        if arm == C { Pending } else { Allow },
        &mut || {
            write(&mut || {
                b.open();
                b.owner.abort_modification_fence([10; 16]).unwrap();
            })
        },
    );
    check("open-fence", 4, &req, 110, 110, Pending, &mut || {
        write(&mut || b.open())
    });
    write(&mut || b.owner.abort_modification_fence([10; 16]).unwrap());
    check(
        "same-meaning",
        4,
        &req,
        110,
        110,
        if arm == A { Allow } else { Pending },
        &mut || write(&mut || b.publish(&publication(10, 0, ALLOW))),
    );
    check(
        "new-deny",
        4,
        &req,
        110,
        110,
        if arm == A { Deny } else { Pending },
        &mut || write(&mut || b.publish(&publication(10, 1, REVOKED))),
    );
    check("fresh-after-deny", 4, &req, 110, 110, Deny, &mut noop);
}

#[derive(Default)]
struct Reads {
    lat: Vec<u64>,
    final_calls: Vec<u64>,
    admitted_final_calls: Vec<u64>,
    admitted_holds: Vec<u64>,
    waits: Vec<u64>,
    holds: Vec<u64>,
    native_waits: Vec<u64>,
    native_holds: Vec<u64>,
    outcomes: [usize; 3],
    legal: usize,
    legal_allow: usize,
}
fn dist(mut v: Vec<u64>) -> serde_json::Value {
    if v.is_empty() {
        return serde_json::Value::Null;
    }
    v.sort_unstable();
    let at = |p: usize| v[(v.len() * p).div_ceil(100) - 1];
    serde_json::json!([v.len(), at(50usize), at(95), at(99)])
}
fn load(b: &Bench, arm: Arm, mode: &str, ops: usize, rep: usize) {
    let n = if mode == "hot" { 8 } else { 4 };
    let writes = if mode == "pure" {
        0
    } else if mode == "hot" {
        256
    } else {
        32
    };
    let plan: Vec<_> = (0..writes)
        .map(|i| {
            if mode == "unrelated" {
                publication(13, i, OTHER)
            } else {
                publication(10, i, ALLOW)
            }
        })
        .collect();
    let initial = b.owner.handle().metadata().unwrap();
    let barrier = Barrier::new(n + 2);
    let (mut all, outer_w, native_w, wlat, elapsed) = std::thread::scope(|s| {
        let readers: Vec<_> = (0..n)
            .map(|_| {
                s.spawn(|| {
                    let mut r = Reads::default();
                    let req = request();
                    barrier.wait();
                    for i in 0..ops {
                        let card = if i % 4 == 3 { 7 } else { 4 };
                        let t = Instant::now();
                        let (e, timing) = b.read(arm, card, &req, 110, 110, || {});
                        r.lat.push(ns(t));
                        if let Some(timing) = timing {
                            r.final_calls.push(timing.final_call_wall_ns);
                            if e.decision == Allow {
                                r.admitted_final_calls.push(timing.final_call_wall_ns);
                                let (_, held) = timing
                                    .benchmark_gate
                                    .or(timing.native_root_lock)
                                    .expect("an admission has a guarded sample");
                                r.admitted_holds.push(held);
                            }
                            if let Some((w, h)) = timing.benchmark_gate {
                                r.waits.push(w);
                                r.holds.push(h);
                            }
                            if let Some((w, h)) = timing.native_root_lock {
                                r.native_waits.push(w);
                                r.native_holds.push(h);
                            }
                        }
                        if card == 4 {
                            r.legal += 1;
                            assert_ne!(e.decision, Deny);
                            r.legal_allow += usize::from(e.decision == Allow);
                        } else {
                            assert_ne!(e.decision, Allow);
                            if e.decision == Deny {
                                assert_eq!(e.deny_source, Some(MemoryV1DenySource::RuleDenied));
                            }
                        }
                        oracle(&e, card, 110, e.decision);
                        r.outcomes[match e.decision {
                            Allow => 0,
                            Deny => 1,
                            Pending => 2,
                        }] += 1;
                    }
                    r
                })
            })
            .collect();
        let writer = s.spawn(|| {
            let mut outer = vec![];
            let mut native = vec![];
            let mut lat = vec![];
            barrier.wait();
            for m in &plan {
                let t = Instant::now();
                let guard = (arm != C).then(|| b.gate.write().unwrap());
                let waited = ns(t);
                let held = Instant::now();
                let (_, measurement) = native_timing(|| b.publish(m));
                let hold = ns(held);
                drop(guard);
                lat.push(ns(t));
                if arm != C {
                    outer.push((waited, hold));
                }
                native.push(measurement.expect("native publication guard"));
            }
            (outer, native, lat)
        });
        let t = Instant::now();
        barrier.wait();
        let parts = readers
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        let (outer, native, lat) = writer.join().unwrap();
        (parts, outer, native, lat, ns(t))
    });
    let mut total = Reads::default();
    for r in &mut all {
        total.lat.append(&mut r.lat);
        total.final_calls.append(&mut r.final_calls);
        total
            .admitted_final_calls
            .append(&mut r.admitted_final_calls);
        total.admitted_holds.append(&mut r.admitted_holds);
        total.waits.append(&mut r.waits);
        total.holds.append(&mut r.holds);
        total.native_waits.append(&mut r.native_waits);
        total.native_holds.append(&mut r.native_holds);
        for (i, num) in r.outcomes.iter().enumerate() {
            total.outcomes[i] += num;
        }
        total.legal += r.legal;
        total.legal_allow += r.legal_allow;
    }
    assert_eq!(total.lat.len(), n * ops);
    assert_eq!(total.outcomes.iter().sum::<usize>(), n * ops);
    assert_eq!(total.legal, n * (ops / 4) * 3);
    assert_eq!(
        b.owner.handle().metadata().unwrap().version,
        initial.version + u64::from(writes)
    );
    if mode == "pure" || arm == A {
        assert_eq!(total.outcomes[2], 0);
    }
    assert_eq!(total.admitted_final_calls.len(), total.legal_allow);
    assert_eq!(total.admitted_holds.len(), total.legal_allow);
    let final_call_samples = total.final_calls.len();
    let benchmark_gate_samples = total.waits.len();
    let native_root_lock_samples = total.native_waits.len();
    let pair = |waits: Vec<u64>, holds: Vec<u64>| serde_json::json!({"wait":dist(waits),"hold":dist(holds)});
    let pairs = |v: Vec<(u64, u64)>| {
        let (waits, holds): (Vec<_>, Vec<_>) = v.into_iter().unzip();
        pair(waits, holds)
    };
    println!(
        "ABC_RESULT {}",
        serde_json::json!({"rep":rep,"arm":format!("{arm:?}"),"mode":mode,"readers":n,"reads":n*ops,"writes":writes,"writer_rejects":0,"wall_ns":elapsed,"reads_per_s":n as f64*ops as f64*1e9/elapsed as f64,"outcomes":total.outcomes,"legal":total.legal,"legal_allow":total.legal_allow,"lat_ns":dist(total.lat),"final_call_wall_ns":dist(total.final_calls),"admitted_final_wall_ns":dist(total.admitted_final_calls),"admitted_lock_hold_ns":dist(total.admitted_holds),"benchmark_gate_ns":pair(total.waits,total.holds),"native_root_lock_ns":pair(total.native_waits,total.native_holds),"native_root_lock_scope":"C inner mutation_lock only; not full synchronized final-call wall time","writer_gate_ns":pairs(outer_w),"writer_native_ns":pairs(native_w),"writer_latency_ns":dist(wlat),"denominators":{"reads":n*ops,"legal_reads":total.legal,"final_calls":final_call_samples,"benchmark_gate_samples":benchmark_gate_samples,"native_root_lock_samples":native_root_lock_samples},"notes":["A is the shared indexed evaluator baseline under the full benchmark gate; evaluate_card_candidate still builds winning/dependency vectors that A does not consume.","A/B benchmark_gate_ns and C native_root_lock_ns are separate synchronization intervals; compare final_call_wall_ns for whole final calls."]})
    );
}

#[test]
#[ignore = "release-only paired ordinary evaluator comparison in isolated child roots"]
fn ordinary_read_comparison() {
    if let Ok(case) = std::env::var(CHILD) {
        let p: Vec<_> = case.split(':').collect();
        let arm = match p[0] {
            "A" => A,
            "B" => B,
            "C" => C,
            _ => unreachable!(),
        };
        let b = Bench::new();
        if p[1] == "control" {
            controls(&b, arm);
        } else {
            load(&b, arm, p[1], p[2].parse().unwrap(), p[3].parse().unwrap());
        }
        return;
    }
    let smoke = std::env::var_os("ASTRAL_ABC_SMOKE").is_some();
    let reps = if smoke { 1 } else { 6 };
    let ops = if smoke { 64 } else { 4096 };
    for rep in 0..reps {
        for mode in ["control", "pure", "unrelated", "related", "hot"] {
            if rep > 0 && mode == "control" {
                continue;
            }
            for index in 0..3 {
                let arm = [A, B, C][(rep + index) % 3];
                let case = format!("{arm:?}:{mode}:{ops}:{rep}");
                let out = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        SELECTOR,
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD, &case)
                    .output()
                    .unwrap();
                let stdout = String::from_utf8(out.stdout).unwrap();
                print!("{stdout}");
                eprint!("{}", String::from_utf8_lossy(&out.stderr));
                println!("ABC_CHILD case={case} exit={:?}", out.status.code());
                assert!(
                    out.status.success() && stdout.contains("1 passed; 0 failed; 0 ignored"),
                    "{case}"
                );
            }
        }
    }
}
