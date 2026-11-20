//! memory—v1: Phase timing and contention probes for isolated scale fixtures.

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::Duration;

use astral_authorization_root::memory_v1_root::RootHandle;
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};

use super::*;

#[derive(Default)]
pub(super) struct Samples(BTreeMap<&'static str, Vec<u128>>);

pub(super) struct Sample<'a> {
    samples: &'a mut Samples,
    stamps: BTreeMap<&'static str, Instant>,
    started: Instant,
    last: Instant,
}

impl Samples {
    pub(super) fn sample(&mut self) -> Sample<'_> {
        let started = Instant::now();
        Sample {
            samples: self,
            stamps: BTreeMap::from([("start", started)]),
            started,
            last: started,
        }
    }

    pub(super) fn report(&mut self, scope: &str) {
        for (phase, times) in &mut self.0 {
            times.sort_unstable();
            let percentile = |p: usize| times[(times.len() * p).div_ceil(100) - 1];
            println!(
                "scale: profile={scope} phase={phase} n={} p50_ns={} p95_ns={} p99_ns={}",
                times.len(),
                percentile(50),
                percentile(95),
                percentile(99),
            );
        }
    }
}

impl Sample<'_> {
    pub(super) fn mark(&mut self, phase: &'static str) {
        let now = Instant::now();
        assert!(self.stamps.insert(phase, now).is_none());
        self.record(phase, now.duration_since(self.last));
        self.last = now;
    }

    fn interval(&mut self, name: &'static str, from: &'static str, to: &'static str) {
        self.record(name, self.stamps[to].duration_since(self.stamps[from]));
    }

    pub(super) fn finish(mut self) {
        self.record("total", self.last.duration_since(self.started));
    }

    fn record(&mut self, phase: &'static str, duration: Duration) {
        self.samples
            .0
            .entry(phase)
            .or_default()
            .push(duration.as_nanos());
    }
}

type Principal = ([u8; 16], [u8; 16], [u8; 16], [u8; 16]);

struct Probe<'a> {
    principal: Principal,
    resource: &'a str,
    action: &'a str,
    rule_set: [u8; 16],
}

impl Probe<'_> {
    fn evaluate(
        &self,
        engine: &PolicyEngine,
        authority: &MemoryV1SessionAuthority,
        handle: &RootHandle,
        now: i64,
    ) -> MemoryV1Decision {
        let (user, identity, card, tenant) = self.principal;
        let scope = RequestRootScopeShim::new(handle.clone());
        let root = scope.extension();
        let credential = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(
                CandidateIdentity {
                    user_id: MemoryId::from_bytes(user),
                    identity_card_id: MemoryId::from_bytes(identity),
                    user_card_id: MemoryId::from_bytes(card),
                    tenant_id: MemoryId::from_bytes(tenant),
                },
                now - 30,
                300,
            )
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(credential.credential(), now, &root)
            .unwrap();
        engine
            .evaluate_memory_v1(
                &root,
                &session,
                &MemoryV1Request {
                    resource: self.resource,
                    action: self.action,
                    target: Some(b"scale-profile"),
                    target_tenant: Some(&tenant),
                    target_owner: Some(&user),
                    operation_id: b"scale-profile",
                    operation_fingerprint: b"scale-profile",
                },
            )
            .decision
    }
}

fn allow_probe(
    fixture: &ShardFixture,
    base: usize,
    include: impl Fn([u8; 16]) -> bool,
) -> Probe<'static> {
    for (index, principal) in fixture.principals[..base].iter().enumerate() {
        let rule_set = fixture.rows.bindings[index].rule_set_id;
        if !include(rule_set) {
            continue;
        }
        for resource in RESOURCES {
            for action in ACTIONS {
                if oracle_decide(
                    fixture,
                    principal.2,
                    resource,
                    action,
                    Some(&principal.0),
                    Some(&principal.3),
                ) == Expected::Allow
                {
                    return Probe {
                        principal: *principal,
                        resource,
                        action,
                        rule_set,
                    };
                }
            }
        }
    }
    panic!("profile fixture needs a warm ALLOW for each probe");
}

pub(super) fn run() {
    let started = Instant::now();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    for base in [100, 300, 400] {
        for batch in [1, 40, 200] {
            let mut setup = Samples::default();
            let mut load = Samples::default();
            for _ in 0..12 {
                run_sample(base, batch, now, &mut setup, &mut load, false);
            }
            setup.report(&format!("setup_{base}_{batch}"));
            load.report(&format!("context_load_{base}_{batch}"));
        }
    }
    run_sample(
        400,
        200,
        now,
        &mut Samples::default(),
        &mut Samples::default(),
        true,
    );
    println!(
        "scale: profile=process total_ms={}",
        started.elapsed().as_millis()
    );
}

fn run_sample(
    base: usize,
    batch: usize,
    now: i64,
    setup: &mut Samples,
    load: &mut Samples,
    overlap: bool,
) {
    let mut setup = setup.sample();
    let mut fixture = shard_fixture(0);
    let range = base..base + batch;
    let probe = allow_probe(&fixture, base, |_| true);
    let shared_set = probe.rule_set;
    let other_probe = allow_probe(&fixture, base, |id| id != shared_set);
    let loaded_probe = Probe {
        principal: fixture.principals[base],
        ..probe
    };
    let mut missing = CandidateRows {
        users: fixture.rows.users[range.clone()].to_vec(),
        identity_cards: fixture.rows.identity_cards[range.clone()].to_vec(),
        user_cards: fixture.rows.user_cards[range.clone()].to_vec(),
        bindings: fixture.rows.bindings[range.clone()].to_vec(),
        binding_confirmations: fixture.rows.binding_confirmations[range].to_vec(),
        ..CandidateRows::default()
    };
    for (binding, confirmation) in missing
        .bindings
        .iter_mut()
        .zip(&mut missing.binding_confirmations)
    {
        binding.rule_set_id = shared_set;
        confirmation.rule_set_id = shared_set;
    }
    fixture.rows.users.truncate(base);
    fixture.rows.identity_cards.truncate(base);
    fixture.rows.user_cards.truncate(base);
    fixture.rows.bindings.truncate(base);
    fixture.rows.binding_confirmations.truncate(base);
    setup.mark("fixture_and_batch");
    let owner = install_isolated_test_root_with_phases(
        fixture.rows,
        fixture.selections,
        CandidateBudget {
            max_table_rows: MAX_ROOT_DIGEST_KEYS,
            max_bindings_per_read: 256,
        },
        |phase| setup.mark(phase),
    )
    .unwrap();
    let declarations = RESOURCES
        .iter()
        .map(|resource| RegistryDeclaration {
            resource: (*resource).to_owned(),
            actions: ACTIONS.iter().map(|action| (*action).to_owned()).collect(),
        })
        .collect::<Vec<_>>();
    owner.install_registry(&declarations).unwrap();
    setup.mark("registry");
    let before = owner.adopt_serving_for_isolated_tests().unwrap();
    setup.mark("adopt_isolated");
    setup.finish();

    let handle = owner.handle();
    let engine = PolicyEngine::new();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let mutation = ManagementMutationV2::ContextLoad {
        rows: missing,
        selections: Vec::new(),
    };
    let precondition = MutationPrecondition {
        evaluated_root_version: before.version,
    };
    let mut load = load.sample();
    let loaded = if overlap {
        for warm in [&probe, &other_probe] {
            assert_eq!(
                warm.evaluate(&engine, &authority, &handle, now),
                MemoryV1Decision::Allow
            );
        }
        std::thread::scope(|scope| {
            let (start, ready) = mpsc::sync_channel(0);
            let (done, result) = mpsc::channel();
            let engine = &engine;
            let authority = &authority;
            let handle = &handle;
            scope.spawn(move || {
                if ready.recv_timeout(Duration::from_secs(30)).is_err() {
                    return;
                }
                let evaluate = |probe: &Probe<'_>| {
                    let mut counts = [0; 3];
                    for _ in 0..32 {
                        let index = match probe.evaluate(engine, authority, handle, now) {
                            MemoryV1Decision::Allow => 0,
                            MemoryV1Decision::Deny => 1,
                            MemoryV1Decision::Pending => 2,
                        };
                        counts[index] += 1;
                    }
                    counts
                };
                done.send((evaluate(&probe), evaluate(&other_probe)))
                    .unwrap();
            });
            owner.execute_context_load_for_scale_test(&mutation, &precondition, |phase| {
                if phase == "prepared" {
                    start.send(()).unwrap();
                    let (shared, other) = result.recv_timeout(Duration::from_secs(30)).unwrap();
                    assert_eq!(shared, [32, 0, 0]);
                    assert_eq!(other, [32, 0, 0]);
                    println!("scale: overlap phase=prepared shared_allow={} shared_pending={} other_allow={} other_pending={}", shared[0], shared[2], other[0], other[2]);
                }
            }).unwrap()
        })
    } else {
        let loaded = owner
            .execute_context_load_for_scale_test(&mutation, &precondition, |phase| load.mark(phase))
            .unwrap();
        load.interval("exclusive_lock", "lock_acquired", "lock_released");
        load.interval("mutation_only", "start", "lock_released");
        loaded
    };
    assert_eq!(loaded.version, before.version + 1);
    assert_eq!(loaded.row_count, before.row_count + 5 * batch);
    assert_eq!(
        loaded_probe.evaluate(&engine, &authority, &handle, now),
        MemoryV1Decision::Allow
    );
    load.mark("request_setup_and_reevaluate");
    drop(owner);
    load.mark("drop");
    load.finish();
}
