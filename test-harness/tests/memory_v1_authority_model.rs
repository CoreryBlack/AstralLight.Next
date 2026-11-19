//! memory—v1: Explicit-state checks for the single-owner authority contract.
//! The model is independent of production code and performs no I/O.
//!
//! Boundaries of the models (disclosed; no check here exercises them):
//! - The read predicates are fixed fixtures, not production rule resolution. A mutant that
//!   changes permits() and validate() together (common mode) is invisible to its own oracle.
//!   The fixed Reference oracle exposes a validator that disagrees with the fixture, but a
//!   change to the fixture itself is invisible to refinement against that same fixture.
//! - Winning windows: the Monotone fixture has only the end at tick 2 (deny activation).
//!   RollbackWithStart adds a start at tick 1 and one backward clock step. Session expiry is
//!   not modeled; a session is represented by its version counter only.
//! - The fence bracket is one Boolean at the cut. The candidate is exact except for the
//!   IncompleteCandidate mutant, which omits the policy clause.
//! - The journal has one owner, at most two mutations, one denial and one crash. Publication
//!   follows the target order (at registration). The current production order (append, sync,
//!   then publish) is not explored. Stickiness after an uncertain sync and database atomicity
//!   are scenario parameters; the owner's read-back is an abstract reconcile step.

use std::collections::{BTreeSet, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

// memory—v1: Explore the whole finite graph, accounting for every transition.
fn explore<S>(initial: S, mut step: impl FnMut(S, &mut Vec<S>)) -> (usize, usize)
where
    S: Copy + Debug + Eq + Hash,
{
    let mut seen = HashSet::from([initial]);
    let mut queue = VecDeque::from([initial]);
    let mut next = Vec::new();
    let mut edges = 0;
    while let Some(state) = queue.pop_front() {
        step(state, &mut next);
        for successor in next.drain(..) {
            edges += 1;
            if seen.insert(successor) {
                queue.push_back(successor);
            }
        }
    }
    (seen.len(), edges)
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
struct Versions {
    policy: u8,
    card: u8,
    session: u8,
    registry: u8,
    unrelated: u8,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ReadFacts {
    versions: Versions,
    tick: u8,
    fenced: bool,
    serving: bool,
}

// memory—v1: Mutants alter one validator gate (Drop*, IgnoreCandidate, bounds,
// over-strict), one step-relation rule (StepNo*), one candidate clause (IncompleteCandidate),
// or a common-mode constant that changes permits() and validate() together. Reference is the
// unchanged fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mutant {
    Reference,
    DropPolicy,
    DropCard,
    DropSession,
    DropRegistry,
    DropServing,
    DropFence,
    DropUpperBound,
    UpperBoundInclusive,
    DropLowerBound,
    IgnoreCandidate,
    OverStrictUnrelated,
    OverStrictEqualTick,
    RejectFencedObservation,
    StepNoServingOff,
    StepNoFenceToggle,
    StepNoTick,
    CommonIgnoreRegistry,
    CommonIgnoreFence,
    CommonTickBelowThree,
    IncompleteCandidate,
}

// memory—v1: Time scenario of the read model. Monotone is the original fixture: the clock never
// moves back and the grant holds from tick 0. RollbackWithStart adds one backward clock step and
// starts the grant at tick 1, so the window start and the lower bound are exercised. The deny
// activation at tick 2 is the window end in both scenarios.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scenario {
    Monotone,
    RollbackWithStart,
}

impl Scenario {
    // memory—v1: First tick at which the grant is active (the winning-window start).
    fn allow_start(self) -> u8 {
        match self {
            Scenario::Monotone => 0,
            Scenario::RollbackWithStart => 1,
        }
    }

    // memory—v1: Whether the step relation may move the live clock backwards by one tick.
    fn rolls_back(self) -> bool {
        self == Scenario::RollbackWithStart
    }
}

impl ReadFacts {
    // memory—v1: Conjunction of the fixture clauses. In this fixture the base grants, odd
    // updates disable facts, and a time-dependent DENY overrides the grant starting at tick 2.
    // `skip_policy` drops only the policy-parity clause; the IncompleteCandidate mutant uses it
    // for the candidate alone.
    fn clauses(self, m: Mutant, sc: Scenario, skip_policy: bool) -> bool {
        let v = self.versions;
        let fence_ok = m == Mutant::CommonIgnoreFence || !self.fenced;
        let registry_ok = m == Mutant::CommonIgnoreRegistry || v.registry.is_multiple_of(2);
        let tick_ok = if m == Mutant::CommonTickBelowThree {
            self.tick < 3
        } else {
            self.tick < 2
        };
        let policy_ok = skip_policy || v.policy.is_multiple_of(2);
        self.serving
            && fence_ok
            && policy_ok
            && v.card.is_multiple_of(2)
            && v.session.is_multiple_of(2)
            && registry_ok
            && tick_ok
            && self.tick >= sc.allow_start()
    }

    // memory—v1: Live-state predicate. It is the oracle for every ALLOW edge under a mutant's own
    // predicate, and under the fixed Reference predicate when m is Reference.
    fn permits_with(self, m: Mutant, sc: Scenario) -> bool {
        self.clauses(m, sc, false)
    }

    // memory—v1: Candidate evaluated when the request starts. Only IncompleteCandidate differs
    // from permits_with, by omitting the policy clause.
    fn candidate_with(self, m: Mutant, sc: Scenario) -> bool {
        self.clauses(m, sc, m == Mutant::IncompleteCandidate)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ReadPhase {
    New,
    Observed { facts: ReadFacts, candidate: bool },
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ReadState {
    live: ReadFacts,
    phase: ReadPhase,
}

// memory—v1: Bound each version at two to include change-and-restore histories.
fn bump(value: &mut u8) -> bool {
    if *value == 2 {
        return false;
    }
    *value += 1;
    true
}

// memory—v1: The abstract validation uses captured policy facts, live fences and the validation
// tick. The live-state oracle is evaluated separately.
// memory—v1: Each Mutant switches off or strengthens exactly one clause; the Reference clause set
// is the original validator and the reference run is unchanged.
fn validate_with(m: Mutant, observed: ReadFacts, candidate: bool, live: ReadFacts) -> bool {
    let old = observed.versions;
    let new = live.versions;
    let candidate_ok = m == Mutant::IgnoreCandidate || candidate;
    let serving_ok = m == Mutant::DropServing || live.serving;
    let fence_ok = m == Mutant::DropFence || m == Mutant::CommonIgnoreFence || !live.fenced;
    let policy_ok = m == Mutant::DropPolicy || old.policy == new.policy;
    let card_ok = m == Mutant::DropCard || old.card == new.card;
    let session_ok = m == Mutant::DropSession || old.session == new.session;
    let registry_ok = m == Mutant::DropRegistry
        || m == Mutant::CommonIgnoreRegistry
        || old.registry == new.registry;
    let unrelated_ok = m != Mutant::OverStrictUnrelated || old.unrelated == new.unrelated;
    let observed_ok = m != Mutant::RejectFencedObservation || !observed.fenced;
    let window_ok = match m {
        Mutant::DropLowerBound => live.tick < 2,
        Mutant::DropUpperBound => observed.tick <= live.tick,
        Mutant::UpperBoundInclusive => (observed.tick..=2).contains(&live.tick),
        Mutant::OverStrictEqualTick => live.tick == observed.tick && live.tick < 2,
        Mutant::CommonTickBelowThree => (observed.tick..3).contains(&live.tick),
        _ => (observed.tick..2).contains(&live.tick),
    };
    candidate_ok
        && serving_ok
        && fence_ok
        && policy_ok
        && card_ok
        && session_ok
        && registry_ok
        && unrelated_ok
        && observed_ok
        && window_ok
}

// memory—v1: Everything one exploration of the read model observes. Soundness and witnesses are
// recorded rather than asserted so that mutant runs can be classified under either oracle.
#[derive(Debug, Default)]
struct ReadRun {
    rolls_back: bool,
    states: usize,
    edges: usize,
    phases: [usize; 3],
    allowed: usize,
    // memory—v1: ALLOW edges whose live state violates the mutant's own predicate.
    unsound: usize,
    // memory—v1: ALLOW edges whose live state violates the fixed Reference predicate.
    unsound_ref: usize,
    first_unsound: Option<ReadState>,
    unrelated: bool,
    restored: bool,
    expired: bool,
    candidate_gate: bool,
    advanced: bool,
    rejected: [bool; 6],
    // memory—v1: A candidate was rejected after the clock moved back (rollback scenario only).
    rolled_back_rejected: bool,
    tick_regressions: usize,
    fenced_candidates: usize,
    common_pass: usize,
    v4: usize,
    v5: usize,
    v4_only: usize,
    v4_only_equal_unrelated: usize,
    v4_outside_common: usize,
    scoring_unsound: usize,
}

impl ReadRun {
    // memory—v1: Reachability witnesses that the reference run must exhibit. The monotone fixture
    // must advance the tick inside an ALLOW. The rollback scenario has the single-tick window
    // [1,2), so no ALLOW advances the tick there; it must instead reject a rolled-back cut.
    fn witnesses_hold(&self) -> bool {
        let common = self.allowed > 0
            && self.unrelated
            && self.restored
            && self.expired
            && self.candidate_gate
            && self.rejected == [true; 6];
        if self.rolls_back {
            common && self.rolled_back_rejected
        } else {
            common && self.advanced
        }
    }
}

// memory—v1: Score the two validators on one Observed state. The common checks are written out
// here rather than derived from validate, so the 4,608 count is independent of validate.
// The scoring_unsound and v4_outside_common counters are redundant guards, not sampled evidence:
// an admission needs candidate = permits(F), which makes F's checked generations and tick
// satisfy the live predicate; equal generations then transfer it to the live state. The
// closed-form test records the same argument.
fn score(run: &mut ReadRun, observed: ReadFacts, candidate: bool, live: ReadFacts, sc: Scenario) {
    let common =
        candidate && live.serving && !live.fenced && (observed.tick..2).contains(&live.tick);
    let v4 = validate_with(Mutant::Reference, observed, candidate, live);
    let v5 = validate_with(Mutant::OverStrictUnrelated, observed, candidate, live);
    run.common_pass += usize::from(common);
    run.v4 += usize::from(v4);
    run.v5 += usize::from(v5);
    run.v4_outside_common += usize::from(v4 && !common);
    if v4 && !v5 {
        run.v4_only += 1;
        run.v4_only_equal_unrelated +=
            usize::from(observed.versions.unrelated == live.versions.unrelated);
    }
    if (v4 || v5) && !live.permits_with(Mutant::Reference, sc) {
        run.scoring_unsound += 1;
    }
}

// memory—v1: Explore the read model under one mutant in one scenario. The step relation, the
// candidate and the validator depend on the mutant; the Reference run is the original fixture.
fn read_model_run_in(sc: Scenario, m: Mutant) -> ReadRun {
    let initial = ReadState {
        live: ReadFacts {
            versions: Versions::default(),
            tick: 0,
            fenced: false,
            serving: true,
        },
        phase: ReadPhase::New,
    };
    let mut run = ReadRun {
        rolls_back: sc.rolls_back(),
        ..ReadRun::default()
    };
    let (states, edges) = explore(initial, |s, next| {
        for index in 0..5 {
            let mut successor = s;
            let v = &mut successor.live.versions;
            let versions = [
                &mut v.policy,
                &mut v.card,
                &mut v.session,
                &mut v.registry,
                &mut v.unrelated,
            ];
            if bump(versions[index]) {
                next.push(successor);
            }
        }
        if m != Mutant::StepNoFenceToggle {
            next.push(ReadState {
                live: ReadFacts {
                    fenced: !s.live.fenced,
                    ..s.live
                },
                ..s
            });
        }
        if s.live.serving && m != Mutant::StepNoServingOff {
            next.push(ReadState {
                live: ReadFacts {
                    serving: false,
                    ..s.live
                },
                ..s
            });
        }
        if s.live.tick < 3 && m != Mutant::StepNoTick {
            next.push(ReadState {
                live: ReadFacts {
                    tick: s.live.tick + 1,
                    ..s.live
                },
                ..s
            });
        }
        // memory—v1: The rollback step exists only in the rollback scenario and moves the clock
        // back by one tick.
        if sc.rolls_back() && s.live.tick > 0 {
            next.push(ReadState {
                live: ReadFacts {
                    tick: s.live.tick - 1,
                    ..s.live
                },
                ..s
            });
        }
        match s.phase {
            ReadPhase::New => {
                run.phases[0] += 1;
                next.push(ReadState {
                    phase: ReadPhase::Observed {
                        facts: s.live,
                        candidate: s.live.candidate_with(m, sc),
                    },
                    ..s
                });
            }
            ReadPhase::Observed { facts, candidate } => {
                run.phases[1] += 1;
                score(&mut run, facts, candidate, s.live, sc);
                run.tick_regressions += usize::from(s.live.tick < facts.tick);
                run.fenced_candidates += usize::from(facts.fenced && candidate);
                if validate_with(m, facts, candidate, s.live) {
                    if !s.live.permits_with(m, sc) {
                        run.unsound += 1;
                        run.first_unsound.get_or_insert(s);
                    }
                    if !s.live.permits_with(Mutant::Reference, sc) {
                        run.unsound_ref += 1;
                    }
                    run.allowed += 1;
                    run.unrelated |= facts.versions.unrelated != s.live.versions.unrelated;
                    run.advanced |= s.live.tick > facts.tick;
                } else if candidate {
                    let old = facts.versions;
                    let live = s.live.versions;
                    let changes = [
                        old.policy != live.policy,
                        old.card != live.card,
                        old.session != live.session,
                        old.registry != live.registry,
                        s.live.fenced,
                        !s.live.serving,
                    ];
                    if s.live.tick == facts.tick
                        && changes.iter().filter(|&&diff| diff).count() == 1
                    {
                        for (seen, changed) in run.rejected.iter_mut().zip(changes) {
                            *seen |= changed;
                        }
                    }
                    run.rolled_back_rejected |= s.live.tick < facts.tick;
                    run.restored |=
                        old.policy == 0 && live.policy == 2 && s.live.permits_with(m, sc);
                    run.expired |= s.live.tick >= 2 && !changes.into_iter().any(|changed| changed);
                }
                let same_generations = facts.versions.policy == s.live.versions.policy
                    && facts.versions.card == s.live.versions.card
                    && facts.versions.session == s.live.versions.session
                    && facts.versions.registry == s.live.versions.registry;
                run.candidate_gate |= !candidate
                    && s.live.permits_with(m, sc)
                    && same_generations
                    && !validate_with(m, facts, candidate, s.live);
                next.push(ReadState {
                    phase: ReadPhase::Finished,
                    ..s
                });
            }
            ReadPhase::Finished => run.phases[2] += 1,
        }
    });
    run.states = states;
    run.edges = edges;
    run
}

// memory—v1: Explore the monotone read model (the original fixture) under one mutant.
fn read_model_run(m: Mutant) -> ReadRun {
    read_model_run_in(Scenario::Monotone, m)
}

#[test]
// memory—v1: Check the point-in-time refinement at the modeled validation cut.
// The pinned counts are 940,896 states, 5,117,256 transitions and 288 ALLOW edges.
fn allow_refines_live_policy_at_validation() {
    let run = read_model_run(Mutant::Reference);
    assert_eq!(
        run.unsound, 0,
        "ALLOW has no live-policy witness: {:?}",
        run.first_unsound
    );
    assert!(
        run.witnesses_hold(),
        "reachability witness missing: {run:?}"
    );
    assert_eq!(
        run.tick_regressions, 0,
        "live tick never precedes the observed tick"
    );
    assert_eq!(
        run.fenced_candidates, 0,
        "a fenced observation is never a candidate"
    );
    assert_eq!(run.states, 940_896, "read model state count");
    assert_eq!(run.edges, 5_117_256, "read model transition count");
    assert_eq!(run.allowed, 288, "read model ALLOW edge count");
    println!(
        "read model: {} states, {} transitions, {} ALLOW edges",
        run.states, run.edges, run.allowed
    );
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Record {
    Unused,
    SetPolicy(bool),
    Deny { observation: u8 },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Process {
    Serving,
    Crashed { retained: u8 },
    Recovered { policy: bool },
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct JournalState {
    log: [Record; 3],
    len: u8,
    written: u8,
    durable: u8,
    database: u8,
    database_policy: bool,
    // memory—v1: True after a database commit whose outcome the owner has not read back.
    // It is always false outside the UncertainDatabase scenario.
    database_unknown: bool,
    sync_target: Option<u8>,
    publication: bool,
    observed_deny: Option<u8>,
    acknowledged: u8,
    uncertain: bool,
    process: Process,
}

impl JournalState {
    // memory—v1: The independent sequential reducer ignores audit-only frames.
    fn policy_at(self, prefix: u8) -> bool {
        self.log[..usize::from(prefix)]
            .iter()
            .rev()
            .find_map(|record| match record {
                Record::SetPolicy(value) => Some(*value),
                _ => None,
            })
            .unwrap_or(false)
    }

    // memory—v1: Reserve the record and publish it in the same model step (target order). The
    // PublicationInverted and DenyResetsPublication mutants alter only this publication rule.
    fn add(mut self, record: Record, m: JournalMutant) -> Self {
        self.log[usize::from(self.len)] = record;
        self.len += 1;
        match record {
            Record::SetPolicy(value) => {
                self.publication = if m == JournalMutant::PublicationInverted {
                    !value
                } else {
                    value
                };
            }
            Record::Deny { .. } => {
                if m == JournalMutant::DenyResetsPublication {
                    self.publication = false;
                }
            }
            Record::Unused => {}
        }
        self
    }
}

// memory—v1: Journal mutants alter one step-relation rule. Each one is classified by the
// refinement checks (violations) or by the witnesses that the reference reaches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalMutant {
    Reference,
    AckBeforeDurable,
    DenyNotCaptured,
    DatabaseAheadOfDurable,
    DatabaseNeverAdvances,
    CrashRetainedBelowDurable,
    BatchCapturesUnwritten,
    RecoveryIgnoresDatabase,
    NoUncertainSync,
    SingleMutation,
    SingleFrameSync,
    DenyCapturedWhenGranted,
    PublicationInverted,
    DenyResetsPublication,
    DatabaseSkipsSetPolicy,
    DatabaseWrongPolicyOnDeny,
    // memory—v1: Only in the UncertainDatabase scenario: an uncertain commit advances the checkpoint
    // without applying the policy. It is not in JOURNAL_MATRIX; the scenario test requires it to fail.
    NonAtomicUncertainCommit,
}

// memory—v1: Journal scenario. Sticky is the original fixture and the production behaviour: after
// an uncertain sync round the owner accepts no further append, confirmation or response, since
// the failure is sticky. RetryAfterUncertain reads the target text (an uncertain round adds no
// confirmation; a later round may run) as permitting progress after the uncertain round.
// UncertainDatabase lets a database commit finish with the outcome unknown to the owner. Each
// outcome is atomic; the owner reads back (reconcile) before applying the next frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalScenario {
    Sticky,
    RetryAfterUncertain,
    UncertainDatabase,
}

impl JournalScenario {
    // memory—v1: Whether progress (append, sync start, acknowledgement) continues after an
    // uncertain sync round.
    fn resumes_after_uncertain(self) -> bool {
        self == JournalScenario::RetryAfterUncertain
    }
}

// memory—v1: Witnesses, refinement violations and state counts of one journal run.
#[derive(Debug, Default)]
struct JournalRun {
    states: usize,
    edges: usize,
    success: bool,
    deny_at_zero: bool,
    deny_after_mutations: bool,
    batch: bool,
    recovered_extra: bool,
    visible_before_sync: bool,
    volatile_loss: bool,
    uncertain: bool,
    two_mutations: bool,
    resumed_after_uncertain: bool,
    db_uncertain_commit: bool,
    db_uncertain_abort: bool,
    db_reconciled: bool,
    violations: usize,
    // memory—v1: Names of the refinement checks that failed at least once.
    failed_checks: BTreeSet<&'static str>,
    first_violation: Option<String>,
}

impl JournalRun {
    // memory—v1: Record a refinement violation without panicking, so a mutant can be counted.
    fn check(&mut self, ok: bool, state: JournalState, what: &'static str) {
        if !ok {
            self.violations += 1;
            self.failed_checks.insert(what);
            self.first_violation
                .get_or_insert_with(|| format!("{what}: {state:?}"));
        }
    }

    // memory—v1: Reachability witnesses that the Sticky reference run must exhibit.
    fn witnesses_hold(&self) -> bool {
        self.success
            && self.deny_at_zero
            && self.deny_after_mutations
            && self.batch
            && self.recovered_extra
            && self.visible_before_sync
            && self.volatile_loss
            && self.uncertain
            && self.two_mutations
    }

    // memory—v1: Witnesses that only a non-default journal scenario can exhibit.
    fn scenario_witness(&self, sc: JournalScenario) -> bool {
        match sc {
            JournalScenario::Sticky => true,
            JournalScenario::RetryAfterUncertain => self.resumed_after_uncertain,
            JournalScenario::UncertainDatabase => {
                self.db_uncertain_commit && self.db_uncertain_abort && self.db_reconciled
            }
        }
    }
}

// memory—v1: Model one owner, at most two mutations, one observed DENY and one reboot. Refinement
// checks are recorded in `w`. The Reference mutant in the Sticky scenario leaves every rule unchanged.
fn journal_steps(
    s: JournalState,
    next: &mut Vec<JournalState>,
    w: &mut JournalRun,
    m: JournalMutant,
    sc: JournalScenario,
) {
    w.check(
        s.database <= s.durable && s.durable <= s.written && s.written <= s.len,
        s,
        "frame counters ordered",
    );
    w.check(
        s.publication == s.policy_at(s.len),
        s,
        "publication equals reducer at len",
    );
    w.check(
        s.database_policy == s.policy_at(s.database),
        s,
        "database policy equals reducer at database",
    );
    let mutations = s
        .log
        .iter()
        .filter(|entry| matches!(entry, Record::SetPolicy(_)))
        .count();
    w.two_mutations |= mutations == 2;
    for index in 0..s.len {
        if s.acknowledged & (1 << index) == 0 {
            continue;
        }
        w.check(index < s.durable, s, "response lacks durable frame");
        if let Record::Deny { observation } = s.log[usize::from(index)] {
            w.check(
                observation <= index && !s.policy_at(observation),
                s,
                "DENY evidence mismatch",
            );
            w.deny_at_zero |= observation == 0;
            w.deny_after_mutations |= observation > 0;
        } else {
            w.success = true;
        }
    }
    match s.process {
        Process::Serving => {}
        Process::Crashed { retained } => {
            w.check(
                s.durable <= retained && retained <= s.written,
                s,
                "retained prefix lies in [durable, written]",
            );
            let mut policy = if m == JournalMutant::RecoveryIgnoresDatabase {
                false
            } else {
                s.database_policy
            };
            // memory—v1: Replay from the database position; an empty range replays nothing.
            for record in s
                .log
                .iter()
                .take(usize::from(retained))
                .skip(usize::from(s.database))
            {
                if let Record::SetPolicy(value) = record {
                    policy = *value;
                }
            }
            w.check(
                policy == s.policy_at(retained),
                s,
                "replay equals sequential reducer",
            );
            w.recovered_extra |= retained > s.durable;
            w.volatile_loss |= policy != s.publication;
            next.push(JournalState {
                process: Process::Recovered { policy },
                ..s
            });
            return;
        }
        Process::Recovered { .. } => return,
    }

    w.visible_before_sync |= s.publication && !s.policy_at(s.durable);
    w.uncertain |= s.uncertain;
    if !s.uncertain || sc.resumes_after_uncertain() {
        let mutation_limit = if m == JournalMutant::SingleMutation {
            1
        } else {
            2
        };
        if mutations < mutation_limit {
            next.push(s.add(Record::SetPolicy(!s.publication), m));
        }
        let capture_allowed = m == JournalMutant::DenyCapturedWhenGranted || !s.publication;
        if s.observed_deny.is_none() && capture_allowed && m != JournalMutant::DenyNotCaptured {
            next.push(JournalState {
                observed_deny: Some(s.len),
                ..s
            });
        }
        if let Some(observation) = s.observed_deny {
            if !s
                .log
                .iter()
                .any(|entry| matches!(entry, Record::Deny { .. }))
            {
                next.push(s.add(Record::Deny { observation }, m));
            }
        }
        if s.written < s.len {
            next.push(JournalState {
                written: s.written + 1,
                ..s
            });
        }
        if let Some(target) = s.sync_target {
            w.batch |= target - s.durable > 1;
            w.resumed_after_uncertain |= s.uncertain;
            next.push(JournalState {
                durable: target,
                sync_target: None,
                ..s
            });
            if m != JournalMutant::NoUncertainSync {
                next.push(JournalState {
                    uncertain: true,
                    sync_target: None,
                    ..s
                });
            }
        } else if s.durable < s.written {
            let target = match m {
                JournalMutant::SingleFrameSync => s.durable + 1,
                JournalMutant::BatchCapturesUnwritten => s.len,
                _ => s.written,
            };
            next.push(JournalState {
                sync_target: Some(target),
                ..s
            });
        }
        let ack_limit = if m == JournalMutant::AckBeforeDurable {
            s.written
        } else {
            s.durable
        };
        for index in 0..ack_limit {
            next.push(JournalState {
                acknowledged: s.acknowledged | (1 << index),
                ..s
            });
        }
    }
    let database_limit = if m == JournalMutant::DatabaseAheadOfDurable {
        s.written
    } else {
        s.durable
    };
    if m != JournalMutant::DatabaseNeverAdvances
        && s.database < database_limit
        && !s.database_unknown
    {
        let advanced = match s.log[usize::from(s.database)] {
            Record::SetPolicy(policy) => Some(if m == JournalMutant::DatabaseSkipsSetPolicy {
                s.database_policy
            } else {
                policy
            }),
            Record::Deny { .. } => Some(if m == JournalMutant::DatabaseWrongPolicyOnDeny {
                !s.database_policy
            } else {
                s.database_policy
            }),
            Record::Unused => None,
        };
        match advanced {
            Some(database_policy) => {
                next.push(JournalState {
                    database: s.database + 1,
                    database_policy,
                    ..s
                });
                // memory—v1: An uncertain commit either applied the frame (atomically) or did not;
                // the owner cannot tell which until it reads back.
                if sc == JournalScenario::UncertainDatabase {
                    w.db_uncertain_commit = true;
                    let committed_policy = if m == JournalMutant::NonAtomicUncertainCommit {
                        s.database_policy
                    } else {
                        database_policy
                    };
                    next.push(JournalState {
                        database: s.database + 1,
                        database_policy: committed_policy,
                        database_unknown: true,
                        ..s
                    });
                    w.db_uncertain_abort = true;
                    next.push(JournalState {
                        database_unknown: true,
                        ..s
                    });
                }
            }
            None => w.check(false, s, "database advanced over an unwritten position"),
        }
    }
    if sc == JournalScenario::UncertainDatabase && s.database_unknown {
        w.db_reconciled = true;
        next.push(JournalState {
            database_unknown: false,
            ..s
        });
    }
    let retained_from = if m == JournalMutant::CrashRetainedBelowDurable {
        s.database
    } else {
        s.durable
    };
    for retained in retained_from..=s.written {
        next.push(JournalState {
            process: Process::Crashed { retained },
            ..s
        });
    }
}

// memory—v1: Explore the journal model under one mutant and scenario from the empty journal.
fn journal_model_run_in(m: JournalMutant, sc: JournalScenario) -> JournalRun {
    let initial = JournalState {
        log: [Record::Unused; 3],
        len: 0,
        written: 0,
        durable: 0,
        database: 0,
        database_policy: false,
        database_unknown: false,
        sync_target: None,
        publication: false,
        observed_deny: None,
        acknowledged: 0,
        uncertain: false,
        process: Process::Serving,
    };
    let mut run = JournalRun::default();
    let (states, edges) = explore(initial, |s, next| journal_steps(s, next, &mut run, m, sc));
    run.states = states;
    run.edges = edges;
    run
}

// memory—v1: Explore the Sticky journal model (the original fixture) under one mutant.
fn journal_model_run(m: JournalMutant) -> JournalRun {
    journal_model_run_in(m, JournalScenario::Sticky)
}

#[test]
// memory—v1: Check response ordering, durable prefixes and equivalent replay.
fn responses_and_recovery_refine_the_journal_prefix() {
    let run = journal_model_run(JournalMutant::Reference);
    assert_eq!(
        run.violations, 0,
        "journal refinement violated: {:?}",
        run.first_violation
    );
    assert!(run.witnesses_hold(), "journal witness missing: {run:?}");
    // memory—v1: Pinned counts of the exhaustive journal-model exploration.
    assert_eq!(run.states, 2_969, "journal model state count");
    assert_eq!(run.edges, 4_623, "journal model transition count");
    println!(
        "journal model: {} states, {} transitions",
        run.states, run.edges
    );
}

// memory—v1: Closed forms of the monotone read model. Live states are five versions with values
// 0..=2, a tick 0..=3, a fence bit and a serving bit: 3^5*4*2*2 = 3,888. An Observed state pairs
// the captured facts with a live state reachable from them: versions 6 pairs per dimension
// (old <= new), ticks 10 pairs (a <= b), fence 4 (free), serving 3 (only off after capture):
// 6^5*10*4*3 = 933,120.
const LIVE_STATES: usize = 3usize.pow(5) * 4 * 2 * 2;
const OBSERVED_STATES: usize = 6usize.pow(5) * 10 * 4 * 3;
// memory—v1: Common checks (candidate, live serving, unfenced, observed.tick <= live.tick < 2)
// leave 4 pairs per checked generation, 6 unrelated pairs and 3 tick pairs: 4^4*6*3 = 4,608.
const COMMON_EDGES: usize = 4usize.pow(4) * 6 * 3;
// memory—v1: V4 requires the four checked generations equal (2 of 4 pairs each): 2^4*6*3 = 288.
const V4_ADMITS: usize = 2usize.pow(4) * 6 * 3;
// memory—v1: V5 also requires the unrelated generation equal (3 of 6 pairs): 2^4*3*3 = 144.
const V5_ADMITS: usize = 2usize.pow(4) * 3 * 3;

// memory—v1: Closed-form transition count of the monotone graph, summed over the three phases.
// With N = 3,888 live states, a live state has out-degree b + 1 + s + t, where b counts versions
// below 2 (bump), 1 is the fence toggle, s = [serving], t = [tick < 3]. New and Observed states
// add one phase edge each; Finished states add none. Sums over live states:
// b = 5*2*3^4*4*2*2 = 12,960; s = 1,944; t = 2,916. Observed states are weighted by
// W(L) = prod(v+1) * (tick+1) * 2 * (1 if serving else 2): sum W = 933,120,
// sum W*b = 5*3*6^4*10*4*3 = 2,332,800, sum W*s = 6^5*10*4*1 = 311,040,
// sum W*t = 6^5*6*4*3 = 559,872. Total = (b + 2N + s + t) + (W*b + 2W + W*s + W*t)
// + (b + N + s + t) = 5,117,256.
fn closed_form_read_edges() -> usize {
    let n = LIVE_STATES;
    let sum_b = 5 * 2 * 3usize.pow(4) * 4 * 2 * 2;
    let sum_s = n / 2;
    let sum_t = n * 3 / 4;
    let w_total = OBSERVED_STATES;
    let w_b = 5 * 3 * 6usize.pow(4) * 10 * 4 * 3;
    let w_s = 6usize.pow(5) * 10 * 4;
    let w_t = 6usize.pow(5) * 6 * 4 * 3;
    (sum_b + 2 * n + sum_s + sum_t) + (w_b + 2 * w_total + w_s + w_t) + (sum_b + n + sum_s + sum_t)
}

#[test]
// memory—v1: Closed forms and scored validators on the monotone Observed graph. Pinned values:
// 3,888 + 933,120 + 3,888 states, 4,608 common-check edges, 288 V4 and 144 V5 admissions.
// The 144 V4-only admissions are a counting identity of this fixture (the cuts at which only the
// unrelated generation moved), not an empirical availability measurement. The soundness counters
// (unsound, scoring_unsound, v4_outside_common) are redundant guards. An admission requires
// candidate = permits(F), which forces F's checked generations and tick to satisfy the live
// predicate, and equal generations transfer it to the live state. Hence these counters are zero
// for this validator on every graph, by the structure of its guards. They detect a regression in
// the guards and are not evidence about the explored graph. The discriminating content is the
// counts and the mutation matrix.
// Command: cargo test -p test-harness --test memory_v1_authority_model closed_forms
fn closed_forms_and_scored_validators_match_the_graph() {
    let run = read_model_run(Mutant::Reference);
    assert_eq!(run.phases, [LIVE_STATES, OBSERVED_STATES, LIVE_STATES]);
    assert_eq!(run.states, LIVE_STATES + OBSERVED_STATES + LIVE_STATES);
    assert_eq!(
        run.edges,
        closed_form_read_edges(),
        "closed-form transition count"
    );
    assert_eq!(run.common_pass, COMMON_EDGES, "common-check edges");
    assert_eq!(run.v4, V4_ADMITS, "V4 admissions");
    assert_eq!(run.v5, V5_ADMITS, "V5 admissions");
    assert_eq!(run.v4_only, V4_ADMITS - V5_ADMITS, "V4-only admissions");
    assert_eq!(
        run.v4_only_equal_unrelated, 0,
        "every V4-only admission changes unrelated"
    );
    assert_eq!(
        run.v4_outside_common, 0,
        "V4 admits only common-check edges"
    );
    assert_eq!(
        run.scoring_unsound, 0,
        "every admission of both validators is live-sound"
    );
    assert_eq!(run.unsound, 0, "every reference ALLOW is live-sound");
    println!(
        "closed forms: {} states, {} transitions; common {}, V4 {}, V5 {}, V4-only {}",
        run.states, run.edges, run.common_pass, run.v4, run.v5, run.v4_only
    );
}

// memory—v1: Closed forms of the rollback scenario. Live states are as in the monotone fixture
// (3,888), because a backward tick step only adds edges. Observed pairs: versions 6 per
// dimension, tick 16 (any pair, since the clock can roll back), fence 4 (free), serving 3:
// 6^5*16*4*3 = 1,492,992.
const ROLLBACK_OBSERVED_STATES: usize = 6usize.pow(5) * 16 * 4 * 3;
// memory—v1: ALLOW edges of the rollback scenario under the Reference validator. The candidate
// and the window [1,2) admit only observed and live tick 1; serving and fence are fixed; the four
// checked generations are even and equal (2 each); the unrelated generation has 6 pairs:
// 2^4*6 = 96.
const ROLLBACK_ALLOWS: usize = 2usize.pow(4) * 6;

// memory—v1: Closed-form transition count of the rollback scenario. A live state has out-degree
// b + 1 + s + t + r, adding r = [tick > 0] to the monotone degree. Sums over the 3,888 live
// states: b = 12,960, s = 1,944, t = r = 2,916, so the live degree sum is 24,624. Observed states
// are weighted by W(L) = prod(v+1) * 4 (tick) * 2 (fence) * sigma(serving), with sigma = 1 when
// serving and 2 otherwise. The weighted sums are: W*b = 5*3*6^4*16*4*3 = 3,732,480;
// W*s = 6^5*16*4*1 = 497,664; W*t = W*r = 6^5*12*4*3 = 1,119,744; sum W = 1,492,992.
// Total = (24,624 + N) + (W*b + W + W*s + W*t + W*r + W) + 24,624 = 9,508,752.
fn closed_form_rollback_edges() -> usize {
    let n = LIVE_STATES;
    let w = ROLLBACK_OBSERVED_STATES;
    let sum_b = 5 * 2 * 3usize.pow(4) * 4 * 2 * 2;
    let sum_s = n / 2;
    let sum_t = n * 3 / 4;
    let sum_r = n * 3 / 4;
    let live_degree = sum_b + n + sum_s + sum_t + sum_r;
    let w_b = 5 * 3 * 6usize.pow(4) * 16 * 4 * 3;
    let w_s = 6usize.pow(5) * 16 * 4;
    let w_t = 6usize.pow(5) * 12 * 4 * 3;
    let w_r = w_t;
    let observed_degree = w_b + w + w_s + w_t + w_r;
    (live_degree + n) + (observed_degree + w) + live_degree
}

#[test]
// memory—v1: Closed forms, witnesses and verdicts of the rollback scenario, where the clock may
// move back one tick and the grant starts at tick 1. The Reference must reject every rolled-back
// cut, with no unsound ALLOW under either oracle. The counts are 1,500,768 states, 9,508,752
// transitions and 96 ALLOW edges. Command: cargo test -p test-harness --test
// memory_v1_authority_model rollback_scenario (about 23 s in debug).
fn rollback_scenario_closed_forms_and_matrix() {
    let run = read_model_run_in(Scenario::RollbackWithStart, Mutant::Reference);
    assert_eq!(run.unsound, 0, "rollback ALLOW has a live-policy witness");
    assert_eq!(run.unsound_ref, 0, "rollback ALLOW satisfies the Reference");
    assert!(run.witnesses_hold(), "rollback witness missing: {run:?}");
    assert_eq!(
        run.fenced_candidates, 0,
        "a fenced observation is never a candidate"
    );
    assert_eq!(
        run.phases,
        [LIVE_STATES, ROLLBACK_OBSERVED_STATES, LIVE_STATES]
    );
    assert_eq!(
        run.states,
        LIVE_STATES + ROLLBACK_OBSERVED_STATES + LIVE_STATES,
        "rollback state count"
    );
    assert_eq!(
        run.edges,
        closed_form_rollback_edges(),
        "closed-form rollback transition count"
    );
    assert_eq!(run.allowed, ROLLBACK_ALLOWS, "rollback ALLOW edge count");
    println!(
        "rollback scenario: {} states, {} transitions, {} ALLOW edges, {} rolled-back cuts rejected",
        run.states, run.edges, run.allowed, run.rolled_back_rejected
    );
    for (mutant, by_own, by_reference) in ROLLBACK_MATRIX {
        let run = read_model_run_in(Scenario::RollbackWithStart, mutant);
        let own = classify_read(&run, Oracle::OwnPredicate);
        let fixed = classify_read(&run, Oracle::FixedReference);
        println!("rollback {mutant:?}: own predicate {own:?}, fixed reference {fixed:?}");
        assert_eq!(
            own, by_own,
            "rollback mutant {mutant:?} by own predicate: {run:?}"
        );
        assert_eq!(
            fixed, by_reference,
            "rollback mutant {mutant:?} by fixed reference: {run:?}"
        );
        // memory—v1: The equal-tick clause is equivalent on the rollback graph: its ALLOW set is the
        // Reference's single-tick set, so the count is the same 96 edges.
        if mutant == Mutant::OverStrictEqualTick {
            assert_eq!(
                run.allowed, ROLLBACK_ALLOWS,
                "equal-tick clause admits the Reference's ALLOW set on the rollback graph"
            );
        }
    }
}

// memory—v1: Verdict of one mutant. KilledBySoundness: the refinement oracle rejects an accept.
// KilledByWitness: a reachability witness fails. Survived: neither detects it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    KilledBySoundness,
    KilledByWitness,
    Survived,
}

// memory—v1: Which predicate the refinement oracle uses. OwnPredicate is the mutant's own permits();
// FixedReference is the unchanged fixture predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Oracle {
    OwnPredicate,
    FixedReference,
}

// memory—v1: Classify a read-model run under one oracle; soundness takes precedence over witnesses.
fn classify_read(run: &ReadRun, oracle: Oracle) -> Verdict {
    let unsound = match oracle {
        Oracle::OwnPredicate => run.unsound,
        Oracle::FixedReference => run.unsound_ref,
    };
    if unsound > 0 {
        Verdict::KilledBySoundness
    } else if !run.witnesses_hold() {
        Verdict::KilledByWitness
    } else {
        Verdict::Survived
    }
}

// memory—v1: Classify a journal run; refinement violations take precedence over witnesses.
fn classify_journal(run: &JournalRun) -> Verdict {
    if run.violations > 0 {
        Verdict::KilledBySoundness
    } else if !run.witnesses_hold() {
        Verdict::KilledByWitness
    } else {
        Verdict::Survived
    }
}

// memory—v1: Expected verdicts of the 20 read-model mutants on the monotone graph, as
// (mutant, by own predicate, by fixed Reference predicate). DropLowerBound is equivalent on this
// graph (live.tick never precedes observed.tick), and RejectFencedObservation is structurally
// equivalent (a fenced observation is never a candidate). CommonTickBelowThree changes the window
// and the predicate together, so its own predicate cannot see it; the fixed Reference column shows
// the disagreement. A change to the fixture itself would be invisible in both columns.
const READ_MATRIX: [(Mutant, Verdict, Verdict); 20] = [
    (
        Mutant::DropPolicy,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::DropCard,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::DropSession,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::DropRegistry,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::DropServing,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::DropFence,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::DropUpperBound,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::UpperBoundInclusive,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (Mutant::DropLowerBound, Verdict::Survived, Verdict::Survived),
    (
        Mutant::IgnoreCandidate,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::OverStrictUnrelated,
        Verdict::KilledByWitness,
        Verdict::KilledByWitness,
    ),
    (
        Mutant::OverStrictEqualTick,
        Verdict::KilledByWitness,
        Verdict::KilledByWitness,
    ),
    (
        Mutant::RejectFencedObservation,
        Verdict::Survived,
        Verdict::Survived,
    ),
    (
        Mutant::StepNoServingOff,
        Verdict::KilledByWitness,
        Verdict::KilledByWitness,
    ),
    (
        Mutant::StepNoFenceToggle,
        Verdict::KilledByWitness,
        Verdict::KilledByWitness,
    ),
    (
        Mutant::StepNoTick,
        Verdict::KilledByWitness,
        Verdict::KilledByWitness,
    ),
    (
        Mutant::CommonIgnoreRegistry,
        Verdict::KilledByWitness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::CommonIgnoreFence,
        Verdict::KilledByWitness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::CommonTickBelowThree,
        Verdict::Survived,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::IncompleteCandidate,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
];

// memory—v1: Expected verdicts of the rollback scenario for the window and common-mode mutants,
// as (mutant, by own predicate, by fixed Reference predicate). DropLowerBound is killed here:
// with the grant starting at tick 1, a cut that rolls back to tick 0 is admitted by the window
// alone, and the Reference predicate rejects it. OverStrictEqualTick survives here: its ALLOW set
// equals the Reference's, because the single-tick window admits only observed = live = 1, so the
// equal-tick clause is equivalent on this graph (it is killed only in the monotone scenario).
const ROLLBACK_MATRIX: [(Mutant, Verdict, Verdict); 5] = [
    (
        Mutant::DropLowerBound,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::DropUpperBound,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::UpperBoundInclusive,
        Verdict::KilledBySoundness,
        Verdict::KilledBySoundness,
    ),
    (
        Mutant::OverStrictEqualTick,
        Verdict::Survived,
        Verdict::Survived,
    ),
    (
        Mutant::CommonTickBelowThree,
        Verdict::Survived,
        Verdict::KilledBySoundness,
    ),
];

// memory—v1: Expected verdicts of the journal mutants in the Sticky scenario, as (mutant, verdict,
// refinement checks that must fail). The four publication and database mutants must fail the
// named check; the other entries leave the check list empty. DatabaseNeverAdvances survives:
// replaying from position zero reproduces the reducer, so database progress is not observable by
// the replay oracle.
const JOURNAL_MATRIX: [(JournalMutant, Verdict, &[&str]); 15] = [
    (
        JournalMutant::AckBeforeDurable,
        Verdict::KilledBySoundness,
        &[],
    ),
    (
        JournalMutant::DenyNotCaptured,
        Verdict::KilledByWitness,
        &[],
    ),
    (
        JournalMutant::DatabaseAheadOfDurable,
        Verdict::KilledBySoundness,
        &[],
    ),
    (JournalMutant::DatabaseNeverAdvances, Verdict::Survived, &[]),
    (
        JournalMutant::CrashRetainedBelowDurable,
        Verdict::KilledBySoundness,
        &[],
    ),
    (
        JournalMutant::BatchCapturesUnwritten,
        Verdict::KilledBySoundness,
        &[],
    ),
    (
        JournalMutant::RecoveryIgnoresDatabase,
        Verdict::KilledBySoundness,
        &[],
    ),
    (
        JournalMutant::NoUncertainSync,
        Verdict::KilledByWitness,
        &[],
    ),
    (JournalMutant::SingleMutation, Verdict::KilledByWitness, &[]),
    (
        JournalMutant::SingleFrameSync,
        Verdict::KilledByWitness,
        &[],
    ),
    (
        JournalMutant::DenyCapturedWhenGranted,
        Verdict::KilledBySoundness,
        &[],
    ),
    (
        JournalMutant::PublicationInverted,
        Verdict::KilledBySoundness,
        &["publication equals reducer at len"],
    ),
    (
        JournalMutant::DenyResetsPublication,
        Verdict::KilledBySoundness,
        &["publication equals reducer at len"],
    ),
    (
        JournalMutant::DatabaseSkipsSetPolicy,
        Verdict::KilledBySoundness,
        &["database policy equals reducer at database"],
    ),
    (
        JournalMutant::DatabaseWrongPolicyOnDeny,
        Verdict::KilledBySoundness,
        &["database policy equals reducer at database"],
    ),
];

// memory—v1: Find the run of one mutant in a matrix result. Each mutant is explored once.
fn run_for(runs: &[(Mutant, ReadRun)], m: Mutant) -> &ReadRun {
    &runs
        .iter()
        .find(|(candidate, _)| *candidate == m)
        .expect("mutant was explored by the matrix")
        .1
}

#[test]
// memory—v1: Mutation adequacy matrix for the read and journal models. Each read mutant is explored
// once and classified by its own predicate and by the fixed Reference predicate. The matrix checks
// refinement of a validator against a fixed fixture, not the correctness of the fixture. A change
// to the fixture itself (common mode) is invisible to its own oracle, and the fixed Reference
// column reveals only validator-side disagreement. Default run, about 40 s in debug.
fn mutation_adequacy_matrix() {
    let mut runs: Vec<(Mutant, ReadRun)> = Vec::new();
    for (mutant, by_own, by_reference) in READ_MATRIX {
        let run = read_model_run(mutant);
        let own = classify_read(&run, Oracle::OwnPredicate);
        let fixed = classify_read(&run, Oracle::FixedReference);
        println!("read {mutant:?}: own predicate {own:?}, fixed reference {fixed:?}");
        assert_eq!(
            own, by_own,
            "read mutant {mutant:?} by own predicate: {run:?}"
        );
        assert_eq!(
            fixed, by_reference,
            "read mutant {mutant:?} by fixed reference: {run:?}"
        );
        if matches!(
            mutant,
            Mutant::CommonIgnoreRegistry | Mutant::CommonIgnoreFence | Mutant::CommonTickBelowThree
        ) {
            assert_eq!(
                run.unsound, 0,
                "common-mode {mutant:?} is invisible to its own predicate"
            );
            assert!(
                run.unsound_ref > 0,
                "common-mode {mutant:?} is visible to the fixed Reference predicate"
            );
        }
        runs.push((mutant, run));
    }
    let equivalent = run_for(&runs, Mutant::DropLowerBound);
    assert_eq!(
        equivalent.tick_regressions, 0,
        "the lower bound never binds"
    );
    let fenced = run_for(&runs, Mutant::RejectFencedObservation);
    assert_eq!(
        fenced.fenced_candidates, 0,
        "a fenced observation is never a candidate"
    );
    // memory—v1: The original witness set (before the advanced-tick witness) misses
    // OverStrictEqualTick; the advanced-tick witness is what kills it.
    let equal_tick = run_for(&runs, Mutant::OverStrictEqualTick);
    let original_witnesses = equal_tick.allowed > 0
        && equal_tick.unrelated
        && equal_tick.restored
        && equal_tick.expired
        && equal_tick.rejected == [true; 6];
    assert!(
        original_witnesses,
        "original witnesses hold under OverStrictEqualTick"
    );
    assert!(
        !equal_tick.advanced,
        "no ALLOW advances the tick under OverStrictEqualTick"
    );
    for (mutant, expected, checks) in JOURNAL_MATRIX {
        let run = journal_model_run(mutant);
        let verdict = classify_journal(&run);
        println!("journal {mutant:?}: {verdict:?}");
        assert_eq!(verdict, expected, "journal mutant {mutant:?}: {run:?}");
        for check in checks {
            assert!(
                run.failed_checks.contains(check),
                "journal mutant {mutant:?} must fail the check '{check}': {run:?}"
            );
        }
    }
}

#[test]
// memory—v1: Refinement, witnesses and pinned counts of the two non-default journal scenarios.
// Both use the Reference mutant. The pinned counts are breadth-first counts of the explicit
// graphs, not closed forms. The Sticky reference never exhibits the non-default witnesses.
fn journal_scenarios_refine_the_prefix() {
    let sticky = journal_model_run(JournalMutant::Reference);
    assert!(
        !sticky.resumed_after_uncertain && !sticky.db_uncertain_commit,
        "the Sticky reference exhibits no non-default behaviour"
    );
    let retry = journal_model_run_in(
        JournalMutant::Reference,
        JournalScenario::RetryAfterUncertain,
    );
    assert_eq!(
        retry.violations, 0,
        "retry-after-uncertain refinement violated: {:?}",
        retry.first_violation
    );
    assert!(
        retry.witnesses_hold() && retry.scenario_witness(JournalScenario::RetryAfterUncertain),
        "retry-after-uncertain witness missing: {retry:?}"
    );
    assert_eq!(
        retry.states, 4_650,
        "retry-after-uncertain state count (breadth-first)"
    );
    assert_eq!(
        retry.edges, 7_945,
        "retry-after-uncertain transition count (breadth-first)"
    );
    println!(
        "journal retry-after-uncertain: {} states, {} transitions",
        retry.states, retry.edges
    );
    let uncertain_db =
        journal_model_run_in(JournalMutant::Reference, JournalScenario::UncertainDatabase);
    assert_eq!(
        uncertain_db.violations, 0,
        "uncertain-database refinement violated: {:?}",
        uncertain_db.first_violation
    );
    assert!(
        uncertain_db.witnesses_hold()
            && uncertain_db.scenario_witness(JournalScenario::UncertainDatabase),
        "uncertain-database witness missing: {uncertain_db:?}"
    );
    assert_eq!(
        uncertain_db.states, 5_369,
        "uncertain-database state count (breadth-first)"
    );
    assert_eq!(
        uncertain_db.edges, 9_475,
        "uncertain-database transition count (breadth-first)"
    );
    println!(
        "journal uncertain-database: {} states, {} transitions",
        uncertain_db.states, uncertain_db.edges
    );
    // memory—v1: Faulty variant of the uncertain commit: the checkpoint advances without the
    // policy. The database check must fail, so the atomicity premise is observable in this scenario.
    let non_atomic = journal_model_run_in(
        JournalMutant::NonAtomicUncertainCommit,
        JournalScenario::UncertainDatabase,
    );
    assert_eq!(
        classify_journal(&non_atomic),
        Verdict::KilledBySoundness,
        "non-atomic uncertain commit is killed: {non_atomic:?}"
    );
    assert!(
        non_atomic
            .failed_checks
            .contains("database policy equals reducer at database"),
        "non-atomic uncertain commit must fail the database check: {non_atomic:?}"
    );
}
