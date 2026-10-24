use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

pub const MODEL: &str = "projection-owner-abstract-model";
pub const VERSION: &str = "2.3.0";
pub const DEFAULT_MAX_STATES: usize = 20_000;
pub const DEFAULT_MAX_DEPTH: usize = 64;
pub const MAX_STATES: usize = 20_000;
pub const MAX_DEPTH: usize = 64;
pub const MAX_LEASE_EPISODES_PER_EVENT: u8 = 2;
pub const MAX_PROVEN_FAILURES_PER_EVENT: u8 = 1;
pub const MAX_REVOKES: u8 = 1;
pub const MAX_TARGETS_PER_CALL: u8 = 32;
pub const MAX_NON_TARGETS_PER_CALL: u8 = 1;

const NO_OWNER: u8 = u8::MAX;
const NO_READ: u8 = 0;
const ALLOW: u8 = 1;
const PENDING_DENY: u8 = 2;
const EVENT_COUNT: usize = 2;
const NO_PREDECESSOR: i8 = -1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Phase {
    Pending,
    Leased,
    Executing,
    Unknown,
    Published,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Leased => "LEASED",
            Self::Executing => "EXECUTING",
            Self::Unknown => "UNKNOWN",
            Self::Published => "PUBLISHED",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct State {
    phase: [Phase; EVENT_COUNT],
    owner: [u8; EVENT_COUNT],
    token: [u8; EVENT_COUNT],
    owner_epoch: [u8; EVENT_COUNT],
    lease_installs: [u8; EVENT_COUNT],
    attempts: [u8; EVENT_COUNT],
    execs: [u8; EVENT_COUNT],
    failures: [u8; EVENT_COUNT],
    failure_cap: [bool; EVENT_COUNT],
    aggregate_epoch: u8,
    previous_owner: [u8; EVENT_COUNT],
    previous_token: [u8; EVENT_COUNT],
    previous_epoch: [u8; EVENT_COUNT],
    stale_release_done: [bool; EVENT_COUNT],
    source_generation: u8,
    revoke_fence: u8,
    revoke_count: u8,
    revoked: bool,
    manifest_generation: u8,
    manifest_events: u8,
    current_generation: u8,
    current_events: u8,
    impact_events: u8,
    proof_events: u8,
    receipt_events: u8,
    published_order: [u8; EVENT_COUNT],
    published_len: u8,
    nudges: u8,
    recovered: u8,
    unknown: u8,
    read_decisions: [u8; EVENT_COUNT],
    bad_binding: bool,
    bad_release: bool,
    budget_polluted: bool,
    bad_receipt: bool,
}

impl State {
    fn initial() -> Self {
        Self {
            phase: [Phase::Pending; EVENT_COUNT],
            owner: [NO_OWNER; EVENT_COUNT],
            token: [0; EVENT_COUNT],
            owner_epoch: [0; EVENT_COUNT],
            lease_installs: [0; EVENT_COUNT],
            attempts: [0; EVENT_COUNT],
            execs: [0; EVENT_COUNT],
            failures: [0; EVENT_COUNT],
            failure_cap: [false; EVENT_COUNT],
            aggregate_epoch: 0,
            previous_owner: [NO_OWNER; EVENT_COUNT],
            previous_token: [0; EVENT_COUNT],
            previous_epoch: [0; EVENT_COUNT],
            stale_release_done: [false; EVENT_COUNT],
            source_generation: 1,
            revoke_fence: 0,
            revoke_count: 0,
            revoked: false,
            manifest_generation: 0,
            manifest_events: 0,
            current_generation: 0,
            current_events: 0,
            impact_events: 0,
            proof_events: 0,
            receipt_events: 0,
            published_order: [0; EVENT_COUNT],
            published_len: 0,
            nudges: 0b11,
            recovered: 0,
            unknown: 0,
            read_decisions: [NO_READ; EVENT_COUNT],
            bad_binding: false,
            bad_release: false,
            budget_polluted: false,
            bad_receipt: false,
        }
    }

    fn has_owner(&self) -> bool {
        self.owner.iter().any(|owner| *owner != NO_OWNER)
    }

    fn has_unknown(&self) -> bool {
        self.unknown != 0
    }

    fn record_published(&mut self, event: usize) {
        let index = usize::from(self.published_len);
        if index < EVENT_COUNT {
            self.published_order[index] = event as u8;
            self.published_len += 1;
        }
    }

    fn published_events(&self) -> &[u8] {
        &self.published_order[..usize::from(self.published_len)]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Premises {
    pub exact_binding: bool,
    pub single_active_slot: bool,
    pub epoch_fence: bool,
    pub random_token_fence: bool,
    pub worker_owner_check: bool,
    pub release_ownership_fence: bool,
    pub atomic_publication: bool,
    pub durable_source_receipt: bool,
    pub failure_budget_clean: bool,
    pub strict_read_gate: bool,
}

impl Default for Premises {
    fn default() -> Self {
        Self {
            exact_binding: true,
            single_active_slot: true,
            epoch_fence: true,
            random_token_fence: true,
            worker_owner_check: true,
            release_ownership_fence: true,
            atomic_publication: true,
            durable_source_receipt: true,
            failure_budget_clean: true,
            strict_read_gate: true,
        }
    }
}

impl Premises {
    #[cfg(test)]
    fn without(mut self, premise: &str) -> Result<Self, String> {
        match premise {
            "exact_binding" => self.exact_binding = false,
            "single_active_slot" => self.single_active_slot = false,
            "epoch_fence" => self.epoch_fence = false,
            "random_token_fence" => self.random_token_fence = false,
            "worker_owner_check" => self.worker_owner_check = false,
            "release_ownership_fence" => self.release_ownership_fence = false,
            "atomic_publication" => self.atomic_publication = false,
            "durable_source_receipt" => self.durable_source_receipt = false,
            "failure_budget_clean" => self.failure_budget_clean = false,
            "strict_read_gate" => self.strict_read_gate = false,
            _ => return Err(format!("unknown premise: {premise}")),
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug)]
struct Scenario {
    name: &'static str,
    grants: [&'static str; EVENT_COUNT],
    revisions: [u8; EVENT_COUNT],
    predecessors: [i8; EVENT_COUNT],
    request_events: [usize; EVENT_COUNT],
    source_generations: [u8; EVENT_COUNT],
    delta_event_ids: [u8; EVENT_COUNT],
    durable_receipts: bool,
}

impl Scenario {
    fn receipt(self, event: usize) -> Receipt {
        Receipt {
            event,
            aggregate: "aggregate-A",
            grant: self.grants[event],
            revision: self.revisions[event],
            source_generation: self.source_generations[event],
        }
    }

    fn aggregate_key(self, event: usize) -> (u8, u8) {
        (self.source_generations[event], self.delta_event_ids[event])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Receipt {
    event: usize,
    aggregate: &'static str,
    grant: &'static str,
    revision: u8,
    source_generation: u8,
}

const SCENARIOS: [Scenario; 3] = [
    Scenario {
        name: "same-grant-duplicate-and-predecessor-chain",
        grants: ["G", "G"],
        revisions: [1, 2],
        predecessors: [NO_PREDECESSOR, 0],
        request_events: [0, 0],
        source_generations: [1, 1],
        delta_event_ids: [1, 2],
        durable_receipts: true,
    },
    Scenario {
        name: "same-grant-request-predecessor-chain",
        grants: ["G", "G"],
        revisions: [1, 2],
        predecessors: [NO_PREDECESSOR, 0],
        request_events: [0, 1],
        source_generations: [1, 1],
        delta_event_ids: [1, 2],
        durable_receipts: true,
    },
    Scenario {
        name: "independent-grants-same-aggregate",
        grants: ["G", "H"],
        revisions: [1, 1],
        predecessors: [NO_PREDECESSOR; EVENT_COUNT],
        request_events: [0, 1],
        source_generations: [1, 1],
        delta_event_ids: [7, 7],
        durable_receipts: true,
    },
];

const ACTIVE_SLOT_SCENARIO: Scenario = Scenario {
    name: "active-slot-control-fixture",
    grants: ["G", "H"],
    revisions: [1, 1],
    predecessors: [NO_PREDECESSOR; EVENT_COUNT],
    request_events: [0, 1],
    source_generations: [1, 1],
    delta_event_ids: [1, 1],
    durable_receipts: true,
};

const ORDER_SCENARIO: Scenario = Scenario {
    name: "aggregate-source-generation-delta-id-order",
    grants: ["G", "H"],
    revisions: [1, 1],
    predecessors: [NO_PREDECESSOR; EVENT_COUNT],
    request_events: [1, 0],
    source_generations: [7, 64],
    delta_event_ids: [7, 64],
    durable_receipts: true,
};

const SCENARIO_WITNESSES: [(&str, &[&str]); 3] = [
    (
        "same-grant-duplicate",
        &[
            "W0 claims E0 for R0",
            "W1 gets BUSY before lease for duplicate R1",
            "W0 begins E0 once",
            "W0 publishes E0 atomically",
            "R1 observes E0 already published",
            "recovery scans lost E1 nudge",
        ],
    ),
    (
        "same-grant-predecessor",
        &[
            "publish E0",
            "recovery enables E1",
            "claim E1 only after E0 predecessor",
            "publish E1",
            "final read uses current/manifest/impact/proof gate",
        ],
    ),
    (
        "independent-grants",
        &[
            "W0 owns E0",
            "W1 gets BUSY before lease for E1",
            "W0 publishes E0",
            "W1 claims E1",
            "W1 publishes E1 independently",
        ],
    ),
];

fn bit(event: usize) -> u8 {
    1 << event
}

fn aggregate_predecessor_exists(state: &State, scenario: Scenario, event: usize) -> bool {
    let candidate_key = scenario.aggregate_key(event);
    (0..EVENT_COUNT).any(|predecessor| {
        scenario.aggregate_key(predecessor) < candidate_key
            && state.phase[predecessor] != Phase::Published
    })
}

fn eligible(state: &State, scenario: Scenario, event: usize) -> bool {
    let predecessor = scenario.predecessors[event];
    predecessor < 0 || state.phase[predecessor as usize] == Phase::Published
}

fn publication_proven(state: &State, event: usize) -> bool {
    let event_bit = bit(event);
    state.manifest_events & event_bit != 0
        && state.current_events & event_bit != 0
        && state.impact_events & event_bit != 0
        && state.proof_events & event_bit != 0
        && state.receipt_events & event_bit != 0
        && state.current_generation == state.manifest_generation
}

fn stale_release_is_rejected(
    state: &State,
    event: usize,
    actor: u8,
    old_token: u8,
    old_epoch: u8,
    premises: Premises,
) -> bool {
    if !premises.release_ownership_fence {
        return false;
    }
    (premises.worker_owner_check && actor != state.owner[event])
        || (premises.random_token_fence && old_token != state.token[event])
        || (premises.epoch_fence && old_epoch != state.owner_epoch[event])
}

fn transitions(
    state: &State,
    scenario: Scenario,
    premises: Premises,
) -> Vec<(&'static str, State)> {
    let mut result = Vec::new();

    for worker in 0..2u8 {
        for request in [Some(0usize), Some(1usize), None] {
            for event in 0..EVENT_COUNT {
                if state.revoked || !eligible(state, scenario, event) {
                    continue;
                }
                if state.phase[event] != Phase::Pending || state.owner[event] != NO_OWNER {
                    continue;
                }
                if state.failure_cap[event]
                    || state.failures[event] >= MAX_PROVEN_FAILURES_PER_EVENT
                {
                    continue;
                }
                if state.lease_installs[event] >= MAX_LEASE_EPISODES_PER_EVENT {
                    continue;
                }
                let event_bit = bit(event);
                if (state.nudges | state.recovered) & event_bit == 0 {
                    continue;
                }
                let matches = request.is_none_or(|request| {
                    scenario.receipt(scenario.request_events[request]) == scenario.receipt(event)
                });
                if request.is_none() && state.recovered & event_bit == 0 {
                    continue;
                }
                if premises.exact_binding && !matches {
                    continue;
                }
                if state.has_unknown() {
                    result.push(("busy-before-unknown", state.clone()));
                    continue;
                }
                if aggregate_predecessor_exists(state, scenario, event) {
                    result.push(("busy-before-aggregate-predecessor", state.clone()));
                    continue;
                }
                if premises.single_active_slot && state.has_owner() {
                    let mut successor = state.clone();
                    if !premises.failure_budget_clean {
                        successor.failures[event] += 1;
                        successor.failure_cap[event] =
                            successor.failures[event] >= MAX_PROVEN_FAILURES_PER_EVENT;
                        successor.budget_polluted = true;
                    }
                    result.push(("busy-before-lease", successor));
                    continue;
                }
                let mut successor = state.clone();
                let new_epoch = state.aggregate_epoch + 1;
                successor.phase[event] = Phase::Leased;
                successor.owner[event] = worker;
                successor.token[event] += 1;
                successor.owner_epoch[event] = new_epoch;
                successor.lease_installs[event] += 1;
                successor.attempts[event] += 1;
                successor.aggregate_epoch = new_epoch;
                successor.nudges &= !event_bit;
                successor.recovered &= !event_bit;
                successor.bad_binding |= !matches;
                result.push(("claim-lease-install", successor));
            }
        }
    }

    for event in 0..EVENT_COUNT {
        let event_bit = bit(event);
        let phase = state.phase[event];

        if phase == Phase::Pending && eligible(state, scenario, event) {
            if state.nudges & event_bit != 0 {
                let mut successor = state.clone();
                successor.nudges &= !event_bit;
                result.push(("lose-nudge", successor));
            } else if state.recovered & event_bit == 0 {
                let mut successor = state.clone();
                successor.recovered |= event_bit;
                result.push(("recovery-scan-lost-nudge", successor));
            }
        }

        if phase == Phase::Leased && state.owner[event] != NO_OWNER {
            let mut executing = state.clone();
            executing.phase[event] = Phase::Executing;
            executing.execs[event] += 1;
            result.push(("begin-exec", executing));

            let mut released = state.clone();
            released.phase[event] = Phase::Pending;
            released.owner[event] = NO_OWNER;
            result.push(("release-current-lease", released));
        }

        if phase == Phase::Executing && state.owner[event] != NO_OWNER {
            result.push(("begin-exec-same-token-idempotent", state.clone()));

            if state.failures[event] < MAX_PROVEN_FAILURES_PER_EVENT {
                let mut failed = state.clone();
                failed.phase[event] = Phase::Pending;
                failed.owner[event] = NO_OWNER;
                failed.failures[event] += 1;
                failed.failure_cap[event] = failed.failures[event] >= MAX_PROVEN_FAILURES_PER_EVENT;
                result.push(("proven-execution-failure", failed));
            }

            if state.lease_installs[event] < MAX_LEASE_EPISODES_PER_EVENT {
                let mut takeover = state.clone();
                let old_owner = state.owner[event];
                let old_token = state.token[event];
                let old_epoch = state.owner_epoch[event];
                takeover.phase[event] = Phase::Unknown;
                takeover.owner[event] = NO_OWNER;
                takeover.previous_owner[event] = old_owner;
                takeover.previous_token[event] = old_token;
                takeover.previous_epoch[event] = old_epoch;
                takeover.stale_release_done[event] = false;
                takeover.unknown |= event_bit;
                result.push(("stale-takeover", takeover));
            }

            if !state.revoked
                && state.unknown & event_bit == 0
                && scenario.durable_receipts
                && premises.durable_source_receipt
            {
                let mask = state.manifest_events | event_bit;
                let mut published = state.clone();
                published.phase[event] = Phase::Published;
                published.owner[event] = NO_OWNER;
                if premises.atomic_publication {
                    published.manifest_generation = state.source_generation;
                    published.manifest_events = mask;
                    published.current_generation = state.source_generation;
                    published.current_events = mask;
                    published.impact_events = mask;
                    published.proof_events = mask;
                    published.receipt_events |= event_bit;
                    published.record_published(event);
                    result.push(("publish-atomic", published));
                } else {
                    published.manifest_generation = state.source_generation;
                    published.manifest_events = mask;
                    result.push(("publish-manifest-only", published));
                }
            } else if !state.revoked && !premises.durable_source_receipt {
                let mask = state.manifest_events | event_bit;
                let mut unproven = state.clone();
                unproven.phase[event] = Phase::Published;
                unproven.owner[event] = NO_OWNER;
                unproven.manifest_generation = state.source_generation;
                unproven.manifest_events = mask;
                unproven.current_generation = state.source_generation;
                unproven.current_events |= event_bit;
                unproven.impact_events |= event_bit;
                unproven.proof_events |= event_bit;
                unproven.bad_receipt = true;
                result.push(("publish-without-source-receipt", unproven));
            }

            result.push(("publication-precommit-abort", state.clone()));
        }

        if phase == Phase::Unknown {
            if publication_proven(state, event) {
                let mut reconciled = state.clone();
                reconciled.phase[event] = Phase::Published;
                reconciled.owner[event] = NO_OWNER;
                reconciled.unknown &= !event_bit;
                reconciled.record_published(event);
                result.push(("reconcile-unknown", reconciled));
            } else if state.lease_installs[event] < MAX_LEASE_EPISODES_PER_EVENT {
                for worker in 0..2u8 {
                    let mut reconciled = state.clone();
                    let new_epoch = state.aggregate_epoch + 1;
                    reconciled.phase[event] = Phase::Leased;
                    reconciled.owner[event] = worker;
                    reconciled.token[event] += 1;
                    reconciled.owner_epoch[event] = new_epoch;
                    reconciled.lease_installs[event] += 1;
                    reconciled.attempts[event] += 1;
                    reconciled.aggregate_epoch = new_epoch;
                    reconciled.unknown &= !event_bit;
                    reconciled.nudges &= !event_bit;
                    reconciled.recovered &= !event_bit;
                    result.push(("reconcile-unknown", reconciled));
                }
            }
        }

        if state.manifest_events & event_bit != 0 {
            let mut allowed = state.current_events & event_bit != 0
                && state.impact_events & event_bit != 0
                && state.proof_events & event_bit != 0
                && state.receipt_events & event_bit != 0
                && state.current_generation == state.source_generation
                && state.manifest_generation == state.source_generation
                && !state.revoked;
            if !premises.strict_read_gate {
                allowed = state.manifest_events & event_bit != 0;
            }
            if state.unknown & event_bit != 0 {
                allowed = false;
            }
            let decision = if allowed { ALLOW } else { PENDING_DENY };
            if state.read_decisions[event] != decision {
                let mut read = state.clone();
                read.read_decisions[event] = decision;
                result.push((
                    if allowed {
                        "final-read-allow"
                    } else {
                        "final-read-pending-deny"
                    },
                    read,
                ));
            }
        }

        if state.owner[event] != NO_OWNER
            && state.previous_owner[event] != NO_OWNER
            && !state.stale_release_done[event]
        {
            let actor = state.previous_owner[event];
            let old_token = state.previous_token[event];
            let old_epoch = state.previous_epoch[event];
            if stale_release_is_rejected(state, event, actor, old_token, old_epoch, premises) {
                let mut rejected = state.clone();
                rejected.stale_release_done[event] = true;
                result.push(("stale-release-rejected", rejected));
            } else {
                let mut accepted = state.clone();
                accepted.phase[event] = Phase::Pending;
                accepted.owner[event] = NO_OWNER;
                accepted.stale_release_done[event] = true;
                accepted.bad_release = true;
                result.push(("stale-release-accepted", accepted));
            }
        }
    }

    if state.revoke_count < MAX_REVOKES {
        let mut revoked = state.clone();
        revoked.source_generation += 1;
        revoked.revoke_fence += 1;
        revoked.revoke_count += 1;
        revoked.revoked = true;
        revoked.read_decisions = [NO_READ; EVENT_COUNT];
        result.push(("source-revoke", revoked));
    }
    result
}

fn invariant_violations(state: &State, scenario: Scenario) -> Vec<String> {
    let mut failures = Vec::new();
    if state.bad_binding {
        failures.push("wrong-immutable-binding-accepted".to_owned());
    }
    if state.bad_release {
        failures.push("stale-owner-release-accepted".to_owned());
    }
    if state.budget_polluted {
        failures.push("busy-consumed-failure-budget".to_owned());
    }
    if state.bad_receipt {
        failures.push("publication-without-durable-source-receipt".to_owned());
    }
    if state
        .owner
        .iter()
        .filter(|owner| **owner != NO_OWNER)
        .count()
        > 1
    {
        failures.push("aggregate-single-active-slot-violated".to_owned());
    }
    if !(state.manifest_events == state.current_events
        && state.current_events == state.impact_events
        && state.impact_events == state.proof_events
        && state.proof_events == state.receipt_events)
    {
        failures.push("manifest-current-impact-proof-receipt-not-atomic".to_owned());
    }
    let published_keys = state
        .published_events()
        .iter()
        .map(|event| scenario.aggregate_key(usize::from(*event)))
        .collect::<Vec<_>>();
    if published_keys
        .windows(2)
        .any(|window| window[0] > window[1])
    {
        failures.push("aggregate-publication-order-regressed".to_owned());
    }
    for event in 0..EVENT_COUNT {
        let event_bit = bit(event);
        if state.unknown & event_bit != 0 && state.phase[event] != Phase::Unknown {
            failures.push(format!("unknown-bit-without-unknown-phase:{event}"));
        }
        if state.unknown & event_bit != 0 && state.read_decisions[event] == ALLOW {
            failures.push(format!("read-gate-allowed-with-unknown:{event}"));
        }
        if state.phase[event] == Phase::Published {
            if state.unknown & event_bit != 0 {
                failures.push(format!("published-with-unknown-bit:{event}"));
            }
            if state.proof_events & event_bit == 0 {
                failures.push(format!("published-without-event-proof:{event}"));
            }
            if state.receipt_events & event_bit == 0 {
                failures.push(format!("published-without-source-receipt:{event}"));
            }
        }
        if state.failures[event] > MAX_PROVEN_FAILURES_PER_EVENT {
            failures.push(format!("proven-failure-budget-exceeded:{event}"));
        }
        if state.lease_installs[event] > MAX_LEASE_EPISODES_PER_EVENT {
            failures.push(format!("lease-episode-bound-exceeded:{event}"));
        }
        if state.revoked && state.read_decisions[event] == ALLOW {
            failures.push(format!("read-gate-allowed-after-source-revoke:{event}"));
        }
    }
    failures
}

fn state_summary(state: &State) -> Value {
    let owner = state
        .owner
        .iter()
        .map(|owner| {
            if *owner == NO_OWNER {
                -1
            } else {
                i64::from(*owner)
            }
        })
        .collect::<Vec<_>>();
    let read_decisions = state
        .read_decisions
        .iter()
        .map(|decision| u64::from(*decision))
        .collect::<Vec<_>>();
    json!({
        "phase": state.phase.iter().map(|phase| phase.name()).collect::<Vec<_>>(),
        "owner": owner,
        "token": state.token,
        "aggregateEpoch": state.aggregate_epoch,
        "leaseInstalls": state.lease_installs,
        "attempts": state.attempts,
        "execs": state.execs,
        "provenFailures": state.failures,
        "failureCap": state.failure_cap,
        "sourceGeneration": state.source_generation,
        "revokeFence": state.revoke_fence,
        "manifestEvents": state.manifest_events,
        "currentEvents": state.current_events,
        "impactEvents": state.impact_events,
        "proofEvents": state.proof_events,
        "receiptEvents": state.receipt_events,
        "unknown": state.unknown,
        "publishedOrder": state.published_events(),
        "readDecisions": read_decisions,
    })
}

#[derive(Clone, Debug)]
struct SearchNode {
    state: State,
    depth: usize,
    parent: Option<(usize, &'static str)>,
}

fn path_to(index: usize, nodes: &[SearchNode]) -> Vec<&'static str> {
    let mut path = Vec::new();
    let mut current = index;
    while let Some((parent, action)) = nodes[current].parent {
        path.push(action);
        current = parent;
    }
    path.reverse();
    path
}

fn explore(
    scenario: Scenario,
    premises: Premises,
    max_states: usize,
    max_depth: usize,
    stop_at_counterexample: bool,
) -> Value {
    let start = State::initial();
    let mut seen = HashMap::from([(start.clone(), 0usize)]);
    let mut nodes = vec![SearchNode {
        state: start,
        depth: 0,
        parent: None,
    }];
    let mut queue = VecDeque::from([0usize]);
    let mut transitions_generated = 0u64;
    let mut action_counts = BTreeMap::<&'static str, u64>::new();
    let mut expanded = 0usize;
    let mut cutoffs = Vec::<Value>::new();
    let mut counterexample = None;
    let mut liveness_witness = None;

    while let Some(index) = queue.pop_front() {
        expanded += 1;
        let node = &nodes[index];
        let violations = invariant_violations(&node.state, scenario);
        if !violations.is_empty() && counterexample.is_none() {
            counterexample = Some(json!({
                "violations": violations,
                "state": state_summary(&node.state),
                "trace": path_to(index, &nodes),
            }));
            if stop_at_counterexample {
                break;
            }
        }
        if node.state.phase == [Phase::Published; EVENT_COUNT] && liveness_witness.is_none() {
            liveness_witness = Some(path_to(index, &nodes));
        }

        let depth = node.depth;
        let outgoing = transitions(&node.state, scenario, premises);
        transitions_generated += outgoing.len() as u64;
        for (action, _) in &outgoing {
            *action_counts.entry(action).or_default() += 1;
        }
        let mut locally_scheduled = HashSet::new();
        let unseen = outgoing
            .iter()
            .filter(|(_, successor)| {
                !seen.contains_key(successor) && locally_scheduled.insert((*successor).clone())
            })
            .collect::<Vec<_>>();
        if depth >= max_depth && !unseen.is_empty() {
            cutoffs.push(json!({
                "kind": "max_depth",
                "depth": depth,
                "unseenSuccessors": unseen.len(),
            }));
            continue;
        }
        for (action, successor) in unseen {
            if nodes.len() >= max_states {
                cutoffs.push(json!({
                    "kind": "max_states",
                    "limit": max_states,
                    "nextTransition": action,
                }));
                queue.clear();
                break;
            }
            let successor = successor.clone();
            let next_index = nodes.len();
            seen.insert(successor.clone(), next_index);
            nodes.push(SearchNode {
                state: successor,
                depth: depth + 1,
                parent: Some((index, action)),
            });
            queue.push_back(next_index);
        }
        if stop_at_counterexample && counterexample.is_some() {
            break;
        }
    }

    let complete = cutoffs.is_empty() && !(stop_at_counterexample && counterexample.is_some());
    let status = if counterexample.is_some() {
        "COUNTEREXAMPLE"
    } else if complete {
        "PASS"
    } else {
        "UNKNOWN"
    };
    let by_kind = action_counts
        .into_iter()
        .map(|(kind, count)| (kind.to_owned(), json!(count)))
        .collect::<Map<_, _>>();
    let max_depth_reached = nodes
        .iter()
        .map(|node| node.depth)
        .max()
        .unwrap_or_default();
    json!({
        "status": status,
        "explorationComplete": complete,
        "counterexampleFound": counterexample.is_some(),
        "states": {
            "distinctReachable": nodes.len(),
            "expanded": expanded,
            "limit": max_states,
            "maxDepthReached": max_depth_reached,
        },
        "transitions": {
            "generated": transitions_generated,
            "byKind": Value::Object(by_kind),
        },
        "cutoffs": cutoffs,
        "counterexample": counterexample,
        "conditionalLiveness": {
            "property": "both events reach PUBLISHED within this finite episode",
            "status": if liveness_witness.is_some() { "WITNESS" } else { "NO_WITNESS" },
            "shortestWitness": liveness_witness,
            "assumptions": [
                "source does not revoke",
                "no proven execution failure",
                "lost nudge is eventually recovered",
                "enabled worker transitions are eventually scheduled",
            ],
            "notUniversalFairnessProof": true,
        },
    })
}

fn negative_controls(max_states: usize, max_depth: usize) -> Value {
    let wrong_binding = Premises {
        exact_binding: false,
        ..Premises::default()
    };
    let active_slot = Premises {
        single_active_slot: false,
        ..Premises::default()
    };
    let ownership_fences = Premises {
        epoch_fence: false,
        random_token_fence: false,
        worker_owner_check: false,
        release_ownership_fence: false,
        ..Premises::default()
    };
    let half_publication = Premises {
        atomic_publication: false,
        ..Premises::default()
    };
    let stale_release = Premises {
        release_ownership_fence: false,
        ..Premises::default()
    };
    let budget_pollution = Premises {
        failure_budget_clean: false,
        ..Premises::default()
    };
    let read_gate_bypass = Premises {
        strict_read_gate: false,
        ..Premises::default()
    };
    let missing_receipt = Premises {
        durable_source_receipt: false,
        ..Premises::default()
    };

    let controls = [
        ("wrong-binding", SCENARIOS[2], wrong_binding),
        ("active-slot", ACTIVE_SLOT_SCENARIO, active_slot),
        (
            "ownership-fence-combination",
            SCENARIOS[0],
            ownership_fences,
        ),
        ("half-publication", SCENARIOS[2], half_publication),
        ("stale-release", SCENARIOS[0], stale_release),
        ("budget-pollution", SCENARIOS[2], budget_pollution),
        ("read-gate-bypass", SCENARIOS[2], read_gate_bypass),
        (
            "missing-durable-source-receipt",
            SCENARIOS[2],
            missing_receipt,
        ),
    ];
    let counterexamples = controls
        .iter()
        .map(|(name, scenario, premises)| {
            let report = explore(*scenario, *premises, max_states, max_depth, true);
            let dropped = premise_names()
                .into_iter()
                .filter(|(premise, _)| !premise_enabled(*premises, premise))
                .map(|(premise, _)| premise)
                .collect::<Vec<_>>();
            json!({
                "id": name,
                "droppedPremises": dropped,
                "status": report["status"],
                "explorationComplete": report["explorationComplete"],
                "counterexampleFound": report["counterexampleFound"],
                "states": report["states"],
                "transitions": report["transitions"],
                "cutoffs": report["cutoffs"],
                "counterexample": report["counterexample"],
            })
        })
        .collect::<Vec<_>>();
    let epoch_only = explore(
        SCENARIOS[0],
        Premises {
            epoch_fence: false,
            ..Premises::default()
        },
        max_states,
        max_depth,
        false,
    );
    let ordering = explore(
        ORDER_SCENARIO,
        Premises::default(),
        max_states,
        max_depth,
        false,
    );
    json!({
        "counterexamples": counterexamples,
        "epochOmissionAlone": {
            "status": epoch_only["status"],
            "explorationComplete": epoch_only["explorationComplete"],
            "states": epoch_only["states"],
            "transitions": epoch_only["transitions"],
            "interpretation": "random-token and worker-owner fences remain; no vulnerability is asserted",
        },
        "aggregateOrdering": {
            "status": ordering["status"],
            "explorationComplete": ordering["explorationComplete"],
            "states": ordering["states"],
            "transitions": ordering["transitions"],
            "cutoffs": ordering["cutoffs"],
            "counterexample": ordering["counterexample"],
        },
    })
}

fn premise_names() -> [(&'static str, bool); 10] {
    let premises = Premises::default();
    [
        ("exact_binding", premises.exact_binding),
        ("single_active_slot", premises.single_active_slot),
        ("epoch_fence", premises.epoch_fence),
        ("random_token_fence", premises.random_token_fence),
        ("worker_owner_check", premises.worker_owner_check),
        ("release_ownership_fence", premises.release_ownership_fence),
        ("atomic_publication", premises.atomic_publication),
        ("durable_source_receipt", premises.durable_source_receipt),
        ("failure_budget_clean", premises.failure_budget_clean),
        ("strict_read_gate", premises.strict_read_gate),
    ]
}

fn premise_enabled(premises: Premises, name: &str) -> bool {
    match name {
        "exact_binding" => premises.exact_binding,
        "single_active_slot" => premises.single_active_slot,
        "epoch_fence" => premises.epoch_fence,
        "random_token_fence" => premises.random_token_fence,
        "worker_owner_check" => premises.worker_owner_check,
        "release_ownership_fence" => premises.release_ownership_fence,
        "atomic_publication" => premises.atomic_publication,
        "durable_source_receipt" => premises.durable_source_receipt,
        "failure_budget_clean" => premises.failure_budget_clean,
        "strict_read_gate" => premises.strict_read_gate,
        _ => true,
    }
}

fn fixed_schedule_ablation() -> Value {
    let rows = [
        json!({
            "variant": "legacy_scope_claim",
            "scopeCalls": 2,
            "nonTargetCandidatesVisited": 2,
            "nonTargetPerCallMax": 1,
            "targetProcessingCapPerCall": MAX_TARGETS_PER_CALL,
            "exactBindingChecks": 0,
            "workerOwnerChecks": 0,
            "failureBudgetChecks": 0,
        }),
        json!({
            "variant": "exact_claim",
            "scopeCalls": 0,
            "nonTargetCandidatesVisited": 0,
            "nonTargetPerCallMax": 0,
            "targetProcessingCapPerCall": MAX_TARGETS_PER_CALL,
            "exactBindingChecks": 2,
            "workerOwnerChecks": 0,
            "failureBudgetChecks": 0,
        }),
        json!({
            "variant": "exact+worker_owner",
            "scopeCalls": 0,
            "nonTargetCandidatesVisited": 0,
            "nonTargetPerCallMax": 0,
            "targetProcessingCapPerCall": MAX_TARGETS_PER_CALL,
            "exactBindingChecks": 2,
            "workerOwnerChecks": 2,
            "failureBudgetChecks": 0,
        }),
        json!({
            "variant": "exact+owner+failure_budget",
            "scopeCalls": 0,
            "nonTargetCandidatesVisited": 0,
            "nonTargetPerCallMax": 0,
            "targetProcessingCapPerCall": MAX_TARGETS_PER_CALL,
            "exactBindingChecks": 3,
            "workerOwnerChecks": 2,
            "failureBudgetChecks": 3,
        }),
    ];
    json!({
        "kind": "fixed_schedule_abstract_operation_counts",
        "fixture": "2 requests, 2 workers, 2 events in one aggregate",
        "legacyRule": "stop at first non-target; at most one non-target per call",
        "notDatabasePerformance": true,
        "notGlobalOptimum": true,
        "notUnboundedProof": true,
        "rows": rows,
    })
}

pub fn run_model(max_states: usize, max_depth: usize) -> Result<Value, String> {
    if !(1..=MAX_STATES).contains(&max_states) {
        return Err(format!(
            "max_states must be an integer from 1 to {MAX_STATES}"
        ));
    }
    if !(1..=MAX_DEPTH).contains(&max_depth) {
        return Err(format!(
            "max_depth must be an integer from 1 to {MAX_DEPTH}"
        ));
    }

    let cases = SCENARIOS
        .iter()
        .map(|scenario| {
            let mut report = explore(*scenario, Premises::default(), max_states, max_depth, false);
            let events = (0..EVENT_COUNT)
                .map(|event| {
                    let predecessor = scenario.predecessors[event];
                    json!({
                        "grant": scenario.grants[event],
                        "revision": scenario.revisions[event],
                        "predecessor": predecessor,
                    })
                })
                .collect::<Vec<_>>();
            report["name"] = json!(scenario.name);
            report["requests"] = json!(scenario.request_events);
            report["events"] = json!(events);
            report
        })
        .collect::<Vec<_>>();
    let negative = negative_controls(max_states, max_depth);
    let base_complete = cases
        .iter()
        .all(|case| case["status"] == "PASS" && case["explorationComplete"] == true);
    let controls_found = negative["counterexamples"]
        .as_array()
        .is_some_and(|controls| {
            controls.iter().all(|item| {
                item["counterexampleFound"] == true
                    && item["status"] == "COUNTEREXAMPLE"
                    && item["explorationComplete"] == false
            })
        });
    let epoch_safe = negative["epochOmissionAlone"]["status"] == "PASS"
        && negative["epochOmissionAlone"]["explorationComplete"] == true;
    let ordering_safe = negative["aggregateOrdering"]["status"] == "PASS"
        && negative["aggregateOrdering"]["explorationComplete"] == true;
    let status = if base_complete && controls_found && epoch_safe && ordering_safe {
        "PASS"
    } else if cases.iter().any(|case| case["status"] == "UNKNOWN") || !controls_found {
        "UNKNOWN"
    } else {
        "FAIL"
    };
    Ok(json!({
        "model": MODEL,
        "version": VERSION,
        "status": status,
        "explorationComplete": base_complete && epoch_safe && ordering_safe,
        "evidenceBoundary": "complete BFS over the stated finite episode only; not an unbounded or production proof",
        "finiteUniverse": {
            "events": EVENT_COUNT,
            "workers": 2,
            "requests": 2,
            "maxLeaseEpisodesPerEvent": MAX_LEASE_EPISODES_PER_EVENT,
            "maxProvenFailuresPerEvent": MAX_PROVEN_FAILURES_PER_EVENT,
            "maxSourceRevokes": MAX_REVOKES,
            "maxAggregateEpoch": 2 * MAX_LEASE_EPISODES_PER_EVENT,
            "maxStatesPerSearch": max_states,
            "maxDepthPerSearch": max_depth,
            "hardMaxStates": MAX_STATES,
            "hardMaxDepth": MAX_DEPTH,
        },
        "stateSemantics": {
            "stateType": "immutable hashable state",
            "claimCounterIncrement": "lease installation only",
            "beginExec": "increments once per lease; same-token repeat is idempotent",
            "failureBudget": "only proven execution failure consumes budget",
            "busyOrReleaseConsumesFailureBudget": false,
            "unknown": "reconcile durable publication proof before successor lease",
            "exhaustedEvent": "PENDING_WITH_FAILURE_CAP",
            "publicationAtomicFields": ["manifest", "current", "impact", "event_proof", "source_receipt"],
            "durableSourceReceipt": "immutable event/aggregate/grant/revision/generation binding",
            "aggregatePredecessor": "(source_generation, delta_event_id); exact and poll share Busy-before-install gate",
            "ownership": "aggregate epoch + random-token abstraction + worker-owner fence",
        },
        "scenarioWitnesses": SCENARIO_WITNESSES
            .iter()
            .map(|(name, steps)| json!({"name": name, "steps": steps}))
            .collect::<Vec<_>>(),
        "cases": cases,
        "negativeControls": negative,
        "ablation": fixed_schedule_ablation(),
    }))
}

pub fn run_default_model() -> Result<Value, String> {
    run_model(DEFAULT_MAX_STATES, DEFAULT_MAX_DEPTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    static REPORT: OnceLock<Value> = OnceLock::new();

    fn report() -> &'static Value {
        REPORT.get_or_init(|| run_default_model().expect("finite default model"))
    }

    fn selected_transition(
        state: &State,
        scenario: Scenario,
        premises: Premises,
        action: &str,
    ) -> State {
        transitions(state, scenario, premises)
            .into_iter()
            .find_map(|(kind, successor)| (kind == action).then_some(successor))
            .unwrap_or_else(|| panic!("missing transition {action}"))
    }

    #[test]
    fn default_bfs_is_reproducible_and_complete_in_the_finite_universe() {
        let first = report();
        let second = run_default_model().unwrap();
        assert_eq!(*first, second);
        assert_eq!(first["status"], "PASS");
        assert_eq!(first["explorationComplete"], true);
        let cases = first["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for case in cases {
            assert_eq!(case["status"], "PASS");
            assert_eq!(case["explorationComplete"], true);
            assert_eq!(case["cutoffs"], json!([]));
            assert!(case["states"]["expanded"].as_u64().unwrap() > 1);
            assert!(case["transitions"]["generated"].as_u64().unwrap() > 0);
        }
    }

    #[test]
    fn same_grant_predecessor_scenarios_have_conditional_liveness_witnesses() {
        for case in &report()["cases"].as_array().unwrap()[..2] {
            let grants = case["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| event["grant"].as_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(grants, ["G", "G"]);
            assert_eq!(case["events"][1]["predecessor"], 0);
            assert_eq!(case["conditionalLiveness"]["status"], "WITNESS");
            assert!(!case["conditionalLiveness"]["shortestWitness"]
                .as_array()
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn independent_grants_in_one_aggregate_can_both_publish() {
        let case = &report()["cases"][2];
        assert_eq!(case["events"][0]["grant"], "G");
        assert_eq!(case["events"][1]["grant"], "H");
        assert_eq!(case["conditionalLiveness"]["status"], "WITNESS");
        assert!(!case["conditionalLiveness"]["shortestWitness"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn transition_counters_cover_claim_execution_failure_and_release() {
        let actions = report()["cases"][2]["transitions"]["byKind"]
            .as_object()
            .unwrap();
        for action in [
            "claim-lease-install",
            "begin-exec",
            "begin-exec-same-token-idempotent",
            "proven-execution-failure",
            "busy-before-lease",
            "release-current-lease",
        ] {
            assert!(actions.contains_key(action), "{action}");
        }
    }

    #[test]
    fn unknown_reconciliation_precedes_a_bounded_retry() {
        let initial = State::initial();
        let claimed = selected_transition(
            &initial,
            SCENARIOS[0],
            Premises::default(),
            "claim-lease-install",
        );
        let executing =
            selected_transition(&claimed, SCENARIOS[0], Premises::default(), "begin-exec");
        let unknown = selected_transition(
            &executing,
            SCENARIOS[0],
            Premises::default(),
            "stale-takeover",
        );
        assert_eq!(unknown.phase[0], Phase::Unknown);
        assert_eq!(unknown.owner[0], NO_OWNER);
        assert_eq!(unknown.unknown & 1, 1);
        assert_eq!(unknown.lease_installs[0], 1);
        let reconciled = transitions(&unknown, SCENARIOS[0], Premises::default())
            .into_iter()
            .filter_map(|(action, successor)| (action == "reconcile-unknown").then_some(successor))
            .collect::<Vec<_>>();
        assert_eq!(
            reconciled
                .iter()
                .map(|state| state.owner[0])
                .collect::<std::collections::BTreeSet<_>>(),
            [0, 1].into_iter().collect()
        );
        for successor in reconciled {
            assert_eq!(successor.phase[0], Phase::Leased);
            assert_eq!(successor.unknown & 1, 0);
            assert_eq!(successor.lease_installs[0], 2);
            assert_eq!(successor.attempts[0], 2);
        }
    }

    #[test]
    fn unknown_blocks_publication_and_allow_until_durable_reconciliation() {
        let mut state = State::initial();
        state.phase = [Phase::Unknown, Phase::Pending];
        state.unknown = 1;
        state.manifest_generation = 1;
        state.manifest_events = 1;
        state.current_generation = 1;
        state.current_events = 1;
        state.impact_events = 1;
        state.proof_events = 1;
        state.receipt_events = 1;
        let actions = transitions(&state, SCENARIOS[0], Premises::default())
            .into_iter()
            .map(|(action, _)| action)
            .collect::<Vec<_>>();
        assert!(!actions.contains(&"publish-atomic"));
        assert!(!actions.contains(&"final-read-allow"));
        assert!(actions.contains(&"final-read-pending-deny"));
        let reconciled = transitions(&state, SCENARIOS[0], Premises::default())
            .into_iter()
            .any(|(action, successor)| {
                action == "reconcile-unknown"
                    && successor.phase[0] == Phase::Published
                    && successor.unknown == 0
            });
        assert!(reconciled);
    }

    #[test]
    fn normal_atomic_publication_does_not_create_unknown_state() {
        let initial = State::initial();
        let claimed = selected_transition(
            &initial,
            SCENARIOS[0],
            Premises::default(),
            "claim-lease-install",
        );
        let executing =
            selected_transition(&claimed, SCENARIOS[0], Premises::default(), "begin-exec");
        let published = selected_transition(
            &executing,
            SCENARIOS[0],
            Premises::default(),
            "publish-atomic",
        );
        assert_eq!(published.unknown, 0);
        assert_eq!(published.phase[0], Phase::Published);
    }

    #[test]
    fn aggregate_predecessor_busy_edges_do_not_charge_counters() {
        let scenario = ORDER_SCENARIO;
        let initial = State::initial();
        let exact_busy = transitions(&initial, scenario, Premises::default())
            .into_iter()
            .filter(|(action, _)| *action == "busy-before-aggregate-predecessor")
            .map(|(_, successor)| successor)
            .collect::<Vec<_>>();
        assert!(!exact_busy.is_empty());
        for successor in exact_busy {
            assert_eq!(successor, initial);
            assert_eq!(successor.attempts, [0, 0]);
            assert_eq!(successor.execs, [0, 0]);
            assert_eq!(successor.failures, [0, 0]);
        }

        let mut poll_seed = initial;
        poll_seed.nudges = 1;
        let poll_state = selected_transition(
            &poll_seed,
            scenario,
            Premises::default(),
            "recovery-scan-lost-nudge",
        );
        let poll_busy = transitions(&poll_state, scenario, Premises::default())
            .into_iter()
            .filter(|(action, _)| *action == "busy-before-aggregate-predecessor")
            .map(|(_, successor)| successor)
            .collect::<Vec<_>>();
        assert!(!poll_busy.is_empty());
        for successor in poll_busy {
            assert_eq!(successor, poll_state);
            assert_eq!(successor.attempts, [0, 0]);
            assert_eq!(successor.execs, [0, 0]);
            assert_eq!(successor.failures, [0, 0]);
        }
    }

    #[test]
    fn aggregate_ordering_does_not_publish_source_64_before_source_7() {
        let initial = State::initial();
        let claim_7 = transitions(&initial, ORDER_SCENARIO, Premises::default())
            .into_iter()
            .find_map(|(action, successor)| {
                (action == "claim-lease-install" && successor.owner[0] != NO_OWNER)
                    .then_some(successor)
            })
            .unwrap();
        let begin_7 =
            selected_transition(&claim_7, ORDER_SCENARIO, Premises::default(), "begin-exec");
        let publish_7 = selected_transition(
            &begin_7,
            ORDER_SCENARIO,
            Premises::default(),
            "publish-atomic",
        );
        let claim_64 = transitions(&publish_7, ORDER_SCENARIO, Premises::default())
            .into_iter()
            .filter(|(action, successor)| {
                *action == "claim-lease-install" && successor.owner[1] != NO_OWNER
            })
            .map(|(_, successor)| successor)
            .collect::<Vec<_>>();
        assert!(!claim_64.is_empty());
        assert_eq!(publish_7.published_events(), [0]);
        assert_eq!(
            publish_7
                .published_events()
                .iter()
                .map(|event| ORDER_SCENARIO.source_generations[usize::from(*event)])
                .collect::<Vec<_>>(),
            [7]
        );
    }

    #[test]
    fn negative_controls_find_shortest_counterexamples() {
        let controls = report()["negativeControls"]["counterexamples"]
            .as_array()
            .unwrap();
        let expected = [
            "wrong-binding",
            "active-slot",
            "ownership-fence-combination",
            "half-publication",
            "stale-release",
            "budget-pollution",
            "read-gate-bypass",
            "missing-durable-source-receipt",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            controls
                .iter()
                .map(|item| item["id"].as_str().unwrap())
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
        for item in controls {
            assert_eq!(item["status"], "COUNTEREXAMPLE", "{}", item["id"]);
            assert_eq!(item["counterexampleFound"], true, "{}", item["id"]);
            assert_eq!(item["explorationComplete"], false, "{}", item["id"]);
            assert!(!item["counterexample"]["trace"]
                .as_array()
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn removing_only_epoch_fence_is_not_reported_as_a_vulnerability() {
        let case = &report()["negativeControls"]["epochOmissionAlone"];
        assert_eq!(case["status"], "PASS");
        assert_eq!(case["explorationComplete"], true);
        assert!(case["interpretation"]
            .as_str()
            .unwrap()
            .contains("random-token and worker-owner"));
    }

    #[test]
    fn search_cutoff_is_unknown_not_pass() {
        let limited = run_model(1, 1).unwrap();
        assert_eq!(limited["status"], "UNKNOWN");
        assert_eq!(limited["explorationComplete"], false);
        assert!(limited["cases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|case| case["explorationComplete"] == false));
    }

    #[test]
    fn fixed_schedule_ablation_is_not_a_performance_claim() {
        let ablation = &report()["ablation"];
        assert_eq!(ablation["notDatabasePerformance"], true);
        assert_eq!(ablation["notGlobalOptimum"], true);
        assert_eq!(ablation["notUnboundedProof"], true);
        let rows = ablation["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| (item["variant"].as_str().unwrap(), item))
            .collect::<BTreeMap<_, _>>();
        let legacy = rows["legacy_scope_claim"];
        assert_eq!(legacy["nonTargetPerCallMax"], 1);
        assert_eq!(legacy["targetProcessingCapPerCall"], 32);
        assert_eq!(legacy["nonTargetCandidatesVisited"], 2);
        assert_eq!(rows["exact+owner+failure_budget"]["failureBudgetChecks"], 3);
    }

    #[test]
    fn finite_episode_limits_and_search_bounds_are_pinned() {
        let limits = &report()["finiteUniverse"];
        assert_eq!(limits["maxLeaseEpisodesPerEvent"], 2);
        assert_eq!(limits["maxProvenFailuresPerEvent"], 1);
        assert_eq!(limits["maxSourceRevokes"], 1);
        for (max_states, max_depth) in [
            (0, DEFAULT_MAX_DEPTH),
            (MAX_STATES + 1, DEFAULT_MAX_DEPTH),
            (DEFAULT_MAX_STATES, 0),
            (DEFAULT_MAX_STATES, MAX_DEPTH + 1),
        ] {
            assert!(run_model(max_states, max_depth).is_err());
        }
    }

    #[test]
    fn premise_registry_rejects_unknown_names() {
        assert!(Premises::default().without("unregistered").is_err());
    }
}
