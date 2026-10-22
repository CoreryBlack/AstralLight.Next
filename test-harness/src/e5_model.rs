use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

mod report;
pub use report::{build_report, format_text_report};

pub const MODEL_NAME: &str = "e5-bounded-model-check";
pub const MODEL_VERSION: &str = "2.1.0";
pub const THEOREM_ID: &str = "E5";
pub const MIN_BOUND: usize = 2;
pub const MAX_BOUND: usize = 64;
pub const DEFAULT_BOUND: usize = 28;

pub const PREMISES: [&str; 6] = [
    "pending_probe",
    "post_recheck",
    "final_reload",
    "exact_identity",
    "generation_revoke_fence",
    "host_mediation",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Bracket,
    Strict,
}

impl Mode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "bracket" => Ok(Self::Bracket),
            "strict" => Ok(Self::Strict),
            _ => Err(format!("unknown observation mode: {value}")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bracket => "bracket",
            Self::Strict => "strict",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Premises {
    pub pending_probe: bool,
    pub post_recheck: bool,
    pub final_reload: bool,
    pub exact_identity: bool,
    pub generation_revoke_fence: bool,
    pub host_mediation: bool,
}

impl Default for Premises {
    fn default() -> Self {
        Self {
            pending_probe: true,
            post_recheck: true,
            final_reload: true,
            exact_identity: true,
            generation_revoke_fence: true,
            host_mediation: true,
        }
    }
}

impl Premises {
    pub fn without(self, premise: &str) -> Result<Self, String> {
        let mut result = self;
        match premise {
            "pending_probe" => result.pending_probe = false,
            "post_recheck" => result.post_recheck = false,
            "final_reload" => result.final_reload = false,
            "exact_identity" => result.exact_identity = false,
            "generation_revoke_fence" => result.generation_revoke_fence = false,
            "host_mediation" => result.host_mediation = false,
            _ => return Err(format!("unknown premise: {premise}")),
        }
        Ok(result)
    }

    fn as_value(self) -> Value {
        json!({
            "pending_probe": self.pending_probe,
            "post_recheck": self.post_recheck,
            "final_reload": self.final_reload,
            "exact_identity": self.exact_identity,
            "generation_revoke_fence": self.generation_revoke_fence,
            "host_mediation": self.host_mediation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    Init,
    CommitBegin,
    CommitDurable,
    Publish,
    BodyAdvance,
    Rollback,
    PreBegin,
    PreEnd,
    ReloadM0,
    ReloadP0,
    ReloadM1,
    ReloadP1,
    StrictLoad,
    Match,
    PostBegin,
    PostEnd,
    StrictObs,
    Admit,
    Bypass,
}

const EVENT_COUNT: usize = 19;
const EVENTS: [Event; EVENT_COUNT] = [
    Event::Init,
    Event::CommitBegin,
    Event::CommitDurable,
    Event::Publish,
    Event::BodyAdvance,
    Event::Rollback,
    Event::PreBegin,
    Event::PreEnd,
    Event::ReloadM0,
    Event::ReloadP0,
    Event::ReloadM1,
    Event::ReloadP1,
    Event::StrictLoad,
    Event::Match,
    Event::PostBegin,
    Event::PostEnd,
    Event::StrictObs,
    Event::Admit,
    Event::Bypass,
];

impl Event {
    fn index(self) -> usize {
        self as usize
    }

    fn name(self) -> &'static str {
        match self {
            Self::Init => "INIT",
            Self::CommitBegin => "COMMIT_BEGIN",
            Self::CommitDurable => "COMMIT_DURABLE",
            Self::Publish => "PUBLISH",
            Self::BodyAdvance => "EVIDENCE_BODY_ADVANCE",
            Self::Rollback => "ROLLBACK",
            Self::PreBegin => "PRE_OBS_BEGIN",
            Self::PreEnd => "PRE_OBS_END",
            Self::ReloadM0 => "RELOAD_M0",
            Self::ReloadP0 => "RELOAD_P0",
            Self::ReloadM1 => "RELOAD_M1",
            Self::ReloadP1 => "RELOAD_P1",
            Self::StrictLoad => "STRICT_LOAD",
            Self::Match => "MATCH",
            Self::PostBegin => "POST_OBS_BEGIN",
            Self::PostEnd => "POST_OBS_END",
            Self::StrictObs => "STRICT_OBS",
            Self::Admit => "ADMIT",
            Self::Bypass => "BYPASS",
        }
    }

    fn is_cache_read(self) -> bool {
        matches!(
            self,
            Self::PreEnd
                | Self::ReloadM0
                | Self::ReloadM1
                | Self::StrictLoad
                | Self::PostEnd
                | Self::StrictObs
        )
    }

    fn is_pending_probe(self) -> bool {
        matches!(self, Self::ReloadP0 | Self::ReloadP1 | Self::StrictLoad)
    }
}

#[derive(Clone, Debug)]
pub struct Chains {
    pub checklist: Vec<&'static str>,
    pub pre: Vec<&'static str>,
    pub mutation: Vec<&'static str>,
    pub body: Vec<&'static str>,
    pub bypass: Vec<&'static str>,
    pub recheck: Vec<&'static str>,
    checklist_events: Vec<Event>,
    pre_events: Vec<Event>,
    mutation_events: Vec<Event>,
    body_events: Vec<Event>,
    bypass_events: Vec<Event>,
}

impl Chains {
    fn new(premises: Premises, mode: Mode) -> Self {
        let mut checklist_events = Vec::new();
        if premises.final_reload {
            if mode == Mode::Bracket {
                checklist_events.push(Event::ReloadM0);
                if premises.pending_probe {
                    checklist_events.push(Event::ReloadP0);
                }
                checklist_events.push(Event::ReloadM1);
                if premises.pending_probe {
                    checklist_events.push(Event::ReloadP1);
                }
            } else {
                checklist_events.push(Event::StrictLoad);
            }
        }
        checklist_events.push(Event::Match);
        let recheck_events = if premises.post_recheck {
            match mode {
                Mode::Bracket => vec![Event::PostBegin, Event::PostEnd],
                Mode::Strict => vec![Event::StrictObs],
            }
        } else {
            Vec::new()
        };
        checklist_events.extend(recheck_events.iter().copied());
        checklist_events.push(Event::Admit);
        let pre_events = if mode == Mode::Bracket {
            vec![Event::PreBegin, Event::PreEnd]
        } else {
            Vec::new()
        };
        let mutation_events = vec![
            Event::CommitBegin,
            Event::CommitDurable,
            Event::Publish,
            Event::Rollback,
        ];
        let body_events = vec![Event::BodyAdvance];
        let bypass_events = if premises.host_mediation {
            Vec::new()
        } else {
            vec![Event::Bypass]
        };
        let names = |events: &[Event]| events.iter().map(|event| event.name()).collect();
        Self {
            checklist: names(&checklist_events),
            pre: names(&pre_events),
            mutation: names(&mutation_events),
            body: names(&body_events),
            bypass: names(&bypass_events),
            recheck: names(&recheck_events),
            checklist_events,
            pre_events,
            mutation_events,
            body_events,
            bypass_events,
        }
    }

    pub fn as_value(&self) -> Value {
        json!({
            "checklist": self.checklist,
            "pre": self.pre,
            "mutation": self.mutation,
            "body": self.body,
            "bypass": self.bypass,
            "recheck": self.recheck,
        })
    }
}

pub fn build_chains(premises: Premises, mode: Mode) -> Chains {
    Chains::new(premises, mode)
}

pub fn required_bound(premises: Premises, mode: Mode) -> usize {
    let chains = Chains::new(premises, mode);
    1 + chains.checklist_events.len()
        + chains.pre_events.len()
        + chains.mutation_events.len()
        + chains.body_events.len()
        + chains.bypass_events.len()
}

pub fn validate_bound(bound: usize) -> Result<usize, String> {
    if !(MIN_BOUND..=MAX_BOUND).contains(&bound) {
        return Err(format!(
            "max-steps must be a finite bound in [{MIN_BOUND}, {MAX_BOUND}], got {bound}"
        ));
    }
    Ok(bound)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Generation {
    Before,
    After,
}

impl Generation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Before => "g0",
            Self::After => "g1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Revision {
    Candidate,
    Successor,
}

impl Revision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "r0",
            Self::Successor => "r1",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ReadObservation {
    manifest: Generation,
    body: Revision,
    head: Generation,
    consistent: bool,
    valid: bool,
    reason: Option<&'static str>,
    step: usize,
}

#[derive(Clone, Copy, Debug)]
struct PendingObservation {
    step: usize,
    pending: bool,
}

fn observe_cache(
    step: usize,
    publish_step: Option<usize>,
    body_step: Option<usize>,
    rollback_step: Option<usize>,
    fence_on: bool,
) -> ReadObservation {
    let published = publish_step.is_some_and(|position| position <= step);
    let advanced = body_step.is_some_and(|position| position <= step);
    let rolled = rollback_step.is_some_and(|position| position <= step);
    let head = if published {
        Generation::After
    } else {
        Generation::Before
    };
    let manifest = if published && !rolled {
        Generation::After
    } else {
        Generation::Before
    };
    let body_advanced =
        advanced && rollback_step.is_none_or(|rollback| body_step.unwrap() > rollback);
    let body = if body_advanced {
        Revision::Successor
    } else {
        Revision::Candidate
    };
    let consistent = (manifest == Generation::After) == (body == Revision::Successor);
    let mut valid = true;
    let mut reason = None;
    if fence_on {
        if !consistent {
            valid = false;
            reason = Some(if manifest == Generation::After {
                "manifest_ahead_body_stale"
            } else {
                "body_ahead_manifest_stale"
            });
        } else if manifest == Generation::Before && head == Generation::After {
            valid = false;
            reason = Some("generation_below_published_head");
        }
    }
    ReadObservation {
        manifest,
        body,
        head,
        consistent,
        valid,
        reason,
        step,
    }
}

pub fn cache_observation(
    step: usize,
    publish_step: Option<usize>,
    body_step: Option<usize>,
    rollback_step: Option<usize>,
    fence_on: bool,
) -> Value {
    let observation = observe_cache(step, publish_step, body_step, rollback_step, fence_on);
    json!({
        "manifest": observation.manifest.as_str(),
        "body": observation.body.as_str(),
        "head": observation.head.as_str(),
        "consistent": observation.consistent,
        "valid": observation.valid,
        "reason": observation.reason,
    })
}

pub fn classify_domain(
    commit_interval: Option<(usize, usize)>,
    final_observation_interval: Option<(usize, usize)>,
) -> &'static str {
    let Some((commit_begin, commit_durable)) = commit_interval else {
        return "not_stale";
    };
    let Some((observation_begin, observation_end)) = final_observation_interval else {
        return "unknown_domain";
    };
    if commit_durable < observation_begin {
        "strictly_before"
    } else if observation_begin <= commit_durable && commit_begin <= observation_end {
        "overlap_unknown"
    } else {
        "after_final_observation"
    }
}

#[derive(Clone, Copy, Default)]
struct SearchState {
    checklist_index: usize,
    pre_index: usize,
    mutation_index: usize,
    body_index: usize,
    bypass_index: usize,
    positions: [Option<usize>; EVENT_COUNT],
    reads: [Option<ReadObservation>; EVENT_COUNT],
    pending: [Option<PendingObservation>; EVENT_COUNT],
    evidence: Option<ReadObservation>,
    match_ok: Option<bool>,
}

#[derive(Default)]
struct Counters {
    explored_states: usize,
    explored_traces: usize,
    incomplete_traces: usize,
    admitted_traces: usize,
    denied_traces: usize,
    bypass_admitted_traces: usize,
    admitted_not_stale: usize,
    admitted_strictly_before: usize,
    admitted_overlap_unknown: usize,
    admitted_after_final_observation: usize,
    admitted_unknown_domain: usize,
    violations: usize,
    publish_after_last_read_before_admission_traces: usize,
    admitted_publish_after_last_read: usize,
    rollback_after_last_read_before_admission_traces: usize,
    publish_after_final_observation_before_admission_traces: usize,
    admitted_publish_after_final_observation: usize,
    stale_commit_publish_after_last_read_traces: usize,
    admitted_stale_commit_publish_after_last_read: usize,
    torn_read_traces: usize,
    admitted_torn_read_traces: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Admitted,
    Denied,
    BypassAdmitted,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "ADMITTED",
            Self::Denied => "DENIED",
            Self::BypassAdmitted => "BYPASS_ADMITTED",
        }
    }
}

struct BestViolation {
    names: Vec<&'static str>,
    detail: Value,
}

struct RunContext {
    premises: Premises,
    mode: Mode,
    bound: usize,
    chains: Chains,
    counters: Counters,
    denial_reasons: BTreeMap<String, usize>,
    torn_kind_counts: BTreeMap<String, usize>,
    admitted_torn_by_domain: BTreeMap<String, usize>,
    violation_classes: BTreeMap<String, usize>,
    best_violation: Option<BestViolation>,
}

impl RunContext {
    fn new(premises: Premises, mode: Mode, bound: usize) -> Self {
        let mut torn_kind_counts = BTreeMap::new();
        torn_kind_counts.insert("manifest_ahead_body_stale".into(), 0);
        torn_kind_counts.insert("body_ahead_manifest_stale".into(), 0);
        Self {
            premises,
            mode,
            bound,
            chains: Chains::new(premises, mode),
            counters: Counters::default(),
            denial_reasons: BTreeMap::new(),
            torn_kind_counts,
            admitted_torn_by_domain: BTreeMap::new(),
            violation_classes: BTreeMap::new(),
            best_violation: None,
        }
    }

    fn final_event(&self) -> Event {
        match self.mode {
            Mode::Bracket => Event::ReloadM0,
            Mode::Strict => Event::StrictLoad,
        }
    }

    fn recheck_event(&self) -> Event {
        match self.mode {
            Mode::Bracket => Event::PostEnd,
            Mode::Strict => Event::StrictObs,
        }
    }

    fn configured_probes(&self) -> &'static [Event] {
        if !self.premises.final_reload || !self.premises.pending_probe {
            return &[];
        }
        match self.mode {
            Mode::Bracket => &[Event::ReloadP0, Event::ReloadP1],
            Mode::Strict => &[Event::StrictLoad],
        }
    }

    fn read_for(&self, state: SearchState, step: usize) -> ReadObservation {
        observe_cache(
            step,
            state.positions[Event::Publish.index()],
            state.positions[Event::BodyAdvance.index()],
            state.positions[Event::Rollback.index()],
            self.premises.generation_revoke_fence,
        )
    }

    fn evidence_read(
        &self,
        reads: &[Option<ReadObservation>; EVENT_COUNT],
    ) -> Option<ReadObservation> {
        if self.premises.final_reload {
            let observation = reads[self.final_event().index()]?;
            return observation.valid.then_some(observation);
        }
        if self.mode == Mode::Bracket {
            let observation = reads[Event::PreEnd.index()]?;
            return observation.valid.then_some(observation);
        }
        None
    }

    fn evaluate_admission(&self, state: SearchState) -> (Outcome, Option<String>) {
        let mut reasons = Vec::new();
        if state.match_ok != Some(true) {
            reasons.push("candidate_match_failed".to_owned());
        }
        if self.premises.pending_probe {
            for event in self.configured_probes() {
                match state.pending[event.index()] {
                    None => reasons.push(format!(
                        "pending_probe_observation_missing:{}",
                        event.name()
                    )),
                    Some(observation) if observation.pending => reasons.push(format!(
                        "pending_probe_latched_unsafe_delta:{}",
                        event.name()
                    )),
                    Some(_) => {}
                }
            }
        }
        if self.premises.post_recheck {
            let observation = state.reads[self.recheck_event().index()];
            match observation {
                None => reasons.push("post_recheck_read_missing_or_rejected".into()),
                Some(observation) if !observation.valid => {
                    reasons.push("post_recheck_read_missing_or_rejected".into())
                }
                Some(observation) => {
                    if state.evidence.is_none_or(|evidence| {
                        (observation.manifest, observation.body)
                            != (evidence.manifest, evidence.body)
                    }) {
                        reasons.push("post_recheck_disagrees_with_evidence".into());
                    }
                }
            }
            if self.mode == Mode::Bracket {
                match state.reads[Event::PreEnd.index()] {
                    None => reasons.push("pre_observation_missing_or_rejected".into()),
                    Some(observation) if !observation.valid => {
                        reasons.push("pre_observation_missing_or_rejected".into())
                    }
                    Some(observation) => {
                        if state.positions[Event::CommitDurable.index()]
                            .is_some_and(|durable| observation.step >= durable)
                        {
                            reasons.push("pre_observation_does_not_precede_commit".into());
                        }
                    }
                }
            }
        }
        if self.premises.final_reload {
            let first = state.reads[self.final_event().index()];
            if first.is_none_or(|observation| !observation.valid) {
                reasons.push("final_load_read_missing_or_rejected".into());
            }
            if self.mode == Mode::Bracket
                && state.reads[Event::ReloadM1.index()].is_none_or(|observation| !observation.valid)
            {
                reasons.push("final_load_read_missing_or_rejected:RELOAD_M1".into());
            }
        }
        if self.premises.generation_revoke_fence {
            let rejected = EVENTS
                .iter()
                .copied()
                .filter(|event| state.reads[event.index()].is_some_and(|read| !read.valid))
                .map(Event::name)
                .collect::<BTreeSet<_>>();
            if !rejected.is_empty() {
                reasons.push(format!(
                    "generation_fence_rejected_reads:{}",
                    rejected.into_iter().collect::<Vec<_>>().join(",")
                ));
            }
        }
        if reasons.is_empty() {
            (Outcome::Admitted, None)
        } else {
            (Outcome::Denied, Some(reasons.join(";")))
        }
    }

    fn dfs(&mut self, state: SearchState, sequence: &mut Vec<Event>) {
        self.counters.explored_states += 1;
        let next_checklist = self
            .chains
            .checklist_events
            .get(state.checklist_index)
            .copied();
        let mut enabled = Vec::with_capacity(5);
        if let Some(event) = next_checklist {
            if !(event == Event::Match && state.pre_index < self.chains.pre_events.len()) {
                enabled.push(event);
            }
        }
        if let Some(event) = self.chains.pre_events.get(state.pre_index).copied() {
            enabled.push(event);
        }
        if let Some(event) = self
            .chains
            .mutation_events
            .get(state.mutation_index)
            .copied()
        {
            enabled.push(event);
        }
        if state.body_index < self.chains.body_events.len() && state.mutation_index >= 2 {
            enabled.push(self.chains.body_events[state.body_index]);
        }
        if !self.chains.bypass_events.is_empty() && state.bypass_index == 0 {
            enabled.push(self.chains.bypass_events[0]);
        }
        if sequence.len() >= self.bound {
            self.counters.incomplete_traces += 1;
            self.counters.explored_traces += 1;
            return;
        }
        let step = sequence.len();
        for event in enabled {
            let mut next = state;
            let mut terminal = false;
            let mut outcome = None;
            let mut reason = None;
            if event.is_cache_read() {
                let observation = self.read_for(state, step);
                next.reads[event.index()] = Some(observation);
                if event == self.final_event() && self.premises.final_reload {
                    next.evidence = observation.valid.then_some(observation);
                }
            } else if event == Event::Match {
                if !self.premises.final_reload {
                    next.evidence = self.evidence_read(&state.reads);
                }
                next.match_ok = Some(next.evidence.is_some_and(|evidence| {
                    !self.premises.exact_identity || evidence.body == Revision::Candidate
                }));
            } else if event == Event::Admit {
                let (admission, denial_reason) = self.evaluate_admission(state);
                outcome = Some(admission);
                reason = denial_reason;
                terminal = true;
            } else if event == Event::Bypass {
                outcome = Some(Outcome::BypassAdmitted);
                terminal = true;
            }
            if event.is_pending_probe() {
                let mutation_begun = state.mutation_index >= 1;
                let publication_complete = state.mutation_index >= 3 && state.body_index >= 1;
                next.pending[event.index()] = Some(PendingObservation {
                    step,
                    pending: mutation_begun && !publication_complete,
                });
            }
            if self.chains.checklist_events.contains(&event) {
                next.checklist_index += 1;
            } else if self.chains.mutation_events.contains(&event) {
                next.mutation_index += 1;
            } else if self.chains.body_events.contains(&event) {
                next.body_index += 1;
            } else if self.chains.pre_events.contains(&event) {
                next.pre_index += 1;
            } else {
                next.bypass_index += 1;
            }
            next.positions[event.index()] = Some(step);
            sequence.push(event);
            if terminal {
                self.record_terminal(
                    &next,
                    sequence,
                    outcome.expect("terminal event has an outcome"),
                    reason.as_deref(),
                );
            } else {
                self.dfs(next, sequence);
            }
            sequence.pop();
        }
    }

    fn final_observation_interval(&self, state: SearchState) -> Option<(usize, usize)> {
        if self.premises.final_reload {
            if let Some(step) = state.positions[self.final_event().index()] {
                return Some((step, step));
            }
        }
        if self.premises.post_recheck {
            if let Some(step) = state.positions[self.recheck_event().index()] {
                return if self.mode == Mode::Strict {
                    Some((step, step))
                } else {
                    Some((state.positions[Event::PostBegin.index()]?, step))
                };
            }
        }
        if self.mode == Mode::Bracket {
            return Some((
                state.positions[Event::PreBegin.index()]?,
                state.positions[Event::PreEnd.index()]?,
            ));
        }
        None
    }

    fn schedule_class(
        &self,
        state: SearchState,
        evidence: Option<ReadObservation>,
        last_read_step: isize,
    ) -> &'static str {
        if state.positions[Event::Bypass.index()].is_some() {
            return "bypass_unmediated_admission";
        }
        if state.reads.iter().flatten().any(|read| !read.consistent) {
            return "mixed_manifest_body_state";
        }
        if state.positions[Event::Rollback.index()].is_some() {
            return "stale_generation_pointer_rollback";
        }
        let Some(publish_step) = state.positions[Event::Publish.index()] else {
            return "source_pending_commit_without_publication";
        };
        let admit_step = state.positions[Event::Admit.index()].unwrap_or_default();
        let body_step = state.positions[Event::BodyAdvance.index()];
        if publish_step < admit_step
            && (publish_step as isize > last_read_step
                || body_step.is_some_and(|step| step as isize > last_read_step))
        {
            return "mutation_published_after_last_read_before_admission";
        }
        if evidence.is_some_and(|observation| publish_step > observation.step) {
            return "mutation_published_between_evidence_read_and_last_read";
        }
        if evidence.is_some_and(|observation| observation.body == Revision::Successor) {
            return "successor_revision_identity_confusion";
        }
        "unclassified"
    }

    fn record_terminal(
        &mut self,
        state: &SearchState,
        sequence: &[Event],
        outcome: Outcome,
        reason: Option<&str>,
    ) {
        self.counters.explored_traces += 1;
        let torn_kinds = state
            .reads
            .iter()
            .flatten()
            .filter(|observation| !observation.consistent)
            .map(|observation| {
                if observation.manifest == Generation::After {
                    "manifest_ahead_body_stale"
                } else {
                    "body_ahead_manifest_stale"
                }
            })
            .collect::<BTreeSet<_>>();
        if !torn_kinds.is_empty() {
            self.counters.torn_read_traces += 1;
            for kind in torn_kinds.iter() {
                *self.torn_kind_counts.entry((*kind).into()).or_default() += 1;
            }
        }
        let last_read_step = state
            .reads
            .iter()
            .flatten()
            .map(|observation| observation.step)
            .chain(
                state
                    .pending
                    .iter()
                    .flatten()
                    .map(|observation| observation.step),
            )
            .max()
            .map(|step| step as isize)
            .unwrap_or(-1);
        if outcome != Outcome::BypassAdmitted && !state.reads.iter().all(Option::is_none) {
            let admit_step = state.positions[Event::Admit.index()].unwrap_or_default();
            let publish_step = state.positions[Event::Publish.index()];
            let body_step = state.positions[Event::BodyAdvance.index()];
            let rollback_step = state.positions[Event::Rollback.index()];
            let publish_in_window = publish_step
                .is_some_and(|step| last_read_step < step as isize && step < admit_step);
            let body_in_window =
                body_step.is_some_and(|step| last_read_step < step as isize && step < admit_step);
            let rollback_in_window = rollback_step
                .is_some_and(|step| last_read_step < step as isize && step < admit_step);
            if publish_in_window || body_in_window {
                self.counters
                    .publish_after_last_read_before_admission_traces += 1;
                if outcome == Outcome::Admitted {
                    self.counters.admitted_publish_after_last_read += 1;
                }
            }
            if rollback_in_window {
                self.counters
                    .rollback_after_last_read_before_admission_traces += 1;
            }
            if self.premises.final_reload {
                if let Some(tf_step) = state.positions[self.final_event().index()] {
                    let publish_after_tf =
                        publish_step.is_some_and(|step| tf_step < step && step < admit_step);
                    let body_after_tf =
                        body_step.is_some_and(|step| tf_step < step && step < admit_step);
                    if publish_after_tf || body_after_tf {
                        self.counters
                            .publish_after_final_observation_before_admission_traces += 1;
                        if outcome == Outcome::Admitted {
                            self.counters.admitted_publish_after_final_observation += 1;
                        }
                    }
                    if state.positions[Event::CommitDurable.index()]
                        .is_some_and(|durable| durable < tf_step)
                        && (publish_in_window || body_in_window)
                    {
                        self.counters.stale_commit_publish_after_last_read_traces += 1;
                        if outcome == Outcome::Admitted {
                            self.counters.admitted_stale_commit_publish_after_last_read += 1;
                        }
                    }
                }
            }
        }
        if outcome == Outcome::Denied {
            self.counters.denied_traces += 1;
            for denial_reason in reason.unwrap_or_default().split(';') {
                *self
                    .denial_reasons
                    .entry(denial_reason.to_owned())
                    .or_default() += 1;
            }
            return;
        }
        self.counters.admitted_traces += 1;
        let commit_interval = state.positions[Event::CommitDurable.index()].map(|durable| {
            (
                state.positions[Event::CommitBegin.index()].unwrap_or_default(),
                durable,
            )
        });
        let domain = classify_domain(commit_interval, self.final_observation_interval(*state));
        if !torn_kinds.is_empty() {
            self.counters.admitted_torn_read_traces += 1;
            *self
                .admitted_torn_by_domain
                .entry(domain.to_owned())
                .or_default() += 1;
        }
        if outcome == Outcome::BypassAdmitted {
            self.counters.bypass_admitted_traces += 1;
        }
        if commit_interval.is_none() {
            self.counters.admitted_not_stale += 1;
            return;
        }
        match domain {
            "strictly_before" => self.counters.admitted_strictly_before += 1,
            "overlap_unknown" => self.counters.admitted_overlap_unknown += 1,
            "after_final_observation" => self.counters.admitted_after_final_observation += 1,
            _ => self.counters.admitted_unknown_domain += 1,
        }
        if domain != "strictly_before" {
            return;
        }
        self.counters.violations += 1;
        let schedule_class = self.schedule_class(*state, state.evidence, last_read_step);
        *self
            .violation_classes
            .entry(schedule_class.to_owned())
            .or_default() += 1;
        let candidate_names = sequence
            .iter()
            .map(|event| event.name())
            .collect::<Vec<_>>();
        let replace = self.best_violation.as_ref().is_none_or(|best| {
            (candidate_names.len(), candidate_names.as_slice())
                < (best.names.len(), best.names.as_slice())
        });
        if replace {
            let detail =
                self.counterexample_value(state, sequence, schedule_class, outcome, domain);
            self.best_violation = Some(BestViolation {
                names: candidate_names,
                detail,
            });
        }
    }

    fn counterexample_value(
        &self,
        state: &SearchState,
        sequence: &[Event],
        schedule_class: &str,
        outcome: Outcome,
        domain: &str,
    ) -> Value {
        let mut reads = Map::new();
        let mut pending = Map::new();
        for event in EVENTS {
            if let Some(observation) = state.reads[event.index()] {
                reads.insert(
                    event.name().into(),
                    json!({
                        "step": observation.step,
                        "gen": observation.manifest.as_str(),
                        "rev": observation.body.as_str(),
                        "valid": observation.valid,
                        "consistent": observation.consistent,
                        "reason": observation.reason,
                    }),
                );
            }
            if let Some(observation) = state.pending[event.index()] {
                pending.insert(
                    event.name().into(),
                    json!({"step": observation.step, "pending": observation.pending}),
                );
            }
        }
        let trace = sequence
            .iter()
            .enumerate()
            .map(|(step, event)| json!({"step": step, "event": event.name()}))
            .collect::<Vec<_>>();
        json!({
            "scheduleClass": schedule_class,
            "outcome": outcome.as_str(),
            "domain": domain,
            "staleAtAdmission": true,
            "eventCount": sequence.len(),
            "stepCount": sequence.len(),
            "reads": reads,
            "pendingObservations": pending,
            "trace": trace,
        })
    }

    fn into_value(self) -> Value {
        let counters = self.counters;
        let complete = counters.incomplete_traces == 0;
        let status = if counters.violations > 0 {
            "FAIL"
        } else if complete {
            "PASS"
        } else {
            "UNKNOWN"
        };
        let violation_classes = map_value(self.violation_classes);
        let denial_reasons = map_value(self.denial_reasons);
        let torn_kind_counts = map_value(self.torn_kind_counts);
        let admitted_torn_by_domain = map_value(self.admitted_torn_by_domain);
        let counterexample = self
            .best_violation
            .map(|best| best.detail)
            .unwrap_or(Value::Null);
        json!({
            "premises": self.premises.as_value(),
            "mode": self.mode.as_str(),
            "bound": self.bound,
            "requiredBound": required_bound(self.premises, self.mode),
            "explorationComplete": complete,
            "exploredStates": counters.explored_states,
            "exploredTraces": counters.explored_traces,
            "incompleteTraces": counters.incomplete_traces,
            "admittedTraces": counters.admitted_traces,
            "deniedTraces": counters.denied_traces,
            "bypassAdmittedTraces": counters.bypass_admitted_traces,
            "admittedDomainCounts": {
                "notStale": counters.admitted_not_stale,
                "strictlyBefore": counters.admitted_strictly_before,
                "overlapUnknown": counters.admitted_overlap_unknown,
                "afterFinalObservation": counters.admitted_after_final_observation,
                "unknownDomain": counters.admitted_unknown_domain,
            },
            "violations": counters.violations,
            "violationsByDomain": {
                "strictlyBefore": counters.admitted_strictly_before,
                "overlapUnknown": 0,
                "afterFinalObservation": 0,
                "unknownDomain": 0,
                "notStale": 0,
            },
            "violationClasses": violation_classes,
            "denialReasons": denial_reasons,
            "admissionWindow": {
                "publishAfterLastReadBeforeAdmissionTraces": counters.publish_after_last_read_before_admission_traces,
                "admittedPublishAfterLastRead": counters.admitted_publish_after_last_read,
                "rollbackAfterLastReadBeforeAdmissionTraces": counters.rollback_after_last_read_before_admission_traces,
                "publishAfterFinalObservationBeforeAdmissionTraces": counters.publish_after_final_observation_before_admission_traces,
                "admittedPublishAfterFinalObservation": counters.admitted_publish_after_final_observation,
                "staleCommitPublishAfterLastReadTraces": counters.stale_commit_publish_after_last_read_traces,
                "admittedStaleCommitPublishAfterLastRead": counters.admitted_stale_commit_publish_after_last_read,
            },
            "mixedManifestBody": {
                "tornReadTraces": counters.torn_read_traces,
                "admittedTornReadTraces": counters.admitted_torn_read_traces,
                "admittedTornReadTracesByDomain": admitted_torn_by_domain,
                "tornReadTracesByKind": torn_kind_counts,
            },
            "counterexample": counterexample,
            "status": status,
        })
    }
}

fn map_value(values: BTreeMap<String, usize>) -> Value {
    let mut result = Map::new();
    for (key, value) in values {
        result.insert(key, json!(value));
    }
    Value::Object(result)
}

pub fn run_model(premises: Premises, mode: Mode, bound: usize) -> Result<Value, String> {
    validate_bound(bound)?;
    let mut context = RunContext::new(premises, mode, bound);
    let mut initial = SearchState::default();
    initial.positions[Event::Init.index()] = Some(0);
    context.dfs(initial, &mut vec![Event::Init]);
    Ok(context.into_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    static DEFAULT_REPORT: OnceLock<Value> = OnceLock::new();

    fn default_report() -> &'static Value {
        DEFAULT_REPORT.get_or_init(|| build_report(DEFAULT_BOUND).unwrap())
    }

    fn events(counterexample: &Value) -> Vec<&str> {
        counterexample["trace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["event"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn observation_modes_keep_the_ordered_read_and_latch_contract() {
        let bracket = build_chains(Premises::default(), Mode::Bracket);
        assert_eq!(
            &bracket.checklist[..5],
            ["RELOAD_M0", "RELOAD_P0", "RELOAD_M1", "RELOAD_P1", "MATCH"]
        );
        assert_eq!(bracket.recheck, ["POST_OBS_BEGIN", "POST_OBS_END"]);
        assert_eq!(bracket.checklist.last(), Some(&"ADMIT"));
        let strict = build_chains(Premises::default(), Mode::Strict);
        assert_eq!(
            strict.checklist,
            ["STRICT_LOAD", "MATCH", "STRICT_OBS", "ADMIT"]
        );
        assert!(strict.pre.is_empty());
        let no_probe = build_chains(
            Premises::default().without("pending_probe").unwrap(),
            Mode::Bracket,
        );
        assert!(!no_probe.checklist.contains(&"RELOAD_P0"));
        assert!(no_probe.checklist.contains(&"RELOAD_M0"));
        let no_reload = build_chains(
            Premises::default().without("final_reload").unwrap(),
            Mode::Bracket,
        );
        assert!(["RELOAD_M0", "RELOAD_P0", "RELOAD_M1", "RELOAD_P1"]
            .iter()
            .all(|event| !no_reload.checklist.contains(event)));
    }

    #[test]
    fn cache_observation_covers_consistent_torn_and_rollback_states() {
        let before = cache_observation(10, None, None, None, true);
        assert_eq!(before["manifest"], "g0");
        assert_eq!(before["body"], "r0");
        assert_eq!(before["head"], "g0");
        assert_eq!(before["valid"], true);
        let published_first = cache_observation(10, Some(4), None, None, true);
        assert_eq!(published_first["reason"], "manifest_ahead_body_stale");
        let body_first = cache_observation(10, None, Some(4), None, true);
        assert_eq!(body_first["reason"], "body_ahead_manifest_stale");
        let rolled_back = cache_observation(10, Some(4), Some(3), Some(5), true);
        assert_eq!(rolled_back["reason"], "generation_below_published_head");
        let re_advanced = cache_observation(10, Some(4), Some(7), Some(5), true);
        assert_eq!(re_advanced["reason"], "body_ahead_manifest_stale");
        let raw_torn = cache_observation(10, Some(4), None, None, false);
        assert_eq!(raw_torn["valid"], true);
        assert_eq!(raw_torn["consistent"], false);
    }

    #[test]
    fn domain_classification_keeps_overlap_outside_the_theorem() {
        assert_eq!(
            classify_domain(Some((3, 5)), Some((6, 8))),
            "strictly_before"
        );
        assert_eq!(
            classify_domain(Some((3, 5)), Some((5, 8))),
            "overlap_unknown"
        );
        assert_eq!(
            classify_domain(Some((3, 6)), Some((6, 6))),
            "overlap_unknown"
        );
        assert_eq!(
            classify_domain(Some((6, 8)), Some((2, 4))),
            "after_final_observation"
        );
        assert_eq!(classify_domain(None, Some((2, 4))), "not_stale");
        assert_eq!(classify_domain(Some((3, 5)), None), "unknown_domain");
    }

    #[test]
    fn bound_validation_and_fail_unknown_precedence_are_preserved() {
        assert_eq!(validate_bound(MIN_BOUND), Ok(MIN_BOUND));
        assert_eq!(validate_bound(MAX_BOUND), Ok(MAX_BOUND));
        for invalid in [0, 1, MAX_BOUND + 1, 1_000_000] {
            assert!(validate_bound(invalid).is_err());
        }
        let incomplete = run_model(Premises::default(), Mode::Bracket, 8).unwrap();
        assert_eq!(incomplete["status"], "UNKNOWN");
        assert_eq!(incomplete["explorationComplete"], false);
        assert!(incomplete["incompleteTraces"].as_u64().unwrap() > 0);
        let decisive = run_model(
            Premises::default().without("pending_probe").unwrap(),
            Mode::Bracket,
            13,
        )
        .unwrap();
        assert_eq!(decisive["status"], "FAIL");
        assert_eq!(decisive["explorationComplete"], false);
        assert!(decisive["violations"].as_u64().unwrap() > 0);
    }

    #[test]
    fn full_contract_and_omission_counts_match_the_reference_checker() {
        let report = default_report();
        let reference: Value =
            serde_json::from_str(include_str!("fixtures/e5-single-reference-28.json")).unwrap();
        assert_eq!(*report, reference);
        assert_eq!(report["model"], MODEL_NAME);
        assert_eq!(report["modelVersion"], MODEL_VERSION);
        assert_eq!(report["theorem"], THEOREM_ID);
        assert_eq!(report["status"], "PASS");
        assert_eq!(report["exploredStates"], 1_503_835);
        assert_eq!(report["exploredTraces"], 931_110);
        let bracket = &report["fullContract"]["modes"]["bracket"];
        assert_eq!(bracket["requiredBound"], 16);
        assert_eq!(bracket["exploredStates"], 333_417);
        assert_eq!(bracket["exploredTraces"], 129_855);
        assert_eq!(bracket["violations"], 0);
        assert_eq!(
            bracket["admittedDomainCounts"]["afterFinalObservation"],
            1_566
        );
        assert_eq!(
            bracket["admissionWindow"]["staleCommitPublishAfterLastReadTraces"],
            2_523
        );
        assert_eq!(
            bracket["admissionWindow"]["admittedStaleCommitPublishAfterLastRead"],
            0
        );
        assert_eq!(bracket["mixedManifestBody"]["tornReadTraces"], 70_089);
        assert_eq!(bracket["mixedManifestBody"]["admittedTornReadTraces"], 0);
        let strict = &report["fullContract"]["modes"]["strict"];
        assert_eq!(strict["requiredBound"], 10);
        assert_eq!(strict["exploredStates"], 524);
        assert_eq!(strict["exploredTraces"], 328);
        assert_eq!(strict["violations"], 0);
        assert_eq!(
            strict["admissionWindow"]["admittedPublishAfterFinalObservation"],
            48
        );
        assert_eq!(strict["mixedManifestBody"]["tornReadTraces"], 119);
        assert_eq!(strict["mixedManifestBody"]["admittedTornReadTraces"], 0);
        let omissions = report["omissions"].as_array().unwrap();
        assert_eq!(omissions.len(), PREMISES.len());
        let expected = [
            (
                "pending_probe",
                27,
                "source_pending_commit_without_publication",
                11,
            ),
            (
                "post_recheck",
                302,
                "mutation_published_between_evidence_read_and_last_read",
                13,
            ),
            (
                "final_reload",
                63,
                "source_pending_commit_without_publication",
                9,
            ),
            (
                "exact_identity",
                12,
                "successor_revision_identity_confusion",
                15,
            ),
            (
                "generation_revoke_fence",
                42,
                "stale_generation_pointer_rollback",
                16,
            ),
            ("host_mediation", 65_672, "bypass_unmediated_admission", 5),
        ];
        for (item, (premise, violation_count, class, event_count)) in omissions.iter().zip(expected)
        {
            assert_eq!(item["premise"], premise);
            assert_eq!(item["status"], "FAIL");
            assert_eq!(item["finding"], "counterexample_found");
            assert_eq!(item["run"]["violations"], violation_count);
            assert_eq!(item["counterexample"]["scheduleClass"], class);
            assert_eq!(item["counterexample"]["eventCount"], event_count);
            assert_eq!(item["counterexample"]["domain"], "strictly_before");
            assert_eq!(item["counterexample"]["staleAtAdmission"], true);
        }
        assert_eq!(
            events(&omissions[0]["counterexample"]),
            [
                "INIT",
                "COMMIT_BEGIN",
                "PRE_OBS_BEGIN",
                "PRE_OBS_END",
                "COMMIT_DURABLE",
                "RELOAD_M0",
                "RELOAD_M1",
                "MATCH",
                "POST_OBS_BEGIN",
                "POST_OBS_END",
                "ADMIT"
            ]
        );
        assert_eq!(
            events(&omissions[1]["counterexample"]),
            [
                "INIT",
                "COMMIT_BEGIN",
                "COMMIT_DURABLE",
                "PRE_OBS_BEGIN",
                "PRE_OBS_END",
                "RELOAD_M0",
                "EVIDENCE_BODY_ADVANCE",
                "PUBLISH",
                "RELOAD_P0",
                "RELOAD_M1",
                "RELOAD_P1",
                "MATCH",
                "ADMIT"
            ]
        );
        assert_eq!(
            events(&omissions[2]["counterexample"]),
            [
                "INIT",
                "COMMIT_BEGIN",
                "PRE_OBS_BEGIN",
                "PRE_OBS_END",
                "COMMIT_DURABLE",
                "MATCH",
                "POST_OBS_BEGIN",
                "POST_OBS_END",
                "ADMIT"
            ]
        );
        assert_eq!(
            events(&omissions[3]["counterexample"]),
            [
                "INIT",
                "COMMIT_BEGIN",
                "PRE_OBS_BEGIN",
                "PRE_OBS_END",
                "COMMIT_DURABLE",
                "EVIDENCE_BODY_ADVANCE",
                "PUBLISH",
                "RELOAD_M0",
                "RELOAD_P0",
                "RELOAD_M1",
                "RELOAD_P1",
                "MATCH",
                "POST_OBS_BEGIN",
                "POST_OBS_END",
                "ADMIT"
            ]
        );
        assert_eq!(
            events(&omissions[4]["counterexample"]),
            [
                "INIT",
                "COMMIT_BEGIN",
                "PRE_OBS_BEGIN",
                "PRE_OBS_END",
                "COMMIT_DURABLE",
                "EVIDENCE_BODY_ADVANCE",
                "PUBLISH",
                "ROLLBACK",
                "RELOAD_M0",
                "RELOAD_P0",
                "RELOAD_M1",
                "RELOAD_P1",
                "MATCH",
                "POST_OBS_BEGIN",
                "POST_OBS_END",
                "ADMIT"
            ]
        );
        assert_eq!(
            events(&omissions[5]["counterexample"]),
            [
                "INIT",
                "COMMIT_BEGIN",
                "COMMIT_DURABLE",
                "RELOAD_M0",
                "BYPASS"
            ]
        );
    }

    #[test]
    fn default_report_and_individual_runs_are_deterministic() {
        let first = run_model(
            Premises::default().without("exact_identity").unwrap(),
            Mode::Bracket,
            20,
        )
        .unwrap();
        let second = run_model(
            Premises::default().without("exact_identity").unwrap(),
            Mode::Bracket,
            20,
        )
        .unwrap();
        assert_eq!(first, second);
        let first_report = build_report(DEFAULT_BOUND).unwrap();
        let second_report = build_report(DEFAULT_BOUND).unwrap();
        assert_eq!(first_report, second_report);
    }
}
