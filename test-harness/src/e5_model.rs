//! ABSTRACT BOUNDED-MODEL EVIDENCE ONLY (E5 v2.1.0).
//!
//! NOT a mechanized proof of the AstralLight Rust or Java implementation, any
//! deployment, or runtime behavior. Structural assumptions are reported in
//! `scopeLimitations`.

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

pub fn validate_bound_value(value: &Value) -> Result<usize, String> {
    let bound = value
        .as_u64()
        .and_then(|bound| usize::try_from(bound).ok())
        .ok_or_else(|| {
            format!("max-steps must be a finite integer in [{MIN_BOUND}, {MAX_BOUND}]")
        })?;
    validate_bound(bound)
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
        let no_probe_strict = build_chains(
            Premises::default().without("pending_probe").unwrap(),
            Mode::Strict,
        );
        assert!(no_probe_strict.checklist.contains(&"STRICT_LOAD"));
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
        assert_eq!(
            (
                before["manifest"].as_str(),
                before["body"].as_str(),
                before["head"].as_str()
            ),
            (Some("g0"), Some("r0"), Some("g0"))
        );
        assert_eq!(before["valid"], true);
        assert_eq!(before["consistent"], true);
        let after = cache_observation(10, Some(4), Some(5), None, true);
        assert_eq!(
            (
                after["manifest"].as_str(),
                after["body"].as_str(),
                after["head"].as_str()
            ),
            (Some("g1"), Some("r1"), Some("g1"))
        );
        assert_eq!(after["valid"], true);
        assert_eq!(after["consistent"], true);
        let boundary = cache_observation(4, Some(4), None, None, true);
        assert_eq!(boundary["manifest"], "g1");
        assert_eq!(boundary["head"], "g1");
        let published_first = cache_observation(10, Some(4), None, None, true);
        assert_eq!(published_first["consistent"], false);
        assert_eq!(published_first["valid"], false);
        assert_eq!(published_first["reason"], "manifest_ahead_body_stale");
        let body_first = cache_observation(10, None, Some(4), None, true);
        assert_eq!(body_first["consistent"], false);
        assert_eq!(body_first["valid"], false);
        assert_eq!(body_first["reason"], "body_ahead_manifest_stale");
        let rolled_back = cache_observation(10, Some(4), Some(3), Some(5), true);
        assert_eq!(rolled_back["manifest"], "g0");
        assert_eq!(rolled_back["body"], "r0");
        assert_eq!(rolled_back["head"], "g1");
        assert_eq!(rolled_back["consistent"], true);
        assert_eq!(rolled_back["valid"], false);
        assert_eq!(rolled_back["reason"], "generation_below_published_head");
        let re_advanced = cache_observation(10, Some(4), Some(7), Some(5), true);
        assert_eq!(re_advanced["manifest"], "g0");
        assert_eq!(re_advanced["body"], "r1");
        assert_eq!(re_advanced["consistent"], false);
        assert_eq!(re_advanced["valid"], false);
        assert_eq!(re_advanced["reason"], "body_ahead_manifest_stale");
        let raw_manifest_ahead = cache_observation(10, Some(4), None, None, false);
        assert_eq!(raw_manifest_ahead["manifest"], "g1");
        assert_eq!(raw_manifest_ahead["body"], "r0");
        assert_eq!(raw_manifest_ahead["head"], "g1");
        assert_eq!(raw_manifest_ahead["valid"], true);
        assert_eq!(raw_manifest_ahead["consistent"], false);
        assert_eq!(raw_manifest_ahead["reason"], Value::Null);
        let raw_body_ahead = cache_observation(10, None, Some(4), None, false);
        assert_eq!(raw_body_ahead["manifest"], "g0");
        assert_eq!(raw_body_ahead["body"], "r1");
        assert_eq!(raw_body_ahead["head"], "g0");
        assert_eq!(raw_body_ahead["valid"], true);
        assert_eq!(raw_body_ahead["consistent"], false);
        assert_eq!(raw_body_ahead["reason"], Value::Null);
    }

    #[test]
    fn domain_classification_keeps_overlap_outside_the_theorem() {
        let report = default_report();
        for mode in ["bracket", "strict"] {
            assert_eq!(
                report["fullContract"]["modes"][mode]["violationsByDomain"]["overlapUnknown"], 0,
                "{mode}"
            );
            assert_eq!(
                report["fullContract"]["modes"][mode]["violations"],
                report["fullContract"]["modes"][mode]["admittedDomainCounts"]["strictlyBefore"],
                "{mode}"
            );
        }
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
        assert_eq!(validate_bound(14), Ok(14));
        assert_eq!(validate_bound_value(&json!(MIN_BOUND)), Ok(MIN_BOUND));
        assert_eq!(validate_bound_value(&json!(MAX_BOUND)), Ok(MAX_BOUND));
        assert_eq!(validate_bound_value(&json!(14)), Ok(14));
        for invalid in [0, 1, MAX_BOUND + 1, 1_000_000] {
            assert!(validate_bound(invalid).is_err());
        }
        for invalid in [json!(0), json!(1), json!(MAX_BOUND + 1), json!(1_000_000)] {
            assert!(validate_bound_value(&invalid).is_err(), "{invalid}");
        }
        for invalid in [
            Value::Null,
            json!("12"),
            json!(-1),
            json!(1.0),
            json!(2.5),
            json!(true),
            json!(false),
            json!([14]),
            json!({"bound": 14}),
        ] {
            assert!(validate_bound_value(&invalid).is_err(), "{invalid}");
        }
        let incomplete = run_model(Premises::default(), Mode::Bracket, 8).unwrap();
        assert_eq!(incomplete["status"], "UNKNOWN");
        assert_eq!(incomplete["explorationComplete"], false);
        assert_eq!(incomplete["violations"], 0);
        assert!(incomplete["incompleteTraces"].as_u64().unwrap() > 0);
        assert!(
            incomplete["bound"].as_u64().unwrap() < incomplete["requiredBound"].as_u64().unwrap()
        );
        let decisive = run_model(
            Premises::default().without("pending_probe").unwrap(),
            Mode::Bracket,
            13,
        )
        .unwrap();
        assert_eq!(decisive["status"], "FAIL");
        assert_eq!(decisive["explorationComplete"], false);
        assert!(decisive["incompleteTraces"].as_u64().unwrap() > 0);
        assert!(decisive["violations"].as_u64().unwrap() > 0);
        assert!(decisive["bound"].as_u64().unwrap() < decisive["requiredBound"].as_u64().unwrap());
        assert!(decisive["counterexample"].is_object());
    }

    #[test]
    fn full_contract_and_omission_counts_match_the_reference_checker() {
        let report = default_report();
        let reference: Value =
            serde_json::from_str(include_str!("fixtures/e5-single-reference-28.json")).unwrap();
        let serialized = serde_json::to_string(report).unwrap();
        let round_tripped: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(round_tripped["model"], report["model"]);
        assert!(round_tripped["scopeLimitations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item.as_str().unwrap().contains("not a mechanized proof")));
        assert_eq!(*report, reference);
        assert_eq!(report["model"], MODEL_NAME);
        assert_eq!(report["modelVersion"], MODEL_VERSION);
        assert_eq!(report["theorem"], THEOREM_ID);
        assert_eq!(report["status"], "PASS");
        for mode in ["bracket", "strict"] {
            let run = &report["fullContract"]["modes"][mode];
            assert_eq!(run["status"], "PASS", "{mode}");
            assert_eq!(run["violations"], 0, "{mode}");
            assert_eq!(run["explorationComplete"], true, "{mode}");
            assert_eq!(run["bound"], DEFAULT_BOUND, "{mode}");
            assert!(
                run["bound"].as_u64().unwrap() >= run["requiredBound"].as_u64().unwrap(),
                "{mode}"
            );
        }
        assert_eq!(report["exploredStates"], 1_503_835);
        assert_eq!(report["exploredTraces"], 931_110);
        let bracket = &report["fullContract"]["modes"]["bracket"];
        assert_eq!(bracket["requiredBound"], 16);
        assert_eq!(bracket["admittedDomainCounts"]["strictlyBefore"], 0);
        assert_eq!(bracket["violations"], 0);
        assert!(
            bracket["admissionWindow"]["staleCommitPublishAfterLastReadTraces"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(
            bracket["admissionWindow"]["admittedStaleCommitPublishAfterLastRead"],
            0
        );
        assert!(bracket["denialReasons"]
            .as_object()
            .unwrap()
            .keys()
            .any(|key| { key.starts_with("pending_probe_latched_unsafe_delta") }));
        assert!(bracket["denialReasons"]
            .as_object()
            .unwrap()
            .contains_key("pending_probe_latched_unsafe_delta:RELOAD_P0"));
        assert!(bracket["denialReasons"]
            .as_object()
            .unwrap()
            .contains_key("pending_probe_latched_unsafe_delta:RELOAD_P1"));
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
        assert_eq!(strict["admittedDomainCounts"]["strictlyBefore"], 0);
        assert_eq!(strict["violations"], 0);
        assert_eq!(strict["exploredStates"], 524);
        assert_eq!(strict["exploredTraces"], 328);
        assert_eq!(strict["violations"], 0);
        assert_eq!(
            strict["admissionWindow"]["admittedPublishAfterFinalObservation"],
            48
        );
        assert_eq!(strict["mixedManifestBody"]["tornReadTraces"], 119);
        assert_eq!(strict["mixedManifestBody"]["admittedTornReadTraces"], 0);
        for mode in ["bracket", "strict"] {
            let run = &report["fullContract"]["modes"][mode];
            assert_eq!(run["admittedDomainCounts"]["strictlyBefore"], 0, "{mode}");
            assert_eq!(run["violations"], 0, "{mode}");
            assert!(
                run["mixedManifestBody"]["tornReadTracesByKind"]["manifest_ahead_body_stale"]
                    .as_u64()
                    .unwrap()
                    > 0,
                "{mode}"
            );
            assert!(
                run["mixedManifestBody"]["tornReadTracesByKind"]["body_ahead_manifest_stale"]
                    .as_u64()
                    .unwrap()
                    > 0,
                "{mode}"
            );
            assert_eq!(
                run["mixedManifestBody"]["admittedTornReadTraces"], 0,
                "{mode}"
            );
            assert!(
                run["admissionWindow"]["staleCommitPublishAfterLastReadTraces"]
                    .as_u64()
                    .unwrap()
                    > 0,
                "{mode}"
            );
            assert_eq!(
                run["admissionWindow"]["admittedStaleCommitPublishAfterLastRead"], 0,
                "{mode}"
            );
            assert!(
                run["denialReasons"]
                    .as_object()
                    .unwrap()
                    .keys()
                    .any(|key| { key.starts_with("pending_probe_latched_unsafe_delta:") }),
                "{mode}"
            );
            assert!(
                run["admittedDomainCounts"]["afterFinalObservation"]
                    .as_u64()
                    .unwrap()
                    > 0,
                "{mode}"
            );
            assert!(
                run["admissionWindow"]["admittedPublishAfterFinalObservation"]
                    .as_u64()
                    .unwrap()
                    > 0,
                "{mode}"
            );
            assert_eq!(
                run["violationsByDomain"]["afterFinalObservation"], 0,
                "{mode}"
            );
            assert_eq!(run["violationsByDomain"]["overlapUnknown"], 0, "{mode}");
            assert_eq!(
                run["violations"], run["admittedDomainCounts"]["strictlyBefore"],
                "{mode}"
            );
            for (domain, count) in run["violationsByDomain"].as_object().unwrap() {
                if domain != "strictlyBefore" {
                    assert_eq!(count, 0, "{mode} {domain}");
                }
            }
        }
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
        for entry in omissions {
            for key in [
                "premise",
                "premiseRemoved",
                "status",
                "finding",
                "intendedSchedule",
                "counterexample",
                "note",
                "run",
            ] {
                assert!(
                    entry.get(key).is_some(),
                    "{} missing {key}",
                    entry["premise"]
                );
            }
            assert_eq!(entry["premise"], entry["premiseRemoved"]);
            assert!(matches!(
                entry["status"].as_str(),
                Some("PASS" | "FAIL" | "BLOCKED" | "UNKNOWN")
            ));
            assert_eq!(entry["counterexample"]["domain"], "strictly_before");
            assert_eq!(entry["counterexample"]["staleAtAdmission"], true);
            for key in [
                "scheduleClass",
                "outcome",
                "domain",
                "staleAtAdmission",
                "eventCount",
                "stepCount",
                "reads",
                "pendingObservations",
                "trace",
            ] {
                assert!(
                    entry["counterexample"].get(key).is_some(),
                    "{} counterexample missing {key}",
                    entry["premise"]
                );
            }
        }
        let pending_probe_counterexample = &omissions[0]["counterexample"];
        assert_eq!(
            pending_probe_counterexample["scheduleClass"],
            "source_pending_commit_without_publication"
        );
        assert!(pending_probe_counterexample["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event"] == "COMMIT_DURABLE"));
        assert!(pending_probe_counterexample["trace"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| !matches!(
                event["event"].as_str(),
                Some("PUBLISH" | "EVIDENCE_BODY_ADVANCE")
            )));
        assert!(pending_probe_counterexample["trace"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event"] == "ADMIT"));
        assert_eq!(pending_probe_counterexample["outcome"], "ADMITTED");
        assert_eq!(pending_probe_counterexample["staleAtAdmission"], true);
        assert_eq!(pending_probe_counterexample["domain"], "strictly_before");
        assert_eq!(
            pending_probe_counterexample["pendingObservations"],
            json!({})
        );
        let before_t_f_probe_omission = &omissions[0]["run"]["admissionWindow"];
        assert!(
            before_t_f_probe_omission["staleCommitPublishAfterLastReadTraces"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(
            before_t_f_probe_omission["admittedStaleCommitPublishAfterLastRead"]
                .as_u64()
                .unwrap()
                > 0
        );
        let no_recheck_counterexample = &omissions[1]["counterexample"];
        let no_recheck_events = events(no_recheck_counterexample);
        let event_position = |name: &str| {
            no_recheck_events
                .iter()
                .position(|event| *event == name)
                .unwrap()
        };
        assert!(event_position("RELOAD_M0") < event_position("PUBLISH"));
        assert!(event_position("PUBLISH") < event_position("RELOAD_P0"));
        assert_eq!(
            no_recheck_counterexample["pendingObservations"]["RELOAD_P0"]["pending"],
            false
        );
        assert_eq!(
            no_recheck_counterexample["pendingObservations"]["RELOAD_P1"]["pending"],
            false
        );
        assert_eq!(no_recheck_counterexample["reads"]["RELOAD_M0"]["gen"], "g0");
        assert_eq!(no_recheck_counterexample["reads"]["RELOAD_M0"]["rev"], "r0");
        assert_eq!(no_recheck_counterexample["reads"]["RELOAD_M1"]["gen"], "g1");
        assert_eq!(no_recheck_counterexample["reads"]["RELOAD_M1"]["rev"], "r1");
        assert!(!no_recheck_events.contains(&"POST_OBS_END"));
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
        let no_final_reload_counterexample = &omissions[2]["counterexample"];
        let no_final_reload_events = events(no_final_reload_counterexample);
        for event in ["RELOAD_M0", "RELOAD_P0", "RELOAD_M1", "RELOAD_P1"] {
            assert!(!no_final_reload_events.contains(&event));
        }
        assert_eq!(
            no_final_reload_counterexample["pendingObservations"],
            json!({})
        );
        assert!(no_final_reload_events.contains(&"COMMIT_DURABLE"));
        assert_eq!(no_final_reload_counterexample["domain"], "strictly_before");

        let no_identity_counterexample = &omissions[3]["counterexample"];
        let no_identity_events = events(no_identity_counterexample);
        assert!(
            no_identity_events
                .iter()
                .position(|event| *event == "PUBLISH")
                .unwrap()
                < no_identity_events
                    .iter()
                    .position(|event| *event == "RELOAD_M0")
                    .unwrap()
        );
        assert!(!no_identity_events.contains(&"ROLLBACK"));
        for event in ["RELOAD_P0", "RELOAD_P1", "POST_OBS_END", "MATCH"] {
            assert!(no_identity_events.contains(&event));
        }
        assert_eq!(
            no_identity_counterexample["reads"]["RELOAD_M0"]["gen"],
            "g1"
        );
        assert_eq!(
            no_identity_counterexample["reads"]["RELOAD_M0"]["rev"],
            "r1"
        );
        assert!(omissions[3]["run"]["violationClasses"]
            .get("stale_generation_pointer_rollback")
            .is_some());

        let no_fence_counterexample = &omissions[4]["counterexample"];
        let no_fence_events = events(no_fence_counterexample);
        assert!(
            no_fence_events
                .iter()
                .position(|event| *event == "PUBLISH")
                .unwrap()
                < no_fence_events
                    .iter()
                    .position(|event| *event == "ROLLBACK")
                    .unwrap()
        );
        assert!(
            no_fence_events
                .iter()
                .position(|event| *event == "ROLLBACK")
                .unwrap()
                < no_fence_events
                    .iter()
                    .position(|event| *event == "RELOAD_M0")
                    .unwrap()
        );
        assert_eq!(no_fence_counterexample["domain"], "strictly_before");
        assert_eq!(
            omissions[4]["run"]["violationClasses"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            omissions[4]["run"]["violationClasses"]["stale_generation_pointer_rollback"],
            omissions[4]["run"]["violations"]
        );

        let no_host_mediation = run_model(
            Premises::default().without("host_mediation").unwrap(),
            Mode::Bracket,
            DEFAULT_BOUND,
        )
        .unwrap();
        assert_eq!(no_host_mediation["status"], "FAIL");
        assert!(
            no_host_mediation["admittedDomainCounts"]["overlapUnknown"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(no_host_mediation["violationsByDomain"]["overlapUnknown"], 0);
        assert_eq!(
            no_host_mediation["violations"],
            no_host_mediation["admittedDomainCounts"]["strictlyBefore"]
        );
        assert_eq!(
            no_host_mediation["violations"],
            no_host_mediation["violationsByDomain"]["strictlyBefore"]
        );

        let fence_omission = run_model(
            Premises::default()
                .without("generation_revoke_fence")
                .unwrap(),
            Mode::Bracket,
            DEFAULT_BOUND,
        )
        .unwrap();
        assert_eq!(fence_omission["status"], "FAIL");
        let mixed = &fence_omission["mixedManifestBody"];
        assert!(mixed["tornReadTraces"].as_u64().unwrap() > 0);
        assert!(
            mixed["tornReadTracesByKind"]["manifest_ahead_body_stale"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(
            mixed["tornReadTracesByKind"]["body_ahead_manifest_stale"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(mixed["admittedTornReadTraces"].as_u64().unwrap() > 0);
        let admitted_domains = mixed["admittedTornReadTracesByDomain"].as_object().unwrap();
        assert_eq!(admitted_domains.len(), 1);
        assert!(admitted_domains.contains_key("after_final_observation"));
        assert_eq!(
            fence_omission["counterexample"]["scheduleClass"],
            "stale_generation_pointer_rollback"
        );
        assert_eq!(
            fence_omission["violations"],
            fence_omission["admittedDomainCounts"]["strictlyBefore"]
        );
        let bypass_counterexample = &omissions[5]["counterexample"];
        let bypass_events = events(bypass_counterexample);
        assert!(bypass_events.contains(&"BYPASS"));
        assert!(bypass_events.contains(&"COMMIT_DURABLE"));
        assert!(!bypass_events.contains(&"ADMIT"));
        assert!(bypass_events.contains(&"RELOAD_M0"));
        assert!(
            bypass_events
                .iter()
                .position(|event| *event == "COMMIT_DURABLE")
                .unwrap()
                < bypass_events
                    .iter()
                    .position(|event| *event == "RELOAD_M0")
                    .unwrap()
        );
        assert_eq!(bypass_counterexample["eventCount"], 5);
        assert_eq!(bypass_counterexample["domain"], "strictly_before");
        assert_eq!(
            bypass_events,
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
    fn full_contract_passes_at_python_required_bound_and_required_bound_plus_four_in_both_modes() {
        let required = required_bound(Premises::default(), Mode::Bracket);
        for extra_steps in [0, 4] {
            let bound = required + extra_steps;
            for mode in [Mode::Bracket, Mode::Strict] {
                let run = run_model(Premises::default(), mode, bound).unwrap();
                assert_eq!(run["status"], "PASS", "{mode:?}, extra_steps={extra_steps}");
                assert_eq!(run["violations"], 0, "{mode:?}, extra_steps={extra_steps}");
                assert_eq!(
                    run["explorationComplete"], true,
                    "{mode:?}, extra_steps={extra_steps}"
                );
                assert_eq!(run["bound"], bound, "{mode:?}, extra_steps={extra_steps}");
                assert_eq!(
                    run["requiredBound"],
                    required_bound(Premises::default(), mode),
                    "{mode:?}, extra_steps={extra_steps}"
                );
                let anchor = if mode == Mode::Bracket {
                    "RELOAD_M0"
                } else {
                    "STRICT_LOAD"
                };
                assert_eq!(run["mode"], mode.as_str());
                assert_eq!(build_chains(Premises::default(), mode).checklist[0], anchor);
                assert_eq!(run["admittedDomainCounts"]["strictlyBefore"], 0);
                assert!(run["bound"].as_u64().unwrap() >= run["requiredBound"].as_u64().unwrap());
            }
        }
    }

    #[test]
    fn required_bound_matches_the_reported_mode_bounds() {
        let report = default_report();
        assert_eq!(
            required_bound(Premises::default(), Mode::Bracket),
            report["fullContract"]["modes"]["bracket"]["requiredBound"]
        );
        assert_eq!(
            required_bound(Premises::default(), Mode::Strict),
            report["fullContract"]["modes"]["strict"]["requiredBound"]
        );
    }

    #[test]
    fn run_model_is_deterministic_for_full_exact_identity_and_host_mediation_modes() {
        for (premises, mode) in [
            (Premises::default(), Mode::Bracket),
            (
                Premises::default().without("exact_identity").unwrap(),
                Mode::Bracket,
            ),
            (
                Premises::default().without("host_mediation").unwrap(),
                Mode::Bracket,
            ),
        ] {
            let first = run_model(premises, mode, 20).unwrap();
            let second = run_model(premises, mode, 20).unwrap();
            assert_eq!(first, second);
            if first["counterexample"].is_object() {
                assert_eq!(
                    first["counterexample"]["trace"],
                    second["counterexample"]["trace"]
                );
            }
        }
    }

    #[test]
    fn report_scope_limits_and_status_vocabulary_are_frozen() {
        let report = default_report();
        let serialized = serde_json::to_string(report).unwrap();
        for expected in [
            "NO admission-side watermark",
            "NO admission-time pending re-derivation",
            "read-time",
            "Full-contract PASS is an abstract bounded property only",
            "does not suppress them",
            "not by any admission-time check",
            "t_f is m0",
            "m0 < p0 < m1 < p1",
            "latched",
            "EVIDENCE_BODY_ADVANCE",
            "torn",
            "decisive",
            "independent single-premise results",
            "ONLY the full contract",
            "BoundError",
            "not a mechanized proof",
            "never counted as violations",
        ] {
            assert!(
                serialized.contains(expected),
                "missing report scope text: {expected}"
            );
        }
        for status in ["PASS", "FAIL", "BLOCKED", "UNKNOWN"] {
            assert!(report["statusVocabulary"][status].is_string(), "{status}");
        }
        assert_eq!(report["statusVocabulary"].as_object().unwrap().len(), 4);
        let blocked = report["statusVocabulary"]["BLOCKED"].as_str().unwrap();
        assert!(blocked.contains("BoundError"));
        assert!(blocked.contains("code 2"));
        let status_scope = report["statusScope"].as_str().unwrap();
        assert!(status_scope.contains("ONLY the full contract"));
        assert!(status_scope.contains("omissions"));
        assert!(status_scope.contains("independent single-premise status"));
        assert_eq!(report["status"], "PASS");
        assert_eq!(report["status"], report["fullContract"]["status"]);
        assert!(report["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["status"] == "FAIL"));

        let limitations = report["scopeLimitations"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        for expected in [
            "does not suppress them",
            "NO admission-side watermark and NO admission-time pending re-derivation",
            "not by any admission-time check",
            "t_f is m0",
            "m0 < p0 < m1 < p1",
            "latched",
            "EVIDENCE_BODY_ADVANCE",
            "torn",
            "decisive",
            "independent single-premise results",
            "ONLY the full contract",
            "BoundError",
            "not a mechanized proof",
            "never counted as violations",
        ] {
            assert!(
                limitations.contains(expected),
                "missing structural assumption: {expected}"
            );
        }

        let meaning = report["fullContract"]["meaning"].as_str().unwrap();
        for expected in [
            "abstract bounded property only",
            "scopeLimitations",
            "NO admission-time re-derivation and NO admission-side watermark",
            "latched unsafe pending delta",
            "not evidence about the production implementation",
            "strictly before t_f",
        ] {
            assert!(
                meaning.contains(expected),
                "missing full-contract qualification: {expected}"
            );
        }

        let premise_descriptions = &report["premiseDescriptions"];
        assert!(premise_descriptions["generation_revoke_fence"]
            .as_str()
            .unwrap()
            .contains("read gate ONLY"));
        assert!(premise_descriptions["pending_probe"]
            .as_str()
            .unwrap()
            .contains("read time"));
        for removed_field in ["admissionWatermarkCounterfactual", "admission_watermark"] {
            assert!(
                !serialized.contains(removed_field),
                "obsolete report field: {removed_field}"
            );
        }
        for key in [
            "model",
            "modelVersion",
            "theorem",
            "bound",
            "exploredStates",
            "exploredTraces",
            "fullContract",
            "omissions",
            "status",
            "statusScope",
            "statusVocabulary",
            "scopeLimitations",
        ] {
            assert!(
                report.get(key).is_some(),
                "missing top-level report field: {key}"
            );
        }
    }

    #[test]
    fn e5_source_documents_abstract_evidence_boundary() {
        let source = include_str!("../../Docs/authorization-validation/tools/e5_model_check.py");
        assert!(source.starts_with("#!/usr/bin/env python3\n\"\"\""));
        let module_doc = source
            .split_once("\"\"\"")
            .and_then(|(_, rest)| rest.split_once("\"\"").map(|(doc, _)| doc))
            .expect("Python checker module docstring");
        let normalized_doc = module_doc.split_whitespace().collect::<Vec<_>>().join(" ");
        for expected in [
            "ABSTRACT BOUNDED-MODEL EVIDENCE ONLY",
            "NOT a mechanized proof",
            "Rust (or Java) implementation",
            "deployment",
            "runtime behavior",
            "v2.1.0",
            "scopeLimitations",
        ] {
            assert!(
                normalized_doc.contains(expected),
                "missing Python module docstring boundary: {expected}"
            );
        }
    }

    #[test]
    fn aggregate_underbound_report_never_claims_pass() {
        let report = build_report(8).unwrap();
        let status = report["fullContract"]["status"].as_str().unwrap();
        assert!(matches!(status, "UNKNOWN" | "FAIL"));
        assert_ne!(status, "PASS");
        assert_eq!(report["status"], status);
    }

    #[test]
    fn no_report_status_field_emits_blocked() {
        fn assert_no_blocked(value: &Value, path: &str) {
            match value {
                Value::Object(fields) => {
                    for (key, nested) in fields {
                        if key == "status" {
                            assert_ne!(nested, "BLOCKED", "blocked status at {path}");
                        }
                        assert_no_blocked(nested, &format!("{path}.{key}"));
                    }
                }
                Value::Array(items) => {
                    for (index, nested) in items.iter().enumerate() {
                        assert_no_blocked(nested, &format!("{path}[{index}]"));
                    }
                }
                _ => {}
            }
        }
        assert_no_blocked(default_report(), "report");
        assert!(validate_bound(0).is_err());
        assert!(validate_bound(MAX_BOUND + 1).is_err());
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

    fn production(source: &str) -> &str {
        source.split("#[cfg(test)]").next().unwrap_or(source)
    }

    #[test]
    fn model_sources_have_no_process_socket_or_network_coupling() {
        let sources = [
            include_str!("e5_model.rs"),
            include_str!("two_mutation_model.rs"),
            include_str!("universal_hypotheses.rs"),
            include_str!("model_acceptance.rs"),
        ];
        for token in [
            "std::process",
            "std::net",
            "TcpStream",
            "UdpSocket",
            "tokio::net",
            "tokio::process",
            "reqwest",
            "hyper::",
            "Command::new",
        ] {
            for source in sources.map(production) {
                assert!(!source.contains(token), "{token}");
            }
        }
    }

    #[test]
    fn model_sources_have_no_mutable_module_initializers() {
        let sources = [
            include_str!("e5_model.rs"),
            include_str!("two_mutation_model.rs"),
            include_str!("universal_hypotheses.rs"),
            include_str!("model_acceptance.rs"),
        ];
        for token in [
            "static mut",
            "lazy_static!",
            "once_cell",
            "#[ctor]",
            "thread_local!",
        ] {
            for source in sources.map(production) {
                assert!(!source.contains(token), "{token}");
            }
        }
    }

    #[test]
    fn model_entrypoints_are_repeatable_without_environment_or_file_reads() {
        let sources = [
            include_str!("e5_model.rs"),
            include_str!("two_mutation_model.rs"),
            include_str!("universal_hypotheses.rs"),
            include_str!("model_acceptance.rs"),
        ];
        for token in ["std::fs", "std::env", "std::process"] {
            for source in sources.map(production) {
                assert!(!source.contains(token), "{token}");
            }
        }
        let first = run_model(Premises::default(), Mode::Strict, 2).unwrap();
        let second = run_model(Premises::default(), Mode::Strict, 2).unwrap();
        assert_eq!(first, second);
    }
}
