use crate::bounded_execution_contract::{self, Configuration, Shard};
#[cfg(test)]
use crate::e5_model::DEFAULT_BOUND;
use crate::e5_model::{Mode, Premises, MAX_BOUND, MIN_BOUND};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const MODEL_NAME: &str = "e5-bounded-model-check-two-mutations";
pub const MODEL_VERSION: &str = "1.0.0";
pub const PREMISES: [&str; 6] = [
    "pending_probe",
    "post_recheck",
    "final_reload",
    "exact_identity",
    "generation_revoke_fence",
    "host_mediation",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Event {
    Init,
    BeginA,
    DurableA,
    PublishA,
    BodyA,
    BeginB,
    DurableB,
    PublishB,
    BodyB,
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

impl Event {
    fn name(self) -> &'static str {
        match self {
            Self::Init => "INIT",
            Self::BeginA => "COMMIT_BEGIN_A",
            Self::DurableA => "COMMIT_DURABLE_A",
            Self::PublishA => "PUBLISH_A",
            Self::BodyA => "BODY_ADVANCE_A",
            Self::BeginB => "COMMIT_BEGIN_B",
            Self::DurableB => "COMMIT_DURABLE_B",
            Self::PublishB => "PUBLISH_B",
            Self::BodyB => "BODY_ADVANCE_B",
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

    fn is_read(self) -> bool {
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

    fn is_probe(self) -> bool {
        matches!(self, Self::ReloadP0 | Self::ReloadP1 | Self::StrictLoad)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Chains {
    pub checklist: Vec<String>,
    pub pre: Vec<String>,
    pub mutation_a: Vec<String>,
    pub mutation_b: Vec<String>,
    pub rollback: Vec<String>,
    pub bypass: Vec<String>,
    pub recheck: Vec<String>,
    checklist_events: Vec<Event>,
    pre_events: Vec<Event>,
    mutation_a_events: Vec<Event>,
    mutation_b_events: Vec<Event>,
    rollback_events: Vec<Event>,
    bypass_events: Vec<Event>,
}

impl Chains {
    fn new(premises: Premises, mode: Mode) -> Self {
        let mut checklist_events = Vec::new();
        if premises.final_reload {
            match mode {
                Mode::Bracket => {
                    checklist_events.push(Event::ReloadM0);
                    if premises.pending_probe {
                        checklist_events.push(Event::ReloadP0);
                    }
                    checklist_events.push(Event::ReloadM1);
                    if premises.pending_probe {
                        checklist_events.push(Event::ReloadP1);
                    }
                }
                Mode::Strict => checklist_events.push(Event::StrictLoad),
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
        let mutation_a_events = vec![
            Event::BeginA,
            Event::DurableA,
            Event::PublishA,
            Event::BodyA,
        ];
        let mutation_b_events = vec![
            Event::BeginB,
            Event::DurableB,
            Event::PublishB,
            Event::BodyB,
        ];
        let rollback_events = vec![Event::Rollback];
        let bypass_events = if premises.host_mediation {
            Vec::new()
        } else {
            vec![Event::Bypass]
        };
        let names = |events: &[Event]| events.iter().map(|event| event.name().to_owned()).collect();
        Self {
            checklist: names(&checklist_events),
            pre: names(&pre_events),
            mutation_a: names(&mutation_a_events),
            mutation_b: names(&mutation_b_events),
            rollback: names(&rollback_events),
            bypass: names(&bypass_events),
            recheck: names(&recheck_events),
            checklist_events,
            pre_events,
            mutation_a_events,
            mutation_b_events,
            rollback_events,
            bypass_events,
        }
    }
}

pub fn build_chains(premises: Premises, mode: Mode) -> Chains {
    Chains::new(premises, mode)
}

pub fn required_bound(premises: Premises, mode: Mode) -> usize {
    let chains = Chains::new(premises, mode);
    1 + chains.checklist_events.len()
        + chains.pre_events.len()
        + chains.mutation_a_events.len()
        + chains.mutation_b_events.len()
        + chains.rollback_events.len()
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
pub struct CacheObservation {
    pub manifest_count: u8,
    pub body_count: u8,
    pub head_count: u8,
    pub consistent: bool,
    pub valid: bool,
    pub candidate_present: bool,
    pub reason: Option<&'static str>,
}

fn effective(fired: Option<usize>, step: usize, rollback: Option<usize>) -> bool {
    fired.is_some_and(|fired| {
        fired <= step && rollback.is_none_or(|rollback| rollback > step || fired > rollback)
    })
}

pub fn cache_observation_two(
    step: usize,
    publish_a: Option<usize>,
    body_a: Option<usize>,
    publish_b: Option<usize>,
    body_b: Option<usize>,
    rollback: Option<usize>,
    fence_on: bool,
) -> CacheObservation {
    let head_count = u8::from(publish_a.is_some_and(|fired| fired <= step))
        + u8::from(publish_b.is_some_and(|fired| fired <= step));
    let manifest_count = u8::from(effective(publish_a, step, rollback))
        + u8::from(effective(publish_b, step, rollback));
    let body_count =
        u8::from(effective(body_a, step, rollback)) + u8::from(effective(body_b, step, rollback));
    let consistent = manifest_count == body_count;
    let candidate_present = !effective(body_a, step, rollback);
    let (valid, reason) = if !fence_on {
        (true, None)
    } else if !consistent {
        (
            false,
            Some(if manifest_count > body_count {
                "manifest_ahead_body_stale"
            } else {
                "body_ahead_manifest_stale"
            }),
        )
    } else if manifest_count < head_count {
        (false, Some("generation_below_published_head"))
    } else {
        (true, None)
    };
    CacheObservation {
        manifest_count,
        body_count,
        head_count,
        consistent,
        valid,
        candidate_present,
        reason,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReadObservation {
    event: Event,
    step: usize,
    cache: CacheObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingObservation {
    step: usize,
    pending: bool,
}

#[derive(Clone, Debug, Default)]
struct Counters {
    explored_states: u64,
    explored_traces: u64,
    incomplete_traces: u64,
    admitted_traces: u64,
    denied_traces: u64,
    bypass_admitted_traces: u64,
    admitted_not_stale: u64,
    admitted_strictly_before: u64,
    admitted_strictly_before_represented: u64,
    admitted_identity_substitution: u64,
    admitted_overlap_unknown: u64,
    admitted_after_final_observation: u64,
    admitted_unknown_domain: u64,
    violations: u64,
    violations_by_candidate_removal: u64,
    violations_by_second_narrowing_only: u64,
    violations_by_both: u64,
    violations_by_candidate_absent: u64,
    publish_after_last_read_before_admission_traces: u64,
    admitted_publish_after_last_read: u64,
    rollback_after_last_read_before_admission_traces: u64,
    publish_after_final_observation_before_admission_traces: u64,
    admitted_publish_after_final_observation: u64,
    stale_commit_publish_after_last_read_traces: u64,
    admitted_stale_commit_publish_after_last_read: u64,
    torn_read_traces: u64,
    admitted_torn_read_traces: u64,
}

#[derive(Clone, Debug)]
struct BestViolation {
    key: (usize, Vec<String>),
    detail: Value,
}

struct RunContext {
    premises: Premises,
    mode: Mode,
    bound: usize,
    chains: Chains,
    trace_prefix: Option<Vec<Event>>,
    counters: Counters,
    denial_reasons: BTreeMap<String, u64>,
    torn_kind_counts: BTreeMap<String, u64>,
    admitted_torn_by_domain: BTreeMap<String, u64>,
    violation_classes: BTreeMap<String, u64>,
    best_violation: Option<BestViolation>,
}

impl RunContext {
    fn new(premises: Premises, mode: Mode, bound: usize, trace_prefix: Option<Vec<Event>>) -> Self {
        Self {
            premises,
            mode,
            bound,
            chains: Chains::new(premises, mode),
            trace_prefix,
            counters: Counters::default(),
            denial_reasons: BTreeMap::new(),
            torn_kind_counts: BTreeMap::from([
                ("manifest_ahead_body_stale".to_owned(), 0),
                ("body_ahead_manifest_stale".to_owned(), 0),
            ]),
            admitted_torn_by_domain: BTreeMap::new(),
            violation_classes: BTreeMap::new(),
            best_violation: None,
        }
    }

    fn boundary_event(&self) -> Option<Event> {
        if self.premises.final_reload {
            return Some(match self.mode {
                Mode::Bracket => Event::ReloadM0,
                Mode::Strict => Event::StrictLoad,
            });
        }
        if self.premises.post_recheck {
            return Some(match self.mode {
                Mode::Bracket => Event::PostBegin,
                Mode::Strict => Event::StrictObs,
            });
        }
        if self.mode == Mode::Bracket {
            return Some(Event::PreBegin);
        }
        None
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

    fn analyze_trace(&self, sequence: &[Event]) -> TraceEvidence {
        let mut positions = BTreeMap::<Event, usize>::new();
        let mut reads = BTreeMap::<Event, ReadObservation>::new();
        let mut probes = BTreeMap::<Event, PendingObservation>::new();
        let mut evidence = None;
        let mut match_ok = None;
        let mut last_read_step = None;
        let boundary = self.boundary_event();
        let mut observation_step = None;

        for (step, event) in sequence.iter().copied().enumerate() {
            if boundary == Some(event) {
                observation_step = Some(step);
            }
            if event.is_read() {
                let observation = CacheObservation {
                    ..cache_observation_two(
                        step,
                        positions.get(&Event::PublishA).copied(),
                        positions.get(&Event::BodyA).copied(),
                        positions.get(&Event::PublishB).copied(),
                        positions.get(&Event::BodyB).copied(),
                        positions.get(&Event::Rollback).copied(),
                        self.premises.generation_revoke_fence,
                    )
                };
                let read = ReadObservation {
                    event,
                    step,
                    cache: observation,
                };
                reads.insert(event, read);
                last_read_step = Some(step);
                if event
                    == match self.mode {
                        Mode::Bracket => Event::ReloadM0,
                        Mode::Strict => Event::StrictLoad,
                    }
                    && self.premises.final_reload
                {
                    evidence = observation.valid.then_some(read);
                }
            }
            if event.is_probe() && self.premises.pending_probe {
                let began_a = positions.contains_key(&Event::BeginA);
                let complete_a = positions.contains_key(&Event::BodyA);
                let began_b = positions.contains_key(&Event::BeginB);
                let complete_b = positions.contains_key(&Event::BodyB);
                probes.insert(
                    event,
                    PendingObservation {
                        step,
                        pending: (began_a && !complete_a) || (began_b && !complete_b),
                    },
                );
                last_read_step = Some(step);
            }
            if event == Event::Match {
                if !self.premises.final_reload {
                    evidence = if self.mode == Mode::Bracket {
                        reads
                            .get(&Event::PreEnd)
                            .copied()
                            .filter(|read| read.cache.valid)
                    } else {
                        None
                    };
                }
                match_ok = Some(evidence.is_some_and(|read| {
                    !self.premises.exact_identity || read.cache.candidate_present
                }));
            }
            positions.insert(event, step);
        }

        let admit_step = positions.get(&Event::Admit).copied();
        let outcome = if positions.contains_key(&Event::Bypass) {
            Outcome::BypassAdmitted
        } else {
            Outcome::Admission(
                self.evaluate_admission(&positions, &reads, &probes, evidence, match_ok),
            )
        };
        TraceEvidence {
            positions,
            reads,
            probes,
            evidence,
            observation_step,
            last_read_step,
            admit_step,
            outcome,
        }
    }

    fn evaluate_admission(
        &self,
        positions: &BTreeMap<Event, usize>,
        reads: &BTreeMap<Event, ReadObservation>,
        probes: &BTreeMap<Event, PendingObservation>,
        evidence: Option<ReadObservation>,
        match_ok: Option<bool>,
    ) -> Result<(), Vec<String>> {
        let mut reasons = Vec::new();
        if match_ok != Some(true) {
            reasons.push("candidate_match_failed".to_owned());
        }
        if self.premises.pending_probe {
            for event in self.configured_probes() {
                match probes.get(event) {
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
            let recheck_event = match self.mode {
                Mode::Bracket => Event::PostEnd,
                Mode::Strict => Event::StrictObs,
            };
            match reads.get(&recheck_event) {
                None => reasons.push("post_recheck_read_missing_or_rejected".to_owned()),
                Some(read) if !read.cache.valid => {
                    reasons.push("post_recheck_read_missing_or_rejected".to_owned())
                }
                Some(read) => {
                    if evidence.is_none_or(|evidence| {
                        (read.cache.manifest_count, read.cache.body_count)
                            != (evidence.cache.manifest_count, evidence.cache.body_count)
                    }) {
                        reasons.push("post_recheck_disagrees_with_evidence".to_owned());
                    }
                }
            }
            if self.mode == Mode::Bracket {
                match reads.get(&Event::PreEnd) {
                    None => reasons.push("pre_observation_missing_or_rejected".to_owned()),
                    Some(read) if !read.cache.valid => {
                        reasons.push("pre_observation_missing_or_rejected".to_owned())
                    }
                    Some(read) => {
                        let first_durable = [Event::DurableA, Event::DurableB]
                            .iter()
                            .filter_map(|event| positions.get(event))
                            .copied()
                            .min();
                        if first_durable.is_some_and(|durable| read.step >= durable) {
                            reasons.push("pre_observation_does_not_precede_commit".to_owned());
                        }
                    }
                }
            }
        }
        if self.premises.final_reload {
            let final_read = match self.mode {
                Mode::Bracket => Event::ReloadM0,
                Mode::Strict => Event::StrictLoad,
            };
            if reads.get(&final_read).is_none_or(|read| !read.cache.valid) {
                reasons.push("final_load_read_missing_or_rejected".to_owned());
            }
            if self.mode == Mode::Bracket
                && reads
                    .get(&Event::ReloadM1)
                    .is_none_or(|read| !read.cache.valid)
            {
                reasons.push("final_load_read_missing_or_rejected:RELOAD_M1".to_owned());
            }
        }
        if self.premises.generation_revoke_fence {
            let rejected = reads
                .values()
                .filter(|read| !read.cache.valid)
                .map(|read| read.event.name())
                .collect::<Vec<_>>();
            if !rejected.is_empty() {
                reasons.push(format!(
                    "generation_fence_rejected_reads:{}",
                    rejected.join(",")
                ));
            }
        }
        if reasons.is_empty() {
            Ok(())
        } else {
            Err(reasons)
        }
    }

    fn record_terminal(&mut self, sequence: &[Event]) {
        self.counters.explored_traces += 1;
        let trace = self.analyze_trace(sequence);
        let torn = trace
            .reads
            .values()
            .filter(|read| !read.cache.consistent)
            .map(|read| {
                if read.cache.manifest_count > read.cache.body_count {
                    "manifest_ahead_body_stale"
                } else {
                    "body_ahead_manifest_stale"
                }
            })
            .collect::<std::collections::BTreeSet<_>>();
        if !torn.is_empty() {
            self.counters.torn_read_traces += 1;
            for kind in &torn {
                *self.torn_kind_counts.entry((*kind).to_owned()).or_default() += 1;
            }
        }
        if let Outcome::Admission(admission) = &trace.outcome {
            self.record_window_metrics(&trace, sequence, admission.is_ok());
        }
        let Outcome::Admission(admission) = &trace.outcome else {
            self.counters.admitted_traces += 1;
            self.counters.bypass_admitted_traces += 1;
            if !torn.is_empty() {
                self.counters.admitted_torn_read_traces += 1;
            }
            self.record_admission(&trace, sequence, true, &torn);
            return;
        };
        if let Err(reasons) = admission {
            self.counters.denied_traces += 1;
            for reason in reasons {
                *self.denial_reasons.entry(reason.clone()).or_default() += 1;
            }
            return;
        }
        self.counters.admitted_traces += 1;
        if !torn.is_empty() {
            self.counters.admitted_torn_read_traces += 1;
        }
        self.record_admission(&trace, sequence, false, &torn);
    }

    fn record_window_metrics(&mut self, trace: &TraceEvidence, sequence: &[Event], admitted: bool) {
        if trace.reads.is_empty() {
            return;
        }
        let positions = &trace.positions;
        let admit_step = trace.admit_step.unwrap_or(sequence.len().saturating_sub(1));
        let last_read = trace.last_read_step.unwrap_or(0);
        let sub_events = [Event::PublishA, Event::BodyA, Event::PublishB, Event::BodyB];
        let publish_in_tail = sub_events.iter().any(|event| {
            positions
                .get(event)
                .is_some_and(|step| last_read < *step && *step < admit_step)
        });
        if publish_in_tail {
            self.counters
                .publish_after_last_read_before_admission_traces += 1;
            if admitted {
                self.counters.admitted_publish_after_last_read += 1;
            }
        }
        let rollback_in_tail = positions
            .get(&Event::Rollback)
            .is_some_and(|step| last_read < *step && *step < admit_step);
        if rollback_in_tail {
            self.counters
                .rollback_after_last_read_before_admission_traces += 1;
        }
        if let Some(observation_step) = trace.observation_step {
            let after_final = sub_events.iter().any(|event| {
                positions
                    .get(event)
                    .is_some_and(|step| observation_step < *step && *step < admit_step)
            });
            if after_final {
                self.counters
                    .publish_after_final_observation_before_admission_traces += 1;
                if admitted {
                    self.counters.admitted_publish_after_final_observation += 1;
                }
            }
            for (durable, publication) in [
                (Event::DurableA, [Event::PublishA, Event::BodyA]),
                (Event::DurableB, [Event::PublishB, Event::BodyB]),
            ] {
                if positions
                    .get(&durable)
                    .is_some_and(|step| *step < observation_step)
                    && publication.iter().any(|event| {
                        positions
                            .get(event)
                            .is_some_and(|step| last_read < *step && *step < admit_step)
                    })
                {
                    self.counters.stale_commit_publish_after_last_read_traces += 1;
                    if admitted {
                        self.counters.admitted_stale_commit_publish_after_last_read += 1;
                    }
                }
            }
        }
    }

    fn record_admission(
        &mut self,
        trace: &TraceEvidence,
        sequence: &[Event],
        bypass: bool,
        torn: &std::collections::BTreeSet<&str>,
    ) {
        let positions = &trace.positions;
        let fired_durables = [Event::DurableA, Event::DurableB]
            .iter()
            .filter_map(|event| positions.get(event))
            .copied()
            .collect::<Vec<_>>();
        let evidence_step = trace.evidence.map(|read| read.step);
        let rollback = positions.get(&Event::Rollback).copied();
        let mut strictly_before = Vec::new();
        let mut unrepresented = Vec::new();
        for (label, durable, publish, body) in [
            ("A", Event::DurableA, Event::PublishA, Event::BodyA),
            ("B", Event::DurableB, Event::PublishB, Event::BodyB),
        ] {
            if positions.get(&durable).is_some_and(|step| {
                trace
                    .observation_step
                    .is_some_and(|boundary| *step < boundary)
            }) {
                strictly_before.push(label);
                let represented = evidence_step.is_some_and(|step| {
                    let published = positions.get(&publish).copied();
                    let body_advanced = positions.get(&body).copied();
                    effective(published, step, rollback) && effective(body_advanced, step, rollback)
                });
                if !represented {
                    unrepresented.push(label);
                }
            }
        }
        let candidate_absent = trace
            .evidence
            .is_some_and(|read| !read.cache.candidate_present);
        let violating = !unrepresented.is_empty() || candidate_absent;
        let domain = if fired_durables.is_empty() {
            self.counters.admitted_not_stale += 1;
            "notStale"
        } else if candidate_absent {
            self.counters.admitted_identity_substitution += 1;
            "identitySubstitution"
        } else if trace.observation_step.is_none() {
            self.counters.admitted_unknown_domain += 1;
            "unknownDomain"
        } else if !unrepresented.is_empty() {
            self.counters.admitted_strictly_before += 1;
            "strictlyBefore"
        } else if !strictly_before.is_empty() {
            self.counters.admitted_strictly_before_represented += 1;
            "strictlyBeforeRepresented"
        } else if [
            (Event::BeginA, Event::DurableA),
            (Event::BeginB, Event::DurableB),
        ]
        .iter()
        .any(|(begin, durable)| {
            trace.observation_step.is_some_and(|boundary| {
                positions.get(begin).is_some_and(|start| *start <= boundary)
                    && positions.get(durable).is_some_and(|end| *end >= boundary)
            })
        }) {
            self.counters.admitted_overlap_unknown += 1;
            "overlapUnknown"
        } else {
            self.counters.admitted_after_final_observation += 1;
            "afterFinalObservation"
        };
        if !torn.is_empty() {
            *self
                .admitted_torn_by_domain
                .entry(domain.to_owned())
                .or_default() += 1;
        }
        if !violating {
            return;
        }
        self.counters.violations += 1;
        if !unrepresented.is_empty() {
            if unrepresented.len() == 2 {
                self.counters.violations_by_both += 1;
            } else if unrepresented == ["B"] {
                self.counters.violations_by_second_narrowing_only += 1;
            } else {
                self.counters.violations_by_candidate_removal += 1;
            }
        } else {
            self.counters.violations_by_candidate_absent += 1;
        }
        let class = schedule_class(trace, sequence, candidate_absent);
        *self.violation_classes.entry(class.to_owned()).or_default() += 1;
        let names = sequence
            .iter()
            .map(|event| event.name().to_owned())
            .collect::<Vec<_>>();
        let key = (sequence.len(), names);
        if self
            .best_violation
            .as_ref()
            .is_none_or(|best| key < best.key)
        {
            let detail = json!({
                "scheduleClass": class,
                "outcome": if bypass { "BYPASS_ADMITTED" } else { "ADMITTED" },
                "domain": domain,
                "violatingMutations": unrepresented,
                "candidateAbsent": candidate_absent,
                "eventCount": sequence.len(),
                "reads": trace.reads.iter().map(|(event, read)| (event.name().to_owned(), json!({
                    "step": read.step,
                    "manifestCount": read.cache.manifest_count,
                    "bodyCount": read.cache.body_count,
                    "candidatePresent": read.cache.candidate_present,
                    "valid": read.cache.valid,
                    "consistent": read.cache.consistent,
                    "reason": read.cache.reason,
                }))).collect::<serde_json::Map<_, _>>(),
                "pendingObservations": trace.probes.iter().map(|(event, observation)| (event.name().to_owned(), json!({
                    "step": observation.step,
                    "pending": observation.pending,
                }))).collect::<serde_json::Map<_, _>>(),
                "trace": sequence.iter().enumerate().map(|(step, event)| json!({"step":step,"event":event.name()})).collect::<Vec<_>>(),
            });
            self.best_violation = Some(BestViolation { key, detail });
        }
    }

    fn dfs(&mut self, indices: [usize; 6], sequence: &mut Vec<Event>) {
        let prefix = self.trace_prefix.as_deref().unwrap_or_default();
        if prefix.is_empty() || sequence.len() > prefix.len() {
            self.counters.explored_states += 1;
        }
        let checklist_next = self.chains.checklist_events.get(indices[0]).copied();
        let mut enabled = Vec::with_capacity(6);
        if let Some(event) = checklist_next {
            if !(event == Event::Match && indices[1] < self.chains.pre_events.len()) {
                enabled.push(event);
            }
        }
        if let Some(event) = self.chains.pre_events.get(indices[1]).copied() {
            enabled.push(event);
        }
        if let Some(event) = self.chains.mutation_a_events.get(indices[2]).copied() {
            enabled.push(event);
        }
        if let Some(event) = self.chains.mutation_b_events.get(indices[3]).copied() {
            enabled.push(event);
        }
        if let Some(event) = self.chains.rollback_events.get(indices[4]).copied() {
            if indices[0] == self.chains.checklist_events.len().saturating_sub(1) {
                enabled.push(event);
            }
        }
        if let Some(event) = self.chains.bypass_events.get(indices[5]).copied() {
            enabled.push(event);
        }
        if sequence.len() >= self.bound {
            self.counters.incomplete_traces += 1;
            self.counters.explored_traces += 1;
            return;
        }
        if sequence.len() <= prefix.len() {
            let expected = prefix[sequence.len() - 1];
            enabled.retain(|event| *event == expected);
        }
        for event in enabled {
            let mut next = indices;
            if self.chains.checklist_events.contains(&event) {
                next[0] += 1;
            } else if self.chains.pre_events.contains(&event) {
                next[1] += 1;
            } else if self.chains.mutation_a_events.contains(&event) {
                next[2] += 1;
            } else if self.chains.mutation_b_events.contains(&event) {
                next[3] += 1;
            } else if self.chains.rollback_events.contains(&event) {
                next[4] += 1;
            } else {
                next[5] += 1;
            }
            sequence.push(event);
            if matches!(event, Event::Admit | Event::Bypass) {
                self.record_terminal(sequence);
            } else {
                self.dfs(next, sequence);
            }
            sequence.pop();
        }
    }

    fn into_report(self) -> Value {
        let exploration_complete = self.counters.incomplete_traces == 0;
        let status = if self.counters.violations > 0 {
            "FAIL"
        } else if exploration_complete {
            "PASS"
        } else {
            "UNKNOWN"
        };
        let counterexample = self.best_violation.map(|item| item.detail);
        json!({
            "premises": {
                "pending_probe":self.premises.pending_probe,
                "post_recheck":self.premises.post_recheck,
                "final_reload":self.premises.final_reload,
                "exact_identity":self.premises.exact_identity,
                "generation_revoke_fence":self.premises.generation_revoke_fence,
                "host_mediation":self.premises.host_mediation
            },
            "mode":self.mode.as_str(),
            "bound":self.bound,
            "requiredBound":required_bound(self.premises,self.mode),
            "explorationComplete":exploration_complete,
            "exploredStates":self.counters.explored_states,
            "exploredTraces":self.counters.explored_traces,
            "incompleteTraces":self.counters.incomplete_traces,
            "admittedTraces":self.counters.admitted_traces,
            "deniedTraces":self.counters.denied_traces,
            "bypassAdmittedTraces":self.counters.bypass_admitted_traces,
            "admittedDomainCounts":{
                "notStale":self.counters.admitted_not_stale,
                "strictlyBefore":self.counters.admitted_strictly_before,
                "strictlyBeforeRepresented":self.counters.admitted_strictly_before_represented,
                "identitySubstitution":self.counters.admitted_identity_substitution,
                "overlapUnknown":self.counters.admitted_overlap_unknown,
                "afterFinalObservation":self.counters.admitted_after_final_observation,
                "unknownDomain":self.counters.admitted_unknown_domain
            },
            "violations":self.counters.violations,
            "violationsByMutation":{
                "candidateRemoval":self.counters.violations_by_candidate_removal,
                "secondNarrowingOnly":self.counters.violations_by_second_narrowing_only,
                "both":self.counters.violations_by_both,
                "candidateAbsent":self.counters.violations_by_candidate_absent
            },
            "violationClasses":self.violation_classes,
            "denialReasons":self.denial_reasons,
            "admissionWindow":{
                "publishAfterLastReadBeforeAdmissionTraces":self.counters.publish_after_last_read_before_admission_traces,
                "admittedPublishAfterLastRead":self.counters.admitted_publish_after_last_read,
                "rollbackAfterLastReadBeforeAdmissionTraces":self.counters.rollback_after_last_read_before_admission_traces,
                "publishAfterFinalObservationBeforeAdmissionTraces":self.counters.publish_after_final_observation_before_admission_traces,
                "admittedPublishAfterFinalObservation":self.counters.admitted_publish_after_final_observation,
                "staleCommitPublishAfterLastReadTraces":self.counters.stale_commit_publish_after_last_read_traces,
                "admittedStaleCommitPublishAfterLastRead":self.counters.admitted_stale_commit_publish_after_last_read
            },
            "mixedManifestBody":{
                "tornReadTraces":self.counters.torn_read_traces,
                "admittedTornReadTraces":self.counters.admitted_torn_read_traces,
                "admittedTornReadTracesByDomain":self.admitted_torn_by_domain,
                "tornReadTracesByKind":self.torn_kind_counts
            },
            "counterexample":counterexample,
            "status":status
        })
    }
}

#[derive(Clone, Debug)]
enum Outcome {
    Admission(Result<(), Vec<String>>),
    BypassAdmitted,
}

struct TraceEvidence {
    positions: BTreeMap<Event, usize>,
    reads: BTreeMap<Event, ReadObservation>,
    probes: BTreeMap<Event, PendingObservation>,
    evidence: Option<ReadObservation>,
    observation_step: Option<usize>,
    last_read_step: Option<usize>,
    admit_step: Option<usize>,
    outcome: Outcome,
}

fn schedule_class(
    trace: &TraceEvidence,
    sequence: &[Event],
    candidate_absent: bool,
) -> &'static str {
    if trace.positions.contains_key(&Event::Bypass) {
        return "bypass_unmediated_admission";
    }
    if trace.reads.values().any(|read| !read.cache.consistent) {
        return "mixed_manifest_body_state";
    }
    if trace.positions.contains_key(&Event::Rollback) {
        return "stale_generation_pointer_rollback";
    }
    let publishes_fired = [Event::PublishA, Event::PublishB]
        .iter()
        .any(|event| trace.positions.contains_key(event));
    let incomplete = [
        (Event::BeginA, Event::PublishA, Event::BodyA),
        (Event::BeginB, Event::PublishB, Event::BodyB),
    ]
    .iter()
    .any(|(begin, publish, body)| {
        trace.positions.contains_key(begin)
            && !(trace.positions.contains_key(publish) && trace.positions.contains_key(body))
    });
    if !publishes_fired || incomplete {
        return "source_pending_commit_without_publication";
    }
    let admit = trace.admit_step.unwrap_or(usize::MAX);
    let last_read = trace.last_read_step.unwrap_or(0);
    if [Event::PublishA, Event::BodyA, Event::PublishB, Event::BodyB]
        .iter()
        .any(|event| {
            trace
                .positions
                .get(event)
                .is_some_and(|step| last_read < *step && *step < admit)
        })
    {
        return "mutation_published_after_last_read_before_admission";
    }
    if let Some(evidence) = trace.evidence {
        if [Event::PublishA, Event::PublishB].iter().any(|event| {
            trace
                .positions
                .get(event)
                .is_some_and(|step| evidence.step < *step && *step <= last_read)
        }) {
            return "mutation_published_between_evidence_read_and_last_read";
        }
    }
    if candidate_absent {
        return "candidate_removal_identity_confusion";
    }
    let _ = sequence;
    "unclassified"
}

fn run_model_unchecked(
    premises: Premises,
    mode: Mode,
    bound: usize,
    trace_prefix: Option<Vec<Event>>,
) -> Value {
    let mut context = RunContext::new(premises, mode, bound, trace_prefix);
    let mut sequence = vec![Event::Init];
    context.dfs([0; 6], &mut sequence);
    context.into_report()
}

pub fn run_model(premises: Premises, mode: Mode, bound: usize) -> Result<Value, String> {
    validate_bound(bound)?;
    Ok(run_model_unchecked(premises, mode, bound, None))
}

fn event_from_name(name: &str) -> Option<Event> {
    Some(match name {
        "INIT" => Event::Init,
        "COMMIT_BEGIN_A" => Event::BeginA,
        "COMMIT_DURABLE_A" => Event::DurableA,
        "PUBLISH_A" => Event::PublishA,
        "BODY_ADVANCE_A" => Event::BodyA,
        "COMMIT_BEGIN_B" => Event::BeginB,
        "COMMIT_DURABLE_B" => Event::DurableB,
        "PUBLISH_B" => Event::PublishB,
        "BODY_ADVANCE_B" => Event::BodyB,
        "ROLLBACK" => Event::Rollback,
        "PRE_OBS_BEGIN" => Event::PreBegin,
        "PRE_OBS_END" => Event::PreEnd,
        "RELOAD_M0" => Event::ReloadM0,
        "RELOAD_P0" => Event::ReloadP0,
        "RELOAD_M1" => Event::ReloadM1,
        "RELOAD_P1" => Event::ReloadP1,
        "STRICT_LOAD" => Event::StrictLoad,
        "MATCH" => Event::Match,
        "POST_OBS_BEGIN" => Event::PostBegin,
        "POST_OBS_END" => Event::PostEnd,
        "STRICT_OBS" => Event::StrictObs,
        "ADMIT" => Event::Admit,
        "BYPASS" => Event::Bypass,
        _ => return None,
    })
}

fn model_configuration(premises: Premises, mode: Mode, bound: usize) -> Configuration {
    Configuration {
        premises: BTreeMap::from([
            ("pending_probe".to_owned(), premises.pending_probe),
            ("post_recheck".to_owned(), premises.post_recheck),
            ("final_reload".to_owned(), premises.final_reload),
            ("exact_identity".to_owned(), premises.exact_identity),
            (
                "generation_revoke_fence".to_owned(),
                premises.generation_revoke_fence,
            ),
            ("host_mediation".to_owned(), premises.host_mediation),
        ]),
        mode: mode.as_str().to_owned(),
        bound: bound as u64,
        required_bound: required_bound(premises, mode) as u64,
    }
}

pub fn shard_prefixes(
    premises: Premises,
    mode: Mode,
    bound: usize,
) -> Result<Vec<Vec<String>>, String> {
    validate_bound(bound)?;
    let chains = Chains::new(premises, mode);
    let names = [
        chains.checklist,
        chains.pre,
        chains.mutation_a,
        chains.mutation_b,
        chains.rollback,
        chains.bypass,
    ];
    let lengths: [usize; 6] = std::array::from_fn(|index| names[index].len());
    let depth = 2.min(bound - 1);
    let mut prefixes = Vec::new();
    fn visit(
        chains: &[Vec<String>; 6],
        lengths: &[usize; 6],
        checklist_len: usize,
        depth: usize,
        indices: [usize; 6],
        prefix: &mut Vec<String>,
        output: &mut Vec<Vec<String>>,
    ) {
        if prefix.len() == depth
            || prefix
                .last()
                .is_some_and(|event| event == "ADMIT" || event == "BYPASS")
        {
            output.push(prefix.clone());
            return;
        }
        for slot in 0..chains.len() {
            let index = indices[slot];
            if index >= lengths[slot] {
                continue;
            }
            let event = &chains[slot][index];
            if slot == 0 && event == "MATCH" && indices[1] < lengths[1] {
                continue;
            }
            if slot == 4 && indices[0] != checklist_len - 1 {
                continue;
            }
            let mut next = indices;
            next[slot] += 1;
            prefix.push(event.clone());
            visit(chains, lengths, checklist_len, depth, next, prefix, output);
            prefix.pop();
        }
    }
    let checklist_len = lengths[0];
    visit(
        &names,
        &lengths,
        checklist_len,
        depth,
        [0; 6],
        &mut Vec::new(),
        &mut prefixes,
    );
    Ok(prefixes)
}

pub fn run_model_shard(
    premises: Premises,
    mode: Mode,
    bound: usize,
    prefix: &[String],
) -> Result<Shard, String> {
    validate_bound(bound)?;
    let expected = shard_prefixes(premises, mode, bound)?;
    if !expected.iter().any(|candidate| candidate == prefix) {
        return Err("model shard prefix is not in the deterministic prefix set".into());
    }
    let events = prefix
        .iter()
        .map(|name| event_from_name(name).ok_or_else(|| format!("unknown shard event {name}")))
        .collect::<Result<Vec<_>, _>>()?;
    let report = run_model_unchecked(premises, mode, bound, Some(events));
    let counters = report
        .as_object()
        .expect("model report is an object")
        .iter()
        .filter(|(key, _)| {
            matches!(
                key.as_str(),
                "exploredStates"
                    | "exploredTraces"
                    | "incompleteTraces"
                    | "admittedTraces"
                    | "deniedTraces"
                    | "bypassAdmittedTraces"
                    | "admittedDomainCounts"
                    | "violations"
                    | "violationsByMutation"
                    | "violationClasses"
                    | "denialReasons"
                    | "admissionWindow"
                    | "mixedManifestBody"
            )
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<serde_json::Map<_, _>>();
    Ok(Shard {
        prefix: prefix.to_vec(),
        configuration: model_configuration(premises, mode, bound),
        explored_states: report["exploredStates"].as_u64().unwrap(),
        counters: Value::Object(counters),
        exploration_complete: report["explorationComplete"].as_bool().unwrap(),
        counterexample: (!report["counterexample"].is_null())
            .then(|| report["counterexample"].clone()),
    })
}

pub fn run_sharded_model(premises: Premises, mode: Mode, bound: usize) -> Result<Value, String> {
    validate_bound(bound)?;
    let configuration = model_configuration(premises, mode, bound);
    let prefixes = shard_prefixes(premises, mode, bound)?;
    let shards = prefixes
        .iter()
        .map(|prefix| run_model_shard(premises, mode, bound, prefix))
        .collect::<Result<Vec<_>, _>>()?;
    let merged = bounded_execution_contract::merge_shards(&configuration, &prefixes, &shards)
        .map_err(|error| format!("failed to merge model shards: {error:?}"))?;
    let mut report = json!({
        "premises": {
            "pending_probe": premises.pending_probe,
            "post_recheck": premises.post_recheck,
            "final_reload": premises.final_reload,
            "exact_identity": premises.exact_identity,
            "generation_revoke_fence": premises.generation_revoke_fence,
            "host_mediation": premises.host_mediation,
        },
        "mode": mode.as_str(),
        "bound": bound,
        "requiredBound": required_bound(premises, mode),
    });
    let report_object = report.as_object_mut().expect("report object");
    for (key, value) in merged.counters.as_object().expect("merged counters object") {
        report_object.insert(key.clone(), value.clone());
    }
    report_object.insert("exploredStates".to_owned(), json!(merged.explored_states));
    report_object.insert(
        "explorationComplete".to_owned(),
        json!(merged.exploration_complete),
    );
    report_object.insert(
        "counterexample".to_owned(),
        merged.counterexample.unwrap_or(Value::Null),
    );
    report_object.insert("status".to_owned(), json!(merged.status));
    Ok(report)
}

pub fn without_premise(premises: Premises, name: &str) -> Result<Premises, String> {
    premises.without(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> Premises {
        Premises::default()
    }

    #[test]
    fn strict_full_contract_is_complete_repeatable_and_conserves_trace_counts() {
        let first = run_model(full(), Mode::Strict, DEFAULT_BOUND).unwrap();
        let repeated = run_model(full(), Mode::Strict, DEFAULT_BOUND).unwrap();
        assert_eq!(first, repeated);
        assert_eq!(first["status"], "PASS");
        assert_eq!(first["explorationComplete"], true);
        assert_eq!(first["violations"], 0);
        assert_eq!(first["admittedDomainCounts"]["strictlyBefore"], 0);
        assert_eq!(
            first["admittedTraces"].as_u64().unwrap() + first["deniedTraces"].as_u64().unwrap(),
            first["exploredTraces"].as_u64().unwrap()
        );
        let domain_sum = first["admittedDomainCounts"]
            .as_object()
            .unwrap()
            .values()
            .map(|value| value.as_u64().unwrap())
            .sum::<u64>();
        assert_eq!(domain_sum, first["admittedTraces"].as_u64().unwrap());
    }

    #[test]
    fn strict_model_exposes_torn_and_stale_windows_without_admitting_them() {
        let report = run_model(full(), Mode::Strict, DEFAULT_BOUND).unwrap();
        assert!(
            report["mixedManifestBody"]["tornReadTraces"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(report["mixedManifestBody"]["admittedTornReadTraces"], 0);
        assert_eq!(
            report["mixedManifestBody"]["admittedTornReadTracesByDomain"],
            json!({})
        );
        let window = &report["admissionWindow"];
        assert!(
            window["staleCommitPublishAfterLastReadTraces"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(window["admittedStaleCommitPublishAfterLastRead"], 0);
        assert!(report["denialReasons"]
            .as_object()
            .unwrap()
            .keys()
            .any(|reason| reason.starts_with("pending_probe_latched_unsafe_delta")));
    }

    #[test]
    fn strict_omission_outcomes_and_counterexample_families_are_pinned() {
        let expected = [
            (
                "pending_probe",
                "FAIL",
                Some("source_pending_commit_without_publication"),
            ),
            ("post_recheck", "PASS", None),
            ("final_reload", "PASS", None),
            (
                "exact_identity",
                "FAIL",
                Some("candidate_removal_identity_confusion"),
            ),
            ("generation_revoke_fence", "PASS", None),
            (
                "host_mediation",
                "FAIL",
                Some("bypass_unmediated_admission"),
            ),
        ];
        for (premise, status, schedule_class) in expected {
            let omitted = full().without(premise).unwrap();
            let report = run_model(omitted, Mode::Strict, DEFAULT_BOUND).unwrap();
            assert_eq!(report["status"], status, "{premise}");
            if let Some(schedule_class) = schedule_class {
                assert_eq!(
                    report["counterexample"]["scheduleClass"], schedule_class,
                    "{premise}"
                );
            } else {
                assert_eq!(report["counterexample"], Value::Null, "{premise}");
                assert_eq!(report["explorationComplete"], true, "{premise}");
            }
        }
    }

    #[test]
    fn bracket_pending_probe_omission_has_a_bounded_hazard() {
        const COUNTEREXAMPLE_BOUND: usize = 11;
        let pending = full().without("pending_probe").unwrap();
        let report = run_model(pending, Mode::Bracket, COUNTEREXAMPLE_BOUND).unwrap();
        assert_eq!(report["status"], "FAIL");
        assert_eq!(report["explorationComplete"], false);
        assert_eq!(
            report["counterexample"]["scheduleClass"],
            "source_pending_commit_without_publication"
        );
        assert!(
            report["counterexample"]["eventCount"].as_u64().unwrap() <= COUNTEREXAMPLE_BOUND as u64
        );
    }

    #[test]
    fn bracket_post_recheck_omission_has_a_bounded_hazard() {
        const COUNTEREXAMPLE_BOUND: usize = 13;
        let no_recheck = full().without("post_recheck").unwrap();
        let report = run_model(no_recheck, Mode::Bracket, COUNTEREXAMPLE_BOUND).unwrap();
        assert_eq!(report["status"], "FAIL");
        assert_eq!(report["explorationComplete"], false);
        assert_eq!(
            report["counterexample"]["scheduleClass"],
            "mutation_published_between_evidence_read_and_last_read"
        );
        assert!(
            report["counterexample"]["eventCount"].as_u64().unwrap() <= COUNTEREXAMPLE_BOUND as u64
        );
    }

    #[test]
    fn complete_bound_and_underbound_status_are_distinguished() {
        let premises = full();
        let required = required_bound(premises, Mode::Strict);
        assert_eq!(required, 14);
        let complete = run_model(premises, Mode::Strict, required).unwrap();
        assert_eq!(complete["status"], "PASS");
        assert_eq!(complete["explorationComplete"], true);
        let under = run_model(premises, Mode::Strict, required - 1).unwrap();
        assert_ne!(under["status"], "PASS");
        assert_eq!(under["explorationComplete"], false);
    }

    #[test]
    fn deterministic_model_shards_reproduce_complete_and_incomplete_python_reports() {
        for mode in [Mode::Strict, Mode::Bracket] {
            let bound = if mode == Mode::Strict {
                DEFAULT_BOUND
            } else {
                8
            };
            for premise in std::iter::once(None).chain(PREMISES.map(Some)) {
                let premises = match premise {
                    Some(premise) => full().without(premise).unwrap(),
                    None => full(),
                };
                let serial = run_model(premises, mode, bound).unwrap();
                let sharded = run_sharded_model(premises, mode, bound).unwrap();
                assert_eq!(sharded, serial, "{}/{premise:?}/{bound}", mode.as_str());
                if mode == Mode::Strict {
                    assert_eq!(sharded["explorationComplete"], true, "{premise:?}");
                } else {
                    assert_eq!(sharded["explorationComplete"], false, "{premise:?}");
                }
                if sharded["status"] == "FAIL" {
                    assert!(sharded["counterexample"].is_object(), "{premise:?}");
                }
            }
        }
    }

    #[test]
    fn deterministic_model_shards_preserve_underbound_reports() {
        let premises = full().without("host_mediation").unwrap();
        for bound in [2, 3, 6] {
            let serial = run_model(premises, Mode::Strict, bound).unwrap();
            let sharded = run_sharded_model(premises, Mode::Strict, bound).unwrap();
            assert_eq!(sharded, serial, "bound={bound}");
            if bound < required_bound(premises, Mode::Strict) {
                assert_ne!(sharded["status"], "PASS", "bound={bound}");
            }
            if !sharded["counterexample"].is_null() {
                assert_eq!(sharded["status"], "FAIL", "bound={bound}");
            }
        }
    }

    #[test]
    fn model_shard_prefix_set_and_merge_reject_unknown_or_reordered_shards() {
        let premises = full();
        let mode = Mode::Strict;
        let bound = 4;
        let prefixes = shard_prefixes(premises, mode, bound).unwrap();
        assert!(!prefixes.is_empty());
        assert!(run_model_shard(premises, mode, bound, &["NOPE".into()]).is_err());

        let configuration = model_configuration(premises, mode, bound);
        let mut shards = prefixes
            .iter()
            .map(|prefix| run_model_shard(premises, mode, bound, prefix).unwrap())
            .collect::<Vec<_>>();
        shards.reverse();
        assert_eq!(
            bounded_execution_contract::merge_shards(&configuration, &prefixes, &shards),
            Err(bounded_execution_contract::ContractError::ShardSetMismatch)
        );
    }

    #[test]
    fn two_mutation_violation_attribution_is_reported_by_family() {
        let omitted = full().without("pending_probe").unwrap();
        let report = run_model(omitted, Mode::Strict, DEFAULT_BOUND).unwrap();
        let example = &report["counterexample"];
        let mutations = example["violatingMutations"].as_array().unwrap();
        let labels = mutations
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()
            .unwrap();
        assert!(labels == ["A"] || labels == ["B"] || labels == ["A", "B"]);
        let attribution = &report["violationsByMutation"];
        let total = attribution
            .as_object()
            .unwrap()
            .values()
            .map(|value| value.as_u64().unwrap())
            .sum::<u64>();
        assert_eq!(total, report["violations"].as_u64().unwrap());
    }

    #[test]
    fn mutation_event_chains_are_unique_in_both_observation_modes() {
        let mut all_premises_disabled = full();
        for premise in PREMISES {
            all_premises_disabled = all_premises_disabled.without(premise).unwrap();
        }
        for premises in [full(), all_premises_disabled] {
            for mode in [Mode::Bracket, Mode::Strict] {
                let chains = build_chains(premises, mode);
                for chain in [
                    &chains.checklist,
                    &chains.pre,
                    &chains.mutation_a,
                    &chains.mutation_b,
                    &chains.rollback,
                    &chains.bypass,
                    &chains.recheck,
                ] {
                    let unique = chain.iter().collect::<std::collections::BTreeSet<_>>();
                    assert_eq!(unique.len(), chain.len(), "{}", mode.as_str());
                }
            }
        }
    }

    #[test]
    fn count_based_cache_observation_distinguishes_torn_candidate_and_rollback_states() {
        let cross_mutation_pair =
            cache_observation_two(4, None, Some(3), Some(2), None, None, true);
        assert_eq!(cross_mutation_pair.manifest_count, 1);
        assert_eq!(cross_mutation_pair.body_count, 1);
        assert!(cross_mutation_pair.consistent);
        assert!(!cross_mutation_pair.candidate_present);

        let manifest_ahead = cache_observation_two(4, Some(2), None, None, None, None, true);
        assert_eq!(manifest_ahead.reason, Some("manifest_ahead_body_stale"));
        assert!(!manifest_ahead.consistent);
        assert!(!manifest_ahead.valid);

        let body_ahead = cache_observation_two(4, None, None, None, Some(3), None, true);
        assert_eq!(body_ahead.reason, Some("body_ahead_manifest_stale"));
        assert!(!body_ahead.consistent);
        assert!(!body_ahead.valid);
        assert!(body_ahead.candidate_present);

        let before_rollback = cache_observation_two(4, Some(2), Some(3), None, None, Some(5), true);
        assert_eq!(before_rollback.manifest_count, 1);
        assert_eq!(before_rollback.body_count, 1);
        assert_eq!(before_rollback.head_count, 1);
        assert!(before_rollback.valid);
        assert!(!before_rollback.candidate_present);

        let after_rollback = cache_observation_two(6, Some(2), Some(3), None, None, Some(5), true);
        assert_eq!(after_rollback.manifest_count, 0);
        assert_eq!(after_rollback.body_count, 0);
        assert_eq!(after_rollback.head_count, 1);
        assert_eq!(
            after_rollback.reason,
            Some("generation_below_published_head")
        );
        assert!(!after_rollback.valid);
        assert!(after_rollback.candidate_present);
    }
}
