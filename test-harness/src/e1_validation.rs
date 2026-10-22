use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateIdentity {
    pub tenant_id: String,
    pub card_id: String,
    pub grant_id: String,
    pub grant_revision: String,
    pub grant_hash: String,
}

impl CandidateIdentity {
    fn is_complete(&self) -> bool {
        !self.tenant_id.is_empty()
            && !self.card_id.is_empty()
            && !self.grant_id.is_empty()
            && !self.grant_revision.is_empty()
            && !self.grant_hash.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    SignedContextBound,
    CandidateMatch,
    FinalReloadStart,
    AuthoritativeReadStart,
    AuthoritativeReadEnd,
    EvidenceLoadResult,
    StableCheckEnd,
    DecisionReturn,
    HostAdmission,
    SourceCommitStart,
    SourceCommitEnd,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub kind: EventKind,
    pub sequence: u64,
    pub node: String,
    pub process_epoch: String,
    pub observation: Option<String>,
    pub outcome: Option<String>,
    pub source: Option<String>,
    pub allowed: Option<bool>,
    pub stable: Option<bool>,
    pub pending: Option<bool>,
    pub identity: Option<CandidateIdentity>,
}

impl Event {
    pub fn new(kind: EventKind, sequence: u64) -> Self {
        Self {
            kind,
            sequence,
            node: "node-a".into(),
            process_epoch: "proc-a".into(),
            observation: None,
            outcome: None,
            source: None,
            allowed: None,
            stable: None,
            pending: None,
            identity: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceInterval {
    pub start: u64,
    pub end: u64,
}

impl SequenceInterval {
    fn new(start: u64, end: u64) -> Result<Self, String> {
        if start == 0 || end < start {
            return Err(format!("invalid event interval [{start}, {end}]"));
        }
        Ok(Self { start, end })
    }

    fn before(self, other: Self) -> bool {
        self.end < other.start
    }

    fn overlaps(self, other: Self) -> bool {
        !(self.before(other) || other.before(self))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Category {
    PreCommit,
    PostCommitBeforeFinalObservation,
    PostFinalObservationOverlap,
    IntervalOverlapUnknown,
    InFlight,
    UnclassifiedUnknown,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreCommit => "pre-commit",
            Self::PostCommitBeforeFinalObservation => "post-commit-before-final-observation",
            Self::PostFinalObservationOverlap => "post-final-observation-overlap",
            Self::IntervalOverlapUnknown => "interval-overlap-unknown",
            Self::InFlight => "in-flight",
            Self::UnclassifiedUnknown => "unclassified-unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Classification {
    pub category: Category,
    pub theorem_domain: bool,
    pub stale_allow_violation: bool,
    pub evidence_source: String,
    pub commit_interval: SequenceInterval,
    pub final_observation_interval: SequenceInterval,
    pub stable_check_sequence: u64,
    pub host_admission_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelDomain {
    NotStale,
    UnknownDomain,
    StrictlyBefore,
    OverlapUnknown,
    AfterFinalObservation,
}

pub fn classify_domain(
    commit: Option<SequenceInterval>,
    final_observation: Option<SequenceInterval>,
) -> ModelDomain {
    let Some(commit) = commit else {
        return ModelDomain::NotStale;
    };
    let Some(final_observation) = final_observation else {
        return ModelDomain::UnknownDomain;
    };
    if commit.end < final_observation.start {
        ModelDomain::StrictlyBefore
    } else if final_observation.start <= commit.end && commit.start <= final_observation.end {
        ModelDomain::OverlapUnknown
    } else {
        ModelDomain::AfterFinalObservation
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MultiClassification {
    pub per_mutation: Vec<Classification>,
    pub hazard_candidates: Vec<usize>,
    pub violating_mutations: Vec<usize>,
    pub attribution_mode: &'static str,
    pub stale_allow_violation: bool,
    pub theorem_domain: bool,
    pub combined_domain: &'static str,
}

fn one_event(events: &[Event], kind: EventKind) -> Result<&Event, String> {
    let matches = events
        .iter()
        .filter(|event| event.kind == kind)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(format!(
            "expected exactly one {kind:?}, got {}",
            matches.len()
        ));
    }
    Ok(matches[0])
}

fn require_same_process(event_groups: &[&[Event]]) -> Result<(), String> {
    let events = event_groups
        .iter()
        .flat_map(|group| group.iter())
        .collect::<Vec<_>>();
    let nodes = events
        .iter()
        .map(|event| event.node.as_str())
        .collect::<BTreeSet<_>>();
    let epochs = events
        .iter()
        .map(|event| event.process_epoch.as_str())
        .collect::<BTreeSet<_>>();
    if nodes.len() != 1 || nodes.contains("") {
        return Err("E1 sequence classification requires one same-node process log".into());
    }
    if epochs.len() != 1 || epochs.contains("") {
        return Err("E1 sequence classification requires one same-node process epoch".into());
    }
    let sequences = events
        .iter()
        .map(|event| event.sequence)
        .collect::<Vec<_>>();
    if sequences.contains(&0)
        || sequences.iter().copied().collect::<BTreeSet<_>>().len() != sequences.len()
    {
        return Err("E1 process log has invalid or duplicate event_sequence values".into());
    }
    Ok(())
}

fn read_pairs<'a>(
    events: &'a [Event],
    observation: &str,
    after: u64,
    before: u64,
) -> Result<Vec<(&'a Event, &'a Event)>, String> {
    let selected = events
        .iter()
        .filter(|event| {
            matches!(
                event.kind,
                EventKind::AuthoritativeReadStart | EventKind::AuthoritativeReadEnd
            ) && event.observation.as_deref() == Some(observation)
                && event.sequence > after
                && event.sequence < before
        })
        .collect::<Vec<_>>();
    if selected.len() % 2 != 0 {
        return Err(format!("unpaired {observation} observations"));
    }
    let mut starts = BTreeMap::new();
    let mut ends = BTreeMap::new();
    for event in selected {
        let bucket = match event.kind {
            EventKind::AuthoritativeReadStart => &mut starts,
            EventKind::AuthoritativeReadEnd => &mut ends,
            _ => unreachable!(),
        };
        if bucket.insert(event.sequence, event).is_some() {
            return Err(format!("duplicate {observation} sequence"));
        }
    }
    if starts.len() != ends.len() {
        return Err(format!("unpaired {observation} observations"));
    }
    let mut pairs = Vec::with_capacity(starts.len());
    for ((start_sequence, start), (end_sequence, end)) in starts.into_iter().zip(ends) {
        if start_sequence >= end_sequence {
            return Err(format!("invalid {observation} observation ordering"));
        }
        if start.outcome.as_deref() != Some("started") || end.outcome.as_deref() != Some("ok") {
            return Err(format!("invalid or unsuccessful {observation} observation"));
        }
        pairs.push((start, end));
    }
    Ok(pairs)
}

fn final_observation_interval(events: &[Event]) -> Result<(SequenceInterval, String), String> {
    let final_start = one_event(events, EventKind::FinalReloadStart)?;
    let stable = one_event(events, EventKind::StableCheckEnd)?;
    if final_start.sequence >= stable.sequence {
        return Err("final reload must precede stable-check completion".into());
    }
    let evidence = events
        .iter()
        .filter(|event| {
            event.kind == EventKind::EvidenceLoadResult
                && event.sequence > final_start.sequence
                && event.sequence < stable.sequence
        })
        .collect::<Vec<_>>();
    if evidence.len() != 1 {
        return Err(format!(
            "expected one final evidence_load_result, got {}",
            evidence.len()
        ));
    }
    let source = evidence[0]
        .source
        .as_deref()
        .ok_or_else(|| "missing final evidence source".to_owned())?;
    match source {
        "strict_db" => {
            let pairs = read_pairs(
                events,
                "strict_pending_probe",
                final_start.sequence,
                evidence[0].sequence,
            )?;
            if pairs.len() != 1 {
                return Err(format!(
                    "expected one strict_pending_probe pair, got {}",
                    pairs.len()
                ));
            }
            let (start, end) = pairs[0];
            if end.outcome.as_deref() != Some("ok") || end.pending != Some(false) {
                return Err("strict final load observed an unsafe pending delta".into());
            }
            Ok((
                SequenceInterval::new(start.sequence, end.sequence)?,
                source.into(),
            ))
        }
        "l1_cache" | "l2_cache" => {
            let manifests = read_pairs(
                events,
                "cache_manifest",
                final_start.sequence,
                evidence[0].sequence,
            )?;
            let pending = read_pairs(
                events,
                "cache_pending_probe",
                final_start.sequence,
                evidence[0].sequence,
            )?;
            if manifests.len() != 2 || pending.len() != 2 {
                return Err(
                    "cache final load requires two manifest and two pending observations".into(),
                );
            }
            let ordered = manifests[0].1.sequence < pending[0].0.sequence
                && pending[0].1.sequence < manifests[1].0.sequence
                && manifests[1].1.sequence < pending[1].0.sequence
                && pending[1].1.sequence < evidence[0].sequence;
            if !ordered {
                return Err("cache admission bracket is not m0 < p0 < m1 < p1".into());
            }
            if pending
                .iter()
                .any(|(_, end)| end.outcome.as_deref() != Some("ok") || end.pending != Some(false))
            {
                return Err("cache admission bracket observed an unsafe pending delta".into());
            }
            Ok((
                SequenceInterval::new(manifests[0].0.sequence, manifests[0].1.sequence)?,
                source.into(),
            ))
        }
        _ => Err(format!("unknown evidence source {source:?}")),
    }
}

fn mutation_commit_interval(events: &[Event]) -> Result<SequenceInterval, String> {
    let start = one_event(events, EventKind::SourceCommitStart)?;
    let end = one_event(events, EventKind::SourceCommitEnd)?;
    if end.outcome.as_deref() != Some("committed") {
        return Err("source commit outcome is not durably proven".into());
    }
    if start.node != end.node
        || start.process_epoch.is_empty()
        || start.process_epoch != end.process_epoch
    {
        return Err("source commit interval spans process logs or epochs".into());
    }
    SequenceInterval::new(start.sequence, end.sequence)
}

pub fn classify_e1_allow(
    request_events: &[Event],
    mutation_events: &[Event],
) -> Result<Classification, String> {
    require_same_process(&[request_events, mutation_events])?;
    let signed = one_event(request_events, EventKind::SignedContextBound)?;
    let candidate = one_event(request_events, EventKind::CandidateMatch)?;
    let final_start = one_event(request_events, EventKind::FinalReloadStart)?;
    let stable = one_event(request_events, EventKind::StableCheckEnd)?;
    let decision = one_event(request_events, EventKind::DecisionReturn)?;
    let admission = one_event(request_events, EventKind::HostAdmission)?;
    if decision.allowed != Some(true) {
        return Err("host_admission exists without an ALLOW decision".into());
    }
    if stable.stable != Some(true) {
        return Err("host_admission exists without a stable final identity check".into());
    }
    let identity = candidate
        .identity
        .as_ref()
        .filter(|identity| identity.is_complete())
        .ok_or_else(|| "candidate_match lacks exact candidate identity".to_owned())?;
    if final_start.identity.as_ref() != Some(identity) || stable.identity.as_ref() != Some(identity)
    {
        return Err("candidate identity changed across the final reload".into());
    }
    if !(signed.sequence < candidate.sequence
        && candidate.sequence < final_start.sequence
        && final_start.sequence < stable.sequence
        && stable.sequence < decision.sequence
        && decision.sequence < admission.sequence)
    {
        return Err("request event ordering is incomplete or invalid".into());
    }
    let (final_interval, source) = final_observation_interval(request_events)?;
    if !(final_start.sequence < final_interval.start && final_interval.end < stable.sequence) {
        return Err("final authoritative observation is outside the final reload".into());
    }
    let commit = mutation_commit_interval(mutation_events)?;
    let all_sequences = request_events
        .iter()
        .chain(mutation_events.iter())
        .map(|event| event.sequence)
        .collect::<BTreeSet<_>>();
    let (category, theorem_domain, violation) = if admission.sequence < commit.start {
        (Category::PreCommit, false, false)
    } else if commit.end < final_interval.start {
        (Category::PostCommitBeforeFinalObservation, true, true)
    } else if final_interval.end < commit.start && commit.start < admission.sequence {
        (Category::PostFinalObservationOverlap, false, false)
    } else if commit.overlaps(final_interval) {
        (Category::IntervalOverlapUnknown, false, false)
    } else if signed.sequence < commit.start
        && commit.end < admission.sequence
        && all_sequences.contains(&commit.start)
        && all_sequences.contains(&commit.end)
    {
        (Category::InFlight, false, false)
    } else {
        (Category::UnclassifiedUnknown, false, false)
    };
    Ok(Classification {
        category,
        theorem_domain,
        stale_allow_violation: violation,
        evidence_source: source,
        commit_interval: commit,
        final_observation_interval: final_interval,
        stable_check_sequence: stable.sequence,
        host_admission_sequence: admission.sequence,
    })
}

pub fn classify_e1_allow_multi(
    request_events: &[Event],
    mutations: &[Vec<Event>],
    represented: Option<&BTreeMap<usize, bool>>,
) -> Result<MultiClassification, String> {
    if mutations.is_empty() {
        return Err("classify_e1_allow_multi requires at least one mutation".into());
    }
    let mut groups = vec![request_events];
    groups.extend(mutations.iter().map(Vec::as_slice));
    require_same_process(&groups)?;
    let per_mutation = mutations
        .iter()
        .map(|mutation| classify_e1_allow(request_events, mutation))
        .collect::<Result<Vec<_>, _>>()?;
    let hazard_candidates = per_mutation
        .iter()
        .enumerate()
        .filter_map(|(index, item)| item.theorem_domain.then_some(index))
        .collect::<Vec<_>>();
    let (violating_mutations, attribution_mode) = if let Some(represented) = represented {
        let missing = hazard_candidates
            .iter()
            .filter(|index| !represented.contains_key(index))
            .copied()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(format!(
                "representation missing for pre-t_f mutation indices: {missing:?}"
            ));
        }
        (
            hazard_candidates
                .iter()
                .copied()
                .filter(|index| !represented[index])
                .collect::<Vec<_>>(),
            "representation-adjudicated",
        )
    } else {
        (hazard_candidates.clone(), "conservative")
    };
    let stale_allow_violation = !violating_mutations.is_empty();
    let combined_domain = if stale_allow_violation {
        "strictlyBefore"
    } else if !hazard_candidates.is_empty() {
        "strictlyBeforeRepresented"
    } else {
        "outsideTheoremDomain"
    };
    Ok(MultiClassification {
        per_mutation,
        hazard_candidates,
        violating_mutations,
        attribution_mode,
        stale_allow_violation,
        theorem_domain: stale_allow_violation,
        combined_domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDENTITY: CandidateIdentity = CandidateIdentity {
        tenant_id: String::new(),
        card_id: String::new(),
        grant_id: String::new(),
        grant_revision: String::new(),
        grant_hash: String::new(),
    };

    fn identity() -> CandidateIdentity {
        CandidateIdentity {
            tenant_id: "7".into(),
            card_id: "17".into(),
            grant_id: "550e8400-e29b-41d4-a716-446655440001".into(),
            grant_revision: "4".into(),
            grant_hash: "a".repeat(64),
        }
    }

    fn event(kind: EventKind, sequence: u64) -> Event {
        Event::new(kind, sequence)
    }

    fn identity_event(kind: EventKind, sequence: u64) -> Event {
        let mut result = event(kind, sequence);
        result.identity = Some(identity());
        result
    }

    fn request(ladder: &[u64; 15], source: &str) -> Vec<Event> {
        let [signed, candidate, final_start, m0s, m0e, p0s, p0e, m1s, m1e, p1s, p1e, evidence, stable, decision, admission] =
            *ladder;
        let mut events = vec![
            event(EventKind::SignedContextBound, signed),
            identity_event(EventKind::CandidateMatch, candidate),
            identity_event(EventKind::FinalReloadStart, final_start),
        ];
        if source == "strict_db" {
            let mut start = event(EventKind::AuthoritativeReadStart, m0s);
            start.observation = Some("strict_pending_probe".into());
            start.outcome = Some("started".into());
            let mut end = event(EventKind::AuthoritativeReadEnd, m0e);
            end.observation = Some("strict_pending_probe".into());
            end.outcome = Some("ok".into());
            end.pending = Some(false);
            events.extend([start, end]);
        } else {
            for (kind, name, start_seq, end_seq) in [
                ("manifest", "cache_manifest", m0s, m0e),
                ("pending", "cache_pending_probe", p0s, p0e),
                ("manifest", "cache_manifest", m1s, m1e),
                ("pending", "cache_pending_probe", p1s, p1e),
            ] {
                let _ = kind;
                let mut start = event(EventKind::AuthoritativeReadStart, start_seq);
                start.observation = Some(name.into());
                start.outcome = Some("started".into());
                let mut end = event(EventKind::AuthoritativeReadEnd, end_seq);
                end.observation = Some(name.into());
                end.outcome = Some("ok".into());
                if name == "cache_pending_probe" {
                    end.pending = Some(false);
                }
                events.extend([start, end]);
            }
        }
        let mut evidence_event = event(EventKind::EvidenceLoadResult, evidence);
        evidence_event.source = Some(source.into());
        let mut stable_event = identity_event(EventKind::StableCheckEnd, stable);
        stable_event.stable = Some(true);
        let mut decision_event = event(EventKind::DecisionReturn, decision);
        decision_event.allowed = Some(true);
        events.extend([
            evidence_event,
            stable_event,
            decision_event,
            event(EventKind::HostAdmission, admission),
        ]);
        events
    }

    fn mutation(start: u64, end: u64) -> Vec<Event> {
        let begin = event(EventKind::SourceCommitStart, start);
        let mut durable = event(EventKind::SourceCommitEnd, end);
        durable.outcome = Some("committed".into());
        vec![begin, durable]
    }

    fn ladder(kind: &str) -> [u64; 15] {
        match kind {
            "odd" => [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29],
            "even" => [2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30],
            _ => [1, 4, 7, 10, 13, 16, 19, 22, 25, 28, 31, 34, 37, 40, 43],
        }
    }

    #[test]
    fn classifier_matches_exhaustive_interval_oracle_and_domain_grid() {
        let mut seen = BTreeSet::new();
        let mut total = 0;
        for ladder_name in ["odd", "even", "gap3"] {
            let ladder = ladder(ladder_name);
            let reserved = ladder.into_iter().collect::<BTreeSet<_>>();
            for source in ["l1_cache", "strict_db"] {
                let request = request(&ladder, source);
                let values = (1..=ladder[14] + 5)
                    .filter(|value| !reserved.contains(value))
                    .collect::<Vec<_>>();
                for start in &values {
                    for end in &values {
                        if start >= end {
                            continue;
                        }
                        let result = classify_e1_allow(&request, &mutation(*start, *end)).unwrap();
                        let expected_violation = *end < result.final_observation_interval.start;
                        assert_eq!(
                            result.stale_allow_violation, expected_violation,
                            "{ladder_name}/{source}/{start}/{end}"
                        );
                        assert_eq!(result.theorem_domain, result.stale_allow_violation);
                        if result.category == Category::IntervalOverlapUnknown {
                            assert!(result
                                .commit_interval
                                .overlaps(result.final_observation_interval));
                        }
                        seen.insert(result.category);
                        total += 1;
                    }
                }
            }
        }
        assert!(total > 400);
        assert_eq!(
            seen,
            BTreeSet::from([
                Category::PreCommit,
                Category::PostCommitBeforeFinalObservation,
                Category::PostFinalObservationOverlap,
                Category::IntervalOverlapUnknown,
            ])
        );
        assert!(!seen.contains(&Category::InFlight));
        assert!(!seen.contains(&Category::UnclassifiedUnknown));
        for (m0_start, m0_end) in [(7, 9), (8, 10)] {
            assert_eq!(
                classify_domain(
                    Some(SequenceInterval {
                        start: m0_start - 2,
                        end: m0_start
                    }),
                    Some(SequenceInterval {
                        start: m0_start,
                        end: m0_end
                    }),
                ),
                ModelDomain::OverlapUnknown
            );
            assert_eq!(
                classify_domain(
                    Some(SequenceInterval {
                        start: m0_start - 2,
                        end: m0_start - 1
                    }),
                    Some(SequenceInterval {
                        start: m0_start,
                        end: m0_end
                    }),
                ),
                ModelDomain::StrictlyBefore
            );
        }
    }

    #[test]
    fn classifier_fails_closed_on_identity_epoch_order_and_commit_evidence() {
        let l = ladder("odd");
        let mut events = request(&l, "l1_cache");
        events
            .iter_mut()
            .find(|item| item.kind == EventKind::StableCheckEnd)
            .unwrap()
            .identity
            .as_mut()
            .unwrap()
            .grant_revision = "5".into();
        assert!(classify_e1_allow(&events, &mutation(2, 4)).is_err());

        let mut events = request(&l, "strict_db");
        events
            .iter_mut()
            .find(|item| item.kind == EventKind::DecisionReturn)
            .unwrap()
            .allowed = Some(false);
        assert!(classify_e1_allow(&events, &mutation(2, 4)).is_err());

        let mut mutation_events = mutation(2, 4);
        mutation_events[1].outcome = Some("unknown".into());
        assert!(classify_e1_allow(&request(&l, "strict_db"), &mutation_events).is_err());

        let mut mutation_events = mutation(2, 4);
        mutation_events[1].process_epoch = "proc-b".into();
        assert!(classify_e1_allow(&request(&l, "strict_db"), &mutation_events).is_err());

        let request_events = request(&l, "l1_cache");
        for defect in [
            EventKind::AuthoritativeReadEnd,
            EventKind::EvidenceLoadResult,
            EventKind::HostAdmission,
        ] {
            let mut malformed = request_events.clone();
            malformed.retain(|item| item.kind != defect);
            assert!(classify_e1_allow(&malformed, &mutation(2, 4)).is_err());
        }

        let mut malformed = request_events;
        malformed
            .iter_mut()
            .find(|item| {
                item.kind == EventKind::AuthoritativeReadEnd
                    && item.observation.as_deref() == Some("cache_pending_probe")
            })
            .unwrap()
            .pending = Some(true);
        assert!(classify_e1_allow(&malformed, &mutation(2, 4)).is_err());
    }

    #[test]
    fn multi_mutation_requires_representation_and_tracks_attribution() {
        let l = ladder("odd");
        let request = request(&l, "l1_cache");
        let mutations = vec![mutation(2, 4), mutation(16, 18)];
        let conservative = classify_e1_allow_multi(&request, &mutations, None).unwrap();
        assert_eq!(conservative.hazard_candidates, vec![0]);
        assert_eq!(conservative.violating_mutations, vec![0]);
        let represented =
            classify_e1_allow_multi(&request, &mutations, Some(&BTreeMap::from([(0, true)])))
                .unwrap();
        assert_eq!(represented.combined_domain, "strictlyBeforeRepresented");
        assert!(!represented.stale_allow_violation);
        assert!(classify_e1_allow_multi(&request, &[], None).is_err());
    }

    #[test]
    fn multi_mutation_requires_only_pre_tf_hazards_and_reports_missing_indices() {
        let l = ladder("even");
        let request = request(&l, "l1_cache");
        let mutations = vec![mutation(1, 3), mutation(5, 7), mutation(9, 11)];
        let conservative = classify_e1_allow_multi(&request, &mutations, None).unwrap();
        assert_eq!(conservative.hazard_candidates, vec![0, 1]);
        assert_eq!(conservative.violating_mutations, vec![0, 1]);

        let missing = BTreeMap::from([(0, true)]);
        let error = classify_e1_allow_multi(&request, &mutations, Some(&missing)).unwrap_err();
        assert!(error.contains("[1]"));

        let adjudicated = classify_e1_allow_multi(
            &request,
            &mutations,
            Some(&BTreeMap::from([(0, true), (1, false)])),
        )
        .unwrap();
        assert_eq!(adjudicated.hazard_candidates, vec![0, 1]);
        assert_eq!(adjudicated.violating_mutations, vec![1]);
        assert!(adjudicated.stale_allow_violation);
    }

    #[test]
    fn candidate_identity_requires_all_fields() {
        assert!(!IDENTITY.is_complete());
        assert!(identity().is_complete());
    }
}
