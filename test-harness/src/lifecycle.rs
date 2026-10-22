use crate::e3_reconciliation::{E3Event, E3EventKind};
use std::collections::{BTreeMap, BTreeSet};

const E1_STAGES: [&str; 6] = [
    "signed_context_bound",
    "candidate_match",
    "final_reload_start",
    "stable_check_end",
    "decision_return",
    "host_admission",
];
const E3_TERMINALS: [E3EventKind; 6] = [
    E3EventKind::PublishCommitted,
    E3EventKind::QuarantineCommitted,
    E3EventKind::BackoffCommitted,
    E3EventKind::ReleaseCommitted,
    E3EventKind::LeaseLeftToExpire,
    E3EventKind::TerminalUnknown,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub event: String,
    pub request_id: String,
    pub sequence: u64,
    pub wall_unix_ns: u64,
    pub node: String,
    pub process_observation_id: String,
    pub stable: Option<bool>,
    pub allowed: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sample {
    pub key: String,
    pub node: String,
    pub process_observation_id: String,
    pub durations_ns: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    pub kind: &'static str,
    pub status: &'static str,
    pub samples: usize,
    pub unknown_samples: usize,
    pub unknown: BTreeMap<String, Vec<String>>,
    pub percentiles: BTreeMap<String, Percentiles>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Percentiles {
    pub samples: usize,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

fn percentile(values: &[u64], rank_percent: usize) -> Option<u64> {
    if values.is_empty() || ![50, 95, 99].contains(&rank_percent) {
        return None;
    }
    let mut ordered = values.to_vec();
    ordered.sort_unstable();
    let rank = (ordered.len() * rank_percent).div_ceil(100).max(1);
    ordered.get(rank - 1).copied()
}

fn report(
    samples: Vec<Sample>,
    unknown: BTreeMap<String, Vec<String>>,
    kind: &'static str,
) -> Report {
    let mut values = BTreeMap::<String, Vec<u64>>::new();
    for sample in &samples {
        for (stage, duration) in &sample.durations_ns {
            values.entry(stage.clone()).or_default().push(*duration);
        }
    }
    let percentiles = values
        .into_iter()
        .filter_map(|(stage, values)| {
            Some((
                stage,
                Percentiles {
                    samples: values.len(),
                    p50_ns: percentile(&values, 50)?,
                    p95_ns: percentile(&values, 95)?,
                    p99_ns: percentile(&values, 99)?,
                },
            ))
        })
        .collect();
    let status = if !samples.is_empty() && unknown.is_empty() {
        "PASS"
    } else {
        "UNKNOWN"
    };
    Report {
        kind,
        status,
        samples: samples.len(),
        unknown_samples: unknown.len(),
        unknown,
        percentiles,
    }
}

fn duration(start: &Event, end: &Event, label: &str) -> Result<u64, String> {
    if start.sequence >= end.sequence {
        return Err(format!("sequence_order:{label}"));
    }
    if end.wall_unix_ns < start.wall_unix_ns {
        return Err(format!("wall_clock_order:{label}"));
    }
    Ok(end.wall_unix_ns - start.wall_unix_ns)
}

pub fn reduce_e1(events: &[Event]) -> Report {
    let mut grouped = BTreeMap::<String, Vec<&Event>>::new();
    for event in events {
        grouped
            .entry(event.request_id.clone())
            .or_default()
            .push(event);
    }
    let mut samples = Vec::new();
    let mut unknown = BTreeMap::new();
    for (request_id, request_events) in grouped {
        let epochs = request_events
            .iter()
            .map(|event| (&event.node, &event.process_observation_id))
            .collect::<BTreeSet<_>>();
        if epochs.len() != 1 {
            unknown.insert(request_id, vec!["cross_epoch".to_owned()]);
            continue;
        }
        let mut ordered = request_events;
        ordered.sort_by_key(|event| event.sequence);
        let mut sequence_set = BTreeSet::new();
        if ordered
            .iter()
            .any(|event| !sequence_set.insert(event.sequence))
        {
            unknown.insert(request_id, vec!["duplicate_process_sequence".to_owned()]);
            continue;
        }
        let mut stage_map = BTreeMap::<&str, Vec<&Event>>::new();
        for event in &ordered {
            if E1_STAGES.contains(&event.event.as_str()) {
                stage_map.entry(&event.event).or_default().push(event);
            }
        }
        let mut stages = BTreeMap::<&str, &Event>::new();
        let mut problems = Vec::new();
        for stage in E1_STAGES {
            match stage_map.get(stage).map(Vec::as_slice).unwrap_or_default() {
                [] => problems.push(format!("missing:{stage}")),
                [one] => {
                    stages.insert(stage, *one);
                }
                _ => problems.push(format!("ambiguous:{stage}")),
            }
        }
        if !problems.is_empty() {
            unknown.insert(request_id, problems);
            continue;
        }
        let final_start = stages["final_reload_start"];
        let stable_end = stages["stable_check_end"];
        let final_evidence = ordered
            .iter()
            .filter(|event| {
                event.event == "evidence_load_result"
                    && final_start.sequence < event.sequence
                    && event.sequence < stable_end.sequence
            })
            .copied()
            .collect::<Vec<_>>();
        let initial_evidence = ordered
            .iter()
            .filter(|event| {
                event.event == "evidence_load_result"
                    && event.sequence < stages["candidate_match"].sequence
            })
            .copied()
            .collect::<Vec<_>>();
        if initial_evidence.is_empty() {
            problems.push("missing:initial_evidence_load".to_owned());
        } else if initial_evidence.len() != 1 {
            problems.push("ambiguous:initial_evidence_load".to_owned());
        }
        if final_evidence.is_empty() {
            problems.push("missing:final_evidence_load".to_owned());
        } else if final_evidence.len() != 1 {
            problems.push("ambiguous:final_evidence_load".to_owned());
        }
        if !problems.is_empty() {
            unknown.insert(request_id, problems);
            continue;
        }
        if stable_end.stable != Some(true) {
            unknown.insert(request_id, vec!["stable_check_not_proven".to_owned()]);
            continue;
        }
        if stages["decision_return"].allowed != Some(true) {
            unknown.insert(request_id, vec!["allow_decision_not_proven".to_owned()]);
            continue;
        }
        let initial = initial_evidence[0];
        let final_evidence = final_evidence[0];
        let pairs = [
            (
                "initial_evidence_to_candidate",
                initial,
                stages["candidate_match"],
            ),
            (
                "context_to_candidate",
                stages["signed_context_bound"],
                stages["candidate_match"],
            ),
            (
                "candidate_to_final_reload",
                stages["candidate_match"],
                final_start,
            ),
            ("final_reload_to_evidence", final_start, final_evidence),
            ("evidence_to_stable_check", final_evidence, stable_end),
            (
                "stable_check_to_decision",
                stable_end,
                stages["decision_return"],
            ),
            (
                "decision_to_admission",
                stages["decision_return"],
                stages["host_admission"],
            ),
            (
                "total",
                stages["signed_context_bound"],
                stages["host_admission"],
            ),
        ];
        let mut durations = BTreeMap::new();
        for (label, start, end) in pairs {
            match duration(start, end, label) {
                Ok(value) => {
                    durations.insert(label.to_owned(), value);
                }
                Err(problem) => problems.push(problem),
            }
        }
        if !problems.is_empty() {
            unknown.insert(request_id, problems);
            continue;
        }
        let epoch = stages["signed_context_bound"];
        samples.push(Sample {
            key: request_id,
            node: epoch.node.clone(),
            process_observation_id: epoch.process_observation_id.clone(),
            durations_ns: durations,
        });
    }
    report(samples, unknown, "e1")
}

pub fn reduce_e3(events: &[E3Event]) -> Report {
    let mut grouped = BTreeMap::<(u64, String, u32), Vec<&E3Event>>::new();
    let mut unknown = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        let Some(attempt) = event.attempts.filter(|attempt| *attempt > 0) else {
            unknown.insert(
                format!("{}:{}:{index}", event.delta_event_id, event.event_id),
                vec!["missing_or_invalid_attempt".to_owned()],
            );
            continue;
        };
        grouped
            .entry((event.delta_event_id, event.event_id.clone(), attempt))
            .or_default()
            .push(event);
    }
    let mut samples = Vec::new();
    for ((delta_id, event_id, attempt), attempt_events) in grouped {
        let key = format!("{delta_id}:{event_id}:{attempt}");
        let epochs = attempt_events
            .iter()
            .map(|event| (&event.node, &event.process_observation_id))
            .collect::<BTreeSet<_>>();
        if epochs.len() != 1 {
            unknown.insert(key, vec!["cross_epoch_attempt".to_owned()]);
            continue;
        }
        let mut sequences = BTreeSet::new();
        if attempt_events
            .iter()
            .any(|event| !sequences.insert(event.sequence))
        {
            unknown.insert(key, vec!["duplicate_process_sequence".to_owned()]);
            continue;
        }
        let claims = attempt_events
            .iter()
            .filter(|event| event.kind == E3EventKind::ClaimCommitted)
            .copied()
            .collect::<Vec<_>>();
        let terminals = attempt_events
            .iter()
            .filter(|event| E3_TERMINALS.contains(&event.kind))
            .copied()
            .collect::<Vec<_>>();
        if claims.len() != 1 || terminals.len() != 1 {
            unknown.insert(
                key,
                vec![if claims.len() != 1 {
                    "missing_or_ambiguous_claim".to_owned()
                } else {
                    "missing_or_ambiguous_terminal".to_owned()
                }],
            );
            continue;
        }
        let claim = claims[0];
        let terminal = terminals[0];
        if terminal.kind == E3EventKind::TerminalUnknown {
            unknown.insert(key, vec!["terminal_unknown".to_owned()]);
            continue;
        }
        if terminal.durable != Some(true) {
            unknown.insert(key, vec!["terminal_durable_proof_missing".to_owned()]);
            continue;
        }
        if claim.sequence >= terminal.sequence || terminal.wall_unix_ns < claim.wall_unix_ns {
            unknown.insert(key, vec!["invalid_claim_terminal_order".to_owned()]);
            continue;
        }
        samples.push(Sample {
            key,
            node: claim.node.clone(),
            process_observation_id: claim.process_observation_id.clone(),
            durations_ns: BTreeMap::from([(
                "claim_to_terminal".to_owned(),
                terminal.wall_unix_ns - claim.wall_unix_ns,
            )]),
        });
    }
    report(samples, unknown, "e3")
}

pub fn reduce_cross_node_interval(
    start_node: &str,
    start_wall_ns: u64,
    end_node: &str,
    end_wall_ns: u64,
    clock_offset_proven: bool,
) -> Result<u64, &'static str> {
    if start_node != end_node && !clock_offset_proven {
        return Err("cross_node_clock_offset_unproven");
    }
    end_wall_ns
        .checked_sub(start_wall_ns)
        .ok_or("wall_clock_order")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e1(sequence: u64, event: &str) -> Event {
        Event {
            event: event.into(),
            request_id: "req-1".into(),
            sequence,
            wall_unix_ns: sequence * 1_000,
            node: "node-a".into(),
            process_observation_id: "proc-a".into(),
            stable: None,
            allowed: None,
        }
    }

    fn complete_e1() -> Vec<Event> {
        let mut events = vec![
            e1(1, "signed_context_bound"),
            e1(2, "evidence_load_result"),
            e1(3, "candidate_match"),
            e1(4, "final_reload_start"),
            e1(5, "evidence_load_result"),
            e1(6, "stable_check_end"),
            e1(7, "decision_return"),
            e1(8, "host_admission"),
        ];
        events[5].stable = Some(true);
        events[6].allowed = Some(true);
        events
    }

    fn e3(kind: E3EventKind, sequence: u64, durable: Option<bool>) -> E3Event {
        E3Event {
            kind,
            node: "node-a".into(),
            process_observation_id: "proc-a".into(),
            sequence,
            wall_unix_ns: sequence * 1_000,
            delta_event_id: 7,
            event_id: "event-7".into(),
            operation_id: Some("op-7".into()),
            attempts: Some(1),
            durable,
            outcome: None,
        }
    }

    #[test]
    fn e1_reduction_requires_complete_same_epoch_allow_and_uses_nearest_rank() {
        let result = reduce_e1(&complete_e1());
        assert_eq!(result.status, "PASS");
        assert_eq!(result.samples, 1);
        assert_eq!(result.percentiles["total"].p50_ns, 7_000);
        assert_eq!(result.percentiles["total"].p95_ns, 7_000);
        assert_eq!(result.percentiles["total"].p99_ns, 7_000);
        assert_eq!(result.percentiles["final_reload_to_evidence"].p99_ns, 1_000);

        let mut missing_initial = complete_e1();
        missing_initial.retain(|event| event.sequence != 2);
        let result = reduce_e1(&missing_initial);
        assert_eq!(result.status, "UNKNOWN");
        assert_eq!(result.samples, 0);
        assert_eq!(result.unknown["req-1"], ["missing:initial_evidence_load"]);

        let mut cross_epoch = complete_e1();
        cross_epoch.last_mut().unwrap().process_observation_id = "proc-b".into();
        assert_eq!(reduce_e1(&cross_epoch).unknown["req-1"], ["cross_epoch"]);
        let mut unproven = complete_e1();
        unproven[6].allowed = Some(false);
        assert_eq!(
            reduce_e1(&unproven).unknown["req-1"],
            ["allow_decision_not_proven"]
        );
    }

    #[test]
    fn e3_reduction_refuses_restart_ambiguous_and_unproven_terminals() {
        let complete = [
            e3(E3EventKind::ClaimCommitted, 1, Some(true)),
            e3(E3EventKind::PublishCommitted, 5, Some(true)),
        ];
        let result = reduce_e3(&complete);
        assert_eq!(result.status, "PASS");
        assert_eq!(result.percentiles["claim_to_terminal"].p95_ns, 4_000);

        let mut restarted = complete.to_vec();
        restarted[1].process_observation_id = "proc-b".into();
        assert_eq!(
            reduce_e3(&restarted).unknown["7:event-7:1"],
            ["cross_epoch_attempt"]
        );

        let duplicate = [
            complete[0].clone(),
            complete[1].clone(),
            e3(E3EventKind::QuarantineCommitted, 6, Some(true)),
        ];
        assert_eq!(reduce_e3(&duplicate).status, "UNKNOWN");
        assert_eq!(
            reduce_e3(&[
                complete[0].clone(),
                e3(E3EventKind::PublishCommitted, 2, None)
            ])
            .unknown["7:event-7:1"],
            ["terminal_durable_proof_missing"]
        );
        assert_eq!(
            reduce_e3(&[
                complete[0].clone(),
                e3(E3EventKind::TerminalUnknown, 2, Some(true))
            ])
            .unknown["7:event-7:1"],
            ["terminal_unknown"]
        );
    }

    #[test]
    fn cross_node_time_needs_clock_proof_and_percentiles_are_bounded() {
        assert_eq!(
            reduce_cross_node_interval("node-a", 100, "node-b", 200, false),
            Err("cross_node_clock_offset_unproven")
        );
        assert_eq!(
            reduce_cross_node_interval("node-a", 100, "node-b", 200, true),
            Ok(100)
        );
        assert_eq!(
            reduce_cross_node_interval("node-a", 200, "node-a", 100, false),
            Err("wall_clock_order")
        );
        assert_eq!(percentile(&[10, 1, 7, 4, 3, 2, 9, 5, 8, 6], 50), Some(5));
        assert_eq!(percentile(&[10, 1, 7, 4, 3, 2, 9, 5, 8, 6], 95), Some(10));
        assert_eq!(percentile(&[], 50), None);
        assert_eq!(percentile(&[1], 90), None);
    }
}
