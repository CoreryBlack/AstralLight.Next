#!/usr/bin/env python3
"""Conservative offline lifecycle reduction for authorization campaign events.

The reducer has no network, database, subprocess, or write behavior. It only
turns already-captured E1/E3 structured observations into diagnostic latency
samples. A missing stage, duplicate stage, process epoch boundary, absent
durable terminal proof, or cross-node clock relationship without explicit
offset evidence stays UNKNOWN and is excluded from percentiles.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from experiment_common import E3Event, Event


E1_REQUIRED_STAGES = (
    "signed_context_bound",
    "candidate_match",
    "final_reload_start",
    "stable_check_end",
    "decision_return",
    "host_admission",
)
E3_TERMINALS = frozenset(
    {
        "publish_committed",
        "quarantine_committed",
        "backoff_committed",
        "release_committed",
        "lease_left_to_expire",
        "terminal_unknown",
    }
)


@dataclass(frozen=True)
class LifecycleSample:
    """One safely ordered diagnostic sample from a single process epoch."""

    key: str
    node: str
    process_observation_id: str
    durations_ns: Mapping[str, int]


def _same_epoch(events: Sequence[Event]) -> Optional[Tuple[str, str]]:
    epochs = {(event.node, event.process_observation_id) for event in events}
    if len(epochs) != 1:
        return None
    return next(iter(epochs))


def _unique_stages(
    events: Sequence[Event], required: Sequence[str]
) -> Tuple[Dict[str, Event], List[str]]:
    by_stage: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.event in required:
            by_stage[event.event].append(event)
    unknown: List[str] = []
    unique: Dict[str, Event] = {}
    for stage in required:
        matches = by_stage.get(stage, [])
        if not matches:
            unknown.append("missing:" + stage)
        elif len(matches) != 1:
            unknown.append("ambiguous:" + stage)
        else:
            unique[stage] = matches[0]
    return unique, unknown


def _ordered_wall_duration(
    start: Event, end: Event, label: str
) -> Tuple[Optional[int], Optional[str]]:
    if start.sequence >= end.sequence:
        return None, "sequence_order:" + label
    if end.wall_unix_ns < start.wall_unix_ns:
        return None, "wall_clock_order:" + label
    return end.wall_unix_ns - start.wall_unix_ns, None


def _final_evidence_event(
    events: Sequence[Event], final_start: Event, stable_end: Event
) -> Tuple[Optional[Event], Optional[str]]:
    """Select the one evidence read inside the final reload bracket.

    E1 ALLOW requests intentionally have an initial evidence read before
    candidate matching and a final read after ``final_reload_start``. Only the
    latter belongs to the final-reload latency interval; treating both as a
    duplicate would discard every valid ALLOW sample.
    """
    candidates = [
        event
        for event in events
        if event.event == "evidence_load_result"
        and final_start.sequence < event.sequence < stable_end.sequence
    ]
    if not candidates:
        return None, "missing:final_evidence_load"
    if len(candidates) != 1:
        return None, "ambiguous:final_evidence_load"
    return candidates[0], None


def reduce_e1_lifecycle(events: Sequence[Event]) -> Dict[str, Any]:
    """Reduce complete same-process E1 ALLOW/admission observations.

    The report does not classify stale authorization or prove durable source
    publication. It only reports timing for requests whose complete existing
    event contract proves one same-process, identity-stable admitted ALLOW.
    """
    by_request: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        by_request[event.request_id].append(event)

    samples: List[LifecycleSample] = []
    unknown: Dict[str, List[str]] = {}
    for request_id, request_events in sorted(by_request.items()):
        epoch = _same_epoch(request_events)
        if epoch is None:
            unknown[request_id] = ["cross_epoch"]
            continue
        ordered = sorted(request_events, key=lambda item: item.sequence)
        sequences = [event.sequence for event in ordered]
        if len(sequences) != len(set(sequences)):
            unknown[request_id] = ["duplicate_process_sequence"]
            continue
        stages, reasons = _unique_stages(ordered, E1_REQUIRED_STAGES)
        if reasons:
            unknown[request_id] = reasons
            continue
        final_evidence, evidence_problem = _final_evidence_event(
            ordered, stages["final_reload_start"], stages["stable_check_end"]
        )
        initial_evidence = [
            event
            for event in ordered
            if event.event == "evidence_load_result"
            and event.sequence < stages["candidate_match"].sequence
        ]
        if not initial_evidence:
            reasons.append("missing:initial_evidence_load")
        elif len(initial_evidence) != 1:
            reasons.append("ambiguous:initial_evidence_load")
        if reasons:
            unknown[request_id] = reasons
            continue
        if evidence_problem is not None or final_evidence is None:
            unknown[request_id] = [evidence_problem or "invalid:final_evidence_load"]
            continue
        initial_evidence_event = initial_evidence[0]
        if stages["stable_check_end"].fields.get("stable") is not True:
            unknown[request_id] = ["stable_check_not_proven"]
            continue
        if stages["decision_return"].fields.get("allowed") is not True:
            unknown[request_id] = ["allow_decision_not_proven"]
            continue
        stages["initial_evidence_load"] = initial_evidence_event
        stages["final_evidence_load"] = final_evidence
        durations: Dict[str, int] = {}
        pairs = (
            ("initial_evidence_to_candidate", "initial_evidence_load", "candidate_match"),
            ("context_to_candidate", "signed_context_bound", "candidate_match"),
            ("candidate_to_final_reload", "candidate_match", "final_reload_start"),
            ("final_reload_to_evidence", "final_reload_start", "final_evidence_load"),
            ("evidence_to_stable_check", "final_evidence_load", "stable_check_end"),
            ("stable_check_to_decision", "stable_check_end", "decision_return"),
            ("decision_to_admission", "decision_return", "host_admission"),
            ("total", "signed_context_bound", "host_admission"),
        )
        for label, start_name, end_name in pairs:
            elapsed, problem = _ordered_wall_duration(
                stages[start_name], stages[end_name], label
            )
            if problem is not None or elapsed is None:
                reasons.append(problem or "invalid:" + label)
            else:
                durations[label] = elapsed
        if reasons:
            unknown[request_id] = reasons
            continue
        node, process_observation_id = epoch
        samples.append(
            LifecycleSample(request_id, node, process_observation_id, durations)
        )

    return _report(samples, unknown, "e1")


def reduce_e3_lifecycle(events: Sequence[E3Event]) -> Dict[str, Any]:
    """Reduce per-attempt E3 claim-to-durable-terminal intervals.

    Current E3 structured logs provide a stable claim and terminal boundary,
    not a cross-process trace for every internal projector phase. The runtime
    Prometheus phase histograms carry those per-phase distributions. This
    reducer refuses to pair claim and terminal observations across a restart
    or when the terminal durable proof is absent.
    """
    grouped: Dict[Tuple[int, str, int], List[E3Event]] = defaultdict(list)
    unknown: Dict[str, List[str]] = {}
    for ordinal, event in enumerate(events):
        if isinstance(event.attempts, bool) or not isinstance(event.attempts, int) or event.attempts <= 0:
            unknown[
                "{}:{}:{}".format(event.delta_event_id, event.event_id, ordinal)
            ] = ["missing_or_invalid_attempt"]
            continue
        grouped[(event.delta_event_id, event.event_id, event.attempts)].append(event)

    samples: List[LifecycleSample] = []
    for (delta_id, event_id, attempt), attempt_events in sorted(grouped.items()):
        key = "{}:{}:{}".format(delta_id, event_id, attempt)
        epochs = {(event.node, event.process_observation_id) for event in attempt_events}
        if len(epochs) != 1:
            unknown[key] = ["cross_epoch_attempt"]
            continue
        node, process_observation_id = next(iter(epochs))
        ordered = sorted(attempt_events, key=lambda item: item.sequence)
        sequences = [event.sequence for event in ordered]
        if len(sequences) != len(set(sequences)):
            unknown[key] = ["duplicate_process_sequence"]
            continue
        claims = [event for event in ordered if event.event == "claim_committed"]
        terminals = [event for event in ordered if event.event in E3_TERMINALS]
        if len(claims) != 1 or len(terminals) != 1:
            unknown[key] = [
                "missing_or_ambiguous_claim"
                if len(claims) != 1
                else "missing_or_ambiguous_terminal"
            ]
            continue
        claim, terminal = claims[0], terminals[0]
        if terminal.event == "terminal_unknown":
            unknown[key] = ["terminal_unknown"]
            continue
        if terminal.fields.get("durable") is not True:
            unknown[key] = ["terminal_durable_proof_missing"]
            continue
        if claim.sequence >= terminal.sequence or terminal.wall_unix_ns < claim.wall_unix_ns:
            unknown[key] = ["invalid_claim_terminal_order"]
            continue
        durations = {"claim_to_terminal": terminal.wall_unix_ns - claim.wall_unix_ns}
        samples.append(
            LifecycleSample(key, node, process_observation_id, durations)
        )

    return _report(samples, unknown, "e3")


def reduce_cross_node_interval(
    start: Event, end: Event, *, clock_offset_evidence: bool
) -> Dict[str, Any]:
    """Compute a wall-clock interval only with a proven cross-node offset."""
    if start.node != end.node and not clock_offset_evidence:
        return {"status": "UNKNOWN", "reason": "cross_node_clock_offset_unproven"}
    if start.wall_unix_ns > end.wall_unix_ns:
        return {"status": "UNKNOWN", "reason": "wall_clock_order"}
    return {"status": "PASS", "durationNs": end.wall_unix_ns - start.wall_unix_ns}


def percentile(values: Sequence[int], percentile_value: int) -> Optional[int]:
    """Nearest-rank p50/p95/p99 for a non-empty diagnostic sample set."""
    if not values:
        return None
    if percentile_value not in {50, 95, 99}:
        raise ValueError("only p50, p95, and p99 are supported")
    ordered = sorted(values)
    rank = max(1, (len(ordered) * percentile_value + 99) // 100)
    return ordered[rank - 1]


def _report(
    samples: Iterable[LifecycleSample],
    unknown: Mapping[str, Sequence[str]],
    kind: str,
) -> Dict[str, Any]:
    resolved = list(samples)
    stage_values: Dict[str, List[int]] = defaultdict(list)
    for sample in resolved:
        for stage, value in sample.durations_ns.items():
            stage_values[stage].append(value)
    percentiles = {
        stage: {
            "samples": len(values),
            "p50Ns": percentile(values, 50),
            "p95Ns": percentile(values, 95),
            "p99Ns": percentile(values, 99),
        }
        for stage, values in sorted(stage_values.items())
    }
    return {
        "kind": kind,
        "status": "PASS" if resolved and not unknown else "UNKNOWN",
        "samples": len(resolved),
        "unknownSamples": len(unknown),
        "excludedSamples": len(unknown),
        "unknown": {key: list(value) for key, value in sorted(unknown.items())},
        "percentiles": percentiles,
    }
