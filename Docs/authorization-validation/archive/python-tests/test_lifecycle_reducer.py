#!/usr/bin/env python3
"""Offline unit tests for conservative authorization lifecycle reduction."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from typing import List


_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import experiment_common as common  # noqa: E402
import lifecycle_reducer as reducer  # noqa: E402


def e1(
    sequence: int,
    name: str,
    *,
    request_id: str = "req-1",
    node: str = "node-a",
    process: str = "proc-a",
    wall: int = 0,
    **fields: object,
) -> common.Event:
    wall_unix_ns = sequence * 1_000 if wall == 0 else wall
    payload = {"event": name, "request_id": request_id}
    payload.update(fields)
    return common.Event(name, request_id, sequence, wall_unix_ns, payload, node, process)


def complete_e1(
    *, request_id: str = "req-1", node: str = "node-a", process: str = "proc-a"
) -> List[common.Event]:
    # The first evidence event is the initial read. The second lies strictly
    # inside final_reload_start..stable_check_end and is the final reload read.
    return [
        e1(1, "signed_context_bound", request_id=request_id, node=node, process=process),
        e1(2, "evidence_load_result", request_id=request_id, node=node, process=process),
        e1(3, "candidate_match", request_id=request_id, node=node, process=process),
        e1(4, "final_reload_start", request_id=request_id, node=node, process=process),
        e1(5, "evidence_load_result", request_id=request_id, node=node, process=process),
        e1(6, "stable_check_end", request_id=request_id, node=node, process=process, stable=True),
        e1(7, "decision_return", request_id=request_id, node=node, process=process, allowed=True),
        e1(8, "host_admission", request_id=request_id, node=node, process=process),
    ]


def e3(
    sequence: int,
    name: str,
    *,
    delta_id: int = 7,
    attempt: int = 1,
    node: str = "node-a",
    process: str = "proc-a",
    wall: int = 0,
    durable: bool = True,
) -> common.E3Event:
    wall_unix_ns = sequence * 1_000 if wall == 0 else wall
    return common.E3Event(
        name,
        process,
        sequence,
        wall_unix_ns,
        delta_id,
        "event-{}".format(delta_id),
        "op-{}".format(delta_id),
        attempt,
        {"event": name, "durable": durable},
        node,
    )


class E1LifecycleReductionTest(unittest.TestCase):
    def test_complete_same_epoch_request_produces_stage_percentiles(self) -> None:
        report = reducer.reduce_e1_lifecycle(complete_e1())
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["samples"], 1)
        self.assertEqual(report["unknownSamples"], 0)
        self.assertEqual(
            report["percentiles"]["total"],
            {"samples": 1, "p50Ns": 7_000, "p95Ns": 7_000, "p99Ns": 7_000},
        )
        self.assertEqual(report["percentiles"]["final_reload_to_evidence"]["p50Ns"], 1_000)
        self.assertEqual(report["percentiles"]["initial_evidence_to_candidate"]["p50Ns"], 1_000)

    def test_missing_initial_evidence_is_unknown_and_excluded(self) -> None:
        missing = [event for event in complete_e1() if event.sequence != 2]
        report = reducer.reduce_e1_lifecycle(missing)
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertEqual(report["samples"], 0)
        self.assertEqual(report["unknown"]["req-1"], ["missing:initial_evidence_load"])

    def test_missing_or_ambiguous_final_evidence_is_unknown_and_excluded(self) -> None:
        missing = [event for event in complete_e1() if event.sequence != 5]
        duplicate = complete_e1(request_id="req-2")
        duplicate[5] = e1(7, "stable_check_end", request_id="req-2", stable=True)
        duplicate[6] = e1(8, "decision_return", request_id="req-2", allowed=True)
        duplicate[7] = e1(9, "host_admission", request_id="req-2")
        duplicate.insert(5, e1(6, "evidence_load_result", request_id="req-2"))
        report = reducer.reduce_e1_lifecycle(missing + duplicate)
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertEqual(report["samples"], 0)
        self.assertEqual(report["unknownSamples"], 2)
        self.assertIn("missing:final_evidence_load", report["unknown"]["req-1"])
        self.assertIn("ambiguous:final_evidence_load", report["unknown"]["req-2"])
        self.assertEqual(report["percentiles"], {})

    def test_cross_epoch_or_unproven_allow_is_unknown_without_sequence_comparison(self) -> None:
        across_epochs = complete_e1()
        across_epochs[-1] = e1(
            1, "host_admission", process="proc-after-restart", wall=10_000
        )
        pending = complete_e1(request_id="req-2")
        pending[-2] = e1(7, "decision_return", request_id="req-2", allowed=False)
        report = reducer.reduce_e1_lifecycle(across_epochs + pending)
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertEqual(report["samples"], 0)
        self.assertEqual(report["unknown"]["req-1"], ["cross_epoch"])
        self.assertEqual(report["unknown"]["req-2"], ["allow_decision_not_proven"])

    def test_cross_node_interval_requires_clock_offset_evidence(self) -> None:
        start = e1(1, "source_commit_end", node="node-a")
        end = e1(2, "pointer_visible", node="node-b")
        self.assertEqual(
            reducer.reduce_cross_node_interval(start, end, clock_offset_evidence=False),
            {"status": "UNKNOWN", "reason": "cross_node_clock_offset_unproven"},
        )
        self.assertEqual(
            reducer.reduce_cross_node_interval(start, end, clock_offset_evidence=True),
            {"status": "PASS", "durationNs": 1_000},
        )


class E3LifecycleReductionTest(unittest.TestCase):
    def test_same_process_durable_claim_to_terminal_is_reduced(self) -> None:
        report = reducer.reduce_e3_lifecycle(
            [e3(1, "claim_committed"), e3(5, "publish_committed")]
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["samples"], 1)
        self.assertEqual(report["percentiles"]["claim_to_terminal"]["p95Ns"], 4_000)

    def test_restart_boundary_does_not_pair_claim_and_terminal(self) -> None:
        report = reducer.reduce_e3_lifecycle(
            [
                e3(1, "claim_committed", process="proc-before"),
                e3(2, "publish_committed", process="proc-after"),
            ]
        )
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertEqual(report["samples"], 0)
        self.assertEqual(report["unknownSamples"], 1)
        self.assertEqual(
            report["unknown"]["7:event-7:1"], ["cross_epoch_attempt"]
        )

    def test_duplicate_terminal_or_missing_durable_proof_is_unknown(self) -> None:
        duplicate = reducer.reduce_e3_lifecycle(
            [
                e3(1, "claim_committed"),
                e3(2, "publish_committed"),
                e3(3, "quarantine_committed"),
            ]
        )
        self.assertEqual(duplicate["status"], "UNKNOWN")
        self.assertEqual(duplicate["samples"], 0)

        no_durable_proof = reducer.reduce_e3_lifecycle(
            [e3(1, "claim_committed"), e3(2, "terminal_unknown", durable=False)]
        )
        self.assertEqual(no_durable_proof["status"], "UNKNOWN")
        self.assertEqual(
            no_durable_proof["unknown"]["7:event-7:1"],
            ["terminal_unknown"],
        )

        malformed_unknown_terminal = reducer.reduce_e3_lifecycle(
            [e3(1, "claim_committed"), e3(2, "terminal_unknown", durable=True)]
        )
        self.assertEqual(malformed_unknown_terminal["status"], "UNKNOWN")
        self.assertEqual(
            malformed_unknown_terminal["unknown"]["7:event-7:1"],
            ["terminal_unknown"],
        )


class PercentileTest(unittest.TestCase):
    def test_nearest_rank_percentiles_are_conservative_and_fixed(self) -> None:
        values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        self.assertEqual(reducer.percentile(values, 50), 5)
        self.assertEqual(reducer.percentile(values, 95), 10)
        self.assertEqual(reducer.percentile(values, 99), 10)
        self.assertIsNone(reducer.percentile([], 50))
        with self.assertRaises(ValueError):
            reducer.percentile(values, 90)


if __name__ == "__main__":
    unittest.main()
