#!/usr/bin/env python3
"""Offline tests for the side-effect-free node campaign helpers."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import experiment_common as common  # noqa: E402


IDENTITY: Dict[str, Any] = {
    "tenant_id": 7,
    "card_id": 17,
    "grant_id": "550e8400-e29b-41d4-a716-446655440001",
    "grant_revision": 4,
    "grant_hash": "a" * 64,
}


def event(
    sequence: int,
    name: str,
    *,
    request_id: str = "req-reader",
    node: str = "node-a",
    process_observation_id: str = "proc-a",
    **fields: Any,
) -> common.Event:
    flattened: Dict[str, Any] = {
        "event": name,
        "request_id": request_id,
        "event_sequence": sequence,
        "wall_unix_ns": sequence * 1_000,
        "process_observation_id": process_observation_id,
    }
    flattened.update(fields)
    return common.Event(
        name, request_id, sequence, sequence * 1_000, flattened, node, process_observation_id
    )


def identity_event(sequence: int, name: str, **fields: Any) -> common.Event:
    payload = dict(IDENTITY)
    payload.update(fields)
    return event(sequence, name, **payload)


def strict_request(*, stable: bool = True, identity_override: Optional[Mapping[str, Any]] = None) -> List[common.Event]:
    stable_identity = dict(IDENTITY)
    if identity_override:
        stable_identity.update(identity_override)
    return [
        event(1, "signed_context_bound"),
        identity_event(2, "candidate_match"),
        identity_event(3, "final_reload_start"),
        event(
            10,
            "authoritative_read_start",
            observation="strict_pending_probe",
            outcome="started",
        ),
        event(
            20,
            "authoritative_read_end",
            observation="strict_pending_probe",
            outcome="ok",
            pending=False,
        ),
        event(21, "evidence_load_result", source="strict_db"),
        event(30, "stable_check_end", stable=stable, **stable_identity),
        event(31, "decision_return", allowed=True, reason="PUBLISHED_EVIDENCE_ALLOW"),
        event(40, "host_admission"),
    ]


def cache_request() -> List[common.Event]:
    return [
        event(1, "signed_context_bound"),
        identity_event(2, "candidate_match"),
        identity_event(3, "final_reload_start"),
        event(4, "authoritative_read_start", observation="cache_manifest", outcome="started"),
        event(5, "authoritative_read_end", observation="cache_manifest", outcome="ok"),
        event(6, "authoritative_read_start", observation="cache_pending_probe", outcome="started"),
        event(
            7,
            "authoritative_read_end",
            observation="cache_pending_probe",
            outcome="ok",
            pending="Some(false)",
        ),
        event(8, "authoritative_read_start", observation="cache_manifest", outcome="started"),
        event(9, "authoritative_read_end", observation="cache_manifest", outcome="ok"),
        event(10, "authoritative_read_start", observation="cache_pending_probe", outcome="started"),
        event(
            11,
            "authoritative_read_end",
            observation="cache_pending_probe",
            outcome="ok",
            pending="Some(false)",
        ),
        event(12, "evidence_load_result", source="l1_cache"),
        identity_event(13, "stable_check_end", stable=True),
        event(14, "decision_return", allowed=True, reason="PUBLISHED_EVIDENCE_ALLOW"),
        event(15, "host_admission"),
    ]


def commit_events(
    start: int,
    end: int,
    *,
    outcome: str = "committed",
    node: str = "node-a",
    process_observation_id: str = "proc-a",
) -> List[common.Event]:
    return [
        event(
            start,
            "source_commit_start",
            request_id="req-mutation",
            node=node,
            process_observation_id=process_observation_id,
            operation_id="op-e1",
        ),
        event(
            end,
            "source_commit_end",
            request_id="req-mutation",
            node=node,
            process_observation_id=process_observation_id,
            operation_id="op-e1",
            outcome=outcome,
        ),
    ]


def as_json_lines(events: Iterable[common.Event]) -> List[str]:
    lines = []
    for item in events:
        lines.append(
            json.dumps(
                {
                    "target": "authz_e1",
                    "fields": dict(item.fields, message="e1 authorization observation"),
                }
            )
        )
    return lines


def as_e3_json_lines(events: Iterable[Mapping[str, Any]]) -> List[str]:
    return [
        json.dumps({"target": "authz_e3", "fields": dict(item, message="e3 projector observation")})
        for item in events
    ]


def e3_fixture_events() -> List[Mapping[str, Any]]:
    return [
        {
            "event": "claim_committed",
            "process_observation_id": "proc-a",
            "event_sequence": 1,
            "wall_unix_ns": 1000,
            "delta_event_id": 11,
            "event_id": "event-11",
            "operation_id": "op-11",
            "attempts": 1,
            "outcome": "leased",
            "durable": True,
        },
        {
            "event": "backoff_committed",
            "process_observation_id": "proc-a",
            "event_sequence": 2,
            "wall_unix_ns": 2000,
            "delta_event_id": 11,
            "event_id": "event-11",
            "operation_id": None,
            "attempts": None,
            "outcome": "pending",
            "durable": True,
        },
        {
            "event": "claim_committed",
            "process_observation_id": "proc-a",
            "event_sequence": 3,
            "wall_unix_ns": 3000,
            "delta_event_id": 11,
            "event_id": "event-11",
            "operation_id": "op-11",
            "attempts": 2,
            "outcome": "leased",
            "durable": True,
        },
        {
            "event": "publish_committed",
            "process_observation_id": "proc-a",
            "event_sequence": 4,
            "wall_unix_ns": 4000,
            "delta_event_id": 11,
            "event_id": "event-11",
            "operation_id": None,
            "attempts": None,
            "outcome": "succeeded",
            "durable": True,
        },
    ]


def as_e4_json_line(
    *,
    node: str,
    sequence: int,
    event_name: str = "pool_connection_precondition",
    **fields: Any,
) -> str:
    payload: Dict[str, Any] = {
        "event": event_name,
        "process_observation_id": "proc-" + node,
        "event_sequence": sequence,
        "wall_unix_ns": sequence * 1000,
        "message": "e4 deployment precondition observation",
    }
    payload.update(fields)
    return json.dumps({"target": "authz_e4", "fields": payload})


def e4_connection_line(node: str, sequence: int, **overrides: Any) -> str:
    fields: Dict[str, Any] = {
        "connection_id": sequence,
        "server_identity_sha256": "b" * 64,
        "primary_route": True,
        "session_isolation": "REPEATABLE-READ",
        "session_time_zone": "+00:00",
        "wall_start_ns": sequence * 1000 + 1000,
        "wall_end_ns": sequence * 1000 + 3000,
        "db_utc_unix_ns": sequence * 1000 + 2000,
        "offset_lower_ns": -1000,
        "offset_upper_ns": 1000,
        "db_clock_inside_call_interval": True,
    }
    fields.update(overrides)
    return as_e4_json_line(node=node, sequence=sequence, **fields)


class E4RuntimePreconditionTest(unittest.TestCase):
    def parse_happy(self) -> List[common.E4Event]:
        parsed: List[common.E4Event] = []
        for index, node in enumerate(("node-a", "node-b", "node-c"), 1):
            parsed.extend(common.parse_e4_events([e4_connection_line(node, index)], node=node))
        parsed.extend(
            common.parse_e4_events(
                [
                    as_e4_json_line(
                        node="node-b",
                        sequence=10,
                        event_name="cache_epoch_observed",
                        epoch_sha256="c" * 64,
                        source="existing",
                    )
                ],
                node="node-b",
            )
        )
        return parsed

    def test_three_node_runtime_preconditions_pass_with_rotation_journal(self) -> None:
        report = common.validate_e4_runtime_preconditions(
            self.parse_happy(),
            ("node-a", "node-b", "node-c"),
            rotation_journal_present=True,
            expected_pool_connections={"node-a": 1, "node-b": 1, "node-c": 1},
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["connectionsObserved"], 3)
        self.assertEqual(report["epochHashes"], ["c" * 64])

    def test_missing_node_or_rotation_journal_is_blocked(self) -> None:
        events = self.parse_happy()
        events = [event for event in events if event.node != "node-c"]
        report = common.validate_e4_runtime_preconditions(
            events,
            ("node-a", "node-b", "node-c"),
            rotation_journal_present=False,
            expected_pool_connections={"node-a": 1, "node-b": 1, "node-c": 1},
        )
        self.assertEqual(report["status"], "BLOCKED")
        self.assertIn("node-c:no_pool_connection_observation", report["blocked"])
        self.assertIn("cache_epoch_rotation_reason_unproven", report["blocked"])

    def test_non_primary_bad_clock_or_session_contract_fails(self) -> None:
        events = self.parse_happy()
        bad = common.parse_e4_events(
            [
                e4_connection_line(
                    "node-a",
                    20,
                    primary_route=False,
                    session_time_zone="SYSTEM",
                    session_isolation="UNKNOWN",
                    wall_start_ns=20_000,
                    wall_end_ns=1_000_020_000,
                    db_utc_unix_ns=4_000_020_000,
                    db_clock_inside_call_interval=False,
                    offset_lower_ns=3_000_000_000,
                    offset_upper_ns=4_000_000_000,
                )
            ],
            node="node-a",
        )
        report = common.validate_e4_runtime_preconditions(
            events + bad,
            ("node-a", "node-b", "node-c"),
            rotation_journal_present=True,
            expected_pool_connections={"node-a": 2, "node-b": 1, "node-c": 1},
        )
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(report["failures"])

    def test_epoch_change_without_journal_is_blocked(self) -> None:
        events = self.parse_happy()
        events.extend(
            common.parse_e4_events(
                [
                    as_e4_json_line(
                        node="node-b",
                        sequence=11,
                        event_name="cache_epoch_observed",
                        epoch_sha256="d" * 64,
                        source="created_set_nx",
                    )
                ],
                node="node-b",
            )
        )
        report = common.validate_e4_runtime_preconditions(
            events,
            ("node-a", "node-b", "node-c"),
            rotation_journal_present=False,
        )
        self.assertEqual(report["status"], "BLOCKED")
        self.assertIn("cache_epoch_changed_without_rotation_journal", report["blocked"])

    def test_missing_pool_inventory_or_clock_interval_is_not_pass(self) -> None:
        without_inventory = common.validate_e4_runtime_preconditions(
            self.parse_happy(),
            ("node-a", "node-b", "node-c"),
            rotation_journal_present=True,
        )
        self.assertEqual(without_inventory["status"], "BLOCKED")
        self.assertIn("node-a:pool_connection_inventory_missing", without_inventory["blocked"])

        broken = common.parse_e4_events(
            [e4_connection_line("node-a", 1, offset_lower_ns=0)], node="node-a"
        )
        report = common.validate_e4_runtime_preconditions(
            broken,
            ("node-a",),
            rotation_journal_present=True,
            expected_pool_connections={"node-a": 1},
        )
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertIn("node-a:1:invalid_clock_interval_evidence", report["unknown"])

    def test_multiple_server_identities_need_a_route_journal(self) -> None:
        events = self.parse_happy()
        events.extend(
            common.parse_e4_events(
                [e4_connection_line("node-a", 20, server_identity_sha256="d" * 64)],
                node="node-a",
            )
        )
        report = common.validate_e4_runtime_preconditions(
            events,
            ("node-a", "node-b", "node-c"),
            rotation_journal_present=True,
            expected_pool_connections={"node-a": 2, "node-b": 1, "node-c": 1},
        )
        self.assertEqual(report["status"], "BLOCKED")
        self.assertIn("node-a:mixed_server_identity_without_route_journal", report["blocked"])

    def test_parser_and_validator_reject_malformed_inputs(self) -> None:
        with self.assertRaises(common.EvidenceError):
            common.parse_e4_events(
                [as_e4_json_line(node="node-a", sequence=1, event_name="unknown")],
                node="node-a",
            )
        with self.assertRaises(common.EvidenceError):
            common.validate_e4_runtime_preconditions([], (), rotation_journal_present=False)
        with self.assertRaises(common.EvidenceError):
            common.validate_e4_runtime_preconditions(
                [], ("node-a",), clock_skew_threshold_ns=-1
            )


class E3HistoryTest(unittest.TestCase):
    def test_attempt_history_accepts_durable_retry_then_publish(self) -> None:
        parsed = common.parse_e3_events(as_e3_json_lines(e3_fixture_events()), node="node-a")
        report = common.validate_e3_attempt_history(
            parsed,
            {"event-11": {"status": "SUCCEEDED", "attempts": 2}},
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["attempts"], 2)
        self.assertEqual(report["perEvent"]["11"]["lastAttempt"], 2)

    def test_pending_retry_is_not_pass_and_unknown_terminal_is_preserved(self) -> None:
        pending = e3_fixture_events()[:2]
        parsed = common.parse_e3_events(as_e3_json_lines(pending), node="node-a")
        report = common.validate_e3_attempt_history(parsed)
        self.assertEqual(report["status"], "PENDING")

        unknown = [dict(item) for item in e3_fixture_events()[:1]]
        unknown.append(
            {
                "event": "terminal_unknown",
                "process_observation_id": "proc-a",
                "event_sequence": 2,
                "wall_unix_ns": 2000,
                "delta_event_id": 11,
                "event_id": "event-11",
                "operation_id": "op-11",
                "attempts": 1,
                "outcome": "publish_ack_unknown",
                "durable": False,
            }
        )
        report = common.validate_e3_attempt_history(
            common.parse_e3_events(as_e3_json_lines(unknown), node="node-a")
        )
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertTrue(report["unknown"])

    def test_missing_claim_or_attempt_regression_is_unknown(self) -> None:
        missing = [item for item in e3_fixture_events() if item["event"] != "claim_committed"]
        report = common.validate_e3_attempt_history(
            common.parse_e3_events(as_e3_json_lines(missing), node="node-a")
        )
        self.assertEqual(report["status"], "UNKNOWN")

        regression = e3_fixture_events()
        regression[2] = dict(regression[2], attempts=1)
        report = common.validate_e3_attempt_history(
            common.parse_e3_events(as_e3_json_lines(regression), node="node-a")
        )
        self.assertEqual(report["status"], "UNKNOWN")

    def test_process_restart_pairs_each_attempt_inside_its_own_epoch(self) -> None:
        restarted = [dict(item) for item in e3_fixture_events()]
        restarted[0]["process_observation_id"] = "proc-z"
        restarted[1]["process_observation_id"] = "proc-z"
        restarted[2]["process_observation_id"] = "proc-a"
        restarted[2]["event_sequence"] = 1
        restarted[3]["process_observation_id"] = "proc-a"
        restarted[3]["event_sequence"] = 2
        report = common.validate_e3_attempt_history(
            common.parse_e3_events(as_e3_json_lines(restarted), node="node-a"),
            {"event-11": {"status": "SUCCEEDED", "attempts": 2}},
        )
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["perEvent"]["11"]["pairedAttempts"], [1, 2])

    def test_terminal_cannot_close_a_claim_from_another_process(self) -> None:
        split = [dict(item) for item in e3_fixture_events()[:2]]
        split[1]["process_observation_id"] = "proc-b"
        split[1]["event_sequence"] = 1
        report = common.validate_e3_attempt_history(
            common.parse_e3_events(as_e3_json_lines(split), node="node-a")
        )
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertTrue(any("without_open_claim" in item for item in report["unknown"]))
        self.assertTrue(any("claim_without_terminal" in item for item in report["unknown"]))

    def test_attempt_gap_and_terminal_identity_drift_are_unknown(self) -> None:
        gap = [dict(item) for item in e3_fixture_events()]
        gap[2]["attempts"] = 3
        report = common.validate_e3_attempt_history(
            common.parse_e3_events(as_e3_json_lines(gap), node="node-a")
        )
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertTrue(any("attempt_history_gap" in item for item in report["unknown"]))

        drift = [dict(item) for item in e3_fixture_events()[:2]]
        drift[1]["event_id"] = "event-other"
        report = common.validate_e3_attempt_history(
            common.parse_e3_events(as_e3_json_lines(drift), node="node-a")
        )
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertTrue(any("event_identity_drift" in item for item in report["unknown"]))

    def test_earlier_unknown_attempt_cannot_be_hidden_by_later_publish(self) -> None:
        history = [dict(item) for item in e3_fixture_events()]
        history[1] = dict(
            history[1], event="terminal_unknown", outcome="backoff_cas_unknown", durable=False
        )
        report = common.validate_e3_attempt_history(
            common.parse_e3_events(as_e3_json_lines(history), node="node-a"),
            {"event-11": {"status": "SUCCEEDED", "attempts": 2}},
        )
        self.assertEqual(report["status"], "UNKNOWN")
        self.assertTrue(any("attempt_1:outcome_unknown" in item for item in report["unknown"]))

        clean = common.parse_e3_events(as_e3_json_lines(e3_fixture_events()), node="node-a")
        malformed = common.validate_e3_attempt_history(
            clean, {"event-11": {"status": "SUCCEEDED", "attempts": "invalid"}}
        )
        self.assertEqual(malformed["status"], "UNKNOWN")

    def test_parser_rejects_unknown_event_and_duplicate_process_sequence(self) -> None:
        bad = dict(e3_fixture_events()[0], event="not-an-event")
        with self.assertRaises(common.EvidenceError):
            common.parse_e3_events(as_e3_json_lines([bad]), node="node-a")
        duplicate = e3_fixture_events()[:2]
        duplicate[1] = dict(duplicate[1], event_sequence=1)
        with self.assertRaises(common.EvidenceError):
            common.parse_e3_events(as_e3_json_lines(duplicate), node="node-a")


class SequenceIntervalTest(unittest.TestCase):
    def test_interval_relations_are_strict(self) -> None:
        first = common.SequenceInterval(1, 2)
        second = common.SequenceInterval(3, 4)
        touching = common.SequenceInterval(2, 3)
        self.assertTrue(first.before(second))
        self.assertFalse(first.overlaps(second))
        self.assertTrue(first.overlaps(touching))

    def test_invalid_interval_is_rejected(self) -> None:
        for start, end in ((0, 1), (2, 1)):
            with self.subTest(start=start, end=end), self.assertRaises(common.EvidenceError):
                common.SequenceInterval(start, end)


class ConfigAndArtifactTest(unittest.TestCase):
    def valid_config(self) -> Dict[str, Any]:
        digest = "b" * 64
        return {
            "run_id": "us27-e1-001",
            "nodes": {"node-a": "private-a", "node-b": "private-b", "node-c": "private-c"},
            "ssh": {},
            "base_dir": "private",
            "db": "private",
            "mysql_container": "private",
            "redis_container": "private",
            "hmac_secret_file": "private",
            "binary_sha256": digest,
            "source_snapshot_sha256": digest,
            "source_git_rev": "c" * 40,
            "source_dirty_patch_sha256": digest,
            "bootstrap_bin_sha256": digest,
        }

    def test_config_validation_and_public_provenance(self) -> None:
        config = self.valid_config()
        self.assertEqual(common.validate_run_config_shape(config), [])
        public = common.public_provenance(config)
        self.assertEqual(public["nodeLabels"], ["node-a", "node-b", "node-c"])
        rendered = json.dumps(public)
        self.assertNotIn("private-a", rendered)
        self.assertNotIn("hmac", rendered.lower())

    def test_config_rejects_missing_nodes_and_bad_hash(self) -> None:
        config = self.valid_config()
        config["nodes"] = {"node-a": "x"}
        config["binary_sha256"] = "not-a-hash"
        problems = common.validate_run_config_shape(config)
        self.assertIn("invalid:nodes", problems)
        self.assertIn("invalid:binary_sha256", problems)

    def test_stable_id_is_deterministic_and_validated(self) -> None:
        self.assertEqual(common.stable_id("run-1", "reader-1"), common.stable_id("run-1", "reader-1"))
        self.assertNotEqual(common.stable_id("run-1", "reader-1"), common.stable_id("run-1", "reader-2"))
        with self.assertRaises(common.EvidenceError):
            common.stable_id("bad id", "reader")

    def test_atomic_json_and_checksums_use_lf_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = root / "nested" / "record.json"
            common.atomic_json(document, {"status": "PASS"})
            self.assertTrue(document.read_bytes().endswith(b"\n"))
            checksum = common.write_checksums(root, [document])
            self.assertNotIn(b"\r\n", checksum.read_bytes())
            common.verify_checksums(root, checksum)
            document.write_text("changed\n", encoding="utf-8")
            with self.assertRaises(common.EvidenceError):
                common.verify_checksums(root, checksum)

    def test_checksum_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checksum = root / "checksums.sha256"
            checksum.write_text(f"{'a' * 64}  ../escape\n", encoding="utf-8")
            with self.assertRaises(common.EvidenceError):
                common.verify_checksums(root, checksum)


class EventParsingTest(unittest.TestCase):
    def test_parser_flattens_filters_sorts_and_selects_request(self) -> None:
        source = [
            "not json",
            json.dumps({"fields": {"message": "unrelated"}}),
            *reversed(as_json_lines([event(1, "first"), event(2, "second")])),
        ]
        parsed = common.parse_authz_events(source, node="node-a")
        self.assertEqual([item.event for item in parsed], ["first", "second"])
        self.assertEqual(len(common.events_for_request(parsed, "req-reader")), 2)
        self.assertEqual(common.events_for_request(parsed, "missing"), [])

    def test_parser_rejects_missing_request_and_duplicate_sequence(self) -> None:
        missing = json.dumps(
            {
                "fields": {
                    "message": "e1 authorization observation",
                    "event": "x",
                    "request_id": "",
                    "event_sequence": 1,
                    "wall_unix_ns": 1,
                    "process_observation_id": "proc-a",
                }
            }
        )
        with self.assertRaises(common.EvidenceError):
            common.parse_authz_events([missing], node="node-a")
        duplicated = as_json_lines([event(1, "x"), event(1, "y")])
        with self.assertRaises(common.EvidenceError):
            common.parse_authz_events(duplicated, node="node-a")

    def test_parser_requires_valid_process_observation_id(self) -> None:
        absent = json.dumps(
            {
                "fields": {
                    "message": "e1 authorization observation",
                    "event": "x",
                    "request_id": "req-reader",
                    "event_sequence": 1,
                    "wall_unix_ns": 1,
                }
            }
        )
        with self.assertRaises(common.EvidenceError):
            common.parse_authz_events([absent], node="node-a")
        empty = as_json_lines([event(1, "x", process_observation_id="")])
        with self.assertRaises(common.EvidenceError):
            common.parse_authz_events(empty, node="node-a")
        unsafe = as_json_lines([event(1, "x", process_observation_id="bad id!")])
        with self.assertRaises(common.EvidenceError):
            common.parse_authz_events(unsafe, node="node-a")

    def test_parser_duplicate_sequence_is_scoped_to_one_process_epoch(self) -> None:
        # A restart starts a new epoch: the same process-local sequence value
        # reappears, and that is legal. Only one epoch must refuse duplicates.
        restarted = as_json_lines(
            [
                event(1, "signed_context_bound", process_observation_id="proc-old"),
                event(1, "signed_context_bound", process_observation_id="proc-new"),
                event(2, "decision_return", process_observation_id="proc-old"),
                event(2, "decision_return", process_observation_id="proc-new"),
            ]
        )
        parsed = common.parse_authz_events(restarted, node="node-a")
        self.assertEqual(len(parsed), 4)
        self.assertEqual(
            [item.process_observation_id for item in parsed],
            ["proc-new", "proc-new", "proc-old", "proc-old"],
        )


class FinalObservationTest(unittest.TestCase):
    def test_strict_final_observation_uses_initial_pending_probe(self) -> None:
        interval, source = common.final_observation_interval(strict_request())
        self.assertEqual(source, "strict_db")
        self.assertEqual(interval, common.SequenceInterval(10, 20))

    def test_cache_final_observation_requires_full_bracket_and_returns_m0(self) -> None:
        interval, source = common.final_observation_interval(cache_request())
        self.assertEqual(source, "l1_cache")
        self.assertEqual(interval, common.SequenceInterval(4, 5))

    def test_cache_missing_second_observation_is_rejected(self) -> None:
        events = [item for item in cache_request() if item.sequence not in {8, 9}]
        with self.assertRaises(common.EvidenceError):
            common.final_observation_interval(events)

    def test_cache_misordered_bracket_is_rejected(self) -> None:
        events = cache_request()
        events = [
            event(5 if item.sequence == 6 else 6 if item.sequence == 5 else item.sequence, item.event, **{
                key: value
                for key, value in item.fields.items()
                if key not in {"event", "request_id", "event_sequence", "wall_unix_ns"}
            })
            if item.sequence in {5, 6}
            else item
            for item in events
        ]
        with self.assertRaises(common.EvidenceError):
            common.final_observation_interval(events)

    def test_pending_true_or_failed_observation_is_rejected(self) -> None:
        cache_events = cache_request()
        pending = cache_events[6]
        cache_events[6] = event(
            pending.sequence,
            pending.event,
            observation="cache_pending_probe",
            outcome="ok",
            pending="Some(true)",
        )
        with self.assertRaises(common.EvidenceError):
            common.final_observation_interval(cache_events)

        strict_events = strict_request()
        ending = strict_events[4]
        strict_events[4] = event(
            ending.sequence,
            ending.event,
            observation="strict_pending_probe",
            outcome="error",
            pending=None,
        )
        with self.assertRaises(common.EvidenceError):
            common.final_observation_interval(strict_events)


class E1ClassificationTest(unittest.TestCase):
    def test_post_commit_before_final_observation_is_theorem_violation(self) -> None:
        result = common.classify_e1_allow(strict_request(), commit_events(5, 6))
        self.assertEqual(result["category"], "post-commit-before-final-observation")
        self.assertTrue(result["theoremDomain"])
        self.assertTrue(result["staleAllowViolation"])

    def test_pre_commit_and_post_observation_are_outside_theorem_domain(self) -> None:
        pre = common.classify_e1_allow(strict_request(), commit_events(50, 51))
        post = common.classify_e1_allow(strict_request(), commit_events(22, 23))
        self.assertEqual(pre["category"], "pre-commit")
        self.assertEqual(post["category"], "post-final-observation-overlap")
        self.assertFalse(pre["staleAllowViolation"])
        self.assertFalse(post["staleAllowViolation"])

    def test_overlapping_commit_interval_stays_unknown_subclass(self) -> None:
        result = common.classify_e1_allow(strict_request(), commit_events(15, 25))
        self.assertEqual(result["category"], "interval-overlap-unknown")
        self.assertFalse(result["theoremDomain"])
        self.assertFalse(result["staleAllowViolation"])

    def test_unknown_commit_cross_process_and_duplicate_sequences_are_rejected(self) -> None:
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(strict_request(), commit_events(5, 6, outcome="unknown"))
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(strict_request(), commit_events(5, 6, node="node-b"))
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(strict_request(), commit_events(10, 11))

    def test_cross_epoch_mutation_is_rejected_even_with_unique_sequences(self) -> None:
        # Same node, every event_sequence unique, but the mutation happened in a
        # different process epoch than the request: process-local sequences are
        # not comparable, so the evidence must be refused outright.
        request = strict_request()
        mutation = commit_events(5, 6, process_observation_id="proc-b")
        sequences = [item.sequence for item in request + mutation]
        self.assertEqual(len(sequences), len(set(sequences)))
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(request, mutation)

    def test_cross_epoch_within_request_events_is_rejected(self) -> None:
        # A restart in the middle of one request also spans two epochs.
        restarted = strict_request()
        restarted[0] = event(1, "signed_context_bound", process_observation_id="proc-old")
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(restarted, commit_events(50, 51))

    def test_missing_epoch_is_rejected(self) -> None:
        epochless_request = strict_request()
        epochless_request[0] = event(1, "signed_context_bound", process_observation_id="")
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(epochless_request, commit_events(5, 6))
        epochless_mutation = commit_events(5, 6, process_observation_id="")
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(strict_request(), epochless_mutation)

    def test_commit_interval_spanning_epochs_is_refused(self) -> None:
        split = [
            event(5, "source_commit_start", request_id="req-mutation", operation_id="op-e1"),
            event(
                6,
                "source_commit_end",
                request_id="req-mutation",
                operation_id="op-e1",
                outcome="committed",
                process_observation_id="proc-b",
            ),
        ]
        with self.assertRaises(common.EvidenceError):
            common.mutation_commit_interval(split)

    def test_identity_drift_and_unstable_recheck_are_rejected(self) -> None:
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(
                strict_request(identity_override={"grant_revision": 5}), commit_events(5, 6)
            )
        with self.assertRaises(common.EvidenceError):
            common.classify_e1_allow(strict_request(stable=False), commit_events(5, 6))


class TerminalDecisionTest(unittest.TestCase):
    def test_allow_requires_host_admission(self) -> None:
        allowed = [event(1, "decision_return", allowed=True, reason="ok"), event(2, "host_admission")]
        self.assertEqual(common.validate_request_terminal(allowed, 200)["decision"], "ALLOW")
        with self.assertRaises(common.EvidenceError):
            common.validate_request_terminal(allowed[:1], 200)

    def test_pending_deny_and_unknown_are_distinct(self) -> None:
        pending = [event(1, "decision_return", allowed=False, reason="AUTHORIZATION_PENDING")]
        denied = [event(1, "decision_return", allowed=False, reason="DEFAULT_DENY")]
        unavailable = [event(1, "decision_return", allowed=False, reason="SOD_UNAVAILABLE")]
        self.assertEqual(common.validate_request_terminal(pending, 503)["decision"], "PENDING")
        self.assertEqual(common.validate_request_terminal(denied, 403)["decision"], "DENY")
        self.assertEqual(common.validate_request_terminal(unavailable, 503)["decision"], "UNKNOWN")


class E5DomainCorrespondenceTest(unittest.TestCase):
    """Lock the E1 runtime classifier to the E5 abstract domain vocabulary.

    E5 is the abstract bounded model of the same observation protocol the E1
    classifier consumes. A rename or boundary change on either side must fail
    here and force an explicit sync, so validation never reports one vocabulary
    while the evidence uses another.
    """

    def test_classifier_categories_correspond_to_e5_domains(self) -> None:
        import e5_model_check

        obs_interval, _source = common.final_observation_interval(strict_request())
        obs_pair = (obs_interval.start, obs_interval.end)

        # durable commit strictly before t_f: E5 theorem domain == E1 violation.
        before_pair = (obs_interval.start - 5, obs_interval.start - 1)
        before = commit_events(*before_pair)
        self.assertEqual(
            common.classify_e1_allow(strict_request(), before)["category"],
            "post-commit-before-final-observation",
        )
        self.assertEqual(
            common.classify_e1_allow(strict_request(), before)["staleAllowViolation"],
            True,
        )
        self.assertEqual(
            e5_model_check.classify_domain(before_pair, obs_pair),
            "strictly_before",
        )

        # commit interval spanning the final observation: UNKNOWN on both sides.
        spanning_pair = (obs_interval.start - 3, obs_interval.end + 3)
        spanning = commit_events(*spanning_pair)
        self.assertEqual(
            common.classify_e1_allow(strict_request(), spanning)["category"],
            "interval-overlap-unknown",
        )
        self.assertEqual(
            e5_model_check.classify_domain(spanning_pair, obs_pair),
            "overlap_unknown",
        )

        # commit beginning strictly after the final observation: out of domain.
        after_pair = (obs_interval.end + 2, obs_interval.end + 3)
        after = commit_events(*after_pair)
        self.assertEqual(
            common.classify_e1_allow(strict_request(), after)["category"],
            "post-final-observation-overlap",
        )
        self.assertEqual(
            e5_model_check.classify_domain(after_pair, obs_pair),
            "after_final_observation",
        )

        # admission before the commit ever begins: E1 pre-commit == the commit
        # is invisible at admission (E5's not_stale / after-domain boundary).
        late = commit_events(100, 101)
        self.assertEqual(
            common.classify_e1_allow(strict_request(), late)["category"],
            "pre-commit",
        )
        self.assertEqual(
            e5_model_check.classify_domain((100, 101), obs_pair),
            "after_final_observation",
        )
        # No durable commit at admission is E5's not_stale; E1's analogous
        # refusal (no orderable evidence) is unclassified-unknown, never a
        # stale/non-stale verdict.
        self.assertEqual(e5_model_check.classify_domain(None, obs_pair), "not_stale")


    def test_non_200_must_not_cross_host_admission(self) -> None:
        events = [
            event(1, "decision_return", allowed=False, reason="DEFAULT_DENY"),
            event(2, "host_admission"),
        ]
        with self.assertRaises(common.EvidenceError):
            common.validate_request_terminal(events, 403)

    def test_status_vocabulary_is_closed(self) -> None:
        for value in common.ALLOWED_STATUSES:
            self.assertEqual(common.status(value), value)
        with self.assertRaises(common.EvidenceError):
            common.status("SUCCESS")

    def test_required_parser_and_validator_symbols_remain_callable(self) -> None:
        for name in (
            "parse_authz_events",
            "parse_e3_events",
            "validate_e3_attempt_history",
            "parse_e4_events",
            "validate_e4_runtime_preconditions",
            "events_for_request",
        ):
            self.assertTrue(callable(getattr(common, name, None)), name)


if __name__ == "__main__":
    unittest.main()
