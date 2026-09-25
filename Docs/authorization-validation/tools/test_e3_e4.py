#!/usr/bin/env python3
"""Offline unit tests for tools/e3_e4.py.

Every test uses in-memory fake probes. No database, Redis, HTTP service,
network, or filesystem resource is touched. The suite verifies:

- the read-only probe contract (Protocol conformance, SELECT-only SQL,
  Redis verb allowlist),
- the actor-aware probe contract: per-card signed decisions require
  ``signed_get_for_role(role, card, node, path)`` returning
  ``(http_status, body, request_id)`` with the exact card binding and a safe
  request id; a probe without the capability is BLOCKED, never PASS,
- capture_e4_preconditions statuses (PASS / FAIL / BLOCKED / UNKNOWN / SKIP),
- sample_e3 fixed-interval behavior, decision classification, stop handling,
  and the always-present snapshot-only limitations (E3 never claimed),
- evaluate_fault_outcomes purity and fail-closed validation (ALLOW and
  UNKNOWN/absent outcomes are rejected),
- the no-host/no-secret scrubbing guarantee on returned data.
"""

from __future__ import annotations

import copy
import io
import json
import contextlib
import re
import sys
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import e3_e4  # noqa: E402

E4_KEY = e3_e4.DEFAULT_CACHE_EPOCH_KEY
DECISION_PATH = "/main/api/v1/permission-rules"
UTC_EPOCH = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc).timestamp()


class FakeProbe:
    """In-memory read-only probe; raises if used outside the read-only contract.

    ``signed_get_for_role`` enforces the actor-aware contract: the path must
    carry the percent-encoded card in both the ``cardId`` and ``card_id``
    parameters (exact card binding), and request ids are generated per call in
    the safe bounded format the module validates. ``request_id_override`` and
    3-tuple role responses let tests inject malformed or hostile ids, which the
    module must reject or scrub, never store verbatim.
    """

    def __init__(
        self,
        *,
        sql_rows: Optional[Dict[str, List[List[str]]]] = None,
        redis_values: Optional[Dict[Any, str]] = None,
        responses: Any = None,
        sql_error: Optional[Exception] = None,
        redis_error: Optional[Exception] = None,
        http_error: Optional[Exception] = None,
        clock: float = UTC_EPOCH,
        request_id_override: Optional[str] = None,
    ) -> None:
        self.sql_rows = sql_rows if sql_rows is not None else {}
        self.redis_values = redis_values if redis_values is not None else {}
        self.responses = responses if responses is not None else {}
        self.sql_error = sql_error
        self.redis_error = redis_error
        self.http_error = http_error
        self.clock_value = clock
        self.request_id_override = request_id_override
        self.sql_queries: List[str] = []
        self.redis_commands: List[Tuple[str, ...]] = []
        self.http_requests: List[Tuple[str, str]] = []
        self.role_requests: List[Tuple[str, str, str, str]] = []
        self.request_id_seq = 0
        self.clock_samples = 0

    def sql(self, query: str) -> List[List[str]]:
        if self.sql_error is not None:
            raise self.sql_error
        self.sql_queries.append(query)
        if query in self.sql_rows:
            return self.sql_rows[query]
        return []

    def redis(self, *argv: str) -> str:
        verb = argv[0] if argv else ""
        if verb not in e3_e4.READONLY_REDIS_VERBS:
            raise AssertionError(f"non-read-only redis verb attempted: {verb}")
        self.redis_commands.append(tuple(argv))
        if self.redis_error is not None:
            raise self.redis_error
        key = argv[1] if len(argv) > 1 else ""
        return self.redis_values.get((verb, key), self.redis_values.get(verb, ""))

    def signed_get(self, node: str, path: str) -> Tuple[int, Dict[str, Any]]:
        if self.http_error is not None:
            raise self.http_error
        self.http_requests.append((node, path))
        if callable(self.responses):
            return self.responses(node, path)
        if path in self.responses:
            return self.responses[path]
        return 404, {}

    def signed_get_for_role(
        self, role: str, card: str, node: str, path: str
    ) -> Tuple[int, Dict[str, Any], str]:
        if self.http_error is not None:
            raise self.http_error
        self.role_requests.append((role, card, node, path))
        encoded = e3_e4._percent_encode(card)
        if f"cardId={encoded}" not in path or f"card_id={encoded}" not in path:
            raise ValueError(f"card binding mismatch: path does not carry card for role {role}")
        self.request_id_seq += 1
        if callable(self.responses):
            result = self.responses(node, path)
        elif isinstance(self.responses, dict):
            result = self.responses.get(card, (404, {}))
        else:
            result = (404, {})
        if isinstance(result, tuple) and len(result) == 2:
            request_id = (
                self.request_id_override
                if self.request_id_override is not None
                else f"req-{self.request_id_seq:04d}"
            )
            return result[0], result[1], request_id
        if isinstance(result, tuple) and len(result) == 3:
            return result
        raise ValueError("role response shape invalid")

    def clock_sample(self) -> float:
        self.clock_samples += 1
        return self.clock_value


class SqlOnlyProbe:
    """Probe without redis capability (used for BLOCKED coverage).

    Answers every scalar with "1" except UTC_TIMESTAMP(), which returns a
    parseable UTC timestamp so the clock-offset check can be exercised.
    """

    def __init__(self, clock: float = UTC_EPOCH, utc_now: str = "2026-09-19 12:00:00") -> None:
        self.clock_value = clock
        self.utc_now = utc_now
        self.sql_queries: List[str] = []
        self.http_requests: List[Tuple[str, str]] = []

    def sql(self, query: str) -> List[List[str]]:
        self.sql_queries.append(query)
        if query == "SELECT UTC_TIMESTAMP()":
            return [[self.utc_now]]
        return [["1"]]

    def signed_get(self, node: str, path: str) -> Tuple[int, Dict[str, Any]]:
        self.http_requests.append((node, path))
        return 200, {"allowed": True}

    def clock_sample(self) -> float:
        return self.clock_value


class LegacySignedGetProbe:
    """Probe with only the legacy ``signed_get`` surface.

    Deliberately implements no ``signed_get_for_role``: per-card decisions must
    be reported BLOCKED (never silently downgraded to the legacy method), while
    SQL/Redis reads and legacy worker health keep working.
    """

    def __init__(self) -> None:
        self.http_requests: List[Tuple[str, str]] = []

    def sql(self, query: str) -> List[List[str]]:
        return [["1"]]

    def redis(self, *argv: str) -> str:
        if argv[0] not in e3_e4.READONLY_REDIS_VERBS:
            raise AssertionError(f"non-read-only redis verb attempted: {argv[0]}")
        return "PONG" if argv[0] == "PING" else ""

    def signed_get(self, node: str, path: str) -> Tuple[int, Dict[str, Any]]:
        self.http_requests.append((node, path))
        return 200, {}


E4_ROWS = {
    "SELECT @@global.transaction_isolation": [["REPEATABLE-READ"]],
    "SELECT @@global.read_only": [["0"]],
    "SELECT @@global.super_read_only": [["0"]],
    "SELECT @@session.time_zone": [["+00:00"]],
    "SELECT UTC_TIMESTAMP()": [["2026-09-19 12:00:00"]],
}


def e3_config(**overrides: Any) -> e3_e4.E3SampleConfig:
    defaults: Dict[str, Any] = {
        "row_queries": (("delta_event_rows", "SELECT COUNT(*) FROM authorization_delta_event"),),
        "pointer_keys": (E4_KEY,),
        "redis_queue_keys": ("astral.test.queue",),
        "decision_path": DECISION_PATH,
        "worker_health_path": None,
    }
    defaults.update(overrides)
    return e3_e4.E3SampleConfig(**defaults)


def decision_responses(node: str, path: str) -> Tuple[int, Dict[str, Any]]:
    if "cardId=card-target" in path:
        return 403, {"allowed": False, "reason": "AUTHORIZATION_PENDING"}
    if "cardId=card-unrelated" in path:
        return 200, {"allowed": True, "generation": "gen-7", "reason": "ok"}
    if "cardId=card-cold" in path:
        return 503, {}
    return 404, {}


def happy_redis() -> Dict[Any, str]:
    return {
        ("LLEN", "astral.test.queue"): "2",
        ("GET", E4_KEY): "550e8400-e29b-41d4-a716-446655440000",
        "PING": "PONG",
    }


class ProtocolConformanceTest(unittest.TestCase):
    def test_fake_probe_satisfies_read_only_probe(self) -> None:
        self.assertIsInstance(FakeProbe(), e3_e4.ReadOnlyProbe)
        self.assertIsInstance(FakeProbe(), e3_e4.ClockSamplingProbe)

    def test_fake_probe_satisfies_actor_aware_probe(self) -> None:
        self.assertIsInstance(FakeProbe(), e3_e4.ActorAwareReadOnlyProbe)
        self.assertNotIsInstance(SqlOnlyProbe(), e3_e4.ActorAwareReadOnlyProbe)
        self.assertNotIsInstance(LegacySignedGetProbe(), e3_e4.ActorAwareReadOnlyProbe)
        # the legacy surface alone still satisfies the base protocol
        self.assertIsInstance(LegacySignedGetProbe(), e3_e4.ReadOnlyProbe)

    def test_probe_without_redis_does_not_satisfy_protocol(self) -> None:
        self.assertNotIsInstance(SqlOnlyProbe(), e3_e4.ReadOnlyProbe)

    def test_redis_verb_allowlist_is_read_only(self) -> None:
        self.assertEqual(e3_e4.READONLY_REDIS_VERBS, {"LLEN", "GET", "PING"})


class SelectOnlyGuardTest(unittest.TestCase):
    def test_accepts_select_statements(self) -> None:
        for query in (
            "SELECT 1",
            "/* lead */ SELECT 1",
            "  select 1;  ",
            "-- comment\nSELECT 1",
            "SELECT COUNT(*) FROM authorization_delta_event",
        ):
            self.assertEqual(e3_e4._require_select_only(query), query)

    def test_rejects_non_select_statements(self) -> None:
        for query in ("", "   ", "UPDATE t SET x=1", "SET x=1", "INSERT INTO t VALUES (1)", "DELETE FROM t"):
            with self.assertRaises(ValueError):
                e3_e4._require_select_only(query)

    def test_rejects_multiple_statements(self) -> None:
        with self.assertRaises(ValueError):
            e3_e4._require_select_only("SELECT 1; DROP TABLE t")
        with self.assertRaises(ValueError):
            e3_e4._require_select_only("SELECT 1;SELECT 2")


class CaptureE4PreconditionsTest(unittest.TestCase):
    def test_happy_path_all_checks_pass(self) -> None:
        probe = FakeProbe(sql_rows=dict(E4_ROWS), redis_values=happy_redis())
        report = e3_e4.capture_e4_preconditions(probe, ("writer-a",))
        self.assertEqual(report["kind"], "e4_preconditions")
        self.assertEqual(report["overall"], "PASS")
        self.assertEqual(report["node_count"], 1)
        node = report["nodes"][0]
        self.assertEqual(node["node_key"], "node-0")
        self.assertEqual(node["overall"], "PASS")
        for name in ("transaction_isolation", "read_only", "super_read_only", "session_time_zone", "utc_clock_offset"):
            self.assertEqual(node["checks"][name]["status"], "PASS", name)
        self.assertEqual(node["checks"]["utc_clock_offset"]["value"]["skew_s"], 0.0)
        self.assertEqual(report["cache_epoch"]["status"], "PASS")
        self.assertEqual(
            report["cache_epoch"]["value"],
            "550e8400-e29b-41d4-a716-446655440000",
        )
        for query in probe.sql_queries:
            self.assertTrue(query.strip().upper().startswith("SELECT"), query)
        self.assertTrue(all(argv[0] == "GET" for argv in probe.redis_commands))

    def test_node_aliases_never_stored_and_indexes_are_stable(self) -> None:
        probe = FakeProbe(sql_rows=dict(E4_ROWS), redis_values=happy_redis())
        report = e3_e4.capture_e4_preconditions(probe, ("n1", "n2"))
        blob = json.dumps(report)
        self.assertEqual([n["node_key"] for n in report["nodes"]], ["node-0", "node-1"])
        self.assertNotIn('"n1"', blob)
        self.assertNotIn('"n2"', blob)

    def test_isolation_fallback_for_mysql57(self) -> None:
        rows = {k: v for k, v in E4_ROWS.items() if k != "SELECT @@global.transaction_isolation"}
        rows["SELECT @@global.tx_isolation"] = [["REPEATABLE-READ"]]
        probe = FakeProbe(sql_rows=rows, redis_values=happy_redis())
        report = e3_e4.capture_e4_preconditions(probe, ("n",))
        check = report["nodes"][0]["checks"]["transaction_isolation"]
        self.assertEqual(check["status"], "PASS")
        self.assertEqual(check["query"], "SELECT @@global.tx_isolation")
        self.assertIn("SELECT @@global.transaction_isolation", probe.sql_queries)

    def test_sql_error_is_unknown_and_leaks_no_error_text(self) -> None:
        probe = FakeProbe(sql_rows=dict(E4_ROWS), sql_error=RuntimeError("connect failed db.example.invalid"))
        report = e3_e4.capture_e4_preconditions(probe, ("n",))
        self.assertEqual(report["overall"], "UNKNOWN")
        check = report["nodes"][0]["checks"]["read_only"]
        self.assertEqual(check["status"], "UNKNOWN")
        self.assertEqual(check["error_class"], "RuntimeError")
        blob = json.dumps(report)
        self.assertNotIn("db.example.invalid", blob)
        self.assertNotIn("connect failed", blob)

    def test_empty_and_ambiguous_results_are_unknown(self) -> None:
        empty_probe = FakeProbe(sql_rows={}, redis_values=happy_redis())
        report = e3_e4.capture_e4_preconditions(empty_probe, ("n",))
        self.assertEqual(report["nodes"][0]["checks"]["read_only"]["status"], "UNKNOWN")
        multi_probe = FakeProbe(
            sql_rows={**E4_ROWS, "SELECT @@global.read_only": [["0"], ["1"]]},
            redis_values=happy_redis(),
        )
        report = e3_e4.capture_e4_preconditions(multi_probe, ("n",))
        self.assertEqual(report["nodes"][0]["checks"]["read_only"]["status"], "UNKNOWN")

    def test_unrecognized_isolation_is_unknown(self) -> None:
        rows = {**E4_ROWS, "SELECT @@global.transaction_isolation": [["MAGIC-LEVEL"]]}
        probe = FakeProbe(sql_rows=rows, redis_values=happy_redis())
        report = e3_e4.capture_e4_preconditions(probe, ("n",))
        self.assertEqual(report["nodes"][0]["checks"]["transaction_isolation"]["status"], "UNKNOWN")

    def test_clock_skew_beyond_threshold_fails(self) -> None:
        probe = FakeProbe(sql_rows=dict(E4_ROWS), redis_values=happy_redis(), clock=UTC_EPOCH + 10.0)
        report = e3_e4.capture_e4_preconditions(probe, ("n",))
        check = report["nodes"][0]["checks"]["utc_clock_offset"]
        self.assertEqual(check["status"], "FAIL")
        self.assertEqual(report["overall"], "FAIL")
        self.assertGreater(abs(check["value"]["skew_s"]), report["assertions"]["clock_skew_threshold_s"])

    def test_fail_outranks_blocked_when_redis_capability_missing(self) -> None:
        probe = SqlOnlyProbe(clock=UTC_EPOCH + 10.0)
        report = e3_e4.capture_e4_preconditions(probe, ("n",))
        self.assertEqual(report["nodes"][0]["checks"]["utc_clock_offset"]["status"], "FAIL")
        self.assertEqual(report["cache_epoch"]["status"], "BLOCKED")
        self.assertEqual(report["overall"], "FAIL")

    def test_cache_epoch_variants(self) -> None:
        empty = FakeProbe(sql_rows=dict(E4_ROWS), redis_values={("GET", E4_KEY): ""})
        report = e3_e4.capture_e4_preconditions(empty, ("n",))
        self.assertEqual(report["cache_epoch"]["status"], "SKIP")

        error = FakeProbe(sql_rows=dict(E4_ROWS), redis_values={})
        error.redis_error = RuntimeError("down")
        report = e3_e4.capture_e4_preconditions(error, ("n",))
        self.assertEqual(report["cache_epoch"]["status"], "UNKNOWN")
        self.assertEqual(report["cache_epoch"]["error_class"], "RuntimeError")

        sql_only = SqlOnlyProbe()
        report = e3_e4.capture_e4_preconditions(sql_only, ("n",))
        self.assertEqual(report["cache_epoch"]["status"], "BLOCKED")

        via_sql = FakeProbe(sql_rows=dict(E4_ROWS), redis_values={})
        report = e3_e4.capture_e4_preconditions(
            via_sql, ("n",), cache_epoch_query="SELECT @@global.read_only"
        )
        self.assertEqual(report["cache_epoch"]["status"], "PASS")
        self.assertEqual(report["cache_epoch"]["value"], "0")

        with self.assertRaises(ValueError):
            e3_e4.capture_e4_preconditions(
                FakeProbe(sql_rows=dict(E4_ROWS)), ("n",), cache_epoch_query="DELETE FROM t"
            )

    def test_unproven_checks_never_yield_overall_pass(self) -> None:
        # SqlOnlyProbe answers scalars with "1": isolation is form-invalid
        # (UNKNOWN), skew is PASS via the explicit clock override, and the
        # cache epoch is BLOCKED (no redis capability). BLOCKED dominates
        # UNKNOWN in the worst-first aggregate; nothing collapses into PASS.
        report = e3_e4.capture_e4_preconditions(
            SqlOnlyProbe(), ("n",), clock=lambda: UTC_EPOCH
        )
        self.assertEqual(report["nodes"][0]["checks"]["transaction_isolation"]["status"], "UNKNOWN")
        self.assertEqual(report["cache_epoch"]["status"], "BLOCKED")
        self.assertEqual(report["overall"], "BLOCKED")

    def test_input_validation(self) -> None:
        with self.assertRaises(TypeError):
            e3_e4.capture_e4_preconditions(FakeProbe(), "not-a-list")
        with self.assertRaises(TypeError):
            e3_e4.capture_e4_preconditions(FakeProbe(), [""], clock=lambda: 0.0)

    def test_no_hosts_or_secrets_in_report(self) -> None:
        rows = {
            **E4_ROWS,
            "SELECT @@session.time_zone": [["db01.internal.example.com"]],
        }
        probe = FakeProbe(
            sql_rows=rows,
            redis_values={("GET", E4_KEY): "redis://cache.example.invalid:6380/0"},
        )
        report = e3_e4.capture_e4_preconditions(probe, ("node.example.invalid",))
        blob = json.dumps(report)
        for forbidden in ("node.example.invalid", "cache.example.invalid", "example.com", "db01.internal", "redis://"):
            self.assertNotIn(forbidden, blob)


class SampleE3Test(unittest.TestCase):
    def test_fixed_interval_happy_path(self) -> None:
        probe = FakeProbe(
            sql_rows={"SELECT COUNT(*) FROM authorization_delta_event": [["3"]]},
            redis_values=happy_redis(),
            responses=decision_responses,
        )
        summary = e3_e4.sample_e3(
            probe,
            "card-target",
            "card-unrelated",
            "card-cold",
            interval=0.02,
            duration=0.12,
            config=e3_config(),
            clock=lambda: 1000.5,
        )
        self.assertEqual(summary["kind"], "e3_sampling")
        self.assertEqual(summary["e3_evidence_claim"], "NOT_CLAIMED")
        self.assertTrue(summary["completed"])
        self.assertFalse(summary["stopped_early"])
        self.assertEqual(summary["scheduled_samples"], 6)
        self.assertGreaterEqual(summary["samples_collected"], 4)
        self.assertLessEqual(summary["samples_collected"], summary["scheduled_samples"])
        # The cold-card fixture answers with a plain 503, which is ambiguous by
        # design: worst-first aggregation must keep the overall UNKNOWN and
        # never promote an unclassifiable decision to PASS.
        self.assertEqual(summary["overall"], "UNKNOWN")
        self.assertIn("samples", summary)

        for sample in summary["samples"]:
            self.assertEqual(sample["probe_clock_epoch_s"], 1000.5)
            self.assertEqual(
                sample["queue_counts"]["entries"]["astral.test.queue"],
                {"status": "PASS", "value": 2},
            )
            self.assertEqual(
                sample["row_counts"]["entries"]["delta_event_rows"]["value"], 3
            )
            self.assertEqual(sample["pointers"]["entries"][E4_KEY]["status"], "PASS")
            self.assertEqual(len(sample["decisions"]), 3)
            by_role = {d["role"]: d for d in sample["decisions"]}
            self.assertEqual(by_role["target"]["classification"], "PENDING")
            self.assertEqual(by_role["target"]["http_status"], 403)
            self.assertTrue(by_role["target"]["pending_predicate"])
            self.assertEqual(by_role["target"]["decision_status"], "PASS")
            self.assertEqual(by_role["target"]["card"], "card-target")
            self.assertEqual(by_role["unrelated"]["classification"], "ALLOW")
            self.assertEqual(by_role["unrelated"]["generation"], "gen-7")
            self.assertEqual(by_role["unrelated"]["decision_status"], "PASS")
            self.assertEqual(by_role["cold"]["classification"], "UNKNOWN")
            self.assertEqual(by_role["cold"]["http_status"], 503)
            self.assertFalse(by_role["cold"]["pending_predicate"])
            self.assertEqual(by_role["cold"]["decision_status"], "UNKNOWN")
            self.assertEqual(
                [(d["role"], d["card"]) for d in sample["decisions"]],
                [("target", "card-target"), ("unrelated", "card-unrelated"), ("cold", "card-cold")],
            )
            request_ids = [d["request_id"] for d in sample["decisions"]]
            for request_id in request_ids:
                self.assertRegex(request_id, r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$")
            self.assertEqual(len(set(request_ids)), len(request_ids))
            for decision in sample["decisions"]:
                self.assertIsInstance(decision["latency_ms"], float)
            self.assertEqual(sample["worker_health"]["redis_ping"]["status"], "PASS")
            self.assertTrue(sample["worker_health"]["redis_ping"]["healthy"])
            self.assertEqual(sample["worker_health"]["health_endpoint"]["status"], "SKIP")

        for query in probe.sql_queries:
            self.assertTrue(query.strip().upper().startswith("SELECT"), query)
        self.assertTrue({argv[0] for argv in probe.redis_commands} <= {"LLEN", "GET", "PING"})
        # decisions go through the actor-aware surface only; the legacy
        # signed_get is reserved for worker health and stays untouched here
        self.assertEqual(probe.http_requests, [])
        for _role, _card, _node, path in probe.role_requests:
            self.assertTrue(path.startswith(DECISION_PATH), path)

        categories = summary["output_categories"]
        self.assertEqual(categories["request_side_denial_pending"]["status"], "PASS")
        self.assertEqual(categories["unrelated_card_availability"]["status"], "PASS")
        self.assertEqual(categories["publication_drain"]["status"], "PASS")
        self.assertEqual(categories["per_event_retry_history"]["status"], "SKIP")

    def test_snapshot_only_limitations_always_present(self) -> None:
        probe = FakeProbe(sql_rows={}, redis_values={}, responses=decision_responses)
        summary = e3_e4.sample_e3(
            probe, "t", "u", "c", interval=0.02, duration=0.03, config=e3_config()
        )
        items = {item["item"]: item for item in summary["limitations"]}
        self.assertEqual(items["per_attempt_decision_history"]["status"], "SKIP")
        self.assertEqual(items["fault_injection"]["status"], "SKIP")
        self.assertIn("per-attempt", items["per_attempt_decision_history"]["note"])
        self.assertEqual(summary["e3_evidence_claim"], "NOT_CLAIMED")
        self.assertIn("snapshot", summary["status_note"])
        self.assertIn("not complete E3 evidence", summary["status_note"])

    def test_stop_event_stops_between_samples(self) -> None:
        probe = FakeProbe(
            sql_rows={"SELECT COUNT(*) FROM authorization_delta_event": [["1"]]},
            redis_values=happy_redis(),
            responses=decision_responses,
        )
        stop = threading.Event()
        seen: List[Dict[str, Any]] = []

        def sink(sample: Dict[str, Any]) -> None:
            seen.append(sample)
            stop.set()

        summary = e3_e4.sample_e3(
            probe,
            "card-target",
            "card-unrelated",
            "card-cold",
            interval=0.05,
            duration=5.0,
            stop_event=stop,
            sink=sink,
            config=e3_config(),
        )
        self.assertEqual(summary["samples_collected"], 1)
        self.assertEqual(len(seen), 1)
        self.assertTrue(summary["stopped_early"])
        self.assertFalse(summary["completed"])
        self.assertEqual(summary["overall"], "UNKNOWN")
        self.assertNotIn("samples", summary)  # streaming mode keeps no copies

    def test_zero_duration_is_blocked_and_touches_nothing(self) -> None:
        probe = FakeProbe(sql_rows={}, redis_values={}, responses=decision_responses)
        summary = e3_e4.sample_e3(
            probe, "t", "u", "c", interval=0.01, duration=0, config=e3_config()
        )
        self.assertEqual(summary["overall"], "BLOCKED")
        self.assertEqual(summary["samples_collected"], 0)
        self.assertEqual(probe.sql_queries, [])
        self.assertEqual(probe.redis_commands, [])
        self.assertEqual(probe.http_requests, [])
        self.assertEqual(probe.role_requests, [])

    def test_missing_redis_capability_is_blocked_but_sampling_continues(self) -> None:
        probe = SqlOnlyProbe()
        summary = e3_e4.sample_e3(
            probe, "t", "u", "c", interval=0.02, duration=0.03, config=e3_config()
        )
        self.assertGreaterEqual(summary["samples_collected"], 1)
        sample = summary["samples"][0]
        self.assertEqual(sample["queue_counts"]["status"], "BLOCKED")
        self.assertEqual(sample["pointers"]["status"], "BLOCKED")
        self.assertEqual(sample["worker_health"]["redis_ping"]["status"], "BLOCKED")
        self.assertEqual(sample["row_counts"]["status"], "PASS")
        # SqlOnlyProbe also lacks the actor-aware extension: per-card decisions
        # are BLOCKED, not silently downgraded to the legacy signed_get surface.
        self.assertEqual(sample["decisions"][0]["decision_status"], "BLOCKED")
        self.assertEqual(sample["decisions"][0]["note"], "actor_aware_probe_required")
        self.assertEqual(summary["overall"], "BLOCKED")
        items = {item["item"]: item for item in summary["limitations"]}
        self.assertEqual(items["redis_reads"]["status"], "BLOCKED")

    def test_missing_actor_aware_capability_is_blocked(self) -> None:
        # Redis/SQL work and the legacy signed_get exists, but per-card
        # decisions still require signed_get_for_role: BLOCKED without it,
        # and the legacy surface must never be used for decisions.
        probe = LegacySignedGetProbe()
        summary = e3_e4.sample_e3(
            probe, "t", "u", "c", interval=0.02, duration=0.03, config=e3_config()
        )
        self.assertGreaterEqual(summary["samples_collected"], 1)
        sample = summary["samples"][0]
        self.assertEqual(sample["row_counts"]["status"], "PASS")
        self.assertEqual(sample["worker_health"]["redis_ping"]["status"], "PASS")
        for decision in sample["decisions"]:
            self.assertEqual(decision["decision_status"], "BLOCKED")
            self.assertEqual(decision["note"], "actor_aware_probe_required")
        self.assertEqual(probe.http_requests, [])
        self.assertEqual(summary["overall"], "BLOCKED")

    def test_signed_get_error_is_unknown_and_does_not_abort(self) -> None:
        probe = FakeProbe(
            sql_rows={"SELECT COUNT(*) FROM authorization_delta_event": [["1"]]},
            redis_values=happy_redis(),
            http_error=RuntimeError("connection refused"),
        )
        summary = e3_e4.sample_e3(
            probe, "t", "u", "c", interval=0.02, duration=0.03, config=e3_config()
        )
        self.assertGreaterEqual(summary["samples_collected"], 1)
        for decision in summary["samples"][0]["decisions"]:
            self.assertEqual(decision["decision_status"], "UNKNOWN")
            self.assertEqual(decision["error_class"], "RuntimeError")
        self.assertEqual(summary["overall"], "UNKNOWN")

    def test_http_200_without_allowed_true_is_unknown_classification(self) -> None:
        probe = FakeProbe(responses={"t": (200, {})})
        summary = e3_e4.sample_e3(
            probe,
            "t",
            "u",
            "c",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=()),
        )
        decision = summary["samples"][0]["decisions"][0]
        self.assertEqual(decision["classification"], "UNKNOWN")
        # an ambiguous body must not be promoted to a PASS decision record
        self.assertEqual(decision["decision_status"], "UNKNOWN")
        self.assertFalse(decision["pending_predicate"])

    def test_plain_503_is_unknown_not_authorization_pending(self) -> None:
        probe = FakeProbe(responses={"t": (503, {})})
        summary = e3_e4.sample_e3(
            probe,
            "t",
            "u",
            "c",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=()),
        )
        decision = summary["samples"][0]["decisions"][0]
        self.assertEqual(decision["classification"], "UNKNOWN")
        self.assertEqual(decision["decision_status"], "UNKNOWN")
        self.assertFalse(decision["pending_predicate"])

    def test_role_and_card_pairs_bound_exactly(self) -> None:
        probe = FakeProbe(
            sql_rows={"SELECT COUNT(*) FROM authorization_delta_event": [["1"]]},
            redis_values=happy_redis(),
            responses=decision_responses,
        )
        summary = e3_e4.sample_e3(
            probe,
            "card-target",
            "card-unrelated",
            "card-cold",
            interval=0.02,
            duration=0.03,
            config=e3_config(),
        )
        sample = summary["samples"][0]
        expected = [
            ("target", "card-target"),
            ("unrelated", "card-unrelated"),
            ("cold", "card-cold"),
        ]
        self.assertEqual([(d["role"], d["card"]) for d in sample["decisions"]], expected)
        # role_requests accumulate across samples: every full round of three
        # repeats the exact same role/card binding in input order
        self.assertEqual([(r, c) for r, c, _n, _p in probe.role_requests[:3]], expected)
        self.assertEqual(len(probe.role_requests) % len(expected), 0)
        for _role, card, node, path in probe.role_requests:
            self.assertEqual(node, "gateway")
            # both the campaign parameter and the card_id alias carry the
            # exact card bound to the role, percent-encoded
            self.assertIn(f"cardId={card}", path)
            self.assertIn(f"card_id={card}", path)

    def test_probe_rejects_path_card_mismatch(self) -> None:
        probe = FakeProbe()
        with self.assertRaises(ValueError):
            probe.signed_get_for_role(
                "target", "card-a", "gateway", f"{DECISION_PATH}?cardId=card-b&card_id=card-b"
            )
        with self.assertRaises(ValueError):
            # the card_id alias is mandatory: a path carrying only cardId is rejected
            probe.signed_get_for_role("target", "card-a", "gateway", f"{DECISION_PATH}?cardId=card-a")

    def test_percent_encoded_card_is_bound_in_path(self) -> None:
        card = "card 1/2?a=b"
        probe = FakeProbe(
            responses=lambda node, path: (403, {"allowed": False, "reason": "AUTHORIZATION_PENDING"})
        )
        summary = e3_e4.sample_e3(
            probe,
            card,
            "u",
            "c",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=()),
        )
        decision = summary["samples"][0]["decisions"][0]
        self.assertEqual(decision["classification"], "PENDING")
        _role, bound_card, _node, path = probe.role_requests[0]
        self.assertEqual(bound_card, card)
        encoded = e3_e4._percent_encode(card)
        self.assertIn(f"cardId={encoded}", path)
        self.assertIn(f"card_id={encoded}", path)
        self.assertNotIn("cardId=card 1", path)

    def test_default_decision_path_is_real_route(self) -> None:
        self.assertEqual(
            e3_e4.DEFAULT_DECISION_PATH,
            "/main/api/v1/permission-rules/check?resourceType=monitor&actionCode=read",
        )
        # the cardId/card_id pair is appended with the correct separator
        self.assertEqual(
            e3_e4._decision_path_for(e3_e4.DEFAULT_DECISION_PATH, "c1", "cardId"),
            "/main/api/v1/permission-rules/check"
            "?resourceType=monitor&actionCode=read&cardId=c1&card_id=c1",
        )
        self.assertEqual(
            e3_e4._decision_path_for("/base", "c1", "cardId"), "/base?cardId=c1&card_id=c1"
        )

    def test_ambiguous_responses_cannot_yield_pass(self) -> None:
        probe = FakeProbe(
            responses={
                "t": (200, {}),
                "u": (200, {"data": {"effect": "MAYBE"}}),
                "c": (503, {}),
            }
        )
        summary = e3_e4.sample_e3(
            probe,
            "t",
            "u",
            "c",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=()),
        )
        self.assertEqual(summary["overall"], "UNKNOWN")
        for decision in summary["samples"][0]["decisions"]:
            self.assertEqual(decision["classification"], "UNKNOWN")
            self.assertEqual(decision["decision_status"], "UNKNOWN")
        categories = summary["output_categories"]
        self.assertEqual(categories["request_side_denial_pending"]["status"], "SKIP")
        self.assertEqual(categories["unrelated_card_availability"]["status"], "SKIP")

    def test_api_response_envelope_end_to_end(self) -> None:
        def responses(node: str, path: str) -> Tuple[int, Dict[str, Any]]:
            if "cardId=card-allow" in path:
                return 200, {"data": {"effect": "ALLOW", "reason": "RULE_MATCH", "generation": "gen-11"}}
            if "cardId=card-deny" in path:
                return 200, {"data": {"effect": "DENY", "reason": "NO_MATCH"}}
            return 200, {"data": {"effect": "MAYBE"}}

        probe = FakeProbe(responses=responses)
        summary = e3_e4.sample_e3(
            probe,
            "card-allow",
            "card-deny",
            "card-weird",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=()),
        )
        by_role = {d["role"]: d for d in summary["samples"][0]["decisions"]}
        self.assertEqual(by_role["target"]["classification"], "ALLOW")
        self.assertEqual(by_role["target"]["generation"], "gen-11")
        self.assertEqual(by_role["target"]["reason"], "RULE_MATCH")
        self.assertEqual(by_role["target"]["decision_status"], "PASS")
        self.assertEqual(by_role["unrelated"]["classification"], "DENY")
        self.assertEqual(by_role["unrelated"]["decision_status"], "PASS")
        self.assertEqual(by_role["cold"]["classification"], "UNKNOWN")
        self.assertEqual(by_role["cold"]["decision_status"], "UNKNOWN")
        self.assertEqual(summary["overall"], "UNKNOWN")

        def responses2(node: str, path: str) -> Tuple[int, Dict[str, Any]]:
            if "cardId=card-pending" in path:
                return 200, {"data": {"effect": "ALLOW", "reason": "AUTHORIZATION_PENDING: projection cold"}}
            if "cardId=card-nomatch" in path:
                return 200, {"data": {"effect": "NO_MATCH", "reason": "NO_RULE"}}
            return 403, {"data": {"effect": "DENY", "reason": "PERMISSION_DENIED"}}

        probe2 = FakeProbe(responses=responses2, redis_values={"PING": "PONG"})
        summary2 = e3_e4.sample_e3(
            probe2,
            "card-pending",
            "card-nomatch",
            "card-denied403",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=()),
        )
        by_role2 = {d["role"]: d for d in summary2["samples"][0]["decisions"]}
        self.assertEqual(by_role2["target"]["classification"], "PENDING")
        self.assertTrue(by_role2["target"]["pending_predicate"])
        self.assertEqual(by_role2["unrelated"]["classification"], "DENY")
        self.assertEqual(by_role2["cold"]["classification"], "DENY")
        self.assertEqual(by_role2["cold"]["http_status"], 403)
        for decision in summary2["samples"][0]["decisions"]:
            self.assertEqual(decision["decision_status"], "PASS")
        # every executed read is well-formed and classified: PASS is reachable
        self.assertEqual(summary2["overall"], "PASS")

    def test_invalid_request_id_is_unknown(self) -> None:
        probe = FakeProbe(
            responses={"t": (200, {"data": {"effect": "ALLOW"}})},
            request_id_override="unsafe id; DROP TABLE evidence",
        )
        summary = e3_e4.sample_e3(
            probe,
            "t",
            "u",
            "c",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=()),
        )
        decision = summary["samples"][0]["decisions"][0]
        self.assertEqual(decision["decision_status"], "UNKNOWN")
        self.assertEqual(decision["error_class"], "ValueError")
        self.assertNotIn("classification", decision)
        self.assertNotIn("request_id", decision)
        self.assertEqual(summary["overall"], "UNKNOWN")

        # a non-string request id smuggled through a 3-tuple is rejected too
        probe_int = FakeProbe(responses={"t": (200, {"data": {"effect": "ALLOW"}}, 123)})
        summary_int = e3_e4.sample_e3(
            probe_int,
            "t",
            "u",
            "c",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=()),
        )
        decision_int = summary_int["samples"][0]["decisions"][0]
        self.assertEqual(decision_int["decision_status"], "UNKNOWN")
        self.assertNotIn("request_id", decision_int)

    def test_hostile_request_id_is_scrubbed_before_storage(self) -> None:
        # the request-id charset alone admits URL-shaped strings; storage must
        # still apply the host scrubber (probe-derived strings are untrusted)
        probe = FakeProbe(responses={"t": (200, {"data": {"effect": "ALLOW"}}, "http://upstream.example.invalid/req-1")})
        summary = e3_e4.sample_e3(
            probe,
            "t",
            "u",
            "c",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=()),
        )
        decision = summary["samples"][0]["decisions"][0]
        self.assertEqual(decision["classification"], "ALLOW")
        self.assertEqual(decision["request_id"], "[redacted-host]")
        self.assertNotIn("upstream.example.invalid", json.dumps(summary))

    def test_sink_errors_are_counted_and_do_not_abort(self) -> None:
        probe = FakeProbe(
            sql_rows={"SELECT COUNT(*) FROM authorization_delta_event": [["1"]]},
            redis_values=happy_redis(),
            responses=decision_responses,
        )

        def sink(sample: Dict[str, Any]) -> None:
            raise RuntimeError("bad sink")

        summary = e3_e4.sample_e3(
            probe,
            "t",
            "u",
            "c",
            interval=0.02,
            duration=0.06,
            sink=sink,
            config=e3_config(),
        )
        self.assertGreaterEqual(summary["samples_collected"], 1)
        self.assertEqual(summary["sink_errors"], summary["samples_collected"])

    def test_worker_health_endpoint_recorded_when_configured(self) -> None:
        calls: List[str] = []

        def responses(node: str, path: str) -> Tuple[int, Dict[str, Any]]:
            calls.append(path)
            if path == "/health":
                return 200, {}
            return 404, {}

        probe = FakeProbe(responses=responses)
        summary = e3_e4.sample_e3(
            probe,
            "t",
            "u",
            "c",
            interval=0.02,
            duration=0.03,
            config=e3_config(redis_queue_keys=(), pointer_keys=(), row_queries=(), worker_health_path="/health"),
        )
        health = summary["samples"][0]["worker_health"]["health_endpoint"]
        self.assertEqual(health["status"], "PASS")
        self.assertTrue(health["healthy"])
        self.assertIn("/health", calls)

    def test_worker_health_accepts_two_and_three_tuple(self) -> None:
        config = e3_config(
            redis_queue_keys=(), pointer_keys=(), row_queries=(), worker_health_path="/health"
        )
        # legacy 2-tuple (status, body) stays accepted
        probe = FakeProbe(responses=lambda node, path: (200, {}))
        summary = e3_e4.sample_e3(
            probe, "t", "u", "c", interval=0.02, duration=0.03, config=config
        )
        health = summary["samples"][0]["worker_health"]["health_endpoint"]
        self.assertEqual(health["status"], "PASS")
        self.assertTrue(health["healthy"])
        self.assertEqual(health["http_status"], 200)

        # actor-aware-style 3-tuple (status, body, request id) is accepted too
        probe3 = FakeProbe(responses=lambda node, path: (204, {}, "req-health-1"))
        summary3 = e3_e4.sample_e3(
            probe3, "t", "u", "c", interval=0.02, duration=0.03, config=config
        )
        health3 = summary3["samples"][0]["worker_health"]["health_endpoint"]
        self.assertEqual(health3["status"], "PASS")
        self.assertTrue(health3["healthy"])
        self.assertEqual(health3["http_status"], 204)

    def test_worker_health_rejects_bad_arity(self) -> None:
        config = e3_config(
            redis_queue_keys=(), pointer_keys=(), row_queries=(), worker_health_path="/health"
        )
        for bad_result in ((200,), (200, {}, "req", "extra")):
            probe = FakeProbe(responses=lambda node, path, _r=bad_result: _r)
            summary = e3_e4.sample_e3(
                probe, "t", "u", "c", interval=0.02, duration=0.03, config=config
            )
            health = summary["samples"][0]["worker_health"]["health_endpoint"]
            self.assertEqual(health["status"], "UNKNOWN")
            self.assertFalse(health["healthy"])
            self.assertEqual(health["error_class"], "ValueError")

    def test_worker_health_non_2xx_is_unknown(self) -> None:
        probe = FakeProbe(responses=lambda node, path: (503, {}, "req-h"))
        summary = e3_e4.sample_e3(
            probe,
            "t",
            "u",
            "c",
            interval=0.02,
            duration=0.03,
            config=e3_config(
                redis_queue_keys=(), pointer_keys=(), row_queries=(), worker_health_path="/health"
            ),
        )
        health = summary["samples"][0]["worker_health"]["health_endpoint"]
        self.assertEqual(health["status"], "UNKNOWN")
        self.assertFalse(health["healthy"])
        self.assertEqual(health["http_status"], 503)

    def test_input_validation_and_config_rejection_touch_nothing(self) -> None:
        probe = FakeProbe()
        with self.assertRaises(ValueError):
            e3_e4.sample_e3(probe, "t", "u", "c", interval=0, duration=0.1)
        with self.assertRaises(ValueError):
            e3_e4.sample_e3(probe, "t", "u", "c", interval=-0.1, duration=0.1)
        with self.assertRaises(ValueError):
            e3_e4.sample_e3(probe, "t", "u", "c", interval=float("nan"), duration=0.1)
        with self.assertRaises(ValueError):
            e3_e4.sample_e3(probe, "t", "u", "c", interval=0.01, duration=-1)
        with self.assertRaises(TypeError):
            e3_e4.sample_e3(probe, "", "u", "c", interval=0.01, duration=0.1)
        with self.assertRaises(TypeError):
            e3_e4.sample_e3(probe, "t", "u", "c", interval=0.01, duration=0.1, stop_event=object())
        with self.assertRaises(TypeError):
            e3_e4.sample_e3(probe, "t", "u", "c", interval=0.01, duration=0.1, sink="not-callable")
        with self.assertRaises(ValueError):
            e3_e4.sample_e3(
                probe,
                "t",
                "u",
                "c",
                interval=0.01,
                duration=0.1,
                config=e3_config(row_queries=(("bad", "UPDATE t SET x=1"),)),
            )
        with self.assertRaises(ValueError):
            e3_e4.sample_e3(
                probe,
                "t",
                "u",
                "c",
                interval=0.01,
                duration=0.1,
                config=e3_config(decision_path="main/api/v1/no-leading-slash"),
            )
        with self.assertRaises(ValueError):
            e3_e4.sample_e3(
                probe,
                "t",
                "u",
                "c",
                interval=0.01,
                duration=0.1,
                config=e3_config(row_queries=(("a", "SELECT 1"), ("a", "SELECT 2"))),
            )
        self.assertEqual(probe.sql_queries, [])
        self.assertEqual(probe.redis_commands, [])
        self.assertEqual(probe.http_requests, [])

    def test_no_hosts_or_secrets_in_sampling_report(self) -> None:
        probe = FakeProbe(
            sql_rows={"SELECT COUNT(*) FROM authorization_delta_event": [["1"]]},
            redis_values={
                ("LLEN", "astral.test.queue"): "2",
                ("GET", E4_KEY): "redis://cache.example.invalid:6380/0",
                "PING": "PONG",
            },
            responses=lambda node, path: (403, {"allowed": False, "reason": "upstream http://upstream.example.invalid:8080/x unreachable"}),
        )
        summary = e3_e4.sample_e3(
            probe,
            "card-target.example.invalid",
            "card-unrelated",
            "card-cold",
            interval=0.02,
            duration=0.03,
            decision_node="decision.example.invalid",
            config=e3_config(),
        )
        blob = json.dumps(summary)
        for forbidden in ("card-target.example.invalid", "decision.example.invalid", "cache.example.invalid", "upstream.example.invalid", "http://", "redis://"):
            self.assertNotIn(forbidden, blob)


class DecisionClassificationTest(unittest.TestCase):
    """ApiResponse-envelope classification matrix (probe level, no sampling)."""

    def test_api_response_effect_matrix(self) -> None:
        classify = e3_e4._classify_decision
        self.assertEqual(classify(200, {"data": {"effect": "ALLOW", "reason": "RULE_MATCH"}}), "ALLOW")
        self.assertEqual(classify(200, {"data": {"effect": "DENY", "reason": "NO_MATCH"}}), "DENY")
        self.assertEqual(classify(200, {"data": {"effect": "NO_MATCH"}}), "DENY")
        self.assertEqual(classify(200, {"data": {"effect": "MAYBE"}}), "UNKNOWN")
        # a pending reason code outranks the ALLOW effect (fail-safe)
        self.assertEqual(
            classify(200, {"data": {"effect": "ALLOW", "reason": "AUTHORIZATION_PENDING"}}), "PENDING"
        )
        self.assertEqual(classify(200, {}), "UNKNOWN")
        self.assertEqual(classify(403, {"data": {"effect": "DENY", "reason": "PERMISSION_DENIED"}}), "DENY")
        self.assertEqual(classify(403, {"errorType": "PERMISSION_DENIED"}), "DENY")
        self.assertEqual(classify(403, {"allowed": False, "reason": "AUTHORIZATION_PENDING"}), "PENDING")
        self.assertEqual(classify(503, {"reason": "AUTHORIZATION_PENDING"}), "PENDING")
        self.assertEqual(classify(503, {}), "UNKNOWN")
        self.assertEqual(classify(404, {"allowed": False}), "UNKNOWN")
        # a non-integer HTTP status is never trusted for classification
        self.assertEqual(classify("200", {"data": {"effect": "ALLOW"}}), "UNKNOWN")

    def test_reason_and_generation_field_extraction(self) -> None:
        allowed, reason, generation = e3_e4._decision_fields(
            {"data": {"effect": "ALLOW", "reason": "RULE_MATCH", "generation": "gen-11"}}
        )
        self.assertIs(allowed, True)
        self.assertEqual(reason, "RULE_MATCH")
        self.assertEqual(generation, "gen-11")

        # envelope-level reasonCode nested beside data (AppError rendering shape)
        allowed, reason, _generation = e3_e4._decision_fields(
            {"data": {"effect": "DENY"}, "reasonCode": "NO_ACTIVE_RULE"}
        )
        self.assertIs(allowed, False)
        self.assertEqual(reason, "NO_ACTIVE_RULE")

        # legacy flat fields and the evidence_generation alias still work
        allowed, reason, generation = e3_e4._decision_fields(
            {"allowed": True, "reason": "ok", "evidence_generation": "g2"}
        )
        self.assertIs(allowed, True)
        self.assertEqual(reason, "ok")
        self.assertEqual(generation, "g2")

        # non-mapping bodies never yield a classification input
        self.assertEqual(e3_e4._decision_fields("not-a-mapping"), (None, "", None))
        self.assertEqual(e3_e4._decision_fields(None), (None, "", None))


class EvaluateFaultOutcomesTest(unittest.TestCase):
    def test_accepts_deny_and_pending_with_reason_codes(self) -> None:
        outcomes = [
            {"fault_id": "redis_unavailable", "component": "redis", "observed": "PENDING", "reason": "REDIS_UNAVAILABLE"},
            {"fault_id": "stale_hmac", "component": "gateway", "observed": "DENY", "reason": "BAD_SIGNATURE"},
        ]
        report = e3_e4.evaluate_fault_outcomes(outcomes)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["total"], 2)
        self.assertEqual(report["accepted"], 2)
        self.assertEqual(report["rejections"], [])

    def test_rejects_allow_as_fail_closed_violation(self) -> None:
        report = e3_e4.evaluate_fault_outcomes(
            [{"fault_id": "lease_expiry", "observed": "ALLOW", "reason": "some reason"}]
        )
        self.assertEqual(report["verdict"], "FAIL")
        self.assertEqual(report["rejections"][0]["status"], "FAIL")
        self.assertEqual(report["rejections"][0]["reason"], "allow_observed_fail_closed_violation")

    def test_rejects_unknown_outcome_as_unproven(self) -> None:
        report = e3_e4.evaluate_fault_outcomes(
            [{"fault_id": "unknown_ack", "observed": "UNKNOWN", "reason": "no evidence"}]
        )
        self.assertEqual(report["verdict"], "BLOCKED")
        self.assertEqual(report["rejections"][0]["status"], "UNKNOWN")

    def test_rejects_absent_observed_and_missing_reason(self) -> None:
        report = e3_e4.evaluate_fault_outcomes(
            [
                {"fault_id": "pointer_movement", "reason": "r"},
                {"fault_id": "worker_restart", "observed": "DENY"},
            ]
        )
        self.assertEqual(report["verdict"], "BLOCKED")
        self.assertEqual([item["reason"] for item in report["rejections"]], ["missing:observed", "missing:reason_code"])

    def test_expected_allow_and_expected_mismatch_are_rejected(self) -> None:
        report = e3_e4.evaluate_fault_outcomes(
            [
                {"fault_id": "a", "observed": "DENY", "reason": "r", "expected": "DENY"},
                {"fault_id": "b", "observed": "DENY", "reason": "r", "expected": "PENDING"},
                {"fault_id": "c", "observed": "DENY", "reason": "r", "expected": "ALLOW"},
            ]
        )
        self.assertEqual(report["verdict"], "FAIL")
        reasons = [item["reason"] for item in report["rejections"]]
        self.assertEqual(reasons, ["expected_mismatch", "expected_allow_rejected"])
        self.assertEqual(report["accepted_fault_ids"], ["a"])

    def test_empty_input_is_blocked(self) -> None:
        self.assertEqual(e3_e4.evaluate_fault_outcomes([])["verdict"], "BLOCKED")

    def test_non_mapping_entry_is_rejected(self) -> None:
        report = e3_e4.evaluate_fault_outcomes(["not-a-mapping"])
        self.assertEqual(report["verdict"], "BLOCKED")
        self.assertEqual(report["rejections"][0]["reason"], "outcome_not_a_mapping")

    def test_fault_matrix_items_match_protocol_e4(self) -> None:
        report = e3_e4.evaluate_fault_outcomes([])
        self.assertEqual(
            report["fault_matrix_items"],
            ["redis_unavailable", "stale_hmac", "pointer_movement", "worker_restart", "lease_expiry", "unknown_ack"],
        )

    def test_inputs_are_never_mutated(self) -> None:
        outcomes = [
            {"fault_id": "a", "observed": "PENDING", "reason": "r"},
            {"fault_id": "b", "observed": "ALLOW", "reason": "r"},
        ]
        snapshot = copy.deepcopy(outcomes)
        e3_e4.evaluate_fault_outcomes(outcomes)
        self.assertEqual(outcomes, snapshot)


class ModuleSafetyTest(unittest.TestCase):
    def test_module_imports_no_network_or_process_capability(self) -> None:
        source = (_HERE / "e3_e4.py").read_text(encoding="utf-8")
        forbidden = (
            "import socket",
            "import subprocess",
            "import urllib.request",
            "import http.client",
            "import requests",
            "import pymysql",
            "import mysql.connector",
            "import redis",
            "import ssl",
            "import paramiko",
            "import ftplib",
        )
        for token in forbidden:
            self.assertNotIn(token, source, f"forbidden import: {token}")

    def test_self_test_entrypoint_exists_and_help_exits_cleanly(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertEqual(e3_e4.main([]), 0)
            with self.assertRaises(SystemExit) as caught:
                e3_e4.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("--self-test", buffer.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
